"""Loopback integration checks for an opaque, durable mailbox relay."""

import asyncio
import importlib.util
import sqlite3

import pytest
from vodozemac import Account


def modules():
    assert importlib.util.find_spec("server.relay") is not None, "relay implementation missing"
    assert importlib.util.find_spec("core.relay_client") is not None, "relay client missing"
    from server.relay import RelayServer
    from core.relay_client import RelayConnection, RelayError
    return RelayServer, RelayConnection, RelayError


def party(count=3):
    from core.protocol import identity_from_account, prekey_signing_bytes
    account = Account()
    identity = identity_from_account(account)
    account.generate_one_time_keys(count)
    prekeys = []
    for key_id, key in account.one_time_keys.items():
        key = key.to_base64()
        prekeys.append({"id": key_id, "key": key, "signature": account.sign(prekey_signing_bytes(identity["id"], key_id, key)).to_base64()})
    return identity, lambda payload: account.sign(payload).to_base64(), {"identity": identity, "prekeys": prekeys}


def envelope(sender, recipient, message_id="1" * 32):
    return {"v": 1, "sender": sender["id"], "recipient": recipient["id"], "message_id": message_id,
            "session_id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "message_type": 0, "ciphertext": "c3ludGhldGlj"}


def test_offline_mailbox_survives_restart_is_private_and_idempotent(tmp_path):
    async def scenario():
        RelayServer, RelayConnection, RelayError = modules()
        db = tmp_path / "relay.sqlite"
        alice, alice_sign, alice_bundle = party()
        bob, bob_sign, bob_bundle = party()
        eve, eve_sign, eve_bundle = party()
        server = await RelayServer(db).start()
        connections = []
        try:
            a = await RelayConnection.connect(*server.address, alice, alice_sign)
            b = await RelayConnection.connect(*server.address, bob, bob_sign)
            e = await RelayConnection.connect(*server.address, eve, eve_sign)
            connections.extend((a, b, e))
            for connection, bundle in ((a, alice_bundle), (b, bob_bundle), (e, eve_bundle)):
                await connection.publish(bundle)
            await b.close()
            packet = envelope(alice, bob)
            assert (await a.send(packet))["ok"]
            assert (await a.send(packet))["duplicate"] is True
            assert await e.fetch() == []
            assert (await e.ack([packet["message_id"]]))["acked"] == 0
            changed = {**packet, "ciphertext": "Y2hhbmdlZA=="}
            with pytest.raises(RelayError, match="message_conflict"):
                await a.send(changed)
        finally:
            for connection in connections:
                await connection.close()
            await server.close()
        server = await RelayServer(db).start()
        b = await RelayConnection.connect(*server.address, bob, bob_sign)
        try:
            assert await b.fetch() == [packet]
            assert (await b.ack([packet["message_id"]]))["acked"] == 1
            assert await b.fetch() == []
        finally:
            await b.close()
            await server.close()
        with sqlite3.connect(db) as connection:
            dump = "\n".join(connection.iterdump())
            assert "PRIVATE KEY" not in dump
            assert "plaintext" not in dump
    asyncio.run(scenario())


def test_claim_consumes_once_and_republish_cannot_restore(tmp_path):
    async def scenario():
        RelayServer, RelayConnection, RelayError = modules()
        alice, alice_sign, _ = party()
        bob, bob_sign, bundle = party(1)
        server = await RelayServer(tmp_path / "relay.sqlite").start()
        a = await RelayConnection.connect(*server.address, alice, alice_sign)
        b = await RelayConnection.connect(*server.address, bob, bob_sign)
        try:
            await b.publish(bundle)
            claim = await a.claim(bob["id"])
            assert claim == {"identity": bob, "prekey": bundle["prekeys"][0]}
            await b.publish(bundle)
            with pytest.raises(RelayError, match="prekey_unavailable"):
                await a.claim(bob["id"])
            with pytest.raises(RelayError, match="forbidden"):
                await a.publish(bundle)
        finally:
            await a.close()
            await b.close()
            await server.close()
    asyncio.run(scenario())


def test_sender_binding_recipient_registration_and_queue_limit(tmp_path):
    async def scenario():
        RelayServer, RelayConnection, RelayError = modules()
        alice, alice_sign, _ = party()
        bob, bob_sign, bundle = party()
        outsider, _, _ = party()
        server = await RelayServer(tmp_path / "relay.sqlite", max_messages_per_account=1).start()
        a = await RelayConnection.connect(*server.address, alice, alice_sign)
        b = await RelayConnection.connect(*server.address, bob, bob_sign)
        try:
            await b.publish(bundle)
            with pytest.raises(RelayError, match="forbidden"):
                await a.send(envelope(outsider, bob))
            with pytest.raises(RelayError, match="recipient_unavailable"):
                await a.send(envelope(alice, outsider))
            await a.send(envelope(alice, bob))
            with pytest.raises(RelayError, match="queue_full"):
                await a.send(envelope(alice, bob, "2" * 32))
            assert (await b.status())["queued"] == 1
        finally:
            await a.close()
            await b.close()
            await server.close()
    asyncio.run(scenario())


def test_account_capacity_has_a_stable_error(tmp_path):
    async def scenario():
        RelayServer, RelayConnection, RelayError = modules()
        alice, alice_sign, _ = party()
        bob, bob_sign, _ = party()
        server = await RelayServer(tmp_path / "relay.sqlite", max_accounts=1).start()
        a = await RelayConnection.connect(*server.address, alice, alice_sign)
        b = await RelayConnection.connect(*server.address, bob, bob_sign)
        try:
            assert (await a.status())["ok"]
            with pytest.raises(RelayError, match="account_limit"):
                await b.status()
        finally:
            await a.close()
            await b.close()
            await server.close()
    asyncio.run(scenario())


def test_prekey_claim_is_atomic_under_parallel_clients(tmp_path):
    async def scenario():
        RelayServer, RelayConnection, RelayError = modules()
        alice, sign_a, _ = party()
        bob, sign_b, bundle = party(1)
        server = await RelayServer(tmp_path / "relay.sqlite").start()
        a = await RelayConnection.connect(*server.address, alice, sign_a)
        a2 = await RelayConnection.connect(*server.address, alice, sign_a)
        b = await RelayConnection.connect(*server.address, bob, sign_b)
        try:
            await b.publish(bundle)
            claims = await asyncio.gather(a.claim(bob["id"]), a2.claim(bob["id"]), return_exceptions=True)
            assert sum(type(item) is dict for item in claims) == 1
            assert sum(isinstance(item, RelayError) for item in claims) == 1
        finally:
            await asyncio.gather(a.close(), a2.close(), b.close())
            await server.close()
    asyncio.run(scenario())


def test_ttl_size_limits_and_bounded_fetch_frames(tmp_path):
    async def scenario():
        import base64
        RelayServer, RelayConnection, RelayError = modules()
        alice, sign_a, _ = party()
        bob, sign_b, bundle = party()
        server = await RelayServer(tmp_path / "relay.sqlite", message_ttl=0.05).start()
        a = await RelayConnection.connect(*server.address, alice, sign_a)
        b = await RelayConnection.connect(*server.address, bob, sign_b)
        try:
            await b.publish(bundle)
            item = envelope(alice, bob)
            await a.send(item)
            await asyncio.sleep(0.06)
            assert await b.fetch() == []
            # Three individually valid ciphertexts cannot fit in one wire frame.
            server.message_ttl = 3600
            item["ciphertext"] = base64.b64encode(b"x" * 40000).decode("ascii")
            for number in range(3):
                await a.send({**item, "message_id": str(number) * 32})
            first_page = await b.fetch(100)
            assert 0 < len(first_page) < 3
            await b.ack([entry["message_id"] for entry in first_page])
            assert len(await b.fetch()) + len(first_page) == 3
            with pytest.raises(RelayError, match="invalid_request"):
                await b.fetch(True)
            with pytest.raises(RelayError, match="invalid_request"):
                await b.ack(["invalid-id"])
        finally:
            await a.close()
            await b.close()
            await server.close()
    asyncio.run(scenario())


def test_prekey_signature_rejected_and_failed_batch_is_atomic(tmp_path):
    async def scenario():
        RelayServer, RelayConnection, RelayError = modules()
        alice, sign_a, bundle = party(2)
        server = await RelayServer(tmp_path / "relay.sqlite", max_prekeys_per_account=1).start()
        a = await RelayConnection.connect(*server.address, alice, sign_a)
        try:
            bad = {"identity": alice, "prekeys": [{**bundle["prekeys"][0], "signature": sign_a(b"wrong message")}]}
            with pytest.raises(RelayError, match="invalid_request"):
                await a.publish(bad)
            assert (await a.status())["prekeys"] == 0
            with pytest.raises(RelayError, match="prekey_limit"):
                await a.publish(bundle)
            assert (await a.status())["prekeys"] == 0
        finally:
            await a.close()
            await server.close()
    asyncio.run(scenario())


def test_connection_cap_and_shutdown_close_pending_handshakes(tmp_path):
    async def scenario():
        from core.transport import TransportError
        RelayServer, RelayConnection, _ = modules()
        alice, sign_a, _ = party()
        server = await RelayServer(tmp_path / "relay.sqlite", max_connections=1).start()
        reader, writer = await asyncio.open_connection(*server.address)
        try:
            with pytest.raises(TransportError):
                await RelayConnection.connect(*server.address, alice, sign_a, timeout=0.1)
            await asyncio.wait_for(server.close(), 2)
            assert await asyncio.wait_for(reader.read(), 1) == b""
            assert not server._tasks
        finally:
            writer.close()
            await writer.wait_closed()
            await server.close()
    asyncio.run(scenario())

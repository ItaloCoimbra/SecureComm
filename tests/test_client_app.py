import asyncio
import sqlite3

import pytest

from client.app import SecureClient
from core.identity import IdentityVault, VaultError
from core.relay_client import RelayError
from server.relay import RelayServer


PASSWORD = "synthetic integration passphrase"


def paired_profiles(tmp_path):
    alice = IdentityVault.create(tmp_path / "alice.vault", PASSWORD)
    bob = IdentityVault.create(tmp_path / "bob.vault", PASSWORD)
    alice.add_contact("bob", bob.public_identity(), bob.public_identity()["id"])
    bob.add_contact("alice", alice.public_identity(), alice.public_identity()["id"])
    return alice, bob


def test_direct_delivery_and_receipt_without_any_relay(tmp_path):
    async def scenario():
        alice_vault, bob_vault = paired_profiles(tmp_path)
        alice, bob = SecureClient(alice_vault), SecureClient(bob_vault)
        try:
            await bob.start()
            message_id = await alice.send_direct("bob", "synthetic direct hello", *bob.address)
            received = await asyncio.wait_for(bob.received.get(), timeout=3)
            assert received["text"] == "synthetic direct hello"
            assert any(row["message_id"] == message_id and row["status"] == "delivered"
                       for row in alice.messenger.history())
            assert not alice.messenger.pending_envelopes()
        finally:
            await alice.close()
            await bob.close()
            alice_vault.close()
            bob_vault.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["storage", "capacity"])
def test_local_failure_preserves_remote_message_for_retry(tmp_path, monkeypatch, failure):
    async def scenario():
        av, bv = paired_profiles(tmp_path)
        alice, bob = SecureClient(av), SecureClient(bv)
        relay = RelayServer(tmp_path / "relay.sqlite")
        try:
            await relay.start()
            al = await alice.connect_relay(*relay.address)
            bl = await bob.connect_relay(*relay.address)
            mid = await alice.send_via_relay("bob", "synthetic durable message", al)
            if failure == "storage":
                def unavailable(state):
                    raise VaultError("Synthetic storage failure")
                monkeypatch.setattr(bv, "commit", unavailable)
            else:
                monkeypatch.setattr("core.e2ee.MAX_PENDING_ENVELOPES", 0)
            with pytest.raises((VaultError, RuntimeError)):
                await bob.sync_relay(bl)
            assert [item["message_id"] for item in await bl.fetch()] == [mid]
            assert bob.messenger.history() == []
            monkeypatch.undo()
            assert len(await bob.sync_relay(bl)) == 1
            assert await bl.fetch() == []
            await alice.sync_relay(al)
            assert alice.messenger.history()[0]["status"] == "delivered"
        finally:
            await alice.close()
            await bob.close()
            av.close()
            bv.close()
            await relay.close()
    asyncio.run(scenario())


def test_full_remote_queue_does_not_block_incoming_receipts(tmp_path):
    async def scenario():
        av, bv = paired_profiles(tmp_path)
        alice, bob = SecureClient(av), SecureClient(bv)
        relay = RelayServer(tmp_path / "relay.sqlite", max_messages_per_account=1)
        try:
            await relay.start()
            al = await alice.connect_relay(*relay.address)
            bl = await bob.connect_relay(*relay.address)
            first = await alice.send_via_relay("bob", "synthetic first", al)
            await bob.sync_relay(bl)
            await alice.send_via_relay("bob", "synthetic second", al)
            with pytest.raises(RelayError, match="queue_full"):
                await alice.send_via_relay("bob", "synthetic third", al)
            await alice.sync_relay(al)
            assert next(row for row in alice.messenger.history() if row["message_id"] == first)["status"] == "delivered"
            assert len(alice.messenger.pending_envelopes()) == 2
            for _ in range(3):
                await bob.sync_relay(bl)
                await alice.sync_relay(al)
            assert not alice.messenger.pending_envelopes()
            assert len(bob.messenger.history()) == 3
        finally:
            await alice.close()
            await bob.close()
            av.close()
            bv.close()
            await relay.close()
    asyncio.run(scenario())


def test_independent_relays_do_not_block_other_contacts(tmp_path):
    async def scenario():
        av, bv = paired_profiles(tmp_path)
        cv = IdentityVault.create(tmp_path / "charlie.vault", PASSWORD)
        av.add_contact("charlie", cv.public_identity(), cv.public_identity()["id"])
        cv.add_contact("alice", av.public_identity(), av.public_identity()["id"])
        alice, bob, charlie = SecureClient(av), SecureClient(bv), SecureClient(cv)
        first = RelayServer(tmp_path / "first.sqlite")
        second = RelayServer(tmp_path / "second.sqlite")
        try:
            await first.start()
            await second.start()
            a1 = await alice.connect_relay(*first.address)
            a2 = await alice.connect_relay(*second.address)
            b1 = await bob.connect_relay(*first.address)
            c2 = await charlie.connect_relay(*second.address)
            await alice.send_via_relay("bob", "synthetic relay one", a1)
            await charlie.send_via_relay("alice", "synthetic relay two", c2)
            assert [event["text"] for event in await alice.sync_relay(a2)] == ["synthetic relay two"]
            await charlie.sync_relay(c2)
            assert charlie.messenger.history()[0]["status"] == "delivered"
            assert [event["text"] for event in await bob.sync_relay(b1)] == ["synthetic relay one"]
            await alice.sync_relay(a1)
            assert not alice.messenger.pending_envelopes()
        finally:
            for app in (alice, bob, charlie):
                await app.close()
                app.vault.close()
            await first.close()
            await second.close()
    asyncio.run(scenario())


def test_revoked_sender_does_not_block_a_trusted_sender(tmp_path):
    async def scenario():
        av, bv = paired_profiles(tmp_path)
        cv = IdentityVault.create(tmp_path / "charlie.vault", PASSWORD)
        bv.add_contact("charlie", cv.public_identity(), cv.public_identity()["id"])
        cv.add_contact("bob", bv.public_identity(), bv.public_identity()["id"])
        alice, bob, charlie = SecureClient(av), SecureClient(bv), SecureClient(cv)
        relay = RelayServer(tmp_path / "relay.sqlite")
        try:
            await relay.start()
            al = await alice.connect_relay(*relay.address)
            bl = await bob.connect_relay(*relay.address)
            cl = await charlie.connect_relay(*relay.address)
            await alice.send_via_relay("bob", "synthetic old contact", al)
            await charlie.send_via_relay("bob", "synthetic trusted contact", cl)
            bv.revoke_contact("alice", av.public_identity()["id"])
            assert [event["text"] for event in await bob.sync_relay(bl)] == ["synthetic trusted contact"]
            assert await bl.fetch() == []
        finally:
            for app in (alice, bob, charlie):
                await app.close()
                app.vault.close()
            await relay.close()
    asyncio.run(scenario())


def test_full_text_outboxes_reserve_capacity_for_receipts(tmp_path, monkeypatch):
    async def scenario():
        av, bv = paired_profiles(tmp_path)
        alice, bob = SecureClient(av), SecureClient(bv)
        relay = RelayServer(tmp_path / "relay.sqlite")
        try:
            await relay.start()
            al = await alice.connect_relay(*relay.address)
            bl = await bob.connect_relay(*relay.address)
            monkeypatch.setattr("core.e2ee.MAX_PENDING_ENVELOPES", 1)
            await alice.send_via_relay("bob", "synthetic full alice", al)
            await bob.send_via_relay("alice", "synthetic full bob", bl)
            await bob.sync_relay(bl)
            await alice.sync_relay(al)
            await bob.sync_relay(bl)
            assert not alice.messenger.pending_envelopes()
            assert not bob.messenger.pending_envelopes()
        finally:
            await alice.close()
            await bob.close()
            av.close()
            bv.close()
            await relay.close()
    asyncio.run(scenario())


def test_direct_backlog_drains_in_bounded_exchanges(tmp_path, monkeypatch):
    async def scenario():
        av, bv = paired_profiles(tmp_path)
        alice, bob = SecureClient(av), SecureClient(bv)
        try:
            monkeypatch.setattr("client.app.DIRECT_BATCH_SIZE", 2, raising=False)
            bundle = bob.messenger.issue_prekeys(1)
            claim = {"identity": bundle["identity"], "prekey": bundle["prekeys"][0]}
            for index in range(5):
                alice.messenger.prepare_message("bob", f"synthetic backlog {index}", claim if index == 0 else None)
            await bob.start()
            await alice.sync_direct("bob", *bob.address)
            assert len(bob.messenger.history()) == 2
            for _ in range(3):
                await alice.sync_direct("bob", *bob.address)
            assert len(bob.messenger.history()) == 5
            assert not alice.messenger.pending_envelopes()
        finally:
            await alice.close()
            await bob.close()
            av.close()
            bv.close()
    asyncio.run(scenario())


def test_offline_relay_delivery_survives_all_restarts(tmp_path):
    async def scenario():
        alice_vault, bob_vault = paired_profiles(tmp_path)
        alice, bob = SecureClient(alice_vault), SecureClient(bob_vault)
        relay = RelayServer(tmp_path / "relay.sqlite")
        try:
            await relay.start()
            alice_link = await alice.connect_relay(*relay.address)
            await bob.connect_relay(*relay.address)
            await bob.close()
            bob_vault.close()
            message_id = await alice.send_via_relay("bob", "synthetic offline hello", alice_link)
            assert not any(row.get("status") == "delivered" for row in alice.messenger.history())
            with sqlite3.connect(tmp_path / "relay.sqlite") as connection:
                dump = "\n".join(connection.iterdump())
            assert "synthetic offline hello" not in dump
            assert "ciphertext" in dump
            await alice.close()
            alice_vault.close()
            await relay.close()

            relay = RelayServer(tmp_path / "relay.sqlite")
            await relay.start()
            alice_vault = IdentityVault.open(tmp_path / "alice.vault", PASSWORD)
            bob_vault = IdentityVault.open(tmp_path / "bob.vault", PASSWORD)
            alice, bob = SecureClient(alice_vault), SecureClient(bob_vault)
            bob_link = await bob.connect_relay(*relay.address)
            received = await bob.sync_relay(bob_link)
            assert [item["text"] for item in received] == ["synthetic offline hello"]
            alice_link = await alice.connect_relay(*relay.address)
            await alice.sync_relay(alice_link)
            assert any(row["message_id"] == message_id and row["status"] == "delivered"
                       for row in alice.messenger.history())
            assert await bob.sync_relay(bob_link) == []
        finally:
            await alice.close()
            await bob.close()
            alice_vault.close()
            bob_vault.close()
            await relay.close()
    asyncio.run(scenario())

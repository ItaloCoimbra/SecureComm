"""Real TLS checks restricted to loopback with short-lived synthetic certificates."""

import asyncio
from datetime import datetime, timedelta, timezone
import ssl
import sqlite3

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID
from vodozemac import Account

from client.app import SecureClient
from core import transport
from core.identity import IdentityVault
from core.protocol import auth_bytes, identity_from_account
from core.relay_client import RelayConnection
from server.relay import RelayServer


def test_plaintext_external_transport_fails_before_opening_a_socket(monkeypatch, tmp_path):
    async def unexpected_socket(*args, **kwargs):
        pytest.fail("external socket creation must not be attempted")

    async def scenario():
        monkeypatch.setattr(asyncio, "open_connection", unexpected_socket)
        monkeypatch.setattr(asyncio, "start_server", unexpected_socket)
        identity = identity_from_account(Account())
        with pytest.raises(transport.TransportError, match="TLS"):
            await RelayConnection.connect("192.0.2.10", 12345, identity, lambda _: "unused")
        with pytest.raises(transport.TransportError, match="TLS"):
            await RelayServer(tmp_path / "relay.sqlite", host="0.0.0.0").start()
        assert not (tmp_path / "relay.sqlite").exists()
    asyncio.run(scenario())


def _certificates(tmp_path):
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic SecureComm Test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=True, crl_sign=True,
                                      encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def server_context(name, signature_hash=None):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                .issuer_name(ca_name).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(ca_key, signature_hash or hashes.SHA256()))
        key_path = tmp_path / (name + ".key")
        cert_path = tmp_path / (name + ".pem")
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                              serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        assert hasattr(transport, "make_server_tls_context"), "certificate binding helper missing"
        return transport.make_server_tls_context(cert_path, key_path)

    client = ssl.create_default_context(cafile=str(ca_path))
    client.minimum_version = ssl.TLSVersion.TLSv1_2
    return client, server_context


def test_verified_tls_roundtrip_rejects_wrong_ca_and_hostname(tmp_path):
    async def scenario():
        client_context, server_context = _certificates(tmp_path)
        assert hasattr(transport, "connect_transport"), "TLS transport is missing"
        server = await RelayServer(tmp_path / "good.sqlite", ssl_context=server_context("localhost")).start()
        account = Account()
        identity = identity_from_account(account)
        sign = lambda payload: account.sign(payload).to_base64()
        try:
            connection = await RelayConnection.connect("localhost", server.address[1], identity, sign,
                                                       ssl_context=client_context)
            try:
                assert (await connection.status())["ok"] is True
                assert connection.writer.get_extra_info("ssl_object").version() in ("TLSv1.2", "TLSv1.3")
            finally:
                await connection.close()
            with pytest.raises(transport.TransportError, match="transport unavailable"):
                await RelayConnection.connect("localhost", server.address[1], identity, sign,
                                              ssl_context=ssl.create_default_context())
            with pytest.raises(transport.TransportError, match="transport unavailable"):
                await RelayConnection.connect("127.0.0.1", server.address[1], identity, sign,
                                              ssl_context=client_context)
        finally:
            await server.close()
        wrong_name_server = await RelayServer(tmp_path / "wrong.sqlite",
                                               ssl_context=server_context("wrong.example")).start()
        try:
            with pytest.raises(transport.TransportError, match="transport unavailable"):
                await RelayConnection.connect("localhost", wrong_name_server.address[1], identity, sign,
                                              ssl_context=client_context)
        finally:
            await wrong_name_server.close()
    asyncio.run(scenario())


def test_insecure_tls_contexts_rejected_before_connection(monkeypatch):
    async def unexpected_socket(*args, **kwargs):
        pytest.fail("invalid TLS contexts must not reach socket creation")

    async def scenario():
        assert hasattr(transport, "connect_transport"), "TLS transport is missing"
        monkeypatch.setattr(asyncio, "open_connection", unexpected_socket)
        no_hostname = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        no_hostname.check_hostname = False
        no_verification = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        no_verification.check_hostname = False
        no_verification.verify_mode = ssl.CERT_NONE
        weak_minimum = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        weak_minimum.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        for context in (no_hostname, no_verification, weak_minimum):
            with pytest.raises(transport.TransportError, match="TLS"):
                await transport.connect_transport("192.0.2.10", 12345, ssl_context=context)
    asyncio.run(scenario())


@pytest.mark.parametrize("host,expected", [("localhost", "127.0.0.1"), ("LOCALHOST", "127.0.0.1"),
                                           ("127.0.0.1", "127.0.0.1"), ("127.2.3.4", "127.2.3.4"), ("::1", "::1")])
def test_plain_loopback_host_policy(host, expected):
    assert hasattr(transport, "validate_server_transport"), "TLS host policy is missing"
    assert transport.validate_server_transport(host) == expected


@pytest.mark.parametrize("host", ["localhost.example", "localhost.", "127.0.0.1.example", "0.0.0.0", "::", "192.0.2.1"])
def test_plain_other_hosts_are_denied(host):
    assert hasattr(transport, "validate_server_transport"), "TLS host policy is missing"
    with pytest.raises(transport.TransportError, match="TLS"):
        transport.validate_server_transport(host)


def test_tls_server_context_without_local_certificate_binding_fails_closed():
    with pytest.raises(transport.TransportError, match="certificate"):
        transport.validate_server_transport("127.0.0.1", ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))


def test_tls_authentication_binds_locally_derived_certificate_and_tls_version(tmp_path):
    async def scenario():
        client_context, server_context = _certificates(tmp_path)
        account = Account()
        identity = identity_from_account(account)
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            serving_context = server_context("localhost")
            serving_context.minimum_version = serving_context.maximum_version = version
            client_context.minimum_version = client_context.maximum_version = version
            server = await RelayServer(tmp_path / (version.name + ".sqlite"), ssl_context=serving_context).start()
            try:
                signed = []
                def sign(payload):
                    import json
                    signed.append(json.loads(payload))
                    return account.sign(payload).to_base64()
                connection = await RelayConnection.connect("localhost", server.address[1], identity, sign,
                                                           ssl_context=client_context)
                try:
                    assert (await connection.status())["ok"]
                    binding = signed[0]["channel_binding"]
                    assert binding.startswith("tls-server-end-point:sha256:")
                    assert len(binding.rsplit(":", 1)[1]) == 64
                finally:
                    await connection.close()

                def sign_wrong_context(payload):
                    import json
                    context = json.loads(payload)
                    return account.sign(auth_bytes(context["nonce"], identity["id"],
                                        "tls-server-end-point:sha256:" + "0" * 64)).to_base64()
                with pytest.raises(transport.TransportError, match="authentication failed"):
                    await RelayConnection.connect("localhost", server.address[1], identity, sign_wrong_context,
                                                  ssl_context=client_context)
            finally:
                await server.close()
    asyncio.run(scenario())


def test_tls_server_handshake_deadline_closes_unfinished_connection(tmp_path):
    async def scenario():
        _, server_context = _certificates(tmp_path)
        server = await RelayServer(tmp_path / "deadline.sqlite", ssl_context=server_context("localhost"),
                                   handshake_timeout=0.05).start()
        reader, writer = await asyncio.open_connection(*server.address)
        try:
            try:
                assert await asyncio.wait_for(reader.read(), 1) == b""
            except ConnectionResetError:
                pass
        finally:
            await transport.close_writer(writer)
            await server.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("algorithm,size", [(hashes.SHA256(), 64), (hashes.SHA384(), 96), (hashes.SHA512(), 128)])
def test_endpoint_certificate_binding_uses_signature_hash(tmp_path, algorithm, size):
    _, make_context = _certificates(tmp_path)
    context = make_context("localhost", algorithm)
    binding = transport._certificate_binding(context._securecomm_certificate_der)
    assert binding.startswith("tls-server-end-point:" + algorithm.name + ":")
    assert len(binding.rsplit(":", 1)[1]) == size


def test_undefined_certificate_binding_algorithm_is_rejected(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                   .sign(key, None))
    cert_path, key_path = tmp_path / "eddsa.pem", tmp_path / "eddsa.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    with pytest.raises(transport.TransportError, match="supported SHA"):
        transport.make_server_tls_context(cert_path, key_path)


def _paired_tls_vaults(tmp_path):
    password = "synthetic TLS integration passphrase"
    alice = IdentityVault.create(tmp_path / "alice.vault", password)
    bob = IdentityVault.create(tmp_path / "bob.vault", password)
    alice.add_contact("bob", bob.public_identity(), bob.public_identity()["id"])
    bob.add_contact("alice", alice.public_identity(), alice.public_identity()["id"])
    return alice, bob, password


def test_secure_clients_exchange_e2ee_text_and_receipts_directly_over_tls(tmp_path):
    async def scenario():
        client_context, make_context = _certificates(tmp_path)
        av, bv, _ = _paired_tls_vaults(tmp_path)
        alice, bob = SecureClient(av), SecureClient(bv)
        try:
            await alice.start(ssl_context=make_context("localhost"))
            await bob.start(ssl_context=make_context("localhost"))
            first_id = await alice.send_direct("bob", "synthetic direct TLS greeting",
                                                "localhost", bob.address[1], ssl_context=client_context)
            first = await asyncio.wait_for(bob.received.get(), timeout=3)
            assert first["text"] == "synthetic direct TLS greeting"
            assert first["message_id"] == first_id
            reply_id = await bob.send_direct("alice", "synthetic direct TLS reply",
                                              "localhost", alice.address[1], ssl_context=client_context)
            reply = await asyncio.wait_for(alice.received.get(), timeout=3)
            assert reply["text"] == "synthetic direct TLS reply"
            assert reply["message_id"] == reply_id
            assert next(item for item in alice.messenger.history() if item["message_id"] == first_id)["status"] == "delivered"
            assert next(item for item in bob.messenger.history() if item["message_id"] == reply_id)["status"] == "delivered"
            assert not alice.messenger.pending_envelopes()
            assert not bob.messenger.pending_envelopes()
            assert alice.errors.empty() and bob.errors.empty()
        finally:
            await alice.close()
            await bob.close()
            av.close()
            bv.close()
    asyncio.run(scenario())


def test_secure_clients_deliver_offline_e2ee_through_tls_relay_after_restart(tmp_path):
    async def scenario():
        client_context, make_context = _certificates(tmp_path)
        server_context = make_context("localhost")
        av, bv, password = _paired_tls_vaults(tmp_path)
        alice, bob = SecureClient(av), SecureClient(bv)
        database = tmp_path / "tls-offline.sqlite"
        relay = RelayServer(database, ssl_context=server_context)
        text = "synthetic TLS offline greeting survives restart"
        try:
            await relay.start()
            al = await alice.connect_relay("localhost", relay.address[1], ssl_context=client_context)
            bl = await bob.connect_relay("localhost", relay.address[1], ssl_context=client_context)
            assert al.writer.get_extra_info("ssl_object") is not None
            assert bl.writer.get_extra_info("ssl_object") is not None
            await bob.close()
            bv.close()
            message_id = await alice.send_via_relay("bob", text, al)
            with sqlite3.connect(database) as connection:
                stored = connection.execute("SELECT envelope FROM messages WHERE id=?", (message_id,)).fetchone()[0]
                assert text not in stored
                assert '"ciphertext"' in stored
            await alice.close()
            av.close()
            await relay.close()

            av = IdentityVault.open(tmp_path / "alice.vault", password)
            bv = IdentityVault.open(tmp_path / "bob.vault", password)
            alice, bob = SecureClient(av), SecureClient(bv)
            relay = await RelayServer(database, ssl_context=server_context).start()
            al = await alice.connect_relay("localhost", relay.address[1], ssl_context=client_context)
            bl = await bob.connect_relay("localhost", relay.address[1], ssl_context=client_context)
            events = await bob.sync_relay(bl)
            assert len(events) == 1
            assert events[0]["message_id"] == message_id
            assert events[0]["text"] == text
            await alice.sync_relay(al)
            assert next(item for item in alice.messenger.history() if item["message_id"] == message_id)["status"] == "delivered"
            assert not alice.messenger.pending_envelopes()
            assert await bl.fetch() == []
            assert alice.errors.empty() and bob.errors.empty()
        finally:
            await alice.close()
            await bob.close()
            av.close()
            bv.close()
            await relay.close()
    asyncio.run(scenario())

"""Baseline checks for primitives, not proof of authenticated E2EE messaging."""

import pytest

from core.auth import AuthManager
from core.crypto import CryptoManager


@pytest.fixture
def peers():
    alice, bob = CryptoManager(), CryptoManager()
    alice_secret = alice.generate_shared_secret(bob.get_public_key_bytes())
    bob_secret = bob.generate_shared_secret(alice.get_public_key_bytes())
    _, salt = alice.derive_session_key(alice_secret)
    bob.derive_session_key(bob_secret, salt=salt)
    return alice, bob


@pytest.mark.parametrize("message", [b"", b"synthetic test message", "Olá, teste".encode()])
def test_peers_exchange_messages_in_both_directions(peers, message):
    alice, bob = peers
    assert bob.decrypt_message(alice.encrypt_message(message)) == message
    assert alice.decrypt_message(bob.encrypt_message(message)) == message


def test_encryption_requires_an_established_session():
    with pytest.raises(ValueError, match="Chave de sessão"):
        CryptoManager().encrypt_message(b"synthetic data")


def test_reset_requires_a_new_session_before_sending(peers):
    alice, _ = peers
    previous_public_key = alice.get_public_key_bytes()
    alice.reset_session()
    assert alice.get_public_key_bytes() != previous_public_key
    with pytest.raises(ValueError, match="Chave de sessão"):
        alice.encrypt_message(b"new session required")


def test_signature_is_verified_with_the_supplied_public_key():
    sender = AuthManager()
    message = b"synthetic signed message"
    signature = sender.sign_message(message)
    assert AuthManager.verify_signature(sender.get_signing_public_key_bytes(), message, signature)


def test_signature_does_not_validate_a_different_message():
    sender = AuthManager()
    signature = sender.sign_message(b"first synthetic message")
    assert not AuthManager.verify_signature(
        sender.get_signing_public_key_bytes(), b"different synthetic message", signature
    )

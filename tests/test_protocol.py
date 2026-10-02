import base64

import pytest
from vodozemac import Account

from core.protocol import (
    ValidationError, auth_bytes, identity_from_account, prekey_signing_bytes,
    validate_bundle, validate_claim, validate_envelope, validate_identity,
    verify_signature,
)


def test_identity_is_stable_and_binds_both_public_keys():
    account = Account()
    identity = identity_from_account(account)
    assert validate_identity(identity) == identity
    assert identity_from_account(account) == identity
    other = identity_from_account(Account())
    with pytest.raises(ValidationError):
        validate_identity({**identity, "curve25519": other["curve25519"]})


def test_signed_prekey_claim_requires_the_verified_contact():
    account = Account()
    identity = identity_from_account(account)
    account.generate_one_time_keys(1)
    key_id, public_key = next(iter(account.one_time_keys.items()))
    key = public_key.to_base64()
    signature = account.sign(prekey_signing_bytes(identity["id"], key_id, key)).to_base64()
    prekey = {"id": key_id, "key": key, "signature": signature}
    assert validate_bundle({"identity": identity, "prekeys": [prekey]})["prekeys"] == [prekey]
    claim = {"identity": identity, "prekey": prekey}
    assert validate_claim(claim, identity) == claim
    with pytest.raises(ValidationError):
        validate_claim(claim, identity_from_account(Account()))


def test_transport_proof_is_bound_to_challenge_and_identity():
    account = Account()
    identity = identity_from_account(account)
    proof = auth_bytes("12" * 32, identity["id"])
    signature = account.sign(proof).to_base64()
    verify_signature(identity, proof, signature)
    with pytest.raises(ValidationError):
        verify_signature(identity, auth_bytes("34" * 32, identity["id"]), signature)
    tls_proof = auth_bytes("12" * 32, identity["id"], "tls-server-end-point:sha256:" + "ab" * 32)
    tls_signature = account.sign(tls_proof).to_base64()
    verify_signature(identity, tls_proof, tls_signature)
    with pytest.raises(ValidationError):
        verify_signature(identity, proof, tls_signature)
    with pytest.raises(ValidationError):
        verify_signature(identity, auth_bytes("12" * 32, identity["id"],
                         "tls-server-end-point:sha256:" + "cd" * 32), tls_signature)
    with pytest.raises(ValidationError):
        auth_bytes("12" * 32, identity["id"], "tls-server-end-point:sha256:" + "ab" * 31)


def test_envelope_only_accepts_public_routing_and_ciphertext_fields():
    envelope = {
        "v": 1, "sender": "a" * 64, "recipient": "b" * 64,
        "message_id": "c" * 32,
        "session_id": base64.b64encode(bytes(32)).decode().rstrip("="),
        "message_type": 0, "ciphertext": base64.b64encode(b"opaque bytes").decode(),
    }
    assert validate_envelope(envelope) == envelope
    with pytest.raises(ValidationError):
        validate_envelope({**envelope, "text": "not an envelope field"})
    with pytest.raises(ValidationError):
        validate_envelope({**envelope, "message_type": True})

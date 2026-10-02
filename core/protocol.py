"""Public wire formats. This module never creates or stores private identity keys."""

import base64
import hashlib
import json
import re

from vodozemac import Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature

PROTOCOL = "securecomm-olm-v1"
MAX_FRAME_BYTES = 131072
MAX_TEXT_BYTES = 16384
MAX_PREKEYS = 100
IDENTITY_DOMAIN = b"SecureComm identity v1\x00"


class ValidationError(ValueError):
    """Invalid public data; error messages deliberately exclude input content."""


def canonical_bytes(value):
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValidationError("Invalid JSON data") from exc


def _fields(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ValidationError("Invalid object fields")


def require_id(value, length=64):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{%d}" % length, value) is None:
        raise ValidationError("Invalid identifier")
    return value


def _public_key(value):
    if not isinstance(value, str) or len(value) != 43:
        raise ValidationError("Invalid public key")
    try:
        raw = base64.b64decode(value + "=", validate=True)
    except (ValueError, TypeError) as exc:
        raise ValidationError("Invalid public key") from exc
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ValidationError("Invalid public key")
    return raw


def identity_from_account(account):
    ed = account.ed25519_key.to_base64()
    curve = account.curve25519_key.to_base64()
    identity_id = hashlib.sha256(IDENTITY_DOMAIN + _public_key(ed) + _public_key(curve)).hexdigest()
    return {"v": 1, "id": identity_id, "ed25519": ed, "curve25519": curve}


def validate_identity(value):
    _fields(value, ("v", "id", "ed25519", "curve25519"))
    if type(value["v"]) is not int or value["v"] != 1:
        raise ValidationError("Unsupported identity version")
    ed, curve = _public_key(value["ed25519"]), _public_key(value["curve25519"])
    require_id(value["id"])
    expected = hashlib.sha256(IDENTITY_DOMAIN + ed + curve).hexdigest()
    if value["id"] != expected:
        raise ValidationError("Identity fingerprint mismatch")
    try:
        Ed25519PublicKey.from_base64(value["ed25519"])
        Curve25519PublicKey.from_base64(value["curve25519"])
    except ValueError as exc:
        raise ValidationError("Invalid identity keys") from exc
    return dict(value)


def verify_signature(identity, payload, signature):
    identity = validate_identity(identity)
    if not isinstance(signature, str) or len(signature) not in (86, 88):
        raise ValidationError("Invalid signature")
    try:
        key = Ed25519PublicKey.from_base64(identity["ed25519"])
        key.verify_signature(payload, Ed25519Signature.from_base64(signature))
    except ValueError as exc:
        raise ValidationError("Signature verification failed") from exc


def prekey_signing_bytes(owner, key_id, key):
    require_id(owner)
    if not isinstance(key_id, str) or re.fullmatch(r"[A-Za-z0-9+/_=-]{1,64}", key_id) is None:
        raise ValidationError("Invalid prekey identifier")
    _public_key(key)
    return canonical_bytes({"protocol": PROTOCOL, "owner": owner, "key_id": key_id, "key": key})


def validate_prekey(identity, prekey):
    identity = validate_identity(identity)
    _fields(prekey, ("id", "key", "signature"))
    signed = prekey_signing_bytes(identity["id"], prekey["id"], prekey["key"])
    verify_signature(identity, signed, prekey["signature"])
    return dict(prekey)


def validate_bundle(bundle):
    _fields(bundle, ("identity", "prekeys"))
    identity = validate_identity(bundle["identity"])
    if type(bundle["prekeys"]) is not list or len(bundle["prekeys"]) > MAX_PREKEYS:
        raise ValidationError("Invalid prekey count")
    prekeys = [validate_prekey(identity, item) for item in bundle["prekeys"]]
    if len({item["id"] for item in prekeys}) != len(prekeys):
        raise ValidationError("Duplicate prekey identifiers")
    return {"identity": identity, "prekeys": prekeys}


def validate_claim(claim, expected_identity=None):
    _fields(claim, ("identity", "prekey"))
    identity = validate_identity(claim["identity"])
    if expected_identity is not None:
        expected_id = expected_identity if isinstance(expected_identity, str) else validate_identity(expected_identity)["id"]
        if identity["id"] != expected_id:
            raise ValidationError("Prekey does not belong to the verified contact")
    return {"identity": identity, "prekey": validate_prekey(identity, claim["prekey"])}


def validate_envelope(value):
    _fields(value, ("v", "sender", "recipient", "message_id", "session_id", "message_type", "ciphertext"))
    if type(value["v"]) is not int or value["v"] != 1:
        raise ValidationError("Unsupported envelope version")
    require_id(value["sender"])
    require_id(value["recipient"])
    require_id(value["message_id"], 32)
    _public_key(value["session_id"])
    if type(value["message_type"]) is not int or value["message_type"] not in (0, 1):
        raise ValidationError("Invalid message type")
    encoded = value["ciphertext"]
    if not isinstance(encoded, str) or not 1 <= len(encoded) <= MAX_FRAME_BYTES // 2:
        raise ValidationError("Invalid ciphertext length")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValidationError("Invalid ciphertext encoding") from exc
    if not decoded or base64.b64encode(decoded).decode("ascii") != encoded:
        raise ValidationError("Invalid ciphertext encoding")
    return dict(value)


def auth_bytes(nonce, identity_id, channel_binding="loopback-plain"):
    require_id(nonce)
    require_id(identity_id)
    if channel_binding != "loopback-plain":
        if not isinstance(channel_binding, str):
            raise ValidationError("Invalid transport binding")
        match = re.fullmatch(r"tls-server-end-point:(sha256|sha384|sha512):([0-9a-f]+)", channel_binding)
        if match is None or len(match[2]) != {"sha256": 64, "sha384": 96, "sha512": 128}[match[1]]:
            raise ValidationError("Invalid transport binding")
    return canonical_bytes({"protocol": PROTOCOL, "op": "authenticate", "nonce": nonce,
                            "identity": identity_id, "channel_binding": channel_binding})

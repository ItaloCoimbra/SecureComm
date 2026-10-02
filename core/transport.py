"""Bounded JSON framing and public-identity proof of possession.

TLS authenticates remote endpoints and protects transport operations. Olm
separately encrypts conversations so a relay cannot decrypt their contents.
Plain TCP is restricted to numeric loopback (or localhost mapped without DNS).
"""

import asyncio
import hashlib
import ipaddress
import json
from pathlib import Path
import secrets
import ssl
import struct
import sys

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from core.protocol import (
    MAX_FRAME_BYTES, ValidationError, auth_bytes, canonical_bytes,
    validate_identity, verify_signature,
)

DEFAULT_TIMEOUT = 10.0


class TransportError(RuntimeError):
    """Public error which never includes packet contents."""


def _normalized_host(host):
    if not isinstance(host, str) or not host or "%" in host:
        raise TransportError("invalid TLS endpoint")
    if host.lower() == "localhost":
        return "127.0.0.1", True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host, False
    return str(address), address.is_loopback


def _validate_tls(context, *, server):
    expected = ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT
    if (not isinstance(context, ssl.SSLContext) or context.protocol != expected
            or context.minimum_version < ssl.TLSVersion.TLSv1_2):
        raise TransportError("verified TLS 1.2 or newer is required")
    if not server and (context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname):
        raise TransportError("verified TLS certificates and hostname are required")
    if server and not isinstance(getattr(context, "_securecomm_certificate_der", None), bytes):
        raise TransportError("TLS certificate binding requires make_server_tls_context")


def _certificate_binding(der):
    """RFC 5929 server-end-point binding; this is not a unique-channel binding.

    Identical leaf certificates identify the same TLS authority. Python's TLS
    exporter API is unavailable, so tls-unique is never assumed for TLS 1.3.
    """
    try:
        certificate = x509.load_der_x509_certificate(der)
        algorithm = certificate.signature_hash_algorithm
        name = algorithm.name if algorithm is not None else ""
        if name in ("md5", "sha1"):
            name = "sha256"
        if name not in ("sha256", "sha384", "sha512"):
            raise ValueError("unsupported certificate signature hash")
        return "tls-server-end-point:" + name + ":" + hashlib.new(name, der).hexdigest()
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise TransportError("TLS certificate must use a supported SHA-256, SHA-384 or SHA-512 signature") from None


def make_server_tls_context(certfile, keyfile):
    """Load a PEM chain/key and retain its public leaf for local endpoint binding."""
    try:
        certificate = x509.load_pem_x509_certificate(Path(certfile).read_bytes())
        der = certificate.public_bytes(serialization.Encoding.DER)
        _certificate_binding(der)  # Reject undefined binding algorithms before listening.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.options |= ssl.OP_NO_RENEGOTIATION
        # An empty password avoids an interactive OpenSSL prompt for encrypted keys.
        context.load_cert_chain(certfile, keyfile, password="")
        context._securecomm_certificate_der = der
        return context
    except TransportError:
        raise
    except (OSError, ValueError, UnsupportedAlgorithm):
        raise TransportError("TLS certificate or key could not be loaded") from None


def _channel_binding(writer, *, server):
    tls = writer.get_extra_info("ssl_object")
    if tls is None:
        return "loopback-plain"
    _validate_tls(tls.context, server=server)
    if server:
        certificate = tls.context._securecomm_certificate_der
    else:
        certificate = tls.getpeercert(binary_form=True)
    if not certificate:
        raise TransportError("TLS certificate binding unavailable")
    return _certificate_binding(certificate)


def validate_server_transport(host, ssl_context=None):
    """Validate a bind before opening files or sockets; return its safe host."""
    normalized, loopback = _normalized_host(host)
    if ssl_context is None:
        if not loopback:
            raise TransportError("TLS is required outside loopback")
    else:
        _validate_tls(ssl_context, server=True)
    return normalized


def tls_options(ssl_context, timeout=DEFAULT_TIMEOUT):
    """Stream options shared by listeners and connections, including deadlines."""
    if ssl_context is None:
        return {}
    options = {"ssl": ssl_context, "ssl_handshake_timeout": timeout}
    if sys.version_info >= (3, 11):
        options["ssl_shutdown_timeout"] = 1.0
    return options


async def connect_transport(host, port, *, ssl_context=None, timeout=DEFAULT_TIMEOUT):
    """Connect with certificate/hostname verification, or local-only plain TCP."""
    normalized, loopback = _normalized_host(host)
    if ssl_context is None:
        if not loopback:
            raise TransportError("TLS is required outside loopback")
        options = {}
    else:
        _validate_tls(ssl_context, server=False)
        options = tls_options(ssl_context, timeout)
        # Preserve the requested certificate name even for DNS-free localhost.
        options["server_hostname"] = host
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(normalized, port, limit=MAX_FRAME_BYTES, **options), timeout)
    except (OSError, ValueError, asyncio.TimeoutError):
        raise TransportError("transport unavailable") from None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("non-finite number")


async def read_packet(reader, *, timeout=DEFAULT_TIMEOUT):
    """Read one object with a single deadline for both length and payload."""
    async def read():
        length = struct.unpack("!I", await reader.readexactly(4))[0]
        if not 0 < length <= MAX_FRAME_BYTES:
            raise TransportError("invalid packet")
        raw = await reader.readexactly(length)
        try:
            packet = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                                parse_constant=_reject_constant)
            if type(packet) is not dict:
                raise ValueError("not an object")
            # Reject invalid Unicode and overflowing numeric literals as well.
            canonical_bytes(packet)
            return packet
        except (ValueError, UnicodeError, RecursionError):
            raise TransportError("invalid packet") from None
    try:
        return await asyncio.wait_for(read(), timeout)
    except (OSError, EOFError, asyncio.IncompleteReadError, asyncio.TimeoutError):
        raise TransportError("transport unavailable") from None


async def write_packet(writer, packet, *, timeout=DEFAULT_TIMEOUT):
    try:
        if type(packet) is not dict:
            raise ValidationError("not an object")
        raw = canonical_bytes(packet)
        if not 0 < len(raw) <= MAX_FRAME_BYTES:
            raise ValidationError("size")
    except ValidationError:
        raise TransportError("invalid packet") from None
    try:
        writer.write(struct.pack("!I", len(raw)) + raw)
        await asyncio.wait_for(writer.drain(), timeout)
    except (OSError, RuntimeError, asyncio.TimeoutError):
        raise TransportError("transport unavailable") from None


async def close_writer(writer):
    """Close a stream without making shutdown depend on a remote peer."""
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 1.0)
    except (OSError, RuntimeError, asyncio.TimeoutError):
        writer.transport.abort()


async def authenticate_client(reader, writer, identity, signer, *, timeout=DEFAULT_TIMEOUT):
    try:
        identity = validate_identity(identity)
        channel_binding = _channel_binding(writer, server=False)
        await write_packet(writer, {"op": "hello", "identity": identity}, timeout=timeout)
        challenge = await read_packet(reader, timeout=timeout)
        if set(challenge) != {"op", "nonce"} or challenge["op"] != "challenge":
            raise ValidationError("challenge")
        signature = signer(auth_bytes(challenge["nonce"], identity["id"], channel_binding))
        await write_packet(writer, {"op": "auth", "signature": signature}, timeout=timeout)
        if await read_packet(reader, timeout=timeout) != {"op": "authenticated"}:
            raise ValidationError("authentication")
    except asyncio.CancelledError:
        await close_writer(writer)
        raise
    except Exception:
        await close_writer(writer)
        raise TransportError("authentication failed") from None


async def authenticate_server(reader, writer, *, timeout=DEFAULT_TIMEOUT):
    try:
        channel_binding = _channel_binding(writer, server=True)
        hello = await read_packet(reader, timeout=timeout)
        if set(hello) != {"op", "identity"} or hello["op"] != "hello":
            raise ValidationError("hello")
        identity = validate_identity(hello["identity"])
        nonce = secrets.token_hex(32)
        await write_packet(writer, {"op": "challenge", "nonce": nonce}, timeout=timeout)
        proof = await read_packet(reader, timeout=timeout)
        if set(proof) != {"op", "signature"} or proof["op"] != "auth":
            raise ValidationError("proof")
        verify_signature(identity, auth_bytes(nonce, identity["id"], channel_binding), proof["signature"])
        await write_packet(writer, {"op": "authenticated"}, timeout=timeout)
        return identity
    except asyncio.CancelledError:
        await close_writer(writer)
        raise
    except Exception:
        await close_writer(writer)
        raise TransportError("authentication failed") from None

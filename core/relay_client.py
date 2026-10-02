"""Small authenticated client for relay mailboxes; no private keys are retained."""

import asyncio

from core.protocol import ValidationError, validate_claim, validate_envelope
from core.transport import (
    DEFAULT_TIMEOUT, TransportError, authenticate_client, close_writer, connect_transport,
    read_packet, write_packet,
)


ERROR_CODES = frozenset({
    "invalid_request", "forbidden", "recipient_unavailable", "prekey_unavailable",
    "prekey_conflict", "prekey_limit", "message_conflict", "queue_full",
    "account_limit", "server_unavailable", "request_limit",
})


class RelayError(RuntimeError):
    """Stable public error code; never echo untrusted relay data."""

    def __init__(self, code):
        self.code = code if isinstance(code, str) and code in ERROR_CODES else "server_unavailable"
        super().__init__(self.code)


class RelayConnection:
    def __init__(self, reader, writer, identity, timeout):
        self.reader, self.writer = reader, writer
        self.identity = dict(identity)
        self.timeout = timeout
        self._lock = asyncio.Lock()
        self._closed = False

    @classmethod
    async def connect(cls, host, port, identity, signer, *, timeout=DEFAULT_TIMEOUT, ssl_context=None):
        reader, writer = await connect_transport(host, port, ssl_context=ssl_context, timeout=timeout)
        await authenticate_client(reader, writer, identity, signer, timeout=timeout)
        return cls(reader, writer, identity, timeout)

    async def request(self, op, **fields):
        async with self._lock:
            if self._closed:
                raise TransportError("transport unavailable")
            try:
                await write_packet(self.writer, {"op": op, **fields}, timeout=self.timeout)
                response = await read_packet(self.reader, timeout=self.timeout)
                if type(response.get("ok")) is not bool:
                    raise TransportError("invalid packet")
            except (TransportError, asyncio.CancelledError):
                await self.close()
                raise
            if not response["ok"]:
                raise RelayError(response.get("error"))
            return response

    async def publish(self, bundle):
        return await self.request("publish", bundle=bundle)

    async def claim(self, recipient):
        response = await self.request("claim", recipient=recipient)
        try:
            return validate_claim({"identity": response.get("identity"), "prekey": response.get("prekey")}, recipient)
        except ValidationError:
            raise RelayError("invalid_request") from None

    async def send(self, envelope):
        return await self.request("send", envelope=envelope)

    async def fetch(self, limit=50):
        response = await self.request("fetch", limit=limit)
        try:
            messages = response.get("envelopes")
            if type(messages) is not list or len(messages) > limit:
                raise ValidationError("list")
            result = [validate_envelope(item) for item in messages]
            if any(item["recipient"] != self.identity["id"] for item in result):
                raise ValidationError("recipient")
            return result
        except (ValidationError, TypeError):
            raise RelayError("invalid_request") from None

    async def ack(self, ids):
        return await self.request("ack", ids=ids)

    async def status(self):
        return await self.request("status")

    async def close(self):
        if not self._closed:
            self._closed = True
            await close_writer(self.writer)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.close()

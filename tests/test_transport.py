"""Bounded framing and proof-of-possession, using only synthetic identities."""

import asyncio
import importlib.util
import struct

import pytest


def transport():
    assert importlib.util.find_spec("core.transport") is not None, "transport implementation missing"
    from core import transport as module
    return module


def test_packet_fragmentation_and_coalescing():
    async def scenario():
        module = transport()
        reader = asyncio.StreamReader()
        first = b'{"ok":true}'
        second = b'{"value":17}'
        combined = struct.pack("!I", len(first)) + first + struct.pack("!I", len(second)) + second

        async def feed():
            for chunk in (combined[:2], combined[2:9], combined[9:]):
                reader.feed_data(chunk)
                await asyncio.sleep(0)
        task = asyncio.create_task(feed())
        assert await module.read_packet(reader) == {"ok": True}
        assert await module.read_packet(reader) == {"value": 17}
        await task
    asyncio.run(scenario())


@pytest.mark.parametrize("payload", [b'[]', b'{"a":1,"a":2}', b'{"a":NaN}', b'\xff', b'{'])
def test_packet_rejects_ambiguous_or_invalid_json(payload):
    async def scenario():
        module = transport()
        reader = asyncio.StreamReader()
        reader.feed_data(struct.pack("!I", len(payload)) + payload)
        with pytest.raises(module.TransportError, match="invalid packet"):
            await module.read_packet(reader)
    asyncio.run(scenario())


def test_packet_rejects_size_before_reading_payload_and_times_out():
    async def scenario():
        module = transport()
        for size in (0, module.MAX_FRAME_BYTES + 1):
            reader = asyncio.StreamReader()
            reader.feed_data(struct.pack("!I", size))
            with pytest.raises(module.TransportError, match="invalid packet"):
                await module.read_packet(reader, timeout=0.05)
        with pytest.raises(module.TransportError, match="transport unavailable"):
            await module.read_packet(asyncio.StreamReader(), timeout=0.01)
    asyncio.run(scenario())


def test_authenticated_roundtrip_and_wrong_signer():
    async def scenario():
        module = transport()
        from core.protocol import identity_from_account
        from vodozemac import Account
        account, impostor = Account(), Account()
        identity = identity_from_account(account)
        seen = []

        async def handler(reader, writer):
            try:
                seen.append(await module.authenticate_server(reader, writer, timeout=1))
                value = await module.read_packet(reader, timeout=1)
                await module.write_packet(writer, value)
            except module.TransportError:
                pass
            finally:
                await module.close_writer(writer)
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        try:
            host, port = server.sockets[0].getsockname()[:2]
            reader, writer = await asyncio.open_connection(host, port)
            await module.authenticate_client(reader, writer, identity, lambda value: account.sign(value).to_base64())
            await module.write_packet(writer, {"synthetic": "message"})
            assert await module.read_packet(reader) == {"synthetic": "message"}
            await module.close_writer(writer)
            reader, writer = await asyncio.open_connection(host, port)
            with pytest.raises(module.TransportError):
                await module.authenticate_client(reader, writer, identity, lambda value: impostor.sign(value).to_base64(), timeout=1)
            await module.close_writer(writer)
            assert seen == [identity]
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(scenario())

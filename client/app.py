"""Client-owned E2EE over direct connections or independent opaque relays."""

import asyncio
import contextlib

from core.e2ee import CapacityError, Messenger
from core.identity import ContactError, VaultError
from core.protocol import MAX_FRAME_BYTES, canonical_bytes, require_id
from core.relay_client import RelayConnection, RelayError
from core.transport import (
    TransportError, authenticate_client, authenticate_server, close_writer,
    connect_transport, read_packet, tls_options, validate_server_transport, write_packet,
)


DIRECT_BATCH_SIZE = 50


class DeliveryError(RuntimeError):
    """Delivery did not finish; already prepared ciphertext stays in the outbox."""


class SecureClient:
    def __init__(self, vault):
        self.vault = vault
        self.messenger = Messenger(vault)
        self.received = asyncio.Queue(maxsize=1000)
        self.errors = asyncio.Queue(maxsize=100)
        self._server = None
        self._writers = set()
        self._tasks = set()
        self._relays = {}
        self._sync_locks = {}

    @property
    def address(self):
        if self._server is None:
            raise RuntimeError("Direct listener is not running")
        return self._server.sockets[0].getsockname()[:2]

    async def start(self, host="127.0.0.1", port=0, *, ssl_context=None):
        if self._server is not None:
            raise RuntimeError("Direct listener is already running")
        host = validate_server_transport(host, ssl_context)
        self._server = await asyncio.start_server(
            self._handle_direct, host, port, **tls_options(ssl_context)
        )
        return self.address

    def _notify(self, event):
        if event is not None:
            # Durable history is authoritative if a UI consumer falls behind.
            if self.received.full():
                self.received.get_nowait()
            self.received.put_nowait(event)

    def _report_error(self, code):
        if not self.errors.full():
            self.errors.put_nowait(code)

    def _can_submit(self, envelope):
        # Recheck a detached batch after previous network awaits. An operation
        # already handed to the transport cannot be recalled by local revocation.
        with self.vault.transaction_lock:
            try:
                self.vault.require_contact_id(envelope["recipient"])
            except ContactError:
                return False
            entry = self.vault.snapshot()["outbox"].get(envelope["message_id"])
            return entry is not None and entry["envelope"] == envelope

    async def _request(self, reader, writer, packet):
        await write_packet(writer, packet)
        response = await read_packet(reader)
        if response.get("ok") is not True:
            raise DeliveryError("Peer did not accept the operation")
        return response

    def _direct_pending(self, peer_id):
        batch = []
        for envelope in self.messenger.pending_envelopes(recipient=peer_id):
            candidate = batch + [envelope]
            if len(candidate) > DIRECT_BATCH_SIZE or len(canonical_bytes({"ok": True, "envelopes": candidate})) > MAX_FRAME_BYTES - 1024:
                break
            batch = candidate
        return batch

    async def _handle_direct(self, reader, writer):
        if len(self._writers) >= 32:
            await close_writer(writer)
            return
        task = asyncio.current_task()
        self._writers.add(writer)
        self._tasks.add(task)
        try:
            identity = await authenticate_server(reader, writer)
            peer_id = identity["id"]
            self.vault.require_contact_id(peer_id)
            for _ in range(200):
                packet = await read_packet(reader)
                self.vault.require_contact_id(peer_id)
                op = packet.get("op")
                if op == "claim" and set(packet) == {"op"}:
                    bundle = self.messenger.issue_prekeys(1, pool="direct:" + peer_id)
                    if not bundle["prekeys"]:
                        await write_packet(writer, {"ok": False, "error": "prekeys_unavailable"})
                        continue
                    response = {"ok": True, "claim": {"identity": bundle["identity"], "prekey": bundle["prekeys"][0]}}
                elif op == "send" and set(packet) == {"op", "envelope"}:
                    envelope = packet["envelope"]
                    if type(envelope) is not dict or envelope.get("sender") != peer_id:
                        raise ValueError("Unexpected sender")
                    event = self.messenger.receive(envelope)
                    self._notify(event)
                    response = {"ok": True, "stored": True}
                elif op == "fetch" and set(packet) == {"op"}:
                    response = {"ok": True, "envelopes": self._direct_pending(peer_id)}
                elif op == "ack" and set(packet) == {"op", "ids"}:
                    ids = packet["ids"]
                    if type(ids) is not list or len(ids) > 50:
                        raise ValueError("Invalid acknowledgement")
                    for message_id in ids:
                        require_id(message_id, 32)
                    allowed = {item["message_id"] for item in self.messenger.pending_envelopes(recipient=peer_id)}
                    for message_id in ids:
                        if message_id in allowed:
                            self.messenger.mark_submitted(message_id)
                    response = {"ok": True}
                else:
                    raise ValueError("Unsupported operation")
                await write_packet(writer, response)
        except ContactError:
            with contextlib.suppress(TransportError, OSError):
                await write_packet(writer, {"ok": False, "error": "message_not_accepted"})
        except VaultError:
            self._report_error("local_storage_unavailable")
        except (ValueError, ContactError):
            with contextlib.suppress(TransportError, OSError):
                await write_packet(writer, {"ok": False, "error": "message_not_accepted"})
        except (TransportError, OSError, asyncio.TimeoutError):
            pass
        finally:
            self._tasks.discard(task)
            self._writers.discard(writer)
            await close_writer(writer)

    async def _open_direct(self, host, port, *, ssl_context=None):
        try:
            reader, writer = await connect_transport(host, port, ssl_context=ssl_context)
        except (TransportError, OSError, asyncio.TimeoutError) as exc:
            raise DeliveryError("Direct peer is unavailable") from exc
        try:
            await authenticate_client(reader, writer, self.vault.public_identity(), self.vault.sign)
        except BaseException:
            await close_writer(writer)
            raise
        return reader, writer

    async def _exchange_direct(self, alias, reader, writer):
        peer_id = self.vault.get_contact(alias)["identity"]["id"]
        for envelope in self.messenger.pending_envelopes(recipient=peer_id)[:DIRECT_BATCH_SIZE]:
            if not self._can_submit(envelope):
                continue
            await self._request(reader, writer, {"op": "send", "envelope": envelope})
            self.messenger.mark_submitted(envelope["message_id"])
        response = await self._request(reader, writer, {"op": "fetch"})
        envelopes = response.get("envelopes")
        if type(envelopes) is not list or len(envelopes) > 50:
            raise DeliveryError("Invalid peer response")
        received = []
        ids = []
        for envelope in envelopes:
            if type(envelope) is not dict or envelope.get("sender") != peer_id:
                raise DeliveryError("Unexpected peer identity")
            event = self.messenger.receive(envelope)
            self._notify(event)
            if event is not None:
                received.append(event)
            ids.append(envelope["message_id"])
        if ids:
            await self._request(reader, writer, {"op": "ack", "ids": ids})
        # Newly generated encrypted receipts confirm peer messages, not socket ACKs.
        for envelope in self.messenger.pending_envelopes(recipient=peer_id, receipts_only=True)[:DIRECT_BATCH_SIZE]:
            if not self._can_submit(envelope):
                continue
            await self._request(reader, writer, {"op": "send", "envelope": envelope})
            self.messenger.mark_submitted(envelope["message_id"])
        return received

    async def send_direct(self, alias, text, host, port, *, ssl_context=None):
        self.vault.get_contact(alias)
        reader, writer = await self._open_direct(host, port, ssl_context=ssl_context)
        try:
            claim = None
            if self.messenger.needs_prekey(alias):
                response = await self._request(reader, writer, {"op": "claim"})
                claim = response.get("claim")
            envelope = self.messenger.prepare_message(alias, text, claim)
            await self._exchange_direct(alias, reader, writer)
            return envelope["message_id"]
        finally:
            await close_writer(writer)

    async def sync_direct(self, alias, host, port, *, ssl_context=None):
        self.vault.get_contact(alias)
        reader, writer = await self._open_direct(host, port, ssl_context=ssl_context)
        try:
            return await self._exchange_direct(alias, reader, writer)
        finally:
            await close_writer(writer)

    async def _publish_prekeys(self, relay):
        status = await relay.status()
        pool = self._relays[relay]
        cached = pool in self.vault.snapshot().get("prekey_bundles", {})
        if cached or status["prekeys"] < 5:
            bundle = self.messenger.issue_prekeys(20, pool=pool)
            if bundle["prekeys"]:
                await relay.publish(bundle)
                self.messenger.ack_prekey_bundle(pool)
            elif status["prekeys"] == 0:
                self._report_error("prekeys_exhausted")

    async def connect_relay(self, host, port, *, ssl_context=None):
        relay = await RelayConnection.connect(
            host, port, self.vault.public_identity(), self.vault.sign, ssl_context=ssl_context
        )
        self._relays[relay] = f"relay:{host}:{port}"
        self._sync_locks[relay] = asyncio.Lock()
        try:
            await self._publish_prekeys(relay)
        except BaseException:
            self._relays.pop(relay, None)
            self._sync_locks.pop(relay, None)
            await relay.close()
            raise
        return relay

    async def send_via_relay(self, alias, text, relay):
        peer = self.vault.get_contact(alias)["identity"]
        claim = await relay.claim(peer["id"]) if self.messenger.needs_prekey(alias) else None
        envelope = self.messenger.prepare_message(alias, text, claim)
        await relay.send(envelope)
        self.messenger.mark_submitted(envelope["message_id"])
        return envelope["message_id"]

    async def disconnect_relay(self, relay):
        self._relays.pop(relay, None)
        self._sync_locks.pop(relay, None)
        await relay.close()

    async def _flush_relay(self, relay):
        for envelope in self.messenger.pending_envelopes():
            if not self._can_submit(envelope):
                continue
            try:
                await relay.send(envelope)
            except RelayError as exc:
                # An independent relay may not host every contact's mailbox.
                if exc.code in {"recipient_unavailable", "queue_full"}:
                    if exc.code == "queue_full":
                        self._report_error("remote_queue_full")
                    continue
                raise
            self.messenger.mark_submitted(envelope["message_id"])

    async def sync_relay(self, relay):
        if relay not in self._sync_locks:
            raise DeliveryError("Relay is not connected")
        async with self._sync_locks[relay]:
            received = []
            for _ in range(4):
                envelopes = await relay.fetch(limit=50)
                acknowledged = []
                capacity_blocked = False
                for envelope in envelopes:
                    try:
                        event = self.messenger.receive(envelope)
                    except ContactError:
                        self._report_error("untrusted_message_discarded")
                    except CapacityError:
                        # Keep this item, but process receipts later in the batch.
                        capacity_blocked = True
                        continue
                    except VaultError:
                        # No ACK for a batch containing a failed durable commit.
                        # Previously committed items are safe to deduplicate on retry.
                        self._report_error("local_storage_unavailable")
                        raise
                    except (ValueError, ContactError):
                        # Reject untrusted/invalid messages without displaying content.
                        self._report_error("untrusted_message_discarded")
                    else:
                        self._notify(event)
                        if event is not None:
                            received.append(event)
                    acknowledged.append(envelope["message_id"])
                if acknowledged:
                    await relay.ack(acknowledged)
                await self._flush_relay(relay)
                if not capacity_blocked and len(envelopes) < 50:
                    break
            if capacity_blocked:
                self._report_error("local_capacity_exhausted")
                raise CapacityError("Pending message limit reached; remote messages retained")
            await self._publish_prekeys(relay)
            return received

    async def close(self):
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)
        for writer in list(self._writers):
            await close_writer(writer)
        self._writers.clear()
        for relay in list(self._relays):
            await relay.close()
        self._relays.clear()
        self._sync_locks.clear()

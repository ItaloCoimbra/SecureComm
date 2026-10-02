"""Opaque SQLite relay: public identities, signed prekeys and ciphertext only.

Requests have an ``op`` plus the named argument. Successful responses carry
``ok: true``; rejected requests carry ``ok: false, error: <static code>``.
No operation loads a vault, decrypts a conversation or logs request contents.
"""

import asyncio
import hashlib
import json
from pathlib import Path
import sqlite3
import time

from core.protocol import (
    MAX_FRAME_BYTES, ValidationError, canonical_bytes, require_id,
    validate_bundle, validate_envelope,
)
from core.transport import (
    TransportError, authenticate_server, close_writer, read_packet, write_packet,
    tls_options, validate_server_transport,
)


class _Rejected(Exception):
    pass


class RelayServer:
    """Single-event-loop server. All bounded database operations are atomic."""

    def __init__(self, db_path, host="127.0.0.1", port=0, *, max_connections=100,
                 max_accounts=10000, max_messages_per_account=1000,
                 max_messages=10000, max_queue_bytes=64 * 1024 * 1024,
                 max_account_bytes=8 * 1024 * 1024, max_prekeys_per_account=10000,
                 max_prekeys=100000, max_requests=1000, idle_timeout=30.0,
                 handshake_timeout=10.0, message_ttl=7 * 86400, ssl_context=None):
        limits = (max_connections, max_accounts, max_messages_per_account,
                  max_messages, max_queue_bytes, max_account_bytes,
                  max_prekeys_per_account, max_prekeys, max_requests)
        if any(type(item) is not int or item < 1 for item in limits):
            raise ValueError("relay limits must be positive integers")
        if min(idle_timeout, handshake_timeout, message_ttl) <= 0:
            raise ValueError("relay deadlines must be positive")
        self.db_path, self.host, self.port = Path(db_path), host, port
        self.ssl_context = ssl_context
        self.max_connections, self.max_accounts = max_connections, max_accounts
        self.max_messages_per_account, self.max_messages = max_messages_per_account, max_messages
        self.max_queue_bytes, self.max_account_bytes = max_queue_bytes, max_account_bytes
        self.max_prekeys_per_account, self.max_prekeys = max_prekeys_per_account, max_prekeys
        self.max_requests, self.idle_timeout = max_requests, idle_timeout
        self.handshake_timeout, self.message_ttl = handshake_timeout, message_ttl
        self._server = None
        self._db = None
        self._tasks = set()
        self._writers = set()
        self._closing = False

    @property
    def address(self):
        if self._server is None or not self._server.sockets:
            raise RuntimeError("relay is not running")
        return self._server.sockets[0].getsockname()[:2]

    async def start(self):
        if self._server is not None:
            raise RuntimeError("relay is already running")
        bind_host = validate_server_transport(self.host, self.ssl_context)
        self._closing = False
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.db_path, timeout=1)
        try:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS identities (
                    id TEXT PRIMARY KEY, public TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS prekeys (
                    owner TEXT NOT NULL REFERENCES identities(id),
                    id TEXT NOT NULL, public TEXT NOT NULL,
                    consumed INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(owner, id)
                );
                CREATE INDEX IF NOT EXISTS prekeys_available ON prekeys(owner, consumed);
                CREATE TABLE IF NOT EXISTS messages (
                    recipient TEXT NOT NULL REFERENCES identities(id),
                    id TEXT NOT NULL, envelope TEXT NOT NULL, digest TEXT NOT NULL,
                    size INTEGER NOT NULL, created REAL NOT NULL, expires REAL NOT NULL,
                    PRIMARY KEY(recipient, id)
                );
                CREATE INDEX IF NOT EXISTS messages_expiry ON messages(expires);
            """)
            self._cleanup()
            self._server = await asyncio.start_server(
                self._accept, bind_host, self.port, limit=MAX_FRAME_BYTES,
                backlog=self.max_connections, **tls_options(self.ssl_context, self.handshake_timeout))
        except BaseException:
            self._db.close()
            self._db = None
            raise
        return self

    def _accept(self, reader, writer):
        if self._closing or len(self._tasks) >= self.max_connections:
            writer.close()
            return
        task = asyncio.create_task(self._handle(reader, writer))
        self._tasks.add(task)
        self._writers.add(writer)
        task.add_done_callback(self._tasks.discard)

    async def _handle(self, reader, writer):
        try:
            identity = await authenticate_server(reader, writer, timeout=self.handshake_timeout)
            self._register(identity)
            for _ in range(self.max_requests):
                packet = await read_packet(reader, timeout=self.idle_timeout)
                response = self._dispatch(identity, packet)
                await write_packet(writer, response, timeout=self.idle_timeout)
            await write_packet(writer, {"ok": False, "error": "request_limit"}, timeout=self.idle_timeout)
        except _Rejected as exc:
            try:
                await write_packet(writer, {"ok": False, "error": str(exc)}, timeout=self.idle_timeout)
            except TransportError:
                pass
        except (TransportError, sqlite3.Error):
            pass
        finally:
            self._writers.discard(writer)
            await close_writer(writer)

    def _register(self, identity):
        encoded = canonical_bytes(identity).decode("utf-8")
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            row = self._db.execute("SELECT public FROM identities WHERE id=?", (identity["id"],)).fetchone()
            if row is not None:
                if row[0] != encoded:
                    raise _Rejected("forbidden")
                return
            if self._db.execute("SELECT COUNT(*) FROM identities").fetchone()[0] >= self.max_accounts:
                raise _Rejected("account_limit")
            self._db.execute("INSERT INTO identities(id,public) VALUES (?,?)", (identity["id"], encoded))

    def _cleanup(self):
        with self._db:
            self._db.execute("DELETE FROM messages WHERE expires<=?", (time.time(),))

    def _dispatch(self, identity, packet):
        try:
            self._cleanup()
            op = packet.get("op")
            fields = {"publish": {"op", "bundle"}, "claim": {"op", "recipient"},
                      "send": {"op", "envelope"}, "fetch": {"op", "limit"},
                      "ack": {"op", "ids"}, "status": {"op"}}
            if not isinstance(op, str) or op not in fields or set(packet) != fields[op]:
                raise _Rejected("invalid_request")
            return {"ok": True, **getattr(self, "_" + op)(identity, packet)}
        except ValidationError:
            return {"ok": False, "error": "invalid_request"}
        except _Rejected as exc:
            return {"ok": False, "error": str(exc)}
        except sqlite3.Error:
            return {"ok": False, "error": "server_unavailable"}

    def _publish(self, identity, packet):
        bundle = validate_bundle(packet["bundle"])
        if bundle["identity"] != identity:
            raise _Rejected("forbidden")
        owner = identity["id"]
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            total = self._db.execute("SELECT COUNT(*) FROM prekeys").fetchone()[0]
            own = self._db.execute("SELECT COUNT(*) FROM prekeys WHERE owner=?", (owner,)).fetchone()[0]
            inserted = 0
            for key in bundle["prekeys"]:
                encoded = canonical_bytes(key).decode("utf-8")
                row = self._db.execute("SELECT public FROM prekeys WHERE owner=? AND id=?", (owner, key["id"])).fetchone()
                if row is not None:
                    if row[0] != encoded:
                        raise _Rejected("prekey_conflict")
                    continue  # Includes consumed keys: publishing never resurrects them.
                if own + inserted >= self.max_prekeys_per_account or total + inserted >= self.max_prekeys:
                    raise _Rejected("prekey_limit")
                self._db.execute("INSERT INTO prekeys(owner,id,public) VALUES (?,?,?)", (owner, key["id"], encoded))
                inserted += 1
        return {"published": inserted}

    def _claim(self, identity, packet):
        owner = require_id(packet["recipient"])
        # A BEGIN IMMEDIATE keeps selection and consumption atomic even when
        # two relay processes intentionally share the same SQLite database.
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            public = self._db.execute("SELECT public FROM identities WHERE id=?", (owner,)).fetchone()
            if public is None:
                raise _Rejected("recipient_unavailable")
            row = self._db.execute("SELECT id,public FROM prekeys WHERE owner=? AND consumed=0 ORDER BY rowid LIMIT 1", (owner,)).fetchone()
            if row is None:
                raise _Rejected("prekey_unavailable")
            self._db.execute("UPDATE prekeys SET consumed=1 WHERE owner=? AND id=?", (owner, row[0]))
            return {"identity": json.loads(public[0]), "prekey": json.loads(row[1])}

    def _send(self, identity, packet):
        envelope = validate_envelope(packet["envelope"])
        if envelope["sender"] != identity["id"]:
            raise _Rejected("forbidden")
        recipient = envelope["recipient"]
        raw = canonical_bytes(envelope)
        digest = hashlib.sha256(raw).hexdigest()
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            if self._db.execute("SELECT 1 FROM identities WHERE id=?", (recipient,)).fetchone() is None:
                raise _Rejected("recipient_unavailable")
            existing = self._db.execute("SELECT digest FROM messages WHERE recipient=? AND id=?", (recipient, envelope["message_id"])).fetchone()
            if existing is not None:
                if existing[0] != digest:
                    raise _Rejected("message_conflict")
                return {"duplicate": True}
            count, size = self._db.execute("SELECT COUNT(*),COALESCE(SUM(size),0) FROM messages").fetchone()
            own_count, own_size = self._db.execute("SELECT COUNT(*),COALESCE(SUM(size),0) FROM messages WHERE recipient=?", (recipient,)).fetchone()
            if (count >= self.max_messages or own_count >= self.max_messages_per_account
                    or size + len(raw) > self.max_queue_bytes or own_size + len(raw) > self.max_account_bytes):
                raise _Rejected("queue_full")
            now = time.time()
            self._db.execute("INSERT INTO messages(recipient,id,envelope,digest,size,created,expires) VALUES (?,?,?,?,?,?,?)",
                             (recipient, envelope["message_id"], raw.decode("utf-8"), digest, len(raw), now, now + self.message_ttl))
        return {"duplicate": False}

    def _fetch(self, identity, packet):
        limit = packet["limit"]
        if type(limit) is not int or not 1 <= limit <= 100:
            raise _Rejected("invalid_request")
        rows = self._db.execute("SELECT envelope FROM messages WHERE recipient=? ORDER BY created,rowid LIMIT ?",
                                (identity["id"], limit)).fetchall()
        envelopes = []
        for row in rows:
            item = json.loads(row[0])
            if len(canonical_bytes({"ok": True, "envelopes": envelopes + [item]})) > MAX_FRAME_BYTES:
                break
            envelopes.append(item)
        return {"envelopes": envelopes}

    def _ack(self, identity, packet):
        ids = packet["ids"]
        if type(ids) is not list or len(ids) > 100:
            raise _Rejected("invalid_request")
        for message_id in ids:
            require_id(message_id, 32)
        acked = 0
        with self._db:
            for message_id in set(ids):
                cursor = self._db.execute("DELETE FROM messages WHERE recipient=? AND id=?", (identity["id"], message_id))
                acked += cursor.rowcount
        return {"acked": acked}

    def _status(self, identity, packet):
        owner = identity["id"]
        return {"prekeys": self._db.execute("SELECT COUNT(*) FROM prekeys WHERE owner=? AND consumed=0", (owner,)).fetchone()[0],
                "queued": self._db.execute("SELECT COUNT(*) FROM messages WHERE recipient=?", (owner,)).fetchone()[0]}

    async def close(self):
        self._closing = True
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        for writer in list(self._writers):
            writer.close()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self._db is not None:
            self._db.close()
            self._db = None

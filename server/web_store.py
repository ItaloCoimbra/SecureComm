"""Bounded opaque storage for the browser protocol, without user identities.

Capabilities authorize one queue or blob, not a person. Only their hashes are
stored. The operator can still observe traffic and queue relationships; this
module is not an anonymity system or a secure-erasure guarantee.
"""

import base64
import binascii
import hashlib
import hmac
import os
from pathlib import Path
import re
import sqlite3
import time
from contextlib import contextmanager


FRAME_BYTES = 32768
BLOB_BYTES = 65536
CONTENT_TTL = 7 * 24 * 60 * 60
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class StoreError(Exception):
    """Safe public error: never includes request values or SQLite diagnostics."""

    def __init__(self, code, status=None):
        self.code = code
        self.status = status or {"invalid_request": 400, "forbidden": 403,
                                 "conflict": 409, "consumed": 409,
                                 "capacity": 429}.get(code, 503)
        super().__init__(code)


def _fields(packet, expected):
    if not isinstance(packet, dict) or set(packet) != set(expected.split()):
        raise StoreError("invalid_request")


def _hex(value):
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        raise StoreError("invalid_request")
    return value


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise StoreError("invalid_request")
    return value


def _body(value, size):
    if not isinstance(value, str) or len(value) != 4 * ((size + 2) // 3):
        raise StoreError("invalid_request")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise StoreError("invalid_request") from None
    if len(decoded) != size or base64.b64encode(decoded).decode("ascii") != value:
        raise StoreError("invalid_request")
    return decoded


def _hash(token):
    return hashlib.sha256(_hex(token).encode("ascii")).hexdigest()


class WebStore:
    """Synchronous, process-safe SQLite store, used on the HTTP event-loop thread.

    Every check-plus-write uses BEGIN IMMEDIATE, including quota checks. Calls
    contain no await and connections are never shared across worker threads.
    Message tombstones preserve immutable retries until the original expiry;
    bounded record quotas include these tombstones.
    """

    def __init__(self, path, *, clock=time.time, max_queues=4096,
                 max_messages=32768, max_messages_per_queue=256,
                 max_records_per_queue=2048, max_message_bytes=128 * 1024 * 1024,
                 max_blobs=4096, max_blob_bytes=256 * 1024 * 1024):
        for value in (max_queues, max_messages, max_messages_per_queue,
                      max_records_per_queue, max_message_bytes, max_blobs, max_blob_bytes):
            if type(value) is not int or value <= 0:
                raise ValueError("store limits must be positive integers")
        self.clock = clock
        self.max_queues = max_queues
        self.max_messages = max_messages
        self.max_messages_per_queue = max_messages_per_queue
        self.max_records_per_queue = max_records_per_queue
        self.max_message_bytes = max_message_bytes
        self.max_blobs = max_blobs
        self.max_blob_bytes = max_blob_bytes
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, timeout=1)
        try:
            os.chmod(path, 0o600)
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA secure_delete=ON")
            existing = {row[0] for row in self._db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            if existing - {"queues", "messages", "blobs"}:
                raise ValueError("the web relay requires a separate database")
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS queues (
                    read_id TEXT PRIMARY KEY, write_id TEXT NOT NULL UNIQUE,
                    read_hash TEXT NOT NULL, write_hash TEXT NOT NULL,
                    ttl INTEGER NOT NULL, single_use INTEGER NOT NULL,
                    expires REAL NOT NULL, used_id TEXT, used_digest TEXT
                );
                CREATE INDEX IF NOT EXISTS queues_expiry ON queues(expires);
                CREATE TABLE IF NOT EXISTS messages (
                    read_id TEXT NOT NULL REFERENCES queues(read_id) ON DELETE CASCADE,
                    id TEXT NOT NULL, body BLOB, digest TEXT NOT NULL,
                    created REAL NOT NULL, expires REAL NOT NULL,
                    PRIMARY KEY(read_id,id)
                );
                CREATE INDEX IF NOT EXISTS messages_expiry ON messages(expires);
                CREATE INDEX IF NOT EXISTS messages_order ON messages(read_id,created);
                CREATE TABLE IF NOT EXISTS blobs (
                    id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, body BLOB NOT NULL,
                    digest TEXT NOT NULL, expires REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS blobs_expiry ON blobs(expires);
            """)
            self.cleanup()
        except BaseException:
            self._db.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self._db is not None:
            self._db.close()
            self._db = None

    def _expire(self, now):
        self._db.execute("DELETE FROM queues WHERE expires<=?", (now,))
        self._db.execute("DELETE FROM messages WHERE expires<=?", (now,))
        self._db.execute("DELETE FROM blobs WHERE expires<=?", (now,))

    @contextmanager
    def _transaction(self):
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            now = self.clock()
            self._expire(now)
            yield now

    def cleanup(self):
        """Expire rows even with no traffic; the HTTP lifecycle also calls this."""
        with self._transaction():
            pass

    def _authorize(self, field, identifier, token):
        # The column is selected internally, never from a request value.
        assert field in ("read_id", "write_id")
        token_hash = _hash(token)
        row = self._db.execute(f"SELECT * FROM queues WHERE {field}=?", (_hex(identifier),)).fetchone()
        expected = row["read_hash" if field == "read_id" else "write_hash"] if row else "0" * 64
        matches = hmac.compare_digest(expected, token_hash)
        if row is None or not matches:
            raise StoreError("forbidden")
        return row

    def create_queue(self, packet):
        _fields(packet, "read_id write_id read_hash write_hash ttl single_use")
        for field in ("read_id", "write_id", "read_hash", "write_hash"):
            _hex(packet[field])
        _integer(packet["ttl"], 60, 2592000)
        if (type(packet["single_use"]) is not bool or packet["read_id"] == packet["write_id"]
                or packet["read_hash"] == packet["write_hash"]):
            raise StoreError("invalid_request")
        with self._transaction() as now:
            old = self._db.execute(
                "SELECT * FROM queues WHERE read_id IN (?,?) OR write_id IN (?,?)",
                (packet["read_id"], packet["write_id"], packet["read_id"], packet["write_id"])).fetchall()
            if old:
                if len(old) == 1 and all(old[0][field] == packet[field] for field in packet):
                    return {"ok": True}
                raise StoreError("conflict")
            if self._db.execute("SELECT COUNT(*) FROM queues").fetchone()[0] >= self.max_queues:
                raise StoreError("capacity")
            self._db.execute("""INSERT INTO queues
                (read_id,write_id,read_hash,write_hash,ttl,single_use,expires)
                VALUES (?,?,?,?,?,?,?)""", (packet["read_id"], packet["write_id"],
                packet["read_hash"], packet["write_hash"], packet["ttl"],
                packet["single_use"], now + packet["ttl"]))
        return {"ok": True}

    def send(self, packet):
        _fields(packet, "write_id token id body")
        identifier = _hex(packet["id"])
        body = _body(packet["body"], FRAME_BYTES)
        digest = hashlib.sha256(body).hexdigest()
        with self._transaction() as now:
            queue = self._authorize("write_id", packet["write_id"], packet["token"])
            if queue["single_use"] and queue["used_id"] is not None:
                if queue["used_id"] == identifier:
                    if queue["used_digest"] == digest:
                        return {"ok": True}
                    raise StoreError("conflict")
                raise StoreError("consumed")
            previous = self._db.execute("SELECT digest FROM messages WHERE read_id=? AND id=?",
                                        (queue["read_id"], identifier)).fetchone()
            if previous:
                if previous["digest"] == digest:
                    return {"ok": True}
                raise StoreError("conflict")
            count, size = self._db.execute(
                "SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM messages").fetchone()
            own_records, own_pending = self._db.execute(
                "SELECT COUNT(*),COUNT(body) FROM messages WHERE read_id=?", (queue["read_id"],)).fetchone()
            if (count >= self.max_messages or size + FRAME_BYTES > self.max_message_bytes
                    or own_records >= self.max_records_per_queue
                    or own_pending >= self.max_messages_per_queue):
                raise StoreError("capacity")
            self._db.execute("INSERT INTO messages(read_id,id,body,digest,created,expires) VALUES (?,?,?,?,?,?)",
                             (queue["read_id"], identifier, body, digest, now,
                              min(now + CONTENT_TTL, queue["expires"])))
            if queue["single_use"]:
                self._db.execute("UPDATE queues SET used_id=?,used_digest=? WHERE read_id=?",
                                 (identifier, digest, queue["read_id"]))
        return {"ok": True}

    def read(self, packet):
        _fields(packet, "read_id token limit")
        limit = _integer(packet["limit"], 1, 16)
        with self._transaction() as now:
            queue = self._authorize("read_id", packet["read_id"], packet["token"])
            if not queue["single_use"]:
                self._db.execute("UPDATE queues SET expires=? WHERE read_id=?", (now + queue["ttl"], queue["read_id"]))
            items = self._db.execute("""SELECT id,body FROM messages
                WHERE read_id=? AND body IS NOT NULL ORDER BY created,rowid LIMIT ?""", (queue["read_id"], limit)).fetchall()
            return {"items": [{"id": row["id"], "body": base64.b64encode(row["body"]).decode("ascii")} for row in items]}

    def ack(self, packet):
        _fields(packet, "read_id token ids")
        ids = packet["ids"]
        if not isinstance(ids, list) or len(ids) > 16:
            raise StoreError("invalid_request")
        for identifier in ids:
            _hex(identifier)
        with self._transaction():
            queue = self._authorize("read_id", packet["read_id"], packet["token"])
            self._db.executemany("UPDATE messages SET body=NULL WHERE read_id=? AND id=?",
                                 ((queue["read_id"], identifier) for identifier in ids))
        return {"ok": True}

    def delete_queue(self, packet):
        _fields(packet, "read_id token")
        with self._transaction():
            queue = self._authorize("read_id", packet["read_id"], packet["token"])
            self._db.execute("DELETE FROM queues WHERE read_id=?", (queue["read_id"],))
        return {"ok": True}

    def put_blob(self, packet):
        _fields(packet, "id token body")
        identifier, token_hash = _hex(packet["id"]), _hash(packet["token"])
        body = _body(packet["body"], BLOB_BYTES)
        digest = hashlib.sha256(body).hexdigest()
        with self._transaction() as now:
            previous = self._db.execute("SELECT token_hash,digest FROM blobs WHERE id=?", (identifier,)).fetchone()
            if previous:
                if not hmac.compare_digest(previous["token_hash"], token_hash):
                    raise StoreError("forbidden")
                if previous["digest"] != digest:
                    raise StoreError("conflict")
                return {"ok": True}
            count, size = self._db.execute("SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM blobs").fetchone()
            if count >= self.max_blobs or size + BLOB_BYTES > self.max_blob_bytes:
                raise StoreError("capacity")
            self._db.execute("INSERT INTO blobs(id,token_hash,body,digest,expires) VALUES (?,?,?,?,?)",
                             (identifier, token_hash, body, digest, now + CONTENT_TTL))
        return {"ok": True}

    def _authorize_blob(self, packet):
        _fields(packet, "id token")
        identifier, token_hash = _hex(packet["id"]), _hash(packet["token"])
        row = self._db.execute("SELECT * FROM blobs WHERE id=?", (identifier,)).fetchone()
        matches = hmac.compare_digest(row["token_hash"] if row else "0" * 64, token_hash)
        if row is None or not matches:
            raise StoreError("forbidden")
        return row

    def get_blob(self, packet):
        with self._transaction():
            row = self._authorize_blob(packet)
            return {"body": base64.b64encode(row["body"]).decode("ascii")}

    def delete_blob(self, packet):
        with self._transaction():
            row = self._authorize_blob(packet)
            self._db.execute("DELETE FROM blobs WHERE id=?", (row["id"],))
        return {"ok": True}

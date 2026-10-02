"""Real SQLite tests for the identity-free browser relay contract."""

import base64
import hashlib
import importlib.util
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest


def modules():
    assert importlib.util.find_spec("server.web_store") is not None, "web capability store is not implemented"
    from server.web_store import StoreError, WebStore
    return WebStore, StoreError


def hexid(number):
    return f"{number:064x}"


def digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def queue(number=1, *, single_use=False, ttl=60):
    return {"read_id": hexid(number * 4), "write_id": hexid(number * 4 + 1),
            "read_hash": digest(hexid(number * 4 + 2)), "write_hash": digest(hexid(number * 4 + 3)),
            "ttl": ttl, "single_use": single_use}


def read_args(number=1):
    return {"read_id": hexid(number * 4), "token": hexid(number * 4 + 2)}


def frame(number=1, message=1, *, fill=b"x"):
    return {"write_id": hexid(number * 4 + 1), "token": hexid(number * 4 + 3),
            "id": hexid(message), "body": base64.b64encode(fill * 32768).decode("ascii")}


def test_queue_capabilities_and_ciphertext_survive_restart(tmp_path):
    WebStore, StoreError = modules()
    path = tmp_path / "web.sqlite"
    with WebStore(path) as store:
        assert store.create_queue(queue()) == {"ok": True}
        assert store.send(frame()) == {"ok": True}
        with pytest.raises(StoreError, match="forbidden"):
            store.read({**read_args(), "token": hexid(7), "limit": 16})
    with WebStore(path) as store:
        assert store.read({**read_args(), "limit": 16}) == {"items": [{"id": hexid(1), "body": frame()["body"]}]}
    with sqlite3.connect(path) as db:
        dump = "\n".join(db.iterdump())
        assert hexid(6) not in dump and hexid(7) not in dump
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert tables == {"queues", "messages", "blobs"}


def test_duplicate_create_and_send_are_immutable(tmp_path):
    WebStore, StoreError = modules()
    with WebStore(tmp_path / "web.sqlite") as store:
        store.create_queue(queue())
        assert store.create_queue(queue()) == {"ok": True}
        with pytest.raises(StoreError, match="conflict"):
            store.create_queue({**queue(), "ttl": 61})
        store.send(frame())
        assert store.send(frame()) == {"ok": True}
        with pytest.raises(StoreError, match="conflict"):
            store.send(frame(fill=b"y"))


def test_ack_and_delete_are_scoped_to_read_capability(tmp_path):
    WebStore, StoreError = modules()
    with WebStore(tmp_path / "web.sqlite") as store:
        for number in (1, 2):
            store.create_queue(queue(number))
            store.send(frame(number))
        store.ack({**read_args(2), "ids": [hexid(1)]})
        assert len(store.read({**read_args(1), "limit": 16})["items"]) == 1
        assert store.read({**read_args(2), "limit": 16})["items"] == []
        with pytest.raises(StoreError, match="forbidden"):
            store.delete_queue({**read_args(1), "token": read_args(2)["token"]})
        store.delete_queue(read_args(1))
        with pytest.raises(StoreError, match="forbidden"):
            store.send(frame(1, 2))


def test_acknowledged_retry_does_not_resurrect_a_frame(tmp_path):
    WebStore, StoreError = modules()
    with WebStore(tmp_path / "web.sqlite") as store:
        store.create_queue(queue())
        store.send(frame())
        store.ack({**read_args(), "ids": [hexid(1)]})
        store.ack({**read_args(), "ids": [hexid(1)]})
        store.send(frame())
        assert store.read({**read_args(), "limit": 1}) == {"items": []}
        with pytest.raises(StoreError, match="conflict"):
            store.send(frame(fill=b"y"))


def test_single_use_invitation_stays_consumed_after_ack(tmp_path):
    WebStore, StoreError = modules()
    with WebStore(tmp_path / "web.sqlite") as store:
        store.create_queue(queue(single_use=True))
        store.send(frame())
        store.ack({**read_args(), "ids": [hexid(1)]})
        assert store.send(frame()) == {"ok": True}
        with pytest.raises(StoreError, match="consumed"):
            store.send(frame(message=2))
        assert store.read({**read_args(), "limit": 16})["items"] == []


def test_single_use_claim_race_has_one_winner(tmp_path):
    WebStore, StoreError = modules()
    path = tmp_path / "web.sqlite"
    with WebStore(path) as store:
        store.create_queue(queue(single_use=True))

    def attempt(message):
        with WebStore(path) as store:
            try:
                store.send(frame(message=message))
                return "ok"
            except StoreError as exc:
                return exc.code
    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(attempt, (1, 2))) == ["consumed", "ok"]


def test_queue_quota_is_atomic_across_connections(tmp_path):
    WebStore, StoreError = modules()
    path = tmp_path / "web.sqlite"
    with WebStore(path, max_queues=1):
        pass

    def attempt(number):
        with WebStore(path, max_queues=1) as store:
            try:
                store.create_queue(queue(number))
                return "ok"
            except StoreError as exc:
                return exc.code
    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(attempt, (1, 2))) == ["capacity", "ok"]


def test_fixed_frames_and_canonical_base64_only(tmp_path):
    WebStore, StoreError = modules()
    with WebStore(tmp_path / "web.sqlite") as store:
        store.create_queue(queue())
        for body in ("", "YQ==", frame()["body"] + "\n", frame()["body"].rstrip("="), 3):
            with pytest.raises(StoreError, match="invalid_request"):
                store.send({**frame(), "body": body})


@pytest.mark.parametrize("change", [
    {"ttl": 59}, {"ttl": 2592001}, {"ttl": True}, {"single_use": 1},
    {"read_id": "A" * 64}, {"read_id": hexid(5)}, {"extra": "field"},
    {"read_hash": "bad"}, {"write_hash": digest(hexid(6))},
])
def test_invalid_queue_creation_is_rejected(tmp_path, change):
    WebStore, StoreError = modules()
    with WebStore(tmp_path / "web.sqlite") as store:
        with pytest.raises(StoreError, match="invalid_request"):
            store.create_queue({**queue(), **change})


def test_limits_are_strict_and_capacity_recovers_after_ack(tmp_path):
    WebStore, StoreError = modules()
    with WebStore(tmp_path / "web.sqlite", max_messages_per_queue=1, max_message_bytes=32768) as store:
        store.create_queue(queue())
        store.send(frame())
        with pytest.raises(StoreError, match="capacity"):
            store.send(frame(message=2))
        for limit in (0, 17, True, 1.5):
            with pytest.raises(StoreError, match="invalid_request"):
                store.read({**read_args(), "limit": limit})
        with pytest.raises(StoreError, match="invalid_request"):
            store.ack({**read_args(), "ids": [hexid(x) for x in range(17)]})
        store.ack({**read_args(), "ids": [hexid(1)]})
        store.send(frame(message=2))


def test_expiry_and_renewal_do_not_extend_invitation_deadline(tmp_path):
    WebStore, StoreError = modules()
    clock = [1000.0]
    with WebStore(tmp_path / "web.sqlite", clock=lambda: clock[0]) as store:
        store.create_queue(queue(1))
        store.create_queue(queue(2, single_use=True))
        store.send(frame(1))
        clock[0] += 50
        store.read({**read_args(1), "limit": 1})
        store.read({**read_args(2), "limit": 1})
        clock[0] += 11
        store.cleanup()
        assert store.read({**read_args(1), "limit": 1}) == {"items": []}
        with pytest.raises(StoreError, match="forbidden"):
            store.read({**read_args(2), "limit": 1})


def test_message_lifetime_is_at_most_seven_days(tmp_path):
    WebStore, StoreError = modules()
    clock = [1000.0]
    with WebStore(tmp_path / "web.sqlite", clock=lambda: clock[0]) as store:
        store.create_queue(queue(ttl=2592000))
        store.send(frame())
        clock[0] += 604801
        store.cleanup()
        assert store.read({**read_args(), "limit": 16}) == {"items": []}


def test_blob_capability_immutability_bounds_and_expiry(tmp_path):
    WebStore, StoreError = modules()
    clock = [1000.0]
    blob = {"id": hexid(100), "token": hexid(101), "body": base64.b64encode(b"b" * 65536).decode("ascii")}
    access = {"id": blob["id"], "token": blob["token"]}
    with WebStore(tmp_path / "web.sqlite", clock=lambda: clock[0], max_blob_bytes=65536) as store:
        assert store.put_blob(blob) == {"ok": True}
        assert store.put_blob(blob) == {"ok": True}
        assert store.get_blob(access) == {"body": blob["body"]}
        with pytest.raises(StoreError, match="forbidden"):
            store.get_blob({**access, "token": hexid(102)})
        with pytest.raises(StoreError, match="conflict"):
            store.put_blob({**blob, "body": base64.b64encode(b"c" * 65536).decode("ascii")})
        with pytest.raises(StoreError, match="capacity"):
            store.put_blob({**blob, "id": hexid(103)})
        with pytest.raises(StoreError, match="invalid_request"):
            store.put_blob({**blob, "body": "YQ=="})
        clock[0] += 604801
        store.cleanup()
        with pytest.raises(StoreError, match="forbidden"):
            store.get_blob(access)


def test_blob_delete_requires_matching_capability(tmp_path):
    WebStore, StoreError = modules()
    blob = {"id": hexid(100), "token": hexid(101), "body": base64.b64encode(b"b" * 65536).decode("ascii")}
    with WebStore(tmp_path / "web.sqlite") as store:
        store.put_blob(blob)
        with pytest.raises(StoreError, match="forbidden"):
            store.delete_blob({"id": blob["id"], "token": hexid(102)})
        assert store.delete_blob({"id": blob["id"], "token": blob["token"]}) == {"ok": True}
        with pytest.raises(StoreError, match="forbidden"):
            store.get_blob({"id": blob["id"], "token": blob["token"]})

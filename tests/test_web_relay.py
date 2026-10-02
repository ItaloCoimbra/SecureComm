"""Real loopback HTTP checks, not mocked request handlers."""

import asyncio
import base64
import hashlib
import importlib.util
import inspect
import json
import sqlite3

import aiohttp
import pytest


def module():
    assert importlib.util.find_spec("server.web_relay") is not None, "web HTTP relay is not implemented"
    from server.web_relay import WebRelay
    return WebRelay


def identifier(number):
    return f"{number:064x}"


def capabilities():
    return {"read_id": identifier(1), "write_id": identifier(2),
            "read_hash": hashlib.sha256(identifier(3).encode()).hexdigest(),
            "write_hash": hashlib.sha256(identifier(4).encode()).hexdigest(),
            "ttl": 60, "single_use": False}


async def post(client, relay, path, packet, status=200, **kwargs):
    async with client.post(relay.base_url + path, json=packet, **kwargs) as response:
        result = await response.json()
        assert response.status == status, result
        assert response.headers["Cache-Control"] == "no-store"
        assert "Set-Cookie" not in response.headers
        return result


def test_real_http_round_trip_restart_and_scoped_capabilities(tmp_path):
    async def scenario():
        WebRelay = module()
        path = tmp_path / "web.sqlite"
        packet = {"write_id": identifier(2), "token": identifier(4), "id": identifier(9),
                  "body": base64.b64encode(b"x" * 32768).decode()}
        relay = await WebRelay(path).start()
        async with aiohttp.ClientSession() as client:
            try:
                assert await post(client, relay, "/v1/queues", capabilities()) == {"ok": True}
                await post(client, relay, "/v1/send", packet)
                await post(client, relay, "/v1/send", packet)
                await post(client, relay, "/v1/read", {"read_id": identifier(1), "token": identifier(4), "limit": 16}, 403)
            finally:
                await relay.close()
            relay = await WebRelay(path).start()
            try:
                access = {"read_id": identifier(1), "token": identifier(3)}
                assert await post(client, relay, "/v1/read", {**access, "limit": 16}) == {"items": [{"id": packet["id"], "body": packet["body"]}]}
                await post(client, relay, "/v1/ack", {**access, "ids": [packet["id"]]})
                assert await post(client, relay, "/v1/read", {**access, "limit": 16}) == {"items": []}
                await post(client, relay, "/v1/delete", access)
                await post(client, relay, "/v1/send", packet, 403)
            finally:
                await relay.close()
    asyncio.run(scenario())


def test_blob_http_round_trip_and_delete(tmp_path):
    async def scenario():
        relay = await module()(tmp_path / "web.sqlite").start()
        access = {"id": identifier(11), "token": identifier(12)}
        blob = {**access, "body": base64.b64encode(b"b" * 65536).decode()}
        try:
            async with aiohttp.ClientSession() as client:
                await post(client, relay, "/v1/blobs/put", blob)
                assert await post(client, relay, "/v1/blobs/get", access) == {"body": blob["body"]}
                await post(client, relay, "/v1/blobs/delete", access)
                await post(client, relay, "/v1/blobs/get", access, 403)
        finally:
            await relay.close()
    asyncio.run(scenario())


def test_health_is_minimal_and_has_security_headers(tmp_path):
    async def scenario():
        relay = await module()(tmp_path / "web.sqlite").start()
        try:
            async with aiohttp.ClientSession() as client:
                async with client.get(relay.base_url + "/v1/health") as response:
                    assert await response.json() == {"ok": True, "protocol": "securecomm-web-v1"}
                    assert response.headers["Referrer-Policy"] == "no-referrer"
                    assert response.headers["X-Content-Type-Options"] == "nosniff"
                    assert response.headers["X-Frame-Options"] == "DENY"
                    assert response.headers["Cache-Control"] == "no-store"
                    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
                    assert "'wasm-unsafe-eval'" in response.headers["Content-Security-Policy"]
                    assert "'unsafe-inline'" not in response.headers["Content-Security-Policy"]
                    assert "Set-Cookie" not in response.headers
        finally:
            await relay.close()
    asyncio.run(scenario())


def test_cors_only_explicit_or_same_origin_never_credentials(tmp_path):
    async def scenario():
        relay = await module()(tmp_path / "web.sqlite", allowed_origins=["https://chat.example"]).start()
        try:
            async with aiohttp.ClientSession() as client:
                for origin, expected in (("https://chat.example", 200), (relay.base_url, 200), ("https://evil.example", 403), ("null", 403)):
                    async with client.get(relay.base_url + "/v1/health", headers={"Origin": origin}) as response:
                        assert response.status == expected
                        assert "Access-Control-Allow-Credentials" not in response.headers
                        if expected == 200:
                            assert response.headers["Access-Control-Allow-Origin"] == origin
                        else:
                            assert "Access-Control-Allow-Origin" not in response.headers
                async with client.options(relay.base_url + "/v1/send", headers={
                    "Origin": "https://chat.example", "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type"}) as response:
                    assert response.status == 204
                    assert response.headers["Access-Control-Allow-Headers"] == "Content-Type"
                async with client.options(relay.base_url + "/v1/send", headers={
                    "Origin": "https://chat.example", "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "authorization"}) as response:
                    assert response.status == 403
        finally:
            await relay.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("origin", ["*", "https://chat.example/", "http://example.com", "https://x.example/path", "https://u:p@chat.example", "https://x.example\r\nX: bad"])
def test_invalid_origin_configuration_is_rejected_before_database(tmp_path, origin):
    WebRelay = module()
    path = tmp_path / "web.sqlite"
    with pytest.raises(ValueError):
        WebRelay(path, allowed_origins=[origin])
    assert not path.exists()


def test_http_bounds_json_shape_and_no_secret_echo(tmp_path, caplog):
    async def scenario():
        relay = await module()(tmp_path / "web.sqlite").start()
        try:
            async with aiohttp.ClientSession() as client:
                for payload in ('[]', '{"token":"synthetic-secret","token":"again"}', '{"x":NaN}', '{"x":1e999}', '{"bad":'):
                    async with client.post(relay.base_url + "/v1/queues", data=payload, headers={"Content-Type": "application/json"}) as response:
                        assert response.status == 400
                        assert await response.json() == {"error": "invalid_request"}
                async with client.post(relay.base_url + "/v1/queues", data="x" * 100001, headers={"Content-Type": "application/json"}) as response:
                    assert response.status == 413
                async with client.post(relay.base_url + "/v1/queues", data=json.dumps(capabilities()), headers={"Content-Type": "text/plain"}) as response:
                    assert response.status == 415
                async with client.post(relay.base_url + "/v1/queues?token=synthetic-secret", json=capabilities()) as response:
                    assert response.status == 400
        finally:
            await relay.close()
    asyncio.run(scenario())
    assert "synthetic-secret" not in caplog.text
    assert "POST /" not in caplog.text


def test_slow_body_has_a_deadline(tmp_path):
    async def scenario():
        relay = await module()(tmp_path / "web.sqlite", body_timeout=0.03).start()
        async def body():
            yield b'{'
            await asyncio.sleep(0.2)
            yield b'}'
        try:
            async with aiohttp.ClientSession() as client:
                async with client.post(relay.base_url + "/v1/queues", data=body(), headers={"Content-Type": "application/json"}) as response:
                    assert response.status == 408
        finally:
            await relay.close()
    asyncio.run(scenario())


def test_global_admission_budget_has_no_per_ip_state(tmp_path):
    async def scenario():
        relay = await module()(tmp_path / "web.sqlite", admission_burst=2, admission_rate=0.001).start()
        try:
            async with aiohttp.ClientSession() as client:
                for expected in (200, 200, 429):
                    async with client.get(relay.base_url + "/v1/health") as response:
                        assert response.status == expected
        finally:
            await relay.close()
        with sqlite3.connect(tmp_path / "web.sqlite") as db:
            assert "127.0.0.1" not in "\n".join(db.iterdump())
    asyncio.run(scenario())


def test_idle_cleanup_runs_without_requests(tmp_path):
    async def scenario():
        clock = [1000.0]
        path = tmp_path / "web.sqlite"
        relay = await module()(path, cleanup_interval=0.01, store_options={"clock": lambda: clock[0]}).start()
        try:
            async with aiohttp.ClientSession() as client:
                await post(client, relay, "/v1/queues", capabilities())
            clock[0] += 61
            await asyncio.sleep(0.06)
            with sqlite3.connect(path) as db:
                assert db.execute("SELECT COUNT(*) FROM queues").fetchone()[0] == 0
        finally:
            await relay.close()
        await relay.close()
    asyncio.run(scenario())


def test_nonloopback_plaintext_rejected_before_opening_database(tmp_path):
    async def scenario():
        path = tmp_path / "web.sqlite"
        relay = module()(path, host="0.0.0.0")
        with pytest.raises(RuntimeError, match="TLS"):
            await relay.start()
        assert not path.exists()
        await relay.close()
    asyncio.run(scenario())


def test_static_frontend_and_path_confinement(tmp_path):
    async def scenario():
        static = tmp_path / "static"
        (static / "assets").mkdir(parents=True)
        (static / "index.html").write_text('<html><script src="/assets/app.js"></script></html>', encoding="utf-8")
        (static / "assets" / "app.js").write_text('"use strict";', encoding="utf-8")
        (static / "assets" / "app.wasm").write_bytes(b"\x00asm")
        (static / "assets" / "app.js.map").write_text("private source", encoding="utf-8")
        (tmp_path / "secret.txt").write_text("not public", encoding="utf-8")
        relay = await module()(tmp_path / "web.sqlite", static_dir=static).start()
        try:
            async with aiohttp.ClientSession() as client:
                for path, content_type in (("/", "text/html"), ("/assets/app.js", "application/javascript"), ("/assets/app.wasm", "application/wasm")):
                    async with client.get(relay.base_url + path) as response:
                        assert response.status == 200
                        assert response.content_type == content_type
                        assert response.headers["Cache-Control"] == "no-store"
                for path in ("/assets/app.js.map", "/assets/../secret.txt", "/.env", "/missing", "/v1/users"):
                    async with client.get(relay.base_url + path) as response:
                        assert response.status == 404
                        assert "not public" not in await response.text()
        finally:
            await relay.close()
    asyncio.run(scenario())


def test_live_connections_are_bounded_before_any_http_headers(tmp_path):
    async def scenario():
        WebRelay = module()
        assert "max_connections" in inspect.signature(WebRelay).parameters, "pre-header connection cap is missing"
        relay = await WebRelay(tmp_path / "web.sqlite", max_connections=1, header_timeout=1).start()
        first_writer = second_writer = None
        try:
            _, first_writer = await asyncio.open_connection(*relay.address)
            await asyncio.sleep(0.01)
            second_reader, second_writer = await asyncio.open_connection(*relay.address)
            assert await asyncio.wait_for(second_reader.read(), 0.5) == b""
        finally:
            for writer in (first_writer, second_writer):
                if writer is not None:
                    writer.close()
                    await writer.wait_closed()
            await relay.close()
    asyncio.run(scenario())


def test_partial_initial_headers_have_a_deadline_and_free_the_slot(tmp_path):
    async def scenario():
        WebRelay = module()
        assert "header_timeout" in inspect.signature(WebRelay).parameters, "initial header deadline is missing"
        relay = await WebRelay(tmp_path / "web.sqlite", max_connections=1, header_timeout=0.03).start()
        writer = None
        try:
            reader, writer = await asyncio.open_connection(*relay.address)
            writer.write(b"GET /v1/health HTTP/1.1\r\n")
            await writer.drain()
            assert await asyncio.wait_for(reader.read(), 0.5) == b""
            async with aiohttp.ClientSession() as client:
                async with client.get(relay.base_url + "/v1/health") as response:
                    assert response.status == 200
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()
            await relay.close()
    asyncio.run(scenario())


def test_active_request_budget_is_released_after_timeout(tmp_path):
    async def scenario():
        relay = await module()(tmp_path / "web.sqlite", max_inflight=1, body_timeout=0.05).start()
        writer = None
        try:
            reader, writer = await asyncio.open_connection(*relay.address)
            writer.write(b"POST /v1/queues HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
            await writer.drain()
            await asyncio.sleep(0.01)
            async with aiohttp.ClientSession() as client:
                async with client.get(relay.base_url + "/v1/health") as response:
                    assert response.status == 429
                assert b"408" in await asyncio.wait_for(reader.read(), 0.5)
                async with client.get(relay.base_url + "/v1/health") as response:
                    assert response.status == 200
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()
            await relay.close()
    asyncio.run(scenario())

"""Browser relay entrypoint remains separate from the historical CLI."""

import asyncio
import importlib.util

import aiohttp
import pytest


def module():
    assert importlib.util.find_spec("server.web_server") is not None, "browser server entrypoint is not implemented"
    from server import web_server
    return web_server


def test_cli_has_explicit_web_defaults_and_configuration(tmp_path):
    server = module()
    args = server.build_parser().parse_args([])
    assert args.host == "127.0.0.1"
    assert args.port == 8080
    assert args.database.name == "securecomm-web.sqlite"
    args = server.build_parser().parse_args(["--host", "0.0.0.0", "--port", "8443", "--database", str(tmp_path / "web.sqlite"),
        "--tls-cert", "cert.pem", "--tls-key", "key.pem", "--origin", "https://chat.example", "--static-dir", str(tmp_path)])
    assert args.origin == ["https://chat.example"]
    assert args.static_dir == tmp_path


def test_cli_rejects_partial_tls_and_bad_ports():
    server = module()
    with pytest.raises(SystemExit):
        server.main(["--tls-cert", "cert.pem"])
    with pytest.raises(SystemExit):
        server.build_parser().parse_args(["--port", "65536"])


def test_serve_cancellation_closes_listener(tmp_path):
    async def scenario():
        server = module()
        future = asyncio.get_running_loop().create_future()
        task = asyncio.create_task(server.serve(tmp_path / "web.sqlite", "127.0.0.1", 0, on_start=future.set_result))
        address = await asyncio.wait_for(future, 2)
        async with aiohttp.ClientSession() as client:
            async with client.get(f"http://{address[0]}:{address[1]}/v1/health") as response:
                assert response.status == 200
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(OSError):
            await asyncio.open_connection(*address)
    asyncio.run(scenario())

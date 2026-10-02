"""Synthetic local CLI flows; never start the legacy chat or load ML models."""

import asyncio
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import ssl
import warnings

import pytest

from core.identity import IdentityVault


@pytest.fixture
def cli():
    return importlib.import_module("client.cli")


@pytest.mark.parametrize("module", ["client.client", "server.server"])
def test_help_has_no_files_or_legacy_imports(tmp_path, module):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    env["PYTHONUTF8"] = "1"
    result = subprocess.run(
        [sys.executable, "-m", module, "--help"], cwd=tmp_path, env=env,
        capture_output=True, text=True, encoding="utf-8", timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "--host" in result.stdout and "--port" in result.stdout
    assert list(tmp_path.iterdir()) == []
    assert "LOGGER" not in result.stdout


@pytest.mark.parametrize("value,expected", [
    ("127.0.0.1:12345", ("127.0.0.1", 12345)),
    ("localhost:1", ("localhost", 1)),
    ("[::1]:443", ("::1", 443)),
])
def test_endpoint_validation(cli, value, expected):
    assert cli.parse_endpoint(value) == expected


@pytest.mark.parametrize("value", ["http://localhost:80", "localhost:0", "localhost:65536", "::1:443", "a\n:80", "a:x"])
def test_invalid_endpoint(cli, value):
    with pytest.raises(cli.argparse.ArgumentTypeError):
        cli.parse_endpoint(value)


def test_terminal_sanitization_preserves_text_without_control_sequences(cli):
    result = cli.safe_terminal("Olá\x1b[31m\r\n\t\u202eX\u2066Y\x00")
    assert "Olá" in result and "X" in result and "Y" in result
    assert not any(char in result for char in "\x1b\r\n\t\u202e\u2066\x00")


def test_profile_identity_contact_replacement_and_revocation(tmp_path, cli, monkeypatch, capsys):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "synthetic password")
    alice = tmp_path / "alice.vault"
    assert cli.main(["--profile", str(alice), "init"]) == 0
    capsys.readouterr()
    assert cli.main(["--profile", str(alice), "identity"]) == 0
    public = json.loads(capsys.readouterr().out)
    assert set(public) == {"v", "id", "ed25519", "curve25519"}
    export = tmp_path / "alice-public.json"
    assert cli.main(["--profile", str(alice), "identity", "--output", str(export)]) == 0
    original = export.read_bytes()
    assert cli.main(["--profile", str(alice), "identity", "--output", str(export)]) == 1
    assert export.read_bytes() == original
    with IdentityVault.create(tmp_path / "bob.vault", "synthetic password") as bob:
        bob_public = bob.public_identity()
    contact_file = tmp_path / "bob-public.json"
    contact_file.write_text(json.dumps(bob_public), encoding="utf-8")
    assert cli.main(["--profile", str(alice), "add-contact", "bob", str(contact_file), "--fingerprint", "0" * 64]) == 1
    assert cli.main(["--profile", str(alice), "add-contact", "bob", str(contact_file), "--fingerprint", bob_public["id"]]) == 0
    with IdentityVault.create(tmp_path / "bob-new.vault", "synthetic password") as bob:
        newer = bob.public_identity()
    contact_file.write_text(json.dumps(newer), encoding="utf-8")
    assert cli.main(["--profile", str(alice), "replace-contact", "bob", str(contact_file), "--old-fingerprint", bob_public["id"], "--new-fingerprint", newer["id"]]) == 0
    assert cli.main(["--profile", str(alice), "revoke", "bob", "--fingerprint", newer["id"]]) == 0
    capsys.readouterr()
    assert cli.main(["--profile", str(alice), "contacts"]) == 0
    assert "revogado" in capsys.readouterr().out


@pytest.mark.parametrize("contact,limit,expected", [
    (None, None, [0, 1, 2, 3, 4]),
    ("bob", None, [0, 3]),
    ("Bob", None, [2]),
    (None, 2, [3, 4]),
    (None, 10, [0, 1, 2, 3, 4]),
    ("bob", 1, [3]),
    ("bob", 2, [0, 3]),
    ("missing", None, []),
    ("missing", 2, []),
    ("", None, []),
])
def test_history_filters_preserve_order_and_output(cli, capsys, contact, limit, expected):
    history = [
        {"direction": "outgoing", "status": "pending", "alias": "bob", "text": "first"},
        {"direction": "incoming", "status": "received", "alias": "bobby", "text": "second"},
        {"direction": "incoming", "status": "received", "alias": "Bob", "text": "third"},
        {"direction": "outgoing", "status": "delivered", "alias": "bob", "text": "fourth\x1b[31m"},
        {"direction": "incoming", "status": "received", "alias": "carol\n", "text": "fifth"},
    ]
    lines = [
        "[pendente] para bob: first\n",
        "[recebida] de bobby: second\n",
        "[recebida] de Bob: third\n",
        "[entregue] para bob: fourth\\u001b[31m\n",
        "[recebida] de carol\\u000a: fifth\n",
    ]
    original = [message.copy() for message in history]
    cli._print_history(history, contact=contact, limit=limit)
    assert capsys.readouterr().out == ("".join(lines[index] for index in expected) or "Histórico vazio.\n")
    assert history == original


def test_history_without_filters_preserves_existing_output(cli, capsys):
    cli._print_history([])
    assert capsys.readouterr().out == "Histórico vazio.\n"
    cli._print_history([{"direction": "outgoing", "status": "queued", "alias": "bob", "text": "synthetic"}])
    assert capsys.readouterr().out == "[enfileirada] para bob: synthetic\n"


@pytest.mark.parametrize("value", ["0", "-1", "abc", "1.5", ""])
def test_history_invalid_limit_is_argparse_error(cli, monkeypatch, capsys, value):
    def forbidden_prompt(prompt):
        pytest.fail("Invalid limits must fail before asking for a password")
    monkeypatch.setattr(cli.getpass, "getpass", forbidden_prompt)
    with pytest.raises(SystemExit) as result:
        cli.main(["history", "--limit", value])
    assert result.value.code == 2
    assert "argument --limit:" in capsys.readouterr().err


@pytest.mark.parametrize("flags,expected", [
    ([], "[pendente] para bob: first\n[recebida] de carol: second\n[entregue] para bob: third\n"),
    (["--contact", "bob"], "[pendente] para bob: first\n[entregue] para bob: third\n"),
    (["--limit", "2"], "[recebida] de carol: second\n[entregue] para bob: third\n"),
    (["--contact", "bob", "--limit", "1"], "[entregue] para bob: third\n"),
    (["--contact", "missing", "--limit", "1"], "Histórico vazio.\n"),
])
def test_history_command_forwards_filters(tmp_path, cli, monkeypatch, capsys, flags, expected):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "synthetic password")
    path = tmp_path / "history.vault"
    with IdentityVault.create(path, "synthetic password"):
        pass
    history = [
        {"direction": "outgoing", "status": "pending", "alias": "bob", "text": "first"},
        {"direction": "incoming", "status": "received", "alias": "carol", "text": "second"},
        {"direction": "outgoing", "status": "delivered", "alias": "bob", "text": "third"},
    ]
    monkeypatch.setattr(IdentityVault, "snapshot", lambda self: {"history": history})
    assert cli.main(["--profile", str(path), "history", *flags]) == 0
    assert capsys.readouterr().out == expected


def test_init_password_confirmation_mismatch_does_not_create(tmp_path, cli, monkeypatch):
    answers = iter(["first synthetic password", "second synthetic password"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: next(answers))
    path = tmp_path / "alice"
    assert cli.main(["--profile", str(path), "init"]) == 1
    assert not path.exists()


def test_chat_eof_closes_listener_and_unlocks_profile(tmp_path, cli, monkeypatch, capsys):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "synthetic password")
    path = tmp_path / "alice"
    with IdentityVault.create(path, "synthetic password"):
        pass
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(""))
    assert cli.main(["--profile", str(path), "chat"]) == 0
    assert "Escutando" in capsys.readouterr().out
    with IdentityVault.open(path, "synthetic password"):
        pass


def test_chat_requires_explicit_destination_and_never_broadcasts(tmp_path, cli, capsys):
    async def scenario():
        with IdentityVault.create(tmp_path / "alice", "synthetic password") as vault:
            app = cli.SecureClient(vault)
            chat = cli.ChatSession(app)
            assert await chat.handle_line("synthetic message without recipient") is True
            assert app.messenger.history() == []
            assert "destinatário" in capsys.readouterr().out
            assert await chat.handle_line("/sair") is False
            await app.close()
    asyncio.run(scenario())


def test_server_cancellation_closes_listener_and_database(tmp_path):
    from server.server import serve

    async def scenario():
        started = asyncio.Event()
        address = []
        def on_start(value):
            address.extend(value)
            started.set()
        task = asyncio.create_task(serve(tmp_path / "relay.sqlite", "127.0.0.1", 0, on_start=on_start))
        await asyncio.wait_for(started.wait(), 3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(OSError):
            await asyncio.open_connection(*address)
    asyncio.run(scenario())


def test_outgoing_tls_requires_certificate_and_hostname_verification(cli):
    assert cli.outgoing_context("127.0.0.1") is None
    assert cli.outgoing_context("::1") is None
    context = cli.outgoing_context("localhost")
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_unpaired_tls_options_fail_before_password(cli, monkeypatch):
    def forbidden_prompt(prompt):
        pytest.fail("Invalid TLS arguments must fail before asking for a password")
    monkeypatch.setattr(cli.getpass, "getpass", forbidden_prompt)
    with pytest.raises(SystemExit) as result:
        cli.main(["--tls-cert", "synthetic.pem", "init"])
    assert result.value.code == 2


def test_password_echo_fallback_is_rejected(tmp_path, cli, monkeypatch):
    def insecure_prompt(prompt):
        warnings.warn("synthetic no terminal", cli.getpass.GetPassWarning)
        return "synthetic password"
    monkeypatch.setattr(cli.getpass, "getpass", insecure_prompt)
    path = tmp_path / "alice"
    assert cli.main(["--profile", str(path), "init"]) == 1
    assert not path.exists()


def test_chat_direct_route_only_delivers_to_selected_contact(tmp_path, cli, capsys):
    async def scenario():
        with IdentityVault.create(tmp_path / "alice", "synthetic password") as alice, \
             IdentityVault.create(tmp_path / "bob", "synthetic password") as bob, \
             IdentityVault.create(tmp_path / "carol", "synthetic password") as carol:
            for alias, peer in (("bob", bob), ("carol", carol)):
                public = peer.public_identity()
                alice.add_contact(alias, public, public["id"])
                public = alice.public_identity()
                peer.add_contact("alice", public, public["id"])
            apps = [cli.SecureClient(vault) for vault in (alice, bob, carol)]
            try:
                for app in apps:
                    await app.start()
                chat = cli.ChatSession(apps[0])
                endpoint = apps[1].address
                await chat.handle_line(f"/conectar bob {endpoint[0]}:{endpoint[1]}")
                await chat.handle_line("/usar bob")
                await chat.handle_line("synthetic private \x1b[31m message")
                assert apps[0].messenger.history()[-1]["status"] == "delivered"
                assert apps[1].messenger.history()[-1]["text"] == "synthetic private \x1b[31m message"
                assert apps[2].messenger.history() == []
                await chat.handle_line("/dm bob Here's  \"quoted\" text")
                assert apps[1].messenger.history()[-1]["text"] == "Here's  \"quoted\" text"
                cli.ChatSession(apps[1]).display_updates()
                output = capsys.readouterr().out
                assert "\\u001b" in output and "\x1b" not in output
            finally:
                for app in apps:
                    await app.close()
    asyncio.run(scenario())


def test_background_failure_does_not_skip_client_shutdown(tmp_path, cli, monkeypatch):
    closed = []
    class ObservedClient(cli.SecureClient):
        async def close(self):
            closed.append(True)
            await super().close()
    async def failed_background(self):
        raise ValueError("synthetic background failure")
    async def finish_input(self):
        await asyncio.sleep(0.02)
        return None
    monkeypatch.setattr(cli, "SecureClient", ObservedClient)
    monkeypatch.setattr(cli.ChatSession, "background", failed_background)
    monkeypatch.setattr(cli.ConsoleInput, "readline", finish_input)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(""))
    async def scenario():
        with IdentityVault.create(tmp_path / "alice", "synthetic password") as vault:
            with pytest.raises(ValueError, match="synthetic background failure"):
                await cli.run_chat(vault, "127.0.0.1", 0, [])
        assert closed == [True]
    asyncio.run(scenario())


def test_incoming_display_is_not_delayed_by_a_slow_route(tmp_path, cli, monkeypatch, capsys):
    async def scenario():
        with IdentityVault.create(tmp_path / "alice", "synthetic password") as vault:
            app = cli.SecureClient(vault)
            chat = cli.ChatSession(app)
            async def slow_route():
                await asyncio.Event().wait()
            monkeypatch.setattr(chat, "synchronize", slow_route)
            app.received.put_nowait({"alias": "synthetic", "text": "local received event"})
            task = asyncio.create_task(chat.background())
            try:
                await asyncio.sleep(0.15)
                assert "local received event" in capsys.readouterr().out
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                await app.close()
    asyncio.run(scenario())


def test_chat_cancellation_does_not_wait_for_stdin(tmp_path, cli, monkeypatch):
    read_fd, write_fd = os.pipe()
    stream = os.fdopen(read_fd, "r", encoding="utf-8")
    monkeypatch.setattr(cli.sys, "stdin", stream)
    async def scenario():
        with IdentityVault.create(tmp_path / "alice", "synthetic password") as vault:
            task = asyncio.create_task(cli.run_chat(vault, "127.0.0.1", 0, []))
            await asyncio.sleep(0.1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 1)
    try:
        asyncio.run(scenario())
    finally:
        os.close(write_fd)
        stream.close()


def test_relay_command_can_reconnect_a_closed_connection(tmp_path, cli):
    from core.transport import TransportError
    from server.relay import RelayServer
    async def scenario():
        relay = RelayServer(tmp_path / "relay.sqlite")
        await relay.start()
        try:
            with IdentityVault.create(tmp_path / "alice", "synthetic password") as vault:
                app = cli.SecureClient(vault)
                chat = cli.ChatSession(app)
                try:
                    await chat.add_relay(relay.address)
                    previous = chat.relays[relay.address]
                    await previous.close()
                    await chat.add_relay(relay.address)
                    assert chat.relays[relay.address] is not previous
                    assert await chat.relays[relay.address].status()
                    with pytest.raises(TransportError):
                        await previous.status()
                finally:
                    await app.close()
        finally:
            await relay.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("hide_revoked", [False, True])
def test_contacts_filter_preserves_order_and_format(cli, capsys, hide_revoked):
    contacts = [
        {"alias": "zeta\n", "identity": {"id": "synthetic-z"}, "revoked": False},
        {"alias": "revoked", "identity": {"id": "synthetic-r"}, "revoked": "truthy"},
        {"alias": "alpha", "identity": {"id": "synthetic-a"}, "revoked": 0},
    ]

    class FakeVault:
        def list_contacts(self):
            return contacts

    if hide_revoked:
        cli._print_contacts(FakeVault(), hide_revoked=True)
    else:
        cli._print_contacts(FakeVault())
    lines = ["zeta\\u000a | synthetic-z | verificado\n"]
    if not hide_revoked:
        lines.append("revoked | synthetic-r | revogado\n")
    lines.append("alpha | synthetic-a | verificado\n")
    assert capsys.readouterr().out == "".join(lines)
    assert len(contacts) == 3


@pytest.mark.parametrize("hide_revoked", [False, True])
@pytest.mark.parametrize("has_contacts", [False, True])
def test_contacts_empty_messages(cli, capsys, hide_revoked, has_contacts):
    class FakeVault:
        def list_contacts(self):
            return [{"alias": "revoked", "identity": {"id": "synthetic-r"}, "revoked": True}] if has_contacts else []

    cli._print_contacts(FakeVault(), hide_revoked=hide_revoked)
    if not has_contacts:
        expected = "Nenhum contato verificado. Use add-contact após conferir o fingerprint por outro canal.\n"
    elif hide_revoked:
        expected = "Nenhum contato ativo.\n"
    else:
        expected = "revoked | synthetic-r | revogado\n"
    assert capsys.readouterr().out == expected


@pytest.mark.parametrize("flags,expected", [
    ([], "revoked | synthetic-r | revogado\n"),
    (["--hide-revoked"], "Nenhum contato ativo.\n"),
])
def test_contacts_command_forwards_hide_revoked(tmp_path, cli, monkeypatch, capsys, flags, expected):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "synthetic password")
    path = tmp_path / "contacts.vault"
    with IdentityVault.create(path, "synthetic password"):
        pass
    monkeypatch.setattr(IdentityVault, "list_contacts", lambda self: [
        {"alias": "revoked", "identity": {"id": "synthetic-r"}, "revoked": True},
    ])
    assert cli.main(["--profile", str(path), "contacts", *flags]) == 0
    assert capsys.readouterr().out == expected


def test_known_error_codes_explain_pending_state(tmp_path, cli, capsys):
    with IdentityVault.create(tmp_path / "alice", "synthetic password") as vault:
        app = cli.SecureClient(vault)
        chat = cli.ChatSession(app)
        for code in ("prekeys_exhausted", "local_capacity_exhausted", "remote_queue_full", "untrusted_message_discarded", "local_storage_unavailable"):
            app.errors.put_nowait(code)
        chat.display_updates()
        output = capsys.readouterr().out
        assert "Sessões existentes" in output
        assert "cofre" in output
        assert "prekeys_exhausted" not in output

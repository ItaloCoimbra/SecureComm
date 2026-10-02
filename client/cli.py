"""One-to-one CLI with explicit independently verified contact identities."""

import argparse
import asyncio
import codecs
import getpass
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import select
import shlex
import ssl
import sys
import threading
import unicodedata
import warnings

from client.app import SecureClient
from core.identity import IdentityVault, VaultError
from core.protocol import validate_identity

_STATUS = {"pending": "pendente", "queued": "enfileirada", "delivered": "entregue", "received": "recebida"}
_ERRORS = {
    "prekeys_exhausted": "Prekeys locais esgotadas; novas sessões podem aguardar. Sessões existentes continuam disponíveis.",
    "local_capacity_exhausted": "Limite local de sessões ou pendências atingido. Sincronize as conversas; recebimento não confirmado.",
    "remote_queue_full": "Fila do relay cheia; pendências permanecem no cofre. O destinatário precisa sincronizar.",
    "untrusted_message_discarded": "Mensagem inválida ou de identidade não verificada foi descartada.",
    "local_storage_unavailable": "Falha ao salvar o cofre; recebimento não confirmado. Verifique espaço e permissões locais.",
}
_HELP = """/conectar ALIAS HOST:PORT  configura uma rota direta
/relay HOST:PORT           conecta e seleciona um relay
/usar ALIAS                seleciona o destinatário do texto
/dm ALIAS TEXTO            envia somente para esse contato
/sincronizar               reenvia pendências e busca mensagens
/peers                     lista contatos verificados
/historico                 mostra mensagens e estado de entrega
/ajuda                     mostra estes comandos
/sair                      fecha conexões e cofre
Use aspas para apelidos com espaços. Sem rota direta, usa o relay selecionado."""


def safe_terminal(value):
    """Escape controls, bidi formatting, and separators in untrusted text."""
    return "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C") or char in "\u2028\u2029" else char
        for char in str(value)
    )


def parse_host(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9.-]{1,253}", value) is None:
            raise argparse.ArgumentTypeError("Host inválido") from None
    return value


def parse_port(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9]{1,5}", value) is None or not 0 <= int(value) <= 65535:
        raise argparse.ArgumentTypeError("Porta deve estar entre 0 e 65535")
    return int(value)


def parse_limit(value):
    try:
        limit = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Limite deve ser um inteiro positivo") from None
    if limit <= 0:
        raise argparse.ArgumentTypeError("Limite deve ser um inteiro positivo")
    return limit


def parse_endpoint(value):
    if value.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\]:([0-9]{1,5})", value)
        if match is None:
            raise argparse.ArgumentTypeError("Use [IPv6]:PORTA")
        host, raw_port = match.groups()
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise argparse.ArgumentTypeError("IPv6 inválido") from None
    else:
        if value.count(":") != 1:
            raise argparse.ArgumentTypeError("Use HOST:PORTA ou [IPv6]:PORTA")
        host, raw_port = value.split(":")
        parse_host(host)
    port = parse_port(raw_port)
    if not port:
        raise argparse.ArgumentTypeError("Destino exige porta entre 1 e 65535")
    return host, port


def outgoing_context(host, ca_file=None):
    try:
        local = ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = False
    if local and ca_file is None:
        return None
    context = ssl.create_default_context(cafile=ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def incoming_context(cert_file, key_file):
    if bool(cert_file) != bool(key_file):
        raise ValueError("Certificado e chave TLS precisam ser usados juntos")
    if cert_file is None:
        return None
    from core.transport import make_server_tls_context
    return make_server_tls_context(cert_file, key_file)


def build_parser():
    parser = argparse.ArgumentParser(description="SecureComm: E2EE entre dispositivos verificados.")
    parser.add_argument("--profile", type=Path, default=Path.home() / ".securecomm" / "default.vault", help="Cofre local cifrado por senha")
    parser.add_argument("--host", type=parse_host, default="127.0.0.1", help="Escuta direta; fora de loopback exige TLS")
    parser.add_argument("--port", type=parse_port, default=0, help="Porta direta; 0 escolhe uma disponível")
    parser.add_argument("--tls-ca", type=Path, help="CA PEM para verificar destinos TLS; sem opção usa CAs do sistema fora de loopback")
    parser.add_argument("--tls-cert", type=Path, help="Certificado PEM da escuta direta")
    parser.add_argument("--tls-key", type=Path, help="Chave TLS PEM da escuta direta")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Cria uma identidade persistente e cofre novo")
    identity = commands.add_parser("identity", help="Exporta somente a identidade pública")
    identity.add_argument("--output", type=Path, help="Arquivo novo, sem sobrescrever")
    add = commands.add_parser("add-contact", help="Adiciona contato após verificação por outro canal")
    add.add_argument("alias")
    add.add_argument("identity_file", type=Path)
    add.add_argument("--fingerprint", required=True, help="Fingerprint completo confirmado fora do relay")
    contacts = commands.add_parser("contacts", help="Lista contatos, fingerprints e revogações")
    contacts.add_argument("--hide-revoked", action="store_true", help="Oculta contatos revogados")
    revoke = commands.add_parser("revoke", help="Revoga contato e remove sessões e pendências dele")
    revoke.add_argument("alias")
    revoke.add_argument("--fingerprint", required=True)
    replace = commands.add_parser("replace-contact", help="Substitui explicitamente a identidade de um contato")
    replace.add_argument("alias")
    replace.add_argument("identity_file", type=Path)
    replace.add_argument("--old-fingerprint", required=True)
    replace.add_argument("--new-fingerprint", required=True)
    history = commands.add_parser("history", help="Exibe localmente o histórico cifrado no cofre")
    history.add_argument("--contact", metavar="ALIAS", help="Exibe somente mensagens deste apelido exato")
    history.add_argument("--limit", type=parse_limit, metavar="N", help="Exibe somente as últimas N mensagens após filtrar o contato")
    chat = commands.add_parser("chat", help="Abre chat e escuta direta; relays opcionais")
    chat.add_argument("--relay", action="append", type=parse_endpoint, default=[], metavar="HOST:PORTA", help="Relay independente; pode repetir")
    return parser


def _password(confirm=False):
    # Fail closed instead of getpass's echoed-stdin fallback.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        password = getpass.getpass("Senha do cofre: ")
        if confirm and password != getpass.getpass("Confirme a senha: "):
            raise VaultError("As senhas não coincidem; nenhum perfil foi criado")
        return password


def _read_identity(path):
    with path.open("rb") as stream:
        raw = stream.read(8193)
    if len(raw) > 8192:
        raise ValueError("Arquivo de identidade excede o limite")
    return validate_identity(json.loads(raw))


def _print_contacts(vault, hide_revoked=False):
    contacts = vault.list_contacts()
    if not contacts:
        print("Nenhum contato verificado. Use add-contact após conferir o fingerprint por outro canal.")
        return
    if hide_revoked:
        contacts = [contact for contact in contacts if not contact["revoked"]]
        if not contacts:
            print("Nenhum contato ativo.")
            return
    for contact in contacts:
        status = "revogado" if contact["revoked"] else "verificado"
        print(f"{safe_terminal(contact['alias'])} | {contact['identity']['id']} | {status}")


def _print_history(history, contact=None, limit=None):
    if contact is not None:
        history = [message for message in history if message["alias"] == contact]
    if limit is not None:
        history = history[-limit:]
    if not history:
        print("Histórico vazio.")
    for message in history:
        direction = "para" if message["direction"] == "outgoing" else "de"
        status = _STATUS.get(message["status"], "desconhecido")
        print(f"[{status}] {direction} {safe_terminal(message['alias'])}: {safe_terminal(message['text'])}")


class ConsoleInput:
    """Cancelable input: console polling, POSIX readiness, daemon pipe fallback."""

    def __init__(self, stream):
        self.stream, self.buffer = stream, ""
        self.closed = threading.Event()
        self.items, self.thread, self.eof = None, None, False
        self.decoder = codecs.getincrementaldecoder(getattr(stream, "encoding", None) or "utf-8")("replace")
        self.tty = bool(stream.isatty())
        try:
            self.fd = stream.fileno()
        except (OSError, ValueError, AttributeError):
            self.fd = None
        if os.name == "nt" and not self.tty and self.fd is not None:
            self.items = queue.Queue(maxsize=64)
            self.thread = threading.Thread(target=self._read_pipe, daemon=True, name="securecomm-stdin")
            self.thread.start()

    def _read_pipe(self):
        while not self.closed.is_set():
            try:
                value = self.stream.readline(65537)
            except (OSError, ValueError):
                value = ""
            while not self.closed.is_set():
                try:
                    self.items.put(value, timeout=0.1)
                    break
                except queue.Full:
                    pass
            if not value:
                return

    async def readline(self):
        if self.tty:
            print("> ", end="", flush=True)
        while not self.closed.is_set():
            if len(self.buffer) > 65536:
                raise ValueError("Entrada excede o limite")
            if "\n" in self.buffer:
                line, self.buffer = self.buffer.split("\n", 1)
                return line.rstrip("\r")
            if self.eof:
                line, self.buffer = self.buffer, ""
                return line or None
            if self.fd is None:
                line = self.stream.readline(65537)
                if len(line) > 65536:
                    raise ValueError("Entrada excede o limite")
                return line.rstrip("\r\n") if line else None
            if os.name == "nt" and self.tty:
                import msvcrt
                if msvcrt.kbhit():
                    char = msvcrt.getwch()
                    if char == "\x03":
                        raise KeyboardInterrupt
                    if char in ("\x00", "\xe0"):
                        msvcrt.getwch()
                    elif char == "\x1a":
                        return None
                    elif char == "\r":
                        print()
                        line, self.buffer = self.buffer, ""
                        return line
                    elif char == "\b":
                        if self.buffer:
                            self.buffer = self.buffer[:-1]
                            print("\b \b", end="", flush=True)
                    elif unicodedata.category(char) not in ("Cc", "Cf"):
                        self.buffer += char
                        print(char, end="", flush=True)
            elif self.items is not None:
                try:
                    line = self.items.get_nowait()
                except queue.Empty:
                    pass
                else:
                    if len(line) > 65536:
                        raise ValueError("Entrada excede o limite")
                    return line.rstrip("\r\n") if line else None
            elif select.select([self.fd], [], [], 0)[0]:
                data = os.read(self.fd, 4096)
                self.buffer += self.decoder.decode(data, final=not data)
                self.eof = not data
            await asyncio.sleep(0.05)
        return None

    def close(self):
        self.closed.set()


class ChatSession:
    def __init__(self, app, ca_file=None):
        self.app, self.ca_file = app, ca_file
        self.routes, self.relays, self.contexts = {}, {}, {}
        self.active_relay, self.selected = None, None
        self.failed_routes = set()
        self.displayed_deliveries = {
            row["message_id"] for row in app.messenger.history()
            if row["direction"] == "outgoing" and row["status"] == "delivered"
        }

    def _tls(self, host):
        if host not in self.contexts:
            self.contexts[host] = outgoing_context(host, self.ca_file)
        context = self.contexts[host]
        return {"ssl_context": context} if context is not None else {}

    async def add_relay(self, endpoint):
        previous = self.relays.get(endpoint)
        self.relays[endpoint] = await self.app.connect_relay(*endpoint, **self._tls(endpoint[0]))
        if previous is not None:
            await self.app.disconnect_relay(previous)
        self.active_relay = endpoint
        print(f"Relay selecionado: {safe_terminal(endpoint[0])}:{endpoint[1]}")

    async def send(self, alias, text):
        self.app.vault.get_contact(alias)
        if alias in self.routes:
            endpoint = self.routes[alias]
            message_id = await self.app.send_direct(alias, text, *endpoint, **self._tls(endpoint[0]))
        elif self.active_relay is not None:
            message_id = await self.app.send_via_relay(alias, text, self.relays[self.active_relay])
        else:
            print("Configure uma rota com /conectar ou /relay antes de enviar.")
            return
        row = next(item for item in self.app.messenger.history() if item["message_id"] == message_id)
        print(f"[{_STATUS[row['status']]}] para {safe_terminal(alias)}; /historico mostra o estado.")

    def display_updates(self):
        while not self.app.received.empty():
            event = self.app.received.get_nowait()
            print(f"[recebida] {safe_terminal(event['alias'])}: {safe_terminal(event['text'])}", flush=True)
        while not self.app.errors.empty():
            code = self.app.errors.get_nowait()
            print(f"[aviso] {safe_terminal(_ERRORS.get(code, 'Operação não concluída. Consulte o estado das mensagens.'))}", flush=True)
        for row in self.app.messenger.history():
            if row["direction"] == "outgoing" and row["status"] == "delivered" and row["message_id"] not in self.displayed_deliveries:
                self.displayed_deliveries.add(row["message_id"])
                print(f"[entregue] confirmação do dispositivo de {safe_terminal(row['alias'])} ({row['message_id'][:8]})", flush=True)

    async def synchronize(self):
        operations = [("direto:" + alias, self.app.sync_direct, (alias, *endpoint), self._tls(endpoint[0])) for alias, endpoint in list(self.routes.items())]
        operations += [("relay:" + str(endpoint), self.app.sync_relay, (relay,), {}) for endpoint, relay in list(self.relays.items())]
        for label, operation, args, kwargs in operations:
            try:
                await operation(*args, **kwargs)
                self.failed_routes.discard(label)
            except (ValueError, RuntimeError, OSError):
                if label not in self.failed_routes:
                    self.failed_routes.add(label)
                    print(f"[aviso] rota indisponível: {safe_terminal(label)}; pendências permanecem no cofre.")
        self.display_updates()

    async def _synchronization_loop(self):
        while True:
            await self.synchronize()
            await asyncio.sleep(2)

    async def background(self):
        synchronization = asyncio.create_task(self._synchronization_loop())
        try:
            while True:
                if synchronization.done():
                    await synchronization
                    raise RuntimeError("A sincronização foi interrompida")
                self.display_updates()
                await asyncio.sleep(0.1)
        finally:
            synchronization.cancel()
            await asyncio.gather(synchronization, return_exceptions=True)

    async def handle_line(self, line):
        if not line.strip():
            return True
        try:
            if not line.startswith("/"):
                if self.selected is None:
                    print("Selecione um destinatário com /usar ALIAS ou use /dm ALIAS TEXTO.")
                else:
                    await self.send(self.selected, line)
                return True
            if line.split(maxsplit=1)[0] == "/dm":
                # Parse only the command and alias. Message quotes, apostrophes,
                # backslashes and spacing are conversation content, not syntax.
                lexer = shlex.shlex(line, posix=True)
                lexer.whitespace_split = True
                lexer.commenters = ""
                lexer.get_token()
                alias = lexer.get_token()
                text = lexer.instream.read().lstrip(" \t")
                if not alias or not text:
                    print("Use /dm ALIAS TEXTO.")
                else:
                    await self.send(alias, text)
                return True
            parts = shlex.split(line)
            command = parts[0]
            if command == "/sair" and len(parts) == 1:
                return False
            if command == "/ajuda" and len(parts) == 1:
                print(_HELP)
            elif command == "/peers" and len(parts) == 1:
                _print_contacts(self.app.vault)
            elif command == "/historico" and len(parts) == 1:
                _print_history(self.app.messenger.history())
            elif command == "/usar" and len(parts) == 2:
                self.app.vault.get_contact(parts[1])
                self.selected = parts[1]
                print(f"Destinatário: {safe_terminal(self.selected)}")
            elif command == "/conectar" and len(parts) == 3:
                self.app.vault.get_contact(parts[1])
                self.routes[parts[1]] = parse_endpoint(parts[2])
                print(f"Rota direta configurada para {safe_terminal(parts[1])}.")
            elif command == "/relay" and len(parts) == 2:
                await self.add_relay(parse_endpoint(parts[1]))
            elif command == "/sincronizar" and len(parts) == 1:
                await self.synchronize()
            else:
                print("Comando inválido; consulte /ajuda.")
        except (ValueError, RuntimeError, OSError, argparse.ArgumentTypeError):
            print("Operação não concluída. Confira contato e rota; use /sincronizar para pendências já criadas.")
        return True


async def run_chat(vault, host, port, relays, *, ca_file=None, ssl_context=None):
    app, background, console, input_task = SecureClient(vault), None, None, None
    try:
        kwargs = {"ssl_context": ssl_context} if ssl_context is not None else {}
        await app.start(host, port, **kwargs)
        print(f"Escutando em {app.address[0]}:{app.address[1]}. Fingerprint: {vault.public_identity()['id']}")
        print("Enfileirada não significa entregue; entregue exige confirmação cifrada do destinatário.")
        print(_HELP)
        chat = ChatSession(app, ca_file=ca_file)
        for endpoint in relays:
            await chat.add_relay(endpoint)
        background = asyncio.create_task(chat.background())
        console = ConsoleInput(sys.stdin)
        while True:
            input_task = asyncio.create_task(console.readline())
            done, _ = await asyncio.wait((input_task, background), return_when=asyncio.FIRST_COMPLETED)
            if background in done:
                await background
                raise RuntimeError("A sincronização foi interrompida")
            line = input_task.result()
            if line is None or not await chat.handle_line(line):
                break
            chat.display_updates()
    finally:
        if console is not None:
            console.close()
        tasks = [task for task in (input_task, background) if task is not None]
        for task in tasks:
            task.cancel()
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            await app.close()


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("--tls-cert e --tls-key precisam ser usados juntos")
    try:
        if args.command == "init":
            with IdentityVault.create(args.profile, _password(confirm=True)) as vault:
                print(f"Perfil criado. Fingerprint: {vault.public_identity()['id']}")
            return 0
        with IdentityVault.open(args.profile, _password()) as vault:
            if args.command == "identity":
                public = json.dumps(vault.public_identity(), ensure_ascii=True, indent=2) + "\n"
                if args.output is None:
                    print(public, end="")
                else:
                    with args.output.open("x", encoding="utf-8") as stream:
                        stream.write(public)
                    print("Identidade pública exportada.")
            elif args.command == "add-contact":
                vault.add_contact(args.alias, _read_identity(args.identity_file), args.fingerprint)
                print("Contato verificado e salvo.")
            elif args.command == "contacts":
                _print_contacts(vault, hide_revoked=args.hide_revoked)
            elif args.command == "revoke":
                vault.revoke_contact(args.alias, args.fingerprint)
                print("Contato revogado; sessões e pendências dele removidas.")
            elif args.command == "replace-contact":
                vault.replace_contact(args.alias, _read_identity(args.identity_file), args.old_fingerprint, args.new_fingerprint)
                print("Identidade do contato substituída após confirmação explícita.")
            elif args.command == "history":
                _print_history(vault.snapshot()["history"], contact=args.contact, limit=args.limit)
            elif args.command == "chat":
                context = incoming_context(args.tls_cert, args.tls_key)
                asyncio.run(run_chat(vault, args.host, args.port, args.relay, ca_file=args.tls_ca, ssl_context=context))
    except KeyboardInterrupt:
        return 0
    except getpass.GetPassWarning:
        print("Abra um terminal interativo para digitar a senha sem exibi-la.", file=sys.stderr)
        return 1
    except VaultError as exc:
        print(f"Cofre/contato: {safe_terminal(exc)}", file=sys.stderr)
        return 1
    except (OSError, ValueError, RuntimeError, EOFError):
        print("Operação não concluída; confira arquivo, identidade, TLS, interface e conexão.", file=sys.stderr)
        return 1
    return 0

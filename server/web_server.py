"""Explicit browser-messenger server entrypoint; does not start the CLI relay."""

import argparse
import asyncio
from pathlib import Path
import sqlite3
import sys

from core.transport import make_server_tls_context
from server.web_relay import WebRelay, create_app


def _port(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Porta inválida") from None
    if not 0 <= number <= 65535:
        raise argparse.ArgumentTypeError("Porta deve estar entre 0 e 65535")
    return number


def default_static_dir():
    packaged = Path(__file__).resolve().parent / "web_static"
    checkout = Path(__file__).resolve().parent.parent / "web" / "dist"
    for candidate in (packaged, checkout):
        if (candidate / "index.html").is_file():
            return candidate
    raise ValueError("Frontend não compilado. Execute npm ci e npm run build dentro de web/.")


def build_parser():
    parser = argparse.ArgumentParser(description="Website experimental E2EE e relay opaco SecureComm.")
    parser.add_argument("--host", default="127.0.0.1", help="Fora de loopback exige TLS; proxy Tor somente em loopback")
    parser.add_argument("--port", type=_port, default=8080)
    parser.add_argument("--database", type=Path, default=Path("securecomm-web.sqlite"), help="Banco separado de caixas e ciphertext")
    parser.add_argument("--tls-cert", type=Path)
    parser.add_argument("--tls-key", type=Path)
    parser.add_argument("--static-dir", type=Path, help="Frontend compilado; padrão pacote web_static ou web/dist")
    parser.add_argument("--origin", action="append", default=[], help="Origem HTTPS exata autorizada por CORS; repetível")
    parser.add_argument("--relay-only", action="store_true", help="Não servir frontend; relay independente")
    return parser


async def serve(database, host, port, *, ssl_context=None, static_dir=None, allowed_origins=(), on_start=None):
    relay = WebRelay(database, host=host, port=port, ssl_context=ssl_context,
                     static_dir=static_dir, allowed_origins=allowed_origins)
    try:
        await relay.start()
        address = relay.address
        print(f"SecureComm Web escutando em {address[0]}:{address[1]}. Ctrl+C para encerrar.", flush=True)
        if on_start is not None:
            on_start(address)
        await asyncio.Event().wait()
    finally:
        await relay.close()


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("--tls-cert e --tls-key precisam ser usados juntos")
    if args.relay_only and args.static_dir:
        parser.error("--relay-only não pode ser combinado com --static-dir")
    try:
        context = make_server_tls_context(args.tls_cert, args.tls_key) if args.tls_cert else None
        static_dir = None if args.relay_only else (args.static_dir or default_static_dir())
        if static_dir is not None and not (static_dir / "index.html").is_file():
            raise ValueError("Frontend não compilado. Execute npm ci e npm run build dentro de web/.")
        asyncio.run(serve(args.database, args.host, args.port, ssl_context=context,
                          static_dir=static_dir, allowed_origins=args.origin))
    except KeyboardInterrupt:
        return 0
    except (OSError, sqlite3.Error, ValueError, RuntimeError) as exc:
        # Only known locally generated configuration guidance is printed, never
        # an arbitrary I/O exception or request/SQL value.
        if isinstance(exc, ValueError) and str(exc).startswith("Frontend não compilado."):
            print(str(exc), file=sys.stderr)
        else:
            print("Não foi possível iniciar/manter o website; confira frontend, interface, TLS, porta e banco.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Independent opaque relay; no private accounts or legacy chat imports."""

import argparse
import asyncio
from pathlib import Path
import sqlite3
import sys

from core.transport import make_server_tls_context
from server.relay import RelayServer


def _port(value):
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Porta inválida") from None
    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError("Porta deve estar entre 0 e 65535")
    return port


def build_parser():
    parser = argparse.ArgumentParser(description="Relay independente de envelopes E2EE SecureComm.")
    parser.add_argument("--host", default="127.0.0.1", help="Interface de escuta; fora de loopback exige TLS")
    parser.add_argument("--port", type=_port, default=12345)
    parser.add_argument("--database", type=Path, default=Path("securecomm-relay.sqlite"), help="Banco de públicos, ciphertext e metadados")
    parser.add_argument("--tls-cert", type=Path, help="Certificado PEM do servidor")
    parser.add_argument("--tls-key", type=Path, help="Chave TLS PEM correspondente (não é uma chave de conversa)")
    return parser


async def serve(database, host, port, *, ssl_context=None, on_start=None):
    kwargs = {"ssl_context": ssl_context} if ssl_context is not None else {}
    relay = RelayServer(database, host=host, port=port, **kwargs)
    try:
        await relay.start()
        address = relay.address
        print(f"Relay escutando em {address[0]}:{address[1]}. Ctrl+C para encerrar.", flush=True)
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
    try:
        context = None
        if args.tls_cert:
            context = make_server_tls_context(args.tls_cert, args.tls_key)
        asyncio.run(serve(args.database, args.host, args.port, ssl_context=context))
    except KeyboardInterrupt:
        return 0
    except (OSError, sqlite3.Error, ValueError, RuntimeError):
        print("Não foi possível iniciar/manter o relay; confira interface, TLS, porta e banco.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

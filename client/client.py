"""Default E2EE entry point; no legacy chat fallback."""

from client.cli import main

if __name__ == "__main__":
    raise SystemExit(main())

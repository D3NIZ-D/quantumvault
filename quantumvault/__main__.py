"""Command-line entry point: ``python -m quantumvault``."""

from __future__ import annotations

import argparse
import threading
import webbrowser
from pathlib import Path

from werkzeug.serving import make_server

from . import __version__
from .server import DEFAULT_IDLE_TIMEOUT, create_app

DEFAULT_VAULT = Path.home() / ".quantumvault" / "vault.json"


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="quantumvault",
        description="Local, quantum-resistant password generator with an encrypted vault.",
    )
    parser.add_argument("--port", type=int, default=8765, help="port to listen on (default: 8765)")
    parser.add_argument(
        "--vault",
        type=Path,
        default=DEFAULT_VAULT,
        help=f"path of the encrypted vault file (default: {DEFAULT_VAULT})",
    )
    parser.add_argument(
        "--idle-timeout",
        type=int,
        default=DEFAULT_IDLE_TIMEOUT,
        help="lock the vault after this many idle seconds (default: 600)",
    )
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    app = create_app(args.vault, port=args.port, idle_timeout=args.idle_timeout)
    # Bind to loopback only: the dashboard is never reachable from the network.
    server = make_server("127.0.0.1", args.port, app, threaded=True)
    url = f"http://127.0.0.1:{args.port}/"

    print(f"QuantumVault {__version__}")
    print(f"  Vault file : {args.vault}")
    print(f"  Dashboard  : {url}")
    print("  Press Ctrl+C to stop.")

    if not args.no_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped. Vault locked.")


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import asyncio
import secrets
import sys

import structlog

from .core.encoding import b64e
from .core.crypto import normalize_password
from .relay.app import build_relay_app
from .protocol.client import WSClient
from .protocol.selfcheck import security_self_check
from .core.errors import ProtocolError

def _configure_logger():
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )
    return structlog.get_logger()

def main():
    logger = _configure_logger()

    parser = argparse.ArgumentParser(description="RelayBind Secure Pairing Protocol (Reference Implementation)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    relay_parser = subparsers.add_parser("relay", help="Run the untrusted relay server")
    relay_parser.add_argument("--host", default="127.0.0.1")
    relay_parser.add_argument("--port", type=int, default=8000)

    client_parser = subparsers.add_parser("client", help="Run a pairing client")
    client_parser.add_argument("--url", default="ws://localhost:8000")
    client_parser.add_argument("--session", required=True)
    client_parser.add_argument("--role", choices=["alice", "bob"], required=True)

    auth_group = client_parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("--pin", help="6-12 digit PIN")
    auth_group.add_argument("--secret-b64", help="Base64 secret (≥16 bytes)")

    client_parser.add_argument("--message", default="Hello from RelayBind!")

    subparsers.add_parser("gen-secret", help="Generate a high-entropy secret")
    subparsers.add_parser("check", help="Run security self-check")

    args = parser.parse_args()

    if args.command == "check":
        security_self_check(logger)
        print("✓ Security self-check passed")
        return 0

    if args.command == "gen-secret":
        secret = secrets.token_bytes(24)
        print(b64e(secret))
        return 0

    if args.command == "relay":
        security_self_check(logger)
        import uvicorn
        app = build_relay_app(logger)
        logger.info("starting_relay", host=args.host, port=args.port)
        uvicorn.run(app, host=args.host, port=args.port, log_config=None)
        return 0

    if args.command == "client":
        security_self_check(logger)
        try:
            password = normalize_password(args.pin, args.secret_b64)
        except ValueError as e:
            logger.error("password_error", error=str(e))
            print(f"Error: {e}")
            return 2

        client = WSClient(url=args.url, session_code=args.session, role=args.role, password=password, logger=logger)
        print(f"Starting RelayBind client as {args.role} in session {args.session}")
        print("Press Ctrl+C to exit")

        try:
            asyncio.run(client.run(args.message))
        except KeyboardInterrupt:
            logger.info("client_shutdown", reason="keyboard_interrupt")
            print("\nShutting down...")
        except ProtocolError as e:
            logger.error("protocol_error", error=str(e))
            print(f"Protocol error: {e}")
            return 3
        except Exception as e:
            logger.error("unexpected_error", error=str(e))
            print(f"Unexpected error: {e}")
            return 4

    return 0

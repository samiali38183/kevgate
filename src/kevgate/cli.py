"""``kevgate`` command line: serve, keygen, import-csv, kev-refresh."""

from __future__ import annotations

import argparse
import secrets
import sys
from collections.abc import Sequence
from pathlib import Path

from kevgate import __version__
from kevgate.auth import Scope, format_key_line, generate_key
from kevgate.config import ConfigError, Settings
from kevgate.csv_import import CsvImportError, parse_csv
from kevgate.db import FindingRepository
from kevgate.kev import CISA_KEV_URL, KevFeedError, refresh_kev
from kevgate.logs import configure_logging

CLI_BATCH = 1000


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = Settings.from_env()
    configure_logging(settings.log_level)
    uvicorn.run(
        "kevgate.main:app",
        host=args.host,
        port=args.port,
        access_log=False,
        server_header=False,
        proxy_headers=args.proxy_headers,
        log_config=None,
    )
    return 0


def _cmd_keygen(args: argparse.Namespace) -> int:
    key_id = args.key_id or f"key-{secrets.token_hex(4)}"
    key = generate_key()
    try:
        line = format_key_line(key_id, (Scope(s) for s in args.scope), key)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"key:  {key}")
    print(f"line: {line}")
    print(
        "Give the key to the client now; it is not stored anywhere and cannot be shown again. "
        "Append the line to the file named by KEVGATE_API_KEYS_FILE.",
        file=sys.stderr,
    )
    return 0


def _cmd_import_csv(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    db_path = args.db or settings.db_path
    try:
        text = Path(args.file).read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"error: cannot read {args.file}: {exc}", file=sys.stderr)
        return 1
    try:
        result = parse_csv(text, default_acr=args.default_acr)
    except CsvImportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        for row in exc.errors:
            print(f"  {row}", file=sys.stderr)
        return 1
    repo = FindingRepository(db_path)
    try:
        written = 0
        for i in range(0, len(result.findings), CLI_BATCH):
            written += repo.upsert_many(result.findings[i : i + CLI_BATCH])
    finally:
        repo.close()
    print(f"imported {written} finding(s), skipped {result.skipped} row(s) without a CVE")
    return 0


def _cmd_kev_refresh(args: argparse.Namespace) -> int:
    output = args.output or Settings.from_env().kev_path
    try:
        n = refresh_kev(output, url=args.url, timeout=args.timeout, min_entries=args.min_entries)
    except (KevFeedError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {n} KEV entries to {output}; restart the service to load them")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kevgate", description=__doc__)
    parser.add_argument("--version", action="version", version=f"kevgate {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="run the API with uvicorn")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument(
        "--proxy-headers",
        action="store_true",
        help="trust X-Forwarded-For (only behind a proxy you control)",
    )
    p.set_defaults(func=_cmd_serve)

    p = sub.add_parser("keygen", help="create an API key and print its key-file line")
    p.add_argument(
        "--scope",
        action="append",
        required=True,
        choices=[s.value for s in Scope],
        help="repeat for several scopes",
    )
    p.add_argument("--key-id", help="name for the key (default: random)")
    p.set_defaults(func=_cmd_keygen)

    p = sub.add_parser("import-csv", help="load a Nessus/Tenable CSV export into the database")
    p.add_argument("file")
    p.add_argument("--default-acr", type=int, default=4, choices=range(1, 9), metavar="1-8")
    p.add_argument("--db", help="database path (default: KEVGATE_DB_PATH)")
    p.set_defaults(func=_cmd_import_csv)

    p = sub.add_parser("kev-refresh", help="download and validate the CISA KEV feed")
    p.add_argument("--url", default=CISA_KEV_URL)
    p.add_argument("--output", help="destination file (default: KEVGATE_KEV_PATH)")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--min-entries", type=int, default=1)
    p.set_defaults(func=_cmd_kev_refresh)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

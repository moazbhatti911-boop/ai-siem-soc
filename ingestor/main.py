"""Ingestor entry point: parse a log file and ship its events to the server.

Usage::

    python -m ingestor.main --file samples/sample_auth.log
    python -m ingestor.main --file /var/log/auth.log --server-url http://127.0.0.1:8003

The API key is read from the ``SIEM_API_KEY`` environment variable (see ``.env``).
"""

import argparse
import os
import sys

from dotenv import load_dotenv

from ingestor.parser import parse_file
from ingestor.shipper import send_events

load_dotenv()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Parse a log file and ship events to the SIEM server.")
    parser.add_argument("--file", required=True, help="Path to the log file to ingest.")
    parser.add_argument(
        "--server-url",
        default=os.environ.get("SIEM_SERVER_URL", "http://127.0.0.1:8003"),
        help="Base URL of the SIEM server (default: %(default)s).",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("SIEM_API_KEY", ""),
        help="API key for the server (default: $SIEM_API_KEY).",
    )
    args = parser.parse_args(argv)

    if not args.api_key:
        print("Error: no API key. Set SIEM_API_KEY in .env or pass --api-key.", file=sys.stderr)
        return 2
    if not os.path.isfile(args.file):
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        return 2

    events = parse_file(args.file)
    print(f"Parsed {len(events)} events from {args.file}")
    try:
        result = send_events(events, args.server_url, args.api_key)
    except Exception as exc:  # noqa: BLE001 - surface any transport error plainly
        print(f"Error shipping events to {args.server_url}: {exc}", file=sys.stderr)
        return 1
    print(f"Stored {result.get('stored', 0)} events, {result.get('alerts_created', 0)} new alerts raised.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

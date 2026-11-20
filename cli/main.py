"""SIEM CLI (argparse).

Usage (server must be running)::

    python -m cli.main list-alerts
    python -m cli.main list-alerts --severity High
    python -m cli.main show-alert 1
    python -m cli.main ack-alert 1
    python -m cli.main stats

Server URL and API key come from ``SIEM_SERVER_URL`` / ``SIEM_API_KEY``
(or ``--server-url`` / ``--api-key``).
"""

import argparse
import json
import os
import sys

import httpx
from dotenv import load_dotenv

load_dotenv()


def _client(server_url: str, api_key: str) -> httpx.Client:
    # trust_env=False: the server is always local (127.0.0.1), so proxy
    # environment variables must never reroute or break this call.
    return httpx.Client(
        base_url=server_url.rstrip("/"),
        headers={"X-API-Key": api_key},
        timeout=15.0,
        trust_env=False,
    )


def _require_key(api_key: str) -> int:
    if not api_key:
        print("Error: no API key. Set SIEM_API_KEY in .env or pass --api-key.", file=sys.stderr)
        return 2
    return 0


def cmd_list_alerts(client: httpx.Client, severity: str | None) -> int:
    params = {"severity": severity} if severity else {}
    resp = client.get("/alerts", params=params)
    resp.raise_for_status()
    alerts = resp.json()
    if not alerts:
        print("No alerts.")
        return 0
    for alert in alerts:
        print(
            f"#{alert['id']} [{alert['severity']}] {alert['alert_type']}: "
            f"{alert['title']} ({alert['status']})"
        )
    return 0


def cmd_show_alert(client: httpx.Client, alert_id: int) -> int:
    resp = client.get(f"/alerts/{alert_id}")
    if resp.status_code == 404:
        print(f"Alert #{alert_id} not found.", file=sys.stderr)
        return 1
    resp.raise_for_status()
    print(json.dumps(resp.json(), indent=2))
    return 0


def cmd_ack_alert(client: httpx.Client, alert_id: int) -> int:
    resp = client.post(f"/alerts/{alert_id}/acknowledge")
    if resp.status_code == 404:
        print(f"Alert #{alert_id} not found.", file=sys.stderr)
        return 1
    resp.raise_for_status()
    print(f"Alert #{alert_id} acknowledged.")
    return 0


def cmd_stats(client: httpx.Client) -> int:
    resp = client.get("/stats")
    resp.raise_for_status()
    print(json.dumps(resp.json(), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AI SIEM & SOC command-line client.")
    parser.add_argument(
        "--server-url",
        default=os.environ.get("SIEM_SERVER_URL", "http://127.0.0.1:8003"),
    )
    parser.add_argument("--api-key", default=os.environ.get("SIEM_API_KEY", ""))
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list-alerts", help="List alerts, newest first.")
    p_list.add_argument("--severity", choices=["Low", "Medium", "High"], default=None)

    p_show = sub.add_parser("show-alert", help="Show one alert in full.")
    p_show.add_argument("alert_id", type=int)

    p_ack = sub.add_parser("ack-alert", help="Acknowledge one alert.")
    p_ack.add_argument("alert_id", type=int)

    sub.add_parser("stats", help="Show event/alert/incident counts.")

    args = parser.parse_args(argv)
    if (code := _require_key(args.api_key)) != 0:
        return code
    with _client(args.server_url, args.api_key) as client:
        try:
            if args.command == "list-alerts":
                return cmd_list_alerts(client, args.severity)
            if args.command == "show-alert":
                return cmd_show_alert(client, args.alert_id)
            if args.command == "ack-alert":
                return cmd_ack_alert(client, args.alert_id)
            if args.command == "stats":
                return cmd_stats(client)
        except httpx.HTTPError as exc:
            print(f"Error talking to {args.server_url}: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

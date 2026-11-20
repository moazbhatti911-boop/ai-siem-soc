"""Ship parsed events to the SIEM server API."""

import httpx

from shared.schemas import LogEvent


def send_events(
    events: list[LogEvent],
    server_url: str,
    api_key: str,
    timeout: float = 30.0,
) -> dict:
    """POST a batch of events to ``POST /events`` and return the server reply."""
    if not events:
        return {"stored": 0, "alerts_created": 0}
    payload = [event.model_dump() for event in events]
    headers = {"X-API-Key": api_key}
    # trust_env=False: the server is always local (127.0.0.1), so proxy
    # environment variables must never reroute or break this call.
    with httpx.Client(timeout=timeout, trust_env=False) as client:
        response = client.post(f"{server_url.rstrip('/')}/events", json=payload, headers=headers)
        response.raise_for_status()
        return response.json()

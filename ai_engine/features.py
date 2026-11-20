"""Feature extraction: turn a log event into a numeric vector for the ML model.

Feature vector (6 numbers)::

    [failed_logins_from_this_ip, hour_of_day, is_failed_login,
     is_root_user, is_sudo, is_new_source_ip]

``context`` carries the running state the server keeps while ingesting:
``failed_counts`` maps source IP -> failed-login count so far, and
``known_ips`` is the set of IPs seen before this batch.
"""

from datetime import datetime

from shared.schemas import LogEvent


def hour_of(timestamp: str, default: int = 12) -> int:
    """Extract the hour (0-23) from an ISO timestamp, or ``default`` if unknown."""
    try:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).hour
    except (ValueError, AttributeError):
        return default


def failed_login_count(events: list[LogEvent], source_ip: str) -> int:
    """Count failed logins from one IP across a list of events."""
    return sum(1 for e in events if e.event_type == "failed_login" and e.source_ip == source_ip)


def extract_features(event: LogEvent, context: dict) -> list[float]:
    """Build the 6-number feature vector for one event."""
    failed_counts: dict[str, int] = context.get("failed_counts", {})
    known_ips: set[str] = context.get("known_ips", set())
    ip = event.source_ip or ""
    return [
        float(failed_counts.get(ip, 0)),
        float(hour_of(event.timestamp)),
        1.0 if event.event_type == "failed_login" else 0.0,
        1.0 if event.user == "root" else 0.0,
        1.0 if event.event_type == "sudo" else 0.0,
        0.0 if (not ip or ip in known_ips) else 1.0,
    ]

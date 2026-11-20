"""Alert detection wiring: run the AI/rule engine over ingested events."""

from ai_engine.scoring import detect_alerts as _detect
from server import storage
from shared.schemas import Alert, LogEvent


def detect_and_store(new_events: list[LogEvent]) -> list[Alert]:
    """Detect new alerts for a batch and store them; return the new alerts."""
    all_events = storage.get_events(limit=10000)
    existing = storage.get_alerts()
    new_alerts = _detect(new_events, all_events, existing)
    return [storage.insert_alert(alert) for alert in new_alerts]

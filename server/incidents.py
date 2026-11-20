"""Incident handling: group alerts into SOC incidents."""

from server import storage
from shared.schemas import Incident


def create_incident(title: str, severity: str, alert_ids: list[int]) -> Incident:
    """Create and store an incident from a list of alert ids."""
    return storage.insert_incident(
        Incident(title=title, severity=severity, alert_ids=alert_ids)
    )


def list_incidents() -> list[Incident]:
    """Return all incidents, newest first."""
    return storage.get_incidents()

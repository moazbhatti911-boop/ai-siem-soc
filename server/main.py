"""SIEM server entry point (FastAPI).

Run from inside the project folder::

    uvicorn server.main:app --reload --port 8003

Health check (no auth needed):  GET http://127.0.0.1:8003/health
Every other endpoint requires the ``X-API-Key`` header.
"""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException

from server import alerts as alert_service
from server import incidents as incident_service
from server import storage
from server.auth import require_api_key
from shared.schemas import Alert, Incident, LogEvent


@asynccontextmanager
async def lifespan(_app: FastAPI):
    storage.init_db()
    yield


app = FastAPI(title="AI-Powered SIEM & SOC Platform", version="0.1.0", lifespan=lifespan)


@app.get("/health")
def health() -> dict:
    """Liveness check; no API key needed."""
    return {"status": "ok", "service": "ai-siem-soc"}


@app.post("/events")
def ingest_events(
    events: list[LogEvent], _key: str = Depends(require_api_key)
) -> dict:
    """Store events and run detection; returns counts of stored events and new alerts."""
    stored = storage.insert_events(events)
    new_alerts = alert_service.detect_and_store(events)
    return {"stored": stored, "alerts_created": len(new_alerts)}


@app.get("/events")
def list_events(limit: int = 100, _key: str = Depends(require_api_key)) -> list[LogEvent]:
    """Most recent events, newest first."""
    return storage.get_events(limit=limit)


@app.get("/alerts")
def list_alerts(
    severity: str | None = None,
    status: str | None = None,
    _key: str = Depends(require_api_key),
) -> list[Alert]:
    """Alerts, newest first; filter with ?severity=High&status=open."""
    return storage.get_alerts(severity=severity, status=status)


@app.get("/alerts/{alert_id}")
def get_one_alert(alert_id: int, _key: str = Depends(require_api_key)) -> Alert:
    """One alert by id."""
    alert = storage.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.post("/alerts/{alert_id}/acknowledge")
def acknowledge(alert_id: int, _key: str = Depends(require_api_key)) -> dict:
    """Mark an alert acknowledged."""
    if not storage.acknowledge_alert(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"id": alert_id, "status": "acknowledged"}


@app.post("/incidents")
def create_incident(
    incident: Incident, _key: str = Depends(require_api_key)
) -> Incident:
    """Create an incident grouping alert ids."""
    return incident_service.create_incident(
        incident.title, incident.severity, incident.alert_ids
    )


@app.get("/incidents")
def list_incidents(_key: str = Depends(require_api_key)) -> list[Incident]:
    """All incidents, newest first."""
    return incident_service.list_incidents()


@app.get("/stats")
def stats(_key: str = Depends(require_api_key)) -> dict:
    """Counts: events, alerts (total / open / by severity), incidents."""
    return storage.get_stats()

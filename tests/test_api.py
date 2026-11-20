"""API tests using FastAPI's TestClient against a temporary database.

The server reads SIEM_API_KEY / SIEM_DB_PATH from the environment at request
time, so the fixtures below point it at a throwaway database per test.
"""

import os

import pytest
from fastapi.testclient import TestClient

from ingestor.parser import parse_file
from server.main import app

TEST_KEY = "test-key-123"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEM_API_KEY", TEST_KEY)
    monkeypatch.setenv("SIEM_DB_PATH", str(tmp_path / "test.db"))
    with TestClient(app) as test_client:
        yield test_client


def _headers():
    return {"X-API-Key": TEST_KEY}


def _sample_events():
    return [event.model_dump() for event in parse_file("samples/sample_auth.log")]


def test_health_needs_no_auth(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_missing_api_key_is_401(client):
    assert client.get("/alerts").status_code == 401
    assert client.get("/stats").status_code == 401


def test_wrong_api_key_is_401(client):
    assert client.get("/stats", headers={"X-API-Key": "wrong"}).status_code == 401


def test_ingest_sample_log_raises_expected_alerts(client):
    response = client.post("/events", json=_sample_events(), headers=_headers())
    assert response.status_code == 200
    assert response.json()["stored"] == 12
    assert response.json()["alerts_created"] >= 3

    stats = client.get("/stats", headers=_headers()).json()
    assert stats["events"] == 12
    assert stats["alerts"] >= 3
    assert stats["alerts_by_severity"].get("High", 0) >= 1

    alerts = client.get("/alerts", headers=_headers()).json()
    by_type = {a["alert_type"] for a in alerts}
    assert "brute_force" in by_type
    assert "root_login" in by_type
    assert "sudo_use" in by_type

    brute = [a for a in alerts if a["alert_type"] == "brute_force"][0]
    assert brute["severity"] == "High"
    assert brute["source_ip"] == "192.168.56.10"


def test_acknowledge_flow(client):
    client.post("/events", json=_sample_events(), headers=_headers())
    alert_id = client.get("/alerts", headers=_headers()).json()[0]["id"]

    response = client.post(f"/alerts/{alert_id}/acknowledge", headers=_headers())
    assert response.status_code == 200
    assert response.json()["status"] == "acknowledged"

    alert = client.get(f"/alerts/{alert_id}", headers=_headers()).json()
    assert alert["status"] == "acknowledged"

    assert client.post("/alerts/99999/acknowledge", headers=_headers()).status_code == 404


def test_incident_flow(client):
    client.post("/events", json=_sample_events(), headers=_headers())
    alert_ids = [a["id"] for a in client.get("/alerts", headers=_headers()).json()]

    response = client.post(
        "/incidents",
        json={"title": "Brute-force campaign", "severity": "High", "alert_ids": alert_ids},
        headers=_headers(),
    )
    assert response.status_code == 200
    assert response.json()["title"] == "Brute-force campaign"

    incidents = client.get("/incidents", headers=_headers()).json()
    assert len(incidents) == 1
    assert incidents[0]["alert_ids"] == alert_ids


def test_reingest_does_not_duplicate_rule_alerts(client):
    first = client.post("/events", json=_sample_events(), headers=_headers()).json()
    second = client.post("/events", json=_sample_events(), headers=_headers()).json()
    # Same log twice: no new brute-force / root / sudo alerts the second time.
    assert second["alerts_created"] == 0
    assert first["alerts_created"] >= 3

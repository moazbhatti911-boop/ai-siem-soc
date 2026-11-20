"""Tests for rule scoring and alert detection."""

from ai_engine.scoring import (
    BRUTE_FORCE_THRESHOLD,
    brute_force_alert,
    detect_alerts,
    rule_alerts_for_event,
    severity_for_anomaly,
)
from shared.schemas import LogEvent


def _event(event_type, user=None, source_ip="192.168.56.10"):
    return LogEvent(
        timestamp="2026-11-20T10:00:00Z",
        host="kali",
        service="sshd",
        user=user,
        source_ip=source_ip,
        event_type=event_type,
        message="test",
        raw="test",
    )


def test_brute_force_threshold():
    assert BRUTE_FORCE_THRESHOLD == 5
    alert = brute_force_alert("192.168.56.10", 5)
    assert alert.severity == "High"
    assert alert.alert_type == "brute_force"
    assert "5 failed logins" in alert.description


def test_root_login_is_medium():
    alerts = rule_alerts_for_event(_event("login_success", user="root"))
    assert len(alerts) == 1
    assert alerts[0].alert_type == "root_login"
    assert alerts[0].severity == "Medium"


def test_sudo_is_low():
    alerts = rule_alerts_for_event(_event("sudo", user="luffy"))
    assert len(alerts) == 1
    assert alerts[0].alert_type == "sudo_use"
    assert alerts[0].severity == "Low"


def test_normal_login_raises_nothing():
    assert rule_alerts_for_event(_event("login_success", user="luffy")) == []


def test_detect_alerts_brute_force_once():
    failed = [_event("failed_login", user="admin") for _ in range(5)]
    alerts = detect_alerts(failed, failed, [])
    brute = [a for a in alerts if a.alert_type == "brute_force"]
    assert len(brute) == 1
    assert brute[0].severity == "High"
    # A second identical batch must not raise a duplicate brute-force alert.
    again = detect_alerts(failed, failed, alerts)
    assert [a for a in again if a.alert_type == "brute_force"] == []


def test_detect_alerts_below_threshold_has_no_brute_force():
    failed = [_event("failed_login", user="admin") for _ in range(4)]
    alerts = detect_alerts(failed, failed, [])
    assert [a for a in alerts if a.alert_type == "brute_force"] == []


def test_severity_for_anomaly():
    assert severity_for_anomaly(-0.30) == "High"
    assert severity_for_anomaly(-0.05) == "Medium"

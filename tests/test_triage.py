"""Tests for triage text (plain-language alert explanations)."""

from ai_engine.triage import explain_alert, triage_text
from shared.schemas import Alert


def test_brute_force_triage_mentions_count_and_action():
    text = triage_text("brute_force", source_ip="192.168.56.10", count=5)
    assert "5 failed logins" in text
    assert "192.168.56.10" in text
    assert "brute-force" in text


def test_root_login_triage():
    text = triage_text("root_login", source_ip="192.168.56.10", user="root")
    assert "root" in text.lower()
    assert "192.168.56.10" in text


def test_sudo_triage_names_user():
    text = triage_text("sudo_use", user="luffy", source_ip="192.168.56.20")
    assert "luffy" in text


def test_anomaly_triage():
    text = triage_text("anomaly", source_ip="192.168.56.10", score=-0.25)
    assert "192.168.56.10" in text
    assert "normal" in text.lower()


def test_explain_alert():
    alert = Alert(
        alert_type="brute_force",
        severity="High",
        title="Possible brute-force attack",
        description="",
        source_ip="192.168.56.10",
    )
    assert "192.168.56.10" in explain_alert(alert)

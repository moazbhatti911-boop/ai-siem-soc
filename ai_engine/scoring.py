"""Severity scoring: rule alerts plus anomaly alerts.

Rules (evaluated per ingest batch):
- 5+ failed logins from one IP -> High brute-force alert (once per IP).
- root login success -> Medium alert.
- sudo use -> Low alert.
- IsolationForest anomaly score below threshold -> Medium/High
  "Unusual activity" alert (once per source IP per batch).

``detect_alerts`` is pure: it takes the new events, every event stored so
far, and the alerts already raised, and returns only *new* alerts.
"""

from ai_engine.anomaly import STRONG_ANOMALY_THRESHOLD, anomaly_score
from ai_engine.features import extract_features, failed_login_count
from ai_engine.triage import triage_text
from shared.schemas import Alert, LogEvent

BRUTE_FORCE_THRESHOLD = 5


def brute_force_alert(source_ip: str, count: int) -> Alert:
    """High alert for repeated failed logins from one IP."""
    return Alert(
        alert_type="brute_force",
        severity="High",
        title=f"Possible brute-force attack from {source_ip}",
        description=triage_text("brute_force", source_ip=source_ip, count=count),
        source_ip=source_ip,
    )


def rule_alerts_for_event(event: LogEvent) -> list[Alert]:
    """Rule alerts raised by a single event (root login, sudo use)."""
    alerts: list[Alert] = []
    if event.event_type == "login_success" and event.user == "root":
        alerts.append(
            Alert(
                alert_type="root_login",
                severity="Medium",
                title="Root login succeeded",
                description=triage_text(
                    "root_login", source_ip=event.source_ip, user=event.user
                ),
                source_ip=event.source_ip,
                user=event.user,
            )
        )
    if event.event_type == "sudo":
        alerts.append(
            Alert(
                alert_type="sudo_use",
                severity="Low",
                title=f"Sudo command used by {event.user or 'unknown user'}",
                description=triage_text(
                    "sudo_use", source_ip=event.source_ip, user=event.user
                ),
                source_ip=event.source_ip,
                user=event.user,
            )
        )
    return alerts


def severity_for_anomaly(score: float) -> str:
    """Map an anomaly score to a severity."""
    return "High" if score < STRONG_ANOMALY_THRESHOLD else "Medium"


def detect_alerts(
    new_events: list[LogEvent],
    all_events: list[LogEvent],
    existing_alerts: list[Alert],
) -> list[Alert]:
    """Return new alerts for a batch of events, de-duplicated against existing ones."""
    alerts: list[Alert] = []
    seen_types: set[tuple[str, str]] = {
        (a.alert_type, a.source_ip or "") for a in existing_alerts
    }

    # Per-event rule alerts (root login, sudo), de-duplicated by (type, ip).
    for event in new_events:
        for alert in rule_alerts_for_event(event):
            key = (alert.alert_type, alert.source_ip or "")
            if key not in seen_types:
                seen_types.add(key)
                alerts.append(alert)

    # Brute force: count failed logins per IP across all stored events.
    failed_ips = {e.source_ip for e in all_events if e.event_type == "failed_login" and e.source_ip}
    for ip in sorted(failed_ips):
        count = failed_login_count(all_events, ip)
        if count >= BRUTE_FORCE_THRESHOLD and ("brute_force", ip) not in seen_types:
            seen_types.add(("brute_force", ip))
            alerts.append(brute_force_alert(ip, count))

    # Anomaly alerts: one per source IP, for events the model flags.
    context = {
        "failed_counts": {
            ip: failed_login_count(all_events, ip) for ip in failed_ips
        },
        "known_ips": {e.source_ip for e in all_events if e.source_ip},
    }
    for event in new_events:
        if not event.source_ip:
            continue
        key = ("anomaly", event.source_ip)
        if key in seen_types:
            continue
        features = extract_features(event, context)
        score = anomaly_score(features)
        if score < 0.0:
            seen_types.add(key)
            alerts.append(
                Alert(
                    alert_type="anomaly",
                    severity=severity_for_anomaly(score),
                    title=f"Unusual activity from {event.source_ip}",
                    description=triage_text(
                        "anomaly", source_ip=event.source_ip, score=score
                    ),
                    source_ip=event.source_ip,
                    user=event.user,
                )
            )
    return alerts

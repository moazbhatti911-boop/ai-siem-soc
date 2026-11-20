"""Triage: short plain-language explanations attached to every alert.

A SOC analyst should understand *why* an alert fired and what to do next
without reading model internals. Keep every message to one or two sentences
plus one recommended action.
"""

from typing import Optional

from shared.schemas import Alert


def triage_text(
    alert_type: str,
    source_ip: Optional[str] = None,
    user: Optional[str] = None,
    count: Optional[int] = None,
    score: Optional[float] = None,
) -> str:
    """Plain-language explanation for an alert type."""
    ip = source_ip or "an unknown IP"
    if alert_type == "brute_force":
        return (
            f"{count} failed logins from {ip} in a short window — this looks like "
            "a password-guessing (brute-force) attempt. Check whether the targeted "
            "account exists, block or rate-limit the IP, and enforce strong passwords."
        )
    if alert_type == "root_login":
        return (
            f"A login as root succeeded from {ip}. Root logins should be rare and "
            "audited — confirm this was an authorised administrator, then consider "
            "disabling direct root SSH login."
        )
    if alert_type == "sudo_use":
        return (
            f"User {user or 'unknown'} ran a command with sudo from {ip}. Sudo use is "
            "normal for admins but worth logging — verify the command was expected."
        )
    if alert_type == "anomaly":
        detail = f" (anomaly score {score:.2f})" if score is not None else ""
        return (
            f"Activity from {ip} does not match normal lab traffic{detail} — unusual "
            "time, volume or account for this host. Review the related events before "
            "deciding whether to escalate."
        )
    return "Unusual activity detected. Review the related events."


def explain_alert(alert: Alert) -> str:
    """One-line explanation for an already-built alert."""
    return triage_text(
        alert.alert_type, source_ip=alert.source_ip, user=alert.user
    )

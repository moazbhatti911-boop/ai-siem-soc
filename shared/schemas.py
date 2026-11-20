"""Shared Pydantic schemas for the AI-Powered SIEM & SOC Platform."""

from typing import Optional

from pydantic import BaseModel, Field


class LogEvent(BaseModel):
    """One parsed log event, as shipped by the ingestor and stored by the server."""

    timestamp: str
    host: str = "unknown"
    service: str = "unknown"
    user: Optional[str] = None
    source_ip: Optional[str] = None
    event_type: str = "other"  # failed_login | login_success | sudo | other
    message: str = ""
    raw: str = ""


class Alert(BaseModel):
    """A detection alert raised by the AI/rule engine."""

    id: Optional[int] = None
    alert_type: str  # brute_force | root_login | sudo_use | anomaly
    severity: str  # Low | Medium | High
    title: str
    description: str
    source_ip: Optional[str] = None
    user: Optional[str] = None
    status: str = "open"  # open | acknowledged
    created_at: Optional[str] = None


class Incident(BaseModel):
    """A SOC incident grouping one or more alerts."""

    id: Optional[int] = None
    title: str
    severity: str  # Low | Medium | High
    alert_ids: list[int] = Field(default_factory=list)
    status: str = "open"  # open | investigating | resolved
    created_at: Optional[str] = None

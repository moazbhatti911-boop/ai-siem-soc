"""SOC dashboard (Streamlit).

Run from inside the project folder (server must be running first)::

    streamlit run dashboard/app.py

Then open http://127.0.0.1:8503. Server URL and API key come from the
environment (``SIEM_SERVER_URL`` / ``SIEM_API_KEY``) and can be changed in
the sidebar.
"""

import os

import httpx
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

st.set_page_config(page_title="AI SIEM & SOC", layout="wide")
st.title("AI-Powered SIEM & SOC Platform")

server_url = st.sidebar.text_input(
    "Server URL", value=os.environ.get("SIEM_SERVER_URL", "http://127.0.0.1:8003")
)
api_key = st.sidebar.text_input(
    "API key", value=os.environ.get("SIEM_API_KEY", ""), type="password"
)
headers = {"X-API-Key": api_key}


def _get(path: str):
    # trust_env=False: the server is always local (127.0.0.1), so proxy
    # environment variables must never reroute or break this call.
    with httpx.Client(timeout=10.0, trust_env=False) as client:
        response = client.get(f"{server_url.rstrip('/')}{path}", headers=headers)
        response.raise_for_status()
        return response.json()


if not api_key:
    st.warning("Set the API key (sidebar or SIEM_API_KEY in .env) to load the SOC data.")
    st.stop()

try:
    stats = _get("/stats")
except Exception as exc:  # noqa: BLE001 - show any connection/auth error plainly
    st.error(f"Could not reach the server at {server_url}: {exc}")
    st.stop()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Events", stats.get("events", 0))
col2.metric("Alerts", stats.get("alerts", 0))
col3.metric("Open alerts", stats.get("open_alerts", 0))
col4.metric("Incidents", stats.get("incidents", 0))

by_severity = stats.get("alerts_by_severity", {})
st.subheader("Alerts by severity")
sev_cols = st.columns(3)
for i, severity in enumerate(["High", "Medium", "Low"]):
    sev_cols[i].metric(severity, by_severity.get(severity, 0))

st.subheader("Alert queue")
severity_filter = st.selectbox("Severity", ["All", "High", "Medium", "Low"])
alerts = _get("/alerts")
if severity_filter != "All":
    alerts = [a for a in alerts if a["severity"] == severity_filter]
if alerts:
    st.dataframe(
        [
            {
                "ID": a["id"],
                "Severity": a["severity"],
                "Type": a["alert_type"],
                "Title": a["title"],
                "Source IP": a.get("source_ip") or "-",
                "Status": a["status"],
            }
            for a in alerts
        ],
        use_container_width=True,
    )
    selected = st.selectbox(
        "Acknowledge an alert", [a["id"] for a in alerts if a["status"] == "open"],
        format_func=lambda aid: f"#{aid}",
    )
    if selected is not None and st.button("Acknowledge selected alert"):
        with httpx.Client(timeout=10.0, trust_env=False) as client:
            resp = client.post(
                f"{server_url.rstrip('/')}/alerts/{selected}/acknowledge", headers=headers
            )
        if resp.status_code == 200:
            st.success(f"Alert #{selected} acknowledged.")
            st.rerun()
        else:
            st.error(f"Failed to acknowledge: {resp.text}")
else:
    st.info("No alerts yet — ingest a log file to generate some.")

st.subheader("Recent events")
events = _get("/events?limit=50")
if events:
    st.dataframe(
        [
            {
                "Time": e["timestamp"],
                "Host": e["host"],
                "Service": e["service"],
                "User": e.get("user") or "-",
                "Source IP": e.get("source_ip") or "-",
                "Type": e["event_type"],
                "Message": e["message"],
            }
            for e in events
        ],
        use_container_width=True,
    )
else:
    st.info("No events stored yet.")

# Architecture

AI-Powered SIEM & SOC Platform. It ingests logs from your own lab
machines (or the bundled samples), detects suspicious activity with rules and
a small ML model, stores everything in SQLite, and shows it in a SOC
dashboard. Everything runs on `127.0.0.1`.

```
samples/*.log ──> ingestor ──POST /events──> server (FastAPI :8003)
                                                        │
                              SQLite (siem.db) ◄────────┤
                                                        │
                        dashboard (Streamlit :8503) ────┤
                        cli (python -m cli.main) ───────┘
```

## Components

| Component | What it does |
| --- | --- |
| `ingestor/` | Parses auth/syslog-style lines into `LogEvent`s and POSTs them to the server. |
| `ai_engine/` | Feature extraction, IsolationForest anomaly detection, rule scoring, triage text. |
| `server/` | FastAPI API on 127.0.0.1:8003, API-key auth, SQLite storage, alert/incident endpoints. |
| `dashboard/` | Streamlit SOC dashboard on 127.0.0.1:8503: stats, alert queue, acknowledge, events. |
| `cli/` | Argparse client: `list-alerts`, `show-alert`, `ack-alert`, `stats`. |
| `shared/` | Pydantic models shared by every component (`LogEvent`, `Alert`, `Incident`). |

## Data flow

1. The ingestor reads a log file line by line, parses each line, and sends
   one `POST /events` batch.
2. The server stores the events, then runs detection over the batch:
   rule alerts (brute force, root login, sudo) plus an IsolationForest
   anomaly check per source IP.
3. New alerts are stored with severity, a title and a plain-language triage
   explanation. The dashboard and CLI read them back through the API.

## Security notes

- Ingest logs from your own lab machines or the samples only.
- The server binds to `127.0.0.1` and every endpoint except `/health`
  requires the `X-API-Key` header.
- The API key lives in `.env`, which is git-ignored and must never be committed.

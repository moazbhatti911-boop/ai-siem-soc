# AI-Powered SIEM & SOC Platform

A Security Information and Event Management (SIEM) and Security
Operations Center (SOC) platform in Python. It ingests logs from your own lab
machines (or the bundled samples), detects suspicious activity with rules
plus a small machine-learning model, stores events and alerts in SQLite, and
shows them in a SOC dashboard.

> Ingest logs from your own lab machines or the sample logs only. The
> server binds to `127.0.0.1` and never talks to real networks. Do not
> point this at a production system or a network you do not own.

## What it does

- **Log ingestion** — parses auth/syslog-style lines (timestamp, host, user,
  source IP, event) and ships them to the server API.
- **Rule detection** — 5 failed logins from one IP → High brute-force alert;
  root login success → Medium; sudo use → Low.
- **AI anomaly detection** — a scikit-learn `IsolationForest` trained on
  normal lab traffic scores every event; unusual activity raises a
  Medium/High alert with a plain-language triage explanation.
- **SOC workflow** — alert queue by severity, acknowledge alerts, group
  alerts into incidents, stats and an event timeline.
- **Interfaces** — FastAPI server, Streamlit dashboard, and an argparse CLI.

## Requirements

- Python 3.10 or newer (`python --version`)
- Git (`git --version`)
- pip (comes with Python)
- About 600 MB free disk (scikit-learn + Streamlit dependencies)

## Installation

### Installation — Windows

```powershell
git clone https://github.com/<your-username>/ai-siem-soc.git
cd ai-siem-soc
python -m venv venv
venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
python -c "import fastapi, sklearn, streamlit; print('ok')"
```

### Installation — Kali Linux

```bash
git clone https://github.com/<your-username>/ai-siem-soc.git
cd ai-siem-soc
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python3 -c "import fastapi, sklearn, streamlit; print('ok')"
```

> Run every command below from **inside the `ai-siem-soc` folder**. On Kali,
> never use `venv\Scripts\activate` — that is Windows only.

## Generate Keys

```bash
# Kali Linux
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

```powershell
# Windows
copy .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Open `.env` and replace `change-this-api-key` with the generated key.
`SIEM_SERVER_URL` stays `http://127.0.0.1:8003`. Never commit `.env` —
it is already in `.gitignore`.

## Running on Kali Linux

Use 3 terminals. In each one, first run `cd ai-siem-soc` and
`source venv/bin/activate`.

**Terminal 1 — server:**

```bash
uvicorn server.main:app --reload --port 8003
```

Check it is up (do not close this terminal):

```bash
curl http://127.0.0.1:8003/health
```

Expected: `{"status": "ok", "service": "ai-siem-soc"}`

**Terminal 2 — ingestor (sample log):**

```bash
python3 -m ingestor.main --file samples/sample_auth.log
```

Expected: `Parsed 12 events ... Stored 12 events, 4 new alerts raised.`

**Terminal 3 — dashboard:**

```bash
streamlit run dashboard/app.py
```

Open http://127.0.0.1:8503 in the browser.

## Running on Windows

Same 3 terminals, with Windows commands. In each one, first run
`cd ai-siem-soc` and `venv\Scripts\activate`.

**Terminal 1 — server:**

```powershell
uvicorn server.main:app --reload --port 8003
```

Check: open http://127.0.0.1:8003/health in the browser.

**Terminal 2 — ingestor:**

```powershell
python -m ingestor.main --file samples/sample_auth.log
```

**Terminal 3 — dashboard:**

```powershell
streamlit run dashboard/app.py
```

Open http://127.0.0.1:8503 in the browser.

## Detection & AI

| Signal | Severity | What it means |
| --- | --- | --- |
| 5+ failed logins from one IP | High | Likely password-guessing (brute-force) attempt |
| Root login success | Medium | A root login happened — confirm it was authorised |
| Sudo use | Low | A privileged command ran — verify it was expected |
| IsolationForest anomaly score < 0 | Medium | Activity unlike normal lab traffic |
| IsolationForest anomaly score < −0.2 | High | Strongly unusual activity |

The model is a scikit-learn `IsolationForest` (`n_estimators=100`,
`contamination=0.1`, `random_state=42`) trained on synthetic normal lab
traffic: daytime hours, 0–1 failed logins, ordinary users. Each event is
scored on 6 features (failed logins from the IP, hour, failed-login flag,
root flag, sudo flag, new-IP flag). Every alert carries a plain-language
triage explanation — what happened and what to check next. See
`docs/ai-model.md` for details.

## API

Base URL: `http://127.0.0.1:8003`. Every endpoint except `/health` needs
the header `X-API-Key: <key from .env>`. Full reference: `docs/api.md`.

| Method | Path | Description |
| --- | --- | --- |
| GET | `/health` | Liveness check (no auth) |
| POST | `/events` | Ingest events, run detection |
| GET | `/events?limit=100` | Recent events |
| GET | `/alerts` | Alerts (`?severity=High`, `?status=open`) |
| GET | `/alerts/{id}` | One alert |
| POST | `/alerts/{id}/acknowledge` | Acknowledge an alert |
| POST | `/incidents` | Create an incident from alert ids |
| GET | `/incidents` | All incidents |
| GET | `/stats` | Event/alert/incident counts |

## CLI

The server must be running. Run from inside the project folder with the
venv activated.

```bash
python3 -m cli.main list-alerts
python3 -m cli.main list-alerts --severity High
python3 -m cli.main show-alert 1
python3 -m cli.main ack-alert 1
python3 -m cli.main stats
```

(On Windows use `python` instead of `python3`.)

## Tests

Run from **inside the project folder** (otherwise imports fail):

```bash
# Kali Linux
pytest -q

# Windows
pytest -q
```

The tests are fast and deterministic: small synthetic data, and the
IsolationForest uses a fixed `random_state`. The API tests use a temporary
database, so they never touch your real `siem.db`.

## Project Structure

```
ai-siem-soc/
├── ingestor/        # log parser, shipper, CLI entry point
├── ai_engine/       # features, IsolationForest anomaly model, scoring, triage
├── server/          # FastAPI server, config, auth, SQLite storage, alerts, incidents
├── dashboard/       # Streamlit SOC dashboard
├── cli/             # argparse client (list/show/ack alerts, stats)
├── shared/          # Pydantic models: LogEvent, Alert, Incident
├── samples/         # sample_auth.log (12 events: normal logins, brute force, root, sudo)
├── tests/           # pytest: parser, scoring, anomaly, API, triage
├── docs/            # architecture.md, ai-model.md, api.md
├── requirements.txt
├── pyproject.toml
├── .env.example
├── .gitignore
└── README.md
```

## Security

- Ingest logs from your own lab machines or the samples only.
- The server listens on `127.0.0.1` only; all API calls except `/health`
  require the `X-API-Key` header.
- The API key lives in `.env` and is git-ignored — never commit it, never
  paste it into chat, never hard-code it.
- The anomaly model is a hint, not proof of an attack: always read the
  events behind an alert before acting.

# AI Model

Detection combines deterministic rules with a small unsupervised ML model.
No external API or cloud service is used — the model trains locally in
milliseconds on synthetic normal traffic.

## Features

Each event becomes a 6-number vector (`ai_engine/features.py`):

| # | Feature | Meaning |
| --- | --- | --- |
| 1 | failed logins from this IP | How many failed logins this IP has so far |
| 2 | hour of day (0–23) | When the event happened |
| 3 | is failed login (0/1) | Event type |
| 4 | is root user (0/1) | Whether the account is root |
| 5 | is sudo (0/1) | Whether the event is a sudo command |
| 6 | is new source IP (0/1) | Whether the IP was seen before |

## Model

- **Algorithm:** scikit-learn `IsolationForest`
  (`n_estimators=100`, `contamination=0.1`, `random_state=42`).
- **Training data:** 240 synthetic rows of *normal* lab traffic — daytime
  hours (07:00–19:00), 0–1 failed logins, ordinary users. Generated with a
  fixed seed, so training is fully deterministic.
- **Scoring:** `decision_function()` — positive means normal, negative means
  anomalous. Threshold `0.0`; scores below `-0.2` are strong anomalies.

## How alerts are scored

| Signal | Severity | Alert |
| --- | --- | --- |
| 5+ failed logins from one IP | High | Possible brute-force attack |
| Root login success | Medium | Root login succeeded |
| Sudo use | Low | Sudo command used |
| Anomaly score < 0 | Medium | Unusual activity |
| Anomaly score < −0.2 | High | Unusual activity |

Rule alerts and anomaly alerts are de-duplicated per source IP so re-ingesting
the same log does not spam the queue. Every alert carries a plain-language
triage explanation (`ai_engine/triage.py`) saying what happened and what to
check next.

## Limits

- The model knows only the synthetic "normal" baseline above; real networks
  have their own baseline. Retrain on your own lab's normal traffic before
  trusting it on anything else.
- It is an anomaly *hint*, not proof of an attack — always read the events
  behind an alert before acting.

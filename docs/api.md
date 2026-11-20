# API

Base URL: `http://127.0.0.1:8003`

Every endpoint except `GET /health` requires the header:

```
X-API-Key: <your key from .env>
```

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| GET | `/health` | Liveness check, returns `{"status": "ok"}`. No auth. |
| POST | `/events` | Ingest a list of `LogEvent`s; runs detection. Returns `{"stored": n, "alerts_created": m}`. |
| GET | `/events?limit=100` | Most recent events, newest first. |
| GET | `/alerts` | Alerts, newest first. Filters: `?severity=High`, `?status=open`. |
| GET | `/alerts/{id}` | One alert. |
| POST | `/alerts/{id}/acknowledge` | Mark an alert acknowledged. |
| POST | `/incidents` | Create an incident: `{"title", "severity", "alert_ids": [1, 2]}`. |
| GET | `/incidents` | All incidents, newest first. |
| GET | `/stats` | Counts: events, alerts, open alerts, alerts by severity, incidents. |

## Examples

```bash
# Health check (no key needed)
curl http://127.0.0.1:8003/health

# Stats (needs the key from .env)
curl -H "X-API-Key: YOUR_KEY" http://127.0.0.1:8003/stats

# High alerts only
curl -H "X-API-Key: YOUR_KEY" "http://127.0.0.1:8003/alerts?severity=High"

# Acknowledge alert #1
curl -X POST -H "X-API-Key: YOUR_KEY" http://127.0.0.1:8003/alerts/1/acknowledge
```

## Objects

- `LogEvent`: `timestamp`, `host`, `service`, `user`, `source_ip`,
  `event_type` (`failed_login` | `login_success` | `sudo` | `other`),
  `message`, `raw`.
- `Alert`: `id`, `alert_type`, `severity` (`Low` | `Medium` | `High`),
  `title`, `description`, `source_ip`, `user`, `status`, `created_at`.
- `Incident`: `id`, `title`, `severity`, `alert_ids`, `status`, `created_at`.

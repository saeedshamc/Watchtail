# Watchtail

A lightweight, self-hosted log monitoring and threat-detection tool.

Watchtail tails the log files you already have — nginx and Apache access
logs, Linux `auth.log` — parses them as they grow, spots suspicious
behaviour (SSH brute force, repeated 403/404 probing, abnormal request
bursts) and shows everything on a live web dashboard. It is a fast,
minimal-dependency alternative to heavyweight stacks like ELK: copy a
config, run one command, open a browser.

## Features

- **Live tailing** of any number of log files, one worker thread per
  source, with rotation and truncation handling
- **Parsers** for nginx and Apache combined access logs, Linux
  `auth.log` (sshd), generic and RFC 5424 syslog, and JSON-lines
  structured logs
- **Rule-based detection**: failed-SSH-login bursts, 403/404 spikes,
  request bursts, path scanning, post-failure SSH logins, distributed
  credential-stuffing campaigns and multi-signal correlation — all
  with thresholds, windows and severities editable from the settings
  page
- **Threat scoring** with time decay, surfacing the highest-risk IPs
  first on a dedicated dashboard panel
- **Threat intel**: local blocklists (FireHOL netsets, AbuseIPDB CSV)
  flag known-bad addresses as critical on first sight; optional
  offline GeoIP country enrichment
- **Alerting your way**: webhook, email (SMTP) and Telegram with
  per-channel severity routing plus a daily digest — and a REST API
  with hashed bearer tokens for machine integrations
- **Response workflow**: ready-to-review firewall commands for six
  platforms with an immutable audit trail (watchtail never touches
  the firewall itself)
- **Multi-user** with admin and viewer roles, managed via the CLI
- **Live dashboard** — server-rendered pages, Chart.js traffic and 4xx
  graphs, event table updating over Socket.IO
- **Flagged IPs** with one-click review or dismissal, operator notes
  and tags for tracking investigations
- **Webhook alerts** through a pluggable notifier interface
- **Single admin login**, PBKDF2-hashed password, session-based
- **SQLite storage** via SQLAlchemy, swappable for PostgreSQL through a
  single config line

## Requirements

- Python 3.11 or newer
- Read access to the log files you want to monitor

> **Prefer an installer?** Ready-made packages — a Windows portable
> zip and installer, Linux AppImage and deb — are described in
> [docs/INSTALL.md](docs/INSTALL.md); no Python needed on the target
> machine.

## Quick start

```bash
git clone <repository-url> watchtail
cd watchtail

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
python scripts/fetch_vendor.py   # downloads Chart.js / socket.io client

cp config/watchtail.example.yml watchtail.yml
# edit watchtail.yml: point sources at your real log paths

export WATCHTAIL_ADMIN_PASSWORD='choose-a-password'
python run.py
```

Open `http://127.0.0.1:5555` and log in. If you skip
`WATCHTAIL_ADMIN_PASSWORD`, a random password is generated and printed
once at startup.

Prefer containers? `docker compose up -d` gives you the same dashboard
with persistent storage — see [docs/INSTALL.md](docs/INSTALL.md) for
the Docker section. Lost the admin password? Reset it with
`python -m app.cli passwd`.

### Running the tests

```bash
python -m pytest
```

## Configuration

Watchtail reads `watchtail.yml` from the working directory (override
with `python run.py --config path/to/file.yml`). See
[config/watchtail.example.yml](config/watchtail.example.yml) for a fully
commented example. The essentials:

```yaml
server:
  host: 127.0.0.1
  port: 5555

database:
  # Any SQLAlchemy URL; e.g. postgresql+psycopg://user:pass@host/watchtail
  url: sqlite:///data/watchtail.db

sources:
  - name: auth log
    type: auth            # auth | nginx | apache | syslog | syslog5424 | json
    path: /var/log/auth.log
    enabled: true

detectors:
  ssh_bruteforce:
    enabled: true
    max_failures: 5       # alert after N failures...
    window_seconds: 300   # ...within this many seconds, per IP
  http_error_spike:
    enabled: true
    max_errors: 20
    window_seconds: 60
    status_codes: [403, 404]
  request_burst:
    enabled: true
    max_requests: 120
    window_seconds: 60

notifier:
  webhook:
    url: ""               # POST target for alert JSON; empty = disabled
    timeout_seconds: 5
```

Secrets stay out of the YAML: `WATCHTAIL_ADMIN_PASSWORD` sets the
dashboard password and `WATCHTAIL_SECRET_KEY` the session key (a key is
generated and stored under `data/` when unset). `WATCHTAIL_DATABASE_URL`
overrides `database.url`.

Sources can also be added, paused and removed from the dashboard's
Sources page; rows declared in the config file are re-applied on
startup.

## Screenshots

> Placeholder — replace with real captures.

![Dashboard](docs/screenshots/dashboard.png)

*Dashboard: live events, traffic chart and flagged IPs.*

![Sources](docs/screenshots/sources.png)

*Sources: manage monitored log files.*

## Production notes

- The dev server (`python run.py`) is fine for trying Watchtail out.
  For longer-lived deployments, run it behind a WSGI server with
  eventlet, e.g.
  `gunicorn --worker-class eventlet -w 1 'app:create_app()'` together
  with a Socket.IO-capable entrypoint, or keep `run.py` behind a
  reverse proxy with TLS.
- Point the webhook at an incoming-webhook URL (Slack-compatible
  payloads work out of the box for simple notification flows).
- Events and alerts older than `retention.max_age_days` are trimmed at
  startup.

## Project layout

```
app/
  __init__.py      app factory, security headers, admin bootstrap
  cli.py           `python -m app.cli passwd` admin CLI
  config.py        YAML settings loader (WATCHTAIL_CONFIG aware)
  database.py      engine/session management
  models.py        LogSource, Event, Alert, IpStatus, AdminUser
  tailer.py        per-source tail threads with rotation handling
  pipeline.py      tailer -> persistence -> detection -> notifier
  realtime.py      Socket.IO broadcaster + periodic stats snapshots
  auth.py          session auth helpers
  parsers/         nginx, apache, auth, syslog, rfc5424, json-lines
  settings route   detector thresholds UI writing back to config
  detectors/       brute force, 4xx spike, burst, path scan, ssh compromise
  notifiers/       webhook notifier + registry
  routes/          dashboard, events, ip detail, respond, settings, api v1, sources, reviews, auth, health
  scoring.py       threat score with decay
  threatintel.py   local blocklist store and lookup
  response.py      firewall command suggestions + audit trail
  tokens.py        hashed API token lifecycle
  geoip.py         optional offline country enrichment
  templates/       Jinja2 templates
  static/          CSS, JS and vendored vendor bundles
config/            example watchtail.yml
tests/             pytest suites
scripts/           vendor fetch helper
Dockerfile         production image (gunicorn + eventlet, non-root)
docker-compose.yml single-container deployment with persistent volume
run.py             entrypoint (dev/server mode with live tailing)
wsgi.py            WSGI entrypoint for gunicorn
```

## License

[MIT](LICENSE)

# MailGate

> **Deutsch:** MailGate ist ein selbst gehostetes E-Mail-Sicherheitstor für persönliche KI-Assistenten. Es liest ein eigenes Postfach ausschließlich per IMAP, bereinigt und bewertet Nachrichten und gibt nur ausdrücklich freigegebene Inhalte über eine stark begrenzte Lese-API weiter. Der aktuelle Stand ist ein technischer Release Candidate, noch keine Produktionsfreigabe.

MailGate is an open-source, self-hosted security boundary between an owner's mailbox and a personal AI assistant. Each installation manages only its owner's data, uses no telemetry by default, and never gives the assistant IMAP, SMTP, database, delete, move, or write access.

## Current status

The release-candidate implementation includes:

- a responsive English/German owner setup, dashboard, mailbox creation, editing, credential
  rotation and local deletion, quarantine review, message details, tokens, status, and audit UI;
- TLS-only read-only IMAP ingestion using read-only mailbox selection and `BODY.PEEK[]`;
- idempotency by mailbox, `UIDVALIDITY`, and UID;
- bounded MIME processing, safe HTML-to-text conversion, visible Unicode control characters, normalized link inventory, and attachment metadata without storing attachment bytes;
- independent DKIM verification over unchanged raw bytes through a secretless, bounded DNS resolver,
  kept separate from provider `Authentication-Results` claims for SPF, DKIM, DMARC, and ARC;
- deterministic risk, category, priority, quarantine, and approval policy;
- revocable, rate-limited, hash-at-rest API tokens with the fixed scope
  `messages:read:approved`; tokens expire by default, while an explicit lifetime of `0` creates a
  higher-risk token without automatic expiry;
- a GET-only API that returns approved sanitized fields and hides quarantined IDs;
- Docker Compose with PostgreSQL, separate owner-web, approved-only API and worker processes, Caddy, file-backed secrets, non-root read-only application containers, and an optional automatic-HTTPS production override;
- a database-enforced approved-only API view/function and a dedicated API role that cannot read base, token, audit, mailbox or attachment tables;
- destination-enforced IMAPS egress through an SNI-checking relay; the worker has no direct external network and one installation permits exactly one configured IMAP host on port 993;
- synthetic unit, adversarial, fuzz, browser/Axe, UI authorization, API authorization, IMAP
  command-boundary, PostgreSQL privilege, backup/restore, and key-rotation tests;
- an owner-only local prompt-injection self-test, including PDF-attachment containment, that
  performs no SMTP, IMAP, or message-store mutation and makes no claim to inspect PDFs or detect
  every possible injection;
- a public, static “How MailGate works” page plus owner-only observed local status, and a
  GitHub-friendly translation workflow documented in [docs/translating.md](docs/translating.md).

This is deliberately **not yet labelled production-ready**. The technical V1 release-candidate gates
are implemented and tested, including an encrypted restore drill and credential-key rotation. An
independent 15-minute installation acceptance and the required four-week isolated pilot remain open.
See [release gates](docs/release-gates.md) and [release evidence](docs/release-evidence.md).

## Quick start for local evaluation

Prerequisites: Docker Engine with Docker Compose and Python 3.13 or 3.14 for host-side tools.

```text
python scripts/create_local_secrets.py
copy .env.example .env
# Edit MAILGATE_IMAP_ALLOWED_HOST in .env before adding a mailbox.
python scripts/doctor.py
docker compose up --build -d
```

Open `http://127.0.0.1:8080/setup/`, copy the bootstrap value from
`.local/secrets/setup_token`, create the sole installation owner, then connect a dedicated
test mailbox. Never reuse mailbox credentials pasted into chat, logs, issues, or screenshots;
rotate them first.

The [operations runbook](docs/operations.md) covers health checks, encrypted backup/restore,
credential rotation, retention, owner export, upgrades, and rollback.

Stop without deleting data:

```text
docker compose down
```

`docker compose down --volumes` permanently removes the local database volume and should be used only intentionally.

## Production-like HTTPS evaluation

Point a DNS name at the host, allow inbound ports 80/443, and set non-secret environment values:

```text
MAILGATE_DOMAIN=mailgate.example.org
MAILGATE_ENVIRONMENT=production
MAILGATE_HTTPS_ONLY=true
MAILGATE_TRUST_PROXY_HEADERS=true
MAILGATE_IMAP_ALLOWED_HOST=imap.example.org
docker compose -f compose.yaml -f compose.production.yaml up --build -d
```

Caddy obtains and renews certificates automatically. The public HTTPS vhost returns 404 for
`/api/*`; the agent API remains available only at the host-loopback listener
`http://127.0.0.1:8080`. This deployment path is for release-candidate evaluation until all
[release gates](docs/release-gates.md) pass.

## Read-only API

Create a token in the owner UI. The raw value is displayed once.
The default expiry is 90 days. Entering `0` disables automatic expiry; use this only when Hermes
cannot rotate credentials and revoke the token manually when it is no longer needed.

```text
GET /api/v1/messages?state=approved&limit=50
GET /api/v1/messages/{uuid}/summary
GET /api/v1/categories
Authorization: Bearer mg_...
```

All non-GET methods are rejected. The API has no endpoints for raw mail, attachments, quarantine, sending, replying, deletion, moving, or state changes.

## Security model

- Email, HTML, headers, links, attachments, and future model output are untrusted input.
- Untrusted/missing authentication provenance, parser defects, dangerous attachments, and processing errors fail closed into internal review.
- Provider SPF/DKIM/DMARC/ARC statements are not treated as independent MailGate verification.
- Raw message bodies and attachment bytes are not retained.
- Attachment metadata is inventoried, but PDF contents are not interpreted or declared safe.
- Only deterministic application policy changes state; owners can explicitly review quarantined items.
- API authorization is independent of the owner browser session, content-minimal, audited, and `Cache-Control: no-store`.
- No telemetry or remote content loading is implemented.

Read the [threat model](docs/threat-model.md), [architecture](docs/architecture.md), [v1 boundary ADR](docs/decisions/0002-v1-security-boundaries.md), and [German project plan](docs/projektplan.md).

## Development

```text
python -m pip install --require-hashes -r requirements.lock
$env:PYTHONPATH="app;worker"  # PowerShell
$env:DJANGO_SETTINGS_MODULE="mailgate.test_settings"
python app/manage.py test tests --settings=mailgate.test_settings
python app/manage.py check --settings=mailgate.test_settings
docker compose config --quiet
docker compose build web
```

The repository layout is:

```text
app/gateway/       domain models, mail pipeline, owner UI, read-only API
app/mailgate/      Django configuration and health endpoints
worker/            periodic read-only mailbox ingestion
tests/             synthetic and adversarial tests; never real mail
deploy/            local and automatic-HTTPS Caddy configurations
docs/              plan, architecture, threat model, ADRs, release gates
scripts/           local secret bootstrap helpers
```

## Security reporting and contributing

Never submit real credentials, private addresses, message content, or tokens. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Development guidance is in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MailGate is licensed under the [GNU Affero General Public License v3.0](LICENSE) (`AGPL-3.0-only`).

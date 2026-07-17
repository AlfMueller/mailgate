# Development and release-candidate operation

## Local stack

```text
python scripts/create_local_secrets.py
docker compose up --build -d
docker compose ps
```

Services prefixed with `install-` are one-shot installation jobs. A successful stack shows them as
exited after they bootstrap database roles, apply migrations, and verify least-privilege grants.
Only `db`, `web`, `api`, `worker`, `imap-egress`, and `proxy` remain running.

The generator creates nine independent, ignored files under `.local/secrets` for Django signing,
database roles, authenticated mailbox-credential encryption, and owner bootstrap. It refuses to
overwrite any existing file. On POSIX hosts, the directory remains owner-only (`0700`), while its
files are read-only (`0444`) because Compose bind-mounted secrets retain host ownership and the
containers run as UID 10001. On multi-user Windows hosts, keep this directory on an owner-only
volume and verify its ACL; POSIX mode bits alone do not replace Windows ACLs.

Open `http://127.0.0.1:8080/setup/`. Health checks remain available at `/health/live` and `/health/ready`.

Copy `.env.example` to `.env` and set the single operator-approved IMAP DNS hostname before adding a
mailbox. Port 993 is mandatory. The worker connects only over certificate-verified IMAPS through an
SNI-enforcing relay, requests a read-only mailbox, and fetches with `BODY.PEEK[]`. It has no direct
external network, SMTP implementation or SMTP credentials. Use only a dedicated, isolated,
synthetic test mailbox during the release-candidate phase.

## Tests

```text
$env:PYTHONPATH="app;worker"
$env:DJANGO_SETTINGS_MODULE="mailgate.test_settings"
python app/manage.py test tests --settings=mailgate.test_settings
python app/manage.py check --settings=mailgate.test_settings
python app/manage.py makemigrations --check --dry-run --settings=mailgate.test_settings
python -m compileall -q app worker scripts tests
docker compose config --quiet
docker compose build web
docker compose --profile integration up --build --detach --wait
```

The explicit `integration` profile adds a synthetic TLS IMAP upstream and a one-shot PostgreSQL
boundary test. It verifies an allowed certificate-checked SNI path, rejected SNI/direct egress,
real API-function behavior, worker quarantine enforcement, denied message mutation, and both
mailbox-configuration/worker lock orderings without using a real mailbox.

All fixtures must use reserved domains such as `example.test`, synthetic tokens, and invented content. Real mail, credentials, private addresses, or copied production headers are prohibited.

## HTTPS evaluation

Use the production override with a real DNS name:

```text
MAILGATE_DOMAIN=mailgate.example.org
MAILGATE_IMAP_ALLOWED_HOST=imap.example.org
docker compose -f compose.yaml -f compose.production.yaml up --build -d
```

The override enables automatic HTTPS, exact hosts/origins, proxy-header trust, HSTS, secure cookies,
and mandatory restricted IMAP egress. A production environment intentionally refuses to start
without HTTPS and IMAP-egress enforcement. Production deployment support is currently limited to
Linux Docker Engine; Docker Desktop is a development/integration environment.

## Data lifecycle

The PostgreSQL volume is the sole persistent message store. Raw email and attachment bytes are not stored. The master key is not in the database; losing it makes mailbox credentials unrecoverable.

`MAILGATE_WORKER_POLL_INTERVAL_SECONDS` controls the normal mailbox polling interval and defaults to
30 seconds. The owner status page uses the same value and reports a stale observation only after
more than two expected cycles plus a small tolerance.

Before pilot operation, implement and test encrypted backup/restore plus key rotation as listed in `docs/release-gates.md`. Until those gates pass, do not treat the database volume as production data.

`docker compose down` retains volumes. `docker compose down --volumes` irreversibly removes the database volume; delete the external secrets directory separately only after confirming that destruction is intended.

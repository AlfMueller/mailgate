# Development Foundation

Status: first Phase 1 scaffold. Mail ingestion and the graphical setup are not implemented yet.

## Verified platform baseline

- Python 3.13 (current patch line; container tag currently `3.13.14-slim-bookworm`)
- Django 5.2 LTS (`5.2.16`)
- PostgreSQL 17 (`17.10-bookworm`)
- Psycopg 3 (`3.3.4`)
- Gunicorn (`26.0.0`)

Direct and transitive Python dependencies are recorded with hashes in `requirements.lock`. Updating a dependency requires regenerating the lock file, reviewing the diff and licenses, rebuilding the image, and running the full checks.

Dockerfile frontend, Python, PostgreSQL, and Caddy references include immutable image digests. The readable version tags remain alongside the digests for maintenance and review.

## Local container startup

Create local secret files once:

```text
python scripts/create_local_secrets.py
```

The script refuses to overwrite existing values. The `.local` directory is ignored by Git. Secret values must never be placed in `.env`, Compose YAML, screenshots, logs, issues, or commits.

Build and start the foundation:

```text
docker compose up --build -d
docker compose ps
```

The current web surface is intentionally limited to:

```text
GET http://127.0.0.1:8080/health/live
GET http://127.0.0.1:8080/health/ready
```

Stop the stack with `docker compose down`. Add `--volumes` only when intentionally deleting the local PostgreSQL data volume.

## Architecture enforced by Compose

- `proxy` is the only service attached to the frontend network and publishes the loopback port.
- `web` is attached only to the internal application and database networks.
- `worker` is attached to the database network and its own egress network.
- `db` is not published to the host.
- application containers run as UID/GID 10001, use read-only root filesystems, and set `no-new-privileges`; web and worker drop all Linux capabilities, while the proxy retains only `NET_BIND_SERVICE` because the official Caddy binary carries that file capability.
- a one-shot `migrate` service runs database migrations before web and worker start.
- only services that need a secret receive its mounted file.

The database image still performs its standard initialization behavior. Further database UID and capability hardening will be tested before production guidance is published.

## Checks

Tests use the built application image and its hash-locked dependencies, with the repository mounted read-only as test source:

```text
docker compose run --rm --no-deps \
  --volume .:/workspace:ro \
  --workdir /workspace \
  -e MAILGATE_ENVIRONMENT=test \
  -e MAILGATE_DATABASE_ENGINE=sqlite \
  -e PYTHONPATH=/workspace/app:/workspace/worker \
  web python app/manage.py test tests --settings=mailgate.test_settings
```

CI also compiles all Python sources, runs Django system checks, validates Compose configuration, and builds the container image.

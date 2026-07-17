# Production operations

This runbook applies to the supported Linux Docker Engine deployment. Keep the repository,
`.local/secrets`, encrypted backups, and recovery keys on owner-controlled storage. Never paste a
secret, mailbox address, message, token, or backup metadata into an issue or support chat.

## Pre-flight

Install the pinned host-side runtime once in an owner-controlled Python 3.13 virtual environment:

```text
python -m venv .venv
# Activate .venv using the command for your shell.
python -m pip install --require-hashes --requirement requirements.lock
```

Run the read-only doctor before installation, update, backup, and pilot review:

```text
python scripts/doctor.py
docker compose config --quiet
docker compose ps
```

The runtime containers must remain non-root and healthy. `worker` may reach only the internal IMAP
and DKIM-resolution relays. The public production vhost must return 404 for `/api/*`; the private
agent API remains bound to host loopback.

## Credential-key rotation

Mailbox passwords use a versioned Fernet keyring. Existing single-key installations remain readable
through the legacy `master_key` fallback while records are moved to the current primary key.

1. Create an encrypted database backup and complete an isolated restore drill.
2. Stop ingestion: `docker compose stop worker`.
3. Add a new primary key atomically with the keyring rotation helper. Use a non-sensitive key ID,
   for example `k2026q3`; the generated key value is never printed.
4. Recreate web: `docker compose up --detach --force-recreate web`.
5. Run `docker compose run --rm install-migrate python app/manage.py rotate_mailbox_credentials`.
6. Run `docker compose run --rm install-migrate python app/manage.py verify_mailbox_credentials`.
7. Recreate the worker with `docker compose up --detach --force-recreate worker` and confirm one
   read-only sync cycle.
8. Retain the previous key through the backup/rollback window. Remove it only after a second backup
   and restore drill proves every stored credential uses the new primary.

Rotation is transactional at the database layer: an unreadable credential rolls back every record.
The worker configuration-version guard prevents an in-flight old credential from persisting state.

Changing Django signing keys intentionally invalidates owner sessions unless the old key is supplied
through Django's fallback-key mechanism. Rotate the API signing key by replacing its file and
recreating `api`; agent bearer tokens are database hashes and are not signing-key-derived.

Database role passwords are not all equivalent. The application-role files are reconciled by the
`install-db-bootstrap` job. PostgreSQL's initial admin password is only consumed when a volume is
created, so use the dedicated database-password rotation helper; replacing `postgres_password` by
hand can lock the installation out.

## Encrypted backup

`backup_key` is independent from the mailbox credential keyring and is never mounted into a runtime
container. Store an offline copy separately. The backup contains a PostgreSQL custom-format dump and
the credential-key recovery bundle inside one AES-256-GCM authenticated archive. The dump streams
directly into encryption; an existing output is never overwritten.

```text
python scripts/backup.py .local/backups/mailgate-YYYYMMDD.mgb
```

The command prints only content-minimal archive metadata. Treat the archive as sensitive even though
it is encrypted. Copy it off-host and apply retention to old archives.

## Isolated restore drill

Never test a restore over the only production database. Start a separate Compose project with no
public proxy or worker:

```text
docker compose --project-name mailgate-restore-drill up --detach db
docker compose --project-name mailgate-restore-drill run --rm install-db-bootstrap
python scripts/restore.py .local/backups/mailgate-YYYYMMDD.mgb \
  --project-name mailgate-restore-drill \
  --confirm "RESTORE mailgate-restore-drill" \
  --credential-output-dir .local/recovered-credential-keys
docker compose --project-name mailgate-restore-drill run --rm install-migrate
docker compose --project-name mailgate-restore-drill run --rm install-db-permissions
```

The restore decrypts to a mode-`0600` temporary file only after archive authentication and deletes it
after `pg_restore`. Verify migrations, record counts, credential decryption, API database boundaries,
and a read-only synthetic sync. Destroy only the explicitly named drill project afterward:

```text
docker compose --project-name mailgate-restore-drill down --volumes
```

## Retention, export, and deletion

Preview retention first; applying it is explicit and bounded:

```text
docker compose run --rm install-migrate python app/manage.py purge_retention
docker compose run --rm install-migrate python app/manage.py purge_retention --apply
```

The command accepts separate day limits for approved, quarantined, rejected, inactive-token, and
audit records. It preserves mailbox UID cursors so locally expired messages are not imported again.

Create a versioned, secret-free owner export with:

```text
mkdir .local/exports
docker compose run --rm install-migrate python app/manage.py export_owner_data --output - \
  > .local/exports/mailgate-owner.ndjson
```

The redirection happens on the host; restrict the resulting file to the owner. PowerShell users can
pipe to `Set-Content -Encoding utf8 .local/exports/mailgate-owner.ndjson` instead. Create
`.local/exports` first. Exports omit mailbox
passwords, password hashes, token hashes, secret values, and audit metadata, but still contain
personal message data and require owner-only storage.

Deleting a mailbox in the UI removes its local messages and attachment metadata by database cascade
without changing the remote mailbox. Complete installation deletion additionally requires removing
the explicitly resolved database/Caddy volumes, external secrets, exports, and every backup copy.
Prefer cryptographic deletion by destroying the separately held backup key, then remove media copies
according to the storage provider's process.

## Upgrade and rollback

1. Record the current image digest and application version.
2. Create and restore-test an encrypted backup.
3. Download the release bundle, verify `SHA256SUMS` and the GitHub artifact attestation, then load
   `mailgate.release.env`. It pins `MAILGATE_IMAGE` to the verified `sha256` digest; do not replace
   it with a mutable tag.
4. Start the target with `compose.release.yaml` plus `compose.production.yaml`. In PowerShell use
   `$env:MAILGATE_IMAGE=(Get-Content mailgate.release.env).Split('=', 2)[1]`; in a POSIX shell use
   `set -a; . ./mailgate.release.env; set +a` before `docker compose`.
5. Run health, database-boundary, private/public API, and read-only IMAP checks.

Do not reverse a data migration in place. Rollback means a fresh volume restored from the pre-upgrade
backup and the previously recorded immutable image digest. Rotate sessions, agent tokens, and
database passwords after an incident-driven restore.

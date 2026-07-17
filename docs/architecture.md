# Architecture

Status: technical release candidate; production release gates remain open.

## Components and authority

| Component | Responsibility | Possesses | Explicitly denied |
| --- | --- | --- | --- |
| `proxy` | Local ingress or production TLS | public/private listeners | database and mail credentials |
| `web` | owner bootstrap, review UI, GET-only agent API | web DB role, setup token, credential master key | network route to IMAP/SMTP |
| `worker` | read-only IMAP, bounded parsing and ingestion | worker DB role, credential master key, IMAP egress | owner/session/token tables; approval updates; SMTP |
| `install-migrate` | one-shot schema migrations | migration DB role | runtime services |
| `install-db-bootstrap` | one-shot creation/rotation of fixed least-privilege roles | PostgreSQL admin secret | application runtime |
| `install-db-permissions` | one-shot post-migration worker grants and permission self-test | PostgreSQL admin secret | application runtime |
| `db` | local persistent state | PostgreSQL volume | host/public port |

The current web process contains both owner UI and agent API. A separate API process plus an
approved-only database view remains a release gate before v1.

## Data flow

1. The owner unlocks first-time setup with an independent file-backed bootstrap token.
2. Mailbox passwords are Fernet-encrypted under a file-backed master key independent of Django and
   PostgreSQL.
3. The worker connects with TLS, selects `INBOX` read-only and fetches new UID records with
   `BODY.PEEK[]`.
4. The parser bounds raw bytes, MIME parts, text, links and attachments. It emits safe text and
   metadata; raw mail and attachment bytes are discarded.
5. Explicitly configured provider `Authentication-Results` claims are recorded as untrusted signals.
   They never cause automatic approval.
6. Deterministic rules quarantine every newly ingested message; the owner may approve the sanitized
   representation or reject it.
7. Random UUIDs identify messages. The agent API accepts only revocable bearer tokens with fixed
   scope `messages:read:approved`. Tokens expire by default, with an explicit no-expiry owner option.
   The API returns only approved, sanitized fields.

## Agent contract

```text
GET /api/v1/messages?state=approved
GET /api/v1/messages/{uuid}/summary
GET /api/v1/categories
scope: messages:read:approved
```

All other methods and non-approved filters fail closed. There is no raw mail, attachment, quarantine,
send, reply, delete, move or state-change endpoint. Production Caddy blocks `/api/*` on the public
vhost; the API is available only on the host-loopback listener unless a future private transport is
explicitly configured.

## Remaining boundaries

The exact unfulfilled requirements are tracked in [release-gates.md](release-gates.md). In particular,
the combined web/API process, egress enforcement, key rotation, backup/restore, independent DKIM,
broader adversarial testing and the four-week pilot prevent a production claim.

# Planned Architecture

Status: Phase 1 foundation implemented; mailbox ingestion and inspection pipeline still planned.

## Current foundation

The repository now enforces the first deployable process boundaries:

- Caddy is the only process connected to the frontend network and host loopback port.
- Django is reachable only through Caddy and is attached to internal application and database networks.
- The worker is attached to the internal database network and a separate egress network.
- PostgreSQL is attached only to the internal database network and has no published port.
- Compose mounts secret files only into the services that need them.
- Web, worker, and proxy run unprivileged with read-only root filesystems and restricted Linux capabilities.

The current HTTP surface contains only liveness and database-readiness checks. There is no IMAP, SMTP, AI-agent API, classification, message, or owner-data implementation yet.

## Design objective

MailGate separates an owner-controlled mailbox from an AI agent. It reduces untrusted messages to sanitized, explicitly approved records before the agent can read them. The architecture limits authority even if a message, parser input, classifier response, or AI-agent request is malicious.

## Planned components

| Component | Responsibility | Allowed external access | Explicitly denied |
| --- | --- | --- | --- |
| `worker` | Fetch mail, parse MIME, evaluate authentication, sanitize, classify, apply policy | Configured mail provider and configured model provider | AI-agent requests, UI sessions, arbitrary tools |
| `web` | Owner setup, review UI, administration, restricted API | Inbound HTTPS through the proxy | Direct IMAP/SMTP access |
| `db` | Persist local owner configuration, message state, and minimal audit data | Internal application networks only | Public network exposure |
| `proxy` | Terminate HTTPS and route allowed inbound traffic | Inbound HTTPS | Mail credentials and classification logic |
| `agent-adapter` (optional) | Map the same restricted read-only operations for an AI agent | MailGate API and the owner's AI agent | IMAP, SMTP, database, quarantine, write operations |

The `web` and `worker` processes may use the same versioned image, but they must run separately with different credentials, network routes, and privileges.

## Planned data flow

1. The worker connects to a mailbox configured by the installation owner.
2. It records provider-authenticated transport signals and ignores untrusted look-alike headers.
3. It parses MIME with bounded size, depth, time, and supported formats.
4. It produces sanitized text without executing content or loading remote resources.
5. Technical checks and an optional classifier produce structured signals.
6. A deterministic policy validates those signals and selects an allowed state transition.
7. The database stores local state and only the content required by configured retention rules.
8. The web UI exposes owner controls; the AI-agent API exposes only approved, sanitized summaries.

## AI-agent contract

The initial credential scope is:

```text
messages:read:approved
```

The planned first endpoints are:

```text
GET /api/v1/messages?state=approved
GET /api/v1/messages/{id}/summary
GET /api/v1/categories
```

There will be no AI-agent endpoint for sending, replying, deleting, moving, changing state, accessing quarantine, reading unprocessed messages, or downloading raw attachments. Unsupported HTTP methods and broader scopes must fail closed.

## Deployment boundaries

- One installation serves one owner and stores only that owner's data.
- The API defaults to a private Docker network. Remote AI-agent deployments require an explicitly configured private transport such as WireGuard, Tailscale, or mTLS.
- Containers run as non-root with minimal capabilities and writable paths.
- Secrets are mounted from files or a suitable secrets mechanism, never committed or embedded in images.
- The classifier has neither mailbox credentials nor general-purpose tools.
- External model use is explicit, configurable, and limited to the necessary sanitized fields.
- Telemetry is off by default and no data is sent to a MailGate-operated service.

These statements are requirements to be tested before release, not claims about a current implementation.

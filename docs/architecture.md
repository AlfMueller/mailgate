# Planned Architecture

Status: design baseline; no implementation exists yet.

## Design objective

MailGate separates an owner-controlled mailbox from an AI assistant. It reduces untrusted messages to sanitized, explicitly approved records before Hermes can read them. The architecture limits authority even if a message, parser input, classifier response, or Hermes request is malicious.

## Planned components

| Component | Responsibility | Allowed external access | Explicitly denied |
| --- | --- | --- | --- |
| `worker` | Fetch mail, parse MIME, evaluate authentication, sanitize, classify, apply policy | Configured mail provider and configured model provider | Hermes requests, UI sessions, arbitrary tools |
| `web` | Owner setup, review UI, administration, restricted API | Inbound HTTPS through the proxy | Direct IMAP/SMTP access |
| `db` | Persist local owner configuration, message state, and minimal audit data | Internal application networks only | Public network exposure |
| `proxy` | Terminate HTTPS and route allowed inbound traffic | Inbound HTTPS | Mail credentials and classification logic |
| `hermes-adapter` (optional) | Map the same restricted read-only operations for Hermes | MailGate API and the owner's Hermes | IMAP, SMTP, database, quarantine, write operations |

The `web` and `worker` processes may use the same versioned image, but they must run separately with different credentials, network routes, and privileges.

## Planned data flow

1. The worker connects to a mailbox configured by the installation owner.
2. It records provider-authenticated transport signals and ignores untrusted look-alike headers.
3. It parses MIME with bounded size, depth, time, and supported formats.
4. It produces sanitized text without executing content or loading remote resources.
5. Technical checks and an optional classifier produce structured signals.
6. A deterministic policy validates those signals and selects an allowed state transition.
7. The database stores local state and only the content required by configured retention rules.
8. The web UI exposes owner controls; the Hermes API exposes only approved, sanitized summaries.

## Hermes contract

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

There will be no Hermes endpoint for sending, replying, deleting, moving, changing state, accessing quarantine, reading unprocessed messages, or downloading raw attachments. Unsupported HTTP methods and broader scopes must fail closed.

## Deployment boundaries

- One installation serves one owner and stores only that owner's data.
- The API defaults to a private Docker network. Remote Hermes deployments require an explicitly configured private transport such as WireGuard, Tailscale, or mTLS.
- Containers run as non-root with minimal capabilities and writable paths.
- Secrets are mounted from files or a suitable secrets mechanism, never committed or embedded in images.
- The classifier has neither mailbox credentials nor general-purpose tools.
- External model use is explicit, configurable, and limited to the necessary sanitized fields.
- Telemetry is off by default and no data is sent to a MailGate-operated service.

These statements are requirements to be tested before release, not claims about a current implementation.

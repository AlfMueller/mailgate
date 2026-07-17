# Threat Model

Status: initial Phase 0 baseline, 17 July 2026. This document must be revised as implementation choices are made.

## Security goal

MailGate allows an owner's Hermes assistant to read selected, sanitized message information without giving Hermes authority over the mailbox or exposing unapproved mail. It assumes every message and every model-produced classification may be malicious.

## Protected assets

- mailbox credentials and OAuth tokens;
- raw and sanitized message content;
- private forwarding addresses and owner identity data;
- classification-provider credentials;
- MailGate credentials issued to Hermes;
- rules, categories, review decisions, and audit records;
- encryption and backup keys;
- integrity of approval and quarantine state.

## Untrusted inputs

- all message headers, bodies, HTML, MIME structure, encodings, URLs, filenames, and attachments;
- Unicode controls, invisible content, homographs, oversized or deeply nested structures;
- forged authentication headers and contradictory routing information;
- prompt-injection text in any message field or attachment metadata;
- classifier responses, including malformed or adversarial structured output;
- Hermes API requests, bearer credentials, and network identity;
- configuration imports, restore data, and provider error responses.

## Trust boundaries

### Mail provider to worker

The worker accepts hostile message data. It trusts authentication results only when they come from explicitly configured receiving infrastructure. Parsing is bounded and does not execute attachments, scripts, forms, styles, links, or remote images.

### Worker to classifier

The classifier receives the minimum necessary sanitized data. It has no mailbox secrets, shell, file tools, Docker socket, or authority to change state. Its output is untrusted and rejected unless it matches a closed, versioned schema.

### Classifier to policy engine

The policy engine permits only predefined state transitions. The classifier recommends; deterministic code decides. Unknown categories, actions, fields, invalid JSON, low confidence, and provider failures lead to review or no processing—not deletion or forwarding.

### Database to web and API

Administrative owner sessions and Hermes credentials are separate. A Hermes credential is hashed at rest, shown once, revocable, expiring, rate-limited, and limited to approved sanitized data. It does not authorize raw content, quarantine, configuration, or any write.

### MailGate API to Hermes

There is no direct network path or shared credential from Hermes to IMAP, SMTP, or the database. Private networking and transport authentication protect the API. All access is audited without recording unnecessary message content or bearer tokens.

## Mandatory fail-closed behavior

| Condition | Required behavior |
| --- | --- |
| Mail provider unavailable | Retry later; do not delete or advance state |
| Authentication lookup fails | Mark for review; do not infer success |
| MIME limits exceeded | Preserve safe metadata and quarantine content |
| Sanitization fails | Do not classify or expose the message |
| Classifier unavailable | Leave message unprocessed |
| Classifier output invalid or unknown | Reject output and require review |
| Database operation fails | Stop processing and record a content-minimal error |
| Hermes scope, state, method, or rate check fails | Deny the request |

## Prohibited capabilities

The Hermes-facing surface must never provide:

- IMAP, SMTP, mailbox, database, Docker, shell, or filesystem credentials;
- send, reply, forward, delete, move, mark, approve, or quarantine actions;
- raw message source, unapproved content, quarantine content, or raw attachments;
- arbitrary queries, arbitrary URLs, remote-content loading, or model/tool execution;
- cross-owner or cross-installation data.

These are architectural constraints. Adding any such capability requires a new threat model and is outside the initial MailGate product.

## Privacy requirements

- No central registration or shared customer database.
- No telemetry by default.
- No real personal data in tests, examples, screenshots, logs, or issue reports.
- Configurable retention with deletion and export under owner control.
- Credentials encrypted at rest with the master key stored outside the database.
- Audit events prefer identifiers and hashes over message content.
- External model transmission is transparent, minimized, and optional where a local compatible model is configured.

## Verification gates before a first release

- Parser, sanitizer, schema, policy, authentication-header, authorization, and isolation tests pass.
- Adversarial prompt-injection cases cannot cause additional authority or state transitions.
- Every non-GET method on the Hermes interface is rejected where no explicit read-only route exists.
- A stolen, expired, revoked, or wrong-scope Hermes credential is denied.
- Containers run without root and unnecessary Linux capabilities, mounts, and network routes.
- Secrets and personal data scans cover repository history, build artifacts, fixtures, and logs.
- Backup, restore, update, and complete local deletion are tested.
- Known residual risks and unsupported configurations are published.

## Known residual risks

SPF, DKIM, DMARC, and ARC establish limited transport and domain properties; they do not prove that content is truthful or safe. Sanitization and prompt-injection detection can fail. Approved summaries can still contain misleading information. The primary control is therefore least privilege: even a successful content attack must not grant Hermes mailbox actions or access to unapproved data.

## Out of scope for the initial version

- guaranteeing detection of all spam, phishing, or prompt injection;
- autonomous replies or destructive mailbox actions;
- executing or deeply analyzing arbitrary attachments;
- a centrally operated MailGate service;
- protecting a host or mail provider already fully compromised by its administrator.

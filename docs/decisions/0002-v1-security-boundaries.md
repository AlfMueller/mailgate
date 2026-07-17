# ADR 0002: Version-one mail and agent boundaries

Status: Accepted for the release candidate

## Decision

- MailGate uses IMAPS only, selects `INBOX` read-only and fetches with `BODY.PEEK[]`.
- Quarantine is an internal MailGate state. It never creates, moves, flags, or deletes IMAP messages.
- SMTP and forwarding are outside version one. No container receives SMTP credentials.
- Provider `Authentication-Results` are accepted only when their leading `authserv-id` is explicitly configured for that mailbox. Missing provenance remains `unknown`, never `pass`.
- Raw message and attachment bytes are processed in memory and are not persisted. Only bounded safe text, normalized links, hashes, and attachment metadata are stored.
- Classification is deterministic in this release candidate. A future model adapter may recommend categories, but may never change message state.
- The agent API exposes only approved, sanitized fields and only supports GET. Tokens have one fixed scope, are shown once, stored as SHA-256 digests, expire by default, can be explicitly configured without automatic expiry, can be revoked, and are rate-limited.
- A four-week isolated-mailbox pilot and an installation by an independent tester remain release gates before a production v1 claim.

## Consequences

These choices deliberately exclude forwarding, mailbox cleanup, attachment download, raw source access, MCP, model tool calls, and automatic approval when authentication provenance is absent or processing fails.

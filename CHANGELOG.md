# Changelog

All notable changes are documented here. MailGate follows Semantic Versioning after V1.

## 1.0.0rc1 - Unreleased

First public V1 release candidate:

- self-hosted English/German owner UI with setup, status, mailbox lifecycle, quarantine review,
  security self-tests, and revocable read-only API tokens;
- certificate-verified read-only IMAPS ingestion with destination-enforced egress and no SMTP,
  mailbox mutation, attachment download, telemetry, or external model call;
- independent DKIM verification separated from provider SPF/DKIM/DMARC/ARC claims;
- bounded sanitization and fail-closed deterministic policy with owner-only approval;
- database-enforced approved-only API, separate processes and least-privilege PostgreSQL roles;
- encrypted mailbox credential keyring, automated rotation, retention, export, encrypted backup and
  isolated restore tooling;
- synthetic browser, accessibility, fuzz, protocol, database-boundary, security and release checks;
- digest-pinned Compose dependencies and an attestable SBOM-producing container release workflow.

The final `1.0.0` release remains gated on independent installation acceptance, credential rotation
before public deployment, and a documented 28-day isolated pilot.

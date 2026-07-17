# Release gates

MailGate is a release candidate, not a production release, until every item below is evidenced.

- [x] License and security boundary decisions recorded.
- [x] TLS-only read-only IMAP code uses read-only selection and `BODY.PEEK[]`.
- [x] Credentials are authenticated-encrypted under an independent file-backed master key.
- [x] A bounded MIME/HTML processing, internal quarantine, minimal owner review UI and constrained GET-only API vertical slice has synthetic tests.
- [x] The browser bootstrap requires an independent file-backed setup token and serializes owner creation.
- [x] Provider authentication claims never auto-approve mail, including a forged matching `authserv-id`.
- [x] Production Caddy denies the agent API on the public vhost and exposes it only through the host-loopback listener.
- [x] A separate API process and DB-enforced approved-only view isolate agent reads from owner-web privileges.
- [x] Destination-enforced worker egress policy is exercised by Linux Compose CI; production support is limited to Linux Docker Engine.
- [x] A persisted mailbox configuration version prevents a worker already in flight from writing
  stale sync status after credential rotation or disablement.
- [x] Independent DKIM verification and documented provider trust presets.
- [x] Key rotation, encrypted backup/restore, retention/export/delete and rollback drills are automated and tested.
- [ ] Browser E2E, PostgreSQL integration, fuzzing, SAST, secret/history scan, container CVE scan and SBOM/provenance/signing gates are green.
- [ ] German UI and accessibility review are complete.
- [ ] A person unfamiliar with the project completes installation in 15 minutes.
- [ ] The isolated public pilot mailbox runs for at least four weeks with documented false-positive/negative review.

No maintainer should label or publish v1.0.0 until all unchecked items are complete.

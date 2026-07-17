# V1 release-candidate evidence

This record contains no mailbox address, credential, token, message content, or secret value.
Evidence was collected on 17 July 2026 from branch `codex/production-ready-v1`.

## Local technical evidence

- Locked dependency installation succeeded.
- Ruff lint and format checks passed for `app`, `worker`, `scripts`, and `tests`.
- Django ran 128 tests successfully with three expected Windows platform/opt-in skips; Linux CI
  exercised the directory-link protection and the dedicated browser journey separately.
- Django system checks, translation compilation, migration drift checks, and Python bytecode
  compilation passed.
- A disposable browser journey passed against a fresh Compose project: owner setup, English/German
  locale, mailbox creation, synthetic TLS IMAP ingestion, quarantine/approval, token API/revocation,
  credential rotation, mailbox deletion, and Axe checks. It recorded no trace, screenshot, video,
  HAR, credential, or mail content.
- The main Compose stack built and became healthy. The read-only doctor reported zero failures and
  one expected Windows ACL warning; Windows ACL ownership remains an operator check.
- The synthetic integration environment rejected IMAP mutation commands and direct worker egress.
- An authenticated encrypted backup was restored into an isolated project. Record counts matched,
  mailbox credentials decrypted, migrations were current, and PostgreSQL privilege tests returned
  `POSTGRES_BOUNDARIES_OK`.
- The credential keyring primary was changed, every stored credential was re-encrypted and verified,
  and a second encrypted post-rotation backup was restored successfully. The previous key is retained
  only for the documented rollback window.
- Retention dry-run and a secret-field-negative owner export drill passed. The temporary plaintext
  export and recovered key copies were removed after verification.
- Full Git history secret scanning passed. The final MailGate/Caddy artifact passed OS, Python,
  Go-binary and secret scanning with zero fixable High/Critical findings; pinned PostgreSQL and
  HAProxy images passed the infrastructure OS-package policy in `security-scan-policy.md`.
- All workflow files passed actionlint 1.7.12.

## GitHub evidence

Pull request 2 is green for Python 3.13/3.14, Compose/PostgreSQL boundaries, browser E2E, CodeQL,
dependency review, full-history secret scanning, and the container/SBOM job. `main` is protected by
those exact required checks. The `release` environment requires explicit maintainer approval and
accepts only `v*` refs. Release tags re-run the full CI/security workflows for the exact tag commit,
require that commit to belong to `main`, build once, scan the exact candidate digest, publish SPDX
and CycloneDX SBOMs, add GitHub build provenance, and then promote that same digest.

## Public V1 work and external acceptance still required

- Implement and benchmark the shadow mode, pinned scanner interface, versioned deterministic
  auto-approval policy, kill switch, decision provenance and owner correction workflow described in
  `docs/automation-plan.md`.
- Provide and test the reference Hermes/MCP action-guardrail policy without adding write authority
  to MailGate.
- Rotate every credential that has appeared outside the local secret store before public deployment.
- A person unfamiliar with MailGate must complete `docs/installation-acceptance.md` in 15 minutes.
- The isolated pilot must complete 28 consecutive days using `docs/pilot-runbook.md`, demonstrate at
  least 70% correct automatic approval of eligible messages, and document false positives, false
  negatives, incidents, backup checks, and upgrades.

Do not publish `v1.0.0` until the automation implementation and its automated checks are green and
the external evidence is attached to the release decision.

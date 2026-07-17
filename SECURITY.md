# Security Policy

MailGate is security-sensitive software and is currently a technical release candidate. There are no supported production releases yet.

## Supported versions

| Version | Supported |
| --- | --- |
| `1.0.0rc1` | Security fixes during release-candidate evaluation |
| `< 1.0.0rc1` | No |

Until the final V1 gates pass, use only a dedicated isolated pilot mailbox with unique rotated
credentials and an independently verified encrypted backup. Do not expose the owner UI publicly
without the production HTTPS override.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through this repository's **Security** tab using **Report a vulnerability** (GitHub private vulnerability reporting).

Do not create a public issue, pull request, discussion, or social-media post before the report has been assessed. Never include real email messages, mailbox credentials, API keys, tokens, private email addresses, recovery codes, or other personal data. Use synthetic examples and redact secrets.

A useful report includes:

- the affected document, component, version, or commit;
- the security boundary that may be bypassed;
- reproducible steps using synthetic data;
- observed and expected behavior;
- likely impact and any known preconditions;
- a minimal proof of concept, if it can be shared safely.

The project will acknowledge a valid private report, coordinate remediation and disclosure, and credit the reporter if requested. Response-time commitments will be added once maintainers and release support processes are established.

## High-priority boundaries

Reports are especially important when they show a path to:

- mailbox credentials or classification-provider secrets;
- raw, quarantined, or unapproved message content through the AI-agent interface;
- any send, reply, move, delete, attachment-download, database, or mailbox operation from the AI agent;
- bypassing owner isolation;
- executing content from messages or attachments;
- accepting forged authentication results as trusted;
- causing classifier output to directly perform an action;
- leaking sensitive content through logs, telemetry, diagnostics, or error reports.

The full baseline is documented in [docs/threat-model.md](docs/threat-model.md); container scan scope
and the narrow upstream-image reachability decision are recorded in
[docs/security-scan-policy.md](docs/security-scan-policy.md).

# Contributing to MailGate

MailGate is currently in Phase 0: requirements, security boundaries, architecture, and governance decisions.

## Current contribution policy

Code contributions are not accepted until the project license and contribution terms are selected. This avoids ambiguity about the rights granted by contributors and to users.

Design feedback, documentation corrections, and threat-model review are welcome through GitHub issues, provided they contain no secrets, personal data, private email addresses, or real message content. Security findings must be reported privately as described in [SECURITY.md](SECURITY.md).

Before proposing a change:

1. Read [docs/projektplan.md](docs/projektplan.md) and [docs/threat-model.md](docs/threat-model.md).
2. Check that the proposal preserves the strict read-only boundary toward Hermes.
3. Use only synthetic and clearly fictional examples.
4. Explain any new data flow, external connection, privilege, secret, or retained data.

The contribution process will be expanded after the license decision is recorded.

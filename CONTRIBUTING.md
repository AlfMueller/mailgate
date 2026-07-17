# Contributing to MailGate

MailGate is currently in Phase 0: requirements, security boundaries, architecture, and governance decisions.

## Contribution policy

MailGate is licensed under the GNU Affero General Public License v3.0. By submitting a contribution, you confirm that you have the right to provide it and agree that it will be distributed under the project's AGPL-3.0 license.

Design feedback, documentation corrections, tests, focused code changes, and threat-model review are welcome through GitHub issues and pull requests, provided they contain no secrets, personal data, private email addresses, or real message content. Security findings must be reported privately as described in [SECURITY.md](SECURITY.md).

Before proposing a change:

1. Read [docs/projektplan.md](docs/projektplan.md) and [docs/threat-model.md](docs/threat-model.md).
2. Check that the proposal preserves the strict read-only boundary toward Hermes.
3. Use only synthetic and clearly fictional examples.
4. Explain any new data flow, external connection, privilege, secret, or retained data.
5. Add or update tests for behavior changes.
6. Keep commits focused and ensure the available checks pass.

Source files should use the SPDX identifier `AGPL-3.0-only` where a per-file identifier is appropriate. Dependency additions must be license-compatible and justified.

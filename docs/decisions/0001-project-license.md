# ADR 0001: Select the Project License

- Status: **Accepted**
- Date opened: 17 July 2026
- Date decided: 17 July 2026
- Decision owners: project maintainers

## Context

MailGate is intended to become a public open-source project. Its license must be explicit before application code or external code contributions are accepted. The project may be self-hosted by individuals and organizations, and modified versions could also be offered as a hosted service.

Publishing a repository without a license does not make its contents open source. Until this decision is accepted and a `LICENSE` file is committed, no permission is granted to use, modify, or redistribute the repository contents beyond rights supplied directly by GitHub's terms.

## Options under consideration

### Apache License 2.0

- Permissive use, modification, and redistribution, including commercial products.
- Includes an explicit patent grant and notice requirements.
- Makes adoption and integration straightforward.
- Does not require hosted or distributed modifications to remain open source.

### GNU Affero General Public License v3.0

- Strong copyleft for distributed versions.
- Requires operators who modify the software and provide it over a network to offer the corresponding source to those users.
- Better preserves access to improvements in hosted variants.
- May reduce adoption by organizations that avoid strong copyleft dependencies.

## Decision criteria

- whether improvements to hosted MailGate services should remain available to their users;
- compatibility with planned Python and container dependencies;
- willingness to accept proprietary integrations or commercial redistribution;
- contributor expectations and project sustainability;
- clarity for Docker images, optional adapters, documentation, and example configuration;
- legal review appropriate to the maintainer's risk tolerance.

## Decision

MailGate is licensed under the **GNU Affero General Public License v3.0 only** (`AGPL-3.0-only`). The network-use provision is intentional: users of a modified MailGate service must be able to obtain the corresponding source code.

## Consequences

- The complete canonical license text is stored in `LICENSE`.
- Application source files should identify the license as `AGPL-3.0-only` where appropriate.
- Contributions are accepted under the same license; contribution guidance must say so explicitly.
- Every dependency must be checked for compatibility with AGPL-3.0-only.
- Modified versions offered over a network must provide their corresponding source as required by section 13.
- Documentation and distribution metadata must not imply a permissive license.

The license decision completes the final governance prerequisite for beginning application implementation.

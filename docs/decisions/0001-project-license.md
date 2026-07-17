# ADR 0001: Select the Project License

- Status: **Proposed — decision required before application code**
- Date opened: 17 July 2026
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

## Current consequence

- No `LICENSE` file is present.
- README and contribution guidance must clearly state that the license is undecided.
- Code contributions are paused to avoid ambiguous inbound rights.
- Planning documents may be viewed and discussed, but are not offered under an open-source license yet.

## Required follow-up

1. Choose and record one license (or a precisely reviewed multi-license model).
2. Verify dependency-license compatibility before adding dependencies.
3. Add the complete canonical license text as `LICENSE`.
4. Add copyright and SPDX guidance.
5. Define contribution terms and update `CONTRIBUTING.md` and README.
6. Only then begin application implementation and accept code contributions.

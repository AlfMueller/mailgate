# Container security scan policy

Every MailGate release artifact is scanned without project-specific vulnerability exceptions for:

- fixable High and Critical operating-system vulnerabilities;
- Python dependency vulnerabilities;
- embedded Go-binary vulnerabilities, including the Caddy reverse proxy;
- embedded secrets.

MailGate rebuilds the exact Caddy 2.11.4 source with the security-fixed Go 1.26.5 toolchain inside a
digest-pinned builder. This removed findings in the older official Caddy image while keeping one
attested MailGate release digest for web, API, worker, resolver, migration and proxy processes.

Digest-pinned official PostgreSQL and HAProxy images are scanned for fixable High/Critical OS-package
vulnerabilities. Trivy's Go-binary scanner additionally reports standard-library CVEs against
PostgreSQL's `gosu` entrypoint helper. In this deployment `gosu` receives only the fixed local UID/GID
and server command, changes identity once, and exits before PostgreSQL starts. It does not process
mail, HTTP, TLS sessions, URLs, MIME, DNS, filesystem roots, or other attacker-controlled input. The
reported vulnerable packages are therefore outside its executed path. The upstream image also ships
a default snake-oil TLS test key; MailGate does not enable PostgreSQL TLS or publish its database port.

Rather than globally suppressing CVE identifiers or private-key detection, CI limits upstream
infrastructure scans to OS packages and documents this narrow reachability decision here. The digest
remains pinned and Dependabot monitors rebuilds. Any future use of `gosu` with untrusted arguments,
PostgreSQL TLS, or externally published database access invalidates this decision and must restore a
full binary/secret scan or replace the image.

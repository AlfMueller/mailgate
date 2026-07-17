# GitHub Workflows

- `ci.yml` compiles sources, runs tests and Django checks, then starts the full Linux Compose stack
  and proves API/owner process separation, least-privilege PostgreSQL grants, concurrent stale-write
  protection, synthetic allowed/denied IMAPS egress and production health-check startup.
- `dependency-review.yml` rejects pull requests that introduce dependencies with known high-severity vulnerabilities or denied licenses.

Workflows receive no production mailbox credentials or unrestricted pull-request secrets.

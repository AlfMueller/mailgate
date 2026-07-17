# GitHub Workflows

- `ci.yml` compiles sources, runs tests and Django checks, then starts the full Linux Compose stack
  and proves API/owner process separation, least-privilege PostgreSQL grants, concurrent stale-write
  protection, synthetic allowed/denied IMAPS egress and production health-check startup.
- `dependency-review.yml` rejects pull requests that introduce dependencies with known high-severity vulnerabilities or denied licenses.
- `security.yml` runs CodeQL, full-history secret scanning, exact container vulnerability scans,
  non-root boundary checks, and SPDX/CycloneDX SBOM generation.
- `release.yml` re-runs CI and security gates for the tag commit, requires that commit to belong to
  `main`, publishes only a scanned digest, attests it, and creates a digest-pinned release bundle.

Workflows receive no production mailbox credentials or unrestricted pull-request secrets.

# GitHub Workflows

- `ci.yml` compiles sources, runs tests and Django checks, validates Compose, and builds the image.
- `dependency-review.yml` rejects pull requests that introduce dependencies with known high-severity vulnerabilities or denied licenses.

Workflows receive no production mailbox credentials or unrestricted pull-request secrets.

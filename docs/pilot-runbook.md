# Isolated four-week pilot runbook

The public V1 tag remains blocked until this gate records 28 complete consecutive days on one fixed
release candidate. Any security-relevant code or configuration change restarts the affected
observation window. Pilot data stays under ignored `.local/pilot/`; only aggregated, content-free
results may enter GitHub.

## Entry criteria

- all automated CI, security, browser, fuzz, backup/restore, key-rotation and rollback gates green;
- successful independent 15-minute installation acceptance;
- dedicated isolated mailbox with rotated credentials and no private primary-mailbox content;
- production Linux Docker Engine deployment using a digest-pinned, attested release candidate;
- tested encrypted off-host backup and documented recovery owner.

## Daily evidence

Record the release digest and UTC observation window, then only aggregate:

- received, ingested, duplicate, quarantined, approved, and rejected counts;
- ingestion latency p50/p95/max; worker gaps, restarts, failures, and recovery time;
- owner gold labels versus risk, category, and prompt-injection signal;
- review-time p50/p95 and maximum review backlog;
- private API successful reads and 401/404/429 counts;
- restore/backup job status and age of last verified backup.

Hard invariants for every day:

- unapproved or quarantined API exposures: **0**;
- remote mailbox mutations: **0**;
- stored or returned attachment bytes: **0**;
- secrets, addresses, message content, or other personal data in logs/report: **0**.

Every incident receives a content-free identifier, start/end time, impact, detection, recovery, and
decision whether the 28-day clock restarts. Prompt-injection detection is not treated as perfect;
the pilot evaluates whether least privilege still prevents additional authority.

## Exit review

At day 28, calculate a confusion matrix for the predeclared synthetic/gold labels plus precision,
recall, and uncertainty appropriate to the sample size. Explain every false negative, every service
gap, and every manual exception. A maintainer and one independent reviewer sign the aggregate report.
The report cannot waive a hard-invariant violation.

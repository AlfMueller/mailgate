# ADR 0003: Automated approval and agent action guardrails

Status: Proposed for public V1; not implemented by `1.0.0rc1`

## Context

Manual approval of every message preserves a strong security boundary but does not deliver enough
value over reading the mailbox directly. Public V1 must automate routine mail while preserving the
core rule that email content is untrusted data and can never grant an agent additional authority.

Prompt-injection classifiers are probabilistic. Sender allowlists, DKIM signatures, provider
headers, and model confidence are useful signals, but none proves that message content is safe.
Automation therefore needs several independent signals plus deterministic, fail-closed policy.

## Decision

- Public V1 targets automatic approval of 70–80% of eligible pilot messages after a bounded warm-up.
- `eligible` excludes parsing failures, deliberately adversarial test traffic, oversized/truncated
  content, and messages for which MailGate cannot produce its bounded sanitized representation.
- Automatic approval is performed only by a versioned deterministic policy. A model or external
  service may produce signals but may never write message state directly.
- Automatic rejection, deletion, forwarding, replying, mailbox mutation, and attachment release
  remain forbidden. Uncertain or failed evaluation always enters owner review.
- An auto-approval candidate needs independently verified aligned DKIM, successful bounded parsing,
  no hard-risk signal, no dangerous attachment type, and agreement from the configured scanner
  policy. Provider `Authentication-Results` alone can never satisfy this requirement.
- Attachments remain withheld from the agent. A safe message body may be approved while its
  attachment is listed as unavailable; attachment bytes are never treated as agent instructions.
- Fresh installations start in shadow mode. MailGate records recommendations without applying them.
  The owner explicitly enables balanced automation after reviewing the warm-up report.
- Every decision stores policy version, scanner versions, reason codes, decision source, timestamps,
  and the input configuration version. It stores no raw message or scanner prompt in audit logs.
- Local scanning is the default. Any cloud scanner is explicit opt-in, documents exactly which
  sanitized text leaves the installation, and is never the sole approval signal.
- MailGate's API remains GET-only. A separate optional Hermes/MCP guardrail package constrains tools
  outside MailGate when an agent combines MailGate data with send, browser, filesystem, or other
  mutating capabilities.

## Safety invariants

- Known adversarial regression cases automatically approved: **0**.
- Unapproved API exposures, remote mailbox mutations, and returned attachment bytes: **0**.
- Scanner failure, disagreement, timeout, missing required signal, or policy error: owner review.
- No sender/domain rule can bypass a hard-risk signal.
- No LLM output can directly approve, reject, send, delete, move, download, or execute anything.
- Automation has a one-click global kill switch and can be rolled back without changing message
  content or mailbox credentials.

## Consequences

The manual-only release candidate is not yet the public V1 product. The automation work, its
benchmarks, and the measured pilot target become explicit release gates. This ADR supersedes only
ADR 0002's statement that future model adapters may never change message state: models still cannot
change state, but deterministic policy may automatically approve using their bounded signals. All
other mail, API, credential, network, and attachment boundaries in ADR 0002 remain in force.

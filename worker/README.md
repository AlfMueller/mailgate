# Mail Worker

The first worker foundation verifies database readiness and provides a signal-aware process shell for later Phase 1 ingestion work.

It deliberately does **not** connect to IMAP, classify messages, or mutate mailbox state yet. No mailbox or model-provider credentials are present in the Compose deployment.

The worker must not expose mailbox credentials to classifiers or Hermes and must fail closed when processing is incomplete or invalid.

The worker is the only application process attached to the `worker_egress` network. The web process remains isolated from external mail services.

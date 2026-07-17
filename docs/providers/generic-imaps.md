# Generic IMAPS preset

The `generic_imaps` preset uses exactly the one public DNS hostname configured by the operator in
`MAILGATE_IMAP_ALLOWED_HOST` and fixes the port to 993. A mailbox form cannot add another destination
or an IP address. End-to-end certificate and hostname verification remains active through the
internal SNI-enforcing relay.

Trusted authentication-service IDs are optional and advanced. An ID is the first token in a
receiving system's `Authentication-Results` header, not necessarily its IMAP hostname. Configure one
only when the provider documents how injected headers are removed or distinguished. Even a matching
header remains a provider claim and cannot automatically approve a message.

Independent DKIM verification uses bounded TXT lookups and unchanged raw message bytes. DNS failure
is reported as unknown/temporary and fails closed into owner review. No SMTP setting belongs to this
preset or the V1 runtime.

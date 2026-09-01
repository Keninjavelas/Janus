# Threat Model

## Scope

Janus is a research control plane for cryptographic discovery, policy derivation, verification, workload attribution, audit integrity, and migration planning.

It is not assumed to be a production-hardened enforcement or identity platform.

## Assets

- policy bundles and their canonical identity
- posture decisions and policy provenance
- wire-observed TLS evidence
- workload attribution metadata
- CBOM and discovery inventory
- risk assessments and migration plans
- tamper-evident audit records

## Trust Boundaries

- request inputs -> policy engine
- policy bundle -> human activation
- TLS endpoint reports -> independent verifier
- wire evidence -> attribution resolver
- workload identity -> audit and migration records
- AI draft generation -> validation and human review

## Primary Threats

- classical downgrade hidden behind policy intent
- missing or malformed wire evidence being mistaken for compliant evidence
- TCP ambiguity causing false cryptographic conclusions
- PID reuse or vanished processes causing stale ownership claims
- unknown algorithms being silently treated as approved
- tampered policy or audit records being accepted as authentic
- migration intent being mistaken for migration success
- LLM-generated policy bypassing validation or human review

## Security Invariants

- no cryptographic evidence -> `UNVERIFIED`
- weaker observed posture than required -> `NON_COMPLIANT`
- ambiguous or damaged packet evidence -> `UNVERIFIED`
- unknown owner -> `UNATTRIBUTED`
- multiple plausible owners -> `AMBIGUOUS`
- migration target != verified observed posture -> not verified
- unknown algorithm -> never implicitly approved

## Residual Risks

- direct TLS discovery is narrower than broad autonomous environment discovery
- local procfs attribution is Linux-specific and not a universal workload identity mechanism
- research signature metadata on policy bundles is lighter than a production signing system
- endpoint-to-wire disagreement handling remains limited
- dashboard/API surfaces are useful for research and demonstration, not hardened multi-tenant operations

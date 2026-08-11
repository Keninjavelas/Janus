# Security Tests

This directory is reserved for adversarial and failure-oriented validation of Janus.

The intent is to evaluate the system against explicit security-relevant scenarios rather than only happy-path functionality.

## Planned scenarios

- `downgrade/`
- `stale-cache/`
- `tampered-policy/`
- `expired-policy/`
- `unknown-algorithm/`
- `unsupported-peer/`
- `ai-malformed-output/`
- `identity-revocation/`
- `janus-unavailable/`
- `policy-conflict/`

## Design rule

Two requests whose security-relevant context differs must never incorrectly share a cached decision.

That invariant should be preserved in both ordinary tests and adversarial tests.

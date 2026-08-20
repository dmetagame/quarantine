# Security Audit Note

Audit scope: the browser demo boundary, demo orchestrator, HydraDB client,
trusted provenance writer, trusted-state verifier, policy evaluator, and action
gateway.

## Verified Path

```text
browser scenario key
  -> strict HTTP validation
  -> server-owned demo orchestration
  -> HydraDB-backed provenance writer/verifier
  -> branded trusted state
  -> deterministic policy and freshness checks
  -> process-local replay ledger
  -> opaque gateway-issued action
  -> dry-run adapter
```

The browser cannot submit trusted state, provenance witnesses, policy results,
freshness, depth limits, artifact identifiers, or an adapter. The action
gateway rejects those fields before verification. The adapter has no public
execution method and can only be reached through a gateway-issued capability.

## Findings

- No direct path from untrusted request data to the action adapter was found.
- Forged parent claims are rejected by the provenance writer before graph
  mutation; mixed valid and forged parent sets remain atomic.
- Missing, malformed, unresolved, stale, replayed, or system-error states fail
  closed. Unexpected demo orchestration errors return `BLOCK_SYSTEM_ERROR`.
- HydraDB response hydration and verifier failures are handled before an action
  can be authorized. Provenance and adapter execution deadlines fail closed;
  an adapter timeout is indeterminate and is not retried.
- The demo HTTP boundary accepts only a single whitelisted scenario field and
  requires the exact `application/json` media type.

## Residual Limits

- Replay protection is process-local and must be made durable before real
  side effects.
- The trusted writer's serialization boundary is single-process; independent
  multi-process races are outside the current proof.
- Connector attestation uses local proof keys and does not provide expiry,
  revocation, or organization-wide key management.
- The demo adapter is deliberately dry-run only. No external action is
  authorized by this repository.
- Adapter timeout does not imply cancellation of an underlying executor; a
  real side-effect adapter needs its own cancellation/idempotency contract.

The live HydraDB and demo proof commands are required to refresh hash-bound
evidence after implementation changes. This audit does not rewrite evidence
by hand when Docker is unavailable.

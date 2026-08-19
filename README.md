# QUARANTINE

QUARANTINE is an action safety layer for AI systems. Before an AI-proposed
action can execute, Quarantine uses HydraDB to prove that the supporting
context has trustworthy, resolvable provenance. The model may interpret or
propose content, but it cannot declare its own ancestry, trust, verification
state, or authority; deterministic verification and the action gateway decide
whether the system may act.

This repository contains three security gates and one end-to-end demonstration:

1. The original HydraDB viability proof for indexed reverse lineage traversal.
2. The trusted provenance writer, including the forged `parent_ids` regression.
3. The trusted-state contract and fail-closed action gateway.
4. A live valid-versus-tampered demo that exercises the same trusted core.

The action gateway is deliberately a dry-run authorization boundary. It does
not perform external side effects. A dependency-free server and browser demo
expose the same trusted path without moving any security decision into the
client.

## The Thesis

Quarantine verifies whether an action is justified by trustworthy provenance
before allowing the action. It uses HydraDB to reconstruct the relevant
multi-hop lineage, issues trusted state only after that graph is authenticated,
and fails closed when required ancestry cannot be established. The point is
not to make an AI answer sound confident; it is to make the action boundary
refuse unsupported context.

### The Problem

LLMs can produce plausible but unsupported conclusions. Vector similarity can
find related text, but it cannot prove which source supports an action or
whether every transformation in between is authentic. A relational table can
store relationship rows, but the application still has to reconstruct and
validate the connected, multi-hop closure itself. An agent should not turn
uncertain context into an irreversible action.

### The Solution

```text
Evidence
   -> HydraDB provenance graph
   -> signed verification
   -> internal trusted state
   -> deterministic policy
   -> fail-closed action gateway
   -> dry-run action
```

The producer controls content only. The writer controls lineage, the verifier
controls trusted state, the policy evaluator controls the decision, and the
gateway is the only path to the adapter.

## Architecture

```text
Browser
  |  { scenario: "valid" | "tampered" }
  v
demo-server.mjs
  v
demo-orchestrator.mjs
  +--> hydradb-client.mjs --> HydraDB 0.1.1
  +--> provenance-writer.mjs --> signed graph verification
  +--> action-gateway.mjs
          +--> trusted state
          +--> deterministic policy
          +--> replay + freshness checks
          +--> opaque dry-run adapter
```

The browser renders server results; it cannot submit trusted state, witnesses,
policy results, freshness, depth limits, or an adapter. The orchestrator is a
thin composition layer. Authorization remains in the trusted core and is
performed again by the gateway after the display-only graph read.

### Why HydraDB?

HydraDB is central because this demo uses its indexed property selectors,
incoming reverse traversal over child-to-parent `DERIVES_FROM` edges, and
multi-hop witness reconstruction. The graph exposes multiple source-to-action
paths and an explicit unresolved frontier when a bounded traversal cannot
reach a trusted terminal source. Removing HydraDB would remove the demonstrated
graph-backed reconstruction primitive; a similarity score or an unverified
relationship lookup would not provide the same evidence of connected ancestry.

## Judge Quickstart

Requirements: Node.js `>=22`, Docker with permission to run the pinned
HydraDB image, `curl`, and a browser. The project has no runtime npm
dependencies, so `npm install` is only a reproducibility check.

```bash
npm install
./scripts/start-hydradb.sh
npm run check
npm run test:unit
npm run proof:hydradb
npm run test:provenance
npm run test:gateway
npm run test:demo
npm run validate:evidence
npm run demo
```

Open <http://127.0.0.1:4173>, run `VALID`, then run `TAMPERED`. The valid
flow ends with one dry-run adapter call. The tampered flow shows
`BLOCK_UNRESOLVED_ANCESTRY` and zero adapter calls. The full spoken narrative
is in [`docs/demo-script.md`](docs/demo-script.md).

The proof commands require HydraDB to be running. `npm run validate:evidence`
checks the existing dated/latest artifacts and should be run after the proof
commands on a fresh checkout. The rolling `latest-*` files are intentionally
ignored because they are generated outputs.

The release checklist is in
[`docs/submission-checklist.md`](docs/submission-checklist.md).

## Trust Boundary

The producer/model controls one field:

```text
{ content }
```

Trusted middleware observes the actual transformation inputs and calls:

```text
prepareTransformation({ artifactId, role, observedParentIds, kind })
```

The writer resolves every parent from HydraDB, verifies the parent's complete
signed ancestry, computes the next generation, and returns an HMAC-bound
context. Only that context can be committed with `writeDerivedArtifact`.

All source, context, parent-array, and producer inputs are copied and frozen at
the synchronous API boundary before any verifier, lock, or database await. A
caller cannot mutate an object after validation to retarget the signed write.

Producer fields such as `parent_ids`, `trusted`, `verified`, `source`,
`confidence`, `provenance`, `ancestry`, and `authority` are rejected before any
HydraDB access.

Terminal trusted sources require a connector attestation binding:

```text
artifact id + content hash + issuer + key id
```

The proof uses a local HMAC connector key. It is evidence-only; production keys
must remain in connector middleware or a secret manager and outside model
access.

## Write Protocol

HydraDB's public HTTP query surface does not expose one transaction spanning a
child vertex and its relationship batch. The writer therefore uses an explicit
state machine:

```text
verify every parent closure
  -> stage signed child as pending
  -> write all DERIVES_FROM edges in one UNWIND batch
  -> hydrate and authenticate the exact edge set
  -> conditionally mark the same batch committed
  -> hydrate and verify the complete committed closure
```

Pending children are never authentic parents. An interrupted write blocks, and
retrying the same signed batch resumes idempotently. Committed artifact IDs are
immutable through this writer under the current single-writer process boundary.

Every node signature covers its artifact identity, content hash, generation,
parent count and digest, context, batch, authority proof, writer identity, and
auth state. Every edge signature covers both endpoints, generations, edge kind,
batch, and writer identity.

HydraDB 0.1.1 read queries project explicit properties because its OpenCypher
surface does not return whole node or relationship bindings. Relationships also
store a regular signed `edge_id` property: the reserved `r.id` expression is not
available through scalar projection, while `edge_id` remains hydratable for
integrity verification.

## Graph Model

The lineage direction is always child to parent:

```text
ActionArgument -[:DERIVES_FROM {kind}]-> DerivedArtifact -> SourceArtifact
```

The proof deliberately starts from terminal sources and traverses incoming
`DERIVES_FROM` edges to multiple action arguments. That exercises HydraDB's
reverse adjacency through one batched `algo.MSpaths` call without duplicating
reverse edges.

## Run

```bash
./scripts/start-hydradb.sh
npm run check
npm run test:unit
npm run proof:hydradb
npm run test:provenance
npm run test:gateway
npm run test:demo
npm run validate:evidence
```

The rolling `latest-*` evidence files are intentionally ignored. On a clean
checkout, run the live proof commands before `npm run validate:evidence`; the
validator binds the reports to the current implementation hashes.

The launcher pins `ghcr.io/hydra-db/hydradb:0.1.1`. Override it only
deliberately with `HYDRA_IMAGE`; an already-running container on a different
image is rejected instead of silently reused.

Defaults:

- HTTP: `http://127.0.0.1:18443`
- Admin: `http://127.0.0.1:19091`
- Bolt: `127.0.0.1:17687`
- Container: `quarantine-hydradb`

Stop and remove the disposable container before a clean restart with:

```bash
docker stop quarantine-hydradb
docker rm quarantine-hydradb
```

## End-to-End Demo

With HydraDB running, start the server:

```bash
npm run demo
```

Open <http://127.0.0.1:4173>. The single screen is split into incoming
evidence, the actual HydraDB provenance closure, and the security decision.
The browser submits only `{ "scenario": "valid" }` or
`{ "scenario": "tampered" }`; it cannot submit artifact IDs, witnesses,
trusted-state fields, policy results, depth limits, or an adapter.

The verified flow writes a small two-branch graph through the provenance
writer, reads its signed nodes and `DERIVES_FROM` edges back from HydraDB, and
then lets one persistent action gateway authorize a dry-run action. The attack
flow runs a real forged `parent_ids` producer probe and a separate three-hop
signed chain through the same gateway configuration. The complete graph is
observed at depth 16, while authorization is always capped at depth 2; the
required terminal source is therefore beyond the attack bound, producing
`BLOCK_UNRESOLVED_ANCESTRY / DEPTH_CAP_REACHED` with zero adapter calls.

The UI labels the displayed source-to-action direction explicitly: HydraDB
stores lineage as child-to-parent `DERIVES_FROM` edges. Graph metrics and
witnesses are returned by the server's trusted reads; no frontend graph or
authorization fixture exists.

The deterministic end-to-end proof is recorded in
[`evidence/2026-08-18-end-to-end-demo-proof.json`](evidence/2026-08-18-end-to-end-demo-proof.json)
and its rolling copy `evidence/latest-end-to-end-demo-proof.json`.

## HydraDB Viability Proof

1. Vertex and relationship fixtures load through batched `UNWIND` requests,
   including an exact-count 512-vertex and 511-relationship probe.
2. `algo.MSpaths` resolves many sources and targets by indexed label/property
   selectors in one request.
3. `relDirection: 'incoming'` follows reverse adjacency over child-to-parent
   `DERIVES_FROM` edges.
4. Returned witness paths preserve the `kind` edge property needed for display
   and policy checks.
5. A terminal source inside the depth cap is accepted as resolved.
6. A non-source frontier at the cap is classified as unresolved and therefore
   must block.

HydraDB maintains property indexes as part of its canonical write records.
There is no HydraDB `CREATE INDEX` step in this proof. The Neo4j-style `CREATE
INDEX` statement present in HydraDB's external benchmark is not part of the
documented HydraDB Cypher surface.

The original proof remains a database viability proof. Its fixture and evidence
are intentionally separate from the provenance-writer gate.

## Provenance Writer Proof

The live regression suite uses fresh run-scoped IDs for mutable fixtures (the
requested `child-001` / `forged-parent-001` attack literals are deliberately
fixed) and verifies HydraDB state, not only API return values. It covers:

- forged producer-controlled `parent_ids`;
- source and signed-context mutation races that attempt to retarget a write
  after asynchronous verification or validation has started;
- missing and existing-but-unauthenticated parents;
- mixed valid and forged parent sets with no partial ancestry;
- revalidation of a previously valid two-parent context after one parent is
  tampered, with no partial child or edge write;
- a legitimate connector-attested parent and hydrated `DERIVES_FROM.kind`;
- reverse `algo.MSpaths` recovery of the legitimate ancestry;
- duplicate-parent normalization, self-parent rejection, and immutable-ID cycle
  prevention;
- deterministic replay without duplicate graph state;
- client-controlled trust escalation;
- invalid connector attestations;
- an interrupted pending write, rejection of that pending child as a parent,
  and idempotent recovery; and
- rejection of a signed parent node whose lineage edge was mutated directly.

The key attack assertion is:

```text
valid middleware context for child-001 + legitimate observed parent
  + producer parent_ids = ["forged-parent-001"]
  -> BLOCK_INVALID_PROVENANCE
  -> no forged parent vertex
  -> no child vertex
  -> no forged or legitimate DERIVES_FROM edge
  -> no reverse ancestry witness
```

## Recorded Result

The HydraDB viability proof passed against
`ghcr.io/hydra-db/hydradb:0.1.1` on August 17, 2026.
See [`evidence/2026-08-17-hydradb-proof.json`](evidence/2026-08-17-hydradb-proof.json).

The recorded run loaded the 13-vertex lineage fixture, then separately verified
a 512-vertex and 511-relationship single-request `UNWIND` probe. It returned
four batched incoming witnesses at one read epoch, preserved `assert`,
`summarize`, `support`, and `require` edge kinds, and failed closed on a
generation-1 frontier after three hops.

Each successful run writes the same report printed to stdout to
`evidence/latest-proof.json`. The dated evidence file is generated by the same
runner with `QUARANTINE_PROOF_OUTPUT=evidence/2026-08-17-hydradb-proof.json`, so
both artifacts use one schema and one reproducible execution path.

The provenance writer runner writes one report to both
`evidence/2026-08-17-provenance-writer-proof.json` and the ignored rolling file
`evidence/latest-provenance-writer-proof.json`. The report records the run ID,
input classification, expected and actual result, reason code, graph
assertions, HydraDB configuration, and overall status. Validation requires the
two reports to be identical, recomputes the case summary, rejects duplicate or
missing required cases, and binds the evidence to SHA-256 hashes of the writer,
HydraDB client, proof runner, and validator sources.

## Trusted State and Action Gateway

The gateway is the boundary between verified graph state and an action
adapter:

```text
raw ActionIntent
  -> strict validation and snapshot
  -> signed provenance closure verification
  -> internal TrustedState issuance
  -> deterministic policy evaluation
  -> trusted-clock freshness check
  -> request/action replay check
  -> opaque authorized-action capability
  -> dry-run adapter
```

Callers cannot submit a trusted state, witness list, policy result, freshness
flag, or verification status. Those fields are rejected as untrusted control
fields before the verifier is called. The verified action argument is bound to
the canonical intent semantic digest, so a valid graph record for a different
payload cannot authorize this action.

The runtime contract checks more than a verifier boolean. It requires an
authenticated `action_argument` with `require` lineage, a complete reachable
witness closure, strictly decreasing generations, consistent child batches,
and terminal source records. Any disconnected witness, missing terminal, or
malformed closure blocks.

The policy MVP permits only `send_message` actions to the exact
`internal:alerts` destination, with non-`restricted` data and an explicitly
allowlisted connector authority. The gateway uses these fail-closed reason
codes:

```text
BLOCK_INVALID_INPUT
BLOCK_MISSING_PROVENANCE
BLOCK_INVALID_PROVENANCE
BLOCK_UNRESOLVED_ANCESTRY
BLOCK_POLICY
BLOCK_STALE
BLOCK_REPLAY
BLOCK_SYSTEM_ERROR
```

The adapter receives both caller request metadata and a gateway-issued
`authorized_at` timestamp from the trusted clock; `requested_at` is never used
as proof of authorization.

Action adapters are opaque capability handles created by the trusted
composition root. They have no public `execute` method; only the gateway's
private capability registry can invoke the registered executor. A blocked
intent therefore cannot reach the adapter through the gateway or through the
returned adapter handle.

Replay protection is process-local for this MVP and keys both `request_id` and
`action_id`. An exact replay returns `BLOCK_REPLAY / REQUEST_REPLAYED`; an
identity conflict also blocks. If an adapter fails after authorization, the
request becomes indeterminate and is never automatically retried. Freshness
uses only the injected trusted clock; clock rollback fails closed. Provenance
verification has a bounded deadline; query failures, verifier exceptions,
malformed verifier results, and timeouts are `BLOCK_SYSTEM_ERROR`.
Requests that were blocked before reservation may be retried after the
underlying state is repaired; only reserved identities are replay-protected.

The final trust-boundary review and residual limits are recorded in
[`docs/security-audit.md`](docs/security-audit.md).

The gateway proof writes
[`evidence/2026-08-17-action-gateway-proof.json`](evidence/2026-08-17-action-gateway-proof.json)
and the ignored rolling copy
`evidence/latest-action-gateway-proof.json`. It includes a live HydraDB
positive control, forged-state bypass attempts, live missing and depth-capped
provenance, stale state, policy violation, replay conflicts, malformed input,
verifier failure, verifier timeout, and an assertion that blocked actions never
call the adapter. The positive, missing-record, and depth-capped controls use
the live writer and HydraDB. Negative policy controls use deterministic
verifier fixtures, and the HydraDB failure control uses an explicitly injected
throwing Hydra client rather than claiming a live database outage.

## Limitations

- `prepareTransformation` belongs inside trusted middleware. Exposing it as a
  producer-facing API would move the trust boundary and invalidate the claim.
- HMACs detect out-of-band graph mutation; they do not make an untrusted
  HydraDB administrator trustworthy.
- Integrity verification uses bounded recursive graph reads with a default
  1,024-node closure budget. `algo.MSpaths` remains the later policy/witness
  primitive; the writer does not claim to use it for HMAC closure validation.
- The connector attestation used by the proof is deliberately narrow and does
  not yet implement expiry, revocation, or organization-wide PKI.
- The current fault evidence covers failure after child staging and before the
  edge batch. Lost responses after successful edge/commit writes and
  independent multi-process writer races remain follow-up tests; process-local
  locking is not presented as a distributed serialization mechanism.
- The deterministic numeric vertex mapping uses a truncated hash for this MVP.
  A production deployment should maintain and collision-check an external ID
  allocation table.
- The action policy is intentionally narrow: only the internal `send_message`
  dry-run path is covered. Real external side effects remain a later gate.
- Replay state is process-local; a restart loses the in-memory ledger. A
  durable idempotency store is required before production side effects.
- HydraDB reads are strongly consistent per request, but the current verifier
  does not claim a distributed multi-query snapshot across independent reads.

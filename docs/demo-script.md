# Quarantine Demo Script

This is the three-minute judge narrative for the live demo at
`http://127.0.0.1:4173`.

## 0:00-0:20: The Problem

Say: "AI systems can produce plausible conclusions, but plausibility is not
proof. Quarantine verifies whether the graph can justify an action before an
action capability is allowed to run."

Point out that the incoming claim begins as `UNTRUSTED INPUT`. The model or
producer can suggest content, but it cannot declare its own parents, trust, or
authorization.

## 0:20-0:50: Incoming Evidence

The valid scenario runs automatically when the page opens. Point first to the
top result banner, then show the source, entity, claim, and the explicit
untrusted classification in the left panel.

Say: "This is evidence, not permission. The permission decision is still
ahead of us."

## 0:50-1:20: HydraDB Provenance

Point to the center graph and its live metrics: nodes, signed edge witnesses,
source-to-action paths, and depth. Explain that stored HydraDB edges point
`child -> parent`; the screen reverses that relationship only for readability.

Say: "HydraDB is doing the meaningful work here: reverse traversal reconstructs
the multi-hop lineage and exposes whether every branch reaches a trusted
source. Similar text or a row in a relational table would not establish this
connected ancestry."

## 1:20-1:50: Valid Action

Start with the prominent action-gateway outcome, then use the verification and
policy sections beneath it to show why that result was justified: provenance,
freshness, deterministic policy, and replay protection all passed.

Say: "The policy is deterministic and server-side. The AI did not authorize
this. The trusted verifier issued state, the policy passed, and the opaque
gateway capability reached the dry-run adapter exactly once."

## 1:50-2:30: Attack

Select **Run tampered scenario**. Point first to **Defense 1 / write boundary**:
the forged `parent_ids` claim is rejected with zero forged child vertices,
zero forged parent vertices, and no edge created. Then point to **Defense 2 /
authorization bound**: observed depth 3 exceeds the gateway bound of 2, so the
trusted verifier returns `BLOCK_UNRESOLVED_ANCESTRY / DEPTH_CAP_REACHED`.

Say: "The producer's forged parent claim is rejected before it can create graph
state. The remaining signed chain is deeper than the gateway's authorization
bound, so the graph is observed but not authorized."

Point to `adapter invocations: 0` and `ACTION NOT EXECUTED`.
Note that policy is `NOT REACHED`, not a separate policy failure: provenance
stopped the authorization pipeline first.

## 2:30-3:00: Close

Say: "Quarantine does not ask whether information looks relevant. It asks
whether trustworthy graph provenance proves enough lineage to justify an
action. When that proof is missing, stale, malformed, replayed, or unresolved,
the action does not run."

Do not claim that the demo performs an external side effect. The adapter is a
deliberate dry run, and the current replay ledger is process-local.

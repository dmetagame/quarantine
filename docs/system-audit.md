# QUARANTINE System Audit — 2026-08-20

Scope: deployed runtime commit `e5b23fb`, the release-candidate repository,
live host `https://quarantine.rouma.online`, and a fresh full proof run.
Previous PASS artifacts were treated as history until the current
implementation, evidence, and deployed image were independently revalidated.

No authorization bypass was found on the public HTTP surface. The trust
boundary holds. The gaps below are observed in code, reproduced on the live
host, or strongly justified by the architecture.

## Architecture Map

```text
browser (untrusted)
  -> Caddy TLS reverse proxy
  -> demo-server.mjs  (scenario key only)
  -> demo-orchestrator.mjs  (server-owned fixtures + intent)
  -> provenance-writer.mjs  (HMAC-signed HydraDB writes / reverse verify)
  -> HydraDB 0.1.1  (DERIVES_FROM graph, strong consistency)
  -> branded trusted state
  -> deterministic policy
  -> process-local replay ledger
  -> opaque gateway-issued action
  -> dry-run adapter
```

| Component | Purpose | Inputs | Outputs | Trust | Boundary | Failure | Deps | Tests |
|---|---|---|---|---|---|---|---|---|
| `public/app.js` + `index.html` | Display only | Scenario click | `{scenario}` POST | Untrusted | Must not authorize | Client abort 15s | Fetch | Shape checks in app; server tests |
| `scripts/demo-server.mjs` | HTTP gate | JSON body ≤256B | Static assets, health, demo JSON | Untrusted in / trusted out | Exact `application/json`, one field | 400/413/415/503 | Orchestrator | `demo-boundary.test.mjs` |
| `src/demo-orchestrator.mjs` | Server-owned demo | `valid`/`tampered` | Graph, checks, gateway result | Trusted middleware | Builds intent; never accepts client provenance | `failureResponse` BLOCK | Writer, gateway, HydraDB | boundary + live demo proof |
| `src/hydradb-client.mjs` | Graph HTTP | OpenCypher + params | Projected rows | Trusted infra client | Bearer token, `consistency: strong` | Throws | fetch | `hydradb-client.test.mjs` |
| `src/provenance-writer.mjs` | Signed lineage write/verify | Content + observed parents | HMAC nodes/edges, VERIFIED/INVALID/UNRESOLVED/MISSING/SYSTEM_ERROR | Trusted writer | Producer may send only `{content}` | Fail-closed BLOCK | HydraDB, signing key | writer unit + live proof |
| `src/action-gateway.mjs` | Authorize + execute | Action intent | ALLOW/BLOCK + adapter | Trusted | Rejects trust-control fields; branded state | Fail-closed | Verifier, adapter, clock | `action-gateway.test.mjs` + live proof |
| Dry-run adapter | Record authorized action | Branded capability | `DRY_RUN` | Trusted, opaque | No public `execute` | Indeterminate on throw or timeout | WeakMap executor | gateway tests |
| Caddy | TLS + HTTP→HTTPS | Host 80/443 | Reverse proxy to loopback 4173 | Infra | HydraDB unpublished | ACME/startup fail | Host Caddy | Live headers |
| Compose | One-host runtime | `.env.deploy` + secrets | `demo` + `hydradb` | Infra | Secrets as files, demo bind 127.0.0.1 | Restart unless-stopped | Docker | `docs/deployment.md` |

## Data Flow (untrusted HTTP → adapter)

1. Browser sends `{ "scenario": "valid"|"tampered" }` only.
2. Server rejects extra fields, wrong types, oversized bodies, lookalike media types.
3. Orchestrator assigns `action_id`, `request_id`, payload, and
   `provenance_artifact_id` from server constants. The client cannot name an
   artifact, policy, witness, or adapter.
4. Fixtures are written through the trusted writer (connector HMAC + parent
   resolution + create-only HydraDB writes).
5. Observation verify uses maxDepth 16 (display). Authorization verify uses
   maxDepth 2 (gateway bound). Intentional demo split, not a client control.
6. Gateway validates intent, checks replay identity first, verifies provenance
   from HydraDB, brands trusted state, evaluates policy, checks freshness,
   reserves identity, then invokes the opaque adapter.
7. Display graph is hydrated **before** authorization so a later HydraDB read
   cannot hide an executed action.

Client-controlled security fields: **none** on the public API. Demo
`parent_ids` on producer output are rejected as `UNTRUSTED_CONTROL_FIELD`
before graph mutation (live tampered probe).

## Threat Model (compressed)

| Class | Result |
|---|---|
| Forged evidence / parent_ids / trust flags via HTTP | Rejected; only `scenario` accepted (live 400) |
| Direct adapter invoke | No public execute; handle has no `execute` |
| Replay same request_id/action_id | BLOCK_REPLAY; concurrent exact replay executes once |
| Parameter mutation after validate | Snapshotted; proxy intents fail closed |
| TOCTOU display vs authorize | Serialized `runQueue`; second HydraDB verify inside gateway |
| HydraDB down | Health 503; orchestrator `failureResponse` BLOCK; bounded query/readiness deadline |
| Graph cycles / truncated depth | INVALID / UNRESOLVED fail-closed |
| Prompt injection / AI override | No model in the authorize path. AI is not an authority. |
| Oversized body | Live 413 |
| Extra HTTP methods | Live 404 |
| Source/static leak | `/public/app.js` expected; `/src/*` 404; no cookies; no CORS |

## HydraDB Usage

Quarantine uses HydraDB for:

- `ProvenanceArtifact` nodes and `DERIVES_FROM` child→parent edges
- indexed vertex selectors (`id` derived from artifact id)
- reverse multi-hop witness reconstruction
- `consistency: strong`
- `__hydradb_create_only_*` and `__hydradb_update_if_newer_by`

Authenticity is **application HMAC**, not a HydraDB-native signature.
Replacing HydraDB with PostgreSQL would keep HMAC and policy, but would lose
native reverse traversal, create-only edge semantics, and the unresolved
frontier as a first-class graph result. The graph is essential to the demo;
the cryptographic root of trust is the writer key.

## Provenance States

Implemented and distinguishable: `VERIFIED`, `INVALID`, `UNRESOLVED`,
`MISSING`, `SYSTEM_ERROR`.

Not implemented: `CONFLICTING`, `STALE` (artifact-level; freshness is a
gateway trusted-state window), or a distinct provenance classification for
insufficient support. The hosted demo policy requires two trusted terminal
artifact nodes and reports `BLOCK_POLICY /
INSUFFICIENT_TRUSTED_SOURCES`; this is a policy result, not an independent-
authority proof. Its `independent_paths` metric counts graph paths only.

## Failure Matrix

| Failure | Current | Required |
|---|---|---|
| HydraDB not ready | Health 503 BLOCK | BLOCK |
| HydraDB query error | BLOCK_SYSTEM_ERROR | BLOCK |
| HydraDB HTTP hang | Full request/body deadline; timeout maps to `BLOCK_SYSTEM_ERROR` | BLOCK |
| Malformed projection | Throws → orchestrator BLOCK | BLOCK |
| Missing parent | PARENT_NOT_AUTHENTIC / UNRESOLVED | BLOCK |
| Stale trusted state | BLOCK_STALE | BLOCK |
| Policy deny | BLOCK_POLICY | BLOCK |
| Adapter throw/timeout | ACTION_INDETERMINATE, no retry; timeout is `ACTION_ADAPTER_TIMEOUT` | BLOCK |
| Process restart | Replay ledger wiped (documented; adapter is dry-run) | Durable before real side effects |
| Duplicate demo click | New request_id each run, so ALLOW again | Demo UX; bounded ledger |
| Public burst | `MAX_PENDING_DEMO_RUNS=8`; excess returns `DEMO_BUSY` | Bound + busy |

## Live Host (`https://quarantine.rouma.online`)

Verified 2026-08-20:

- Deployed source and static-asset hashes match repository commit `e5b23fb`
- HTTPS, Let's Encrypt CN `quarantine.rouma.online`, HTTP 308 → HTTPS
- CSP, COOP, CORP, `nosniff`, `DENY` frame, `no-store`, no cookies, no CORS
- Health GET PASS; HydraDB endpoint leaked as `http://hydradb:8443`
- HEAD `/api/health` 404 (GET-only)
- No `Strict-Transport-Security`
- HydraDB ports 18443/19091/4173/7687 closed publicly
- Valid ALLOW + adapter 1 + `action-proof-v1`; tampered
  `BLOCK_UNRESOLVED_ANCESTRY` + adapter 0 + `action-proof-v1`
- Two 12-request bursts returned bounded combinations of ALLOW and `DEMO_BUSY`;
  every ALLOW invoked the adapter once and busy responses invoked it zero times

## Judge Score (Hack Hydra, brutal)

These scores reflect the current repository, evidence, and deployed
`e5b23fb` image. They are intentionally conservative about the dry-run adapter,
process-local replay, and the absence of an in-loop model.

| Criterion | Score /10 | Note |
|---|---|---|
| Originality | 8 | Fail-closed action gateway on reverse lineage is distinctive |
| HydraDB integration | 7 | Real graph reads/writes and native path proofs; runtime closure validation is application-owned |
| Technical depth | 9 | Signed graph state, snapshots, brands, replay, depth caps, atomic mixed-parent rejection |
| Security | 8 | Core boundary and deadlines are strong; durable replay and key lifecycle remain future work |
| Usefulness | 6 | Compelling control plane, but the shipped adapter is deliberately dry-run |
| AI relevance | 6 | Frames untrusted producer output; no model in-loop |
| Demo clarity | 9 | Live VALID/TAMPERED contrast is immediate and judge-legible |
| UI/UX | 8 | Focused single-screen graph and decision flow; operational metadata is still exposed |
| Engineering quality | 9 | No runtime deps, bounded failures, hash-bound evidence, 70 unit tests |
| Why HydraDB? | 8 | Reverse multi-path witnesses and unresolved frontiers are naturally graph-shaped |

**Overall ~7.8 / 10.** The largest remaining judge gap is product proof, not
boundary correctness: the shipped flow uses server-owned fixtures and a dry-run
adapter, so it demonstrates how Quarantine gates an AI-proposed action without
showing an actual model-to-tool integration.

## Ranked Backlog

| ID | Sev / status | Category | Current | Risk | Fix | Complexity | Tests | Hackathon |
|---|---|---|---|---|---|---|---|---|
| P1-TIMEOUT | Resolved | Fail-closed | Complete HydraDB request/body deadline is deployed and verified | Availability; not an auth bypass | Keep the bounded deadline | S | Body-stall unit test | High |
| P1-ADAPTER-TIMEOUT | Resolved | Fail-closed | Bounded adapter deadline and indeterminate replay state are deployed and verified | Prevents stalled execution from holding a request indefinitely | Keep timeout + no automatic retry | S | Gateway/proof regression | High |
| P1-QUEUE | P1 / resolved | DoS | `runQueue` and replay ledger are bounded and live burst backpressure returns `DEMO_BUSY` | Memory / stalled public demo | Keep caps and busy response | S | Concurrent busy | High |
| P1-PRODKEYS | P1 / resolved | Config | Production refuses published proof keys | Footgun if env missing | Keep production fallback disabled | S | Boot test | Medium |
| P2-HSTS | P2 | Deploy | No HSTS | SSL-strip after first visit | Caddy header | S | Live header | Medium |
| P2-HMACCMP | P2 | Crypto | Connector compare uses `===` | Timing leak; not on public API | `timingSafeEqual` | S | Writer unit | Low |
| P2-HEALTHLEAK | P2 | Info | Health returns `http://hydradb:8443` | Internal name leak | Omit URL | S | Health contract | Low |
| P2-HEAD | P3 | HTTP | HEAD `/api/health` 404 | Harmless | Allow HEAD | S | Boundary | Low |
| P2-REPLAYVOL | P2 | Residual | Replay ledger process-local | Real side effects after restart | Durable ledger | M | Restart test | Medium |
| P2-PROOF | P2 | Product | Compact `action_proof-v1` is shipped; self-contained witness detail remains a gap | Judge "why allowed?" | Extend only if evidence value justifies it | M | Demo proof | High |
| P2-WITNESS | P2 | Product | Demo requires two terminal artifacts, but does not prove independent authorities | Under-sells HydraDB | Add explicit authority/disjoint-branch semantics only if justified | M | Gateway + demo | High |
| P3-CONFLICT | P3 | Product | No CONFLICTING state | Future depth | Distinguish contradictory claims | L | New proofs | High |
| P3-CI | P3 | Eng | No CI | Drift | GitHub Actions `npm test` | S | Workflow | Medium |

### Must fix before release

None open. The complete-response deadline, adapter deadline, bounded public
queue, bounded replay ledger, and production key safeguards are deployed and
verified.

### Should fix (P2)

1. Remove internal HydraDB/admin URLs from public health and demo metadata
2. Add HSTS after confirming the custom domain is permanently HTTPS-only
3. Use timing-safe connector-attestation comparison

### Optional

1. Explicit independent-authority/disjoint-branch policy semantics
2. Conflict-aware and artifact-staleness provenance states
3. Durable replay before real adapters; CI for release drift

Implementation follows one issue at a time. Live evidence is regenerated only
after hashed implementation files change.

## Implementation record (2026-08-20)

| ID | Result |
|---|---|
| P1-TIMEOUT | Done. HydraDB `query` and `readyz` abort after 5s (override 1–30000). Hung fetch unit tests pass. Observation hangs now become orchestrator BLOCK. |
| P1-ADAPTER-TIMEOUT | Done and deployed. Adapter execution has a 5s deadline; timeout returns `ACTION_ADAPTER_TIMEOUT`, marks the identity indeterminate, and blocks replay. |
| P1-QUEUE | Done. `MAX_PENDING_DEMO_RUNS = 8` returns `DEMO_BUSY`. Gateway `maxLedgerEntries = 10000` returns `ACTION_LEDGER_FULL` without evicting replay identity. |
| P1-PRODKEYS | Done. `NODE_ENV=production` refuses published proof-key fallbacks. |
| P2-WITNESS | Done. Demo gateway requires `minTrustedSources: 2` (existing two-path valid graph). |
| P2-PROOF | Done. Server returns `action_proof` v1; UI shows decision, independent paths, sources, authorization id prefix. |

Fresh `npm test` PASS: 70 unit tests, HydraDB viability proof, 17 provenance
cases, 18 gateway cases, 2 end-to-end scenarios, and all evidence validators.
The public host matches `e5b23fb`; TLS, health, VALID/TAMPERED behavior,
`action-proof-v1`, adapter cardinality, request bounds, static-file isolation,
and queue backpressure were revalidated before release tagging.

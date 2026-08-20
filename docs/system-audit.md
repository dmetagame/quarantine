# QUARANTINE System Audit — 2026-08-20

Scope: repository, live host `https://quarantine.rouma.online`, and the
previously passing proof suite. Previous PASS artifacts were treated as
history, not as proof that the deployed product is complete.

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
| Dry-run adapter | Record authorized action | Branded capability | `DRY_RUN` | Trusted, opaque | No public `execute` | Indeterminate on throw | WeakMap executor | gateway tests |
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
| HydraDB down | Health 503; orchestrator `failureResponse` BLOCK; **hang is not BLOCK** (P1) |
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
gateway trusted-state window), `INSUFFICIENT` (policy currently requires ≥1
trusted terminal, not N independent witnesses). The valid demo graph already
has two source-to-action paths; policy does not require that.

## Failure Matrix

| Failure | Current | Required |
|---|---|---|
| HydraDB not ready | Health 503 BLOCK | BLOCK |
| HydraDB query error | BLOCK_SYSTEM_ERROR | BLOCK |
| HydraDB HTTP hang | Observation `fetch` has no abort; request sticks until client 15s | BLOCK |
| Malformed projection | Throws → orchestrator BLOCK | BLOCK |
| Missing parent | PARENT_NOT_AUTHENTIC / UNRESOLVED | BLOCK |
| Stale trusted state | BLOCK_STALE | BLOCK |
| Policy deny | BLOCK_POLICY | BLOCK |
| Adapter throw | ACTION_INDETERMINATE, no retry | BLOCK |
| Process restart | Replay ledger wiped (documented; adapter is dry-run) | Durable before real side effects |
| Duplicate demo click | New request_id each run, so ALLOW again | Demo UX; ledger grows (P1) |
| Public burst | Unbounded promise queue | Bound + busy |

## Live Host (`https://quarantine.rouma.online`)

Verified 2026-08-20:

- HTTPS, Let's Encrypt CN `quarantine.rouma.online`, HTTP 308 → HTTPS
- CSP, COOP, CORP, `nosniff`, `DENY` frame, `no-store`, no cookies, no CORS
- Health GET PASS; HydraDB endpoint leaked as `http://hydradb:8443`
- HEAD `/api/health` 404 (GET-only)
- No `Strict-Transport-Security`
- HydraDB ports 18443/19091/4173/7687 closed publicly
- Valid ALLOW + adapter 1; tampered `BLOCK_UNRESOLVED_ANCESTRY` + adapter 0

## Judge Score (Hack Hydra, brutal)

| Criterion | Score /10 | Note |
|---|---|---|
| Originality | 8 | Fail-closed action gateway on reverse lineage is distinctive |
| HydraDB usage | 7 | Real reverse traversal + create-only; HMAC is app-layer |
| Technical depth | 8 | Snapshots, brands, replay, depth cap, atomic mixed-parent |
| Security | 7 | Boundary is strong; hosted availability/timeouts are weak |
| Product clarity | 7 | Two-scenario demo is clear; not yet an ACTION PROOF product |
| Demo quality | 8 | Live HTTPS works; graph + attack probe are judge-legible |
| Practical usefulness | 6 | Dry-run adapter; process-local replay |
| AI relevance | 6 | Frames untrusted producer output; no model in-loop |
| Engineering quality | 8 | No runtime deps, hashed evidence, tight tests |
| Why HydraDB? | 7 | Multi-path + unresolved frontier are graph-shaped |

**Overall ~7.2 / 10.** Top score levers: (1) ACTION PROOF object, (2)
independent-witness policy using the existing two-path graph, (3) fail-closed
timeouts on live HydraDB, (4) conflict state, (5) durable replay before
claiming production side effects.

## Ranked Backlog

| ID | Sev | Category | Current | Risk | Fix | Complexity | Tests | Hackathon |
|---|---|---|---|---|---|---|---|---|
| P1-TIMEOUT | P1 | Fail-closed | `fetch` has no abort; observation verify can hang | Availability; not an auth bypass | Default query + ready timeout; abort signal | S | Unit abort test | High |
| P1-QUEUE | P1 | DoS | Unbounded `runQueue` + growing replay Maps | Memory / stalled public demo | Cap pending runs; cap/evict ledger | S | Concurrent busy | High |
| P1-PRODKEYS | P1 | Config | Orchestrator falls back to published proof keys | Footgun if env missing | Refuse defaults when `NODE_ENV=production` | S | Boot test | Medium |
| P2-HSTS | P2 | Deploy | No HSTS | SSL-strip after first visit | Caddy header | S | Live header | Medium |
| P2-HMACCMP | P2 | Crypto | Connector compare uses `===` | Timing leak; not on public API | `timingSafeEqual` | S | Writer unit | Low |
| P2-HEALTHLEAK | P2 | Info | Health returns `http://hydradb:8443` | Internal name leak | Omit URL | S | Health contract | Low |
| P2-HEAD | P3 | HTTP | HEAD `/api/health` 404 | Harmless | Allow HEAD | S | Boundary | Low |
| P2-REPLAYVOL | P2 | Residual | Replay ledger process-local | Real side effects after restart | Durable ledger | M | Restart test | Medium |
| P2-PROOF | P2 | Product | ALLOW is not a bound proof object | Judge "why allowed?" | ACTION_PROOF from existing state | M | Demo proof | High |
| P2-WITNESS | P2 | Product | Policy does not require independent paths | Under-sells HydraDB | Require ≥2 trusted sources | M | Gateway + demo | High |
| P3-CONFLICT | P3 | Product | No CONFLICTING state | Future depth | Distinguish contradictory claims | L | New proofs | High |
| P3-CI | P3 | Eng | No CI | Drift | GitHub Actions `npm test` | S | Workflow | Medium |

### Must fix (P1)

1. HydraDB HTTP abort/timeout
2. Bound public demo queue and replay Maps
3. Refuse published signing keys in production

### Should fix (P2)

1. ACTION_PROOF in the demo response
2. Independent-witness policy (uses existing two-path graph)
3. HSTS + timing-safe connector compare

### Optional

1. Conflict-aware provenance
2. Durable replay before real adapters
3. CI

Implementation follows one issue at a time. Live evidence is regenerated only
after hashed implementation files change.

## Implementation record (2026-08-20)

| ID | Result |
|---|---|
| P1-TIMEOUT | Done. HydraDB `query` and `readyz` abort after 5s (override 1–30000). Hung fetch unit tests pass. Observation hangs now become orchestrator BLOCK. |
| P1-QUEUE | Done. `MAX_PENDING_DEMO_RUNS = 8` returns `DEMO_BUSY`. Gateway `maxLedgerEntries = 10000` returns `ACTION_LEDGER_FULL` without evicting replay identity. |
| P1-PRODKEYS | Done. `NODE_ENV=production` refuses published proof-key fallbacks. |
| P2-WITNESS | Done. Demo gateway requires `minTrustedSources: 2` (existing two-path valid graph). |
| P2-PROOF | Done. Server returns `action_proof` v1; UI shows decision, independent paths, sources, authorization id prefix. |

Live local proofs regenerated and `npm run validate:evidence` PASS. The public host still runs the previous image until this tree is deployed.

#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const DATED_PATH = "evidence/2026-08-17-action-gateway-proof.json";
const LATEST_PATH = "evidence/latest-action-gateway-proof.json";

const REQUIRED_CASES = Object.freeze([
  "forged_trusted_state_fields_are_rejected",
  "forged_provenance_witness_is_rejected",
  "forged_policy_result_is_rejected",
  "forged_freshness_is_rejected",
  "forged_verification_status_is_rejected",
  "direct_adapter_bypass_is_unavailable",
  "malformed_verified_provenance_blocks",
  "legitimate_live_hydradb_action_is_allowed",
  "missing_provenance_blocks",
  "unresolved_ancestry_blocks",
  "stale_trusted_state_blocks",
  "policy_violation_blocks",
  "replay_is_deterministic_and_adapter_runs_once",
  "malformed_action_blocks_before_verification",
  "hydradb_verification_failure_blocks",
  "verification_timeout_blocks",
  "blocked_actions_never_reach_adapter",
]);

const CASE_CONTRACTS = Object.freeze({
  forged_trusted_state_fields_are_rejected: ["BLOCK", "BLOCK_INVALID_INPUT", "UNTRUSTED_CONTROL_FIELD"],
  forged_provenance_witness_is_rejected: ["BLOCK", "BLOCK_INVALID_INPUT", "UNTRUSTED_CONTROL_FIELD"],
  forged_policy_result_is_rejected: ["BLOCK", "BLOCK_INVALID_INPUT", "UNTRUSTED_CONTROL_FIELD"],
  forged_freshness_is_rejected: ["BLOCK", "BLOCK_INVALID_INPUT", "UNTRUSTED_CONTROL_FIELD"],
  forged_verification_status_is_rejected: ["BLOCK", "BLOCK_INVALID_INPUT", "UNTRUSTED_CONTROL_FIELD"],
  direct_adapter_bypass_is_unavailable: ["BLOCK", "BLOCK_INVALID_INPUT", "UNTRUSTED_CONTROL_FIELD"],
  malformed_verified_provenance_blocks: ["BLOCK", "BLOCK_INVALID_PROVENANCE", "MALFORMED_OR_UNBOUND_PROVENANCE"],
  legitimate_live_hydradb_action_is_allowed: ["ALLOW", null, "ACTION_AUTHORIZED"],
  missing_provenance_blocks: ["BLOCK", "BLOCK_MISSING_PROVENANCE", "PROVENANCE_ARTIFACT_NOT_FOUND"],
  unresolved_ancestry_blocks: ["BLOCK", "BLOCK_UNRESOLVED_ANCESTRY", "DEPTH_CAP_REACHED"],
  stale_trusted_state_blocks: ["BLOCK", "BLOCK_STALE", "TRUSTED_STATE_EXPIRED"],
  policy_violation_blocks: ["BLOCK", "BLOCK_POLICY", "DESTINATION_NOT_ALLOWED"],
  replay_is_deterministic_and_adapter_runs_once: ["BLOCK", "BLOCK_REPLAY", "REQUEST_REPLAYED"],
  malformed_action_blocks_before_verification: ["BLOCK", "BLOCK_INVALID_INPUT", "INVALID_ACTION_PARAMETERS"],
  hydradb_verification_failure_blocks: ["BLOCK", "BLOCK_SYSTEM_ERROR", "PROVENANCE_VERIFICATION_FAILED"],
  verification_timeout_blocks: ["BLOCK", "BLOCK_SYSTEM_ERROR", "PROVENANCE_VERIFICATION_TIMEOUT"],
  blocked_actions_never_reach_adapter: ["BLOCK", "BLOCK_MISSING_PROVENANCE", "ADAPTER_NOT_CALLED"],
});

const IMPLEMENTATION_FILES = Object.freeze([
  "src/hydradb-client.mjs",
  "src/provenance-writer.mjs",
  "src/action-gateway.mjs",
  "scripts/prove-action-gateway.mjs",
  "scripts/validate-action-gateway-evidence.mjs",
]);

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function implementationHashes() {
  const entries = await Promise.all(IMPLEMENTATION_FILES.map(async (path) => [
    path,
    sha256(await readFile(resolve(path), "utf8")),
  ]));
  return Object.fromEntries(entries);
}

const [datedText, latestText, dated, latest] = await Promise.all([
  readFile(DATED_PATH, "utf8"),
  readFile(LATEST_PATH, "utf8"),
  readJson(DATED_PATH),
  readJson(LATEST_PATH),
]);

assert(datedText === latestText, "Dated and latest action-gateway evidence differ");
assert(JSON.stringify(dated) === JSON.stringify(latest), "Dated and latest action-gateway JSON differs");
assert(dated.status === "PASS", "Action-gateway evidence is not PASS");
assert(dated.gate === "trusted_state_action_gateway", "Action-gateway evidence has the wrong gate");
assert(dated.schema_version === 1, "Action-gateway evidence has the wrong schema version");
assert(dated.recorded_at === "2026-08-17T00:00:00.000Z", "Action-gateway evidence timestamp changed");
assert(dated.run_id === "gateway-gate-v1", "Action-gateway evidence run identity changed");
assert(dated.implementation?.hash_algorithm === "sha256", "Action-gateway evidence has the wrong hash contract");
assert(JSON.stringify(dated.implementation.files) === JSON.stringify(await implementationHashes()), "Action-gateway evidence is stale relative to implementation");
assert(dated.hydradb_identity?.image === dated.image, "Action-gateway HydraDB identity is inconsistent");
assert(dated.hydradb_identity?.registry_digest === dated.image_digest, "Action-gateway registry digest is inconsistent");
assert(dated.gateway?.verification_timeout_ms === 5_000, "Action-gateway verification timeout changed");
assert(JSON.stringify(dated.gateway?.allowed_source_authorities) === JSON.stringify(["quarantine-proof-connector"]), "Action-gateway source authority policy changed");
assert(JSON.stringify(dated.gateway?.allowed_destinations) === JSON.stringify(["internal:alerts"]), "Action-gateway destination policy changed");
assert(dated.setup?.graph_assertions?.trusted_source_vertices === 1, "Action-gateway proof lost trusted source assertion");
assert(dated.setup?.graph_assertions?.action_argument_vertices === 1, "Action-gateway proof lost action argument assertion");
assert(dated.setup?.graph_assertions?.direct_edges === 1, "Action-gateway proof lost ancestry edge assertion");
assert(dated.setup?.graph_assertions?.hydrated_edge_kind === "require", "Action-gateway proof lost edge kind hydration");
assert(dated.setup?.graph_assertions?.reverse_witness_count >= 1, "Action-gateway proof lost reverse witness assertion");
assert(dated.setup?.graph_assertions?.verification_status === "PASS", "Action-gateway proof lost live verification assertion");

assert(Array.isArray(dated.tests), "Action-gateway evidence has no test list");
const names = dated.tests.map((testCase) => testCase.name);
assert(new Set(names).size === names.length, "Action-gateway evidence contains duplicate test names");
for (const requiredCase of REQUIRED_CASES) {
  assert(names.includes(requiredCase), `Action-gateway evidence is missing ${requiredCase}`);
}
for (const testCase of dated.tests) {
  assert(testCase.status === "PASS", `Action-gateway evidence contains a failed case: ${testCase.name}`);
  assert(testCase.actual_result === testCase.expected_result, `Action-gateway outcome mismatch: ${testCase.name}`);
  const contract = CASE_CONTRACTS[testCase.name];
  assert(contract, `Action-gateway evidence contains an unknown case: ${testCase.name}`);
  assert(testCase.expected_result === contract[0], `Action-gateway expected result mismatch: ${testCase.name}`);
  assert(testCase.reason_code === contract[1], `Action-gateway reason code mismatch: ${testCase.name}`);
  assert(testCase.detail === contract[2], `Action-gateway detail mismatch: ${testCase.name}`);
}

const byName = new Map(dated.tests.map((testCase) => [testCase.name, testCase]));
for (const name of REQUIRED_CASES.slice(0, 5)) {
  const testCase = byName.get(name);
  assert(testCase.graph_assertions?.verifier_calls === 0, `${name} reached the verifier`);
  assert(testCase.graph_assertions?.adapter_calls === 0, `${name} reached the adapter`);
  assert(JSON.stringify(testCase.graph_assertions?.rejected_fields) === JSON.stringify([testCase.input?.field]), `${name} lost its rejected field assertion`);
}

const directAdapter = byName.get("direct_adapter_bypass_is_unavailable");
assert(directAdapter.graph_assertions?.public_execute_method === false, "Opaque adapter exposed a direct execute method");
assert(directAdapter.graph_assertions?.verifier_calls === 0, "Direct adapter bypass reached the verifier");
assert(directAdapter.graph_assertions?.adapter_calls === 0, "Direct adapter bypass reached the adapter");
assert(JSON.stringify(directAdapter.graph_assertions?.rejected_fields) === JSON.stringify(["adapter"]), "Direct adapter bypass lost its rejected field assertion");

const positive = byName.get("legitimate_live_hydradb_action_is_allowed");
assert(positive.graph_assertions?.adapter_calls === 1, "Positive control did not execute exactly once");
assert(positive.graph_assertions?.adapter_result === "DRY_RUN", "Positive control did not use the dry-run adapter");
assert(positive.graph_assertions?.authorized_at === 2_000, "Positive control did not preserve the trusted authorization timestamp");

const replay = byName.get("replay_is_deterministic_and_adapter_runs_once");
assert(replay.graph_assertions?.first_result === "ALLOW", "Replay control lost initial allow");
assert(replay.graph_assertions?.replay_result === "BLOCK", "Replay control lost replay block");
assert(replay.graph_assertions?.request_conflict_detail === "REQUEST_ID_CONFLICT", "Replay control lost request conflict");
assert(replay.graph_assertions?.action_conflict_detail === "ACTION_ID_CONFLICT", "Replay control lost action conflict");
assert(replay.graph_assertions?.adapter_calls === 1, "Replay control executed adapter more than once");

const missing = byName.get("missing_provenance_blocks");
assert(missing.input_classification === "live_hydradb_missing_graph_record", "Missing provenance case is not live HydraDB-backed");
assert(missing.graph_assertions?.missing_vertices === 0, "Missing provenance case found a graph vertex");
assert(missing.graph_assertions?.adapter_calls === 0, "Missing provenance reached the adapter");

const unresolved = byName.get("unresolved_ancestry_blocks");
assert(unresolved.input_classification === "live_hydradb_depth_capped_provenance", "Unresolved ancestry case is not live HydraDB-backed");
assert(unresolved.graph_assertions?.full_verification_status === "PASS", "Unresolved control did not verify without the cap");
assert(unresolved.graph_assertions?.capped_verification_status === "BLOCK", "Depth-capped verification did not block");
assert(unresolved.graph_assertions?.capped_verification_detail === "DEPTH_CAP_REACHED", "Depth-capped verification detail changed");
assert(unresolved.graph_assertions?.unresolved_argument_vertices === 1, "Unresolved action argument is missing");
assert(unresolved.graph_assertions?.unresolved_summary_vertices === 1, "Unresolved summary is missing");
assert(unresolved.graph_assertions?.argument_to_summary_edges === 1, "Unresolved argument edge is missing");
assert(unresolved.graph_assertions?.summary_to_source_edges === 1, "Unresolved summary edge is missing");
assert(unresolved.graph_assertions?.adapter_calls === 0, "Unresolved ancestry reached the adapter");

const hydraFailure = byName.get("hydradb_verification_failure_blocks");
assert(hydraFailure.input_classification === "injected_hydradb_query_failure", "HydraDB failure case has the wrong classification");
assert(hydraFailure.graph_assertions?.verifier_classification === "SYSTEM_ERROR", "HydraDB failure did not surface a verifier system error");
assert(hydraFailure.graph_assertions?.adapter_calls === 0, "HydraDB failure reached the adapter");

const timeout = byName.get("verification_timeout_blocks");
assert(timeout.graph_assertions?.adapter_calls === 0, "Verification timeout reached the adapter");

const aggregate = byName.get("blocked_actions_never_reach_adapter");
assert(aggregate.graph_assertions?.all_blocked === true, "Aggregate blocked paths did not all block");
assert(aggregate.graph_assertions?.blocked_attempts === 6, "Aggregate invariant did not exercise all six blocked paths");
assert(aggregate.graph_assertions?.adapter_calls === 0, "Aggregate blocked path reached adapter");

const failedCount = dated.tests.filter((testCase) => testCase.status !== "PASS").length;
assert(dated.summary?.total === dated.tests.length, "Action-gateway evidence total is wrong");
assert(dated.summary?.passed === dated.tests.length - failedCount, "Action-gateway evidence passed count is wrong");
assert(dated.summary?.failed === 0 && failedCount === 0, "Action-gateway evidence contains failures");

process.stdout.write(`Action gateway evidence validated: ${dated.tests.length} cases, PASS\n`);

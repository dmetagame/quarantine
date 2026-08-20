#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const DATED_PATH = "evidence/2026-08-18-end-to-end-demo-proof.json";
const LATEST_PATH = "evidence/latest-end-to-end-demo-proof.json";
const IMPLEMENTATION_FILES = Object.freeze([
  "src/hydradb-client.mjs",
  "src/provenance-writer.mjs",
  "src/action-gateway.mjs",
  "src/demo-orchestrator.mjs",
  "scripts/demo-server.mjs",
  "scripts/prove-demo.mjs",
  "scripts/validate-demo-evidence.mjs",
  "index.html",
  "public/app.js",
  "public/styles.css",
]);

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

async function implementationHashes() {
  const entries = await Promise.all(IMPLEMENTATION_FILES.map(async (path) => [
    path,
    sha256(await readFile(resolve(path), "utf8")),
  ]));
  return Object.fromEntries(entries);
}

function scenarioByName(report, name) {
  const scenario = report.scenarios.find((candidate) => candidate.name === name);
  assert(scenario, `Demo evidence is missing the ${name} scenario`);
  return scenario;
}

function checkByLabel(scenario, label) {
  const check = scenario.verification?.checks?.find((candidate) => candidate.label === label);
  assert(check, `${scenario.name} scenario is missing verification check: ${label}`);
  return check;
}

function hasTimelineEvent(scenario, label, status) {
  return scenario.timeline?.some((event) => event.label === label && event.status === status);
}

const [datedText, latestText, dated, latest] = await Promise.all([
  readFile(DATED_PATH, "utf8"),
  readFile(LATEST_PATH, "utf8"),
  readFile(DATED_PATH, "utf8").then(JSON.parse),
  readFile(LATEST_PATH, "utf8").then(JSON.parse),
]);

assert(datedText === latestText, "Dated and latest demo evidence differ");
assert(JSON.stringify(dated) === JSON.stringify(latest), "Dated and latest demo JSON differs");
assert(dated.status === "PASS", "End-to-end demo evidence is not PASS");
assert(dated.gate === "end_to_end_demo", "Demo evidence has the wrong gate");
assert(dated.schema_version === 1, "Demo evidence has the wrong schema version");
assert(dated.recorded_at === "2026-08-18T00:00:00.000Z", "Demo evidence timestamp changed");
assert(dated.run_id === "quarantine-demo-proof-v1", "Demo evidence run identity changed");
assert(dated.image === "ghcr.io/hydra-db/hydradb:0.1.1", "Demo evidence HydraDB image changed");
assert(dated.image_digest === "sha256:db78309a233be54662db29744047e985a39b51c45a270d1a1f47c31a62cdb709", "Demo evidence HydraDB digest changed");
assert(dated.hydradb_identity?.image === dated.image, "Demo HydraDB identity image is inconsistent");
assert(dated.hydradb_identity?.registry_digest === dated.image_digest, "Demo HydraDB identity digest is inconsistent");
assert(dated.hydradb?.consistency === "strong", "Demo HydraDB reads are not marked strong");
assert(dated.implementation?.hash_algorithm === "sha256", "Demo evidence has the wrong hash contract");
assert(JSON.stringify(dated.implementation.files) === JSON.stringify(await implementationHashes()), "Demo evidence is stale relative to implementation");

assert(dated.demo?.demo_version === "quarantine-demo-v2", "Demo runtime version changed");
assert(dated.demo?.gateway_version === "fail-closed-action-gateway-v1", "Demo gateway version changed");
assert(dated.demo?.trusted_state_contract_version === "trusted-state-contract-v1", "Demo trusted-state contract changed");
assert(dated.demo?.policy_version === "internal-message-policy-v1", "Demo policy version changed");
assert(dated.demo?.verifier_version === "provenance-state-verifier-v1", "Demo verifier version changed");
assert(JSON.stringify(dated.demo?.scenarios) === JSON.stringify(["valid", "tampered"]), "Demo scenario contract changed");
assert(dated.demo?.observation_max_depth === 16, "Demo observation depth changed");
assert(dated.demo?.authorization_max_depth === 2, "Demo authorization depth changed");

assert(Array.isArray(dated.scenarios), "Demo evidence has no scenario list");
assert(dated.scenarios.length === 2, "Demo evidence must contain exactly two scenarios");
assert(new Set(dated.scenarios.map((scenario) => scenario.name)).size === 2, "Demo evidence contains duplicate scenarios");
for (const scenario of dated.scenarios) {
  assert(scenario.status === "PASS", `Demo scenario failed: ${scenario.name}`);
  assert(scenario.actual_result === scenario.expected_result, `Demo scenario outcome mismatch: ${scenario.name}`);
  assert(Array.isArray(scenario.timeline) && scenario.timeline.length >= 6, `Demo scenario has an incomplete timeline: ${scenario.name}`);
  assert(Array.isArray(scenario.verification?.checks) && scenario.verification.checks.length === 7, `Demo scenario has an incomplete verification checklist: ${scenario.name}`);
}

assert(dated.summary?.total === dated.scenarios.length, "Demo summary total is inconsistent");
assert(dated.summary?.passed === dated.scenarios.filter((scenario) => scenario.status === "PASS").length, "Demo summary pass count is inconsistent");
assert(dated.summary?.failed === 0, "Demo summary contains failures");

const valid = scenarioByName(dated, "valid");
assert(valid.input_classification === "trusted_graph_backed_evidence", "Valid scenario input classification changed");
assert(valid.expected_result === "ALLOW" && valid.actual_result === "ALLOW", "Valid scenario did not allow");
assert(valid.graph_assertions?.nodes === 5, "Valid demo graph lost its five-node closure");
assert(valid.graph_assertions?.edges === 4, "Valid demo graph lost its four signed edges");
assert(valid.graph_assertions?.authenticated_witnesses === 4, "Valid demo witness count changed");
assert(valid.graph_assertions?.source_to_action_paths === 2, "Valid demo path count changed");
assert(valid.graph_assertions?.deepest_hops === 2, "Valid demo depth changed");
assert(valid.graph_assertions?.authorization_depth === 2, "Valid authorization depth changed");
assert(valid.graph_assertions?.ancestry === "RESOLVED", "Valid demo ancestry is not resolved");
assert(valid.graph_assertions?.trusted_sources === 2, "Valid demo trusted source count changed");
assert(JSON.stringify(valid.graph_assertions?.edge_kinds) === JSON.stringify(["assert", "require", "summarize"]), "Valid demo edge kinds changed");
assert(valid.verification?.status === "PASS", "Valid demo verification did not pass");
assert(valid.verification?.observation_status === "PASS", "Valid demo observation did not pass");
assert(valid.verification?.ancestry_status === "RESOLVED", "Valid demo verification ancestry changed");
assert(valid.verification?.reason_code === null, "Valid demo verification returned a reason code");
assert(valid.verification.checks.every((check) => check.status === "PASS"), "Valid demo verification checklist is not all PASS");
assert(valid.policy?.status === "PASS" && valid.policy?.result === "POLICY_ALLOW", "Valid demo policy did not allow");
assert(valid.gateway?.status === "ALLOW", "Valid demo gateway did not allow");
assert(valid.gateway?.reason_code === null && valid.gateway?.detail === "ACTION_AUTHORIZED", "Valid demo gateway result changed");
assert(valid.gateway?.adapter_calls === 1, "Valid demo gateway did not invoke the adapter exactly once");
assert(valid.action?.executed === true, "Valid demo action did not execute");
assert(valid.action?.adapter_calls === 1 && valid.action?.result === "DRY_RUN", "Valid demo action did not use the dry-run adapter once");
assert(valid.action_proof?.version === "action-proof-v1", "Valid demo action proof is missing");
assert(valid.action_proof?.decision === valid.gateway.status, "Valid demo action proof decision changed");
assert(valid.action_proof?.reason_code === valid.gateway.reason_code, "Valid demo action proof reason changed");
assert(valid.action_proof?.detail === valid.gateway.detail, "Valid demo action proof detail changed");
assert(valid.action_proof?.action?.type === "send_message", "Valid demo action proof type changed");
assert(valid.action_proof?.action?.destination === "internal:alerts", "Valid demo action proof destination changed");
assert(valid.action_proof?.provenance?.ancestry_status === "RESOLVED", "Valid demo action proof ancestry changed");
assert(valid.action_proof?.provenance?.source_count === 2, "Valid demo action proof source count changed");
assert(valid.action_proof?.provenance?.witness_count === 4, "Valid demo action proof witness count changed");
assert(valid.action_proof?.provenance?.independent_paths === 2, "Valid demo action proof path count changed");
assert(valid.action_proof?.provenance?.deepest_hops === 2, "Valid demo action proof depth changed");
assert(valid.action_proof?.provenance?.max_depth === 2, "Valid demo action proof authorization bound changed");
assert(valid.action_proof?.policy_version === "internal-message-policy-v1", "Valid demo action proof policy changed");
assert(typeof valid.action_proof?.authorization_id === "string", "Valid demo action proof lost authorization identity");
assert(typeof valid.action_proof?.trusted_state_id === "string", "Valid demo action proof lost trusted-state identity");
assert(valid.action_proof?.executed === true, "Valid demo action proof execution flag changed");
assert(hasTimelineEvent(valid, "Action gateway decision", "PASS"), "Valid demo timeline lost its gateway allow");
assert(hasTimelineEvent(valid, "Dry-run action executed", "PASS"), "Valid demo timeline lost its dry-run execution");

const tampered = scenarioByName(dated, "tampered");
assert(tampered.input_classification === "forged_parent_and_unresolved_ancestry", "Tampered scenario input classification changed");
assert(tampered.expected_result === "BLOCK" && tampered.actual_result === "BLOCK", "Tampered scenario did not block");
assert(tampered.attack_probe?.status === "BLOCK", "Tampered producer parent claim did not block");
assert(tampered.attack_probe?.reason_code === "BLOCK_INVALID_PROVENANCE", "Tampered producer parent reason changed");
assert(tampered.attack_probe?.detail === "UNTRUSTED_CONTROL_FIELD", "Tampered producer parent detail changed");
assert(tampered.attack_probe?.forged_child_vertices === 0, "Tampered flow created a forged child");
assert(tampered.attack_probe?.forged_parent_vertices === 0, "Tampered flow created a forged parent");
assert(tampered.attack_probe?.edge_created === false, "Tampered flow created a forged edge");
assert(tampered.attack_probe?.producer_parent_ids_rejected === true, "Tampered flow accepted producer parent_ids");
assert(tampered.graph_assertions?.nodes === 4, "Tampered graph node count changed");
assert(tampered.graph_assertions?.edges === 3, "Tampered graph edge count changed");
assert(tampered.graph_assertions?.authenticated_witnesses === 3, "Tampered graph witness count changed");
assert(tampered.graph_assertions?.source_to_action_paths === 1, "Tampered graph path count changed");
assert(tampered.graph_assertions?.deepest_hops === 3, "Tampered full graph depth changed");
assert(tampered.graph_assertions?.authorization_depth === 2, "Tampered authorization depth changed");
assert(tampered.graph_assertions?.ancestry === "UNRESOLVED", "Tampered ancestry did not remain unresolved");
assert(JSON.stringify(tampered.graph_assertions?.edge_kinds) === JSON.stringify(["require", "summarize"]), "Tampered edge kinds changed");
assert(tampered.verification?.observation_status === "PASS", "Tampered full graph observation did not pass");
assert(tampered.verification?.bounded_status === "BLOCK", "Tampered bounded verification did not block");
assert(tampered.verification?.reason_code === "BLOCK_UNRESOLVED_ANCESTRY", "Tampered verification reason changed");
assert(tampered.verification?.detail === "DEPTH_CAP_REACHED", "Tampered verification detail changed");
assert(tampered.verification?.ancestry_status === "UNRESOLVED", "Tampered verification ancestry changed");
assert(checkByLabel(tampered, "Ancestry resolved within gateway bound").status === "BLOCK", "Tampered ancestry checklist did not block");
assert(checkByLabel(tampered, "Deterministic policy").status === "NOT_REACHED", "Tampered policy checklist was reached");
assert(tampered.policy?.status === "NOT_REACHED", "Tampered policy was evaluated");
assert(tampered.gateway?.status === "BLOCK", "Tampered gateway did not block");
assert(tampered.gateway?.reason_code === "BLOCK_UNRESOLVED_ANCESTRY", "Tampered gateway reason changed");
assert(tampered.gateway?.detail === "DEPTH_CAP_REACHED", "Tampered gateway detail changed");
assert(tampered.gateway?.adapter_calls === 0, "Tampered gateway reached the adapter");
assert(tampered.action?.executed === false, "Tampered action executed");
assert(tampered.action?.adapter_calls === 0 && tampered.action?.detail === "ACTION_NOT_EXECUTED", "Tampered adapter contract changed");
assert(tampered.action_proof?.version === "action-proof-v1", "Tampered demo action proof is missing");
assert(tampered.action_proof?.decision === tampered.gateway.status, "Tampered demo action proof decision changed");
assert(tampered.action_proof?.reason_code === tampered.gateway.reason_code, "Tampered demo action proof reason changed");
assert(tampered.action_proof?.detail === tampered.gateway.detail, "Tampered demo action proof detail changed");
assert(tampered.action_proof?.action?.type === "send_message", "Tampered demo action proof type changed");
assert(tampered.action_proof?.action?.destination === "internal:alerts", "Tampered demo action proof destination changed");
assert(tampered.action_proof?.provenance?.ancestry_status === "UNRESOLVED", "Tampered demo action proof ancestry changed");
assert(tampered.action_proof?.provenance?.source_count === 1, "Tampered demo action proof source count changed");
assert(tampered.action_proof?.provenance?.witness_count === 3, "Tampered demo action proof witness count changed");
assert(tampered.action_proof?.provenance?.independent_paths === 1, "Tampered demo action proof path count changed");
assert(tampered.action_proof?.provenance?.deepest_hops === 3, "Tampered demo action proof depth changed");
assert(tampered.action_proof?.provenance?.max_depth === 2, "Tampered demo action proof authorization bound changed");
assert(tampered.action_proof?.policy_version === "internal-message-policy-v1", "Tampered demo action proof policy changed");
assert(tampered.action_proof?.authorization_id === null, "Tampered demo action proof gained authorization identity");
assert(tampered.action_proof?.trusted_state_id === null, "Tampered demo action proof gained trusted-state identity");
assert(tampered.action_proof?.executed === false, "Tampered demo action proof execution flag changed");
assert(hasTimelineEvent(tampered, "Forged parent claim rejected", "BLOCK"), "Tampered timeline lost the forged-parent rejection");
assert(hasTimelineEvent(tampered, "Gateway verification", "BLOCK"), "Tampered timeline lost the verification block");
assert(hasTimelineEvent(tampered, "Action adapter not invoked", "BLOCK"), "Tampered timeline lost the adapter guard");

assert(dated.demo?.central_invariant?.allowed_adapter_calls === 1, "Positive flow did not reach the adapter exactly once");
assert(dated.demo?.central_invariant?.blocked_adapter_calls === 0, "Blocked flow reached the adapter");
assert(dated.demo?.central_invariant?.blocked_action_executed === false, "Blocked flow executed an action");

process.stdout.write("End-to-end demo evidence validated: 2 scenarios, PASS\n");

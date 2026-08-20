#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import {
  ACTION_GATEWAY_VERSION,
  ACTION_POLICY_VERSION,
  BLOCK_INVALID_PROVENANCE,
  BLOCK_UNRESOLVED_ANCESTRY,
  TRUSTED_STATE_CONTRACT_VERSION,
} from "../src/action-gateway.mjs";
import {
  DEMO_VERSION,
  DEMO_AUTHORIZATION_MAX_DEPTH,
  DEMO_OBSERVATION_MAX_DEPTH,
  createDemoOrchestrator,
} from "../src/demo-orchestrator.mjs";
import { PROVENANCE_STATE_VERIFIER_VERSION } from "../src/provenance-writer.mjs";

const DATED_OUTPUT = resolve(
  process.env.QUARANTINE_DEMO_OUTPUT ?? "evidence/2026-08-18-end-to-end-demo-proof.json",
);
const LATEST_OUTPUT = resolve(
  process.env.QUARANTINE_DEMO_LATEST_OUTPUT ?? "evidence/latest-end-to-end-demo-proof.json",
);

const RECORDED_AT = "2026-08-18T00:00:00.000Z";
const RUN_ID = "quarantine-demo-proof-v1";
const TRUSTED_CLOCK_MS = 2_000;
const IMAGE = process.env.HYDRA_IMAGE ?? "ghcr.io/hydra-db/hydradb:0.1.1";
const IMAGE_DIGEST = process.env.HYDRA_IMAGE_DIGEST
  ?? "sha256:db78309a233be54662db29744047e985a39b51c45a270d1a1f47c31a62cdb709";
const CONTAINER = process.env.QUARANTINE_HYDRADB_CONTAINER ?? "quarantine-hydradb";

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

function sortedKinds(edges) {
  return [...new Set(edges.map((edge) => edge.kind))].sort();
}

function checkStatuses(checks) {
  return checks.map((check) => ({
    label: check.label,
    status: check.status,
    detail: check.detail,
  }));
}

function timelineSummary(timeline) {
  return timeline.map((event) => ({
    at: event.at,
    label: event.label,
    status: event.status,
    detail: event.detail,
  }));
}

function validScenarioEvidence(response) {
  const metrics = response.graph.metrics;
  const verification = response.verification;
  const gateway = response.gateway;
  const action = response.action;
  const actionProof = response.action_proof;
  const sourceCount = verification.source_nodes.length;
  const kinds = sortedKinds(response.graph.edges);
  const nodeRoles = response.graph.nodes.map((node) => node.role).sort();

  assert(response.status === "PASS", "Valid demo response did not complete");
  assert(response.scenario === "valid", "Valid demo scenario identity changed");
  assert(gateway.status === "ALLOW", "Valid demo was not allowed");
  assert(gateway.reason_code === null, "Valid demo returned a block reason");
  assert(action.executed === true, "Valid demo action did not execute");
  assert(action.adapter_calls === 1, "Valid demo adapter did not execute exactly once");
  assert(gateway.adapter_calls === 1, "Valid gateway adapter count changed");
  assert(metrics.node_count === 5, "Valid graph node count changed");
  assert(metrics.edge_count === 4, "Valid graph edge count changed");
  assert(metrics.witness_count === 4, "Valid witness count changed");
  assert(metrics.path_count === 2, "Valid source-to-action path count changed");
  assert(metrics.deepest_hops === 2, "Valid graph depth changed");
  assert(metrics.ancestry_status === "RESOLVED", "Valid ancestry is not resolved");
  assert(metrics.max_depth === DEMO_AUTHORIZATION_MAX_DEPTH, "Valid authorization depth changed");
  assert(sourceCount === 2, "Valid trusted source count changed");
  assert(JSON.stringify(kinds) === JSON.stringify(["assert", "require", "summarize"]), "Valid edge kinds changed");
  assert(JSON.stringify(nodeRoles) === JSON.stringify(["action_argument", "claim", "source", "source", "summary"]), "Valid graph roles changed");
  assert(verification.status === "PASS", "Valid verification did not pass");
  assert(verification.observation_status === "PASS", "Valid observation did not pass");
  assert(verification.ancestry_status === "RESOLVED", "Valid verification ancestry changed");
  assert(verification.checks.every((check) => check.status === "PASS"), "Valid verification checks are not all PASS");
  assert(response.policy.status === "PASS", "Valid policy did not pass");
  assert(response.policy.result === "POLICY_ALLOW", "Valid policy result changed");
  assert(action.result?.status === "DRY_RUN", "Valid action did not use the dry-run adapter");
  assert(actionProof?.version === "action-proof-v1", "Valid action proof is missing");
  assert(actionProof.decision === gateway.status, "Valid action proof decision changed");
  assert(actionProof.reason_code === gateway.reason_code, "Valid action proof reason changed");
  assert(actionProof.detail === gateway.detail, "Valid action proof detail changed");
  assert(actionProof.action?.type === action.action_type, "Valid action proof type changed");
  assert(actionProof.action?.destination === action.destination, "Valid action proof destination changed");
  assert(actionProof.provenance?.ancestry_status === metrics.ancestry_status, "Valid action proof ancestry changed");
  assert(actionProof.provenance?.source_count === sourceCount, "Valid action proof source count changed");
  assert(actionProof.provenance?.witness_count === metrics.witness_count, "Valid action proof witness count changed");
  assert(actionProof.provenance?.independent_paths === metrics.path_count, "Valid action proof path count changed");
  assert(actionProof.provenance?.deepest_hops === metrics.deepest_hops, "Valid action proof depth changed");
  assert(actionProof.provenance?.max_depth === metrics.max_depth, "Valid action proof authorization bound changed");
  assert(actionProof.policy_version === ACTION_POLICY_VERSION, "Valid action proof policy version changed");
  assert(typeof actionProof.authorization_id === "string", "Valid action proof lost authorization identity");
  assert(typeof actionProof.trusted_state_id === "string", "Valid action proof lost trusted-state identity");
  assert(actionProof.executed === action.executed, "Valid action proof execution flag changed");

  return {
    name: "valid",
    input_classification: "trusted_graph_backed_evidence",
    expected_result: "ALLOW",
    actual_result: gateway.status,
    status: "PASS",
    evidence: response.evidence,
    graph_assertions: {
      nodes: metrics.node_count,
      edges: metrics.edge_count,
      authenticated_witnesses: metrics.witness_count,
      source_to_action_paths: metrics.path_count,
      deepest_hops: metrics.deepest_hops,
      authorization_depth: metrics.max_depth,
      ancestry: metrics.ancestry_status,
      trusted_sources: sourceCount,
      edge_kinds: kinds,
      node_roles: nodeRoles,
    },
    verification: {
      status: verification.status,
      observation_status: verification.observation_status,
      ancestry_status: verification.ancestry_status,
      reason_code: verification.reason_code,
      checks: checkStatuses(verification.checks),
    },
    policy: {
      status: response.policy.status,
      result: response.policy.result,
      reason_code: response.policy.reason_code,
    },
    gateway: {
      status: gateway.status,
      result: gateway.result,
      reason_code: gateway.reason_code,
      detail: gateway.detail,
      adapter_calls: gateway.adapter_calls,
    },
    action: {
      executed: action.executed,
      adapter_calls: action.adapter_calls,
      result: action.result?.status ?? null,
      detail: action.detail,
    },
    action_proof: actionProof,
    adapter_calls: gateway.adapter_calls,
    timeline: timelineSummary(response.timeline),
  };
}

function tamperedScenarioEvidence(response) {
  const metrics = response.graph.metrics;
  const verification = response.verification;
  const gateway = response.gateway;
  const action = response.action;
  const actionProof = response.action_proof;
  const attack = response.attack_probe;
  const kinds = sortedKinds(response.graph.edges);

  assert(response.status === "PASS", "Tampered demo orchestration did not complete");
  assert(response.scenario === "tampered", "Tampered demo scenario identity changed");
  assert(attack?.status === "BLOCK", "Forged parent probe did not block");
  assert(attack.expected_result === "BLOCK" && attack.actual_result === "BLOCK", "Forged parent probe outcome changed");
  assert(attack.reason_code === BLOCK_INVALID_PROVENANCE, "Forged parent reason code changed");
  assert(attack.detail === "UNTRUSTED_CONTROL_FIELD", "Forged parent detail changed");
  assert(attack.child_vertices === 0, "Forged child vertex was created");
  assert(attack.forged_parent_vertices === 0, "Forged parent vertex was created");
  assert(attack.edge_created === false, "Forged edge was created");
  assert(attack.producer_parent_ids_rejected === true, "Producer parent claim was not rejected");
  assert(metrics.node_count === 4, "Tampered graph node count changed");
  assert(metrics.edge_count === 3, "Tampered graph edge count changed");
  assert(metrics.witness_count === 3, "Tampered witness count changed");
  assert(metrics.path_count === 1, "Tampered source-to-action path count changed");
  assert(metrics.deepest_hops === 3, "Tampered graph depth changed");
  assert(metrics.max_depth === DEMO_AUTHORIZATION_MAX_DEPTH, "Tampered gateway depth changed");
  assert(metrics.ancestry_status === "UNRESOLVED", "Tampered ancestry did not fail closed");
  assert(JSON.stringify(kinds) === JSON.stringify(["require", "summarize"]), "Tampered edge kinds changed");
  assert(verification.observation_status === "PASS", "Tampered full graph observation did not pass");
  assert(verification.status === "BLOCK", "Tampered bounded verification did not block");
  assert(verification.reason_code === BLOCK_UNRESOLVED_ANCESTRY, "Tampered verification reason code changed");
  assert(verification.detail === "DEPTH_CAP_REACHED", "Tampered verification detail changed");
  assert(verification.ancestry_status === "UNRESOLVED", "Tampered verification ancestry changed");
  assert(verification.checks.some((check) => check.label === "Ancestry resolved within gateway bound" && check.status === "BLOCK"), "Tampered ancestry check did not block");
  assert(response.policy.status === "NOT_REACHED", "Tampered policy was evaluated");
  assert(gateway.status === "BLOCK", "Tampered action gateway did not block");
  assert(gateway.reason_code === BLOCK_UNRESOLVED_ANCESTRY, "Tampered gateway reason code changed");
  assert(gateway.detail === "DEPTH_CAP_REACHED", "Tampered gateway detail changed");
  assert(gateway.adapter_calls === 0, "Tampered gateway reached the adapter");
  assert(action.executed === false, "Tampered action executed");
  assert(action.adapter_calls === 0, "Tampered adapter call count changed");
  assert(actionProof?.version === "action-proof-v1", "Tampered action proof is missing");
  assert(actionProof.decision === gateway.status, "Tampered action proof decision changed");
  assert(actionProof.reason_code === gateway.reason_code, "Tampered action proof reason changed");
  assert(actionProof.detail === gateway.detail, "Tampered action proof detail changed");
  assert(actionProof.action?.type === action.action_type, "Tampered action proof type changed");
  assert(actionProof.action?.destination === action.destination, "Tampered action proof destination changed");
  assert(actionProof.provenance?.ancestry_status === metrics.ancestry_status, "Tampered action proof ancestry changed");
  assert(actionProof.provenance?.source_count === verification.source_nodes.length, "Tampered action proof source count changed");
  assert(actionProof.provenance?.witness_count === metrics.witness_count, "Tampered action proof witness count changed");
  assert(actionProof.provenance?.independent_paths === metrics.path_count, "Tampered action proof path count changed");
  assert(actionProof.provenance?.deepest_hops === metrics.deepest_hops, "Tampered action proof depth changed");
  assert(actionProof.provenance?.max_depth === metrics.max_depth, "Tampered action proof authorization bound changed");
  assert(actionProof.policy_version === ACTION_POLICY_VERSION, "Tampered action proof policy version changed");
  assert(actionProof.authorization_id === null, "Tampered action proof gained authorization identity");
  assert(actionProof.trusted_state_id === null, "Tampered action proof gained trusted-state identity");
  assert(actionProof.executed === action.executed, "Tampered action proof execution flag changed");

  return {
    name: "tampered",
    input_classification: "forged_parent_and_unresolved_ancestry",
    expected_result: "BLOCK",
    actual_result: gateway.status,
    status: "PASS",
    evidence: response.evidence,
    graph_assertions: {
      nodes: metrics.node_count,
      edges: metrics.edge_count,
      authenticated_witnesses: metrics.witness_count,
      source_to_action_paths: metrics.path_count,
      deepest_hops: metrics.deepest_hops,
      authorization_depth: metrics.max_depth,
      ancestry: metrics.ancestry_status,
      edge_kinds: kinds,
    },
    attack_probe: {
      status: attack.status,
      reason_code: attack.reason_code,
      detail: attack.detail,
      forged_child_vertices: attack.child_vertices,
      forged_parent_vertices: attack.forged_parent_vertices,
      edge_created: attack.edge_created,
      producer_parent_ids_rejected: attack.producer_parent_ids_rejected,
    },
    verification: {
      observation_status: verification.observation_status,
      bounded_status: verification.status,
      reason_code: verification.reason_code,
      detail: verification.detail,
      ancestry_status: verification.ancestry_status,
      frontier_artifact_id: verification.frontier_artifact_id,
      checks: checkStatuses(verification.checks),
    },
    policy: {
      status: response.policy.status,
      result: response.policy.result,
      reason_code: response.policy.reason_code,
    },
    gateway: {
      status: gateway.status,
      reason_code: gateway.reason_code,
      detail: gateway.detail,
      adapter_calls: gateway.adapter_calls,
    },
    action: {
      executed: action.executed,
      adapter_calls: action.adapter_calls,
      result: action.result?.status ?? null,
      detail: action.detail,
    },
    action_proof: actionProof,
    adapter_calls: gateway.adapter_calls,
    timeline: timelineSummary(response.timeline),
  };
}

async function main() {
  const orchestrator = createDemoOrchestrator({ now: () => TRUSTED_CLOCK_MS });
  const ready = await orchestrator.assertReady();
  const validResponse = await orchestrator.run("valid");
  const tamperedResponse = await orchestrator.run("tampered");
  const valid = validScenarioEvidence(validResponse);
  const tampered = tamperedScenarioEvidence(tamperedResponse);

  assert(orchestrator.adapter.callCount() === 1, "Blocked tampered flow changed the adapter call count");

  const report = {
    status: "PASS",
    recorded_at: RECORDED_AT,
    gate: "end_to_end_demo",
    schema_version: 1,
    run_id: RUN_ID,
    container: CONTAINER,
    image: IMAGE,
    image_digest: IMAGE_DIGEST,
    hydradb_identity: {
      source: "declared_by_pinned_start_script_and_environment",
      image: IMAGE,
      registry_digest: IMAGE_DIGEST,
    },
    hydradb: {
      http: ready.endpoint,
      admin: orchestrator.hydraConfig.adminBase,
      graph: ready.graph,
      namespace: ready.namespace,
      cell: ready.cell,
      consistency: "strong",
    },
    implementation: {
      hash_algorithm: "sha256",
      files: await implementationHashes(),
    },
    demo: {
      demo_version: DEMO_VERSION,
      trusted_clock_ms: TRUSTED_CLOCK_MS,
      gateway_version: ACTION_GATEWAY_VERSION,
      trusted_state_contract_version: TRUSTED_STATE_CONTRACT_VERSION,
      policy_version: ACTION_POLICY_VERSION,
      verifier_version: PROVENANCE_STATE_VERIFIER_VERSION,
      scenarios: ["valid", "tampered"],
      observation_max_depth: DEMO_OBSERVATION_MAX_DEPTH,
      authorization_max_depth: DEMO_AUTHORIZATION_MAX_DEPTH,
      central_invariant: {
        allowed_adapter_calls: valid.adapter_calls,
        blocked_adapter_calls: tampered.adapter_calls,
        blocked_action_executed: tampered.action.executed,
      },
    },
    scenarios: [valid, tampered],
    summary: {
      total: 2,
      passed: 2,
      failed: 0,
    },
    notes: [
      "Both scenarios execute the server-owned orchestrator against the live HydraDB client, trusted provenance writer, verifier, deterministic policy, and opaque dry-run adapter.",
      "The valid graph contains five authenticated nodes, four signed lineage witnesses, two trusted sources, two source-to-action paths, and three edge kinds.",
      "The tampered flow first rejects producer-controlled parent_ids, then blocks the authentic deep chain at the gateway ancestry cap with BLOCK_UNRESOLVED_ANCESTRY / DEPTH_CAP_REACHED.",
      "The browser submits only a whitelisted scenario name; it cannot submit trusted state, witnesses, policy results, freshness, gateway options, or an adapter.",
      "The fixed clock, fixture identifiers, and response projection make dated and latest evidence byte-identical. The clock is a proof fixture, not a wall-clock timestamp.",
    ],
  };

  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  await Promise.all([
    mkdir(dirname(DATED_OUTPUT), { recursive: true }),
    mkdir(dirname(LATEST_OUTPUT), { recursive: true }),
  ]);
  await writeFile(DATED_OUTPUT, serialized, "utf8");
  await writeFile(LATEST_OUTPUT, serialized, "utf8");
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.stdout.write(`End-to-end demo evidence written to ${DATED_OUTPUT}, ${LATEST_OUTPUT}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});

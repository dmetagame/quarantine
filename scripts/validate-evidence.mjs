#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const REQUIRED_PROVENANCE_CASES = Object.freeze([
  "forged_parent_ids_from_untrusted_output",
  "source_input_mutation_cannot_retarget_attested_write",
  "context_and_output_mutation_cannot_retarget_derived_write",
  "unknown_observed_parent",
  "existing_parent_without_valid_authenticity",
  "mixed_valid_and_forged_parents_are_atomic",
  "parent_invalidated_after_prepare_blocks_without_partial_write",
  "legitimate_parent_creates_hydrated_reverse_ancestry",
  "duplicate_parent_is_deduplicated",
  "self_parent_is_rejected",
  "immutable_artifact_rewrite_cannot_create_cycle",
  "valid_write_replay_is_idempotent",
  "client_controlled_trust_escalation_is_rejected",
  "invalid_connector_attestation_cannot_create_source",
  "staged_write_fault_is_not_valid_provenance",
  "retry_recovers_same_staged_write_idempotently",
  "parent_with_tampered_ancestry_is_rejected",
]);

const CASE_CONTRACTS = Object.freeze({
  forged_parent_ids_from_untrusted_output: ["BLOCK", "BLOCK_INVALID_PROVENANCE", "UNTRUSTED_CONTROL_FIELD"],
  source_input_mutation_cannot_retarget_attested_write: ["PASS", null, "INPUT_SNAPSHOT_PRESERVED"],
  context_and_output_mutation_cannot_retarget_derived_write: ["PASS", null, "CONTEXT_SNAPSHOT_PRESERVED"],
  unknown_observed_parent: ["BLOCK", "BLOCK_INVALID_PROVENANCE", "PARENT_NOT_AUTHENTIC"],
  existing_parent_without_valid_authenticity: ["BLOCK", "BLOCK_INVALID_PROVENANCE", "PARENT_NOT_AUTHENTIC"],
  mixed_valid_and_forged_parents_are_atomic: ["BLOCK", "BLOCK_INVALID_PROVENANCE", "PARENT_NOT_AUTHENTIC"],
  parent_invalidated_after_prepare_blocks_without_partial_write: ["BLOCK", "BLOCK_INVALID_PROVENANCE", "PARENT_NOT_AUTHENTIC"],
  legitimate_parent_creates_hydrated_reverse_ancestry: ["PASS", null, "VALID_ANCESTRY"],
  duplicate_parent_is_deduplicated: ["PASS", null, "DUPLICATE_PARENT_DEDUPLICATED"],
  self_parent_is_rejected: ["BLOCK", "BLOCK_INVALID_PROVENANCE", "SELF_PARENT"],
  immutable_artifact_rewrite_cannot_create_cycle: ["BLOCK", "BLOCK_INVALID_PROVENANCE", "ARTIFACT_IMMUTABILITY_CONFLICT"],
  valid_write_replay_is_idempotent: ["PASS", null, "WRITE_REPLAYED"],
  client_controlled_trust_escalation_is_rejected: ["BLOCK", "BLOCK_INVALID_PROVENANCE", "UNTRUSTED_CONTROL_FIELD"],
  invalid_connector_attestation_cannot_create_source: ["BLOCK", "BLOCK_INVALID_PROVENANCE", "SOURCE_ATTESTATION_INVALID"],
  staged_write_fault_is_not_valid_provenance: ["BLOCK", "BLOCK_INVALID_PROVENANCE", "HYDRADB_EDGE_WRITE_FAILED"],
  retry_recovers_same_staged_write_idempotently: ["PASS", null, "PENDING_BATCH_RECOVERED"],
  parent_with_tampered_ancestry_is_rejected: ["BLOCK", "BLOCK_INVALID_PROVENANCE", "PARENT_NOT_AUTHENTIC"],
});

const IMPLEMENTATION_FILES = Object.freeze([
  "src/hydradb-client.mjs",
  "src/provenance-writer.mjs",
  "scripts/prove-provenance-writer.mjs",
  "scripts/validate-evidence.mjs",
]);

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
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

const hydraReports = [
  ["dated HydraDB", await readJson("evidence/2026-08-17-hydradb-proof.json")],
  ["latest HydraDB", await readJson("evidence/latest-proof.json")],
];

for (const [name, report] of hydraReports) {
  assert(report.status === "PASS", `${name} evidence is not PASS`);
  assert(report.batch_throughput_probe?.verified_counts?.vertices === 512, `${name} evidence lost the 512-vertex assertion`);
  assert(report.batch_throughput_probe?.verified_counts?.relationships === 511, `${name} evidence lost the 511-relationship assertion`);
  assert(report.indexed_reverse_mspaths?.witness_count === 4, `${name} evidence lost the four-witness assertion`);
  assert(report.depth_cap?.decision === "BLOCK_UNRESOLVED_ANCESTRY", `${name} evidence lost fail-closed truncation`);
}

const [provenanceDatedText, provenanceLatestText, provenanceDated, provenanceLatest] = await Promise.all([
  readFile("evidence/2026-08-17-provenance-writer-proof.json", "utf8"),
  readFile("evidence/latest-provenance-writer-proof.json", "utf8"),
  readJson("evidence/2026-08-17-provenance-writer-proof.json"),
  readJson("evidence/latest-provenance-writer-proof.json"),
]);
assert(provenanceDatedText === provenanceLatestText, "Dated and latest provenance evidence differ");
assert(JSON.stringify(provenanceDated) === JSON.stringify(provenanceLatest), "Dated and latest provenance JSON differs");
const currentImplementationHashes = await implementationHashes();

for (const [name, report] of [["dated provenance", provenanceDated], ["latest provenance", provenanceLatest]]) {
  assert(report.status === "PASS", `${name} evidence is not PASS`);
  assert(report.gate === "trusted_provenance_writer", `${name} evidence has the wrong gate`);
  assert(report.schema_version === 2, `${name} evidence has the wrong schema version`);
  assert(Array.isArray(report.tests), `${name} evidence has no test list`);
  assert(report.implementation?.hash_algorithm === "sha256", `${name} evidence has the wrong implementation hash contract`);
  assert(
    JSON.stringify(report.implementation?.files) === JSON.stringify(currentImplementationHashes),
    `${name} evidence was not generated by the current provenance implementation`,
  );

  const names = report.tests.map((testCase) => testCase.name);
  assert(new Set(names).size === names.length, `${name} evidence contains duplicate test names`);
  for (const requiredCase of REQUIRED_PROVENANCE_CASES) {
    assert(names.includes(requiredCase), `${name} evidence is missing ${requiredCase}`);
  }
  for (const testCase of report.tests) {
    assert(testCase.status === "PASS", `${name} evidence contains a failed case: ${testCase.name}`);
    assert(testCase.actual_result === testCase.expected_result, `${name} evidence has an outcome mismatch: ${testCase.name}`);
    const contract = CASE_CONTRACTS[testCase.name];
    assert(contract, `${name} evidence contains an unknown case: ${testCase.name}`);
    assert(testCase.expected_result === contract[0], `${name} evidence has the wrong expected result: ${testCase.name}`);
    assert(testCase.reason_code === contract[1], `${name} evidence has the wrong reason code: ${testCase.name}`);
    assert(testCase.detail === contract[2], `${name} evidence has the wrong detail: ${testCase.name}`);
  }

  const recomputedFailed = report.tests.filter((testCase) => testCase.status !== "PASS").length;
  assert(report.summary?.total === report.tests.length, `${name} evidence has the wrong total count`);
  assert(report.summary?.passed === report.tests.length - recomputedFailed, `${name} evidence has the wrong passed count`);
  assert(report.summary?.failed === recomputedFailed && recomputedFailed === 0, `${name} evidence contains failed cases`);

  const byName = new Map(report.tests.map((testCase) => [testCase.name, testCase]));
  function assertGraphFields(caseName, expectedFields) {
    const testCase = byName.get(caseName);
    for (const [field, expected] of Object.entries(expectedFields)) {
      assert(testCase.graph_assertions?.[field] === expected, `${name} evidence has the wrong ${caseName}.${field}`);
    }
  }

  const forged = byName.get("forged_parent_ids_from_untrusted_output");
  assert(forged?.expected_result === "BLOCK" && forged.actual_result === "BLOCK", `${name} evidence lost the forged-parent block`);
  assert(forged.reason_code === "BLOCK_INVALID_PROVENANCE", `${name} evidence has the wrong forged-parent reason code`);
  assert(forged.detail === "UNTRUSTED_CONTROL_FIELD", `${name} evidence has the wrong forged-parent detail`);
  assert(JSON.stringify(forged.rejected_fields) === JSON.stringify(["parent_ids"]), `${name} evidence lost the rejected producer field`);
  assert(forged.input?.child_id === "child-001", `${name} evidence has the wrong forged child fixture`);
  assert(JSON.stringify(forged.input?.producer_parent_ids) === JSON.stringify(["forged-parent-001"]), `${name} evidence has the wrong forged parent fixture`);
  assert(JSON.stringify(forged.input?.middleware_parent_ids) === JSON.stringify([report.setup?.legitimate_parent]), `${name} evidence did not use a valid middleware parent context`);
  assert(forged.graph_assertions?.forged_parent_vertices === 0, `${name} evidence introduced a forged parent vertex`);
  assert(forged.graph_assertions?.child_vertices === 0, `${name} evidence introduced a forged child vertex`);
  assert(forged.graph_assertions?.direct_edges === 0, `${name} evidence introduced a forged ancestry edge`);
  assert(forged.graph_assertions?.legitimate_parent_edges === 0, `${name} evidence let producer provenance override the middleware parent set`);
  assert(forged.graph_assertions?.outgoing_child_edges === 0, `${name} evidence introduced outgoing ancestry`);
  assert(forged.graph_assertions?.reverse_witnesses_from_legitimate_parent === 0, `${name} evidence introduced an indirect trusted witness`);
  assert(forged.graph_assertions?.verification_status === "BLOCK", `${name} evidence authenticated the forged child`);
  assert(forged.graph_assertions?.verification_detail === "ARTIFACT_NOT_AUTHENTIC", `${name} evidence has the wrong forged verification verdict`);

  const sourceSnapshot = byName.get("source_input_mutation_cannot_retarget_attested_write");
  assertGraphFields(sourceSnapshot.name, {
    verifier_input_frozen: true,
    verifier_attestation_frozen: true,
    original_source_vertices: 1,
    retargeted_source_vertices: 0,
    original_authority_id: report.setup?.connector_issuer,
    committed_artifact_id: sourceSnapshot.input?.original_source_id,
  });
  assert(sourceSnapshot.graph_assertions?.original_content_hash === sha256("Attested source content before caller mutation."), `${name} evidence has the wrong source snapshot content hash`);

  const contextSnapshot = byName.get("context_and_output_mutation_cannot_retarget_derived_write");
  assertGraphFields(contextSnapshot.name, {
    original_child_vertices: 1,
    retargeted_child_vertices: 0,
    original_parent_edges: 1,
    retargeted_parent_edges: 0,
    original_role: "summary",
    original_lineage_kind: "summarize",
    committed_artifact_id: contextSnapshot.input?.original_child_id,
    original_verification_status: "PASS",
    retargeted_verification_status: "BLOCK",
    retargeted_verification_detail: "ARTIFACT_NOT_AUTHENTIC",
  });
  assert(contextSnapshot.graph_assertions?.original_content_hash === sha256("Derived content before caller mutation."), `${name} evidence has the wrong context snapshot content hash`);

  const positive = byName.get("legitimate_parent_creates_hydrated_reverse_ancestry");
  assert(positive?.expected_result === "PASS" && positive.actual_result === "PASS", `${name} evidence lost the positive control`);
  assert(positive.graph_assertions?.first_write_result === "WRITE_COMMITTED", `${name} evidence did not prove a fresh positive write`);
  assert(positive.graph_assertions?.first_write_replayed === false, `${name} evidence replayed the positive control`);
  assert(positive.graph_assertions?.parent_vertices === 1, `${name} evidence has the wrong positive parent count`);
  assert(positive.graph_assertions?.child_vertices === 1, `${name} evidence has the wrong positive child count`);
  assert(positive.graph_assertions?.child_auth_state === "committed", `${name} evidence did not commit the positive child`);
  assert(positive.graph_assertions?.direct_edges === 1, `${name} evidence has the wrong positive edge count`);
  assert(positive.graph_assertions?.edge_kind === "summarize", `${name} evidence lost DERIVES_FROM.kind`);
  assert(positive.graph_assertions?.edge_writer_id === report.writer?.writer_id, `${name} evidence has the wrong edge writer`);
  assert(typeof positive.graph_assertions?.edge_batch_id === "string" && /^[a-f0-9]{64}$/.test(positive.graph_assertions.edge_batch_id), `${name} evidence has an invalid edge batch id`);
  assert(positive.graph_assertions?.edge_write_version === 1, `${name} evidence has the wrong edge write version`);
  assert(positive.graph_assertions?.edge_auth_tag_present === true, `${name} evidence lost the edge auth tag`);
  assert(positive.graph_assertions?.reverse_witness_count === 1, `${name} evidence lost reverse ancestry traversal`);
  assert(
    JSON.stringify(positive.graph_assertions?.reverse_witnesses) === JSON.stringify([[report.setup?.legitimate_parent, positive.input?.child_id]]),
    `${name} evidence has the wrong reverse ancestry witness`,
  );
  assert(positive.graph_assertions?.verification_status === "PASS" && positive.graph_assertions?.verification_result === "PROVENANCE_VERIFIED", `${name} evidence failed positive integrity verification`);

  const mixed = byName.get("mixed_valid_and_forged_parents_are_atomic");
  assert(mixed?.expected_result === "BLOCK" && mixed.actual_result === "BLOCK", `${name} evidence lost mixed-parent atomic rejection`);
  assert(mixed.reason_code === "BLOCK_INVALID_PROVENANCE" && mixed.detail === "PARENT_NOT_AUTHENTIC", `${name} evidence has the wrong mixed-parent block`);
  for (const field of ["child_vertices", "valid_parent_edges", "forged_parent_edges", "outgoing_child_edges", "reverse_witnesses"]) {
    assert(mixed.graph_assertions?.[field] === 0, `${name} evidence partially committed mixed ancestry: ${field}`);
  }

  assertGraphFields("parent_invalidated_after_prepare_blocks_without_partial_write", {
    valid_parent_vertices: 1,
    invalidated_parent_vertices: 1,
    invalidated_parent_verification_status: "BLOCK",
    invalidated_parent_verification_detail: "ARTIFACT_NOT_AUTHENTIC",
    child_vertices: 0,
    valid_parent_edges: 0,
    invalidated_parent_edges: 0,
    outgoing_child_edges: 0,
  });

  assertGraphFields("unknown_observed_parent", {
    unknown_parent_vertices: 0,
    child_vertices: 0,
    outgoing_child_edges: 0,
  });
  assertGraphFields("existing_parent_without_valid_authenticity", {
    fake_parent_vertices: 1,
    child_vertices: 0,
    direct_edges: 0,
  });
  assertGraphFields("duplicate_parent_is_deduplicated", {
    child_vertices: 1,
    direct_edges: 1,
    outgoing_child_edges: 1,
    duplicate_parent_count: 1,
    committed_parent_count: 1,
  });
  assertGraphFields("self_parent_is_rejected", {
    child_vertices: 0,
    self_edges: 0,
  });
  assertGraphFields("immutable_artifact_rewrite_cannot_create_cycle", {
    a_to_b_edges: 0,
    b_to_a_edges: 1,
    a_outgoing_edges: 0,
  });
  assertGraphFields("client_controlled_trust_escalation_is_rejected", {
    child_vertices: 0,
    outgoing_child_edges: 0,
  });
  assertGraphFields("invalid_connector_attestation_cannot_create_source", {
    source_vertices: 0,
  });
  assertGraphFields("staged_write_fault_is_not_valid_provenance", {
    fault_injected: true,
    pending_child_vertices: 1,
    pending_child_auth_state: "pending",
    pending_child_edges: 0,
    integrity_verification_status: "BLOCK",
    integrity_verification_detail: "ARTIFACT_NOT_AUTHENTIC",
    pending_parent_prepare_status: "BLOCK",
    pending_parent_prepare_detail: "PARENT_NOT_AUTHENTIC",
    pending_consumer_vertices: 0,
  });
  assertGraphFields("retry_recovers_same_staged_write_idempotently", {
    child_vertices: 1,
    child_auth_state: "committed",
    direct_edges: 1,
    outgoing_edges: 1,
    verification_status: "PASS",
  });
  assertGraphFields("parent_with_tampered_ancestry_is_rejected", {
    parent_vertices: 1,
    parent_edges: 1,
    tampered_edge_kind: "tampered",
    parent_verification_status: "BLOCK",
    child_vertices: 0,
    child_edges: 0,
  });

  const replay = byName.get("valid_write_replay_is_idempotent");
  assert(replay?.expected_result === "PASS" && replay.actual_result === "PASS", `${name} evidence lost replay coverage`);
  assert(replay.detail === "WRITE_REPLAYED", `${name} evidence did not classify the replay`);
  assert(replay.graph_assertions?.edges_before_replay === 1, `${name} evidence has the wrong pre-replay edge count`);
  assert(replay.graph_assertions?.edges_after_first_replay === 1, `${name} evidence duplicated the first replay edge`);
  assert(replay.graph_assertions?.edges_after_second_replay === 1, `${name} evidence duplicated the second replay edge`);
  assert(replay.graph_assertions?.child_vertices === 1, `${name} evidence duplicated the replay child`);
  assert(replay.graph_assertions?.first_result === "WRITE_REPLAYED" && replay.graph_assertions?.second_result === "WRITE_REPLAYED", `${name} evidence has the wrong replay results`);
  assert(replay.graph_assertions?.first_replayed === true && replay.graph_assertions?.second_replayed === true, `${name} evidence has the wrong replay flags`);
}

assert(
  JSON.stringify(provenanceDated) === JSON.stringify(provenanceLatest),
  "Dated and latest provenance evidence are not byte-equivalent JSON reports",
);

process.stdout.write("Evidence JSON is valid and all required gate assertions are PASS.\n");

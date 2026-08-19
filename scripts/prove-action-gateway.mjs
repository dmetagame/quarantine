#!/usr/bin/env node

import {
  createHash,
  createHmac,
} from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import {
  createHydraClient,
  pathRows,
  projectedRows,
  singleScalar,
} from "../src/hydradb-client.mjs";
import {
  BLOCK_INVALID_PROVENANCE,
  BLOCK_UNRESOLVED_ANCESTRY,
  PROVENANCE_STATE_VERIFIER_VERSION,
  createProvenanceWriter,
  deriveSelector,
  deriveVertexId,
} from "../src/provenance-writer.mjs";
import {
  ACTION_GATEWAY_VERSION,
  ACTION_POLICY_VERSION,
  BLOCK_INVALID_INPUT,
  BLOCK_MISSING_PROVENANCE,
  BLOCK_POLICY,
  BLOCK_REPLAY,
  BLOCK_STALE,
  BLOCK_SYSTEM_ERROR,
  createActionGateway,
  createDryRunActionAdapter,
  TRUSTED_STATE_CONTRACT_VERSION,
  validateActionIntent,
} from "../src/action-gateway.mjs";

const outputPath = resolve(
  process.env.QUARANTINE_GATEWAY_OUTPUT
    ?? "evidence/2026-08-17-action-gateway-proof.json",
);
const latestOutputPath = resolve(
  process.env.QUARANTINE_GATEWAY_LATEST_OUTPUT
    ?? "evidence/latest-action-gateway-proof.json",
);

// The gateway proof deliberately uses fixed IDs and a fixed trusted clock. This
// makes the dated and latest artifacts byte-stable while writer retries remain
// idempotent against an already-populated local HydraDB.
const recordedAt = "2026-08-17T00:00:00.000Z";
const runId = "gateway-gate-v1";
const signingKey = process.env.QUARANTINE_PROVENANCE_SIGNING_KEY
  ?? "local-provenance-writer-test-key-2026";
const connectorKey = process.env.QUARANTINE_CONNECTOR_ATTESTATION_KEY
  ?? "local-connector-attestation-key-2026";
const connectorIssuer = "quarantine-proof-connector";
const connectorKeyId = "local-evidence-key-v1";
const container = process.env.QUARANTINE_HYDRADB_CONTAINER ?? "quarantine-hydradb";
const image = process.env.HYDRA_IMAGE ?? "ghcr.io/hydra-db/hydradb:0.1.1";
const imageDigest = process.env.HYDRA_IMAGE_DIGEST
  ?? "sha256:db78309a233be54662db29744047e985a39b51c45a270d1a1f47c31a62cdb709";

const implementationFiles = Object.freeze([
  "src/hydradb-client.mjs",
  "src/provenance-writer.mjs",
  "src/action-gateway.mjs",
  "scripts/prove-action-gateway.mjs",
  "scripts/validate-action-gateway-evidence.mjs",
]);

const ids = Object.freeze({
  trustedSource: "gateway-gate-v1:source:trusted",
  actionArgument: "gateway-gate-v1:action:argument",
  unresolvedSummary: "gateway-gate-v1:unresolved:summary",
  unresolvedArgument: "gateway-gate-v1:unresolved:argument",
  action: "gateway-gate-v1:action:send",
  subject: "gateway-gate-v1:subject",
  request: "gateway-gate-v1:request:send",
});

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function hmac(key, fields) {
  return createHmac("sha256", key).update(JSON.stringify(fields), "utf8").digest("hex");
}

function attestationMessage(source) {
  return [
    "connector-attestation-v1",
    source.id,
    sha256(source.content),
    connectorIssuer,
    connectorKeyId,
  ];
}

function attestSource(id, content) {
  const source = { id, content };
  return {
    ...source,
    attestation: {
      issuer: connectorIssuer,
      key_id: connectorKeyId,
      signature: hmac(connectorKey, attestationMessage(source)),
    },
  };
}

async function verifyTrustedSource(source) {
  if (source.attestation?.issuer !== connectorIssuer
    || source.attestation?.key_id !== connectorKeyId) {
    return false;
  }
  return source.attestation.signature === hmac(connectorKey, attestationMessage(source));
}

function baseIntent(overrides = {}) {
  return {
    action_id: ids.action,
    subject_id: ids.subject,
    action_type: "send_message",
    parameters: {
      data_class: "internal",
      destination: "internal:alerts",
      payload: "Gateway proof payload",
    },
    request_id: ids.request,
    requested_at: 1_000,
    provenance_artifact_id: ids.actionArgument,
    ...overrides,
  };
}

function fixtureVerification(intent, overrides = {}) {
  const validated = validateActionIntent(intent);
  assert(validated.status === "PASS", "Fixture intent must be valid");
  const artifactId = intent.provenance_artifact_id;
  const batchId = sha256(`gateway-fixture:batch:${artifactId}`);
  const sourceId = `gateway-fixture:${artifactId}:source`;
  return {
    status: "PASS",
    result: "PROVENANCE_STATE_VERIFIED",
    reason_code: null,
    classification: "VERIFIED",
    verifier_version: PROVENANCE_STATE_VERIFIER_VERSION,
    artifact: {
      artifact_id: artifactId,
      vertex_id: deriveVertexId(artifactId),
      role: "action_argument",
      lineage_kind: "require",
      generation: 1,
      parent_count: 1,
      terminal: false,
      content_hash: validated.semantic_digest,
      trust_state: "derived",
      authority_id: "quarantine-writer-v1",
      batch_id: batchId,
    },
    ancestry_status: "RESOLVED",
    source_nodes: [{
      artifact_id: sourceId,
      vertex_id: deriveVertexId(sourceId),
      role: "source",
      lineage_kind: "source",
      generation: 0,
      parent_count: 0,
      terminal: true,
      content_hash: sha256(`gateway-fixture:content:${sourceId}`),
      trust_state: "trusted_source",
      authority_id: connectorIssuer,
      batch_id: sha256(`gateway-fixture:source:${sourceId}`),
    }],
    witnesses: [{
      edge_id: Number.parseInt(sha256(`gateway-fixture:edge:${artifactId}`).slice(0, 12), 16),
      child_artifact_id: artifactId,
      parent_artifact_id: sourceId,
      kind: "require",
      child_generation: 1,
      parent_generation: 0,
      batch_id: batchId,
    }],
    graph_snapshot: {
      node_count: 2,
      edge_count: 1,
      deepest_hops: 1,
      max_depth: 16,
    },
    ...overrides,
  };
}

function gatewayWith(verifier, adapter = createDryRunActionAdapter(), options = {}) {
  return createActionGateway({
    verifyProvenanceState: verifier,
    actionAdapter: adapter,
    now: options.now ?? (() => 2_000),
    maxFreshnessMs: options.maxFreshnessMs ?? 100,
    maxAncestryDepth: options.maxAncestryDepth ?? 16,
    verificationTimeoutMs: options.verificationTimeoutMs ?? 5_000,
    allowedSourceAuthorities: [connectorIssuer],
  });
}

async function implementationHashes() {
  const entries = await Promise.all(implementationFiles.map(async (path) => [
    path,
    sha256(await readFile(resolve(path), "utf8")),
  ]));
  return Object.fromEntries(entries);
}

async function main() {
  const baseHydra = createHydraClient();
  await baseHydra.assertReady();
  const hydra = baseHydra;
  const writer = createProvenanceWriter({
    hydra,
    signingKey,
    verifyTrustedSource,
  });
  const failingWriter = createProvenanceWriter({
    hydra: {
      async query() {
        throw new Error("HydraDB unavailable in proof fault control");
      },
    },
    signingKey,
    verifyTrustedSource,
  });

  async function artifactCount(artifactId) {
    return singleScalar(await hydra.query(
      "MATCH (n:ProvenanceArtifact {id: $vertex_id}) RETURN count(*) AS total",
      { vertex_id: deriveVertexId(artifactId) },
    ), `artifact count for ${artifactId}`);
  }

  async function edgeCount(childId, parentId) {
    return singleScalar(await hydra.query(
      "MATCH (c:ProvenanceArtifact {id: $child_id})-[r:DERIVES_FROM]->(p) WHERE p.id = $parent_id RETURN count(*) AS total",
      { child_id: deriveVertexId(childId), parent_id: deriveVertexId(parentId) },
    ), `edge count for ${childId} -> ${parentId}`);
  }

  async function hydratedEdge(childId, parentId) {
    const response = await hydra.query(
      "MATCH (c:ProvenanceArtifact {id: $child_id})-[r:DERIVES_FROM]->(p) WHERE p.id = $parent_id RETURN r.edge_id AS edge_id, r.kind AS kind, r.batch_id AS batch_id, r.write_version AS write_version",
      { child_id: deriveVertexId(childId), parent_id: deriveVertexId(parentId) },
    );
    return projectedRows(response)[0] ?? null;
  }

  async function reverseWitnesses(sourceId, targetId) {
    const sourceSelector = deriveSelector(sourceId);
    const targetSelector = deriveSelector(targetId);
    const query = `CALL algo.MSpaths({sourceLabel: 'ProvenanceArtifact', sourceProperty: 'selector', sourceValues: ['${sourceSelector}'], targetValues: ['${targetSelector}'], pairwise: false, relTypes: ['DERIVES_FROM'], relDirection: 'incoming', maxLen: 8, pathCount: 8, resultLimit: 32}) YIELD path RETURN path`;
    return pathRows(await hydra.query(query));
  }

  const sourceSetup = await writer.registerTrustedSource(
    attestSource(ids.trustedSource, "Trusted gateway source fixture."),
  );
  assert(sourceSetup.status === "PASS", `Trusted source setup failed: ${JSON.stringify(sourceSetup)}`);

  const liveIntent = baseIntent();
  const liveValidated = validateActionIntent(liveIntent);
  assert(liveValidated.status === "PASS", "Live action fixture intent is invalid");
  const prepared = await writer.prepareTransformation({
    artifactId: ids.actionArgument,
    role: "action_argument",
    observedParentIds: [ids.trustedSource],
    kind: "require",
  });
  assert(prepared.status === "PASS", `Action argument preparation failed: ${JSON.stringify(prepared)}`);
  const argumentWrite = await writer.writeDerivedArtifact({
    context: prepared.context,
    producerOutput: { content: liveValidated.semantic_payload },
  });
  assert(argumentWrite.status === "PASS", `Action argument write failed: ${JSON.stringify(argumentWrite)}`);
  const liveVerification = await writer.verifyProvenanceState(ids.actionArgument, { maxDepth: 16 });
  assert(liveVerification.status === "PASS", `Live action argument verification failed: ${JSON.stringify(liveVerification)}`);

  const unresolvedIntent = baseIntent({
    action_id: "gateway-gate-v1:unresolved:action",
    request_id: "gateway-gate-v1:unresolved:request",
    provenance_artifact_id: ids.unresolvedArgument,
  });
  const unresolvedValidated = validateActionIntent(unresolvedIntent);
  assert(unresolvedValidated.status === "PASS", "Unresolved action fixture intent is invalid");
  const unresolvedSummaryPrepared = await writer.prepareTransformation({
    artifactId: ids.unresolvedSummary,
    role: "summary",
    observedParentIds: [ids.trustedSource],
    kind: "summarize",
  });
  assert(unresolvedSummaryPrepared.status === "PASS", "Unresolved summary preparation failed");
  const unresolvedSummaryWrite = await writer.writeDerivedArtifact({
    context: unresolvedSummaryPrepared.context,
    producerOutput: { content: "Depth-capped gateway summary fixture." },
  });
  assert(unresolvedSummaryWrite.status === "PASS", "Unresolved summary write failed");
  const unresolvedArgumentPrepared = await writer.prepareTransformation({
    artifactId: ids.unresolvedArgument,
    role: "action_argument",
    observedParentIds: [ids.unresolvedSummary],
    kind: "require",
  });
  assert(unresolvedArgumentPrepared.status === "PASS", "Unresolved action argument preparation failed");
  const unresolvedArgumentWrite = await writer.writeDerivedArtifact({
    context: unresolvedArgumentPrepared.context,
    producerOutput: { content: unresolvedValidated.semantic_payload },
  });
  assert(unresolvedArgumentWrite.status === "PASS", "Unresolved action argument write failed");
  const unresolvedFullVerification = await writer.verifyProvenanceState(ids.unresolvedArgument, { maxDepth: 16 });
  const unresolvedCappedVerification = await writer.verifyProvenanceState(ids.unresolvedArgument, { maxDepth: 1 });
  assert(unresolvedFullVerification.status === "PASS", "Full unresolved control closure did not verify");
  assert(
    unresolvedCappedVerification.status === "BLOCK"
      && unresolvedCappedVerification.reason_code === BLOCK_UNRESOLVED_ANCESTRY,
    "Depth-capped live closure did not fail closed",
  );

  const setupAssertions = {
    trusted_source_vertices: await artifactCount(ids.trustedSource),
    action_argument_vertices: await artifactCount(ids.actionArgument),
    direct_edges: await edgeCount(ids.actionArgument, ids.trustedSource),
    hydrated_edge_kind: (await hydratedEdge(ids.actionArgument, ids.trustedSource))?.kind ?? null,
    reverse_witness_count: (await reverseWitnesses(ids.trustedSource, ids.actionArgument)).length,
    verification_status: liveVerification.status,
    verification_result: liveVerification.result,
  };
  assert(setupAssertions.trusted_source_vertices === 1, "Trusted source fixture is missing");
  assert(setupAssertions.action_argument_vertices === 1, "Action argument fixture is missing");
  assert(setupAssertions.direct_edges === 1, "Action argument ancestry edge is missing");
  assert(setupAssertions.hydrated_edge_kind === "require", "Action argument edge kind did not hydrate");
  assert(setupAssertions.reverse_witness_count >= 1, "Reverse provenance witness is missing");

  const cases = [];
  async function runCase({ name, inputClassification, expectedResult, input, execute }) {
    try {
      const outcome = await execute();
      assert(outcome.actual_result === expectedResult,
        `${name}: expected ${expectedResult}, received ${outcome.actual_result}`);
      cases.push({
        name,
        input_classification: inputClassification,
        input,
        expected_result: expectedResult,
        ...outcome,
        status: "PASS",
      });
    } catch (error) {
      cases.push({
        name,
        input_classification: inputClassification,
        input,
        expected_result: expectedResult,
        actual_result: "ERROR",
        reason_code: null,
        detail: null,
        graph_assertions: {},
        error: error.message,
        status: "FAIL",
      });
    }
  }

  const forgedFieldCases = [
    ["forged_trusted_state_fields_are_rejected", "trusted_state", "forged_trusted_state"],
    ["forged_provenance_witness_is_rejected", "witnesses", "forged_provenance_witness"],
    ["forged_policy_result_is_rejected", "policy_result", "forged_policy_result"],
    ["forged_freshness_is_rejected", "fresh", "forged_freshness"],
    ["forged_verification_status_is_rejected", "verified", "forged_verification_status"],
  ];
  for (const [name, field, classification] of forgedFieldCases) {
    await runCase({
      name,
      inputClassification: "caller_controlled_trust_claim",
      expectedResult: "BLOCK",
      input: { field, attempted_value: field === "witnesses" ? [{ forged: true }] : true },
      execute: async () => {
        let verifierCalls = 0;
        const adapter = createDryRunActionAdapter();
        const gateway = gatewayWith(async () => {
          verifierCalls += 1;
          return liveVerification;
        }, adapter);
        const result = await gateway.authorizeAndExecute({
          ...liveIntent,
          action_id: `gateway-gate-v1:${classification}:action`,
          request_id: `gateway-gate-v1:${classification}:request`,
          [field]: field === "witnesses" ? [{ forged: true }] : true,
        });
        const assertions = {
          verifier_calls: verifierCalls,
          adapter_calls: adapter.callCount(),
          rejected_fields: result.rejected_fields ?? [],
        };
        assert(result.reason_code === BLOCK_INVALID_INPUT, "Forged trust claim was not invalid input");
        assert(result.detail === "UNTRUSTED_CONTROL_FIELD", "Forged trust claim detail changed");
        assert(verifierCalls === 0 && adapter.callCount() === 0, "Forged trust claim reached trusted code");
        return {
          actual_result: result.status,
          reason_code: result.reason_code,
          detail: result.detail,
          graph_assertions: assertions,
        };
      },
    });
  }

  await runCase({
    name: "direct_adapter_bypass_is_unavailable",
    inputClassification: "caller_supplied_adapter_capability",
    expectedResult: "BLOCK",
    input: { attempted_field: "adapter" },
    execute: async () => {
      let verifierCalls = 0;
      const adapter = createDryRunActionAdapter();
      const gateway = gatewayWith(async () => {
        verifierCalls += 1;
        return liveVerification;
      }, adapter);
      const result = await gateway.authorizeAndExecute({
        ...liveIntent,
        action_id: "gateway-gate-v1:direct-adapter:action",
        request_id: "gateway-gate-v1:direct-adapter:request",
        adapter,
      });
      assert(result.reason_code === BLOCK_INVALID_INPUT, "Caller-supplied adapter was not rejected");
      assert(result.detail === "UNTRUSTED_CONTROL_FIELD", "Caller-supplied adapter detail changed");
      assert(typeof adapter.execute === "undefined", "Opaque adapter exposed a direct execute method");
      assert(verifierCalls === 0 && adapter.callCount() === 0, "Direct adapter bypass reached trusted code");
      return {
        actual_result: result.status,
        reason_code: result.reason_code,
        detail: result.detail,
        graph_assertions: {
          public_execute_method: false,
          verifier_calls: verifierCalls,
          adapter_calls: adapter.callCount(),
          rejected_fields: result.rejected_fields ?? [],
        },
      };
    },
  });

  await runCase({
    name: "malformed_verified_provenance_blocks",
    inputClassification: "verifier_returned_disconnected_witness",
    expectedResult: "BLOCK",
    input: { forged_parent_artifact_id: "gateway-gate-v1:forged:parent" },
    execute: async () => {
      const intent = baseIntent({
        action_id: "gateway-gate-v1:malformed-provenance:action",
        request_id: "gateway-gate-v1:malformed-provenance:request",
        provenance_artifact_id: "gateway-gate-v1:malformed-provenance:artifact",
      });
      const adapter = createDryRunActionAdapter();
      const gateway = gatewayWith(async () => {
        const verification = fixtureVerification(intent);
        verification.witnesses[0] = {
          ...verification.witnesses[0],
          parent_artifact_id: "gateway-gate-v1:forged:parent",
        };
        return verification;
      }, adapter);
      const result = await gateway.authorizeAndExecute(intent);
      assert(result.reason_code === BLOCK_INVALID_PROVENANCE, "Malformed verified provenance was accepted");
      assert(result.detail === "MALFORMED_OR_UNBOUND_PROVENANCE", "Malformed verified provenance detail changed");
      assert(adapter.callCount() === 0, "Malformed verified provenance reached the adapter");
      return {
        actual_result: result.status,
        reason_code: result.reason_code,
        detail: result.detail,
        graph_assertions: { adapter_calls: adapter.callCount() },
      };
    },
  });

  await runCase({
    name: "legitimate_live_hydradb_action_is_allowed",
    inputClassification: "live_hydradb_verified_provenance",
    expectedResult: "ALLOW",
    input: { action_id: liveIntent.action_id, provenance_artifact_id: liveIntent.provenance_artifact_id },
    execute: async () => {
      const adapter = createDryRunActionAdapter();
      const gateway = gatewayWith(
        (artifactId, options) => writer.verifyProvenanceState(artifactId, options),
        adapter,
      );
      const result = await gateway.authorizeAndExecute(liveIntent);
      const [authorizedAction] = adapter.calls();
      const assertions = {
        adapter_calls: adapter.callCount(),
        authorized_at: authorizedAction?.authorized_at ?? null,
        verification_status: liveVerification.status,
        direct_edges: setupAssertions.direct_edges,
        reverse_witness_count: setupAssertions.reverse_witness_count,
        authorized_action_id: result.action_id ?? null,
        adapter_result: result.adapter_result?.status ?? null,
      };
      assert(result.status === "ALLOW" && result.result === "ACTION_EXECUTED", "Live action was not authorized");
      assert(adapter.callCount() === 1, "Live action did not reach dry-run adapter once");
      assert(authorizedAction?.authorized_at === 2_000, "Live action did not receive the trusted authorization timestamp");
      return {
        actual_result: result.status,
        reason_code: result.reason_code,
        detail: result.detail,
        graph_assertions: assertions,
      };
    },
  });

  await runCase({
    name: "missing_provenance_blocks",
    inputClassification: "live_hydradb_missing_graph_record",
    expectedResult: "BLOCK",
    input: { provenance_artifact_id: "gateway-gate-v1:missing:artifact" },
    execute: async () => {
      const adapter = createDryRunActionAdapter();
      const gateway = gatewayWith(
        (artifactId, options) => writer.verifyProvenanceState(artifactId, options),
        adapter,
      );
      const result = await gateway.authorizeAndExecute(baseIntent({
        action_id: "gateway-gate-v1:missing:action",
        request_id: "gateway-gate-v1:missing:request",
        provenance_artifact_id: "gateway-gate-v1:missing:artifact",
      }));
      const missingVertices = await artifactCount("gateway-gate-v1:missing:artifact");
      assert(result.reason_code === BLOCK_MISSING_PROVENANCE && adapter.callCount() === 0, "Missing provenance was not fail closed");
      assert(missingVertices === 0, "Missing provenance fixture unexpectedly exists");
      return {
        actual_result: result.status,
        reason_code: result.reason_code,
        detail: result.detail,
        graph_assertions: {
          missing_vertices: missingVertices,
          adapter_calls: adapter.callCount(),
        },
      };
    },
  });

  await runCase({
    name: "unresolved_ancestry_blocks",
    inputClassification: "live_hydradb_depth_capped_provenance",
    expectedResult: "BLOCK",
    input: { provenance_artifact_id: ids.unresolvedArgument, max_depth: 1 },
    execute: async () => {
      const adapter = createDryRunActionAdapter();
      const gateway = gatewayWith(
        (artifactId, options) => writer.verifyProvenanceState(artifactId, options),
        adapter,
        { maxAncestryDepth: 1 },
      );
      const result = await gateway.authorizeAndExecute(unresolvedIntent);
      assert(result.reason_code === BLOCK_UNRESOLVED_ANCESTRY && adapter.callCount() === 0, "Unresolved ancestry was not fail closed");
      return {
        actual_result: result.status,
        reason_code: result.reason_code,
        detail: result.detail,
        graph_assertions: {
          full_verification_status: unresolvedFullVerification.status,
          capped_verification_status: unresolvedCappedVerification.status,
          capped_verification_detail: unresolvedCappedVerification.detail,
          unresolved_argument_vertices: await artifactCount(ids.unresolvedArgument),
          unresolved_summary_vertices: await artifactCount(ids.unresolvedSummary),
          argument_to_summary_edges: await edgeCount(ids.unresolvedArgument, ids.unresolvedSummary),
          summary_to_source_edges: await edgeCount(ids.unresolvedSummary, ids.trustedSource),
          adapter_calls: adapter.callCount(),
        },
      };
    },
  });

  await runCase({
    name: "stale_trusted_state_blocks",
    inputClassification: "trusted_clock_freshness_expired",
    expectedResult: "BLOCK",
    input: { max_freshness_ms: 10, verified_at: 2_000, current_time: 2_010 },
    execute: async () => {
      const adapter = createDryRunActionAdapter();
      let clockCalls = 0;
      const gateway = gatewayWith(async () => fixtureVerification(baseIntent({
        action_id: "gateway-gate-v1:stale:action",
        request_id: "gateway-gate-v1:stale:request",
        provenance_artifact_id: "gateway-gate-v1:stale:artifact",
      })), adapter, {
        maxFreshnessMs: 10,
        now: () => (clockCalls++ === 0 ? 2_000 : 2_010),
      });
      const result = await gateway.authorizeAndExecute(baseIntent({
        action_id: "gateway-gate-v1:stale:action",
        request_id: "gateway-gate-v1:stale:request",
        provenance_artifact_id: "gateway-gate-v1:stale:artifact",
      }));
      assert(result.reason_code === BLOCK_STALE && adapter.callCount() === 0, "Stale trusted state was authorized");
      return {
        actual_result: result.status,
        reason_code: result.reason_code,
        detail: result.detail,
        graph_assertions: { adapter_calls: adapter.callCount(), trusted_clock_calls: clockCalls },
      };
    },
  });

  await runCase({
    name: "policy_violation_blocks",
    inputClassification: "external_destination_policy_violation",
    expectedResult: "BLOCK",
    input: { destination: "external:webhook", data_class: "internal" },
    execute: async () => {
      const intent = baseIntent({
        action_id: "gateway-gate-v1:policy:action",
        request_id: "gateway-gate-v1:policy:request",
        provenance_artifact_id: "gateway-gate-v1:policy:artifact",
        parameters: {
          data_class: "internal",
          destination: "external:webhook",
          payload: "Policy violation payload",
        },
      });
      const adapter = createDryRunActionAdapter();
      const gateway = gatewayWith(async () => fixtureVerification(intent), adapter);
      const result = await gateway.authorizeAndExecute(intent);
      assert(result.reason_code === BLOCK_POLICY && result.detail === "DESTINATION_NOT_ALLOWED", "Policy violation was authorized");
      return {
        actual_result: result.status,
        reason_code: result.reason_code,
        detail: result.detail,
        graph_assertions: { adapter_calls: adapter.callCount() },
      };
    },
  });

  await runCase({
    name: "replay_is_deterministic_and_adapter_runs_once",
    inputClassification: "same_request_and_action_replayed",
    expectedResult: "BLOCK",
    input: { request_id: "gateway-gate-v1:replay:request", action_id: "gateway-gate-v1:replay:action" },
    execute: async () => {
      const intent = baseIntent({
        action_id: "gateway-gate-v1:replay:action",
        request_id: "gateway-gate-v1:replay:request",
        provenance_artifact_id: "gateway-gate-v1:replay:artifact",
      });
      const adapter = createDryRunActionAdapter();
      const gateway = gatewayWith(async () => fixtureVerification(intent), adapter);
      const first = await gateway.authorizeAndExecute(intent);
      const replay = await gateway.authorizeAndExecute(intent);
      const requestConflict = await gateway.authorizeAndExecute({
        ...intent,
        action_id: "gateway-gate-v1:replay:other-action",
      });
      const actionConflict = await gateway.authorizeAndExecute({
        ...intent,
        request_id: "gateway-gate-v1:replay:other-request",
      });
      assert(first.status === "ALLOW", "Replay control first write did not authorize");
      assert(replay.reason_code === BLOCK_REPLAY && replay.detail === "REQUEST_REPLAYED", "Exact replay was not blocked deterministically");
      assert(requestConflict.reason_code === BLOCK_REPLAY && requestConflict.detail === "REQUEST_ID_CONFLICT", "Request identity conflict was not blocked");
      assert(actionConflict.reason_code === BLOCK_REPLAY && actionConflict.detail === "ACTION_ID_CONFLICT", "Action identity conflict was not blocked");
      assert(adapter.callCount() === 1, "Replay executed the adapter more than once");
      return {
        actual_result: replay.status,
        reason_code: replay.reason_code,
        detail: replay.detail,
        graph_assertions: {
          first_result: first.status,
          replay_result: replay.status,
          request_conflict_detail: requestConflict.detail,
          action_conflict_detail: actionConflict.detail,
          adapter_calls: adapter.callCount(),
        },
      };
    },
  });

  await runCase({
    name: "malformed_action_blocks_before_verification",
    inputClassification: "malformed_or_unsupported_action_intent",
    expectedResult: "BLOCK",
    input: { action_type: "send_message", malformed_parameter: true },
    execute: async () => {
      let verifierCalls = 0;
      const adapter = createDryRunActionAdapter();
      const gateway = gatewayWith(async () => {
        verifierCalls += 1;
        return liveVerification;
      }, adapter);
      const result = await gateway.authorizeAndExecute({
        ...baseIntent({
          action_id: "gateway-gate-v1:malformed:action",
          request_id: "gateway-gate-v1:malformed:request",
        }),
        parameters: {
          data_class: "internal",
          destination: "internal:alerts",
          payload: "Malformed payload",
          forged: true,
        },
      });
      assert(result.reason_code === BLOCK_INVALID_INPUT && verifierCalls === 0 && adapter.callCount() === 0, "Malformed action reached verification or adapter");
      return {
        actual_result: result.status,
        reason_code: result.reason_code,
        detail: result.detail,
        graph_assertions: { verifier_calls: verifierCalls, adapter_calls: adapter.callCount() },
      };
    },
  });

  await runCase({
    name: "hydradb_verification_failure_blocks",
    inputClassification: "injected_hydradb_query_failure",
    expectedResult: "BLOCK",
    input: { failure: "hydradb_query_throw" },
    execute: async () => {
      const adapter = createDryRunActionAdapter();
      const failureVerification = await failingWriter.verifyProvenanceState(
        "gateway-gate-v1:system:artifact",
        { maxDepth: 16 },
      );
      const gateway = gatewayWith(
        (artifactId, options) => failingWriter.verifyProvenanceState(artifactId, options),
        adapter,
      );
      const result = await gateway.authorizeAndExecute(baseIntent({
        action_id: "gateway-gate-v1:system:action",
        request_id: "gateway-gate-v1:system:request",
        provenance_artifact_id: "gateway-gate-v1:system:artifact",
      }));
      assert(result.reason_code === BLOCK_SYSTEM_ERROR && result.detail === "PROVENANCE_VERIFICATION_FAILED", "Verifier failure authorized an action");
      assert(failureVerification.classification === "SYSTEM_ERROR", "HydraDB fault did not reach verifier system classification");
      return {
        actual_result: result.status,
        reason_code: result.reason_code,
        detail: result.detail,
        graph_assertions: {
          verifier_classification: failureVerification.classification,
          adapter_calls: adapter.callCount(),
        },
      };
    },
  });

  await runCase({
    name: "verification_timeout_blocks",
    inputClassification: "stalled_trusted_verifier",
    expectedResult: "BLOCK",
    input: { verification_timeout_ms: 5 },
    execute: async () => {
      const adapter = createDryRunActionAdapter();
      const gateway = gatewayWith(() => new Promise(() => {}), adapter, {
        verificationTimeoutMs: 5,
      });
      const result = await gateway.authorizeAndExecute(baseIntent({
        action_id: "gateway-gate-v1:timeout:action",
        request_id: "gateway-gate-v1:timeout:request",
        provenance_artifact_id: "gateway-gate-v1:timeout:artifact",
      }));
      assert(
        result.reason_code === BLOCK_SYSTEM_ERROR
          && result.detail === "PROVENANCE_VERIFICATION_TIMEOUT",
        "Stalled verification did not fail closed",
      );
      assert(adapter.callCount() === 0, "Timed-out verification reached the adapter");
      return {
        actual_result: result.status,
        reason_code: result.reason_code,
        detail: result.detail,
        graph_assertions: { adapter_calls: adapter.callCount() },
      };
    },
  });

  await runCase({
    name: "blocked_actions_never_reach_adapter",
    inputClassification: "aggregate_fail_closed_adapter_guard",
    expectedResult: "BLOCK",
    input: { blocked_paths: ["missing", "unresolved", "stale", "policy", "malformed", "system_error"] },
    execute: async () => {
      const adapter = createDryRunActionAdapter();
      const missingGateway = gatewayWith(async () => ({
        status: "BLOCK",
        reason_code: BLOCK_INVALID_PROVENANCE,
        classification: "MISSING",
        detail: "ARTIFACT_NOT_FOUND",
      }), adapter);
      const unresolvedGateway = gatewayWith(async () => ({
        status: "BLOCK",
        reason_code: BLOCK_UNRESOLVED_ANCESTRY,
        classification: "UNRESOLVED",
        detail: "DEPTH_CAP_REACHED",
      }), adapter);
      const staleIntent = baseIntent({
        action_id: "gateway-gate-v1:aggregate:stale",
        request_id: "gateway-gate-v1:aggregate:stale",
        provenance_artifact_id: "gateway-gate-v1:aggregate:stale-artifact",
      });
      let staleClockCalls = 0;
      const staleGateway = gatewayWith(async () => fixtureVerification(staleIntent), adapter, {
        maxFreshnessMs: 10,
        now: () => (staleClockCalls++ === 0 ? 2_000 : 2_010),
      });
      const policyIntent = baseIntent({
        action_id: "gateway-gate-v1:aggregate:policy",
        request_id: "gateway-gate-v1:aggregate:policy",
        provenance_artifact_id: "gateway-gate-v1:aggregate:policy-artifact",
        parameters: {
          data_class: "internal",
          destination: "external:webhook",
          payload: "Aggregate policy block",
        },
      });
      const policyGateway = gatewayWith(async () => fixtureVerification(policyIntent), adapter);
      const systemGateway = gatewayWith(async () => {
        throw new Error("HydraDB unavailable");
      }, adapter);
      const results = await Promise.all([
        missingGateway.authorizeAndExecute(baseIntent({
          action_id: "gateway-gate-v1:aggregate:missing",
          request_id: "gateway-gate-v1:aggregate:missing",
          provenance_artifact_id: "gateway-gate-v1:aggregate:missing-artifact",
        })),
        unresolvedGateway.authorizeAndExecute(baseIntent({
          action_id: "gateway-gate-v1:aggregate:unresolved",
          request_id: "gateway-gate-v1:aggregate:unresolved",
          provenance_artifact_id: "gateway-gate-v1:aggregate:unresolved-artifact",
        })),
        staleGateway.authorizeAndExecute(staleIntent),
        policyGateway.authorizeAndExecute(policyIntent),
        missingGateway.authorizeAndExecute({
          ...baseIntent({
            action_id: "gateway-gate-v1:aggregate:malformed",
            request_id: "gateway-gate-v1:aggregate:malformed",
          }),
          parameters: { forged: true },
        }),
        systemGateway.authorizeAndExecute(baseIntent({
          action_id: "gateway-gate-v1:aggregate:system",
          request_id: "gateway-gate-v1:aggregate:system",
          provenance_artifact_id: "gateway-gate-v1:aggregate:system-artifact",
        })),
      ]);
      assert(results.every((result) => result.status === "BLOCK"), "An aggregate blocked path unexpectedly allowed");
      assert(adapter.callCount() === 0, "A blocked action reached the adapter");
      return {
        actual_result: "BLOCK",
        reason_code: BLOCK_MISSING_PROVENANCE,
        detail: "ADAPTER_NOT_CALLED",
        graph_assertions: {
          blocked_attempts: results.length,
          adapter_calls: adapter.callCount(),
          all_blocked: results.every((result) => result.status === "BLOCK"),
        },
      };
    },
  });

  const failed = cases.filter((testCase) => testCase.status !== "PASS");
  const report = {
    status: failed.length === 0 ? "PASS" : "FAIL",
    recorded_at: recordedAt,
    gate: "trusted_state_action_gateway",
    schema_version: 1,
    run_id: runId,
    container,
    image,
    image_digest: imageDigest,
    hydradb_identity: {
      source: "declared_by_pinned_start_script_and_environment",
      image,
      registry_digest: imageDigest,
    },
    hydradb: {
      http: hydra.config.httpBase,
      admin: hydra.config.adminBase,
      graph: hydra.config.graphId,
      namespace: hydra.config.namespace,
      cell: hydra.config.cellId,
      consistency: "strong",
    },
    implementation: {
      hash_algorithm: "sha256",
      files: await implementationHashes(),
    },
    gateway: {
      gateway_version: ACTION_GATEWAY_VERSION,
      trusted_state_contract_version: TRUSTED_STATE_CONTRACT_VERSION,
      policy_version: ACTION_POLICY_VERSION,
      verifier_version: PROVENANCE_STATE_VERIFIER_VERSION,
      verification_timeout_ms: 5_000,
      allowed_source_authorities: [connectorIssuer],
      allowed_destinations: ["internal:alerts"],
      fail_closed_reason_codes: [
        BLOCK_INVALID_INPUT,
        BLOCK_MISSING_PROVENANCE,
        BLOCK_INVALID_PROVENANCE,
        BLOCK_UNRESOLVED_ANCESTRY,
        BLOCK_POLICY,
        BLOCK_STALE,
        BLOCK_REPLAY,
        BLOCK_SYSTEM_ERROR,
      ],
    },
    setup: {
      trusted_source: ids.trustedSource,
      action_argument: ids.actionArgument,
      source_result: "READY",
      action_argument_result: "READY",
      graph_assertions: setupAssertions,
    },
    tests: cases,
    summary: {
      total: cases.length,
      passed: cases.length - failed.length,
      failed: failed.length,
    },
    notes: [
      "The positive control writes an action_argument through the trusted provenance writer and verifies it from live HydraDB before gateway authorization.",
      "The missing-record and depth-capped ancestry controls call the live writer verifier; the unresolved fixture is a signed two-hop chain that passes at depth 16 and blocks at depth 1.",
      "The gateway accepts only raw ActionIntent values; trusted state, provenance witnesses, policy decisions, freshness, and verification claims are not caller-controlled fields.",
      "The dry-run adapter is an opaque capability without a public execute method and receives an authorized immutable action only after graph verification, policy evaluation, freshness, and replay checks.",
      "HydraDB query failures, verifier exceptions, and verification timeouts are mapped to BLOCK_SYSTEM_ERROR and never authorize an action.",
      "The MVP policy uses an exact internal:alerts destination and a trusted connector-authority allowlist.",
      "Replay protection is process-local and covers both request_id and action_id; adapter response loss remains indeterminate and is not automatically retried.",
      "The fixed recorded_at value, clock, and fixture identifiers make this evidence deterministic; recorded_at is not a wall-clock execution timestamp, and local signing and connector keys are proof fixtures only.",
    ],
  };

  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  const destinations = [...new Set([outputPath, latestOutputPath])];
  for (const destination of destinations) {
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, serialized, "utf8");
  }
  process.stdout.write(serialized);
  process.stderr.write(`Action gateway evidence written to ${destinations.join(", ")}\n`);
  if (failed.length > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  process.stderr.write(`ACTION GATEWAY PROOF FAILED: ${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});

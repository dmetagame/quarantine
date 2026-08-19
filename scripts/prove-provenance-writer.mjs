#!/usr/bin/env node

import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import {
  createHydraClient,
  nodeProperty,
  pathRows,
  projectedRows,
  singleScalar,
} from "../src/hydradb-client.mjs";
import {
  BLOCK_INVALID_PROVENANCE,
  PROVENANCE_GATE_ID,
  PROVENANCE_SCHEMA_VERSION,
  PROVENANCE_WRITER_ID,
  createProvenanceWriter,
  deriveSelector,
  deriveVertexId,
} from "../src/provenance-writer.mjs";

const outputPath = resolve(
  process.env.QUARANTINE_PROVENANCE_OUTPUT
    ?? "evidence/2026-08-17-provenance-writer-proof.json",
);
const latestOutputPath = resolve(
  process.env.QUARANTINE_PROVENANCE_LATEST_OUTPUT
    ?? "evidence/latest-provenance-writer-proof.json",
);
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
const recordedAt = new Date().toISOString();
const runId = process.env.QUARANTINE_PROVENANCE_RUN_ID
  ?? sha256(`${recordedAt}:${process.pid}:${randomBytes(16).toString("hex")}`).slice(0, 16);
const prefix = `writer-gate-v2:${runId}`;
const implementationFiles = Object.freeze([
  "src/hydradb-client.mjs",
  "src/provenance-writer.mjs",
  "scripts/prove-provenance-writer.mjs",
  "scripts/validate-evidence.mjs",
]);

const ids = Object.freeze({
  legitimateParent: `${prefix}:parent:legitimate`,
  forgedClaim: "forged-parent-001",
  forgedChild: "child-001",
  unknownParent: `${prefix}:parent:does-not-exist`,
  unknownChild: `${prefix}:child:unknown`,
  fakeExistingParent: `${prefix}:parent:fake-existing`,
  fakeExistingChild: `${prefix}:child:fake-existing`,
  mixedChild: `${prefix}:child:mixed`,
  positiveChild: `${prefix}:child:positive`,
  duplicateChild: `${prefix}:child:duplicate`,
  selfChild: `${prefix}:child:self`,
  cycleA: `${prefix}:cycle:a`,
  cycleB: `${prefix}:cycle:b`,
  trustEscalationChild: `${prefix}:child:trust-escalation`,
  invalidAttestationSource: `${prefix}:source:invalid-attestation`,
  pendingChild: `${prefix}:child:pending-recovery`,
  pendingConsumer: `${prefix}:child:pending-consumer`,
  integritySource: `${prefix}:source:integrity`,
  integrityParent: `${prefix}:parent:integrity`,
  integrityChild: `${prefix}:child:integrity`,
  sourceSnapshotOriginal: `${prefix}:source:snapshot-original`,
  sourceSnapshotRetargeted: `${prefix}:source:snapshot-retargeted`,
  contextSnapshotChild: `${prefix}:child:context-snapshot`,
  contextSnapshotRetargeted: `${prefix}:child:context-retargeted`,
  revalidationParent: `${prefix}:parent:revalidation`,
  revalidationChild: `${prefix}:child:revalidation`,
});

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

async function implementationHashes() {
  const entries = await Promise.all(implementationFiles.map(async (path) => [
    path,
    sha256(await readFile(resolve(path), "utf8")),
  ]));
  return Object.fromEntries(entries);
}

function hmac(key, fields) {
  return createHmac("sha256", key).update(JSON.stringify(fields), "utf8").digest("hex");
}

function secureEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") {
    return false;
  }
  const leftBuffer = Buffer.from(left, "utf8");
  const rightBuffer = Buffer.from(right, "utf8");
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
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
  return secureEqual(
    source.attestation.signature,
    hmac(connectorKey, attestationMessage(source)),
  );
}

async function main() {
  const baseHydra = createHydraClient();
  let lastHydraError = null;
  const hydra = Object.freeze({
    ...baseHydra,
    async query(query, parameters, options) {
      try {
        const result = await baseHydra.query(query, parameters, options);
        lastHydraError = null;
        return result;
      } catch (error) {
        lastHydraError = {
          query_id: options?.queryId ?? null,
          message: error.message,
        };
        throw error;
      }
    },
  });
  const writer = createProvenanceWriter({
    hydra,
    signingKey,
    verifyTrustedSource,
  });
  await hydra.assertReady();

  async function artifactCount(artifactId) {
    const result = await hydra.query(
      "MATCH (n:ProvenanceArtifact {id: $vertex_id}) RETURN count(*) AS total",
      { vertex_id: deriveVertexId(artifactId) },
    );
    return singleScalar(result, `artifact count for ${artifactId}`);
  }

  async function artifactRecord(artifactId) {
    const result = await hydra.query(
      "MATCH (n:ProvenanceArtifact {id: $vertex_id}) RETURN n.artifact_id AS artifact_id, n.auth_state AS auth_state, n.content_hash AS content_hash, n.authority_id AS authority_id, n.role AS role, n.lineage_kind AS lineage_kind",
      { vertex_id: deriveVertexId(artifactId) },
    );
    const records = projectedRows(result);
    return records.length === 0 ? null : records[0];
  }

  async function edgeCount(childId, parentId) {
    const result = await hydra.query(
      "MATCH (c:ProvenanceArtifact {id: $child_id})-[r:DERIVES_FROM]->(p:ProvenanceArtifact {id: $parent_id}) RETURN count(*) AS total",
      {
        child_id: deriveVertexId(childId),
        parent_id: deriveVertexId(parentId),
      },
    );
    return singleScalar(result, `edge count for ${childId} -> ${parentId}`);
  }

  async function outgoingEdgeCount(childId) {
    const result = await hydra.query(
      "MATCH (c:ProvenanceArtifact {id: $child_id})-[r:DERIVES_FROM]->() RETURN count(*) AS total",
      { child_id: deriveVertexId(childId) },
    );
    return singleScalar(result, `outgoing edge count for ${childId}`);
  }

  async function hydratedEdges(childId, parentId) {
    const result = await hydra.query(
      "MATCH (c:ProvenanceArtifact {id: $child_id})-[r:DERIVES_FROM]->(p:ProvenanceArtifact {id: $parent_id}) RETURN r.edge_id AS edge_id, r.kind AS kind, r.writer_id AS writer_id, r.batch_id AS batch_id, r.write_version AS write_version, r.auth_tag AS auth_tag",
      {
        child_id: deriveVertexId(childId),
        parent_id: deriveVertexId(parentId),
      },
    );
    return projectedRows(result);
  }

  async function reverseWitnesses(sourceId, targetId, maxLen = 8) {
    const sourceSelector = deriveSelector(sourceId);
    const targetSelector = deriveSelector(targetId);
    assert(
      /^[a-f0-9]{64}$/.test(sourceSelector) && /^[a-f0-9]{64}$/.test(targetSelector),
      "Unsafe provenance selector",
    );
    const query = `CALL algo.MSpaths({sourceLabel: 'ProvenanceArtifact', sourceProperty: 'selector', sourceValues: ['${sourceSelector}'], targetValues: ['${targetSelector}'], pairwise: false, relTypes: ['DERIVES_FROM'], relDirection: 'incoming', maxLen: ${maxLen}, pathCount: 8, resultLimit: 32}) YIELD path RETURN path`;
    return pathRows(await hydra.query(query));
  }

  const cases = [];

  async function runCase({ name, inputClassification, expectedResult, input, execute }) {
    try {
      const outcome = await execute();
      assert(
        outcome.actual_result === expectedResult,
        `${name}: expected ${expectedResult}, received ${outcome.actual_result}`,
      );
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
        graph_assertions: {},
        error: error.message,
        status: "FAIL",
      });
    }
  }

  const legitimateContent = "Approved internal catalog endpoint: https://support.internal.example/upload";
  const setup = await writer.registerTrustedSource(
    attestSource(ids.legitimateParent, legitimateContent),
  );
  assert(
    setup.status === "PASS",
    `Could not establish the legitimate trusted parent fixture: setup=${JSON.stringify(setup)} last_hydra_error=${JSON.stringify(lastHydraError)}`,
  );
  assert(setup.result === "WRITE_COMMITTED" && setup.replayed === false, "Legitimate parent was not a fresh committed write");

  const forgedOverridePrepared = await writer.prepareTransformation({
    artifactId: ids.forgedChild,
    role: "summary",
    observedParentIds: [ids.legitimateParent],
    kind: "summarize",
  });
  assert(forgedOverridePrepared.status === "PASS", "Could not prepare the forged-parent override control");

  await runCase({
    name: "forged_parent_ids_from_untrusted_output",
    inputClassification: "attacker_controlled_producer_output",
    expectedResult: "BLOCK",
    input: {
      child_id: ids.forgedChild,
      middleware_parent_ids: [ids.legitimateParent],
      producer_parent_ids: [ids.forgedClaim],
    },
    execute: async () => {
      const result = await writer.writeDerivedArtifact({
        context: forgedOverridePrepared.context,
        producerOutput: {
          content: "A plausible summary that attempts to claim trusted ancestry.",
          parent_ids: [ids.forgedClaim],
        },
      });
      const verification = await writer.verifyProvenanceIntegrity(ids.forgedChild);
      const assertions = {
        forged_parent_vertices: await artifactCount(ids.forgedClaim),
        child_vertices: await artifactCount(ids.forgedChild),
        direct_edges: await edgeCount(ids.forgedChild, ids.forgedClaim),
        legitimate_parent_edges: await edgeCount(ids.forgedChild, ids.legitimateParent),
        outgoing_child_edges: await outgoingEdgeCount(ids.forgedChild),
        reverse_witnesses_from_legitimate_parent: (await reverseWitnesses(ids.legitimateParent, ids.forgedChild)).length,
        verification_status: verification.status,
        verification_detail: verification.detail,
      };
      assert(result.status === "BLOCK", "Forged parent_ids were not blocked");
      assert(result.reason_code === BLOCK_INVALID_PROVENANCE, "Forged parent_ids returned the wrong reason code");
      assert(result.detail === "UNTRUSTED_CONTROL_FIELD", "Forged parent_ids were not classified as an untrusted control field");
      assert(result.rejected_fields.length === 1 && result.rejected_fields[0] === "parent_ids", "Forged parent_ids rejection was ambiguous");
      assert(assertions.forged_parent_vertices === 0, "Forged parent vertex was introduced");
      assert(
        assertions.child_vertices === 0
          && assertions.direct_edges === 0
          && assertions.legitimate_parent_edges === 0
          && assertions.outgoing_child_edges === 0,
        "Forged provenance changed graph state",
      );
      assert(assertions.reverse_witnesses_from_legitimate_parent === 0, "Forged write created indirect trusted ancestry");
      assert(verification.status === "BLOCK" && verification.detail === "ARTIFACT_NOT_AUTHENTIC", "Forged child passed provenance verification");
      return {
        actual_result: result.status,
        reason_code: result.reason_code,
        detail: result.detail,
        rejected_fields: result.rejected_fields,
        graph_assertions: assertions,
      };
    },
  });

  await runCase({
    name: "source_input_mutation_cannot_retarget_attested_write",
    inputClassification: "caller_mutation_during_async_source_verification",
    expectedResult: "PASS",
    input: {
      original_source_id: ids.sourceSnapshotOriginal,
      attempted_source_id: ids.sourceSnapshotRetargeted,
    },
    execute: async () => {
      let releaseVerifier;
      let verifierObserved;
      const verifierGate = new Promise((resolveGate) => {
        releaseVerifier = resolveGate;
      });
      const verifierStarted = new Promise((resolveStarted) => {
        verifierObserved = resolveStarted;
      });
      const snapshotWriter = createProvenanceWriter({
        hydra,
        signingKey,
        verifyTrustedSource: async (source) => {
          const decision = verifyTrustedSource(source);
          verifierObserved(source);
          await verifierGate;
          return decision;
        },
      });
      const originalContent = "Attested source content before caller mutation.";
      const mutableSource = attestSource(ids.sourceSnapshotOriginal, originalContent);
      const registration = snapshotWriter.registerTrustedSource(mutableSource);
      const verifierInput = await verifierStarted;
      mutableSource.id = ids.sourceSnapshotRetargeted;
      mutableSource.content = "Caller-mutated source content.";
      mutableSource.attestation.issuer = "attacker-retargeted-issuer";
      mutableSource.attestation.key_id = "attacker-retargeted-key";
      mutableSource.attestation.signature = "0".repeat(64);
      releaseVerifier();

      const result = await registration;
      const originalRecord = await artifactRecord(ids.sourceSnapshotOriginal);
      const assertions = {
        verifier_input_frozen: Object.isFrozen(verifierInput),
        verifier_attestation_frozen: Object.isFrozen(verifierInput.attestation),
        original_source_vertices: await artifactCount(ids.sourceSnapshotOriginal),
        retargeted_source_vertices: await artifactCount(ids.sourceSnapshotRetargeted),
        original_content_hash: originalRecord?.content_hash ?? null,
        original_authority_id: originalRecord?.authority_id ?? null,
        committed_artifact_id: result.artifact_id,
      };
      assert(result.status === "PASS" && result.result === "WRITE_COMMITTED", "Source snapshot control did not commit");
      assert(result.artifact_id === ids.sourceSnapshotOriginal, "Caller mutation retargeted the trusted source write");
      assert(assertions.verifier_input_frozen && assertions.verifier_attestation_frozen, "Verifier received mutable source input");
      assert(assertions.original_source_vertices === 1 && assertions.retargeted_source_vertices === 0, "Source mutation created the wrong graph identity");
      assert(assertions.original_content_hash === sha256(originalContent), "Source mutation changed the attested content hash");
      assert(assertions.original_authority_id === connectorIssuer, "Source mutation changed the attested authority");
      return { actual_result: result.status, reason_code: result.reason_code, detail: "INPUT_SNAPSHOT_PRESERVED", graph_assertions: assertions };
    },
  });

  await runCase({
    name: "context_and_output_mutation_cannot_retarget_derived_write",
    inputClassification: "caller_mutation_after_signed_context_validation",
    expectedResult: "PASS",
    input: {
      original_child_id: ids.contextSnapshotChild,
      attempted_child_id: ids.contextSnapshotRetargeted,
      observed_parent_ids: [ids.legitimateParent],
    },
    execute: async () => {
      const prepared = await writer.prepareTransformation({
        artifactId: ids.contextSnapshotChild,
        role: "summary",
        observedParentIds: [ids.legitimateParent],
        kind: "summarize",
      });
      assert(prepared.status === "PASS", "Could not prepare context snapshot control");
      const mutableContext = {
        ...prepared.context,
        parent_ids: [...prepared.context.parent_ids],
      };
      const originalContent = "Derived content before caller mutation.";
      const mutableOutput = { content: originalContent };
      const write = writer.writeDerivedArtifact({
        context: mutableContext,
        producerOutput: mutableOutput,
      });

      mutableContext.artifact_id = ids.contextSnapshotRetargeted;
      mutableContext.selector = deriveSelector(ids.contextSnapshotRetargeted);
      mutableContext.role = "action_argument";
      mutableContext.kind = "require";
      mutableContext.context_id = "a".repeat(64);
      mutableContext.batch_id = "b".repeat(64);
      mutableContext.token = "c".repeat(64);
      mutableOutput.content = "Caller-mutated derived content.";

      const result = await write;
      const originalRecord = await artifactRecord(ids.contextSnapshotChild);
      const originalVerification = await writer.verifyProvenanceIntegrity(ids.contextSnapshotChild);
      const retargetedVerification = await writer.verifyProvenanceIntegrity(ids.contextSnapshotRetargeted);
      const assertions = {
        original_child_vertices: await artifactCount(ids.contextSnapshotChild),
        retargeted_child_vertices: await artifactCount(ids.contextSnapshotRetargeted),
        original_parent_edges: await edgeCount(ids.contextSnapshotChild, ids.legitimateParent),
        retargeted_parent_edges: await edgeCount(ids.contextSnapshotRetargeted, ids.legitimateParent),
        original_content_hash: originalRecord?.content_hash ?? null,
        original_role: originalRecord?.role ?? null,
        original_lineage_kind: originalRecord?.lineage_kind ?? null,
        committed_artifact_id: result.artifact_id,
        original_verification_status: originalVerification.status,
        retargeted_verification_status: retargetedVerification.status,
        retargeted_verification_detail: retargetedVerification.detail,
      };
      assert(result.status === "PASS" && result.result === "WRITE_COMMITTED", "Context snapshot control did not commit");
      assert(result.artifact_id === ids.contextSnapshotChild, "Caller mutation retargeted the derived write");
      assert(assertions.original_child_vertices === 1 && assertions.retargeted_child_vertices === 0, "Context mutation created the wrong child identity");
      assert(assertions.original_parent_edges === 1 && assertions.retargeted_parent_edges === 0, "Context mutation created unauthorized ancestry");
      assert(assertions.original_content_hash === sha256(originalContent), "Producer output mutation changed the signed content hash");
      assert(assertions.original_role === "summary" && assertions.original_lineage_kind === "summarize", "Context mutation changed signed graph properties");
      assert(originalVerification.status === "PASS", "Original context snapshot did not verify");
      assert(retargetedVerification.status === "BLOCK" && retargetedVerification.detail === "ARTIFACT_NOT_AUTHENTIC", "Retargeted context became authentic provenance");
      return { actual_result: result.status, reason_code: result.reason_code, detail: "CONTEXT_SNAPSHOT_PRESERVED", graph_assertions: assertions };
    },
  });

  await runCase({
    name: "unknown_observed_parent",
    inputClassification: "trusted_middleware_reference_to_missing_record",
    expectedResult: "BLOCK",
    input: { child_id: ids.unknownChild, observed_parent_ids: [ids.unknownParent] },
    execute: async () => {
      const result = await writer.prepareTransformation({
        artifactId: ids.unknownChild,
        role: "summary",
        observedParentIds: [ids.unknownParent],
        kind: "summarize",
      });
      const assertions = {
        unknown_parent_vertices: await artifactCount(ids.unknownParent),
        child_vertices: await artifactCount(ids.unknownChild),
        outgoing_child_edges: await outgoingEdgeCount(ids.unknownChild),
      };
      assert(result.status === "BLOCK" && result.detail === "PARENT_NOT_AUTHENTIC", "Unknown parent was not blocked");
      assert(Object.values(assertions).every((value) => value === 0), "Unknown parent attempt changed graph state");
      return { actual_result: result.status, reason_code: result.reason_code, detail: result.detail, graph_assertions: assertions };
    },
  });

  await hydra.query(
    "UNWIND $rows AS row MERGE (n {id: row.vertex_id}) SET n:ProvenanceArtifact, n.artifact_id = row.artifact_id, n.selector = row.selector, n.role = row.role, n.generation = row.generation, n.terminal = row.terminal, n.content_hash = row.content_hash, n.trust_state = row.trust_state, n.auth_state = row.auth_state, n.writer_id = row.writer_id, n.writer_key_id = row.writer_key_id, n.gate_id = row.gate_id, n.parent_count = row.parent_count, n.parent_set_hash = row.parent_set_hash, n.lineage_kind = row.lineage_kind, n.context_id = row.context_id, n.batch_id = row.batch_id, n.write_version = row.write_version, n.create_only = row.create_only, n.authority_id = row.authority_id, n.authority_proof_hash = row.authority_proof_hash, n.auth_tag = row.auth_tag",
    {
      rows: [{
        vertex_id: deriveVertexId(ids.fakeExistingParent),
        artifact_id: ids.fakeExistingParent,
        selector: deriveSelector(ids.fakeExistingParent),
        role: "source",
        generation: 0,
        terminal: true,
        content_hash: "forged",
        trust_state: "trusted_source",
        auth_state: "committed",
        writer_id: PROVENANCE_WRITER_ID,
        writer_key_id: "forged-writer-key",
        gate_id: PROVENANCE_GATE_ID,
        parent_count: 0,
        parent_set_hash: sha256("[]"),
        lineage_kind: "source",
        context_id: "forged-context",
        batch_id: "0".repeat(64),
        write_version: 1,
        create_only: "forged",
        authority_id: "attacker",
        authority_proof_hash: "forged",
        auth_tag: "forged-auth-tag",
      }],
    },
  );

  await runCase({
    name: "existing_parent_without_valid_authenticity",
    inputClassification: "existing_but_unattested_graph_record",
    expectedResult: "BLOCK",
    input: { child_id: ids.fakeExistingChild, observed_parent_ids: [ids.fakeExistingParent] },
    execute: async () => {
      const result = await writer.prepareTransformation({
        artifactId: ids.fakeExistingChild,
        role: "summary",
        observedParentIds: [ids.fakeExistingParent],
        kind: "summarize",
      });
      const assertions = {
        fake_parent_vertices: await artifactCount(ids.fakeExistingParent),
        child_vertices: await artifactCount(ids.fakeExistingChild),
        direct_edges: await edgeCount(ids.fakeExistingChild, ids.fakeExistingParent),
      };
      assert(result.status === "BLOCK" && result.detail === "PARENT_NOT_AUTHENTIC", "Unauthenticated existing parent was not blocked");
      assert(assertions.fake_parent_vertices === 1, "Authenticity fixture is missing");
      assert(assertions.child_vertices === 0 && assertions.direct_edges === 0, "Unauthenticated parent created legitimate ancestry");
      return { actual_result: result.status, reason_code: result.reason_code, detail: result.detail, graph_assertions: assertions };
    },
  });

  await runCase({
    name: "mixed_valid_and_forged_parents_are_atomic",
    inputClassification: "mixed_trusted_and_missing_parent_set",
    expectedResult: "BLOCK",
    input: { child_id: ids.mixedChild, observed_parent_ids: [ids.legitimateParent, ids.unknownParent] },
    execute: async () => {
      const result = await writer.prepareTransformation({
        artifactId: ids.mixedChild,
        role: "summary",
        observedParentIds: [ids.legitimateParent, ids.unknownParent],
        kind: "summarize",
      });
      const assertions = {
        child_vertices: await artifactCount(ids.mixedChild),
        valid_parent_edges: await edgeCount(ids.mixedChild, ids.legitimateParent),
        forged_parent_edges: await edgeCount(ids.mixedChild, ids.unknownParent),
        outgoing_child_edges: await outgoingEdgeCount(ids.mixedChild),
        reverse_witnesses: (await reverseWitnesses(ids.legitimateParent, ids.mixedChild)).length,
      };
      assert(result.status === "BLOCK" && result.detail === "PARENT_NOT_AUTHENTIC", "Mixed parent set was not blocked");
      assert(Object.values(assertions).every((value) => value === 0), "Mixed parent rejection partially committed ancestry");
      return { actual_result: result.status, reason_code: result.reason_code, detail: result.detail, graph_assertions: assertions };
    },
  });

  const revalidationParentSetup = await writer.registerTrustedSource(
    attestSource(ids.revalidationParent, "Parent that will be invalidated after context preparation."),
  );
  assert(revalidationParentSetup.status === "PASS" && revalidationParentSetup.result === "WRITE_COMMITTED", "Could not establish parent revalidation fixture");
  const revalidationPrepared = await writer.prepareTransformation({
    artifactId: ids.revalidationChild,
    role: "summary",
    observedParentIds: [ids.legitimateParent, ids.revalidationParent],
    kind: "summarize",
  });
  assert(revalidationPrepared.status === "PASS", "Could not prepare valid two-parent revalidation context");
  await hydra.query(
    "MATCH (n:ProvenanceArtifact {id: $vertex_id}) SET n.auth_tag = $auth_tag",
    {
      vertex_id: deriveVertexId(ids.revalidationParent),
      auth_tag: "tampered-after-context-preparation",
    },
  );

  await runCase({
    name: "parent_invalidated_after_prepare_blocks_without_partial_write",
    inputClassification: "valid_signed_context_with_parent_tampered_before_commit",
    expectedResult: "BLOCK",
    input: {
      child_id: ids.revalidationChild,
      observed_parent_ids: [ids.legitimateParent, ids.revalidationParent],
    },
    execute: async () => {
      const result = await writer.writeDerivedArtifact({
        context: revalidationPrepared.context,
        producerOutput: { content: "This child must not commit after a parent loses authenticity." },
      });
      const invalidParentVerification = await writer.verifyProvenanceIntegrity(ids.revalidationParent);
      const assertions = {
        valid_parent_vertices: await artifactCount(ids.legitimateParent),
        invalidated_parent_vertices: await artifactCount(ids.revalidationParent),
        invalidated_parent_verification_status: invalidParentVerification.status,
        invalidated_parent_verification_detail: invalidParentVerification.detail,
        child_vertices: await artifactCount(ids.revalidationChild),
        valid_parent_edges: await edgeCount(ids.revalidationChild, ids.legitimateParent),
        invalidated_parent_edges: await edgeCount(ids.revalidationChild, ids.revalidationParent),
        outgoing_child_edges: await outgoingEdgeCount(ids.revalidationChild),
      };
      assert(result.status === "BLOCK" && result.detail === "PARENT_NOT_AUTHENTIC", "Write did not revalidate the prepared parent set");
      assert(assertions.valid_parent_vertices === 1 && assertions.invalidated_parent_vertices === 1, "Parent revalidation fixture is incomplete");
      assert(invalidParentVerification.status === "BLOCK" && invalidParentVerification.detail === "ARTIFACT_NOT_AUTHENTIC", "Tampered parent remained authentic");
      assert(assertions.child_vertices === 0 && assertions.valid_parent_edges === 0 && assertions.invalidated_parent_edges === 0 && assertions.outgoing_child_edges === 0, "Parent revalidation failure partially committed ancestry");
      return { actual_result: result.status, reason_code: result.reason_code, detail: result.detail, graph_assertions: assertions };
    },
  });

  const positivePrepared = await writer.prepareTransformation({
    artifactId: ids.positiveChild,
    role: "summary",
    observedParentIds: [ids.legitimateParent],
    kind: "summarize",
  });
  assert(positivePrepared.status === "PASS", "Could not prepare positive control");
  const positiveOutput = { content: "Approved catalog summary." };

  await runCase({
    name: "legitimate_parent_creates_hydrated_reverse_ancestry",
    inputClassification: "trusted_middleware_observed_parent",
    expectedResult: "PASS",
    input: { child_id: ids.positiveChild, observed_parent_ids: [ids.legitimateParent] },
    execute: async () => {
      const result = await writer.writeDerivedArtifact({
        context: positivePrepared.context,
        producerOutput: positiveOutput,
      });
      const edges = await hydratedEdges(ids.positiveChild, ids.legitimateParent);
      const witnesses = await reverseWitnesses(ids.legitimateParent, ids.positiveChild);
      const verification = await writer.verifyProvenanceIntegrity(ids.positiveChild);
      const witnessKeys = witnesses.map((path) => path.nodes.map((node) => nodeProperty(node, "artifact_id")));
      const assertions = {
        first_write_result: result.result,
        first_write_replayed: result.replayed,
        parent_vertices: await artifactCount(ids.legitimateParent),
        child_vertices: await artifactCount(ids.positiveChild),
        child_auth_state: (await artifactRecord(ids.positiveChild))?.auth_state ?? null,
        direct_edges: edges.length,
        edge_kind: edges.length === 1 ? edges[0].kind : null,
        edge_writer_id: edges.length === 1 ? edges[0].writer_id : null,
        edge_batch_id: edges.length === 1 ? edges[0].batch_id : null,
        edge_write_version: edges.length === 1 ? edges[0].write_version : null,
        edge_auth_tag_present: edges.length === 1 && typeof edges[0].auth_tag === "string",
        reverse_witness_count: witnesses.length,
        reverse_witnesses: witnessKeys,
        verification_status: verification.status,
        verification_result: verification.result,
      };
      assert(result.status === "PASS" && result.result === "WRITE_COMMITTED" && result.replayed === false, "Legitimate control was not a fresh commit");
      assert(assertions.parent_vertices === 1 && assertions.child_vertices === 1, "Legitimate vertices were not persisted");
      assert(assertions.child_auth_state === "committed", "Legitimate child was not committed");
      assert(assertions.direct_edges === 1, "Legitimate DERIVES_FROM edge was not persisted exactly once");
      assert(assertions.edge_kind === "summarize", "DERIVES_FROM.kind did not survive hydration");
      assert(assertions.edge_writer_id === PROVENANCE_WRITER_ID && assertions.edge_auth_tag_present, "Edge authenticity properties did not survive hydration");
      assert(assertions.edge_batch_id === positivePrepared.context.batch_id && assertions.edge_write_version === 1, "Edge batch commitment did not survive hydration");
      assert(assertions.reverse_witness_count === 1, "Reverse MSpaths did not recover legitimate ancestry");
      assert(JSON.stringify(assertions.reverse_witnesses[0]) === JSON.stringify([ids.legitimateParent, ids.positiveChild]), "Reverse witness endpoints are wrong");
      assert(verification.status === "PASS" && verification.result === "PROVENANCE_VERIFIED", "Legitimate ancestry failed integrity verification");
      return { actual_result: result.status, reason_code: result.reason_code, detail: "VALID_ANCESTRY", graph_assertions: assertions };
    },
  });

  await runCase({
    name: "duplicate_parent_is_deduplicated",
    inputClassification: "trusted_duplicate_parent_reference",
    expectedResult: "PASS",
    input: { child_id: ids.duplicateChild, observed_parent_ids: [ids.legitimateParent, ids.legitimateParent] },
    execute: async () => {
      const prepared = await writer.prepareTransformation({
        artifactId: ids.duplicateChild,
        role: "summary",
        observedParentIds: [ids.legitimateParent, ids.legitimateParent],
        kind: "summarize",
      });
      assert(prepared.status === "PASS" && prepared.duplicate_parent_count === 1, "Duplicate parent was not deterministically normalized");
      const result = await writer.writeDerivedArtifact({
        context: prepared.context,
        producerOutput: { content: "Duplicate input control." },
      });
      const assertions = {
        child_vertices: await artifactCount(ids.duplicateChild),
        direct_edges: await edgeCount(ids.duplicateChild, ids.legitimateParent),
        outgoing_child_edges: await outgoingEdgeCount(ids.duplicateChild),
        duplicate_parent_count: prepared.duplicate_parent_count,
        committed_parent_count: prepared.context.parent_count,
      };
      assert(result.status === "PASS" && result.result === "WRITE_COMMITTED", "Duplicate parent input was not handled deterministically");
      assert(assertions.child_vertices === 1 && assertions.direct_edges === 1 && assertions.outgoing_child_edges === 1, "Duplicate parent created duplicate graph state");
      return { actual_result: result.status, reason_code: result.reason_code, detail: "DUPLICATE_PARENT_DEDUPLICATED", graph_assertions: assertions };
    },
  });

  await runCase({
    name: "self_parent_is_rejected",
    inputClassification: "self_referential_ancestry",
    expectedResult: "BLOCK",
    input: { child_id: ids.selfChild, observed_parent_ids: [ids.selfChild] },
    execute: async () => {
      const result = await writer.prepareTransformation({
        artifactId: ids.selfChild,
        role: "summary",
        observedParentIds: [ids.selfChild],
        kind: "summarize",
      });
      const assertions = {
        child_vertices: await artifactCount(ids.selfChild),
        self_edges: await edgeCount(ids.selfChild, ids.selfChild),
      };
      assert(result.status === "BLOCK" && result.detail === "SELF_PARENT", "Self-parent input was not blocked");
      assert(Object.values(assertions).every((value) => value === 0), "Self-parent rejection changed graph state");
      return { actual_result: result.status, reason_code: result.reason_code, detail: result.detail, graph_assertions: assertions };
    },
  });

  const cycleASetup = await writer.registerTrustedSource(attestSource(ids.cycleA, "Cycle source A."));
  assert(cycleASetup.status === "PASS" && cycleASetup.result === "WRITE_COMMITTED", "Could not establish cycle source A");
  const cycleBPrepared = await writer.prepareTransformation({
    artifactId: ids.cycleB,
    role: "summary",
    observedParentIds: [ids.cycleA],
    kind: "summarize",
  });
  assert(cycleBPrepared.status === "PASS", "Could not prepare cycle child B");
  const cycleBSetup = await writer.writeDerivedArtifact({
    context: cycleBPrepared.context,
    producerOutput: { content: "Cycle child B." },
  });
  assert(cycleBSetup.status === "PASS" && cycleBSetup.result === "WRITE_COMMITTED", "Could not establish cycle child B");

  await runCase({
    name: "immutable_artifact_rewrite_cannot_create_cycle",
    inputClassification: "cycle_attempt_against_committed_artifact",
    expectedResult: "BLOCK",
    input: { existing_artifact_id: ids.cycleA, attempted_parent_ids: [ids.cycleB] },
    execute: async () => {
      const prepared = await writer.prepareTransformation({
        artifactId: ids.cycleA,
        role: "summary",
        observedParentIds: [ids.cycleB],
        kind: "summarize",
      });
      assert(prepared.status === "PASS", "Cycle rewrite context was not prepared for the immutability control");
      const result = await writer.writeDerivedArtifact({
        context: prepared.context,
        producerOutput: { content: "Attempt to rewrite A beneath B." },
      });
      const assertions = {
        a_to_b_edges: await edgeCount(ids.cycleA, ids.cycleB),
        b_to_a_edges: await edgeCount(ids.cycleB, ids.cycleA),
        a_outgoing_edges: await outgoingEdgeCount(ids.cycleA),
      };
      assert(result.status === "BLOCK" && result.detail === "ARTIFACT_IMMUTABILITY_CONFLICT", "Committed artifact rewrite was not blocked");
      assert(assertions.a_to_b_edges === 0 && assertions.b_to_a_edges === 1 && assertions.a_outgoing_edges === 0, "Cycle attempt changed committed ancestry");
      return { actual_result: result.status, reason_code: result.reason_code, detail: result.detail, graph_assertions: assertions };
    },
  });

  await runCase({
    name: "valid_write_replay_is_idempotent",
    inputClassification: "identical_trusted_write_replayed_twice",
    expectedResult: "PASS",
    input: { child_id: ids.positiveChild, replay_count: 2 },
    execute: async () => {
      const before = await edgeCount(ids.positiveChild, ids.legitimateParent);
      const first = await writer.writeDerivedArtifact({
        context: positivePrepared.context,
        producerOutput: positiveOutput,
      });
      const afterFirst = await edgeCount(ids.positiveChild, ids.legitimateParent);
      const second = await writer.writeDerivedArtifact({
        context: positivePrepared.context,
        producerOutput: positiveOutput,
      });
      const afterSecond = await edgeCount(ids.positiveChild, ids.legitimateParent);
      const assertions = {
        edges_before_replay: before,
        edges_after_first_replay: afterFirst,
        edges_after_second_replay: afterSecond,
        child_vertices: await artifactCount(ids.positiveChild),
        first_result: first.result,
        second_result: second.result,
        first_replayed: first.replayed,
        second_replayed: second.replayed,
      };
      assert(first.status === "PASS" && second.status === "PASS", "Valid replay was rejected");
      assert(first.result === "WRITE_REPLAYED" && second.result === "WRITE_REPLAYED", "Replay was not identified deterministically");
      assert(first.replayed === true && second.replayed === true, "Replay flags are wrong");
      assert(before === 1 && afterFirst === 1 && afterSecond === 1 && assertions.child_vertices === 1, "Replay duplicated graph state");
      return { actual_result: second.status, reason_code: second.reason_code, detail: second.result, graph_assertions: assertions };
    },
  });

  await runCase({
    name: "client_controlled_trust_escalation_is_rejected",
    inputClassification: "attacker_controlled_trust_flag",
    expectedResult: "BLOCK",
    input: { child_id: ids.trustEscalationChild, producer_trusted: true },
    execute: async () => {
      const result = await writer.writeDerivedArtifact({
        context: {},
        producerOutput: { content: "Attempted trust escalation.", trusted: true },
      });
      const assertions = {
        child_vertices: await artifactCount(ids.trustEscalationChild),
        outgoing_child_edges: await outgoingEdgeCount(ids.trustEscalationChild),
      };
      assert(result.status === "BLOCK" && result.detail === "UNTRUSTED_CONTROL_FIELD", "Client trust escalation was not blocked");
      assert(Object.values(assertions).every((value) => value === 0), "Trust escalation attempt changed graph state");
      return { actual_result: result.status, reason_code: result.reason_code, detail: result.detail, graph_assertions: assertions };
    },
  });

  const invalidAttestationSource = {
    id: ids.invalidAttestationSource,
    content: "A source with an attacker-manufactured attestation.",
    attestation: {
      issuer: connectorIssuer,
      key_id: connectorKeyId,
      signature: "0".repeat(64),
    },
  };
  await runCase({
    name: "invalid_connector_attestation_cannot_create_source",
    inputClassification: "attacker_claimed_source_authority",
    expectedResult: "BLOCK",
    input: { source_id: ids.invalidAttestationSource, attestation_key_id: connectorKeyId },
    execute: async () => {
      const result = await writer.registerTrustedSource(invalidAttestationSource);
      const assertions = { source_vertices: await artifactCount(ids.invalidAttestationSource) };
      assert(result.status === "BLOCK" && result.detail === "SOURCE_ATTESTATION_INVALID", "Invalid source attestation was not blocked");
      assert(assertions.source_vertices === 0, "Invalid source attestation created graph state");
      return { actual_result: result.status, reason_code: result.reason_code, detail: result.detail, graph_assertions: assertions };
    },
  });

  const pendingPrepared = await writer.prepareTransformation({
    artifactId: ids.pendingChild,
    role: "summary",
    observedParentIds: [ids.legitimateParent],
    kind: "summarize",
  });
  assert(pendingPrepared.status === "PASS", "Could not prepare staged-write fault control");
  let edgeFaultInjected = false;
  const faultHydra = {
    async query(query, parameters, options = {}) {
      if (!edgeFaultInjected && options.queryId?.endsWith(".edges")) {
        edgeFaultInjected = true;
        throw new Error("INJECTED_EDGE_WRITE_FAILURE");
      }
      return hydra.query(query, parameters, options);
    },
  };
  const faultWriter = createProvenanceWriter({
    hydra: faultHydra,
    signingKey,
    verifyTrustedSource,
  });

  await runCase({
    name: "staged_write_fault_is_not_valid_provenance",
    inputClassification: "injected_failure_after_pending_child_stage",
    expectedResult: "BLOCK",
    input: { child_id: ids.pendingChild, fault_phase: "before_edge_batch" },
    execute: async () => {
      const result = await faultWriter.writeDerivedArtifact({
        context: pendingPrepared.context,
        producerOutput: { content: "Pending child recovery control." },
      });
      const pendingRecord = await artifactRecord(ids.pendingChild);
      const verification = await writer.verifyProvenanceIntegrity(ids.pendingChild);
      const consumerPrepared = await writer.prepareTransformation({
        artifactId: ids.pendingConsumer,
        role: "summary",
        observedParentIds: [ids.pendingChild],
        kind: "summarize",
      });
      const assertions = {
        fault_injected: edgeFaultInjected,
        pending_child_vertices: await artifactCount(ids.pendingChild),
        pending_child_auth_state: pendingRecord?.auth_state ?? null,
        pending_child_edges: await outgoingEdgeCount(ids.pendingChild),
        integrity_verification_status: verification.status,
        integrity_verification_detail: verification.detail,
        pending_parent_prepare_status: consumerPrepared.status,
        pending_parent_prepare_detail: consumerPrepared.detail,
        pending_consumer_vertices: await artifactCount(ids.pendingConsumer),
      };
      assert(result.status === "BLOCK" && result.detail === "HYDRADB_EDGE_WRITE_FAILED", "Injected write fault did not fail closed");
      assert(assertions.fault_injected && assertions.pending_child_vertices === 1, "Pending stage fixture was not created");
      assert(assertions.pending_child_auth_state === "pending" && assertions.pending_child_edges === 0, "Failed stage became valid ancestry");
      assert(verification.status === "BLOCK", "Pending child passed integrity verification");
      assert(consumerPrepared.status === "BLOCK" && consumerPrepared.detail === "PARENT_NOT_AUTHENTIC", "Pending child was accepted as a parent");
      assert(assertions.pending_consumer_vertices === 0, "Pending parent attempt created a consumer");
      return { actual_result: result.status, reason_code: result.reason_code, detail: result.detail, graph_assertions: assertions };
    },
  });

  await runCase({
    name: "retry_recovers_same_staged_write_idempotently",
    inputClassification: "trusted_retry_of_identical_pending_batch",
    expectedResult: "PASS",
    input: { child_id: ids.pendingChild, batch_id: pendingPrepared.context.batch_id },
    execute: async () => {
      const result = await writer.writeDerivedArtifact({
        context: pendingPrepared.context,
        producerOutput: { content: "Pending child recovery control." },
      });
      const verification = await writer.verifyProvenanceIntegrity(ids.pendingChild);
      const assertions = {
        child_vertices: await artifactCount(ids.pendingChild),
        child_auth_state: (await artifactRecord(ids.pendingChild))?.auth_state ?? null,
        direct_edges: await edgeCount(ids.pendingChild, ids.legitimateParent),
        outgoing_edges: await outgoingEdgeCount(ids.pendingChild),
        verification_status: verification.status,
      };
      assert(result.status === "PASS" && result.result === "WRITE_COMMITTED" && result.replayed === false, "Pending batch retry did not recover as one commit");
      assert(assertions.child_vertices === 1 && assertions.child_auth_state === "committed", "Retry did not commit the staged child");
      assert(assertions.direct_edges === 1 && assertions.outgoing_edges === 1, "Retry created missing or duplicate ancestry");
      assert(verification.status === "PASS", "Recovered ancestry failed verification");
      return { actual_result: result.status, reason_code: result.reason_code, detail: "PENDING_BATCH_RECOVERED", graph_assertions: assertions };
    },
  });

  const integritySourceSetup = await writer.registerTrustedSource(
    attestSource(ids.integritySource, "Integrity closure source."),
  );
  assert(integritySourceSetup.status === "PASS" && integritySourceSetup.result === "WRITE_COMMITTED", "Could not create integrity source");
  const integrityParentPrepared = await writer.prepareTransformation({
    artifactId: ids.integrityParent,
    role: "claim",
    observedParentIds: [ids.integritySource],
    kind: "assert",
  });
  assert(integrityParentPrepared.status === "PASS", "Could not prepare integrity parent");
  const integrityParentSetup = await writer.writeDerivedArtifact({
    context: integrityParentPrepared.context,
    producerOutput: { content: "Integrity parent claim." },
  });
  assert(integrityParentSetup.status === "PASS" && integrityParentSetup.result === "WRITE_COMMITTED", "Could not create integrity parent");
  await hydra.query(
    "MATCH (c:ProvenanceArtifact {id: $child_id})-[r:DERIVES_FROM]->(p:ProvenanceArtifact {id: $parent_id}) SET r.kind = $kind",
    {
      child_id: deriveVertexId(ids.integrityParent),
      parent_id: deriveVertexId(ids.integritySource),
      kind: "tampered",
    },
  );

  await runCase({
    name: "parent_with_tampered_ancestry_is_rejected",
    inputClassification: "signed_parent_node_with_mutated_lineage_edge",
    expectedResult: "BLOCK",
    input: { child_id: ids.integrityChild, observed_parent_ids: [ids.integrityParent] },
    execute: async () => {
      const result = await writer.prepareTransformation({
        artifactId: ids.integrityChild,
        role: "summary",
        observedParentIds: [ids.integrityParent],
        kind: "summarize",
      });
      const verification = await writer.verifyProvenanceIntegrity(ids.integrityParent);
      const assertions = {
        parent_vertices: await artifactCount(ids.integrityParent),
        parent_edges: await outgoingEdgeCount(ids.integrityParent),
        tampered_edge_kind: (await hydratedEdges(ids.integrityParent, ids.integritySource))[0]?.kind ?? null,
        parent_verification_status: verification.status,
        child_vertices: await artifactCount(ids.integrityChild),
        child_edges: await outgoingEdgeCount(ids.integrityChild),
      };
      assert(result.status === "BLOCK" && result.detail === "PARENT_NOT_AUTHENTIC", "Tampered ancestor edge was trusted through its signed node");
      assert(assertions.parent_vertices === 1 && assertions.parent_edges === 1 && assertions.tampered_edge_kind === "tampered", "Tamper fixture was not present");
      assert(verification.status === "BLOCK", "Tampered parent passed closure verification");
      assert(assertions.child_vertices === 0 && assertions.child_edges === 0, "Tampered parent created downstream ancestry");
      return { actual_result: result.status, reason_code: result.reason_code, detail: result.detail, graph_assertions: assertions };
    },
  });

  const failed = cases.filter((testCase) => testCase.status === "FAIL");
  const report = {
    status: failed.length === 0 ? "PASS" : "FAIL",
    recorded_at: recordedAt,
    gate: "trusted_provenance_writer",
    schema_version: 2,
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
    writer: {
      writer_id: PROVENANCE_WRITER_ID,
      gate_id: PROVENANCE_GATE_ID,
      provenance_schema_version: PROVENANCE_SCHEMA_VERSION,
      invalid_reason_code: BLOCK_INVALID_PROVENANCE,
      lineage_direction: "child_to_parent",
      authenticity: "connector_attestation_plus_server_hmac_over_batch_bound_node_and_edge_properties",
      producer_control_fields: ["content"],
      middleware_control_fields: ["artifactId", "role", "observedParentIds", "kind"],
      pending_nodes_are_valid_parents: false,
    },
    setup: {
      legitimate_parent: ids.legitimateParent,
      legitimate_parent_status: setup.status,
      legitimate_parent_result: setup.result,
      connector_issuer: connectorIssuer,
      connector_key_id: connectorKeyId,
    },
    tests: cases,
    summary: {
      total: cases.length,
      passed: cases.length - failed.length,
      failed: failed.length,
    },
    notes: [
      "The producer payload is rejected if it contains lineage, trust, verification, source, confidence, or authority fields.",
      "Source, transformation-context, parent-array, and producer inputs are snapshotted before the first asynchronous boundary; live mutation controls verify that writes cannot be retargeted after validation starts.",
      "Observed parents are resolved and their complete signed ancestry is verified before any mutation statement.",
      "A signed pending child is not authentic provenance and cannot be used as a parent.",
      "The fault control injects failure after child staging and before the edge batch; the pending child blocks as a parent and the exact signed batch then retries successfully.",
      "Response-loss faults after successful edge or commit writes and independent multi-process writer races are not covered by this evidence artifact.",
      "Committed artifact identifiers are immutable under the current single-writer process boundary, and generation must increase monotonically.",
      "The connector and writer keys in this proof are local evidence fixtures only; production keys must remain outside producer/model access.",
      "The image digest is declared from the same pinned configuration used by the HydraDB launcher; container registry identity is checked separately during release validation.",
    ],
  };

  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  const destinations = [...new Set([outputPath, latestOutputPath])];
  for (const destination of destinations) {
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, serialized, "utf8");
  }
  process.stdout.write(serialized);
  process.stderr.write(`Provenance writer evidence written to ${destinations.join(", ")}\n`);

  if (failed.length > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  process.stderr.write(`PROVENANCE PROOF FAILED: ${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});

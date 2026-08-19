import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  BLOCK_INVALID_PROVENANCE,
  createProvenanceWriter,
  deriveSelector,
  deriveVertexId,
} from "../src/provenance-writer.mjs";

const signingKey = "unit-test-provenance-signing-key-32-bytes";

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function encodedCell(value) {
  if (value === null || value === undefined) {
    return { type: "null" };
  }
  if (typeof value === "boolean") {
    return { type: "boolean", value };
  }
  if (typeof value === "number") {
    return { type: Number.isInteger(value) ? "integer" : "float", value };
  }
  return { type: "string", value };
}

function projectedResponse(query, bindings, includeRow) {
  const returnIndex = query.indexOf(" RETURN ");
  assert.notEqual(returnIndex, -1, `Missing projection in unit query: ${query}`);
  const projections = query.slice(returnIndex + " RETURN ".length).split(", ");
  const parsed = projections.map((projection) => {
    const match = /^([a-z])\.([A-Za-z0-9_]+) AS ([A-Za-z0-9_]+)$/.exec(projection);
    assert(match, `Unsupported unit projection: ${projection}`);
    return { binding: match[1], property: match[2], alias: match[3] };
  });
  return {
    columns: parsed.map(({ alias }) => alias),
    rows: includeRow
      ? [parsed.map(({ binding, property }) => encodedCell(bindings[binding]?.[property]))]
      : [],
  };
}

function createMemoryHydra() {
  const nodes = new Map();
  let failChildStage = false;
  let stagedChild = null;

  return {
    hydra: {
      async query(query, parameters) {
        if (query.startsWith("MATCH (n:ProvenanceArtifact {id: $vertex_id}) RETURN ")) {
          const node = nodes.get(parameters.vertex_id);
          return projectedResponse(query, { n: node }, Boolean(node));
        }
        if (query.startsWith("MATCH (c:ProvenanceArtifact {id: $vertex_id})-[r:DERIVES_FROM]")) {
          return projectedResponse(query, {}, false);
        }
        if (query.includes("MERGE (n {id: row.vertex_id})")) {
          for (const row of parameters.rows) {
            nodes.set(row.vertex_id, { ...row, id: row.vertex_id });
          }
          return { rows: [] };
        }
        if (query.includes("MERGE (c {id: row.vertex_id})")) {
          stagedChild = structuredClone(parameters.rows[0]);
          if (failChildStage) {
            throw new Error("STOP_AFTER_CHILD_SNAPSHOT");
          }
          for (const row of parameters.rows) {
            nodes.set(row.vertex_id, { ...row, id: row.vertex_id });
          }
          return { rows: [] };
        }
        throw new Error(`Unexpected unit HydraDB query: ${query}`);
      },
    },
    nodes,
    failNextChildStage() {
      failChildStage = true;
    },
    get stagedChild() {
      return stagedChild;
    },
  };
}

function noQueryHydra() {
  let queryCount = 0;
  return {
    hydra: {
      async query() {
        queryCount += 1;
        throw new Error("Untrusted producer fields must be rejected before HydraDB access");
      },
    },
    get queryCount() {
      return queryCount;
    },
  };
}

test("forged parent_ids are rejected before any graph access", async () => {
  const fixture = noQueryHydra();
  const writer = createProvenanceWriter({
    hydra: fixture.hydra,
    signingKey,
    verifyTrustedSource: async () => false,
  });

  const result = await writer.writeDerivedArtifact({
    context: {},
    producerOutput: {
      content: "Attacker-controlled output.",
      parent_ids: ["forged-parent-001"],
    },
  });

  assert.equal(result.status, "BLOCK");
  assert.equal(result.reason_code, BLOCK_INVALID_PROVENANCE);
  assert.equal(result.detail, "UNTRUSTED_CONTROL_FIELD");
  assert.deepEqual(result.rejected_fields, ["parent_ids"]);
  assert.equal(fixture.queryCount, 0);
});

for (const field of ["id", "role", "parentIds", "source", "verified", "trusted", "confidence", "provenance", "ancestry", "authority"]) {
  test(`producer-controlled ${field} is rejected before graph access`, async () => {
    const fixture = noQueryHydra();
    const writer = createProvenanceWriter({
      hydra: fixture.hydra,
      signingKey,
      verifyTrustedSource: async () => false,
    });
    const producerOutput = {
      content: "Attacker-controlled output.",
      [field]: true,
    };

    const result = await writer.writeDerivedArtifact({
      context: {},
      producerOutput,
    });

    assert.equal(result.status, "BLOCK");
    assert.equal(result.reason_code, BLOCK_INVALID_PROVENANCE);
    assert.equal(result.detail, "UNTRUSTED_CONTROL_FIELD");
    assert.deepEqual(result.rejected_fields, [field]);
    assert.equal(fixture.queryCount, 0);
  });
}

test("trusted source input is snapshotted before asynchronous verification", async () => {
  const fixture = createMemoryHydra();
  let releaseVerifier;
  let verifierStarted;
  const verifierGate = new Promise((resolve) => {
    releaseVerifier = resolve;
  });
  const verifierObserved = new Promise((resolve) => {
    verifierStarted = resolve;
  });
  const writer = createProvenanceWriter({
    hydra: fixture.hydra,
    signingKey,
    verifyTrustedSource: async (source) => {
      verifierStarted(source);
      await verifierGate;
      return true;
    },
  });
  const original = {
    id: "source-original",
    content: "Original connector content.",
    attestation: {
      issuer: "connector-original",
      key_id: "key-original",
      signature: "signature-original",
    },
  };

  const registration = writer.registerTrustedSource(original);
  const verifierInput = await verifierObserved;
  original.id = "source-retargeted";
  original.content = "Mutated after verification started.";
  original.attestation.issuer = "connector-retargeted";
  original.attestation.key_id = "key-retargeted";
  original.attestation.signature = "signature-retargeted";
  releaseVerifier();

  const result = await registration;
  assert.equal(result.status, "PASS");
  assert.equal(result.artifact_id, "source-original");
  assert.equal(Object.isFrozen(verifierInput), true);
  assert.equal(Object.isFrozen(verifierInput.attestation), true);
  const stored = fixture.nodes.get(deriveVertexId("source-original"));
  assert.equal(stored.artifact_id, "source-original");
  assert.equal(stored.content_hash, sha256("Original connector content."));
  assert.equal(stored.authority_id, "connector-original");
  assert.equal(fixture.nodes.has(deriveVertexId("source-retargeted")), false);
});

test("derived writes use immutable snapshots of context and producer output", async () => {
  const fixture = createMemoryHydra();
  const writer = createProvenanceWriter({
    hydra: fixture.hydra,
    signingKey,
    verifyTrustedSource: async () => true,
  });
  const sourceId = "snapshot-parent";
  const sourceResult = await writer.registerTrustedSource({
    id: sourceId,
    content: "Snapshot parent content.",
    attestation: {
      issuer: "snapshot-connector",
      key_id: "snapshot-key",
      signature: "snapshot-signature",
    },
  });
  assert.equal(sourceResult.status, "PASS");

  const prepared = await writer.prepareTransformation({
    artifactId: "snapshot-child",
    role: "summary",
    observedParentIds: [sourceId],
    kind: "summarize",
  });
  assert.equal(prepared.status, "PASS");

  const mutableContext = {
    ...prepared.context,
    parent_ids: [...prepared.context.parent_ids],
  };
  const mutableOutput = { content: "Original derived content." };
  fixture.failNextChildStage();
  const write = writer.writeDerivedArtifact({
    context: mutableContext,
    producerOutput: mutableOutput,
  });

  mutableContext.artifact_id = "snapshot-retargeted-child";
  mutableContext.selector = deriveSelector(mutableContext.artifact_id);
  mutableContext.role = "action_argument";
  mutableContext.kind = "require";
  mutableContext.context_id = "a".repeat(64);
  mutableContext.batch_id = "b".repeat(64);
  mutableContext.token = "c".repeat(64);
  mutableOutput.content = "Mutated derived content.";

  const result = await write;
  assert.equal(result.status, "BLOCK");
  assert.equal(result.detail, "HYDRADB_CHILD_STAGE_FAILED");
  assert.equal(fixture.stagedChild.artifact_id, "snapshot-child");
  assert.equal(fixture.stagedChild.selector, deriveSelector("snapshot-child"));
  assert.equal(fixture.stagedChild.role, "summary");
  assert.equal(fixture.stagedChild.lineage_kind, "summarize");
  assert.equal(fixture.stagedChild.context_id, prepared.context.context_id);
  assert.equal(fixture.stagedChild.batch_id, prepared.context.batch_id);
  assert.equal(fixture.stagedChild.content_hash, sha256("Original derived content."));
  assert.notEqual(fixture.stagedChild.artifact_id, mutableContext.artifact_id);
});

test("transformation preparation snapshots the observed parent array", async () => {
  const fixture = createMemoryHydra();
  const writer = createProvenanceWriter({
    hydra: fixture.hydra,
    signingKey,
    verifyTrustedSource: async () => true,
  });
  const sourceId = "observed-parent-snapshot";
  const sourceResult = await writer.registerTrustedSource({
    id: sourceId,
    content: "Observed parent snapshot content.",
    attestation: {
      issuer: "snapshot-connector",
      key_id: "snapshot-key",
      signature: "snapshot-signature",
    },
  });
  assert.equal(sourceResult.status, "PASS");

  const observedParentIds = [sourceId, sourceId];
  const preparing = writer.prepareTransformation({
    artifactId: "observed-parent-child",
    role: "summary",
    observedParentIds,
    kind: "summarize",
  });
  observedParentIds.push(sourceId);

  const prepared = await preparing;
  assert.equal(prepared.status, "PASS");
  assert.equal(prepared.context.parent_count, 1);
  assert.equal(prepared.duplicate_parent_count, 1);
  assert.deepEqual(prepared.context.parent_ids, [sourceId]);
});

test("structured provenance verification exposes authenticated terminal state", async () => {
  const fixture = createMemoryHydra();
  const writer = createProvenanceWriter({
    hydra: fixture.hydra,
    signingKey,
    verifyTrustedSource: async () => true,
  });
  const sourceId = "structured-verification-source";
  const registration = await writer.registerTrustedSource({
    id: sourceId,
    content: "Structured verification source content.",
    attestation: {
      issuer: "structured-connector",
      key_id: "structured-key",
      signature: "structured-signature",
    },
  });
  assert.equal(registration.status, "PASS");

  const verified = await writer.verifyProvenanceState(sourceId, { maxDepth: 1 });
  assert.equal(verified.status, "PASS");
  assert.equal(verified.result, "PROVENANCE_STATE_VERIFIED");
  assert.equal(verified.ancestry_status, "RESOLVED");
  assert.equal(verified.artifact.artifact_id, sourceId);
  assert.equal(verified.source_nodes.length, 1);
  assert.equal(verified.source_nodes[0].trust_state, "trusted_source");
  assert.equal(verified.witnesses.length, 0);

  const missing = await writer.verifyProvenanceState("structured-missing-source");
  assert.equal(missing.status, "BLOCK");
  assert.equal(missing.classification, "MISSING");
  assert.equal(missing.detail, "ARTIFACT_NOT_FOUND");
});

import {
  createHash,
  createHmac,
  timingSafeEqual,
} from "node:crypto";

import {
  projectedRows,
} from "./hydradb-client.mjs";

export const PROVENANCE_GATE_ID = "trusted-provenance-writer-v1";
export const PROVENANCE_WRITER_ID = "quarantine-writer-v1";
export const BLOCK_INVALID_PROVENANCE = "BLOCK_INVALID_PROVENANCE";
export const BLOCK_UNRESOLVED_ANCESTRY = "BLOCK_UNRESOLVED_ANCESTRY";
export const PROVENANCE_SCHEMA_VERSION = 2;
export const PROVENANCE_STATE_VERIFIER_VERSION = "provenance-state-verifier-v1";

const VALID_DERIVED_ROLES = new Set(["claim", "summary", "action_argument"]);
const VALID_EDGE_KINDS = new Set(["assert", "summarize", "support", "require"]);
const ALLOWED_PRODUCER_FIELDS = new Set(["content"]);
const MAX_PARENT_COUNT = 64;
const DEFAULT_MAX_GENERATION = 64;
const DEFAULT_MAX_CLOSURE_NODES = 1_024;
const CREATE_ONLY_MARKER = "quarantine-provenance-create-only-v1";
const CONTROL_FIELDS = new Set([
  "id",
  "role",
  "parent_ids",
  "parentIds",
  "source",
  "verified",
  "trusted",
  "confidence",
  "provenance",
  "ancestry",
  "authority",
]);

const ARTIFACT_PROJECTION = [
  "n.id AS vertex_id",
  "n.artifact_id AS artifact_id",
  "n.selector AS selector",
  "n.role AS role",
  "n.generation AS generation",
  "n.terminal AS terminal",
  "n.content_hash AS content_hash",
  "n.trust_state AS trust_state",
  "n.auth_state AS auth_state",
  "n.writer_id AS writer_id",
  "n.writer_key_id AS writer_key_id",
  "n.gate_id AS gate_id",
  "n.parent_count AS parent_count",
  "n.parent_set_hash AS parent_set_hash",
  "n.lineage_kind AS lineage_kind",
  "n.context_id AS context_id",
  "n.batch_id AS batch_id",
  "n.write_version AS write_version",
  "n.create_only AS create_only",
  "n.authority_id AS authority_id",
  "n.authority_proof_hash AS authority_proof_hash",
  "n.auth_tag AS auth_tag",
].join(", ");

const EDGE_PROJECTION = [
  "r.edge_id AS edge_edge_id",
  "r.child_artifact_id AS edge_child_artifact_id",
  "r.parent_artifact_id AS edge_parent_artifact_id",
  "r.kind AS edge_kind",
  "r.child_generation AS edge_child_generation",
  "r.parent_generation AS edge_parent_generation",
  "r.writer_id AS edge_writer_id",
  "r.writer_key_id AS edge_writer_key_id",
  "r.gate_id AS edge_gate_id",
  "r.batch_id AS edge_batch_id",
  "r.write_version AS edge_write_version",
  "r.auth_tag AS edge_auth_tag",
].join(", ");

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
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

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function block(detail, extra = {}) {
  return Object.freeze({
    status: "BLOCK",
    reason_code: BLOCK_INVALID_PROVENANCE,
    detail,
    ...extra,
  });
}

function pass(result, extra = {}) {
  return Object.freeze({
    status: "PASS",
    reason_code: null,
    result,
    ...extra,
  });
}

function parentSetHash(parentIds) {
  return sha256(JSON.stringify([...parentIds].sort()));
}

function canonicalNodeFields(record) {
  return [
    "node-v3",
    record.vertex_id,
    record.artifact_id,
    record.selector,
    record.role,
    record.generation,
    record.terminal,
    record.content_hash,
    record.trust_state,
    record.auth_state,
    record.writer_id,
    record.writer_key_id,
    record.gate_id,
    record.parent_count,
    record.parent_set_hash,
    record.lineage_kind,
    record.context_id,
    record.batch_id,
    record.write_version,
    record.create_only,
    record.authority_id,
    record.authority_proof_hash,
  ];
}

function canonicalEdgeFields(record) {
  return [
    "edge-v2",
    record.edge_id,
    record.child_artifact_id,
    record.parent_artifact_id,
    record.kind,
    record.child_generation,
    record.parent_generation,
    record.writer_id,
    record.writer_key_id,
    record.gate_id,
    record.batch_id,
    record.write_version,
  ];
}

function canonicalContextFields(context) {
  return [
    "context-v2",
    context.artifact_id,
    context.selector,
    context.role,
    context.generation,
    context.kind,
    context.parent_count,
    context.parent_set_hash,
    context.parent_ids,
    context.writer_id,
    context.writer_key_id,
    context.gate_id,
    context.write_version,
    context.duplicate_parent_count,
  ];
}

function hydrateArtifact(record, prefix = "") {
  const field = (name) => record[`${prefix}${name}`];
  return {
    vertex_id: field("vertex_id"),
    artifact_id: field("artifact_id"),
    selector: field("selector"),
    role: field("role"),
    generation: field("generation"),
    terminal: field("terminal"),
    content_hash: field("content_hash"),
    trust_state: field("trust_state"),
    auth_state: field("auth_state"),
    writer_id: field("writer_id"),
    writer_key_id: field("writer_key_id"),
    gate_id: field("gate_id"),
    parent_count: field("parent_count"),
    parent_set_hash: field("parent_set_hash"),
    lineage_kind: field("lineage_kind"),
    context_id: field("context_id"),
    batch_id: field("batch_id"),
    write_version: field("write_version"),
    create_only: field("create_only"),
    authority_id: field("authority_id"),
    authority_proof_hash: field("authority_proof_hash"),
    auth_tag: field("auth_tag"),
  };
}

function hydrateEdge(record, prefix = "edge_") {
  const field = (name) => record[`${prefix}${name}`];
  return {
    edge_id: field("edge_id"),
    child_artifact_id: field("child_artifact_id"),
    parent_artifact_id: field("parent_artifact_id"),
    kind: field("kind"),
    child_generation: field("child_generation"),
    parent_generation: field("parent_generation"),
    writer_id: field("writer_id"),
    writer_key_id: field("writer_key_id"),
    gate_id: field("gate_id"),
    batch_id: field("batch_id"),
    write_version: field("write_version"),
    auth_tag: field("auth_tag"),
  };
}

function sameArtifact(left, right) {
  const rightFields = canonicalNodeFields(right);
  return canonicalNodeFields(left).every((value, index) => value === rightFields[index]);
}

function validateProducerOutput(output) {
  if (!isPlainObject(output)) {
    return block("INVALID_PRODUCER_OUTPUT");
  }
  const rejectedFields = Object.keys(output)
    .filter((field) => CONTROL_FIELDS.has(field) || !ALLOWED_PRODUCER_FIELDS.has(field))
    .sort();
  if (rejectedFields.length > 0) {
    return block("UNTRUSTED_CONTROL_FIELD", { rejected_fields: rejectedFields });
  }
  if (typeof output.content !== "string") {
    return block("INVALID_ARTIFACT_CONTENT");
  }
  if (Buffer.byteLength(output.content, "utf8") > 1_000_000) {
    return block("ARTIFACT_CONTENT_TOO_LARGE");
  }
  return null;
}

function validateArtifactId(artifactId) {
  return typeof artifactId === "string"
    && artifactId.length > 0
    && Buffer.byteLength(artifactId, "utf8") <= 256;
}

function validateSourceInput(source) {
  if (!isPlainObject(source)) {
    return block("INVALID_SOURCE_INPUT");
  }
  const rejectedFields = Object.keys(source).filter((field) => !new Set(["id", "content", "attestation"]).has(field));
  if (rejectedFields.length > 0) {
    return block("UNTRUSTED_CONTROL_FIELD", { rejected_fields: rejectedFields.sort() });
  }
  if (!validateArtifactId(source.id)) {
    return block("INVALID_ARTIFACT_ID");
  }
  if (typeof source.content !== "string" || Buffer.byteLength(source.content, "utf8") > 1_000_000) {
    return block("INVALID_ARTIFACT_CONTENT");
  }
  if (!isPlainObject(source.attestation)
    || typeof source.attestation.issuer !== "string"
    || typeof source.attestation.key_id !== "string"
    || typeof source.attestation.signature !== "string") {
    return block("INVALID_SOURCE_ATTESTATION");
  }
  const attestationFields = Object.keys(source.attestation).sort();
  if (JSON.stringify(attestationFields) !== JSON.stringify(["issuer", "key_id", "signature"])) {
    return block("INVALID_SOURCE_ATTESTATION");
  }
  return null;
}

function snapshotSourceInput(source) {
  if (!isPlainObject(source)) {
    return source;
  }
  const snapshot = { ...source };
  if (isPlainObject(snapshot.attestation)) {
    snapshot.attestation = Object.freeze({ ...snapshot.attestation });
  }
  return Object.freeze(snapshot);
}

function snapshotTransformationContext(context) {
  if (!isPlainObject(context)) {
    return context;
  }
  const snapshot = { ...context };
  if (Array.isArray(snapshot.parent_ids)) {
    snapshot.parent_ids = Object.freeze([...snapshot.parent_ids]);
  }
  return Object.freeze(snapshot);
}

function snapshotProducerOutput(producerOutput) {
  return isPlainObject(producerOutput)
    ? Object.freeze({ ...producerOutput })
    : producerOutput;
}

export function deriveVertexId(artifactId) {
  return Number.parseInt(sha256(`quarantine:vertex:${artifactId}`).slice(0, 12), 16);
}

export function deriveSelector(artifactId) {
  return sha256(`quarantine:selector:${artifactId}`);
}

function deriveEdgeId(childArtifactId, parentArtifactId, kind) {
  return Number.parseInt(sha256(`quarantine:edge:${childArtifactId}:${parentArtifactId}:${kind}`).slice(0, 12), 16);
}

export function createProvenanceWriter({
  hydra,
  signingKey,
  writerKeyId = "local-writer-key-v1",
  verifyTrustedSource,
  maxGeneration = DEFAULT_MAX_GENERATION,
  maxClosureNodes = DEFAULT_MAX_CLOSURE_NODES,
}) {
  if (!hydra || typeof hydra.query !== "function") {
    throw new Error("A HydraDB client is required");
  }
  if (typeof signingKey !== "string" || Buffer.byteLength(signingKey, "utf8") < 32) {
    throw new Error("The provenance writer requires a server-side signing key of at least 32 bytes");
  }
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(writerKeyId)) {
    throw new Error("writerKeyId must use 1-64 ASCII alphanumeric, dot, underscore, or hyphen characters");
  }
  if (typeof verifyTrustedSource !== "function") {
    throw new Error("A trusted source attestation verifier is required");
  }
  if (!Number.isInteger(maxGeneration) || maxGeneration < 1 || maxGeneration > 1_000) {
    throw new Error("maxGeneration must be an integer between 1 and 1000");
  }
  if (!Number.isInteger(maxClosureNodes) || maxClosureNodes < 1 || maxClosureNodes > 100_000) {
    throw new Error("maxClosureNodes must be an integer between 1 and 100000");
  }

  const locks = new Map();

  function signNode(record) {
    return hmac(signingKey, canonicalNodeFields(record));
  }

  function signEdge(record) {
    return hmac(signingKey, canonicalEdgeFields(record));
  }

  function signContext(context) {
    return hmac(signingKey, [
      ...canonicalContextFields(context),
      context.context_id,
      context.batch_id,
    ]);
  }

  function signedNodeInState(record, authState) {
    return record.writer_id === PROVENANCE_WRITER_ID
      && record.writer_key_id === writerKeyId
      && record.gate_id === PROVENANCE_GATE_ID
      && record.auth_state === authState
      && record.create_only === CREATE_ONLY_MARKER
      && record.write_version === 1
      && typeof record.batch_id === "string"
      && /^[a-f0-9]{64}$/.test(record.batch_id)
      && Number.isInteger(record.generation)
      && record.generation >= 0
      && Number.isInteger(record.parent_count)
      && record.parent_count >= 0
      && secureEqual(record.auth_tag, signNode(record));
  }

  function authenticNode(record) {
    return signedNodeInState(record, "committed");
  }

  function authenticEdge(record) {
    return record.writer_id === PROVENANCE_WRITER_ID
      && record.writer_key_id === writerKeyId
      && record.gate_id === PROVENANCE_GATE_ID
      && record.write_version === 1
      && typeof record.batch_id === "string"
      && /^[a-f0-9]{64}$/.test(record.batch_id)
      && secureEqual(record.auth_tag, signEdge(record));
  }

  async function withArtifactLock(artifactId, operation) {
    const prior = locks.get(artifactId) ?? Promise.resolve();
    let release;
    const current = new Promise((resolve) => {
      release = resolve;
    });
    const tail = prior.then(() => current);
    locks.set(artifactId, tail);
    await prior;
    try {
      return await operation();
    } finally {
      release();
      if (locks.get(artifactId) === tail) {
        locks.delete(artifactId);
      }
    }
  }

  async function findArtifactByVertex(vertexId) {
    const response = await hydra.query(
      `MATCH (n:ProvenanceArtifact {id: $vertex_id}) RETURN ${ARTIFACT_PROJECTION}`,
      { vertex_id: vertexId },
    );
    const records = projectedRows(response);
    if (records.length > 1) {
      throw new Error(`HydraDB returned duplicate vertex id ${vertexId}`);
    }
    return records.length === 0 ? null : hydrateArtifact(records[0]);
  }

  async function findArtifacts(artifactIds) {
    const artifacts = [];
    for (const artifactId of artifactIds) {
      const artifact = await findArtifactByVertex(deriveVertexId(artifactId));
      if (artifact) {
        artifacts.push(artifact);
      }
    }
    return artifacts;
  }

  async function findEdgesFrom(vertexId) {
    const response = await hydra.query(
      `MATCH (c:ProvenanceArtifact {id: $vertex_id})-[r:DERIVES_FROM]->(p) RETURN ${EDGE_PROJECTION}, p.id AS parent_vertex_id`,
      { vertex_id: vertexId },
    );
    const records = projectedRows(response);
    const hydrated = [];
    for (const record of records) {
      const parent = await findArtifactByVertex(record.parent_vertex_id);
      if (!parent) {
        throw new Error(`HydraDB lineage edge points to a non-ProvenanceArtifact vertex ${record.parent_vertex_id}`);
      }
      hydrated.push({ edge: hydrateEdge(record), parent });
    }
    return hydrated;
  }

  async function validateArtifactClosure(record, state = {
    stack: new Set(),
    memo: new Map(),
    visited: 0,
  }) {
    if (!record || !validateArtifactId(record.artifact_id)) {
      return false;
    }
    if (state.memo.has(record.artifact_id)) {
      return state.memo.get(record.artifact_id);
    }
    state.visited += 1;
    if (state.visited > maxClosureNodes) {
      return false;
    }
    if (state.stack.has(record.artifact_id)
      || record.vertex_id !== deriveVertexId(record.artifact_id)
      || record.selector !== deriveSelector(record.artifact_id)
      || !authenticNode(record)
      || record.generation > maxGeneration) {
      return false;
    }

    state.stack.add(record.artifact_id);
    let valid = true;
    const outgoing = await findEdgesFrom(record.vertex_id);

    if (record.terminal === true) {
      valid = record.role === "source"
        && record.generation === 0
        && record.parent_count === 0
        && record.parent_set_hash === parentSetHash([])
        && record.lineage_kind === "source"
        && ["trusted_source", "untrusted_source"].includes(record.trust_state)
        && outgoing.length === 0;
    } else {
      const parentIds = outgoing.map(({ parent }) => parent.artifact_id).sort();
      valid = VALID_DERIVED_ROLES.has(record.role)
        && record.trust_state === "derived"
        && record.generation > 0
        && record.parent_count > 0
        && VALID_EDGE_KINDS.has(record.lineage_kind)
        && outgoing.length === record.parent_count
        && record.parent_set_hash === parentSetHash(parentIds);

      for (const { edge, parent } of outgoing) {
        if (!valid
          || !validateArtifactId(parent.artifact_id)
          || parent.vertex_id !== deriveVertexId(parent.artifact_id)
          || parent.selector !== deriveSelector(parent.artifact_id)
          || !authenticNode(parent)
          || !authenticEdge(edge)
          || edge.edge_id !== deriveEdgeId(record.artifact_id, parent.artifact_id, record.lineage_kind)
          || edge.kind !== record.lineage_kind
          || edge.child_artifact_id !== record.artifact_id
          || edge.parent_artifact_id !== parent.artifact_id
          || edge.child_generation !== record.generation
          || edge.parent_generation !== parent.generation
          || edge.batch_id !== record.batch_id
          || edge.write_version !== record.write_version
          || parent.generation >= record.generation
          || !await validateArtifactClosure(parent, state)) {
          valid = false;
          break;
        }
      }
    }

    state.stack.delete(record.artifact_id);
    state.memo.set(record.artifact_id, valid);
    return valid;
  }

  async function resolveAuthenticParents(parentIds) {
    const found = await findArtifacts(parentIds);
    const byId = new Map(found.map((parent) => [parent.artifact_id, parent]));
    const invalidParentIds = [];
    const state = { stack: new Set(), memo: new Map(), visited: 0 };
    for (const parentId of parentIds) {
      const parent = byId.get(parentId);
      if (!parent || !await validateArtifactClosure(parent, state)) {
        invalidParentIds.push(parentId);
      }
    }
    return {
      parents: invalidParentIds.length === 0 ? parentIds.map((parentId) => byId.get(parentId)) : [],
      invalidParentIds,
    };
  }

  async function validateEdgeSet(expected, expectedParents) {
    const outgoing = await findEdgesFrom(expected.vertex_id);
    const parentIds = outgoing.map(({ parent }) => parent.artifact_id).sort();
    const expectedIds = expectedParents.map((parent) => parent.artifact_id).sort();
    const exactSet = outgoing.length === expected.parent_count
      && parentSetHash(parentIds) === expected.parent_set_hash
      && JSON.stringify(parentIds) === JSON.stringify(expectedIds);
    const validEdges = outgoing.every(({ edge, parent }) => authenticNode(parent)
      && authenticEdge(edge)
      && edge.edge_id === deriveEdgeId(expected.artifact_id, parent.artifact_id, expected.lineage_kind)
      && edge.kind === expected.lineage_kind
      && edge.child_artifact_id === expected.artifact_id
      && edge.parent_artifact_id === parent.artifact_id
      && edge.child_generation === expected.generation
      && edge.parent_generation === parent.generation
      && edge.batch_id === expected.batch_id
      && edge.write_version === expected.write_version
      && parent.generation < expected.generation);
    return { valid: exactSet && validEdges, outgoing, parentIds };
  }

  async function verifyCommittedArtifact(expected, expectedParents) {
    const current = await findArtifactByVertex(expected.vertex_id);
    if (!current || !authenticNode(current) || !sameArtifact(current, expected)) {
      return block("ARTIFACT_IMMUTABILITY_CONFLICT", { artifact_id: expected.artifact_id });
    }
    const edgeSet = await validateEdgeSet(expected, expectedParents);
    if (!edgeSet.valid || !await validateArtifactClosure(current)) {
      return block("INVALID_COMMITTED_ANCESTRY", { artifact_id: expected.artifact_id });
    }
    return pass("WRITE_REPLAYED", {
      artifact_id: expected.artifact_id,
      generation: expected.generation,
      replayed: true,
      parent_ids: edgeSet.parentIds,
      relationship_count: edgeSet.outgoing.length,
    });
  }

  // This is the only writer API intended to feed authorization. It returns
  // authenticated graph facts, including every terminal branch, rather than
  // reducing a closure to a boolean. The compatibility verifier below keeps
  // the original compact result for existing callers and proof artifacts.
  async function verifyProvenanceState(artifactId, options = {}) {
    if (!validateArtifactId(artifactId)) {
      return Object.freeze({
        status: "BLOCK",
        reason_code: BLOCK_INVALID_PROVENANCE,
        detail: "INVALID_ARTIFACT_ID",
        classification: "INVALID",
        artifact_id: artifactId,
      });
    }

    const maxDepth = options.maxDepth ?? maxGeneration;
    const closureLimit = options.maxClosureNodes ?? maxClosureNodes;
    if (!Number.isInteger(maxDepth) || maxDepth < 0 || maxDepth > maxGeneration
      || !Number.isInteger(closureLimit) || closureLimit < 1 || closureLimit > maxClosureNodes) {
      return Object.freeze({
        status: "BLOCK",
        reason_code: BLOCK_INVALID_PROVENANCE,
        detail: "INVALID_VERIFICATION_BOUNDS",
        classification: "INVALID",
        artifact_id: artifactId,
      });
    }

    let root;
    try {
      root = await findArtifactByVertex(deriveVertexId(artifactId));
    } catch {
      return Object.freeze({
        status: "BLOCK",
        reason_code: BLOCK_INVALID_PROVENANCE,
        detail: "PROVENANCE_VERIFICATION_FAILED",
        classification: "SYSTEM_ERROR",
        artifact_id: artifactId,
      });
    }
    if (!root || root.artifact_id !== artifactId) {
      return Object.freeze({
        status: "BLOCK",
        reason_code: BLOCK_INVALID_PROVENANCE,
        detail: "ARTIFACT_NOT_FOUND",
        classification: "MISSING",
        artifact_id: artifactId,
      });
    }

    const visitState = new Map();
    const nodes = new Map();
    const edges = new Map();
    const sources = new Map();
    let deepestHops = 0;
    let invalidDetail = null;
    let invalidArtifactId = null;
    let unresolvedDetail = null;
    let unresolvedFrontier = null;
    let systemError = false;

    const nodeSummary = (record) => Object.freeze({
      artifact_id: record.artifact_id,
      vertex_id: record.vertex_id,
      role: record.role,
      lineage_kind: record.lineage_kind,
      generation: record.generation,
      parent_count: record.parent_count,
      terminal: record.terminal,
      content_hash: record.content_hash,
      trust_state: record.trust_state,
      authority_id: record.authority_id,
      batch_id: record.batch_id,
    });

    const edgeSummary = (edge) => Object.freeze({
      edge_id: edge.edge_id,
      child_artifact_id: edge.child_artifact_id,
      parent_artifact_id: edge.parent_artifact_id,
      kind: edge.kind,
      child_generation: edge.child_generation,
      parent_generation: edge.parent_generation,
      batch_id: edge.batch_id,
    });

    async function visit(record, depth) {
      if (invalidDetail || unresolvedDetail || systemError) {
        return;
      }
      deepestHops = Math.max(deepestHops, depth);
      if (depth > maxDepth) {
        unresolvedDetail = "DEPTH_CAP_REACHED";
        unresolvedFrontier = record?.artifact_id ?? null;
        return;
      }
      if (!record || !validateArtifactId(record.artifact_id)) {
        invalidDetail = "ARTIFACT_NOT_AUTHENTIC";
        invalidArtifactId = record?.artifact_id ?? null;
        return;
      }
      const priorState = visitState.get(record.artifact_id);
      if (priorState === "visiting") {
        invalidDetail = "ANCESTRY_CYCLE";
        invalidArtifactId = record.artifact_id;
        return;
      }
      if (priorState === "done") {
        return;
      }
      if (nodes.size >= closureLimit) {
        unresolvedDetail = "CLOSURE_NODE_CAP_REACHED";
        unresolvedFrontier = record.artifact_id;
        return;
      }

      if (record.vertex_id !== deriveVertexId(record.artifact_id)
        || record.selector !== deriveSelector(record.artifact_id)
        || !authenticNode(record)
        || record.generation > maxGeneration) {
        invalidDetail = "ARTIFACT_NOT_AUTHENTIC";
        invalidArtifactId = record.artifact_id;
        return;
      }

      visitState.set(record.artifact_id, "visiting");
      nodes.set(record.artifact_id, nodeSummary(record));

      let outgoing;
      try {
        outgoing = await findEdgesFrom(record.vertex_id);
      } catch {
        systemError = true;
        visitState.delete(record.artifact_id);
        return;
      }

      if (record.terminal === true) {
        const validTerminal = record.role === "source"
          && record.generation === 0
          && record.parent_count === 0
          && record.parent_set_hash === parentSetHash([])
          && record.lineage_kind === "source"
          && ["trusted_source", "untrusted_source"].includes(record.trust_state)
          && outgoing.length === 0;
        if (!validTerminal) {
          invalidDetail = "ARTIFACT_NOT_AUTHENTIC";
          invalidArtifactId = record.artifact_id;
        } else {
          sources.set(record.artifact_id, nodeSummary(record));
        }
        visitState.set(record.artifact_id, "done");
        return;
      }

      if (depth >= maxDepth) {
        unresolvedDetail = "DEPTH_CAP_REACHED";
        unresolvedFrontier = record.artifact_id;
        visitState.delete(record.artifact_id);
        return;
      }

      const parentIds = outgoing.map(({ parent }) => parent.artifact_id).sort();
      const validDerived = VALID_DERIVED_ROLES.has(record.role)
        && record.trust_state === "derived"
        && record.generation > 0
        && record.parent_count > 0
        && VALID_EDGE_KINDS.has(record.lineage_kind)
        && outgoing.length === record.parent_count
        && record.parent_set_hash === parentSetHash(parentIds);
      if (!validDerived) {
        invalidDetail = "ARTIFACT_NOT_AUTHENTIC";
        invalidArtifactId = record.artifact_id;
        visitState.set(record.artifact_id, "done");
        return;
      }

      for (const { edge, parent } of outgoing) {
        const validEdge = validateArtifactId(parent.artifact_id)
          && parent.vertex_id === deriveVertexId(parent.artifact_id)
          && parent.selector === deriveSelector(parent.artifact_id)
          && authenticNode(parent)
          && authenticEdge(edge)
          && edge.edge_id === deriveEdgeId(record.artifact_id, parent.artifact_id, record.lineage_kind)
          && edge.kind === record.lineage_kind
          && edge.child_artifact_id === record.artifact_id
          && edge.parent_artifact_id === parent.artifact_id
          && edge.child_generation === record.generation
          && edge.parent_generation === parent.generation
          && edge.batch_id === record.batch_id
          && edge.write_version === record.write_version
          && parent.generation < record.generation;
        if (!validEdge) {
          invalidDetail = "ARTIFACT_NOT_AUTHENTIC";
          invalidArtifactId = record.artifact_id;
          break;
        }
        edges.set(`${record.artifact_id}:${parent.artifact_id}:${edge.kind}`, edgeSummary(edge));
        await visit(parent, depth + 1);
        if (invalidDetail || unresolvedDetail || systemError) {
          break;
        }
      }
      visitState.set(record.artifact_id, "done");
    }

    await visit(root, 0);

    if (systemError) {
      return Object.freeze({
        status: "BLOCK",
        reason_code: BLOCK_INVALID_PROVENANCE,
        detail: "PROVENANCE_VERIFICATION_FAILED",
        classification: "SYSTEM_ERROR",
        artifact_id: artifactId,
      });
    }
    if (unresolvedDetail) {
      return Object.freeze({
        status: "BLOCK",
        reason_code: BLOCK_UNRESOLVED_ANCESTRY,
        detail: unresolvedDetail,
        classification: "UNRESOLVED",
        artifact_id: artifactId,
        frontier_artifact_id: unresolvedFrontier,
        deepest_hops: deepestHops,
      });
    }
    if (invalidDetail) {
      return Object.freeze({
        status: "BLOCK",
        reason_code: BLOCK_INVALID_PROVENANCE,
        detail: invalidDetail,
        classification: "INVALID",
        artifact_id: artifactId,
        invalid_artifact_id: invalidArtifactId,
      });
    }

    return Object.freeze({
      status: "PASS",
      result: "PROVENANCE_STATE_VERIFIED",
      reason_code: null,
      classification: "VERIFIED",
      verifier_version: PROVENANCE_STATE_VERIFIER_VERSION,
      artifact: nodeSummary(root),
      ancestry_status: "RESOLVED",
      source_nodes: Object.freeze([...sources.values()].sort((left, right) => left.artifact_id.localeCompare(right.artifact_id))),
      witnesses: Object.freeze([...edges.values()].sort((left, right) => left.edge_id - right.edge_id)),
      graph_snapshot: Object.freeze({
        node_count: nodes.size,
        edge_count: edges.size,
        deepest_hops: deepestHops,
        max_depth: maxDepth,
      }),
    });
  }

  async function registerTrustedSource(source) {
    let trustedSource;
    try {
      trustedSource = snapshotSourceInput(source);
    } catch {
      return block("INVALID_SOURCE_INPUT");
    }
    const validation = validateSourceInput(trustedSource);
    if (validation) {
      return validation;
    }
    let attestationValid = false;
    try {
      attestationValid = await verifyTrustedSource(trustedSource) === true;
    } catch {
      return block("SOURCE_ATTESTATION_VERIFICATION_FAILED", { artifact_id: trustedSource.id });
    }
    if (!attestationValid) {
      return block("SOURCE_ATTESTATION_INVALID", { artifact_id: trustedSource.id });
    }

    const selector = deriveSelector(trustedSource.id);
    const authorityProofHash = sha256(JSON.stringify([
      trustedSource.attestation.issuer,
      trustedSource.attestation.key_id,
      trustedSource.attestation.signature,
    ]));
    const contextId = sha256(JSON.stringify([
      "trusted-source-context-v1",
      trustedSource.id,
      selector,
      authorityProofHash,
    ]));
    const record = {
      vertex_id: deriveVertexId(trustedSource.id),
      artifact_id: trustedSource.id,
      selector,
      role: "source",
      generation: 0,
      terminal: true,
      content_hash: sha256(trustedSource.content),
      trust_state: "trusted_source",
      auth_state: "committed",
      writer_id: PROVENANCE_WRITER_ID,
      writer_key_id: writerKeyId,
      gate_id: PROVENANCE_GATE_ID,
      parent_count: 0,
      parent_set_hash: parentSetHash([]),
      lineage_kind: "source",
      context_id: contextId,
      batch_id: sha256(`quarantine:source-batch:${contextId}`),
      write_version: 1,
      create_only: CREATE_ONLY_MARKER,
      authority_id: trustedSource.attestation.issuer,
      authority_proof_hash: authorityProofHash,
    };
    record.auth_tag = signNode(record);

    return withArtifactLock(trustedSource.id, async () => {
      let existing;
      try {
        existing = await findArtifactByVertex(record.vertex_id);
      } catch {
        return block("SOURCE_LOOKUP_FAILED", { artifact_id: record.artifact_id });
      }
      if (existing) {
        try {
          return await verifyCommittedArtifact(record, []);
        } catch {
          return block("SOURCE_REPLAY_VERIFICATION_FAILED", { artifact_id: record.artifact_id });
        }
      }
      try {
        await hydra.query(
          "UNWIND $rows AS row MERGE (n {id: row.vertex_id}) SET n:ProvenanceArtifact, n.artifact_id = row.artifact_id, n.selector = row.selector, n.role = row.role, n.generation = row.generation, n.terminal = row.terminal, n.content_hash = row.content_hash, n.trust_state = row.trust_state, n.auth_state = row.auth_state, n.writer_id = row.writer_id, n.writer_key_id = row.writer_key_id, n.gate_id = row.gate_id, n.parent_count = row.parent_count, n.parent_set_hash = row.parent_set_hash, n.lineage_kind = row.lineage_kind, n.context_id = row.context_id, n.batch_id = row.batch_id, n.write_version = row.write_version, n.create_only = row.create_only, n.authority_id = row.authority_id, n.authority_proof_hash = row.authority_proof_hash, n.auth_tag = row.auth_tag, n.__hydradb_update_if_newer_by = row.write_version, n.__hydradb_create_only_artifact_id = row.artifact_id",
          { rows: [record] },
          { queryId: `lineage.${selector}.source` },
        );
      } catch {
        return block("HYDRADB_SOURCE_WRITE_FAILED", { artifact_id: record.artifact_id });
      }
      let verified;
      try {
        verified = await verifyCommittedArtifact(record, []);
      } catch {
        return block("SOURCE_COMMIT_READBACK_FAILED", { artifact_id: record.artifact_id });
      }
      if (verified.status !== "PASS") {
        return block("SOURCE_COMMIT_VERIFICATION_FAILED", { artifact_id: record.artifact_id });
      }
      return pass("WRITE_COMMITTED", {
        artifact_id: record.artifact_id,
        generation: 0,
        replayed: false,
        parent_ids: [],
      });
    });
  }

  async function prepareTransformation({ artifactId, role, observedParentIds, kind }) {
    const observedParentSnapshot = Array.isArray(observedParentIds)
      ? [...observedParentIds]
      : observedParentIds;
    if (!validateArtifactId(artifactId)) {
      return block("INVALID_ARTIFACT_ID");
    }
    if (!VALID_DERIVED_ROLES.has(role)) {
      return block("INVALID_DERIVED_ROLE");
    }
    if (!VALID_EDGE_KINDS.has(kind)) {
      return block("INVALID_EDGE_KIND");
    }
    if (!Array.isArray(observedParentSnapshot)
      || observedParentSnapshot.length === 0
      || observedParentSnapshot.length > MAX_PARENT_COUNT
      || observedParentSnapshot.some((parentId) => !validateArtifactId(parentId))) {
      return block("INVALID_OBSERVED_PARENTS");
    }

    const parentIds = [...new Set(observedParentSnapshot)].sort();
    if (parentIds.includes(artifactId)) {
      return block("SELF_PARENT", { artifact_id: artifactId });
    }
    let resolved;
    try {
      resolved = await resolveAuthenticParents(parentIds);
    } catch {
      return block("PARENT_RESOLUTION_FAILED");
    }
    if (resolved.invalidParentIds.length > 0) {
      return block("PARENT_NOT_AUTHENTIC", { invalid_parent_ids: resolved.invalidParentIds.sort() });
    }

    const generation = Math.max(...resolved.parents.map((parent) => parent.generation)) + 1;
    if (generation > maxGeneration) {
      return block("GENERATION_CAP_EXCEEDED", { max_generation: maxGeneration });
    }

    const context = {
      artifact_id: artifactId,
      selector: deriveSelector(artifactId),
      role,
      generation,
      kind,
      parent_count: parentIds.length,
      parent_set_hash: parentSetHash(parentIds),
      parent_ids: parentIds,
      writer_id: PROVENANCE_WRITER_ID,
      writer_key_id: writerKeyId,
      gate_id: PROVENANCE_GATE_ID,
      write_version: 1,
      duplicate_parent_count: observedParentSnapshot.length - parentIds.length,
    };
    context.context_id = sha256(JSON.stringify(canonicalContextFields(context)));
    context.batch_id = sha256(`quarantine:derived-batch:${context.context_id}`);
    context.token = signContext(context);

    return pass("CONTEXT_PREPARED", {
      context: Object.freeze({ ...context, parent_ids: Object.freeze([...context.parent_ids]) }),
      duplicate_parent_count: context.duplicate_parent_count,
    });
  }

  function validContext(context) {
    if (!isPlainObject(context)
      || !validateArtifactId(context.artifact_id)
      || context.selector !== deriveSelector(context.artifact_id)
      || !VALID_DERIVED_ROLES.has(context.role)
      || !VALID_EDGE_KINDS.has(context.kind)
      || !Array.isArray(context.parent_ids)
      || context.parent_ids.length === 0
      || context.parent_ids.length > MAX_PARENT_COUNT
      || context.parent_ids.length !== context.parent_count
      || JSON.stringify(context.parent_ids) !== JSON.stringify([...new Set(context.parent_ids)].sort())
      || context.parent_ids.includes(context.artifact_id)
      || context.parent_set_hash !== parentSetHash(context.parent_ids)
      || context.writer_id !== PROVENANCE_WRITER_ID
      || context.writer_key_id !== writerKeyId
      || context.gate_id !== PROVENANCE_GATE_ID
      || context.write_version !== 1
      || !Number.isInteger(context.duplicate_parent_count)
      || context.duplicate_parent_count < 0
      || !Number.isInteger(context.generation)
      || context.generation < 1
      || context.generation > maxGeneration
      || context.context_id !== sha256(JSON.stringify(canonicalContextFields(context)))
      || context.batch_id !== sha256(`quarantine:derived-batch:${context.context_id}`)) {
      return false;
    }
    return secureEqual(context.token, signContext(context));
  }

  async function writeDerivedArtifact({ context, producerOutput }) {
    let trustedContext;
    try {
      trustedContext = snapshotTransformationContext(context);
    } catch {
      return block("INVALID_TRANSFORMATION_CONTEXT");
    }
    let trustedOutput;
    try {
      trustedOutput = snapshotProducerOutput(producerOutput);
    } catch {
      return block("INVALID_PRODUCER_OUTPUT");
    }
    const outputValidation = validateProducerOutput(trustedOutput);
    if (outputValidation) {
      return outputValidation;
    }
    if (!validContext(trustedContext)) {
      return block("INVALID_TRANSFORMATION_CONTEXT");
    }

    return withArtifactLock(trustedContext.artifact_id, async () => {
      let resolved;
      try {
        resolved = await resolveAuthenticParents(trustedContext.parent_ids);
      } catch {
        return block("PARENT_RESOLUTION_FAILED");
      }
      if (resolved.invalidParentIds.length > 0) {
        return block("PARENT_NOT_AUTHENTIC", { invalid_parent_ids: resolved.invalidParentIds.sort() });
      }
      const generation = Math.max(...resolved.parents.map((parent) => parent.generation)) + 1;
      if (generation !== trustedContext.generation || generation > maxGeneration) {
        return block("CONTEXT_GENERATION_MISMATCH");
      }

      const record = {
        vertex_id: deriveVertexId(trustedContext.artifact_id),
        artifact_id: trustedContext.artifact_id,
        selector: trustedContext.selector,
        role: trustedContext.role,
        generation: trustedContext.generation,
        terminal: false,
        content_hash: sha256(trustedOutput.content),
        trust_state: "derived",
        auth_state: "committed",
        writer_id: PROVENANCE_WRITER_ID,
        writer_key_id: writerKeyId,
        gate_id: PROVENANCE_GATE_ID,
        parent_count: trustedContext.parent_count,
        parent_set_hash: trustedContext.parent_set_hash,
        lineage_kind: trustedContext.kind,
        context_id: trustedContext.context_id,
        batch_id: trustedContext.batch_id,
        write_version: trustedContext.write_version,
        create_only: CREATE_ONLY_MARKER,
        authority_id: PROVENANCE_WRITER_ID,
        authority_proof_hash: sha256(trustedContext.token),
      };
      record.auth_tag = signNode(record);

      let existing;
      try {
        existing = await findArtifactByVertex(record.vertex_id);
      } catch {
        return block("ARTIFACT_LOOKUP_FAILED", { artifact_id: record.artifact_id });
      }
      if (existing?.auth_state === "committed") {
        let replay;
        try {
          replay = await verifyCommittedArtifact(record, resolved.parents);
        } catch {
          return block("REPLAY_VERIFICATION_FAILED", { artifact_id: record.artifact_id });
        }
        return replay.status === "PASS"
          ? Object.freeze({ ...replay, duplicate_parent_count: trustedContext.duplicate_parent_count })
          : replay;
      }

      const pending = { ...record, auth_state: "pending" };
      pending.auth_tag = signNode(pending);
      if (existing && (!signedNodeInState(existing, "pending") || !sameArtifact(existing, pending))) {
        return block("ARTIFACT_IMMUTABILITY_CONFLICT", { artifact_id: record.artifact_id });
      }

      if (!existing) {
        try {
          await hydra.query(
            "UNWIND $rows AS row MERGE (c {id: row.vertex_id}) SET c:ProvenanceArtifact, c.artifact_id = row.artifact_id, c.selector = row.selector, c.role = row.role, c.generation = row.generation, c.terminal = row.terminal, c.content_hash = row.content_hash, c.trust_state = row.trust_state, c.auth_state = row.auth_state, c.writer_id = row.writer_id, c.writer_key_id = row.writer_key_id, c.gate_id = row.gate_id, c.parent_count = row.parent_count, c.parent_set_hash = row.parent_set_hash, c.lineage_kind = row.lineage_kind, c.context_id = row.context_id, c.batch_id = row.batch_id, c.write_version = row.write_version, c.create_only = row.create_only, c.authority_id = row.authority_id, c.authority_proof_hash = row.authority_proof_hash, c.auth_tag = row.auth_tag, c.__hydradb_update_if_newer_by = row.write_version, c.__hydradb_create_only_artifact_id = row.artifact_id",
            { rows: [pending] },
            { queryId: `lineage.${record.selector}.child` },
          );
        } catch {
          return block("HYDRADB_CHILD_STAGE_FAILED", { artifact_id: record.artifact_id });
        }
      }

      let staged;
      try {
        staged = await findArtifactByVertex(record.vertex_id);
      } catch {
        return block("PENDING_STAGE_READBACK_FAILED", { artifact_id: record.artifact_id });
      }
      if (!staged || !signedNodeInState(staged, "pending") || !sameArtifact(staged, pending)) {
        return block("PENDING_STAGE_CONFLICT", { artifact_id: record.artifact_id });
      }

      const rows = resolved.parents.map((parent) => {
        const edge = {
          edge_id: deriveEdgeId(record.artifact_id, parent.artifact_id, trustedContext.kind),
          child_artifact_id: record.artifact_id,
          parent_artifact_id: parent.artifact_id,
          kind: trustedContext.kind,
          child_generation: record.generation,
          parent_generation: parent.generation,
          writer_id: PROVENANCE_WRITER_ID,
          writer_key_id: writerKeyId,
          gate_id: PROVENANCE_GATE_ID,
          batch_id: record.batch_id,
          write_version: record.write_version,
        };
        edge.auth_tag = signEdge(edge);
        return {
          child_vertex_id: record.vertex_id,
          parent_vertex_id: parent.vertex_id,
          edge_id: edge.edge_id,
          child_artifact_id: edge.child_artifact_id,
          parent_artifact_id: edge.parent_artifact_id,
          kind: edge.kind,
          child_generation: edge.child_generation,
          parent_generation: edge.parent_generation,
          writer_id: edge.writer_id,
          writer_key_id: edge.writer_key_id,
          gate_id: edge.gate_id,
          batch_id: edge.batch_id,
          write_version: edge.write_version,
          pending_state: pending.auth_state,
          child_pending_auth_tag: pending.auth_tag,
          parent_state: parent.auth_state,
          parent_auth_tag: parent.auth_tag,
          edge_auth_tag: edge.auth_tag,
        };
      });

      try {
        await hydra.query(
          "UNWIND $rows AS row MATCH (c:ProvenanceArtifact {id: row.child_vertex_id}), (p:ProvenanceArtifact {id: row.parent_vertex_id}) MERGE (c)-[r:DERIVES_FROM {id: row.edge_id}]->(p) SET r.edge_id = row.edge_id, r.kind = row.kind, r.child_artifact_id = row.child_artifact_id, r.parent_artifact_id = row.parent_artifact_id, r.child_generation = row.child_generation, r.parent_generation = row.parent_generation, r.writer_id = row.writer_id, r.writer_key_id = row.writer_key_id, r.gate_id = row.gate_id, r.batch_id = row.batch_id, r.write_version = row.write_version, r.auth_tag = row.edge_auth_tag, r.__hydradb_update_if_newer_by = row.write_version, r.__hydradb_create_only_child_artifact_id = row.child_artifact_id, r.__hydradb_create_only_parent_artifact_id = row.parent_artifact_id",
          { rows },
          { queryId: `lineage.${record.selector}.edges` },
        );
      } catch {
        return block("HYDRADB_EDGE_WRITE_FAILED", { artifact_id: record.artifact_id });
      }

      let edgeSet;
      try {
        edgeSet = await validateEdgeSet(record, resolved.parents);
      } catch {
        return block("STAGED_ANCESTRY_READBACK_FAILED", { artifact_id: record.artifact_id });
      }
      if (!edgeSet.valid) {
        return block("INCOMPLETE_STAGED_ANCESTRY", { artifact_id: record.artifact_id });
      }

      try {
        await hydra.query(
          "MATCH (c:ProvenanceArtifact {id: $vertex_id}) WHERE c.batch_id = $batch_id AND c.context_id = $context_id AND c.auth_state = $pending_state AND c.auth_tag = $pending_auth_tag SET c.auth_state = $committed_state, c.auth_tag = $committed_auth_tag",
          {
            vertex_id: record.vertex_id,
            batch_id: record.batch_id,
            context_id: record.context_id,
            pending_state: pending.auth_state,
            pending_auth_tag: pending.auth_tag,
            committed_state: record.auth_state,
            committed_auth_tag: record.auth_tag,
          },
          { queryId: `lineage.${record.selector}.commit` },
        );
      } catch {
        return block("HYDRADB_COMMIT_FAILED", { artifact_id: record.artifact_id });
      }

      let verified;
      try {
        verified = await verifyCommittedArtifact(record, resolved.parents);
      } catch {
        return block("COMMIT_READBACK_FAILED", { artifact_id: record.artifact_id });
      }
      if (verified.status !== "PASS") {
        return block("COMMIT_VERIFICATION_FAILED", { artifact_id: record.artifact_id });
      }
      return pass("WRITE_COMMITTED", {
        artifact_id: record.artifact_id,
        generation: record.generation,
        replayed: false,
        parent_ids: [...trustedContext.parent_ids],
        relationship_count: trustedContext.parent_count,
        duplicate_parent_count: trustedContext.duplicate_parent_count,
        batch_id: record.batch_id,
      });
    });
  }

  async function verifyProvenanceIntegrity(artifactId) {
    if (!validateArtifactId(artifactId)) {
      return block("INVALID_ARTIFACT_ID");
    }
    const state = await verifyProvenanceState(artifactId);
    if (state.status !== "PASS") {
      return state.classification === "SYSTEM_ERROR"
        ? block("PROVENANCE_VERIFICATION_FAILED", { artifact_id: artifactId })
        : block("ARTIFACT_NOT_AUTHENTIC", { artifact_id: artifactId });
    }
    return pass("PROVENANCE_VERIFIED", {
      artifact_id: artifactId,
      generation: state.artifact.generation,
      parent_count: state.artifact.parent_count,
      batch_id: state.artifact.batch_id,
    });
  }

  return Object.freeze({
    registerTrustedSource,
    prepareTransformation,
    verifyProvenanceState,
    verifyProvenanceIntegrity,
    writeDerivedArtifact,
  });
}

import assert from "node:assert/strict";
import { Readable } from "node:stream";
import test from "node:test";

import {
  createDemoServer,
  validateDemoRequestBody,
} from "../scripts/demo-server.mjs";
import {
  validateActionIntent,
} from "../src/action-gateway.mjs";
import {
  DEMO_VERSION,
  MAX_PENDING_DEMO_RUNS,
  createDemoOrchestrator,
} from "../src/demo-orchestrator.mjs";
import {
  PROVENANCE_STATE_VERIFIER_VERSION,
  PROVENANCE_WRITER_ID,
  deriveVertexId,
} from "../src/provenance-writer.mjs";

function validDemoVerification(artifactId, maxDepth) {
  const validated = validateActionIntent({
    action_id: `${DEMO_VERSION}:action:valid:test`,
    subject_id: `${DEMO_VERSION}:subject:incident`,
    action_type: "send_message",
    parameters: {
      data_class: "internal",
      destination: "internal:alerts",
      payload: "Catalog and incident evidence support an internal alert.",
    },
    request_id: `${DEMO_VERSION}:request:valid:test`,
    requested_at: 2_000,
    provenance_artifact_id: artifactId,
  });
  assert.equal(validated.status, "PASS");

  const catalogSource = `${DEMO_VERSION}:test:source:catalog`;
  const incidentSource = `${DEMO_VERSION}:test:source:incident`;
  const claim = `${DEMO_VERSION}:test:claim`;
  const summary = `${DEMO_VERSION}:test:summary`;
  const rootBatch = "a".repeat(64);
  return {
    status: "PASS",
    result: "PROVENANCE_STATE_VERIFIED",
    reason_code: null,
    classification: "VERIFIED",
    verifier_version: PROVENANCE_STATE_VERIFIER_VERSION,
    artifact: {
      artifact_id: artifactId,
      vertex_id: 105,
      role: "action_argument",
      lineage_kind: "require",
      generation: 2,
      parent_count: 2,
      terminal: false,
      content_hash: validated.semantic_digest,
      trust_state: "derived",
      authority_id: PROVENANCE_WRITER_ID,
      batch_id: rootBatch,
    },
    ancestry_status: "RESOLVED",
    source_nodes: [catalogSource, incidentSource].map((sourceId, index) => ({
      artifact_id: sourceId,
      vertex_id: 101 + index,
      role: "source",
      lineage_kind: "source",
      generation: 0,
      parent_count: 0,
      terminal: true,
      content_hash: String(index + 1).repeat(64),
      trust_state: "trusted_source",
      authority_id: "quarantine-proof-connector",
      batch_id: String(index + 3).repeat(64),
    })),
    witnesses: [
      {
        edge_id: 1,
        child_artifact_id: artifactId,
        parent_artifact_id: claim,
        kind: "require",
        child_generation: 2,
        parent_generation: 1,
        batch_id: rootBatch,
      },
      {
        edge_id: 2,
        child_artifact_id: artifactId,
        parent_artifact_id: summary,
        kind: "require",
        child_generation: 2,
        parent_generation: 1,
        batch_id: rootBatch,
      },
      {
        edge_id: 3,
        child_artifact_id: claim,
        parent_artifact_id: catalogSource,
        kind: "assert",
        child_generation: 1,
        parent_generation: 0,
        batch_id: "b".repeat(64),
      },
      {
        edge_id: 4,
        child_artifact_id: summary,
        parent_artifact_id: incidentSource,
        kind: "summarize",
        child_generation: 1,
        parent_generation: 0,
        batch_id: "c".repeat(64),
      },
    ],
    graph_snapshot: {
      node_count: 5,
      edge_count: 4,
      deepest_hops: 2,
      max_depth: maxDepth,
    },
  };
}

function createHydrationFailureFixture(query) {
  let verifierCalls = 0;
  const hydra = Object.freeze({
    config: Object.freeze({
      httpBase: "http://127.0.0.1:1",
      adminBase: "http://127.0.0.1:2",
      graphId: "default",
      namespace: "default",
      cellId: "cell-0",
    }),
    async assertReady() {},
    query,
  });
  const writer = Object.freeze({
    async registerTrustedSource() {
      return { status: "PASS" };
    },
    async prepareTransformation() {
      return { status: "PASS", context: Object.freeze({}) };
    },
    async writeDerivedArtifact() {
      return { status: "PASS" };
    },
    async verifyProvenanceState(artifactId, { maxDepth }) {
      verifierCalls += 1;
      return validDemoVerification(artifactId, maxDepth);
    },
  });
  return {
    orchestrator: createDemoOrchestrator({ hydra, writer, now: () => 2_000 }),
    verifierCalls: () => verifierCalls,
  };
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

async function invokeDemoServer(server, body, contentType = "application/json") {
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  const request = Readable.from([payload]);
  request.method = "POST";
  request.url = "/api/demo/run";
  request.headers = {
    "content-length": String(payload.length),
    "content-type": contentType,
  };

  return new Promise((resolvePromise, reject) => {
    const response = {
      statusCode: null,
      headers: null,
      writeHead(statusCode, headers) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end(responseBody = Buffer.alloc(0)) {
        try {
          resolvePromise({
            statusCode: this.statusCode,
            headers: this.headers,
            body: JSON.parse(Buffer.from(responseBody).toString("utf8")),
          });
        } catch (error) {
          reject(error);
        }
      },
    };
    server.emit("request", request, response);
  });
}

function graphNodesForVerification(verification) {
  const nodes = new Map();
  nodes.set(verification.artifact.artifact_id, {
    ...verification.artifact,
    auth_state: "committed",
  });
  for (const source of verification.source_nodes) {
    nodes.set(source.artifact_id, {
      ...source,
      auth_state: "committed",
    });
  }
  for (const witness of verification.witnesses) {
    if (witness.parent_generation !== 1 || nodes.has(witness.parent_artifact_id)) {
      continue;
    }
    const outgoing = verification.witnesses.filter(
      (candidate) => candidate.child_artifact_id === witness.parent_artifact_id,
    );
    nodes.set(witness.parent_artifact_id, {
      artifact_id: witness.parent_artifact_id,
      role: outgoing[0]?.kind === "assert" ? "claim" : "summary",
      generation: 1,
      terminal: false,
      trust_state: "derived",
      auth_state: "committed",
      lineage_kind: outgoing[0]?.kind,
      parent_count: outgoing.length,
      content_hash: "e".repeat(64),
      authority_id: PROVENANCE_WRITER_ID,
      batch_id: outgoing[0]?.batch_id,
    });
  }
  return nodes;
}

function projectedNodeResponse(node) {
  const columns = [
    "vertex_id",
    "artifact_id",
    "role",
    "generation",
    "terminal",
    "trust_state",
    "auth_state",
    "lineage_kind",
    "parent_count",
    "content_hash",
    "authority_id",
    "batch_id",
  ];
  return {
    columns,
    rows: node
      ? [columns.map((column) => encodedCell(
        column === "vertex_id" ? deriveVertexId(node.artifact_id) : node[column],
      ))]
      : [],
  };
}

test("demo HTTP boundary accepts only a whitelisted scenario", () => {
  assert.deepEqual(validateDemoRequestBody({ scenario: "valid" }), { scenario: "valid" });
  assert.deepEqual(validateDemoRequestBody({ scenario: "tampered" }), { scenario: "tampered" });

  for (const forgedField of [
    "trusted_state",
    "witnesses",
    "verified",
    "policy_result",
    "fresh",
    "adapter",
    "provenance_artifact_id",
  ]) {
    assert.throws(
      () => validateDemoRequestBody({ scenario: "valid", [forgedField]: true }),
      /ONLY_SCENARIO_MAY_BE_SUBMITTED/,
    );
  }
  assert.throws(() => validateDemoRequestBody({ scenario: "unknown" }), /UNKNOWN_DEMO_SCENARIO/);
  assert.throws(() => validateDemoRequestBody(null), /REQUEST_BODY_MUST_BE_AN_OBJECT/);
});

test("demo HTTP boundary maps unexpected orchestration failure to a fail-closed response", async () => {
  const server = createDemoServer({
    orchestrator: Object.freeze({
      async assertReady() {},
      async run() {
        throw new Error("unexpected orchestration failure");
      },
    }),
  });

  const response = await invokeDemoServer(server, { scenario: "valid" });

  assert.equal(response.statusCode, 503);
  assert.equal(response.body.status, "BLOCK");
  assert.equal(response.body.reason_code, "BLOCK_SYSTEM_ERROR");
  assert.equal(response.body.detail, "DEMO_ORCHESTRATION_FAILED");
  assert.notEqual(response.body.status, "ALLOW");
});

test("demo HTTP boundary rejects lookalike JSON media types", async () => {
  let runCalls = 0;
  const server = createDemoServer({
    orchestrator: Object.freeze({
      async assertReady() {},
      async run() {
        runCalls += 1;
        return { status: "PASS" };
      },
    }),
  });

  const response = await invokeDemoServer(server, { scenario: "valid" }, "application/jsonx");

  assert.equal(response.statusCode, 415);
  assert.equal(response.body.status, "BLOCK");
  assert.equal(response.body.reason_code, "BLOCK_INVALID_INPUT");
  assert.equal(response.body.detail, "CONTENT_TYPE_MUST_BE_APPLICATION_JSON");
  assert.equal(runCalls, 0);
});

test("excess concurrent demo runs fail closed instead of queueing unbounded", async () => {
  let release;
  const hold = new Promise((resolve) => {
    release = resolve;
  });
  const hydra = Object.freeze({
    config: Object.freeze({
      httpBase: "http://127.0.0.1:1",
      adminBase: "http://127.0.0.1:2",
      graphId: "default",
      namespace: "default",
      cellId: "cell-0",
    }),
    async assertReady() {
      await hold;
    },
    async query() {
      throw new Error("must not query while the demo is busy");
    },
  });
  const orchestrator = createDemoOrchestrator({ hydra, now: () => 2_000 });
  const started = Array.from({ length: MAX_PENDING_DEMO_RUNS }, () => orchestrator.run("valid"));
  const busy = await orchestrator.run("tampered");
  release();
  const held = await Promise.all(started);

  assert.equal(busy.status, "FAIL");
  assert.equal(busy.gateway.reason_code, "BLOCK_SYSTEM_ERROR");
  assert.equal(busy.gateway.detail, "DEMO_BUSY");
  assert.equal(busy.action.executed, false);
  assert.equal(orchestrator.adapter.callCount(), 0);
  assert.equal(held.length, MAX_PENDING_DEMO_RUNS);
  assert.equal(held.every((result) => result.action.executed === false), true);
});

test("demo orchestrator fails closed when HydraDB is unavailable", async () => {
  const hydra = Object.freeze({
    config: Object.freeze({
      httpBase: "http://127.0.0.1:1",
      adminBase: "http://127.0.0.1:2",
      graphId: "default",
      namespace: "default",
      cellId: "cell-0",
    }),
    async assertReady() {
      throw new Error("HydraDB unavailable");
    },
    async query() {
      throw new Error("HydraDB unavailable");
    },
  });
  const orchestrator = createDemoOrchestrator({ hydra, now: () => 2_000 });
  const result = await orchestrator.run("valid");

  assert.equal(result.status, "FAIL");
  assert.equal(result.verification.status, "BLOCK");
  assert.equal(result.verification.reason_code, "BLOCK_SYSTEM_ERROR");
  assert.equal(result.gateway.status, "BLOCK");
  assert.equal(result.gateway.reason_code, "BLOCK_SYSTEM_ERROR");
  assert.equal(result.gateway.adapter_calls, 0);
  assert.equal(result.action.executed, false);
  assert.equal(orchestrator.adapter.callCount(), 0);
});

test("production refuses published proof keys", () => {
  const previousNodeEnv = process.env.NODE_ENV;
  const previousSigning = process.env.QUARANTINE_PROVENANCE_SIGNING_KEY;
  const previousConnector = process.env.QUARANTINE_CONNECTOR_ATTESTATION_KEY;
  process.env.NODE_ENV = "production";
  delete process.env.QUARANTINE_PROVENANCE_SIGNING_KEY;
  delete process.env.QUARANTINE_CONNECTOR_ATTESTATION_KEY;
  try {
    assert.throws(
      () => createDemoOrchestrator({
        hydra: Object.freeze({
          config: Object.freeze({
            httpBase: "http://127.0.0.1:1",
            adminBase: "http://127.0.0.1:2",
            graphId: "default",
            namespace: "default",
            cellId: "cell-0",
          }),
          async assertReady() {},
          async query() {
            throw new Error("must not query");
          },
        }),
      }),
      /Production demo requires/,
    );
  } finally {
    if (previousNodeEnv === undefined) {
      delete process.env.NODE_ENV;
    } else {
      process.env.NODE_ENV = previousNodeEnv;
    }
    if (previousSigning === undefined) {
      delete process.env.QUARANTINE_PROVENANCE_SIGNING_KEY;
    } else {
      process.env.QUARANTINE_PROVENANCE_SIGNING_KEY = previousSigning;
    }
    if (previousConnector === undefined) {
      delete process.env.QUARANTINE_CONNECTOR_ATTESTATION_KEY;
    } else {
      process.env.QUARANTINE_CONNECTOR_ATTESTATION_KEY = previousConnector;
    }
  }
});

test("unknown direct demo scenario is invalid input and cannot execute", async () => {
  const hydra = Object.freeze({
    config: Object.freeze({
      httpBase: "http://127.0.0.1:1",
      adminBase: "http://127.0.0.1:2",
      graphId: "default",
      namespace: "default",
      cellId: "cell-0",
    }),
    async assertReady() {
      throw new Error("must not be called");
    },
    async query() {
      throw new Error("must not be called");
    },
  });
  const orchestrator = createDemoOrchestrator({ hydra, now: () => 2_000 });
  const result = await orchestrator.run("caller-controlled");

  assert.equal(result.status, "FAIL");
  assert.equal(result.verification.reason_code, "BLOCK_INVALID_INPUT");
  assert.equal(result.gateway.status, "BLOCK");
  assert.equal(result.gateway.adapter_calls, 0);
  assert.equal(orchestrator.adapter.callCount(), 0);
});

test("graph hydration failure happens before authorization and cannot hide execution", async () => {
  const fixture = createHydrationFailureFixture(async () => {
    throw new Error("DISPLAY_GRAPH_HYDRATION_FAILED");
  });

  const result = await fixture.orchestrator.run("valid");

  assert.equal(result.status, "FAIL");
  assert.equal(result.verification.reason_code, "BLOCK_SYSTEM_ERROR");
  assert.equal(result.verification.detail, "DEMO_ORCHESTRATION_FAILED");
  assert.equal(result.gateway.detail, "DEMO_ORCHESTRATION_FAILED");
  assert.equal(result.timeline[0].detail.includes("DISPLAY_GRAPH_HYDRATION_FAILED"), false);
  assert.equal(result.gateway.adapter_calls, 0);
  assert.equal(result.action.executed, false);
  assert.equal(fixture.orchestrator.adapter.callCount(), 0);
  assert.equal(fixture.verifierCalls(), 2);
});

test("empty graph hydration rows fail closed before authorization", async () => {
  const fixture = createHydrationFailureFixture(async () => ({
    columns: [],
    rows: [],
  }));

  const result = await fixture.orchestrator.run("valid");

  assert.equal(result.status, "FAIL");
  assert.equal(result.verification.reason_code, "BLOCK_SYSTEM_ERROR");
  assert.equal(result.verification.detail, "DEMO_ORCHESTRATION_FAILED");
  assert.equal(result.gateway.detail, "DEMO_ORCHESTRATION_FAILED");
  assert.equal(result.timeline[0].detail.includes("GRAPH_NODE_HYDRATION_INCOMPLETE"), false);
  assert.equal(result.gateway.adapter_calls, 0);
  assert.equal(result.action.executed, false);
  assert.equal(fixture.orchestrator.adapter.callCount(), 0);
  assert.equal(fixture.verifierCalls(), 2);
});

test("orchestrator uses one depth-2 gateway for the verified closure", async () => {
  const depthCalls = [];
  const verification = validDemoVerification(`${DEMO_VERSION}:valid:action-argument`, 2);
  const nodes = graphNodesForVerification(verification);
  const hydra = Object.freeze({
    config: Object.freeze({
      httpBase: "http://127.0.0.1:1",
      adminBase: "http://127.0.0.1:2",
      graphId: "default",
      namespace: "default",
      cellId: "cell-0",
    }),
    async assertReady() {},
    async query(query, parameters) {
      assert.match(query, /^MATCH \(n:ProvenanceArtifact/);
      const node = [...nodes.values()].find(
        (candidate) => deriveVertexId(candidate.artifact_id) === parameters.vertex_id,
      );
      return projectedNodeResponse(node);
    },
  });
  const writer = Object.freeze({
    async registerTrustedSource() {
      return { status: "PASS" };
    },
    async prepareTransformation() {
      return { status: "PASS", context: Object.freeze({}) };
    },
    async writeDerivedArtifact() {
      return { status: "PASS" };
    },
    async verifyProvenanceState(artifactId, { maxDepth }) {
      depthCalls.push(maxDepth);
      return {
        ...validDemoVerification(artifactId, maxDepth),
        graph_snapshot: {
          ...verification.graph_snapshot,
          max_depth: maxDepth,
        },
      };
    },
  });
  const orchestrator = createDemoOrchestrator({ hydra, writer, now: () => 2_000 });

  const result = await orchestrator.run("valid");

  assert.equal(result.status, "PASS");
  assert.equal(result.gateway.status, "ALLOW");
  assert.equal(result.action.executed, true);
  assert.equal(result.graph.metrics.node_count, 5);
  assert.equal(result.graph.metrics.edge_count, 4);
  assert.equal(result.graph.metrics.path_count, 2);
  assert.equal(result.graph.metrics.max_depth, 2);
  assert.deepEqual(depthCalls, [16, 2, 2]);
  assert.equal(orchestrator.adapter.callCount(), 1);
});

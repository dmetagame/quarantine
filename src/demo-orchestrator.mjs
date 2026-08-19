import {
  createHash,
  createHmac,
} from "node:crypto";

import {
  createHydraClient,
  projectedRows,
  singleScalar,
} from "./hydradb-client.mjs";
import {
  ACTION_GATEWAY_VERSION,
  ACTION_POLICY_VERSION,
  BLOCK_INVALID_INPUT,
  BLOCK_SYSTEM_ERROR,
  BLOCK_UNRESOLVED_ANCESTRY,
  TRUSTED_STATE_CONTRACT_VERSION,
  createActionGateway,
  createDryRunActionAdapter,
  validateActionIntent,
} from "./action-gateway.mjs";
import {
  PROVENANCE_STATE_VERIFIER_VERSION,
  createProvenanceWriter,
  deriveVertexId,
} from "./provenance-writer.mjs";

export const DEMO_VERSION = "quarantine-demo-v2";
export const DEMO_SCENARIOS = Object.freeze(["valid", "tampered"]);
export const DEMO_OBSERVATION_MAX_DEPTH = 16;
export const DEMO_AUTHORIZATION_MAX_DEPTH = 2;

const DEFAULT_SIGNING_KEY = "local-provenance-writer-test-key-2026";
const DEFAULT_CONNECTOR_KEY = "local-connector-attestation-key-2026";
const CONNECTOR_ISSUER = "quarantine-proof-connector";
const CONNECTOR_KEY_ID = "local-evidence-key-v1";
const FRESHNESS_MS = 5_000;

const IDS = Object.freeze({
  catalogSource: `${DEMO_VERSION}:source:catalog`,
  incidentSource: `${DEMO_VERSION}:source:incident`,
  attackSource: `${DEMO_VERSION}:source:attack`,
  validClaim: `${DEMO_VERSION}:valid:claim`,
  validSummary: `${DEMO_VERSION}:valid:summary`,
  validArgument: `${DEMO_VERSION}:valid:action-argument`,
  attackSummaryOne: `${DEMO_VERSION}:tampered:summary-1`,
  attackSummaryTwo: `${DEMO_VERSION}:tampered:summary-2`,
  attackArgument: `${DEMO_VERSION}:tampered:action-argument`,
  subject: `${DEMO_VERSION}:subject:incident`,
  forgedChild: `${DEMO_VERSION}:attack:forged-child`,
  forgedParent: `${DEMO_VERSION}:attack:forged-parent`,
});

const DISPLAY_LABELS = Object.freeze({
  [IDS.catalogSource]: "Trusted catalog",
  [IDS.incidentSource]: "Incident feed",
  [IDS.attackSource]: "Trusted source",
  [IDS.validClaim]: "Catalog rule",
  [IDS.validSummary]: "Leak observed",
  [IDS.validArgument]: "Alert argument",
  [IDS.attackSummaryOne]: "Summary layer 1",
  [IDS.attackSummaryTwo]: "Summary layer 2",
  [IDS.attackArgument]: "Unresolved alert",
});

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function hmac(key, fields) {
  return createHmac("sha256", key)
    .update(JSON.stringify(fields), "utf8")
    .digest("hex");
}

function attestationMessage(source) {
  return [
    "connector-attestation-v1",
    source.id,
    sha256(source.content),
    CONNECTOR_ISSUER,
    CONNECTOR_KEY_ID,
  ];
}

function attestSource(id, content, connectorKey) {
  const source = { id, content };
  return {
    ...source,
    attestation: {
      issuer: CONNECTOR_ISSUER,
      key_id: CONNECTOR_KEY_ID,
      signature: hmac(connectorKey, attestationMessage(source)),
    },
  };
}

function validParameters() {
  return Object.freeze({
    data_class: "internal",
    destination: "internal:alerts",
    payload: "Catalog and incident evidence support an internal alert.",
  });
}

function tamperedParameters() {
  return Object.freeze({
    data_class: "internal",
    destination: "internal:alerts",
    payload: "An adversarial summary requests an internal alert before its ancestry is resolved.",
  });
}

function createIntent(scenario, sequence, requestedAt) {
  const prefix = `${DEMO_VERSION}:request:${scenario}:${sequence}`;
  return Object.freeze({
    action_id: `${DEMO_VERSION}:action:${scenario}:${sequence}`,
    subject_id: IDS.subject,
    action_type: "send_message",
    parameters: scenario === "valid" ? validParameters() : tamperedParameters(),
    request_id: prefix,
    requested_at: requestedAt,
    provenance_artifact_id: scenario === "valid" ? IDS.validArgument : IDS.attackArgument,
  });
}

function requirePass(result, description) {
  if (!result || result.status !== "PASS") {
    throw new Error(`${description}: ${JSON.stringify(result)}`);
  }
  return result;
}

function formatTime(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    return "unknown";
  }
  return new Date(value).toISOString().slice(11, 19);
}

function timelineEvent(label, status, detail, at) {
  return Object.freeze({
    label,
    status,
    detail,
    at: formatTime(at),
  });
}

function outcomeStatus(result) {
  if (result?.status === "PASS" || result?.status === "ALLOW") {
    return "PASS";
  }
  if (result?.status === "BLOCK") {
    return "BLOCK";
  }
  return "NOT_REACHED";
}

function countPaths(rootId, sourceIds, witnesses) {
  const adjacency = new Map();
  for (const edge of witnesses) {
    const outgoing = adjacency.get(edge.child_artifact_id) ?? [];
    outgoing.push(edge.parent_artifact_id);
    adjacency.set(edge.child_artifact_id, outgoing);
  }
  const memo = new Map();
  function pathsFrom(artifactId, visiting = new Set()) {
    if (sourceIds.has(artifactId)) {
      return 1;
    }
    if (memo.has(artifactId)) {
      return memo.get(artifactId);
    }
    if (visiting.has(artifactId)) {
      return 0;
    }
    const nextVisiting = new Set(visiting);
    nextVisiting.add(artifactId);
    const count = (adjacency.get(artifactId) ?? [])
      .reduce((total, parentId) => total + pathsFrom(parentId, nextVisiting), 0);
    memo.set(artifactId, count);
    return count;
  }
  return pathsFrom(rootId);
}

export function createDemoOrchestrator(options = {}) {
  const hydra = options.hydra ?? createHydraClient();
  const signingKey = options.signingKey
    ?? process.env.QUARANTINE_PROVENANCE_SIGNING_KEY
    ?? DEFAULT_SIGNING_KEY;
  const connectorKey = options.connectorKey
    ?? process.env.QUARANTINE_CONNECTOR_ATTESTATION_KEY
    ?? DEFAULT_CONNECTOR_KEY;
  const now = options.now ?? (() => Date.now());
  const writer = options.writer ?? createProvenanceWriter({
    hydra,
    signingKey,
    verifyTrustedSource: async (source) => source.attestation?.issuer === CONNECTOR_ISSUER
      && source.attestation?.key_id === CONNECTOR_KEY_ID
      && source.attestation?.signature === hmac(connectorKey, attestationMessage(source)),
  });
  const adapter = createDryRunActionAdapter();

  // These are capabilities, not request-scoped objects. In particular, the
  // replay ledger survives each demo request inside this process.
  const gatewayOptions = {
    verifyProvenanceState: (artifactId, verificationOptions) => writer.verifyProvenanceState(
      artifactId,
      verificationOptions,
    ),
    actionAdapter: adapter,
    now,
    maxFreshnessMs: FRESHNESS_MS,
    verificationTimeoutMs: 5_000,
    allowedSourceAuthorities: [CONNECTOR_ISSUER],
  };
  const gateway = createActionGateway({
    ...gatewayOptions,
    maxAncestryDepth: DEMO_AUTHORIZATION_MAX_DEPTH,
  });

  let fixturePromise = null;
  let runSequence = 0;
  let runQueue = Promise.resolve();

  function timelineNow() {
    try {
      const value = now();
      return Number.isSafeInteger(value) && value >= 0 ? value : null;
    } catch {
      return null;
    }
  }

  async function assertReady() {
    await hydra.assertReady();
    return {
      status: "PASS",
      graph: hydra.config.graphId,
      namespace: hydra.config.namespace,
      cell: hydra.config.cellId,
      endpoint: hydra.config.httpBase,
    };
  }

  async function writeDerived({ artifactId, role, parentIds, kind, content }) {
    const prepared = requirePass(await writer.prepareTransformation({
      artifactId,
      role,
      observedParentIds: parentIds,
      kind,
    }), `Preparing ${artifactId}`);
    return requirePass(await writer.writeDerivedArtifact({
      context: prepared.context,
      producerOutput: { content },
    }), `Writing ${artifactId}`);
  }

  async function ensureFixtures() {
    const validIntent = createIntent("valid", 0, 0);
    const tamperedIntent = createIntent("tampered", 0, 0);
    const validValidated = requirePass(validateActionIntent(validIntent), "Validating valid fixture intent");
    const tamperedValidated = requirePass(validateActionIntent(tamperedIntent), "Validating tampered fixture intent");

    const sourceResults = await Promise.all([
      writer.registerTrustedSource(attestSource(
        IDS.catalogSource,
        "Internal incident catalog: a confirmed token leak requires credential rotation.",
        connectorKey,
      )),
      writer.registerTrustedSource(attestSource(
        IDS.incidentSource,
        "Incident feed: a service-account token was observed in a public artifact.",
        connectorKey,
      )),
      writer.registerTrustedSource(attestSource(
        IDS.attackSource,
        "Incident feed: an adversarial summary has no bounded terminal authority.",
        connectorKey,
      )),
    ]);
    sourceResults.forEach((result, index) => requirePass(result, `Registering demo source ${index + 1}`));

    const validClaim = await writeDerived({
      artifactId: IDS.validClaim,
      role: "claim",
      parentIds: [IDS.catalogSource],
      kind: "assert",
      content: "Catalog rule: a confirmed token leak requires credential rotation.",
    });
    const validSummary = await writeDerived({
      artifactId: IDS.validSummary,
      role: "summary",
      parentIds: [IDS.incidentSource],
      kind: "summarize",
      content: "Incident feed: the observed token matches the catalog rule's trigger.",
    });
    const validArgument = await writeDerived({
      artifactId: IDS.validArgument,
      role: "action_argument",
      parentIds: [IDS.validClaim, IDS.validSummary],
      kind: "require",
      content: validValidated.semantic_payload,
    });

    const attackSummaryOne = await writeDerived({
      artifactId: IDS.attackSummaryOne,
      role: "summary",
      parentIds: [IDS.attackSource],
      kind: "summarize",
      content: "Adversarial summary layer one.",
    });
    const attackSummaryTwo = await writeDerived({
      artifactId: IDS.attackSummaryTwo,
      role: "summary",
      parentIds: [IDS.attackSummaryOne],
      kind: "summarize",
      content: "Adversarial summary layer two.",
    });
    const attackArgument = await writeDerived({
      artifactId: IDS.attackArgument,
      role: "action_argument",
      parentIds: [IDS.attackSummaryTwo],
      kind: "require",
      content: tamperedValidated.semantic_payload,
    });

    return Object.freeze({
      sourceResults,
      validClaim,
      validSummary,
      validArgument,
      attackSummaryOne,
      attackSummaryTwo,
      attackArgument,
    });
  }

  async function ensureFixturesOnce() {
    if (!fixturePromise) {
      fixturePromise = ensureFixtures().catch((error) => {
        fixturePromise = null;
        throw error;
      });
    }
    return fixturePromise;
  }

  async function readNode(artifactId) {
    const response = await hydra.query(
      "MATCH (n:ProvenanceArtifact {id: $vertex_id}) RETURN n.id AS vertex_id, n.artifact_id AS artifact_id, n.role AS role, n.generation AS generation, n.terminal AS terminal, n.trust_state AS trust_state, n.auth_state AS auth_state, n.lineage_kind AS lineage_kind, n.parent_count AS parent_count, n.content_hash AS content_hash, n.authority_id AS authority_id, n.batch_id AS batch_id",
      { vertex_id: deriveVertexId(artifactId) },
    );
    const rows = projectedRows(response);
    if (rows.length > 1) {
      throw new Error(`GRAPH_NODE_HYDRATION_AMBIGUOUS:${artifactId}`);
    }
    return rows[0] ?? null;
  }

  async function graphForVerification(verification, options = {}) {
    const ids = new Set();
    ids.add(verification.artifact.artifact_id);
    verification.source_nodes.forEach((source) => ids.add(source.artifact_id));
    verification.witnesses.forEach((witness) => {
      ids.add(witness.child_artifact_id);
      ids.add(witness.parent_artifact_id);
    });
    const expectedArtifactIds = [...ids];
    const rows = await Promise.all(expectedArtifactIds.map((artifactId) => readNode(artifactId)));
    const missingArtifactIds = expectedArtifactIds.filter((artifactId, index) => !rows[index]);
    if (missingArtifactIds.length > 0) {
      throw new Error(`GRAPH_NODE_HYDRATION_INCOMPLETE:${missingArtifactIds.join(",")}`);
    }
    const mismatchedArtifactIds = expectedArtifactIds.filter(
      (artifactId, index) => rows[index].artifact_id !== artifactId,
    );
    if (mismatchedArtifactIds.length > 0) {
      throw new Error(`GRAPH_NODE_HYDRATION_MISMATCH:${mismatchedArtifactIds.join(",")}`);
    }
    if (expectedArtifactIds.length !== verification.graph_snapshot.node_count
      || verification.witnesses.length !== verification.graph_snapshot.edge_count) {
      throw new Error("GRAPH_SNAPSHOT_HYDRATION_MISMATCH");
    }
    const nodes = rows
      .map((node) => Object.freeze({
        ...node,
        label: DISPLAY_LABELS[node.artifact_id] ?? node.artifact_id,
        ...(node.artifact_id === options.frontierArtifactId
          ? { verification_status: "BLOCK" }
          : {}),
      }))
      .sort((left, right) => left.generation - right.generation
        || left.artifact_id.localeCompare(right.artifact_id));
    const edges = verification.witnesses.map((witness) => Object.freeze({
      edge_id: witness.edge_id,
      source: witness.parent_artifact_id,
      target: witness.child_artifact_id,
      stored_child: witness.child_artifact_id,
      stored_parent: witness.parent_artifact_id,
      kind: witness.kind,
      child_generation: witness.child_generation,
      parent_generation: witness.parent_generation,
      batch_id: witness.batch_id,
    }));
    const sourceIds = new Set(verification.source_nodes.map((source) => source.artifact_id));
    const pathCount = countPaths(verification.artifact.artifact_id, sourceIds, verification.witnesses);
    return Object.freeze({
      nodes,
      edges,
      metrics: {
        node_count: verification.graph_snapshot.node_count,
        edge_count: verification.graph_snapshot.edge_count,
        witness_count: verification.witnesses.length,
        path_count: pathCount,
        deepest_hops: verification.graph_snapshot.deepest_hops,
        max_depth: options.authorizationMaxDepth ?? verification.graph_snapshot.max_depth,
        ancestry_status: options.ancestryStatus ?? verification.ancestry_status,
      },
      direction_note: "Displayed flow is source to action; stored DERIVES_FROM edges are child to parent.",
    });
  }

  async function forgedParentProbe() {
    const prepared = await writer.prepareTransformation({
      artifactId: IDS.forgedChild,
      role: "summary",
      observedParentIds: [IDS.catalogSource],
      kind: "summarize",
    });
    const result = prepared.status === "PASS"
      ? await writer.writeDerivedArtifact({
        context: prepared.context,
        producerOutput: {
          content: "Attacker-controlled summary.",
          parent_ids: [IDS.forgedParent],
        },
      })
      : prepared;
    const childCount = singleScalar(await hydra.query(
      "MATCH (n:ProvenanceArtifact {id: $vertex_id}) RETURN count(*) AS total",
      { vertex_id: deriveVertexId(IDS.forgedChild) },
    ), "forged child count");
    const forgedParentCount = singleScalar(await hydra.query(
      "MATCH (n:ProvenanceArtifact {id: $vertex_id}) RETURN count(*) AS total",
      { vertex_id: deriveVertexId(IDS.forgedParent) },
    ), "forged parent count");
    if (result.status !== "BLOCK"
      || result.reason_code !== "BLOCK_INVALID_PROVENANCE"
      || result.detail !== "UNTRUSTED_CONTROL_FIELD"
      || childCount !== 0
      || forgedParentCount !== 0) {
      throw new Error(`FORGED_PARENT_PROBE_FAILED: ${JSON.stringify({
        result,
        childCount,
        forgedParentCount,
      })}`);
    }
    return Object.freeze({
      status: result.status,
      expected_result: "BLOCK",
      actual_result: result.status === "BLOCK" ? "BLOCK" : result.status,
      reason_code: result.reason_code,
      detail: result.detail,
      child_vertices: childCount,
      forged_parent_vertices: forgedParentCount,
      edge_created: childCount > 0,
      producer_parent_ids_rejected: true,
    });
  }

  function checksFor({ scenario, fullVerification, boundedVerification, gatewayResult }) {
    const boundedPass = boundedVerification.status === "PASS";
    const gatewayAllowed = gatewayResult.status === "ALLOW";
    return [
      {
        label: "Root artifact identified",
        status: fullVerification.status === "PASS" ? "PASS" : "BLOCK",
        detail: fullVerification.status === "PASS" ? "HydraDB returned the signed action argument." : fullVerification.detail,
      },
      {
        label: "Ancestry resolved within gateway bound",
        status: boundedPass ? "PASS" : "BLOCK",
        detail: boundedPass ? "Every required branch reached a trusted terminal source." : boundedVerification.detail,
      },
      {
        label: "Authenticated witnesses present",
        status: fullVerification.witnesses.length > 0 ? "PASS" : "BLOCK",
        detail: `${fullVerification.witnesses.length} signed lineage edge(s) observed from HydraDB.`,
      },
      {
        label: "Graph snapshot verified",
        status: fullVerification.status === "PASS" ? "PASS" : "BLOCK",
        detail: `${fullVerification.graph_snapshot.node_count} nodes / ${fullVerification.graph_snapshot.edge_count} edges at strong consistency.`,
      },
      {
        label: "Freshness",
        status: gatewayAllowed ? "PASS" : "NOT_REACHED",
        detail: gatewayAllowed ? "Trusted clock window valid." : "Gateway stopped before freshness authorization.",
      },
      {
        label: "Deterministic policy",
        status: gatewayAllowed ? "PASS" : "NOT_REACHED",
        detail: gatewayAllowed ? "Internal destination and source authority allowed." : "Policy was not evaluated after provenance blocked.",
      },
      {
        label: "Replay protection",
        status: gatewayAllowed ? "PASS" : "NOT_REACHED",
        detail: gatewayAllowed ? "Request identity reserved once." : "No action reservation was created.",
      },
    ].map((check) => Object.freeze(check));
  }

  function failureResponse(scenario, error, reasonCode = BLOCK_SYSTEM_ERROR) {
    const detail = error?.message || "DEMO_ORCHESTRATION_FAILED";
    return Object.freeze({
      status: "FAIL",
      scenario,
      demo_version: DEMO_VERSION,
      evidence: {
        source: "Unavailable",
        entity: IDS.subject,
        claim: "The trusted graph response could not be established.",
        received_at: null,
        classification: "UNVERIFIED",
      },
      graph: {
        nodes: [],
        edges: [],
        metrics: {
          node_count: 0,
          edge_count: 0,
          witness_count: 0,
          path_count: 0,
          deepest_hops: 0,
          max_depth: DEMO_AUTHORIZATION_MAX_DEPTH,
          ancestry_status: "UNRESOLVED",
        },
        direction_note: "No graph was accepted because HydraDB verification failed.",
      },
      verification: {
        status: "BLOCK",
        result: null,
        reason_code: reasonCode,
        detail,
        checks: [],
        observation_status: "SYSTEM_ERROR",
      },
      policy: {
        status: "NOT_REACHED",
        reason_code: reasonCode,
        detail: "Policy was not evaluated.",
      },
      gateway: {
        status: "BLOCK",
        reason_code: reasonCode,
        detail,
        adapter_calls: 0,
      },
      action: {
        status: "BLOCK",
        executed: false,
        adapter_calls: 0,
        result: null,
        reason_code: reasonCode,
        detail: "ACTION_NOT_EXECUTED",
      },
      attack_probe: null,
      timeline: [timelineEvent("Action gateway BLOCK", "BLOCK", `${reasonCode}: ${detail}`, timelineNow())],
      meta: {
        hydradb: {
          http: hydra.config.httpBase,
          admin: hydra.config.adminBase,
          graph: hydra.config.graphId,
          namespace: hydra.config.namespace,
          cell: hydra.config.cellId,
          consistency: "strong",
        },
        gateway_version: ACTION_GATEWAY_VERSION,
        trusted_state_contract_version: TRUSTED_STATE_CONTRACT_VERSION,
        policy_version: ACTION_POLICY_VERSION,
        verifier_version: PROVENANCE_STATE_VERIFIER_VERSION,
      },
    });
  }

  async function runOne(scenario) {
    if (!DEMO_SCENARIOS.includes(scenario)) {
      return failureResponse("valid", new Error("UNKNOWN_DEMO_SCENARIO"), BLOCK_INVALID_INPUT);
    }
    const startedAt = now();
    const sequence = ++runSequence;
    const intent = createIntent(scenario, sequence, startedAt);
    const timeline = [timelineEvent(
      "Evidence received",
      "PASS",
      scenario === "valid"
        ? "Incoming evidence is untrusted until the trusted writer and verifier establish its lineage."
        : "Adversarial evidence includes a caller-supplied parent claim and an ancestry beyond the gateway bound.",
      startedAt,
    )];

    await assertReady();
    await ensureFixturesOnce();
    timeline.push(timelineEvent("HydraDB graph prepared", "PASS", "Server-owned fixtures were written and read through the real HydraDB client.", timelineNow()));

    const artifactId = intent.provenance_artifact_id;
    const fullVerification = await writer.verifyProvenanceState(
      artifactId,
      { maxDepth: DEMO_OBSERVATION_MAX_DEPTH },
    );
    requirePass(fullVerification, `Observing ${artifactId}`);
    timeline.push(timelineEvent(
      "Provenance observed",
      "PASS",
      `${fullVerification.source_nodes.length} trusted source(s), ${fullVerification.witnesses.length} authenticated edge witness(es), ${fullVerification.graph_snapshot.node_count} graph node(s).`,
      timelineNow(),
    ));

    const attackProbe = scenario === "tampered" ? await forgedParentProbe() : null;
    if (attackProbe) {
      timeline.push(timelineEvent(
        "Forged parent claim rejected",
        outcomeStatus(attackProbe),
        `${attackProbe.reason_code}: ${attackProbe.detail}; child vertices ${attackProbe.child_vertices}, forged parent vertices ${attackProbe.forged_parent_vertices}.`,
        timelineNow(),
      ));
    }

    const boundedVerification = await writer.verifyProvenanceState(
      artifactId,
      { maxDepth: DEMO_AUTHORIZATION_MAX_DEPTH },
    );
    // Complete every fallible display read before authorization. Once the
    // adapter runs, response assembly below must not be able to hide execution
    // behind a later HydraDB hydration failure.
    const graph = await graphForVerification(fullVerification, {
      ancestryStatus: boundedVerification.status === "PASS" ? "RESOLVED" : "UNRESOLVED",
      authorizationMaxDepth: DEMO_AUTHORIZATION_MAX_DEPTH,
      frontierArtifactId: boundedVerification.frontier_artifact_id,
    });

    const beforeCalls = adapter.callCount();
    const gatewayResult = await gateway.authorizeAndExecute(intent);
    const allCalls = adapter.calls();
    const adapterCalls = allCalls.slice(beforeCalls);
    const gatewayAllowed = gatewayResult.status === "ALLOW";
    const expectedAttackBlock = scenario === "tampered"
      && gatewayResult.reason_code === BLOCK_UNRESOLVED_ANCESTRY;
    if (scenario === "valid" && !gatewayAllowed) {
      throw new Error(`VALID_DEMO_NOT_ALLOWED: ${JSON.stringify(gatewayResult)}`);
    }
    if (scenario === "tampered" && (!expectedAttackBlock || adapterCalls.length !== 0)) {
      throw new Error(`TAMPERED_DEMO_NOT_FAIL_CLOSED: ${JSON.stringify(gatewayResult)}`);
    }

    const checks = checksFor({
      scenario,
      fullVerification,
      boundedVerification,
      gatewayResult,
    });
    timeline.push(timelineEvent(
      "Gateway verification",
      boundedVerification.status === "PASS" ? "PASS" : "BLOCK",
      boundedVerification.status === "PASS"
        ? "Bounded ancestry resolved to trusted terminal sources."
        : `${boundedVerification.reason_code}: ${boundedVerification.detail}`,
      timelineNow(),
    ));
    timeline.push(timelineEvent(
      "Policy evaluated",
      gatewayAllowed ? "PASS" : "NOT_REACHED",
      gatewayAllowed ? "Deterministic policy allowed the internal alert destination." : "Policy was not evaluated after provenance failed closed.",
      timelineNow(),
    ));
    timeline.push(timelineEvent(
      "Action gateway decision",
      gatewayAllowed ? "PASS" : "BLOCK",
      gatewayAllowed ? "ACTION_AUTHORIZED" : `${gatewayResult.reason_code}: ${gatewayResult.detail}`,
      timelineNow(),
    ));
    timeline.push(timelineEvent(
      gatewayAllowed ? "Dry-run action executed" : "Action adapter not invoked",
      gatewayAllowed ? "PASS" : "BLOCK",
      gatewayAllowed
        ? `DRY_RUN / adapter calls this run: ${adapterCalls.length}.`
        : "The gateway returned before an authorized action capability could reach the adapter.",
      timelineNow(),
    ));

    return Object.freeze({
      status: "PASS",
      scenario,
      demo_version: DEMO_VERSION,
      intent: {
        action_id: intent.action_id,
        subject_id: intent.subject_id,
        action_type: intent.action_type,
        destination: intent.parameters.destination,
        data_class: intent.parameters.data_class,
        payload: intent.parameters.payload,
        request_id: intent.request_id,
      },
      evidence: {
        source: scenario === "valid" ? "Internal catalog + incident feed" : "Adversarial producer output",
        entity: "service-account-token",
        claim: scenario === "valid"
          ? "A confirmed token leak requires an internal credential-rotation alert."
          : "An attacker claims a deep summary justifies an internal alert.",
        received_at: formatTime(startedAt),
        classification: scenario === "valid" ? "UNTRUSTED INPUT" : "ADVERSARIAL INPUT",
      },
      graph,
      verification: {
        status: boundedVerification.status,
        result: boundedVerification.status === "PASS" ? boundedVerification.result : null,
        reason_code: gatewayResult.reason_code,
        detail: gatewayResult.detail,
        observation_status: fullVerification.status,
        observation_result: fullVerification.result,
        ancestry_status: graph.metrics.ancestry_status,
        frontier_artifact_id: boundedVerification.frontier_artifact_id ?? null,
        witnesses: fullVerification.witnesses,
        source_nodes: fullVerification.source_nodes,
        graph_snapshot: graph.metrics,
        checks,
      },
      policy: {
        status: gatewayAllowed ? "PASS" : "NOT_REACHED",
        result: gatewayAllowed ? "POLICY_ALLOW" : null,
        reason_code: gatewayAllowed ? null : gatewayResult.reason_code,
        detail: gatewayAllowed ? "POLICY_ALLOW" : "POLICY_NOT_REACHED",
      },
      gateway: {
        status: gatewayResult.status,
        result: gatewayResult.result ?? null,
        reason_code: gatewayResult.reason_code,
        detail: gatewayResult.detail,
        authorization_id: gatewayResult.authorization_id ?? null,
        trusted_state_id: gatewayResult.trusted_state_id ?? null,
        policy_version: gatewayResult.policy_version ?? null,
        adapter_calls: adapterCalls.length,
      },
      action: {
        status: gatewayAllowed ? "ALLOW" : "BLOCK",
        executed: gatewayAllowed && adapterCalls.length === 1,
        adapter_calls: adapterCalls.length,
        result: gatewayAllowed ? (gatewayResult.adapter_result ?? null) : null,
        adapter_result: gatewayAllowed ? gatewayResult.adapter_result?.status ?? null : null,
        reason_code: gatewayResult.reason_code,
        detail: gatewayAllowed ? "DRY_RUN" : "ACTION_NOT_EXECUTED",
        action_type: intent.action_type,
        destination: intent.parameters.destination,
      },
      attack_probe: attackProbe,
      timeline,
      meta: {
        hydradb: {
          http: hydra.config.httpBase,
          admin: hydra.config.adminBase,
          graph: hydra.config.graphId,
          namespace: hydra.config.namespace,
          cell: hydra.config.cellId,
          consistency: "strong",
        },
        gateway_version: ACTION_GATEWAY_VERSION,
        trusted_state_contract_version: TRUSTED_STATE_CONTRACT_VERSION,
        policy_version: ACTION_POLICY_VERSION,
        verifier_version: PROVENANCE_STATE_VERIFIER_VERSION,
        observation_max_depth: DEMO_OBSERVATION_MAX_DEPTH,
        authorization_max_depth: DEMO_AUTHORIZATION_MAX_DEPTH,
        freshness_ms: FRESHNESS_MS,
      },
    });
  }

  async function run(scenario = "valid") {
    const task = runQueue.then(async () => {
      try {
        return await runOne(scenario);
      } catch (error) {
        return failureResponse(scenario, error);
      }
    });
    runQueue = task.then(() => undefined, () => undefined);
    return task;
  }

  return Object.freeze({
    assertReady,
    run,
    ids: IDS,
    hydraConfig: hydra.config,
    adapter,
  });
}

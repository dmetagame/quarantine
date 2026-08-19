import assert from "node:assert/strict";
import test from "node:test";

import {
  BLOCK_INVALID_INPUT,
  BLOCK_INVALID_PROVENANCE,
  BLOCK_MISSING_PROVENANCE,
  BLOCK_POLICY,
  BLOCK_REPLAY,
  BLOCK_STALE,
  BLOCK_SYSTEM_ERROR,
  BLOCK_UNRESOLVED_ANCESTRY,
  createActionAdapter,
  createActionGateway,
  createDryRunActionAdapter,
  validateActionIntent,
} from "../src/action-gateway.mjs";

const baseIntent = Object.freeze({
  action_id: "action-001",
  subject_id: "subject-001",
  action_type: "send_message",
  parameters: Object.freeze({
    data_class: "internal",
    destination: "internal:alerts",
    payload: "Approved action payload",
  }),
  request_id: "request-001",
  requested_at: 1_000,
  provenance_artifact_id: "action-argument-001",
});

function verificationFor(intent = baseIntent, overrides = {}) {
  const validated = validateActionIntent(intent);
  assert.equal(validated.status, "PASS");
  return {
    status: "PASS",
    result: "PROVENANCE_STATE_VERIFIED",
    reason_code: null,
    classification: "VERIFIED",
    verifier_version: "provenance-state-verifier-v1",
    artifact: {
      artifact_id: intent.provenance_artifact_id,
      vertex_id: 101,
      role: "action_argument",
      lineage_kind: "require",
      generation: 1,
      parent_count: 1,
      terminal: false,
      content_hash: validated.semantic_digest,
      trust_state: "derived",
      authority_id: "quarantine-writer-v1",
      batch_id: "a".repeat(64),
    },
    ancestry_status: "RESOLVED",
    source_nodes: [{
      artifact_id: "source-001",
      vertex_id: 100,
      role: "source",
      lineage_kind: "source",
      generation: 0,
      parent_count: 0,
      terminal: true,
      content_hash: "c".repeat(64),
      trust_state: "trusted_source",
      authority_id: "connector-001",
      batch_id: "b".repeat(64),
    }],
    witnesses: [{
      edge_id: 7,
      child_artifact_id: intent.provenance_artifact_id,
      parent_artifact_id: "source-001",
      kind: "require",
      child_generation: 1,
      parent_generation: 0,
      batch_id: "a".repeat(64),
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
    now: options.now ?? (() => 1_001),
    maxFreshnessMs: options.maxFreshnessMs ?? 100,
    maxAncestryDepth: options.maxAncestryDepth ?? 16,
    verificationTimeoutMs: options.verificationTimeoutMs ?? 100,
    allowedSourceAuthorities: options.allowedSourceAuthorities ?? ["connector-001"],
  });
}

test("valid verified state reaches the adapter exactly once", async () => {
  let verifierCalls = 0;
  const adapter = createDryRunActionAdapter();
  const gateway = gatewayWith(async (artifactId) => {
    verifierCalls += 1;
    assert.equal(artifactId, baseIntent.provenance_artifact_id);
    return verificationFor();
  }, adapter);

  const result = await gateway.authorizeAndExecute(baseIntent);

  assert.equal(result.status, "ALLOW");
  assert.equal(result.result, "ACTION_EXECUTED");
  assert.equal(verifierCalls, 1);
  assert.equal(adapter.callCount(), 1);
  const [authorized] = adapter.calls();
  assert.equal(Object.isFrozen(authorized), true);
  assert.equal(authorized.authorized_at, 1_001);
  assert.equal("verified" in authorized, false);
  assert.equal("provenance" in authorized, false);
});

test("a complete multi-hop verified closure reaches the adapter", async () => {
  const adapter = createDryRunActionAdapter();
  const verification = verificationFor();
  const gateway = gatewayWith(async () => ({
    ...verification,
    artifact: {
      ...verification.artifact,
      generation: 2,
    },
    witnesses: [
      {
        ...verification.witnesses[0],
        parent_artifact_id: "summary-001",
        child_generation: 2,
        parent_generation: 1,
      },
      {
        edge_id: 8,
        child_artifact_id: "summary-001",
        parent_artifact_id: "source-001",
        kind: "summarize",
        child_generation: 1,
        parent_generation: 0,
        batch_id: "d".repeat(64),
      },
    ],
    graph_snapshot: {
      ...verification.graph_snapshot,
      node_count: 3,
      edge_count: 2,
      deepest_hops: 2,
    },
  }), adapter);

  const result = await gateway.authorizeAndExecute({
    ...baseIntent,
    action_id: "action-multihop",
    request_id: "request-multihop",
  });

  assert.equal(result.status, "ALLOW");
  assert.equal(result.provenance_witness_count, 2);
  assert.equal(adapter.callCount(), 1);
});

test("disconnected witnesses and non-require action lineage fail closed", async () => {
  const adapter = createDryRunActionAdapter();
  const verification = verificationFor();
  const disconnected = gatewayWith(async () => ({
    ...verification,
    source_nodes: [
      ...verification.source_nodes,
      {
        ...verification.source_nodes[0],
        artifact_id: "source-disconnected",
        vertex_id: 102,
        content_hash: "e".repeat(64),
      },
    ],
    witnesses: [
      ...verification.witnesses,
      {
        ...verification.witnesses[0],
        edge_id: 9,
        child_artifact_id: "summary-disconnected",
        parent_artifact_id: "source-disconnected",
        kind: "summarize",
        batch_id: "f".repeat(64),
      },
    ],
    graph_snapshot: {
      ...verification.graph_snapshot,
      node_count: 4,
      edge_count: 2,
    },
  }), adapter);
  const wrongLineage = gatewayWith(async () => ({
    ...verification,
    artifact: {
      ...verification.artifact,
      lineage_kind: "support",
    },
    witnesses: [{
      ...verification.witnesses[0],
      kind: "support",
    }],
  }), adapter);

  const disconnectedResult = await disconnected.authorizeAndExecute({
    ...baseIntent,
    action_id: "action-disconnected",
    request_id: "request-disconnected",
  });
  const wrongLineageResult = await wrongLineage.authorizeAndExecute({
    ...baseIntent,
    action_id: "action-wrong-lineage",
    request_id: "request-wrong-lineage",
  });

  assert.equal(disconnectedResult.reason_code, BLOCK_INVALID_PROVENANCE);
  assert.equal(wrongLineageResult.reason_code, BLOCK_INVALID_PROVENANCE);
  assert.equal(adapter.callCount(), 0);
});

for (const field of [
  "verified",
  "trusted",
  "trusted_state",
  "ancestry_status",
  "provenance",
  "witnesses",
  "policy_status",
  "policy_result",
  "fresh",
  "freshness",
  "expires_at",
  "adapter",
  "execute",
]) {
  test(`caller-controlled ${field} cannot bypass verification`, async () => {
    let verifierCalls = 0;
    const adapter = createDryRunActionAdapter();
    const gateway = gatewayWith(async () => {
      verifierCalls += 1;
      return verificationFor();
    }, adapter);
    const result = await gateway.authorizeAndExecute({
      ...baseIntent,
      [field]: field === "witnesses" ? [] : true,
    });

    assert.equal(result.status, "BLOCK");
    assert.equal(result.reason_code, BLOCK_INVALID_INPUT);
    assert.equal(result.detail, "UNTRUSTED_CONTROL_FIELD");
    assert.equal(verifierCalls, 0);
    assert.equal(adapter.callCount(), 0);
  });
}

test("missing subject, unknown action, and malformed parameters block before verification", async () => {
  let verifierCalls = 0;
  const gateway = gatewayWith(async () => {
    verifierCalls += 1;
    return verificationFor();
  });

  const missingSubject = await gateway.authorizeAndExecute({
    ...baseIntent,
    subject_id: "",
  });
  const unknownAction = await gateway.authorizeAndExecute({
    ...baseIntent,
    action_id: "action-unknown",
    request_id: "request-unknown",
    action_type: "delete_everything",
  });
  const malformedParameters = await gateway.authorizeAndExecute({
    ...baseIntent,
    action_id: "action-malformed",
    request_id: "request-malformed",
    parameters: { ...baseIntent.parameters, forged: true },
  });

  assert.equal(missingSubject.reason_code, BLOCK_INVALID_INPUT);
  assert.equal(unknownAction.reason_code, BLOCK_INVALID_INPUT);
  assert.equal(malformedParameters.reason_code, BLOCK_INVALID_INPUT);
  assert.equal(verifierCalls, 0);
});

test("proxy-backed intents cannot change semantics between validation and snapshot", async () => {
  let verifierCalls = 0;
  const adapter = createDryRunActionAdapter();
  const gateway = gatewayWith(async () => {
    verifierCalls += 1;
    return verificationFor();
  }, adapter);
  const proxy = new Proxy({ ...baseIntent }, {
    get(target, property, receiver) {
      if (property === "action_type") {
        return "send_message";
      }
      return Reflect.get(target, property, receiver);
    },
  });

  const result = await gateway.authorizeAndExecute(proxy);

  assert.equal(result.reason_code, BLOCK_INVALID_INPUT);
  assert.equal(result.detail, "INVALID_ACTION_INTENT");
  assert.equal(verifierCalls, 0);
  assert.equal(adapter.callCount(), 0);
});

test("proxy-backed nested parameters and revoked intents fail closed", async () => {
  let verifierCalls = 0;
  const adapter = createDryRunActionAdapter();
  const gateway = gatewayWith(async () => {
    verifierCalls += 1;
    return verificationFor();
  }, adapter);
  const nestedProxy = new Proxy({ ...baseIntent.parameters }, {});
  const nestedResult = await gateway.authorizeAndExecute({
    ...baseIntent,
    parameters: nestedProxy,
  });
  const revocable = Proxy.revocable({ ...baseIntent }, {});
  revocable.revoke();
  const revokedResult = await gateway.authorizeAndExecute(revocable.proxy);

  assert.equal(nestedResult.reason_code, BLOCK_INVALID_INPUT);
  assert.equal(nestedResult.detail, "INVALID_ACTION_PARAMETERS");
  assert.equal(revokedResult.reason_code, BLOCK_INVALID_INPUT);
  assert.equal(revokedResult.detail, "INVALID_ACTION_INTENT");
  assert.equal(verifierCalls, 0);
  assert.equal(adapter.callCount(), 0);
});

test("missing and unresolved provenance fail closed", async () => {
  const missing = gatewayWith(async () => ({
    status: "BLOCK",
    reason_code: BLOCK_INVALID_PROVENANCE,
    classification: "MISSING",
    detail: "ARTIFACT_NOT_FOUND",
  }));
  const unresolved = gatewayWith(async () => ({
    status: "BLOCK",
    reason_code: BLOCK_UNRESOLVED_ANCESTRY,
    classification: "UNRESOLVED",
    detail: "DEPTH_CAP_REACHED",
  }));

  const missingResult = await missing.authorizeAndExecute(baseIntent);
  const unresolvedResult = await unresolved.authorizeAndExecute({
    ...baseIntent,
    action_id: "action-unresolved",
    request_id: "request-unresolved",
  });

  assert.equal(missingResult.reason_code, BLOCK_MISSING_PROVENANCE);
  assert.equal(unresolvedResult.reason_code, BLOCK_UNRESOLVED_ANCESTRY);
});

test("malformed verified output and verifier failures never authorize", async () => {
  const malformed = gatewayWith(async () => ({
    ...verificationFor(),
    artifact: { ...verificationFor().artifact, content_hash: "f".repeat(64) },
  }));
  const throwing = gatewayWith(async () => {
    throw new Error("Hydra unavailable");
  });

  const malformedResult = await malformed.authorizeAndExecute(baseIntent);
  const throwingResult = await throwing.authorizeAndExecute({
    ...baseIntent,
    action_id: "action-system",
    request_id: "request-system",
  });

  assert.equal(malformedResult.reason_code, BLOCK_INVALID_PROVENANCE);
  assert.equal(throwingResult.reason_code, BLOCK_SYSTEM_ERROR);
});

test("throwing verifier result properties return a deterministic system block", async () => {
  const adapter = createDryRunActionAdapter();
  const malformedResult = {};
  Object.defineProperty(malformedResult, "status", {
    enumerable: true,
    get() {
      throw new Error("Malformed hydrated verifier result");
    },
  });
  const gateway = gatewayWith(async () => malformedResult, adapter);

  const result = await gateway.authorizeAndExecute({
    ...baseIntent,
    action_id: "action-malformed-verifier-result",
    request_id: "request-malformed-verifier-result",
  });

  assert.equal(result.reason_code, BLOCK_SYSTEM_ERROR);
  assert.equal(result.detail, "PROVENANCE_VERIFICATION_RESULT_FAILED");
  assert.equal(adapter.callCount(), 0);
});

test("a stalled verifier times out and never reaches the adapter", async () => {
  const adapter = createDryRunActionAdapter();
  const gateway = gatewayWith(() => new Promise(() => {}), adapter, {
    verificationTimeoutMs: 5,
  });

  const result = await gateway.authorizeAndExecute({
    ...baseIntent,
    action_id: "action-timeout",
    request_id: "request-timeout",
  });

  assert.equal(result.reason_code, BLOCK_SYSTEM_ERROR);
  assert.equal(result.detail, "PROVENANCE_VERIFICATION_TIMEOUT");
  assert.equal(adapter.callCount(), 0);
});

test("a verifier rejection after timeout cannot change the fail-closed result", async () => {
  const adapter = createDryRunActionAdapter();
  let rejectVerifier;
  const verifier = new Promise((_, reject) => {
    rejectVerifier = reject;
  });
  const gateway = gatewayWith(() => verifier, adapter, {
    verificationTimeoutMs: 5,
  });

  const result = await gateway.authorizeAndExecute({
    ...baseIntent,
    action_id: "action-late-verifier-rejection",
    request_id: "request-late-verifier-rejection",
  });
  rejectVerifier(new Error("Late Hydra failure"));
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(result.reason_code, BLOCK_SYSTEM_ERROR);
  assert.equal(result.detail, "PROVENANCE_VERIFICATION_TIMEOUT");
  assert.equal(adapter.callCount(), 0);
});

test("policy blocks unlisted destinations and restricted data", async () => {
  const adapter = createDryRunActionAdapter();
  const verifier = async (artifactId) => {
    const intent = artifactId === "action-argument-external"
      ? { ...baseIntent, provenance_artifact_id: artifactId, parameters: { ...baseIntent.parameters, destination: "external:webhook" } }
      : artifactId === "action-argument-deceptive"
        ? { ...baseIntent, provenance_artifact_id: artifactId, parameters: { ...baseIntent.parameters, destination: "internal:https://external.example" } }
        : { ...baseIntent, provenance_artifact_id: artifactId, parameters: { ...baseIntent.parameters, data_class: "restricted" } };
    return verificationFor(intent);
  };
  const gateway = gatewayWith(verifier, adapter);

  const external = await gateway.authorizeAndExecute({
    ...baseIntent,
    action_id: "action-external",
    request_id: "request-external",
    provenance_artifact_id: "action-argument-external",
    parameters: { ...baseIntent.parameters, destination: "external:webhook" },
  });
  const deceptiveInternal = await gateway.authorizeAndExecute({
    ...baseIntent,
    action_id: "action-deceptive-internal",
    request_id: "request-deceptive-internal",
    provenance_artifact_id: "action-argument-deceptive",
    parameters: { ...baseIntent.parameters, destination: "internal:https://external.example" },
  });
  const restricted = await gateway.authorizeAndExecute({
    ...baseIntent,
    action_id: "action-restricted",
    request_id: "request-restricted",
    provenance_artifact_id: "action-argument-restricted",
    parameters: { ...baseIntent.parameters, data_class: "restricted" },
  });

  assert.equal(external.reason_code, BLOCK_POLICY);
  assert.equal(deceptiveInternal.reason_code, BLOCK_POLICY);
  assert.equal(restricted.reason_code, BLOCK_POLICY);
  assert.equal(adapter.callCount(), 0);
});

test("an authenticated but untrusted terminal source is policy-blocked", async () => {
  const adapter = createDryRunActionAdapter();
  const trusted = verificationFor();
  const result = await gatewayWith(async () => verificationFor(baseIntent, {
    source_nodes: [{
      ...trusted.source_nodes[0],
      trust_state: "untrusted_source",
    }],
  }), adapter).authorizeAndExecute({
    ...baseIntent,
    action_id: "action-untrusted-source",
    request_id: "request-untrusted-source",
  });

  assert.equal(result.reason_code, BLOCK_POLICY);
  assert.equal(result.detail, "UNTRUSTED_TERMINAL_SOURCE");
  assert.equal(adapter.callCount(), 0);
});

test("an authenticated source from an unapproved authority is policy-blocked", async () => {
  const adapter = createDryRunActionAdapter();
  const trusted = verificationFor();
  const result = await gatewayWith(async () => verificationFor(baseIntent, {
    source_nodes: [{
      ...trusted.source_nodes[0],
      authority_id: "connector-unapproved",
    }],
  }), adapter).authorizeAndExecute({
    ...baseIntent,
    action_id: "action-unapproved-authority",
    request_id: "request-unapproved-authority",
  });

  assert.equal(result.reason_code, BLOCK_POLICY);
  assert.equal(result.detail, "SOURCE_AUTHORITY_NOT_ALLOWED");
  assert.equal(adapter.callCount(), 0);
});

test("freshness is trusted-clock based, not caller-controlled", async () => {
  let clockCalls = 0;
  const adapter = createDryRunActionAdapter();
  const gateway = gatewayWith(async () => verificationFor(), adapter, {
    maxFreshnessMs: 10,
    now: () => (clockCalls++ === 0 ? 1_000 : 1_011),
  });

  const result = await gateway.authorizeAndExecute(baseIntent);

  assert.equal(result.reason_code, BLOCK_STALE);
  assert.equal(adapter.callCount(), 0);
});

test("same request replays deterministically and conflicting identities never execute", async () => {
  const adapter = createDryRunActionAdapter();
  let verifierCalls = 0;
  const gateway = gatewayWith(async (artifactId) => {
    verifierCalls += 1;
    const intent = { ...baseIntent, provenance_artifact_id: artifactId };
    return verificationFor(intent);
  }, adapter);
  const first = await gateway.authorizeAndExecute(baseIntent);
  const replay = await gateway.authorizeAndExecute(baseIntent);
  const requestConflict = await gateway.authorizeAndExecute({
    ...baseIntent,
    action_id: "action-different",
  });
  const actionConflict = await gateway.authorizeAndExecute({
    ...baseIntent,
    request_id: "request-different",
  });

  assert.equal(first.status, "ALLOW");
  assert.equal(replay.reason_code, BLOCK_REPLAY);
  assert.equal(replay.detail, "REQUEST_REPLAYED");
  assert.equal(requestConflict.reason_code, BLOCK_REPLAY);
  assert.equal(requestConflict.detail, "REQUEST_ID_CONFLICT");
  assert.equal(actionConflict.reason_code, BLOCK_REPLAY);
  assert.equal(actionConflict.detail, "ACTION_ID_CONFLICT");
  assert.equal(adapter.callCount(), 1);
  assert.equal(verifierCalls, 1);
});

test("concurrent exact replays reserve once and execute the adapter once", async () => {
  const adapter = createDryRunActionAdapter();
  const gateway = gatewayWith(async () => verificationFor(), adapter);

  const results = await Promise.all([
    gateway.authorizeAndExecute({
      ...baseIntent,
      action_id: "action-concurrent-replay",
      request_id: "request-concurrent-replay",
    }),
    gateway.authorizeAndExecute({
      ...baseIntent,
      action_id: "action-concurrent-replay",
      request_id: "request-concurrent-replay",
    }),
  ]);

  assert.equal(results.filter((result) => result.status === "ALLOW").length, 1);
  assert.equal(results.filter((result) => result.reason_code === BLOCK_REPLAY).length, 1);
  assert.equal(adapter.callCount(), 1);
});

test("adapter failure becomes indeterminate and is never retried", async () => {
  let calls = 0;
  const adapter = createActionAdapter(async () => {
    calls += 1;
    throw new Error("dry-run adapter failed");
  });
  const gateway = gatewayWith(async () => verificationFor(), adapter);

  const first = await gateway.authorizeAndExecute(baseIntent);
  const second = await gateway.authorizeAndExecute(baseIntent);

  assert.equal(first.reason_code, BLOCK_SYSTEM_ERROR);
  assert.equal(first.detail, "ACTION_ADAPTER_FAILED");
  assert.equal(second.reason_code, BLOCK_SYSTEM_ERROR);
  assert.equal(second.detail, "ACTION_INDETERMINATE");
  assert.equal(calls, 1);
});

test("the adapter handle has no direct execution path", async () => {
  const adapter = createDryRunActionAdapter();
  assert.equal("execute" in adapter, false);
  assert.equal(typeof adapter.execute, "undefined");
  assert.equal(adapter.callCount(), 0);
});

test("clock rollback fails closed before adapter invocation", async () => {
  const adapter = createDryRunActionAdapter();
  let clockCalls = 0;
  const gateway = gatewayWith(async () => verificationFor(), adapter, {
    now: () => (clockCalls++ === 0 ? 1_000 : 999),
  });
  const result = await gateway.authorizeAndExecute({
    ...baseIntent,
    action_id: "action-clock-rollback",
    request_id: "request-clock-rollback",
  });
  assert.equal(result.reason_code, BLOCK_SYSTEM_ERROR);
  assert.equal(result.detail, "TRUSTED_CLOCK_ROLLBACK");
  assert.equal(adapter.callCount(), 0);
});

test("intent input is snapshotted before asynchronous verification", async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let observed;
  const observedPromise = new Promise((resolve) => { observed = resolve; });
  const adapter = createDryRunActionAdapter();
  const mutable = {
    ...baseIntent,
    parameters: { ...baseIntent.parameters },
  };
  const gateway = gatewayWith(async () => {
    observed();
    await gate;
    return verificationFor({
      ...baseIntent,
      parameters: { ...baseIntent.parameters },
    });
  }, adapter);
  const pending = gateway.authorizeAndExecute(mutable);
  await observedPromise;
  mutable.subject_id = "retargeted-subject";
  mutable.parameters.destination = "external:retargeted";
  release();

  const result = await pending;

  assert.equal(result.status, "ALLOW");
  assert.equal(adapter.calls()[0].subject_id, baseIntent.subject_id);
  assert.equal(adapter.calls()[0].parameters.destination, "internal:alerts");
});

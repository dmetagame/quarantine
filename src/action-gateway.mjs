import {
  createHash,
} from "node:crypto";
import {
  types as utilTypes,
} from "node:util";

import {
  BLOCK_INVALID_PROVENANCE,
  BLOCK_UNRESOLVED_ANCESTRY,
  PROVENANCE_WRITER_ID,
  PROVENANCE_STATE_VERIFIER_VERSION,
} from "./provenance-writer.mjs";

export const ACTION_GATEWAY_VERSION = "fail-closed-action-gateway-v1";
export const TRUSTED_STATE_CONTRACT_VERSION = "trusted-state-contract-v1";
export const ACTION_POLICY_VERSION = "internal-message-policy-v1";

export const BLOCK_INVALID_INPUT = "BLOCK_INVALID_INPUT";
export const BLOCK_MISSING_PROVENANCE = "BLOCK_MISSING_PROVENANCE";
export { BLOCK_INVALID_PROVENANCE, BLOCK_UNRESOLVED_ANCESTRY };
export const BLOCK_POLICY = "BLOCK_POLICY";
export const BLOCK_STALE = "BLOCK_STALE";
export const BLOCK_REPLAY = "BLOCK_REPLAY";
export const BLOCK_SYSTEM_ERROR = "BLOCK_SYSTEM_ERROR";

const SUPPORTED_ACTION_TYPES = new Set(["send_message"]);
const ALLOWED_INTENT_FIELDS = new Set([
  "action_id",
  "subject_id",
  "action_type",
  "parameters",
  "request_id",
  "requested_at",
  "provenance_artifact_id",
]);
const TRUST_CONTROL_FIELDS = new Set([
  "verified",
  "trusted",
  "trusted_state",
  "ancestry_status",
  "provenance",
  "witnesses",
  "source_nodes",
  "policy_status",
  "policy_result",
  "fresh",
  "freshness",
  "expires_at",
  "authorization",
  "authority",
  "confidence",
  "adapter",
  "execute",
]);
const SEND_MESSAGE_FIELDS = Object.freeze(["data_class", "destination", "payload"]);
const ALLOWED_DESTINATIONS = new Set(["internal:alerts"]);
const MAX_IDENTIFIER_BYTES = 256;
const MAX_PARAMETER_BYTES = 8_192;
const MAX_PAYLOAD_BYTES = 4_096;
const actionAdapterExecutors = new WeakMap();

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  if (utilTypes.isProxy(value)) {
    return false;
  }
  if (Array.isArray(value)) {
    return false;
  }
  try {
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function block(reasonCode, detail, extra = {}) {
  return Object.freeze({
    status: "BLOCK",
    reason_code: reasonCode,
    detail,
    ...extra,
  });
}

function allow(extra = {}) {
  return Object.freeze({
    status: "ALLOW",
    reason_code: null,
    detail: "ACTION_AUTHORIZED",
    ...extra,
  });
}

function validIdentifier(value) {
  return typeof value === "string"
    && value.length > 0
    && Buffer.byteLength(value, "utf8") <= MAX_IDENTIFIER_BYTES
    && /^[A-Za-z0-9._:@/-]+$/.test(value);
}

function ownDataEntries(value) {
  if (!isPlainObject(value)) {
    throw new Error("Only plain data objects are accepted at the action boundary");
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error("Symbol properties are not accepted at the action boundary");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  return keys.map((key) => {
    const descriptor = descriptors[key];
    if (!descriptor
      || descriptor.enumerable !== true
      || typeof descriptor.get === "function"
      || typeof descriptor.set === "function") {
      throw new Error("Accessor properties are not accepted at the action boundary");
    }
    return [key, descriptor.value];
  });
}

function normalizeJson(value, depth = 0) {
  if (depth > 8) {
    throw new Error("Action parameters exceed the nesting limit");
  }
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 64) {
      throw new Error("Action parameter arrays exceed the item limit");
    }
    return Object.freeze(value.map((item) => normalizeJson(item, depth + 1)));
  }
  if (!isPlainObject(value)) {
    throw new Error("Action parameters must contain only JSON values");
  }
  const entries = ownDataEntries(value);
  if (entries.length > 32) {
    throw new Error("Action parameter objects exceed the field limit");
  }
  return Object.freeze(Object.fromEntries(
    entries
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => {
        if (!/^[A-Za-z0-9._-]{1,64}$/.test(key)) {
          throw new Error("Action parameter keys must use bounded ASCII identifiers");
        }
        return [key, normalizeJson(item, depth + 1)];
      }),
  ));
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const item of Object.values(value)) {
    deepFreeze(item);
  }
  return Object.freeze(value);
}

function normalizeSendMessageParameters(parameters) {
  const keys = Object.keys(parameters).sort();
  if (JSON.stringify(keys) !== JSON.stringify(SEND_MESSAGE_FIELDS)) {
    throw new Error("send_message parameters must be destination, data_class, and payload");
  }
  if (typeof parameters.destination !== "string"
    || parameters.destination.length === 0
    || Buffer.byteLength(parameters.destination, "utf8") > 256) {
    throw new Error("send_message destination is invalid");
  }
  if (!["public", "internal", "restricted"].includes(parameters.data_class)) {
    throw new Error("send_message data_class is invalid");
  }
  if (typeof parameters.payload !== "string"
    || parameters.payload.length === 0
    || Buffer.byteLength(parameters.payload, "utf8") > MAX_PAYLOAD_BYTES) {
    throw new Error("send_message payload is invalid");
  }
}

export function validateActionIntent(rawIntent) {
  if (!isPlainObject(rawIntent)) {
    return block(BLOCK_INVALID_INPUT, "INVALID_ACTION_INTENT");
  }

  let entries;
  try {
    entries = ownDataEntries(rawIntent);
  } catch {
    return block(BLOCK_INVALID_INPUT, "INVALID_ACTION_INTENT");
  }
  const input = Object.freeze(Object.fromEntries(entries));
  const rejectedFields = entries
    .map(([key]) => key)
    .filter((key) => TRUST_CONTROL_FIELDS.has(key) || !ALLOWED_INTENT_FIELDS.has(key))
    .sort();
  if (rejectedFields.length > 0) {
    return block(BLOCK_INVALID_INPUT, "UNTRUSTED_CONTROL_FIELD", {
      rejected_fields: rejectedFields,
    });
  }

  const requiredFields = [...ALLOWED_INTENT_FIELDS];
  if (requiredFields.some((field) => !Object.prototype.hasOwnProperty.call(input, field))) {
    return block(BLOCK_INVALID_INPUT, "MISSING_ACTION_FIELD");
  }
  if (!validIdentifier(input.action_id)
    || !validIdentifier(input.subject_id)
    || !validIdentifier(input.request_id)
    || !validIdentifier(input.provenance_artifact_id)
    || typeof input.action_type !== "string"
    || !SUPPORTED_ACTION_TYPES.has(input.action_type)
    || !Number.isSafeInteger(input.requested_at)
    || input.requested_at < 0) {
    return block(BLOCK_INVALID_INPUT, "INVALID_ACTION_FIELD");
  }

  let parameters;
  try {
    parameters = normalizeJson(input.parameters);
    if (!isPlainObject(parameters)) {
      throw new Error("parameters must be an object");
    }
    if (Buffer.byteLength(canonicalJson(parameters), "utf8") > MAX_PARAMETER_BYTES) {
      throw new Error("parameters exceed the byte limit");
    }
    if (input.action_type === "send_message") {
      normalizeSendMessageParameters(parameters);
    }
  } catch {
    return block(BLOCK_INVALID_INPUT, "INVALID_ACTION_PARAMETERS");
  }

  const intent = deepFreeze({
    action_id: input.action_id,
    subject_id: input.subject_id,
    action_type: input.action_type,
    parameters,
    request_id: input.request_id,
    requested_at: input.requested_at,
    provenance_artifact_id: input.provenance_artifact_id,
  });
  const semanticPayload = canonicalJson({
    action_type: intent.action_type,
    parameters: intent.parameters,
    subject_id: intent.subject_id,
  });
  const fingerprint = sha256(canonicalJson(intent));

  return Object.freeze({
    status: "PASS",
    reason_code: null,
    result: "ACTION_INTENT_VALID",
    intent,
    semantic_payload: semanticPayload,
    semantic_digest: sha256(semanticPayload),
    fingerprint,
  });
}

export function createDryRunActionAdapter() {
  const calls = [];
  const adapter = Object.freeze({
    callCount() {
      return calls.length;
    },
    calls() {
      return Object.freeze([...calls]);
    },
  });
  actionAdapterExecutors.set(adapter, async (authorizedAction) => {
    calls.push(authorizedAction);
    return Object.freeze({
      status: "DRY_RUN",
      authorization_id: authorizedAction.authorization_id,
      action_id: authorizedAction.action_id,
    });
  });
  return adapter;
}

// Adapter execution stays behind an opaque capability handle. The returned
// object has no public execute method, so untrusted code cannot feed raw input
// directly to an action implementation merely by obtaining the handle.
export function createActionAdapter(executeAuthorized) {
  if (typeof executeAuthorized !== "function") {
    throw new Error("An authorized action executor is required");
  }
  const adapter = Object.freeze({
    adapter_type: "quarantine-action-adapter-v1",
  });
  actionAdapterExecutors.set(adapter, executeAuthorized);
  return adapter;
}

export function createActionGateway({
  verifyProvenanceState,
  actionAdapter,
  now = () => Date.now(),
  maxFreshnessMs = 5_000,
  maxAncestryDepth = 16,
  verificationTimeoutMs = 5_000,
  allowedSourceAuthorities = ["quarantine-proof-connector"],
} = {}) {
  if (typeof verifyProvenanceState !== "function") {
    throw new Error("A trusted provenance-state verifier is required");
  }
  const executeAction = actionAdapterExecutors.get(actionAdapter);
  if (typeof executeAction !== "function") {
    throw new Error("An opaque action adapter capability is required");
  }
  if (typeof now !== "function") {
    throw new Error("A trusted clock is required");
  }
  if (!Number.isSafeInteger(maxFreshnessMs) || maxFreshnessMs < 1 || maxFreshnessMs > 300_000) {
    throw new Error("maxFreshnessMs must be between 1 and 300000");
  }
  if (!Number.isInteger(maxAncestryDepth) || maxAncestryDepth < 1 || maxAncestryDepth > 64) {
    throw new Error("maxAncestryDepth must be between 1 and 64");
  }
  if (!Number.isInteger(verificationTimeoutMs)
    || verificationTimeoutMs < 1
    || verificationTimeoutMs > 30_000) {
    throw new Error("verificationTimeoutMs must be between 1 and 30000");
  }
  if (!Array.isArray(allowedSourceAuthorities)
    || allowedSourceAuthorities.length === 0
    || allowedSourceAuthorities.length > 64
    || allowedSourceAuthorities.some((authorityId) => !validIdentifier(authorityId))) {
    throw new Error("allowedSourceAuthorities must contain trusted authority identifiers");
  }
  const sourceAuthorityAllowlist = new Set(allowedSourceAuthorities);

  const trustedStateBrand = new WeakSet();
  const authorizedActionBrand = new WeakSet();
  const requests = new Map();
  const actions = new Map();

  function trustedNow() {
    const value = now();
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error("Trusted clock returned an invalid timestamp");
    }
    return value;
  }

  function mapVerificationBlock(verification, intent) {
    const common = {
      request_id: intent.request_id,
      action_id: intent.action_id,
      provenance_artifact_id: intent.provenance_artifact_id,
    };
    if (verification?.classification === "MISSING") {
      return block(BLOCK_MISSING_PROVENANCE, "PROVENANCE_ARTIFACT_NOT_FOUND", common);
    }
    if (verification?.classification === "UNRESOLVED"
      || verification?.reason_code === BLOCK_UNRESOLVED_ANCESTRY) {
      return block(BLOCK_UNRESOLVED_ANCESTRY, verification?.detail ?? "UNRESOLVED_ANCESTRY", common);
    }
    if (verification?.classification === "SYSTEM_ERROR") {
      return block(BLOCK_SYSTEM_ERROR, "PROVENANCE_VERIFICATION_FAILED", common);
    }
    return block(BLOCK_INVALID_PROVENANCE, verification?.detail ?? "INVALID_PROVENANCE", common);
  }

  function validVerificationResult(verification, intent, semanticDigest) {
    if (!isPlainObject(verification)
      || verification.status !== "PASS"
      || verification.result !== "PROVENANCE_STATE_VERIFIED"
      || verification.classification !== "VERIFIED"
      || verification.verifier_version !== PROVENANCE_STATE_VERIFIER_VERSION
      || verification.ancestry_status !== "RESOLVED"
      || !isPlainObject(verification.artifact)
      || verification.artifact.artifact_id !== intent.provenance_artifact_id
      || verification.artifact.role !== "action_argument"
      || verification.artifact.terminal !== false
      || verification.artifact.content_hash !== semanticDigest
      || !/^[a-f0-9]{64}$/.test(verification.artifact.content_hash)
      || !/^[a-f0-9]{64}$/.test(verification.artifact.batch_id)
      || !Number.isInteger(verification.artifact.generation)
      || verification.artifact.generation < 1
      || verification.artifact.trust_state !== "derived"
      || verification.artifact.authority_id !== PROVENANCE_WRITER_ID
      || !Number.isInteger(verification.artifact.parent_count)
      || verification.artifact.parent_count < 1
      || verification.artifact.lineage_kind !== "require"
      || !Array.isArray(verification.source_nodes)
      || verification.source_nodes.length === 0
      || !Array.isArray(verification.witnesses)
      || verification.witnesses.length === 0
      || !isPlainObject(verification.graph_snapshot)
      || !Number.isInteger(verification.graph_snapshot.node_count)
      || !Number.isInteger(verification.graph_snapshot.edge_count)
      || !Number.isInteger(verification.graph_snapshot.deepest_hops)
      || verification.graph_snapshot.node_count < 2
      || verification.graph_snapshot.edge_count !== verification.witnesses.length
      || verification.graph_snapshot.edge_count < 1
      || verification.graph_snapshot.max_depth !== maxAncestryDepth) {
      return false;
    }
    const sourceIds = new Set();
    for (const source of verification.source_nodes) {
      if (!isPlainObject(source)
        || !validIdentifier(source.artifact_id)
        || source.role !== "source"
        || source.terminal !== true
        || source.generation !== 0
        || source.parent_count !== 0
        || source.lineage_kind !== "source"
        || !["trusted_source", "untrusted_source"].includes(source.trust_state)
        || !/^[a-f0-9]{64}$/.test(source.content_hash)
        || !/^[a-f0-9]{64}$/.test(source.batch_id)
        || !validIdentifier(source.authority_id)
        || sourceIds.has(source.artifact_id)) {
        return false;
      }
      sourceIds.add(source.artifact_id);
    }

    const edgeIds = new Set();
    const adjacency = new Map();
    const nodeGenerations = new Map([
      [verification.artifact.artifact_id, verification.artifact.generation],
    ]);
    const nodeSet = new Set([verification.artifact.artifact_id]);
    for (const witness of verification.witnesses) {
      if (!isPlainObject(witness)
        || !Number.isSafeInteger(witness.edge_id)
        || edgeIds.has(witness.edge_id)
        || !validIdentifier(witness.child_artifact_id)
        || !validIdentifier(witness.parent_artifact_id)
        || witness.child_artifact_id === witness.parent_artifact_id
        || !["assert", "summarize", "support", "require"].includes(witness.kind)
        || !Number.isInteger(witness.child_generation)
        || !Number.isInteger(witness.parent_generation)
        || witness.child_generation < 1
        || witness.parent_generation < 0
        || witness.parent_generation >= witness.child_generation
        || !/^[a-f0-9]{64}$/.test(witness.batch_id)) {
        return false;
      }
      const priorChildGeneration = nodeGenerations.get(witness.child_artifact_id);
      const priorParentGeneration = nodeGenerations.get(witness.parent_artifact_id);
      if ((priorChildGeneration !== undefined && priorChildGeneration !== witness.child_generation)
        || (priorParentGeneration !== undefined && priorParentGeneration !== witness.parent_generation)) {
        return false;
      }
      edgeIds.add(witness.edge_id);
      nodeGenerations.set(witness.child_artifact_id, witness.child_generation);
      nodeGenerations.set(witness.parent_artifact_id, witness.parent_generation);
      nodeSet.add(witness.child_artifact_id);
      nodeSet.add(witness.parent_artifact_id);
      const outgoing = adjacency.get(witness.child_artifact_id) ?? [];
      outgoing.push(witness);
      adjacency.set(witness.child_artifact_id, outgoing);
    }

    const rootEdges = adjacency.get(verification.artifact.artifact_id) ?? [];
    if (rootEdges.length !== verification.artifact.parent_count
      || rootEdges.some((edge) => edge.kind !== verification.artifact.lineage_kind
        || edge.child_generation !== verification.artifact.generation
        || edge.batch_id !== verification.artifact.batch_id)) {
      return false;
    }

    const reachableDepths = new Map([[verification.artifact.artifact_id, 0]]);
    const pending = [verification.artifact.artifact_id];
    let deepestReachable = 0;
    while (pending.length > 0) {
      const currentId = pending.pop();
      const currentDepth = reachableDepths.get(currentId);
      deepestReachable = Math.max(deepestReachable, currentDepth);
      const outgoing = adjacency.get(currentId) ?? [];
      if (outgoing.length === 0) {
        if (!sourceIds.has(currentId)) {
          return false;
        }
        continue;
      }
      if (sourceIds.has(currentId)) {
        return false;
      }
      for (const edge of outgoing) {
        const nextDepth = currentDepth + 1;
        if (nextDepth > (reachableDepths.get(edge.parent_artifact_id) ?? -1)) {
          reachableDepths.set(edge.parent_artifact_id, nextDepth);
          pending.push(edge.parent_artifact_id);
        }
      }
    }

    if (reachableDepths.size !== nodeSet.size
      || [...sourceIds].some((sourceId) => !reachableDepths.has(sourceId))
      || verification.graph_snapshot.node_count !== nodeSet.size
      || verification.graph_snapshot.edge_count !== edgeIds.size
      || verification.graph_snapshot.deepest_hops !== deepestReachable
      || verification.graph_snapshot.deepest_hops > verification.graph_snapshot.max_depth) {
      return false;
    }

    return [...adjacency.entries()].every(([childId, outgoing]) => {
      const first = outgoing[0];
      return outgoing.every((edge) => edge.kind === first.kind
        && edge.child_generation === first.child_generation
        && edge.batch_id === first.batch_id)
        && (childId !== verification.artifact.artifact_id
          || first.kind === verification.artifact.lineage_kind);
    });
  }

  function issueTrustedState(verification, intent, semanticDigest) {
    const verifiedAt = trustedNow();
    const validUntil = verifiedAt + maxFreshnessMs;
    if (!Number.isSafeInteger(validUntil)) {
      throw new Error("Trusted-state validity timestamp overflowed");
    }
    const state = deepFreeze({
      state_id: sha256(canonicalJson([
        TRUSTED_STATE_CONTRACT_VERSION,
        verification.artifact.artifact_id,
        verification.artifact.batch_id,
        semanticDigest,
        verifiedAt,
      ])),
      subject_id: intent.subject_id,
      observed_at: verifiedAt,
      graph_snapshot: { ...verification.graph_snapshot },
      provenance: {
        witnesses: verification.witnesses.map((witness) => ({ ...witness })),
        source_nodes: verification.source_nodes.map((source) => ({ ...source })),
        ancestry_status: verification.ancestry_status,
      },
      policy_context: {
        action_type: intent.action_type,
        intent_digest: semanticDigest,
        provenance_artifact_id: intent.provenance_artifact_id,
      },
      verification: {
        status: "VERIFIED",
        verifier_version: verification.verifier_version,
        reason_codes: [],
      },
      freshness: {
        verified_at: verifiedAt,
        valid_until: validUntil,
      },
    });
    trustedStateBrand.add(state);
    return state;
  }

  function evaluatePolicy(intent, trustedState) {
    if (!trustedStateBrand.has(trustedState)) {
      return block(BLOCK_SYSTEM_ERROR, "UNBRANDED_TRUSTED_STATE");
    }
    if (trustedState.subject_id !== intent.subject_id
      || trustedState.policy_context.intent_digest !== sha256(canonicalJson({
        action_type: intent.action_type,
        parameters: intent.parameters,
        subject_id: intent.subject_id,
      }))) {
      return block(BLOCK_INVALID_PROVENANCE, "ACTION_BINDING_MISMATCH");
    }
    if (trustedState.provenance.ancestry_status !== "RESOLVED") {
      return block(BLOCK_UNRESOLVED_ANCESTRY, "UNRESOLVED_ANCESTRY");
    }
    if (trustedState.provenance.witnesses.length === 0
      || trustedState.provenance.source_nodes.length === 0) {
      return block(BLOCK_MISSING_PROVENANCE, "MISSING_PROVENANCE_WITNESS");
    }
    if (trustedState.provenance.source_nodes.some((source) => source.trust_state !== "trusted_source")) {
      return block(BLOCK_POLICY, "UNTRUSTED_TERMINAL_SOURCE");
    }
    if (trustedState.provenance.source_nodes.some(
      (source) => !sourceAuthorityAllowlist.has(source.authority_id),
    )) {
      return block(BLOCK_POLICY, "SOURCE_AUTHORITY_NOT_ALLOWED");
    }
    if (!ALLOWED_DESTINATIONS.has(intent.parameters.destination)) {
      return block(BLOCK_POLICY, "DESTINATION_NOT_ALLOWED");
    }
    if (intent.parameters.data_class === "restricted") {
      return block(BLOCK_POLICY, "DATA_CLASS_NOT_ALLOWED");
    }
    return Object.freeze({
      status: "PASS",
      reason_code: null,
      result: "POLICY_ALLOW",
      policy_version: ACTION_POLICY_VERSION,
    });
  }

  function replayDecision(intent, fingerprint) {
    const existingRequest = requests.get(intent.request_id);
    if (existingRequest) {
      if (existingRequest.state === "indeterminate") {
        return block(BLOCK_SYSTEM_ERROR, "ACTION_INDETERMINATE", {
          request_id: intent.request_id,
          action_id: intent.action_id,
        });
      }
      return block(BLOCK_REPLAY,
        existingRequest.fingerprint === fingerprint && existingRequest.action_id === intent.action_id
          ? "REQUEST_REPLAYED"
          : "REQUEST_ID_CONFLICT",
        {
          request_id: intent.request_id,
          action_id: intent.action_id,
          replayed: true,
        });
    }

    const existingAction = actions.get(intent.action_id);
    if (existingAction) {
      if (existingAction.state === "indeterminate") {
        return block(BLOCK_SYSTEM_ERROR, "ACTION_INDETERMINATE", {
          request_id: intent.request_id,
          action_id: intent.action_id,
        });
      }
      return block(BLOCK_REPLAY, "ACTION_ID_CONFLICT", {
        request_id: intent.request_id,
        action_id: intent.action_id,
        replayed: true,
      });
    }
    return null;
  }

  function reserve(intent, fingerprint, stateId) {
    const record = {
      action_id: intent.action_id,
      request_id: intent.request_id,
      fingerprint,
      state_id: stateId,
      state: "reserved",
    };
    requests.set(intent.request_id, record);
    actions.set(intent.action_id, record);
    return record;
  }

  async function authorizeAndExecute(rawIntent) {
    const validated = validateActionIntent(rawIntent);
    if (validated.status !== "PASS") {
      return validated;
    }
    const { intent, semantic_digest: semanticDigest, fingerprint } = validated;

    // Replay identity is authoritative once reserved. Check it before any
    // verifier or database call so a replay cannot change classification when
    // the backing graph is temporarily unavailable.
    const earlyReplay = replayDecision(intent, fingerprint);
    if (earlyReplay) {
      return earlyReplay;
    }

    let verification;
    let verificationTimer;
    const verificationTimedOut = Symbol("verification-timed-out");
    try {
      verification = await Promise.race([
        Promise.resolve().then(() => verifyProvenanceState(
          intent.provenance_artifact_id,
          Object.freeze({ maxDepth: maxAncestryDepth }),
        )),
        new Promise((resolve) => {
          verificationTimer = setTimeout(() => resolve(verificationTimedOut), verificationTimeoutMs);
        }),
      ]);
    } catch {
      return block(BLOCK_SYSTEM_ERROR, "PROVENANCE_VERIFICATION_FAILED", {
        request_id: intent.request_id,
        action_id: intent.action_id,
      });
    } finally {
      clearTimeout(verificationTimer);
    }
    if (verification === verificationTimedOut) {
      return block(BLOCK_SYSTEM_ERROR, "PROVENANCE_VERIFICATION_TIMEOUT", {
        request_id: intent.request_id,
        action_id: intent.action_id,
      });
    }
    try {
      if (verification?.status !== "PASS") {
        return mapVerificationBlock(verification, intent);
      }
      if (!validVerificationResult(verification, intent, semanticDigest)) {
        return block(BLOCK_INVALID_PROVENANCE, "MALFORMED_OR_UNBOUND_PROVENANCE", {
          request_id: intent.request_id,
          action_id: intent.action_id,
        });
      }
    } catch {
      return block(BLOCK_SYSTEM_ERROR, "PROVENANCE_VERIFICATION_RESULT_FAILED", {
        request_id: intent.request_id,
        action_id: intent.action_id,
      });
    }

    let trustedState;
    try {
      trustedState = issueTrustedState(verification, intent, semanticDigest);
    } catch {
      return block(BLOCK_SYSTEM_ERROR, "TRUSTED_STATE_ISSUANCE_FAILED", {
        request_id: intent.request_id,
        action_id: intent.action_id,
      });
    }

    const policy = evaluatePolicy(intent, trustedState);
    if (policy.status !== "PASS") {
      return Object.freeze({
        ...policy,
        request_id: intent.request_id,
        action_id: intent.action_id,
      });
    }

    let currentTime;
    try {
      currentTime = trustedNow();
    } catch {
      return block(BLOCK_SYSTEM_ERROR, "FRESHNESS_CHECK_FAILED", {
        request_id: intent.request_id,
        action_id: intent.action_id,
      });
    }
    if (currentTime >= trustedState.freshness.valid_until) {
      return block(BLOCK_STALE, "TRUSTED_STATE_EXPIRED", {
        request_id: intent.request_id,
        action_id: intent.action_id,
        verified_at: trustedState.freshness.verified_at,
        valid_until: trustedState.freshness.valid_until,
      });
    }
    if (currentTime < trustedState.freshness.verified_at) {
      return block(BLOCK_SYSTEM_ERROR, "TRUSTED_CLOCK_ROLLBACK", {
        request_id: intent.request_id,
        action_id: intent.action_id,
      });
    }

    const replay = replayDecision(intent, fingerprint);
    if (replay) {
      return replay;
    }
    const reservation = reserve(intent, fingerprint, trustedState.state_id);

    const authorizedAction = deepFreeze({
      authorization_id: sha256(canonicalJson([
        ACTION_GATEWAY_VERSION,
        intent.request_id,
        intent.action_id,
        trustedState.state_id,
      ])),
      action_id: intent.action_id,
      subject_id: intent.subject_id,
      action_type: intent.action_type,
      parameters: intent.parameters,
      request_id: intent.request_id,
      requested_at: intent.requested_at,
      authorized_at: currentTime,
      trusted_state_id: trustedState.state_id,
      policy_version: policy.policy_version,
      provenance_artifact_id: intent.provenance_artifact_id,
    });
    authorizedActionBrand.add(authorizedAction);

    let adapterResult;
    try {
      if (!authorizedActionBrand.has(authorizedAction)) {
        throw new Error("Authorized action brand was lost");
      }
      adapterResult = await executeAction(authorizedAction);
    } catch {
      reservation.state = "indeterminate";
      return block(BLOCK_SYSTEM_ERROR, "ACTION_ADAPTER_FAILED", {
        request_id: intent.request_id,
        action_id: intent.action_id,
        authorization_id: authorizedAction.authorization_id,
      });
    }
    reservation.state = "completed";

    return allow({
      result: "ACTION_EXECUTED",
      request_id: intent.request_id,
      action_id: intent.action_id,
      authorization_id: authorizedAction.authorization_id,
      trusted_state_id: trustedState.state_id,
      provenance_artifact_id: intent.provenance_artifact_id,
      provenance_witness_count: trustedState.provenance.witnesses.length,
      source_count: trustedState.provenance.source_nodes.length,
      policy_version: policy.policy_version,
      adapter_result: adapterResult,
    });
  }

  return Object.freeze({
    authorizeAndExecute,
  });
}

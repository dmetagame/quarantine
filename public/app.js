/*
 * QUARANTINE demo client
 *
 * This file is intentionally a display/orchestration layer. The browser sends
 * only a scenario key to the server and renders the server's verified result.
 * It does not contain provenance, policy, replay, or authorization logic.
 */

const API_BASE = document.documentElement.dataset.apiBase
  || globalThis.QUARANTINE_API_BASE
  || "";
const RUN_PATH = "/api/demo/run";
const SCENARIOS = Object.freeze({
  valid: {
    title: "Two inputs. Same pipeline. Opposite outcomes.",
    subtitle: "Run the trusted flow, then attack the same boundary with tampered provenance.",
  },
  tampered: {
    title: "Two inputs. Same pipeline. Opposite outcomes.",
    subtitle: "The writer rejects the forged parent, then the gateway blocks unresolved ancestry before execution.",
  },
});

const dom = Object.freeze({
  connectionBadge: document.querySelector("#connectionBadge"),
  connectionText: document.querySelector("#connectionText"),
  demoTitle: document.querySelector("#demo-title"),
  demoSubtitle: document.querySelector("#demoSubtitle"),
  validScenario: document.querySelector("#validScenario"),
  tamperedScenario: document.querySelector("#tamperedScenario"),
  evidenceBadge: document.querySelector("#evidenceBadge"),
  evidenceClaim: document.querySelector("#evidenceClaim"),
  evidenceSource: document.querySelector("#evidenceSource"),
  evidenceEntity: document.querySelector("#evidenceEntity"),
  evidenceReceived: document.querySelector("#evidenceReceived"),
  evidenceClassification: document.querySelector("#evidenceClassification"),
  graphState: document.querySelector("#graphState"),
  metricNodes: document.querySelector("#metricNodes"),
  metricEdges: document.querySelector("#metricEdges"),
  metricWitnesses: document.querySelector("#metricWitnesses"),
  metricPaths: document.querySelector("#metricPaths"),
  metricDepth: document.querySelector("#metricDepth"),
  metricBound: document.querySelector("#metricBound"),
  provenanceGraph: document.querySelector("#provenanceGraph"),
  graphEdges: document.querySelector("#graphEdges"),
  graphNodes: document.querySelector("#graphNodes"),
  graphEmpty: document.querySelector("#graphEmpty"),
  graphDescription: document.querySelector("#graphDescription"),
  directionNote: document.querySelector("#directionNote"),
  witnessSummary: document.querySelector("#witnessSummary"),
  frontierNotice: document.querySelector("#frontierNotice"),
  frontierDetail: document.querySelector("#frontierDetail"),
  attackProbe: document.querySelector("#attackProbe"),
  attackProbeStatus: document.querySelector("#attackProbeStatus"),
  attackProbeReason: document.querySelector("#attackProbeReason"),
  attackChildCount: document.querySelector("#attackChildCount"),
  attackParentCount: document.querySelector("#attackParentCount"),
  attackEdgeCreated: document.querySelector("#attackEdgeCreated"),
  decisionBadge: document.querySelector("#decisionBadge"),
  verificationStatus: document.querySelector("#verificationStatus"),
  verificationChecks: document.querySelector("#verificationChecks"),
  verificationDetail: document.querySelector("#verificationDetail"),
  policyStatus: document.querySelector("#policyStatus"),
  policyDetail: document.querySelector("#policyDetail"),
  gatewayStatus: document.querySelector("#gatewayStatus"),
  gatewayOutcome: document.querySelector("#gatewayOutcome"),
  actionOutcome: document.querySelector("#actionOutcome"),
  actionDetail: document.querySelector("#actionDetail"),
  actionType: document.querySelector("#actionType"),
  actionDestination: document.querySelector("#actionDestination"),
  adapterCalls: document.querySelector("#adapterCalls"),
  resultBanner: document.querySelector("#resultBanner"),
  resultGlyph: document.querySelector("#resultGlyph"),
  summaryProvenance: document.querySelector("#summaryProvenance"),
  summaryPolicy: document.querySelector("#summaryPolicy"),
  summaryGateway: document.querySelector("#summaryGateway"),
  timeline: document.querySelector("#timeline"),
  traceStatus: document.querySelector("#traceStatus"),
  implementationMeta: document.querySelector("#implementationMeta"),
  liveRegion: document.querySelector("#liveRegion"),
});

const state = {
  scenario: "valid",
  running: false,
  sequence: 0,
};

function text(value, fallback = "-") {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }
  return String(value);
}

function statusKind(value) {
  const normalized = String(value ?? "").toUpperCase();
  if (["PASS", "ALLOW", "READY", "RESOLVED", "VERIFIED", "EXECUTED", "COMPLETED"].includes(normalized)
    || normalized.startsWith("PASS_")
    || normalized.startsWith("ALLOW_")) {
    return "pass";
  }
  if (["BLOCK", "FAIL", "UNRESOLVED", "STALE", "ERROR"].includes(normalized)
    || normalized.startsWith("BLOCK_")
    || normalized.startsWith("FAIL_")
    || normalized.startsWith("ERROR_")) {
    return "block";
  }
  return "neutral";
}

function displayStatusKind(value) {
  return String(value ?? "").toUpperCase() === "NOT_REACHED" ? "neutral" : statusKind(value);
}

function statusLabel(value, fallback = "NOT RUN") {
  const normalized = String(value ?? "").toUpperCase();
  if (!normalized) {
    return fallback;
  }
  if (normalized === "PASS" || normalized === "ALLOW") {
    return normalized;
  }
  return normalized.replaceAll("_", " ");
}

function setStatusClass(element, kind, prefix = "state") {
  if (!element) {
    return;
  }
  element.classList.remove(`${prefix}-pass`, `${prefix}-block`, `${prefix}-neutral`);
  element.classList.add(`${prefix}-${kind}`);
}

function setText(element, value, fallback = "-") {
  if (element) {
    element.textContent = text(value, fallback);
  }
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateResponseShape(raw, expectedScenario) {
  if (!isObject(raw)
    || !["PASS", "FAIL"].includes(raw.status)
    || !["valid", "tampered"].includes(raw.scenario)
    || !isObject(raw.evidence)
    || !isObject(raw.graph)
    || !Array.isArray(raw.graph.nodes)
    || !Array.isArray(raw.graph.edges)
    || !isObject(raw.graph.metrics)
    || !isObject(raw.verification)
    || !Array.isArray(raw.verification.checks)
    || !isObject(raw.policy)
    || !isObject(raw.gateway)
    || !isObject(raw.action)
    || !Array.isArray(raw.timeline)
    || !isObject(raw.meta)) {
    throw new Error("DEMO_RESPONSE_MALFORMED");
  }
  if (raw.scenario !== expectedScenario) {
    throw new Error("DEMO_RESPONSE_SCENARIO_MISMATCH");
  }
  if (!["PASS", "BLOCK"].includes(raw.verification.status)
    || !["ALLOW", "BLOCK"].includes(raw.gateway.status)
    || !["PASS", "BLOCK", "NOT_REACHED"].includes(raw.policy.status)
    || typeof raw.action.executed !== "boolean"
    || !Number.isInteger(Number(raw.gateway.adapter_calls))
    || Number(raw.gateway.adapter_calls) < 0) {
    throw new Error("DEMO_RESPONSE_MALFORMED");
  }
  if ((raw.gateway.status === "ALLOW"
    && (raw.status !== "PASS"
      || raw.verification.status !== "PASS"
      || raw.policy.status !== "PASS"
      || raw.action.executed !== true))
    || (raw.gateway.status === "BLOCK" && raw.action.executed === true)) {
    throw new Error("DEMO_RESPONSE_CONTRADICTORY");
  }
  return raw;
}

function systemBlock(scenario, detail = "DEMO_REQUEST_FAILED") {
  // This is a display-only error envelope. It can never authorize an action.
  return {
    status: "FAIL",
    scenario,
    evidence: {
      source: "Unavailable",
      entity: "Unavailable",
      claim: "The trusted demo response could not be established.",
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
        deepest_hops: 0,
        ancestry_status: "UNRESOLVED",
      },
    },
    verification: {
      status: "BLOCK",
      reason_code: "BLOCK_SYSTEM_ERROR",
      detail,
      checks: [],
    },
    policy: {
      status: "NOT_REACHED",
      reason_code: "BLOCK_SYSTEM_ERROR",
      detail: "Policy was not evaluated.",
    },
    gateway: {
      status: "BLOCK",
      reason_code: "BLOCK_SYSTEM_ERROR",
      detail,
      adapter_calls: 0,
    },
    action: {
      executed: false,
      adapter_result: null,
      action_type: null,
      destination: null,
    },
    timeline: [],
    meta: {},
  };
}

async function postScenario(scenario, requestSequence) {
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch(`${API_BASE}${RUN_PATH}`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ scenario }),
      signal: controller.signal,
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) {
      throw new Error(`DEMO_HTTP_${response.status}`);
    }
    if (requestSequence !== state.sequence) {
      return null;
    }
    return validateResponseShape(body, scenario);
  } finally {
    globalThis.clearTimeout(timeout);
  }
}

function setConnection(kind, label) {
  if (!dom.connectionBadge || !dom.connectionText) {
    return;
  }
  dom.connectionBadge.classList.remove("status-pass", "status-block", "status-neutral");
  dom.connectionBadge.classList.add(`status-${kind}`);
  dom.connectionText.textContent = label;
}

function setScenarioButtons(scenario) {
  for (const button of [dom.validScenario, dom.tamperedScenario]) {
    const selected = button?.dataset.scenario === scenario;
    button?.classList.toggle("is-selected", selected);
    button?.setAttribute("aria-pressed", String(selected));
  }
}

function renderEvidence(evidence, scenario) {
  const kind = scenario === "tampered" ? "block" : "neutral";
  setStatusClass(dom.evidenceBadge, kind);
  setText(dom.evidenceBadge, evidence.classification || "UNTRUSTED INPUT");
  setText(dom.evidenceClaim, evidence.claim);
  setText(dom.evidenceSource, evidence.source);
  setText(dom.evidenceEntity, evidence.entity);
  setText(dom.evidenceReceived, evidence.received_at);
  setText(dom.evidenceClassification, evidence.classification);
}

function renderAttackProbe(probe) {
  const visible = isObject(probe);
  dom.attackProbe.hidden = !visible;
  if (!visible) {
    return;
  }
  const kind = displayStatusKind(probe.status);
  dom.attackProbe.classList.toggle("probe-block", kind === "block");
  setText(dom.attackProbeStatus, statusLabel(probe.status, "BLOCK"));
  setText(dom.attackProbeReason, `${text(probe.reason_code, "BLOCK_INVALID_PROVENANCE")}: ${text(probe.detail, "UNTRUSTED_CONTROL_FIELD")}. No producer-supplied graph state was accepted.`);
  setText(dom.attackChildCount, probe.child_vertices ?? probe.forged_child_vertices, "0");
  setText(dom.attackParentCount, probe.forged_parent_vertices, "0");
  setText(dom.attackEdgeCreated, probe.edge_created === true ? "YES" : "NO");
}

function graphNodeId(node) {
  if (!isObject(node)) {
    return null;
  }
  const id = node.id ?? node.artifact_id ?? node.vertex_id;
  return id === null || id === undefined ? null : String(id);
}

function graphLabel(node, id) {
  const label = node?.label ?? node?.artifact_id ?? node?.id ?? id;
  return String(label);
}

function nodeKind(node) {
  const role = String(node?.role ?? "").toLowerCase();
  if (role === "source" || node?.terminal === true || String(node?.trust_state ?? "").toLowerCase() === "trusted_source") {
    return "source";
  }
  if (role === "action_argument") {
    return "action";
  }
  if (String(node?.verification_status ?? "").toUpperCase() === "BLOCK") {
    return "block";
  }
  return "derived";
}

function truncate(value, max = 24) {
  const stringValue = String(value);
  return stringValue.length > max ? `${stringValue.slice(0, max - 1)}...` : stringValue;
}

function svgElement(tag, attributes = {}) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attributes)) {
    node.setAttribute(key, String(value));
  }
  return node;
}

function renderGraph(graph, verification) {
  const nodes = graph.nodes
    .filter((node) => graphNodeId(node) !== null)
    .map((node) => ({ ...node, id: graphNodeId(node) }));
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const edges = graph.edges
    .filter((edge) => isObject(edge) && edge.source !== undefined && edge.target !== undefined)
    .map((edge) => ({
      ...edge,
      source: String(edge.source),
      target: String(edge.target),
    }))
    .filter((edge) => nodeMap.has(edge.source) && nodeMap.has(edge.target));

  dom.graphEdges.replaceChildren();
  dom.graphNodes.replaceChildren();
  dom.graphEmpty.classList.toggle("is-hidden", nodes.length > 0);

  const metrics = graph.metrics || {};
  setText(dom.metricNodes, metrics.node_count ?? nodes.length);
  setText(dom.metricEdges, metrics.edge_count ?? edges.length);
  setText(dom.metricWitnesses, metrics.witness_count ?? 0);
  setText(dom.metricPaths, metrics.path_count ?? 0);
  setText(dom.metricDepth, metrics.deepest_hops ?? 0);
  setText(dom.metricBound, metrics.max_depth ?? "-");
  setText(dom.directionNote, graph.direction_note, "Graph direction unavailable.");

  const systemUnavailable = verification?.reason_code === "BLOCK_SYSTEM_ERROR";
  const ancestryLabel = systemUnavailable
    ? "UNAVAILABLE"
    : (metrics.ancestry_status || verification.status);
  const graphKind = systemUnavailable ? "block" : statusKind(ancestryLabel);
  setStatusClass(dom.graphState, graphKind);
  setText(dom.graphState, statusLabel(ancestryLabel, "WAITING"));
  dom.witnessSummary.classList.toggle("is-block", graphKind === "block");
  dom.witnessSummary.textContent = systemUnavailable
    ? "HydraDB graph state was unavailable or unverified. Quarantine failed closed before authorization."
    : graphKind === "block"
    ? `${text(metrics.witness_count, 0)} provenance witnesses across ${text(metrics.path_count, 0)} source-to-action path(s); unresolved ancestry cannot authorize an action.`
    : `${text(metrics.witness_count, 0)} provenance witnesses across ${text(metrics.path_count, 0)} source-to-action path(s), ${text(metrics.node_count, nodes.length)} nodes, and ${text(metrics.edge_count, edges.length)} edges. HydraDB proves connected ancestry, not text similarity.`;
  dom.graphDescription.textContent = systemUnavailable
    ? "HydraDB graph state was unavailable or unverified; the action failed closed."
    : `HydraDB graph: ${text(metrics.node_count, nodes.length)} nodes, ${text(metrics.edge_count, edges.length)} edges, ${text(metrics.witness_count, 0)} witnesses, ancestry ${text(metrics.ancestry_status, "unknown")}.`;

  const frontierId = verification?.frontier_artifact_id;
  const bound = metrics.max_depth ?? verification?.graph_snapshot?.max_depth;
  const observed = metrics.deepest_hops;
  const unresolved = verification?.reason_code === "BLOCK_UNRESOLVED_ANCESTRY"
    || Boolean(frontierId);
  dom.frontierNotice.hidden = !unresolved;
  if (unresolved) {
    const frontierLabel = graph.nodes.find((node) => graphNodeId(node) === frontierId)?.label || frontierId || "the unresolved frontier";
    setText(dom.frontierDetail, `Observed depth ${text(observed, "-")}; authorization bound ${text(bound, "-")}. Frontier: ${frontierLabel}. The graph is visible, but the gateway cannot authorize beyond its bound.`);
  }

  if (nodes.length === 0) {
    return;
  }

  const generations = nodes.map((node) => Number.isFinite(Number(node.generation)) ? Number(node.generation) : 0);
  const minGeneration = Math.min(...generations);
  const maxGeneration = Math.max(...generations);
  const groups = new Map();
  for (const node of nodes) {
    const generation = Number.isFinite(Number(node.generation)) ? Number(node.generation) : 0;
    if (!groups.has(generation)) {
      groups.set(generation, []);
    }
    groups.get(generation).push(node);
  }
  const positions = new Map();
  const left = 76;
  const right = 684;
  const top = 58;
  const bottom = 320;
  const generationSpan = Math.max(1, maxGeneration - minGeneration);
  for (const [generation, group] of [...groups.entries()].sort((a, b) => a[0] - b[0])) {
    const x = left + ((generation - minGeneration) / generationSpan) * (right - left);
    const spacing = (bottom - top) / Math.max(1, group.length - 1);
    group.forEach((node, index) => {
      positions.set(node.id, {
        x,
        y: group.length === 1 ? (top + bottom) / 2 : top + (spacing * index),
      });
    });
  }

  const defs = svgElement("defs");
  const marker = svgElement("marker", {
    id: "graphArrow",
    viewBox: "0 0 10 10",
    refX: "9",
    refY: "5",
    markerWidth: "5",
    markerHeight: "5",
    orient: "auto-start-reverse",
  });
  marker.append(svgElement("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: "#6d7e8b" }));
  defs.append(marker);
  dom.graphEdges.append(defs);

  for (const edge of edges) {
    const source = positions.get(edge.source);
    const target = positions.get(edge.target);
    if (!source || !target) {
      continue;
    }
    const deltaX = target.x - source.x;
    const deltaY = target.y - source.y;
    const distance = Math.hypot(deltaX, deltaY) || 1;
    const unitX = deltaX / distance;
    const unitY = deltaY / distance;
    const line = svgElement("line", {
      x1: source.x + (unitX * 21),
      y1: source.y + (unitY * 21),
      x2: target.x - (unitX * 27),
      y2: target.y - (unitY * 27),
      class: `graph-edge${edge.target === frontierId ? " edge-frontier" : ""}`,
      "marker-end": "url(#graphArrow)",
    });
    const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
    title.textContent = `${edge.kind || "DERIVES_FROM"}: ${edge.source} -> ${edge.target}`;
    line.append(title);
    dom.graphEdges.append(line);

    if (edge.kind) {
      const label = svgElement("text", {
        x: (source.x + target.x) / 2,
        y: (source.y + target.y) / 2 - 8,
        class: "graph-edge-label",
      });
      label.textContent = String(edge.kind).toUpperCase();
      dom.graphEdges.append(label);
    }
  }

  for (const node of nodes) {
    const position = positions.get(node.id);
    if (!position) {
      continue;
    }
    const kind = nodeKind(node);
    const group = svgElement("g", {
      class: `graph-node node-${kind}`,
      transform: `translate(${position.x} ${position.y})`,
    });
    const circle = svgElement("circle", { r: 19 });
    const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
    title.textContent = `${graphLabel(node, node.id)} / ${node.role || "artifact"} / generation ${text(node.generation, 0)}`;
    circle.append(title);
    group.append(circle);

    const label = svgElement("text", { x: 0, y: 39, "text-anchor": "middle" });
    label.textContent = truncate(graphLabel(node, node.id), 27);
    group.append(label);
    const role = svgElement("text", { x: 0, y: 52, class: "node-role", "text-anchor": "middle" });
    role.textContent = String(node.role || "artifact").replaceAll("_", " ");
    group.append(role);
    dom.graphNodes.append(group);
  }
}

function renderChecks(checks) {
  dom.verificationChecks.replaceChildren();
  if (!checks.length) {
    const empty = document.createElement("li");
    empty.className = "check-item check-neutral";
    empty.textContent = "No verification checks returned.";
    dom.verificationChecks.append(empty);
    return;
  }
  for (const check of checks) {
    const item = document.createElement("li");
    const kind = statusKind(check?.status);
    item.className = `check-item check-${kind}`;
    const icon = document.createElement("span");
    icon.className = "check-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = kind === "pass" ? "OK" : kind === "block" ? "NO" : "-";
    const label = document.createElement("span");
    label.textContent = text(check?.label, "Verification check");
    const result = document.createElement("strong");
    result.textContent = statusLabel(check?.status, "-");
    item.append(icon, label, result);
    dom.verificationChecks.append(item);
  }
}

function renderDecision(response) {
  const verification = response.verification;
  const policy = response.policy;
  const gateway = response.gateway;
  const verificationKind = statusKind(verification.status);
  const policyKind = displayStatusKind(policy.status);
  const gatewayKind = statusKind(gateway.status);

  setStatusClass(dom.decisionBadge, gatewayKind);
  setText(dom.decisionBadge, statusLabel(gateway.status, "WAITING"));
  dom.decisionBadge.setAttribute("aria-label", `Gateway ${statusLabel(gateway.status)}`);

  setText(dom.verificationStatus, statusLabel(verification.status));
  dom.verificationStatus.className = `section-status status-${verificationKind}-text`;
  renderChecks(verification.checks);
  setText(dom.verificationDetail, verification.reason_code
    ? `${verification.reason_code}: ${verification.detail || "The verifier did not resolve the required ancestry."}`
    : (verification.detail || "The trusted verifier returned a complete graph-backed result."));

  setText(dom.policyStatus, statusLabel(policy.status));
  dom.policyStatus.className = `section-status status-${policyKind}-text`;
  setText(dom.policyDetail, policy.status === "NOT_REACHED"
    ? "Not evaluated because provenance verification stopped the authorization pipeline."
    : (policy.detail || policy.reason_code || "Policy result returned by the trusted gateway."));

  setText(dom.gatewayStatus, statusLabel(gateway.status));
  dom.gatewayStatus.className = `section-status status-${gatewayKind}-text`;
  dom.gatewayOutcome.className = `gateway-outcome gateway-${gatewayKind}`;
  dom.gatewayOutcome.replaceChildren();
  const symbol = document.createElement("span");
  symbol.className = "gateway-symbol";
  symbol.setAttribute("aria-hidden", "true");
  symbol.textContent = gatewayKind === "pass" ? "OK" : gatewayKind === "block" ? "NO" : "-";
  const outcomeCopy = document.createElement("div");
  const outcomeTitle = document.createElement("strong");
  outcomeTitle.textContent = gateway.status === "ALLOW" ? "ACTION ALLOWED" : "ACTION NOT EXECUTED";
  const outcomeDetail = document.createElement("span");
  outcomeDetail.textContent = gateway.reason_code
    ? `${gateway.reason_code}: ${gateway.detail || "The gateway failed closed."}`
    : (gateway.detail || "The gateway returned no execution detail.");
  outcomeCopy.append(outcomeTitle, outcomeDetail);
  dom.gatewayOutcome.append(symbol, outcomeCopy);

  const action = response.action;
  setText(dom.actionType, action.action_type);
  setText(dom.actionDestination, action.destination);
  setText(dom.adapterCalls, gateway.adapter_calls, "0");
  if (gateway.status === "ALLOW" && action.executed === true) {
    setText(dom.actionOutcome, "ACTION EXECUTED / DRY RUN");
    setText(dom.actionDetail, action.adapter_result || "The gateway-issued action reached the dry-run adapter.");
  } else {
    setText(dom.actionOutcome, "ACTION NOT EXECUTED");
    setText(dom.actionDetail, gateway.reason_code
      ? `${gateway.reason_code}: ${gateway.detail || "The gateway failed closed."}`
      : "The action adapter was not called.");
  }
}

function renderResultSummary(response) {
  const verification = response.verification || {};
  const policy = response.policy || {};
  const gateway = response.gateway || {};
  const action = response.action || {};
  const gatewayKind = displayStatusKind(gateway.status);
  const verificationLabel = verification.ancestry_status
    ? statusLabel(verification.ancestry_status)
    : verification.status === "PASS"
      ? "RESOLVED"
      : statusLabel(verification.reason_code || verification.status, "BLOCKED");
  const policyLabel = policy.status === "NOT_REACHED" ? "NOT REACHED" : statusLabel(policy.status, "WAITING");
  setStatusClass(dom.resultBanner, gatewayKind, "result");
  dom.resultBanner.classList.toggle("result-running", state.running);
  setText(dom.resultGlyph, gateway.status === "ALLOW" ? "✓" : gateway.status === "BLOCK" ? "×" : "…");
  setText(dom.summaryProvenance, verificationLabel);
  setText(dom.summaryPolicy, policyLabel);
  setText(dom.summaryGateway, gateway.status === "ALLOW"
    ? "ALLOWED"
    : gateway.status === "BLOCK"
      ? "BLOCKED"
      : statusLabel(gateway.status, "WAITING"));
  const resultText = gateway.status === "ALLOW"
    ? "ACTION ALLOWED / DRY RUN"
    : gateway.status === "BLOCK"
      ? "ACTION BLOCKED"
      : "VERIFYING LIVE PROVENANCE";
  setText(dom.actionOutcome, resultText);
  const adapterCallCount = Number(gateway.adapter_calls ?? 0);
  setText(dom.actionDetail, gateway.status === "ALLOW"
    ? `Trusted state passed deterministic policy. Adapter invoked ${adapterCallCount} ${adapterCallCount === 1 ? "time" : "times"}.`
    : gateway.status === "BLOCK"
      ? `${text(gateway.reason_code, "BLOCK_SYSTEM_ERROR")}: ${text(gateway.detail, "The gateway failed closed.")}. Adapter invoked ${text(gateway.adapter_calls, 0)} times.`
      : "The adapter cannot run until the trusted core returns a decision.");
  setStatusClass(dom.summaryProvenance, displayStatusKind(verification.status), "summary");
  setStatusClass(dom.summaryPolicy, policyKindForSummary(policy.status), "summary");
  setStatusClass(dom.summaryGateway, gatewayKind, "summary");
  setStatusClass(dom.adapterCalls, gatewayKind, "summary");
  setText(dom.adapterCalls, gateway.adapter_calls, "0");
  setText(dom.actionType, action.action_type);
  setText(dom.actionDestination, action.destination);
}

function policyKindForSummary(value) {
  return String(value ?? "").toUpperCase() === "NOT_REACHED" ? "neutral" : displayStatusKind(value);
}

function renderTimeline(timeline) {
  dom.timeline.replaceChildren();
  if (!timeline.length) {
    const empty = document.createElement("li");
    empty.className = "timeline-empty";
    empty.textContent = "No event trace was returned.";
    dom.timeline.append(empty);
    setText(dom.traceStatus, "No trace");
    return;
  }
  for (const event of timeline) {
    const item = document.createElement("li");
    const kind = statusKind(event?.status);
    item.className = `timeline-item timeline-${kind}`;
    const marker = document.createElement("span");
    marker.className = "timeline-marker";
    marker.setAttribute("aria-hidden", "true");
    const at = document.createElement("span");
    at.className = "timeline-time";
    at.textContent = text(event?.at, "-");
    const label = document.createElement("span");
    label.className = "timeline-label";
    label.textContent = text(event?.label, "Event");
    const detail = document.createElement("span");
    detail.className = "timeline-detail";
    detail.textContent = text(event?.detail, "-");
    item.append(marker, at, label, detail);
    dom.timeline.append(item);
  }
  setText(dom.traceStatus, `${timeline.length} events`);
}

function renderMeta(meta) {
  const hydradb = isObject(meta.hydradb) ? meta.hydradb : {};
  const host = hydradb.http || hydradb.url || "HydraDB";
  const versions = [meta.verifier_version, meta.policy_version, meta.gateway_version]
    .filter(Boolean)
    .join(" / ");
  dom.implementationMeta.textContent = versions
    ? `${host} / ${versions}`
    : `${host} / Authorization remains server-side.`;
}

function renderResponse(response) {
  state.scenario = response.scenario;
  setScenarioButtons(state.scenario);
  const scenarioCopy = SCENARIOS[state.scenario] || SCENARIOS.valid;
  setText(dom.demoTitle, scenarioCopy.title);
  setText(dom.demoSubtitle, scenarioCopy.subtitle);
  renderEvidence(response.evidence, response.scenario);
  renderAttackProbe(response.attack_probe);
  renderGraph(response.graph, response.verification);
  renderDecision(response);
  renderResultSummary(response);
  renderTimeline(response.timeline);
  renderMeta(response.meta);
  const gatewayKind = statusKind(response.gateway.status);
  setConnection("pass", "HYDRADB CONNECTED");
  setText(dom.liveRegion, gatewayKind === "pass"
    ? "Verified action allowed and dry-run executed."
    : `Action blocked: ${response.gateway.reason_code || response.gateway.detail || "fail closed"}.`);
}

function renderFailure(response) {
  state.scenario = response.scenario;
  setScenarioButtons(state.scenario);
  setText(dom.demoTitle, "The trusted run could not be established.");
  setText(dom.demoSubtitle, "Quarantine treats malformed or unavailable verification as a system block.");
  renderEvidence(response.evidence, response.scenario);
  renderAttackProbe(null);
  renderGraph(response.graph, response.verification);
  renderDecision(response);
  renderResultSummary(response);
  renderTimeline(response.timeline);
  renderMeta(response.meta);
  setConnection("block", "SYSTEM BLOCK");
  setText(dom.liveRegion, "The demo response was unavailable. Action blocked by the system boundary.");
}

async function runScenario(scenario) {
  if (!SCENARIOS[scenario] || state.running) {
    return;
  }
  state.running = true;
  state.sequence += 1;
  const requestSequence = state.sequence;
  setScenarioButtons(scenario);
  document.querySelector("#live-demo")?.setAttribute("aria-busy", "true");
  document.querySelector(".demo-section")?.classList.add("is-running");
  for (const button of [dom.validScenario, dom.tamperedScenario]) {
    if (button) button.disabled = true;
  }
  setConnection("neutral", "VERIFYING");
  renderResultSummary({ verification: { status: "WAITING" }, policy: { status: "NOT_REACHED" }, gateway: { status: "WAITING", adapter_calls: 0 }, action: {} });
  dom.resultBanner?.classList.add("result-running");
  setText(dom.traceStatus, "Running");
  try {
    const result = await postScenario(scenario, requestSequence);
    if (!result) {
      return;
    }
    if (result.gateway.status === "ALLOW" && result.action.executed !== true) {
      // A contradictory response is unsafe to display as an allow.
      renderFailure(systemBlock(scenario, "DEMO_RESPONSE_CONTRADICTORY"));
    } else if (result.status === "PASS") {
      renderResponse(result);
    } else if (result.status === "FAIL") {
      renderFailure(result);
    } else {
      renderFailure(systemBlock(scenario, "DEMO_RESPONSE_MALFORMED"));
    }
  } catch (error) {
    const detail = error?.name === "AbortError" ? "DEMO_REQUEST_TIMEOUT" : (error?.message || "DEMO_REQUEST_FAILED");
    renderFailure(systemBlock(scenario, detail));
  } finally {
    state.running = false;
    document.querySelector("#live-demo")?.setAttribute("aria-busy", "false");
    document.querySelector(".demo-section")?.classList.remove("is-running");
    dom.resultBanner?.classList.remove("result-running");
    for (const button of [dom.validScenario, dom.tamperedScenario]) {
      if (button) button.disabled = false;
    }
  }
}

dom.validScenario?.addEventListener("click", () => runScenario("valid"));
dom.tamperedScenario?.addEventListener("click", () => runScenario("tampered"));

// Start with a real server request. There is deliberately no fixture fallback:
// a disconnected UI displays SYSTEM BLOCK rather than pretending to verify.
runScenario("valid");

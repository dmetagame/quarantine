#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { performance } from "node:perf_hooks";

const httpBase = process.env.HYDRA_HTTP_URL ?? "http://127.0.0.1:18443";
const adminBase = process.env.HYDRA_ADMIN_URL ?? "http://127.0.0.1:19091";
const token = process.env.HYDRA_AUTH_TOKEN ?? "local-development-token-32-bytes";
const namespace = process.env.HYDRA_NAMESPACE ?? "default";
const graphId = process.env.HYDRA_GRAPH_ID ?? "default";
const cellId = process.env.HYDRA_CELL_ID ?? "cell-0";
const container = process.env.QUARANTINE_HYDRADB_CONTAINER ?? "quarantine-hydradb";
const defaultImage = "ghcr.io/hydra-db/hydradb:0.1.1";
const defaultImageDigest = "sha256:db78309a233be54662db29744047e985a39b51c45a270d1a1f47c31a62cdb709";
const image = process.env.HYDRA_IMAGE ?? defaultImage;
const imageDigest = process.env.HYDRA_IMAGE_DIGEST ?? (image === defaultImage ? defaultImageDigest : null);
const outputPath = resolve(process.env.QUARANTINE_PROOF_OUTPUT ?? "evidence/latest-proof.json");

const artifacts = [
  { vertex: 100, key: "source:external", role: "source", generation: 0, trust: "untrusted", terminal: true },
  { vertex: 110, key: "summary:external:1", role: "summary", generation: 1, trust: "derived", terminal: false },
  { vertex: 120, key: "summary:external:2", role: "summary", generation: 2, trust: "derived", terminal: false },
  { vertex: 130, key: "action:poisoned", role: "action_argument", generation: 3, trust: "derived", terminal: false },
  { vertex: 200, key: "source:catalog", role: "source", generation: 0, trust: "trusted", terminal: true },
  { vertex: 210, key: "claim:catalog", role: "claim", generation: 1, trust: "derived", terminal: false },
  { vertex: 220, key: "action:safe", role: "action_argument", generation: 2, trust: "derived", terminal: false },
  { vertex: 230, key: "action:mixed", role: "action_argument", generation: 3, trust: "derived", terminal: false },
  { vertex: 300, key: "source:deep", role: "source", generation: 0, trust: "untrusted", terminal: true },
  { vertex: 310, key: "deep:1", role: "claim", generation: 1, trust: "derived", terminal: false },
  { vertex: 320, key: "deep:2", role: "summary", generation: 2, trust: "derived", terminal: false },
  { vertex: 330, key: "deep:3", role: "summary", generation: 3, trust: "derived", terminal: false },
  { vertex: 340, key: "action:deep", role: "action_argument", generation: 4, trust: "derived", terminal: false },
];

const derivations = [
  { child: 110, parent: 100, edge_id: 1001, kind: "summarize" },
  { child: 120, parent: 110, edge_id: 1002, kind: "summarize" },
  { child: 130, parent: 120, edge_id: 1003, kind: "require" },
  { child: 210, parent: 200, edge_id: 1004, kind: "assert" },
  { child: 220, parent: 210, edge_id: 1005, kind: "require" },
  { child: 230, parent: 120, edge_id: 1006, kind: "require" },
  { child: 230, parent: 210, edge_id: 1007, kind: "support" },
  { child: 310, parent: 300, edge_id: 1008, kind: "assert" },
  { child: 320, parent: 310, edge_id: 1009, kind: "summarize" },
  { child: 330, parent: 320, edge_id: 1010, kind: "summarize" },
  { child: 340, parent: 330, edge_id: 1011, kind: "require" },
];

const throughputProbeVertices = Array.from({ length: 512 }, (_, index) => ({
  vertex: 10000 + index,
  batch_key: `probe:${index}`,
  generation: index,
}));

const throughputProbeRelationships = Array.from({ length: 511 }, (_, index) => ({
  child: 10001 + index,
  parent: 10000 + index,
  edge_id: 20000 + index,
  kind: "probe",
}));

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function propertyValue(value) {
  if (value === null || value === undefined || typeof value !== "object") {
    return value;
  }
  const entries = Object.entries(value);
  if (entries.length !== 1) {
    return value;
  }
  return entries[0][1];
}

function nodeProperty(node, name) {
  return propertyValue(node.properties?.[name]);
}

function relationshipProperty(relationship, name) {
  return propertyValue(relationship.properties?.[name]);
}

function pathRows(response) {
  return response.rows.map((row) => {
    const value = row[0];
    assert(value?.type === "path", `Expected a path value, received ${JSON.stringify(value)}`);
    return value.value;
  });
}

function pathKeys(path) {
  return path.nodes.map((node) => nodeProperty(node, "key"));
}

function singleScalar(response, description) {
  assert(response.rows.length === 1, `${description} returned ${response.rows.length} rows`);
  assert(response.rows[0].length === 1, `${description} returned an unexpected column count`);
  return response.rows[0][0].value;
}

function queryRequestBody(query, parameters) {
  return {
    cell_id: cellId,
    query,
    parameters,
    page_size: 1000,
    consistency: "strong",
  };
}

function queryRequestBytes(query, parameters) {
  return Buffer.byteLength(JSON.stringify(queryRequestBody(query, parameters)), "utf8");
}

function validateIncomingWitness(path) {
  assert(path.nodes.length === path.relationships.length + 1, "Malformed path cardinality");
  for (let index = 0; index < path.relationships.length; index += 1) {
    const parent = path.nodes[index];
    const child = path.nodes[index + 1];
    const relationship = path.relationships[index];
    assert(relationship.edge_type === "DERIVES_FROM", "Witness contains a non-lineage edge");
    assert(relationship.src === child.id && relationship.dst === parent.id, "Incoming traversal returned an invalid child-to-parent relationship");
    assert(nodeProperty(parent, "generation") < nodeProperty(child, "generation"), "Generation did not increase from parent to child");
  }
  assert(nodeProperty(path.nodes[0], "terminal") === true, "Incoming witness did not begin at a terminal source");
}

async function hydraQuery(query, parameters = {}) {
  const response = await fetch(`${httpBase}/v1/graphs/${graphId}/query`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "X-Graph-Namespace": namespace,
    },
    body: JSON.stringify(queryRequestBody(query, parameters)),
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(`HydraDB query failed (${response.status}): ${JSON.stringify(body)}`);
  }
  return body;
}

async function main() {
  const readyResponse = await fetch(`${adminBase}/readyz`);
  assert(readyResponse.ok, `HydraDB is not ready at ${adminBase}`);

  const vertexQuery = "UNWIND $rows AS row MERGE (n {id: row.vertex}) SET n:Artifact, n.key = row.key, n.role = row.role, n.generation = row.generation, n.trust = row.trust, n.terminal = row.terminal";
  const edgeQuery = "UNWIND $rows AS row MATCH (s:Artifact {id: row.child}), (d:Artifact {id: row.parent}) MERGE (s)-[r:DERIVES_FROM {id: row.edge_id}]->(d) SET r.kind = row.kind";

  const vertexStarted = performance.now();
  const vertexResult = await hydraQuery(vertexQuery, { rows: artifacts });
  const vertexWriteMs = performance.now() - vertexStarted;

  const edgeStarted = performance.now();
  const edgeResult = await hydraQuery(edgeQuery, { rows: derivations });
  const edgeWriteMs = performance.now() - edgeStarted;

  const probeVertexQuery = "UNWIND $rows AS row MERGE (n {id: row.vertex}) SET n:BatchProbe, n.batch_key = row.batch_key, n.generation = row.generation";
  const probeRelationshipQuery = "UNWIND $rows AS row MATCH (s:BatchProbe {id: row.child}), (d:BatchProbe {id: row.parent}) MERGE (s)-[r:BATCH_LINK {id: row.edge_id}]->(d) SET r.kind = row.kind";

  const probeVertexParameters = { rows: throughputProbeVertices };
  const probeVertexStarted = performance.now();
  const probeVertexResult = await hydraQuery(probeVertexQuery, probeVertexParameters);
  const probeVertexWriteMs = performance.now() - probeVertexStarted;

  const probeRelationshipParameters = { rows: throughputProbeRelationships };
  const probeRelationshipStarted = performance.now();
  const probeRelationshipResult = await hydraQuery(probeRelationshipQuery, probeRelationshipParameters);
  const probeRelationshipWriteMs = performance.now() - probeRelationshipStarted;

  const probeVertexCountResult = await hydraQuery("MATCH (n:BatchProbe) RETURN count(*) AS total");
  const probeRelationshipCountResult = await hydraQuery("MATCH ()-[r:BATCH_LINK]->() RETURN count(*) AS total");
  const probeVertexCount = singleScalar(probeVertexCountResult, "BatchProbe vertex count");
  const probeRelationshipCount = singleScalar(probeRelationshipCountResult, "BATCH_LINK relationship count");
  assert(probeVertexCount === throughputProbeVertices.length, `Expected ${throughputProbeVertices.length} BatchProbe vertices, received ${probeVertexCount}`);
  assert(probeRelationshipCount === throughputProbeRelationships.length, `Expected ${throughputProbeRelationships.length} BATCH_LINK relationships, received ${probeRelationshipCount}`);

  const incomingQuery = "CALL algo.MSpaths({sourceLabel: 'Artifact', sourceProperty: 'key', sourceValues: ['source:external', 'source:catalog'], targetValues: ['action:poisoned', 'action:safe', 'action:mixed'], pairwise: false, relTypes: ['DERIVES_FROM'], relDirection: 'incoming', maxLen: 3, pathCount: 8, resultLimit: 64}) YIELD path RETURN path";
  const incomingStarted = performance.now();
  const incomingResult = await hydraQuery(incomingQuery);
  const incomingReadMs = performance.now() - incomingStarted;
  const incomingPaths = pathRows(incomingResult);
  incomingPaths.forEach(validateIncomingWitness);

  const endpointPairs = new Set(incomingPaths.map((path) => {
    const keys = pathKeys(path);
    return `${keys[0]} -> ${keys.at(-1)}`;
  }));
  const expectedPairs = [
    "source:external -> action:poisoned",
    "source:external -> action:mixed",
    "source:catalog -> action:safe",
    "source:catalog -> action:mixed",
  ];
  expectedPairs.forEach((pair) => assert(endpointPairs.has(pair), `Missing indexed MSpaths pair: ${pair}`));

  const edgeKinds = new Set(incomingPaths.flatMap((path) => path.relationships.map((relationship) => relationshipProperty(relationship, "kind"))));
  ["assert", "summarize", "support", "require"].forEach((kind) => assert(edgeKinds.has(kind), `Missing returned DERIVES_FROM.kind=${kind}`));

  const cappedTerminalQuery = "CALL algo.MSpaths({sourceLabel: 'Artifact', sourceProperty: 'key', sourceValues: ['source:deep'], targetValues: ['action:deep'], pairwise: false, relTypes: ['DERIVES_FROM'], relDirection: 'incoming', maxLen: 3, pathCount: 8, resultLimit: 32}) YIELD path RETURN path";
  const cappedTerminalPaths = pathRows(await hydraQuery(cappedTerminalQuery));
  assert(cappedTerminalPaths.length === 0, "Depth-capped terminal query unexpectedly reached the source");

  const frontierQuery = "CALL algo.MSpaths({sourceLabel: 'Artifact', sourceProperty: 'key', sourceValues: ['action:deep'], targetValues: ['deep:3', 'deep:2', 'deep:1', 'source:deep'], pairwise: false, relTypes: ['DERIVES_FROM'], relDirection: 'outgoing', maxLen: 3, pathCount: 8, resultLimit: 32}) YIELD path RETURN path";
  const frontierPaths = pathRows(await hydraQuery(frontierQuery));
  const deepest = frontierPaths.reduce((selected, path) => path.relationships.length > selected.relationships.length ? path : selected, { nodes: [], relationships: [] });
  assert(deepest.relationships.length === 3, "Did not observe the configured depth frontier");
  const frontierNode = deepest.nodes.at(-1);
  assert(nodeProperty(frontierNode, "terminal") === false, "Depth frontier unexpectedly ended at a terminal source");
  assert(nodeProperty(frontierNode, "generation") > 0, "Depth frontier did not preserve unresolved ancestry");

  const report = {
    status: "PASS",
    recorded_at: new Date().toISOString(),
    container,
    image,
    ...(imageDigest ? { image_digest: imageDigest } : {}),
    hydradb: {
      http: httpBase,
      admin: adminBase,
      graph: graphId,
      namespace,
      cell: cellId,
    },
    batch_ingestion: {
      vertices: artifacts.length,
      relationships: derivations.length,
      vertex_write_ms: Number(vertexWriteMs.toFixed(2)),
      relationship_write_ms: Number(edgeWriteMs.toFixed(2)),
      bookmarks: [vertexResult.bookmark, edgeResult.bookmark].filter(Boolean),
    },
    batch_throughput_probe: {
      vertex_batch: {
        rows: throughputProbeVertices.length,
        request_bytes: queryRequestBytes(probeVertexQuery, probeVertexParameters),
        elapsed_ms: Number(probeVertexWriteMs.toFixed(2)),
        bookmark: probeVertexResult.bookmark,
      },
      relationship_batch: {
        rows: throughputProbeRelationships.length,
        request_bytes: queryRequestBytes(probeRelationshipQuery, probeRelationshipParameters),
        elapsed_ms: Number(probeRelationshipWriteMs.toFixed(2)),
        bookmark: probeRelationshipResult.bookmark,
      },
      verified_counts: {
        vertices: probeVertexCount,
        relationships: probeRelationshipCount,
        read_epoch: probeRelationshipCountResult.read_epoch,
      },
    },
    indexed_reverse_mspaths: {
      query_ms: Number(incomingReadMs.toFixed(2)),
      witness_count: incomingPaths.length,
      required_pairs: expectedPairs,
      returned_edge_kinds: [...edgeKinds].sort(),
      witnesses: incomingPaths.map(pathKeys),
      read_epoch: incomingResult.read_epoch,
    },
    depth_cap: {
      terminal_paths_with_max_len_3: cappedTerminalPaths.length,
      deepest_frontier_hops: deepest.relationships.length,
      frontier_key: nodeProperty(frontierNode, "key"),
      frontier_generation: nodeProperty(frontierNode, "generation"),
      decision: "BLOCK_UNRESOLVED_ANCESTRY",
    },
    notes: [
      "Timings are local cold-path observations, not benchmark claims.",
      "HydraDB property indexes are maintained automatically by canonical writes.",
      "Incoming witnesses preserve each relationship's stored child-to-parent src/dst orientation.",
      "The throughput probe is idempotent and verifies exact stored counts after each run.",
    ],
  };

  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, serialized, "utf8");
  process.stdout.write(serialized);
  process.stderr.write(`Proof evidence written to ${outputPath}\n`);
}

main().catch((error) => {
  process.stderr.write(`PROOF FAILED: ${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});

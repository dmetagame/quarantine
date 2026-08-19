import assert from "node:assert/strict";
import test from "node:test";

import {
  createHydraClient,
  projectedRows,
  resultCellValue,
} from "../src/hydradb-client.mjs";

test("forwards causal and bounded HTTP query options", () => {
  const client = createHydraClient();
  const body = client.requestBody("MATCH (n) RETURN n", {}, {
    queryId: "stable-write-id",
    bookmark: "sgk:test-bookmark",
    pageSize: 42,
    timeoutMs: 1500,
  });

  assert.equal(body.query_id, "stable-write-id");
  assert.equal(body.bookmark, "sgk:test-bookmark");
  assert.equal(body.page_size, 42);
  assert.equal(body.timeout_ms, 1500);
  assert.equal("read_epoch" in body, false);
});

test("rejects invalid query bounds before network access", () => {
  const client = createHydraClient();
  assert.throws(
    () => client.requestBody("RETURN 1", {}, { pageSize: 0 }),
    /pageSize/,
  );
  assert.throws(
    () => client.requestBody("RETURN 1", {}, { pageSize: 4097 }),
    /pageSize/,
  );
  assert.throws(
    () => client.requestBody("RETURN 1", {}, { timeoutMs: -1 }),
    /timeoutMs/,
  );
});

test("hydrates HydraDB scalar property projections including nulls", () => {
  const response = {
    columns: ["vertex_id", "artifact_id", "terminal", "authority_id"],
    rows: [[
      { type: "vertex_id", value: 42 },
      { type: "string", value: "source-42" },
      { type: "boolean", value: true },
      { type: "null" },
    ]],
  };

  assert.deepEqual(projectedRows(response), [{
    vertex_id: 42,
    artifact_id: "source-42",
    terminal: true,
    authority_id: null,
  }]);
  assert.equal(resultCellValue({ type: "null" }), null);
});

test("rejects malformed projected result shapes", () => {
  assert.throws(
    () => projectedRows({ columns: ["artifact_id"], rows: [[]] }),
    /unexpected result shape/,
  );
});

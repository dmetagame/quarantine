const DEFAULTS = Object.freeze({
  httpBase: "http://127.0.0.1:18443",
  adminBase: "http://127.0.0.1:19091",
  token: "local-development-token-32-bytes",
  namespace: "default",
  graphId: "default",
  cellId: "cell-0",
});

export function propertyValue(value) {
  if (value === null || value === undefined || typeof value !== "object") {
    return value;
  }

  const entries = Object.entries(value);
  if (entries.length !== 1) {
    return value;
  }

  return entries[0][1];
}

// HydraDB 0.1.x exposes scalar property projections, not whole node or
// relationship bindings. Convert a typed result cell into the scalar value
// used by the rest of the application.
export function resultCellValue(cell) {
  if (cell === null || cell === undefined || typeof cell !== "object") {
    return cell;
  }
  if (cell.type === "null") {
    return null;
  }
  if (Object.prototype.hasOwnProperty.call(cell, "value")) {
    return cell.value;
  }
  return cell;
}

export function projectedRows(response) {
  if (!response || !Array.isArray(response.columns) || !Array.isArray(response.rows)) {
    throw new Error("HydraDB projected response has an unexpected result shape");
  }

  return response.rows.map((row, rowIndex) => {
    if (!Array.isArray(row) || row.length !== response.columns.length) {
      throw new Error(`HydraDB projected row ${rowIndex} has an unexpected result shape`);
    }
    return Object.fromEntries(
      response.columns.map((column, columnIndex) => [
        column,
        resultCellValue(row[columnIndex]),
      ]),
    );
  });
}

export function nodeProperty(node, name) {
  return propertyValue(node?.properties?.[name]);
}

export function relationshipProperty(relationship, name) {
  return propertyValue(relationship?.properties?.[name]);
}

export function singleScalar(response, description = "query") {
  if (response.rows.length !== 1 || response.rows[0].length !== 1) {
    throw new Error(`${description} returned an unexpected result shape`);
  }

  const cell = response.rows[0][0];
  return propertyValue(cell && typeof cell === "object" && "value" in cell ? cell.value : cell);
}

export function nodeRows(response, column = 0) {
  return response.rows.map((row) => {
    const value = row[column];
    if (value?.type !== "node") {
      throw new Error(`Expected node result, received ${JSON.stringify(value)}`);
    }
    return value.value;
  });
}

export function relationshipRows(response, column = 0) {
  return response.rows.map((row) => {
    const value = row[column];
    if (value?.type !== "relationship") {
      throw new Error(`Expected relationship result, received ${JSON.stringify(value)}`);
    }
    return value.value;
  });
}

export function pathRows(response, column = 0) {
  return response.rows.map((row) => {
    const value = row[column];
    if (value?.type !== "path") {
      throw new Error(`Expected path result, received ${JSON.stringify(value)}`);
    }
    return value.value;
  });
}

export function createHydraClient(options = {}) {
  const config = {
    httpBase: options.httpBase ?? process.env.HYDRA_HTTP_URL ?? DEFAULTS.httpBase,
    adminBase: options.adminBase ?? process.env.HYDRA_ADMIN_URL ?? DEFAULTS.adminBase,
    token: options.token ?? process.env.HYDRA_AUTH_TOKEN ?? DEFAULTS.token,
    namespace: options.namespace ?? process.env.HYDRA_NAMESPACE ?? DEFAULTS.namespace,
    graphId: options.graphId ?? process.env.HYDRA_GRAPH_ID ?? DEFAULTS.graphId,
    cellId: options.cellId ?? process.env.HYDRA_CELL_ID ?? DEFAULTS.cellId,
  };

  function requestBody(query, parameters, options = {}) {
    const pageSize = options.pageSize ?? 1000;
    if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 4_096) {
      throw new Error("HydraDB pageSize must be an integer between 1 and 4096");
    }
    if (options.timeoutMs !== undefined
      && (!Number.isInteger(options.timeoutMs) || options.timeoutMs < 1)) {
      throw new Error("HydraDB timeoutMs must be a positive integer");
    }
    return {
      cell_id: config.cellId,
      query,
      parameters,
      page_size: pageSize,
      consistency: "strong",
      ...(options.queryId ? { query_id: options.queryId } : {}),
      ...(options.bookmark ? { bookmark: options.bookmark } : {}),
      ...(options.timeoutMs ? { timeout_ms: options.timeoutMs } : {}),
    };
  }

  async function query(queryText, parameters = {}, options = {}) {
    const response = await fetch(`${config.httpBase}/v1/graphs/${config.graphId}/query`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${config.token}`,
        "Content-Type": "application/json",
        "X-Graph-Namespace": config.namespace,
      },
      body: JSON.stringify(requestBody(queryText, parameters, options)),
    });

    const body = await response.json().catch(() => null);
    if (!response.ok) {
      throw new Error(`HydraDB query failed (${response.status}): ${JSON.stringify(body)}`);
    }

    return body;
  }

  async function assertReady() {
    const response = await fetch(`${config.adminBase}/readyz`);
    if (!response.ok) {
      throw new Error(`HydraDB is not ready at ${config.adminBase}`);
    }
  }

  return Object.freeze({
    config: Object.freeze({ ...config }),
    query,
    assertReady,
    requestBody,
  });
}

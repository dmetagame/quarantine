const DEFAULTS = Object.freeze({
  httpBase: "http://127.0.0.1:18443",
  adminBase: "http://127.0.0.1:19091",
  token: "local-development-token-32-bytes",
  namespace: "default",
  graphId: "default",
  cellId: "cell-0",
  timeoutMs: 5_000,
});

function abortError(timeoutMs, description) {
  const error = new Error(`${description} timed out after ${timeoutMs}ms`);
  error.name = "TimeoutError";
  return error;
}

async function fetchWithTimeout(url, options, timeoutMs, description) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error("HydraDB timeoutMs must be a positive integer");
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (error) {
    if (error?.name === "AbortError" || controller.signal.aborted) {
      throw abortError(timeoutMs, description);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

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
  const timeoutMs = options.timeoutMs ?? DEFAULTS.timeoutMs;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) {
    throw new Error("HydraDB timeoutMs must be an integer between 1 and 30000");
  }
  const config = {
    httpBase: options.httpBase ?? process.env.HYDRA_HTTP_URL ?? DEFAULTS.httpBase,
    adminBase: options.adminBase ?? process.env.HYDRA_ADMIN_URL ?? DEFAULTS.adminBase,
    token: options.token ?? process.env.HYDRA_AUTH_TOKEN ?? DEFAULTS.token,
    namespace: options.namespace ?? process.env.HYDRA_NAMESPACE ?? DEFAULTS.namespace,
    graphId: options.graphId ?? process.env.HYDRA_GRAPH_ID ?? DEFAULTS.graphId,
    cellId: options.cellId ?? process.env.HYDRA_CELL_ID ?? DEFAULTS.cellId,
    timeoutMs,
  };

  function requestBody(query, parameters, options = {}) {
    const pageSize = options.pageSize ?? 1000;
    const queryTimeoutMs = options.timeoutMs ?? config.timeoutMs;
    if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 4_096) {
      throw new Error("HydraDB pageSize must be an integer between 1 and 4096");
    }
    if (!Number.isInteger(queryTimeoutMs) || queryTimeoutMs < 1 || queryTimeoutMs > 30_000) {
      throw new Error("HydraDB timeoutMs must be an integer between 1 and 30000");
    }
    return {
      cell_id: config.cellId,
      query,
      parameters,
      page_size: pageSize,
      consistency: "strong",
      timeout_ms: queryTimeoutMs,
      ...(options.queryId ? { query_id: options.queryId } : {}),
      ...(options.bookmark ? { bookmark: options.bookmark } : {}),
    };
  }

  async function query(queryText, parameters = {}, options = {}) {
    const request = requestBody(queryText, parameters, options);
    const response = await fetchWithTimeout(
      `${config.httpBase}/v1/graphs/${config.graphId}/query`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${config.token}`,
          "Content-Type": "application/json",
          "X-Graph-Namespace": config.namespace,
        },
        body: JSON.stringify(request),
      },
      request.timeout_ms,
      "HydraDB query",
    );

    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      throw new Error(`HydraDB query failed (${response.status}): ${JSON.stringify(payload)}`);
    }

    return payload;
  }

  async function assertReady() {
    const response = await fetchWithTimeout(
      `${config.adminBase}/readyz`,
      { method: "GET" },
      config.timeoutMs,
      "HydraDB readiness",
    );
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

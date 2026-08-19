#!/usr/bin/env node

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  DEMO_SCENARIOS,
  createDemoOrchestrator,
} from "../src/demo-orchestrator.mjs";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = resolve(SCRIPT_DIR, "..");
const MAX_BODY_BYTES = 256;
const SECURITY_HEADERS = Object.freeze({
  "Cache-Control": "no-store",
  "Content-Security-Policy": "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
});

const STATIC_FILES = Object.freeze({
  "/": Object.freeze({ path: resolve(ROOT_DIR, "index.html"), type: "text/html; charset=utf-8" }),
  "/index.html": Object.freeze({ path: resolve(ROOT_DIR, "index.html"), type: "text/html; charset=utf-8" }),
  "/public/app.js": Object.freeze({ path: resolve(ROOT_DIR, "public/app.js"), type: "text/javascript; charset=utf-8" }),
  "/public/styles.css": Object.freeze({ path: resolve(ROOT_DIR, "public/styles.css"), type: "text/css; charset=utf-8" }),
});

function responseJson(response, statusCode, body) {
  const payload = Buffer.from(`${JSON.stringify(body)}\n`, "utf8");
  response.writeHead(statusCode, {
    ...SECURITY_HEADERS,
    "Content-Length": payload.length,
    "Content-Type": "application/json; charset=utf-8",
  });
  response.end(payload);
}

function responseText(response, statusCode, text) {
  const payload = Buffer.from(text, "utf8");
  response.writeHead(statusCode, {
    ...SECURITY_HEADERS,
    "Content-Length": payload.length,
    "Content-Type": "text/plain; charset=utf-8",
  });
  response.end(payload);
}

function invalidRequest(response, detail, statusCode = 400) {
  responseJson(response, statusCode, {
    status: "BLOCK",
    reason_code: "BLOCK_INVALID_INPUT",
    detail,
  });
}

async function readBoundedJson(request) {
  const contentType = request.headers["content-type"] ?? "";
  const mediaType = contentType.split(";", 1)[0].trim().toLowerCase();
  if (mediaType !== "application/json") {
    const error = new Error("CONTENT_TYPE_MUST_BE_APPLICATION_JSON");
    error.statusCode = 415;
    throw error;
  }
  const declaredLength = Number(request.headers["content-length"] ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
    const error = new Error("REQUEST_BODY_TOO_LARGE");
    error.statusCode = 413;
    throw error;
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) {
      const error = new Error("REQUEST_BODY_TOO_LARGE");
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  if (total === 0) {
    const error = new Error("REQUEST_BODY_REQUIRED");
    error.statusCode = 400;
    throw error;
  }
  let parsed;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    const error = new Error("REQUEST_BODY_MALFORMED");
    error.statusCode = 400;
    throw error;
  }
  return validateDemoRequestBody(parsed);
}

export function validateDemoRequestBody(parsed) {
  if (parsed === null
    || typeof parsed !== "object"
    || Array.isArray(parsed)
    || Object.getPrototypeOf(parsed) !== Object.prototype) {
    const error = new Error("REQUEST_BODY_MUST_BE_AN_OBJECT");
    error.statusCode = 400;
    throw error;
  }
  const keys = Object.keys(parsed);
  if (keys.length !== 1 || keys[0] !== "scenario") {
    const error = new Error("ONLY_SCENARIO_MAY_BE_SUBMITTED");
    error.statusCode = 400;
    throw error;
  }
  if (!DEMO_SCENARIOS.includes(parsed.scenario)) {
    const error = new Error("UNKNOWN_DEMO_SCENARIO");
    error.statusCode = 400;
    throw error;
  }
  return Object.freeze({ scenario: parsed.scenario });
}

export function createDemoServer(options = {}) {
  const orchestrator = options.orchestrator ?? createDemoOrchestrator(options.orchestratorOptions);
  return createServer(async (request, response) => {
    const method = request.method ?? "GET";
    let pathname;
    try {
      pathname = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    } catch {
      invalidRequest(response, "INVALID_REQUEST_TARGET");
      return;
    }

    if (method === "GET" && pathname === "/api/health") {
      try {
        const ready = await orchestrator.assertReady();
        responseJson(response, 200, { status: "PASS", hydradb: ready });
      } catch {
        responseJson(response, 503, {
          status: "BLOCK",
          reason_code: "BLOCK_SYSTEM_ERROR",
          detail: "HYDRADB_UNAVAILABLE",
        });
      }
      return;
    }

    if (method === "POST" && pathname === "/api/demo/run") {
      let body;
      try {
        body = await readBoundedJson(request);
      } catch (error) {
        invalidRequest(response, error.message, error.statusCode ?? 400);
        return;
      }
      try {
        const result = await orchestrator.run(body.scenario);
        responseJson(response, 200, result);
      } catch {
        responseJson(response, 503, {
          status: "BLOCK",
          reason_code: "BLOCK_SYSTEM_ERROR",
          detail: "DEMO_ORCHESTRATION_FAILED",
        });
      }
      return;
    }

    if ((method === "GET" || method === "HEAD") && STATIC_FILES[pathname]) {
      try {
        const file = await readFile(STATIC_FILES[pathname].path);
        response.writeHead(200, {
          ...SECURITY_HEADERS,
          "Content-Length": file.length,
          "Content-Type": STATIC_FILES[pathname].type,
        });
        response.end(method === "HEAD" ? undefined : file);
      } catch {
        responseText(response, 500, "Demo asset unavailable\n");
      }
      return;
    }

    if (method === "GET" && pathname === "/favicon.ico") {
      response.writeHead(204, SECURITY_HEADERS);
      response.end();
      return;
    }

    responseText(response, 404, "Not found\n");
  });
}

function parsePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("QUARANTINE_DEMO_PORT must be an integer between 1 and 65535");
  }
  return port;
}

async function main() {
  const host = process.env.QUARANTINE_DEMO_HOST ?? "127.0.0.1";
  const port = parsePort(process.env.QUARANTINE_DEMO_PORT ?? "4173");
  const orchestrator = createDemoOrchestrator();
  await orchestrator.assertReady();
  const server = createDemoServer({ orchestrator });
  await new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(port, host, resolvePromise);
  });
  process.stdout.write(`QUARANTINE demo listening at http://${host}:${port}\n`);

  const close = () => {
    server.close(() => process.exit(0));
  };
  process.once("SIGINT", close);
  process.once("SIGTERM", close);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  });
}

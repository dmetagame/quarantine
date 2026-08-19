# Hosted Demo Deployment

This is a small, faithful deployment for the Quarantine hackathon demo. It
runs one long-lived Node process and one persistent HydraDB 0.1.1 container on
the same Docker host. The action adapter remains a dry run; this is not a
production side-effect service.

## Why One Host

The demo server keeps the action gateway, replay ledger, and writer locks in
one process. HydraDB also needs persistent `/data`. Keeping both services on a
private Docker network preserves the verified boundary and avoids a remote
database timeout. Do not deploy the app as a stateless/serverless function
without redesigning those semantics.

## Prepare

On the target host, install Docker Engine and Compose v2, clone the repository,
and run:

```bash
npm install
bash scripts/bootstrap-deployment.sh
```

The bootstrap command generates fresh 32-byte hex secrets in three mode-600
files, creates a fresh persistent HydraDB directory, and writes a mode-600
`.env.deploy` containing paths only. It never uses the proof fixture keys.
Review the generated file without copying secret contents into chat or source
control.

## Start

```bash
docker compose --env-file .env.deploy -f compose.yaml up -d --build
docker compose --env-file .env.deploy -f compose.yaml ps
curl --fail http://127.0.0.1:4173/api/health
```

The app is bound to loopback by default. Put a TLS reverse proxy (Caddy,
nginx, or an approved tunnel) in front of it and expose only the proxy. Do not
publish HydraDB's HTTP, admin, or Bolt ports to the public network.

## Smoke Test

Run both real scenarios through the deployed server:

```bash
curl --fail -sS -X POST http://127.0.0.1:4173/api/demo/run \
  -H 'content-type: application/json' \
  --data '{"scenario":"valid"}'

curl --fail -sS -X POST http://127.0.0.1:4173/api/demo/run \
  -H 'content-type: application/json' \
  --data '{"scenario":"tampered"}'
```

The first response must report `gateway.status: "ALLOW"`,
`action.executed: true`, and `adapter_calls: 1`. The second must report
`BLOCK_UNRESOLVED_ANCESTRY`, `action.executed: false`, and `adapter_calls: 0`.
Run the browser check at the public HTTPS URL after the reverse proxy is
configured.

## Operations

```bash
docker compose --env-file .env.deploy -f compose.yaml logs -f demo hydradb
docker compose --env-file .env.deploy -f compose.yaml restart demo
docker compose --env-file .env.deploy -f compose.yaml down
```

Keep `.env.deploy`, `.secrets/`, and `.hydradb-hosted-data/` private and backed
up as one unit according to the host policy. Keep the signing and connector
keys stable for the lifetime of the graph volume: existing records are
cryptographically bound to those keys. The current replay ledger is
process-local and resets on an app restart; because the adapter is a dry run,
this is an explicit demo limitation rather than a production guarantee.

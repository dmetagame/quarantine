#!/usr/bin/env bash
set -euo pipefail
umask 077

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
data_dir="${QUARANTINE_HYDRADB_DATA:-$project_root/.hydradb-data}"
container_name="${QUARANTINE_HYDRADB_CONTAINER:-quarantine-hydradb}"
image="${HYDRA_IMAGE:-ghcr.io/hydra-db/hydradb:0.1.1}"
auth_token="${HYDRA_AUTH_TOKEN:-local-development-token-32-bytes}"
http_port="${HYDRA_HTTP_PORT:-18443}"
bolt_port="${HYDRA_BOLT_PORT:-17687}"
admin_port="${HYDRA_ADMIN_PORT:-19091}"

if docker inspect "$container_name" >/dev/null 2>&1; then
  if [ "$(docker inspect --format '{{.State.Running}}' "$container_name")" = "true" ]; then
    existing_image="$(docker inspect --format '{{.Config.Image}}' "$container_name")"
    if [ "$existing_image" != "$image" ]; then
      printf 'Container %s is running %s, expected %s. Stop it explicitly before retrying.\n' \
        "$container_name" "$existing_image" "$image" >&2
      exit 1
    fi

    printf 'HydraDB is already running: %s\n' "$container_name"
    printf 'Image: %s\n' "$image"
    printf 'HTTP: http://127.0.0.1:%s\n' "$http_port"
    exit 0
  fi

  printf 'Container %s exists but is not running; remove it explicitly before retrying.\n' "$container_name" >&2
  exit 1
fi

mkdir -p "$data_dir/store" "$data_dir/cache"
printf '%s\n' "$auth_token" > "$data_dir/auth-token"
chmod 600 "$data_dir/auth-token"

docker run --rm --detach \
  --name "$container_name" \
  --user "$(id -u):$(id -g)" \
  -p "127.0.0.1:$bolt_port:7687" \
  -p "127.0.0.1:$http_port:8443" \
  -p "127.0.0.1:$admin_port:9090" \
  -v "$data_dir:/data" \
  -e CLOUD_PROVIDER=local \
  -e LOCAL_PATH=/data/store \
  -e GRAPH_NAMESPACE=default \
  -e GRAPH_ID=default \
  -e GRAPH_CELL_ID=cell-0 \
  -e GRAPH_CELLS=cell-0 \
  -e GRAPH_NODE_ID=node-0 \
  -e GRAPH_BOLT_NODE_ADDRESSES=node-0=127.0.0.1:7687 \
  -e GRAPH_ADVERTISED_BOLT_ADDR=127.0.0.1:7687 \
  -e GRAPH_DATA_CACHE_DIR=/data/cache \
  -e GRAPH_AUTH_TOKEN_FILE=/data/auth-token \
  -e GRAPH_ALLOW_PLAINTEXT=true \
  -e RUST_MIN_STACK=33554432 \
  "$image" >/dev/null

for attempt in $(seq 1 90); do
  if curl --fail --silent "http://127.0.0.1:$admin_port/readyz" >/dev/null; then
    printf 'HydraDB ready after %s attempt(s).\n' "$attempt"
    printf 'Image: %s\n' "$image"
    printf 'HTTP: http://127.0.0.1:%s\n' "$http_port"
    exit 0
  fi
  sleep 1
done

printf 'HydraDB did not become ready within 90 seconds.\n' >&2
docker logs --tail 80 "$container_name" >&2
exit 1

#!/usr/bin/env bash
set -euo pipefail
umask 077

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="${1:-$project_root/.env.deploy}"
case "$env_file" in
  /*) ;;
  *) env_file="$project_root/$env_file" ;;
esac

if [ -e "$env_file" ]; then
  printf 'Refusing to overwrite existing deployment environment: %s\n' "$env_file" >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  printf 'Node.js is required to generate deployment secrets.\n' >&2
  exit 1
fi

uid="${HYDRA_UID:-$(id -u)}"
gid="${HYDRA_GID:-$(id -g)}"
hydra_data="${HYDRA_DATA_DIR:-./.hydradb-hosted-data}"
token_file="${HYDRA_AUTH_TOKEN_FILE:-./.secrets/hydra-auth-token}"
signing_file="${QUARANTINE_PROVENANCE_SIGNING_KEY_FILE:-./.secrets/provenance-signing-key}"
connector_file="${QUARANTINE_CONNECTOR_ATTESTATION_KEY_FILE:-./.secrets/connector-attestation-key}"

absolute_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$project_root" "$1" ;;
  esac
}

hydra_data_path="$(absolute_path "$hydra_data")"
token_file_path="$(absolute_path "$token_file")"
signing_file_path="$(absolute_path "$signing_file")"
connector_file_path="$(absolute_path "$connector_file")"
secret_dir="$(dirname "$token_file_path")"

if [ "$token_file_path" = "$signing_file_path" ] \
  || [ "$token_file_path" = "$connector_file_path" ] \
  || [ "$signing_file_path" = "$connector_file_path" ] \
  || [ "$env_file" = "$token_file_path" ] \
  || [ "$env_file" = "$signing_file_path" ] \
  || [ "$env_file" = "$connector_file_path" ]; then
  printf 'Deployment environment and secret paths must be distinct.\n' >&2
  exit 1
fi

mkdir -p "$hydra_data_path/store" "$hydra_data_path/cache" \
  "$secret_dir" "$(dirname "$signing_file_path")" "$(dirname "$connector_file_path")"

for secret_path in "$token_file_path" "$signing_file_path" "$connector_file_path"; do
  if [ -e "$secret_path" ]; then
    printf 'Refusing to overwrite existing deployment secret: %s\n' "$secret_path" >&2
    exit 1
  fi
done

random_hex() {
  node --input-type=module -e \
    'import { randomBytes } from "node:crypto"; process.stdout.write(randomBytes(32).toString("hex"));'
}

hydra_token="$(random_hex)"
signing_key="$(random_hex)"
connector_key="$(random_hex)"
printf '%s\n' "$hydra_token" > "$token_file_path"
printf '%s\n' "$signing_key" > "$signing_file_path"
printf '%s\n' "$connector_key" > "$connector_file_path"
chmod 600 "$token_file_path"
chmod 600 "$signing_file_path" "$connector_file_path"

cat > "$env_file" <<EOF
HYDRA_UID=$uid
HYDRA_GID=$gid
HYDRA_DATA_DIR=$hydra_data
HYDRA_AUTH_TOKEN_FILE=$token_file
QUARANTINE_PROVENANCE_SIGNING_KEY_FILE=$signing_file
QUARANTINE_CONNECTOR_ATTESTATION_KEY_FILE=$connector_file
HYDRA_NAMESPACE=default
HYDRA_GRAPH_ID=default
HYDRA_CELL_ID=cell-0
HYDRA_HTTP_PORT=18443
HYDRA_ADMIN_PORT=19091
QUARANTINE_DEMO_BIND=127.0.0.1
QUARANTINE_DEMO_PORT=4173
HYDRA_IMAGE=ghcr.io/hydra-db/hydradb:0.1.1@sha256:db78309a233be54662db29744047e985a39b51c45a270d1a1f47c31a62cdb709
EOF
chmod 600 "$env_file"

printf 'Created %s and three mode-600 secret files under %s.\n' "$env_file" "$secret_dir"
printf 'Start the hosted demo with:\n'
printf '  docker compose --env-file %s -f compose.yaml up -d --build\n' "${env_file#$project_root/}"
printf 'Do not commit either generated file or expose HydraDB ports publicly.\n'

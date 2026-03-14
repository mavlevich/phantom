#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
SERVER_DIR="$ROOT_DIR/apps/server"
server_pid=""

cleanup() {
  if [ -n "$server_pid" ] && kill -0 "$server_pid" >/dev/null 2>&1; then
    kill -INT "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" || true
  fi
}

trap 'cleanup; exit 0' INT TERM

cd "$ROOT_DIR"

./scripts/ensure-env.sh

docker compose up -d
echo "Waiting for services to be ready..."
sleep 2
docker compose ps

./scripts/migrate.sh up

(
  cd "$SERVER_DIR"
  set -a
  . ./.env
  set +a
  go run ./cmd/api
) &
server_pid=$!

wait "$server_pid"

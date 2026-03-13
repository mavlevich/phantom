#!/bin/sh

set -eu

. "$(dirname "$0")/common.sh"

if should_skip_hooks; then
  hook_log "Skipping pre-push hook because PHANTOM_SKIP_HOOKS=1"
  exit 0
fi

ensure_tool go

hook_log "pre-push: running go vet"
(
  cd "$SERVER_DIR"
  go vet ./...
)

hook_log "pre-push: running go test with coverage"
(
  cd "$SERVER_DIR"
  go test ./... -race -timeout 60s -coverprofile=coverage.out -covermode=atomic
)

hook_log "pre-push: checking coverage threshold"
sh "$ROOT_DIR/scripts/check-coverage.sh"

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

hook_log "pre-push: running go test"
(
  cd "$SERVER_DIR"
  go test ./... -race -timeout 60s
)

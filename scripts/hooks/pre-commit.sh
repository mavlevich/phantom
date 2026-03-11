#!/bin/sh

set -eu

. "$(dirname "$0")/common.sh"

if should_skip_hooks; then
  hook_log "Skipping pre-commit hook because PHANTOM_SKIP_HOOKS=1"
  exit 0
fi

if ! has_server_changes; then
  hook_log "pre-commit: no staged changes under apps/server, skipping"
  exit 0
fi

ensure_tool gofmt
ensure_tool goimports
ensure_tool golangci-lint

GO_FILES=$(staged_go_files)

if [ -n "$GO_FILES" ]; then
  hook_log "pre-commit: formatting staged Go files"
  printf '%s\n' "$GO_FILES" | while IFS= read -r file; do
    [ -n "$file" ] || continue
    gofmt -w "$ROOT_DIR/$file"
    goimports -w "$ROOT_DIR/$file"
    restage_file "$file"
  done
fi

hook_log "pre-commit: running golangci-lint"
(
  cd "$SERVER_DIR"
  golangci-lint run ./...
)

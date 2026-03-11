#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
SERVER_DIR="$ROOT_DIR/apps/server"

hook_log() {
  printf '%s\n' "$1"
}

ensure_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    hook_log "Missing required tool: $1"
    hook_log "Run 'make setup' from the repo root and try again."
    exit 1
  fi
}

should_skip_hooks() {
  [ "${PHANTOM_SKIP_HOOKS:-}" = "1" ]
}

staged_files() {
  git -C "$ROOT_DIR" diff --cached --name-only --diff-filter=ACMR
}

has_server_changes() {
  staged_files | grep -Eq '^apps/server/'
}

staged_go_files() {
  staged_files | grep -E '^apps/server/.*\.go$' || true
}

restage_file() {
  git -C "$ROOT_DIR" add "$1"
}

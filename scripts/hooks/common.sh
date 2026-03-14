#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
SERVER_DIR="$ROOT_DIR/apps/server"

go_bin_dir() {
  if command -v go >/dev/null 2>&1; then
    gobin=$(go env GOBIN 2>/dev/null || true)
    if [ -n "$gobin" ]; then
      printf '%s\n' "$gobin"
      return
    fi

    gopath=$(go env GOPATH 2>/dev/null || true)
    if [ -n "$gopath" ]; then
      printf '%s/bin\n' "$gopath"
      return
    fi
  fi
}

GO_BIN_DIR=$(go_bin_dir)
if [ -n "${GO_BIN_DIR:-}" ] && [ -d "$GO_BIN_DIR" ]; then
  PATH="$GO_BIN_DIR:$PATH"
  export PATH
fi

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

#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
SERVER_DIR="$ROOT_DIR/apps/server"
ENV_FILE="$SERVER_DIR/.env"
EXAMPLE_FILE="$SERVER_DIR/.env.example"
PLACEHOLDER_SECRET="replace-with-random-32-char-secret"

if [ ! -f "$ENV_FILE" ]; then
  cp "$EXAMPLE_FILE" "$ENV_FILE"
  echo "Created $ENV_FILE from .env.example"
fi

if grep -q "^JWT_SECRET=$PLACEHOLDER_SECRET$" "$ENV_FILE"; then
  if ! command -v openssl >/dev/null 2>&1; then
    echo "Missing required tool: openssl"
    echo "Install openssl or update $ENV_FILE manually."
    exit 1
  fi

  secret=$(openssl rand -hex 32)
  tmp_file=$(mktemp "${TMPDIR:-/tmp}/phantom-env.XXXXXX")

  awk -v secret="$secret" -v placeholder="$PLACEHOLDER_SECRET" '
    $0 == "JWT_SECRET=" placeholder {
      print "JWT_SECRET=" secret
      next
    }
    { print }
  ' "$ENV_FILE" > "$tmp_file"

  mv "$tmp_file" "$ENV_FILE"
  echo "Generated JWT secret in $ENV_FILE"
fi

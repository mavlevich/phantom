#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
MIGRATIONS_DIR="$ROOT_DIR/apps/server/migrations"
POSTGRES_SERVICE="postgres"

usage() {
  echo "Usage: $0 up|down"
  exit 1
}

require_running_postgres() {
  if ! (cd "$ROOT_DIR" && docker compose exec -T "$POSTGRES_SERVICE" true >/dev/null 2>&1); then
    echo "PostgreSQL container is not running."
    echo "Run 'make dev-up' first."
    exit 1
  fi
}

psql_query() {
  query=$1
  printf '%s\n' "$query" | psql_exec -t -A
}

psql_exec() {
  (cd "$ROOT_DIR" && docker compose exec -T "$POSTGRES_SERVICE" psql -v ON_ERROR_STOP=1 -U phantom -d phantom "$@")
}

wait_for_postgres() {
  attempts=30

  while [ "$attempts" -gt 0 ]; do
    if (cd "$ROOT_DIR" && docker compose exec -T "$POSTGRES_SERVICE" pg_isready -U phantom >/dev/null 2>&1); then
      return 0
    fi

    attempts=$((attempts - 1))
    sleep 1
  done

  echo "PostgreSQL is running but not ready to accept connections."
  exit 1
}

ensure_schema_migrations_table() {
  psql_query "CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW());" >/dev/null
}

table_exists() {
  table_name=$1
  psql_query "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '$(sql_escape_literal "$table_name")');"
}

mark_applied_if_present() {
  version=$1
  shift

  already_marked=$(psql_query "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '$(sql_escape_literal "$version")');")
  present="t"

  for table_name in "$@"; do
    if [ "$(table_exists "$table_name")" != "t" ]; then
      present="f"
      break
    fi
  done

  if [ "$present" = "t" ] && [ "$already_marked" != "t" ]; then
    psql_query "INSERT INTO schema_migrations (version) VALUES ('$(sql_escape_literal "$version")') ON CONFLICT (version) DO NOTHING;" >/dev/null
    echo "Baselined existing migration $version"
  fi
}

baseline_existing_schema() {
  mark_applied_if_present "001_init" "users" "messages"
  mark_applied_if_present "002_invites" "invites"
}

apply_up_migration() {
  file=$1
  version=$(basename "$file" .up.sql)

  already_applied=$(psql_query "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '$(sql_escape_literal "$version")');")
  if [ "$already_applied" = "t" ]; then
    return 0
  fi

  echo "Applying $version"
  {
    printf 'BEGIN;\n'
    cat "$file"
    printf "\nINSERT INTO schema_migrations (version) VALUES ('%s');\n" "$(sql_escape_literal "$version")"
    printf 'COMMIT;\n'
  } | psql_exec >/dev/null
}

apply_down_migration() {
  version=$1
  file="$MIGRATIONS_DIR/$version.down.sql"

  if [ ! -f "$file" ]; then
    echo "Missing down migration for $version"
    exit 1
  fi

  echo "Rolling back $version"
  {
    printf 'BEGIN;\n'
    cat "$file"
    printf "\nDELETE FROM schema_migrations WHERE version = '%s';\n" "$(sql_escape_literal "$version")"
    printf 'COMMIT;\n'
  } | psql_exec >/dev/null
}

migrate_up() {
  ensure_schema_migrations_table
  baseline_existing_schema

  for file in "$MIGRATIONS_DIR"/*.up.sql; do
    apply_up_migration "$file"
  done

  echo "Migrations are up to date."
}

migrate_down() {
  ensure_schema_migrations_table
  baseline_existing_schema

  last_version=$(psql_query "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1;")
  if [ -z "$last_version" ]; then
    echo "No applied migrations to roll back."
    exit 0
  fi

  apply_down_migration "$last_version"
}

sql_escape_literal() {
  printf '%s' "$1" | sed "s/'/''/g"
}

command=${1:-}
[ -n "$command" ] || usage

require_running_postgres

wait_for_postgres

case "$command" in
  up)
    migrate_up
    ;;
  down)
    migrate_down
    ;;
  *)
    usage
    ;;
esac

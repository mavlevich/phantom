#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
SERVER_DIR="$ROOT_DIR/apps/server"
COVERAGE_THRESHOLD="${COVERAGE_THRESHOLD:-70}"

cd "$SERVER_DIR"

awk 'NR == 1 || $1 !~ /^github.com\/mavlevich\/phantom\/server\/cmd\/api\//' coverage.out > coverage.filtered.out

if [ "$(wc -l < coverage.filtered.out)" -le 1 ]; then
  echo "No non-bootstrap coverage data found"
  exit 1
fi

COVERAGE=$(go tool cover -func=coverage.filtered.out | awk '/total:/ {gsub("%", "", $3); print $3}')
echo "Coverage: ${COVERAGE}%"

if ! awk -v coverage="$COVERAGE" -v threshold="$COVERAGE_THRESHOLD" 'BEGIN { exit !(coverage < threshold) }'; then
  exit 0
fi

echo "Coverage ${COVERAGE}% is below threshold of ${COVERAGE_THRESHOLD}%"
exit 1

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENG_DIR="$ROOT/target/integration-engagements"
ENGAGEMENT="local-target"
TARGET_URL="http://localhost:18080"

rm -rf "$ENG_DIR"
mkdir -p "$ENG_DIR"

cd "$ROOT/engine-rust"

MG_ENGAGEMENTS_DIR="$ENG_DIR" cargo run -q -p engagement --bin mg-engagement -- \
  init "$ENGAGEMENT" --target localhost --platform local

cat > "$ENG_DIR/$ENGAGEMENT/recon/summary.json" <<'JSON'
{
  "hosts": [
    {
      "hostname": "localhost",
      "http_accessible": true,
      "fingerprint": null,
      "open_ports": [18080]
    }
  ]
}
JSON

cargo run -q -p mg-crawl -- "$ENGAGEMENT" "$TARGET_URL" \
  --engagements-dir "$ENG_DIR" --depth 1 --rate-ms 0 --ignore-robots --force

CRAWL_DIR="$ENG_DIR/$ENGAGEMENT/crawl/localhost"
test -f "$CRAWL_DIR/endpoints.json"
test -f "$CRAWL_DIR/internal-refs.json"
test -f "$CRAWL_DIR/vulnerable-libraries.json"
test -f "$CRAWL_DIR/graphql-candidates.json"
test -f "$CRAWL_DIR/graphql-schema.json"
grep -q '"graphql": true' "$CRAWL_DIR/endpoints.json"
grep -q 'api.internal' "$CRAWL_DIR/internal-refs.json"
grep -q 'CVE-2020-11022' "$CRAWL_DIR/vulnerable-libraries.json"

cargo run -q -p mg-probe -- "$ENGAGEMENT" \
  --engagements-dir "$ENG_DIR" --active --force --rate-ms 0 --timeout-ms 2000

REPORT_JSON="$ENG_DIR/$ENGAGEMENT/recon/probe-report.json"
grep -q 'active-open-redirect' "$REPORT_JSON"
grep -q 'active-sqli-error' "$REPORT_JSON"
grep -q 'active-reflection' "$REPORT_JSON"

FINDING_ID="$(find "$ENG_DIR/$ENGAGEMENT/findings" -name '*.md' ! -name '*-report.md' -print -quit | sed -E 's#.*/([0-9]{8}-probe-[0-9]{3}).*#\1#')"
test -n "$FINDING_ID"
cargo run -q -p mg-report -- generate "$ENGAGEMENT" "$FINDING_ID" \
  --engagements-dir "$ENG_DIR" --offline --force
find "$ENG_DIR/$ENGAGEMENT/findings" -name '*-report.md' -print -quit | grep -q report.md

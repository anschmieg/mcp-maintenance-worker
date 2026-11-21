#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
go test -mod=readonly ./...
(cd worker && npm ci --ignore-scripts)
if [[ "${VERIFY_TAILNET_BUILD:-0}" == 1 ]]; then
  (cd experiments/tailnet && npm ci --ignore-scripts && bash build.sh)
  node worker/node_modules/wrangler/bin/wrangler.js deploy --dry-run --config experiments/tailnet/wrangler.jsonc
fi
cd worker
sh build.sh
scratch="$(mktemp -d)"
config="$(mktemp "$PWD/.wrangler-ci.XXXXXX.json")"
cleanup() {
  if [[ -n "${worker_pid:-}" ]]; then kill "$worker_pid" 2>/dev/null || true; fi
  rm -f "$config"
}
trap cleanup EXIT
export MCP_BEARER_TOKEN="$(openssl rand -hex 32)"
export TEST_MCP_URL=http://127.0.0.1:8795/mcp
node --input-type=module - "$config" <<'JS'
import fs from 'node:fs';
const config = JSON.parse(fs.readFileSync('wrangler.jsonc','utf8'));
delete config.ai;
fs.writeFileSync(process.argv[2],JSON.stringify(config));
JS
node node_modules/wrangler/bin/wrangler.js dev --config "$config" --port 8795 --persist-to "$scratch/state" --var "MCP_BEARER_TOKEN:$MCP_BEARER_TOKEN" > "$scratch/worker.log" 2>&1 &
worker_pid=$!
for _ in {1..30}; do
  if curl -s -o /dev/null "$TEST_MCP_URL"; then break; fi
  if ! kill -0 "$worker_pid" 2>/dev/null; then cat "$scratch/worker.log"; exit 1; fi
  sleep 1
done
node test.mjs
PROBE_SECONDS=5 node test-timing.mjs

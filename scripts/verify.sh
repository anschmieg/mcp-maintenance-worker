#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
go test -mod=readonly ./...
(cd worker && npm ci --ignore-scripts)
(cd experiments/tailnet && npm ci --ignore-scripts)
if [[ "${VERIFY_TAILNET_BUILD:-0}" == 1 ]]; then
  (cd experiments/tailnet && bash build.sh)
  node worker/node_modules/wrangler/bin/wrangler.js deploy --dry-run --config experiments/tailnet/wrangler.jsonc
fi
cd worker
sh build.sh
scratch="$(mktemp -d)"
config="$(mktemp "$PWD/.wrangler-ci.XXXXXX.json")"
cleanup() {
  if [[ -n "${worker_pid:-}" ]]; then kill "$worker_pid" 2>/dev/null || true; fi
  if [[ -n "${fixture_pid:-}" ]]; then kill "$fixture_pid" 2>/dev/null || true; fi
  if [[ -n "${worker_pid:-}" ]]; then wait "$worker_pid" 2>/dev/null || true; fi
  if [[ -n "${fixture_pid:-}" ]]; then wait "$fixture_pid" 2>/dev/null || true; fi
  rm -f "$config"
  rm -rf -- "$scratch"
}
trap cleanup EXIT
export MCP_BEARER_TOKEN="$(openssl rand -hex 32)"
export TEST_MCP_URL=http://127.0.0.1:8795/mcp
export PASSKEY_SETUP_TOKEN="$(openssl rand -hex 32)"
export PASSKEY_ORIGIN=http://localhost:8795
node --input-type=module - "$config" <<'JS'
import fs from 'node:fs';
const config = JSON.parse(fs.readFileSync('wrangler.jsonc','utf8'));
delete config.ai;
config.services = [{binding:'HOST_PROBE', service:'maintenance-enrollment-test-probe', entrypoint:'HostVerifier'}];
fs.writeFileSync(process.argv[2],JSON.stringify(config));
JS
node test-ssh-fixture.mjs "$scratch" > "$scratch/ssh.log" 2>&1 &
fixture_pid=$!
start_worker() {
  node node_modules/wrangler/bin/wrangler.js dev --config "$config" --config wrangler.test-probe.jsonc --port 8795 --persist-to "$scratch/state" --var "MCP_BEARER_TOKEN:$MCP_BEARER_TOKEN" --var "PASSKEY_SETUP_TOKEN:$PASSKEY_SETUP_TOKEN" --var "PASSKEY_ORIGIN:$PASSKEY_ORIGIN" --var PASSKEY_LOCAL_TEST_JOB_TTL_MS:3000 > "$scratch/worker.log" 2>&1 &
  worker_pid=$!
  for _ in {1..30}; do
    if curl --max-time 2 -s -o /dev/null "$TEST_MCP_URL"; then return; fi
    if ! kill -0 "$worker_pid" 2>/dev/null; then break; fi
    sleep 1
  done
  cat "$scratch/worker.log"
  return 1
}

start_worker
node --experimental-strip-types test-assessment.mjs
node --experimental-strip-types test-host-approval.mjs
node test.mjs
PROBE_SECONDS=5 node test-timing.mjs
if ! node test-passkeys.mjs "$scratch/restart-test.json"; then cat "$scratch/worker.log" "$scratch/ssh.log"; exit 1; fi
kill "$worker_pid"
wait "$worker_pid" || true
start_worker
if ! node test-passkeys.mjs "$scratch/restart-test.json" after-restart; then cat "$scratch/worker.log" "$scratch/ssh.log"; exit 1; fi

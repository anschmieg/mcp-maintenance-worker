#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077

config_home="$(printenv XDG_CONFIG_HOME || true)"
if [[ -z "$config_home" ]]; then config_home="$HOME/.config"; fi
config_dir="$(printenv PASTA_CONFIG_DIR || true)"
if [[ -z "$config_dir" ]]; then config_dir="$config_home/pasta"; fi
mkdir -p "$config_dir"
chmod 700 "$config_dir"
secrets_file="$config_dir/worker-secrets.json"

node --input-type=module - "$secrets_file" <<'JS'
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';

const file = process.argv[2];
if (existsSync(file)) {
  chmodSync(file, 0o600);
} else {
  const { PASSKEY_ORIGIN, PASTA_WORKERS_SUBDOMAIN, PASSKEY_SETUP_TOKEN, MCP_BEARER_TOKEN } = process.env;
  const subdomainValid = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(PASTA_WORKERS_SUBDOMAIN ?? '');
  const origin = PASSKEY_ORIGIN || (subdomainValid && 'https://pasta.' + PASTA_WORKERS_SUBDOMAIN + '.workers.dev');
  if (!origin || new URL(origin).origin !== origin || !origin.startsWith('https://')) {
    throw new Error('Set PASTA_WORKERS_SUBDOMAIN or a stable HTTPS PASSKEY_ORIGIN.');
  }
  const seed = {
    PASSKEY_ORIGIN: origin,
    PASSKEY_SETUP_TOKEN: PASSKEY_SETUP_TOKEN ?? randomBytes(32).toString('hex'),
    MCP_BEARER_TOKEN: MCP_BEARER_TOKEN ?? randomBytes(32).toString('hex'),
  };
  if (seed.PASSKEY_SETUP_TOKEN.length < 32 || seed.MCP_BEARER_TOKEN.length < 32 ||
      seed.PASSKEY_SETUP_TOKEN === seed.MCP_BEARER_TOKEN) throw new Error('Use distinct credentials of at least 32 characters.');
  writeFileSync(file, JSON.stringify(seed, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}

const secrets = JSON.parse(readFileSync(file, 'utf8'));
console.log('After deployment, open: ' + new URL('/passkeys/onboard', secrets.PASSKEY_ORIGIN));
console.log('Read PASSKEY_SETUP_TOKEN in the owner-only file: ' + file);
JS

(cd worker && npm ci --ignore-scripts && sh build.sh)
(cd experiments/tailnet && npm ci --ignore-scripts && bash build.sh)
node worker/node_modules/wrangler/bin/wrangler.js deploy --config experiments/tailnet/wrangler.jsonc
# Reuse the saved file even when the operator has credentials set in the shell.
env -u PASSKEY_SETUP_TOKEN -u MCP_BEARER_TOKEN -u PASSKEY_ORIGIN \
  node worker/node_modules/wrangler/bin/wrangler.js deploy --config worker/wrangler.jsonc --secrets-file "$secrets_file"

# Exercise the public Worker's private service binding without running an SSH command.
node --input-type=module - "$secrets_file" <<'JS'
import { readFileSync } from 'node:fs';

const { PASSKEY_ORIGIN, MCP_BEARER_TOKEN } = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const url = new URL('/health/ssh-backend', PASSKEY_ORIGIN);
for (let attempt = 1; attempt <= 5; attempt++) {
  const response = await fetch(url, {
    headers: { Authorization: 'Bearer ' + MCP_BEARER_TOKEN },
    signal: AbortSignal.timeout(20_000),
  });
  if (response.ok) {
    const { state } = await response.json();
    if (state === 'connected') {
      console.log('PaSTA SSH backend is connected to Tailscale.');
      process.exit(0);
    }
    if (state === 'unconfigured' && process.env.PASTA_REQUIRE_CONNECTED !== '1') {
      console.log('PaSTA SSH backend is reachable. Complete Tailscale setup to connect it.');
      process.exit(0);
    }
    if (state !== 'unconfigured') throw new Error('Unexpected backend smoke check response.');
  }
  if (!response.ok && response.status !== 503) throw new Error('Backend smoke check returned HTTP ' + response.status);
  if (attempt < 5) await new Promise(resolve => setTimeout(resolve, 2_000));
}
throw new Error('PaSTA SSH backend is not connected. Check the Tailscale setup page.');
JS

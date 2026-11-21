#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
upstream=https://github.com/littledivy/tailnet-do.git
revision="$(cat upstream.sha)"
[[ "$revision" =~ ^[a-f0-9]{40}$ ]]
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
git -C "$scratch" init -q
git -C "$scratch" fetch --depth=1 "$upstream" "$revision"
git -C "$scratch" -c advice.detachedHead=false checkout -q FETCH_HEAD
git -C "$scratch" submodule update --init --depth 1
(cd "$scratch" && sh scripts/apply-patches.sh && sh scripts/build-wasm.sh)
mkdir -p src
cp "$scratch"/src/{index.js,wasm_exec.js,tailnet.wasm} src/

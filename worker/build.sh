#!/bin/sh
set -eu
cd "$(dirname "$0")"
GOOS=js GOARCH=wasm go build -ldflags='-s -w' -o src/screen.wasm ../cmd/screenwasm
install -m 0644 "$(go env GOROOT)/lib/wasm/wasm_exec.js" src/wasm_exec.js

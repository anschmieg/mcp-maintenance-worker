#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mapfile -t go_modules < <(go list -m -f '{{if and (not .Main) (not .Indirect)}}{{.Path}}@latest{{end}}' all | sed '/^$/d')
go get "${go_modules[@]}"
go mod tidy
cd worker
mapfile -t node_modules < <(node -p 'Object.keys(require("./package.json").dependencies).map(name => name + "@latest").join("\n")')
npm install --package-lock-only --ignore-scripts --save-exact "${node_modules[@]}"
cd ../experiments/tailnet
npm install --package-lock-only --ignore-scripts --save-exact @workeryard/undershell@latest
git ls-remote https://github.com/littledivy/tailnet-do.git HEAD | cut -f1 > upstream.sha

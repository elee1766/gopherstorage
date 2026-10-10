#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest_dir="$repo_root/scripts/vendor-js"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

cp "$manifest_dir/package.json" "$manifest_dir/package-lock.json" "$work_dir/"
npm ci --prefix "$work_dir" --ignore-scripts --no-audit --no-fund

cmp "$repo_root/pkg/ui/static/htmx-2.0.11.min.js" \
  "$work_dir/node_modules/htmx.org/dist/htmx.min.js"
cmp "$repo_root/pkg/ui/static/alpine-csp-3.17.4.min.js" \
  "$work_dir/node_modules/@alpinejs/csp/dist/cdn.min.js"
printf '%s\n' 'Vendored JavaScript matches locked npm tarballs.'

npm audit --prefix "$work_dir" --audit-level=low

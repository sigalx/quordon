#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
manifest="$repo_root/third_party/runtime-modules.txt"

expected_modules=$(awk 'NF && $1 !~ /^#/ { print $1 " " $2 }' "$manifest" | LC_ALL=C sort -u)
actual_modules=$(
    cd "$repo_root"
    go list -deps -f '{{if and .Module (not .Module.Main)}}{{.Module.Path}} {{.Module.Version}}{{end}}' ./cmd/quordon |
        awk 'NF' |
        LC_ALL=C sort -u
)

if [ "$actual_modules" != "$expected_modules" ]; then
    echo "runtime module notices are out of date" >&2
    diff -u <(printf '%s\n' "$expected_modules") <(printf '%s\n' "$actual_modules") || true
    exit 1
fi

while read -r module version license_path extra; do
    if [ -z "$module" ] || [[ "$module" == \#* ]]; then
        continue
    fi
    if [ -z "$version" ] || [ -z "$license_path" ] || [ -n "${extra:-}" ]; then
        echo "invalid runtime module manifest entry for $module" >&2
        exit 1
    fi
    if [ ! -s "$repo_root/third_party/$license_path" ]; then
        echo "missing license notice for $module: third_party/$license_path" >&2
        exit 1
    fi
    if ! grep -Fq "\`$module\` $version" "$repo_root/third_party/NOTICE.md"; then
        echo "third-party notice is missing $module $version" >&2
        exit 1
    fi
done <"$manifest"

for required_notice in \
    "$repo_root/third_party/NOTICE.md" \
    "$repo_root/third_party/licenses/go-standard-library-BSD-3-Clause.txt"; do
    if [ ! -s "$required_notice" ]; then
        echo "missing required notice: $required_notice" >&2
        exit 1
    fi
done

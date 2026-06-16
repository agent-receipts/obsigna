#!/bin/sh
# Canonical reproducible build of any obsigna toolset binary (ADR-0031/0034).
#
# Single source of the determinism flags shared by every CI rebuild — the
# per-module Gate B cross-path byte-identity checks (daemon.yml, mcp-proxy.yml,
# collector.yml, hook.yml) and the release attestation (release-obsigna.yml,
# rebuild-matches-artifact). One script serves every binary across every module
# (ADR-0034 folded the toolset onto one train), so the flags cannot drift per
# module. Keep them in lockstep with the builds in daemon/.goreleaser.yaml: CGO
# off (no host C toolchain bytes), -trimpath (no absolute $GOPATH/working-dir
# paths baked in), -buildvcs=false (no git stamp — the release LICENSE-copy hook
# would otherwise dirty the tree), and a version stamp that derives only from the
# tag.
#
# Usage: reproducible-build.sh <module-dir> <output-path> <cmd> [version]
#   module-dir   Go module directory to build from (resolves its own go.mod)
#   output-path  where to write the binary
#   cmd          main package to build, relative to module-dir (e.g.
#                ./cmd/obsigna-mcp)
#   version      optional; when given, stamps -X main.version=v<version> to match
#                the released build. Omit it for the cross-path determinism check
#                (both builds just need identical flags) and for binaries that
#                carry no version symbol (the obsigna CLI ships with -s -w only).
#
# GOWORK, GOOS, and GOARCH are read from the environment so callers choose
# workspace vs published-module resolution and the target platform.
set -eu

module_dir="$1"
out="$2"
cmd="$3"
version="${4:-}"

ldflags="-s -w"
if [ -n "$version" ]; then
  ldflags="$ldflags -X main.version=v${version}"
fi

cd "$module_dir"
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$out" "$cmd"

#!/usr/bin/env bash
# Install pinned CI tools. Usage: scripts/ci-install-tools.sh <tool>...
#   (staticcheck govulncheck yamllint)
# Versions come from versions.env. Go tools are built from source by `go install` at a pinned
# version (module checksums verified by the Go checksum database); yamllint comes from pipx
# at an exact pinned version. Binary-download tools added later must be sha256-verified.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/versions.env"

install_tool() {
  case "$1" in
    staticcheck) go install "honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}" ;;
    govulncheck) go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ;;
    yamllint) pipx install "yamllint==${YAMLLINT_VERSION}" ;;
    *) echo "ci-install-tools: unknown tool '$1'" >&2; exit 1 ;;
  esac
  echo "ci-install-tools: installed $1"
}

[ "$#" -gt 0 ] || { echo "usage: $0 <tool>..." >&2; exit 2; }
for t in "$@"; do install_tool "$t"; done

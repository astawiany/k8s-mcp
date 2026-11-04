#!/usr/bin/env bash
# Install pinned CI tools. Usage: scripts/ci-install-tools.sh <tool>...
#   (staticcheck govulncheck yamllint kubectl)
# Versions come from versions.env. Go tools are built from source by `go install` at a pinned
# version (module checksums verified by the Go checksum database); yamllint comes from pipx
# at an exact pinned version. Binary downloads are sha256-verified against a pin in versions.env
# before install (kubectl: linux/amd64 only, into $BIN_DIR, default ~/.local/bin).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/versions.env"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# install_kubectl downloads the pinned kubectl and installs it only if its
# sha256 equals KUBECTL_SHA256_LINUX_AMD64.
install_kubectl() {
  [ "$(uname -s)/$(uname -m)" = "Linux/x86_64" ] || { echo "ci-install-tools: kubectl is pinned for linux/amd64 only" >&2; exit 1; }
  local tmp got bin_dir="${BIN_DIR:-$HOME/.local/bin}"
  tmp="$(mktemp -d)"
  curl -fsSL --retry 3 -o "$tmp/kubectl" "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
  got="$(sha256_of "$tmp/kubectl")"
  if [ "$got" != "$KUBECTL_SHA256_LINUX_AMD64" ]; then
    echo "ci-install-tools: kubectl sha256 $got, want $KUBECTL_SHA256_LINUX_AMD64" >&2
    rm -rf "$tmp"
    exit 1
  fi
  mkdir -p "$bin_dir"
  install -m 0755 "$tmp/kubectl" "$bin_dir/kubectl"
  rm -rf "$tmp"
}

install_tool() {
  case "$1" in
    staticcheck) go install "honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}" ;;
    govulncheck) go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ;;
    yamllint) pipx install "yamllint==${YAMLLINT_VERSION}" ;;
    kubectl) install_kubectl ;;
    *) echo "ci-install-tools: unknown tool '$1'" >&2; exit 1 ;;
  esac
  echo "ci-install-tools: installed $1"
}

[ "$#" -gt 0 ] || { echo "usage: $0 <tool>..." >&2; exit 2; }
for t in "$@"; do install_tool "$t"; done

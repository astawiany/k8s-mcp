#!/usr/bin/env bash
# Install pinned CI tools. Usage: scripts/ci-install-tools.sh <tool>...
#   (staticcheck govulncheck yamllint kubectl kind go trivy actionlint)
# Versions come from versions.env. Go tools are built from source by `go install` at a pinned
# version (module checksums verified by the Go checksum database); yamllint comes from pipx
# at an exact pinned version. Binary downloads are sha256-verified against a pin in versions.env
# before install (kubectl, kind, trivy, actionlint: linux/amd64 only, into $BIN_DIR, default ~/.local/bin; go: into
# $GO_ROOT_DIR, default ~/.local/go-<version>, binaries in its go/bin).
set -euo pipefail

BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/versions.env"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# Every temp dir is registered here and removed on any exit, including a checksum mismatch.
TMPS=()
cleanup_tmps() { if [ "${#TMPS[@]}" -gt 0 ]; then rm -rf "${TMPS[@]}"; fi; }
trap cleanup_tmps EXIT
# mk_tmp sets the caller's `tmp` (declared local there) to a fresh registered temp dir.
mk_tmp() { tmp="$(mktemp -d "${TMPDIR:-/tmp}/ci-install.XXXXXX")"; TMPS+=("$tmp"); }

# fetch_verified <url> <expected-sha256> <dest>: download, then keep the file only if its sha256
# equals the pin. A mismatch aborts with a non-zero exit before anything is installed.
fetch_verified() {
  local url="$1" want="$2" dest="$3" got
  curl -fsSL --retry 3 -o "$dest" "$url"
  got="$(sha256_of "$dest")"
  if [ "$got" != "$want" ]; then
    echo "ci-install-tools: sha256 mismatch for $url: got $got, want $want" >&2
    rm -f "$dest"
    exit 1
  fi
}

require_linux_amd64() {
  [ "$(uname -s)/$(uname -m)" = "Linux/x86_64" ] || { echo "ci-install-tools: $1 is pinned for linux/amd64 only" >&2; exit 1; }
}

# install_tarball_bin <tool> <url> <sha256> <path-in-tar>: verified tarball, one binary into $BIN_DIR.
install_tarball_bin() {
  local tool="$1" url="$2" sha="$3" member="$4" tmp
  require_linux_amd64 "$tool"
  mk_tmp
  fetch_verified "$url" "$sha" "$tmp/archive.tgz"
  tar -xzf "$tmp/archive.tgz" -C "$tmp" "$member"
  mkdir -p "$BIN_DIR"
  install -m 0755 "$tmp/$member" "$BIN_DIR/$(basename "$member")"
  rm -rf "$tmp"
}

install_kubectl() {
  local tmp
  require_linux_amd64 kubectl
  mk_tmp
  fetch_verified "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" "$KUBECTL_SHA256_LINUX_AMD64" "$tmp/kubectl"
  mkdir -p "$BIN_DIR"
  install -m 0755 "$tmp/kubectl" "$BIN_DIR/kubectl"
  rm -rf "$tmp"
}

install_kind() {
  local tmp
  require_linux_amd64 kind
  mk_tmp
  fetch_verified "https://github.com/kubernetes-sigs/kind/releases/download/v${KIND_VERSION}/kind-linux-amd64" "$KIND_SHA256_LINUX_AMD64" "$tmp/kind"
  mkdir -p "$BIN_DIR"
  install -m 0755 "$tmp/kind" "$BIN_DIR/kind"
  rm -rf "$tmp"
}

# install_go unpacks the verified official tarball into $GO_ROOT_DIR (default ~/.local/go-<version>);
# put $GO_ROOT_DIR/go/bin on PATH afterwards.
install_go() {
  local tmp root="${GO_ROOT_DIR:-$HOME/.local/go-${GO_VERSION}}"
  require_linux_amd64 go
  mk_tmp
  fetch_verified "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" "$GO_SHA256_LINUX_AMD64" "$tmp/go.tgz"
  rm -rf "$root"
  mkdir -p "$root"
  tar -xzf "$tmp/go.tgz" -C "$root"
  rm -rf "$tmp"
}

install_tool() {
  case "$1" in
    staticcheck) go install "honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}" ;;
    govulncheck) go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ;;
    yamllint) pipx install "yamllint==${YAMLLINT_VERSION}" ;;
    kubectl) install_kubectl ;;
    kind) install_kind ;;
    go) install_go ;;
    trivy) install_tarball_bin trivy "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" "$TRIVY_SHA256_LINUX_AMD64" trivy ;;
    actionlint) install_tarball_bin actionlint "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz" "$ACTIONLINT_SHA256_LINUX_AMD64" actionlint ;;
    *) echo "ci-install-tools: unknown tool '$1'" >&2; exit 1 ;;
  esac
  echo "ci-install-tools: installed $1"
}

[ "$#" -gt 0 ] || { echo "usage: $0 <tool>..." >&2; exit 2; }
for t in "$@"; do install_tool "$t"; done

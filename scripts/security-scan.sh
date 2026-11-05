#!/usr/bin/env bash
# Security gate of the release image: run every scan, print a summary, exit 1 if any failed.
# Adapted from the sibling project fleet-in-a-repo (scripts/security-scan.sh).
# Usage: scripts/security-scan.sh <local image>
#   - image vulnerabilities: fixable HIGH/CRITICAL fail (trivy image --ignore-unfixed)
#   - secrets in the image and in the repo checkout: any finding fails, whatever its severity
#   - misconfiguration of the Dockerfile: HIGH/CRITICAL fail (trivy config)
#   - Go: a vulnerable symbol the code actually calls fails (govulncheck, in the pinned builder image)
# Needs trivy (scripts/ci-install-tools.sh trivy) and docker. Results are a point-in-time gate: the
# vulnerability databases are downloaded at run time.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
img="${1:-}"
[ -n "$img" ] || { echo "usage: $0 <local image>" >&2; exit 2; }
command -v trivy > /dev/null 2>&1 || { echo "security-scan: trivy not found on PATH" >&2; exit 2; }

failed=""
scan() { # <name> <command...>
  local name="$1"; shift
  echo "::group::$name"
  if "$@"; then echo "security-scan: PASS $name"; else echo "security-scan: FAIL $name"; failed="$failed $name"; fi
  echo "::endgroup::"
}

scan image-vulns trivy image --no-progress --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 "$img"
scan image-secrets trivy image --no-progress --scanners secret --exit-code 1 "$img"
scan dockerfile-config trivy config --severity HIGH,CRITICAL --exit-code 1 "$ROOT/Dockerfile"
# .superpowers/, bin/ and dist/ are git-ignored local output: they never exist in a CI checkout.
scan repo-secrets trivy fs --no-progress --scanners secret --exit-code 1 --skip-dirs "$ROOT/.superpowers" \
  --skip-dirs "$ROOT/bin" --skip-dirs "$ROOT/dist" "$ROOT"
scan govulncheck "$ROOT/scripts/release.sh" govulncheck

if [ -n "$failed" ]; then
  echo "security-scan: failed:$failed" >&2
  exit 1
fi
echo "security-scan: all scans passed"

#!/usr/bin/env bash
# Release helpers for .github/workflows/release.yml. Each command checks one thing and fails closed.
# Adapted from the sibling project fleet-in-a-repo (scripts/release.sh), which ran it on GitHub.
# Usage: scripts/release.sh <command> [args]
#   validate-tag <tag>                print <tag> if it is exactly vMAJOR.MINOR.PATCH; fail otherwise
#   check-ancestor <rev> [<base>]     fail unless <rev> (a tag is peeled to its commit) is in the
#                                     history of <base> (default origin/main): releases come from main
#   check-absent image <ref>          fail if <ref> already exists in its registry (tags are mutable on
#                                     GHCR: never overwrite)
#   check-absent release <owner/repo> <tag>
#                                     fail if a GitHub Release <tag> already exists in <owner/repo>
#                                     Both exit 2 when the answer is neither "exists" nor "not found"
#                                     (auth, network, missing tool): unknown is not absent.
#   build <buildx flags>...           docker buildx build of the Dockerfile for linux/amd64 with the
#                                     release build args from the environment (TAG, REVISION, SOURCE,
#                                     SOURCE_DATE_EPOCH; BUILDER, default "release"). The scan build and
#                                     the push build both go through here, so they cannot drift apart.
#   assert-scanned <local image> <ref@digest>
#                                     fail unless the pushed linux/amd64 image has the same config
#                                     digest (same layer diff_ids, labels, entrypoint) as the scanned one
#   assert-tag <repo:tag> <digest>    fail unless <repo:tag> resolves to <digest> in the registry
#   identity <owner/repo> <tag>       print the exact Sigstore certificate identity of release.yml
#                                     running for <tag>
#   identity-regexp <owner/repo> [<tag>]
#                                     print an anchored regexp of that identity: for exactly <tag>, or
#                                     for any vX.Y.Z tag when <tag> is omitted
#   image-digest <metadata.json>      print containerimage.digest from a buildx --metadata-file
#   local-config-digest <image>       print the config digest of a local image (via docker save)
#   remote-config-digest <ref@digest> [<os/arch>]
#                                     print the config digest of the <os/arch> image (default
#                                     linux/amd64) in a pushed index or manifest
#   govulncheck                       run govulncheck (GOVULNCHECK_VERSION) on the module inside the
#                                     Dockerfile's pinned builder image, so the analysed toolchain and
#                                     stdlib are the ones the image is built with
#   build-binary <goos> <goarch> <tag> [<outdir>]
#                                     static binary (CGO_ENABLED=0, -trimpath) of ./cmd/k8s-mcp with
#                                     main.version=<tag>, archived as <outdir>/k8s-mcp_<tag>_<goos>_<goarch>.tar.gz
#                                     (default outdir dist/) with LICENSE and README.md
#   checksums <dir> <tag>             write <dir>/SHA256SUMS over exactly the four release archives
#   notes <tag> <image ref@digest> <owner/repo>
#                                     print the GitHub Release notes with the verification commands
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ISSUER=https://token.actions.githubusercontent.com
PLATFORMS="darwin_amd64 darwin_arm64 linux_amd64 linux_arm64"

die() { echo "release: $*" >&2; exit 1; }
digest_re='^sha256:[0-9a-f]{64}$'
repo_re='^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'

validate_tag() {
  local tag="${1:-}"
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || die "tag '$tag' is not vMAJOR.MINOR.PATCH (no prerelease or build suffix)"
  echo "$tag"
}

check_repo() { [[ "${1:-}" =~ $repo_re ]] || die "expected owner/repo (got '${1:-}')"; }

sha256_of() {
  if command -v sha256sum > /dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

check_ancestor() {
  local rev="${1:-}" base="${2:-origin/main}" commit
  [ -n "$rev" ] || die "check-ancestor needs a revision"
  commit="$(git -C "$ROOT" rev-parse --verify -q "${rev}^{commit}")" || die "unknown revision '$rev'"
  git -C "$ROOT" rev-parse --verify -q "${base}^{commit}" > /dev/null \
    || die "unknown base '$base' (fetch it first)"
  git -C "$ROOT" merge-base --is-ancestor "$commit" "$base" \
    || die "$rev ($commit) is not on $base: releases are cut from $base only"
  echo "release: $rev ($commit) is on $base"
}

check_absent_image() {
  local ref="${1:-}" out
  [ -n "$ref" ] || die "check-absent image needs an image reference"
  # a missing or broken docker/buildx must not read as "not published"
  if ! docker buildx version > /dev/null 2>&1; then
    echo "release: docker buildx is not usable, cannot check whether $ref exists" >&2
    exit 2
  fi
  if out="$(docker buildx imagetools inspect --raw "$ref" 2>&1)"; then
    die "$ref already exists: refusing to overwrite a published version (bump the version instead)"
  fi
  case "$out" in
    # only a registry answer about this very ref counts as "absent"
    *"$ref: not found"* | *"manifest unknown"* | *MANIFEST_UNKNOWN* | *NAME_UNKNOWN*)
      echo "release: $ref does not exist yet" ;;
    *)
      echo "release: cannot tell whether $ref exists (registry said: $out)" >&2
      exit 2 ;;
  esac
}

check_absent_release() {
  local repo="${1:-}" tag="${2:-}" out
  check_repo "$repo"
  validate_tag "$tag" > /dev/null
  if ! command -v gh > /dev/null 2>&1; then
    echo "release: gh is not installed, cannot check whether release $tag exists" >&2
    exit 2
  fi
  if out="$(gh release view "$tag" --repo "$repo" --json tagName 2>&1)"; then
    die "GitHub Release $tag already exists in $repo: refusing to overwrite it (bump the version instead)"
  fi
  case "$out" in
    *"release not found"*) echo "release: no GitHub Release $tag in $repo yet" ;;
    *)
      echo "release: cannot tell whether GitHub Release $tag exists (gh said: $out)" >&2
      exit 2 ;;
  esac
}

check_absent() {
  local kind="${1:-}"
  [ "$#" -gt 0 ] && shift
  case "$kind" in
    image) check_absent_image "$@" ;;
    release) check_absent_release "$@" ;;
    *) die "usage: check-absent image <ref> | check-absent release <owner/repo> <tag>" ;;
  esac
}

image_digest() {
  local f="${1:-}" d
  [ -f "$f" ] || die "no metadata file '$f'"
  d="$(jq -r '."containerimage.digest" // empty' "$f")"
  [[ "$d" =~ $digest_re ]] || die "no valid containerimage.digest in $f (got '$d')"
  echo "$d"
}

local_config_digest() {
  local img="${1:-}" cfg hex
  [ -n "$img" ] || die "local-config-digest needs an image"
  # docker save writes manifest.json in both image stores: Config is "<hex>.json" (classic) or
  # "blobs/sha256/<hex>" (containerd); .Id would be the manifest digest in the containerd store.
  cfg="$(docker save "$img" | tar -xOf - manifest.json | jq -r '.[0].Config')"
  hex="$(printf '%s' "$cfg" | sed -nE 's#^(blobs/sha256/)?([0-9a-f]{64})(\.json)?$#\2#p')"
  [ -n "$hex" ] || die "could not read the config digest of $img (manifest.json Config: '$cfg')"
  echo "sha256:$hex"
}

remote_config_digest() {
  local ref="${1:-}" platform="${2:-linux/amd64}" raw mt m d os arch
  [[ "$ref" == *@sha256:* ]] || die "remote-config-digest needs <repo>@sha256:<digest> (never a tag)"
  os="${platform%%/*}"; arch="${platform#*/}"
  raw="$(docker buildx imagetools inspect --raw "$ref")"
  mt="$(printf '%s' "$raw" | jq -r '.mediaType // empty')"
  case "$mt" in
    application/vnd.oci.image.index.v1+json | application/vnd.docker.distribution.manifest.list.v2+json)
      m="$(printf '%s' "$raw" | jq -r --arg os "$os" --arg arch "$arch" \
        '[.manifests[] | select(.platform.os == $os and .platform.architecture == $arch)] | if length == 1 then .[0].digest else empty end')"
      [ -n "$m" ] || die "no single $platform manifest in $ref"
      raw="$(docker buildx imagetools inspect --raw "${ref%@*}@$m")" ;;
  esac
  d="$(printf '%s' "$raw" | jq -r '.config.digest // empty')"
  [[ "$d" =~ $digest_re ]] || die "no config digest in $ref"
  echo "$d"
}

build() {
  local v
  for v in TAG REVISION SOURCE SOURCE_DATE_EPOCH; do
    [ -n "${!v:-}" ] || die "build needs $v in the environment"
  done
  validate_tag "$TAG" > /dev/null
  [[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH must be a unix timestamp"
  docker buildx build --builder "${BUILDER:-release}" --platform linux/amd64 \
    --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" --build-arg "VERSION=$TAG" \
    --build-arg "REVISION=$REVISION" --build-arg "SOURCE=$SOURCE" \
    "$@" "$ROOT"
}

assert_scanned() {
  local img="${1:-}" ref="${2:-}" scanned pushed
  [ -n "$img" ] && [ -n "$ref" ] || die "assert-scanned needs <local image> <ref@digest>"
  pushed="$(remote_config_digest "$ref" linux/amd64)"
  scanned="$(local_config_digest "$img")"
  [ "$scanned" = "$pushed" ] \
    || die "pushed image $ref (config $pushed) is not the scanned image $img (config $scanned)"
  echo "release: pushed image config $pushed equals the scanned image config"
}

assert_tag() {
  local ref="${1:-}" want="${2:-}" got
  [[ "$ref" == *:* && "$ref" != *@* ]] || die "assert-tag needs <repo:tag> (got '$ref')"
  [[ "$want" =~ $digest_re ]] || die "assert-tag needs a sha256 digest (got '$want')"
  got="$(docker buildx imagetools inspect --format '{{json .Manifest}}' "$ref" | jq -r '.digest // empty')"
  [ "$got" = "$want" ] || die "$ref resolves to '$got', expected the signed digest $want"
  echo "release: $ref resolves to $want"
}

identity() {
  local repo="${1:-}" tag="${2:-}"
  check_repo "$repo"
  validate_tag "$tag" > /dev/null
  echo "https://github.com/${repo}/.github/workflows/release.yml@refs/tags/${tag}"
}

identity_regexp() {
  local repo="${1:-}" tag="${2:-}" t
  check_repo "$repo"
  if [ -n "$tag" ]; then
    validate_tag "$tag" > /dev/null
    t="${tag//./\\.}"
  else
    t='v[0-9]+\.[0-9]+\.[0-9]+'
  fi
  printf '^https://github\\.com/%s/\\.github/workflows/release\\.yml@refs/tags/%s$\n' "${repo//./\\.}" "$t"
}

run_govulncheck() {
  # shellcheck disable=SC1091
  source "$ROOT/versions.env"
  local builder
  builder="$(awk 'toupper($1) == "FROM" && toupper($3) == "AS" && $4 == "build" { print $2; exit }' "$ROOT/Dockerfile")"
  [[ "$builder" == *@sha256:* ]] || die "builder image in Dockerfile is not digest-pinned ('$builder')"
  [[ "${GOVULNCHECK_VERSION:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "GOVULNCHECK_VERSION missing from versions.env"
  # govulncheck exits 3 when the code calls a vulnerable symbol; go install verifies the module
  # against the Go checksum database (sum.golang.org).
  docker run --rm -v "$ROOT:/src:ro" -w /src -e GOFLAGS=-mod=readonly -e GOTOOLCHAIN=local "$builder" \
    sh -c "go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION} && govulncheck ./..."
}

build_binary() {
  local goos="${1:-}" goarch="${2:-}" tag="${3:-}" out="${4:-$ROOT/dist}" name stage
  case " $PLATFORMS " in
    *" ${goos}_${goarch} "*) ;;
    *) die "unsupported platform '$goos/$goarch' (release platforms: $PLATFORMS)" ;;
  esac
  validate_tag "$tag" > /dev/null
  name="k8s-mcp_${tag}_${goos}_${goarch}"
  stage="$(mktemp -d "${TMPDIR:-/tmp}/k8s-mcp-release.XXXXXX")"
  # shellcheck disable=SC2064 # expand now: stage is local
  trap "rm -rf '$stage'" EXIT
  mkdir -p "$stage/$name" "$out"
  (cd "$ROOT" && CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOFLAGS=-mod=readonly \
    go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$tag" -o "$stage/$name/k8s-mcp" ./cmd/k8s-mcp)
  cp "$ROOT/LICENSE" "$ROOT/README.md" "$stage/$name/"
  # GNU tar (the CI runner): fixed order, owner and mtime, so the archive depends only on its inputs
  if tar --version 2> /dev/null | grep -q 'GNU tar'; then
    tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner --mtime="@${SOURCE_DATE_EPOCH:-0}" \
      -cf - "$name" | gzip -n > "$out/$name.tar.gz"
  else
    COPYFILE_DISABLE=1 tar -C "$stage" -cf - "$name" | gzip -n > "$out/$name.tar.gz"
  fi
  echo "release: wrote $out/$name.tar.gz"
}

checksums() {
  local dir="${1:-}" tag="${2:-}" want="" got="" f p
  [ -d "$dir" ] || die "checksums needs a directory (got '$dir')"
  validate_tag "$tag" > /dev/null
  for p in $PLATFORMS; do want="${want}k8s-mcp_${tag}_${p}.tar.gz "; done
  for f in "$dir"/*.tar.gz; do [ -e "$f" ] && got="${got}${f##*/} "; done
  [ "$got" = "$want" ] || die "expected exactly the archives '$want' in $dir, found '$got'"
  for f in $want; do printf '%s  %s\n' "$(sha256_of "$dir/$f")" "$f"; done > "$dir/SHA256SUMS"
  echo "release: wrote $dir/SHA256SUMS"
}

notes() {
  local tag="${1:-}" ref="${2:-}" repo="${3:-}" id p
  validate_tag "$tag" > /dev/null
  [[ "$ref" =~ ^ghcr\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]] || die "notes needs the image as ghcr.io/<name>@sha256:<digest> (got '$ref')"
  id="$(identity "$repo" "$tag")"
  cat << EOF
k8s-mcp $tag: static binaries for linux and darwin (amd64, arm64), \`SHA256SUMS\` and a container
image, all signed keylessly with cosign by \`release.yml\` of this repository. Verify before use; the
full procedure and what it does not guarantee: [docs/security.md](https://github.com/$repo/blob/$tag/docs/security.md).

### Binaries

\`\`\`sh
cosign verify-blob --bundle SHA256SUMS.sigstore.json \\
  --certificate-identity $id \\
  --certificate-oidc-issuer $ISSUER SHA256SUMS
EOF
  for p in $PLATFORMS; do
    if [ "$p" = linux_amd64 ]; then
      cat << EOF
cosign verify-blob --bundle k8s-mcp_${tag}_${p}.tar.gz.sigstore.json \\
  --certificate-identity $id \\
  --certificate-oidc-issuer $ISSUER k8s-mcp_${tag}_${p}.tar.gz
EOF
    fi
  done
  cat << EOF
sha256sum --ignore-missing -c SHA256SUMS
\`\`\`

(Replace \`linux_amd64\` with your platform: \`linux_arm64\`, \`darwin_amd64\`, \`darwin_arm64\`.)

### Container image

Use the image by digest: tags on GHCR are mutable.

\`\`\`sh
cosign verify $ref \\
  --certificate-identity $id \\
  --certificate-oidc-issuer $ISSUER
docker buildx imagetools inspect $ref --format '{{json .SBOM}}'
docker buildx imagetools inspect $ref --format '{{json .Provenance}}'
\`\`\`
EOF
}

cmd="${1:-}"
[ "$#" -gt 0 ] && shift
case "$cmd" in
  validate-tag) validate_tag "$@" ;;
  check-ancestor) check_ancestor "$@" ;;
  check-absent) check_absent "$@" ;;
  build) build "$@" ;;
  assert-scanned) assert_scanned "$@" ;;
  assert-tag) assert_tag "$@" ;;
  identity) identity "$@" ;;
  identity-regexp) identity_regexp "$@" ;;
  image-digest) image_digest "$@" ;;
  local-config-digest) local_config_digest "$@" ;;
  remote-config-digest) remote_config_digest "$@" ;;
  govulncheck) run_govulncheck "$@" ;;
  build-binary) build_binary "$@" ;;
  checksums) checksums "$@" ;;
  notes) notes "$@" ;;
  *) echo "usage: $0 validate-tag|check-ancestor|check-absent|build|assert-scanned|assert-tag|identity|identity-regexp|image-digest|local-config-digest|remote-config-digest|govulncheck|build-binary|checksums|notes" >&2; exit 2 ;;
esac

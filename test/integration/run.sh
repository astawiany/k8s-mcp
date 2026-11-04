#!/usr/bin/env bash
# kind integration tests (make integration). Docker, kind, kubectl, curl and
# Go are required; versions come from versions.env.
#
# Creates ONE throwaway single-node kind cluster named k8s-mcp-it, with its
# kubeconfig in a private temp file (the user's kubeconfig is never read or
# written), installs Flux (source, kustomize and helm controllers only) from
# the sha256-verified release manifests, applies test/integration/fixtures,
# waits for each fixture to reach its broken state (bounded polls), builds
# two read-only identities, runs `go test -tags integration` and ALWAYS
# deletes the cluster (trap EXIT). metrics-server is not installed: the top
# test asserts available=false.
#
# Environment: IT_GO_TEST_ARGS  extra `go test` arguments (e.g. -run TestX).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HERE="$ROOT/test/integration"
# shellcheck disable=SC1091
source "$ROOT/versions.env"

CLUSTER=k8s-mcp-it
CTX="kind-$CLUSTER"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/k8s-mcp-it.XXXXXX")
KC="$WORK/kubeconfig"
# Every kubectl and kind call below uses this file; nothing else is touched.
export KUBECONFIG="$KC"

created=0
start=$SECONDS
phase_start=$SECONDS
timings=()

die() {
	echo "run.sh: $*" >&2
	exit 1
}

phase() {
	local now=$SECONDS
	if [[ -n ${current_phase:-} ]]; then
		timings+=("$(printf '%-34s %4ds' "$current_phase" $((now - phase_start)))")
	fi
	current_phase=$1
	phase_start=$now
	echo "== [$((now - start))s] $1"
}

cleanup() {
	local rc=$?
	trap - EXIT INT TERM
	phase "delete cluster"
	if [[ $created -eq 1 ]]; then
		kind delete cluster --name "$CLUSTER" --kubeconfig "$KC" || rc=1
	fi
	rm -rf "$WORK"
	phase "done"
	echo "== timings"
	printf '  %s\n' "${timings[@]}"
	printf '  %-34s %4ds\n' "total" $((SECONDS - start))
	if [[ $rc -eq 0 ]]; then echo "== integration: PASS"; else echo "== integration: FAIL (exit $rc)"; fi
	exit "$rc"
}

# k runs kubectl against the test cluster only.
k() {
	kubectl --kubeconfig "$KC" --context "$CTX" "$@"
}

# poll <timeout-s> <description> <regex> <kubectl get args...>: re-reads the
# object every 2s until the output matches regex, or fails at the timeout.
poll() {
	local timeout=$1 desc=$2 re=$3
	shift 3
	local deadline=$((SECONDS + timeout)) got
	while :; do
		got=$(k get "$@" 2>/dev/null || true)
		if [[ $got =~ $re ]]; then
			echo "  ok ($((timeout - deadline + SECONDS))s): $desc = $got"
			return 0
		fi
		((SECONDS < deadline)) || die "timed out after ${timeout}s waiting for $desc (last: '${got}')"
		sleep 2
	done
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# sa_kubeconfig <namespace> <serviceaccount> <context> <file>: a kubeconfig
# that authenticates as the ServiceAccount with a short-lived token.
sa_kubeconfig() {
	local ns=$1 sa=$2 ctx=$3 out=$4 server ca token
	server=$(k config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')
	ca=$(k config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
	token=$(k -n "$ns" create token "$sa" --duration=1h)
	(
		umask 077
		cat >"$out" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: $CLUSTER
  cluster:
    server: $server
    certificate-authority-data: $ca
users:
- name: $sa
  user:
    token: $token
contexts:
- name: $ctx
  context: {cluster: $CLUSTER, user: $sa}
current-context: $ctx
EOF
	)
}

# can_i_no <identity> <verb> <resource> <namespace>: RBAC must deny.
can_i_no() {
	local got
	got=$(k auth can-i "$2" "$3" -n "$4" --as="$1" 2>/dev/null || true)
	[[ $got == no ]] || die "RBAC: $1 can $2 $3 in $4 (got '$got', want 'no')"
	echo "  ok: kubectl auth can-i $2 $3 -n $4 --as=$1 -> $got"
}

phase "preflight"
for c in docker kind kubectl go curl tar; do
	command -v "$c" >/dev/null 2>&1 || die "$c is not installed"
done
kv=$(kind version | awk '{print $2}')
[[ $kv == "v$KIND_VERSION" ]] || die "kind $kv found, versions.env pins v$KIND_VERSION"
docker info >/dev/null 2>&1 || die "docker is not running"
kubectl_v=$(kubectl version --client 2>/dev/null | awk '/^Client Version:/ {print $3}')
[[ $kubectl_v == "v$KUBECTL_VERSION" ]] ||
	echo "run.sh: WARNING: kubectl $kubectl_v differs from KUBECTL_VERSION v$KUBECTL_VERSION (scripts/ci-install-tools.sh kubectl)" >&2
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
	die "a kind cluster named $CLUSTER already exists; it is not ours to delete (kind delete cluster --name $CLUSTER)"
fi
trap cleanup EXIT
trap 'exit 130' INT TERM

phase "create kind cluster"
created=1
kind create cluster --name "$CLUSTER" --image "$KIND_NODE_IMAGE" --kubeconfig "$KC" --wait 180s
# Refuse to touch anything but the cluster just created.
[[ $(kubectl --kubeconfig "$KC" config current-context) == "$CTX" ]] || die "kube context is not $CTX"
[[ $(k config view --minify -o jsonpath='{.clusters[0].cluster.server}') =~ ^https://127\.0\.0\.1:[0-9]+$ ]] ||
	die "context $CTX does not point at a local kind API server"

phase "install flux (verified manifests)"
flux_images=("$FLUX_SOURCE_CONTROLLER_IMAGE" "$FLUX_KUSTOMIZE_CONTROLLER_IMAGE" "$FLUX_HELM_CONTROLLER_IMAGE")
mkdir -p "$WORK/flux/manifests"
curl -fsSL --retry 3 -o "$WORK/flux/manifests.tar.gz" \
	"https://github.com/fluxcd/flux2/releases/download/v${FLUX_VERSION}/manifests.tar.gz"
got=$(sha256 "$WORK/flux/manifests.tar.gz")
[[ $got == "$FLUX_MANIFESTS_SHA256" ]] || die "flux manifests sha256 $got, want $FLUX_MANIFESTS_SHA256"
echo "  ok: manifests.tar.gz sha256 $got"
tar -xzf "$WORK/flux/manifests.tar.gz" -C "$WORK/flux/manifests"
{
	echo "apiVersion: kustomize.config.k8s.io/v1beta1"
	echo "kind: Kustomization"
	echo "namespace: flux-system"
	echo "resources: [namespace.yaml, manifests/rbac.yaml, manifests/source-controller.yaml,"
	echo "  manifests/kustomize-controller.yaml, manifests/helm-controller.yaml]"
	echo "images:"
	# manifests.tar.gz names the images fluxcd/<name>:<tag>, install.yaml
	# ghcr.io/fluxcd/<name>:<tag>; kustomize matches names exactly, so both
	# spellings are rewritten to the pinned ghcr.io digest.
	for img in "${flux_images[@]}"; do
		repo=${img%@*}
		for name in "$repo" "${repo#ghcr.io/}"; do
			echo "- name: $name"
			echo "  newName: $repo"
			echo "  digest: ${img#*@}"
		done
	done
} >"$WORK/flux/kustomization.yaml"
printf 'apiVersion: v1\nkind: Namespace\nmetadata:\n  name: flux-system\n' >"$WORK/flux/namespace.yaml"
k apply --server-side -k "$WORK/flux"
# Every flux-system container must run a pinned digest from versions.env.
deployed=$(k -n flux-system get deploy -o jsonpath='{range .items[*]}{range .spec.template.spec.containers[*]}{.image}{"\n"}{end}{end}')
[[ $(wc -l <<<"$deployed") -eq ${#flux_images[@]} ]] || die "flux-system runs $(wc -l <<<"$deployed") containers, want ${#flux_images[@]}"
while read -r img; do
	[[ $img == *@sha256:* && " ${flux_images[*]} " == *" $img "* ]] || die "flux-system image $img is not a pinned digest from versions.env"
	echo "  ok: $img"
done <<<"$deployed"

phase "apply fixtures"
k apply -f "$ROOT/deploy/rbac/readonly-clusterrole.yaml"
for f in 10-workloads 20-secret 30-log-injection 50-ns-reader; do
	sed "s|@BUSYBOX_IMAGE@|$BUSYBOX_IMAGE|g" "$HERE/fixtures/$f.yaml" | k apply --server-side -f -
done
k wait --for=condition=Established --timeout=60s \
	crd/gitrepositories.source.toolkit.fluxcd.io crd/helmrepositories.source.toolkit.fluxcd.io \
	crd/kustomizations.kustomize.toolkit.fluxcd.io crd/helmreleases.helm.toolkit.fluxcd.io
k apply --server-side -f "$HERE/fixtures/40-flux.yaml"

phase "wait for fixture states"
for d in source-controller kustomize-controller helm-controller; do
	k -n flux-system rollout status "deploy/$d" --timeout=240s
done
k -n broken rollout status deploy/healthy --timeout=180s
poll 180 "crashloop waiting reason" '^CrashLoopBackOff$' -n broken pod -l app=crashloop \
	-o jsonpath='{.items[0].status.containerStatuses[0].state.waiting.reason}'
poll 180 "oomkilled last termination" '^OOMKilled$' -n broken pod -l app=oomkilled \
	-o jsonpath='{.items[0].status.containerStatuses[0].lastState.terminated.reason}'
poll 180 "imagepull waiting reason" '^(ErrImagePull|ImagePullBackOff)$' -n broken pod -l app=imagepull \
	-o jsonpath='{.items[0].status.containerStatuses[0].state.waiting.reason}'
poll 120 "unschedulable PodScheduled reason" '^Unschedulable$' -n broken pod -l app=unschedulable \
	-o jsonpath='{.items[0].status.conditions[?(@.type=="PodScheduled")].reason}'
poll 180 "failing-readiness phase/started/ready" '^Running/true/false$' -n broken pod -l app=failing-readiness \
	-o jsonpath='{.items[0].status.phase}/{.items[0].status.containerStatuses[0].started}/{.items[0].status.containerStatuses[0].ready}'
k -n broken wait pod/log-injection pod/secret-user --for=condition=Ready --timeout=180s
poll 180 "GitRepository unreachable Ready status/reason" '^False/GitOperationFailed$' -n broken gitrepository/unreachable \
	-o jsonpath='{.status.conditions[?(@.type=="Ready")].status}/{.status.conditions[?(@.type=="Ready")].reason}'
# Whether Flux itself already hides the URL password (the tool scrubs it
# either way; the tests check that no output contains it).
raw=$(k -n broken get gitrepository/unreachable -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}')
if [[ $raw == *s3cr3tpass-k8smcp* ]]; then
	echo "  note: the raw GitRepository Ready message contains the URL password (Flux does not mask it)"
else
	echo "  note: the raw GitRepository Ready message does not contain the URL password (Flux masks it): ${raw:0:120}"
fi
poll 180 "HelmRelease failing Ready" '^False$' -n broken helmrelease/failing \
	-o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'

phase "read-only identities"
sa_kubeconfig k8s-mcp k8s-mcp k8s-mcp-readonly "$WORK/readonly.kubeconfig"
sa_kubeconfig broken ns-reader k8s-mcp-ns-reader "$WORK/ns-reader.kubeconfig"
for id in system:serviceaccount:k8s-mcp:k8s-mcp system:serviceaccount:broken:ns-reader; do
	can_i_no "$id" get secrets broken
	can_i_no "$id" list secrets broken
	can_i_no "$id" create pods broken
done
can_i_no system:serviceaccount:broken:ns-reader list nodes default

phase "go test -tags integration"
# shellcheck disable=SC2086
K8S_MCP_IT_KUBECONFIG="$KC" \
	K8S_MCP_IT_READONLY_KUBECONFIG="$WORK/readonly.kubeconfig" \
	K8S_MCP_IT_NSREADER_KUBECONFIG="$WORK/ns-reader.kubeconfig" \
	go -C "$ROOT" test -tags integration -count=1 -timeout 10m -v ${IT_GO_TEST_ARGS:-} ./test/integration/...

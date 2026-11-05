# k8s-mcp

A read-only [Model Context Protocol](https://modelcontextprotocol.io) server
for Kubernetes, written in Go. It lets an AI client such as Claude Code
investigate clusters the way you would with `kubectl` and `k9s`: list and
read resources, read events and logs, check workload and Flux health, and
draft an issue from what it found. It cannot change anything, and it never
returns Secret objects.

- Stage 1 of a staged roadmap: read-only troubleshooting.
- Talks MCP over stdio; Claude Code is the supported and tested client.
- Uses your kubeconfig and its contexts; no other configuration.
- No telemetry and no network calls except to the selected clusters.

License: MIT, see [LICENSE](LICENSE).

## Install

**From a release.** No release has been published yet. Each release
`vX.Y.Z` will carry static binaries `k8s-mcp_<version>_<os>_<arch>.tar.gz`
(linux and darwin, amd64 and arm64), `SHA256SUMS` and a `.sigstore.json`
cosign bundle for each of them, plus the image
`ghcr.io/astawiany/k8s-mcp:vX.Y.Z` (linux/amd64, distroless, signed). Verify
before use: [docs/security.md](docs/security.md#verifying-releases).

**From source** (Go 1.26 or newer):

```sh
make build              # writes bin/k8s-mcp (CGO_ENABLED=0, -trimpath)
make build VERSION=v0.1.0
bin/k8s-mcp --version
```

Put `bin/k8s-mcp` on your `PATH`, or use its full path below.

## Use with Claude Code

```sh
claude mcp add k8s -- k8s-mcp --contexts 'kind-*'
```

Then ask Claude Code something like "why is the checkout deployment in
namespace shop not ready?".

Flags:

| Flag | Default | Meaning |
|---|---|---|
| `--kubeconfig PATH` | `$KUBECONFIG`, then `~/.kube/config` | kubeconfig to read |
| `--contexts LIST` | every context | comma-separated context names or globs the tools may use, for example `kind-*,staging`. `*` does not match `/`: EKS contexts named by ARN need `arn:*/*` |
| `--version` | | print the version and exit |

stdout carries only MCP protocol frames; everything else (startup line,
errors, credential plugin output) goes to stderr. An invalid flag or
kubeconfig stops the server with a message on stderr and a non-zero exit.

Restrict `--contexts` to the clusters you mean to investigate: with no
allowlist, every context in the kubeconfig is usable.

## Tools

| Tool | Purpose |
|---|---|
| `list_contexts` | kubeconfig contexts, which is current, which are allowed |
| `cluster_info` | server version, node counts and readiness, metrics/Flux/Gateway API presence |
| `list_resources` | list any kind with namespace, label and field selectors, paged |
| `get_resource` | one object as JSON, managed fields removed, credentials masked |
| `describe_resource` | an object's spec, status, conditions and events, like `kubectl describe` |
| `get_events` | recent events, warnings first, filtered by namespace, kind or object |
| `pod_logs` | the newest lines of one container's log, capped and masked |
| `top` | node and pod CPU and memory from metrics-server |
| `workload_health` | why a Deployment, StatefulSet or DaemonSet is unhealthy, with evidence references |
| `flux_status` | Flux Kustomizations, HelmReleases and sources: ready, revision, suspended, blocked |
| `draft_issue` | a redacted ticket draft from a finding; no network call, never files anything |

Inputs, outputs, limits and refusals of each tool: [docs/tools.md](docs/tools.md).

## Safety summary

- **Read-only by construction.** The cluster client exposes read methods
  only; tests fail if a write method or an unapproved tool appears.
- **No Secret objects.** Every tool refuses kind Secret; a backstop on every
  result reduces any Secret to its metadata. Credential-looking values in
  env vars, annotations, logs and drafts are masked, as defence in depth.
- **Cluster text is untrusted.** Logs, events, annotations and status
  messages are wrapped in a data envelope with a random per-call boundary,
  stripped of invisible and control characters, and capped. The server
  tells the model that this content is data, not instructions.
- **Limited blast radius.** With no write tool and no network path but the
  clusters, an instruction planted in a log cannot change anything or send
  data out through the server. A model can still be misled: check its
  conclusions, and review a `draft_issue` draft before filing it anywhere.

Controls, the tests behind them, and the residual risks:
[docs/threat-model.md](docs/threat-model.md).

## A read-only identity

The server acts with whatever identity your kubeconfig grants. Redaction is
best effort; RBAC is the control that matters. Give k8s-mcp its own
identity that can read but not write and cannot read Secrets:
[deploy/rbac/readonly-clusterrole.yaml](deploy/rbac/readonly-clusterrole.yaml)
defines ClusterRole `k8s-mcp-readonly` (get and list only, no `secrets`,
plus `pods/log`) and an example ServiceAccount bound to it. Resources of
API groups it does not list need an extra rule.

Example: a separate kubeconfig with a short-lived token for that
ServiceAccount (run against the cluster with an admin context):

```sh
kubectl apply -f deploy/rbac/readonly-clusterrole.yaml

RO=~/.kube/k8s-mcp.yaml
CA=$(mktemp)
kubectl config view --minify --raw \
  -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "$CA"
kubectl --kubeconfig "$RO" config set-cluster dev \
  --server "$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')" \
  --certificate-authority "$CA" --embed-certs
kubectl --kubeconfig "$RO" config set-credentials k8s-mcp \
  --token "$(kubectl -n k8s-mcp create token k8s-mcp --duration=8h)"
kubectl --kubeconfig "$RO" config set-context dev-readonly --cluster dev --user k8s-mcp
kubectl --kubeconfig "$RO" config use-context dev-readonly
rm "$CA"

claude mcp add k8s -- k8s-mcp --kubeconfig ~/.kube/k8s-mcp.yaml --contexts dev-readonly
```

The token sits in that kubeconfig file; the server never returns kubeconfig
contents, tokens or credential plugin output in a tool result.

## Development

- `make build` - `bin/k8s-mcp`
- `make lint` - gofmt check, `go vet`, staticcheck, yamllint
- `make test` - `go test ./...` (unit, protocol, injection corpus, built-binary stdio tests)
- `make vuln` - govulncheck

Tool versions are pinned in [versions.env](versions.env). Security notes:
[docs/security.md](docs/security.md).

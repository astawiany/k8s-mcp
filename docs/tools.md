# Tools

k8s-mcp has eleven tools, all read-only. This page describes each one: what
it is for, its inputs, the fields it returns, its limits and what it refuses.
The tool descriptions the server sends to the model say the same in short
form. The field names are stable; a change to them is a breaking change.

For the reasons behind the limits and the redaction rules, see
[threat-model.md](threat-model.md).

## Common rules

**Read-only.** No tool creates, changes or deletes anything. The cluster
client interface has read methods only (`get`, `list`, log and metrics
reads), and tests fail if a mutating method appears or a tool outside the
approved eleven is registered.

**`context`.** Every tool except `list_contexts` takes an optional
`context`: a kubeconfig context name. Empty means the kubeconfig's current
context. A context that does not exist, or is not on the `--contexts`
allowlist, is an error; `list_contexts` shows which are allowed. (`draft_issue`
accepts `context` and ignores it: it never contacts a cluster.)

**Result format.** A successful result is one text block: a JSON document
between a line `<<<DATA <boundary>>>` and a line `<<<END <boundary>>>`. The
boundary is random for every call; any `<<<` inside the data is shown as
`<<‹`, so the data cannot end the envelope early. The server instructions tell
the model that everything inside the envelope is untrusted data from the
cluster and never instructions.

**What every result goes through.** One wrapper handles every tool result:

- control characters, ANSI escapes, zero-width and bidirectional-override
  characters are removed from every string (map keys too);
- a string that looks like a Kubernetes Secret manifest is replaced whole
  with a marker; a string holding a token shape (JWT, cloud and SaaS API
  keys, private key blocks, URL passwords) is replaced with `[redacted]`;
- any object with `kind: Secret`, at any depth, is reduced to its metadata,
  and Secrets embedded in annotations such as
  `kubectl.kubernetes.io/last-applied-configuration` are masked;
- each string is capped at 2000 bytes per line, 500 lines and 64 KiB; the
  whole document is capped at 64 KiB. A cut ends with
  `[truncated: <reason>; narrow with <hint>]`.

Tools that return Kubernetes objects also mask credential-looking values
themselves (env values, probe headers and command flags with credential
names or token shapes), and remove `metadata.managedFields`.

**Item caps.** List-like results return at most 200 items and say so with
`truncated: true` (and `total` or `continue` where the API gives one).

**Timeout.** Every API request has a 15 second timeout.

**Errors.** Errors are tool errors (`isError: true`), not protocol errors, so
the model can recover. The text starts with a fixed class sentence and a hint,
then the detail in a data envelope (the detail may quote the cluster). The
classes are: unknown kubeconfig context; context not on the allowlist (the
message lists the allowlist); kind not found (with up to five close matches);
not found; forbidden by RBAC (with the API server's message, which names the
verb and resource); unauthorized; API request timed out; cannot reach the
API server; credential plugin (exec) failed; metrics API not available.

**Secrets.** Every tool that takes a kind refuses the core `Secret` kind
under any spelling (kind `Secret` or resource `secrets` in any case, short
names, the `resource.group` form), and refuses an object read under another
name that turns out to be a Secret. Values in other objects are
masked by heuristics, which are best effort: RBAC that does not grant
`secrets` is the primary control (see
[deploy/rbac/readonly-clusterrole.yaml](../deploy/rbac/readonly-clusterrole.yaml)).

## `list_contexts`

**Purpose.** Show the kubeconfig contexts and which ones the tools may use.

**Input.** None.

**Output.** A JSON array of `{name, current, allowed}`, sorted by name.
`current` marks the kubeconfig's current context. `allowed: false` means the
context is outside the `--contexts` allowlist and every tool refuses it.

**Limits.** Never returns server URLs, user names, credentials or any other
kubeconfig content. Never contacts a cluster.

**Refusals.** None.

## `cluster_info`

**Purpose.** A first look at one cluster.

**Input.** `context` (optional).

**Output.**

| Field | Meaning |
|---|---|
| `context` | the context used |
| `serverVersion` | the API server's version |
| `nodes.total`, `nodes.ready` | node counts; a node with no Ready condition counts as not ready |
| `nodes.notReady` | names of not-ready nodes |
| `nodes.truncated` | more than 200 not-ready names |
| `nodes.totalIsLowerBound` | counting stopped at 10000 nodes |
| `apiGroups.metrics`, `.flux`, `.gatewayAPI` | whether metrics-server, Flux and Gateway API are served |
| `nodesNote`, `apiGroupsNote` | set when nodes or discovery could not be read (RBAC, timeout): that part is unknown, not zero |

**Limits.** At most 200 not-ready names; at most 10000 nodes counted. Reads
nodes and discovery only.

**Refusals.** A failed server version read is an error; failures of the node
list or discovery degrade to the notes above.

## `list_resources`

**Purpose.** List objects of any kind, like `kubectl get`.

**Input.**

| Field | Required | Meaning |
|---|---|---|
| `kind` | yes | kind, resource name or short name, any case: `Pod`, `pods`, `po`, `deployments.apps` |
| `group`, `version` | no | filter when a name is ambiguous; `core` means the legacy group |
| `namespace` | no | empty lists all namespaces; ignored for cluster-scoped kinds |
| `labelSelector` | no | for example `app=web,tier!=db` |
| `fieldSelector` | no | for example `status.phase=Running` |
| `limit` | no | rows per page; default 100, at most 200 |
| `continue` | no | token from the previous page of the same query |
| `context` | no | |

**Output.** `{resource, kind, namespaced, items, limit, continue, truncated,
total, note}`. Each item is `{namespace, name, age, status}`. `status` is a
short derived string: Pod phase or container reason plus ready/total;
ready/desired for Deployments, StatefulSets, ReplicaSets and DaemonSets;
Ready/NotReady for Nodes; Complete/Failed/Running for Jobs; otherwise the
Ready condition, else the first False condition, else `status.phase`.

**Limits.** One page per call, at most 200 rows. When more exist,
`truncated: true` and `continue` holds the next page token; `total` is the
server's estimate.

**Refusals.** Secrets (any alias). Unknown kinds return close matches.

## `get_resource`

**Purpose.** One object in full, like `kubectl get -o json`.

**Input.** `kind` (required), `name` (required), `namespace` (required for
namespaced kinds, ignored otherwise), `group`, `version`, `context`.

**Output.** The object as JSON, status included, `metadata.managedFields`
removed, credential-looking values masked (env values, probe headers, command
flags with credential names or token shapes, Secrets embedded in
annotations).

**Limits.** Strings and the document are capped at 64 KiB with a marker.

**Refusals.** Secrets (any alias). An object that turns out to be a Secret is
refused even if it was asked for under another name.

## `describe_resource`

**Purpose.** An object's key state plus its events, like `kubectl describe`.

**Input.** As `get_resource`.

**Output.** `{object, conditions, events, eventsTruncated, eventsNote}`.

- `object` keeps only `apiVersion`, `kind`, `metadata` (name, namespace,
  labels, annotations without last-applied-configuration, ownerReferences,
  creationTimestamp, deletionTimestamp), `spec` and `status`, masked as in
  `get_resource`. Top-level fields such as ConfigMap `data` or Role `rules`
  are not shown: use `get_resource` for them.
- `conditions` are `status.conditions` as `{type, status, reason, message,
  lastTransitionTime}`.
- `events` are the events about this object (Node events include the
  kubelet's), oldest first, each as in `get_events`.

**Limits.** At most 200 conditions; at most the 50 newest events
(`eventsTruncated: true` when there were more). If events cannot be read, the
object is still returned with `eventsNote` set.

**Refusals.** Secrets.

## `get_events`

**Purpose.** Recent events, warnings first.

**Input.**

| Field | Meaning |
|---|---|
| `namespace` | empty means all namespaces |
| `involvedKind` | only events about this kind (kind, resource or short name) |
| `involvedName` | only events about the object with this name |
| `sinceMinutes` | only events seen in the last N minutes; default 60, at most 1440 |
| `warningsOnly` | only events of type Warning |
| `context` | |

**Output.** `{events, total, truncated, note}`. Each event is `{type, reason,
message, object (Kind/name), namespace, count, firstSeen, lastSeen,
warning}`. Sorted warnings first, then oldest to newest within each group.

**Limits.** At most 200 events (warnings kept first, then the newest others);
at most the 5000 newest events are read from the API.

**Refusals.** `involvedKind` Secret.

## `pod_logs`

**Purpose.** The newest lines of one container's log.

**Input.**

| Field | Required | Meaning |
|---|---|---|
| `namespace`, `pod` | yes | the pod |
| `container` | when the pod has more than one | the error lists the containers |
| `tailLines` | no | default 200, at most 500 |
| `sinceSeconds` | no | at most 86400 |
| `previous` | no | the last terminated instance, for example after a crash |
| `context` | no | |

**Output.** `{namespace, pod, container, previous, log, lineCount,
redactedLines, truncated, note, hidden, hiddenReason, hint}`. `log` is one
string, newest line last.

**What is done to the log.** It is untrusted workload output.

- Control, ANSI and invisible characters are stripped. CRLF ends a line; of a
  line rewritten with bare carriage returns (a progress bar) only the last
  segment is kept.
- A private key block (`BEGIN ... PRIVATE KEY` through `END`, or to the end
  of the window if `END` is missing) becomes one marker line.
- A line with a credential-looking value (JWT; GitHub, AWS, Slack, Google or
  Stripe token; URL password) is replaced whole by a marker and counted in
  `redactedLines`.
- If the log looks like a Kubernetes Secret manifest, or the text as a whole
  matches a token shape (for example base64 over several lines that decodes
  to a token), the whole log is withheld: `log` is empty, `hidden: true`,
  `hiddenReason` says why and `hint` suggests a narrower read. This is
  fail-closed on purpose; logs of controllers that print Secret manifests
  cannot be read through this tool.

**Limits.** Lines over 2000 bytes are cut. The log is cut from the oldest
end to about 56 KiB (`truncated: true`, also when older lines may exist
beyond `tailLines`). A token split across two lines is not detected. A tail
window that starts inside a private key (no `BEGIN` in the window) can show
parts of the key body; see the threat model.

**Refusals.** Out-of-range `tailLines` or `sinceSeconds`; a multi-container
pod without `container`; `previous` when there is no terminated instance.

## `top`

**Purpose.** Current CPU and memory use, like `kubectl top`.

**Input.** `scope` (required: `nodes` or `pods`), `namespace` (pods only;
empty means all namespaces), `context`.

**Output.** `{scope, available, message, rows, total, truncated, note}`. Each
row is `{name, namespace, cpu, memory, cpuMillicores, memoryBytes}`, sorted by
CPU, highest first. Pod rows add `cpuPercentOfRequests` and
`memoryPercentOfRequests` when every container of the pod declares that
request.

**Limits.** At most 200 rows. Without metrics-server the result is
`{available: false, message}`, not an error.

**Refusals.** Any other `scope`.

## `workload_health`

**Purpose.** Why a Deployment, StatefulSet or DaemonSet is not healthy.

**Input.** `namespace`, `kind` (Deployment, StatefulSet or DaemonSet), `name`
(all required), `context`.

**Output.** `{rollout, pods, findings, truncated, note}`.

- `rollout`: `{desired, ready, updated, unavailable, progressing, message}`.
- `pods`: `{name, phase, restarts, ready, waitingReason, lastTermination
  {reason, exitCode, finishedAt}, unschedulableMessage}`, unhealthy pods
  first.
- `findings`: `{severity (critical or warning), summary, evidenceRef}` with a
  cause: CrashLoopBackOff, OOMKilled (with the memory limit),
  ImagePullBackOff, unschedulable, failing readiness,
  ProgressDeadlineExceeded, evicted, configuration errors. `evidenceRef` such
  as `pod/<name>/lastState` can be quoted in `draft_issue`.

Pods are selected by the workload's `spec.selector`; pods owned by another
controller and pods of scaled-down old ReplicaSets are dropped. Only fields
derived from status are returned, never pod specs or env.

**Limits.** At most 50 pods returned; the pod list is read up to 200
(`truncated: true` when either cap is hit).

**Refusals.** Other kinds.

## `flux_status`

**Purpose.** Health of Flux CD objects.

**Input.** `kinds` (any of Kustomization, HelmRelease, GitRepository,
HelmRepository, OCIRepository, HelmChart, Bucket; default the first five),
`namespace` (empty reads all), `onlyUnhealthy`, `context`.

**Output.** `{installed, message, statuses, blockedBy, summary, missingKinds,
truncated, note}`.

- `statuses`: `{kind, namespace, name, ready, reason, message, revision,
  suspended, stalled, dependsOn}`, unhealthy first.
- `blockedBy`: not-Ready objects waiting on `dependsOn` entries that are not
  Ready, missing, or outside what was read.
- `summary`: `{total, ready, notReady, suspended}` over everything read,
  before `onlyUnhealthy` and the cap. A Ready but suspended object counts in
  both `ready` and `suspended`.
- `missingKinds`: kinds the cluster does not serve. Without Flux CRDs the
  result is `installed: false`.

**Limits.** At most 200 statuses and at most 200 `blockedBy` entries
(`truncated: true` and a `note` when either cap is hit). Only status fields
are returned, never spec contents; credentials in URLs in messages are
redacted.

**Refusals.** Unknown kinds.

## `draft_issue`

**Purpose.** Turn a finding into a ticket draft that the user can file with
whichever ticketing MCP server they run. This tool makes no network calls and
never talks to Jira or any other system.

**Input.**

| Field | Required | Limit |
|---|---|---|
| `title` | yes | 120 characters |
| `severity` | yes | `low`, `medium`, `high` or `critical` |
| `cluster` | yes | |
| `namespace`, `object` | no | for example `Deployment/web` |
| `summary` | yes | 1000 characters |
| `evidence` | no | at most 10 `{ref, quote}`; `ref` up to 200 characters, `quote` cut to 300 |
| `suggestedNext` | no | at most 10, 300 characters each |
| `context` | no | ignored |

**Output.** `{summary, description, labels, warnings, droppedEvidence,
droppedSuggestedNext}`. `summary` is a one-line ticket title (at most 120
characters); `description` is plain Markdown; `labels` are `k8s-mcp`,
`severity-<s>` and `cluster-<name>`; `warnings` lists what was changed.

**What is done to the input.** Every field is sanitised; URL credentials are
scrubbed; each line that looks like a credential, and whole private key
blocks, are masked; a field that looks like a Secret manifest is replaced.
The assembled description and summary line are checked as a whole too, since
words from different fields can combine (a summary saying "this kind of
rollout waits for the secret" plus a quote holding `volume "data"`). When the
whole trips the check, evidence quotes are withheld one by one, then the
summary, the object, the evidence refs and the suggested steps (for the
summary line: the title, then cluster and namespace), each replaced by a fixed
note and named in `warnings`, until it passes; the draft is never blanked
silently. A field whose credential masking does not settle after three passes
is replaced by a fixed note with a warning.
Markdown and Jira wiki special characters are backslash-escaped, quotes go in
a fenced block that a quote cannot close, and no link, image or mention
markup is generated. Bare URLs in the text may still be autolinked by the
viewer (GitHub, Jira).

**Limits.** As in the input table.

**Refusals.** Missing required fields, an unknown severity. The description
tells the model to show the draft to the user and get explicit confirmation
before filing it anywhere.

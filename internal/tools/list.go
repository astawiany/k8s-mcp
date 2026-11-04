package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/limits"
	"github.com/astawiany/k8s-mcp/internal/redact"
	"github.com/astawiany/k8s-mcp/internal/server"
)

// defaultListLimit is the page size when the caller gives none; the maximum
// is limits.Default().MaxItems.
const defaultListLimit = 100

type listIn struct {
	Context       string `json:"context,omitempty" jsonschema:"kubeconfig context name; defaults to the current context"`
	Kind          string `json:"kind" jsonschema:"kind, resource name or short name, any case: Pod, pods, po, deployments.apps"`
	Group         string `json:"group,omitempty" jsonschema:"API group filter, e.g. apps; core for the legacy group"`
	Version       string `json:"version,omitempty" jsonschema:"API version filter, e.g. v1"`
	Namespace     string `json:"namespace,omitempty" jsonschema:"namespace; empty lists all namespaces; ignored for cluster-scoped kinds"`
	LabelSelector string `json:"labelSelector,omitempty" jsonschema:"label selector, e.g. app=web,tier!=db"`
	FieldSelector string `json:"fieldSelector,omitempty" jsonschema:"field selector, e.g. status.phase=Running"`
	Limit         int    `json:"limit,omitempty" jsonschema:"rows per page; default 100, at most 200"`
	Continue      string `json:"continue,omitempty" jsonschema:"continue token from a previous page of the same query"`
}

type listRow struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Age       string `json:"age,omitempty"`
	Status    string `json:"status,omitempty"`
}

type listOut struct {
	Resource   string    `json:"resource"`
	Kind       string    `json:"kind"`
	Namespaced bool      `json:"namespaced"`
	Items      []listRow `json:"items"`
	Limit      int       `json:"limit"`
	Continue   string    `json:"continue,omitempty"`
	Truncated  bool      `json:"truncated"`
	// Total is the server's estimate of all matching objects, when it gives one.
	Total *int64 `json:"total,omitempty"`
	Note  string `json:"note,omitempty"`
}

func registerList(s *server.Server) {
	server.Register(s, &mcp.Tool{
		Name: "list_resources",
		Description: "List objects of any kind as compact rows {namespace, name, age, status}. status is a short " +
			"derived string when the kind has one (Pod: phase or container reason plus ready/total; Deployment, " +
			"StatefulSet, ReplicaSet, DaemonSet: ready/desired; Node: Ready/NotReady; Job: Complete/Failed/Running; " +
			"others: the Ready condition, else the first False condition, else status.phase). One page per call: " +
			"limit defaults to 100 and is capped at 200; when more objects exist truncated=true and continue holds " +
			"the token for the next page (total is the server's estimate). namespace is ignored for cluster-scoped " +
			"kinds. Secrets are refused (kind Secret, secrets, any alias). Read-only: never creates, changes or deletes anything.",
	}, server.CapRead, listResources)
}

func listResources(ctx context.Context, f kube.Factory, in listIn) (any, error) {
	if in.Limit < 0 {
		return nil, fmt.Errorf("limit must not be negative")
	}
	limit := in.Limit
	if limit == 0 {
		limit = defaultListLimit
	}
	limit = min(limit, limits.Default().MaxItems)

	c, err := clientFor(f, in.Context)
	if err != nil {
		return nil, err
	}
	r, err := resolveReadable(ctx, c, in.Kind, in.Group, in.Version)
	if err != nil {
		return nil, err
	}
	ns, _ := namespaceFor(r, in.Namespace, false)
	lr, err := c.List(ctx, r, ns, kube.ListOptions{
		LabelSelector: in.LabelSelector,
		FieldSelector: in.FieldSelector,
		Limit:         int64(limit),
		Continue:      in.Continue,
	})
	if err != nil {
		return nil, err
	}

	out := listOut{Resource: r.String(), Kind: r.Kind, Namespaced: r.Namespaced, Limit: limit, Items: []listRow{}, Continue: lr.Continue}
	items := lr.Items
	if len(items) > limit { // a server that ignored the limit
		items = items[:limit]
		out.Truncated = true
	}
	now := time.Now()
	for _, obj := range items {
		if objectIsSecret(obj) {
			return nil, errSecretRefused
		}
		obj = redact.Workload(obj)
		row := listRow{Name: str(obj, "metadata", "name"), Age: age(str(obj, "metadata", "creationTimestamp"), now), Status: rowStatus(r, obj)}
		if r.Namespaced {
			row.Namespace = str(obj, "metadata", "namespace")
		}
		out.Items = append(out.Items, row)
	}
	if lr.Continue != "" {
		out.Truncated = true
	}
	if lr.RemainingItemCount != nil {
		total := int64(len(lr.Items)) + *lr.RemainingItemCount
		out.Total = &total
	}
	if out.Truncated {
		out.Note = limits.Note(fmt.Sprintf("more than %d objects match", limit),
			"the continue token for the next page, a namespace, or a label or field selector")
	}
	return out, nil
}

// age renders the time since an RFC 3339 timestamp like kubectl: 45s, 12m,
// 5h, 3d. Empty when the timestamp is missing or unparseable.
func age(ts string, now time.Time) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ""
	}
	d := max(now.Sub(t), 0)
	switch {
	case d < 2*time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < 2*time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// rowStatus derives the short status of a list row.
func rowStatus(r kube.Resource, obj map[string]any) string {
	switch {
	case r.Group == "" && r.Kind == "Pod":
		return podStatus(obj)
	case r.Group == "" && r.Kind == "Node":
		return nodeStatus(obj)
	case r.Group == "apps" && (r.Kind == "Deployment" || r.Kind == "StatefulSet" || r.Kind == "ReplicaSet"):
		ready, _ := num(obj, "status", "readyReplicas")
		desired, ok := num(obj, "spec", "replicas")
		if !ok {
			desired = 1 // the API default
		}
		return fmt.Sprintf("%d/%d ready", ready, desired)
	case r.Group == "apps" && r.Kind == "DaemonSet":
		ready, _ := num(obj, "status", "numberReady")
		desired, _ := num(obj, "status", "desiredNumberScheduled")
		return fmt.Sprintf("%d/%d ready", ready, desired)
	case r.Group == "batch" && r.Kind == "Job":
		for _, t := range []string{"Failed", "Complete"} {
			if c := condition(obj, t); c != nil && c["status"] == "True" {
				return t
			}
		}
		return "Running"
	}
	return genericStatus(obj)
}

// podStatus is "<phase or reason> ready/total", where the reason is the
// pod's status.reason (e.g. Evicted) or the first container waiting or
// terminated reason (e.g. CrashLoopBackOff), like kubectl's STATUS column.
func podStatus(obj map[string]any) string {
	status := str(obj, "status", "phase")
	if s := str(obj, "status", "reason"); s != "" {
		status = s
	}
	statuses := list(obj, "status", "containerStatuses")
	ready := 0
	reason := ""
	for _, cs := range statuses {
		m := asMap(cs)
		if m["ready"] == true {
			ready++
		}
		if reason == "" {
			reason = str(m, "state", "waiting", "reason")
		}
		if reason == "" {
			reason = str(m, "state", "terminated", "reason")
		}
	}
	if reason != "" {
		status = reason
	}
	if str(obj, "metadata", "deletionTimestamp") != "" {
		status = "Terminating"
	}
	total := len(list(obj, "spec", "containers"))
	if total == 0 {
		total = len(statuses)
	}
	if status == "" {
		status = "Unknown"
	}
	return fmt.Sprintf("%s %d/%d", status, ready, total)
}

func nodeStatus(obj map[string]any) string {
	s := "NotReady"
	if c := condition(obj, "Ready"); c != nil && c["status"] == "True" {
		s = "Ready"
	}
	if nested(obj, "spec", "unschedulable") == true {
		s += ",SchedulingDisabled"
	}
	return s
}

// genericStatus is the Ready condition, else the first False condition,
// else status.phase.
func genericStatus(obj map[string]any) string {
	cond := condition(obj, "Ready")
	if cond == nil {
		for _, c := range list(obj, "status", "conditions") {
			if m := asMap(c); m["status"] == "False" {
				cond = m
				break
			}
		}
	}
	if cond != nil {
		s := fmt.Sprintf("%s=%s", str(cond, "type"), str(cond, "status"))
		if reason := str(cond, "reason"); reason != "" && cond["status"] != "True" {
			s += ": " + reason
		}
		return s
	}
	return strings.TrimSpace(str(obj, "status", "phase"))
}

// condition returns status.conditions[type=t], or nil.
func condition(obj map[string]any, t string) map[string]any {
	for _, c := range list(obj, "status", "conditions") {
		if m := asMap(c); m["type"] == t {
			return m
		}
	}
	return nil
}

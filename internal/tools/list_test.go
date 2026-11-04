package tools_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/limits"
	"github.com/astawiany/k8s-mcp/internal/server/servertest"
)

type listRow struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Age       string `json:"age"`
	Status    string `json:"status"`
}

type listOut struct {
	Resource   string    `json:"resource"`
	Kind       string    `json:"kind"`
	Namespaced bool      `json:"namespaced"`
	Items      []listRow `json:"items"`
	Continue   string    `json:"continue"`
	Truncated  bool      `json:"truncated"`
	Total      *int64    `json:"total"`
	Note       string    `json:"note"`
	Limit      int       `json:"limit"`
}

// pod returns a Running pod with one ready container named app.
func pod(ns, name string) map[string]any {
	o := kube.Object("v1", "Pod", ns, name)
	o["metadata"].(map[string]any)["creationTimestamp"] = "2026-01-01T00:00:00Z"
	o["spec"] = map[string]any{"containers": []any{map[string]any{"name": "app", "image": "registry.example/app:1"}}}
	o["status"] = map[string]any{
		"phase":             "Running",
		"containerStatuses": []any{map[string]any{"name": "app", "ready": true}},
	}
	return o
}

func crashingPod(ns, name string) map[string]any {
	o := pod(ns, name)
	o["status"] = map[string]any{
		"phase": "Running",
		"containerStatuses": []any{map[string]any{"name": "app", "ready": false,
			"state": map[string]any{"waiting": map[string]any{"reason": "CrashLoopBackOff", "message": "back-off"}}}},
	}
	return o
}

func rowsByName(rows []listRow) map[string]listRow {
	m := map[string]listRow{}
	for _, r := range rows {
		m[r.Namespace+"/"+r.Name] = r
	}
	return m
}

func TestListPodsNamespaceScopeAndStatus(t *testing.T) {
	fc := kube.NewFakeClient(pod("a", "web-1"), crashingPod("a", "web-2"), pod("b", "api-1"))
	var out listOut
	decode(t, callTool(t, kube.SingleFakeFactory(fc), "list_resources", map[string]any{"kind": "po", "namespace": "a"}), &out)
	if out.Resource != "pods" || out.Kind != "Pod" || !out.Namespaced {
		t.Errorf("resource info: %+v", out)
	}
	if len(out.Items) != 2 {
		t.Fatalf("namespace a: want 2 rows, got %+v", out.Items)
	}
	rows := rowsByName(out.Items)
	if r := rows["a/web-1"]; r.Status != "Running 1/1" || r.Age == "" {
		t.Errorf("web-1 row: %+v", r)
	}
	if r := rows["a/web-2"]; r.Status != "CrashLoopBackOff 0/1" {
		t.Errorf("web-2 row: %+v", r)
	}
	if out.Truncated || out.Continue != "" {
		t.Errorf("small list must not be truncated: %+v", out)
	}

	decode(t, callTool(t, kube.SingleFakeFactory(fc), "list_resources", map[string]any{"kind": "pods"}), &out)
	if len(out.Items) != 3 {
		t.Errorf("all namespaces: want 3 rows, got %+v", out.Items)
	}
}

func TestListWorkloadAndNodeStatus(t *testing.T) {
	dep := kube.Object("apps/v1", "Deployment", "a", "web")
	dep["spec"] = map[string]any{"replicas": 3}
	dep["status"] = map[string]any{"readyReplicas": 2, "replicas": 3}
	n1 := kube.Object("v1", "Node", "", "n1")
	n1["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}
	n2 := kube.Object("v1", "Node", "", "n2")
	n2["spec"] = map[string]any{"unschedulable": true}
	n2["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "False"}}}
	job := kube.Object("batch/v1", "Job", "a", "migrate")
	job["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Failed", "status": "True", "reason": "BackoffLimitExceeded"}}}
	ks := kube.Object("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "apps")
	ks["status"] = map[string]any{"conditions": []any{
		map[string]any{"type": "Reconciling", "status": "True"},
		map[string]any{"type": "Ready", "status": "False", "reason": "BuildFailed", "message": "kustomize build failed"},
	}}
	f := kube.SingleFakeFactory(kube.NewFakeClient(dep, n1, n2, job, ks))

	var out listOut
	decode(t, callTool(t, f, "list_resources", map[string]any{"kind": "Deployment", "group": "apps"}), &out)
	if len(out.Items) != 1 || out.Items[0].Status != "2/3 ready" {
		t.Errorf("deployment: %+v", out.Items)
	}

	// Nodes are cluster-scoped: the namespace is ignored, rows have none.
	out = listOut{}
	decode(t, callTool(t, f, "list_resources", map[string]any{"kind": "nodes", "namespace": "kube-system"}), &out)
	if out.Namespaced || len(out.Items) != 2 {
		t.Fatalf("nodes: %+v", out)
	}
	rows := rowsByName(out.Items)
	if rows["/n1"].Status != "Ready" || rows["/n2"].Status != "NotReady,SchedulingDisabled" {
		t.Errorf("node rows: %+v", out.Items)
	}

	decode(t, callTool(t, f, "list_resources", map[string]any{"kind": "jobs"}), &out)
	if len(out.Items) != 1 || out.Items[0].Status != "Failed" {
		t.Errorf("job: %+v", out.Items)
	}

	decode(t, callTool(t, f, "list_resources", map[string]any{"kind": "ks"}), &out)
	if len(out.Items) != 1 || out.Items[0].Status != "Ready=False: BuildFailed" {
		t.Errorf("kustomization: %+v", out.Items)
	}
}

func TestListSelectors(t *testing.T) {
	fc := kube.NewFakeClient(
		kube.WithLabels(pod("a", "web-1"), map[string]string{"app": "web"}),
		kube.WithLabels(pod("a", "api-1"), map[string]string{"app": "api"}),
	)
	var out listOut
	decode(t, callTool(t, kube.SingleFakeFactory(fc), "list_resources", map[string]any{"kind": "pods", "labelSelector": "app=web"}), &out)
	if len(out.Items) != 1 || out.Items[0].Name != "web-1" {
		t.Errorf("label selector: %+v", out.Items)
	}
	decode(t, callTool(t, kube.SingleFakeFactory(fc), "list_resources", map[string]any{"kind": "pods", "fieldSelector": "metadata.name=api-1"}), &out)
	if len(out.Items) != 1 || out.Items[0].Name != "api-1" {
		t.Errorf("field selector: %+v", out.Items)
	}
}

func TestListCapsTenThousandPods(t *testing.T) {
	var pods []map[string]any
	for i := 0; i < 10000; i++ {
		pods = append(pods, pod("load", fmt.Sprintf("p%05d", i)))
	}
	f := kube.SingleFakeFactory(kube.NewFakeClient(pods...))
	maxItems := limits.Default().MaxItems

	var out listOut
	decode(t, callTool(t, f, "list_resources", map[string]any{"kind": "pods"}), &out)
	if len(out.Items) != 100 || out.Limit != 100 {
		t.Errorf("default limit: want 100 rows, got %d (limit %d)", len(out.Items), out.Limit)
	}
	if out.Continue == "" || !out.Truncated || !strings.Contains(out.Note, "truncated") {
		t.Errorf("want continue token, truncated and a note: %+v", out)
	}
	if out.Total == nil || *out.Total != 10000 {
		t.Errorf("total: %v", out.Total)
	}

	decode(t, callTool(t, f, "list_resources", map[string]any{"kind": "pods", "limit": 1000000}), &out)
	if len(out.Items) > maxItems || out.Limit != maxItems {
		t.Errorf("huge limit: want at most %d rows, got %d (limit %d)", maxItems, len(out.Items), out.Limit)
	}
	if out.Continue == "" || !out.Truncated {
		t.Errorf("huge limit: want continue and truncated: %+v", out.Continue)
	}

	// The continue token resumes where the page ended.
	decode(t, callTool(t, f, "list_resources", map[string]any{"kind": "pods", "limit": 10}), &out)
	var next listOut
	decode(t, callTool(t, f, "list_resources", map[string]any{"kind": "pods", "limit": 10, "continue": out.Continue}), &next)
	if len(next.Items) != 10 || next.Items[0].Name != "p00010" {
		t.Errorf("second page: %+v", next.Items)
	}
}

func TestListRejectsNegativeLimit(t *testing.T) {
	res := callTool(t, kube.SingleFakeFactory(kube.NewFakeClient()), "list_resources", map[string]any{"kind": "pods", "limit": -1})
	if !res.IsError {
		t.Fatal("want tool error")
	}
}

func TestListUnknownKindSuggests(t *testing.T) {
	res := callTool(t, kube.SingleFakeFactory(kube.NewFakeClient()), "list_resources", map[string]any{"kind": "deploymnts"})
	text := servertest.Text(t, res)
	if !res.IsError || !strings.Contains(text, "deployments.apps") || !strings.Contains(text, "kind not found") {
		t.Errorf("want kind-not-found error with close matches:\n%s", text)
	}
}

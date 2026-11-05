package tools_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/server/servertest"
)

type topRow struct {
	Name                    string   `json:"name"`
	Namespace               string   `json:"namespace"`
	CPU                     string   `json:"cpu"`
	Memory                  string   `json:"memory"`
	CPUMillicores           int64    `json:"cpuMillicores"`
	MemoryBytes             int64    `json:"memoryBytes"`
	CPUPercentOfRequests    *float64 `json:"cpuPercentOfRequests"`
	MemoryPercentOfRequests *float64 `json:"memoryPercentOfRequests"`
}

type topOut struct {
	Scope     string   `json:"scope"`
	Available bool     `json:"available"`
	Message   string   `json:"message"`
	Rows      []topRow `json:"rows"`
	Total     int      `json:"total"`
	Truncated bool     `json:"truncated"`
	Note      string   `json:"note"`
}

func top(t *testing.T, fc *kube.FakeClient, args map[string]any) topOut {
	t.Helper()
	var out topOut
	decode(t, callTool(t, kube.SingleFakeFactory(fc), "top", args), &out)
	return out
}

func TestTopMetricsUnavailableIsAResult(t *testing.T) {
	for _, scope := range []string{"nodes", "pods"} {
		res := callTool(t, kube.SingleFakeFactory(kube.NewFakeClient().SetMetricsUnavailable()), "top", map[string]any{"scope": scope})
		if res.IsError {
			t.Fatalf("%s: want a normal result, got error %s", scope, servertest.Text(t, res))
		}
		var out topOut
		decode(t, res, &out)
		if out.Available || !strings.Contains(out.Message, "metrics-server") || len(out.Rows) != 0 {
			t.Errorf("%s: %+v", scope, out)
		}
	}
}

func TestTopRejectsBadScope(t *testing.T) {
	for _, args := range []map[string]any{{}, {"scope": "containers"}} {
		if res := callTool(t, kube.SingleFakeFactory(kube.NewFakeClient()), "top", args); !res.IsError {
			t.Errorf("%v: want an error", args)
		}
	}
}

func TestTopNodes(t *testing.T) {
	fc := kube.NewFakeClient().SetNodeMetrics(
		kube.NodeMetric("n1", "250m", "1Gi"),
		kube.NodeMetric("n2", "2", "512Mi"),
	)
	out := top(t, fc, map[string]any{"scope": "nodes"})
	if !out.Available || out.Total != 2 || len(out.Rows) != 2 || out.Truncated {
		t.Fatalf("%+v", out)
	}
	r := out.Rows[0]
	if r.Name != "n2" || r.CPUMillicores != 2000 || r.MemoryBytes != 512<<20 || r.CPU != "2000m" || r.Memory != "512Mi" {
		t.Errorf("row 0 (highest cpu first): %+v", r)
	}
	if out.Rows[1].Name != "n1" || out.Rows[1].MemoryBytes != 1<<30 {
		t.Errorf("row 1: %+v", out.Rows[1])
	}
}

func TestTopPodsPercentOfRequests(t *testing.T) {
	fc := kube.NewFakeClient(
		testPod("a", "web", [3]string{"app", "100m", "128Mi"}, [3]string{"side", "100m", "64Mi"}),
		testPod("a", "batch", [3]string{"job", "", ""}),
		testPod("a", "half", [3]string{"x", "200m", ""}, [3]string{"y", "", "1Gi"}),
	).SetPodMetrics(
		kube.PodMetric("a", "web", map[string][2]string{"app": {"50m", "64Mi"}, "side": {"50m", "32Mi"}}),
		kube.PodMetric("a", "batch", map[string][2]string{"job": {"10m", "8Mi"}}),
		kube.PodMetric("a", "half", map[string][2]string{"x": {"20m", "1Mi"}, "y": {"1m", "1Mi"}}),
		kube.PodMetric("b", "other", map[string][2]string{"c": {"999m", "1Mi"}}),
	)
	out := top(t, fc, map[string]any{"scope": "pods", "namespace": "a"})
	if !out.Available || out.Total != 3 || len(out.Rows) != 3 {
		t.Fatalf("%+v", out)
	}
	rows := map[string]topRow{}
	for _, r := range out.Rows {
		rows[r.Name] = r
	}
	web := rows["web"]
	if web.CPUMillicores != 100 || web.MemoryBytes != 96<<20 || web.Namespace != "a" {
		t.Errorf("web usage: %+v", web)
	}
	if web.CPUPercentOfRequests == nil || *web.CPUPercentOfRequests != 50 ||
		web.MemoryPercentOfRequests == nil || *web.MemoryPercentOfRequests != 50 {
		t.Errorf("web percent of requests: %+v", web)
	}
	if b := rows["batch"]; b.CPUPercentOfRequests != nil || b.MemoryPercentOfRequests != nil {
		t.Errorf("batch has no requests, want no percent: %+v", b)
	}
	// Requests are known only when every container sets them.
	if h := rows["half"]; h.CPUPercentOfRequests != nil || h.MemoryPercentOfRequests != nil {
		t.Errorf("half has partial requests, want no percent: %+v", h)
	}
}

func TestTopPodsWithoutPodReadStillReportsUsage(t *testing.T) {
	fc := kube.NewFakeClient(testPod("a", "web", [3]string{"app", "100m", "128Mi"})).
		SetPodMetrics(kube.PodMetric("a", "web", map[string][2]string{"app": {"50m", "64Mi"}})).
		FailOn("List", "pods", kube.NewAPIError(kube.ErrForbidden, "list", "pods", "a", "", "forbidden"))
	out := top(t, fc, map[string]any{"scope": "pods", "namespace": "a"})
	if len(out.Rows) != 1 || out.Rows[0].CPUMillicores != 50 || out.Rows[0].CPUPercentOfRequests != nil || out.Note == "" {
		t.Errorf("want usage without percent and a note: %+v", out)
	}
}

func TestTopPodsCapAndSort(t *testing.T) {
	var ms []map[string]any
	for i := range 250 {
		ms = append(ms, kube.PodMetric("a", fmt.Sprintf("p%03d", i), map[string][2]string{"c": {fmt.Sprintf("%dm", i+1), "1Mi"}}))
	}
	out := top(t, kube.NewFakeClient().SetPodMetrics(ms...), map[string]any{"scope": "pods"})
	if len(out.Rows) != 200 || out.Total != 250 || !out.Truncated || out.Note == "" {
		t.Fatalf("cap: %d rows, total %d, truncated %v", len(out.Rows), out.Total, out.Truncated)
	}
	if out.Rows[0].Name != "p249" || out.Rows[0].CPUMillicores != 250 || out.Rows[199].Name != "p050" {
		t.Errorf("want highest cpu first: first %+v last %+v", out.Rows[0], out.Rows[199])
	}
	for i := 1; i < len(out.Rows); i++ {
		if out.Rows[i].CPUMillicores > out.Rows[i-1].CPUMillicores {
			t.Fatalf("not sorted by cpu desc at %d", i)
		}
	}
}

// TestTopPodsRequestReadIsBounded: pod specs are read for at most 20 pages of
// 500; beyond that the percentages are partial and the note says so.
func TestTopPodsRequestReadIsBounded(t *testing.T) {
	var pods []map[string]any
	for i := 0; i < 10001; i++ {
		pods = append(pods, testPod("a", fmt.Sprintf("p%05d", i), [3]string{"app", "100m", "128Mi"}))
	}
	fc := kube.NewFakeClient(pods...).SetPodMetrics(
		kube.PodMetric("a", "p00000", map[string][2]string{"app": {"50m", "64Mi"}}),
		kube.PodMetric("a", "p10000", map[string][2]string{"app": {"50m", "64Mi"}}),
	)
	out := top(t, fc, map[string]any{"scope": "pods"})
	rows := map[string]topRow{}
	for _, r := range out.Rows {
		rows[r.Name] = r
	}
	if rows["p00000"].CPUPercentOfRequests == nil {
		t.Errorf("first page pod has no percent: %+v", rows["p00000"])
	}
	if rows["p10000"].CPUPercentOfRequests != nil {
		t.Errorf("pod beyond the page cap has a percent: %+v", rows["p10000"])
	}
	if !strings.Contains(out.Note, "partial") {
		t.Errorf("note does not say percentages are partial: %q", out.Note)
	}
}

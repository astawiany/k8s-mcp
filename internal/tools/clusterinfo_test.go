package tools_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/server/servertest"
)

func node(name, ready string) map[string]any {
	return map[string]any{
		"apiVersion": "v1", "kind": "Node",
		"metadata": map[string]any{"name": name},
		"status": map[string]any{"conditions": []any{
			map[string]any{"type": "MemoryPressure", "status": "False"},
			map[string]any{"type": "Ready", "status": ready},
		}},
	}
}

type clusterInfoOut struct {
	Context       string `json:"context"`
	ServerVersion string `json:"serverVersion"`
	Nodes         struct {
		Total    int      `json:"total"`
		Ready    int      `json:"ready"`
		NotReady []string `json:"notReady"`
	} `json:"nodes"`
	APIGroups struct {
		Metrics    bool `json:"metrics"`
		Flux       bool `json:"flux"`
		GatewayAPI bool `json:"gatewayAPI"`
	} `json:"apiGroups"`
}

func TestClusterInfoNodesAndGroups(t *testing.T) {
	fc := kube.NewFakeClient(node("n1", "True"), node("n2", "False"), node("n3", "Unknown")).
		SetServerVersion("v1.30.1").
		SetAPIGroups("v1", "apps/v1", "metrics.k8s.io/v1beta1", "kustomize.toolkit.fluxcd.io/v1", "gateway.networking.k8s.io/v1")
	var out clusterInfoOut
	decode(t, callTool(t, kube.SingleFakeFactory(fc), "cluster_info", map[string]any{}), &out)
	if out.Context != "fake" || out.ServerVersion != "v1.30.1" {
		t.Errorf("context/version: %+v", out)
	}
	if out.Nodes.Total != 3 || out.Nodes.Ready != 1 || !reflect.DeepEqual(out.Nodes.NotReady, []string{"n2", "n3"}) {
		t.Errorf("nodes: %+v", out.Nodes)
	}
	if !out.APIGroups.Metrics || !out.APIGroups.Flux || !out.APIGroups.GatewayAPI {
		t.Errorf("apiGroups: %+v", out.APIGroups)
	}
}

func TestClusterInfoWithoutOptionalGroups(t *testing.T) {
	fc := kube.NewFakeClient(node("n1", "True")).SetAPIGroups("v1", "apps/v1")
	var out clusterInfoOut
	decode(t, callTool(t, kube.SingleFakeFactory(fc), "cluster_info", map[string]any{}), &out)
	if out.APIGroups.Metrics || out.APIGroups.Flux || out.APIGroups.GatewayAPI {
		t.Errorf("want all false, got %+v", out.APIGroups)
	}
	if out.Nodes.NotReady == nil || len(out.Nodes.NotReady) != 0 {
		t.Errorf("notReady must be an empty list, got %#v", out.Nodes.NotReady)
	}
}

func TestClusterInfoDisallowedContext(t *testing.T) {
	f := kube.NewFakeFactory("dev", map[string]*kube.FakeClient{"dev": kube.NewFakeClient(), "prod": kube.NewFakeClient()})
	f.Allow = kube.MustParseAllowlist("dev")
	res := callTool(t, f, "cluster_info", map[string]any{"context": "prod"})
	if !res.IsError {
		t.Fatal("want a tool error")
	}
	text := servertest.Text(t, res)
	if !strings.Contains(text, "--contexts") {
		t.Errorf("error must name the --contexts flag:\n%s", text)
	}
}

func TestClusterInfoNodeNameIsWrapped(t *testing.T) {
	fc := kube.NewFakeClient(node("evil\u202e\x1b[31mname", "False"))
	res := callTool(t, kube.SingleFakeFactory(fc), "cluster_info", nil)
	body := servertest.Payload(t, res)
	if strings.ContainsAny(body, "\x1b\u202e") {
		t.Errorf("control characters leaked: %q", body)
	}
}

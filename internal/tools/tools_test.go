package tools_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/server"
	"github.com/astawiany/k8s-mcp/internal/server/servertest"
	"github.com/astawiany/k8s-mcp/internal/tools"
)

// callTool runs a tool through an in-memory MCP session with all tools registered.
func callTool(t *testing.T, f kube.Factory, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	cs := servertest.NewTestSession(t, f, tools.RegisterAll)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	return res
}

// decode unmarshals the envelope payload of a successful result into v.
func decode(t *testing.T, res *mcp.CallToolResult, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(servertest.Payload(t, res)), v); err != nil {
		t.Fatalf("payload is not the expected JSON: %v", err)
	}
}

func TestRegisterAllUsesReadCapOnly(t *testing.T) {
	s := server.New(kube.SingleFakeFactory(kube.NewFakeClient()), server.Options{Version: "test"})
	tools.RegisterAll(s)
	for _, sp := range s.Tools() {
		if sp.Cap != server.CapRead {
			t.Errorf("tool %s has capability %q", sp.Name, sp.Cap)
		}
	}
}

// TestTruncatedIsAlwaysPresent: every list-like tool returns "truncated",
// false included, so models and scripts can rely on the field.
func TestTruncatedIsAlwaysPresent(t *testing.T) {
	cases := []struct {
		tool string
		args map[string]any
		objs []map[string]any
		want string
	}{
		{"cluster_info", nil, []map[string]any{node("n1", "True")}, `"truncated":false`},
		{"workload_health", map[string]any{"namespace": "app", "kind": "Deployment", "name": "web"},
			[]map[string]any{hDeploy(1, 1), hRS("web-1", 1), hPod("web-1-a", "web-1", "Running", true, nil, nil)}, `"truncated":false`},
		{"flux_status", nil, []map[string]any{fObj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "f", "k", true, "ok", "", nil)}, `"truncated":false`},
	}
	for _, c := range cases {
		body := servertest.Payload(t, callTool(t, kube.SingleFakeFactory(kube.NewFakeClient(c.objs...)), c.tool, c.args))
		if !strings.Contains(body, c.want) {
			t.Errorf("%s: %s missing in %s", c.tool, c.want, body)
		}
	}
}

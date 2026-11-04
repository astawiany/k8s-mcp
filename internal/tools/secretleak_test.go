package tools_test

import (
	"context"
	"strings"
	"testing"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/server/servertest"
)

// leakyClient serves Secret objects under a resource that does not look like
// Secrets (as a misbehaving aggregated API or CRD might), so the resolve-time
// check passes and only the checks on what was read can refuse.
type leakyClient struct{ *kube.FakeClient }

func (c leakyClient) Get(ctx context.Context, r kube.Resource, ns, name string) (map[string]any, error) {
	return seededSecret(), nil
}

func (c leakyClient) List(ctx context.Context, r kube.Resource, ns string, o kube.ListOptions) (kube.ListResult, error) {
	return kube.ListResult{Items: []map[string]any{pod("default", "ok"), seededSecret()}}, nil
}

type leakyFactory struct{ c kube.Client }

func (f leakyFactory) Contexts() []kube.ContextInfo {
	return []kube.ContextInfo{{Name: "fake", Current: true, Allowed: true}}
}
func (f leakyFactory) For(string) (kube.Client, error) { return f.c, nil }

func TestSecretReadUnderOtherKindIsRefused(t *testing.T) {
	f := leakyFactory{leakyClient{kube.NewFakeClient()}}
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"get_resource", map[string]any{"kind": "configmaps", "namespace": "default", "name": "db"}},
		{"describe_resource", map[string]any{"kind": "configmaps", "namespace": "default", "name": "db"}},
		{"list_resources", map[string]any{"kind": "configmaps", "namespace": "default"}},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			res := callTool(t, f, tc.tool, tc.args)
			text := servertest.Text(t, res)
			if !res.IsError || !strings.Contains(text, "refused") {
				t.Errorf("want a Secret refusal:\n%s", text)
			}
		})
	}
}

package tools_test

import (
	"strings"
	"testing"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/server/servertest"
)

// secretValue is the base64 data of the seeded Secret; it must never appear
// in any output.
const secretValue = "c3VwZXJzZWNyZXQtdmFsdWU="

func seededSecret() map[string]any {
	s := kube.Object("v1", "Secret", "default", "db")
	s["type"] = "Opaque"
	s["data"] = map[string]any{"password": secretValue}
	return s
}

// TestSecretRefusedByEveryTool asks each of the four object tools for Secrets
// under every spelling a model might use. Each call must be a tool error that
// says why, must not read Secrets from the cluster, and must not leak data.
func TestSecretRefusedByEveryTool(t *testing.T) {
	spellings := []struct {
		name                 string
		kind, group, version string
	}{
		{"Kind", "Secret", "", ""},
		{"singular", "secret", "", ""},
		{"plural", "secrets", "", ""},
		{"upper", "SECRETS", "", ""},
		{"core group", "Secret", "core", ""},
		{"core group and version", "secrets", "", "v1"},
		{"short name", "scrt", "", ""},
		{"resource.group form", "secrets.", "", ""},
		{"padded", "  Secret ", "", ""},
	}
	for _, tool := range []string{"list_resources", "get_resource", "describe_resource", "get_events"} {
		for _, sp := range spellings {
			t.Run(tool+"/"+sp.name, func(t *testing.T) {
				fc := kube.NewFakeClient(seededSecret()).AddResources(kube.ResourceInfo{
					Resource:   kube.Resource{Version: "v1", Resource: "secrets", Kind: "Secret", Namespaced: true},
					Singular:   "secret",
					ShortNames: []string{"scrt"},
					Verbs:      []string{"get", "list"},
					Preferred:  true,
				})
				args := map[string]any{"kind": sp.kind, "namespace": "default", "name": "db"}
				if sp.group != "" {
					args["group"] = sp.group
				}
				if sp.version != "" {
					args["version"] = sp.version
				}
				if tool == "list_resources" {
					delete(args, "name")
				}
				if tool == "get_events" {
					args = map[string]any{"involvedKind": sp.kind, "involvedName": "db", "namespace": "default"}
				}
				res := callTool(t, kube.SingleFakeFactory(fc), tool, args)
				text := servertest.Text(t, res)
				if !res.IsError {
					t.Fatalf("want a tool error, got:\n%s", text)
				}
				if !strings.Contains(text, "Secret") || !strings.Contains(text, "refused") {
					t.Errorf("error must say that Secrets are refused:\n%s", text)
				}
				if strings.Contains(text, secretValue) {
					t.Errorf("Secret data leaked:\n%s", text)
				}
				for _, c := range fc.Calls() {
					if strings.HasPrefix(c, "List") || strings.HasPrefix(c, "Get") || strings.HasPrefix(c, "Events") {
						t.Errorf("refused request still read the cluster: %q", c)
					}
				}
			})
		}
	}
}

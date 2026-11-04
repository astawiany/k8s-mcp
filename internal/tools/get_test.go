package tools_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/server/servertest"
)

// sensitivePod has a credential-named env var and an Authorization probe
// header, neither of which has a token shape (so only redact.PodSpec, not
// the wrapper's backstop, can hide them), plus managedFields.
func sensitivePod() map[string]any {
	o := pod("a", "web-1")
	o["metadata"].(map[string]any)["managedFields"] = []any{map[string]any{"manager": "kubectl", "operation": "Apply"}}
	o["spec"] = map[string]any{"containers": []any{map[string]any{
		"name":  "app",
		"image": "registry.example/app:1",
		"env": []any{
			map[string]any{"name": "API_TOKEN", "value": "plain-opaque-value-1"},
			map[string]any{"name": "LOG_LEVEL", "value": "debug"},
		},
		"livenessProbe": map[string]any{"httpGet": map[string]any{
			"path": "/healthz", "port": 8080,
			"httpHeaders": []any{map[string]any{"name": "Authorization", "value": "Bearer opaque-header-2"}},
		}},
	}}}
	return o
}

func TestGetPodMasksEnvAndProbeHeaders(t *testing.T) {
	f := kube.SingleFakeFactory(kube.NewFakeClient(sensitivePod()))
	res := callTool(t, f, "get_resource", map[string]any{"kind": "pod", "namespace": "a", "name": "web-1"})
	body := servertest.Payload(t, res)
	for _, leak := range []string{"plain-opaque-value-1", "opaque-header-2", "managedFields"} {
		if strings.Contains(body, leak) {
			t.Errorf("%q leaked:\n%s", leak, body)
		}
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		t.Fatal(err)
	}
	env := obj["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["env"].([]any)
	if v := env[0].(map[string]any)["value"]; v != "[redacted]" {
		t.Errorf("API_TOKEN: %v", v)
	}
	if v := env[1].(map[string]any)["value"]; v != "debug" {
		t.Errorf("LOG_LEVEL must be kept: %v", v)
	}
	if st, _ := obj["status"].(map[string]any); st["phase"] != "Running" {
		t.Errorf("status must be kept: %v", obj["status"])
	}
}

func TestGetDeploymentWithEmbeddedSecretManifest(t *testing.T) {
	embedded := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"db","namespace":"a"},"data":{"password":"` + secretValue + `"}}`
	dep := kube.Object("apps/v1", "Deployment", "a", "web")
	dep["metadata"].(map[string]any)["annotations"] = map[string]any{
		"kubectl.kubernetes.io/last-applied-configuration": `{"apiVersion":"v1","kind":"List","items":[` + embedded + `]}`,
		"example.com/raw": "apiVersion: v1\nkind: Secret\ndata:\n  password: " + secretValue + "\n",
	}
	dep["spec"] = map[string]any{"replicas": 1, "template": map[string]any{"spec": map[string]any{"containers": []any{
		map[string]any{"name": "app", "env": []any{map[string]any{"name": "DB_PASSWORD", "value": "hunter2-plain"}}},
	}}}}
	f := kube.SingleFakeFactory(kube.NewFakeClient(dep))
	body := servertest.Payload(t, callTool(t, f, "get_resource", map[string]any{"kind": "deploy", "namespace": "a", "name": "web"}))
	for _, leak := range []string{secretValue, "c3VwZXJzZWNyZXQ", "hunter2-plain"} {
		if strings.Contains(body, leak) {
			t.Errorf("%q leaked:\n%s", leak, body)
		}
	}
	if !strings.Contains(body, `"kind":"Deployment"`) {
		t.Errorf("object missing:\n%s", body)
	}
}

func TestGetNotFound(t *testing.T) {
	res := callTool(t, kube.SingleFakeFactory(kube.NewFakeClient()), "get_resource", map[string]any{"kind": "pods", "namespace": "a", "name": "nope"})
	text := servertest.Text(t, res)
	if !res.IsError || !strings.Contains(text, "error: not found") {
		t.Errorf("want a not-found tool error:\n%s", text)
	}
}

func TestGetNamespacedNeedsNamespace(t *testing.T) {
	res := callTool(t, kube.SingleFakeFactory(kube.NewFakeClient(pod("a", "web-1"))), "get_resource", map[string]any{"kind": "pods", "name": "web-1"})
	if text := servertest.Text(t, res); !res.IsError || !strings.Contains(text, "namespace") {
		t.Errorf("want an error asking for a namespace:\n%s", text)
	}
}

func TestGetClusterScopedIgnoresNamespace(t *testing.T) {
	n := kube.Object("v1", "Node", "", "n1")
	var obj map[string]any
	decode(t, callTool(t, kube.SingleFakeFactory(kube.NewFakeClient(n)), "get_resource",
		map[string]any{"kind": "node", "namespace": "kube-system", "name": "n1"}), &obj)
	if obj["kind"] != "Node" {
		t.Errorf("got %v", obj)
	}
}

func TestGetUnknownKind(t *testing.T) {
	res := callTool(t, kube.SingleFakeFactory(kube.NewFakeClient()), "get_resource", map[string]any{"kind": "deploymnt", "namespace": "a", "name": "x"})
	if text := servertest.Text(t, res); !res.IsError || !strings.Contains(text, "deployments.apps") {
		t.Errorf("want close matches:\n%s", text)
	}
}

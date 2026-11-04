// Package injection_test is test layer 1 of spec section 6.1: every payload
// of the corpus is planted in every untrusted field type of a fake cluster,
// and every tool that can return that field is called through an in-memory
// MCP session with all real tools registered.
package injection_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/limits"
	"github.com/astawiany/k8s-mcp/internal/server/servertest"
	"github.com/astawiany/k8s-mcp/internal/tools"
	"github.com/astawiany/k8s-mcp/test/injection/corpus"
)

const ns = "inj"

// Field ids. probe(f) is planted in front of the payload so a test can prove
// the field actually reached the output.
const (
	fPodLog          = "podlog"
	fEventMessage    = "eventmessage"
	fAnnotationValue = "annotationvalue"
	fAnnotationKey   = "annotationkey"
	fLabelValue      = "labelvalue"
	fResourceName    = "resourcename"
	fFluxMessage     = "fluxmessage"
	fConfigMapValue  = "configmapvalue"
	fConfigMapKey    = "configmapkey"
	fEnvValue        = "envvalue"
	fWaitingMessage  = "waitingmessage"
	fNodeName        = "nodename"
	fDraftInput      = "draftinput"
)

func probe(field string) string { return "injprobe" + field }

// plant puts the probe on both ends: cuts keep the start of a string, and a
// bare carriage return keeps only the end of a log line.
func plant(field string, p corpus.Payload) string {
	return probe(field) + " " + p.Text + " " + probe(field)
}

// plantName is plant for names: the tools trim surrounding space from names.
func plantName(field string, p corpus.Payload) string {
	return strings.TrimSpace(probe(field) + "-" + p.Text + "-" + probe(field))
}

// cluster builds a fake cluster with p planted in every field type, plus a
// Secret whose value is corpus.SecretCanary.
func cluster(p corpus.Payload) *kube.FakeClient {
	now := time.Now().UTC()
	podName := plantName(fResourceName, p)
	nodeName := plantName(fNodeName, p)
	meta := func(o map[string]any) map[string]any {
		md := o["metadata"].(map[string]any)
		md["annotations"] = map[string]any{"inj": plant(fAnnotationValue, p), plant(fAnnotationKey, p): "v"}
		return o
	}
	owned := func(o map[string]any, kind, name string) map[string]any {
		o["metadata"].(map[string]any)["ownerReferences"] = []any{map[string]any{"kind": kind, "name": name, "controller": true}}
		return o
	}

	deploy := meta(kube.WithLabels(kube.Object("apps/v1", "Deployment", ns, "web"),
		map[string]string{"app": "web", "inj": plant(fLabelValue, p)}))
	deploy["spec"] = map[string]any{"replicas": 2, "selector": map[string]any{"matchLabels": map[string]any{"app": "web"}},
		"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "x",
			"env": []any{map[string]any{"name": "INJ_VALUE", "value": plant(fEnvValue, p)}}}}}}}
	deploy["status"] = map[string]any{"replicas": 2, "readyReplicas": 1, "updatedReplicas": 2}

	rs := owned(kube.WithLabels(kube.Object("apps/v1", "ReplicaSet", ns, "web-rs"), map[string]string{"app": "web"}), "Deployment", "web")
	rs["spec"] = map[string]any{"replicas": 2}

	bad := meta(owned(kube.WithLabels(kube.Object("v1", "Pod", ns, "web-1"),
		map[string]string{"app": "web", "inj": plant(fLabelValue, p)}), "ReplicaSet", "web-rs"))
	bad["spec"] = map[string]any{"nodeName": nodeName, "containers": []any{map[string]any{"name": "app", "image": "x",
		"env": []any{map[string]any{"name": "INJ_VALUE", "value": plant(fEnvValue, p)}}}}}
	bad["status"] = map[string]any{"phase": "Pending",
		"conditions": []any{map[string]any{"type": "Ready", "status": "False"}},
		"containerStatuses": []any{map[string]any{"name": "app", "ready": false, "restartCount": 0, "image": "x",
			"state": map[string]any{"waiting": map[string]any{"reason": "CreateContainerConfigError",
				"message": plant(fWaitingMessage, p)}}}}}

	named := owned(kube.WithLabels(kube.Object("v1", "Pod", ns, podName), map[string]string{"app": "web"}), "ReplicaSet", "web-rs")
	named["spec"] = map[string]any{"containers": []any{map[string]any{"name": "app", "image": "x"}}}
	named["status"] = map[string]any{"phase": "Running",
		"conditions":        []any{map[string]any{"type": "Ready", "status": "True"}},
		"containerStatuses": []any{map[string]any{"name": "app", "ready": true, "state": map[string]any{"running": map[string]any{}}}}}

	cm := meta(kube.Object("v1", "ConfigMap", ns, "cfg"))
	cm["data"] = map[string]any{"k": plant(fConfigMapValue, p), plant(fConfigMapKey, p): "v"}

	secret := kube.Object("v1", "Secret", ns, "db-creds")
	secret["type"] = "Opaque"
	secret["data"] = map[string]any{"password": corpus.SecretCanaryBase64, "raw": corpus.SecretCanary}

	node := map[string]any{"apiVersion": "v1", "kind": "Node", "metadata": map[string]any{"name": nodeName},
		"status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "False"}}}}

	flux := func(name, msg string) map[string]any {
		o := kube.Object("kustomize.toolkit.fluxcd.io/v1", "Kustomization", ns, name)
		o["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "False",
			"reason": "ReconciliationFailed", "message": msg}}}
		return o
	}

	c := kube.NewFakeClient(deploy, rs, bad, named, cm, secret, node,
		flux("apps", plant(fFluxMessage, p)), flux(podName, "ok"),
		kube.Event(ns, "e1", "Pod", "web-1", "Warning", "Failed", plant(fEventMessage, p), now),
		kube.Event(ns, "e2", "Pod", podName, "Normal", "Pulled", "ok", now),
	)
	c.SetLogs(ns, "web-1", "app", "starting\n"+plant(fPodLog, p)+"\nready\n")
	c.SetPodMetrics(
		kube.PodMetric(ns, "web-1", map[string][2]string{"app": {"10m", "10Mi"}}),
		kube.PodMetric(ns, podName, map[string][2]string{"app": {"20m", "20Mi"}}),
	)
	return c
}

// toolCall is one call and the fields it is expected to return.
type toolCall struct {
	name   string
	tool   string
	args   map[string]any
	fields []string
	// refused: the call must be a Secret refusal.
	refused bool
}

func calls(p corpus.Payload) []toolCall {
	podName := plantName(fResourceName, p)
	obj := func(kind, name string) map[string]any {
		return map[string]any{"kind": kind, "namespace": ns, "name": name}
	}
	draftText := plant(fDraftInput, p)
	cs := []toolCall{
		{"pod_logs", "pod_logs", map[string]any{"namespace": ns, "pod": "web-1"}, []string{fPodLog}, false},
		{"get_events", "get_events", map[string]any{"namespace": ns}, []string{fEventMessage, fResourceName}, false},
		{"get_resource-pod", "get_resource", obj("Pod", "web-1"),
			[]string{fAnnotationValue, fAnnotationKey, fLabelValue, fEnvValue, fWaitingMessage, fNodeName}, false},
		{"get_resource-named-pod", "get_resource", obj("Pod", podName), []string{fResourceName}, false},
		{"get_resource-deployment", "get_resource", obj("Deployment", "web"),
			[]string{fAnnotationValue, fAnnotationKey, fLabelValue, fEnvValue}, false},
		{"get_resource-configmap", "get_resource", obj("ConfigMap", "cfg"),
			[]string{fConfigMapValue, fConfigMapKey, fAnnotationValue}, false},
		{"get_resource-kustomization", "get_resource", obj("Kustomization", "apps"), []string{fFluxMessage}, false},
		{"get_resource-node", "get_resource", map[string]any{"kind": "Node", "name": plantName(fNodeName, p)}, []string{fNodeName}, false},
		{"describe_resource-pod", "describe_resource", obj("Pod", "web-1"),
			[]string{fAnnotationValue, fAnnotationKey, fLabelValue, fEnvValue, fWaitingMessage, fNodeName, fEventMessage}, false},
		{"describe_resource-kustomization", "describe_resource", obj("Kustomization", "apps"), []string{fFluxMessage}, false},
		{"list_resources-pods", "list_resources", map[string]any{"kind": "Pod", "namespace": ns}, []string{fResourceName}, false},
		{"list_resources-nodes", "list_resources", map[string]any{"kind": "Node"}, []string{fNodeName}, false},
		{"flux_status", "flux_status", map[string]any{"namespace": ns}, []string{fFluxMessage, fResourceName}, false},
		{"workload_health", "workload_health", map[string]any{"namespace": ns, "kind": "Deployment", "name": "web"},
			[]string{fWaitingMessage, fResourceName}, false},
		{"cluster_info", "cluster_info", map[string]any{}, []string{fNodeName}, false},
		{"top-pods", "top", map[string]any{"scope": "pods", "namespace": ns}, []string{fResourceName}, false},
		{"draft_issue", "draft_issue", map[string]any{
			"title": draftText, "severity": "high", "cluster": "kind", "namespace": ns, "object": "Deployment/web",
			"summary":       draftText,
			"evidence":      []any{map[string]any{"ref": "Pod " + ns + "/web-1 logs", "quote": draftText}},
			"suggestedNext": []any{draftText},
		}, []string{fDraftInput}, false},
	}
	if p.Name == "secret-request" {
		// What a model obeying the payload would call.
		cs = append(cs,
			toolCall{"get_resource-secret", "get_resource", obj("Secret", "db-creds"), nil, true},
			toolCall{"get_resource-secret-alias", "get_resource", obj("secrets", "db-creds"), nil, true},
			toolCall{"describe_resource-secret", "describe_resource", obj("Secret", "db-creds"), nil, true},
			toolCall{"list_resources-secrets", "list_resources", map[string]any{"kind": "Secret", "namespace": ns}, nil, true},
			toolCall{"get_events-secret", "get_events", map[string]any{"namespace": ns, "involvedKind": "Secret"}, nil, true},
		)
	}
	return cs
}

// TestInjectionCorpus runs every payload x tool call and checks the output.
func TestInjectionCorpus(t *testing.T) {
	canaries := corpus.Canaries()
	for _, p := range corpus.Payloads() {
		t.Run(p.Name, func(t *testing.T) {
			t.Parallel()
			cs := servertest.NewTestSession(t, kube.SingleFakeFactory(cluster(p)), tools.RegisterAll)
			for _, c := range calls(p) {
				t.Run(c.name, func(t *testing.T) {
					res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: c.tool, Arguments: c.args})
					if err != nil {
						t.Fatalf("CallTool: %v", err)
					}
					text := checkOutput(t, res, canaries)
					if c.refused {
						if !res.IsError || !strings.Contains(text, "refused") {
							t.Errorf("Secret request was not refused:\n%.1500s", text)
						}
						return
					}
					if res.IsError {
						t.Fatalf("unexpected error result:\n%.1500s", text)
					}
					if p.Masked {
						return
					}
					for _, f := range c.fields {
						if !strings.Contains(text, probe(f)) {
							t.Errorf("field %s did not reach the output (probe %q missing); the test would not cover it:\n%.1500s",
								f, probe(f), text)
						}
					}
				})
			}
		})
	}
}

// checkOutput applies the output assertions to one result and returns its text.
func checkOutput(t *testing.T, res *mcp.CallToolResult, canaries []string) string {
	t.Helper()
	text := servertest.Text(t, res)
	if n := limits.Default().MaxBytes; len(text) > n {
		t.Errorf("output is %d bytes, cap is %d", len(text), n)
	}
	if r, i := firstDisallowed(text); i >= 0 {
		t.Errorf("raw control/invisible character %U at byte %d: %q", r, i, around(text, i))
	}
	for _, c := range canaries {
		if strings.Contains(text, c) {
			t.Errorf("canary %q appears in the output", c)
		}
	}
	env := text
	if res.IsError {
		head, rest, ok := strings.Cut(text, "detail (untrusted data, may quote the cluster):\n")
		if markerRe.MatchString(head) {
			t.Errorf("error header holds a marker: %q", head)
		}
		if !ok {
			return text // no detail at all: nothing cluster-sourced
		}
		env = rest
	}
	_, body, err := parseEnvelope(env)
	if err != nil {
		t.Errorf("not exactly one strict envelope: %v\n%.1500s", err, text)
		return text
	}
	if res.IsError {
		return text
	}
	strs, err := jsonStrings(body)
	if err != nil {
		t.Errorf("envelope body is not JSON: %v", err)
		return text
	}
	for _, s := range strs {
		if r, i := firstDisallowed(s); i >= 0 {
			t.Errorf("decoded string holds %U: %q", r, around(s, i))
		}
	}
	return text
}

func around(s string, i int) string {
	lo, hi := max(0, i-40), min(len(s), i+40)
	return s[lo:hi]
}

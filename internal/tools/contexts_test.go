package tools_test

import (
	"reflect"
	"testing"

	"github.com/astawiany/k8s-mcp/internal/kube"
)

func TestListContexts(t *testing.T) {
	f := kube.NewFakeFactory("dev", map[string]*kube.FakeClient{
		"dev": kube.NewFakeClient(), "prod": kube.NewFakeClient(),
	})
	f.Allow = kube.MustParseAllowlist("dev")
	var got []kube.ContextInfo
	decode(t, callTool(t, f, "list_contexts", map[string]any{}), &got)
	want := []kube.ContextInfo{{Name: "dev", Current: true, Allowed: true}, {Name: "prod", Allowed: false}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

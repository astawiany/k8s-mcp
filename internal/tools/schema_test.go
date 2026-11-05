package tools_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/server/servertest"
	"github.com/astawiany/k8s-mcp/internal/tools"
)

// TestToolInputSchemas pins the input schemas served over tools/list (spec
// §8 "protocol ... checks schemas"): which tools take the optional context,
// the required fields, and additionalProperties false.
func TestToolInputSchemas(t *testing.T) {
	want := map[string]struct {
		context  bool
		required []string
	}{
		"list_contexts":     {false, nil},
		"cluster_info":      {true, nil},
		"list_resources":    {true, []string{"kind"}},
		"get_resource":      {true, []string{"kind", "name"}},
		"describe_resource": {true, []string{"kind", "name"}},
		"get_events":        {true, nil},
		"pod_logs":          {true, []string{"namespace", "pod"}},
		"top":               {true, []string{"scope"}},
		"workload_health":   {true, []string{"namespace", "kind", "name"}},
		"flux_status":       {true, nil},
		"draft_issue":       {true, []string{"title", "severity", "cluster", "summary"}},
	}
	cs := servertest.NewTestSession(t, kube.SingleFakeFactory(kube.NewFakeClient()), tools.RegisterAll)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != len(want) {
		t.Fatalf("got %d tools, want %d", len(res.Tools), len(want))
	}
	for _, tl := range res.Tools {
		w, ok := want[tl.Name]
		if !ok {
			t.Errorf("unexpected tool %s", tl.Name)
			continue
		}
		raw, err := json.Marshal(tl.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		var s struct {
			Type                 string                     `json:"type"`
			Properties           map[string]json.RawMessage `json:"properties"`
			Required             []string                   `json:"required"`
			AdditionalProperties *bool                      `json:"additionalProperties"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatalf("%s: %v", tl.Name, err)
		}
		if s.Type != "object" {
			t.Errorf("%s: type %q", tl.Name, s.Type)
		}
		if s.AdditionalProperties == nil || *s.AdditionalProperties {
			t.Errorf("%s: additionalProperties must be false: %s", tl.Name, raw)
		}
		_, hasCtx := s.Properties["context"]
		if hasCtx != w.context {
			t.Errorf("%s: context property present=%v, want %v", tl.Name, hasCtx, w.context)
		}
		if slices.Contains(s.Required, "context") {
			t.Errorf("%s: context must be optional", tl.Name)
		}
		got, exp := slices.Clone(s.Required), slices.Clone(w.required)
		slices.Sort(got)
		slices.Sort(exp)
		if !slices.Equal(got, exp) {
			t.Errorf("%s: required %v, want %v", tl.Name, s.Required, w.required)
		}
	}
}

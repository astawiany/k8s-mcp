package tools_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/limits"
	"github.com/astawiany/k8s-mcp/internal/server/servertest"
)

var testNow = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

type eventRow struct {
	Type      string `json:"type"`
	Reason    string `json:"reason"`
	Message   string `json:"message"`
	Object    string `json:"object"`
	Namespace string `json:"namespace"`
	Count     int64  `json:"count"`
	FirstSeen string `json:"firstSeen"`
	LastSeen  string `json:"lastSeen"`
	Warning   bool   `json:"warning"`
}

type eventsOut struct {
	Events    []eventRow `json:"events"`
	Total     int        `json:"total"`
	Truncated bool       `json:"truncated"`
	Note      string     `json:"note"`
}

func ago(m int) time.Time { return testNow.Add(-time.Duration(m) * time.Minute) }

func reasons(evs []eventRow) string {
	var r []string
	for _, e := range evs {
		r = append(r, e.Reason)
	}
	return strings.Join(r, ",")
}

func eventsClient() *kube.FakeClient {
	return kube.NewFakeClient(
		kube.Event("a", "e0", "Pod", "web-1", "Warning", "W0", "old warning", ago(120)),
		kube.Event("a", "e1", "Pod", "web-1", "Normal", "N1", "scheduled", ago(50)),
		kube.Event("a", "e2", "Pod", "web-1", "Warning", "W1", "back-off", ago(40)),
		kube.Event("a", "e3", "Pod", "web-2", "Normal", "N2", "pulled", ago(10)),
		kube.Event("a", "e4", "Deployment", "web", "Warning", "W2", "progress deadline", ago(5)),
		kube.Event("b", "e5", "Pod", "api-1", "Normal", "N3", "started", ago(3)),
	).SetNow(testNow)
}

func TestGetEventsOrderingAndWarningsOnly(t *testing.T) {
	f := kube.SingleFakeFactory(eventsClient())
	var out eventsOut
	decode(t, callTool(t, f, "get_events", map[string]any{"namespace": "a"}), &out)
	if got := reasons(out.Events); got != "W1,W2,N1,N2" {
		t.Errorf("default (60 min, warnings first, then oldest first): got %s", got)
	}
	if !out.Events[0].Warning || out.Events[0].Object != "Pod/web-1" || out.Events[0].Namespace != "a" ||
		out.Events[0].Count != 1 || out.Events[0].LastSeen == "" || out.Events[0].FirstSeen == "" {
		t.Errorf("event fields: %+v", out.Events[0])
	}
	if out.Events[2].Warning {
		t.Errorf("normal event flagged as warning: %+v", out.Events[2])
	}

	decode(t, callTool(t, f, "get_events", map[string]any{"namespace": "a", "warningsOnly": true}), &out)
	if got := reasons(out.Events); got != "W1,W2" {
		t.Errorf("warningsOnly: got %s", got)
	}

	decode(t, callTool(t, f, "get_events", map[string]any{"namespace": "a", "sinceMinutes": 180}), &out)
	if got := reasons(out.Events); got != "W0,W1,W2,N1,N2" {
		t.Errorf("sinceMinutes=180: got %s", got)
	}
}

func TestGetEventsScoping(t *testing.T) {
	f := kube.SingleFakeFactory(eventsClient())
	var out eventsOut
	decode(t, callTool(t, f, "get_events", map[string]any{}), &out)
	if got := reasons(out.Events); got != "W1,W2,N1,N2,N3" {
		t.Errorf("all namespaces: got %s", got)
	}
	decode(t, callTool(t, f, "get_events", map[string]any{"namespace": "b"}), &out)
	if got := reasons(out.Events); got != "N3" {
		t.Errorf("namespace b: got %s", got)
	}
	// involvedKind is resolved like kind elsewhere: "po" means Pod.
	decode(t, callTool(t, f, "get_events", map[string]any{"namespace": "a", "involvedKind": "po", "involvedName": "web-1"}), &out)
	if got := reasons(out.Events); got != "W1,N1" {
		t.Errorf("involved pod web-1: got %s", got)
	}
	decode(t, callTool(t, f, "get_events", map[string]any{"involvedKind": "deployments"}), &out)
	if got := reasons(out.Events); got != "W2" {
		t.Errorf("involved deployments: got %s", got)
	}
}

func TestGetEventsCapKeepsWarnings(t *testing.T) {
	maxItems := limits.Default().MaxItems
	var evs []map[string]any
	for i := 0; i < maxItems+100; i++ {
		evs = append(evs, kube.Event("a", fmt.Sprintf("n%04d", i), "Pod", "p", "Normal", "Pulled", "pulled", ago(30)))
	}
	evs = append(evs, kube.Event("a", "w", "Pod", "p", "Warning", "BackOff", "back-off", ago(59)))
	var out eventsOut
	decode(t, callTool(t, kube.SingleFakeFactory(kube.NewFakeClient(evs...).SetNow(testNow)), "get_events", map[string]any{"namespace": "a"}), &out)
	if len(out.Events) != maxItems || !out.Truncated || out.Total != maxItems+101 || out.Note == "" {
		t.Errorf("cap: len=%d truncated=%v total=%d note=%q", len(out.Events), out.Truncated, out.Total, out.Note)
	}
	if out.Events[0].Reason != "BackOff" {
		t.Errorf("the oldest warning must survive the cap, first is %+v", out.Events[0])
	}
}

func TestGetEventsSinceBounds(t *testing.T) {
	f := kube.SingleFakeFactory(eventsClient())
	for _, v := range []int{-1, 1441} {
		res := callTool(t, f, "get_events", map[string]any{"sinceMinutes": v})
		if text := servertest.Text(t, res); !res.IsError || !strings.Contains(text, "sinceMinutes") {
			t.Errorf("sinceMinutes=%d: want error:\n%s", v, text)
		}
	}
}

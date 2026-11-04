package tools_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/server/servertest"
)

type describeOut struct {
	Object     map[string]any `json:"object"`
	Conditions []struct {
		Type               string `json:"type"`
		Status             string `json:"status"`
		Reason             string `json:"reason"`
		Message            string `json:"message"`
		LastTransitionTime string `json:"lastTransitionTime"`
	} `json:"conditions"`
	Events          []eventRow `json:"events"`
	EventsTruncated bool       `json:"eventsTruncated"`
	EventsNote      string     `json:"eventsNote"`
}

func TestDescribePodConditionsAndOwnEventsOnly(t *testing.T) {
	p := sensitivePod()
	p["metadata"].(map[string]any)["annotations"] = map[string]any{
		"kubectl.kubernetes.io/last-applied-configuration": `{"kind":"Pod"}`,
		"team": "web",
	}
	p["status"].(map[string]any)["conditions"] = []any{
		map[string]any{"type": "Ready", "status": "False", "reason": "ContainersNotReady", "message": "containers with unready status: [app]", "lastTransitionTime": "2026-11-04T11:00:00Z", "lastProbeTime": nil},
		map[string]any{"type": "PodScheduled", "status": "True"},
	}
	fc := kube.NewFakeClient(p,
		kube.Event("a", "e1", "Pod", "web-1", "Warning", "BackOff", "back-off restarting", ago(5)),
		kube.Event("a", "e2", "Pod", "web-1", "Normal", "Scheduled", "assigned", ago(50)),
		kube.Event("a", "e3", "Pod", "web-2", "Warning", "Other", "other pod", ago(4)),
		kube.Event("a", "e4", "Deployment", "web-1", "Normal", "SameName", "other kind", ago(4)),
		kube.Event("b", "e5", "Pod", "web-1", "Normal", "OtherNs", "other namespace", ago(4)),
	).SetNow(testNow)
	f := kube.SingleFakeFactory(fc)
	res := callTool(t, f, "describe_resource", map[string]any{"kind": "Pod", "namespace": "a", "name": "web-1"})
	body := servertest.Payload(t, res)
	for _, leak := range []string{"plain-opaque-value-1", "opaque-header-2", "managedFields", "last-applied-configuration"} {
		if strings.Contains(body, leak) {
			t.Errorf("%q in describe output:\n%s", leak, body)
		}
	}
	var out describeOut
	decode(t, res, &out)
	if got := reasons(out.Events); got != "Scheduled,BackOff" {
		t.Errorf("want only this pod's events, newest last; got %s", got)
	}
	if !out.Events[1].Warning || out.Events[0].Warning {
		t.Errorf("warning flags: %+v", out.Events)
	}
	if len(out.Conditions) != 2 || out.Conditions[0].Type != "Ready" || out.Conditions[0].Status != "False" ||
		out.Conditions[0].Reason != "ContainersNotReady" || out.Conditions[0].LastTransitionTime == "" {
		t.Errorf("conditions: %+v", out.Conditions)
	}
	md, _ := out.Object["metadata"].(map[string]any)
	if md["name"] != "web-1" || md["namespace"] != "a" || md["annotations"].(map[string]any)["team"] != "web" {
		t.Errorf("metadata: %v", md)
	}
	if out.Object["spec"] == nil || out.Object["status"] == nil || out.Object["kind"] != "Pod" {
		t.Errorf("object must keep kind, spec and status: %v", out.Object)
	}
}

func TestDescribeEventsForbiddenDegrades(t *testing.T) {
	fc := kube.NewFakeClient(pod("a", "web-1")).
		FailOn("Events", "events", kube.NewAPIError(kube.ErrForbidden, "list", "events", "a", "", "nope"))
	var out describeOut
	decode(t, callTool(t, kube.SingleFakeFactory(fc), "describe_resource", map[string]any{"kind": "pods", "namespace": "a", "name": "web-1"}), &out)
	if out.EventsNote == "" || out.Object["kind"] != "Pod" || out.Events == nil {
		t.Errorf("want object, empty events and a note: %+v", out)
	}
}

func TestDescribeNotFound(t *testing.T) {
	res := callTool(t, kube.SingleFakeFactory(kube.NewFakeClient()), "describe_resource", map[string]any{"kind": "pods", "namespace": "a", "name": "nope"})
	if text := servertest.Text(t, res); !res.IsError || !strings.Contains(text, "error: not found") {
		t.Errorf("want not found:\n%s", text)
	}
}

func TestDescribeCapsEventsKeepingNewest(t *testing.T) {
	objs := []map[string]any{pod("a", "web-1")}
	for i := 0; i < 60; i++ {
		objs = append(objs, kube.Event("a", fmt.Sprintf("e%02d", i), "Pod", "web-1", "Normal", fmt.Sprintf("R%02d", i), "m", ago(60-i)))
	}
	var out describeOut
	decode(t, callTool(t, kube.SingleFakeFactory(kube.NewFakeClient(objs...).SetNow(testNow)), "describe_resource",
		map[string]any{"kind": "pods", "namespace": "a", "name": "web-1"}), &out)
	if len(out.Events) != 50 || !out.EventsTruncated || out.Events[0].Reason != "R10" || out.Events[49].Reason != "R59" {
		t.Errorf("want the 50 newest, newest last: len=%d truncated=%v first=%+v", len(out.Events), out.EventsTruncated, out.Events[0])
	}
}

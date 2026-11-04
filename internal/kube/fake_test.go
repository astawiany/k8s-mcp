package kube

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

var bg = context.Background()

func names(items []map[string]any) []string {
	var out []string
	for _, it := range items {
		md, _ := it["metadata"].(map[string]any)
		ns, _ := md["namespace"].(string)
		n, _ := md["name"].(string)
		if ns != "" {
			n = ns + "/" + n
		}
		out = append(out, n)
	}
	return out
}

func mustResolve(t *testing.T, c Client, q string) Resource {
	t.Helper()
	r, err := c.Resolve(bg, q, "", "")
	if err != nil {
		t.Fatalf("Resolve(%q): %v", q, err)
	}
	return r
}

func podFixture() *FakeClient {
	return NewFakeClient(
		WithLabels(Object("v1", "Pod", "default", "web-1"), map[string]string{"app": "web", "tier": "fe"}),
		WithLabels(Object("v1", "Pod", "default", "web-2"), map[string]string{"app": "web", "tier": "db"}),
		WithLabels(Object("v1", "Pod", "default", "api-1"), map[string]string{"app": "api"}),
		Object("v1", "Pod", "default", "lonely"),
		Object("v1", "Pod", "kube-system", "coredns"),
		Object("apps/v1", "Deployment", "default", "web"),
		Object("v1", "Node", "", "node-a"),
		Object("v1", "Node", "", "node-b"),
	)
}

func TestFakeListPagination(t *testing.T) {
	c := podFixture()
	pods := mustResolve(t, c, "pods")

	var all []string
	var pages [][]string
	opts := ListOptions{Limit: 2}
	for i := 0; ; i++ {
		res, err := c.List(bg, pods, "", opts)
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, names(res.Items))
		all = append(all, names(res.Items)...)
		if res.Continue == "" {
			if res.RemainingItemCount != nil {
				t.Errorf("last page RemainingItemCount = %d, want nil", *res.RemainingItemCount)
			}
			break
		}
		if res.RemainingItemCount == nil {
			t.Error("non-final page must report RemainingItemCount")
		}
		if i > 10 {
			t.Fatal("pagination does not terminate")
		}
		opts.Continue = res.Continue
	}
	want := []string{"default/api-1", "default/lonely", "default/web-1", "default/web-2", "kube-system/coredns"}
	if !slices.Equal(all, want) {
		t.Fatalf("all = %v, want %v", all, want)
	}
	if fmt.Sprint(pages) != "[[default/api-1 default/lonely] [default/web-1 default/web-2] [kube-system/coredns]]" {
		t.Errorf("pages = %v", pages)
	}

	res, err := c.List(bg, pods, "", ListOptions{})
	if err != nil || len(res.Items) != 5 || res.Continue != "" {
		t.Errorf("no limit: %v items, continue %q, err %v", len(res.Items), res.Continue, err)
	}
	if _, err := c.List(bg, pods, "", ListOptions{Continue: "garbage"}); err == nil {
		t.Error("invalid continue token: want error")
	}
	if _, err := c.List(bg, pods, "", ListOptions{Limit: -1}); err == nil {
		t.Error("negative limit: want error")
	}
}

func TestFakeListNamespaceAndScope(t *testing.T) {
	c := podFixture()
	res, err := c.List(bg, mustResolve(t, c, "pods"), "kube-system", ListOptions{})
	if err != nil || !slices.Equal(names(res.Items), []string{"kube-system/coredns"}) {
		t.Errorf("kube-system pods = %v, %v", names(res.Items), err)
	}
	// cluster-scoped kinds ignore the namespace argument
	res, err = c.List(bg, mustResolve(t, c, "nodes"), "default", ListOptions{})
	if err != nil || !slices.Equal(names(res.Items), []string{"node-a", "node-b"}) {
		t.Errorf("nodes = %v, %v", names(res.Items), err)
	}
	res, _ = c.List(bg, mustResolve(t, c, "deploy"), "", ListOptions{})
	if !slices.Equal(names(res.Items), []string{"default/web"}) {
		t.Errorf("deployments = %v", names(res.Items))
	}
}

func TestFakeListSelectors(t *testing.T) {
	c := podFixture()
	pods := mustResolve(t, c, "pods")
	cases := []struct {
		label, field string
		want         []string
	}{
		{"app=web", "", []string{"default/web-1", "default/web-2"}},
		{"app==web,tier!=db", "", []string{"default/web-1"}},
		{"tier!=db", "", []string{"default/api-1", "default/lonely", "default/web-1", "kube-system/coredns"}},
		{"app", "", []string{"default/api-1", "default/web-1", "default/web-2"}},
		{"app in (api,web),tier notin (fe)", "", []string{"default/api-1", "default/web-2"}},
		{"", "metadata.name=lonely", []string{"default/lonely"}},
		{"", "metadata.namespace=kube-system", []string{"kube-system/coredns"}},
		{"", "metadata.namespace!=default", []string{"kube-system/coredns"}},
		{"app=web", "metadata.name=web-2", []string{"default/web-2"}},
	}
	for _, cs := range cases {
		res, err := c.List(bg, pods, "", ListOptions{LabelSelector: cs.label, FieldSelector: cs.field})
		if err != nil {
			t.Errorf("%q/%q: %v", cs.label, cs.field, err)
			continue
		}
		if got := names(res.Items); !slices.Equal(got, cs.want) {
			t.Errorf("%q/%q = %v, want %v", cs.label, cs.field, got, cs.want)
		}
	}
	if _, err := c.List(bg, pods, "", ListOptions{LabelSelector: "a=(("}); err == nil {
		t.Error("bad label selector: want error")
	}
	if _, err := c.List(bg, pods, "", ListOptions{FieldSelector: "metadata.name"}); err == nil {
		t.Error("bad field selector: want error")
	}
}

func TestFakeGet(t *testing.T) {
	c := podFixture()
	obj, err := c.Get(bg, mustResolve(t, c, "deploy"), "default", "web")
	if err != nil {
		t.Fatal(err)
	}
	if obj["kind"] != "Deployment" {
		t.Errorf("kind = %v", obj["kind"])
	}
	// Returned objects are copies: mutating them must not change the store.
	obj["kind"] = "Mutated"
	again, _ := c.Get(bg, mustResolve(t, c, "deploy"), "default", "web")
	if again["kind"] != "Deployment" {
		t.Error("Get must return a deep copy")
	}
	n, err := c.Get(bg, mustResolve(t, c, "node"), "", "node-a")
	if err != nil || names([]map[string]any{n})[0] != "node-a" {
		t.Errorf("node get = %v, %v", n, err)
	}
	_, err = c.Get(bg, mustResolve(t, c, "deploy"), "default", "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("missing object: %v, want ErrNotFound", err)
	}
	_, err = c.Get(bg, mustResolve(t, c, "deploy"), "other", "web")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("wrong namespace: %v, want ErrNotFound", err)
	}
}

func TestFakeAddAutoRegistersCRD(t *testing.T) {
	c := NewFakeClient(Object("example.com/v1alpha1", "Widget", "default", "w1"))
	r, err := c.Resolve(bg, "widget", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Group != "example.com" || r.Version != "v1alpha1" || r.Resource != "widgets" || !r.Namespaced {
		t.Errorf("auto resource = %+v", r)
	}
	res, _ := c.List(bg, r, "", ListOptions{})
	if len(res.Items) != 1 {
		t.Errorf("items = %d", len(res.Items))
	}
	groups, _ := c.APIGroups(bg)
	if !slices.Contains(groups, "example.com/v1alpha1") {
		t.Errorf("groups = %v", groups)
	}
}

func TestFakeAddRejectsInvalidObjects(t *testing.T) {
	for _, obj := range []map[string]any{
		{"kind": "Pod", "metadata": map[string]any{"name": "x"}},
		{"apiVersion": "v1", "metadata": map[string]any{"name": "x"}},
		{"apiVersion": "v1", "kind": "Pod"},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Add(%v) must panic", obj)
				}
			}()
			NewFakeClient(obj)
		}()
	}
}

func TestFakeDiscovery(t *testing.T) {
	c := NewFakeClient()
	v, err := c.ServerVersion(bg)
	if err != nil || v == "" {
		t.Errorf("version %q %v", v, err)
	}
	c.SetServerVersion("v1.99.0")
	if v, _ := c.ServerVersion(bg); v != "v1.99.0" {
		t.Errorf("version = %q", v)
	}
	g, err := c.APIGroups(bg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"v1", "apps/v1", "batch/v1", "kustomize.toolkit.fluxcd.io/v1", "helm.toolkit.fluxcd.io/v2", "source.toolkit.fluxcd.io/v1"} {
		if !slices.Contains(g, want) {
			t.Errorf("APIGroups missing %s: %v", want, g)
		}
	}
	if slices.Contains(g, "metrics.k8s.io/v1beta1") {
		t.Error("metrics group must be absent until metrics are set")
	}
	c.SetNodeMetrics()
	g, _ = c.APIGroups(bg)
	if !slices.Contains(g, "metrics.k8s.io/v1beta1") {
		t.Error("metrics group must appear once metrics are set")
	}
	c.SetAPIGroups("v1")
	if g, _ := c.APIGroups(bg); !slices.Equal(g, []string{"v1"}) {
		t.Errorf("override = %v", g)
	}
	for _, q := range []string{"secret", "cm", "events", "ds", "sts", "job", "cronjob", "ingress", "hr", "gitrepo", "helmrepository", "ocirepository", "gateway", "httproute", "pvc", "ns", "rs"} {
		if _, err := c.Resolve(bg, q, "", ""); err != nil {
			t.Errorf("default discovery cannot resolve %q: %v", q, err)
		}
	}
}

func TestFakeEvents(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	c := NewFakeClient(
		Event("default", "e-old", "Pod", "web-1", "Warning", "BackOff", "old", now.Add(-2*time.Hour)),
		Event("default", "e-new", "Pod", "web-1", "Warning", "BackOff", "new", now.Add(-time.Minute)),
		Event("default", "e-mid", "Deployment", "web", "Normal", "ScalingReplicaSet", "mid", now.Add(-30*time.Minute)),
		Event("kube-system", "e-ks", "Pod", "web-1", "Normal", "Pulled", "ks", now.Add(-time.Minute)),
	).SetNow(now)

	ev, err := c.Events(bg, "default", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(ev); !slices.Equal(got, []string{"default/e-old", "default/e-mid", "default/e-new"}) {
		t.Errorf("all default events (oldest first) = %v", got)
	}
	ev, _ = c.Events(bg, "default", nil, time.Hour)
	if got := names(ev); !slices.Equal(got, []string{"default/e-mid", "default/e-new"}) {
		t.Errorf("last hour = %v", got)
	}
	ev, _ = c.Events(bg, "default", &ObjectRef{Kind: "Pod", Name: "web-1"}, 0)
	if got := names(ev); !slices.Equal(got, []string{"default/e-old", "default/e-new"}) {
		t.Errorf("involved pod = %v", got)
	}
	ev, _ = c.Events(bg, "", &ObjectRef{Kind: "Pod", Name: "web-1", Namespace: "kube-system"}, 0)
	if got := names(ev); !slices.Equal(got, []string{"kube-system/e-ks"}) {
		t.Errorf("involved pod in kube-system = %v", got)
	}
	ev, _ = c.Events(bg, "", nil, 0)
	if len(ev) != 4 {
		t.Errorf("all namespaces = %v", names(ev))
	}
}

func TestFakePodLogs(t *testing.T) {
	c := NewFakeClient(Object("v1", "Pod", "default", "quiet")).
		SetLogs("default", "web", "app", "l1\nl2\nl3\n").
		SetPreviousLogs("default", "web", "app", "crashed\n").
		SetLogs("default", "multi", "a", "A\n").
		SetLogs("default", "multi", "b", "B\n")

	got, err := c.PodLogs(bg, "default", "web", LogOptions{})
	if err != nil || got != "l1\nl2\nl3\n" {
		t.Errorf("single container default = %q, %v", got, err)
	}
	got, _ = c.PodLogs(bg, "default", "web", LogOptions{Container: "app", TailLines: 2})
	if got != "l2\nl3\n" {
		t.Errorf("tail 2 = %q", got)
	}
	got, _ = c.PodLogs(bg, "default", "web", LogOptions{Previous: true})
	if got != "crashed\n" {
		t.Errorf("previous = %q", got)
	}
	got, _ = c.PodLogs(bg, "default", "multi", LogOptions{Container: "b"})
	if got != "B\n" {
		t.Errorf("container b = %q", got)
	}
	if _, err := c.PodLogs(bg, "default", "multi", LogOptions{}); err == nil || !strings.Contains(err.Error(), "a, b") {
		t.Errorf("multi-container without container: %v", err)
	}
	if _, err := c.PodLogs(bg, "default", "multi", LogOptions{Previous: true, Container: "a"}); err == nil {
		t.Error("missing previous logs: want error")
	}
	if _, err := c.PodLogs(bg, "default", "web", LogOptions{Container: "nope"}); err == nil {
		t.Error("unknown container: want error")
	}
	if _, err := c.PodLogs(bg, "default", "ghost", LogOptions{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown pod: %v, want ErrNotFound", err)
	}
	if got, err := c.PodLogs(bg, "default", "quiet", LogOptions{}); err != nil || got != "" {
		t.Errorf("pod without logs = %q, %v", got, err)
	}
	got, _ = c.PodLogs(bg, "default", "web", LogOptions{LimitBytes: 4})
	if got != "l1\nl" {
		t.Errorf("limitBytes 4 = %q", got)
	}
}

func TestFakeMetrics(t *testing.T) {
	c := NewFakeClient()
	if _, err := c.NodeMetrics(bg); !errors.Is(err, ErrMetricsUnavailable) {
		t.Errorf("node metrics default: %v", err)
	}
	if _, err := c.PodMetrics(bg, ""); !errors.Is(err, ErrMetricsUnavailable) {
		t.Errorf("pod metrics default: %v", err)
	}
	c.SetNodeMetrics(NodeMetric("node-a", "250m", "1Gi")).
		SetPodMetrics(PodMetric("default", "web-1", map[string][2]string{"app": {"10m", "20Mi"}}),
			PodMetric("kube-system", "coredns", map[string][2]string{"coredns": {"5m", "15Mi"}}))
	nm, err := c.NodeMetrics(bg)
	if err != nil || len(nm) != 1 || names(nm)[0] != "node-a" {
		t.Errorf("node metrics = %v, %v", nm, err)
	}
	usage := nm[0]["usage"].(map[string]any)
	if usage["cpu"] != "250m" || usage["memory"] != "1Gi" {
		t.Errorf("usage = %v", usage)
	}
	pm, _ := c.PodMetrics(bg, "default")
	if !slices.Equal(names(pm), []string{"default/web-1"}) {
		t.Errorf("pod metrics default ns = %v", names(pm))
	}
	pm, _ = c.PodMetrics(bg, "")
	if len(pm) != 2 {
		t.Errorf("pod metrics all = %v", names(pm))
	}
	c.SetMetricsUnavailable()
	if _, err := c.NodeMetrics(bg); !errors.Is(err, ErrMetricsUnavailable) {
		t.Errorf("after SetMetricsUnavailable: %v", err)
	}
}

func TestFakeFailOn(t *testing.T) {
	c := podFixture()
	forbidden := NewAPIError(ErrForbidden, "list", "secrets", "default", "", `secrets is forbidden: User "x" cannot list resource "secrets"`)
	c.FailOn("List", "secrets", forbidden).FailOn("ServerVersion", "", errors.New("boom"))
	_, err := c.List(bg, mustResolve(t, c, "secrets"), "default", ListOptions{})
	if !errors.Is(err, ErrForbidden) || !strings.Contains(err.Error(), "cannot list") {
		t.Errorf("list secrets: %v", err)
	}
	if _, err := c.List(bg, mustResolve(t, c, "pods"), "default", ListOptions{}); err != nil {
		t.Errorf("list pods must still work: %v", err)
	}
	if _, err := c.ServerVersion(bg); err == nil || err.Error() != "boom" {
		t.Errorf("ServerVersion: %v", err)
	}
	_, err = c.List(bg, mustResolve(t, c, "secrets"), "default", ListOptions{})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Verb != "list" || ae.Resource != "secrets" || ae.Namespace != "default" {
		t.Errorf("APIError fields: %+v", ae)
	}
}

func TestFakeRecordsCalls(t *testing.T) {
	c := podFixture()
	_, _ = c.ServerVersion(bg)
	_, _ = c.List(bg, mustResolve(t, c, "pods"), "default", ListOptions{})
	got := c.Calls()
	want := []string{"ServerVersion", "Resolve pods", "List pods default"}
	if !slices.Equal(got, want) {
		t.Errorf("Calls() = %q, want %q", got, want)
	}
}

func TestFakeFactory(t *testing.T) {
	dev, prod := NewFakeClient(), NewFakeClient()
	f := NewFakeFactory("dev", map[string]*FakeClient{"dev": dev, "prod": prod, "kind-x": NewFakeClient()})
	f.Allow = MustParseAllowlist("dev,kind-*")

	want := []ContextInfo{{Name: "dev", Current: true, Allowed: true}, {Name: "kind-x", Allowed: true}, {Name: "prod"}}
	if got := f.Contexts(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Contexts = %+v", got)
	}
	c, err := f.For("")
	if err != nil || c != Client(dev) {
		t.Errorf(`For("") = %v, %v`, c, err)
	}
	if c, _ := f.For("dev"); c != Client(dev) {
		t.Error("For(dev) returned another client")
	}
	if _, err := f.For("prod"); !errors.Is(err, ErrContextNotAllowed) {
		t.Errorf("For(prod) = %v", err)
	}
	if _, err := f.For("nope"); !errors.Is(err, ErrUnknownContext) {
		t.Errorf("For(nope) = %v", err)
	}
	f.Current = ""
	if _, err := f.For(""); !errors.Is(err, ErrUnknownContext) {
		t.Errorf(`For("") without current = %v`, err)
	}
	single := SingleFakeFactory(dev)
	if c, err := single.For(""); err != nil || c != Client(dev) {
		t.Errorf("SingleFakeFactory: %v %v", c, err)
	}
}

func TestEventsCapKeepsNewest(t *testing.T) {
	old := maxEvents
	maxEvents = 2
	t.Cleanup(func() { maxEvents = old })
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	// Names sort opposite to time, so a cap by key order would keep the oldest.
	c := NewFakeClient(
		Event("default", "a-newest", "Pod", "p", "Warning", "BackOff", "", now.Add(-time.Minute)),
		Event("default", "b-newer", "Pod", "p", "Warning", "BackOff", "", now.Add(-2*time.Minute)),
		Event("default", "c-old", "Pod", "p", "Warning", "BackOff", "", now.Add(-3*time.Minute)),
		Event("default", "d-oldest", "Pod", "p", "Warning", "BackOff", "", now.Add(-4*time.Minute)),
	).SetNow(now)
	ev, err := c.Events(bg, "default", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(ev); !slices.Equal(got, []string{"default/b-newer", "default/a-newest"}) {
		t.Errorf("capped events = %v, want the two newest, oldest first", got)
	}
}

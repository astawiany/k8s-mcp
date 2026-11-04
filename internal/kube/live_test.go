package kube

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// apiStub is a tiny local HTTP server speaking enough of the Kubernetes API
// for the live client. It is not a cluster: tests stay hermetic.
type apiStub struct {
	srv     *httptest.Server
	metrics bool

	mu      sync.Mutex
	queries map[string]url.Values // path -> last query
	methods []string
}

func status(code int, reason, msg string) map[string]any {
	return map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": code, "reason": reason, "message": msg}
}

func pod(name string) map[string]any {
	return map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": name, "namespace": "default"}}
}

func newAPIStub(t *testing.T, metrics bool) *apiStub {
	t.Helper()
	s := &apiStub{metrics: metrics, queries: map[string]url.Values{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *apiStub) query(path string) url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries[path]
}

func (s *apiStub) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.queries[r.URL.Path] = r.URL.Query()
	s.methods = append(s.methods, r.Method)
	s.mu.Unlock()

	write := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	res := func(name, kind string, ns bool, short ...string) map[string]any {
		return map[string]any{"name": name, "singularName": strings.ToLower(kind), "kind": kind, "namespaced": ns, "shortNames": short, "verbs": []string{"get", "list"}}
	}
	q := r.URL.Query()
	switch r.URL.Path {
	case "/version":
		write(200, map[string]any{"major": "1", "minor": "31", "gitVersion": "v1.31.2"})
	case "/api":
		write(200, map[string]any{"kind": "APIVersions", "versions": []string{"v1"}})
	case "/apis":
		groups := []any{map[string]any{"name": "apps", "versions": []any{map[string]any{"groupVersion": "apps/v1", "version": "v1"}},
			"preferredVersion": map[string]any{"groupVersion": "apps/v1", "version": "v1"}}}
		if s.metrics {
			groups = append(groups, map[string]any{"name": "metrics.k8s.io", "versions": []any{map[string]any{"groupVersion": "metrics.k8s.io/v1beta1", "version": "v1beta1"}},
				"preferredVersion": map[string]any{"groupVersion": "metrics.k8s.io/v1beta1", "version": "v1beta1"}})
		}
		write(200, map[string]any{"kind": "APIGroupList", "apiVersion": "v1", "groups": groups})
	case "/api/v1":
		write(200, map[string]any{"kind": "APIResourceList", "groupVersion": "v1", "resources": []any{
			res("pods", "Pod", true, "po"), res("events", "Event", true, "ev"), res("nodes", "Node", false, "no")}})
	case "/apis/apps/v1":
		write(200, map[string]any{"kind": "APIResourceList", "groupVersion": "apps/v1", "resources": []any{res("deployments", "Deployment", true, "deploy")}})
	case "/apis/metrics.k8s.io/v1beta1":
		write(200, map[string]any{"kind": "APIResourceList", "groupVersion": "metrics.k8s.io/v1beta1", "resources": []any{
			res("nodes", "NodeMetrics", false), res("pods", "PodMetrics", true)}})
	case "/api/v1/namespaces/default/pods":
		if q.Get("continue") == "tok2" {
			write(200, map[string]any{"kind": "PodList", "apiVersion": "v1", "metadata": map[string]any{}, "items": []any{pod("c")}})
			return
		}
		write(200, map[string]any{"kind": "PodList", "apiVersion": "v1", "metadata": map[string]any{"continue": "tok2", "remainingItemCount": 1},
			"items": []any{pod("a"), pod("b")}})
	case "/api/v1/namespaces/locked/pods":
		write(403, status(403, "Forbidden", `pods is forbidden: User "viewer" cannot list resource "pods" in API group "" in the namespace "locked"`))
	case "/api/v1/namespaces/slow/pods":
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
			return
		}
		write(200, map[string]any{"kind": "PodList", "apiVersion": "v1", "items": []any{}})
	case "/apis/apps/v1/namespaces/default/deployments/web":
		write(200, map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "web", "namespace": "default"}})
	case "/apis/apps/v1/namespaces/default/deployments/nope":
		write(404, status(404, "NotFound", `deployments.apps "nope" not found`))
	case "/api/v1/namespaces/default/pods/web-1/log":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("line1\nline2\n"))
	case "/api/v1/namespaces/default/events":
		now := time.Now().UTC()
		ev := func(name string, at time.Time) map[string]any {
			return map[string]any{"apiVersion": "v1", "kind": "Event", "metadata": map[string]any{"name": name, "namespace": "default"},
				"lastTimestamp": at.Format(time.RFC3339)}
		}
		write(200, map[string]any{"kind": "EventList", "apiVersion": "v1", "metadata": map[string]any{},
			"items": []any{ev("new", now.Add(-time.Minute)), ev("old", now.Add(-3*time.Hour))}})
	case "/apis/metrics.k8s.io/v1beta1/nodes":
		write(200, map[string]any{"kind": "NodeMetricsList", "apiVersion": "metrics.k8s.io/v1beta1", "metadata": map[string]any{},
			"items": []any{map[string]any{"metadata": map[string]any{"name": "node-a"}, "usage": map[string]any{"cpu": "100m", "memory": "1Gi"}}}})
	default:
		write(404, status(404, "NotFound", "the server could not find the requested resource"))
	}
}

func (s *apiStub) client(t *testing.T, opts ...FactoryOption) Client {
	t.Helper()
	isolateEnv(t)
	cfg := "apiVersion: v1\nkind: Config\ncurrent-context: stub\nclusters:\n- name: stub\n  cluster: {server: " + s.srv.URL +
		"}\nusers:\n- name: u\n  user: {token: tok-SECRET-123}\ncontexts:\n- name: stub\n  context: {cluster: stub, user: u}\n"
	f, err := NewFactory(writeKubeconfig(t, cfg), Allowlist{}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.For("")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLiveDiscovery(t *testing.T) {
	s := newAPIStub(t, false)
	c := s.client(t)
	v, err := c.ServerVersion(bg)
	if err != nil || v != "v1.31.2" {
		t.Errorf("ServerVersion = %q, %v", v, err)
	}
	g, err := c.APIGroups(bg)
	if err != nil || !slices.Equal(g, []string{"v1", "apps/v1"}) {
		t.Errorf("APIGroups = %v, %v", g, err)
	}
	r, err := c.Resolve(bg, "deploy", "", "")
	if err != nil || r != (Resource{Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment", Namespaced: true}) {
		t.Errorf("Resolve(deploy) = %+v, %v", r, err)
	}
	_, err = c.Resolve(bg, "deploymnt", "", "")
	if !errors.Is(err, ErrKindNotFound) || !strings.Contains(err.Error(), "deployments.apps") {
		t.Errorf("Resolve(deploymnt) = %v", err)
	}
}

func TestLiveListGetAndErrors(t *testing.T) {
	s := newAPIStub(t, false)
	c := s.client(t)
	pods := Resource{Version: "v1", Resource: "pods", Kind: "Pod", Namespaced: true}

	res, err := c.List(bg, pods, "default", ListOptions{Limit: 2, LabelSelector: "app=web", FieldSelector: "status.phase=Running"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names(res.Items), []string{"default/a", "default/b"}) || res.Continue != "tok2" ||
		res.RemainingItemCount == nil || *res.RemainingItemCount != 1 {
		t.Errorf("page 1 = %v continue %q", names(res.Items), res.Continue)
	}
	q := s.query("/api/v1/namespaces/default/pods")
	if q.Get("limit") != "2" || q.Get("labelSelector") != "app=web" || q.Get("fieldSelector") != "status.phase=Running" {
		t.Errorf("query = %v", q)
	}
	res, err = c.List(bg, pods, "default", ListOptions{Limit: 2, Continue: "tok2"})
	if err != nil || !slices.Equal(names(res.Items), []string{"default/c"}) || res.Continue != "" {
		t.Errorf("page 2 = %v %q %v", names(res.Items), res.Continue, err)
	}

	obj, err := c.Get(bg, Resource{Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment", Namespaced: true}, "default", "web")
	if err != nil || obj["kind"] != "Deployment" {
		t.Errorf("Get = %v, %v", obj, err)
	}
	_, err = c.Get(bg, Resource{Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment", Namespaced: true}, "default", "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get(nope) = %v, want ErrNotFound", err)
	}

	_, err = c.List(bg, pods, "locked", ListOptions{})
	var ae *APIError
	if !errors.Is(err, ErrForbidden) || !errors.As(err, &ae) || ae.Verb != "list" || ae.Resource != "pods" || ae.Namespace != "locked" ||
		!strings.Contains(ae.Message, `cannot list resource "pods"`) {
		t.Errorf("forbidden = %#v", err)
	}
	if strings.Contains(err.Error(), "tok-SECRET") {
		t.Error("error leaks token")
	}

	s.mu.Lock()
	for _, m := range s.methods {
		if m != http.MethodGet {
			t.Errorf("live client sent %s", m)
		}
	}
	s.mu.Unlock()
}

func TestLiveTimeout(t *testing.T) {
	s := newAPIStub(t, false)
	c := s.client(t, WithTimeout(200*time.Millisecond))
	start := time.Now()
	_, err := c.List(bg, Resource{Version: "v1", Resource: "pods", Kind: "Pod", Namespaced: true}, "slow", ListOptions{})
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("slow list = %v, want ErrTimeout", err)
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Errorf("timeout not applied: took %v", time.Since(start))
	}
}

func TestLivePodLogsAndEvents(t *testing.T) {
	s := newAPIStub(t, false)
	c := s.client(t)
	out, err := c.PodLogs(bg, "default", "web-1", LogOptions{Container: "app", TailLines: 50, Previous: true, SinceSeconds: 600})
	if err != nil || out != "line1\nline2\n" {
		t.Errorf("PodLogs = %q, %v", out, err)
	}
	q := s.query("/api/v1/namespaces/default/pods/web-1/log")
	if q.Get("container") != "app" || q.Get("tailLines") != "50" || q.Get("previous") != "true" || q.Get("sinceSeconds") != "600" ||
		q.Get("limitBytes") == "" {
		t.Errorf("log query = %v", q)
	}
	out, _ = c.PodLogs(bg, "default", "web-1", LogOptions{LimitBytes: 3})
	if out != "lin" {
		t.Errorf("LimitBytes 3 = %q", out)
	}

	ev, err := c.Events(bg, "default", &ObjectRef{Kind: "Pod", Name: "web-1", UID: "u-1"}, time.Hour)
	if err != nil || !slices.Equal(names(ev), []string{"default/new"}) {
		t.Errorf("Events = %v, %v", names(ev), err)
	}
	fs := s.query("/api/v1/namespaces/default/events").Get("fieldSelector")
	for _, want := range []string{"involvedObject.kind=Pod", "involvedObject.name=web-1", "involvedObject.uid=u-1"} {
		if !strings.Contains(fs, want) {
			t.Errorf("event fieldSelector %q missing %q", fs, want)
		}
	}
}

func TestLiveMetrics(t *testing.T) {
	c := newAPIStub(t, false).client(t)
	if _, err := c.NodeMetrics(bg); !errors.Is(err, ErrMetricsUnavailable) {
		t.Errorf("no metrics group: %v", err)
	}
	if _, err := c.PodMetrics(bg, "default"); !errors.Is(err, ErrMetricsUnavailable) {
		t.Errorf("no metrics group (pods): %v", err)
	}
	c = newAPIStub(t, true).client(t)
	nm, err := c.NodeMetrics(bg)
	if err != nil || len(nm) != 1 || names(nm)[0] != "node-a" {
		t.Errorf("NodeMetrics = %v, %v", nm, err)
	}
	// metrics group advertised but the pods endpoint 404s (APIService down)
	if _, err := c.PodMetrics(bg, "default"); !errors.Is(err, ErrMetricsUnavailable) {
		t.Errorf("metrics endpoint 404: %v", err)
	}
}

func TestLiveEventsCapKeepsNewest(t *testing.T) {
	old := maxEvents
	maxEvents = 1
	t.Cleanup(func() { maxEvents = old })
	c := newAPIStub(t, false).client(t)
	// the stub lists "new" before "old"; both pass a zero since
	ev, err := c.Events(bg, "default", nil, 0)
	if err != nil || !slices.Equal(names(ev), []string{"default/new"}) {
		t.Errorf("capped live events = %v, %v", names(ev), err)
	}
}

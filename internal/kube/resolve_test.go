package kube

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fakeDiscovery mimics what an API server returns: core first, then named
// groups in server priority order, with several versions for some groups.
func fakeDiscovery() ([]*metav1.APIGroup, []*metav1.APIResourceList) {
	gv := func(g, v string) metav1.GroupVersionForDiscovery {
		if g == "" {
			return metav1.GroupVersionForDiscovery{GroupVersion: v, Version: v}
		}
		return metav1.GroupVersionForDiscovery{GroupVersion: g + "/" + v, Version: v}
	}
	group := func(name, preferred string, versions ...string) *metav1.APIGroup {
		g := &metav1.APIGroup{Name: name, PreferredVersion: gv(name, preferred)}
		for _, v := range versions {
			g.Versions = append(g.Versions, gv(name, v))
		}
		return g
	}
	rw := []string{"get", "list", "watch", "create", "delete"}
	r := func(name, singular, kind string, ns bool, short ...string) metav1.APIResource {
		return metav1.APIResource{Name: name, SingularName: singular, Kind: kind, Namespaced: ns, ShortNames: short, Verbs: rw}
	}
	groups := []*metav1.APIGroup{
		group("", "v1", "v1"),
		group("apps", "v1", "v1"),
		group("events.k8s.io", "v1", "v1"),
		group("autoscaling", "v2", "v2", "v1"),
		group("kustomize.toolkit.fluxcd.io", "v1", "v1", "v1beta2"),
	}
	lists := []*metav1.APIResourceList{
		{GroupVersion: "v1", APIResources: []metav1.APIResource{
			r("pods", "pod", "Pod", true, "po"),
			{Name: "pods/log", Kind: "Pod", Namespaced: true, Verbs: []string{"get"}},
			{Name: "pods/status", Kind: "Pod", Namespaced: true, Verbs: []string{"get", "patch"}},
			r("nodes", "node", "Node", false, "no"),
			r("events", "event", "Event", true, "ev"),
			r("services", "service", "Service", true, "svc"),
			r("secrets", "secret", "Secret", true),
			r("namespaces", "namespace", "Namespace", false, "ns"),
		}},
		{GroupVersion: "apps/v1", APIResources: []metav1.APIResource{
			r("deployments", "deployment", "Deployment", true, "deploy"),
			{Name: "deployments/scale", Kind: "Scale", Group: "autoscaling", Version: "v1", Namespaced: true},
			r("daemonsets", "daemonset", "DaemonSet", true, "ds"),
			r("statefulsets", "statefulset", "StatefulSet", true, "sts"),
			r("replicasets", "replicaset", "ReplicaSet", true, "rs"),
		}},
		{GroupVersion: "events.k8s.io/v1", APIResources: []metav1.APIResource{
			r("events", "event", "Event", true, "ev"),
		}},
		{GroupVersion: "autoscaling/v2", APIResources: []metav1.APIResource{
			r("horizontalpodautoscalers", "horizontalpodautoscaler", "HorizontalPodAutoscaler", true, "hpa"),
		}},
		{GroupVersion: "autoscaling/v1", APIResources: []metav1.APIResource{
			r("horizontalpodautoscalers", "horizontalpodautoscaler", "HorizontalPodAutoscaler", true, "hpa"),
		}},
		{GroupVersion: "kustomize.toolkit.fluxcd.io/v1beta2", APIResources: []metav1.APIResource{
			r("kustomizations", "kustomization", "Kustomization", true, "ks"),
		}},
		{GroupVersion: "kustomize.toolkit.fluxcd.io/v1", APIResources: []metav1.APIResource{
			r("kustomizations", "kustomization", "Kustomization", true, "ks"),
		}},
	}
	return groups, lists
}

func testInfos() []ResourceInfo {
	return infosFromDiscovery(fakeDiscovery())
}

func TestInfosFromDiscovery(t *testing.T) {
	infos := testInfos()
	for _, in := range infos {
		if strings.Contains(in.Resource.Resource, "/") {
			t.Errorf("subresource %q must be skipped", in.Resource.Resource)
		}
	}
	var hpa []ResourceInfo
	for _, in := range infos {
		if in.Kind == "HorizontalPodAutoscaler" {
			hpa = append(hpa, in)
		}
	}
	if len(hpa) != 2 {
		t.Fatalf("hpa entries = %d, want 2", len(hpa))
	}
	for _, h := range hpa {
		if h.Preferred != (h.Version == "v2") {
			t.Errorf("hpa %s preferred = %v", h.Version, h.Preferred)
		}
	}
	if infos[0].Group != "" || infos[0].Resource.Resource != "pods" || !infos[0].Namespaced ||
		infos[0].Singular != "pod" || !slices.Equal(infos[0].ShortNames, []string{"po"}) {
		t.Errorf("first info = %+v", infos[0])
	}
}

func TestResolve(t *testing.T) {
	infos := testInfos()
	cases := []struct {
		q, group, version string
		want              Resource
	}{
		{"deploy", "", "", Resource{Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment", Namespaced: true}},
		{"deployments", "", "", Resource{Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment", Namespaced: true}},
		{"deployment", "", "", Resource{Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment", Namespaced: true}},
		{"Deployment", "", "", Resource{Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment", Namespaced: true}},
		{"  DEPLOY ", "APPS", "", Resource{Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment", Namespaced: true}},
		{"deployments.apps", "", "", Resource{Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment", Namespaced: true}},
		{"po", "", "", Resource{Version: "v1", Resource: "pods", Kind: "Pod", Namespaced: true}},
		{"Node", "", "", Resource{Version: "v1", Resource: "nodes", Kind: "Node"}},
		{"no", "core", "", Resource{Version: "v1", Resource: "nodes", Kind: "Node"}},
		// ambiguity across versions: the group's preferred version wins
		{"hpa", "", "", Resource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers", Kind: "HorizontalPodAutoscaler", Namespaced: true}},
		{"hpa", "", "v1", Resource{Group: "autoscaling", Version: "v1", Resource: "horizontalpodautoscalers", Kind: "HorizontalPodAutoscaler", Namespaced: true}},
		{"ks", "", "", Resource{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations", Kind: "Kustomization", Namespaced: true}},
		// ambiguity across groups: server priority order (core first)
		{"events", "", "", Resource{Version: "v1", Resource: "events", Kind: "Event", Namespaced: true}},
		{"ev", "events.k8s.io", "", Resource{Group: "events.k8s.io", Version: "v1", Resource: "events", Kind: "Event", Namespaced: true}},
	}
	for _, c := range cases {
		got, err := resolveIn(infos, c.q, c.group, c.version)
		if err != nil {
			t.Errorf("resolve(%q,%q,%q): %v", c.q, c.group, c.version, err)
			continue
		}
		if got != c.want {
			t.Errorf("resolve(%q,%q,%q) = %+v, want %+v", c.q, c.group, c.version, got, c.want)
		}
	}
}

func TestResolveUnknownSuggestsCloseMatches(t *testing.T) {
	_, err := resolveIn(testInfos(), "deploymnt", "", "")
	if !errors.Is(err, ErrKindNotFound) {
		t.Fatalf("err = %v, want ErrKindNotFound", err)
	}
	var kn *KindNotFoundError
	if !errors.As(err, &kn) {
		t.Fatalf("err %T is not *KindNotFoundError", err)
	}
	if len(kn.Suggestions) == 0 || len(kn.Suggestions) > 5 {
		t.Fatalf("suggestions = %v", kn.Suggestions)
	}
	if kn.Suggestions[0] != "deployments.apps" {
		t.Errorf("best suggestion = %q, want deployments.apps (all: %v)", kn.Suggestions[0], kn.Suggestions)
	}
	if !strings.Contains(err.Error(), "deploymnt") || !strings.Contains(err.Error(), "deployments.apps") {
		t.Errorf("message = %q", err.Error())
	}
}

func TestResolveSuggestionsCapped(t *testing.T) {
	_, err := resolveIn(testInfos(), "s", "", "")
	var kn *KindNotFoundError
	if !errors.As(err, &kn) {
		t.Fatalf("err = %v", err)
	}
	if len(kn.Suggestions) > 5 {
		t.Errorf("got %d suggestions, max 5", len(kn.Suggestions))
	}
}

func TestResolveNothingClose(t *testing.T) {
	_, err := resolveIn(testInfos(), "zzzzzzzzzzzzzzzz", "", "")
	var kn *KindNotFoundError
	if !errors.As(err, &kn) {
		t.Fatalf("err = %v", err)
	}
	if len(kn.Suggestions) != 0 {
		t.Errorf("suggestions = %v, want none", kn.Suggestions)
	}
}

func TestResolveGroupVersionFilters(t *testing.T) {
	infos := testInfos()
	for _, c := range [][3]string{
		{"deploy", "batch", ""},
		{"deploy", "apps", "v1beta1"},
		{"pods", "apps", ""},
		{"", "", ""},
	} {
		if _, err := resolveIn(infos, c[0], c[1], c[2]); !errors.Is(err, ErrKindNotFound) {
			t.Errorf("resolve(%q,%q,%q) err = %v, want ErrKindNotFound", c[0], c[1], c[2], err)
		}
	}
}

func TestResolveViaFakeClient(t *testing.T) {
	c := NewFakeClient()
	r, err := c.Resolve(context.Background(), "deploy", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Group != "apps" || r.Version != "v1" || r.Resource != "deployments" {
		t.Fatalf("got %+v", r)
	}
	_, err = c.Resolve(context.Background(), "deploymnt", "", "")
	var kn *KindNotFoundError
	if !errors.As(err, &kn) || !slices.Contains(kn.Suggestions, "deployments.apps") {
		t.Fatalf("err = %v", err)
	}
}

func TestLevenshtein(t *testing.T) {
	for _, c := range []struct {
		a, b string
		d    int
	}{{"", "", 0}, {"a", "", 1}, {"kitten", "sitting", 3}, {"deploymnt", "deployment", 1}, {"é", "e", 1}} {
		if got := levenshtein(c.a, c.b); got != c.d {
			t.Errorf("levenshtein(%q,%q) = %d, want %d", c.a, c.b, got, c.d)
		}
	}
}

package kube

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	utiljson "k8s.io/apimachinery/pkg/util/json"
)

// FakeClient is an in-memory Client for tests. Seed it with objects (any
// kind, as JSON trees), logs and metrics; it serves them with the same
// semantics as the live client: pagination (Limit/Continue), label and field
// selectors, namespaces, NotFound errors, Resolve over discovery data.
//
// Objects are stored per group, kind, namespace and name; the version is not
// part of the key (an API server serves an object at every version), so
// List/Get of any version of a group+kind see the same objects. Objects are
// normalised like the live client's (integers are int64) and every read
// returns a deep copy. All methods are safe for concurrent use; the setters
// return the client so they chain.
type FakeClient struct {
	mu          sync.Mutex
	version     string
	groups      []string // explicit APIGroups override
	resources   []ResourceInfo
	objects     map[fakeKey]map[string]any
	logs        map[logKey]string
	prevLogs    map[logKey]string
	metricsOn   bool
	nodeMetrics []map[string]any
	podMetrics  []map[string]any
	now         func() time.Time
	fails       []failRule
	calls       []string
}

type fakeKey struct{ group, kind, ns, name string }
type logKey struct{ ns, pod, container string }
type failRule struct {
	method, resource string
	err              error
}

var _ Client = (*FakeClient)(nil)

// NewFakeClient returns a client with DefaultResources discovery, server
// version "v1.31.0", no metrics, the real clock, and objs added.
func NewFakeClient(objs ...map[string]any) *FakeClient {
	f := &FakeClient{
		version:   "v1.31.0",
		resources: DefaultResources(),
		objects:   map[fakeKey]map[string]any{},
		logs:      map[logKey]string{},
		prevLogs:  map[logKey]string{},
		now:       time.Now,
	}
	return f.Add(objs...)
}

// Add stores objects (replacing any with the same group, kind, namespace and
// name). Each needs apiVersion, kind and metadata.name; Add panics otherwise.
// Unknown group/kinds are registered in discovery automatically (plural =
// lower-case kind + "s", namespaced if the object has a namespace).
func (f *FakeClient) Add(objs ...map[string]any) *FakeClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, o := range objs {
		obj := normalize(o)
		apiVersion, _ := obj["apiVersion"].(string)
		kind, _ := obj["kind"].(string)
		name := objName(obj)
		group, version, ok := splitGroupVersion(apiVersion)
		if !ok || kind == "" || name == "" {
			panic(fmt.Sprintf("kube.FakeClient.Add: object needs apiVersion, kind and metadata.name: %v", o))
		}
		ns := objNamespace(obj)
		if _, ok := f.resourceForKind(group, kind); !ok {
			f.resources = append(f.resources, ResourceInfo{
				Resource:  Resource{Group: group, Version: version, Resource: strings.ToLower(kind) + "s", Kind: kind, Namespaced: ns != ""},
				Singular:  strings.ToLower(kind),
				Verbs:     []string{"get", "list", "watch"},
				Preferred: true,
			})
		}
		f.objects[fakeKey{group, kind, ns, name}] = obj
	}
	return f
}

// AddResources adds discovery entries (e.g. CRDs, or extra versions).
func (f *FakeClient) AddResources(infos ...ResourceInfo) *FakeClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resources = append(f.resources, infos...)
	return f
}

// SetResources replaces the whole discovery data.
func (f *FakeClient) SetResources(infos ...ResourceInfo) *FakeClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resources = slices.Clone(infos)
	return f
}

// SetServerVersion sets what ServerVersion returns.
func (f *FakeClient) SetServerVersion(v string) *FakeClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version = v
	return f
}

// SetAPIGroups overrides APIGroups (otherwise derived from the resources,
// plus metrics.k8s.io/v1beta1 while metrics are available).
func (f *FakeClient) SetAPIGroups(groupVersions ...string) *FakeClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groups = slices.Clone(groupVersions)
	return f
}

// SetNow fixes the clock used by Events' since filter.
func (f *FakeClient) SetNow(t time.Time) *FakeClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = func() time.Time { return t }
	return f
}

// SetLogs sets the current log of a container.
func (f *FakeClient) SetLogs(ns, pod, container, text string) *FakeClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logs[logKey{ns, pod, container}] = text
	return f
}

// SetPreviousLogs sets the log of a container's previous instance.
func (f *FakeClient) SetPreviousLogs(ns, pod, container, text string) *FakeClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prevLogs[logKey{ns, pod, container}] = text
	return f
}

// SetNodeMetrics makes metrics available and sets the NodeMetrics items.
func (f *FakeClient) SetNodeMetrics(items ...map[string]any) *FakeClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.metricsOn = true
	f.nodeMetrics = normalizeAll(items)
	return f
}

// SetPodMetrics makes metrics available and sets the PodMetrics items.
func (f *FakeClient) SetPodMetrics(items ...map[string]any) *FakeClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.metricsOn = true
	f.podMetrics = normalizeAll(items)
	return f
}

// SetMetricsUnavailable makes the metrics methods return ErrMetricsUnavailable.
func (f *FakeClient) SetMetricsUnavailable() *FakeClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.metricsOn = false
	return f
}

// FailOn makes method (a Client method name such as "List") return err.
// resource restricts it to one plural resource name ("" = any call); for
// PodLogs the resource is "pods", for Events "events".
func (f *FakeClient) FailOn(method, resource string, err error) *FakeClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fails = append(f.fails, failRule{method, resource, err})
	return f
}

// Calls returns the calls made so far, e.g. "List pods default".
func (f *FakeClient) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// begin records a call and returns an injected error, if any. Callers hold mu.
func (f *FakeClient) begin(method, resource string, args ...string) error {
	parts := []string{method}
	for _, a := range append([]string{resource}, args...) {
		if a != "" {
			parts = append(parts, a)
		}
	}
	f.calls = append(f.calls, strings.Join(parts, " "))
	for _, r := range f.fails {
		if r.method == method && (r.resource == "" || r.resource == resource) {
			return r.err
		}
	}
	return nil
}

// ServerVersion implements Client.
func (f *FakeClient) ServerVersion(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("ServerVersion", ""); err != nil {
		return "", err
	}
	return f.version, ctx.Err()
}

// APIGroups implements Client.
func (f *FakeClient) APIGroups(ctx context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("APIGroups", ""); err != nil {
		return nil, err
	}
	if f.groups != nil {
		return slices.Clone(f.groups), ctx.Err()
	}
	var out []string
	add := func(gv string) {
		if !slices.Contains(out, gv) {
			out = append(out, gv)
		}
	}
	for _, r := range f.resources {
		add(r.GroupVersion())
	}
	if f.metricsOn {
		add("metrics.k8s.io/v1beta1")
	}
	return out, ctx.Err()
}

// Resolve implements Client.
func (f *FakeClient) Resolve(ctx context.Context, kindOrResource, group, version string) (Resource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("Resolve", kindOrResource, group, version); err != nil {
		return Resource{}, err
	}
	if err := ctx.Err(); err != nil {
		return Resource{}, err
	}
	return resolveIn(f.resources, kindOrResource, group, version)
}

// List implements Client.
func (f *FakeClient) List(ctx context.Context, r Resource, ns string, opts ListOptions) (ListResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("List", r.Resource, ns); err != nil {
		return ListResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return ListResult{}, err
	}
	info, ok := f.served(r)
	if !ok {
		return ListResult{}, NewAPIError(ErrNotFound, "list", r.String(), ns, "", "the server could not find the requested resource")
	}
	if opts.Limit < 0 {
		return ListResult{}, NewAPIError(nil, "list", r.String(), ns, "", "limit must not be negative")
	}
	lsel, err := labels.Parse(opts.LabelSelector)
	if err != nil {
		return ListResult{}, NewAPIError(nil, "list", r.String(), ns, "", "invalid label selector: "+err.Error())
	}
	fsel, err := fields.ParseSelector(opts.FieldSelector)
	if err != nil {
		return ListResult{}, NewAPIError(nil, "list", r.String(), ns, "", "invalid field selector: "+err.Error())
	}
	var items []map[string]any
	for k, obj := range f.objects {
		if k.group != info.Group || k.kind != info.Kind {
			continue
		}
		if info.Namespaced && ns != "" && k.ns != ns {
			continue
		}
		if !lsel.Matches(objLabels(obj)) || !fsel.Matches(objFields(obj, fsel)) {
			continue
		}
		items = append(items, obj)
	}
	slices.SortFunc(items, func(a, b map[string]any) int {
		return cmp.Or(strings.Compare(objNamespace(a), objNamespace(b)), strings.Compare(objName(a), objName(b)))
	})

	start := 0
	if opts.Continue != "" {
		start, err = strconv.Atoi(opts.Continue)
		if err != nil || start < 0 || start > len(items) {
			return ListResult{}, NewAPIError(nil, "list", r.String(), ns, "", "invalid continue token; restart the list without it")
		}
	}
	end := len(items)
	if opts.Limit > 0 && int64(end-start) > opts.Limit {
		end = start + int(opts.Limit)
	}
	res := ListResult{Items: deepCopyAll(items[start:end])}
	if end < len(items) {
		res.Continue = strconv.Itoa(end)
		rem := int64(len(items) - end)
		res.RemainingItemCount = &rem
	}
	return res, nil
}

// Get implements Client.
func (f *FakeClient) Get(ctx context.Context, r Resource, ns, name string) (map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("Get", r.Resource, ns, name); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, ok := f.served(r)
	if !ok {
		return nil, NewAPIError(ErrNotFound, "get", r.String(), ns, name, "the server could not find the requested resource")
	}
	if !info.Namespaced {
		ns = ""
	}
	obj, ok := f.objects[fakeKey{info.Group, info.Kind, ns, name}]
	if !ok {
		return nil, NewAPIError(ErrNotFound, "get", r.String(), ns, name, fmt.Sprintf("%s %q not found", r.String(), name))
	}
	return deepCopy(obj).(map[string]any), nil
}

// Events implements Client.
func (f *FakeClient) Events(ctx context.Context, ns string, involved *ObjectRef, since time.Duration) ([]map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("Events", "events", ns); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var items []map[string]any
	for k, obj := range f.objects {
		if k.group != "" || k.kind != "Event" || (ns != "" && k.ns != ns) {
			continue
		}
		if involved != nil {
			io, _ := obj["involvedObject"].(map[string]any)
			match := func(field, want string) bool {
				got, _ := io[field].(string)
				return want == "" || got == want
			}
			if !match("kind", involved.Kind) || !match("namespace", involved.Namespace) ||
				!match("name", involved.Name) || !match("uid", involved.UID) {
				continue
			}
		}
		items = append(items, obj)
	}
	return deepCopyAll(sinceAndSort(items, since, f.now())), nil
}

// PodLogs implements Client. SinceSeconds is accepted but not applied.
func (f *FakeClient) PodLogs(ctx context.Context, ns, pod string, o LogOptions) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("PodLogs", "pods", ns, pod); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	podObj, podExists := f.objects[fakeKey{"", "Pod", ns, pod}]
	var containers []string
	for _, m := range []map[logKey]string{f.logs, f.prevLogs} {
		for k := range m {
			if k.ns == ns && k.pod == pod && !slices.Contains(containers, k.container) {
				containers = append(containers, k.container)
			}
		}
	}
	if podExists {
		cs, _ := nested(podObj, "spec", "containers").([]any)
		for _, c := range cs {
			if n, _ := nested(asMap(c), "name").(string); n != "" && !slices.Contains(containers, n) {
				containers = append(containers, n)
			}
		}
	}
	slices.Sort(containers)
	if !podExists && len(containers) == 0 {
		return "", NewAPIError(ErrNotFound, "get", "pods/log", ns, pod, fmt.Sprintf("pods %q not found", pod))
	}
	c := o.Container
	switch {
	case c == "" && len(containers) == 0:
		return "", nil
	case c == "" && len(containers) == 1:
		c = containers[0]
	case c == "":
		return "", NewAPIError(nil, "get", "pods/log", ns, pod,
			fmt.Sprintf("a container name must be specified for pod %s, choose one of: %s", pod, strings.Join(containers, ", ")))
	case !slices.Contains(containers, c):
		return "", NewAPIError(nil, "get", "pods/log", ns, pod, fmt.Sprintf("container %s is not valid for pod %s", c, pod))
	}
	src := f.logs
	if o.Previous {
		src = f.prevLogs
	}
	text, ok := src[logKey{ns, pod, c}]
	if !ok && o.Previous {
		return "", NewAPIError(nil, "get", "pods/log", ns, pod, fmt.Sprintf("previous terminated container %q in pod %q not found", c, pod))
	}
	text = tailLines(text, o.TailLines)
	if o.LimitBytes > 0 && len(text) > o.LimitBytes {
		text = text[:o.LimitBytes]
	}
	return text, nil
}

// NodeMetrics implements Client.
func (f *FakeClient) NodeMetrics(ctx context.Context) ([]map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("NodeMetrics", "nodes"); err != nil {
		return nil, err
	}
	if !f.metricsOn {
		return nil, ErrMetricsUnavailable
	}
	return deepCopyAll(f.nodeMetrics), ctx.Err()
}

// PodMetrics implements Client.
func (f *FakeClient) PodMetrics(ctx context.Context, ns string) ([]map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("PodMetrics", "pods", ns); err != nil {
		return nil, err
	}
	if !f.metricsOn {
		return nil, ErrMetricsUnavailable
	}
	var out []map[string]any
	for _, m := range f.podMetrics {
		if ns == "" || objNamespace(m) == ns {
			out = append(out, m)
		}
	}
	return deepCopyAll(out), ctx.Err()
}

// served finds the discovery entry for r by group and resource name (or kind
// when the name is empty).
func (f *FakeClient) served(r Resource) (ResourceInfo, bool) {
	for _, in := range f.resources {
		if in.Group == r.Group && (in.Resource.Resource == r.Resource || (r.Resource == "" && in.Kind == r.Kind)) {
			return in, true
		}
	}
	return ResourceInfo{}, false
}

func (f *FakeClient) resourceForKind(group, kind string) (ResourceInfo, bool) {
	for _, in := range f.resources {
		if in.Group == group && in.Kind == kind {
			return in, true
		}
	}
	return ResourceInfo{}, false
}

func objLabels(obj map[string]any) labels.Set {
	set := labels.Set{}
	m, _ := nested(obj, "metadata", "labels").(map[string]any)
	for k, v := range m {
		set[k] = fmt.Sprint(v)
	}
	return set
}

// objFields exposes every field the selector asks about by its dotted path.
func objFields(obj map[string]any, sel fields.Selector) fields.Set {
	set := fields.Set{}
	for _, req := range sel.Requirements() {
		v := nested(obj, strings.Split(req.Field, ".")...)
		if v != nil {
			set[req.Field] = fmt.Sprint(v)
		} else {
			set[req.Field] = ""
		}
	}
	return set
}

func tailLines(text string, n int) string {
	if n <= 0 || text == "" {
		return text
	}
	trailing := strings.HasSuffix(text, "\n")
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) <= n {
		return text
	}
	out := strings.Join(lines[len(lines)-n:], "\n")
	if trailing {
		out += "\n"
	}
	return out
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// normalize turns any JSON-able tree into the live client's representation:
// map[string]any, []any, string, bool, int64, float64, nil.
func normalize(obj map[string]any) map[string]any {
	b, err := json.Marshal(obj)
	if err != nil {
		panic(fmt.Sprintf("kube: object is not JSON-serialisable: %v", err))
	}
	var out map[string]any
	if err := utiljson.Unmarshal(b, &out); err != nil {
		panic(fmt.Sprintf("kube: object does not round-trip through JSON: %v", err))
	}
	return out
}

func normalizeAll(items []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		out = append(out, normalize(it))
	}
	return out
}

// deepCopy copies a normalised JSON tree.
func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, e := range t {
			m[k] = deepCopy(e)
		}
		return m
	case []any:
		s := make([]any, len(t))
		for i, e := range t {
			s[i] = deepCopy(e)
		}
		return s
	default:
		return t
	}
}

func deepCopyAll(items []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		out = append(out, deepCopy(it).(map[string]any))
	}
	return out
}

// Object returns a minimal object; namespace "" makes it cluster-scoped.
// Add fields to the returned map as needed.
func Object(apiVersion, kind, namespace, name string) map[string]any {
	md := map[string]any{"name": name}
	if namespace != "" {
		md["namespace"] = namespace
	}
	return map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": md}
}

// WithLabels sets metadata.labels on obj and returns it.
func WithLabels(obj map[string]any, l map[string]string) map[string]any {
	md, _ := obj["metadata"].(map[string]any)
	if md == nil {
		md = map[string]any{}
		obj["metadata"] = md
	}
	m := map[string]any{}
	for k, v := range l {
		m[k] = v
	}
	md["labels"] = m
	return obj
}

// Event returns a core/v1 Event about kind/name in ns, last seen at.
func Event(ns, name, involvedKind, involvedName, eventType, reason, message string, at time.Time) map[string]any {
	ts := at.UTC().Format(time.RFC3339)
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Event",
		"metadata":   map[string]any{"name": name, "namespace": ns, "creationTimestamp": ts},
		"involvedObject": map[string]any{
			"kind": involvedKind, "name": involvedName, "namespace": ns,
		},
		"type":           eventType,
		"reason":         reason,
		"message":        message,
		"count":          int64(1),
		"firstTimestamp": ts,
		"lastTimestamp":  ts,
		"source":         map[string]any{"component": "fake"},
	}
}

// NodeMetric returns a metrics.k8s.io NodeMetrics item.
func NodeMetric(node, cpu, memory string) map[string]any {
	return map[string]any{
		"apiVersion": "metrics.k8s.io/v1beta1",
		"kind":       "NodeMetrics",
		"metadata":   map[string]any{"name": node},
		"window":     "30s",
		"usage":      map[string]any{"cpu": cpu, "memory": memory},
	}
}

// PodMetric returns a metrics.k8s.io PodMetrics item; containers maps a
// container name to its {cpu, memory} usage.
func PodMetric(ns, pod string, containers map[string][2]string) map[string]any {
	var cs []any
	for _, name := range slices.Sorted(maps.Keys(containers)) {
		u := containers[name]
		cs = append(cs, map[string]any{"name": name, "usage": map[string]any{"cpu": u[0], "memory": u[1]}})
	}
	return map[string]any{
		"apiVersion": "metrics.k8s.io/v1beta1",
		"kind":       "PodMetrics",
		"metadata":   map[string]any{"name": pod, "namespace": ns},
		"window":     "30s",
		"containers": cs,
	}
}

// DefaultResources is the discovery data of a typical cluster with Flux and
// Gateway API installed, in server priority order (core first).
func DefaultResources() []ResourceInfo {
	verbs := []string{"get", "list", "watch"}
	r := func(group, version, plural, kind string, namespaced bool, short ...string) ResourceInfo {
		return ResourceInfo{
			Resource:   Resource{Group: group, Version: version, Resource: plural, Kind: kind, Namespaced: namespaced},
			Singular:   strings.ToLower(kind),
			ShortNames: short,
			Verbs:      verbs,
			Preferred:  true,
		}
	}
	return []ResourceInfo{
		r("", "v1", "pods", "Pod", true, "po"),
		r("", "v1", "services", "Service", true, "svc"),
		r("", "v1", "configmaps", "ConfigMap", true, "cm"),
		r("", "v1", "secrets", "Secret", true),
		r("", "v1", "events", "Event", true, "ev"),
		r("", "v1", "namespaces", "Namespace", false, "ns"),
		r("", "v1", "nodes", "Node", false, "no"),
		r("", "v1", "serviceaccounts", "ServiceAccount", true, "sa"),
		r("", "v1", "endpoints", "Endpoints", true, "ep"),
		r("", "v1", "persistentvolumeclaims", "PersistentVolumeClaim", true, "pvc"),
		r("", "v1", "persistentvolumes", "PersistentVolume", false, "pv"),
		r("apps", "v1", "deployments", "Deployment", true, "deploy"),
		r("apps", "v1", "statefulsets", "StatefulSet", true, "sts"),
		r("apps", "v1", "daemonsets", "DaemonSet", true, "ds"),
		r("apps", "v1", "replicasets", "ReplicaSet", true, "rs"),
		r("events.k8s.io", "v1", "events", "Event", true, "ev"),
		r("autoscaling", "v2", "horizontalpodautoscalers", "HorizontalPodAutoscaler", true, "hpa"),
		r("batch", "v1", "jobs", "Job", true),
		r("batch", "v1", "cronjobs", "CronJob", true, "cj"),
		r("networking.k8s.io", "v1", "ingresses", "Ingress", true, "ing"),
		r("networking.k8s.io", "v1", "networkpolicies", "NetworkPolicy", true, "netpol"),
		r("policy", "v1", "poddisruptionbudgets", "PodDisruptionBudget", true, "pdb"),
		r("storage.k8s.io", "v1", "storageclasses", "StorageClass", false, "sc"),
		r("apiextensions.k8s.io", "v1", "customresourcedefinitions", "CustomResourceDefinition", false, "crd", "crds"),
		r("kustomize.toolkit.fluxcd.io", "v1", "kustomizations", "Kustomization", true, "ks"),
		r("helm.toolkit.fluxcd.io", "v2", "helmreleases", "HelmRelease", true, "hr"),
		r("source.toolkit.fluxcd.io", "v1", "gitrepositories", "GitRepository", true, "gitrepo"),
		r("source.toolkit.fluxcd.io", "v1", "helmrepositories", "HelmRepository", true, "helmrepo"),
		r("source.toolkit.fluxcd.io", "v1", "helmcharts", "HelmChart", true, "hc"),
		r("source.toolkit.fluxcd.io", "v1", "ocirepositories", "OCIRepository", true, "ocirepo"),
		r("source.toolkit.fluxcd.io", "v1", "buckets", "Bucket", true),
		r("gateway.networking.k8s.io", "v1", "gatewayclasses", "GatewayClass", false, "gc"),
		r("gateway.networking.k8s.io", "v1", "gateways", "Gateway", true, "gtw"),
		r("gateway.networking.k8s.io", "v1", "httproutes", "HTTPRoute", true),
	}
}

// FakeFactory is an in-memory Factory over named FakeClients. Set the fields
// before use; the zero Allow allows every context.
type FakeFactory struct {
	Clients map[string]*FakeClient
	Current string
	Allow   Allowlist
}

var _ Factory = (*FakeFactory)(nil)

// NewFakeFactory returns a factory whose current context is current.
func NewFakeFactory(current string, clients map[string]*FakeClient) *FakeFactory {
	return &FakeFactory{Clients: clients, Current: current}
}

// SingleFakeFactory returns a factory with one context, "fake", that is
// current and allowed.
func SingleFakeFactory(c *FakeClient) *FakeFactory {
	return NewFakeFactory("fake", map[string]*FakeClient{"fake": c})
}

// Contexts implements Factory.
func (f *FakeFactory) Contexts() []ContextInfo {
	return contextInfos(slices.Collect(maps.Keys(f.Clients)), f.Current, f.Allow)
}

// For implements Factory.
func (f *FakeFactory) For(name string) (Client, error) {
	name, err := checkContext(name, f.Current, func(n string) bool { _, ok := f.Clients[n]; return ok }, f.Allow)
	if err != nil {
		return nil, err
	}
	return f.Clients[name], nil
}

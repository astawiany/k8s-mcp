package kube

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

const (
	metricsGroup = "metrics.k8s.io"
	// maxEventPages bounds Events: 10 pages of 500.
	maxEventPages = 10
	eventPageSize = 500
)

// liveClient talks to one cluster. Only get/list/log/discovery requests are
// issued: the dynamic client is used for Get and List only, the typed core
// client for pod logs only.
type liveClient struct {
	cfg  *rest.Config
	dyn  dynamic.Interface
	disc discovery.CachedDiscoveryInterfaceWithContext
	core corev1client.CoreV1Interface
}

var _ Client = (*liveClient)(nil)

func newLiveClient(cfg *rest.Config) (*liveClient, error) {
	cfg = rest.CopyConfig(cfg)
	cfg.UserAgent = "k8s-mcp (read-only)"
	if cfg.QPS == 0 {
		cfg.QPS, cfg.Burst = 20, 40
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, err
	}
	core, err := corev1client.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &liveClient{cfg: cfg, dyn: dyn, disc: memory.NewMemCacheClientWithContext(dc), core: core}, nil
}

// ServerVersion implements Client.
func (c *liveClient) ServerVersion(ctx context.Context) (string, error) {
	v, err := c.disc.ServerVersionWithContext(ctx)
	if err != nil {
		return "", mapErr(err, "get", "version", "", "")
	}
	return v.GitVersion, nil
}

// APIGroups implements Client.
func (c *liveClient) APIGroups(ctx context.Context) ([]string, error) {
	gl, err := c.disc.ServerGroupsWithContext(ctx)
	if err != nil {
		return nil, mapErr(err, "get", "discovery", "", "")
	}
	var out []string
	for _, g := range gl.Groups {
		for _, v := range g.Versions {
			out = append(out, v.GroupVersion)
		}
	}
	return out, nil
}

// infos returns discovery entries, tolerating groups that fail to discover
// (an unavailable aggregated API must not break everything else).
func (c *liveClient) infos(ctx context.Context) ([]ResourceInfo, error) {
	groups, lists, err := c.disc.ServerGroupsAndResourcesWithContext(ctx)
	if err != nil && !discovery.IsGroupDiscoveryFailedError(err) {
		return nil, mapErr(err, "get", "discovery", "", "")
	}
	return infosFromDiscovery(groups, lists), nil
}

// Resolve implements Client. On a miss the discovery cache is refreshed once,
// so CRDs installed after the first call are found.
func (c *liveClient) Resolve(ctx context.Context, kindOrResource, group, version string) (Resource, error) {
	infos, err := c.infos(ctx)
	if err != nil {
		return Resource{}, err
	}
	r, err := resolveIn(infos, kindOrResource, group, version)
	if errors.Is(err, ErrKindNotFound) && kindOrResource != "" {
		c.disc.InvalidateWithContext(ctx)
		if infos, ierr := c.infos(ctx); ierr == nil {
			r, err = resolveIn(infos, kindOrResource, group, version)
		}
	}
	return r, err
}

func gvr(r Resource) schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: r.Group, Version: r.Version, Resource: r.Resource}
}

func (c *liveClient) resource(r Resource, ns string) dynamic.ResourceInterface {
	ri := c.dyn.Resource(gvr(r))
	if r.Namespaced && ns != "" {
		return ri.Namespace(ns)
	}
	return ri
}

// List implements Client.
func (c *liveClient) List(ctx context.Context, r Resource, ns string, opts ListOptions) (ListResult, error) {
	if opts.Limit < 0 {
		return ListResult{}, NewAPIError(nil, "list", r.String(), ns, "", "limit must not be negative")
	}
	l, err := c.resource(r, ns).List(ctx, metav1.ListOptions{
		LabelSelector: opts.LabelSelector,
		FieldSelector: opts.FieldSelector,
		Limit:         opts.Limit,
		Continue:      opts.Continue,
	})
	if err != nil {
		return ListResult{}, mapErr(err, "list", r.String(), nsIf(r, ns), "")
	}
	return ListResult{Items: items(l), Continue: l.GetContinue(), RemainingItemCount: l.GetRemainingItemCount()}, nil
}

// Get implements Client.
func (c *liveClient) Get(ctx context.Context, r Resource, ns, name string) (map[string]any, error) {
	o, err := c.resource(r, ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, mapErr(err, "get", r.String(), nsIf(r, ns), name)
	}
	return o.Object, nil
}

// Events implements Client.
func (c *liveClient) Events(ctx context.Context, ns string, involved *ObjectRef, since time.Duration) ([]map[string]any, error) {
	r := Resource{Version: "v1", Resource: "events", Kind: "Event", Namespaced: true}
	opts := metav1.ListOptions{FieldSelector: involvedFieldSelector(involved), Limit: eventPageSize}
	var all []map[string]any
	for range maxEventPages {
		l, err := c.resource(r, ns).List(ctx, opts)
		if err != nil {
			return nil, mapErr(err, "list", "events", ns, "")
		}
		all = append(all, items(l)...)
		if opts.Continue = l.GetContinue(); opts.Continue == "" {
			break
		}
	}
	return sinceAndSort(all, since, time.Now()), nil
}

// PodLogs implements Client.
func (c *liveClient) PodLogs(ctx context.Context, ns, pod string, o LogOptions) (string, error) {
	limit := int64(o.LimitBytes)
	if limit <= 0 {
		limit = DefaultLogLimitBytes
	}
	po := &corev1.PodLogOptions{Container: o.Container, Previous: o.Previous, LimitBytes: &limit}
	if o.TailLines > 0 {
		t := int64(o.TailLines)
		po.TailLines = &t
	}
	if o.SinceSeconds > 0 {
		s := int64(o.SinceSeconds)
		po.SinceSeconds = &s
	}
	rc, err := c.core.Pods(ns).GetLogs(pod, po).Stream(ctx)
	if err != nil {
		return "", mapErr(err, "get", "pods/log", ns, pod)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil {
		return "", mapErr(err, "get", "pods/log", ns, pod)
	}
	return string(b), nil
}

// NodeMetrics implements Client.
func (c *liveClient) NodeMetrics(ctx context.Context) ([]map[string]any, error) {
	return c.metrics(ctx, "nodes", "NodeMetrics", false, "")
}

// PodMetrics implements Client.
func (c *liveClient) PodMetrics(ctx context.Context, ns string) ([]map[string]any, error) {
	return c.metrics(ctx, "pods", "PodMetrics", true, ns)
}

func (c *liveClient) metrics(ctx context.Context, res, kind string, namespaced bool, ns string) ([]map[string]any, error) {
	gl, err := c.disc.ServerGroupsWithContext(ctx)
	if err != nil {
		return nil, mapErr(err, "get", "discovery", "", "")
	}
	version := ""
	for _, g := range gl.Groups {
		if g.Name == metricsGroup {
			version = g.PreferredVersion.Version
		}
	}
	if version == "" {
		return nil, ErrMetricsUnavailable
	}
	r := Resource{Group: metricsGroup, Version: version, Resource: res, Kind: kind, Namespaced: namespaced}
	l, err := c.resource(r, ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) || apierrors.IsServiceUnavailable(err) {
			return nil, fmt.Errorf("%w (%s)", ErrMetricsUnavailable, err.Error())
		}
		return nil, mapErr(err, "list", r.String(), ns, "")
	}
	return items(l), nil
}

func items(l *unstructured.UnstructuredList) []map[string]any {
	out := make([]map[string]any, 0, len(l.Items))
	for i := range l.Items {
		out = append(out, l.Items[i].Object)
	}
	return out
}

func nsIf(r Resource, ns string) string {
	if r.Namespaced {
		return ns
	}
	return ""
}

// mapErr turns client-go errors into *APIError with a sentinel kind, keeping
// the server's message verbatim.
func mapErr(err error, verb, resource, ns, name string) error {
	var kind error
	var netErr net.Error
	switch {
	case apierrors.IsForbidden(err):
		kind = ErrForbidden
	case apierrors.IsUnauthorized(err):
		kind = ErrUnauthorized
	case apierrors.IsNotFound(err):
		kind = ErrNotFound
	case apierrors.IsTimeout(err), apierrors.IsServerTimeout(err),
		errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &netErr) && netErr.Timeout():
		kind = ErrTimeout
	}
	msg := err.Error()
	var se apierrors.APIStatus
	if errors.As(err, &se) && se.Status().Message != "" {
		msg = se.Status().Message
	}
	return &APIError{Verb: verb, Resource: resource, Namespace: ns, Name: name, Message: msg, kind: kind}
}

package kube

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
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
	// maxEventPages bounds how much Events reads: 40 pages of 500.
	maxEventPages = 40
	eventPageSize = 500
	// guardGrace is added to the request timeout before a call is abandoned,
	// so ordinary timeouts surface from client-go first.
	guardGrace = time.Second
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

// guarded runs one request (or one discovery round) and abandons it when it
// outlives budget. client-go runs exec credential plugins without a context,
// so a hanging plugin would otherwise block the call forever; the abandoned
// goroutine ends when the plugin exits.
func guarded[T any](ctx context.Context, budget time.Duration, fn func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := fn(ctx)
		ch <- result{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

// budget is the abandonment deadline for one request; discovery fans out
// one request per group version in parallel, so it gets two timeouts.
func (c *liveClient) budget() time.Duration          { return c.cfg.Timeout + guardGrace }
func (c *liveClient) discoveryBudget() time.Duration { return 2*c.cfg.Timeout + guardGrace }

// ServerVersion implements Client.
func (c *liveClient) ServerVersion(ctx context.Context) (string, error) {
	v, err := guarded(ctx, c.budget(), func(ctx context.Context) (string, error) {
		v, err := c.disc.ServerVersionWithContext(ctx)
		if err != nil {
			return "", err
		}
		return v.GitVersion, nil
	})
	if err != nil {
		return "", mapErr(err, "get", "version", "", "")
	}
	return v, nil
}

func (c *liveClient) groups(ctx context.Context) (*metav1.APIGroupList, error) {
	gl, err := guarded(ctx, c.discoveryBudget(), c.disc.ServerGroupsWithContext)
	if err != nil {
		return nil, mapErr(err, "get", "discovery", "", "")
	}
	return gl, nil
}

// APIGroups implements Client.
func (c *liveClient) APIGroups(ctx context.Context) ([]string, error) {
	gl, err := c.groups(ctx)
	if err != nil {
		return nil, err
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
	type disc struct {
		groups []*metav1.APIGroup
		lists  []*metav1.APIResourceList
	}
	d, err := guarded(ctx, c.discoveryBudget(), func(ctx context.Context) (disc, error) {
		g, l, err := c.disc.ServerGroupsAndResourcesWithContext(ctx)
		if err != nil && discovery.IsGroupDiscoveryFailedError(err) {
			err = nil
		}
		return disc{g, l}, err
	})
	if err != nil {
		return nil, mapErr(err, "get", "discovery", "", "")
	}
	return infosFromDiscovery(d.groups, d.lists), nil
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

func (c *liveClient) list(ctx context.Context, r Resource, ns string, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	return guarded(ctx, c.budget(), func(ctx context.Context) (*unstructured.UnstructuredList, error) {
		return c.resource(r, ns).List(ctx, opts)
	})
}

// List implements Client.
func (c *liveClient) List(ctx context.Context, r Resource, ns string, opts ListOptions) (ListResult, error) {
	if opts.Limit < 0 {
		return ListResult{}, NewAPIError(nil, "list", r.String(), ns, "", "limit must not be negative")
	}
	l, err := c.list(ctx, r, ns, metav1.ListOptions{
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
	o, err := guarded(ctx, c.budget(), func(ctx context.Context) (*unstructured.Unstructured, error) {
		return c.resource(r, ns).Get(ctx, name, metav1.GetOptions{})
	})
	if err != nil {
		return nil, mapErr(err, "get", r.String(), nsIf(r, ns), name)
	}
	return o.Object, nil
}

// Events implements Client. It reads at most maxEventPages pages, then keeps
// the newest maxEvents (see sinceAndSort).
func (c *liveClient) Events(ctx context.Context, ns string, involved *ObjectRef, since time.Duration) ([]map[string]any, error) {
	r := Resource{Version: "v1", Resource: "events", Kind: "Event", Namespaced: true}
	opts := metav1.ListOptions{FieldSelector: involvedFieldSelector(involved), Limit: eventPageSize}
	var all []map[string]any
	for range maxEventPages {
		l, err := c.list(ctx, r, ns, opts)
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
	out, err := guarded(ctx, c.budget(), func(ctx context.Context) (string, error) {
		rc, err := c.core.Pods(ns).GetLogs(pod, po).Stream(ctx)
		if err != nil {
			return "", err
		}
		defer func() { _ = rc.Close() }()
		b, err := io.ReadAll(io.LimitReader(rc, limit))
		return string(b), err
	})
	if err != nil {
		return "", mapErr(err, "get", "pods/log", ns, pod)
	}
	return out, nil
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
	gl, err := c.groups(ctx)
	if err != nil {
		return nil, err
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
	l, err := c.list(ctx, r, ns, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) || apierrors.IsServiceUnavailable(err) {
			// Only the server's status message, never the transport error.
			return nil, &APIError{Verb: "list", Resource: r.String(), Namespace: ns, Message: statusMessage(err), kind: ErrMetricsUnavailable}
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

// statusMessage is the API server's own message of a status error, or "".
func statusMessage(err error) string {
	var se apierrors.APIStatus
	if errors.As(err, &se) {
		return se.Status().Message
	}
	return ""
}

// mapErr turns client-go errors into *APIError with a sentinel kind.
//
// API status errors (the server answered) keep the server's message verbatim.
// Every other error is replaced by a fixed message per class: client-go's
// transport errors quote the request URL (server host and path), and exec
// plugin errors quote the plugin command, none of which may reach a tool
// result.
func mapErr(err error, verb, resource, ns, name string) error {
	var se apierrors.APIStatus
	if errors.As(err, &se) {
		var kind error
		switch {
		case apierrors.IsForbidden(err):
			kind = ErrForbidden
		case apierrors.IsUnauthorized(err):
			kind = ErrUnauthorized
		case apierrors.IsNotFound(err):
			kind = ErrNotFound
		case apierrors.IsTimeout(err), apierrors.IsServerTimeout(err):
			kind = ErrTimeout
		}
		msg := se.Status().Message
		if msg == "" {
			msg = string(se.Status().Reason)
		}
		return &APIError{Verb: verb, Resource: resource, Namespace: ns, Name: name, Message: msg, kind: kind}
	}
	msg, kind := classifyTransport(err)
	return &APIError{Verb: verb, Resource: resource, Namespace: ns, Name: name, Message: msg, kind: kind}
}

// classifyTransport maps a non-API error to a sentinel and a fixed message
// that contains no detail from the error itself.
func classifyTransport(err error) (msg string, kind error) {
	var (
		netErr   net.Error
		opErr    *net.OpError
		dnsErr   *net.DNSError
		uaErr    x509.UnknownAuthorityError
		hostErr  x509.HostnameError
		certErr  x509.CertificateInvalidError
		tlsVErr  *tls.CertificateVerificationError
		tlsRHErr tls.RecordHeaderError
	)
	switch {
	// client-go formats plugin failures with %v, so only the text identifies them.
	case strings.Contains(err.Error(), "getting credentials:"):
		return "run any kubectl command with this context to see why", ErrCredentialPlugin
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "no response within the request timeout", ErrTimeout
	case errors.Is(err, context.Canceled):
		return "request canceled", nil
	case errors.As(err, &dnsErr), errors.As(err, &opErr), errors.As(err, &uaErr), errors.As(err, &hostErr),
		errors.As(err, &certErr), errors.As(err, &tlsVErr), errors.As(err, &tlsRHErr),
		errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "check that the cluster is up and the context is right", ErrUnreachable
	}
	return "transport error talking to the API server (details withheld: they can contain the server address)", nil
}

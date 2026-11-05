// Package kube is the read-only Kubernetes access layer. Tools depend on the
// small Client and Factory interfaces declared here, never on client-go, so
// they can be tested against FakeClient/FakeFactory.
//
// Read-only by construction: Client has only get/list/log/discovery methods
// (readonly_test.go fails on any method named like a write), and the package
// sources never call a client-go write method or import a write helper.
package kube

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DefaultTimeout bounds every request a live client sends.
const DefaultTimeout = 15 * time.Second

// Client reads from one cluster (one kubeconfig context). Every method is
// read-only; objects are returned as unstructured JSON trees.
type Client interface {
	// ServerVersion returns the server's git version, e.g. "v1.31.2".
	ServerVersion(ctx context.Context) (string, error)
	// APIGroups returns every served group/version, e.g. "v1", "apps/v1".
	APIGroups(ctx context.Context) ([]string, error)
	// Resolve maps a resource name (plural, singular or short name) or a Kind,
	// case-insensitively, to a served resource. group and version are optional
	// filters ("core" names the legacy group). Several matches resolve to the
	// group's preferred version, then to the server's group priority order.
	// Unknown names return a *KindNotFoundError listing close matches.
	Resolve(ctx context.Context, kindOrResource, group, version string) (Resource, error)
	// List lists objects of r in namespace ns ("" = all namespaces; ignored
	// for cluster-scoped resources).
	List(ctx context.Context, r Resource, ns string, opts ListOptions) (ListResult, error)
	// Get reads one object.
	Get(ctx context.Context, r Resource, ns, name string) (map[string]any, error)
	// Events lists core/v1 events in ns ("" = all), optionally only those
	// about involved, and only those seen within since (0 = no bound), oldest
	// first. At most 5000 events are returned: when there are more, the
	// NEWEST are kept (by last-seen time). The live client reads at most 40
	// pages of 500 events before applying this cap.
	Events(ctx context.Context, ns string, involved *ObjectRef, since time.Duration) ([]map[string]any, error)
	// PodLogs reads a container's log.
	PodLogs(ctx context.Context, ns, pod string, o LogOptions) (string, error)
	// NodeMetrics lists metrics.k8s.io NodeMetrics, or ErrMetricsUnavailable.
	NodeMetrics(ctx context.Context) ([]map[string]any, error)
	// PodMetrics lists metrics.k8s.io PodMetrics in ns ("" = all), or
	// ErrMetricsUnavailable.
	PodMetrics(ctx context.Context, ns string) ([]map[string]any, error)
}

// MutatingMethodPrefixes returns the method-name prefixes that Client and
// Factory must never have (write or interactive verbs; "Delete" also covers
// DeleteCollection). readonly_test.go checks the declarations by AST and
// test/injection checks the compiled method sets by reflection.
func MutatingMethodPrefixes() []string {
	return []string{"Create", "Update", "Patch", "Delete", "Apply", "Exec", "PortForward",
		"Attach", "Evict", "Scale", "Set"}
}

// Factory hands out one cached Client per kubeconfig context.
type Factory interface {
	// Contexts lists the kubeconfig contexts sorted by name. It never returns
	// server URLs, users, credentials or any other kubeconfig content.
	Contexts() []ContextInfo
	// For returns the client for a context; "" means the current context.
	// Errors wrap ErrUnknownContext or ErrContextNotAllowed.
	For(name string) (Client, error)
}

// ContextInfo describes a kubeconfig context without any connection details.
type ContextInfo struct {
	Name    string `json:"name"`
	Current bool   `json:"current"`
	Allowed bool   `json:"allowed"`
}

// Resource identifies a served resource (like schema.GroupVersionResource
// plus Kind and scope). Group "" is the core (legacy) group.
type Resource struct {
	Group      string `json:"group"`
	Version    string `json:"version"`
	Resource   string `json:"resource"` // plural, lower-case, e.g. "deployments"
	Kind       string `json:"kind"`
	Namespaced bool   `json:"namespaced"`
}

// GroupVersion returns the apiVersion string, e.g. "v1" or "apps/v1".
func (r Resource) GroupVersion() string {
	if r.Group == "" {
		return r.Version
	}
	return r.Group + "/" + r.Version
}

// String returns kubectl's fully qualified name, e.g. "deployments.apps".
func (r Resource) String() string {
	if r.Group == "" {
		return r.Resource
	}
	return r.Resource + "." + r.Group
}

// ResourceInfo is one discovery entry: a Resource plus the names it answers to.
type ResourceInfo struct {
	Resource
	Singular   string
	ShortNames []string
	Verbs      []string
	// Preferred is true when Version is the group's preferred version.
	Preferred bool
}

// ListOptions narrow a List call. Limit 0 means no limit; Continue is the
// opaque token from a previous ListResult.
type ListOptions struct {
	LabelSelector string
	FieldSelector string
	Limit         int64
	Continue      string
}

// ListResult is one page of objects. Continue is "" on the last page.
type ListResult struct {
	Items              []map[string]any
	Continue           string
	RemainingItemCount *int64
}

// ObjectRef selects the object events are about. Empty fields match anything.
type ObjectRef struct {
	Kind      string
	Namespace string
	Name      string
	UID       string
}

// LogOptions select which log to read and how much of it. Zero values mean
// "not set". LimitBytes caps the bytes read; live clients cap at
// DefaultLogLimitBytes when it is 0.
type LogOptions struct {
	Container    string
	TailLines    int
	Previous     bool
	SinceSeconds int
	LimitBytes   int
}

// DefaultLogLimitBytes bounds a log read when LogOptions.LimitBytes is 0.
const DefaultLogLimitBytes = 4 << 20

// Sentinel errors. Use errors.Is; the concrete errors carry details.
var (
	ErrMetricsUnavailable = errors.New("metrics API (metrics.k8s.io) is not available on this cluster; install metrics-server")
	ErrUnknownContext     = errors.New("unknown kubeconfig context")
	ErrContextNotAllowed  = errors.New("kubeconfig context is not on the allowlist")
	ErrKindNotFound       = errors.New("kind not found")
	ErrNotFound           = errors.New("not found")
	ErrForbidden          = errors.New("forbidden by RBAC")
	ErrUnauthorized       = errors.New("unauthorized: credentials rejected or expired")
	ErrTimeout            = errors.New("API request timed out")
	ErrUnreachable        = errors.New("cannot reach the API server (connection, DNS or TLS error)")
	ErrCredentialPlugin   = errors.New("kubeconfig credential plugin (exec) failed")
	// ErrRefused marks a request the server refuses by policy (a Secret
	// under any spelling), before or after reading the cluster.
	ErrRefused = errors.New("refused by server policy")
)

// KindNotFoundError reports an unknown kind or resource name with up to five
// close matches in kubectl's "resource.group" form.
type KindNotFoundError struct {
	Query       string
	Group       string
	Version     string
	Suggestions []string
}

func (e *KindNotFoundError) Error() string {
	q := e.Query
	if e.Group != "" || e.Version != "" {
		q = fmt.Sprintf("%s (group %q, version %q)", e.Query, e.Group, e.Version)
	}
	msg := fmt.Sprintf("kind or resource %q not found on the server", q)
	if e.Query == "" {
		msg = "no kind or resource name given"
	}
	if len(e.Suggestions) > 0 {
		msg += "; did you mean: " + strings.Join(e.Suggestions, ", ")
	}
	return msg
}

// Unwrap makes errors.Is(err, ErrKindNotFound) true.
func (e *KindNotFoundError) Unwrap() error { return ErrKindNotFound }

// APIError is a failed API request. Message is the server's message verbatim
// (cluster-sourced text: tools must pass it through the result wrapper).
type APIError struct {
	Verb      string
	Resource  string
	Namespace string
	Name      string
	Message   string
	kind      error // one of the sentinels, or nil
}

// NewAPIError builds an APIError; kind is a sentinel such as ErrForbidden or
// ErrNotFound (nil for others). Fakes and tests use it to simulate failures.
func NewAPIError(kind error, verb, resource, ns, name, msg string) *APIError {
	return &APIError{Verb: verb, Resource: resource, Namespace: ns, Name: name, Message: msg, kind: kind}
}

func (e *APIError) Error() string {
	var b strings.Builder
	b.WriteString(e.Verb)
	b.WriteString(" ")
	b.WriteString(e.Resource)
	if e.Name != "" {
		fmt.Fprintf(&b, " %q", e.Name)
	}
	if e.Namespace != "" {
		fmt.Fprintf(&b, " in namespace %q", e.Namespace)
	}
	if e.kind != nil {
		b.WriteString(": ")
		b.WriteString(e.kind.Error())
	}
	if e.Message != "" {
		b.WriteString(": ")
		b.WriteString(e.Message)
	}
	return b.String()
}

// Unwrap exposes the sentinel kind for errors.Is.
func (e *APIError) Unwrap() error { return e.kind }

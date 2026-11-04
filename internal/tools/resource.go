package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/redact"
)

// Helpers shared by list_resources, get_resource, describe_resource and
// get_events.

// errSecretRefused is returned, before any object is read, for every request
// that names the core Secret kind in any spelling.
var errSecretRefused = errors.New("refused: this server never reads or returns Secret objects (kind Secret, resource secrets); " +
	"use RBAC-visible metadata such as a pod's volumes or envFrom references instead")

// clientFor returns the client of a kubeconfig context, explaining the
// allowlist when the context is not on it.
func clientFor(f kube.Factory, name string) (kube.Client, error) {
	c, err := f.For(name)
	if err != nil && errors.Is(err, kube.ErrContextNotAllowed) {
		return nil, fmt.Errorf("%w; start the server with a --contexts allowlist that includes it to use this context", err)
	}
	return c, err
}

// refuseSecret returns errSecretRefused when group/kind (or group/resource)
// names the core Secret kind.
func refuseSecret(group string, names ...string) error {
	for _, n := range names {
		if redact.IsSecretKind(group, n) {
			return errSecretRefused
		}
	}
	return nil
}

// resolveReadable resolves a kind, resource name or short name and refuses
// Secrets. The request as typed is checked first (so a Secret is refused
// even when discovery fails), then the resolved resource, which catches
// aliases such as short names and the "resource.group" form.
func resolveReadable(ctx context.Context, c kube.Client, kind, group, version string) (kube.Resource, error) {
	if err := refuseSecret(group, kind); err != nil {
		return kube.Resource{}, err
	}
	r, err := c.Resolve(ctx, kind, group, version)
	if err != nil {
		return kube.Resource{}, err
	}
	if err := refuseSecret(r.Group, r.Kind, r.Resource); err != nil {
		return kube.Resource{}, err
	}
	return r, nil
}

// objectIsSecret reports whether an object read from the cluster is a core
// Secret anyway (for example served under an unexpected resource name).
func objectIsSecret(obj map[string]any) bool {
	apiVersion, _ := obj["apiVersion"].(string)
	kind, _ := obj["kind"].(string)
	group := ""
	if g, _, ok := strings.Cut(apiVersion, "/"); ok {
		group = g
	}
	return refuseSecret(group, kind) != nil
}

// namespaceFor returns the namespace to use for r: "" for cluster-scoped
// resources (whatever was given), ns otherwise. When required is set a
// namespaced resource without a namespace is an error.
func namespaceFor(r kube.Resource, ns string, required bool) (string, error) {
	ns = strings.TrimSpace(ns)
	if !r.Namespaced {
		return "", nil
	}
	if ns == "" && required {
		return "", fmt.Errorf("namespace is required: %s is namespaced", r.String())
	}
	return ns, nil
}

// nested walks a JSON tree; nil when any step is missing.
func nested(obj map[string]any, path ...string) any {
	var cur any = obj
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

func str(obj map[string]any, path ...string) string {
	s, _ := nested(obj, path...).(string)
	return s
}

// num reads an integer field (int64 from the client, float64 from plain
// encoding/json); ok is false when absent.
func num(obj map[string]any, path ...string) (int64, bool) {
	switch v := nested(obj, path...).(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case float64:
		return int64(v), true
	}
	return 0, false
}

func list(obj map[string]any, path ...string) []any {
	l, _ := nested(obj, path...).([]any)
	return l
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

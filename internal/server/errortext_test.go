package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/astawiany/k8s-mcp/internal/kube"
)

func TestErrorTextActionable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want []string
	}{
		{"forbidden", kube.NewAPIError(kube.ErrForbidden, "list", "pods", "prod", "", `pods is forbidden: User "u" cannot list`),
			[]string{`list pods in namespace "prod": forbidden by RBAC`, "hint:", "cluster admin", "cannot list", "<<<DATA "}},
		{"not found", kube.NewAPIError(kube.ErrNotFound, "get", "deployments", "default", "web", ""),
			[]string{`get deployments "web" in namespace "default": not found`, "list_resources"}},
		{"kind suggestions", fmt.Errorf("resolve: %w", &kube.KindNotFoundError{Query: "deploy", Suggestions: []string{"deployments.apps"}}),
			[]string{"kind not found", "did you mean: deployments.apps"}},
		{"kind no suggestions", &kube.KindNotFoundError{Query: "zzz"}, []string{"kind not found", "cluster_info"}},
		{"unknown context", fmt.Errorf("x: %w", kube.ErrUnknownContext), []string{"unknown kubeconfig context", "list_contexts"}},
		{"not allowed", fmt.Errorf("x: %w", kube.ErrContextNotAllowed), []string{"allowlist", "list_contexts"}},
		{"metrics", kube.ErrMetricsUnavailable, []string{"metrics-server"}},
		{"unauthorized", kube.ErrUnauthorized, []string{"log in again"}},
		{"timeout", kube.ErrTimeout, []string{"timed out", "narrow"}},
		{"deadline", context.DeadlineExceeded, []string{"timed out", "narrow"}},
		{"unreachable", kube.ErrUnreachable, []string{"cannot reach", "running"}},
		{"plugin", kube.ErrCredentialPlugin, []string{"credential plugin", "refresh"}},
		{"plain", errors.New("bad input: namespace is required"), []string{"the tool failed", "namespace is required"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := errorText(c.err)
			for _, w := range c.want {
				if !strings.Contains(got, w) {
					t.Errorf("missing %q in:\n%s", w, got)
				}
			}
			if len(got) > lim.MaxBytes {
				t.Errorf("%d bytes > %d", len(got), lim.MaxBytes)
			}
		})
	}
}

func TestErrorTextHugeClusterMessageCapped(t *testing.T) {
	err := kube.NewAPIError(nil, "get", "pods", "", "p", strings.Repeat("<<<x\n", 1<<18))
	got := errorText(err)
	if len(got) > lim.MaxBytes {
		t.Errorf("%d bytes > %d", len(got), lim.MaxBytes)
	}
	if strings.Count(got, "<<<") != 2 {
		t.Errorf("want only the two envelope markers, got %d", strings.Count(got, "<<<"))
	}
}

func TestErrorTextRedactsTokenInMessage(t *testing.T) {
	tok := "ghp_" + strings.Repeat("Ab12", 9)
	if got := errorText(errors.New("auth failed with " + tok)); strings.Contains(got, tok) {
		t.Errorf("token leaked: %s", got)
	}
}

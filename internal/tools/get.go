package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/redact"
	"github.com/astawiany/k8s-mcp/internal/server"
)

// objectIn names one object; get_resource and describe_resource share it.
type objectIn struct {
	Context   string `json:"context,omitempty" jsonschema:"kubeconfig context name; defaults to the current context"`
	Kind      string `json:"kind" jsonschema:"kind, resource name or short name, any case: Pod, pods, po, deployments.apps"`
	Group     string `json:"group,omitempty" jsonschema:"API group filter, e.g. apps; core for the legacy group"`
	Version   string `json:"version,omitempty" jsonschema:"API version filter, e.g. v1"`
	Namespace string `json:"namespace,omitempty" jsonschema:"namespace; required for namespaced kinds, ignored for cluster-scoped kinds"`
	Name      string `json:"name" jsonschema:"object name"`
}

func registerGet(s *server.Server) {
	server.Register(s, &mcp.Tool{
		Name: "get_resource",
		Description: "Get one object of any kind as JSON, status included, metadata.managedFields removed. " +
			"Credential-looking values are masked (env values, probe headers and command flags with credential " +
			"names or token shapes, Secrets embedded in annotations such as last-applied-configuration). " +
			"Secrets are refused (kind Secret, secrets, any alias). Long strings and documents over 64 KiB are " +
			"truncated with a marker. Read-only: never creates, changes or deletes anything.",
	}, server.CapRead, getResource)
}

func getResource(ctx context.Context, f kube.Factory, in objectIn) (any, error) {
	o, err := readObject(ctx, f, in)
	if err != nil {
		return nil, err
	}
	return o.obj, nil
}

// readResult is one object read by readObject, already redacted.
type readResult struct {
	client kube.Client
	res    kube.Resource
	ns     string
	obj    map[string]any
}

// readObject resolves, refuses Secrets, reads and redacts (redact.Workload)
// one object.
func readObject(ctx context.Context, f kube.Factory, in objectIn) (readResult, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return readResult{}, fmt.Errorf("name is required")
	}
	c, err := clientFor(f, in.Context)
	if err != nil {
		return readResult{}, err
	}
	r, err := resolveReadable(ctx, c, in.Kind, in.Group, in.Version)
	if err != nil {
		return readResult{}, err
	}
	ns, err := namespaceFor(r, in.Namespace, true)
	if err != nil {
		return readResult{}, err
	}
	obj, err := c.Get(ctx, r, ns, name)
	if err != nil {
		return readResult{}, err
	}
	if objectIsSecret(obj) {
		return readResult{}, errSecretRefused
	}
	return readResult{client: c, res: r, ns: ns, obj: redact.Workload(obj)}, nil
}

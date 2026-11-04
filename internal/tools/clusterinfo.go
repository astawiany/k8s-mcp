package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/limits"
	"github.com/astawiany/k8s-mcp/internal/server"
)

type clusterInfoIn struct {
	Context string `json:"context,omitempty" jsonschema:"kubeconfig context name; defaults to the current context"`
}

type nodeSummary struct {
	Total    int      `json:"total"`
	Ready    int      `json:"ready"`
	NotReady []string `json:"notReady"`
	// Truncated is set when notReady holds only the first names or not every node was counted.
	Truncated bool `json:"truncated,omitempty"`
}

type apiGroupFlags struct {
	Metrics    bool `json:"metrics"`
	Flux       bool `json:"flux"`
	GatewayAPI bool `json:"gatewayAPI"`
}

type clusterInfoOut struct {
	Context       string        `json:"context"`
	ServerVersion string        `json:"serverVersion"`
	Nodes         nodeSummary   `json:"nodes"`
	APIGroups     apiGroupFlags `json:"apiGroups"`
}

// Node pages are read until the cluster has no more, bounded so a huge
// cluster cannot make one call unbounded.
const (
	nodePageSize = 500
	maxNodePages = 20
)

func registerClusterInfo(s *server.Server) {
	server.Register(s, &mcp.Tool{
		Name: "cluster_info",
		Description: "Summarise one cluster: server version, node counts (total, ready, names of not-ready nodes; " +
			"at most 200 names are listed, then truncated=true; at most 10000 nodes are counted) and whether " +
			"metrics-server, Flux and Gateway API are served. Reads nodes only; returns no server URLs.",
	}, server.CapRead, clusterInfo)
}

func clusterInfo(ctx context.Context, f kube.Factory, in clusterInfoIn) (any, error) {
	c, err := f.For(in.Context)
	if err != nil {
		if errors.Is(err, kube.ErrContextNotAllowed) {
			return nil, fmt.Errorf("%w; start the server with a --contexts allowlist that includes it to use this context", err)
		}
		return nil, err
	}
	name := in.Context
	if name == "" {
		for _, ci := range f.Contexts() {
			if ci.Current {
				name = ci.Name
			}
		}
	}
	out := clusterInfoOut{Context: name}
	if out.ServerVersion, err = c.ServerVersion(ctx); err != nil {
		return nil, err
	}
	groups, err := c.APIGroups(ctx)
	if err != nil {
		return nil, err
	}
	out.APIGroups = groupFlags(groups)
	if out.Nodes, err = summariseNodes(ctx, c); err != nil {
		return nil, err
	}
	return out, nil
}

func groupFlags(groupVersions []string) apiGroupFlags {
	var fl apiGroupFlags
	for _, gv := range groupVersions {
		g, _, _ := strings.Cut(gv, "/")
		switch {
		case g == "metrics.k8s.io":
			fl.Metrics = true
		case g == "gateway.networking.k8s.io":
			fl.GatewayAPI = true
		case strings.HasSuffix(g, ".toolkit.fluxcd.io"):
			fl.Flux = true
		}
	}
	return fl
}

func summariseNodes(ctx context.Context, c kube.Client) (nodeSummary, error) {
	res, err := c.Resolve(ctx, "nodes", "core", "")
	if err != nil {
		return nodeSummary{}, err
	}
	sum := nodeSummary{NotReady: []string{}}
	maxNames := limits.Default().MaxItems
	opts := kube.ListOptions{Limit: nodePageSize}
	for page := 0; page < maxNodePages; page++ {
		lr, err := c.List(ctx, res, "", opts)
		if err != nil {
			return nodeSummary{}, err
		}
		for _, n := range lr.Items {
			sum.Total++
			if nodeReady(n) {
				sum.Ready++
			} else if len(sum.NotReady) < maxNames {
				sum.NotReady = append(sum.NotReady, nodeName(n))
			} else {
				sum.Truncated = true
			}
		}
		if lr.Continue == "" {
			break
		}
		if page == maxNodePages-1 {
			sum.Truncated = true // more nodes exist than were counted
		}
		opts.Continue = lr.Continue
	}
	return sum, nil
}

func nodeName(n map[string]any) string {
	md, _ := n["metadata"].(map[string]any)
	s, _ := md["name"].(string)
	return s
}

// nodeReady reports whether the node's Ready condition is "True".
func nodeReady(n map[string]any) bool {
	st, _ := n["status"].(map[string]any)
	conds, _ := st["conditions"].([]any)
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if m["type"] == "Ready" {
			return m["status"] == "True"
		}
	}
	return false
}

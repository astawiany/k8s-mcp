package tools

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/limits"
	"github.com/astawiany/k8s-mcp/internal/server"
)

// metricsUnavailable is top's message when metrics.k8s.io is not served.
const metricsUnavailable = "metrics API (metrics-server) is not installed or not reachable"

type topIn struct {
	Context   string `json:"context,omitempty" jsonschema:"kubeconfig context name; defaults to the current context"`
	Namespace string `json:"namespace,omitempty" jsonschema:"namespace for scope pods; empty means all namespaces; ignored for nodes"`
	Scope     string `json:"scope" jsonschema:"nodes or pods"`
}

// topRow is one node or pod. The percent fields are set only for pods whose
// containers all declare that request.
type topRow struct {
	Name                    string   `json:"name"`
	Namespace               string   `json:"namespace,omitempty"`
	CPU                     string   `json:"cpu"`
	Memory                  string   `json:"memory"`
	CPUMillicores           int64    `json:"cpuMillicores"`
	MemoryBytes             int64    `json:"memoryBytes"`
	CPUPercentOfRequests    *float64 `json:"cpuPercentOfRequests,omitempty"`
	MemoryPercentOfRequests *float64 `json:"memoryPercentOfRequests,omitempty"`
}

type topOut struct {
	Scope     string   `json:"scope"`
	Available bool     `json:"available"`
	Message   string   `json:"message,omitempty"`
	Rows      []topRow `json:"rows"`
	Total     int      `json:"total"`
	Truncated bool     `json:"truncated"`
	Note      string   `json:"note,omitempty"`
}

func registerTop(s *server.Server) {
	server.Register(s, &mcp.Tool{
		Name: "top",
		Description: "Current CPU and memory usage from the metrics API (metrics-server), like kubectl top. " +
			"scope nodes or pods (pods optionally in one namespace). Rows {name, namespace, cpu, memory, " +
			"cpuMillicores, memoryBytes} sorted by CPU, highest first; pod rows add cpuPercentOfRequests and " +
			"memoryPercentOfRequests when every container of the pod declares that request. At most 200 rows " +
			"(truncated=true and total when more). Without metrics-server the result is {available: false, " +
			"message} instead of an error.",
	}, server.CapRead, top)
}

func top(ctx context.Context, f kube.Factory, in topIn) (any, error) {
	scope := strings.ToLower(strings.TrimSpace(in.Scope))
	if scope != "nodes" && scope != "pods" {
		return nil, errors.New(`scope must be "nodes" or "pods"`)
	}
	c, err := clientFor(f, in.Context)
	if err != nil {
		return nil, err
	}
	ns := strings.TrimSpace(in.Namespace)
	var items []map[string]any
	if scope == "nodes" {
		items, err = c.NodeMetrics(ctx)
	} else {
		items, err = c.PodMetrics(ctx, ns)
	}
	if errors.Is(err, kube.ErrMetricsUnavailable) {
		return topOut{Scope: scope, Message: metricsUnavailable, Rows: []topRow{}}, nil
	}
	if err != nil {
		return nil, err
	}

	out := topOut{Scope: scope, Available: true, Rows: []topRow{}}
	var reqs map[string]podRequests
	if scope == "pods" {
		reqs, err = readRequests(ctx, c, ns)
		if err != nil {
			out.Note = "pod specs could not be read, so percent of requests is not shown"
		}
	}
	for _, m := range items {
		row := topRow{Name: str(m, "metadata", "name"), Namespace: str(m, "metadata", "namespace")}
		if scope == "nodes" {
			row.CPUMillicores = milli(str(m, "usage", "cpu"))
			row.MemoryBytes = bytesOf(str(m, "usage", "memory"))
		} else {
			for _, ct := range list(m, "containers") {
				row.CPUMillicores += milli(str(asMap(ct), "usage", "cpu"))
				row.MemoryBytes += bytesOf(str(asMap(ct), "usage", "memory"))
			}
			if r, ok := reqs[row.Namespace+"/"+row.Name]; ok {
				row.CPUPercentOfRequests = percent(row.CPUMillicores, r.cpuMilli)
				row.MemoryPercentOfRequests = percent(row.MemoryBytes, r.memBytes)
			}
		}
		row.CPU = fmt.Sprintf("%dm", row.CPUMillicores)
		row.Memory = fmt.Sprintf("%dMi", row.MemoryBytes>>20)
		out.Rows = append(out.Rows, row)
	}
	slices.SortFunc(out.Rows, func(a, b topRow) int {
		return cmp.Or(cmp.Compare(b.CPUMillicores, a.CPUMillicores), cmp.Compare(b.MemoryBytes, a.MemoryBytes),
			strings.Compare(a.Namespace, b.Namespace), strings.Compare(a.Name, b.Name))
	})
	out.Total = len(out.Rows)
	if maxItems := limits.Default().MaxItems; len(out.Rows) > maxItems {
		out.Rows = out.Rows[:maxItems]
		out.Truncated = true
		note := limits.Note(fmt.Sprintf("%d rows, the %d with the highest CPU returned", out.Total, maxItems), "a namespace")
		out.Note = strings.TrimPrefix(out.Note+"; "+note, "; ")
	}
	return out, nil
}

// podRequests is the sum of a pod's container requests; 0 when any
// container does not declare it.
type podRequests struct{ cpuMilli, memBytes int64 }

// readRequests lists the pods in ns and returns their summed requests by
// "namespace/name". Only these numbers leave this function.
func readRequests(ctx context.Context, c kube.Client, ns string) (map[string]podRequests, error) {
	out := map[string]podRequests{}
	opts := kube.ListOptions{Limit: 500}
	for {
		page, err := c.List(ctx, kube.Resource{Version: "v1", Resource: "pods", Kind: "Pod", Namespaced: true}, ns, opts)
		if err != nil {
			return nil, err
		}
		for _, p := range page.Items {
			var r podRequests
			cpuKnown, memKnown := true, true
			cs := list(p, "spec", "containers")
			for _, ct := range cs {
				cpu, mem := str(asMap(ct), "resources", "requests", "cpu"), str(asMap(ct), "resources", "requests", "memory")
				cpuKnown = cpuKnown && cpu != ""
				memKnown = memKnown && mem != ""
				r.cpuMilli += milli(cpu)
				r.memBytes += bytesOf(mem)
			}
			if !cpuKnown || len(cs) == 0 {
				r.cpuMilli = 0
			}
			if !memKnown || len(cs) == 0 {
				r.memBytes = 0
			}
			out[str(p, "metadata", "namespace")+"/"+str(p, "metadata", "name")] = r
		}
		if page.Continue == "" {
			return out, nil
		}
		opts.Continue = page.Continue
	}
}

// percent returns used/requested in percent with one decimal, or nil when
// the request is unknown (0).
func percent(used, requested int64) *float64 {
	if requested <= 0 {
		return nil
	}
	p := math.Round(float64(used)*1000/float64(requested)) / 10
	return &p
}

// milli parses a CPU quantity to millicores (0 when unparsable).
func milli(q string) int64 {
	v, err := resource.ParseQuantity(q)
	if err != nil {
		return 0
	}
	return v.MilliValue()
}

// bytesOf parses a memory quantity to bytes (0 when unparsable).
func bytesOf(q string) int64 {
	v, err := resource.ParseQuantity(q)
	if err != nil {
		return 0
	}
	return v.Value()
}

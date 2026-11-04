package server

import (
	"context"
	"fmt"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/astawiany/k8s-mcp/internal/kube"
)

// Capability is what a tool may do. A tool can only be registered when its
// capability is enabled on the server.
type Capability string

// CapRead marks a tool that only reads (get, list, logs, discovery). It is
// the only capability enabled in stage 1.
const CapRead Capability = "read"

// Spec describes a registered tool, for the registry invariant tests.
type Spec struct {
	Name string
	Cap  Capability
}

// Register adds a tool whose result always passes through the result wrapper.
// The tool has no output schema (Out is any); its input schema is inferred
// from In unless t.InputSchema is set. h returns a Go value that encodes to
// JSON. Handlers should already redact what they return (redact.Workload and
// friends); the wrapper's redaction is only a backstop.
//
// Register panics (a programming error) when cap is not enabled on s, when
// t is nil or unnamed, or when a tool with the same name already exists.
func Register[In any](s *Server, t *mcp.Tool, cap Capability, h func(ctx context.Context, f kube.Factory, in In) (any, error)) {
	if t == nil || t.Name == "" {
		panic("server.Register: tool must have a name")
	}
	if h == nil {
		panic(fmt.Sprintf("server.Register: tool %q has a nil handler", t.Name))
	}
	if !s.enabled[cap] {
		panic(fmt.Sprintf("server.Register: tool %q needs capability %q, which is not enabled on this server", t.Name, cap))
	}
	s.mu.Lock()
	if _, dup := s.specs[t.Name]; dup {
		s.mu.Unlock()
		panic(fmt.Sprintf("server.Register: tool %q is already registered", t.Name))
	}
	s.specs[t.Name] = Spec{Name: t.Name, Cap: cap}
	s.mu.Unlock()

	name := t.Name
	mcp.AddTool[In, any](s.mcp, t, func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		// The handler's value never reaches the SDK: only the wrapper's
		// result does, and Out is always nil so the SDK adds nothing.
		return call(ctx, name, func(ctx context.Context) (any, error) { return h(ctx, s.factory, in) }), nil, nil
	})
}

// Tools returns the registered tools sorted by name.
func (s *Server) Tools() []Spec {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Spec, 0, len(s.specs))
	for _, sp := range s.specs {
		out = append(out, sp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Package tools holds the eleven MCP tools. Each tool lives in its own file
// as an input struct, a handler func(ctx, kube.Factory, In) (any, error) and
// a registerX func; RegisterAll is the one place that lists them.
package tools

import "github.com/astawiany/k8s-mcp/internal/server"

// RegisterAll registers every tool on s.
func RegisterAll(s *server.Server) {
	registerListContexts(s)
	registerClusterInfo(s)
	registerList(s)
	registerGet(s)
	registerDescribe(s)
	registerEvents(s)
	registerLogs(s)
	registerTop(s)
	registerHealth(s)
	registerFlux(s)
	registerDraftIssue(s)
}

package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/server"
)

type listContextsIn struct{}

func registerListContexts(s *server.Server) {
	server.Register(s, &mcp.Tool{
		Name: "list_contexts",
		Description: "List the kubeconfig contexts as [{name, current, allowed}]. Contexts outside the " +
			"server's --contexts allowlist are listed with allowed=false and cannot be used by any tool. " +
			"Never returns server URLs, users or credentials. Read-only: never creates, changes or deletes anything.",
	}, server.CapRead, listContexts)
}

func listContexts(_ context.Context, f kube.Factory, _ listContextsIn) (any, error) {
	return f.Contexts(), nil
}

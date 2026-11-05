// Command k8s-mcp is a read-only Model Context Protocol server for
// Kubernetes. It serves one MCP session over stdio and reads the clusters of
// a kubeconfig with the identity that kubeconfig grants.
//
// Usage:
//
//	k8s-mcp [--kubeconfig PATH] [--contexts LIST]
//	k8s-mcp --version
//
// stdout is the protocol channel: it carries JSON-RPC frames and nothing
// else (--version prints only the version). Every diagnostic goes to stderr.
// To keep a stray print from corrupting the protocol, main hands the real
// stdout to the transport and then points os.Stdout at stderr.
//
// Build: make build, or
//
//	CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=v1.2.3" ./cmd/k8s-mcp
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/server"
	"github.com/astawiany/k8s-mcp/internal/tools"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	stdin, stdout, stderr := os.Stdin, os.Stdout, os.Stderr
	// From here on only the transport holds the real stdout.
	os.Stdout = os.Stderr
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], stdin, stdout, stderr)
	stop()
	os.Exit(code)
}

// run parses args and serves until stdin closes or ctx is cancelled. It
// returns the process exit code: 0 on a clean shutdown, 1 on a startup or
// serving error, 2 on a usage error.
func run(ctx context.Context, args []string, stdin io.ReadCloser, stdout io.WriteCloser, stderr io.Writer) int {
	fs := flag.NewFlagSet("k8s-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	kubeconfig := fs.String("kubeconfig", "", "path to a kubeconfig file (default: $KUBECONFIG, then ~/.kube/config)")
	contexts := fs.String("contexts", "", "comma-separated kubeconfig context names or globs that tools may use, e.g. 'kind-*,staging'\n(default: every context; '*' does not match '/', so EKS ARNs need 'arn:*/*')")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "k8s-mcp %s: read-only Kubernetes MCP server over stdio.\n\nUsage: k8s-mcp [--kubeconfig PATH] [--contexts LIST]\n\n", version)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2 // the flag package already printed the error and usage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "k8s-mcp: unexpected argument %q (flags only; see --help)\n", fs.Arg(0))
		return 2
	}
	// Every flag is validated before --version prints, so a bad flag is
	// never hidden behind a successful exit.
	allow, err := kube.ParseAllowlist(*contexts)
	if err != nil {
		fmt.Fprintf(stderr, "k8s-mcp: invalid --contexts: %v\n", err)
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	// The kubeconfig error may name the file; it goes to stderr only, at
	// startup, never into a tool result.
	f, err := kube.NewFactory(*kubeconfig, allow)
	if err != nil {
		fmt.Fprintf(stderr, "k8s-mcp: %v\n", err)
		return 1
	}

	s := server.New(f, server.Options{Version: version})
	tools.RegisterAll(s)
	fmt.Fprintf(stderr, "k8s-mcp %s: serving MCP on stdio (read-only); allowed contexts: %s\n", version, allow)
	err = s.Run(ctx, &mcp.IOTransport{Reader: stdin, Writer: stdout})
	if err != nil && ctx.Err() == nil && !errors.Is(err, io.EOF) {
		fmt.Fprintf(stderr, "k8s-mcp: %v\n", err)
		return 1
	}
	fmt.Fprintln(stderr, "k8s-mcp: shut down")
	return 0
}

// Package server wires the MCP server: the tool registry, the capability
// gate and the single result wrapper every tool result passes through (spec
// sections 4, 6 and 6.1).
//
// Tools are added only with Register. Register never hands the tool's own
// return value to the MCP SDK: it calls the tool handler, then builds the
// CallToolResult itself (see wrap.go), so a tool cannot skip sanitising,
// size caps, the Secret backstop or the data envelope. Server does not
// expose the underlying *mcp.Server, so there is no other way to add a tool.
//
// The wrapper, in order, for a successful call:
//
//  1. encode the handler's Go value to JSON and decode it to a generic tree
//     (then the first backstop pass of step 3);
//  2. for every string, map keys included: replace it with redact.Redacted
//     if it holds a token shape (redact.EnvValue), cut a string larger than
//     MaxBytes before sanitising (to bound the cost), untrusted.Sanitize it,
//     cap it with limits.TruncateText(Default), and check the token shapes
//     again on the sanitised text;
//  3. backstop: redact.Object over the whole tree, which reduces any map
//     with kind Secret (any case, at any depth) to its metadata and masks
//     embedded Secrets in annotations. It runs twice: on the raw tree
//     before step 2 (an embedded Secret in an annotation is only found
//     while its JSON parses, so before any cut) and again after step 2
//     (kinds and keys hidden by invisible characters only match after
//     Sanitize);
//  4. encode the tree as compact JSON and cut the document so that the
//     escaped body plus the envelope fits MaxBytes, with a limits.Note;
//  5. untrusted.Wrap with a fresh untrusted.NewBoundary, as one TextContent.
//
// A handler error, or a panic, becomes an IsError result whose text comes
// from errorText: only fixed server-authored sentences (error class, hint)
// stay outside; the error's own text, which may quote the cluster, is
// sanitised, capped and placed in a data envelope.
//
// Sessions stay inside Run: the server never hands out an *mcp.ServerSession,
// whose Log and CreateMessage would reach the client outside the wrapper.
//
// The package must not import net/http or os/exec (tested).
package server

import (
	"context"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/untrusted"
)

// DefaultName is the implementation name announced to clients.
const DefaultName = "k8s-mcp"

// usageNotes follows untrusted.Preamble in the server instructions.
const usageNotes = `

Usage notes: every tool is read-only; no tool can create, change or delete anything in any cluster. Every tool takes an optional "context" (a kubeconfig context name; default: the current context); list_contexts shows which contexts exist and which are allowed. Results are JSON inside the data envelope described above. Large results are cut and end with a "[truncated: ...]" note that says how to narrow the request. Secret values are never returned: they appear as "[redacted]". Errors are returned as tool errors with a hint on how to recover; text quoted from the cluster inside an error is also placed in a data envelope.`

// Instructions is the text sent to clients as the server instructions.
const Instructions = untrusted.Preamble + usageNotes

// Options configures New.
type Options struct {
	// Name and Version identify the server to clients. Name defaults to
	// DefaultName and Version to "dev".
	Name    string
	Version string
}

// Server is the k8s-mcp MCP server. Create it with New, add tools with
// Register, then call Run.
type Server struct {
	mcp     *mcp.Server
	factory kube.Factory
	// enabled is the capability set. Stage 1 enables only CapRead and there
	// is deliberately no option or flag that adds to it.
	enabled map[Capability]bool

	mu    sync.Mutex
	specs map[string]Spec
}

// New returns a server whose tools read clusters through f.
func New(f kube.Factory, opts Options) *Server {
	if opts.Name == "" {
		opts.Name = DefaultName
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	return &Server{
		mcp: mcp.NewServer(
			&mcp.Implementation{Name: opts.Name, Version: opts.Version},
			&mcp.ServerOptions{Instructions: Instructions},
		),
		factory: f,
		enabled: map[Capability]bool{CapRead: true},
		specs:   map[string]Spec{},
	}
}

// Run serves one session over t (for example &mcp.StdioTransport{}) until
// the client disconnects or ctx is cancelled.
func (s *Server) Run(ctx context.Context, t mcp.Transport) error {
	return s.mcp.Run(ctx, t)
}

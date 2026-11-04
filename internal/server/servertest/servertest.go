// Package servertest connects an MCP client to a server.Server over
// in-memory transports, for tool tests (Tasks 7-13).
//
//	cs := servertest.NewTestSession(t, kube.SingleFakeFactory(fc), func(s *server.Server) {
//		tools.RegisterListContexts(s)
//	})
//	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_contexts"})
//	body := servertest.Payload(t, res) // JSON inside the data envelope
//
// Sessions are closed by t.Cleanup.
package servertest

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/server"
)

// NewTestSession builds a server over f, lets register add tools to it, and
// returns a connected, initialised client session.
func NewTestSession(t testing.TB, f kube.Factory, register func(*server.Server)) *mcp.ClientSession {
	t.Helper()
	s := server.New(f, server.Options{Version: "test"})
	if register != nil {
		register(s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	st, ct := mcp.NewInMemoryTransports()
	// Server.Run is the only way to serve (it never hands out the
	// ServerSession); connected tells us when the server side is up, since
	// the server must connect before the client.
	sig := &connectSignal{Transport: st, connected: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, sig) }()
	select {
	case <-sig.connected:
	case err := <-done:
		cancel()
		t.Fatalf("server run: %v", err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "servertest", Version: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		cancel()
		<-done
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() {
		_ = cs.Close()
		cancel()
		<-done
	})
	return cs
}

// connectSignal closes connected once the server side is connected.
type connectSignal struct {
	mcp.Transport
	connected chan struct{}
}

func (c *connectSignal) Connect(ctx context.Context) (mcp.Connection, error) {
	conn, err := c.Transport.Connect(ctx)
	if err == nil {
		close(c.connected)
	}
	return conn, err
}

// Payload checks that res is a successful result made of exactly one text
// content holding exactly one data envelope, and returns the envelope body
// (the JSON document). It fails the test otherwise.
func Payload(t testing.TB, res *mcp.CallToolResult) string {
	t.Helper()
	text := Text(t, res)
	if res.IsError {
		t.Fatalf("result is an error: %s", text)
	}
	body, ok := Unwrap(text)
	if !ok {
		t.Fatalf("result is not a single data envelope:\n%.2000s", text)
	}
	return body
}

// Text returns the text of a result that has exactly one TextContent, or
// fails the test.
func Text(t testing.TB, res *mcp.CallToolResult) string {
	t.Helper()
	if res == nil || len(res.Content) != 1 {
		t.Fatalf("want exactly one content item, got %+v", res)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("want *mcp.TextContent, got %T", res.Content[0])
	}
	return tc.Text
}

// Unwrap returns the body of text when text is exactly one envelope:
// "<<<DATA b>>>\n" + body + "\n<<<END b>>>" with b 32 lowercase hex
// characters, and body holding no "<<<" and no copy of b.
func Unwrap(text string) (body string, ok bool) {
	const open, end, sfx = "<<<DATA ", "<<<END ", ">>>"
	if !strings.HasPrefix(text, open) || len(text) < len(open)+32+len(sfx)+1 {
		return "", false
	}
	b := text[len(open) : len(open)+32]
	for _, r := range b {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return "", false
		}
	}
	head := open + b + sfx + "\n"
	tail := "\n" + end + b + sfx
	if !strings.HasPrefix(text, head) || !strings.HasSuffix(text, tail) || len(text) < len(head)+len(tail) {
		return "", false
	}
	body = text[len(head) : len(text)-len(tail)]
	if strings.Contains(body, "<<<") || strings.Contains(strings.ToLower(body), b) {
		return "", false
	}
	return body, true
}

// Boundary returns the boundary of an envelope (see Unwrap), or "".
func Boundary(text string) string {
	if _, ok := Unwrap(text); !ok {
		return ""
	}
	return text[len("<<<DATA ") : len("<<<DATA ")+32]
}

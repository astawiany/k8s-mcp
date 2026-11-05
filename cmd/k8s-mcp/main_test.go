package main

// These tests build the real binary and talk to it over stdio, the way
// Claude Code does. The child process gets a minimal environment (HOME and
// KUBECONFIG point into a temp dir, nothing else is inherited), so no host
// kubeconfig, credential or tool can influence the result. Building the
// binary uses the host's Go toolchain and module cache, as `go test` does.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/astawiany/k8s-mcp/internal/server/servertest"
)

// approvedTools are the eleven tools of spec section 5.
var approvedTools = []string{
	"cluster_info", "describe_resource", "draft_issue", "flux_status", "get_events", "get_resource",
	"list_contexts", "list_resources", "pod_logs", "top", "workload_health",
}

const testVersion = "v9.8.7-test"

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "k8s-mcp-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binPath = filepath.Join(dir, "k8s-mcp")
	build := exec.Command("go", "build", "-trimpath", "-ldflags", "-X main.version="+testVersion, "-o", binPath, ".")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "go build:", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// unreachableKubeconfig has two contexts pointing at a TEST-NET-1 address on
// a closed port; nothing in these tests contacts it.
const unreachableKubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: c
  cluster:
    server: https://192.0.2.1:1
contexts:
- name: kind-a
  context: {cluster: c, user: u}
- name: kind-b
  context: {cluster: c, user: u}
current-context: kind-a
users:
- name: u
  user:
    token: not-a-real-token
`

// childEnv returns a temp HOME with a kubeconfig and the env for the child.
func childEnv(t *testing.T) []string {
	t.Helper()
	home := t.TempDir()
	kc := filepath.Join(home, "config.yaml")
	if err := os.WriteFile(kc, []byte(unreachableKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{"HOME=" + home, "KUBECONFIG=" + kc}
}

// syncBuffer is a goroutine-safe bytes.Buffer.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// runOnce runs the binary to completion with no stdin.
func runOnce(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = childEnv(t)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code = 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run: %v", err)
	}
	return out.String(), errb.String(), code
}

func TestVersionPrintsOnlyTheVersion(t *testing.T) {
	out, errOut, code := runOnce(t, "--version")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if out != testVersion+"\n" {
		t.Errorf("stdout = %q, want exactly %q", out, testVersion+"\n")
	}
	if errOut != "" {
		t.Errorf("stderr = %q, want empty", errOut)
	}
}

func TestInvalidFlagsExitNonZeroWithMessageOnStderr(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"bad glob", []string{"--contexts", "kind-["}, "--contexts"},
		// Flags are validated before --version prints anything.
		{"bad glob with --version", []string{"--version", "--contexts", "["}, "--contexts"},
		{"bad glob before --version", []string{"--contexts", "[", "--version"}, "--contexts"},
		{"unknown flag", []string{"--write"}, "write"},
		{"positional arg", []string{"extra"}, "unexpected argument"},
		{"missing kubeconfig", []string{"--kubeconfig", "/nonexistent/k8s-mcp-test/config"}, "kubeconfig"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, code := runOnce(t, tc.args...)
			if code == 0 {
				t.Errorf("exit 0, want non-zero")
			}
			if out != "" {
				t.Errorf("stdout = %q, want empty", out)
			}
			if !strings.Contains(errOut, tc.want) {
				t.Errorf("stderr = %q, want it to mention %q", errOut, tc.want)
			}
		})
	}
}

// proc is a running binary with a connected MCP client.
type proc struct {
	cs     *mcp.ClientSession
	cmd    *exec.Cmd
	stdout *syncBuffer   // every byte the child wrote to stdout
	eof    chan struct{} // closed when the child's stdout reached EOF
	stderr *syncBuffer
}

// start launches the binary over stdio. A copier goroutine reads the child's
// stdout to EOF into p.stdout and forwards it to the client while the client
// is open, so bytes written after the session ended are captured too.
func start(t *testing.T, args ...string) *proc {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = childEnv(t)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	clientR, clientW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &proc{cmd: cmd, stdout: &syncBuffer{}, eof: make(chan struct{}), stderr: &syncBuffer{}}
	cmd.Stdout, cmd.Stderr = outW, p.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = outW.Close() // the child holds the only write end now
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		_ = outR.Close()
		_ = clientR.Close()
	})
	go func() {
		defer close(p.eof)
		fwd := clientW
		buf := make([]byte, 32*1024)
		for {
			n, err := outR.Read(buf)
			if n > 0 {
				_, _ = p.stdout.Write(buf[:n])
				if fwd != nil {
					if _, werr := fwd.Write(buf[:n]); werr != nil {
						fwd = nil // the client closed; keep capturing
					}
				}
			}
			if err != nil {
				_ = clientW.Close()
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "main-test", Version: "test"}, nil).
		Connect(ctx, &mcp.IOTransport{Reader: clientR, Writer: stdin}, nil)
	if err != nil {
		t.Fatalf("connect: %v\nstderr: %s", err, p.stderr.String())
	}
	p.cs = cs
	return p
}

// wait waits for the child to exit and its stdout to be fully captured, and
// returns its exit code.
func (p *proc) wait(t *testing.T) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	timeout := time.After(15 * time.Second)
	var code int
	select {
	case err := <-done:
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("wait: %v", err)
		}
	case <-timeout:
		t.Fatalf("server did not exit\nstderr: %s", p.stderr.String())
	}
	select {
	case <-p.eof:
	case <-timeout:
		t.Fatal("child stdout never reached EOF")
	}
	return code
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	slices.Sort(names)
	return names
}

// assertOnlyProtocolFrames fails unless every stdout line is a JSON-RPC 2.0
// message.
func assertOnlyProtocolFrames(t *testing.T, stdout string) {
	t.Helper()
	if stdout == "" {
		t.Fatal("no bytes on stdout")
	}
	if !strings.HasSuffix(stdout, "\n") {
		t.Errorf("stdout does not end with a newline: %q", stdout[max(0, len(stdout)-80):])
	}
	for i, line := range strings.Split(strings.TrimSuffix(stdout, "\n"), "\n") {
		var msg map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Errorf("stdout line %d is not JSON: %q", i+1, line)
			continue
		}
		if string(msg["jsonrpc"]) != `"2.0"` {
			t.Errorf("stdout line %d is not a JSON-RPC 2.0 frame: %q", i+1, line)
		}
	}
}

func TestStdioServesTheApprovedToolsAndOnlyProtocolFrames(t *testing.T) {
	s := start(t, "--contexts", "kind-*")
	if got := s.cs.InitializeResult().ServerInfo; got.Name != "k8s-mcp" || got.Version != testVersion {
		t.Errorf("serverInfo = %+v", got)
	}
	if names := toolNames(t, s.cs); !slices.Equal(names, approvedTools) {
		t.Errorf("tools/list = %v\nwant exactly %v", names, approvedTools)
	}
	if _, err := s.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_contexts", Arguments: map[string]any{}}); err != nil {
		t.Fatalf("list_contexts: %v", err)
	}
	if err := s.cs.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
	if code := s.wait(t); code != 0 {
		t.Errorf("exit %d after stdin closed, want 0\nstderr: %s", code, s.stderr.String())
	}
	assertOnlyProtocolFrames(t, s.stdout.String())
}

// TestCommandTransport is the plain SDK client path (mcp.CommandTransport),
// as a stdio MCP host runs the server.
func TestCommandTransport(t *testing.T) {
	cmd := exec.Command(binPath)
	cmd.Env = childEnv(t)
	var errb syncBuffer
	cmd.Stderr = &errb
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "main-test", Version: "test"}, nil).
		Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect: %v\nstderr: %s", err, errb.String())
	}
	if names := toolNames(t, cs); !slices.Equal(names, approvedTools) {
		t.Errorf("tools/list = %v\nwant exactly %v", names, approvedTools)
	}
	if err := cs.Close(); err != nil {
		t.Errorf("close: %v\nstderr: %s", err, errb.String())
	}
}

func TestContextsAllowlistWithNoMatchAllowsNothing(t *testing.T) {
	s := start(t, "--contexts", "nomatch")
	res, err := s.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_contexts", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	var got []struct {
		Name    string `json:"name"`
		Allowed bool   `json:"allowed"`
	}
	if err := json.Unmarshal([]byte(servertest.Payload(t, res)), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("contexts = %+v, want kind-a and kind-b", got)
	}
	for _, c := range got {
		if c.Allowed {
			t.Errorf("context %s allowed=true with --contexts nomatch", c.Name)
		}
	}
	// A tool on a disallowed context is refused without contacting it.
	res, err = s.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "cluster_info", Arguments: map[string]any{"context": "kind-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Errorf("cluster_info on a disallowed context succeeded")
	}
}

func TestSIGTERMShutsDownCleanly(t *testing.T) {
	s := start(t)
	toolNames(t, s.cs) // the server is up and serving
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := s.wait(t); code != 0 {
		t.Errorf("exit %d after SIGTERM, want 0\nstderr: %s", code, s.stderr.String())
	}
	assertOnlyProtocolFrames(t, s.stdout.String())
}

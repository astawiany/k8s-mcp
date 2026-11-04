package injection_test

// Test layer 2 of spec section 6.1: blast-radius invariants. They fail when a
// tool outside the approved read-only set is registered, when a kube
// interface gains a mutating method, or when module code outside
// internal/kube could reach the network or start a process.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/server"
	"github.com/astawiany/k8s-mcp/internal/server/servertest"
	"github.com/astawiany/k8s-mcp/internal/tools"
)

// approvedTools are the eleven tools of spec section 5. Changing this list is
// a design change: it needs a new spec, not a test edit.
var approvedTools = []string{
	"cluster_info", "describe_resource", "draft_issue", "flux_status", "get_events", "get_resource",
	"list_contexts", "list_resources", "pod_logs", "top", "workload_health",
}

func TestToolRegistryIsExactlyTheApprovedReadOnlySet(t *testing.T) {
	s := server.New(kube.SingleFakeFactory(kube.NewFakeClient()), server.Options{Version: "test"})
	tools.RegisterAll(s)
	var names []string
	for _, sp := range s.Tools() {
		names = append(names, sp.Name)
		if sp.Cap != server.CapRead {
			t.Errorf("tool %s has capability %q; stage 1 allows only %q", sp.Name, sp.Cap, server.CapRead)
		}
	}
	if !slices.Equal(names, approvedTools) {
		t.Errorf("registered tools = %v\nwant exactly %v", names, approvedTools)
	}

	// What a client sees must match the registry.
	cs := servertest.NewTestSession(t, kube.SingleFakeFactory(kube.NewFakeClient()), tools.RegisterAll)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var listed []string
	for _, tl := range res.Tools {
		listed = append(listed, tl.Name)
	}
	slices.Sort(listed)
	if !slices.Equal(listed, approvedTools) {
		t.Errorf("tools/list = %v\nwant exactly %v", listed, approvedTools)
	}
}

// limitRe: every cluster-reading description states a cap or a cut.
var limitRe = regexp.MustCompile(`(?i)at most|capped|truncat|KiB`)

func TestToolDescriptionsStateLimits(t *testing.T) {
	cs := servertest.NewTestSession(t, kube.SingleFakeFactory(kube.NewFakeClient()), tools.RegisterAll)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		d := strings.ToLower(tl.Description)
		if d == "" {
			t.Errorf("%s: empty description", tl.Name)
			continue
		}
		if !strings.Contains(d, "read-only") {
			t.Errorf("%s: description does not say it is read-only: %q", tl.Name, tl.Description)
		}
		if tl.Name != "list_contexts" && !limitRe.MatchString(d) {
			t.Errorf("%s: description states no cap or cut: %q", tl.Name, tl.Description)
		}
	}
}

// TestKubeInterfacesHaveNoMutatingMethods checks the compiled method sets
// (embedded interfaces included) against kube.MutatingMethodPrefixes; the
// kube package's own test checks the declarations.
func TestKubeInterfacesHaveNoMutatingMethods(t *testing.T) {
	for _, it := range []reflect.Type{reflect.TypeFor[kube.Client](), reflect.TypeFor[kube.Factory]()} {
		if bad := mutatingMethods(it); len(bad) > 0 {
			t.Errorf("kube.%s has mutating methods: %v", it.Name(), bad)
		}
	}
}

func mutatingMethods(it reflect.Type) []string {
	var bad []string
	for m := range it.Methods() {
		for _, p := range kube.MutatingMethodPrefixes() {
			if strings.HasPrefix(m.Name, p) {
				bad = append(bad, m.Name)
				break
			}
		}
	}
	return bad
}

type mutator interface {
	Get() error
	DeleteCollection() error
	PortForward() error
}

func TestMutatingMethodCheckBites(t *testing.T) {
	if got := mutatingMethods(reflect.TypeFor[mutator]()); !slices.Equal(got, []string{"DeleteCollection", "PortForward"}) {
		t.Errorf("mutatingMethods = %v", got)
	}
}

// netDir is the only directory whose code may reach the network: the
// cluster clients.
const netDir = "internal/kube"

// netImport reports imports that can open connections (or build a cluster
// client) and so are allowed only in netDir.
func netImport(p string) bool {
	switch {
	case p == "net", p == "net/http", strings.HasPrefix(p, "net/http/"), p == "net/rpc", p == "net/smtp",
		p == "crypto/tls", strings.HasPrefix(p, "golang.org/x/net/"), strings.HasPrefix(p, "k8s.io/client-go"),
		p == "golang.org/x/sys/unix", p == "k8s.io/apimachinery/pkg/util/net":
		return true
	}
	return false
}

// Imports and selectors no non-test file of the module may use.
var (
	processImports = []string{"os/exec", "plugin"}
	// pkg path -> selector names: process starts anywhere, dialers and HTTP
	// clients outside netDir, SDK transports that dial, spawn or listen.
	processSelectors = map[string][]string{
		"os":                    {"StartProcess"},
		"syscall":               {"Exec", "ForkExec", "StartProcess"},
		"golang.org/x/sys/unix": {"Exec", "ForkExec", "StartProcess"},
	}
	dialSelectors = map[string][]string{
		"net":                              {"Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP", "DialUnix", "Dialer", "Listen", "ListenTCP", "ListenUDP", "ListenPacket"},
		"net/http":                         {"Client", "Transport", "DefaultClient", "DefaultTransport", "Get", "Post", "PostForm", "Head", "NewRequest", "NewRequestWithContext", "ListenAndServe", "Serve"},
		"crypto/tls":                       {"Dial", "DialWithDialer", "Dialer"},
		"syscall":                          {"Socket", "Connect"},
		"golang.org/x/sys/unix":            {"Socket", "Connect"},
		"k8s.io/apimachinery/pkg/util/net": {"DialerFor", "DialerFunc", "SetTransportDefaults", "SetOldTransportDefaults", "NewProxierWithNoProxyCIDR"},
		"github.com/modelcontextprotocol/go-sdk/mcp": {"CommandTransport", "StreamableClientTransport", "SSEClientTransport",
			"StreamableServerTransport", "SSEServerTransport", "NewStreamableHTTPHandler", "NewSSEHandler",
			"StreamableHTTPHandler", "SSEHandler"},
	}
)

// blastRadiusViolations checks one Go source file; rel is its slash path
// relative to the module root.
func blastRadiusViolations(t *testing.T, rel, src string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), rel, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	inNet := strings.HasPrefix(rel, netDir+"/")
	var bad []string
	local := map[string]string{} // local name -> import path
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		name := p[strings.LastIndex(p, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		local[name] = p
		if slices.Contains(processImports, p) {
			bad = append(bad, "import "+p)
		}
		if netImport(p) && !inNet {
			bad = append(bad, "import "+p+" outside "+netDir)
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		p, ok := local[id.Name]
		if !ok {
			return true
		}
		if slices.Contains(processSelectors[p], sel.Sel.Name) {
			bad = append(bad, "use "+p+"."+sel.Sel.Name)
		}
		if !inNet && slices.Contains(dialSelectors[p], sel.Sel.Name) {
			bad = append(bad, "use "+p+"."+sel.Sel.Name+" outside "+netDir)
		}
		return true
	})
	return bad
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil || !strings.Contains(string(b), "module github.com/astawiany/k8s-mcp\n") {
		t.Fatalf("module root not found at %s: %v", root, err)
	}
	return root
}

// TestModuleSourceBlastRadius scans every non-test .go file of the module
// (test/ included: the eval payload printer is a binary) outside testdata,
// vendor and hidden directories.
func TestModuleSourceBlastRadius(t *testing.T) {
	root := moduleRoot(t)
	var scanned []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned = append(scanned, rel)
		if bad := blastRadiusViolations(t, rel, string(src)); len(bad) > 0 {
			t.Errorf("%s: %v", rel, bad)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, must := range []string{"internal/kube/live.go", "internal/server/wrap.go", "internal/tools/register.go",
		"test/injection/eval/payload/main.go", "test/injection/corpus/corpus.go"} {
		if !slices.Contains(scanned, must) {
			t.Errorf("scan missed %s (scanned %d files)", must, len(scanned))
		}
	}
}

// Bite proof of the scanner on synthetic sources.
func TestBlastRadiusCheckerBites(t *testing.T) {
	src := `package x
import (
	"os"
	"os/exec"
	h "net/http"
	"net"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/client-go/dynamic"
	"syscall"
	"golang.org/x/sys/unix"
	utilnet "k8s.io/apimachinery/pkg/util/net"
)
func f() {
	syscall.ForkExec("/bin/sh", nil, nil)
	unix.Exec("/bin/sh", nil, nil)
	_ = utilnet.DialerFor
	exec.Command("kubectl", "delete")
	os.StartProcess("x", nil, nil)
	_ = &h.Client{}
	net.Dial("tcp", "evil.example:443")
	_ = &mcp.CommandTransport{}
	var _ dynamic.Interface
}
`
	want := []string{
		"import os/exec", "import net/http outside internal/kube", "import net outside internal/kube",
		"import k8s.io/client-go/dynamic outside internal/kube",
		"import golang.org/x/sys/unix outside internal/kube", "import k8s.io/apimachinery/pkg/util/net outside internal/kube",
		"use syscall.ForkExec", "use golang.org/x/sys/unix.Exec", "use k8s.io/apimachinery/pkg/util/net.DialerFor outside internal/kube",
		"use os.StartProcess", "use net/http.Client outside internal/kube", "use net.Dial outside internal/kube",
		"use github.com/modelcontextprotocol/go-sdk/mcp.CommandTransport outside internal/kube",
	}
	if got := blastRadiusViolations(t, "internal/tools/x.go", src); !slices.Equal(got, want) {
		t.Errorf("violations =\n%q\nwant\n%q", got, want)
	}
	// Inside internal/kube only process starts are flagged.
	got := blastRadiusViolations(t, "internal/kube/live.go", src)
	if !slices.Equal(got, []string{"import os/exec", "use syscall.ForkExec", "use golang.org/x/sys/unix.Exec", "use os.StartProcess"}) {
		t.Errorf("internal/kube violations = %q", got)
	}
}

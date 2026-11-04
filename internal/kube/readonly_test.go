package kube

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Method-name prefixes that indicate a mutating or interactive operation. The
// Client interface must not have any method starting with one of these.
var forbiddenInterfacePrefixes = MutatingMethodPrefixes()

// Selector names whose call would write to a cluster when invoked on a
// client-go client. No non-test file in this package may call them.
var forbiddenCalls = []string{
	"Create", "Update", "UpdateStatus", "UpdateScale", "UpdateEphemeralContainers",
	"UpdateResize", "Patch", "Apply", "ApplyStatus", "ApplyScale", "Delete",
	"DeleteCollection", "Evict", "EvictV1", "EvictV1beta1", "Bind", "ProxyGet",
	// raw REST paths: rest.Interface verbs and ways to obtain a raw client
	"Post", "Put", "Verb", "RESTClient", "RESTClientFor", "UnversionedRESTClientFor",
	"NewRESTClient", "HTTPClientFor",
}

// Imports allowed only in the named files (raw REST access stays in the live
// client, where the call check above guards it).
var importOnlyIn = map[string][]string{
	"k8s.io/client-go/rest": {"live.go"},
}

// Imports no non-test file may use: a raw HTTP client could send any verb.
var forbiddenImports = []string{"net/http"}

// Only these Kubernetes packages may be imported: none of them is a write
// helper on its own (typed core/v1 is needed for pod logs and is guarded by
// the call check above).
var allowedK8sImports = []string{
	"k8s.io/api/core/v1",
	"k8s.io/apimachinery/pkg/api/errors",
	"k8s.io/apimachinery/pkg/apis/meta/v1",
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured",
	"k8s.io/apimachinery/pkg/fields",
	"k8s.io/apimachinery/pkg/labels",
	"k8s.io/apimachinery/pkg/runtime/schema",
	"k8s.io/apimachinery/pkg/util/json",
	"k8s.io/client-go/discovery",
	"k8s.io/client-go/discovery/cached/memory",
	"k8s.io/client-go/dynamic",
	"k8s.io/client-go/kubernetes/typed/core/v1",
	"k8s.io/client-go/rest",
	"k8s.io/client-go/tools/clientcmd",
	"k8s.io/client-go/tools/clientcmd/api",
}

// interfaceViolations returns the methods of interface iface declared in src
// whose names start with a forbidden prefix, and whether iface was found.
func interfaceViolations(t *testing.T, filename, src, iface string) (bad []string, found bool) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filename, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != iface {
			return true
		}
		it, ok := ts.Type.(*ast.InterfaceType)
		if !ok {
			t.Fatalf("%s is not an interface", iface)
		}
		found = true
		for _, m := range it.Methods.List {
			if len(m.Names) == 0 {
				// An embedded interface could smuggle in methods we cannot
				// see here: refuse it outright.
				bad = append(bad, "embedded interface")
				continue
			}
			for _, n := range m.Names {
				for _, p := range forbiddenInterfacePrefixes {
					if strings.HasPrefix(n.Name, p) {
						bad = append(bad, n.Name)
					}
				}
			}
		}
		return false
	})
	return bad, found
}

// sourceViolations returns forbidden calls and imports in one Go file.
func sourceViolations(t *testing.T, filename, src string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filename, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	var bad []string
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if strings.HasPrefix(p, "k8s.io/") && !slices.Contains(allowedK8sImports, p) {
			bad = append(bad, "import "+p)
		}
		if files, ok := importOnlyIn[p]; ok && !slices.Contains(files, filepath.Base(filename)) {
			bad = append(bad, "import "+p+" outside "+strings.Join(files, ","))
		}
		if slices.Contains(forbiddenImports, p) {
			bad = append(bad, "import "+p)
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && slices.Contains(forbiddenCalls, sel.Sel.Name) {
			bad = append(bad, "call ."+sel.Sel.Name)
		}
		return true
	})
	return bad
}

func TestClientInterfaceIsReadOnly(t *testing.T) {
	src, err := os.ReadFile("client.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range []string{"Client", "Factory"} {
		bad, found := interfaceViolations(t, "client.go", string(src), iface)
		if !found {
			t.Fatalf("interface %s not found in client.go", iface)
		}
		if len(bad) > 0 {
			t.Errorf("interface %s has mutating methods: %v", iface, bad)
		}
	}
}

func TestPackageMakesNoWriteCalls(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, fn := range files {
		if strings.HasSuffix(fn, "_test.go") {
			continue
		}
		src, err := os.ReadFile(fn)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		if bad := sourceViolations(t, fn, string(src)); len(bad) > 0 {
			t.Errorf("%s: %v", fn, bad)
		}
	}
	if checked < 4 {
		t.Fatalf("only %d source files checked", checked)
	}
}

// Bite proofs: the checkers must flag a mutating method, an embedded
// interface, a write call and a disallowed import.
func TestReadOnlyCheckersBite(t *testing.T) {
	iface := `package kube
type Client interface {
	Get() error
	DeleteCollection() error
	SetImage() error
	Exec() error
}
type Sneaky interface { Client; Get() }
`
	bad, found := interfaceViolations(t, "x.go", iface, "Client")
	if !found || !slices.Equal(bad, []string{"DeleteCollection", "SetImage", "Exec"}) {
		t.Errorf("interface checker: found=%v bad=%v", found, bad)
	}
	bad, _ = interfaceViolations(t, "x.go", iface, "Sneaky")
	if !slices.Equal(bad, []string{"embedded interface"}) {
		t.Errorf("embedded interface not flagged: %v", bad)
	}
	if _, found := interfaceViolations(t, "x.go", "package kube\n", "Client"); found {
		t.Error("missing interface reported as found")
	}

	calls := `package kube
import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/dynamic"
)
func f(d dynamic.Interface, c *kubernetes.Clientset) {
	d.Resource(gvr).Namespace("x").Delete(ctx, "n", opts)
	c.CoreV1().Pods("x").Create(ctx, nil, opts)
	d.Resource(gvr).Get(ctx, "n", opts)
}
`
	got := sourceViolations(t, "y.go", calls)
	want := []string{"import k8s.io/client-go/kubernetes", "call .Delete", "call .Create"}
	if !slices.Equal(got, want) {
		t.Errorf("source checker = %v, want %v", got, want)
	}

	// Raw REST bypasses: write verbs on rest.Interface and raw clients.
	raw := `package kube
import (
	"net/http"
	"k8s.io/client-go/rest"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)
func g(c corev1client.CoreV1Interface, cfg *rest.Config) {
	c.RESTClient().Post().Resource("pods").Do(nil)
	c.RESTClient().Verb("DELETE").Do(nil)
	c.RESTClient().Put()
	rest.RESTClientFor(cfg)
	rest.HTTPClientFor(cfg)
	http.Post("u", "", nil)
}
`
	got = sourceViolations(t, "fake.go", raw)
	want = []string{
		"import net/http", "import k8s.io/client-go/rest outside live.go",
		"call .Post", "call .RESTClient", "call .Verb", "call .RESTClient", "call .Put", "call .RESTClient",
		"call .RESTClientFor", "call .HTTPClientFor", "call .Post",
	}
	if !slices.Equal(got, want) {
		t.Errorf("raw REST checker = %q\nwant %q", got, want)
	}
	// rest is fine in live.go itself (its calls are still checked).
	if got := sourceViolations(t, "live.go", "package kube\nimport \"k8s.io/client-go/rest\"\nvar _ rest.Config\n"); len(got) != 0 {
		t.Errorf("rest import in live.go flagged: %v", got)
	}
}

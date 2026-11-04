package test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/server"
	"github.com/astawiany/k8s-mcp/internal/tools"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("git rev-parse: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// TestNoEmployerNames scans every tracked or untracked-but-not-ignored file.
// The pattern is assembled from fragments so this file never contains the names.
func TestNoEmployerNames(t *testing.T) {
	root := repoRoot(t)
	pat := regexp.MustCompile(`(?i)(` + "Deutsche" + `\s+` + "Tele" + "kom" + `|` + "T" + `-` + "Mobile" + `|` + "Tele" + "kom" + `)`)
	cmd := exec.Command("git", "ls-files", "-co", "--exclude-standard")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f == "" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			continue // deleted or unreadable entries are not scannable
		}
		if pat.Match(b) || pat.MatchString(f) {
			t.Errorf("%s mentions a forbidden employer name", f)
		}
	}
}

func TestLicenseIsMIT(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "LICENSE"))
	if err != nil {
		t.Fatalf("read LICENSE: %v", err)
	}
	for _, want := range []string{"MIT License", "Adrian Stawiany"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("LICENSE missing %q", want)
		}
	}
}

var mdLink = regexp.MustCompile(`\]\(([^)\s]+)\)`)

// docFiles are the user-facing Markdown files whose links are checked.
func docFiles(t *testing.T, root string) []string {
	t.Helper()
	files := []string{"README.md"}
	more, err := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range more {
		rel, _ := filepath.Rel(root, m)
		files = append(files, rel)
	}
	return files
}

// TestMarkdownLinksResolve checks every relative link in README.md and
// docs/*.md, resolved against the linking file's directory.
func TestMarkdownLinksResolve(t *testing.T) {
	root := repoRoot(t)
	files := docFiles(t, root)
	for _, want := range []string{"docs/tools.md", "docs/threat-model.md", "docs/security.md"} {
		if !slices.Contains(files, want) {
			t.Errorf("%s is missing", want)
		}
	}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range mdLink.FindAllStringSubmatch(string(b), -1) {
			l := m[1]
			if strings.Contains(l, "://") || strings.HasPrefix(l, "mailto:") || strings.HasPrefix(l, "#") {
				continue
			}
			l, _, _ = strings.Cut(l, "#")
			if _, err := os.Stat(filepath.Join(root, filepath.Dir(f), l)); err != nil {
				t.Errorf("%s: link %q does not resolve", f, m[1])
			}
		}
	}
}

func readDoc(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

var toolHeading = regexp.MustCompile("(?m)^## `([a-z_]+)`\\s*$")

// TestToolsDocMatchesRegistry: docs/tools.md has one "## `name`" section per
// registered tool and none for tools that do not exist.
func TestToolsDocMatchesRegistry(t *testing.T) {
	s := server.New(kube.SingleFakeFactory(kube.NewFakeClient()), server.Options{Version: "test"})
	tools.RegisterAll(s)
	var registered []string
	for _, sp := range s.Tools() {
		registered = append(registered, sp.Name)
	}
	if len(registered) != 11 {
		t.Fatalf("registry has %d tools, want 11", len(registered))
	}
	var documented []string
	for _, m := range toolHeading.FindAllStringSubmatch(readDoc(t, "docs/tools.md"), -1) {
		documented = append(documented, m[1])
	}
	for _, n := range registered {
		if !slices.Contains(documented, n) {
			t.Errorf("docs/tools.md has no section \"## `%s`\"", n)
		}
	}
	for _, n := range documented {
		if !slices.Contains(registered, n) {
			t.Errorf("docs/tools.md documents %q, which is not a registered tool", n)
		}
	}
}

// TestReadmeEssentials: the Claude Code setup line, the RBAC manifest and the
// tool table.
func TestReadmeEssentials(t *testing.T) {
	r := readDoc(t, "README.md")
	for _, want := range []string{
		"claude mcp add k8s -- k8s-mcp --contexts 'kind-*'",
		"deploy/rbac/readonly-clusterrole.yaml",
		"docs/threat-model.md",
		"docs/tools.md",
		"docs/security.md",
		"make build",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("README.md lacks %q", want)
		}
	}
}

// TestThreatModelStatesResidualRisks: every residual risk ruled in the
// stage 1 ledger is named.
func TestThreatModelStatesResidualRisks(t *testing.T) {
	tm := strings.ToLower(readDoc(t, "docs/threat-model.md"))
	for _, want := range []string{
		"private key",      // tail window starting inside a key
		"fail-closed",      // pod_logs over-hiding
		"prompt injection", // residual model influence
		"exec plugin",      // stderr, hung plugins
		"defence in depth", // heuristics vs RBAC
		"split",            // tokens split across lines
		"arn:*/*",          // path.Match globs
		"allowlist",        // ErrContextNotAllowed lists it
		"autolink",         // draft_issue bare URLs
		"confused deputy",  // stage 3 ticketing
		"behavioural eval", // evidence, not guarantee
		"fixed-point",      // draft_issue masking loop
		"go 1.26",          // toolchain floor
	} {
		if !strings.Contains(tm, want) {
			t.Errorf("docs/threat-model.md does not mention %q", want)
		}
	}
}

func TestSecurityDocHasReleaseVerificationStub(t *testing.T) {
	if !strings.Contains(readDoc(t, "docs/security.md"), "## Verifying releases") {
		t.Error(`docs/security.md lacks the "## Verifying releases" section`)
	}
}

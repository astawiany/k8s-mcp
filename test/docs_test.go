package test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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

func TestReadmeLinksResolve(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	for _, m := range mdLink.FindAllStringSubmatch(string(b), -1) {
		l := m[1]
		if strings.Contains(l, "://") || strings.HasPrefix(l, "mailto:") || strings.HasPrefix(l, "#") {
			continue
		}
		l, _, _ = strings.Cut(l, "#")
		if _, err := os.Stat(filepath.Join(root, l)); err != nil {
			t.Errorf("README link %q does not resolve", m[1])
		}
	}
}

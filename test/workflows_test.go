package test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Structural tests of .github/workflows/validate.yml and the files it depends on. Nothing here
// talks to GitHub. checkWorkflow takes the workflow text so the bite proofs can feed it a
// mutated copy and show that each rule really rejects what it claims to.

var (
	requiredJobs = []string{"lint", "test", "integration"}
	usesLine     = regexp.MustCompile(`^\s*(?:-\s+)?uses:\s*(\S+)(.*)$`)
	pinned       = regexp.MustCompile(`^[^@\s]+@[0-9a-f]{40}$`)
	versionNote  = regexp.MustCompile(`^\s+#\s*v\d+(\.\d+)*\S*\s*$`)
	untrustedCtx = regexp.MustCompile(`\$\{\{[^}]*\b(github\.event\.|github\.head_ref\b)`)
)

func readFileT(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func workflowPath(t *testing.T) string {
	return filepath.Join(repoRoot(t), ".github", "workflows", "validate.yml")
}

// checkWorkflow returns every rule violation found in the workflow text.
func checkWorkflow(text string) []string {
	var bad []string
	add := func(format string, a ...any) { bad = append(bad, fmt.Sprintf(format, a...)) }

	for i, line := range strings.Split(text, "\n") {
		m := usesLine.FindStringSubmatch(line)
		if m == nil || strings.HasPrefix(m[1], "./") {
			continue
		}
		if !pinned.MatchString(m[1]) {
			add("line %d: %q is not pinned to a 40-hex commit SHA", i+1, m[1])
		} else if !versionNote.MatchString(m[2]) {
			add("line %d: %q has no '# vX.Y.Z' version comment", i+1, m[1])
		}
	}

	var wf map[string]any
	if err := yaml.Unmarshal([]byte(text), &wf); err != nil {
		return append(bad, "YAML does not parse: "+err.Error())
	}

	perms, ok := wf["permissions"].(map[string]any)
	if !ok {
		add("no workflow-level permissions map")
	} else {
		if perms["contents"] != "read" {
			add("workflow permissions.contents is %v, want read", perms["contents"])
		}
		for k, v := range perms {
			if v != "read" && v != "none" {
				add("workflow permission %s: %v is not read-only", k, v)
			}
		}
	}

	on, _ := wf["on"].(map[string]any)
	if _, has := on["pull_request_target"]; has {
		add("workflow uses pull_request_target")
	}
	for _, trig := range []string{"push", "pull_request", "workflow_dispatch"} {
		if _, has := on[trig]; !has {
			add("missing trigger %s", trig)
		}
	}
	if _, has := wf["concurrency"]; !has {
		add("no concurrency group")
	}

	jobs, _ := wf["jobs"].(map[string]any)
	for _, name := range append(append([]string{}, requiredJobs...), "security") {
		if _, has := jobs[name]; !has {
			add("job %q is missing", name)
		}
	}
	names := make([]string, 0, len(jobs))
	for n := range jobs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		job, _ := jobs[n].(map[string]any)
		if _, has := job["timeout-minutes"]; !has {
			add("job %q has no timeout-minutes", n)
		}
		jp, _ := job["permissions"].(map[string]any)
		for k, v := range jp {
			if v != "read" && v != "none" {
				add("job %q permission %s: %v is not read-only", n, k, v)
			}
		}
		steps, _ := job["steps"].([]any)
		for i, s := range steps {
			step, _ := s.(map[string]any)
			run, _ := step["run"].(string)
			if untrustedCtx.MatchString(run) {
				add("job %q step %d interpolates a github.event/head_ref context inside run:", n, i+1)
			}
		}
	}
	if integ, _ := jobs["integration"].(map[string]any); integ != nil {
		if _, has := integ["if"]; has {
			add("integration job has an if: condition; it must run on pull requests too")
		}
		found := false
		steps, _ := integ["steps"].([]any)
		for _, st := range steps {
			step, _ := st.(map[string]any)
			uses, _ := step["uses"].(string)
			if strings.HasPrefix(uses, "actions/upload-artifact@") {
				w, _ := step["with"].(map[string]any)
				if step["if"] == "failure()" && fmt.Sprint(w["retention-days"]) == "7" && w["path"] != nil {
					found = true
				}
			}
		}
		if !found {
			add("integration job has no upload-artifact step with if: failure() and retention-days: 7")
		}
	}
	return bad
}

func TestValidateWorkflowStructure(t *testing.T) {
	if bad := checkWorkflow(readFileT(t, workflowPath(t))); len(bad) > 0 {
		t.Fatalf("validate.yml violates:\n- %s", strings.Join(bad, "\n- "))
	}
}

func TestValidateWorkflowRulesBite(t *testing.T) {
	good := readFileT(t, workflowPath(t))
	pin := "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2"
	cases := []struct {
		name, from, to, want string
	}{
		{"unpinned action", pin, "actions/checkout@v4", "not pinned"},
		{"short sha", "11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2", "11bd719  # v4.2.2", "not pinned"},
		{"missing version comment", pin, "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", "no '# vX.Y.Z'"},
		{"pull_request_target", "  pull_request:\n", "  pull_request_target:\n", "pull_request_target"},
		{"write permission", "  contents: read\n\nconcurrency", "  contents: write\n\nconcurrency", "contents is write"},
		{"permissions removed", "permissions:\n  contents: read\n", "", "no workflow-level permissions"},
		{"event interpolation in run", "run: go test -race ./...", `run: echo "${{ github.event.pull_request.title }}"`, "interpolates"},
		{"head_ref interpolation in run", "run: go test -race ./...", `run: echo ${{ github.head_ref }}`, "interpolates"},
		{"integration skipped on PRs", "  integration:\n", "  integration:\n    if: github.event_name != 'pull_request'\n", "must run on pull requests"},
		{"diagnostics upload not on failure", "if: failure()\n        uses: actions/upload-artifact", "if: always()\n        uses: actions/upload-artifact", "no upload-artifact step"},
		{"timeout removed from lint", "    timeout-minutes: 15\n", "", "no timeout-minutes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(good, c.from) {
				t.Fatalf("mutation anchor %q not found in validate.yml", c.from)
			}
			bad := checkWorkflow(strings.Replace(good, c.from, c.to, 1))
			if !strings.Contains(strings.Join(bad, "\n"), c.want) {
				t.Fatalf("mutation %q not rejected with %q; violations: %v", c.name, c.want, bad)
			}
		})
	}
	for _, job := range requiredJobs {
		t.Run("drop job "+job, func(t *testing.T) {
			var wf map[string]any
			if err := yaml.Unmarshal([]byte(good), &wf); err != nil {
				t.Fatal(err)
			}
			delete(wf["jobs"].(map[string]any), job)
			out, err := yaml.Marshal(wf)
			if err != nil {
				t.Fatal(err)
			}
			bad := checkWorkflow(string(out))
			if !strings.Contains(strings.Join(bad, "\n"), `job "`+job+`" is missing`) {
				t.Fatalf("dropping %s not detected: %v", job, bad)
			}
		})
	}
}

// protectChecks runs protect-branch.sh --dry-run against a copy of the repo layout holding the
// given workflow text and returns the "# required status checks:" list.
func protectChecks(t *testing.T, workflow string) []string {
	t.Helper()
	root := t.TempDir()
	copyScript(t, root, "protect-branch.sh")
	wf := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wf, "validate.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(root, "scripts", "protect-branch.sh"), "--dry-run", "--repo", "o/r")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("protect-branch --dry-run: %v\n%s", err, out)
	}
	for _, l := range strings.Split(string(out), "\n") {
		if rest, ok := strings.CutPrefix(l, "# required status checks:"); ok {
			return strings.Fields(rest)
		}
	}
	t.Fatalf("no required checks line in:\n%s", out)
	return nil
}

func TestRequiredChecksExcludeSecurity(t *testing.T) {
	got := protectChecks(t, readFileT(t, workflowPath(t)))
	if strings.Join(got, ",") != "lint,test,integration" {
		t.Fatalf("required checks = %v, want lint,test,integration (security must stay optional)", got)
	}
	// Bite: a required job removed from the workflow disappears from the printed checks, so a
	// comparison against the expected list fails.
	mutated := strings.Replace(readFileT(t, workflowPath(t)), "\n  integration:\n", "\n  integration-renamed:\n", 1)
	if got := protectChecks(t, mutated); strings.Join(got, ",") == "lint,test,integration" {
		t.Fatalf("renaming a job did not change the required checks: %v", got)
	}
}

func TestInstallerGoPinMatchesGoMod(t *testing.T) {
	root := repoRoot(t)
	gomod := readFileT(t, filepath.Join(root, "go.mod"))
	// The CI toolchain is the `toolchain` line (go<version>) when go.mod has one, else the `go` line.
	mod := regexp.MustCompile(`(?m)^go (\S+)$`).FindStringSubmatch(gomod)
	if tc := regexp.MustCompile(`(?m)^toolchain go(\S+)$`).FindStringSubmatch(gomod); tc != nil {
		mod = tc
	}
	env := regexp.MustCompile(`(?m)^GO_VERSION=(\S+)$`).FindStringSubmatch(readFileT(t, filepath.Join(root, "versions.env")))
	if mod == nil || env == nil || mod[1] != env[1] {
		t.Fatalf("go.mod toolchain/go %v != versions.env GO_VERSION %v", mod, env)
	}
}

func TestCodeownersAndReadme(t *testing.T) {
	root := repoRoot(t)
	if !regexp.MustCompile(`(?m)^\* @astawiany$`).MatchString(readFileT(t, filepath.Join(root, ".github", "CODEOWNERS"))) {
		t.Fatal("CODEOWNERS lacks '* @astawiany'")
	}
	readme := readFileT(t, filepath.Join(root, ".github", "README.md"))
	for _, want := range []string{"protect-branch.sh", "Environment", "release-tags", "--approvals 0", "pinned by commit SHA", "Dependabot", "type: User", "upload-artifact"} {
		if !strings.Contains(readme, want) {
			t.Errorf(".github/README.md does not mention %q", want)
		}
	}
}

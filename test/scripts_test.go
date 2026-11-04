package test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Tests of scripts/ci-install-tools.sh and scripts/protect-branch.sh. Both run in a temp copy of
// the repo layout with a PATH holding only stubs (curl, uname, gh) plus /usr/bin:/bin, so no
// network, no GitHub and no host tool decides the outcome.

func copyScript(t *testing.T, root, name string) {
	t.Helper()
	src := readFileT(t, filepath.Join(repoRoot(t), "scripts", name))
	dst := filepath.Join(root, "scripts")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, name), []byte(src), 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeStub(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/bash\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func tgz(t *testing.T, members map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range members {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type installEnv struct {
	root, stubs, bin, goRoot, payload string
}

// newInstallEnv builds the temp layout. payload is what the stub curl "downloads" for any URL.
func newInstallEnv(t *testing.T, payload []byte, uname string) *installEnv {
	t.Helper()
	e := &installEnv{root: t.TempDir(), stubs: t.TempDir()}
	copyScript(t, e.root, "ci-install-tools.sh")
	if err := os.WriteFile(filepath.Join(e.root, "versions.env"), []byte(readFileT(t, filepath.Join(repoRoot(t), "versions.env"))), 0o644); err != nil {
		t.Fatal(err)
	}
	e.bin = filepath.Join(e.root, "out-bin")
	e.goRoot = filepath.Join(e.root, "out-go")
	e.payload = filepath.Join(e.root, "payload")
	if err := os.WriteFile(e.payload, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	writeStub(t, e.stubs, "curl", `out=""; url=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac; done
echo "$url" >> "$STUB_LOG"
cp "$STUB_PAYLOAD" "$out"
`)
	writeStub(t, e.stubs, "uname", `case "$1" in -s) echo "`+strings.Split(uname, "/")[0]+`" ;; -m) echo "`+strings.Split(uname, "/")[1]+`" ;; esac
`)
	return e
}

func (e *installEnv) pin(t *testing.T, key, value string) {
	t.Helper()
	p := filepath.Join(e.root, "versions.env")
	s := readFileT(t, p)
	re := regexp.MustCompile(`(?m)^` + key + `=.*$`)
	if !re.MatchString(s) {
		t.Fatalf("%s not in versions.env", key)
	}
	if err := os.WriteFile(p, []byte(re.ReplaceAllString(s, key+"="+value)), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (e *installEnv) run(t *testing.T, tool string) (string, error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(e.root, "scripts", "ci-install-tools.sh"), tool)
	cmd.Env = []string{
		"PATH=" + e.stubs + ":/usr/bin:/bin", "HOME=" + e.root,
		"BIN_DIR=" + e.bin, "GO_ROOT_DIR=" + e.goRoot,
		"STUB_PAYLOAD=" + e.payload, "STUB_LOG=" + filepath.Join(e.root, "curl.log"),
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestInstallerRejectsBadChecksum(t *testing.T) {
	// Every binary download is pinned in versions.env; the stub serves a payload that matches none.
	for _, tool := range []string{"kubectl", "kind", "trivy", "actionlint", "go"} {
		t.Run(tool, func(t *testing.T) {
			e := newInstallEnv(t, []byte("tampered payload"), "Linux/x86_64")
			out, err := e.run(t, tool)
			if err == nil {
				t.Fatalf("installer accepted a payload with the wrong sha256:\n%s", out)
			}
			if !strings.Contains(out, "sha256 mismatch") {
				t.Fatalf("no 'sha256 mismatch' message:\n%s", out)
			}
			for _, bin := range []string{"kubectl", "kind", "trivy", "actionlint"} {
				if exists(filepath.Join(e.bin, bin)) {
					t.Fatalf("%s was installed despite the checksum failure", bin)
				}
			}
			if exists(filepath.Join(e.goRoot, "go")) {
				t.Fatal("go was unpacked despite the checksum failure")
			}
		})
	}
}

func TestInstallerAcceptsMatchingChecksum(t *testing.T) {
	t.Run("kubectl", func(t *testing.T) {
		payload := []byte("#!/bin/sh\necho fake kubectl\n")
		e := newInstallEnv(t, payload, "Linux/x86_64")
		e.pin(t, "KUBECTL_SHA256_LINUX_AMD64", sum(payload))
		if out, err := e.run(t, "kubectl"); err != nil {
			t.Fatalf("matching checksum rejected: %v\n%s", err, out)
		}
		if !exists(filepath.Join(e.bin, "kubectl")) {
			t.Fatal("kubectl not installed")
		}
		if log := readFileT(t, filepath.Join(e.root, "curl.log")); !strings.Contains(log, "dl.k8s.io/release/v1.34.0/") {
			t.Fatalf("unexpected download URL: %s", log)
		}
	})
	for _, tc := range []struct{ tool, key, member string }{
		{"trivy", "TRIVY_SHA256_LINUX_AMD64", "trivy"},
		{"actionlint", "ACTIONLINT_SHA256_LINUX_AMD64", "actionlint"},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			payload := tgz(t, map[string]string{tc.member: "#!/bin/sh\n", "LICENSE": "x"})
			e := newInstallEnv(t, payload, "Linux/x86_64")
			e.pin(t, tc.key, sum(payload))
			if out, err := e.run(t, tc.tool); err != nil {
				t.Fatalf("matching checksum rejected: %v\n%s", err, out)
			}
			if !exists(filepath.Join(e.bin, tc.tool)) {
				t.Fatalf("%s not installed", tc.tool)
			}
		})
	}
	t.Run("go", func(t *testing.T) {
		payload := tgz(t, map[string]string{"go/bin/go": "#!/bin/sh\n", "go/VERSION": "go1.26.0"})
		e := newInstallEnv(t, payload, "Linux/x86_64")
		e.pin(t, "GO_SHA256_LINUX_AMD64", sum(payload))
		if out, err := e.run(t, "go"); err != nil {
			t.Fatalf("matching checksum rejected: %v\n%s", err, out)
		}
		if !exists(filepath.Join(e.goRoot, "go", "bin", "go")) {
			t.Fatal("go not unpacked")
		}
	})
}

func TestInstallerLinuxAmd64OnlyAndUnknownTool(t *testing.T) {
	e := newInstallEnv(t, []byte("x"), "Darwin/arm64")
	if out, err := e.run(t, "kubectl"); err == nil || !strings.Contains(out, "linux/amd64 only") {
		t.Fatalf("kubectl on darwin: err=%v\n%s", err, out)
	}
	if exists(filepath.Join(e.root, "curl.log")) {
		t.Fatal("downloaded before checking the platform")
	}
	e = newInstallEnv(t, []byte("x"), "Linux/x86_64")
	if out, err := e.run(t, "nosuchtool"); err == nil || !strings.Contains(out, "unknown tool") {
		t.Fatalf("unknown tool: err=%v\n%s", err, out)
	}
}

func TestVersionsEnvChecksumsAreWellFormed(t *testing.T) {
	env := readFileT(t, filepath.Join(repoRoot(t), "versions.env"))
	for _, key := range []string{"KUBECTL", "KIND", "GO", "TRIVY", "ACTIONLINT"} {
		if !regexp.MustCompile(`(?m)^` + key + `_SHA256_LINUX_AMD64=[0-9a-f]{64}$`).MatchString(env) {
			t.Errorf("versions.env: %s_SHA256_LINUX_AMD64 missing or not 64 hex", key)
		}
	}
}

// --- protect-branch.sh -------------------------------------------------------------------

// stateful gh stub: PUT/POST calls create state files, GETs read them back. STUB_DROP names a
// write that is silently ignored, which is how the read-back failures are provoked.
const ghStub = `
state="$STUB_STATE"; mkdir -p "$state"
method=GET; path=""; jq=""; input=0
while [ $# -gt 0 ]; do case "$1" in
  api) shift ;;
  --method) method="$2"; shift 2 ;;
  --jq) jq="$2"; shift 2 ;;
  --input) input=1; shift 2 ;;
  *) path="$1"; shift ;;
esac; done
body=""; [ "$input" = 1 ] && body="$(cat)"
echo "$method $path" >> "$state/calls.log"
[ -n "$body" ] && echo "$body" > "$state/body.$(echo "$method $path" | tr -c 'A-Za-z0-9\n' _)"
drop() { [ "${STUB_DROP:-}" = "$1" ]; }
case "$method $path" in
  "GET users/"*) echo 4242 ;;
  "PUT repos/o/r/branches/main/protection") drop protection || touch "$state/protection" ;;
  "PUT repos/o/r/environments/release") touch "$state/env" ;;
  "POST repos/o/r/environments/release/deployment-branch-policies") drop policy || touch "$state/policy" ;;
  "GET repos/o/r/environments/release/deployment-branch-policies")
    if [ -f "$state/policy" ]; then case "$jq" in *length*) echo 1 ;; *) echo 77 ;; esac
    else case "$jq" in *length*) echo 0 ;; esac; fi ;;
  "POST repos/o/r/rulesets") drop ruleset || touch "$state/ruleset" ;;
  "PUT repos/o/r/rulesets/9") touch "$state/ruleset_put" ;;
  "GET repos/o/r/rulesets")
    if [ -f "$state/ruleset" ]; then case "$jq" in *length*) echo 1 ;; *) echo 9 ;; esac
    else case "$jq" in *length*) echo 0 ;; esac; fi ;;
  "GET repos/o/r/branches/main/protection") [ -f "$state/protection" ] && echo 3 || exit 1 ;;
  *) echo "unexpected gh call: $method $path" >&2; exit 99 ;;
esac
`

type protectEnv struct{ root, stubs, state string }

func newProtectEnv(t *testing.T) *protectEnv {
	t.Helper()
	e := &protectEnv{root: t.TempDir(), stubs: t.TempDir(), state: t.TempDir()}
	copyScript(t, e.root, "protect-branch.sh")
	wf := filepath.Join(e.root, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wf, "validate.yml"), []byte(readFileT(t, workflowPath(t))), 0o644); err != nil {
		t.Fatal(err)
	}
	writeStub(t, e.stubs, "gh", ghStub)
	return e
}

func (e *protectEnv) run(t *testing.T, drop string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(e.root, "scripts", "protect-branch.sh"), args...)
	cmd.Env = []string{"PATH=" + e.stubs + ":/usr/bin:/bin", "STUB_STATE=" + e.state, "STUB_DROP=" + drop, "PROTECT_VERIFY_SLEEP=0"}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (e *protectEnv) calls() string {
	b, _ := os.ReadFile(filepath.Join(e.state, "calls.log"))
	return string(b)
}

func TestProtectBranchRequiresRepo(t *testing.T) {
	for _, args := range [][]string{{}, {"--dry-run"}, {"--repo", "no-slash"}, {"--dry-run", "--repo", "o/r", "--approvals", "9"}} {
		e := newProtectEnv(t)
		out, err := e.run(t, "", args...)
		if err == nil {
			t.Fatalf("args %v accepted:\n%s", args, out)
		}
		if e.calls() != "" {
			t.Fatalf("args %v reached gh: %s", args, e.calls())
		}
	}
}

func TestProtectBranchDryRunListsEverythingAndExecutesNothing(t *testing.T) {
	e := newProtectEnv(t)
	out, err := e.run(t, "", "--dry-run", "--repo", "o/r")
	if err != nil {
		t.Fatalf("dry run failed: %v\n%s", err, out)
	}
	for _, want := range []string{
		`"contexts": ["lint", "test", "integration"]`, `"strict": true`, `"required_approving_review_count": 0`, `"enforce_admins": false`,
		"environments/release", `"name": "release-tags"`, `refs/tags/v*`, `"type": "creation"`, `"type": "update"`, `"type": "deletion"`,
		"deployment-branch-policies", "reviewers",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output lacks %q", want)
		}
	}
	if strings.Contains(out, `"security"`) {
		t.Error("security must not be a required check")
	}
	if e.calls() != "" {
		t.Fatalf("dry run called gh: %s", e.calls())
	}
	out, _ = e.run(t, "", "--dry-run", "--repo", "o/r", "--approvals", "1", "--enforce-admins")
	if !strings.Contains(out, `"enforce_admins": true`) || !strings.Contains(out, `"require_code_owner_reviews": true`) {
		t.Errorf("--approvals 1 --enforce-admins not reflected:\n%s", out)
	}
}

func TestProtectBranchRealModeIssuesExpectedCalls(t *testing.T) {
	e := newProtectEnv(t)
	out, err := e.run(t, "", "--repo", "o/r")
	if err != nil {
		t.Fatalf("real run failed: %v\n%s", err, out)
	}
	calls := e.calls()
	for _, want := range []string{
		"GET users/o", "PUT repos/o/r/branches/main/protection", "PUT repos/o/r/environments/release",
		"POST repos/o/r/environments/release/deployment-branch-policies", "POST repos/o/r/rulesets",
	} {
		if !strings.Contains(calls, want+"\n") {
			t.Errorf("missing call %q in:\n%s", want, calls)
		}
	}
	if body := readFileT(t, filepath.Join(e.state, "body.PUT_repos_o_r_environments_release")); !strings.Contains(body, `"id": 4242`) {
		t.Errorf("environment reviewer is not the owner's id: %s", body)
	}
	if !strings.Contains(out, "verified") {
		t.Errorf("no verification message:\n%s", out)
	}
	// Re-run is idempotent: the ruleset is updated in place, the tag policy is not posted twice.
	e2calls := len(strings.Split(e.calls(), "POST repos/o/r/rulesets"))
	if out, err = e.run(t, "", "--repo", "o/r"); err != nil {
		t.Fatalf("re-run failed: %v\n%s", err, out)
	}
	after := e.calls()
	if len(strings.Split(after, "POST repos/o/r/rulesets")) != e2calls || !strings.Contains(after, "PUT repos/o/r/rulesets/9") {
		t.Errorf("re-run did not update the ruleset in place:\n%s", after)
	}
	if strings.Count(after, "POST repos/o/r/environments/release/deployment-branch-policies") != 1 {
		t.Errorf("tag policy posted again on re-run:\n%s", after)
	}
}

func TestProtectBranchReadBackFailureExitsNonZero(t *testing.T) {
	for drop, msg := range map[string]string{
		"policy":     "no v* tag policy",
		"ruleset":    "no active tag ruleset",
		"protection": "no branch protection",
	} {
		t.Run(drop, func(t *testing.T) {
			e := newProtectEnv(t)
			out, err := e.run(t, drop, "--repo", "o/r")
			if err == nil {
				t.Fatalf("exit 0 although %s was not applied:\n%s", drop, out)
			}
			if !strings.Contains(out, "FAILED to verify") || !strings.Contains(out, msg) {
				t.Fatalf("expected %q in:\n%s", msg, out)
			}
		})
	}
}

package test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	root, stubs, bin, goRoot, payload, tmp string
}

// newInstallEnv builds the temp layout. payload is what the stub curl "downloads" for any URL.
func newInstallEnv(t *testing.T, payload []byte, uname string) *installEnv {
	t.Helper()
	e := &installEnv{root: t.TempDir(), stubs: t.TempDir()}
	copyScript(t, e.root, "ci-install-tools.sh")
	if err := os.WriteFile(filepath.Join(e.root, "versions.env"), []byte(readFileT(t, filepath.Join(repoRoot(t), "versions.env"))), 0o644); err != nil {
		t.Fatal(err)
	}
	e.tmp = filepath.Join(e.root, "tmp")
	if err := os.MkdirAll(e.tmp, 0o755); err != nil {
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
# a file named like the URL's last path segment in $STUB_PAYLOAD_DIR wins over the default payload
if [ -f "$STUB_PAYLOAD_DIR/${url##*/}" ]; then cp "$STUB_PAYLOAD_DIR/${url##*/}" "$out"; else cp "$STUB_PAYLOAD" "$out"; fi
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
		"TMPDIR=" + e.tmp, "STUB_PAYLOAD=" + e.payload, "STUB_PAYLOAD_DIR=" + filepath.Join(e.root, "payloads"), "STUB_LOG=" + filepath.Join(e.root, "curl.log"),
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
			if left, _ := os.ReadDir(e.tmp); len(left) != 0 {
				t.Fatalf("temp dir left behind after the failure: %v", left)
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
	for _, key := range []string{"KUBECTL", "KIND", "GO", "TRIVY", "ACTIONLINT", "COSIGN"} {
		if !regexp.MustCompile(`(?m)^` + key + `_SHA256_LINUX_AMD64=[0-9a-f]{64}$`).MatchString(env) {
			t.Errorf("versions.env: %s_SHA256_LINUX_AMD64 missing or not 64 hex", key)
		}
	}
}

// servePayload makes the stub curl answer URLs ending in /name with body.
func (e *installEnv) servePayload(t *testing.T, name string, body []byte) {
	t.Helper()
	dir := filepath.Join(e.root, "payloads")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

// cosign must match both the release's cosign_checksums.txt and the sha256 pinned in versions.env.
func TestInstallerCosign(t *testing.T) {
	bin := []byte("#!/bin/sh\necho fake cosign\n")
	checksums := func(hexsum string) []byte {
		return []byte(hexsum + "  cosign-darwin-arm64\n" + hexsum + "  cosign-linux-amd64\n" + sum([]byte("x")) + "  cosign-linux-amd64.sig\n")
	}
	t.Run("matching pin and checksum file", func(t *testing.T) {
		e := newInstallEnv(t, bin, "Linux/x86_64")
		e.servePayload(t, "cosign_checksums.txt", checksums(sum(bin)))
		e.pin(t, "COSIGN_SHA256_LINUX_AMD64", sum(bin))
		if out, err := e.run(t, "cosign"); err != nil {
			t.Fatalf("matching checksums rejected: %v\n%s", err, out)
		}
		if !exists(filepath.Join(e.bin, "cosign")) {
			t.Fatal("cosign not installed")
		}
		log := readFileT(t, filepath.Join(e.root, "curl.log"))
		for _, want := range []string{"github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64", "github.com/sigstore/cosign/releases/download/v3.1.4/cosign_checksums.txt"} {
			if !strings.Contains(log, want) {
				t.Fatalf("no download of %s: %s", want, log)
			}
		}
	})
	t.Run("tampered binary", func(t *testing.T) {
		e := newInstallEnv(t, []byte("tampered"), "Linux/x86_64")
		e.servePayload(t, "cosign_checksums.txt", checksums(sum(bin)))
		e.pin(t, "COSIGN_SHA256_LINUX_AMD64", sum(bin))
		out, err := e.run(t, "cosign")
		if err == nil || !strings.Contains(out, "sha256 mismatch") || exists(filepath.Join(e.bin, "cosign")) {
			t.Fatalf("tampered cosign accepted: err=%v\n%s", err, out)
		}
	})
	t.Run("checksum file disagrees with the pin", func(t *testing.T) {
		e := newInstallEnv(t, bin, "Linux/x86_64")
		e.servePayload(t, "cosign_checksums.txt", checksums(sum([]byte("other release"))))
		e.pin(t, "COSIGN_SHA256_LINUX_AMD64", sum(bin))
		out, err := e.run(t, "cosign")
		if err == nil || !strings.Contains(out, "disagrees") || exists(filepath.Join(e.bin, "cosign")) {
			t.Fatalf("disagreeing checksum file accepted: err=%v\n%s", err, out)
		}
		if left, _ := os.ReadDir(e.tmp); len(left) != 0 {
			t.Fatalf("temp dir left behind: %v", left)
		}
	})
	t.Run("linux/amd64 only", func(t *testing.T) {
		e := newInstallEnv(t, bin, "Darwin/arm64")
		if out, err := e.run(t, "cosign"); err == nil || !strings.Contains(out, "linux/amd64 only") {
			t.Fatalf("cosign on darwin: err=%v\n%s", err, out)
		}
	})
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
  "PUT repos/o/r/branches/main/protection")
    drop protection || { touch "$state/protection"
      ctx="$(echo "$body" | sed -n 's/.*"contexts": \[\(.*\)\].*/\1/p' | tr -d '" ' )"
      [ "${STUB_DROP:-}" = contexts ] && ctx="lint"
      strict=true; echo "$body" | grep -q '"strict": true' || strict=false
      [ "${STUB_DROP:-}" = strict ] && strict=false
      echo "$strict $(echo "$ctx" | tr ',' '\n' | sort | paste -sd, -)" > "$state/protection_state"; } ;;
  "PUT repos/o/r/environments/release") touch "$state/env" ;;
  "POST repos/o/r/environments/release/deployment-branch-policies") drop policy || touch "$state/policy" ;;
  "GET repos/o/r/environments/release/deployment-branch-policies")
    if [ -f "$state/policy" ]; then case "$jq" in *length*) echo 1 ;; *) echo 77 ;; esac
    else case "$jq" in *length*) echo 0 ;; esac; fi ;;
  "POST repos/o/r/rulesets") drop ruleset || touch "$state/ruleset" ;;
  "PUT repos/o/r/rulesets/9") touch "$state/ruleset_put" ;;
  "GET repos/o/r/rulesets")
    if [ -n "${STUB_RULESETS_FAIL:-}" ]; then echo "gh: Not Found (HTTP 404)" >&2; exit 1; fi
    if [ -f "$state/ruleset" ]; then case "$jq" in *length*) echo 1 ;; *) echo 9 ;; esac
    else case "$jq" in *length*) echo 0 ;; esac; fi ;;
  "GET repos/o/r/branches/main/protection") [ -f "$state/protection" ] && cat "$state/protection_state" || exit 1 ;;
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
		"contexts":   "required checks are",
		"strict":     "required checks are",
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

func TestProtectBranchRulesetsUnavailableIsClearAndWritesNothing(t *testing.T) {
	e := newProtectEnv(t)
	cmd := exec.Command(filepath.Join(e.root, "scripts", "protect-branch.sh"), "--repo", "o/r")
	cmd.Env = []string{"PATH=" + e.stubs + ":/usr/bin:/bin", "STUB_STATE=" + e.state, "STUB_RULESETS_FAIL=1", "PROTECT_VERIFY_SLEEP=0"}
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure:\n%s", out)
	}
	if !strings.Contains(string(out), "rulesets are not available") || !strings.Contains(string(out), "--no-protect-tags") {
		t.Fatalf("unclear message:\n%s", out)
	}
	if strings.Contains(e.calls(), "PUT ") || strings.Contains(e.calls(), "POST ") {
		t.Fatalf("wrote before the ruleset lookup failed:\n%s", e.calls())
	}
}

// --- run.sh diagnostics ------------------------------------------------------------------

// runCleanup executes run.sh's dump_diagnostics/cleanup (sliced out of the script) with stub
// kubectl and kind, as if the script had failed with exit code rc. It returns the diagnostics
// dir, the script's exit code and its output.
func runCleanup(t *testing.T, rc int, kubectlOut string) (diag string, code int, out string) {
	t.Helper()
	src := readFileT(t, filepath.Join(repoRoot(t), "test", "integration", "run.sh"))
	from := strings.Index(src, "DIAG_DIR=")
	to := strings.Index(src, "# poll <timeout-s>")
	if from < 0 || to < 0 {
		t.Fatal("cannot slice run.sh")
	}
	work, stubs := t.TempDir(), t.TempDir()
	diag = filepath.Join(work, "diag")
	writeStub(t, stubs, "kubectl", `case "$*" in *"get pods,events"*) printf '%s\n' "$STUB_KUBECTL_OUT" ;; esac
`)
	writeStub(t, stubs, "kind", `if [ "$1 $2" = "export logs" ]; then
  for p in kube-system_etcd_u1/etcd flux-system_source_u2/manager broken_log-injection_u3/app broken_other_u4/app local-path-storage_prov_u5/p; do
    mkdir -p "$3/node/pods/${p%%/*}/${p##*/}"
    echo "stdout of $p" > "$3/node/pods/${p%%/*}/${p##*/}/0.log"
  done
  echo "-----BEGIN RSA PRIVATE KEY-----" > "$3/node/pods/kube-system_etcd_u1/etcd/1.log"
  echo journal > "$3/node/kubelet.log"
  mkdir -p "$3/node/containers"
  ln -s ../pods/broken_log-injection_u3/app/0.log "$3/node/containers/log-injection_broken_app-u3.log"
  echo "ghp_K8sMcpCanaryGithubToken0123456789" > "$3/node/containers/log-injection_copy.log"
  echo apt > "$3/node/alternatives.log"
  echo v > "$3/kind-version.txt"
fi
exit 0
`)
	script := "set -uo pipefail\nROOT=" + work + "\nCLUSTER=c\nKC=x\nCTX=y\nWORK=" + work + "/w\ncreated=1\nstart=0\ntimings=(x)\nphase() { :; }\nIT_DIAG_DIR=" + diag + "\n" +
		src[from:to] + "\n(exit " + fmt.Sprint(rc) + ")\ncleanup\n"
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Env = []string{"PATH=" + stubs + ":/usr/bin:/bin", "STUB_KUBECTL_OUT=" + kubectlOut}
	b, err := cmd.CombinedOutput()
	code = 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return diag, code, string(b)
}

func TestDiagnosticsDropFixturePodLogsKeepInfra(t *testing.T) {
	diag, _, out := runCleanup(t, 1, "pod/a Running")
	pods := filepath.Join(diag, "kind", "node", "pods")
	for _, keep := range []string{"kube-system_etcd_u1", "flux-system_source_u2", "local-path-storage_prov_u5"} {
		if !exists(filepath.Join(pods, keep)) {
			t.Errorf("infrastructure pod log %s was deleted\n%s", keep, out)
		}
	}
	for _, gone := range []string{"broken_log-injection_u3", "broken_other_u4"} {
		if exists(filepath.Join(pods, gone)) {
			t.Errorf("fixture pod log %s survived in the uploaded directory\n%s", gone, out)
		}
	}
	if !exists(filepath.Join(pods, "kube-system_etcd_u1", "etcd", "0.log")) || exists(filepath.Join(pods, "kube-system_etcd_u1", "etcd", "1.log")) {
		t.Error("final marker sweep: plain log must stay, the file with the fixture marker must go")
	}
	for _, gone := range []string{"containers", "alternatives.log"} {
		if exists(filepath.Join(diag, "kind", "node", gone)) {
			t.Errorf("%s survived the allow-list prune", gone)
		}
	}
	if !exists(filepath.Join(diag, "kind", "kind-version.txt")) {
		t.Error("kind-version.txt lost")
	}
	if !exists(filepath.Join(diag, "kind", "node", "kubelet.log")) || !exists(filepath.Join(diag, "pods-events.txt")) {
		t.Error("kubelet journal or get/describe output lost")
	}
	// the fake canary token is deliberately not a scrub pattern: a failed run must not be re-flagged
	if strings.Contains(out, "contains a secret value") || strings.Contains(out, "contains a JWT") {
		t.Errorf("unexpected scrub error:\n%s", out)
	}
}

func TestCleanupPreservesOriginalExitCode(t *testing.T) {
	for _, rc := range []int{130, 7, 1} {
		if _, code, out := runCleanup(t, rc, "pod/a Running"); code != rc {
			t.Errorf("exit code %d became %d\n%s", rc, code, out)
		}
	}
	// a real-secret leak is reported and the file deleted, still without changing the exit code
	diag, code, out := runCleanup(t, 130, "password k8smcp-canary-secret-value-7f3a9c2e51d4")
	if code != 130 || !strings.Contains(out, "contains a secret value") || exists(filepath.Join(diag, "pods-events.txt")) {
		t.Errorf("leak handling: code=%d\n%s", code, out)
	}
}

func TestPruneExportIsAnAllowList(t *testing.T) {
	src := readFileT(t, filepath.Join(repoRoot(t), "test", "integration", "run.sh"))
	from, to := strings.Index(src, "# prune_export <dir>"), strings.Index(src, "dump_diagnostics() {")
	if from < 0 || to < 0 {
		t.Fatal("cannot slice run.sh")
	}
	base := t.TempDir()
	outside := filepath.Join(base, "outside-secret.txt")
	if err := os.WriteFile(outside, []byte("must survive"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "export")
	node := filepath.Join(root, "kind-control-plane")
	files := map[string]string{
		"kind-version.txt": "v", "docker-info.txt": "d", "stray.txt": "x",
		"kind-control-plane/kubelet.log": "k", "kind-control-plane/containerd.log": "c", "kind-control-plane/journal.log": "j",
		"kind-control-plane/inspect.json": "{}", "kind-control-plane/kubernetes-version.txt": "v1",
		"kind-control-plane/alternatives.log": "a", "kind-control-plane/apt/history.log": "a",
		"kind-control-plane/containers/log-injection_broken_app-u3.log": "ghp_x",
		"kind-control-plane/pods/default_log-injection_x/app/0.log":     "ghp_x",
		"kind-control-plane/pods/kube-system_etcd_y/etcd/0.log":         "etcd",
		"kind-control-plane/pods/flux-system_source_z/manager/0.log":    "flux",
		"kind-control-plane/pods/local-path-storage_p_w/p/0.log":        "lps",
		"kind-control-plane/pods/broken_other_q/app/0.log":              "other",
	}
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{
		"kind-control-plane/containers/link-to-outside.log":             outside,
		"kind-control-plane/pods/default_log-injection_link":            filepath.Join(base),
		"kind-control-plane/pods/kube-system_symlinked":                 base,
		"kind-control-plane/journal-link.log":                           outside,
		"kind-control-plane/pods/kube-system_etcd_y/etcd/escape":        outside,
		"kind-control-plane/pods/kube-system_etcd_y/etcd/escape-to-dir": base,
	}
	for rel, target := range links {
		if err := os.Symlink(target, filepath.Join(root, rel)); err != nil {
			t.Fatal(err)
		}
	}
	_ = node
	script := "set -uo pipefail\n" + src[from:to] + "\nprune_export " + root + "\n"
	if out, err := exec.Command("/bin/bash", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("prune_export: %v\n%s", err, out)
	}
	keep := []string{
		"kind-version.txt", "docker-info.txt", "kind-control-plane/kubelet.log", "kind-control-plane/containerd.log",
		"kind-control-plane/journal.log", "kind-control-plane/inspect.json", "kind-control-plane/kubernetes-version.txt",
		"kind-control-plane/pods/kube-system_etcd_y/etcd/0.log", "kind-control-plane/pods/flux-system_source_z/manager/0.log",
		"kind-control-plane/pods/local-path-storage_p_w/p/0.log",
	}
	gone := []string{
		"stray.txt", "kind-control-plane/alternatives.log", "kind-control-plane/apt", "kind-control-plane/containers",
		"kind-control-plane/pods/default_log-injection_x", "kind-control-plane/pods/default_log-injection_link",
		"kind-control-plane/pods/broken_other_q", "kind-control-plane/pods/kube-system_etcd_y/etcd/escape", "kind-control-plane/pods/kube-system_etcd_y/etcd/escape-to-dir", "kind-control-plane/pods/kube-system_symlinked", "kind-control-plane/journal-link.log",
	}
	for _, k := range keep {
		if !exists(filepath.Join(root, k)) {
			t.Errorf("allow-listed %s was removed", k)
		}
	}
	for _, g := range gone {
		if _, err := os.Lstat(filepath.Join(root, g)); err == nil {
			t.Errorf("%s survived the prune", g)
		}
	}
	if b, err := os.ReadFile(outside); err != nil || string(b) != "must survive" {
		t.Fatalf("a symlink was followed: the target outside the tree is gone or changed (%v)", err)
	}
	if _, err := os.Stat(base); err != nil {
		t.Fatal(err)
	}
}

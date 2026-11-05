package test

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Release hardening: scripts/release.sh, scripts/security-scan.sh, the shape of
// .github/workflows/release.yml, the Dockerfile and .dockerignore. docker, gh, go, trivy and git
// remotes are stubbed or local; nothing talks to a registry, GitHub or Sigstore. Mirrors the
// release tests of the sibling project fleet-in-a-repo (test/release.bats).

const (
	repoSlug = "astawiany/k8s-mcp"
	issuer   = "https://token.actions.githubusercontent.com"
)

var (
	d64  = strings.Repeat("a", 64)
	d64b = strings.Repeat("b", 64)
)

func releaseScript(t *testing.T) string {
	return filepath.Join(repoRoot(t), "scripts", "release.sh")
}

func releaseWorkflowPath(t *testing.T) string {
	return filepath.Join(repoRoot(t), ".github", "workflows", "release.yml")
}

// relRun runs a script with PATH = stubs + extra dirs + /usr/bin:/bin and the given env; it
// returns the combined output and the exit code.
func relRun(t *testing.T, stubs string, extraPath []string, env []string, script string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(script, args...)
	path := append(append([]string{stubs}, extraPath...), "/usr/bin", "/bin")
	cmd.Env = append([]string{"PATH=" + strings.Join(path, ":"), "HOME=" + t.TempDir()}, env...)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &ee):
		return string(out), ee.ExitCode()
	default:
		t.Fatalf("run %s: %v", script, err)
		return "", -1
	}
}

// jqDir returns the directory of a jq binary; the JSON-reading subcommands need it (ubuntu
// runners ship it). Skipped, not failed, where it is missing.
func jqDir(t *testing.T) []string {
	t.Helper()
	p, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("jq not installed: the JSON-reading release.sh subcommands need it")
	}
	return []string{filepath.Dir(p)}
}

// --- validate-tag ---------------------------------------------------------------------------

func TestReleaseValidateTag(t *testing.T) {
	stubs := t.TempDir()
	for _, tc := range []struct {
		tag string
		ok  bool
	}{
		{"v1.2.3", true}, {"v0.1.0", true}, {"v10.20.30", true},
		{"v1.2", false}, {"v1.2.3-rc.1", false}, {"v1.2.3+build", false}, {"1.2.3", false},
		{"chart-v1.2.3", false}, {"v1.2.3.4", false}, {"v1.2.3 ", false}, {" v1.2.3", false},
		{"", false}, {"v1.2.x", false}, {"V1.2.3", false}, {"v1.2.3\nv1.2.4", false}, {"refs/tags/v1.2.3", false},
	} {
		out, rc := relRun(t, stubs, nil, nil, releaseScript(t), "validate-tag", tc.tag)
		if tc.ok && (rc != 0 || strings.TrimSpace(out) != tc.tag) {
			t.Errorf("validate-tag %q: rc=%d out=%q, want accepted and echoed", tc.tag, rc, out)
		}
		if !tc.ok && rc == 0 {
			t.Errorf("validate-tag accepted %q", tc.tag)
		}
	}
}

// --- check-ancestor (a throwaway git repo with an origin/main remote-tracking ref) -------------

func ancestorRepo(t *testing.T) string {
	t.Helper()
	r := t.TempDir()
	copyScript(t, r, "release.sh")
	g := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", r, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
		// isolated from the user's git config (signing, hooks, default branch)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + r, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	g("init", "-q", "-b", "main")
	g("commit", "-q", "--allow-empty", "-m", "c1")
	g("tag", "-a", "-m", "rel", "v0.1.0")
	g("commit", "-q", "--allow-empty", "-m", "c2")
	g("update-ref", "refs/remotes/origin/main", "HEAD")
	g("checkout", "-q", "-b", "side")
	g("commit", "-q", "--allow-empty", "-m", "c3")
	g("tag", "-a", "-m", "rel", "v0.2.0")
	return r
}

func TestReleaseCheckAncestor(t *testing.T) {
	r := ancestorRepo(t)
	script := filepath.Join(r, "scripts", "release.sh")
	env := []string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}
	stubs := t.TempDir()
	out, rc := relRun(t, stubs, nil, env, script, "check-ancestor", "refs/tags/v0.1.0", "origin/main")
	if rc != 0 || !strings.Contains(out, "is on origin/main") {
		t.Fatalf("tag on main rejected: rc=%d\n%s", rc, out)
	}
	for _, tc := range []struct{ name, rev, base, want string }{
		{"tag on a side branch", "refs/tags/v0.2.0", "origin/main", "not on origin/main"},
		{"side branch head", "side", "origin/main", "not on origin/main"},
		{"unknown base", "refs/tags/v0.1.0", "origin/nope", "unknown base"},
		{"unknown revision", "refs/tags/v9.9.9", "origin/main", "unknown revision"},
	} {
		out, rc := relRun(t, stubs, nil, env, script, "check-ancestor", tc.rev, tc.base)
		if rc == 0 || !strings.Contains(out, tc.want) {
			t.Errorf("%s: rc=%d, want failure with %q\n%s", tc.name, rc, tc.want, out)
		}
	}
	// the default base is origin/main
	if out, rc := relRun(t, stubs, nil, env, script, "check-ancestor", "refs/tags/v0.2.0"); rc == 0 {
		t.Errorf("default base accepted a side-branch tag:\n%s", out)
	}
}

// --- docker / gh stubs ------------------------------------------------------------------------

// dockerStub: records calls in $STUB_LOG; `buildx imagetools inspect ... <ref>` prints
// $STUB_RAW/<ref with / : @ replaced by _> or fails with the content of $STUB_ERR; `buildx version`
// exits $DOCKER_BUILDX_RC; `save` streams $STUB_SAVE; `run` exits $DOCKER_RUN_RC.
const dockerStub = `echo "docker $*" >> "$STUB_LOG"
case "$1 $2 $3" in
  "buildx imagetools inspect")
    ref="${@: -1}"; f="$STUB_RAW/$(printf '%s' "$ref" | tr '/:@' '___')"
    if [ -f "$f" ]; then cat "$f"; else cat "$STUB_ERR" >&2 2> /dev/null; exit 1; fi ;;
  "buildx build "*) exit 0 ;;
  "buildx version "*) exit "${DOCKER_BUILDX_RC:-0}" ;;
esac
case "$1" in
  save) cat "$STUB_SAVE" ;;
  run) exit "${DOCKER_RUN_RC:-0}" ;;
esac
`

// ghStubRelease: `gh release view <tag> ...` succeeds when $STUB_GH = exists, prints gh's
// not-found message when it is notfound, and anything else is an auth/network failure.
const ghStubRelease = `echo "gh $*" >> "$STUB_LOG"
case "${STUB_GH:-}" in
  exists) echo '{"tagName":"v1.0.0"}' ;;
  notfound) echo "release not found" >&2; exit 1 ;;
  *) echo "HTTP 401: Bad credentials (https://api.github.com/graphql)" >&2; exit 1 ;;
esac
`

type relEnv struct{ dir, stubs, raw, log string }

func newRelEnv(t *testing.T) *relEnv {
	t.Helper()
	e := &relEnv{dir: t.TempDir()}
	e.stubs = filepath.Join(e.dir, "bin")
	e.raw = filepath.Join(e.dir, "raw")
	e.log = filepath.Join(e.dir, "calls.log")
	if err := os.MkdirAll(e.raw, 0o755); err != nil {
		t.Fatal(err)
	}
	writeStub(t, e.stubs, "docker", dockerStub)
	writeStub(t, e.stubs, "gh", ghStubRelease)
	return e
}

func (e *relEnv) setRaw(t *testing.T, ref, body string) {
	t.Helper()
	name := strings.NewReplacer("/", "_", ":", "_", "@", "_").Replace(ref)
	if err := os.WriteFile(filepath.Join(e.raw, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (e *relEnv) setErr(t *testing.T, msg string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.dir, "err"), []byte(msg+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (e *relEnv) run(t *testing.T, extraPath, env []string, args ...string) (string, int) {
	t.Helper()
	base := []string{"STUB_LOG=" + e.log, "STUB_RAW=" + e.raw, "STUB_ERR=" + filepath.Join(e.dir, "err"), "STUB_SAVE=" + filepath.Join(e.dir, "save.tar")}
	return relRun(t, e.stubs, extraPath, append(base, env...), releaseScript(t), args...)
}

func (e *relEnv) calls(t *testing.T) string {
	b, _ := os.ReadFile(e.log)
	return string(b)
}

// runMinPath runs release.sh with a PATH of only bash and dirname, so no docker or gh can be found
// (on the ubuntu runner both live in /usr/bin, so /usr/bin must not be on this PATH).
func runMinPath(t *testing.T, args ...string) (string, int) {
	t.Helper()
	dir := t.TempDir()
	for _, c := range []string{"bash", "dirname"} {
		p, err := exec.LookPath(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(p, filepath.Join(dir, c)); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(releaseScript(t), args...)
	cmd.Env = []string{"PATH=" + dir}
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(out), 0
}

// --- check-absent -----------------------------------------------------------------------------

func TestReleaseCheckAbsentImage(t *testing.T) {
	e := newRelEnv(t)
	e.setRaw(t, "ghcr.io/o/k8s-mcp:v1.0.0", `{"schemaVersion":2}`)
	if out, rc := e.run(t, nil, nil, "check-absent", "image", "ghcr.io/o/k8s-mcp:v1.0.0"); rc != 1 || !strings.Contains(out, "already exists") {
		t.Fatalf("existing image tag: rc=%d\n%s", rc, out)
	}
	for _, msg := range []string{"ERROR: ghcr.io/o/k8s-mcp:v2.0.0: not found", "manifest unknown",
		`{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, `{"errors":[{"code":"NAME_UNKNOWN"}]}`} {
		e.setErr(t, msg)
		if out, rc := e.run(t, nil, nil, "check-absent", "image", "ghcr.io/o/k8s-mcp:v2.0.0"); rc != 0 {
			t.Errorf("%q should read as absent: rc=%d\n%s", msg, rc, out)
		}
	}
	// unknown is not absent: auth, network, another ref's not-found, empty output
	for _, msg := range []string{"denied", "failed to fetch anonymous token: 403 Forbidden",
		"dial tcp: lookup ghcr.io: no such host", "", "ERROR: ghcr.io/o/other:v2.0.0: not found", "ERROR: file not found"} {
		e.setErr(t, msg)
		if out, rc := e.run(t, nil, nil, "check-absent", "image", "ghcr.io/o/k8s-mcp:v2.0.0"); rc != 2 {
			t.Errorf("%q gave rc=%d, want 2 (fail closed)\n%s", msg, rc, out)
		}
	}
	// a missing or broken buildx is not "not published"
	e.setErr(t, "ERROR: ghcr.io/o/k8s-mcp:v2.0.0: not found")
	if out, rc := e.run(t, nil, []string{"DOCKER_BUILDX_RC=1"}, "check-absent", "image", "ghcr.io/o/k8s-mcp:v2.0.0"); rc != 2 || !strings.Contains(out, "not usable") {
		t.Errorf("broken buildx: rc=%d\n%s", rc, out)
	}
	if out, rc := runMinPath(t, "check-absent", "image", "ghcr.io/o/k8s-mcp:v2.0.0"); rc != 2 {
		t.Errorf("no docker on PATH: rc=%d\n%s", rc, out)
	}
}

func TestReleaseCheckAbsentRelease(t *testing.T) {
	e := newRelEnv(t)
	if out, rc := e.run(t, nil, []string{"STUB_GH=exists"}, "check-absent", "release", repoSlug, "v1.0.0"); rc != 1 || !strings.Contains(out, "already exists") {
		t.Fatalf("existing release: rc=%d\n%s", rc, out)
	}
	if !strings.Contains(e.calls(t), "gh release view v1.0.0 --repo "+repoSlug) {
		t.Fatalf("unexpected gh call: %s", e.calls(t))
	}
	if out, rc := e.run(t, nil, []string{"STUB_GH=notfound"}, "check-absent", "release", repoSlug, "v1.0.0"); rc != 0 {
		t.Fatalf("missing release should pass: rc=%d\n%s", rc, out)
	}
	if out, rc := e.run(t, nil, []string{"STUB_GH=broken"}, "check-absent", "release", repoSlug, "v1.0.0"); rc != 2 {
		t.Fatalf("gh auth failure must fail closed with 2: rc=%d\n%s", rc, out)
	}
	for _, args := range [][]string{{"release", repoSlug, "v1.0"}, {"release", "not a repo", "v1.0.0"}, {"nothing", "x"}, {}} {
		if out, rc := e.run(t, nil, []string{"STUB_GH=notfound"}, append([]string{"check-absent"}, args...)...); rc == 0 {
			t.Errorf("check-absent %v accepted:\n%s", args, out)
		}
	}
	if out, rc := runMinPath(t, "check-absent", "release", repoSlug, "v1.0.0"); rc != 2 {
		t.Errorf("no gh on PATH: rc=%d\n%s", rc, out)
	}
}

// --- identity ---------------------------------------------------------------------------------

func TestReleaseIdentity(t *testing.T) {
	stubs := t.TempDir()
	want := "https://github.com/astawiany/k8s-mcp/.github/workflows/release.yml@refs/tags/v1.2.3"
	out, rc := relRun(t, stubs, nil, nil, releaseScript(t), "identity", repoSlug, "v1.2.3")
	if rc != 0 || strings.TrimSpace(out) != want {
		t.Fatalf("identity: rc=%d out=%q, want %q", rc, out, want)
	}
	for _, args := range [][]string{{repoSlug, "v1.2"}, {repoSlug, "main"}, {"not a repo", "v1.2.3"}, {repoSlug}} {
		if out, rc := relRun(t, stubs, nil, nil, releaseScript(t), append([]string{"identity"}, args...)...); rc == 0 {
			t.Errorf("identity %v accepted: %s", args, out)
		}
	}

	// exact regexp for one tag
	out, rc = relRun(t, stubs, nil, nil, releaseScript(t), "identity-regexp", repoSlug, "v1.2.3")
	if rc != 0 {
		t.Fatalf("identity-regexp: rc=%d %s", rc, out)
	}
	exact := strings.TrimSpace(out)
	if exact != `^https://github\.com/astawiany/k8s-mcp/\.github/workflows/release\.yml@refs/tags/v1\.2\.3$` {
		t.Fatalf("identity-regexp with tag = %q", exact)
	}
	// any release tag
	out, _ = relRun(t, stubs, nil, nil, releaseScript(t), "identity-regexp", repoSlug)
	anyTag := strings.TrimSpace(out)
	if anyTag != `^https://github\.com/astawiany/k8s-mcp/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$` {
		t.Fatalf("identity-regexp = %q", anyTag)
	}
	reExact, reAny := regexp.MustCompile(exact), regexp.MustCompile(anyTag)
	if !reExact.MatchString(want) || !reAny.MatchString(want) {
		t.Fatal("regexps do not match the real identity")
	}
	for _, bad := range []string{
		"https://github.com/astawiany/k8s-mcp/.github/workflows/release.yml@refs/heads/main",
		"https://github.com/astawiany/k8s-mcp/.github/workflows/validate.yml@refs/tags/v1.2.3",
		"https://github.com/evil/k8s-mcp/.github/workflows/release.yml@refs/tags/v1.2.3",
		"https://github.com/astawiany/k8s-mcpX/.github/workflows/release.yml@refs/tags/v1.2.3",
		"https://github.com/astawiany/k8s-mcp/.github/workflows/release.yml@refs/tags/v1.2.3-rc1",
		"https://githubXcom/astawiany/k8s-mcp/.github/workflows/release.yml@refs/tags/v1.2.3",
	} {
		if reAny.MatchString(bad) || reExact.MatchString(bad) {
			t.Errorf("identity regexp matched %s", bad)
		}
	}
	if reExact.MatchString(strings.Replace(want, "v1.2.3", "v1.2.4", 1)) {
		t.Error("exact regexp matched another tag")
	}
}

// --- digests, assert-scanned, assert-tag --------------------------------------------------------

func TestReleaseImageDigest(t *testing.T) {
	jq := jqDir(t)
	e := newRelEnv(t)
	m := filepath.Join(e.dir, "m.json")
	write := func(s string) {
		if err := os.WriteFile(m, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"containerimage.digest": "sha256:` + d64 + `"}`)
	if out, rc := e.run(t, jq, nil, "image-digest", m); rc != 0 || strings.TrimSpace(out) != "sha256:"+d64 {
		t.Fatalf("image-digest: rc=%d %q", rc, out)
	}
	for _, bad := range []string{`{}`, `{"containerimage.digest": "sha256:abc"}`, `{"containerimage.digest": "latest"}`} {
		write(bad)
		if out, rc := e.run(t, jq, nil, "image-digest", m); rc == 0 {
			t.Errorf("accepted %s: %s", bad, out)
		}
	}
	if _, rc := e.run(t, jq, nil, "image-digest", filepath.Join(e.dir, "missing.json")); rc == 0 {
		t.Error("missing metadata file accepted")
	}
}

func saveTar(t *testing.T, path, config string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	body := fmt.Sprintf(`[{"Config": %q, "Layers": []}]`, config)
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
}

func (e *relEnv) pushedIndex(t *testing.T, config string) {
	e.setRaw(t, "ghcr.io/o/k8s-mcp@sha256:"+d64, fmt.Sprintf(`{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"digest":"sha256:%s","platform":{"os":"linux","architecture":"amd64"}},{"digest":"sha256:%s","platform":{"os":"unknown","architecture":"unknown"}}]}`, d64b, strings.Repeat("c", 64)))
	e.setRaw(t, "ghcr.io/o/k8s-mcp@sha256:"+d64b, fmt.Sprintf(`{"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":%q}}`, config))
}

func TestReleaseAssertScanned(t *testing.T) {
	jq := jqDir(t)
	e := newRelEnv(t)
	cfg := strings.Repeat("e", 64)
	e.pushedIndex(t, "sha256:"+cfg)
	ref := "ghcr.io/o/k8s-mcp@sha256:" + d64
	for _, layout := range []string{cfg + ".json", "blobs/sha256/" + cfg} {
		saveTar(t, filepath.Join(e.dir, "save.tar"), layout)
		if out, rc := e.run(t, jq, nil, "assert-scanned", "k8s-mcp:scan", ref); rc != 0 || !strings.Contains(out, "equals the scanned image config") {
			t.Fatalf("%s: rc=%d\n%s", layout, rc, out)
		}
	}
	e.pushedIndex(t, "sha256:"+strings.Repeat("f", 64))
	if out, rc := e.run(t, jq, nil, "assert-scanned", "k8s-mcp:scan", ref); rc == 0 || !strings.Contains(out, "is not the scanned image") {
		t.Fatalf("different pushed image accepted: rc=%d\n%s", rc, out)
	}
	if out, rc := e.run(t, jq, nil, "assert-scanned", "k8s-mcp:scan", "ghcr.io/o/k8s-mcp:v1.0.0"); rc == 0 || !strings.Contains(out, "never a tag") {
		t.Fatalf("tag accepted: rc=%d\n%s", rc, out)
	}
	e.setRaw(t, "ghcr.io/o/k8s-mcp@sha256:"+d64, `{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	if out, rc := e.run(t, jq, nil, "assert-scanned", "k8s-mcp:scan", ref); rc == 0 {
		t.Fatalf("index without amd64 accepted:\n%s", out)
	}
}

func TestReleaseAssertTag(t *testing.T) {
	jq := jqDir(t)
	e := newRelEnv(t)
	e.setRaw(t, "ghcr.io/o/k8s-mcp:v1.0.0", `{"digest":"sha256:`+d64+`"}`)
	if out, rc := e.run(t, jq, nil, "assert-tag", "ghcr.io/o/k8s-mcp:v1.0.0", "sha256:"+d64); rc != 0 {
		t.Fatalf("matching tag rejected: rc=%d\n%s", rc, out)
	}
	if !strings.Contains(e.calls(t), "buildx imagetools inspect --format {{json .Manifest}} ghcr.io/o/k8s-mcp:v1.0.0") {
		t.Fatalf("unexpected docker call: %s", e.calls(t))
	}
	for _, args := range [][]string{
		{"ghcr.io/o/k8s-mcp:v1.0.0", "sha256:" + d64b},
		{"ghcr.io/o/k8s-mcp:v2.0.0", "sha256:" + d64},
		{"ghcr.io/o/k8s-mcp@sha256:" + d64, "sha256:" + d64},
		{"ghcr.io/o/k8s-mcp:v1.0.0", "latest"},
	} {
		if out, rc := e.run(t, jq, nil, append([]string{"assert-tag"}, args...)...); rc == 0 {
			t.Errorf("assert-tag %v accepted:\n%s", args, out)
		}
	}
}

// --- image build args, govulncheck --------------------------------------------------------------

func TestReleaseImageBuildArgs(t *testing.T) {
	e := newRelEnv(t)
	env := []string{"TAG=v1.2.3", "REVISION=abc", "SOURCE=https://github.com/o/r", "SOURCE_DATE_EPOCH=1700000000"}
	if out, rc := e.run(t, nil, env, "build", "--load", "-t", "k8s-mcp:scan"); rc != 0 {
		t.Fatalf("build: rc=%d\n%s", rc, out)
	}
	call := e.calls(t)
	for _, want := range []string{"buildx build --builder release --platform linux/amd64",
		"--build-arg SOURCE_DATE_EPOCH=1700000000", "--build-arg VERSION=v1.2.3", "--build-arg REVISION=abc",
		"--build-arg SOURCE=https://github.com/o/r", "--load -t k8s-mcp:scan " + repoRoot(t)} {
		if !strings.Contains(call, want) {
			t.Errorf("missing %q in %s", want, call)
		}
	}
	if out, rc := e.run(t, nil, env[:3], "build", "--load"); rc == 0 || !strings.Contains(out, "SOURCE_DATE_EPOCH") {
		t.Errorf("build without SOURCE_DATE_EPOCH: rc=%d\n%s", rc, out)
	}
	if out, rc := e.run(t, nil, append([]string{"TAG=latest"}, env[1:]...), "build", "--load"); rc == 0 {
		t.Errorf("build with an invalid tag accepted:\n%s", out)
	}
}

func TestReleaseGovulncheckUsesPinnedBuilder(t *testing.T) {
	e := newRelEnv(t)
	if out, rc := e.run(t, nil, nil, "govulncheck"); rc != 0 {
		t.Fatalf("govulncheck: rc=%d\n%s", rc, out)
	}
	call := e.calls(t)
	builder := regexp.MustCompile(`(?m)^FROM (\S+) AS build$`).FindStringSubmatch(readFileT(t, filepath.Join(repoRoot(t), "Dockerfile")))
	if builder == nil || !regexp.MustCompile(`^golang:\S+@sha256:[0-9a-f]{64}$`).MatchString(builder[1]) {
		t.Fatalf("Dockerfile builder not digest-pinned: %v", builder)
	}
	ver := regexp.MustCompile(`(?m)^GOVULNCHECK_VERSION=(\S+)$`).FindStringSubmatch(readFileT(t, filepath.Join(repoRoot(t), "versions.env")))[1]
	for _, want := range []string{"run --rm -v " + repoRoot(t) + ":/src:ro -w /src", " " + builder[1] + " ",
		"golang.org/x/vuln/cmd/govulncheck@" + ver + " && govulncheck ./..."} {
		if !strings.Contains(call, want) {
			t.Errorf("missing %q in %s", want, call)
		}
	}
	if _, rc := e.run(t, nil, []string{"DOCKER_RUN_RC=3"}, "govulncheck"); rc != 3 {
		t.Errorf("govulncheck failure not propagated: rc=%d", rc)
	}
}

// --- binaries: build-binary, checksums, notes ---------------------------------------------------

// goStub writes the args and selected env to $STUB_LOG and a fake binary to the -o path.
const goStub = `echo "go $* CGO_ENABLED=$CGO_ENABLED GOOS=$GOOS GOARCH=$GOARCH GOFLAGS=$GOFLAGS" >> "$STUB_LOG"
out=""; while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac; done
printf 'fake binary\n' > "$out"
`

func tarGzNames(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			names = append(names, h.Name)
		}
	}
	slices.Sort(names)
	return names
}

func TestReleaseBuildBinary(t *testing.T) {
	e := newRelEnv(t)
	writeStub(t, e.stubs, "go", goStub)
	dist := filepath.Join(e.dir, "dist")
	out, rc := e.run(t, nil, []string{"SOURCE_DATE_EPOCH=1700000000"}, "build-binary", "darwin", "arm64", "v1.2.3", dist)
	if rc != 0 {
		t.Fatalf("build-binary: rc=%d\n%s", rc, out)
	}
	call := e.calls(t)
	for _, want := range []string{"go build -trimpath -buildvcs=false", `-ldflags -s -w -X main.version=v1.2.3`,
		"./cmd/k8s-mcp", "CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 GOFLAGS=-mod=readonly"} {
		if !strings.Contains(call, want) {
			t.Errorf("missing %q in %s", want, call)
		}
	}
	archive := filepath.Join(dist, "k8s-mcp_v1.2.3_darwin_arm64.tar.gz")
	got := tarGzNames(t, archive)
	want := []string{"k8s-mcp_v1.2.3_darwin_arm64/LICENSE", "k8s-mcp_v1.2.3_darwin_arm64/README.md", "k8s-mcp_v1.2.3_darwin_arm64/k8s-mcp"}
	if !slices.Equal(got, want) {
		t.Fatalf("archive members = %v, want %v", got, want)
	}
	for _, args := range [][]string{{"windows", "amd64", "v1.2.3", dist}, {"linux", "386", "v1.2.3", dist},
		{"linux", "amd64", "1.2.3", dist}, {"linux", "amd64", "v1.2.3 -X main.x=y", dist}} {
		if out, rc := e.run(t, nil, nil, append([]string{"build-binary"}, args...)...); rc == 0 {
			t.Errorf("build-binary %v accepted:\n%s", args, out)
		}
	}
}

func TestReleaseChecksums(t *testing.T) {
	e := newRelEnv(t)
	dist := filepath.Join(e.dir, "dist")
	if err := os.MkdirAll(dist, 0o755); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range []string{"darwin_amd64", "darwin_arm64", "linux_amd64", "linux_arm64"} {
		n := "k8s-mcp_v1.2.3_" + p + ".tar.gz"
		names = append(names, n)
		if err := os.WriteFile(filepath.Join(dist, n), []byte(p), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if out, rc := e.run(t, nil, nil, "checksums", dist, "v1.2.3"); rc != 0 {
		t.Fatalf("checksums: rc=%d\n%s", rc, out)
	}
	var want strings.Builder
	for _, n := range names {
		b, _ := os.ReadFile(filepath.Join(dist, n))
		fmt.Fprintf(&want, "%s  %s\n", sum(b), n)
	}
	if got := readFileT(t, filepath.Join(dist, "SHA256SUMS")); got != want.String() {
		t.Fatalf("SHA256SUMS =\n%s\nwant\n%s", got, want.String())
	}
	// a missing platform or an unexpected extra archive is an error, not a shorter list
	if err := os.WriteFile(filepath.Join(dist, "k8s-mcp_v1.2.3_windows_amd64.tar.gz"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, rc := e.run(t, nil, nil, "checksums", dist, "v1.2.3"); rc == 0 {
		t.Errorf("extra archive accepted:\n%s", out)
	}
	_ = os.Remove(filepath.Join(dist, "k8s-mcp_v1.2.3_windows_amd64.tar.gz"))
	_ = os.Remove(filepath.Join(dist, names[0]))
	if out, rc := e.run(t, nil, nil, "checksums", dist, "v1.2.3"); rc == 0 {
		t.Errorf("missing archive accepted:\n%s", out)
	}
}

func TestReleaseNotesCarryVerificationCommands(t *testing.T) {
	e := newRelEnv(t)
	ref := "ghcr.io/astawiany/k8s-mcp@sha256:" + d64
	out, rc := e.run(t, nil, nil, "notes", "v1.2.3", ref, repoSlug)
	if rc != 0 {
		t.Fatalf("notes: rc=%d\n%s", rc, out)
	}
	id := "https://github.com/astawiany/k8s-mcp/.github/workflows/release.yml@refs/tags/v1.2.3"
	for _, want := range []string{
		"cosign verify " + ref, "--certificate-identity " + id, "--certificate-oidc-issuer " + issuer,
		"cosign verify-blob --bundle SHA256SUMS.sigstore.json", "cosign verify-blob --bundle k8s-mcp_v1.2.3_linux_amd64.tar.gz.sigstore.json",
		"sha256sum --ignore-missing -c SHA256SUMS", "docs/security.md",
		"creates the GHCR package as private", "not for anonymous users",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("notes lack %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, ":latest") {
		t.Error("notes mention :latest")
	}
	for _, args := range [][]string{{"v1.2.3", "ghcr.io/astawiany/k8s-mcp:v1.2.3", repoSlug}, {"v1.2", ref, repoSlug}} {
		if out, rc := e.run(t, nil, nil, append([]string{"notes"}, args...)...); rc == 0 {
			t.Errorf("notes %v accepted:\n%s", args, out)
		}
	}
}

// --- security-scan.sh -------------------------------------------------------------------------

// trivyStub records calls and exits 1 when its argument list contains $TRIVY_FAIL.
const trivyStub = `echo "trivy $*" >> "$STUB_LOG"
case " $* " in *" ${TRIVY_FAIL:-none} "*) exit 1 ;; esac
exit 0
`

func TestSecurityScanGates(t *testing.T) {
	e := newRelEnv(t)
	writeStub(t, e.stubs, "trivy", trivyStub)
	scan := filepath.Join(repoRoot(t), "scripts", "security-scan.sh")
	env := []string{"STUB_LOG=" + e.log}
	out, rc := relRun(t, e.stubs, nil, env, scan, "k8s-mcp:scan")
	if rc != 0 {
		t.Fatalf("all gates pass: rc=%d\n%s", rc, out)
	}
	root := repoRoot(t)
	calls := e.calls(t)
	for _, want := range []string{
		"trivy image --no-progress --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 k8s-mcp:scan",
		"trivy image --no-progress --scanners secret --exit-code 1 k8s-mcp:scan",
		"trivy config --severity HIGH,CRITICAL --exit-code 1 " + root + "/Dockerfile",
		"trivy fs --no-progress --scanners secret --exit-code 1",
		"docker run --rm",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing gate %q in:\n%s", want, calls)
		}
	}
	for _, g := range []struct{ fail, name string }{
		{"vuln", "image-vulns"}, {"k8s-mcp:scan", "image-vulns"}, {root + "/Dockerfile", "dockerfile-config"}, {"fs", "repo-secrets"},
	} {
		out, rc := relRun(t, e.stubs, nil, append(env, "TRIVY_FAIL="+g.fail), scan, "k8s-mcp:scan")
		if rc != 1 || !strings.Contains(out, "FAIL "+g.name) {
			t.Errorf("TRIVY_FAIL=%s: rc=%d, want FAIL %s\n%s", g.fail, rc, g.name, out)
		}
	}
	if out, rc := relRun(t, e.stubs, nil, append(env, "DOCKER_RUN_RC=3", "STUB_RAW="+e.raw), scan, "k8s-mcp:scan"); rc != 1 || !strings.Contains(out, "FAIL govulncheck") {
		t.Errorf("govulncheck failure not a gate failure: rc=%d\n%s", rc, out)
	}
	if _, rc := relRun(t, e.stubs, nil, env, scan); rc != 2 {
		t.Errorf("no image argument: rc=%d, want 2", rc)
	}
}

// --- release.yml structure -----------------------------------------------------------------------

type wfStep = map[string]any

func jobSteps(job map[string]any) []wfStep {
	var out []wfStep
	steps, _ := job["steps"].([]any)
	for _, s := range steps {
		m, _ := s.(map[string]any)
		out = append(out, m)
	}
	return out
}

func str(v any) string { s, _ := v.(string); return s }

// stepIndex returns the index of the first step in steps whose run contains needle, or -1.
func stepIndex(steps []wfStep, needle string) int {
	for i, s := range steps {
		if strings.Contains(str(s["run"]), needle) {
			return i
		}
	}
	return -1
}

func permsOf(job map[string]any) map[string]string {
	out := map[string]string{}
	p, _ := job["permissions"].(map[string]any)
	for k, v := range p {
		out[k] = fmt.Sprint(v)
	}
	return out
}

func needsOf(job map[string]any) []string {
	switch n := job["needs"].(type) {
	case string:
		return []string{n}
	case []any:
		var out []string
		for _, x := range n {
			out = append(out, fmt.Sprint(x))
		}
		return out
	}
	return nil
}

func samePerms(got map[string]string, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

// ordered returns whether the step order a < b < c ... holds and all indexes exist.
func ordered(idx ...int) bool {
	for i, x := range idx {
		if x < 0 || (i > 0 && idx[i-1] >= x) {
			return false
		}
	}
	return true
}

// checkReleaseWorkflow returns every rule violation found in the release workflow text.
func checkReleaseWorkflow(text string) []string {
	var bad []string
	add := func(format string, a ...any) { bad = append(bad, fmt.Sprintf(format, a...)) }

	for i, line := range strings.Split(text, "\n") {
		if m := usesLine.FindStringSubmatch(line); m != nil {
			if !pinned.MatchString(m[1]) {
				add("line %d: %q is not pinned to a 40-hex commit SHA", i+1, m[1])
			} else if !versionNote.MatchString(m[2]) {
				add("line %d: %q has no '# vX.Y.Z' version comment", i+1, m[1])
			}
			name := strings.SplitN(m[1], "@", 2)[0]
			if !slices.Contains([]string{"actions/checkout", "actions/upload-artifact", "actions/download-artifact"}, name) {
				add("line %d: third-party action %q is not allowed", i+1, name)
			}
		}
		if strings.Contains(line, ":latest") {
			add("line %d: uses a :latest tag", i+1)
		}
	}
	if strings.Contains(text, "--certificate-identity-regexp") {
		add("cosign verification uses an identity regexp instead of the exact identity")
	}

	var wf map[string]any
	if err := yaml.Unmarshal([]byte(text), &wf); err != nil {
		return append(bad, "YAML does not parse: "+err.Error())
	}
	bad = append(bad, checkoutCredentials(wf)...)
	if p, ok := wf["permissions"].(map[string]any); !ok || len(p) != 0 {
		add("workflow-level permissions must be {} (got %v)", wf["permissions"])
	}
	on, _ := wf["on"].(map[string]any)
	push, _ := on["push"].(map[string]any)
	tags, _ := push["tags"].([]any)
	if len(on) != 1 || len(push) != 1 || len(tags) != 1 || tags[0] != "v*" {
		add("trigger must be only push of tags ['v*'] (got %v)", wf["on"])
	}
	if c, _ := wf["concurrency"].(map[string]any); c == nil || c["cancel-in-progress"] != false {
		add("concurrency with cancel-in-progress: false is missing")
	}

	jobs, _ := wf["jobs"].(map[string]any)
	var names []string
	for n := range jobs {
		names = append(names, n)
	}
	slices.Sort(names)
	if strings.Join(names, ",") != "build,image,release,verify" {
		add("jobs are %v, want build, image, release, verify", names)
	}
	job := func(n string) map[string]any { j, _ := jobs[n].(map[string]any); return j }
	for _, n := range names {
		j := job(n)
		if _, has := j["timeout-minutes"]; !has {
			add("job %q has no timeout-minutes", n)
		}
		if _, has := j["permissions"]; !has {
			add("job %q has no explicit permissions", n)
		}
		p := permsOf(j)
		writes := false
		for k, v := range p {
			if v == "write" || k == "id-token" {
				writes = true
			}
		}
		if writes && j["environment"] != "release" {
			add("job %q can publish (write or id-token permission) but has no environment: release", n)
		}
		if n != "verify" && !slices.Contains(needsOf(j), "verify") {
			add("job %q does not need verify", n)
		}
		for i, s := range jobSteps(j) {
			if strings.Contains(str(s["run"]), "${{") {
				add("job %q step %d interpolates an expression inside run: (use env)", n, i+1)
			}
		}
	}
	for _, n := range []string{"image", "release"} {
		if job(n)["environment"] != "release" {
			add("publishing job %q has no environment: release", n)
		}
	}
	if _, has := job("verify")["environment"]; has {
		add("verify must not wait for an Environment approval")
	}

	// verify
	if v := job("verify"); v != nil {
		if !samePerms(permsOf(v), map[string]string{"contents": "read", "packages": "read"}) {
			add("verify permissions are %v, want contents: read, packages: read", permsOf(v))
		}
		steps := jobSteps(v)
		if len(steps) == 0 || fmt.Sprint(mapOf(steps[0]["with"])["fetch-depth"]) != "0" {
			add("verify checkout has no fetch-depth: 0")
		}
		body := ""
		for _, s := range steps {
			body += str(s["run"])
		}
		for _, want := range []string{`scripts/release.sh validate-tag "$TAG"`, `scripts/release.sh check-ancestor "$GITHUB_SHA" origin/main`,
			`scripts/release.sh check-absent image "ghcr.io/${owner}/k8s-mcp:${tag}"`, `scripts/release.sh check-absent release "$GITHUB_REPOSITORY" "$tag"`} {
			if !strings.Contains(body, want) {
				add("verify does not run %s", want)
			}
		}
	}

	// build
	if b := job("build"); b != nil {
		if !samePerms(permsOf(b), map[string]string{"contents": "read"}) {
			add("build permissions are %v, want contents: read", permsOf(b))
		}
		strat := mapOf(b["strategy"])
		mx := mapOf(strat["matrix"])
		if fmt.Sprint(mx["goos"]) != "[linux darwin]" || fmt.Sprint(mx["goarch"]) != "[amd64 arm64]" {
			add("build matrix is %v, want goos [linux darwin] x goarch [amd64 arm64]", mx)
		}
		steps := jobSteps(b)
		vuln, bin := stepIndex(steps, "govulncheck ./..."), stepIndex(steps, "scripts/release.sh build-binary")
		up := -1
		for i, s := range steps {
			if strings.HasPrefix(str(s["uses"]), "actions/upload-artifact@") {
				up = i
			}
		}
		if !ordered(vuln, bin, up) {
			add("build must run govulncheck, then build-binary, then upload-artifact (got %d %d %d)", vuln, bin, up)
		}
	}

	// image
	if im := job("image"); im != nil {
		if !samePerms(permsOf(im), map[string]string{"contents": "read", "packages": "write", "id-token": "write"}) {
			add("image permissions are %v", permsOf(im))
		}
		steps := jobSteps(im)
		scanBuild := stepIndex(steps, "build --load -t k8s-mcp:scan")
		gate := stepIndex(steps, "scripts/security-scan.sh k8s-mcp:scan")
		push := stepIndex(steps, "push-by-digest=true")
		same := stepIndex(steps, "assert-scanned k8s-mcp:scan")
		sign := stepIndex(steps, "cosign sign --yes")
		verify := stepIndex(steps, "cosign verify ")
		tag := stepIndex(steps, "imagetools create -t")
		if !ordered(scanBuild, gate, push, same, sign, tag) || verify < sign || verify > tag {
			add("image steps out of order: scan build %d, trivy gate %d, push %d, assert-scanned %d, sign %d, verify %d, tag %d",
				scanBuild, gate, push, same, sign, verify, tag)
		}
		if push >= 0 {
			pr := str(steps[push]["run"])
			for _, want := range []string{"--provenance=mode=max", `--sbom="generator=$SBOM_GENERATOR_IMAGE"`,
				`--output "type=image,name=$IMAGE,push-by-digest=true,name-canonical=true,push=true"`} {
				if !strings.Contains(pr, want) {
					add("push step lacks %s", want)
				}
			}
			if strings.Contains(pr, "--push") || strings.Contains(pr, " -t ") {
				add("push step pushes a tag")
			}
			if !strings.Contains(pr, "check-absent image") || strings.Index(pr, "check-absent image") > strings.Index(pr, "scripts/release.sh build") {
				add("push step does not re-check the version is absent before pushing")
			}
		}
		if tag >= 0 {
			tr := str(steps[tag]["run"])
			ca, ic, at := strings.Index(tr, "check-absent image"), strings.Index(tr, "imagetools create"), strings.Index(tr, "assert-tag")
			if ca < 0 || !(ca < ic && ic < at) {
				add("tag step must check-absent, imagetools create, then assert-tag")
			}
		}
		if sign >= 0 {
			checkCosignVerify(str(steps[sign]["run"]), "cosign verify ", add)
		}
		if strings.Count(text, `-t "$IMAGE:$TAG"`) != 1 {
			add("the version tag must be written exactly once (imagetools create)")
		}
	}

	// release
	if r := job("release"); r != nil {
		if !samePerms(permsOf(r), map[string]string{"contents": "write", "id-token": "write"}) {
			add("release permissions are %v, want contents: write, id-token: write", permsOf(r))
		}
		for _, n := range []string{"build", "image"} {
			if !slices.Contains(needsOf(r), n) {
				add("release does not need %s", n)
			}
		}
		steps := jobSteps(r)
		sums := stepIndex(steps, "scripts/release.sh checksums")
		signBlob := stepIndex(steps, "cosign sign-blob")
		verifyBlob := stepIndex(steps, "cosign verify-blob")
		create := stepIndex(steps, "gh release create")
		if !ordered(sums, signBlob, create) || verifyBlob < signBlob || verifyBlob >= create {
			add("release steps out of order: checksums %d, sign-blob %d, verify-blob %d, gh release create %d", sums, signBlob, verifyBlob, create)
		}
		if signBlob >= 0 {
			body := str(steps[signBlob]["run"])
			if !strings.Contains(body, "--bundle") || !strings.Contains(body, "dist/SHA256SUMS") || !strings.Contains(body, "dist/k8s-mcp_*.tar.gz") {
				add("sign-blob must write --bundle files for every archive and SHA256SUMS")
			}
		}
		if verifyBlob >= 0 {
			checkCosignVerify(str(steps[verifyBlob]["run"]), "cosign verify-blob", add)
		}
		if create >= 0 {
			body := str(steps[create]["run"])
			for _, want := range []string{`check-absent release "$GITHUB_REPOSITORY" "$TAG"`, "--verify-tag", "--notes-file",
				"dist/SHA256SUMS", "dist/*.sigstore.json", "dist/k8s-mcp_*.tar.gz"} {
				if !strings.Contains(body, want) {
					add("release creation step lacks %s", want)
				}
			}
		}
		down := false
		for _, s := range steps {
			if strings.HasPrefix(str(s["uses"]), "actions/download-artifact@") {
				down = true
			}
		}
		if !down {
			add("release job does not download the build artifacts")
		}
	}
	return bad
}

// checkCosignVerify requires the exact identity of this tag and the GitHub OIDC issuer.
func checkCosignVerify(body, verb string, add func(string, ...any)) {
	if !strings.Contains(body, verb) {
		add("no %s", verb)
		return
	}
	if !strings.Contains(body, `identity="$(scripts/release.sh identity "$GITHUB_REPOSITORY" "$TAG")"`) ||
		!strings.Contains(body, `--certificate-identity "$identity"`) {
		add("%s does not use the exact identity of release.yml at this tag", verb)
	}
	if !strings.Contains(body, "--certificate-oidc-issuer "+issuer) {
		add("%s does not pin the OIDC issuer", verb)
	}
}

func mapOf(v any) map[string]any { m, _ := v.(map[string]any); return m }

func TestReleaseWorkflowStructure(t *testing.T) {
	if bad := checkReleaseWorkflow(readFileT(t, releaseWorkflowPath(t))); len(bad) > 0 {
		t.Fatalf("release.yml violates:\n- %s", strings.Join(bad, "\n- "))
	}
}

func TestReleaseWorkflowRulesBite(t *testing.T) {
	good := readFileT(t, releaseWorkflowPath(t))
	cases := []struct{ name, from, to, want string }{
		{"unpinned action", "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", "actions/checkout@v4", "not pinned"},
		{"third-party action", "uses: actions/download-artifact@", "uses: evil/download-artifact@", "third-party action"},
		{"workflow permissions granted", "permissions: {}", "permissions:\n  contents: write", "must be {}"},
		{"branch trigger", "    tags: ['v*']", "    tags: ['v*']\n    branches: [main]", "only push of tags"},
		{"wider tag trigger", "    tags: ['v*']", "    tags: ['*']", "only push of tags"},
		{"image without environment", "    environment: release\n    permissions:\n      contents: read\n      packages: write", "    permissions:\n      contents: read\n      packages: write", `"image" has no environment: release`},
		{"release without environment", "    environment: release\n    permissions:\n      contents: write", "    permissions:\n      contents: write", `"release" has no environment: release`},
		{"tag before signing", "      - name: Sign by digest and verify\n", "      - name: Tag early\n        run: docker buildx imagetools create -t x y\n      - name: Sign by digest and verify\n", "image steps out of order"},
		{":latest tag", `docker buildx imagetools create -t "$IMAGE:$TAG" "$REF"`, `docker buildx imagetools create -t "$IMAGE:$TAG" -t "$IMAGE:latest" "$REF"`, ":latest"},
		{"event interpolation in run", `tag="$(scripts/release.sh validate-tag "$TAG")"`, `tag="$(scripts/release.sh validate-tag "${{ github.ref_name }}")"`, "interpolates an expression"},
		{"verify not needed by image", "  image:\n    needs: verify", "  image:\n    needs: []", `"image" does not need verify`},
		{"no provenance", "--provenance=mode=max", "--provenance=false", "lacks --provenance=mode=max"},
		{"no sbom", `--sbom="generator=$SBOM_GENERATOR_IMAGE"`, "--sbom=false", "lacks --sbom="},
		{"identity regexp instead of exact", `--certificate-identity "$identity"`, `--certificate-identity-regexp ".*"`, "identity regexp"},
		{"verify-blob dropped", "cosign verify-blob", "echo skipped", "release steps out of order"},
		{"push before trivy gate", "run: scripts/security-scan.sh k8s-mcp:scan", "run: echo no gate", "image steps out of order"},
		{"no ancestor check", `scripts/release.sh check-ancestor "$GITHUB_SHA" origin/main`, "true", "check-ancestor"},
		{"no fetch-depth", "          fetch-depth: 0\n", "", "fetch-depth: 0"},
		{"govulncheck dropped", "govulncheck ./...", "echo skipped", "govulncheck"},
		{"timeout removed", "    timeout-minutes: 10\n", "", "no timeout-minutes"},
		{"checkout persists credentials", "          persist-credentials: false\n      - name: Install cosign", "          persist-credentials: true\n      - name: Install cosign", "without persist-credentials: false"},
		{"checkout persist-credentials unset", "          fetch-depth: 0\n          persist-credentials: false\n", "          fetch-depth: 0\n", "without persist-credentials: false"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(good, c.from) {
				t.Fatalf("mutation anchor %q not found in release.yml", c.from)
			}
			bad := checkReleaseWorkflow(strings.Replace(good, c.from, c.to, 1))
			if !strings.Contains(strings.Join(bad, "\n"), c.want) {
				t.Fatalf("mutation %q not rejected with %q; violations: %v", c.name, c.want, bad)
			}
		})
	}
}

// --- Dockerfile, .dockerignore, versions.env -----------------------------------------------------

func TestDockerfileHardening(t *testing.T) {
	root := repoRoot(t)
	df := readFileT(t, filepath.Join(root, "Dockerfile"))
	goVer := regexp.MustCompile(`(?m)^GO_VERSION=(\S+)$`).FindStringSubmatch(readFileT(t, filepath.Join(root, "versions.env")))[1]
	froms := regexp.MustCompile(`(?m)^FROM (\S+)`).FindAllStringSubmatch(df, -1)
	if len(froms) != 2 {
		t.Fatalf("want 2 stages, got %v", froms)
	}
	for _, f := range froms {
		if !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(f[1]) {
			t.Errorf("base %s is not digest-pinned", f[1])
		}
	}
	if !strings.HasPrefix(froms[0][1], "golang:"+goVer+"-alpine@sha256:") {
		t.Errorf("builder %s is not golang:%s-alpine (versions.env GO_VERSION)", froms[0][1], goVer)
	}
	if !strings.HasPrefix(froms[1][1], "gcr.io/distroless/static-debian12:nonroot@sha256:") {
		t.Errorf("final stage %s is not distroless static nonroot", froms[1][1])
	}
	for _, want := range []string{"GOFLAGS=-mod=readonly", "CGO_ENABLED=0", "go mod verify",
		`go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=${VERSION}"`,
		`org.opencontainers.image.source="${SOURCE}"`, `org.opencontainers.image.revision="${REVISION}"`,
		`org.opencontainers.image.version="${VERSION}"`, `org.opencontainers.image.licenses="MIT"`,
		`org.opencontainers.image.title="k8s-mcp"`, "\nUSER 65532:65532\n", "\nENTRYPOINT [\"/k8s-mcp\"]\n",
		"COPY --from=build /out/k8s-mcp /k8s-mcp"} {
		if !strings.Contains(df, want) {
			t.Errorf("Dockerfile lacks %q", want)
		}
	}
	if strings.Contains(df, ":latest") || strings.Contains(df, "COPY . ") {
		t.Error("Dockerfile uses :latest or copies the whole context")
	}
}

func TestDockerignoreIsAllowlist(t *testing.T) {
	var lines []string
	for _, l := range strings.Split(readFileT(t, filepath.Join(repoRoot(t), ".dockerignore")), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 || lines[0] != "*" {
		t.Fatalf(".dockerignore must start with '*' (deny all): %v", lines)
	}
	var allowed []string
	for _, l := range lines {
		if strings.HasPrefix(l, "!") {
			allowed = append(allowed, l)
		}
	}
	slices.Sort(allowed)
	if strings.Join(allowed, " ") != "!cmd/ !go.mod !go.sum !internal/" {
		t.Errorf("re-included paths = %v, want only go.mod, go.sum, cmd/, internal/", allowed)
	}
	for _, want := range []string{"**/*_test.go", "**/testdata/", "**/.env*", "**/*kubeconfig*", "**/*.pem", "**/*.key"} {
		if !slices.Contains(lines, want) {
			t.Errorf(".dockerignore does not exclude %s inside the allowed dirs", want)
		}
	}
}

func TestVersionsEnvReleasePins(t *testing.T) {
	env := readFileT(t, filepath.Join(repoRoot(t), "versions.env"))
	for _, re := range []string{
		`(?m)^COSIGN_VERSION=3\.\d+\.\d+$`,
		`(?m)^COSIGN_SHA256_LINUX_AMD64=[0-9a-f]{64}$`,
		`(?m)^BUILDKIT_IMAGE=moby/buildkit:v[0-9.]+@sha256:[0-9a-f]{64}$`,
		`(?m)^SBOM_GENERATOR_IMAGE=docker/buildkit-syft-scanner:[0-9.]+@sha256:[0-9a-f]{64}$`,
	} {
		if !regexp.MustCompile(re).MatchString(env) {
			t.Errorf("versions.env does not match %s", re)
		}
	}
}

// --- docs ----------------------------------------------------------------------------------------

func TestSecurityDocReleaseVerification(t *testing.T) {
	doc := readDoc(t, "docs/security.md")
	for _, want := range []string{
		"## Verifying releases",
		"ghcr.io/astawiany/k8s-mcp",
		"k8s-mcp_${TAG}_linux_amd64.tar.gz",
		"SHA256SUMS.sigstore.json",
		"cosign verify \"ghcr.io/astawiany/k8s-mcp@$DIGEST\"",
		"--certificate-identity \"https://github.com/astawiany/k8s-mcp/.github/workflows/release.yml@refs/tags/$TAG\"",
		"--certificate-oidc-issuer " + issuer,
		"cosign verify-blob --bundle",
		"sha256sum --ignore-missing -c SHA256SUMS",
		"{{json .SBOM}}",
		"{{json .Provenance}}",
		"## Threat model of releases",
		"## Release procedure",
		"## GHCR packages",
		"--jq .visibility",
		"by digest",
		"reproducible",
		"SLSA",
		"point-in-time",
		"k8s-mcp_<tag>_<os>_<arch>.tar.gz",
		"ghcr.io/astawiany/k8s-mcp:<tag>",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/security.md lacks %q", want)
		}
	}
	// Sentences that wrap across lines: compare with whitespace collapsed.
	flat := strings.Join(strings.Fields(doc), " ")
	for _, want := range []string{
		"a re-run can never overwrite an existing tag or release",
		"If a run half-published (a job failed after something was pushed), do not re-run it: bump the version",
		"fail for anonymous consumers until you make the package public",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("docs/security.md lacks %q", want)
		}
	}
	if strings.Contains(doc, "Added in Task 17") || strings.Contains(doc, ":latest") {
		t.Error("docs/security.md still has the stub text or mentions :latest")
	}
	readme := readDoc(t, "README.md")
	for _, want := range []string{"k8s-mcp_<tag>_<os>_<arch>.tar.gz", "SHA256SUMS", ".sigstore.json", "ghcr.io/astawiany/k8s-mcp:<tag>",
		"https://github.com/astawiany/k8s-mcp/releases", ".github/workflows/release.yml"} {
		if !strings.Contains(readme, want) {
			t.Errorf("README.md \"From a release\" lacks %q", want)
		}
	}
}

// TestReleasedDocsAreTimeIndependent: README.md is copied into every release archive and the
// Release notes link docs/security.md at the tag, so neither may say something that is true only
// until the first release ("no release yet", "not run on GitHub"). Dated status lives in
// STATUS.md, which the archives do not carry (TestReleaseBuildBinary lists their exact content).
func TestReleasedDocsAreTimeIndependent(t *testing.T) {
	for _, f := range []string{"README.md", "docs/security.md"} {
		doc := strings.ToLower(readDoc(t, f))
		for _, bad := range []string{"no release has been published", "not run on github", "has not run", "at the time of writing", "not yet", "will carry"} {
			if strings.Contains(doc, bad) {
				t.Errorf("%s says %q, which goes stale once a release exists; put dated status in STATUS.md", f, bad)
			}
		}
	}
	status := readDoc(t, "STATUS.md")
	if !regexp.MustCompile(`(?m)^As of \d{4}-\d{2}-\d{2}:`).MatchString(status) {
		t.Error("STATUS.md has no dated \"As of YYYY-MM-DD:\" line")
	}
}

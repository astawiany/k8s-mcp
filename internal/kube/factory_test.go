package kube

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Secrets planted in the test kubeconfig; none may ever leave the factory.
var kubeconfigSecrets = []string{
	"s3cretpw", "tok-SECRET-123", "prod.invalid", "127.0.0.1", "://",
	"k8s-mcp-test-plugin", "PLUGINENV", "client-key", "LS0t", "private-cert-path",
}

const testKubeconfig = `apiVersion: v1
kind: Config
current-context: dev
clusters:
- name: dev-cluster
  cluster:
    server: https://127.0.0.1:1
    insecure-skip-tls-verify: true
- name: prod-cluster
  cluster:
    server: https://admin:s3cretpw@prod.invalid:6443
users:
- name: token-user
  user:
    token: tok-SECRET-123
- name: exec-user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /nonexistent/k8s-mcp-test-plugin
      interactiveMode: Never
      env:
      - name: PLUGINENV
        value: tok-SECRET-123
- name: cert-user
  user:
    client-certificate-data: LS0tLS1CRUdJTg==
    client-key-data: LS0tLS1CRUdJTg==
contexts:
- name: dev
  context: {cluster: dev-cluster, user: token-user}
- name: prod
  context: {cluster: prod-cluster, user: token-user}
- name: staging
  context: {cluster: dev-cluster, user: exec-user}
- name: kind-a
  context: {cluster: dev-cluster, user: token-user}
`

func writeKubeconfig(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// isolateEnv makes sure no host kubeconfig can be picked up by accident.
func isolateEnv(t *testing.T) {
	t.Helper()
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "does-not-exist"))
	t.Setenv("HOME", t.TempDir())
}

func newTestFactory(t *testing.T, allow string) Factory {
	t.Helper()
	isolateEnv(t)
	f, err := NewFactory(writeKubeconfig(t, testKubeconfig), MustParseAllowlist(allow))
	if err != nil {
		t.Fatalf("NewFactory: %v", err)
	}
	return f
}

func assertNoSecrets(t *testing.T, what, s string) {
	t.Helper()
	for _, sec := range kubeconfigSecrets {
		if strings.Contains(s, sec) {
			t.Errorf("%s leaks %q: %s", what, sec, s)
		}
	}
}

func TestFactoryContexts(t *testing.T) {
	f := newTestFactory(t, "dev,stag*,kind-*")
	got := f.Contexts()
	want := []ContextInfo{
		{Name: "dev", Current: true, Allowed: true},
		{Name: "kind-a", Allowed: true},
		{Name: "prod"},
		{Name: "staging", Allowed: true},
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	// Safety first: no server URL, credential or plugin detail in any form.
	assertNoSecrets(t, "Contexts JSON", string(b))
	assertNoSecrets(t, "Contexts %#v", fmt.Sprintf("%#v", got))
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Contexts() = %+v\nwant %+v", got, want)
	}
	if string(b) != `[{"name":"dev","current":true,"allowed":true},{"name":"kind-a","current":false,"allowed":true},{"name":"prod","current":false,"allowed":false},{"name":"staging","current":false,"allowed":true}]` {
		t.Errorf("JSON = %s", b)
	}
}

func TestFactoryForErrors(t *testing.T) {
	f := newTestFactory(t, "dev,stag*")

	_, err := f.For("nope")
	if !errors.Is(err, ErrUnknownContext) {
		t.Fatalf("For(nope) = %v, want ErrUnknownContext", err)
	}
	if !strings.Contains(err.Error(), `"nope"`) {
		t.Errorf("error should name the context: %v", err)
	}
	assertNoSecrets(t, "unknown-context error", err.Error())

	_, err = f.For("prod")
	if !errors.Is(err, ErrContextNotAllowed) {
		t.Fatalf("For(prod) = %v, want ErrContextNotAllowed", err)
	}
	if errors.Is(err, ErrUnknownContext) {
		t.Error("not-allowed must not also be unknown")
	}
	assertNoSecrets(t, "not-allowed error", err.Error())
}

func TestFactoryForBuildsAndCachesWithoutContactingCluster(t *testing.T) {
	f := newTestFactory(t, "")

	cur, err := f.For("")
	if err != nil {
		t.Fatalf(`For(""): %v`, err)
	}
	dev, err := f.For("dev")
	if err != nil {
		t.Fatalf("For(dev): %v", err)
	}
	if cur != dev {
		t.Error(`For("") must return the cached client of the current context`)
	}
	// The exec plugin does not exist: building the client must not run it.
	st, err := f.For("staging")
	if err != nil {
		t.Fatalf("For(staging): %v", err)
	}
	if st == dev {
		t.Error("distinct contexts must have distinct clients")
	}
	lc, ok := dev.(*liveClient)
	if !ok {
		t.Fatalf("For returned %T", dev)
	}
	if lc.cfg.Timeout != DefaultTimeout || DefaultTimeout != 15*time.Second {
		t.Errorf("rest timeout = %v, want %v (15s)", lc.cfg.Timeout, DefaultTimeout)
	}
	if !strings.HasPrefix(lc.cfg.UserAgent, "k8s-mcp") {
		t.Errorf("UserAgent = %q", lc.cfg.UserAgent)
	}
}

func TestFactoryWithTimeout(t *testing.T) {
	isolateEnv(t)
	f, err := NewFactory(writeKubeconfig(t, testKubeconfig), Allowlist{}, WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.For("dev")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.(*liveClient).cfg.Timeout; got != 3*time.Second {
		t.Errorf("timeout = %v", got)
	}
}

func TestFactoryConcurrentForReturnsOneClient(t *testing.T) {
	f := newTestFactory(t, "")
	var wg sync.WaitGroup
	got := make([]Client, 32)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := f.For("kind-a")
			if err != nil {
				t.Error(err)
			}
			got[i] = c
		}()
	}
	wg.Wait()
	for _, c := range got[1:] {
		if c != got[0] {
			t.Fatal("concurrent For returned different clients")
		}
	}
}

func TestFactoryCurrentContextNotAllowed(t *testing.T) {
	f := newTestFactory(t, "prod")
	if _, err := f.For(""); !errors.Is(err, ErrContextNotAllowed) {
		t.Fatalf(`For("") = %v, want ErrContextNotAllowed`, err)
	}
}

func TestFactoryNoCurrentContext(t *testing.T) {
	isolateEnv(t)
	cfg := strings.Replace(testKubeconfig, "current-context: dev\n", "", 1)
	f, err := NewFactory(writeKubeconfig(t, cfg), Allowlist{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Contexts() {
		if c.Current {
			t.Errorf("%s marked current", c.Name)
		}
	}
	if _, err := f.For(""); !errors.Is(err, ErrUnknownContext) {
		t.Fatalf(`For("") = %v, want ErrUnknownContext`, err)
	}
}

func TestFactoryHonoursKUBECONFIGWhenPathEmpty(t *testing.T) {
	isolateEnv(t)
	t.Setenv("KUBECONFIG", writeKubeconfig(t, testKubeconfig))
	f, err := NewFactory("", Allowlist{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(f.Contexts()); n != 4 {
		t.Fatalf("got %d contexts from $KUBECONFIG, want 4", n)
	}
}

func TestFactoryExplicitPathWinsOverKUBECONFIG(t *testing.T) {
	isolateEnv(t)
	other := strings.ReplaceAll(testKubeconfig, "kind-a", "other-ctx")
	t.Setenv("KUBECONFIG", writeKubeconfig(t, other))
	f, err := NewFactory(writeKubeconfig(t, testKubeconfig), Allowlist{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Contexts() {
		if c.Name == "other-ctx" {
			t.Fatal("explicit path must override $KUBECONFIG")
		}
	}
}

func TestNewFactoryErrors(t *testing.T) {
	isolateEnv(t)
	_, err := NewFactory(filepath.Join(t.TempDir(), "missing"), Allowlist{})
	if err == nil {
		t.Error("missing explicit kubeconfig: want error")
	}
	_, err = NewFactory(writeKubeconfig(t, "apiVersion: v1\nkind: Config\n"), Allowlist{})
	if err == nil {
		t.Error("kubeconfig without contexts: want error")
	}
	_, err = NewFactory(writeKubeconfig(t, "{{{ not yaml"), Allowlist{})
	if err == nil {
		t.Error("garbage kubeconfig: want error")
	}
}

func TestFactoryBrokenContextErrorHasNoSecrets(t *testing.T) {
	isolateEnv(t)
	cfg := strings.Replace(testKubeconfig, "contexts:\n", `- name: file-user
  user:
    client-certificate: /nonexistent/private-cert-path/c.crt
    client-key: /nonexistent/private-cert-path/c.key
contexts:
`, 1) + `- name: broken
  context: {cluster: missing-cluster, user: token-user}
- name: broken-cert
  context: {cluster: prod-cluster, user: file-user}
`
	f, err := NewFactory(writeKubeconfig(t, cfg), Allowlist{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"broken", "broken-cert"} {
		_, err = f.For(name)
		if err == nil {
			t.Errorf("%s: want error", name)
			continue
		}
		if !strings.Contains(err.Error(), `"`+name+`"`) {
			t.Errorf("%s: error should name the context: %v", name, err)
		}
		assertNoSecrets(t, name+" error", err.Error())
	}
}

package kube

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// Connection details that must never reach a tool result through an error.
var transportSecrets = []string{
	"secret-host", "prefix-s3cret", "127.0.0.1", "private-dir", "getcreds",
	"tok-SECRET", "://", "invalid:1", "/api/v1",
}

const leakKubeconfig = `apiVersion: v1
kind: Config
current-context: refused
clusters:
- name: dns
  cluster: {server: "https://secret-host.invalid:1/prefix-s3cret"}
- name: local
  cluster: {server: "https://127.0.0.1:1/prefix-s3cret"}
users:
- name: tok
  user: {token: tok-SECRET-123}
- name: execu
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /opt/private-dir/getcreds
      interactiveMode: Never
contexts:
- name: dns
  context: {cluster: dns, user: tok}
- name: refused
  context: {cluster: local, user: tok}
- name: execfail
  context: {cluster: local, user: execu}
`

// allCalls invokes every Client method and returns the errors by name.
func allCalls(c Client) map[string]error {
	pods := Resource{Version: "v1", Resource: "pods", Kind: "Pod", Namespaced: true}
	errs := map[string]error{}
	_, errs["ServerVersion"] = c.ServerVersion(bg)
	_, errs["APIGroups"] = c.APIGroups(bg)
	_, errs["Resolve"] = c.Resolve(bg, "pods", "", "")
	_, errs["List"] = c.List(bg, pods, "default", ListOptions{})
	_, errs["Get"] = c.Get(bg, pods, "default", "p")
	_, errs["Events"] = c.Events(bg, "default", &ObjectRef{Kind: "Pod", Name: "p"}, time.Hour)
	_, errs["PodLogs"] = c.PodLogs(bg, "default", "p", LogOptions{})
	_, errs["NodeMetrics"] = c.NodeMetrics(bg)
	_, errs["PodMetrics"] = c.PodMetrics(bg, "default")
	return errs
}

func assertNoTransportLeak(t *testing.T, what string, err error) {
	t.Helper()
	for _, form := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		for _, s := range transportSecrets {
			if strings.Contains(form, s) {
				t.Errorf("%s leaks %q: %s", what, s, form)
			}
		}
	}
}

func TestTransportErrorsDoNotLeakConnectionDetails(t *testing.T) {
	isolateEnv(t)
	f, err := NewFactory(writeKubeconfig(t, leakKubeconfig), Allowlist{}, WithTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ctx  string
		want []error // any of these classes
	}{
		{"refused", []error{ErrUnreachable}},
		{"dns", []error{ErrUnreachable, ErrTimeout}},
		{"execfail", []error{ErrCredentialPlugin}},
	}
	for _, cs := range cases {
		c, err := f.For(cs.ctx)
		if err != nil {
			t.Fatal(err)
		}
		for method, err := range allCalls(c) {
			what := cs.ctx + "/" + method
			if err == nil {
				t.Errorf("%s: want error", what)
				continue
			}
			assertNoTransportLeak(t, what, err)
			ok := false
			for _, w := range cs.want {
				ok = ok || errors.Is(err, w)
			}
			if !ok {
				t.Errorf("%s: %v is not one of %v", what, err, cs.want)
			}
		}
	}
}

func writeScript(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	p := filepath.Join(t.TempDir(), "plugin.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHangingExecPluginIsAbandonedAtTimeout(t *testing.T) {
	isolateEnv(t)
	plugin := writeScript(t, "sleep 5\n")
	cfg := `apiVersion: v1
kind: Config
current-context: hang
clusters:
- name: local
  cluster: {server: "https://127.0.0.1:1"}
users:
- name: hang
  user:
    exec: {apiVersion: client.authentication.k8s.io/v1, command: "` + plugin + `", interactiveMode: Never}
contexts:
- name: hang
  context: {cluster: local, user: hang}
`
	f, err := NewFactory(writeKubeconfig(t, cfg), Allowlist{}, WithTimeout(500*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.For("")
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range []func() error{
		func() error { _, err := c.ServerVersion(bg); return err },
		func() error {
			_, err := c.List(bg, Resource{Version: "v1", Resource: "pods", Kind: "Pod", Namespaced: true}, "", ListOptions{})
			return err
		},
	} {
		start := time.Now()
		err := call()
		took := time.Since(start)
		if !errors.Is(err, ErrTimeout) {
			t.Errorf("hanging plugin: err = %v, want ErrTimeout", err)
		}
		if took > 3*time.Second {
			t.Errorf("hanging plugin: call took %v, want about the 0.5s timeout", took)
		}
		if err != nil && strings.Contains(err.Error(), plugin) {
			t.Errorf("error leaks plugin path: %v", err)
		}
	}
}

func TestExecPluginNeverInteractive(t *testing.T) {
	isolateEnv(t)
	// TLS: clientcmd only applies user credentials to https servers.
	s := &apiStub{queries: map[string]url.Values{}}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	info := filepath.Join(t.TempDir(), "exec-info")
	plugin := writeScript(t, `printf '%s' "$KUBERNETES_EXEC_INFO" > "$INFO_OUT"
echo '{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"t"}}'
`)
	cfg := `apiVersion: v1
kind: Config
current-context: ia
clusters:
- name: stub
  cluster: {server: "` + s.srv.URL + `", insecure-skip-tls-verify: true}
users:
- name: ia
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: "` + plugin + `"
      interactiveMode: Always
      env: [{name: INFO_OUT, value: "` + info + `"}]
contexts:
- name: ia
  context: {cluster: stub, user: ia}
`
	f, err := NewFactory(writeKubeconfig(t, cfg), Allowlist{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.For("")
	if err != nil {
		t.Fatal(err)
	}
	ep := c.(*liveClient).cfg.ExecProvider
	if ep == nil || ep.InteractiveMode != clientcmdapi.NeverExecInteractiveMode || !ep.StdinUnavailable {
		t.Fatalf("exec provider not forced non-interactive: %+v", ep)
	}
	if v, err := c.ServerVersion(bg); err != nil || v != "v1.31.2" {
		t.Fatalf("ServerVersion via exec plugin = %q, %v", v, err)
	}
	b, err := os.ReadFile(info)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"interactive":false`) {
		t.Errorf("plugin was told interactive; exec info = %s", b)
	}
}

package flux_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/astawiany/k8s-mcp/internal/flux"
)

func TestSummarizeReadyAndRevision(t *testing.T) {
	obj := map[string]any{
		"kind":     "Kustomization",
		"metadata": map[string]any{"name": "apps", "namespace": "flux-system"},
		"spec":     map[string]any{"suspend": true, "dependsOn": []any{map[string]any{"name": "infra"}, map[string]any{"name": "crds", "namespace": "other"}, "junk", map[string]any{}}},
		"status": map[string]any{
			"lastAppliedRevision":   "main@sha1:aaa",
			"lastAttemptedRevision": "main@sha1:bbb",
			"artifact":              map[string]any{"revision": "main@sha1:ccc"},
			"conditions": []any{
				"junk",
				map[string]any{"type": "Stalled", "status": "True"},
				map[string]any{"type": "Ready", "status": "False", "reason": "BuildFailed", "message": "boom"},
			},
		},
	}
	got := flux.Summarize(obj)
	want := flux.Status{Kind: "Kustomization", Namespace: "flux-system", Name: "apps", Reason: "BuildFailed", Message: "boom",
		Revision: "main@sha1:aaa", Suspended: true, Stalled: true, DependsOn: []string{"infra", "other/crds"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestSummarizeRevisionPrecedence(t *testing.T) {
	art := map[string]any{"status": map[string]any{"artifact": map[string]any{"revision": "r1"}, "lastAttemptedRevision": "r2"}}
	if r := flux.Summarize(art).Revision; r != "r1" {
		t.Errorf("artifact should beat attempted, got %q", r)
	}
	att := map[string]any{"status": map[string]any{"lastAttemptedRevision": "r2"}}
	if r := flux.Summarize(att).Revision; r != "r2" {
		t.Errorf("got %q", r)
	}
}

func TestSummarizeReadyTrue(t *testing.T) {
	s := flux.Summarize(map[string]any{"status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}})
	if !s.Ready || s.Stalled || s.Suspended {
		t.Fatalf("%+v", s)
	}
}

func TestSummarizeOddShapesDoNotPanic(t *testing.T) {
	for _, obj := range []map[string]any{
		nil, {}, {"status": "x", "spec": 3, "metadata": []any{}},
		{"status": map[string]any{"conditions": "x", "artifact": 1}, "spec": map[string]any{"dependsOn": "x", "suspend": "yes"}},
		{"status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": 1, "reason": 2, "message": 3}}}},
	} {
		s := flux.Summarize(obj)
		if s.Ready || s.Suspended {
			t.Errorf("%v -> %+v", obj, s)
		}
	}
}

func TestScrubURLs(t *testing.T) {
	cases := map[string]string{
		"https://user:pass@host/x.git":                    "https://[redacted]@host/x.git",
		"auth failed for https://oauth2:abc@github.com/a": "auth failed for https://[redacted]@github.com/a",
		"ssh://git@host:22/r and https://u:p@h2":          "ssh://[redacted]@host:22/r and https://[redacted]@h2",
		"https://host/path@v1 no creds":                   "https://host/path@v1 no creds",
		"plain text":                                      "plain text",
		"https://u:p@ss@host/x":                           "https://[redacted]@host/x",
		"https://u:p@ss@host":                             "https://[redacted]@host",
	}
	for in, want := range cases {
		if got := flux.ScrubURLs(in); got != want {
			t.Errorf("ScrubURLs(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSummarizeScrubsMessage(t *testing.T) {
	msg := "failed to checkout: authentication required for https://x-access-token:s3cr3t@github.com/org/repo.git"
	s := flux.Summarize(map[string]any{"status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "False", "message": msg}}}})
	if strings.Contains(s.Message, "s3cr3t") || !strings.Contains(s.Message, "https://[redacted]@github.com") {
		t.Fatalf("message %q", s.Message)
	}
	tok := "clone failed: ghp_" + strings.Repeat("a", 36)
	s = flux.Summarize(map[string]any{"status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "False", "message": tok}}}})
	if strings.Contains(s.Message, "ghp_") {
		t.Fatalf("token shape kept: %q", s.Message)
	}
}

func TestScrubQueryCredentials(t *testing.T) {
	r := "[redacted]"
	cases := map[string]string{
		"fetch https://h/x?token=abc123def&a=1":       "fetch https://h/x?token=" + r + "&a=1",
		"https://h/x?access_token=abc123":             "https://h/x?access_token=" + r,
		"https://h/x?a=1&password=p&sig=s&ref=main":   "https://h/x?a=1&password=" + r + "&sig=" + r + "&ref=main",
		"https://h/x?%74oken=abc&b=2":                 "https://h/x?%74oken=" + r + "&b=2",
		"https://h/x?API_KEY=zzz":                     "https://h/x?API_KEY=" + r,
		"https://h/x#access_token=abc&state=ok":       "https://h/x#access_token=" + r + "&state=ok",
		"get 'https://h/x?client_secret=abc' failed":  "get 'https://h/x?client_secret=" + r + "' failed",
		"get \"https://h/x?code=abc\" failed":         "get \"https://h/x?code=" + r + "\" failed",
		"https://h/x?apikey=abc more text":            "https://h/x?apikey=" + r + " more text",
		"https://h/x?foo=bar&ref=main&keyword=go&a=b": "https://h/x?foo=bar&ref=main&keyword=go&a=b",
		"https://h/x?authorization=Bearer&token=":     "https://h/x?authorization=" + r + "&token=",
		"no url, ref=main token=notinquery":           "no url, ref=main token=notinquery",
	}
	for in, want := range cases {
		if got := flux.ScrubURLs(in); got != want {
			t.Errorf("ScrubURLs(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

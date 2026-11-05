package issue_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/astawiany/k8s-mcp/internal/issue"
	"github.com/astawiany/k8s-mcp/internal/redact"
)

// wrapperBlanks is what the result wrapper replaces whole (see
// server.sanitizeString): a Secret-manifest look-alike or a token shape.
func wrapperBlanks(s string) bool {
	return redact.LooksLikeSecretManifest(s) || redact.EnvValue("", s) == redact.Redacted
}

// TestDraftNeverReturnsTextTheWrapperBlanks spreads the words of the manifest
// check over every pair of fields: no output string may trip the check, and
// whenever a field was withheld a warning says so.
func TestDraftNeverReturnsTextTheWrapperBlanks(t *testing.T) {
	fields := []string{"title", "cluster", "namespace", "object", "summary", "ref", "quote", "next"}
	words := []string{"kind", "secret", "data:", `"data"`, "stringData"}
	for _, dataWord := range words[2:] {
		for _, a := range fields {
			for _, b := range fields {
				for _, c := range fields {
					in := issue.In{Title: "t", Severity: "low", Cluster: "c1", Summary: "s",
						Evidence: []issue.Evidence{{Ref: "r", Quote: "q"}}, SuggestedNext: []string{"n"}}
					put := func(field, w string) {
						switch field {
						case "title":
							in.Title += " " + w
						case "cluster":
							in.Cluster += "-" + w
						case "namespace":
							in.Namespace += w
						case "object":
							in.Object += " " + w
						case "summary":
							in.Summary += " " + w
						case "ref":
							in.Evidence[0].Ref += " " + w
						case "quote":
							in.Evidence[0].Quote += " " + w
						case "next":
							in.SuggestedNext[0] += " " + w
						}
					}
					put(a, "kind")
					put(b, "secret")
					put(c, dataWord)
					name := fmt.Sprintf("%s/%s/%s/%s", a, b, c, dataWord)
					out, err := issue.Draft(in)
					if err != nil {
						t.Fatalf("%s: %v", name, err)
					}
					for _, s := range append([]string{out.Summary, out.Description}, append(out.Labels, out.Warnings...)...) {
						if wrapperBlanks(s) {
							t.Fatalf("%s: output string trips the wrapper: %q", name, s)
						}
					}
					if strings.Contains(out.Description+out.Summary, issue.WithheldNote) && len(out.Warnings) == 0 {
						t.Fatalf("%s: field withheld without a warning", name)
					}
				}
			}
		}
	}
}

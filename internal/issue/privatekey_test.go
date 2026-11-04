package issue_test

import (
	"strings"
	"testing"

	"github.com/astawiany/k8s-mcp/internal/issue"
)

// Every free-text field of a draft masks the whole private key block, in
// the forms redact.MaskPrivateKeyBlocks covers (its own table test is the
// full list).
func TestDraftMasksWholePrivateKeyBlocks(t *testing.T) {
	keys := map[string]string{
		"rsa":         "-----BEGIN RSA PRIVATE KEY-----\nSECRETBODY\n-----END RSA PRIVATE KEY-----",
		"pgp":         "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBFSECRETBODY\n=abcd\n-----END PGP PRIVATE KEY BLOCK-----",
		"four dashes": "----BEGIN RSA PRIVATE KEY----\nSECRETBODY\n----END RSA PRIVATE KEY----",
		"tab":         "-----BEGIN\tEC  PRIVATE KEY-----\nSECRETBODY\n-----END\tEC  PRIVATE KEY-----",
		"no END":      "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETBODY\nSECRETBODY",
	}
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			v := "before " + key + " after"
			out, err := issue.Draft(issue.In{
				Title: "t", Severity: "high", Cluster: "c", Object: v, Summary: v,
				Evidence:      []issue.Evidence{{Ref: "r", Quote: v}},
				SuggestedNext: []string{v},
			})
			if err != nil {
				t.Fatal(err)
			}
			all := out.Summary + "\n" + out.Description
			if strings.Contains(all, "SECRETBODY") || strings.Contains(strings.ToUpper(all), "PRIVATE KEY") {
				t.Errorf("key material kept:\n%s", all)
			}
			if !strings.Contains(all, "before") {
				t.Errorf("text before the key was lost:\n%s", all)
			}
		})
	}
}

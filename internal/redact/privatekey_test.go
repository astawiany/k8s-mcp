package redact

import (
	"strings"
	"testing"
)

// privateKeyCases is shared with EnvValue's test below. body is a secret
// line that must disappear; keep lists text that must survive.
var privateKeyCases = []struct {
	name, in string
	masked   bool
	keep     []string
}{
	{"rsa", "a\n-----BEGIN RSA PRIVATE KEY-----\nSECRETBODY\n-----END RSA PRIVATE KEY-----\nb", true, []string{"a\n", "\nb"}},
	{"pkcs8", "-----BEGIN PRIVATE KEY-----\nSECRETBODY\n-----END PRIVATE KEY-----", true, nil},
	{"ec", "-----BEGIN EC PRIVATE KEY-----\nSECRETBODY\n-----END EC PRIVATE KEY-----", true, nil},
	{"dsa", "-----BEGIN DSA PRIVATE KEY-----\nSECRETBODY\n-----END DSA PRIVATE KEY-----", true, nil},
	{"openssh", "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETBODY\n-----END OPENSSH PRIVATE KEY-----", true, nil},
	{"encrypted", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nSECRETBODY\n-----END ENCRYPTED PRIVATE KEY-----", true, nil},
	{"pgp block", "x\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBFSECRETBODY\n=abcd\n-----END PGP PRIVATE KEY BLOCK-----\ny", true, []string{"x\n", "\ny"}},
	{"four dashes", "----BEGIN RSA PRIVATE KEY----\nSECRETBODY\n----END RSA PRIVATE KEY----", true, nil},
	{"mixed dashes", "-----BEGIN RSA PRIVATE KEY----\nSECRETBODY\n----END RSA PRIVATE KEY-----", true, nil},
	{"tab after BEGIN", "-----BEGIN\tRSA PRIVATE KEY-----\nSECRETBODY\n-----END\tRSA PRIVATE KEY-----", true, nil},
	{"multiple spaces", "-----BEGIN  EC   PRIVATE  KEY-----\nSECRETBODY\n-----END  EC   PRIVATE  KEY-----", true, nil},
	{"lowercase", "-----begin rsa private key-----\nSECRETBODY\n-----end rsa private key-----", true, nil},
	{"crlf", "a\r\n-----BEGIN RSA PRIVATE KEY-----\r\nSECRETBODY\r\n-----END RSA PRIVATE KEY-----\r\nb", true, []string{"a\r\n", "\r\nb"}},
	{"log prefixed", "2026-11-04T10:00:00Z app -----BEGIN RSA PRIVATE KEY-----\n2026-11-04T10:00:00Z app SECRETBODY\n" +
		"2026-11-04T10:00:00Z app -----END RSA PRIVATE KEY-----\n2026-11-04T10:00:01Z app ready",
		true, []string{"2026-11-04T10:00:00Z app ", "\n2026-11-04T10:00:01Z app ready"}},
	{"missing END", "a\n-----BEGIN RSA PRIVATE KEY-----\nSECRETBODY\nSECRETBODY too", true, []string{"a\n"}},
	{"two blocks", "-----BEGIN EC PRIVATE KEY-----\nSECRETBODY\n-----END EC PRIVATE KEY-----\nbetween\n" +
		"-----BEGIN PRIVATE KEY-----\nSECRETBODY\n-----END PRIVATE KEY-----\nafter", true, []string{"\nbetween\n", "\nafter"}},
	{"text after END on the line", "-----BEGIN RSA PRIVATE KEY-----\nSECRETBODY\n-----END RSA PRIVATE KEY----- trailing", true, []string{" trailing"}},
	{"json escaped single line", `{"key":"-----BEGIN RSA PRIVATE KEY-----\nSECRETBODY\n-----END RSA PRIVATE KEY-----\n","x":1}`,
		true, []string{`{"key":"`, `\n","x":1}`}},
	{"certificate kept", "-----BEGIN CERTIFICATE-----\nMIIBCERT\n-----END CERTIFICATE-----", false, nil},
	{"public key kept", "-----BEGIN PUBLIC KEY-----\nMIIBPUB\n-----END PUBLIC KEY-----", false, nil},
	{"rsa public key kept", "-----BEGIN RSA PUBLIC KEY-----\nMIIBPUB\n-----END RSA PUBLIC KEY-----", false, nil},
	{"plain text kept", "the private key is rotated nightly", false, nil},
}

func TestMaskPrivateKeyBlocks(t *testing.T) {
	for _, tc := range privateKeyCases {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := MaskPrivateKeyBlocks(tc.in)
			if changed != tc.masked {
				t.Fatalf("changed = %v, want %v: %q", changed, tc.masked, got)
			}
			if !tc.masked {
				if got != tc.in {
					t.Errorf("unmasked text changed: %q", got)
				}
				return
			}
			if strings.Contains(got, "SECRETBODY") || !strings.Contains(got, Redacted) {
				t.Errorf("key body kept or no marker: %q", got)
			}
			if strings.Contains(strings.ToUpper(got), "PRIVATE") {
				t.Errorf("a key marker survived: %q", got)
			}
			for _, k := range tc.keep {
				if !strings.Contains(got, k) {
					t.Errorf("text %q outside the block was lost: %q", k, got)
				}
			}
		})
	}
}

// EnvValue (the token-shape check the result wrapper uses) must treat every
// private key form as a token, and not certificates or public keys.
func TestEnvValuePrivateKeyForms(t *testing.T) {
	for _, tc := range privateKeyCases {
		got := EnvValue("", tc.in)
		if tc.masked && got != Redacted {
			t.Errorf("%s: EnvValue kept %q", tc.name, got)
		}
		if !tc.masked && got != tc.in {
			t.Errorf("%s: EnvValue changed %q to %q", tc.name, tc.in, got)
		}
	}
	// The END marker alone (a window cut inside a block) is a token too.
	if got := EnvValue("", "SECRETBODY\n-----END PGP PRIVATE KEY BLOCK-----"); got != Redacted {
		t.Errorf("END marker alone kept: %q", got)
	}
}

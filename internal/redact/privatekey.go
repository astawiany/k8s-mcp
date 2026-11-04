package redact

import (
	"fmt"
	"regexp"
)

// keyMarker is a BEGIN or END marker of a private key block: 4 or 5 dashes,
// the word, spaces or tabs, any type words (RSA, EC, DSA, OPENSSH,
// ENCRYPTED, PGP, none), PRIVATE KEY, an optional BLOCK (PGP), and 4 or 5
// dashes; any case. CERTIFICATE and PUBLIC KEY markers do not match.
const keyMarker = `-{4,5}[ \t]*%s[ \t]+(?:[A-Z0-9]+[ \t]+)*PRIVATE[ \t]+KEY(?:[ \t]+BLOCK)?[ \t]*-{4,5}`

var (
	// PrivateKeyBeginRE matches the BEGIN marker of a private key block.
	PrivateKeyBeginRE = regexp.MustCompile(`(?i)` + fmt.Sprintf(keyMarker, "BEGIN"))
	// PrivateKeyEndRE matches the END marker of a private key block.
	PrivateKeyEndRE = regexp.MustCompile(`(?i)` + fmt.Sprintf(keyMarker, "END"))
	// PrivateKeyBlockRE matches a whole block: from a BEGIN marker through
	// the next END marker, or to the end of the text when there is none
	// (fail closed). It spans lines (LF, CRLF) and JSON-escaped "\n" forms.
	PrivateKeyBlockRE = regexp.MustCompile(`(?is)` + fmt.Sprintf(keyMarker, "BEGIN") + `.*?(?:` +
		fmt.Sprintf(keyMarker, "END") + `|\z)`)
)

// MaskPrivateKeyBlocks replaces every private key block of s (see
// PrivateKeyBlockRE) with Redacted; text before, between and after blocks is
// kept. changed reports whether anything was replaced. A body without its
// BEGIN marker is not detected here; EnvValue still treats a lone END marker
// as a token.
func MaskPrivateKeyBlocks(s string) (out string, changed bool) {
	out = PrivateKeyBlockRE.ReplaceAllLiteralString(s, Redacted)
	return out, out != s
}

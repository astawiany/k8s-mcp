package injection_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// markerRe and parseEnvelope are copied from internal/untrusted's tests (the
// strict envelope reader): any "<<<" (or its fullwidth/small-form
// look-alikes) followed by optional whitespace and DATA or END in any case
// counts as a marker.
var markerRe = regexp.MustCompile(`(?i)[<\x{FF1C}\x{FE64}]{3}\s*(data|end)`)

var dataLineRe = regexp.MustCompile(`^<<<DATA ([0-9a-f]{32})>>>$`)

// parseEnvelope fails unless s is exactly one DATA line, a body, and one END
// line with the same boundary, with no other marker-like text anywhere and
// no copy of the boundary in the body.
func parseEnvelope(s string) (boundary, body string, err error) {
	lines := strings.Split(s, "\n")
	if len(lines) < 3 {
		return "", "", errors.New("envelope needs a DATA line, a body and an END line")
	}
	m := dataLineRe.FindStringSubmatch(lines[0])
	if m == nil {
		return "", "", fmt.Errorf("first line is not a DATA line: %q", lines[0])
	}
	boundary = m[1]
	if want := "<<<END " + boundary + ">>>"; lines[len(lines)-1] != want {
		return "", "", fmt.Errorf("last line %q, want %q", lines[len(lines)-1], want)
	}
	if n := len(markerRe.FindAllStringIndex(s, -1)); n != 2 {
		return "", "", fmt.Errorf("found %d marker-like sequences, want exactly 2", n)
	}
	body = strings.Join(lines[1:len(lines)-1], "\n")
	if strings.Contains(strings.ToLower(body), boundary) {
		return "", "", errors.New("body contains the boundary")
	}
	return boundary, body, nil
}

// disallowed is the rune set Sanitize must remove (copied from
// internal/untrusted's tests): control characters other than newline and
// tab, format characters (zero-width, bidi, tags), Hangul fillers, the
// variation selectors supplement and the line/paragraph separators.
func disallowed(r rune) bool {
	if r == '\n' || r == '\t' {
		return false
	}
	return r < 0x20 || (r >= 0x7f && r <= 0x9f) || unicode.Is(unicode.Cf, r) ||
		r == 0x3164 || r == 0x115f || r == 0x1160 || (r >= 0xe0100 && r <= 0xe01ef) ||
		r == 0x2028 || r == 0x2029
}

// firstDisallowed returns the first disallowed rune of s and its index, or -1.
func firstDisallowed(s string) (rune, int) {
	for i, r := range s {
		if disallowed(r) {
			return r, i
		}
	}
	return 0, -1
}

// jsonStrings decodes a JSON document and returns every key and string value.
func jsonStrings(doc string) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader([]byte(doc)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for k, e := range t {
				out = append(out, k)
				walk(e)
			}
		}
	}
	walk(v)
	return out, nil
}

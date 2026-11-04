// Package limits caps the size of text and lists returned to MCP clients and
// produces the standard truncation marker.
//
// Default limits (see Default):
//
//	MaxBytes   65536 (64 KiB) total bytes of text, marker included
//	MaxLines   500            lines of text
//	MaxItems   200            items in a list result
//	MaxLineLen 2000           bytes in a single line
//
// A limit value <= 0 disables that limit. The package has no dependencies
// beyond the standard library.
package limits

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// lineCut is appended to a line that was cut at MaxLineLen.
const lineCut = "…[line truncated]"

// Limits holds the output caps.
type Limits struct {
	MaxBytes   int
	MaxLines   int
	MaxItems   int
	MaxLineLen int
}

// Default returns the standard limits.
func Default() Limits {
	return Limits{MaxBytes: 64 * 1024, MaxLines: 500, MaxItems: 200, MaxLineLen: 2000}
}

// Note returns the standard truncation marker.
func Note(reason, hint string) string {
	return fmt.Sprintf("[truncated: %s; narrow with %s]", reason, hint)
}

// cutRunes returns the longest prefix of s that is at most n bytes and does
// not split a multi-byte rune.
func cutRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// TruncateText applies the line-length, line-count and byte limits to s. The
// result, including any marker, is at most l.MaxBytes bytes and always valid
// at rune boundaries. truncated reports whether anything was cut.
func TruncateText(s string, l Limits) (out string, truncated bool) {
	if s == "" {
		return "", false
	}
	var (
		b         strings.Builder
		rest      = s
		lineCount int
		cutLines  bool
		overLines bool
		overBytes bool
	)
	for len(rest) > 0 {
		if l.MaxLines > 0 && lineCount >= l.MaxLines {
			overLines = true
			break
		}
		line, nl := rest, ""
		if i := strings.IndexByte(rest, '\n'); i >= 0 {
			line, nl = rest[:i], "\n"
			rest = rest[i+1:]
		} else {
			rest = ""
		}
		if l.MaxLineLen > 0 && len(line) > l.MaxLineLen {
			line = cutRunes(line, l.MaxLineLen) + lineCut
			cutLines = true
		}
		b.WriteString(line)
		b.WriteString(nl)
		lineCount++
		if l.MaxBytes > 0 && b.Len() > l.MaxBytes {
			overBytes = true
			break
		}
	}
	if !overLines && !overBytes && !cutLines {
		return s, false
	}

	var reasons []string
	if overBytes {
		reasons = append(reasons, fmt.Sprintf("output exceeds %d bytes", l.MaxBytes))
	}
	if overLines {
		reasons = append(reasons, fmt.Sprintf("output exceeds %d lines", l.MaxLines))
	}
	if cutLines {
		reasons = append(reasons, fmt.Sprintf("lines cut at %d bytes", l.MaxLineLen))
	}
	marker := Note(strings.Join(reasons, ", "), "a narrower selector, time range or tail count")

	body := b.String()
	if l.MaxBytes > 0 {
		body = cutRunes(body, l.MaxBytes-len(marker)-1)
	}
	if body != "" && !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	return body + marker, true
}

// TruncateTail keeps the last n lines. truncated is true when lines were
// dropped. n <= 0 keeps nothing.
func TruncateTail(lines []string, n int) ([]string, bool) {
	if n < 0 {
		n = 0
	}
	if len(lines) <= n {
		return lines, false
	}
	return lines[len(lines)-n:], true
}

package issue

import (
	"strings"
	"testing"
)

// TestMaskingThatIsNotAFixedPointFailsClosed: when masking still changes the
// text after the last pass, the field is replaced by a fixed placeholder and
// a warning, never returned half-masked.
func TestMaskingThatIsNotAFixedPointFailsClosed(t *testing.T) {
	orig := maskText
	t.Cleanup(func() { maskText = orig })
	// A masker that never settles: every pass changes the text.
	maskText = func(s string) string { return s + "x" }

	c := &cleaner{}
	got := c.clean("summary", "some text", false)
	if got != MaskUnstable {
		t.Errorf("clean = %q, want the fixed placeholder %q", got, MaskUnstable)
	}
	if w := strings.Join(c.warnings, "|"); !strings.Contains(w, "summary: masking did not settle") {
		t.Errorf("warnings = %v", c.warnings)
	}
}

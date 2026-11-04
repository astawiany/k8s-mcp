package limits

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestDefaultValues(t *testing.T) {
	d := Default()
	want := Limits{MaxBytes: 64 * 1024, MaxLines: 500, MaxItems: 200, MaxLineLen: 2000}
	if d != want {
		t.Fatalf("Default() = %+v, want %+v", d, want)
	}
}

func TestNote(t *testing.T) {
	got := Note("500 lines", "tailLines")
	want := "[truncated: 500 lines; narrow with tailLines]"
	if got != want {
		t.Fatalf("Note = %q, want %q", got, want)
	}
}

func TestTruncateTextEmpty(t *testing.T) {
	out, tr := TruncateText("", Default())
	if out != "" || tr {
		t.Fatalf("got %q, %v", out, tr)
	}
}

func TestTruncateTextExactlyAtLimit(t *testing.T) {
	l := Limits{MaxBytes: 10, MaxLines: 3, MaxLineLen: 10}
	for _, s := range []string{"0123456789", "a\nb\nc", "a\nb\nc\n"} {
		out, tr := TruncateText(s, l)
		if out != s || tr {
			t.Fatalf("input %q: got %q, %v; want untouched", s, out, tr)
		}
	}
}

func TestTruncateTextOneByteOverBytes(t *testing.T) {
	l := Limits{MaxBytes: 100, MaxLines: 1000, MaxLineLen: 1000}
	s := strings.Repeat("a", 101)
	out, tr := TruncateText(s, l)
	if !tr {
		t.Fatal("want truncated")
	}
	if !strings.Contains(out, "[truncated:") {
		t.Fatalf("missing marker: %q", out)
	}
	if len(out) > l.MaxBytes {
		t.Fatalf("len %d > %d", len(out), l.MaxBytes)
	}
}

func TestTruncateTextOneLineOver(t *testing.T) {
	l := Limits{MaxBytes: 1000, MaxLines: 3, MaxLineLen: 100}
	out, tr := TruncateText("a\nb\nc\nd", l)
	if !tr || !strings.Contains(out, "[truncated:") {
		t.Fatalf("got %q, %v", out, tr)
	}
	if body := strings.SplitN(out, "[truncated", 2)[0]; strings.Contains(body, "d") {
		t.Fatalf("line 4 kept: %q", body)
	}
}

func TestTruncateTextRuneBoundary(t *testing.T) {
	l := Limits{MaxBytes: 120, MaxLines: 1000, MaxLineLen: 1000}
	for pad := 0; pad < 4; pad++ {
		s := strings.Repeat("a", pad) + strings.Repeat("日", 200)
		out, tr := TruncateText(s, l)
		if !tr || !utf8.ValidString(out) || len(out) > l.MaxBytes {
			t.Fatalf("pad %d: truncated=%v valid=%v len=%d", pad, tr, utf8.ValidString(out), len(out))
		}
	}
}

func TestTruncateTextHugeInput(t *testing.T) {
	l := Default()
	s := strings.Repeat("x", 50<<20)
	out, tr := TruncateText(s, l)
	if !tr || len(out) > l.MaxBytes {
		t.Fatalf("truncated=%v len=%d", tr, len(out))
	}
	lines := strings.Repeat("some log line\n", 4<<20)
	out, tr = TruncateText(lines, l)
	if !tr || len(out) > l.MaxBytes {
		t.Fatalf("truncated=%v len=%d", tr, len(out))
	}
}

func TestTruncateTextLongLine(t *testing.T) {
	l := Default()
	s := strings.Repeat("y", 1<<20) + "\nshort\n"
	out, tr := TruncateText(s, l)
	if !tr {
		t.Fatal("want truncated")
	}
	first := strings.SplitN(out, "\n", 2)[0]
	if !strings.HasSuffix(first, "…[line truncated]") {
		t.Fatalf("first line %q", first[len(first)-30:])
	}
	if len(first) > l.MaxLineLen+len("…[line truncated]") {
		t.Fatalf("line len %d", len(first))
	}
	if !strings.Contains(out, "short") {
		t.Fatal("following line lost")
	}
}

func TestTruncateTextLongLineRuneSafe(t *testing.T) {
	l := Limits{MaxBytes: 10000, MaxLines: 10, MaxLineLen: 10}
	out, tr := TruncateText(strings.Repeat("日", 50), l)
	if !tr || !utf8.ValidString(out) {
		t.Fatalf("got %q", out)
	}
}

func TestTruncateTail(t *testing.T) {
	in := []string{"a", "b", "c", "d"}
	got, tr := TruncateTail(in, 2)
	if !tr || len(got) != 2 || got[0] != "c" || got[1] != "d" {
		t.Fatalf("got %v %v", got, tr)
	}
	got, tr = TruncateTail(in, 4)
	if tr || len(got) != 4 {
		t.Fatalf("at limit: %v %v", got, tr)
	}
	got, tr = TruncateTail(nil, 4)
	if tr || len(got) != 0 {
		t.Fatalf("nil: %v %v", got, tr)
	}
	got, tr = TruncateTail(in, 0)
	if !tr || len(got) != 0 {
		t.Fatalf("zero: %v %v", got, tr)
	}
}

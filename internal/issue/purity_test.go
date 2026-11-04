package issue_test

import (
	"os/exec"
	"strings"
	"testing"
)

var forbidden = []string{"net", "net/http", "os/exec"}

func deps(t *testing.T, pkg string) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
	}
	return strings.Fields(string(out))
}

func bad(ds []string) []string {
	var r []string
	for _, d := range ds {
		for _, f := range forbidden {
			if d == f {
				r = append(r, d)
			}
		}
	}
	return r
}

func TestPackageIsPure(t *testing.T) {
	if b := bad(deps(t, ".")); len(b) > 0 {
		t.Errorf("internal/issue depends on %v", b)
	}
}

// Bite proof: the detector must flag a package that imports net/http.
func TestPurityCheckDetectsNetHTTP(t *testing.T) {
	if b := bad(deps(t, "./testdata/impure")); len(b) == 0 {
		t.Error("purity check did not detect net/http")
	}
}

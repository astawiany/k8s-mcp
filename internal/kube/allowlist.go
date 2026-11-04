package kube

import (
	"fmt"
	"path"
	"strings"
)

// Allowlist restricts which kubeconfig contexts may be used. Entries are exact
// context names or path.Match globs ("kind-*", "stag?ng", "team-[ab]"); note
// that "*" does not match "/". The zero value allows every context.
type Allowlist struct {
	patterns []string
}

// ParseAllowlist parses a comma-separated list of names and globs. Blank
// entries are ignored; an empty list allows every context. A malformed glob
// returns an error wrapping path.ErrBadPattern.
func ParseAllowlist(csv string) (Allowlist, error) {
	var a Allowlist
	for _, p := range strings.Split(csv, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := path.Match(p, ""); err != nil {
			return Allowlist{}, fmt.Errorf("context allowlist entry %q: %w", p, err)
		}
		a.patterns = append(a.patterns, p)
	}
	return a, nil
}

// MustParseAllowlist is ParseAllowlist that panics on error (tests, constants).
func MustParseAllowlist(csv string) Allowlist {
	a, err := ParseAllowlist(csv)
	if err != nil {
		panic(err)
	}
	return a
}

// AllowsAll reports whether the list is empty (every context allowed).
func (a Allowlist) AllowsAll() bool { return len(a.patterns) == 0 }

// Allows reports whether a context name is allowed.
func (a Allowlist) Allows(name string) bool {
	if a.AllowsAll() {
		return true
	}
	for _, p := range a.patterns {
		if p == name {
			return true
		}
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

// String returns the normalised list, or "(all)" when empty.
func (a Allowlist) String() string {
	if a.AllowsAll() {
		return "(all)"
	}
	return strings.Join(a.patterns, ",")
}

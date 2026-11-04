package kube

import (
	"errors"
	"path"
	"testing"
)

func TestAllowlistEmptyAllowsAll(t *testing.T) {
	for _, csv := range []string{"", "  ", ",", " , ,"} {
		a, err := ParseAllowlist(csv)
		if err != nil {
			t.Fatalf("ParseAllowlist(%q): %v", csv, err)
		}
		if !a.AllowsAll() {
			t.Errorf("ParseAllowlist(%q).AllowsAll() = false", csv)
		}
		for _, n := range []string{"dev", "prod", "arn:aws:eks:eu-west-1:1:cluster/x", ""} {
			if !a.Allows(n) {
				t.Errorf("ParseAllowlist(%q).Allows(%q) = false, want true", csv, n)
			}
		}
	}
	var zero Allowlist
	if !zero.Allows("anything") {
		t.Error("zero Allowlist must allow all")
	}
}

func TestAllowlistExactAndGlob(t *testing.T) {
	a, err := ParseAllowlist(" dev , kind-*,stag?ng,team-[ab]")
	if err != nil {
		t.Fatal(err)
	}
	if a.AllowsAll() {
		t.Fatal("non-empty list must not allow all")
	}
	cases := map[string]bool{
		"dev":         true,
		"dev2":        false,
		"Dev":         false, // case-sensitive, like kubeconfig context names
		"kind-a":      true,
		"kind-":       true,
		"kind":        false,
		"staging":     true,
		"stagxng":     true,
		"stagng":      false,
		"team-a":      true,
		"team-c":      false,
		"prod":        false,
		"kind-x/y":    false, // path.Match: * never crosses '/'
		" dev":        false,
		"":            false,
		"anythingdev": false,
	}
	for name, want := range cases {
		if got := a.Allows(name); got != want {
			t.Errorf("Allows(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestAllowlistExactNameWithMetaCharacters(t *testing.T) {
	// A context literally named "a[1]" is matched exactly even though as a
	// glob it would only match "a1".
	a, err := ParseAllowlist("a[1]")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Allows("a[1]") || !a.Allows("a1") || a.Allows("a2") {
		t.Errorf("a[1]: exact %v glob %v other %v", a.Allows("a[1]"), a.Allows("a1"), a.Allows("a2"))
	}
}

func TestAllowlistRejectsInvalidPattern(t *testing.T) {
	for _, csv := range []string{"[", "dev,[a-", "ok,a\\", "x[]"} {
		_, err := ParseAllowlist(csv)
		if err == nil {
			t.Errorf("ParseAllowlist(%q): want error", csv)
			continue
		}
		if !errors.Is(err, path.ErrBadPattern) {
			t.Errorf("ParseAllowlist(%q): error %v does not wrap path.ErrBadPattern", csv, err)
		}
	}
}

func TestAllowlistString(t *testing.T) {
	a := MustParseAllowlist("b, a*")
	if got := a.String(); got != "b,a*" {
		t.Errorf("String() = %q", got)
	}
	if got := (Allowlist{}).String(); got != "(all)" {
		t.Errorf("empty String() = %q", got)
	}
}

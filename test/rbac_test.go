package test

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

const (
	rbacManifest = "deploy/rbac/readonly-clusterrole.yaml"
	roleName     = "k8s-mcp-readonly"
)

// rbacDocs decodes every YAML document of the manifest into kind -> objects
// (as JSON, for typed decoding).
func rbacDocs(t *testing.T) map[string][][]byte {
	t.Helper()
	f, err := os.Open(filepath.Join(repoRoot(t), rbacManifest))
	if err != nil {
		t.Fatalf("open %s: %v", rbacManifest, err)
	}
	defer f.Close()
	docs := map[string][][]byte{}
	dec := yaml.NewYAMLOrJSONDecoder(f, 4096)
	for {
		var obj map[string]any
		if err := dec.Decode(&obj); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decode %s: %v", rbacManifest, err)
		}
		if obj == nil {
			continue
		}
		kind, _ := obj["kind"].(string)
		b, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		docs[kind] = append(docs[kind], b)
	}
	return docs
}

func readonlyRole(t *testing.T) rbacv1.ClusterRole {
	t.Helper()
	roles := rbacDocs(t)["ClusterRole"]
	if len(roles) != 1 {
		t.Fatalf("%s has %d ClusterRoles, want 1", rbacManifest, len(roles))
	}
	var cr rbacv1.ClusterRole
	if err := json.Unmarshal(roles[0], &cr); err != nil {
		t.Fatal(err)
	}
	if cr.Name != roleName {
		t.Fatalf("ClusterRole name = %q, want %q", cr.Name, roleName)
	}
	return cr
}

// TestClusterRoleIsReadOnlyAndHasNoSecrets: only get/list, never Secrets,
// no wildcard that could reach them, no aggregation that could add rules.
func TestClusterRoleIsReadOnlyAndHasNoSecrets(t *testing.T) {
	cr := readonlyRole(t)
	if cr.AggregationRule != nil {
		t.Error("ClusterRole has an aggregationRule (other roles' rules would be merged in)")
	}
	if len(cr.Rules) == 0 {
		t.Fatal("ClusterRole has no rules")
	}
	for i, r := range cr.Rules {
		for _, v := range r.Verbs {
			if v != "get" && v != "list" {
				t.Errorf("rule %d: verb %q; only get and list are allowed", i, v)
			}
		}
		if len(r.NonResourceURLs) > 0 {
			t.Errorf("rule %d: nonResourceURLs %v", i, r.NonResourceURLs)
		}
		for _, g := range r.APIGroups {
			if strings.Contains(g, "*") {
				t.Errorf("rule %d: wildcard apiGroup %q", i, g)
			}
		}
		for _, res := range r.Resources {
			base, _, _ := strings.Cut(strings.ToLower(res), "/")
			if base == "secrets" || base == "secret" {
				t.Errorf("rule %d (apiGroups %q): grants %q", i, r.APIGroups, res)
			}
			if strings.Contains(res, "*") {
				t.Errorf("rule %d (apiGroups %q): wildcard resource %q could include secrets", i, r.APIGroups, res)
			}
		}
	}
}

// grants reports whether some rule gives verb on group/resource.
func grants(cr rbacv1.ClusterRole, group, resource, verb string) bool {
	for _, r := range cr.Rules {
		if slices.Contains(r.APIGroups, group) && slices.Contains(r.Resources, resource) && slices.Contains(r.Verbs, verb) {
			return true
		}
	}
	return false
}

// TestClusterRoleCoversTheTools: what the eleven tools read.
func TestClusterRoleCoversTheTools(t *testing.T) {
	cr := readonlyRole(t)
	need := []struct{ group, resource, verb string }{
		{"", "pods/log", "get"},
		{"", "pods", "get"}, {"", "pods", "list"},
		{"", "nodes", "list"}, {"", "events", "list"}, {"", "namespaces", "list"},
		{"", "configmaps", "get"}, {"", "services", "list"},
		{"apps", "deployments", "get"}, {"apps", "statefulsets", "get"}, {"apps", "daemonsets", "get"},
		{"apps", "replicasets", "list"},
		{"events.k8s.io", "events", "list"},
		{"metrics.k8s.io", "nodes", "list"}, {"metrics.k8s.io", "pods", "list"},
		{"kustomize.toolkit.fluxcd.io", "kustomizations", "list"},
		{"helm.toolkit.fluxcd.io", "helmreleases", "list"},
		{"source.toolkit.fluxcd.io", "gitrepositories", "list"},
		{"source.toolkit.fluxcd.io", "helmrepositories", "list"},
		{"source.toolkit.fluxcd.io", "ocirepositories", "list"},
		{"apiextensions.k8s.io", "customresourcedefinitions", "list"},
	}
	for _, n := range need {
		if !grants(cr, n.group, n.resource, n.verb) {
			t.Errorf("ClusterRole does not grant %s on %q in group %q", n.verb, n.resource, n.group)
		}
	}
}

func TestClusterRoleBindingExampleBindsTheRole(t *testing.T) {
	docs := rbacDocs(t)
	bs := docs["ClusterRoleBinding"]
	if len(bs) != 1 {
		t.Fatalf("%d ClusterRoleBindings, want 1", len(bs))
	}
	var b rbacv1.ClusterRoleBinding
	if err := json.Unmarshal(bs[0], &b); err != nil {
		t.Fatal(err)
	}
	if b.RoleRef.Kind != "ClusterRole" || b.RoleRef.Name != roleName {
		t.Errorf("roleRef = %+v", b.RoleRef)
	}
	if len(b.Subjects) != 1 || b.Subjects[0].Kind != "ServiceAccount" {
		t.Errorf("subjects = %+v, want one ServiceAccount", b.Subjects)
	}
	for kind := range docs {
		switch kind {
		case "Namespace", "ServiceAccount", "ClusterRole", "ClusterRoleBinding":
		default:
			t.Errorf("unexpected kind %q in %s", kind, rbacManifest)
		}
	}
}

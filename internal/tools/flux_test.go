package tools_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/astawiany/k8s-mcp/internal/kube"
)

type fStatus struct {
	Kind      string   `json:"kind"`
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Ready     bool     `json:"ready"`
	Reason    string   `json:"reason"`
	Message   string   `json:"message"`
	Revision  string   `json:"revision"`
	Suspended bool     `json:"suspended"`
	Stalled   bool     `json:"stalled"`
	DependsOn []string `json:"dependsOn"`
}

type fOut struct {
	Installed    bool      `json:"installed"`
	Message      string    `json:"message"`
	Statuses     []fStatus `json:"statuses"`
	MissingKinds []string  `json:"missingKinds"`
	Truncated    bool      `json:"truncated"`
	BlockedBy    []struct {
		Kind      string `json:"kind"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		WaitingOn []struct {
			Kind, Namespace, Name, State, Reason string
		} `json:"waitingOn"`
	} `json:"blockedBy"`
	Summary struct{ Total, Ready, NotReady, Suspended int } `json:"summary"`
}

func fObj(apiVersion, kind, ns, name string, ready bool, reason, msg string, spec map[string]any) map[string]any {
	o := kube.Object(apiVersion, kind, ns, name)
	st := "False"
	if ready {
		st = "True"
	}
	o["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": st, "reason": reason, "message": msg}}}
	if spec != nil {
		o["spec"] = spec
	}
	return o
}

func runFlux(t *testing.T, c *kube.FakeClient, args map[string]any) fOut {
	t.Helper()
	var out fOut
	decode(t, callTool(t, kube.SingleFakeFactory(c), "flux_status", args), &out)
	return out
}

func TestFluxFailingHelmRelease(t *testing.T) {
	c := kube.NewFakeClient(
		fObj("helm.toolkit.fluxcd.io/v2", "HelmRelease", "apps", "web", false, "InstallFailed", "Helm install failed: timeout", map[string]any{"values": map[string]any{"password": "hunter2"}, "valuesFrom": []any{map[string]any{"kind": "Secret", "name": "creds"}}}),
		fObj("helm.toolkit.fluxcd.io/v2", "HelmRelease", "apps", "ok", true, "InstallSucceeded", "ok", nil),
	)
	res := callTool(t, kube.SingleFakeFactory(c), "flux_status", nil)
	var out fOut
	decode(t, res, &out)
	if !out.Installed || len(out.Statuses) != 2 {
		t.Fatalf("%+v", out)
	}
	first := out.Statuses[0]
	if first.Name != "web" || first.Ready || first.Reason != "InstallFailed" || first.Kind != "HelmRelease" {
		t.Fatalf("unhealthy first: %+v", out.Statuses)
	}
	if out.Summary.Total != 2 || out.Summary.Ready != 1 || out.Summary.NotReady != 1 {
		t.Fatalf("summary %+v", out.Summary)
	}
	for _, c := range res.Content {
		if strings.Contains(fmt.Sprint(c), "hunter2") {
			t.Fatal("spec contents leaked")
		}
	}
	// the three source kinds and Kustomization exist in default discovery; no
	// objects there is fine
	if len(out.MissingKinds) != 0 {
		t.Fatalf("missing %v", out.MissingKinds)
	}
}

func TestFluxSuspendedKustomization(t *testing.T) {
	c := kube.NewFakeClient(
		fObj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "paused", true, "ReconciliationSucceeded", "", map[string]any{"suspend": true}),
		fObj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "fine", true, "ReconciliationSucceeded", "", nil),
	)
	out := runFlux(t, c, nil)
	if out.Summary.Suspended != 1 || !out.Statuses[0].Suspended || out.Statuses[0].Name != "paused" {
		t.Fatalf("%+v", out)
	}
	out = runFlux(t, c, map[string]any{"onlyUnhealthy": true})
	if len(out.Statuses) != 1 || out.Statuses[0].Name != "paused" || out.Summary.Total != 2 {
		t.Fatalf("onlyUnhealthy: %+v", out)
	}
}

func TestFluxOnlyUnhealthyDropsReady(t *testing.T) {
	c := kube.NewFakeClient(
		fObj("source.toolkit.fluxcd.io/v1", "GitRepository", "flux-system", "good", true, "Succeeded", "", nil),
		fObj("source.toolkit.fluxcd.io/v1", "GitRepository", "flux-system", "bad", false, "GitOperationFailed", "x", nil),
	)
	out := runFlux(t, c, map[string]any{"onlyUnhealthy": true, "kinds": []string{"gitrepository"}})
	if len(out.Statuses) != 1 || out.Statuses[0].Name != "bad" {
		t.Fatalf("%+v", out.Statuses)
	}
}

func TestFluxDependencyBlocking(t *testing.T) {
	ks := "kustomize.toolkit.fluxcd.io/v1"
	c := kube.NewFakeClient(
		fObj(ks, "Kustomization", "flux-system", "infra", false, "BuildFailed", "kustomize build failed", nil),
		fObj(ks, "Kustomization", "flux-system", "apps", false, "DependencyNotReady", "dependency 'flux-system/infra' is not ready",
			map[string]any{"dependsOn": []any{map[string]any{"name": "infra"}, map[string]any{"name": "ghost"}, map[string]any{"name": "crds", "namespace": "flux-system"}}}),
		fObj(ks, "Kustomization", "flux-system", "crds", true, "ReconciliationSucceeded", "", nil),
	)
	out := runFlux(t, c, nil)
	if len(out.BlockedBy) != 1 || out.BlockedBy[0].Name != "apps" {
		t.Fatalf("blockedBy %+v", out.BlockedBy)
	}
	w := out.BlockedBy[0].WaitingOn
	if len(w) != 2 || w[0].Name != "infra" || w[0].State != "notReady" || w[0].Reason != "BuildFailed" || w[1].Name != "ghost" || w[1].State != "missing" {
		t.Fatalf("waitingOn %+v", w)
	}
	// narrowing to another namespace hides the dependency: unknown, not missing
	c.Add(fObj(ks, "Kustomization", "team", "t", false, "DependencyNotReady", "",
		map[string]any{"dependsOn": []any{map[string]any{"name": "infra", "namespace": "flux-system"}}}))
	out = runFlux(t, c, map[string]any{"namespace": "team"})
	if len(out.BlockedBy) != 1 || out.BlockedBy[0].WaitingOn[0].State != "unknown" {
		t.Fatalf("%+v", out.BlockedBy)
	}
}

func TestFluxGitAuthMessageScrubbed(t *testing.T) {
	c := kube.NewFakeClient(fObj("source.toolkit.fluxcd.io/v1", "GitRepository", "flux-system", "repo", false, "GitOperationFailed",
		"failed to checkout and determine revision: unable to clone 'https://deploy:s3cr3tpw@github.com/org/repo.git': authentication required", nil))
	res := callTool(t, kube.SingleFakeFactory(c), "flux_status", nil)
	var out fOut
	decode(t, res, &out)
	m := out.Statuses[0].Message
	if strings.Contains(m, "s3cr3tpw") || !strings.Contains(m, "https://[redacted]@github.com/org/repo.git") || !strings.Contains(m, "authentication required") {
		t.Fatalf("message %q", m)
	}
}

func TestFluxCRDsAbsent(t *testing.T) {
	c := kube.NewFakeClient()
	c.SetResources(kube.DefaultResources()[:5]...)
	out := runFlux(t, c, nil)
	if out.Installed || !strings.Contains(out.Message, "Flux CRDs") || len(out.Statuses) != 0 {
		t.Fatalf("%+v", out)
	}
}

func TestFluxSomeKindsMissing(t *testing.T) {
	var infos []kube.ResourceInfo
	for _, r := range kube.DefaultResources() {
		if r.Kind != "OCIRepository" && r.Kind != "HelmRepository" {
			infos = append(infos, r)
		}
	}
	c := kube.NewFakeClient()
	c.SetResources(infos...)
	c.Add(fObj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "a", "k", true, "ok", "", nil))
	out := runFlux(t, c, nil)
	if !out.Installed || len(out.Statuses) != 1 || strings.Join(out.MissingKinds, ",") != "HelmRepository,OCIRepository" {
		t.Fatalf("%+v", out)
	}
}

func TestFluxVersionsResolvedNotHardcoded(t *testing.T) {
	for _, v := range []string{"v2beta2", "v2"} {
		t.Run(v, func(t *testing.T) {
			c := kube.NewFakeClient()
			c.SetResources(kube.ResourceInfo{
				Resource:  kube.Resource{Group: "helm.toolkit.fluxcd.io", Version: v, Resource: "helmreleases", Kind: "HelmRelease", Namespaced: true},
				Singular:  "helmrelease",
				Verbs:     []string{"get", "list"},
				Preferred: true,
			})
			c.Add(fObj("helm.toolkit.fluxcd.io/"+v, "HelmRelease", "a", "r", false, "UpgradeFailed", "", nil))
			out := runFlux(t, c, map[string]any{"kinds": []string{"HelmRelease"}})
			if !out.Installed || len(out.Statuses) != 1 || out.Statuses[0].Reason != "UpgradeFailed" {
				t.Fatalf("%+v", out)
			}
		})
	}
}

func TestFluxCapsStatuses(t *testing.T) {
	c := kube.NewFakeClient()
	for i := 0; i < 300; i++ {
		c.Add(fObj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "ns", fmt.Sprintf("ks-%03d", i), i%2 == 0, "r", "", nil))
	}
	out := runFlux(t, c, nil)
	if len(out.Statuses) != 200 || !out.Truncated || out.Summary.Total != 300 {
		t.Fatalf("len=%d truncated=%v summary=%+v", len(out.Statuses), out.Truncated, out.Summary)
	}
	if out.Statuses[0].Ready {
		t.Fatal("unhealthy must come first")
	}
}

func TestFluxRejectsUnknownKind(t *testing.T) {
	res := callTool(t, kube.SingleFakeFactory(kube.NewFakeClient()), "flux_status", map[string]any{"kinds": []string{"Secret"}})
	if !res.IsError {
		t.Fatal("expected an error result")
	}
}

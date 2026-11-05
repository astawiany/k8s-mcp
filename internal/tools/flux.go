package tools

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/astawiany/k8s-mcp/internal/flux"
	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/limits"
	"github.com/astawiany/k8s-mcp/internal/server"
)

// fluxGroups maps the Flux kinds this tool reads to their API group. Versions
// are never hardcoded: Resolve picks whichever the cluster prefers.
var fluxGroups = map[string]string{
	"Kustomization":  "kustomize.toolkit.fluxcd.io",
	"HelmRelease":    "helm.toolkit.fluxcd.io",
	"GitRepository":  "source.toolkit.fluxcd.io",
	"HelmRepository": "source.toolkit.fluxcd.io",
	"OCIRepository":  "source.toolkit.fluxcd.io",
	"HelmChart":      "source.toolkit.fluxcd.io",
	"Bucket":         "source.toolkit.fluxcd.io",
}

var defaultFluxKinds = []string{"Kustomization", "HelmRelease", "GitRepository", "HelmRepository", "OCIRepository"}

const (
	fluxPageSize = 500
	fluxMaxFetch = 5000 // objects read per kind before giving up on completeness
)

type fluxIn struct {
	Context       string   `json:"context,omitempty" jsonschema:"kubeconfig context name; defaults to the current context"`
	Namespace     string   `json:"namespace,omitempty" jsonschema:"namespace; empty reads all namespaces"`
	Kinds         []string `json:"kinds,omitempty" jsonschema:"Flux kinds to read (any case): Kustomization, HelmRelease, GitRepository, HelmRepository, OCIRepository, HelmChart, Bucket; default is the first five"`
	OnlyUnhealthy bool     `json:"onlyUnhealthy,omitempty" jsonschema:"only return objects that are not Ready, stalled or suspended; default false"`
}

type fluxWait struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	// State is notReady, missing (the kind was read completely and has no
	// such object) or unknown (the dependency is outside what was read).
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

type fluxBlocked struct {
	Kind      string     `json:"kind"`
	Namespace string     `json:"namespace,omitempty"`
	Name      string     `json:"name"`
	WaitingOn []fluxWait `json:"waitingOn"`
}

type fluxSummary struct {
	Total     int `json:"total"`
	Ready     int `json:"ready"`
	NotReady  int `json:"notReady"`
	Suspended int `json:"suspended"`
}

type fluxOut struct {
	Installed    bool          `json:"installed"`
	Message      string        `json:"message,omitempty"`
	Statuses     []flux.Status `json:"statuses,omitempty"`
	BlockedBy    []fluxBlocked `json:"blockedBy,omitempty"`
	Summary      *fluxSummary  `json:"summary,omitempty"`
	MissingKinds []string      `json:"missingKinds,omitempty"`
	Truncated    bool          `json:"truncated"`
	Note         string        `json:"note,omitempty"`
}

func registerFlux(s *server.Server) {
	server.Register(s, &mcp.Tool{
		Name: "flux_status",
		Description: "Health of Flux CD objects (kinds default to Kustomization, HelmRelease, GitRepository, " +
			"HelmRepository, OCIRepository; HelmChart and Bucket are also accepted). Returns per object: " +
			"ready, reason, message, revision, suspended, stalled, dependsOn, unhealthy first. blockedBy lists " +
			"not-Ready objects waiting on dependsOn entries that are not Ready (or missing, or outside what was " +
			"read). Kinds the cluster does not serve are skipped and listed in missingKinds; with no Flux CRDs the " +
			"result is installed=false. At most 200 statuses and 200 blockedBy entries are returned (truncated=true; narrow with namespace, " +
			"kinds or onlyUnhealthy); summary counts everything read before onlyUnhealthy and the cap: ready = Ready condition True (a Stalled but Ready object counts as ready), notReady = not Ready, suspended = spec.suspend true (a Ready but suspended object counts in both ready and suspended). Only status fields are returned, never spec " +
			"contents, and URL credentials in messages are redacted. Read-only: it never reconciles or patches.",
	}, server.CapRead, fluxStatus)
}

type fluxKey struct{ kind, ns, name string }

func fluxStatus(ctx context.Context, f kube.Factory, in fluxIn) (any, error) {
	kinds, err := fluxKinds(in.Kinds)
	if err != nil {
		return nil, err
	}
	c, err := clientFor(f, in.Context)
	if err != nil {
		return nil, err
	}
	ns := strings.TrimSpace(in.Namespace)

	var all []flux.Status
	var missing []string
	complete := map[string]bool{} // kind -> every object was read
	for _, kind := range kinds {
		r, err := c.Resolve(ctx, kind, fluxGroups[kind], "")
		if err != nil {
			if errors.Is(err, kube.ErrKindNotFound) {
				missing = append(missing, kind)
				continue
			}
			return nil, err
		}
		if err := refuseSecret(r.Group, r.Kind, r.Resource); err != nil {
			return nil, err
		}
		kns, _ := namespaceFor(r, ns, false)
		cont, n := "", 0
		complete[kind] = kns == ""
		for {
			lr, err := c.List(ctx, r, kns, kube.ListOptions{Limit: fluxPageSize, Continue: cont})
			if err != nil {
				return nil, err
			}
			for _, obj := range lr.Items {
				if objectIsSecret(obj) {
					return nil, errSecretRefused
				}
				st := flux.Summarize(obj)
				st.Kind = kind
				all = append(all, st)
			}
			n += len(lr.Items)
			cont = lr.Continue
			if cont == "" {
				break
			}
			if n >= fluxMaxFetch {
				complete[kind] = false
				break
			}
		}
	}

	if len(missing) == len(kinds) {
		return fluxOut{Installed: false, Message: "Flux CRDs (toolkit.fluxcd.io) not found on this cluster", MissingKinds: missing}, nil
	}

	byKey := map[fluxKey]flux.Status{}
	for _, st := range all {
		byKey[fluxKey{st.Kind, st.Namespace, st.Name}] = st
	}
	out := fluxOut{Installed: true, MissingKinds: missing, Summary: &fluxSummary{Total: len(all)}}
	for _, st := range all {
		switch {
		case st.Ready:
			out.Summary.Ready++
		default:
			out.Summary.NotReady++
		}
		if st.Suspended {
			out.Summary.Suspended++
		}
		if st.Ready || len(st.DependsOn) == 0 {
			continue
		}
		var waits []fluxWait
		for _, d := range st.DependsOn {
			dns, dname := st.Namespace, d
			if a, b, ok := strings.Cut(d, "/"); ok {
				dns, dname = a, b
			}
			dep, found := byKey[fluxKey{st.Kind, dns, dname}]
			switch {
			case found && dep.Ready:
			case found:
				waits = append(waits, fluxWait{Kind: st.Kind, Namespace: dns, Name: dname, State: "notReady", Reason: dep.Reason})
			case complete[st.Kind]:
				waits = append(waits, fluxWait{Kind: st.Kind, Namespace: dns, Name: dname, State: "missing"})
			default:
				waits = append(waits, fluxWait{Kind: st.Kind, Namespace: dns, Name: dname, State: "unknown"})
			}
		}
		if len(waits) > 0 {
			out.BlockedBy = append(out.BlockedBy, fluxBlocked{Kind: st.Kind, Namespace: st.Namespace, Name: st.Name, WaitingOn: waits})
		}
	}

	unhealthy := func(s flux.Status) bool { return !s.Ready || s.Stalled || s.Suspended }
	if in.OnlyUnhealthy {
		all = slices.DeleteFunc(all, func(s flux.Status) bool { return !unhealthy(s) })
	}
	slices.SortStableFunc(all, func(a, b flux.Status) int {
		if ua, ub := unhealthy(a), unhealthy(b); ua != ub {
			if ua {
				return -1
			}
			return 1
		}
		return cmp.Or(strings.Compare(a.Namespace, b.Namespace), strings.Compare(a.Name, b.Name), strings.Compare(a.Kind, b.Kind))
	})
	slices.SortFunc(out.BlockedBy, func(a, b fluxBlocked) int {
		return cmp.Or(strings.Compare(a.Namespace, b.Namespace), strings.Compare(a.Name, b.Name), strings.Compare(a.Kind, b.Kind))
	})
	max := limits.Default().MaxItems
	var cut []string
	if len(all) > max {
		all = all[:max]
		cut = append(cut, fmt.Sprintf("more than %d Flux objects match", max))
	}
	if len(out.BlockedBy) > max {
		out.BlockedBy = out.BlockedBy[:max]
		cut = append(cut, fmt.Sprintf("more than %d blockedBy entries", max))
	}
	if len(cut) > 0 {
		out.Truncated = true
		out.Note = limits.Note(strings.Join(cut, " and "), "a namespace, fewer kinds or onlyUnhealthy")
	}
	out.Statuses = all
	if out.Statuses == nil {
		out.Statuses = []flux.Status{}
	}
	return out, nil
}

func fluxKinds(in []string) ([]string, error) {
	if len(in) == 0 {
		return defaultFluxKinds, nil
	}
	var out []string
	for _, k := range in {
		canon := ""
		for name := range fluxGroups {
			if strings.EqualFold(name, strings.TrimSpace(k)) {
				canon = name
			}
		}
		if canon == "" {
			return nil, fmt.Errorf("unsupported Flux kind %q; supported: Kustomization, HelmRelease, GitRepository, HelmRepository, OCIRepository, HelmChart, Bucket", k)
		}
		if !slices.Contains(out, canon) {
			out = append(out, canon)
		}
	}
	return out, nil
}

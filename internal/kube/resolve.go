package kube

import (
	"cmp"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// maxSuggestions caps the close matches listed for an unknown kind.
const maxSuggestions = 5

// infosFromDiscovery flattens discovery output into ResourceInfos in server
// priority order (the order of groups), skipping subresources.
func infosFromDiscovery(groups []*metav1.APIGroup, lists []*metav1.APIResourceList) []ResourceInfo {
	preferred := map[string]string{}
	order := map[string]int{}
	for i, g := range groups {
		if g == nil {
			continue
		}
		preferred[g.Name] = g.PreferredVersion.Version
		if _, seen := order[g.Name]; !seen {
			order[g.Name] = i
		}
	}
	var out []ResourceInfo
	for _, l := range lists {
		if l == nil {
			continue
		}
		group, version, ok := splitGroupVersion(l.GroupVersion)
		if !ok {
			continue
		}
		for _, r := range l.APIResources {
			if r.Name == "" || strings.Contains(r.Name, "/") {
				continue
			}
			pv, known := preferred[group]
			out = append(out, ResourceInfo{
				Resource:   Resource{Group: group, Version: version, Resource: r.Name, Kind: r.Kind, Namespaced: r.Namespaced},
				Singular:   r.SingularName,
				ShortNames: slices.Clone(r.ShortNames),
				Verbs:      slices.Clone(r.Verbs),
				Preferred:  !known || pv == version,
			})
		}
	}
	// Stable: keeps list order inside a group, sorts groups by server order.
	slices.SortStableFunc(out, func(a, b ResourceInfo) int {
		return cmp.Compare(groupOrder(order, a.Group), groupOrder(order, b.Group))
	})
	return out
}

func groupOrder(order map[string]int, g string) int {
	if i, ok := order[g]; ok {
		return i
	}
	return len(order)
}

// splitGroupVersion splits "apps/v1" or "v1".
func splitGroupVersion(gv string) (group, version string, ok bool) {
	switch parts := strings.Split(gv, "/"); len(parts) {
	case 1:
		return "", parts[0], parts[0] != ""
	case 2:
		return parts[0], parts[1], parts[0] != "" && parts[1] != ""
	}
	return "", "", false
}

func (in ResourceInfo) names() []string {
	n := []string{strings.ToLower(in.Resource.Resource), strings.ToLower(in.Kind)}
	if in.Singular != "" {
		n = append(n, strings.ToLower(in.Singular))
	}
	for _, s := range in.ShortNames {
		n = append(n, strings.ToLower(s))
	}
	return n
}

func normGroup(g string) string {
	g = strings.ToLower(strings.TrimSpace(g))
	if g == "core" {
		return ""
	}
	return g
}

// resolveIn resolves a name against discovery entries (see Client.Resolve).
func resolveIn(infos []ResourceInfo, kindOrResource, group, version string) (Resource, error) {
	q := strings.ToLower(strings.TrimSpace(kindOrResource))
	g := normGroup(group)
	groupSet := strings.TrimSpace(group) != ""
	v := strings.ToLower(strings.TrimSpace(version))
	notFound := &KindNotFoundError{Query: strings.TrimSpace(kindOrResource), Group: strings.TrimSpace(group), Version: strings.TrimSpace(version)}
	if q == "" {
		return Resource{}, notFound
	}

	if r, ok := pick(infos, q, g, groupSet, v); ok {
		return r, nil
	}
	// kubectl's "resource.group" form, e.g. deployments.apps
	if name, grp, ok := strings.Cut(q, "."); ok && !groupSet && name != "" {
		if r, ok := pick(infos, name, grp, true, v); ok {
			return r, nil
		}
	}
	notFound.Suggestions = suggest(infos, q)
	return Resource{}, notFound
}

func pick(infos []ResourceInfo, q, g string, groupSet bool, v string) (Resource, bool) {
	best := -1
	for i, in := range infos {
		if groupSet && in.Group != g {
			continue
		}
		if v != "" && strings.ToLower(in.Version) != v {
			continue
		}
		if !slices.Contains(in.names(), q) {
			continue
		}
		// infos are in server priority order: the first match wins unless a
		// later one is the preferred version of the same group.
		if best < 0 || (infos[best].Group == in.Group && !infos[best].Preferred && in.Preferred) {
			best = i
		}
	}
	if best < 0 {
		return Resource{}, false
	}
	return infos[best].Resource, true
}

// suggest lists up to maxSuggestions resources whose names are within a small
// edit distance of q (or that q is a prefix of), closest first.
func suggest(infos []ResourceInfo, q string) []string {
	threshold := max(2, len([]rune(q))/3)
	type cand struct {
		label string
		dist  int
		order int
	}
	seen := map[string]bool{}
	var cands []cand
	for i, in := range infos {
		label := in.Resource.String()
		if seen[label] {
			continue
		}
		d := -1
		for _, n := range in.names() {
			nd := levenshtein(q, n)
			if nd > threshold && !(len(q) >= 3 && strings.HasPrefix(n, q)) {
				continue
			}
			if d < 0 || nd < d {
				d = nd
			}
		}
		if d < 0 {
			continue
		}
		seen[label] = true
		cands = append(cands, cand{label, d, i})
	}
	slices.SortStableFunc(cands, func(a, b cand) int {
		return cmp.Or(cmp.Compare(a.dist, b.dist), cmp.Compare(a.order, b.order))
	})
	var out []string
	for _, c := range cands[:min(len(cands), maxSuggestions)] {
		out = append(out, c.label)
	}
	return out
}

// levenshtein is the edit distance between a and b, in runes.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}

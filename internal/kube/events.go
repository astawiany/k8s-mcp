package kube

import (
	"cmp"
	"slices"
	"strings"
	"time"
)

// eventTime is the most recent time an event was observed: the latest of
// series.lastObservedTime, lastTimestamp, eventTime, firstTimestamp and
// metadata.creationTimestamp. Zero if none parses.
func eventTime(ev map[string]any) time.Time {
	var best time.Time
	for _, p := range [][]string{
		{"series", "lastObservedTime"},
		{"lastTimestamp"},
		{"eventTime"},
		{"firstTimestamp"},
		{"metadata", "creationTimestamp"},
	} {
		s, _ := nested(ev, p...).(string)
		if s == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			continue
		}
		if t.After(best) {
			best = t
		}
	}
	return best
}

// maxEvents caps what Events returns; the newest events are kept. A variable
// so tests can lower it.
var maxEvents = 5000

// sinceAndSort drops events older than since (0 = keep all; events without a
// parseable time are kept), keeps the newest maxEvents and returns them
// oldest first.
func sinceAndSort(items []map[string]any, since time.Duration, now time.Time) []map[string]any {
	out := items[:0:0]
	cutoff := now.Add(-since)
	for _, ev := range items {
		if since > 0 {
			if t := eventTime(ev); !t.IsZero() && t.Before(cutoff) {
				continue
			}
		}
		out = append(out, ev)
	}
	slices.SortStableFunc(out, func(a, b map[string]any) int {
		return cmp.Or(eventTime(a).Compare(eventTime(b)), strings.Compare(objName(a), objName(b)))
	})
	if len(out) > maxEvents {
		out = out[len(out)-maxEvents:]
	}
	return out
}

// involvedFieldSelector builds the server-side field selector for ref.
func involvedFieldSelector(ref *ObjectRef) string {
	if ref == nil {
		return ""
	}
	var parts []string
	add := func(field, v string) {
		if v != "" {
			parts = append(parts, field+"="+escapeFieldValue(v))
		}
	}
	add("involvedObject.kind", ref.Kind)
	add("involvedObject.namespace", ref.Namespace)
	add("involvedObject.name", ref.Name)
	add("involvedObject.uid", ref.UID)
	return strings.Join(parts, ",")
}

// escapeFieldValue escapes \, comma and = as fields.EscapeValue does.
func escapeFieldValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, `,`, `\,`, `=`, `\=`).Replace(s)
}

// nested walks a JSON tree; nil when any step is missing.
func nested(obj map[string]any, path ...string) any {
	var cur any = obj
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

func objName(obj map[string]any) string {
	s, _ := nested(obj, "metadata", "name").(string)
	return s
}

func objNamespace(obj map[string]any) string {
	s, _ := nested(obj, "metadata", "namespace").(string)
	return s
}

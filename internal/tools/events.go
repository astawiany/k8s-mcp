package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/limits"
	"github.com/astawiany/k8s-mcp/internal/redact"
	"github.com/astawiany/k8s-mcp/internal/server"
)

const (
	defaultSinceMinutes = 60
	maxSinceMinutes     = 1440
)

type eventsIn struct {
	Context      string `json:"context,omitempty" jsonschema:"kubeconfig context name; defaults to the current context"`
	Namespace    string `json:"namespace,omitempty" jsonschema:"namespace; empty means all namespaces"`
	InvolvedKind string `json:"involvedKind,omitempty" jsonschema:"only events about this kind (kind, resource or short name, e.g. Pod, deploy)"`
	InvolvedName string `json:"involvedName,omitempty" jsonschema:"only events about the object with this name"`
	SinceMinutes int    `json:"sinceMinutes,omitempty" jsonschema:"only events seen in the last N minutes; default 60, at most 1440"`
	WarningsOnly bool   `json:"warningsOnly,omitempty" jsonschema:"only events of type Warning"`
}

// eventOut is one event in tool output.
type eventOut struct {
	Type      string `json:"type"`
	Reason    string `json:"reason"`
	Message   string `json:"message"`
	Object    string `json:"object"` // Kind/name of the involved object
	Namespace string `json:"namespace,omitempty"`
	Count     int64  `json:"count"`
	FirstSeen string `json:"firstSeen,omitempty"`
	LastSeen  string `json:"lastSeen,omitempty"`
	Warning   bool   `json:"warning,omitempty"`
}

type eventsOut struct {
	Events []eventOut `json:"events"`
	// Total is the number of matching events read (at most 5000, the newest).
	Total     int    `json:"total"`
	Truncated bool   `json:"truncated"`
	Note      string `json:"note,omitempty"`
}

func registerEvents(s *server.Server) {
	server.Register(s, &mcp.Tool{
		Name: "get_events",
		Description: "List core/v1 events seen in the last sinceMinutes (default 60, at most 1440), optionally " +
			"only in one namespace, only about one kind and/or object name, or only warnings. Each event is " +
			"{type, reason, message, object (Kind/name), namespace, count, firstSeen, lastSeen, warning}. " +
			"Sorted warnings first, then oldest to newest within each group. At most 200 events are returned " +
			"(warnings kept first, then the newest others) with truncated=true and total when more matched; at " +
			"most the 5000 newest events are read. involvedKind Secret is refused. Read-only: never creates, changes or deletes anything.",
	}, server.CapRead, getEvents)
}

func getEvents(ctx context.Context, f kube.Factory, in eventsIn) (any, error) {
	since := in.SinceMinutes
	if since == 0 {
		since = defaultSinceMinutes
	}
	if since < 0 || since > maxSinceMinutes {
		return nil, fmt.Errorf("sinceMinutes must be between 1 and %d", maxSinceMinutes)
	}
	c, err := clientFor(f, in.Context)
	if err != nil {
		return nil, err
	}
	ns := strings.TrimSpace(in.Namespace)
	var ref *kube.ObjectRef
	if strings.TrimSpace(in.InvolvedKind) != "" || strings.TrimSpace(in.InvolvedName) != "" {
		ref = &kube.ObjectRef{Namespace: ns, Name: strings.TrimSpace(in.InvolvedName)}
		if strings.TrimSpace(in.InvolvedKind) != "" {
			r, err := resolveReadable(ctx, c, in.InvolvedKind, "", "")
			if err != nil {
				return nil, err
			}
			ref.Kind = r.Kind
		}
	}
	evs, err := c.Events(ctx, ns, ref, time.Duration(since)*time.Minute)
	if err != nil {
		return nil, err
	}
	var warnings, others []map[string]any // each oldest first, as Events returns them
	for _, ev := range evs {
		switch {
		case str(ev, "type") == "Warning":
			warnings = append(warnings, ev)
		case !in.WarningsOnly:
			others = append(others, ev)
		}
	}
	out := eventsOut{Total: len(warnings) + len(others), Events: []eventOut{}}
	maxItems := limits.Default().MaxItems
	// Keep warnings first (the newest when there are too many), then the
	// newest other events in the room left.
	warnings = newest(warnings, maxItems)
	others = newest(others, maxItems-len(warnings))
	for _, ev := range append(warnings, others...) {
		out.Events = append(out.Events, toEvent(ev))
	}
	if len(out.Events) < out.Total {
		out.Truncated = true
		out.Note = limits.Note(fmt.Sprintf("%d events matched, %d returned", out.Total, len(out.Events)),
			"a namespace, involvedKind/involvedName, warningsOnly or a smaller sinceMinutes")
	}
	return out, nil
}

// newest keeps the last n of an oldest-first slice.
func newest(evs []map[string]any, n int) []map[string]any {
	if n <= 0 {
		return nil
	}
	if len(evs) > n {
		return evs[len(evs)-n:]
	}
	return evs
}

// toEvent converts a core/v1 Event (after redact.Workload) to eventOut.
func toEvent(raw map[string]any) eventOut {
	ev := redact.Workload(raw)
	e := eventOut{
		Type:      str(ev, "type"),
		Reason:    str(ev, "reason"),
		Message:   str(ev, "message"),
		Object:    str(ev, "involvedObject", "kind") + "/" + str(ev, "involvedObject", "name"),
		Namespace: str(ev, "involvedObject", "namespace"),
		Count:     1,
	}
	if e.Namespace == "" {
		e.Namespace = str(ev, "metadata", "namespace")
	}
	if n, ok := num(ev, "series", "count"); ok && n > 0 {
		e.Count = n
	} else if n, ok := num(ev, "count"); ok && n > 0 {
		e.Count = n
	}
	e.FirstSeen = firstNonEmpty(str(ev, "firstTimestamp"), str(ev, "eventTime"), str(ev, "metadata", "creationTimestamp"))
	e.LastSeen = firstNonEmpty(str(ev, "series", "lastObservedTime"), str(ev, "lastTimestamp"), str(ev, "eventTime"), e.FirstSeen)
	e.Warning = e.Type == "Warning"
	return e
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

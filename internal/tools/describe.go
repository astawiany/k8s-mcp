package tools

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/limits"
	"github.com/astawiany/k8s-mcp/internal/redact"
	"github.com/astawiany/k8s-mcp/internal/server"
)

// describeMaxEvents caps the events of one described object (the newest are
// kept); well under limits.Default().MaxItems so the object still fits the
// 64 KiB document cap.
const describeMaxEvents = 50

type conditionOut struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason,omitempty"`
	Message            string `json:"message,omitempty"`
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
}

type describeOut struct {
	Object          map[string]any `json:"object"`
	Conditions      []conditionOut `json:"conditions"`
	Events          []eventOut     `json:"events"`
	EventsTruncated bool           `json:"eventsTruncated,omitempty"`
	// EventsNote is set when events could not be read: they are unknown, not none.
	EventsNote string `json:"eventsNote,omitempty"`
}

func registerDescribe(s *server.Server) {
	server.Register(s, &mcp.Tool{
		Name: "describe_resource",
		Description: "Describe one object like kubectl describe: {object, conditions, events}. object keeps " +
			"only apiVersion, kind, metadata, spec and status (so top-level fields such as ConfigMap data or " +
			"Role rules are not shown; use get_resource for them): metadata (name, namespace, labels, annotations without last-applied-configuration, " +
			"ownerReferences, creationTimestamp, deletionTimestamp), spec and status, with credential-looking " +
			"values masked as in get_resource. conditions are status.conditions as {type, status, reason, " +
			"message, lastTransitionTime} (at most 200). events are the events about this object, oldest first " +
			"(newest last), warning=true on warnings, at most the 50 newest (eventsTruncated=true when more). " +
			"If events cannot be read the object is still returned with eventsNote set. Secrets are refused. Read-only: never creates, changes or deletes anything.",
	}, server.CapRead, describeResource)
}

func describeResource(ctx context.Context, f kube.Factory, in objectIn) (any, error) {
	o, err := readObject(ctx, f, in)
	if err != nil {
		return nil, err
	}
	out := describeOut{Object: trimObject(o.obj), Conditions: conditions(o.obj), Events: []eventOut{}}

	ref := &kube.ObjectRef{
		Kind:      o.res.Kind,
		Namespace: o.ns,
		Name:      str(o.obj, "metadata", "name"),
		UID:       str(o.obj, "metadata", "uid"),
	}
	// The kubelet records Node events with involvedObject.uid set to the
	// node name, not its UID (kubectl's node describer works around it the
	// same way): match nodes by kind and name only.
	if o.res.Group == "" && o.res.Kind == "Node" {
		ref.UID = ""
	}
	evs, err := o.client.Events(ctx, o.ns, ref, 0)
	switch {
	case err == nil:
	case ctx.Err() != nil:
		return nil, err
	case errors.Is(err, kube.ErrForbidden), errors.Is(err, kube.ErrTimeout), errors.Is(err, kube.ErrUnreachable):
		out.EventsNote = "cannot read events: " + errClass(err)
		return out, nil
	default:
		return nil, err
	}
	if len(evs) > describeMaxEvents {
		evs = evs[len(evs)-describeMaxEvents:]
		out.EventsTruncated = true
	}
	for _, ev := range evs {
		out.Events = append(out.Events, toEvent(ev))
	}
	return out, nil
}

// trimObject keeps the describe-worthy parts of an already redacted object.
func trimObject(obj map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range []string{"apiVersion", "kind", "spec", "status"} {
		if v, ok := obj[k]; ok {
			out[k] = v
		}
	}
	md := asMap(obj["metadata"])
	tmd := map[string]any{}
	for _, k := range []string{"name", "namespace", "labels", "ownerReferences", "creationTimestamp", "deletionTimestamp"} {
		if v, ok := md[k]; ok {
			tmd[k] = v
		}
	}
	if ann := asMap(md["annotations"]); len(ann) > 0 {
		kept := map[string]any{}
		for k, v := range ann {
			if k != redact.LastAppliedAnnotation { // duplicates the spec; dropped
				kept[k] = v
			}
		}
		if len(kept) > 0 {
			tmd["annotations"] = kept
		}
	}
	out["metadata"] = tmd
	return out
}

// conditions normalises status.conditions, capped at MaxItems.
func conditions(obj map[string]any) []conditionOut {
	out := []conditionOut{}
	for _, c := range list(obj, "status", "conditions") {
		if len(out) == limits.Default().MaxItems {
			break
		}
		m := asMap(c)
		if m == nil {
			continue
		}
		out = append(out, conditionOut{
			Type:               str(m, "type"),
			Status:             str(m, "status"),
			Reason:             str(m, "reason"),
			Message:            str(m, "message"),
			LastTransitionTime: str(m, "lastTransitionTime"),
		})
	}
	return out
}

// Package flux summarises Flux CD custom resources (Kustomization,
// HelmRelease, GitRepository, ...) into a small, secret-free Status.
//
// It is pure: map[string]any trees in, Status out, no Kubernetes imports.
// Only the fields of Status are ever read from an object; spec contents
// (values, secretRef, ...) are never copied. Cluster-sourced strings are NOT
// sanitised here (the server's result wrapper does that), but Message is
// scrubbed of URL credentials and credential-looking tokens because Flux
// echoes git and registry URLs in its errors.
package flux

import (
	"net/url"
	"regexp"

	"github.com/astawiany/k8s-mcp/internal/redact"
)

// Status is the health of one Flux object.
type Status struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	// Ready is true only when the Ready condition has status True.
	Ready   bool   `json:"ready"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
	// Revision precedence: status.lastAppliedRevision, else
	// status.artifact.revision, else status.lastAttemptedRevision.
	Revision  string `json:"revision,omitempty"`
	Suspended bool   `json:"suspended"`
	// Stalled is true when the Stalled condition has status True.
	Stalled bool `json:"stalled"`
	// DependsOn lists spec.dependsOn names, "namespace/name" when the entry
	// sets a namespace, plain "name" otherwise (same namespace as the object).
	DependsOn []string `json:"dependsOn,omitempty"`
}

// Summarize reads the health fields of a Flux object. Missing or oddly typed
// fields yield zero values; it never panics.
func Summarize(obj map[string]any) Status {
	s := Status{
		Kind:      str(obj, "kind"),
		Namespace: str(obj, "metadata", "namespace"),
		Name:      str(obj, "metadata", "name"),
	}
	if ready := condition(obj, "Ready"); ready != nil {
		s.Ready = ready["status"] == "True"
		s.Reason, _ = ready["reason"].(string)
		msg, _ := ready["message"].(string)
		s.Message = ScrubMessage(msg)
	}
	if st := condition(obj, "Stalled"); st != nil {
		s.Stalled = st["status"] == "True"
	}
	for _, p := range [][]string{
		{"status", "lastAppliedRevision"},
		{"status", "artifact", "revision"},
		{"status", "lastAttemptedRevision"},
	} {
		if r := str(obj, p...); r != "" {
			s.Revision = r
			break
		}
	}
	s.Suspended = get(obj, "spec", "suspend") == true
	if deps, ok := get(obj, "spec", "dependsOn").([]any); ok {
		for _, d := range deps {
			m, _ := d.(map[string]any)
			name := str(m, "name")
			if name == "" {
				continue
			}
			if ns := str(m, "namespace"); ns != "" {
				name = ns + "/" + name
			}
			s.DependsOn = append(s.DependsOn, name)
		}
	}
	return s
}

// userinfo matches scheme://...@ up to the LAST "@" before the first "/" (or
// the end), so passwords containing "@" are covered.
var userinfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://)[^\s/]*@`)

// param matches a query or fragment parameter name=value.
var param = regexp.MustCompile(`([?&#])([^=&#\s"'<>]+)=([^&#\s"'<>]+)`)

var credName = regexp.MustCompile(`(?i)^(token|access_token|refresh_token|id_token|auth|authorization|password|passwd|pwd|secret|client_secret|api[_-]?key|apikey|key|sig|signature|code|credential)$`)

// ScrubURLs replaces URL credentials in s: the userinfo
// (https://user:pass@host becomes https://[redacted]@host) and the values of
// query or fragment parameters whose (URL-decoded) name looks like a
// credential (?token=abc becomes ?token=[redacted]). Other parameters are
// left alone.
func ScrubURLs(s string) string {
	s = userinfo.ReplaceAllString(s, "${1}"+redact.Redacted+"@")
	return param.ReplaceAllStringFunc(s, func(m string) string {
		sub := param.FindStringSubmatch(m)
		name, err := url.QueryUnescape(sub[2])
		if err != nil {
			name = sub[2]
		}
		if !credName.MatchString(name) {
			return m
		}
		return sub[1] + sub[2] + "=" + redact.Redacted
	})
}

// ScrubMessage removes URL credentials from a Flux message, then redacts the
// whole message if it still contains a token shape (see redact.EnvValue).
func ScrubMessage(s string) string {
	return redact.EnvValue("", ScrubURLs(s))
}

func get(obj map[string]any, path ...string) any {
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

func str(obj map[string]any, path ...string) string {
	s, _ := get(obj, path...).(string)
	return s
}

func condition(obj map[string]any, t string) map[string]any {
	conds, _ := get(obj, "status", "conditions").([]any)
	for _, c := range conds {
		if m, ok := c.(map[string]any); ok && m["type"] == t {
			return m
		}
	}
	return nil
}

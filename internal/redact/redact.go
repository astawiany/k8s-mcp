// Package redact blocks Secret data and scrubs credential-looking values from
// Kubernetes objects before they are returned to an MCP client (and so to an
// AI model). It is defense in depth: RBAC without access to `secrets` is the
// primary control.
//
// Objects are the map[string]any / []any trees produced by the dynamic client
// or by encoding/json. The package has no Kubernetes imports and every
// function is pure: inputs are never modified, results are deep copies.
//
// Exported API:
//
//	Redacted                    the replacement string, "[redacted]".
//	IsSecretKind(group, kind)   true for the core Secret kind or resource name
//	                            ("Secret", "secrets", "SecretList"; any case;
//	                            group "", "core" or "v1"). Callers use it to
//	                            refuse Secret requests outright.
//	Object(obj)                 deep copy with, anywhere in the tree:
//	                            - metadata.managedFields removed;
//	                            - every map whose kind is Secret (any case, any
//	                              apiVersion), and every item of a SecretList,
//	                              reduced to apiVersion, kind, metadata, type
//	                              and immutable; all other fields (data,
//	                              stringData, ...) keep their keys but every
//	                              value becomes Redacted;
//	                            - the kubectl.kubernetes.io/last-applied-
//	                              configuration annotation parsed and scrubbed
//	                              with the Workload rules (embedded Secrets and
//	                              env values), or replaced by Redacted if it is
//	                              not a JSON object or array;
//	                            - any other annotation holding a JSON object or
//	                              array scrubbed the same way when the scrub
//	                              changes something (otherwise left verbatim).
//	EnvValue(name, value)       value, or Redacted when the name looks like a
//	                            credential (pass, secret, token, key,
//	                            credential, auth, cert, private; any case) or
//	                            the value, raw or base64-decoded, contains a
//	                            token shape: JWT, GitHub token (ghp_, gho_,
//	                            ghu_, ghs_, ghr_, github_pat_), AWS access key
//	                            id (AKIA/ASIA), PEM private key, or a URL with
//	                            embedded user:password. Empty values stay empty.
//	PodSpec(spec)               deep copy of a pod spec with EnvValue applied to
//	                            every env[].value of containers, initContainers
//	                            and ephemeralContainers; valueFrom is kept.
//	Workload(obj)               Object plus PodSpec on spec (Pod), template.spec
//	                            (PodTemplate), spec.template.spec (Deployment,
//	                            StatefulSet, DaemonSet, ReplicaSet, Job, ...)
//	                            and spec.jobTemplate.spec.template.spec
//	                            (CronJob), matched by shape not kind, and on
//	                            every element of items (lists). Use it for any
//	                            object returned to a client.
//
// Not covered (documented limits): credentials in container args or command,
// in ConfigMap data, or in annotations that are not JSON.
package redact

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

// Redacted replaces every hidden value.
const Redacted = "[redacted]"

const lastAppliedAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

// IsSecretKind reports whether group/kind names the core Secret kind, its
// plural resource name or its list kind.
func IsSecretKind(group, kind string) bool {
	switch strings.ToLower(strings.TrimSpace(group)) {
	case "", "core", "v1":
	default:
		return false
	}
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "secret", "secrets", "secretlist":
		return true
	}
	return false
}

// Object returns a scrubbed deep copy of obj (see the package comment).
func Object(obj map[string]any) map[string]any {
	if obj == nil {
		return nil
	}
	c := deepCopy(obj).(map[string]any)
	scrubTree(c, false)
	return c
}

// Workload returns Object(obj) with PodSpec applied to every embedded pod
// spec (see the package comment).
func Workload(obj map[string]any) map[string]any {
	if obj == nil {
		return nil
	}
	c := Object(obj)
	maskWorkload(c)
	return c
}

// PodSpec returns a deep copy of spec with credential-looking env values
// masked.
func PodSpec(spec map[string]any) map[string]any {
	if spec == nil {
		return nil
	}
	c := deepCopy(spec).(map[string]any)
	maskPodSpec(c)
	return c
}

var (
	credName = regexp.MustCompile(`(?i)(pass(word)?|secret|token|key|credential|auth|cert|private)`)
	tokenRes = []*regexp.Regexp{
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`), // JWT
		regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),                              // GitHub
		regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),                            // GitHub fine-grained
		regexp.MustCompile(`(AKIA|ASIA)[0-9A-Z]{16}`),                                 // AWS key id
		regexp.MustCompile(`(?i)-----BEGIN[A-Z0-9 ]*PRIVATE KEY-----`),                // PEM
		regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@`),           // URL credentials
	}
	b64Encodings = []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	}
	whitespace = strings.NewReplacer(" ", "", "\n", "", "\r", "", "\t", "")
)

// EnvValue returns value, or Redacted when name or value looks like a
// credential (see the package comment).
func EnvValue(name, value string) string {
	if value == "" {
		return value
	}
	if credName.MatchString(name) || hasToken(value) {
		return Redacted
	}
	if compact := whitespace.Replace(value); len(compact) >= 16 {
		for _, enc := range b64Encodings {
			if dec, err := enc.DecodeString(compact); err == nil {
				if hasToken(string(dec)) {
					return Redacted
				}
				break
			}
		}
	}
	return value
}

func hasToken(s string) bool {
	for _, re := range tokenRes {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// secretKeep lists the fields of a Secret that are returned verbatim.
var secretKeep = map[string]bool{
	"apiversion": true, "kind": true, "metadata": true, "type": true, "immutable": true,
}

// scrubTree scrubs v in place. asSecret marks a map known to be a Secret even
// without a kind field (an item of a SecretList).
func scrubTree(v any, asSecret bool) {
	switch t := v.(type) {
	case map[string]any:
		kind := strings.ToLower(strings.TrimSpace(fmt.Sprint(lookup(t, "kind"))))
		if asSecret || kind == "secret" {
			for k, val := range t {
				if !secretKeep[strings.ToLower(k)] {
					t[k] = redactValue(val)
				}
			}
		}
		for k, val := range t {
			switch strings.ToLower(k) {
			case "metadata":
				if md, ok := val.(map[string]any); ok {
					scrubMetadata(md)
				}
			case "items":
				if kind == "secretlist" {
					if items, ok := val.([]any); ok {
						for _, it := range items {
							scrubTree(it, true)
						}
						continue
					}
				}
			}
			scrubTree(val, false)
		}
	case []any:
		for _, e := range t {
			scrubTree(e, false)
		}
	}
}

// redactValue keeps map keys and replaces every other value with Redacted.
func redactValue(v any) any {
	if m, ok := v.(map[string]any); ok {
		out := make(map[string]any, len(m))
		for k := range m {
			out[k] = Redacted
		}
		return out
	}
	return Redacted
}

func scrubMetadata(md map[string]any) {
	for k := range md {
		if strings.EqualFold(k, "managedFields") {
			delete(md, k)
		}
	}
	for k, val := range md {
		if !strings.EqualFold(k, "annotations") {
			continue
		}
		ann, ok := val.(map[string]any)
		if !ok {
			continue
		}
		for ak, av := range ann {
			if strings.EqualFold(ak, lastAppliedAnnotation) {
				ann[ak] = scrubJSONString(av, true)
			} else {
				ann[ak] = scrubJSONString(av, false)
			}
		}
	}
}

// scrubJSONString scrubs an annotation value that holds a JSON object or
// array. With strict set, anything that cannot be scrubbed is replaced by
// Redacted; otherwise it is returned unchanged.
func scrubJSONString(v any, strict bool) any {
	s, ok := v.(string)
	if !ok {
		if strict {
			return Redacted
		}
		return v
	}
	trimmed := strings.TrimSpace(s)
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
		if strict && trimmed != "" {
			return Redacted
		}
		return v
	}
	var parsed any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		if strict {
			return Redacted
		}
		return v
	}
	orig := deepCopy(parsed)
	scrubTree(parsed, false)
	maskWorkloadAny(parsed)
	if !strict && reflect.DeepEqual(orig, parsed) {
		return v
	}
	b, err := json.Marshal(parsed)
	if err != nil {
		return Redacted
	}
	return string(b)
}

// podSpecPaths are the locations of pod specs in workload objects.
var podSpecPaths = [][]string{
	{"spec"},
	{"template", "spec"},
	{"spec", "template", "spec"},
	{"spec", "jobTemplate", "spec", "template", "spec"},
}

func maskWorkloadAny(v any) {
	switch t := v.(type) {
	case map[string]any:
		maskWorkload(t)
	case []any:
		for _, e := range t {
			maskWorkloadAny(e)
		}
	}
}

func maskWorkload(m map[string]any) {
	for _, p := range podSpecPaths {
		var cur any = m
		for _, k := range p {
			mm, ok := cur.(map[string]any)
			if !ok {
				cur = nil
				break
			}
			cur = lookup(mm, k)
		}
		if spec, ok := cur.(map[string]any); ok {
			maskPodSpec(spec)
		}
	}
	if items, ok := lookup(m, "items").([]any); ok {
		maskWorkloadAny(items)
	}
}

func maskPodSpec(spec map[string]any) {
	for k, cs := range spec {
		switch strings.ToLower(k) {
		case "containers", "initcontainers", "ephemeralcontainers":
		default:
			continue
		}
		list, ok := cs.([]any)
		if !ok {
			continue
		}
		for _, c := range list {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			env, ok := lookup(cm, "env").([]any)
			if !ok {
				continue
			}
			for _, e := range env {
				em, ok := e.(map[string]any)
				if !ok {
					continue
				}
				name := fmt.Sprint(lookup(em, "name"))
				for ek, ev := range em {
					if !strings.EqualFold(ek, "value") || ev == nil {
						continue
					}
					sv, isStr := ev.(string)
					if !isStr {
						sv = fmt.Sprint(ev)
					}
					if masked := EnvValue(name, sv); masked != sv {
						em[ek] = masked
					}
				}
			}
		}
	}
}

// lookup returns m[key], falling back to a case-insensitive match so that
// case variants of field names cannot bypass the scrub.
func lookup(m map[string]any, key string) any {
	if v, ok := m[key]; ok {
		return v
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return nil
}

// deepCopy copies the container types found in decoded JSON / unstructured
// objects. Other values are immutable scalars and are returned as is.
func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = deepCopy(e)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = deepCopy(e)
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = e
		}
		return out
	case []string:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = e
		}
		return out
	case []map[string]any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = deepCopy(e)
		}
		return out
	}
	return v
}

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
//	                            id (AKIA/ASIA), PEM private key, Slack token
//	                            (xox[abprs]-), Google API key (AIza...), Stripe
//	                            live key (sk_live_/rk_live_), or a URL with
//	                            embedded [user]:password@. Empty values stay
//	                            empty.
//	PodSpec(spec)               deep copy of a pod spec where, for every entry
//	                            of containers, initContainers and
//	                            ephemeralContainers:
//	                            - EnvValue is applied to every env[].value
//	                              (valueFrom is kept);
//	                            - httpGet.httpHeaders values of livenessProbe,
//	                              readinessProbe, startupProbe and lifecycle
//	                              postStart/preStop are masked when the header
//	                              name is Authorization, Proxy-Authorization,
//	                              Cookie, X-Api-Key, X-Auth-Token or matches
//	                              the credential-name pattern (or EnvValue
//	                              masks it); names are kept;
//	                            - in command and args, the value of
//	                              --name=value / -name=value with a
//	                              credential-looking name (also inside a
//	                              single "sh -c ..." string) becomes Redacted,
//	                              an element that is only such a flag masks the
//	                              following element unless that starts with
//	                              "-", and an element with a token shape is
//	                              masked whole.
//	Workload(obj)               Object plus PodSpec on spec (Pod), template.spec
//	                            (PodTemplate), spec.template.spec (Deployment,
//	                            StatefulSet, DaemonSet, ReplicaSet, Job, ...)
//	                            and spec.jobTemplate.spec.template.spec
//	                            (CronJob), matched by shape not kind, and on
//	                            every element of items (lists). Use it for any
//	                            object returned to a client.
//
// A Secret's metadata keeps name, namespace, labels, ownerReferences,
// timestamps, resourceVersion and uid, but every annotation value becomes
// Redacted (keys kept).
//
// Not covered (documented limits): other credential forms in command/args
// (for example "--password value" inside one shell string), credentials in
// ConfigMap data, and in annotations that are not JSON.
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
		regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]*:[^/\s@]+@`),           // URL credentials (user may be empty)
		regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`),                            // Slack
		regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),                                   // Google API key
		regexp.MustCompile(`[sr]k_live_[0-9A-Za-z]{10,}`),                             // Stripe live key
	}
	// credHeader lists HTTP header names whose values are always masked, in
	// addition to names matching credName.
	credHeader = map[string]bool{
		"authorization": true, "proxy-authorization": true, "cookie": true,
		"x-api-key": true, "x-auth-token": true,
	}
	// flagAssign matches -name=value / --name=value at the start of an
	// argument or after whitespace (inline in an "sh -c" string).
	flagAssign = regexp.MustCompile(`(^|\s)(--?[A-Za-z0-9][A-Za-z0-9_.-]*)=([^\s'"]+)`)
	// bareFlag matches an argument that is only a flag name.
	bareFlag     = regexp.MustCompile(`^--?[A-Za-z0-9][A-Za-z0-9_.-]*$`)
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
					continue
				}
				if md, ok := val.(map[string]any); ok && strings.EqualFold(k, "metadata") {
					for mk, mv := range md {
						if strings.EqualFold(mk, "annotations") {
							md[mk] = redactValue(mv)
						}
					}
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
			if cm, ok := c.(map[string]any); ok {
				maskContainer(cm)
			}
		}
	}
}

// httpHandlerPaths are the container fields that may hold an httpGet action.
var httpHandlerPaths = [][]string{
	{"livenessProbe"}, {"readinessProbe"}, {"startupProbe"},
	{"lifecycle", "postStart"}, {"lifecycle", "preStop"},
}

func maskContainer(c map[string]any) {
	if env, ok := lookup(c, "env").([]any); ok {
		maskNameValues(env, EnvValue)
	}
	for _, p := range httpHandlerPaths {
		var cur any = c
		for _, k := range append(append([]string{}, p...), "httpGet", "httpHeaders") {
			mm, ok := cur.(map[string]any)
			if !ok {
				cur = nil
				break
			}
			cur = lookup(mm, k)
		}
		if hdrs, ok := cur.([]any); ok {
			maskNameValues(hdrs, headerValue)
		}
	}
	for k, v := range c {
		switch strings.ToLower(k) {
		case "command", "args":
			if l, ok := v.([]any); ok {
				maskArgs(l)
			}
		}
	}
}

// headerValue masks an HTTP header value by header name or value shape.
func headerValue(name, value string) string {
	if value != "" && credHeader[strings.ToLower(strings.TrimSpace(name))] {
		return Redacted
	}
	return EnvValue(name, value)
}

// maskNameValues applies mask to the value of every {name, value} entry,
// keeping names and any other field (such as valueFrom).
func maskNameValues(list []any, mask func(name, value string) string) {
	for _, e := range list {
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
			if masked := mask(name, sv); masked != sv {
				em[ek] = masked
			}
		}
	}
}

// maskArgs masks credential values in a command or args list in place.
func maskArgs(l []any) {
	maskNext := false
	for i, a := range l {
		s, ok := a.(string)
		if !ok {
			continue
		}
		if maskNext {
			maskNext = false
			if !strings.HasPrefix(s, "-") {
				l[i] = Redacted
				continue
			}
		}
		if hasToken(s) {
			l[i] = Redacted
			continue
		}
		if bareFlag.MatchString(s) {
			maskNext = credName.MatchString(s)
			continue
		}
		l[i] = flagAssign.ReplaceAllStringFunc(s, func(m string) string {
			sub := flagAssign.FindStringSubmatch(m)
			if !credName.MatchString(sub[2]) {
				return m
			}
			return sub[1] + sub[2] + "=" + Redacted
		})
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

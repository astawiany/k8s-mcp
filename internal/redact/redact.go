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
//	MaskPrivateKeyBlocks(s)     s with every private key block (BEGIN
//	                            through END, or to the end; RSA, EC, DSA,
//	                            OPENSSH, ENCRYPTED, PGP ... BLOCK; 4 or 5
//	                            dashes; any case) replaced by Redacted.
//	                            PrivateKeyBeginRE/EndRE/BlockRE are the
//	                            shared patterns (logs use them per line).
//
//	LooksLikeSecretManifest(s)  true when s, JSON-unescaped at any depth,
//	                            ignoring case and with control, format and
//	                            ANSI characters removed, contains "secret",
//	                            "kind" and one of "\"data\"", "data:" or
//	                            "stringdata" (the last two not preceded by a
//	                            letter, digit, "_", "-" or ".", so not
//	                            "metadata:"). Broad on purpose: callers
//	                            replace the whole string with
//	                            RedactedSecretManifest. It sees one string at
//	                            a time, so multi-line text such as a pod log
//	                            must be passed as ONE string, never as a list
//	                            of lines.
//
// Annotation values (any key) that are not a parseable JSON object or array
// but LooksLikeSecretManifest are replaced whole by RedactedSecretManifest
// (fail closed: a cut, prefixed or YAML Secret cannot be scrubbed field by
// field); so is any string inside a parseable JSON annotation that
// LooksLikeSecretManifest (a manifest held as escaped JSON or YAML text).
// Field names and kind values are compared with control and format
// characters removed ("ki\u200bnd": "Sec\u200bret" is a Secret), but only
// where a match makes the scrub stricter: the Secret fields that are kept
// (apiVersion, kind, metadata, type, immutable) must match exactly.
//
// A Secret's metadata keeps name, namespace, labels, ownerReferences,
// timestamps, resourceVersion and uid, but every annotation value becomes
// Redacted (keys kept).
//
// Not covered (documented limits):
//   - other credential forms in command/args (for example "--password value"
//     inside one shell string) and credentials in ConfigMap data that are not
//     a Secret manifest;
//   - Secret manifests that are base64- or gzip-encoded (for example Helm
//     release storage in a ConfigMap or Secret, or Tiller ConfigMaps);
//   - a manifest split across separate strings or list items (callers must
//     return multi-line text such as pod logs as one string) and lines
//     without their context (a "password: x" line with no kind and no
//     "data:" in the same string);
//   - registry credentials (.dockerconfigjson "auths"/"auth") or other
//     credentials in ConfigMap or annotation JSON that do not contain the
//     words above, unless EnvValue's token shapes match;
//   - YAML "data :" (space before the colon), a single-quoted 'data' key,
//     HTML-entity escaping (&quot;data&quot;), and look-alike letters such
//     as fullwidth forms (U+FF41 to U+FF5A) of "secret", "kind" or "data".
//
// False positives (whole string hidden though it holds no Secret): any one
// string with "secret" and "kind" anywhere (including "secretName",
// "secretKeyRef", "kindly") plus a JSON "data" key, a "data:" key or
// "stringData" as above. Examples: a multi-document YAML or Helm template
// with a ConfigMap and a Deployment that mounts a Secret; a structured log
// line with a "data" field that mentions a Secret and a kind.
package redact

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/astawiany/k8s-mcp/internal/untrusted"
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
		PrivateKeyBeginRE, // PEM/PGP private key (privatekey.go)
		PrivateKeyEndRE,
		regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]*:[^/\s@]+@`), // URL credentials (user may be empty)
		regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`),                  // Slack
		regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),                         // Google API key
		regexp.MustCompile(`[sr]k_live_[0-9A-Za-z]{10,}`),                   // Stripe live key
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
		kind := normKey(fmt.Sprint(lookup(t, "kind")))
		if asSecret || kind == "secret" {
			for k, val := range t {
				if !secretKeep[strings.ToLower(k)] {
					t[k] = redactValue(val)
					continue
				}
				if md, ok := val.(map[string]any); ok && strings.EqualFold(k, "metadata") {
					for mk, mv := range md {
						if normKey(mk) == "annotations" {
							md[mk] = redactValue(mv)
						}
					}
				}
			}
		}
		for k, val := range t {
			switch normKey(k) {
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
		if normKey(k) == "managedfields" {
			delete(md, k)
		}
	}
	for k, val := range md {
		if normKey(k) != "annotations" {
			continue
		}
		ann, ok := val.(map[string]any)
		if !ok {
			continue
		}
		for ak, av := range ann {
			if normKey(ak) == lastAppliedAnnotation {
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
		return unparsable(s)
	}
	var parsed any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		if strict {
			return Redacted
		}
		return unparsable(s)
	}
	orig := deepCopy(parsed)
	scrubTree(parsed, false)
	maskWorkloadAny(parsed)
	parsed = failClosedStrings(parsed)
	if !strict && reflect.DeepEqual(orig, parsed) {
		return v
	}
	b, err := json.Marshal(parsed)
	if err != nil {
		return Redacted
	}
	return string(b)
}

// failClosedStrings replaces, in a parsed annotation, every string value
// that LooksLikeSecretManifest with RedactedSecretManifest: a manifest held
// as text inside the JSON (escaped JSON, YAML) is not a Secret map, so
// scrubTree does not see it.
func failClosedStrings(v any) any {
	switch t := v.(type) {
	case string:
		if LooksLikeSecretManifest(t) {
			return RedactedSecretManifest
		}
	case map[string]any:
		for k, e := range t {
			t[k] = failClosedStrings(e)
		}
	case []any:
		for i, e := range t {
			t[i] = failClosedStrings(e)
		}
	}
	return v
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
		switch normKey(k) {
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
		switch normKey(k) {
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
			if normKey(ek) != "value" || ev == nil {
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
		if normKey(k) == strings.ToLower(key) {
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

// RedactedSecretManifest replaces, whole, a string that looks like a Secret
// manifest but cannot be scrubbed field by field.
const RedactedSecretManifest = "[redacted: embedded Secret manifest]"

// unparsable handles an annotation value that is not a JSON object or
// array: fail closed if it looks like a Secret manifest, else keep it.
func unparsable(s string) any {
	if LooksLikeSecretManifest(s) {
		return RedactedSecretManifest
	}
	return s
}

// LooksLikeSecretManifest reports whether s may hold a Secret manifest (JSON
// or YAML, whole or cut). s is first unescaped: JSON escapes, at any depth of
// escaping (a run of backslashes counts as one), are decoded, so that a
// manifest inside a JSON string inside a log line is seen. The result is
// then checked twice, raw and after untrusted.Sanitize (what a client sees),
// each time lower-cased with line breaks kept and other control and format
// characters removed. It is true when one of them contains "secret", "kind"
// and one of: "\"data\"", "data:" or "stringdata" with neither a letter,
// digit, "_", "-" nor "." just before it (so "metadata:" does not count).
// It is deliberately broad (fail closed): callers replace such a string
// whole. Time is linear in len(s).
//
// It sees one string at a time: a manifest split across separate strings
// (for example a log returned as a list of lines) is not found, so callers
// must pass multi-line text such as pod logs as one string.
func LooksLikeSecretManifest(s string) bool {
	d := unescapeJSON(s)
	if manifestWords(normManifest(d)) {
		return true
	}
	// ANSI sequences: "Sec\x1b[0mret" reads "Secret" once sanitised.
	if strings.IndexFunc(d, func(r rune) bool { return r == 0x1b || (r >= 0x80 && r <= 0x9f) }) >= 0 {
		return manifestWords(normManifest(untrusted.Sanitize(d)))
	}
	return false
}

func manifestWords(n string) bool {
	return strings.Contains(n, "secret") && strings.Contains(n, "kind") &&
		(strings.Contains(n, `"data"`) || hasWord(n, "data:") || hasWord(n, "stringdata"))
}

// hasWord reports whether w occurs in n with no word character just before
// it.
func hasWord(n, w string) bool {
	for off := 0; ; {
		i := strings.Index(n[off:], w)
		if i < 0 {
			return false
		}
		i += off
		r, _ := utf8.DecodeLastRuneInString(n[:i])
		if i == 0 || !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.') {
			return true
		}
		off = i + 1
	}
}

// invisibleRune reports control and format characters, which can hide or
// split a word without being seen.
func invisibleRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
}

// normKey normalises a field name or kind value for comparison: control and
// format characters removed, spaces trimmed, lower case. Used only where a
// match makes the scrub stricter, never to keep a field.
func normKey(s string) string {
	if strings.IndexFunc(s, invisibleRune) >= 0 {
		s = strings.Map(func(r rune) rune {
			if invisibleRune(r) {
				return -1
			}
			return r
		}, s)
	}
	return strings.ToLower(strings.TrimSpace(s))
}

// normManifest lower-cases s, turns line breaks into "\n" and tabs into
// spaces, and drops every other control or format character.
func normManifest(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\v', '\f', 0x85, 0x2028, 0x2029:
			return '\n'
		case '\t':
			return ' '
		}
		if invisibleRune(r) {
			return -1
		}
		return unicode.ToLower(r)
	}, s)
}

// unescapeJSON decodes JSON string escapes in s for matching only. A run of
// backslashes is one escape, so text escaped several times decodes in one
// pass: \uXXXX (and surrogate pairs) become the rune, n and r a line break,
// t a tab, b and f are dropped, and before any other character (such as a
// quote) the backslashes are dropped.
func unescapeJSON(s string) string {
	if strings.IndexByte(s, '\\') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := skipBackslashes(s, i)
		if j == len(s) {
			break
		}
		if r, end := hexEscape(s, j); end > 0 {
			b.WriteRune(r)
			i = end
			continue
		}
		switch s[j] {
		case 'n', 'r':
			b.WriteByte('\n')
			j++
		case 't':
			b.WriteByte('\t')
			j++
		case 'b', 'f':
			j++
		}
		i = j
	}
	return b.String()
}

func skipBackslashes(s string, i int) int {
	for i < len(s) && s[i] == '\\' {
		i++
	}
	return i
}

// hexEscape decodes uXXXX at s[j:] (the backslashes already skipped), with a
// following low surrogate escape if r is a high surrogate. It returns the
// rune and the index after the escape, or end == 0.
func hexEscape(s string, j int) (r rune, end int) {
	hex4 := func(j int) (rune, bool) {
		if j+5 > len(s) || s[j] != 'u' {
			return 0, false
		}
		v, err := strconv.ParseUint(s[j+1:j+5], 16, 32)
		return rune(v), err == nil
	}
	r1, ok := hex4(j)
	if !ok {
		return 0, 0
	}
	if utf16.IsSurrogate(r1) {
		if k := skipBackslashes(s, j+5); k > j+5 {
			if r2, ok := hex4(k); ok {
				if d := utf16.DecodeRune(r1, r2); d != utf8.RuneError {
					return d, k + 5
				}
			}
		}
	}
	return r1, j + 5
}

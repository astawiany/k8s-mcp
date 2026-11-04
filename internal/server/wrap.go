package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/limits"
	"github.com/astawiany/k8s-mcp/internal/redact"
	"github.com/astawiany/k8s-mcp/internal/untrusted"
)

// lim are the output limits of every result (limits.Default; there is no
// option to change them).
var lim = limits.Default()

// envelopeOverhead is the size of the envelope around the body:
// "<<<DATA " + 32 + ">>>\n" and "\n<<<END " + 32 + ">>>".
const envelopeOverhead = len("<<<DATA ") + 32 + len(">>>\n") + len("\n<<<END ") + 32 + len(">>>")

// narrowHint is the hint of the whole-document truncation note.
const narrowHint = "a namespace, label or field selector, a smaller limit (then the continue token), or a shorter time range or tail"

// call runs one tool handler and turns whatever it returns, value, error or
// panic, into the tool result. It is the only path from a handler to a
// client.
func call(ctx context.Context, name string, h func(context.Context) (any, error)) (res *mcp.CallToolResult) {
	defer func() {
		if r := recover(); r != nil {
			res = errorResult(fmt.Errorf("internal error in tool %s: %v", name, r))
		}
	}()
	v, err := h(ctx)
	if err != nil {
		return errorResult(err)
	}
	return wrapResult(v)
}

// wrapResult is the success path of the result wrapper (see the package
// comment for the steps).
func wrapResult(v any) *mcp.CallToolResult {
	raw, err := json.Marshal(v)
	if err != nil {
		return errorResult(fmt.Errorf("internal error: the tool result cannot be encoded as JSON: %w", err))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return errorResult(fmt.Errorf("internal error: the tool result cannot be decoded: %w", err))
	}

	// Sanitize every string and key first, without the size cut, so that
	// invisible characters cannot hide a Secret kind or an annotations key,
	// nor break the JSON of an annotation, from the first backstop pass.
	tree = mapTree(tree, sanitizeString)
	// Backstop, first pass: embedded Secrets in annotations are only found
	// while their JSON still parses, i.e. before any cut.
	tree = backstop(tree)
	tree = mapTree(tree, capString)
	// Second pass, on the final strings.
	tree = backstop(tree)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(tree); err != nil {
		return errorResult(fmt.Errorf("internal error: the tool result cannot be encoded: %w", err))
	}
	boundary := untrusted.NewBoundary()
	doc := capDocument(boundary, strings.TrimSuffix(buf.String(), "\n"))
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: untrusted.Wrap(boundary, doc)}}}
}

// backstop applies redact.Object to any tree. redact.Object only accepts a
// map root; a holder map with no kind lets it scrub any root (a list, a
// scalar) at every depth.
func backstop(tree any) any {
	return redact.Object(map[string]any{"v": tree})["v"]
}

// preCut bounds the text Sanitize sees per string. Sanitize is linear, so
// this is only a guard against absurd inputs; it is far above the per-string
// cap applied later, and equals the default log read limit.
const preCut = 4 << 20

// mapTree returns v with f applied to every string and map key. Keys that
// become equal after f get a " (n)" suffix so no value is lost or
// overwritten; keys are visited in sorted order so the suffixes are the same
// on every call.
func mapTree(v any, f func(string) string) any {
	switch t := v.(type) {
	case string:
		return f(t)
	case []any:
		for i, e := range t {
			t[i] = mapTree(e, f)
		}
		return t
	case map[string]any:
		out := make(map[string]any, len(t))
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			e := t[k]
			base := f(k)
			ck := base
			for n := 2; ; n++ {
				if _, taken := out[ck]; !taken {
					break
				}
				ck = fmt.Sprintf("%s (%d)", base, n)
			}
			out[ck] = mapTree(e, f)
		}
		return out
	}
	return v // json.Number, bool, nil
}

// sanitizeString is the first string pass: token-shape redaction of the raw
// string, a guard cut at preCut, untrusted.Sanitize, and token-shape
// redaction again (tokens hidden by invisible characters only match after
// Sanitize). Both token checks see the whole string, before the per-string
// cap, so a token split by a later cut still hides the value.
func sanitizeString(str string) string {
	if str == "" {
		return str
	}
	if redact.EnvValue("", str) == redact.Redacted {
		return redact.Redacted
	}
	if len(str) > preCut {
		str, _ = limits.TruncateText(str, limits.Limits{MaxBytes: preCut})
	}
	return redact.EnvValue("", untrusted.Sanitize(str))
}

// capString is the second string pass: the per-string limits
// (limits.Default: line length, lines, bytes) and a final token check.
func capString(str string) string {
	str, _ = limits.TruncateText(str, lim)
	return redact.EnvValue("", str)
}

// capDocument cuts doc so that the escaped body plus the envelope fits
// MaxBytes, ending it with a limits.Note. Escaping can grow the text ("<<<"
// becomes "<<‹"), so the budget is measured after untrusted.Escape (which
// Wrap applies again with the same result: Escape is idempotent).
func capDocument(boundary, doc string) string {
	max := lim.MaxBytes
	if max <= 0 || len(untrusted.Escape(boundary, doc))+envelopeOverhead <= max {
		return doc
	}
	note := limits.Note(fmt.Sprintf("result exceeds %d bytes", max), narrowHint)
	budget := max - envelopeOverhead - len(note) - 1
	for budget > 0 {
		out := cutRunes(doc, budget) + "\n" + note
		over := len(untrusted.Escape(boundary, out)) + envelopeOverhead - max
		if over <= 0 {
			return out
		}
		budget -= over
	}
	return note
}

// cutRunes returns the longest prefix of s of at most n bytes that does not
// split a rune.
func cutRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// errorResult turns a handler error into an IsError result with errorText.
func errorResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: errorText(err)}}}
}

// errorText renders err for the client. Outside the envelope there are only
// fixed server-authored sentences: the error class (the text of a kube
// sentinel, or "the tool failed") and a hint. Everything else, including
// verbs, resources, names, namespaces, kind suggestions, API server messages
// and the text of any wrapped error, is the detail: err.Error(), sanitised,
// token-checked, capped and placed in a data envelope. The whole text is at
// most MaxBytes.
func errorText(err error) string {
	head := "error: " + summary(err)
	if h := hint(err); h != "" {
		head += "\nhint: " + h
	}
	head += "\ndetail (untrusted data, may quote the cluster):\n"

	detail := untrusted.Sanitize(err.Error())
	if redact.EnvValue("", detail) == redact.Redacted {
		detail = redact.Redacted
	}
	boundary := untrusted.NewBoundary()
	l := lim
	l.MaxBytes = lim.MaxBytes - len(head) - envelopeOverhead
	for l.MaxBytes > 0 {
		cut, _ := limits.TruncateText(detail, l)
		over := len(untrusted.Escape(boundary, cut)) - (lim.MaxBytes - len(head) - envelopeOverhead)
		if over <= 0 {
			return head + untrusted.Wrap(boundary, cut)
		}
		l.MaxBytes -= over
	}
	return strings.TrimSuffix(head, "\n")
}

// summary is the fixed class sentence of err.
func summary(err error) string {
	if c := class(err); c != "" {
		return c
	}
	return "the tool failed"
}

// class is the sentinel's own text, or "".
func class(err error) string {
	for _, s := range []error{
		kube.ErrForbidden, kube.ErrUnauthorized, kube.ErrNotFound, kube.ErrKindNotFound,
		kube.ErrTimeout, kube.ErrUnreachable, kube.ErrCredentialPlugin,
		kube.ErrMetricsUnavailable, kube.ErrUnknownContext, kube.ErrContextNotAllowed,
	} {
		if errors.Is(err, s) {
			return s.Error()
		}
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "the request timed out"
	case errors.Is(err, context.Canceled):
		return "the request was cancelled"
	}
	return ""
}

// hint says how to recover.
func hint(err error) string {
	var knf *kube.KindNotFoundError
	switch {
	case errors.As(err, &knf) && len(knf.Suggestions) > 0:
		return "retry with one of the close matches listed in the detail below."
	case errors.Is(err, kube.ErrKindNotFound):
		return "check the spelling; cluster_info lists the API groups served by this cluster."
	case errors.Is(err, kube.ErrForbidden):
		return "the kubeconfig identity lacks RBAC permission for this verb and resource. This server cannot change permissions; try another namespace or context, or ask a cluster admin."
	case errors.Is(err, kube.ErrUnauthorized):
		return "the credentials of this context were rejected or have expired; the user must log in again outside this server, then retry."
	case errors.Is(err, kube.ErrNotFound):
		return "check the name and namespace; list_resources shows what exists."
	case errors.Is(err, kube.ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return "narrow the request (namespace, label selector, smaller limit) or retry later."
	case errors.Is(err, kube.ErrUnreachable):
		return "the cluster's API server is not reachable from this machine; check that the cluster is running and the network or VPN is up."
	case errors.Is(err, kube.ErrCredentialPlugin):
		return "the kubeconfig credential plugin failed; the user must refresh the login of this context outside this server."
	case errors.Is(err, kube.ErrMetricsUnavailable):
		return "the top tool needs metrics-server; use workload_health or describe_resource instead."
	case errors.Is(err, kube.ErrUnknownContext):
		return "call list_contexts for the available context names."
	case errors.Is(err, kube.ErrContextNotAllowed):
		return "call list_contexts and use a context marked allowed; the allowlist is fixed when the server starts."
	}
	return ""
}

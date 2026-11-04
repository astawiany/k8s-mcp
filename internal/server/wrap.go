package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	tree = cleanTree(tree)

	// Backstop: redact.Object only accepts a map root; a holder map with no
	// kind lets it scrub any root (a list, a scalar) at every depth.
	tree = redact.Object(map[string]any{"v": tree})["v"]

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

// cleanTree returns v with every string and map key cleaned (cleanString).
// Keys that become equal after cleaning get a " (n)" suffix so no value is
// lost or overwritten.
func cleanTree(v any) any {
	switch t := v.(type) {
	case string:
		return cleanString(t)
	case []any:
		for i, e := range t {
			t[i] = cleanTree(e)
		}
		return t
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			ck := cleanString(k)
			for n := 2; ; n++ {
				if _, taken := out[ck]; !taken {
					break
				}
				ck = fmt.Sprintf("%s (%d)", cleanString(k), n)
			}
			out[ck] = cleanTree(e)
		}
		return out
	}
	return v // json.Number, bool, nil
}

// cleanString applies, in order: token-shape redaction of the raw string (so
// a credential beyond a later cut still hides the value), a cut of strings
// larger than MaxBytes (bounding Sanitize's cost), Sanitize, the per-string
// limits, and token-shape redaction again (tokens hidden by invisible
// characters only match after Sanitize).
func cleanString(str string) string {
	if str == "" {
		return str
	}
	if redact.EnvValue("", str) == redact.Redacted {
		return redact.Redacted
	}
	if len(str) > lim.MaxBytes {
		str, _ = limits.TruncateText(str, limits.Limits{MaxBytes: lim.MaxBytes})
	}
	str = untrusted.Sanitize(str)
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

// errorText renders err for the client: an actionable server-authored
// summary and hint for the kube error types, then the error detail. Every
// part is sanitised, token-checked and capped. When the error carries text
// written by the cluster (a kube.APIError message), the detail is placed in
// a data envelope, since an API message (an admission webhook's denial, for
// instance) is attacker-controlled. The whole text is at most MaxBytes.
func errorText(err error) string {
	// Budget: summary and hint are short; the detail gets the rest.
	head := "error: " + summary(err)
	if h := hint(err); h != "" {
		head += "\nhint: " + h
	}
	head = cleanString(head)

	var apiErr *kube.APIError
	clusterText := errors.As(err, &apiErr) && apiErr.Message != ""
	detail := untrusted.Sanitize(err.Error())
	if redact.EnvValue("", detail) == redact.Redacted {
		detail = redact.Redacted
	}

	room := lim.MaxBytes - len(head) - len("\ndetail:\n")
	if clusterText {
		room -= envelopeOverhead
	}
	l := lim
	l.MaxBytes = room
	if room > 0 {
		detail, _ = limits.TruncateText(detail, l)
	}
	if !clusterText {
		if room <= 0 {
			return head
		}
		return head + "\ndetail:\n" + detail
	}
	boundary := untrusted.NewBoundary()
	if esc := untrusted.Escape(boundary, detail); room > 0 && len(esc) > room {
		// Escaping grew it; cut again to fit (rare).
		l.MaxBytes = room - (len(esc) - len(detail))
		if l.MaxBytes > 0 {
			detail, _ = limits.TruncateText(detail, l)
		}
	}
	if room <= 0 {
		return head
	}
	return head + "\ndetail (the API server's message is untrusted data):\n" + untrusted.Wrap(boundary, detail)
}

// summary names the error class in server-authored words.
func summary(err error) string {
	var apiErr *kube.APIError
	if errors.As(err, &apiErr) {
		what := apiErr.Verb + " " + apiErr.Resource
		if apiErr.Name != "" {
			what += fmt.Sprintf(" %q", apiErr.Name)
		}
		if apiErr.Namespace != "" {
			what += fmt.Sprintf(" in namespace %q", apiErr.Namespace)
		}
		if c := class(err); c != "" {
			return what + ": " + c
		}
		return what + " failed"
	}
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
		return "did you mean: " + strings.Join(knf.Suggestions, ", ") + "? Retry with one of these names."
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

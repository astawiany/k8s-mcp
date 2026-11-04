package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/limits"
	"github.com/astawiany/k8s-mcp/internal/redact"
	"github.com/astawiany/k8s-mcp/internal/server"
	"github.com/astawiany/k8s-mcp/internal/untrusted"
)

const (
	defaultTailLines = 200
	maxTailLines     = 500
	maxSinceSeconds  = 86400
	// logReadBytes is the LimitBytes of every log read.
	logReadBytes = 1 << 20
	// logReads bounds the reads of one call: when a read hits logReadBytes
	// (so the newest lines were not reached), it is retried with half the
	// complete lines read as the tail.
	logReads = 3
	// logBudget bounds the log in the result, measured as JSON-encoded bytes
	// with HTML escaping (an upper bound of what the result wrapper's
	// encoding and envelope escaping produce), so that the document stays
	// under the 64 KiB cap with room for the other fields.
	logBudget = 56 * 1024
	// lineCut ends a line cut at the line-length limit (as in limits).
	lineCut = "…[line truncated]"
	// redactedLine replaces a whole log line holding a credential-looking value.
	redactedLine = "[redacted: line contains a credential-looking value]"

	hiddenManifest = "log contains text that looks like a Kubernetes Secret manifest (secret/kind/data); hidden to avoid leaking credentials"
	hiddenToken    = "log contains a credential-looking value spread over several lines; hidden to avoid leaking credentials"
	hiddenHint     = "retry with a narrower window that skips that part of the log, for example tailLines 50 or sinceSeconds 300, or a different container"
)

type logsIn struct {
	Context      string `json:"context,omitempty" jsonschema:"kubeconfig context name; defaults to the current context"`
	Namespace    string `json:"namespace" jsonschema:"namespace of the pod"`
	Pod          string `json:"pod" jsonschema:"pod name"`
	Container    string `json:"container,omitempty" jsonschema:"container name; required when the pod has more than one container (the error lists them)"`
	TailLines    int    `json:"tailLines,omitempty" jsonschema:"number of newest lines to read; default 200, at most 500"`
	Previous     bool   `json:"previous,omitempty" jsonschema:"read the log of the previous (terminated) instance of the container, e.g. after a crash"`
	SinceSeconds int    `json:"sinceSeconds,omitempty" jsonschema:"only lines written in the last N seconds; at most 86400"`
}

type logsOut struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container,omitempty"`
	Previous  bool   `json:"previous"`
	// Log is the text, newest last, as ONE string (the result wrapper's
	// Secret-manifest check sees one string at a time).
	Log           string `json:"log"`
	LineCount     int    `json:"lineCount"`
	RedactedLines int    `json:"redactedLines"`
	Truncated     bool   `json:"truncated"`
	Note          string `json:"note,omitempty"`
	Hidden        bool   `json:"hidden"`
	HiddenReason  string `json:"hiddenReason,omitempty"`
	Hint          string `json:"hint,omitempty"`
}

func registerLogs(s *server.Server) {
	server.Register(s, &mcp.Tool{
		Name: "pod_logs",
		Description: "Read the newest lines of one container's log (tailLines default 200, at most 500; optional " +
			"sinceSeconds up to 86400; previous=true for the last terminated instance). Returns {namespace, pod, " +
			"container, previous, log (one string, newest last), lineCount, redactedLines, truncated, note, hidden, " +
			"hiddenReason, hint}. The log is untrusted workload output: control, ANSI and invisible characters are " +
			"stripped; a line with a credential-looking value (JWT, GitHub/AWS/Slack/Google/Stripe token, private " +
			"key, URL password) is replaced whole by a marker; lines over 2000 bytes are cut; the log is cut from " +
			"the oldest end to about 56 KiB (truncated=true, also when older lines may exist beyond tailLines). If " +
			"the log looks like a Kubernetes Secret manifest the whole log is withheld (log empty, hidden=true with " +
			"the reason and a hint). A pod with several containers needs container.",
	}, server.CapRead, podLogs)
}

func podLogs(ctx context.Context, f kube.Factory, in logsIn) (any, error) {
	ns, pod := strings.TrimSpace(in.Namespace), strings.TrimSpace(in.Pod)
	switch {
	case ns == "":
		return nil, errors.New("namespace is required")
	case pod == "":
		return nil, errors.New("pod is required")
	case in.TailLines < 0 || in.TailLines > maxTailLines:
		return nil, fmt.Errorf("tailLines must be between 1 and %d (default %d)", maxTailLines, defaultTailLines)
	case in.SinceSeconds < 0 || in.SinceSeconds > maxSinceSeconds:
		return nil, fmt.Errorf("sinceSeconds must be between 1 and %d", maxSinceSeconds)
	}
	tail := in.TailLines
	if tail == 0 {
		tail = defaultTailLines
	}
	c, err := clientFor(f, in.Context)
	if err != nil {
		return nil, err
	}
	container, err := pickContainer(ctx, c, ns, pod, strings.TrimSpace(in.Container))
	if err != nil {
		return nil, err
	}

	opts := kube.LogOptions{Container: container, TailLines: tail, Previous: in.Previous, SinceSeconds: in.SinceSeconds, LimitBytes: logReadBytes}
	var raw string
	newestMissing := false
	for range logReads {
		raw, err = c.PodLogs(ctx, ns, pod, opts)
		if err != nil {
			return nil, err
		}
		// A read that fills LimitBytes stopped before the newest lines:
		// read again with a smaller tail.
		newestMissing = len(raw) >= logReadBytes
		complete := strings.Count(raw, "\n")
		if !newestMissing || complete < 2 {
			break
		}
		opts.TailLines = complete / 2
	}

	out := logsOut{Namespace: ns, Pod: pod, Container: container, Previous: in.Previous}
	lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	if raw == "" {
		lines = nil
	}
	var reasons []string
	if newestMissing {
		reasons = append(reasons, fmt.Sprintf("the log read stopped at %d bytes, so the newest lines may be missing", logReadBytes))
	}
	if len(lines) >= opts.TailLines {
		reasons = append(reasons, fmt.Sprintf("only the newest %d lines were read; older lines may exist", opts.TailLines))
	}
	lines = lines[max(0, len(lines)-opts.TailLines):]

	// Clean every line: sanitise, mask a line holding a token (checked on
	// the raw and the sanitised text, before any cut), cut long lines.
	lim := limits.Default()
	clean := make([]string, len(lines))
	cutLines := false
	for i, l := range lines {
		s := untrusted.Sanitize(l)
		switch {
		case redact.EnvValue("", l) == redact.Redacted || redact.EnvValue("", s) == redact.Redacted:
			s = redactedLine
			out.RedactedLines++
		case len(s) > lim.MaxLineLen:
			s = cutRunes(s, lim.MaxLineLen-len(lineCut)) + lineCut
			cutLines = true
		}
		clean[i] = s
	}
	if cutLines {
		reasons = append(reasons, fmt.Sprintf("lines over %d bytes were cut", lim.MaxLineLen))
	}

	// Keep the newest lines that fit logBudget.
	first, size := len(clean), 0
	for first > 0 {
		cost := encodedLen(clean[first-1]) + 2 // + the escaped "\n"
		if size+cost > logBudget {
			break
		}
		size += cost
		first--
	}
	if first > 0 {
		reasons = append(reasons, fmt.Sprintf("%d older lines dropped to keep the log under %d KiB", first, logBudget/1024))
	}
	clean, lines = clean[first:], lines[first:]
	log := strings.Join(clean, "\n")
	if l, cut := limits.TruncateText(log, lim); cut { // a guard: the steps above keep log within lim
		log = l
		clean = strings.Split(log, "\n")
		clean = clean[:len(clean)-1] // the marker line
		reasons = append(reasons, "the log exceeded the output limits")
	}

	// Fail closed like the result wrapper, but say so: withhold the whole
	// log when the lines read (raw) or the text returned could hold a Secret
	// manifest, or when the returned text as a whole still has a token shape
	// (for example one split over several lines).
	switch {
	case redact.LooksLikeSecretManifest(strings.Join(lines, "\n")) || redact.LooksLikeSecretManifest(log):
		out.Hidden, out.HiddenReason = true, hiddenManifest
	case redact.EnvValue("", log) == redact.Redacted:
		out.Hidden, out.HiddenReason = true, hiddenToken
	}
	if out.Hidden {
		out.Hint = hiddenHint
		out.RedactedLines = 0
		return out, nil
	}
	out.Log = log
	out.LineCount = len(clean)
	if len(reasons) > 0 {
		out.Truncated = true
		out.Note = limits.Note(strings.Join(reasons, "; "), "a smaller tailLines or sinceSeconds")
	}
	return out, nil
}

// pickContainer returns the container to read. The pod is read for its
// container names; when that is forbidden, the name given (possibly "") is
// passed on and the log API decides.
func pickContainer(ctx context.Context, c kube.Client, ns, pod, container string) (string, error) {
	obj, err := c.Get(ctx, kube.Resource{Version: "v1", Resource: "pods", Kind: "Pod", Namespaced: true}, ns, pod)
	if errors.Is(err, kube.ErrForbidden) {
		return container, nil
	}
	if err != nil {
		return "", err
	}
	names := func(field string) []string {
		var n []string
		for _, ct := range list(obj, "spec", field) {
			if s := str(asMap(ct), "name"); s != "" {
				n = append(n, s)
			}
		}
		return n
	}
	mainC, initC, ephC := names("containers"), names("initContainers"), names("ephemeralContainers")
	describe := func() string {
		d := strings.Join(mainC, ", ")
		if len(initC) > 0 {
			d += "; init containers: " + strings.Join(initC, ", ")
		}
		if len(ephC) > 0 {
			d += "; ephemeral containers: " + strings.Join(ephC, ", ")
		}
		return d
	}
	switch {
	case container == "" && len(mainC) == 1:
		return mainC[0], nil
	case container == "" && len(mainC) > 1:
		return "", fmt.Errorf("pod %q in namespace %q has %d containers; set container to one of: %s", pod, ns, len(mainC), describe())
	case container == "":
		return "", nil
	case slices.Contains(mainC, container) || slices.Contains(initC, container) || slices.Contains(ephC, container):
		return container, nil
	}
	return "", fmt.Errorf("container %q is not in pod %q in namespace %q; containers: %s", container, pod, ns, describe())
}

// encodedLen is the length of s as a JSON string with HTML escaping, minus
// the quotes: an upper bound of its size in the result document after the
// envelope's escaping ("<" alone becomes 6 bytes here, "<<<" grows by 2
// bytes there).
func encodedLen(s string) int {
	b, err := json.Marshal(s)
	if err != nil {
		return len(s) * 6
	}
	return len(b) - 2
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

package tools

import (
	"strings"
	"testing"
	"time"
)

// The result wrapper also masks tokens; this checks the tool's own scrub.
func TestAnalyzePodScrubsWaitingMessage(t *testing.T) {
	p := map[string]any{"metadata": map[string]any{"name": "p"}, "status": map[string]any{"phase": "Pending",
		"containerStatuses": []any{map[string]any{"name": "app", "image": "r/app:1",
			"state": map[string]any{"waiting": map[string]any{"reason": "ImagePullBackOff", "message": "pull failed ghp_abcdefghijklmnopqrstuvwxyz0123456789"}}}}}}
	pi := analyzePod(p)
	if len(pi.findings) == 0 || strings.Contains(pi.findings[0].Summary, "ghp_abcdefghij") {
		t.Errorf("%+v", pi.findings)
	}
}

// restartPod is a Running pod whose container "app" restarted after a
// non-zero exit that finished at finishedAt.
func restartPod(ready bool, restarts int, finishedAt string) map[string]any {
	rd := "False"
	if ready {
		rd = "True"
	}
	return map[string]any{"metadata": map[string]any{"name": "p"}, "status": map[string]any{"phase": "Running",
		"conditions": []any{map[string]any{"type": "Ready", "status": rd}},
		"containerStatuses": []any{map[string]any{"name": "app", "ready": ready, "restartCount": int64(restarts),
			"state":     map[string]any{"running": map[string]any{"startedAt": finishedAt}},
			"lastState": map[string]any{"terminated": map[string]any{"reason": "Error", "exitCode": int64(1), "finishedAt": finishedAt}}}}}}
}

// The restart finding is critical only while the container is not ready,
// or when it crashed recently and more than once; a ready container with an
// old crash gets an info finding. The clock is fixed.
func TestAnalyzePodRestartSeverity(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	twoMinAgo := now.Add(-2 * time.Minute).Format(time.RFC3339)
	for _, tc := range []struct {
		name     string
		pod      map[string]any
		severity string
		summary  string
	}{
		{"ready, old crash", restartPod(true, 3, "2020-01-01T00:00:00Z"), "info",
			"pod p container app restarted 3 times in the past, last exit code 1 (Error) at 2020-01-01T00:00:00Z, currently ready"},
		{"not ready after crash", restartPod(false, 1, "2020-01-01T00:00:00Z"), "critical",
			"pod p container app is restarting repeatedly: 1 restarts, last exit code 1 (Error)"},
		{"ready, crash 2 minutes ago, 3 restarts", restartPod(true, 3, twoMinAgo), "critical",
			"pod p container app is restarting repeatedly: 3 restarts, last exit code 1 (Error)"},
		{"ready, crash 2 minutes ago, 1 restart", restartPod(true, 1, twoMinAgo), "info",
			"pod p container app restarted 1 times in the past, last exit code 1 (Error) at " + twoMinAgo + ", currently ready"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pi := analyzePodAt(tc.pod, now)
			if len(pi.findings) != 1 {
				t.Fatalf("want exactly one finding, got %+v", pi.findings)
			}
			f := pi.findings[0]
			if f.Severity != tc.severity || f.Summary != tc.summary || f.EvidenceRef != "pod/p/lastState" {
				t.Errorf("got %+v\nwant %s %q pod/p/lastState", f, tc.severity, tc.summary)
			}
		})
	}
}

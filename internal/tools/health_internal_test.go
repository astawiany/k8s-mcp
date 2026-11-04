package tools

import (
	"strings"
	"testing"
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

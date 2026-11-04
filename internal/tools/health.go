package tools

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/limits"
	"github.com/astawiany/k8s-mcp/internal/redact"
	"github.com/astawiany/k8s-mcp/internal/server"
)

// maxHealthPods bounds the pods array of workload_health's output.
const maxHealthPods = 50

var healthKinds = []string{"Deployment", "StatefulSet", "DaemonSet"}

// recentCrash is how long after a crash a ready container that restarted
// more than once is still reported as restarting repeatedly (critical).
const recentCrash = 15 * time.Minute

type healthIn struct {
	Context   string `json:"context,omitempty" jsonschema:"kubeconfig context name; defaults to the current context"`
	Namespace string `json:"namespace" jsonschema:"namespace of the workload"`
	Kind      string `json:"kind" jsonschema:"Deployment, StatefulSet or DaemonSet"`
	Name      string `json:"name" jsonschema:"workload name"`
}

type healthRollout struct {
	Desired     int64  `json:"desired"`
	Ready       int64  `json:"ready"`
	Updated     int64  `json:"updated"`
	Unavailable int64  `json:"unavailable"`
	Progressing bool   `json:"progressing"`
	Message     string `json:"message,omitempty"`
}

type healthTermination struct {
	Reason     string `json:"reason"`
	ExitCode   int64  `json:"exitCode"`
	FinishedAt string `json:"finishedAt,omitempty"`
}

type healthPod struct {
	Name                 string             `json:"name"`
	Phase                string             `json:"phase"`
	Restarts             int64              `json:"restarts"`
	Ready                bool               `json:"ready"`
	WaitingReason        string             `json:"waitingReason,omitempty"`
	LastTermination      *healthTermination `json:"lastTermination,omitempty"`
	UnschedulableMessage string             `json:"unschedulableMessage,omitempty"`
}

type healthFinding struct {
	Severity    string `json:"severity"`
	Summary     string `json:"summary"`
	EvidenceRef string `json:"evidenceRef"`
}

type healthOut struct {
	Rollout   healthRollout   `json:"rollout"`
	Pods      []healthPod     `json:"pods"`
	Findings  []healthFinding `json:"findings"`
	Truncated bool            `json:"truncated,omitempty"`
	Note      string          `json:"note,omitempty"`
}

func registerHealth(s *server.Server) {
	server.Register(s, &mcp.Tool{
		Name: "workload_health",
		Description: "Health of one Deployment, StatefulSet or DaemonSet: rollout counts, per-pod status and " +
			"findings with a cause (CrashLoopBackOff, OOMKilled with the memory limit, ImagePullBackOff, " +
			"unschedulable, failing readiness, ProgressDeadlineExceeded, evicted, config errors). Pods are " +
			"selected by the workload's spec.selector, then pods owned by another controller, and pods of " +
			"scaled-down old ReplicaSets, are dropped. Only status-derived fields are returned, never pod specs " +
			"or env. Unhealthy pods first; at most 50 pods returned (truncated=true when more exist or the " +
			"pod list was cut at 200). Every finding has an evidenceRef such as pod/<name>/lastState. Other " +
			"kinds are an error. Read-only: never creates, changes or deletes anything.",
	}, server.CapRead, workloadHealth)
}

func workloadHealth(ctx context.Context, f kube.Factory, in healthIn) (any, error) {
	kind := ""
	for _, k := range healthKinds {
		if strings.EqualFold(strings.TrimSpace(in.Kind), k) {
			kind = k
		}
	}
	if kind == "" {
		return nil, fmt.Errorf("unsupported kind %q; supported kinds: %s", in.Kind, strings.Join(healthKinds, ", "))
	}
	name, ns := strings.TrimSpace(in.Name), strings.TrimSpace(in.Namespace)
	if name == "" || ns == "" {
		return nil, fmt.Errorf("namespace and name are required")
	}
	c, err := clientFor(f, in.Context)
	if err != nil {
		return nil, err
	}
	wr, err := c.Resolve(ctx, kind, "apps", "")
	if err != nil {
		return nil, err
	}
	w, err := c.Get(ctx, wr, ns, name)
	if err != nil {
		return nil, err
	}
	sel, err := selectorString(w)
	if err != nil {
		return nil, err
	}
	pr, err := c.Resolve(ctx, "Pod", "", "v1")
	if err != nil {
		return nil, err
	}
	max := limits.Default().MaxItems
	pl, err := c.List(ctx, pr, ns, kube.ListOptions{LabelSelector: sel, Limit: int64(max)})
	if err != nil {
		return nil, err
	}
	out := healthOut{Pods: []healthPod{}, Findings: []healthFinding{}}
	out.Truncated = pl.Continue != ""

	pods := pl.Items
	var ignored, unattributed int
	if kind == "Deployment" {
		rr, err := c.Resolve(ctx, "ReplicaSet", "apps", "")
		if err != nil {
			return nil, err
		}
		rl, err := c.List(ctx, rr, ns, kube.ListOptions{LabelSelector: sel, Limit: int64(max)})
		if err != nil {
			return nil, err
		}
		pods, ignored, unattributed = filterDeploymentPods(pods, rl.Items, name)
	} else {
		pods, ignored = filterOwned(pods, kind, name)
	}

	out.Rollout = rolloutOf(kind, w, &out.Findings, name)
	var infos []podInfo
	for _, p := range pods {
		infos = append(infos, analyzePod(p))
	}
	slices.SortStableFunc(infos, func(a, b podInfo) int {
		return cmp.Or(
			cmp.Compare(boolInt(b.unhealthy), boolInt(a.unhealthy)),
			cmp.Compare(b.pod.Restarts, a.pod.Restarts),
			strings.Compare(a.pod.Name, b.pod.Name))
	})
	for _, pi := range infos {
		out.Findings = append(out.Findings, pi.findings...)
	}
	if len(infos) > maxHealthPods {
		infos = infos[:maxHealthPods]
		out.Truncated = true
	}
	for _, pi := range infos {
		out.Pods = append(out.Pods, pi.pod)
	}
	finishFindings(kind, name, &out)
	if len(out.Findings) > max {
		out.Findings = out.Findings[:max]
		out.Truncated = true
	}
	var notes []string
	if out.Truncated {
		notes = append(notes, fmt.Sprintf("pods capped at %d (list read at most %d); unhealthy pods are listed first", maxHealthPods, max))
	}
	if ignored > 0 {
		notes = append(notes, fmt.Sprintf("%d pod(s) ignored: not controlled by this workload, or from a scaled-down old ReplicaSet", ignored))
	}
	if unattributed > 0 {
		notes = append(notes, fmt.Sprintf("%d pod(s) could not be attributed (their ReplicaSet was not found) and are included", unattributed))
	}
	out.Note = strings.Join(notes, "; ")
	return out, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// selectorString renders spec.selector (matchLabels and matchExpressions) as
// a label selector. An empty selector is refused: it would match every pod.
func selectorString(w map[string]any) (string, error) {
	var parts []string
	ml, _ := nested(w, "spec", "selector", "matchLabels").(map[string]any)
	for k, v := range ml {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	exprs, _ := nested(w, "spec", "selector", "matchExpressions").([]any)
	for _, e := range exprs {
		m, _ := e.(map[string]any)
		key, _ := m["key"].(string)
		op, _ := m["operator"].(string)
		var vals []string
		vs, _ := m["values"].([]any)
		for _, v := range vs {
			vals = append(vals, fmt.Sprint(v))
		}
		switch op {
		case "In":
			parts = append(parts, fmt.Sprintf("%s in (%s)", key, strings.Join(vals, ",")))
		case "NotIn":
			parts = append(parts, fmt.Sprintf("%s notin (%s)", key, strings.Join(vals, ",")))
		case "Exists":
			parts = append(parts, key)
		case "DoesNotExist":
			parts = append(parts, "!"+key)
		default:
			return "", fmt.Errorf("unsupported selector operator %q", op)
		}
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("workload has an empty spec.selector; refusing to match every pod in the namespace")
	}
	slices.Sort(parts)
	return strings.Join(parts, ","), nil
}

// controllerOwner returns the kind and name of obj's controller owner, if any.
func controllerOwner(obj map[string]any) (kind, name string, ok bool) {
	refs, _ := nested(obj, "metadata", "ownerReferences").([]any)
	for _, r := range refs {
		m, _ := r.(map[string]any)
		if c, _ := m["controller"].(bool); c {
			kind, _ = m["kind"].(string)
			name, _ = m["name"].(string)
			return kind, name, true
		}
	}
	return "", "", false
}

// filterOwned keeps pods without a controller owner (selector match only) and
// pods controlled by kind/name; the rest belong to someone else.
func filterOwned(pods []map[string]any, kind, name string) (keep []map[string]any, ignored int) {
	for _, p := range pods {
		if k, n, ok := controllerOwner(p); ok && (k != kind || n != name) {
			ignored++
			continue
		}
		keep = append(keep, p)
	}
	return keep, ignored
}

// filterDeploymentPods applies the Deployment rule: a pod controlled by a
// ReplicaSet is kept only when that ReplicaSet is controlled by the
// Deployment and has spec.replicas > 0 (old revisions scaled to zero only
// leave terminating leftovers). Pods with no controller owner are kept; a pod
// owned by anything else is dropped.
func filterDeploymentPods(pods, rss []map[string]any, name string) (keep []map[string]any, ignored, unattributed int) {
	live, known := map[string]bool{}, map[string]bool{}
	for _, rs := range rss {
		rn := str(rs, "metadata", "name")
		known[rn] = true
		if k, n, ok := controllerOwner(rs); !ok || k != "Deployment" || n != name {
			continue
		}
		if replicas, ok := toInt(nested(rs, "spec", "replicas")); ok && replicas == 0 {
			continue
		}
		live[rn] = true
	}
	for _, p := range pods {
		k, n, ok := controllerOwner(p)
		switch {
		case !ok:
		case k != "ReplicaSet":
			ignored++
			continue
		case !known[n]:
			unattributed++ // ReplicaSet not in the list: keep what cannot be attributed
		case !live[n]:
			ignored++
			continue
		}
		keep = append(keep, p)
	}
	return keep, ignored, unattributed
}

func toInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	}
	return 0, false
}

func intAt(obj map[string]any, path ...string) int64 {
	n, _ := toInt(nested(obj, path...))
	return n
}

// cluster-sourced message text: mask credential-looking values.
func clean(s string) string { return redact.EnvValue("", s) }

func workloadCondition(w map[string]any, typ string) map[string]any {
	cs, _ := nested(w, "status", "conditions").([]any)
	for _, c := range cs {
		if m, _ := c.(map[string]any); m != nil && m["type"] == typ {
			return m
		}
	}
	return nil
}

func rolloutOf(kind string, w map[string]any, findings *[]healthFinding, name string) healthRollout {
	var r healthRollout
	switch kind {
	case "DaemonSet":
		r.Desired = intAt(w, "status", "desiredNumberScheduled")
		r.Ready = intAt(w, "status", "numberReady")
		r.Updated = intAt(w, "status", "updatedNumberScheduled")
		r.Unavailable = intAt(w, "status", "numberUnavailable")
	default:
		r.Desired = 1
		if n, ok := toInt(nested(w, "spec", "replicas")); ok {
			r.Desired = n
		}
		r.Ready = intAt(w, "status", "readyReplicas")
		r.Updated = intAt(w, "status", "updatedReplicas")
		r.Unavailable = intAt(w, "status", "unavailableReplicas")
		if kind == "StatefulSet" {
			r.Unavailable = max(0, r.Desired-r.Ready)
		}
	}
	r.Progressing = r.Updated < r.Desired || r.Ready < r.Desired
	if kind == "Deployment" {
		if c := workloadCondition(w, "Progressing"); c != nil {
			r.Message = clean(fmt.Sprint(c["message"]))
			if c["reason"] == "ProgressDeadlineExceeded" || c["status"] == "False" {
				r.Progressing = false
				*findings = append(*findings, healthFinding{"critical",
					fmt.Sprintf("Deployment %s rollout stuck: ProgressDeadlineExceeded (%d of %d replicas ready, %d updated): %s",
						name, r.Ready, r.Desired, r.Updated, r.Message),
					"deployment/" + name + "/conditions"})
			}
		}
	}
	if r.Message == "" {
		r.Message = fmt.Sprintf("%d/%d ready, %d updated, %d unavailable", r.Ready, r.Desired, r.Updated, r.Unavailable)
	}
	return r
}

type podInfo struct {
	pod       healthPod
	unhealthy bool
	findings  []healthFinding
}

var configErrors = map[string]bool{"CreateContainerConfigError": true, "CreateContainerError": true, "RunContainerError": true, "InvalidImageName": true}

func memoryLimit(p map[string]any, container string) string {
	cs, _ := nested(p, "spec", "containers").([]any)
	for _, c := range cs {
		m, _ := c.(map[string]any)
		if m["name"] == container {
			s, _ := nested(m, "resources", "limits", "memory").(string)
			return s
		}
	}
	return ""
}

// failingWaiting are the waiting reasons that mark a container as the failing
// one when choosing what the pod summary shows.
var failingWaiting = map[string]bool{"CrashLoopBackOff": true, "ImagePullBackOff": true, "ErrImagePull": true,
	"CreateContainerConfigError": true, "RunContainerError": true, "CreateContainerError": true, "InvalidImageName": true}

const (
	stuckInitAfter = 5 * time.Minute
	terminatingFor = 5 * time.Minute
)

func tsAge(ts string, now time.Time) (time.Duration, bool) {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return 0, false
	}
	return now.Sub(t), true
}

func analyzePod(p map[string]any) podInfo {
	return analyzePodAt(p, time.Now())
}

// analyzePodAt is analyzePod with the current time passed in (tests use a
// fixed clock).
func analyzePodAt(p map[string]any, now time.Time) podInfo {
	name := str(p, "metadata", "name")
	hp := healthPod{Name: name, Phase: str(p, "status", "phase")}
	ref := func(s string) string { return "pod/" + name + "/" + s }
	var fs []healthFinding
	add := func(sev, summary, evidence string) { fs = append(fs, healthFinding{sev, summary, ref(evidence)}) }

	if c := podCondition(p, "Ready"); c != nil && c["status"] == "True" {
		hp.Ready = true
	}
	type cstat struct {
		m    map[string]any
		init bool
	}
	var statuses []cstat
	for _, key := range []string{"initContainerStatuses", "containerStatuses"} {
		l, _ := nested(p, "status", key).([]any)
		for _, s := range l {
			if m, _ := s.(map[string]any); m != nil {
				statuses = append(statuses, cstat{m, key == "initContainerStatuses"})
			}
		}
	}
	var notReadyRunning, picked bool
	var firstWaiting string
	for _, st := range statuses {
		cs := st.m
		cname, _ := cs["name"].(string)
		label := cname
		prefix := ""
		if st.init {
			label = "init:" + cname
			prefix = "Init:"
		}
		restarts := intAt(cs, "restartCount")
		hp.Restarts += restarts
		wait, _ := nested(cs, "state", "waiting").(map[string]any)
		reason, _ := wait["reason"].(string)
		msg := clean(fmt.Sprint(orEmpty(wait["message"])))
		// The termination to report: the current terminated state, else the last one.
		curTerm, _ := nested(cs, "state", "terminated").(map[string]any)
		src, evid := curTerm, "lastState"
		if src == nil {
			src, _ = nested(cs, "lastState", "terminated").(map[string]any)
		}
		var term *healthTermination
		if src != nil {
			term = &healthTermination{Reason: clean(fmt.Sprint(orEmpty(src["reason"]))), ExitCode: intAt(src, "exitCode"),
				FinishedAt: fmt.Sprint(orEmpty(src["finishedAt"]))}
		}
		failing := failingWaiting[reason] || (term != nil && term.ExitCode != 0)
		if failing && !picked {
			picked = true
			hp.LastTermination = term
			if reason != "" {
				hp.WaitingReason = prefix + reason
			}
		}
		if reason != "" && firstWaiting == "" && reason != "ContainerCreating" && reason != "PodInitializing" {
			firstWaiting = prefix + reason
		}
		switch {
		case reason == "CrashLoopBackOff":
			exit := "unknown"
			e := "status"
			if term != nil {
				exit = fmt.Sprintf("%d (%s)", term.ExitCode, term.Reason)
				e = "lastState"
			}
			add("critical", fmt.Sprintf("pod %s container %s is in CrashLoopBackOff: %d restarts, last exit code %s", name, label, restarts, exit), e)
		case reason == "ImagePullBackOff" || reason == "ErrImagePull":
			add("critical", fmt.Sprintf("pod %s container %s cannot pull image %q (%s): %s", name, label, clean(str(cs, "image")), reason, msg), "status")
		case configErrors[reason]:
			add("critical", fmt.Sprintf("pod %s container %s: %s: %s", name, label, reason, msg), "status")
		}
		switch {
		case term != nil && term.Reason == "OOMKilled":
			lim := "no memory limit set"
			if l := memoryLimit(p, cname); l != "" {
				lim = "memory limit " + l
			}
			add("critical", fmt.Sprintf("pod %s container %s was OOMKilled (exit code %d), %s, %d restarts", name, label, term.ExitCode, lim, restarts), evid)
		case term != nil && term.ExitCode != 0 && restarts > 0 && reason != "CrashLoopBackOff":
			// A crash loop seen between back-offs: running again, terminated
			// again, or being recreated. CrashLoopBackOff already has its
			// own finding with the same facts. A container that is ready
			// again is critical only if it crashed recently and more than
			// once; an old crash is reported as info.
			age, known := tsAge(term.FinishedAt, now)
			recent := known && age < recentCrash
			if cs["ready"] != true || (recent && restarts >= 2) {
				add("critical", fmt.Sprintf("pod %s container %s is restarting repeatedly: %d restarts, last exit code %d (%s)", name, label, restarts, term.ExitCode, term.Reason), evid)
			} else {
				at := term.FinishedAt
				if at == "" {
					at = "an unknown time"
				}
				add("info", fmt.Sprintf("pod %s container %s restarted %d times in the past, last exit code %d (%s) at %s, currently ready", name, label, restarts, term.ExitCode, term.Reason, at), evid)
			}
		case curTerm != nil && term.ExitCode != 0:
			add("critical", fmt.Sprintf("pod %s container %s terminated with exit code %d (%s)", name, label, term.ExitCode, term.Reason), evid)
		}
		if run, _ := nested(cs, "state", "running").(map[string]any); run != nil {
			if cs["ready"] == false && restarts == 0 && !st.init {
				notReadyRunning = true
			}
			if st.init {
				started, _ := run["startedAt"].(string)
				if started == "" {
					started = str(p, "metadata", "creationTimestamp")
				}
				if d, ok := tsAge(started, now); ok && d >= stuckInitAfter {
					add("warning", fmt.Sprintf("pod %s init container %s still running after %d minutes", name, cname, int(d.Minutes())), "status")
				}
			}
		}
	}
	if hp.WaitingReason == "" {
		hp.WaitingReason = firstWaiting
	}
	for _, c := range podConditions(p) {
		if c["type"] == "PodScheduled" && c["status"] == "False" && c["reason"] == "Unschedulable" {
			hp.UnschedulableMessage = clean(fmt.Sprint(orEmpty(c["message"])))
			add("warning", fmt.Sprintf("pod %s is Pending and unschedulable: %s", name, hp.UnschedulableMessage), "conditions")
		}
	}
	if hp.Phase == "Failed" {
		reason := clean(str(p, "status", "reason"))
		msg := clean(str(p, "status", "message"))
		switch {
		case reason == "Evicted":
			add("warning", fmt.Sprintf("pod %s was Evicted: %s", name, msg), "status")
		case reason != "":
			add("warning", fmt.Sprintf("pod %s failed: %s: %s", name, reason, msg), "status")
		}
	}
	if d, ok := tsAge(str(p, "metadata", "deletionTimestamp"), now); ok && d >= terminatingFor {
		add("warning", fmt.Sprintf("pod %s is stuck Terminating for %d minutes", name, int(d.Minutes())), "status")
	}
	if hp.Phase == "Running" && !hp.Ready && notReadyRunning && hp.WaitingReason == "" {
		add("warning", fmt.Sprintf("pod %s is Running but not Ready: readiness is failing (0 restarts)", name), "conditions")
	}
	unhealthy := !hp.Ready && hp.Phase != "Succeeded"
	return podInfo{pod: hp, unhealthy: unhealthy || len(fs) > 0, findings: fs}
}

func orEmpty(v any) any {
	if v == nil {
		return ""
	}
	return v
}

func podConditions(p map[string]any) []map[string]any {
	var out []map[string]any
	cs, _ := nested(p, "status", "conditions").([]any)
	for _, c := range cs {
		if m, _ := c.(map[string]any); m != nil {
			out = append(out, m)
		}
	}
	return out
}

func podCondition(p map[string]any, typ string) map[string]any {
	for _, c := range podConditions(p) {
		if c["type"] == typ {
			return c
		}
	}
	return nil
}

// finishFindings adds the rollout-level findings that depend on the pod
// findings and orders findings critical first.
func finishFindings(kind, name string, out *healthOut) {
	r := out.Rollout
	bad := false
	for _, f := range out.Findings {
		if f.Severity != "info" {
			bad = true
		}
	}
	lower := strings.ToLower(kind) + "/" + name + "/status"
	switch {
	case kind != "DaemonSet" && r.Desired == 0:
		out.Findings = append(out.Findings, healthFinding{"info", fmt.Sprintf("%s %s is scaled to zero replicas", kind, name), lower})
	case r.Ready < r.Desired && !bad:
		out.Findings = append(out.Findings, healthFinding{"warning", fmt.Sprintf("%s %s has %d of %d replicas ready", kind, name, r.Ready, r.Desired), lower})
	case !bad && r.Desired > 0:
		out.Findings = append(out.Findings, healthFinding{"info", fmt.Sprintf("all %d replicas ready", r.Ready), lower})
	}
	rank := map[string]int{"critical": 0, "warning": 1, "info": 2}
	slices.SortStableFunc(out.Findings, func(a, b healthFinding) int { return cmp.Compare(rank[a.Severity], rank[b.Severity]) })
}

package tools_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/astawiany/k8s-mcp/internal/kube"
	"github.com/astawiany/k8s-mcp/internal/server/servertest"
)

type hFinding struct {
	Severity    string `json:"severity"`
	Summary     string `json:"summary"`
	EvidenceRef string `json:"evidenceRef"`
}

type hOut struct {
	Rollout struct {
		Desired, Ready, Updated, Unavailable int64
		Progressing                          bool
		Message                              string
	} `json:"rollout"`
	Pods []struct {
		Name                 string `json:"name"`
		Phase                string `json:"phase"`
		Restarts             int64  `json:"restarts"`
		Ready                bool   `json:"ready"`
		WaitingReason        string `json:"waitingReason"`
		UnschedulableMessage string `json:"unschedulableMessage"`
		LastTermination      *struct {
			Reason   string `json:"reason"`
			ExitCode int64  `json:"exitCode"`
		} `json:"lastTermination"`
	} `json:"pods"`
	Findings  []hFinding `json:"findings"`
	Truncated bool       `json:"truncated"`
	Note      string     `json:"note"`
}

func hDeploy(replicas, ready int, conds ...any) map[string]any {
	o := kube.Object("apps/v1", "Deployment", "app", "web")
	o["spec"] = map[string]any{"replicas": replicas, "selector": map[string]any{"matchLabels": map[string]any{"app": "web"}}}
	o["status"] = map[string]any{"readyReplicas": ready, "updatedReplicas": ready, "conditions": conds}
	return o
}

func hRS(name string, replicas int) map[string]any {
	o := kube.WithLabels(kube.Object("apps/v1", "ReplicaSet", "app", name), map[string]string{"app": "web"})
	o["metadata"].(map[string]any)["ownerReferences"] = []any{map[string]any{"kind": "Deployment", "name": "web", "controller": true}}
	o["spec"] = map[string]any{"replicas": replicas}
	return o
}

// hPod builds a pod owned by ReplicaSet rs with one container "app".
func hPod(name, rs, phase string, ready bool, cstatus map[string]any, extra map[string]any) map[string]any {
	p := kube.WithLabels(kube.Object("v1", "Pod", "app", name), map[string]string{"app": "web"})
	if rs != "" {
		p["metadata"].(map[string]any)["ownerReferences"] = []any{map[string]any{"kind": "ReplicaSet", "name": rs, "controller": true}}
	}
	p["spec"] = map[string]any{"containers": []any{map[string]any{"name": "app", "image": "x", "env": []any{map[string]any{"name": "PW", "value": "hunter2"}},
		"resources": map[string]any{"limits": map[string]any{"memory": "128Mi"}}}}}
	rd := "False"
	if ready {
		rd = "True"
	}
	st := map[string]any{"phase": phase, "conditions": []any{map[string]any{"type": "Ready", "status": rd}}}
	if cstatus != nil {
		cstatus["name"] = "app"
		if _, ok := cstatus["ready"]; !ok {
			cstatus["ready"] = ready
		}
		st["containerStatuses"] = []any{cstatus}
	}
	for k, v := range extra {
		st[k] = v
	}
	p["status"] = st
	return p
}

func health(t *testing.T, objs ...map[string]any) hOut {
	t.Helper()
	return healthArgs(t, map[string]any{"namespace": "app", "kind": "Deployment", "name": "web"}, objs...)
}

func healthArgs(t *testing.T, args map[string]any, objs ...map[string]any) hOut {
	t.Helper()
	var out hOut
	decode(t, callTool(t, kube.SingleFakeFactory(kube.NewFakeClient(objs...)), "workload_health", args), &out)
	return out
}

func wantFinding(t *testing.T, out hOut, sev string, ref string, parts ...string) {
	t.Helper()
	for _, f := range out.Findings {
		ok := f.Severity == sev && f.EvidenceRef == ref
		for _, p := range parts {
			ok = ok && strings.Contains(f.Summary, p)
		}
		if ok {
			return
		}
	}
	t.Errorf("no %s finding %s containing %v in %+v", sev, ref, parts, out.Findings)
}

func TestWorkloadHealthCauses(t *testing.T) {
	waiting := func(reason, msg string) map[string]any {
		return map[string]any{"state": map[string]any{"waiting": map[string]any{"reason": reason, "message": msg}}}
	}
	crash := waiting("CrashLoopBackOff", "back-off")
	crash["restartCount"] = 7
	crash["lastState"] = map[string]any{"terminated": map[string]any{"reason": "Error", "exitCode": 1, "finishedAt": "2026-11-04T10:00:00Z"}}
	oom := map[string]any{"restartCount": 3, "state": map[string]any{"running": map[string]any{}},
		"lastState": map[string]any{"terminated": map[string]any{"reason": "OOMKilled", "exitCode": 137}}}
	pull := waiting("ImagePullBackOff", "Back-off pulling image")
	pull["image"] = "registry.example/app:nope"
	errpull := waiting("ErrImagePull", "rpc error")
	errpull["image"] = "registry.example/app:nope"
	cfg := waiting("CreateContainerConfigError", `secret "db" not found`)
	run := waiting("RunContainerError", "failed to start")
	notReady := map[string]any{"restartCount": 0, "ready": false, "state": map[string]any{"running": map[string]any{}}}

	cases := []struct {
		name  string
		pod   map[string]any
		sev   string
		ref   string
		parts []string
	}{
		{"crashloop", hPod("p", "web-1", "Running", false, crash, nil), "critical", "pod/p/lastState", []string{"CrashLoopBackOff", "7 restarts", "exit code 1"}},
		{"oom", hPod("p", "web-1", "Running", true, oom, nil), "critical", "pod/p/lastState", []string{"OOMKilled", "137", "128Mi"}},
		{"imagepull", hPod("p", "web-1", "Pending", false, pull, nil), "critical", "pod/p/status", []string{"ImagePullBackOff", "registry.example/app:nope"}},
		{"errimagepull", hPod("p", "web-1", "Pending", false, errpull, nil), "critical", "pod/p/status", []string{"ErrImagePull", "registry.example/app:nope"}},
		{"createconfig", hPod("p", "web-1", "Pending", false, cfg, nil), "critical", "pod/p/status", []string{"CreateContainerConfigError"}},
		{"runcontainer", hPod("p", "web-1", "Pending", false, run, nil), "critical", "pod/p/status", []string{"RunContainerError"}},
		{"unschedulable", hPod("p", "web-1", "Pending", false, nil, map[string]any{"conditions": []any{
			map[string]any{"type": "PodScheduled", "status": "False", "reason": "Unschedulable", "message": "0/3 nodes available: insufficient cpu"}}}),
			"warning", "pod/p/conditions", []string{"unschedulable", "0/3 nodes available: insufficient cpu"}},
		{"readiness", hPod("p", "web-1", "Running", false, notReady, nil), "warning", "pod/p/conditions", []string{"not Ready", "readiness"}},
		{"evicted", hPod("p", "web-1", "Failed", false, nil, map[string]any{"reason": "Evicted", "message": "The node was low on resource: memory."}),
			"warning", "pod/p/status", []string{"Evicted", "low on resource"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := health(t, hDeploy(1, 0), hRS("web-1", 1), tc.pod)
			wantFinding(t, out, tc.sev, tc.ref, tc.parts...)
			if len(out.Pods) != 1 || out.Pods[0].Name != "p" {
				t.Fatalf("pods: %+v", out.Pods)
			}
		})
	}
}

func TestWorkloadHealthPodFields(t *testing.T) {
	crash := map[string]any{"restartCount": 7, "state": map[string]any{"waiting": map[string]any{"reason": "CrashLoopBackOff"}},
		"lastState": map[string]any{"terminated": map[string]any{"reason": "Error", "exitCode": 2, "finishedAt": "2026-11-04T10:00:00Z"}}}
	out := health(t, hDeploy(1, 0), hRS("web-1", 1), hPod("p", "web-1", "Running", false, crash, nil))
	p := out.Pods[0]
	if p.Restarts != 7 || p.WaitingReason != "CrashLoopBackOff" || p.LastTermination == nil || p.LastTermination.ExitCode != 2 || p.LastTermination.Reason != "Error" {
		t.Errorf("%+v", p)
	}
}

func TestWorkloadHealthNeverReturnsEnvOrSpec(t *testing.T) {
	res := callTool(t, kube.SingleFakeFactory(kube.NewFakeClient(hDeploy(1, 1), hRS("web-1", 1), hPod("p", "web-1", "Running", true, nil, nil))),
		"workload_health", map[string]any{"namespace": "app", "kind": "Deployment", "name": "web"})
	if txt := servertest.Payload(t, res); strings.Contains(txt, "hunter2") || strings.Contains(txt, `"env"`) || strings.Contains(txt, `"spec"`) {
		t.Errorf("payload leaks pod spec: %s", txt)
	}
}

func TestWorkloadHealthRedactsMessages(t *testing.T) {
	w := map[string]any{"state": map[string]any{"waiting": map[string]any{"reason": "CreateContainerConfigError", "message": "failed: ghp_abcdefghijklmnopqrstuvwxyz0123456789"}}}
	out := health(t, hDeploy(1, 0), hRS("web-1", 1), hPod("p", "web-1", "Pending", false, w, nil))
	if txt := fmt.Sprint(out.Findings); strings.Contains(txt, "ghp_abcdefghij") {
		t.Errorf("token in findings: %s", txt)
	}
}

func TestWorkloadHealthProgressDeadlineExceeded(t *testing.T) {
	d := hDeploy(3, 1, map[string]any{"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded", "message": "ReplicaSet web-2 has timed out progressing."})
	out := health(t, d, hRS("web-1", 1))
	wantFinding(t, out, "critical", "deployment/web/conditions", "ProgressDeadlineExceeded")
	if out.Rollout.Progressing || out.Rollout.Desired != 3 || out.Rollout.Ready != 1 {
		t.Errorf("%+v", out.Rollout)
	}
}

func TestWorkloadHealthHealthyHasNoWarnings(t *testing.T) {
	d := hDeploy(2, 2, map[string]any{"type": "Progressing", "status": "True", "reason": "NewReplicaSetAvailable", "message": "ok"})
	out := health(t, d, hRS("web-1", 2),
		hPod("a", "web-1", "Running", true, map[string]any{"restartCount": 0, "ready": true}, nil),
		hPod("b", "web-1", "Running", true, map[string]any{"restartCount": 0, "ready": true}, nil))
	for _, f := range out.Findings {
		if f.Severity != "info" {
			t.Errorf("unexpected finding %+v", f)
		}
	}
	if len(out.Pods) != 2 || out.Rollout.Progressing {
		t.Errorf("%+v", out)
	}
}

func TestWorkloadHealthScaledToZero(t *testing.T) {
	out := health(t, hDeploy(0, 0), hRS("web-1", 0))
	wantFinding(t, out, "info", "deployment/web/status", "scaled to zero")
	if len(out.Findings) != 1 {
		t.Errorf("%+v", out.Findings)
	}
}

func TestWorkloadHealthMatchExpressionsSelector(t *testing.T) {
	d := hDeploy(1, 1)
	d["spec"] = map[string]any{"replicas": 1, "selector": map[string]any{"matchExpressions": []any{
		map[string]any{"key": "app", "operator": "In", "values": []any{"web", "api"}},
		map[string]any{"key": "canary", "operator": "DoesNotExist"}}}}
	other := hPod("other", "web-1", "Running", true, nil, nil)
	other["metadata"].(map[string]any)["labels"] = map[string]any{"app": "web", "canary": "yes"}
	out := health(t, d, hRS("web-1", 1), hPod("mine", "web-1", "Running", true, nil, nil), other)
	if len(out.Pods) != 1 || out.Pods[0].Name != "mine" {
		t.Errorf("pods %+v", out.Pods)
	}
}

func TestWorkloadHealthStaleAndForeignPods(t *testing.T) {
	foreign := hPod("foreign", "other-rs", "Running", true, nil, nil)
	otherRS := hRS("other-rs", 1)
	otherRS["metadata"].(map[string]any)["ownerReferences"] = []any{map[string]any{"kind": "Deployment", "name": "other", "controller": true}}
	bare := hPod("bare", "", "Running", true, nil, nil)
	out := health(t, hDeploy(1, 1), hRS("web-1", 0), hRS("web-2", 1), otherRS,
		hPod("old", "web-1", "Running", false, nil, nil), hPod("new", "web-2", "Running", true, nil, nil), foreign, bare)
	var names []string
	for _, p := range out.Pods {
		names = append(names, p.Name)
	}
	if fmt.Sprint(names) != "[bare new]" || !strings.Contains(out.Note, "2 pod(s) ignored") {
		t.Errorf("pods %v note %q", names, out.Note)
	}
}

func TestWorkloadHealthStatefulSetAndDaemonSet(t *testing.T) {
	sts := kube.Object("apps/v1", "StatefulSet", "app", "db")
	sts["spec"] = map[string]any{"replicas": 3, "selector": map[string]any{"matchLabels": map[string]any{"app": "db"}}}
	sts["status"] = map[string]any{"readyReplicas": 1, "updatedReplicas": 3}
	pod := kube.WithLabels(kube.Object("v1", "Pod", "app", "db-0"), map[string]string{"app": "db"})
	pod["metadata"].(map[string]any)["ownerReferences"] = []any{map[string]any{"kind": "StatefulSet", "name": "db", "controller": true}}
	pod["status"] = map[string]any{"phase": "Running"}
	out := healthArgs(t, map[string]any{"namespace": "app", "kind": "StatefulSet", "name": "db"}, sts, pod)
	if out.Rollout.Unavailable != 2 || len(out.Pods) != 1 {
		t.Errorf("%+v", out)
	}
	wantFinding(t, out, "warning", "statefulset/db/status", "1 of 3")

	ds := kube.Object("apps/v1", "DaemonSet", "app", "agent")
	ds["spec"] = map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"app": "agent"}}}
	ds["status"] = map[string]any{"desiredNumberScheduled": 4, "numberReady": 4, "updatedNumberScheduled": 4}
	out = healthArgs(t, map[string]any{"namespace": "app", "kind": "daemonset", "name": "agent"}, ds)
	if out.Rollout.Desired != 4 || len(out.Findings) != 1 || out.Findings[0].Severity != "info" {
		t.Errorf("%+v", out)
	}
}

func TestWorkloadHealthUnhealthyFirstAndCapped(t *testing.T) {
	objs := []map[string]any{hDeploy(60, 59), hRS("web-1", 60)}
	for i := 0; i < 59; i++ {
		objs = append(objs, hPod(fmt.Sprintf("ok-%02d", i), "web-1", "Running", true, nil, nil))
	}
	objs = append(objs, hPod("zz-bad", "web-1", "Running", false, nil, nil))
	out := health(t, objs...)
	if len(out.Pods) != 50 || !out.Truncated || out.Pods[0].Name != "zz-bad" || !strings.Contains(out.Note, "capped at 50") {
		t.Errorf("pods %d first %s trunc %v note %q", len(out.Pods), out.Pods[0].Name, out.Truncated, out.Note)
	}
}

func TestWorkloadHealthUnsupportedKind(t *testing.T) {
	for _, k := range []string{"Pod", "Secret", "Job", ""} {
		res := callTool(t, kube.SingleFakeFactory(kube.NewFakeClient()), "workload_health", map[string]any{"namespace": "app", "kind": k, "name": "x"})
		if !res.IsError || !strings.Contains(servertest.Text(t, res), "Deployment, StatefulSet, DaemonSet") {
			t.Errorf("%q: %v %s", k, res.IsError, servertest.Text(t, res))
		}
	}
}

func TestWorkloadHealthNotFoundIsTyped(t *testing.T) {
	res := callTool(t, kube.SingleFakeFactory(kube.NewFakeClient()), "workload_health", map[string]any{"namespace": "app", "kind": "Deployment", "name": "nope"})
	if !res.IsError {
		t.Error("want error")
	}
}

func setStatuses(p map[string]any, key string, cs ...any) map[string]any {
	p["status"].(map[string]any)[key] = cs
	return p
}

func terminated(reason string, exit int, finished string) map[string]any {
	return map[string]any{"terminated": map[string]any{"reason": reason, "exitCode": exit, "finishedAt": finished}}
}

func TestWorkloadHealthMidRolloutKeepsBothRevisions(t *testing.T) {
	out := health(t, hDeploy(2, 1), hRS("web-1", 1), hRS("web-2", 1),
		hPod("old", "web-1", "Running", true, nil, nil), hPod("new", "web-2", "Running", false, nil, nil))
	if len(out.Pods) != 2 {
		t.Errorf("both revisions must be present: %+v", out.Pods)
	}
}

func TestWorkloadHealthKeepsPodsWithUnknownReplicaSet(t *testing.T) {
	out := health(t, hDeploy(1, 1), hRS("web-1", 1), hPod("lost", "gone-rs", "Running", true, nil, nil))
	if len(out.Pods) != 1 || !strings.Contains(out.Note, "could not be attributed") {
		t.Errorf("pods %+v note %q", out.Pods, out.Note)
	}
}

func TestWorkloadHealthCurrentTerminatedState(t *testing.T) {
	oom := hPod("p", "web-1", "Failed", false, nil, nil)
	setStatuses(oom, "containerStatuses", map[string]any{"name": "app", "ready": false, "state": terminated("OOMKilled", 137, "2026-11-04T10:00:00Z")})
	out := health(t, hDeploy(1, 0), hRS("web-1", 1), oom)
	wantFinding(t, out, "critical", "pod/p/lastState", "OOMKilled", "128Mi")
	if lt := out.Pods[0].LastTermination; lt == nil || lt.Reason != "OOMKilled" || lt.ExitCode != 137 {
		t.Errorf("%+v", out.Pods[0])
	}

	job := hPod("j", "web-1", "Failed", false, nil, nil)
	setStatuses(job, "containerStatuses", map[string]any{"name": "app", "ready": false, "state": terminated("Error", 1, "2026-11-04T10:00:00Z")})
	out = health(t, hDeploy(1, 0), hRS("web-1", 1), job)
	wantFinding(t, out, "critical", "pod/j/lastState", "exit code 1")
	if lt := out.Pods[0].LastTermination; lt == nil || lt.ExitCode != 1 {
		t.Errorf("%+v", out.Pods[0])
	}
}

func TestWorkloadHealthSelectsFailingContainer(t *testing.T) {
	p := hPod("p", "web-1", "Running", false, nil, nil)
	setStatuses(p, "containerStatuses",
		map[string]any{"name": "side", "ready": true, "state": map[string]any{"running": map[string]any{}}, "lastState": terminated("Completed", 0, "2020-01-01T00:00:00Z")},
		map[string]any{"name": "app", "ready": false, "restartCount": 2, "state": map[string]any{"running": map[string]any{}}, "lastState": terminated("OOMKilled", 137, "2026-11-04T10:00:00Z")})
	out := health(t, hDeploy(1, 0), hRS("web-1", 1), p)
	if lt := out.Pods[0].LastTermination; lt == nil || lt.Reason != "OOMKilled" {
		t.Errorf("%+v", out.Pods[0])
	}
}

func TestWorkloadHealthInitContainers(t *testing.T) {
	crash := hPod("c", "web-1", "Pending", false, nil, nil)
	setStatuses(crash, "initContainerStatuses", map[string]any{"name": "migrate", "restartCount": 4,
		"state":     map[string]any{"waiting": map[string]any{"reason": "CrashLoopBackOff"}},
		"lastState": terminated("Error", 3, "2026-11-04T10:00:00Z")})
	out := health(t, hDeploy(1, 0), hRS("web-1", 1), crash)
	wantFinding(t, out, "critical", "pod/c/lastState", "init:migrate", "CrashLoopBackOff", "exit code 3")
	if out.Pods[0].WaitingReason != "Init:CrashLoopBackOff" {
		t.Errorf("%+v", out.Pods[0])
	}

	stuck := hPod("s", "web-1", "Pending", false, nil, nil)
	stuck["metadata"].(map[string]any)["creationTimestamp"] = "2020-01-01T00:00:00Z"
	setStatuses(stuck, "initContainerStatuses", map[string]any{"name": "wait-db", "ready": false,
		"state": map[string]any{"running": map[string]any{"startedAt": "2020-01-01T00:00:05Z"}}})
	out = health(t, hDeploy(1, 0), hRS("web-1", 1), stuck)
	wantFinding(t, out, "warning", "pod/s/status", "init container wait-db still running after")

	fresh := hPod("f", "web-1", "Pending", false, nil, nil)
	setStatuses(fresh, "initContainerStatuses", map[string]any{"name": "wait-db", "ready": false,
		"state": map[string]any{"running": map[string]any{"startedAt": time.Now().UTC().Format(time.RFC3339)}}})
	out = health(t, hDeploy(1, 0), hRS("web-1", 1), fresh)
	for _, f := range out.Findings {
		if strings.Contains(f.Summary, "still running") {
			t.Errorf("fresh init flagged: %+v", f)
		}
	}
}

func TestWorkloadHealthTerminatingAndOtherFailed(t *testing.T) {
	term := hPod("t", "web-1", "Running", true, nil, nil)
	term["metadata"].(map[string]any)["deletionTimestamp"] = "2020-01-01T00:00:00Z"
	out := health(t, hDeploy(1, 1), hRS("web-1", 1), term)
	wantFinding(t, out, "warning", "pod/t/status", "Terminating")

	failed := hPod("d", "web-1", "Failed", false, nil, map[string]any{"reason": "DeadlineExceeded", "message": "Pod was active longer than allowed"})
	out = health(t, hDeploy(1, 0), hRS("web-1", 1), failed)
	wantFinding(t, out, "warning", "pod/d/status", "DeadlineExceeded", "active longer")
}

func TestWorkloadHealthRedactsTokenInWaitingMessage(t *testing.T) {
	w := map[string]any{"state": map[string]any{"waiting": map[string]any{"reason": "ImagePullBackOff", "message": "pull failed ghp_abcdefghijklmnopqrstuvwxyz0123456789"}}, "image": "r/app:1"}
	out := health(t, hDeploy(1, 0), hRS("web-1", 1), hPod("p", "web-1", "Pending", false, w, nil))
	if strings.Contains(fmt.Sprint(out.Findings), "ghp_abcdefghij") {
		t.Errorf("token in findings: %+v", out.Findings)
	}
}

// A container that keeps crashing is reported in every phase of the
// restart cycle, not only while it waits in CrashLoopBackOff.
func TestWorkloadHealthRestartingRepeatedly(t *testing.T) {
	findingsFor := func(cs map[string]any, phase string) hOut {
		t.Helper()
		p := hPod("p", "web-1", phase, false, nil, nil)
		cs["name"] = "app"
		cs["ready"] = false
		setStatuses(p, "containerStatuses", cs)
		return health(t, hDeploy(1, 0), hRS("web-1", 1), p)
	}
	countRestarting := func(out hOut) int {
		n := 0
		for _, f := range out.Findings {
			if strings.Contains(f.Summary, "restarting repeatedly") {
				n++
			}
		}
		return n
	}

	t.Run("running after a crash", func(t *testing.T) {
		out := findingsFor(map[string]any{"restartCount": 3, "state": map[string]any{"running": map[string]any{}},
			"lastState": terminated("Error", 1, "2026-11-04T10:00:00Z")}, "Running")
		wantFinding(t, out, "critical", "pod/p/lastState", "container app is restarting repeatedly: 3 restarts, last exit code 1 (Error)")
	})
	t.Run("terminated between restarts", func(t *testing.T) {
		out := findingsFor(map[string]any{"restartCount": 2, "state": terminated("Error", 1, "2026-11-04T10:01:00Z"),
			"lastState": terminated("Error", 1, "2026-11-04T10:00:00Z")}, "Running")
		wantFinding(t, out, "critical", "pod/p/lastState", "container app is restarting repeatedly: 2 restarts, last exit code 1 (Error)")
		for _, f := range out.Findings {
			if strings.Contains(f.Summary, "terminated with exit code") {
				t.Errorf("duplicate plain termination finding: %+v", out.Findings)
			}
		}
	})
	t.Run("waiting other than CrashLoopBackOff", func(t *testing.T) {
		out := findingsFor(map[string]any{"restartCount": 4, "state": map[string]any{"waiting": map[string]any{"reason": "ContainerCreating"}},
			"lastState": terminated("Error", 2, "2026-11-04T10:00:00Z")}, "Running")
		wantFinding(t, out, "critical", "pod/p/lastState", "restarting repeatedly: 4 restarts, last exit code 2 (Error)")
	})
	t.Run("CrashLoopBackOff keeps its own finding only", func(t *testing.T) {
		out := findingsFor(map[string]any{"restartCount": 5, "state": map[string]any{"waiting": map[string]any{"reason": "CrashLoopBackOff"}},
			"lastState": terminated("Error", 1, "2026-11-04T10:00:00Z")}, "Running")
		wantFinding(t, out, "critical", "pod/p/lastState", "CrashLoopBackOff", "5 restarts", "exit code 1")
		if n := countRestarting(out); n != 0 {
			t.Errorf("CrashLoopBackOff also got %d restarting findings: %+v", n, out.Findings)
		}
	})
	t.Run("restarts with exit 0", func(t *testing.T) {
		out := findingsFor(map[string]any{"restartCount": 3, "state": map[string]any{"running": map[string]any{}},
			"lastState": terminated("Completed", 0, "2026-11-04T10:00:00Z")}, "Running")
		if n := countRestarting(out); n != 0 {
			t.Errorf("exit 0 restarts reported as crashing: %+v", out.Findings)
		}
		for _, f := range out.Findings {
			if f.Severity == "critical" {
				t.Errorf("critical finding for clean restarts: %+v", f)
			}
		}
	})
	t.Run("OOMKilled keeps its own finding without duplicate", func(t *testing.T) {
		out := findingsFor(map[string]any{"restartCount": 3, "state": map[string]any{"running": map[string]any{}},
			"lastState": terminated("OOMKilled", 137, "2026-11-04T10:00:00Z")}, "Running")
		wantFinding(t, out, "critical", "pod/p/lastState", "OOMKilled", "128Mi")
		if n := countRestarting(out); n != 0 {
			t.Errorf("OOMKilled also got %d restarting findings: %+v", n, out.Findings)
		}
		if len(out.Findings) != 1 {
			t.Errorf("want exactly the OOMKilled finding, got %+v", out.Findings)
		}
	})
	t.Run("first termination without restarts keeps the plain wording", func(t *testing.T) {
		out := findingsFor(map[string]any{"restartCount": 0, "state": terminated("Error", 1, "2026-11-04T10:00:00Z")}, "Failed")
		wantFinding(t, out, "critical", "pod/p/lastState", "terminated with exit code 1 (Error)")
		if n := countRestarting(out); n != 0 {
			t.Errorf("%+v", out.Findings)
		}
	})
}

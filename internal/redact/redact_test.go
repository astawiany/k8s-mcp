package redact

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// obj parses a JSON literal into the map shape the dynamic client produces.
func obj(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("bad fixture: %v\n%s", err, s)
	}
	return m
}

// dump serialises v so assertions can check that a sensitive string appears
// nowhere in the output, whatever path it would have taken.
func dump(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// get walks a path of map keys and list indexes.
func get(t *testing.T, v any, path ...any) any {
	t.Helper()
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				t.Fatalf("path %v: not a map at %q", path, k)
			}
			v = m[k]
		case int:
			l, ok := v.([]any)
			if !ok || k >= len(l) {
				t.Fatalf("path %v: not a list or short at %d", path, k)
			}
			v = l[k]
		}
	}
	return v
}

func assertAbsent(t *testing.T, out any, secrets ...string) {
	t.Helper()
	s := dump(t, out)
	for _, sec := range secrets {
		if strings.Contains(s, sec) {
			t.Errorf("sensitive value %q leaked in output: %s", sec, s)
		}
	}
}

func TestIsSecretKind(t *testing.T) {
	cases := []struct {
		group, kind string
		want        bool
	}{
		{"", "Secret", true},
		{"", "secret", true},
		{"", "SECRET", true},
		{"", "secrets", true},
		{"", "Secrets", true},
		{"core", "Secret", true},
		{"v1", "Secret", true},
		{"", " Secret ", true},
		{"", "SecretList", true},
		{"", "ConfigMap", false},
		{"", "configmaps", false},
		{"apps", "Deployment", false},
		{"external-secrets.io", "ExternalSecret", false},
		{"bitnami.com", "SealedSecret", false},
		{"example.com", "Secret", false},
	}
	for _, c := range cases {
		if got := IsSecretKind(c.group, c.kind); got != c.want {
			t.Errorf("IsSecretKind(%q, %q) = %v, want %v", c.group, c.kind, got, c.want)
		}
	}
}

func TestObjectSecretDataRedactedKeysKept(t *testing.T) {
	in := obj(t, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"db"},
		"type":"Opaque",
		"data":{"password":"aHVudGVyMg==","user":"YWRtaW4="},
		"stringData":{"token":"plain-token-value"}}`)
	out := Object(in)
	data := get(t, out, "data").(map[string]any)
	if len(data) != 2 || data["password"] != Redacted || data["user"] != Redacted {
		t.Fatalf("data = %v", data)
	}
	sd := get(t, out, "stringData").(map[string]any)
	if len(sd) != 1 || sd["token"] != Redacted {
		t.Fatalf("stringData = %v", sd)
	}
	if get(t, out, "metadata", "name") != "db" || get(t, out, "type") != "Opaque" {
		t.Fatalf("non-secret fields changed: %v", out)
	}
	assertAbsent(t, out, "aHVudGVyMg==", "YWRtaW4=", "plain-token-value")
}

func TestObjectSecretCaseVariantsAndOddShapes(t *testing.T) {
	cases := map[string]string{
		"lowercase kind":    `{"apiVersion":"v1","kind":"secret","data":{"k":"LEAK1"}}`,
		"uppercase kind":    `{"apiVersion":"v1","kind":"SECRET","data":{"k":"LEAK1"}}`,
		"no apiVersion":     `{"kind":"Secret","data":{"k":"LEAK1"}}`,
		"capitalised keys":  `{"Kind":"Secret","Data":{"k":"LEAK1"},"StringData":{"k":"LEAK1"}}`,
		"data not a map":    `{"kind":"Secret","data":"LEAK1"}`,
		"data list":         `{"kind":"Secret","data":["LEAK1"]}`,
		"stringData nested": `{"kind":"Secret","stringData":{"k":{"x":"LEAK1"}}}`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			assertAbsent(t, Object(obj(t, src)), "LEAK1")
		})
	}
}

func TestObjectConfigMapUntouched(t *testing.T) {
	src := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cfg","annotations":{"a":"b"}},
		"data":{"password":"not-a-secret-by-design","LOG_LEVEL":"debug"}}`
	in := obj(t, src)
	out := Object(in)
	if !reflect.DeepEqual(out, obj(t, src)) {
		t.Fatalf("ConfigMap changed:\n got %v\nwant %v", out, obj(t, src))
	}
}

func TestObjectRemovesManagedFields(t *testing.T) {
	in := obj(t, `{"kind":"ConfigMap","metadata":{"name":"x","managedFields":[{"manager":"kubectl"}]},
		"items":[{"kind":"Pod","metadata":{"name":"p","managedFields":[{"manager":"m"}]}}]}`)
	out := Object(in)
	if _, ok := get(t, out, "metadata").(map[string]any)["managedFields"]; ok {
		t.Fatalf("managedFields kept: %v", out)
	}
	if _, ok := get(t, out, "items", 0, "metadata").(map[string]any)["managedFields"]; ok {
		t.Fatalf("nested managedFields kept: %v", out)
	}
	if get(t, out, "metadata", "name") != "x" {
		t.Fatalf("metadata damaged: %v", out)
	}
}

const lastApplied = "kubectl.kubernetes.io/last-applied-configuration"

func withAnnotation(t *testing.T, kind string, embedded any) map[string]any {
	t.Helper()
	b, err := json.Marshal(embedded)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       kind,
		"metadata": map[string]any{
			"name":        "app",
			"annotations": map[string]any{lastApplied: string(b), "keep": "me"},
		},
	}
}

func TestObjectLastAppliedEmbeddedSecretRedacted(t *testing.T) {
	embedded := obj(t, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s"},
		"data":{"password":"RU1CRURERUQ="},"stringData":{"api":"embedded-plain"}}`)
	out := Object(withAnnotation(t, "Deployment", embedded))
	assertAbsent(t, out, "RU1CRURERUQ=", "embedded-plain")

	ann := get(t, out, "metadata", "annotations").(map[string]any)
	if ann["keep"] != "me" {
		t.Fatalf("other annotation changed: %v", ann)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(ann[lastApplied].(string)), &parsed); err != nil {
		t.Fatalf("annotation no longer JSON: %v", err)
	}
	if get(t, parsed, "data", "password") != Redacted || get(t, parsed, "metadata", "name") != "s" {
		t.Fatalf("embedded secret not redacted as expected: %v", parsed)
	}
}

func TestObjectLastAppliedOnSecretItself(t *testing.T) {
	embedded := obj(t, `{"apiVersion":"v1","kind":"Secret","data":{"k":"SELFLEAK"}}`)
	in := withAnnotation(t, "Secret", embedded)
	in["apiVersion"] = "v1"
	in["data"] = map[string]any{"k": "SELFLEAK"}
	assertAbsent(t, Object(in), "SELFLEAK")
}

func TestObjectLastAppliedEmbeddedEnvMasked(t *testing.T) {
	embedded := obj(t, `{"apiVersion":"apps/v1","kind":"Deployment","spec":{"template":{"spec":{
		"containers":[{"name":"c","env":[{"name":"DB_PASSWORD","value":"ENVLEAK"},{"name":"LOG_LEVEL","value":"debug"}]}]}}}}`)
	out := Object(withAnnotation(t, "Deployment", embedded))
	assertAbsent(t, out, "ENVLEAK")
	if !strings.Contains(dump(t, out), "debug") {
		t.Fatalf("harmless env value lost: %v", out)
	}
}

func TestObjectLastAppliedUnparsable(t *testing.T) {
	in := withAnnotation(t, "Deployment", nil)
	in["metadata"].(map[string]any)["annotations"].(map[string]any)[lastApplied] = `{"kind":"Secret","data":{"k":"TRUNCLEAK"`
	out := Object(in)
	if got := get(t, out, "metadata", "annotations", lastApplied); got != Redacted {
		t.Fatalf("unparsable annotation = %v, want %q", got, Redacted)
	}
}

func TestObjectLastAppliedNonString(t *testing.T) {
	in := withAnnotation(t, "Deployment", nil)
	in["metadata"].(map[string]any)["annotations"].(map[string]any)[lastApplied] = map[string]any{"kind": "Secret", "data": map[string]any{"k": "ODDLEAK"}}
	assertAbsent(t, Object(in), "ODDLEAK")
}

func TestObjectNestedLastAppliedInsideLastApplied(t *testing.T) {
	inner := withAnnotation(t, "Secret", obj(t, `{"kind":"Secret","data":{"k":"DEEPLEAK"}}`))
	inner["kind"] = "ConfigMap" // outer layer of the embedded object is not a Secret
	assertAbsent(t, Object(withAnnotation(t, "Deployment", inner)), "DEEPLEAK")
}

func TestObjectOtherJSONAnnotationWithSecret(t *testing.T) {
	b, _ := json.Marshal(obj(t, `{"kind":"Secret","stringData":{"k":"OTHERANNLEAK"}}`))
	in := obj(t, `{"kind":"ConfigMap","metadata":{"annotations":{"tool.example.com/snapshot":"","plain":"{not json"}}}`)
	in["metadata"].(map[string]any)["annotations"].(map[string]any)["tool.example.com/snapshot"] = string(b)
	out := Object(in)
	assertAbsent(t, out, "OTHERANNLEAK")
	if get(t, out, "metadata", "annotations", "plain") != "{not json" {
		t.Fatalf("non-JSON ordinary annotation changed: %v", out)
	}
}

func TestObjectListOfSecrets(t *testing.T) {
	cases := map[string]string{
		"kind List with Secret items": `{"apiVersion":"v1","kind":"List","items":[
			{"kind":"ConfigMap","data":{"a":"fine"}},
			{"apiVersion":"v1","kind":"Secret","data":{"k":"LISTLEAK"}}]}`,
		// Raw API list responses omit kind on items.
		"SecretList with kindless items": `{"apiVersion":"v1","kind":"SecretList","items":[
			{"metadata":{"name":"a"},"data":{"k":"LISTLEAK"},"stringData":{"k":"LISTLEAK"}}]}`,
		"Secret deep inside a custom resource": `{"apiVersion":"example.com/v1","kind":"Bundle","spec":{
			"resources":[{"manifest":{"kind":"Secret","data":{"k":"LISTLEAK"}}}]}}`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			out := Object(obj(t, src))
			assertAbsent(t, out, "LISTLEAK")
			if strings.Contains(src, `"fine"`) && !strings.Contains(dump(t, out), `"fine"`) {
				t.Fatalf("ConfigMap item damaged: %v", out)
			}
		})
	}
}

func TestObjectDoesNotMutateInput(t *testing.T) {
	src := `{"apiVersion":"v1","kind":"List","metadata":{"managedFields":[{"m":1}],
		"annotations":{"` + lastApplied + `":"{\"kind\":\"Secret\",\"data\":{\"k\":\"v\"}}"}},
		"items":[{"kind":"Secret","data":{"k":"v"},"stringData":{"s":"v"}},
		{"kind":"Pod","spec":{"containers":[{"name":"c","env":[{"name":"TOKEN","value":"t"}]}]}}]}`
	in := obj(t, src)
	_ = Object(in)
	_ = Workload(in)
	if !reflect.DeepEqual(in, obj(t, src)) {
		t.Fatalf("input mutated: %v", in)
	}
}

func TestObjectNil(t *testing.T) {
	if Object(nil) != nil || Workload(nil) != nil || PodSpec(nil) != nil {
		t.Fatal("nil input should give nil output")
	}
}

func TestEnvValue(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
	cases := []struct {
		name, value string
		masked      bool
	}{
		{"DB_PASSWORD", "hunter2", true},
		{"db_password", "hunter2", true},
		{"DB_PASS", "hunter2", true},
		{"API_TOKEN", "x", true},
		{"CLIENT_SECRET", "x", true},
		{"AWS_SECRET_ACCESS_KEY", "x", true},
		{"ApiKey", "x", true},
		{"GOOGLE_APPLICATION_CREDENTIALS", "/var/run/creds.json", true},
		{"BASIC_AUTH", "x", true},
		{"TLS_CERT", "x", true},
		{"PRIVATE_DATA", "x", true},
		{"LOG_LEVEL", "debug", false},
		{"PORT", "8080", false},
		{"HOME", "/root", false},
		{"X", jwt, true},
		{"X", "Bearer " + jwt, true},
		{"X", "ghp_" + strings.Repeat("a", 36), true},
		{"X", "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz", true},
		{"X", "gho_" + strings.Repeat("B", 36), true},
		{"X", "AKIAIOSFODNN7EXAMPLE", true},
		{"X", pem, true},
		{"X", "-----begin private key-----", true},
		{"X", base64.StdEncoding.EncodeToString([]byte(pem)), true},
		{"X", base64.StdEncoding.EncodeToString([]byte(jwt)), true},
		{"X", base64.StdEncoding.EncodeToString([]byte("AKIAIOSFODNN7EXAMPLE")), true},
		{"DATABASE_URL", "postgres://app:s3cr3t@db:5432/app", true},
		{"X", "aGVsbG8gd29ybGQgdGhpcyBpcyBmaW5l", false}, // base64 of harmless text
		{"X", "eyJ-not-a-jwt", false},
		{"DB_PASSWORD", "", false},
	}
	for _, c := range cases {
		got := EnvValue(c.name, c.value)
		if c.masked && got != Redacted {
			t.Errorf("EnvValue(%q, %q) = %q, want masked", c.name, c.value, got)
		}
		if !c.masked && got != c.value {
			t.Errorf("EnvValue(%q, %q) = %q, want unchanged", c.name, c.value, got)
		}
	}
}

func podSpecFixture(t *testing.T) map[string]any {
	return obj(t, `{
		"containers":[{"name":"app","env":[
			{"name":"DB_PASSWORD","value":"hunter2"},
			{"name":"LOG_LEVEL","value":"debug"},
			{"name":"X","value":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXZhbHVl"},
			{"name":"API_TOKEN","valueFrom":{"secretKeyRef":{"name":"s","key":"token"}}}]}],
		"initContainers":[{"name":"init","env":[{"name":"INIT_SECRET","value":"initleak"}]}],
		"ephemeralContainers":[{"name":"dbg","env":[{"name":"GH","value":"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}]}`)
}

func TestPodSpec(t *testing.T) {
	in := podSpecFixture(t)
	out := PodSpec(in)
	if !reflect.DeepEqual(in, podSpecFixture(t)) {
		t.Fatal("PodSpec mutated its input")
	}
	assertAbsent(t, out, "hunter2", "initleak", "ghp_aaaa", "eyJhbGciOiJIUzI1NiJ9")
	if get(t, out, "containers", 0, "env", 1, "value") != "debug" {
		t.Fatalf("LOG_LEVEL changed: %v", out)
	}
	ref := get(t, out, "containers", 0, "env", 3)
	want := obj(t, `{"name":"API_TOKEN","valueFrom":{"secretKeyRef":{"name":"s","key":"token"}}}`)
	if !reflect.DeepEqual(ref, want) {
		t.Fatalf("valueFrom changed: %v", ref)
	}
}

func TestWorkload(t *testing.T) {
	ps := `{"containers":[{"name":"c","env":[{"name":"DB_PASSWORD","value":"WLLEAK"},{"name":"LOG_LEVEL","value":"debug"}]}],
		"initContainers":[{"name":"i","env":[{"name":"TOKEN","value":"WLLEAK"}]}]}`
	meta := `"metadata":{"name":"w","managedFields":[{"manager":"MFLEAK"}]}`
	cases := map[string]string{
		"Pod":         `{"apiVersion":"v1","kind":"Pod",` + meta + `,"spec":` + ps + `}`,
		"Deployment":  `{"apiVersion":"apps/v1","kind":"Deployment",` + meta + `,"spec":{"template":{"spec":` + ps + `}}}`,
		"StatefulSet": `{"apiVersion":"apps/v1","kind":"StatefulSet",` + meta + `,"spec":{"template":{"spec":` + ps + `}}}`,
		"DaemonSet":   `{"apiVersion":"apps/v1","kind":"DaemonSet",` + meta + `,"spec":{"template":{"spec":` + ps + `}}}`,
		"ReplicaSet":  `{"apiVersion":"apps/v1","kind":"ReplicaSet",` + meta + `,"spec":{"template":{"spec":` + ps + `}}}`,
		"Job":         `{"apiVersion":"batch/v1","kind":"Job",` + meta + `,"spec":{"template":{"spec":` + ps + `}}}`,
		"CronJob":     `{"apiVersion":"batch/v1","kind":"CronJob",` + meta + `,"spec":{"jobTemplate":{"spec":{"template":{"spec":` + ps + `}}}}}`,
		"PodTemplate": `{"apiVersion":"v1","kind":"PodTemplate",` + meta + `,"template":{"spec":` + ps + `}}`,
		"List of Deployments": `{"apiVersion":"v1","kind":"List","items":[{"kind":"Deployment",` + meta +
			`,"spec":{"template":{"spec":` + ps + `}}}]}`,
		"DeploymentList kindless items": `{"apiVersion":"apps/v1","kind":"DeploymentList","items":[{` + meta +
			`,"spec":{"template":{"spec":` + ps + `}}}]}`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			in := obj(t, src)
			out := Workload(in)
			assertAbsent(t, out, "WLLEAK", "MFLEAK")
			if !strings.Contains(dump(t, out), `"debug"`) {
				t.Fatalf("harmless env value lost: %v", out)
			}
			if !reflect.DeepEqual(in, obj(t, src)) {
				t.Fatal("Workload mutated its input")
			}
		})
	}
}

func TestWorkloadAppliesObjectRules(t *testing.T) {
	out := Workload(obj(t, `{"kind":"Secret","data":{"k":"WLSECRET"}}`))
	assertAbsent(t, out, "WLSECRET")
}

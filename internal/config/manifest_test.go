// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"text/template"

	"gopkg.in/yaml.v3"
	"soundpost/internal/appcore"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// ---- YAML navigation (the manifests are parsed, never grepped) ----

func repoPath(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}

func loadYAML(t testing.TB, file string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err = yaml.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return out
}

func at(t testing.TB, v any, keys ...any) any {
	t.Helper()
	for _, k := range keys {
		switch node := v.(type) {
		case map[string]any:
			v = node[k.(string)]
		case []any:
			v = node[k.(int)]
		default:
			return nil
		}
	}
	return v
}

func strs(v any) []string {
	var out []string
	for _, e := range asList(v) {
		out = append(out, fmt.Sprint(e))
	}
	return out
}

func asList(v any) []any { l, _ := v.([]any); return l }
func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// ---- a Helm-compatible renderer built on text/template ----
//
// It supports exactly the functions the chart uses (default, required, fail, int, quote,
// toJson, add1, printf, len, lt, ne). It proves properties of the rendered documents; it does
// not prove that Helm itself accepts the chart (helm lint/template are run separately and, when
// a helm binary is on PATH, this test also checks Helm's own output with the same assertions).

func renderChart(t testing.TB, overrides map[string]any) []map[string]any {
	t.Helper()
	values := loadYAML(t, repoPath("deploy", "helm", "soundpost", "values.yaml"))
	merge(values, overrides)
	text, err := renderTemplates(values)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return splitDocuments(t, text)
}

func merge(dst, src map[string]any) {
	for k, v := range src {
		if m, ok := v.(map[string]any); ok {
			if d, ok := dst[k].(map[string]any); ok {
				merge(d, m)
				continue
			}
		}
		dst[k] = v
	}
}

func renderTemplates(values map[string]any) (string, error) {
	funcs := template.FuncMap{
		"default": func(def, v any) any {
			if s, ok := v.(string); ok && s == "" || v == nil {
				return def
			}
			return v
		},
		"required": func(msg string, v any) (any, error) {
			if s, ok := v.(string); v == nil || ok && s == "" {
				return nil, errors.New(msg)
			}
			return v, nil
		},
		"fail":   func(msg string) (string, error) { return "", errors.New(msg) },
		"int":    func(v any) int { n, _ := strconv.Atoi(fmt.Sprint(v)); return n },
		"add1":   func(v any) int { n, _ := strconv.Atoi(fmt.Sprint(v)); return n + 1 },
		"quote":  func(v any) string { return strconv.Quote(fmt.Sprint(v)) },
		"toJson": func(v any) (string, error) { b, err := json.Marshal(v); return string(b), err },
	}
	files, err := filepath.Glob(repoPath("deploy", "helm", "soundpost", "templates", "*.yaml"))
	if err != nil || len(files) == 0 {
		return "", errors.New("no templates")
	}
	sort.Strings(files)
	var out strings.Builder
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		tpl, err := template.New(filepath.Base(file)).Funcs(funcs).Option("missingkey=error").Parse(string(raw))
		if err != nil {
			return "", fmt.Errorf("%s: %w", file, err)
		}
		var buf bytes.Buffer
		data := map[string]any{"Values": values, "Release": map[string]any{"Name": "t", "Namespace": "sp"}}
		if err = tpl.Execute(&buf, data); err != nil {
			return "", err
		}
		out.WriteString("\n---\n")
		out.Write(buf.Bytes())
	}
	return out.String(), nil
}

var documentSeparator = regexp.MustCompile(`(?m)^---\s*$`)

func splitDocuments(t testing.TB, text string) []map[string]any {
	t.Helper()
	var docs []map[string]any
	for _, part := range documentSeparator.Split(text, -1) {
		if strings.TrimSpace(part) == "" {
			continue
		}
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(part), &doc); err != nil {
			t.Fatalf("rendered document is not YAML: %v\n%s", err, part)
		}
		if doc != nil {
			docs = append(docs, doc)
		}
	}
	return docs
}

func ofKind(docs []map[string]any, kind string) []map[string]any {
	var out []map[string]any
	for _, d := range docs {
		if d["kind"] == kind {
			out = append(out, d)
		}
	}
	return out
}

var chartImage = map[string]any{"image": map[string]any{"repository": "registry.example.invalid/soundpost", "tag": "1.0.0"}}

// helmBinary returns a helm executable if one is on PATH or named by SOUNDPOST_HELM.
func helmBinary() string {
	if p := os.Getenv("SOUNDPOST_HELM"); p != "" {
		return p
	}
	p, _ := exec.LookPath("helm")
	return p
}

// renderedBoth returns the documents rendered by the Go renderer and, when a helm binary exists,
// by Helm itself. Every chart assertion below runs on each.
func renderedBoth(t *testing.T, overrides map[string]any, sets ...string) map[string][]map[string]any {
	t.Helper()
	out := map[string][]map[string]any{"go-template": renderChart(t, overrides)}
	if helm := helmBinary(); helm != "" {
		chart, err := filepath.Abs(repoPath("deploy", "helm", "soundpost"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(helm, ".exe") { // a Windows helm driven from WSL needs a Windows path
			if out, err := exec.Command("wslpath", "-w", chart).Output(); err == nil {
				chart = strings.TrimSpace(string(out))
			}
		}
		args := []string{"template", "t", chart, "--namespace", "sp", "--set", "image.repository=registry.example.invalid/soundpost,image.tag=1.0.0"}
		for _, s := range sets {
			args = append(args, "--set", s)
		}
		raw, err := exec.Command(helm, args...).Output()
		if err != nil {
			t.Fatalf("helm template: %v", err)
		}
		out["helm"] = splitDocuments(t, string(raw))
	} else {
		t.Log("no helm binary on PATH or SOUNDPOST_HELM: only the Go renderer was checked (Helm itself NOT run by this test)")
	}
	return out
}

// ---- Compose / Helm permission separation ----

func TestNativeRecipeSeparatesHelperAndServerPermissions(t *testing.T) {
	forbidden := func(where string, caps []string, security []string, privileged any) {
		for _, c := range caps {
			if up := strings.ToUpper(strings.TrimPrefix(strings.ToUpper(c), "CAP_")); up == "SYS_ADMIN" || up == "ALL" || up == "SYS_PTRACE" || up == "BPF" {
				t.Errorf("%s adds capability %s", where, c)
			}
		}
		for _, s := range security {
			if l := strings.ToLower(s); strings.Contains(l, "unconfined") {
				t.Errorf("%s relaxes confinement: %s", where, s)
			}
		}
		if privileged == true {
			t.Errorf("%s is privileged", where)
		}
	}

	t.Run("compose", func(t *testing.T) {
		compose := loadYAML(t, repoPath("deploy", "compose.distributed.yaml"))
		services := asMap(compose["services"])
		if len(services) != 4 {
			t.Fatalf("services: %d", len(services))
		}
		profile := loadSeccomp(t)
		for name, raw := range services {
			svc := asMap(raw)
			where := "compose service " + name
			forbidden(where, strs(svc["cap_add"]), strs(svc["security_opt"]), svc["privileged"])
			if svc["pid"] == "host" || svc["network_mode"] == "host" || svc["ipc"] == "host" || len(asList(svc["devices"])) != 0 || svc["userns_mode"] == "host" {
				t.Errorf("%s shares a host namespace or device", where)
			}
			for _, v := range strs(svc["volumes"]) {
				for _, bad := range []string{"/sys", "/proc", "docker.sock", "/dev", "tracing", "debugfs"} {
					if strings.Contains(v, bad) {
						t.Errorf("%s mounts %s", where, v)
					}
				}
			}
			if !has(strs(svc["cap_drop"]), "ALL") || svc["read_only"] != true {
				t.Errorf("%s must drop ALL capabilities and be read_only", where)
			}
			if name == "soundpost-perf-helper" {
				continue
			}
			// server members: no capability at all, no seccomp override (the runtime default
			// profile admits perf_event_open only with CAP_PERFMON/CAP_SYS_ADMIN, which they lack)
			if len(asList(svc["cap_add"])) != 0 {
				t.Errorf("%s: a server member holds a capability", where)
			}
			for _, s := range strs(svc["security_opt"]) {
				if strings.HasPrefix(s, "seccomp=") || strings.HasPrefix(s, "apparmor=") || strings.HasPrefix(s, "label=") {
					t.Errorf("%s overrides confinement: %s (a seccomp file allowing perf_event_open would give the server the syscall)", where, s)
				}
			}
			if !has(strs(svc["security_opt"]), "no-new-privileges:true") || svc["user"] != "65532:65532" {
				t.Errorf("%s must run as nonroot with no-new-privileges", where)
			}
		}
		helper := asMap(services["soundpost-perf-helper"])
		if !has(strs(helper["profiles"]), "native") || len(asList(helper["profiles"])) != 1 {
			t.Errorf("the helper must be an opt-in profile only: %v", helper["profiles"])
		}
		if got := strs(helper["cap_add"]); len(got) != 1 || got[0] != "PERFMON" {
			t.Errorf("helper capabilities must be exactly PERFMON: %v", got)
		}
		seccomp := ""
		for _, s := range strs(helper["security_opt"]) {
			if v, ok := strings.CutPrefix(s, "seccomp="); ok {
				seccomp = v
			}
		}
		if !strings.Contains(seccomp, "seccomp/soundpost-perf.json") {
			t.Errorf("helper must use the audited seccomp profile, got %q", seccomp)
		}
		if pid := fmt.Sprint(helper["pid"]); strings.Contains(pid, "host") && !strings.Contains(pid, "${") {
			t.Errorf("helper PID namespace must be an explicit operator choice, not host: %s", pid)
		}
		if !strings.Contains(fmt.Sprint(helper["pid"]), "-unset}") {
			t.Errorf("helper PID namespace has a default: %v", helper["pid"])
		}
		// The helper is container uid 0 holding only PERFMON (a non-root container process gets no
		// effective capability from cap_add, verified at runtime by install-distributed). It must never
		// share the server's uid or its mounts, and has no network.
		if helper["network_mode"] != "none" || helper["user"] == "65532:65532" || strings.Contains(fmt.Sprint(helper["volumes"]), "-data") {
			t.Errorf("helper must have no network, not the server uid and no data volume: %v %v", helper["network_mode"], helper["user"])
		}
		assertAuditedProfile(t, profile)
	})

	t.Run("helm", func(t *testing.T) {
		for source, docs := range renderedBoth(t, chartImage) {
			// default install: no PERFMON anywhere, no helper at all
			for _, d := range docs {
				if strings.Contains(fmt.Sprint(d), "PERFMON") || d["kind"] == "DaemonSet" {
					t.Errorf("%s: default render carries the native helper: %v", source, d["kind"])
				}
			}
			for _, sts := range ofKind(docs, "StatefulSet") {
				pod := asMap(at(t, sts, "spec", "template", "spec"))
				c := asMap(at(t, pod, "containers", 0))
				sc := asMap(c["securityContext"])
				caps := asMap(sc["capabilities"])
				forbidden(source+" server "+fmt.Sprint(at(t, sts, "metadata", "name")), strs(caps["add"]), nil, sc["privileged"])
				if len(asList(caps["add"])) != 0 || !has(strs(caps["drop"]), "ALL") || sc["privileged"] != false || sc["allowPrivilegeEscalation"] != false || sc["readOnlyRootFilesystem"] != true {
					t.Errorf("%s: server container security context: %v", source, sc)
				}
				if at(t, pod, "securityContext", "seccompProfile", "type") != "RuntimeDefault" || pod["hostPID"] != false || pod["hostNetwork"] != false || pod["hostIPC"] != false {
					t.Errorf("%s: server pod must keep the runtime seccomp default and no host namespaces", source)
				}
			}
		}
		for source, docs := range renderedBoth(t, map[string]any{"image": chartImage["image"], "perfHelper": map[string]any{"enabled": true, "image": map[string]any{"repository": "registry.example.invalid/helper", "tag": "1.0.0"}}}, "perfHelper.enabled=true", "perfHelper.image.repository=registry.example.invalid/helper", "perfHelper.image.tag=1.0.0") {
			sets := ofKind(docs, "DaemonSet")
			if len(sets) != 1 {
				t.Fatalf("%s: want one helper DaemonSet, have %d", source, len(sets))
			}
			pod := asMap(at(t, sets[0], "spec", "template", "spec"))
			c := asMap(at(t, pod, "containers", 0))
			sc := asMap(c["securityContext"])
			caps := asMap(sc["capabilities"])
			forbidden(source+" helper", strs(caps["add"]), nil, sc["privileged"])
			if got := strs(caps["add"]); len(got) != 1 || got[0] != "PERFMON" || !has(strs(caps["drop"]), "ALL") || sc["privileged"] != false || sc["allowPrivilegeEscalation"] != false {
				t.Errorf("%s: helper must hold exactly PERFMON: %v", source, sc)
			}
			profile := asMap(at(t, pod, "securityContext", "seccompProfile"))
			if profile["type"] != "Localhost" || !strings.HasSuffix(fmt.Sprint(profile["localhostProfile"]), "soundpost-perf.json") {
				t.Errorf("%s: helper needs the audited Localhost profile: %v", source, profile)
			}
			if pod["hostPID"] != false || pod["hostNetwork"] != false || pod["hostIPC"] != false {
				t.Errorf("%s: by default the helper has no host PID: capability stays denied until the operator grants visibility (%v)", source, pod["hostPID"])
			}
			// the server pods are still unprivileged in the same render
			for _, sts := range ofKind(docs, "StatefulSet") {
				c := asMap(at(t, sts, "spec", "template", "spec", "containers", 0))
				if len(asList(at(t, c, "securityContext", "capabilities", "add"))) != 0 {
					t.Errorf("%s: enabling the helper changed server capabilities", source)
				}
			}
		}
	})
}

func loadSeccomp(t testing.TB) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(repoPath("deploy", "seccomp", "soundpost-perf.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err = json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// assertAuditedProfile checks the shape the audit approved: deny by default, perf_event_open
// only with a constrained argument, and none of the memory-inspection or tracing syscalls.
func assertAuditedProfile(t testing.TB, profile map[string]any) {
	t.Helper()
	if profile["defaultAction"] != "SCMP_ACT_ERRNO" {
		t.Errorf("seccomp default action %v", profile["defaultAction"])
	}
	conditional := false
	for _, r := range asList(profile["syscalls"]) {
		rule := asMap(r)
		if rule["action"] != "SCMP_ACT_ALLOW" {
			continue
		}
		for _, name := range strs(rule["names"]) {
			switch name {
			case "ptrace", "bpf", "process_vm_readv", "process_vm_writev", "kcmp", "userfaultfd", "pidfd_getfd", "mount", "setns", "unshare", "init_module", "finit_module", "kexec_load", "open_by_handle_at", "keyctl":
				t.Errorf("audited profile allows %s", name)
			case "perf_event_open":
				if len(asList(rule["args"])) == 0 {
					t.Error("perf_event_open is allowed without an argument constraint")
				}
				conditional = true
			}
		}
	}
	if !conditional {
		t.Error("the profile does not allow perf_event_open at all: the helper could never run")
	}
}

// ---- Compose: three members, three volumes ----

func TestComposeRunsThreeSeparateMembers(t *testing.T) {
	compose := loadYAML(t, repoPath("deploy", "compose.distributed.yaml"))
	services := asMap(compose["services"])
	data, config, nodeIDs, configs, ports := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, name := range []string{"soundpost-a", "soundpost-b", "soundpost-c"} {
		svc := asMap(services[name])
		if svc == nil {
			t.Fatalf("missing member %s", name)
		}
		image := fmt.Sprint(svc["image"])
		if !strings.Contains(image, "${SOUNDPOST_IMAGE:?") || strings.Contains(image, "latest") {
			t.Errorf("%s: the produced image must be required and pinned: %s", name, image)
		}
		var cmd = strs(svc["command"])
		if len(cmd) == 0 || cmd[0] != "serve" || !has(cmd, "--mode=distributed") {
			t.Errorf("%s command: %v", name, cmd)
		}
		for _, a := range cmd {
			if id, ok := strings.CutPrefix(a, "--node-id="); ok {
				if nodeIDs[id] {
					t.Errorf("node id %s reused", id)
				}
				nodeIDs[id] = true
				if !has(cmd, "--cluster-config=/etc/soundpost/node-"+id+".json") {
					t.Errorf("%s: node id %s does not read its own configuration file: %v", name, id, cmd)
				}
			}
		}
		mounts := strs(svc["volumes"])
		dataSeen, configSeen := false, false
		for _, v := range mounts {
			parts := strings.Split(v, ":")
			switch {
			case strings.HasSuffix(v, ":/var/lib/soundpost"):
				if data[parts[0]] {
					t.Errorf("data volume %s is shared", parts[0])
				}
				data[parts[0]], dataSeen = true, true
			case strings.Contains(v, ":/etc/soundpost"):
				if !strings.HasSuffix(v, ":/etc/soundpost:ro") {
					t.Errorf("%s: cluster config and certificates must be read-only: %s", name, v)
				}
				if config[parts[0]] {
					t.Errorf("configuration volume %s is shared between members (a member would hold another's private key)", parts[0])
				}
				config[parts[0]], configSeen = true, true
			default:
				t.Errorf("%s: unexpected mount %s", name, v)
			}
		}
		if !dataSeen || !configSeen {
			t.Errorf("%s: needs its own data and config volume: %v", name, mounts)
		}
		for _, p := range strs(svc["ports"]) {
			if ports[p] {
				t.Errorf("published port %s reused", p)
			}
			ports[p] = true
			if !strings.Contains(p, "127.0.0.1") {
				t.Errorf("%s publishes beyond loopback by default: %s", name, p)
			}
			if strings.Contains(p, "9444") {
				t.Errorf("%s publishes the peer port", name)
			}
		}
		if !strings.Contains(fmt.Sprint(svc["healthcheck"]), "ready") {
			t.Errorf("%s has no functional readiness health check", name)
		}
		configs[fmt.Sprint(svc["command"])] = true
	}
	if len(nodeIDs) != 3 || len(data) != 3 || len(config) != 3 {
		t.Fatalf("ids=%d data=%d config=%d", len(nodeIDs), len(data), len(config))
	}
	if asMap(at(t, compose, "networks", "peer"))["internal"] != true {
		t.Error("the peer network must be internal")
	}
	// Named volumes exist and every one has its own name (the name is overridable per member).
	names := map[string]bool{}
	for key, v := range asMap(compose["volumes"]) {
		n := fmt.Sprint(asMap(v)["name"])
		if names[n] {
			t.Errorf("volume %s resolves to the shared name %s", key, n)
		}
		names[n] = true
	}
	// A Compose file with the simulation caveat in plain words.
	raw, _ := os.ReadFile(repoPath("deploy", "compose.distributed.yaml"))
	if !bytes.Contains(raw, []byte("NOT three physical failure domains")) {
		t.Error("the Compose file must state that volumes on one host are not physical failure domains")
	}
}

// ---- Helm: voters apart ----

func TestHelmChartKeepsThreeVotersApart(t *testing.T) {
	for source, docs := range renderedBoth(t, chartImage) {
		t.Run(source, func(t *testing.T) { assertChart(t, docs) })
	}
}

func assertChart(t *testing.T, docs []map[string]any) {
	t.Helper()
	sets := ofKind(docs, "StatefulSet")
	if len(sets) != 3 {
		t.Fatalf("want three StatefulSets, have %d", len(sets))
	}
	ids, names, claims, pki := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	secrets := map[string]map[string]any{}
	for _, s := range ofKind(docs, "Secret") {
		secrets[fmt.Sprint(at(t, s, "metadata", "name"))] = asMap(s["stringData"])
	}
	for _, sts := range sets {
		name := fmt.Sprint(at(t, sts, "metadata", "name"))
		if names[name] {
			t.Errorf("duplicate StatefulSet %s", name)
		}
		names[name] = true
		spec := asMap(sts["spec"])
		if spec["replicas"] != 1 {
			t.Errorf("%s: one voter per StatefulSet, replicas=%v", name, spec["replicas"])
		}
		if at(t, spec, "updateStrategy", "type") != "OnDelete" {
			t.Errorf("%s: a helm upgrade must never restart a voter by itself (updateStrategy %v)", name, at(t, spec, "updateStrategy"))
		}
		claim := fmt.Sprint(at(t, spec, "volumeClaimTemplates", 0, "metadata", "name")) + "-" + name + "-0"
		if claims[claim] || at(t, spec, "volumeClaimTemplates", 0, "spec", "accessModes", 0) != "ReadWriteOnce" {
			t.Errorf("%s: persistent claim %s shared or not RWO", name, claim)
		}
		claims[claim] = true
		if at(t, spec, "persistentVolumeClaimRetentionPolicy", "whenDeleted") != "Retain" {
			t.Errorf("%s: a voter's disk must survive deletion of its set", name)
		}
		pod := asMap(at(t, spec, "template", "spec"))
		c := asMap(at(t, pod, "containers", 0))
		args := strs(c["args"])
		var id string
		for _, a := range args {
			if v, ok := strings.CutPrefix(a, "--node-id="); ok {
				id = v
			}
		}
		if id == "" || ids[id] || !has(args, "--mode=distributed") || !has(args, "--cluster-config=/etc/soundpost/config/node-"+id+".json") {
			t.Errorf("%s: member identity %q duplicated or config mismatch: %v", name, id, args)
		}
		ids[id] = true
		// required anti-affinity over the member pods, on a node-level key
		terms := asList(at(t, pod, "affinity", "podAntiAffinity", "requiredDuringSchedulingIgnoredDuringExecution"))
		if len(terms) != 1 || asMap(terms[0])["topologyKey"] != "kubernetes.io/hostname" || asMap(at(t, terms[0], "labelSelector", "matchLabels"))["app.kubernetes.io/component"] != "member" {
			t.Errorf("%s: missing required anti-affinity: %v", name, terms)
		}
		if at(t, c, "readinessProbe", "httpGet", "path") != "/readyz" || at(t, c, "readinessProbe", "httpGet", "scheme") != "HTTPS" || at(t, c, "startupProbe", "httpGet", "path") != "/readyz" {
			t.Errorf("%s: readiness must be the committed /readyz route over HTTPS", name)
		}
		if c["livenessProbe"] != nil {
			t.Errorf("%s: a liveness probe on a quorum member restarts the cluster during an outage", name)
		}
		for _, v := range asList(at(t, pod, "volumes")) {
			vol := asMap(v)
			if secret := asMap(vol["secret"]); secret != nil && vol["name"] == "pki" {
				if pki[fmt.Sprint(secret["secretName"])] {
					t.Errorf("%s: certificate Secret shared between members", name)
				}
				pki[fmt.Sprint(secret["secretName"])] = true
			}
			if vol["hostPath"] != nil {
				t.Errorf("%s: server pod mounts a host path", name)
			}
		}
		// the node file this member reads is a real appcore.NodeConfig of the same identity
		file := fmt.Sprint(at(t, pod, "volumes", 0, "secret", "secretName"))
		raw, _ := secrets[file]["node-"+id+".json"].(string)
		var node appcore.NodeConfig
		if err := json.Unmarshal([]byte(raw), &node); err != nil {
			t.Fatalf("%s: config secret %s is not an appcore.NodeConfig: %v\n%s", name, file, err, raw)
		}
		if strconv.FormatUint(node.NodeID, 10) != id || replica.ValidateMembers(node.Members) != nil || len(node.Members.Nodes) != 3 || node.Members.Revision != model.Revision(1) {
			t.Errorf("%s: node file rejected by the engine's own membership validator: %+v", name, node)
		}
		domains, identities, addresses := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, m := range node.Members.Nodes {
			if m.Learner {
				t.Errorf("%s: learner in the initial membership", name)
			}
			domains[m.FailureDomain], identities[m.NodeIdentity], addresses[m.Address] = true, true, true
			if !strings.Contains(m.Address, ".sp.svc:9444") {
				t.Errorf("%s: peer address %s is not the stable pod DNS name on the peer port", name, m.Address)
			}
		}
		if len(domains) != 3 || len(identities) != 3 || len(addresses) != 3 {
			t.Errorf("%s: members share a domain, identity or address", name)
		}
		if !strings.HasSuffix(node.Certificate, ".crt") || !strings.Contains(node.Certificate, "node-") || node.PrivateKey == node.Certificate {
			t.Errorf("%s: certificate paths %q %q", name, node.Certificate, node.PrivateKey)
		}
	}
	if len(ids) != 3 || len(claims) != 3 || len(pki) != 3 {
		t.Errorf("identities=%d claims=%d certificates=%d", len(ids), len(claims), len(pki))
	}

	budgets := ofKind(docs, "PodDisruptionBudget")
	if len(budgets) != 1 || at(t, budgets[0], "spec", "minAvailable") != 2 || asMap(at(t, budgets[0], "spec", "selector", "matchLabels"))["app.kubernetes.io/component"] != "member" {
		t.Errorf("PodDisruptionBudget must keep two of three members: %v", budgets)
	}

	policies := ofKind(docs, "NetworkPolicy")
	if len(policies) != 1 {
		t.Fatalf("network policies: %d", len(policies))
	}
	spec := asMap(policies[0]["spec"])
	if !has(strs(spec["policyTypes"]), "Ingress") || !has(strs(spec["policyTypes"]), "Egress") {
		t.Error("the policy must govern ingress and egress")
	}
	ingress := asList(spec["ingress"])
	if len(ingress) != 1 {
		t.Fatalf("default ingress rules: %d (public ingress must be opt-in)", len(ingress))
	}
	peerRule := asMap(ingress[0])
	if asMap(at(t, peerRule, "from", 0, "podSelector", "matchLabels"))["app.kubernetes.io/component"] != "member" || len(asList(peerRule["ports"])) != 1 || at(t, peerRule, "ports", 0, "port") != 9444 {
		t.Errorf("member-to-member ingress must be members only on the mTLS port: %v", peerRule)
	}
	var memberEgress map[string]any
	for _, e := range asList(spec["egress"]) {
		if asMap(at(t, e, "to", 0, "podSelector", "matchLabels"))["app.kubernetes.io/component"] == "member" {
			memberEgress = asMap(e)
		}
	}
	if memberEgress == nil || len(asList(memberEgress["ports"])) != 1 || at(t, memberEgress, "ports", 0, "port") != 9444 {
		t.Errorf("member-to-member egress must be the peer port only: %v", memberEgress)
	}

	services := ofKind(docs, "Service")
	headless := false
	for _, s := range services {
		if at(t, s, "spec", "clusterIP") == "None" {
			headless = true
			if at(t, s, "spec", "publishNotReadyAddresses") != true {
				t.Error("the peer service must publish not-ready addresses so a quorum can re-form")
			}
		}
	}
	if !headless || len(services) != 2 {
		t.Errorf("services: %d headless=%v", len(services), headless)
	}
}

func TestHelmChartRefusesUnsafeValues(t *testing.T) {
	cases := map[string]map[string]any{
		"no image":                {},
		"replication factor five": {"image": chartImage["image"], "replicationFactor": 5},
		"replication factor two":  {"image": chartImage["image"], "replicationFactor": 2},
		"budget allows two down":  {"image": chartImage["image"], "podDisruptionBudget": map[string]any{"minAvailable": 1}},
		"image without a tag":     {"image": map[string]any{"repository": "registry.example.invalid/soundpost"}},
		"helper without an image": {"image": chartImage["image"], "perfHelper": map[string]any{"enabled": true}},
	}
	for name, overrides := range cases {
		values := loadYAML(t, repoPath("deploy", "helm", "soundpost", "values.yaml"))
		merge(values, overrides)
		if _, err := renderTemplates(values); err == nil {
			t.Errorf("%s: the chart rendered", name)
		}
	}
	values := loadYAML(t, repoPath("deploy", "helm", "soundpost", "values.yaml"))
	merge(values, chartImage)
	values["members"] = asList(values["members"])[:2]
	if _, err := renderTemplates(values); err == nil {
		t.Error("two members rendered")
	}
	if strings.Contains(fmt.Sprint(loadYAML(t, repoPath("deploy", "helm", "soundpost", "values.yaml"))), "PRIVATE KEY") {
		t.Error("values.yaml carries key material")
	}
}

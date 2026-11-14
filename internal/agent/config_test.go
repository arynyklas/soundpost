// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/sources"
)

func validConfigJSON(t *testing.T) (map[string]any, string) {
	t.Helper()
	abs := func(p string) string {
		if runtime.GOOS == "windows" {
			return `C:\` + p
		}
		return "/" + p
	}
	m := map[string]any{
		"version": 1, "server": "https://ingest.example.test:8443", "credential_file": abs("etc/soundpost/credential"), "state_dir": abs("var/lib/soundpost-agent"),
		"org": model.ID{1}.String(), "project": model.ID{2}.String(), "source": model.ID{3}.String(), "policy_revision": 1,
		"resource": map[string]any{"service_id": model.ID{4}.String(), "environment_id": model.ID{5}.String(), "build_id": model.ID{6}.String(), "instance_pseudonym": "host-1"},
		"host":     map[string]any{"interval": "30s", "allow": []string{"cpu", "memory"}},
	}
	return m, abs("var/log/app.log")
}

func parse(t *testing.T, m map[string]any) error {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseConfig(raw)
	return err
}

func TestConfigStrictValidation(t *testing.T) {
	m, _ := validConfigJSON(t)
	if err := parse(t, m); err != nil {
		t.Fatalf("baseline refused: %v", err)
	}
	mutations := map[string]func(map[string]any){
		"unknown field":           func(m map[string]any) { m["surprise"] = true },
		"wrong version":           func(m map[string]any) { m["version"] = 2 },
		"plain http":              func(m map[string]any) { m["server"] = "http://ingest.example.test" },
		"userinfo in server":      func(m map[string]any) { m["server"] = "https://user:pw@ingest.example.test" },
		"server path":             func(m map[string]any) { m["server"] = "https://ingest.example.test/ingest" },
		"relative credential":     func(m map[string]any) { m["credential_file"] = "credential" },
		"relative state dir":      func(m map[string]any) { m["state_dir"] = "state" },
		"bad org":                 func(m map[string]any) { m["org"] = "nothex" },
		"zero revision":           func(m map[string]any) { m["policy_revision"] = 0 },
		"nothing to collect":      func(m map[string]any) { delete(m, "host") },
		"host interval too short": func(m map[string]any) { m["host"] = map[string]any{"interval": "500ms", "allow": []string{"cpu"}} },
		"host group unknown":      func(m map[string]any) { m["host"] = map[string]any{"interval": "30s", "allow": []string{"keylogger"}} },
		"filesystem alias is a path": func(m map[string]any) {
			m["host"] = map[string]any{"interval": "30s", "allow": []string{"filesystem"}, "filesystems": []map[string]string{{"alias": "/var/lib", "path": "/var/lib"}}}
		},
	}
	for name, mutate := range mutations {
		c, _ := validConfigJSON(t)
		mutate(c)
		if err := parse(t, c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// trailing data and non-object
	if _, err := ParseConfig([]byte(`{} {}`)); err == nil {
		t.Error("trailing value accepted")
	}
}

func TestConfigLogSourcesInheritTheTopLevelIdentity(t *testing.T) {
	m, logPath := validConfigJSON(t)
	tpl := []map[string]any{{"id": "svc.started", "revision": "1", "line": "service started unit {unit}", "severity": "info", "fields": []map[string]any{
		{"name": "unit", "type": "string", "max_bytes": 16, "sensitivity": "metadata", "values": []string{"alpha"}},
	}}}
	src := func() map[string]any {
		return map[string]any{"name": "app", "kind": "file", "class": "structured", "stream_labels": []map[string]string{{"name": "source", "value": "app"}}, "templates": tpl, "file": map[string]any{"path": logPath}, "poll_interval": "2s"}
	}
	m["logs"] = []any{src()}
	if err := parse(t, m); err != nil {
		t.Fatalf("valid log source refused: %v", err)
	}
	// a per-source revision/resource would let one source diverge from the
	// installation's policy: refused
	for name, mutate := range map[string]func(map[string]any){
		"own revision":                 func(s map[string]any) { s["policy_revision"] = 7 },
		"own resource":                 func(s map[string]any) { s["resource"] = map[string]any{"instance_pseudonym": "other"} },
		"bad poll":                     func(s map[string]any) { s["poll_interval"] = "10ms" },
		"restricted raw without grant": func(s map[string]any) { s["class"] = "restricted_raw" },
		"relative file":                func(s map[string]any) { s["file"] = map[string]any{"path": "app.log"} },
	} {
		s := src()
		mutate(s)
		c, _ := validConfigJSON(t)
		c["logs"] = []any{s}
		if err := parse(t, c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	dup, _ := validConfigJSON(t)
	dup["logs"] = []any{src(), src()}
	if err := parse(t, dup); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate source names: %v", err)
	}
	// the decoded policy is what the sources package validates
	raw, _ := json.Marshal(m)
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Logs) != 1 || cfg.Logs[0].Kind != sources.KindFile || time.Duration(cfg.Logs[0].Poll) != 2*time.Second || filepath.Base(cfg.Logs[0].File.Path) != "app.log" {
		t.Fatalf("decoded %+v", cfg.Logs)
	}
}

func TestLoadConfigRefusesMissingAndOversizedFiles(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("missing config accepted")
	}
}

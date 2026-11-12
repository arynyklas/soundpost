// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"soundpost/internal/adapters/queryinput"
	"soundpost/internal/model"
)

type cfgDoc = map[string]any

func cfgIDs() (project, source, producer, service, environment, build string) {
	return model.ID{1}.String(), model.ID{2}.String(), model.ID{3}.String(), model.ID{4}.String(), model.ID{5}.String(), model.ID{6}.String()
}

// validConfigDoc is a complete document with one https-less target; mutate
// edits it before encoding.
func validConfigDoc(mutate func(doc cfgDoc, target cfgDoc)) []byte {
	project, source, producer, service, environment, build := cfgIDs()
	target := cfgDoc{
		"alias": "node-exporter", "url": "https://exporter.example.test:9100/metrics",
		"interval": "15s", "timeout": "5s", "max_bytes": 1 << 20,
		"auth": "bearer", "secret": "exporter-token",
		"stale":  cfgDoc{"on_disappear": true, "on_failure": true},
		"source": cfgDoc{"project": project, "source": source, "producer": producer, "policy_revision": 1, "credential_secret": "source-token", "resource": cfgDoc{"service": service, "environment": environment, "build": build, "instance": "host-1", "labels": cfgDoc{"zone": "a"}}},
	}
	doc := cfgDoc{"version": 1, "targets": []any{target}}
	if mutate != nil {
		mutate(doc, target)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return raw
}

func writeConfigFile(t *testing.T, raw []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scrape.json")
	if err := os.WriteFile(p, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func cfgReason(t *testing.T, err error) string {
	t.Helper()
	var ce *ScrapeConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("not a typed configuration error: %v", err)
	}
	return ce.Reason
}

func loadSpecs(t *testing.T, raw []byte) ([]ScrapeTargetSpec, error) {
	t.Helper()
	cfg, err := LoadScrapeConfig(writeConfigFile(t, raw, 0o600))
	if err != nil {
		return nil, err
	}
	r, err := NewDirSecretReader(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Specs(r)
}

func TestScrapeConfigBuildsTheDocumentedTarget(t *testing.T) {
	raw := validConfigDoc(func(doc cfgDoc, target cfgDoc) {
		target["egress"] = cfgDoc{"allow_prefixes": []string{"10.20.0.0/16"}}
		target["profile"] = cfgDoc{"names": "utf8", "out_of_order": "reject", "histograms": "reject", "exemplars": "trace_link", "help": "discard", "default_unit": "s"}
	})
	specs, err := loadSpecs(t, raw)
	if err != nil || len(specs) != 1 {
		t.Fatalf("%v %d", err, len(specs))
	}
	s := specs[0]
	project, source, _, _, _, _ := cfgIDs()
	if s.Target.Alias != "node-exporter" || s.Target.Interval != 15*time.Second || s.Target.Timeout != 5*time.Second || s.Target.MaxBytes != 1<<20 ||
		s.Target.Auth != ScrapeAuthBearer || s.Target.Secret != "exporter-token" || s.Target.Secrets == nil ||
		!s.Target.Stale.OnDisappear || !s.Target.Stale.OnFailure || len(s.Target.Egress.AllowPrefixes) != 1 {
		t.Fatalf("target %+v", s.Target)
	}
	if s.CredentialSecret != "source-token" || s.Project.String() != project || s.Source.String() != source || s.PolicyRevision != 1 {
		t.Fatalf("source %+v", s)
	}
	p := s.Target.Profile
	if p.Names != queryinput.NamesUTF8 || p.OutOfOrder != queryinput.OutOfOrderReject || p.Histograms != queryinput.HistogramsReject || p.Exemplars != queryinput.ExemplarsTraceLink || p.Help != queryinput.HelpDiscard || p.DefaultUnit != "s" {
		t.Fatalf("profile %+v", p)
	}
	if len(p.Resource.Labels) != 1 || p.Resource.Labels[0] != (model.Label{Name: "zone", Value: "a"}) || p.Resource.Instance != "host-1" {
		t.Fatalf("resource %+v", p.Resource)
	}
	// defaults: an empty profile is the strictest vocabulary
	specs, err = loadSpecs(t, validConfigDoc(nil))
	if err != nil {
		t.Fatal(err)
	}
	if d := specs[0].Target.Profile; d.Names != queryinput.NamesStrict || d.OutOfOrder != queryinput.OutOfOrderSort || d.Histograms != queryinput.HistogramsPreserve || d.Exemplars != queryinput.ExemplarsReject || d.Help != queryinput.HelpReject {
		t.Fatalf("defaults %+v", d)
	}
}

func TestScrapeConfigRefusesUnknownFieldsAtEveryLevel(t *testing.T) {
	cases := map[string]func(doc, target cfgDoc){
		"top level":       func(doc, _ cfgDoc) { doc["extra"] = true },
		"target":          func(_, target cfgDoc) { target["extra"] = true },
		"tls":             func(_, target cfgDoc) { target["tls"] = cfgDoc{"server_name": "x", "insecure_skip_verify": true} },
		"egress":          func(_, target cfgDoc) { target["egress"] = cfgDoc{"allow_loopback": true} },
		"stale":           func(_, target cfgDoc) { target["stale"] = cfgDoc{"on_disappear": true, "extra": 1} },
		"profile":         func(_, target cfgDoc) { target["profile"] = cfgDoc{"limits": cfgDoc{}} },
		"source":          func(_, target cfgDoc) { target["source"].(cfgDoc)["org"] = "x" },
		"source.resource": func(_, target cfgDoc) { target["source"].(cfgDoc)["resource"].(cfgDoc)["extra"] = 1 },
	}
	for name, mutate := range cases {
		_, err := loadSpecs(t, validConfigDoc(mutate))
		if err == nil || cfgReason(t, err) != ScrapeConfigInvalid {
			t.Errorf("%s: an unknown field was accepted: %v", name, err)
		}
	}
	if _, err := loadSpecs(t, validConfigDoc(nil)); err != nil {
		t.Fatalf("control: %v", err)
	}
	// trailing data after the document is refused too
	if _, err := ParseScrapeConfig(append(validConfigDoc(nil), []byte(` {}`)...)); err == nil {
		t.Error("trailing data accepted")
	}
}

func TestScrapeConfigRefusesInvalidTargets(t *testing.T) {
	cases := map[string]func(doc, target cfgDoc){
		"version":               func(doc, _ cfgDoc) { doc["version"] = 2 },
		"no targets":            func(doc, _ cfgDoc) { doc["targets"] = []any{} },
		"bad alias":             func(_, target cfgDoc) { target["alias"] = "bad alias!" },
		"userinfo in url":       func(_, target cfgDoc) { target["url"] = "https://u:p@exporter.example.test/metrics" },
		"ftp url":               func(_, target cfgDoc) { target["url"] = "ftp://exporter.example.test/metrics" },
		"timeout over interval": func(_, target cfgDoc) { target["timeout"] = "30s" },
		"interval too short":    func(_, target cfgDoc) { target["interval"] = "500ms"; target["timeout"] = "400ms" },
		"bad duration":          func(_, target cfgDoc) { target["interval"] = "soon" },
		"max bytes zero":        func(_, target cfgDoc) { target["max_bytes"] = 0 },
		"max bytes too big":     func(_, target cfgDoc) { target["max_bytes"] = 65 << 20 },
		"auth without secret":   func(_, target cfgDoc) { delete(target, "secret") },
		"secret without auth":   func(_, target cfgDoc) { delete(target, "auth") },
		"unknown auth":          func(_, target cfgDoc) { target["auth"] = "digest" },
		"traversal secret":      func(_, target cfgDoc) { target["secret"] = "../exporter-token" },
		"bad egress prefix":     func(_, target cfgDoc) { target["egress"] = cfgDoc{"allow_prefixes": []string{"not-a-prefix"}} },
		"loopback prefix":       func(_, target cfgDoc) { target["egress"] = cfgDoc{"allow_prefixes": []string{"127.0.0.0/8"}} },
		"metadata prefix":       func(_, target cfgDoc) { target["egress"] = cfgDoc{"allow_prefixes": []string{"169.254.0.0/16"}} },
		"tls on http": func(_, target cfgDoc) {
			target["url"] = "http://exporter.example.test/metrics"
			target["tls"] = cfgDoc{"server_name": "x"}
		},
		"bad project id":       func(_, target cfgDoc) { target["source"].(cfgDoc)["project"] = "nope" },
		"zero source id":       func(_, target cfgDoc) { target["source"].(cfgDoc)["source"] = model.ID{}.String() },
		"policy revision 0":    func(_, target cfgDoc) { target["source"].(cfgDoc)["policy_revision"] = 0 },
		"no credential ref":    func(_, target cfgDoc) { target["source"].(cfgDoc)["credential_secret"] = "" },
		"traversal credential": func(_, target cfgDoc) { target["source"].(cfgDoc)["credential_secret"] = "a/b" },
		"no instance":          func(_, target cfgDoc) { target["source"].(cfgDoc)["resource"].(cfgDoc)["instance"] = "" },
		"unknown names mode":   func(_, target cfgDoc) { target["profile"] = cfgDoc{"names": "lenient"} },
		"unknown histograms":   func(_, target cfgDoc) { target["profile"] = cfgDoc{"histograms": "maybe"} },
		"duplicate alias": func(doc, target cfgDoc) {
			second := cfgDoc{}
			for k, v := range target {
				second[k] = v
			}
			doc["targets"] = []any{target, second}
		},
	}
	for name, mutate := range cases {
		specs, err := loadSpecs(t, validConfigDoc(mutate))
		if err == nil || len(specs) != 0 {
			t.Errorf("%s: accepted", name)
			continue
		}
		if r := cfgReason(t, err); r != ScrapeConfigInvalid && r != ScrapeConfigTargetFailed {
			t.Errorf("%s: reason %q", name, r)
		}
		for _, leak := range []string{"exporter.example.test", "exporter-token", "source-token", "node-exporter", os.TempDir()} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: the error leaks %q: %v", name, leak, err)
			}
		}
	}
	// one bad target refuses the whole file: no target is silently dropped
	_, err := loadSpecs(t, validConfigDoc(func(doc, target cfgDoc) {
		bad := cfgDoc{}
		for k, v := range target {
			bad[k] = v
		}
		bad["alias"] = "second"
		bad["url"] = "ftp://x/"
		doc["targets"] = []any{target, bad}
	}))
	if err == nil {
		t.Fatal("a file with one bad target was accepted")
	}
}

func TestScrapeConfigFileModeAndKind(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	raw := validConfigDoc(nil)
	for _, mode := range []os.FileMode{0o620, 0o602, 0o666, 0o660, 0o606} {
		_, err := LoadScrapeConfig(writeConfigFile(t, raw, mode))
		if err == nil || cfgReason(t, err) != ScrapeConfigNotPrivate {
			t.Errorf("mode %v: %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o640, 0o644, 0o400} {
		if _, err := LoadScrapeConfig(writeConfigFile(t, raw, mode)); err != nil {
			t.Errorf("mode %v is not writable by others: %v", mode, err)
		}
	}
	dir := t.TempDir()
	for name, path := range map[string]string{"missing": filepath.Join(dir, "none.json"), "directory": dir} {
		if _, err := LoadScrapeConfig(path); err == nil || cfgReason(t, err) != ScrapeConfigUnreadable {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := LoadScrapeConfig(path); err != nil && strings.Contains(err.Error(), dir) {
			t.Errorf("%s: the error leaks the path: %v", name, err)
		}
	}
	// a symlink to a private file is read (the operator owns the link); a
	// symlink that lands on a group-writable file is judged by the target's mode
	target := writeConfigFile(t, raw, 0o666)
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadScrapeConfig(link); err == nil || cfgReason(t, err) != ScrapeConfigNotPrivate {
		t.Errorf("symlink to a world-writable file: %v", err)
	}
}

func TestScrapeConfigTLSRoots(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	roots := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	specs, err := loadSpecs(t, validConfigDoc(func(_, target cfgDoc) {
		target["tls"] = cfgDoc{"roots_file": roots, "server_name": "example.com"}
	}))
	if err != nil || specs[0].Target.TLS.RootCAs == nil || specs[0].Target.TLS.ServerName != "example.com" {
		t.Fatalf("%v %+v", err, specs)
	}
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{"garbage": garbage, "missing": filepath.Join(t.TempDir(), "none.pem")} {
		_, err := loadSpecs(t, validConfigDoc(func(_, target cfgDoc) { target["tls"] = cfgDoc{"roots_file": p} }))
		if err == nil || cfgReason(t, err) != ScrapeConfigTLSRoots || strings.Contains(err.Error(), p) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/sources"
)

const scrapeCmdCanary = "CANARY-cmd-secret-5b7e1f0c93"

// scrapeCmdFiles writes a private secrets directory and a configuration file
// for one target at url and returns their paths.
func scrapeCmdFiles(t *testing.T, url string, mutate func(target map[string]any)) (config, secrets string) {
	t.Helper()
	root := t.TempDir()
	secrets = filepath.Join(root, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"exporter-token": scrapeCmdCanary, "source-token": scrapeCmdCanary + "-source"} {
		if err := os.WriteFile(filepath.Join(secrets, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target := map[string]any{
		"alias": "cmd-target", "url": url, "interval": "1s", "timeout": "1s", "max_bytes": 1 << 20,
		"auth": "bearer", "secret": "exporter-token",
		"source": map[string]any{
			"project": model.ID{1}.String(), "source": model.ID{2}.String(), "producer": model.ID{3}.String(), "policy_revision": 1,
			"credential_secret": "source-token",
			"resource":          map[string]any{"service": model.ID{4}.String(), "environment": model.ID{5}.String(), "build": model.ID{6}.String(), "instance": "host-1"},
		},
	}
	if mutate != nil {
		mutate(target)
	}
	raw, err := json.Marshal(map[string]any{"version": 1, "targets": []any{target}})
	if err != nil {
		t.Fatal(err)
	}
	config = filepath.Join(root, "scrape.json")
	if err = os.WriteFile(config, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return config, secrets
}

func parseScrapeFlags(t *testing.T, args ...string) scrapeOptions {
	t.Helper()
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	o := addScrapeFlags(f)
	if err := f.Parse(args); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestScrapeFlagSurface(t *testing.T) {
	// not configured: no scrapers, no error
	s, err := parseScrapeFlags(t).settings()
	if err != nil || len(s.specs) != 0 {
		t.Fatalf("%v %+v", err, s)
	}
	// the two flags are required together
	for _, args := range [][]string{{"--scrape-config", "x.json"}, {"--scrape-secrets-dir", "dir"}} {
		_, err := parseScrapeFlags(t, args...).settings()
		if err == nil || scrapeFailureNotice(err) != "scrape: flags_incomplete" {
			t.Errorf("%v: %v", args, err)
		}
	}
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	config, secrets := scrapeCmdFiles(t, "https://exporter.example.test/metrics", nil)
	s, err = parseScrapeFlags(t, "--scrape-config", config, "--scrape-secrets-dir", secrets).settings()
	if err != nil || len(s.specs) != 1 || s.specs[0].Target.Alias != "cmd-target" || s.secrets == nil {
		t.Fatalf("%v %+v", err, s)
	}
}

// Every refusal is a static code: never the path, alias, URL or secret.
func TestScrapeSettingsRefuseBadConfigurationWithStaticCodes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	type tc struct {
		name   string
		mutate func(config, secrets string)
		want   string
	}
	cases := []tc{
		{"group-writable config", func(c, _ string) { _ = os.Chmod(c, 0o664) }, "scrape: config_not_private"},
		{"world-writable config", func(c, _ string) { _ = os.Chmod(c, 0o666) }, "scrape: config_not_private"},
		{"missing config", func(c, _ string) { _ = os.Remove(c) }, "scrape: config_unreadable"},
		{"unknown field", func(c, _ string) {
			_ = os.WriteFile(c, []byte(`{"version":1,"targets":[],"extra":1}`), 0o600)
		}, "scrape: config_invalid"},
		{"invalid target", func(c, _ string) {
			raw, _ := os.ReadFile(c)
			_ = os.WriteFile(c, bytes.Replace(raw, []byte(`"1s"`), []byte(`"0s"`), 1), 0o600)
		}, "scrape: config_target_invalid"},
		{"open secrets directory", func(_, s string) { _ = os.Chmod(s, 0o755) }, "scrape: secrets_dir_insecure"},
		{"missing secrets directory", func(_, s string) { _ = os.RemoveAll(s) }, "scrape: secrets_dir_invalid"},
	}
	for _, c := range cases {
		config, secrets := scrapeCmdFiles(t, "https://exporter.example.test/metrics", nil)
		c.mutate(config, secrets)
		_, err := parseScrapeFlags(t, "--scrape-config", config, "--scrape-secrets-dir", secrets).settings()
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		got := scrapeFailureNotice(err)
		if got != c.want {
			t.Errorf("%s: notice %q, want %q", c.name, got, c.want)
		}
		for _, leak := range []string{config, secrets, "cmd-target", "exporter.example.test", scrapeCmdCanary} {
			if strings.Contains(got, leak) || strings.Contains(err.Error(), leak) {
				t.Errorf("%s: leaks %q", c.name, leak)
			}
		}
	}
}

// start hands the node's real authority and ingest service to the host and the
// host's Close stops every schedule. The credential in the secrets directory
// belongs to no source of the fresh installation, so the typed health read back
// through the host is grant_denied, and the exporter is not contacted.
func TestScrapeStartRunsTheConfiguredTargetsAndStopsThemOnClose(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	var mu sync.Mutex
	hits := 0
	exporter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
	}))
	defer exporter.Close()
	config, secrets := scrapeCmdFiles(t, exporter.URL+"/metrics", nil)
	settings, err := parseScrapeFlags(t, "--scrape-config", config, "--scrape-secrets-dir", secrets).settings()
	if err != nil {
		t.Fatal(err)
	}
	host, err := settings.start(context.Background(), app)
	if err != nil || host == nil {
		t.Fatalf("%v %v", host, err)
	}
	defer host.Close()
	deadline := time.Now().Add(15 * time.Second)
	var st sources.ScrapeTargetStatus
	for time.Now().Before(deadline) {
		if all := host.Status(); len(all) == 1 && all[0].Cycles >= 1 {
			st = all[0]
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	// The node's real authority answered: the secrets directory holds a credential
	// no source of this fresh installation owns, so the grant is denied (typed) and
	// the exporter is never contacted.
	if st.Alias != "cmd-target" || st.Reason != sources.ScrapeReasonGrantDenied || st.OK() {
		t.Fatalf("status %+v", st)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatalf("an unauthorized target was requested %d times", hits)
	}
	if notice := scrapeStartedNotice(host); notice != "scrape: 1 target(s) started" {
		t.Fatalf("notice %q", notice)
	}
	// Close stops the schedule: no further cycle runs.
	host.Close()
	cycles := host.Status()[0].Cycles
	time.Sleep(2500 * time.Millisecond)
	if after := host.Status()[0].Cycles; after != cycles {
		t.Fatalf("%d cycles ran after Close", after-cycles)
	}
	// not configured: nothing starts
	none, err := scrapeSettings{}.start(context.Background(), app)
	if err != nil || none != nil {
		t.Fatalf("%v %v", none, err)
	}
}

// lockedBuf is a bytes.Buffer safe for the reader goroutine and the test.
type lockedBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuf) WriteString(s string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.WriteString(s)
}

func (b *lockedBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// serveChild runs the real `soundpost serve` in a child process and returns its
// stderr lines on a channel.
func serveChild(t *testing.T, args ...string) (cmd *exec.Cmd, lines <-chan string, errOut *lockedBuf) {
	t.Helper()
	raw, err := json.Marshal(append([]string{"serve"}, args...))
	if err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(os.Args[0], "-test.run=^TestMainHelper$")
	cmd.Env = append(os.Environ(), "SOUNDPOST_TEST_ARGS="+string(raw))
	pipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ch := make(chan string, 256)
	errOut = &lockedBuf{}
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(pipe)
		for sc.Scan() {
			errOut.WriteString(sc.Text() + "\n")
			ch <- sc.Text()
		}
	}()
	return cmd, ch, errOut
}

// The real serve path: the flags are parsed, the configuration is loaded before
// storage opens and the scrapers start after the node opens, and SIGINT stops
// everything and exits cleanly.
func TestServeStartsTheConfiguredScrapers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes and signals")
	}
	config, secrets := scrapeCmdFiles(t, "https://127.0.0.1:9/metrics", nil)
	dir := filepath.Join(t.TempDir(), "data")
	cmd, lines, errOut := serveChild(t, "--data-dir", dir, "--listen", "127.0.0.1:0", "--scrape-config", config, "--scrape-secrets-dir", secrets)
	defer cmd.Process.Kill()
	started := false
	deadline := time.After(40 * time.Second)
wait:
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				break wait
			}
			if line == "scrape: 1 target(s) started" {
				started = true
				break wait
			}
		case <-deadline:
			break wait
		}
	}
	if !started {
		t.Fatalf("serve never reported its scrapers started; stderr:\n%s", errOut.String())
	}
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for range lines {
		}
		done <- cmd.Wait()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve did not exit cleanly after SIGINT: %v\n%s", err, errOut.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("serve did not stop after SIGINT; stderr:\n%s", errOut.String())
	}
	for _, leak := range []string{config, secrets, scrapeCmdCanary, "exporter.example.test"} {
		if strings.Contains(errOut.String(), leak) {
			t.Errorf("serve printed %q", leak)
		}
	}
}

func TestServeRefusesABadScrapeConfigurationBeforeOpeningStorage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	config, secrets := scrapeCmdFiles(t, "https://127.0.0.1:9/metrics", nil)
	if err := os.WriteFile(config, []byte(`{"version":1,"targets":[],"extra":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "data")
	stderr, exit := runSoundpost(t, "serve", "--data-dir", dir, "--listen", "127.0.0.1:0", "--scrape-config", config, "--scrape-secrets-dir", secrets)
	if exit == 0 || !strings.Contains(stderr, "scrape: config_invalid") {
		t.Fatalf("exit %d stderr %q", exit, stderr)
	}
	for _, leak := range []string{config, secrets, scrapeCmdCanary} {
		if strings.Contains(stderr, leak) {
			t.Errorf("stderr leaks %q: %q", leak, stderr)
		}
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("storage was opened (the data directory exists) although the scrape configuration was refused")
	}
}

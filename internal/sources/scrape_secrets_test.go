// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const secretCanary = "CANARY-secret-7f3a91c2d4e85b60"

func privateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func putSecret(t *testing.T, dir, ref, value string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, ref)
	if err := os.WriteFile(p, []byte(value), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func secretReason(t *testing.T, err error) string {
	t.Helper()
	var se *SecretError
	if !errors.As(err, &se) || !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("not a typed secret error: %v", err)
	}
	return se.Reason
}

func TestDirSecretReaderReadsFreshEveryTime(t *testing.T) {
	dir := privateDir(t)
	r, err := NewDirSecretReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	putSecret(t, dir, "exporter-token", "first-value\n", 0o600)
	got, err := r.ReadSecret(context.Background(), "exporter-token")
	if err != nil || string(got) != "first-value" {
		t.Fatalf("first read %q %v (one trailing line feed is not part of the secret)", got, err)
	}
	putSecret(t, dir, "exporter-token", "second-value", 0o600)
	got, err = r.ReadSecret(context.Background(), "exporter-token")
	if err != nil || string(got) != "second-value" {
		t.Fatalf("a rotated secret must be read fresh, not cached: %q %v", got, err)
	}
	if err = os.Remove(filepath.Join(dir, "exporter-token")); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ReadSecret(context.Background(), "exporter-token"); secretReason(t, err) != SecretNotFound {
		t.Fatalf("a removed secret must not be served from memory: %v", err)
	}
	// CRLF is trimmed too; an interior line feed is kept and the fetch layer refuses it.
	putSecret(t, dir, "crlf", "value\r\n", 0o600)
	if got, err = r.ReadSecret(context.Background(), "crlf"); err != nil || string(got) != "value" {
		t.Fatalf("crlf %q %v", got, err)
	}
}

func TestDirSecretReaderRefusesEveryTraversalAndMalformedReference(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "secrets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A readable, private file outside the directory that traversal would reach.
	putSecret(t, root, "outside", secretCanary, 0o600)
	putSecret(t, dir, ".hidden", secretCanary, 0o600)
	putSecret(t, dir, "ok", "fine", 0o600)
	r, err := NewDirSecretReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	refs := []SecretRef{
		"../outside", "..", ".", "./ok", "sub/ok", `sub\ok`, "/etc/passwd", SecretRef(filepath.Join(root, "outside")),
		".hidden", "a..b", "ok/", "ok\x00", "ok ", "", SecretRef(strings.Repeat("a", 65)), "ok:stream", "%2e%2e/outside", "ok\n",
	}
	for _, ref := range refs {
		got, err := r.ReadSecret(context.Background(), ref)
		if err == nil || len(got) != 0 || secretReason(t, err) != SecretBadReference {
			t.Errorf("ref %q: %q %v", ref, got, err)
		}
		if strings.Contains(err.Error(), root) || strings.Contains(err.Error(), secretCanary) {
			t.Errorf("ref %q: the error leaks a path or secret: %v", ref, err)
		}
	}
	if got, err := r.ReadSecret(context.Background(), "ok"); err != nil || string(got) != "fine" {
		t.Fatalf("control read %q %v", got, err)
	}
}

func TestDirSecretReaderRefusesWrongModeSymlinkAndNonRegular(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes and symlinks")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "secrets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r, err := NewDirSecretReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{"group-readable": 0o640, "world-readable": 0o604, "world-writable": 0o666, "group-writable": 0o620, "group-exec": 0o710} {
		putSecret(t, dir, name, secretCanary, mode)
		got, err := r.ReadSecret(context.Background(), SecretRef(name))
		if len(got) != 0 || secretReason(t, err) != SecretInsecureMode {
			t.Errorf("mode %v: %q %v", mode, got, err)
		}
	}
	putSecret(t, dir, "owner-readonly", "ro-value", 0o400)
	if got, err := r.ReadSecret(context.Background(), "owner-readonly"); err != nil || string(got) != "ro-value" {
		t.Errorf("0400 is private: %q %v", got, err)
	}

	// a symbolic link to a perfectly private file is still refused
	putSecret(t, root, "target", secretCanary, 0o600)
	if err = os.Symlink(filepath.Join(root, "target"), filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	got, err := r.ReadSecret(context.Background(), "linked")
	if len(got) != 0 || secretReason(t, err) != SecretSymlink {
		t.Errorf("symlink: %q %v", got, err)
	}
	if err = os.Symlink("missing-target", filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}
	if got, err = r.ReadSecret(context.Background(), "dangling"); len(got) != 0 || secretReason(t, err) != SecretSymlink {
		t.Errorf("dangling symlink: %q %v", got, err)
	}
	if err = os.Mkdir(filepath.Join(dir, "adir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err = r.ReadSecret(context.Background(), "adir"); len(got) != 0 || secretReason(t, err) != SecretNotRegular {
		t.Errorf("directory: %q %v", got, err)
	}
	putSecret(t, dir, "empty", "\n", 0o600)
	if got, err = r.ReadSecret(context.Background(), "empty"); len(got) != 0 || secretReason(t, err) != SecretEmpty {
		t.Errorf("empty: %q %v", got, err)
	}
	putSecret(t, dir, "huge", strings.Repeat("x", scrapeSecretMaxBytes+1), 0o600)
	if got, err = r.ReadSecret(context.Background(), "huge"); len(got) != 0 || secretReason(t, err) != SecretTooLarge {
		t.Errorf("oversize: %q %v", got, err)
	}
}

func TestNewDirSecretReaderChecksTheDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes and symlinks")
	}
	root := t.TempDir()
	open := filepath.Join(root, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDirSecretReader(open); secretReason(t, err) != SecretDirInsecure {
		t.Errorf("a world-readable directory must be refused: %v", err)
	}
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDirSecretReader(link); secretReason(t, err) != SecretDirInvalid {
		t.Errorf("a symlinked directory must be refused: %v", err)
	}
	if _, err := NewDirSecretReader(filepath.Join(root, "missing")); secretReason(t, err) != SecretDirInvalid {
		t.Errorf("a missing directory must be refused: %v", err)
	}
	if _, err := NewDirSecretReader(""); secretReason(t, err) != SecretDirInvalid {
		t.Errorf("an empty directory name must be refused: %v", err)
	}
	file := filepath.Join(root, "file")
	putSecret(t, root, "file", "x", 0o600)
	if _, err := NewDirSecretReader(file); secretReason(t, err) != SecretDirInvalid {
		t.Errorf("a file is not a secrets directory: %v", err)
	}
}

// A missing secret is a typed source health, not an error and never a request:
// the exporter must not be contacted without its credential.
func TestMissingTargetSecretIsSecretUnavailableHealth(t *testing.T) {
	f := newScrapeFixture(t)
	dir := privateDir(t)
	r, err := NewDirSecretReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv, listener := scrapeServe(t, http.NotFoundHandler())
	target := f.target(srv.URL)
	target.Auth, target.Secret, target.Secrets = ScrapeAuthBearer, "absent-token", r
	res, err := FetchScrape(f.ctx, f.grant, target)
	if err != nil {
		t.Fatalf("a missing secret is a health status, not an error: %v", err)
	}
	if res.Health.Status != ScrapeSecretUnavailable || res.Coverage != CoverageUnknown || len(res.Batches) != 0 {
		t.Fatalf("health %+v coverage %s batches %d", res.Health, res.Coverage, len(res.Batches))
	}
	if n := listener.accepts.Load(); n != 0 {
		t.Fatalf("the exporter was contacted %d times without its credential", n)
	}
}

// The credential reaches the exporter and nothing else: the typed result,
// health, every error and the process logs of a failed fetch are free of it.
func TestSecretCanaryNeverAppearsInResultsErrorsOrLogs(t *testing.T) {
	f := newScrapeFixture(t)
	dir := privateDir(t)
	putSecret(t, dir, "canary", secretCanary, 0o600)
	r, err := NewDirSecretReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	oldLog, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&logs)
	oldSlog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer func() { log.SetOutput(oldLog); log.SetFlags(oldFlags); slog.SetDefault(oldSlog) }()

	var mu sync.Mutex
	var seen []string
	srv, _ := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		seen = append(seen, req.Header.Get("Authorization"))
		mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
	}))
	target := f.target(srv.URL)
	target.Auth, target.Secret, target.Secrets = ScrapeAuthBearer, "canary", r
	res, err := FetchScrape(f.ctx, f.grant, target)
	if err != nil || res.Health.Status != ScrapeBadStatus || res.Health.HTTPStatus != 401 {
		t.Fatalf("%+v %v", res, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != "Bearer "+secretCanary {
		t.Fatalf("the exporter must see exactly the bearer header: %q", seen)
	}
	if text := fmt.Sprintf("%+v %#v %v", res, res, err) + logs.String(); strings.Contains(text, secretCanary) {
		t.Fatalf("the secret leaked into the result or logs: %s", text)
	}
}

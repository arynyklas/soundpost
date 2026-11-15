// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

func serveFixture(t *testing.T) (work, keys, restricted string) {
	t.Helper()
	work = t.TempDir()
	keys = filepath.Join(work, "authority.keys")
	restricted = filepath.Join(work, "authority.restricted")
	if _, code := runSoundpost(t, "backup", "authority-keygen", "--out", keys, "--id", "authority-1", "--restricted-out", restricted); code != 0 {
		t.Fatal("authority-keygen failed")
	}
	return work, keys, restricted
}

// serve refuses, before listening and with a static reason that names no path, every
// authority configuration that cannot checkpoint deletions.
func TestServeRefusesAnUnusableAuthorityConfiguration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	work, keys, restricted := serveFixture(t)
	loose := filepath.Join(work, "loose.keys")
	raw, err := os.ReadFile(keys)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(loose, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(loose, 0o640); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(work, "journal")
	data := filepath.Join(work, "data")
	if err = os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	serve := []string{"serve", "--mode=single", "--data-dir", data, "--listen", "127.0.0.1:0"}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"keys without a destination", []string{"--authority-keys", keys}, "both"},
		{"destination without keys", []string{"--authority-dir", journal}, "both"},
		{"restricted keys cannot checkpoint", []string{"--authority-keys", restricted, "--authority-dir", journal}, "full"},
		{"group-readable keys", []string{"--authority-keys", loose, "--authority-dir", journal}, "private"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stderr, code := runSoundpost(t, append(append([]string{}, serve...), tc.args...)...)
			if code != 1 || !strings.Contains(stderr, "--authority") || !strings.Contains(stderr, tc.want) {
				t.Fatalf("exit %d, stderr %q: want a refusal naming the authority flags and %q", code, stderr, tc.want)
			}
			if strings.Contains(stderr, work) {
				t.Fatalf("stderr names a path: %q", stderr)
			}
		})
	}
}

// With no authority flag serve configures nothing; with both it opens the authority and
// installs it on the retention service (a second install is then a conflict).
func TestServeInstallsTheAuthorityOnRetention(t *testing.T) {
	work, keysPath, _ := serveFixture(t)
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	none := addAuthorityFlags(f)
	if err := f.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if a, err := none.open(); a != nil || err != nil {
		t.Fatalf("no flags: authority %v err %v, want neither", a, err)
	}
	f = flag.NewFlagSet("serve", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	flags := addAuthorityFlags(f)
	journal := filepath.Join(work, "journal")
	if err := f.Parse([]string{"--authority-keys", keysPath, "--authority-dir", journal}); err != nil {
		t.Fatal(err)
	}
	authority, err := flags.open()
	if err != nil || authority == nil {
		t.Fatalf("open: %v", err)
	}
	dir := filepath.Join(work, "data")
	if err = os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	core, err := appcore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	var installation model.ID
	if err = core.Control.View(context.Background(), func(st control.State) error { installation = st.Installation; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = authority.Initialize(context.Background(), installation); err != nil {
		t.Fatal(err)
	}
	if err = installServeAuthority(core, authority); err != nil {
		t.Fatal(err)
	}
	var fault *model.Fault
	if err = core.Retention.UseAuthority(authority); !errors.As(err, &fault) || fault.Code != model.Conflict {
		t.Fatalf("second install: %v, want conflict (the first was not installed)", err)
	}
}

// authorityState is what the authority's journal holds now: its head sequence and the
// tombstones of the deletions it has been told about. It opens the journal the way serve does
// (the serve flags, full keys), so it reads exactly what a served node writes.
func authorityState(t *testing.T, keys, journal string) (sequence uint64, tombstones []model.DeletePredicate) {
	t.Helper()
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	flags := addAuthorityFlags(f)
	if err := f.Parse([]string{"--authority-keys", keys, "--authority-dir", journal}); err != nil {
		t.Fatal(err)
	}
	authority, err := flags.open()
	if err != nil || authority == nil {
		t.Fatalf("open the authority: %v", err)
	}
	current, err := authority.Current(context.Background())
	if err != nil {
		t.Fatalf("read the authority journal: %v", err)
	}
	return current.Head.Sequence, current.Tombstones
}

// waitForServe returns a client of the served process once GET /readyz answers 200, trusting the
// certificate the node generated in its own data directory.
func waitForServe(t *testing.T, dir, listen string, stderr *lockedBuf) *api {
	t.Helper()
	for deadline := time.Now().Add(120 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		pemBytes, err := os.ReadFile(filepath.Join(dir, "server.crt"))
		if err != nil {
			continue
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			continue
		}
		jar, _ := cookiejar.New(nil)
		client := &http.Client{Jar: jar, Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
		resp, err := client.Get("https://" + listen + "/readyz")
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return &api{t: t, base: "https://" + listen, client: client}
		}
	}
	t.Fatalf("serve never became ready; stderr:\n%s", stderr.String())
	return nil
}

// A deletion begun and completed through a SERVED node (the real serve process, started with the
// authority flags) reaches the authority: its journal gains a checkpoint naming the deletion. The
// retention worker completes a deletion only with the authority's receipt, so this is also the
// proof that serve installs the authority on the service that begins the deletion. Without that
// wiring (the state before the flags existed) the same deletion completes and the journal stays as
// it was, which a restore would then answer by serving the deleted data again.
func TestAServedDeletionIsCheckpointedToTheAuthorityJournal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes and signals")
	}
	work, keys, _ := serveFixture(t)
	dir := filepath.Join(work, "data")
	journal := filepath.Join(work, "journal")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// The installation exists before the authority is bound to it (backup-restore.md:
	// authority-init --data-dir on the node's own directory).
	first, err := appcore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	if err = runBackup([]string{"authority-init", "--data-dir", dir, "--authority-keys", keys, "--authority-dir", journal}); err != nil {
		t.Fatalf("authority-init: %s", backupFailureLine(err))
	}
	sequenceBefore, tombstonesBefore := authorityState(t, keys, journal)
	if len(tombstonesBefore) != 0 {
		t.Fatalf("a freshly initialized authority already holds %d deletions", len(tombstonesBefore))
	}

	listen := net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))
	cmd, lines, stderr := serveChild(t, "--data-dir", dir, "--listen", listen, "--authority-keys", keys, "--authority-dir", journal)
	defer cmd.Process.Kill()
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range lines {
		}
	}()
	a := waitForServe(t, dir, listen, stderr)

	token, err := os.ReadFile(filepath.Join(dir, "bootstrap.token"))
	if err != nil {
		t.Fatal(err)
	}
	code, raw := a.do("POST", "/api/v1/bootstrap", map[string]string{"Token": strings.TrimSpace(string(token)), "Email": "owner@example.test", "Password": "serve authority password 2026"}, nil)
	var session struct {
		CSRF string `json:"csrf"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &session) != nil {
		t.Fatalf("bootstrap %d: %s", code, raw)
	}
	a.csrf = session.CSRF
	org, project := model.NewID(), model.NewID()
	a.command(org, "create_org", auth.AdminPayload{Name: "serve authority"})
	a.command(org, "create_project", auth.AdminPayload{ID: project, Name: "serve authority project"})

	// Begin retire_project through the served node: 202, fencing.
	var begun httpapi.DeletionReceipt
	for attempt := 0; ; attempt++ {
		var read struct {
			Revision model.Revision `json:"revision"`
		}
		code, raw = a.do("POST", "/api/v1/admin/read", map[string]any{"kind": "organizations"}, nil)
		if code != http.StatusOK || json.Unmarshal(raw, &read) != nil {
			t.Fatalf("admin read %d: %s", code, raw)
		}
		code, raw = a.do("POST", "/api/v1/admin/deletions", httpapi.DeletionRequest{CommandID: model.NewID(), ExpectedRevision: model.Uint64(read.Revision), Mode: model.DeleteRetireProject, OrgID: org, ProjectIDs: []model.ID{project}, Reason: "serve authority checkpoint"}, nil)
		if code == http.StatusConflict && attempt < 8 {
			continue // the background runner moved the revision between the read and the begin
		}
		if code != http.StatusAccepted || json.Unmarshal(raw, &begun) != nil || begun.OperationID == (model.ID{}) {
			t.Fatalf("begin retire_project: %d %s", code, raw)
		}
		break
	}

	// The retention worker of the served node drives it to complete (its pass runs once a minute).
	var phase string
	for deadline := time.Now().Add(6 * time.Minute); phase != model.DeletePhaseComplete; time.Sleep(time.Second) {
		if time.Now().After(deadline) {
			t.Fatalf("the deletion did not complete through the served node (phase %q); stderr:\n%s", phase, stderr.String())
		}
		code, raw = a.do("GET", "/api/v1/lifecycle/operations/"+begun.OperationID.String()+"?org="+org.String(), nil, nil)
		var op httpapi.LifecycleOperation
		if code != http.StatusOK || json.Unmarshal(raw, &op) != nil {
			t.Fatalf("poll %d: %s", code, raw)
		}
		if phase = op.Phase; phase == model.DeletePhaseFailed || phase == model.DeletePhaseHeld {
			t.Fatalf("the deletion ended %s: %s", phase, raw)
		}
	}

	// Stop the node (a graceful stop) before reading its journal.
	if err = cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-drained:
	case <-time.After(60 * time.Second):
		t.Fatalf("serve did not stop; stderr:\n%s", stderr.String())
	}
	_ = cmd.Wait()

	sequenceAfter, tombstonesAfter := authorityState(t, keys, journal)
	if sequenceAfter <= sequenceBefore {
		t.Fatalf("the authority journal did not gain a checkpoint: head sequence %d before, %d after a deletion that completed through the served node", sequenceBefore, sequenceAfter)
	}
	if len(tombstonesAfter) != 1 || tombstonesAfter[0].Org != org || tombstonesAfter[0].Mode != model.DeleteRetireProject || len(tombstonesAfter[0].Projects) != 1 || tombstonesAfter[0].Projects[0] != project || tombstonesAfter[0].Operation != begun.OperationID {
		t.Fatalf("the checkpoint does not name the completed deletion (%s of project %s in org %s): %+v", begun.OperationID, project, org, tombstonesAfter)
	}
}

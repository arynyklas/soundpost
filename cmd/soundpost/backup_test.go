// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"soundpost/internal/appcore"
	"soundpost/internal/artifacts"
	"soundpost/internal/auth"
	"soundpost/internal/backup"
	"soundpost/internal/model"
)

const (
	cliAdminEmail    = "ops@example.test"
	cliAdminPassword = "cli backup fixture password 2026"
)

// TestMainHelper runs the real main() in a child process (see runSoundpost); it is
// a no-op in a normal test run.
func TestMainHelper(t *testing.T) {
	raw := os.Getenv("SOUNDPOST_TEST_ARGS")
	if raw == "" {
		t.Skip("helper process only")
	}
	var args []string
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		t.Fatal(err)
	}
	os.Args = append([]string{"soundpost"}, args...)
	main()
}

// runSoundpost executes `soundpost <args>` as a real process and returns its stderr and exit code.
func runSoundpost(t *testing.T, args ...string) (stderr string, exit int) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainHelper$")
	cmd.Env = append(os.Environ(), "SOUNDPOST_TEST_ARGS="+string(raw))
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	err = cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok {
		return errOut.String(), exitErr.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return errOut.String(), 0
}

// The failure matrix in docs/operations/backup-restore.md is operator-facing
// diagnosis, so the CLI must say which row applies: the typed code and approved
// detail, never a path, a key or the text of an arbitrary error.
func TestBackupCLIReportsTheSafeFailureCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	work := t.TempDir()
	keysPath := filepath.Join(work, "authority-keys.json")
	restrictedPath := filepath.Join(work, "authority-restricted.json")
	if _, code := runSoundpost(t, "backup", "authority-keygen", "--out", keysPath, "--restricted-out", restrictedPath, "--id", "authority-1"); code != 0 {
		t.Fatal("authority-keygen failed")
	}
	worldReadable := filepath.Join(work, "authority-open.json")
	raw, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(worldReadable, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(worldReadable, 0o644); err != nil { // umask may have narrowed it
		t.Fatal(err)
	}
	keyDir := filepath.Join(work, "keys")
	if _, code := runSoundpost(t, "backup", "keygen", "--key-dir", keyDir, "--id", "data-kek"); code != 0 {
		t.Fatal("keygen failed")
	}
	emptyDest := filepath.Join(work, "dest")
	authorityDir := filepath.Join(work, "authority")
	for _, tc := range []struct {
		name string
		args []string
		want []string // every one must appear
	}{
		{"a group-readable authority key file is forbidden",
			[]string{"backup", "authority-init", "--installation", model.NewID().String(), "--authority-keys", worldReadable, "--authority-dir", authorityDir},
			[]string{"forbidden"}},
		{"a backup that is not in the destination is unavailable",
			[]string{"backup", "restore", "--backup-id", model.NewID().String(), "--root", filepath.Join(work, "root"), "--key-dir", keyDir, "--authority-keys", restrictedPath, "--dest-dir", emptyDest, "--authority-dir", authorityDir},
			[]string{"unavailable"}},
		{"a missing authority key file is not found",
			[]string{"backup", "authority-init", "--installation", model.NewID().String(), "--authority-keys", filepath.Join(work, "absent.json"), "--authority-dir", authorityDir},
			[]string{"not_found"}},
		{"an error that is not a typed fault reveals no path",
			[]string{"backup", "keygen", "--key-dir", keyDir, "--id", "data-kek"}, // refuses to overwrite: an OS error naming the file
			[]string{"backup failed"}},
		{"usage is printed for a missing subcommand", []string{"backup"}, []string{"usage: soundpost backup <command>"}},
		{"an unknown flag is a usage error", []string{"backup", "list", "--no-such-flag"}, []string{"usage: soundpost backup <command>"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stderr, code := runSoundpost(t, tc.args...)
			if code != 1 {
				t.Fatalf("exit code %d, want 1", code)
			}
			for _, want := range tc.want {
				if !strings.Contains(stderr, want) {
					t.Fatalf("stderr %q does not name %q", stderr, want)
				}
			}
			if strings.Contains(stderr, "startup or service failed") {
				t.Fatalf("a backup failure was collapsed into the generic line: %q", stderr)
			}
			if strings.Contains(stderr, work) || strings.Contains(stderr, "no-such-flag") {
				t.Fatalf("stderr echoes a path or an input value: %q", stderr)
			}
		})
	}
	t.Run("other commands keep the generic line", func(t *testing.T) {
		stderr, code := runSoundpost(t, "serve", "--mode", "nope")
		if code != 1 || strings.TrimSpace(stderr) != "soundpost: startup or service failed" {
			t.Fatalf("serve failure printed %q (exit %d)", stderr, code)
		}
	})
}

// seedInstallation creates an installation holding one published source-map
// artifact (an artifact reference intent over blob bytes in the data plane).
func seedInstallation(t *testing.T, dir string) {
	t.Helper()
	ctx := context.Background()
	app, err := appcore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	bootstrap, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.Auth.Bootstrap(ctx, bootstrap, cliAdminEmail, cliAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org, project, source, build := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	for _, cmd := range []struct {
		kind string
		p    auth.AdminPayload
	}{{"create_org", auth.AdminPayload{Name: "artifacts"}}, {"create_project", auth.AdminPayload{ID: project, Name: "builds"}}} {
		cmd.p.Reason = "cli backup fixture"
		payload, _ := json.Marshal(cmd.p)
		var revision model.Revision
		_ = app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil })
		if _, err = app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: cmd.kind, Payload: payload}); err != nil {
			t.Fatal(cmd.kind, err)
		}
	}
	if err = app.Control.Update(ctx, func(st *model.ControlState) error {
		o := st.Orgs[org.String()]
		o.Members[session.User.String()] = true
		o.Grants[session.User.String()+":"+project.String()] = []string{"artifacts.write", "artifacts.read", "raw.read"}
		cfg, encodeErr := json.Marshal(auth.SourcePolicyConfig{ProjectID: project, Enabled: true, Readers: []model.ID{session.User}})
		if encodeErr != nil {
			return encodeErr
		}
		o.Settings["source_policy:"+source.String()] = cfg
		st.Orgs[org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{
		CommandID: model.NewID(), Org: org, Project: project, Source: source,
		Expires: model.UnixNano(time.Now().Add(24 * time.Hour).UnixNano()),
		Policy: model.SourcePolicy{Enabled: true, Revision: 1, Class: "structured", Kinds: []model.Kind{model.Metric},
			Resources:     model.ResourceRegistry{Services: []model.ID{model.NewID()}, Environments: []model.ID{model.NewID()}, Builds: []model.ID{build}, Instances: []string{"cli-fixture"}},
			RetentionDays: map[model.Kind]uint32{model.Metric: 30}, MaxBytes: 1 << 30, MaxSeries: 1000},
		Reason: "cli backup fixture source",
	}); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"version":3,"sources":["src/app.ts"],"names":[],"mappings":"AAAA"}`)
	scope, err := app.Auth.Authorize(ctx, actor, org, []model.ID{project}, auth.Permission("artifacts.write"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := artifacts.Manifest{Version: 1, Org: org, Project: project, Source: source, Build: build, DebugID: "debug-1", GeneratedSHA256: model.HashCanonical([]byte("generated")), MapSHA256: model.HashCanonical(raw), Path: "dist/app.js", Size: model.Uint64(len(raw)), RetainUntil: model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
	if _, err = app.Artifacts.Put(ctx, scope, manifest, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if err = app.Control.ValidateArtifactReferences(ctx); err != nil {
		t.Fatalf("the fixture's own artifact does not validate: %v", err)
	}
}

// A restored root keeps its engine closed until `backup activate` lifts the
// restore hold, and artifact-reference validation reads blob bytes through that
// engine. Opening the root for activation must therefore defer the validation
// to the moment the hold is lifted, or an installation that ever stored an
// artifact could never be activated.
func TestBackupActivateOpensARestoredRootHoldingAnArtifact(t *testing.T) {
	work := t.TempDir()
	live, dest, authority, keys := filepath.Join(work, "live"), filepath.Join(work, "dest"), filepath.Join(work, "authority"), filepath.Join(work, "keys")
	keysPath, restricted, root := filepath.Join(work, "authority-keys.json"), filepath.Join(work, "authority-restricted.json"), filepath.Join(work, "restored")
	seedInstallation(t, live)
	t.Setenv("SOUNDPOST_ADMIN_PASSWORD", cliAdminPassword)
	run := func(args ...string) {
		t.Helper()
		if err := runBackup(args); err != nil {
			t.Fatalf("soundpost backup %s: %v (prints as %q)", args[0], err, backupFailureLine(err))
		}
	}
	run("keygen", "--key-dir", keys, "--id", "data-kek")
	run("keygen", "--key-dir", keys, "--id", "secret-kek")
	run("authority-keygen", "--out", keysPath, "--restricted-out", restricted, "--id", "authority-1")
	run("authority-init", "--data-dir", live, "--authority-keys", keysPath, "--authority-dir", authority)
	run("create", "--data-dir", live, "--admin-email", cliAdminEmail, "--key-dir", keys, "--data-kek", "data-kek", "--secret-kek", "secret-kek", "--authority-keys", keysPath, "--authority-dir", authority, "--dest-dir", dest)
	source, err := backup.NewLocalDestination(dest)
	if err != nil {
		t.Fatal(err)
	}
	names, err := source.List(context.Background(), "backups/")
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, name := range names {
		if strings.HasSuffix(name, "/manifest.json") {
			id = strings.TrimSuffix(strings.TrimPrefix(name, "backups/"), "/manifest.json")
		}
	}
	if id == "" {
		t.Fatalf("no backup was created: %v", names)
	}
	run("restore", "--backup-id", id, "--root", root, "--key-dir", keys, "--authority-keys", restricted, "--dest-dir", dest, "--authority-dir", authority)
	if err = runBackup([]string{"activate", "--root", root, "--authority-keys", restricted, "--authority-dir", authority}); err != nil {
		t.Fatalf("a restored root holding an artifact cannot be activated: %s", backupFailureLine(err))
	}
	// Activation is idempotent, and the activated root opens like any other (validation runs at open again).
	run("activate", "--root", root, "--authority-keys", restricted, "--authority-dir", authority)
	app, err := appcore.Open(root)
	if err != nil {
		t.Fatalf("the activated root does not open: %v", err)
	}
	defer app.Close()
	if err = app.Storage.RestoreReady(); err != nil {
		t.Fatalf("the activated root is not ready: %v", err)
	}
	if err = app.Control.ValidateArtifactReferences(context.Background()); err != nil {
		t.Fatalf("the restored artifact's bytes do not verify after activation: %v", err)
	}
}

func TestServeDoesNotPrintTheRestoreRecoveryToken(t *testing.T) {
	dir := t.TempDir()
	const token = "recovery-secret-token"
	if got := bootstrapNotice(dir, token); !strings.Contains(got, token) {
		t.Fatalf("a fresh installation's bootstrap notice lost its token: %q", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "restore.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got := bootstrapNotice(dir, token)
	if strings.Contains(got, token) {
		t.Fatalf("serve wrote the restore's one-time recovery secret to the service log: %q", got)
	}
	if !strings.Contains(got, "bootstrap.token") {
		t.Fatalf("the notice does not say where the token is: %q", got)
	}
}

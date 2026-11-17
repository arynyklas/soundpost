// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/backup"
	"github.com/arynyklas/soundpost/internal/config"
)

// gateWork is one installation, its keys, and an installation file whose off-host backup points at the
// named destination and authority directories.
type gateWork struct {
	t                      *testing.T
	dir, live, keys        string
	keysPath, restrictedAt string
}

func newGateWork(t *testing.T) *gateWork {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	w := &gateWork{t: t, dir: t.TempDir()}
	w.live, w.keys = filepath.Join(w.dir, "live"), filepath.Join(w.dir, "keys")
	w.keysPath, w.restrictedAt = filepath.Join(w.dir, "authority-keys.json"), filepath.Join(w.dir, "authority-restricted.json")
	seedInstallation(t, w.live)
	t.Setenv("SOUNDPOST_ADMIN_PASSWORD", cliAdminPassword)
	w.run("keygen", "--key-dir", w.keys, "--id", "data-kek")
	w.run("keygen", "--key-dir", w.keys, "--id", "secret-kek")
	w.run("authority-keygen", "--out", w.keysPath, "--restricted-out", w.restrictedAt, "--id", "authority-1")
	return w
}

func (w *gateWork) run(args ...string) {
	w.t.Helper()
	if err := runBackup(args); err != nil {
		w.t.Fatalf("soundpost backup %s: %v (prints as %q)", args[0], err, backupFailureLine(err))
	}
}

// installFile writes an installation file (single node) whose backup block is mode, with the stores
// at dest and authority when the mode is off-host. It is written by hand: a SecretRef never marshals
// (it prints [redacted]), by design.
func (w *gateWork) installFile(name string, mode config.BackupMode, dest, authority string) string {
	w.t.Helper()
	backupBlock := "  mode: none\n"
	switch mode {
	case config.BackupLocal:
		backupBlock = "  mode: local\n  local:\n    dir: /var/backups/soundpost\n"
	case config.BackupOffhost:
		backupBlock = "  mode: offhost\n" +
			"  destination:\n    kind: dir\n    path: " + dest + "\n    device_id: device-backup\n" +
			"  authority:\n    store:\n      kind: dir\n      path: " + authority + "\n      device_id: device-authority\n" +
			"    keys: file:" + w.keysPath + "\n    restricted_keys: file:" + w.restrictedAt + "\n    signing_node: node-a\n" +
			"    capabilities:\n      conditional_create: true\n      fresh_head: true\n      restricted_restore: true\n" +
			"  data_kek_id: data-kek\n  secret_kek_id: secret-kek\n  retention_days: 30\n"
	}
	text := "mode: single\nreplication_factor: 1\n" +
		"nodes:\n  - id: 1\n    identity: node-a\n    failure_domain: domain-a\n    peer_address: https://soundpost-a.example.invalid:9444\n    peer_listen: 0.0.0.0:9444\n" +
		"    disk:\n      id: disk-a\n      volume: vol-a\n      path: /var/lib/soundpost\n      capacity_bytes: 1099511627776\n" +
		"    certificate: /etc/soundpost/pki/a.pem\n    private_key: file:/etc/soundpost/pki/a.key\n" +
		"listen:\n  address: 0.0.0.0:8443\n  public_origins:\n    - https://soundpost.example.invalid\n" +
		"sources:\n  - id: backend\n    class: private\n" +
		"quotas:\n  max_bytes_per_source: 1073741824\n  max_series_per_source: 1000\n" +
		"retention:\n  days:\n    metric: 30\n" +
		"backup:\n" + backupBlock
	cfg, err := config.Parse([]byte(text))
	if err != nil {
		w.t.Fatalf("the fixture installation file does not parse: %v", err)
	}
	if err = config.Validate(cfg); err != nil {
		w.t.Fatalf("the fixture installation file does not validate: %v", err)
	}
	path := filepath.Join(w.dir, name)
	if err = os.WriteFile(path, []byte(text), 0o600); err != nil {
		w.t.Fatal(err)
	}
	return path
}

func (w *gateWork) create(extra ...string) (stdout string, err error) {
	w.t.Helper()
	args := append([]string{"create", "--data-dir", w.live, "--admin-email", cliAdminEmail, "--key-dir", w.keys, "--data-kek", "data-kek", "--secret-kek", "secret-kek", "--authority-keys", w.keysPath}, extra...)
	saved := os.Stdout
	r, wr, perr := os.Pipe()
	if perr != nil {
		w.t.Fatal(perr)
	}
	os.Stdout = wr
	err = runBackup(args)
	os.Stdout = saved
	wr.Close()
	out, _ := io.ReadAll(r)
	return string(out), err
}

func objects(t *testing.T, dir string) []string {
	t.Helper()
	d, err := backup.NewLocalDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	names, err := d.List(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// 07.02#12: an off-host backup cannot be taken or labelled deletion-safe unless the authority's conditional
// create and a fresh verified head pass NOW; the gate is in front of `backup create`, not only in soundpost-config.
func TestBackupCreateUnderAnInstallationFileIsRefusedUntilTheAuthorityGatePasses(t *testing.T) {
	w := newGateWork(t)
	dest, authority := filepath.Join(w.dir, "dest"), filepath.Join(w.dir, "authority")

	// the authority journal was never initialised: no head, no backup, nothing written
	offhost := w.installFile("offhost.yaml", config.BackupOffhost, dest, authority)
	_, err := w.create("--install-config", offhost, "--authority-dir", authority, "--dest-dir", dest)
	if err == nil || !strings.Contains(backupFailureLine(err), "backup_not_ready: head_unavailable") {
		t.Fatalf("an uninitialised authority must refuse the backup with the typed reason: %v", err)
	}
	if names := objects(t, dest); len(names) != 0 {
		t.Fatalf("a refused backup wrote objects: %v", names)
	}
	// the authority is untouched by the refusal: initialising it now still works, and the same command is taken
	// and says what it may be called
	w.run("authority-init", "--data-dir", w.live, "--authority-keys", w.keysPath, "--authority-dir", authority)
	stdout, err := w.create("--install-config", offhost, "--authority-dir", authority, "--dest-dir", dest)
	if err != nil {
		t.Fatalf("a passing gate must take the backup: %s", backupFailureLine(err))
	}
	if !strings.Contains(stdout, `"backup_label": "deletion-safe-disaster-backup"`) {
		t.Fatalf("the result must carry the label the passing gate earned:\n%s", stdout)
	}
	if len(objects(t, dest)) == 0 {
		t.Fatal("the backup was not written")
	}

	// the installation file and the command line must name the same stores: a gate on one authority proves nothing about another
	other := filepath.Join(w.dir, "other-authority")
	_, err = w.create("--install-config", offhost, "--authority-dir", other, "--dest-dir", dest)
	if err == nil || !strings.Contains(backupFailureLine(err), "install_config_mismatch") {
		t.Fatalf("a backup to a store the installation file does not declare must be refused: %v", err)
	}
	_, err = w.create("--install-config", offhost, "--authority-dir", authority, "--dest-dir", filepath.Join(w.dir, "other-dest"))
	if err == nil || !strings.Contains(backupFailureLine(err), "install_config_mismatch") {
		t.Fatalf("a backup to a destination the installation file does not declare must be refused: %v", err)
	}
}

// An S3 destination is off-host by nature: without an installation file whose backup block is off-host the
// command refuses before it opens anything (no network, no authority).
func TestBackupCreateToAnS3DestinationNeedsAnOffhostInstallationFile(t *testing.T) {
	w := newGateWork(t)
	authority := filepath.Join(w.dir, "authority")
	s3 := []string{"--dest-s3-endpoint", "https://objects.example.invalid", "--dest-s3-bucket", "backups", "--authority-dir", authority}
	_, err := w.create(s3...)
	if err == nil || !strings.Contains(backupFailureLine(err), "install_config_required") {
		t.Fatalf("an S3 destination without --install-config must be refused: %v", err)
	}
	local := w.installFile("local.yaml", config.BackupLocal, "", "")
	_, err = w.create(append([]string{"--install-config", local}, s3...)...)
	if err == nil || !strings.Contains(backupFailureLine(err), "install_config_mode") {
		t.Fatalf("an S3 destination under a local-copy installation file must be refused: %v", err)
	}
	if names := objects(t, authority); len(names) != 0 {
		t.Fatalf("a refused backup touched the authority: %v", names)
	}
}

// A local backup mode is a recovery copy: the command takes it and labels it as exactly that; a command line
// without an installation file keeps working and says the label is unverified.
func TestBackupCreateLabelsALocalCopyAndAnUnverifiedRun(t *testing.T) {
	w := newGateWork(t)
	dest, authority := filepath.Join(w.dir, "dest"), filepath.Join(w.dir, "authority")
	w.run("authority-init", "--data-dir", w.live, "--authority-keys", w.keysPath, "--authority-dir", authority)
	local := w.installFile("local.yaml", config.BackupLocal, "", "")
	stdout, err := w.create("--install-config", local, "--authority-dir", authority, "--dest-dir", dest)
	if err != nil || !strings.Contains(stdout, `"backup_label": "local-recovery-copy"`) {
		t.Fatalf("local mode: err=%v\n%s", err, stdout)
	}
	stdout, err = w.create("--authority-dir", authority, "--dest-dir", filepath.Join(w.dir, "dest2"))
	if err != nil || !strings.Contains(stdout, `"backup_label": "unverified"`) {
		t.Fatalf("no installation file: err=%v\n%s", err, stdout)
	}
	bad := filepath.Join(w.dir, "bad.yaml")
	if err = os.WriteFile(bad, []byte("not: an installation\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = w.create("--install-config", bad, "--authority-dir", authority, "--dest-dir", dest)
	var message cliError
	if !errors.As(err, &message) || !strings.Contains(string(message), "install_config_invalid") || strings.Contains(string(message), w.dir) {
		t.Fatalf("an invalid installation file must be refused without echoing its path: %v", err)
	}
}

func gateFlags(t *testing.T, name string, args ...string) *destinationFlags {
	t.Helper()
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	d := newDestinationFlags(f, name)
	if err := f.Parse(args); err != nil {
		t.Fatal(err)
	}
	return d
}

// An S3 store is identified by its region too: a gate that verified one location cannot be used to write another.
func TestBackupGateSameS3StoreComparesTheRegion(t *testing.T) {
	store := config.Store{Kind: "s3", Endpoint: "https://objects.example.invalid", Region: "eu-west-1", Bucket: "backups", Prefix: "p"}
	base := []string{"--dest-s3-endpoint", "https://objects.example.invalid", "--dest-s3-bucket", "backups", "--dest-s3-prefix", "p"}
	if !sameStore(gateFlags(t, "dest", append(append([]string{}, base...), "--dest-s3-region", "eu-west-1")...), store) {
		t.Fatal("the identical store must match")
	}
	for name, args := range map[string][]string{
		"another region":   append(append([]string{}, base...), "--dest-s3-region", "us-east-1"),
		"no region flag":   base,
		"another bucket":   {"--dest-s3-endpoint", "https://objects.example.invalid", "--dest-s3-bucket", "other", "--dest-s3-prefix", "p", "--dest-s3-region", "eu-west-1"},
		"another endpoint": {"--dest-s3-endpoint", "https://elsewhere.example.invalid", "--dest-s3-bucket", "backups", "--dest-s3-prefix", "p", "--dest-s3-region", "eu-west-1"},
		"another prefix":   {"--dest-s3-endpoint", "https://objects.example.invalid", "--dest-s3-bucket", "backups", "--dest-s3-prefix", "q", "--dest-s3-region", "eu-west-1"},
	} {
		if sameStore(gateFlags(t, "dest", args...), store) {
			t.Errorf("%s must not match the declared store", name)
		}
	}
	// the file declares no region: only a command line without one is the same store
	store.Region = ""
	if !sameStore(gateFlags(t, "dest", base...), store) {
		t.Fatal("a store without a region matches a command line without one")
	}
	if sameStore(gateFlags(t, "dest", append(append([]string{}, base...), "--dest-s3-region", "eu-west-1")...), store) {
		t.Fatal("a region named only on the command line is another location")
	}
}

// The gate refuses an S3 location whose region differs from the installation file's, before the store is opened.
func TestBackupGateRefusesAnS3RegionTheInstallationFileDoesNotDeclare(t *testing.T) {
	w := newGateWork(t)
	dest, authority := filepath.Join(w.dir, "dest"), filepath.Join(w.dir, "authority")
	text, err := os.ReadFile(w.installFile("dirs.yaml", config.BackupOffhost, dest, authority))
	if err != nil {
		t.Fatal(err)
	}
	dirBlock := "  destination:\n    kind: dir\n    path: " + dest + "\n    device_id: device-backup\n"
	s3Block := "  destination:\n    kind: s3\n    endpoint: https://objects.example.invalid\n    region: eu-west-1\n    bucket: backups\n" +
		"    access_key: env:SOUNDPOST_DEST_S3_ACCESS_KEY\n    secret_key: env:SOUNDPOST_DEST_S3_SECRET_KEY\n"
	if !strings.Contains(string(text), dirBlock) {
		t.Fatal("the fixture's destination block changed")
	}
	path := filepath.Join(w.dir, "s3.yaml")
	if err = os.WriteFile(path, []byte(strings.Replace(string(text), dirBlock, s3Block, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	d := gateFlags(t, "dest", "--dest-s3-endpoint", "https://objects.example.invalid", "--dest-s3-region", "us-east-1", "--dest-s3-bucket", "backups")
	a := gateFlags(t, "authority", "--authority-dir", authority)
	_, err = backupGate(path, d, a, w.keysPath, time.Now)
	var message cliError
	if !errors.As(err, &message) || !strings.Contains(string(message), "install_config_mismatch") {
		t.Fatalf("a region the installation file does not declare must be refused: %v", err)
	}
}

// --authority-keys must be the key file the installation file declares; the refusal comes from the gate,
// before the authority is opened or the backup runs, and its text carries no path.
func TestBackupCreateRefusesAuthorityKeysTheInstallationFileDoesNotDeclare(t *testing.T) {
	w := newGateWork(t)
	dest, authority := filepath.Join(w.dir, "dest"), filepath.Join(w.dir, "authority")
	w.run("authority-init", "--data-dir", w.live, "--authority-keys", w.keysPath, "--authority-dir", authority)
	offhost := w.installFile("offhost.yaml", config.BackupOffhost, dest, authority)

	// the restricted keys are valid keys of the same authority, but not the file the installation declares
	for name, keys := range map[string]string{"restricted keys": w.restrictedAt, "another file": filepath.Join(w.dir, "elsewhere", "authority-keys.json")} {
		saved := w.keysPath
		w.keysPath = keys
		stdout, err := w.create("--install-config", offhost, "--authority-dir", authority, "--dest-dir", dest)
		w.keysPath = saved
		var message cliError
		if !errors.As(err, &message) || !strings.Contains(string(message), "install_config_authority_keys_mismatch") {
			t.Fatalf("%s: keys the installation file does not declare must be refused by the gate: %v", name, err)
		}
		if strings.Contains(string(message), w.dir) || strings.Contains(stdout, `"backup_label"`) {
			t.Fatalf("%s: the refusal must be static and take no backup: %v\n%s", name, err, stdout)
		}
		if names := objects(t, dest); len(names) != 0 {
			t.Fatalf("%s: a refused backup wrote objects: %v", name, names)
		}
	}
	// an equivalent spelling of the declared path is the same file
	spelled := filepath.Join(w.dir, "sub", "..", "authority-keys.json")
	saved := w.keysPath
	w.keysPath = spelled
	_, err := w.create("--install-config", offhost, "--authority-dir", authority, "--dest-dir", dest)
	w.keysPath = saved
	if err != nil {
		t.Fatalf("the declared key file under another spelling must pass: %s", backupFailureLine(err))
	}
}

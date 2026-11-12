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

	"soundpost/internal/appcore"
	"soundpost/internal/control"
	"soundpost/internal/model"
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

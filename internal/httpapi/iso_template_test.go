// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
)

// Every isoEnv starts from a freshly bootstrapped installation: one owner, one session. Bootstrapping is a
// password KDF (3 passes over 64 MiB, about 0.4 CPU-seconds under -race) plus opening the installation, and
// this package builds several hundred environments, so each environment used to pay it again for the same
// result. The installation is now bootstrapped once through the real Bootstrap path, closed, and each
// environment opens its own byte-for-byte copy of it, the way a restart opens a data directory.
//
// Nothing about an environment is shared: every one has its own directory, its own control store and its own
// storage engine. They share only the identity the bootstrap minted (owner ID, session token), which no test
// compares across environments.
//
// The owner's session is only "fresh" (auth.Credential.Fresh, which every administrative command requires)
// for five minutes after its login, so the template is bootstrapped again when it is older than
// isoTemplateMaxAge; an environment therefore always starts with at least four minutes of freshness left, the
// longest test of this package needing a fraction of that.
const isoTemplateMaxAge = time.Minute

var isoTemplate struct {
	mu      sync.Mutex
	dir     string
	built   time.Time
	session auth.Session
	dirs    []string // every directory made for a template or a snapshot, removed when the test binary ends
}

func TestMain(m *testing.M) {
	code := m.Run()
	isoTemplate.mu.Lock()
	for _, dir := range isoTemplate.dirs {
		os.RemoveAll(dir)
	}
	isoTemplate.mu.Unlock()
	os.Exit(code)
}

// isoKeepDir makes a directory that outlives the test that asked for it and is removed when the test binary ends.
func isoKeepDir(t *testing.T, pattern string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", pattern)
	if err != nil {
		t.Fatal(err)
	}
	isoTemplate.mu.Lock()
	isoTemplate.dirs = append(isoTemplate.dirs, dir)
	isoTemplate.mu.Unlock()
	return dir
}

// isoBootstrapped returns a directory holding its own copy of a bootstrapped installation, closed, and the
// session the bootstrap issued. The caller opens the directory with appcore.Open.
func isoBootstrapped(t *testing.T) (string, auth.Session) {
	t.Helper()
	dst := t.TempDir()
	return dst, isoBootstrappedInto(t, dst)
}

// isoBootstrappedInto copies the bootstrapped installation into the existing directory dst and returns the
// session the bootstrap issued.
func isoBootstrappedInto(t *testing.T, dst string) auth.Session {
	t.Helper()
	var dir string
	var session auth.Session
	func() {
		isoTemplate.mu.Lock()
		defer isoTemplate.mu.Unlock()
		if isoTemplate.dir == "" || time.Since(isoTemplate.built) > isoTemplateMaxAge {
			made, err := os.MkdirTemp("", "soundpost-iso-template-")
			if err != nil {
				t.Fatal(err)
			}
			isoTemplate.dirs = append(isoTemplate.dirs, made)
			app, err := appcore.Open(made)
			if err != nil {
				t.Fatal(err)
			}
			boot, err := app.Control.BootstrapToken()
			if err != nil {
				app.Close()
				t.Fatal(err)
			}
			issued, err := app.Auth.Bootstrap(context.Background(), boot, "isolation-owner@example.test", "isolation owner password 2026")
			app.Close()
			if err != nil {
				t.Fatal(err)
			}
			isoTemplate.dir, isoTemplate.built, isoTemplate.session = made, time.Now(), issued
		}
		dir, session = isoTemplate.dir, isoTemplate.session
	}()
	copyInstallation(t, dir, dst)
	return session
}

// An isoSnapshot is a closed installation with more in it than a bootstrap: whatever build made on a fresh
// environment (organizations, users, grants), kept with the plain values build returned (identifiers, session
// tokens). A family of tests whose fixture is dozens of password KDFs builds it once, through the same helpers
// and the same real paths, and every test of the family opens its own copy, the way isoBootstrapped does for the
// bare installation. Like the template it is built again after isoTemplateMaxAge, so the sessions in it stay fresh.
type isoSnapshot[T any] struct {
	mu      sync.Mutex
	dir     string
	built   time.Time
	session auth.Session
	data    T
}

// get returns a directory with the caller's own copy of the snapshot, the owner's session of the installation it was
// built on, and what build returned. build runs, on the calling test, only when there is no snapshot younger than
// isoTemplateMaxAge; the environment it is given is shut down before get returns.
func (s *isoSnapshot[T]) get(t *testing.T, build func(*isoEnv) T) (string, auth.Session, T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == "" || time.Since(s.built) > isoTemplateMaxAge {
		dir := isoKeepDir(t, "soundpost-iso-snapshot-")
		session := isoBootstrappedInto(t, dir)
		e := newIsoEnvAt(t, dir, session)
		s.data = build(e)
		e.shutdown()
		s.dir, s.built, s.session = dir, time.Now(), session
	}
	dst := t.TempDir()
	copyInstallation(t, s.dir, dst)
	return dst, s.session, s.data
}

// copyInstallation copies the closed installation src into the existing directory dst, keeping every mode.
func copyInstallation(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(out, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return &fs.PathError{Op: "copy", Path: path, Err: fs.ErrInvalid}
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		o, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_EXCL, info.Mode().Perm())
		if err != nil {
			return err
		}
		if _, err = io.Copy(o, in); err != nil {
			o.Close()
			return err
		}
		return o.Close()
	})
	if err != nil {
		t.Fatalf("copy the installation: %v", err)
	}
}

// rebind is who as this environment's own authenticator knows them: a snapshot keeps a person's identifier and
// session, and the credential derived from the session is bound to the application it was derived on.
func (e *isoEnv) rebind(who person) person {
	e.t.Helper()
	cred, err := e.app.Auth.Authenticate(e.ctx, who.Session.Token)
	if err != nil {
		e.t.Fatal(err)
	}
	who.Cred = cred
	return who
}

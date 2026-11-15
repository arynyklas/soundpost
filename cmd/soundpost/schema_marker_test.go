// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
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
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/health"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// serveProcess is a real `soundpost serve` child (the test binary's main, see TestMainHelper).
type serveProcess struct {
	cmd    *exec.Cmd
	stderr *syncBuffer
	exited chan error
	addr   string
	cert   string
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func startServe(t *testing.T, dir string) *serveProcess {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal([]string{"serve", "--mode=single", "--data-dir", dir, "--listen", addr})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainHelper$")
	cmd.Env = append(os.Environ(), "SOUNDPOST_TEST_ARGS="+string(raw))
	p := &serveProcess{cmd: cmd, stderr: &syncBuffer{}, exited: make(chan error, 1), addr: addr, cert: filepath.Join(dir, "server.crt")}
	cmd.Stderr = p.stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.exited <- cmd.Wait() }()
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			select {
			case <-p.exited:
			case <-time.After(10 * time.Second):
			}
		}
	})
	return p
}

// ready is `soundpost ready` against the child: the same probe, the installation's own certificate.
func (p *serveProcess) ready() health.Readiness {
	return probeReady("https://"+p.addr, p.cert, 3*time.Second)
}

// settle polls the child's readiness until it names a reason other than "no listener yet" or
// "still starting", or the child exits (the second result is then false) or the deadline passes.
func (p *serveProcess) settle(t *testing.T) (health.Readiness, bool) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-p.exited:
			p.exited <- nil
			return health.Readiness{}, false
		default:
		}
		got := p.ready()
		if got.Ready || (got.Reason != health.ReasonUnreachable && got.Reason != health.ReasonStarting) {
			return got, true
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the child neither answered nor exited; stderr:\n%s", p.stderr.String())
	return health.Readiness{}, false
}

// installationWithMarker is a data directory holding an initialized installation whose persisted
// format marker was rewritten to marker, stopped and closed again.
func installationWithMarker(t *testing.T, marker uint8) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "installation")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	app, err := appcore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = app.Control.Update(t.Context(), func(st *model.ControlState) error { st.BearerHashKeyVersion = marker; return nil })
	if cerr := app.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// garbleMarker makes the stored state's marker undecodable (a string where the number is) and
// re-seals the state, so the file still opens: the marker, not the file, is what is garbage.
func garbleMarker(t *testing.T, dir string) {
	t.Helper()
	db, err := bolt.Open(filepath.Join(dir, "control.db"), 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("control"))
		state := bytes.Clone(b.Get([]byte("state")))
		field := []byte(`"BearerHashKeyVersion":1`)
		if !bytes.Contains(state, field) {
			t.Fatalf("the stored state does not carry %s", field)
		}
		state = bytes.Replace(state, field, []byte(`"BearerHashKeyVersion":"garbage"`), 1)
		sum := sha256.Sum256(state)
		if err := b.Put([]byte("state"), state); err != nil {
			return err
		}
		return b.Put([]byte("state_seal"), sum[:])
	})
	if err != nil {
		t.Fatal(err)
	}
}

func requireNoLongerServing(t *testing.T, p *serveProcess) {
	t.Helper()
	roots := x509.NewCertPool()
	pemBytes, err := os.ReadFile(p.cert)
	if err != nil || !roots.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("no certificate to trust: %v", err)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, DisableKeepAlives: true}}
	for _, path := range []string{"/api/v1/session", "/api/v1/login"} {
		resp, err := client.Get("https://" + p.addr + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("GET %s answered %d %s, a refusing member serves nothing", path, resp.StatusCode, body)
		}
	}
}

// A data directory whose format marker differs from what the binary supports is not corruption: the
// member stays up as an unready member whose /readyz (and so `soundpost ready`) names schema_newer
// or schema_old, and serves nothing. A marker that cannot be read at all stays corrupt and the
// process exits with that typed reason.
func TestServeRefusesAForeignSchemaMarkerWithATypedReadinessReason(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	for _, tc := range []struct {
		name   string
		marker uint8
		want   health.Reason
	}{
		{"marker above the binary's", auth.SchemaMarker + 1, health.ReasonSchemaNewer},
		{"marker below the binary's", auth.SchemaMarker - 1, health.ReasonSchemaOld},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := installationWithMarker(t, tc.marker)
			p := startServe(t, dir)
			got, listening := p.settle(t)
			if !listening {
				t.Fatalf("serve exited instead of staying up as an unready member; stderr:\n%s", p.stderr.String())
			}
			if got.Ready || got.Reason != tc.want {
				t.Fatalf("readiness %+v, want unready with %s; stderr:\n%s", got, tc.want, p.stderr.String())
			}
			requireNoLongerServing(t, p)
			select {
			case err := <-p.exited:
				t.Fatalf("the refusing member exited (%v) instead of staying unready; stderr:\n%s", err, p.stderr.String())
			default:
			}
			if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-p.exited:
				if err != nil {
					t.Fatalf("a stopped refusing member must exit cleanly: %v", err)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("the refusing member ignored SIGTERM")
			}
			log := p.stderr.String()
			if !strings.Contains(log, string(tc.want)) || strings.Contains(log, "reason=corrupt") || strings.Contains(log, dir) {
				t.Fatalf("log must name %s, never corruption or the data directory:\n%s", tc.want, log)
			}
		})
	}
	t.Run("a marker that cannot be read is corruption", func(t *testing.T) {
		dir := installationWithMarker(t, auth.SchemaMarker)
		garbleMarker(t, dir)
		p := startServe(t, dir)
		select {
		case err := <-p.exited:
			if err == nil {
				t.Fatal("serve exited cleanly on an unreadable marker")
			}
		case <-time.After(90 * time.Second):
			t.Fatalf("serve kept running on an unreadable marker; readiness %+v", p.ready())
		}
		if log := p.stderr.String(); !strings.Contains(log, "startup or service failed (reason=corrupt)") {
			t.Fatalf("an unreadable marker must stay corrupt, stderr:\n%s", log)
		}
	})
}

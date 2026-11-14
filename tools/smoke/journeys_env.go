// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// journeyID derives a deterministic identity from a name, so the expected IDs are known before
// anything runs and identical on every run.
func journeyID(name string) model.ID {
	sum := sha256.Sum256([]byte("soundpost/reference-journeys/v1/" + name))
	return model.ID(sum[:16])
}

// journeyPKI writes a private CA and a loopback leaf (ECDSA P-256, short lived).
type journeyPKI struct {
	CA, Cert, Key string
	pool          *x509.CertPool
	caCert        *x509.Certificate
}

func newJourneyPKI(dir string) (*journeyPKI, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Soundpost reference journeys private CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	p := &journeyPKI{CA: filepath.Join(dir, "ca.pem"), Cert: filepath.Join(dir, "leaf.pem"), Key: filepath.Join(dir, "leaf.key"), caCert: caCert, pool: x509.NewCertPool()}
	p.pool.AddCert(caCert)
	for path, block := range map[string]*pem.Block{p.CA: {Type: "CERTIFICATE", Bytes: caDER}, p.Cert: {Type: "CERTIFICATE", Bytes: leafDER}, p.Key: {Type: "EC PRIVATE KEY", Bytes: keyDER}} {
		if err = os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *journeyPKI) client() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: p.pool, MinVersion: tls.VersionTLS13}, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// jproc is one real child process with captured output (never printed unfiltered: the logs are
// scanned for canaries and reported by size only).
type jproc struct {
	name string
	cmd  *exec.Cmd
	out  *syncBuffer
	err  *syncBuffer
	done chan error
}

func startJProc(name string, dir string, env []string, argv ...string) (*jproc, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	p := &jproc{name: name, cmd: cmd, out: &syncBuffer{}, err: &syncBuffer{}, done: make(chan error, 1)}
	cmd.Stdout, cmd.Stderr = p.out, p.err
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() { p.done <- cmd.Wait() }()
	return p, nil
}

// stop sends SIGTERM and waits; the exit error is returned (nil = exit status 0).
func (p *jproc) stop(limit time.Duration) error {
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-p.done:
		p.done <- err
		return err
	case <-time.After(limit):
		_ = p.cmd.Process.Kill()
		err := <-p.done
		p.done <- err
		return fmt.Errorf("%s did not stop within %s", p.name, limit)
	}
}

func (p *jproc) wait(limit time.Duration) error {
	select {
	case err := <-p.done:
		p.done <- err
		return err
	case <-time.After(limit):
		_ = p.cmd.Process.Kill()
		<-p.done
		return fmt.Errorf("%s exceeded %s", p.name, limit)
	}
}

func (p *jproc) exited() bool {
	select {
	case err := <-p.done:
		p.done <- err
		return true
	default:
		return false
	}
}

func waitHTTPS(client *http.Client, url string, p *jproc, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if p != nil && p.exited() {
			return fmt.Errorf("%s exited before answering", p.name)
		}
		resp, err := client.Get(url)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("%s not ready within %s", url, limit)
}

func runOut(dir string, env []string, argv ...string) (string, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		return strings.TrimSpace(out.String()), fmt.Errorf("%s: %w: %s", argv[0], err, firstLine(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// lastJSONLine returns the last line of out that starts with '{'.
func lastJSONLine(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); strings.HasPrefix(l, "{") {
			return l
		}
	}
	return ""
}

// journeyDeepContains reports whether needle occurs in data directly or inside base64 text nested
// up to depth levels (the same decoding the storage canary tests use for batch commands).
func journeyDeepContains(data, needle []byte, depth int) bool {
	if bytes.Contains(data, needle) {
		return true
	}
	if depth == 0 {
		return false
	}
	for _, run := range base64Run.FindAll(data, -1) {
		for skip := range 4 {
			if skip >= len(run) {
				break
			}
			for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
				text := bytes.TrimRight(run[skip:], "=")
				if len(text)%4 == 1 {
					text = text[:len(text)-1]
				}
				if decoded, err := enc.DecodeString(string(text)); err == nil && journeyDeepContains(decoded, needle, depth-1) {
					return true
				}
			}
		}
	}
	return false
}

// scanTreeForCanaries walks every regular file under dir (apply database, segments, Raft tree,
// control state, temp files) and reports files holding a canary in any nesting of encodings.
func scanTreeForCanaries(ctx context.Context, dir string, canaries []string) ([]leakHit, int, error) {
	var hits []leakHit
	files := 0
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		files++
		rel, _ := filepath.Rel(dir, p)
		for _, c := range canaries {
			if journeyDeepContains(raw, []byte(c), 5) {
				hits = append(hits, leakHit{Canary: c, Where: "node data dir: " + filepath.ToSlash(rel)})
			}
		}
		return nil
	})
	return hits, files, err
}

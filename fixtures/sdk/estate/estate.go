// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package estate provisions a REAL `soundpost serve` (single mode, verified TLS, OCI sandbox symbolicator) for the
// SDK qualification fixtures: private CA, bootstrap, organization/project/user, artifact and read tokens, and one
// onboarded SDK source whose signed policy the fixtures load. It uses only the product's own HTTP routes; the data
// directory is never read except by the callers that explicitly stop the server first.
package estate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/symbolicate"
)

// Options selects what is provisioned.
type Options struct {
	Binary   string       // linux soundpost binary
	Work     string       // shared work directory (public material only: CA and leaf certificate)
	SymImage string       // local OCI sandbox image; empty disables the symbolicator
	Kinds    []model.Kind // signal kinds the SDK source may deliver
	Builds   []string     // build labels registered in the source policy
	Browser  bool
	Origins  []string
	Replay   bool
	Name     string // identity namespace (deterministic ids)
}

// Estate is one running product.
type Estate struct {
	Opts                             Options
	Addr                             string
	CA, Cert, Key                    string
	Client                           *http.Client
	DataDir                          string
	Org, Project, Source             model.ID
	Service, Environment             model.ID
	Builds                           map[string]model.ID
	WriteToken, ArtifactRead, Reader string
	Onboarded                        auth.SourceOnboarded
	SymStatus                        string

	cmd    *exec.Cmd
	out    bytes.Buffer
	done   chan error
	csrf   string
	keyDir string
	symCfg string
	pool   *x509.CertPool
}

// ID derives a stable identity from a name.
func (e *Estate) ID(name string) model.ID {
	sum := sha256.Sum256([]byte("soundpost/estate/v1/" + e.Opts.Name + "/" + name))
	return model.ID(sum[:16])
}

var exitHooks []func()

// OnExit registers cleanup that Fail runs (newest first) before it exits, so a failed fixture never leaks a
// server process or a database container.
func OnExit(f func()) { exitHooks = append(exitHooks, f) }

// Fail aborts the fixture with a closed, secret-free message.
func Fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "estate: FAIL: "+format+"\n", a...)
	for i := len(exitHooks) - 1; i >= 0; i-- {
		exitHooks[i]()
	}
	os.Exit(1)
}

// Must aborts on err.
func Must(err error, what string) {
	if err != nil {
		Fail("%s: %v", what, err)
	}
}

// Logf prints a progress line.
func Logf(f string, a ...any) { fmt.Fprintf(os.Stderr, "estate: "+f+"\n", a...) }

// Tail returns the last 600 bytes of s.
func Tail(s string) string {
	if len(s) > 600 {
		return s[len(s)-600:]
	}
	return s
}

// RunOut runs a command and returns trimmed combined output.
func RunOut(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return strings.TrimSpace(buf.String()), err
}

// New creates the PKI. Start launches the server.
func New(o Options) *Estate {
	e := &Estate{Opts: o, Builds: map[string]model.ID{}}
	e.setupPKI()
	OnExit(e.Close)
	return e
}

func (e *Estate) setupPKI() {
	dir := filepath.Join(e.Opts.Work, "pki")
	Must(os.MkdirAll(dir, 0o755), "pki dir")
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Must(err, "ca key")
	now := time.Now()
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "soundpost sdk fixtures private CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(12 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	Must(err, "ca cert")
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Must(err, "leaf key")
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	Must(err, "leaf cert")
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	e.CA, e.Cert = filepath.Join(dir, "ca.pem"), filepath.Join(dir, "leaf.pem")
	// The private key never touches the shared checkout.
	e.keyDir, err = os.MkdirTemp("", "estate-key-")
	Must(err, "key dir")
	e.Key = filepath.Join(e.keyDir, "leaf.key")
	for path, block := range map[string]*pem.Block{e.CA: {Type: "CERTIFICATE", Bytes: caDER}, e.Cert: {Type: "CERTIFICATE", Bytes: leafDER}, e.Key: {Type: "EC PRIVATE KEY", Bytes: keyDER}} {
		Must(os.WriteFile(path, pem.EncodeToMemory(block), 0o600), "pki write")
	}
	e.pool = x509.NewCertPool()
	e.pool.AddCert(caCert)
	jar, _ := cookiejar.New(nil)
	e.Client = &http.Client{Timeout: 90 * time.Second, Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.pool, MinVersion: tls.VersionTLS13}, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// TLSCertificate loads the leaf for an in-process fixture listener.
func (e *Estate) TLSCertificate() tls.Certificate {
	c, err := tls.LoadX509KeyPair(e.Cert, e.Key)
	Must(err, "leaf key pair")
	return c
}

// LeafSPKIPin is the base64 SHA-256 of the server leaf's public key, the form Chrome's
// --ignore-certificate-errors-spki-list takes (a certificate pin, not a blanket TLS bypass).
func (e *Estate) LeafSPKIPin() string {
	raw, err := os.ReadFile(e.Cert)
	Must(err, "leaf pem")
	block, _ := pem.Decode(raw)
	if block == nil {
		Fail("leaf pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	Must(err, "leaf parse")
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func (e *Estate) symbolicateConfig() string {
	if e.Opts.SymImage == "" {
		return ""
	}
	if e.symCfg != "" {
		return e.symCfg
	}
	image, err := RunOut("docker", "image", "inspect", "--format", "{{.Id}}", e.Opts.SymImage)
	Must(err, "sandbox image (never pulled)")
	label, err := RunOut("docker", "image", "inspect", "--format", `{{index .Config.Labels "org.soundpost.worker.sha256"}}`, e.Opts.SymImage)
	Must(err, "sandbox image label")
	docker, err := exec.LookPath("docker")
	Must(err, "docker")
	var hash model.Hash
	raw, err := hex.DecodeString(label)
	if err != nil || len(raw) != len(hash) {
		Fail("sandbox image worker label is not a sha256")
	}
	copy(hash[:], raw)
	cfg, _ := json.Marshal(symbolicate.Config{Mode: "oci", OCIRuntime: docker, OCIImage: image, WorkerSHA256: hash, CacheBytes: 1 << 20})
	dir, err := os.MkdirTemp("", "estate-sym-")
	Must(err, "sym dir")
	e.symCfg = filepath.Join(dir, "symbolicate.json")
	Must(os.WriteFile(e.symCfg, cfg, 0o600), "sym config")
	return e.symCfg
}

// Start launches (or relaunches on the same data directory) `soundpost serve`.
func (e *Estate) Start() {
	if e.DataDir == "" {
		d, err := os.MkdirTemp("", "estate-data-")
		Must(err, "data dir")
		e.DataDir = d
	}
	if e.Addr == "" {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		Must(err, "free port")
		e.Addr = l.Addr().String()
		l.Close()
	}
	args := []string{"serve", "--mode=single", "--data-dir", e.DataDir, "--listen", e.Addr, "--tls-cert", e.Cert, "--tls-key", e.Key}
	if cfg := e.symbolicateConfig(); cfg != "" {
		args = append(args, "--symbolicate-config", cfg)
	} else {
		args = append(args, "--symbolicate-sandbox=off")
	}
	e.out.Reset()
	e.done = make(chan error, 1)
	e.cmd = exec.Command(e.Opts.Binary, args...)
	e.cmd.Stdout, e.cmd.Stderr = &e.out, &e.out
	ownProcessGroup(e.cmd)
	Must(e.cmd.Start(), "start soundpost serve")
	go func() { e.done <- e.cmd.Wait() }()
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := e.Client.Get("https://" + e.Addr + "/readyz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		select {
		case err := <-e.done:
			Fail("soundpost serve exited early: %v: %s", err, Tail(e.out.String()))
		default:
		}
		time.Sleep(300 * time.Millisecond)
	}
	for _, line := range strings.Split(e.out.String(), "\n") {
		if strings.HasPrefix(line, "symbolicator:") {
			e.SymStatus = strings.TrimSpace(line)
		}
	}
	if e.Opts.SymImage != "" && !strings.HasPrefix(e.SymStatus, "symbolicator: ready") {
		Fail("symbolicator not ready: %q", e.SymStatus)
	}
	Logf("serve up on %s (%s)", e.Addr, e.SymStatus)
}

// Stop ends the serve process group (idempotent).
func (e *Estate) Stop() {
	if e.cmd == nil {
		return
	}
	terminateGroup(e.cmd, false)
	select {
	case <-e.done:
	case <-time.After(40 * time.Second):
		terminateGroup(e.cmd, true)
		<-e.done
	}
	e.cmd = nil
}

// Close stops the server and removes private material.
func (e *Estate) Close() {
	e.Stop()
	if e.DataDir != "" {
		os.RemoveAll(e.DataDir)
	}
	if e.keyDir != "" {
		os.RemoveAll(e.keyDir)
	}
	if e.symCfg != "" {
		os.RemoveAll(filepath.Dir(e.symCfg))
	}
}

// Post issues a JSON POST: bearer when given, else the owner session with CSRF.
func (e *Estate) Post(path string, body any, bearer string) (int, []byte) {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", "https://"+e.Addr+path, bytes.NewReader(raw))
	Must(err, "request")
	req.Header.Set("Content-Type", "application/json")
	client := e.Client
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
		c := *client
		c.Jar = nil
		client = &c
	} else {
		req.Header.Set("Origin", "https://"+e.Addr)
		req.Header.Set("X-CSRF-Token", e.csrf)
	}
	resp, err := client.Do(req)
	Must(err, "POST "+path)
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp.StatusCode, out
}

// Expect aborts unless the status is the wanted one.
func Expect(what string, status int, raw []byte, want int) {
	if status != want {
		Fail("%s: status %d (want %d): %s", what, status, want, Tail(string(raw)))
	}
}

func (e *Estate) admin(kind string, p auth.AdminPayload) {
	status, raw := e.Post("/api/v1/admin/read", map[string]string{"kind": "organizations"}, "")
	Expect("admin_read", status, raw, 200)
	var view auth.AdminView
	Must(json.Unmarshal(raw, &view), "admin view")
	p.Reason = "sdk fixtures"
	payload, _ := json.Marshal(p)
	status, raw = e.Post("/api/v1/admin/commands", auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: view.Revision, OrgID: e.Org, Kind: kind, Payload: payload}, "")
	Expect("admin_"+kind, status, raw, 200)
}

func (e *Estate) issue(principal model.ID, permissions ...string) string {
	status, raw := e.Post("/api/v1/admin/tokens/issue", map[string]any{"org_id": e.Org, "principal": principal, "projects": []model.ID{e.Project}, "permissions": permissions, "expires": fmt.Sprint(time.Now().Add(2 * time.Hour).Unix()), "reason": "sdk fixtures"}, "")
	Expect("token_issue", status, raw, 200)
	var issued struct{ Token string }
	Must(json.Unmarshal(raw, &issued), "token")
	if issued.Token == "" {
		Fail("empty token")
	}
	return issued.Token
}

// Provision bootstraps the product and onboards the SDK source.
func (e *Estate) Provision() {
	token, err := os.ReadFile(filepath.Join(e.DataDir, "bootstrap.token"))
	Must(err, "bootstrap token")
	status, raw := e.Post("/api/v1/bootstrap", map[string]string{"Token": string(token), "Email": "owner@fixtures.invalid", "Password": "sdk fixtures owner password 2026"}, "")
	Expect("bootstrap", status, raw, 200)
	var session auth.Session
	Must(json.Unmarshal(raw, &session), "session")
	e.csrf = session.CSRF
	e.Org, e.Project, e.Source, e.Service, e.Environment = e.ID("org"), e.ID("project"), e.ID("source"), e.ID("service"), e.ID("environment")
	builder, reader := e.ID("user/builder"), e.ID("user/reader")
	for _, c := range []struct {
		kind string
		p    auth.AdminPayload
	}{
		{"create_org", auth.AdminPayload{Name: "sdk fixtures"}},
		{"create_project", auth.AdminPayload{ID: e.Project, Name: "sdk"}},
		{"create_user", auth.AdminPayload{ID: builder, Email: "builder@fixtures.invalid", Password: "builder fixtures password 2026"}},
		{"membership", auth.AdminPayload{UserID: builder, Enabled: true}},
		{"grant", auth.AdminPayload{UserID: builder, ProjectID: e.Project, Enabled: true, Permissions: []string{"artifacts.write", "artifacts.read"}}},
		{"create_user", auth.AdminPayload{ID: reader, Email: "reader@fixtures.invalid", Password: "reader fixtures password 2026"}},
		{"membership", auth.AdminPayload{UserID: reader, Enabled: true}},
		{"grant", auth.AdminPayload{UserID: reader, ProjectID: e.Project, Enabled: true, Permissions: []string{string(auth.Read)}}},
	} {
		e.admin(c.kind, c.p)
	}
	e.WriteToken = e.issue(builder, "artifacts.write")
	e.ArtifactRead = e.issue(builder, "artifacts.read")
	e.Reader = e.issue(reader, string(auth.Read))
	for _, b := range e.Opts.Builds {
		e.Builds[b] = e.ID("build/" + b)
	}
	if len(e.Builds) == 0 {
		e.Builds["main"] = e.ID("build/main")
	}
	e.Onboarded = e.Onboard(e.Source, e.Opts.Browser, e.Opts.Origins)
}

// Onboard registers one more SDK source (own credential and signed policy) in the project.
func (e *Estate) Onboard(source model.ID, browser bool, origins []string) auth.SourceOnboarded {
	var builds []model.ID
	for _, b := range e.Builds {
		builds = append(builds, b)
	}
	resource := model.ResourceRegistry{Services: []model.ID{e.Service}, Environments: []model.ID{e.Environment}, Builds: builds, Instances: []string{"fixture-1", "fixture-2"}}
	retention := map[model.Kind]uint32{}
	for _, k := range e.Opts.Kinds {
		retention[k] = 14
	}
	ops := []string{"request", "http.call", "db.execute", "worker", "worker.unrelated", "navigation", "ui.action", "job.run"}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: e.Opts.Kinds, Resources: resource, Operations: ops, Dependencies: []string{"api", "postgres", "dependency", "gateway"}, Codes: ops,
		RetentionDays: retention, MaxBytes: 1 << 30, MaxSeries: 1000, Replay: e.Opts.Replay}
	ob := auth.SourceOnboarding{CommandID: model.NewID(), Org: e.Org, Project: e.Project, Source: source, Browser: browser, Origins: origins, Expires: model.UnixNano(time.Now().Add(2 * time.Hour).UnixNano()), Policy: policy, Reason: "sdk fixtures"}
	status, raw := e.Post("/api/v1/sources", ob, "")
	Expect("source_onboard", status, raw, 200)
	var onboarded auth.SourceOnboarded
	Must(json.Unmarshal(raw, &onboarded), "onboarded")
	return onboarded
}

// SDKConfig is the private configuration file the SDK fixtures load (the shape of the reference journeys).
func (e *Estate) SDKConfig(build model.ID, instance string) map[string]any {
	return e.SDKConfigFor(e.Source, e.Onboarded, build, instance)
}

// SDKConfigFor is SDKConfig for any onboarded source.
func (e *Estate) SDKConfigFor(source model.ID, o auth.SourceOnboarded, build model.ID, instance string) map[string]any {
	return map[string]any{
		"org": e.Org, "project": e.Project, "source": source, "credential": o.Credential, "build": build,
		"endpoint": "https://" + e.Addr + "/ingest/v1/batches", "policy": o.Policy, "trusted_keys": o.TrustedKeys, "descriptor": o.Descriptor,
		"resource": model.Resource{Service: e.Service, Environment: e.Environment, Build: build, Instance: instance, Labels: model.Labels{}},
	}
}

// WriteJSON writes v to path (0600).
func WriteJSON(path string, v any) {
	raw, err := json.Marshal(v)
	Must(err, "marshal")
	Must(os.WriteFile(path, raw, 0o600), "write "+filepath.Base(path))
}

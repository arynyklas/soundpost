// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/config"
	"github.com/arynyklas/soundpost/internal/model"
)

// authority is a throw-away certificate authority of the run.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func newAuthority(cn string, serial int64) authority {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err, "ca key")
	t := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: t.Add(-time.Minute), NotAfter: t.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	must(err, "ca cert")
	cert, err := x509.ParseCertificate(der)
	must(err, "ca parse")
	return authority{cert: cert, key: key, der: der}
}

func (a authority) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.der})
}

// leaf issues a certificate for a key pair made here; pkcs8 selects the key encoding (the peer listener's PKCS#8, the public listener's SEC1).
func (a authority) leaf(cn string, serial int64, dns []string, ips []net.IP, uris []*url.URL, pkcs8 bool) (certPEM, keyPEM []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err, "leaf key")
	t := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: t.Add(-time.Minute), NotAfter: t.Add(48 * time.Hour), DNSNames: dns, IPAddresses: ips, URIs: uris,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, a.cert, &key.PublicKey, a.key)
	must(err, "leaf cert")
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if pkcs8 {
		enc, err := x509.MarshalPKCS8PrivateKey(key)
		must(err, "leaf key encode")
		return certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: enc})
	}
	enc, err := x509.MarshalECPrivateKey(key)
	must(err, "leaf key encode")
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: enc})
}

// provisioner drives the admin routes of the throw-away single installation the estate is created on; the cluster is made from its seed.
type provisioner struct {
	addr, dataDir string
	client        *http.Client
	csrf          string
}

// post issues a JSON POST as the owner session (CSRF bound) or with a bearer.
func (s *provisioner) post(path string, body any, bearer string) (int, []byte) {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", "https://"+s.addr+path, bytes.NewReader(raw))
	must(err, "request")
	req.Header.Set("Content-Type", "application/json")
	client := s.client
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
		c := *client
		c.Jar = nil
		client = &c
	} else {
		req.Header.Set("Origin", "https://"+s.addr)
		req.Header.Set("X-CSRF-Token", s.csrf)
	}
	resp, err := client.Do(req)
	must(err, "POST "+path)
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp.StatusCode, out
}

func expect(what string, status int, raw []byte, want int) {
	if status != want {
		msg := string(raw)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		fatalf("%s: status %d (want %d): %s", what, status, want, msg)
	}
}

const provisionReason = "distributed overhead"

func (s *provisioner) admin(org model.ID, kind string, p auth.AdminPayload) {
	p.Reason = provisionReason
	payload, _ := json.Marshal(p)
	command := model.NewID()
	// create_org and create_user are based on the global control revision, every other command on the organization's policy epoch; a
	// 409 is a stale precondition, and the fixed command ID makes the retry idempotent.
	orgScoped := kind != "create_org" && kind != "create_user"
	for attempt := 0; ; attempt++ {
		req := auth.AdminCommandRequest{CommandID: command, OrgID: org, Kind: kind, Payload: payload}
		if orgScoped {
			status, raw := s.post("/api/v1/admin/read", map[string]any{"org_id": org, "kind": "organization"}, "")
			expect("admin_read_org", status, raw, 200)
			var view auth.AdminView
			must(json.Unmarshal(raw, &view), "admin org view")
			req.ExpectedRevision, req.ExpectedEpoch = view.Revision, &view.Epoch
		} else {
			status, raw := s.post("/api/v1/admin/read", map[string]string{"kind": "organizations"}, "")
			expect("admin_read", status, raw, 200)
			var view auth.AdminView
			must(json.Unmarshal(raw, &view), "admin view")
			req.ExpectedRevision = view.Revision
		}
		status, raw := s.post("/api/v1/admin/commands", req, "")
		if status == http.StatusConflict && attempt < 300 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		expect("admin_"+kind, status, raw, 200)
		return
	}
}

// quota sets the admission quota of an organization (see the single-host harness for why the default would refuse the load).
func (s *provisioner) quota(org model.ID, maxBytes, maxSeries uint64) {
	command := model.NewID()
	for attempt := 0; ; attempt++ {
		status, raw := s.post("/api/v1/admin/read", map[string]string{"kind": "organizations"}, "")
		expect("admin_read", status, raw, 200)
		var view auth.AdminView
		must(json.Unmarshal(raw, &view), "admin view")
		status, raw = s.post("/api/v1/quotas", auth.AdmissionQuotaChange{CommandID: command, ExpectedRevision: view.Revision, Org: org,
			MaxBytes: model.Uint64(maxBytes), MaxSeries: model.Uint64(maxSeries), Reason: provisionReason}, "")
		if status == http.StatusConflict && attempt < 300 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		expect("admission_quota", status, raw, 200)
		return
	}
}

// provision bootstraps the product and creates every org, project, read-only user, source credential and policy of the estate.
func (s *provisioner) provision(cfg Config, plan *Plan) {
	token, err := os.ReadFile(filepath.Join(s.dataDir, "bootstrap.token"))
	must(err, "bootstrap token")
	status, raw := s.post("/api/v1/bootstrap", map[string]string{"Token": string(token), "Email": "owner@overhead.invalid", "Password": "distributed overhead owner password 2026"}, "")
	expect("bootstrap", status, raw, 200)
	var session auth.Session
	must(json.Unmarshal(raw, &session), "session")
	s.csrf = session.CSRF
	perOrg := cfg.Projects / cfg.Orgs
	for o := 0; o < cfg.Orgs; o++ {
		first := NewProject(cfg, o*perOrg)
		s.admin(first.Org, "create_org", auth.AdminPayload{Name: fmt.Sprintf("overhead-org-%d", o)})
		s.admin(first.Org, "create_user", auth.AdminPayload{ID: first.Reader, Email: fmt.Sprintf("reader%d@overhead.invalid", o), Password: "distributed overhead reader password 2026"})
		s.admin(first.Org, "membership", auth.AdminPayload{UserID: first.Reader, Enabled: true})
		var projects []model.ID
		for i := 0; i < perOrg; i++ {
			pj := NewProject(cfg, o*perOrg+i)
			projects = append(projects, pj.Project)
			s.admin(pj.Org, "create_project", auth.AdminPayload{ID: pj.Project, Name: fmt.Sprintf("overhead-project-%d", pj.Index)})
			s.admin(pj.Org, "grant", auth.AdminPayload{UserID: pj.Reader, ProjectID: pj.Project, Enabled: true, Permissions: []string{string(auth.Read)}})
			ob := auth.SourceOnboarding{CommandID: model.NewID(), Org: pj.Org, Project: pj.Project, Source: pj.Source, Expires: model.UnixNano(time.Now().Add(policyCredential).UnixNano()), Policy: pj.Policy, Reason: provisionReason}
			status, raw := s.post("/api/v1/sources", ob, "")
			expect(fmt.Sprintf("onboard project %d", pj.Index), status, raw, 200)
			var onboarded auth.SourceOnboarded
			must(json.Unmarshal(raw, &onboarded), "onboarded")
			if onboarded.Credential == "" {
				fatalf("project %d: empty credential", pj.Index)
			}
			plan.Sources = append(plan.Sources, PlanSource{Project: pj.Index, Credential: onboarded.Credential})
		}
		s.quota(first.Org, 1<<40, uint64(perOrg)*uint64(cfg.SeriesPerProject())*11/10)
		status, raw := s.post("/api/v1/admin/tokens/issue", map[string]any{"org_id": first.Org, "principal": first.Reader, "projects": projects, "permissions": []string{string(auth.Read)},
			"expires": fmt.Sprint(time.Now().Add(policyCredential).Unix()), "reason": provisionReason}, "")
		expect("token_issue", status, raw, 200)
		var issued struct{ Token string }
		must(json.Unmarshal(raw, &issued), "token")
		plan.Readers = append(plan.Readers, PlanReader{Org: o, Token: issued.Token})
		fmt.Fprintf(os.Stderr, "distributed: org %d provisioned (%d projects)\n", o, perOrg)
	}
}

// kvList parses "1=a,2=b,3=c" into a map by node id.
func kvList(flagName, s string) map[uint64]string {
	out := map[uint64]string{}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		id, err := strconv.ParseUint(k, 10, 64)
		if !ok || err != nil || id < 1 || id > 3 || v == "" {
			fatalf("--%s: %q is not a list of 1=…,2=…,3=…", flagName, s)
		}
		out[id] = v
	}
	if len(out) != 3 {
		fatalf("--%s needs exactly the three nodes 1, 2 and 3", flagName)
	}
	return out
}

func writePrivate(path string, content []byte) {
	must(os.MkdirAll(filepath.Dir(path), 0o700), "mkdir "+filepath.Dir(path))
	must(os.WriteFile(path, content, 0o600), "write "+path)
}

func runPrepare(args []string) {
	f := flag.NewFlagSet("prepare", flag.ExitOnError)
	bin := f.String("soundpost", "", "soundpost binary the cluster runs")
	work := f.String("work", "", "scratch directory for the throw-away single installation (removed by the caller)")
	out := f.String("out", "", "output directory: node-1..3 bundles, plan.json and ca.pem (private)")
	nodes := f.String("nodes", "", "IP address of each node, 1=…,2=…,3=…")
	domains := f.String("failure-domains", "", "operator attestation of each node's physical failure domain (hypervisor host and disk), 1=…,2=…,3=…")
	nodeRoot := f.String("node-root", "", "absolute directory on every node that holds its bundle and its data (short: the membership socket lives in it)")
	publicPort := f.Int("public-port", 8443, "public HTTPS port of every node")
	peerPort := f.Int("peer-port", 9444, "mTLS peer port of every node")
	controlPort := f.Int("control-port", 9090, "harness control port of every node agent")
	seed := f.Uint64("seed", 20261113, "workload seed")
	orgs := f.Int("orgs", 10, "organizations")
	projects := f.Int("projects", 100, "projects")
	series := f.Int("series", 100000, "active metric series")
	rate := f.Int("rate", 5000, "mixed records per second")
	window := f.Duration("window", 8*time.Second, "per-source flush window")
	f.Parse(args)
	cfg := Config{Seed: *seed, Orgs: *orgs, Projects: *projects, Series: *series, Rate: *rate, Window: *window}
	must(cfg.Check(), "config")
	if *bin == "" || *work == "" || *out == "" || *nodes == "" || *domains == "" || !strings.HasPrefix(*nodeRoot, "/") {
		fatalf("--soundpost, --work, --out, --nodes, --failure-domains and an absolute --node-root are required")
	}
	ips, doms := kvList("nodes", *nodes), kvList("failure-domains", *domains)
	if entries, _ := os.ReadDir(*work); len(entries) > 0 {
		fatalf("work directory %s is not empty", *work)
	}

	// 1. the estate on a throw-away single installation, then its seed (docs/operations/distributed.md, "Initial seed and startup").
	single := filepath.Join(*work, "single")
	must(os.MkdirAll(single, 0o700), "single dir")
	boot := newAuthority("soundpost distributed overhead bootstrap CA", 1)
	bootCert, bootKey := boot.leaf("localhost", 2, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, nil, false)
	certPath, keyPath := filepath.Join(*work, "boot.pem"), filepath.Join(*work, "boot.key")
	writePrivate(certPath, bootCert)
	writePrivate(keyPath, bootKey)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	must(err, "free port")
	addr := lis.Addr().String()
	lis.Close()
	pool := x509.NewCertPool()
	pool.AddCert(boot.cert)
	jar, _ := cookiejar.New(nil)
	pv := &provisioner{addr: addr, dataDir: single, client: &http.Client{Timeout: 120 * time.Second, Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	logf, err := os.OpenFile(filepath.Join(*work, "bootstrap-server.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	must(err, "bootstrap log")
	cmd := exec.Command(*bin, "serve", "--mode=single", "--data-dir", single, "--listen", addr, "--tls-cert", certPath, "--tls-key", keyPath, "--symbolicate-sandbox=off")
	cmd.Env = append(os.Environ(), "GOMAXPROCS=4")
	cmd.Stdout, cmd.Stderr = logf, logf
	must(cmd.Start(), "start the bootstrap installation")
	activePID.Store(int64(cmd.Process.Pid))
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	for began := time.Now(); ; time.Sleep(200 * time.Millisecond) {
		select {
		case err := <-exited:
			fatalf("the bootstrap installation exited during start: %v", err)
		default:
		}
		if resp, err := pv.client.Get("https://" + addr + "/readyz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		if time.Since(began) > 180*time.Second {
			fatalf("the bootstrap installation is not ready after 180 s")
		}
	}
	plan := &Plan{Config: cfg, StartedAt: now()}
	pv.provision(cfg, plan)
	must(cmd.Process.Signal(syscall.SIGTERM), "stop the bootstrap installation")
	select {
	case <-exited:
	case <-time.After(120 * time.Second):
		cmd.Process.Kill()
		<-exited
		fatalf("the bootstrap installation did not stop within 120 s")
	}
	activePID.Store(0)
	seedPath := filepath.Join(*work, "cluster.seed")
	if raw, err := exec.Command(*bin, "cluster-seed", "--data-dir", single, "--output", seedPath).CombinedOutput(); err != nil {
		fatalf("cluster-seed: %v: %s", err, raw)
	}
	seedRaw, err := os.ReadFile(seedPath)
	must(err, "seed")

	// 2. the cluster's PKI: a CA, per node one peer certificate (URI SAN spiffe://soundpost/node/<identity>, the node's address) and one
	// public certificate (the address the SDKs dial), both signed by it.
	ca := newAuthority("soundpost distributed overhead cluster CA", 1)
	names := map[uint64]string{1: "node-a", 2: "node-b", 3: "node-c"}
	var installNodes []config.Node
	for id := uint64(1); id <= 3; id++ {
		ip := net.ParseIP(ips[id])
		if ip == nil {
			fatalf("--nodes: %q is not an IP address", ips[id])
		}
		uri, _ := url.Parse("spiffe://soundpost/node/" + names[id])
		peerCert, peerKey := ca.leaf("distributed overhead node "+names[id], int64(10+id), []string{"localhost"}, []net.IP{ip, net.ParseIP("127.0.0.1")}, []*url.URL{uri}, true)
		pubCert, pubKey := ca.leaf("distributed overhead public "+names[id], int64(20+id), []string{"localhost"}, []net.IP{ip, net.ParseIP("127.0.0.1")}, nil, false)
		bundle := filepath.Join(*out, fmt.Sprintf("node-%d", id))
		writePrivate(filepath.Join(bundle, "pki", fmt.Sprintf("node-%d.pem", id)), peerCert)
		writePrivate(filepath.Join(bundle, "pki", fmt.Sprintf("node-%d.key", id)), peerKey)
		writePrivate(filepath.Join(bundle, "pki", fmt.Sprintf("public-%d.pem", id)), pubCert)
		writePrivate(filepath.Join(bundle, "pki", fmt.Sprintf("public-%d.key", id)), pubKey)
		writePrivate(filepath.Join(bundle, "pki", "ca.pem"), ca.pem())
		writePrivate(filepath.Join(bundle, "cluster.seed"), seedRaw)
		peer := net.JoinHostPort(ips[id], strconv.Itoa(*peerPort))
		installNodes = append(installNodes, config.Node{ID: id, Identity: names[id], FailureDomain: doms[id], PeerAddress: config.Endpoint("https://" + peer), PeerListen: "0.0.0.0:" + strconv.Itoa(*peerPort),
			Disk:        config.Disk{ID: fmt.Sprintf("disk-%d", id), Volume: fmt.Sprintf("volume-%d", id), Path: fmt.Sprintf("%s/data-%d", *nodeRoot, id), CapacityBytes: 100 << 30},
			Certificate: fmt.Sprintf("%s/pki/node-%d.pem", *nodeRoot, id), PrivateKey: config.NewSecretRef(fmt.Sprintf("file:%s/pki/node-%d.key", *nodeRoot, id))})
	}
	icfg := config.InstallConfig{
		Mode: config.ModeDistributed, ReplicationFactor: 3,
		Cluster:   config.Cluster{Placement: config.PlacementPhysical, CA: *nodeRoot + "/pki/ca.pem", Seed: config.NewSecretRef("file:" + *nodeRoot + "/cluster.seed"), InitialLeader: 1, Revision: 1},
		Nodes:     installNodes,
		Listen:    config.Listen{Address: "0.0.0.0:" + strconv.Itoa(*publicPort), PublicOrigins: []string{"https://soundpost.example.invalid"}},
		Sources:   []config.SourcePolicy{{ID: "backend", Class: "private"}},
		Quotas:    config.Quotas{MaxBytesPerSource: 1 << 30, MaxSeriesPerSource: 1000},
		Retention: config.Retention{Days: map[string]uint32{"metric": 30, "log": 14}},
		Backup:    config.Backup{Mode: config.BackupNone},
	}
	must(config.Validate(icfg), "install configuration")
	files, err := config.NodeConfigs(icfg)
	must(err, "render node files")
	for id, content := range files {
		writePrivate(filepath.Join(*out, fmt.Sprintf("node-%d", id), "node.json"), content)
	}

	// 3. the plan.
	var tok [16]byte
	rand.Read(tok[:])
	token := fmt.Sprintf("%x", tok)
	for id := uint64(1); id <= 3; id++ {
		plan.Nodes = append(plan.Nodes, PlanNode{ID: id, Addr: net.JoinHostPort(ips[id], strconv.Itoa(*publicPort)), Control: net.JoinHostPort(ips[id], strconv.Itoa(*controlPort)), ControlToken: token})
	}
	rawPlan, _ := json.Marshal(plan)
	writePrivate(filepath.Join(*out, "plan.json"), rawPlan)
	writePrivate(filepath.Join(*out, "ca.pem"), ca.pem())
	fmt.Fprintf(os.Stderr, "distributed: prepared %d projects in %d orgs, cluster files in %s\n", cfg.Projects, cfg.Orgs, *out)
}

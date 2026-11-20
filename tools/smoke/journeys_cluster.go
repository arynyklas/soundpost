// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/model"
)

// `journeys --cluster-attach FILE` runs the reference journeys against a cluster that somebody else provisioned, bootstrapped
// and put through a node loss (07.07#16, `tools/drills --scenario node-loss-journeys`): three real members of the produced
// binary on loopback, every one serving the same TLS leaf the applications and the browser trust. The journeys then do what
// they do against one node, with these differences and no others:
//
//   - nothing is started or bootstrapped here: the installation's owner logs in and provisions the journeys' organizations;
//   - every application ingests through the member its role names (some of them members that were killed and restored);
//   - the in-process storage scan of the collect step needs a member's data directory to itself, so the cluster's owner stops
//     the `scan` member over the control channel (stdin/stdout JSON lines), the scan runs in this process as that member
//     (appcore.OpenDistributed on its directory and node file, joining the two members that keep running), and the owner starts
//     the member again; every read of the journeys then goes through that restored member;
//   - control writes and reads retry the answers a recovering cluster documents as retryable (a lost index race, a conflict,
//     a typed 503); every other answer is the row's evidence as it is.
//
// The rows, their assertions and the pass/fail verdict are the single-node ones (journeys_assert.go), evaluated from what the
// cluster served.

// journeyAttach is the attach document: strict JSON, every field named.
type journeyAttach struct {
	Version   int                `json:"version"`
	Control   string             `json:"control"`
	TLS       journeyAttachTLS   `json:"tls"`
	Owner     journeyAttachOwner `json:"owner"`
	Members   []attachMember     `json:"members"`
	Recovered []uint64           `json:"recovered"`
	Roles     map[string]uint64  `json:"roles"`
}

// journeyAttachTLS is the PKI of the members' public listeners: the CA that signed the leaf, the leaf and its key (each member
// serves this one leaf, as the single node does, so the browser can trust it by one public-key pin).
type journeyAttachTLS struct {
	CA   string `json:"ca"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// journeyAttachOwner is an administrator of the installation that already exists (its bootstrap was done by the cluster's owner).
type journeyAttachOwner struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type attachMember struct {
	ID         uint64 `json:"id"`
	Address    string `json:"address"`     // public HTTPS listener, loopback host:port
	DataDir    string `json:"data_dir"`    // private data directory of the member
	NodeConfig string `json:"node_config"` // the member's node file (what `serve --cluster-config` reads)
}

// attachRoleNames is the closed set of roles: where each journey leg goes.
//   - admin: provisioning (owner login, admin commands, source onboarding) and the logins before the scan; it stays up while the
//     scan member is stopped.
//   - gateway, api, jobs: the ingest endpoint of that application's SDK.
//   - web: the ingest endpoint in the page's own configuration; the page's connect-src names the gateway's ingest origin, so it
//     must be the gateway's member.
//   - webbuild: the artifact upload of the web build.
//   - scan: the member stopped for the in-process scan and restored; every read of the journeys goes through it.
var attachRoleNames = []string{"admin", "gateway", "api", "jobs", "web", "webbuild", "scan"}

func parseJourneyAttach(raw []byte) (*journeyAttach, error) {
	var a journeyAttach
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("attach document does not decode: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return nil, errors.New("attach document has data after the document")
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	return &a, nil
}

func (a *journeyAttach) validate() error {
	if a.Version != 1 {
		return fmt.Errorf("attach document version %d is not supported", a.Version)
	}
	if a.Control != "stdio" {
		return fmt.Errorf("attach control %q is not supported (stdio)", a.Control)
	}
	for name, p := range map[string]string{"tls.ca": a.TLS.CA, "tls.cert": a.TLS.Cert, "tls.key": a.TLS.Key} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("attach %s must be an absolute path", name)
		}
	}
	if a.Owner.Email == "" || a.Owner.Password == "" {
		return errors.New("attach owner needs an email and a password")
	}
	if len(a.Members) < 3 {
		return fmt.Errorf("attach names %d members, a cluster has at least 3", len(a.Members))
	}
	for i, m := range a.Members {
		if m.ID == 0 {
			return fmt.Errorf("attach member %d has no id", i)
		}
		if a.indexOf(m.ID) != i {
			return fmt.Errorf("attach member id %d is listed twice", m.ID)
		}
		host, port, err := net.SplitHostPort(m.Address)
		if err != nil {
			return fmt.Errorf("attach member %d: address is not host:port", m.ID)
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("attach member %d: address is not a loopback literal", m.ID)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("attach member %d: address has no usable port", m.ID)
		}
		if !filepath.IsAbs(m.DataDir) || !filepath.IsAbs(m.NodeConfig) {
			return fmt.Errorf("attach member %d: data_dir and node_config must be absolute paths", m.ID)
		}
	}
	if len(a.Recovered) == 0 {
		return errors.New("attach names no member that was killed and restored: the journeys are for a recovered cluster")
	}
	for _, id := range a.Recovered {
		if _, ok := a.memberByID(id); !ok {
			return fmt.Errorf("attach recovered member %d is not a member", id)
		}
	}
	if len(a.Roles) != len(attachRoleNames) {
		return fmt.Errorf("attach roles must be exactly %v", attachRoleNames)
	}
	for _, role := range attachRoleNames {
		id, ok := a.Roles[role]
		if !ok {
			return fmt.Errorf("attach role %s is missing", role)
		}
		if _, ok = a.memberByID(id); !ok {
			return fmt.Errorf("attach role %s names member %d, which is not a member", role, id)
		}
	}
	if !slices.Contains(a.Recovered, a.Roles["scan"]) {
		return fmt.Errorf("attach scan member %d was not killed and restored: the reads must go through a restored member", a.Roles["scan"])
	}
	if a.Roles["admin"] == a.Roles["scan"] {
		return errors.New("attach admin member must stay up while the scan member is stopped")
	}
	if a.Roles["web"] != a.Roles["gateway"] {
		return errors.New("attach web member must be the gateway member (the page's connect-src names the gateway's ingest origin)")
	}
	return nil
}

func (a *journeyAttach) indexOf(id uint64) int {
	for i, m := range a.Members {
		if m.ID == id {
			return i
		}
	}
	return -1
}

func (a *journeyAttach) memberByID(id uint64) (attachMember, bool) {
	if i := a.indexOf(id); i >= 0 {
		return a.Members[i], true
	}
	return attachMember{}, false
}

// roleAddress is the public address of the member a role names ("" for an unknown role).
func (a *journeyAttach) roleAddress(role string) string {
	id, ok := a.Roles[role]
	if !ok {
		return ""
	}
	m, _ := a.memberByID(id)
	return m.Address
}

// memberReady asks one member's /readyz: it is ready only on a 200 whose body says ready.
func memberReady(client *http.Client, address string) (bool, string) {
	resp, err := client.Get("https://" + address + "/readyz")
	if err != nil {
		return false, "no answer"
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var st struct {
		Ready  bool   `json:"ready"`
		Reason string `json:"reason"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(raw, &st) != nil || !st.Ready {
		reason := st.Reason
		if reason == "" {
			reason = "status " + strconv.Itoa(resp.StatusCode)
		}
		return false, "not ready (" + reason + ")"
	}
	return true, ""
}

// awaitMembersReady waits (at most limit per member) until every member of the document answers /readyz ready. A leg pointed
// at a member that is not serving fails here, before anything is provisioned.
func (a *journeyAttach) awaitMembersReady(client *http.Client, limit time.Duration) error {
	for _, m := range a.Members {
		deadline := time.Now().Add(limit)
		for {
			ready, why := memberReady(client, m.Address)
			if ready {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("member %d is not ready: %s", m.ID, why)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return nil
}

// retryableClusterAnswer is the answer a cluster documents as "nothing was committed, send the same request again": a control
// write that lost its index race or a revision conflict (HTTP 400/409 naming stale or conflict), or the typed retryable
// fault of a member that has no quorum yet (HTTP 503).
func retryableClusterAnswer(status int, body []byte) bool {
	switch status {
	case 400, 409:
		return bytes.Contains(body, []byte(`"stale"`)) || bytes.Contains(body, []byte(`"conflict"`))
	case 503:
		var f struct {
			Code      string `json:"code"`
			Retryable bool   `json:"retryable"`
		}
		if json.Unmarshal(body, &f) != nil || !f.Retryable {
			return false
		}
		return f.Code == "unavailable" || f.Code == "timeout" || f.Code == "stale"
	}
	return false
}

// ---- the control channel to the cluster's owner ----

// journeyControl is the journeys' side of the control channel: one JSON request per line on out, one JSON answer per line on
// in, strictly one request at a time. The owner (the drill that holds the member processes) is the only party that can stop
// and start a member; the journeys only ask.
type journeyControl struct {
	mu  sync.Mutex
	in  *bufio.Reader
	out io.Writer
}

type controlRequest struct {
	Op     string `json:"op"`
	Member uint64 `json:"member,omitempty"`
	Name   string `json:"name,omitempty"`
}

type controlAnswer struct {
	OK   bool   `json:"ok"`
	Code string `json:"code,omitempty"`
}

func newJourneyControl(r io.Reader, w io.Writer) *journeyControl {
	return &journeyControl{in: bufio.NewReader(r), out: w}
}

func (c *journeyControl) do(r controlRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err = c.out.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("control channel is closed: %w", err)
	}
	text, err := c.in.ReadString('\n')
	if err != nil && strings.TrimSpace(text) == "" {
		return fmt.Errorf("control channel closed before the owner answered %s", r.Op)
	}
	var a controlAnswer
	if json.Unmarshal([]byte(text), &a) != nil {
		return fmt.Errorf("the owner's answer to %s is not JSON", r.Op)
	}
	if !a.OK {
		return fmt.Errorf("the owner refused %s: %s", r.Op, sanitizeErr(errors.New(a.Code)))
	}
	return nil
}

func (c *journeyControl) stopMember(id uint64) error {
	return c.do(controlRequest{Op: "stop_member", Member: id})
}

func (c *journeyControl) startMember(id uint64) error {
	return c.do(controlRequest{Op: "start_member", Member: id})
}

func (c *journeyControl) phase(name string) error {
	return c.do(controlRequest{Op: "phase", Name: name})
}

// ---- the TLS the members serve ----

// loadJourneyPKI loads the PKI the members serve (instead of making one): the CA must be a CA, the leaf must be signed by it,
// valid now, name 127.0.0.1, and the key must belong to it.
func loadJourneyPKI(caPath, certPath, keyPath string) (*journeyPKI, error) {
	parse := func(path string) (*x509.Certificate, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("not a PEM certificate")
		}
		return x509.ParseCertificate(block.Bytes)
	}
	ca, err := parse(caPath)
	if err != nil {
		return nil, fmt.Errorf("cluster CA: %w", err)
	}
	if !ca.IsCA {
		return nil, errors.New("cluster CA certificate is not a CA")
	}
	leaf, err := parse(certPath)
	if err != nil {
		return nil, fmt.Errorf("cluster leaf: %w", err)
	}
	if err = leaf.CheckSignatureFrom(ca); err != nil {
		return nil, errors.New("cluster leaf is not signed by the cluster CA")
	}
	if now := time.Now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, errors.New("cluster leaf is not valid now")
	}
	if !slices.ContainsFunc(leaf.IPAddresses, func(ip net.IP) bool { return ip.Equal(net.ParseIP("127.0.0.1")) }) {
		return nil, errors.New("cluster leaf does not name 127.0.0.1")
	}
	if _, err = tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return nil, errors.New("cluster key does not belong to the cluster leaf")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &journeyPKI{CA: caPath, Cert: certPath, Key: keyPath, pool: pool, caCert: ca}, nil
}

// ---- a scan of directories that members may still be writing ----

// scanLiveTreeForCanaries is scanTreeForCanaries for a tree a running member can still change: a file that vanishes between
// the listing and the read (a rotated or renamed temporary file) is skipped and counted, any other error fails the scan.
func scanLiveTreeForCanaries(ctx context.Context, dir string, canaries []string, read func(string) ([]byte, error)) ([]leakHit, int, int, error) {
	var hits []leakHit
	files, skipped := 0, 0
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				skipped++
				return nil
			}
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		raw, rerr := read(p)
		if errors.Is(rerr, fs.ErrNotExist) {
			skipped++
			return nil
		}
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
	return hits, files, skipped, err
}

// ---- the journeys' steps in attach mode ----

// post is installSite.post, and against a cluster it repeats a request the cluster answered with a documented retryable answer.
func (j *journeyRun) post(s *installSite, path string, body any, csrf, bearer string) (int, []byte, error) {
	if j.attach == nil {
		return s.post(path, body, csrf, bearer)
	}
	for attempt := 0; ; attempt++ {
		status, raw, err := s.post(path, body, csrf, bearer)
		if err != nil || !retryableClusterAnswer(status, raw) || attempt >= 40 {
			return status, raw, err
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// nodeBase is the origin the run's logins and reads go to: the node, or the member the run currently reads through.
func (j *journeyRun) nodeBase() string {
	if j.attach != nil {
		m, _ := j.attach.memberByID(j.cur)
		return "https://" + m.Address
	}
	return "https://" + j.nodeAddr
}

// ingestAddress is the host:port an application's SDK (or the web build's upload) sends to.
func (j *journeyRun) ingestAddress(app string) string {
	if j.attach != nil {
		return j.attach.roleAddress(app)
	}
	if j.svc != nil {
		return j.svc.ingestAddress(app)
	}
	return j.nodeAddr
}

// phase tells the cluster's owner which part of the run starts or ends; a single node has no owner to tell.
func (j *journeyRun) phase(name string) error {
	if j.ctl == nil {
		return nil
	}
	return j.ctl.phase(name)
}

func (j *journeyRun) setupPKI() (err error) {
	if j.attach != nil {
		j.pki, err = loadJourneyPKI(j.attach.TLS.CA, j.attach.TLS.Cert, j.attach.TLS.Key)
		return err
	}
	j.pki, err = newJourneyPKI(filepath.Join(j.work, "pki"))
	return err
}

// attachCluster replaces the start of the node: it checks that every member the document names is serving and settles on the
// administration member.
func (j *journeyRun) attachCluster() error {
	if err := j.attach.awaitMembersReady(j.pki.client(), 120*time.Second); err != nil {
		return err
	}
	j.ctl = newJourneyControl(os.Stdin, os.Stdout)
	j.cur = j.attach.Roles["admin"]
	j.site = &installSite{base: j.nodeBase(), client: j.pki.client()}
	j.site.client.Jar, _ = cookiejar.New(nil)
	members := make([]uint64, 0, len(j.attach.Members))
	for _, m := range j.attach.Members {
		members = append(members, m.ID)
	}
	j.rep["cluster"] = map[string]any{"members": members, "recovered": j.attach.Recovered, "roles": j.attach.Roles}
	return nil
}

// establishOwner is the first thing provision does: a single node is bootstrapped; an attached cluster already has its owner,
// who logs in.
func (j *journeyRun) establishOwner() error {
	if j.attach != nil {
		status, raw, err := j.post(j.site, "/api/v1/login", map[string]string{"Email": j.attach.Owner.Email, "Password": j.attach.Owner.Password, "Code": ""}, "", "")
		if err = requireSmokeResponse("owner_login", status, 200, raw, err); err != nil {
			return err
		}
		return json.Unmarshal(raw, &j.owner)
	}
	token, err := os.ReadFile(filepath.Join(j.nodeDir, "bootstrap.token"))
	if err != nil {
		return err
	}
	status, raw, err := j.site.post("/api/v1/bootstrap", map[string]string{"Token": string(token), "Email": "owner@journeys.invalid", "Password": "journeys owner password 2026"}, "", "")
	if err = requireSmokeResponse("bootstrap", status, 200, raw, err); err != nil {
		return err
	}
	return json.Unmarshal(raw, &j.owner)
}

// quiesceNode is what the collect step needs before it can open storage in this process: the single node is stopped, or the
// cluster's owner stops the scan member (the other two keep the quorum).
func (j *journeyRun) quiesceNode() error {
	if j.attach == nil {
		return j.stopNode()
	}
	return j.ctl.stopMember(j.attach.Roles["scan"])
}

// openStorage opens the storage the scan reads: the node's directory, or, for a cluster, the stopped scan member's directory as
// that member (its node file), which joins the running members and answers once every group has its quorum.
func (j *journeyRun) openStorage() (*appcore.App, error) {
	if j.attach == nil {
		return appcore.Open(j.nodeDir)
	}
	m, _ := j.attach.memberByID(j.attach.Roles["scan"])
	raw, err := os.ReadFile(m.NodeConfig)
	if err != nil {
		return nil, err
	}
	var config appcore.NodeConfig
	if model.StrictJSON(raw, &config) != nil || config.NodeID != m.ID {
		return nil, fmt.Errorf("node file of member %d does not decode or names another node", m.ID)
	}
	return appcore.OpenDistributed(m.DataDir, config)
}

// restartNode brings the node back for the reads: the single node is launched again on its data; for a cluster the owner starts
// the scan member again and every following login and read goes through it.
func (j *journeyRun) restartNode() error {
	if j.attach == nil {
		return j.launchNode()
	}
	scan := j.attach.Roles["scan"]
	if err := j.ctl.startMember(scan); err != nil {
		return err
	}
	j.cur = scan
	j.rep["cluster"].(map[string]any)["reads_through_member"] = scan
	return nil
}

// finishReads ends the reads: the single node is stopped; the cluster belongs to its owner and stays up.
func (j *journeyRun) finishReads() error {
	if j.attach == nil {
		return j.stopNode()
	}
	return nil
}

// scanNodeData is the canary scan of the node's stored bytes: the node's data directory, or every member's.
func (j *journeyRun) scanNodeData(ctx context.Context, canaries []string) ([]leakHit, int, error) {
	if j.attach == nil {
		return scanTreeForCanaries(ctx, j.nodeDir, canaries)
	}
	var hits []leakHit
	total, skipped := 0, 0
	for _, m := range j.attach.Members {
		h, files, skip, err := scanLiveTreeForCanaries(ctx, m.DataDir, canaries, os.ReadFile)
		if err != nil {
			return nil, 0, err
		}
		for i := range h {
			h[i].Where = fmt.Sprintf("member %d %s", m.ID, h[i].Where)
		}
		hits, total, skipped = append(hits, h...), total+files, skipped+skip
	}
	j.rep["cluster"].(map[string]any)["scan_skipped_vanished_files"] = skipped
	return hits, total, nil
}

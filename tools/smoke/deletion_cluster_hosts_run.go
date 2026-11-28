// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/config"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

// dcLoadBase is the sequence number the ACK-journal load counts up from; every sample the sibling had before the load is at or below it.
const dcLoadBase = 1000

// dcHostsOptions is everything the cross-host run is told: nothing about a machine is built in.
type dcHostsOptions struct {
	hosts                map[uint64]dcHostSpec
	cut, via, backupNode uint64
	beginAt              time.Time
	cutLead              time.Duration
	minOutage, waitCut   time.Duration
	cutFile              string
	spot                 *dcAuthority
	loadWorkers          int
	loadInterval         time.Duration
	rehearsal            bool // the operator's cut is replaced by a service stop of the cut voter: the tooling is proven, the evidence is labelled as no power cut
	cleanup              bool // wipe the hosts after a passed run
}

// dcHostsFlags registers the cross-host flags on the deletion-cluster flag set and returns a function
// that turns them into options once the set is parsed (nil options: the run is the single-host one).
func dcHostsFlags(f *flag.FlagSet) func(artifactDir string) (*dcHostsOptions, error) {
	hosts := f.String("hosts", "", "cross-host mode: id=ssh=address,... for voters 1, 2, 3, each on its own machine (the voters run as enabled systemd units; the smoke is driven from a fourth place over ssh)")
	cut := f.Uint64("cut-node", 1, "cross-host mode: the voter whose machine the operator powers off during the deletion")
	via := f.Uint64("via-node", 2, "cross-host mode: the voter the deletion is begun through (never the cut one)")
	backupNode := f.Uint64("backup-node", 3, "cross-host mode: the voter the older backup is taken through (stopped for it, never the cut one)")
	beginAt := f.String("begin-at", "", "cross-host mode: RFC 3339 instant at which the deletion begins; the cut is asked for --cut-lead after it")
	cutLead := f.Duration("cut-lead", 25*time.Second, "cross-host mode: how long after the deletion begins the operator is asked to cut")
	minOutage := f.Duration("min-outage", 90*time.Second, "cross-host mode: shortest outage of the cut voter that counts as a power cut")
	waitCut := f.Duration("wait-cut", 25*time.Minute, "cross-host mode: how long to wait for the cut and the voter's return")
	cutFile := f.String("cut-file", "", "cross-host mode: file the cut schedule is written to (default: in --artifact-dir)")
	s3Endpoint := f.String("authority-s3-endpoint", "", "cross-host mode: the authority journal is this S3-compatible HTTPS endpoint (credentials: SOUNDPOST_AUTHORITY_S3_ACCESS_KEY/SECRET_KEY; CA bundle: SSL_CERT_FILE)")
	s3Region := f.String("authority-s3-region", "us-east-1", "cross-host mode: S3 region")
	s3Bucket := f.String("authority-s3-bucket", "", "cross-host mode: S3 bucket of the authority journal")
	s3Prefix := f.String("authority-s3-prefix", "", "cross-host mode: S3 key prefix of the authority journal")
	authDir := f.String("authority-dir", "", "cross-host mode: instead of S3, a directory of the authority journal that every voter and this process reach (a mount of another host)")
	workers := f.Int("load-workers", 2, "cross-host mode: concurrent writers of the ACK-journal load")
	interval := f.Duration("load-interval", 500*time.Millisecond, "cross-host mode: pause of a writer between two batches")
	rehearsal := f.Bool("rehearsal", false, "cross-host mode: the cut is a stop of the voter's service (done by the one who runs the rehearsal), not a power cut: the boot id check is not made and the artifact says so")
	cleanup := f.Bool("cleanup", false, "cross-host mode: after a run that PASSED, wipe every host (stop, disable and remove the unit, binaries, keys, credentials, node data, backups); a failed run always keeps its state on the hosts")
	return func(artifactDir string) (*dcHostsOptions, error) {
		if *hosts == "" {
			return nil, nil
		}
		parsed, err := dcParseHosts(*hosts)
		if err != nil {
			return nil, err
		}
		o := &dcHostsOptions{hosts: parsed, cut: *cut, via: *via, backupNode: *backupNode, cutLead: *cutLead, minOutage: *minOutage, waitCut: *waitCut, cutFile: *cutFile, loadWorkers: *workers, loadInterval: *interval, rehearsal: *rehearsal, cleanup: *cleanup}
		if err = dcCheckRoles(o.cut, o.via, o.backupNode); err != nil {
			return nil, err
		}
		if o.beginAt, err = time.Parse(time.RFC3339, *beginAt); err != nil {
			return nil, errors.New("--begin-at wants an RFC 3339 instant")
		}
		if o.cutLead < 0 || o.minOutage <= 0 || o.waitCut <= 0 || o.loadWorkers < 1 || o.loadInterval <= 0 {
			return nil, errors.New("--cut-lead, --min-outage, --wait-cut, --load-workers and --load-interval must be positive")
		}
		if o.cutFile == "" {
			o.cutFile = filepath.Join(artifactDir, "cut-schedule.json")
		}
		switch {
		case *s3Endpoint != "" && *authDir != "":
			return nil, errors.New("--authority-s3-endpoint and --authority-dir are exclusive")
		case *s3Endpoint != "":
			u, err := url.Parse(*s3Endpoint)
			if err != nil || u.Scheme != "https" || u.Host == "" || *s3Bucket == "" {
				return nil, errors.New("--authority-s3-endpoint wants an https URL and --authority-s3-bucket")
			}
			o.spot = &dcAuthority{S3: &dcS3{Endpoint: *s3Endpoint, Region: *s3Region, Bucket: *s3Bucket, Prefix: *s3Prefix}}
		case *authDir != "":
			o.spot = &dcAuthority{Dir: *authDir}
		default:
			return nil, errors.New("cross-host mode needs the authority journal off the voters' own disks: --authority-s3-endpoint (+ bucket) or --authority-dir")
		}
		return o, nil
	}
}

// dcCheckRoles: the three roles are voters of the cluster, and the deletion is never begun through,
// nor the older backup taken through, the voter that is going to be powered off.
func dcCheckRoles(cut, via, backupNode uint64) error {
	for _, id := range []uint64{cut, via, backupNode} {
		if id < 1 || id > 3 {
			return errors.New("--cut-node, --via-node and --backup-node are voters 1, 2 or 3")
		}
	}
	if via == cut || backupNode == cut {
		return errors.New("the deletion is not begun through, and the backup not taken through, the voter that is cut")
	}
	return nil
}

// dcCutSchedule is what the operator is told: which machine to power off and when.
type dcCutSchedule struct {
	Node    uint64 `json:"cut_node"`
	Host    string `json:"cut_host"`
	BeginAt string `json:"deletion_begins_at"`
	CutAt   string `json:"cut_at"`
	DownFor string `json:"keep_down_for_at_least"`
}

func dcSchedule(o *dcHostsOptions) dcCutSchedule {
	return dcCutSchedule{Node: o.cut, Host: o.hosts[o.cut].SSH, BeginAt: o.beginAt.UTC().Format(time.RFC3339), CutAt: o.beginAt.Add(o.cutLead).UTC().Format(time.RFC3339), DownFor: o.minOutage.String()}
}

// newHostsCluster lays out a cluster whose voters are on other machines: the PKI, the typed installation
// and the node files are made here (their paths are the voters' own), the bootstrap installation and
// the cluster seed too; provisioning pushes them.
func newHostsCluster(binary, release, work string, hosts map[uint64]dcHostSpec, report map[string]any) (*processCluster, error) {
	boot, err := newBinaryHost(binary, release, report)
	if err != nil {
		return nil, err
	}
	abs, _ := filepath.Abs(binary)
	c := &processCluster{binary: abs, root: work, boot: boot, public: map[uint64]string{}, peer: map[uint64]string{}, data: map[uint64]string{}, cmds: map[uint64]*exec.Cmd{}, done: map[uint64]chan error{}, logs: map[uint64]*syncBuffer{}, certs: map[uint64]*x509.Certificate{}, sites: map[uint64]*installSite{}}
	pki := filepath.Join(work, "pki")
	if err = os.MkdirAll(pki, 0o700); err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, n := range distNodes {
		ips = append(ips, net.ParseIP(hosts[n.id].Addr))
	}
	ca, certs, keys, material, signer, err := distPKI(pki, map[uint64][]string{1: nil, 2: nil, 3: nil}, ips)
	if err != nil {
		return nil, err
	}
	c.keys = material
	c.pki = &processPKI{dir: pki, caFile: ca, ca: signer, certs: certs, keys: keys}
	c.seed = filepath.Join(work, "cluster.seed")
	var nodes []config.Node
	for _, n := range distNodes {
		h := hosts[n.id]
		c.public[n.id], c.peer[n.id] = net.JoinHostPort(h.Addr, dcPublicPort), net.JoinHostPort(h.Addr, dcPeerPort)
		c.data[n.id] = dcRemoteVar + "/node-" + strconv.FormatUint(n.id, 10)
		c.logs[n.id] = &syncBuffer{}
		nodes = append(nodes, config.Node{ID: n.id, Identity: n.identity, FailureDomain: "host-" + n.name, PeerAddress: config.Endpoint("https://" + c.peer[n.id]), PeerListen: c.peer[n.id],
			Disk: config.Disk{ID: "disk-" + n.name, Volume: "vol-" + n.name, Path: c.data[n.id], CapacityBytes: 1 << 30}, Certificate: dcRemoteEtc + "/pki/" + n.name + ".pem", PrivateKey: config.NewSecretRef("file:" + dcRemoteEtc + "/pki/" + n.name + ".key")})
	}
	c.cfg = installConfigFor(nodes, dcRemoteEtc+"/pki/ca.pem", "file:"+dcRemoteEtc+"/cluster.seed", "0.0.0.0:"+dcPublicPort)
	return c, nil
}

// dcHostsNotRun is what the cross-host run does not cover, stated in its artifact.
func dcHostsNotRun(o *dcHostsOptions) []string {
	out := []string{
		"independent hardware, power feed or hypervisor behind the three machines (the placement is attested `simulated`: virtual machines of one cluster are not evidence of independent failure domains)",
		"loss of two voters, loss of the authority store during the deletion, a whole-site power loss",
	}
	if o.spot != nil && o.spot.S3 == nil {
		out = append(out, "an authority on separate hardware (a directory every voter reaches, named by the operator)")
	}
	return append(out, "an operator cut of any voter other than the one named in --cut-node (run it again with another --cut-node)")
}

// ---- probing and the deletion timeline while the operator cuts the power ----

// dcMonitor probes every voter's readiness twice a second from this process (a machine that is never
// cut) and samples the deletion's state through the live voters.
type dcMonitor struct {
	mu       sync.Mutex
	started  time.Time
	times    map[uint64][]int64
	ready    map[uint64][]bool
	timeline []dcPoint
	stop     chan struct{}
	wg       sync.WaitGroup
}

func (m *dcMonitor) since() int64 { return time.Since(m.started).Milliseconds() }

// startMonitor starts the probes (own clients with a short timeout, so a powered-off machine costs two
// seconds, not twenty) and the timeline poll through the live voters.
func (r *dcRun) startMonitor(poll []uint64, t0 time.Time) *dcMonitor {
	m := &dcMonitor{started: t0, times: map[uint64][]int64{}, ready: map[uint64][]bool{}, stop: make(chan struct{})}
	for _, id := range dcNodes {
		site := r.sites[id]
		client := *site.client
		client.Timeout = 2 * time.Second
		probe := &installSite{base: site.base, client: &client}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			for {
				code, raw, err := probe.get("/readyz")
				ok := false
				if err == nil && code == 200 {
					var st installReadiness
					ok = json.Unmarshal(raw, &st) == nil && st.Ready
				}
				m.mu.Lock()
				m.times[id] = append(m.times[id], m.since())
				m.ready[id] = append(m.ready[id], ok)
				m.mu.Unlock()
				select {
				case <-m.stop:
					return
				case <-time.After(500 * time.Millisecond):
				}
			}
		}()
	}
	for _, id := range poll {
		id := id
		owner := r.ownerSite[id]
		client := *owner.client
		client.Timeout = 5 * time.Second
		site := &installSite{base: owner.base, client: &client}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			for {
				var op struct {
					Phase, Physical string
					Residual        []string
				}
				status, raw, err := site.get("/api/v1/operations/" + r.op.String() + "?org=" + r.fx.org.String())
				if err == nil && status == 200 {
					var got struct {
						Phase    string   `json:"phase"`
						Physical string   `json:"physical"`
						Residual []string `json:"residual_stores"`
					}
					if json.Unmarshal(raw, &got) == nil {
						op.Phase, op.Physical, op.Residual = got.Phase, got.Physical, got.Residual
						m.mu.Lock()
						m.timeline = append(m.timeline, dcPoint{AtMS: m.since(), Phase: op.Phase, Physical: op.Physical, Residual: op.Residual})
						m.mu.Unlock()
					}
				}
				select {
				case <-m.stop:
					return
				case <-time.After(2 * time.Second):
				}
			}
		}()
	}
	return m
}

func (m *dcMonitor) finish() {
	close(m.stop)
	m.wg.Wait()
}

// outageOf is the longest finished outage of a voter in the probe log.
func (m *dcMonitor) outageOf(id uint64) (dcOutage, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return dcLongest(dcOutages(m.times[id], m.ready[id], 3))
}

func (m *dcMonitor) points() []dcPoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	pts := slices.Clone(m.timeline)
	sort.Slice(pts, func(i, j int) bool { return pts[i].AtMS < pts[j].AtMS })
	return pts
}

// ---- the ACK-journal load ----

type dcAckLoad struct {
	r       *dcRun
	journal *dcAckJournal
	jmu     sync.Mutex
	sites   []*installSite
	nodes   []uint64
	seq     atomic.Uint64
	stop    atomic.Bool
	wg      sync.WaitGroup
	issued  atomic.Int64
	acked   atomic.Int64
	refused atomic.Int64
	resent  atomic.Int64
	failure atomic.Value // error of the journal or a refusal
	perNode sync.Map     // uint64 -> *atomic.Int64
	drained atomic.Bool
}

// startLoad starts the writers: each batch is one sample of the sibling project whose value is its
// sequence number; its `issue` line is synced before the first send and its `ack` line before the
// writer counts it or sends the next one; an unacknowledged batch is resent with the identical body to
// the voters in turn (the original dedup identity makes the answer the original receipt).
func (r *dcRun) startLoad(file string, workers int, interval time.Duration) (*dcAckLoad, error) {
	j, err := dcCreateAckJournal(file)
	if err != nil {
		return nil, err
	}
	l := &dcAckLoad{r: r, journal: j, nodes: slices.Clone(dcNodes)}
	l.seq.Store(dcLoadBase) // the load's sequence numbers start above every sample the sibling had before it
	for _, id := range dcNodes {
		client := *r.sites[id].client
		client.Timeout = 6 * time.Second
		l.sites = append(l.sites, &installSite{base: r.sites[id].base, client: &client})
		l.perNode.Store(id, new(atomic.Int64))
	}
	for w := 0; w < workers; w++ {
		l.wg.Add(1)
		go func(w int) {
			defer l.wg.Done()
			for !l.stop.Load() {
				if err := l.one(w); err != nil {
					l.failure.CompareAndSwap(nil, err)
					return
				}
				time.Sleep(interval)
			}
		}(w)
	}
	return l, nil
}

func (l *dcAckLoad) record(kind string, seq uint64, at int64, node uint64) error {
	l.jmu.Lock()
	defer l.jmu.Unlock()
	return l.journal.add(kind, seq, at, node)
}

// one issues, sends and acknowledges one batch.
func (l *dcAckLoad) one(w int) error {
	seq := l.seq.Add(1)
	at := time.Now()
	batch, err := dcSiblingBatch(l.r.fx, l.r.sib, float64(seq), at)
	if err != nil {
		return err
	}
	if err = l.record("issue", seq, at.UnixNano(), 0); err != nil {
		return err
	}
	l.issued.Add(1)
	for attempt := 0; ; attempt++ {
		i := (int(seq) + attempt) % len(l.sites)
		status, _, err := l.sites[i].ingest(batch, l.r.sib.credential)
		switch {
		case err == nil && status == http.StatusOK:
			if err = l.record("ack", seq, at.UnixNano(), l.nodes[i]); err != nil {
				return err
			}
			l.acked.Add(1)
			if n, ok := l.perNode.Load(l.nodes[i]); ok {
				n.(*atomic.Int64).Add(1)
			}
			return nil
		case err == nil && status != http.StatusServiceUnavailable:
			l.refused.Add(1)
			return l.record("reject", seq, at.UnixNano(), l.nodes[i])
		}
		l.resent.Add(1)
		time.Sleep(300 * time.Millisecond)
	}
}

// drain stops the writers: no new batch is issued, every in-flight one is resent until acknowledged.
func (l *dcAckLoad) drain() error {
	l.stop.Store(true)
	l.wg.Wait()
	if e, ok := l.failure.Load().(error); ok && e != nil {
		return e
	}
	return l.journal.close()
}

// ---- the retained samples of a voter ----

// readRetained reads every sample of the sibling metric through one voter (one range-selector query,
// a complete answer or an error).
func (r *dcRun) readRetained(id uint64) ([]dcRetained, error) {
	fx := r.siblingFixture(id)
	fx.queryTime = fmt.Sprint(time.Now().Add(time.Minute).UnixNano())
	slow := *r.sites[id] // a whole-range read of a voter that just rebooted can take longer than the 20 s of the other calls
	client := *slow.client
	client.Timeout = 2 * time.Minute
	slow.client = &client
	status, raw, err := queryExpr(&slow, fx, r.sib.marker+"[3h]")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, dcRetainedStatusFailure(r.stage, status, raw)
	}
	var result query.Result
	if err = json.Unmarshal(raw, &result); err != nil || len(result.Projects) != 1 {
		return nil, &smokeFailure{Smoke: dcSmoke, Stage: r.stage, Code: "retained_read_not_one_project"}
	}
	p := result.Projects[0]
	if p.Failure != nil || p.Completeness != query.CompletenessComplete || p.Value == nil {
		return nil, &smokeFailure{Smoke: dcSmoke, Stage: r.stage, Code: "retained_read_not_complete"}
	}
	var out []dcRetained
	for _, s := range p.Value.Matrix {
		for _, sample := range s.Samples {
			if sample.Float == nil {
				return nil, &smokeFailure{Smoke: dcSmoke, Stage: r.stage, Code: "retained_sample_not_a_float"}
			}
			v := math.Float64frombits(uint64(*sample.Float))
			if v < 1 || v != math.Trunc(v) {
				return nil, &smokeFailure{Smoke: dcSmoke, Stage: r.stage, Code: "retained_sample_not_a_sequence_number"}
			}
			if uint64(v) <= dcLoadBase {
				continue // a sample of the sibling's earlier phases (1..dcSiblingBatches+1): not the load's, not in its journal
			}
			out = append(out, dcRetained{Seq: uint64(v), At: int64(sample.Time)})
		}
	}
	return out, nil
}

// dcRetainedStatusFailure is the failure of a read-back the voter answered with an error status: it
// carries the status and the typed fault code of the answer (a token of letters, or no_answer / unknown).
func dcRetainedStatusFailure(stage string, status int, raw []byte) error {
	return &smokeFailure{Smoke: dcSmoke, Stage: stage, Code: "retained_read_status_" + safeToken(dcFaultCode(raw)), Actual: status}
}

// dcReadFailureWhy names a failed read-back for the detail of the failed wait: the code of the failure
// and, when the voter answered, the HTTP status (digits are fine here: the name is built from the closed
// tokens above, never from the answer's text).
func dcReadFailureWhy(err error) string {
	var sf *smokeFailure
	if errors.As(err, &sf) {
		if sf.Actual != 0 {
			return sf.Code + "_http_" + strconv.Itoa(sf.Actual)
		}
		return sf.Code
	}
	return classifySmokeError(err)
}

// ---- the cross-host scenario ----

// siteOf waits for a voter's public listener certificate on its own host and returns a client that trusts it.
func (r *dcRun) siteOf(rem *dcRemote, id uint64) (*installSite, error) {
	var site *installSite
	err := r.until("voter_certificate_"+dcKey(id), 3*time.Minute, time.Second, func() (bool, string, error) {
		cert, err := rem.certificate(id, r.cluster.data[id])
		if err != nil {
			return false, "not_yet", nil
		}
		site = newInstallSite("https://"+r.cluster.public[id], cert)
		return true, "", nil
	})
	return site, err
}

// scenarioHosts is the cross-host run. See RunDeletionCluster for the shape; the differences are that
// the three voters are enabled systemd units on three machines, the authority journal is off every voter's
// disk, a load with an ACK journal runs through the deletion, and the operator powers one machine off
// while the deletion is pending.
func (r *dcRun) scenarioHosts(binary, release string, o *dcHostsOptions) (result error) {
	rem := newDCRemote(o.hosts)
	r.scanner = func(id uint64, needle string) (dcScan, error) {
		return rem.scan(id, dcRemoteVar+"/node-"+dcKey(id), needle)
	}
	r.authSpot = o.spot
	r.members = slices.Clone(dcNodes)
	r.watch, r.lag = o.cut, o.cut
	for _, id := range dcNodes {
		if id != o.cut {
			r.live = append(r.live, id)
		}
	}
	r.art.Caveat = "three voters on three machines driven over ssh and one of them powered off by the operator during the deletion; the machines are virtual machines of one cluster, so this is NOT an attestation of independent hardware, power or storage"
	r.art.NotRun = dcHostsNotRun(o)
	r.art.Evidence["mode"] = "cross-host"
	r.art.Evidence["cut_node"], r.art.Evidence["deletion_begun_through_node"], r.art.Evidence["older_backup_through_node"] = o.cut, o.via, o.backupNode
	placementOK := false
	defer func() { // a run that passed leaves nothing on the hosts when --cleanup asks for it; a failed run keeps its state for the post-mortem
		if result != nil || !o.cleanup {
			return
		}
		r.enter("dc_cleanup")
		for _, id := range dcNodes {
			if err := rem.wipe(id); err != nil {
				result = r.wrap(err)
				return
			}
		}
		r.art.Evidence["cleanup"] = "every host was wiped after the passed run: unit stopped, disabled and removed, binaries, keys, credentials, node data and backups removed; the authority journal and the operator's own directories are not touched"
	}()

	r.enter("dc_hosts_facts")
	facts := map[uint64]dcHostFacts{}
	for _, id := range dcNodes {
		f, err := rem.facts(id)
		if err != nil {
			return r.wrap(err)
		}
		facts[id] = f
	}
	r.art.Evidence["voter_machines"] = facts
	distinct, why := dcDistinctDomains(facts)
	if err := r.check("voters_on_three_distinct_machines", distinct, why); err != nil {
		return err
	}

	r.enter("dc_layout")
	work, err := os.MkdirTemp("", "soundpost-delcluster-hosts-")
	if err != nil {
		return r.wrap(err)
	}
	defer os.RemoveAll(work)
	cl, err := newHostsCluster(binary, release, work, o.hosts, r.art.Evidence)
	if err != nil {
		return r.wrap(err)
	}
	defer cl.cleanup()
	r.cluster = cl
	cfg := cl.installConfig()
	if err = config.Validate(cfg); err != nil {
		return r.wrap(err)
	}
	files, err := config.NodeConfigs(cfg)
	if err != nil {
		return r.wrap(err)
	}
	r.canary = "deletion_cluster_canary_" + strings.ReplaceAll(model.NewID().String(), "-", "")

	r.enter("dc_bootstrap_and_seed")
	fx, seed, err := cl.bootstrap(r.art.Evidence)
	if err != nil {
		return r.wrap(err)
	}
	r.fx = fx
	if err = cl.provision(files, seed); err != nil {
		return r.wrap(err)
	}
	r.enter("dc_authority_setup")
	if err = r.setupAuthority(work); err != nil {
		return err
	}
	placement, placementWhy, placementEvidence, perr := dcAuthorityPlacement(rem, o, net.LookupHost)
	if perr != nil {
		r.detail = dcSafeLine(perr.Error())
		return r.wrap(perr)
	}
	r.art.Evidence["authority_placement"] = placementEvidence
	if err = r.check("authority_journal_not_on_the_cut_machine", placement, placementWhy); err != nil {
		return err
	}
	placementOK = placement

	r.enter("dc_hosts_provision")
	binaryRaw, err := os.ReadFile(cl.binary)
	if err != nil {
		return r.wrap(err)
	}
	self, err := os.Executable()
	if err != nil {
		return r.wrap(err)
	}
	smokeRaw, err := os.ReadFile(self)
	if err != nil {
		return r.wrap(err)
	}
	for _, id := range dcNodes {
		spec := o.hosts[id]
		if err = rem.wipe(id); err != nil {
			return r.wrap(err)
		}
		k := dcKey(id)
		steps := []func() error{
			func() error { return rem.push(id, dcRemoteBin, "0755", binaryRaw) },
			func() error { return rem.push(id, dcRemoteSmoke, "0755", smokeRaw) },
			func() error {
				return rem.pushFile(id, dcRemoteEtc+"/node-"+k+".json", "0600", filepath.Join(work, "node-"+k+".json"))
			},
			func() error { return rem.pushFile(id, dcRemoteEtc+"/cluster.seed", "0600", cl.seed) },
			func() error { return rem.pushFile(id, dcRemoteEtc+"/pki/ca.pem", "0644", cl.pki.caFile) },
			func() error {
				return rem.pushFile(id, dcRemoteEtc+"/pki/"+distNodes[id-1].name+".pem", "0644", cl.pki.certs[id])
			},
			func() error {
				return rem.pushFile(id, dcRemoteEtc+"/pki/"+distNodes[id-1].name+".key", "0600", cl.pki.keys[id])
			},
			func() error { return rem.pushFile(id, dcRemoteKeys, "0600", r.auth.Keys) },
			func() error {
				return rem.push(id, "/etc/systemd/system/"+dcRemoteUnit+".service", "0644", []byte(dcUnit(spec, r.auth)))
			},
		}
		if env := dcAuthorityEnv(r.auth); env != nil {
			ca := os.Getenv("SSL_CERT_FILE")
			steps = append(steps, func() error { return rem.push(id, dcRemoteEnv, "0600", env) },
				func() error { return rem.pushFile(id, dcRemoteS3CA, "0644", ca) })
		}
		entries, err := os.ReadDir(r.auth.KeyDir)
		if err != nil {
			return r.wrap(err)
		}
		for _, e := range entries {
			name := e.Name()
			steps = append(steps, func() error {
				return rem.pushFile(id, dcRemoteKeyDir+"/"+name, "0600", filepath.Join(r.auth.KeyDir, name))
			})
		}
		for _, step := range steps {
			if err = step(); err != nil {
				return r.wrap(err)
			}
		}
		if _, err = rem.run(id, "systemctl daemon-reload && systemctl enable "+dcRemoteUnit+" >/dev/null 2>&1; sync", nil, 2*time.Minute); err != nil {
			return r.wrap(err)
		}
	}
	sum := sha256.Sum256(binaryRaw)
	r.art.Evidence["voter_binary_sha256"] = fmt.Sprintf("%x", sum)

	r.enter("dc_start_three_members")
	for _, id := range dcNodes {
		if err = rem.systemctl(id, "start"); err != nil {
			return r.wrap(err)
		}
	}
	for _, id := range dcNodes {
		site, err := r.siteOf(rem, id)
		if err != nil {
			return err
		}
		r.sites[id] = site
	}
	r.enter("dc_ready_all")
	if err = r.ready(240*time.Second, dcNodes...); err != nil {
		return err
	}
	r.mark("cluster_ready_ms")
	for _, id := range dcNodes {
		if err = r.login(id); err != nil {
			return err
		}
	}

	r.enter("dc_onboard_sibling_and_ingest_canary")
	if err = r.createSibling(1); err != nil {
		return err
	}
	r.fx.queryTime = fmt.Sprint(time.Now().Add(time.Minute).UnixNano())
	resource := model.Resource{Service: fx.service, Environment: fx.environment, Build: fx.build, Instance: "instance", Labels: model.Labels{}}
	for i := 1; i <= dcBatches; i++ {
		value := model.FloatBits(math.Float64bits(float64(i)))
		record := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(time.Now().Add(-time.Duration(dcBatches-i) * time.Second).UnixNano()), Resource: resource,
			Payload: model.Payload{Metric: &model.MetricPoint{Name: r.canary, Labels: model.Labels{}, SampleKind: "float", Value: &value, Unit: "1", Type: "gauge"}}}
		batch := model.Batch{Version: 1, Project: fx.project, Source: fx.source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{record}}
		if batch.RouteSlot, err = model.OwnerSlot(fx.org, fx.project, fx.source, batch.Producer, record); err != nil {
			return r.wrap(err)
		}
		status, raw, _, err := retryIngest(r.sites[1], batch, fx.credential, 120*time.Second)
		if err != nil || status != 200 {
			return r.wrap(requireSmokeResponse("ingest_canary", status, 200, raw, err))
		}
	}
	for i := 1; i <= dcSiblingBatches; i++ {
		if err = r.siblingIngest(1, float64(i)); err != nil {
			return err
		}
	}
	for _, id := range dcNodes {
		var body []byte
		err = r.until("canary_served_node_"+dcKey(id), 120*time.Second, time.Second, func() (bool, string, error) {
			status, raw, err := r.query(id)
			if err != nil {
				return false, "transport", nil
			}
			body = raw
			return dcServedLatest(status, raw, dcBatches), dcServedWhat(status, raw), nil
		})
		if err != nil {
			return err
		}
		if err = r.check("canary_served_node_"+dcKey(id), bytes.Contains(body, []byte(r.canary)), "complete answer with the latest value; the canary name is in the body"); err != nil {
			return err
		}
	}
	if err = r.checkSibling("before_deletion", dcNodes...); err != nil {
		return err
	}

	r.enter("dc_positive_control_live_scan")
	control := map[string]dcScan{}
	for _, id := range dcNodes {
		s, err := r.scan(id)
		if err != nil {
			return err
		}
		control[dcKey(id)] = s
		if err = r.check("positive_control_canary_present_node_"+dcKey(id), s.Hits > 0, fmt.Sprintf("%d hits in %d files, by store %v", s.Hits, s.Files, s.ByStore)); err != nil {
			return err
		}
		m, err := r.scanMarker(id, r.sib.marker)
		if err != nil {
			return err
		}
		if err = r.check("positive_control_sibling_marker_present_node_"+dcKey(id), m.Hits > 0, fmt.Sprintf("%d hits in %d files, by store %v", m.Hits, m.Files, m.ByStore)); err != nil {
			return err
		}
	}
	r.art.Evidence["live_scan_before_deletion"] = control

	r.enter("dc_older_backup_through_a_stopped_voter")
	if err = r.backupThroughHost(rem, o.backupNode); err != nil {
		return err
	}
	if err = rem.systemctl(o.backupNode, "start"); err != nil {
		return r.wrap(err)
	}
	if err = r.ready(240*time.Second, o.backupNode); err != nil {
		return err
	}
	bootBefore := facts[o.cut].BootID

	// ---- the load, then the deletion at the announced instant, the cut after it ----
	r.enter("dc_ack_journal_load")
	journalFile := filepath.Join(filepath.Dir(o.cutFile), "ack-journal.jsonl")
	load, err := r.startLoad(journalFile, o.loadWorkers, o.loadInterval)
	if err != nil {
		return r.wrap(err)
	}
	loadStopped := false
	defer func() {
		if !loadStopped {
			_ = load.drain()
		}
	}()
	schedule := dcSchedule(o)
	raw, _ := json.MarshalIndent(schedule, "", "  ")
	if err = os.WriteFile(o.cutFile, append(raw, '\n'), 0o600); err != nil {
		return r.wrap(err)
	}
	fmt.Fprintf(os.Stderr, "DC_CUT_SCHEDULE cut_node=%d cut_host=%s deletion_begins_at=%s cut_at=%s keep_down_for_at_least=%s\n", schedule.Node, schedule.Host, schedule.BeginAt, schedule.CutAt, schedule.DownFor)
	r.art.Evidence["cut_schedule"] = schedule
	if err = r.check("begin_instant_not_in_the_past", time.Until(o.beginAt) > 15*time.Second, "the setup finished before the announced instant, leaving time for a fresh session and the first load"); err != nil {
		return err
	}
	time.Sleep(time.Until(o.beginAt.Add(-10 * time.Second)))
	if err = r.login(o.via); err != nil { // a deletion needs a session younger than 5 minutes
		return err
	}
	time.Sleep(time.Until(o.beginAt))

	r.enter("dc_begin_deletion_under_load")
	t0 := time.Now()
	if err = r.beginDeletion(o.via); err != nil {
		return err
	}
	beganMS := time.Since(t0).Milliseconds() // the begin call itself took this long; the monitor's clock starts at t0
	other := o.live2()
	mon := r.startMonitor([]uint64{o.via, other}, t0)
	monStopped := false
	defer func() {
		if !monStopped {
			mon.finish()
		}
	}()
	r.mark("deletion_begun_under_load_ms")

	r.enter("dc_wait_for_the_power_cut_and_the_return")
	var outage dcOutage
	err = r.until("cut_voter_outage_and_return", o.waitCut, 2*time.Second, func() (bool, string, error) {
		if found, ok := mon.outageOf(o.cut); ok {
			outage = found
		}
		return outage.EndMS != 0 && outage.lasted() >= o.minOutage, fmt.Sprintf("outage_seen_%v", outage.EndMS != 0), nil
	})
	if err != nil {
		return err
	}
	// the voter is back and ready: stop probing before any new login touches the sessions
	mon.finish()
	monStopped = true
	points := mon.points()
	r.art.Evidence["outage_of_the_cut_voter"] = map[string]any{"start_ms_after_begin": outage.StartMS, "end_ms_after_begin": outage.EndMS, "lasted_s": outage.lasted().Seconds()}
	r.art.Evidence["deletion_timeline_through_live_voters"] = points
	mid, midWhy := dcCutMidDeletion(beganMS, points, outage) // both clocks start at t0, before the begin call
	r.mark("cut_voter_back_ms")

	r.enter("dc_cut_host_really_rebooted")
	after, err := rem.facts(o.cut)
	if err != nil {
		return r.wrap(err)
	}
	if o.rehearsal {
		r.art.Evidence["rehearsal"] = "the cut was a stop of the voter's service: the boot id was not required to change and this run is NOT a power-cut result"
	} else if err = r.check("cut_machine_rebooted_boot_id_changed", after.BootID != "" && after.BootID != bootBefore, "the machine's boot id differs from the one read before the cut (a power cycle, not a process restart)"); err != nil {
		return err
	}
	r.art.Evidence["cut_machine_after"] = after

	r.enter("dc_drain_the_load")
	if err = load.drain(); err != nil {
		return r.wrap(err)
	}
	loadStopped = true
	r.art.Evidence["load"] = map[string]any{"issued": load.issued.Load(), "acknowledged": load.acked.Load(), "refused": load.refused.Load(), "resent_attempts": load.resent.Load()}
	if err = r.check("load_issued_and_acknowledged", load.acked.Load() > 0 && load.refused.Load() == 0, fmt.Sprintf("%d issued, %d acknowledged, %d refused as non-retryable, %d resent attempts", load.issued.Load(), load.acked.Load(), load.refused.Load(), load.resent.Load())); err != nil {
		return err
	}

	r.enter("dc_wait_complete_after_the_return")
	for _, id := range dcNodes {
		if err = r.login(id); err != nil { // a fresh session: the cut voter's old one is as good as any, but nothing is assumed
			return err
		}
	}
	for _, id := range dcNodes {
		err = r.until("operation_complete_node_"+dcKey(id), r.wait, dcPollInterval, func() (bool, string, error) {
			op, err := r.poll(id)
			if err != nil {
				var sf *smokeFailure
				if errors.As(err, &sf) && sf.Actual >= 500 {
					return false, "status_" + strconv.Itoa(sf.Actual), nil
				}
				return false, "", err
			}
			return op.Phase == "complete" && op.Physical == "done", "phase_" + safeToken(op.Phase) + "_physical_" + safeToken(op.Physical), nil
		})
		if err != nil {
			return err
		}
		r.mark("complete_seen_node_" + dcKey(id) + "_ms")
	}
	r.enter("dc_authority_checkpointed_deletion")
	if err = r.checkAuthority(); err != nil {
		return err
	}
	if err = r.check("authority_tombstone_read_from_a_journal_off_the_cut_machine_after_the_cut", placementOK && r.authTombstones >= 1, fmt.Sprintf("%d tombstone(s) read after the cut and the voter's return from a journal that is not on the cut machine", r.authTombstones)); err != nil {
		return err
	}

	r.enter("dc_wait_receipt_clean_all_nodes")
	track := newDCCleanTrack()
	err = r.until("receipt_clean_all_nodes", r.wait, dcPollInterval, func() (bool, string, error) {
		progress, err := r.sample(track, dcNodes...)
		if err != nil {
			return false, "", err
		}
		return len(track.cleanAt) == len(dcNodes) && len(progress) == 0, "not_clean " + strings.Join(progress, " "), nil
	})
	if err != nil {
		return err
	}
	r.art.Evidence["live_scan_at_first_clean_receipt"] = track.own
	r.art.Evidence["cut_voter_scan_at_first_clean_receipt"] = track.lagging
	r.art.Evidence["receipt_residual_trail"] = track.trail
	if err = r.check("receipt_clean_on_all_three_nodes", true, "phase complete, physical done, no residual store on nodes 1, 2 and 3"); err != nil {
		return err
	}
	for _, id := range dcNodes {
		key := dcKey(id)
		if err = r.check("live_scan_zero_when_receipt_first_clean_node_"+key, track.own[key].Hits == 0, fmt.Sprintf("%d hits in %d files, by store %v", track.own[key].Hits, track.own[key].Files, track.own[key].ByStore)); err != nil {
			return err
		}
	}

	// ---- every acknowledged sample, read back from every voter ----
	r.enter("dc_ack_journal_readback")
	jraw, err := os.ReadFile(journalFile)
	if err != nil {
		return r.wrap(err)
	}
	st, jerr := dcReadAckJournal(jraw)
	if err = r.check("ack_journal_intact", jerr == nil, fmt.Sprintf("%d lines, hash-chained", st.Lines)); err != nil {
		if jerr != nil {
			r.detail = jerr.Error()
		}
		return err
	}
	digests := map[uint64]string{}
	err = r.until("voters_retain_every_acknowledged_sample", 5*time.Minute, 5*time.Second, func() (bool, string, error) {
		var bad []string
		equal := true
		for _, id := range dcNodes {
			retained, err := r.readRetained(id)
			if err != nil {
				return false, "read_failed_node_" + dcKey(id) + "_" + dcReadFailureWhy(err), nil
			}
			digests[id] = dcDigest(retained)
			if v := dcJudgeRetained(st, retained); len(v) > 0 {
				bad = append(bad, fmt.Sprintf("node_%d:%d_violations_first_%s", id, len(v), v[0]))
			}
			equal = equal && digests[id] == digests[dcNodes[0]]
		}
		return len(bad) == 0 && equal, strings.Join(bad, " ") + fmt.Sprintf(" digests_equal_%v", equal), nil
	})
	if err != nil {
		return err
	}
	r.art.Evidence["ack_journal"] = map[string]any{"lines": st.Lines, "samples_issued": len(st.Issued), "samples_acknowledged": len(st.Acked), "acknowledged_by_voter": dcCountByVoter(st), "digest_per_voter": digests}
	if err = r.check("every_acknowledged_sample_read_back_from_every_voter", true, fmt.Sprintf("%d acknowledged samples present with exact value and time on all three voters, no duplicate or foreign sample, one digest", len(st.Acked))); err != nil {
		return err
	}

	// ---- stop every voter, scan every directory, start them again ----
	r.enter("dc_stop_all_and_scan")
	for _, id := range dcNodes {
		if err = rem.systemctl(id, "stop"); err != nil {
			return r.wrap(err)
		}
	}
	if err = r.scanAll("whole_file_scan_all_nodes_stopped", "dc_whole_file_scan"); err != nil {
		return err
	}
	r.enter("dc_restart_all_and_verify")
	for _, id := range dcNodes {
		if err = rem.systemctl(id, "start"); err != nil {
			return r.wrap(err)
		}
	}
	if err = r.ready(240*time.Second, dcNodes...); err != nil {
		return err
	}
	for _, id := range dcNodes {
		if err = r.login(id); err != nil {
			return err
		}
		if err = r.receiptStaysCleanAfterRestart(dcKey(id), r.wait, dcPollInterval, func() (string, string, []string, error) {
			op, err := r.poll(id)
			return op.Phase, op.Physical, op.ResidualStores, err
		}); err != nil {
			return err
		}
		status, raw, err := r.query(id)
		if err != nil {
			return r.wrap(err)
		}
		if err = r.check("retired_project_denied_after_restart_node_"+dcKey(id), dcDenied(status, raw) && !bytes.Contains(raw, []byte(r.canary)), fmt.Sprintf("status %d code %s", status, dcFaultCode(raw))); err != nil {
			return err
		}
	}
	if err = r.siblingIngest(o.cut, float64(dcSiblingBatches+1)); err != nil {
		return err
	}
	if err = r.check("sibling_ingest_acknowledged_through_the_cut_voter", true, "a new sample for the sibling project acknowledged through node "+dcKey(o.cut)); err != nil {
		return err
	}
	for _, id := range dcNodes {
		if err = rem.systemctl(id, "stop"); err != nil {
			return r.wrap(err)
		}
	}
	if err = r.scanAll("second_whole_file_scan", "dc_second_whole_file_scan"); err != nil {
		return err
	}

	// ---- the older backup restored against the current authority (on this machine) ----
	r.enter("dc_restore_older_backup")
	if err = r.restoreOlderBackup(); err != nil {
		return err
	}

	// ---- the verdicts that need the whole run ----
	r.enter("dc_verdict")
	if err = r.check("power_cut_landed_during_the_deletion", mid, midWhy); err != nil {
		return err
	}
	return r.check("outage_of_the_cut_voter_at_least_min_outage", outage.lasted() >= o.minOutage, fmt.Sprintf("%.0f s down, at least %.0f s wanted", outage.lasted().Seconds(), o.minOutage.Seconds()))
}

// live2 is the live voter other than the one the deletion is begun through.
func (o *dcHostsOptions) live2() uint64 {
	for _, id := range dcNodes {
		if id != o.cut && id != o.via {
			return id
		}
	}
	return o.via
}

func dcCountByVoter(st dcAckState) map[string]int {
	out := map[string]int{}
	for _, node := range st.Acked {
		out[strconv.FormatUint(node, 10)]++
	}
	return out
}

// backupThroughHost stops one voter on its own machine and takes a distributed backup of the cluster
// THROUGH its directory there (`backup create --mode distributed`: the process joins the two running
// voters, which keep the quorum), before any deletion exists, then brings the backup here for the restore.
func (r *dcRun) backupThroughHost(rem *dcRemote, id uint64) error {
	a := r.auth
	if err := rem.systemctl(id, "stop"); err != nil {
		return r.wrap(err)
	}
	k := dcKey(id)
	remote := *a
	remote.Keys = dcRemoteKeys
	args := append([]string{dcRemoteBin, "backup", "create", "--mode", "distributed", "--node-id", k, "--cluster-config", dcRemoteEtc + "/node-" + k + ".json", "--data-dir", dcRemoteVar + "/node-" + k,
		"--admin-email", dcOwnerEmail, "--key-dir", dcRemoteKeyDir, "--data-kek", dcDataKEK, "--secret-kek", dcSecretKEK, "--authority-keys", dcRemoteKeys, "--dest-dir", dcRemoteBackup, "--reason", "deletion-cluster smoke older backup"}, remote.flags()...)
	var quoted []string
	for _, w := range args {
		quoted = append(quoted, dcQuote(w))
	}
	// the owner's password reaches the command through stdin, never through a command line
	script := "read -r SOUNDPOST_ADMIN_PASSWORD; export SOUNDPOST_ADMIN_PASSWORD; set -a; [ ! -f " + dcRemoteEnv + " ] || . " + dcRemoteEnv + "; set +a; exec " + strings.Join(quoted, " ")
	started := time.Now()
	out, err := rem.run(id, "sh -c "+dcQuote(script), strings.NewReader(r.fx.password+"\n"), 12*time.Minute)
	if err != nil {
		return r.wrap(err)
	}
	info, err := dcParseBackupCreate(out)
	if err != nil {
		r.detail = dcSafeLine(err.Error())
		return r.wrap(err)
	}
	if err = rem.copyDown(id, dcRemoteBackup, a.BackupDir); err != nil {
		return r.wrap(err)
	}
	r.backup, r.backupSibling, r.backupAt = info, r.sib.last, r.sib.queryTime
	r.art.Evidence["backup_before_deletion"] = map[string]any{"backup_id": info.ID, "taken_through_voter": id, "voters": info.Voters, "objects": info.Objects, "control_revision": info.ControlRevision,
		"authority_sequence": info.AuthoritySequence, "authority_generation": info.AuthorityGeneration, "duration_ms": time.Since(started).Milliseconds(), "canary_ingested_before": true}
	r.mark("older_backup_taken_ms")
	return r.check("older_backup_taken_before_the_deletion_through_a_stopped_voter", info.Voters == 3 && info.Objects > 0, fmt.Sprintf("backup %s of a three-voter cluster, %d objects, authority sequence %d", info.ID, info.Objects, info.AuthoritySequence))
}

// runDeletionClusterHosts is the cross-host entry: one fresh cluster over the hosts, one artifact.
func runDeletionClusterHosts(o *dcHostsOptions, artifactDir, binary, release string, wait, hold time.Duration) error {
	run := newDCRecorder()
	run.artifactDir, run.file = artifactDir, "deletion-cluster-hosts.json"
	if o.rehearsal {
		run.file = "deletion-cluster-hosts-rehearsal.json"
	}
	r := &dcRun{dcRecorder: run, wait: wait, hold: hold, lag: o.cut, withAuthority: true, sites: map[uint64]*installSite{}, ownerSite: map[uint64]*installSite{}, owner: map[uint64]auth.Session{}, reader: map[uint64]auth.Session{}}
	return run.finish(r.scenarioHosts(binary, release, o))
}

// receiptStaysCleanAfterRestart judges the receipt a voter answers after the restart of every voter. A restarted voter judges itself
// unproven until its first worker pass has attested again (control.Store.ClusterOperationResidual), so for a moment the receipt of a
// completed deletion may still name a store: that is the conservative direction and not a failure, and the receipt must be clean once
// the pass ran. It is therefore polled until it is clean, bounded by limit (the typed failure is timeout_receipt_clean_after_restart_node_<n>
// with the last answer, its residual stores included, as detail). What is never waited out is a receipt that is not complete and done: that
// one is judged at once. The single-host variant makes the same wait (deletion_cluster_phases.go).
func (r *dcRecorder) receiptStaysCleanAfterRestart(node string, limit, interval time.Duration, poll func() (phase, physical string, residual []string, err error)) error {
	var phase, physical string
	var residual []string
	notClean := 0
	err := r.until("receipt_clean_after_restart_node_"+node, limit, interval, func() (bool, string, error) {
		var err error
		if phase, physical, residual, err = poll(); err != nil {
			return false, "", err
		}
		complete := phase == "complete" && physical == "done"
		if complete && len(residual) != 0 {
			notClean++
		}
		return !complete || len(residual) == 0, fmt.Sprintf("phase %s physical %s residual %v", safeToken(phase), safeToken(physical), residual), nil
	})
	if err != nil {
		return err
	}
	return r.check("receipt_stays_clean_after_restart_node_"+node, phase == "complete" && physical == "done" && len(residual) == 0,
		fmt.Sprintf("phase %s physical %s residual %v after %d answer(s) that named a store", safeToken(phase), safeToken(physical), residual, notClean))
}

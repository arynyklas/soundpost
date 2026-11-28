// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

const (
	maxInFlight = 20000 // beyond this a request is shed and counted: the generator never blocks (open loop)
	rowsHeader  = "start_us,sched_us,latency_us,late_us,status,project,records,bytes,slot,attempts,node,err"
	// A batch the product has not durably ACKed is sent again, identical (same id, same body), to the next member, the way the SDK's queue
	// does (docs/operations/distributed.md, "A batch that is committed but whose acknowledgement never reached the sender"). The request
	// as the SDK's caller sees it ends at the first durable ACK, or is counted as not ACKed after requestBudget.
	requestBudget  = 40 * time.Second
	attemptTimeout = 15 * time.Second
)

// AckRow is one request: its first send (relative to T0), how long it waited after its scheduled instant, the latency from that first
// send to the product's durable receipt (every retry included) and its outcome. Numbers and closed vocabulary only.
type AckRow struct {
	StartUS, SchedUS  int64
	LatencyUS, LateUS int64
	Status            int // HTTP status of the last attempt; 0 = transport failure or timeout, -1 = shed by the generator
	Project           int
	Records           int
	Bytes             int
	Slot              int
	Attempts          int
	Node              int // the member (1..3) that gave the durable ACK, 0 when none did
	Err               string
}

type loader struct {
	plan   *Plan
	client *http.Client
	t0     time.Time
	out    string

	mu       sync.Mutex
	rowsGz   *gzip.Writer
	rowsBuf  *bufio.Writer
	ledger   *bufio.Writer
	ledgerF  *os.File
	inflight atomic.Int64
	maxInFl  atomic.Int64
	wg       sync.WaitGroup

	sent, ok, refused, transport, shed atomic.Int64
	retriedRequests, attemptsTotal     atomic.Int64
	ackedBy                            [4]atomic.Int64
	refusedBy                          sync.Map // status -> *atomic.Int64
	recSent, recAcked                  [256]atomic.Int64
	bytesSent                          atomic.Int64
	ackedBatches                       atomic.Int64
	lookups, lookupHits, lookupMisses  atomic.Int64  // receipt lookups made after an attempt without an answer, the ones that found the batch, the 404s
	attemptTo                          time.Duration // a test's attempt timeout; zero: attemptTimeout
}

func (l *loader) tlsClient(caPath string) {
	pem, err := os.ReadFile(caPath)
	must(err, "ca")
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		fatalf("ca holds no certificate")
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, MaxIdleConns: 2048, MaxIdleConnsPerHost: 2048, IdleConnTimeout: 90 * time.Second,
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, ResponseHeaderTimeout: attemptTimeout, DisableCompression: true}
	l.client = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (l *loader) recordRow(r AckRow) {
	l.mu.Lock()
	fmt.Fprintf(l.rowsBuf, "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%s\n", r.StartUS, r.SchedUS, r.LatencyUS, r.LateUS, r.Status, r.Project, r.Records, r.Bytes, r.Slot, r.Attempts, r.Node, r.Err)
	l.mu.Unlock()
}

// ledgerEntry persists one ACKed batch: the receipt as the product answered it and the records it carried (identifiers and numbers only).
func (l *loader) ledgerEntry(pr Prepared, rc model.Receipt) {
	var head [1 + 2 + 2 + 16 + 32 + 16 + 8]byte
	head[0] = byte(pr.Project)
	binary.BigEndian.PutUint16(head[1:], pr.Slot)
	binary.BigEndian.PutUint16(head[3:], uint16(len(pr.Records)))
	copy(head[5:], pr.ID[:])
	copy(head[21:], rc.Hash[:])
	copy(head[53:], rc.Cursor.Group[:])
	binary.BigEndian.PutUint64(head[69:], uint64(rc.Cursor.Index))
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ledger.Write(head[:])
	var rec [1 + 16 + 8 + 16]byte
	for _, m := range pr.Records {
		rec[0] = m.Kind
		copy(rec[1:], m.ID[:])
		binary.BigEndian.PutUint64(rec[17:], uint64(m.TS))
		copy(rec[25:], m.Aux[:])
		l.ledger.Write(rec[:])
	}
}

// attempt sends the batch once to member ni, or, when lookup is set, asks it for the receipt of the batch (POST /ingest/v1/receipts,
// the request packages/core/src/transport.ts lookup makes), and returns the answer (status 0 = transport failure or timeout) and its
// Retry-After.
func (l *loader) attempt(pr Prepared, cred string, ni int, timeout time.Duration, lookup *model.ReceiptRequest) (status int, body []byte, retryAfter string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	path, payload := "/ingest/v1/batches", pr.Body
	if lookup != nil {
		path = "/ingest/v1/receipts"
		payload, _ = json.Marshal(*lookup)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+l.plan.Nodes[ni].Addr+path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("User-Agent", "soundpost-overhead-distributed")
	resp, err := l.client.Do(req)
	if err != nil {
		return 0, nil, ""
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil {
		return 0, nil, ""
	}
	return resp.StatusCode, body, resp.Header.Get("Retry-After")
}

// attemptTimeout is how long one attempt may take: the SDK's own wire deadline is its flush's, the generator's is a fixed budget.
func (l *loader) attemptTimeout() time.Duration {
	if l.attemptTo != 0 {
		return l.attemptTo
	}
	return attemptTimeout
}

// receiptRequest is the lookup of the receipt of the batch pr carries: its identity and the hash of its canonical form, which is
// what the product names as the original hash of the batch (policy.Normalize). The SDK has them from the batch it froze; the
// generator, which builds a batch once and sends it, reads them back from the body, and only when an attempt ended without an answer.
func receiptRequest(pr Prepared) (model.ReceiptRequest, error) {
	var b model.Batch
	if err := json.Unmarshal(pr.Body, &b); err != nil {
		return model.ReceiptRequest{}, err
	}
	canonical, err := model.CanonicalJSON(b)
	if err != nil {
		return model.ReceiptRequest{}, err
	}
	return model.ReceiptRequest{Source: b.Source, Producer: b.Producer, RouteSlot: b.RouteSlot, BatchID: b.ID, OriginalHash: model.HashCanonical(canonical)}, nil
}

func (l *loader) send(pr Prepared, sched time.Time, cred string) {
	defer l.wg.Done()
	row := AckRow{SchedUS: sched.Sub(l.t0).Microseconds(), Project: pr.Project, Records: len(pr.Records), Bytes: len(pr.Body), Slot: int(pr.Slot)}
	if l.inflight.Add(1) > maxInFlight {
		l.inflight.Add(-1)
		row.StartUS, row.Status, row.Err = time.Since(l.t0).Microseconds(), -1, "shed"
		l.shed.Add(1)
		l.recordRow(row)
		return
	}
	defer l.inflight.Add(-1)
	if n := l.inflight.Load(); n > l.maxInFl.Load() {
		l.maxInFl.Store(n)
	}
	l.sent.Add(1)
	l.bytesSent.Add(int64(len(pr.Body)))
	for _, m := range pr.Records {
		l.recSent[m.Kind].Add(1)
	}
	t0 := time.Now()
	row.StartUS, row.LateUS = t0.Sub(l.t0).Microseconds(), t0.Sub(sched).Microseconds()
	deadline := t0.Add(requestBudget)
	first := pr.Project % len(l.plan.Nodes) // the SDK's own member; a failure moves the batch on to the next one
	// The SDK's queue (packages/core/src/queue.ts flush): an attempt is marked ambiguous before it is sent, and a send that ended without
	// an answer (a timeout, a connection that broke) leaves it so: the next attempt does not send the batch again but asks for its
	// receipt (POST /ingest/v1/receipts), which the product answers when the batch is durably in its data and with 404 when it is not;
	// only that 404 (or an explicit refusal of the send, 429/503) lets the batch be sent again. Every other answer to a lookup is
	// retried as a lookup after the wait.
	ambiguous := false
	var ask *model.ReceiptRequest // the receipt lookup of the batch, made when the first one is needed
	for try := 0; ; try++ {
		ni := (first + try) % len(l.plan.Nodes)
		row.Attempts = try + 1
		lookup := ambiguous
		ambiguous = true
		var q *model.ReceiptRequest
		if lookup {
			if ask == nil {
				r, err := receiptRequest(pr)
				if err != nil {
					row.Err = "lookup_unavailable"
					l.refused.Add(1)
					break
				}
				ask = &r
			}
			q = ask
			l.lookups.Add(1)
		}
		status, body, retryAfter := l.attempt(pr, cred, ni, min(l.attemptTimeout(), time.Until(deadline)), q)
		row.Status = status
		if status == http.StatusOK {
			var rc model.Receipt
			if model.StrictJSON(body, &rc) != nil || rc.Version == 0 || rc.BatchID != pr.ID || lookup && rc.Hash != ask.OriginalHash {
				row.Err = "bad_receipt"
				l.refused.Add(1)
				break
			}
			row.Err, row.Node = "", ni+1
			l.ok.Add(1)
			l.ackedBatches.Add(1)
			l.ackedBy[ni+1].Add(1)
			if lookup {
				l.lookupHits.Add(1)
			}
			for _, m := range pr.Records {
				l.recAcked[m.Kind].Add(1)
			}
			l.ledgerEntry(pr, rc)
			break
		}
		switch {
		case status == http.StatusUnauthorized || status == http.StatusForbidden || !lookup && status != 0 && !retriable(status):
			// denied, or a send answered with a status the SDK drops the batch for (terminal_rejected)
			row.Err = "refused"
			l.refused.Add(1)
			c, _ := l.refusedBy.LoadOrStore(status, new(atomic.Int64))
			if n := c.(*atomic.Int64).Add(1); n <= 3 {
				// the body of a refusal is the product's closed fault document (code, retryable, safe detail): never record content.
				fmt.Fprintf(os.Stderr, "distributed: refusal %d #%d: %.300s\n", status, n, body)
			}
		case lookup && status == http.StatusNotFound:
			ambiguous = false // the product holds no such batch: send it again
			l.lookupMisses.Add(1)
		case !lookup && retriable(status) && status != 0:
			ambiguous = false // an explicit refusal of the send: nothing was appended
		}
		if row.Err == "refused" {
			break
		}
		wait := sdkWait(try, retryAfter)
		if time.Until(deadline) <= wait {
			row.Err = "transport"
			if status != 0 {
				row.Err = "unavailable"
				c, _ := l.refusedBy.LoadOrStore(status, new(atomic.Int64))
				c.(*atomic.Int64).Add(1)
			}
			l.transport.Add(1)
			break
		}
		time.Sleep(wait)
	}
	row.LatencyUS = time.Since(t0).Microseconds()
	if row.Attempts > 1 {
		l.retriedRequests.Add(1)
	}
	l.attemptsTotal.Add(int64(row.Attempts))
	l.recordRow(row)
}

// KillRecord is what the shard that carries the kill did: the decision (the leadership each member reports for itself just before),
// the request, and the answers of the node's agent (the SIGKILL of the exact server PID, the restart).
type KillRecord struct {
	AtS            float64        `json:"planned_at_s"`
	DownS          float64        `json:"down_s"`
	Node           uint64         `json:"node"`
	LeadersBefore  map[string]int `json:"leaders_before_by_node"`   // node id -> groups it reports leading
	LeadersAfter   map[string]int `json:"leaders_after_by_node"`    // the same, after the node is ready again
	SentUnixMS     int64          `json:"kill_sent_unix_ms"`        // the generator's clock, just before the request
	AnsweredUnixMS int64          `json:"restart_answered_unix_ms"` // the node was ready again
	Kill           Event          `json:"agent_kill"`
	Start          Event          `json:"agent_start"`
}

// LoadSummary is the generator's own account of a run.
type LoadSummary struct {
	Label           string           `json:"label"`
	Shard           int              `json:"shard"`
	Shards          int              `json:"shards"`
	Config          Config           `json:"config"`
	T0UnixMS        int64            `json:"t0_unix_ms"`
	EndUnixMS       int64            `json:"end_unix_ms"`
	WarmupS         float64          `json:"warmup_s"`
	DurationS       float64          `json:"steady_s"`
	Sent            int64            `json:"requests_sent"`
	Acked           int64            `json:"requests_acked"`
	Refused         int64            `json:"requests_refused"`
	RefusedByCode   map[int]int64    `json:"refused_by_status"`
	Transport       int64            `json:"requests_transport_failed"`
	Shed            int64            `json:"requests_shed_by_generator"`
	Retried         int64            `json:"requests_retried"`
	Attempts        int64            `json:"attempts_total"`
	Lookups         int64            `json:"receipt_lookups"`
	LookupHits      int64            `json:"receipt_lookups_found"`
	LookupMisses    int64            `json:"receipt_lookups_not_found"`
	AckedByNode     map[int]int64    `json:"acked_by_node"`
	MaxInFlight     int64            `json:"max_in_flight"`
	RecordsSent     map[string]int64 `json:"records_sent_by_kind"`
	RecordsAcked    map[string]int64 `json:"records_acked_by_kind"`
	EncodedBytes    int64            `json:"encoded_bytes_sent"`
	Window          string           `json:"flush_window"`
	GeneratorCPUs   int              `json:"generator_gomaxprocs"`
	BatchesPerSec   float64          `json:"batches_per_s_mean"`
	RowsFile        string           `json:"rows_file"`
	LedgerFile      string           `json:"ledger_file"`
	LedgerSHA256    string           `json:"ledger_sha256"`
	LedgerBatches   int64            `json:"ledger_batches"`
	Kill            *KillRecord      `json:"kill,omitempty"`
	LeadersAtStart  map[string]int   `json:"leaders_at_start_by_node,omitempty"`
	PlannedKillAtS  float64          `json:"kill_at_s,omitempty"`
	GeneratorStatus string           `json:"generator_status,omitempty"`
}

func kindName(b byte) string {
	switch b {
	case 'm':
		return "metric"
	case 's':
		return "span"
	case 'l':
		return "log"
	case 'e':
		return "error"
	case 'j':
		return "job_attempt"
	}
	return "unknown"
}

// control calls a node agent's control endpoint.
func control(n PlanNode, method, path string, timeout time.Duration, into any) error {
	req, _ := http.NewRequest(method, "http://"+n.Control+path, nil)
	req.Header.Set("X-Harness-Token", n.ControlToken)
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("control %s %s: status %d: %.200s", method, path, resp.StatusCode, raw)
	}
	if into != nil {
		return json.Unmarshal(raw, into)
	}
	return nil
}

// leadership asks every agent for the leaderships it holds in its own view: node id -> groups it leads.
func leadership(plan *Plan) (map[string]int, error) {
	out := map[string]int{}
	for _, n := range plan.Nodes {
		var r struct {
			Leaders map[string]int `json:"leaders"`
			Groups  int            `json:"groups"`
		}
		if err := control(n, "GET", "/leaders", 2*time.Minute, &r); err != nil {
			return nil, err
		}
		if r.Groups == 0 {
			return nil, fmt.Errorf("node %d reports no groups", n.ID)
		}
		out[strconv.FormatUint(n.ID, 10)] = r.Leaders[strconv.FormatUint(n.ID, 10)]
	}
	return out, nil
}

// killMostLeading is the failure of the gate: the node that leads the most groups is killed (SIGKILL of its server process, by its
// agent), stays down for down, and is started again from its own data directory.
func killMostLeading(plan *Plan, down time.Duration, rec *KillRecord) error {
	before, err := leadership(plan)
	if err != nil {
		return fmt.Errorf("leadership before the kill: %w", err)
	}
	rec.LeadersBefore = before
	var target PlanNode
	best := -1
	for _, n := range plan.Nodes { // the lowest id wins a tie
		if c := before[strconv.FormatUint(n.ID, 10)]; c > best {
			best, target = c, n
		}
	}
	rec.Node = target.ID
	rec.SentUnixMS = now()
	var answer map[string]Event
	if err := control(target, "POST", "/kill9?down="+down.String(), 15*time.Minute, &answer); err != nil {
		return fmt.Errorf("kill -9 of node %d: %w", target.ID, err)
	}
	rec.AnsweredUnixMS = now()
	rec.Kill, rec.Start = answer["kill"], answer["start"]
	if after, err := leadership(plan); err == nil {
		rec.LeadersAfter = after
	} else {
		fmt.Fprintf(os.Stderr, "distributed: leadership after the restart: %v\n", err)
	}
	return nil
}

func runLoad(args []string) {
	f := flag.NewFlagSet("load", flag.ExitOnError)
	planPath := f.String("plan", "", "plan.json written by prepare")
	ca := f.String("ca", "", "CA certificate of the cluster")
	out := f.String("out", "", "output directory")
	label := f.String("label", "steady", "label of this run")
	duration := f.Duration("duration", time.Hour, "steady window")
	warmup := f.Duration("warmup", time.Minute, "warm-up before the steady window (same rate; judged separately)")
	shard := f.Int("shard", 0, "this generator's shard (0-based): it drives the projects p with p % shards == shard")
	shards := f.Int("shards", 1, "number of generator hosts")
	t0ms := f.Int64("t0-unix-ms", 0, "common start instant of every shard (0: 3 s from now)")
	epoch := f.Uint64("epoch", 0, "run number on this estate")
	killAt := f.Duration("kill-at", 0, "when set, this shard kills the node that leads most groups this long after T0 and restarts it (one shard only)")
	killDown := f.Duration("kill-down", 90*time.Second, "how long the killed node stays down before its restart")
	f.Parse(args)
	if *planPath == "" || *ca == "" || *out == "" || *shards < 1 || *shard < 0 || *shard >= *shards {
		fatalf("--plan, --ca, --out and a valid --shard/--shards are required")
	}
	raw, err := os.ReadFile(*planPath)
	must(err, "plan")
	var plan Plan
	must(json.Unmarshal(raw, &plan), "plan json")
	must(plan.Config.Check(), "plan config")
	if len(plan.Nodes) != 3 {
		fatalf("the plan has %d nodes, the gate has 3", len(plan.Nodes))
	}
	cfg := plan.Config
	cfg.Epoch = *epoch
	must(os.MkdirAll(*out, 0o755), "out dir")
	rawHF, _ := json.MarshalIndent(hostFacts("", runtime.GOMAXPROCS(0)), "", " ")
	must(os.WriteFile(filepath.Join(*out, "generator.json"), rawHF, 0o644), "generator host facts")
	l := &loader{plan: &plan, out: *out}
	l.tlsClient(*ca)

	rowsF, err := os.Create(filepath.Join(*out, "acks.csv.gz"))
	must(err, "rows file")
	l.rowsGz = gzip.NewWriter(rowsF)
	l.rowsBuf = bufio.NewWriterSize(l.rowsGz, 1<<20)
	fmt.Fprintln(l.rowsBuf, rowsHeader)
	ledgerPath := filepath.Join(*out, "ledger.bin")
	l.ledgerF, err = os.OpenFile(ledgerPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	must(err, "ledger")
	l.ledger = bufio.NewWriterSize(l.ledgerF, 1<<20)

	creds := map[int]string{}
	for _, s := range plan.Sources {
		creds[s.Project] = s.Credential
	}
	projects := make([]*Project, cfg.Projects)
	fmt.Fprintf(os.Stderr, "distributed: shard %d/%d building its projects (%d series each)\n", *shard, *shards, cfg.SeriesPerProject())
	var bw sync.WaitGroup
	for p := range projects {
		if p%*shards != *shard {
			continue
		}
		bw.Add(1)
		go func() { defer bw.Done(); projects[p] = NewProject(cfg, p) }()
	}
	bw.Wait()
	var atStart map[string]int
	if *killAt > 0 {
		if atStart, err = leadership(&plan); err != nil {
			fatalf("leadership at the start: %v", err)
		}
	}

	total := *warmup + *duration
	l.t0 = time.Now().Add(3 * time.Second)
	if *t0ms != 0 {
		l.t0 = time.UnixMilli(*t0ms)
		if time.Until(l.t0) < 0 {
			fatalf("--t0-unix-ms is in the past")
		}
	}
	var kill *KillRecord
	var killMu sync.Mutex
	var killDone chan struct{}
	if *killAt > 0 {
		killDone = make(chan struct{})
		time.AfterFunc(time.Until(l.t0.Add(*killAt)), func() {
			defer close(killDone)
			rec := &KillRecord{AtS: killAt.Seconds(), DownS: killDown.Seconds()}
			if err := killMostLeading(&plan, *killDown, rec); err != nil {
				fatalf("%v", err)
			}
			killMu.Lock()
			kill = rec
			killMu.Unlock()
		})
	}
	var sched sync.WaitGroup
	for p, pj := range projects {
		if pj == nil {
			continue
		}
		sched.Add(1)
		phase := time.Duration(int64(cfg.Window) * int64(p) / int64(cfg.Projects))
		go func() {
			defer sched.Done()
			for j := 0; ; j++ {
				built := l.t0.Add(phase + time.Duration(j)*cfg.Window)
				if built.Sub(l.t0) >= total {
					return
				}
				time.Sleep(time.Until(built))
				batches := pj.Window(j, built.Add(-cfg.Window))
				m := len(batches)
				for k, pr := range batches {
					at := built.Add(time.Duration(int64(cfg.Window) * int64(k) / int64(m)))
					if at.Sub(l.t0) >= total {
						break
					}
					l.wg.Add(1)
					time.AfterFunc(time.Until(at), func() { l.send(pr, at, creds[pr.Project]) })
				}
			}
		}()
	}
	tick := time.NewTicker(30 * time.Second)
	doneSched := make(chan struct{})
	go func() { sched.Wait(); close(doneSched) }()
loop:
	for {
		select {
		case <-tick.C:
			l.mu.Lock()
			l.rowsBuf.Flush()
			l.rowsGz.Flush()
			l.ledger.Flush()
			l.mu.Unlock()
			fmt.Fprintf(os.Stderr, "distributed: t=%4.0fs sent=%d ok=%d refused=%d transport=%d shed=%d retried=%d inflight=%d\n", time.Since(l.t0).Seconds(), l.sent.Load(), l.ok.Load(), l.refused.Load(), l.transport.Load(), l.shed.Load(), l.retriedRequests.Load(), l.inflight.Load())
		case <-doneSched:
			break loop
		}
	}
	tick.Stop()
	time.Sleep(time.Until(l.t0.Add(total)))
	l.wg.Wait()
	end := time.Now()
	// A run whose time ran out while the killed node was still down ends only when the restart answered: whatever follows (the
	// read-back) must meet three ready members.
	if killDone != nil {
		select {
		case <-killDone:
		case <-time.After(15 * time.Minute):
			fatalf("the kill -9 restart did not answer within 15 minutes")
		}
	}

	l.mu.Lock()
	l.rowsBuf.Flush()
	l.rowsGz.Close()
	rowsF.Close()
	l.ledger.Flush()
	l.ledgerF.Close()
	l.mu.Unlock()
	ledgerSum := sha256.New()
	lf, err := os.Open(ledgerPath)
	must(err, "ledger reopen")
	_, err = io.Copy(ledgerSum, lf)
	must(err, "ledger digest")
	lf.Close()

	sum := LoadSummary{Label: *label, Shard: *shard, Shards: *shards, Config: cfg, T0UnixMS: l.t0.UnixMilli(), EndUnixMS: end.UnixMilli(), WarmupS: warmup.Seconds(), DurationS: duration.Seconds(),
		Sent: l.sent.Load(), Acked: l.ok.Load(), Refused: l.refused.Load(), RefusedByCode: map[int]int64{}, Transport: l.transport.Load(), Shed: l.shed.Load(), MaxInFlight: l.maxInFl.Load(),
		Retried: l.retriedRequests.Load(), Attempts: l.attemptsTotal.Load(), Lookups: l.lookups.Load(), LookupHits: l.lookupHits.Load(), LookupMisses: l.lookupMisses.Load(), AckedByNode: map[int]int64{},
		RecordsSent: map[string]int64{}, RecordsAcked: map[string]int64{}, EncodedBytes: l.bytesSent.Load(), Window: cfg.Window.String(), RowsFile: "acks.csv.gz", LedgerFile: filepath.Base(ledgerPath),
		LedgerSHA256: hex.EncodeToString(ledgerSum.Sum(nil)), LedgerBatches: l.ackedBatches.Load(), GeneratorCPUs: runtime.GOMAXPROCS(0), LeadersAtStart: atStart, PlannedKillAtS: killAt.Seconds()}
	l.refusedBy.Range(func(k, v any) bool { sum.RefusedByCode[k.(int)] = v.(*atomic.Int64).Load(); return true })
	for n := 1; n <= 3; n++ {
		sum.AckedByNode[n] = l.ackedBy[n].Load()
	}
	for k := range 256 {
		if n := l.recSent[k].Load(); n > 0 {
			sum.RecordsSent[kindName(byte(k))] = n
			sum.RecordsAcked[kindName(byte(k))] = l.recAcked[k].Load()
		}
	}
	sum.BatchesPerSec = float64(sum.Sent) / total.Seconds()
	killMu.Lock()
	sum.Kill = kill
	killMu.Unlock()
	rawSum, _ := json.MarshalIndent(sum, "", " ")
	must(os.WriteFile(filepath.Join(*out, "load-summary.json"), rawSum, 0o644), "summary")
	fmt.Fprintf(os.Stderr, "distributed: shard %d load done: sent=%d ok=%d refused=%d transport=%d shed=%d retried=%d\n", *shard, sum.Sent, sum.Acked, sum.Refused, sum.Transport, sum.Shed, sum.Retried)
}

// readRows decodes an acks.csv.gz.
func readRows(path string) ([]AckRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	var rows []AckRow
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	first := true
	for sc.Scan() {
		if first {
			first = false
			if sc.Text() != rowsHeader {
				return nil, fmt.Errorf("unexpected rows header")
			}
			continue
		}
		var r AckRow
		n, _ := fmt.Sscanf(sc.Text(), "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%s", &r.StartUS, &r.SchedUS, &r.LatencyUS, &r.LateUS, &r.Status, &r.Project, &r.Records, &r.Bytes, &r.Slot, &r.Attempts, &r.Node, &r.Err)
		if n < 11 {
			return nil, fmt.Errorf("bad row %q", sc.Text())
		}
		rows = append(rows, r)
	}
	return rows, sc.Err()
}

// percentile is the nearest-rank percentile of a sorted slice (p in (0,1]).
func percentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(p*float64(len(sorted)) + 0.999999999)
	rank = min(max(rank, 1), len(sorted))
	return sorted[rank-1]
}

func sortInts(v []int64) { sort.Slice(v, func(i, j int) bool { return v[i] < v[j] }) }

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

const (
	maxInFlight = 6000 // beyond this a request is shed and counted: the generator never blocks (open loop)
	rowsHeader  = "start_us,sched_us,latency_us,late_us,status,project,records,bytes,err"
)

// AckRow is one request: its send start (relative to T0), how long it waited after its scheduled instant, the latency to the product's
// durable receipt and its outcome. Numbers and closed vocabulary only.
type AckRow struct {
	StartUS, SchedUS  int64
	LatencyUS, LateUS int64
	Status            int // HTTP status; 0 = transport failure or timeout, -1 = shed by the generator
	Project           int
	Records           int
	Bytes             int
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
	refusedBy                          sync.Map // status -> *atomic.Int64
	recSent, recAcked                  [256]atomic.Int64
	bytesSent                          atomic.Int64
	ackedBatches                       atomic.Int64
}

func (l *loader) tlsClient(caPath string) {
	pem, err := os.ReadFile(caPath)
	must(err, "ca")
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		fatalf("ca holds no certificate")
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, MaxIdleConns: 2048, MaxIdleConnsPerHost: 2048, IdleConnTimeout: 90 * time.Second,
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, ResponseHeaderTimeout: 30 * time.Second, DisableCompression: true}
	l.client = &http.Client{Transport: tr, Timeout: 40 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (l *loader) recordRow(r AckRow) {
	l.mu.Lock()
	fmt.Fprintf(l.rowsBuf, "%d,%d,%d,%d,%d,%d,%d,%d,%s\n", r.StartUS, r.SchedUS, r.LatencyUS, r.LateUS, r.Status, r.Project, r.Records, r.Bytes, r.Err)
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

func (l *loader) send(pr Prepared, sched time.Time, cred string) {
	defer l.wg.Done()
	row := AckRow{SchedUS: sched.Sub(l.t0).Microseconds(), Project: pr.Project, Records: len(pr.Records), Bytes: len(pr.Body)}
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
	req, _ := http.NewRequest(http.MethodPost, "https://"+l.plan.Addr+"/ingest/v1/batches", bytes.NewReader(pr.Body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("User-Agent", "soundpost-overhead-singlehost")
	t0 := time.Now()
	row.StartUS, row.LateUS = t0.Sub(l.t0).Microseconds(), t0.Sub(sched).Microseconds()
	resp, err := l.client.Do(req)
	var body []byte
	if err == nil {
		body, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
	}
	row.LatencyUS = time.Since(t0).Microseconds()
	switch {
	case err != nil:
		row.Status, row.Err = 0, "transport"
		l.transport.Add(1)
	case resp.StatusCode != http.StatusOK:
		row.Status, row.Err = resp.StatusCode, "refused"
		l.refused.Add(1)
		c, _ := l.refusedBy.LoadOrStore(resp.StatusCode, new(atomic.Int64))
		if n := c.(*atomic.Int64).Add(1); n <= 3 {
			// the body of a refusal is the product's closed fault document (code, retryable, safe detail): never record content.
			fmt.Fprintf(os.Stderr, "singlehost: refusal %d #%d: %.300s\n", resp.StatusCode, n, body)
		}
	default:
		var rc model.Receipt
		if model.StrictJSON(body, &rc) != nil || rc.Version == 0 || rc.BatchID != pr.ID {
			row.Status, row.Err = resp.StatusCode, "bad_receipt"
			l.refused.Add(1)
			break
		}
		row.Status = 200
		l.ok.Add(1)
		l.ackedBatches.Add(1)
		for _, m := range pr.Records {
			l.recAcked[m.Kind].Add(1)
		}
		l.ledgerEntry(pr, rc)
	}
	l.recordRow(row)
}

// LoadSummary is the generator's own account of a run.
type LoadSummary struct {
	Label         string           `json:"label"`
	Config        Config           `json:"config"`
	T0UnixMS      int64            `json:"t0_unix_ms"`
	EndUnixMS     int64            `json:"end_unix_ms"`
	WarmupS       float64          `json:"warmup_s"`
	DurationS     float64          `json:"steady_s"`
	Sent          int64            `json:"requests_sent"`
	Acked         int64            `json:"requests_acked"`
	Refused       int64            `json:"requests_refused"`
	RefusedByCode map[int]int64    `json:"refused_by_status"`
	Transport     int64            `json:"requests_transport_failed"`
	Shed          int64            `json:"requests_shed_by_generator"`
	MaxInFlight   int64            `json:"max_in_flight"`
	RecordsSent   map[string]int64 `json:"records_sent_by_kind"`
	RecordsAcked  map[string]int64 `json:"records_acked_by_kind"`
	EncodedBytes  int64            `json:"encoded_bytes_sent"`
	Kill9AtS      float64          `json:"kill9_at_s,omitempty"`
	Kill9Restart  *Event           `json:"kill9_restart,omitempty"`
	Window        string           `json:"flush_window"`
	GeneratorHost string           `json:"generator_host_class"`
	GeneratorCPUs int              `json:"generator_gomaxprocs"`
	BatchesPerSec float64          `json:"batches_per_s_mean"`
	RowsFile      string           `json:"rows_file"`
	LedgerFile    string           `json:"ledger_file"`
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

func (l *loader) callControl(path string) (Event, error) {
	req, _ := http.NewRequest(http.MethodPost, "http://"+l.plan.Control+path, nil)
	req.Header.Set("X-Harness-Token", l.plan.ControlToken)
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return Event{}, err
	}
	defer resp.Body.Close()
	var e Event
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || json.Unmarshal(raw, &e) != nil {
		return e, fmt.Errorf("control %s: status %d", path, resp.StatusCode)
	}
	return e, nil
}

func runLoad(args []string) {
	f := flag.NewFlagSet("load", flag.ExitOnError)
	planPath := f.String("plan", "", "plan.json written by the server role")
	ca := f.String("ca", "", "CA certificate of the product")
	out := f.String("out", "", "output directory")
	label := f.String("label", "load", "label of this run (smoke, steady, kill9)")
	duration := f.Duration("duration", time.Hour, "steady window")
	warmup := f.Duration("warmup", time.Minute, "warm-up before the steady window (same rate; judged separately)")
	kill9At := f.Duration("kill9-at", 0, "when set, ask the server host to kill -9 the exact server PID this long after the start and restart it")
	epoch := f.Uint64("epoch", 0, "run number on this estate: a run that follows another on the same data directory (kill9) sends records and batches of its own")
	appendTo := f.String("append-ledger-to", "", "append the ACK ledger to this existing ledger instead of starting a new one")
	f.Parse(args)
	if *planPath == "" || *ca == "" || *out == "" {
		fatalf("--plan, --ca and --out are required")
	}
	raw, err := os.ReadFile(*planPath)
	must(err, "plan")
	var plan Plan
	must(json.Unmarshal(raw, &plan), "plan json")
	must(plan.Config.Check(), "plan config")
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
	if *appendTo != "" {
		ledgerPath = *appendTo
	}
	l.ledgerF, err = os.OpenFile(ledgerPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	must(err, "ledger")
	l.ledger = bufio.NewWriterSize(l.ledgerF, 1<<20)

	creds := map[int]string{}
	for _, s := range plan.Sources {
		creds[s.Project] = s.Credential
	}
	projects := make([]*Project, cfg.Projects)
	fmt.Fprintf(os.Stderr, "singlehost: building %d projects (%d series each)\n", cfg.Projects, cfg.SeriesPerProject())
	var bw sync.WaitGroup
	for p := range projects {
		bw.Add(1)
		go func() { defer bw.Done(); projects[p] = NewProject(cfg, p) }()
	}
	bw.Wait()

	total := *warmup + *duration
	l.t0 = time.Now().Add(3 * time.Second)
	var kill *Event
	var killMu sync.Mutex
	var killDone chan struct{} // closed when the kill -9 restart answered (the node is ready again)
	if *kill9At > 0 {
		killDone = make(chan struct{})
		time.AfterFunc(time.Until(l.t0.Add(*kill9At)), func() {
			defer close(killDone)
			e, err := l.callControl("/restart?mode=kill9")
			if err != nil {
				fatalf("kill -9 restart: %v", err)
			}
			killMu.Lock()
			kill = &e
			killMu.Unlock()
		})
	}
	var sched sync.WaitGroup
	for p, pj := range projects {
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
			fmt.Fprintf(os.Stderr, "singlehost: t=%4.0fs sent=%d ok=%d refused=%d transport=%d shed=%d inflight=%d\n", time.Since(l.t0).Seconds(), l.sent.Load(), l.ok.Load(), l.refused.Load(), l.transport.Load(), l.shed.Load(), l.inflight.Load())
		case <-doneSched:
			break loop
		}
	}
	tick.Stop()
	time.Sleep(time.Until(l.t0.Add(total)))
	l.wg.Wait()
	end := time.Now()
	// A run whose time ran out while the killed node was still restarting ends only when the restart answered: whatever follows
	// (the read-back) must meet a node that is ready, not one the generator left behind in its start-up gate.
	if killDone != nil {
		if err := awaitKill9Restart(killDone, 10*time.Minute); err != nil {
			fatalf("%v", err)
		}
	}

	l.mu.Lock()
	l.rowsBuf.Flush()
	l.rowsGz.Close()
	rowsF.Close()
	l.ledger.Flush()
	l.ledgerF.Close()
	l.mu.Unlock()

	sum := LoadSummary{Label: *label, Config: cfg, T0UnixMS: l.t0.UnixMilli(), EndUnixMS: end.UnixMilli(), WarmupS: warmup.Seconds(), DurationS: duration.Seconds(),
		Sent: l.sent.Load(), Acked: l.ok.Load(), Refused: l.refused.Load(), RefusedByCode: map[int]int64{}, Transport: l.transport.Load(), Shed: l.shed.Load(), MaxInFlight: l.maxInFl.Load(),
		RecordsSent: map[string]int64{}, RecordsAcked: map[string]int64{}, EncodedBytes: l.bytesSent.Load(), Window: cfg.Window.String(), RowsFile: "acks.csv.gz", LedgerFile: filepath.Base(ledgerPath), Kill9AtS: kill9At.Seconds()}
	l.refusedBy.Range(func(k, v any) bool { sum.RefusedByCode[k.(int)] = v.(*atomic.Int64).Load(); return true })
	for k := 0; k < 256; k++ {
		if n := l.recSent[k].Load(); n > 0 {
			sum.RecordsSent[kindName(byte(k))] = n
			sum.RecordsAcked[kindName(byte(k))] = l.recAcked[k].Load()
		}
	}
	sum.BatchesPerSec = float64(sum.Sent) / total.Seconds()
	killMu.Lock()
	sum.Kill9Restart = kill
	killMu.Unlock()
	rawSum, _ := json.MarshalIndent(sum, "", " ")
	must(os.WriteFile(filepath.Join(*out, "load-summary.json"), rawSum, 0o644), "summary")
	fmt.Fprintf(os.Stderr, "singlehost: load done: sent=%d ok=%d refused=%d transport=%d shed=%d\n", sum.Sent, sum.Acked, sum.Refused, sum.Transport, sum.Shed)
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
		n, _ := fmt.Sscanf(sc.Text(), "%d,%d,%d,%d,%d,%d,%d,%d,%s", &r.StartUS, &r.SchedUS, &r.LatencyUS, &r.LateUS, &r.Status, &r.Project, &r.Records, &r.Bytes, &r.Err)
		if n < 8 {
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
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

func sortedLatencies(rows []AckRow, keep func(AckRow) bool) []int64 {
	var v []int64
	for _, r := range rows {
		if r.Status == 200 && keep(r) {
			v = append(v, r.LatencyUS)
		}
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v
}

// awaitKill9Restart waits until done is closed (the kill -9 restart answered, so the node is ready) for at most limit.
func awaitKill9Restart(done <-chan struct{}, limit time.Duration) error {
	select {
	case <-done:
		return nil
	case <-time.After(limit):
		return fmt.Errorf("the kill -9 restart did not answer within %s", limit)
	}
}

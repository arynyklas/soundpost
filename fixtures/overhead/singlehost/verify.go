// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

// ackedBatch is one ledger entry: a batch the product answered with a durable receipt, as the ACK said it.
type ackedBatch struct {
	Project int
	Slot    uint16
	ID      model.ID
	Hash    model.Hash
	Cursor  model.Cursor
	Records []RecMeta
}

const ledgerHead = 1 + 2 + 2 + 16 + 32 + 16 + 8

// readLedger decodes ledger.bin. A truncated final entry (a generator killed mid-write) is an error: the ledger is never repaired.
func readLedger(path string) ([]ackedBatch, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	var out []ackedBatch
	var head [ledgerHead]byte
	var rec [1 + 16 + 8 + 16]byte
	for {
		if _, err := io.ReadFull(r, head[:]); err != nil {
			if err == io.EOF {
				return out, nil
			}
			return nil, fmt.Errorf("ledger header: %w", err)
		}
		b := ackedBatch{Project: int(head[0]), Slot: binary.BigEndian.Uint16(head[1:])}
		n := int(binary.BigEndian.Uint16(head[3:]))
		copy(b.ID[:], head[5:])
		copy(b.Hash[:], head[21:])
		copy(b.Cursor.Group[:], head[53:])
		b.Cursor.Index = model.Uint64(binary.BigEndian.Uint64(head[69:]))
		b.Records = make([]RecMeta, n)
		for i := range b.Records {
			if _, err := io.ReadFull(r, rec[:]); err != nil {
				return nil, fmt.Errorf("ledger record: %w", err)
			}
			m := &b.Records[i]
			m.Kind = rec[0]
			copy(m.ID[:], rec[1:])
			m.TS = int64(binary.BigEndian.Uint64(rec[17:]))
			copy(m.Aux[:], rec[25:])
		}
		out = append(out, b)
	}
}

// KindCheck is the read-back of one record kind.
type KindCheck struct {
	Acked   int64  `json:"acked_records"`
	Checked int64  `json:"checked_records"`
	Found   int64  `json:"found_records"`
	Missing int64  `json:"missing_records"`
	Extra   int64  `json:"extra_records_not_in_ledger"`
	Method  string `json:"method"`
}

// VerifyReport is the outcome of one verification pass after a restart.
type VerifyReport struct {
	Label                 string               `json:"label"`
	StartedUnixMS         int64                `json:"started_unix_ms"`
	ReadyWaitMS           int64                `json:"waited_for_readyz_ms"`
	DurationS             float64              `json:"duration_s"`
	LedgerBatches         int                  `json:"ledger_batches"`
	LedgerRecords         int64                `json:"ledger_records"`
	ReceiptsChecked       int64                `json:"receipts_checked"`
	ReceiptsMatching      int64                `json:"receipts_matching_the_ack"`
	ReceiptsNotFound      int64                `json:"receipts_not_found"`
	ReceiptsMismatch      int64                `json:"receipts_with_other_hash_or_cursor"`
	ReceiptErrors         int64                `json:"receipt_lookup_errors"`
	RecordsInBatchesLost  int64                `json:"records_in_batches_without_matching_receipt"`
	UnavailableAnswers    int64                `json:"unavailable_answers"`
	FirstUnavailableMS    int64                `json:"first_unavailable_answer_ms_after_start"`
	LastUnavailableMS     int64                `json:"last_unavailable_answer_ms_after_start"`
	UnavailableSamples    []string             `json:"unavailable_answer_samples,omitempty"`
	Kinds                 map[string]KindCheck `json:"kinds"`
	MissingAckedRecords   int64                `json:"missing_acked_records"`
	MissingAckedBatches   int64                `json:"missing_acked_batches"`
	QueryErrors           []string             `json:"query_errors,omitempty"`
	FirstMissingBatchIDs  []string             `json:"first_missing_batch_ids,omitempty"`
	Method                []string             `json:"method"`
	TraceSampleEvery      int                  `json:"trace_sample_every"`
	ControlRestartContext *Event               `json:"restart,omitempty"`
}

type verifier struct {
	plan   *Plan
	client *http.Client
	cfg    Config
	creds  map[int]string
	tokens map[int]string
	began  time.Time

	unavailMu    sync.Mutex
	unavailable  int64
	unavailFirst int64
	unavailLast  int64
	unavailBody  []string
}

// noteUnavailable records one 503/429 answer of the product: how many there were, the span of time since the
// verifier started in which they came and the first few answer bodies.
func (v *verifier) noteUnavailable(status int, body []byte) {
	ms := time.Since(v.began).Milliseconds()
	v.unavailMu.Lock()
	defer v.unavailMu.Unlock()
	if v.unavailable == 0 {
		v.unavailFirst = ms
	}
	v.unavailable++
	v.unavailLast = ms
	if len(v.unavailBody) < 5 {
		v.unavailBody = append(v.unavailBody, fmt.Sprintf("%d %s", status, strings.TrimSpace(string(body[:min(len(body), 300)]))))
	}
}

func (v *verifier) post(path, bearer string, body any) (int, []byte, error) {
	raw, _ := json.Marshal(body)
	var lastStatus int
	var last []byte
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		req, _ := http.NewRequest(http.MethodPost, "https://"+v.plan.Addr+path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := v.client.Do(req)
		if err == nil {
			out, rerr := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
			resp.Body.Close()
			if rerr == nil && resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusTooManyRequests {
				return resp.StatusCode, out, nil
			}
			lastStatus, last, lastErr = resp.StatusCode, out, rerr
			if rerr == nil {
				v.noteUnavailable(resp.StatusCode, out)
			}
		} else {
			lastErr = err
		}
		time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
	}
	return lastStatus, last, lastErr
}

// receipt looks the receipt of one ledger batch up. An answer that says "unavailable" or "try later" (503, 429)
// is the server not serving yet, not evidence about the batch: it is asked again for up to two minutes (post
// already retries a few times), and only an answer that stays unavailable counts against the batch.
func (v *verifier) receipt(b ackedBatch, pj *Project) (int, []byte, error) {
	deadline := time.Now().Add(2 * time.Minute)
	for {
		status, body, err := v.post("/ingest/v1/receipts", v.creds[b.Project], model.ReceiptRequest{Source: pj.Source, Producer: pj.Producer, RouteSlot: b.Slot, BatchID: b.ID, OriginalHash: b.Hash})
		if err == nil && status != http.StatusServiceUnavailable && status != http.StatusTooManyRequests || time.Now().After(deadline) {
			return status, body, err
		}
	}
}

func runVerify(args []string) {
	f := flag.NewFlagSet("verify", flag.ExitOnError)
	planPath := f.String("plan", "", "plan.json written by the server role")
	ca := f.String("ca", "", "CA certificate of the product")
	ledgerPath := f.String("ledger", "", "ledger.bin of the load runs to verify")
	out := f.String("out", "", "report file")
	label := f.String("label", "verify", "label of this pass")
	workers := f.Int("workers", 8, "parallel read-back requests")
	traceEvery := f.Int("trace-sample-every", 10, "read back every Nth trace of each project through the trace view (1 = all)")
	f.Parse(args)
	if *planPath == "" || *ca == "" || *ledgerPath == "" || *out == "" {
		fatalf("--plan, --ca, --ledger and --out are required")
	}
	raw, err := os.ReadFile(*planPath)
	must(err, "plan")
	var plan Plan
	must(json.Unmarshal(raw, &plan), "plan json")
	pem, err := os.ReadFile(*ca)
	must(err, "ca")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	v := &verifier{plan: &plan, cfg: plan.Config, creds: map[int]string{}, tokens: map[int]string{}}
	v.client = &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, MaxIdleConnsPerHost: 64, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, s := range plan.Sources {
		v.creds[s.Project] = s.Credential
	}
	for _, r := range plan.Readers {
		v.tokens[r.Org] = r.Token
	}
	readyWait, err := v.waitReady(10 * time.Minute)
	must(err, "the product is not ready")
	began := time.Now()
	v.began = began
	ledger, err := readLedger(*ledgerPath)
	must(err, "ledger")
	rep := VerifyReport{Label: *label, StartedUnixMS: began.UnixMilli(), ReadyWaitMS: readyWait.Milliseconds(), LedgerBatches: len(ledger), Kinds: map[string]KindCheck{}, TraceSampleEvery: *traceEvery,
		Method: []string{
			"receipts: every ACKed batch is looked up through POST /ingest/v1/receipts with its source credential and must answer the hash and cursor the ACK carried",
			"metrics: every ACKed sample is read back through POST /api/v1/query (PromQL range selector, org reader bearer, read fenced by the ACK cursors) and matched by series and timestamp",
			"logs: every ACKed log record is read back through POST /api/v1/query (LogQL) and matched by record id",
			"spans: every Nth trace of each project is read back through POST /api/v1/traces/view and its span count compared with the ACKed spans of that trace",
			"errors and job attempts have no read route that returns a raw record by id before background grouping: they are verified through their batch receipts only",
		}}
	for _, b := range ledger {
		rep.LedgerRecords += int64(len(b.Records))
	}

	// Phase A: receipts of every ACKed batch.
	lostBatch := make([]bool, len(ledger))
	var next, checked, match, notFound, mismatch, errs atomic.Int64
	var wg sync.WaitGroup
	var mu sync.Mutex
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(ledger) {
					return
				}
				b := ledger[i]
				pj := NewProjectIdentity(v.cfg, b.Project)
				status, body, err := v.receipt(b, pj)
				checked.Add(1)
				switch {
				case err != nil:
					errs.Add(1)
					lostBatch[i] = true
				case status == http.StatusOK:
					var rc model.Receipt
					if model.StrictJSON(body, &rc) != nil || rc.BatchID != b.ID {
						errs.Add(1)
						lostBatch[i] = true
					} else if rc.Hash != b.Hash || rc.Cursor != b.Cursor {
						mismatch.Add(1)
						lostBatch[i] = true
					} else {
						match.Add(1)
					}
				default:
					notFound.Add(1)
					lostBatch[i] = true
					mu.Lock()
					if len(rep.FirstMissingBatchIDs) < 10 {
						rep.FirstMissingBatchIDs = append(rep.FirstMissingBatchIDs, fmt.Sprintf("%s (http %d)", b.ID, status))
					}
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	rep.ReceiptsChecked, rep.ReceiptsMatching, rep.ReceiptsNotFound, rep.ReceiptsMismatch, rep.ReceiptErrors = checked.Load(), match.Load(), notFound.Load(), mismatch.Load(), errs.Load()
	fmt.Fprintf(os.Stderr, "singlehost: verify receipts: checked=%d match=%d notfound=%d mismatch=%d errors=%d\n", rep.ReceiptsChecked, rep.ReceiptsMatching, rep.ReceiptsNotFound, rep.ReceiptsMismatch, rep.ReceiptErrors)

	// Phase B: record read-back, per project.
	perProject := make([][]int, v.cfg.Projects)
	for i, b := range ledger {
		perProject[b.Project] = append(perProject[b.Project], i)
	}
	kinds := map[byte]*KindCheck{'m': {Method: "PromQL range selector, matched by timestamp and series"}, 'l': {Method: "LogQL stream query, matched by record id"}, 's': {Method: "trace view span count, every Nth trace"}, 'e': {Method: "batch receipt only"}, 'j': {Method: "batch receipt only"}}
	var kmu sync.Mutex
	recordLost := int64(0)
	var qerrs []string
	addErr := func(s string) {
		kmu.Lock()
		if len(qerrs) < 20 {
			qerrs = append(qerrs, s)
		}
		kmu.Unlock()
	}
	var pnext atomic.Int64
	var pwg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		pwg.Add(1)
		go func() {
			defer pwg.Done()
			for {
				p := int(pnext.Add(1)) - 1
				if p >= v.cfg.Projects {
					return
				}
				res := v.readBackProject(p, ledger, perProject[p], lostBatch, *traceEvery, addErr)
				kmu.Lock()
				for k, c := range res.kinds {
					t := kinds[k]
					t.Acked += c.Acked
					t.Checked += c.Checked
					t.Found += c.Found
					t.Missing += c.Missing
					t.Extra += c.Extra
				}
				recordLost += res.lost
				kmu.Unlock()
			}
		}()
	}
	pwg.Wait()
	for k, c := range kinds {
		rep.Kinds[kindName(k)] = *c
	}
	for i, b := range ledger {
		if lostBatch[i] {
			rep.MissingAckedBatches++
			rep.RecordsInBatchesLost += int64(len(b.Records))
		}
	}
	rep.MissingAckedRecords = recordLost
	rep.QueryErrors = qerrs
	v.unavailMu.Lock()
	rep.UnavailableAnswers, rep.FirstUnavailableMS, rep.LastUnavailableMS, rep.UnavailableSamples = v.unavailable, v.unavailFirst, v.unavailLast, v.unavailBody
	v.unavailMu.Unlock()
	rep.DurationS = time.Since(began).Seconds()
	raw, _ = json.MarshalIndent(rep, "", " ")
	must(os.WriteFile(*out, raw, 0o644), "report")
	fmt.Fprintf(os.Stderr, "singlehost: verify done: missing acked batches=%d missing acked records=%d query errors=%d in %.0f s\n", rep.MissingAckedBatches, rep.MissingAckedRecords, len(qerrs), rep.DurationS)
}

// NewProjectIdentity is the identity of project p without the generator state (no series tables).
func NewProjectIdentity(cfg Config, p int) *Project {
	perOrg := cfg.Projects / cfg.Orgs
	return &Project{Index: p, OrgIndex: p / perOrg, Org: ident(cfg.Seed, "org", p/perOrg), Project: ident(cfg.Seed, "project", p), Source: ident(cfg.Seed, "source", p), Producer: ident(cfg.Seed, "producer", p)}
}

type projectResult struct {
	kinds map[byte]*KindCheck
	lost  int64 // acked records not demonstrably present (records of batches without receipt + records missing in a read-back)
}

// registry is the pinned query profile of each language and its first feature set, read from the product.
func (v *verifier) profile(token, language string) (id, featureSet string, err error) {
	req, _ := http.NewRequest(http.MethodGet, "https://"+v.plan.Addr+"/api/v1/query/profiles", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := v.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var reg httpapi.ProfileRegistryResponse
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		return "", "", err
	}
	var ids []string
	for _, p := range reg.Profiles {
		if p.Language == language && len(p.FeatureSets) > 0 {
			ids = append(ids, p.ID)
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return "", "", fmt.Errorf("no %s profile", language)
	}
	for _, p := range reg.Profiles {
		if p.ID == ids[len(ids)-1] {
			return p.ID, p.FeatureSets[0].ID, nil
		}
	}
	return "", "", fmt.Errorf("no %s profile", language)
}

func (v *verifier) readBackProject(p int, ledger []ackedBatch, idx []int, lostBatch []bool, traceEvery int, addErr func(string)) projectResult {
	res := projectResult{kinds: map[byte]*KindCheck{'m': {}, 'l': {}, 's': {}, 'e': {}, 'j': {}}}
	pj := NewProject(v.cfg, p)
	token := v.tokens[pj.OrgIndex]
	type exp struct {
		batch int
		meta  RecMeta
	}
	metrics := map[int64]exp{}
	logs := map[model.ID]exp{}
	traces := map[model.ID][]exp{}
	var traceOrder []model.ID
	fence := map[model.ID]model.Cursor{}
	var lo, hi int64 = 1 << 62, 0
	for _, bi := range idx {
		b := ledger[bi]
		if c, ok := fence[b.Cursor.Group]; !ok || b.Cursor.Index > c.Index {
			fence[b.Cursor.Group] = b.Cursor
		}
		for _, m := range b.Records {
			res.kinds[m.Kind].Acked++
			if lostBatch[bi] {
				res.lost++ // the batch itself has no matching receipt: all of its records count as missing
			}
			lo, hi = min(lo, m.TS), max(hi, m.TS)
			switch m.Kind {
			case 'm':
				metrics[m.TS] = exp{bi, m}
			case 'l':
				logs[m.ID] = exp{bi, m}
			case 's':
				var tr model.ID
				copy(tr[:], m.Aux[:])
				if _, seen := traces[tr]; !seen {
					traceOrder = append(traceOrder, tr)
				}
				traces[tr] = append(traces[tr], exp{bi, m})
			}
		}
	}
	if len(idx) == 0 {
		return res
	}
	var cursors []model.Cursor
	for _, c := range fence {
		cursors = append(cursors, c)
	}
	sort.Slice(cursors, func(i, j int) bool { return cursors[i].Group.String() < cursors[j].Group.String() })
	lost := func(e exp) bool { return lostBatch[e.batch] }
	base := func(language, profileID, featureSet, expr string, instant bool) map[string]any {
		ev := map[string]any{"instant": true, "time": strconv.FormatInt(hi+int64(time.Minute), 10), "start": "0", "end": "0", "step": "0"}
		if !instant {
			ev = map[string]any{"instant": false, "time": "0", "start": strconv.FormatInt(lo-1e9, 10), "end": strconv.FormatInt(hi+1e9, 10), "step": "1000000000"}
		}
		return map[string]any{"org": pj.Org.String(), "language": language, "profile": profileID, "feature_set": featureSet, "expression": expr, "evaluation": ev, "projects": []string{pj.Project.String()},
			"budget": map[string]any{"timeout_ns": "0", "memory_bytes": "0", "max_returned": "0"}, "allow_partial": false, "min_cursors": cursors}
	}

	// metrics
	if len(metrics) > 0 {
		pid, fs, err := v.profile(token, "promql")
		if err != nil {
			addErr(fmt.Sprintf("project %d promql profile: %v", p, err))
		} else {
			rng := (hi-lo)/1e9 + 120
			status, body, err := v.post("/api/v1/query", token, base("promql", pid, fs, fmt.Sprintf(`{__name__=~"app_m.+"}[%ds]`, rng), true))
			var result query.Result
			switch {
			case err != nil || status != 200:
				addErr(fmt.Sprintf("project %d metric query: status %d err %v %.120s", p, status, err, body))
			case json.Unmarshal(body, &result) != nil || len(result.Projects) != 1 || result.Projects[0].Value == nil:
				addErr(fmt.Sprintf("project %d metric query: unreadable result", p))
			default:
				seen := map[int64]bool{}
				for _, s := range result.Projects[0].Value.Matrix {
					for _, smp := range s.Samples {
						seen[int64(smp.Time)] = true
					}
				}
				for ts, e := range metrics {
					c := res.kinds['m']
					c.Checked++
					if seen[ts] {
						c.Found++
					} else {
						c.Missing++
						if !lost(e) {
							res.lost++
						}
					}
				}
				res.kinds['m'].Extra += int64(len(seen)) - res.kinds['m'].Found
				if c := result.Projects[0].Completeness; c != query.CompletenessComplete {
					addErr(fmt.Sprintf("project %d metric query completeness %s", p, c))
				}
			}
		}
	}

	// logs
	if len(logs) > 0 {
		pid, fs, err := v.profile(token, "logql")
		if err != nil {
			addErr(fmt.Sprintf("project %d logql profile: %v", p, err))
		} else {
			q := base("logql", pid, fs, `{route=~".+"}`, false)
			q["log_order"], q["log_limit"] = "forward", strconv.Itoa(len(logs)*2+1000)
			status, body, err := v.post("/api/v1/query", token, q)
			var result query.Result
			switch {
			case err != nil || status != 200:
				addErr(fmt.Sprintf("project %d log query: status %d err %v %.120s", p, status, err, body))
			case json.Unmarshal(body, &result) != nil || len(result.Projects) != 1 || result.Projects[0].Value == nil:
				addErr(fmt.Sprintf("project %d log query: unreadable result", p))
			default:
				seen := map[model.ID]bool{}
				for _, s := range result.Projects[0].Value.Streams {
					for _, e := range s.Entries {
						seen[e.ID] = true
					}
				}
				for id, e := range logs {
					c := res.kinds['l']
					c.Checked++
					if seen[id] {
						c.Found++
					} else {
						c.Missing++
						if !lost(e) {
							res.lost++
						}
					}
				}
				res.kinds['l'].Extra += int64(len(seen)) - res.kinds['l'].Found
			}
		}
	}

	// spans: every Nth trace
	for i, tr := range traceOrder {
		if traceEvery < 1 || i%traceEvery != 0 {
			continue
		}
		exps := traces[tr]
		var tlo, thi int64 = 1 << 62, 0
		for _, e := range exps {
			tlo, thi = min(tlo, e.meta.TS), max(thi, e.meta.TS)
		}
		body := map[string]any{"org": pj.Org.String(), "project": pj.Project.String(), "trace": tr.String(), "window": map[string]any{"start": strconv.FormatInt(tlo-int64(time.Hour), 10), "end": strconv.FormatInt(thi+int64(time.Hour), 10)}}
		status, raw, err := v.post("/api/v1/traces/view", token, body)
		var view httpapi.TraceView
		found := 0
		if err == nil && status == 200 && json.Unmarshal(raw, &view) == nil && view.Path != nil {
			found = view.Path.SpanCount
		} else {
			addErr(fmt.Sprintf("project %d trace view: status %d err %v %.100s", p, status, err, raw))
		}
		c := res.kinds['s']
		c.Checked += int64(len(exps))
		c.Found += int64(min(found, len(exps)))
		if found < len(exps) {
			c.Missing += int64(len(exps) - found)
			for _, e := range exps[:len(exps)-found] {
				if !lost(e) {
					res.lost++
				}
			}
		}
	}
	return res
}

// summaryLine is used by the summarize role to print the verification report in one line.
func (r VerifyReport) summaryLine() string {
	var parts []string
	for _, k := range []string{"metric", "log", "span", "error", "job_attempt"} {
		if c, ok := r.Kinds[k]; ok {
			parts = append(parts, fmt.Sprintf("%s acked=%d checked=%d missing=%d", k, c.Acked, c.Checked, c.Missing))
		}
	}
	return fmt.Sprintf("receipts %d/%d matching; %s; missing acked records %d", r.ReceiptsMatching, r.ReceiptsChecked, strings.Join(parts, "; "), r.MissingAckedRecords)
}

// waitReady polls GET /readyz until the product answers 200 and returns how long that took. The read-back starts on a node that
// says it is ready: every answer of the retryable kind (503, 429) the read-back then receives is counted in the report
// (unavailable_answers) and is a defect of the product, not of the order of events.
func (v *verifier) waitReady(limit time.Duration) (time.Duration, error) {
	began := time.Now()
	for {
		resp, err := v.client.Get("https://" + v.plan.Addr + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return time.Since(began), nil
			}
		}
		if time.Since(began) > limit {
			return time.Since(began), fmt.Errorf("/readyz did not answer 200 within %s", limit)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

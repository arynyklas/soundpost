// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

// Scenario `capacity-faults`: failed sync, slow apply and full disk, driven in process against real
// engines and real files under env.Work.
//
//   - failed sync and slow apply drive the committed replica journal (internal/replica: ready.wal,
//     fsync, Raft apply) through its exported fault hook replica.Config.Fault, which is called
//     immediately before the journal write and fsync ("wal_write", "wal_payload_write",
//     "wal_sync"). The state machine is a durable bbolt store of the drill (bbolt fsyncs every
//     transaction), so an acknowledgement means: journal fsynced, entry committed, entry applied
//     and committed to the machine.
//   - full disk drives the real application (internal/appcore: control, replicated storage, auth,
//     ingest over HTTPS, the retention worker) through storage.DiskMeter, the committed seam the
//     01.08 disk-pressure admission reads (the 80/90/95 gate).
//
// None of this is a failing or a full disk. A hook that returns an error before fsync, a meter that
// reports 95 % and a state machine that sleeps are injections at the seams the engine itself
// exposes; the real operating-system errors (EIO, ENOSPC) were not produced and the report says so.
// The pure verifiers (classifier, window check, receipt comparison, digests) are unit-tested in
// capacity_test.go.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/health"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/retention"
	"github.com/arynyklas/soundpost/internal/storage"
	bolt "go.etcd.io/bbolt"
)

func init() { register("capacity-faults", capacityFaults) }

// ---- pure verifiers (unit-tested) ----

// capClass is what a caller can tell apart about one answer.
type capClass string

const (
	capAck         capClass = "ack"
	capUnavailable capClass = "unavailable"
	capStale       capClass = "stale"
	capCapacity    capClass = "capacity"
	capTimeout     capClass = "timeout"
	capConflict    capClass = "conflict"
	capInvalid     capClass = "invalid"
	capUntyped     capClass = "untyped"
)

// capClassify reduces an error from the replica or storage layer to a class. Only the closed set
// the product defines (unavailable, stale, capacity, and the caller's own deadline) is a typed
// refusal; everything else (an arbitrary I/O error text) is untyped and fails the drill.
func capClassify(err error) capClass {
	if err == nil {
		return capAck
	}
	var f *model.Fault
	if errors.As(err, &f) {
		switch {
		case f.Code == model.Unavailable && f.SafeDetail == "capacity":
			return capCapacity
		case f.Code == model.Unavailable:
			return capUnavailable
		case f.Code == model.Stale:
			return capStale
		case f.Code == model.Timeout || f.Code == model.Cancelled:
			return capTimeout
		case f.Code == model.Conflict:
			return capConflict
		case f.Code == model.Invalid:
			return capInvalid
		}
		return capUntyped
	}
	switch {
	case errors.Is(err, replica.ErrUnavailable):
		return capUnavailable
	case errors.Is(err, replica.ErrStale):
		return capStale
	case errors.Is(err, replica.ErrConflict):
		return capConflict
	case errors.Is(err, replica.ErrInvalid):
		return capInvalid
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return capTimeout
	}
	return capUntyped
}

// typedRefusal reports whether the class is an acceptable "not acknowledged" answer under a fault.
func (c capClass) typedRefusal() bool {
	switch c {
	case capUnavailable, capStale, capCapacity, capTimeout:
		return true
	}
	return false
}

// capClassifyHTTP reduces an ingest HTTP answer. A refusal counts as typed only with its closed
// fault body and the Retry-After hint a client needs to retry.
func capClassifyHTTP(status int, retryAfter string, body []byte) capClass {
	if status == 200 {
		return capAck
	}
	var f struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(body, &f) != nil || f.Code == "" {
		return capUntyped
	}
	switch {
	case status == 503 && retryAfter != "":
		switch model.Code(f.Code) {
		case model.Unavailable:
			if f.Detail == "capacity" {
				return capCapacity
			}
			return capUnavailable
		case model.Stale:
			return capStale
		case model.Timeout, model.Cancelled:
			return capTimeout
		}
	case status == 409 && model.Code(f.Code) == model.Conflict:
		return capConflict
	case status == 400 && model.Code(f.Code) == model.Invalid:
		return capInvalid
	}
	return capUntyped
}

// capFaultText reduces an error body to its closed code and safe detail; nothing else of the body
// (request ids, tenant data) reaches a report.
func capFaultText(body []byte) string {
	var f struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(body, &f) != nil || f.Code == "" {
		return "unparsed"
	}
	return f.Code + "/" + f.Detail
}

// capOutcome is one write attempt made while a fault was active.
type capOutcome struct {
	ID     string
	Digest string
	Acked  bool
	Class  capClass
}

// capVerifyWindow checks every attempt made inside one fault window. With allowAck=false no
// attempt may have been acknowledged (a fault that must refuse everything). With allowAck=true an
// acknowledgement is legitimate only with full durability, which means the exact data must be
// retained after recovery. Every unacknowledged attempt must carry a typed refusal. An empty window
// fails: a fault that was never exercised proves nothing.
func capVerifyWindow(out []capOutcome, allowAck bool, retained map[string]string) error {
	if len(out) == 0 {
		return errors.New("fault window is empty: the fault was never exercised")
	}
	for _, o := range out {
		switch {
		case o.Acked && o.Class != capAck:
			return fmt.Errorf("%s is both acknowledged and refused (%s)", o.ID, o.Class)
		case o.Acked && !allowAck:
			return fmt.Errorf("%s was acknowledged while the fault required refusal", o.ID)
		case o.Acked:
			got, ok := retained[o.ID]
			if !ok {
				return fmt.Errorf("%s was acknowledged during the fault and is not retained", o.ID)
			}
			if got != o.Digest {
				return fmt.Errorf("%s was acknowledged during the fault and its retained data differs", o.ID)
			}
		case !o.Class.typedRefusal():
			return fmt.Errorf("%s was not acknowledged and its refusal is %q, not a typed refusal", o.ID, o.Class)
		}
	}
	return nil
}

// capReceipt is the identity of an acknowledgement.
type capReceipt struct {
	Group  string
	Index  uint64
	Digest string
}

// capSameReceipt is the retry contract: the same batch answers with the same receipt.
func capSameReceipt(first, again capReceipt) error {
	if first != again {
		return fmt.Errorf("repeat answered %s/%d, first answer was %s/%d (or the data differs)", again.Group, again.Index, first.Group, first.Index)
	}
	return nil
}

// capRecord is the semantic content of one telemetry record that a reader must retrieve.
type capRecord struct {
	ID    string `json:"id"`
	At    int64  `json:"at"`
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}

// capDigest is the digest of the exact semantic data of a batch: every record's identity, time,
// name and value, independent of order, with unambiguous field boundaries.
func capDigest(records []capRecord) string {
	sorted := append([]capRecord(nil), records...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	h := sha256.New()
	var buf [binary.MaxVarintLen64]byte
	text := func(s string) {
		n := binary.PutUvarint(buf[:], uint64(len(s)))
		h.Write(buf[:n])
		h.Write([]byte(s))
	}
	number := func(v uint64) {
		binary.BigEndian.PutUint64(buf[:8], v)
		h.Write(buf[:8])
	}
	number(uint64(len(sorted)))
	for _, r := range sorted {
		text(r.ID)
		number(uint64(r.At))
		text(r.Name)
		number(r.Value)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// capFold attributes the rows read back from a system to the batches that carried them. A batch
// none of whose records came back is absent; a batch with some missing is present with the digest
// of what is there, which then differs from the digest that was acknowledged.
func capFold(batches map[string][]string, rows map[string]capRecord) map[string]string {
	out := map[string]string{}
	for id, ids := range batches {
		var found []capRecord
		for _, rid := range ids {
			if r, ok := rows[rid]; ok {
				found = append(found, r)
			}
		}
		if len(found) > 0 {
			out[id] = capDigest(found)
		}
	}
	return out
}

// capProbe is one readiness probe made with a short deadline while a fault was active.
type capProbe struct {
	TimedOut bool
	Ready    bool
	Reason   string
}

func capProbeSummary(p []capProbe) (timedOut, ready, unready int) {
	for _, x := range p {
		switch {
		case x.TimedOut:
			timedOut++
		case x.Ready:
			ready++
		default:
			unready++
		}
	}
	return
}

// capRequireReason demands that readiness reported exactly the safe reason of the fault.
func capRequireReason(r health.Readiness, want health.Reason) error {
	if r.Ready {
		return fmt.Errorf("node reported ready while the fault was active (wanted %q)", want)
	}
	if r.Reason != want {
		return fmt.Errorf("readiness reported %q, wanted %q", r.Reason, want)
	}
	return nil
}

// ---- bookkeeping shared by the three parts ----

// capPart records one part's acknowledgements and refusals in its own ledger and in the scenario
// ledger, and every refusal in the outage timeline.
type capPart struct {
	rep  *Report
	name string
	led  *Ledger
}

func newCapPart(rep *Report, name string) *capPart {
	return &capPart{rep: rep, name: name, led: &Ledger{}}
}

func (p *capPart) ack(id string, r capReceipt, label string) error {
	a := Ack{ID: id, Group: r.Group, Index: r.Index, Digest: r.Digest, Label: p.name + ":" + label}
	if err := p.led.Record(a); err != nil {
		return err
	}
	return p.rep.Ledger().Record(a)
}

func (p *capPart) refuse(id string, class capClass, detail string) {
	a := Attempt{ID: id, Outcome: string(class), Detail: p.name + ": " + detail}
	p.led.Attempted(a)
	p.rep.Ledger().Attempted(a)
	p.rep.Timeline().Fail(p.name, id+" "+string(class))
}

func (p *capPart) require(name string, ok bool, detail string) error {
	return p.rep.Require(p.name+"."+name, ok, detail)
}

// reconcile compares the part's own ledger with data read back from the system.
func (p *capPart) reconcile(name string, retained map[string]string) error {
	rec, err := Reconcile(p.led, retained)
	if err != nil {
		return p.require(name, false, err.Error())
	}
	return p.require(name, true, fmt.Sprintf("%d acknowledged ids retained with identical semantic data, %d retained ids never acknowledged", rec.ExactMatches, len(rec.UnackedRetained)))
}

// ---- replica-layer nodes (failed sync, slow apply) ----

var errCapInjectedSync = errors.New("drill: injected journal sync failure")

// capSwitch is the fault function handed to replica.Config.Fault. It acts only at "wal_sync", the
// point immediately before the journal's fsync: it can delay (a slow disk) and/or refuse (a failed
// fsync). It never replaces the fsync itself: when it returns nil the real fsync runs.
type capSwitch struct {
	mu       sync.Mutex
	fail     bool
	delay    time.Duration
	injected int
}

func (s *capSwitch) hook(at string) error {
	if at != "wal_sync" {
		return nil
	}
	s.mu.Lock()
	fail, delay := s.fail, s.delay
	if fail || delay > 0 {
		s.injected++
	}
	s.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	if fail {
		return errCapInjectedSync
	}
	return nil
}

func (s *capSwitch) set(fail bool, delay time.Duration) {
	s.mu.Lock()
	s.fail, s.delay = fail, delay
	s.mu.Unlock()
}

func (s *capSwitch) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.injected
}

// capMachine is the drill's durable state machine: every applied command is one bbolt transaction
// (fsynced), applied index and row commit together, and a command that reaches the machine twice
// under different log indexes is counted instead of overwritten.
type capMachine struct {
	db    *bolt.DB
	delay atomic.Int64 // nanoseconds every non-noop apply sleeps (slow apply)
}

func openCapMachine(path string) (*capMachine, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{"rows", "meta", "dupes"} {
			if _, e := tx.CreateBucketIfNotExists([]byte(name)); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &capMachine{db: db}, nil
}

func capU64(v []byte) (uint64, bool) {
	if len(v) != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(v), true
}

func capBE(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func (m *capMachine) Applied() uint64 {
	var n uint64
	_ = m.db.View(func(tx *bolt.Tx) error {
		n, _ = capU64(tx.Bucket([]byte("meta")).Get([]byte("applied")))
		return nil
	})
	return n
}

func (m *capMachine) Apply(c replica.CommittedEntry) error {
	return m.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		if applied, ok := capU64(meta.Get([]byte("applied"))); ok && c.Index <= applied {
			return nil
		}
		if c.Entry.Kind != replica.Noop {
			if d := m.delay.Load(); d > 0 {
				time.Sleep(time.Duration(d))
			}
			key := []byte(c.Entry.ID.String())
			rows := tx.Bucket([]byte("rows"))
			if rows.Get(key) != nil {
				dupes := tx.Bucket([]byte("dupes"))
				n, _ := capU64(dupes.Get(key))
				if err := dupes.Put(key, capBE(n+1)); err != nil {
					return err
				}
			} else if err := rows.Put(key, append([]byte(nil), c.Entry.Payload...)); err != nil {
				return err
			}
		}
		return meta.Put([]byte("applied"), capBE(c.Index))
	})
}

func (m *capMachine) Snapshot() ([]byte, error) {
	rows, err := m.rows()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for k, v := range rows {
		out[k] = string(v)
	}
	return json.Marshal(out)
}

func (m *capMachine) Restore(raw []byte, index uint64) error {
	var rows map[string]string
	if err := json.Unmarshal(raw, &rows); err != nil {
		return err
	}
	return m.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("rows"))
		for k, v := range rows {
			if err := b.Put([]byte(k), []byte(v)); err != nil {
				return err
			}
		}
		return tx.Bucket([]byte("meta")).Put([]byte("applied"), capBE(index))
	})
}

// rows reads back every retained command payload by command id.
func (m *capMachine) rows() (map[string][]byte, error) {
	out := map[string][]byte{}
	err := m.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("rows")).ForEach(func(k, v []byte) error {
			out[string(k)] = append([]byte(nil), v...)
			return nil
		})
	})
	return out, err
}

func (m *capMachine) duplicateApplies() (int, error) {
	n := 0
	err := m.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("dupes")).ForEach(func(_, v []byte) error {
			c, _ := capU64(v)
			n += int(c)
			return nil
		})
	})
	return n, err
}

// capRetained digests the retained payloads: this is what a reader of the machine gets back.
func capRetained(rows map[string][]byte) (map[string]string, error) {
	out := make(map[string]string, len(rows))
	for id, raw := range rows {
		var p capPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("retained row %s is unreadable: %w", id, err)
		}
		out[id] = capDigest(p.Records)
	}
	return out, nil
}

type capPayload struct {
	Batch   string      `json:"batch"`
	Records []capRecord `json:"records"`
}

// capBatch is one replica command carrying three synthetic metric records.
type capBatch struct {
	ID      model.ID
	Records []capRecord
}

var capSeq atomic.Uint64

func capNewBatch() capBatch {
	b := capBatch{ID: model.NewID()}
	for range 3 {
		n := capSeq.Add(1)
		b.Records = append(b.Records, capRecord{ID: model.NewID().String(), At: int64(1_000_000 + n), Name: "drill_capacity_total", Value: n})
	}
	return b
}

func (b capBatch) digest() string { return capDigest(b.Records) }

func (b capBatch) entry() replica.Entry {
	raw, _ := json.Marshal(capPayload{Batch: b.ID.String(), Records: b.Records})
	return replica.Entry{ID: b.ID, Kind: replica.Data, Payload: raw}
}

// capNode is one real replica group (single voter) with its journal and durable machine.
type capNode struct {
	machine   *capMachine
	transport *replica.Loopback
	group     *replica.Group
	closed    bool
}

func capOpenNode(dir string, id model.ID, sw *capSwitch) (*capNode, error) {
	if err := os.MkdirAll(filepath.Join(dir, "machine"), 0o700); err != nil {
		return nil, err
	}
	machine, err := openCapMachine(filepath.Join(dir, "machine", "state.db"))
	if err != nil {
		return nil, err
	}
	transport := replica.NewLoopback()
	members := replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}
	group, err := replica.Open(replica.Config{ID: 1, Group: id, Directory: filepath.Join(dir, "raft"), Members: members, Machine: machine, Transport: transport, Fault: sw.hook})
	if err == nil {
		err = transport.Register(group)
	}
	if err == nil {
		err = group.Campaign()
	}
	if err != nil {
		if group != nil {
			group.Close()
		}
		transport.Close()
		machine.db.Close()
		return nil, err
	}
	return &capNode{machine: machine, transport: transport, group: group}, nil
}

func (n *capNode) close() {
	if n.closed {
		return
	}
	n.closed = true
	n.group.Close()
	n.transport.Close()
	n.machine.db.Close()
}

func (n *capNode) propose(b capBatch, timeout time.Duration) (replica.CommittedEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return n.group.Propose(ctx, b.entry())
}

func capReceiptOf(c replica.CommittedEntry, digest string) capReceipt {
	return capReceipt{Group: c.ApplicationCursor.Group.String(), Index: uint64(c.ApplicationCursor.Index), Digest: digest}
}

// capProposer is what the retry logic needs from a node: propose one batch and report the receipt.
type capProposer interface {
	propose(b capBatch, timeout time.Duration) (replica.CommittedEntry, error)
}

// ackBatch acknowledges one batch in the part ledger.
func (p *capPart) ackBatch(n capProposer, b capBatch, label string) (capReceipt, error) {
	c, err := n.propose(b, 20*time.Second)
	if err != nil {
		return capReceipt{}, fmt.Errorf("%s: %s: %w", p.name, label, err)
	}
	r := capReceiptOf(c, b.digest())
	return r, p.ack(b.ID.String(), r, label)
}

// retryBatch retries the SAME batch (same id, same bytes) after healing and then repeats it: the
// first answer is an acknowledgement, the repeat must carry the same receipt.
func (p *capPart) retryBatch(n capProposer, b capBatch, label string) error {
	first, err := p.ackBatch(n, b, label)
	if err != nil {
		return err
	}
	p.rep.Timeline().Deliver(p.name, b.ID.String()+" retried")
	c, err := n.propose(b, 20*time.Second)
	if err != nil {
		return fmt.Errorf("%s: repeat of %s: %w", p.name, b.ID, err)
	}
	detail := "the repeat carries the receipt of the first acknowledgement"
	same := capSameReceipt(first, capReceiptOf(c, b.digest()))
	if same != nil {
		detail = same.Error()
	}
	return p.require("repeat_returns_same_receipt:"+b.ID.String(), same == nil, detail)
}

// capCall runs fn but gives up when ctx ends: a probe must not hang behind a stuck node.
func capCall[T any](ctx context.Context, fn func() T) (T, error) {
	done := make(chan T, 1)
	go func() { done <- fn() }()
	select {
	case v := <-done:
		return v, nil
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

// capGroupState is health.LocalState for one replica group: the same inputs the node's /readyz
// reads (the group's own Failed flag, one quorum read, commit/apply cursors), evaluated by the
// committed health.Ready.
type capGroupState struct{ group *replica.Group }

func (s capGroupState) Version() string   { return "drill" }
func (s capGroupState) RestoreHold() bool { return false }
func (s capGroupState) Schema(context.Context) (health.Schema, error) {
	return health.Schema{Observed: 1, Supported: 1}, nil
}
func (s capGroupState) Groups(ctx context.Context) ([]health.Group, error) {
	type snap struct {
		st     replica.Status
		quorum bool
	}
	v, err := capCall(ctx, func() snap {
		st := s.group.Status()
		_, e := s.group.ReadIndex(ctx)
		return snap{st: st, quorum: e == nil}
	})
	if err != nil {
		return nil, err
	}
	return []health.Group{{ID: v.st.Group, Control: true, Failed: v.st.Failed, Quorum: v.quorum, Commit: v.st.Commit, Applied: v.st.Applied, Cursor: v.st.ApplicationCursor}}, nil
}
func (s capGroupState) PendingPolicyFences(context.Context) (uint64, error) { return 0, nil }
func (s capGroupState) Disk(context.Context) (health.Disk, error)           { return health.Disk{}, nil }

func capReady(ctx context.Context, s health.LocalState) (health.Readiness, error) {
	return health.Ready(ctx, s)
}

func capProbeOnce(s health.LocalState, deadline time.Duration) capProbe {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	r, err := capReady(ctx, s)
	switch {
	case err != nil:
		return capProbe{TimedOut: true}
	case r.Ready:
		return capProbe{Ready: true}
	}
	return capProbe{Reason: string(r.Reason)}
}

// capWait polls until fn is true.
func capWait(what string, limit time.Duration, fn func() bool) error {
	for deadline := time.Now().Add(limit); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if fn() {
			return nil
		}
	}
	return fmt.Errorf("timed out waiting for %s", what)
}

func capStatusFact(st replica.Status) map[string]any {
	return map[string]any{"leader": st.Leader, "term": st.Term, "commit": st.Commit, "applied": st.Applied, "last_index": st.LastIndex,
		"application_cursor": uint64(st.ApplicationCursor.Index), "failed": st.Failed}
}

// ---- part 1: failed sync ----

func capFailedSync(env *Env, rep *Report) (map[string]string, error) {
	dir := filepath.Join(env.Work, "failed-sync")
	if err := env.Approve([]string{dir}, nil); err != nil {
		return nil, err
	}
	p := newCapPart(rep, "failed_sync")
	id := model.NewID()
	sw := &capSwitch{}
	node, err := capOpenNode(dir, id, sw)
	if err != nil {
		return nil, err
	}
	defer func() { node.close() }()

	var pre []capBatch
	for i := range 6 {
		b := capNewBatch()
		if _, err = p.ackBatch(node, b, fmt.Sprintf("before_fault_%d", i)); err != nil {
			return nil, err
		}
		pre = append(pre, b)
	}
	rep.Cursor("failed_sync.before_fault", capStatusFact(node.group.Status()))
	ready, err := capReady(context.Background(), capGroupState{node.group})
	if err != nil {
		return nil, err
	}
	if err = p.require("ready_before_fault", ready.Ready, "a healthy node reports ready"); err != nil {
		return nil, err
	}

	// The fault: the journal's fsync step refuses (committed hook "wal_sync").
	sw.set(true, 0)
	var refused []capBatch
	var window []capOutcome
	for range 4 {
		b := capNewBatch()
		refused = append(refused, b)
		c, perr := node.propose(b, 5*time.Second)
		class := capClassify(perr)
		o := capOutcome{ID: b.ID.String(), Digest: b.digest(), Acked: perr == nil, Class: class}
		window = append(window, o)
		if perr == nil {
			// An ACK during a sync failure is a violation; keep it in the ledger so that the
			// reconciliation below also reports it, then fail the window check.
			if err = p.ack(o.ID, capReceiptOf(c, o.Digest), "acked_during_sync_fault"); err != nil {
				return nil, err
			}
			continue
		}
		p.refuse(o.ID, class, perr.Error())
	}
	if err = p.require("no_ack_and_typed_refusal_while_sync_fails", capVerifyWindow(window, false, nil) == nil, fmt.Sprint(capVerifyWindow(window, false, nil))); err != nil {
		return nil, err
	}
	if err = p.require("hook_fired", sw.count() >= 1, fmt.Sprintf("%d injected wal_sync failures", sw.count())); err != nil {
		return nil, err
	}
	failed := node.group.Status()
	rep.Cursor("failed_sync.during_fault", capStatusFact(failed))
	if err = p.require("status_reports_failed_group", failed.Failed, "replica status Failed is true after the journal fsync step failed"); err != nil {
		return nil, err
	}
	ready, err = capReady(context.Background(), capGroupState{node.group})
	if err != nil {
		return nil, err
	}
	if err = p.require("readiness_reports_sync_failed", capRequireReason(ready, health.ReasonSyncFailed) == nil, fmt.Sprintf("ready=%v reason=%q", ready.Ready, ready.Reason)); err != nil {
		return nil, err
	}
	// Reads continue: every acknowledged batch is still readable from the machine while the group is failed.
	rows, err := node.machine.rows()
	if err != nil {
		return nil, err
	}
	during, err := capRetained(rows)
	if err != nil {
		return nil, err
	}
	if err = p.reconcile("reads_continue_exact_while_failed", during); err != nil {
		return nil, err
	}

	// Heal the hook only. A failed group is a latch: the node stays failed and keeps refusing.
	sw.set(false, 0)
	late := capNewBatch()
	refused = append(refused, late)
	_, perr := node.propose(late, 5*time.Second)
	lateClass := capClassify(perr)
	p.refuse(late.ID.String(), lateClass, "after the hook was healed, before restart")
	if err = p.require("healing_the_hook_alone_does_not_revive_the_node", perr != nil && lateClass.typedRefusal() && node.group.Status().Failed, fmt.Sprintf("class=%s failed=%v", lateClass, node.group.Status().Failed)); err != nil {
		return nil, err
	}

	// Restart: close and reopen the node over the same files.
	node.close()
	if node, err = capOpenNode(dir, id, sw); err != nil {
		return nil, fmt.Errorf("reopen after sync failure: %w", err)
	}
	st := node.group.Status()
	rep.Cursor("failed_sync.after_restart", capStatusFact(st))
	ready, err = capReady(context.Background(), capGroupState{node.group})
	if err != nil {
		return nil, err
	}
	if err = p.require("restarted_node_is_ready", !st.Failed && ready.Ready, fmt.Sprintf("failed=%v ready=%v reason=%q", st.Failed, ready.Ready, ready.Reason)); err != nil {
		return nil, err
	}
	// Observation: a refused batch may have reached the file before the refused fsync; it is then
	// committed on replay without ever having been acknowledged. That is allowed; it is recorded.
	rows, err = node.machine.rows()
	if err != nil {
		return nil, err
	}
	var survivors []string
	for _, b := range refused {
		if _, ok := rows[b.ID.String()]; ok {
			survivors = append(survivors, b.ID.String())
		}
	}
	rep.Fact("failed_sync.refused_but_retained_after_restart", survivors)
	for i, b := range refused {
		if err = p.retryBatch(node, b, fmt.Sprintf("retry_%d", i)); err != nil {
			return nil, err
		}
	}
	if err = p.require("every_refused_batch_acknowledged_after_retry", p.led.Len() == len(pre)+len(refused), fmt.Sprintf("%d acknowledged ids", p.led.Len())); err != nil {
		return nil, err
	}
	if err = rep.Timeline().Recover(p.name); err != nil {
		return nil, p.require("recovery_after_delivery", false, err.Error())
	}

	// Close and reopen once more; the retained data is what a fresh node reads back.
	node.close()
	if node, err = capOpenNode(dir, id, sw); err != nil {
		return nil, fmt.Errorf("final reopen: %w", err)
	}
	if rows, err = node.machine.rows(); err != nil {
		return nil, err
	}
	retained, err := capRetained(rows)
	if err != nil {
		return nil, err
	}
	dupes, err := node.machine.duplicateApplies()
	if err != nil {
		return nil, err
	}
	rep.Cursor("failed_sync.final", capStatusFact(node.group.Status()))
	if err = p.require("no_duplicate_apply", dupes == 0, fmt.Sprintf("%d duplicate applies", dupes)); err != nil {
		return nil, err
	}
	if err = p.require("fault_window_verified_against_retained_data", capVerifyWindow(window, false, retained) == nil, "no ACK and typed refusals in the sync fault window"); err != nil {
		return nil, err
	}
	if err = p.reconcile("reconcile_after_reopen", retained); err != nil {
		return nil, err
	}
	return retained, nil
}

// ---- part 2: slow apply (and slow sync through the same hook) ----

// capSlowRound proposes the batches concurrently while a slowness is active: every fourth caller is
// patient (long deadline), the others have a short one. Readiness is probed all the while with a
// short deadline.
func capSlowRound(p *capPart, node *capNode, batches []capBatch, deadline time.Duration) ([]capOutcome, []capProbe, error) {
	state := capGroupState{node.group}
	stop := make(chan struct{})
	var probes []capProbe
	var pwg sync.WaitGroup
	pwg.Add(1)
	go func() {
		defer pwg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			probes = append(probes, capProbeOnce(state, 40*time.Millisecond))
			time.Sleep(15 * time.Millisecond)
		}
	}()
	outcomes := make([]capOutcome, len(batches))
	receipts := make([]capReceipt, len(batches))
	var wg sync.WaitGroup
	for i, b := range batches {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := deadline
			if i%4 == 3 {
				d = 30 * time.Second // a patient caller: it must be acknowledged, slowly, with full durability
			}
			c, err := node.propose(b, d)
			outcomes[i] = capOutcome{ID: b.ID.String(), Digest: b.digest(), Acked: err == nil, Class: capClassify(err)}
			if err == nil {
				receipts[i] = capReceiptOf(c, b.digest())
			}
		}()
	}
	wg.Wait()
	close(stop)
	pwg.Wait()
	for i, o := range outcomes {
		if o.Acked {
			if err := p.ack(o.ID, receipts[i], "acked_during_slowness"); err != nil {
				return outcomes, probes, err
			}
			continue
		}
		p.refuse(o.ID, o.Class, "caller deadline "+deadline.String())
	}
	return outcomes, probes, nil
}

func capSlowApply(env *Env, rep *Report) (map[string]string, error) {
	dir := filepath.Join(env.Work, "slow-apply")
	if err := env.Approve([]string{dir}, nil); err != nil {
		return nil, err
	}
	p := newCapPart(rep, "slow_apply")
	id := model.NewID()
	sw := &capSwitch{}
	node, err := capOpenNode(dir, id, sw)
	if err != nil {
		return nil, err
	}
	defer func() { node.close() }()
	for i := range 4 {
		if _, err = p.ackBatch(node, capNewBatch(), fmt.Sprintf("before_slowness_%d", i)); err != nil {
			return nil, err
		}
	}

	type phase struct {
		name     string
		arm      func()
		disarm   func()
		deadline time.Duration
		batches  int
	}
	phases := []phase{
		{"slow_apply", func() { node.machine.delay.Store(int64(200 * time.Millisecond)) }, func() { node.machine.delay.Store(0) }, 150 * time.Millisecond, 16},
		{"slow_sync", func() { sw.set(false, 200*time.Millisecond) }, func() { sw.set(false, 0) }, 150 * time.Millisecond, 16},
	}
	var all []capBatch
	var windows [][]capOutcome
	for _, ph := range phases {
		batches := make([]capBatch, ph.batches)
		for i := range batches {
			batches[i] = capNewBatch()
		}
		all = append(all, batches...)
		ph.arm()
		started := time.Now()
		outcomes, probes, err := capSlowRound(p, node, batches, ph.deadline)
		ph.disarm()
		if err != nil {
			return nil, err
		}
		windows = append(windows, outcomes)
		acked, refused := 0, 0
		for _, o := range outcomes {
			if o.Acked {
				acked++
			} else {
				refused++
			}
		}
		timedOut, ready, unready := capProbeSummary(probes)
		rep.Fact("slow_apply."+ph.name, map[string]any{"proposed": ph.batches, "acked_in_window": acked, "refused_in_window": refused,
			"caller_deadline_ms": ph.deadline.Milliseconds(), "window_ms": time.Since(started).Milliseconds(),
			"probes": len(probes), "probe_timed_out": timedOut, "probe_ready": ready, "probe_unready": unready})
		if err = p.require(ph.name+"_caller_deadline_refusals_observed", refused >= 1, fmt.Sprintf("%d refused, %d acknowledged inside the window", refused, acked)); err != nil {
			return nil, err
		}
		if err = p.require(ph.name+"_patient_callers_acknowledged_with_full_durability_pending_reconcile", acked >= 1, fmt.Sprintf("%d acknowledged inside the window (reconciled against retained data after the reopen)", acked)); err != nil {
			return nil, err
		}
		if err = p.require(ph.name+"_probe_fails_closed_while_apply_is_in_flight", timedOut >= 1, fmt.Sprintf("%d of %d probes with a 40ms deadline timed out behind the node; %d answered ready, %d answered unready", timedOut, len(probes), ready, unready)); err != nil {
			return nil, err
		}
		if ph.name == "slow_sync" {
			if err = p.require("slow_sync_hook_fired", sw.count() >= 1, fmt.Sprintf("%d delayed wal_sync calls", sw.count())); err != nil {
				return nil, err
			}
		}
		// Heal: the group must drain what it already accepted, then the node reports ready.
		if err = capWait("the group to apply everything it accepted", 60*time.Second, func() bool {
			st := node.group.Status()
			return !st.Failed && st.Applied == st.LastIndex
		}); err != nil {
			return nil, err
		}
		st := node.group.Status()
		rep.Cursor("slow_apply."+ph.name+".healed", capStatusFact(st))
		ready2, err := capReady(context.Background(), capGroupState{node.group})
		if err != nil {
			return nil, err
		}
		if err = p.require(ph.name+"_ready_after_heal", ready2.Ready, fmt.Sprintf("ready=%v reason=%q", ready2.Ready, ready2.Reason)); err != nil {
			return nil, err
		}
		// Retry the SAME batches (every one, acknowledged or refused): same id, same receipt on a repeat.
		for i, b := range batches {
			if err = p.retryBatch(node, b, fmt.Sprintf("%s_retry_%d", ph.name, i)); err != nil {
				return nil, err
			}
		}
	}
	if err = rep.Timeline().Recover(p.name); err != nil {
		return nil, p.require("recovery_after_delivery", false, err.Error())
	}

	node.close()
	if node, err = capOpenNode(dir, id, sw); err != nil {
		return nil, fmt.Errorf("reopen after slow apply: %w", err)
	}
	rows, err := node.machine.rows()
	if err != nil {
		return nil, err
	}
	retained, err := capRetained(rows)
	if err != nil {
		return nil, err
	}
	dupes, err := node.machine.duplicateApplies()
	if err != nil {
		return nil, err
	}
	rep.Cursor("slow_apply.final", capStatusFact(node.group.Status()))
	if err = p.require("no_duplicate_apply", dupes == 0, fmt.Sprintf("%d duplicate applies: a timed-out batch that the group applied later must not be applied again by its retry", dupes)); err != nil {
		return nil, err
	}
	for i, w := range windows {
		if err = p.require(fmt.Sprintf("window_%d_acks_durable_refusals_typed", i), capVerifyWindow(w, true, retained) == nil, fmt.Sprint(capVerifyWindow(w, true, retained))); err != nil {
			return nil, err
		}
	}
	if err = p.require("every_proposed_batch_retained_once", func() bool {
		for _, b := range all {
			if _, ok := retained[b.ID.String()]; !ok {
				return false
			}
		}
		return true
	}(), fmt.Sprintf("%d proposed, %d retained rows", len(all)+4, len(retained))); err != nil {
		return nil, err
	}
	if err = p.reconcile("reconcile_after_reopen", retained); err != nil {
		return nil, err
	}
	return retained, nil
}

// ---- part 3: full disk (the 80/90/95 admission gate through storage.DiskMeter) ----

// capMeter is the disk accounting the admission gate reads: a fixed capacity and usage set to
// exact percentages. It is the committed DiskMeter seam; it is not a full disk.
type capMeter struct {
	total uint64
	used  atomic.Uint64
}

func (m *capMeter) set(percent uint64) { m.used.Store(m.total / 100 * percent) }
func (m *capMeter) Usage(string) (storage.DiskUsage, error) {
	return storage.DiskUsage{TotalBytes: m.total, UsedBytes: m.used.Load()}, nil
}

type capSite struct {
	app    *appcore.App
	server *httptest.Server
	client *http.Client
	owner  auth.Session
	actor  auth.Credential
	org    model.ID
	dir    string
}

type capProject struct {
	id, source model.ID
	credential string
	resource   model.Resource
}

func (s *capSite) close() {
	if s.server != nil {
		s.server.Close()
	}
	if s.app != nil {
		s.app.Close()
	}
}

// capStartSite opens the application over dir and serves it on an approved loopback address.
func capStartSite(env *Env, dir string, meter storage.DiskMeter, cfg storage.PressureConfig) (*capSite, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	if err = env.Approve([]string{dir}, []string{ln.Addr().String()}); err != nil {
		ln.Close()
		return nil, err
	}
	app, err := appcore.OpenWithPressure(dir, meter, cfg)
	if err != nil {
		ln.Close()
		return nil, err
	}
	server := httptest.NewUnstartedServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	server.Listener.Close()
	server.Listener = ln
	server.StartTLS()
	return &capSite{app: app, server: server, client: server.Client(), dir: dir}, nil
}

func (s *capSite) command(ctx context.Context, kind string, p auth.AdminPayload) error {
	var revision model.Revision
	if err := s.app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		return err
	}
	p.Reason = "capacity drill"
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = s.app.Auth.AdminCommand(ctx, s.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: s.org, Kind: kind, Payload: raw})
	return err
}

func (s *capSite) bootstrap(ctx context.Context) error {
	s.org = model.NewID()
	boot, err := s.app.Control.BootstrapToken()
	if err != nil {
		return err
	}
	if s.owner, err = s.app.Auth.Bootstrap(ctx, boot, "capacity-drill-owner@example.test", "capacity drill owner password 2026"); err != nil {
		return err
	}
	if s.actor, err = s.app.Auth.Authenticate(ctx, s.owner.Token); err != nil {
		return err
	}
	for _, step := range []struct {
		kind string
		p    auth.AdminPayload
	}{{"create_org", auth.AdminPayload{Name: "capacity drill"}}, {"membership", auth.AdminPayload{UserID: s.owner.User, Enabled: true}}} {
		if err = s.command(ctx, step.kind, step.p); err != nil {
			return err
		}
	}
	return nil
}

func (s *capSite) project(ctx context.Context, name string) (capProject, error) {
	p := capProject{id: model.NewID(), source: model.NewID()}
	if err := s.command(ctx, "create_project", auth.AdminPayload{ID: p.id, Name: name}); err != nil {
		return p, err
	}
	if err := s.command(ctx, "grant", auth.AdminPayload{UserID: s.owner.User, ProjectID: p.id, Enabled: true, Permissions: []string{string(auth.Read)}}); err != nil {
		return p, err
	}
	cfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: p.id, Enabled: true})
	if err := s.command(ctx, "source_policy", auth.AdminPayload{ID: p.source, Config: cfg}); err != nil {
		return p, err
	}
	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	p.resource = model.Resource{Service: service, Environment: environment, Build: build, Instance: "opaque-instance", Labels: model.Labels{}}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric, model.SpanKind}, Resources: model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"opaque-instance"}}, Operations: []string{"operation"}, RetentionDays: map[model.Kind]uint32{model.Metric: 14, model.SpanKind: 14}, MaxBytes: 1 << 20, MaxSeries: 100}
	issued, err := s.app.Auth.OnboardSource(ctx, s.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: s.org, Project: p.id, Source: p.source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "capacity drill"})
	p.credential = issued.Credential
	return p, err
}

// capHTTPBatch is one fixed ingest batch: posting the same bytes again is a retry.
type capHTTPBatch struct {
	id      model.ID
	body    []byte
	low     bool
	records []capRecord
}

func (p capProject) metricRecord(at int64, name string) (model.Record, capRecord) {
	bits := model.FloatBits(math.Float64bits(1))
	r := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(at), Resource: p.resource, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &bits, Unit: "1", Type: "counter"}}}
	return r, capRecord{ID: r.ID.String(), At: at, Name: name, Value: uint64(bits)}
}

func (p capProject) spanRecord(at int64) (model.Record, capRecord) {
	clock := model.TraceClock{Wall: 1, Mono: 1, Domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}}
	end := clock
	end.Mono = 2
	var sid model.SpanID
	sid[0] = 1
	r := model.Record{ID: model.NewID(), Kind: model.SpanKind, ObservedAt: model.UnixNano(at), Resource: p.resource, Payload: model.Payload{Span: &model.Span{Trace: model.NewID(), ID: sid, Kind: "internal", Operation: "operation", Start: clock, End: &end, Status: "ok", SampleProbability: model.FloatBits(0x3ff0000000000000), SampleDecision: "keep"}}}
	return r, capRecord{ID: r.ID.String(), At: at, Name: "span:operation", Value: uint64(clock.Mono)}
}

func (s *capSite) batch(p capProject, low bool, at int64, name string) (capHTTPBatch, error) {
	var rec model.Record
	var flat capRecord
	if low {
		rec, flat = p.spanRecord(at)
	} else {
		rec, flat = p.metricRecord(at, name)
	}
	b := model.Batch{Version: 1, Project: p.id, Source: p.source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{rec}}
	var err error
	if b.RouteSlot, err = model.OwnerSlot(s.org, p.id, p.source, b.Producer, rec); err != nil {
		return capHTTPBatch{}, err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return capHTTPBatch{}, err
	}
	return capHTTPBatch{id: b.ID, body: raw, low: low, records: []capRecord{flat}}, nil
}

func (s *capSite) post(credential string, body []byte) (int, http.Header, []byte, error) {
	req, err := http.NewRequest("POST", s.server.URL+"/ingest/v1/batches", bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, resp.Header, raw, err
}

// capIngestAnswer is one HTTP answer to one batch.
type capIngestAnswer struct {
	class   capClass
	status  int
	reply   []byte
	receipt capReceipt
	header  string
}

func (s *capSite) send(p capProject, b capHTTPBatch) (capIngestAnswer, error) {
	status, header, reply, err := s.post(p.credential, b.body)
	if err != nil {
		return capIngestAnswer{}, err
	}
	a := capIngestAnswer{status: status, reply: reply, class: capClassifyHTTP(status, header.Get("Retry-After"), reply), header: header.Get("X-Soundpost-Receipt")}
	if a.class == capAck {
		var r model.Receipt
		if json.Unmarshal(reply, &r) != nil || r.BatchID != b.id {
			return a, fmt.Errorf("acknowledgement for %s carries no receipt for that batch", b.id)
		}
		a.receipt = capReceipt{Group: r.Cursor.Group.String(), Index: uint64(r.Cursor.Index), Digest: capDigest(b.records)}
	}
	return a, nil
}

// readAll reads every record of the project back through an authorized scan.
func (s *capSite) readAll(ctx context.Context, p capProject) (map[string]capRecord, error) {
	scope, err := s.app.Auth.Authorize(ctx, s.actor, s.org, []model.ID{p.id}, auth.Read)
	if err != nil {
		return nil, err
	}
	out := map[string]capRecord{}
	for _, kind := range []model.Kind{model.Metric, model.SpanKind} {
		it, err := s.app.Storage.Scan(ctx, scope, storage.ScanRequest{Projects: []model.ID{p.id}, Signal: kind, End: model.UnixNano(math.MaxInt64)})
		if err != nil {
			return nil, err
		}
		for {
			page, err := it.Next(ctx)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				it.Close()
				return nil, err
			}
			for i := range page.IDs {
				r := capRecord{ID: page.IDs[i].String(), At: int64(page.ObservedTimes[i])}
				switch v := page.Values[i]; {
				case v.Metric != nil && v.Metric.Value != nil:
					r.Name, r.Value = v.Metric.Name, uint64(*v.Metric.Value)
				case v.Span != nil:
					r.Name, r.Value = "span:"+v.Span.Operation, uint64(v.Span.Start.Mono)
				}
				out[r.ID] = r
			}
		}
		it.Close()
	}
	return out, nil
}

func (s *capSite) adminScope(ctx context.Context) (auth.Scope, error) {
	return s.app.Auth.Authorize(ctx, s.actor, s.org, nil, auth.OrgAdmin)
}

// deleteProject begins a retire-project deletion and drives the retention worker until it is
// physically complete.
func (s *capSite) deleteProject(ctx context.Context, project model.ID) error {
	var receipt retention.DeleteReceipt
	var last error
	for range 50 {
		scope, err := s.adminScope(ctx)
		if err != nil {
			return err
		}
		var revision model.Revision
		if err = s.app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
			return err
		}
		receipt, err = s.app.Retention.Delete(ctx, scope, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: revision, Mode: model.DeleteRetireProject, OrgID: s.org, ProjectIDs: []model.ID{project}, Reason: "free space at full disk"})
		var fault *model.Fault
		if err == nil {
			last = nil
			break
		}
		if !errors.As(err, &fault) || fault.Code != model.Conflict {
			return err
		}
		last = err
	}
	if last != nil {
		return last
	}
	for deadline := time.Now().Add(4 * time.Minute); ; time.Sleep(200 * time.Millisecond) {
		_ = s.app.Retention.RunOnce(ctx)
		scope, err := s.adminScope(ctx)
		if err != nil {
			return err
		}
		if receipt, err = s.app.Retention.PollDelete(ctx, scope, receipt.OperationID); err != nil {
			return err
		}
		if receipt.Phase == model.DeletePhaseComplete && receipt.Physical == retention.PhysicalDone {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("deletion did not complete at full disk")
		}
	}
}

// capAppState is health.LocalState over the running application: the same sources the server's
// /readyz uses (replication group status and one quorum read each, the control schema marker, the
// engine's sampled disk pressure).
type capAppState struct{ app *appcore.App }

func (s capAppState) Version() string   { return "drill" }
func (s capAppState) RestoreHold() bool { return s.app.Storage.RestoreReady() != nil }
func (s capAppState) Schema(ctx context.Context) (health.Schema, error) {
	out := health.Schema{Supported: 1}
	err := s.app.Control.View(ctx, func(st model.ControlState) error { out.Observed = uint32(st.BearerHashKeyVersion); return nil })
	return out, err
}
func (s capAppState) Groups(ctx context.Context) ([]health.Group, error) {
	statuses := s.app.ReplicationStatus()
	node := s.app.ReplicaNode()
	control := s.app.Control.ReplicaGroup()
	if len(statuses) == 0 || node == nil || control == nil {
		return nil, model.Fail(model.Unavailable)
	}
	controlID := control.Status().Group
	out := make([]health.Group, len(statuses))
	var wg sync.WaitGroup
	for i, st := range statuses {
		out[i] = health.Group{ID: st.Group, Control: st.Group == controlID, Failed: st.Failed, Commit: st.Commit, Applied: st.Applied, Cursor: st.ApplicationCursor}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := node.ReadIndex(ctx, st.Group)
			out[i].Quorum = err == nil
		}()
	}
	wg.Wait()
	return out, nil
}
func (s capAppState) PendingPolicyFences(ctx context.Context) (uint64, error) {
	var pending uint64
	err := s.app.Control.View(ctx, func(st model.ControlState) error {
		for _, f := range st.SourceFences {
			if f.Phase == "fencing" {
				pending++
			}
		}
		return nil
	})
	return pending, err
}
func (s capAppState) Disk(ctx context.Context) (health.Disk, error) {
	status, err := s.app.Storage.ObservePressure(ctx)
	if err != nil {
		return health.Disk{}, err
	}
	out := health.Disk{Unmetered: status.Unmetered}
	switch status.Level {
	case storage.PressureWarn:
		out.Level = health.DiskWarn
	case storage.PressureDenyLow:
		out.Level = health.DiskDenyLow
	case storage.PressureDenyAll:
		out.Level = health.DiskDenyAll
	}
	return out, nil
}

func capFullDisk(env *Env, rep *Report) (map[string]string, error) {
	ctx := env.Ctx
	dir := filepath.Join(env.Work, "full-disk")
	p := newCapPart(rep, "full_disk")
	meter := &capMeter{total: 100 << 30} // a multiple of 100: every percentage below is exact
	meter.set(50)
	cfg := storage.DefaultPressureConfig()
	cfg.Interval = 0 // sample on every admission: a level change is visible to the very next request
	site, err := capStartSite(env, dir, meter, cfg)
	if err != nil {
		return nil, err
	}
	defer func() { site.close() }()
	if err = site.bootstrap(ctx); err != nil {
		return nil, err
	}
	proj, err := site.project(ctx, "capacity")
	if err != nil {
		return nil, err
	}
	victim, err := site.project(ctx, "freed-by-deletion")
	if err != nil {
		return nil, err
	}
	state := capAppState{site.app}
	batches := map[string][]string{} // every batch of the part: id -> record ids
	bodies := map[string]capHTTPBatch{}
	clock := int64(1000)
	next := func(low bool, name string) (capHTTPBatch, error) {
		clock++
		b, err := site.batch(proj, low, clock, name)
		if err == nil {
			batches[b.id.String()] = []string{b.records[0].ID}
			bodies[b.id.String()] = b
		}
		return b, err
	}
	level := func(percent uint64, want storage.PressureLevel) error {
		meter.set(percent)
		st, err := site.app.Storage.ObservePressure(ctx)
		if err != nil {
			return err
		}
		return p.require(fmt.Sprintf("level_at_%d_percent", percent), st.Level == want, fmt.Sprintf("level %d, want %d", st.Level, want))
	}
	// try sends the batch once. An ACK goes into the ledger; a refusal into the attempts and the timeline.
	try := func(b capHTTPBatch, label string) (capIngestAnswer, error) {
		a, err := site.send(proj, b)
		if err != nil {
			return a, err
		}
		if a.class == capAck {
			return a, p.ack(b.id.String(), a.receipt, label)
		}
		p.refuse(b.id.String(), a.class, fmt.Sprintf("%s: http %d %s", label, a.status, capFaultText(a.reply)))
		return a, nil
	}
	outcome := func(b capHTTPBatch, a capIngestAnswer) capOutcome {
		return capOutcome{ID: b.id.String(), Digest: capDigest(b.records), Acked: a.class == capAck, Class: a.class}
	}

	// 50 %: normal. ACK a ledger of batches before any fault; seed the project that deletion will free space with.
	var seeded []capHTTPBatch
	for i := range 4 {
		b, err := next(false, "capacity_acked_total")
		if err != nil {
			return nil, err
		}
		a, err := try(b, fmt.Sprintf("normal_%d", i))
		if err != nil {
			return nil, err
		}
		if err = p.require(fmt.Sprintf("normal_ack_%d", i), a.class == capAck, fmt.Sprintf("http %d", a.status)); err != nil {
			return nil, err
		}
		seeded = append(seeded, b)
	}
	lowSeed, err := next(true, "")
	if err != nil {
		return nil, err
	}
	if a, err := try(lowSeed, "normal_low"); err != nil || a.class != capAck {
		return nil, fmt.Errorf("low-priority batch refused at 50%%: %v %v", a.status, err)
	}
	seeded = append(seeded, lowSeed)
	for range 2 {
		clock++
		vb, err := site.batch(victim, false, clock, "victim_total")
		if err != nil {
			return nil, err
		}
		if status, _, reply, err := site.post(victim.credential, vb.body); err != nil || status != 200 {
			return nil, fmt.Errorf("victim ingest: %d %v %s", status, err, string(reply))
		}
	}
	ready, err := capReady(ctx, state)
	if err != nil {
		return nil, err
	}
	if err = p.require("ready_at_50_percent", ready.Ready, fmt.Sprintf("ready=%v reason=%q", ready.Ready, ready.Reason)); err != nil {
		return nil, err
	}
	rep.Cursor("full_disk.before_fault", map[string]any{"acked": p.led.Len(), "last_receipt_index": p.led.Acks()[p.led.Len()-1].Index})

	var windows [][]capOutcome
	var refusedBatches []capHTTPBatch
	var refuseWindows [][]capOutcome
	// retryAll retries the SAME batches (same id, same bytes) after healing, then repeats each: the first
	// answer must be an acknowledgement, the repeat the same receipt and the same reply bytes.
	retryAll := func(list []capHTTPBatch, tag string) error {
		for i, b := range list {
			a, err := try(b, fmt.Sprintf("%s_%d", tag, i))
			if err != nil {
				return err
			}
			if err = p.require(fmt.Sprintf("%s_%d_acknowledged", tag, i), a.class == capAck, fmt.Sprintf("class %s http %d %s", a.class, a.status, capFaultText(a.reply))); err != nil {
				return err
			}
			rep.Timeline().Deliver(p.name, b.id.String()+" retried")
			again, err := site.send(proj, b)
			if err != nil {
				return err
			}
			if err = p.require(fmt.Sprintf("%s_%d_repeat_same_receipt_and_bytes", tag, i), again.class == capAck && capSameReceipt(a.receipt, again.receipt) == nil && bytes.Equal(a.reply, again.reply), fmt.Sprintf("class %s http %d", again.class, again.status)); err != nil {
				return err
			}
		}
		return nil
	}

	// 80 %: warn. Everything is still admitted; readiness is still ready.
	if err = level(80, storage.PressureWarn); err != nil {
		return nil, err
	}
	{
		var w []capOutcome
		for _, low := range []bool{false, true} {
			b, err := next(low, "capacity_warn_total")
			if err != nil {
				return nil, err
			}
			a, err := try(b, "warn")
			if err != nil {
				return nil, err
			}
			w = append(w, outcome(b, a))
			if err = p.require(fmt.Sprintf("warn_admits_low=%v", low), a.class == capAck, fmt.Sprintf("http %d", a.status)); err != nil {
				return nil, err
			}
		}
		windows = append(windows, w)
		ready, err = capReady(ctx, state)
		if err != nil {
			return nil, err
		}
		if err = p.require("ready_at_80_percent", ready.Ready, fmt.Sprintf("ready=%v reason=%q", ready.Ready, ready.Reason)); err != nil {
			return nil, err
		}
	}

	// 90 %: low-priority intake is refused (typed), normal intake continues; readiness reports disk pressure.
	if err = level(90, storage.PressureDenyLow); err != nil {
		return nil, err
	}
	{
		var w []capOutcome
		okBatch, err := next(false, "capacity_denylow_total")
		if err != nil {
			return nil, err
		}
		a, err := try(okBatch, "deny_low_normal")
		if err != nil {
			return nil, err
		}
		w = append(w, outcome(okBatch, a))
		if err = p.require("deny_low_still_admits_normal", a.class == capAck, fmt.Sprintf("http %d", a.status)); err != nil {
			return nil, err
		}
		lowBatch, err := next(true, "")
		if err != nil {
			return nil, err
		}
		a, err = try(lowBatch, "deny_low_low")
		if err != nil {
			return nil, err
		}
		w = append(w, outcome(lowBatch, a))
		if err = p.require("deny_low_refuses_low_with_typed_capacity_refusal", a.class == capCapacity, fmt.Sprintf("class %s http %d", a.class, a.status)); err != nil {
			return nil, err
		}
		refusedBatches = append(refusedBatches, lowBatch)
		windows = append(windows, w)
		ready, err = capReady(ctx, state)
		if err != nil {
			return nil, err
		}
		if err = p.require("readiness_reports_disk_pressure_at_90", capRequireReason(ready, health.ReasonDiskPressure) == nil, fmt.Sprintf("ready=%v reason=%q", ready.Ready, ready.Reason)); err != nil {
			return nil, err
		}
	}

	// 95 %: deny-all. No new batch is acknowledged; every one is refused with a typed capacity fault.
	if err = level(95, storage.PressureDenyAll); err != nil {
		return nil, err
	}
	var denyAll []capOutcome
	for i := range 4 {
		low := i == 3
		b, err := next(low, "capacity_denyall_total")
		if err != nil {
			return nil, err
		}
		a, err := try(b, "deny_all")
		if err != nil {
			return nil, err
		}
		denyAll = append(denyAll, outcome(b, a))
		refusedBatches = append(refusedBatches, b)
	}
	if err = p.require("deny_all_refuses_every_new_batch_typed_and_acks_none", capVerifyWindow(denyAll, false, nil) == nil, fmt.Sprint(capVerifyWindow(denyAll, false, nil))); err != nil {
		return nil, err
	}
	for _, o := range denyAll {
		if err = p.require("deny_all_refusal_is_capacity:"+o.ID, o.Class == capCapacity, string(o.Class)); err != nil {
			return nil, err
		}
	}
	ready, err = capReady(ctx, state)
	if err != nil {
		return nil, err
	}
	if err = p.require("readiness_reports_disk_pressure_at_95", capRequireReason(ready, health.ReasonDiskPressure) == nil, fmt.Sprintf("ready=%v reason=%q", ready.Ready, ready.Reason)); err != nil {
		return nil, err
	}
	if err = site.app.Retention.RunOnce(ctx); err != nil {
		rep.Fact("full_disk.retention_pass_at_95_error_class", string(capClassify(err)))
	}
	if err = p.require("retention_worker_surfaces_deny_all", site.app.Retention.Status().Pressure.Level == storage.PressureDenyAll, fmt.Sprintf("level %d", site.app.Retention.Status().Pressure.Level)); err != nil {
		return nil, err
	}
	// Reads continue at full disk: every ACKed batch is read back exactly.
	rows, err := site.readAll(ctx, proj)
	if err != nil {
		return nil, p.require("reads_continue_at_95_percent", false, err.Error())
	}
	if err = p.reconcile("reads_continue_exact_at_95_percent", capFold(batches, rows)); err != nil {
		return nil, err
	}
	// The ACKed batches still answer with their original receipt byte for byte.
	for i, b := range seeded {
		a, err := site.send(proj, b)
		if err != nil {
			return nil, err
		}
		if err = p.require(fmt.Sprintf("acked_retry_%d_unchanged_at_95_percent", i), a.class == capAck && a.header == b.id.String() && a.receipt == mustReceipt(p, b.id.String()), fmt.Sprintf("class %s http %d", a.class, a.status)); err != nil {
			return nil, err
		}
	}
	// Hysteresis: 94 % is still deny-all.
	if err = level(94, storage.PressureDenyAll); err != nil {
		return nil, err
	}
	{
		b, err := next(false, "capacity_hysteresis_total")
		if err != nil {
			return nil, err
		}
		a, err := try(b, "hysteresis")
		if err != nil {
			return nil, err
		}
		denyAll = append(denyAll, outcome(b, a))
		refusedBatches = append(refusedBatches, b)
		if err = p.require("hysteresis_at_94_still_refuses", a.class == capCapacity, string(a.class)); err != nil {
			return nil, err
		}
	}
	refuseWindows = append(refuseWindows, denyAll)
	if err = level(91, storage.PressureDenyLow); err != nil {
		return nil, err
	}

	// Heal: the meter drops back; retry the SAME refused batches, then repeat each.
	if err = level(50, storage.PressureNormal); err != nil {
		return nil, err
	}
	ready, err = capReady(ctx, state)
	if err != nil {
		return nil, err
	}
	if err = p.require("ready_after_heal", ready.Ready, fmt.Sprintf("ready=%v reason=%q", ready.Ready, ready.Reason)); err != nil {
		return nil, err
	}
	if err = retryAll(refusedBatches, "retry"); err != nil {
		return nil, err
	}
	if err = rep.Timeline().Recover(p.name); err != nil {
		return nil, p.require("recovery_after_delivery", false, err.Error())
	}

	// Deletion at full disk: new writes are refused, the deletion that frees space is not.
	if err = level(95, storage.PressureDenyAll); err != nil {
		return nil, err
	}
	var deleteWindow []capOutcome
	var beforeDelete, afterDelete []capHTTPBatch
	for range 2 {
		b, err := next(false, "capacity_predelete_total")
		if err != nil {
			return nil, err
		}
		a, err := try(b, "deny_all_before_delete")
		if err != nil {
			return nil, err
		}
		deleteWindow = append(deleteWindow, outcome(b, a))
		beforeDelete = append(beforeDelete, b)
	}
	if err = site.deleteProject(ctx, victim.id); err != nil {
		return nil, p.require("delete_allowed_at_95_percent", false, err.Error())
	}
	if err = p.require("delete_allowed_at_95_percent", true, "the retire-project deletion completed physically while new writes were refused"); err != nil {
		return nil, err
	}
	_, readErr := site.readAll(ctx, victim)
	if err = p.require("deleted_project_is_unreadable", readErr != nil, "an authorized scan of the retired project fails"); err != nil {
		return nil, err
	}
	{
		b, err := next(false, "capacity_postdelete_total")
		if err != nil {
			return nil, err
		}
		a, err := try(b, "deny_all_after_delete")
		if err != nil {
			return nil, err
		}
		deleteWindow = append(deleteWindow, outcome(b, a))
		afterDelete = append(afterDelete, b)
	}
	refuseWindows = append(refuseWindows, deleteWindow)
	if err = p.require("deny_all_still_refuses_after_delete_typed_and_no_ack", capVerifyWindow(deleteWindow, false, nil) == nil, fmt.Sprint(capVerifyWindow(deleteWindow, false, nil))); err != nil {
		return nil, err
	}
	if err = level(50, storage.PressureNormal); err != nil {
		return nil, err
	}
	if err = retryAll(afterDelete, "retry_after_delete"); err != nil {
		return nil, err
	}
	if err = rep.Timeline().Recover(p.name); err != nil {
		return nil, p.require("recovery_after_delete_delivery", false, err.Error())
	}
	// Observation (not a pass criterion): the same retry for batches that were refused BEFORE the
	// deletion, which changed the policy epoch. These are probed with a plain send: they are not
	// recorded as ledger attempts and a result other than an acknowledgement is reported as a finding.
	probe := make([]map[string]any, 0, len(beforeDelete))
	for _, b := range beforeDelete {
		a, err := site.send(proj, b)
		if err != nil {
			return nil, err
		}
		if a.class == capAck {
			if err = p.ack(b.id.String(), a.receipt, "retry_across_policy_epoch"); err != nil {
				return nil, err
			}
		}
		probe = append(probe, map[string]any{"id": b.id.String(), "class": string(a.class), "http_status": a.status, "fault": capFaultText(a.reply)})
	}
	rep.Fact("finding.retry_of_capacity_refused_batch_across_a_policy_epoch_change", map[string]any{
		"batches_refused_before_deletion_then_retried_after": probe,
		"batches_refused_after_deletion_then_retried":        "acknowledged (retry_after_delete checks)",
		"batches_refused_then_retried_without_any_change":    "acknowledged (retry checks)",
		"note": "a 503 capacity refusal is advertised as retryable; the retry of the same batch id after a project deletion changed the policy epoch is answered 403 forbidden, which a client reads as permanent. Source: ValidateReservation compares the reservation made at the first attempt with the batch's current policy epoch. Not asserted as pass.",
	})
	status := site.app.Storage.PressureStatus()
	var codes []string
	for _, w := range status.Warnings {
		codes = append(codes, w.Code)
	}
	want := []string{"disk_warn", "disk_deny_low", "disk_deny_all", "disk_deny_low", "disk_recovered", "disk_deny_all", "disk_recovered"}
	if err = p.require("pressure_warning_sequence_matches_01_08", fmt.Sprint(codes) == fmt.Sprint(want), strings.Join(codes, ",")); err != nil {
		return nil, err
	}
	if err = p.require("denials_were_counted", status.DeniedAll > 0 && status.DeniedLow > 0, fmt.Sprintf("denied_all=%d denied_low=%d", status.DeniedAll, status.DeniedLow)); err != nil {
		return nil, err
	}
	rep.Cursor("full_disk.final", map[string]any{"acked": p.led.Len(), "refused_attempts": len(p.led.Attempts()), "denied_all": status.DeniedAll, "denied_low": status.DeniedLow, "last_receipt_index": p.led.Acks()[p.led.Len()-1].Index})

	// Close and reopen the application over the same files; read everything back.
	owner, org, actorToken := site.owner, site.org, site.owner.Token
	site.close()
	reopened, err := capStartSite(env, dir, meter, cfg)
	if err != nil {
		return nil, fmt.Errorf("reopen after full disk: %w", err)
	}
	site = reopened
	site.owner, site.org = owner, org
	if site.actor, err = site.app.Auth.Authenticate(ctx, actorToken); err != nil {
		return nil, fmt.Errorf("authenticate after reopen: %w", err)
	}
	rows, err = site.readAll(ctx, proj)
	if err != nil {
		return nil, err
	}
	retained := capFold(batches, rows)
	for i, w := range windows {
		if err = p.require(fmt.Sprintf("window_%d_acks_durable_refusals_typed", i), capVerifyWindow(w, true, retained) == nil, fmt.Sprint(capVerifyWindow(w, true, retained))); err != nil {
			return nil, err
		}
	}
	for i, w := range refuseWindows {
		if err = p.require(fmt.Sprintf("deny_all_window_%d_no_ack_typed_refusals", i), capVerifyWindow(w, false, retained) == nil, fmt.Sprint(capVerifyWindow(w, false, retained))); err != nil {
			return nil, err
		}
	}
	if err = p.reconcile("reconcile_after_reopen", retained); err != nil {
		return nil, err
	}
	return retained, nil
}

func mustReceipt(p *capPart, id string) capReceipt {
	for _, a := range p.led.Acks() {
		if a.ID == id {
			return capReceipt{Group: a.Group, Index: a.Index, Digest: a.Digest}
		}
	}
	return capReceipt{}
}

// ---- the scenario ----

func capacityFaults(env *Env, rep *Report) error {
	rep.Fact("injection", map[string]string{
		"failed_sync": "replica.Config.Fault hook \"wal_sync\" of the committed replica journal, called immediately before the real fsync",
		"slow_apply":  "the drill's durable bbolt state machine sleeps inside Apply; slow sync: the same hook delays before the real fsync",
		"full_disk":   "storage.DiskMeter bound with BindPressure through appcore.OpenWithPressure: the 80/90/95 admission gate reads an injected usage",
		"honesty":     "hook-injected failures are NOT a failing disk: no EIO or ENOSPC was produced by the operating system and the real fsync was never replaced",
	})
	rep.NotRun("engine-level failed sync and slow apply (storage.Engine / appcore)",
		"the engine's fault hook storage.Engine.fault (\"wal_sync\", \"before_apply\", \"receipt_write\", \"applied_cursor\") is an unexported field set only by in-package tests (internal/storage/wal_test.go TestSyncFailureNeverAcknowledges); EnableReplication overwrites replica.Config.Fault with it, so no exported seam reaches it from a drill; failed sync and slow apply were therefore driven through the exported replica.Config.Fault hook of the replica journal with a drill-owned durable state machine, not through the full storage engine")
	rep.NotRun("real out-of-space (ENOSPC) and real I/O errors (EIO)",
		"filling a real size-limited filesystem needs a mount (tmpfs/loop), which needs privilege this drill must not use, and /tmp is a large shared volume that must not be filled; the full-disk behaviour was driven through the committed storage.DiskMeter seam only, which exercises the admission gate and not the operating system's write failure path")

	retained := map[string]string{}
	for _, part := range []func(*Env, *Report) (map[string]string, error){capFailedSync, capSlowApply, capFullDisk} {
		got, err := part(env, rep)
		for id, d := range got {
			retained[id] = d
		}
		if err != nil {
			return err
		}
	}
	events := rep.Timeline().Events()
	failures := len(rep.Ledger().Attempts())
	if err := rep.Require("timeline_keeps_every_failed_attempt", VerifyTimeline(events, failures) == nil && FailedAttempts(events) == failures && rep.Timeline().State() == StateRecovered,
		fmt.Sprintf("%d failed attempts in the timeline, %d refusals in the ledger, state %s", FailedAttempts(events), failures, rep.Timeline().State())); err != nil {
		return err
	}
	return rep.Reconcile(retained)
}

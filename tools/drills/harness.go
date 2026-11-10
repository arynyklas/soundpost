// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---- the ACK ledger ----

// Ack is one acknowledged write: the batch identity, the receipt cursor the server returned and
// the digest of the SEMANTIC data the batch carried (what a reader must be able to retrieve).
type Ack struct {
	Seq    int    `json:"seq"`
	ID     string `json:"id"`
	Group  string `json:"cursor_group"`
	Index  uint64 `json:"cursor_index"`
	Digest string `json:"semantic_digest"`
	Label  string `json:"label,omitempty"`
}

// Attempt is one send that was NOT acknowledged (a refusal, a timeout, a transport error). It is
// kept so a retry can be shown to carry the same identity and so a later acknowledgement of the
// same batch can be matched with the failed attempts that preceded it.
type Attempt struct {
	ID      string `json:"id"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// Ledger records every acknowledgement and every failed attempt of one drill. It is the only
// source of truth for what must exist after recovery.
type Ledger struct {
	mu       sync.Mutex
	acks     []Ack
	byID     map[string]int
	attempts []Attempt
}

// Record adds an acknowledgement. A second acknowledgement of the same ID is accepted only when
// it carries the same receipt cursor and digest (a retry preserves ID and receipt); anything else
// is a harness failure because it would mean one batch was acknowledged twice differently.
func (l *Ledger) Record(a Ack) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if a.ID == "" || a.Digest == "" {
		return errors.New("ledger: acknowledgement without id or semantic digest")
	}
	if l.byID == nil {
		l.byID = map[string]int{}
	}
	if i, ok := l.byID[a.ID]; ok {
		p := l.acks[i]
		if p.Group != a.Group || p.Index != a.Index || p.Digest != a.Digest {
			return fmt.Errorf("ledger: retry of %s changed its receipt or data", a.ID)
		}
		return nil
	}
	a.Seq = len(l.acks) + 1
	l.byID[a.ID] = len(l.acks)
	l.acks = append(l.acks, a)
	return nil
}

// Attempted records a failed attempt.
func (l *Ledger) Attempted(a Attempt) {
	l.mu.Lock()
	l.attempts = append(l.attempts, a)
	l.mu.Unlock()
}

// Acks returns a copy of the acknowledgements in order.
func (l *Ledger) Acks() []Ack {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Ack(nil), l.acks...)
}

// Attempts returns a copy of the failed attempts in order.
func (l *Ledger) Attempts() []Attempt {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Attempt(nil), l.attempts...)
}

// Len is the number of distinct acknowledged batches.
func (l *Ledger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.acks)
}

// Mismatch is one acknowledged batch whose retained data differs from what was acknowledged.
type Mismatch struct {
	ID   string `json:"id"`
	Want string `json:"want_digest"`
	Got  string `json:"got_digest"`
}

// ReconcileError is returned when the retained data is not exactly the acknowledged data.
type ReconcileError struct {
	Missing    []string
	Mismatched []Mismatch
	Acked      int
	Retained   int
}

func (e *ReconcileError) Error() string {
	return fmt.Sprintf("reconciliation failed: %d acknowledged, %d retained, %d missing %v, %d different",
		e.Acked, e.Retained, len(e.Missing), e.Missing, len(e.Mismatched))
}

// Reconciliation is the machine-readable outcome of a successful comparison.
type Reconciliation struct {
	Acked           int      `json:"acked"`
	Retained        int      `json:"retained"`
	ExactMatches    int      `json:"exact_matches"`
	UnackedRetained []string `json:"unacked_retained,omitempty"`
}

// Reconcile compares the exact retained semantic data with the ledger. `retained` maps batch ID
// to the digest of the data actually read back from the system after recovery. EVERY acknowledged
// ID must be present with the identical digest: one missing batch fails the reconciliation, and
// equal counts never substitute for equality of content. Retained IDs that were never
// acknowledged (a write that committed but whose acknowledgement was lost) are reported, not
// failed, because the contract is "no acknowledged write is lost".
func Reconcile(l *Ledger, retained map[string]string) (Reconciliation, error) {
	acks := l.Acks()
	var miss []string
	var diff []Mismatch
	known := make(map[string]bool, len(acks))
	exact := 0
	for _, a := range acks {
		known[a.ID] = true
		got, ok := retained[a.ID]
		switch {
		case !ok:
			miss = append(miss, a.ID)
		case got != a.Digest:
			diff = append(diff, Mismatch{ID: a.ID, Want: a.Digest, Got: got})
		default:
			exact++
		}
	}
	if len(miss) > 0 || len(diff) > 0 {
		return Reconciliation{}, &ReconcileError{Missing: miss, Mismatched: diff, Acked: len(acks), Retained: len(retained)}
	}
	var extra []string
	for id := range retained {
		if !known[id] {
			extra = append(extra, id)
		}
	}
	sort.Strings(extra)
	return Reconciliation{Acked: len(acks), Retained: len(retained), ExactMatches: exact, UnackedRetained: extra}, nil
}

// ---- the outage timeline ----

// State of the outage record. A drill moves ok -> outage -> recovered, never backwards without a
// new outage.
type State string

const (
	StateOK        State = "ok"
	StateOutage    State = "outage"
	StateRecovered State = "recovered"
)

// Event is one entry of the append-only timeline. Hash chains it to its predecessor, so removing,
// reordering or rewriting an earlier event (for example overwriting a failed attempt with a later
// success) is detected by Verify.
type Event struct {
	Seq     int    `json:"seq"`
	At      int64  `json:"at_unix_ns"`
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
	Prev    string `json:"prev"`
	Hash    string `json:"hash"`
}

func (e Event) digest() string {
	h := sha256.New()
	fmt.Fprintf(h, "%d|%d|%s|%s|%s|%s|%s", e.Seq, e.At, e.Kind, e.Subject, e.Outcome, e.Detail, e.Prev)
	return hex.EncodeToString(h.Sum(nil))
}

// Timeline is the append-only, hash-chained record of an outage and its recovery.
type Timeline struct {
	mu     sync.Mutex
	events []Event
	state  State
	clock  func() time.Time
}

// NewTimeline returns an empty timeline in StateOK.
func NewTimeline(clock func() time.Time) *Timeline {
	if clock == nil {
		clock = time.Now
	}
	return &Timeline{state: StateOK, clock: clock}
}

func (t *Timeline) append(kind, subject, outcome, detail string) {
	e := Event{Seq: len(t.events) + 1, At: t.clock().UnixNano(), Kind: kind, Subject: subject, Outcome: outcome, Detail: detail}
	if n := len(t.events); n > 0 {
		e.Prev = t.events[n-1].Hash
	}
	e.Hash = e.digest()
	t.events = append(t.events, e)
}

// ErrFalseRecovery is returned when recovery is claimed without the evidence that justifies it.
var ErrFalseRecovery = errors.New("outage is not recovery: no successful delivery after the failed attempts")

// Fail records a failed attempt (a provider refusal, an unreachable destination, a missed
// heartbeat). The first failure opens the outage; later failures are appended, never merged.
func (t *Timeline) Fail(subject, detail string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state = StateOutage
	t.append("attempt", subject, "failed", detail)
}

// Deliver records a successful delivery. It does NOT by itself end the outage.
func (t *Timeline) Deliver(subject, detail string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.append("attempt", subject, "delivered", detail)
}

// Recover declares the outage over. It is refused (ErrFalseRecovery) unless an outage is open and
// at least one delivery succeeded AFTER the last failed attempt; the failed attempts stay in the
// record either way.
func (t *Timeline) Recover(subject string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state != StateOutage {
		return fmt.Errorf("%w: state is %s", ErrFalseRecovery, t.state)
	}
	lastFail, lastOK := 0, 0
	for _, e := range t.events {
		if e.Kind != "attempt" {
			continue
		}
		switch e.Outcome {
		case "failed":
			lastFail = e.Seq
		case "delivered":
			lastOK = e.Seq
		}
	}
	if lastOK == 0 || lastOK < lastFail {
		return ErrFalseRecovery
	}
	t.state = StateRecovered
	t.append("state", subject, "recovered", "")
	return nil
}

// State reports the current state.
func (t *Timeline) State() State {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

// Events returns a copy of the chain.
func (t *Timeline) Events() []Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]Event(nil), t.events...)
}

// FailedAttempts counts the failed attempts still present.
func FailedAttempts(events []Event) int {
	n := 0
	for _, e := range events {
		if e.Kind == "attempt" && e.Outcome == "failed" {
			n++
		}
	}
	return n
}

// VerifyTimeline checks a chain: sequence numbers are contiguous, every hash matches its content
// and predecessor, no failed attempt vanished relative to `expectFailed`, and a `recovered` entry
// is preceded by a delivery that follows the last failure. It is the harness's guard against a
// false recovered state and against an overwritten failed attempt.
func VerifyTimeline(events []Event, expectFailed int) error {
	prev := ""
	lastFail, lastOK := 0, 0
	for i, e := range events {
		if e.Seq != i+1 {
			return fmt.Errorf("timeline: event %d has sequence %d", i+1, e.Seq)
		}
		if e.Prev != prev || e.Hash != e.digest() {
			return fmt.Errorf("timeline: event %d was rewritten", e.Seq)
		}
		prev = e.Hash
		switch {
		case e.Kind == "attempt" && e.Outcome == "failed":
			lastFail = e.Seq
		case e.Kind == "attempt" && e.Outcome == "delivered":
			lastOK = e.Seq
		case e.Kind == "state" && e.Outcome == "recovered":
			if lastOK == 0 || lastOK < lastFail {
				return fmt.Errorf("timeline: event %d claims recovery without a later successful delivery: %w", e.Seq, ErrFalseRecovery)
			}
		}
	}
	if got := FailedAttempts(events); got < expectFailed {
		return fmt.Errorf("timeline: %d failed attempts remain, %d were recorded: a failed attempt was overwritten", got, expectFailed)
	}
	return nil
}

// ---- the isolated-target allowlist ----

// TargetName is the only literal `--target` accepts in this repository: production execution is a
// separate owner action.
const TargetName = "isolated"

// Allowlist is the explicit set of places a drill may touch. It is read from drills/scenarios.yaml
// and is never empty by default: an empty allowlist refuses everything.
type Allowlist struct {
	// DataRoots are absolute directory prefixes a drill may create its data under.
	DataRoots []string `yaml:"data_roots"`
	// Hosts are the literal host names/addresses a drill may bind or dial. Only loopback entries
	// are ever accepted, whatever this lists.
	Hosts []string `yaml:"hosts"`
	// Forbidden are directories that are the production/default data locations of the product.
	Forbidden []string `yaml:"forbidden_data_dirs"`
}

// Target is what one scenario run wants to touch.
type Target struct {
	Name      string
	DataDirs  []string
	Addresses []string
}

func cleanPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	parts := strings.Split(p, "/")
	var out []string
	for _, s := range parts {
		switch s {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, s)
		}
	}
	return "/" + strings.Join(out, "/")
}

func under(path, root string) bool {
	path, root = cleanPath(path), cleanPath(root)
	return path == root || strings.HasPrefix(path, strings.TrimSuffix(root, "/")+"/")
}

// ErrRefused wraps every refusal so callers can tell a safety refusal from a drill failure.
var ErrRefused = errors.New("drill refused")

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}

// CheckTarget refuses anything that is not explicitly allowlisted: a target name other than the
// literal `isolated`, a data directory that is relative, contains `..`, is outside every
// allowlisted root, is (or is inside) a production/default data directory, or is a root itself;
// and any address that is not a loopback literal with an explicit port.
func CheckTarget(a Allowlist, t Target) error {
	if t.Name != TargetName {
		return refuse("target %q is not the isolated target", t.Name)
	}
	if len(a.DataRoots) == 0 {
		return refuse("the allowlist names no isolated data root")
	}
	for _, d := range t.DataDirs {
		if !strings.HasPrefix(strings.ReplaceAll(d, "\\", "/"), "/") {
			return refuse("data directory %q is not absolute", d)
		}
		if strings.Contains(strings.ReplaceAll(d, "\\", "/"), "/../") || strings.HasSuffix(d, "/..") {
			return refuse("data directory %q contains a parent reference", d)
		}
		for _, f := range a.Forbidden {
			if under(d, f) || under(f, d) {
				return refuse("data directory %q is a production or default data directory", d)
			}
		}
		ok := false
		for _, r := range a.DataRoots {
			if cleanPath(r) != "/" && cleanPath(d) != cleanPath(r) && under(d, r) {
				ok = true
			}
		}
		if !ok {
			return refuse("data directory %q is not under an allowlisted isolated root", d)
		}
	}
	for _, addr := range t.Addresses {
		if err := checkLoopback(a, addr); err != nil {
			return err
		}
	}
	return nil
}

func checkLoopback(a Allowlist, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" || port == "0" {
		return refuse("address %q is not host:port with an explicit port", addr)
	}
	listed := false
	for _, h := range a.Hosts {
		if h == host {
			listed = true
		}
	}
	if !listed {
		return refuse("host %q is not on the allowlist", host)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || ip.IsUnspecified() {
		return refuse("host %q is not a loopback address", host)
	}
	return nil
}

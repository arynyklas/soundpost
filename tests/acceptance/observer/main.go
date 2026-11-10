// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command observer is the test fixture of the independent external deadman: a
// separate process with its own credentials, its own storage path and its own
// schedule. It polls heartbeat endpoints of the product (product, ingest and
// notification pipeline are three separate components), declares a component
// missing when no healthy heartbeat arrived for the configured interval and
// delivers to an authorized destination. It imports nothing of the product: it
// shares nothing with the product but the heartbeat contract.
//
// THE FIXTURE IS NOT AN INDEPENDENT FAILURE DOMAIN. When the acceptance test
// runs it, it runs on the same host as the product, so a host failure would
// take both down. What it demonstrates is the mechanism (a separate process,
// state and credentials that keeps running while the product is stopped);
// docs/operations/external-deadman.md states what a real deployment needs.
//
// Heartbeat contract: GET <url> with "Authorization: Bearer <poll credential>"
// answers 200 with {"component":"<name>","ok":true,"seq":N,"at_ns":T} when the
// component works, and anything else (503, a timeout, a refused connection, a
// malformed body) is no heartbeat. Credentials come from the environment only:
// OBSERVER_POLL_TOKEN and OBSERVER_DELIVERY_TOKEN. Nothing secret is logged or
// stored.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Attempt is one delivery attempt: when, and how it ended (a status code or a
// closed error class, never a response body).
type Attempt struct {
	N      int    `json:"n"`
	AtNS   int64  `json:"at_ns"`
	Kind   string `json:"kind"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Outage is one detected absence of a component's heartbeat and everything the
// observer did about it. It is never erased.
type Outage struct {
	ID          string    `json:"id"`
	Component   string    `json:"component"`
	LastOKNS    int64     `json:"last_ok_ns"`
	DetectedNS  int64     `json:"detected_ns"`
	NeverSeen   bool      `json:"never_seen,omitempty"`
	RecoveredNS int64     `json:"recovered_ns,omitempty"`
	Alerted     bool      `json:"alerted"`
	Recovery    bool      `json:"recovery_notified"`
	Attempts    []Attempt `json:"attempts"`
}

// Component is the observer's view of one polled component.
type Component struct {
	Name     string `json:"name"`
	LastOKNS int64  `json:"last_ok_ns"`
	LastSeq  uint64 `json:"last_seq"`
	// Status is ok, missing or unknown (never seen healthy yet).
	Status string `json:"status"`
}

// State is everything the observer persists.
type State struct {
	Observer   string      `json:"observer"`
	StartedNS  int64       `json:"started_ns"`
	LastCycle  int64       `json:"last_cycle_ns"`
	Armed      bool        `json:"armed"`
	Components []Component `json:"components"`
	Outages    []Outage    `json:"outages"`
}

type config struct {
	state       string
	id          string
	polls       map[string]string
	interval    time.Duration
	missing     time.Duration
	timeout     time.Duration
	destination string
	allowed     map[string]bool
	allowLocal  bool
	maxAttempts int
	pollToken   string
	delivToken  string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "observer:", err)
		os.Exit(2)
	}
}

func parse() (config, error) {
	var c config
	var polls, allowed string
	flag.StringVar(&c.state, "state", "", "the observer's own storage directory")
	flag.StringVar(&c.id, "id", "observer", "the observer's identity")
	flag.StringVar(&polls, "poll", "", "name=url,name=url heartbeat endpoints")
	flag.DurationVar(&c.interval, "interval", 200*time.Millisecond, "poll interval")
	flag.DurationVar(&c.missing, "missing-after", time.Second, "no healthy heartbeat for this long is a missing heartbeat")
	flag.DurationVar(&c.timeout, "timeout", 300*time.Millisecond, "per request timeout")
	flag.StringVar(&c.destination, "destination", "", "delivery destination URL")
	flag.StringVar(&allowed, "authorized-destination", "", "host:port,host:port the observer may deliver to")
	flag.BoolVar(&c.allowLocal, "test-allow-loopback", false, "TEST ONLY: permit a loopback destination")
	flag.IntVar(&c.maxAttempts, "max-attempts", 8, "delivery attempts per notice")
	flag.Parse()
	c.pollToken, c.delivToken = os.Getenv("OBSERVER_POLL_TOKEN"), os.Getenv("OBSERVER_DELIVERY_TOKEN")
	c.polls, c.allowed = map[string]string{}, map[string]bool{}
	for _, p := range strings.Split(polls, ",") {
		if name, u, ok := strings.Cut(p, "="); ok && name != "" && u != "" {
			c.polls[name] = u
		}
	}
	for _, a := range strings.Split(allowed, ",") {
		if a != "" {
			c.allowed[a] = true
		}
	}
	switch {
	case c.state == "" || len(c.polls) == 0 || c.destination == "" || c.pollToken == "" || c.delivToken == "":
		return c, errors.New("-state, -poll, -destination and both credentials are required")
	case c.interval <= 0 || c.missing < c.interval || c.timeout <= 0 || c.maxAttempts < 1:
		return c, errors.New("invalid schedule")
	}
	return c, authorize(c)
}

// authorize refuses a destination that is not explicitly authorized: only a
// listed host:port is ever delivered to, and a loopback or private address only
// when the test allowance is given.
func authorize(c config) error {
	u, err := url.Parse(c.destination)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return errors.New("destination is not an http(s) URL")
	}
	if !c.allowed[u.Host] {
		return errors.New("destination is not authorized")
	}
	ip := net.ParseIP(u.Hostname())
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) && !c.allowLocal {
		return errors.New("destination is a local address and the test allowance is not set")
	}
	return nil
}

func run() error {
	c, err := parse()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(c.state, 0o700); err != nil {
		return err
	}
	st, err := load(c)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := &http.Client{Timeout: c.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	tick := time.NewTicker(c.interval)
	defer tick.Stop()
	logEvent("started", map[string]any{"observer": c.id, "components": len(c.polls)})
	for {
		cycle(ctx, c, client, st)
		if err = save(c, st); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

func logEvent(event string, fields map[string]any) {
	fields["event"] = event
	raw, _ := json.Marshal(fields)
	fmt.Println(string(raw))
}

func load(c config) (*State, error) {
	st := &State{Observer: c.id, StartedNS: time.Now().UnixNano()}
	raw, err := os.ReadFile(filepath.Join(c.state, "state.json"))
	switch {
	case err == nil:
		prev := &State{}
		if err = json.Unmarshal(raw, prev); err != nil {
			return nil, fmt.Errorf("state is corrupt: %w", err)
		}
		if prev.Observer != c.id {
			return nil, errors.New("state belongs to another observer")
		}
		st = prev
		st.Armed = false // armed again only by a fresh healthy cycle after a start
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	names := make([]string, 0, len(c.polls))
	for n := range c.polls {
		names = append(names, n)
	}
	sort.Strings(names)
	have := map[string]bool{}
	for _, comp := range st.Components {
		have[comp.Name] = true
	}
	for _, n := range names {
		if !have[n] {
			st.Components = append(st.Components, Component{Name: n, Status: "unknown"})
		}
	}
	return st, nil
}

// save replaces the state file atomically and durably.
func save(c config, st *State) error {
	raw, err := json.MarshalIndent(st, "", " ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(c.state, "state.json.tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(c.state, "state.json"))
}

// appendAttempt adds one line to the append-only attempt log.
func appendAttempt(c config, outage string, a Attempt) {
	f, err := os.OpenFile(filepath.Join(c.state, "attempts.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	raw, _ := json.Marshal(struct {
		Outage string `json:"outage"`
		Attempt
	}{outage, a})
	f.Write(append(raw, '\n'))
	f.Sync()
}

type beat struct {
	Component string `json:"component"`
	OK        bool   `json:"ok"`
	Seq       uint64 `json:"seq"`
}

func poll(ctx context.Context, c config, client *http.Client, name, target string) (uint64, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, false
	}
	req.Header.Set("Authorization", "Bearer "+c.pollToken)
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil || resp.StatusCode != http.StatusOK {
		return 0, false
	}
	var b beat
	if json.Unmarshal(body, &b) != nil || !b.OK || b.Component != name {
		return 0, false
	}
	return b.Seq, true
}

func outageID(component string, lastOK int64, detected int64) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", component, lastOK, detected)))
	return hex.EncodeToString(h[:8])
}

func cycle(ctx context.Context, c config, client *http.Client, st *State) {
	now := time.Now().UnixNano()
	all := true
	for i := range st.Components {
		comp := &st.Components[i]
		seq, ok := poll(ctx, c, client, comp.Name, c.polls[comp.Name])
		if ok {
			comp.LastOKNS, comp.LastSeq = now, seq
			if comp.Status != "ok" {
				closeOutage(st, comp.Name, now)
			}
			comp.Status = "ok"
			continue
		}
		all = false
		since := comp.LastOKNS
		never := since == 0
		if never {
			since = st.StartedNS
		}
		if time.Duration(now-since) > c.missing && comp.Status != "missing" {
			comp.Status = "missing"
			o := Outage{ID: outageID(comp.Name, comp.LastOKNS, now), Component: comp.Name, LastOKNS: comp.LastOKNS, DetectedNS: now, NeverSeen: never}
			st.Outages = append(st.Outages, o)
			logEvent("missing", map[string]any{"component": comp.Name, "outage": o.ID})
		}
	}
	if all {
		st.Armed = true
	}
	st.LastCycle = now
	for i := range st.Outages {
		deliver(ctx, c, client, &st.Outages[i], now)
	}
}

// closeOutage closes the open outage of a component whose heartbeat is back: the
// outage and every attempt stay; one recovery notice is owed, once.
func closeOutage(st *State, name string, now int64) {
	for i := range st.Outages {
		o := &st.Outages[i]
		if o.Component == name && o.RecoveredNS == 0 {
			o.RecoveredNS = now
			logEvent("recovered", map[string]any{"component": name, "outage": o.ID})
		}
	}
}

// deliver makes at most one attempt per cycle for the one notice an outage
// owes: the alert first, then (after recovery) one recovery notice. Neither is
// repeated once accepted, and a restart does not repeat an accepted one.
func deliver(ctx context.Context, c config, client *http.Client, o *Outage, now int64) {
	kind := ""
	switch {
	case !o.Alerted:
		kind = "alert"
	case o.RecoveredNS != 0 && !o.Recovery:
		kind = "recovery"
	default:
		return
	}
	n := 0
	for _, a := range o.Attempts {
		if a.Kind == kind {
			n++
		}
	}
	if n >= c.maxAttempts {
		return
	}
	body, _ := json.Marshal(map[string]any{"observer": c.id, "kind": kind, "outage": o.ID, "component": o.Component, "last_ok_ns": o.LastOKNS, "detected_ns": o.DetectedNS, "recovered_ns": o.RecoveredNS})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.destination, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.delivToken)
	req.Header.Set("Idempotency-Key", o.ID+"-"+kind)
	a := Attempt{N: n + 1, AtNS: now, Kind: kind}
	resp, err := client.Do(req)
	switch {
	case err != nil:
		a.Error = "transport"
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			a.Error = "timeout"
		}
	default:
		a.Status = resp.StatusCode
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if a.Status >= 200 && a.Status < 300 {
			if kind == "alert" {
				o.Alerted = true
			} else {
				o.Recovery = true
			}
		} else {
			a.Error = "status"
		}
	}
	o.Attempts = append(o.Attempts, a)
	appendAttempt(c, o.ID, a)
	logEvent("attempt", map[string]any{"outage": o.ID, "kind": kind, "n": a.N, "status": a.Status, "error": a.Error})
}

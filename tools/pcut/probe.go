// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// probeLine is one probe of one voter. A readiness line (Q false) carries the /readyz answer; a read line (Q true) carries whether a
// complete PromQL read as the project reader was served and how long it took. The two are separate loops so a slow read never delays
// the next readiness probe.
type probeLine struct {
	T      int64  `json:"t"` // unix ms at the start of the probe
	Ep     string `json:"ep"`
	Q      bool   `json:"q,omitempty"` // a read line
	Code   int    `json:"code"`
	Ready  bool   `json:"ready"`
	Reason string `json:"reason,omitempty"`
	Role   string `json:"role,omitempty"`
	Leader uint64 `json:"leader,omitempty"`
	Term   uint64 `json:"term,omitempty"`
	Cursor string `json:"cursor,omitempty"`
	Err    string `json:"err,omitempty"`
	RMs    int64  `json:"rms,omitempty"`
	QOK    bool   `json:"qok"`
	QDet   string `json:"qdet,omitempty"`
	QMs    int64  `json:"qms,omitempty"`
	QN     int    `json:"qn,omitempty"` // series of the read (1 = the newest sample of w00 was served)
}

// runProbe asks every voter, every second, whether it is ready, and keeps one complete read going against each voter, and logs one
// JSON line per probe. It runs on a host that is never cut.
func runProbe(args []string) error {
	fl := flag.NewFlagSet("probe", flag.ContinueOnError)
	fixturePath := fl.String("fixture", "", "fixture file written by bootstrap")
	logPath := fl.String("log", "", "probe log (appended)")
	interval := fl.Duration("interval", time.Second, "readiness probe period")
	queryInterval := fl.Duration("query-interval", 2*time.Second, "least time between the starts of two reads of one voter")
	queryTimeout := fl.Duration("query-timeout", 25*time.Second, "a read that takes longer is a failed read (the service's own cap is 30 s)")
	pidFile := fl.String("pid-file", "", "file to write the process id to")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *fixturePath == "" || *logPath == "" || *interval < 200*time.Millisecond || *queryInterval < 200*time.Millisecond || *queryTimeout < time.Second {
		return errors.New("usage: pcut probe --fixture F --log L [--interval 1s] [--query-interval 2s] [--query-timeout 25s] [--pid-file F]")
	}
	fx, err := loadFixture(*fixturePath)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<16)
	var mu sync.Mutex
	emit := func(l probeLine) {
		raw, _ := json.Marshal(l)
		mu.Lock()
		w.Write(raw)
		w.WriteByte('\n')
		mu.Unlock()
	}
	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sig; close(stop) }()
	if *pidFile != "" {
		if err = os.WriteFile(*pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
			return err
		}
		defer removePidFile(*pidFile)
	}
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for n := 0; ; n++ {
			select {
			case <-stop:
				return
			case <-t.C:
				mu.Lock()
				_ = w.Flush()
				if n%10 == 0 {
					_ = f.Sync()
				}
				mu.Unlock()
			}
		}
	}()
	fmt.Printf("%s probe started pid=%d readiness every %s, a read every %s, endpoints=%d log=%s\n", time.Now().UTC().Format(time.RFC3339), os.Getpid(), *interval, *queryInterval, len(fx.Endpoints), *logPath)
	// every loop runs once per period, measured start to start (a probe longer than the period starts the next one at once)
	every := func(period time.Duration, probe func(start time.Time)) {
		for {
			start := time.Now()
			probe(start)
			wait := period - time.Since(start)
			if wait < 0 {
				wait = 0
			}
			select {
			case <-stop:
				return
			case <-time.After(wait):
			}
		}
	}
	var wg sync.WaitGroup
	for _, ep := range fx.Endpoints {
		s, err := newSite(ep.Name, ep.URL, fx.CA, true)
		if err != nil {
			return err
		}
		rd := newReader(s, fx)
		var down atomic.Bool // the last readiness probe of this voter failed: a read would only wait for its timeout
		wg.Add(2)
		go func() {
			defer wg.Done()
			every(*interval, func(start time.Time) {
				l := probeReady(ep.Name, s, start)
				down.Store(l.Code != 200 || !l.Ready)
				emit(l)
			})
		}()
		go func() {
			defer wg.Done()
			every(*queryInterval, func(start time.Time) { emit(probeRead(ep.Name, rd, start, *queryTimeout, &down)) })
		}()
	}
	wg.Wait()
	mu.Lock()
	_ = w.Flush()
	_ = f.Sync()
	mu.Unlock()
	return nil
}

func probeReady(name string, s *site, start time.Time) probeLine {
	r := s.readyz(1500 * time.Millisecond)
	return probeLine{T: start.UnixMilli(), Ep: name, Code: r.Code, Ready: r.Ready, Reason: r.Reason, Role: r.Role, Leader: r.Leader, Term: r.Term, Cursor: r.Applied, Err: r.Err, RMs: time.Since(start).Milliseconds()}
}

// probeRead is one complete read of the last 15 seconds of every series. The window is short on purpose: the service scans every record of a
// query's time range whatever the selector (a 5-minute window took 1.3 s with ~4,800 records, a 10-second one 0.28 s), so a long window
// would make the probe itself the load.
func probeRead(name string, rd *reader, start time.Time, timeout time.Duration, down *atomic.Bool) probeLine {
	l := probeLine{T: start.UnixMilli(), Ep: name, Q: true}
	if down.Load() {
		l.QDet = "skipped_not_ready"
		return l
	}
	status, raw, err := rd.query(fmt.Sprintf(`last_over_time(%s[15s])`, metricName), time.Now(), timeout)
	l.QMs = time.Since(start).Milliseconds()
	if err != nil {
		l.QDet = errDetail(err)
		return l
	}
	v, err := completeValue(status, raw)
	if err != nil {
		l.QDet = err.Error()
		return l
	}
	l.QOK, l.QDet, l.QN = true, "complete", len(v.Vector)
	return l
}

// errDetail is a closed description of a failed read: a login refusal keeps its text (it carries no secret), a transport error its class.
func errDetail(err error) string {
	if strings.HasPrefix(err.Error(), "login: ") {
		return err.Error()
	}
	return transportClass(err)
}

// removePidFile removes a pid file only while it still names this process (a restarted instance may have written its own already).
func removePidFile(path string) {
	if raw, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(raw)) == strconv.Itoa(os.Getpid()) {
		_ = os.Remove(path)
	}
}

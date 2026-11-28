// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// runGen is the continuous ingest load with the durable-ACK journal. Every batch is ONE metric record of one series whose value is
// the series' next sequence number. The journal line "issue" (id, series, sequence number, observed time) is fsynced before the
// first send and the line "ack" (receipt) is fsynced before the writer counts the acknowledgement or sends its next batch, so the
// journal never contains an ACK the cluster did not give and never lacks one the generator acted on. An unacknowledged batch is
// resent with the IDENTICAL body (same id) to the voters in turn until it is acknowledged: the original dedup identity makes the
// answer the original receipt, never a second copy.
func runGen(args []string) error {
	fl := flag.NewFlagSet("gen", flag.ContinueOnError)
	fixturePath := fl.String("fixture", "", "fixture file written by bootstrap")
	journalPath := fl.String("journal", "", "ACK journal file to create (must not exist)")
	rate := fl.Float64("rate", 2, "batches per second over all writers")
	writers := fl.Int("writers", 4, "concurrent writers")
	records := fl.Int("records", 8, "records (samples of ONE series) per batch")
	stopFile := fl.String("stop-file", "", "when this file exists the generator drains and exits")
	pidFile := fl.String("pid-file", "", "file to write the process id to")
	drain := fl.Duration("drain", 10*time.Minute, "how long the generator keeps resending in-flight batches after a stop request")
	attempt := fl.Duration("attempt-timeout", 6*time.Second, "timeout of one ingest attempt")
	statsPath := fl.String("stats", "", "append a stats line every 10 s to this file")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *fixturePath == "" || *journalPath == "" || *rate <= 0 || *writers < 1 || *records < 1 || *records > 100 {
		return errors.New("usage: pcut gen --fixture F --journal J [--rate 2] [--writers 4] [--records 8] [--stop-file F] [--pid-file F] [--drain 10m] [--stats F]")
	}
	fx, err := loadFixture(*fixturePath)
	if err != nil {
		return err
	}
	ids, err := fx.ids()
	if err != nil {
		return err
	}
	if *writers > len(fx.Series) {
		*writers = len(fx.Series)
	}
	j, err := createJournal(*journalPath)
	if err != nil {
		return err
	}
	g := &gen{fx: fx, ids: ids, j: j, attemptTimeout: *attempt, records: *records, stopCh: make(chan struct{})}
	for _, ep := range fx.Endpoints {
		s, err := newSite(ep.Name, ep.URL, fx.CA, false)
		if err != nil {
			return err
		}
		g.eps = append(g.eps, &genEndpoint{ep: ep, site: s})
	}
	producers := make([]model.ID, *writers)
	pstr := make([]string, *writers)
	for i := range producers {
		producers[i] = model.NewID()
		pstr[i] = producers[i].String()
	}
	host, _ := os.Hostname()
	info, _ := json.Marshal(map[string]any{"host": host, "pid": os.Getpid(), "rate": *rate, "writers": *writers, "series": fx.Series, "producers": pstr, "endpoints": fx.Endpoints, "metric": metricName})
	if err = j.Append(entry{T: "start", At: time.Now().UnixNano(), Info: info}); err != nil {
		return err
	}
	if *pidFile != "" {
		if err = os.WriteFile(*pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
			return err
		}
		defer removePidFile(*pidFile)
	}
	fmt.Printf("%s gen started pid=%d rate=%.1f batches/s x %d records writers=%d series=%d endpoints=%d journal=%s\n", time.Now().UTC().Format(time.RFC3339), os.Getpid(), *rate, *records, *writers, len(fx.Series), len(g.eps), *journalPath)

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		g.beginStop(*drain, "signal")
	}()
	if *stopFile != "" {
		go func() {
			for {
				if _, err := os.Stat(*stopFile); err == nil {
					g.beginStop(*drain, "stop file")
					return
				}
				select {
				case <-g.stopCh:
					return
				case <-time.After(time.Second):
				}
			}
		}()
	}
	var stats *os.File
	if *statsPath != "" {
		if stats, err = os.OpenFile(*statsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err != nil {
			return err
		}
		defer stats.Close()
	}
	finished := make(chan struct{})
	go g.report(stats, finished)

	interval := time.Duration(float64(time.Second) * float64(*writers) / *rate)
	var wg sync.WaitGroup
	for k := range *writers {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			g.writer(k, *writers, producers[k], interval)
		}(k)
	}
	wg.Wait()
	close(finished)
	if g.fatal.Load() != nil {
		return *g.fatal.Load()
	}
	final, _ := json.Marshal(g.counters())
	if err = j.Append(entry{T: "end", At: time.Now().UnixNano(), Info: final}); err != nil {
		return err
	}
	if err = j.Close(); err != nil {
		return err
	}
	fmt.Printf("%s gen ended %s\n", time.Now().UTC().Format(time.RFC3339), final)
	if g.lost.Load() > 0 || g.rejected.Load() > 0 {
		return fmt.Errorf("generator ended with %d unresolved and %d rejected batches", g.lost.Load(), g.rejected.Load())
	}
	return nil
}

type genEndpoint struct {
	ep        Endpoint
	site      *site
	downUntil atomic.Int64
	attempts  atomic.Int64
	acks      atomic.Int64
	transport atomic.Int64
	refusals  atomic.Int64
}

type gen struct {
	fx             *Fixture
	ids            fixtureIDs
	j              *journal
	eps            []*genEndpoint
	attemptTimeout time.Duration
	records        int

	stopCh   chan struct{}
	stopOnce sync.Once
	stopping atomic.Bool
	drainBy  atomic.Int64 // unix ns after which an unacknowledged batch is given up (only once stopping)
	rr       atomic.Uint64
	fatal    atomic.Pointer[error]

	issued, acked, rejected, lost, resent atomic.Int64
}

func (g *gen) beginStop(drain time.Duration, why string) {
	g.stopOnce.Do(func() {
		g.drainBy.Store(time.Now().Add(drain).UnixNano())
		g.stopping.Store(true)
		close(g.stopCh)
		fmt.Printf("%s gen stop requested (%s); draining in-flight batches for at most %s\n", time.Now().UTC().Format(time.RFC3339), why, drain)
	})
}

func (g *gen) failJournal(err error) {
	e := fmt.Errorf("journal: %w", err)
	g.fatal.Store(&e)
	g.beginStop(0, "journal failure")
}

func (g *gen) counters() map[string]any {
	eps := map[string]any{}
	for _, e := range g.eps {
		eps[e.ep.Name] = map[string]int64{"attempts": e.attempts.Load(), "acks": e.acks.Load(), "transport_failures": e.transport.Load(), "typed_refusals": e.refusals.Load()}
	}
	return map[string]any{"issued": g.issued.Load(), "acked": g.acked.Load(), "rejected": g.rejected.Load(), "lost": g.lost.Load(), "resent_attempts": g.resent.Load(), "endpoints": eps}
}

func (g *gen) report(stats *os.File, finished <-chan struct{}) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-finished:
			return
		case <-t.C:
			line, _ := json.Marshal(map[string]any{"t": time.Now().UnixMilli(), "counters": g.counters()})
			fmt.Printf("%s %s\n", time.Now().UTC().Format(time.RFC3339), line)
			if stats != nil {
				_, _ = stats.Write(append(line, '\n'))
			}
		}
	}
}

// writer k owns the series k, k+writers, k+2*writers... and sends them in turn, one batch at a time, so a series never has two
// batches in flight and its observed times increase with its sequence numbers.
func (g *gen) writer(k, writers int, producer model.ID, interval time.Duration) {
	var mine []string
	for i := k; i < len(g.fx.Series); i += writers {
		mine = append(mine, g.fx.Series[i])
	}
	next := map[string]uint64{}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	// stagger the writers so they do not all fire in the same instant
	select {
	case <-g.stopCh:
		return
	case <-time.After(time.Duration(k) * interval / time.Duration(writers)):
	}
	for i := 0; ; i++ {
		select {
		case <-g.stopCh:
			return
		case <-tick.C:
		}
		series := mine[i%len(mine)]
		first := next[series] + 1
		next[series] += uint64(g.records)
		g.one(producer, series, first)
	}
}

func (g *gen) one(producer model.ID, series string, n uint64) {
	// the batch's records are g.records consecutive sequence numbers of one series, observed 1 ms apart and ending now
	ts := time.Now().UnixNano() - int64(g.records-1)*int64(time.Millisecond)
	batch, body, err := g.build(producer, series, n, ts)
	if err != nil {
		e := fmt.Errorf("build: %w", err)
		g.fatal.Store(&e)
		g.beginStop(0, "build failure")
		return
	}
	id := batch.ID.String()
	if err = g.j.Append(entry{T: "issue", At: time.Now().UnixNano(), W: series, N: n, Cnt: g.records, ID: id, Ts: ts}); err != nil {
		g.failJournal(err)
		return
	}
	g.issued.Add(1)
	res := g.deliver(batch.ID, body)
	switch res.verdict {
	case vAcked:
		raw, _ := json.Marshal(res.receipt)
		if err = g.j.Append(entry{T: "ack", At: time.Now().UnixNano(), W: series, N: n, Cnt: g.records, ID: id, Member: res.member, Started: res.started, Attempts: res.attempts, Receipt: raw}); err != nil {
			g.failJournal(err)
			return
		}
		g.acked.Add(1)
	case vRejected, vMalformed:
		g.rejected.Add(1)
		_ = g.j.Append(entry{T: "reject", At: time.Now().UnixNano(), W: series, N: n, ID: id, Member: res.member, Attempts: res.attempts, Detail: res.detail})
		fmt.Printf("%s rejected batch %s: %s\n", time.Now().UTC().Format(time.RFC3339), id, res.detail)
	default:
		g.lost.Add(1)
		_ = g.j.Append(entry{T: "lost", At: time.Now().UnixNano(), W: series, N: n, ID: id, Attempts: res.attempts, Detail: res.detail})
	}
}

func (g *gen) build(producer model.ID, series string, n uint64, ts int64) (model.Batch, []byte, error) {
	resource := model.Resource{Service: g.ids.service, Environment: g.ids.environment, Build: g.ids.build, Instance: "instance", Labels: model.Labels{}}
	records := make([]model.Record, g.records)
	for i := range records {
		value := model.FloatBits(math.Float64bits(float64(n + uint64(i))))
		records[i] = model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(ts + int64(i)*int64(time.Millisecond)), Resource: resource,
			Payload: model.Payload{Metric: &model.MetricPoint{Name: metricName, Labels: model.Labels{{Name: seriesLabel, Value: series}}, SampleKind: "float", Value: &value, Unit: "1", Type: "gauge"}}}
	}
	batch := model.Batch{Version: 1, Project: g.ids.project, Source: g.ids.source, Producer: producer, ID: model.NewID(), PolicyRevision: 1, Records: records}
	slot, err := model.OwnerSlot(g.ids.org, g.ids.project, g.ids.source, batch.Producer, records[0])
	if err != nil {
		return batch, nil, err
	}
	batch.RouteSlot = slot
	body, err := json.Marshal(batch)
	return batch, body, err
}

type delivery struct {
	verdict  verdict
	detail   string
	receipt  model.Receipt
	member   string
	started  int64
	attempts int
}

// deliver sends the identical body to the voters in turn until one acknowledges it. A voter that failed is left alone for a few
// seconds so a powered-off one costs one timeout, not one per batch.
func (g *gen) deliver(id model.ID, body []byte) delivery {
	d := delivery{started: time.Now().UnixNano()}
	for {
		start := int(g.rr.Add(1))
		tried := false
		for k := range len(g.eps) {
			e := g.eps[(start+k)%len(g.eps)]
			now := time.Now().UnixNano()
			if now < e.downUntil.Load() {
				continue
			}
			tried = true
			d.attempts++
			if d.attempts > 1 {
				g.resent.Add(1)
			}
			e.attempts.Add(1)
			status, raw, err := e.site.do("POST", "/ingest/v1/batches", body, g.attemptTimeout, "", g.fx.Credential)
			v, detail, receipt := classifyIngest(status, raw, err, id)
			switch v {
			case vAcked:
				e.acks.Add(1)
				d.verdict, d.detail, d.receipt, d.member = vAcked, detail, receipt, e.ep.Name
				return d
			case vRefusal:
				e.refusals.Add(1)
				e.downUntil.Store(time.Now().Add(time.Second).UnixNano())
				d.detail = detail
			case vTransport:
				e.transport.Add(1)
				e.downUntil.Store(time.Now().Add(3 * time.Second).UnixNano())
				d.detail = detail
			default:
				d.verdict, d.detail, d.member = v, detail, e.ep.Name
				return d
			}
		}
		if g.stopping.Load() && time.Now().UnixNano() > g.drainBy.Load() {
			d.verdict = "lost"
			return d
		}
		if tried {
			time.Sleep(150 * time.Millisecond)
		} else {
			time.Sleep(250 * time.Millisecond)
		}
	}
}

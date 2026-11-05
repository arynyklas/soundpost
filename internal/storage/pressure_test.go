// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/model"
)

type fakeMeter struct {
	mu         sync.Mutex
	total, use uint64
	err        error
}

func (m *fakeMeter) set(used uint64) { m.mu.Lock(); m.use = used; m.mu.Unlock() }
func (m *fakeMeter) fail(err error)  { m.mu.Lock(); m.err = err; m.mu.Unlock() }
func (m *fakeMeter) Usage(string) (DiskUsage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return DiskUsage{}, m.err
	}
	return DiskUsage{TotalBytes: m.total, UsedBytes: m.use}, nil
}

func pressureConfig(clock *time.Time) PressureConfig {
	c := DefaultPressureConfig()
	c.ReservedConsensusBytes, c.ReservedAuditBytes, c.Interval = 0, 0, 0
	c.Now = func() time.Time { *clock = clock.Add(time.Second); return *clock }
	return c
}

func requireCapacity(t *testing.T, err error) {
	t.Helper()
	var f *model.Fault
	if !errors.As(err, &f) || f.Code != model.Unavailable || !f.Retryable || f.SafeDetail != "capacity" {
		t.Fatalf("want retryable unavailable/capacity, got %v", err)
	}
}

func TestDiskPressureBindValidation(t *testing.T) {
	var clock time.Time
	e := &Engine{}
	m := &fakeMeter{total: 1000}
	if err := e.BindPressure(t.TempDir(), nil, pressureConfig(&clock)); err == nil {
		t.Fatal("nil meter accepted")
	}
	for _, bad := range [][3]uint8{{0, 90, 95}, {90, 90, 95}, {80, 95, 95}, {80, 90, 101}, {80, 90, 80}} {
		c := pressureConfig(&clock)
		c.WarnPercent, c.LowPercent, c.DenyPercent = bad[0], bad[1], bad[2]
		if err := e.BindPressure(t.TempDir(), m, c); err == nil {
			t.Fatalf("thresholds %v accepted", bad)
		}
	}
	if err := e.BindPressure(t.TempDir(), m, pressureConfig(&clock)); err != nil {
		t.Fatal(err)
	}
	if err := e.BindPressure(t.TempDir(), m, pressureConfig(&clock)); err == nil {
		t.Fatal("rebind accepted")
	}
}

func TestDiskPressureLevelBoundaries(t *testing.T) {
	var clock time.Time
	m := &fakeMeter{total: 1000}
	e := &Engine{}
	if err := e.BindPressure(t.TempDir(), m, pressureConfig(&clock)); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		used  uint64
		level PressureLevel
	}{{790, PressureNormal}, {799, PressureNormal}, {800, PressureWarn}, {899, PressureWarn}, {900, PressureDenyLow}, {949, PressureDenyLow}, {950, PressureDenyAll}, {1000, PressureDenyAll}} {
		m.set(c.used)
		st, err := e.ObservePressure(context.Background())
		if err != nil || st.Level != c.level || uint64(st.UsedPercent) != c.used/10 {
			t.Fatalf("used %d: level %d pct %d err %v, want level %d", c.used, st.Level, st.UsedPercent, err, c.level)
		}
	}
}

func TestDiskPressureHysteresis(t *testing.T) {
	var clock time.Time
	m := &fakeMeter{total: 1000}
	e := &Engine{}
	if err := e.BindPressure(t.TempDir(), m, pressureConfig(&clock)); err != nil {
		t.Fatal(err)
	}
	m.set(960)
	e.ObservePressure(context.Background())
	for _, c := range []struct {
		used  uint64
		level PressureLevel
	}{{940, PressureDenyAll}, {930, PressureDenyAll}, {929, PressureDenyLow}, {880, PressureDenyLow}, {879, PressureWarn}, {780, PressureWarn}, {779, PressureNormal}} {
		m.set(c.used)
		st, err := e.ObservePressure(context.Background())
		if err != nil || st.Level != c.level {
			t.Fatalf("used %d: level %d want %d (%v)", c.used, st.Level, c.level, err)
		}
	}
}

func TestDiskPressureAdmissionClasses(t *testing.T) {
	var clock time.Time
	m := &fakeMeter{total: 1000}
	e := &Engine{}
	if err := e.BindPressure(t.TempDir(), m, pressureConfig(&clock)); err != nil {
		t.Fatal(err)
	}
	m.set(850)
	if e.admitPressure(ClassLow, 1) != nil || e.admitPressure(ClassNormal, 1) != nil {
		t.Fatal("warn level must admit everything")
	}
	m.set(900)
	requireCapacity(t, e.admitPressure(ClassLow, 1))
	if err := e.admitPressure(ClassNormal, 1); err != nil {
		t.Fatalf("normal denied at 90%%: %v", err)
	}
	m.set(950)
	requireCapacity(t, e.admitPressure(ClassLow, 1))
	requireCapacity(t, e.admitPressure(ClassNormal, 1))
	st := e.PressureStatus()
	if st.DeniedLow != 1 || st.DeniedAll != 2 {
		t.Fatalf("counters low=%d all=%d", st.DeniedLow, st.DeniedAll)
	}
}

func TestDiskPressureBatchClass(t *testing.T) {
	r := func(k model.Kind) model.Record { return model.Record{Kind: k} }
	if batchClass([]model.Record{r(model.SpanKind), r(model.Replay), r(model.Profile)}) != ClassLow {
		t.Fatal("span/replay/profile batch must be low")
	}
	if batchClass([]model.Record{r(model.SpanKind), r(model.Metric)}) != ClassNormal {
		t.Fatal("mixed batch must be normal")
	}
	if batchClass([]model.Record{r(model.ErrorKind)}) != ClassNormal || batchClass([]model.Record{r(model.Loss)}) != ClassNormal {
		t.Fatal("error/loss batches must be normal")
	}
}

func TestDiskPressureReserveRespected(t *testing.T) {
	var clock time.Time
	m := &fakeMeter{total: 1000, use: 500}
	e := &Engine{}
	c := pressureConfig(&clock)
	c.ReservedConsensusBytes, c.ReservedAuditBytes = 100, 100
	if err := e.BindPressure(t.TempDir(), m, c); err != nil {
		t.Fatal(err)
	}
	if err := e.admitPressure(ClassNormal, 300); err != nil {
		t.Fatalf("batch fitting beside reserve denied: %v", err)
	}
	requireCapacity(t, e.admitPressure(ClassNormal, 301))
}

func TestDiskPressureAppendDeniedThenRecovers(t *testing.T) {
	store, a, c, d := fixture(t)
	scope, b := normalized(t, store, a, c, d)
	engine, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	var clock time.Time
	m := &fakeMeter{total: 1000, use: 960}
	if err = engine.BindPressure(t.TempDir(), m, pressureConfig(&clock)); err != nil {
		t.Fatal(err)
	}
	receipt, err := engine.Append(context.Background(), scope, b)
	requireCapacity(t, err)
	if receipt.Cursor.Index != 0 {
		t.Fatal("denied batch carries a cursor")
	}
	if n := engine.indexes[b.RouteSlot]; n != 0 {
		t.Fatalf("denied batch consumed an index: %d", n)
	}
	m.set(100)
	if receipt, err = engine.Append(context.Background(), scope, b); err != nil || receipt.Cursor.Index != 1 {
		t.Fatalf("recovered append: %v %+v", err, receipt)
	}
	codes := []string{}
	for _, w := range engine.PressureStatus().Warnings {
		codes = append(codes, w.Code)
	}
	if strings.Join(codes, ",") != "disk_deny_all,disk_recovered" {
		t.Fatalf("warnings %v", codes)
	}
}

func TestDiskPressureACKedRetryAndDataSurviveFullDisk(t *testing.T) {
	store, a, c, d := fixture(t)
	scope, b := normalized(t, store, a, c, d)
	engine, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	var clock time.Time
	m := &fakeMeter{total: 1000}
	if err = engine.BindPressure(t.TempDir(), m, pressureConfig(&clock)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	original, err := engine.Append(ctx, scope, b)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func() (int, []byte, []byte) {
		var pages int
		var receipts, batches []byte
		engine.db.View(func(tx *bolt.Tx) error {
			pages = tx.Bucket([]byte("scan_pages")).Stats().KeyN
			tx.Bucket([]byte("receipts")).ForEach(func(k, v []byte) error { receipts = append(append(receipts, k...), v...); return nil })
			tx.Bucket([]byte("batches")).ForEach(func(k, v []byte) error { batches = append(append(batches, k...), v...); return nil })
			return nil
		})
		return pages, receipts, batches
	}
	pages, receipts, batches := snapshot()
	if pages == 0 || len(batches) == 0 {
		t.Fatal("fixture wrote no indexed data")
	}
	for _, used := range []uint64{800, 950, 1000, 950, 800, 0} {
		m.set(used)
		if used >= 950 {
			_, other := normalized(t, store, a, c, d)
			if _, err = engine.Append(ctx, scope, other); err == nil {
				t.Fatalf("new batch admitted at %d", used)
			}
		}
		got, err := engine.Append(ctx, scope, b)
		if err != nil || string(mustJSON(t, got)) != string(mustJSON(t, original)) {
			t.Fatalf("retry at %d: %v", used, err)
		}
		p2, r2, b2 := snapshot()
		if p2 != pages || !bytes.Equal(r2, receipts) || !bytes.Equal(b2, batches) {
			t.Fatalf("stored data changed at %d%%", used/10)
		}
	}
}

func TestDiskPressureCancelStillWorksAtFullDisk(t *testing.T) {
	store, a, c, d := fixture(t)
	scope, b := normalized(t, store, a, c, d)
	engine, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	var clock time.Time
	m := &fakeMeter{total: 1000, use: 1000}
	if err = engine.BindPressure(t.TempDir(), m, pressureConfig(&clock)); err != nil {
		t.Fatal(err)
	}
	if _, err = engine.Cancel(context.Background(), scope, b.Reservation); err != nil {
		t.Fatalf("maintenance write blocked by pressure: %v", err)
	}
}

func TestDiskPressureMeterFailureFailsClosed(t *testing.T) {
	store, a, c, d := fixture(t)
	scope, b := normalized(t, store, a, c, d)
	engine, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	var clock time.Time
	m := &fakeMeter{total: 1000}
	if err = engine.BindPressure(t.TempDir(), m, pressureConfig(&clock)); err != nil {
		t.Fatal(err)
	}
	m.fail(errors.New("statfs broke"))
	if _, err = engine.Append(context.Background(), scope, b); err == nil {
		t.Fatal("append admitted without a working meter")
	}
	var f *model.Fault
	if !errors.As(err, &f) || f.Code != model.Unavailable {
		t.Fatalf("want unavailable, got %v", err)
	}
	if _, err = engine.ObservePressure(context.Background()); err == nil {
		t.Fatal("observe hid the meter failure")
	}
	m.fail(nil)
	if _, err = engine.Append(context.Background(), scope, b); err != nil {
		t.Fatalf("meter recovery should admit: %v", err)
	}
}

func TestDiskPressureWarningsBoundedOrderedAndPrivate(t *testing.T) {
	store, a, _, d := fixture(t)
	engine, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	var clock time.Time
	m := &fakeMeter{total: 1000}
	if err = engine.BindPressure(t.TempDir(), m, pressureConfig(&clock)); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		m.set(1000)
		engine.ObservePressure(context.Background())
		m.set(0)
		engine.ObservePressure(context.Background())
	}
	w := engine.PressureStatus().Warnings
	if len(w) != 64 {
		t.Fatalf("ring size %d", len(w))
	}
	for i := 1; i < len(w); i++ {
		if w[i].Seq != w[i-1].Seq+1 || w[i].At <= w[i-1].At {
			t.Fatalf("not ordered oldest first at %d", i)
		}
	}
	if w[len(w)-1].Seq != 200 || w[len(w)-1].Code != "disk_recovered" || w[len(w)-2].Code != "disk_deny_all" {
		t.Fatalf("tail %+v", w[len(w)-2:])
	}
	if raw := string(mustJSON(t, w)); strings.Contains(raw, d.Org.String()) || strings.Contains(raw, d.Project.String()) {
		t.Fatal("warning carries tenant data")
	}
}

func TestDiskPressureWriteBlobDeniedThenAdmitted(t *testing.T) {
	c, a, scope, mf, raw := blobFixture(t)
	engine, err := openTestEngine(t, t.TempDir(), a, c)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	var clock time.Time
	m := &fakeMeter{total: 1 << 30, use: (1 << 30) / 100 * 96}
	if err = engine.BindPressure(t.TempDir(), m, pressureConfig(&clock)); err != nil {
		t.Fatal(err)
	}
	_, err = engine.WriteBlob(context.Background(), scope, mf, bytes.NewReader(raw))
	requireCapacity(t, err)
	engine.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("artifact_roots")).Stats().KeyN != 0 || tx.Bucket([]byte("artifact_fragments")).Stats().KeyN != 0 {
			t.Fatal("denied blob left bytes behind")
		}
		return nil
	})
	m.set(0)
	if _, err = engine.WriteBlob(context.Background(), scope, mf, bytes.NewReader(raw)); err != nil {
		t.Fatalf("admission did not reopen: %v", err)
	}
}

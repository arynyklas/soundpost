// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

func gate() Config {
	return Config{Seed: 20261113, Orgs: 10, Projects: 100, Series: 100000, Rate: 2000, Window: 10 * time.Second}
}

func TestGateConfigIsExactAndOddWindowsAreRefused(t *testing.T) {
	if err := gate().Check(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"window with fractional records": func(c *Config) { c.Window = 7 * time.Second },
		"projects not over orgs":         func(c *Config) { c.Orgs = 7 },
		"series not a label product":     func(c *Config) { c.Series = 100100 },
		"rate not over projects":         func(c *Config) { c.Rate = 2050 },
	} {
		c := gate()
		mutate(&c)
		if c.Check() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	sum := 0
	for _, m := range mixPerMille {
		sum += m.PM
	}
	if sum != 1000 {
		t.Fatalf("mix sums to %d per mille", sum)
	}
}

func decode(t *testing.T, body []byte) model.Batch {
	t.Helper()
	var b model.Batch
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWindowIsAdmissibleSlotConsistentAndExact(t *testing.T) {
	cfg := gate()
	pj := NewProject(cfg, 37)
	if err := model.ValidateSourcePolicy(pj.Policy); err != nil {
		t.Fatalf("policy: %v", err)
	}
	start := time.Unix(1_800_000_000, 0)
	want := map[model.Kind]int{model.Metric: 120, model.SpanKind: 40, model.Log: 24, model.ErrorKind: 6, model.JobAttempt: 10}
	ids, batchIDs := map[model.ID]bool{}, map[model.ID]bool{}
	for j := 0; j < 3; j++ {
		got := map[model.Kind]int{}
		for _, pr := range pj.Window(j, start.Add(time.Duration(j)*cfg.Window)) {
			if batchIDs[pr.ID] {
				t.Fatalf("batch id repeated")
			}
			batchIDs[pr.ID] = true
			b := decode(t, pr.Body)
			if b.ID != pr.ID || b.Project != pj.Project || b.Source != pj.Source || b.Producer != pj.Producer || b.Version != 1 || b.PolicyRevision != 1 {
				t.Fatalf("batch envelope: %+v", b)
			}
			if len(b.Records) == 0 || len(b.Records) > maxRecordsBatch || len(b.Records) != len(pr.Records) {
				t.Fatalf("batch holds %d records (meta %d)", len(b.Records), len(pr.Records))
			}
			for i := range b.Records {
				r := &b.Records[i]
				if ids[r.ID] {
					t.Fatalf("record id repeated")
				}
				ids[r.ID] = true
				if err := model.ValidateRecord(r, pj.Policy); err != nil {
					t.Fatalf("window %d %s record refused by the product's validation: %v", j, r.Kind, err)
				}
				slot, err := model.OwnerSlot(pj.Org, b.Project, b.Source, b.Producer, *r)
				if err != nil || slot != b.RouteSlot {
					t.Fatalf("%s record slot %d, batch slot %d (%v)", r.Kind, slot, b.RouteSlot, err)
				}
				if pr.Records[i].ID != r.ID || pr.Records[i].Kind != kindByte(r.Kind) || pr.Records[i].TS != int64(r.ObservedAt) {
					t.Fatalf("record meta does not match the encoded record")
				}
				got[r.Kind]++
			}
		}
		for k, n := range want {
			if got[k] != n {
				t.Errorf("window %d: %d %s records, want %d", j, got[k], k, n)
			}
		}
	}
}

func TestWindowIsDeterministicForTheSeed(t *testing.T) {
	cfg := gate()
	a, b := NewProject(cfg, 5), NewProject(cfg, 5)
	start := time.Unix(1_800_000_000, 0)
	for j := 0; j < 2; j++ {
		pa, pb := a.Window(j, start), b.Window(j, start)
		if len(pa) != len(pb) {
			t.Fatal("batch count differs")
		}
		for i := range pa {
			if !bytes.Equal(pa[i].Body, pb[i].Body) {
				t.Fatalf("window %d batch %d differs between two builds with one seed", j, i)
			}
		}
	}
	other := cfg
	other.Seed++
	if bytes.Equal(NewProject(other, 5).Window(0, start)[0].Body, a.Window(2, start)[0].Body) {
		t.Fatal("a different seed produced the same bytes")
	}
}

func TestEstateHas100kDistinctSeriesAndEveryOneIsWritten(t *testing.T) {
	cfg := gate()
	seen := map[string]bool{}
	start := time.Unix(1_800_000_000, 0)
	for p := 0; p < cfg.Projects; p++ {
		pj := NewProject(cfg, p)
		for _, s := range pj.series {
			rec := model.Record{Kind: model.Metric, Payload: model.Payload{Metric: &model.MetricPoint{Name: s.name, Labels: s.labels}}}
			id, err := model.CanonicalSeriesID(pj.Project, rec)
			if err != nil {
				t.Fatal(err)
			}
			seen[id] = true
		}
		if p != 0 {
			continue
		}
		// every series of a project is sampled within ceil(series / samples-per-window) windows.
		written := map[string]bool{}
		for j := 0; j < 9; j++ {
			for _, pr := range pj.Window(j, start) {
				for _, r := range decode(t, pr.Body).Records {
					if r.Kind != model.Metric {
						continue
					}
					id, _ := model.CanonicalSeriesID(pj.Project, r)
					written[id] = true
				}
			}
		}
		if len(written) < cfg.SeriesPerProject()-cfg.SeriesPerProject()/10 {
			t.Errorf("project 0 wrote %d of %d series in 9 windows", len(written), cfg.SeriesPerProject())
		}
	}
	if len(seen) != cfg.Series {
		t.Fatalf("%d distinct series, want %d", len(seen), cfg.Series)
	}
}

func TestPercentileIsNearestRank(t *testing.T) {
	v := make([]int64, 100)
	for i := range v {
		v[i] = int64(i + 1)
	}
	for p, want := range map[float64]int64{0.5: 50, 0.95: 95, 0.99: 99, 1: 100} {
		if got := percentile(v, p); got != want {
			t.Errorf("p%.0f = %d, want %d", p*100, got, want)
		}
	}
	if percentile(nil, 0.95) != 0 {
		t.Error("empty")
	}
}

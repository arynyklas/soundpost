// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package queryinput_test

import (
	"bytes"
	"path/filepath"
	"reflect"
	"testing"

	. "github.com/arynyklas/soundpost/internal/adapters/queryinput"
	"github.com/arynyklas/soundpost/internal/model"
)

func identitiesOf(batches []model.Batch) (batchIDs []model.ID, recordIDs []model.ID) {
	for _, b := range batches {
		batchIDs = append(batchIDs, b.ID)
		for _, r := range b.Records {
			recordIDs = append(recordIDs, r.ID)
		}
	}
	return batchIDs, recordIDs
}

// A scrape of an exporter whose text did not change is a different request every
// time: its samples take the scrape time as their time, so two scrapes must not
// share a batch or record identifier (a receipt ledger would see one identifier
// with different observed times). A retry of one scrape (the same body and the
// same scrape time) keeps its identifiers.
func TestOpenMetricsScrapeTimeIsPartOfTheRequestIdentity(t *testing.T) {
	e := newRealEnv(t)
	body := realFile(t, "fixture-exposition.om")
	decode := func(at model.UnixNano) ([]model.ID, []model.ID) {
		t.Helper()
		cfg := e.cfg
		cfg.Exemplars = ExemplarsTraceLink
		cfg.DefaultTimestamp = at
		batches, err := DecodeOpenMetrics(t.Context(), e.g, bytes.NewReader(body), cfg)
		if err != nil || len(batches) == 0 {
			t.Fatalf("decode at %d: %d batches, %v", at, len(batches), err)
		}
		return identitiesOf(batches)
	}
	const t1, t2 = model.UnixNano(1_700_000_100_000_000_000), model.UnixNano(1_700_000_115_000_000_000)
	b1, r1 := decode(t1)
	b1again, r1again := decode(t1)
	if !reflect.DeepEqual(b1, b1again) || !reflect.DeepEqual(r1, r1again) {
		t.Fatal("a retry of one scrape changed its identifiers")
	}
	b2, r2 := decode(t2)
	if len(b2) != len(b1) || len(r2) != len(r1) {
		t.Fatalf("shape changed with the scrape time: %d/%d batches, %d/%d records", len(b1), len(b2), len(r1), len(r2))
	}
	for i := range b1 {
		if b1[i] == b2[i] {
			t.Errorf("batch %d: two scrapes of unchanged text share batch id %s", i, b1[i])
		}
	}
	for i := range r1 {
		if r1[i] == r2[i] {
			t.Errorf("record %d: two scrapes of unchanged text share record id %s", i, r1[i])
		}
	}
}

// The scrape time is not part of the identity of a request that never reads it:
// a retried remote-write push keeps its identifiers whatever time it arrives.
func TestRemoteWriteIdentityDoesNotDependOnTheDefaultTimestamp(t *testing.T) {
	e := newRealEnv(t)
	checked := 0
	for _, f := range realFiles(t, "rw-v1-*.bin") {
		body := realFile(t, filepath.Base(f))
		var ids [2][]model.ID
		var recs [2][]model.ID
		ok := true
		for i, at := range []model.UnixNano{1_700_000_100_000_000_000, 1_700_000_200_000_000_000} {
			cfg := e.cfg
			cfg.DefaultTimestamp = at
			batches, err := e.rw(t, RemoteWriteV1, body, cfg)
			if err != nil || len(batches) == 0 {
				ok = false
				break
			}
			ids[i], recs[i] = identitiesOf(batches)
		}
		if !ok {
			continue
		}
		checked++
		if !reflect.DeepEqual(ids[0], ids[1]) || !reflect.DeepEqual(recs[0], recs[1]) {
			t.Fatalf("%s: a retried push changed its identifiers with the arrival time", f)
		}
	}
	if checked == 0 {
		t.Fatal("no remote-write fixture decoded")
	}
}

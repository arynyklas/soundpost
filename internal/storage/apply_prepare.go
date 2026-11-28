// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"encoding/json"

	"github.com/arynyklas/soundpost/internal/model"
)

// batchPrep is what the apply of a batch derives from the batch and its receipt alone: the canonical
// bytes and keys of its metric samples, the JSON the batch, its receipt and its consumed reservation are
// stored as, and the index rows of its records (builtIndex). The bolt commit that carries the apply holds
// the single write lock of apply.db while the records of every append in it are encoded and hashed; the
// profile of the 2,000 records/s load put 30 % of that lock's time in this CPU work. prepareBatch runs
// it in the goroutine of the slot before the commit, so the transaction only validates against the store
// and puts. The result describes the batch with every record stored: the apply uses it when the store held
// none of the batch's samples already (a replay of a sample skips the record, and the rows are derived again
// from the records that remain).
type batchPrep struct {
	metricKeys [][]byte // per record; nil for a record that is not a metric
	metricVals [][]byte
	batches    []byte
	batchesRef []byte // the payload reference of batches when the apply stores it outside bolt (externalize)
	receipt    []byte
	consumed   []byte
	index      *builtIndex
}

// prepareBatch derives the batchPrep of an append. It returns nil when anything fails: the transaction
// then derives (and reports) what it needs itself, so a malformed batch fails exactly where it always did.
func prepareBatch(b model.NormalizedBatch, r model.Receipt) *batchPrep {
	p := &batchPrep{metricKeys: make([][]byte, len(b.Records)), metricVals: make([][]byte, len(b.Records))}
	for i, rec := range b.Records {
		if rec.Kind != model.Metric {
			continue
		}
		v, err := model.CanonicalJSON(rec.Payload.Metric)
		if err != nil {
			return nil
		}
		p.metricKeys[i], p.metricVals[i] = metricKey(b, rec), v
	}
	records := b.Records
	if records == nil {
		records = []model.Record{} // stored as [], as the loop of the apply that skips nothing stores it
	}
	var err error
	if p.batches, err = json.Marshal(records); err != nil {
		return nil
	}
	if p.receipt, err = json.Marshal(r); err != nil {
		return nil
	}
	consumed := b.Reservation
	consumed.State = "consumed"
	consumed.Cursor = &r.Cursor
	if p.consumed, err = json.Marshal(consumed); err != nil {
		return nil
	}
	if p.index, err = buildBatchIndex(b, r, b.Records); err != nil {
		return nil
	}
	return p
}

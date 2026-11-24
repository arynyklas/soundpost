// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/json"
	"math/rand/v2"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// TestSnapshotStreamEqualsMarshal pins that the snapshot of the control state, assembled from the blob
// and the records of the ledger, is byte for byte what encoding the decoded state writes: the group's
// snapshot is verified and installed by builds that decode it, and a digest of it must not depend on how
// it was made. Random books (reservations, keys, quota heads with series, settled windows and charges)
// of many shapes, series names that the encoder escapes, and the empty ledger.
func TestSnapshotStreamEqualsMarshal(t *testing.T) {
	for seed := uint64(1); seed <= 24; seed++ {
		s := newLedgerStore(t)
		var st State
		r := rand.New(rand.NewPCG(seed, 77))
		rounds := int(seed) * 3 % 40
		for range rounds {
			randomRound(r, stateBooks{&st})
		}
		if seed%3 == 0 {
			// Names the encoder escapes: <, >, &, quotes, a non-ASCII rune.
			q := st.Quotas
			if q == nil {
				q = map[string]model.QuotaState{}
			}
			q["org:<a&b>"] = model.QuotaState{Bytes: 9, MaxBytes: 10, MaxSeries: 3, Series: map[string]uint64{"s\"1": 2, "é<>": 1}}
			st.Quotas = q
			if st.AdmissionKeys == nil {
				st.AdmissionKeys = map[string]string{}
			}
			st.AdmissionKeys["k&<>\""] = "id\u2028x"
		}
		writeLedger(t, s, func(l *ledgerTx) error { return l.replace(detachLedger(&st).normalized()) })
		if err := s.db.View(func(tx *bolt.Tx) error {
			var whole State
			if err := loadLogical(tx, &whole); err != nil {
				return err
			}
			want, err := json.Marshal(whole)
			if err != nil {
				return err
			}
			got, err := snapshotState(tx)
			if err != nil {
				return err
			}
			if !bytes.Equal(got, want) {
				t.Errorf("seed %d: the streamed snapshot differs from the encoded one (%d B, %d B)\n got %.300s\nwant %.300s", seed, len(got), len(want), got, want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

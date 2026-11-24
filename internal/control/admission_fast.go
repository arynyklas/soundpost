// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The admission transitions run on the ledger records (ledger.go) when the group can apply them
// (every member declared protocol 6: the state patch gate). What they read is the state without the
// ledger, decoded once for every command that leaves it as it is (coreState), and the few records of
// the batch; what they write is the patch ops of those records. Nothing they cost depends on how many
// batches were admitted before.

// Whether a transition is proposed as a ledger command is decided by two facts: the file keeps its books in
// the ledger (its installation is contracted: Store.layoutLedger, read per transition in admissionUpdate)
// and every member declared the protocol of that layout (Store.StatePatch). The second is a question to the
// replica group, so it is asked once per round (roundOnce), not once per transition: a round commits up to
// maxRoundTransitions of them.

// coreEntry is the state without the ledger as the blob of bolt transaction txid held it.
type coreEntry struct {
	txid  int64
	state *State
}

// coreState is the committed state without the ledger members, of the transaction tx. Revision is
// the current one; RevisionClock is the one of the transaction that decoded it. The State and its
// maps are shared by every reader of the same blob and must not be changed.
//
// A decode is reused while no write changed the blob other than stepping it (putState marks every
// other write with the transaction that made it, in the transaction itself, before it commits): the
// last marked write is not newer than the entry nor than tx, so the blob the entry decoded is the blob of
// tx, whichever of the two transactions is the newer (a reader that began a moment before the freshest
// decode was made uses it).
func (s *Store) coreState(tx *bolt.Tx) (*State, error) {
	d := s.db
	var rev model.Revision
	cacheable := false
	if meta := tx.Bucket([]byte("replica_control")); meta != nil {
		if raw := meta.Get([]byte("application")); len(raw) == 8 {
			rev, cacheable = model.Revision(readWatermark(raw)), true
		}
	}
	id := int64(tx.ID())
	if e := d.core.Load(); cacheable && e != nil && d.coreAt.Load() <= min(e.txid, id) {
		cp := *e.state
		cp.Revision = rev
		return &cp, nil
	}
	st := new(State)
	if readState(tx.Bucket([]byte("control")), st) != nil {
		return nil, model.Fail(model.Corrupt)
	}
	d.decodes.Add(1)
	// The job books are not part of what a core reader sees: a job update does not drop this decode
	// (putStateLayout, onlyJobBooksDiffer), so the books it holds would be the ones of the first
	// decode. JobBook reads its record from the blob (viewJobBook).
	st.JobBooks = nil
	if !cacheable {
		return st, nil
	}
	d.publishCore(&coreEntry{txid: id, state: st})
	cp := *st
	cp.Revision = rev
	return &cp, nil
}

// A background loop of the serving process (the fences, the workers: appcore.RunWorkers) reads the control state
// every few seconds through View, and View assembles the admission ledger into the State it gives the reader:
// every reservation and every per-series quota record that was ever admitted and not yet settled, a few hundred
// thousand records at the single-host gate's cardinality, a decode of most of a second of CPU for each read. None
// of those loops reads the books (Reservations, AdmissionKeys, Quotas, Settlement come empty to a reader that
// does not need them); the context the process starts them with says so.
// WithoutBooks marks ctx so that the reads of the control store made under it (View) give the reader the
// state without the admission books: the four members are empty. It is for a reader that does not look at
// them; a reader that does (a backup cut, a settlement, a quota report) must not run under it.
func WithoutBooks(ctx context.Context) context.Context {
	return model.WithoutBooks(ctx)
}

// ViewCore is View for a reader that does not read the admission ledger (Reservations, AdmissionKeys,
// Quotas, Settlement come empty) nor the job books (JobBooks is empty) and only reads: the state is the decode of the blob that every
// concurrent core reader shares, its maps are not the reader's to change, and its RevisionClock may be
// older than the committed one. The linearizable read barrier is View's.
func (s *Store) ViewCore(ctx context.Context, fn func(State) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.repl != nil {
		if _, err := s.repl.group.ReadIndex(ctx); err != nil {
			return replicaFaultUnder(ctx, err)
		}
	}
	return s.db.View(func(tx *bolt.Tx) error {
		st, err := s.coreState(tx)
		if err != nil {
			return err
		}
		return fn(*st)
	})
}

// ReadinessFacts is what the readiness probe reads of the control state: the schema marker the file was
// written under (BearerHashKeyVersion) and the number of source fences still draining. It is a core read: the
// probe runs on every request of a load balancer, and the admission ledger it does not look at is, on a server
// that has taken load, most of a second of CPU to assemble, which is more than the probe may spend.
func (s *Store) ReadinessFacts(ctx context.Context) (marker uint8, fencing uint64, err error) {
	err = s.ViewCore(ctx, func(st State) error {
		marker = st.BearerHashKeyVersion
		for _, f := range st.SourceFences {
			if f.Phase == "fencing" {
				fencing++
			}
		}
		return nil
	})
	return
}

// viewJobBook is ViewCore that also gives the reader the record of one job book, read from the blob
// of the same transaction (the state it is given has no job books, see coreState). The record is a
// view of the transaction's bytes and is not the reader's to keep past fn.
func (s *Store) viewJobBook(ctx context.Context, key string, fn func(st State, record json.RawMessage, found bool) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.repl != nil {
		if _, err := s.repl.group.ReadIndex(ctx); err != nil {
			return replicaFaultUnder(ctx, err)
		}
	}
	return s.db.View(func(tx *bolt.Tx) error {
		st, err := s.coreState(tx)
		if err != nil {
			return err
		}
		ctrl := tx.Bucket([]byte("control"))
		if ctrl == nil {
			return model.Fail(model.Corrupt)
		}
		if ledgerLayout(ctrl) {
			l, err := openLedger(tx)
			if err != nil {
				return err
			}
			raw := l.t[tableJobBooks].Get([]byte(key))
			return fn(*st, raw, raw != nil)
		}
		record, found, err := blobJobBook(ctrl.Get(stateKey), key)
		if err != nil {
			return err
		}
		return fn(*st, record, found)
	})
}

// blobJobBook is the record of the job book key in the encoding of a state, found by scanning the
// blob's two levels, not by decoding it.
func blobJobBook(blob []byte, key string) (json.RawMessage, bool, error) {
	top, ok := scanObject(blob, 0, len(blob), make([]rawMember, 0, 64))
	if !ok {
		var st struct {
			JobBooks map[string]json.RawMessage
		}
		if json.Unmarshal(blob, &st) != nil {
			return nil, false, model.Fail(model.Corrupt)
		}
		rec, found := st.JobBooks[key]
		return rec, found, nil
	}
	for _, m := range top {
		if name, named := unquoteMemberName(blob, m); !named {
			return nil, false, model.Fail(model.Corrupt)
		} else if name != memberJobBooks {
			continue
		}
		if string(blob[m.vs:m.ve]) == "null" {
			return nil, false, nil
		}
		books, ok := scanObject(blob, m.vs, m.ve, nil)
		if !ok {
			return nil, false, model.Fail(model.Corrupt)
		}
		for _, b := range books {
			name, named := unquoteMemberName(blob, b)
			if !named {
				return nil, false, model.Fail(model.Corrupt)
			}
			if name == key {
				return blob[b.vs:b.ve:b.ve], true, nil
			}
		}
		return nil, false, nil
	}
	return nil, false, nil
}

// ledgerReader is auth.AdmissionReader over the ledger of one transaction.
type ledgerReader struct{ l *ledgerTx }

func (r ledgerReader) Reservation(id string) (model.AdmissionReservation, bool, error) {
	return r.l.reservation(id)
}

// stateReader is auth.AdmissionReader over the books a file keeps in its blob.
type stateReader struct{ st *State }

func (r stateReader) Reservation(id string) (model.AdmissionReservation, bool, error) {
	v, ok := r.st.Reservations[id]
	return v, ok, nil
}

var (
	_ auth.AdmissionReader = ledgerReader{}
	_ auth.AdmissionReader = stateReader{}
)

// errNotLedgerLayout is what a ledger command answers when the file keeps its books in the blob.
var errNotLedgerLayout = errors.New("control: the books are not in the ledger")

// ViewAdmission is ViewCore that also gives the reader the reservation rows of the same revision.
func (s *Store) ViewAdmission(ctx context.Context, fn func(State, auth.AdmissionReader) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.repl != nil {
		if _, err := s.repl.group.ReadIndex(ctx); err != nil {
			return replicaFaultUnder(ctx, err)
		}
	}
	return s.db.View(func(tx *bolt.Tx) error {
		st, err := s.coreState(tx)
		if err != nil {
			return err
		}
		if !ledgerLayout(tx.Bucket([]byte("control"))) {
			return fn(*st, stateReader{st})
		}
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		return fn(*st, ledgerReader{l})
	})
}

// admissionUpdate commits one admission transition. build runs on the state without the ledger and the
// books; on a group that applies ledger commands it runs against the records of one read transaction,
// together with the other transitions that wait for the same commit (admission_group.go), and what it
// wrote is proposed as patch ops; otherwise it runs inside the whole-state funnel against the members
// of the State, like any other writer.
func (s *Store) admissionUpdate(ctx context.Context, w writer, build func(core *State, books admissionBooks) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.repl == nil {
		return model.Fail(model.Unavailable)
	}
	// The ledger command moves the revision and never AuthorityRevision: a writer the allowlist does not
	// keep out of the bump goes through the whole-state funnel, which does bump.
	if _, keep := nonAuthorityWriters[w]; !keep || !s.layoutLedger.Load() {
		return s.updateAs(ctx, w, func(st *State) error { return build(st, stateBooks{st}) })
	}
	err := s.submitAdmission(ctx, build)
	if errors.Is(err, errNotLedgerLayout) {
		// The file left the layout between the decision and the read (a snapshot of an installation
		// that is not contracted was installed): the whole-state funnel commits it.
		return s.updateAs(ctx, w, func(st *State) error { return build(st, stateBooks{st}) })
	}
	return err
}

func sortOps(ops []patchOp) {
	slices.SortFunc(ops, func(a, b patchOp) int {
		switch {
		case pathLess(a.Path, b.Path):
			return -1
		case pathLess(b.Path, a.Path):
			return 1
		}
		return 0
	})
}

// viewBooks gives fn the books of the committed ledger (read only: what fn writes to them goes
// nowhere), after the linearizable read barrier View makes.
func (s *Store) viewBooks(ctx context.Context, fn func(admissionBooks) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.repl != nil {
		if _, err := s.repl.group.ReadIndex(ctx); err != nil {
			return replicaFaultUnder(ctx, err)
		}
	}
	return s.db.View(func(tx *bolt.Tx) error {
		if !ledgerLayout(tx.Bucket([]byte("control"))) {
			var st State
			if err := loadLogical(tx, &st); err != nil {
				return err
			}
			return fn(stateBooks{&st})
		}
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		return fn(newLedgerBooks(l))
	})
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/json"
	"math/bits"
	"reflect"
	"strings"
	"sync/atomic"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The decode of the state without the ledger is shared by every reader of the same blob (coreState) and
// kept per member of the blob. A control commit rewrites the blob, and most commits change a few of its
// members: a rule commit the rule books and the outbox, an outbox write the delivery books, a login the
// sessions. Decoding the whole blob again after each of them (1.8 MB at the single-host gate's estate, a few
// tens of milliseconds of CPU) was the largest cost of the background workers and of every page chunk of every query,
// and it was paid for members no reader had asked for.
//
// The writer knows what it changed: putStateLayout compares the members of the blob it replaces with its
// own and marks, in its transaction and before it commits, each member that differs with that transaction's id
// (markMembersChanged). A member of the shared decode was decoded by the read transaction `at`; it serves a reader
// whose transaction is `id` when no write newer than both changed it (the mark is not above min(at, id)),
// whichever of the two transactions is the newer: the blob did not change between them. The reader decodes the
// members it cannot reuse from the blob of its own snapshot, so it always sees one whole revision, and publishes
// them for the readers after it unless a write it has no part in has already marked them.

// coreMax is the most members the shared decode tracks: one bit each of a memberSet.
const coreMax = 64

// memberSet is a set of the members of the state the shared decode holds, by their position in coreFields.
type memberSet uint64

func bit(i int) memberSet { return 1 << uint(i) }

// coreField is a member of the state as the blob encodes it.
type coreField struct {
	name   string // the name the blob encodes the member under
	index  int    // the field of State that holds it
	rawMap bool   // a map of opaque records (map[string]json.RawMessage), decoded without a pass of encoding/json
}

// coreFields are the members of the state the shared decode holds: every field of State but Revision
// (the committed revision is the reader's own: it comes from the commit) and the job books (a core reader does
// not see them; viewJobBook reads one record from the blob).
var coreFields = stateFields()

var (
	coreByName = func() map[string]int {
		m := make(map[string]int, len(coreFields))
		for i, f := range coreFields {
			m[f.name] = i
		}
		return m
	}()
	// allCore is every member.
	allCore = memberSet(1)<<uint(len(coreFields)) - 1
	// clockMember is the revision clock: in a layout 2 file the blob does not hold it (state_layout.go), it
	// is read from its key whenever a member is decoded.
	clockMember = coreByName[memberClock]
	// readOnlyMembers are the members a shared reader (ViewShared) is given: the ones ReadOnlyControl reads
	// from the state. Its books are decoded when it asks for them (sharedBooks).
	readOnlyMembers = memberSetOf(model.ReadOnlyControlMembers()...)
)

func stateFields() []coreField {
	t := reflect.TypeFor[State]()
	rawMap := reflect.TypeFor[map[string]json.RawMessage]()
	var fields []coreField
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := f.Name
		if tag, ok := f.Tag.Lookup("json"); ok {
			n, _, _ := strings.Cut(tag, ",")
			if n == "-" {
				continue
			}
			if n != "" {
				name = n
			}
		}
		if name == memberRevision || name == memberJobBooks {
			continue
		}
		fields = append(fields, coreField{name: name, index: i, rawMap: f.Type == rawMap})
	}
	if len(fields) > coreMax {
		panic("control: the state has more members than the shared decode tracks")
	}
	return fields
}

// memberSetOf is the set of the named members. A name that is no member of the state is a mistake of the caller.
func memberSetOf(names ...string) (set memberSet) {
	for _, name := range names {
		i, ok := coreByName[name]
		if !ok {
			panic("control: " + name + " is not a member of the state the shared decode holds")
		}
		set |= bit(i)
	}
	return set
}

// coreEntry is the shared decode: for each member it holds, the decoded value in the field of state and the
// read transaction that decoded it (0: the member is not held). An entry is never changed once published.
type coreEntry struct {
	state *State
	at    [coreMax]int64
}

func (e *coreEntry) held() (set memberSet) {
	for i := range coreFields {
		if e.at[i] != 0 {
			set |= bit(i)
		}
	}
	return set
}

// without is e without the members of set; nil when nothing is left.
func (e *coreEntry) without(set memberSet) *coreEntry {
	next := &coreEntry{state: new(State), at: e.at}
	*next.state = *e.state
	v := reflect.ValueOf(next.state).Elem()
	for m := set; m != 0; m &= m - 1 {
		i := bits.TrailingZeros64(uint64(m))
		v.Field(coreFields[i].index).SetZero()
		next.at[i] = 0
	}
	if next.held() == 0 {
		return nil
	}
	return next
}

// copyMembers sets the members of set in dst to those of src.
func copyMembers(dst, src *State, set memberSet) {
	d, s := reflect.ValueOf(dst).Elem(), reflect.ValueOf(src).Elem()
	for m := set; m != 0; m &= m - 1 {
		f := coreFields[bits.TrailingZeros64(uint64(m))].index
		d.Field(f).Set(s.Field(f))
	}
}

// markedAt is the newest transaction known to have changed member i.
func (d *trackedDB) markedAt(i int) int64 { return max(d.coreAt.Load(), d.memberAt[i].Load()) }

// usable is the members of want that e holds and that no write newer than the entry's decode of them and
// the reader's transaction id has changed.
func (d *trackedDB) usable(e *coreEntry, want memberSet, id int64) (ok memberSet) {
	for m := want; m != 0; m &= m - 1 {
		i := bits.TrailingZeros64(uint64(m))
		if a := e.at[i]; a != 0 && d.markedAt(i) <= min(a, id) {
			ok |= bit(i)
		}
	}
	return ok
}

// raise moves a to id unless it is already higher.
func raise(a *atomic.Int64, id int64) {
	for {
		cur := a.Load()
		if id <= cur || a.CompareAndSwap(cur, id) {
			return
		}
	}
}

func trackedOf(tx *bolt.Tx) *trackedDB {
	v, ok := trackedDBs.Load(tx.DB())
	if !ok {
		return nil
	}
	return v.(*trackedDB)
}

// markCoreChanged records, from inside the write transaction tx and before it commits, that every member of the
// blob under control/state changed in a way a decode of the older blob does not reflect, and drops the
// decode that is held: a state that was just rewritten (an erasure) is not kept in memory until the next read
// replaces it.
func markCoreChanged(tx *bolt.Tx) {
	d := trackedOf(tx)
	if d == nil {
		return
	}
	raise(&d.coreAt, int64(tx.ID()))
	d.core.Store(nil)
}

// markMembersChanged is markCoreChanged for the members of the blob that changed, by the names the blob encodes
// them under. A change of the job books, which no core reader sees, and of the revision and its clock, which
// every read takes from the commit, marks nothing. A name that is no member the shared decode holds marks all of them.
func markMembersChanged(tx *bolt.Tx, names []string) {
	d := trackedOf(tx)
	if d == nil {
		return
	}
	var set memberSet
	for _, name := range names {
		switch name {
		case memberJobBooks, memberRevision, memberClock:
			continue
		}
		i, ok := coreByName[name]
		if !ok {
			markCoreChanged(tx)
			return
		}
		set |= bit(i)
	}
	if set == 0 {
		return
	}
	id := int64(tx.ID())
	for m := set; m != 0; m &= m - 1 {
		raise(&d.memberAt[bits.TrailingZeros64(uint64(m))], id)
	}
	for {
		cur := d.core.Load()
		if cur == nil || cur.held()&set == 0 || d.core.CompareAndSwap(cur, cur.without(set)) {
			return
		}
	}
}

// publishCore keeps the members e holds that are newer than the ones held: e itself when it supersedes the
// entry, otherwise the entry with those members replaced.
func (d *trackedDB) publishCore(e *coreEntry) {
	for {
		cur := d.core.Load()
		next := mergeCore(cur, e)
		if next == cur || d.core.CompareAndSwap(cur, next) {
			return
		}
	}
}

func mergeCore(cur, e *coreEntry) *coreEntry {
	if cur == nil {
		if e.held() == 0 {
			return nil
		}
		return e
	}
	var take, held memberSet
	for i := range coreFields {
		if cur.at[i] != 0 {
			held |= bit(i)
		}
		if e.at[i] > cur.at[i] {
			take |= bit(i)
		}
	}
	switch {
	case take == 0:
		return cur
	case held&^take == 0:
		return e // every member cur holds is replaced by a newer one: e holds nothing else than newer members
	}
	next := &coreEntry{state: new(State), at: cur.at}
	*next.state = *cur.state
	copyMembers(next.state, e.state, take)
	for m := take; m != 0; m &= m - 1 {
		i := bits.TrailingZeros64(uint64(m))
		next.at[i] = e.at[i]
	}
	return next
}

// coreState is the committed state without the ledger members, of the transaction tx. Revision is
// the current one; RevisionClock is the one of the transaction that decoded it. The State and its
// maps are shared by every reader of the same blob and must not be changed.
func (s *Store) coreState(tx *bolt.Tx) (*State, error) { return s.coreMembers(tx, allCore) }

// coreMembers is coreState for a reader that reads the members of want only: the others are empty. A member
// is decoded from tx's blob only when the shared decode does not hold it as the blob of tx has it. The State and
// its maps are shared with the other readers and must not be changed.
func (s *Store) coreMembers(tx *bolt.Tx, want memberSet) (*State, error) {
	d := s.db
	var rev model.Revision
	cacheable := false
	if meta := tx.Bucket([]byte("replica_control")); meta != nil {
		if raw := meta.Get([]byte("application")); len(raw) == 8 {
			rev, cacheable = model.Revision(readWatermark(raw)), true
		}
	}
	id := int64(tx.ID())
	var base *coreEntry
	var reusable memberSet
	if cacheable {
		if base = d.core.Load(); base != nil {
			reusable = d.usable(base, want, id)
		}
	}
	if reusable == want && base != nil {
		return shapeCore(base.state, want, rev), nil
	}
	out := new(State)
	if reusable != 0 {
		copyMembers(out, base.state, reusable)
	}
	ctrl := tx.Bucket([]byte("control"))
	decoded, err := decodeCoreMembers(ctrl, out, want&^reusable, want&bit(clockMember) != 0)
	if err != nil {
		return nil, err
	}
	if decoded == allCore {
		d.decodes.Add(1) // every member of the state: the whole state, decoded
	}
	if cacheable {
		frag := &coreEntry{state: out}
		for m := decoded; m != 0; m &= m - 1 {
			i := bits.TrailingZeros64(uint64(m))
			// A member that a write newer than this reader's snapshot has marked is the older revision's: it is
			// the reader's own and nobody after it can use it.
			if d.markedAt(i) <= id {
				frag.at[i] = id
			}
		}
		if frag.held() != 0 {
			d.publishCore(frag)
		}
	}
	return shapeCore(out, want, rev), nil
}

// shapeCore is the state a reader of want is given from the decode src: a copy of its members, never src itself.
func shapeCore(src *State, want memberSet, rev model.Revision) *State {
	if want == allCore {
		cp := *src
		cp.Revision = rev
		return &cp
	}
	out := new(State)
	copyMembers(out, src, want)
	out.Revision = rev
	return out
}

// decodeCoreMembers decodes the members of missing from the blob of ctrl into out and says which members out
// holds then: the same, or all of them when the blob is not an encoding whose members can be told apart without
// decoding it (not the compact one the encoder writes, a member twice, a name only a case-insensitive match reads),
// which is decoded as a whole as it always was. A file of layout 2 keeps the revision clock outside the blob: it is
// read from its key, with the members, when the reader wants it.
func decodeCoreMembers(ctrl *bolt.Bucket, out *State, missing memberSet, refreshClock bool) (memberSet, error) {
	if ctrl == nil {
		return 0, model.Fail(model.Corrupt)
	}
	d := trackedOf(ctrl.Tx())
	whole := func() (memberSet, error) {
		var st State
		if err := readState(ctrl, &st); err != nil {
			return 0, err
		}
		st.JobBooks = nil
		*out = st
		if d != nil {
			d.memberDecodes.Add(uint64(len(coreFields)))
		}
		return allCore, nil
	}
	spans, ok := scanCore(ctrl.Get(stateKey))
	if !ok {
		return whole()
	}
	counted := missing
	if ledgerLayout(ctrl) && missing != 0 && refreshClock {
		// The blob of layout 2 holds no revision clock; the clock of the rebuilt state is the committed one.
		spans[clockMember] = ctrl.Get(stateClockKey)
		missing |= bit(clockMember)
		counted &^= bit(clockMember)
	}
	for m := missing; m != 0; m &= m - 1 {
		i := bits.TrailingZeros64(uint64(m))
		if err := decodeCoreMember(out, coreFields[i], spans[i]); err != nil {
			return 0, err
		}
	}
	if d != nil {
		d.memberDecodes.Add(uint64(bits.OnesCount64(uint64(counted))))
	}
	return missing, nil
}

// scanCore is the encoding of each member of the blob, found by scanning its two top levels. ok is false when
// decoding the members one by one is not what decoding the blob does.
func scanCore(blob []byte) (spans *[coreMax][]byte, ok bool) {
	members, ok := scanObject(blob, 0, len(blob), make([]rawMember, 0, 64))
	if !ok {
		return nil, false
	}
	spans = new([coreMax][]byte)
	for _, m := range members {
		name, named := unquoteMemberName(blob, m)
		if !named {
			return nil, false
		}
		i, known := coreByName[name]
		if !known {
			if name == memberRevision || name == memberJobBooks {
				continue // not decoded by a core read, whatever else the blob says of them
			}
			for _, f := range coreFields {
				if strings.EqualFold(f.name, name) {
					return nil, false // encoding/json reads it as that member; so must the decode
				}
			}
			continue // a member the state does not have: encoding/json skips it
		}
		if spans[i] != nil {
			return nil, false
		}
		spans[i] = blob[m.vs:m.ve:m.ve]
	}
	return spans, true
}

// decodeCoreMember sets the field of the member f in st to the value of its encoding raw (nil: the blob has no
// such member), as decoding the whole blob into a State does.
func decodeCoreMember(st *State, f coreField, raw []byte) error {
	fv := reflect.ValueOf(st).Elem().Field(f.index)
	fv.SetZero()
	if raw == nil {
		return nil
	}
	if f.rawMap {
		if m, ok := rawMapOf(raw); ok {
			if m != nil {
				fv.Set(reflect.ValueOf(m))
			}
			return nil
		}
	}
	if json.Unmarshal(raw, fv.Addr().Interface()) != nil {
		return model.Fail(model.Corrupt)
	}
	return nil
}

// rawMapOf is the map of records the encoding raw of a map[string]json.RawMessage holds, found by scanning it:
// the records are views of one copy of raw, not a copy each. ok is false for an encoding that is not the compact
// object the encoder writes; a nil map with ok is the `null` the encoder writes for a map that is nil.
func rawMapOf(raw []byte) (m map[string]json.RawMessage, ok bool) {
	if string(raw) == "null" {
		return nil, true
	}
	members, ok := scanObject(raw, 0, len(raw), nil)
	if !ok {
		return nil, false
	}
	buf := bytes.Clone(raw)
	m = make(map[string]json.RawMessage, len(members))
	for _, mem := range members {
		name, named := unquoteMemberName(raw, mem)
		if !named {
			return nil, false
		}
		m[name] = buf[mem.vs:mem.ve:mem.ve]
	}
	return m, true
}

// sharedBooks serves the books to a shared reader (ViewShared): the members that hold them are not part of what a
// reader of the control state is given up front, and a member is decoded (or taken from the shared decode) when the reader first asks
// for the book. A rule commit or an outbox write then costs a reader that never opens the rule books or the outbox
// nothing, and a reader of one book decodes that book only. The books the ledger holds are the ledger's.
type sharedBooks struct {
	s      *Store
	tx     *bolt.Tx
	ledger model.BookSource // nil: the file keeps its books in the blob
	held   map[model.Book]map[string]json.RawMessage
	err    error
}

// ledgerBook reports a book that a file of the ledger layout keeps in its ledger.
func ledgerBook(book model.Book) bool {
	return book == model.BookIssues || book == model.BookJobs || book == model.BookGroupingIssues || book == model.BookJobPositions
}

// Serves reports the books sharedBooks answers for: the ledger's, and the books of opaque records the blob holds.
// The job books are not among them: a core reader sees none (coreMembers).
func (b *sharedBooks) Serves(book model.Book) bool {
	if b.ledger != nil && ledgerBook(book) {
		return true
	}
	i, ok := coreByName[string(book)]
	return ok && coreFields[i].rawMap
}

func (b *sharedBooks) BookKeys(book model.Book, prefix string) []string {
	if b.ledger != nil && ledgerBook(book) {
		return b.ledger.BookKeys(book, prefix)
	}
	var out []string
	for key := range b.member(book) {
		if strings.HasPrefix(key, prefix) {
			out = append(out, key)
		}
	}
	return out
}

func (b *sharedBooks) BookRecord(book model.Book, key string) ([]byte, bool) {
	if b.ledger != nil && ledgerBook(book) {
		return b.ledger.BookRecord(book, key)
	}
	raw, ok := b.member(book)[key]
	if !ok {
		return nil, false
	}
	return append([]byte{}, raw...), true
}

// member is the map of the book, decoded at the first ask of the reader. A blob that cannot be decoded is
// reported when the read ends: the interface a reader asks through has no error to return.
func (b *sharedBooks) member(book model.Book) map[string]json.RawMessage {
	if m, ok := b.held[book]; ok {
		return m
	}
	i := coreByName[string(book)]
	st, err := b.s.coreMembers(b.tx, bit(i))
	if err != nil {
		if b.err == nil {
			b.err = err
		}
		return nil
	}
	m := reflect.ValueOf(st).Elem().Field(coreFields[i].index).Interface().(map[string]json.RawMessage)
	if b.held == nil {
		b.held = map[model.Book]map[string]json.RawMessage{}
	}
	b.held[book] = m
	return m
}

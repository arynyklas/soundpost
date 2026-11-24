// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The admission ledger (07.06 #11, lane 2 wave 20).
//
// Every intake batch is one reservation row, one AdmissionKeys entry, a charge on three quota keys
// (bytes and, per series, a reference count) and, once its data window is settled, a share of the
// settlement: members of the control State that every control command decoded and encoded whole. At
// the cardinality of the single-host gate (100,000 series charged to three tiers) that state is tens
// of megabytes, and what one admission cost grew with everything admitted before it (mean 7.9 ms at
// 50 batches, 84 ms at 1,400): at 200 records per second the server collapsed.
//
// The ledger is where those four members live on disk: a record per reservation, per key, per quota
// key, per (quota key, series) and per settled window, in buckets of control.db that a command
// writes record by record in the transaction that applies it. It is a LOCAL layout. The logical state
// is unchanged: the members are still the members of State with the same encoding on the wire (a
// replacement carries them, a patch addresses them by the same paths, a snapshot, a backup and a View
// assemble them), so nothing about the replicated protocol is a precondition of it; the one thing
// added to a patch is a finer address into a quota record (Quotas/<key>/series/<id>) and into the
// settlement, which a proposer uses only once every member of the group declared protocol 6.
//
// What the blob under control/state holds is the State with those four members empty (null). The
// digest a patch names (state_patch.go Base) covers the blob and the ledger's accumulator
// (ledgerAcc: the XOR of the SHA-256 of every record), so a voter whose ledger differs from the
// proposer's refuses a patch exactly as one whose blob differs does.

// Tables of the ledger, in the order of ledgerTables.
const (
	tableReservations   = iota // reservation ID -> AdmissionReservation (JSON)
	tableKeys                  // reservation key -> reservation ID
	tableQuotas                // quota key -> quotaHead (JSON)
	tableSeries                // quota key NUL series -> reference count (8 bytes, big endian)
	tableSpans                 // data group -> window span (8 bytes)
	tableWindows               // SettledKey -> SettledWindow (JSON)
	tableCharges               // quota key -> settled bytes (8 bytes)
	tableChargeSeries          // quota key NUL series -> settled reference count (8 bytes, big endian)
	tableJobBooks              // job book key -> JobRecord (JSON, as the blob held it)
	tableIssueBooks            // issue book key -> IssueBook (JSON, as the blob held it)
	tableGroupingIssues        // grouping issue key (org:project:issue) -> GroupingIssue (JSON)
	tableCommands              // command ID -> the Result it committed (JSON)
	tableCommandOwners         // command ID -> the binding (principal:org:kind) that committed it (raw bytes)
	tableJobPositions          // job producer position key (org:project) -> JobPositionRecord (JSON, as the blob held it)
	ledgerTableCount
)

var ledgerTables = [ledgerTableCount]string{"adm_res", "adm_keys", "adm_quota", "adm_series", "adm_spans", "adm_windows", "adm_charge", "adm_cseries", "job_books", "issue_books", "grouping_issues", "cmd_results", "cmd_owners", "job_positions"}

var (
	ledgerAccKey    = []byte("ledger_acc")
	ledgerFormatKey = []byte("ledger_format")
	// ledgerSealKey holds the digest of the blob (stateSealKey's value) that the ledger belongs to.
	// Every state write of this build moves both seals together, in the transaction that writes it.
	// A build that does not know the ledger (a rollback of the voter to the previous release) moves
	// the state seal alone, keeping the whole logical state in the blob it writes; the next Open of
	// this build finds the two apart and takes the books from the blob (migrateLedger) instead of
	// trusting a ledger that is older than the blob.
	ledgerSealKey = []byte("ledger_seal")
	// openIndexBucket is the bucket of the open-reservation index (ledgerTx.open) and ledgerOpenKey the ledger
	// accumulator it was last brought up to date with: the index belongs to the ledger only while the two agree,
	// and a file whose ledger a build without the index changed finds them apart and rebuilds it.
	openIndexBucket = []byte("adm_open")
	ledgerOpenKey   = []byte("ledger_open_acc")
)

// ledgerFormat is the value of ledgerFormatKey: the six members of the State the ledger holds (the four of
// the admission books and the job and issue books) live in it and the blob holds the state without its
// revision (state_layout.go). A file of an earlier build of the layout holds a legacy format and Open moves
// it (migrateLedger): legacyLedgerFormat (1) still holds the revision in the blob and keeps the job and
// issue books there, booksInBlobFormat (2) keeps those two books in the blob.
var ledgerFormat = []byte{5}

// previousLedgerFormat is the layout of the build before the overlay (D83): the series tables are plain sorted
// buckets of records. Open moves them into blocks (blockSeriesTables) and writes ledgerFormat.
var previousLedgerFormat = []byte{4}

var (
	legacyLedgerFormat = []byte{1}
	booksInBlobFormat  = []byte{2}
	// hotMembersInBlobFormat is the layout of the build before D85: the job and issue books are records,
	// the grouping issues and the applied-command log (Commands, CommandOwners) are still members of the
	// blob. Open moves them (migrateLedger).
	hotMembersInBlobFormat = []byte{3}
)

// quotaHead is a quota record without its series: the four scalars of model.QuotaState and the number
// of series records of the key.
type quotaHead struct {
	Bytes      model.Uint64 `json:"bytes"`
	MaxBytes   model.Uint64 `json:"max_bytes"`
	MaxSeries  model.Uint64 `json:"max_series"`
	Configured bool         `json:"configured"`
	Series     uint64       `json:"series"`
}

// ledgerMembers are the members of the State the ledger holds: the admission books (Reservations,
// AdmissionKeys, Quotas, Settlement), the job and issue books, maps of records the workers rewrite one
// record at a time (JobBooks, IssueBooks), the grouping issues those workers commit (GroupingIssues) and the
// applied-command log (Commands, CommandOwners): a record per key, in tables of their own, so that the cost
// of writing one does not grow with the others.
type ledgerMembers struct {
	Reservations   map[string]model.AdmissionReservation
	AdmissionKeys  map[string]string
	Quotas         map[string]model.QuotaState
	Settlement     *model.Settlement
	JobBooks       map[string]json.RawMessage
	IssueBooks     map[string]json.RawMessage
	GroupingIssues map[string]model.GroupingIssue
	Commands       map[string]model.ControlResult
	CommandOwners  map[string]string
	JobPositions   map[string]json.RawMessage
}

// memberScope says which of the ledger's members a transition reads or writes: the admission books, the
// books of the workers (the job and issue books and the grouping issues), the applied-command log, or any
// of them. A transition that names none gets the state without them.
type memberScope uint8

const (
	scopeAdmission memberScope = 1 << iota
	scopeBooks
	scopeCommands
	scopeAll = scopeAdmission | scopeBooks | scopeCommands
)

// tableScope is the scope a table of the ledger belongs to.
func tableScope(table int) memberScope {
	switch table {
	case tableJobBooks, tableIssueBooks, tableGroupingIssues, tableJobPositions:
		return scopeBooks
	case tableCommands, tableCommandOwners:
		return scopeCommands
	}
	return scopeAdmission
}

// detachLedger moves every ledger member out of st (they are empty in what the blob holds).
func detachLedger(st *State) ledgerMembers { return detachScope(st, scopeAll) }

// detachScope moves the members of scope out of st and leaves the others where they are.
func detachScope(st *State, scope memberScope) (m ledgerMembers) {
	if scope&scopeAdmission != 0 {
		m.Reservations, m.AdmissionKeys, m.Quotas, m.Settlement = st.Reservations, st.AdmissionKeys, st.Quotas, st.Settlement
		st.Reservations, st.AdmissionKeys, st.Quotas, st.Settlement = nil, nil, nil, nil
	}
	if scope&scopeBooks != 0 {
		m.JobBooks, m.IssueBooks, m.GroupingIssues, m.JobPositions = st.JobBooks, st.IssueBooks, st.GroupingIssues, st.JobPositions
		st.JobBooks, st.IssueBooks, st.GroupingIssues, st.JobPositions = nil, nil, nil, nil
	}
	if scope&scopeCommands != 0 {
		m.Commands, m.CommandOwners = st.Commands, st.CommandOwners
		st.Commands, st.CommandOwners = nil, nil
	}
	return m
}

// attachLedger is the inverse of detachLedger.
func attachLedger(st *State, m ledgerMembers) { attachScope(st, m, scopeAll) }

// attachScope is the inverse of detachScope.
func attachScope(st *State, m ledgerMembers, scope memberScope) {
	if scope&scopeAdmission != 0 {
		st.Reservations, st.AdmissionKeys, st.Quotas, st.Settlement = m.Reservations, m.AdmissionKeys, m.Quotas, m.Settlement
	}
	if scope&scopeBooks != 0 {
		st.JobBooks, st.IssueBooks, st.GroupingIssues, st.JobPositions = m.JobBooks, m.IssueBooks, m.GroupingIssues, m.JobPositions
	}
	if scope&scopeCommands != 0 {
		st.Commands, st.CommandOwners = m.Commands, m.CommandOwners
	}
}

// normalized is m with every empty map nil and an empty settlement absent, the form the ledger
// assembles: it cannot tell an empty map from an absent one.
func (m ledgerMembers) normalized() ledgerMembers {
	if len(m.Reservations) == 0 {
		m.Reservations = nil
	}
	if len(m.AdmissionKeys) == 0 {
		m.AdmissionKeys = nil
	}
	if len(m.Quotas) == 0 {
		m.Quotas = nil
	} else {
		quotas := make(map[string]model.QuotaState, len(m.Quotas))
		for k, q := range m.Quotas {
			if len(q.Series) == 0 {
				q.Series = nil
			}
			quotas[k] = q
		}
		m.Quotas = quotas
	}
	if s := m.Settlement; s != nil {
		if len(s.Spans) == 0 && len(s.Windows) == 0 && len(s.Charges) == 0 {
			m.Settlement = nil
		} else {
			c := *s
			if len(c.Spans) == 0 {
				c.Spans = nil
			}
			if len(c.Windows) == 0 {
				c.Windows = nil
			}
			if len(c.Charges) == 0 {
				c.Charges = nil
			} else {
				charges := make(map[string]model.SettledCharge, len(c.Charges))
				for k, ch := range c.Charges {
					if len(ch.Series) == 0 {
						ch.Series = nil
					}
					charges[k] = ch
				}
				c.Charges = charges
			}
			m.Settlement = &c
		}
	}
	if len(m.JobBooks) == 0 {
		m.JobBooks = nil
	}
	if len(m.IssueBooks) == 0 {
		m.IssueBooks = nil
	}
	if len(m.JobPositions) == 0 {
		m.JobPositions = nil
	}
	if len(m.GroupingIssues) == 0 {
		m.GroupingIssues = nil
	}
	if len(m.Commands) == 0 {
		m.Commands = nil
	}
	if len(m.CommandOwners) == 0 {
		m.CommandOwners = nil
	}
	return m
}

// normalizeLedger puts the ledger members of st in the form the ledger assembles.
func normalizeLedger(st *State) {
	attachLedger(st, detachLedger(st).normalized())
}

// ledgerRoot says whether the first member of a patch path is one of the ledger's.
func ledgerRoot(name string) bool {
	return name == "Reservations" || name == "AdmissionKeys" || name == "Quotas" || name == "settlement" || bookRoot(name)
}

// bookRoot says whether the first member of a patch path is one of the maps of records of the workers' books
// and the command log: the job and issue books, the grouping issues and the applied commands, each record
// addressed as [member, key].
func bookRoot(name string) bool {
	switch name {
	case "JobBooks", "IssueBooks", "GroupingIssues", "Commands", "CommandOwners", "JobPositions":
		return true
	}
	return false
}

// splitLedgerOps separates the ops that address the ledger from the ones that address the blob.
func splitLedgerOps(ops []patchOp) (blob, ledger []patchOp) {
	for _, op := range ops {
		if len(op.Path) > 0 && ledgerRoot(op.Path[0]) {
			ledger = append(ledger, op)
		} else {
			blob = append(blob, op)
		}
	}
	return
}

var quotaFields = map[string]bool{"bytes": true, "max_bytes": true, "max_series": true, "configured": true}

// validLedgerOp is the structural rule for an op that addresses the ledger: the path says what it
// writes and the op is one that place accepts. Every proposal and every applied command is checked
// with it before any state is read.
func validLedgerOp(op patchOp) bool {
	p := op.Path
	set, del := op.Op == opSet, op.Op == opDelete
	if !set && !del {
		return false
	}
	switch p[0] {
	case "Reservations", "AdmissionKeys", "JobBooks", "IssueBooks", "GroupingIssues", "Commands", "CommandOwners", "JobPositions":
		return len(p) == 2
	case "Quotas":
		switch len(p) {
		case 2:
			return true
		case 3:
			return quotaFields[p[2]] && set || p[2] == "series"
		case 4:
			return p[2] == "series"
		}
	case "settlement":
		switch len(p) {
		case 1:
			return true
		case 3:
			return p[1] == "spans" || p[1] == "windows" || p[1] == "charges"
		case 4:
			return p[1] == "charges" && (p[3] == "bytes" && set || p[3] == "series")
		case 5:
			return p[1] == "charges" && p[3] == "series"
		}
	}
	return false
}

// ledgerTx is the ledger inside one bolt transaction.
type ledgerTx struct {
	ctrl *bolt.Bucket
	t    [ledgerTableCount]ledgerTable
	// ov is the overlay of the random-key tables (ledger_overlay.go): the reservation keys and the series tables.
	ov    *ovTx
	tx    *bolt.Tx
	acc   [32]byte
	dirty bool
	// fresh says that the series tables hold none of the records a write names (the ledger was just emptied
	// and filled tier by tier), so clearing a quota key's records is a pass over a table for nothing.
	fresh bool
	// open is the index of the reservations that are still reserved (no outcome yet): their IDs, kept beside
	// the table so that the reconciliation of outcomes reads those rows and not every reservation ever held
	// (admission_open.go). It is derived from the table and not part of the ledger: it is outside ledgerTables, so
	// no digest, patch, snapshot or backup carries it. nil when the file does not have the bucket yet.
	open *bolt.Bucket
}

// ensureLedger creates the ledger's buckets (every file has them, empty while it keeps its books in the
// blob).
func ensureLedger(tx *bolt.Tx) error {
	if tx.Bucket([]byte("control")) == nil {
		return model.Fail(model.Corrupt)
	}
	for _, name := range ledgerTables {
		if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
			return err
		}
	}
	if _, err := tx.CreateBucketIfNotExists(openIndexBucket); err != nil {
		return err
	}
	for _, name := range [][]byte{ovLogBucket, ovTierBucket} {
		if _, err := tx.CreateBucketIfNotExists(name); err != nil {
			return err
		}
	}
	return nil
}

// ledgerLayout says whether the file keeps the admission books in the ledger. The layout is that of the
// installation: a contracted installation (born so, or the operator ran `soundpost upgrade
// contract-indexes`) has no previous release to roll back to, and only then do the books leave the blob;
// an installation the previous release can still read keeps them in the blob, byte for byte as that
// release holds them, so that the digest of a patch, the patches themselves and the snapshots are the
// ones both releases compute.
func ledgerLayout(ctrl *bolt.Bucket) bool {
	return ctrl != nil && bytes.Equal(ctrl.Get(ledgerFormatKey), ledgerFormat)
}

// contractedMark is how the stored state names a contracted installation (model.IndexesContractedKey).
var contractedMark = []byte(`"` + model.IndexesContractedKey + `"`)

// blobContracted says whether an encoding of the state names a contracted installation.
func blobContracted(raw []byte) bool { return bytes.Contains(raw, contractedMark) }

// logicalContracted is blobContracted for a decoded state.
func logicalContracted(st *State) bool {
	if _, ok := st.OIDC[model.IndexesContractedKey]; ok {
		return true
	}
	for _, o := range st.Orgs {
		if _, ok := o.Settings[model.IndexesContractedKey]; ok {
			return true
		}
	}
	return false
}

// openLedger opens the ledger of tx. The buckets exist in every store (Open and OpenSeed create them).
func openLedger(tx *bolt.Tx) (*ledgerTx, error) {
	l := &ledgerTx{tx: tx, ctrl: tx.Bucket([]byte("control"))}
	if l.ctrl == nil {
		return nil, model.Fail(model.Corrupt)
	}
	var raw [ledgerTableCount]*bolt.Bucket
	for i, name := range ledgerTables {
		if raw[i] = tx.Bucket([]byte(name)); raw[i] == nil {
			return nil, model.Fail(model.Corrupt)
		}
	}
	ov, err := newOvTx(tx, l.ctrl, raw)
	if err != nil {
		return nil, err
	}
	l.ov = ov
	for i := range raw {
		if slot := ovSlotOf(i); slot >= 0 {
			l.t[i] = &ovTable{ov: ov, slot: slot}
		} else {
			l.t[i] = boltTable{raw[i]}
		}
	}
	if raw := l.ctrl.Get(ledgerAccKey); len(raw) == len(l.acc) {
		copy(l.acc[:], raw)
	}
	l.open = tx.Bucket(openIndexBucket) // nil in a file that does not have it yet (ensureOpenIndex)
	return l, nil
}

func recordHash(table int, key, value []byte) (sum [sha256.Size]byte) {
	h := sha256.New()
	h.Write([]byte{byte(table), 0})
	h.Write(key)
	h.Write([]byte{0})
	h.Write(value)
	h.Sum(sum[:0])
	return
}

func (l *ledgerTx) xor(sum [sha256.Size]byte) {
	for i := range sum {
		l.acc[i] ^= sum[i]
	}
	l.dirty = true
}

// put writes a record and folds it into the accumulator.
func (l *ledgerTx) put(table int, key, value []byte) error {
	if old := l.t[table].Get(key); old != nil {
		l.xor(recordHash(table, key, old))
	}
	if err := l.t[table].Put(key, value); err != nil {
		return err
	}
	l.xor(recordHash(table, key, value))
	if table == tableReservations {
		return l.noteOpen(key, value)
	}
	return nil
}

// del removes a record (nothing when it is absent) and reports whether one was there.
func (l *ledgerTx) del(table int, key []byte) (bool, error) {
	old := l.t[table].Get(key)
	if old == nil {
		return false, nil
	}
	l.xor(recordHash(table, key, old))
	if table == tableReservations {
		if err := l.noteOpen(key, nil); err != nil {
			return true, err
		}
	}
	return true, l.t[table].Delete(key)
}

// flush stores the accumulator, and with it the mark that says the index of open reservations belongs to it.
func (l *ledgerTx) flush() error {
	if err := l.ov.seal(); err != nil {
		return err
	}
	if !l.dirty {
		return nil
	}
	l.dirty = false
	if err := l.ctrl.Put(ledgerAccKey, l.acc[:]); err != nil {
		return err
	}
	return l.ctrl.Put(ledgerOpenKey, l.acc[:])
}

// seriesKey is the key of the reference count of one series under one quota key (and of a settled charge): the
// series first, the quota key after it. An admission charges a series under each of its quota tiers (three of
// them), so the records of one series lie together: a round that charges thousands of series dirties the
// pages of those series once, where tier-major keys (every tier's own run of series) put them on three times
// as many pages of a table that is 300,000 records at the single-host gate. A key holds no NUL in either part.
func seriesKey(tier, id string) []byte {
	k := make([]byte, 0, len(tier)+1+len(id))
	k = append(k, id...)
	k = append(k, 0)
	return append(k, tier...)
}

// splitSeriesKey is the quota key and the series of a seriesKey.
func splitSeriesKey(k string) (tier, id string) {
	id, tier, _ = strings.Cut(k, "\x00")
	return
}

// splitSeriesKeyBytes is splitSeriesKey for the bytes of a key of the series tables (views of k).
func splitSeriesKeyBytes(k []byte) (tier, id []byte) {
	id, tier, _ = bytes.Cut(k, []byte{0})
	return
}

// clearTier removes every record of a quota key (or a settled charge) from a series table. The table is
// series-major, so the records of one quota key are found by a pass over it: the writes that do this (a whole
// quota record replaced or removed) are rare, and the admissions that write one series are not slowed by them.
func (l *ledgerTx) clearTier(table int, tier string) error {
	if l.fresh {
		return nil
	}
	suffix := append([]byte{0}, tier...)
	var keys [][]byte
	c := l.t[table].Cursor()
	for k, _ := c.First(); k != nil; k, _ = c.Next() {
		if bytes.HasSuffix(k, suffix) {
			keys = append(keys, bytes.Clone(k))
		}
	}
	for _, k := range keys {
		if _, err := l.del(table, k); err != nil {
			return err
		}
	}
	return nil
}

func u64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func readU64(raw []byte) uint64 {
	if len(raw) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(raw)
}

// each calls fn for the records of the table whose key starts with prefix, in key order, until fn
// says stop.
func (l *ledgerTx) each(table int, prefix []byte, fn func(key, value []byte) bool) {
	c := l.t[table].Cursor()
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		if !fn(k, v) {
			return
		}
	}
}

// tableEmpty reports whether a table holds no record.
func (l *ledgerTx) tableEmpty(table int) bool {
	k, _ := l.t[table].Cursor().First()
	return k == nil
}

// empty reports whether the ledger holds no record.
func (l *ledgerTx) empty() bool {
	for i := range l.t {
		if k, _ := l.t[i].Cursor().First(); k != nil {
			return false
		}
	}
	return true
}

// reads

func (l *ledgerTx) reservation(id string) (r model.AdmissionReservation, ok bool, err error) {
	raw := l.t[tableReservations].Get([]byte(id))
	if raw == nil {
		return r, false, nil
	}
	if json.Unmarshal(raw, &r) != nil {
		return r, false, model.Fail(model.Corrupt)
	}
	return r, true, nil
}

func (l *ledgerTx) keyed(key string) (string, bool) {
	raw := l.t[tableKeys].Get([]byte(key))
	if raw == nil {
		return "", false
	}
	return string(raw), true
}

func (l *ledgerTx) head(tier string) (h quotaHead, ok bool, err error) {
	raw := l.t[tableQuotas].Get([]byte(tier))
	if raw == nil {
		return h, false, nil
	}
	if json.Unmarshal(raw, &h) != nil {
		return h, false, model.Fail(model.Corrupt)
	}
	return h, true, nil
}

func (l *ledgerTx) series(tier, id string) uint64 {
	return readU64(l.t[tableSeries].Get(seriesKey(tier, id)))
}

func (l *ledgerTx) span(group string) uint64 { return readU64(l.t[tableSpans].Get([]byte(group))) }

func (l *ledgerTx) window(key string) (w model.SettledWindow, ok bool, err error) {
	raw := l.t[tableWindows].Get([]byte(key))
	if raw == nil {
		return w, false, nil
	}
	if json.Unmarshal(raw, &w) != nil {
		return w, false, model.Fail(model.Corrupt)
	}
	return w, true, nil
}

func (l *ledgerTx) hasWindows() bool {
	k, _ := l.t[tableWindows].Cursor().First()
	return k != nil
}

func (l *ledgerTx) charge(tier string) (bytes uint64, ok bool) {
	raw := l.t[tableCharges].Get([]byte(tier))
	return readU64(raw), raw != nil
}

func (l *ledgerTx) chargeSeries(tier, id string) uint64 {
	return readU64(l.t[tableChargeSeries].Get(seriesKey(tier, id)))
}

// members assembles the members of the State (in the normalized form).
func (l *ledgerTx) members() (ledgerMembers, error) { return l.membersOf(scopeAll) }

// membersOf assembles the members of scope (in the normalized form); the others come empty.
func (l *ledgerTx) membersOf(scope memberScope) (m ledgerMembers, err error) {
	return l.membersOfKeyed(scope, "")
}

// membersOfKeyed is membersOf, with the applied-command log (Commands, CommandOwners) reduced to the records of
// command when it is not empty: a transition that applies one command reads and writes that command's
// records and no other (store.go, transactCommit), and the log is as long as the dedup window.
func (l *ledgerTx) membersOfKeyed(scope memberScope, command string) (m ledgerMembers, err error) {
	each := func(table int, fn func(k, v []byte) error) {
		if err != nil {
			return
		}
		if scope&tableScope(table) == 0 {
			return
		}
		if command != "" && tableScope(table) == scopeCommands {
			if v := l.t[table].Get([]byte(command)); v != nil {
				err = fn([]byte(command), v)
			}
			return
		}
		c := l.t[table].Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if err = fn(k, v); err != nil {
				return
			}
		}
	}
	each(tableJobBooks, func(k, v []byte) error {
		if m.JobBooks == nil {
			m.JobBooks = map[string]json.RawMessage{}
		}
		m.JobBooks[string(k)] = bytes.Clone(v)
		return nil
	})
	each(tableIssueBooks, func(k, v []byte) error {
		if m.IssueBooks == nil {
			m.IssueBooks = map[string]json.RawMessage{}
		}
		m.IssueBooks[string(k)] = bytes.Clone(v)
		return nil
	})
	each(tableGroupingIssues, func(k, v []byte) error {
		var gi model.GroupingIssue
		if json.Unmarshal(v, &gi) != nil {
			return model.Fail(model.Corrupt)
		}
		if m.GroupingIssues == nil {
			m.GroupingIssues = map[string]model.GroupingIssue{}
		}
		m.GroupingIssues[string(k)] = gi
		return nil
	})
	each(tableCommands, func(k, v []byte) error {
		var r model.ControlResult
		if json.Unmarshal(v, &r) != nil {
			return model.Fail(model.Corrupt)
		}
		if m.Commands == nil {
			m.Commands = map[string]model.ControlResult{}
		}
		m.Commands[string(k)] = r
		return nil
	})
	each(tableJobPositions, func(k, v []byte) error {
		if m.JobPositions == nil {
			m.JobPositions = map[string]json.RawMessage{}
		}
		m.JobPositions[string(k)] = bytes.Clone(v)
		return nil
	})
	each(tableCommandOwners, func(k, v []byte) error {
		if m.CommandOwners == nil {
			m.CommandOwners = map[string]string{}
		}
		m.CommandOwners[string(k)] = string(v)
		return nil
	})
	each(tableReservations, func(k, v []byte) error {
		var r model.AdmissionReservation
		if json.Unmarshal(v, &r) != nil {
			return model.Fail(model.Corrupt)
		}
		if m.Reservations == nil {
			m.Reservations = map[string]model.AdmissionReservation{}
		}
		m.Reservations[string(k)] = r
		return nil
	})
	each(tableKeys, func(k, v []byte) error {
		if m.AdmissionKeys == nil {
			m.AdmissionKeys = map[string]string{}
		}
		m.AdmissionKeys[string(k)] = string(v)
		return nil
	})
	each(tableQuotas, func(k, v []byte) error {
		var h quotaHead
		if json.Unmarshal(v, &h) != nil {
			return model.Fail(model.Corrupt)
		}
		if m.Quotas == nil {
			m.Quotas = map[string]model.QuotaState{}
		}
		m.Quotas[string(k)] = model.QuotaState{Bytes: h.Bytes, MaxBytes: h.MaxBytes, MaxSeries: h.MaxSeries, Configured: h.Configured}
		return nil
	})
	each(tableSeries, func(k, v []byte) error {
		tier, id := splitSeriesKeyBytes(k)
		q, ok := m.Quotas[string(tier)]
		if !ok {
			return model.Fail(model.Corrupt)
		}
		if q.Series == nil {
			q.Series = map[string]uint64{}
		}
		q.Series[string(id)] = readU64(v)
		m.Quotas[string(tier)] = q
		return nil
	})
	settlement := func() *model.Settlement {
		if m.Settlement == nil {
			m.Settlement = &model.Settlement{}
		}
		return m.Settlement
	}
	each(tableSpans, func(k, v []byte) error {
		s := settlement()
		if s.Spans == nil {
			s.Spans = map[string]uint64{}
		}
		s.Spans[string(k)] = readU64(v)
		return nil
	})
	each(tableWindows, func(k, v []byte) error {
		var w model.SettledWindow
		if json.Unmarshal(v, &w) != nil {
			return model.Fail(model.Corrupt)
		}
		s := settlement()
		if s.Windows == nil {
			s.Windows = map[string]model.SettledWindow{}
		}
		s.Windows[string(k)] = w
		return nil
	})
	each(tableCharges, func(k, v []byte) error {
		s := settlement()
		if s.Charges == nil {
			s.Charges = map[string]model.SettledCharge{}
		}
		s.Charges[string(k)] = model.SettledCharge{Bytes: model.Uint64(readU64(v))}
		return nil
	})
	each(tableChargeSeries, func(k, v []byte) error {
		tier, id := splitSeriesKeyBytes(k)
		s := settlement()
		c, ok := s.Charges[string(tier)]
		if !ok {
			return model.Fail(model.Corrupt)
		}
		if c.Series == nil {
			c.Series = map[string]uint64{}
		}
		c.Series[string(id)] = readU64(v)
		s.Charges[string(tier)] = c
		return nil
	})
	return m, err
}

// writes

func (l *ledgerTx) putReservation(r model.AdmissionReservation) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return model.Fail(model.Invalid)
	}
	return l.put(tableReservations, []byte(r.ID.String()), raw)
}

func (l *ledgerTx) putHead(tier string, h quotaHead) error {
	raw, err := json.Marshal(h)
	if err != nil {
		return model.Fail(model.Invalid)
	}
	return l.put(tableQuotas, []byte(tier), raw)
}

// clearTier removes every record of a quota key (or a settled charge) from tables.
func (l *ledgerTx) clearPrefix(table int, prefix []byte) error {
	var keys [][]byte
	l.each(table, prefix, func(k, _ []byte) bool { keys = append(keys, bytes.Clone(k)); return true })
	for _, k := range keys {
		if _, err := l.del(table, k); err != nil {
			return err
		}
	}
	return nil
}

// clear empties every table (a replacement of the state), and resets the accumulator.
func (l *ledgerTx) clear() error {
	for i, name := range ledgerTables {
		if ovSlotOf(i) >= 0 {
			continue
		}
		if k, _ := l.t[i].Cursor().First(); k == nil {
			continue
		}
		if err := l.tx.DeleteBucket([]byte(name)); err != nil {
			return err
		}
		b, err := l.tx.CreateBucket([]byte(name))
		if err != nil {
			return err
		}
		l.t[i] = boltTable{b}
	}
	if err := l.ov.wipe(); err != nil {
		return err
	}
	if l.open != nil {
		if k, _ := l.open.Cursor().First(); k != nil {
			if err := l.tx.DeleteBucket(openIndexBucket); err != nil {
				return err
			}
			b, err := l.tx.CreateBucket(openIndexBucket)
			if err != nil {
				return err
			}
			l.open = b
		}
	}
	l.acc = [32]byte{}
	l.dirty = true
	return nil
}

// replace makes the ledger hold exactly m.
func (l *ledgerTx) replace(m ledgerMembers) error {
	if err := l.clear(); err != nil {
		return err
	}
	l.fresh = true
	defer func() { l.fresh = false }()
	for id, r := range m.Reservations {
		raw, err := json.Marshal(r)
		if err != nil {
			return model.Fail(model.Invalid)
		}
		if err = l.put(tableReservations, []byte(id), raw); err != nil {
			return err
		}
	}
	for key, id := range m.AdmissionKeys {
		if err := l.put(tableKeys, []byte(key), []byte(id)); err != nil {
			return err
		}
	}
	for tier, q := range m.Quotas {
		if err := l.putQuota(tier, q); err != nil {
			return err
		}
	}
	if s := m.Settlement; s != nil {
		if err := l.putSettlement(s); err != nil {
			return err
		}
	}
	for key, raw := range m.JobBooks {
		if err := l.putBook(tableJobBooks, key, raw); err != nil {
			return err
		}
	}
	for key, raw := range m.IssueBooks {
		if err := l.putBook(tableIssueBooks, key, raw); err != nil {
			return err
		}
	}
	for key, gi := range m.GroupingIssues {
		if err := l.putRecord(tableGroupingIssues, key, mustJSON(gi)); err != nil {
			return err
		}
	}
	for id, r := range m.Commands {
		if err := l.putRecord(tableCommands, id, mustJSON(r)); err != nil {
			return err
		}
	}
	for id, owner := range m.CommandOwners {
		if err := l.put(tableCommandOwners, []byte(id), []byte(owner)); err != nil {
			return err
		}
	}
	for key, raw := range m.JobPositions {
		if err := l.putBook(tableJobPositions, key, raw); err != nil {
			return err
		}
	}
	return l.flush()
}

// recordTable is the table that holds the records of a member addressed as [member, key] (bookRoot).
func recordTable(member string) int {
	switch member {
	case "JobBooks":
		return tableJobBooks
	case "IssueBooks":
		return tableIssueBooks
	case "GroupingIssues":
		return tableGroupingIssues
	case "Commands":
		return tableCommands
	case "JobPositions":
		return tableJobPositions
	}
	return tableCommandOwners
}

// canonicalRecord is the bytes a record of a table of the books is stored as: the compact encoding of the
// object for the job and issue books, the encoding of the decoded value for the grouping issues and the
// commands, the string itself for an owner. The proposer's bytes and every voter's are then the same bytes,
// whatever spacing the command carried.
func canonicalRecord(table int, raw []byte) ([]byte, error) {
	switch table {
	case tableGroupingIssues:
		var gi model.GroupingIssue
		if decodeValue(raw, &gi) != nil {
			return nil, model.Fail(model.Corrupt)
		}
		return json.Marshal(gi)
	case tableCommands:
		var r model.ControlResult
		if decodeValue(raw, &r) != nil {
			return nil, model.Fail(model.Corrupt)
		}
		return json.Marshal(r)
	case tableCommandOwners:
		var owner string
		if decodeValue(raw, &owner) != nil {
			return nil, model.Fail(model.Corrupt)
		}
		return []byte(owner), nil
	}
	return canonicalBook(raw)
}

// putRecord writes a record of the books in its canonical form (canonicalRecord).
func (l *ledgerTx) putRecord(table int, key string, raw []byte) error {
	record, err := canonicalRecord(table, raw)
	if err != nil {
		return err
	}
	return l.put(table, []byte(key), record)
}

// putBook writes a record of the job or issue books in its canonical form: the compact encoding of an
// object.
func (l *ledgerTx) putBook(table int, key string, raw json.RawMessage) error {
	return l.putRecord(table, key, raw)
}

// canonicalBook is the compact encoding of a book record; a record is a JSON object.
func canonicalBook(raw []byte) ([]byte, error) {
	if !isJSONObject(bytes.TrimLeft(raw, " \t\r\n")) {
		return nil, model.Fail(model.Corrupt)
	}
	var out bytes.Buffer
	out.Grow(len(raw))
	if json.Compact(&out, raw) != nil {
		return nil, model.Fail(model.Corrupt)
	}
	return out.Bytes(), nil

}

// putQuota writes a whole quota record: head and series.
func (l *ledgerTx) putQuota(tier string, q model.QuotaState) error {
	if err := l.clearTier(tableSeries, tier); err != nil {
		return err
	}
	for id, n := range q.Series {
		if n == 0 {
			continue
		}
		if err := l.put(tableSeries, seriesKey(tier, id), u64(n)); err != nil {
			return err
		}
	}
	var count uint64
	for _, n := range q.Series {
		if n != 0 {
			count++
		}
	}
	return l.putHead(tier, quotaHead{Bytes: q.Bytes, MaxBytes: q.MaxBytes, MaxSeries: q.MaxSeries, Configured: q.Configured, Series: count})
}

func (l *ledgerTx) delQuota(tier string) error {
	if err := l.clearTier(tableSeries, tier); err != nil {
		return err
	}
	_, err := l.del(tableQuotas, []byte(tier))
	return err
}

func (l *ledgerTx) putCharge(tier string, c model.SettledCharge) error {
	if err := l.clearTier(tableChargeSeries, tier); err != nil {
		return err
	}
	for id, n := range c.Series {
		if n == 0 {
			continue
		}
		if err := l.put(tableChargeSeries, seriesKey(tier, id), u64(n)); err != nil {
			return err
		}
	}
	return l.put(tableCharges, []byte(tier), u64(uint64(c.Bytes)))
}

func (l *ledgerTx) delCharge(tier string) error {
	if err := l.clearTier(tableChargeSeries, tier); err != nil {
		return err
	}
	_, err := l.del(tableCharges, []byte(tier))
	return err
}

func (l *ledgerTx) putSettlement(s *model.Settlement) error {
	for group, span := range s.Spans {
		if err := l.put(tableSpans, []byte(group), u64(span)); err != nil {
			return err
		}
	}
	for key, w := range s.Windows {
		raw, err := json.Marshal(w)
		if err != nil {
			return model.Fail(model.Invalid)
		}
		if err = l.put(tableWindows, []byte(key), raw); err != nil {
			return err
		}
	}
	for tier, c := range s.Charges {
		if err := l.putCharge(tier, c); err != nil {
			return err
		}
	}
	return nil
}

func (l *ledgerTx) clearSettlement() error {
	for _, table := range []int{tableSpans, tableWindows, tableCharges, tableChargeSeries} {
		if err := l.clearPrefix(table, nil); err != nil {
			return err
		}
	}
	return nil
}

// opApplier applies ledger ops, keeping the quota heads it touches in memory until the end so that
// a batch of series ops writes each head once.
type opApplier struct {
	l     *ledgerTx
	heads map[string]*headState
}

type headState struct {
	h      quotaHead
	exists bool
}

func (a *opApplier) head(tier string) (*headState, error) {
	if hs, ok := a.heads[tier]; ok {
		return hs, nil
	}
	h, ok, err := a.l.head(tier)
	if err != nil {
		return nil, err
	}
	hs := &headState{h: h, exists: ok}
	if a.heads == nil {
		a.heads = map[string]*headState{}
	}
	a.heads[tier] = hs
	return hs, nil
}

// applyLedgerOps applies the ops that address the ledger (validLedgerOp holds for each) and stores
// the accumulator. A value that does not decode into the type of its place is corrupt: a proposer
// never writes one.
func (l *ledgerTx) applyLedgerOps(ops []patchOp) error {
	a := &opApplier{l: l}
	for _, op := range ops {
		if err := a.apply(op); err != nil {
			return err
		}
	}
	tiers := make([]string, 0, len(a.heads))
	for tier := range a.heads {
		tiers = append(tiers, tier)
	}
	sort.Strings(tiers)
	for _, tier := range tiers {
		if hs := a.heads[tier]; hs.exists {
			if err := l.putHead(tier, hs.h); err != nil {
				return err
			}
		}
	}
	return l.flush()
}

func decodeValue(raw []byte, v any) error {
	if model.StrictJSON(raw, v) != nil {
		return model.Fail(model.Corrupt)
	}
	return nil
}

func (a *opApplier) apply(op patchOp) error {
	if wholeMemberOp(op) {
		return model.Fail(model.Corrupt) // a whole member is an op of the blob layout, never of the ledger
	}
	l, p := a.l, op.Path
	set := op.Op == opSet
	switch p[0] {
	case "Reservations":
		if !set {
			_, err := l.del(tableReservations, []byte(p[1]))
			return err
		}
		var r model.AdmissionReservation
		if err := decodeValue(op.Value, &r); err != nil {
			return err
		}
		raw, err := json.Marshal(r)
		if err != nil {
			return model.Fail(model.Corrupt)
		}
		return l.put(tableReservations, []byte(p[1]), raw)
	case "JobBooks", "IssueBooks", "GroupingIssues", "Commands", "CommandOwners", "JobPositions":
		table := recordTable(p[0])
		if !set {
			_, err := l.del(table, []byte(p[1]))
			return err
		}
		return l.putRecord(table, p[1], op.Value)
	case "AdmissionKeys":
		if !set {
			_, err := l.del(tableKeys, []byte(p[1]))
			return err
		}
		var id string
		if err := decodeValue(op.Value, &id); err != nil {
			return err
		}
		return l.put(tableKeys, []byte(p[1]), []byte(id))
	case "Quotas":
		return a.quota(op)
	}
	return a.settlement(op)
}

func (a *opApplier) quota(op patchOp) error {
	l, p := a.l, op.Path
	tier := p[1]
	set := op.Op == opSet
	if len(p) == 2 {
		delete(a.heads, tier)
		if !set {
			return l.delQuota(tier)
		}
		var q model.QuotaState
		if err := decodeValue(op.Value, &q); err != nil {
			return err
		}
		return l.putQuota(tier, q)
	}
	hs, err := a.head(tier)
	if err != nil {
		return err
	}
	hs.exists = true
	switch field := p[2]; field {
	case "bytes", "max_bytes", "max_series":
		var v model.Uint64
		if err = decodeValue(op.Value, &v); err != nil {
			return err
		}
		switch field {
		case "bytes":
			hs.h.Bytes = v
		case "max_bytes":
			hs.h.MaxBytes = v
		default:
			hs.h.MaxSeries = v
		}
	case "configured":
		var v bool
		if err = decodeValue(op.Value, &v); err != nil {
			return err
		}
		hs.h.Configured = v
	default: // series
		if len(p) == 3 {
			if err = l.clearTier(tableSeries, tier); err != nil {
				return err
			}
			hs.h.Series = 0
			if !set {
				return nil
			}
			var series map[string]uint64
			if err = decodeValue(op.Value, &series); err != nil {
				return err
			}
			for id, n := range series {
				if n == 0 {
					continue
				}
				if err = l.put(tableSeries, seriesKey(tier, id), u64(n)); err != nil {
					return err
				}
				hs.h.Series++
			}
			return nil
		}
		key := seriesKey(tier, p[3])
		had := l.t[tableSeries].Get(key) != nil
		if !set {
			if _, err = l.del(tableSeries, key); err != nil {
				return err
			}
			if had {
				hs.h.Series--
			}
			return nil
		}
		var n uint64
		if err = decodeValue(op.Value, &n); err != nil || n == 0 {
			return model.Fail(model.Corrupt)
		}
		if err = l.put(tableSeries, key, u64(n)); err != nil {
			return err
		}
		if !had {
			hs.h.Series++
		}
	}
	return nil
}

func (a *opApplier) settlement(op patchOp) error {
	l, p := a.l, op.Path
	set := op.Op == opSet
	if len(p) == 1 {
		if err := l.clearSettlement(); err != nil {
			return err
		}
		if !set || string(op.Value) == "null" {
			return nil
		}
		var s model.Settlement
		if err := decodeValue(op.Value, &s); err != nil {
			return err
		}
		return l.putSettlement(&s)
	}
	switch p[1] {
	case "spans":
		if !set {
			_, err := l.del(tableSpans, []byte(p[2]))
			return err
		}
		var span uint64
		if err := decodeValue(op.Value, &span); err != nil {
			return err
		}
		return l.put(tableSpans, []byte(p[2]), u64(span))
	case "windows":
		if !set {
			_, err := l.del(tableWindows, []byte(p[2]))
			return err
		}
		var w model.SettledWindow
		if err := decodeValue(op.Value, &w); err != nil {
			return err
		}
		raw, err := json.Marshal(w)
		if err != nil {
			return model.Fail(model.Corrupt)
		}
		return l.put(tableWindows, []byte(p[2]), raw)
	}
	tier := p[2]
	if len(p) == 3 {
		if !set {
			return l.delCharge(tier)
		}
		var c model.SettledCharge
		if err := decodeValue(op.Value, &c); err != nil {
			return err
		}
		return l.putCharge(tier, c)
	}
	if p[3] == "bytes" {
		var v model.Uint64
		if err := decodeValue(op.Value, &v); err != nil {
			return err
		}
		return l.put(tableCharges, []byte(tier), u64(uint64(v)))
	}
	if len(p) == 4 {
		if err := l.clearTier(tableChargeSeries, tier); err != nil || !set {
			return err
		}
		var series map[string]uint64
		if err := decodeValue(op.Value, &series); err != nil {
			return err
		}
		for id, n := range series {
			if n == 0 {
				continue
			}
			if err := l.put(tableChargeSeries, seriesKey(tier, id), u64(n)); err != nil {
				return err
			}
		}
		return nil
	}
	if !set {
		_, err := l.del(tableChargeSeries, seriesKey(tier, p[4]))
		return err
	}
	var n uint64
	if err := decodeValue(op.Value, &n); err != nil || n == 0 {
		return model.Fail(model.Corrupt)
	}
	return l.put(tableChargeSeries, seriesKey(tier, p[4]), u64(n))
}

// verifyLedgerOps checks that the ledger already holds what ops write (a replay of a command the
// state has applied): every set value equal, every deleted record absent.
func (l *ledgerTx) verifyLedgerOps(ops []patchOp) error {
	// The check is made on a copy of the ledger's effect: apply the ops in a scratch transaction
	// state is not possible, so each op is compared with the record it addresses.
	for _, op := range ops {
		if err := l.verifyOp(op); err != nil {
			return err
		}
	}
	return nil
}

func (l *ledgerTx) verifyOp(op patchOp) error {
	if wholeMemberOp(op) {
		return model.Fail(model.Corrupt)
	}
	p := op.Path
	set := op.Op == opSet
	bad := model.Fail(model.Corrupt)
	switch p[0] {
	case "Reservations":
		r, ok, err := l.reservation(p[1])
		if err != nil {
			return err
		}
		if !set {
			if ok {
				return bad
			}
			return nil
		}
		var want model.AdmissionReservation
		if decodeValue(op.Value, &want) != nil || !ok || !sameValue(r, want) {
			return bad
		}
	case "JobBooks", "IssueBooks", "GroupingIssues", "Commands", "CommandOwners", "JobPositions":
		table := recordTable(p[0])
		got := l.t[table].Get([]byte(p[1]))
		if !set {
			if got != nil {
				return bad
			}
			return nil
		}
		want, err := canonicalRecord(table, op.Value)
		if err != nil || got == nil || !bytes.Equal(got, want) {
			return bad
		}
	case "AdmissionKeys":
		got, ok := l.keyed(p[1])
		if !set {
			if ok {
				return bad
			}
			return nil
		}
		var want string
		if decodeValue(op.Value, &want) != nil || !ok || got != want {
			return bad
		}
	case "Quotas":
		return l.verifyQuota(op)
	default:
		return l.verifySettlement(op)
	}
	return nil
}

func sameValue(a, b any) bool {
	x, e1 := json.Marshal(a)
	y, e2 := json.Marshal(b)
	return e1 == nil && e2 == nil && bytes.Equal(x, y)
}

func (l *ledgerTx) verifyQuota(op patchOp) error {
	p := op.Path
	set := op.Op == opSet
	bad := model.Fail(model.Corrupt)
	tier := p[1]
	h, ok, err := l.head(tier)
	if err != nil {
		return err
	}
	if len(p) == 2 {
		if !set {
			if ok {
				return bad
			}
			return nil
		}
		var want model.QuotaState
		if decodeValue(op.Value, &want) != nil || !ok || h.Bytes != want.Bytes || h.MaxBytes != want.MaxBytes || h.MaxSeries != want.MaxSeries || h.Configured != want.Configured {
			return bad
		}
		var count uint64
		for id, n := range want.Series {
			if n == 0 {
				continue
			}
			count++
			if l.series(tier, id) != n {
				return bad
			}
		}
		if count != h.Series {
			return bad
		}
		return nil
	}
	if !ok {
		return bad
	}
	switch field := p[2]; field {
	case "bytes", "max_bytes", "max_series":
		var v model.Uint64
		if decodeValue(op.Value, &v) != nil {
			return bad
		}
		got := map[string]model.Uint64{"bytes": h.Bytes, "max_bytes": h.MaxBytes, "max_series": h.MaxSeries}[field]
		if got != v {
			return bad
		}
	case "configured":
		var v bool
		if decodeValue(op.Value, &v) != nil || h.Configured != v {
			return bad
		}
	default:
		if len(p) == 3 {
			if !set {
				if h.Series != 0 {
					return bad
				}
				return nil
			}
			var series map[string]uint64
			if decodeValue(op.Value, &series) != nil {
				return bad
			}
			var count uint64
			for id, n := range series {
				if n == 0 {
					continue
				}
				count++
				if l.series(tier, id) != n {
					return bad
				}
			}
			if count != h.Series {
				return bad
			}
			return nil
		}
		got := l.series(tier, p[3])
		if !set {
			if got != 0 {
				return bad
			}
			return nil
		}
		var n uint64
		if decodeValue(op.Value, &n) != nil || got != n {
			return bad
		}
	}
	return nil
}

func (l *ledgerTx) verifySettlement(op patchOp) error {
	p := op.Path
	set := op.Op == opSet
	bad := model.Fail(model.Corrupt)
	if len(p) == 1 {
		var want model.Settlement
		if !set || string(op.Value) == "null" {
			if !l.tableEmpty(tableSpans) || !l.tableEmpty(tableWindows) || !l.tableEmpty(tableCharges) {
				return bad
			}
			return nil
		}
		if decodeValue(op.Value, &want) != nil {
			return bad
		}
		m, err := l.members()
		if err != nil {
			return err
		}
		if !sameValue(m.normalized().Settlement, ledgerMembers{Settlement: &want}.normalized().Settlement) {
			return bad
		}
		return nil
	}
	switch p[1] {
	case "spans":
		got := l.span(p[2])
		if !set {
			if got != 0 {
				return bad
			}
			return nil
		}
		var span uint64
		if decodeValue(op.Value, &span) != nil || got != span {
			return bad
		}
	case "windows":
		w, ok, err := l.window(p[2])
		if err != nil {
			return err
		}
		if !set {
			if ok {
				return bad
			}
			return nil
		}
		var want model.SettledWindow
		if decodeValue(op.Value, &want) != nil || !ok || !sameValue(w, want) {
			return bad
		}
	default:
		tier := p[2]
		bytesNow, ok := l.charge(tier)
		if len(p) == 3 {
			if !set {
				if ok {
					return bad
				}
				return nil
			}
			var want model.SettledCharge
			if decodeValue(op.Value, &want) != nil || !ok || uint64(want.Bytes) != bytesNow {
				return bad
			}
			for id, n := range want.Series {
				if n != 0 && l.chargeSeries(tier, id) != n {
					return bad
				}
			}
			return nil
		}
		if p[3] == "bytes" {
			var v model.Uint64
			if decodeValue(op.Value, &v) != nil || !ok || uint64(v) != bytesNow {
				return bad
			}
			return nil
		}
		if len(p) == 4 {
			if !set {
				return nil
			}
			var series map[string]uint64
			if decodeValue(op.Value, &series) != nil {
				return bad
			}
			for id, n := range series {
				if n != 0 && l.chargeSeries(tier, id) != n {
					return bad
				}
			}
			return nil
		}
		got := l.chargeSeries(tier, p[4])
		if !set {
			if got != 0 {
				return bad
			}
			return nil
		}
		var n uint64
		if decodeValue(op.Value, &n) != nil || got != n {
			return bad
		}
	}
	return nil
}

// logical state

// loadLogical decodes the committed state with the ledger members assembled in (a file that keeps its
// books in the blob has them from the decode).
func loadLogical(tx *bolt.Tx, st *State) error {
	ctrl := tx.Bucket([]byte("control"))
	if err := readState(ctrl, st); err != nil {
		return err
	}
	if !ledgerLayout(ctrl) {
		return nil
	}
	l, err := openLedger(tx)
	if err != nil {
		return err
	}
	m, err := l.members()
	if err != nil {
		return err
	}
	attachLedger(st, m)
	return nil
}

// committedBase is the digest of the committed state a proposer names, for the encoding raw of the state
// without the ledger and the ledger's accumulator acc: ledgerBase. Only a group whose books are in the
// ledger names it (a group that keeps them in the blob names the digest of the blob, patchBase, which is
// the digest of the logical state the previous release computes).
func committedBase(raw []byte, acc [32]byte) (string, error) {
	stripped, v, err := splitVolatile(raw)
	if err != nil {
		return "", err
	}
	digest, err := hashStripped(stripped)
	if err != nil {
		return "", err
	}
	return ledgerBase(digest, v.revision, v.clock, acc), nil
}

// baseMatches says whether base names the committed state: the digest of the blob alone when the books
// are in the blob (the layout of the previous release), ledgerBase when they are in the ledger. The
// digest a build named that kept the revision in the blob (ledgerBase1) is accepted for the same state: a
// command it proposed can be in a journal that this build replays.
func baseMatches(tx *bolt.Tx, base string) (bool, error) {
	ctrl := tx.Bucket([]byte("control"))
	raw := ctrl.Get(stateKey)
	if !ledgerLayout(ctrl) {
		var blob string
		var ok bool
		if root := scanStateRoot(raw); root.ok {
			blob, ok = patchBaseRoot(raw, root)
		} else {
			var err error
			blob, err = patchBase(raw)
			ok = err == nil
		}
		return ok && blob == base, nil
	}
	l, err := openLedger(tx)
	if err != nil {
		return false, err
	}
	if layoutBase(ctrl, l.acc) == base {
		return true, nil
	}
	whole, err := stateRaw(ctrl)
	if err != nil {
		return false, err
	}
	blob, err := patchBase(whole)
	if err != nil {
		return false, nil
	}
	return ledgerBase1(blob, l.acc) == base, nil
}

// diffLedger is the ops that take the ledger members before to the ones after (both normalized): a
// quota record is addressed by its fields and series, a record of a book by its key.
func diffLedger(before, after ledgerMembers) []patchOp {
	var ops []patchOp
	set := func(path []string, v any) {
		raw, _ := json.Marshal(v)
		ops = append(ops, patchOp{Op: opSet, Path: path, Value: raw})
	}
	del := func(path []string) { ops = append(ops, patchOp{Op: opDelete, Path: path}) }
	for id, r := range after.Reservations {
		if old, ok := before.Reservations[id]; !ok || !sameValue(old, r) {
			set([]string{"Reservations", id}, r)
		}
	}
	for id := range before.Reservations {
		if _, ok := after.Reservations[id]; !ok {
			del([]string{"Reservations", id})
		}
	}
	for key, id := range after.AdmissionKeys {
		if old, ok := before.AdmissionKeys[key]; !ok || old != id {
			set([]string{"AdmissionKeys", key}, id)
		}
	}
	for key := range before.AdmissionKeys {
		if _, ok := after.AdmissionKeys[key]; !ok {
			del([]string{"AdmissionKeys", key})
		}
	}
	for tier, q := range after.Quotas {
		old, ok := before.Quotas[tier]
		if !ok {
			set([]string{"Quotas", tier}, q)
			continue
		}
		if old.Bytes != q.Bytes {
			set([]string{"Quotas", tier, "bytes"}, q.Bytes)
		}
		if old.MaxBytes != q.MaxBytes {
			set([]string{"Quotas", tier, "max_bytes"}, q.MaxBytes)
		}
		if old.MaxSeries != q.MaxSeries {
			set([]string{"Quotas", tier, "max_series"}, q.MaxSeries)
		}
		if old.Configured != q.Configured {
			set([]string{"Quotas", tier, "configured"}, q.Configured)
		}
		for id, n := range q.Series {
			if old.Series[id] != n {
				if n == 0 {
					del([]string{"Quotas", tier, "series", id})
				} else {
					set([]string{"Quotas", tier, "series", id}, n)
				}
			}
		}
		for id := range old.Series {
			if _, ok := q.Series[id]; !ok {
				del([]string{"Quotas", tier, "series", id})
			}
		}
	}
	for tier := range before.Quotas {
		if _, ok := after.Quotas[tier]; !ok {
			del([]string{"Quotas", tier})
		}
	}
	diffBooks := func(member string, before, after map[string]json.RawMessage) {
		for key, raw := range after {
			if old, ok := before[key]; !ok || !bytes.Equal(old, raw) {
				ops = append(ops, patchOp{Op: opSet, Path: []string{member, key}, Value: raw})
			}
		}
		for key := range before {
			if _, ok := after[key]; !ok {
				del([]string{member, key})
			}
		}
	}
	diffBooks("JobBooks", before.JobBooks, after.JobBooks)
	diffBooks("IssueBooks", before.IssueBooks, after.IssueBooks)
	for key, gi := range after.GroupingIssues {
		if old, ok := before.GroupingIssues[key]; !ok || !sameValue(old, gi) {
			set([]string{"GroupingIssues", key}, gi)
		}
	}
	for key := range before.GroupingIssues {
		if _, ok := after.GroupingIssues[key]; !ok {
			del([]string{"GroupingIssues", key})
		}
	}
	for id, r := range after.Commands {
		if old, ok := before.Commands[id]; !ok || !sameValue(old, r) {
			set([]string{"Commands", id}, r)
		}
	}
	for id := range before.Commands {
		if _, ok := after.Commands[id]; !ok {
			del([]string{"Commands", id})
		}
	}
	for id, owner := range after.CommandOwners {
		if old, ok := before.CommandOwners[id]; !ok || old != owner {
			set([]string{"CommandOwners", id}, owner)
		}
	}
	for id := range before.CommandOwners {
		if _, ok := after.CommandOwners[id]; !ok {
			del([]string{"CommandOwners", id})
		}
	}
	diffBooks("JobPositions", before.JobPositions, after.JobPositions)
	// The settlement is small next to the books and written only by SettleAdmissions: one op for it.
	if !sameValue(before.Settlement, after.Settlement) {
		if after.Settlement == nil {
			del([]string{"settlement"})
		} else {
			set([]string{"settlement"}, after.Settlement)
		}
	}
	sort.Slice(ops, func(i, j int) bool { return pathLess(ops[i].Path, ops[j].Path) })
	return ops
}

func pathLess(a, b []string) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		panic("control: unencodable ledger value: " + err.Error())
	}
	return raw
}

// initLedger makes the ledger of tx hold m (nil: nothing) and marks the file as one that keeps its books
// there: the buckets, the format marker and the records, and a blob that holds the state without its
// revision (state_layout.go). It is the ledger half of the install of a state of a contracted installation
// (a seed, a snapshot, the activation of the layout).
func initLedger(tx *bolt.Tx, m *ledgerMembers) error {
	if err := ensureLedger(tx); err != nil {
		return err
	}
	l, err := openLedger(tx)
	if err != nil {
		return err
	}
	var held ledgerMembers
	if m != nil {
		held = *m
	}
	if err = l.replace(held); err != nil {
		return err
	}
	if !ledgerLayout(l.ctrl) {
		if err = stripBlob(l.ctrl); err != nil {
			return err
		}
	}
	if err = l.ctrl.Put(ledgerFormatKey, ledgerFormat); err != nil {
		return err
	}
	return l.ctrl.Put(ledgerSealKey, l.ctrl.Get(stateSealKey))
}

// resetLedger makes the file one that keeps its books in the blob, as the previous release does: the
// ledger is emptied and the format marker removed, with the keys that hold the revision outside the blob.
// The caller writes the whole state to the blob (putState) after it.
func resetLedger(tx *bolt.Tx) error {
	if err := ensureLedger(tx); err != nil {
		return err
	}
	l, err := openLedger(tx)
	if err != nil {
		return err
	}
	if err = l.replace(ledgerMembers{}); err != nil {
		return err
	}
	for _, key := range [][]byte{ledgerFormatKey, ledgerSealKey, ledgerAccKey} {
		if err = l.ctrl.Delete(key); err != nil {
			return err
		}
	}
	return dropLayoutKeys(l.ctrl)
}

// putLogicalState installs a whole logical state in the layout of its installation: with the books in the
// ledger when it is contracted (see ledgerLayout), in the blob otherwise. The state seal moves with the
// blob.
func putLogicalState(tx *bolt.Tx, st State) error {
	ctrl := tx.Bucket([]byte("control"))
	if ctrl == nil {
		return model.Fail(model.Corrupt)
	}
	if !logicalContracted(&st) {
		raw, err := json.Marshal(st)
		if err != nil {
			return err
		}
		if err = resetLedger(tx); err != nil {
			return err
		}
		return putState(ctrl, raw)
	}
	held := detachLedger(&st).normalized()
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err = putState(ctrl, raw); err != nil {
		return err
	}
	return initLedger(tx, &held)
}

// migrateLedger settles the layout of the file in the transaction that opens it or applies a command to
// it. A file whose state is contracted keeps its books in the ledger: the members the blob still holds
// (a file of an installation that was just contracted, or one the ledger was never given) are moved in
// that transaction and the blob keeps none of them and no revision (state_layout.go). A file of an
// installation that is not contracted is left as it is, books in the blob, the way the previous release
// holds them. A file of the first build of the ledger layout (legacyLedgerFormat) keeps the books where
// they are and loses the revision from its blob. A file that has the ledger format is moved again from
// its blob when the blob was written after the ledger (the two seals differ: a build that does not know
// the ledger committed on the file).
func migrateLedger(tx *bolt.Tx) error {
	if err := ensureLedger(tx); err != nil {
		return err
	}
	ctrl := tx.Bucket([]byte("control"))
	raw := ctrl.Get(stateKey)
	sealsAgree := bytes.Equal(ctrl.Get(ledgerSealKey), ctrl.Get(stateSealKey))
	switch {
	case ledgerLayout(ctrl):
		if sealsAgree {
			return ensureOpenIndex(tx)
		}
	case bytes.Equal(ctrl.Get(ledgerFormatKey), previousLedgerFormat):
		if sealsAgree {
			return moveSeriesToBlocks(tx, ctrl)
		}
	case bytes.Equal(ctrl.Get(ledgerFormatKey), legacyLedgerFormat) || bytes.Equal(ctrl.Get(ledgerFormatKey), booksInBlobFormat) || bytes.Equal(ctrl.Get(ledgerFormatKey), hotMembersInBlobFormat):
		if sealsAgree {
			return moveBooksToLedger(tx, ctrl)
		}
	case !blobContracted(raw):
		return nil
	}
	var st State
	if json.Unmarshal(raw, &st) != nil {
		return model.Fail(model.Corrupt)
	}
	held := detachLedger(&st).normalized()
	whole, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err = putState(ctrl, whole); err != nil {
		return err
	}
	return initLedger(tx, &held)
}

// moveBooksToLedger moves a file of an earlier build of the layout to this one: the admission books are
// already records, the job and issue books are taken out of the blob into theirs and the blob is written
// without them (and without the revision, which the first build of the layout kept in it). It is the one
// step of Open for such a file, in the transaction that opens it.
func moveBooksToLedger(tx *bolt.Tx, ctrl *bolt.Bucket) error {
	var st State
	if json.Unmarshal(ctrl.Get(stateKey), &st) != nil {
		return model.Fail(model.Corrupt)
	}
	if format := ctrl.Get(ledgerFormatKey); bytes.Equal(format, booksInBlobFormat) || bytes.Equal(format, hotMembersInBlobFormat) {
		if err := attachVolatile(ctrl, &st); err != nil {
			return err
		}
	}
	books := detachScope(&st, scopeBooks|scopeCommands).normalized()
	whole, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err = putStateLayout(ctrl, whole); err != nil {
		return err
	}
	l, err := openLedger(tx)
	if err != nil {
		return err
	}
	if err = l.blockSeriesTables(true); err != nil {
		return err
	}
	for key, raw := range books.JobBooks {
		if err = l.putBook(tableJobBooks, key, raw); err != nil {
			return err
		}
	}
	for key, raw := range books.IssueBooks {
		if err = l.putBook(tableIssueBooks, key, raw); err != nil {
			return err
		}
	}
	for key, gi := range books.GroupingIssues {
		if err = l.putRecord(tableGroupingIssues, key, mustJSON(gi)); err != nil {
			return err
		}
	}
	for id, r := range books.Commands {
		if err = l.putRecord(tableCommands, id, mustJSON(r)); err != nil {
			return err
		}
	}
	for id, owner := range books.CommandOwners {
		if err = l.put(tableCommandOwners, []byte(id), []byte(owner)); err != nil {
			return err
		}
	}
	for key, raw := range books.JobPositions {
		if err = l.putBook(tableJobPositions, key, raw); err != nil {
			return err
		}
	}
	if err = l.flush(); err != nil {
		return err
	}
	if err = ctrl.Put(ledgerFormatKey, ledgerFormat); err != nil {
		return err
	}
	return ctrl.Put(ledgerSealKey, ctrl.Get(stateSealKey))
}

// noteLayout records the layout of the file (layoutLedger).
func (s *Store) noteLayout() {
	_ = s.db.View(func(tx *bolt.Tx) error {
		s.layoutLedger.Store(ledgerLayout(tx.Bucket([]byte("control"))))
		return nil
	})
}

// noteSettled tells the store, once, that its ledger already holds settled windows (settledSeen).
func (s *Store) noteSettled() {
	_ = s.db.View(func(tx *bolt.Tx) error {
		if l, err := openLedger(tx); err == nil && l.hasWindows() {
			s.settledSeen.Store(true)
		}
		return nil
	})
}

// commandNamesContraction says whether a control command writes the mark of a contracted installation.
func commandNamesContraction(cmd *controlCommand) bool {
	switch {
	case cmd.patch != nil:
		for _, op := range cmd.patch.Ops {
			if slices.Contains(op.Path, model.IndexesContractedKey) || bytes.Contains(op.Value, contractedMark) {
				return true
			}
		}
	case cmd.replacement != nil:
		return logicalContracted(&cmd.replacement.State)
	}
	return false
}

// onlyStepOps says whether ops write nothing but the revision and its clock: a command that does
// leaves the blob as it was for every reader of the state without the ledger (coreState).
func onlyStepOps(ops []patchOp) bool {
	for _, op := range ops {
		if len(op.Path) != 1 || op.Op != opSet || op.Path[0] != "Revision" && op.Path[0] != "revision_clock" {
			return false
		}
	}
	return len(ops) != 0
}

// wholeMemberOp says whether op sets or deletes a whole book (Reservations, AdmissionKeys, Quotas) as one
// member of the state: what a file that keeps its books in the blob receives from a proposer that diffs
// whole states (a map that was null becomes the map). A file that keeps them in the ledger refuses it.
func wholeMemberOp(op patchOp) bool {
	p := op.Path
	return len(p) == 1 && (p[0] == "Reservations" || p[0] == "AdmissionKeys" || p[0] == "Quotas" || bookRoot(p[0])) && (op.Op == opSet || op.Op == opDelete)
}

// moveSeriesToBlocks moves a file of the layout before the overlay (previousLedgerFormat) to this one: the series
// tables become blocks, the records and the accumulator are what they were. It is the one step of Open for such a
// file, in the transaction that opens it.
func moveSeriesToBlocks(tx *bolt.Tx, ctrl *bolt.Bucket) error {
	l, err := openLedger(tx)
	if err != nil {
		return err
	}
	if err = l.blockSeriesTables(false); err != nil {
		return err
	}
	if err = ctrl.Put(ledgerFormatKey, ledgerFormat); err != nil {
		return err
	}
	return ensureOpenIndex(tx)
}

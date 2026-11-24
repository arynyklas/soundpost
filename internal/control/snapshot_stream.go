// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"reflect"
	"strconv"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The control group cuts a snapshot every DefaultJournalCadence (about every ten seconds under admission
// load) and compacts its journal onto it. The snapshot is the whole logical state: the blob, and the
// ledger's records (a reservation per batch not yet settled, the books of every series). It used to be
// made by decoding all of it into a State, encoding that, and the cut was 17 % of the server's CPU at the
// single-host gate: the ledger alone is hundreds of thousands of records.
//
// snapshotState writes the same bytes without a decode: the blob is carried as it is (joined with the
// revision, in layout 2), and every record of the ledger is already the JSON that encoding the State
// writes for it (the reservation rows, whose encoding is what the apply stored), so the books are
// assembled around the records, in key order, which is the order the encoder writes map keys in.
// TestSnapshotStreamEqualsMarshal pins that the bytes are the ones json.Marshal(State) writes.

// appendJSONString appends the encoding of the string s: the plain ones by hand, the rest by the encoder.
func appendJSONString(out []byte, s []byte) []byte {
	for _, c := range s {
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
			quoted, _ := json.Marshal(string(s))
			return append(out, quoted...)
		}
	}
	out = append(out, '"')
	out = append(out, s...)
	return append(out, '"')
}

// appendQuotedUint appends a model.Uint64: the decimal in quotes.
func appendQuotedUint(out []byte, v uint64) []byte {
	out = append(out, '"')
	out = strconv.AppendUint(out, v, 10)
	return append(out, '"')
}

// appendReservations appends the Reservations member's value (null when the table is empty).
func (l *ledgerTx) appendReservations(out []byte) []byte {
	c := l.t[tableReservations].Cursor()
	k, v := c.First()
	if k == nil {
		return append(out, "null"...)
	}
	out = append(out, '{')
	for first := true; k != nil; k, v = c.Next() {
		if !first {
			out = append(out, ',')
		}
		first = false
		out = appendJSONString(out, k)
		out = append(out, ':')
		out = append(out, v...)
	}
	return append(out, '}')
}

// appendRecords appends the value of a member whose records are the JSON of their values (the grouping issues,
// the commands): null when there is none.
func (l *ledgerTx) appendRecords(out []byte, table int) []byte {
	c := l.t[table].Cursor()
	k, v := c.First()
	if k == nil {
		return append(out, "null"...)
	}
	out = append(out, '{')
	for first := true; k != nil; k, v = c.Next() {
		if !first {
			out = append(out, ',')
		}
		first = false
		out = appendJSONString(out, k)
		out = append(out, ':')
		out = append(out, v...)
	}
	return append(out, '}')
}

// appendOwners appends the CommandOwners member's value.
func (l *ledgerTx) appendOwners(out []byte) []byte {
	c := l.t[tableCommandOwners].Cursor()
	k, v := c.First()
	if k == nil {
		return append(out, "null"...)
	}
	out = append(out, '{')
	for first := true; k != nil; k, v = c.Next() {
		if !first {
			out = append(out, ',')
		}
		first = false
		out = appendJSONString(out, k)
		out = append(out, ':')
		out = appendJSONString(out, v)
	}
	return append(out, '}')
}

// appendBooks appends the value of the job or issue books member (table): what json.Marshal writes for the map of
// records (null when there is none), so the records are escaped the way the encoder escapes a RawMessage.
func (l *ledgerTx) appendBooks(out []byte, table int) ([]byte, error) {
	var books map[string]json.RawMessage
	c := l.t[table].Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if books == nil {
			books = map[string]json.RawMessage{}
		}
		books[string(k)] = v
	}
	raw, err := json.Marshal(books)
	if err != nil {
		return nil, model.Fail(model.Corrupt)
	}
	return append(out, raw...), nil
}

// appendKeys appends the AdmissionKeys member's value.
func (l *ledgerTx) appendKeys(out []byte) []byte {
	c := l.t[tableKeys].Cursor()
	k, v := c.First()
	if k == nil {
		return append(out, "null"...)
	}
	out = append(out, '{')
	for first := true; k != nil; k, v = c.Next() {
		if !first {
			out = append(out, ',')
		}
		first = false
		out = appendJSONString(out, k)
		out = append(out, ':')
		out = appendJSONString(out, v)
	}
	return append(out, '}')
}

// seriesRecord is one reference count of the series table; id is a view of the transaction's own bytes.
type seriesRecord struct {
	id []byte
	n  uint64
}

// seriesByTier lists the records of the series table under each quota key, each list in series order. The table
// is series-major, so one pass over it finds them all, and a pass in key order meets the series in order.
func (l *ledgerTx) seriesByTier() map[string][]seriesRecord {
	out := map[string][]seriesRecord{}
	c := l.t[tableSeries].Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		tier, id := splitSeriesKeyBytes(k)
		out[string(tier)] = append(out[string(tier)], seriesRecord{id: id, n: readU64(v)})
	}
	return out
}

// appendQuotas appends the Quotas member's value: per quota key the record as model.QuotaState encodes it.
func (l *ledgerTx) appendQuotas(out []byte) ([]byte, error) {
	c := l.t[tableQuotas].Cursor()
	k, v := c.First()
	if k == nil {
		return append(out, "null"...), nil
	}
	series := l.seriesByTier()
	out = append(out, '{')
	for first := true; k != nil; k, v = c.Next() {
		var h quotaHead
		if json.Unmarshal(v, &h) != nil {
			return nil, model.Fail(model.Corrupt)
		}
		if !first {
			out = append(out, ',')
		}
		first = false
		out = appendJSONString(out, k)
		out = append(out, `:{"bytes":`...)
		out = appendQuotedUint(out, uint64(h.Bytes))
		out = append(out, `,"series":`...)
		records := series[string(k)]
		if len(records) == 0 {
			out = append(out, "null"...)
		} else {
			out = append(out, '{')
			for i, r := range records {
				if i > 0 {
					out = append(out, ',')
				}
				out = appendJSONString(out, r.id)
				out = append(out, ':')
				out = strconv.AppendUint(out, r.n, 10)
			}
			out = append(out, '}')
		}
		out = append(out, `,"max_bytes":`...)
		out = appendQuotedUint(out, uint64(h.MaxBytes))
		out = append(out, `,"max_series":`...)
		out = appendQuotedUint(out, uint64(h.MaxSeries))
		out = append(out, `,"configured":`...)
		out = strconv.AppendBool(out, h.Configured)
		out = append(out, '}')
	}
	return append(out, '}'), nil
}

// settlementMember is the Settlement member the ledger's settlement tables hold (nil: none).
func (l *ledgerTx) settlementMember() (*model.Settlement, error) {
	var s *model.Settlement
	get := func() *model.Settlement {
		if s == nil {
			s = &model.Settlement{}
		}
		return s
	}
	walk := func(table int, fn func(k, v []byte) error) error {
		c := l.t[table].Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if err := fn(k, v); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(tableSpans, func(k, v []byte) error {
		if get().Spans == nil {
			s.Spans = map[string]uint64{}
		}
		s.Spans[string(k)] = readU64(v)
		return nil
	}); err != nil {
		return nil, err
	}
	if err := walk(tableWindows, func(k, v []byte) error {
		var w model.SettledWindow
		if json.Unmarshal(v, &w) != nil {
			return model.Fail(model.Corrupt)
		}
		if get().Windows == nil {
			s.Windows = map[string]model.SettledWindow{}
		}
		s.Windows[string(k)] = w
		return nil
	}); err != nil {
		return nil, err
	}
	if err := walk(tableCharges, func(k, v []byte) error {
		if get().Charges == nil {
			s.Charges = map[string]model.SettledCharge{}
		}
		s.Charges[string(k)] = model.SettledCharge{Bytes: model.Uint64(readU64(v))}
		return nil
	}); err != nil {
		return nil, err
	}
	if err := walk(tableChargeSeries, func(k, v []byte) error {
		tier, id := splitSeriesKeyBytes(k)
		c, ok := get().Charges[string(tier)]
		if !ok {
			return model.Fail(model.Corrupt)
		}
		if c.Series == nil {
			c.Series = map[string]uint64{}
		}
		c.Series[string(id)] = readU64(v)
		s.Charges[string(tier)] = c
		return nil
	}); err != nil {
		return nil, err
	}
	return s, nil
}

// snapshotState is the encoding json.Marshal writes for the logical state of the transaction (the books in
// the ledger put back into the members they came from), made without decoding it.
func snapshotState(tx *bolt.Tx) ([]byte, error) {
	ctrl := tx.Bucket([]byte("control"))
	if !ledgerLayout(ctrl) {
		var st State
		if err := loadLogical(tx, &st); err != nil {
			return nil, err
		}
		return json.Marshal(st)
	}
	raw, err := stateRaw(ctrl)
	if err != nil {
		return nil, err
	}
	l, err := openLedger(tx)
	if err != nil {
		return nil, err
	}
	members, ok := scanObject(raw, 0, len(raw), make([]rawMember, 0, 64))
	ot := describeObject(reflect.TypeFor[State]())
	if !ok || ot == nil {
		return slowSnapshotState(tx)
	}
	settlement, err := l.settlementMember()
	if err != nil {
		return nil, err
	}
	var settlementRaw []byte
	if settlement != nil {
		if settlementRaw, err = json.Marshal(settlement); err != nil {
			return nil, model.Fail(model.Corrupt)
		}
	}
	settlementField := ot.byName["settlement"]
	if settlementField == nil {
		return slowSnapshotState(tx)
	}
	out := make([]byte, 0, len(raw)+1<<20)
	out = append(out, '{')
	first, settlementDone := true, settlement == nil
	next := func(name string) {
		if !first {
			out = append(out, ',')
		}
		first = false
		out = append(out, '"')
		out = append(out, name...)
		out = append(out, `":`...)
	}
	booksSeen := 0
	for _, m := range members {
		name, named := unquoteMemberName(raw, m)
		field := ot.byName[name]
		if !named || field == nil || name == "settlement" {
			return slowSnapshotState(tx)
		}
		if !settlementDone && field.order > settlementField.order {
			next("settlement")
			out = append(out, settlementRaw...)
			settlementDone = true
		}
		switch name {
		case "Reservations":
			booksSeen++
			next(name)
			out = l.appendReservations(out)
		case "AdmissionKeys":
			booksSeen++
			next(name)
			out = l.appendKeys(out)
		case "Quotas":
			booksSeen++
			next(name)
			if out, err = l.appendQuotas(out); err != nil {
				return nil, err
			}
		case "JobBooks", "IssueBooks":
			booksSeen++
			next(name)
			table := tableJobBooks
			if name == "IssueBooks" {
				table = tableIssueBooks
			}
			if out, err = l.appendBooks(out, table); err != nil {
				return nil, err
			}
		case "GroupingIssues":
			booksSeen++
			next(name)
			out = l.appendRecords(out, tableGroupingIssues)
		case "Commands":
			booksSeen++
			next(name)
			out = l.appendRecords(out, tableCommands)
		case "CommandOwners":
			booksSeen++
			next(name)
			out = l.appendOwners(out)
		default:
			if !first {
				out = append(out, ',')
			}
			first = false
			out = append(out, raw[m.ks:m.ve]...)
		}
	}
	if booksSeen != 8 {
		return slowSnapshotState(tx)
	}
	if !settlementDone {
		next("settlement")
		out = append(out, settlementRaw...)
	}
	// The last member of the state, omitted from the blob when there is none (and from the encoding the state
	// writes): written after everything else, as the encoder writes it.
	if k, _ := l.t[tableJobPositions].Cursor().First(); k != nil {
		next("JobPositions")
		if out, err = l.appendBooks(out, tableJobPositions); err != nil {
			return nil, err
		}
	}
	return append(out, '}'), nil
}

// slowSnapshotState is snapshotState by decoding and encoding the state.
func slowSnapshotState(tx *bolt.Tx) ([]byte, error) {
	var st State
	if err := loadLogical(tx, &st); err != nil {
		return nil, err
	}
	return json.Marshal(st)
}

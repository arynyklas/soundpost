// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The base of the series tables (D83): the reference counts of the series under each quota key, and the settled ones,
// as ovBlocks blocks by the hash of the series. A series is a row of its block: its name once, and the count under each
// quota key it is charged under, the quota key as its number in the dictionary of the file (adm_tiers; the quota
// keys of a ledger are few and a series name is not). The blocks are what a fold of the overlay writes (ledger_overlay.go):
// a generation of records touches at most ovBlocks pages (and the pages of the rows it touches, no more) whatever the ledger
// holds, where one leaf of a sorted table of the records is written for each series of a commit. The records the
// ledger reads and digests are the logical ones (the series name, a NUL, the quota key; a count of eight bytes): the
// blocks only hold them.

const ovBlocks = 4096

func blockKey(b uint32) []byte { return []byte{byte(b >> 8), byte(b)} }

// blockOfID is the block of the series with the given name.
func blockOfID(id []byte) uint32 {
	h := uint32(2166136261)
	for _, c := range id {
		h ^= uint32(c)
		h *= 16777619
	}
	return h % ovBlocks
}

// blockOfKey is the block of a logical record (the series name, a NUL, the quota key).
func blockOfKey(k string) uint32 {
	h := uint32(2166136261)
	for i := range len(k) {
		if k[i] == 0 {
			break
		}
		h ^= uint32(k[i])
		h *= 16777619
	}
	return h % ovBlocks
}

type blockTier struct {
	ord uint32
	n   uint64
}

type blockRow struct {
	id    []byte
	tiers []blockTier // by ord
}

// blockStore is the blocks of one series table and the dictionary of the quota keys.
type blockStore struct {
	b, tiers *bolt.Bucket
}

// ordOf is the number of a quota key in the dictionary.
func (s *blockStore) ordOf(tier []byte) (uint32, bool) {
	var buf [128]byte
	raw := s.tiers.Get(append(append(buf[:0], 't'), tier...))
	if raw == nil {
		return 0, false
	}
	v, n := binary.Uvarint(raw)
	return uint32(v), n > 0
}

func (s *blockStore) nameOf(ord uint32) []byte {
	var k [5]byte
	k[0] = 'o'
	binary.BigEndian.PutUint32(k[1:], ord)
	return s.tiers.Get(k[:])
}

// ensureOrd is the number of a quota key, given one when it has none.
func (s *blockStore) ensureOrd(tier []byte) (uint32, error) {
	if ord, ok := s.ordOf(tier); ok {
		return ord, nil
	}
	seq, err := s.tiers.NextSequence()
	if err != nil {
		return 0, err
	}
	ord := uint32(seq)
	if err = s.tiers.Put(append([]byte{'t'}, tier...), binary.AppendUvarint(nil, seq)); err != nil {
		return 0, err
	}
	k := []byte{'o', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(k[1:], ord)
	return ord, s.tiers.Put(k, bytes.Clone(tier))
}

// blockFind is the count of the series id under the quota key number ord in the encoding of a block, 0 when it has none.
func blockFind(raw, id []byte, ord uint32) uint64 {
	rows, off := binary.Uvarint(raw)
	if off <= 0 {
		return 0
	}
	p := off
	for ; rows > 0; rows-- {
		l, k := binary.Uvarint(raw[p:])
		if k <= 0 || p+k+int(l) > len(raw) {
			return 0
		}
		p += k
		match := bytes.Equal(raw[p:p+int(l)], id)
		p += int(l)
		nt, k := binary.Uvarint(raw[p:])
		if k <= 0 {
			return 0
		}
		p += k
		for ; nt > 0; nt-- {
			o, k1 := binary.Uvarint(raw[p:])
			if k1 <= 0 {
				return 0
			}
			p += k1
			c, k2 := binary.Uvarint(raw[p:])
			if k2 <= 0 {
				return 0
			}
			p += k2
			if match && uint32(o) == ord {
				return c
			}
		}
		if match {
			return 0
		}
	}
	return 0
}

// get is the value of a logical record: the count as eight bytes, nil when the series has none under the quota key.
func (s *blockStore) get(key []byte) []byte {
	tier, id := splitSeriesKeyBytes(key)
	ord, ok := s.ordOf(tier)
	if !ok {
		return nil
	}
	raw := s.b.Get(blockKey(blockOfID(id)))
	if raw == nil {
		return nil
	}
	if n := blockFind(raw, id, ord); n != 0 {
		return u64(n)
	}
	return nil
}

func decodeBlock(raw []byte) ([]blockRow, error) {
	if raw == nil {
		return nil, nil
	}
	bad := model.Fail(model.Corrupt)
	rows, off := binary.Uvarint(raw)
	if off <= 0 {
		return nil, bad
	}
	p := off
	out := make([]blockRow, 0, rows)
	for ; rows > 0; rows-- {
		l, k := binary.Uvarint(raw[p:])
		if k <= 0 || p+k+int(l) > len(raw) {
			return nil, bad
		}
		p += k
		row := blockRow{id: raw[p : p+int(l)]}
		p += int(l)
		nt, k := binary.Uvarint(raw[p:])
		if k <= 0 {
			return nil, bad
		}
		p += k
		row.tiers = make([]blockTier, 0, nt)
		for ; nt > 0; nt-- {
			o, k1 := binary.Uvarint(raw[p:])
			if k1 <= 0 {
				return nil, bad
			}
			p += k1
			c, k2 := binary.Uvarint(raw[p:])
			if k2 <= 0 {
				return nil, bad
			}
			p += k2
			row.tiers = append(row.tiers, blockTier{ord: uint32(o), n: c})
		}
		out = append(out, row)
	}
	return out, nil
}

func encodeBlock(rows []blockRow) []byte {
	raw := binary.AppendUvarint(make([]byte, 0, 64*len(rows)+8), uint64(len(rows)))
	for _, r := range rows {
		raw = binary.AppendUvarint(raw, uint64(len(r.id)))
		raw = append(raw, r.id...)
		raw = binary.AppendUvarint(raw, uint64(len(r.tiers)))
		for _, t := range r.tiers {
			raw = binary.AppendUvarint(raw, uint64(t.ord))
			raw = binary.AppendUvarint(raw, t.n)
		}
	}
	return raw
}

// fold writes records ordered by ovOrder (by block, then key) to the blocks: each block once. It returns the bytes of
// the blocks it wrote.
func (s *blockStore) fold(ents []ovEnt) (uint64, error) {
	var written uint64
	for i := 0; i < len(ents); {
		j := i
		for j < len(ents) && ents[j].b == ents[i].b {
			j++
		}
		n, err := s.foldBlock(ents[i].b, ents[i:j])
		if err != nil {
			return written, err
		}
		written += uint64(n)
		i = j
	}
	return written, nil
}

func (s *blockStore) foldBlock(b uint32, ents []ovEnt) (int, error) {
	key := blockKey(b)
	raw := s.b.Get(key)
	rows, err := decodeBlock(raw)
	if err != nil {
		return 0, err
	}
	for _, e := range ents {
		tier, id := splitSeriesKeyBytes([]byte(e.k))
		idx, found := slices.BinarySearchFunc(rows, id, func(r blockRow, id []byte) int { return bytes.Compare(r.id, id) })
		n := uint64(0)
		if e.v != nil {
			n = readU64(e.v)
		}
		var ord uint32
		if n == 0 {
			var ok bool
			if !found {
				continue
			}
			if ord, ok = s.ordOf(tier); !ok {
				continue
			}
		} else if ord, err = s.ensureOrd(tier); err != nil {
			return 0, err
		}
		if !found {
			rows = slices.Insert(rows, idx, blockRow{id: id})
		}
		row := &rows[idx]
		ti, has := slices.BinarySearchFunc(row.tiers, ord, func(t blockTier, o uint32) int { return int(int64(t.ord) - int64(o)) })
		switch {
		case n != 0 && has:
			row.tiers[ti].n = n
		case n != 0:
			row.tiers = slices.Insert(row.tiers, ti, blockTier{ord: ord, n: n})
		case has:
			row.tiers = slices.Delete(row.tiers, ti, ti+1)
			if len(row.tiers) == 0 {
				rows = slices.Delete(rows, idx, idx+1)
			}
		}
	}
	if len(rows) == 0 {
		if raw != nil {
			return 0, s.b.Delete(key)
		}
		return 0, nil
	}
	enc := encodeBlock(rows)
	ovCounters.blocks.Add(1)
	ovCounters.blockBytes.Add(uint64(len(enc)))
	return len(enc), s.b.Put(key, enc)
}

// records is every logical record of the table, in key order.
func (s *blockStore) records() []ovEnt {
	var out []ovEnt
	names := map[uint32]string{}
	c := s.b.Cursor()
	for k, raw := c.First(); k != nil; k, raw = c.Next() {
		rows, err := decodeBlock(raw)
		if err != nil {
			panic("control: a block of the series table of the ledger is corrupt")
		}
		for _, r := range rows {
			for _, t := range r.tiers {
				name, ok := names[t.ord]
				if !ok {
					name = string(s.nameOf(t.ord))
					names[t.ord] = name
				}
				out = append(out, ovEnt{k: string(r.id) + "\x00" + name, v: u64(t.n)})
			}
		}
	}
	slices.SortFunc(out, func(a, b ovEnt) int { return strings.Compare(a.k, b.k) })
	return out
}

// blockSeriesTables moves the series tables of an earlier layout (plain records, the series first or, with tierFirst,
// the quota key first) into blocks, in the transaction of Open. With tierFirst the records get the key of this
// layout and the accumulator follows them; otherwise the records are the same and so is the accumulator.
func (l *ledgerTx) blockSeriesTables(tierFirst bool) error {
	for _, slot := range ovSeriesSlots {
		table := ovTableOf[slot]
		var ents []ovEnt
		c := l.ov.tbl[slot].Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			key := string(k)
			if tierFirst {
				tier, id, _ := bytes.Cut(k, []byte{0})
				moved := seriesKey(string(tier), string(id))
				l.xor(recordHash(table, k, v))
				l.xor(recordHash(table, moved, v))
				key = string(moved)
			}
			ents = append(ents, ovEnt{k: key, v: bytes.Clone(v)})
		}
		name := []byte(ledgerTables[table])
		if err := l.tx.DeleteBucket(name); err != nil {
			return err
		}
		b, err := l.tx.CreateBucket(name)
		if err != nil {
			return err
		}
		l.ov.tbl[slot] = b
		l.ov.refresh()
		ovOrder(slot, ents)
		if _, err = l.ov.store[slot].fold(ents); err != nil {
			return err
		}
	}
	return nil
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
)

type ID [16]byte
type SpanID [8]byte
type UnixNano int64
type MonoNano uint64
type Revision uint64
type Cursor struct {
	Group ID     `json:"group"`
	Index Uint64 `json:"index"`
}

func NewID() ID {
	var id ID
	if _, e := rand.Read(id[:]); e != nil {
		panic(e)
	}
	return id
}
func (id ID) String() string { return hex.EncodeToString(id[:]) }
func ParseID(s string) (ID, error) {
	var id ID
	if len(s) != 32 {
		return id, errors.New("invalid ID")
	}
	b, e := hex.DecodeString(s)
	if e != nil || hex.EncodeToString(b) != s {
		return id, errors.New("invalid ID")
	}
	copy(id[:], b)
	if id == (ID{}) {
		return id, errors.New("zero ID")
	}
	return id, nil
}
func (id ID) MarshalText() ([]byte, error) {
	if id == (ID{}) {
		return nil, errors.New("zero ID")
	}
	return []byte(id.String()), nil
}
func (id *ID) UnmarshalText(b []byte) error {
	v, e := ParseID(string(b))
	if e == nil {
		*id = v
	}
	return e
}
func (id ID) MarshalJSON() ([]byte, error) {
	b, e := id.MarshalText()
	if e != nil {
		return nil, e
	}
	return json.Marshal(string(b))
}
func (id *ID) UnmarshalJSON(b []byte) error {
	if inner, ok := quotedLowerHex(b, 32); ok { // the form MarshalJSON writes, decoded in place
		var v ID
		_, _ = hex.Decode(v[:], inner)
		if v == (ID{}) {
			return errors.New("zero ID")
		}
		*id = v
		return nil
	}
	var s string
	if e := json.Unmarshal(b, &s); e != nil {
		return e
	}
	return id.UnmarshalText([]byte(s))
}

// quotedLowerHex returns the n lower-case hex digits of b when b is exactly a JSON string of that
// shape (no escapes, no spaces). Anything else is not decided here: callers fall back to the
// general JSON decoder, so the answer for every other input is unchanged. The general decoder
// takes a pooled decoder per call and a snapshot decodes one ID per record; this form allocates
// nothing.
func quotedLowerHex(b []byte, n int) ([]byte, bool) {
	if len(b) != n+2 || b[0] != '"' || b[n+1] != '"' {
		return nil, false
	}
	inner := b[1 : n+1]
	for _, c := range inner {
		if c < '0' || c > '9' && (c < 'a' || c > 'f') {
			return nil, false
		}
	}
	return inner, true
}
func (s SpanID) MarshalJSON() ([]byte, error) {
	if s == (SpanID{}) {
		return nil, errors.New("zero span")
	}
	return json.Marshal(hex.EncodeToString(s[:]))
}
func (s *SpanID) UnmarshalJSON(b []byte) error {
	var v string
	if e := json.Unmarshal(b, &v); e != nil {
		return e
	}
	x, e := hex.DecodeString(v)
	if e != nil || len(x) != 8 || hex.EncodeToString(x) != v {
		return errors.New("invalid span")
	}
	copy(s[:], x)
	if *s == (SpanID{}) {
		return errors.New("zero span")
	}
	return nil
}
func (v UnixNano) MarshalJSON() ([]byte, error) { return Int64(v).MarshalJSON() }
func (v *UnixNano) UnmarshalJSON(raw []byte) error {
	var value Int64
	if err := value.UnmarshalJSON(raw); err != nil {
		return err
	}
	*v = UnixNano(value)
	return nil
}
func (v MonoNano) MarshalJSON() ([]byte, error) { return Uint64(v).MarshalJSON() }
func (v *MonoNano) UnmarshalJSON(raw []byte) error {
	var value Uint64
	if err := value.UnmarshalJSON(raw); err != nil {
		return err
	}
	*v = MonoNano(value)
	return nil
}
func (v Revision) MarshalJSON() ([]byte, error) { return Uint64(v).MarshalJSON() }
func (v *Revision) UnmarshalJSON(raw []byte) error {
	var value Uint64
	if err := value.UnmarshalJSON(raw); err != nil {
		return err
	}
	*v = Revision(value)
	return nil
}

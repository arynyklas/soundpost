// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
)

type ID [16]byte
type SpanID [8]byte
type UnixNano int64
type MonoNano uint64
type Revision uint64
type Cursor struct {
	Group ID     `json:"group"`
	Index uint64 `json:"index,string"`
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
	var s string
	if e := json.Unmarshal(b, &s); e != nil {
		return e
	}
	return id.UnmarshalText([]byte(s))
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
func parseDecimal(b []byte, signed bool) (string, error) {
	var s string
	if e := json.Unmarshal(b, &s); e != nil {
		return "", e
	}
	if signed {
		v, e := strconv.ParseInt(s, 10, 64)
		if e != nil || strconv.FormatInt(v, 10) != s {
			return "", errors.New("invalid integer")
		}
	} else {
		v, e := strconv.ParseUint(s, 10, 64)
		if e != nil || strconv.FormatUint(v, 10) != s {
			return "", errors.New("invalid integer")
		}
	}
	return s, nil
}
func (v UnixNano) MarshalJSON() ([]byte, error) { return json.Marshal(strconv.FormatInt(int64(v), 10)) }
func (v *UnixNano) UnmarshalJSON(b []byte) error {
	s, e := parseDecimal(b, true)
	if e != nil {
		return e
	}
	x, e := strconv.ParseInt(s, 10, 64)
	*v = UnixNano(x)
	return e
}
func (v MonoNano) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(v), 10))
}
func (v *MonoNano) UnmarshalJSON(b []byte) error {
	s, e := parseDecimal(b, false)
	if e != nil {
		return e
	}
	x, e := strconv.ParseUint(s, 10, 64)
	*v = MonoNano(x)
	return e
}
func (v Revision) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(v), 10))
}
func (v *Revision) UnmarshalJSON(b []byte) error {
	s, e := parseDecimal(b, false)
	if e != nil {
		return e
	}
	x, e := strconv.ParseUint(s, 10, 64)
	*v = Revision(x)
	return e
}

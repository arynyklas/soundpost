// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"reflect"
	"sort"
)

// The v1 schema is the ordered C04 Go field layout, not Go's gob format or JSON.
// Every integer is a lossless varint (FloatBits are unsigned bit patterns).
// Strings use a page-local dictionary. Nil pointers/slices/maps have explicit tags.
type columnEncoder struct {
	bytes.Buffer
	dict map[string]uint64
}

func (w *columnEncoder) u(n uint64) { var b [10]byte; k := binary.PutUvarint(b[:], n); w.Write(b[:k]) }
func (w *columnEncoder) text(s string) {
	if n, ok := w.dict[s]; ok {
		w.u(n << 1)
		return
	}
	n := uint64(len(w.dict))
	w.dict[s] = n
	w.u(n<<1 | 1)
	w.u(uint64(len(s)))
	w.WriteString(s)
}

var scalarType = reflect.TypeOf(model.Scalar{})

func (w *columnEncoder) value(v reflect.Value) error {
	if v.Type() == scalarType {
		b, err := json.Marshal(v.Interface())
		if err != nil {
			return err
		}
		w.text(string(b))
		return nil
	}
	switch v.Kind() {
	case reflect.Bool:
		if v.Bool() {
			w.u(1)
		} else {
			w.u(0)
		}
	case reflect.String:
		w.text(v.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := v.Int()
		w.u(uint64(n<<1) ^ uint64(n>>63))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		w.u(v.Uint())
	case reflect.Pointer:
		if v.IsNil() {
			w.u(0)
		} else {
			w.u(1)
			return w.value(v.Elem())
		}
	case reflect.Array:
		for i := range v.Len() {
			if v.Type().Elem().Kind() == reflect.Uint8 {
				w.WriteByte(byte(v.Index(i).Uint()))
			} else if err := w.value(v.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if v.IsNil() {
			w.u(0)
			return nil
		}
		w.u(uint64(v.Len() + 1))
		for i := range v.Len() {
			if err := w.value(v.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		if v.IsNil() {
			w.u(0)
			return nil
		}
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		w.u(uint64(len(keys) + 1))
		for _, k := range keys {
			if err := w.value(k); err != nil {
				return err
			}
			if err := w.value(v.MapIndex(k)); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if err := w.value(v.Field(i)); err != nil {
				return err
			}
		}
	default:
		return model.Fail(model.Corrupt)
	}
	return nil
}

type columnArena struct {
	values reflect.Value
	used   int
}
type columnDecoder struct {
	*bytes.Reader
	raw       []byte
	dict      []string
	remaining int
	batchSize int
	arenas    map[reflect.Type]*columnArena
}

// Native pointer/slice graphs borrow typed column arenas. Decoding a metric
// page does not allocate one MetricPoint (or scalar pointer) per row.
func (r *columnDecoder) reserve(t reflect.Type, n int) reflect.Value {
	if r.arenas == nil {
		r.arenas = make(map[reflect.Type]*columnArena)
	}
	a := r.arenas[t]
	if a == nil || a.values.Len()-a.used < n {
		capacity := r.batchSize
		if capacity < n {
			capacity = n
		}
		if capacity < 1 {
			capacity = 1
		}
		a = &columnArena{values: reflect.MakeSlice(reflect.SliceOf(t), capacity, capacity)}
		r.arenas[t] = a
	}
	start := a.used
	a.used += n
	return a.values.Slice3(start, a.used, a.used)
}
func (r *columnDecoder) u() (uint64, error) {
	n, err := binary.ReadUvarint(r.Reader)
	if err != nil {
		return 0, model.Fail(model.Corrupt)
	}
	return n, nil
}
func (r *columnDecoder) text() (string, error) {
	n, err := r.u()
	if err != nil {
		return "", err
	}
	id := n >> 1
	if n&1 == 0 {
		if id >= uint64(len(r.dict)) {
			return "", model.Fail(model.Corrupt)
		}
		return r.dict[id], nil
	}
	if id != uint64(len(r.dict)) {
		return "", model.Fail(model.Corrupt)
	}
	size, err := r.u()
	if err != nil || size > uint64(r.Len()) {
		return "", model.Fail(model.Corrupt)
	}
	start := len(r.raw) - r.Len()
	s := string(r.raw[start : start+int(size)])
	if _, err = r.Seek(int64(size), io.SeekCurrent); err != nil {
		return "", model.Fail(model.Corrupt)
	}
	r.dict = append(r.dict, s)
	return s, nil
}
func (r *columnDecoder) value(v reflect.Value) error {
	r.remaining--
	if r.remaining < 0 {
		return model.Fail(model.Corrupt)
	}
	if v.Type() == scalarType {
		s, err := r.text()
		if err != nil {
			return err
		}
		return json.Unmarshal([]byte(s), v.Addr().Interface())
	}
	switch v.Kind() {
	case reflect.String:
		s, err := r.text()
		if err != nil {
			return err
		}
		v.SetString(s)
	case reflect.Bool:
		n, err := r.u()
		if err != nil || n > 1 {
			return model.Fail(model.Corrupt)
		}
		v.SetBool(n == 1)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := r.u()
		x := int64(n>>1) ^ -int64(n&1)
		if err != nil || v.OverflowInt(x) {
			return model.Fail(model.Corrupt)
		}
		v.SetInt(x)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := r.u()
		if err != nil || v.OverflowUint(n) {
			return model.Fail(model.Corrupt)
		}
		v.SetUint(n)
	case reflect.Pointer:
		n, err := r.u()
		if err != nil || n > 1 {
			return model.Fail(model.Corrupt)
		}
		if n == 1 {
			cell := r.reserve(v.Type().Elem(), 1).Index(0)
			v.Set(cell.Addr())
			return r.value(cell)
		}
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			if _, err := io.ReadFull(r, v.Slice(0, v.Len()).Bytes()); err != nil {
				return model.Fail(model.Corrupt)
			}
			return nil
		}
		for i := range v.Len() {
			if err := r.value(v.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		n, err := r.u()
		if err != nil || n > uint64(r.Len()+1) || n > 65537 {
			return model.Fail(model.Corrupt)
		}
		if n > 0 {
			size := int(n - 1)
			if r.batchSize == 0 {
				r.batchSize = size
				if r.batchSize > pageRows {
					r.batchSize = pageRows
				}
			}
			v.Set(r.reserve(v.Type().Elem(), size).Convert(v.Type()))
			for i := range v.Len() {
				if err := r.value(v.Index(i)); err != nil {
					return err
				}
			}
		}
	case reflect.Map:
		n, err := r.u()
		if err != nil || n > uint64(r.Len()+1) || n > 65537 {
			return model.Fail(model.Corrupt)
		}
		if n > 0 {
			v.Set(reflect.MakeMapWithSize(v.Type(), int(n-1)))
			for i := uint64(1); i < n; i++ {
				k := r.reserve(v.Type().Key(), 1).Index(0)
				x := r.reserve(v.Type().Elem(), 1).Index(0)
				if err = r.value(k); err != nil {
					return err
				}
				if err = r.value(x); err != nil {
					return err
				}
				if v.MapIndex(k).IsValid() {
					return model.Fail(model.Corrupt)
				}
				v.SetMapIndex(k, x)
			}
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if err := r.value(v.Field(i)); err != nil {
				return err
			}
		}
	default:
		return model.Fail(model.Corrupt)
	}
	return nil
}
func encodeColumn(v any) ([]byte, error) {
	w := columnEncoder{dict: map[string]uint64{}}
	if err := w.value(reflect.ValueOf(v)); err != nil {
		return nil, err
	}
	if w.Len() > pageByteLimit {
		return nil, model.Fail(model.TooLarge)
	}
	return w.Bytes(), nil
}
func decodeColumn(b []byte, v any) error {
	r := columnDecoder{Reader: bytes.NewReader(b), raw: b, remaining: pageByteLimit}
	if err := r.value(reflect.ValueOf(v).Elem()); err != nil {
		return err
	}
	if r.Len() != 0 {
		return model.Fail(model.Corrupt)
	}
	return nil
}

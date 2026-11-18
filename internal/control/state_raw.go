// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/arynyklas/soundpost/internal/model"
)

// This file applies a state patch (and an audit delta, and a stale rejection) to the bytes of the
// committed state without decoding the state into a State and encoding it again.
//
// What the decode and the encode of the whole state cost, per command, on every voter: at the
// production-sized state of state_patch_production_internal_test.go (23 MB encoded) the pair is
// about 0.8 s and half a gigabyte of garbage, for a change of a few hundred bytes
// (BenchmarkStatePatchCommandAtProductionSize). A patch names exactly the members it changes, so the
// bytes of every other member can be carried over as they are: the new encoding is the old one with
// the touched members re-encoded and spliced in.
//
// The result has to be the bytes the decode/encode path leaves, because every voter must hold the
// same bytes (patchBase digests them, and a voter restored from a snapshot holds the encoding of a
// State). So the splice does what encoding a State does and nothing else: a touched value is decoded
// strictly into the Go type of its place and encoded again (canonicalLeaf), members keep the order
// the encoder writes (struct fields in field order, map keys sorted), and a new member goes where the
// encoder would put it. Whatever the splice cannot prove it does exactly (a value that is not what
// the encoder writes back, an omitted zero, a name that needs escaping, a state that is not the
// compact encoding of a State, a patch that does not fit) is refused with ok=false, and the caller
// applies the patch the old way, which also gives every error. TestRawPatchEqualsDecodeEncode pins
// the equivalence of the two on random patches.

// rawMember is one member of a JSON object in a buffer: the quoted name is [ks, ke), the value
// [vs, ve).
type rawMember struct{ ks, ke, vs, ve int }

// jsonSpecial marks the bytes the structural scan stops at.
var jsonSpecial = func() (t [256]bool) {
	for _, c := range []byte("\"{}[] \t\r\n") {
		t[c] = true
	}
	return t
}()

// skipString returns the offset after the string that starts at raw[i] (a quote).
func skipString(raw []byte, i int) (int, bool) {
	for j := i + 1; j < len(raw); {
		k := bytes.IndexByte(raw[j:], '"')
		if k < 0 {
			return 0, false
		}
		k += j
		slashes := 0
		for p := k - 1; p > i && raw[p] == '\\'; p-- {
			slashes++
		}
		if slashes%2 == 0 {
			return k + 1, true
		}
		j = k + 1
	}
	return 0, false
}

// skipValue returns the offset after the value that starts at raw[i]. It reads the compact encoding
// the encoder writes: white space outside a string ends the scan with ok=false.
func skipValue(raw []byte, i int) (int, bool) {
	if i >= len(raw) {
		return 0, false
	}
	switch c := raw[i]; c {
	case '"':
		return skipString(raw, i)
	case '{', '[':
		depth := 0
		for j := i; j < len(raw); j++ {
			if !jsonSpecial[raw[j]] {
				continue
			}
			switch raw[j] {
			case '"':
				e, ok := skipString(raw, j)
				if !ok {
					return 0, false
				}
				j = e - 1
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return j + 1, true
				}
			default:
				return 0, false
			}
		}
		return 0, false
	case '}', ']', ',', ':', ' ', '\t', '\r', '\n':
		return 0, false
	}
	j := i
	for j < len(raw) && raw[j] != ',' && raw[j] != '}' && raw[j] != ']' && !jsonSpecial[raw[j]] {
		j++
	}
	return j, true
}

// scanObject appends the members of the object raw[start:end] to dst.
func scanObject(raw []byte, start, end int, dst []rawMember) ([]rawMember, bool) {
	if start < 0 || end > len(raw) || end-start < 2 || raw[start] != '{' || raw[end-1] != '}' {
		return nil, false
	}
	i := start + 1
	if i == end-1 {
		return dst, true
	}
	for {
		if i >= end || raw[i] != '"' {
			return nil, false
		}
		ke, ok := skipString(raw, i)
		if !ok || ke >= end || raw[ke] != ':' {
			return nil, false
		}
		ve, ok := skipValue(raw, ke+1)
		if !ok || ve >= end {
			return nil, false
		}
		dst = append(dst, rawMember{ks: i, ke: ke, vs: ke + 1, ve: ve})
		switch {
		case raw[ve] == ',':
			i = ve + 1
		case raw[ve] == '}' && ve == end-1:
			return dst, true
		default:
			return nil, false
		}
	}
}

// scanArray returns the rows of the array raw[start:end] as spans (the name fields are unused).
func scanArray(raw []byte, start, end int) ([]rawMember, bool) {
	if start < 0 || end > len(raw) || end-start < 2 || raw[start] != '[' || raw[end-1] != ']' {
		return nil, false
	}
	var rows []rawMember
	i := start + 1
	if i == end-1 {
		return rows, true
	}
	for {
		ve, ok := skipValue(raw, i)
		if !ok || ve >= end {
			return nil, false
		}
		rows = append(rows, rawMember{vs: i, ve: ve})
		switch {
		case raw[ve] == ',':
			i = ve + 1
		case raw[ve] == ']' && ve == end-1:
			return rows, true
		default:
			return nil, false
		}
	}
}

// unquoteMemberName is the name of the member whose quoted name is raw[m.ks:m.ke].
func unquoteMemberName(raw []byte, m rawMember) (string, bool) {
	q := raw[m.ks:m.ke]
	if bytes.IndexByte(q, '\\') < 0 {
		return string(q[1 : len(q)-1]), true
	}
	var name string
	if json.Unmarshal(q, &name) != nil {
		return "", false
	}
	return name, true
}

// stateRoot is the root of the committed state read without decoding it: its members, and the
// members a command is checked against.
type stateRoot struct {
	members      []rawMember
	installation model.ID
	revision     model.Revision
	settled      bool // the Settlement member is present and not null
	ok           bool // false: the bytes are not the compact encoding of a State; decode them
}

func (r *stateRoot) member(raw []byte, name string) (rawMember, bool) {
	quoted := `"` + name + `"`
	for _, m := range r.members {
		if string(raw[m.ks:m.ke]) == quoted {
			return m, true
		}
	}
	return rawMember{}, false
}

// scanStateRoot reads the root members of the state encoding raw, its installation and revision.
func scanStateRoot(raw []byte) stateRoot {
	members, ok := scanObject(raw, 0, len(raw), make([]rawMember, 0, 64))
	if !ok {
		return stateRoot{}
	}
	root := stateRoot{members: members}
	var haveInstallation, haveRevision bool
	for _, m := range members {
		switch string(raw[m.ks:m.ke]) {
		case `"Installation"`:
			haveInstallation = json.Unmarshal(raw[m.vs:m.ve], &root.installation) == nil
		case `"Revision"`:
			haveRevision = json.Unmarshal(raw[m.vs:m.ve], &root.revision) == nil
		case `"settlement"`:
			root.settled = string(raw[m.vs:m.ve]) != "null"
		}
	}
	root.ok = haveInstallation && haveRevision
	return root
}

// patchBaseRoot is patchBase for a state whose root members are scanned: the digest of every member
// in name order. It reads the bytes where they are and allocates nothing but the order.
func patchBaseRoot(raw []byte, root stateRoot) (string, bool) {
	type named struct {
		name string
		m    rawMember
	}
	members := make([]named, 0, len(root.members))
	for _, m := range root.members {
		name, ok := unquoteMemberName(raw, m)
		if !ok {
			return "", false
		}
		members = append(members, named{name, m})
	}
	sort.Slice(members, func(i, j int) bool { return members[i].name < members[j].name })
	h := sha256.New()
	for _, n := range members {
		h.Write([]byte(n.name))
		h.Write([]byte{0})
		h.Write(raw[n.m.vs:n.m.ve])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

// A duplicate root member makes the digest of the scan differ from the one of a decode (which keeps
// the last): the scan is only used on the encoding of a State, which has none.

// objectType describes how the encoder writes a struct or a map[string]T: the fields in order, or the
// element type.
type objectType struct {
	isStruct bool
	fields   []*fieldInfo
	byName   map[string]*fieldInfo
	elem     reflect.Type
}

type fieldInfo struct {
	name   string
	quoted []byte // the quoted name
	order  int
	typ    reflect.Type
	omit   bool
}

var objectTypes sync.Map // reflect.Type -> *objectType (nil when the type is not described)

var (
	marshalerType     = reflect.TypeFor[json.Marshaler]()
	unmarshalerType   = reflect.TypeFor[json.Unmarshaler]()
	textMarshalerType = reflect.TypeFor[encoding.TextMarshaler]()
	textUnmarshalType = reflect.TypeFor[encoding.TextUnmarshaler]()
)

func customCodec(t reflect.Type) bool {
	p := reflect.PointerTo(t)
	return t.Implements(marshalerType) || p.Implements(marshalerType) || t.Implements(unmarshalerType) || p.Implements(unmarshalerType) ||
		t.Implements(textMarshalerType) || p.Implements(textMarshalerType) || t.Implements(textUnmarshalType) || p.Implements(textUnmarshalType)
}

func describeObject(t reflect.Type) *objectType {
	if v, ok := objectTypes.Load(t); ok {
		return v.(*objectType)
	}
	ot := computeObjectType(t)
	objectTypes.Store(t, ot)
	return ot
}

func computeObjectType(t reflect.Type) *objectType {
	if customCodec(t) {
		return nil
	}
	switch t.Kind() {
	case reflect.Map:
		if t.Key().Kind() != reflect.String || customCodec(t.Key()) {
			return nil
		}
		return &objectType{elem: t.Elem()}
	case reflect.Struct:
		ot := &objectType{isStruct: true, byName: map[string]*fieldInfo{}}
		for i := range t.NumField() {
			f := t.Field(i)
			if f.Anonymous {
				return nil
			}
			if !f.IsExported() {
				continue
			}
			tag, has := f.Tag.Lookup("json")
			if tag == "-" {
				continue
			}
			name, opts, _ := strings.Cut(tag, ",")
			if !has || name == "" {
				name = f.Name
			}
			omit := false
			switch opts {
			case "":
			case "omitempty":
				omit = true
			default:
				return nil
			}
			if _, dup := ot.byName[name]; dup || !plainName(name) {
				return nil
			}
			fi := &fieldInfo{name: name, quoted: []byte(`"` + name + `"`), order: len(ot.fields), typ: f.Type, omit: omit}
			ot.fields = append(ot.fields, fi)
			ot.byName[name] = fi
		}
		return ot
	}
	return nil
}

// plainName is whether the encoder writes name as a member name unchanged between its quotes.
func plainName(name string) bool {
	for i := range len(name) {
		switch c := name[i]; {
		case c < 0x20 || c >= 0x7f, c == '"', c == '\\', c == '<', c == '>', c == '&':
			return false
		}
	}
	return name != ""
}

// emptyForOmit is encoding/json's omitempty test.
func emptyForOmit(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Pointer:
		return v.IsNil()
	}
	return false
}

// leafRule says what the place of a value allows: omit is a struct field written only when it is not
// empty; deletable is a place whose member may be absent (a map element, an omitted field).
type leafRule struct{ omit, deletable bool }

// canonicalLeaf is value as the encoder writes it back once it was decoded strictly into t: what the
// decode/encode of the whole state leaves at this place. ok is false when the value does not decode,
// or when the place would be omitted.
func canonicalLeaf(t reflect.Type, value []byte, rule leafRule) ([]byte, bool) {
	v := reflect.New(t)
	if model.StrictJSON(value, v.Interface()) != nil {
		return nil, false
	}
	if rule.omit && emptyForOmit(v.Elem()) {
		return nil, false
	}
	out, err := json.Marshal(v.Interface())
	if err != nil {
		return nil, false
	}
	return out, true
}

// patchEffects is what a raw patch says about the state it leaves, without decoding it.
type patchEffects struct {
	revisionSet bool
	revision    model.Revision
	erasures    int  // erasing audits added minus dropped
	settled     bool // the Settlement member is present and not null afterwards
}

// pieceWriter collects the output of a splice as a list of byte slices, most of them the old bytes,
// so that the new encoding is assembled with one allocation and one copy.
type pieceWriter struct {
	parts [][]byte
	n     int
}

func (w *pieceWriter) add(b []byte) {
	if len(b) > 0 {
		w.parts = append(w.parts, b)
		w.n += len(b)
	}
}

func (w *pieceWriter) bytes() []byte {
	out := make([]byte, 0, w.n)
	for _, p := range w.parts {
		out = append(out, p...)
	}
	return out
}

var (
	litComma = []byte(",")
	litColon = []byte(":")
	litOpen  = []byte("{")
	litClose = []byte("}")
	litLB    = []byte("[")
	litRB    = []byte("]")
)

type rawPatcher struct {
	raw     []byte
	w       pieceWriter
	effects patchEffects
}

// patchRaw applies ops to the state encoding raw (root scanned) and returns the encoding of the
// state they leave. ok is false when the splice does not apply; raw is then untouched and the patch
// has to be applied by decoding the state.
func patchRaw(raw []byte, root stateRoot, ops []patchOp) ([]byte, patchEffects, bool) {
	if !root.ok {
		return nil, patchEffects{}, false
	}
	trie, err := newPatchTrie(ops)
	if err != nil || trie.op != nil {
		return nil, patchEffects{}, false
	}
	p := &rawPatcher{raw: raw}
	p.effects.settled = root.settled
	if !p.editObject(trie, 0, len(raw), reflect.TypeFor[State](), root.members, true) {
		return nil, patchEffects{}, false
	}
	return p.w.bytes(), p.effects, true
}

// before reports whether the touched member sorts before the existing member whose quoted name is
// quoted, in the order the encoder writes (-1), is the same (0) or after (1); bad is true when the
// order cannot be decided from the bytes.
func (p *rawPatcher) compare(ot *objectType, name string, tOrder int, quoted []byte) (cmp int, bad bool) {
	if ot.isStruct {
		f := ot.byName[string(quoted[1:len(quoted)-1])]
		if f == nil || bytes.IndexByte(quoted, '\\') >= 0 {
			return 0, true
		}
		switch {
		case tOrder < f.order:
			return -1, false
		case tOrder > f.order:
			return 1, false
		}
		return 0, false
	}
	if bytes.IndexByte(quoted, '\\') >= 0 {
		return 0, true
	}
	return strings.Compare(name, string(quoted[1:len(quoted)-1])), false
}

type touch struct {
	name  string
	node  *patchNode
	order int
	typ   reflect.Type
	rule  leafRule
}

// editObject writes the object at raw[vs:ve] as it is once n's children are applied to it.
func (p *rawPatcher) editObject(n *patchNode, vs, ve int, t reflect.Type, members []rawMember, root bool) bool {
	ot := describeObject(t)
	if ot == nil || vs >= len(p.raw) || p.raw[vs] != '{' {
		return false
	}
	if members == nil {
		var ok bool
		if members, ok = scanObject(p.raw, vs, ve, nil); !ok {
			return false
		}
	}
	touched := make([]touch, 0, len(n.children))
	for name, child := range n.children {
		if !plainName(name) {
			return false
		}
		tt := touch{name: name, node: child}
		if ot.isStruct {
			f := ot.byName[name]
			if f == nil || root && name == "Installation" {
				return false
			}
			tt.order, tt.typ, tt.rule = f.order, f.typ, leafRule{omit: f.omit, deletable: f.omit}
		} else {
			tt.typ, tt.rule = ot.elem, leafRule{deletable: true}
		}
		touched = append(touched, tt)
	}
	if ot.isStruct {
		sort.Slice(touched, func(i, j int) bool { return touched[i].order < touched[j].order })
	} else {
		sort.Slice(touched, func(i, j int) bool { return touched[i].name < touched[j].name })
	}
	w := &p.w
	w.add(litOpen)
	first := true
	runStart, runEnd := -1, -1
	flush := func() {
		if runStart >= 0 {
			if !first {
				w.add(litComma)
			}
			w.add(p.raw[runStart:runEnd])
			first = false
			runStart = -1
		}
	}
	key := func(quoted []byte) {
		flush()
		if !first {
			w.add(litComma)
		}
		first = false
		w.add(quoted)
		w.add(litColon)
	}
	insert := func(tt *touch) bool {
		op := tt.node.op
		if op == nil {
			return false // an edit inside a member that does not exist
		}
		switch op.Op {
		case opDelete:
			return tt.rule.deletable // nothing to delete
		case opSet:
			canon, ok := canonicalLeaf(tt.typ, op.Value, tt.rule)
			if !ok {
				return false
			}
			key([]byte(`"` + tt.name + `"`))
			w.add(canon)
			if root {
				p.noteRoot(tt.name, canon)
			}
			return true
		}
		return false
	}
	pos := 0
	for _, m := range members {
		quoted := p.raw[m.ks:m.ke]
		for pos < len(touched) {
			cmp, bad := p.compare(ot, touched[pos].name, touched[pos].order, quoted)
			if bad {
				return false
			}
			if cmp >= 0 {
				break
			}
			if !insert(&touched[pos]) {
				return false
			}
			pos++
		}
		if pos < len(touched) {
			cmp, _ := p.compare(ot, touched[pos].name, touched[pos].order, quoted)
			if cmp == 0 {
				tt := &touched[pos]
				pos++
				if tt.node.op != nil && tt.node.op.Op == opDelete {
					if !tt.rule.deletable {
						return false
					}
					flush()
					if root {
						p.noteRootDelete(tt.name)
					}
					continue
				}
				key(quoted)
				if !p.editMember(tt, m.vs, m.ve, root) {
					return false
				}
				continue
			}
		}
		if runStart >= 0 && runEnd+1 == m.ks {
			runEnd = m.ve
		} else {
			flush()
			runStart, runEnd = m.ks, m.ve
		}
	}
	flush()
	for ; pos < len(touched); pos++ {
		if !insert(&touched[pos]) {
			return false
		}
	}
	w.add(litClose)
	return true
}

// editMember writes the value of an existing member as it is once the node is applied to it.
func (p *rawPatcher) editMember(tt *touch, vs, ve int, root bool) bool {
	n := tt.node
	if n.op == nil {
		before := p.w.n
		if !p.editObject(n, vs, ve, tt.typ, nil, false) {
			return false
		}
		// An omitempty map the edit emptied is not written by the encoder: refuse (the caller decodes).
		return !(tt.rule.omit && tt.typ.Kind() == reflect.Map && p.w.n-before == 2)
	}
	switch n.op.Op {
	case opSet:
		canon, ok := canonicalLeaf(tt.typ, n.op.Value, tt.rule)
		if !ok {
			return false
		}
		if root && tt.name == "Audits" {
			old, ok := countErasures(p.raw[vs:ve])
			neu, ok2 := countErasures(canon)
			if !ok || !ok2 {
				return false
			}
			p.effects.erasures += neu - old
		}
		p.w.add(canon)
		if root {
			p.noteRoot(tt.name, canon)
		}
		return true
	case opArray:
		return p.editArray(tt, n.op, vs, ve, root)
	}
	return false
}

// countErasures is the number of erasing audits in the array encoding raw.
func countErasures(raw []byte) (int, bool) {
	var audits []model.ControlAudit
	if json.Unmarshal(raw, &audits) != nil {
		return 0, false
	}
	return erasureCount(audits), true
}

// editArray writes an append-only array with its first Cut rows dropped and the op's rows appended.
func (p *rawPatcher) editArray(tt *touch, op *patchOp, vs, ve int, root bool) bool {
	if tt.typ.Kind() != reflect.Slice || !root {
		return false
	}
	rows, ok := scanArray(p.raw, vs, ve)
	if !ok || op.Cut > len(rows) {
		return false
	}
	more, err := decodeRows(op.Value)
	if err != nil {
		return false
	}
	appended := make([][]byte, 0, len(more))
	for _, row := range more {
		canon, ok := canonicalLeaf(tt.typ.Elem(), row, leafRule{})
		if !ok {
			return false
		}
		appended = append(appended, canon)
	}
	if len(rows)-op.Cut+len(appended) == 0 && tt.rule.omit {
		return false // an empty omitted array is not written
	}
	if tt.name == "Audits" {
		var dropped, added int
		for _, r := range rows[:op.Cut] {
			n, ok := countErasures(append(append([]byte{'['}, p.raw[r.vs:r.ve]...), ']'))
			if !ok {
				return false
			}
			dropped += n
		}
		for _, r := range appended {
			n, ok := countErasures(append(append([]byte{'['}, r...), ']'))
			if !ok {
				return false
			}
			added += n
		}
		p.effects.erasures += added - dropped
	}
	w := &p.w
	w.add(litLB)
	first := true
	if op.Cut < len(rows) {
		w.add(p.raw[rows[op.Cut].vs:rows[len(rows)-1].ve])
		first = false
	}
	for _, r := range appended {
		if !first {
			w.add(litComma)
		}
		first = false
		w.add(r)
	}
	w.add(litRB)
	return true
}

// noteRoot records what a root member written by the patch says about the state.
func (p *rawPatcher) noteRoot(name string, canon []byte) {
	switch name {
	case "Revision":
		var rev model.Revision
		if json.Unmarshal(canon, &rev) == nil {
			p.effects.revisionSet, p.effects.revision = true, rev
		}
	case "settlement":
		p.effects.settled = string(canon) != "null"
	}
}

func (p *rawPatcher) noteRootDelete(name string) {
	if name == "settlement" {
		p.effects.settled = false
	}
}

// revisionOp is the op that sets the revision of the state.
func revisionOp(r model.Revision) patchOp {
	value, _ := json.Marshal(r)
	return patchOp{Op: opSet, Path: []string{"Revision"}, Value: value}
}

// lastAudits is the number of rows of the audit log in the state encoding raw and its last n rows
// (fewer when the log is shorter), decoded without decoding the rest of the state. ok is false when
// the bytes do not say (they are not the compact encoding of a State, or the log is not an array).
func lastAudits(raw []byte, root stateRoot, n int) (total int, tail []model.ControlAudit, ok bool) {
	if !root.ok {
		return 0, nil, false
	}
	member, found := root.member(raw, "Audits")
	if !found {
		return 0, nil, false
	}
	rows, ok := scanArray(raw, member.vs, member.ve)
	if !ok {
		return 0, nil, false
	}
	tail = make([]model.ControlAudit, 0, min(n, len(rows)))
	for _, row := range rows[max(len(rows)-n, 0):] {
		var a model.ControlAudit
		if json.Unmarshal(raw[row.vs:row.ve], &a) != nil {
			return 0, nil, false
		}
		tail = append(tail, a)
	}
	return len(rows), tail, true
}

// deltaRaw is applyAuditDelta on the encoding: the revision steps, the revision clock is stamped
// (noteRevisionTime) and the rows are appended. ok is false when the splice does not apply.
func deltaRaw(raw []byte, root stateRoot, d auditDelta) ([]byte, bool) {
	if !root.ok {
		return nil, false
	}
	rows, err := json.Marshal(d.Audits)
	if err != nil {
		return nil, false
	}
	ops := []patchOp{revisionOp(d.Expected + 1)}
	if m, ok := root.member(raw, "Audits"); ok && raw[m.vs] == '[' {
		ops = append(ops, patchOp{Op: opArray, Path: []string{"Audits"}, Value: rows})
	} else {
		ops = append(ops, patchOp{Op: opSet, Path: []string{"Audits"}, Value: rows}) // no log yet: it starts with the rows
	}
	clock := State{Revision: d.Expected + 1}
	if m, ok := root.member(raw, "revision_clock"); ok {
		if json.Unmarshal(raw[m.vs:m.ve], &clock.RevisionClock) != nil {
			return nil, false
		}
	}
	before := slices.Clone(clock.RevisionClock)
	noteRevisionTime(&clock, d.At)
	if !slices.Equal(before, clock.RevisionClock) {
		stamps, err := json.Marshal(clock.RevisionClock)
		if err != nil {
			return nil, false
		}
		ops = append(ops, patchOp{Op: opSet, Path: []string{"revision_clock"}, Value: stamps})
	}
	out, eff, ok := patchRaw(raw, root, ops)
	if !ok || !eff.revisionSet || eff.revision != d.Expected+1 {
		return nil, false
	}
	return out, true
}

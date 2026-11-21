// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// roFixture is a control state in which every field a ReadOnlyControl method reads is populated,
// lists included. Every call builds its own, so two fixtures never share memory.
func roFixture() model.ControlState {
	id := func(b byte) model.ID { return model.ID{b, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} }
	org := id(1)
	return model.ControlState{
		Installation:      id(9),
		Revision:          41,
		AuthorityRevision: 40,
		Sessions:          map[string]model.ControlSession{"session-hash": {User: id(2), CSRF: "csrf", Expires: 1000, Reauthenticated: 900}},
		Users:             map[string]model.ControlUser{id(2).String(): {ID: id(2), Email: "a@example.test", Recovery: []string{"r1", "r2"}, Disabled: true}},
		ServerTokens: map[string]model.ControlServerToken{"token-digest": {
			ID: id(3), Principal: id(2), Org: org, Projects: []model.ID{id(4), id(5)}, Permissions: []string{"read", "write"}, Expires: 2000, Revoked: true,
		}},
		Orgs: map[string]model.ControlOrg{org.String(): {
			ID: org, Epoch: 7, Projects: map[string]string{id(4).String(): "p4"},
			Admins:  map[string]bool{id(2).String(): true},
			Members: map[string]bool{id(2).String(): true},
			Grants:  map[string][]string{id(2).String() + ":" + id(4).String(): {"read", "policy.write"}},
			Teams:   map[string]model.ControlTeam{"team": {Members: []model.ID{id(2)}, Projects: []model.ID{id(4)}, Permissions: []string{"issues.write"}, Enabled: true}},
		}},
		RetiredOrgs:     map[string]model.ID{id(6).String(): id(7)},
		RetiredProjects: map[string]model.ID{org.String() + ":" + id(5).String(): id(7)},
		Deletions: map[string]model.DeletionOperation{
			"op-a": {Phase: "fencing", Predicate: model.DeletePredicate{Operation: id(10), Org: org, Mode: "historical_range", Projects: []model.ID{id(4), id(5)}, Signals: []model.Kind{model.Metric, model.Log}, Entities: []model.ID{id(8)}}},
			"op-b": {Phase: "complete", Predicate: model.DeletePredicate{Operation: id(11), Org: org, Mode: "historical_range", Projects: []model.ID{id(4)}, Signals: []model.Kind{model.SpanKind}}},
			"op-c": {Phase: model.DeletePhaseHeld, Predicate: model.DeletePredicate{Operation: id(12), Org: org, Mode: "historical_range", Projects: []model.ID{id(4)}}},
		},
		IssueBooks:      map[string]json.RawMessage{"book": json.RawMessage(`{"issue":1}`)},
		JobBooks:        map[string]json.RawMessage{"book": json.RawMessage(`{"job":1}`)},
		ConditionBooks:  map[string]json.RawMessage{"book": json.RawMessage(`{"condition":1}`)},
		IncidentBooks:   map[string]json.RawMessage{"book": json.RawMessage(`{"incident":1}`)},
		DeliveryBooks:   map[string]json.RawMessage{"book": json.RawMessage(`{"delivery":1}`)},
		CutoverBooks:    map[string]json.RawMessage{"book": json.RawMessage(`{"cutover":1}`)},
		RuleBooks:       map[string]json.RawMessage{"book": json.RawMessage(`{"rule":1}`)},
		RuleOutputs:     map[string]json.RawMessage{"book": json.RawMessage(`{"output":1}`)},
		RuleDefinitions: map[string]json.RawMessage{"book": json.RawMessage(`{"definition":1}`)},
		JobDefinitions:  map[string]json.RawMessage{"book": json.RawMessage(`{"job_definition":1}`)},
		JobPositions:    map[string]json.RawMessage{"book": json.RawMessage(`{"position":1}`)},
		SavedViewBooks:  map[string]json.RawMessage{"book": json.RawMessage(`{"view":1}`)},
		GroupingIssues: map[string]model.GroupingIssue{
			"mine":   roIssue(org, id(4)),
			"theirs": roIssue(org, id(5)),
		},
	}
}

// roIssue is a grouping issue of the project in which every pointer and every list is populated.
func roIssue(org, project model.ID) model.GroupingIssue {
	id := func(b byte) model.ID { return model.ID{b, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9} }
	res := model.UnixNano(77)
	evidence := func(b byte) model.GroupingEvidence {
		build, release, epoch := id(b), id(b+1), id(b+2)
		return model.GroupingEvidence{OccurrenceID: id(b + 3), BuildID: &build, ReleaseID: &release, ProducerEpoch: &epoch, Ancestry: "a", Freshness: "fresh", Ordinal: 3,
			Denominator: &model.GroupingDenominator{Name: "d", Count: 5, Cursors: []model.Cursor{{Group: id(b + 4), Index: 7}, {Group: id(b + 5), Index: 8}}}}
	}
	compaction := func() *model.GroupingCompaction {
		return &model.GroupingCompaction{Count: 4, Releases: []model.GroupingCompactedRelease{{Release: id(40)}}, Recent: []model.ID{id(41), id(42)}}
	}
	return model.GroupingIssue{
		ID: id(30), Org: org, Project: project, Workflow: "open", Revision: 5,
		Occurrences: []model.GroupingEvidence{evidence(10), evidence(20)}, LateHistory: []model.GroupingEvidence{evidence(50)},
		Compacted: compaction(), LateCompacted: compaction(), ResolutionTime: &res,
		ResolutionFrontier: []model.ID{id(60)}, ObservedReleases: []model.ID{id(61), id(62)}, FixedDescendants: []model.ID{id(63)}, MigrationLinks: []model.ID{id(64)},
	}
}

// roCalls says how to call each method of ReadOnlyControl against roFixture. A method that is not
// listed fails TestReadOnlyControlResultsAreCopies: an accessor needs a mutation case.
func roCalls() map[string][]any {
	id := func(b byte) model.ID { return model.ID{b, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} }
	org := id(1).String()
	return map[string][]any{
		"Installation":             {},
		"Revision":                 {},
		"AuthorityRevision":        {},
		"Session":                  {"session-hash"},
		"UserState":                {id(2).String()},
		"ServerToken":              {"token-digest"},
		"ServerTokenHasPermission": {"token-digest", "read"},
		"ServerTokenHasProject":    {"token-digest", id(4)},
		"OrgEpoch":                 {org},
		"OrgHasProject":            {org, id(4).String()},
		"OrgRetired":               {id(6).String()},
		"ProjectRetired":           {org, id(5).String()},
		"ActiveDeletions":          {id(1), []model.ID{id(4)}},
		"DeletionPredicates":       {"fencing", "complete"},
		"OrgAdmin":                 {org, id(2).String()},
		"OrgMember":                {org, id(2).String()},
		"OrgGrantHeld":             {org, id(2), id(4), "issues.write"},
		"BookKeys":                 {model.BookConditions, "b"},
		"BookRecord":               {model.BookIncidents, "book"},
		"ProjectIssues":            {id(1), id(4)},
	}
}

func call(t *testing.T, ro model.ReadOnlyControl, name string, args []any) []reflect.Value {
	t.Helper()
	in := make([]reflect.Value, len(args))
	for i, a := range args {
		in[i] = reflect.ValueOf(a)
	}
	return reflect.ValueOf(ro).MethodByName(name).Call(in)
}

// referenceKind reports a kind through which a result could alias the state it came from and that
// no copy can make safe: a map, an interface, a channel or a function. (Slices and pointers are
// allowed because a copy of what they reach is a copy; TestReadOnlyControlResultsAreCopies writes
// through them.)
func referenceKind(k reflect.Kind) bool {
	switch k {
	case reflect.Map, reflect.Interface, reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return true
	}
	return false
}

// leak is the path of a type that lets a result alias the state, or "".
func leak(t reflect.Type, path string, seen map[reflect.Type]bool) string {
	if referenceKind(t.Kind()) {
		return path + " is a " + t.Kind().String()
	}
	if seen[t] {
		return ""
	}
	seen[t] = true
	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		return leak(t.Elem(), path+"[]", seen)
	case reflect.Pointer:
		return leak(t.Elem(), path+"*", seen)
	case reflect.Struct:
		for i := range t.NumField() {
			f := t.Field(i)
			if !f.IsExported() {
				return path + "." + f.Name + " is unexported: a result must be plain data"
			}
			if s := leak(f.Type, path+"."+f.Name, seen); s != "" {
				return s
			}
		}
	}
	return ""
}

// The interface hands out no map, interface, channel or function, directly or inside a result
// struct, slice element or pointee: what a result can reach is slices and pointers, and
// TestReadOnlyControlResultsAreCopies writes through those.
func TestReadOnlyControlReturnsNoReference(t *testing.T) {
	typ := reflect.TypeOf((*model.ReadOnlyControl)(nil)).Elem()
	if typ.NumMethod() == 0 {
		t.Fatal("no methods")
	}
	for i := range typ.NumMethod() {
		m := typ.Method(i)
		for j := range m.Type.NumOut() {
			if why := leak(m.Type.Out(j), m.Name+" result", map[reflect.Type]bool{}); why != "" {
				t.Errorf("%s: %s", m.Name, why)
			}
		}
	}
}

// scribble overwrites every scalar reachable from v through slices, arrays, pointers and struct
// fields.
func scribble(v reflect.Value) {
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			scribble(v.Index(i))
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if f := v.Field(i); f.CanSet() {
				scribble(f)
			}
		}
	case reflect.Pointer:
		if !v.IsNil() {
			scribble(v.Elem())
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(v.String() + "!")
		}
	case reflect.Bool:
		if v.CanSet() {
			v.SetBool(!v.Bool())
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if v.CanSet() {
			v.SetInt(v.Int() + 1)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if v.CanSet() {
			v.SetUint(v.Uint() + 1)
		}
	}
}

// Writing to everything a method returned changes nothing the next call, or another reader's call,
// sees: each result of each method is compared with the result of the same call on a second state
// that no one touched.
func TestReadOnlyControlResultsAreCopies(t *testing.T) {
	typ := reflect.TypeOf((*model.ReadOnlyControl)(nil)).Elem()
	calls := roCalls()
	for i := range typ.NumMethod() {
		name := typ.Method(i).Name
		args, ok := calls[name]
		if !ok {
			t.Errorf("%s has no case in roCalls: an accessor needs a mutation case", name)
			continue
		}
		shared, untouched := roFixture(), roFixture()
		sro, uro := model.ReadOnlyOf(&shared), model.ReadOnlyOf(&untouched)
		want := call(t, uro, name, args)
		for _, v := range call(t, sro, name, args) { // an earlier reader writes to what it was given
			scribble(v)
		}
		got := call(t, sro, name, args)
		for j := range want {
			if !reflect.DeepEqual(want[j].Interface(), got[j].Interface()) {
				t.Errorf("%s result %d: a write to an earlier result changed the next call: want %v, got %v", name, j, want[j], got[j])
			}
		}
		if !reflect.DeepEqual(untouched, shared) {
			t.Errorf("%s: the state itself changed", name)
		}
	}
	for name := range calls {
		if _, ok := typ.MethodByName(name); !ok {
			t.Errorf("roCalls lists %s, which ReadOnlyControl does not have", name)
		}
	}
}

// ActiveDeletions in particular: the lists of a returned predicate are the caller's.
func TestActiveDeletionsReturnsPredicatesWithListsOfTheirOwn(t *testing.T) {
	st := roFixture()
	ro := model.ReadOnlyOf(&st)
	org := model.ID{1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	first := ro.ActiveDeletions(org, nil)
	if len(first) != 2 {
		t.Fatalf("want the fencing and the complete deletion (the held one is not active), got %d", len(first))
	}
	for i := range first {
		for j := range first[i].Projects {
			first[i].Projects[j] = model.ID{0xff}
		}
		for j := range first[i].Signals {
			first[i].Signals[j] = model.Kind("x")
		}
		for j := range first[i].Entities {
			first[i].Entities[j] = model.ID{0xff}
		}
	}
	again := ro.ActiveDeletions(org, nil)
	if fmt.Sprint(again) == fmt.Sprint(first) {
		t.Fatal("a write to a returned predicate is visible to the next call")
	}
	if fresh := roFixture(); !reflect.DeepEqual(st, fresh) {
		t.Fatal("a write to a returned predicate reached the state")
	}
}

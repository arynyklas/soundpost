// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// fill sets every identifier of v that is zero (an identifier that is zero does not encode) to one fixed
// non-zero identifier, whatever the nesting, and returns v: equal calls give equal rows.
func fill[T any](v T) T {
	var walk func(r reflect.Value)
	walk = func(r reflect.Value) {
		switch {
		case r.Type() == reflect.TypeOf(model.ID{}):
			if r.Interface().(model.ID) == (model.ID{}) {
				r.Set(reflect.ValueOf(model.ID{0xf1}))
			}
		case r.Kind() == reflect.Struct:
			for i := range r.NumField() {
				if r.Field(i).CanSet() {
					walk(r.Field(i))
				}
			}
		}
	}
	walk(reflect.ValueOf(&v).Elem())
	return v
}

// verifyFixture is two organizations, x (the one a transition is verified for) and y, and one table
// writer per table the tests exercise.
type verifyFixture struct {
	t              *testing.T
	x, y           model.ID
	installation   model.ID
	project        model.ID
	masked, always []verifyTable
}

type verifyTable struct {
	name string
	// add puts one row for org into st; a nil table is created.
	add func(st *State, org model.ID)
}

func newVerifyFixture(t *testing.T) *verifyFixture {
	f := &verifyFixture{t: t, x: model.NewID(), y: model.NewID(), installation: model.NewID(), project: model.NewID()}
	rid := func(org model.ID) model.ID { return org } // one row id per organization, so that two rows never collide
	raw := func(org model.ID) json.RawMessage {
		return json.RawMessage(`{"org":"` + org.String() + `","payload":"p"}`)
	}
	book := func(org model.ID) string { return org.String() + ":" + f.project.String() + ":" + rid(org).String() }
	put := func(table *map[string]json.RawMessage, key string, value json.RawMessage) {
		if *table == nil {
			*table = map[string]json.RawMessage{}
		}
		(*table)[key] = value
	}
	f.masked = []verifyTable{
		{"Deletions", func(st *State, org model.ID) {
			if st.Deletions == nil {
				st.Deletions = map[string]model.DeletionOperation{}
			}
			st.Deletions[rid(org).String()] = fill(model.DeletionOperation{Predicate: model.DeletePredicate{Operation: rid(org), Org: org}})
		}},
		{"Holds", func(st *State, org model.ID) {
			if st.Holds == nil {
				st.Holds = map[string]model.LegalHold{}
			}
			st.Holds[rid(org).String()] = fill(model.LegalHold{ID: rid(org), Org: org})
		}},
		{"Sources", func(st *State, org model.ID) {
			if st.Sources == nil {
				st.Sources = map[string]model.SourceAuthority{}
			}
			st.Sources[rid(org).String()] = fill(model.SourceAuthority{ID: rid(org), Org: org})
		}},
		{"GroupingIssues", func(st *State, org model.ID) {
			if st.GroupingIssues == nil {
				st.GroupingIssues = map[string]model.GroupingIssue{}
			}
			st.GroupingIssues[rid(org).String()] = fill(model.GroupingIssue{ID: rid(org), Org: org})
		}},
		{"GroupingMigrations", func(st *State, org model.ID) {
			if st.GroupingMigrations == nil {
				st.GroupingMigrations = map[string]model.GroupingMigration{}
			}
			st.GroupingMigrations[book(org)] = fill(model.GroupingMigration{ID: rid(org), Org: org})
		}},
		{"Releases", func(st *State, org model.ID) {
			if st.Releases == nil {
				st.Releases = map[string]model.Release{}
			}
			st.Releases[book(org)] = fill(model.Release{ID: rid(org), Org: org})
		}},
		{"DeleteGenerations", func(st *State, org model.ID) {
			if st.DeleteGenerations == nil {
				st.DeleteGenerations = map[string]uint64{}
			}
			st.DeleteGenerations[org.String()] = 3
		}},
		{"RetiredOrgs", func(st *State, org model.ID) {
			if st.RetiredOrgs == nil {
				st.RetiredOrgs = map[string]model.ID{}
			}
			st.RetiredOrgs[org.String()] = rid(org)
		}},
		{"RetiredProjects", func(st *State, org model.ID) {
			if st.RetiredProjects == nil {
				st.RetiredProjects = map[string]model.ID{}
			}
			st.RetiredProjects[org.String()+":"+f.project.String()] = rid(org)
		}},
		{"RetentionPolicies (organization)", func(st *State, org model.ID) {
			if st.RetentionPolicies == nil {
				st.RetentionPolicies = map[string][]model.RetentionPolicyVersion{}
			}
			st.RetentionPolicies[org.String()] = []model.RetentionPolicyVersion{fill(model.RetentionPolicyVersion{Org: org, Version: 1})}
		}},
		{"RetentionPolicies (project)", func(st *State, org model.ID) {
			if st.RetentionPolicies == nil {
				st.RetentionPolicies = map[string][]model.RetentionPolicyVersion{}
			}
			st.RetentionPolicies[org.String()+":"+f.project.String()] = []model.RetentionPolicyVersion{fill(model.RetentionPolicyVersion{Org: org, Version: 1})}
		}},
	}
	books := map[string]func(st *State) *map[string]json.RawMessage{
		"RuleBooks":       func(st *State) *map[string]json.RawMessage { return &st.RuleBooks },
		"IncidentBooks":   func(st *State) *map[string]json.RawMessage { return &st.IncidentBooks },
		"ConditionBooks":  func(st *State) *map[string]json.RawMessage { return &st.ConditionBooks },
		"IssueBooks":      func(st *State) *map[string]json.RawMessage { return &st.IssueBooks },
		"JobBooks":        func(st *State) *map[string]json.RawMessage { return &st.JobBooks },
		"CutoverBooks":    func(st *State) *map[string]json.RawMessage { return &st.CutoverBooks },
		"SavedViewBooks":  func(st *State) *map[string]json.RawMessage { return &st.SavedViewBooks },
		"RuleDefinitions": func(st *State) *map[string]json.RawMessage { return &st.RuleDefinitions },
		"JobDefinitions":  func(st *State) *map[string]json.RawMessage { return &st.JobDefinitions },
		"JobPositions":    func(st *State) *map[string]json.RawMessage { return &st.JobPositions },
		"RuleOutputs":     func(st *State) *map[string]json.RawMessage { return &st.RuleOutputs },
		"DeliveryBooks":   func(st *State) *map[string]json.RawMessage { return &st.DeliveryBooks },
	}
	for name, field := range books {
		switch name {
		case "RuleOutputs": // keyed by the output id: attributed by the Org the record names
			f.masked = append(f.masked, verifyTable{name, func(st *State, org model.ID) { put(field(st), rid(org).String(), raw(org)) }})
		case "DeliveryBooks":
			f.masked = append(f.masked,
				verifyTable{name + " (delivery)", func(st *State, org model.ID) { put(field(st), "delivery:"+rid(org).String(), raw(org)) }},
				verifyTable{name + " (policy)", func(st *State, org model.ID) {
					put(field(st), "policy:"+org.String()+":"+f.project.String()+":"+rid(org).String()+":s", json.RawMessage(`{}`))
				}})
		default: // keyed "org:project:..."
			f.masked = append(f.masked, verifyTable{name, func(st *State, org model.ID) { put(field(st), book(org), raw(org)) }})
		}
	}
	f.always = []verifyTable{
		{"EvidenceGaps", func(st *State, org model.ID) {
			st.EvidenceGaps = map[string]model.EvidenceGap{rid(org).String(): fill(model.EvidenceGap{ID: rid(org), Org: org})}
		}},
		{"SourceFences", func(st *State, org model.ID) {
			st.SourceFences = map[string]model.SourceFence{rid(org).String(): fill(model.SourceFence{Org: org})}
		}},
		{"SourceOperations", func(st *State, org model.ID) {
			st.SourceOperations = map[string]model.SourceFence{rid(org).String(): fill(model.SourceFence{Org: org})}
		}},
		{"Quotas", func(st *State, org model.ID) { st.Quotas = map[string]model.QuotaState{org.String(): {Bytes: 1}} }},
		{"Reservations", func(st *State, org model.ID) {
			st.Reservations = map[string]model.AdmissionReservation{rid(org).String(): fill(model.AdmissionReservation{ID: rid(org), Org: org})}
		}},
		{"Users", func(st *State, org model.ID) {
			st.Users = map[string]model.ControlUser{org.String(): fill(model.ControlUser{Email: "x"})}
		}},
		{"Sessions", func(st *State, org model.ID) {
			st.Sessions = map[string]model.ControlSession{org.String(): fill(model.ControlSession{})}
		}},
		{"DeliveryBooks (fence)", func(st *State, org model.ID) {
			put(&st.DeliveryBooks, "fence:"+org.String()+":"+f.project.String(), json.RawMessage(`1`))
		}},
		{"a delivery row that names no organization", func(st *State, org model.ID) {
			put(&st.DeliveryBooks, "delivery:"+rid(org).String(), json.RawMessage(`{"payload":"p"}`))
		}},
		{"a rule output that does not decode", func(st *State, org model.ID) {
			put(&st.RuleOutputs, rid(org).String(), json.RawMessage(`[1]`))
		}},
		{"a book row whose key starts like the organization's id but is not", func(st *State, org model.ID) {
			put(&st.IncidentBooks, org.String()[:31]+":"+f.project.String()+":"+rid(org).String(), json.RawMessage(`{}`))
		}},
	}
	return f
}

func (f *verifyFixture) base() *State {
	return &State{Installation: f.installation, Revision: 5, Orgs: map[string]model.ControlOrg{f.x.String(): {ID: f.x}, f.y.String(): {ID: f.y}}}
}

func (f *verifyFixture) enc(st *State) []byte {
	f.t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

// verify is verifyOrgTransition for x between two states, the second one with its revision stamped as
// every commit does.
func (f *verifyFixture) verify(class orgClass, from, to *State) bool {
	f.t.Helper()
	next := *to
	next.Revision = from.Revision + 1
	return verifyOrgTransition(f.enc(from), f.enc(&next), f.x, class)
}

// A retention-class commit may add, change and remove the rows its organization owns in the retention
// tables, and nothing of another organization; an admin-class commit may not touch these tables at all.
func TestVerifyOrgTransitionRetentionTables(t *testing.T) {
	f := newVerifyFixture(t)
	for _, c := range f.masked {
		t.Run(c.name, func(t *testing.T) {
			f.t = t
			own, other, both := f.base(), f.base(), f.base()
			c.add(own, f.x)
			c.add(other, f.y)
			c.add(both, f.y)
			c.add(both, f.x)
			for _, step := range []struct {
				what     string
				from, to *State
				want     bool
			}{
				{"a row of the organization added", f.base(), own, true},
				{"a row of the organization removed", own, f.base(), true},
				{"a row of ANOTHER organization added", f.base(), other, false},
				{"a row of ANOTHER organization removed", other, f.base(), false},
				{"the organization's row added beside another's", other, both, true},
				{"the organization's row removed beside another's", both, other, true},
				{"another organization's row removed beside the organization's", both, own, false},
			} {
				if got := f.verify(orgRetention, step.from, step.to); got != step.want {
					t.Errorf("retention class, %s: %v, want %v", step.what, got, step.want)
				}
			}
			if f.verify(classAdmin, f.base(), own) {
				t.Error("admin class: a row of a retention table was accepted")
			}
		})
	}
}

// A row that was not the organization's does not become its own by changing hands: both sides of a
// changed row have to belong to it.
func TestVerifyOrgTransitionRowChangingOwner(t *testing.T) {
	f := newVerifyFixture(t)
	key, id := model.NewID().String(), model.NewID()
	hold := func(org model.ID) *State {
		st := f.base()
		st.Holds = map[string]model.LegalHold{key: fill(model.LegalHold{ID: id, Org: org})}
		return st
	}
	if !f.verify(orgRetention, hold(f.x), hold(f.x)) { // same row, same bytes but for the stamped revision
		t.Error("an unchanged row of the organization was refused")
	}
	changed := hold(f.x)
	h := changed.Holds[key]
	h.Reason = "changed"
	changed.Holds[key] = h
	if !f.verify(orgRetention, hold(f.x), changed) {
		t.Error("a change to a row of the organization was refused")
	}
	if f.verify(orgRetention, hold(f.x), hold(f.y)) {
		t.Error("a row handed from the organization to another was accepted")
	}
	if f.verify(orgRetention, hold(f.y), hold(f.x)) {
		t.Error("another organization's row taken over was accepted")
	}
}

// A table that is not a retention table, or a row no one owns, changes the verdict whoever the row
// names: the transition keeps the installation-wide bump.
func TestVerifyOrgTransitionRefusesWhatNoClassOwns(t *testing.T) {
	f := newVerifyFixture(t)
	for _, c := range f.always {
		t.Run(c.name, func(t *testing.T) {
			f.t = t
			for _, org := range []model.ID{f.x, f.y} {
				st := f.base()
				c.add(st, org)
				for _, class := range []orgClass{classAdmin, orgRetention} {
					if f.verify(class, f.base(), st) {
						t.Errorf("class %d: a row of %s was accepted", class, org)
					}
					if f.verify(class, st, f.base()) {
						t.Errorf("class %d: the removal of a row of %s was accepted", class, org)
					}
				}
			}
		})
	}
	for name, change := range map[string]func(st *State){
		"the installation revision": func(st *State) { st.AuthorityRevision = 9 },
		"the installation key":      func(st *State) { st.PolicySigningKey = "k" },
		"the bootstrap hash":        func(st *State) { st.BootstrapHash = "h" },
		"the data flag":             func(st *State) { st.DataInitialized = true },
		"the settlement":            func(st *State) { st.Settlement = &model.Settlement{} },
	} {
		st := f.base()
		change(st)
		for _, class := range []orgClass{classAdmin, orgRetention} {
			if f.verify(class, f.base(), st) {
				t.Errorf("class %d: a change of %s was accepted", class, name)
			}
		}
	}
}

// What both classes may do beside the organization's rows: its own record, appended audit rows, added
// commands, and the revision and its clock; and nothing else of the books.
func TestVerifyOrgTransitionBooksAndRecords(t *testing.T) {
	f := newVerifyFixture(t)
	audit := func(reason string) model.ControlAudit {
		return fill(model.ControlAudit{Action: "a", Reason: reason})
	}
	// Rows are compared as encodings, so each one is built once.
	a1, a2, a3 := audit("one"), audit("two"), audit("three")
	audits := func(rows ...model.ControlAudit) *State {
		st := f.base()
		st.Audits = rows
		return st
	}
	results := map[string]model.ControlResult{}
	withCommands := func(ids ...string) *State {
		st := f.base()
		st.Commands, st.CommandOwners = map[string]model.ControlResult{}, map[string]string{}
		for _, id := range ids {
			if _, ok := results[id]; !ok {
				results[id] = fill(model.ControlResult{Phase: id})
			}
			st.Commands[id] = results[id]
			st.CommandOwners[id] = "owner:" + id
		}
		return st
	}
	record := func(org model.ID, epoch uint64, settings map[string]json.RawMessage) *State {
		st := f.base()
		o := st.Orgs[org.String()]
		o.Epoch, o.Settings = epoch, settings
		st.Orgs[org.String()] = o
		return st
	}
	for _, class := range []orgClass{classAdmin, orgRetention} {
		for _, step := range []struct {
			what     string
			from, to *State
			want     bool
		}{
			{"a first audit row", f.base(), audits(a1), true},
			{"audit rows appended", audits(a1), audits(a1, a2, a3), true},
			{"an audit row edited", audits(a1, a2), audits(a1, a3), false},
			{"an audit row removed", audits(a1, a2), audits(a2), false},
			{"the audit log emptied", audits(a1), f.base(), false},
			{"the audit log cut at the end", audits(a1, a2), audits(a1), false},
			{"commands added", withCommands("a"), withCommands("a", "b"), true},
			{"a command edited", withCommands("a", "b"), func() *State {
				st := withCommands("a", "b")
				st.Commands["a"] = fill(model.ControlResult{Phase: "edited"})
				return st
			}(), false},
			{"a command removed", withCommands("a", "b"), withCommands("a"), false},
			{"a command owner edited", withCommands("a"), func() *State {
				st := withCommands("a")
				st.CommandOwners["a"] = "someone else"
				return st
			}(), false},
			{"the organization's own record", record(f.x, 1, nil), record(f.x, 2, map[string]json.RawMessage{model.OrgAuthorityKey: json.RawMessage(`7`)}), true},
			{"another organization's record", record(f.y, 1, nil), record(f.y, 2, nil), false},
			{"another organization created", f.base(), func() *State {
				st := f.base()
				z := model.NewID()
				st.Orgs[z.String()] = model.ControlOrg{ID: z}
				return st
			}(), false},
			{"another organization removed", f.base(), func() *State {
				st := f.base()
				delete(st.Orgs, f.y.String())
				return st
			}(), false},
			{"the organization created", func() *State {
				st := f.base()
				delete(st.Orgs, f.x.String())
				return st
			}(), f.base(), true},
		} {
			if got := f.verify(class, step.from, step.to); got != step.want {
				t.Errorf("class %d, %s: %v, want %v", class, step.what, got, step.want)
			}
		}
		// The revision clock and the revision are moved by every commit, after the transition ran.
		st := f.base()
		st.RevisionClock = []model.RevisionStamp{{Revision: 5, At: 1}}
		if !f.verify(class, f.base(), st) {
			t.Errorf("class %d: a revision clock stamp was refused", class)
		}
	}
	// The encodings that are not of a state, or of another one, are never accepted.
	if verifyOrgTransition(nil, f.enc(f.base()), f.x, orgRetention) || verifyOrgTransition(f.enc(f.base()), []byte("[]"), f.x, orgRetention) {
		t.Error("an encoding that is not a state was accepted")
	}
	// An absent table and a null one are the same table, and a table that went from null to empty is unchanged.
	a, b := f.base(), f.base()
	a.Holds, b.Holds = nil, map[string]model.LegalHold{}
	if !f.verify(orgRetention, a, b) {
		t.Error("a nil table became an empty one: refused")
	}
}

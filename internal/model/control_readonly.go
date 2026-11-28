// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"sort"
	"strings"
)

// ReadOnlyControl is a committed control state that readers SHARE.
//
// Decoding the whole control state costs O(size of the state), and a pass of the background workers
// reads it a few times per project, so decoding it per read made a pass O(projects squared). The
// control store therefore decodes each committed revision once and hands the same decode to every
// concurrent reader (control.Store.ViewShared). That is only sound if no reader can change it, so a
// reader is given this interface and never the state itself:
//
//   - it has no method that returns a map, an interface, a channel or a function, and no method that
//     returns a struct holding one;
//   - what a method returns that can reach memory (a slice, a pointer inside a struct) is a copy
//     made for that call, all the way down, so writing to a result changes nothing another reader
//     (or the next call) sees;
//   - strings are immutable and are returned as they are.
//
// The contract is pinned by TestReadOnlyControlReturnsNoReference and
// TestReadOnlyControlResultsAreCopies (internal/model): the first walks the result types of every
// method, the second writes through every slice and pointer of every result of every method and
// calls again. A new accessor must come with an entry in the second.
//
// Keys are the canonical strings the state is keyed by. The methods answer questions about the
// state; none of them is a way to take part of it out.
type ReadOnlyControl interface {
	Installation() ID
	Revision() Revision
	AuthorityRevision() Revision

	// Session is the session stored under hashToken(token).
	Session(hash string) (ControlSession, bool)
	// UserState reports whether the user exists and whether it is disabled.
	UserState(id string) (exists, disabled bool)
	// ServerToken is the token stored under its digest, without its permission and project lists
	// (ServerTokenHasPermission, ServerTokenHasProject answer for those).
	ServerToken(digest string) (ServerTokenInfo, bool)
	ServerTokenHasPermission(digest, permission string) bool
	ServerTokenHasProject(digest string, project ID) bool

	// OrgEpoch is the policy epoch of an organization.
	OrgEpoch(org string) (epoch uint64, ok bool)
	// OrgHasProject reports whether the organization lists the project.
	OrgHasProject(org, project string) bool
	// OrgRetired and ProjectRetired report an organization or project that has been retired.
	OrgRetired(org string) bool
	ProjectRetired(org, project string) bool

	// ActiveDeletions are the predicates of the deletions of the organization that are not held and
	// cover one of the projects (every project when none is named), in operation order.
	ActiveDeletions(org ID, projects []ID) []DeletePredicate
	// DeletionPredicates are the predicates of every deletion whose phase is one of phases, in
	// operation order.
	DeletionPredicates(phases ...string) []DeletePredicate

	// OrgAdmin and OrgMember report the principal's standing in the organization.
	OrgAdmin(org, principal string) bool
	OrgMember(org, principal string) bool
	// OrgGrantHeld reports whether user holds permission on project in the organization, through
	// a direct grant or through an enabled team that lists both the user and the project.
	OrgGrantHeld(org string, user, project ID, permission string) bool

	// BookKeys lists the keys of one control book that start with prefix, in no particular order.
	BookKeys(book Book, prefix string) []string
	// BookRecord is a copy of the bytes stored under key in one control book.
	BookRecord(book Book, key string) ([]byte, bool)

	// ProjectIssues are copies of the committed grouping issues of one project, in no particular
	// order.
	ProjectIssues(org, project ID) []GroupingIssueEntry
}

// Book names one of the control state's books of opaque records (JSON the control package
// defines); each value is the name of the ControlState field that holds it.
type Book string

const (
	BookIssues         Book = "IssueBooks"
	BookGroupingIssues Book = "GroupingIssues"
	BookJobs           Book = "JobBooks"
	BookConditions     Book = "ConditionBooks"
	BookIncidents      Book = "IncidentBooks"
	BookDeliveries     Book = "DeliveryBooks"
	BookCutovers       Book = "CutoverBooks"
	BookRuleBooks      Book = "RuleBooks"
	BookRuleOutputs    Book = "RuleOutputs"
	BookRuleDefinition Book = "RuleDefinitions"
	BookJobDefinitions Book = "JobDefinitions"
	BookJobPositions   Book = "JobPositions"
	BookSavedViews     Book = "SavedViewBooks"
)

// GroupingIssueEntry is one grouping issue with the key it is stored under.
type GroupingIssueEntry struct {
	Key   string
	Issue GroupingIssue
}

// ServerTokenInfo is the part of a server token that carries no list.
type ServerTokenInfo struct {
	ID        ID
	Principal ID
	Org       ID
	Expires   int64
	Revoked   bool
}

// ReadOnlyOf reads st through the read-only interface, without copying it. It is for code that
// holds a state it may mutate (a transaction in progress) and calls a function written against
// ReadOnlyControl: the function sees the state as it is when it asks.
func ReadOnlyOf(st *ControlState) ReadOnlyControl { return readOnlyControl{st: st} }

// BookSource reads the records of the books a decoded state does not hold: the job and issue books of a
// control store that keeps them as records of their own. Its answers are the state's own, for the
// revision the state is of.
type BookSource interface {
	BookKeys(book Book, prefix string) []string
	BookRecord(book Book, key string) ([]byte, bool)
}

// ReadOnlyOfWith is ReadOnlyOf for a state whose books src serves (the job and issue books, the grouping issues
// and the job positions, unless src is a BookRouter that names others) instead of the state's own members.
func ReadOnlyOfWith(st *ControlState, src BookSource) ReadOnlyControl {
	return readOnlyControl{st: st, src: src}
}

// BookRouter is implemented by a BookSource that says which books it serves. A source without it serves the
// books of the ledger: the issue and job books, the grouping issues and the job positions.
type BookRouter interface {
	Serves(book Book) bool
}

// serves reports whether the book is read from the source instead of the state's own member.
func (r readOnlyControl) serves(book Book) bool {
	if r.src == nil {
		return false
	}
	if router, ok := r.src.(BookRouter); ok {
		return router.Serves(book)
	}
	return book == BookIssues || book == BookJobs || book == BookGroupingIssues || book == BookJobPositions
}

// ReadOnlyControlMembers are the members of ControlState, by the name the state is encoded under, that the
// methods of ReadOnlyControl read from the state, the books apart. A state that holds these members
// and a BookSource for the books answers every call as the whole state does: a control store that decodes
// the members one by one decodes these for a shared reader and no others (TestReadOnlyControlReadsOnlyItsMembers).
func ReadOnlyControlMembers() []string {
	return []string{"Installation", "authority_revision", "Users", "Sessions", "ServerTokens", "Orgs", "RetiredOrgs", "RetiredProjects", "Deletions", "GroupingIssues"}
}

// ReadOnlyBookMembers are the members of ControlState that BookKeys and BookRecord read when the state is
// the source of the book: the name of a book is the name of its member.
func ReadOnlyBookMembers() []string {
	return []string{string(BookIssues), string(BookJobs), string(BookConditions), string(BookIncidents), string(BookDeliveries), string(BookCutovers),
		string(BookRuleBooks), string(BookRuleOutputs), string(BookRuleDefinition), string(BookJobDefinitions), string(BookJobPositions), string(BookSavedViews)}
}

type readOnlyControl struct {
	st  *ControlState
	src BookSource
}

func (r readOnlyControl) Installation() ID {
	return r.st.Installation
}

func (r readOnlyControl) Revision() Revision {
	return r.st.Revision
}

func (r readOnlyControl) AuthorityRevision() Revision {
	return r.st.AuthorityRevision
}

func (r readOnlyControl) Session(hash string) (ControlSession, bool) {
	s, ok := r.st.Sessions[hash]
	return s, ok
}

func (r readOnlyControl) UserState(id string) (exists, disabled bool) {
	u, ok := r.st.Users[id]
	return ok, u.Disabled
}

func (r readOnlyControl) ServerToken(digest string) (ServerTokenInfo, bool) {
	t, ok := r.st.ServerTokens[digest]
	return ServerTokenInfo{ID: t.ID, Principal: t.Principal, Org: t.Org, Expires: t.Expires, Revoked: t.Revoked}, ok
}

func (r readOnlyControl) ServerTokenHasPermission(digest, permission string) bool {
	for _, v := range r.st.ServerTokens[digest].Permissions {
		if v == permission {
			return true
		}
	}
	return false
}

func (r readOnlyControl) ServerTokenHasProject(digest string, project ID) bool {
	return containsID(r.st.ServerTokens[digest].Projects, project)
}

func (r readOnlyControl) OrgEpoch(org string) (uint64, bool) {
	o, ok := r.st.Orgs[org]
	return o.Epoch, ok
}

func (r readOnlyControl) OrgHasProject(org, project string) bool {
	_, ok := r.st.Orgs[org].Projects[project]
	return ok
}

func (r readOnlyControl) OrgRetired(org string) bool {
	_, ok := r.st.RetiredOrgs[org]
	return ok
}

func (r readOnlyControl) ProjectRetired(org, project string) bool {
	_, ok := r.st.RetiredProjects[org+":"+project]
	return ok
}

func (r readOnlyControl) ActiveDeletions(org ID, projects []ID) []DeletePredicate {
	return ActiveDeletionsOf(r.st.Deletions, org, projects)
}

// ActiveDeletionsOf selects, from a deletions table, the predicates of the organization's deletions
// that are not held and cover one of the projects (every project when none is named), in operation
// order. The predicates are copies: their lists are not the table's.
func ActiveDeletionsOf(deletions map[string]DeletionOperation, org ID, projects []ID) []DeletePredicate {
	var out []DeletePredicate
	for _, op := range deletions {
		if op.Phase == DeletePhaseHeld || op.Predicate.Org != org {
			continue
		}
		hit := len(projects) == 0 || op.Predicate.Mode == DeleteRetireOrg
		for _, p := range projects {
			hit = hit || op.Predicate.CoversProject(org, p)
		}
		if hit {
			out = append(out, op.Predicate.clone())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Operation.String() < out[j].Operation.String() })
	return out
}

// clone is p with lists of its own.
func (p DeletePredicate) clone() DeletePredicate {
	p.Projects = append([]ID(nil), p.Projects...)
	p.Signals = append([]Kind(nil), p.Signals...)
	p.Entities = append([]ID(nil), p.Entities...)
	return p
}

func (r readOnlyControl) DeletionPredicates(phases ...string) []DeletePredicate {
	var out []DeletePredicate
	for _, op := range r.st.Deletions {
		for _, phase := range phases {
			if op.Phase == phase {
				out = append(out, op.Predicate.clone())
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Operation.String() < out[j].Operation.String() })
	return out
}

func (r readOnlyControl) OrgAdmin(org, principal string) bool {
	return r.st.Orgs[org].Admins[principal]
}

func (r readOnlyControl) OrgMember(org, principal string) bool {
	return r.st.Orgs[org].Members[principal]
}

func (r readOnlyControl) OrgGrantHeld(org string, user, project ID, permission string) bool {
	o := r.st.Orgs[org]
	for _, v := range o.Grants[user.String()+":"+project.String()] {
		if v == permission {
			return true
		}
	}
	for _, team := range o.Teams {
		if team.Enabled && containsID(team.Members, user) && containsID(team.Projects, project) {
			for _, v := range team.Permissions {
				if v == permission {
					return true
				}
			}
		}
	}
	return false
}

// bookOf is the map a Book names, nil for a name that is not a book.
func (r readOnlyControl) bookOf(book Book) map[string]json.RawMessage {
	switch book {
	case BookIssues:
		return r.st.IssueBooks
	case BookJobs:
		return r.st.JobBooks
	case BookConditions:
		return r.st.ConditionBooks
	case BookIncidents:
		return r.st.IncidentBooks
	case BookDeliveries:
		return r.st.DeliveryBooks
	case BookCutovers:
		return r.st.CutoverBooks
	case BookRuleBooks:
		return r.st.RuleBooks
	case BookRuleOutputs:
		return r.st.RuleOutputs
	case BookRuleDefinition:
		return r.st.RuleDefinitions
	case BookJobDefinitions:
		return r.st.JobDefinitions
	case BookJobPositions:
		return r.st.JobPositions
	case BookSavedViews:
		return r.st.SavedViewBooks
	}
	return nil
}

func (r readOnlyControl) BookKeys(book Book, prefix string) []string {
	if r.serves(book) {
		return r.src.BookKeys(book, prefix)
	}
	var out []string
	if book == BookGroupingIssues {
		// The grouping issues are structs of the state, not opaque records: their keys are listed, their
		// content is read through ProjectIssues.
		for key := range r.st.GroupingIssues {
			if strings.HasPrefix(key, prefix) {
				out = append(out, key)
			}
		}
		return out
	}
	for key := range r.bookOf(book) {
		if strings.HasPrefix(key, prefix) {
			out = append(out, key)
		}
	}
	return out
}

func (r readOnlyControl) BookRecord(book Book, key string) ([]byte, bool) {
	if r.serves(book) {
		return r.src.BookRecord(book, key)
	}
	raw, ok := r.bookOf(book)[key]
	if !ok {
		return nil, false
	}
	return append([]byte{}, raw...), true
}

func (r readOnlyControl) ProjectIssues(org, project ID) []GroupingIssueEntry {
	var out []GroupingIssueEntry
	if r.serves(BookGroupingIssues) {
		// The grouping issues are records of the control store; a project's are those under its key prefix.
		for _, key := range r.src.BookKeys(BookGroupingIssues, org.String()+":"+project.String()+":") {
			raw, ok := r.src.BookRecord(BookGroupingIssues, key)
			if !ok {
				continue
			}
			var gi GroupingIssue
			if json.Unmarshal(raw, &gi) != nil || gi.Org != org || gi.Project != project {
				continue
			}
			out = append(out, GroupingIssueEntry{Key: key, Issue: gi})
		}
		return out
	}
	for key, gi := range r.st.GroupingIssues {
		if gi.Org == org && gi.Project == project {
			out = append(out, GroupingIssueEntry{Key: key, Issue: gi.clone()})
		}
	}
	return out
}

// clone is g with everything it holds a copy of its own.
func (g GroupingIssue) clone() GroupingIssue {
	g.Occurrences = cloneEvidence(g.Occurrences)
	g.LateHistory = cloneEvidence(g.LateHistory)
	g.Compacted = g.Compacted.Clone()
	g.LateCompacted = g.LateCompacted.Clone()
	if g.ResolutionTime != nil {
		t := *g.ResolutionTime
		g.ResolutionTime = &t
	}
	g.ResolutionFrontier = append([]ID(nil), g.ResolutionFrontier...)
	g.ObservedReleases = append([]ID(nil), g.ObservedReleases...)
	g.FixedDescendants = append([]ID(nil), g.FixedDescendants...)
	g.MigrationLinks = append([]ID(nil), g.MigrationLinks...)
	if g.Owner != nil {
		o := *g.Owner
		g.Owner = &o
	}
	g.External = append([]ExternalLink(nil), g.External...)
	return g
}

func cloneEvidence(in []GroupingEvidence) []GroupingEvidence {
	if in == nil {
		return nil
	}
	out := make([]GroupingEvidence, len(in))
	for i, e := range in {
		if e.BuildID != nil {
			v := *e.BuildID
			e.BuildID = &v
		}
		if e.ReleaseID != nil {
			v := *e.ReleaseID
			e.ReleaseID = &v
		}
		if e.ProducerEpoch != nil {
			v := *e.ProducerEpoch
			e.ProducerEpoch = &v
		}
		if e.Denominator != nil {
			v := *e.Denominator
			v.Cursors = append([]Cursor(nil), v.Cursors...)
			e.Denominator = &v
		}
		out[i] = e
	}
	return out
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
)

// The per-organization authority revision (F-10.05-2). AuthorityRevision is one scalar for the whole
// installation, so a command of one tenant that moved it made every other tenant's retention command
// with an older view conflict. Two classes of transition move the organization's own revision
// (model.OrgAuthorityKey in its Settings) instead, each only after control has checked that the
// commit changed nothing outside what the class owns:
//
//   - classAdmin: an admin command of the organization (UpdateOrgAuthority). It may change the
//     organization's own record.
//   - orgRetention: a retention-class command or worker transition of the organization (the retention
//     kinds of Transact, the saga steps of the worker, a delete generation: updateOrgRetention,
//     updateOperation). It may change the organization's record and the rows the organization owns in
//     the retention tables (orgRetentionTables).
//
// Both may append to the audit log and add to the command books. Anything else a commit changes, a row
// of another organization, a row keyed without an organization, an evidence gap, a user, a scalar,
// moves the installation-wide revision as an unclassified writer does.
//
// The check is made on the encodings, never on the handlers' word, and it costs no encoding of its own:
// the proposer encodes the next state to build its command (a state patch diffs it against the bytes it
// read), and the commit is judged by comparing those two encodings member by member
// (verifyOrgTransition).
//
// The rule applies only to a command proposed as a state patch (Store.StatePatch: every member of the
// control group declared protocol 5), because that is the one mode in which the check is free. A
// replacement keeps the installation-wide bump alone.
//
// Both revisions move. A verified commit of an organization sets AuthorityRevision to its own revision
// as every authority commit does, because the previous release (which declares protocol 5 but does not
// know the per-organization rule) judges a retention command against that scalar alone and has to keep
// refusing a same-organization view older than the commit; it may refuse another organization's view
// too, as it always did. This release does not read the scalar as it is: installationFloor gives the
// revision of the last change that was not a verified commit of one organization, recorded in
// State.OIDC[model.ScopedAuthorityKey] together with the AuthorityRevision it belongs to, and void as
// soon as a binary that does not write it moves AuthorityRevision.
//
// Why not in a replacement: the whole-state replacement makes the encoding of the state only inside
// the payload, so the check cost two more encodings of the whole state per attempt. A deletion Begin
// that has to be proposed several times under saturating intake (every attempt that loses the
// application-index race is judged and proposed again, retryLostProposals) then takes several times as
// long per attempt, loses the race more often, and
// TestBeginIsNotRefusedByLostProposalsFromAnyVoterUnderSaturatingIntake refused 7 to 9 of 12 Begins
// (wave 26, reverted: the cause was found in wave 28 with a CPU profile, 5.69 s of json.Marshal inside
// Transact against 0.27 s without the check, 24 ms of CPU per attempt against 7 ms; the stamp itself,
// with or without the installation-wide bump, left the test at 10-14 s).

type orgScopeKey struct{}

// orgClass says what a per-organization transition may change beside the organization's record.
type orgClass uint8

const (
	classAdmin orgClass = iota
	orgRetention
)

// orgScope is what updateOrgScoped tells replicatedUpdateOnce: the class of the transition and the
// organization it named. A transition that named none cannot be verified and moves the
// installation-wide revision.
type orgScope struct {
	class orgClass
	org   model.ID
	named bool
}

// UpdateOrgAuthority commits fn, an admin command of one organization, moving that organization's
// own authority revision (model.OrgAuthorityKey) instead of the installation-wide AuthorityRevision.
// A retention command of another organization keeps a view that predates this commit: the
// installation-wide scalar made one tenant's admin commands (not rate limited) conflict every other
// tenant's deletion Begin (review F-10.05-2). The exemption is verified, never trusted: the
// encodings of the state before and after fn are compared, and anything but the organization's own
// record, appended audit rows and added commands, or an attestation change, bumps the
// installation-wide AuthorityRevision exactly as an unclassified writer does.
//
// A command whose proposal lost the application-index race to another control commit is judged again
// on a fresh read of the state and proposed again (retryLostProposals), as a retention command is:
// fn re-judges the state it is given, the caller's own view (the expected epoch against the object it
// changes) included, so a save whose view still holds commits, and one whose object changed meanwhile
// is the conflict it always was. Without it an admin save made through any voter was refused with the
// plain `stale` (HTTP 409) whenever any other voter committed anything between its read and its
// proposal, which nothing the caller did explains and repeating the request cured. fn MUST therefore
// be a function of the state alone: it runs once per attempt, and nothing a run decided carries over.
func (s *Store) UpdateOrgAuthority(ctx context.Context, org model.ID, fn func(*State) error) error {
	return s.updateOrgScoped(retryLostProposals(ctx), classAdmin, func(st *State, name func(model.ID)) error {
		name(org)
		return fn(st)
	})
}

// updateOrgRetention commits fn, a retention-class transition of one organization (a hold release, a
// step of the deletion saga, a delete generation), moving that organization's own authority revision
// instead of the installation-wide one when fn changed nothing but the rows the organization owns in
// the retention tables (orgRetentionTables). Anything else bumps the installation-wide
// AuthorityRevision as an unclassified writer does. The organization's own revision is what its own
// retention commands are judged against, so a stale view of the same organization is refused exactly
// as before; another organization's retention commands no longer make it stale (F-10.05-2, the
// residual wave 25 disclosed).
func (s *Store) updateOrgRetention(ctx context.Context, org model.ID, fn func(*State) error) error {
	return s.updateOrgScoped(ctx, orgRetention, func(st *State, name func(model.ID)) error {
		name(org)
		return fn(st)
	})
}

// updateOrgScoped is the one commit of the per-organization classes. fn gets a function to call, with
// the organization it writes, before its first write: an organization is named by the transition
// itself, from the very state it is applied to, so a worker transition of an operation (updateOperation)
// cannot act on another organization than the one that owns the operation (a row of any other
// organization it wrote would be a difference). replicatedUpdateOnce does the rest, after fn: it
// stamps the organization's revision, encodes the state and verifies the commit (settleOrgAuthority).
func (s *Store) updateOrgScoped(ctx context.Context, class orgClass, fn func(st *State, name func(org model.ID)) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.repl == nil {
		return model.Fail(model.Unavailable)
	}
	scope := &orgScope{class: class}
	ctx = context.WithValue(ctx, orgScopeKey{}, scope)
	return s.replicatedUpdate(ctx, false, nil, scopeBooks|scopeCommands, func(st *State) error {
		// One run of the transition: a lost proposal runs it again on a fresh read, and nothing a run
		// decided carries over.
		scope.org, scope.named = model.ID{}, false
		name := func(org model.ID) {
			if !scope.named {
				scope.org, scope.named = org, true
			}
		}
		return guardAttestations(func(st *State) error { return fn(st, name) })(st)
	})
}

// settleOrgAuthority is the part of replicatedUpdateOnce that decides which revisions a per-organization
// commit moves. st is the next state after fn, with its revision and clock set, oldRaw the encoding of
// the state fn started from and priorFloor the installation floor of that state. It stamps the
// organization's revision and ALSO moves the installation-wide AuthorityRevision to the commit (the
// previous release judges a retention command against that scalar alone, so a same-organization view
// older than this commit stays refused on an old leader), recording in model.ScopedAuthorityKey that
// the floor this release judges against did not move. It encodes the state once and verifies the
// commit against oldRaw (verifyOrgCommit). When it holds, the encoding is returned for the proposal to
// use. When it does not, the stamp and the pair are taken back and the commit is an ordinary bump,
// which the caller encodes itself.
func settleOrgAuthority(st *State, oldRaw []byte, scope *orgScope, priorFloor model.Revision) []byte {
	key := scope.org.String()
	afterFn, ok := st.Orgs[key]
	if !ok || !stampOrgAuthority(st, scope.org, st.Revision) {
		st.AuthorityRevision = st.Revision
		return nil
	}
	st.AuthorityRevision = st.Revision
	pair, err := json.Marshal(scopedAuthority{Floor: priorFloor, Global: st.Revision})
	if err == nil {
		prev, had := st.OIDC[model.ScopedAuthorityKey]
		oidc := make(map[string]json.RawMessage, len(st.OIDC)+1)
		maps.Copy(oidc, st.OIDC)
		oidc[model.ScopedAuthorityKey] = pair
		st.OIDC = oidc
		if raw, e := json.Marshal(st); e == nil && verifyOrgCommit(oldRaw, raw, scope.org, scope.class, st.Revision) {
			return raw
		}
		if had {
			st.OIDC[model.ScopedAuthorityKey] = prev
		} else {
			delete(st.OIDC, model.ScopedAuthorityKey)
		}
	}
	st.Orgs[key] = afterFn
	return nil
}

// stampOrgAuthority records revision as the organization's own authority revision. An
// organization the transition did not leave behind has nothing to stamp: the caller bumps the
// installation-wide revision instead (reported false).
func stampOrgAuthority(st *State, org model.ID, revision model.Revision) bool {
	o, ok := st.Orgs[org.String()]
	if !ok {
		return false
	}
	raw, err := json.Marshal(revision)
	if err != nil {
		return false
	}
	settings := make(map[string]json.RawMessage, len(o.Settings)+1)
	maps.Copy(settings, o.Settings)
	settings[model.OrgAuthorityKey] = raw
	o.Settings = settings
	st.Orgs[org.String()] = o
	return true
}

// rowOwner says whether one row of a table belongs to an organization: by its key (the organization's
// id or "org:project...", an organization id being a fixed 32 characters, so no id is the prefix of
// another), or by the Org the record names. A row that does neither is nobody's.
type rowOwner struct {
	key func(key, org string) bool
	// value reads the organization out of the record; valuePrefix, when set, limits it to the keys
	// that begin with it (the rows of the delivery books that are not deliveries name theirs in the key).
	value       func(raw []byte) (model.ID, bool)
	valuePrefix string
}

func (r rowOwner) owns(key string, raw []byte, org model.ID) bool {
	if r.key != nil && r.key(key, org.String()) {
		return true
	}
	if r.value == nil || !strings.HasPrefix(key, r.valuePrefix) {
		return false
	}
	o, ok := r.value(raw)
	return ok && o == org
}

func keyIsOrg(key, org string) bool  { return key == org }
func keyInOrg(key, org string) bool  { return strings.HasPrefix(key, org+":") }
func keyIsOrIn(key, org string) bool { return key == org || strings.HasPrefix(key, org+":") }
func keyPolicy(key, org string) bool { return strings.HasPrefix(key, "policy:"+org+":") }

func recordOrg(raw []byte) (model.ID, bool) {
	var row struct {
		Org model.ID `json:"org"`
	}
	if json.Unmarshal(raw, &row) != nil || row.Org == (model.ID{}) {
		return model.ID{}, false
	}
	return row.Org, true
}

func operationOrg(raw []byte) (model.ID, bool) {
	var row struct {
		Predicate struct {
			Org model.ID `json:"org"`
		} `json:"predicate"`
	}
	if json.Unmarshal(raw, &row) != nil || row.Predicate.Org == (model.ID{}) {
		return model.ID{}, false
	}
	return row.Predicate.Org, true
}

// orgRetentionTables are the tables, by the name of the member in the encoding of the state, in which
// a retention-class transition (BindRetention: fence.go, retention.go, and the erasure of the control
// books a deletion covers, erase*.go) may change the rows its organization owns.
//
// NOT here, so that a transition that writes them keeps the installation-wide bump: EvidenceGaps (keyed
// by a hash; the backup attestation binds the committed fact, so declaring one stays an
// installation-wide authority write), SourceFences and SourceOperations (keyed by a source), Users,
// Sessions, ServerTokens, quotas, reservations, settlements, keys and every scalar of the state.
var orgRetentionTables = map[string]rowOwner{
	// By the Org the record names.
	"Deletions":          {value: operationOrg},
	"Holds":              {value: recordOrg},
	"Sources":            {value: recordOrg},
	"GroupingIssues":     {value: recordOrg},
	"GroupingMigrations": {value: recordOrg},
	"Releases":           {value: recordOrg},
	"RuleOutputs":        {value: recordOrg},
	// By the key.
	"DeleteGenerations": {key: keyIsOrg},
	"RetiredOrgs":       {key: keyIsOrg},
	"RetiredProjects":   {key: keyInOrg},
	"RetentionPolicies": {key: keyIsOrIn},
	"RuleBooks":         {key: keyInOrg},
	"IncidentBooks":     {key: keyInOrg},
	"ConditionBooks":    {key: keyInOrg},
	"IssueBooks":        {key: keyInOrg},
	"JobBooks":          {key: keyInOrg},
	"CutoverBooks":      {key: keyInOrg},
	"SavedViewBooks":    {key: keyInOrg},
	"RuleDefinitions":   {key: keyInOrg},
	"JobDefinitions":    {key: keyInOrg},
	"JobPositions":      {key: keyInOrg},
	// A delivery names its organization, an opaque policy state carries it in its key.
	"DeliveryBooks": {key: keyPolicy, value: recordOrg, valuePrefix: "delivery:"},
}

// verifyOrgTransition says whether the commit that takes the state encoded in oldRaw to newRaw (both
// the encoding of a State, so equal values are equal bytes) changed nothing but what class owns for
// org. Members that did not change are not looked into; a member that changed is judged by its
// own rule, and a member without one fails the check.
func verifyOrgTransition(oldRaw, newRaw []byte, org model.ID, class orgClass) bool {
	return verifyOrg(oldRaw, newRaw, org, class, nil)
}

// verifyOrgCommit is verifyOrgTransition for the commit settleOrgAuthority builds: beside what the
// class owns, AuthorityRevision may have moved to revision and the pair of model.ScopedAuthorityKey
// may have been written, nothing else of OIDC.
func verifyOrgCommit(oldRaw, newRaw []byte, org model.ID, class orgClass, revision model.Revision) bool {
	return verifyOrg(oldRaw, newRaw, org, class, &revision)
}

// onlyKeyChanged says whether the record tables o and n differ in the record key alone.
func onlyKeyChanged(o, n []byte, key string) bool {
	om, ok := recordsOf(o)
	if !ok {
		return false
	}
	nm, ok := recordsOf(n)
	if !ok {
		return false
	}
	delete(om, key)
	delete(nm, key)
	if len(om) != len(nm) {
		return false
	}
	for k, v := range om {
		if w, ok := nm[k]; !ok || !bytes.Equal(v, w) {
			return false
		}
	}
	return true
}

func verifyOrg(oldRaw, newRaw []byte, org model.ID, class orgClass, commit *model.Revision) bool {
	oldM, err := decodeMembers(oldRaw)
	if err != nil {
		return false
	}
	newM, err := decodeMembers(newRaw)
	if err != nil {
		return false
	}
	allowed := func(name string) bool {
		o, n := nonNull(oldM[name]), nonNull(newM[name])
		if bytes.Equal(o, n) {
			return true
		}
		switch name {
		case "Revision", "revision_clock": // stamped by every commit after the transition ran
			return true
		case "authority_revision": // moved by settleOrgAuthority to the commit's own revision
			if commit == nil {
				return false
			}
			want, err := json.Marshal(*commit)
			return err == nil && bytes.Equal(n, want)
		case "OIDC": // only the pair settleOrgAuthority writes
			return commit != nil && onlyKeyChanged(o, n, model.ScopedAuthorityKey)
		case "Audits":
			return appendedRows(o, n)
		case "Commands", "CommandOwners":
			return onlyAdded(o, n)
		case "Orgs":
			return onlyOrg(o, n, org)
		}
		if table, ok := orgRetentionTables[name]; ok && class == orgRetention {
			return rowsOfOrg(o, n, table, org)
		}
		return false
	}
	for name := range oldM {
		if !allowed(name) {
			return false
		}
	}
	for name := range newM {
		if _, seen := oldM[name]; !seen && !allowed(name) {
			return false
		}
	}
	return true
}

// nonNull is raw, or nil for an absent member and a null one: they decode alike.
func nonNull(raw []byte) []byte {
	if bytes.Equal(raw, []byte("null")) {
		return nil
	}
	return raw
}

// appendedRows says whether the array n is the array o with rows added at the end: every row of o
// there byte for byte, none removed.
func appendedRows(o, n []byte) bool {
	if len(n) < 2 || n[0] != '[' || n[len(n)-1] != ']' {
		return false
	}
	if len(o) == 0 || bytes.Equal(o, []byte("[]")) {
		return true
	}
	if len(o) < 2 || o[0] != '[' || o[len(o)-1] != ']' {
		return false
	}
	return len(n) > len(o) && bytes.HasPrefix(n, o[:len(o)-1]) && n[len(o)-1] == ','
}

// recordsOf is the members of the object encoding raw; an absent or null table has none.
func recordsOf(raw []byte) (map[string]json.RawMessage, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	m, err := decodeMembers(raw)
	return m, err == nil
}

// onlyAdded says whether every record of the table o is in n unchanged (n may have more).
func onlyAdded(o, n []byte) bool {
	oldRows, ok := recordsOf(o)
	if !ok {
		return false
	}
	newRows, ok := recordsOf(n)
	if !ok {
		return false
	}
	for k, v := range oldRows {
		if got, found := newRows[k]; !found || !bytes.Equal(got, v) {
			return false
		}
	}
	return true
}

// onlyOrg says whether the organizations o and n differ in the record of org alone.
func onlyOrg(o, n []byte, org model.ID) bool {
	oldRows, ok := recordsOf(o)
	if !ok {
		return false
	}
	newRows, ok := recordsOf(n)
	if !ok {
		return false
	}
	own := org.String()
	for k, v := range oldRows {
		if got, found := newRows[k]; k != own && (!found || !bytes.Equal(got, v)) {
			return false
		}
	}
	for k := range newRows {
		if _, found := oldRows[k]; k != own && !found {
			return false
		}
	}
	return true
}

// rowsOfOrg says whether every record that differs between the tables o and n, added, removed or
// changed, belongs to org on every side it exists on.
func rowsOfOrg(o, n []byte, table rowOwner, org model.ID) bool {
	oldRows, ok := recordsOf(o)
	if !ok {
		return false
	}
	newRows, ok := recordsOf(n)
	if !ok {
		return false
	}
	owned := func(k string, raw json.RawMessage, present bool) bool { return !present || table.owns(k, raw, org) }
	for k, v := range oldRows {
		got, found := newRows[k]
		if found && bytes.Equal(got, v) {
			continue
		}
		if !owned(k, v, true) || !owned(k, got, found) {
			return false
		}
	}
	for k, v := range newRows {
		if _, found := oldRows[k]; !found && !owned(k, v, true) {
			return false
		}
	}
	return true
}

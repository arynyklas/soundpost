// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func openAuthorityStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err = s.EnableSingle(context.Background(), filepath.Join(dir, "raft-control")); err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func revisions(t *testing.T, s *Store) (revision, authority model.Revision) {
	t.Helper()
	st, err := s.localState()
	if err != nil {
		t.Fatal(err)
	}
	return st.Revision, st.AuthorityRevision
}

func sortedKeys[K ~string, V any](m map[K]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, string(k))
	}
	sort.Strings(out)
	return out
}

// The tables ARE the review surface of the AuthorityRevision design: this test pins their exact
// content, so adding or moving a writer is a change a reviewer has to look at in this file too.
func TestAuthorityClassificationTablesAreExact(t *testing.T) {
	if got, want := strings.Join(sortedKeys(nonAuthorityWriters), ","), "ArtifactLedger,AttestControl,CancelAdmission,FinalizeAdmission,PublishArtifact,ReconcileAdmissions,RedactNoop,ReplayIndex,ReserveAdmission,ReserveArtifact,SessionCreate,TransactIssues,TransactJobs"; got != want {
		t.Fatalf("non-authority writers: %s, want %s", got, want)
	}
	if got, want := strings.Join(sortedKeys(nonAuthorityKinds), ","), "ApplyCondition,ApplyIssueEvidence,ApplyRuleEvaluation,ClaimDelivery,CompleteDelivery,IncidentAction,RegisterRelease,UpdateJob"; got != want {
		t.Fatalf("non-authority kinds: %s, want %s", got, want)
	}
	if got, want := strings.Join(sortedKeys(retentionKinds), ","), "BeginFence,CompleteFence,DeleteScope,PolicyChange,RecordEvidenceGap"; got != want {
		t.Fatalf("retention kinds: %s, want %s", got, want)
	}
	for kind := range retentionKinds {
		if _, keeps := nonAuthorityKinds[kind]; keeps {
			t.Fatalf("retention kind %s is also classified non-authority", kind)
		}
	}
	// retentionKinds is exactly what BindRetention registers.
	s, _ := openAuthorityStore(t)
	if err := s.BindRetention(); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(sortedKeys(s.handlers), ","), strings.Join(sortedKeys(retentionKinds), ","); got != want {
		t.Fatalf("BindRetention registers %s, retentionKinds is %s", got, want)
	}
}

// Every CommandKind constant is explicitly classified either way, so a new kind cannot appear
// without an entry. (An unlisted kind still bumps and stays strict: this test makes the omission
// visible instead of silent.)
func TestEveryCommandKindIsClassified(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "types.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []CommandKind
	ast.Inspect(file, func(n ast.Node) bool {
		if vs, ok := n.(*ast.ValueSpec); ok {
			if id, ok := vs.Type.(*ast.Ident); ok && id.Name == "CommandKind" {
				for _, v := range vs.Values {
					if lit, ok := v.(*ast.BasicLit); ok {
						kinds = append(kinds, CommandKind(strings.Trim(lit.Value, `"`)))
					}
				}
			}
		}
		return true
	})
	if len(kinds) < 18 {
		t.Fatalf("parsed %d kinds from types.go", len(kinds))
	}
	authority := map[CommandKind]bool{KindCreateOrg: true, KindGrant: true, KindPolicyChange: true, KindBeginFence: true, KindCompleteFence: true, KindReserveAdmission: true, KindFinalizeAdmission: true, KindDeleteScope: true, KindAudit: true, KindRecordEvidenceGap: true}
	for _, kind := range kinds {
		_, keeps := nonAuthorityKinds[kind]
		if keeps == authority[kind] {
			t.Errorf("kind %s: classification %v does not match the reviewed table (authority=%v)", kind, keeps, authority[kind])
		}
		if transactBumps(string(kind)) == keeps {
			t.Errorf("kind %s: transactBumps disagrees with nonAuthorityKinds", kind)
		}
	}
	if !transactBumps("BrandNewKindNobodyClassified") {
		t.Fatal("an unclassified kind must bump")
	}
}

// Every function of this package that commits a control transition is listed here with its class.
// A new writer fails this test until it is classified by a reviewer. Writers of other packages call
// the exported Update, which always bumps, so they are authority writers by construction.
func TestEveryControlWriterIsClassified(t *testing.T) {
	want := map[string]string{
		// Authority (bump): they change deletions, generations, holds, gaps, audits, keys.
		"RecordBarriers":                "bump",
		"CompleteDeletion":              "bump",
		"FailDeletion":                  "bump",
		"RecordPhysicalCleanup":         "bump",
		"AdvanceDeleteGeneration":       "bump",
		"ImportDeletions":               "bump",
		"settleScrub":                   "bump",
		"RecordEvidenceGap":             "bump",
		"InitializeBearerHashKey":       "bump",
		"RedactRetainedControlCommands": "writerRedactNoop",
		"CancelArtifact":                "bump",
		"healLegacyAuthority":           "bump",
		"Update":                        "bump",
		// Dispatch by Command kind (nonAuthorityKinds).
		"Transact": "by kind",
		// Non-authority (updateAs with a writer on nonAuthorityWriters).
		"ReserveAdmission":    "writerReserveAdmission",
		"FinalizeAdmission":   "writerFinalizeAdmission",
		"CancelAdmission":     "writerCancelAdmission",
		"ReconcileAdmissions": "writerReconcileAdmissions",
		"ReserveArtifact":     "writerReserveArtifact",
		"PublishArtifact":     "writerPublishArtifact",
		"TransactIssues":      "writerTransactIssues",
		"TransactJobs":        "writerTransactJobs",
		"UpdateReplayIndex":   "writerReplayIndex",
		// A login that only adds a session record (10.29): see writerSessionCreate for why it
		// cannot change who may read; credential changes, Logout and Bootstrap keep bumping.
		"UpdateSessionCreate": "writerSessionCreate",
		// Reference / Unreference ledger bookkeeping (10.29): see writerArtifactLedger; the GC
		// fence and the retire transition keep bumping.
		"UpdateArtifactReferences": "writerArtifactLedger",
		// A voter's own attestation record (attest.go): evidence about its files only.
		"syncAttestation": "writerAttestControl",
		// The dispatcher itself.
		"updateAs": "dispatcher",
	}
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v", err)
	}
	got := map[string]string{}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || len(call.Args) < 2 {
					return true
				}
				// Our writers take a context first; bolt's db.Update takes a func.
				if id, ok := call.Args[0].(*ast.Ident); !ok || id.Name != "ctx" {
					return true
				}
				switch sel.Sel.Name {
				case "Update":
					got[fn.Name.Name] = "bump"
				case "updateAs", "updateAsGuarded", "updateAsGuardedChecked":
					if id, ok := call.Args[1].(*ast.Ident); ok {
						got[fn.Name.Name] = id.Name
					} else {
						got[fn.Name.Name] = "?"
					}
				case "update":
					if id, ok := call.Args[1].(*ast.Ident); ok && id.Name == "true" {
						got[fn.Name.Name] = "bump"
					} else {
						got[fn.Name.Name] = "by kind"
					}
				}
				return true
			})
		}
	}
	// updateAs forwards to update(ctx, !keep, ...): the one dispatcher.
	delete(got, "updateAs")
	delete(got, "updateAsGuarded") // the guarded dispatcher: forwards to update/replicatedUpdate
	delete(got, "updateAsGuardedChecked")
	delete(want, "updateAs")
	for name, class := range got {
		if want[name] != class {
			t.Errorf("writer %s is %q, reviewed table says %q", name, class, want[name])
		}
	}
	for name, class := range want {
		if got[name] != class {
			t.Errorf("reviewed writer %s no longer found as %q (got %q)", name, class, got[name])
		}
	}
	// A writer constant used by updateAs must be on the allowlist, and the allowlist holds
	// nothing that no writer uses.
	used := map[writer]bool{}
	for _, class := range got {
		if strings.HasPrefix(class, "writer") {
			used[writer(strings.TrimPrefix(class, "writer"))] = true
		}
	}
	for w := range nonAuthorityWriters {
		if !used[w] {
			t.Errorf("allowlisted writer %s is used by no function", w)
		}
	}
	for w := range used {
		if _, ok := nonAuthorityWriters[w]; !ok {
			t.Errorf("updateAs writer %s is not on the allowlist: it would bump", w)
		}
	}
}

func TestExpectedRevisionRule(t *testing.T) {
	st := func(revision, authority model.Revision) *State {
		return &State{Revision: revision, AuthorityRevision: authority}
	}
	cases := []struct {
		name     string
		st       *State
		kind     CommandKind
		expected model.Revision
		ok       bool
	}{
		{"retention at current", st(100, 10), KindDeleteScope, 100, true},
		{"retention at the authority revision", st(100, 10), KindDeleteScope, 10, true},
		{"retention between", st(100, 10), KindDeleteScope, 55, true},
		{"retention just below the authority revision", st(100, 10), KindDeleteScope, 9, false},
		{"retention above current", st(100, 10), KindDeleteScope, 101, false},
		{"retention far above current", st(100, 10), KindDeleteScope, ^model.Revision(0), false},
		{"policy change between", st(100, 10), KindPolicyChange, 50, true},
		{"begin fence between", st(100, 10), KindBeginFence, 50, true},
		{"complete fence between", st(100, 10), KindCompleteFence, 50, true},
		{"evidence gap between", st(100, 10), KindRecordEvidenceGap, 50, true},
		{"authority equals revision: only current", st(100, 100), KindDeleteScope, 99, false},
		{"authority equals revision: current", st(100, 100), KindDeleteScope, 100, true},
		{"empty state", st(0, 0), KindDeleteScope, 0, true},
		{"legacy state is strict", st(100, 0), KindDeleteScope, 99, false},
		{"legacy state accepts current", st(100, 0), KindDeleteScope, 100, true},
		{"other kind: current", st(100, 10), KindApplyCondition, 100, true},
		{"other kind: between", st(100, 10), KindApplyCondition, 50, false},
		{"other kind: authority revision", st(100, 10), KindApplyCondition, 10, false},
		{"other kind: above", st(100, 10), KindApplyCondition, 101, false},
		{"admission kind: between", st(100, 10), KindReserveAdmission, 50, false},
		{"grant kind: between", st(100, 10), KindGrant, 50, false},
		{"audit: between", st(100, 10), KindAudit, 50, false},
	}
	for _, c := range cases {
		if got := expectedRevisionOK(c.st, string(c.kind), c.expected); got != c.ok {
			t.Errorf("%s: expectedRevisionOK(revision %d, authority %d, %s, %d) = %v, want %v", c.name, c.st.Revision, c.st.AuthorityRevision, c.kind, c.expected, got, c.ok)
		}
	}
}

// A state that never set the field encodes exactly as before: omitempty drops it, so every
// golden snapshot and digest of a state with AuthorityRevision zero is unchanged.
func TestZeroAuthorityRevisionEncodesAsBefore(t *testing.T) {
	raw, err := json.Marshal(State{Installation: model.ID{1}, Revision: 7})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "uthority") {
		t.Fatalf("zero AuthorityRevision is encoded: %s", raw)
	}
	raw, err = json.Marshal(State{Installation: model.ID{1}, Revision: 7, AuthorityRevision: 5})
	if err != nil || !strings.Contains(string(raw), `"authority_revision":"5"`) {
		t.Fatalf("non-zero AuthorityRevision encoded as %s (%v)", raw, err)
	}
	var back State
	if err = json.Unmarshal(raw, &back); err != nil || back.AuthorityRevision != 5 {
		t.Fatalf("round trip: %+v %v", back, err)
	}
}

// bump moves AuthorityRevision to the new Revision after fn ran; fn can neither forge it nor stop it.
func TestUpdateCannotForgeAuthorityRevision(t *testing.T) {
	ctx := context.Background()
	s, _ := openAuthorityStore(t)
	forge := func(to model.Revision) func(*State) error {
		return func(st *State) error { st.AuthorityRevision = to; return nil }
	}
	if err := s.Update(ctx, func(*State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	rev, auth := revisions(t, s)
	if rev != auth || rev == 0 {
		t.Fatalf("an authority update must stamp the new revision: revision %d authority %d", rev, auth)
	}
	// A bumping writer that tries to lower or raise the field still ends at the new revision.
	for _, forged := range []model.Revision{0, 1, 999999} {
		if err := s.Update(ctx, forge(forged)); err != nil {
			t.Fatal(err)
		}
		if rev, auth = revisions(t, s); rev != auth {
			t.Fatalf("a writer forged AuthorityRevision to %d: revision %d authority %d", forged, rev, auth)
		}
	}
	// A non-authority writer that tries to move it leaves the value it found.
	before := auth
	for _, forged := range []model.Revision{0, rev + 100} {
		if err := s.updateAs(ctx, writerReserveAdmission, forge(forged)); err != nil {
			t.Fatal(err)
		}
		if _, auth = revisions(t, s); auth != before {
			t.Fatalf("a non-authority writer moved AuthorityRevision %d -> %d (forged %d)", before, auth, forged)
		}
	}
}

// Classification at the primitive: a writer on the allowlist leaves the field, anything else,
// including a name no one has classified, moves it.
func TestUnclassifiedWriterBumps(t *testing.T) {
	ctx := context.Background()
	s, _ := openAuthorityStore(t)
	if err := s.Update(ctx, func(*State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	_, base := revisions(t, s)
	for w := range nonAuthorityWriters {
		if err := s.updateAs(ctx, w, func(*State) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if rev, auth := revisions(t, s); auth != base || rev <= base {
			t.Fatalf("allowlisted writer %s: revision %d authority %d, base %d", w, rev, auth, base)
		}
	}
	for _, w := range []writer{"", "NewWriterNobodyClassified", "reserveadmission", writerReserveAdmission + " "} {
		if err := s.updateAs(ctx, w, func(*State) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if rev, auth := revisions(t, s); auth != rev {
			t.Fatalf("unclassified writer %q did not bump: revision %d authority %d", w, rev, auth)
		}
	}
}

// A control.db written before the field existed opens with AuthorityRevision zero. Its last
// authority change is unknown, so a retention command is strict (the current revision only)
// until the first authority transition stamps the field; Transact stamps it itself the first
// time such a command conflicts, so a legacy installation does not stay starvable.
func TestLegacyStateWithoutAuthorityRevisionIsStrictAndHeals(t *testing.T) {
	ctx := context.Background()
	s, _ := openAuthorityStore(t)
	for range 3 {
		if err := s.updateAs(ctx, writerReserveAdmission, func(*State) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	// Rewrite the committed state as the pre-change build wrote it: no field.
	if _, err := s.MakeLegacyAuthorityForTest(); err != nil {
		t.Fatal(err)
	}
	rev, auth := revisions(t, s)
	if auth != 0 || rev == 0 {
		t.Fatalf("legacy fixture: revision %d authority %d", rev, auth)
	}
	st := &State{Revision: rev}
	if expectedRevisionOK(st, string(KindDeleteScope), rev-1) || !expectedRevisionOK(st, string(KindDeleteScope), rev) {
		t.Fatal("a legacy state must accept exactly the current revision for a retention command")
	}
	if err := s.healLegacyAuthority(ctx); err != nil {
		t.Fatal(err)
	}
	rev2, auth2 := revisions(t, s)
	if auth2 != rev2 || rev2 != rev+1 {
		t.Fatalf("heal: revision %d -> %d, authority %d", rev, rev2, auth2)
	}
	// Healing is idempotent: nothing further to stamp, nothing committed.
	if err := s.healLegacyAuthority(ctx); err != nil {
		t.Fatal(err)
	}
	if rev3, auth3 := revisions(t, s); rev3 != rev2 || auth3 != auth2 {
		t.Fatalf("second heal committed: revision %d authority %d", rev3, auth3)
	}
}

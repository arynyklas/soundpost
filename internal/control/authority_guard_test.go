// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"soundpost/internal/control"
	"soundpost/internal/model"
)

func (f *fenceFx) indexKeys(st *control.State, n int) {
	o := st.Orgs[f.org.String()]
	if o.Settings == nil {
		o.Settings = map[string]json.RawMessage{}
	}
	for i := range n {
		o.Settings[model.ReplayIndexKeyPrefix+f.project.String()+":"+model.NewID().String()+string(rune('a'+i))] = json.RawMessage(`{"seq":1}`)
	}
	o.Settings[model.ReplayPinKeyPrefix+f.project.String()] = json.RawMessage(`{"pin":1}`)
	st.Orgs[f.org.String()] = o
}

// UpdateReplayIndex keeps AuthorityRevision only for a closure that wrote nothing but replay index
// entries; any other difference bumps as an unclassified writer does.
func TestUpdateReplayIndexBumpsWhenAnythingElseChanged(t *testing.T) {
	cases := []struct {
		name  string
		write func(f *fenceFx, st *control.State)
		bumps bool
	}{
		{"index and pin entries only", func(f *fenceFx, st *control.State) { f.indexKeys(st, 3) }, false},
		{"no change at all", func(f *fenceFx, st *control.State) {}, false},
		{"membership edit", func(f *fenceFx, st *control.State) { st.Orgs[f.org.String()].Members[model.NewID().String()] = true }, true},
		{"policy epoch", func(f *fenceFx, st *control.State) {
			o := st.Orgs[f.org.String()]
			o.Epoch++
			st.Orgs[f.org.String()] = o
		}, true},
		{"non-index setting", func(f *fenceFx, st *control.State) {
			st.Orgs[f.org.String()].Settings["source_policy:"+model.NewID().String()] = json.RawMessage(`{}`)
		}, true},
		{"hold", func(f *fenceFx, st *control.State) {
			id := model.NewID()
			st.Holds = map[string]model.LegalHold{id.String(): {ID: id, Org: f.org, Reason: "r", PlacedBy: model.NewID(), PlacedAt: 1}}
		}, true},
		{"deletion generation and retirement", func(f *fenceFx, st *control.State) {
			st.DeleteGenerations = map[string]uint64{f.org.String(): 9}
			st.RetiredProjects = map[string]model.ID{f.org.String() + ":" + model.NewID().String(): model.NewID()}
		}, true},
		{"source expiry", func(f *fenceFx, st *control.State) {
			src := st.Sources[f.source.String()]
			src.Expires++
			st.Sources[f.source.String()] = src
		}, true},
		{"index key AND another field", func(f *fenceFx, st *control.State) {
			f.indexKeys(st, 2)
			st.Orgs[f.org.String()].Members[model.NewID().String()] = true
		}, true},
		{"index key removed", func(f *fenceFx, st *control.State) {
			f.indexKeys(st, 1)
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFenceFx(t)
			if c.name == "index key removed" {
				if err := f.store.UpdateReplayIndex(f.ctx, func(st *control.State) error { f.indexKeys(st, 1); return nil }); err != nil {
					t.Fatal(err)
				}
				c.write = func(f *fenceFx, st *control.State) {
					for k := range st.Orgs[f.org.String()].Settings {
						if strings.HasPrefix(k, model.ReplayIndexKeyPrefix) {
							delete(st.Orgs[f.org.String()].Settings, k)
						}
					}
				}
			}
			rev0, auth0 := f.revisions()
			if err := f.store.UpdateReplayIndex(f.ctx, func(st *control.State) error { c.write(f, st); return nil }); err != nil {
				t.Fatal(err)
			}
			rev1, auth1 := f.revisions()
			if rev1 != rev0+1 {
				t.Fatalf("revision %d -> %d", rev0, rev1)
			}
			if c.bumps && auth1 != rev1 || !c.bumps && auth1 != auth0 {
				t.Fatalf("bumps=%v: authority %d -> %d at revision %d", c.bumps, auth0, auth1, rev1)
			}
		})
	}
}

// The one caller of UpdateReplayIndex is the replay index step; a second caller is a change a
// reviewer has to look at.
func TestUpdateReplayIndexHasExactlyOneCaller(t *testing.T) {
	var sites []string
	fset := token.NewFileSet()
	for _, root := range []string{"../../internal", "../../tools", "../../cmd"} {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			ast.Inspect(file, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "UpdateReplayIndex" {
					sites = append(sites, filepath.ToSlash(path))
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(sites) != 1 || sites[0] != "../../internal/replays/retention.go" {
		t.Fatalf("UpdateReplayIndex is referenced from %v, want exactly internal/replays/retention.go", sites)
	}
}

func (f *fenceFx) beginCmd(id model.ID, view model.Revision) (control.Result, error) {
	req := control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, End: 100, Reason: "retry", At: model.UnixNano(f.now.UnixNano())}
	req.PhysicalDeadline = req.At + model.UnixNano(time.Hour)
	req.BackupDeadline = req.At + model.UnixNano(time.Hour)
	raw, _ := json.Marshal(req)
	return f.store.Transact(f.ctx, f.adminScope(), control.Command{CommandID: id, ExpectedRevision: view, Kind: string(control.KindDeleteScope), Payload: raw})
}

// A retry of an applied command is answered from a read: no revision, no AuthorityRevision, the
// stored Result byte for byte, even with a stale ExpectedRevision; another binding is NotFound.
func TestRetryOfAppliedCommandSpendsNoRevision(t *testing.T) {
	f := newFenceFx(t)
	view, _ := f.revisions()
	id := model.NewID()
	first, err := f.beginCmd(id, view)
	if err != nil {
		t.Fatal(err)
	}
	f.mustIntake()
	rev, auth := f.revisions()
	for _, expected := range []model.Revision{rev, view, 0, rev + 50} {
		again, err := f.beginCmd(id, expected)
		if err != nil || !reflect.DeepEqual(again, first) {
			t.Fatalf("retry with expected %d: %+v %v, want %+v", expected, again, err, first)
		}
	}
	if rev2, auth2 := f.revisions(); rev2 != rev || auth2 != auth {
		t.Fatalf("retries spent a revision: revision %d -> %d, authority %d -> %d", rev, rev2, auth, auth2)
	}
	// Same id under another kind: another binding.
	raw, _ := json.Marshal(control.PolicyChange{Kind: "hold_place"})
	if _, err = f.store.Transact(f.ctx, f.adminScope(), control.Command{CommandID: id, ExpectedRevision: rev, Kind: string(control.KindPolicyChange), Payload: raw}); code(err) != model.NotFound {
		t.Fatalf("foreign-binding retry: %v, want NotFound", err)
	}
	if rev2, _ := f.revisions(); rev2 != rev {
		t.Fatal("a refused retry spent a revision")
	}
}

// Concurrent first submissions of one CommandID: the effect commits exactly once and every
// caller gets the same Result.
func TestConcurrentDoubleSubmissionCommitsOnce(t *testing.T) {
	f := newFenceFx(t)
	view, _ := f.revisions()
	id := model.NewID()
	scope := f.adminScope()
	req := control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, End: 100, Reason: "race", At: model.UnixNano(f.now.UnixNano())}
	req.PhysicalDeadline = req.At + model.UnixNano(time.Hour)
	req.BackupDeadline = req.At + model.UnixNano(time.Hour)
	raw, _ := json.Marshal(req)
	const n = 8
	results := make([]control.Result, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = f.store.Transact(f.ctx, scope, control.Command{CommandID: id, ExpectedRevision: view, Kind: string(control.KindDeleteScope), Payload: raw})
		}()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil || !reflect.DeepEqual(results[i], results[0]) {
			t.Fatalf("submission %d: %+v %v, first %+v", i, results[i], errs[i], results[0])
		}
	}
	begins := 0
	if err := f.store.View(f.ctx, func(st control.State) error {
		for _, a := range st.Audits {
			if a.Action == "delete.begin" {
				begins++
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if begins != 1 {
		t.Fatalf("%d begin audits for one command", begins)
	}
}

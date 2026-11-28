// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// workerBlobDecodes runs a node with the given extra projects and incidents through the production chain (a rule firing, its condition, the
// incidents, the deliveries) until a pass commits nothing, then returns the whole-blob decodes of the next passes, a step apart, and the
// evaluations they made.
func workerBlobDecodes(t *testing.T, projects, incidents, passes int, step time.Duration) (blobs uint64, evaluated int) {
	t.Helper()
	n := newWorkerNode(t)
	rs := byProject{n.alertRule()}
	for range projects {
		id := model.NewID()
		n.addProject(id)
		rs = append(rs, n.alertRuleIn(id))
	}
	for range incidents {
		n.openIncident()
	}
	cfg := n.conditionConfig(rs[0], &countingSender{}, nil, nil)
	cfg.Rules = rs
	cfg.MaxProjects = projects + 1
	w, err := n.app.NewWorkers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var last model.Revision
	for i := 0; ; i++ {
		n.clock.v.Add(int64(time.Second))
		n.tick(w)
		revision, _ := n.commitsByKind()
		if i > 2 && revision == last {
			break
		}
		if i > 40 {
			t.Fatal("the node never settled")
		}
		last = revision
	}
	before := n.app.Control.DecodeStats()
	evaluated = 0
	for range passes {
		n.clock.v.Add(int64(step))
		evaluated += n.tick(w).Evaluated
	}
	blobs = n.app.Control.DecodeStats().Blobs - before.Blobs
	fmt.Printf("WORKERDECODES projects=%d incidents=%d step=%s passes=%d evaluations=%d blobs=%d\n", projects+1, incidents, step, passes, evaluated, blobs)
	return blobs, evaluated
}

// TestASettledWorkerPassDecodesNoControlBlob: once a project's conditions, incidents and deliveries are settled, its pass reads what it needs
// (the routing, the condition and incident books, the project's policy records, the cutover record) from the decode that shared readers keep
// and from the ledger tables. It does not decode the whole control blob, and the decodes do not grow with the projects or incidents in the state.
func TestASettledWorkerPassDecodesNoControlBlob(t *testing.T) {
	for _, c := range []struct{ projects, incidents int }{{0, 0}, {3, 2}, {9, 12}} {
		if got, _ := workerBlobDecodes(t, c.projects, c.incidents, 5, time.Second); got != 0 {
			t.Fatalf("5 settled passes over %d projects and %d incidents decoded the whole blob %d times, want never", c.projects+1, c.incidents, got)
		}
	}
}

// TestEvaluatingWorkerPassesDecodeNoMoreForMoreState: when every pass evaluates every rule (a minute between passes) the rule commit of an
// evaluation is real work and its transition decodes the blob once. Nothing else of the pass may: the conditions, the incidents and the
// deliveries are read as records, so the decodes beyond that one per evaluation do not grow with the projects, conditions and incidents in the
// state. The slack is one per pass, for the replication group's own deletion-ledger read that runs in the background.
func TestEvaluatingWorkerPassesDecodeNoMoreForMoreState(t *testing.T) {
	const passes = 4
	for _, c := range []struct{ projects, incidents int }{{0, 0}, {9, 12}} {
		blobs, evals := workerBlobDecodes(t, c.projects, c.incidents, passes, time.Minute)
		if evals == 0 {
			t.Fatalf("the passes over %d projects evaluated nothing: the test measures nothing", c.projects+1)
		}
		if blobs > uint64(evals+passes) {
			t.Fatalf("%d projects, %d incidents: %d whole-blob decodes for %d evaluations in %d passes, want at most one per evaluation (+%d background)", c.projects+1, c.incidents, blobs, evals, passes, passes)
		}
	}
}

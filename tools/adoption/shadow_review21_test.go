// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import "testing"

// SH-01 (08.02 review): a producer epoch restart lowers the source sequence, and
// conditions.Reduce still accepts the newer event (a different epoch supersedes by
// event time). The shadow policy twin orders on one monotonic version per entity,
// so it must be told a version that advances for an accepted event; otherwise every
// post-restart event is silently "late" history and the twin reports no decision.
func TestShadowEpochRestartStillDecidesReview21(t *testing.T) {
	fx := newShadowFx(t)
	name := "queue-depth"

	firing := shadowCond(name, 10, "firing", 10)
	restarted := firing
	restarted.Epoch = "epoch-2" // the producer restarted: its sequence begins again
	restarted.Sequence = 1
	restarted.Status = "recovered"
	restarted.AtNS = shadowT0ns + 20*1_000_000_000

	fx.deliver(ShadowAdapterConditions, "d1", shadowCondBody(firing))
	fx.deliver(ShadowAdapterConditions, "d2", shadowCondBody(restarted))

	rep := fx.mustRun()
	if len(rep.Conditions) != 1 || rep.Conditions[0].Phase != "recovered" || rep.Conditions[0].Accepted != 2 {
		t.Fatalf("the lifecycle did not fold the post-restart recovery: %+v", rep.Conditions)
	}
	if rep.Decisions.Kinds["open"] != 1 || rep.Decisions.Kinds["recovery"] != 1 {
		t.Fatalf("the policy twin lost every decision after the epoch restart: %+v", rep.Decisions)
	}
	before := rep.Decisions.Total

	// A late replay of the old epoch (never accepted: its sequence fell behind and
	// its event time is older) still decides nothing.
	late := firing
	late.Sequence = 9
	late.Status = "recovered"
	late.AtNS = shadowT0ns + 5*1_000_000_000
	fx.deliver(ShadowAdapterConditions, "d3", shadowCondBody(late))
	rep = fx.mustRun()
	if rep.Records.DroppedByReason[shadowReasonLateVersion] != 1 {
		t.Fatalf("the old-epoch event must be late history: %+v", rep.Records.DroppedByReason)
	}
	if rep.Decisions.Kinds["recovery"] != 1 || rep.Decisions.Total != before {
		t.Fatalf("late history must produce no decision: %+v", rep.Decisions)
	}
	if !rep.Reconciled {
		t.Fatalf("report: %+v", rep)
	}
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/smokecluster"
)

// layoutRefusal is the typed refusal of the post-contract guards: Unsupported, naming the member.
func layoutRefusal(err error, identity string) bool {
	var fault *model.Fault
	return errors.As(err, &fault) && fault.Code == model.Unsupported && fault.SafeDetail == "layout_incompatible:"+identity
}

// controlReasons is the reasons of the control group (the first group) in voter id's membership report.
func controlReasons(t *testing.T, cluster *smokecluster.Cluster, id uint64) []string {
	t.Helper()
	app := cluster.App(id)
	groups, err := app.MembershipGroups()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var control []string
	for i, s := range appcore.ReportMembership(ctx, groups, app.MembershipLayout()) {
		if i == 0 {
			control = s.Reasons
		} else if len(s.Reasons) != 0 {
			t.Fatalf("voter %d: data group %d carries reasons %v; the layout belongs to the control group only", id, i, s.Reasons)
		}
	}
	return control
}

// (a) Once an organization is contracted, a member whose RUNNING binary does not answer the live layout
// question is not admitted to the membership (voter or learner): the refusal is typed and names it, the
// configuration of every group is unchanged, and a member that answers is admitted. Before the contraction
// nobody is refused (the previous release reads the expanded layout). A learner nothing runs for yet is the
// one exception, and only as a learner: the operator adds it and then starts it (`membership add-learner`,
// start the node, `replace`), so its binary cannot be asked at that time. It joins as a learner, a running
// previous-release binary is still refused, and promoting it to voter asks again.
func TestMembershipRefusesAMemberThatCannotReadTheContractedLayout(t *testing.T) {
	cluster, c := contractCluster(t)
	leader := cluster.App(1)
	org, project := contractOrg(t, leader, c)
	contractSeed(t, leader, org, project, 10)
	ctx := context.Background()
	layout := leader.MembershipLayout()
	absent := replica.Member{ID: 9, Address: "https://127.0.0.1:1", NodeIdentity: "node-9", FailureDomain: "disk-9", Learner: true}
	voter2 := cluster.Members().Nodes[1]
	// A learner whose address is alive (a process accepts the connection) but does not answer the layout question: it
	// closes every connection, as a running binary that does not speak the peer protocol would. Refused as a learner too.
	// The real previous release alive on its peer port is TestMixedBinaryPostContractGuard.
	alive, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer alive.Close()
	go func() {
		for {
			conn, aerr := alive.Accept()
			if aerr != nil {
				return
			}
			conn.Close()
		}
	}()
	previous := replica.Member{ID: 8, Address: "https://" + alive.Addr().String(), NodeIdentity: "node-8", FailureDomain: "disk-8", Learner: true}
	if err := layout.Admit(ctx, absent); err != nil {
		t.Fatalf("before the contraction a member was refused: %v", err)
	}
	if err := layout.AdmitLearner(ctx, absent); err != nil {
		t.Fatalf("before the contraction a learner was refused: %v", err)
	}
	contractNow(t, leader, c, "guard test")
	if err := layout.Admit(ctx, absent); !layoutRefusal(err, "node-9") {
		t.Fatalf("a member that does not answer, after the contraction: %v", err)
	}
	if err := layout.AdmitLearner(ctx, absent); err != nil {
		t.Fatalf("a learner nothing runs for yet, after the contraction, must be added before it is started: %v", err)
	}
	for _, ask := range []func(context.Context, replica.Member) error{layout.Admit, layout.AdmitLearner} {
		if err := ask(ctx, voter2); err != nil {
			t.Fatalf("a member that answers was refused: %v", err)
		}
	}
	cluster.App(2).LimitLiveLayoutForTest(true)
	for _, ask := range []func(context.Context, replica.Member) error{layout.Admit, layout.AdmitLearner} {
		if err := ask(ctx, voter2); !layoutRefusal(err, "node-2") {
			t.Fatalf("a member that answers as the previous release does: %v", err)
		}
		if err := ask(ctx, previous); !layoutRefusal(err, "node-8") {
			t.Fatalf("a running previous-release binary as a learner: %v", err)
		}
	}
	cluster.App(2).LimitLiveLayoutForTest(false)

	// The operator step: a running previous-release binary is refused in every group this node leads, nothing proposed.
	groups, err := leader.MembershipGroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		led := false
		for range 600 {
			if g.Status().Leader == 1 {
				led = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !led {
			t.Fatalf("group %v: node 1 did not lead within 60s (a loaded host elects slowly); the steps below need every group led here", g.Status().Group)
		}
	}
	cluster.App(2).LimitLiveLayoutForTest(true)
	refused := 0
	for i, o := range appcore.StepMembership(ctx, groups, layout, appcore.MembershipChange{Op: appcore.MembershipAddLearner, Member: previous}) {
		switch o.Result {
		case appcore.OutcomeLayoutIncompatible:
			refused++
			if o.Detail != "layout_incompatible:node-8" {
				t.Fatalf("group %d: refusal detail %q does not name the member", i, o.Detail)
			}
		case appcore.OutcomeNotLeader:
		default:
			t.Fatalf("group %d: %q, want a refusal naming the member", i, o.Result)
		}
	}
	cluster.App(2).LimitLiveLayoutForTest(false)
	if refused == 0 {
		t.Fatal("no group refused the running previous-release member")
	}
	for i, s := range leader.ReplicationStatus() {
		if len(s.Members.Nodes) != 3 || s.Members.Revision != 1 {
			t.Fatalf("group %d: the configuration changed: %+v", i, s.Members)
		}
	}

	// A learner nothing runs for is added in every group this node leads (the red of the membership-replace drill:
	// every new installation is contracted from its first write, so every add-learner before the start was refused),
	// and promoting it is refused while nothing runs for it.
	added := 0
	for i, o := range appcore.StepMembership(ctx, groups, layout, appcore.MembershipChange{Op: appcore.MembershipAddLearner, Member: absent}) {
		switch o.Result {
		case appcore.OutcomeApplied:
			added++
		case appcore.OutcomeNotLeader:
		default:
			t.Fatalf("group %d: %q, want the learner nothing runs for added", i, o.Result)
		}
	}
	if added == 0 {
		t.Fatal("no group added the learner nothing runs for yet")
	}
	for i, o := range appcore.StepMembership(ctx, groups, layout, appcore.MembershipChange{Op: appcore.MembershipReplace, Remove: 3, Promote: 9}) {
		switch o.Result {
		case appcore.OutcomeLayoutIncompatible:
			if o.Detail != "layout_incompatible:node-9" {
				t.Fatalf("group %d: promotion refusal detail %q does not name the member", i, o.Detail)
			}
		case appcore.OutcomeNotLeader:
		default:
			t.Fatalf("group %d: promotion of a learner nothing runs for: %q, want a refusal naming it", i, o.Result)
		}
	}
	for i, s := range leader.ReplicationStatus() {
		for _, m := range s.Members.Nodes {
			if m.ID != 9 && m.Learner {
				t.Fatalf("group %d: member %d is a learner", i, m.ID)
			}
			if m.ID == 9 && !m.Learner {
				t.Fatalf("group %d: learner 9 was promoted while nothing runs for it", i)
			}
		}
	}
}

// (c) A voter put back on the previous release after the contraction cannot be changed, so the voters that run the new
// binary say it: the membership report of the control group lists every other control member whose running binary
// does not answer the live layout question as layout_incompatible:<identity>. Nothing is listed before the
// contraction (that member reads the expanded layout), for a member that answers, or for the voter itself.
func TestMembershipReportNamesAControlMemberThatCannotReadTheContractedLayout(t *testing.T) {
	cluster, c := contractCluster(t)
	leader := cluster.App(1)
	org, project := contractOrg(t, leader, c)
	contractSeed(t, leader, org, project, 10)
	cluster.App(2).LimitLiveLayoutForTest(true)
	for _, id := range []uint64{1, 2, 3} {
		if got := controlReasons(t, cluster, id); len(got) != 0 {
			t.Fatalf("voter %d before the contraction: %v", id, got)
		}
	}
	cluster.App(2).LimitLiveLayoutForTest(false)
	contractNow(t, leader, c, "report test")
	for _, id := range []uint64{1, 2, 3} {
		if got := controlReasons(t, cluster, id); len(got) != 0 {
			t.Fatalf("voter %d with every member answering: %v", id, got)
		}
	}
	cluster.App(2).LimitLiveLayoutForTest(true)
	for _, id := range []uint64{1, 3} {
		if got := controlReasons(t, cluster, id); len(got) != 1 || got[0] != "layout_incompatible:node-2" {
			t.Fatalf("voter %d: reasons %v, want [layout_incompatible:node-2]", id, got)
		}
	}
	if got := controlReasons(t, cluster, 2); len(got) != 0 {
		t.Fatalf("the rolled-back voter's own report lists %v: it says nothing about itself", got)
	}
	cluster.App(2).LimitLiveLayoutForTest(false)
	if got := controlReasons(t, cluster, 1); len(got) != 0 {
		t.Fatalf("after the member answers again: %v", got)
	}
}

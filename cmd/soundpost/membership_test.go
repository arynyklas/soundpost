// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

type socketGroup struct {
	status replica.Status
	calls  []replica.Members
}

func (g *socketGroup) Status() replica.Status { return g.status }
func (g *socketGroup) ChangeMembers(_ context.Context, _ model.Revision, next replica.Members) error {
	g.calls = append(g.calls, next)
	g.status.Members, g.status.Revision = next, next.Revision
	return nil
}

func threeVoters() replica.Members {
	return replica.Members{Revision: 1, Nodes: []replica.Member{
		{ID: 1, Address: "https://a.example", NodeIdentity: "n1", FailureDomain: "d1"},
		{ID: 2, Address: "https://b.example", NodeIdentity: "n2", FailureDomain: "d2"},
		{ID: 3, Address: "https://c.example", NodeIdentity: "n3", FailureDomain: "d3"},
	}}
}

// socketDir is a data directory short enough for the membership socket on any TMPDIR: t.TempDir
// adds the test name and a random number, which put the socket path past maxSocketPath for the
// longer test names (the product refuses such a directory, rightly).
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "msk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// A connection the peer check refuses is closed before anything is served: another user's process
// gets no answer. (The directory and socket modes keep other users out first; this is the second
// check, on the connection.)
func TestMembershipSocketDropsAPeerThatIsNotTheOwner(t *testing.T) {
	dir := socketDir(t)
	group := &socketGroup{status: replica.Status{Group: model.NewID(), ID: 1, Leader: 1, Revision: 1, Members: threeVoters()}}
	closer, err := serveMembershipGroups(dir, []appcore.MembershipGroup{group}, nil, func(net.Conn) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	var out bytes.Buffer
	if err = runMembership([]string{"status", "--data-dir", dir}, &out); err == nil || out.Len() != 0 {
		t.Fatalf("a refused peer got an answer: %v %q", err, out.String())
	}
	if len(group.calls) != 0 {
		t.Fatal("a refused peer changed the membership")
	}
}

func TestPeerIsOwnerAdmitsTheSameUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Skip("no unix sockets")
	}
	defer l.Close()
	got := make(chan bool, 1)
	go func() {
		if c, e := l.Accept(); e == nil {
			got <- peerIsOwner(c)
			c.Close()
		}
	}()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !<-got {
		t.Fatal("the user's own process was refused")
	}
}

// The operator command talks to the running node over its private socket: status shows every
// group, a step changes the groups the node leads and the exit status tells whether all are done.
func TestMembershipCommandStepsThroughThePrivateSocket(t *testing.T) {
	dir := socketDir(t)
	led := &socketGroup{status: replica.Status{Group: model.NewID(), ID: 1, Leader: 1, Revision: 1, Members: threeVoters()}}
	other := &socketGroup{status: replica.Status{Group: model.NewID(), ID: 1, Leader: 2, Revision: 1, Members: threeVoters()}}
	closer, err := serveMembershipGroups(dir, []appcore.MembershipGroup{led, other}, nil, peerIsOwner)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	info, err := os.Stat(filepath.Join(dir, membershipSocket))
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("membership socket = %v, %v; want no group/other access", info, err)
	}

	var out bytes.Buffer
	if err = runMembership([]string{"status", "--data-dir", dir}, &out); err != nil || strings.Count(out.String(), "\n") != 2 || !strings.Contains(out.String(), "1:voter:n1") {
		t.Fatalf("status = %v\n%s", err, out.String())
	}

	out.Reset()
	add := []string{"add-learner", "--data-dir", dir, "--id", "4", "--address", "https://d.example", "--identity", "n4", "--failure-domain", "d4"}
	err = runMembership(add, &out)
	if !errors.Is(err, errMembershipIncomplete) || !strings.Contains(out.String(), "not_leader (led by node 2") || len(led.calls) != 1 || len(other.calls) != 0 {
		t.Fatalf("add-learner on the node that leads one of two groups = %v, led %d other %d\n%s", err, len(led.calls), len(other.calls), out.String())
	}
	if len(led.calls[0].Nodes) != 4 || !led.calls[0].Nodes[3].Learner {
		t.Fatalf("proposed %+v", led.calls[0])
	}
	// The other node runs the same step for its group; this node's group is already done.
	other.status.Leader = 1
	out.Reset()
	if err = runMembership(add, &out); err != nil || len(led.calls) != 1 || len(other.calls) != 1 {
		t.Fatalf("second run = %v, led %d other %d\n%s", err, len(led.calls), len(other.calls), out.String())
	}

	out.Reset()
	if err = runMembership([]string{"replace", "--data-dir", dir, "--remove", "2", "--promote", "4"}, &out); err != nil || !strings.Contains(out.String(), "applied=2") {
		t.Fatalf("replace = %v\n%s", err, out.String())
	}
	for _, g := range []*socketGroup{led, other} {
		last := g.status.Members
		if len(last.Nodes) != 3 || last.Revision != 3 {
			t.Fatalf("final members %+v", last)
		}
		for _, m := range last.Nodes {
			if m.ID == 2 || m.Learner {
				t.Fatalf("final members %+v", last)
			}
		}
	}
	if err = runMembership([]string{"nonsense", "--data-dir", dir}, &out); !errors.Is(err, errMembershipUsage) {
		t.Fatalf("unknown operation = %v", err)
	}
	if err = runMembership([]string{"status", "--data-dir", t.TempDir()}, &out); err == nil {
		t.Fatal("a directory without a running node answered")
	}
}

// socketLayout is a live layout check that refuses node 4 and reports node n2 as incompatible.
type socketLayout struct{ control model.ID }

func (l socketLayout) Admit(_ context.Context, m replica.Member) error {
	if m.ID == 4 {
		return &model.Fault{Code: model.Unsupported, SafeDetail: "layout_incompatible:" + m.NodeIdentity}
	}
	return nil
}
func (l socketLayout) AdmitLearner(ctx context.Context, m replica.Member) error {
	return l.Admit(ctx, m)
}
func (l socketLayout) Incompatible(context.Context) (model.ID, []string) {
	return l.control, []string{"layout_incompatible:n2"}
}

// After the contraction of the indexes the operator sees, through the private socket, which control member cannot read the
// layout (status), and a step that would add one is refused naming it (exit 1, the group untouched).
func TestMembershipCommandReportsAndRefusesMembersThatCannotReadTheContractedLayout(t *testing.T) {
	dir := socketDir(t)
	control := &socketGroup{status: replica.Status{Group: model.NewID(), ID: 1, Leader: 1, Revision: 1, Members: threeVoters()}}
	data := &socketGroup{status: replica.Status{Group: model.NewID(), ID: 1, Leader: 1, Revision: 1, Members: threeVoters()}}
	closer, err := serveMembershipGroups(dir, []appcore.MembershipGroup{control, data}, socketLayout{control: control.status.Group}, peerIsOwner)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	var out bytes.Buffer
	if err = runMembership([]string{"status", "--data-dir", dir}, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], " reasons=layout_incompatible:n2") || strings.Contains(lines[1], "reasons=") {
		t.Fatalf("status:\n%s", out.String())
	}
	out.Reset()
	add := []string{"add-learner", "--data-dir", dir, "--id", "4", "--address", "https://d.example", "--identity", "n4", "--failure-domain", "d4"}
	if err = runMembership(add, &out); !errors.Is(err, errMembershipIncomplete) || len(control.calls)+len(data.calls) != 0 {
		t.Fatalf("add-learner of a member that cannot read the layout = %v, proposals %d\n%s", err, len(control.calls)+len(data.calls), out.String())
	}
	if !strings.Contains(out.String(), "layout_incompatible:n4") || !strings.Contains(out.String(), "layout_incompatible=2") {
		t.Fatalf("the refusal does not name the member:\n%s", out.String())
	}
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/backup"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// appendVia admits one metric row through a voter of a running cluster exactly like ingest:
// reserve (control), append (data), remember the ACK. The live fixture's own application is
// the installation the cluster continues, so the source credential is the one it issued.
func (l *live) appendVia(app *appcore.App, at int64, name string) ack {
	l.t.Helper()
	credential, err := app.Auth.AuthenticateSource(l.ctx, l.sourceRaw, "", false) // a credential belongs to the service that authenticated it
	if err != nil {
		l.t.Fatal("source credential:", err)
	}
	src, err := app.Auth.SourceAuthority(l.ctx, credential, true)
	if err != nil {
		l.t.Fatal("source authority:", err)
	}
	v := model.FloatBits(0x3ff0000000000000)
	b := model.Batch{Version: 1, Project: l.desc.Project, Source: l.desc.Source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(at), Resource: model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &v, Type: "counter", Unit: "1"}}}}}
	slot, _ := model.OwnerSlot(l.desc.Org, b.Project, b.Source, b.Producer, b.Records[0])
	b.RouteSlot = slot
	n := l.normalizeWith(app, credential, b)
	scope, err := app.Auth.SourceScope(l.ctx, credential, false)
	if err != nil {
		l.t.Fatal("source scope:", err)
	}
	if n.Reservation, err = app.Control.ReserveAdmission(l.ctx, scope, n); err != nil {
		l.t.Fatal("reserve:", err)
	}
	receipt, err := app.Storage.Append(l.ctx, scope, n)
	if err != nil {
		l.t.Fatal("append:", err)
	}
	a := ack{batch: b, at: at, receipt: receipt, bytes: uint64(n.Reservation.Bytes)}
	l.acked = append(l.acked, a)
	return a
}

// clusterBackup takes a backup through the voter app of a running cluster: its own control view,
// its own 64 data groups and its own replication status.
func (l *live) clusterBackup(app *appcore.App, attempts string) (backup.BackupManifest, error) {
	l.t.Helper()
	owner, err := app.Auth.Authenticate(l.ctx, l.ownerS.Token)
	if err != nil {
		l.t.Fatal(err)
	}
	plane := backup.EngineDataPlane(app.Storage)
	svc, err := backup.New(backup.Config{Control: app.Control, Data: plane, Processed: backup.AppliedProcessed(plane), Authority: l.authority, Authorizer: app.Auth, Keys: l.keys, DataKEK: "data-kek", SecretKEK: "secret-kek", Attempts: backup.DirAttempts(attempts), Replication: app.ReplicationStatus, Clock: time.Now})
	if err != nil {
		l.t.Fatal(err)
	}
	scope, err := app.Auth.InstanceScope(l.ctx, owner, "cluster backup")
	if err != nil {
		l.t.Fatal(err)
	}
	return svc.Run(l.ctx, scope, l.dest)
}

func identities(app *appcore.App) []string {
	var out []string
	for _, n := range app.ReplicationStatus()[0].Members.Nodes {
		out = append(out, n.NodeIdentity)
	}
	return out
}

// A backup of a running three-voter cluster restores into a new three-voter cluster with fresh
// node identities: the restored cluster serves the pre-backup data (the installation's first
// writes and the ones the cluster admitted), loses what was admitted after the backup, is a
// working replicated cluster (a control write on a follower commits), and no node of the old
// cluster is a member of it: the identities differ and the old nodes' certificates (the same
// certificate authority) are refused by every voter of the restored cluster.
func TestClusterBackupRestoresIntoAFreshThreeVoterCluster(t *testing.T) {
	quietRaft()
	l := newLive(t)
	l.append(100, "seed_a")
	l.append(200, "seed_b")
	l.reconcile()
	work := t.TempDir()
	seed := filepath.Join(work, "source.seed")
	if err := l.app.WriteClusterSeed(seed); err != nil {
		t.Fatal(err)
	}
	ca := newTestCA(t, work)
	src := newRig(t, filepath.Join(work, "src"), seed, ca, "src")
	if err := src.open(voters...); err != nil {
		t.Fatal(err)
	}
	// Writes the three voters admitted themselves: the backup holds history that exists nowhere
	// but in the cluster's replicated groups.
	n1 := src.app(1)
	l.appendVia(n1, 300, "era_a")
	l.appendVia(n1, 400, "era_b")
	l.appendVia(n1, 500, "era_c")
	if err := n1.Control.ReconcileAdmissions(l.ctx); err != nil {
		t.Fatal(err)
	}

	// The backup is one voter's quorum-verified cut, taken at a follower.
	m, err := l.clusterBackup(src.app(2), filepath.Join(work, "attempts"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Topology == nil || m.Topology.Voters != 3 || m.Topology.SourceNode != 2 || m.Topology.MembersRevision != 1 {
		t.Fatalf("the manifest does not record the three-voter source: %+v", m.Topology)
	}
	if got, want := m.Topology.Retired(), []string{"src-1", "src-2", "src-3"}; !slices.Equal(got, want) {
		t.Fatalf("source identities %v, want %v", got, want)
	}
	lost := l.appendVia(n1, 600, "after_backup")

	// Restore builds a single-voter root; it seeds nothing before its activation completed.
	root := l.newRoot()
	if _, err = l.restoreTo(root, m, l.authority); err != nil {
		t.Fatal(err)
	}
	r := l.openRestored(root)
	early := filepath.Join(work, "early.seed")
	if err = r.app.WriteClusterSeed(early); code(err) != model.Conflict {
		t.Fatalf("a restored root that was not activated wrote a cluster seed: %v", err)
	}
	if fileExists(early) {
		t.Fatal("an unactivated restored root left a seed file behind")
	}
	if _, err = r.activate(l.authority); err != nil {
		t.Fatal(err)
	}
	r.reader() // the owner is explicitly reauthorized: everything else stays quarantined
	restoredSeed := filepath.Join(work, "restored.seed")
	if err = r.app.WriteClusterSeed(restoredSeed); err != nil {
		t.Fatal(err)
	}
	var seeded appcore.ClusterSeed
	if err = json.Unmarshal(mustRead(t, restoredSeed), &seeded); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(seeded.Retired, []string{"src-1", "src-2", "src-3"}) {
		t.Fatalf("the seed does not retire the old cluster's identities: %v", seeded.Retired)
	}

	// The old identities cannot be reused: a membership naming one is refused before anything opens.
	reuse := newRig(t, filepath.Join(work, "reuse"), restoredSeed, ca, "src")
	if err = reuse.open(1); code(err) != model.Invalid {
		t.Fatalf("a restored cluster named a retired identity: %v", err)
	}

	dst := newRig(t, filepath.Join(work, "dr"), restoredSeed, ca, "dr")
	if err = dst.open(voters...); err != nil {
		t.Fatal(err)
	}

	want := map[int64]bool{100: true, 200: true, 300: true, 400: true, 500: true}
	for _, id := range voters {
		app := dst.app(id)
		statuses := app.ReplicationStatus()
		if len(statuses) != 65 {
			t.Fatalf("node %d serves %d groups, want the control group and 64 data groups", id, len(statuses))
		}
		for _, st := range statuses {
			if len(st.Members.Nodes) != 3 || st.Members.Revision != 1 {
				t.Fatalf("node %d group %s membership %+v", id, st.Group, st.Members)
			}
			for _, n := range st.Members.Nodes {
				if slices.Contains(m.Topology.Retired(), n.NodeIdentity) || n.NodeIdentity != dst.identity(n.ID) {
					t.Fatalf("node %d group %s names identity %q: not a fresh identity of the restored cluster", id, st.Group, n.NodeIdentity)
				}
			}
		}
		if err = app.Storage.RestoreReady(); err != nil {
			t.Fatalf("node %d admits nothing: %v", id, err)
		}
		session, err := app.Auth.Login(l.ctx, "owner@example.test", ownerPassword, "")
		if err != nil {
			t.Fatalf("node %d: the reauthorized owner cannot log in (a replicated control write): %v", id, err)
		}
		credential, err := app.Auth.Authenticate(l.ctx, session.Token)
		if err != nil {
			t.Fatal(err)
		}
		scope, err := app.Auth.Authorize(l.ctx, credential, l.org, []model.ID{l.project}, auth.Read)
		if err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(30 * time.Second)
		var rows map[int64]bool
		for {
			if rows, err = l.rows(app, scope); err == nil && len(rows) == len(want) || time.Now().After(deadline) {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("node %d scan: %v", id, err)
		}
		for at := range want {
			if !rows[at] {
				t.Errorf("node %d of the restored cluster lost the row observed at %d", id, at)
			}
		}
		if rows[lost.at] {
			t.Errorf("node %d serves the row admitted after the backup's cut", id)
		}
	}

	// No node of the old cluster is a member of the restored cluster: every voter refuses the
	// old nodes' certificates (the same CA) and answers its own members.
	control := dst.app(1).ReplicationStatus()[0].Group.String()
	for _, id := range voters {
		for _, old := range voters {
			if status := peerStatus(t, dst.targets[id], control, src.certs[old][0], src.certs[old][1]); status != 403 {
				t.Errorf("restored voter %d answered old-cluster node %d with HTTP %d, want 403", id, old, status)
			}
		}
		if status := peerStatus(t, dst.targets[id], control, dst.certs[(id%3)+1][0], dst.certs[(id%3)+1][1]); status != 200 {
			t.Errorf("restored voter %d refused a member of its own cluster: HTTP %d", id, status)
		}
	}
	if slices.Equal(identities(src.app(1)), identities(dst.app(1))) {
		t.Fatal("the restored cluster is the old cluster's membership")
	}
}

// A backup taken without the groups agreeing on one membership names a membership that never
// existed, so it is refused: a group that failed, a learner mid-replacement, a group whose member
// list differs, a node that does not serve the 65 groups.
func TestTopologyOfNamesOnlyAMembershipEveryGroupAgreesOn(t *testing.T) {
	members := func() replica.Members {
		return replica.Members{Revision: 1, Nodes: []replica.Member{
			{ID: 1, Address: "https://a.invalid", NodeIdentity: "n1", FailureDomain: "d1"},
			{ID: 2, Address: "https://b.invalid", NodeIdentity: "n2", FailureDomain: "d2"},
			{ID: 3, Address: "https://c.invalid", NodeIdentity: "n3", FailureDomain: "d3"},
		}}
	}
	statuses := func() []replica.Status {
		out := make([]replica.Status, 65)
		for i := range out {
			out[i] = replica.Status{ID: 2, Members: members()}
		}
		return out
	}
	topology, err := backup.TopologyOf(statuses())
	if err != nil || topology.Voters != 3 || topology.SourceNode != 2 || !slices.Equal(topology.Retired(), []string{"n1", "n2", "n3"}) {
		t.Fatalf("agreeing groups: %+v %v", topology, err)
	}
	for name, mutate := range map[string]func([]replica.Status) []replica.Status{
		"a failed group":                   func(s []replica.Status) []replica.Status { s[40].Failed = true; return s },
		"a data group with another member": func(s []replica.Status) []replica.Status { s[7].Members.Nodes[2].NodeIdentity = "n9"; return s },
		"a data group at another revision": func(s []replica.Status) []replica.Status { s[7].Members.Revision = 2; return s },
		"a learner in flight": func(s []replica.Status) []replica.Status {
			for i := range s {
				s[i].Members.Nodes = append(s[i].Members.Nodes, replica.Member{ID: 4, Address: "https://d.invalid", NodeIdentity: "n4", FailureDomain: "d4", Learner: true})
			}
			return s
		},
		"a group of another node":         func(s []replica.Status) []replica.Status { s[64].ID = 3; return s },
		"a node that serves fewer groups": func(s []replica.Status) []replica.Status { return s[:64] },
	} {
		if _, err = backup.TopologyOf(mutate(statuses())); code(err) != model.Unavailable {
			t.Errorf("%s: %v, want unavailable", name, err)
		}
	}
}

// The topology a backup records is covered by the manifest's MAC: naming other node identities
// (which would let a restore into a new cluster retire the wrong ones) does not authenticate.
func TestManifestTopologyIsBoundByTheMAC(t *testing.T) {
	l := newLive(t)
	l.append(100, "row")
	l.reconcile()
	m, err := l.clusterBackup(l.app, filepath.Join(t.TempDir(), "attempts"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Topology == nil || m.Topology.Voters != 1 || m.Topology.SourceNode != 1 || !slices.Equal(m.Topology.Retired(), []string{"single"}) {
		t.Fatalf("a single-voter backup records %+v", m.Topology)
	}
	raw := readDest(t, l.dest, backup.ManifestName(m.ID))
	forged := bytes.Replace(raw, []byte(`"identity":"single"`), []byte(`"identity":"intruder"`), 1)
	if bytes.Equal(raw, forged) {
		t.Fatal("fixture: the manifest records no topology identity to alter")
	}
	copyDir := filepath.Join(t.TempDir(), "copy")
	copyTree(t, l.destDir, copyDir)
	if err = os.WriteFile(filepath.Join(copyDir, filepath.FromSlash(backup.ManifestName(m.ID))), forged, 0o600); err != nil {
		t.Fatal(err)
	}
	altered, err := backup.NewLocalDestination(copyDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = backup.LoadManifest(l.ctx, altered, m.ID, l.keys); code(err) != model.Forbidden {
		t.Fatalf("a manifest whose topology was edited authenticated: %v", err)
	}
	if _, err = backup.LoadManifest(l.ctx, l.dest, m.ID, l.keys); err != nil {
		t.Fatal(err)
	}
}

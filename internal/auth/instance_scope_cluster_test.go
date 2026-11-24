// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/smokecluster"
)

const (
	scopeEmail, scopeSecret = "owner@instance-scope.invalid", "instance scope cluster password 2026"
	// scopeCaller is the voter a one-shot `soundpost backup create` runs on; scopeRival another voter. Node 1
	// is the initial leader of the cluster, so both are followers and their proposals travel alike.
	scopeCaller, scopeRival = 3, 2
)

// scopeCluster boots a real three-voter cluster over mTLS peer listeners (appcore voters, nothing
// injected) from an installation that has one bootstrapped administrator.
func scopeCluster(t *testing.T) *smokecluster.Cluster {
	t.Helper()
	work := t.TempDir()
	live := filepath.Join(work, "live")
	if err := os.MkdirAll(live, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	app, err := appcore.Open(live)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.Auth.Bootstrap(ctx, bootstrap, scopeEmail, scopeSecret); err != nil {
		t.Fatal(err)
	}
	seed := filepath.Join(work, "cluster.seed")
	if err = app.WriteClusterSeed(seed); err != nil {
		t.Fatal(err)
	}
	if err = app.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(work, "cluster"), 0o700); err != nil {
		t.Fatal(err)
	}
	cluster, err := smokecluster.New(filepath.Join(work, "cluster"), seed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cluster.Close)
	if err = cluster.Open(smokecluster.Voters...); err != nil {
		t.Fatal(err)
	}
	// The record writers of the service commit the scoped delta once every voter declared the protocol of
	// it (declarations take a few seconds after the voters start): the tests that count on that wait for it.
	deadline := time.Now().Add(2 * time.Minute)
	for _, node := range smokecluster.Voters {
		for !cluster.App(node).Control.RecordScope() {
			if time.Now().After(deadline) {
				t.Fatalf("voter %d does not propose the scoped delta two minutes after the cluster started", node)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return cluster
}

// The instance scope of a one-shot command on a voter of a real three-voter cluster is never answered
// `stale` for an index race: another voter commits control writes without pause (the original form of this
// test: a loop of real commits with no think time, which is what admission rounds are at gate load), and
// the scope's own control write reads the state, computes and proposes through the leader. This is
// `soundpost backup create --mode distributed` on a node that has just joined its cluster (the
// deletion-cluster smoke answered `soundpost backup failed: stale` 2 s into the command, in the lag-1 run
// that takes the older backup through the stopped initial leader). Nothing is injected: three appcore
// voters over real mTLS peer listeners.
//
// A writer that commits again the moment it has committed used to leave the scope behind for as long as it
// kept going (under the race detector the scope won 3 % of its attempts and 5 of 300 scopes spent the whole
// 15 s budget, docs/operations/distributed.md): the scope's write named the revision it read, the loser
// learns of the winner's commit through its own refusal, and the winner has read the new revision when its
// commit returns. The write of the scope now names the records it read (the administrator's user and
// session) and is judged against those alone (D102, control/scoped_delta.go), so the competitor's commits,
// which touch neither, do not make it stale.
func TestInstanceScopeOnAVoterIsNotAnsweredStaleByCompetingControlWrites(t *testing.T) {
	ctx := context.Background()
	cluster := scopeCluster(t)
	session, err := cluster.App(scopeCaller).Auth.Login(ctx, scopeEmail, scopeSecret, "")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := cluster.App(scopeCaller).Auth.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var competing sync.WaitGroup
	var commits atomic.Int64
	var rivalErr atomic.Value // the last error of the competing voter's write
	established := make(chan struct{})
	var establish sync.Once
	competing.Add(1)
	go func() {
		defer competing.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := cluster.App(scopeRival).Control.Update(ctx, func(*model.ControlState) error { return nil }); err == nil {
				commits.Add(1)
				establish.Do(func() { close(established) })
			} else {
				rivalErr.Store(err)
			}
		}
	}()
	finish := func() {
		close(stop)
		competing.Wait()
	}
	// The scopes are measured against a writer that is already committing: a voter that has just joined
	// can need seconds for its first commit when the machine is busy.
	select {
	case <-established:
	case <-time.After(time.Minute):
		finish()
		t.Fatalf("the competing voter committed nothing in a minute (last error %v): the test measured no race", rivalErr.Load())
	}
	const scopes = 60
	refused := 0
	repeatsBefore := auth.LoginStaleRetries()
	commitsBefore := commits.Load()
	deltasBefore, _ := cluster.App(scopeCaller).Control.ScopedDeltaStats()
	for i := range scopes {
		scopeStart := time.Now()
		before := auth.LoginStaleRetries()
		if _, err = cluster.App(scopeCaller).Auth.InstanceScope(ctx, credential, "a backup of the cluster"); err != nil {
			refused++
			t.Logf("scope %d on node %d: %v after %s and %d repeats", i+1, scopeCaller, err, time.Since(scopeStart), auth.LoginStaleRetries()-before)
		}
	}
	repeats := auth.LoginStaleRetries() - repeatsBefore
	during := commits.Load() - commitsBefore
	deltas, _ := cluster.App(scopeCaller).Control.ScopedDeltaStats()
	finish()
	t.Logf("%d scopes: %d refused, %d repeats after a stale answer, %d competing commits while they ran, %d scoped deltas", scopes, refused, repeats, during, deltas-deltasBefore)
	if refused != 0 {
		t.Fatalf("%d of %d instance scopes were refused while node %d committed %d control writes: the scope's write lost the race for its index and was answered instead of repeated", refused, scopes, scopeRival, commits.Load())
	}
	if during == 0 {
		t.Fatalf("the competing voter committed nothing while the %d scopes ran: the test measured no race", scopes)
	}
	if deltas-deltasBefore < scopes {
		t.Fatalf("%d scopes were granted by %d scoped deltas: the record-scoped form was not the one that committed", scopes, deltas-deltasBefore)
	}
}

// racingStore is the control store of the caller's voter with a competing writer injected into every
// write: after the write has read the state and before it proposes, another voter commits a control write,
// so a proposal that names the revision it read names one that is taken and the leader refuses it as stale.
// What the competitor does is counted, not timed, so the outcome does not depend on how fast the machine
// is, and it needs no race detector: this is the lost race made certain, for every write that is judged
// against the whole revision. It injects into the three writes of the service that a lost race matters to
// (the whole-state Update and the two record writers) and says it shares their commit with the store, so
// that the service calls the record writers, which then run their transition after the read like Update.
type racingStore struct {
	*control.Store
	rival   *control.Store
	rivals  func(ctx context.Context, rival *control.Store) error // the competing commit; nil: an empty control commit
	armed   atomic.Bool
	writes  atomic.Int64  // writes attempted since armed or reset
	spoiled atomic.Int64  // competing commits that went through
	delay   time.Duration // the round trip of an attempt made slow: waited inside every write
}

// inject is fn preceded by what the competitor does inside the write.
func (s *racingStore) inject(ctx context.Context, fn func(*model.ControlState) error) func(*model.ControlState) error {
	return func(st *model.ControlState) error {
		time.Sleep(s.delay)
		rival := s.rivals
		if rival == nil {
			rival = func(ctx context.Context, rival *control.Store) error {
				return rival.Update(ctx, func(*model.ControlState) error { return nil })
			}
		}
		if rival(ctx, s.rival) == nil {
			s.spoiled.Add(1)
		}
		return fn(st)
	}
}

func (s *racingStore) Update(ctx context.Context, fn func(*model.ControlState) error) error {
	if !s.armed.Load() {
		return s.Store.Update(ctx, fn)
	}
	s.writes.Add(1)
	return s.Store.Update(ctx, s.inject(ctx, fn))
}

func (s *racingStore) UpdateAuditRecords(ctx context.Context, reads model.ControlRecords, fn func(*model.ControlState) error) error {
	if !s.armed.Load() {
		return s.Store.UpdateAuditRecords(ctx, reads, fn)
	}
	s.writes.Add(1)
	return s.Store.UpdateAuditRecords(ctx, reads, s.inject(ctx, fn))
}

func (s *racingStore) UpdateSessionCreateRecords(ctx context.Context, reads model.ControlRecords, fn func(*model.ControlState) error) error {
	if !s.armed.Load() {
		return s.Store.UpdateSessionCreateRecords(ctx, reads, fn)
	}
	s.writes.Add(1)
	return s.Store.UpdateSessionCreateRecords(ctx, reads, s.inject(ctx, fn))
}

// SharesUpdateOf says the service may use the record writers of this store: it commits them as the store does.
func (s *racingStore) SharesUpdateOf(c auth.ControlStore) bool { return c == auth.ControlStore(s) }

// raceFixture is a scope service over a racingStore on the caller's voter, with a fresh credential of the
// administrator, and the racing store armed only afterwards (the login is no scope).
func raceFixture(t *testing.T) (*auth.Service, *racingStore, auth.Credential) {
	t.Helper()
	ctx := context.Background()
	cluster := scopeCluster(t)
	store := &racingStore{Store: cluster.App(scopeCaller).Control, rival: cluster.App(scopeRival).Control}
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	session, err := service.Login(ctx, scopeEmail, scopeSecret, "")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := service.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	store.armed.Store(true)
	return service, store, credential
}

// A competing writer that commits inside EVERY attempt of the scope (the deterministic form of a writer
// that never idles) cannot starve it: the write of the scope names the records it read, the competitor's
// commit touches none of them, and the first attempt is granted. Before D102 the write named the revision
// it read, every attempt lost to the competitor that had committed inside it, and the scope ended with the
// typed `stale` at its budget (the budget is shortened here, 4 s: the value of 15 s is the same code
// path). Every attempt is made 150 ms slow, as a round trip is on a loaded machine. The attempts are
// bounded by 12, and each scope is granted by a scoped delta.
func TestInstanceScopeIsGrantedAgainstAWriterThatCommitsInsideEveryAttempt(t *testing.T) {
	service, store, credential := raceFixture(t)
	store.delay = 150 * time.Millisecond
	service.SetLoginStaleBudget(4 * time.Second)
	const scopes = 20
	deltas, _ := store.ScopedDeltaStats()
	for i := range scopes {
		store.writes.Store(0)
		start := time.Now()
		scope, err := service.InstanceScope(context.Background(), credential, "a backup of the cluster")
		if err != nil {
			t.Fatalf("scope %d answered %v after %s and %d write attempts, %d of them spoiled by a competing commit", i+1, err, time.Since(start), store.writes.Load(), store.spoiled.Load())
		}
		if got := store.writes.Load(); got > 12 {
			t.Fatalf("scope %d needed %d write attempts, want at most 12", i+1, got)
		}
		if err = service.RevalidateInstance(context.Background(), scope); err != nil {
			t.Fatalf("the scope the call returned does not revalidate: %v", err)
		}
	}
	if store.spoiled.Load() == 0 {
		t.Fatal("no competing commit went through: the test measured no race")
	}
	if after, _ := store.ScopedDeltaStats(); after-deltas < scopes {
		t.Fatalf("%d scopes were granted by %d scoped deltas: the record-scoped form was not the one that committed", scopes, after-deltas)
	}
}

// The same for a login: a competing writer inside every attempt does not make it stale, and each login is
// committed by a scoped delta within the original bound of attempts.
func TestLoginIsGrantedAgainstAWriterThatCommitsInsideEveryAttempt(t *testing.T) {
	service, store, _ := raceFixture(t)
	store.delay = 150 * time.Millisecond
	service.SetLoginStaleBudget(4 * time.Second)
	const logins = 20
	deltas, _ := store.ScopedDeltaStats()
	for i := range logins {
		store.writes.Store(0)
		start := time.Now()
		session, err := service.Login(context.Background(), scopeEmail, scopeSecret, "")
		if err != nil {
			t.Fatalf("login %d answered %v after %s and %d write attempts, %d of them spoiled by a competing commit", i+1, err, time.Since(start), store.writes.Load(), store.spoiled.Load())
		}
		if got := store.writes.Load(); got > 12 {
			t.Fatalf("login %d needed %d write attempts, want at most 12", i+1, got)
		}
		if _, err = service.Authenticate(context.Background(), session.Token); err != nil {
			t.Fatalf("the session the login returned does not authenticate: %v", err)
		}
	}
	if store.spoiled.Load() == 0 {
		t.Fatal("no competing commit went through: the test measured no race")
	}
	if after, _ := store.ScopedDeltaStats(); after-deltas < logins {
		t.Fatalf("%d logins were committed by %d scoped deltas: the record-scoped form was not the one that committed", logins, after-deltas)
	}
}

// The competing commit is any control commit that is not a change of the records the write read: another
// organization, another user, another session, an audit row, an admission key, a job book, an issue book.
// None of them makes the scope or the login stale, however it lands between the read and the proposal.
func TestScopeAndLoginAreNotMadeStaleByAnyOtherControlCommit(t *testing.T) {
	service, store, credential := raceFixture(t)
	service.SetLoginStaleBudget(4 * time.Second)
	n := 0
	rivals := map[string]func(st *model.ControlState){
		"another organization": func(st *model.ControlState) {
			id := model.NewID()
			if st.Orgs == nil {
				st.Orgs = map[string]model.ControlOrg{}
			}
			st.Orgs[id.String()] = model.ControlOrg{ID: id, Name: "other", Epoch: 1}
		},
		"another user": func(st *model.ControlState) {
			id := model.NewID()
			st.Users[id.String()] = model.ControlUser{ID: id, Email: id.String() + "@other.invalid", Password: "x"}
		},
		"another session": func(st *model.ControlState) {
			st.Sessions[model.NewID().String()] = model.ControlSession{User: model.NewID(), CSRF: "c", Expires: 1 << 40}
		},
		"an audit row": func(st *model.ControlState) {
			st.Audits = append(st.Audits, model.ControlAudit{ID: model.NewID(), Principal: model.NewID(), Action: "other.write", Time: 1, Outcome: model.AuditAllowed})
		},
		"an admission key": func(st *model.ControlState) { st.AdmissionKeys = map[string]string{model.NewID().String(): "r"} },
		"a job book": func(st *model.ControlState) {
			st.JobBooks = map[string]json.RawMessage{model.NewID().String() + ":p:j": json.RawMessage(`{}`)}
		},
		"an issue book": func(st *model.ControlState) {
			st.IssueBooks = map[string]json.RawMessage{model.NewID().String() + ":p": json.RawMessage(`{}`)}
		},
	}
	for name, commit := range rivals {
		store.rivals = func(ctx context.Context, rival *control.Store) error {
			return rival.Update(ctx, func(st *model.ControlState) error { commit(st); return nil })
		}
		for _, op := range []string{"instance scope", "login"} {
			n++
			store.writes.Store(0)
			store.spoiled.Store(0)
			var err error
			if op == "login" {
				_, err = service.Login(context.Background(), scopeEmail, scopeSecret, "")
			} else {
				_, err = service.InstanceScope(context.Background(), credential, "a backup of the cluster")
			}
			if err != nil {
				t.Fatalf("%s while another voter committed %s: %v after %d write attempts", op, name, err, store.writes.Load())
			}
			if store.spoiled.Load() == 0 || store.writes.Load() > 12 {
				t.Fatalf("%s while another voter committed %s: %d write attempts, %d competing commits", op, name, store.writes.Load(), store.spoiled.Load())
			}
		}
	}
}

// A record write answers the typed `stale` for the one change that matters to it: a change of a record it
// read. The same write is granted when the competitor changed something else; the answer is given by the
// write itself (no wait in between), on the caller's voter of a real cluster.
func TestRecordWritesAreStaleOnlyForAChangeOfARecordTheyRead(t *testing.T) {
	ctx := context.Background()
	cluster := scopeCluster(t)
	caller, rival := cluster.App(scopeCaller).Control, cluster.App(scopeRival).Control
	var key string
	if err := caller.View(ctx, func(st model.ControlState) error {
		for k, u := range st.Users {
			if u.Email == scopeEmail {
				key = k
			}
		}
		return nil
	}); err != nil || key == "" {
		t.Fatalf("the administrator's record: %q %v", key, err)
	}
	stale := func(err error) bool {
		var fault *model.Fault
		return errors.As(err, &fault) && fault.Code == model.Stale
	}
	row := func() model.ControlAudit {
		return model.ControlAudit{ID: model.NewID(), Principal: model.NewID(), Action: "instance.scope", Time: 1, Outcome: model.AuditAllowed}
	}
	grant := func(change func(*model.ControlState)) error {
		return caller.UpdateAuditRecords(ctx, model.ControlRecords{Users: []string{key}}, func(st *model.ControlState) error {
			if err := rival.Update(ctx, func(s *model.ControlState) error { change(s); return nil }); err != nil {
				t.Errorf("the competing commit: %v", err)
			}
			st.Audits = append(st.Audits, row())
			return nil
		})
	}
	login := func(change func(*model.ControlState)) error {
		session := model.NewID().String()
		return caller.UpdateSessionCreateRecords(ctx, model.ControlRecords{Users: []string{key}, Sessions: []string{session}}, func(st *model.ControlState) error {
			if err := rival.Update(ctx, func(s *model.ControlState) error { change(s); return nil }); err != nil {
				t.Errorf("the competing commit: %v", err)
			}
			st.Sessions[session] = model.ControlSession{User: st.Users[key].ID, CSRF: "c", Expires: 1 << 40}
			return nil
		})
	}
	unrelated := func(s *model.ControlState) {
		id := model.NewID()
		s.Users[id.String()] = model.ControlUser{ID: id, Email: id.String() + "@other.invalid", Password: "x"}
		if s.Orgs == nil {
			s.Orgs = map[string]model.ControlOrg{}
		}
		s.Orgs[id.String()] = model.ControlOrg{ID: id, Name: "other", Epoch: 1}
	}
	genuine := func(s *model.ControlState) { u := s.Users[key]; u.LastTOTP++; s.Users[key] = u }
	for name, write := range map[string]func(func(*model.ControlState)) error{"grant": grant, "login": login} {
		if err := write(unrelated); err != nil {
			t.Fatalf("%s: a commit of other records made the write fail: %v", name, err)
		}
		if err := write(genuine); !stale(err) {
			t.Fatalf("%s: a change of the user it read answered %v, want the typed stale", name, err)
		}
		if err := write(unrelated); err != nil {
			t.Fatalf("%s: the write after a stale answer: %v", name, err)
		}
	}
}

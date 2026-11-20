// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command cutoverseed advances the notification ownership cutover of one project of a STOPPED installation through the
// product's own operator facade (notify.CutoverService.AdvanceCutover over the real control store). It exists for the browser
// test of the cutover panel (web/e2e/cutover-real.spec.ts): the cutover is advanced only by the operator flow, never by the
// served console, so a panel that shows a real cutover needs one committed by exactly that facade into the data directory the
// served process then reads. Nothing here fakes a view: the phases, the revision, the timeline, the frontier and the evidence
// digests are what AdvanceCutover committed and what POST /api/v1/cutover then serves.
//
// The installation must not be running (the control database is single-opener). The organization, the project and the
// registered source are the ones the browser seed created over the real admin API; this command only adds the checkpoint
// the cutover barrier is verified against and the transitions.
//
//	cutoverseed -data-dir DIR -org ID -project ID -source ID -source-version N -phases shadow,quiescing_old
//
// SOUNDPOST_SCOPE_EMAIL and SOUNDPOST_SCOPE_PASSWORD name the installation's organization administrator. Every command ID is a
// pure function of the project, the phase and the revision it moves from, so running the same phase list twice is a replay.
// One JSON line per transition is written to standard output.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// The stable labels of the two sides of the e2e cutover and of the independent observer. They are identities the operator
// flow would supply from its own inventory; here they are fixed so a run is reproducible.
var (
	oldOwner = model.ID{0xe2, 0x01}
	newOwner = model.ID{0xe2, 0x02}
	observer = model.ID{0xe2, 0x03}
)

// frontierGroup is the data group of the frontier cursor, and frontierIndex the position the old owner had processed through.
// The product's own committed issue checkpoint for the group is brought to that position through the real issue handler
// before any barrier, which is what the barrier verification compares.
var frontierGroup = model.ID{0xe2, 0xf0}

const frontierIndex = 100

type clock struct{}

func (clock) Now() model.UnixNano { return model.UnixNano(time.Now().UnixNano()) }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "cutoverseed:", err)
		os.Exit(1)
	}
}

func hash(s string) model.Hash { return model.Hash(sha256.Sum256([]byte(s))) }

func idOf(parts ...string) model.ID {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	var id model.ID
	copy(id[:], sum[:])
	return id
}

func run() error {
	dir := flag.String("data-dir", "", "the stopped installation's data directory")
	orgFlag := flag.String("org", "", "organization ID")
	projectFlag := flag.String("project", "", "project ID")
	sourceFlag := flag.String("source", "", "ID of the registered source the frontier names")
	versionFlag := flag.Uint64("source-version", 0, "the source's committed policy revision")
	phases := flag.String("phases", "", "comma-separated phases to commit in order")
	flag.Parse()
	var org, project, source model.ID
	for _, p := range []struct {
		s   string
		dst *model.ID
	}{{*orgFlag, &org}, {*projectFlag, &project}, {*sourceFlag, &source}} {
		if err := p.dst.UnmarshalText([]byte(p.s)); err != nil {
			return errors.New("-org, -project and -source must be IDs")
		}
	}
	email, password := os.Getenv("SOUNDPOST_SCOPE_EMAIL"), os.Getenv("SOUNDPOST_SCOPE_PASSWORD")
	if *dir == "" || *versionFlag == 0 || *phases == "" || email == "" || password == "" {
		return errors.New("-data-dir, -source-version, -phases, SOUNDPOST_SCOPE_EMAIL and SOUNDPOST_SCOPE_PASSWORD are required")
	}
	ctx := context.Background()
	app, err := appcore.Open(*dir)
	if err != nil {
		return fmt.Errorf("the installation did not open (is it still running?): %w", err)
	}
	defer app.Close()
	session, err := app.Auth.Login(ctx, email, password, "")
	if err != nil {
		return errors.New("the administrator did not authenticate")
	}
	cred, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		return err
	}
	admin := func(kind string, p auth.AdminPayload) error {
		p.Reason = "cutover e2e seed"
		raw, _ := json.Marshal(p)
		var revision model.Revision
		if err := app.Control.View(ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
			return err
		}
		_, err := app.Auth.AdminCommand(ctx, cred, auth.AdminCommandRequest{CommandID: idOf("cutoverseed", kind, org.String(), strconv.FormatUint(uint64(revision), 10)), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw})
		return err
	}
	scope := func(p ...auth.Permission) (auth.Scope, error) {
		if len(p) == 0 {
			return app.Auth.Authorize(ctx, cred, org, []model.ID{project}, auth.OrgAdmin)
		}
		return app.Auth.Authorize(ctx, cred, org, []model.ID{project}, p[0])
	}
	// The administrator needs the issues.write grant the checkpoint handler asks for; an existing grant is replaced by an identical one.
	if err = admin("membership", auth.AdminPayload{UserID: session.User, Enabled: true}); err != nil && !conflict(err) {
		return fmt.Errorf("membership: %w", err)
	}
	if err = admin("grant", auth.AdminPayload{UserID: session.User, ProjectID: project, Enabled: true, Permissions: []string{"telemetry.read", "issues.write", "policy.write"}}); err != nil {
		return fmt.Errorf("grant: %w", err)
	}
	if err = commitCheckpoint(ctx, app, scope, org, project); err != nil {
		return fmt.Errorf("issue checkpoint: %w", err)
	}
	cut, err := notify.NewCutoverService(app.Control, clock{})
	if err != nil {
		return err
	}
	frontier := []notify.FrontierEntry{{Source: source, Version: model.Revision(*versionFlag), Cursor: model.Cursor{Group: frontierGroup, Index: frontierIndex}}}
	out := json.NewEncoder(os.Stdout)
	for _, name := range strings.Split(*phases, ",") {
		phase := notify.CutoverPhase(strings.TrimSpace(name))
		if !phase.Valid() {
			return fmt.Errorf("unknown phase %q", name)
		}
		s, err := scope()
		if err != nil {
			return err
		}
		state, _, err := cut.Cutover(ctx, s)
		if err != nil {
			return err
		}
		command := notify.CutoverCommand{ID: idOf("cutoverseed", "advance", project.String(), string(phase), strconv.FormatUint(uint64(state.Revision), 10)), ExpectedRevision: state.Revision, Frontier: frontier,
			OldOwner: oldOwner, NewOwner: newOwner, Phase: phase, Reason: "cutover e2e step to " + string(phase)}
		if phase == notify.CutoverBarrierVerified || phase == notify.CutoverNewActive || phase == notify.CutoverOldActive {
			facts, err := cut.Facts(ctx, s)
			if err != nil {
				return err
			}
			now := clock{}.Now()
			const sec = model.UnixNano(1_000_000_000)
			ev := &notify.BarrierEvidence{Cutover: state.Cutover, ForRevision: state.Revision, ManifestDigest: notify.ManifestDigest(frontier),
				Accounting:    notify.BarrierAccounting{Pending: facts.Pending, Claimed: facts.Claimed, Unknown: facts.Unknown, UnknownDigest: facts.UnknownDigest, Reviewed: facts.Unknown > 0},
				Authorization: &notify.Authorization{Principal: session.User, Ref: hash("authorization"), AuthorizedAt: now - 60*sec, ExpiresAt: now + 3600*sec},
				Route:         &notify.RollbackRoute{Owner: oldOwner, Ref: hash("rollback-route")},
				// The observer's failure domain is the operator flow's assertion; this run states a domain different from the product's.
				Observer: &notify.ObserverProof{Observer: observer, Domain: idOf("observer-domain", "asserted-separate-host"), ProductDomain: idOf("product-domain", "e2e-host"), ObservedAt: now, Ref: hash("observer")}}
			if phase != notify.CutoverOldActive {
				ev.Owner = &notify.OwnerEvidence{Owner: oldOwner, Method: "scheduler_disabled", ObservedAt: now, Ref: hash("old-owner-disabled")}
			}
			command.Evidence = ev
		}
		next, err := cut.AdvanceCutover(ctx, s, command)
		if err != nil {
			return fmt.Errorf("advance to %s: %w", phase, err)
		}
		if err = out.Encode(map[string]any{"phase": next.Phase, "revision": next.Revision, "epoch": next.Epoch, "cutover": next.Cutover, "replayed": next.Replayed, "active_owners": next.ActiveOwners}); err != nil {
			return err
		}
	}
	return nil
}

// conflict reports the typed conflict outcome (an administrator that is already a member).
func conflict(err error) bool {
	var f *model.Fault
	return errors.As(err, &f) && f.Code == model.Conflict
}

// commitCheckpoint brings the project's committed issue checkpoint for the frontier group to the frontier position through the
// real issue handler (a checkpoint-only command), unless it is already there.
func commitCheckpoint(ctx context.Context, app *appcore.App, scope func(...auth.Permission) (auth.Scope, error), org, project model.ID) error {
	s, err := scope(auth.Permission("issues.write"))
	if err != nil {
		return err
	}
	var book control.IssueBook
	var expected model.Revision
	if err = app.Control.View(ctx, func(st control.State) error {
		if raw, ok := st.IssueBooks[org.String()+":"+project.String()]; ok && json.Unmarshal(raw, &book) == nil {
			expected = book.Revision
			if at, ok := book.Checkpoints[frontierGroup.String()]; ok && uint64(at) >= frontierIndex {
				expected = ^model.Revision(0)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if expected == ^model.Revision(0) {
		return nil
	}
	raw, _ := json.Marshal(control.IssueCommand{Operation: "commit", Project: project, ExpectedRevision: expected, Checkpoint: &control.IssueCheckpoint{Group: frontierGroup, Index: model.Uint64(frontierIndex)}})
	_, err = app.Control.TransactIssues(ctx, s, control.Command{CommandID: control.IssueCommandID(raw), Kind: string(control.KindApplyIssueEvidence), Payload: raw})
	return err
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// The lifecycle commits an effect intent with every change that must be acted on
// (an issue regressing, issues.Effect). An intent stays in the project's issue
// book until its consumer acknowledges it, and the book holds a bounded number of
// them: a regression commit that would exceed the bound is refused as quota. This
// producer is the consumer of the one intent kind the lifecycle mints today:
//
//	issue_regressed  the reopening is acted on by the incident producer, which
//	                 opens one incident for the new episode (and the incident is what
//	                 the notification worker decides into the delivery outbox). The
//	                 intent is acknowledged once that episode's incident exists.
//
// An intent of a kind this consumer does not know is never acknowledged (it would
// be lost). An intent that can no longer be acted on is acknowledged: it names an
// issue or an occurrence that no longer exists (a privacy deletion removed it), or
// an episode that cannot receive an incident any more (a later regression
// superseded it, or the issue is no longer open: the incident producer opens one
// incident per open issue, for its current episode only).

// effectAckBudget bounds the intents one Produce call acknowledges (one control
// transaction per issues.MaxEffectAck of them).
const effectAckBudget = 4 * issues.MaxEffectAck

// IssueEffectProducer is the consumer of the issue lifecycle's effect intents.
func (a *App) IssueEffectProducer() Producer { return &effectProducer{app: a} }

type effectProducer struct{ app *App }

// regressionEpisode is the incident episode ordinal a regression intent
// belongs to: 1 for the first episode of an issue, +1 for every reopening, as
// episodeOf counts them, up to and including the reopening by occurrence. current
// is the ordinal of the issue's latest episode.
func regressionEpisode(rec issues.Record, occurrence model.ID) (ordinal, current uint32, found bool) {
	current = 1
	for _, x := range rec.Explanations {
		if x.Reopened {
			current++
			if x.OccurrenceID == occurrence {
				ordinal, found = current, true
			}
		}
	}
	return ordinal, current, found
}

func (p *effectProducer) Produce(ctx context.Context, scopes ProducerScopes, lease replica.FenceToken) (int, error) {
	if err := p.app.leaseGate(ctx, lease); err != nil {
		return 0, err
	}
	write, err := scopes.Scope(ctx, auth.IssuesWrite)
	if err != nil {
		return 0, err
	}
	producer := &issueProducer{app: p.app, clock: systemWorkerClock{}}
	_, store, err := producer.service(lease)
	if err != nil {
		return 0, err
	}
	org, project := scopes.Org(), scopes.Project()
	pending, err := store.PendingEffects(ctx, write, project)
	if err != nil || len(pending) == 0 {
		return 0, err
	}
	state, err := store.Load(ctx, write, project)
	if err != nil {
		return 0, err
	}
	admin, err := scopes.Scope(ctx, auth.OrgAdmin)
	if err != nil {
		return 0, err
	}
	existing, err := p.app.Control.Incidents(ctx, admin, project)
	if err != nil {
		return 0, err
	}
	have := make(map[model.ID]bool, len(existing))
	for _, rec := range existing {
		have[rec.ID] = true
	}
	var done []model.ID
	for _, e := range pending {
		if len(done) >= effectAckBudget {
			break
		}
		if e.Kind != "issue_regressed" {
			continue // not ours: never acknowledged by a consumer that cannot act on it
		}
		rec, found := state.Issues[e.IssueID]
		if !found {
			done = append(done, e.ID) // the issue is gone: nothing to act on
			continue
		}
		ordinal, current, known := regressionEpisode(rec, e.OccurrenceID)
		switch {
		case !known:
			done = append(done, e.ID) // the evaluation that minted it is gone (erased)
		case ordinal < current || rec.Issue.Workflow != "open":
			// The episode can no longer receive an incident: the incident producer
			// opens one only for the CURRENT episode of an open issue, so a later
			// regression superseded it, or the issue was resolved or ignored before
			// the incident pass ran. Nothing is left to act on.
			done = append(done, e.ID)
		case have[derive("incident", org, project, e.IssueID, ordinal)]:
			done = append(done, e.ID) // acted on: the episode's incident exists
		}
	}
	acked := 0
	for len(done) > 0 {
		n := min(len(done), issues.MaxEffectAck)
		if err := p.app.leaseGate(ctx, lease); err != nil {
			return acked, err
		}
		if err := store.AckEffects(ctx, write, project, done[:n]); err != nil {
			return acked, err
		}
		acked += n
		done = done[n:]
	}
	return acked, nil
}

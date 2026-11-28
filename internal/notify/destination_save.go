// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package notify

import (
	"context"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// DestinationCommand creates or replaces one organization destination. It is
// the write counterpart of the registry's read path: the same target validation,
// one command identity (a replay is idempotent), one expected destination
// version (0 = it must not exist yet), an audited reason, and a write-only
// secret (empty keeps the sealed one).
//
// Project names the project whose policy.write grant authorizes the write; the
// destination itself belongs to the organization (decision D20 recommendation:
// it routes every project of the organization, so the scope must be an
// organization administrator's, which the grant check falls back to).
type DestinationCommand struct {
	Command         model.ID
	Org             model.ID
	Project         model.ID
	ID              model.ID
	ExpectedVersion model.Revision
	Channel         Channel
	Endpoint        string
	Address         string
	Enabled         bool
	Secret          string
	Reason          string
}

// DestinationStore is the narrow consumer-owned seam over the control group's
// audited destination write (the parent binds it to the admin command
// transition: revision compare-and-set, command-ID binding, audit record,
// sealed secret). Commit returns the destination as committed, with its new
// Version. A stale ExpectedVersion is model.Conflict; a caller without the
// authority is the transition's own refusal.
type DestinationStore interface {
	Commit(ctx context.Context, scope auth.Scope, c DestinationCommand) (DestinationRecord, error)
}

const maxDestinationSecret = 4096

// SaveDestination validates c, commits it through store under scope and returns
// the redacted view of the destination as committed. Nothing is committed for a
// command that fails validation: an endpoint that could never be delivered to
// is refused here, not at the first send. The scope must be the caller's own
// for c.Org and name c.Project.
func SaveDestination(ctx context.Context, scope auth.Scope, store DestinationStore, c DestinationCommand) (DestinationView, error) {
	if store == nil {
		return DestinationView{}, model.Fail(model.Unavailable)
	}
	if c.Command == (model.ID{}) || c.Org == (model.ID{}) || c.Project == (model.ID{}) || c.ID == (model.ID{}) ||
		c.Reason == "" || len(c.Reason) > 512 || len(c.Secret) > maxDestinationSecret {
		return DestinationView{}, model.Fail(model.Invalid)
	}
	if scope.OrgID() != c.Org || !scope.AllowsProject(c.Project) {
		return DestinationView{}, model.Fail(model.Forbidden)
	}
	if _, err := destinationTarget(c.Channel, c.Endpoint, c.Address); err != nil {
		return DestinationView{}, model.Fail(model.Invalid)
	}
	// A channel is addressed by one field; the other must be empty so no stored
	// value can ever be mistaken for the target.
	if c.Channel == ChannelWebhook && c.Address != "" || c.Channel != ChannelWebhook && c.Endpoint != "" {
		return DestinationView{}, model.Fail(model.Invalid)
	}
	rec, err := store.Commit(ctx, scope, c)
	if err != nil {
		return DestinationView{}, err
	}
	if rec.Type != string(c.Channel) {
		return DestinationView{}, model.Fail(model.Corrupt)
	}
	return rec.View(c.ID), nil
}

// View is the redacted DTO of a configured destination: a webhook shows its
// host only, an e-mail its domain only, a Telegram chat nothing.
func (r DestinationRecord) View(id model.ID) DestinationView {
	d := Destination{ID: id, Channel: Channel(r.Type)}
	switch d.Channel {
	case ChannelWebhook:
		d.Target = r.Endpoint
	default:
		d.Target = r.Address
	}
	if r.HasSecret {
		d.Secret = &SecretRef{ID: id}
	}
	v := d.View()
	enabled := r.Enabled
	v.Enabled, v.Version = &enabled, r.Version
	return v
}

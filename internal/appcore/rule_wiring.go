// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"crypto/sha256"
	"errors"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
	"github.com/arynyklas/soundpost/internal/rules"
)

// RuleCatalogue is the rule catalogue over this node's control state and the
// embedded profile registry: what the authoring route saves definitions into and
// what the workers evaluate. It is a RuleSource (WorkerConfig.Rules). It keeps
// no state, so every call returns an equivalent value.
func (a *App) RuleCatalogue(options ...rules.CatalogueOption) (*rules.Catalogue, error) {
	registry, err := rules.DefaultRegistry()
	if err != nil {
		return nil, err
	}
	return rules.NewCatalogue(a.Control, registry, options...)
}

// RecordingSource is the node's registered recording source: the data-plane
// credential recording rules write their samples through. It is the node's own
// seam, not a principal anyone presents: the credential is the secret issued
// when the source was onboarded (the operator hands it to the node at start, it
// is never stored by the node), and the source's project, resource registry and
// policy are read from committed control state at every use, so a revoked,
// expired or re-versioned source applies at the next evaluation. It is a
// rules.RecordingSource (save-time label check), a rules.ProducerResolver
// (Producer) and an OutputAdmission (Admit, LookupReceipt).
type RecordingSource struct {
	app        *App
	credential auth.SourceCredential
}

var (
	_ OutputAdmission       = (*RecordingSource)(nil)
	_ rules.RecordingSource = (*RecordingSource)(nil)
)

// NewRecordingSource authenticates the node's recording source credential
// against control state. A credential that is unknown, revoked or expired is
// refused here, with the same Forbidden every source credential gets, so a node
// never starts with a recording source it could not write through.
func (a *App) NewRecordingSource(ctx context.Context, secret string) (*RecordingSource, error) {
	credential, err := a.Auth.AuthenticateSource(ctx, secret, "", false)
	if err != nil {
		return nil, err
	}
	return &RecordingSource{app: a, credential: credential}, nil
}

// recordingProducer is the producer identity recorded samples are admitted
// under: one stable ID per source, so the producer of a source never changes and
// a sample admitted once is deduplicated for ever.
func recordingProducer(source model.ID) model.ID {
	sum := sha256.Sum256(append([]byte("soundpost/rules/recording-producer/v1\x00"), source[:]...))
	return model.ID(sum[:16])
}

// Recording implements rules.RecordingSource.
func (r *RecordingSource) Recording(ctx context.Context) (rules.RecordingTarget, error) {
	authority, err := r.app.Auth.SourceAuthority(ctx, r.credential, true)
	if err != nil {
		return rules.RecordingTarget{}, err
	}
	registry := authority.Policy.Resources
	if len(registry.Services) == 0 || len(registry.Environments) == 0 || len(registry.Builds) == 0 || len(registry.Instances) == 0 {
		// A recorded sample needs a registered resource; a source that registers
		// none cannot carry one.
		return rules.RecordingTarget{}, model.Fail(model.Invalid)
	}
	return rules.RecordingTarget{
		Project: authority.Project,
		Policy:  authority.Policy,
		Producer: rules.ProducerIdentity{
			Source: authority.ID, Producer: recordingProducer(authority.ID), PolicyRevision: authority.Policy.Revision,
			Resource: model.Resource{Service: registry.Services[0], Environment: registry.Environments[0], Build: registry.Builds[0], Instance: registry.Instances[0], Labels: model.Labels{}},
		},
	}, nil
}

// Producer is the rules.ProducerResolver of the recording source: the identity
// and the source policy revision recording batches are built for, resolved at
// every evaluation.
func (r *RecordingSource) Producer(ctx context.Context) (rules.ProducerIdentity, error) {
	target, err := r.Recording(ctx)
	return target.Producer, err
}

// Admit implements rules.Admitter: normalization against the source's current
// policy, the quota reservation and the data-group append, through the ordinary
// ingest path under the source credential. Re-admitting a batch returns its
// receipt.
func (r *RecordingSource) Admit(ctx context.Context, batch model.Batch) (model.Receipt, error) {
	grant, err := r.app.Ingest.ResolveSource(ctx, r.credential, batch)
	if err != nil {
		return model.Receipt{}, err
	}
	return r.app.Ingest.Admit(ctx, grant, batch)
}

// LookupReceipt implements rules.ReceiptLookup: the authenticated historical
// receipt of a batch, to settle an admission whose outcome was ambiguous.
func (r *RecordingSource) LookupReceipt(ctx context.Context, batch model.Batch) (model.Receipt, bool, error) {
	grant, err := r.app.Ingest.ResolveSource(ctx, r.credential, batch)
	if err != nil {
		return model.Receipt{}, false, err
	}
	normalized, err := policy.Normalize(grant, batch)
	if err != nil {
		return model.Receipt{}, false, err
	}
	receipt, err := r.app.Ingest.LookupReceipt(ctx, r.credential, model.ReceiptRequest{Source: batch.Source, Producer: batch.Producer, RouteSlot: batch.RouteSlot, BatchID: batch.ID, OriginalHash: normalized.Hash})
	var fault *model.Fault
	if errors.As(err, &fault) && fault.Code == model.NotFound {
		return model.Receipt{}, false, nil
	}
	return receipt, err == nil, err
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"github.com/arynyklas/soundpost/internal/model"
	"time"
)

// NewJobProducerForTest builds the job producer with an explicit per-call bound
// and an explicit rest between two sweeps of the journal.
func NewJobProducerForTest(a *App, bound int, rest time.Duration) Producer {
	p := newJobProducer(a, bound)
	p.rest = rest
	return p
}

// NewProducerScopesForTest derives the scopes a pass hands a producer.
func NewProducerScopesForTest(a *App, org, project model.ID) ProducerScopes {
	return ProducerScopes{authority: a.Auth, org: org, project: project}
}

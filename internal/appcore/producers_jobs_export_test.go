// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import "github.com/arynyklas/soundpost/internal/model"

// NewJobProducerForTest builds the job producer with an explicit per-call bound.
func NewJobProducerForTest(a *App, bound int) Producer { return newJobProducer(a, bound) }

// NewProducerScopesForTest derives the scopes a pass hands a producer.
func NewProducerScopesForTest(a *App, org, project model.ID) ProducerScopes {
	return ProducerScopes{authority: a.Auth, org: org, project: project}
}

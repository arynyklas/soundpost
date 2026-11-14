// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package profiles

import (
	"context"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

type ProfileScanner interface {
	ScanProfile(context.Context, auth.Scope, model.ID, Window) (ProfileIterator, error)
}
type ProfileIterator interface {
	Next(context.Context) (ProfilePage, error)
	Close() error
}
type ScopeAuthorizer interface {
	Revalidate(context.Context, auth.Scope) error
}

// Resolve independently checks every reference under the current scope. No
// reference (including an artifact/build hash) is an authorization carrier.
type LinkResolver interface {
	Resolve(context.Context, auth.Scope, []Reference) ([]ResolvedReference, error)
}

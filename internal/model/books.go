// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import "context"

type withoutBooksKey struct{}

// WithoutBooks marks ctx so that the reads of the control store made under it (View) give the reader the
// state without the admission books (Reservations, AdmissionKeys, Quotas, Settlement come empty): the
// books grow with every batch ever admitted and are not settled for days, so assembling them into every
// read made an authenticated query cost O(history). It is for a reader that does not look at them; a
// reader that does (a backup cut, a settlement, a quota report) must not run under it.
func WithoutBooks(ctx context.Context) context.Context {
	return context.WithValue(ctx, withoutBooksKey{}, struct{}{})
}

// WantsBooks reports whether a control read made under ctx is to carry the admission books.
func WantsBooks(ctx context.Context) bool { return ctx.Value(withoutBooksKey{}) == nil }

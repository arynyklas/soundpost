// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package scan

import (
	"context"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/regexcompat"
	"github.com/arynyklas/soundpost/internal/query/value"
	"github.com/arynyklas/soundpost/internal/storage"
)

type Scanner interface {
	Scan(context.Context, auth.Scope, storage.ScanRequest) (storage.RowIterator, error)
}
type MetricSource interface {
	ProjectID() model.ID
	Select(context.Context, MetricSelection) (SeriesIterator, error)
}
type LabelMatcher struct{ Name, Op, Value string }

// Start/End are raw, half-open C05 bounds, already expanded for lookback,
// predecessor/successor and selector windows by the language planner.
type MetricSelection struct {
	Start, End model.UnixNano
	Matchers   []LabelMatcher
	Profile    profile.Profile
	Account    value.Account
	RegexScope *regexcompat.Scope
}
type SeriesIterator interface {
	Next(context.Context) (value.Series, error)
	Watermarks() []model.Cursor
	Partial() bool
	Close() error
}

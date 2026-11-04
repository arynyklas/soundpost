//go:build soundpost_logql_oracle

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"

	"github.com/go-kit/log"
	native "github.com/grafana/loki/v3/pkg/logql"
	"github.com/grafana/loki/v3/pkg/logql/syntax"
	"github.com/grafana/loki/v3/pkg/logqlmodel"
	"github.com/prometheus/client_golang/prometheus"
)

// Approximation is a native query-frontend operation: the native querier alone
// does not accept approx_topk. Invoke the actual zero-shard planner and actual
// downstream frontend evaluator; its downstream queries use the same native
// querier engine/data/window/configuration. No AST rewrite is authored here.
func executeNativeMetric(ctx context.Context, in input, params native.Params, entries []entry, opts native.EngineOpts, limits oracleLimits) (logqlmodel.Result, error) {
	engine := native.NewEngine(opts, &fixtureQuerier{entries: entries}, limits, nil)
	approximate := false
	params.GetExpression().Walk(func(expr syntax.Expr) {
		if aggregate, ok := expr.(*syntax.VectorAggregationExpr); ok && aggregate.Operation == syntax.OpTypeApproxTopK {
			approximate = true
		}
	})
	if !approximate {
		return engine.Query(params).Exec(ctx)
	}
	var aggregations []string
	for _, gate := range in.Enabled {
		if gate == "approx_topk" || gate == "shard-approx_topk" {
			aggregations = append(aggregations, native.SupportApproxTopk)
		}
	}
	mapper := native.NewShardMapper(native.NewPowerOfTwoStrategy(native.ConstantShards(0)), native.NewShardMapperMetrics(prometheus.NewRegistry()), aggregations)
	_, _, mapped, err := mapper.Parse(params.GetExpression())
	if err != nil {
		return logqlmodel.Result{}, err
	}
	frontend := native.NewDownstreamEngine(opts, nativeFixtureDownstream{engine: engine}, limits, log.NewNopLogger())
	return frontend.Query(ctx, native.ParamsWithExpressionOverride{Params: params, ExpressionOverride: mapped}).Exec(ctx)
}

type nativeFixtureDownstream struct{ engine *native.Engine }

func (d nativeFixtureDownstream) Downstreamer(context.Context) native.Downstreamer { return d }
func (d nativeFixtureDownstream) Downstream(ctx context.Context, queries []native.DownstreamQuery, acc native.Accumulator) ([]logqlmodel.Result, error) {
	for index, query := range queries {
		result, err := d.engine.Query(query.Params).Exec(ctx)
		if err != nil {
			return nil, err
		}
		if err = acc.Accumulate(ctx, result, index); err != nil {
			return nil, err
		}
	}
	return acc.Result(), nil
}

var _ native.Downstreamable = nativeFixtureDownstream{}
var _ native.Downstreamer = nativeFixtureDownstream{}

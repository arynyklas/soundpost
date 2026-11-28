// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

// shardCapabilities are the four names the pinned engine's shard_aggregations
// switch recognizes, in the order of their feature-set gates. Each enables one
// mapper capability independently of the others; approx_topk is an explicit
// capability even though the pinned flag's help text omits it from the possible
// values.
var shardCapabilities = [...]string{"first_over_time", "last_over_time", "quantile_over_time", "approx_topk"}

// ShardAggregationGates maps the strings of a shard_aggregations configuration
// to the profile gates they enable ("shard-" plus the name for the three
// range-aggregation capabilities; approx_topk's gate is "approx_topk", the name the
// profile registers and the type checker tests), in the fixed order
// of shardCapabilities. The switch is a set: a name listed twice enables its
// capability once (repeat enablement is idempotent), and a string that is none of
// the four recognized names (any other spelling, another case, surrounding space,
// the empty string) is ignored, never an error: it enables nothing and does not
// affect the recognized names around it.
func ShardAggregationGates(names []string) []string {
	var seen [len(shardCapabilities)]bool
	for _, name := range names {
		for i, capability := range shardCapabilities {
			if name == capability {
				seen[i] = true
			}
		}
	}
	gates := []string{}
	for i, capability := range shardCapabilities {
		if seen[i] {
			gate := "shard-" + capability
			if capability == "approx_topk" {
				gate = capability
			}
			gates = append(gates, gate)
		}
	}
	return gates
}

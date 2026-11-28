// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues

const (
	// explanationPruneAbove is the encoded size of one issue's explanation list at
	// which the oldest droppable evaluations are pruned. Control refuses a list of
	// 256 KiB (a Quota that would stop the data group's checkpoint), so pruning starts
	// well below it.
	explanationPruneAbove = 192 << 10
	// explanationPruneTo is the size pruning leaves, so one pruning makes room for
	// many evaluations instead of running on every commit.
	explanationPruneTo = 128 << 10
)

// pruneExplanations bounds the stored regression evaluations of one issue (R01-3: a
// hot resolved fingerprint adds one per post-boundary occurrence and would otherwise
// reach control's size cap and wedge the checkpoint). It drops the OLDEST
// evaluations that nothing decides by, until the list is down to
// explanationPruneTo; a list under explanationPruneAbove is returned as it is.
//
// Two kinds are never dropped: an evaluation that reopened the issue (the episode
// ordinal of its incident counts them), and, while the issue is resolved, an
// eligible evaluation of the current resolution (it counts toward the reopen
// threshold). Every other evaluation is history the reader sees as the newest ones
// kept. If what must stay is itself over the bound, the list is returned whole and
// control's honest Quota applies.
func pruneExplanations(list []Explanation, i Issue) []Explanation {
	raw, err := encodeExplanations(list)
	if err != nil || len(raw) <= explanationPruneAbove {
		return list
	}
	droppable := func(x Explanation) bool {
		if x.Reopened {
			return false
		}
		counts := i.Workflow == "resolved" && i.ResolutionTime != nil && x.Decision.Eligible && x.ResolutionTime == *i.ResolutionTime
		return !counts
	}
	size := len(raw)
	drop := make([]bool, len(list))
	for n, x := range list {
		if size <= explanationPruneTo {
			break
		}
		if !droppable(x) {
			continue
		}
		one, err := encodeExplanations(list[n : n+1])
		if err != nil {
			return list
		}
		size -= len(one) - 1 // the entry without its two brackets, plus the comma that joined it
		drop[n] = true
	}
	out := make([]Explanation, 0, len(list))
	for n, x := range list {
		if !drop[n] {
			out = append(out, x)
		}
	}
	return out
}

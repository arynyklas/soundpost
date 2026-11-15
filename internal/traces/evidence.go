// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package traces

import (
	"bytes"
	"cmp"
	"slices"

	"github.com/arynyklas/soundpost/internal/model"
)

// LateAfterNS is how long after a span ended its report may arrive before the span is called late:
// five seconds. A shorter delay is ordinary export batching and is not worth a limit on the page.
const LateAfterNS = int64(5_000_000_000)

// MaxGaps bounds the producer gaps one analysis reports.
const MaxGaps = 100

// Evidence is what an analysis is given besides the spans. Reported holds, per span in input order,
// when that span was reported in wall nanoseconds (0 when unknown); it is empty or exactly as long as
// the spans. Losses are the loss records of the spans' producers: only the ones whose own signal is
// span and whose source contributed a span to this trace belong here (the reader decides that).
type Evidence struct {
	Reported []int64
	Losses   []ProducerLoss
}

// LateSpan is a span that was reported long after it ended.
type LateSpan struct {
	Span         model.SpanID `json:"span_id"`
	EndedWall    model.Int64  `json:"ended_wall_ns"`
	ReportedWall model.Int64  `json:"reported_wall_ns"`
	LateBy       model.Int64  `json:"late_by_ns"`
}

// ProducerLoss is one loss record of a producer: for the interval it names, Count spans never reached
// storage for Reason (queue_full, expired, policy, unsupported, ring_overflow, reorder_gap, transport,
// shutdown, truncated). Whether the lost spans belonged to this trace is not knowable.
type ProducerLoss struct {
	Source   model.ID     `json:"source"`
	Producer model.ID     `json:"producer"`
	Start    model.Int64  `json:"start_ns"`
	End      model.Int64  `json:"end_ns"`
	Reason   string       `json:"reason"`
	Count    model.Uint64 `json:"count"`
}

// relevantGaps keeps the losses whose interval touches the time the trace's spans cover, in a stable
// order, at most MaxGaps of them; truncated says more were dropped from the list.
func relevantGaps(losses []ProducerLoss, spans []*model.Span) (out []ProducerLoss, truncated bool) {
	out = []ProducerLoss{}
	if len(losses) == 0 || len(spans) == 0 {
		return out, false
	}
	lo, hi := int64(spans[0].Start.Wall), int64(spans[0].Start.Wall)
	for _, s := range spans {
		lo, hi = min(lo, int64(s.Start.Wall)), max(hi, int64(s.Start.Wall))
		if s.End != nil {
			lo, hi = min(lo, int64(s.End.Wall)), max(hi, int64(s.End.Wall))
		}
	}
	for _, l := range losses {
		if int64(l.End) >= lo && int64(l.Start) <= hi {
			out = append(out, l)
		}
	}
	slices.SortFunc(out, func(a, b ProducerLoss) int {
		return cmp.Or(cmp.Compare(a.Start, b.Start), cmp.Compare(a.End, b.End), bytes.Compare(a.Source[:], b.Source[:]), bytes.Compare(a.Producer[:], b.Producer[:]), cmp.Compare(a.Reason, b.Reason), cmp.Compare(a.Count, b.Count))
	})
	if len(out) > MaxGaps {
		out, truncated = out[:MaxGaps], true
	}
	return out, truncated
}

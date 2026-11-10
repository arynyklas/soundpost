// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"sort"

	"soundpost/internal/ingest"
	"soundpost/internal/model"
)

// maxBatchRecords is the C03 per-batch record limit.
const maxBatchRecords = 512

// RecordingBatches derives the C03 batches of a recording evaluation. Identities
// are a pure function of (organization, project, rule, version, scheduled time,
// series, owner slot): the same evaluation always yields byte-identical batches,
// so re-admission after any crash is deduplicated by the data group and can never
// store a sample twice. Each batch is one canonical-owner slot (the fixed 64
// virtual slots of C03) and at most 512 records.
//
// The samples were validated when the evaluation was built: names replaced by the
// configured recording name, configured labels applied, duplicate series
// rejected. Nothing here can fail a sample into existence or out of it.
func RecordingBatches(eval Evaluation, rule Rule) ([]ingest.Batch, error) {
	invalid := func() ([]ingest.Batch, error) { return nil, model.Fail(model.Invalid) }
	p := eval.Producer
	if rule.Kind != KindRecording || eval.Kind != KindRecording || eval.Outcome != OutcomeComplete || p == nil ||
		eval.Rule != rule.ID || eval.Version != rule.Version || eval.At < 0 || rule.RecordName == "" {
		return invalid()
	}
	if p.Source == (model.ID{}) || p.Producer == (model.ID{}) || p.PolicyRevision == 0 {
		return invalid()
	}
	resource := p.Resource
	if resource.Labels == nil {
		resource.Labels = model.Labels{}
	}
	recorded := append([]Recorded(nil), eval.Recorded...)
	sort.Slice(recorded, func(i, j int) bool { return seriesKey(recorded[i].Labels) < seriesKey(recorded[j].Labels) })

	bySlot := map[uint16][]model.Record{}
	seen := make(map[string]bool, len(recorded))
	for _, r := range recorded {
		key := seriesKey(r.Labels)
		if seen[key] {
			return invalid()
		}
		seen[key] = true
		labels := r.Labels
		if labels == nil {
			labels = model.Labels{}
		}
		point := &model.MetricPoint{Name: rule.RecordName, Labels: labels, SampleKind: r.SampleKind, Value: r.Value, Histogram: r.Histogram, StartTimestamp: r.StartTimestamp, Unit: "1", Type: "gauge"}
		if r.Histogram != nil {
			point.Type = "histogram"
		}
		record := model.Record{
			ID:         derive("record", eval.Org[:], eval.Project[:], eval.Rule[:], u64(uint64(eval.Version)), u64(uint64(eval.At)), []byte(key)),
			Kind:       model.Metric,
			ObservedAt: eval.At,
			Resource:   resource,
			Payload:    model.Payload{Metric: point},
		}
		slot, err := model.OwnerSlot(eval.Org, eval.Project, p.Source, p.Producer, record)
		if err != nil {
			return invalid()
		}
		bySlot[slot] = append(bySlot[slot], record)
	}
	slots := make([]int, 0, len(bySlot))
	for slot := range bySlot {
		slots = append(slots, int(slot))
	}
	sort.Ints(slots)
	var batches []ingest.Batch
	for _, s := range slots {
		slot := uint16(s)
		records := bySlot[slot]
		for chunk := 0; len(records) > 0; chunk++ {
			n := min(len(records), maxBatchRecords)
			batches = append(batches, ingest.Batch{
				Version: 1, Project: eval.Project, Source: p.Source, Producer: p.Producer,
				ID:             derive("batch", eval.Org[:], eval.Project[:], eval.Rule[:], u64(uint64(eval.Version)), u64(uint64(eval.At)), u64(uint64(slot)), u64(uint64(chunk))),
				PolicyRevision: p.PolicyRevision, RouteSlot: slot, Records: records[:n:n],
			})
			records = records[n:]
		}
	}
	return batches, nil
}

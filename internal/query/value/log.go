// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package value

import "soundpost/internal/model"

// Log preserves record identity and repetitions independently of rendered text.
// Labels are the resulting query labels; original metadata stays separate.
type Log struct {
	Project            model.ID
	ID                 model.ID
	Source             model.ID
	Timestamp          model.UnixNano
	Multiplicity       model.Uint64
	Line               string
	Labels             model.Labels
	StreamLabels       model.Labels
	StructuredMetadata model.Labels
}

func LogBytes(l Log) int64 {
	n := int64(160 + len(l.Line))
	for _, ls := range []model.Labels{l.Labels, l.StreamLabels, l.StructuredMetadata} {
		for _, v := range ls {
			n += int64(32 + len(v.Name) + len(v.Value))
		}
	}
	return n
}

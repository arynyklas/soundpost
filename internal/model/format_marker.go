// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package model

// The persisted control-state format marker (ControlState.BearerHashKeyVersion). A build refuses to start on a marker
// above the highest it supports (readiness reason schema_newer, nothing written): that is how the previous release
// fails closed on a data directory it must not run on.
const (
	// FormatMarkerBase is the format of the previous release: the highest marker it supports.
	FormatMarkerBase uint8 = 1
	// FormatMarkerRecords (D94) says the installation holds, or is about to hold, records only this release
	// understands (an error issue's owner and external links, an incident's title, notes and external links). The
	// previous release ignores such members and drops them when it stores the record again, so it must not run on
	// the data: it refuses to start on this marker. The marker is written BEFORE the first such record and never
	// goes back.
	FormatMarkerRecords uint8 = 2
)

// MarkRecordFormat raises the format marker to FormatMarkerRecords and reports whether it changed. It is
// idempotent and never lowers the marker.
func MarkRecordFormat(st *ControlState) bool {
	if st.BearerHashKeyVersion >= FormatMarkerRecords {
		return false
	}
	st.BearerHashKeyVersion = FormatMarkerRecords
	return true
}

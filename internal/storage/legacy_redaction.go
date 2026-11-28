// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import "github.com/arynyklas/soundpost/internal/model"

// LegacyBundleNeedsReseal is the SafeDetail of the model.Unsupported refusal of a backup bundle
// that was sealed before its quota evidence recorded which batches physical erasure rewrote
// (ReservationEvidence.Redacted/Retained, commit dc732a8). Such a bundle is not damaged and not
// forged: its evidence is what that build wrote, but the restored index no longer holds the series
// of the erased records the evidence charges, so the restore cannot prove the series cross-check
// and stays closed. The operator's remedy is a new backup taken by the current build from a
// running installation; the old bundle cannot be restored.
const LegacyBundleNeedsReseal = "legacy_bundle_needs_reseal"

// legacyBundleFault is the typed refusal of a legacy bundle.
func legacyBundleFault() *model.Fault {
	f := model.Fail(model.Unsupported)
	f.SafeDetail = LegacyBundleNeedsReseal
	return f
}

// isLegacyRedactionShape reports whether sealed (the evidence a bundle carries, whose own digest
// the caller has already verified) differs from derived (the evidence of the installed snapshot
// bytes) in exactly one way: derived records redacted batches and sealed records none. That is
// what a build before the markers wrote for an installation that had erased data, and only that:
//
//   - only version 1 evidence qualifies. The windowed form (version 2) was introduced after the
//     markers, so a version 2 bundle without them is not any build's output;
//   - sealed carries no marker at all (a bundle that claims a redaction is judged by the ordinary
//     comparison, however wrong the claim);
//   - sealed's digest equals the digest of derived once derived's markers are removed, so every
//     charged field of every batch (reservation, source, bytes, series, cursor) is exactly what the
//     bytes hold. Any other difference, however small, is not this shape.
//
// The answer only picks which refusal the caller returns; a legacy bundle is never accepted.
func isLegacyRedactionShape(sealed, derived QuotaEvidence) bool {
	if sealed.Version != 1 || derived.Version != 1 || sealed.Digest != sealed.seal() {
		return false
	}
	for _, c := range sealed.Consumed {
		if c.Redacted || len(c.Retained) != 0 {
			return false
		}
	}
	marked := false
	stripped := derived
	stripped.Consumed = append([]ReservationEvidence(nil), derived.Consumed...)
	for i := range stripped.Consumed {
		if stripped.Consumed[i].Redacted {
			marked = true
		}
		stripped.Consumed[i].Redacted, stripped.Consumed[i].Retained = false, nil
	}
	return marked && stripped.seal() == sealed.Digest
}

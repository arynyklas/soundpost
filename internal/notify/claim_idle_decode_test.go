// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package notify_test

import "testing"

// The notification runner claims once per project on every pass, and almost every claim changes nothing (control.DeliveryClaimIdle answers it
// without a commit). The read that proves it is the decode of the control state that every shared reader uses: a pass over many projects must not
// decode the whole blob of the state once per project.
func TestIdleClaimsDoNotDecodeTheControlBlob(t *testing.T) {
	n := newNode(t)
	ob := n.outbox()
	scope, lease := n.scope(), n.lease()
	// The first claim of a lease commits (it raises the project's fence); the ones after it are idle.
	if got, err := ob.Claim(n.ctx, scope, base, lease, 1); err != nil || len(got) != 0 {
		t.Fatalf("first claim: %d deliveries, %v", len(got), err)
	}
	rev := n.revision()
	if got, err := ob.Claim(n.ctx, scope, base, lease, 1); err != nil || len(got) != 0 { // what this one reads is shared by the rest
		t.Fatalf("second claim: %d deliveries, %v", len(got), err)
	}
	before := n.store.DecodeStats()
	for range 10 {
		if got, err := ob.Claim(n.ctx, scope, base, lease, 1); err != nil || len(got) != 0 {
			t.Fatalf("idle claim: %d deliveries, %v", len(got), err)
		}
	}
	if got := n.store.DecodeStats().Blobs - before.Blobs; got != 0 {
		t.Fatalf("10 idle claims decoded the whole blob %d times, want never", got)
	}
	if n.revision() != rev {
		t.Fatal("an idle claim committed")
	}
}

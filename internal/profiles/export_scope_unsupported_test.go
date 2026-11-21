// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package profiles_test

import (
	"context"
	"testing"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/privacy/privnode"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// A method that was not supported does not claim the system-wide read, even when the producer declared it for the
// scheduler path as a whole: the off-CPU method carries it (its read opened), the runnable split that did not open
// carries target-only (l4w33 mutation battery C).
func TestExporterStampsAMethodThatWasNotSupportedTargetOnly(t *testing.T) {
	const system, target = model.AcquisitionScopeSystemWideScheduler, model.AcquisitionScopeTargetOnly
	for _, status := range []nativeperf.Status{nativeperf.Unsupported, nativeperf.Denied} {
		t.Run(string(status), func(t *testing.T) {
			ctx := context.Background()
			env := newPrivacyEnv(t)
			n, e := privnode.Start(ctx, t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			defer n.Close()
			caps := privacyCapabilities()
			caps.AcquisitionScope = system
			caps.RunqueueSplit = status
			_, admitter, e := exportAndReadWith(t, env, n, "", false, caps)
			if e != nil {
				t.Fatal(e)
			}
			queued := map[string]string{}
			for _, b := range admitter.seen {
				for _, r := range b.Records {
					if r.Kind == model.CapabilityKind {
						queued[r.Payload.Capability.Method] = r.Payload.Capability.AcquisitionScope
					}
				}
			}
			want := map[string]string{"native_cpu": target, "native_offcpu": system, "native_runqueue_split": target}
			if len(queued) != len(want) {
				t.Fatalf("queued capability methods %v, want %v", queued, want)
			}
			for method, scope := range want {
				if got, ok := queued[method]; !ok || got != scope {
					t.Errorf("queued %s: scope %q (present %v), want %q", method, got, ok, scope)
				}
			}
		})
	}
}

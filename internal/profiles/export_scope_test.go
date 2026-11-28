// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package profiles_test

import (
	"context"
	"testing"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/privacy/privnode"
	"github.com/arynyklas/soundpost/internal/model"
)

// 04.04-C11 end to end: the exporter stamps each capability record it queues with how far THAT method's acquisition
// reached, from the producer's declared scope. CPU sampling observes the authorized target only whatever the producer
// declared; the scheduler methods carry the system-wide read exactly when it was supported. An undeclared scope stays
// absent. The same records come back through the real route and the scoped read.
func TestExporterStampsEachCapabilityRecordWithTheAcquisitionScopeOfItsMethod(t *testing.T) {
	const system, target = model.AcquisitionScopeSystemWideScheduler, model.AcquisitionScopeTargetOnly
	cases := []struct {
		name  string
		scope string
		want  map[string]string
	}{
		{"system-wide scheduler read declared", system, map[string]string{"native_cpu": target, "native_offcpu": system, "native_runqueue_split": system}},
		{"target only declared", target, map[string]string{"native_cpu": target, "native_offcpu": target, "native_runqueue_split": target}},
		{"scope not declared", "", map[string]string{"native_cpu": "", "native_offcpu": "", "native_runqueue_split": ""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			env := newPrivacyEnv(t)
			n, e := privnode.Start(ctx, t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			defer n.Close()
			caps := privacyCapabilities()
			caps.AcquisitionScope = c.scope
			l, admitter, e := exportAndReadWith(t, env, n, "", false, caps)
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
			if len(queued) != len(c.want) {
				t.Fatalf("queued capability methods %v, want %v", queued, c.want)
			}
			for method, scope := range c.want {
				if got, ok := queued[method]; !ok || got != scope {
					t.Errorf("queued %s: scope %q (present %v), want %q", method, got, ok, scope)
				}
			}
			read := map[string]string{}
			for _, v := range l.view {
				for _, record := range v.Capabilities {
					read[record.Value.Method] = record.Value.AcquisitionScope
				}
			}
			for method, scope := range c.want {
				if got, ok := read[method]; !ok || got != scope {
					t.Errorf("read back %s: scope %q (present %v), want %q", method, got, ok, scope)
				}
			}
		})
	}
}

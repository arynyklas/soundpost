// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// A permission refusal of the target's /proc entry (DAC, LSM, ptrace scope) and
// a target that is simply not visible (hidepid=2, other PID namespace, exited)
// are different operator fixes, so the probe tool must not print the same text
// for both. Neither message may carry a path, a command or an errno string.
func TestIdentityFailureSeparatesPermissionFromInvisibility(t *testing.T) {
	denied := identityFailure(fmt.Errorf("wrapped: %w", &nativeperf.CapabilityError{Status: nativeperf.Denied, Reason: nativeperf.ReasonPermission}))
	missing := identityFailure(nativeperf.ErrInvalid)
	if denied == missing {
		t.Fatalf("permission refusal and invisible target print the same text: %q", denied)
	}
	if !strings.HasPrefix(denied, "target identity unavailable") || !strings.HasPrefix(missing, "target identity unavailable") {
		t.Fatal(denied, missing)
	}
	if !strings.Contains(denied, "permission_denied") || strings.Contains(missing, "permission_denied") {
		t.Fatal(denied, missing)
	}
	if got := identityFailure(errors.New("open /proc/123/stat: no such file")); strings.Contains(got, "/proc") || strings.Contains(got, "123") {
		t.Fatalf("identity failure leaked a path: %q", got)
	}
}

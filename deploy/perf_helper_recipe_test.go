// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package deploy

import (
	"strings"
	"testing"
)

// The helper image is FROM scratch. The helper names the host from /etc/machine-id in every domain it exports; run as a
// container entrypoint without that file it refuses every capture as "invalid native target identity" (real run on
// sp-oci, kernel 6.12: fixtures/nativeperf/helper-smoke/drive --container-image ... --container-machine-id=false).
// Both container recipes must therefore bind the host file read-only.
func TestPerfHelperContainerRecipesProvideTheHostMachineID(t *testing.T) {
	compose := read(t, "compose.distributed.yaml")
	i := strings.Index(compose, "soundpost-perf-helper:")
	if i < 0 {
		t.Fatal("compose helper service missing")
	}
	service := compose[i:]
	if j := strings.Index(service, "\nnetworks:"); j > 0 {
		service = service[:j]
	}
	if !strings.Contains(service, "source: /etc/machine-id") || !strings.Contains(service, "target: /etc/machine-id") {
		t.Error("compose helper service does not bind the host /etc/machine-id")
	}
	if k := strings.Index(service, "target: /etc/machine-id"); k < 0 || !strings.Contains(service[k:], "read_only: true") {
		t.Error("compose helper machine-id bind is missing or not read-only")
	}
	helm := read(t, "helm/soundpost/templates/perf-helper.yaml")
	if !strings.Contains(helm, "mountPath: /etc/machine-id, readOnly: true") || !strings.Contains(helm, "hostPath: {path: /etc/machine-id, type: File}") {
		t.Error("helm perf-helper DaemonSet does not mount the host /etc/machine-id read-only")
	}
}

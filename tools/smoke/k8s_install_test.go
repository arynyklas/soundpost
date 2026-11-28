// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"strings"
	"testing"
)

func TestParsePodReadiness(t *testing.T) {
	ready := `{"metadata":{"name":"soundpost-a-0","uid":"u1"},"spec":{"nodeName":"n1"},"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}}`
	p, err := parsePod([]byte(ready))
	if err != nil || !p.ready || p.node != "n1" || p.uid != "u1" {
		t.Fatalf("ready pod parsed as %+v, %v", p, err)
	}
	deleting := strings.Replace(ready, `"uid":"u1"`, `"uid":"u1","deletionTimestamp":"2026-01-01T00:00:00Z"`, 1)
	if p, _ = parsePod([]byte(deleting)); p.ready || !p.deleting {
		t.Fatalf("a terminating pod must not count as ready: %+v", p)
	}
	pending := `{"metadata":{"name":"x","uid":"u2"},"spec":{},"status":{"phase":"Pending","conditions":[{"type":"Ready","status":"True"}]}}`
	if p, _ = parsePod([]byte(pending)); p.ready {
		t.Fatalf("a pending pod must not count as ready: %+v", p)
	}
}

func TestCheckRenderedChartRefusesHostAccess(t *testing.T) {
	var b strings.Builder
	for _, id := range []string{"1", "2", "3"} {
		b.WriteString("---\nkind: StatefulSet\nspec:\n  replicas: 1\n  requiredDuringSchedulingIgnoredDuringExecution:\n  args: [--node-id=" + id + "]\n")
	}
	b.WriteString("---\nkind: PodDisruptionBudget\n---\nkind: Service\n---\nkind: Service\n")
	good := b.String()
	if _, err := checkRenderedChart(good); err != nil {
		t.Fatalf("good render refused: %v", err)
	}
	for _, bad := range []string{"hostPID: true", "privileged: true", "hostNetwork: true", "-----BEGIN PRIVATE KEY-----"} {
		if _, err := checkRenderedChart(good + "\n" + bad); err == nil {
			t.Fatalf("render containing %q accepted", bad)
		}
	}
}

func TestK8sValuesCarryDigestAndThreeMembers(t *testing.T) {
	v := k8sValues("registry.invalid/soundpost", "sha256:"+strings.Repeat("a", 64), "", "1Gi")
	if strings.Count(v, "pkiSecret:") != 3 || !strings.Contains(v, `digest: "sha256:`) || strings.Contains(v, "tag:") {
		t.Fatalf("values: %s", v)
	}
}

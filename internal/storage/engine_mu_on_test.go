// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build soundpost_diag

package storage

import (
	"strings"
	"testing"
	"time"
)

// The diagnostic engine mutex lists a long hold with its call site and a long wait with the site of the holder it waited for.
func TestEngineMuReportsSlowHoldsAndWaitsWithTheirSites(t *testing.T) {
	var m engineMu
	m.Lock()
	done := make(chan struct{})
	go func() {
		m.Lock()
		m.Unlock()
		close(done)
	}()
	time.Sleep(emuSlowWait + 100*time.Millisecond)
	m.Unlock()
	<-done
	rep := engineMuReport()
	slow, _ := rep["slow"].([]map[string]any)
	var hold, wait bool
	for _, ev := range slow {
		site, _ := ev["site"].(string)
		holder, _ := ev["holder_site"].(string)
		switch ev["kind"] {
		case "hold":
			hold = hold || strings.Contains(site, "TestEngineMuReportsSlowHoldsAndWaitsWithTheirSites")
		case "wait":
			wait = wait || strings.Contains(site, "TestEngineMuReportsSlowHoldsAndWaitsWithTheirSites") && strings.Contains(holder, "TestEngineMuReportsSlowHoldsAndWaitsWithTheirSites")
		}
	}
	if !hold || !wait {
		t.Fatalf("slow hold listed %v, slow wait listed %v: %v", hold, wait, slow)
	}
	if h, _ := rep["max_hold_ns"].(int64); time.Duration(h) < emuSlowWait {
		t.Fatalf("max hold %v", time.Duration(h))
	}
}

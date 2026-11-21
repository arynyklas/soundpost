// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"strings"
	"testing"
)

const hcShippedUnit = "../../deploy/systemd/soundpost-agent.service"

// The service the smoke runs differs from the shipped unit in exactly the lines
// it names, and every other line (the whole hardening block) is verbatim.
func TestHostCollectionUserUnitReplacesOnlyTheNamedLines(t *testing.T) {
	raw, err := os.ReadFile(hcShippedUnit)
	if err != nil {
		t.Fatal(err)
	}
	shipped := string(raw)
	derived, notes, err := hcDeriveUserUnit(shipped, "soundpost-agent-ab12cd34", "/work/unit-source.token", "/bind/soundpost-agent -config=/bind/agent.json", "/bind")
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 6 {
		t.Fatalf("replacements %q", notes)
	}
	replaced := func(line string) bool {
		for _, p := range []string{"User=", "Group=", "StateDirectory=", "LoadCredential=", "ExecStart=", "ProtectHome="} {
			if strings.HasPrefix(line, p) {
				return true
			}
		}
		return false
	}
	have := map[string]bool{}
	for _, l := range strings.Split(derived, "\n") {
		have[l] = true
	}
	for _, l := range strings.Split(shipped, "\n") {
		if !replaced(l) && l != "" && !have[l] {
			t.Errorf("a line of the shipped unit was lost: %q", l)
		}
	}
	for _, want := range []string{
		"StateDirectory=soundpost-agent-ab12cd34", "LoadCredential=source.token:/work/unit-source.token",
		"ExecStart=/bind/soundpost-agent -config=/bind/agent.json", "ProtectHome=tmpfs", "BindReadOnlyPaths=/bind",
		"ProtectSystem=strict", "NoNewPrivileges=yes", "CapabilityBoundingSet=", "SystemCallFilter=@system-service", "PrivateTmp=yes", "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
	} {
		if !have[want] {
			t.Errorf("derived unit lacks %q", want)
		}
	}
	var active []string
	for _, l := range strings.Split(derived, "\n") {
		if !strings.HasPrefix(l, "#") { // the shipped comments still describe the system install
			active = append(active, l)
		}
	}
	for _, gone := range []string{"User=soundpost-agent", "Group=soundpost-agent", "/usr/local/bin/soundpost-agent", "/etc/soundpost/agent", "ProtectHome=yes"} {
		if strings.Contains(strings.Join(active, "\n"), gone) {
			t.Errorf("derived unit still has %q", gone)
		}
	}
	// a change of the shipped unit that removes a replaced line must fail loudly
	if _, _, err := hcDeriveUserUnit(strings.Replace(shipped, "ProtectHome=yes\n", "", 1), "n", "/c", "/e", "/b"); err == nil {
		t.Error("a shipped unit without ProtectHome=yes was accepted")
	}
	if _, _, err := hcDeriveUserUnit(strings.Replace(shipped, "LoadCredential=", "#LoadCredential=", 1), "n", "/c", "/e", "/b"); err == nil {
		t.Error("a shipped unit without LoadCredential= was accepted")
	}
}

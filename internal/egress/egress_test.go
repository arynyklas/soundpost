// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package egress_test

import (
	"net/netip"
	"testing"

	"github.com/arynyklas/soundpost/internal/egress"
)

// [09.06x-W4 / M-5] The table both the providers and the scrape fetcher decide
// with. Their packages delegate to it, so these rows are the single place the
// ranges are pinned.
func TestAllowedDefaultTable(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "::", "10.0.0.1", "::ffff:10.0.0.1", "172.16.0.1", "192.168.0.1",
		"100.64.0.1", "169.254.169.254", "fe80::1", "fd00:ec2::254", "100.100.100.200", "168.63.129.16", "192.0.0.192",
		"224.0.0.1", "ff02::1", "255.255.255.255", "240.0.0.1", "fc00::1", "64:ff9b::7f00:1", "2002:7f00:1::1",
		"203.0.113.5", "198.51.100.1", "192.0.2.1", "198.18.0.1", "2001:db8::1", "fec0::1", "fe80::1%eth0",
	}
	for _, s := range blocked {
		if egress.Allowed(netip.MustParseAddr(s), nil) {
			t.Errorf("default table admits %s", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "172.15.255.255", "172.32.0.1", "11.0.0.1", "100.63.255.255", "100.128.0.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if !egress.Allowed(netip.MustParseAddr(s), nil) {
			t.Errorf("default table blocks public %s", s)
		}
	}
	if egress.Allowed(netip.Addr{}, nil) {
		t.Error("invalid address admitted")
	}
}

func TestAllowListLiftsOnlyDefaultBlockedRanges(t *testing.T) {
	allow := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("::ffff:192.168.0.0/112")}
	if !egress.ValidAllowList(allow) {
		t.Fatal("a private allow list is valid")
	}
	for s, want := range map[string]bool{"10.1.2.3": true, "::ffff:10.1.2.3": true, "192.168.4.4": true, "172.16.0.1": false, "127.0.0.1": false, "169.254.169.254": false, "100.64.0.1": false} {
		if got := egress.Allowed(netip.MustParseAddr(s), allow); got != want {
			t.Errorf("allow list: %s admitted=%v want %v", s, got, want)
		}
	}
	for _, bad := range []string{"127.0.0.0/8", "0.0.0.0/0", "169.254.0.0/16", "::/0", "fe80::/10"} {
		if egress.ValidAllowList([]netip.Prefix{netip.MustParsePrefix(bad)}) {
			t.Errorf("allow list %s covers a never-allowed range and was accepted", bad)
		}
	}
	if egress.ValidAllowList([]netip.Prefix{{}}) {
		t.Error("an invalid prefix was accepted")
	}
}

func TestExportedTablesAreCopies(t *testing.T) {
	n := egress.NeverAllowed()
	n[0] = netip.MustParsePrefix("1.2.3.0/24")
	if egress.NeverAllowed()[0] == n[0] {
		t.Fatal("NeverAllowed exposes the table")
	}
	b := egress.BlockedByDefault()
	b[0] = netip.MustParsePrefix("1.2.3.0/24")
	if egress.BlockedByDefault()[0] == b[0] {
		t.Fatal("BlockedByDefault exposes the table")
	}
}

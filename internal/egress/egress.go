// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package egress is the one table of outbound address ranges the product will
// not dial: the notification providers and the scrape fetcher both decide with
// it, so a fix to a range lands on both sides at once.
package egress

import "net/netip"

func prefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, v := range s {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}

// neverAllowed can not be lifted by any allow-list entry.
var neverAllowed = prefixes(
	"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
	"100.100.100.200/32", "168.63.129.16/32", "192.0.0.192/32",
	"::/96", "::1/128", "fe80::/10", "ff00::/8", "fd00:ec2::254/128", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16",
)

// blockedByDefault is lifted only by an explicit allow-list entry.
var blockedByDefault = prefixes(
	"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
	"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"100::/64", "2001::/32", "2001:2::/48", "2001:10::/28", "2001:db8::/32", "fc00::/7", "fec0::/10",
)

// NeverAllowed returns a copy of the ranges no allow-list entry can lift.
func NeverAllowed() []netip.Prefix { return append([]netip.Prefix(nil), neverAllowed...) }

// BlockedByDefault returns a copy of the ranges only an explicit allow-list
// entry lifts.
func BlockedByDefault() []netip.Prefix { return append([]netip.Prefix(nil), blockedByDefault...) }

// Normalize maps an IPv4-mapped IPv6 prefix of 96 bits or more to its IPv4 form.
func Normalize(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p
}

// ValidAllowList reports whether every allow-list prefix is well formed and
// clear of the never-allowed ranges.
func ValidAllowList(allow []netip.Prefix) bool {
	for _, a := range allow {
		a = Normalize(a)
		if !a.IsValid() || a.Addr().Zone() != "" {
			return false
		}
		for _, n := range neverAllowed {
			if a.Overlaps(n) {
				return false
			}
		}
	}
	return true
}

// Allowed reports whether a concrete address may be dialed: never-allowed
// ranges refuse first, an allow-list entry then admits, the default-blocked
// ranges and any remaining loopback, link-local, multicast or unspecified
// address refuse, everything else is admitted. An invalid or zoned address is
// refused.
func Allowed(a netip.Addr, allow []netip.Prefix) bool {
	if !a.IsValid() || a.Zone() != "" {
		return false
	}
	a = a.Unmap()
	for _, n := range neverAllowed {
		if n.Contains(a) {
			return false
		}
	}
	for _, n := range allow {
		if Normalize(n).Contains(a) {
			return true
		}
	}
	for _, n := range blockedByDefault {
		if n.Contains(a) {
			return false
		}
	}
	return !(a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLoopback())
}

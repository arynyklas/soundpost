// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// TrustedProxies is the set of peers allowed to say who the client is. Behind a reverse proxy
// every request arrives from the proxy's address, so a login throttle keyed on the peer would
// throttle all users together; keyed on a header any client can send, it would not throttle at
// all. The forwarded address is therefore read only when the peer is in this set, and then the
// rightmost X-Forwarded-For hop that is not itself a trusted proxy is the client (the hops to its
// left were supplied by the client and are never read). An empty set trusts nobody.
type TrustedProxies []netip.Prefix

// ParseTrustedProxies parses a comma-separated list of CIDRs; a bare address is a single host.
func ParseTrustedProxies(list string) (TrustedProxies, error) {
	var out TrustedProxies
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if p, err := netip.ParsePrefix(item); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: not a CIDR or address", item)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func (p TrustedProxies) contains(a netip.Addr) bool {
	a = a.Unmap()
	for _, prefix := range p {
		if prefix.Contains(a) {
			return true
		}
	}
	return false
}

func parseHop(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		return a, true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr(), true
	}
	return netip.Addr{}, false
}

// ClientAddr is the address a request's throttle and pending-login accounting are keyed on.
func (p TrustedProxies) ClientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, ok := parseHop(host)
	if !ok || !p.contains(peer) {
		return host
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, ok := parseHop(hops[i])
		if !ok {
			return host // a hop this proxy chain did not write: nothing to the left can be believed
		}
		if !p.contains(a) {
			return a.Unmap().String()
		}
	}
	return host
}

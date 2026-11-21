// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import "testing"

// [10.16-W4] The dialer's Control hook is the second check: it sees the address
// the kernel is about to connect to, after all resolution, so a name that
// resolved to an allowed answer cannot be rebound to a blocked one.
func TestScrapeEgressControlHookRefusesTheAddressAboutToBeDialed(t *testing.T) {
	p := EgressPolicy{}
	for _, c := range []struct {
		network, address string
		ok               bool
	}{
		{"tcp4", "8.8.8.8:443", true},
		{"tcp4", "127.0.0.1:443", false},
		{"tcp4", "10.1.2.3:80", false},
		{"tcp6", "[::1]:80", false},
		{"tcp4", "169.254.169.254:80", false},
		{"tcp4", "not-an-address", false},
		{"udp4", "8.8.8.8:53", false},
	} {
		if err := p.control(c.network, c.address, nil); (err == nil) != c.ok {
			t.Errorf("control(%s, %s) = %v, want ok=%v", c.network, c.address, err, c.ok)
		}
	}
}

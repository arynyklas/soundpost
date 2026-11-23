// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package gitlab

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/egress"
)

// Egress is the outbound network policy of the GitLab client. It is the policy of
// every notification webhook (internal/egress): loopback, private, link-local,
// unique-local, multicast, unspecified, CGNAT, reserved and cloud-metadata
// addresses, and IPv4-mapped forms of those, are refused unless an administrator
// allowed the private prefix; loopback, link-local, multicast, unspecified and
// metadata addresses can never be allowed.
type Egress struct {
	// AllowPrefixes lifts the block for explicitly named private prefixes.
	AllowPrefixes []netip.Prefix
	// Resolver resolves host names; nil means the system resolver.
	Resolver Resolver

	// loopbackOK is the test-only seam. It is unexported and nothing outside
	// _test.go files assigns it, so no configuration or wire input can enable it.
	loopbackOK bool
}

// Resolver resolves a host name to addresses.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

var (
	errEgressBlocked   = errors.New("gitlab: egress blocked")
	errBaseURLInvalid  = errors.New("gitlab: base url invalid")
	errEgressAllowList = errors.New("gitlab: invalid egress allow list")
)

// Validate refuses an allow list that names a never-allowed range.
func (p Egress) Validate() error {
	if !egress.ValidAllowList(p.AllowPrefixes) {
		return errEgressAllowList
	}
	return nil
}

func (p Egress) check(a netip.Addr) error {
	if p.loopbackOK && a.IsValid() && a.Zone() == "" && a.Unmap().IsLoopback() {
		return nil
	}
	if !egress.Allowed(a, p.AllowPrefixes) {
		return errEgressBlocked
	}
	return nil
}

// CheckHost refuses a literal address that is blocked before any connection is
// attempted. A name is checked when it is resolved, by the dialer.
func (p Egress) CheckHost(host string) error {
	if a, err := netip.ParseAddr(host); err == nil {
		return p.check(a)
	}
	return nil
}

// control sees the address the socket is about to connect to after all
// resolution, so DNS rebinding cannot reach a blocked address.
func (p Egress) control(network, address string, _ syscall.RawConn) error {
	switch network {
	case "tcp4", "tcp6":
	default:
		return errEgressBlocked
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return errEgressBlocked
	}
	return p.check(ap.Addr())
}

// dialContext resolves, validates every answer (any blocked answer refuses the
// whole name), then dials the validated address itself; the Control hook checks it
// a second time.
func (p Egress) dialContext(timeout time.Duration) func(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout, Control: p.control}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4", "tcp6":
		default:
			return nil, errEgressBlocked
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errEgressBlocked
		}
		var addrs []netip.Addr
		if ip, e := netip.ParseAddr(host); e == nil {
			addrs = []netip.Addr{ip}
		} else {
			var r Resolver = net.DefaultResolver
			if p.Resolver != nil {
				r = p.Resolver
			}
			if addrs, err = r.LookupNetIP(ctx, "ip", host); err != nil {
				return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("lookup failed")}
			}
		}
		if len(addrs) == 0 {
			return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("no addresses")}
		}
		for _, a := range addrs {
			if e := p.check(a); e != nil {
				return nil, e
			}
		}
		var last error
		for _, a := range addrs {
			conn, e := d.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
			if e == nil {
				return conn, nil
			}
			last = e
		}
		return nil, last
	}
}

// ValidBaseURL checks a GitLab base URL: https, a host, no credentials, query or
// fragment, an optional plain path (a relative URL root), and an address that is
// not a blocked literal. It returns the normalized URL (no trailing slash) and
// its host name. Names are resolved and checked at connection time.
func ValidBaseURL(raw string, p Egress) (base, host string, err error) {
	if len(raw) == 0 || len(raw) > 256 || strings.ContainsAny(raw, " \t\r\n\\") {
		return "", "", errBaseURLInvalid
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", "", errBaseURLInvalid
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	for i := range len(path) {
		c := path[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '/' || c == '-' || c == '_' || c == '.') {
			return "", "", errBaseURLInvalid
		}
	}
	if strings.Contains(path, "..") || strings.Contains(path, "//") {
		return "", "", errBaseURLInvalid
	}
	if e := p.CheckHost(u.Hostname()); e != nil {
		return "", "", e
	}
	return "https://" + u.Host + path, u.Hostname(), nil
}

// IsEgressBlocked reports whether err is an egress refusal.
func IsEgressBlocked(err error) bool { return errors.Is(err, errEgressBlocked) }

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package providers holds the real delivery adapters (SMTP, Telegram and the
// signed webhook) behind notify.Sender, with secret and egress controls. The
// notification worker never imports this package; the application composition
// binds the adapters to it.
//
// Every adapter shares four rules. A destination is only what the org-scoped
// registry resolves from the delivery's recipient ID. Secrets are read fresh
// for one attempt and never copied into an outcome, error or log: errors are
// mapped to closed codes and whatever a transport printed is discarded. Every
// connection is made by one egress dialer that validates the resolved address
// and the address actually dialed. Outcomes keep the delivery semantics: only
// a request that provably never left (or was refused) is a definite retry or
// terminal; anything that may have reached the provider is unknown.
package providers

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// SecretRef and SecretReader are the notify-owned seam; see notify.SecretReader.
type (
	SecretRef    = notify.SecretRef
	SecretReader = notify.SecretReader
)

// DestinationResolver resolves the destination of a delivery's recipient.
// *notify.Destinations implements it.
type DestinationResolver interface {
	Resolve(ctx context.Context, scope auth.Scope, d notify.Delivery, ch notify.Channel) (notify.Destination, error)
}

// Common is the configuration every adapter shares.
type Common struct {
	// Destinations is required: the only source of where to send.
	Destinations DestinationResolver
	// PublicOrigin is the configured public https origin used for links.
	PublicOrigin string
	// Egress is the outbound network policy.
	Egress EgressPolicy
	// Timeout bounds one attempt; zero means 15 seconds.
	Timeout time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

const (
	defaultTimeout   = 15 * time.Second
	maxResponseBytes = 64 << 10
	maxRetryAfter    = 24 * time.Hour
)

func (c Common) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return defaultTimeout
}

func (c Common) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// prepared validates the shared configuration and returns the normalized
// public origin (no trailing slash).
func (c Common) prepared() (string, error) {
	if c.Destinations == nil {
		return "", errors.New("providers: destinations are required")
	}
	if err := c.Egress.validate(); err != nil {
		return "", err
	}
	u, err := url.Parse(c.PublicOrigin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("providers: public origin must be an https origin")
	}
	return "https://" + u.Host, nil
}

// closed outcome codes (lowercase, notify.outcomeCode-safe)
const (
	codeEgressBlocked    = "egress_blocked"
	codeRedirectRefused  = "redirect_refused"
	codeConnectFailed    = "connect_failed"
	codeConnectTimeout   = "connect_timeout"
	codeTLSFailed        = "tls_failed"
	codeTimeout          = "timeout"
	codeCancelled        = "cancelled"
	codeTransport        = "transport_error"
	codeNoDestination    = "no_destination"
	codeDestInvalid      = "destination_invalid"
	codeDestDisabled     = "destination_disabled"
	codeScopeMismatch    = "scope_mismatch"
	codeSecretForbidden  = "secret_forbidden"
	codeSecretError      = "secret_unavailable"
	codeSecretMissing    = "secret_missing"
	codeHostNotAllowed   = "host_not_allowed"
	codeRateLimited      = "rate_limited"
	codeBadResponse      = "bad_response"
	codeTimestampMissing = "timestamp_unavailable"
)

func retry(code string, after time.Duration) notify.Outcome {
	return notify.Outcome{Kind: notify.OutcomeRetry, Code: code, RetryAfter: model.UnixNano(after)}
}
func terminal(code string) notify.Outcome {
	return notify.Outcome{Kind: notify.OutcomeTerminal, Code: code}
}
func unknown(code string) notify.Outcome {
	return notify.Outcome{Kind: notify.OutcomeUnknown, Code: code}
}

// destinationOutcome maps a registry failure to a closed outcome.
func destinationOutcome(err error) notify.Outcome {
	var f *model.Fault
	switch {
	case errors.Is(err, notify.ErrNoDestination):
		return terminal(codeNoDestination)
	case errors.Is(err, notify.ErrDestinationDisabled):
		return terminal(codeDestDisabled)
	case errors.Is(err, notify.ErrDestinationInvalid):
		return terminal(codeDestInvalid)
	case errors.As(err, &f) && f.Code == model.Forbidden:
		return terminal(codeScopeMismatch)
	}
	return retry("destination_lookup_failed", 0)
}

// secretOutcome maps a secret read failure to a closed outcome.
func secretOutcome(err error) notify.Outcome {
	var f *model.Fault
	if errors.As(err, &f) && f.Code == model.Forbidden {
		return terminal(codeSecretForbidden)
	}
	return retry(codeSecretError, 0)
}

// resolve resolves the destination and, when the destination has a secret,
// reads it. The reference is re-checked against the scope here as well, so a
// cross-organization reference never reaches the reader even if the resolver
// is wrong. need says a missing secret is a terminal configuration failure.
func resolve(ctx context.Context, c Common, secrets SecretReader, scope auth.Scope, d notify.Delivery, ch notify.Channel, need bool) (notify.Destination, []byte, *notify.Outcome) {
	fail := func(o notify.Outcome) (notify.Destination, []byte, *notify.Outcome) {
		return notify.Destination{}, nil, &o
	}
	if scope.OrgID() != d.Key.Org {
		return fail(terminal(codeScopeMismatch))
	}
	dest, err := c.Destinations.Resolve(ctx, scope, d, ch)
	if err != nil {
		return fail(destinationOutcome(err))
	}
	if dest.Org != scope.OrgID() || dest.Channel != ch {
		return fail(terminal(codeScopeMismatch))
	}
	if dest.Secret == nil {
		if need {
			return fail(terminal(codeSecretMissing))
		}
		return dest, nil, nil
	}
	if dest.Secret.Org != scope.OrgID() {
		return fail(terminal(codeSecretForbidden))
	}
	secret, err := secrets.Read(ctx, scope, *dest.Secret)
	if err != nil {
		return fail(secretOutcome(err))
	}
	if len(secret) == 0 {
		return fail(terminal(codeSecretMissing))
	}
	return dest, secret, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ---------------------------------------------------------------- egress

// EgressPolicy is the outbound network policy. The default blocks loopback,
// private, link-local, unique-local, multicast, unspecified, CGNAT,
// documentation/benchmark/reserved, cloud-metadata and IPv4-mapped or
// translated forms of those. Operators may explicitly allow-list prefixes of
// the otherwise-blocked private ranges (for an internal relay) and narrow each
// organization to named hosts; loopback, link-local, multicast, unspecified and
// metadata addresses can never be allow-listed.
type EgressPolicy struct {
	// AllowPrefixes lifts the block for explicitly named private prefixes.
	AllowPrefixes []netip.Prefix
	// OrgHosts, when it has an entry for an organization, restricts that
	// organization's destinations to exactly those host names or literals.
	OrgHosts map[model.ID][]string
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

var errEgressBlocked = errors.New("providers: egress blocked")

func mp(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, v := range s {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}

// neverAllowed can not be lifted by any allow-list entry.
var neverAllowed = mp(
	"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
	"100.100.100.200/32", "168.63.129.16/32", "192.0.0.192/32",
	"::/96", "::1/128", "fe80::/10", "ff00::/8", "fd00:ec2::254/128", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16",
)

// blockedByDefault is lifted only by an explicit allow-list entry.
var blockedByDefault = mp(
	"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
	"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"100::/64", "2001::/32", "2001:2::/48", "2001:10::/28", "2001:db8::/32", "fc00::/7", "fec0::/10",
)

func normPrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p
}

func (p EgressPolicy) validate() error {
	for _, a := range p.AllowPrefixes {
		a = normPrefix(a)
		if !a.IsValid() || a.Addr().Zone() != "" {
			return errors.New("providers: invalid egress allow prefix")
		}
		for _, n := range neverAllowed {
			if a.Overlaps(n) {
				return errors.New("providers: egress allow prefix covers a never-allowed range")
			}
		}
	}
	return nil
}

// check validates one concrete address. It is applied to every resolved
// address and, again, by the dialer's Control hook to the address the kernel is
// about to connect to.
func (p EgressPolicy) check(a netip.Addr) error {
	if !a.IsValid() || a.Zone() != "" {
		return errEgressBlocked
	}
	a = a.Unmap()
	if p.loopbackOK && a.IsLoopback() {
		return nil
	}
	for _, n := range neverAllowed {
		if n.Contains(a) {
			return errEgressBlocked
		}
	}
	for _, n := range p.AllowPrefixes {
		if normPrefix(n).Contains(a) {
			return nil
		}
	}
	for _, n := range blockedByDefault {
		if n.Contains(a) {
			return errEgressBlocked
		}
	}
	if a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLoopback() {
		return errEgressBlocked
	}
	return nil
}

// checkHost applies the per-organization host allow-list and rejects literal
// addresses that are blocked, before any connection is attempted.
func (p EgressPolicy) checkHost(org model.ID, host string) error {
	if hosts, ok := p.OrgHosts[org]; ok {
		allowed := false
		for _, h := range hosts {
			if strings.EqualFold(h, host) {
				allowed = true
				break
			}
		}
		if !allowed {
			return errHostNotAllowed
		}
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return p.check(a)
	}
	return nil
}

var errHostNotAllowed = errors.New("providers: host not allowed")

// control is net.Dialer.Control: it sees the address the socket is about to
// connect to after all resolution, so DNS rebinding cannot reach it.
func (p EgressPolicy) control(network, address string, _ syscall.RawConn) error {
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
// whole name), then dials the validated address itself, so the address that
// was checked is the address that is connected to. The Control hook checks
// it a second time.
func (p EgressPolicy) dialContext(timeout time.Duration) func(ctx context.Context, network, address string) (net.Conn, error) {
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

// ---------------------------------------------------------------- HTTP

var errRedirectRefused = errors.New("providers: redirect refused")

// newHTTPClient builds the only client adapters use. A supplied client
// contributes its timeout and TLS roots; its dialer, proxy and redirect policy
// are always replaced, and certificate verification can not be disabled.
func newHTTPClient(c Common, supplied *http.Client) (*http.Client, error) {
	var tr *http.Transport
	timeout := c.timeout()
	if supplied != nil {
		if supplied.Timeout > 0 {
			timeout = supplied.Timeout
		}
		switch t := supplied.Transport.(type) {
		case nil:
		case *http.Transport:
			tr = t.Clone()
		default:
			return nil, errors.New("providers: client transport must be *http.Transport")
		}
	}
	if tr == nil {
		tr = &http.Transport{}
	}
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		return nil, errors.New("providers: certificate verification can not be disabled")
	}
	if tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		tr.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	tr.Proxy = nil
	tr.DialContext = c.Egress.dialContext(timeout)
	tr.Dial = nil           //nolint:staticcheck
	tr.DialTLS = nil        //nolint:staticcheck
	tr.DialTLSContext = nil // the TLS handshake runs over the checked connection
	tr.DisableKeepAlives = true
	tr.MaxResponseHeaderBytes = 32 << 10
	tr.ResponseHeaderTimeout = timeout
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirectRefused
		},
	}, nil
}

// httpResult is one HTTP exchange. connected says a connection (including TLS)
// was established, so request bytes may have reached the receiver.
type httpResult struct {
	status    int
	header    http.Header
	body      []byte
	connected bool
	err       error
}

func roundTrip(client *http.Client, req *http.Request) httpResult {
	var connected atomic.Bool
	trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { connected.Store(true) }}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := client.Do(req)
	res := httpResult{connected: connected.Load()}
	if resp != nil {
		res.status, res.header = resp.StatusCode, resp.Header
		if err == nil {
			buf := make([]byte, 0, 512)
			tmp := make([]byte, 4096)
			for len(buf) <= maxResponseBytes {
				n, e := resp.Body.Read(tmp)
				buf = append(buf, tmp[:n]...)
				if e != nil {
					break
				}
			}
			if len(buf) > maxResponseBytes {
				buf = buf[:maxResponseBytes]
			}
			res.body = buf
		}
		_ = resp.Body.Close()
	}
	res.err = err
	return res
}

// transportOutcome classifies a failed exchange without printing the error
// (it can quote the URL, which may contain a bot token).
func transportOutcome(r httpResult, ctxErr error) (notify.Outcome, bool) {
	if r.err == nil {
		return notify.Outcome{}, false
	}
	switch {
	case errors.Is(r.err, errRedirectRefused):
		return terminal(codeRedirectRefused), true
	case errors.Is(r.err, errEgressBlocked):
		return terminal(codeEgressBlocked), true
	}
	timedOut := errors.Is(r.err, context.DeadlineExceeded) || errors.Is(ctxErr, context.DeadlineExceeded)
	var ne net.Error
	if errors.As(r.err, &ne) && ne.Timeout() {
		timedOut = true
	}
	if !r.connected {
		// Nothing was written: a definite non-delivery.
		switch {
		case timedOut:
			return retry(codeConnectTimeout, 0), true
		case isTLSError(r.err):
			return retry(codeTLSFailed, 0), true
		}
		return retry(codeConnectFailed, 0), true
	}
	// Connected: the request may have been written and accepted.
	switch {
	case timedOut:
		return unknown(codeTimeout), true
	case errors.Is(r.err, context.Canceled) || errors.Is(ctxErr, context.Canceled):
		return unknown(codeCancelled), true
	}
	return unknown(codeTransport), true
}

func isTLSError(err error) bool {
	var (
		rh  *tls.RecordHeaderError
		cv  *tls.CertificateVerificationError
		alr tls.AlertError
	)
	if errors.As(err, &rh) || errors.As(err, &cv) || errors.As(err, &alr) {
		return true
	}
	return strings.Contains(err.Error(), "tls:") || strings.Contains(err.Error(), "x509:")
}

// retryAfter parses Retry-After (delta seconds or HTTP date), capped.
func retryAfter(h http.Header, now time.Time) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	var d time.Duration
	if secs, err := strconv.ParseUint(v, 10, 32); err == nil {
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	if d < 0 {
		d = 0
	}
	if d > maxRetryAfter {
		d = maxRetryAfter
	}
	return d
}

// ---------------------------------------------------------------- rendering

var wording = map[notify.Kind]string{
	notify.KindOpen:        "opened",
	notify.KindReminder:    "reminder",
	notify.KindWorseImpact: "impact worsened",
	notify.KindRecovery:    "recovered",
	notify.KindResolution:  "resolved",
	notify.KindCurrent:     "state update",
	notify.KindQueue:       "queue update",
	notify.KindDigest:      "digest",
}

// safe keeps a typed enum value printable: lowercase ASCII, digits and _.-
func safe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '_' || r == '-' || r == '.' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func link(origin string, e notify.Entity) string {
	return origin + "/" + safe(string(e.Kind)) + "s/" + e.ID.String()
}

// render is the approved template: typed fields only. No telemetry, log, error
// message, source, replay or profile text exists in a Delivery, so none can
// reach an external channel.
func render(d notify.Delivery, origin string) (subject, text string) {
	t := d.Template
	what := wording[d.Key.Kind]
	if what == "" {
		what = safe(string(d.Key.Kind))
	}
	if d.Key.Kind == notify.KindReminder && t.Reminder > 0 {
		what += " " + strconv.FormatUint(uint64(t.Reminder), 10)
	}
	kind := safe(string(t.Entity.Kind))
	subject = fmt.Sprintf("[Soundpost] %s %s (severity %d)", kind, what, t.Severity)
	var b strings.Builder
	fmt.Fprintf(&b, "Soundpost %s %s\n", kind, what)
	fmt.Fprintf(&b, "Severity: %d  Tier: %s\n", t.Severity, safe(string(t.Tier)))
	ack := ""
	if t.Acknowledged {
		ack = " (acknowledged)"
	}
	fmt.Fprintf(&b, "Source: %s  Freshness: %s  Human: %s%s\n", safe(string(t.Source)), safe(string(t.Freshness)), safe(string(t.Human)), ack)
	ex := t.Explanation
	sat := ""
	if ex.Saturated {
		sat = "+"
	}
	rate := "unknown"
	if ex.Rate == notify.RateKnown {
		rate = fmt.Sprintf("%d.%02d%%", ex.RateBasisPoints/100, ex.RateBasisPoints%100)
	}
	fmt.Fprintf(&b, "Failures: %d%s  Rate: %s\n", ex.Failures, sat, rate)
	fmt.Fprintf(&b, "Link: %s\nDelivery: %s\n", link(origin, t.Entity), d.ID.String())
	return subject, b.String()
}

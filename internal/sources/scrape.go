// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"soundpost/internal/adapters/queryinput"
	"soundpost/internal/model"
	"soundpost/internal/policy"
)

// SecretRef names a locally stored secret; it is never a secret itself.
type SecretRef string

// SecretReader reads a secret by reference. FetchScrape reads it fresh for
// every fetch, uses it only to set the Authorization header, zeroes the bytes
// afterwards and never copies it into a result, error or log.
type SecretReader interface {
	ReadSecret(ctx context.Context, ref SecretRef) ([]byte, error)
}

// ScrapeAuth selects the Authorization scheme: "" none, "bearer" (the secret
// is the whole token) or "basic" (the secret is "user:password").
type ScrapeAuth string

const (
	ScrapeAuthNone   ScrapeAuth = ""
	ScrapeAuthBearer ScrapeAuth = "bearer"
	ScrapeAuthBasic  ScrapeAuth = "basic"
)

// TLSPolicy pins the trust roots of an https target. MinVersion is forced to
// TLS 1.2 and certificate verification can never be disabled.
type TLSPolicy struct {
	RootCAs    *x509.CertPool // nil => system roots
	ServerName string
}

// StalePolicy declares when stale markers are produced (Prometheus semantics).
type StalePolicy struct {
	// OnDisappear marks series present in Previous but absent from a successful
	// scrape stale at the scrape timestamp.
	OnDisappear bool
	// OnFailure marks every Previous series stale at the failure timestamp when
	// the fetch fails. Coverage is unknown either way.
	OnFailure bool
}

// SeriesRef is a series identity: exact metric name plus labels.
type SeriesRef struct {
	Name   string
	Labels model.Labels
}

// ScrapeTarget is one locally approved OpenMetrics endpoint. It is operator
// configuration, never a telemetry-supplied URL.
type ScrapeTarget struct {
	Alias    string // operator alias; the only identifier in results and health
	URL      string // absolute http(s) URL, no userinfo, no fragment
	Interval time.Duration
	Timeout  time.Duration // bounds the whole exchange: dial, TLS, headers, body
	MaxBytes int64         // response body cap, 1..64MiB; exceeding it is a failure
	TLS      TLSPolicy
	Egress   EgressPolicy
	Auth     ScrapeAuth
	Secret   SecretRef
	Secrets  SecretReader
	Profile  queryinput.InputProfile
	Stale    StalePolicy
	Previous []SeriesRef
	Clock    func() time.Time // nil => time.Now
}

// ScrapeStatus is the closed set of scrape outcomes.
type ScrapeStatus string

const (
	ScrapeOK                ScrapeStatus = "ok"
	ScrapeTimeout           ScrapeStatus = "timeout"
	ScrapeConnectionReset   ScrapeStatus = "connection_reset"
	ScrapeConnectionRefused ScrapeStatus = "connection_refused"
	ScrapeUnreachable       ScrapeStatus = "unreachable"
	ScrapeEgressDenied      ScrapeStatus = "egress_denied"
	ScrapeTLSFailed         ScrapeStatus = "tls_failed"
	ScrapeRedirectRefused   ScrapeStatus = "redirect_refused"
	ScrapeBadStatus         ScrapeStatus = "bad_status"
	ScrapeTooLarge          ScrapeStatus = "too_large"
	ScrapeDecodeFailed      ScrapeStatus = "decode_failed"
	ScrapeSecretUnavailable ScrapeStatus = "secret_unavailable"
	ScrapeCancelled         ScrapeStatus = "cancelled"
)

// ScrapeHealth is the source health of one fetch. It carries no URL, header,
// body or transport error text.
type ScrapeHealth struct {
	Status     ScrapeStatus
	HTTPStatus int
	Bytes      int64
	Duration   time.Duration
}

// Coverage says whether the scrape saw the whole target.
type Coverage string

const (
	CoverageComplete Coverage = "complete"
	CoverageUnknown  Coverage = "unknown"
)

// ScrapeResult is the product of one fetch. Batches are only produced here;
// the agent submits them through the real ingest route and waits for the receipt.
type ScrapeResult struct {
	Target   string
	At       model.UnixNano
	Health   ScrapeHealth
	Coverage Coverage
	Batches  []model.Batch
	// Seen is sorted and is carried by the caller as the next Previous. After a
	// failure with OnFailure markers it is empty; after a failure without
	// markers it is the old Previous unchanged.
	Seen         []SeriesRef
	Samples      uint64
	StaleMarkers uint64
}

const (
	scrapeMaxBytesCap  = 64 << 20
	scrapeStaleBits    = 0x7ff0000000000002
	scrapeBatchRecords = 512
	scrapeContentType  = "application/openmetrics-text"
)

var scrapeAliasRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func scrapeInvalid(detail string) error {
	f := model.Fail(model.Invalid)
	f.SafeDetail = detail
	return f
}

// FetchScrape performs one scrape of a locally approved target. err is non-nil
// only for invalid configuration or grant and for cancellation before the
// request; every runtime unavailability is a Health status with Coverage unknown.
func FetchScrape(ctx context.Context, grant policy.SourceGrant, target ScrapeTarget) (ScrapeResult, error) {
	clock := target.Clock
	if clock == nil {
		clock = time.Now
	}
	start := clock()
	u, err := target.validate()
	if err != nil {
		return ScrapeResult{}, err
	}
	scope, err := grant.Scope()
	if err != nil {
		return ScrapeResult{}, err
	}
	startNs := model.UnixNano(start.UnixNano())
	cfg := target.Profile
	cfg.DefaultTimestamp = startNs
	if cfg.MinTimestamp == 0 {
		cfg.MinTimestamp = model.UnixNano(start.Add(-24 * time.Hour).UnixNano())
	}
	if cfg.MaxTimestamp == 0 {
		cfg.MaxTimestamp = model.UnixNano(start.Add(time.Hour).UnixNano())
	}
	// Preflight: an empty exposition is rejected as malformed only after the
	// decoder has validated the profile and bound the grant, so any other error
	// is a configuration/grant fault and no request is made for it.
	if _, perr := queryinput.DecodeOpenMetrics(ctx, grant, strings.NewReader("# EOF\n"), cfg); perr != nil {
		var qe *queryinput.Error
		if !errors.As(perr, &qe) || qe.Reason != queryinput.ReasonMalformed {
			return ScrapeResult{}, perr
		}
	}
	if err := ctx.Err(); err != nil {
		return ScrapeResult{}, model.Fail(model.Cancelled)
	}

	began := time.Now()
	res := ScrapeResult{Target: target.Alias, At: startNs, Coverage: CoverageUnknown}
	body, health := target.exchange(ctx, u)
	health.Duration = time.Since(began)
	res.Health = health
	if health.Status == ScrapeOK {
		batches, derr := queryinput.DecodeOpenMetrics(ctx, grant, bytes.NewReader(body), cfg)
		if derr != nil {
			var qe *queryinput.Error
			switch {
			case !errors.As(derr, &qe):
				return ScrapeResult{}, derr
			case qe.Reason == queryinput.ReasonCancelled:
				res.Health.Status = ScrapeCancelled
			case qe.Reason == queryinput.ReasonMalformed && (qe.Detail == "empty_request" || qe.Detail == "no_samples"):
				batches, derr = nil, nil // a valid exposition with no samples
			default:
				res.Health.Status = ScrapeDecodeFailed
			}
		}
		if derr == nil {
			res.Coverage = CoverageComplete
			// The decoder derives batch and record IDs from the request body
			// only, so two scrapes of an unchanged exporter would reuse one
			// batch ID for different observed times (a receipt-ledger
			// conflict). The scrape time makes each scrape a distinct, still
			// retry-idempotent admission.
			scrapeRekey(target.Alias, startNs, batches)
			res.Batches = batches
			seen := map[string]SeriesRef{}
			for _, b := range batches {
				for _, r := range b.Records {
					m := r.Payload.Metric
					if r.Kind != model.Metric || m == nil || m.SampleKind == "stale" {
						continue
					}
					res.Samples++
					seen[scrapeSeriesKey(m.Name, m.Labels)] = SeriesRef{Name: m.Name, Labels: scrapeSortedLabels(m.Labels)}
				}
			}
			res.Seen = scrapeSortRefs(seen)
			if target.Stale.OnDisappear {
				var gone []SeriesRef
				for _, p := range scrapeDedupe(target.Previous) {
					if _, ok := seen[scrapeSeriesKey(p.Name, p.Labels)]; !ok {
						gone = append(gone, p)
					}
				}
				res.Batches = append(res.Batches, scrapeStaleBatches(target, cfg, scope.OrgID(), startNs, gone)...)
				res.StaleMarkers = uint64(len(gone))
			}
			return res, nil
		}
	}
	// failure path
	if target.Stale.OnFailure {
		at := model.UnixNano(clock().UnixNano())
		if at < startNs {
			at = startNs
		}
		prev := scrapeDedupe(target.Previous)
		res.Batches = scrapeStaleBatches(target, cfg, scope.OrgID(), at, prev)
		res.StaleMarkers = uint64(len(prev))
		res.Seen = nil
	} else {
		res.Seen = append([]SeriesRef(nil), target.Previous...)
	}
	return res, nil
}

func (t ScrapeTarget) validate() (*url.URL, error) {
	if !scrapeAliasRE.MatchString(t.Alias) {
		return nil, scrapeInvalid("scrape alias")
	}
	u, err := url.Parse(t.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, scrapeInvalid("scrape url")
	}
	if t.Interval < time.Second || t.Timeout <= 0 || t.Timeout > t.Interval {
		return nil, scrapeInvalid("scrape interval or timeout")
	}
	if t.MaxBytes < 1 || t.MaxBytes > scrapeMaxBytesCap {
		return nil, scrapeInvalid("scrape max bytes")
	}
	switch t.Auth {
	case ScrapeAuthNone:
		if t.Secret != "" || t.Secrets != nil {
			return nil, scrapeInvalid("scrape secret without auth")
		}
	case ScrapeAuthBearer, ScrapeAuthBasic:
		if t.Secret == "" || t.Secrets == nil {
			return nil, scrapeInvalid("scrape auth without secret")
		}
	default:
		return nil, scrapeInvalid("scrape auth")
	}
	if err := t.Egress.validate(); err != nil {
		return nil, scrapeInvalid("scrape egress")
	}
	return u, nil
}

// exchange performs the HTTP GET and returns the capped body of a healthy
// exchange. It never returns transport error text.
func (t ScrapeTarget) exchange(parent context.Context, u *url.URL) ([]byte, ScrapeHealth) {
	h := ScrapeHealth{}
	fail := func(s ScrapeStatus) ([]byte, ScrapeHealth) { h.Status = s; return nil, h }

	// A literal-IP destination is checked before anything else happens.
	if a, err := netip.ParseAddr(u.Hostname()); err == nil {
		if t.Egress.check(a) != nil {
			return fail(ScrapeEgressDenied)
		}
	}
	ctx, cancel := context.WithTimeout(parent, t.Timeout)
	defer cancel()

	var authz func(*http.Request)
	if t.Auth != ScrapeAuthNone {
		secret, err := t.Secrets.ReadSecret(ctx, t.Secret)
		if err != nil || len(secret) == 0 {
			scrapeZero(secret)
			return fail(ScrapeSecretUnavailable)
		}
		ok := true
		for _, c := range secret {
			if c < 0x20 || c == 0x7f {
				ok = false
			}
		}
		user, pass, hasColon := strings.Cut(string(secret), ":")
		token := string(secret)
		scrapeZero(secret)
		switch {
		case !ok || t.Auth == ScrapeAuthBasic && !hasColon:
			return fail(ScrapeSecretUnavailable)
		case t.Auth == ScrapeAuthBearer:
			authz = func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
		default:
			authz = func(r *http.Request) { r.SetBasicAuth(user, pass) }
		}
	}

	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            t.Egress.dialContext(t.Timeout),
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: t.TLS.RootCAs, ServerName: t.TLS.ServerName},
		TLSHandshakeTimeout:    t.Timeout,
		ResponseHeaderTimeout:  t.Timeout,
		MaxResponseHeaderBytes: 32 << 10,
		DisableKeepAlives:      true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		Timeout:       t.Timeout,
		Jar:           nil,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fail(ScrapeUnreachable)
	}
	req.Header.Set("Accept", "application/openmetrics-text; version=1.0.0")
	req.Header.Set("User-Agent", "soundpost-agent")
	if authz != nil {
		authz(req)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fail(scrapeClassify(parent, ctx, err))
	}
	defer resp.Body.Close()
	h.HTTPStatus = resp.StatusCode
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fail(ScrapeRedirectRefused)
	case resp.StatusCode != http.StatusOK:
		return fail(ScrapeBadStatus)
	}
	if resp.ContentLength > t.MaxBytes {
		return fail(ScrapeTooLarge)
	}
	mt, _, merr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if merr != nil || mt != scrapeContentType {
		return fail(ScrapeDecodeFailed)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, t.MaxBytes+1))
	h.Bytes = int64(len(body))
	if err != nil {
		return fail(scrapeClassify(parent, ctx, err))
	}
	if int64(len(body)) > t.MaxBytes {
		h.Bytes = t.MaxBytes
		return fail(ScrapeTooLarge)
	}
	h.Status = ScrapeOK
	return body, h
}

// scrapeClassify maps a transport error to the closed status set. The error
// text is inspected for classification only and is never stored.
func scrapeClassify(parent, ctx context.Context, err error) ScrapeStatus {
	switch {
	case parent.Err() != nil:
		return ScrapeCancelled
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return ScrapeTimeout
	case errors.Is(err, errScrapeEgress):
		return ScrapeEgressDenied
	}
	var (
		cve  *tls.CertificateVerificationError
		uae  x509.UnknownAuthorityError
		he   x509.HostnameError
		cie  x509.CertificateInvalidError
		rhe  tls.RecordHeaderError
		oe   *net.OpError
		errn syscall.Errno
	)
	switch {
	case errors.As(err, &cve), errors.As(err, &uae), errors.As(err, &he), errors.As(err, &cie), errors.As(err, &rhe),
		strings.Contains(err.Error(), "server gave HTTP response to HTTPS client"):
		return ScrapeTLSFailed
	case errors.As(err, &oe) && oe.Op == "remote error":
		return ScrapeTLSFailed
	}
	if errors.As(err, &errn) {
		switch uintptr(errn) {
		case uintptr(syscall.ECONNREFUSED), 10061:
			return ScrapeConnectionRefused
		case uintptr(syscall.ECONNRESET), uintptr(syscall.ECONNABORTED), 10054, 10053:
			return ScrapeConnectionReset
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ScrapeConnectionReset
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ScrapeTimeout
	}
	return ScrapeUnreachable
}

func scrapeZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ---------------------------------------------------------------- series

func scrapeSortedLabels(l model.Labels) model.Labels {
	out := append(model.Labels{}, l...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func scrapeSeriesKey(name string, l model.Labels) string {
	var sb strings.Builder
	sb.WriteString(name)
	for _, x := range scrapeSortedLabels(l) {
		sb.WriteByte(0)
		sb.WriteString(x.Name)
		sb.WriteByte(1)
		sb.WriteString(x.Value)
	}
	return sb.String()
}

func scrapeSortRefs(m map[string]SeriesRef) []SeriesRef {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]SeriesRef, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}

func scrapeDedupe(in []SeriesRef) []SeriesRef {
	m := make(map[string]SeriesRef, len(in))
	for _, r := range in {
		m[scrapeSeriesKey(r.Name, r.Labels)] = SeriesRef{Name: r.Name, Labels: scrapeSortedLabels(r.Labels)}
	}
	return scrapeSortRefs(m)
}

func scrapeID(domain string, parts ...[]byte) model.ID {
	h := sha256.New()
	for _, p := range append([][]byte{[]byte("soundpost.sources.scrape.v1"), []byte(domain)}, parts...) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	var id model.ID
	copy(id[:], h.Sum(nil))
	if id == (model.ID{}) {
		id[15] = 1
	}
	return id
}

func scrapeU64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

// scrapeRekey replaces the decoder's body-derived batch and record identifiers
// with ones that also bind the target alias and the scrape time.
func scrapeRekey(alias string, at model.UnixNano, batches []model.Batch) {
	for i := range batches {
		b := &batches[i]
		b.ID = scrapeID("batch", []byte(alias), scrapeU64(uint64(at)), b.ID[:])
		for j := range b.Records {
			r := &b.Records[j]
			r.ID = scrapeID("record", []byte(alias), scrapeU64(uint64(at)), r.ID[:])
		}
	}
}

// scrapeStaleBatches builds stale-marker batches grouped per owner slot with
// IDs derived from alias, timestamp and slot, so a retry is idempotent.
func scrapeStaleBatches(t ScrapeTarget, cfg queryinput.InputProfile, org model.ID, at model.UnixNano, series []SeriesRef) []model.Batch {
	if len(series) == 0 {
		return nil
	}
	unit := cfg.DefaultUnit
	if unit == "" {
		unit = "1"
	}
	res := cfg.Resource
	if res.Labels == nil {
		res.Labels = model.Labels{}
	}
	slots := map[uint16][]model.Record{}
	for _, s := range series {
		bits := model.FloatBits(scrapeStaleBits)
		rec := model.Record{
			ID:         scrapeID("record", []byte(t.Alias), scrapeU64(uint64(at)), []byte(scrapeSeriesKey(s.Name, s.Labels))),
			Kind:       model.Metric,
			ObservedAt: at,
			Resource:   res,
			Payload: model.Payload{Metric: &model.MetricPoint{
				Name: s.Name, Labels: scrapeSortedLabels(s.Labels), SampleKind: "stale", Value: &bits, Unit: unit, Type: "unknown",
			}},
		}
		slot, err := model.OwnerSlot(org, cfg.Project, cfg.Source, cfg.Producer, rec)
		if err != nil {
			continue
		}
		slots[slot] = append(slots[slot], rec)
	}
	order := make([]int, 0, len(slots))
	for s := range slots {
		order = append(order, int(s))
	}
	sort.Ints(order)
	var out []model.Batch
	for _, s := range order {
		recs := slots[uint16(s)]
		for chunk := 0; len(recs) > 0; chunk++ {
			n := min(len(recs), scrapeBatchRecords)
			var idx [6]byte
			binary.BigEndian.PutUint16(idx[:2], uint16(s))
			binary.BigEndian.PutUint32(idx[2:], uint32(chunk))
			out = append(out, model.Batch{
				Version: 1, Project: cfg.Project, Source: cfg.Source, Producer: cfg.Producer,
				ID:             scrapeID("batch", []byte(t.Alias), scrapeU64(uint64(at)), idx[:]),
				PolicyRevision: cfg.PolicyRevision, RouteSlot: uint16(s), Records: recs[:n:n],
			})
			recs = recs[n:]
		}
	}
	return out
}

// ---------------------------------------------------------------- egress

// The block below mirrors internal/notify/providers.EgressPolicy (same ranges,
// same any-blocked-answer refusal, same Control re-check). That package is not
// imported because its dialer and policy methods are unexported, it depends on
// notify/auth, and its loopback test seam is private; importing it would drag
// notification delivery into the host agent.

// Resolver resolves a host name to addresses.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// EgressPolicy is the outbound network policy of a scrape target. The default
// blocks loopback, private, link-local, unique-local, multicast, unspecified,
// CGNAT, documentation/reserved, cloud-metadata and IPv4-mapped or translated
// forms of those. AllowPrefixes may lift only the private ranges; loopback,
// link-local, multicast, unspecified and metadata addresses never can be.
type EgressPolicy struct {
	AllowPrefixes []netip.Prefix
	Resolver      Resolver // nil => system resolver

	// loopbackOK is the test-only seam: unexported, assigned only by _test.go.
	loopbackOK bool
}

var errScrapeEgress = errors.New("sources: scrape egress blocked")

func scrapeMP(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, v := range s {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}

// scrapeNeverAllowed can not be lifted by any allow-list entry.
var scrapeNeverAllowed = scrapeMP(
	"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
	"100.100.100.200/32", "168.63.129.16/32", "192.0.0.192/32",
	"::/96", "::1/128", "fe80::/10", "ff00::/8", "fd00:ec2::254/128", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16",
)

// scrapeBlockedByDefault is lifted only by an explicit allow-list entry.
var scrapeBlockedByDefault = scrapeMP(
	"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
	"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"100::/64", "2001::/32", "2001:2::/48", "2001:10::/28", "2001:db8::/32", "fc00::/7", "fec0::/10",
)

func scrapeNormPrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p
}

func (p EgressPolicy) validate() error {
	for _, a := range p.AllowPrefixes {
		a = scrapeNormPrefix(a)
		if !a.IsValid() || a.Addr().Zone() != "" {
			return errors.New("sources: invalid egress allow prefix")
		}
		for _, n := range scrapeNeverAllowed {
			if a.Overlaps(n) {
				return errors.New("sources: egress allow prefix covers a never-allowed range")
			}
		}
	}
	return nil
}

// check validates one concrete address. It is applied to every resolved
// address and again, by the dialer's Control hook, to the address the kernel is
// about to connect to.
func (p EgressPolicy) check(a netip.Addr) error {
	if !a.IsValid() || a.Zone() != "" {
		return errScrapeEgress
	}
	a = a.Unmap()
	if p.loopbackOK && a.IsLoopback() {
		return nil
	}
	for _, n := range scrapeNeverAllowed {
		if n.Contains(a) {
			return errScrapeEgress
		}
	}
	for _, n := range p.AllowPrefixes {
		if scrapeNormPrefix(n).Contains(a) {
			return nil
		}
	}
	for _, n := range scrapeBlockedByDefault {
		if n.Contains(a) {
			return errScrapeEgress
		}
	}
	if a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLoopback() {
		return errScrapeEgress
	}
	return nil
}

// control is net.Dialer.Control: it sees the address the socket is about to
// connect to after all resolution, so DNS rebinding cannot reach it.
func (p EgressPolicy) control(network, address string, _ syscall.RawConn) error {
	switch network {
	case "tcp4", "tcp6":
	default:
		return errScrapeEgress
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return errScrapeEgress
	}
	return p.check(ap.Addr())
}

// dialContext resolves, validates every answer (any blocked answer refuses the
// whole name), then dials the validated literal address, so the address that was
// checked is the address connected to. The Control hook checks it a second time.
func (p EgressPolicy) dialContext(timeout time.Duration) func(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout, Control: p.control}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4", "tcp6":
		default:
			return nil, errScrapeEgress
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errScrapeEgress
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

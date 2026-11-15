// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/adapters/queryinput"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/ingest"
	"github.com/arynyklas/soundpost/internal/model"
)

// Input bridge routes. They are explicitly scoped migration inputs for senders
// that already speak Prometheus remote-write or the Loki push API; they are not
// an upstream backend and promise no read compatibility. Authority comes only
// from the source credential: project, source, policy revision, producer and
// (when the source policy registers exactly one) the resource identities are
// taken from the authenticated source, never from the body. The body is decoded
// and partitioned by queryinput into one-slot child batches whose identities
// are derived from the request body, so the same request retried yields the
// same child batches and the ingest receipt ledger answers a retry with the
// receipt of the first durable admission.
const (
	adapterPrometheusWritePath = "/adapters/v1/prometheus/write"
	adapterLokiPushPath        = "/adapters/v1/loki/push"
	adapterConditionsPath      = "/adapters/v1/conditions"
)

// InputAdmitter is the C03 admission seam the bridge needs. *ingest.Service is
// the production implementation; tests wrap it to lose a child response.
type InputAdmitter interface {
	ResolveSource(ctx context.Context, c ingest.SourceCredential, b ingest.Batch) (ingest.SourceGrant, error)
	Admit(ctx context.Context, g ingest.SourceGrant, b ingest.Batch) (ingest.Receipt, error)
}

// InputAdapterConfig bounds and pins the bridge. The zero value is valid: the
// default limits, a 7 day backfill and 1 hour future window, native histograms
// preserved, and exemplars and HELP text rejected (they have no native home;
// choosing otherwise is an explicit deployment decision).
type InputAdapterConfig struct {
	Now        func() time.Time
	Limits     queryinput.Limits
	MaxAge     time.Duration
	MaxFuture  time.Duration
	Histograms queryinput.HistogramMode
	Exemplars  queryinput.ExemplarMode
	Help       queryinput.HelpMode
}

func (c InputAdapterConfig) resolved() InputAdapterConfig {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Limits == (queryinput.Limits{}) {
		c.Limits = queryinput.DefaultLimits()
	}
	if c.MaxAge <= 0 {
		c.MaxAge = 7 * 24 * time.Hour
	}
	if c.MaxFuture <= 0 {
		c.MaxFuture = time.Hour
	}
	if c.Histograms == "" {
		c.Histograms = queryinput.HistogramsPreserve
	}
	if c.Exemplars == "" {
		c.Exemplars = queryinput.ExemplarsReject
	}
	if c.Help == "" {
		c.Help = queryinput.HelpReject
	}
	return c
}

type inputBridge struct {
	auth *auth.Service
	in   InputAdmitter
	cfg  InputAdapterConfig
}

// RegisterInputAdapterRoutes mounts the migration input bridges.
func RegisterInputAdapterRoutes(mux *http.ServeMux, a *auth.Service, in InputAdmitter, cfg InputAdapterConfig) {
	b := &inputBridge{auth: a, in: in, cfg: cfg.resolved()}
	mux.HandleFunc("POST "+adapterPrometheusWritePath, b.handle("prometheus_write", b.decodeRemoteWrite))
	mux.HandleFunc("POST "+adapterLokiPushPath, b.handle("loki_push", b.decodeLokiPush))
	mux.HandleFunc("POST "+adapterConditionsPath, b.handle("conditions", b.decodeConditions))
}

// adapterChild is the per-child-batch part of a bridge reply. BatchID is the
// retry identity: a retried source request produces the same BatchIDs.
type adapterChild struct {
	BatchID   model.ID       `json:"batch_id"`
	RouteSlot uint16         `json:"route_slot"`
	Records   int            `json:"records"`
	Status    string         `json:"status"`
	Receipt   *model.Receipt `json:"receipt,omitempty"`
	Fault     *adapterFault  `json:"fault,omitempty"`
}
type adapterFault struct {
	Code      model.Code `json:"code"`
	Retryable bool       `json:"retryable"`
	Detail    string     `json:"detail"`
}
type adapterReply struct {
	Version  uint16         `json:"version"`
	Adapter  string         `json:"adapter"`
	Admitted int            `json:"admitted"`
	Failed   int            `json:"failed"`
	Children []adapterChild `json:"children"`
}
type adapterFailure struct {
	model.Fault
	Adapter  string         `json:"adapter"`
	Admitted int            `json:"admitted"`
	Failed   int            `json:"failed"`
	Children []adapterChild `json:"children"`
}

const (
	childAdmitted     = "admitted"
	childFailed       = "failed"
	childNotAttempted = "not_attempted"
)

type adapterDecoder func(ctx context.Context, w http.ResponseWriter, r *http.Request, grant ingest.SourceGrant, p queryinput.InputProfile, src model.SourceAuthority) ([]ingest.Batch, error)

// adapterCredential accepts only a bearer source credential. The bridge routes
// are for server-side senders: a cookie, a browser source header or an Origin is
// refused before any credential is looked at.
func adapterCredential(a *auth.Service, r *http.Request) (auth.SourceCredential, error) {
	if r.Header.Get("Origin") != "" || r.Header.Get("X-Soundpost-Source") != "" {
		return auth.SourceCredential{}, model.Fail(model.Forbidden)
	}
	return sourceCredential(a, r)
}

func (b *inputBridge) handle(adapter string, decode adapterDecoder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cred, err := adapterCredential(b.auth, r)
		if err != nil {
			ingestReply(w, r, nil, err)
			return
		}
		src, err := b.auth.SourceAuthority(r.Context(), cred, true)
		if err != nil {
			ingestReply(w, r, nil, err)
			return
		}
		profile, err := b.profile(r, src)
		if err != nil {
			ingestReply(w, r, nil, err)
			return
		}
		probe := ingest.Batch{Project: src.Project, Source: src.ID, PolicyRevision: src.Policy.Revision}
		grant, err := b.in.ResolveSource(r.Context(), cred, probe)
		if err != nil {
			ingestReply(w, r, nil, err)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, b.cfg.Limits.MaxCompressedBytes+2)
		batches, err := decode(r.Context(), w, r, grant, profile, src)
		if err != nil {
			ingestReply(w, r, nil, err)
			return
		}
		children, admitted := b.admit(r.Context(), cred, batches)
		var ack func(http.Header)
		if adapter == "prometheus_write" && remoteWriteVersion(r) == queryinput.RemoteWriteV2 {
			ack = remoteWriteWritten(batches)
		}
		b.reply(w, r, adapter, children, admitted, ack)
	}
}

// profile derives the input profile from the authenticated source alone.
func (b *inputBridge) profile(r *http.Request, src model.SourceAuthority) (queryinput.InputProfile, error) {
	resource, err := adapterResource(r, src.Policy.Resources)
	if err != nil {
		return queryinput.InputProfile{}, err
	}
	producer := src.CredentialID
	if producer == (model.ID{}) {
		producer = src.ID
	}
	now := b.cfg.Now()
	return queryinput.InputProfile{
		Project: src.Project, Source: src.ID, Producer: producer, PolicyRevision: src.Policy.Revision, Resource: resource,
		Limits:       b.cfg.Limits,
		MinTimestamp: model.UnixNano(now.Add(-b.cfg.MaxAge).UnixNano()), MaxTimestamp: model.UnixNano(now.Add(b.cfg.MaxFuture).UnixNano()),
		DefaultTimestamp: model.UnixNano(now.UnixNano()),
		Names:            queryinput.NamesStrict, OutOfOrder: queryinput.OutOfOrderSort,
		Histograms: b.cfg.Histograms, Exemplars: b.cfg.Exemplars, Help: b.cfg.Help,
	}, nil
}

// adapterResource names the resource of every record of a request: an explicit
// X-Soundpost-Service/-Environment/-Build/-Instance header, or the only entry
// of the source policy's registry. Anything else is ambiguous and refused; the
// policy registry check at admission still decides what is allowed.
func adapterResource(r *http.Request, reg model.ResourceRegistry) (model.Resource, error) {
	one := func(name string) (string, bool, error) {
		v := r.Header.Values(name)
		if len(v) > 1 {
			return "", false, model.Fail(model.Invalid)
		}
		if len(v) == 0 || v[0] == "" {
			return "", false, nil
		}
		return v[0], true, nil
	}
	id := func(name string, registered []model.ID) (model.ID, error) {
		v, set, err := one(name)
		if err != nil {
			return model.ID{}, err
		}
		if set {
			parsed, perr := model.ParseID(v)
			if perr != nil {
				return model.ID{}, model.Fail(model.Invalid)
			}
			return parsed, nil
		}
		if len(registered) == 1 {
			return registered[0], nil
		}
		return model.ID{}, model.Fail(model.Invalid)
	}
	var res model.Resource
	var err error
	if res.Service, err = id("X-Soundpost-Service", reg.Services); err != nil {
		return res, err
	}
	if res.Environment, err = id("X-Soundpost-Environment", reg.Environments); err != nil {
		return res, err
	}
	if res.Build, err = id("X-Soundpost-Build", reg.Builds); err != nil {
		return res, err
	}
	v, set, err := one("X-Soundpost-Instance")
	switch {
	case err != nil:
		return res, err
	case set:
		res.Instance = v
	case len(reg.Instances) == 1:
		res.Instance = reg.Instances[0]
	default:
		return res, model.Fail(model.Invalid)
	}
	res.Labels = model.Labels{}
	return res, nil
}

// admit admits every child batch of one source request in order, each under a
// freshly resolved grant. A failing child does not stop the others (they are
// durable progress that a retry will find already admitted); an authority or
// cancellation failure does, because every later child would fail the same way.
func (b *inputBridge) admit(ctx context.Context, cred auth.SourceCredential, batches []ingest.Batch) ([]adapterChild, int) {
	children := make([]adapterChild, len(batches))
	admitted := 0
	stop := false
	for i := range batches {
		batch := batches[i]
		child := adapterChild{BatchID: batch.ID, RouteSlot: batch.RouteSlot, Records: len(batch.Records), Status: childNotAttempted}
		if !stop {
			grant, err := b.in.ResolveSource(ctx, cred, batch)
			var receipt ingest.Receipt
			if err == nil {
				receipt, err = b.in.Admit(ctx, grant, batch)
			}
			if err == nil {
				child.Status, child.Receipt = childAdmitted, &receipt
				admitted++
			} else {
				f := faultOf(err)
				status := ingestStatus(f.Code)
				child.Status = childFailed
				child.Fault = &adapterFault{Code: f.Code, Retryable: status == 429 || status == 503, Detail: f.SafeDetail}
				switch f.Code {
				case model.Unauthenticated, model.Forbidden, model.Stale, model.Cancelled:
					stop = true
				}
			}
			if ctx.Err() != nil {
				stop = true
			}
		}
		children[i] = child
	}
	return children, admitted
}

func faultOf(err error) *model.Fault {
	var f *model.Fault
	if errors.As(err, &f) {
		return f
	}
	return model.Fail(model.Unavailable)
}

// reply ACKs only when every child is durable (ack, when set, adds the sender's
// written-count headers). Otherwise it answers with the retryable status of the
// first retryable child failure (a sender retries the whole request and finds the
// admitted children already receipted), or, when every failure is final, with the
// first failure's status. The body names every child with its retry identity and
// receipt or fault.
func (b *inputBridge) reply(w http.ResponseWriter, r *http.Request, adapter string, children []adapterChild, admitted int, ack func(http.Header)) {
	failed := len(children) - admitted
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if failed == 0 {
		if ack != nil {
			ack(w.Header())
		}
		_ = json.NewEncoder(w).Encode(adapterReply{Version: 1, Adapter: adapter, Admitted: admitted, Children: children})
		return
	}
	var first *adapterFault
	for i := range children {
		f := children[i].Fault
		if f == nil {
			continue
		}
		if f.Retryable {
			first = f
			break
		}
		if first == nil {
			first = f
		}
	}
	if first == nil {
		first = &adapterFault{Code: model.Unavailable, Retryable: true, Detail: string(model.Unavailable)}
	}
	status := ingestStatus(first.Code)
	if status == 429 || status == 503 {
		w.Header().Set("Retry-After", "1")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(adapterFailure{
		Fault:   model.Fault{Code: first.Code, Retryable: first.Retryable, SafeDetail: first.Detail, RequestID: model.RequestCorrelationID(r.Context(), model.ID{})},
		Adapter: adapter, Admitted: admitted, Failed: failed, Children: children,
	})
}

// remoteWriteVersion is the wire version a request's Content-Type selects.
func remoteWriteVersion(r *http.Request) queryinput.WireVersion {
	if _, params, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && params["proto"] == "io.prometheus.write.v2.Request" {
		return queryinput.RemoteWriteV2
	}
	return queryinput.RemoteWriteV1
}

// remoteWriteWritten reports, as the v2 protocol's response headers, how many
// samples, histograms and exemplars the admitted batches hold.
func remoteWriteWritten(batches []ingest.Batch) func(http.Header) {
	var samples, histograms, exemplars int
	for i := range batches {
		for j := range batches[i].Records {
			m := batches[i].Records[j].Payload.Metric
			if m == nil {
				continue
			}
			if m.Histogram != nil {
				histograms++
			} else {
				samples++
			}
			if m.ExemplarTrace != nil {
				exemplars++
			}
		}
	}
	return func(h http.Header) {
		h.Set("X-Prometheus-Remote-Write-Samples-Written", strconv.Itoa(samples))
		h.Set("X-Prometheus-Remote-Write-Histograms-Written", strconv.Itoa(histograms))
		h.Set("X-Prometheus-Remote-Write-Exemplars-Written", strconv.Itoa(exemplars))
	}
}

func (b *inputBridge) decodeRemoteWrite(ctx context.Context, _ http.ResponseWriter, r *http.Request, grant ingest.SourceGrant, p queryinput.InputProfile, _ model.SourceAuthority) ([]ingest.Batch, error) {
	mt, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/x-protobuf" || !strings.EqualFold(r.Header.Get("Content-Encoding"), "snappy") {
		return nil, model.Fail(model.Unsupported)
	}
	version := queryinput.RemoteWriteV1
	switch params["proto"] {
	case "", "prometheus.WriteRequest":
	case "io.prometheus.write.v2.Request":
		version = queryinput.RemoteWriteV2
	default:
		return nil, model.Fail(model.Unsupported)
	}
	return queryinput.DecodeRemoteWrite(ctx, grant, version, r.Body, p)
}

func (b *inputBridge) decodeLokiPush(ctx context.Context, _ http.ResponseWriter, r *http.Request, grant ingest.SourceGrant, p queryinput.InputProfile, src model.SourceAuthority) ([]ingest.Batch, error) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return nil, model.Fail(model.Unsupported)
	}
	encoding := strings.ToLower(r.Header.Get("Content-Encoding"))
	var enc queryinput.Encoding
	switch {
	case mt == "application/json" && (encoding == "" || encoding == "identity"):
		enc = queryinput.EncodingJSON
	case mt == "application/json" && encoding == "gzip":
		enc = queryinput.EncodingJSONGzip
	case mt == "application/x-protobuf" && encoding == "snappy":
		enc = queryinput.EncodingProtobufSnappy
	default:
		return nil, model.Fail(model.Unsupported)
	}
	mapping, err := lokiMapping(r, src, enc)
	if err != nil {
		return nil, err
	}
	p.Loki = mapping
	return queryinput.DecodeLokiPush(ctx, grant, r.Body, p)
}

// decodeConditions accepts the closed, versioned condition webhook (JSON only;
// see queryinput.DecodeConditions for the schema). It carries condition events,
// never arbitrary source text, and admits them as C04 condition records.
func (b *inputBridge) decodeConditions(ctx context.Context, _ http.ResponseWriter, r *http.Request, grant ingest.SourceGrant, p queryinput.InputProfile, _ model.SourceAuthority) ([]ingest.Batch, error) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	encoding := strings.ToLower(r.Header.Get("Content-Encoding"))
	if err != nil || mt != "application/json" || (encoding != "" && encoding != "identity") {
		return nil, model.Fail(model.Unsupported)
	}
	return queryinput.DecodeConditions(ctx, grant, r.Body, p)
}

// lokiMapping binds a push to one registered log template: X-Soundpost-Template
// (+ -Template-Revision), or the only template of the source policy. The line
// field defaults to "line"; X-Soundpost-Metadata-Fields lists the template
// fields that structured metadata may fill. The template itself is validated
// by the source policy at admission, so a header can never select what the
// source is not allowed to emit.
func lokiMapping(r *http.Request, src model.SourceAuthority, enc queryinput.Encoding) (queryinput.LokiMapping, error) {
	one := func(name string) (string, error) {
		v := r.Header.Values(name)
		if len(v) > 1 {
			return "", model.Fail(model.Invalid)
		}
		if len(v) == 0 {
			return "", nil
		}
		return v[0], nil
	}
	m := queryinput.LokiMapping{Encoding: enc}
	id, err := one("X-Soundpost-Template")
	if err != nil {
		return m, err
	}
	revision, err := one("X-Soundpost-Template-Revision")
	if err != nil {
		return m, err
	}
	switch {
	case id != "":
		m.TemplateID = id
		n, perr := strconv.ParseUint(revision, 10, 32)
		if perr != nil || n == 0 {
			return m, model.Fail(model.Invalid)
		}
		m.TemplateRevision = model.Revision(n)
	case len(src.Policy.Templates) == 1:
		m.TemplateID, m.TemplateRevision = src.Policy.Templates[0].ID, src.Policy.Templates[0].Revision
	default:
		return m, model.Fail(model.Invalid)
	}
	if m.LineField, err = one("X-Soundpost-Line-Field"); err != nil {
		return m, err
	}
	if m.LineField == "" {
		m.LineField = "line"
	}
	fields, err := one("X-Soundpost-Metadata-Fields")
	if err != nil {
		return m, err
	}
	if fields != "" {
		m.MetadataFields = strings.Split(fields, ",")
	}
	return m, nil
}

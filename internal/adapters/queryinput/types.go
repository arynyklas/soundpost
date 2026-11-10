// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package queryinput holds isolated development/migration translators that turn
// external wire formats (OpenMetrics text, remote-write v1/v2, Loki push) into
// Soundpost's own admission batches. No external schema type crosses this
// package boundary: decoders return ingest.Batch values and typed *Error faults,
// and every lossy or unrepresentable input is rejected or counted explicitly.
package queryinput

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sort"
	"strings"
	"unicode/utf8"

	"soundpost/internal/ingest"
	"soundpost/internal/model"
	"soundpost/internal/policy"
)

// WireVersion selects the remote-write protobuf message.
type WireVersion uint8

const (
	// RemoteWriteV1 is prometheus.WriteRequest.
	RemoteWriteV1 WireVersion = 1
	// RemoteWriteV2 is io.prometheus.write.v2.Request.
	RemoteWriteV2 WireVersion = 2
)

// Reason is the closed set of typed rejection reasons. Callers branch on it; the
// detail text of an Error never contains input content.
type Reason string

const (
	ReasonMalformed       Reason = "malformed"
	ReasonTooLarge        Reason = "too_large"
	ReasonLimit           Reason = "limit_exceeded"
	ReasonDuplicateLabel  Reason = "duplicate_label"
	ReasonInvalidName     Reason = "invalid_name"
	ReasonTimestampRange  Reason = "timestamp_out_of_range"
	ReasonOutOfOrder      Reason = "out_of_order"
	ReasonConflict        Reason = "conflicting_duplicate"
	ReasonUnrepresentable Reason = "unrepresentable"
	ReasonScope           Reason = "scope_mismatch"
	ReasonCompression     Reason = "malformed_compression"
	ReasonProfile         Reason = "invalid_profile"
	ReasonCancelled       Reason = "cancelled"
)

func (r Reason) code() model.Code {
	switch r {
	case ReasonTooLarge, ReasonLimit:
		return model.TooLarge
	case ReasonConflict:
		return model.Conflict
	case ReasonUnrepresentable:
		return model.Unsupported
	case ReasonScope:
		return model.Forbidden
	case ReasonCancelled:
		return model.Cancelled
	}
	return model.Invalid
}

// Error is the typed failure of every translator. Unwrap yields the matching
// *model.Fault so callers that classify by model.Code keep working.
type Error struct {
	Format string
	Reason Reason
	Detail string
}

func (e *Error) Error() string {
	s := "queryinput " + e.Format + ": " + string(e.Reason)
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// Unwrap returns the model fault class for this reason.
func (e *Error) Unwrap() error {
	f := model.Fail(e.Reason.code())
	f.SafeDetail = string(e.Reason)
	return f
}

func fail(format string, r Reason, detail string) *Error {
	return &Error{Format: format, Reason: r, Detail: detail}
}

const (
	fmtOpenMetrics = "openmetrics"
	fmtRWv1        = "remote_write_v1"
	fmtRWv2        = "remote_write_v2"
	fmtLoki        = "loki_push"
	fmtNormalize   = "normalize"
)

// Closed vocabularies pinned by the profile.
type (
	// NameMode selects metric/label/stream name validation.
	NameMode string
	// OutOfOrderMode decides what happens when one series arrives out of order.
	OutOfOrderMode string
	// HistogramMode decides whether native histograms are accepted.
	HistogramMode string
	// ExemplarMode decides what happens to exemplars.
	ExemplarMode string
	// HelpMode decides what happens to HELP text, which has no native home.
	HelpMode string
	// Encoding is the Loki push body encoding.
	Encoding string
)

const (
	// NamesStrict requires [a-zA-Z_:][a-zA-Z0-9_:]* metric and [a-zA-Z_][a-zA-Z0-9_]* label names.
	NamesStrict NameMode = "strict"
	// NamesUTF8 allows any nonempty valid UTF-8 name without NUL, CR or LF.
	NamesUTF8 NameMode = "utf8"

	// OutOfOrderSort stably sorts samples of each series by timestamp.
	OutOfOrderSort OutOfOrderMode = "sort"
	// OutOfOrderReject rejects a request whose series is not in timestamp order.
	OutOfOrderReject OutOfOrderMode = "reject"

	// HistogramsPreserve keeps native histograms exactly.
	HistogramsPreserve HistogramMode = "preserve"
	// HistogramsReject rejects any native histogram input.
	HistogramsReject HistogramMode = "reject"

	// ExemplarsReject rejects any input carrying an exemplar: the native model
	// stores only a trace/span link, never the exemplar value or timestamp.
	ExemplarsReject ExemplarMode = "reject"
	// ExemplarsTraceLink keeps trace_id/span_id and counts the discarded value,
	// timestamp and other labels in the report.
	ExemplarsTraceLink ExemplarMode = "trace_link"

	// HelpReject rejects input that carries HELP text.
	HelpReject HelpMode = "reject"
	// HelpDiscard drops HELP text and counts it in the report.
	HelpDiscard HelpMode = "discard"

	// EncodingJSON is a plain Loki JSON push body.
	EncodingJSON Encoding = "json"
	// EncodingJSONGzip is a gzip-compressed Loki JSON push body.
	EncodingJSONGzip Encoding = "json_gzip"
	// EncodingProtobufSnappy is the snappy-block-compressed logproto.PushRequest.
	EncodingProtobufSnappy Encoding = "protobuf_snappy"
)

// Report keys. The set is closed so a report stays bounded reason/count data.
const (
	ReportExactDuplicateCollapsed = "exact_duplicate_collapsed"
	ReportLabelsSorted            = "labels_sorted"
	ReportEmptyLabelDropped       = "empty_label_value_dropped"
	ReportOutOfOrderSorted        = "out_of_order_sorted"
	ReportHelpDiscarded           = "help_text_discarded"
	ReportExemplarDetailDiscarded = "exemplar_value_timestamp_labels_discarded"
	ReportTypeMappedUnknown       = "type_mapped_to_unknown"
	ReportCreatedUnmatched        = "created_timestamp_without_series"
	ReportMetadataUnused          = "metadata_without_series"
	ReportStaleHistogramAsStale   = "stale_histogram_marker_as_stale_sample"
	ReportCreatedApplied          = "created_timestamp_applied"
)

// NormalizationReport is bounded reason/count data; it never holds content.
type NormalizationReport struct {
	Counts map[string]uint64
}

func (r *NormalizationReport) add(key string, n uint64) {
	if n == 0 {
		return
	}
	if r.Counts == nil {
		r.Counts = map[string]uint64{}
	}
	r.Counts[key] += n
}

// Count returns the number of times key was recorded.
func (r NormalizationReport) Count(key string) uint64 { return r.Counts[key] }

func (r *NormalizationReport) merge(o NormalizationReport) {
	for k, v := range o.Counts {
		r.add(k, v)
	}
}

// Limits bounds every allocation a decoder makes on behalf of one request.
type Limits struct {
	MaxCompressedBytes int64
	MaxDecodedBytes    int64
	MaxSeries          int
	MaxSamples         int
	MaxLabels          int
	MaxLabelNameBytes  int
	MaxLabelValueBytes int
	MaxLineBytes       int
	MaxStreams         int
	MaxBuckets         int
}

const (
	hardMaxBody        = 64 << 20
	hardMaxLineBytes   = 4096 // model.Scalar string cap
	hardMaxLabels      = 256
	maxRecordsPerBatch = 512
	maxBatchBytes      = 3 << 20
	maxRecordBytes     = 256 << 10
)

// DefaultLimits is a conservative starting point for a bounded migration bridge.
func DefaultLimits() Limits {
	return Limits{
		MaxCompressedBytes: 4 << 20,
		MaxDecodedBytes:    16 << 20,
		MaxSeries:          20000,
		MaxSamples:         200000,
		MaxLabels:          64,
		MaxLabelNameBytes:  256,
		MaxLabelValueBytes: 2048,
		MaxLineBytes:       hardMaxLineBytes,
		MaxStreams:         1000,
		MaxBuckets:         1024,
	}
}

// LokiMapping binds Loki pushes to one registered log template. The adapter
// never invents a template: lines go into LineField, structured metadata keys
// must be named in MetadataFields (they are template fields), anything else is
// rejected as unrepresentable.
type LokiMapping struct {
	Encoding         Encoding
	TemplateID       string
	TemplateRevision model.Revision
	LineField        string
	MetadataFields   []string
}

// InputProfile pins timestamp, name, duplicate, out-of-order and histogram
// normalization and the source mapping. Duplicate handling is deliberately not
// configurable: identical metric points collapse, differing points at one
// series/timestamp are a conflict, and distinct log records are never merged.
type InputProfile struct {
	// Org is bound from the source grant by the decoders; Normalize requires it.
	Org            model.ID
	Project        model.ID
	Source         model.ID
	Producer       model.ID
	PolicyRevision model.Revision
	Resource       model.Resource

	Limits Limits
	// MinTimestamp and MaxTimestamp bound every accepted timestamp, inclusive.
	MinTimestamp model.UnixNano
	MaxTimestamp model.UnixNano
	// DefaultTimestamp stamps OpenMetrics samples that carry no timestamp (the
	// scrape time). Zero rejects such samples.
	DefaultTimestamp model.UnixNano
	// DefaultUnit is used when the source declares no unit. Empty means "1".
	DefaultUnit string

	Names      NameMode
	OutOfOrder OutOfOrderMode
	Histograms HistogramMode
	Exemplars  ExemplarMode
	Help       HelpMode
	Loki       LokiMapping

	// Report, when set, receives the merged normalization report of a decode.
	Report func(NormalizationReport)
}

func (p InputProfile) unit() string {
	if p.DefaultUnit == "" {
		return "1"
	}
	return p.DefaultUnit
}

func (p InputProfile) validate(format string) error {
	bad := func(detail string) error { return fail(format, ReasonProfile, detail) }
	if p.Project == (model.ID{}) || p.Source == (model.ID{}) || p.Producer == (model.ID{}) || p.PolicyRevision == 0 {
		return bad("source_mapping")
	}
	l := p.Limits
	if l.MaxCompressedBytes <= 0 || l.MaxDecodedBytes <= 0 || l.MaxCompressedBytes > hardMaxBody || l.MaxDecodedBytes > hardMaxBody ||
		l.MaxSeries <= 0 || l.MaxSamples <= 0 || l.MaxLabels <= 0 || l.MaxLabels > hardMaxLabels ||
		l.MaxLabelNameBytes <= 0 || l.MaxLabelValueBytes <= 0 || l.MaxLineBytes <= 0 || l.MaxLineBytes > hardMaxLineBytes ||
		l.MaxStreams <= 0 || l.MaxBuckets <= 0 {
		return bad("limits")
	}
	if p.MinTimestamp > p.MaxTimestamp {
		return bad("timestamp_bounds")
	}
	if p.DefaultUnit != "" && !safeUnit(p.DefaultUnit) {
		return bad("default_unit")
	}
	switch p.Names {
	case NamesStrict, NamesUTF8:
	default:
		return bad("names")
	}
	switch p.OutOfOrder {
	case OutOfOrderSort, OutOfOrderReject:
	default:
		return bad("out_of_order")
	}
	switch p.Histograms {
	case HistogramsPreserve, HistogramsReject:
	default:
		return bad("histograms")
	}
	switch p.Exemplars {
	case ExemplarsReject, ExemplarsTraceLink:
	default:
		return bad("exemplars")
	}
	switch p.Help {
	case HelpReject, HelpDiscard:
	default:
		return bad("help")
	}
	return nil
}

func (p InputProfile) validateLoki(format string) error {
	m := p.Loki
	switch m.Encoding {
	case EncodingJSON, EncodingJSONGzip, EncodingProtobufSnappy:
	default:
		return fail(format, ReasonProfile, "loki_encoding")
	}
	if m.TemplateID == "" || m.TemplateRevision == 0 || m.LineField == "" {
		return fail(format, ReasonProfile, "loki_template")
	}
	seen := map[string]bool{m.LineField: true}
	for _, f := range m.MetadataFields {
		if f == "" || seen[f] {
			return fail(format, ReasonProfile, "loki_metadata_fields")
		}
		seen[f] = true
	}
	return nil
}

// bind verifies the grant covers exactly this profile's project and source and
// stamps the grant's org. A body can never widen scope: the profile and grant
// are the only authority.
func bind(format string, grant policy.SourceGrant, cfg InputProfile) (InputProfile, error) {
	scope, err := grant.Scope()
	if err != nil {
		return cfg, err
	}
	org := scope.OrgID()
	projects := scope.ProjectIDs()
	if org == (model.ID{}) || len(projects) != 1 || projects[0] != cfg.Project || !scope.AllowsProject(cfg.Project) || !scope.AllowsSource(cfg.Source) {
		return cfg, fail(format, ReasonScope, "grant_does_not_cover_profile")
	}
	if cfg.Org != (model.ID{}) && cfg.Org != org {
		return cfg, fail(format, ReasonScope, "org_mismatch")
	}
	cfg.Org = org
	return cfg, nil
}

func ctxErr(format string, ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fail(format, ReasonCancelled, "")
	}
	return nil
}

// ---- name, label and timestamp validation ----

func safeUnit(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.:/<>-+ $", c)) {
			return false
		}
	}
	return true
}

func validMetricName(s string, mode NameMode, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	if mode == NamesUTF8 {
		return utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || c == ':' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

func validLabelName(s string, mode NameMode, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	if mode == NamesUTF8 {
		return utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

// cleanLabels validates, drops empty values (absent and empty are the same label
// in the Prometheus data model), sorts and rejects duplicates and oversize sets.
func cleanLabels(format string, in model.Labels, cfg InputProfile, rep *NormalizationReport) (model.Labels, error) {
	out := make(model.Labels, 0, len(in))
	for _, l := range in {
		if !validLabelName(l.Name, cfg.Names, cfg.Limits.MaxLabelNameBytes) || l.Name == "__name__" {
			return nil, fail(format, ReasonInvalidName, "label_name")
		}
		if !utf8.ValidString(l.Value) || len(l.Value) > cfg.Limits.MaxLabelValueBytes {
			if utf8.ValidString(l.Value) {
				return nil, fail(format, ReasonLimit, "label_value_bytes")
			}
			return nil, fail(format, ReasonMalformed, "label_value_utf8")
		}
		if l.Value == "" {
			rep.add(ReportEmptyLabelDropped, 1)
			continue
		}
		out = append(out, l)
	}
	if len(out) > cfg.Limits.MaxLabels {
		return nil, fail(format, ReasonLimit, "label_count")
	}
	if !sort.SliceIsSorted(out, func(i, j int) bool { return out[i].Name < out[j].Name }) {
		sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		rep.add(ReportLabelsSorted, 1)
	}
	for i := 1; i < len(out); i++ {
		if out[i-1].Name == out[i].Name {
			return nil, fail(format, ReasonDuplicateLabel, "")
		}
	}
	return out, nil
}

func inBounds(cfg InputProfile, t model.UnixNano) bool {
	return t >= cfg.MinTimestamp && t <= cfg.MaxTimestamp
}

func msToNano(ms int64) (model.UnixNano, bool) {
	if ms > math.MaxInt64/1_000_000 || ms < math.MinInt64/1_000_000 {
		return 0, false
	}
	return model.UnixNano(ms * 1_000_000), true
}

const staleBits = 0x7ff0000000000002

// ---- deterministic identity ----

func deriveID(domain string, parts ...[]byte) model.ID {
	h := sha256.New()
	write := func(b []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	write([]byte("soundpost.queryinput.v1"))
	write([]byte(domain))
	for _, p := range parts {
		write(p)
	}
	var id model.ID
	copy(id[:], h.Sum(nil))
	if id == (model.ID{}) {
		id[15] = 1
	}
	return id
}

func u64bytes(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func requestDigest(format string, cfg InputProfile, body []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("soundpost.queryinput.request.v1\x00" + format + "\x00"))
	h.Write(cfg.Project[:])
	h.Write(cfg.Source[:])
	h.Write(cfg.Producer[:])
	h.Write(u64bytes(uint64(cfg.PolicyRevision)))
	h.Write(body)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func seriesKey(name string, labels model.Labels) string {
	var b strings.Builder
	b.WriteString(name)
	for _, l := range labels {
		b.WriteByte(0)
		b.WriteString(l.Name)
		b.WriteByte(0)
		b.WriteString(l.Value)
	}
	return b.String()
}

// ---- normalization ----

// Normalize validates a batch against the profile and returns the normalized
// batch: labels sorted, empty-valued labels dropped, exact duplicate metric
// points and retried identical records collapsed, conflicting metric points
// rejected, out-of-order samples sorted or rejected per the profile. Distinct
// log records with equal timestamps and lines are never merged.
func Normalize(batch ingest.Batch, cfg InputProfile) (ingest.Batch, NormalizationReport, error) {
	var rep NormalizationReport
	if err := cfg.validate(fmtNormalize); err != nil {
		return ingest.Batch{}, rep, err
	}
	if cfg.Org == (model.ID{}) {
		return ingest.Batch{}, rep, fail(fmtNormalize, ReasonProfile, "org_unbound")
	}
	if batch.Version != 1 || batch.Project != cfg.Project || batch.Source != cfg.Source || batch.Producer != cfg.Producer ||
		batch.PolicyRevision != cfg.PolicyRevision || batch.ID == (model.ID{}) || batch.RouteSlot >= 64 {
		return ingest.Batch{}, rep, fail(fmtNormalize, ReasonScope, "batch_identity")
	}
	if len(batch.Records) == 0 || len(batch.Records) > maxRecordsPerBatch {
		return ingest.Batch{}, rep, fail(fmtNormalize, ReasonLimit, "record_count")
	}
	recs, rep, err := normalizeRecords(fmtNormalize, batch.Records, cfg)
	if err != nil {
		return ingest.Batch{}, rep, err
	}
	for i := range recs {
		slot, err := model.OwnerSlot(cfg.Org, cfg.Project, cfg.Source, cfg.Producer, recs[i])
		if err != nil {
			return ingest.Batch{}, rep, fail(fmtNormalize, ReasonMalformed, "owner_key")
		}
		if slot != batch.RouteSlot {
			return ingest.Batch{}, rep, fail(fmtNormalize, ReasonScope, "route_slot")
		}
	}
	out := batch
	out.Records = recs
	return out, rep, nil
}

type keyedRecord struct {
	rec model.Record
	key string
}

func normalizeRecords(format string, in []model.Record, cfg InputProfile) ([]model.Record, NormalizationReport, error) {
	var rep NormalizationReport
	metrics := make([]keyedRecord, 0, len(in))
	logs := make([]model.Record, 0)
	seenID := map[model.ID][]byte{}
	seenPoint := map[string][]byte{}
	for i := range in {
		r := in[i]
		if r.ID == (model.ID{}) {
			return nil, rep, fail(format, ReasonMalformed, "record_id")
		}
		if !inBounds(cfg, r.ObservedAt) {
			return nil, rep, fail(format, ReasonTimestampRange, "observed_at")
		}
		switch r.Kind {
		case model.Metric:
			if r.Payload.Metric == nil {
				return nil, rep, fail(format, ReasonMalformed, "metric_payload")
			}
			m := *r.Payload.Metric
			if err := normalizeMetric(format, &m, r.ObservedAt, cfg, &rep); err != nil {
				return nil, rep, err
			}
			r.Payload = model.Payload{Metric: &m}
			raw, err := model.CanonicalJSON(m)
			if err != nil {
				return nil, rep, fail(format, ReasonMalformed, "metric_encoding")
			}
			key := seriesKey(m.Name, m.Labels)
			point := key + "\x01" + string(u64bytes(uint64(r.ObservedAt)))
			if prev, ok := seenPoint[point]; ok {
				if string(prev) != string(raw) {
					return nil, rep, fail(format, ReasonConflict, "metric_timestamp")
				}
				rep.add(ReportExactDuplicateCollapsed, 1)
				continue
			}
			seenPoint[point] = raw
			if prev, ok := seenID[r.ID]; ok && string(prev) != string(raw) {
				return nil, rep, fail(format, ReasonConflict, "record_id")
			}
			seenID[r.ID] = raw
			metrics = append(metrics, keyedRecord{rec: r, key: key})
		case model.Log:
			if r.Payload.Log == nil {
				return nil, rep, fail(format, ReasonMalformed, "log_payload")
			}
			l := *r.Payload.Log
			if err := normalizeLog(format, &l, r.ObservedAt, cfg, &rep); err != nil {
				return nil, rep, err
			}
			r.Payload = model.Payload{Log: &l}
			raw, err := model.CanonicalJSON(l)
			if err != nil {
				return nil, rep, fail(format, ReasonMalformed, "log_encoding")
			}
			sig := string(u64bytes(uint64(r.ObservedAt))) + string(raw)
			if prev, ok := seenID[r.ID]; ok {
				if string(prev) != sig {
					return nil, rep, fail(format, ReasonConflict, "record_id")
				}
				rep.add(ReportExactDuplicateCollapsed, 1)
				continue
			}
			seenID[r.ID] = []byte(sig)
			logs = append(logs, r)
		default:
			return nil, rep, fail(format, ReasonUnrepresentable, "record_kind")
		}
	}
	inversions := 0
	last := map[string]model.UnixNano{}
	for _, k := range metrics {
		if prev, ok := last[k.key]; ok && k.rec.ObservedAt < prev {
			inversions++
		}
		last[k.key] = k.rec.ObservedAt
	}
	if inversions > 0 {
		if cfg.OutOfOrder == OutOfOrderReject {
			return nil, rep, fail(format, ReasonOutOfOrder, "")
		}
		sort.SliceStable(metrics, func(i, j int) bool {
			if metrics[i].key != metrics[j].key {
				return metrics[i].key < metrics[j].key
			}
			return metrics[i].rec.ObservedAt < metrics[j].rec.ObservedAt
		})
		rep.add(ReportOutOfOrderSorted, uint64(inversions))
	}
	out := make([]model.Record, 0, len(metrics)+len(logs))
	for _, k := range metrics {
		out = append(out, k.rec)
	}
	return append(out, logs...), rep, nil
}

func normalizeMetric(format string, m *model.MetricPoint, ts model.UnixNano, cfg InputProfile, rep *NormalizationReport) error {
	if !validMetricName(m.Name, cfg.Names, 1024) {
		return fail(format, ReasonInvalidName, "metric_name")
	}
	labels, err := cleanLabels(format, m.Labels, cfg, rep)
	if err != nil {
		return err
	}
	m.Labels = labels
	if !safeUnit(m.Unit) {
		return fail(format, ReasonMalformed, "unit")
	}
	switch m.Type {
	case "counter", "gauge", "histogram", "unknown":
	default:
		return fail(format, ReasonMalformed, "metric_type")
	}
	if m.StartTimestamp != nil && !inBounds(cfg, *m.StartTimestamp) {
		return fail(format, ReasonTimestampRange, "start_timestamp")
	}
	if m.ExemplarSpan != nil && m.ExemplarTrace == nil {
		return fail(format, ReasonMalformed, "exemplar_span_without_trace")
	}
	if m.ExemplarTrace != nil && cfg.Exemplars == ExemplarsReject {
		return fail(format, ReasonUnrepresentable, "exemplar")
	}
	switch m.SampleKind {
	case "float", "stale":
		if m.Value == nil || m.Histogram != nil || (m.SampleKind == "stale") != (uint64(*m.Value) == staleBits) {
			return fail(format, ReasonMalformed, "sample_kind")
		}
	case "integer_histogram", "float_histogram":
		if cfg.Histograms == HistogramsReject {
			return fail(format, ReasonUnrepresentable, "native_histogram")
		}
		if m.Value != nil || m.Histogram == nil || m.Histogram.Validate() != nil ||
			m.SampleKind == "integer_histogram" && m.Histogram.Integer == nil || m.SampleKind == "float_histogram" && m.Histogram.Float == nil {
			return fail(format, ReasonMalformed, "native_histogram")
		}
		if (m.Histogram.Integer != nil && len(m.Histogram.Integer.PositiveBuckets)+len(m.Histogram.Integer.NegativeBuckets)+len(m.Histogram.Integer.PositiveCounts)+len(m.Histogram.Integer.NegativeCounts) > cfg.Limits.MaxBuckets) ||
			(m.Histogram.Float != nil && len(m.Histogram.Float.PositiveBuckets)+len(m.Histogram.Float.NegativeBuckets) > cfg.Limits.MaxBuckets) {
			return fail(format, ReasonLimit, "histogram_buckets")
		}
	default:
		return fail(format, ReasonMalformed, "sample_kind")
	}
	return nil
}

func normalizeLog(format string, l *model.LogRecord, ts model.UnixNano, cfg InputProfile, rep *NormalizationReport) error {
	if err := cfg.validateLoki(format); err != nil {
		return err
	}
	m := cfg.Loki
	if l.TemplateID != m.TemplateID || l.TemplateRevision != m.TemplateRevision {
		return fail(format, ReasonScope, "template")
	}
	if l.Timestamp == nil || *l.Timestamp != ts {
		return fail(format, ReasonMalformed, "log_timestamp")
	}
	labels, err := cleanLabels(format, l.StreamLabels, cfg, rep)
	if err != nil {
		return err
	}
	if len(labels) == 0 {
		return fail(format, ReasonMalformed, "stream_labels")
	}
	l.StreamLabels = labels
	line, ok := l.Fields[m.LineField]
	if !ok || len(l.Fields) > 1+len(m.MetadataFields) {
		return fail(format, ReasonMalformed, "log_fields")
	}
	if len(scalarString(line)) > cfg.Limits.MaxLineBytes {
		return fail(format, ReasonTooLarge, "line_bytes")
	}
	allowed := map[string]bool{}
	for _, f := range m.MetadataFields {
		allowed[f] = true
	}
	for k := range l.Metadata {
		if !allowed[k] {
			return fail(format, ReasonUnrepresentable, "structured_metadata_key")
		}
	}
	return nil
}

func scalarString(s model.Scalar) string { return s.Text() }

func newScalar(s string) (model.Scalar, error) {
	var out model.Scalar
	raw, err := jsonString(s)
	if err != nil {
		return out, err
	}
	return out, out.UnmarshalJSON(raw)
}

// ---- partitioning into one-slot, stable-identity batches ----

type assembler struct {
	format  string
	cfg     InputProfile
	request [32]byte
	recs    []model.Record
	report  NormalizationReport
}

func (a *assembler) add(r model.Record) { a.recs = append(a.recs, r) }

func (a *assembler) finish(ctx context.Context) ([]ingest.Batch, error) {
	if len(a.recs) == 0 {
		return nil, fail(a.format, ReasonMalformed, "empty_request")
	}
	slots := map[uint16][]model.Record{}
	for i := range a.recs {
		if i&1023 == 0 {
			if err := ctxErr(a.format, ctx); err != nil {
				return nil, err
			}
		}
		slot, err := model.OwnerSlot(a.cfg.Org, a.cfg.Project, a.cfg.Source, a.cfg.Producer, a.recs[i])
		if err != nil {
			return nil, fail(a.format, ReasonMalformed, "owner_key")
		}
		slots[slot] = append(slots[slot], a.recs[i])
	}
	order := make([]int, 0, len(slots))
	for s := range slots {
		order = append(order, int(s))
	}
	sort.Ints(order)
	report := a.report
	var batches []ingest.Batch
	for _, s := range order {
		recs, rep, err := normalizeRecords(a.format, slots[uint16(s)], a.cfg)
		if err != nil {
			return nil, err
		}
		report.merge(rep)
		chunk := 0
		for len(recs) > 0 {
			n, size := 0, 0
			for n < len(recs) && n < maxRecordsPerBatch {
				raw, err := model.CanonicalJSON(recs[n])
				if err != nil {
					return nil, fail(a.format, ReasonMalformed, "record_encoding")
				}
				if len(raw) > maxRecordBytes {
					return nil, fail(a.format, ReasonTooLarge, "record_bytes")
				}
				if n > 0 && size+len(raw) > maxBatchBytes {
					break
				}
				size += len(raw)
				n++
			}
			var idx [6]byte
			binary.BigEndian.PutUint16(idx[:2], uint16(s))
			binary.BigEndian.PutUint32(idx[2:], uint32(chunk))
			batches = append(batches, ingest.Batch{
				Version: 1, Project: a.cfg.Project, Source: a.cfg.Source, Producer: a.cfg.Producer,
				ID:             deriveID("batch", a.request[:], idx[:]),
				PolicyRevision: a.cfg.PolicyRevision, RouteSlot: uint16(s), Records: recs[:n:n],
			})
			recs = recs[n:]
			chunk++
		}
	}
	if a.cfg.Report != nil {
		a.cfg.Report(report)
	}
	return batches, nil
}

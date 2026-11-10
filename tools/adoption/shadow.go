// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"soundpost/internal/adapters/queryinput"
	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/conditions"
	"soundpost/internal/model"
	"soundpost/internal/notify"
	"soundpost/internal/policy"
	"soundpost/internal/sources"
)

// This file is the generic, customer-agnostic no-send shadow ingestion of plan 08
// task 02. A signed SourceMapping binds one original source and its version to
// an org, project and source policy; deliveries the original source produced are
// translated by the Soundpost-owned adapters (internal/adapters/queryinput),
// admitted through the owned ingest path of an isolated destination and folded
// into the owned condition lifecycle (internal/conditions) and the shadow policy
// twin (internal/notify). Nothing here sends a notification, opens a network
// connection or touches a legacy sender: the file imports no network package and
// a test pins that.

// ErrShadow* are the explicit refusals of the shadow run. Callers branch with
// errors.Is; the wrapped text never carries telemetry content.
var (
	// ErrShadowExternalDelivery: a policy tried to enable normal delivery.
	ErrShadowExternalDelivery = errors.New("shadow policy: external normal delivery is prohibited")
	// ErrShadowRawSource: a policy or destination tried to accept raw sources.
	ErrShadowRawSource = errors.New("shadow policy: arbitrary raw-source acceptance is prohibited")
	// ErrShadowLegacySender: a policy tried to change a legacy sender.
	ErrShadowLegacySender = errors.New("shadow policy: legacy senders are never disabled or modified")
	// ErrShadowPolicy: the policy is malformed.
	ErrShadowPolicy = errors.New("shadow policy: invalid")
	// ErrShadowMapping: the source mapping is unsigned, tampered, expired or invalid.
	ErrShadowMapping = errors.New("shadow source mapping: refused")
	// ErrShadowAdapter: an adapter declaration is missing, generic or invalid.
	ErrShadowAdapter = errors.New("shadow adapter declaration: refused")
	// ErrShadowDestination: the destination does not match the mapping.
	ErrShadowDestination = errors.New("shadow destination: mismatch")
	// ErrShadowParitySpec: the parity expectations are malformed.
	ErrShadowParitySpec = errors.New("shadow parity spec: invalid")
	// ErrShadowPolicyFailed: deliveries violated the shadow policy; the report is still returned.
	ErrShadowPolicyFailed = errors.New("shadow run: deliveries violated the shadow policy")
	// ErrShadowReconcile: admitted plus dropped did not equal received.
	ErrShadowReconcile = errors.New("shadow run: ledger reconciliation failed")
)

// Adapter kinds. The set is closed: there is no generic adapter.
const (
	ShadowAdapterOpenMetrics   = "openmetrics"
	ShadowAdapterRemoteWriteV1 = "remote_write_v1"
	ShadowAdapterRemoteWriteV2 = "remote_write_v2"
	ShadowAdapterLokiPush      = "loki_push"
	ShadowAdapterConditions    = "condition_events"
	ShadowAdapterLogFile       = "log_file"
)

// shadowFeatures is the closed feature vocabulary of each adapter kind. An
// adapter may only declare features from its own list, and the run refuses
// input that needs a feature the declaration lacks.
var shadowFeatures = map[string][]string{
	ShadowAdapterOpenMetrics:   {"counter", "gauge", "histogram", "summary", "created_timestamp", "exemplar_trace_link", "help_text_discard"},
	ShadowAdapterRemoteWriteV1: {"float_samples", "stale_markers", "native_histograms", "exemplar_trace_link", "help_text_discard"},
	ShadowAdapterRemoteWriteV2: {"float_samples", "stale_markers", "native_histograms", "exemplar_trace_link", "help_text_discard"},
	ShadowAdapterLokiPush:      {"stream_labels", "structured_metadata", "duplicate_lines_preserved"},
	ShadowAdapterConditions:    {"sequence_ordering", "timestamp_ordering"},
	ShadowAdapterLogFile:       {"templated_lines", "unmatched_lines_dropped_by_reason", "duplicate_lines_preserved"},
}

// Closed reason vocabulary of the ledger. Decode and admission reasons are the
// owned engines' own closed codes behind a fixed prefix.
const (
	shadowReasonUnmappedSource    = "unmapped_source"
	shadowReasonUndeclaredAdapter = "undeclared_adapter"
	shadowReasonUndeclaredFeature = "undeclared_feature"
	shadowReasonBodyTooLarge      = "body_too_large"
	shadowReasonDeliveryLimit     = "delivery_limit"
	shadowReasonMalformedBody     = "malformed_body"
	shadowReasonFileTooLong       = "file_too_many_lines"
	shadowSourcePrefix            = "source_"
	shadowReasonGrantUnavailable  = "grant_unavailable"
	shadowReasonDuplicateRetry    = "duplicate_retry"
	shadowReasonExactDuplicate    = "exact_duplicate_collapsed"
	shadowReasonLateVersion       = "late_version"
	shadowReasonDuplicateEvent    = "duplicate_event"
	shadowReasonConflictingReplay = "conflicting_replay"
	shadowReasonInvalidEvent      = "invalid_event"
	shadowDecodePrefix            = "decode_"
	shadowAdmissionPrefix         = "admission_"
)

const (
	shadowSchemaVersion   = 1
	shadowMappingDomain   = "soundpost.adoption.source-mapping.v1\n"
	shadowIDDomain        = "soundpost.adoption.shadow.v1"
	shadowMaxCaptureBytes = 64 << 20
	shadowMaxBodyCeiling  = 4 << 20
	shadowMaxDeliveries   = 100000
	shadowMaxCondEvents   = 512
	shadowMaxFileLines    = 512
)

// ShadowResource is the resource identity every record of the mapped source
// carries; it must be registered in the source policy.
type ShadowResource struct {
	Service     string `json:"service_id"`
	Environment string `json:"environment_id"`
	Build       string `json:"build_id"`
	Instance    string `json:"instance"`
}

// ShadowLokiBinding binds a Loki push adapter to one registered log template.
type ShadowLokiBinding struct {
	Encoding         string   `json:"encoding"`
	TemplateID       string   `json:"template_id"`
	TemplateRevision uint64   `json:"template_revision"`
	LineField        string   `json:"line_field"`
	MetadataFields   []string `json:"metadata_fields"`
}

// ShadowFileBinding binds a log_file adapter to the owned file source: the
// source's name, the stream labels every record carries, the registered
// templates its lines are classified by (they must also be registered in the
// destination source policy) and an optional leading time layout. Raw text is
// never accepted: a line that matches no template is dropped by reason.
type ShadowFileBinding struct {
	Name         string              `json:"name"`
	StreamLabels map[string]string   `json:"stream_labels"`
	Templates    []model.LogTemplate `json:"templates"`
	MaxLineBytes int                 `json:"max_line_bytes,omitempty"`
	TimeLayout   string              `json:"time_layout,omitempty"`
}

// ShadowAdapterDeclaration is the version and feature declaration every
// configured adapter carries. Empty and wildcard declarations are refused: an
// adapter never advertises generic compatibility.
type ShadowAdapterDeclaration struct {
	Kind     string             `json:"kind"`
	Version  string             `json:"version"`
	Features []string           `json:"features"`
	Loki     *ShadowLokiBinding `json:"loki,omitempty"`
	File     *ShadowFileBinding `json:"file,omitempty"`
}

// SourceMapping binds one original source and its version to an org, project
// and source policy. It names identities only: it grants no read access, and no
// telemetry label ever selects or widens the project it is admitted to. It is
// signed (ed25519) and verified before any use.
type SourceMapping struct {
	SchemaVersion      int                        `json:"schema_version"`
	OriginalSource     string                     `json:"original_source"`
	OriginalVersion    string                     `json:"original_version"`
	Org                string                     `json:"org"`
	Project            string                     `json:"project"`
	Source             string                     `json:"source"`
	PolicyRevision     uint64                     `json:"policy_revision"`
	SourcePolicySHA256 string                     `json:"source_policy_sha256"`
	Resource           ShadowResource             `json:"resource"`
	MinTimestampNS     int64                      `json:"min_timestamp_ns"`
	MaxTimestampNS     int64                      `json:"max_timestamp_ns"`
	Adapters           []ShadowAdapterDeclaration `json:"adapters"`
	NotBeforeUnix      int64                      `json:"not_before_unix"`
	NotAfterUnix       int64                      `json:"not_after_unix"`
	KeyID              string                     `json:"key_id"`
	Signature          string                     `json:"signature"`
}

// ShadowTrustedKey is one trusted ed25519 mapping-signing public key.
type ShadowTrustedKey struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
}

// ShadowPolicy is the policy of a shadow run. It ALWAYS prohibits external
// normal delivery, legacy sender changes and arbitrary raw-source acceptance.
// ExternalDelivery, EnabledSenders, AcceptRawSources and DisableLegacySenders
// exist only so that a configuration trying to flip them is refused with an
// explicit error instead of silently ignored: the only legal values are false
// and empty.
type ShadowPolicy struct {
	SchemaVersion          int                `json:"schema_version"`
	TrustedKeys            []ShadowTrustedKey `json:"trusted_keys"`
	AllowedOriginalSources []string           `json:"allowed_original_sources"`
	MaxDeliveries          int                `json:"max_deliveries"`
	MaxBodyBytes           int                `json:"max_body_bytes"`
	ExternalDelivery       bool               `json:"external_delivery"`
	EnabledSenders         []string           `json:"enabled_senders"`
	AcceptRawSources       bool               `json:"accept_raw_sources"`
	DisableLegacySenders   bool               `json:"disable_legacy_senders"`

	// Clock replaces the wall clock (mapping validity); tests only.
	Clock func() time.Time `json:"-"`
}

// ShadowConditionInput is one source condition event as the original source
// delivered it. Names are the source's own: identities inside Soundpost derive
// from them deterministically and are bound to the mapped org/project.
type ShadowConditionInput struct {
	Condition string            `json:"condition"`
	Epoch     string            `json:"epoch"`
	Sequence  uint64            `json:"sequence"`
	AtNS      int64             `json:"at_ns"`
	Status    string            `json:"status"`
	Severity  string            `json:"severity"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// ShadowDecisionItem is one shadow policy decision.
type ShadowDecisionItem struct {
	Condition      string `json:"condition"`
	Kind           string `json:"kind"`
	ImpactRevision uint64 `json:"impact_revision"`
	Ordinal        uint64 `json:"ordinal"`
	Recipient      string `json:"recipient,omitempty"`
	SourceVersion  uint64 `json:"source_version"`
	Suppression    string `json:"suppression,omitempty"`
}

// ShadowDelivery is one transmission the original source produced, replayed
// read-only from a recording. ID is the source-side delivery identifier: a
// retry carries the same body and may carry the same ID.
type ShadowDelivery struct {
	ID             string `json:"id"`
	OriginalSource string `json:"original_source"`
	Adapter        string `json:"adapter"`
	ReceivedAtNS   int64  `json:"received_at_ns"`
	Body           []byte `json:"body"`
}

// ShadowFeed is the recorded capture replayed into the destination and the
// legacy answers the result is compared to.
type ShadowFeed struct {
	Deliveries []ShadowDelivery  `json:"deliveries"`
	Parity     *ShadowParitySpec `json:"parity,omitempty"`
}

// SoundpostDestination is the isolated Soundpost instance a shadow run admits
// into and queries, plus the recorded feed to replay. Ingest authority is one
// source credential and read authority is one project-scoped reader scope, both
// granted by the operator that provisioned the destination, never derived from
// telemetry labels. The destination has no notification sender at all.
type SoundpostDestination struct {
	App                *appcore.App
	Org                model.ID
	Project            model.ID
	Source             model.ID
	PolicyRevision     uint64
	SourcePolicyClass  string
	SourcePolicySHA256 string
	Credential         *auth.SourceCredential
	Reader             *auth.Scope
	Feed               ShadowFeed
}

// ShadowLedgerEntry is one normalized source ledger row: provenance, a stable
// dedup ID and the outcome. It never holds telemetry bodies or label values.
type ShadowLedgerEntry struct {
	Seq             int    `json:"seq"`
	Adapter         string `json:"adapter"`
	AdapterVersion  string `json:"adapter_version"`
	OriginalSource  string `json:"original_source"`
	OriginalVersion string `json:"original_version"`
	DeliveryID      string `json:"delivery_id"`
	Ordinal         int    `json:"ordinal"`
	Kind            string `json:"kind"`
	DedupID         string `json:"dedup_id"`
	Outcome         string `json:"outcome"`
	Reason          string `json:"reason,omitempty"`
	SourceVersion   uint64 `json:"source_version,omitempty"`
}

// ShadowCounts is an admitted/dropped tally. Received always equals Admitted
// plus the sum of DroppedByReason; the run fails reconciliation otherwise.
type ShadowCounts struct {
	Received        int            `json:"received"`
	Admitted        int            `json:"admitted"`
	Dropped         int            `json:"dropped"`
	DroppedByReason map[string]int `json:"dropped_by_reason"`
}

// ShadowDeliveryCounts is the delivery-level tally.
type ShadowDeliveryCounts struct {
	Received         int            `json:"received"`
	Accepted         int            `json:"accepted"`
	Rejected         int            `json:"rejected"`
	RejectedByReason map[string]int `json:"rejected_by_reason"`
}

// ShadowSemantics counts the declared source semantics that were retained.
type ShadowSemantics struct {
	StaleMarkersAdmitted       int `json:"stale_markers_admitted"`
	NativeHistogramsAdmitted   int `json:"native_histograms_admitted"`
	DuplicateLogLinesPreserved int `json:"duplicate_log_lines_preserved"`
}

// ShadowCondition is the final lifecycle answer of one source condition.
type ShadowCondition struct {
	Name          string `json:"name"`
	SourceVersion uint64 `json:"source_version"`
	Phase         string `json:"phase"`
	Freshness     string `json:"freshness"`
	Accepted      int    `json:"accepted_events"`
}

// ShadowDecisions summarizes what the shadow policy twin decided. Nothing was
// delivered: WouldDeliver is what the product would send as the active owner.
type ShadowDecisions struct {
	Total        int                  `json:"total"`
	WouldDeliver int                  `json:"would_deliver"`
	Refused      int                  `json:"refused"`
	Suppressed   map[string]int       `json:"suppressed"`
	Kinds        map[string]int       `json:"kinds"`
	Items        []ShadowDecisionItem `json:"items"`
}

// ShadowReport is the private full result of a run. It can name conditions,
// series and case IDs and is never published; Public yields the closed
// allowlisted projection.
type ShadowReport struct {
	SchemaVersion        int                        `json:"schema_version"`
	MappingDigest        string                     `json:"mapping_digest"`
	OriginalSource       string                     `json:"original_source"`
	OriginalVersion      string                     `json:"original_version"`
	Adapters             []ShadowAdapterDeclaration `json:"adapters"`
	ExternalSendAttempts int                        `json:"external_send_attempts"`
	NormalDeliveriesSent int                        `json:"normal_deliveries_sent"`
	Deliveries           ShadowDeliveryCounts       `json:"deliveries"`
	Records              ShadowCounts               `json:"records"`
	PerAdapter           map[string]ShadowCounts    `json:"per_adapter"`
	Semantics            ShadowSemantics            `json:"semantics"`
	Conditions           []ShadowCondition          `json:"conditions"`
	Decisions            ShadowDecisions            `json:"decisions"`
	Parity               ShadowParityReport         `json:"parity"`
	PolicyViolations     []string                   `json:"policy_violations"`
	Reconciled           bool                       `json:"reconciled"`
	BatchesSubmitted     int                        `json:"batches_submitted"`
	LedgerDigest         string                     `json:"ledger_digest"`
	Ledger               []ShadowLedgerEntry        `json:"ledger"`
}

// ShadowPublicSummary is the closed allowlisted projection of a report: only
// counters and booleans, no strings derived from sources, labels or cases.
type ShadowPublicSummary struct {
	SchemaVersion        int
	AdapterCount         int
	DeliveriesReceived   int
	DeliveriesRejected   int
	RecordsReceived      int
	RecordsAdmitted      int
	RecordsDropped       int
	Reconciled           bool
	ParityCases          int
	ParityMismatches     int
	PolicyViolations     int
	ExternalSendAttempts int
	CustomerAcceptance   bool
}

// Public projects the report onto the closed publishable shape.
func (r ShadowReport) Public() ShadowPublicSummary {
	return ShadowPublicSummary{
		SchemaVersion: shadowSchemaVersion, AdapterCount: len(r.Adapters),
		DeliveriesReceived: r.Deliveries.Received, DeliveriesRejected: r.Deliveries.Rejected,
		RecordsReceived: r.Records.Received, RecordsAdmitted: r.Records.Admitted, RecordsDropped: r.Records.Dropped,
		Reconciled:  r.Reconciled,
		ParityCases: r.Parity.QueriesCompared + r.Parity.LifecycleCompared + r.Parity.DecisionsCompared + r.Parity.LedgerCompared, ParityMismatches: len(r.Parity.Mismatches),
		PolicyViolations: len(r.PolicyViolations), ExternalSendAttempts: r.ExternalSendAttempts,
	}
}

// ---- policy -------------------------------------------------------------

// validate refuses every attempt to enable external normal delivery, raw
// acceptance or a legacy sender change with an explicit error; it never
// ignores one. Only then are the limits and the allow list checked.
func (p ShadowPolicy) validate() error {
	switch {
	case p.ExternalDelivery || len(p.EnabledSenders) > 0:
		return ErrShadowExternalDelivery
	case p.AcceptRawSources:
		return ErrShadowRawSource
	case p.DisableLegacySenders:
		return ErrShadowLegacySender
	}
	bad := func(why string) error { return fmt.Errorf("%w: %s", ErrShadowPolicy, why) }
	switch {
	case p.SchemaVersion != shadowSchemaVersion:
		return bad("schema version")
	case p.MaxDeliveries < 1 || p.MaxDeliveries > shadowMaxDeliveries:
		return bad("max_deliveries out of range")
	case p.MaxBodyBytes < 1 || p.MaxBodyBytes > shadowMaxBodyCeiling:
		return bad("max_body_bytes out of range")
	case len(p.AllowedOriginalSources) == 0:
		return bad("an explicit allow list of original sources is required")
	}
	for _, s := range p.AllowedOriginalSources {
		if !shadowSafeName.MatchString(s) {
			return bad("allowed original source")
		}
	}
	return nil
}

// ---- mapping ------------------------------------------------------------

func shadowMappingMessage(m SourceMapping) ([]byte, error) {
	m.Signature = ""
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return append([]byte(shadowMappingDomain), raw...), nil
}

// ShadowSignMapping signs a mapping with an ed25519 key. The signer holds the
// private key; the run only ever needs the trusted public key.
func ShadowSignMapping(key ed25519.PrivateKey, keyID string, m SourceMapping) (SourceMapping, error) {
	m.KeyID, m.Signature = keyID, ""
	msg, err := shadowMappingMessage(m)
	if err != nil {
		return SourceMapping{}, err
	}
	m.Signature = hex.EncodeToString(ed25519.Sign(key, msg))
	return m, nil
}

var shadowVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

// shadowGenericTokens are version words that advertise generic compatibility
// instead of one concrete version.
var shadowGenericTokens = map[string]bool{"any": true, "all": true, "latest": true, "compatible": true, "generic": true, "wildcard": true, "unknown": true, "x": true, "star": true}

// shadowSpecificVersion reports whether v names one concrete version: it has a
// digit and no wildcard, "any", "latest" or "compatible" component.
func shadowSpecificVersion(v string) bool {
	if !shadowVersionPattern.MatchString(v) || !strings.ContainsAny(v, "0123456789") {
		return false
	}
	for _, tok := range strings.FieldsFunc(strings.ToLower(v), func(r rune) bool { return strings.ContainsRune("._+-", r) }) {
		if shadowGenericTokens[tok] {
			return false
		}
	}
	return true
}

// shadowVerifyMapping verifies the signature, validity window and
// declarations, and returns the mapping digest. The signature is checked first
// and nothing of the mapping is used before this returns nil.
func shadowVerifyMapping(m SourceMapping, p ShadowPolicy, now time.Time) (string, error) {
	refuse := func(why string) (string, error) { return "", fmt.Errorf("%w: %s", ErrShadowMapping, why) }
	if m.Signature == "" {
		return refuse("unsigned")
	}
	sig, err := hex.DecodeString(m.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return refuse("signature encoding")
	}
	var pub ed25519.PublicKey
	for _, k := range p.TrustedKeys {
		if k.ID != m.KeyID || m.KeyID == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return refuse("trusted key is malformed")
		}
		pub = raw
		break
	}
	if pub == nil {
		return refuse("signing key is not trusted")
	}
	msg, err := shadowMappingMessage(m)
	if err != nil {
		return refuse("encoding")
	}
	if !ed25519.Verify(pub, msg, sig) {
		return refuse("signature does not verify")
	}
	// Signed by a trusted key: now the content is validated.
	if m.SchemaVersion != shadowSchemaVersion {
		return refuse("schema version")
	}
	if !shadowSafeName.MatchString(m.OriginalSource) || !shadowSpecificVersion(m.OriginalVersion) {
		return refuse("original source and a concrete version are required")
	}
	if _, err := shadowParseIDs(m); err != nil {
		return "", err
	}
	if m.PolicyRevision == 0 || len(m.SourcePolicySHA256) != 64 {
		return refuse("source policy binding")
	}
	if _, err := hex.DecodeString(m.SourcePolicySHA256); err != nil {
		return refuse("source policy binding")
	}
	if m.MinTimestampNS <= 0 || m.MaxTimestampNS <= m.MinTimestampNS {
		return refuse("timestamp bounds")
	}
	if m.NotBeforeUnix <= 0 || m.NotAfterUnix <= m.NotBeforeUnix || now.Unix() < m.NotBeforeUnix || now.Unix() > m.NotAfterUnix {
		return refuse("outside the validity window")
	}
	if err := shadowValidateAdapters(m.Adapters); err != nil {
		return "", err
	}
	sum := sha256.Sum256(msg)
	return hex.EncodeToString(sum[:]), nil
}

// shadowValidateAdapters requires every configured adapter to carry one
// concrete version and an explicit feature list from its own closed vocabulary.
func shadowValidateAdapters(list []ShadowAdapterDeclaration) error {
	refuse := func(kind, why string) error { return fmt.Errorf("%w: %s: %s", ErrShadowAdapter, kind, why) }
	if len(list) == 0 {
		return refuse("-", "at least one declared adapter is required")
	}
	seen := map[string]bool{}
	for _, a := range list {
		allowed, known := shadowFeatures[a.Kind]
		switch {
		case !known:
			return refuse("unknown", "adapter kind is not one of the closed set")
		case seen[a.Kind]:
			return refuse(a.Kind, "declared twice")
		case !shadowSpecificVersion(a.Version):
			return refuse(a.Kind, "a concrete version is required, not a wildcard or generic compatibility claim")
		case len(a.Features) == 0:
			return refuse(a.Kind, "an explicit feature list is required")
		}
		seen[a.Kind] = true
		have := map[string]bool{}
		for _, f := range a.Features {
			if !slices.Contains(allowed, f) || have[f] {
				return refuse(a.Kind, "feature is unknown for this adapter or repeated")
			}
			have[f] = true
		}
		if a.Kind != ShadowAdapterLokiPush && a.Loki != nil {
			return refuse(a.Kind, "a Loki binding belongs only to loki_push")
		}
		if a.Kind != ShadowAdapterLogFile && a.File != nil {
			return refuse(a.Kind, "a file binding belongs only to log_file")
		}
		switch a.Kind {
		case ShadowAdapterLokiPush:
			b := a.Loki
			if b == nil || !slices.Contains([]string{"json", "json_gzip", "protobuf_snappy"}, b.Encoding) || b.TemplateID == "" || len(b.TemplateID) > 128 || b.TemplateRevision == 0 || b.LineField == "" {
				return refuse(a.Kind, "a complete registered-template binding is required")
			}
			fields := map[string]bool{}
			for _, f := range b.MetadataFields {
				if f == "" || fields[f] {
					return refuse(a.Kind, "metadata fields must be named once")
				}
				fields[f] = true
			}
		case ShadowAdapterLogFile:
			if a.File == nil || a.File.validate() != nil {
				return refuse(a.Kind, "a complete, valid file-source template binding is required")
			}
		}
	}
	return nil
}

// ---- identities ---------------------------------------------------------

type shadowIDs struct {
	org, project, source, producer model.ID
	resource                       model.Resource
}

func shadowDeriveID(parts ...string) model.ID {
	h := sha256.New()
	h.Write([]byte(shadowIDDomain))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	var id model.ID
	copy(id[:], h.Sum(nil))
	return id
}

func shadowHexDigest(parts ...string) string {
	h := sha256.New()
	h.Write([]byte(shadowIDDomain))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func shadowParseIDs(m SourceMapping) (shadowIDs, error) {
	var ids shadowIDs
	parse := func(s string) (model.ID, error) {
		id, err := model.ParseID(s)
		if err != nil || id == (model.ID{}) {
			return model.ID{}, fmt.Errorf("%w: identity", ErrShadowMapping)
		}
		return id, nil
	}
	var err error
	if ids.org, err = parse(m.Org); err != nil {
		return ids, err
	}
	if ids.project, err = parse(m.Project); err != nil {
		return ids, err
	}
	if ids.source, err = parse(m.Source); err != nil {
		return ids, err
	}
	svc, err := parse(m.Resource.Service)
	if err != nil {
		return ids, err
	}
	env, err := parse(m.Resource.Environment)
	if err != nil {
		return ids, err
	}
	build, err := parse(m.Resource.Build)
	if err != nil {
		return ids, err
	}
	if m.Resource.Instance == "" {
		return ids, fmt.Errorf("%w: identity", ErrShadowMapping)
	}
	ids.resource = model.Resource{Service: svc, Environment: env, Build: build, Instance: m.Resource.Instance, Labels: model.Labels{}}
	return ids, nil
}

// ShadowSourcePolicyDigest is the digest a mapping binds a source policy by.
func ShadowSourcePolicyDigest(sp model.SourcePolicy) (string, error) {
	raw, err := model.CanonicalJSON(sp)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// ---- RunShadow ----------------------------------------------------------

// RunShadow replays the destination's recorded feed through the owned adapters,
// admission path, condition lifecycle and shadow policy twin, and compares the
// answers to the legacy expectations. It never sends a notification: the
// policy, mapping, declarations, destination and parity expectations are all
// verified before the first delivery is looked at.
//
// Deliveries that name an unmapped source or an undeclared adapter are rejected
// and recorded; the returned report is complete and the error wraps
// ErrShadowPolicyFailed. A ledger that does not reconcile wraps ErrShadowReconcile.
func RunShadow(ctx context.Context, m SourceMapping, d SoundpostDestination, p ShadowPolicy) (ShadowReport, error) {
	if err := ctx.Err(); err != nil {
		return ShadowReport{}, err
	}
	if err := p.validate(); err != nil {
		return ShadowReport{}, err
	}
	digest, err := shadowVerifyMapping(m, p, shadowNow(p))
	if err != nil {
		return ShadowReport{}, err
	}
	if !slices.Contains(p.AllowedOriginalSources, m.OriginalSource) {
		return ShadowReport{}, fmt.Errorf("%w: the mapped original source is not on the allow list", ErrShadowPolicy)
	}
	ids, err := shadowParseIDs(m)
	if err != nil {
		return ShadowReport{}, err
	}
	ids.producer = shadowDeriveID("producer", digest)
	if err := d.check(m, ids); err != nil {
		return ShadowReport{}, err
	}
	if d.Feed.Parity != nil {
		if err := d.Feed.Parity.validate(); err != nil {
			return ShadowReport{}, err
		}
	}
	ps, err := policy.New(d.App.Auth, nil)
	if err != nil {
		return ShadowReport{}, fmt.Errorf("%w: policy service", ErrShadowDestination)
	}
	r := newShadowRun(m, ids, d, p, digest, ps)
	if _, ok := r.decls[ShadowAdapterLogFile]; ok {
		scratch, err := os.MkdirTemp("", "shadow-files-")
		if err != nil {
			return ShadowReport{}, fmt.Errorf("%w: scratch directory", ErrShadowDestination)
		}
		defer os.RemoveAll(scratch)
		r.scratch = scratch
	}
	for i, del := range d.Feed.Deliveries {
		if err := ctx.Err(); err != nil {
			return ShadowReport{}, err
		}
		if err := r.process(ctx, i, del); err != nil {
			return ShadowReport{}, err
		}
	}
	return r.finish(ctx)
}

// check verifies the destination is the isolated instance the mapping binds.
func (d SoundpostDestination) check(m SourceMapping, ids shadowIDs) error {
	bad := func(why string) error { return fmt.Errorf("%w: %s", ErrShadowDestination, why) }
	switch d.SourcePolicyClass {
	case "structured":
	case "restricted_raw":
		return fmt.Errorf("%w: the destination source policy accepts raw sources", ErrShadowRawSource)
	default:
		return bad("source policy class")
	}
	if d.App == nil || d.Credential == nil || d.Reader == nil {
		return bad("missing application, source credential or read scope")
	}
	if d.Org != ids.org || d.Project != ids.project || d.Source != ids.source {
		return bad("identity differs from the mapping")
	}
	if d.PolicyRevision != m.PolicyRevision || d.SourcePolicySHA256 != m.SourcePolicySHA256 {
		return bad("source policy differs from the one the mapping binds")
	}
	if d.Reader.OrgID() != ids.org || len(d.Reader.ProjectIDs()) != 1 || !d.Reader.AllowsProject(ids.project) || d.Reader.Permission() != auth.Read {
		return bad("read scope is not exactly read access to the mapped project")
	}
	return nil
}

// shadowLife is the in-process lifecycle of one source condition: the owned
// reducer's state and the shadow policy twin that decides on it.
type shadowLife struct {
	id     model.ID
	entity notify.Entity
	state  conditions.State
	twin   *notify.ShadowEvaluator
	at     int64
}

type shadowRun struct {
	m         SourceMapping
	ids       shadowIDs
	d         SoundpostDestination
	p         ShadowPolicy
	digest    string
	decls     map[string]ShadowAdapterDeclaration
	policySvc *policy.Service
	scratch   string
	policyID  model.ID
	recipient model.ID
	cfg       notify.Config

	rep        ShadowReport
	ledger     []ShadowLedgerEntry
	seen       map[string]bool
	logKeys    map[string]bool
	violations map[string]bool

	conds     map[string]*shadowLife
	byEntity  map[model.ID]string
	condIDs   map[string]model.ID
	decisions []notify.ShadowDecision
}

type shadowDel struct {
	index int
	id    string
	del   ShadowDelivery
	decl  *ShadowAdapterDeclaration
}

func newShadowRun(m SourceMapping, ids shadowIDs, d SoundpostDestination, p ShadowPolicy, digest string, ps *policy.Service) *shadowRun {
	r := &shadowRun{m: m, ids: ids, d: d, p: p, digest: digest, decls: map[string]ShadowAdapterDeclaration{}, policySvc: ps,
		policyID: shadowDeriveID("policy", digest), recipient: shadowDeriveID("recipient", shadowRecipient), cfg: notify.DefaultConfig(),
		seen: map[string]bool{}, logKeys: map[string]bool{}, violations: map[string]bool{},
		conds: map[string]*shadowLife{}, byEntity: map[model.ID]string{}, condIDs: map[string]model.ID{}}
	for _, a := range m.Adapters {
		r.decls[a.Kind] = a
	}
	r.rep = ShadowReport{SchemaVersion: shadowSchemaVersion, MappingDigest: digest, OriginalSource: m.OriginalSource, OriginalVersion: m.OriginalVersion,
		Adapters:   append([]ShadowAdapterDeclaration(nil), m.Adapters...),
		Deliveries: ShadowDeliveryCounts{RejectedByReason: map[string]int{}}, Records: ShadowCounts{DroppedByReason: map[string]int{}},
		PerAdapter: map[string]ShadowCounts{}, Decisions: ShadowDecisions{Suppressed: map[string]int{}, Kinds: map[string]int{}, Items: []ShadowDecisionItem{}},
		Conditions: []ShadowCondition{}, Parity: ShadowParityReport{Mismatches: []ShadowMismatch{}}, PolicyViolations: []string{}}
	return r
}

// recv counts n source units received through an adapter, independently of the
// ledger rows that later account for each of them.
func (r *shadowRun) recv(adapter string, n int) {
	r.rep.Records.Received += n
	c := r.rep.PerAdapter[adapter]
	c.Received += n
	if c.DroppedByReason == nil {
		c.DroppedByReason = map[string]int{}
	}
	r.rep.PerAdapter[adapter] = c
}

// row appends one ledger row and tallies its outcome.
func (r *shadowRun) row(sd shadowDel, kind string, ordinal int, dedup, outcome, reason string, version uint64) {
	e := ShadowLedgerEntry{Seq: len(r.ledger) + 1, Adapter: sd.del.Adapter, OriginalSource: sd.del.OriginalSource, OriginalVersion: r.m.OriginalVersion,
		DeliveryID: sd.id, Ordinal: ordinal, Kind: kind, DedupID: dedup, Outcome: outcome, Reason: reason, SourceVersion: version}
	if sd.decl != nil {
		e.AdapterVersion = sd.decl.Version
	}
	r.ledger = append(r.ledger, e)
	if kind == "delivery" {
		return
	}
	c := r.rep.PerAdapter[sd.del.Adapter]
	if c.DroppedByReason == nil {
		c.DroppedByReason = map[string]int{}
	}
	if outcome == "admitted" {
		r.rep.Records.Admitted++
		c.Admitted++
	} else {
		r.rep.Records.Dropped++
		r.rep.Records.DroppedByReason[reason]++
		c.Dropped++
		c.DroppedByReason[reason]++
	}
	r.rep.PerAdapter[sd.del.Adapter] = c
}

func (r *shadowRun) reject(sd shadowDel, reason string, violation bool) {
	r.rep.Deliveries.Rejected++
	r.rep.Deliveries.RejectedByReason[reason]++
	if violation {
		r.violations[reason] = true
	}
	r.row(sd, "delivery", 0, shadowHexDigest(r.digest, "delivery", strconv.Itoa(sd.index), sd.id), "rejected", reason, 0)
}

// process gates and accounts one delivery. Only cancellation is an error.
func (r *shadowRun) process(ctx context.Context, idx int, del ShadowDelivery) error {
	sd := shadowDel{index: idx, id: del.ID, del: del}
	if sd.id == "" {
		sd.id = fmt.Sprintf("delivery-%d", idx)
	}
	r.rep.Deliveries.Received++
	decl, declared := r.decls[del.Adapter]
	if declared {
		sd.decl = &decl
	}
	switch {
	case idx >= r.p.MaxDeliveries:
		r.reject(sd, shadowReasonDeliveryLimit, false)
		return nil
	case del.OriginalSource != r.m.OriginalSource:
		r.reject(sd, shadowReasonUnmappedSource, true)
		return nil
	case !declared:
		r.reject(sd, shadowReasonUndeclaredAdapter, true)
		return nil
	case len(del.Body) > r.p.MaxBodyBytes:
		r.reject(sd, shadowReasonBodyTooLarge, false)
		return nil
	}
	var reason string
	var err error
	switch decl.Kind {
	case ShadowAdapterConditions:
		reason = r.conditionDelivery(sd)
	case ShadowAdapterLogFile:
		reason, err = r.fileDelivery(ctx, sd, decl)
	default:
		reason, err = r.wireDelivery(ctx, sd, decl)
	}
	if err != nil {
		return err
	}
	if reason != "" {
		r.reject(sd, reason, false)
		return nil
	}
	r.rep.Deliveries.Accepted++
	return nil
}

func (r *shadowRun) profile(decl ShadowAdapterDeclaration, receivedAt int64) queryinput.InputProfile {
	p := queryinput.InputProfile{Project: r.ids.project, Source: r.ids.source, Producer: r.ids.producer, PolicyRevision: model.Revision(r.m.PolicyRevision), Resource: r.ids.resource,
		Limits: queryinput.DefaultLimits(), MinTimestamp: model.UnixNano(r.m.MinTimestampNS), MaxTimestamp: model.UnixNano(r.m.MaxTimestampNS),
		Names: queryinput.NamesStrict, OutOfOrder: queryinput.OutOfOrderSort, Histograms: queryinput.HistogramsReject, Exemplars: queryinput.ExemplarsReject, Help: queryinput.HelpReject}
	if slices.Contains(decl.Features, "native_histograms") {
		p.Histograms = queryinput.HistogramsPreserve
	}
	if slices.Contains(decl.Features, "exemplar_trace_link") {
		p.Exemplars = queryinput.ExemplarsTraceLink
	}
	if slices.Contains(decl.Features, "help_text_discard") {
		p.Help = queryinput.HelpDiscard
	}
	if receivedAt >= r.m.MinTimestampNS && receivedAt <= r.m.MaxTimestampNS {
		p.DefaultTimestamp = model.UnixNano(receivedAt)
	}
	if b := decl.Loki; b != nil {
		p.Loki = queryinput.LokiMapping{Encoding: queryinput.Encoding(b.Encoding), TemplateID: b.TemplateID, TemplateRevision: model.Revision(b.TemplateRevision), LineField: b.LineField, MetadataFields: b.MetadataFields}
	}
	return p
}

func (r *shadowRun) grant(ctx context.Context) (policy.SourceGrant, error) {
	return r.policySvc.ResolveSource(ctx, *r.d.Credential, r.ids.project, r.ids.source, model.Revision(r.m.PolicyRevision))
}

// undeclaredFeature reports whether any record carries a semantic the adapter's
// declaration does not list: a declaration is the whole of what it accepts.
func undeclaredFeature(decl ShadowAdapterDeclaration, batches []model.Batch) bool {
	for _, b := range batches {
		for _, rec := range b.Records {
			m := rec.Payload.Metric
			if m == nil {
				continue
			}
			if m.SampleKind == "stale" && !slices.Contains(decl.Features, "stale_markers") {
				return true
			}
			if m.Histogram != nil && !slices.Contains(decl.Features, "native_histograms") {
				return true
			}
			if m.ExemplarTrace != nil && !slices.Contains(decl.Features, "exemplar_trace_link") {
				return true
			}
		}
	}
	return false
}

func shadowFaultReason(prefix string, err error) string {
	var f *model.Fault
	if errors.As(err, &f) {
		return prefix + string(f.Code)
	}
	return prefix + "error"
}

// wireDelivery translates one metric or log delivery with the owned adapter and
// admits the resulting batches through the owned ingest path. A non-empty
// reason rejects the whole delivery before any row is written.
func (r *shadowRun) wireDelivery(ctx context.Context, sd shadowDel, decl ShadowAdapterDeclaration) (string, error) {
	grant, err := r.grant(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return shadowReasonGrantUnavailable, nil
	}
	prof := r.profile(decl, sd.del.ReceivedAtNS)
	var norm queryinput.NormalizationReport
	prof.Report = func(n queryinput.NormalizationReport) { norm = n }
	body := bytes.NewReader(sd.del.Body)
	var batches []model.Batch
	switch decl.Kind {
	case ShadowAdapterOpenMetrics:
		batches, err = queryinput.DecodeOpenMetrics(ctx, grant, body, prof)
	case ShadowAdapterRemoteWriteV1:
		batches, err = queryinput.DecodeRemoteWrite(ctx, grant, queryinput.RemoteWriteV1, body, prof)
	case ShadowAdapterRemoteWriteV2:
		batches, err = queryinput.DecodeRemoteWrite(ctx, grant, queryinput.RemoteWriteV2, body, prof)
	case ShadowAdapterLokiPush:
		batches, err = queryinput.DecodeLokiPush(ctx, grant, body, prof)
	default:
		return shadowReasonUndeclaredAdapter, nil
	}
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		var qe *queryinput.Error
		if errors.As(err, &qe) {
			return shadowDecodePrefix + string(qe.Reason), nil
		}
		return shadowDecodePrefix + "error", nil
	}
	if undeclaredFeature(decl, batches) {
		return shadowReasonUndeclaredFeature, nil
	}
	kind := "metric"
	if decl.Kind == ShadowAdapterLokiPush {
		kind = "log"
	}
	collapsed := int(norm.Count(queryinput.ReportExactDuplicateCollapsed))
	for _, b := range batches {
		r.recv(decl.Kind, len(b.Records))
	}
	r.recv(decl.Kind, collapsed)
	ordinal, err := r.admitBatches(ctx, sd, kind, batches, func(rec model.Record, _ int) string { return rec.ID.String() })
	if err != nil {
		return "", err
	}
	for i := range collapsed {
		r.row(sd, kind, ordinal, shadowHexDigest(r.digest, "collapsed", strconv.Itoa(sd.index), sd.id, strconv.Itoa(i)), "dropped", shadowReasonExactDuplicate, 0)
		ordinal++
	}
	return "", nil
}

// admitBatches admits the batches of one delivery through the owned ingest
// path, one ledger row per record. key names a record for dedup: a record whose
// key was already admitted is a retry and is never resubmitted. It returns the
// next ordinal; only cancellation is an error.
func (r *shadowRun) admitBatches(ctx context.Context, sd shadowDel, kind string, batches []model.Batch, key func(rec model.Record, index int) string) (int, error) {
	ordinal := 0
	for _, b := range batches {
		dedup := make([]string, len(b.Records))
		fresh := 0
		for i, rec := range b.Records {
			dedup[i] = shadowHexDigest(r.digest, "record", sd.del.Adapter, key(rec, ordinal+i))
			if !r.seen[dedup[i]] {
				fresh++
			}
		}
		reason := ""
		if fresh > 0 {
			g, gerr := r.grant(ctx)
			if gerr == nil {
				r.rep.BatchesSubmitted++
				_, gerr = r.d.App.Ingest.Admit(ctx, g, b)
			}
			if gerr != nil {
				if ctx.Err() != nil {
					return ordinal, ctx.Err()
				}
				reason = shadowFaultReason(shadowAdmissionPrefix, gerr)
			}
		}
		for i, rec := range b.Records {
			switch {
			case r.seen[dedup[i]]:
				r.row(sd, kind, ordinal, dedup[i], "dropped", shadowReasonDuplicateRetry, 0)
			case reason != "":
				r.row(sd, kind, ordinal, dedup[i], "dropped", reason, 0)
			default:
				r.seen[dedup[i]] = true
				r.row(sd, kind, ordinal, dedup[i], "admitted", "", 0)
				r.account(rec)
			}
			ordinal++
		}
	}
	return ordinal, nil
}

// fileDelivery runs one recorded log file through the owned file source
// (internal/sources): its registered templates classify every line, lines that
// match no template or carry an unapproved value are dropped by the source's own
// closed reasons (never by this tool), and the typed records go through the same
// admission path as pushed logs. Equal lines are distinct records.
func (r *shadowRun) fileDelivery(ctx context.Context, sd shadowDel, decl ShadowAdapterDeclaration) (string, error) {
	body := sd.del.Body
	if len(body) == 0 || body[len(body)-1] != '\n' {
		return shadowReasonMalformedBody, nil
	}
	if bytes.Count(body, []byte{'\n'}) > shadowMaxFileLines {
		return shadowReasonFileTooLong, nil
	}
	path := filepath.Join(r.scratch, strconv.Itoa(sd.index)+".log")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return shadowSourcePrefix + "unavailable", nil
	}
	defer os.Remove(path)
	sp := decl.File.sourcePolicy(path, model.Revision(r.m.PolicyRevision), r.ids.resource)
	sourceReason := func(err error) string {
		if se, ok := sources.AsError(err); ok {
			return shadowSourcePrefix + string(se.Reason)
		}
		return shadowSourcePrefix + "error"
	}
	recs, cp, err := sources.Read(ctx, sp, sources.Checkpoint{})
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return sourceReason(err), nil
	}
	pend := cp.Pending
	if pend == nil {
		return shadowReasonMalformedBody, nil
	}
	id := sources.Identity{Org: r.ids.org, Project: r.ids.project, Source: r.ids.source, Producer: r.ids.producer, Epoch: shadowDeriveID("epoch", r.digest, "file")}
	batches, err := sources.BuildBatches(id, sp, cp, recs)
	if err != nil {
		return sourceReason(err), nil
	}
	sum := sha256.Sum256(body)
	bodyID := hex.EncodeToString(sum[:])
	r.recv(decl.Kind, int(pend.Scanned))
	ordinal, err := r.admitBatches(ctx, sd, "log", batches, func(_ model.Record, i int) string { return bodyID + ":" + strconv.Itoa(i) })
	if err != nil {
		return "", err
	}
	for _, reason := range slices.Sorted(maps.Keys(pend.Dropped)) {
		for k := range pend.Dropped[reason] {
			r.row(sd, "log", ordinal, shadowHexDigest(r.digest, "file-drop", bodyID, reason, strconv.FormatUint(k, 10)), "dropped", shadowSourcePrefix+reason, 0)
			ordinal++
		}
	}
	return "", nil
}

// sourcePolicy is the owned file-source policy of the binding.
func (b *ShadowFileBinding) sourcePolicy(path string, revision model.Revision, res model.Resource) sources.SourcePolicy {
	labels := make(model.Labels, 0, len(b.StreamLabels))
	for _, k := range slices.Sorted(maps.Keys(b.StreamLabels)) {
		labels = append(labels, model.Label{Name: k, Value: b.StreamLabels[k]})
	}
	return sources.SourcePolicy{Name: b.Name, Kind: sources.KindFile, Class: sources.ClassStructured, Revision: revision, Resource: res, Labels: labels,
		Templates: b.Templates, MaxRecords: shadowMaxFileLines, MaxLineBytes: b.MaxLineBytes,
		File: &sources.FileSpec{Path: path, StartAt: sources.StartBeginning, TimeLayout: b.TimeLayout}}
}

// validate has the owned source validate the binding as a structured file source.
func (b *ShadowFileBinding) validate() error {
	res := model.Resource{Service: model.ID{1}, Environment: model.ID{2}, Build: model.ID{3}, Instance: "validate", Labels: model.Labels{}}
	return b.sourcePolicy(filepath.Join(os.TempDir(), "shadow-validate.log"), 1, res).Validate()
}

// account counts the declared source semantics an admitted record carries.
func (r *shadowRun) account(rec model.Record) {
	switch {
	case rec.Payload.Metric != nil:
		if rec.Payload.Metric.SampleKind == "stale" {
			r.rep.Semantics.StaleMarkersAdmitted++
		}
		if rec.Payload.Metric.Histogram != nil {
			r.rep.Semantics.NativeHistogramsAdmitted++
		}
	case rec.Payload.Log != nil:
		l := rec.Payload.Log
		var b strings.Builder
		fmt.Fprintf(&b, "%d|%s|%d|%s|", rec.ObservedAt, l.TemplateID, l.TemplateRevision, l.Line)
		for _, name := range slices.Sorted(maps.Keys(l.Fields)) {
			fmt.Fprintf(&b, "%s=%s;", name, l.Fields[name].Text())
		}
		for _, x := range l.StreamLabels {
			fmt.Fprintf(&b, "%s:%s,", x.Name, x.Value)
		}
		for _, name := range slices.Sorted(maps.Keys(l.Metadata)) {
			fmt.Fprintf(&b, "%s~%s;", name, l.Metadata[name].Text())
		}
		if r.logKeys[b.String()] {
			r.rep.Semantics.DuplicateLogLinesPreserved++
		}
		r.logKeys[b.String()] = true
	}
}

var shadowSafeName = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,128}$`)

// conditionDelivery folds a delivery of source condition events into the
// owned lifecycle. A non-empty reason rejects the delivery.
func (r *shadowRun) conditionDelivery(sd shadowDel) string {
	var body struct {
		Events []ShadowConditionInput `json:"events"`
	}
	dec := json.NewDecoder(bytes.NewReader(sd.del.Body))
	dec.DisallowUnknownFields()
	if dec.Decode(&body) != nil || dec.Decode(new(any)) != io.EOF || len(body.Events) == 0 || len(body.Events) > shadowMaxCondEvents {
		return shadowReasonMalformedBody
	}
	r.recv(ShadowAdapterConditions, len(body.Events))
	for ord, ev := range body.Events {
		r.applyCondition(sd, ord, ev)
	}
	return ""
}

func shadowSeverity(s string) notify.Severity {
	switch strings.ToLower(s) {
	case "critical", "page", "fatal":
		return notify.SeverityCritical
	case "major", "high", "error":
		return notify.SeverityMajor
	}
	return notify.SeverityMinor
}

func shadowSourceState(status string) notify.SourceState {
	switch status {
	case "firing", "recovering":
		return notify.SourceFiring
	case "recovered", "resolved":
		return notify.SourceRecovered
	}
	return notify.SourceUnknown
}

func (r *shadowRun) applyCondition(sd shadowDel, ord int, in ShadowConditionInput) {
	parts := []string{"condition", in.Condition, in.Epoch, strconv.FormatUint(in.Sequence, 10)}
	if in.Sequence == 0 {
		parts = append(parts, strconv.FormatInt(in.AtNS, 10), in.Status)
	}
	dedup := shadowHexDigest(append([]string{r.digest}, parts...)...)
	drop := func(reason string) { r.row(sd, "condition", ord, dedup, "dropped", reason, in.Sequence) }
	if !shadowSafeName.MatchString(in.Condition) || !shadowSafeName.MatchString(in.Epoch) || in.AtNS < 0 {
		drop(shadowReasonInvalidEvent)
		return
	}
	labels := make(model.Labels, 0, len(in.Labels))
	for _, k := range slices.Sorted(maps.Keys(in.Labels)) {
		labels = append(labels, model.Label{Name: k, Value: in.Labels[k]})
	}
	c := r.conds[in.Condition]
	if c == nil {
		id := shadowDeriveID("condition", r.digest, in.Condition)
		c = &shadowLife{id: id, entity: notify.Entity{Kind: notify.EntityCondition, ID: id}}
		r.conds[in.Condition], r.byEntity[id], r.condIDs[in.Condition] = c, in.Condition, id
	}
	event := model.ConditionEvent{Condition: c.id, Epoch: shadowDeriveID("epoch", r.digest, in.Epoch), Sequence: model.Uint64(in.Sequence), At: model.UnixNano(in.AtNS),
		Status: in.Status, Severity: in.Severity, Labels: labels}
	next, err := conditions.Reduce(c.state, event)
	if err != nil {
		var f *model.Fault
		if errors.As(err, &f) && f.Code == model.Conflict {
			drop(shadowReasonConflictingReplay)
		} else {
			drop(shadowReasonInvalidEvent)
		}
		return
	}
	accepted := next.Version != c.state.Version
	known := false
	for _, ref := range c.state.Recent {
		if ref.Epoch == event.Epoch && ref.Sequence == event.Sequence && ref.At == event.At {
			known = true
		}
	}
	switch {
	case accepted:
		r.row(sd, "condition", ord, dedup, "admitted", "", in.Sequence)
	case known:
		drop(shadowReasonDuplicateEvent)
	default:
		drop(shadowReasonLateVersion)
	}
	c.state = next
	r.decide(c, in, event, next)
}

// decide feeds the evidence to the shadow policy twin, late and duplicate
// evidence included: the twin's own source-version ordering must also hold.
func (r *shadowRun) decide(c *shadowLife, in ShadowConditionInput, event model.ConditionEvent, st conditions.State) {
	at := max(in.AtNS, c.at)
	c.at = at
	if c.twin == nil {
		twin, err := notify.NewShadowEvaluator(r.ids.org, r.ids.project, r.policyID, c.entity)
		if err != nil {
			r.rep.Decisions.Refused++
			return
		}
		c.twin = twin
		dest := notify.PolicyEvent{Kind: notify.EventDestination, Command: shadowDeriveID("destination", r.digest, c.entity.ID.String()), Org: r.ids.org, Project: r.ids.project, Policy: r.policyID,
			PolicyRef: notify.PolicyRef{Revision: 1, Config: &r.cfg}, Destination: &notify.DestinationChange{Recipient: r.recipient, Enabled: true}}
		if _, err := twin.Apply(dest, model.UnixNano(at)); err != nil {
			r.rep.Decisions.Refused++
			c.twin = nil
			return
		}
	}
	episode := shadowDeriveID("episode", r.digest, c.entity.ID.String(), in.Epoch)
	if st.Episode != nil {
		episode = *st.Episode
	}
	seq := in.Sequence
	if seq == 0 {
		seq = uint64(st.Version)
	}
	freshness := notify.FreshnessFresh
	if in.Status == "unknown" {
		freshness = notify.FreshnessUnknown
	}
	evidence := notify.PolicyEvent{Kind: notify.EventCondition, Command: shadowDeriveID("event", r.digest, c.entity.ID.String(), in.Epoch, strconv.FormatUint(in.Sequence, 10), strconv.FormatInt(in.AtNS, 10), in.Status),
		Org: r.ids.org, Project: r.ids.project, Policy: r.policyID, PolicyRef: notify.PolicyRef{Revision: 1, Config: &r.cfg}, Entity: &c.entity,
		Condition: &notify.ConditionEvidence{Seq: seq, State: shadowSourceState(in.Status), Freshness: freshness, Severity: shadowSeverity(in.Severity), Episode: episode}}
	out, err := c.twin.Apply(evidence, model.UnixNano(at))
	if err != nil {
		r.rep.Decisions.Refused++
		return
	}
	r.decisions = append(r.decisions, out...)
}

// finish builds the report: lifecycle answers, decisions, ledger digest,
// reconciliation and parity.
func (r *shadowRun) finish(ctx context.Context) (ShadowReport, error) {
	rep := r.rep
	for _, name := range slices.Sorted(maps.Keys(r.conds)) {
		st := r.conds[name].state
		rep.Conditions = append(rep.Conditions, ShadowCondition{Name: name, SourceVersion: uint64(st.Sequence), Phase: string(st.Phase), Freshness: string(st.Freshness), Accepted: int(st.Version)})
	}
	refused := rep.Decisions.Refused
	rep.Decisions = shadowSummarize(r.decisions, r.byEntity)
	rep.Decisions.Refused = refused
	rep.PolicyViolations = slices.Sorted(maps.Keys(r.violations))
	rep.Ledger = r.ledger
	if rep.Ledger == nil {
		rep.Ledger = []ShadowLedgerEntry{}
	}
	raw, err := json.Marshal(rep.Ledger)
	if err != nil {
		return ShadowReport{}, err
	}
	sum := sha256.Sum256(raw)
	rep.LedgerDigest = hex.EncodeToString(sum[:])
	if spec := r.d.Feed.Parity; spec != nil {
		if err := r.parity(ctx, spec, &rep); err != nil {
			return ShadowReport{}, err
		}
	}
	reconcileErr := shadowReconcileHook(rep)
	rep.Reconciled = reconcileErr == nil
	r.rep = rep
	switch {
	case reconcileErr != nil:
		return rep, reconcileErr
	case len(rep.PolicyViolations) > 0:
		return rep, fmt.Errorf("%w: %s", ErrShadowPolicyFailed, strings.Join(rep.PolicyViolations, ","))
	}
	return rep, nil
}

// shadowSummarize condenses the twin's decisions: what would be delivered,
// what is suppressed and why, and every decision itself.
func shadowSummarize(decisions []notify.ShadowDecision, names map[model.ID]string) ShadowDecisions {
	out := ShadowDecisions{Suppressed: map[string]int{}, Kinds: map[string]int{}, Items: []ShadowDecisionItem{}}
	for _, d := range decisions {
		item := ShadowDecisionItem{Condition: names[d.Entity.ID], Kind: string(d.Kind), ImpactRevision: d.ImpactRevision, Ordinal: d.Ordinal, SourceVersion: d.SourceVersion, Suppression: string(d.Suppression)}
		if d.Recipient != nil {
			item.Recipient = shadowRecipient
		}
		out.Items = append(out.Items, item)
		out.Total++
		out.Kinds[item.Kind]++
		if d.Suppression == "" {
			out.WouldDeliver++
		} else {
			out.Suppressed[item.Suppression]++
		}
	}
	return out
}

// shadowReconcileHook is the reconciliation the run applies to its own report;
// a test replaces it to prove a failed reconciliation fails the run.
var shadowReconcileHook = shadowReconcile

func (r *shadowRun) parity(ctx context.Context, spec *ShadowParitySpec, rep *ShadowReport) error {
	pr := &rep.Parity
	for _, q := range spec.Queries {
		ans, err := shadowAnswer(ctx, r.d, q)
		if err != nil {
			return err
		}
		pr.QueriesCompared++
		pr.Mismatches = append(pr.Mismatches, shadowCompareAnswers(q.ID, q.Expect, ans)...)
	}
	pr.LifecycleCompared = len(spec.Conditions)
	pr.Mismatches = append(pr.Mismatches, shadowCompareLifecycle(spec.Conditions, rep.Conditions)...)
	if spec.LegacyDecisions != nil {
		n, mm := shadowCompareDecisions(r.byEntity, r.condIDs, r.decisions, spec.LegacyDecisions)
		pr.DecisionsCompared = n
		pr.Mismatches = append(pr.Mismatches, mm...)
	}
	tally := func(domain string, want, got map[string]int) {
		if want == nil {
			return
		}
		keys := map[string]bool{}
		for k, n := range want {
			keys[k] = n != 0 || keys[k]
		}
		for k, n := range got {
			keys[k] = n != 0 || keys[k]
		}
		for _, present := range keys {
			if present {
				pr.LedgerCompared++
			}
		}
		pr.Mismatches = append(pr.Mismatches, shadowCompareReasons(domain, want, got)...)
	}
	tally("ledger", spec.ExpectedDropReasons, rep.Records.DroppedByReason)
	tally("ledger", spec.ExpectedRejectReason, rep.Deliveries.RejectedByReason)
	return nil
}

// ---- isolated destination -----------------------------------------------

func shadowRandomSecret() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ShadowProvision builds the isolated in-process destination for a mapping in a
// fresh directory: an org, a project, one onboarded source with the given
// source policy and one project-scoped reader. dir must not exist. The returned
// cleanup closes the engines; it does not delete dir.
func ShadowProvision(ctx context.Context, dir string, m SourceMapping, sp model.SourcePolicy) (SoundpostDestination, func() error, error) {
	ids, err := shadowParseIDs(m)
	if err != nil {
		return SoundpostDestination{}, nil, err
	}
	digest, err := ShadowSourcePolicyDigest(sp)
	if err != nil {
		return SoundpostDestination{}, nil, fmt.Errorf("%w: source policy", ErrShadowDestination)
	}
	if digest != m.SourcePolicySHA256 || uint64(sp.Revision) != m.PolicyRevision {
		return SoundpostDestination{}, nil, fmt.Errorf("%w: source policy is not the one the mapping binds", ErrShadowDestination)
	}
	if _, err := os.Stat(dir); err == nil {
		return SoundpostDestination{}, nil, fmt.Errorf("%w: destination directory exists", ErrShadowDestination)
	}
	app, err := appcore.Open(dir)
	if err != nil {
		return SoundpostDestination{}, nil, fmt.Errorf("%w: open: %v", ErrShadowDestination, err)
	}
	cleanup := func() error { return app.Close() }
	fail := func(err error) (SoundpostDestination, func() error, error) {
		cleanup()
		return SoundpostDestination{}, nil, fmt.Errorf("%w: provisioning: %v", ErrShadowDestination, err)
	}
	token, err := app.Control.BootstrapToken()
	if err != nil {
		return fail(err)
	}
	adminPass, err := shadowRandomSecret()
	if err != nil {
		return fail(err)
	}
	session, err := app.Auth.Bootstrap(ctx, token, "shadow-admin@shadow.invalid", adminPass)
	if err != nil {
		return fail(err)
	}
	actor, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		return fail(err)
	}
	command := func(kind string, pl auth.AdminPayload) error {
		var rev model.Revision
		if err := app.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil }); err != nil {
			return err
		}
		pl.Reason = "shadow isolated destination"
		raw, err := json.Marshal(pl)
		if err != nil {
			return err
		}
		_, err = app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: ids.org, Kind: kind, Payload: raw})
		return err
	}
	if err := command("create_org", auth.AdminPayload{Name: "shadow"}); err != nil {
		return fail(err)
	}
	if err := command("create_project", auth.AdminPayload{ID: ids.project, Name: "shadow"}); err != nil {
		return fail(err)
	}
	issued, err := app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: ids.org, Project: ids.project, Source: ids.source,
		Expires: model.UnixNano(time.Now().Add(12 * time.Hour).UnixNano()), Policy: sp, Reason: "shadow isolated destination"})
	if err != nil {
		return fail(err)
	}
	cred, err := app.Auth.AuthenticateSource(ctx, issued.Credential, "", false)
	if err != nil {
		return fail(err)
	}
	user := model.NewID()
	readerPass, err := shadowRandomSecret()
	if err != nil {
		return fail(err)
	}
	email := "shadow-reader@shadow.invalid"
	if err := command("create_user", auth.AdminPayload{ID: user, Email: email, Password: readerPass}); err != nil {
		return fail(err)
	}
	if err := command("membership", auth.AdminPayload{UserID: user, Enabled: true}); err != nil {
		return fail(err)
	}
	if err := command("grant", auth.AdminPayload{UserID: user, ProjectID: ids.project, Enabled: true, Permissions: []string{string(auth.Read)}}); err != nil {
		return fail(err)
	}
	login, err := app.Auth.Login(ctx, email, readerPass, "")
	if err != nil {
		return fail(err)
	}
	readerCred, err := app.Auth.Authenticate(ctx, login.Token)
	if err != nil {
		return fail(err)
	}
	scope, err := app.Auth.Authorize(ctx, readerCred, ids.org, []model.ID{ids.project}, auth.Read)
	if err != nil {
		return fail(err)
	}
	return SoundpostDestination{App: app, Org: ids.org, Project: ids.project, Source: ids.source, PolicyRevision: uint64(sp.Revision),
		SourcePolicyClass: sp.Class, SourcePolicySHA256: digest, Credential: &cred, Reader: &scope}, cleanup, nil
}

// ---- CLI ----------------------------------------------------------------

func shadowReadJSON(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, shadowMaxCaptureBytes+1))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing or oversized JSON")
	}
	return nil
}

// runShadow is the `shadow` subcommand. It provisions an isolated scratch
// destination, replays the recorded capture and writes the private report and
// the closed public summary exclusively. It never opens a network connection.
func runShadow(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("shadow", flag.ContinueOnError)
	mappingPath := fs.String("mapping", "", "signed source mapping JSON")
	policyPath := fs.String("policy", "", "shadow policy JSON")
	sourcePolicyPath := fs.String("source-policy", "", "source policy JSON of the isolated destination")
	capturePath := fs.String("capture", "", "recorded deliveries and parity expectations JSON")
	workdir := fs.String("workdir", "", "existing directory for the scratch destination")
	reportPath := fs.String("report", "", "new private full report file")
	summaryPath := fs.String("public-summary", "", "new public summary file")
	timeout := fs.Duration("timeout", 5*time.Minute, "overall deadline (positive, at most 1h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || !nonempty(*mappingPath, *policyPath, *sourcePolicyPath, *capturePath, *workdir, *reportPath, *summaryPath) {
		return errors.New("usage: adoption shadow --mapping FILE --policy FILE --source-policy FILE --capture FILE --workdir DIRECTORY --report NEWFILE --public-summary NEWFILE")
	}
	if *timeout <= 0 || *timeout > time.Hour {
		return errors.New("timeout must be positive and at most 1h")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	var m SourceMapping
	var p ShadowPolicy
	var sp model.SourcePolicy
	var feed ShadowFeed
	if shadowReadJSON(*mappingPath, &m) != nil || shadowReadJSON(*policyPath, &p) != nil || shadowReadJSON(*capturePath, &feed) != nil {
		return errors.New("invalid operator input")
	}
	if err := shadowReadJSON(*sourcePolicyPath, &sp); err != nil {
		return errors.New("invalid operator input")
	}
	info, err := os.Stat(*workdir)
	if err != nil || !info.IsDir() {
		return errors.New("workdir must be an existing directory")
	}
	// Verify the mapping and policy before anything is provisioned.
	if err := p.validate(); err != nil {
		return err
	}
	if _, err := shadowVerifyMapping(m, p, shadowNow(p)); err != nil {
		return err
	}
	scratch, err := os.MkdirTemp(*workdir, "shadow-")
	if err != nil {
		return errors.New("scratch directory creation failed")
	}
	defer os.RemoveAll(scratch)
	dest, closeDest, err := ShadowProvision(ctx, filepath.Join(scratch, "destination"), m, sp)
	if err != nil {
		return err
	}
	defer closeDest()
	dest.Feed = feed
	report, runErr := RunShadow(ctx, m, dest, p)
	if report.MappingDigest != "" {
		if err := writeExclusive(*reportPath, report); err != nil {
			return errors.New("report creation failed")
		}
	}
	if runErr != nil {
		return runErr
	}
	if err := writeExclusive(*summaryPath, report.Public()); err != nil {
		return errors.New("summary creation failed; private report retained")
	}
	return nil
}

func shadowNow(p ShadowPolicy) time.Time {
	if p.Clock != nil {
		return p.Clock().UTC()
	}
	return time.Now().UTC()
}

func shadowB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func shadowSumReasons(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// shadowReconcile verifies that a report is internally exact: for the records
// and for every adapter, received equals admitted plus dropped, dropped equals
// the sum of its reasons, and every tally equals the same tally recomputed from
// the ledger rows. The delivery tallies reconcile the same way.
func shadowReconcile(r ShadowReport) error {
	bad := func(why string) error { return fmt.Errorf("%w: %s", ErrShadowReconcile, why) }
	type tally struct {
		admitted, dropped int
		reasons           map[string]int
	}
	newTally := func() *tally { return &tally{reasons: map[string]int{}} }
	total, perAdapter := newTally(), map[string]*tally{}
	rejected := map[string]int{}
	rejectedRows := 0
	for _, e := range r.Ledger {
		if e.Kind == "delivery" {
			if e.Outcome != "rejected" || e.Reason == "" {
				return bad("delivery row without a rejection reason")
			}
			rejectedRows++
			rejected[e.Reason]++
			continue
		}
		t := perAdapter[e.Adapter]
		if t == nil {
			t = newTally()
			perAdapter[e.Adapter] = t
		}
		switch {
		case e.Outcome == "admitted" && e.Reason == "":
			total.admitted++
			t.admitted++
		case e.Outcome == "dropped" && e.Reason != "":
			total.dropped++
			total.reasons[e.Reason]++
			t.dropped++
			t.reasons[e.Reason]++
		default:
			return bad("record row without a valid outcome and reason")
		}
	}
	d := r.Deliveries
	if d.Received != d.Accepted+d.Rejected || d.Rejected != shadowSumReasons(d.RejectedByReason) || d.Rejected != rejectedRows {
		return bad("delivery tallies")
	}
	if len(shadowCompareReasons("ledger", d.RejectedByReason, rejected)) != 0 {
		return bad("delivery rejection reasons")
	}
	rec := r.Records
	if rec.Received != rec.Admitted+rec.Dropped || rec.Dropped != shadowSumReasons(rec.DroppedByReason) {
		return bad("record tallies")
	}
	if rec.Admitted != total.admitted || rec.Dropped != total.dropped || len(shadowCompareReasons("ledger", rec.DroppedByReason, total.reasons)) != 0 {
		return bad("record tallies differ from the ledger")
	}
	names := map[string]bool{}
	for n := range r.PerAdapter {
		names[n] = true
	}
	for n := range perAdapter {
		names[n] = true
	}
	var recv, adm, drop int
	for n := range names {
		c, l := r.PerAdapter[n], perAdapter[n]
		if l == nil {
			l = newTally()
		}
		if c.Received != c.Admitted+c.Dropped || c.Dropped != shadowSumReasons(c.DroppedByReason) {
			return bad("adapter tallies")
		}
		if c.Admitted != l.admitted || c.Dropped != l.dropped || len(shadowCompareReasons("ledger", c.DroppedByReason, l.reasons)) != 0 {
			return bad("adapter tallies differ from the ledger")
		}
		recv, adm, drop = recv+c.Received, adm+c.Admitted, drop+c.Dropped
	}
	if recv != rec.Received || adm != rec.Admitted || drop != rec.Dropped {
		return bad("adapter tallies do not add up to the totals")
	}
	return nil
}

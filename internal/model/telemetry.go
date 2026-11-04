// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"
)

type Kind string

const (
	Metric         Kind = "metric"
	Log            Kind = "log"
	SpanKind       Kind = "span"
	ErrorKind      Kind = "error"
	JobAttempt     Kind = "job_attempt"
	Replay         Kind = "replay_chunk"
	Profile        Kind = "profile_chunk"
	CapabilityKind Kind = "capability"
	Loss           Kind = "loss"
	Condition      Kind = "condition"
)

func (k Kind) Valid() bool {
	switch k {
	case Metric, Log, SpanKind, ErrorKind, JobAttempt, Replay, Profile, CapabilityKind, Loss, Condition:
		return true
	}
	return false
}

type Hash [32]byte

func (h Hash) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(h[:])) }
func (h *Hash) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) != nil || len(s) != 64 {
		return Fail(Invalid)
	}
	v, e := hex.DecodeString(s)
	if e != nil || hex.EncodeToString(v) != s {
		return Fail(Invalid)
	}
	copy(h[:], v)
	return nil
}
func HashCanonical(b []byte) Hash { return Hash(sha256.Sum256(b)) }
func (h Hash) String() string     { return hex.EncodeToString(h[:]) }

// Scalar deliberately cannot hold objects, arrays, floating point or arbitrary attributes.
type Scalar struct{ raw string }

func (s Scalar) MarshalJSON() ([]byte, error) {
	if s.raw == "" {
		return []byte("null"), nil
	}
	return []byte(s.raw), nil
}
func (s *Scalar) UnmarshalJSON(b []byte) error {
	var v any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if d.Decode(&v) != nil {
		return Fail(Invalid)
	}
	switch x := v.(type) {
	case nil, bool:
	case string:
		if !utf8.ValidString(x) || len(x) > 4096 {
			return Fail(Invalid)
		}
	case json.Number:
		if _, e := strconv.ParseInt(string(x), 10, 64); e != nil {
			return Fail(Invalid)
		}
	default:
		return Fail(Invalid)
	}
	out, e := json.Marshal(v)
	if e != nil {
		return Fail(Invalid)
	}
	s.raw = string(out)
	return nil
}
func (s Scalar) Text() string {
	if len(s.raw) > 0 && s.raw[0] == '"' {
		var text string
		if json.Unmarshal([]byte(s.raw), &text) == nil {
			return text
		}
	}
	if s.raw == "" {
		return "null"
	}
	return s.raw
}

type Resource struct {
	Service     ID     `json:"service_id"`
	Environment ID     `json:"environment_id"`
	Build       ID     `json:"build_id"`
	Instance    string `json:"instance_pseudonym"`
	Labels      Labels `json:"labels"`
}
type Batch struct {
	Version        uint16   `json:"version"`
	Project        ID       `json:"project"`
	Source         ID       `json:"source"`
	Producer       ID       `json:"producer"`
	ID             ID       `json:"id"`
	PolicyRevision Revision `json:"policy_revision"`
	RouteSlot      uint16   `json:"route_slot"`
	Records        []Record `json:"records"`
}
type Record struct {
	ID         ID       `json:"id"`
	Kind       Kind     `json:"kind"`
	ObservedAt UnixNano `json:"observed_at_ns"`
	Resource   Resource `json:"resource"`
	Payload    Payload  `json:"-"`
}
type Payload struct {
	Metric     *MetricPoint
	Log        *LogRecord
	Span       *Span
	Error      *ErrorOccurrence
	Job        *JobAttemptEvent
	Replay     *ReplayChunk
	Profile    *ProfileChunk
	Capability *Capability
	Loss       *LossReport
	Condition  *ConditionEvent
}

func (p Payload) Value(k Kind) (any, error) {
	n := 0
	for _, v := range []bool{p.Metric != nil, p.Log != nil, p.Span != nil, p.Error != nil, p.Job != nil, p.Replay != nil, p.Profile != nil, p.Capability != nil, p.Loss != nil, p.Condition != nil} {
		if v {
			n++
		}
	}
	if n != 1 {
		return nil, Fail(Invalid)
	}
	switch k {
	case Metric:
		if p.Metric != nil {
			return p.Metric, nil
		}
	case Log:
		if p.Log != nil {
			return p.Log, nil
		}
	case SpanKind:
		if p.Span != nil {
			return p.Span, nil
		}
	case ErrorKind:
		if p.Error != nil {
			return p.Error, nil
		}
	case JobAttempt:
		if p.Job != nil {
			return p.Job, nil
		}
	case Replay:
		if p.Replay != nil {
			return p.Replay, nil
		}
	case Profile:
		if p.Profile != nil {
			return p.Profile, nil
		}
	case CapabilityKind:
		if p.Capability != nil {
			return p.Capability, nil
		}
	case Loss:
		if p.Loss != nil {
			return p.Loss, nil
		}
	case Condition:
		if p.Condition != nil {
			return p.Condition, nil
		}
	}
	return nil, Fail(Invalid)
}
func (r Record) MarshalJSON() ([]byte, error) {
	p, e := r.Payload.Value(r.Kind)
	if e != nil {
		return nil, e
	}
	return json.Marshal(struct {
		ID       ID       `json:"id"`
		Kind     Kind     `json:"kind"`
		At       UnixNano `json:"observed_at_ns"`
		Resource Resource `json:"resource"`
		Payload  any      `json:"payload"`
	}{r.ID, r.Kind, r.ObservedAt, r.Resource, p})
}
func (r *Record) UnmarshalJSON(b []byte) error {
	var x struct {
		ID       ID              `json:"id"`
		Kind     Kind            `json:"kind"`
		At       UnixNano        `json:"observed_at_ns"`
		Resource Resource        `json:"resource"`
		Payload  json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(b, &x) != nil || !x.Kind.Valid() {
		return Fail(Invalid)
	}
	var p Payload
	var target any
	switch x.Kind {
	case Metric:
		p.Metric = &MetricPoint{}
		target = p.Metric
	case Log:
		p.Log = &LogRecord{}
		target = p.Log
	case SpanKind:
		p.Span = &Span{}
		target = p.Span
	case ErrorKind:
		p.Error = &ErrorOccurrence{}
		target = p.Error
	case JobAttempt:
		p.Job = &JobAttemptEvent{}
		target = p.Job
	case Replay:
		p.Replay = &ReplayChunk{}
		target = p.Replay
	case Profile:
		p.Profile = &ProfileChunk{}
		target = p.Profile
	case CapabilityKind:
		p.Capability = &Capability{}
		target = p.Capability
	case Loss:
		p.Loss = &LossReport{}
		target = p.Loss
	case Condition:
		p.Condition = &ConditionEvent{}
		target = p.Condition
	}
	if StrictJSON(x.Payload, target) != nil {
		return Fail(Invalid)
	}
	*r = Record{x.ID, x.Kind, x.At, x.Resource, p}
	return nil
}

type MetricPoint struct {
	Name           string           `json:"name"`
	Labels         Labels           `json:"labels"`
	SampleKind     string           `json:"sample_kind"`
	Value          *FloatBits       `json:"value,omitempty"`
	Histogram      *NativeHistogram `json:"histogram,omitempty"`
	StartTimestamp *UnixNano        `json:"start_timestamp_ns,omitempty"`
	Unit           string           `json:"unit"`
	Type           string           `json:"type"`
	ExemplarTrace  *ID              `json:"exemplar_trace,omitempty"`
	ExemplarSpan   *SpanID          `json:"exemplar_span,omitempty"`
}
type LogRecord struct {
	Timestamp        *UnixNano         `json:"timestamp_ns,omitempty"`
	Severity         string            `json:"severity"`
	TemplateID       string            `json:"template_id"`
	TemplateRevision Revision          `json:"template_revision"`
	Fields           map[string]Scalar `json:"fields"`
	Line             string            `json:"line"`
	StreamLabels     Labels            `json:"stream_labels"`
	Metadata         map[string]Scalar `json:"structured_metadata"`
	SourceClass      string            `json:"source_class"`
	Trace            *ID               `json:"trace_id,omitempty"`
	Span             *SpanID           `json:"span_id,omitempty"`
	Run              *ID               `json:"run_id,omitempty"`
}
type SpanLink struct {
	Trace ID     `json:"trace_id"`
	Span  SpanID `json:"span_id"`
}
type Span struct {
	Trace             ID          `json:"trace_id"`
	ID                SpanID      `json:"span_id"`
	Parent            *SpanID     `json:"parent_id"`
	Kind              string      `json:"span_kind"`
	Operation         string      `json:"operation"`
	Start             TraceClock  `json:"start"`
	End               *TraceClock `json:"end"`
	Status            string      `json:"status"`
	Dependency        string      `json:"dependency_alias"`
	Links             []SpanLink  `json:"links"`
	SampleProbability FloatBits   `json:"sample_probability"`
	SampleDecision    string      `json:"sample_decision"`
	Job               *ID         `json:"job_id,omitempty"`
	Replay            *ID         `json:"replay_id,omitempty"`
	Profile           *ID         `json:"profile_id,omitempty"`
}
type Frame struct {
	Module   string  `json:"module_id"`
	Function string  `json:"function"`
	Artifact string  `json:"artifact_id"`
	Line     uint32  `json:"line"`
	Column   *uint32 `json:"column"`
	InApp    bool    `json:"in_app"`
	Async    bool    `json:"async"`
}
type ExceptionNode struct {
	ID         uint32  `json:"id"`
	Class      string  `json:"exception_class"`
	Frames     []Frame `json:"frames"`
	Suppressed bool    `json:"context_suppressed"`
}
type ExceptionEdge struct {
	From    uint32  `json:"from"`
	To      uint32  `json:"to"`
	Kind    string  `json:"kind"`
	Ordinal *uint32 `json:"ordinal,omitempty"`
}
type ExceptionGraph struct {
	Nodes   []ExceptionNode `json:"nodes"`
	Edges   []ExceptionEdge `json:"edges"`
	Reasons []string        `json:"reasons"`
}
type ErrorOccurrence struct {
	Occurrence ID              `json:"occurrence_id"`
	Class      string          `json:"exception_class"`
	Mechanism  string          `json:"mechanism"`
	Frames     []Frame         `json:"frames"`
	Graph      *ExceptionGraph `json:"exception_graph,omitempty"`
	Template   *string         `json:"template_id,omitempty"`
	Code       *string         `json:"code"`
	Build      ID              `json:"build_id"`
	Release    *ID             `json:"release_id,omitempty"`
	Handled    bool            `json:"handled"`
	Fatal      bool            `json:"fatal"`
	Trace      *ID             `json:"trace_id,omitempty"`
	Span       *SpanID         `json:"span_id,omitempty"`
	Replay     *ID             `json:"replay_id,omitempty"`
	Profile    *ID             `json:"profile_id,omitempty"`
	Run        *ID             `json:"run_id,omitempty"`
}
type JobAttemptEvent struct {
	Job        ID        `json:"job_id"`
	Run        ID        `json:"run_id"`
	Attempt    ID        `json:"attempt_id"`
	Schedule   string    `json:"schedule_occurrence"`
	Ordinal    Uint64    `json:"ordinal"`
	Epoch      ID        `json:"producer_epoch"`
	Sequence   Uint64    `json:"sequence"`
	State      string    `json:"state"`
	Observed   UnixNano  `json:"observed_ns"`
	Terminal   *UnixNano `json:"terminal_ns"`
	CauseTrace *ID       `json:"cause_trace,omitempty"`
	CauseError *ID       `json:"cause_error,omitempty"`
}
type MaskedNode struct {
	ID     Uint64 `json:"id"`
	Parent Uint64 `json:"parent"`
	Tag    string `json:"tag"`
	Class  string `json:"class"`
	Text   string `json:"text"`
}
type MaskedEvent struct {
	At   MonoNano `json:"at_ns"`
	Kind string   `json:"kind"`
	Node Uint64   `json:"node"`
	X    int32    `json:"x"`
	Y    int32    `json:"y"`
}
type ReplayChunk struct {
	Replay             ID            `json:"replay_id"`
	Session            ID            `json:"session_id"`
	Recorder           string        `json:"recorder_version"`
	Sequence           Uint64        `json:"sequence"`
	Previous           Hash          `json:"previous_hash"`
	CheckpointSequence Uint64        `json:"checkpoint_sequence"`
	Checkpoint         Hash          `json:"checkpoint_hash"`
	Clock              TraceClock    `json:"clock"`
	Nodes              []MaskedNode  `json:"nodes"`
	Events             []MaskedEvent `json:"events"`
	Loss               Uint64        `json:"loss"`
	Gap                bool          `json:"gap"`
	PolicyRevision     Revision      `json:"capture_policy_revision"`
}
type ProfileFrame struct {
	Module   string `json:"module_id"`
	Function string `json:"function"`
	Artifact string `json:"artifact_id"`
	Offset   Uint64 `json:"offset"`
	Reason   string `json:"reason"`
}
type ProfileStack struct {
	Frames []uint32 `json:"frames"`
}
type ProfileSample struct {
	At     MonoNano             `json:"at_ns"`
	Stack  uint32               `json:"stack"`
	Count  Uint64               `json:"count"`
	Thread Uint64               `json:"thread"`
	Native *ProfileNativeSample `json:"native,omitempty"`
}
type ProfileInterval struct {
	Start      MonoNano           `json:"start_ns"`
	End        MonoNano           `json:"end_ns"`
	Stack      uint32             `json:"stack"`
	Kind       string             `json:"kind"`
	Thread     Uint64             `json:"thread"`
	Censored   bool               `json:"censored"`
	NativeTask *ProfileNativeTask `json:"native_task,omitempty"`
	Unit       string             `json:"unit,omitempty"`
	Reason     string             `json:"reason,omitempty"`
	Correction bool               `json:"correction,omitempty"`
}
type ProfileChunk struct {
	Profile            ID                   `json:"profile_id"`
	Process            ID                   `json:"process_id"`
	Capability         ID                   `json:"capability_id"`
	Method             string               `json:"method"`
	Units              string               `json:"units"`
	Start              UnixNano             `json:"start_ns"`
	End                UnixNano             `json:"end_ns"`
	Clock              TraceClock           `json:"clock"`
	Frames             []ProfileFrame       `json:"frames"`
	Stacks             []ProfileStack       `json:"stacks"`
	Samples            []ProfileSample      `json:"samples"`
	Intervals          []ProfileInterval    `json:"intervals"`
	Loss               Uint64               `json:"loss"`
	Truncated          bool                 `json:"truncated"`
	NativeDomain       *ProfileNativeDomain `json:"native_domain,omitempty"`
	PolicyRevision     Revision             `json:"policy_revision,omitempty"`
	Sequence           Uint64               `json:"sequence,omitempty"`
	Complete           bool                 `json:"complete,omitempty"`
	NativeCapabilities []ID                 `json:"native_capabilities,omitempty"`
	NativeLoss         []ProfileNativeLoss  `json:"native_loss,omitempty"`
}
type Coverage struct {
	Frames  string `json:"frames"`
	Threads string `json:"threads"`
	Workers string `json:"workers"`
	Tasks   string `json:"tasks"`
}
type Capability struct {
	Runtime  string      `json:"runtime"`
	Version  string      `json:"version"`
	Build    string      `json:"build"`
	OS       string      `json:"os"`
	Arch     string      `json:"arch"`
	Signal   Kind        `json:"signal"`
	Method   string      `json:"method"`
	Status   string      `json:"status"`
	Reason   string      `json:"reason"`
	Coverage Coverage    `json:"coverage"`
	Clock    ClockDomain `json:"clock_domain"`
	Expires  UnixNano    `json:"expires_ns"`
}
type LossReport struct {
	Source       ID       `json:"source"`
	Producer     ID       `json:"producer"`
	Epoch        ID       `json:"producer_epoch"`
	Start        UnixNano `json:"start_ns"`
	End          UnixNano `json:"end_ns"`
	Signal       Kind     `json:"signal"`
	Reason       string   `json:"reason"`
	Count        Uint64   `json:"count"`
	LastAck      *Cursor  `json:"last_ack"`
	QueueBytes   Uint64   `json:"queue_bytes"`
	QueueRecords Uint64   `json:"queue_records"`
}
type ConditionEvent struct {
	Condition ID       `json:"condition_id"`
	Epoch     ID       `json:"epoch"`
	Sequence  Uint64   `json:"sequence"`
	At        UnixNano `json:"event_ns"`
	Status    string   `json:"status"`
	Severity  string   `json:"severity"`
	Labels    Labels   `json:"labels"`
	Links     []ID     `json:"links"`
}
type SignalDeadline struct {
	Kind        Kind     `json:"kind"`
	RetainUntil UnixNano `json:"retain_until_ns"`
}
type Receipt struct {
	Version         uint16           `json:"version"`
	BatchID         ID               `json:"batch_id"`
	Hash            Hash             `json:"hash"`
	Cursor          Cursor           `json:"cursor"`
	RetainUntil     UnixNano         `json:"retain_until_ns"`
	SignalDeadlines []SignalDeadline `json:"signal_deadlines"`
	DedupUntil      UnixNano         `json:"dedup_until_ns"`
	Historical      bool             `json:"historical,omitempty"`
}
type ReceiptRequest struct {
	Source       ID     `json:"source"`
	Producer     ID     `json:"producer"`
	RouteSlot    uint16 `json:"route_slot"`
	BatchID      ID     `json:"batch_id"`
	OriginalHash Hash   `json:"original_hash"`
}
type NormalizedBatch struct {
	Batch
	Org         ID                   `json:"org"`
	Hash        Hash                 `json:"hash"`
	Canonical   []byte               `json:"canonical"`
	PolicyEpoch Uint64               `json:"policy_epoch"`
	PolicyHash  string               `json:"policy_hash"`
	AdmissionAt UnixNano             `json:"admission_at_ns"`
	Deadlines   []SignalDeadline     `json:"deadlines"`
	Reservation AdmissionReservation `json:"reservation"`
	Series      []string             `json:"series"`
}

func CanonicalJSON(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	var x any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e = d.Decode(&x); e != nil {
		return nil, e
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if e = enc.Encode(x); e != nil {
		return nil, e
	}
	return bytes.TrimSuffix(out.Bytes(), []byte{'\n'}), nil
}
func StrictJSON(b []byte, v any) error {
	if ValidateJSON(b) != nil {
		return Fail(Invalid)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return Fail(Invalid)
	}
	if d.Decode(new(any)) != io.EOF {
		return Fail(Invalid)
	}
	return nil
}

// ValidateJSON rejects duplicate keys, invalid UTF-8, lone surrogate escapes, and excessive depth.
func ValidateJSON(b []byte) error {
	if !utf8.Valid(b) {
		return Fail(Invalid)
	}
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		if i+1 >= len(b) {
			return Fail(Invalid)
		}
		if b[i+1] != 'u' {
			i++
			continue
		}
		if i+5 >= len(b) {
			return Fail(Invalid)
		}
		n, e := strconv.ParseUint(string(b[i+2:i+6]), 16, 16)
		if e != nil {
			return Fail(Invalid)
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+11 >= len(b) || b[i+6] != '\\' || b[i+7] != 'u' {
				return Fail(Invalid)
			}
			m, e := strconv.ParseUint(string(b[i+8:i+12]), 16, 16)
			if e != nil || m < 0xdc00 || m > 0xdfff {
				return Fail(Invalid)
			}
			i += 11
		} else if n >= 0xdc00 && n <= 0xdfff {
			return Fail(Invalid)
		} else {
			i += 5
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if walkJSON(d, 0) != nil {
		return Fail(Invalid)
	}
	if _, e := d.Token(); e != io.EOF {
		return Fail(Invalid)
	}
	return nil
}
func walkJSON(d *json.Decoder, depth int) error {
	if depth > 64 {
		return Fail(Invalid)
	}
	t, e := d.Token()
	if e != nil {
		return e
	}
	v, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch v {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := k.(string)
			if !ok || seen[s] {
				return Fail(Invalid)
			}
			seen[s] = true
			if e = walkJSON(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e = walkJSON(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return Fail(Invalid)
	}
	_, e = d.Token()
	return e
}
func OwnerKey(r Record) ([]byte, error) {
	if _, e := r.Payload.Value(r.Kind); e != nil {
		return nil, e
	}
	switch r.Kind {
	case Metric:
		return CanonicalJSON(struct {
			Name   string `json:"name"`
			Labels Labels `json:"labels"`
		}{r.Payload.Metric.Name, r.Payload.Metric.Labels})
	case Log:
		return CanonicalJSON(r.Payload.Log.StreamLabels)
	case SpanKind:
		return []byte(r.Payload.Span.Trace.String()), nil
	case ErrorKind:
		return []byte(r.Payload.Error.Occurrence.String()), nil
	case JobAttempt:
		return []byte(r.Payload.Job.Run.String()), nil
	case Replay:
		return []byte(r.Payload.Replay.Replay.String()), nil
	case Profile:
		return []byte(r.Payload.Profile.Profile.String()), nil
	case Condition:
		return []byte(r.Payload.Condition.Condition.String()), nil
	}
	return nil, nil
}
func OwnerSlot(org, project, source, producer ID, r Record) (uint16, error) {
	owner, e := OwnerKey(r)
	if e != nil {
		return 0, e
	}
	if r.Kind == CapabilityKind || r.Kind == Loss {
		owner = []byte(source.String() + producer.String() + string(r.Kind))
	}
	h := sha256.New()
	for _, v := range [][]byte{[]byte(org.String()), []byte(project.String()), []byte(r.Kind), owner} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(v)))
		h.Write(n[:])
		h.Write(v)
	}
	return uint16(binary.BigEndian.Uint64(h.Sum(nil)[:8]) % 64), nil
}

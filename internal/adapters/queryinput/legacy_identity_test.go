// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package queryinput_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	. "github.com/arynyklas/soundpost/internal/adapters/queryinput"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// referenceDigestV1 is the request digest of the releases before request.v2,
// written out from the formula those releases used (scope, OpenMetrics scrape
// time, unframed body) and sharing no code with the product.
func referenceDigestV1(format string, p InputProfile, body []byte) [32]byte {
	be := func(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }
	h := sha256.New()
	h.Write([]byte("soundpost.queryinput.request.v1\x00" + format + "\x00"))
	h.Write(p.Project[:])
	h.Write(p.Source[:])
	h.Write(p.Producer[:])
	h.Write(be(uint64(p.PolicyRevision)))
	if format == "openmetrics" && p.DefaultTimestamp != 0 {
		h.Write([]byte("default-timestamp\x00"))
		h.Write(be(uint64(p.DefaultTimestamp)))
	}
	h.Write(body)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func rawSeriesKey(name string, labels model.Labels) string {
	key := name
	for _, l := range labels {
		key += "\x00" + l.Name + "\x00" + l.Value
	}
	return key
}

// A retry that crosses the upgrade must find the receipt of the original
// admission. For that the bridge decodes the same body a second time with the
// previous release's identity; these identifiers are what that release stored.
func TestLegacyIdentityIsWhatThePreviousReleaseStored(t *testing.T) {
	f := newFixture(t)
	base := f.profile()
	legacy := base
	legacy.LegacyIdentity = true
	om := []byte("# TYPE hs_id gauge\nhs_id 1 1700000000\n# EOF\n")
	series := `[{"labels":{"__name__":"hs_id","job":"api"},"samples":[{"bits":"3ff0000000000000","timestamp_ms":"1700000000000"}]}]`
	rw1Plain := hsRW(t, `{"version":1,"timeseries":`+series+`}`)
	rw2Plain := hsRW(t, `{"version":2,"timeseries":`+series+`}`)
	rw1, rw2 := snappyEncode(rw1Plain), snappyEncode(rw2Plain)
	push := lokiBodyNoMetadata("alpha")
	hook := []byte(`{"version":1,"events":[{"condition":"hs-id","epoch":"e1","event_time_ns":"1700000000123456789","status":"firing","severity":"info","labels":{},"links":[]}]}`)
	for _, c := range []struct {
		name, format string
		body         []byte
		decode       func(InputProfile) ([]model.Batch, error)
		recordID     func(rec model.Record, digest [32]byte, ordinal int) model.ID
	}{
		{"openmetrics", "openmetrics", om, func(p InputProfile) ([]model.Batch, error) {
			return DecodeOpenMetrics(f.ctx, f.grant(), bytes.NewReader(om), p)
		}, metricRecordID},
		{"remote write v1", "remote_write_v1", rw1Plain, func(p InputProfile) ([]model.Batch, error) {
			return DecodeRemoteWrite(f.ctx, f.grant(), RemoteWriteV1, bytes.NewReader(rw1), p)
		}, metricRecordID},
		{"remote write v2", "remote_write_v2", rw2Plain, func(p InputProfile) ([]model.Batch, error) {
			return DecodeRemoteWrite(f.ctx, f.grant(), RemoteWriteV2, bytes.NewReader(rw2), p)
		}, metricRecordID},
		{"loki push", "loki_push/json", push, func(p InputProfile) ([]model.Batch, error) {
			return DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(push), p)
		}, func(_ model.Record, digest [32]byte, ordinal int) model.ID {
			return DeriveID("log", digest[:], binary.BigEndian.AppendUint64(nil, uint64(ordinal+1))) // the previous release counted entries from 1
		}},
		{"conditions", "condition_webhook", hook, func(p InputProfile) ([]model.Batch, error) {
			return DecodeConditions(f.ctx, f.grant(), bytes.NewReader(hook), p)
		}, func(_ model.Record, digest [32]byte, ordinal int) model.ID {
			return DeriveID("condition-record", digest[:], binary.BigEndian.AppendUint64(nil, uint64(ordinal)))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			digest := referenceDigestV1(c.format, legacy, c.body)
			old, err := c.decode(legacy)
			if err != nil {
				t.Fatal(err)
			}
			current, err := c.decode(base)
			if err != nil {
				t.Fatal(err)
			}
			if len(old) == 0 || len(old) != len(current) {
				t.Fatalf("%d legacy batches, %d current", len(old), len(current))
			}
			ordinal := 0
			for i, b := range old {
				var idx [6]byte
				binary.BigEndian.PutUint16(idx[:2], b.RouteSlot)
				if want := DeriveID("batch", digest[:], idx[:]); b.ID != want {
					t.Errorf("batch %d: id %v, the previous release stored %v", i, b.ID, want)
				}
				if b.ID == current[i].ID {
					t.Errorf("batch %d: the legacy identity equals the current one", i)
				}
				for j, rec := range b.Records {
					if want := c.recordID(rec, digest, ordinal); rec.ID != want {
						t.Errorf("batch %d record %d: id %v, the previous release stored %v", i, j, rec.ID, want)
					}
					ordinal++
					// Only the identifiers differ: what is stored is the same data.
					a, d := rec, current[i].Records[j]
					a.ID, d.ID = model.ID{}, model.ID{}
					ra, _ := model.CanonicalJSON(a)
					rd, _ := model.CanonicalJSON(d)
					if !bytes.Equal(ra, rd) {
						t.Errorf("batch %d record %d: legacy decode holds other data\n%s\n%s", i, j, ra, rd)
					}
				}
			}
		})
	}
}

func metricRecordID(rec model.Record, _ [32]byte, _ int) model.ID {
	raw, _ := model.CanonicalJSON(*rec.Payload.Metric)
	return DeriveID("metric", []byte(rawSeriesKey(rec.Payload.Metric.Name, rec.Payload.Metric.Labels)), binary.BigEndian.AppendUint64(nil, uint64(rec.ObservedAt)), raw)
}

// The series key of the previous release held label values verbatim: a value
// with NUL bytes keeps the raw key in a legacy record identifier, while the
// current identity escapes it.
func TestLegacyMetricIdentityKeepsTheRawSeriesKey(t *testing.T) {
	m := model.MetricPoint{Name: "nul_metric", Type: "gauge", Unit: "1", Labels: model.Labels{{Name: "a", Value: "x\x00b\x00y"}}}
	p := InputProfile{Resource: model.Resource{Instance: "i", Labels: model.Labels{}}}
	legacy := p
	legacy.LegacyIdentity = true
	old, err := NewMetricRecord("remote_write_v1", m, 1_700_000_000_000_000_000, legacy)
	if err != nil {
		t.Fatal(err)
	}
	current, err := NewMetricRecord("remote_write_v1", m, 1_700_000_000_000_000_000, p)
	if err != nil {
		t.Fatal(err)
	}
	if want := metricRecordID(old, [32]byte{}, 0); old.ID != want {
		t.Errorf("legacy id %v, the previous release stored %v", old.ID, want)
	}
	if old.ID == current.ID {
		t.Error("legacy and current identifiers are equal")
	}
}

// Admission renders the template into every log record, so the current decoder
// counts a log record at twice its size plus slack against the batch budget and
// cuts a large push into more batches. A request the previous release admitted
// was cut by its raw size: the legacy decode must cut it the same way, or its
// batch identifiers (the chunk number is part of them) name other batches.
func TestLegacyIdentityCutsLogBatchesByTheOldBudget(t *testing.T) {
	f := newFixture(t)
	rawSource, rawOwner := model.NewID(), model.NewID()
	f.command("create_user", auth.AdminPayload{ID: rawOwner, Email: "legacy-chunks@example.test", Password: "legacy chunks password long 2026"})
	f.command("membership", auth.AdminPayload{UserID: rawOwner, Enabled: true})
	rawConfig, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: f.project, Restricted: true, Readers: []model.ID{rawOwner}, Enabled: true})
	f.command("source_policy", auth.AdminPayload{ID: rawSource, Config: rawConfig})
	rawPolicy := model.SourcePolicy{
		Revision: 1, Enabled: true, Class: "restricted_raw", Kinds: []model.Kind{model.Log},
		Templates: []model.LogTemplate{{ID: "raw.line", Revision: 1, Line: "{line}", Severity: "info", Fields: []model.TemplateField{{Name: "line", Type: "string", MaxBytes: 4096, Sensitivity: "restricted_raw"}}}},
		Resources: model.ResourceRegistry{Services: []model.ID{f.resource.Service}, Environments: []model.ID{f.resource.Environment}, Builds: []model.ID{f.resource.Build}, Instances: []string{f.resource.Instance}},
		Labels:    map[string][]string{"app": {"web"}, "region": {"eu"}}, RetentionDays: map[model.Kind]uint32{model.Log: 7},
		MaxBytes: 64 << 20, MaxSeries: 100, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()),
		RawOwner: &rawOwner, RawRationale: "legacy chunking test", RawMaxBytes: 4096,
	}
	cred := f.onboard(rawSource, rawPolicy)
	grant, err := f.ps.ResolveSource(f.ctx, cred, f.project, rawSource, 1)
	if err != nil {
		t.Fatal(err)
	}
	cfg := f.profile()
	cfg.Source = rawSource
	cfg.Loki = LokiMapping{Encoding: EncodingJSON, TemplateID: "raw.line", TemplateRevision: 1, LineField: "line"}
	line := strings.Repeat("a", 4096)
	var values [][]string
	for i := range 512 {
		values = append(values, []string{strconv.Itoa(1_700_000_000_123_456_789 + i), line})
	}
	body, err := json.Marshal(map[string]any{"streams": []any{map[string]any{"stream": map[string]string{"app": "web", "region": "eu"}, "values": values}}})
	if err != nil {
		t.Fatal(err)
	}
	current, err := DecodeLokiPush(f.ctx, grant, bytes.NewReader(body), cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.LegacyIdentity = true
	old, err := DecodeLokiPush(f.ctx, grant, bytes.NewReader(body), cfg)
	if err != nil {
		t.Fatal(err)
	}
	count := func(batches []model.Batch) (n int) {
		for _, b := range batches {
			n += len(b.Records)
		}
		return
	}
	if len(current) < 2 || count(current) != 512 || count(old) != 512 {
		t.Fatalf("current cut into %d batches (%d records), legacy %d records: the fixture no longer shows the difference", len(current), count(current), count(old))
	}
	if len(old) != 1 {
		t.Fatalf("legacy decode cut the push into %d batches; the previous release stored 512 raw 4 KiB lines in one", len(old))
	}
	digest := referenceDigestV1("loki_push/json", cfg, body)
	var idx [6]byte
	binary.BigEndian.PutUint16(idx[:2], old[0].RouteSlot)
	if want := DeriveID("batch", digest[:], idx[:]); old[0].ID != want {
		t.Errorf("batch id %v, the previous release stored %v", old[0].ID, want)
	}
	if reflect.DeepEqual(old[0].ID, current[0].ID) {
		t.Error("legacy and current batch identifiers are equal")
	}
}

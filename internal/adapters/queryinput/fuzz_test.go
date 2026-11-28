// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package queryinput_test

// Fuzz targets for every decoder. They run as plain tests over their seed corpus
// (the f.Add seeds below and the files under testdata/fuzz) and as coverage-guided
// fuzzers with `go test -fuzz`. The properties are the decoder contract:
//
//   - no panic, whatever the bytes;
//   - a failure is a typed *Error that unwraps to a *model.Fault;
//   - the same bytes decode to the same batches (identities included);
//   - every batch is one owner slot, 1..512 records, unique non-zero record IDs,
//     canonically encodable within the 4 MiB limit, and a fixed point of Normalize;
//   - source policy admission may refuse a batch, but only with a typed fault.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	. "github.com/arynyklas/soundpost/internal/adapters/queryinput"
	"github.com/arynyklas/soundpost/internal/adapters/queryinput/corpus"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
)

type hsFuzzEnv struct {
	h     *corpus.Harness
	grant policy.SourceGrant
	cfg   InputProfile
}

// newFuzzEnv opens one real application per fuzz function (not per input).
func newFuzzEnv(f *testing.F) hsFuzzEnv {
	f.Helper()
	h, err := corpus.OpenHarness(context.Background(), f.TempDir())
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { h.Close() })
	g, err := h.Grant()
	if err != nil {
		f.Fatal(err)
	}
	cfg := h.Profile()
	cfg.Limits = Limits{
		MaxCompressedBytes: 128 << 10, MaxDecodedBytes: 512 << 10, MaxSeries: 200, MaxSamples: 2000,
		MaxLabels: 16, MaxLabelNameBytes: 64, MaxLabelValueBytes: 256, MaxLineBytes: 1024, MaxStreams: 50, MaxBuckets: 64,
	}
	cfg.Exemplars = ExemplarsTraceLink
	cfg.Help = HelpDiscard
	return hsFuzzEnv{h: h, grant: g, cfg: cfg}
}

// check applies the decoder contract to one decode.
func (e hsFuzzEnv) check(t *testing.T, name string, decode func() ([]model.Batch, error)) {
	t.Helper()
	batches, err := decode()
	if err != nil {
		var qe *Error
		var fault *model.Fault
		if !errors.As(err, &qe) || !errors.As(err, &fault) || fault.Code == "" {
			t.Fatalf("%s: untyped failure %T: %v", name, err, err)
		}
		return
	}
	again, err := decode()
	if err != nil || !reflect.DeepEqual(batches, again) {
		t.Fatalf("%s: decoding the same bytes twice differs (second attempt: %v)", name, err)
	}
	cfg := e.cfg
	cfg.Org = e.h.Org
	for i, b := range batches {
		if b.Version != 1 || b.Project != cfg.Project || b.Source != cfg.Source || b.Producer != cfg.Producer || b.PolicyRevision != cfg.PolicyRevision ||
			b.ID == (model.ID{}) || b.RouteSlot >= 64 || len(b.Records) == 0 || len(b.Records) > 512 {
			t.Fatalf("%s: batch %d has a bad envelope", name, i)
		}
		ids := map[model.ID]bool{}
		for _, r := range b.Records {
			if r.ID == (model.ID{}) || ids[r.ID] {
				t.Fatalf("%s: batch %d has a zero or repeated record ID", name, i)
			}
			ids[r.ID] = true
			slot, err := model.OwnerSlot(cfg.Org, cfg.Project, cfg.Source, cfg.Producer, r)
			if err != nil || slot != b.RouteSlot {
				t.Fatalf("%s: batch %d holds a record of another owner slot (%v)", name, i, err)
			}
		}
		raw, err := model.CanonicalJSON(b)
		if err != nil || len(raw) > 4<<20 {
			t.Fatalf("%s: batch %d is not canonically encodable within 4 MiB: %d bytes, %v", name, i, len(raw), err)
		}
		if out, _, err := Normalize(b, cfg); err != nil || len(out.Records) != len(b.Records) {
			t.Fatalf("%s: batch %d is not a fixed point of Normalize: %v", name, i, err)
		}
		if _, err := policy.Normalize(e.grant, b); err != nil {
			var fault *model.Fault
			if !errors.As(err, &fault) {
				t.Fatalf("%s: batch %d: untyped admission failure %T: %v", name, i, err, err)
			}
		}
	}
}

func hsReadSeeds(f *testing.F, pattern string) map[string][]byte {
	f.Helper()
	names, err := filepath.Glob(filepath.Join(realDir, pattern))
	if err != nil {
		f.Fatal(err)
	}
	out := map[string][]byte{}
	for _, n := range names {
		raw, err := os.ReadFile(n)
		if err != nil {
			f.Fatal(err)
		}
		out[filepath.Base(n)] = raw
	}
	return out
}

func FuzzSnappyDecode(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{0x03, 0x08, 'a', 'b', 'c'})
	f.Add([]byte{0x0a, 0x00, 'a', 0x15, 0x01})
	f.Add([]byte{0x08, 0x0c, 'a', 'b', 'c', 'd', 0x0f, 0x04, 0x00, 0x00, 0x00})
	f.Add([]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x20, 0x00})
	f.Add(snappyEncode(bytes.Repeat([]byte("abcdefgh-0123456789-"), 50)))
	for _, raw := range hsReadSeeds(f, "rw-v2-00*.bin") {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		const max = 1 << 16
		out, err := snappyDecode("fuzz", in, max)
		if err != nil {
			var qe *Error
			if !errors.As(err, &qe) {
				t.Fatalf("untyped failure %T", err)
			}
			return
		}
		if len(out) > max {
			t.Fatalf("decoded %d bytes past the limit", len(out))
		}
		// What decoded must survive our own encoder: decode(encode(x)) == x.
		back, err := snappyDecode("fuzz", snappyEncode(out), max)
		if err != nil || !bytes.Equal(back, out) {
			t.Fatalf("round trip of %d decoded bytes: %v", len(out), err)
		}
	})
}

func FuzzDecodeRemoteWrite(f *testing.F) {
	e := newFuzzEnv(f)
	for _, c := range loadCorpus(f) {
		var v uint8
		switch c.Format {
		case "remote_write_v1":
			v = 1
		case "remote_write_v2":
			v = 2
		default:
			continue
		}
		var in semRW
		if err := json.Unmarshal(semanticOf(f, c), &in); err != nil {
			f.Fatal(err)
		}
		plain, err := corpus.EncodeRemoteWrite(in)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(v, plain)
		f.Add(v, snappyEncode(plain))
	}
	for name, raw := range hsReadSeeds(f, "rw-v*-00[1-4].bin") {
		v := uint8(1)
		if versionOf(name) == RemoteWriteV2 {
			v = 2
		}
		f.Add(v, raw)
		if plain, err := snappyDecode("seed", raw, 1<<20); err == nil {
			f.Add(v, plain)
		}
	}
	f.Fuzz(func(t *testing.T, version uint8, body []byte) {
		v := RemoteWriteV1
		if version&1 == 0 {
			v = RemoteWriteV2
		}
		e.check(t, "wire", func() ([]model.Batch, error) {
			return DecodeRemoteWrite(e.h.Ctx, e.grant, v, bytes.NewReader(body), e.cfg)
		})
		e.check(t, "protobuf", func() ([]model.Batch, error) {
			return DecodeRemoteWrite(e.h.Ctx, e.grant, v, bytes.NewReader(snappyEncode(body)), e.cfg)
		})
	})
}

func FuzzDecodeOpenMetrics(f *testing.F) {
	e := newFuzzEnv(f)
	for _, c := range loadCorpus(f) {
		if c.Format == "openmetrics" {
			f.Add(wireOf(f, c, EncodingJSON))
		}
	}
	for _, raw := range hsReadSeeds(f, "fixture-exposition.om") {
		f.Add(raw)
	}
	f.Add([]byte("# TYPE x gauge\nx 1 1700000000\n# EOF\n"))
	f.Add([]byte("# TYPE x counter\nx_total 1 1700000000 # {trace_id=\"0af7651916cd43dd8448eb211c80319c\"} 1 1700000000.5\nx_created 1700000000\n# EOF\n"))
	f.Fuzz(func(t *testing.T, body []byte) {
		e.check(t, "openmetrics", func() ([]model.Batch, error) {
			return DecodeOpenMetrics(e.h.Ctx, e.grant, bytes.NewReader(body), e.cfg)
		})
	})
}

func FuzzDecodeLokiPush(f *testing.F) {
	e := newFuzzEnv(f)
	encodings := []Encoding{EncodingJSON, EncodingJSONGzip, EncodingProtobufSnappy}
	for _, c := range loadCorpus(f) {
		if c.Format != "loki_push" {
			continue
		}
		for i, enc := range encodings {
			f.Add(uint8(i), wireOf(f, c, enc))
		}
	}
	f.Fuzz(func(t *testing.T, which uint8, body []byte) {
		decode := func(enc Encoding, wire []byte) ([]model.Batch, error) {
			cfg := e.cfg
			cfg.Loki.Encoding = enc
			return DecodeLokiPush(e.h.Ctx, e.grant, bytes.NewReader(wire), cfg)
		}
		enc := encodings[int(which)%len(encodings)]
		e.check(t, "wire "+string(enc), func() ([]model.Batch, error) { return decode(enc, body) })
		e.check(t, "json", func() ([]model.Batch, error) { return decode(EncodingJSON, body) })
		e.check(t, "gzip", func() ([]model.Batch, error) { return decode(EncodingJSONGzip, gz(body)) })
		e.check(t, "protobuf", func() ([]model.Batch, error) { return decode(EncodingProtobufSnappy, snappyEncode(body)) })
	})
}

func FuzzDecodeConditions(f *testing.F) {
	e := newFuzzEnv(f)
	f.Add([]byte(`{"version":1,"events":[{"condition":"checkout-latency","epoch":"e1","sequence":"1","event_time_ns":"1700000000000000000","status":"firing","severity":"critical","labels":{"job":"api"},"links":[]}]}`))
	f.Add([]byte(`{"version":1,"events":[{"condition":"a","epoch":"e","event_time_ns":"1700000000000000000","status":"unknown","severity":"info","labels":{},"links":["0af7651916cd43dd8448eb211c80319c"]}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		e.check(t, "conditions", func() ([]model.Batch, error) {
			return DecodeConditions(e.h.Ctx, e.grant, bytes.NewReader(body), e.cfg)
		})
	})
}

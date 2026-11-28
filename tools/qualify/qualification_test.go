// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// firefoxRow is what a Firefox/Safari-style build without a sampling API looks
// like when it was exercised for capability detection.
func firefoxRow() Row {
	return Row{
		ID: "browser.firefox.sample", Suite: SuiteRuntime, Required: true,
		Subject: Subject{Family: "firefox", Version: "130", OS: "linux", Arch: "amd64"},
		State:   StateUnsupported, Reason: "js_self_profiling_api_absent",
		Evidence: []string{"detected: Profiler constructor undefined"},
		Readings: []Reading{{Name: "cpu_samples", Unit: "samples", Availability: AvailUnsupported, Reason: "js_self_profiling_api_absent"}},
	}
}

func TestQualificationCannotPromoteUnsupportedToZero(t *testing.T) {
	row := firefoxRow()
	if err := ValidateRow(row); err != nil {
		t.Fatalf("a truthful unsupported row must validate: %v", err)
	}

	// Unavailable is encoded as its own state and carries no number at all.
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"availability":"unsupported"`)) || bytes.Contains(raw, []byte(`"value"`)) {
		t.Fatalf("unavailable must serialize as a distinct state without a value: %s", raw)
	}
	var back Row
	if err := json.Unmarshal(raw, &back); err != nil || back.Readings[0].Value != nil || back.Readings[0].Availability != AvailUnsupported {
		t.Fatalf("round trip lost the distinct unavailable state: %+v %v", back.Readings, err)
	}

	// A measured zero stays a measurement and is distinguishable from absence.
	measured := Reading{Name: "cpu_samples", Unit: "samples", Availability: AvailAvailable, Value: new(0.0)}
	rawZero, _ := json.Marshal(measured)
	if !bytes.Contains(rawZero, []byte(`"value":0`)) {
		t.Fatalf("a measured zero must serialize its value: %s", rawZero)
	}

	// Promoting the unavailable capability to a numeric zero is rejected, in every row state.
	for _, state := range []State{StateUnsupported, StateDenied, StateNotExercised} {
		bad := firefoxRow()
		bad.State = state
		bad.Readings[0].Value = new(0.0)
		if err := ValidateRow(bad); !errors.Is(err, ErrUnavailableAsZero) {
			t.Errorf("state %s: zero for an unavailable sampler must be rejected with ErrUnavailableAsZero, got %v", state, err)
		}
	}
	// An exercised row that reports its sampler unavailable but still prints zero CPU is the same lie.
	exercised := Row{
		ID: "browser.chrome-bad.sample", Suite: SuiteRuntime, Required: true,
		Subject: Subject{Family: "chrome", Version: "156", OS: "linux", Arch: "amd64"},
		State:   StateExercised, Outcome: OutcomePassed,
		Build:    &Build{Family: "chrome", Version: "156.0.8078.80", OS: "linux", Arch: "amd64", ID: "x"},
		Command:  &CommandRun{Command: "fixture", ExitCode: 0},
		Evidence: []string{"fixture"},
		Readings: []Reading{
			{Name: "cpu_samples", Unit: "samples", Availability: AvailUnsupported, Value: new(0.0)},
			{Name: "duration", Unit: "ms", Availability: AvailAvailable, Value: new(12.0)},
		},
	}
	if err := ValidateRow(exercised); !errors.Is(err, ErrUnavailableAsZero) {
		t.Fatalf("exercised row with unavailable sampler at zero: want ErrUnavailableAsZero, got %v", err)
	}
	// The same promotion arriving through a serialized report is rejected at parse time.
	report := SuiteReport{Suite: SuiteRuntime, Rows: []Row{firefoxRow()}}
	good, _ := json.Marshal(report)
	if _, err := ParseSuiteReport(good); err != nil {
		t.Fatalf("clean report must parse: %v", err)
	}
	tampered := strings.Replace(string(good), `"availability":"unsupported"`, `"availability":"unsupported","value":0`, 1)
	if _, err := ParseSuiteReport([]byte(tampered)); !errors.Is(err, ErrUnavailableAsZero) {
		t.Fatalf("tampered report must be rejected with ErrUnavailableAsZero, got %v", err)
	}
	// An available reading without a value is equally malformed (absence cannot pass as availability).
	hollow := Reading{Name: "cpu_samples", Availability: AvailAvailable}
	row = firefoxRow()
	row.State, row.Reason, row.Readings = StateExercised, "", []Reading{hollow}
	if err := ValidateRow(row); err == nil {
		t.Fatal("available reading with no value must be rejected")
	}
}

func canaryEncodings(secret string) map[string][]byte {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write([]byte(strings.Repeat("prefix "+secret+" suffix ", 40)))
	_ = w.Close()
	return map[string][]byte{
		"plain":    []byte("event " + secret + " end"),
		"base64":   []byte("x" + base64.StdEncoding.EncodeToString([]byte("pad "+secret+" pad"))),
		"lower":    []byte(strings.ToLower(secret)),
		"gzip":     gz.Bytes(),
		"reversed": []byte(reverseString(secret)),
	}
}

func reverseString(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func TestPrivacyCanaryFindsPrebufferLeak(t *testing.T) {
	const secret = "CANARY_PASSWORD_VV_9f31"
	clean := []Surface{
		{Name: SurfaceNetwork, Data: []byte(`{"chunks":[{"seq":1,"masked":true}]}`)},
		{Name: SurfaceRecorderQueue, Data: []byte(`{"queue":[{"seq":1,"masked":true}]}`)},
		{Name: SurfaceExportQueue, Data: []byte(`{"export":[{"seq":1}]}`)},
		{Name: SurfaceStoredRecords, Data: []byte(`{"stored":[{"seq":1}]}`)},
		{Name: SurfaceDiagnostics, Data: []byte(`{"diagnostics":{"dropped":0}}`)},
	}
	base := PrivacyCase{Canaries: []string{secret}, Surfaces: clean, Native: &NativeConfig{SampleType: []string{"IP", "TID", "TIME", "CALLCHAIN", "CPU", "PERIOD"}}}
	if v := InspectPrivacy(base); !v.Pass || len(v.Findings) != 0 {
		t.Fatalf("clean variant must pass: %+v", v)
	}

	// Contaminated variant (permanent negative control): the network is scrubbed, but the secret
	// is materialized in the recorder queue / export queue.
	for _, leak := range []string{SurfaceRecorderQueue, SurfaceExportQueue, SurfaceStoredRecords, SurfaceDiagnostics} {
		for enc, data := range canaryEncodings(secret) {
			if enc == "gzip" && bytes.Contains(data, []byte(secret)) {
				t.Fatal("fixture invalid: the gzip bytes expose the secret raw, so inflating would not be needed to find it")
			}
			c := base
			c.Surfaces = append([]Surface(nil), clean...)
			for i := range c.Surfaces {
				if c.Surfaces[i].Name == leak {
					c.Surfaces[i].Data = append(append([]byte(nil), c.Surfaces[i].Data...), data...)
				}
			}
			v := InspectPrivacy(c)
			if v.Pass {
				t.Errorf("secret in %s (%s encoding) with a scrubbed network must fail", leak, enc)
				continue
			}
			if len(v.Findings) == 0 || v.Findings[0].Surface != leak {
				t.Errorf("%s/%s: finding must name the leaking surface, got %+v", leak, enc, v.Findings)
			}
			for _, f := range v.Findings {
				if strings.Contains(f.Canary+f.Encoding+f.Surface, secret) {
					t.Errorf("finding must not echo the secret: %+v", f)
				}
			}
		}
	}

	// Native: stack bytes in the capture configuration fail even when every record is clean ...
	cfg := base
	cfg.Native = &NativeConfig{SampleType: []string{"IP", "TID", "STACK_USER", "REGS_USER"}}
	if v := InspectPrivacy(cfg); v.Pass {
		t.Error("a capture configuration that requests user stack bytes must fail even with clean records")
	}
	// ... and clean configuration does not excuse a canary in the stored/exported records.
	rec := base
	rec.Surfaces = append([]Surface(nil), clean...)
	rec.Surfaces[3].Data = []byte("stored " + secret)
	if v := InspectPrivacy(rec); v.Pass {
		t.Error("a canary in stored records must fail even with a clean configuration")
	}
	// Blind inspection is not a pass: a missing configuration or an absent/empty record surface fails.
	blind := base
	blind.Native = nil
	if v := InspectPrivacy(blind); v.Pass {
		t.Error("native privacy without an inspected configuration must fail")
	}
	empty := base
	empty.Surfaces = append([]Surface(nil), clean...)
	empty.Surfaces[3].Data = nil
	if v := InspectPrivacy(empty); v.Pass {
		t.Error("an empty stored-records surface means the records were not inspected: must fail")
	}
	missing := base
	missing.Surfaces = clean[:3]
	if v := InspectPrivacy(missing); v.Pass {
		t.Error("an absent stored/exported surface must fail")
	}
}

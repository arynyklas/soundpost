// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"math"
	"soundpost/internal/model"
	"soundpost/internal/query/scan"
	"soundpost/internal/query/value"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Rule table of the unwrap range aggregations (fitted to, and checked against,
// all 288 recorded native observations of sum_over_time, rate, avg_over_time,
// stdvar_over_time and stddev_over_time, 96 of which were last-bit red under
// the earlier compensated/weighted kernel; the rows below are a subset):
//
//	samples    the lines of the window (left, right] of one series in entry
//	           (arrival) order; an entry with multiplicity m is m separate
//	           samples of the same value, each entering the accumulators on its
//	           own (never value*m, never a weighted update)
//	sum        plain left-to-right float64 addition from +0, no compensation
//	rate       sum / (interval ns / 1e9); not sum * (1/seconds)
//	avg        mean += x/n - mean/n with n the 1-based sample number (not
//	           sum/n, not mean*(n-1)/n + x/n, not delta/n, not Kahan)
//	stdvar     Welford: delta = x-mean; mean += delta/n; m2 += delta*(x-mean);
//	           m2/n (population variance); its own mean, not the avg mean
//	stddev     sqrt of the stdvar value
//
// Not constrained by any row: infinities/NaN (the earlier non-finite rules are
// kept), multiplicity beyond 3, windows other than 3, 7 and 12 seconds.
func TestUnwrapAggregationsMatchRecordedNativeObservations(t *testing.T) {
	rows := []struct {
		id     string
		fn     string
		window int
		at     int64
		data   string // "timestamp:multiplicity:value ..." entries of one host
		want   string // float bits of the native result
	}{
		{"mh-0085", "stddev_over_time", 3, 12000000000, "10650000000:1:2 10850000000:1:0 11000000000:2:2", "3febb67ae8584cab"},
		{"mh-0086", "stddev_over_time", 7, 13000000000, "10650000000:1:2 10850000000:1:0 11000000000:2:2", "3febb67ae8584cab"},
		{"mh-0146", "stddev_over_time", 7, 13000000000, "6950000000:2:199 7550000000:1:199 7700000000:1:204 11700000000:1:203", "4001d11cd1209b00"},
		{"mh-0326", "stddev_over_time", 7, 13000000000, "6200000000:2:47 7300000000:1:2 9750000000:3:3 10150000000:1:8 10500000000:2:1", "40326540a17379b9"},
		{"mz-0122", "stddev_over_time", 12, 8000000000, "900000000:1:0.07 1000000000:2:0.001 1400000000:1:-0.1 1600000000:1:-2.25 2300000000:2:7.0 7900000000:1:0.3333333", "400a148840d0985e"},
		{"mz-0000", "avg_over_time", 3, 9000000000, "6200000000:2:3.14159 6500000000:2:3.14159 6700000000:1:7 6800000000:2:1e-05 8100000000:1:-2.25", "400150fe47991bc6"},
		{"mz-0001", "avg_over_time", 7, 12000000000, "6200000000:2:3.14159 6500000000:2:3.14159 6700000000:1:7 6800000000:2:1e-05 8100000000:1:-2.25", "400150fe47991bc6"},
		{"mz-0002", "avg_over_time", 12, 9000000000, "3400000000:2:0.3333333 4200000000:1:123456.789 6200000000:2:3.14159 6500000000:2:3.14159 6700000000:1:7 6800000000:2:1e-05 8100000000:1:-2.25", "40c5ec7d58f29244"},
		{"mz-0040", "avg_over_time", 7, 6000000000, "900000000:2:0.7 4200000000:1:7.0", "4006666666666666"},
		{"mz-0041", "avg_over_time", 12, 6000000000, "900000000:2:0.7 4200000000:1:7.0", "4006666666666666"},
		{"mz-0007", "stdvar_over_time", 7, 9000000000, "3400000000:2:0.3333333 4200000000:1:123456.789 6200000000:2:3.14159 6500000000:2:3.14159 6700000000:1:7 6800000000:2:1e-05 8100000000:1:-2.25", "41d2c4fc173d1b4b"},
		{"mz-0008", "stdvar_over_time", 12, 9000000000, "3400000000:2:0.3333333 4200000000:1:123456.789 6200000000:2:3.14159 6500000000:2:3.14159 6700000000:1:7 6800000000:2:1e-05 8100000000:1:-2.25", "41d2c4fc173d1b4b"},
		{"mz-0046", "stdvar_over_time", 7, 9000000000, "4200000000:1:7.0 6500000000:2:7.0 6800000000:1:1000.03", "410691fadf10cb2a"},
		{"mz-0047", "stdvar_over_time", 12, 6000000000, "900000000:2:0.7 4200000000:1:7.0", "4021a3d70a3d70a4"},
		{"mz-0123", "stdvar_over_time", 3, 4000000000, "1400000000:1:-0.1 1600000000:1:-2.25 2300000000:2:7.0", "403149147ae147af"},
		{"mz-0127", "sum_over_time", 7, 12000000000, "7900000000:1:0.3333333 11300000000:1:10.01 11600000000:2:70", "4062cafc961de416"},
		{"mz-0282", "sum_over_time", 3, 9000000000, "7000000000:1:1.37 8400000000:2:0.01 9000000000:2:1000000.5", "413e848263d70a3e"},
		{"mz-0361", "sum_over_time", 7, 8000000000, "1100000000:2:1.00003 1500000000:2:100.003 3700000000:1:31.4159", "406d2d80b242070b"},
		{"mz-0438", "sum_over_time", 3, 6000000000, "4800000000:1:7 5500000000:2:0.1", "401ccccccccccccc"},
		{"mz-0477", "sum_over_time", 3, 4000000000, "1100000000:1:-1.0 3200000000:2:0.07 3600000000:1:0.001", "bfeb7ced916872af"},
		{"mz-0190", "rate", 7, 12000000000, "6900000000:1:0.001 8000000000:1:1234567.8900000001 10800000000:2:0.7", "41058778552366b1"},
		{"mz-0268", "rate", 7, 6000000000, "1100000000:1:1000000.5 1300000000:2:1.37 2100000000:2:7.0 2700000000:2:0.006999999999999999 4800000000:2:123456.789 5300000000:1:19.99", "4105bebea759d1c7"},
		{"mz-0269", "rate", 12, 6000000000, "1100000000:1:1000000.5 1300000000:2:1.37 2100000000:2:7.0 2700000000:2:0.006999999999999999 4800000000:2:123456.789 5300000000:1:19.99", "40f95e89189374bd"},
		{"mz-0502", "rate", 7, 4000000000, "1100000000:1:-1.0 3200000000:2:0.07 3600000000:1:0.001", "bfbf6a3413e5155a"},
		{"mz-0503", "rate", 12, 6000000000, "1100000000:1:-1.0 3200000000:2:0.07 3600000000:1:0.001", "bfb253490b9af71f"},
		{"mh-0071", "avg_over_time", 7, 12000000000, "5400000000:2:3 6700000000:3:5 7150000000:1:55 11300000000:2:1 11400000000:2:1", "4020000000000000"},
	}
	for _, c := range rows {
		var entries []scan.LogRow
		for i, field := range strings.Fields(c.data) {
			parts := strings.Split(field, ":")
			at, err := strconv.ParseInt(parts[0], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			mult, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			entries = append(entries, variantHostRow(byte(i+1), at, model.Uint64(mult), "a", "n="+parts[2]))
		}
		plan := metricPlan(t, c.fn+"({app=\"api\"}|logfmt|unwrap n["+strconv.Itoa(c.window)+"s])", value.Evaluation{Instant: true, Time: model.UnixNano(c.at)})
		account := value.NewBoundedAccount(32 << 20)
		r, _, err := Evaluate(context.Background(), plan, &metricSource{rows: entries}, account)
		if err != nil || len(r.Vector) != 1 {
			t.Fatalf("%s: err=%v vector=%v", c.id, err, r.Vector)
		}
		want, err := strconv.ParseUint(c.want, 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		if got := uint64(r.Vector[0].Samples[0].Float); got != want {
			t.Fatalf("%s %s: got %016x (%g) want %016x (%g)", c.id, c.fn, got, math.Float64frombits(got), want, math.Float64frombits(want))
		}
		account.Release(value.ResultBytes(r))
		if account.Used() != 0 {
			t.Fatalf("%s leaked %d", c.id, account.Used())
		}
	}
}

// A repeated addend that no longer moves the sum ends the repetition, so an
// astronomically large multiplicity of an overflowing value is not walked.
func TestUnwrapSumOfHugeMultiplicityStopsAtFixedPoint(t *testing.T) {
	plan := metricPlan(t, `sum_over_time({app="api"}|logfmt|unwrap n[5s])`, value.Evaluation{Instant: true, Time: 6e9})
	account := value.NewBoundedAccount(32 << 20)
	row := variantHostRow(1, 5e9, 1<<62, "a", "n=1e308")
	done := make(chan float64, 1)
	go func() {
		r, _, err := Evaluate(context.Background(), plan, &metricSource{rows: []scan.LogRow{row}}, account)
		if err != nil || len(r.Vector) != 1 {
			done <- math.NaN()
			return
		}
		done <- math.Float64frombits(uint64(r.Vector[0].Samples[0].Float))
	}()
	select {
	case got := <-done:
		if !math.IsInf(got, 1) {
			t.Fatalf("sum=%g want +Inf", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("repeated addition of an overflowed sum was walked to the end")
	}
}

// Every repetition is a separate sample, so a mean over an enormous
// multiplicity stays interruptible.
func TestUnwrapAverageOfHugeMultiplicityHonoursCancellation(t *testing.T) {
	plan := metricPlan(t, `avg_over_time({app="api"}|logfmt|unwrap n[5s])`, value.Evaluation{Instant: true, Time: 6e9})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	account := value.NewBoundedAccount(32 << 20)
	row := variantHostRow(1, 5e9, 1<<62, "a", "n=1.5")
	start := time.Now()
	_, _, err := Evaluate(ctx, plan, &metricSource{rows: []scan.LogRow{row}}, account)
	if err == nil {
		t.Fatal("expected the cancelled context to end the repetition")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("cancellation took %s", time.Since(start))
	}
}

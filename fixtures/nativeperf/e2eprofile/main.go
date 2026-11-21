//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0

// Command e2eprofile captures a REAL native CPU profile for the UI end-to-end suite: fixtures/nativeperf/realcapture runs the compiled
// fixtures/nativeperf/cpu/loop.c under the in-process native helper (perf_event_open software CPU-clock samples, no root), and the sanitized
// events are assembled with nativeperf.AssembleProfile into the closed chunk wire format plus the capability records the exporter would send.
//
// Only the wall anchor is mapped: the clock pair maps the capture's first monotonic reading to -wall-ns (the e2e suite's fixed T0), so the
// other specs' T0-based windows contain the profile. Every sample, stack, module, offset, loss count and capability status is what the kernel
// and the probe reported. When the host cannot capture (no cpu_event_open, a refused start, no observations) the command exits 1 with the
// reason and writes nothing: there is no synthetic fallback.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/realcapture"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "e2eprofile:", e)
		var cannot *realcapture.CannotCapture
		if errors.As(e, &cannot) {
			os.Exit(exitCannotCapture)
		}
		os.Exit(1)
	}
}

func fixedClockID(label, value string) model.ID {
	h := sha256.Sum256([]byte("soundpost-native-clock-v1\x00" + label + "\x00" + value))
	var id model.ID
	copy(id[:], h[:])
	return id
}

type capRow struct {
	ID    model.ID         `json:"id"`
	Value model.Capability `json:"value"`
}

// capabilityRows are the three native capability records, built the way nativeperf.Exporter builds them from the probe (status per
// method, the probe's own reason for an unsupported method, the permission reason for a denied one).
func capabilityRows(caps nativeperf.Capabilities, ids []model.ID, clock model.ClockDomain, observed model.UnixNano) []capRow {
	coverage := func(c nativeperf.Coverage) string {
		if !c.Measured {
			return "unknown"
		}
		if c.Eligible == c.Observed {
			return "complete"
		}
		return "partial"
	}
	reason := "coverage_unmeasured"
	if len(caps.Reasons) > 0 {
		reason = string(caps.Reasons[0])
	}
	arch := caps.Arch
	if arch == "" {
		arch = "unknown"
	}
	statuses := []nativeperf.Status{caps.CPU, caps.OffCPU, caps.RunqueueSplit}
	methods := []string{"native_cpu", "native_offcpu", "native_runqueue_split"}
	var rows []capRow
	for i, id := range ids {
		v := model.Capability{Runtime: "native_linux", Version: "1", Build: "owned", OS: "linux", Arch: arch, Signal: model.Profile, Method: methods[i], Status: string(statuses[i]), Reason: reason,
			Coverage: model.Coverage{Frames: coverage(caps.FrameCoverage), Threads: coverage(caps.ThreadCoverage), Workers: "none", Tasks: "unknown"}, Clock: clock, Expires: observed + model.UnixNano(24*time.Hour)}
		if statuses[i] == nativeperf.Denied {
			v.Reason = string(nativeperf.ReasonPermission)
		} else if statuses[i] == nativeperf.Unsupported {
			v.Reason = string(nativeperf.ReasonEvent)
			for _, r := range caps.Reasons {
				if r == nativeperf.ReasonTraceFS || r == nativeperf.ReasonPlatform || r == nativeperf.ReasonEvent {
					v.Reason = string(r)
					break
				}
			}
			if i == 2 {
				v.Reason = string(nativeperf.ReasonAcquisition)
			}
		}
		rows = append(rows, capRow{ID: id, Value: v})
	}
	return rows
}

// exitCannotCapture is the exit status of a host that cannot take the capture at all (as opposed to a capture that failed, status 1).
const exitCannotCapture = 3

func run() error {
	workload := flag.String("workload", "", "compiled fixtures/nativeperf/cpu/loop.c (-fno-pie -no-pie -g -Wl,--build-id)")
	out := flag.String("out", "", "output JSON file")
	eventsOut := flag.String("events-out", "", "instead of assembling a profile, write the captured realcapture.Result as JSON to this file (the acceptance test captures in a child process so the helper's memory budget sees a small process, not a race-instrumented test binary)")
	wall := flag.Int64("wall-ns", 0, "unix nanoseconds the capture's first monotonic reading is mapped to")
	seconds := flag.Int("seconds", 6, "longest capture in seconds (it also ends after the event bound)")
	flag.Parse()
	if *workload == "" || *seconds < 1 || *seconds > 60 || *eventsOut == "" && (*out == "" || *wall <= 0) {
		return errors.New("usage: -workload PATH (-events-out FILE | -out FILE -wall-ns N) [-seconds 1..60]")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*seconds+60)*time.Second)
	defer cancel()
	captured, e := realcapture.Capture(ctx, realcapture.Request{Workload: *workload, Seconds: *seconds})
	if e != nil {
		return e
	}
	if *eventsOut != "" {
		raw, e := json.Marshal(captured)
		if e != nil {
			return e
		}
		return os.WriteFile(*eventsOut, raw, 0o600)
	}
	domain := captured.Events[0].Domain
	clock := model.TraceClock{Wall: model.UnixNano(*wall), Mono: captured.FirstMono, Domain: model.ClockDomain{Host: fixedClockID("host", domain.HostID), Boot: fixedClockID("boot", domain.BootID), Runtime: model.NewID()}}
	last := captured.FirstMono
	for _, ev := range captured.Events {
		if ev.Time > last {
			last = ev.Time
		}
	}
	limits := nativeperf.ProfileLimits{Profile: model.NewID(), Process: model.NewID(), Capability: model.NewID(), Domain: domain, PolicyRevision: 1, Sequence: 1, Start: clock.Wall, End: clock.Wall + model.UnixNano(last-captured.FirstMono) + 1, Clock: clock, Complete: false, MaxBytes: 8 << 20, MaxSamples: 8192, MaxIntervals: 8192, MaxFrames: 4096, MaxStacks: 4096, Mappings: captured.Mappings}
	chunk, e := nativeperf.AssembleProfile(ctx, captured.Events, nil, captured.Capabilities, limits)
	if e != nil {
		return fmt.Errorf("assemble: %w", e)
	}
	if len(chunk.Samples) == 0 {
		return errors.New("the assembled profile holds no sample")
	}
	named := 0
	for _, f := range chunk.Frames {
		if f.Function != "" {
			named++
		}
	}
	caps := captured.Capabilities
	raw, e := json.MarshalIndent(map[string]any{
		"source":       "fixtures/nativeperf/e2eprofile: real perf_event_open software CPU-clock capture of fixtures/nativeperf/cpu/loop.c through the in-process native helper (fixtures/nativeperf/realcapture), assembled by nativeperf.AssembleProfile; only the wall anchor is mapped",
		"chunk":        chunk,
		"capabilities": capabilityRows(caps, chunk.NativeCapabilities, chunk.Clock.Domain, clock.Wall),
		"capture": map[string]any{
			"cpu_samples":      captured.CPUSamples,
			"hot_loop_samples": captured.HotSamples,
			"threads":          captured.Threads,
			"period":           captured.Period,
			"loss":             captured.Loss,
			"frames":           len(chunk.Frames),
			"named_frames":     named,
			"kernel":           caps.Kernel,
			"cpu":              caps.CPU,
			"off_cpu":          caps.OffCPU,
			"runqueue_split":   caps.RunqueueSplit,
			"reasons":          caps.Reasons,
		},
	}, "", " ")
	if e != nil {
		return e
	}
	return os.WriteFile(*out, append(raw, '\n'), 0o644)
}

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestMissingFramesNoFramePointerPolicyRetainsNativePeriod(t *testing.T) {
	task := TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 2}
	table := MappingTable{process: ProcessKey{BootID: "boot", PIDNamespace: 1, TGID: 7, ProcessStart: 1, Generation: 2}, policy: SymbolPolicy{FramePointersAbsent: true}}
	sample := CPUSample{IP: 4096, Callchain: []CallchainEntry{{IP: 4096}}, Method: MethodSoftwareCPUClock, Unit: UnitCPUClockNanoseconds, RequestedHz: 99, Period: 123}
	out, e := ResolveCPUObservation(context.Background(), task, sample, table, nil)
	if e != nil || out.Period != 123 || out.Coverage != FrameMissing || len(out.Frames) != 1 {
		t.Fatal(out, e)
	}
	sample.Truncated = ReasonTruncated
	out, e = ResolveCPUObservation(context.Background(), task, sample, table, nil)
	if e != nil || out.AcquisitionCoverage != ReasonTruncated || out.Coverage != FrameMissing {
		t.Fatal("acquisition truncation hidden", out, e)
	}
}
func TestSymbolPolicyUnapprovedBuildDoesNotExposeOffset(t *testing.T) {
	task := TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 2}
	table := MappingTable{process: ProcessKey{BootID: "boot", PIDNamespace: 1, TGID: 7, ProcessStart: 1, Generation: 2}, entries: []mappingEntry{{start: 0x70000000, end: 0x70001000, reason: FrameUnapproved}}}
	out, e := ResolveFrames(context.Background(), []AddressFrame{{Task: task, IP: 0x70000008}}, table, nil)
	if e != nil || out[0].Offset != 0 || out[0].Module != nil || out[0].Reason != FrameUnapproved {
		t.Fatal(out, e)
	}
	raw, _ := json.Marshal(AddressFrame{Task: task, IP: 0x70000008})
	if strings.Contains(string(raw), "1879048200") {
		t.Fatal("address serialized")
	}
}
func TestSymbolPolicyRejectsOverlappingAndWrappingTables(t *testing.T) {
	task := TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 2}
	table := MappingTable{process: ProcessKey{BootID: "boot", PIDNamespace: 1, TGID: 7, ProcessStart: 1, Generation: 2}, entries: []mappingEntry{{start: 4096, end: 8192, offset: ^uint64(0), module: SafeModule{ID: moduleIdentity("ab12"), BuildID: "ab12"}}}}
	if _, e := ResolveFrames(context.Background(), []AddressFrame{{Task: task, IP: 4100}}, table, nil); e == nil {
		t.Fatal("offset wrap accepted")
	}
}

func TestSymbolPolicyFrameReasonsCannotExportPrivateText(t *testing.T) {
	if _, e := ResolveFrames(context.Background(), []AddressFrame{{Reason: FrameReason("/home/PRIVATE_CANARY")}}, MappingTable{}, nil); e == nil {
		t.Fatal("arbitrary reason exported")
	}
	task := TaskKey{BootID: "/home/PRIVATE_CANARY", PIDNamespace: 1, TGID: 7, TID: 7, ProcessStart: 1, Generation: 1}
	sample := CPUSample{IP: 4096, Method: MethodSoftwareCPUClock, Unit: UnitCPUClockNanoseconds, RequestedHz: 99, Period: 1, Truncated: ReasonMissingCallchain}
	if _, e := ResolveCPUObservation(context.Background(), task, sample, MappingTable{}, nil); e == nil {
		t.Fatal("private task identity exported")
	}
}
func TestMissingFramesExpiredJITMapNeverBorrowsLaterStack(t *testing.T) {
	out, e := ResolveFrames(context.Background(), []AddressFrame{{IP: 4096, Reason: FrameJITExpired}}, MappingTable{}, nil)
	if e != nil || len(out) != 1 || out[0].Reason != FrameJITExpired || out[0].Module != nil || out[0].Offset != 0 {
		t.Fatal(out, e)
	}
}

func TestMissingFramesKernelContextCannotBecomeUserAncestry(t *testing.T) {
	task := TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 7, ProcessStart: 1, Generation: 1}
	table := MappingTable{process: ProcessKey{BootID: "boot", PIDNamespace: 1, TGID: 7, ProcessStart: 1, Generation: 1}}
	sample := CPUSample{IP: 4096, Callchain: []CallchainEntry{{Context: ContextKernel}, {IP: 4100}}, Method: MethodSoftwareCPUClock, Unit: UnitCPUClockNanoseconds, RequestedHz: 99, Period: 1}
	out, e := ResolveCPUObservation(context.Background(), task, sample, table, nil)
	if e != nil || len(out.Frames) != 1 || out.Coverage != FrameUnresolved {
		t.Fatal(out, e)
	}
}

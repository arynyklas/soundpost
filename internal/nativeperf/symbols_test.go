// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Independently constructed ELF64 image: one executable LOAD, one GNU build-ID
// NOTE, a string table and two symbols. No debug/elf implementation generates it.
func symbolFixture(t *testing.T, name string) *os.File {
	t.Helper()
	b := make([]byte, 1024)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	o := binary.LittleEndian
	o.PutUint16(b[16:], 2)
	o.PutUint16(b[18:], 62)
	o.PutUint32(b[20:], 1)
	o.PutUint64(b[32:], 64)
	o.PutUint64(b[40:], 512)
	o.PutUint16(b[52:], 64)
	o.PutUint16(b[54:], 56)
	o.PutUint16(b[56:], 2)
	o.PutUint16(b[58:], 64)
	o.PutUint16(b[60:], 4)
	o.PutUint32(b[64:], 1)
	o.PutUint32(b[68:], 5)
	o.PutUint64(b[72:], 0)
	o.PutUint64(b[80:], 0x400000)
	o.PutUint64(b[96:], 1024)
	o.PutUint64(b[104:], 1024)
	o.PutUint32(b[120:], 4)
	o.PutUint64(b[128:], 256)
	o.PutUint64(b[152:], 20)
	o.PutUint32(b[256:], 4)
	o.PutUint32(b[260:], 2)
	o.PutUint32(b[264:], 3)
	copy(b[268:], []byte{'G', 'N', 'U', 0, 0xab, 0x12})
	copy(b[320:], "\x00"+name+"\x00")
	o.PutUint32(b[384+24:], 1)
	b[384+28] = 2
	o.PutUint16(b[384+30:], 1)
	o.PutUint64(b[384+32:], 0x400100)
	o.PutUint64(b[384+40:], 32)
	// Section1 executable data, section2 STRTAB, section3 SYMTAB linked to2.
	o.PutUint32(b[576+4:], 1)
	o.PutUint64(b[576+8:], 6)
	o.PutUint64(b[576+16:], 0x400000)
	o.PutUint64(b[576+32:], 256)
	o.PutUint32(b[640+4:], 3)
	o.PutUint64(b[640+24:], 320)
	o.PutUint64(b[640+32:], uint64(len(name)+2))
	o.PutUint32(b[704+4:], 2)
	o.PutUint64(b[704+24:], 384)
	o.PutUint64(b[704+32:], 48)
	o.PutUint32(b[704+40:], 2)
	o.PutUint64(b[704+56:], 24)
	path := filepath.Join(t.TempDir(), "artifact.elf")
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
func TestSymbolPolicyELFBuildAndRelativeOffset(t *testing.T) {
	f := symbolFixture(t, "approved_hot_loop")
	info, e := readELFSymbols(context.Background(), f, 1024, 128)
	if e != nil {
		t.Fatal(e)
	}
	if info.buildID != "ab12" {
		t.Fatal(info.buildID)
	}
	name, ok := info.lookup(0x108)
	if !ok || name != "approved_hot_loop" {
		t.Fatal(name, ok)
	}
	if _, ok := info.lookup(0x130); ok {
		t.Fatal("invented symbol extent")
	}
}
func TestSymbolPolicyInvalidELFAndPrivateNames(t *testing.T) {
	f := symbolFixture(t, "/home/PRIVATE_CANARY/source.c")
	info, e := readELFSymbols(context.Background(), f, 1024, 128)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := info.lookup(0x108); ok {
		t.Fatal("private source path exposed as symbol")
	}
	if _, e := readELFSymbols(context.Background(), f, 32, 128); e != ErrResourceBudget {
		t.Fatal(e)
	}
	if _, e := readELFSymbols(context.Background(), bytes.NewReader([]byte("not ELF")), 1024, 128); e == nil {
		t.Fatal("invalid ELF accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := readELFSymbols(ctx, f, 1024, 128); e == nil {
		t.Fatal("canceled parser continued")
	}
}
func TestMissingFramesRemainNonemptyAndRelative(t *testing.T) {
	p := ProcessKey{BootID: "boot", PIDNamespace: 1, TGID: 7, ProcessStart: 1, Generation: 2}
	task := TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 2}
	table := MappingTable{process: p, entries: []mappingEntry{{start: 0x70000000, end: 0x70001000, offset: 0x1000, module: SafeModule{ID: moduleIdentity("ab12"), BuildID: "ab12"}}}}
	frames, e := ResolveFrames(context.Background(), []AddressFrame{{Task: task, IP: 0x70000008}}, table, nil)
	if e != nil || len(frames) != 1 || frames[0].Offset != 0x1008 || frames[0].Reason != FrameArtifactUnavailable {
		t.Fatal(frames, e)
	}
	raw, _ := json.Marshal(frames)
	if bytes.Contains(raw, []byte("1879048200")) {
		t.Fatal("absolute IP escaped")
	}
	task.Generation = 1
	old, e := ResolveFrames(context.Background(), []AddressFrame{{Task: task, IP: 0x70000008}}, table, nil)
	if e != nil || old[0].Reason != FrameGeneration {
		t.Fatal(old, e)
	}
	empty, e := ResolveFrames(context.Background(), nil, table, nil)
	if e != nil || len(empty) != 1 || empty[0].Reason != FrameMissing {
		t.Fatal(empty, e)
	}
}
func TestMissingFramesCPUObservationRetainsMeasurement(t *testing.T) {
	sample := CPUSample{IP: 0x70000008, Method: MethodSoftwareCPUClock, Unit: UnitCPUClockNanoseconds, RequestedHz: 99, Period: 10000000, Truncated: ReasonMissingCallchain}
	task := TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 2}
	table := MappingTable{process: ProcessKey{BootID: "boot", PIDNamespace: 1, TGID: 7, ProcessStart: 1, Generation: 2}}
	observation, e := ResolveCPUObservation(context.Background(), task, sample, table, nil)
	if e != nil {
		t.Fatal(e)
	}
	if observation.Period != 10000000 || observation.Method != MethodSoftwareCPUClock || len(observation.Frames) < 1 || observation.Coverage != FrameMissing {
		t.Fatal(observation)
	}
}

func TestSymbolPolicyELFCodeOffsetsCannotAttributeNonCode(t *testing.T) {
	f := symbolFixture(t, "hot_loop")
	r := boundedELF{ctx: context.Background(), input: f, max: 1024}
	layout, e := readELFLayout(&r)
	if e != nil || layout.buildID != "ab12" {
		t.Fatal(layout, e)
	}
	if !layout.codeOffset(0x108) || layout.codeOffset(1024) {
		t.Fatal("non-code offset attributed")
	}
}

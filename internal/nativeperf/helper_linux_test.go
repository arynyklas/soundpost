//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestHelperProtocolRejectsUnknownAndOversize(t *testing.T) {
	for _, payload := range []string{`{"Targets":[],"command":"id"}`, `{} {}`} {
		var b bytes.Buffer
		binary.Write(&b, binary.BigEndian, uint32(len(payload)))
		b.WriteString(payload)
		var r CaptureRequest
		if readMessage(&b, &r) == nil {
			t.Fatal("accepted non-fixed request")
		}
	}
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(maxHelperMessage+1))
	var r CaptureRequest
	if readMessage(&b, &r) == nil {
		t.Fatal("accepted oversized request")
	}
}

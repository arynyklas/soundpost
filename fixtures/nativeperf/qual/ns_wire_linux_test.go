//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"encoding/binary"
	"net"
	"testing"
)

// The helper serializes its identity-error reply with the event-clock instant as a JSON string (model.MonoNano is exact for
// 64-bit values). The qualification client must decode exactly that frame and keep the closed error code: a reader that
// cannot decode it reports "undecodable" and loses the code that says the identity was lost.
func TestWireReplyDecodesAnIdentityErrorWithProvenThrough(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	body := []byte(`{"error":"generation_changed","proven_through":"124224096910934"}`)
	go func() {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(body)))
		server.Write(append(length[:], body...))
		server.Close()
	}()
	reply, _, err := readFrame(client)
	if err != nil {
		t.Fatalf("the helper's own identity-error frame is undecodable: %v", err)
	}
	if reply.Error != "generation_changed" || uint64(reply.ProvenThrough) != 124224096910934 {
		t.Fatalf("decoded %q proven_through=%d", reply.Error, uint64(reply.ProvenThrough))
	}
}

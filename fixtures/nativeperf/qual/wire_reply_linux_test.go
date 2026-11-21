//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// The helper reports an identity error (generation_changed, thread_coverage_changed, topology_changed) together with
// the instant it last proved the identity, and the product encodes a MonoNano as a decimal string. A client that
// decodes that field as a JSON number cannot read the very frame that carries the error: the capture ended on
// "helper frame undecodable" instead of the closed code, and the consumer could not revoke the unproven tail.
func TestReadFrameDecodesAnIdentityErrorWithItsProvenThrough(t *testing.T) {
	for name, tc := range map[string]struct {
		payload string
		want    uint64
	}{
		"the instant as the product writes it": {`{"error":"topology_changed","proven_through":"402603024316081"}`, 402603024316081},
		"no instant (omitted by the helper)":   {`{"error":"topology_changed"}`, 0},
	} {
		server, client := net.Pipe()
		go func() {
			var n [4]byte
			binary.BigEndian.PutUint32(n[:], uint32(len(tc.payload)))
			server.Write(append(n[:], tc.payload...))
			server.Close()
		}()
		reply, _, err := readFrame(client)
		client.Close()
		if err != nil || reply.Error != "topology_changed" || uint64(reply.ProvenThrough) != tc.want {
			t.Errorf("%s: %+v %v", name, reply, err)
		}
	}
	// whatever instant the helper's own encoder writes for the field, this decoder reads back
	for _, instant := range []uint64{1, 1<<53 + 1, 1<<64 - 1} {
		raw, err := json.Marshal(struct {
			Error         string         `json:"error"`
			ProvenThrough model.MonoNano `json:"proven_through,omitempty"`
		}{"topology_changed", model.MonoNano(instant)})
		if err != nil {
			t.Fatal(err)
		}
		var reply wireReply
		if err := json.Unmarshal(raw, &reply); err != nil || uint64(reply.ProvenThrough) != instant {
			t.Errorf("%d (%s): %+v %v", instant, raw, reply, err)
		}
	}
}

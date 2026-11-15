// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import "bytes"

// gateAdvert prefixes the Context of every snapshot message a sender whose machine implements
// SnapshotGate sends; what follows is the machine's token (possibly empty: the gate declined to
// state anything yet). A snapshot message whose Context does not start with it comes from a sender
// that does not run the gate, so nothing was ordered before its install and a receiver that does
// run the gate refuses it (rule, 11.04-W3): the sender sees a failed delivery and, once upgraded,
// sends again with the statement ordered.
var gateAdvert = []byte("soundpost/snapshot-gate/1\x00")

// gateContext frames a token for the wire.
func gateContext(token []byte) []byte {
	out := make([]byte, 0, len(gateAdvert)+len(token))
	return append(append(out, gateAdvert...), token...)
}

// gateToken is the inverse of gateContext; ok is false for a sender that does not advertise the gate.
func gateToken(context []byte) (token []byte, ok bool) {
	if !bytes.HasPrefix(context, gateAdvert) {
		return nil, false
	}
	return context[len(gateAdvert):], true
}

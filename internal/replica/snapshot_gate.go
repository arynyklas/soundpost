// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"encoding/json"

	pb "go.etcd.io/raft/v3/raftpb"
)

// gateAdvert prefixes the Context of every snapshot message a sender whose machine implements
// SnapshotGate sends; what follows is the machine's token (possibly empty: the gate declined to
// state anything yet). A snapshot message whose Context does not start with it comes from a sender
// that does not advertise the gate: a build that does not run it, or one that predates the
// advertisement and sent its token bare (a non-empty Context with no prefix, nothing at all when it
// had no token). Nothing it ordered can be told from nothing ordered, so a receiver that does run
// the gate refuses it (rule, 11.04-W3): the sender sees a failed delivery and, once upgraded, sends
// again with the advertisement. Upgrade order: the sender of snapshots first (docs/operations/upgrade.md).
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

// retryAdvert prefixes the Context of a snapshot message whose envelope keeps its retry table by
// digest (Entry.Original, no payload: DigestRetryMachine), in front of the erase gate's
// advertisement. It is the sender's statement that it knows that format. A receiver that predates
// it and runs the erase gate finds gateAdvert missing from the start of the Context and refuses
// the message before it admits it; one that runs no gate ignores the Context and refuses the
// envelope itself, which names the format in a field it does not know (snapshotEnvelope.Retry).
// A receiver of this build refuses a digest-kept envelope whose Context does not carry it
// (10.13-W2), and reads an older, payload-bearing envelope as before. It does not start with
// gateAdvert and gateAdvert does not start with it.
var retryAdvert = []byte("soundpost/snapshot-retry/digest-1\x00")

// retryDigestTag is the value of snapshotEnvelope.Retry that says the retry table is kept by digest.
const retryDigestTag = "digest-1"

// withRetryAdvert frames a Context for a snapshot whose envelope is digest-kept.
func withRetryAdvert(context []byte) []byte {
	out := make([]byte, 0, len(retryAdvert)+len(context))
	return append(append(out, retryAdvert...), context...)
}

// retryCapability is the inverse of withRetryAdvert: the Context without the capability, and whether
// the sender named it.
func retryCapability(context []byte) (rest []byte, named bool) {
	if !bytes.HasPrefix(context, retryAdvert) {
		return context, false
	}
	return context[len(retryAdvert):], true
}

// digestKept reports whether e is a retry-table record that holds the digest of a payload and no
// payload (what Group.retained makes of a command of a DigestRetryMachine kind).
func digestKept(e Entry) bool { return len(e.Payload) == 0 && e.Original != nil }

// markRetry sets the envelope's Retry field when its retry table holds a digest-kept record, so
// that a reader that predates the field refuses the envelope.
func (e *snapshotEnvelope) markRetry() {
	for _, c := range e.Completed {
		if digestKept(c.Entry) {
			e.Retry = retryDigestTag
			return
		}
	}
}

// digestBearing reports whether the envelope in data keeps a retry-table record by digest: it says
// so itself (Retry), or, as an envelope cut before the field existed, one of its records is
// digest-kept. Data that is not an envelope is not (the install refuses it).
func digestBearing(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if bytes.Contains(data, []byte(`"retry":"`+retryDigestTag+`"`)) { // the field as snapshotEnvelope marshals it
		return true
	}
	var probe struct {
		Retry     string `json:"retry"`
		Completed []struct {
			Entry struct {
				Payload  json.RawMessage `json:"payload"`
				Original json.RawMessage `json:"original"`
			} `json:"entry"`
		} `json:"completed"`
	}
	if json.Unmarshal(data, &probe) != nil {
		return false
	}
	if probe.Retry != "" {
		return true
	}
	for _, c := range probe.Completed {
		if !jsonAbsent(c.Entry.Original) && jsonAbsent(c.Entry.Payload) {
			return true
		}
	}
	return false
}

// jsonAbsent reports whether a decoded raw member is missing, null or an empty string.
func jsonAbsent(raw json.RawMessage) bool {
	return len(raw) == 0 || string(raw) == "null" || string(raw) == `""`
}

// snapshotContext is the Context a snapshot message leaves under: context (the erase gate's
// advertisement and token, or none) with the retry capability in front of it when the envelope the
// message carries keeps its retry table by digest. Only a group whose machine keeps a digest table
// can have cut such an envelope.
func (g *Group) snapshotContext(m *pb.Message, context []byte) []byte {
	if g.retryDigest != nil && digestBearing(m.GetSnapshot().GetData()) {
		return withRetryAdvert(context)
	}
	return context
}

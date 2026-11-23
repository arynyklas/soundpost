// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package providers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// This is the mutation test of the event webhook signature check. The signature is the
// one thing a receiver trusts, so the suite below (signatureChecks) is run against the
// real sender and the real Receiver, and then against MUTANTS of each: a sender that signs
// with the wrong secret, drops the previous-secret signature, leaves out the delivery ID or
// the timestamp or the body; a receiver whose comparison always succeeds, compares only a
// prefix, reads only the first signature, ignores the replay window or ignores the body.
// The pristine pair must pass every check and every mutant must fail at least one, so a
// weakening of either side is caught. The mutants are injected through the seams the
// production code exposes for exactly this (eventSender.header, Receiver.ops); nothing outside
// _test.go files sets them. Run with -v for the kill table (recorded in
// .superpowers/sdd/approved-product/rdapi-evidence/events-mutation.txt).

type headerFn = func(current, previous []byte, unix int64, deliveryID string, body []byte) string

// rawSignature is HMAC-SHA256 over "<unix>.<id>.<body>", written out independently of Sign.
func rawSignature(secret []byte, unix int64, id string, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(strconv.FormatInt(unix, 10) + "." + id + "."))
	m.Write(body)
	return "v1=" + hex.EncodeToString(m.Sum(nil))
}

type sigRequests struct{ open, expired capturedReq }

// capture sends one delivery inside the rotation window and one after it, through the
// real sender wired with header, and returns both requests as received.
func capture(t *testing.T, rig *eventRig, header headerFn, attempt uint32, until time.Time) sigRequests {
	t.Helper()
	before := len(rig.cap.all())
	rig.sender.header = header
	rig.st.now = until.Add(-time.Hour)
	if out := rig.send(attempt); out.Kind != notify.OutcomeAccepted {
		t.Fatalf("open window send: %+v", out)
	}
	rig.st.now = until.Add(time.Second)
	if out := rig.send(attempt + 1); out.Kind != notify.OutcomeAccepted {
		t.Fatalf("expired window send: %+v", out)
	}
	reqs := rig.cap.all()[before:]
	if len(reqs) != 2 {
		t.Fatalf("captured %d requests", len(reqs))
	}
	return sigRequests{open: reqs[0], expired: reqs[1]}
}

func receiverAt(secret string, unix int64, ops verifyOps) *Receiver {
	r := NewReceiver([]byte(secret), func() time.Time { return time.Unix(unix, 0) }, 0)
	r.ops = ops
	return r
}

func headerUnix(h http.Header) int64 {
	v, _ := strconv.ParseInt(h.Get(HeaderTimestamp), 10, 64)
	return v
}

type sigCheck struct {
	name string
	pass func() bool
}

// signatureChecks is the contract of the signature, as a list of named checks over the two
// captured requests, evaluated by receivers built with ops.
func signatureChecks(reqs sigRequests, ops verifyOps) []sigCheck {
	open, expired := reqs.open, reqs.expired
	at := headerUnix(open.header)
	atExpired := headerUnix(expired.header)
	verifies := func(secret string, r capturedReq, unix int64) error {
		_, err := receiverAt(secret, unix, ops).Receive(r.header, r.body)
		return err
	}
	withHeader := func(r capturedReq, mutate func(http.Header)) capturedReq {
		h := r.header.Clone()
		mutate(h)
		return capturedReq{path: r.path, header: h, body: r.body}
	}
	sigs := func(r capturedReq) []string { return strings.Split(r.header.Get(HeaderSignature), ",") }
	id := open.header.Get(HeaderDeliveryID)
	return []sigCheck{
		{"c01 current secret verifies", func() bool { return verifies(currentSecret, open, at) == nil }},
		{"c02 previous secret verifies during the rotation", func() bool { return verifies(previousSecret, open, at) == nil }},
		{"c03 the sender's signature equals the independent HMAC", func() bool {
			s := sigs(open)
			return len(s) == 2 && s[0] == rawSignature([]byte(currentSecret), at, id, open.body) && s[1] == rawSignature([]byte(previousSecret), at, id, open.body)
		}},
		{"c04 after the window only the current secret signs", func() bool {
			s := sigs(expired)
			return len(s) == 1 && s[0] == rawSignature([]byte(currentSecret), atExpired, id, expired.body) && verifies(currentSecret, expired, atExpired) == nil
		}},
		{"c05 the dropped previous secret no longer verifies", func() bool { return errors.Is(verifies(previousSecret, expired, atExpired), ErrSignature) }},
		{"c06 a wrong secret is refused", func() bool { return errors.Is(verifies("an-unrelated-secret-0123456789", open, at), ErrSignature) }},
		{"c07 a changed body is refused", func() bool {
			tampered := open
			tampered.body = []byte(strings.Replace(string(open.body), `"severity":"critical"`, `"severity":"minor"`, 1))
			return string(tampered.body) != string(open.body) && errors.Is(verifies(currentSecret, tampered, at), ErrSignature)
		}},
		{"c08 the delivery id is part of the signature", func() bool {
			other := strings.Repeat("c", 32)
			tampered := capturedReq{path: open.path, header: open.header.Clone(), body: []byte(strings.Replace(string(open.body), id, other, 1))}
			tampered.header.Set(HeaderDeliveryID, other)
			return errors.Is(verifies(currentSecret, tampered, at), ErrSignature)
		}},
		{"c09 the timestamp is part of the signature", func() bool {
			tampered := withHeader(open, func(h http.Header) { h.Set(HeaderTimestamp, strconv.FormatInt(at+1, 10)) })
			return errors.Is(verifies(currentSecret, tampered, at), ErrSignature)
		}},
		{"c10 a one-character change of the signature is refused", func() bool {
			tampered := withHeader(open, func(h http.Header) {
				s := sigs(open)
				last := s[0][len(s[0])-1]
				flip := byte('0')
				if last == '0' {
					flip = '1'
				}
				s[0] = s[0][:len(s[0])-1] + string(flip)
				h.Set(HeaderSignature, strings.Join(s[:1], ","))
			})
			return errors.Is(verifies(currentSecret, tampered, at), ErrSignature)
		}},
		{"c11 a signature of a different length is refused", func() bool {
			tampered := withHeader(open, func(h http.Header) { h.Set(HeaderSignature, sigs(open)[0]+"00") })
			return errors.Is(verifies(currentSecret, tampered, at), ErrSignature)
		}},
		{"c12 a request signed long ago is refused", func() bool {
			return errors.Is(verifies(currentSecret, open, at+int64(2*ReplayWindow/time.Second)), ErrReplayWindow)
		}},
		{"c13 any of several signatures verifies, in any position", func() bool {
			swapped := withHeader(open, func(h http.Header) { s := sigs(open); h.Set(HeaderSignature, s[1]+","+s[0]) })
			junkFirst := withHeader(open, func(h http.Header) { h.Set(HeaderSignature, "v1=00,"+sigs(open)[0]) })
			return verifies(currentSecret, swapped, at) == nil && verifies(previousSecret, swapped, at) == nil && verifies(currentSecret, junkFirst, at) == nil
		}},
		{"c14 a missing or empty signature is refused", func() bool {
			none := withHeader(open, func(h http.Header) { h.Del(HeaderSignature) })
			empty := withHeader(open, func(h http.Header) { h.Set(HeaderSignature, "") })
			return errors.Is(verifies(currentSecret, none, at), ErrSignature) && errors.Is(verifies(currentSecret, empty, at), ErrSignature)
		}},
	}
}

func failedChecks(reqs sigRequests, ops verifyOps) []string {
	var failed []string
	for _, c := range signatureChecks(reqs, ops) {
		if !passes(c) {
			failed = append(failed, c.name[:3])
		}
	}
	return failed
}

// passes runs one check; a request so malformed that the check cannot even inspect it (a
// mutant sender that sends one signature where two are due) fails it.
func passes(c sigCheck) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return c.pass()
}

func TestEventSignatureMutants(t *testing.T) {
	until := time.Unix(1_800_000_000, 0).Add(2 * time.Hour)
	rig := newEventRig(t, http.HandlerFunc(accept), func(rec *notify.DestinationRecord, reg *eventReg, org model.ID) {
		rec.HasPrevious, rec.PreviousUntil = true, model.UnixNano(until.UnixNano())
		reg.prev[[2]model.ID{org, recipient}] = previousSecret
	})
	var attempt uint32 = 1
	next := func(h headerFn) sigRequests {
		reqs := capture(t, rig, h, attempt, until)
		attempt += 2
		return reqs
	}
	pristine := next(eventSignatureHeader)
	if failed := failedChecks(pristine, verifyOps{}); len(failed) != 0 {
		t.Fatalf("the unmutated sender and receiver fail checks %v", failed)
	}
	t.Logf("pristine sender + pristine receiver: %d checks, 0 failed", len(signatureChecks(pristine, verifyOps{})))

	wrong := []byte("a-wrong-secret-0123456789abcdef")
	senderMutants := []struct {
		name   string
		header headerFn
	}{
		{"S1 signs with the wrong secret", func(c, p []byte, u int64, id string, b []byte) string {
			return eventSignatureHeader(wrong, p, u, id, b)
		}},
		{"S2 drops the previous-secret signature during a rotation", func(c, p []byte, u int64, id string, b []byte) string { return eventSignatureHeader(c, nil, u, id, b) }},
		{"S3 leaves the delivery id out of the signed string", func(c, p []byte, u int64, id string, b []byte) string { return eventSignatureHeader(c, p, u, "", b) }},
		{"S4 signs a timestamp of zero", func(c, p []byte, u int64, id string, b []byte) string { return eventSignatureHeader(c, p, 0, id, b) }},
		{"S5 signs an empty body", func(c, p []byte, u int64, id string, b []byte) string { return eventSignatureHeader(c, p, u, id, nil) }},
		{"S6 omits the v1= prefix", func(c, p []byte, u int64, id string, b []byte) string {
			return strings.ReplaceAll(eventSignatureHeader(c, p, u, id, b), "v1=", "")
		}},
		{"S7 signs only with the previous secret during a rotation", func(c, p []byte, u int64, id string, b []byte) string {
			if len(p) > 0 {
				return Sign(p, u, id, b)
			}
			return Sign(c, u, id, b)
		}},
		{"S8 signs the previous slot with the current secret", func(c, p []byte, u int64, id string, b []byte) string {
			if len(p) > 0 {
				return Sign(c, u, id, b) + "," + Sign(c, u, id, b)
			}
			return Sign(c, u, id, b)
		}},
		{"S9 keeps signing with the previous secret after the window", func(c, p []byte, u int64, id string, b []byte) string {
			return Sign(c, u, id, b) + "," + Sign([]byte(previousSecret), u, id, b)
		}},
		{"S10 appends the signature of the empty secret", func(c, p []byte, u int64, id string, b []byte) string {
			return eventSignatureHeader(c, p, u, id, b) + "," + Sign(nil, u, id, b)
		}},
	}
	for _, m := range senderMutants {
		failed := failedChecks(next(m.header), verifyOps{})
		t.Logf("MUTANT %-62s %s", m.name, verdict(failed))
		if len(failed) == 0 {
			t.Errorf("mutant survived: %s", m.name)
		}
	}

	receiverMutants := []struct {
		name string
		ops  verifyOps
	}{
		{"R1 the comparison is always true", verifyOps{equal: func(a, b []byte) bool { return true }}},
		{"R2 the comparison is always false", verifyOps{equal: func(a, b []byte) bool { return false }}},
		{"R3 the comparison looks at a prefix only", verifyOps{equal: func(a, b []byte) bool { return len(a) >= 16 && len(b) >= 16 && hmac.Equal(a[:16], b[:16]) }}},
		{"R4 the comparison ignores the length", verifyOps{equal: func(a, b []byte) bool { n := min(len(a), len(b)); return n > 0 && hmac.Equal(a[:n], b[:n]) }}},
		{"R5 only the first signature of the header is read", verifyOps{maxSignatures: 1}},
		{"R6 the replay window is a year", verifyOps{window: 365 * 24 * time.Hour}},
		{"R7 the expected signature ignores the body", verifyOps{sign: func(s []byte, u int64, id string, b []byte) string { return Sign(s, u, id, nil) }}},
		{"R8 the expected signature ignores the delivery id", verifyOps{sign: func(s []byte, u int64, id string, b []byte) string { return Sign(s, u, "", b) }}},
		{"R9 the expected signature ignores the timestamp", verifyOps{sign: func(s []byte, u int64, id string, b []byte) string { return Sign(s, 0, id, b) }}},
		{"R10 the expected signature uses a fixed secret", verifyOps{sign: func(s []byte, u int64, id string, b []byte) string { return Sign([]byte("fixed"), u, id, b) }}},
	}
	for _, m := range receiverMutants {
		failed := failedChecks(pristine, m.ops)
		t.Logf("MUTANT %-62s %s", m.name, verdict(failed))
		if len(failed) == 0 {
			t.Errorf("mutant survived: %s", m.name)
		}
	}
}

func verdict(failed []string) string {
	if len(failed) == 0 {
		return "SURVIVED"
	}
	return "KILLED by " + strings.Join(failed, ",")
}

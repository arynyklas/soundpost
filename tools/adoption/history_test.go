// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Every fixture here is synthetic: generated keys, labels, digests and times,
// local temporary directories and in-process evaluation. Nothing names or
// contacts a customer system, and no test result is customer acceptance.

const (
	closureTestScope = "adoption-closure/synthetic"
	closureTestKeyID = "attestor-1"
)

var closureNow = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func closureDig(label string) string {
	sum := sha256.Sum256([]byte("synthetic/" + label))
	return hex.EncodeToString(sum[:])
}

func closureTestKey(seed string) ed25519.PrivateKey {
	sum := sha256.Sum256([]byte("synthetic-key/" + seed))
	return ed25519.NewKeyFromSeed(sum[:])
}

func closureHistoryFixture(now time.Time) HistoryObligations {
	return HistoryObligations{
		Now: now, ObservedAt: now.Add(-time.Hour), MaxEvidenceAgeSecs: 24 * 3600,
		Origin: HistoryOrigin{ReadOnly: true, Retained: true, EvidenceDigest: closureDig("origin")},
		Access: []HistoryAccess{{
			ReaderKey: closureDig("reader-1"), Mode: HistoryAccessRead, NotBefore: now.Add(-48 * time.Hour),
			ExpiresAt: now.Add(48 * time.Hour), AuthorizationDigest: closureDig("authz-1"),
		}},
		Boundary: &HistoryBoundary{
			CutoverAt: now.Add(-72 * time.Hour), Visible: true, Links: 3, LinksReadOnly: true,
			LinksRequireAuthorization: true, MetadataDigest: closureDig("boundary"),
		},
		Obligations: []HistoryObligation{
			{Kind: HistoryKindRetention, DueAt: now.Add(90 * 24 * time.Hour), RecordDigest: closureDig("retention"), ReminderLeadDays: 30},
			{Kind: HistoryKindExport, DueAt: now.Add(30 * 24 * time.Hour), RecordDigest: closureDig("export"), ReminderLeadDays: 14},
		},
		CompletionSteps: []string{"retain", "remind", "verify_read_only"},
	}
}

func closureProofFixture(now time.Time) ClosureDeadmanProof {
	start, end := now.Add(-3*time.Hour), now.Add(-2*time.Hour)
	rec := func(j ClosureJourney) ClosureRecovery {
		return ClosureRecovery{Journey: j, RecoveredAt: end.Add(10 * time.Minute), EvidenceDigest: closureDig("recovery/" + string(j))}
	}
	return ClosureDeadmanProof{
		Purpose: closureProofPurpose, Scope: closureTestScope,
		IssuedAt: now.Add(-90 * time.Minute), ExpiresAt: now.Add(7 * 24 * time.Hour),
		ProductDomain: ClosureFailureDomain{Process: "proc-a", Host: "host-a", Cluster: "cluster-a", Credential: "cred-a"},
		DeadmanDomain: ClosureFailureDomain{Process: "proc-b", Host: "host-b", Cluster: "cluster-b", Credential: "cred-b"},
		Outage:        ClosureOutage{StartedAt: start, EndedAt: end, ProcessesObserved: 5, ProcessesStopped: 5, StopEvidenceDigest: closureDig("stop")},
		Delivery:      ClosureDelivery{Route: ClosureRouteIndependentOperator, ObservedAt: start.Add(10 * time.Minute), ReceiptDigest: closureDig("delivery")},
		HistoryRead:   ClosureHistoryRead{ObservedAt: start.Add(20 * time.Minute), Readable: true, ReadOnly: true, ReceiptDigest: closureDig("read")},
		Recoveries:    []ClosureRecovery{rec(ClosureJourneyGateway), rec(ClosureJourneyFrontend), rec(ClosureJourneyScheduler)},
	}
}

func closureSign(t *testing.T, p ClosureDeadmanProof) *ClosureProofEnvelope {
	t.Helper()
	env, err := ClosureSignProof(closureTestKey("attestor"), closureTestKeyID, p)
	if err != nil {
		t.Fatal(err)
	}
	return &env
}

func closureLedgerFixture(t *testing.T) ClosureLedger {
	t.Helper()
	return ClosureLedger{
		Now: closureNow, Scope: closureTestScope, MaxEvidenceAgeSecs: 7 * 24 * 3600,
		Trust: map[string]ed25519.PublicKey{closureTestKeyID: closureTestKey("attestor").Public().(ed25519.PublicKey)},
		Gate: ClosureGate{
			Digest: closureDig("gate"), VerifiedAt: closureNow.Add(-time.Hour),
			Criteria: append([]ClosureCriterion{}, closureRequiredCriteria...),
		},
		History:      closureHistoryFixture(closureNow),
		DeadmanProof: closureSign(t, closureProofFixture(closureNow)),
	}
}

func closureWithProof(t *testing.T, l *ClosureLedger, edit func(*ClosureDeadmanProof)) {
	t.Helper()
	p := closureProofFixture(l.Now)
	edit(&p)
	l.DeadmanProof = closureSign(t, p)
}

func closureHas(r ClosureReport, area ClosureArea, code string) bool {
	for _, b := range r.Blockers {
		if b.Area == area && b.Code == code {
			return true
		}
	}
	return false
}

func closureClose(t *testing.T, l ClosureLedger) ClosureReport {
	t.Helper()
	r, err := CloseAdoption(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func closureRequireBlocked(t *testing.T, l ClosureLedger, area ClosureArea, code string) ClosureReport {
	t.Helper()
	r := closureClose(t, l)
	if r.Closed || !closureHas(r, area, code) {
		t.Fatalf("closed=%v, want blocker %s/%s; blockers=%v", r.Closed, area, code, r.Blockers)
	}
	if r.EvidenceDigest != "" {
		t.Fatal("a blocked closure carries an evidence digest")
	}
	return r
}

func TestClosureRejectsUnmetRetentionOrMissingDeadmanProof(t *testing.T) {
	if r := closureClose(t, closureLedgerFixture(t)); !r.Closed || len(r.Blockers) != 0 || r.EvidenceDigest == "" || !r.DeadmanIndependent ||
		!r.ProofVerified || !r.DeliveryInOutage || !r.HistoryReadInOutage || r.JourneysRecovered != 3 || r.CriteriaCovered != len(closureRequiredCriteria) {
		t.Fatalf("complete synthetic evidence must close: %+v", r)
	}
	cases := []struct {
		name string
		edit func(t *testing.T, l *ClosureLedger)
		area ClosureArea
		code string
	}{
		{"no export obligation or record", func(t *testing.T, l *ClosureLedger) { l.History.Obligations = l.History.Obligations[:1] }, ClosureAreaHistory, string(HistoryCodeExportRecordMissing)},
		{"export obligation without record digest", func(t *testing.T, l *ClosureLedger) { l.History.Obligations[1].RecordDigest = "" }, ClosureAreaHistory, string(HistoryCodeExportRecordMissing)},
		{"no retention obligation", func(t *testing.T, l *ClosureLedger) {
			l.History.Obligations = []HistoryObligation{l.History.Obligations[1]}
		}, ClosureAreaHistory, string(HistoryCodeRetentionMissing)},
		{"retention obligation overdue", func(t *testing.T, l *ClosureLedger) {
			l.History.Obligations[0].DueAt = closureNow.Add(-time.Second)
		}, ClosureAreaHistory, string(HistoryCodeRetentionOverdue)},
		{"export obligation overdue", func(t *testing.T, l *ClosureLedger) { l.History.Obligations[1].DueAt = closureNow }, ClosureAreaHistory, string(HistoryCodeExportOverdue)},
		{"history write access", func(t *testing.T, l *ClosureLedger) {
			l.History.Access = append(l.History.Access, HistoryAccess{ReaderKey: closureDig("writer"), Mode: HistoryAccessWrite, NotBefore: closureNow.Add(-time.Hour), ExpiresAt: closureNow.Add(time.Hour), AuthorizationDigest: closureDig("authz-w")})
		}, ClosureAreaHistory, string(HistoryCodeWriteAccess)},
		{"deadman proof absent", func(t *testing.T, l *ClosureLedger) { l.DeadmanProof = nil }, ClosureAreaDeadman, string(ClosureCodeProofMissing)},
		{"deadman tied to the product process", func(t *testing.T, l *ClosureLedger) {
			closureWithProof(t, l, func(p *ClosureDeadmanProof) { p.DeadmanDomain.Process = p.ProductDomain.Process })
		}, ClosureAreaDeadman, string(ClosureCodeSharesProcess)},
		{"deadman tied to the product host", func(t *testing.T, l *ClosureLedger) {
			closureWithProof(t, l, func(p *ClosureDeadmanProof) { p.DeadmanDomain.Host = p.ProductDomain.Host })
		}, ClosureAreaDeadman, string(ClosureCodeSharesHost)},
		{"deadman tied to the product cluster", func(t *testing.T, l *ClosureLedger) {
			closureWithProof(t, l, func(p *ClosureDeadmanProof) { p.DeadmanDomain.Cluster = p.ProductDomain.Cluster })
		}, ClosureAreaDeadman, string(ClosureCodeSharesCluster)},
		{"deadman tied to the product credential", func(t *testing.T, l *ClosureLedger) {
			closureWithProof(t, l, func(p *ClosureDeadmanProof) { p.DeadmanDomain.Credential = p.ProductDomain.Credential })
		}, ClosureAreaDeadman, string(ClosureCodeSharesCredential)},
		{"no delivery observed", func(t *testing.T, l *ClosureLedger) {
			closureWithProof(t, l, func(p *ClosureDeadmanProof) { p.Delivery = ClosureDelivery{} })
		}, ClosureAreaDeadman, string(ClosureCodeDeliveryMissing)},
		{"history not readable during outage", func(t *testing.T, l *ClosureLedger) {
			closureWithProof(t, l, func(p *ClosureDeadmanProof) { p.HistoryRead.Readable = false })
		}, ClosureAreaDeadman, string(ClosureCodeHistoryReadMissing)},
		{"a journey did not recover", func(t *testing.T, l *ClosureLedger) {
			closureWithProof(t, l, func(p *ClosureDeadmanProof) { p.Recoveries = p.Recoveries[:2] })
		}, ClosureAreaDeadman, string(ClosureCodeJourneysNotRecov)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := closureLedgerFixture(t)
			tc.edit(t, &l)
			closureRequireBlocked(t, l, tc.area, tc.code)
		})
	}
}

func TestClosureDeadmanDomainIndependence(t *testing.T) {
	dims := []struct {
		name string
		set  func(d *ClosureFailureDomain, v string)
		code ClosureCode
	}{
		{"process", func(d *ClosureFailureDomain, v string) { d.Process = v }, ClosureCodeSharesProcess},
		{"host", func(d *ClosureFailureDomain, v string) { d.Host = v }, ClosureCodeSharesHost},
		{"cluster", func(d *ClosureFailureDomain, v string) { d.Cluster = v }, ClosureCodeSharesCluster},
		{"credential", func(d *ClosureFailureDomain, v string) { d.Credential = v }, ClosureCodeSharesCredential},
	}
	for _, d := range dims {
		t.Run(d.name+" shared, spelled differently", func(t *testing.T) {
			l := closureLedgerFixture(t)
			closureWithProof(t, &l, func(p *ClosureDeadmanProof) {
				d.set(&p.ProductDomain, "Shared-Label")
				d.set(&p.DeadmanDomain, "  shared-label ")
			})
			r := closureRequireBlocked(t, l, ClosureAreaDeadman, string(d.code))
			if r.DeadmanIndependent {
				t.Fatal("a shared dimension is not independent")
			}
			for _, other := range dims {
				if other.code != d.code && closureHas(r, ClosureAreaDeadman, string(other.code)) {
					t.Fatalf("%s sharing blamed on %s", d.name, other.code)
				}
			}
		})
		t.Run(d.name+" unrecorded", func(t *testing.T) {
			for _, side := range []string{"product", "deadman"} {
				l := closureLedgerFixture(t)
				closureWithProof(t, &l, func(p *ClosureDeadmanProof) {
					if side == "product" {
						d.set(&p.ProductDomain, " ")
					} else {
						d.set(&p.DeadmanDomain, "")
					}
				})
				closureRequireBlocked(t, l, ClosureAreaDeadman, string(ClosureCodeDomainUnrecorded))
			}
		})
	}
	t.Run("overlong label is unrecorded", func(t *testing.T) {
		l := closureLedgerFixture(t)
		closureWithProof(t, &l, func(p *ClosureDeadmanProof) { p.DeadmanDomain.Host = strings.Repeat("h", closureMaxLabel+1) })
		closureRequireBlocked(t, l, ClosureAreaDeadman, string(ClosureCodeDomainUnrecorded))
	})
}

func TestClosureDeadmanProofSignature(t *testing.T) {
	good := func(t *testing.T) ClosureLedger { return closureLedgerFixture(t) }
	t.Run("unsigned", func(t *testing.T) {
		l := good(t)
		l.DeadmanProof.Signature = nil
		closureRequireBlocked(t, l, ClosureAreaDeadman, string(ClosureCodeProofUnsigned))
	})
	t.Run("no key id", func(t *testing.T) {
		l := good(t)
		l.DeadmanProof.KeyID = ""
		closureRequireBlocked(t, l, ClosureAreaDeadman, string(ClosureCodeProofUnsigned))
	})
	t.Run("unknown key id", func(t *testing.T) {
		l := good(t)
		l.DeadmanProof.KeyID = "someone-else"
		closureRequireBlocked(t, l, ClosureAreaDeadman, string(ClosureCodeProofUntrustedKey))
	})
	t.Run("trust root of the wrong size", func(t *testing.T) {
		l := good(t)
		l.Trust = map[string]ed25519.PublicKey{closureTestKeyID: []byte("short")}
		closureRequireBlocked(t, l, ClosureAreaDeadman, string(ClosureCodeProofUntrustedKey))
	})
	t.Run("no trust root at all", func(t *testing.T) {
		l := good(t)
		l.Trust = nil
		closureRequireBlocked(t, l, ClosureAreaDeadman, string(ClosureCodeProofUntrustedKey))
	})
	t.Run("signed by another key", func(t *testing.T) {
		l := good(t)
		env, err := ClosureSignProof(closureTestKey("product-key"), closureTestKeyID, closureProofFixture(closureNow))
		if err != nil {
			t.Fatal(err)
		}
		l.DeadmanProof = &env
		closureRequireBlocked(t, l, ClosureAreaDeadman, string(ClosureCodeProofBadSignature))
	})
	t.Run("payload tampered after signing", func(t *testing.T) {
		l := good(t)
		var p ClosureDeadmanProof
		if err := json.Unmarshal(l.DeadmanProof.Payload, &p); err != nil {
			t.Fatal(err)
		}
		p.DeadmanDomain.Process = "tampered"
		l.DeadmanProof.Payload, _ = json.Marshal(p)
		r := closureRequireBlocked(t, l, ClosureAreaDeadman, string(ClosureCodeProofBadSignature))
		if r.ProofVerified || r.DeadmanIndependent || r.DeliveryInOutage || r.HistoryReadInOutage || r.JourneysRecovered != 0 || r.ProofDigest != "" {
			t.Fatalf("a tampered proof contributed facts: %+v", r)
		}
	})
	t.Run("one flipped payload byte", func(t *testing.T) {
		l := good(t)
		l.DeadmanProof.Payload[len(l.DeadmanProof.Payload)/2] ^= 1
		closureRequireBlocked(t, l, ClosureAreaDeadman, string(ClosureCodeProofBadSignature))
	})
	t.Run("signature flipped", func(t *testing.T) {
		l := good(t)
		l.DeadmanProof.Signature[0] ^= 1
		closureRequireBlocked(t, l, ClosureAreaDeadman, string(ClosureCodeProofBadSignature))
	})
	t.Run("empty payload", func(t *testing.T) {
		l := good(t)
		l.DeadmanProof.Payload = nil
		closureRequireBlocked(t, l, ClosureAreaDeadman, string(ClosureCodeProofBadSignature))
	})
	t.Run("oversized payload", func(t *testing.T) {
		l := good(t)
		key := closureTestKey("attestor")
		l.DeadmanProof.Payload = []byte(strings.Repeat(" ", closureMaxPayload+1))
		l.DeadmanProof.Signature = ed25519.Sign(key, closureSigned(l.DeadmanProof.Payload))
		closureRequireBlocked(t, l, ClosureAreaDeadman, string(ClosureCodeProofBadSignature))
	})
	t.Run("signed but malformed payload", func(t *testing.T) {
		l := good(t)
		payload := []byte(`{"purpose":"` + closureProofPurpose + `","unexpected":true}`)
		l.DeadmanProof.Payload = payload
		l.DeadmanProof.Signature = ed25519.Sign(closureTestKey("attestor"), closureSigned(payload))
		r := closureRequireBlocked(t, l, ClosureAreaDeadman, string(ClosureCodeProofMalformed))
		if r.ProofVerified {
			t.Fatal("malformed payload counted as verified")
		}
	})
	t.Run("signature over the payload without the purpose prefix", func(t *testing.T) {
		l := good(t)
		l.DeadmanProof.Signature = ed25519.Sign(closureTestKey("attestor"), l.DeadmanProof.Payload)
		closureRequireBlocked(t, l, ClosureAreaDeadman, string(ClosureCodeProofBadSignature))
	})
	t.Run("signing refuses bad input", func(t *testing.T) {
		if _, err := ClosureSignProof(nil, closureTestKeyID, closureProofFixture(closureNow)); err == nil {
			t.Fatal("signed with no key")
		}
		if _, err := ClosureSignProof(closureTestKey("attestor"), " ", closureProofFixture(closureNow)); err == nil {
			t.Fatal("signed with no key id")
		}
	})
}

func TestClosureDeadmanProofScopeAndFreshness(t *testing.T) {
	cases := []struct {
		name string
		edit func(p *ClosureDeadmanProof)
		code ClosureCode
	}{
		{"wrong scope", func(p *ClosureDeadmanProof) { p.Scope = "adoption-closure/other" }, ClosureCodeProofWrongScope},
		{"wrong purpose", func(p *ClosureDeadmanProof) { p.Purpose = "soundpost/adoption/other/v1" }, ClosureCodeProofWrongScope},
		{"expired", func(p *ClosureDeadmanProof) { p.ExpiresAt = closureNow }, ClosureCodeProofExpired},
		{"future dated", func(p *ClosureDeadmanProof) { p.IssuedAt = closureNow.Add(time.Second) }, ClosureCodeProofFuture},
		{"stale", func(p *ClosureDeadmanProof) {
			p.IssuedAt = closureNow.Add(-7*24*time.Hour - time.Second)
			p.Outage.EndedAt = p.IssuedAt.Add(-time.Minute)
			p.Outage.StartedAt = p.Outage.EndedAt.Add(-time.Hour)
		}, ClosureCodeProofStale},
		{"no issue time", func(p *ClosureDeadmanProof) { p.IssuedAt = time.Time{} }, ClosureCodeProofMalformed},
		{"no expiry", func(p *ClosureDeadmanProof) { p.ExpiresAt = time.Time{} }, ClosureCodeProofMalformed},
		{"expiry before issue", func(p *ClosureDeadmanProof) { p.ExpiresAt = p.IssuedAt }, ClosureCodeProofMalformed},
		{"unbounded lifetime", func(p *ClosureDeadmanProof) { p.ExpiresAt = p.IssuedAt.Add(closureMaxProofLife + time.Second) }, ClosureCodeProofMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := closureLedgerFixture(t)
			closureWithProof(t, &l, tc.edit)
			closureRequireBlocked(t, l, ClosureAreaDeadman, string(tc.code))
		})
	}
	t.Run("age bound is inclusive", func(t *testing.T) {
		l := closureLedgerFixture(t)
		closureWithProof(t, &l, func(p *ClosureDeadmanProof) {
			p.IssuedAt = closureNow.Add(-7 * 24 * time.Hour)
			p.Outage.EndedAt = p.IssuedAt.Add(-time.Minute)
			p.Outage.StartedAt = p.Outage.EndedAt.Add(-time.Hour)
			p.Delivery.ObservedAt = p.Outage.StartedAt.Add(time.Minute)
			p.HistoryRead.ObservedAt = p.Outage.StartedAt.Add(time.Minute)
			for i := range p.Recoveries {
				p.Recoveries[i].RecoveredAt = p.Outage.EndedAt.Add(time.Second)
			}
		})
		l.Gate.VerifiedAt = closureNow.Add(-7 * 24 * time.Hour)
		l.History.ObservedAt = closureNow.Add(-7 * 24 * time.Hour)
		l.History.MaxEvidenceAgeSecs = 7 * 24 * 3600
		if r := closureClose(t, l); !r.Closed {
			t.Fatalf("evidence exactly at the age bound must be fresh: %v", r.Blockers)
		}
	})
	t.Run("expiry is judged by the caller clock", func(t *testing.T) {
		l := closureLedgerFixture(t)
		l.Now = closureNow.Add(8 * 24 * time.Hour)
		l.History.Now = time.Time{}
		l.History.ObservedAt = l.Now.Add(-time.Hour)
		l.Gate.VerifiedAt = l.Now.Add(-time.Hour)
		r := closureClose(t, l)
		if r.Closed || !closureHas(r, ClosureAreaDeadman, string(ClosureCodeProofExpired)) {
			t.Fatalf("later clock must expire the proof: %v", r.Blockers)
		}
	})
}

func TestClosureDeadmanOutageEvidence(t *testing.T) {
	cases := []struct {
		name string
		edit func(p *ClosureDeadmanProof)
		code ClosureCode
	}{
		{"outage shorter than a minute", func(p *ClosureDeadmanProof) {
			p.Outage.EndedAt = p.Outage.StartedAt.Add(closureMinOutage - time.Second)
			p.Delivery.ObservedAt, p.HistoryRead.ObservedAt = p.Outage.StartedAt, p.Outage.StartedAt
			for i := range p.Recoveries {
				p.Recoveries[i].RecoveredAt = p.Outage.EndedAt
			}
		}, ClosureCodeOutageWindow},
		{"outage inverted", func(p *ClosureDeadmanProof) {
			p.Outage.StartedAt, p.Outage.EndedAt = p.Outage.EndedAt, p.Outage.StartedAt
		}, ClosureCodeOutageWindow},
		{"outage with no window", func(p *ClosureDeadmanProof) { p.Outage.StartedAt, p.Outage.EndedAt = time.Time{}, time.Time{} }, ClosureCodeOutageWindow},
		{"outage start missing", func(p *ClosureDeadmanProof) { p.Outage.StartedAt = time.Time{} }, ClosureCodeOutageWindow},
		{"outage end missing", func(p *ClosureDeadmanProof) { p.Outage.EndedAt = time.Time{} }, ClosureCodeOutageWindow},
		{"outage ends after the proof is issued", func(p *ClosureDeadmanProof) { p.Outage.EndedAt = p.IssuedAt.Add(time.Second) }, ClosureCodeOutageWindow},
		{"fewer processes stopped than observed", func(p *ClosureDeadmanProof) { p.Outage.ProcessesStopped = 4 }, ClosureCodeOutageNotAllStop},
		{"more processes stopped than observed", func(p *ClosureDeadmanProof) { p.Outage.ProcessesStopped = 6 }, ClosureCodeOutageNotAllStop},
		{"no processes observed", func(p *ClosureDeadmanProof) { p.Outage.ProcessesObserved, p.Outage.ProcessesStopped = 0, 0 }, ClosureCodeOutageNotAllStop},
		{"no stop evidence", func(p *ClosureDeadmanProof) { p.Outage.StopEvidenceDigest = "stopped" }, ClosureCodeOutageNotAllStop},
		{"delivery through the product channel", func(p *ClosureDeadmanProof) { p.Delivery.Route = ClosureRouteProductChannel }, ClosureCodeRouteNotIndep},
		{"delivery through an unknown route", func(p *ClosureDeadmanProof) { p.Delivery.Route = "carrier-pigeon" }, ClosureCodeRouteNotIndep},
		{"no delivery route", func(p *ClosureDeadmanProof) { p.Delivery.Route = "" }, ClosureCodeDeliveryMissing},
		{"no delivery time", func(p *ClosureDeadmanProof) { p.Delivery.ObservedAt = time.Time{} }, ClosureCodeDeliveryMissing},
		{"no delivery receipt", func(p *ClosureDeadmanProof) { p.Delivery.ReceiptDigest = "" }, ClosureCodeDeliveryMissing},
		{"delivery before the outage", func(p *ClosureDeadmanProof) { p.Delivery.ObservedAt = p.Outage.StartedAt.Add(-time.Second) }, ClosureCodeDeliveryOutside},
		{"delivery after the outage", func(p *ClosureDeadmanProof) { p.Delivery.ObservedAt = p.Outage.EndedAt.Add(time.Second) }, ClosureCodeDeliveryOutside},
		{"history unreadable", func(p *ClosureDeadmanProof) { p.HistoryRead.Readable = false }, ClosureCodeHistoryReadMissing},
		{"history writable during outage", func(p *ClosureDeadmanProof) { p.HistoryRead.ReadOnly = false }, ClosureCodeHistoryReadMissing},
		{"history read without receipt", func(p *ClosureDeadmanProof) { p.HistoryRead.ReceiptDigest = "" }, ClosureCodeHistoryReadMissing},
		{"history read without time", func(p *ClosureDeadmanProof) { p.HistoryRead.ObservedAt = time.Time{} }, ClosureCodeHistoryReadMissing},
		{"history read before the outage", func(p *ClosureDeadmanProof) { p.HistoryRead.ObservedAt = p.Outage.StartedAt.Add(-time.Second) }, ClosureCodeHistoryReadOutside},
		{"history read after the outage", func(p *ClosureDeadmanProof) { p.HistoryRead.ObservedAt = p.Outage.EndedAt.Add(time.Second) }, ClosureCodeHistoryReadOutside},
		{"journey missing", func(p *ClosureDeadmanProof) { p.Recoveries = p.Recoveries[1:] }, ClosureCodeJourneysNotRecov},
		{"no journeys", func(p *ClosureDeadmanProof) { p.Recoveries = nil }, ClosureCodeJourneysNotRecov},
		{"journey duplicated", func(p *ClosureDeadmanProof) { p.Recoveries[2] = p.Recoveries[1] }, ClosureCodeJourneysNotRecov},
		{"unknown journey", func(p *ClosureDeadmanProof) { p.Recoveries[0].Journey = "dashboard_screenshot" }, ClosureCodeJourneysNotRecov},
		{"extra journey", func(p *ClosureDeadmanProof) { p.Recoveries = append(p.Recoveries, p.Recoveries[0]) }, ClosureCodeJourneysNotRecov},
		{"journey recovered before the outage ended", func(p *ClosureDeadmanProof) { p.Recoveries[0].RecoveredAt = p.Outage.EndedAt.Add(-time.Second) }, ClosureCodeJourneysNotRecov},
		{"journey recovery after the proof", func(p *ClosureDeadmanProof) { p.Recoveries[0].RecoveredAt = p.IssuedAt.Add(time.Second) }, ClosureCodeJourneysNotRecov},
		{"journey recovery without evidence", func(p *ClosureDeadmanProof) { p.Recoveries[1].EvidenceDigest = "" }, ClosureCodeJourneysNotRecov},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := closureLedgerFixture(t)
			closureWithProof(t, &l, tc.edit)
			closureRequireBlocked(t, l, ClosureAreaDeadman, string(tc.code))
		})
	}
	t.Run("window edges are inside", func(t *testing.T) {
		l := closureLedgerFixture(t)
		closureWithProof(t, &l, func(p *ClosureDeadmanProof) {
			p.Outage.EndedAt = p.Outage.StartedAt.Add(closureMinOutage)
			p.Delivery.ObservedAt, p.HistoryRead.ObservedAt = p.Outage.StartedAt, p.Outage.EndedAt
			for i := range p.Recoveries {
				p.Recoveries[i].RecoveredAt = p.Outage.EndedAt
			}
			p.IssuedAt = p.Outage.EndedAt
		})
		if r := closureClose(t, l); !r.Closed {
			t.Fatalf("edge values are inside the window: %v", r.Blockers)
		}
	})
	t.Run("an invalid window establishes no fact", func(t *testing.T) {
		l := closureLedgerFixture(t)
		closureWithProof(t, &l, func(p *ClosureDeadmanProof) {
			p.Outage.EndedAt = p.Outage.StartedAt.Add(closureMinOutage - time.Second)
			p.Delivery.ObservedAt, p.HistoryRead.ObservedAt = p.Outage.StartedAt, p.Outage.StartedAt
			for i := range p.Recoveries {
				p.Recoveries[i].RecoveredAt = p.Outage.EndedAt
			}
		})
		r := closureRequireBlocked(t, l, ClosureAreaDeadman, string(ClosureCodeOutageWindow))
		if r.DeliveryInOutage || r.HistoryReadInOutage || r.JourneysRecovered != 0 {
			t.Fatalf("a window that is too short must not support any outage fact: %+v", r)
		}
	})
	t.Run("recovered counted even when other checks fail", func(t *testing.T) {
		l := closureLedgerFixture(t)
		closureWithProof(t, &l, func(p *ClosureDeadmanProof) { p.Recoveries[0].RecoveredAt = p.Outage.EndedAt.Add(-time.Second) })
		if r := closureClose(t, l); r.JourneysRecovered != 2 {
			t.Fatalf("recovered=%d, want 2", r.JourneysRecovered)
		}
	})
}

func TestClosureGateEvidence(t *testing.T) {
	t.Run("no gate", func(t *testing.T) {
		l := closureLedgerFixture(t)
		l.Gate = ClosureGate{}
		r := closureRequireBlocked(t, l, ClosureAreaGate, string(ClosureCodeGateMissing))
		if !closureHas(r, ClosureAreaGate, string(ClosureCodeCriterionMissing)) || len(r.MissingCriteria) != len(closureRequiredCriteria) {
			t.Fatalf("an empty gate covers nothing: %+v", r)
		}
	})
	t.Run("gate digest is not a digest", func(t *testing.T) {
		l := closureLedgerFixture(t)
		l.Gate.Digest = "gate-1"
		closureRequireBlocked(t, l, ClosureAreaGate, string(ClosureCodeGateMissing))
	})
	t.Run("gate without verification time", func(t *testing.T) {
		l := closureLedgerFixture(t)
		l.Gate.VerifiedAt = time.Time{}
		closureRequireBlocked(t, l, ClosureAreaGate, string(ClosureCodeGateMissing))
	})
	t.Run("gate verified in the future", func(t *testing.T) {
		l := closureLedgerFixture(t)
		l.Gate.VerifiedAt = closureNow.Add(time.Nanosecond)
		closureRequireBlocked(t, l, ClosureAreaGate, string(ClosureCodeGateFuture))
	})
	t.Run("gate stale by one second", func(t *testing.T) {
		l := closureLedgerFixture(t)
		l.Gate.VerifiedAt = closureNow.Add(-7*24*time.Hour - time.Second)
		closureRequireBlocked(t, l, ClosureAreaGate, string(ClosureCodeGateStale))
	})
	t.Run("gate exactly at the age bound", func(t *testing.T) {
		l := closureLedgerFixture(t)
		l.Gate.VerifiedAt = closureNow.Add(-7 * 24 * time.Hour)
		if r := closureClose(t, l); !r.Closed {
			t.Fatalf("gate at the bound is fresh: %v", r.Blockers)
		}
	})
	for i, c := range closureRequiredCriteria {
		t.Run("missing criterion "+string(c), func(t *testing.T) {
			l := closureLedgerFixture(t)
			l.Gate.Criteria = append(append([]ClosureCriterion{}, closureRequiredCriteria[:i]...), closureRequiredCriteria[i+1:]...)
			r := closureRequireBlocked(t, l, ClosureAreaGate, string(ClosureCodeCriterionMissing))
			if len(r.MissingCriteria) != 1 || r.MissingCriteria[0] != c || r.CriteriaCovered != len(closureRequiredCriteria)-1 {
				t.Fatalf("missing=%v covered=%d", r.MissingCriteria, r.CriteriaCovered)
			}
		})
	}
	t.Run("unknown criterion is refused, not ignored", func(t *testing.T) {
		l := closureLedgerFixture(t)
		l.Gate.Criteria = append(l.Gate.Criteria, "dashboard_screenshot")
		closureRequireBlocked(t, l, ClosureAreaGate, string(ClosureCodeCriterionUnknown))
	})
	t.Run("repeating one criterion does not cover another", func(t *testing.T) {
		l := closureLedgerFixture(t)
		l.Gate.Criteria = nil
		for range closureRequiredCriteria {
			l.Gate.Criteria = append(l.Gate.Criteria, ClosureCriterionSourcePolicy)
		}
		r := closureRequireBlocked(t, l, ClosureAreaGate, string(ClosureCodeCriterionMissing))
		if r.CriteriaCovered != 1 {
			t.Fatalf("covered=%d", r.CriteriaCovered)
		}
	})
}

func TestClosureClockAndCallValidation(t *testing.T) {
	bad := map[string]func(l *ClosureLedger){
		"no clock":               func(l *ClosureLedger) { l.Now = time.Time{} },
		"no scope":               func(l *ClosureLedger) { l.Scope = "" },
		"scope with capitals":    func(l *ClosureLedger) { l.Scope = "Adoption" },
		"scope with a space":     func(l *ClosureLedger) { l.Scope = "adoption closure" },
		"scope too long":         func(l *ClosureLedger) { l.Scope = strings.Repeat("a", 65) },
		"no age bound":           func(l *ClosureLedger) { l.MaxEvidenceAgeSecs = 0 },
		"negative age bound":     func(l *ClosureLedger) { l.MaxEvidenceAgeSecs = -1 },
		"age bound over 30 days": func(l *ClosureLedger) { l.MaxEvidenceAgeSecs = 30*24*3600 + 1 },
		"history clock differs":  func(l *ClosureLedger) { l.History.Now = closureNow.Add(time.Second) },
		"history age bound bad":  func(l *ClosureLedger) { l.History.MaxEvidenceAgeSecs = 30*24*3600 + 1 },
	}
	for name, edit := range bad {
		t.Run(name, func(t *testing.T) {
			c := closureLedgerFixture(t)
			edit(&c)
			if r, err := CloseAdoption(context.Background(), c); err == nil {
				t.Fatalf("unusable call produced a report: %+v", r.Closed)
			}
		})
	}
	t.Run("history inherits clock and age bound", func(t *testing.T) {
		c := closureLedgerFixture(t)
		c.History.Now, c.History.MaxEvidenceAgeSecs = time.Time{}, 0
		if r := closureClose(t, c); !r.Closed {
			t.Fatalf("inherited history settings must close: %v", r.Blockers)
		}
	})
	t.Run("scope alphabet", func(t *testing.T) {
		c := closureLedgerFixture(t)
		c.Scope = "a_b.c/d-e9"
		closureWithProof(t, &c, func(p *ClosureDeadmanProof) { p.Scope = c.Scope })
		if r := closureClose(t, c); !r.Closed {
			t.Fatalf("%v", r.Blockers)
		}
	})
	t.Run("scope length bound is inclusive", func(t *testing.T) {
		c := closureLedgerFixture(t)
		c.Scope = strings.Repeat("a", 64)
		closureWithProof(t, &c, func(p *ClosureDeadmanProof) { p.Scope = c.Scope })
		if r := closureClose(t, c); !r.Closed {
			t.Fatalf("%v", r.Blockers)
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := CloseAdoption(ctx, closureLedgerFixture(t)); err == nil {
			t.Fatal("closed under a cancelled context")
		}
		if _, err := HistoryStatus(ctx, closureHistoryFixture(closureNow)); err == nil {
			t.Fatal("history evaluated under a cancelled context")
		}
	})
	t.Run("history blockers surface under the history area", func(t *testing.T) {
		c := closureLedgerFixture(t)
		c.History.Boundary.Visible = false
		r := closureRequireBlocked(t, c, ClosureAreaHistory, string(HistoryCodeBoundaryNotVisible))
		if r.History.Clear {
			t.Fatal("history report claims clear")
		}
	})
	t.Run("a later clock is judged, not the file's", func(t *testing.T) {
		c := closureLedgerFixture(t)
		c.Now = closureNow.Add(40 * 24 * time.Hour)
		c.History.Now = time.Time{}
		c.MaxEvidenceAgeSecs = 30 * 24 * 3600
		r := closureClose(t, c)
		if r.Closed || !closureHas(r, ClosureAreaGate, string(ClosureCodeGateStale)) || !closureHas(r, ClosureAreaHistory, string(HistoryCodeEvidenceStale)) || !closureHas(r, ClosureAreaDeadman, string(ClosureCodeProofExpired)) {
			t.Fatalf("every evidence kind must be judged at the caller clock: %v", r.Blockers)
		}
	})
}

func TestHistoryStatusAccess(t *testing.T) {
	now := closureNow
	grant := func(mode HistoryAccessMode, nb, exp, rev time.Time) HistoryAccess {
		return HistoryAccess{ReaderKey: closureDig("principal-" + string(mode)), Mode: mode, NotBefore: nb, ExpiresAt: exp, RevokedAt: rev, AuthorizationDigest: closureDig("authz")}
	}
	statusOf := func(a ...HistoryAccess) HistoryReport {
		h := closureHistoryFixture(now)
		h.Access = a
		r, err := HistoryStatus(context.Background(), h)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	blockedBy := func(r HistoryReport, c HistoryCode) bool {
		for _, b := range r.Blockers {
			if b == c {
				return true
			}
		}
		return false
	}
	hour := time.Hour
	if r := statusOf(); !r.Clear || r.ActiveReaders != 0 {
		t.Fatalf("no grants is not a blocker: %+v", r)
	}
	for name, g := range map[string]HistoryAccess{
		"active write":                grant(HistoryAccessWrite, now.Add(-hour), now.Add(hour), time.Time{}),
		"write that starts later":     grant(HistoryAccessWrite, now.Add(hour), now.Add(2*hour), time.Time{}),
		"write revoked in the future": grant(HistoryAccessWrite, now.Add(-hour), now.Add(2*hour), now.Add(hour)),
		"write starting this instant": grant(HistoryAccessWrite, now, now.Add(hour), time.Time{}),
	} {
		t.Run(name, func(t *testing.T) {
			r := statusOf(g)
			if r.Clear || !blockedBy(r, HistoryCodeWriteAccess) || r.ActiveWriters != 1 {
				t.Fatalf("write access must block: %+v", r)
			}
		})
	}
	t.Run("write with no expiry stays a write grant", func(t *testing.T) {
		r := statusOf(grant(HistoryAccessWrite, now.Add(-hour), time.Time{}, time.Time{}))
		if !blockedBy(r, HistoryCodeWriteAccess) || !blockedBy(r, HistoryCodeAccessInvalid) {
			t.Fatalf("%v", r.Blockers)
		}
	})
	t.Run("unknown mode may be a write", func(t *testing.T) {
		r := statusOf(grant("admin", now.Add(-hour), now.Add(hour), time.Time{}))
		if !blockedBy(r, HistoryCodeWriteAccess) || !blockedBy(r, HistoryCodeAccessInvalid) {
			t.Fatalf("%v", r.Blockers)
		}
	})
	for name, g := range map[string]HistoryAccess{
		"write expired":                grant(HistoryAccessWrite, now.Add(-2*hour), now, time.Time{}),
		"write revoked":                grant(HistoryAccessWrite, now.Add(-2*hour), now.Add(hour), now),
		"write revoked before it ends": grant(HistoryAccessWrite, now.Add(-2*hour), now.Add(hour), now.Add(-hour)),
	} {
		t.Run(name, func(t *testing.T) {
			r := statusOf(g)
			if blockedBy(r, HistoryCodeWriteAccess) || r.ActiveWriters != 0 {
				t.Fatalf("a finished write grant is not write access: %+v", r)
			}
		})
	}
	t.Run("read grants are counted once per reader when active", func(t *testing.T) {
		a := grant(HistoryAccessRead, now.Add(-hour), now.Add(hour), time.Time{})
		b := a
		c := grant(HistoryAccessRead, now.Add(-hour), now.Add(hour), time.Time{})
		c.ReaderKey = closureDig("another")
		expired := grant(HistoryAccessRead, now.Add(-2*hour), now, time.Time{})
		expired.ReaderKey = closureDig("expired")
		future := grant(HistoryAccessRead, now.Add(hour), now.Add(2*hour), time.Time{})
		future.ReaderKey = closureDig("future")
		revoked := grant(HistoryAccessRead, now.Add(-2*hour), now.Add(hour), now)
		revoked.ReaderKey = closureDig("revoked")
		if r := statusOf(a, b, c, expired, future, revoked); r.ActiveReaders != 2 || !r.Clear {
			t.Fatalf("active readers=%d clear=%v", r.ActiveReaders, r.Clear)
		}
	})
	t.Run("raw reader identity is refused", func(t *testing.T) {
		g := grant(HistoryAccessRead, now.Add(-hour), now.Add(hour), time.Time{})
		g.ReaderKey = "operator@example.invalid"
		if r := statusOf(g); !blockedBy(r, HistoryCodeReaderNotKeyed) || r.Clear {
			t.Fatalf("%v", r.Blockers)
		}
		g.ReaderKey = strings.ToUpper(closureDig("upper"))
		if r := statusOf(g); !blockedBy(r, HistoryCodeReaderNotKeyed) {
			t.Fatal("upper case is not the keyed spelling")
		}
	})
	t.Run("grant without authorization digest", func(t *testing.T) {
		g := grant(HistoryAccessRead, now.Add(-hour), now.Add(hour), time.Time{})
		g.AuthorizationDigest = ""
		if r := statusOf(g); !blockedBy(r, HistoryCodeAccessUnauthorized) {
			t.Fatal(r.Blockers)
		}
	})
	t.Run("read grant without a valid window", func(t *testing.T) {
		g := grant(HistoryAccessRead, now.Add(hour), now.Add(-hour), time.Time{})
		if r := statusOf(g); !blockedBy(r, HistoryCodeAccessInvalid) {
			t.Fatal(r.Blockers)
		}
	})
	t.Run("reader keys are keyed", func(t *testing.T) {
		k1, k2 := []byte(strings.Repeat("a", 32)), []byte(strings.Repeat("b", 32))
		a, err := HistoryReaderKey(k1, " reader@example.invalid ")
		if err != nil || !historyDigestOK(a) {
			t.Fatalf("%q %v", a, err)
		}
		if again, _ := HistoryReaderKey(k1, "reader@example.invalid"); again != a {
			t.Fatal("not deterministic")
		}
		if other, _ := HistoryReaderKey(k2, "reader@example.invalid"); other == a {
			t.Fatal("the key does not influence the pseudonym")
		}
		if other, _ := HistoryReaderKey(k1, "reader2@example.invalid"); other == a {
			t.Fatal("the identity does not influence the pseudonym")
		}
		if strings.Contains(a, "reader") {
			t.Fatal("identity visible")
		}
		if _, err := HistoryReaderKey([]byte(strings.Repeat("k", 31)), "x"); err == nil {
			t.Fatal("31-byte key accepted")
		}
		if _, err := HistoryReaderKey([]byte("short"), "x"); err == nil {
			t.Fatal("short key accepted")
		}
		if _, err := HistoryReaderKey(k1, "  "); err == nil {
			t.Fatal("empty identity accepted")
		}
	})
}

func TestHistoryStatusOriginBoundaryAndSteps(t *testing.T) {
	statusOf := func(edit func(h *HistoryObligations)) HistoryReport {
		h := closureHistoryFixture(closureNow)
		edit(&h)
		r, err := HistoryStatus(context.Background(), h)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	want := func(t *testing.T, r HistoryReport, codes ...HistoryCode) {
		t.Helper()
		if len(r.Blockers) != len(codes) || r.Clear {
			t.Fatalf("blockers=%v want %v", r.Blockers, codes)
		}
		for _, c := range codes {
			found := false
			for _, b := range r.Blockers {
				found = found || b == c
			}
			if !found {
				t.Fatalf("blockers=%v want %v", r.Blockers, codes)
			}
		}
	}
	if r := statusOf(func(h *HistoryObligations) {}); !r.Clear || r.Digest == "" || !r.BoundaryShown || r.Open != 2 || r.Overdue != 0 || r.Completed != 0 {
		t.Fatalf("baseline: %+v", r)
	}
	t.Run("origin not read-only", func(t *testing.T) {
		want(t, statusOf(func(h *HistoryObligations) { h.Origin.ReadOnly = false }), HistoryCodeOriginNotReadOnly)
	})
	t.Run("origin without evidence", func(t *testing.T) {
		want(t, statusOf(func(h *HistoryObligations) { h.Origin.EvidenceDigest = "" }), HistoryCodeOriginNotReadOnly)
	})
	t.Run("history removed while obligations are open", func(t *testing.T) {
		want(t, statusOf(func(h *HistoryObligations) { h.Origin.Retained = false }), HistoryCodeHistoryRemoved)
	})
	t.Run("history removed with no obligations at all", func(t *testing.T) {
		r := statusOf(func(h *HistoryObligations) { h.Origin.Retained, h.Obligations = false, nil })
		found := false
		for _, b := range r.Blockers {
			found = found || b == HistoryCodeHistoryRemoved
		}
		if !found || r.Clear {
			t.Fatal(r.Blockers)
		}
	})
	t.Run("history gone after audited completion is not blocked by retention", func(t *testing.T) {
		r := statusOf(func(h *HistoryObligations) {
			h.Origin.Retained = false
			for i := range h.Obligations {
				h.Obligations[i].Completed, h.Obligations[i].CompletedAt = true, closureNow.Add(-time.Hour)
				h.Obligations[i].AuthorizationDigest, h.Obligations[i].AuditDigest = closureDig("authz"), closureDig("audit")
			}
		})
		if !r.Clear || r.Completed != 2 || r.Open != 0 {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("history gone with one obligation still open", func(t *testing.T) {
		r := statusOf(func(h *HistoryObligations) {
			h.Origin.Retained = false
			h.Obligations[0].Completed, h.Obligations[0].CompletedAt = true, closureNow.Add(-time.Hour)
			h.Obligations[0].AuthorizationDigest, h.Obligations[0].AuditDigest = closureDig("authz"), closureDig("audit")
		})
		found := false
		for _, b := range r.Blockers {
			found = found || b == HistoryCodeHistoryRemoved
		}
		if !found {
			t.Fatal(r.Blockers)
		}
	})
	t.Run("boundary absent", func(t *testing.T) {
		want(t, statusOf(func(h *HistoryObligations) { h.Boundary = nil }), HistoryCodeBoundaryMissing)
	})
	t.Run("boundary with no links", func(t *testing.T) {
		want(t, statusOf(func(h *HistoryObligations) { h.Boundary.Links = 0 }), HistoryCodeBoundaryMissing)
	})
	t.Run("boundary metadata without digest", func(t *testing.T) {
		want(t, statusOf(func(h *HistoryObligations) { h.Boundary.MetadataDigest = "" }), HistoryCodeBoundaryMissing)
	})
	t.Run("boundary without cutover time", func(t *testing.T) {
		want(t, statusOf(func(h *HistoryObligations) { h.Boundary.CutoverAt = time.Time{} }), HistoryCodeBoundaryMissing)
	})
	t.Run("cutover in the future", func(t *testing.T) {
		want(t, statusOf(func(h *HistoryObligations) { h.Boundary.CutoverAt = closureNow.Add(time.Second) }), HistoryCodeBoundaryMissing)
	})
	t.Run("cutover at the clock is not the future", func(t *testing.T) {
		if r := statusOf(func(h *HistoryObligations) { h.Boundary.CutoverAt = closureNow }); !r.Clear {
			t.Fatal(r.Blockers)
		}
	})
	t.Run("boundary not visible", func(t *testing.T) {
		r := statusOf(func(h *HistoryObligations) { h.Boundary.Visible = false })
		want(t, r, HistoryCodeBoundaryNotVisible)
		if r.BoundaryShown {
			t.Fatal("hidden boundary reported shown")
		}
	})
	t.Run("links writable", func(t *testing.T) {
		want(t, statusOf(func(h *HistoryObligations) { h.Boundary.LinksReadOnly = false }), HistoryCodeBoundaryNotReadOnly)
	})
	t.Run("links without authorization", func(t *testing.T) {
		want(t, statusOf(func(h *HistoryObligations) { h.Boundary.LinksRequireAuthorization = false }), HistoryCodeBoundaryUnauthorized)
	})
	t.Run("evidence stale and future", func(t *testing.T) {
		want(t, statusOf(func(h *HistoryObligations) { h.ObservedAt = closureNow.Add(-24*time.Hour - time.Second) }), HistoryCodeEvidenceStale)
		want(t, statusOf(func(h *HistoryObligations) { h.ObservedAt = time.Time{} }), HistoryCodeEvidenceStale)
		want(t, statusOf(func(h *HistoryObligations) { h.ObservedAt = closureNow.Add(time.Nanosecond) }), HistoryCodeEvidenceFuture)
		if r := statusOf(func(h *HistoryObligations) { h.ObservedAt = closureNow.Add(-24 * time.Hour) }); !r.Clear {
			t.Fatal("observation exactly at the bound is fresh")
		}
		if r := statusOf(func(h *HistoryObligations) { h.ObservedAt = closureNow }); !r.Clear {
			t.Fatal("observation at the clock is not future dated")
		}
	})
	steps := map[string]HistoryCode{
		"delete_legacy_history": HistoryCodeRemovalStep, "Remove-Origin": HistoryCodeRemovalStep, "purge": HistoryCodeRemovalStep,
		"decommission_legacy": HistoryCodeRemovalStep, "drop_tables": HistoryCodeRemovalStep, "wipe": HistoryCodeRemovalStep,
		"truncate_logs": HistoryCodeRemovalStep, "erase": HistoryCodeRemovalStep, "destroy": HistoryCodeRemovalStep,
		"retire_legacy": HistoryCodeRemovalStep, "cleanup": HistoryCodeRemovalStep, "expire_history": HistoryCodeRemovalStep,
		"shred": HistoryCodeRemovalStep, "clean_up": HistoryCodeRemovalStep,
		"import_history": HistoryCodeImportStep, "migrate_to_soundpost": HistoryCodeImportStep, "backfill": HistoryCodeImportStep, "ingest": HistoryCodeImportStep,
		"export_history": HistoryCodeUnsupportedStep, "": HistoryCodeUnsupportedStep, "do_something": HistoryCodeUnsupportedStep,
	}
	for step, code := range steps {
		t.Run("step "+step, func(t *testing.T) {
			want(t, statusOf(func(h *HistoryObligations) { h.CompletionSteps = append(h.CompletionSteps, step) }), code)
		})
	}
	t.Run("allowed steps in any case", func(t *testing.T) {
		if r := statusOf(func(h *HistoryObligations) { h.CompletionSteps = []string{" RETAIN ", "Remind", "verify_read_only"} }); !r.Clear {
			t.Fatal(r.Blockers)
		}
	})
	t.Run("too many records", func(t *testing.T) {
		h := closureHistoryFixture(closureNow)
		h.CompletionSteps = make([]string, historyMaxItems+1)
		if _, err := HistoryStatus(context.Background(), h); err == nil {
			t.Fatal("accepted an unbounded plan")
		}
		h = closureHistoryFixture(closureNow)
		h.Access = make([]HistoryAccess, historyMaxItems+1)
		if _, err := HistoryStatus(context.Background(), h); err == nil {
			t.Fatal("accepted unbounded access")
		}
		h = closureHistoryFixture(closureNow)
		h.Obligations = make([]HistoryObligation, historyMaxItems+1)
		if _, err := HistoryStatus(context.Background(), h); err == nil {
			t.Fatal("accepted unbounded obligations")
		}
	})
	t.Run("call validation", func(t *testing.T) {
		for name, edit := range map[string]func(h *HistoryObligations){
			"no clock":   func(h *HistoryObligations) { h.Now = time.Time{} },
			"no bound":   func(h *HistoryObligations) { h.MaxEvidenceAgeSecs = 0 },
			"huge bound": func(h *HistoryObligations) { h.MaxEvidenceAgeSecs = 30*24*3600 + 1 },
		} {
			h := closureHistoryFixture(closureNow)
			edit(&h)
			if _, err := HistoryStatus(context.Background(), h); err == nil {
				t.Fatalf("%s accepted", name)
			}
		}
	})
}

func TestHistoryStatusObligations(t *testing.T) {
	now := closureNow
	done := func(o HistoryObligation) HistoryObligation {
		o.Completed, o.CompletedAt = true, now.Add(-time.Hour)
		o.AuthorizationDigest, o.AuditDigest = closureDig("authz"), closureDig("audit")
		return o
	}
	statusOf := func(edit func(h *HistoryObligations)) HistoryReport {
		h := closureHistoryFixture(now)
		edit(&h)
		r, err := HistoryStatus(context.Background(), h)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	has := func(r HistoryReport, c HistoryCode) bool {
		for _, b := range r.Blockers {
			if b == c {
				return true
			}
		}
		return false
	}
	t.Run("overdue per kind", func(t *testing.T) {
		for kind, code := range map[HistoryObligationKind]HistoryCode{HistoryKindRetention: HistoryCodeRetentionOverdue, HistoryKindExport: HistoryCodeExportOverdue, HistoryKindHold: HistoryCodeHoldOverdue} {
			r := statusOf(func(h *HistoryObligations) {
				h.Obligations = append(h.Obligations, HistoryObligation{Kind: HistoryKindHold, DueAt: now.Add(24 * time.Hour), RecordDigest: closureDig("hold"), ReminderLeadDays: 7})
				for i := range h.Obligations {
					if h.Obligations[i].Kind == kind {
						h.Obligations[i].DueAt = now.Add(-time.Second)
					}
				}
			})
			if !has(r, code) || r.Overdue != 1 || r.Open != 3 {
				t.Fatalf("%s: %+v", kind, r)
			}
			for _, st := range r.Obligations {
				if st.Kind == kind && st.State != HistoryStateOverdue {
					t.Fatalf("%s state %s", kind, st.State)
				}
			}
		}
	})
	t.Run("due exactly now is overdue; one second later is not", func(t *testing.T) {
		if r := statusOf(func(h *HistoryObligations) { h.Obligations[1].DueAt = now }); !has(r, HistoryCodeExportOverdue) {
			t.Fatal("due now must be overdue")
		}
		if r := statusOf(func(h *HistoryObligations) { h.Obligations[1].DueAt = now.Add(time.Second) }); !r.Clear {
			t.Fatal(r.Blockers)
		}
	})
	t.Run("missing records per kind", func(t *testing.T) {
		r := statusOf(func(h *HistoryObligations) { h.Obligations[0].RecordDigest = "" })
		if !has(r, HistoryCodeRecordMissing) || has(r, HistoryCodeExportRecordMissing) {
			t.Fatal(r.Blockers)
		}
		r = statusOf(func(h *HistoryObligations) { h.Obligations[1].RecordDigest = "export-1" })
		if !has(r, HistoryCodeExportRecordMissing) || has(r, HistoryCodeRecordMissing) {
			t.Fatal(r.Blockers)
		}
		r = statusOf(func(h *HistoryObligations) {
			h.Obligations = append(h.Obligations, HistoryObligation{Kind: HistoryKindHold, DueAt: now.Add(time.Hour), ReminderLeadDays: 1})
		})
		if !has(r, HistoryCodeRecordMissing) {
			t.Fatal("hold without record")
		}
	})
	t.Run("no export obligation reports both export blockers", func(t *testing.T) {
		r := statusOf(func(h *HistoryObligations) { h.Obligations = h.Obligations[:1] })
		if !has(r, HistoryCodeExportMissing) || !has(r, HistoryCodeExportRecordMissing) || has(r, HistoryCodeRetentionMissing) {
			t.Fatal(r.Blockers)
		}
	})
	t.Run("no obligations at all", func(t *testing.T) {
		r := statusOf(func(h *HistoryObligations) { h.Obligations = nil })
		if !has(r, HistoryCodeRetentionMissing) || !has(r, HistoryCodeExportMissing) {
			t.Fatal(r.Blockers)
		}
	})
	t.Run("due date missing", func(t *testing.T) {
		r := statusOf(func(h *HistoryObligations) { h.Obligations[0].DueAt = time.Time{} })
		if !has(r, HistoryCodeObligationInvalid) || r.Obligations[0].State != HistoryStateInvalid {
			t.Fatal(r.Blockers)
		}
	})
	t.Run("unknown kind", func(t *testing.T) {
		r := statusOf(func(h *HistoryObligations) {
			h.Obligations = append(h.Obligations, HistoryObligation{Kind: "deletion", DueAt: now.Add(time.Hour), RecordDigest: closureDig("x"), ReminderLeadDays: 1})
		})
		if !has(r, HistoryCodeObligationInvalid) || r.Open != 2 {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("duplicate retention or export, repeated holds fine", func(t *testing.T) {
		r := statusOf(func(h *HistoryObligations) { h.Obligations = append(h.Obligations, h.Obligations[0]) })
		if !has(r, HistoryCodeObligationDuplicate) {
			t.Fatal(r.Blockers)
		}
		r = statusOf(func(h *HistoryObligations) { h.Obligations = append(h.Obligations, h.Obligations[1]) })
		if !has(r, HistoryCodeObligationDuplicate) {
			t.Fatal(r.Blockers)
		}
		hold := HistoryObligation{Kind: HistoryKindHold, DueAt: now.Add(time.Hour), RecordDigest: closureDig("hold"), ReminderLeadDays: 1}
		if r = statusOf(func(h *HistoryObligations) { h.Obligations = append(h.Obligations, hold, hold) }); !r.Clear {
			t.Fatal(r.Blockers)
		}
	})
	t.Run("audited completion is accepted", func(t *testing.T) {
		r := statusOf(func(h *HistoryObligations) { h.Obligations[1] = done(h.Obligations[1]) })
		if !r.Clear || r.Completed != 1 || r.Open != 1 {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("completed overdue obligation is not overdue", func(t *testing.T) {
		r := statusOf(func(h *HistoryObligations) {
			h.Obligations[1].DueAt = now.Add(-48 * time.Hour)
			h.Obligations[1] = done(h.Obligations[1])
		})
		if !r.Clear || r.Overdue != 0 {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("completion needs authorization and audit digests", func(t *testing.T) {
		for name, edit := range map[string]func(o *HistoryObligation){
			"no authorization": func(o *HistoryObligation) { o.AuthorizationDigest = "" },
			"no audit":         func(o *HistoryObligation) { o.AuditDigest = "" },
		} {
			r := statusOf(func(h *HistoryObligations) {
				h.Obligations[1] = done(h.Obligations[1])
				edit(&h.Obligations[1])
			})
			if !has(r, HistoryCodeCompletionUnaudited) || r.Obligations[1].State != HistoryStateInvalid {
				t.Fatalf("%s: %v", name, r.Blockers)
			}
		}
	})
	t.Run("completion time must exist and not be in the future", func(t *testing.T) {
		for name, at := range map[string]time.Time{"zero": {}, "future": now.Add(time.Nanosecond)} {
			r := statusOf(func(h *HistoryObligations) {
				h.Obligations[1] = done(h.Obligations[1])
				h.Obligations[1].CompletedAt = at
			})
			if !has(r, HistoryCodeCompletionInvalid) {
				t.Fatalf("%s: %v", name, r.Blockers)
			}
		}
		if r := statusOf(func(h *HistoryObligations) {
			h.Obligations[1] = done(h.Obligations[1])
			h.Obligations[1].CompletedAt = now
		}); !r.Clear {
			t.Fatal("completion at the clock is fine")
		}
	})
	t.Run("a completion claim never hides a missing export record", func(t *testing.T) {
		r := statusOf(func(h *HistoryObligations) {
			h.Obligations[1] = done(h.Obligations[1])
			h.Obligations[1].RecordDigest = ""
		})
		if !has(r, HistoryCodeExportRecordMissing) {
			t.Fatal(r.Blockers)
		}
	})
	t.Run("reminders", func(t *testing.T) {
		for _, lead := range []int{0, -1, historyMaxReminder + 1} {
			if r := statusOf(func(h *HistoryObligations) { h.Obligations[0].ReminderLeadDays = lead }); !has(r, HistoryCodeReminderMissing) {
				t.Fatalf("lead %d: %v", lead, r.Blockers)
			}
		}
		if r := statusOf(func(h *HistoryObligations) { h.Obligations[0].ReminderLeadDays = historyMaxReminder }); has(r, HistoryCodeReminderMissing) {
			t.Fatal("max lead refused")
		}
		// Completed obligations need no reminder.
		if r := statusOf(func(h *HistoryObligations) {
			h.Obligations[1] = done(h.Obligations[1])
			h.Obligations[1].ReminderLeadDays = 0
		}); !r.Clear {
			t.Fatal(r.Blockers)
		}
		r := statusOf(func(h *HistoryObligations) {
			h.Obligations[0].DueAt, h.Obligations[0].ReminderLeadDays = now.Add(10*24*time.Hour), 10
			h.Obligations[1].DueAt, h.Obligations[1].ReminderLeadDays = now.Add(10*24*time.Hour+2*time.Hour), 9
		})
		if r.RemindersDue != 1 || !r.Obligations[0].ReminderDue || r.Obligations[1].ReminderDue || r.Obligations[0].DaysRemaining != 10 {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("digest is stable and covers the findings", func(t *testing.T) {
		a := statusOf(func(h *HistoryObligations) {})
		b := statusOf(func(h *HistoryObligations) {})
		if a.Digest != b.Digest || !historyDigestOK(a.Digest) {
			t.Fatal("unstable digest")
		}
		if c := statusOf(func(h *HistoryObligations) { h.Boundary.Visible = false }); c.Digest == a.Digest {
			t.Fatal("digest ignores findings")
		}
	})
}

func TestClosurePublicSummaryIsClosed(t *testing.T) {
	allowedStrings := map[string]bool{
		"EvaluatedDay": true, "GateVerifiedDay": true, "OutageDay": true, "GateDigest": true,
		"DeadmanProofDigest": true, "HistoryDigest": true, "EvidenceDigest": true, "Code": true,
	}
	var walk func(rt reflect.Type, path string)
	walk = func(rt reflect.Type, path string) {
		switch rt.Kind() {
		case reflect.Bool, reflect.Int:
		case reflect.String:
			last := path[strings.LastIndex(path, ".")+1:]
			if rt.Name() == "string" && !allowedStrings[last] {
				t.Fatalf("free string field %s", path)
			}
		case reflect.Slice:
			walk(rt.Elem(), path+"[]")
		case reflect.Struct:
			for i := range rt.NumField() {
				walk(rt.Field(i).Type, path+"."+rt.Field(i).Name)
			}
		default:
			t.Fatalf("unexpected kind %s at %s", rt.Kind(), path)
		}
	}
	walk(reflect.TypeOf(ClosurePublicSummary{}), "ClosurePublicSummary")
	walk(reflect.TypeOf(HistoryPublicSummary{}), "HistoryPublicSummary")

	canary := "CANARYlabel9f3a"
	l := closureLedgerFixture(t)
	l.Scope = "canaryscope.9f3a"
	l.Trust = map[string]ed25519.PublicKey{canary: closureTestKey("attestor").Public().(ed25519.PublicKey)}
	p := closureProofFixture(l.Now)
	p.Scope = l.Scope
	p.ProductDomain = ClosureFailureDomain{Process: canary + "p1", Host: canary + "h1", Cluster: canary + "c1", Credential: canary + "k1"}
	p.DeadmanDomain = ClosureFailureDomain{Process: canary + "p2", Host: canary + "h2", Cluster: canary + "c2", Credential: canary + "k2"}
	env, err := ClosureSignProof(closureTestKey("attestor"), canary, p)
	if err != nil {
		t.Fatal(err)
	}
	l.DeadmanProof = &env
	l.History.Access[0].ReaderKey = closureDig("reader-canary")
	l.Gate.VerifiedAt = time.Date(2026, 11, 9, 23, 59, 59, 999, time.UTC)
	closed := closureClose(t, l)
	if !closed.Closed {
		t.Fatalf("fixture must close: %v", closed.Blockers)
	}
	pub := ClosurePublicProjection(closed)
	raw, _ := json.Marshal(pub)
	text := string(raw)
	if strings.Contains(strings.ToLower(text), "canary") {
		t.Fatalf("evidence string copied: %s", text)
	}
	if regexp.MustCompile(`\d{2}:\d{2}|\dT\d`).MatchString(text) {
		t.Fatalf("time of day published: %s", text)
	}
	if !pub.Closed || pub.CustomerAcceptance || pub.GateVerifiedDay != "2026-11-09" || pub.EvaluatedDay != "2026-11-10" || pub.OutageDay != "2026-11-10" ||
		pub.CriteriaRequired != len(closureRequiredCriteria) || pub.CriteriaCovered != pub.CriteriaRequired || pub.JourneysRecovered != 3 ||
		!pub.DeadmanIndependent || !pub.DeliveryInOutage || !pub.HistoryReadInOutage || !pub.HistoryClear || pub.ObligationsOpen != 2 ||
		pub.GateDigest != l.Gate.Digest || !historyDigestOK(pub.DeadmanProofDigest) || !historyDigestOK(pub.HistoryDigest) || !historyDigestOK(pub.EvidenceDigest) || len(pub.Blockers) != 0 {
		t.Fatalf("summary %+v", pub)
	}
	if !strings.Contains(text, `"customer_acceptance":false`) {
		t.Fatalf("customer_acceptance must always be present and false: %s", text)
	}
	// Day granularity is a UTC calendar day, not a rounded instant.
	if d := historyDay(time.Date(2026, 11, 10, 1, 0, 0, 0, time.FixedZone("x", 3*3600))); d != "2026-11-09" || historyDay(time.Time{}) != "" {
		t.Fatalf("day %q", d)
	}

	blocked := l
	blocked.DeadmanProof = nil
	br := closureClose(t, blocked)
	bp := ClosurePublicProjection(br)
	if bp.Closed || bp.EvidenceDigest != "" || bp.CustomerAcceptance || bp.DeadmanIndependent || bp.OutageDay != "" || bp.DeadmanProofDigest != "" || len(bp.Blockers) != 1 || bp.Blockers[0] != (ClosurePublicBlocker{Area: ClosureAreaDeadman, Code: string(ClosureCodeProofMissing)}) {
		t.Fatalf("blocked summary %+v", bp)
	}

	// Smuggled values never reach the public shape; an inconsistent report is not "closed".
	forged := closed
	forged.Blockers = []ClosureBlocker{{Area: ClosureAreaGate, Code: canary}, {Area: ClosureArea("free text " + canary), Code: string(ClosureCodeProofMissing)}, {Area: ClosureAreaHistory, Code: string(ClosureCodeProofMissing)}, {Area: ClosureAreaGate, Code: string(HistoryCodeWriteAccess)}}
	forged.GateDigest, forged.ProofDigest, forged.History.Digest = canary, canary, canary
	fp := ClosurePublicProjection(forged)
	if fp.Closed || len(fp.Blockers) != 0 || fp.GateDigest != "" || fp.DeadmanProofDigest != "" || fp.HistoryDigest != "" {
		t.Fatalf("forged report leaked: %+v", fp)
	}
	forged = closed
	forged.EvidenceDigest = ""
	if ClosurePublicProjection(forged).Closed {
		t.Fatal("closed without an evidence digest")
	}
	forged = closed
	forged.Blockers = []ClosureBlocker{{Area: ClosureAreaDeadman, Code: string(ClosureCodeProofMissing)}}
	if ClosurePublicProjection(forged).Closed {
		t.Fatal("closed with a blocker")
	}

	noBoundary := closureLedgerFixture(t)
	noBoundary.History.Boundary = nil
	hist := closureClose(t, noBoundary).History
	hp := HistoryPublicProjection(hist)
	hraw, _ := json.Marshal(hp)
	if hp.Clear || hp.CustomerAcceptance || len(hp.Blockers) != 1 || hp.Blockers[0] != HistoryCodeBoundaryMissing || !strings.Contains(string(hraw), `"customer_acceptance":false`) {
		t.Fatalf("history summary %s", hraw)
	}
	hist.Blockers = append(hist.Blockers, HistoryCode("free text "+canary))
	if hp = HistoryPublicProjection(hist); len(hp.Blockers) != 1 {
		t.Fatalf("unknown history code published: %v", hp.Blockers)
	}
	hist.Blockers, hist.Clear = nil, true
	hist.Open, hist.Overdue, hist.Completed = 4, 1, 2
	if hp = HistoryPublicProjection(hist); !hp.Clear || hp.ObligationsOpen != 4 || hp.ObligationsOverdue != 1 || hp.ObligationsDone != 2 {
		t.Fatalf("%+v", hp)
	}
	// A report that claims clear while carrying only an unknown code is not clear.
	hist.Blockers, hist.Clear = []HistoryCode{HistoryCode("free text " + canary)}, true
	if hp = HistoryPublicProjection(hist); hp.Clear || len(hp.Blockers) != 0 {
		t.Fatalf("%+v", hp)
	}
	hist.Blockers, hist.Clear = nil, false
	if HistoryPublicProjection(hist).Clear {
		t.Fatal("not clear stays not clear")
	}
}

// The tool has no code path that removes, exports or imports anything: the two
// files import no filesystem-mutating, process or network packages and call no
// function whose name removes or renames.
func TestClosureHasNoDeletionOrExportCodePath(t *testing.T) {
	forbiddenImports := map[string]bool{"os": true, "os/exec": true, "net": true, "net/http": true, "syscall": true, "io/fs": true, "database/sql": true}
	forbiddenCalls := regexp.MustCompile(`(?i)^(remove|removeall|delete|unlink|truncate|rename|chmod|chown|mkdir|mkdirall|create|writefile|openfile|symlink|link|trash)$`)
	for _, name := range []string{"history.go", "closure.go"} {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if forbiddenImports[path] {
				t.Errorf("%s imports %s", name, path)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && forbiddenCalls.MatchString(sel.Sel.Name) {
				t.Errorf("%s uses %s", name, sel.Sel.Name)
			}
			if fn, ok := n.(*ast.FuncDecl); ok && forbiddenCalls.MatchString(fn.Name.Name) {
				t.Errorf("%s declares %s", name, fn.Name.Name)
			}
			return true
		})
	}
}

func closureCLIFixture(t *testing.T, now time.Time) (ledger, trust, private, summary string) {
	t.Helper()
	l := closureLedgerFixture(t)
	l.Now = now
	l.Gate.VerifiedAt = now.Add(-time.Hour)
	l.History = closureHistoryFixture(now)
	l.DeadmanProof = closureSign(t, closureProofFixture(now))
	inputs := t.TempDir()
	ledger, trust, summary = filepath.Join(inputs, "ledger.json"), filepath.Join(inputs, "trust.json"), filepath.Join(inputs, "public.json")
	if err := writeExclusive(ledger, l); err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(trust, ClosureTrust{Keys: l.Trust}); err != nil {
		t.Fatal(err)
	}
	return ledger, trust, privateTempDir(t), summary
}

func TestClosureCLIWritesPrivateReportAndClosedSummary(t *testing.T) {
	ledger, trust, private, summary := closureCLIFixture(t, time.Now().UTC())
	args := []string{"--mode", "close", "--ledger", ledger, "--trusted-keys", trust, "--private-output", private, "--public-summary", summary, "--private-directory-acl-confirmed"}
	if err := runClosure(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	var pub ClosurePublicSummary
	if err := readInput(summary, &pub); err != nil || !pub.Closed || pub.CustomerAcceptance || pub.JourneysRecovered != 3 {
		t.Fatalf("summary: %v %+v", err, pub)
	}
	var priv ClosureReport
	if err := readInput(filepath.Join(private, "closure.json"), &priv); err != nil || !priv.Closed || !priv.History.Clear {
		t.Fatalf("private: %v %+v", err, priv.Closed)
	}
	if err := runClosure(context.Background(), args); err == nil {
		t.Fatal("overwrote previous evidence")
	}
}

func TestClosureCLIBlockedDecisionIsNonzeroButWritesEvidence(t *testing.T) {
	ledger, trust, private, summary := closureCLIFixture(t, time.Now().UTC())
	// The operator trusts a different key than the one that signed the proof.
	if err := os.Remove(trust); err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(trust, ClosureTrust{Keys: map[string]ed25519.PublicKey{closureTestKeyID: closureTestKey("someone-else").Public().(ed25519.PublicKey)}}); err != nil {
		t.Fatal(err)
	}
	args := []string{"--mode", "close", "--ledger", ledger, "--trusted-keys", trust, "--private-output", private, "--public-summary", summary, "--private-directory-acl-confirmed"}
	if err := runClosure(context.Background(), args); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("a blocked closure must be an error: %v", err)
	}
	var pub ClosurePublicSummary
	if err := readInput(summary, &pub); err != nil || pub.Closed || len(pub.Blockers) != 1 || pub.Blockers[0].Code != string(ClosureCodeProofBadSignature) {
		t.Fatalf("summary: %v %+v", err, pub)
	}
	var priv ClosureReport
	if err := readInput(filepath.Join(private, "closure.json"), &priv); err != nil || priv.Closed {
		t.Fatalf("private: %v", err)
	}
}

func TestClosureCLIHistoryModeAndUsage(t *testing.T) {
	inputs, private := t.TempDir(), privateTempDir(t)
	h := closureHistoryFixture(time.Now().UTC())
	hPath, summary := filepath.Join(inputs, "history.json"), filepath.Join(inputs, "public.json")
	if err := writeExclusive(hPath, h); err != nil {
		t.Fatal(err)
	}
	args := []string{"--mode", "history", "--ledger", hPath, "--private-output", private, "--public-summary", summary, "--private-directory-acl-confirmed"}
	if err := runClosure(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	var pub HistoryPublicSummary
	if err := readInput(summary, &pub); err != nil || !pub.Clear || pub.CustomerAcceptance || pub.ActiveReaders != 1 {
		t.Fatalf("%v %+v", err, pub)
	}
	if _, err := os.Stat(filepath.Join(private, "history.json")); err != nil {
		t.Fatal(err)
	}
	// A blocked history is non-zero and still recorded.
	h.Boundary.Visible = false
	hPath2, summary2, private2 := filepath.Join(inputs, "history2.json"), filepath.Join(inputs, "public2.json"), privateTempDir(t)
	if err := writeExclusive(hPath2, h); err != nil {
		t.Fatal(err)
	}
	args2 := []string{"--mode", "history", "--ledger", hPath2, "--private-output", private2, "--public-summary", summary2, "--private-directory-acl-confirmed"}
	if err := runClosure(context.Background(), args2); err == nil {
		t.Fatal("a blocked history must be an error")
	}
	if err := readInput(summary2, &pub); err != nil || pub.Clear || len(pub.Blockers) != 1 {
		t.Fatalf("%v %+v", err, pub)
	}
	usage := []struct {
		name string
		args func(out string) []string
		want string
	}{
		{"no mode", func(out string) []string {
			return []string{"--ledger", hPath, "--private-output", out, "--public-summary", filepath.Join(inputs, "a.json")}
		}, "usage"},
		{"unknown mode", func(out string) []string {
			return []string{"--mode", "delete", "--ledger", hPath, "--private-output", out, "--public-summary", filepath.Join(inputs, "b.json")}
		}, "usage"},
		{"unknown mode with trust", func(out string) []string {
			return []string{"--mode", "delete", "--ledger", hPath, "--trusted-keys", hPath, "--private-output", out, "--public-summary", filepath.Join(inputs, "b2.json")}
		}, "usage"},
		{"close without trust", func(out string) []string {
			return []string{"--mode", "close", "--ledger", hPath, "--private-output", out, "--public-summary", filepath.Join(inputs, "c.json")}
		}, "trusted-keys"},
		{"history with trust", func(out string) []string {
			return []string{"--mode", "history", "--ledger", hPath, "--trusted-keys", hPath, "--private-output", out, "--public-summary", filepath.Join(inputs, "d.json")}
		}, "trusted-keys"},
		{"no ledger", func(out string) []string {
			return []string{"--mode", "history", "--private-output", out, "--public-summary", filepath.Join(inputs, "e.json")}
		}, "usage"},
		{"stray argument", func(out string) []string {
			return append([]string{"--mode", "history", "--ledger", hPath, "--private-output", out, "--public-summary", filepath.Join(inputs, "s.json")}, "extra")
		}, "usage"},
		{"timeout over an hour", func(out string) []string {
			return []string{"--mode", "history", "--ledger", hPath, "--private-output", out, "--public-summary", filepath.Join(inputs, "f.json"), "--timeout", "2h"}
		}, "timeout"},
		{"timeout just over an hour", func(out string) []string {
			return []string{"--mode", "history", "--ledger", hPath, "--private-output", out, "--public-summary", filepath.Join(inputs, "f2.json"), "--timeout", "61m"}
		}, "timeout"},
		{"zero timeout", func(out string) []string {
			return []string{"--mode", "history", "--ledger", hPath, "--private-output", out, "--public-summary", filepath.Join(inputs, "f3.json"), "--timeout", "0s"}
		}, "timeout"},
		{"negative timeout", func(out string) []string {
			return []string{"--mode", "history", "--ledger", hPath, "--private-output", out, "--public-summary", filepath.Join(inputs, "f4.json"), "--timeout", "-1s"}
		}, "timeout"},
		{"private output required", func(out string) []string {
			return []string{"--mode", "history", "--ledger", hPath, "--public-summary", filepath.Join(inputs, "g.json")}
		}, "usage"},
		{"unknown flag", func(out string) []string {
			return []string{"--mode", "history", "--now", "2030-01-01T00:00:00Z", "--ledger", hPath, "--private-output", out, "--public-summary", filepath.Join(inputs, "h.json")}
		}, "not defined"},
	}
	for _, u := range usage {
		out := privateTempDir(t)
		err := runClosure(context.Background(), u.args(out))
		if err == nil || !strings.Contains(err.Error(), u.want) {
			t.Fatalf("%s: error %v, want it to mention %q", u.name, err, u.want)
		}
		if entries, _ := os.ReadDir(out); len(entries) != 0 {
			t.Fatalf("%s wrote private output", u.name)
		}
	}
	// The ledger file cannot supply its own clock or trust root.
	for _, field := range []string{`"now":"2030-01-01T00:00:00Z"`, `"trust":{}`, `"Trust":{}`, `"Now":"2030-01-01T00:00:00Z"`} {
		raw := `{"scope":"adoption-closure/synthetic","max_evidence_age_seconds":3600,` + field + `}`
		path := filepath.Join(inputs, "smuggle.json")
		_ = os.Remove(path)
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		var l ClosureLedger
		if readInput(path, &l) == nil {
			t.Fatalf("ledger file supplied %s", field)
		}
	}
	// Private evidence must stay out of the repository.
	cwd, _ := os.Getwd()
	if err := runClosure(context.Background(), []string{"--mode", "history", "--ledger", hPath, "--private-output", cwd, "--public-summary", filepath.Join(inputs, "i.json"), "--private-directory-acl-confirmed"}); err == nil {
		t.Fatal("private output inside the checkout accepted")
	}
}

func TestHistoryDigestFormat(t *testing.T) {
	ok := strings.Repeat("0123456789abcdef", 4)
	if !historyDigestOK(ok) {
		t.Fatal("valid digest refused")
	}
	for name, s := range map[string]string{
		"empty": "", "short": ok[:63], "long": ok + "a", "upper case": strings.ToUpper(ok),
		"non hex g": ok[:63] + "g", "non hex z": "z" + ok[1:], "space": ok[:63] + " ", "prefix": "0x" + ok[2:],
	} {
		if historyDigestOK(s) {
			t.Fatalf("%s accepted", name)
		}
	}
	for _, c := range "0123456789abcdef" {
		if !historyDigestOK(strings.Repeat(string(c), 64)) {
			t.Fatalf("%c refused", c)
		}
	}
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// appendN appends n one-record metric batches with distinct timestamps starting at base.
func (x *eraseEnv) appendN(n, base int) []model.Receipt {
	x.t.Helper()
	var out []model.Receipt
	for i := range n {
		_, r, _ := x.appendRecords(model.NewID(), metricRetention, x.metric("verified_series", model.UnixNano(base+i)))
		out = append(out, r)
	}
	return out
}

func (x *eraseEnv) closeEngine() {
	x.t.Helper()
	if err := x.e.Close(); err != nil {
		x.t.Fatal(err)
	}
}

func (x *eraseEnv) open() (*Engine, error) {
	x.t.Helper()
	e, err := openTestEngine(x.t, x.dir, x.a, x.store)
	if err == nil {
		x.e = e
	}
	return e, err
}

func (x *eraseEnv) recordPath() string { return filepath.Join(x.dir, verifiedRecordName) }

func totalApplied(e *Engine) uint64 {
	var total uint64
	for slot := range uint16(64) {
		total += e.indexes[slot]
	}
	return total
}

// editIndex breaks the CRC of every scan_time entry written by the command of receipt.
func editIndex(t *testing.T, dir string, receipt model.Receipt) {
	t.Helper()
	db, err := bolt.Open(filepath.Join(dir, "apply.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hit := 0
	if err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range logicalBuckets(tx, "scan_time") {
			var keys [][]byte
			_ = b.ForEach(func(k, v []byte) error {
				if len(k) >= 26 && binary.BigEndian.Uint64(k[len(k)-10:len(k)-2]) == uint64(receipt.Cursor.Index) && bytes.Equal(k[len(k)-26:len(k)-10], receipt.Cursor.Group[:]) {
					keys = append(keys, bytes.Clone(k))
				}
				return nil
			})
			for _, k := range keys {
				v := bytes.Clone(b.Get(k))
				v[len(v)-1] ^= 0xff
				if err := b.Put(k, v); err != nil {
					return err
				}
				hit++
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if hit == 0 {
		t.Fatal("no index entry found for the receipt")
	}
}

func flipSegmentByte(t *testing.T, e *Engine) {
	t.Helper()
	e.mu.Lock()
	segments := e.catalog.Manifest.Segments
	e.mu.Unlock()
	if len(segments) == 0 {
		t.Fatal("no segment")
	}
	path, err := segmentPath(e.dir, segments[0].File)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 0xff
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func rewriteRecord(t *testing.T, x *eraseEnv, edit func(*verifiedRecord)) {
	t.Helper()
	raw, err := os.ReadFile(x.recordPath())
	if err != nil {
		t.Fatal(err)
	}
	rec, err := decodeVerifiedRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	edit(rec)
	out, err := rec.encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(x.recordPath(), out, 0600); err != nil {
		t.Fatal(err)
	}
}

func isCorruptFault(err error) bool {
	var fault *model.Fault
	return errors.As(err, &fault) && fault.Code == model.Corrupt
}

// closeEngineWithoutAdvance closes the engine as a close does whose advance of the verified point did not finish (budget 0), or a crash:
// the commands applied since the last verification are the tail the next start verifies. A graceful close advances the point itself
// (verifyAtClose), so a test about the tail cannot use closeEngine.
func (x *eraseEnv) closeEngineWithoutAdvance() {
	oldBudget := closeVerifyBudget
	closeVerifyBudget = 0
	defer func() { closeVerifyBudget = oldBudget }()
	x.closeEngine()
}

// A valid record turns the next start into a tail-only verification: nothing is hashed, only the
// commands above the verified point are looked up.
func TestVerifiedRecordBoundsRestart(t *testing.T) {
	x := newEraseEnv(t)
	x.appendN(6, 100)
	if err := x.e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	x.closeEngine()
	if _, err := x.open(); err != nil { // verifies the six commands, records them
		t.Fatal(err)
	}
	if v := x.e.StartupVerification(); v.Full {
		t.Fatalf("first reopen after a flush was a full verification: %+v", v)
	}
	x.appendN(2, 200)
	x.closeEngineWithoutAdvance()
	if _, err := x.open(); err != nil {
		t.Fatal(err)
	}
	v := x.e.StartupVerification()
	if v.Full || v.SegmentsHashed != 0 || v.Commands == 0 || v.Commands >= 2*totalApplied(x.e) {
		t.Fatalf("not a bounded tail verification: %+v (applied %d)", v, totalApplied(x.e))
	}
	x.closeEngine()
	if _, err := x.open(); err != nil {
		t.Fatal(err)
	}
	if v = x.e.StartupVerification(); v.Full || v.Commands != 0 || v.SegmentsHashed != 0 {
		t.Fatalf("a restart with no new writes still verified history: %+v", v)
	}
}

// D15 (1): a missing, corrupt, foreign or wrongly bound record forces full verification.
func TestVerifiedRecordUnusableForcesFullVerification(t *testing.T) {
	cases := []struct {
		name, reason string
		damage       func(t *testing.T, x *eraseEnv)
	}{
		{"missing", "missing", func(t *testing.T, x *eraseEnv) {
			if err := os.Remove(x.recordPath()); err != nil {
				t.Fatal(err)
			}
		}},
		{"corrupt", "corrupt", func(t *testing.T, x *eraseEnv) {
			raw, err := os.ReadFile(x.recordPath())
			if err != nil {
				t.Fatal(err)
			}
			// Change one hex digit of a group id: still valid JSON, so only the checksum
			// can tell the record was damaged.
			at := bytes.Index(raw, []byte(`"group":"`)) + len(`"group":"`)
			if at < len(`"group":"`) {
				t.Fatal("record has no group id")
			}
			for ; raw[at] < '0' || raw[at] > '8'; at++ {
			}
			raw[at]++
			if err = os.WriteFile(x.recordPath(), raw, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"truncated", "corrupt", func(t *testing.T, x *eraseEnv) {
			if err := os.WriteFile(x.recordPath(), []byte("SPVR"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"unreadable", "unreadable", func(t *testing.T, x *eraseEnv) {
			if err := os.Remove(x.recordPath()); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(x.recordPath(), 0700); err != nil { // a directory cannot be read as a file
				t.Fatal(err)
			}
		}},
		{"foreign manifest digest", "manifest digest differs", func(t *testing.T, x *eraseEnv) {
			rewriteRecord(t, x, func(r *verifiedRecord) { r.ManifestDigest[0] ^= 1 })
		}},
		{"foreign identity", "foreign", func(t *testing.T, x *eraseEnv) {
			rewriteRecord(t, x, func(r *verifiedRecord) { r.Identity[0] ^= 1 })
		}},
		{"foreign group ids", "foreign", func(t *testing.T, x *eraseEnv) {
			rewriteRecord(t, x, func(r *verifiedRecord) { r.Groups[3].Group[0] ^= 1 })
		}},
		{"foreign format", "corrupt", func(t *testing.T, x *eraseEnv) {
			rewriteRecord(t, x, func(r *verifiedRecord) { r.Format = 2 })
		}},
		{"ahead of the database", "inconsistent with the apply database", func(t *testing.T, x *eraseEnv) {
			rewriteRecord(t, x, func(r *verifiedRecord) {
				for i := range r.Groups {
					r.Groups[i].Applied += 5
				}
			})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newEraseEnv(t)
			x.appendN(5, 100)
			x.closeEngine()
			if _, err := x.open(); err != nil {
				t.Fatal(err)
			}
			x.closeEngine()
			c.damage(t, x)
			if _, err := x.open(); err != nil {
				t.Fatalf("a bad record must force verification, not refuse to start: %v", err)
			}
			v := x.e.StartupVerification()
			if !v.Full || v.Reason != c.reason || v.Commands < totalApplied(x.e) {
				t.Fatalf("want full verification (%s), got %+v (applied %d)", c.reason, v, totalApplied(x.e))
			}
		})
	}
}

// A manifest publication rebinds the record, so a flushed node still restarts bounded.
func TestVerifiedRecordFollowsPublication(t *testing.T) {
	x := newEraseEnv(t)
	x.appendN(4, 100)
	x.closeEngine()
	if _, err := x.open(); err != nil {
		t.Fatal(err)
	}
	if err := x.e.Flush(context.Background()); err != nil { // publishes a manifest with a new segment
		t.Fatal(err)
	}
	x.closeEngine()
	if _, err := x.open(); err != nil {
		t.Fatal(err)
	}
	if v := x.e.StartupVerification(); v.Full || v.SegmentsHashed != 0 {
		t.Fatalf("publication left the record unbound or its segments unverified: %+v", v)
	}
}

// slotOf returns the slot whose group the receipt belongs to.
func slotOf(t *testing.T, e *Engine, r model.Receipt) uint16 {
	t.Helper()
	for s := range uint16(64) {
		if e.group(s) == r.Cursor.Group {
			return s
		}
	}
	t.Fatal("receipt group is not one of the engine's groups")
	return 0
}

func editDB(t *testing.T, dir string, edit func(tx *bolt.Tx) error) {
	t.Helper()
	db, err := bolt.Open(filepath.Join(dir, "apply.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Update(edit); err != nil {
		t.Fatal(err)
	}
}

// entriesOf lists the scan_time keys written by the command of receipt.
func entriesOf(b logicalBucket, receipt model.Receipt) [][]byte {
	var keys [][]byte
	_ = b.ForEach(func(k, v []byte) error {
		if len(k) >= 26 && binary.BigEndian.Uint64(k[len(k)-10:len(k)-2]) == uint64(receipt.Cursor.Index) && bytes.Equal(k[len(k)-26:len(k)-10], receipt.Cursor.Group[:]) {
			keys = append(keys, bytes.Clone(k))
		}
		return nil
	})
	return keys
}

// D15: corruption in what was written since the verified point is never served: Open itself
// (not the background pass, which is held back) refuses every one of these.
func TestCorruptionInUnverifiedTailNeverReady(t *testing.T) {
	cases := []struct {
		name   string
		damage func(t *testing.T, x *eraseEnv, tail model.Receipt)
	}{
		{"index entry CRC", func(t *testing.T, x *eraseEnv, tail model.Receipt) { editIndex(t, x.dir, tail) }},
		{"index entry missing", func(t *testing.T, x *eraseEnv, tail model.Receipt) {
			editDB(t, x.dir, func(tx *bolt.Tx) error {
				for _, b := range logicalBuckets(tx, "scan_time") {
					if keys := entriesOf(b, tail); len(keys) > 0 {
						return b.Delete(keys[0])
					}
				}
				t.Fatal("no entry")
				return nil
			})
		}},
		{"hot page bytes", func(t *testing.T, x *eraseEnv, tail model.Receipt) {
			editDB(t, x.dir, func(tx *bolt.Tx) error {
				var ids []committedPage
				if err := json.Unmarshal(logicalGet(tx, "scan_commits", commitKey(tail.Cursor)), &ids); err != nil || len(ids) == 0 {
					t.Fatalf("commit entry: %v", err)
				}
				ref, err := parsePageRef(logicalGet(tx, "scan_pages", ids[0].ID[:]))
				if err == nil && len(ref.Hot) == 0 && isPayloadRef(ref.Log) { // the hot page is a record of the payload log: damage its bytes there
					seq, off, n, _, _ := parsePayloadRef(ref.Log)
					f, ferr := os.OpenFile(filepath.Join(x.dir, payloadDirName, payloadFileName(seq)), os.O_RDWR, 0)
					if ferr != nil {
						t.Fatal(ferr)
					}
					defer f.Close()
					at := off + payloadHeaderLen + int64(n/2)
					var b [1]byte
					if _, ferr = f.ReadAt(b[:], at); ferr != nil {
						t.Fatal(ferr)
					}
					b[0] ^= 0xff
					if _, ferr = f.WriteAt(b[:], at); ferr != nil {
						t.Fatal(ferr)
					}
					return nil
				}
				if err != nil || len(ref.Hot) == 0 {
					t.Fatalf("page is not hot: %v", err)
				}
				ref.Hot = bytes.Clone(ref.Hot)
				ref.Hot[len(ref.Hot)/2] ^= 0xff
				raw, err := pageRefBytes(ref)
				if err != nil {
					return err
				}
				return bucketHolding(tx, "scan_pages", ids[0].ID[:]).Put(ids[0].ID[:], raw)
			})
		}},
		{"command missing", func(t *testing.T, x *eraseEnv, tail model.Receipt) {
			slot := slotOf(t, x.e, tail)
			editDB(t, x.dir, func(tx *bolt.Tx) error {
				return tx.Bucket([]byte("replica_commands")).Delete(commandKey(slot, uint64(tail.Cursor.Index)))
			})
		}},
		{"command above the applied index", func(t *testing.T, x *eraseEnv, tail model.Receipt) {
			slot := slotOf(t, x.e, tail)
			editDB(t, x.dir, func(tx *bolt.Tx) error {
				return tx.Bucket([]byte("replica_commands")).Put(commandKey(slot, uint64(tail.Cursor.Index)+1), []byte("{}"))
			})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Hold the background pass: Open, not the pass, must refuse the damaged tail.
			verifyGate = make(chan struct{})
			t.Cleanup(func() { verifyGate = nil })
			x := newEraseEnv(t)
			x.appendN(3, 100)
			x.closeEngine()
			if _, err := x.open(); err != nil { // verified point: three commands
				t.Fatal(err)
			}
			tail := x.appendN(1, 300)
			x.closeEngineWithoutAdvance() // what a crash leaves; a graceful close would verify (and so cover) the tail
			c.damage(t, x, tail[0])
			e, err := Open(x.dir, x.a)
			if err == nil {
				e.Close()
				t.Fatal("Open succeeded on damage above the verified point")
			}
			if !isCorruptFault(err) {
				t.Fatalf("want a corruption fault, got %v", err)
			}
		})
	}
}

// The same damage below the verified point is not examined before readiness (D15's weaker
// guarantee, stated in docs/operations/recovery.md); the full pass catches it.
func TestCorruptionBelowVerifiedPointCaughtByFullPass(t *testing.T) {
	verifyGate = make(chan struct{})
	t.Cleanup(func() { verifyGate = nil })
	x := newEraseEnv(t)
	old := x.appendN(3, 100)
	x.closeEngine()
	if _, err := x.open(); err != nil {
		t.Fatal(err)
	}
	x.closeEngine()
	editIndex(t, x.dir, old[0])
	e, err := Open(x.dir, x.a)
	if err != nil {
		t.Fatalf("damage below the verified point should be left to the background pass: %v", err)
	}
	defer e.Close()
	if err = e.VerifyFull(context.Background()); !isCorruptFault(err) {
		t.Fatalf("the full pass must catch the damaged old index entry: %v", err)
	}
	if e.VerifyFailure() == nil {
		t.Fatal("no typed failure recorded")
	}
}

// D15 (3): bit rot in an old, already verified segment lets the node start, and the background
// pass then fails it closed.
func TestBitRotInVerifiedSegmentCaughtByBackgroundPass(t *testing.T) {
	gate := make(chan struct{})
	verifyGate = gate
	t.Cleanup(func() { verifyGate = nil })
	x := newEraseEnv(t)
	x.appendN(4, 100)
	if err := x.e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	x.closeEngine()
	if _, err := x.open(); err != nil { // records the segment as verified
		t.Fatal(err)
	}
	x.closeEngine()
	flipSegmentByte(t, x.e)
	if _, err := x.open(); err != nil {
		t.Fatalf("bit rot below the verified point must not block readiness: %v", err)
	}
	if v := x.e.StartupVerification(); v.Full || v.SegmentsHashed != 0 {
		t.Fatalf("startup re-hashed the verified segment: %+v", v)
	}
	if x.e.VerifyFailure() != nil {
		t.Fatal("failed before the background pass ran")
	}
	close(gate)
	deadline := time.Now().Add(20 * time.Second)
	for x.e.VerifyFailure() == nil {
		if time.Now().After(deadline) {
			t.Fatal("background verification never noticed the corrupt segment")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !isCorruptFault(x.e.VerifyFailure()) {
		t.Fatalf("not a typed corruption fault: %v", x.e.VerifyFailure())
	}
	if err := x.e.Flush(context.Background()); err == nil {
		t.Fatal("a failed-closed engine still accepts maintenance")
	}
	if _, err := os.Stat(x.recordPath()); err == nil {
		t.Fatal("the record survived a failed verification; the next start would trust it")
	}
	x.closeEngine()
	if e, err := x.open(); err == nil {
		e.Close()
		t.Fatal("the node restarted into the corrupt segment without a full verification")
	}
}

// The pass repeats: damage that appears while the node runs is caught by a later pass.
func TestBackgroundVerificationRepeats(t *testing.T) {
	old := verifyInterval
	verifyInterval = 30 * time.Millisecond
	t.Cleanup(func() { verifyInterval = old })
	x := newEraseEnv(t)
	x.appendN(4, 100)
	if err := x.e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	x.closeEngine()
	if _, err := x.open(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // several clean passes
	if x.e.VerifyFailure() != nil {
		t.Fatalf("clean node failed verification: %v", x.e.VerifyFailure())
	}
	flipSegmentByte(t, x.e)
	deadline := time.Now().Add(20 * time.Second)
	for x.e.VerifyFailure() == nil {
		if time.Now().After(deadline) {
			t.Fatal("a repeated pass never noticed bit rot that appeared while running")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A clean node passes the full verification and records the point.
func TestVerifyFullRecordsPoint(t *testing.T) {
	x := newEraseEnv(t)
	x.appendN(3, 100)
	if err := os.Remove(x.recordPath()); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := x.e.VerifyFull(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(x.recordPath())
	if err != nil {
		t.Fatal(err)
	}
	rec, err := decodeVerifiedRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	var recorded uint64
	for _, g := range rec.Groups {
		recorded += uint64(g.Applied)
	}
	if recorded != totalApplied(x.e) || recorded < 3 {
		t.Fatalf("recorded %d, applied %d", recorded, totalApplied(x.e))
	}
}

// Startup cost does not depend on history: after 30 or 240 commands the bounded start does the
// same work, while a full verification grows with them. Wall-clock times are reported; the
// assertion is on the work counters (a timing assertion would be flaky).
func TestStartupCostIndependentOfHistory(t *testing.T) {
	type sample struct {
		fast, full         StartupVerification
		fastOpen, fullOpen time.Duration
	}
	run := func(n int) sample {
		x := newEraseEnv(t)
		x.appendN(n, 100)
		if err := x.e.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
		x.closeEngine()
		if _, err := x.open(); err != nil { // verifies and records the n commands
			t.Fatal(err)
		}
		x.closeEngine()
		var s sample
		timed := func() (StartupVerification, time.Duration) {
			began := time.Now()
			e, err := Open(x.dir, x.a)
			took := time.Since(began)
			if err != nil {
				t.Fatal(err)
			}
			v := e.StartupVerification()
			if err = e.Close(); err != nil {
				t.Fatal(err)
			}
			return v, took
		}
		s.fast, s.fastOpen = timed()
		if err := os.Remove(x.recordPath()); err != nil {
			t.Fatal(err)
		}
		s.full, s.fullOpen = timed()
		return s
	}
	smallN, largeN := 30, 240
	if raw := os.Getenv("SOUNDPOST_STARTUP_BOUNDED_N"); raw != "" { // "small,large", for a longer measurement
		if _, err := fmt.Sscanf(raw, "%d,%d", &smallN, &largeN); err != nil || smallN <= 0 || largeN <= smallN {
			t.Fatalf("SOUNDPOST_STARTUP_BOUNDED_N=%q: want small,large", raw)
		}
	}
	small, large := run(smallN), run(largeN)
	t.Logf("history %d: bounded Open %v %+v ; full Open %v %+v", smallN, small.fastOpen, small.fast, small.fullOpen, small.full)
	t.Logf("history %d: bounded Open %v %+v ; full Open %v %+v", largeN, large.fastOpen, large.fast, large.fullOpen, large.full)
	if small.fast.Full || large.fast.Full {
		t.Fatal("bounded runs fell back to full verification")
	}
	if small.fast.Commands != large.fast.Commands || small.fast.SegmentsHashed != large.fast.SegmentsHashed || small.fast.IndexEntries != large.fast.IndexEntries {
		t.Fatalf("bounded startup work depends on history: %+v vs %+v", small.fast, large.fast)
	}
	if !large.full.Full || small.full.Commands < uint64(smallN) || large.full.Commands < uint64(largeN) || large.full.SegmentsHashed == 0 {
		t.Fatalf("full verification should scale with history: %+v vs %+v", small.full, large.full)
	}
}

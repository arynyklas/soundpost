//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"github.com/arynyklas/soundpost/internal/model"
	"golang.org/x/sys/unix"
)

// residentBytes is how much of the file the page cache holds (mincore of a shared read mapping, which touches no page).
func residentBytes(t *testing.T, path string) int64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() == 0 {
		return 0
	}
	m, err := unix.Mmap(int(f.Fd()), 0, int(fi.Size()), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(m)
	ps := os.Getpagesize()
	vec := make([]byte, (int(fi.Size())+ps-1)/ps)
	if _, _, errno := unix.Syscall(unix.SYS_MINCORE, uintptr(unsafe.Pointer(&m[0])), uintptr(len(m)), uintptr(unsafe.Pointer(&vec[0]))); errno != 0 {
		t.Fatal(errno)
	}
	var n int64
	for _, v := range vec {
		if v&1 != 0 {
			n += int64(ps)
		}
	}
	return n
}

// evictFile empties the page cache of the file (after a sync); false when the file system keeps its pages whatever is asked (tmpfs).
func evictFile(t *testing.T, path string) bool {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED); err != nil {
		t.Fatal(err)
	}
	return residentBytes(t, path) == 0
}

func payloadFilePaths(t *testing.T, dir string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, payloadDirName, "*"))
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

// pageCacheTempDir points the temp dir of the test (t.TempDir) at a file system that honours fadvise. tmpfs keeps every page whatever
// is asked, so a test of the pages the log leaves in the page cache measures nothing there: run with TMPDIR on tmpfs (the default of
// several distributions) it failed on every kernel, 6.1 to 6.12, and passed on every kernel with the files on ext4. The temp dir is
// tried first, then /var/tmp, then the package directory; when none of them honours the advice the test is skipped (nothing to assert).
func pageCacheTempDir(t *testing.T) {
	t.Helper()
	wd, _ := os.Getwd()
	for _, base := range []string{"", "/var/tmp", wd} {
		if base != "" {
			if st, err := os.Stat(base); err != nil || !st.IsDir() {
				continue
			}
		}
		dir, err := os.MkdirTemp(base, "pagecache-*")
		if err != nil {
			continue
		}
		probe := filepath.Join(dir, "probe")
		if os.WriteFile(probe, bytes.Repeat([]byte{1}, 64<<10), 0o600) == nil && evictFile(t, probe) {
			if base == "" {
				os.RemoveAll(dir)
				return
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			t.Setenv("TMPDIR", dir)
			return
		}
		os.RemoveAll(dir)
	}
	t.Skip("no file system here keeps the pages of a file only until it is asked to forget them")
}

// noKeep drops the keep window of the log (payloadKeep): a record that was just written is past it at once, which is what the tests of a
// cold read, written for a log with no window, measure. The window itself is TestSyncedRecordsStayCachedForTheKeepWindow's.
func noKeep(t *testing.T) {
	t.Helper()
	old := payloadKeep
	payloadKeep = 0
	t.Cleanup(func() { payloadKeep = old })
}

// A record read cold leaves no page of the page cache behind, however small it is: the pages that it shares with its neighbours go too.
// (Records of a few hundred bytes are most of the log; a drop of the pages a record covers entirely forgets none of them.)
func TestPayloadReadColdLeavesNoPageInTheCache(t *testing.T) {
	noKeep(t)
	pageCacheTempDir(t)
	dir := filepath.Join(t.TempDir(), payloadDirName)
	l, err := openPayloadLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	var refs [][]byte
	for i := range 80 {
		ref, err := l.append(bytes.Repeat([]byte{byte(i)}, 700+i))
		if err != nil {
			t.Fatal(err)
		}
		refs = append(refs, ref)
	}
	if err = l.sync(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, payloadFileName(l.seq))
	if !evictFile(t, path) {
		t.Skip("this file system keeps the pages of a file whatever is asked")
	}
	for _, ref := range refs {
		if _, err = l.read(ref); err != nil {
			t.Fatal(err)
		}
	}
	if resident := residentBytes(t, path); resident == 0 {
		t.Fatal("a plain read left nothing in the cache: the test measures nothing")
	}
	evictFile(t, path)
	for _, ref := range refs {
		if _, err = l.readCold(ref); err != nil {
			t.Fatal(err)
		}
	}
	if resident := residentBytes(t, path); resident != 0 {
		t.Fatalf("%d bytes of the log are cached after the cold reads", resident)
	}
}

// The advance of the verified point reads the record of every page above the point (it hashes the page): those reads, once a minute for
// what the last minute wrote, were what kept 70 % of the payload log in the page cache of the scope at the single-host gate (L2w20Admission34,
// G7: payload 10 of 14 GB cached at 2,040 s, none of it written after its sync), until the scope was full and the pages of apply.db went.
func TestAdvanceLeavesNoPageOfThePayloadLogInTheCache(t *testing.T) {
	holdBackgroundVerification(t)
	noKeep(t)
	pageCacheTempDir(t)
	x := newEraseEnv(t)
	x.adoptPayload()
	for i := range 6 { // pages of tens of KB: the records of a flush window of a busy series
		recs := make([]model.Record, 300)
		for j := range recs {
			recs[j] = x.metric("busy_series", model.UnixNano(1000*i+j+1))
		}
		x.appendRecords(model.NewID(), metricRetention, recs...)
	}
	if err := x.e.payload.sync(); err != nil {
		t.Fatal(err)
	}
	paths := payloadFilePaths(t, x.dir)
	if len(paths) == 0 {
		t.Fatal("no payload file")
	}
	for _, p := range paths {
		if !evictFile(t, p) {
			t.Skip("this file system keeps the pages of a file whatever is asked")
		}
	}
	nreads := x.e.payload.nreads.Load()
	if err := x.e.advanceVerified(context.Background()); err != nil {
		t.Fatal(err)
	}
	if x.e.payload.nreads.Load() == nreads {
		t.Fatal("the advance read no record of the log: the test measures nothing")
	}
	var resident int64
	for _, p := range paths {
		resident += residentBytes(t, p)
	}
	if resident > 16<<10 {
		t.Fatalf("%d bytes of the payload log are cached after the advance", resident)
	}
}

// A record that was just written stays in the page cache for payloadKeep: the readers that follow it (the settlement of its window, the
// derivation of the window of a snapshot cut, the advance of the verified point) read it from memory, inside a read transaction of apply.db
// that a disk read would hold open (L2w20Admission36). Once the window has passed its pages are dropped, and a cold read of a record past
// the window drops its pages, while a cold read of a record inside the window leaves them to the drop that is due.
func TestSyncedRecordsStayCachedForTheKeepWindow(t *testing.T) {
	oldKeep, oldEvery := payloadKeep, payloadDropEvery
	pageCacheTempDir(t)
	payloadKeep, payloadDropEvery = time.Hour, 64<<10
	t.Cleanup(func() { payloadKeep, payloadDropEvery = oldKeep, oldEvery })
	dir := filepath.Join(t.TempDir(), payloadDirName)
	l, err := openPayloadLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	rec := bytes.Repeat([]byte{7}, 20<<10)
	var refs [][]byte
	appendSynced := func() []byte {
		ref, err := l.append(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err = l.sync(); err != nil {
			t.Fatal(err)
		}
		refs = append(refs, ref)
		return ref
	}
	for range 10 {
		appendSynced()
	}
	path := filepath.Join(dir, payloadFileName(l.seq))
	if resident := residentBytes(t, path); resident < 160<<10 {
		if probe := filepath.Join(t.TempDir(), "probe"); os.WriteFile(probe, rec, 0o600) == nil && !evictFile(t, probe) {
			t.Skip("this file system keeps the pages of a file whatever is asked")
		}
		t.Fatalf("%d of 200 KiB are cached inside the keep window", resident)
	}
	payloadKeep = 0 // the window has passed: the next sync drops what is due
	appendSynced()
	if resident := residentBytes(t, path); resident > 80<<10 { // the three records no drop span names, and the pages they share with the span before
		t.Fatalf("%d bytes are cached after the window", resident)
	}
	payloadKeep = time.Hour
	// A record past the window: a cold read leaves no page of it. A record inside it (the newest, which no drop span names): its pages stay.
	base := residentBytes(t, path)
	if _, err = l.read(refs[0]); err != nil {
		t.Fatal(err)
	}
	if got := residentBytes(t, path); got < base+16<<10 {
		t.Fatalf("a plain read of a dropped record left %d bytes cached over %d: the test measures nothing", got, base)
	}
	if _, err = l.readCold(refs[0]); err != nil {
		t.Fatal(err)
	}
	if got := residentBytes(t, path); got > base+4<<10 {
		t.Fatalf("a cold read of a record past the window left %d bytes cached over %d", got, base)
	}
	fresh := appendSynced()
	before := residentBytes(t, path)
	if _, err = l.readCold(fresh); err != nil {
		t.Fatal(err)
	}
	if got := residentBytes(t, path); got < before {
		t.Fatalf("a cold read inside the keep window dropped the record (%d bytes cached of %d)", got, before)
	}
}

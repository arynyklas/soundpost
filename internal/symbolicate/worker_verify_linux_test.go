//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

func workerFile(t testing.TB, size int) (string, model.Hash) {
	t.Helper()
	b := make([]byte, size)
	if _, e := rand.Read(b); e != nil {
		t.Fatal(e)
	}
	name := filepath.Join(t.TempDir(), "worker")
	if e := os.WriteFile(name, b, 0o700); e != nil {
		t.Fatal(e)
	}
	var h model.Hash
	sum := sha256.Sum256(b)
	copy(h[:], sum[:])
	return name, h
}

func quiet(t *testing.T, d time.Duration) {
	t.Helper()
	prev := workerCacheQuiet
	workerCacheQuiet = d
	t.Cleanup(func() { workerCacheQuiet = prev })
}

func hashesDuring(f func()) int64 {
	before := workerHashes.Load()
	f()
	return workerHashes.Load() - before
}

// testQuiet is the quiet period the reuse tests run with. A file's timestamps come from the
// kernel's coarse clock, whose tick is at most 10ms (HZ=100): a rewrite within one tick of the
// last change leaves ctime where it was, and only the quiet period keeps such a file from being
// trusted. The tests age a file past twice this period before they expect its hash to be reused,
// so the next change always lands in a later tick, on every local filesystem.
const testQuiet = 100 * time.Millisecond

// ageOut waits until the last change of the file is older than twice the quiet period.
func ageOut(t *testing.T, name string) {
	t.Helper()
	for {
		fi, e := os.Stat(name)
		if e != nil {
			t.Fatal(e)
		}
		st := fi.Sys().(*syscall.Stat_t)
		if time.Since(time.Unix(0, max(st.Mtim.Nano(), st.Ctim.Nano()))) >= 2*workerCacheQuiet {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// reusable reports whether the filesystem of the file allows the hash to be reused at all, and
// logs its type. A FUSE or network filesystem sets its own timestamps and never does.
func reusable(t *testing.T, name string) bool {
	t.Helper()
	f, e := os.Open(name)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	var sfs syscall.Statfs_t
	if e = syscall.Fstatfs(int(f.Fd()), &sfs); e != nil {
		t.Fatal(e)
	}
	t.Logf("worker filesystem type %#x, kernel-maintained timestamps: %v", uint32(sfs.Type), onKernelTimestamps(f))
	return onKernelTimestamps(f)
}

// A worker whose hash matched is not re-read on every launch, but any change to
// it is: content rewritten with the same size and a restored mtime still moves
// the ctime, and a mismatch is refused and never cached. On a filesystem that sets
// its own timestamps (FUSE, network) nothing is reused, so every launch reads the
// file and a rewrite cannot be missed either.
func TestVerifyWorkerReusesAHashOnlyWhileTheFileIsUnchanged(t *testing.T) {
	quiet(t, testQuiet)
	name, hash := workerFile(t, 1<<20)
	reuse := reusable(t, name)
	// reads is what n launches of an unchanged, aged file cost.
	reads := func(n int64) int64 {
		if reuse {
			return 1
		}
		return n
	}
	s := &Service{config: Config{Mode: "native", WorkerPath: name, WorkerSHA256: hash}}
	ageOut(t, name)
	if n := hashesDuring(func() {
		for range 5 {
			if e := s.verifyWorker(); e != nil {
				t.Fatal(e)
			}
		}
	}); n != reads(5) {
		t.Fatalf("5 launches of an unchanged worker read the file %d times, want %d", n, reads(5))
	}

	fi, _ := os.Stat(name)
	b, _ := os.ReadFile(name)
	b[len(b)/2] ^= 0xff
	if e := os.WriteFile(name, b, 0o700); e != nil {
		t.Fatal(e)
	}
	os.Chtimes(name, fi.ModTime(), fi.ModTime())
	var err error
	if n := hashesDuring(func() { err = s.verifyWorker() }); n != 1 || err == nil {
		t.Fatalf("a same-size, same-mtime rewrite was trusted: reads=%d err=%v", n, err)
	}
	if n := hashesDuring(func() { err = s.verifyWorker() }); n != 1 || err == nil {
		t.Fatalf("a mismatching worker was cached: reads=%d err=%v", n, err)
	}

	// Restoring the exact bytes is accepted again, and cached again.
	b[len(b)/2] ^= 0xff
	if e := os.WriteFile(name, b, 0o700); e != nil {
		t.Fatal(e)
	}
	ageOut(t, name)
	if n := hashesDuring(func() {
		for range 3 {
			if e := s.verifyWorker(); e != nil {
				t.Fatal(e)
			}
		}
	}); n != reads(3) {
		t.Fatalf("reads=%d, want %d", n, reads(3))
	}

	// A replaced file (new inode, same bytes) is read once, too.
	other := filepath.Join(filepath.Dir(name), "other")
	if e := os.WriteFile(other, b, 0o700); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(other, name); e != nil {
		t.Fatal(e)
	}
	if n := hashesDuring(func() {
		if e := s.verifyWorker(); e != nil {
			t.Fatal(e)
		}
	}); n != 1 {
		t.Fatalf("a replaced file was trusted unread: reads=%d", n)
	}
}

// A hash is reused only on filesystems whose timestamps the kernel alone sets.
func TestWorkerHashIsReusedOnlyOnFilesystemsWithKernelTimestamps(t *testing.T) {
	for name, typ := range map[string]uint32{"ext4": 0xEF53, "xfs": 0x58465342, "btrfs": 0x9123683E, "tmpfs": 0x01021994, "overlayfs": 0x794C7630} {
		if !kernelTimestamps(typ) {
			t.Errorf("%s: a local filesystem with kernel timestamps was refused", name)
		}
	}
	for name, typ := range map[string]uint32{"fuse": 0x65735546, "nfs": 0x6969, "smb": 0x517B, "cifs": 0xFF534D42, "smb2": 0xFE534D42, "9p": 0x01021997, "ceph": 0x00C36400, "unknown": 0} {
		if kernelTimestamps(typ) {
			t.Errorf("%s: a filesystem that sets its own timestamps was trusted", name)
		}
	}
}

// With the default quiet period a file that changed moments ago is never cached:
// the kernel's coarse timestamps could not show a further change in the same tick.
func TestVerifyWorkerNeverCachesAFreshlyWrittenFile(t *testing.T) {
	name, hash := workerFile(t, 1<<16)
	s := &Service{config: Config{Mode: "native", WorkerPath: name, WorkerSHA256: hash}}
	if n := hashesDuring(func() {
		for range 4 {
			if e := s.verifyWorker(); e != nil {
				t.Fatal(e)
			}
		}
	}); n != 4 {
		t.Fatalf("reads=%d, want 4 (never cached while the file is younger than %s)", n, workerCacheQuiet)
	}
}

// Launch-time verification cost with the hash read on every launch (what launch
// did before) against the cached path, at two worker sizes. Run on the VM:
// go test ./internal/symbolicate -run xxx -bench VerifyWorker
func BenchmarkVerifyWorker(b *testing.B) {
	for _, size := range []int{8 << 20, 64 << 20} {
		name, hash := workerFile(b, size)
		for _, mode := range []string{"hash-every-launch", "cached"} {
			b.Run(mode+"/"+byteSize(size), func(b *testing.B) {
				prev := workerCacheQuiet
				workerCacheQuiet = 0
				defer func() { workerCacheQuiet = prev }()
				s := &Service{config: Config{Mode: "native", WorkerPath: name, WorkerSHA256: hash}}
				for range b.N {
					if mode == "hash-every-launch" {
						s.verifiedSet = false
					}
					if e := s.verifyWorker(); e != nil {
						b.Fatal(e)
					}
				}
			})
		}
	}
}

func byteSize(n int) string {
	return map[int]string{8 << 20: "8MiB", 64 << 20: "64MiB"}[n]
}

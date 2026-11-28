//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Boundary pins for the task identity (l4w33 mutation battery D): the parsers that read /proc text, the bounded
// metadata reads, the executable identity and the digest that tells a reused TID or start time from the original.

// idbStat is a /proc/<pid>/stat line: the pid, a comm, then `fields` fields after the closing parenthesis of which the
// 20th (index 19) is the start time.
func idbStat(pid uint32, comm string, fields int, start string) []byte {
	var b bytes.Buffer
	b.WriteString(strconv.Itoa(int(pid)) + " (" + comm + ") ")
	for i := range fields {
		if i > 0 {
			b.WriteByte(' ')
		}
		if i == 19 {
			b.WriteString(start)
		} else if i == 0 {
			b.WriteString("S")
		} else {
			b.WriteString("1")
		}
	}
	b.WriteByte('\n')
	return b.Bytes()
}

func TestParseTaskStartReadsTheTwentiethFieldAfterTheCommand(t *testing.T) {
	if got, err := parseTaskStart(idbStat(7, "c", 20, "123"), 7); err != nil || got != 123 {
		t.Fatalf("%d %v", got, err)
	}
	// more fields (a newer kernel) are fine; the start time stays the 20th
	if got, err := parseTaskStart(idbStat(7, "c", 52, "123"), 7); err != nil || got != 123 {
		t.Fatalf("52 fields: %d %v", got, err)
	}
	// one field short is no stat line
	if _, err := parseTaskStart(idbStat(7, "c", 19, "123"), 7); !errors.Is(err, ErrTargetIdentity) {
		t.Fatalf("19 fields: %v", err)
	}
	// a comm with spaces and parentheses cannot move the start time
	if got, err := parseTaskStart(idbStat(7, "a) (b c", 20, "123"), 7); err != nil || got != 123 {
		t.Fatalf("hostile comm: %d %v", got, err)
	}
}

func TestParseTaskStartIsBoundedTo4096Bytes(t *testing.T) {
	line := idbStat(7, "c", 20, "123")
	at4096 := append(bytes.TrimRight(line, "\n"), bytes.Repeat([]byte(" "), 4096-len(line)+1)...)
	if len(at4096) != 4096 {
		t.Fatalf("test line is %d bytes", len(at4096))
	}
	if got, err := parseTaskStart(at4096, 7); err != nil || got != 123 {
		t.Fatalf("4096 bytes: %d %v", got, err)
	}
	if _, err := parseTaskStart(append(at4096, ' '), 7); !errors.Is(err, ErrTargetIdentity) {
		t.Fatalf("4097 bytes: %v", err)
	}
}

func TestParseTaskStartRefusesWhatIsNotTheTasksOwnStatLine(t *testing.T) {
	good := idbStat(7, "c", 20, "123")
	for name, b := range map[string][]byte{
		"another pid":              idbStat(8, "c", 20, "123"),
		"no pid":                   bytes.TrimPrefix(good, []byte("7")),
		"a pid that is no number":  append([]byte("x"), good[1:]...),
		"a pid beyond 32 bits":     append([]byte("4294967303"), good[1:]...),
		"no opening parenthesis":   bytes.Replace(good, []byte(" ("), []byte(" ["), 1),
		"no closing parenthesis":   bytes.Replace(good, []byte(")"), []byte("]"), 1),
		"nothing after the comm":   []byte("7 (c)"),
		"a zero start time":        idbStat(7, "c", 20, "0"),
		"a start time that is not": idbStat(7, "c", 20, "x"),
		"a negative start time":    idbStat(7, "c", 20, "-5"),
		"an overflowing start":     idbStat(7, "c", 20, "18446744073709551616"),
		"empty":                    nil,
	} {
		if got, err := parseTaskStart(b, 7); !errors.Is(err, ErrTargetIdentity) {
			t.Errorf("%s: accepted (%d, %v)", name, got, err)
		}
	}
}

// A start time is in clock ticks and the process start is ticks*10ms: the largest start that cannot overflow that
// product is accepted and the next one is not.
func TestParseTaskStartBoundsTheStartTimeByWhatItsProductCanHold(t *testing.T) {
	const largest = ^uint64(0) / 10000000
	if got, err := parseTaskStart(idbStat(7, "c", 20, strconv.FormatUint(largest, 10)), 7); err != nil || got != largest {
		t.Fatalf("%d: %d %v", largest, got, err)
	}
	if got, err := parseTaskStart(idbStat(7, "c", 20, strconv.FormatUint(largest+1, 10)), 7); !errors.Is(err, ErrTargetIdentity) {
		t.Fatalf("%d: accepted (%d, %v)", largest+1, got, err)
	}
	if got, err := parseTaskStart(idbStat(7, "c", 20, "1"), 7); err != nil || got != 1 {
		t.Fatalf("1: %d %v", got, err)
	}
}

func TestParseTGIDWantsExactlyOneNonZeroTgidLine(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status string
		want   uint32
		ok     bool
	}{
		{"one line", "Name:\tx\nTgid:\t77\nPid:\t78\n", 77, true},
		{"surrounding blanks", "Tgid:   12  \n", 12, true},
		{"no trailing newline", "Tgid:5", 5, true},
		{"the largest tgid", "Tgid:\t4294967295\n", 4294967295, true},
		{"a tgid beyond 32 bits", "Tgid:\t4294967296\n", 0, false},
		{"zero", "Tgid:\t0\n", 0, false},
		{"no tgid", "Name:\tx\nPid:\t78\n", 0, false},
		{"empty", "", 0, false},
		{"not a number", "Tgid:\tseven\n", 0, false},
		{"negative", "Tgid:\t-3\n", 0, false},
		{"two tgid lines", "Tgid:\t7\nTgid:\t7\n", 0, false},
		{"two different tgid lines", "Tgid:\t7\nName:\tx\nTgid:\t8\n", 0, false},
		{"a line that only mentions it", "Name:\tTgid:9\n", 0, false},
	} {
		got, err := parseTGID([]byte(tc.status))
		if tc.ok != (err == nil) || (tc.ok && got != tc.want) || (!tc.ok && !errors.Is(err, ErrTargetIdentity)) {
			t.Errorf("%s: %d, %v", tc.name, got, err)
		}
	}
}

// The digest is the first eight bytes (little endian) of the SHA-256 of the seven inputs as little endian words in the
// order namespace, process, thread, start, thread start, device, inode; each of them moves it.
func TestTaskIdentityDigestIsTheDocumentedHashOfEveryInput(t *testing.T) {
	want := func(in [7]uint64) uint64 {
		var b []byte
		for _, v := range in {
			b = binary.LittleEndian.AppendUint64(b, v)
		}
		sum := sha256.Sum256(b)
		return binary.LittleEndian.Uint64(sum[:8])
	}
	base := [7]uint64{3, 5, 7, 11, 13, 17, 19}
	got := taskIdentityDigest(base[0], base[1], base[2], base[3], base[4], base[5], base[6])
	if got != want(base) || got == 0 {
		t.Fatalf("digest %#x, want %#x", got, want(base))
	}
	for i := range base {
		moved := base
		moved[i]++
		if d := taskIdentityDigest(moved[0], moved[1], moved[2], moved[3], moved[4], moved[5], moved[6]); d == got || d != want(moved) {
			t.Errorf("input %d does not move the digest (or moves it wrongly): %#x", i, d)
		}
	}
	// the same words in another order are another identity
	if d := taskIdentityDigest(5, 3, 7, 11, 13, 17, 19); d == got {
		t.Error("namespace and process are interchangeable")
	}
}

func TestIdentityEpochAcceptsExactlyTheCurrentValidGeneration(t *testing.T) {
	g := identityEpoch{generation: 5}
	if err := g.check(5); err != nil {
		t.Fatalf("the current generation: %v", err)
	}
	for _, expected := range []uint64{0, 4, 6} {
		if err := g.check(expected); !errors.Is(err, ErrTargetIdentity) {
			t.Errorf("generation %d accepted against 5: %v", expected, err)
		}
	}
	if err := (identityEpoch{}).check(0); !errors.Is(err, ErrTargetIdentity) {
		t.Errorf("generation 0 is no generation: %v", err)
	}
	// the invalidated epoch refuses every guard, including the one that names its new generation
	if err := g.invalidate(5); !errors.Is(err, ErrTargetIdentity) {
		t.Fatalf("the same generation: %v", err)
	}
	if err := g.invalidate(4); !errors.Is(err, ErrTargetIdentity) {
		t.Fatalf("an older generation: %v", err)
	}
	if g.invalid || g.generation != 5 {
		t.Fatalf("a refused invalidation changed the epoch: %+v", g)
	}
	if err := g.invalidate(6); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []uint64{5, 6} {
		if err := g.check(expected); !errors.Is(err, ErrTargetIdentity) {
			t.Errorf("generation %d accepted after the invalidation: %v", expected, err)
		}
	}
}

// procFile reads at most limit bytes of a metadata file: exactly limit is fine, one more is refused; a name that is not
// there or is a symbolic link is refused.
func TestProcFileIsBoundedAndNeverFollowsALink(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, n int) {
		if err := os.WriteFile(filepath.Join(dir, name), bytes.Repeat([]byte("a"), n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("exact", 100)
	write("over", 101)
	write("empty", 0)
	if err := os.Symlink(filepath.Join(dir, "exact"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if b, err := procFile(fd, "exact", 100); err != nil || len(b) != 100 {
		t.Fatalf("exactly the limit: %d %v", len(b), err)
	}
	if b, err := procFile(fd, "empty", 100); err != nil || len(b) != 0 {
		t.Fatalf("an empty file: %d %v", len(b), err)
	}
	for _, name := range []string{"over", "missing", "link"} {
		if b, err := procFile(fd, name, 100); !errors.Is(err, ErrTargetIdentity) || b != nil {
			t.Errorf("%s: %d bytes, %v", name, len(b), err)
		}
	}
}

func TestProcNamespaceIsThePIDNamespaceOfTheDirectoryItIsGiven(t *testing.T) {
	fd, err := syscall.Open("/proc/self", syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	got, err := procNamespace(fd)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("/proc/self/ns/pid")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var st syscall.Stat_t
	if err = syscall.Fstat(int(f.Fd()), &st); err != nil || got != st.Ino || got == 0 {
		t.Fatalf("namespace %d, the pid namespace file is inode %d (%v)", got, st.Ino, err)
	}
	empty, err := syscall.Open(t.TempDir(), syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(empty)
	if _, err = procNamespace(empty); !errors.Is(err, ErrTargetIdentity) {
		t.Fatalf("a directory without a namespace link: %v", err)
	}
}

// The identity of an executable is that of the regular file itself - every field of it - and nothing else is one.
func TestFileIdentityIsEveryFieldOfTheRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var st syscall.Stat_t
	if err = syscall.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	got, err := fileIdentity(f)
	if err != nil {
		t.Fatal(err)
	}
	want := executableIdentity{uint64(st.Dev), st.Ino, 5, st.Mtim.Sec, st.Mtim.Nsec, st.Ctim.Sec, st.Ctim.Nsec}
	if got != want {
		t.Fatalf("%+v, want %+v", got, want)
	}
	// a change of the contents is another identity (size and times), and so is the same bytes under another inode
	if err = os.WriteFile(path, []byte("hello, world"), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if again, err := fileIdentity(g); err != nil || again == got || again.size != 12 {
		t.Fatalf("%+v %v", again, err)
	}
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if _, err = fileIdentity(dir); !errors.Is(err, ErrTargetIdentity) {
		t.Fatalf("a directory: %v", err)
	}
	null, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	if _, err = fileIdentity(null); !errors.Is(err, ErrTargetIdentity) {
		t.Fatalf("a device: %v", err)
	}
}

// The executable of a process that was deleted after it started is not an identity: the link says so.
func TestOpenProcExecutableRefusesADeletedExecutable(t *testing.T) {
	src, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep(1)")
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Skip(err)
	}
	path := filepath.Join(t.TempDir(), "sleeper")
	if err = os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err = cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	proc := "/proc/" + strconv.Itoa(cmd.Process.Pid)
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if got, err := os.Readlink(proc + "/exe"); err == nil && got == path {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the child never executed")
		}
	}
	fd, err := syscall.Open(proc, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	live, err := openProcExecutable(fd)
	if err != nil {
		t.Fatalf("a live executable: %v", err)
	}
	var want, got syscall.Stat_t
	if err = syscall.Stat(path, &want); err != nil || syscall.Fstat(int(live.Fd()), &got) != nil || got.Ino != want.Ino || got.Dev != want.Dev {
		t.Fatalf("the executable opened is not the one that runs: %+v %+v %v", got, want, err)
	}
	live.Close()
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if f, err := openProcExecutable(fd); !errors.Is(err, ErrTargetIdentity) || f != nil {
		t.Fatalf("a deleted executable: %v %v", f, err)
	}
}

// A thread of a process is identified as that thread of that process: its own TID, the process's TGID and start time,
// and a generation of its own.
func TestResolveTaskNamesTheThreadAndItsProcess(t *testing.T) {
	f, err := os.Open("/proc/self/ns/pid")
	if err != nil {
		t.Fatal(err)
	}
	ns, err := namespaceInode(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	main, err := resolveTask(os.Getpid(), NamespaceID(ns))
	if err != nil {
		t.Fatal(err)
	}
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	ticks, err := parseTaskStart(stat, uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if uint64(main.ProcessStart) != ticks*10000000 || uint64(main.PIDNamespace) != ns || main.TGID != uint32(os.Getpid()) || main.TID != main.TGID {
		t.Fatalf("%+v (start ticks %d, namespace %d)", main, ticks, ns)
	}
	type result struct {
		key TaskKey
		tid int
		err error
	}
	// several goroutines each hold an OS thread of their own at the same time, so at least one is not the main thread
	const holders = 4
	done := make(chan result, holders)
	release := make(chan struct{})
	defer close(release)
	for range holders {
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			tid := syscall.Gettid()
			key, err := resolveTask(tid, NamespaceID(ns))
			done <- result{key, tid, err}
			<-release
		}()
	}
	var r result
	for range holders {
		got := <-done
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.tid != os.Getpid() {
			r = got
		}
	}
	if r.tid == 0 {
		t.Skip("every goroutine ran on the main thread")
	}
	if r.key.TID != uint32(r.tid) || r.key.TGID != main.TGID || r.key.ProcessStart != main.ProcessStart || r.key.PIDNamespace != main.PIDNamespace || r.key.BootID != main.BootID {
		t.Fatalf("thread %d: %+v, process %+v", r.tid, r.key, main)
	}
	if r.key.Generation == main.Generation || r.key.Generation == 0 {
		t.Fatalf("two threads of a process share a generation: %d %d", r.key.Generation, main.Generation)
	}
	// a pid that is no process of this namespace, and the pids that cannot be ones
	for _, pid := range []int{0, -1, 1 << 40} {
		if _, err := resolveTask(pid, NamespaceID(ns)); !errors.Is(err, ErrTargetIdentity) {
			t.Errorf("pid %d: %v", pid, err)
		}
	}
	if _, err := resolveTask(os.Getpid(), 0); !errors.Is(err, ErrTargetIdentity) {
		t.Errorf("namespace 0: %v", err)
	}
	if main.BootID == "" {
		t.Errorf("no boot id: %+v", main)
	}
}

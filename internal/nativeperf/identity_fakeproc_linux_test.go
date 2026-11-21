//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// resolveTask against a /proc that says whatever the test wants (l4w33 mutation battery D): a private mount namespace
// where the directories of two real processes are replaced, by bind mounts, with directories holding the files resolveTask
// reads - or FIFOs that hand out a different answer to each read, so that a task that changes between the two reads of
// one identity snapshot can be staged deterministically. Needs CAP_SYS_ADMIN; without it the test skips, loudly.

const fakeProcChildEnv = "L4W33_FAKEPROC_CHILD"

func TestResolveTaskRefusesEveryInconsistencyOfWhatProcShows(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("SKIPPED: a private mount namespace needs root")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestFakeProcChild$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), fakeProcChildEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	out, err := cmd.CombinedOutput()
	text := string(out)
	if strings.Contains(text, "FAKEPROC SKIP") {
		t.Skipf("SKIPPED: %s", text[strings.Index(text, "FAKEPROC SKIP"):])
	}
	failed := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "FAKEPROC FAIL") {
			t.Error(line)
			failed++
		}
	}
	if !strings.Contains(text, "FAKEPROC DONE") {
		t.Fatalf("the namespace child did not finish (%v):\n%s", err, text)
	}
	if err != nil && failed == 0 {
		t.Fatalf("the namespace child failed: %v\n%s", err, text)
	}
}

// fakeSpec is what the fake /proc of one scenario holds. The thread is process a, the process (the Tgid its status
// names) is process b. A nil file is absent; a second stat read, when given, is what the second read of the stat file
// returns (the first read returns the first).
type fakeSpec struct {
	aStat, aStat2, status  []byte
	bStat, bStat2          []byte
	aNS, bNS               string // "", "shared" or "other"
	exe                    string // "", "real", "dir" or "deleted"
	statusTgid             int    // the Tgid line of the default status (0: b)
	namespace              uint64 // the namespace resolveTask is asked for (0: the shared one)
	beforeSecondThreadStat func(w *fakeWorld)
	beforeSecondProcStat   func(w *fakeWorld)
}

type fakeWorld struct {
	dir, root         string
	a, b              int
	nsShared, nsOther string
	exeReal, exeOther string
}

func fakeStat(pid int, start string) []byte { return idbStat(uint32(pid), "c", 20, start) }

func TestFakeProcChild(t *testing.T) {
	if os.Getenv(fakeProcChildEnv) == "" {
		t.Skip("helper of TestResolveTaskRefusesEveryInconsistencyOfWhatProcShows")
	}
	if err := syscall.Mount("none", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		fmt.Println("FAKEPROC SKIP: cannot make the mount tree private:", err)
		return
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		fmt.Println("FAKEPROC SKIP: no sleep(1)")
		return
	}
	w := &fakeWorld{dir: t.TempDir()}
	for _, name := range []string{"ns-shared", "ns-other", "exe-real", "exe-other"} {
		src := sleep
		if strings.HasPrefix(name, "ns") {
			src = os.Args[0]
		}
		data, err := os.ReadFile(src)
		if err != nil {
			fmt.Println("FAKEPROC SKIP:", err)
			return
		}
		if strings.HasPrefix(name, "ns") {
			data = data[:16]
		}
		if err = os.WriteFile(filepath.Join(w.dir, name), data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	w.nsShared, w.nsOther = filepath.Join(w.dir, "ns-shared"), filepath.Join(w.dir, "ns-other")
	w.exeReal, w.exeOther = filepath.Join(w.dir, "exe-real"), filepath.Join(w.dir, "exe-other")
	var pids []int
	for range 2 {
		cmd := exec.Command(w.exeReal, "600")
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		if err := cmd.Start(); err != nil {
			fmt.Println("FAKEPROC SKIP: cannot start a helper process:", err)
			return
		}
		defer func() { cmd.Process.Kill(); cmd.Wait() }()
		pids = append(pids, cmd.Process.Pid)
	}
	w.a, w.b = pids[0], pids[1]

	var shared syscall.Stat_t
	if err := syscall.Stat(w.nsShared, &shared); err != nil {
		t.Fatal(err)
	}
	var realExe syscall.Stat_t
	if err := syscall.Stat(w.exeReal, &realExe); err != nil {
		t.Fatal(err)
	}
	baseline := func() fakeSpec {
		return fakeSpec{
			aStat: fakeStat(w.a, "123"), bStat: fakeStat(w.b, "456"),
			status: []byte(fmt.Sprintf("Name:\tx\nTgid:\t%d\nPid:\t%d\n", w.b, w.a)),
			aNS:    "shared", bNS: "shared", exe: "real",
		}
	}
	type scenario struct {
		name string
		spec func(s *fakeSpec)
		// ok: the identity that must come out; otherwise ErrTargetIdentity
		ok bool
	}
	domain, err := localCPUDomain()
	if err != nil {
		fmt.Println("FAKEPROC SKIP:", err)
		return
	}
	scenarios := []scenario{
		{"the consistent snapshot", func(s *fakeSpec) {}, true},
		{"the consistent snapshot with every file read twice", func(s *fakeSpec) {
			s.aStat2, s.bStat2 = s.aStat, s.bStat
		}, true},
		{"no stat of the thread", func(s *fakeSpec) { s.aStat = nil }, false},
		{"the stat of another pid", func(s *fakeSpec) { s.aStat = fakeStat(w.a+1, "123") }, false},
		{"a stat without a start time", func(s *fakeSpec) { s.aStat = fakeStat(w.a, "0") }, false},
		{"no namespace link of the thread", func(s *fakeSpec) { s.aNS = "" }, false},
		{"another namespace than the one asked for", func(s *fakeSpec) { s.namespace = shared.Ino + 1 }, false},
		{"no status", func(s *fakeSpec) { s.status = nil }, false},
		{"a status without a Tgid", func(s *fakeSpec) { s.status = []byte("Name:\tx\n") }, false},
		{"a Tgid of a process that is not there", func(s *fakeSpec) { s.statusTgid = 4194300 }, false},
		{"no stat of the process", func(s *fakeSpec) { s.bStat = nil }, false},
		{"the stat of another process", func(s *fakeSpec) { s.bStat = fakeStat(w.b+1, "456") }, false},
		{"a process stat without a start time", func(s *fakeSpec) { s.bStat = fakeStat(w.b, "0") }, false},
		{"no namespace link of the process", func(s *fakeSpec) { s.bNS = "" }, false},
		{"a process in another namespace than its thread", func(s *fakeSpec) { s.bNS = "other" }, false},
		{"no executable", func(s *fakeSpec) { s.exe = "" }, false},
		{"an executable that is a directory", func(s *fakeSpec) { s.exe = "dir" }, false},
		{"an executable that was deleted", func(s *fakeSpec) { s.exe = "deleted" }, false},
		{"a thread that starts again between the two reads", func(s *fakeSpec) { s.aStat2 = fakeStat(w.a, "124") }, false},
		{"a second thread stat that cannot be read", func(s *fakeSpec) { s.aStat2 = []byte{} }, false},
		{"a second thread stat of another pid", func(s *fakeSpec) { s.aStat2 = fakeStat(w.a+1, "123") }, false},
		{"a thread whose namespace link changes between the two reads", func(s *fakeSpec) {
			s.aStat2 = s.aStat
			s.beforeSecondThreadStat = func(w *fakeWorld) { swapLink(w, filepath.Join(w.root, "a", "ns", "pid"), w.nsOther) }
		}, false},
		{"an executable replaced between the two reads", func(s *fakeSpec) {
			s.aStat2 = s.aStat
			s.beforeSecondThreadStat = func(w *fakeWorld) { swapSymlink(w, filepath.Join(w.root, "b", "exe"), w.exeOther) }
		}, false},
		{"a process that starts again between the two reads", func(s *fakeSpec) { s.bStat2 = fakeStat(w.b, "457") }, false},
		{"a second process stat that cannot be read", func(s *fakeSpec) { s.bStat2 = []byte{} }, false},
		{"a second process stat of another pid", func(s *fakeSpec) { s.bStat2 = fakeStat(w.b+1, "456") }, false},
	}
	for _, sc := range scenarios {
		spec := baseline()
		sc.spec(&spec)
		key, err := runFakeProc(w, spec)
		switch {
		case sc.ok && err != nil:
			fmt.Printf("FAKEPROC FAIL %s: refused with %v\n", sc.name, err)
		case !sc.ok && !errors.Is(err, ErrTargetIdentity):
			fmt.Printf("FAKEPROC FAIL %s: %+v, %v; want ErrTargetIdentity\n", sc.name, key, err)
		case sc.ok:
			want := TaskKey{BootID: domain.BootID, PIDNamespace: model.Uint64(shared.Ino), TGID: uint32(w.b), TID: uint32(w.a), ProcessStart: 456 * 10000000,
				Generation: model.Uint64(taskIdentityDigest(shared.Ino, uint64(w.b), uint64(w.a), 456, 123, uint64(realExe.Dev), realExe.Ino))}
			if key != want {
				fmt.Printf("FAKEPROC FAIL %s: identity %+v, want %+v\n", sc.name, key, want)
			}
		}
	}
	fmt.Println("FAKEPROC DONE", len(scenarios))
}

func swapLink(w *fakeWorld, link, target string) {
	os.Remove(link)
	os.Link(target, link)
}

func swapSymlink(w *fakeWorld, link, target string) {
	os.Remove(link)
	os.Symlink(target, link)
}

// runFakeProc builds the two fake process directories, mounts them over the real ones, runs resolveTask under a
// deadline and unmounts them again.
func runFakeProc(w *fakeWorld, s fakeSpec) (TaskKey, error) {
	root := filepath.Join(w.dir, "world-"+strconv.FormatInt(time.Now().UnixNano(), 36))
	w.root = root
	stop := make(chan struct{})
	defer close(stop)
	build := func(name string, pid int, stat, stat2 []byte, ns string, hook func(*fakeWorld)) string {
		dir := filepath.Join(root, name)
		os.MkdirAll(filepath.Join(dir, "ns"), 0o755)
		if stat != nil {
			if stat2 == nil {
				os.WriteFile(filepath.Join(dir, "stat"), stat, 0o644)
			} else {
				syscall.Mkfifo(filepath.Join(dir, "stat"), 0o644)
				go feedFIFO(filepath.Join(dir, "stat"), stop, []func(){nil, func() {
					if hook != nil {
						hook(w)
					}
				}}, stat, stat2)
			}
		}
		switch ns {
		case "shared":
			os.Link(w.nsShared, filepath.Join(dir, "ns", "pid"))
		case "other":
			os.Link(w.nsOther, filepath.Join(dir, "ns", "pid"))
		}
		return dir
	}
	aDir := build("a", w.a, s.aStat, s.aStat2, s.aNS, s.beforeSecondThreadStat)
	bDir := build("b", w.b, s.bStat, s.bStat2, s.bNS, s.beforeSecondProcStat)
	status := s.status
	if s.statusTgid != 0 && status != nil {
		status = []byte(fmt.Sprintf("Name:\tx\nTgid:\t%d\nPid:\t%d\n", s.statusTgid, w.a))
	}
	if status != nil {
		os.WriteFile(filepath.Join(aDir, "status"), status, 0o644)
	}
	switch s.exe {
	case "real":
		os.Symlink(w.exeReal, filepath.Join(bDir, "exe"))
	case "dir":
		os.Symlink(w.dir, filepath.Join(bDir, "exe"))
	case "deleted":
		os.Symlink(w.exeReal+" (deleted)", filepath.Join(bDir, "exe"))
	}
	for pid, dir := range map[int]string{w.a: aDir, w.b: bDir} {
		target := "/proc/" + strconv.Itoa(pid)
		if err := syscall.Mount(dir, target, "", syscall.MS_BIND, ""); err != nil {
			return TaskKey{}, fmt.Errorf("mount: %w", err)
		}
		defer syscall.Unmount(target, syscall.MNT_DETACH)
	}
	ns := s.namespace
	if ns == 0 {
		var st syscall.Stat_t
		syscall.Stat(w.nsShared, &st)
		ns = st.Ino
	}
	type result struct {
		key TaskKey
		err error
	}
	done := make(chan result, 1)
	go func() {
		key, err := resolveTask(w.a, NamespaceID(ns))
		done <- result{key, err}
	}()
	select {
	case r := <-done:
		return r.key, r.err
	case <-time.After(5 * time.Second):
		return TaskKey{}, errors.New("resolveTask did not return: it read a file more often than the snapshot reads it")
	}
}

// feedFIFO answers each open of the FIFO for reading with the next content; hooks[i] runs after the i-th reader has
// arrived and before it is given its content. It waits for a reader to close its end before it serves the next one, so
// that one read never receives the content of two.
func feedFIFO(path string, stop <-chan struct{}, hooks []func(), contents ...[]byte) {
	in, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if err != nil {
		return
	}
	defer syscall.Close(in)
	if _, err = syscall.InotifyAddWatch(in, path, syscall.IN_CLOSE_NOWRITE); err != nil {
		return
	}
	pause := func() bool {
		select {
		case <-stop:
			return false
		case <-time.After(time.Millisecond):
			return true
		}
	}
	for i, content := range contents {
		var fd int
		for {
			if fd, err = syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				break
			}
			if !pause() {
				return
			}
		}
		if i < len(hooks) && hooks[i] != nil {
			hooks[i]()
		}
		syscall.SetNonblock(fd, false)
		syscall.Write(fd, content)
		syscall.Close(fd)
		buf := make([]byte, 4096)
		for {
			if n, _ := syscall.Read(in, buf); n > 0 {
				break
			}
			if !pause() {
				return
			}
		}
	}
}

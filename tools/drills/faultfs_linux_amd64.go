//go:build linux && amd64

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// This file is the drills' storage fault injector. It runs the REAL produced binary under an
// unprivileged seccomp filter with SECCOMP_RET_USER_NOTIF: the file-durability and file-namespace
// system calls of the member (fsync, fdatasync, open, mkdir, unlink, rename...) are delivered to the
// drill, which either lets the kernel run them (SECCOMP_USER_NOTIF_FLAG_CONTINUE) or answers EIO
// like a failing or vanished disk does. No sysctl, capability, mount or privileged container is
// involved; a seccomp filter only needs no_new_privs.
//
// The same stream of fsync/rename events is a ledger of what the member made durable, which is what
// the power-loss drill needs: after the process group is killed, every byte and directory entry the
// member did not fsync is rolled back (see PowerCut). The filter is a fault injector, not a
// security boundary (CONTINUE is racy by design) and covers only the native amd64 syscall ABI.

const dcFaultExecEnv = "SOUNDPOST_DRILL_FAULT_EXEC"

const (
	scSetModeFilter  = 1
	scFlagNewListen  = 1 << 3
	scRetAllow       = 0x7fff0000
	scRetUserNotif   = 0x7fc00000
	scIoctlRecv      = 0xc0502100
	scIoctlSend      = 0xc0182101 // _IOWR('!', 1, struct seccomp_notif_resp)
	scRespFlagCont   = 1
	auditArchX8664   = 0xc000003e
	bpfLdWAbs        = 0x20
	bpfJeqK          = 0x15
	bpfRetK          = 0x06
	atFdCwd          = -100
	maxTraceePathLen = 4096
)

type scNotif struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Nr    int32
	Arch  uint32
	IP    uint64
	Args  [6]uint64
}

type scResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

// the trapped system calls (amd64 numbers).
var scTrapped = []uint32{
	syscall.SYS_FSYNC, syscall.SYS_FDATASYNC,
	syscall.SYS_OPEN, syscall.SYS_OPENAT, syscall.SYS_CREAT, 437, /* openat2 */
	syscall.SYS_MKDIR, syscall.SYS_MKDIRAT, syscall.SYS_UNLINK, syscall.SYS_UNLINKAT, syscall.SYS_RMDIR,
	syscall.SYS_RENAME, syscall.SYS_RENAMEAT, 316, /* renameat2 */
}

func scProgram() []unix.SockFilter {
	p := []unix.SockFilter{
		{Code: bpfLdWAbs, K: 4}, // arch
		{Code: bpfJeqK, Jt: 1, K: auditArchX8664},
		{Code: bpfRetK, K: scRetAllow},
		{Code: bpfLdWAbs, K: 0}, // nr
	}
	for i, nr := range scTrapped {
		// on a match jump to the final USER_NOTIF return, otherwise fall to the next test
		p = append(p, unix.SockFilter{Code: bpfJeqK, Jt: uint8(len(scTrapped) - i), K: nr})
	}
	p = append(p, unix.SockFilter{Code: bpfRetK, K: scRetAllow}, unix.SockFilter{Code: bpfRetK, K: scRetUserNotif})
	return p
}

// dcFaultExecMain is the child half: re-executed by the drills binary itself, it installs the filter
// on this thread, hands the listener to the parent over fd 3 and execs the real binary, which
// inherits the filter.
func dcFaultExecMain() int {
	if len(os.Args) < 2 {
		return 2
	}
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fmt.Fprintln(os.Stderr, "no_new_privs:", err)
		return 3
	}
	prog := scProgram()
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	fd, _, errno := syscall.Syscall(unix.SYS_SECCOMP, scSetModeFilter, scFlagNewListen, uintptr(unsafe.Pointer(&fprog)))
	if errno != 0 {
		fmt.Fprintln(os.Stderr, "seccomp:", errno)
		return 3
	}
	unix.CloseOnExec(int(fd))
	if err := syscall.Sendmsg(3, []byte{1}, syscall.UnixRights(int(fd)), nil, 0); err != nil {
		fmt.Fprintln(os.Stderr, "send listener:", err)
		return 3
	}
	unix.CloseOnExec(3)
	err := syscall.Exec(os.Args[1], os.Args[1:], []string{"PATH=" + os.Getenv("PATH")})
	fmt.Fprintln(os.Stderr, "exec:", err)
	return 3
}

// dcDisk is the injected disk of one member: the fault switches and the durability ledger.
type dcDisk struct {
	root   string
	shadow string

	mu       sync.Mutex
	failSync bool
	gone     bool
	roots    []string // root and, once the disk is detached, where it was moved to
	files    map[string]int64
	dirs     map[string]map[string]struct{}
	renames  []*dcRename
	seq      int
	stats    dcDiskStats
	hold     chan struct{} // while non-nil every fsync of the member blocks (a power cut that lands inside fsync)
	held     chan struct{} // closed when the first fsync is held
	heldDone bool
	quit     chan struct{}
	done     chan struct{}
}

type dcRename struct {
	src, dst         string
	shadow           string // hard link to the file dst replaced, "" if none
	oldSize          int64
	srcDone, dstDone bool
}

// dcDiskStats counts what the injector did; it goes into the report.
type dcDiskStats struct {
	Syncs, SyncsFailed, SyncsOnGone, PathOpsDenied, DirSyncs, Renames int
}

func newDCDisk(root, shadow string) (*dcDisk, error) {
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(shadow, 0o700); err != nil {
		return nil, err
	}
	return &dcDisk{root: real, shadow: shadow, roots: []string{real}}, nil
}

func (d *dcDisk) under(p string) bool {
	for _, r := range d.roots {
		if p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

// rebaseline records the disk as it is NOW as fully durable (what a restarted node finds on disk).
func (d *dcDisk) rebaseline() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.files, d.dirs, d.renames, d.hold = map[string]int64{}, map[string]map[string]struct{}{}, nil, nil
	return filepath.WalkDir(d.root, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			names, rerr := dirNames(p)
			if rerr != nil {
				return rerr
			}
			d.dirs[p] = names
			return nil
		}
		if info, ierr := e.Info(); ierr == nil && info.Mode().IsRegular() {
			d.files[p] = info.Size()
		}
		return nil
	})
}

func dirNames(p string) (map[string]struct{}, error) {
	ents, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, len(ents))
	for _, e := range ents {
		out[e.Name()] = struct{}{}
	}
	return out, nil
}

func (d *dcDisk) setFailSync(on bool) { d.mu.Lock(); d.failSync = on; d.mu.Unlock() }

// detach makes the disk vanish: the directory is moved away (a path walk now finds nothing) and every
// durability point and path operation of the running member answers EIO.
func (d *dcDisk) detach(awayTo string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := os.Rename(d.root, awayTo); err != nil {
		return err
	}
	d.roots = append(d.roots, awayTo)
	d.gone = true
	return nil
}

// reattachOriginal puts the disk that was moved away back at its path (the member is not running).
func (d *dcDisk) reattachOriginal(awayTo string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := os.Rename(awayTo, d.root); err != nil {
		return err
	}
	d.roots = d.roots[:1]
	d.gone = false
	return nil
}

// reattachBlank puts an EMPTY directory where the vanished disk was (a replacement disk); the
// original stays at awayTo.
func (d *dcDisk) reattachBlank(awayTo string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := os.Mkdir(d.root, 0o700); err != nil {
		return err
	}
	d.roots = d.roots[:1]
	d.gone = false
	return nil
}

// discardBlank removes the replacement disk again so the original can be put back.
func (d *dcDisk) discardBlank(awayTo string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.gone = true
	d.roots = []string{d.root, awayTo}
	return os.RemoveAll(d.root)
}

func (d *dcDisk) Stats() dcDiskStats { d.mu.Lock(); defer d.mu.Unlock(); return d.stats }

// attach starts serving the listener of a running member.
func (d *dcDisk) attach(fd int) {
	d.quit, d.done = make(chan struct{}), make(chan struct{})
	go d.serve(fd, d.quit, d.done)
}

// stop ends the supervisor of the previous incarnation (it also ends by itself when the process is gone).
func (d *dcDisk) stop() {
	if d.quit != nil {
		select {
		case <-d.quit:
		default:
			close(d.quit)
		}
		<-d.done
	}
}

func (d *dcDisk) serve(fd int, quit, done chan struct{}) {
	defer close(done)
	defer unix.Close(fd)
	for {
		select {
		case <-quit:
			return
		default:
		}
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if _, err := unix.Poll(pfd, 100); err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}
		if pfd[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return
		}
		if pfd[0].Revents&unix.POLLIN == 0 {
			continue
		}
		var n scNotif
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), scIoctlRecv, uintptr(unsafe.Pointer(&n))); e != 0 {
			continue
		}
		if ch := d.holdingSync(&n); ch != nil {
			select {
			case <-ch:
			case <-quit:
				return
			}
		}
		r := scResp{ID: n.ID}
		if errno := d.decide(&n); errno != 0 {
			r.Error = -int32(errno)
		} else {
			r.Flags = scRespFlagCont
		}
		_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), scIoctlSend, uintptr(unsafe.Pointer(&r)))
	}
}

// holdingSync returns the hold channel when this notification is an fsync of the member's disk that
// must be held (see armHold), and nil otherwise.
func (d *dcDisk) holdingSync(n *scNotif) chan struct{} {
	if n.Nr != syscall.SYS_FSYNC && n.Nr != syscall.SYS_FDATASYNC {
		return nil
	}
	path := traceeLink(n.PID, fmt.Sprintf("fd/%d", int32(n.Args[0])))
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.hold == nil || path == "" || !d.under(path) {
		return nil
	}
	if !d.heldDone {
		d.heldDone = true
		close(d.held)
	}
	return d.hold
}

// armHold makes every following fsync of the member block until the member is killed: writes the
// member already issued stay unsynced and unacknowledged, which is exactly what a power cut inside
// an fsync leaves behind.
func (d *dcDisk) armHold() {
	d.mu.Lock()
	d.hold, d.held, d.heldDone = make(chan struct{}), make(chan struct{}), false
	d.mu.Unlock()
}

// waitHeld reports whether an fsync was held within the limit.
func (d *dcDisk) waitHeld(limit time.Duration) bool {
	d.mu.Lock()
	h := d.held
	d.mu.Unlock()
	select {
	case <-h:
		return true
	case <-time.After(limit):
		return false
	}
}

func traceeLink(pid uint32, what string) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/%s", pid, what))
	if err != nil {
		return ""
	}
	return p
}

func traceeString(pid uint32, addr uint64) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return ""
	}
	defer f.Close()
	var out []byte
	buf := make([]byte, 256)
	for len(out) < maxTraceePathLen {
		chunk := len(buf)
		if rest := 4096 - int(addr%4096); rest < chunk {
			chunk = rest
		}
		n, err := f.ReadAt(buf[:chunk], int64(addr))
		for i := range n {
			if buf[i] == 0 {
				return string(append(out, buf[:i]...))
			}
		}
		out = append(out, buf[:n]...)
		addr += uint64(n)
		if err != nil || n == 0 {
			break
		}
	}
	return string(out)
}

func traceePath(pid uint32, dirfd int32, addr uint64) string {
	p := traceeString(pid, addr)
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, "/") {
		return filepath.Clean(p)
	}
	base := traceeLink(pid, "cwd")
	if dirfd != atFdCwd {
		base = traceeLink(pid, fmt.Sprintf("fd/%d", dirfd))
	}
	if base == "" {
		return ""
	}
	return filepath.Join(base, p)
}

// decide returns 0 to let the kernel run the call, or the errno to answer instead.
func (d *dcDisk) decide(n *scNotif) syscall.Errno {
	d.mu.Lock()
	defer d.mu.Unlock()
	a := n.Args
	switch n.Nr {
	case syscall.SYS_FSYNC, syscall.SYS_FDATASYNC:
		path := traceeLink(n.PID, fmt.Sprintf("fd/%d", int32(a[0])))
		if path == "" || !d.under(path) {
			return 0
		}
		if d.gone {
			d.stats.SyncsOnGone++
			return syscall.EIO
		}
		if d.failSync {
			d.stats.SyncsFailed++
			return syscall.EIO
		}
		d.stats.Syncs++
		d.recordSync(n.PID, int32(a[0]), path)
	case syscall.SYS_OPEN, syscall.SYS_CREAT, syscall.SYS_MKDIR, syscall.SYS_UNLINK, syscall.SYS_RMDIR:
		return d.pathOp(traceePath(n.PID, atFdCwd, a[0]))
	case syscall.SYS_OPENAT, syscall.SYS_MKDIRAT, syscall.SYS_UNLINKAT, 437:
		return d.pathOp(traceePath(n.PID, int32(a[0]), a[1]))
	case syscall.SYS_RENAME:
		return d.renameOp(traceePath(n.PID, atFdCwd, a[0]), traceePath(n.PID, atFdCwd, a[1]))
	case syscall.SYS_RENAMEAT, 316:
		return d.renameOp(traceePath(n.PID, int32(a[0]), a[1]), traceePath(n.PID, int32(a[2]), a[3]))
	}
	return 0
}

func (d *dcDisk) pathOp(p string) syscall.Errno {
	if p != "" && d.gone && d.under(p) {
		d.stats.PathOpsDenied++
		return syscall.EIO
	}
	return 0
}

func (d *dcDisk) recordSync(pid uint32, fd int32, path string) {
	st, err := os.Stat(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil {
		return
	}
	if st.IsDir() {
		names, err := dirNames(path)
		if err != nil {
			return
		}
		d.dirs[path] = names
		d.stats.DirSyncs++
		for _, r := range d.renames {
			if filepath.Dir(r.dst) == path {
				r.dstDone = true
			}
			if filepath.Dir(r.src) == path {
				r.srcDone = true
			}
		}
		return
	}
	d.files[path] = st.Size()
}

func (d *dcDisk) renameOp(src, dst string) syscall.Errno {
	if src == "" || dst == "" || !(d.under(src) || d.under(dst)) {
		return 0
	}
	if d.gone {
		d.stats.PathOpsDenied++
		return syscall.EIO
	}
	d.stats.Renames++
	r := &dcRename{src: src, dst: dst}
	if st, err := os.Lstat(dst); err == nil && st.Mode().IsRegular() {
		d.seq++
		r.shadow = filepath.Join(d.shadow, fmt.Sprintf("r%d", d.seq))
		if os.Link(dst, r.shadow) != nil {
			r.shadow = ""
		}
		r.oldSize = d.files[dst]
	}
	d.files[dst] = d.files[src]
	delete(d.files, src)
	d.renames = append(d.renames, r)
	return 0
}

// dcCutStats says what a simulated power cut removed.
type dcCutStats struct {
	RenamesUndone, EntriesRemoved, FilesTruncated int
	BytesLost                                     int64
}

// PowerCut rolls the disk back to what the dead member had made durable: renames whose directories
// were not fsynced are undone, directory entries created since the last fsync of their directory
// disappear, and file bytes beyond the last fsync of the file are lost. With torn the first half of
// the unsynced tail survives instead (a power cut that landed mid-write: a torn tail record).
// The member MUST be dead (its process group killed and reaped) before this is called.
func (d *dcDisk) PowerCut(torn bool) (dcCutStats, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var s dcCutStats
	for i := len(d.renames) - 1; i >= 0; i-- {
		r := d.renames[i]
		if r.srcDone && r.dstDone {
			continue
		}
		if _, err := os.Lstat(r.dst); err == nil {
			if _, serr := os.Lstat(r.src); os.IsNotExist(serr) {
				if err = os.Rename(r.dst, r.src); err != nil {
					return s, err
				}
				d.files[r.src] = d.files[r.dst]
				delete(d.files, r.dst)
				s.RenamesUndone++
			}
		}
		if r.shadow != "" {
			if _, err := os.Lstat(r.dst); os.IsNotExist(err) {
				if err = os.Link(r.shadow, r.dst); err != nil {
					return s, err
				}
				d.files[r.dst] = r.oldSize
			}
		}
	}
	d.renames = nil
	var walk func(dir string) error
	walk = func(dir string) error {
		want, known := d.dirs[dir]
		ents, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range ents {
			p := filepath.Join(dir, e.Name())
			if _, ok := want[e.Name()]; known && !ok {
				if err = os.RemoveAll(p); err != nil {
					return err
				}
				s.EntriesRemoved++
				continue
			}
			if e.IsDir() {
				if err = walk(p); err != nil {
					return err
				}
				continue
			}
			info, err := e.Info()
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			keep := d.files[p]
			if torn && info.Size() > keep {
				keep += (info.Size() - keep) / 2
			}
			if info.Size() > keep {
				if err = os.Truncate(p, keep); err != nil {
					return err
				}
				s.FilesTruncated++
				s.BytesLost += info.Size() - keep
			}
		}
		return nil
	}
	if err := walk(d.root); err != nil {
		return s, err
	}
	return s, nil
}

// dcSpawnFaulted starts the real binary under the injector and returns the running command; the
// supervisor of disk is attached before this returns.
func dcSpawnFaulted(disk *dcDisk, binary string, args []string, out io.Writer) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parent := fds[0]
	child := os.NewFile(uintptr(fds[1]), "drill-fault-sock")
	cmd := exec.Command(self)
	cmd.Args = append([]string{self, binary}, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), dcFaultExecEnv + "=1"}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.ExtraFiles = []*os.File{child}
	dcOwnGroup(cmd)
	if err = disk.rebaseline(); err != nil {
		child.Close()
		syscall.Close(parent)
		return nil, err
	}
	err = cmd.Start()
	child.Close()
	if err != nil {
		syscall.Close(parent)
		return nil, err
	}
	defer syscall.Close(parent)
	_ = unix.SetsockoptTimeval(parent, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 20})
	buf, oob := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
	n, oobn, _, _, err := syscall.Recvmsg(parent, buf, oob, 0)
	if err != nil || n == 0 {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("fault injector helper did not hand over its listener: %v", err)
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) == 0 {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, errors.New("fault injector helper sent no listener")
	}
	rights, err := syscall.ParseUnixRights(&msgs[0])
	if err != nil || len(rights) != 1 {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, errors.New("fault injector helper sent a malformed listener")
	}
	disk.attach(rights[0])
	return cmd, nil
}

// dcKillGroup SIGKILLs the whole process group of a started member.
func dcKillGroup(cmd *exec.Cmd) error {
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if err == syscall.ESRCH {
		return nil
	}
	return err
}

// dcOwnGroup puts a member in its own process group so a power cut reaches everything it started.
func dcOwnGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

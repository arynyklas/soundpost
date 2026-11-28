//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// Boundary pins for the checked target (l4w33 mutation battery D): the build ID read out of an executable, the bounded
// metadata reads, the cgroup identity, and every way openCheckedTarget refuses a process that is not the authorized one.

// tgtNote is one ELF note: name, descriptor, type.
func tgtNote(name string, desc []byte, typ uint32) []byte {
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, uint32(len(name)))
	b = binary.LittleEndian.AppendUint32(b, uint32(len(desc)))
	b = binary.LittleEndian.AppendUint32(b, typ)
	b = append(b, name...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	b = append(b, desc...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

type tgtSegment struct {
	typ    uint32
	offset uint64
	size   uint64
}

// tgtELF writes a 64-bit little endian ELF header, then the program headers, then data, to a temporary file. Fields of
// the header can be overridden.
func tgtELF(t *testing.T, segments []tgtSegment, data []byte, edit func(header []byte)) *os.File {
	t.Helper()
	const phOffset = 64
	b := make([]byte, 64+56*len(segments))
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint64(b[32:], phOffset)
	binary.LittleEndian.PutUint16(b[54:], 56)
	binary.LittleEndian.PutUint16(b[56:], uint16(len(segments)))
	for i, s := range segments {
		ph := b[phOffset+56*i:]
		binary.LittleEndian.PutUint32(ph, s.typ)
		binary.LittleEndian.PutUint64(ph[8:], s.offset)
		binary.LittleEndian.PutUint64(ph[32:], s.size)
	}
	if edit != nil {
		edit(b)
	}
	b = append(b, data...)
	path := filepath.Join(t.TempDir(), "x.elf")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// tgtNoteELF is an ELF whose single PT_NOTE segment holds the notes.
func tgtNoteELF(t *testing.T, notes ...[]byte) *os.File {
	t.Helper()
	data := bytes.Join(notes, nil)
	return tgtELF(t, []tgtSegment{{4, 64 + 56, uint64(len(data))}}, data, nil)
}

func TestExecutableBuildIDIsTheDescriptorOfTheGNUBuildIDNote(t *testing.T) {
	id := bytes.Repeat([]byte{0xab, 0x12}, 10)
	if got, err := executableBuildID(tgtNoteELF(t, tgtNote("GNU\x00", id, 3))); err != nil || got != hex.EncodeToString(id) {
		t.Fatalf("%q %v", got, err)
	}
	// descriptors of 1 and 64 bytes are build IDs, 0 and 65 are not
	for n, ok := range map[int]bool{0: false, 1: true, 64: true, 65: false} {
		desc := bytes.Repeat([]byte{0x5a}, n)
		got, err := executableBuildID(tgtNoteELF(t, tgtNote("GNU\x00", desc, 3)))
		if ok && (err != nil || got != hex.EncodeToString(desc)) || !ok && !errors.Is(err, ErrAuthorization) {
			t.Errorf("a descriptor of %d bytes: %q %v", n, got, err)
		}
	}
	// the note that names the build is found behind others, and only a GNU note of type 3 is one
	other := tgtNote("GNU\x00", []byte{1, 2, 3, 4}, 1)
	foreign := tgtNote("XYZ\x00", id, 3)
	if got, err := executableBuildID(tgtNoteELF(t, other, foreign, tgtNote("GNU\x00", id, 3))); err != nil || got != hex.EncodeToString(id) {
		t.Fatalf("behind other notes: %q %v", got, err)
	}
	if _, err := executableBuildID(tgtNoteELF(t, other, foreign)); !errors.Is(err, ErrAuthorization) {
		t.Fatalf("no GNU build ID note: %v", err)
	}
	// the name need not carry its terminator
	if got, err := executableBuildID(tgtNoteELF(t, tgtNote("GNU", id, 3))); err != nil || got != hex.EncodeToString(id) {
		t.Fatalf("a name without terminator: %q %v", got, err)
	}
	// a note that claims more than the segment holds is invalid, not skipped
	truncated := tgtNote("GNU\x00", id, 3)
	if _, err := executableBuildID(tgtNoteELF(t, truncated[:len(truncated)-4])); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a truncated note: %v", err)
	}
	// every PT_NOTE segment is searched, not only the first
	data := tgtNote("GNU\x00", id, 3)
	two := tgtELF(t, []tgtSegment{{4, 64 + 56*3, 0}, {1, 0, 0}, {4, 64 + 56*3, uint64(len(data))}}, data, nil)
	if got, err := executableBuildID(two); err != nil || got != hex.EncodeToString(id) {
		t.Fatalf("the second note segment: %q %v", got, err)
	}
}

func TestExecutableBuildIDRefusesWhatIsNotALittleEndianELF64WithinItsBounds(t *testing.T) {
	data := tgtNote("GNU\x00", []byte{1, 2, 3, 4}, 3)
	segment := []tgtSegment{{4, 64 + 56, uint64(len(data))}}
	refused := map[string]func([]byte){
		"no magic":              func(h []byte) { h[1] = 'X' },
		"32-bit":                func(h []byte) { h[4] = 1 },
		"big endian":            func(h []byte) { h[5] = 2 },
		"no program headers":    func(h []byte) { binary.LittleEndian.PutUint16(h[56:], 0) },
		"129 program headers":   func(h []byte) { binary.LittleEndian.PutUint16(h[56:], 129) },
		"a program header size": func(h []byte) { binary.LittleEndian.PutUint16(h[54:], 57) },
		"headers beyond 1 GiB":  func(h []byte) { binary.LittleEndian.PutUint64(h[32:], 1<<30+1) },
	}
	for name, edit := range refused {
		if got, err := executableBuildID(tgtELF(t, segment, data, edit)); !errors.Is(err, ErrAuthorization) {
			t.Errorf("%s: %q %v, want ErrAuthorization", name, got, err)
		}
	}
	// 128 program headers are fine (the note is behind 127 others), the bound itself is accepted
	many := make([]tgtSegment, 128)
	for i := range many {
		many[i] = tgtSegment{1, 0, 0}
	}
	many[127] = tgtSegment{4, uint64(64 + 56*128), uint64(len(data))}
	if got, err := executableBuildID(tgtELF(t, many, data, nil)); err != nil || got != "01020304" {
		t.Fatalf("128 program headers: %q %v", got, err)
	}
	// headers at exactly 1 GiB are within the bound: the read then fails for lack of a file, it is not the bound
	if _, err := executableBuildID(tgtELF(t, segment, data, func(h []byte) { binary.LittleEndian.PutUint64(h[32:], 1<<30) })); errors.Is(err, ErrAuthorization) || err == nil {
		t.Fatalf("headers at exactly 1 GiB: %v, want a failed read", err)
	}
	// notes: 64 KiB is the bound for a segment, one more byte is refused, and the start may be at most 1 TiB
	pad := make([]byte, 65536)
	copy(pad, tgtNote("GNU\x00", []byte{1, 2, 3, 4}, 3))
	if got, err := executableBuildID(tgtELF(t, []tgtSegment{{4, 64 + 56, 65536}}, pad, nil)); err != nil || got != "01020304" {
		t.Fatalf("a note segment of 64 KiB: %q %v", got, err)
	}
	if _, err := executableBuildID(tgtELF(t, []tgtSegment{{4, 64 + 56, 65537}}, pad, nil)); !errors.Is(err, ErrAuthorization) {
		t.Fatalf("a note segment of 64 KiB and one byte: %v", err)
	}
	if _, err := executableBuildID(tgtELF(t, []tgtSegment{{4, 1<<40 + 1, 8}}, data, nil)); !errors.Is(err, ErrAuthorization) {
		t.Fatalf("a note segment starting beyond 1 TiB: %v", err)
	}
	if _, err := executableBuildID(tgtELF(t, []tgtSegment{{4, 1 << 40, 8}}, data, nil)); errors.Is(err, ErrAuthorization) || err == nil {
		t.Fatalf("a note segment starting at exactly 1 TiB: %v, want a failed read", err)
	}
	// a file too short for its own header
	short := filepath.Join(t.TempDir(), "short")
	if err := os.WriteFile(short, []byte{0x7f, 'E', 'L', 'F'}, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(short)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = executableBuildID(f); err == nil {
		t.Fatal("a truncated header was read")
	}
}

// Metadata files are read up to 64 KiB: that much is fine, one byte more is invalid.
func TestReadProcMetadataIsBoundedTo64KiB(t *testing.T) {
	dir := t.TempDir()
	for name, n := range map[string]int{"exact": 65536, "over": 65537, "empty": 0} {
		if err := os.WriteFile(filepath.Join(dir, name), bytes.Repeat([]byte("a"), n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if b, err := readProcMetadata(fd, "exact"); err != nil || len(b) != 65536 {
		t.Fatalf("64 KiB: %d %v", len(b), err)
	}
	if b, err := readProcMetadata(fd, "empty"); err != nil || len(b) != 0 {
		t.Fatalf("empty: %d %v", len(b), err)
	}
	if b, err := readProcMetadata(fd, "over"); !errors.Is(err, ErrInvalid) || b != nil {
		t.Fatalf("64 KiB and a byte: %d %v", len(b), err)
	}
	if b, err := readProcMetadata(fd, "missing"); !errors.Is(err, syscall.ENOENT) || b != nil {
		t.Fatalf("a missing file: %d bytes, %v, want the open failure itself (ENOENT)", len(b), err)
	}
}

// The cgroup identity is the inode of the directory the "0::" line names under the cgroup2 mount; the first such line
// counts, a line of a v1 hierarchy never does, and nothing that leaves the hierarchy or is not there is an identity.
func TestCgroupIdentityIsTheInodeOfTheCgroupTheUnifiedLineNames(t *testing.T) {
	root, err := openCgroup2Root()
	if err != nil {
		t.Skipf("no cgroup2 hierarchy here: %v", err)
	}
	defer syscall.Close(root)
	var st syscall.Stat_t
	if err = syscall.Fstat(root, &st); err != nil {
		t.Fatal(err)
	}
	if got, err := cgroupIdentity([]byte("0::/\n")); err != nil || got != st.Ino {
		t.Fatalf("the root: %d %v, want inode %d", got, err, st.Ino)
	}
	own, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	want, err := cgroupIdentity(own)
	if err != nil {
		t.Skipf("the process's own cgroup is not under the cgroup2 mount here: %v", err)
	}
	var path string
	for _, line := range bytes.Split(own, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("0::/")) {
			path = string(line[3:])
			break
		}
	}
	if dir, err := syscall.Open(root2path(t, root)+path, syscall.O_RDONLY|syscall.O_DIRECTORY, 0); err == nil {
		var dirStat syscall.Stat_t
		if syscall.Fstat(dir, &dirStat) == nil && dirStat.Ino != want {
			t.Errorf("own cgroup %q: inode %d, the directory has %d", path, want, dirStat.Ino)
		}
		syscall.Close(dir)
	}
	// the first unified line wins, v1 lines and other text are ignored
	if got, err := cgroupIdentity([]byte("12:cpu:/ignored\n0::" + path + "\n0::/nonexistent-" + strconv.Itoa(os.Getpid()) + "\n")); err != nil || got != want {
		t.Fatalf("the first unified line: %d %v, want %d", got, err, want)
	}
	// lines that are no unified hierarchy at all, and paths that leave it or are not there
	for name, b := range map[string]string{
		"empty":                  "",
		"only a v1 hierarchy":    "12:cpu,cpuacct:/x\n",
		"0:: without a slash":    "0::x\n",
		"a path that is not":     "0::/nonexistent-" + strconv.Itoa(os.Getpid()) + "/child\n",
		"a dot component":        "0::/./x\n",
		"a parent component":     "0::/x/../y\n",
		"a parent after the dot": "0::/.\n",
	} {
		if got, err := cgroupIdentity([]byte(b)); err == nil {
			t.Errorf("%s: accepted (%d)", name, got)
		}
	}
	// a path that leaves the hierarchy, or no unified line at all, is an authorization error and not a failed read
	for _, b := range []string{"0::/../x\n", "0::/./x\n", "", "7:foo:/bar\n", "0::x\n"} {
		if _, err := cgroupIdentity([]byte(b)); !errors.Is(err, ErrAuthorization) {
			t.Errorf("%q: %v, want ErrAuthorization", b, err)
		}
	}
}

// root2path is the path of an open directory FD as the kernel names it.
func root2path(t *testing.T, fd int) string {
	t.Helper()
	p, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return "/nonexistent"
	}
	return p
}

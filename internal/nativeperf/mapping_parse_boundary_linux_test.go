//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Boundary pins for the /proc/<pid>/maps parser and the mapped-file opener (l4w33 mutation battery D).

func TestMapPathDecodesOnlyTheEscapesTheKernelWrites(t *testing.T) {
	for raw, want := range map[string]string{
		"/usr/lib/libx.so":    "/usr/lib/libx.so",
		`/with\040space`:      "/with space",
		`/back\134slash`:      `/back\slash`,
		`\040`:                " ",
		`/a\040\040b`:         "/a  b",
		`/ends\040`:           "/ends ",
		"/non-ascii-\xc3\xa9": "/non-ascii-\xc3\xa9",
		"":                    "",
	} {
		if got, err := mapPath(raw); err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", raw, got, err, want)
		}
	}
	for name, raw := range map[string]string{
		"an unknown escape":                    `/a\101b`,
		"an escape cut short":                  `/a\04`,
		"an escape cut short at one digit":     `/a\0`,
		"a bare backslash at the end":          `/a\`,
		"a tab escape (a tab is no path text)": `/a\011b`,
		"a newline escape":                     `/a\012b`,
		"a raw tab":                            "/a\tb",
		"a raw newline":                        "/a\nb",
		"a raw carriage return":                "/a\rb",
		"a raw NUL":                            "/a\x00b",
	} {
		if got, err := mapPath(raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %q %v, want ErrInvalid", name, got, err)
		}
	}
	long := "/" + strings.Repeat("a", 4095)
	if got, err := mapPath(long); err != nil || got != long {
		t.Errorf("4096 bytes: %d %v", len(got), err)
	}
	if _, err := mapPath(long + "a"); !errors.Is(err, ErrInvalid) {
		t.Errorf("4097 bytes: %v", err)
	}
}

func TestValidMappedPathIsAnAbsolutePathOfPlainNamedComponents(t *testing.T) {
	for _, path := range []string{"/a", "/a/b", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/...", "/a/.hidden", "/" + strings.Repeat("a", 4095)} {
		if !validMappedPath(path) {
			t.Errorf("%q refused", path)
		}
	}
	for _, path := range []string{"", "/", "a", "a/b", "/a/", "//a", "/a//b", "/a/./b", "/./a", "/a/..", "/../a", "/a/../b", "/a\\b", "/a\nb", "/a\rb", "/a\x00b", "/" + strings.Repeat("a", 4096)} {
		if validMappedPath(path) {
			t.Errorf("%q accepted", path)
		}
	}
}

const mapsLine = "7f0000000000-7f0000001000 r-xp 00001000 08:01 1234                      /usr/lib/libx.so\n"

func TestParseExecutableMapsReadsTheColumnsOfAnExecutableMapping(t *testing.T) {
	got, err := parseExecutableMaps([]byte(mapsLine), 1<<20, 16)
	if err != nil || len(got) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	m := got[0]
	if m.start != 0x7f0000000000 || m.end != 0x7f0000001000 || m.offset != 0x1000 || m.device != 0x801 || m.inode != 1234 || m.path != "/usr/lib/libx.so" || m.reason != "" {
		t.Fatalf("%+v", m)
	}
	// the device number is the kernel's dev_t: 12 bits of major and 8 of minor below, the rest above
	for _, tc := range []struct {
		dev  string
		want uint64
	}{
		{"08:11", 0x811}, {"103:00", 0x10300}, {"00:2f", 0x2f}, {"fff:ff", 0xfffff},
		{"1000:100", 0x1000<<32 | 0x100<<12}, {"1001:101", 0x1000<<32 | 0x100<<12 | 0x1<<8 | 0x1},
	} {
		line := "1000-2000 r-xp 0 " + tc.dev + " 5 /x\n"
		got, err := parseExecutableMaps([]byte(line), 1<<20, 16)
		if err != nil || len(got) != 1 || got[0].device != tc.want {
			t.Errorf("device %s: %+v %v, want %#x", tc.dev, got, err, tc.want)
		}
	}
	// only executable mappings are returned; the rest are validated and skipped
	text := "1000-2000 r--p 0 08:01 5 /a\n2000-3000 rw-p 0 08:01 5 /a\n3000-4000 r-xp 0 08:01 5 /a\n4000-5000 ---s 0 08:01 5 /a\n5000-6000 rwxs 0 08:01 6 /b\n"
	got, err = parseExecutableMaps([]byte(text), 1<<20, 16)
	if err != nil || len(got) != 2 || got[0].start != 0x3000 || got[1].start != 0x5000 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestParseExecutableMapsClassifiesWhatIsNotAFileOnDisk(t *testing.T) {
	for name, tc := range map[string]struct {
		line   string
		reason FrameReason
		path   string
	}{
		"no path":                 {"1000-2000 r-xp 0 00:00 0\n", FrameJITMissing, ""},
		"no path, trailing pad":   {"1000-2000 r-xp 0 00:00 0                       \n", FrameJITMissing, ""},
		"a pseudo path":           {"1000-2000 r-xp 0 00:00 0 [vdso]\n", FrameJITMissing, ""},
		"a path of inode zero":    {"1000-2000 r-xp 0 08:01 0 /memfd:x\n", FrameJITMissing, ""},
		"a deleted file":          {"1000-2000 r-xp 0 08:01 7 /tmp/x (deleted)\n", FrameDeleted, ""},
		"a named file":            {"1000-2000 r-xp 0 08:01 7 /tmp/x\n", "", "/tmp/x"},
		"a file with a space":     {"1000-2000 r-xp 0 08:01 7 /tmp/a\\040b\n", "", "/tmp/a b"},
		"a path starting a space": {"1000-2000 r-xp 0 08:01 7  \t /tmp/x\n", "", "/tmp/x"},
	} {
		got, err := parseExecutableMaps([]byte(tc.line), 1<<20, 16)
		if err != nil || len(got) != 1 || got[0].reason != tc.reason || got[0].path != tc.path {
			t.Errorf("%s: %+v %v, want reason %q path %q", name, got, err, tc.reason, tc.path)
		}
	}
}

func TestParseExecutableMapsRefusesAMapsFileThatIsNotWellFormed(t *testing.T) {
	good := "1000-2000 r-xp 0 08:01 7 /a\n"
	for name, text := range map[string]string{
		"no final newline":                               "1000-2000 r-xp 0 08:01 7 /a",
		"an empty line":                                  good + "\n" + good,
		"too few columns":                                "1000-2000 r-xp 0 08:01\n",
		"a range without a dash":                         "10002000 r-xp 0 08:01 7 /a\n",
		"a range with two dashes":                        "1000-2000-3000 r-xp 0 08:01 7 /a\n",
		"an empty range":                                 "1000-1000 r-xp 0 08:01 7 /a\n",
		"a reversed range":                               "2000-1000 r-xp 0 08:01 7 /a\n",
		"a start that is not hex":                        "zz00-2000 r-xp 0 08:01 7 /a\n",
		"an end that is not hex":                         "1000-zz00 r-xp 0 08:01 7 /a\n",
		"an offset that is not hex":                      "1000-2000 r-xp zz 08:01 7 /a\n",
		"a device without a colon":                       "1000-2000 r-xp 0 0801 7 /a\n",
		"a device with two colons":                       "1000-2000 r-xp 0 08:01:02 7 /a\n",
		"a major that is not hex":                        "1000-2000 r-xp 0 zz:01 7 /a\n",
		"a major beyond 32 bits":                         "1000-2000 r-xp 0 100000000:01 7 /a\n",
		"a minor that is not hex":                        "1000-2000 r-xp 0 08:zz 7 /a\n",
		"a minor beyond 32 bits":                         "1000-2000 r-xp 0 08:100000000 7 /a\n",
		"an inode that is not a number":                  "1000-2000 r-xp 0 08:01 x /a\n",
		"an inode in hex":                                "1000-2000 r-xp 0 08:01 1f /a\n",
		"permissions of three characters":                "1000-2000 r-x 0 08:01 7 /a\n",
		"permissions of five characters":                 "1000-2000 r-xpp 0 08:01 7 /a\n",
		"an unknown read bit":                            "1000-2000 x-xp 0 08:01 7 /a\n",
		"an unknown write bit":                           "1000-2000 rxxp 0 08:01 7 /a\n",
		"an unknown execute bit":                         "1000-2000 r-rp 0 08:01 7 /a\n",
		"an unknown sharing bit":                         "1000-2000 r-xq 0 08:01 7 /a\n",
		"a mapping that overlaps the last":               good + "1fff-3000 r-xp 0 08:01 7 /a\n",
		"mappings out of order":                          "3000-4000 r-xp 0 08:01 7 /a\n1000-2000 r-xp 0 08:01 7 /a\n",
		"an offset that wraps":                           "1000-2000 r-xp ffffffffffffff01 08:01 7 /a\n",
		"a path that is not a plain path":                "1000-2000 r-xp 0 08:01 7 /a/../b\n",
		"a path with an unknown escape":                  "1000-2000 r-xp 0 08:01 7 /a\\101\n",
		"a path with a trailing slash":                   "1000-2000 r-xp 0 08:01 7 /a/\n",
		"a path of one slash":                            "1000-2000 r-xp 0 08:01 7 /\n",
		"a bad line behind a skipped mapping":            "1000-2000 r--p 0 08:01 7 /a\nzz-2000 r-xp 0 08:01 7 /a\n",
		"a bad line of a mapping that is not executable": "1000-2000 rw-p 0 08:01 x /a\n",
	} {
		if got, err := parseExecutableMaps([]byte(text), 1<<20, 16); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %+v %v, want ErrInvalid", name, got, err)
		}
	}
	// ... but touching mappings, an offset that just fits and every legal permission are fine
	for name, text := range map[string]string{
		"touching mappings":          good + "2000-3000 r-xp 0 08:01 7 /a\n",
		"the largest offset":         "1000-2000 r-xp ffffffffffffefff 08:01 7 /a\n",
		"every read/write/exec form": "1000-2000 --xp 0 08:01 7 /a\n2000-3000 rwxs 0 08:01 7 /a\n3000-4000 ---p 0 08:01 7 /a\n",
	} {
		if _, err := parseExecutableMaps([]byte(text), 1<<20, 16); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseExecutableMapsIsBoundedInBytesLinesAndMappings(t *testing.T) {
	line := "1000-2000 r-xp 0 08:01 7 /a\n"
	if _, err := parseExecutableMaps([]byte(line), uint64(len(line)), 1); err != nil {
		t.Fatalf("exactly the byte bound: %v", err)
	}
	if _, err := parseExecutableMaps([]byte(line), uint64(len(line))-1, 1); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("one byte over the bound: %v", err)
	}
	// executable mappings count against the bound, the others do not
	two := "1000-2000 r-xp 0 08:01 7 /a\n2000-3000 rw-p 0 08:01 7 /a\n3000-4000 r-xp 0 08:01 7 /b\n"
	if got, err := parseExecutableMaps([]byte(two), 1<<20, 2); err != nil || len(got) != 2 {
		t.Fatalf("two executable mappings and a bound of two: %+v %v", got, err)
	}
	if _, err := parseExecutableMaps([]byte(two), 1<<20, 1); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("a bound of one: %v", err)
	}
	if _, err := parseExecutableMaps([]byte(two), 1<<20, 0); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("a bound of none: %v", err)
	}
	// a line is at most 8192 bytes (the newline not counted)
	pad := func(n int) string {
		head := "1000-2000 r-xp 0 08:01 7"
		return head + strings.Repeat(" ", n-len(head)-len("/a")) + "/a\n"
	}
	if got, err := parseExecutableMaps([]byte(pad(8192)), 1<<20, 1); err != nil || len(got) != 1 {
		t.Fatalf("a line of 8192 bytes: %+v %v", got, err)
	}
	if _, err := parseExecutableMaps([]byte(pad(8193)), 1<<20, 1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a line of 8193 bytes: %v", err)
	}
	// nothing at all is no mappings
	if got, err := parseExecutableMaps(nil, 1<<20, 1); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("an empty file: %+v %v", got, err)
	}
}

// A mapped file is opened below a root directory, one component at a time and never through a symbolic link, and only
// when it is a regular file.
func TestOpenMappedPathNeverFollowsALinkAndOnlyOpensRegularFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "d", "e"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"d/e/lib.so", "d/top.so", "file"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "d", "e"), filepath.Join(dir, "linkdir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "file"), filepath.Join(dir, "linkfile")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(root)
	for _, path := range []string{"/d/e/lib.so", "/d/top.so", "/file"} {
		f, err := openMappedPath(root, path)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		var st, want syscall.Stat_t
		if syscall.Fstat(int(f.Fd()), &st) != nil || syscall.Stat(filepath.Join(dir, path), &want) != nil || st.Ino != want.Ino {
			t.Errorf("%s: opened another file", path)
		}
		f.Close()
	}
	for name, path := range map[string]string{
		"a link as a directory": "/linkdir/lib.so",
		"a link as the file":    "/linkfile",
		"a directory":           "/d/e",
		"a fifo":                "/fifo",
		"a missing file":        "/d/e/missing.so",
		"a file as a directory": "/file/x",
	} {
		before := openFDs(t)
		if f, err := openMappedPath(root, path); !errors.Is(err, ErrTargetIdentity) || f != nil {
			t.Errorf("%s: %v %v, want ErrTargetIdentity", name, f, err)
		}
		if after := openFDs(t); after != before {
			t.Errorf("%s: %d descriptors open after the refusal, %d before", name, after, before)
		}
	}
	for _, path := range []string{"", "/", "d/e/lib.so", "/d/../file", "/d//top.so"} {
		if f, err := openMappedPath(root, path); !errors.Is(err, ErrInvalid) || f != nil {
			t.Errorf("%q: %v %v, want ErrInvalid", path, f, err)
		}
	}
	if f, err := openMappedPath(-1, "/file"); !errors.Is(err, ErrTargetIdentity) || f != nil {
		t.Errorf("a root that is not open: %v %v", f, err)
	}
}

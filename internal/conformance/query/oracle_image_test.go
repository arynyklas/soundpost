// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const fakeRuntimeScript = `#!/bin/bash
D=%q
echo "$@" >> "$D/calls"
case "$1 $2" in
"image inspect")
  ref=${@: -1}
  if [ "$3" = "--format" ]; then
    if [ -f "$D/present/$ref" ]; then echo "$ref"; exit 0; fi
    echo "Error response from daemon: No such image: $ref" >&2; exit 1
  fi
  if [ -f "$D/tags/$ref" ]; then cat "$D/tags/$ref"; exit 0; fi
  echo "Error response from daemon: No such image: $ref" >&2; exit 1 ;;
esac
case "$1" in
create) echo %s ;;
cp) src=${3#*:}; tar -cf - -C "$D/fs$(dirname "$src")" "$(basename "$src")" ;;
rm) ;;
*) echo "unsupported: $*" >&2; exit 2 ;;
esac
`

type fakeDaemon struct {
	t       *testing.T
	dir     string
	runtime string
}

func newFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake runtime is a bash script")
	}
	dir := t.TempDir()
	cid := strings.Repeat("c", 64)
	script := filepath.Join(dir, "docker")
	if err := os.WriteFile(script, []byte(fmt.Sprintf(fakeRuntimeScript, dir, cid)), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"present", "tags", "fs"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &fakeDaemon{t: t, dir: dir, runtime: script}
}

func (d *fakeDaemon) hasLocked(id string) {
	d.t.Helper()
	if err := os.WriteFile(filepath.Join(d.dir, "present", id), nil, 0o644); err != nil {
		d.t.Fatal(err)
	}
}

func (d *fakeDaemon) tag(tag, id, platformOS, arch string, entrypoint ...string) {
	d.t.Helper()
	body := fmt.Sprintf(`[{"Id":%q,"Os":%q,"Architecture":%q,"Config":{"Entrypoint":[%s]}}]`, id, platformOS, arch, quoteAll(entrypoint))
	if err := os.WriteFile(filepath.Join(d.dir, "tags", tag), []byte(body), 0o644); err != nil {
		d.t.Fatal(err)
	}
}

func quoteAll(values []string) string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = fmt.Sprintf("%q", v)
	}
	return strings.Join(out, ",")
}

func (d *fakeDaemon) file(p, content string) string {
	d.t.Helper()
	full := filepath.Join(d.dir, "fs", filepath.FromSlash(p))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		d.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		d.t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func (d *fakeDaemon) calls() []string {
	raw, _ := os.ReadFile(filepath.Join(d.dir, "calls"))
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func (d *fakeDaemon) created() bool {
	for _, c := range d.calls() {
		if strings.HasPrefix(c, "create ") {
			return true
		}
	}
	return false
}

const (
	lockedImage  = "sha256:6234d450fe5c3770af5c0a3d20adff668e4594d3abd626a29d626a73ab69d417"
	rebuiltImage = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	oracleTag    = "soundpost-oracle-promql-prometheus-3.1.0:current"
)

func rebuiltFixture(t *testing.T) (*fakeDaemon, *ContentIdentity) {
	d := newFakeDaemon(t)
	d.tag(oracleTag, rebuiltImage, "linux", "amd64", "/adapter", "adapter", "promql-prometheus-3.1.0")
	want := &ContentIdentity{
		Architecture: "linux/amd64",
		Entrypoint:   []string{"/adapter", "adapter", "promql-prometheus-3.1.0"},
		Files: []ImageFile{
			{Path: "/evaluation-reference", SHA256: d.file("/evaluation-reference", "driver bytes")},
			{Path: "/bin/prometheus", SHA256: d.file("/bin/prometheus", "upstream bytes")},
		},
	}
	return d, want
}

func TestOracleImageResolvesTheLockedIdWhereTheDaemonHoldsIt(t *testing.T) {
	d, want := rebuiltFixture(t)
	d.hasLocked(lockedImage)
	ref, rebuilt, err := resolveOracleImage(context.Background(), d.runtime, lockedImage, oracleTag, want)
	if err != nil || ref != lockedImage || rebuilt {
		t.Fatalf("got %q rebuilt=%v err=%v, want the locked id untouched", ref, rebuilt, err)
	}
	if d.created() {
		t.Fatal("a daemon that holds the locked id must not be asked to prove another image")
	}
}

func TestOracleImageAcceptsARebuiltImageOnlyAfterProvingItsFiles(t *testing.T) {
	d, want := rebuiltFixture(t)
	ref, rebuilt, err := resolveOracleImage(context.Background(), d.runtime, lockedImage, oracleTag, want)
	if err != nil || ref != rebuiltImage || !rebuilt {
		t.Fatalf("got %q rebuilt=%v err=%v, want the rebuilt image id", ref, rebuilt, err)
	}
	if !d.created() {
		t.Fatal("the rebuilt image was accepted without proving its files")
	}
	before := len(d.calls())
	if ref, rebuilt, err = resolveOracleImage(context.Background(), d.runtime, lockedImage, oracleTag, want); err != nil || ref != rebuiltImage || !rebuilt {
		t.Fatalf("second resolution: %q %v %v", ref, rebuilt, err)
	}
	if len(d.calls()) != before {
		t.Fatalf("a proven image is proven once per process, calls grew from %d to %d", before, len(d.calls()))
	}
}

func TestOracleImageRefusesARebuiltImageWhoseFileDiffers(t *testing.T) {
	d, want := rebuiltFixture(t)
	d.file("/bin/prometheus", "another upstream build")
	_, _, err := resolveOracleImage(context.Background(), d.runtime, lockedImage, oracleTag, want)
	if err == nil || !strings.Contains(err.Error(), "/bin/prometheus") || !strings.Contains(err.Error(), "not the pinned oracle") {
		t.Fatalf("a changed upstream binary was accepted or misreported: %v", err)
	}
}

func TestOracleImageRefusesAnotherPlatformOrEntrypoint(t *testing.T) {
	d, want := rebuiltFixture(t)
	d.tag(oracleTag, rebuiltImage, "linux", "arm64", "/adapter", "adapter", "promql-prometheus-3.1.0")
	if _, _, err := resolveOracleImage(context.Background(), d.runtime, lockedImage, oracleTag, want); err == nil || !strings.Contains(err.Error(), "linux/arm64") {
		t.Fatalf("another platform accepted: %v", err)
	}
	d, want = rebuiltFixture(t)
	d.tag(oracleTag, rebuiltImage, "linux", "amd64", "/bin/sh")
	if _, _, err := resolveOracleImage(context.Background(), d.runtime, lockedImage, oracleTag, want); err == nil || !strings.Contains(err.Error(), "entrypoint") {
		t.Fatalf("another entrypoint accepted: %v", err)
	}
}

func TestOracleImageNamesTheBuildWhenNothingWasBuilt(t *testing.T) {
	d := newFakeDaemon(t)
	_, want := rebuiltFixture(t)
	_, _, err := resolveOracleImage(context.Background(), d.runtime, lockedImage, oracleTag, want)
	if err == nil || !strings.Contains(err.Error(), "build-images.sh") {
		t.Fatalf("an absent oracle must fail with the way to build it: %v", err)
	}
}

func TestOracleImageWithoutAContentIdentityKeepsTheLockedIdAndItsFailure(t *testing.T) {
	d := newFakeDaemon(t)
	d.tag(oracleTag, rebuiltImage, "linux", "amd64", "/adapter")
	ref, rebuilt, err := resolveOracleImage(context.Background(), d.runtime, lockedImage, oracleTag, nil)
	if err != nil || ref != lockedImage || rebuilt {
		t.Fatalf("got %q rebuilt=%v err=%v: an image without a content identity must never replace the locked id", ref, rebuilt, err)
	}
}

func TestOracleImageLeavesARuntimeThatCannotInspectUntouched(t *testing.T) {
	d := newFakeDaemon(t)
	script := filepath.Join(d.dir, "shim")
	if err := os.WriteFile(script, []byte("#!/bin/bash\n[ \"$1\" = run ] && exit 0\necho \"unsupported: $*\" >&2\nexit 2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, want := rebuiltFixture(t)
	ref, rebuilt, err := resolveOracleImage(context.Background(), script, lockedImage, oracleTag, want)
	if err != nil || ref != lockedImage || rebuilt {
		t.Fatalf("got %q rebuilt=%v err=%v: a runtime that is not a docker CLI keeps the locked id (the native shim)", ref, rebuilt, err)
	}
}

func TestContentIdentityValidateRefusesWhatCannotPin(t *testing.T) {
	good := ContentIdentity{Architecture: "linux/amd64", Entrypoint: []string{"/adapter"}, Files: []ImageFile{{Path: "/a", SHA256: strings.Repeat("a", 64)}}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ContentIdentity){
		"no files":       func(c *ContentIdentity) { c.Files = nil },
		"no entrypoint":  func(c *ContentIdentity) { c.Entrypoint = nil },
		"platform":       func(c *ContentIdentity) { c.Architecture = "linux/arm64" },
		"relative path":  func(c *ContentIdentity) { c.Files[0].Path = "a" },
		"unclean path":   func(c *ContentIdentity) { c.Files[0].Path = "/x/../a" },
		"short digest":   func(c *ContentIdentity) { c.Files[0].SHA256 = "abc" },
		"duplicate path": func(c *ContentIdentity) { c.Files = append(c.Files, c.Files[0]) },
	} {
		c := good
		c.Files = append([]ImageFile(nil), good.Files...)
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The lock's content identities are what a daemon without the locked ids is held to; they must be
// complete and consistent with the rest of the lock.
func TestSourceLockContentIdentitiesAreCompleteAndConsistent(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	var lock SourceLock
	if err := ReadJSON(filepath.Join(root, "conformance/query/source-lock.json"), &lock); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSourceLock(lock); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "conformance/query/source-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var generic struct {
		Profiles []struct {
			ID               string `json:"id"`
			ReferenceCompile struct {
				Builder string `json:"builder_image"`
			} `json:"reference_compiler"`
		} `json:"profiles"`
	}
	if err = json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	builders := map[string]string{}
	for _, p := range generic.Profiles {
		builders[p.ID] = p.ReferenceCompile.Builder
	}
	for _, p := range lock.Profiles {
		b := builders[p.ID]
		if i := strings.LastIndex(b, "@sha256:"); i < 0 || !hex64.MatchString(b[i+len("@sha256:"):]) {
			t.Errorf("%s: reference_compiler.builder_image %q is not a digest-pinned image", p.ID, b)
		}
		ci := p.Artifact.ContentIdentity
		if ci == nil {
			t.Errorf("%s: no content identity for the oracle image", p.ID)
			continue
		}
		if want := []string{"/adapter", "adapter", p.ID}; strings.Join(ci.Entrypoint, " ") != strings.Join(want, " ") {
			t.Errorf("%s: entrypoint %v, want %v", p.ID, ci.Entrypoint, want)
		}
		files := map[string]string{}
		for _, f := range ci.Files {
			files[f.Path] = f.SHA256
		}
		reference := "/evaluation-reference"
		if strings.HasPrefix(p.ID, "logql-") {
			reference = "/logql-reference"
		}
		if files[reference] == "" {
			t.Errorf("%s: the reference driver %s is not pinned", p.ID, reference)
		}
		co := p.ConfigurationOracle
		if co == nil {
			continue
		}
		cc := co.ContentIdentity
		if cc == nil {
			t.Errorf("%s: no content identity for the configuration oracle image", p.ID)
			continue
		}
		if strings.Join(cc.Entrypoint, " ") != strings.Join(ci.Entrypoint, " ") {
			t.Errorf("%s: the configuration oracle must keep the evaluation oracle's entrypoint", p.ID)
		}
		variant := map[string]string{}
		for _, f := range cc.Files {
			variant[f.Path] = f.SHA256
		}
		for path, sum := range files {
			if variant[path] != sum {
				t.Errorf("%s: the configuration oracle is the evaluation oracle plus one file, but %s differs", p.ID, path)
			}
		}
		if len(variant) != len(files)+1 || variant[co.InstalledAt] != co.ConfigurationFileSHA256 {
			t.Errorf("%s: the configuration oracle must add exactly %s with the locked configuration file digest", p.ID, co.InstalledAt)
		}
	}
}

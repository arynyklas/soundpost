// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command release builds the Soundpost server distribution reproducibly:
//
//	go run ./build verify  [--root DIR] [--archive PATH]
//	go run ./build release --out DIR --version V [--commit SHA] [--arch amd64,arm64]
//	                       [--web-dist DIR] [--reproduce] [--cache DIR]
//
// verify proves the inputs: the pinned Go archive hash (build/toolchains.json), that the
// installed GOROOT is byte-for-byte that archive, go.sum module hashes (go mod verify, no
// network), and the hash-locked Python and pnpm inputs. release verifies first and refuses to
// build on any failure, then builds static linux binaries (CGO_ENABLED=0, -trimpath,
// -buildvcs=false, no build id) with the UI compiled in, checks they are static ELF, and
// writes SHA256SUMS and release.json without timestamps so the manifest is reproducible too.
// --reproduce builds everything a second time with an empty Go build cache and compares
// sha256 of every binary.
//
// Only linux/amd64 hosts are supported: the archive the compiler is proven against is the
// pinned linux-amd64 one. linux/arm64 binaries are cross-compiled.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"debug/elf"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/arynyklas/soundpost/internal/releaseevidence"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: release verify|release|artifacts|image-context|inventory|sbom|notices|gate|verify-signature|handles [flags]")
	}
	switch args[0] {
	case "verify":
		f := flag.NewFlagSet("verify", flag.ContinueOnError)
		root := f.String("root", ".", "repository root")
		archive := f.String("archive", "", "pinned Go archive (default .tools/go<version>.linux-amd64.tar.gz)")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		inputs, err := verifyInputs(*root, *archive)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(inputs)
	case "release":
		return runRelease(args[1:], out)
	case "artifacts":
		return runArtifacts(args[1:], out)
	case "image-context":
		return runImageContext(args[1:])
	case "source-digest":
		return runSourceDigest(args[1:], out)
	case "inventory":
		return runInventory(args[1:], out)
	case "sbom", "notices", "gate", "verify-signature", "handles":
		return runPackage(args[0], args[1:], out)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

// runSourceDigest prints releaseevidence.SourceDigest of --root: the identity producers stamp in their
// reports and `release` records as the first component of build_id.
func runSourceDigest(args []string, out io.Writer) error {
	f := flag.NewFlagSet("source-digest", flag.ContinueOnError)
	root := f.String("root", ".", "repository root")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("source-digest takes no arguments")
	}
	sum, err := releaseevidence.SourceDigest(*root)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, sum)
	return err
}

// releaseCommands are the shipped commands `release` builds (static, per architecture), in order.
// soundpost-perf-acquire is the native acquisition helper: it is packaged only by its own
// image (deploy/Dockerfile.perf-helper), never in the server image.
var releaseCommands = []string{"soundpost", "soundpost-agent", "soundpost-perf-acquire"}

// imageKind names one image the release packages: the release binary it carries, the Dockerfile
// that declares it, and whether it needs the (empty, runtime-owned) data directory in its context.
type imageKind struct {
	binary, dockerfile string
	dataDir            bool
}

var imageKinds = map[string]imageKind{
	"server":      {binary: "soundpost", dockerfile: "Dockerfile", dataDir: true},
	"perf-helper": {binary: "soundpost-perf-acquire", dockerfile: "Dockerfile.perf-helper"},
}

// listedBinary returns the release binary of an architecture and its sha256, only when the
// release's own SHA256SUMS lists exactly that content.
func listedBinary(release, arch, name string) (path, sum string, err error) {
	path = filepath.Join(release, "linux-"+arch, name)
	if sum, err = sha256File(path); err != nil {
		return "", "", err
	}
	sums, err := os.ReadFile(filepath.Join(release, "SHA256SUMS"))
	if err != nil {
		return "", "", err
	}
	if !strings.Contains(string(sums), sum+"  linux-"+arch+"/"+name+"\n") {
		return "", "", fmt.Errorf("the binary %s is not the one SHA256SUMS lists", name)
	}
	return path, sum, nil
}

// pins is the part of build/toolchains.json the release uses; the file is read, never rewritten.
type pins struct {
	Go struct {
		Version    string `json:"version"`
		LinuxAMD64 struct {
			URL    string `json:"url"`
			SHA256 string `json:"sha256"`
		} `json:"linux_amd64"`
		// LinuxARM64 pins the arm64 archive and records how linux/arm64 binaries are produced:
		// the release host is amd64, so arm64 binaries are cross-compiled by the pinned
		// linux-amd64 toolchain; the arm64 archive is pinned so nothing else can stand in for it.
		LinuxARM64 struct {
			URL            string `json:"url"`
			SHA256         string `json:"sha256"`
			CrossBuiltFrom string `json:"cross_built_from"`
		} `json:"linux_arm64"`
	} `json:"go"`
	Pnpm        string `json:"pnpm"`
	PnpmTarball struct {
		URL       string `json:"url"`
		Integrity string `json:"integrity"`
	} `json:"pnpm_tarball"`
}

// Inputs is the verified input record that goes into release.json.
type Inputs struct {
	GoVersion         string            `json:"go_version"`
	GoArchiveSHA256   string            `json:"go_archive_sha256"`
	GoRootFiles       int               `json:"goroot_files_verified"`
	GoModSHA256       string            `json:"go_mod_sha256"`
	GoSumSHA256       string            `json:"go_sum_sha256"`
	GoModVerify       string            `json:"go_mod_verify"`
	GoARM64           string            `json:"go_linux_arm64"`
	PnpmVersion       string            `json:"pnpm_version"`
	PnpmIntegrity     string            `json:"pnpm_tarball_integrity"`
	PnpmTarball       string            `json:"pnpm_tarball"`
	PnpmLockSHA256    string            `json:"pnpm_lock_sha256"`
	LicenseInventory  string            `json:"node_license_inventory"`
	PythonLocks       map[string]string `json:"python_locks_sha256"`
	PythonLocksHashed bool              `json:"python_locks_hash_pinned"`
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func loadPins(root string) (pins, error) {
	var p pins
	raw, err := os.ReadFile(filepath.Join(root, "build", "toolchains.json"))
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	if p.Go.Version == "" || len(p.Go.LinuxAMD64.SHA256) != 64 {
		return p, errors.New("build/toolchains.json has no pinned linux-amd64 Go archive")
	}
	return p, nil
}

// verifyArchiveTree proves goroot is exactly the pinned archive: the archive's own sha256
// equals want, and every regular file in it exists in goroot with identical bytes. Files
// the archive does not know about (a build cache, a stray file) cannot alter what the
// archive's files do, but a compiler or standard library edit cannot hide.
func verifyArchiveTree(archive, want, goroot string) (int, error) {
	got, err := sha256File(archive)
	if err != nil {
		return 0, err
	}
	if got != want {
		return 0, fmt.Errorf("Go archive sha256 %s does not match the pin %s", got, want)
	}
	f, err := os.Open(archive)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(bufio.NewReader(f))
	if err != nil {
		return 0, err
	}
	tr := tar.NewReader(zr)
	type member struct{ rel, sum string }
	var members []member
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		rel := strings.TrimPrefix(header.Name, "go/")
		if rel == header.Name || !fs.ValidPath(rel) {
			return 0, fmt.Errorf("unexpected archive member %q", header.Name)
		}
		h := sha256.New()
		if _, err = io.Copy(h, tr); err != nil {
			return 0, err
		}
		members = append(members, member{rel, hex.EncodeToString(h.Sum(nil))})
	}
	// The files are compared in parallel: the tree can sit on a slow filesystem.
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		next     atomic.Int64
	)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(members) {
					return
				}
				onDisk, err := sha256File(filepath.Join(goroot, filepath.FromSlash(members[i].rel)))
				if err != nil || onDisk != members[i].sum {
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("GOROOT file %s differs from the pinned archive", members[i].rel)
					}
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return 0, firstErr
	}
	return len(members), nil
}

// runImageContext writes the exact build context a Dockerfile under deploy/ expects: the release
// binary, copied only after its sha256 is found in the release's own SHA256SUMS (and, for the
// server image, an empty data/).
func runImageContext(args []string) error {
	f := flag.NewFlagSet("image-context", flag.ContinueOnError)
	release := f.String("release", "", "release directory")
	arch := f.String("arch", "amd64", "linux architecture")
	out := f.String("out", "", "context directory (created)")
	root := f.String("root", ".", "repository root (for the Dockerfile under deploy/)")
	image := f.String("image", "server", "image to make a context for: server (deploy/Dockerfile) or perf-helper (deploy/Dockerfile.perf-helper)")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *release == "" || *out == "" {
		return errors.New("--release and --out are required")
	}
	kind, ok := imageKinds[*image]
	if !ok {
		return fmt.Errorf("unknown --image %q (server or perf-helper)", *image)
	}
	binary, sum, err := listedBinary(*release, *arch, kind.binary)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	if kind.dataDir {
		if err = os.MkdirAll(filepath.Join(*out, "data"), 0o755); err != nil {
			return err
		}
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(*out, kind.binary), raw, 0o755); err != nil {
		return err
	}
	docker, err := os.ReadFile(filepath.Join(*root, "deploy", kind.dockerfile))
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(*out, "Dockerfile"), docker, 0o644); err != nil {
		return err
	}
	fmt.Println(sum)
	return nil
}

// pythonLockHashed reports whether every pinned requirement in a uv lock carries at least one
// sha256 hash: a line "name==version \" must be followed by a --hash=sha256: line.
func pythonLockHashed(raw []byte) bool {
	lines := strings.Split(string(raw), "\n")
	pinned := 0
	for i, line := range lines {
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, " ") || strings.TrimSpace(line) == "" || !strings.Contains(line, "==") {
			continue
		}
		pinned++
		if i+1 >= len(lines) || !strings.Contains(lines[i+1], "--hash=sha256:") {
			return false
		}
	}
	return pinned > 0
}

func goEnv(extra ...string) []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "GOTOOLCHAIN=local", "GOFLAGS=", "GOWORK=off", "GOPROXY=off", "GONOSUMDB=*", "GOENV=off", "TMPDIR=" + os.TempDir()}
	return append(env, extra...)
}

func goBinary(root string) string {
	if p := os.Getenv("SOUNDPOST_GO"); p != "" {
		return p
	}
	return filepath.Join(root, ".tools", "linux", "go", "bin", "go")
}

func verifyInputs(root, archive string) (Inputs, error) {
	var in Inputs
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return in, fmt.Errorf("unsupported build host %s/%s: only linux/amd64 is proven against the pinned archive", runtime.GOOS, runtime.GOARCH)
	}
	p, err := loadPins(root)
	if err != nil {
		return in, err
	}
	in.GoVersion, in.GoArchiveSHA256 = p.Go.Version, p.Go.LinuxAMD64.SHA256
	if archive == "" {
		archive = filepath.Join(root, ".tools", "go"+p.Go.Version+".linux-amd64.tar.gz")
	}
	goBin := goBinary(root)
	if _, err = os.Stat(goBin); err != nil {
		return in, fmt.Errorf("pinned Go toolchain missing: %s is not usable (%v); unpack the pinned Go %s linux-amd64 archive to .tools/linux/go or set SOUNDPOST_GO to its bin/go (docs/operations/install-single.md, section 1)", goBin, err, p.Go.Version)
	}
	if _, err = os.Stat(archive); err != nil {
		return in, fmt.Errorf("pinned Go archive missing: %s is not readable (%v); the pinned go%s.linux-amd64.tar.gz must be in .tools or passed with --archive (docs/operations/install-single.md, section 1)", archive, err, p.Go.Version)
	}
	cmd := exec.Command(goBin, "env", "GOROOT")
	cmd.Env = goEnv()
	rawRoot, err := cmd.Output()
	if err != nil {
		return in, fmt.Errorf("go env GOROOT: %w", err)
	}
	cmd = exec.Command(goBin, "version")
	cmd.Env = goEnv()
	version, err := cmd.Output()
	if err != nil {
		return in, err
	}
	if !strings.HasPrefix(string(version), "go version go"+p.Go.Version+" linux/amd64") {
		return in, fmt.Errorf("compiler reports %q, pin is go%s", strings.TrimSpace(string(version)), p.Go.Version)
	}
	if in.GoRootFiles, err = verifyArchiveTree(archive, p.Go.LinuxAMD64.SHA256, strings.TrimSpace(string(rawRoot))); err != nil {
		return in, err
	}
	if in.GoModSHA256, err = sha256File(filepath.Join(root, "go.mod")); err != nil {
		return in, err
	}
	if in.GoSumSHA256, err = sha256File(filepath.Join(root, "go.sum")); err != nil {
		return in, err
	}
	verify := exec.Command(goBin, "mod", "verify")
	verify.Dir, verify.Env = root, goEnv("GOFLAGS=-mod=readonly")
	if output, err := verify.CombinedOutput(); err != nil || !strings.Contains(string(output), "all modules verified") {
		return in, errors.New("go mod verify failed: " + strings.TrimSpace(string(output)) + " (the build runs with GOPROXY=off: every module in go.sum must already be in the Go module cache; download them with network access first, e.g. `go mod download`, before building offline; docs/operations/install-single.md, section 1)")
	}
	in.GoModVerify = "all modules verified"
	if err = verifyPnpmPin(root, p, &in); err != nil {
		return in, err
	}
	if in.PnpmLockSHA256, err = sha256File(filepath.Join(root, "pnpm-lock.yaml")); err != nil {
		return in, err
	}
	var inventory struct {
		Lock string `json:"lock_sha256"`
	}
	raw, err := os.ReadFile(filepath.Join(root, "build", "dependencies", "node-licenses.json"))
	if err != nil {
		return in, err
	}
	if err = json.Unmarshal(raw, &inventory); err != nil {
		return in, err
	}
	// A stale license inventory is reported, not hidden and not "fixed" here: the pin file is
	// regenerated by its owner, and a publication gate refuses a release while it is stale.
	in.LicenseInventory = "current"
	if inventory.Lock != in.PnpmLockSHA256 {
		in.LicenseInventory = "stale"
	}
	in.PythonLocks, in.PythonLocksHashed = map[string]string{}, true
	for _, name := range []string{"requirements-dev.lock", "requirements-integrations.lock"} {
		path := filepath.Join(root, "sdk", "python", name)
		lock, err := os.ReadFile(path)
		if err != nil {
			return in, err
		}
		sum := sha256.Sum256(lock)
		in.PythonLocks[name] = hex.EncodeToString(sum[:])
		in.PythonLocksHashed = in.PythonLocksHashed && pythonLockHashed(lock)
	}
	if !in.PythonLocksHashed {
		return in, errors.New("a Python lock has a requirement without a sha256 hash")
	}
	return in, nil
}

// fileIntegrity is the npm "sha512-<base64>" integrity string of a file.
func fileIntegrity(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha512.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha512-" + base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

func validIntegrity(s string) bool {
	raw, ok := strings.CutPrefix(s, "sha512-")
	if !ok {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	return err == nil && len(b) == sha512.Size
}

// verifyPnpmPin proves the pnpm pin: the pinned version is the one package.json's
// packageManager names, the pin carries a full sha512 integrity of the registry tarball, and
// the linux/arm64 archive is pinned by sha256 (verified when present at
// .tools/go<version>.linux-arm64.tar.gz) and arm64 is declared cross-built from the pinned amd64 toolchain. When the tarball is present (SOUNDPOST_PNPM_TARBALL or
// .tools/pnpm-<version>.tgz) its integrity must equal the pin; the record says which it was.
func verifyPnpmPin(root string, p pins, in *Inputs) error {
	arm := p.Go.LinuxARM64
	if arm.CrossBuiltFrom != "linux_amd64" || len(arm.SHA256) != 64 || arm.URL == "" {
		return errors.New("build/toolchains.json must pin go.linux_arm64 (url, 64-hex sha256) and declare cross_built_from = linux_amd64")
	}
	in.GoARM64 = "cross-compiled by the pinned linux-amd64 toolchain; arm64 archive sha256 pinned (not present)"
	armArchive := filepath.Join(root, ".tools", "go"+p.Go.Version+".linux-arm64.tar.gz")
	if _, err := os.Stat(armArchive); err == nil {
		got, err := sha256File(armArchive)
		if err != nil {
			return err
		}
		if got != arm.SHA256 {
			return fmt.Errorf("Go arm64 archive sha256 %s does not match the pin %s", got, arm.SHA256)
		}
		in.GoARM64 = "cross-compiled by the pinned linux-amd64 toolchain; arm64 archive sha256 verified"
	}
	if p.Pnpm == "" || !validIntegrity(p.PnpmTarball.Integrity) || p.PnpmTarball.URL == "" {
		return errors.New("build/toolchains.json has no pinned pnpm tarball integrity (sha512)")
	}
	raw, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return err
	}
	var pkg struct {
		PackageManager string `json:"packageManager"`
	}
	if err = json.Unmarshal(raw, &pkg); err != nil {
		return err
	}
	if pkg.PackageManager != "pnpm@"+p.Pnpm {
		return fmt.Errorf("package.json packageManager %q does not match the pnpm pin %q", pkg.PackageManager, p.Pnpm)
	}
	in.PnpmVersion, in.PnpmIntegrity, in.PnpmTarball = p.Pnpm, p.PnpmTarball.Integrity, "pin_only"
	tarball := os.Getenv("SOUNDPOST_PNPM_TARBALL")
	if tarball == "" {
		tarball = filepath.Join(root, ".tools", "pnpm-"+p.Pnpm+".tgz")
	}
	if _, err = os.Stat(tarball); err != nil {
		return nil
	}
	got, err := fileIntegrity(tarball)
	if err != nil {
		return err
	}
	if got != p.PnpmTarball.Integrity {
		return fmt.Errorf("pnpm tarball %s integrity %s does not match the pin %s", tarball, got, p.PnpmTarball.Integrity)
	}
	in.PnpmTarball = "verified"
	return nil
}

// Binary is one produced artifact.
type Binary struct {
	Platform string `json:"platform"`
	Name     string `json:"name"`
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
	Static   bool   `json:"static_elf"`
}

// Reproducibility is the result of the second, empty-cache build.
type Reproducibility struct {
	Checked bool   `json:"checked"`
	Equal   bool   `json:"equal,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Manifest is release.json.
type Manifest struct {
	Version         string          `json:"version"`
	Commit          string          `json:"commit"`
	BuildID         string          `json:"build_id"`
	Inputs          Inputs          `json:"inputs"`
	UIDigest        string          `json:"ui_tree_sha256"`
	UIFiles         int             `json:"ui_files"`
	Binaries        []Binary        `json:"binaries"`
	Skipped         []string        `json:"skipped,omitempty"`
	Reproducibility Reproducibility `json:"reproducibility"`
	BuildFlags      []string        `json:"build_flags"`
}

// isStaticELF is true for an ELF with no interpreter and no needed shared libraries.
func isStaticELF(path string) (bool, error) {
	f, err := elf.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP || p.Type == elf.PT_DYNAMIC {
			return false, nil
		}
	}
	libs, err := f.ImportedLibraries()
	return err == nil && len(libs) == 0, nil
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("non-regular file %s in the UI bundle", rel)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o644)
	})
}

// stageUI copies a verified bundle into cmd/soundpost/webdist for `-tags webembed` and returns
// its tree digest. The directory is generated output: it carries its own .gitignore and the
// caller removes it after the build.
func stageUI(root, dist string) (digest string, files int, err error) {
	index, err := os.ReadFile(filepath.Join(dist, "index.html"))
	if err != nil || !bytes.Contains(index, []byte(`id="root"`)) {
		return "", 0, errors.New("web dist has no built index.html (build it with the pinned Node and `pnpm --filter @soundpost/web build`)")
	}
	if digest, files, err = releaseevidence.TreeDigest(dist, nil); err != nil {
		return "", 0, err
	}
	staged := filepath.Join(root, "cmd", "soundpost", "webdist")
	if err = os.RemoveAll(staged); err != nil {
		return "", 0, err
	}
	if err = os.MkdirAll(staged, 0o755); err != nil {
		return "", 0, err
	}
	if err = copyTree(dist, staged); err != nil {
		return "", 0, err
	}
	return digest, files, os.WriteFile(filepath.Join(staged, ".gitignore"), []byte("*\n!.gitignore\n"), 0o644)
}

type buildPlan struct {
	root, goBin, version, commit, buildID string
	arches, commands                      []string
}

func (b buildPlan) flags() []string {
	return []string{"-trimpath", "-buildvcs=false", "-mod=readonly", "-tags=netgo,osusergo,webembed", "-ldflags=-s -w -buildid= -X main.version=" + b.version + " -X main.commit=" + b.commit + " -X main.buildID=" + b.buildID}
}

// build produces every binary into outDir/<os>-<arch>/ using a Go build cache at cache.
func (b buildPlan) build(outDir, cache string) ([]Binary, error) {
	var out []Binary
	for _, arch := range b.arches {
		for _, name := range b.commands {
			target := filepath.Join(outDir, "linux-"+arch, name)
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, err
			}
			args := append([]string{"build"}, b.flags()...)
			args = append(args, "-o", target, "./cmd/"+name)
			cmd := exec.Command(b.goBin, args...)
			cmd.Dir = b.root
			cmd.Env = goEnv("CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch, "GOCACHE="+cache, "GOFLAGS=")
			if output, err := cmd.CombinedOutput(); err != nil {
				return nil, fmt.Errorf("build linux/%s %s: %w\n%s", arch, name, err, output)
			}
			sum, err := sha256File(target)
			if err != nil {
				return nil, err
			}
			info, err := os.Stat(target)
			if err != nil {
				return nil, err
			}
			static, err := isStaticELF(target)
			if err != nil {
				return nil, err
			}
			out = append(out, Binary{Platform: "linux/" + arch, Name: name, SHA256: sum, Bytes: info.Size(), Static: static})
		}
	}
	return out, nil
}

func runRelease(args []string, out io.Writer) error {
	f := flag.NewFlagSet("release", flag.ContinueOnError)
	root := f.String("root", ".", "repository root")
	outDir := f.String("out", "", "output directory (created)")
	version := f.String("version", "", "release version")
	commitFlag := f.String("commit", "", "source commit; with a git context it must equal HEAD (derived when omitted); without git the manifest records \"unknown\"")
	arches := f.String("arch", releaseArches(), "comma-separated linux architectures (default: the release platforms, decision D10)")
	webDist := f.String("web-dist", "", "built UI bundle (default web/dist)")
	archive := f.String("archive", "", "pinned Go archive")
	reproduce := f.Bool("reproduce", false, "build twice with empty caches and compare sha256")
	cache := f.String("cache", "", "Go build cache for the first build (default: a fresh temp directory)")
	if err := f.Parse(args); err != nil {
		return err
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	if *outDir == "" || *version == "" {
		return errors.New("--out and --version are required")
	}
	commit, err := releaseCommit(absRoot, *commitFlag)
	if err != nil {
		return err
	}
	inputs, err := verifyInputs(absRoot, *archive)
	if err != nil {
		return fmt.Errorf("input verification failed, nothing was built: %w", err)
	}
	if *webDist == "" {
		*webDist = filepath.Join(absRoot, "web", "dist")
	}
	uiDigest, uiFiles, err := stageUI(absRoot, *webDist)
	if err != nil {
		return err
	}
	defer os.RemoveAll(filepath.Join(absRoot, "cmd", "soundpost", "webdist"))
	buildID, err := releaseevidence.SourceDigest(absRoot)
	if err != nil {
		return err
	}
	plan := buildPlan{root: absRoot, goBin: goBinary(absRoot), version: *version, commit: commit, buildID: "sha256:" + buildID + "+ui:" + uiDigest[:16], arches: strings.Split(*arches, ",")}
	manifest := Manifest{Version: *version, Commit: commit, BuildID: plan.buildID, Inputs: inputs, UIDigest: uiDigest, UIFiles: uiFiles, BuildFlags: append([]string{"CGO_ENABLED=0"}, plan.flags()...)}
	for _, name := range releaseCommands {
		if _, err := os.Stat(filepath.Join(absRoot, "cmd", name, "main.go")); err == nil {
			plan.commands = append(plan.commands, name)
		} else {
			manifest.Skipped = append(manifest.Skipped, name+": cmd/"+name+" does not exist in this tree")
		}
	}
	if err = os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	firstCache := *cache
	if firstCache == "" {
		if firstCache, err = os.MkdirTemp("", "soundpost-gocache-"); err != nil {
			return err
		}
		defer os.RemoveAll(firstCache)
	}
	manifest.Binaries, err = plan.build(*outDir, firstCache)
	if err != nil {
		return err
	}
	for _, b := range manifest.Binaries {
		if !b.Static {
			return fmt.Errorf("%s %s is not a static ELF", b.Platform, b.Name)
		}
	}
	if *reproduce {
		second, err := os.MkdirTemp("", "soundpost-repro-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(second)
		secondCache, err := os.MkdirTemp("", "soundpost-gocache-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(secondCache)
		again, err := plan.build(second, secondCache)
		if err != nil {
			return err
		}
		manifest.Reproducibility = Reproducibility{Checked: true, Equal: len(again) == len(manifest.Binaries)}
		for i := range again {
			if i < len(manifest.Binaries) && again[i].SHA256 != manifest.Binaries[i].SHA256 {
				manifest.Reproducibility.Equal = false
				manifest.Reproducibility.Detail += fmt.Sprintf("%s %s differs (%s vs %s); ", again[i].Platform, again[i].Name, manifest.Binaries[i].SHA256, again[i].SHA256)
			}
		}
	}
	sort.Slice(manifest.Binaries, func(i, j int) bool {
		a, b := manifest.Binaries[i], manifest.Binaries[j]
		return a.Platform+"/"+a.Name < b.Platform+"/"+b.Name
	})
	var sums bytes.Buffer
	for _, b := range manifest.Binaries {
		fmt.Fprintf(&sums, "%s  %s/%s\n", b.SHA256, strings.ReplaceAll(b.Platform, "/", "-"), b.Name)
	}
	if err = os.WriteFile(filepath.Join(*outDir, "SHA256SUMS"), sums.Bytes(), 0o644); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err = os.WriteFile(filepath.Join(*outDir, "release.json"), raw, 0o644); err != nil {
		return err
	}
	if _, err = out.Write(raw); err != nil {
		return err
	}
	if manifest.Reproducibility.Checked && !manifest.Reproducibility.Equal {
		return errors.New("the two builds are not byte-identical: " + manifest.Reproducibility.Detail)
	}
	return nil
}

// releaseCommit decides the commit a release records. With a git context at root it is HEAD: an
// explicit commit that differs is refused, and so is a tree with a modified or untracked file in the
// digested set (cmd/, internal/, profiles/, go.mod, go.sum; see releaseevidence.SourceDigest), because
// then the digest would describe bytes HEAD does not contain. Without git the commit is "unknown";
// a typed value is refused since nothing can vouch for it.
func releaseCommit(root, explicit string) (string, error) {
	git := func(args ...string) (string, string, error) {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		var so, se bytes.Buffer
		cmd.Stdout, cmd.Stderr = &so, &se
		err := cmd.Run()
		return so.String(), se.String(), err
	}
	inside, stderr, err := git("rev-parse", "--is-inside-work-tree")
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) || strings.Contains(stderr, "not a git repository") {
			if explicit != "" && explicit != "unknown" {
				return "", fmt.Errorf("--commit %q refused: %s is not in a git work tree, so the commit cannot be derived or checked (omit --commit; the manifest records \"unknown\")", explicit, root)
			}
			return "unknown", nil
		}
		return "", fmt.Errorf("git rev-parse: %w: %s", err, strings.TrimSpace(stderr))
	}
	if strings.TrimSpace(inside) != "true" {
		return "", fmt.Errorf("%s is not inside a git work tree", root)
	}
	headOut, stderr, err := git("rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("git rev-parse HEAD: %w: %s", err, strings.TrimSpace(stderr))
	}
	head := strings.TrimSpace(headOut)
	if explicit != "" && explicit != head {
		return "", fmt.Errorf("--commit %q is not HEAD %s of %s: the commit is derived from git, never typed", explicit, head, root)
	}
	prefixOut, stderr, err := git("rev-parse", "--show-prefix")
	if err != nil {
		return "", fmt.Errorf("git rev-parse --show-prefix: %w: %s", err, strings.TrimSpace(stderr))
	}
	prefix := strings.TrimSpace(prefixOut)
	status, stderr, err := git("status", "--porcelain=v1", "-z", "--untracked-files=all", "--", "cmd", "internal", "profiles", "go.mod", "go.sum")
	if err != nil {
		return "", fmt.Errorf("git status: %w: %s", err, strings.TrimSpace(stderr))
	}
	var dirty []string
	entries := strings.Split(status, "\x00")
	for i := 0; i < len(entries); i++ {
		e := entries[i]
		if len(e) < 4 {
			continue
		}
		if e[0] == 'R' || e[0] == 'C' {
			i++ // the original path follows as its own entry
		}
		rel := filepath.ToSlash(strings.TrimPrefix(e[3:], prefix))
		if inDigestedSet(rel) {
			dirty = append(dirty, strings.TrimSpace(e[:2])+" "+rel)
		}
	}
	if len(dirty) > 0 {
		sort.Strings(dirty)
		return "", fmt.Errorf("refusing to release a dirty tree: %d modified or untracked file(s) under the digested set would make the digest describe bytes HEAD %s does not contain: %s", len(dirty), head, strings.Join(dirty, ", "))
	}
	return head, nil
}

// inDigestedSet mirrors releaseevidence.SourceDigest's inclusion rules for a slash path under root.
func inDigestedSet(rel string) bool {
	if rel == "go.mod" || rel == "go.sum" {
		return true
	}
	for _, dir := range []string{"cmd/", "internal/", "profiles/"} {
		if strings.HasPrefix(rel, dir) {
			return !strings.HasSuffix(rel, "_test.go") && !strings.HasPrefix(rel, "cmd/soundpost/webdist/")
		}
	}
	return false
}

// releaseArches lists the linux architectures of releaseevidence.ReleasePlatforms, comma separated.
func releaseArches() string {
	var arches []string
	for _, p := range releaseevidence.ReleasePlatforms {
		if arch, ok := strings.CutPrefix(p, "linux/"); ok {
			arches = append(arches, arch)
		}
	}
	return strings.Join(arches, ",")
}

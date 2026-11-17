// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package releaseevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SourceDigest is the identity of the code a release is built from and a producer ran against: the
// sha256 over every non-test Go source and embedded profile of cmd/, internal/ and profiles/ plus
// go.mod and go.sum. It does not depend on version control (VM copies and release trees are not git
// checkouts) or on the staged UI copy. `go run ./build release` records it as the first component of
// the release's build_id ("sha256:<SourceDigest>+ui:..."); producers stamp it in their own reports and
// the gate refuses evidence whose stamp is not the release's.
func SourceDigest(root string) (string, error) {
	h := sha256.New()
	for _, dir := range []string{"cmd", "internal", "profiles"} {
		sum, n, err := TreeDigest(filepath.Join(root, dir), func(rel string) bool {
			return !strings.HasSuffix(rel, "_test.go") && !strings.HasPrefix(rel, "soundpost/webdist/")
		})
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s %s %d\n", dir, sum, n)
	}
	for _, name := range []string{"go.mod", "go.sum"} {
		sum, err := fileSHA256(filepath.Join(root, name))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s %s\n", name, sum)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ModuleRoot returns the nearest directory at or above dir that holds go.mod: the tree a producer
// stamps. A producer started from a subdirectory (a test's working directory) still stamps the
// module it belongs to.
func ModuleRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for d := abs; ; d = filepath.Dir(d) {
		if st, err := os.Stat(filepath.Join(d, "go.mod")); err == nil && st.Mode().IsRegular() {
			return d, nil
		}
		if filepath.Dir(d) == d {
			return "", errors.New("no go.mod at or above " + abs)
		}
	}
}

// CurrentSourceDigest is SourceDigest of the module that contains the working directory.
func CurrentSourceDigest() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	root, err := ModuleRoot(wd)
	if err != nil {
		return "", err
	}
	return SourceDigest(root)
}

// TreeDigest hashes a directory deterministically: sorted slash paths with each file's sha256.
func TreeDigest(root string, include func(rel string) bool) (string, int, error) {
	type entry struct{ rel, sum string }
	var entries []entry
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if include != nil && !include(rel) {
			return nil
		}
		sum, err := fileSHA256(path)
		entries = append(entries, entry{rel, sum})
		return err
	})
	if err != nil {
		return "", 0, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	h := sha256.New()
	for _, e := range entries {
		fmt.Fprintf(h, "%s %s\n", e.sum, e.rel)
	}
	return hex.EncodeToString(h.Sum(nil)), len(entries), nil
}

func fileSHA256(path string) (string, error) {
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

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type OracleRun struct {
	Profile       SourceProfile
	Input         json.RawMessage
	Configuration []byte
	Runtime       string
}

// RunOracle invokes a separately acquired OCI oracle adapter, never a product
// evaluator. The adapter image contains the exact upstream process and translates
// its observations to SemanticResult; an absent adapter is a hard failure.
// Runtime is an explicitly supplied absolute docker/podman executable path.
func RunOracle(ctx context.Context, run OracleRun) (SemanticResult, error) {
	var result SemanticResult
	if exactPins[run.Profile.ID] != run.Profile.Commit || run.Profile.Commit == "" {
		return result, fmt.Errorf("unknown oracle profile identity")
	}
	a := run.Profile.Artifact
	if a == nil || a.Adapter != "oci-semantic-json-v1" || !strings.HasPrefix(a.Path, "sha256:") || len(a.Path) != 71 || a.SHA256 != strings.TrimPrefix(a.Path, "sha256:") {
		return result, fmt.Errorf("missing digest-locked isolated oracle artifact")
	}
	if _, err := hex.DecodeString(a.SHA256); err != nil {
		return result, fmt.Errorf("invalid image digest")
	}
	if a.Architecture != "linux/amd64" {
		return result, fmt.Errorf("oracle architecture must be locked to linux/amd64")
	}
	if !filepath.IsAbs(run.Runtime) {
		return result, fmt.Errorf("absolute OCI runtime path required")
	}
	hash := sha256.Sum256(run.Configuration)
	if hex.EncodeToString(hash[:]) != a.ConfigurationSHA256 {
		return result, fmt.Errorf("oracle configuration digest mismatch")
	}
	if len(run.Input) == 0 || !json.Valid(run.Input) {
		return result, fmt.Errorf("valid authored oracle input required")
	}
	dir, err := os.MkdirTemp("", "soundpost-query-oracle-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(dir)
	if err = os.Chmod(dir, 0755); err != nil {
		return result, err
	}
	if err = os.WriteFile(filepath.Join(dir, "configuration"), run.Configuration, 0444); err != nil {
		return result, err
	}
	cidfile := filepath.Join(dir, "container-id")
	args := []string{"run", "--rm", "--cidfile=" + cidfile, "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=512m", "--cpus=1", "--user=65534:65534", "--tmpfs=/tmp:rw,noexec,nosuid,size=268435456", "--mount=type=bind,src=" + dir + ",dst=/fixture,readonly", "-i"}
	args = append(args, a.Path)
	args = append(args, a.Args...)
	cmd := exec.CommandContext(ctx, run.Runtime, args...)
	cmd.Env = []string{}
	cmd.Stdin = bytes.NewReader(run.Input)
	defer func() {
		id, e := os.ReadFile(cidfile)
		if e != nil {
			return
		}
		value := strings.TrimSpace(string(id))
		if len(value) != 64 {
			return
		}
		if _, e = hex.DecodeString(value); e != nil {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cleanup := exec.CommandContext(cleanupCtx, run.Runtime, "rm", "--force", value)
		cleanup.Env = []string{}
		_ = cleanup.Run()
	}()
	var stdout, stderr boundedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err = cmd.Run(); err != nil {
		return result, fmt.Errorf("isolated oracle failed: %w; diagnostic: %s", err, stderr.data)
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&result); err != nil {
		return result, fmt.Errorf("invalid oracle observation: %w", err)
	}
	if result.Kind == "" || result.Oracle == nil || result.Oracle.Profile != run.Profile.ID || len(result.Oracle.Revision) < 7 || !strings.HasPrefix(run.Profile.Commit, result.Oracle.Revision) {
		return result, fmt.Errorf("oracle returned no verified semantic observation")
	}
	result.Oracle.ImageSHA256 = a.SHA256
	result.Oracle.ConfigurationSHA256 = a.ConfigurationSHA256
	return result, nil
}

type boundedBuffer struct{ data []byte }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > 16<<20 {
		return 0, fmt.Errorf("oracle output exceeds 16 MiB")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

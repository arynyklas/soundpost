// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// The helper is built separately INSIDE the exact upstream module/compiler. It
// is present only in development oracle images; no upstream module is linked
// into Soundpost or used as an owned-evaluator fallback.
func serveEvaluationAdapter(ctx context.Context, profileID string, input *evaluationInput, output io.Writer) error {
	if input == nil || input.Profile != profileID || input.Commit != exactPins[profileID] || !strings.HasPrefix(profileID, "promql-") || len(input.Cases) == 0 {
		return fmt.Errorf("missing pinned native evaluation input")
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "/evaluation-reference")
	command.Env = []string{}
	command.Stdin = bytes.NewReader(raw)
	var stdout, stderr boundedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err = command.Run(); err != nil {
		return fmt.Errorf("native reference driver unavailable or failed: %w; %s", err, stderr.data)
	}
	var batch EvaluationBatch
	decoder := json.NewDecoder(bytes.NewReader(stdout.data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&batch); err != nil {
		return fmt.Errorf("invalid native reference observation: %w", err)
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing native reference observation")
	}
	if batch.Profile != profileID || batch.Commit != exactPins[profileID] || len(batch.Observations) != len(input.Cases) {
		return fmt.Errorf("native reference identity or observation count mismatch")
	}
	version := strings.TrimPrefix(profileID, "promql-prometheus-")
	return json.NewEncoder(output).Encode(SemanticResult{Kind: "evaluation", Type: "evaluation", Evaluation: &batch, Oracle: &OracleIdentity{Profile: profileID, Revision: batch.Commit, Version: version}})
}

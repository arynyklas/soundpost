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
)

func runLogQLNative(ctx context.Context, input []byte) (LogQLBatch, error) {
	var batch LogQLBatch
	command := exec.CommandContext(ctx, "/logql-reference")
	command.Env = []string{}
	command.Stdin = bytes.NewReader(input)
	var stdout, stderr boundedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return batch, fmt.Errorf("actual pinned native LogQL driver unavailable or failed: %w; %s", err, stderr.data)
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&batch); err != nil {
		return batch, fmt.Errorf("invalid native LogQL observation: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return batch, fmt.Errorf("trailing native LogQL observation")
	}
	return batch, nil
}

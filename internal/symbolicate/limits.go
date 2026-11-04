// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"errors"
	"io"
	"soundpost/internal/model"
	"time"
)

const (
	MaxMapBytes    = 32 << 20
	MaxInputBytes  = (MaxMapBytes * 4 / 3) + (64 << 10)
	MaxOutputBytes = 64 << 10
	MaxFrames      = 1024
	// MaxResolvedFrames bounds distinct (artifact, line, column) lookups per Resolve call.
	MaxResolvedFrames = 64
	MemoryBytes       = 256 << 20
	FrameTimeout      = 100 * time.Millisecond
	ProcessTimeout    = 5 * time.Second
)

func decodeClosed(r io.Reader, out any, max int64) error {
	raw, e := io.ReadAll(io.LimitReader(r, max+1))
	if e != nil {
		return e
	}
	if int64(len(raw)) > max {
		return errors.New("protocol limit")
	}
	return model.StrictJSON(raw, out)
}

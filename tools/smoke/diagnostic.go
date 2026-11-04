// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"soundpost/internal/model"
	"syscall"
)

// No cause/message/path/body is retained in a public diagnostic. Stages and
// request names are fixture-owned identifiers, never request values.
type smokeFailure struct {
	Smoke, Stage, Code string
	RunID              model.ID
	Actual, Expected   int
}

func (f *smokeFailure) Error() string {
	text := "smoke=" + f.Smoke + " stage=" + f.Stage + " code=" + f.Code
	if f.RunID != (model.ID{}) {
		text += " run_id=" + f.RunID.String()
	}
	if f.Actual != 0 || f.Expected != 0 {
		text += fmt.Sprintf(" actual=%d expected=%d", f.Actual, f.Expected)
	}
	return text
}
func publicSmokeCode(code model.Code) string {
	switch code {
	case model.Invalid, model.Unauthenticated, model.Forbidden, model.Conflict, model.TooLarge, model.Unsupported, model.Quota, model.Unavailable, model.Timeout, model.Cancelled, model.Stale, model.NotFound, model.Corrupt:
		return string(code)
	}
	return ""
}
func classifySmokeError(err error) string {
	var encoded *json.MarshalerError
	if errors.As(err, &encoded) {
		return "encode"
	}
	var fault *model.Fault
	if errors.As(err, &fault) {
		if code := publicSmokeCode(fault.Code); code != "" {
			return code
		}
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case os.IsPermission(err):
		return "permission"
	case os.IsNotExist(err):
		return "not_found"
	case os.IsExist(err):
		return "exists"
	case errors.Is(err, os.ErrInvalid):
		return "invalid"
	case errors.Is(err, syscall.ENOSPC):
		return "no_space"
	case errors.Is(err, syscall.EROFS):
		return "read_only"
	case errors.Is(err, syscall.EIO):
		return "io"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected_eof"
	}
	var syntax *json.SyntaxError
	var value *json.UnmarshalTypeError
	if errors.As(err, &syntax) || errors.As(err, &value) {
		return "decode"
	}
	var network net.Error
	if errors.As(err, &network) {
		if network.Timeout() {
			return "timeout"
		}
		return "transport"
	}
	return "unavailable"
}
func annotateSmokeFailure(smoke, stage string, runID model.ID, err error) error {
	if err == nil {
		return nil
	}
	var existing *smokeFailure
	if errors.As(err, &existing) {
		copy := *existing
		copy.Smoke = smoke
		copy.RunID = runID
		return &copy
	}
	return &smokeFailure{Smoke: smoke, Stage: stage, Code: classifySmokeError(err), RunID: runID}
}
func httpSmokeFailure(name string, actual, expected int, body []byte) error {
	code := "unexpected_status"
	var response struct {
		Code model.Code `json:"code"`
	}
	if json.Unmarshal(body, &response) == nil {
		if safe := publicSmokeCode(response.Code); safe != "" {
			code = safe
		}
	}
	return &smokeFailure{Stage: "http_" + name + "_status", Code: code, Actual: actual, Expected: expected}
}
func requireSmokeResponse(stage string, status, want int, body []byte, err error) error {
	if err != nil {
		return annotateSmokeFailure("drill", stage, model.ID{}, err)
	}
	if status != want {
		return httpSmokeFailure(stage, status, want, body)
	}
	return nil
}

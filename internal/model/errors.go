// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

type Code string

const (
	Invalid         Code = "invalid"
	Unauthenticated Code = "unauthenticated"
	Forbidden       Code = "forbidden"
	Conflict        Code = "conflict"
	TooLarge        Code = "too_large"
	Unsupported     Code = "unsupported"
	Quota           Code = "quota"
	Unavailable     Code = "unavailable"
	Timeout         Code = "timeout"
	Cancelled       Code = "cancelled"
	Stale           Code = "stale"
	NotFound        Code = "not_found"
	Corrupt         Code = "corrupt"
)

type Fault struct {
	Code       Code   `json:"code"`
	Retryable  bool   `json:"retryable"`
	SafeDetail string `json:"detail"`
	RequestID  ID     `json:"request_id"`
}

func (f *Fault) Error() string { return string(f.Code) + ": " + f.SafeDetail }
func Fail(c Code) *Fault       { return &Fault{Code: c, SafeDetail: string(c), RequestID: NewID()} }

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"unicode/utf8"
)

// Status is the capability state of a source. A source that cannot be read is
// never reported as an empty source: it is denied, unsupported or unknown with
// a reason.
type Status string

const (
	StatusSupported   Status = "supported"
	StatusDenied      Status = "denied"
	StatusUnsupported Status = "unsupported"
	StatusUnknown     Status = "unknown"
)

// Reason is the closed vocabulary of typed source failures. It never carries
// a path, a command line or any source content.
type Reason string

const (
	ReasonNone             Reason = ""
	ReasonPermission       Reason = "permission_denied"
	ReasonNotPresent       Reason = "not_present"
	ReasonRawExpired       Reason = "raw_grant_expired"
	ReasonInvalidPolicy    Reason = "invalid_policy"
	ReasonReadFailed       Reason = "read_failed"
	ReasonJournalFailed    Reason = "journal_failed"
	ReasonCancelled        Reason = "cancelled"
	ReasonCheckpointCorrup Reason = "checkpoint_corrupt"
	ReasonReceiptMismatch  Reason = "receipt_mismatch"
	ReasonCheckpointState  Reason = "checkpoint_state"
)

// Error is the only error a source adapter returns. The text is source alias,
// status and reason: no path, no OS error text, no source bytes.
type Error struct {
	Source string
	Status Status
	Reason Reason
}

func newError(source string, s Status, r Reason) *Error {
	return &Error{Source: source, Status: s, Reason: r}
}

func (e *Error) Error() string {
	return "sources: " + e.Source + ": " + string(e.Status) + ": " + string(e.Reason)
}

// AsError returns the typed source error of err, if any.
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

func isAbs(s string) bool { return filepath.IsAbs(s) }

func containsString(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

// jsonString encodes validated UTF-8 text as a JSON string literal.
func jsonString(b []byte) (string, error) {
	if !utf8.Valid(b) {
		return "", errors.New("invalid utf8")
	}
	out, err := json.Marshal(string(b))
	return string(out), err
}

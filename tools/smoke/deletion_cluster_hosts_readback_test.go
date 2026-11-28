// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"testing"
)

// A voter that answers the read-back with an error must be named by what it said: the HTTP status and the
// typed fault code, not "unknown" (a digit made the old token unsafe, and the run's only evidence of a
// refused read was the word unknown).
func TestDeletionClusterHostsReadFailureNamesTheStatusAndTheFaultCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"typed fault", dcRetainedStatusFailure("dc_ack_journal_readback", 503, []byte(`{"code":"unavailable"}`)), "retained_read_status_unavailable_http_503"},
		{"stale", dcRetainedStatusFailure("dc_ack_journal_readback", 409, []byte(`{"code":"stale","message":"x"}`)), "retained_read_status_stale_http_409"},
		{"no body", dcRetainedStatusFailure("dc_ack_journal_readback", 502, nil), "retained_read_status_no_answer_http_502"},
		{"hostile body", dcRetainedStatusFailure("dc_ack_journal_readback", 500, []byte(`{"code":"Bad Token 7"}`)), "retained_read_status_unknown_http_500"},
		{"transport", errors.New("connection reset"), "unavailable"},
	}
	for _, c := range cases {
		if got := dcReadFailureWhy(c.err); got != c.want {
			t.Errorf("%s: named %q, want %q", c.name, got, c.want)
		}
	}
}

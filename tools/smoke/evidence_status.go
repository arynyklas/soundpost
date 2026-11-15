// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import "net/http"

// typedDenial reports whether an HTTP status is the server's own typed refusal of a read: unauthenticated,
// forbidden or not found. Status 0 (no answer: the process died or the connection failed), 5xx and 200 are not
// refusals, so a crashed server can never satisfy a row that says "the read was denied".
func typedDenial(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound
}

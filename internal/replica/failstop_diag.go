// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build soundpost_diag

package replica

import (
	"fmt"
	"os"
)

// noteFailure prints the error behind a fail-stop. The closed vocabulary of FailReason carries no text on
// purpose (an error can name paths); a diagnostic build (-tags soundpost_diag) prints it to stderr so that
// a live investigation can tell what failed. The shipped binaries are built without the tag.
func noteFailure(where string, err error) {
	fmt.Fprintf(os.Stderr, "replica: fail-stop in %s: %v\n", where, err)
}

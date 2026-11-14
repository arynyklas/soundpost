// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"strings"
	"testing"
)

// Every subcommand the tool implements must be reachable from the command line:
// run hands the arguments after its name to that subcommand, which refuses the
// missing flags with its own usage line. A subcommand left out of the dispatcher
// would answer with another command's usage (or the generic one) instead.
func TestEverySubcommandIsDispatched(t *testing.T) {
	for _, name := range []string{"intake", "shadow", "journeys", "policy-compare", "readiness", "cutover", "rollback", "closure"} {
		err := run(context.Background(), []string{name})
		if err == nil {
			t.Fatalf("%s: a command with no flags must be refused", name)
		}
		if err.Error() == adoptionUsage || !strings.Contains(err.Error(), name) {
			t.Errorf("%s is not dispatched to its subcommand: %v", name, err)
		}
	}
}

func TestUnknownSubcommandIsRefusedWithTheCommandList(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"nope"}, {"--targets", "x"}} {
		err := run(context.Background(), args)
		if err == nil || !strings.Contains(err.Error(), "usage: adoption") {
			t.Errorf("%v: %v", args, err)
		}
	}
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// A retention command read through a voter that does not lead is proposed a read-index round trip and a forward after its read,
// and a group that proposes whole-state replacements gives the leader no way to hold the other writers' commands for it
// (admission_yield.go classifies only state patches): with other writers committing in that window on every attempt, the command
// lost the application-index race 64 times in a row and was refused as stale, not retryable (begin-flake-1). The leader's own
// command loses the same way to the writers of the other voters. Here the other writer is exact: it commits between the command's
// read and its proposal, every time it can. A command that lost asks the leader for a turn (the leader takes it for itself), and
// the leader holds the other writer until the command's proposal is found current: the command is committed by its second
// attempt, and the writer that was held is told stale, as any writer that loses a race is.
func TestAWriterThatLostToAnotherOnEveryAttemptIsGivenATurnByTheLeader(t *testing.T) {
	for _, c := range []struct {
		name          string
		writer, racer uint64 // the voter the command is made through, and the voter whose writer commits in its window
	}{{"follower", 3, 1}, {"leader", 1, 2}} {
		t.Run(c.name, func(t *testing.T) {
			v := newControlVoters(t)
			v.leaderIs(1)
			writer, racer := v.stores[c.writer], v.stores[c.racer]
			f := v.fx[c.writer]
			attempts, raced, held := 0, 0, 0
			err := writer.RetryingUpdateForTest(f.ctx, func() {
				attempts++
				switch err := racer.PlainUpdateForTest(f.ctx); {
				case err == nil:
					raced++
				case isFault(err, model.Stale):
					held++
				default:
					t.Errorf("the racing writer: %v", err)
				}
			})
			if err != nil {
				t.Fatalf("after %d attempts (the racing writer committed %d times, was held %d times): %v", attempts, raced, held, err)
			}
			if attempts > 3 || raced < 1 || held < 1 {
				t.Fatalf("attempts %d, the racing writer committed %d times and was held %d times: want the command to lose once (no turn yet), ask for a turn, and commit while the racer is held", attempts, raced, held)
			}
		})
	}
}

func isFault(err error, code model.Code) bool {
	var fault *model.Fault
	return errors.As(err, &fault) && fault.Code == code
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// contractedOrg is an organization whose indexes are contracted (D70): the per-replay pins alone.
func contractedOrg() model.ControlOrg {
	return model.ControlOrg{Settings: map[string]json.RawMessage{model.IndexesContractedKey: json.RawMessage(`true`)}}
}

// expandedOrg is one the operator has not contracted: the previous release's pin map is kept current too.
func expandedOrg() model.ControlOrg { return model.ControlOrg{Settings: map[string]json.RawMessage{}} }

func scaleChunk(replay, session model.ID) model.ReplayChunk {
	return model.ReplayChunk{Replay: replay, Session: session, Sequence: 1, CheckpointSequence: 1}
}

// recordNew indexes one new replay (a checkpoint) into st.
func recordNew(t *testing.T, st *model.ControlState, org, project model.ID, now time.Time) model.ID {
	t.Helper()
	replay := model.NewID()
	changed, err := applyIndex(st, org, project, scaleChunk(replay, model.NewID()), model.Hash{1}, model.UnixNano(now.Add(7*24*time.Hour).UnixNano()), now)
	if err != nil || !changed {
		t.Fatalf("applyIndex: changed=%v err=%v", changed, err)
	}
	return replay
}

// Recording one more replay rewrites that replay's own group and pin, not a value that grows
// with the project's live replays (review F-10.06-2: the pin map was one Settings value per
// project, rewritten whole by every new replay: 147 ms at 10k live replays, 703 ms at 40k, a
// hard 16 MiB ceiling near 108k).
func TestRecordingANewReplayRewritesOnlyItsOwnKeys(t *testing.T) {
	org, project := model.NewID(), model.NewID()
	st := &model.ControlState{Orgs: map[string]model.ControlOrg{org.String(): contractedOrg()}}
	now := time.Unix(1_800_000_000, 0)
	const n = 3000
	for range n {
		recordNew(t, st, org, project, now)
	}
	before := map[string]json.RawMessage{}
	for k, v := range st.Orgs[org.String()].Settings {
		before[k] = bytes.Clone(v)
	}
	recordNew(t, st, org, project, now)
	changed := 0
	for k, v := range st.Orgs[org.String()].Settings {
		if !bytes.Equal(before[k], v) {
			changed += len(k) + len(v)
		}
	}
	if changed > 8<<10 {
		t.Fatalf("recording one replay changed %d bytes of Settings in a project of %d live replays; want its own group and pin (< 8 KiB)", changed, n)
	}
}

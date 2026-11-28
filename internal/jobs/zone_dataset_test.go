// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package jobs_test

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
	timezone "github.com/arynyklas/soundpost/third_party/timezone/go124"
)

// Job schedule zones and notification digest zones resolve from the same pinned
// dataset: a zone the pinned dataset does not know is refused even when the
// toolchain's own database has it (America/Coyhaique is newer than the pinned
// dataset), and every zone it does know is accepted.
func TestScheduleZonesResolveFromThePinnedDataset(t *testing.T) {
	for _, zone := range []string{"UTC", "Europe/Berlin", "America/New_York", "Asia/Almaty", "America/Coyhaique", "Mars/Olympus"} {
		_, pinnedErr := timezone.LoadLocation(zone)
		def := jobs.Definition{Revision: 1, EffectiveFrom: 1, Schedule: &jobs.Schedule{Cron: "0 * * * *", Timezone: zone}}
		_, _, err := jobs.Observe(jobs.JobState{}, jobs.ScheduleEvidence{Job: jobID, Observer: observe, ObservedAt: 10, CompleteThrough: 10, Healthy: true, Definition: &def})
		if (err == nil) != (pinnedErr == nil) {
			t.Errorf("%s: schedule accepted=%v but the pinned dataset knows it=%v (err %v)", zone, err == nil, pinnedErr == nil, err)
		}
		if err != nil && code(err) != model.Invalid {
			t.Errorf("%s: %v", zone, err)
		}
	}
}

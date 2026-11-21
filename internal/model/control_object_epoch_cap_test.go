// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"fmt"
	"strings"
	"testing"
)

func objectRecordCount(o ControlOrg) (n int) {
	for k := range o.Settings {
		if strings.HasPrefix(k, ObjEpochKeyPrefix) {
			n++
		}
	}
	return n
}

// Past MaxObjEpochs tracked objects the floor rises to the current epoch and the records are dropped: a
// save of a dropped object, based on an older read, conflicts (the coarse rule), the records stay bounded,
// and a save based on the epoch after the cap is not refused for objects the cap dropped.
func TestObjEpochsCapRaisesTheFloorAndDropsTheOldest(t *testing.T) {
	o := ControlOrg{Epoch: 1}
	o.StartObjectRecords()
	o.TrackChange("first")
	readBefore := o.Epoch
	if o.ObjectChangedAfter("other", readBefore) {
		t.Fatal("an untouched object conflicts before the cap")
	}
	for i := range MaxObjEpochs + 10 {
		o.TrackChange(fmt.Sprintf("obj-%d", i))
		if n := objectRecordCount(o); n > MaxObjEpochs {
			t.Fatalf("the organization holds %d object records, bound %d", n, MaxObjEpochs)
		}
	}
	if _, kept := o.Settings[ObjEpochKeyPrefix+"first"]; kept {
		t.Fatal("the oldest record was not dropped")
	}
	if floor := o.objFloor(); floor <= readBefore {
		t.Fatalf("floor %d was not raised past the epoch read before the cap (%d)", floor, readBefore)
	}
	if !o.ObjectChangedAfter("first", readBefore) || !o.ObjectChangedAfter("other", readBefore) {
		t.Fatal("a save of a dropped or untouched object based on an older read does not conflict after the cap")
	}
	if o.ObjectChangedAfter("other", o.Epoch) {
		t.Fatal("a save based on the current epoch conflicts")
	}
}

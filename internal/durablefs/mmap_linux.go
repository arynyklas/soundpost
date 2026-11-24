//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package durablefs

// BoltInitialMmapSize is the address space the bolt files of the product (apply.db, control.db) are mapped with at open. bolt maps its
// file once and maps it again, under the lock every read transaction holds shared, whenever a commit grows the file past the mapping:
// the commit waits for every open read transaction to end and every read transaction that starts after it waits for the commit, so one
// reader that lives a second (a snapshot cut, a scrub, a verification pass) stops the whole engine for as long as it lives. A mapping
// larger than the file is address space only (the file is not extended on Linux, and pages past its end are never touched): the
// commits of a file that stays below it never remap (bolt: "Read transactions won't block write transaction if the InitialMmapSize is
// large enough"). The apply.db of the single-host gate grew 1.6 GB to 2.1 GB in the minute its requests took 10 seconds (L2w20Admission26).
// 8 GiB is above what a file of the gate holds (the freelist of D91 is out of the commits); a file that grows past it remaps in 1 GiB steps as before.
const BoltInitialMmapSize = 8 << 30

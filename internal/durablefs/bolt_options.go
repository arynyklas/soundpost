// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package durablefs

import (
	"time"

	bolt "go.etcd.io/bbolt"
)

// BoltOptions are the options the bolt files of the product (apply.db of every data group, control.db) are opened with, D91:
//
//   - The freelist is not written by the commits (NoFreelistSync): a commit that writes it lists every free and pending page id of the
//     file, 8 bytes each, and the files that churn (the index merges, the copy-on-write pages of both) are mostly free pages that only
//     grow (L2w20Admission26, L2w20Admission27). A graceful close writes it once; a start after a crash rebuilds it from the live tree
//     (PreLoadFreelist), after WarmBoltTree has read that tree.
//   - The freelist is the array type, not the hashmap type. The hashmap hands out the first span of a Go map iteration, a random one:
//     the commits of a file that holds a million free pages then write 4 KiB pages scattered over its whole length (the cache of a 5 GB
//     file is a working set of all of it, every write a seek), where the array hands out the lowest free page, so the pages a commit
//     writes stay at the front of the file, next to the pages the commit before it wrote (L2w20Admission28; the hashmap was introduced
//     with the freelist fix of L2w20Admission26).
//   - The file is mapped ahead of its growth (BoltInitialMmapSize): a commit that grows it past the mapping waits for every reader.
func BoltOptions() *bolt.Options {
	return &bolt.Options{
		Timeout:         time.Second,
		FreelistType:    bolt.FreelistArrayType,
		NoFreelistSync:  true,
		PreLoadFreelist: true,
		InitialMmapSize: BoltInitialMmapSize,
	}
}

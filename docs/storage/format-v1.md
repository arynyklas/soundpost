# Owned storage format v1

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

## Authority and publication

The one-voter engine retains the original versioned, CRC32C-protected WAL and original bbolt receipt/consumption state. This format does not truncate WAL, advertise Raft quorum durability, expire receipts, implement physical retention/deletion, or claim power-loss/device qualification. `apply.db` is an embedded transactional metadata/index/hot-page store, not a SQL or upstream telemetry query engine.

 Ordered apply writes typed pages, checksummed time/ID postings and committed-feed page routes in the **same** transaction as records, original receipt, reservation consumption and applied cursor. The append path publishes to live subscribers only after that transaction commits and the group watermark advances. The one-time 01.03 upgrade reads only already-applied WAL prefixes and the surviving committed batch rows, retaining each original capture-policy revision; it never substitutes current policy, regenerates receipts, rewrites WAL, resurrects removed batches or publishes replay events. The frozen recovery owner still validates/truncates its tail and applies unapplied entries after storage initialization.

A manifest is immutable JSON named `manifest-<canonical ID>.json`; its SHA-256 and exact contents are held in the transactional `meta/segment_manifest` pointer. Version, installation identity, format term, revision, checksummed segment identities and namespaces, signal/time/retention bounds, page identities, applied cursors and tombstone generation are explicit. The manifest and everything it points at are node-local: each voter publishes its own, with no leadership or quorum requirement, and the format term is the constant 1, not a Raft term (see `docs/operations/recovery.md`). Replacement requires the exact revision and term and cannot drop any retained cold page, alter its namespace or replace its hash. Snapshot coverage records the applied cursors of the verified per-group snapshots this node cut (01.07); it is empty until a snapshot has been cut, and truncating a journal is gated by the verified snapshot directory, not by this field.

Every segment is exclusively created with a durable random filename, fully written, file-synced and directory-synced before an immutable manifest is file/directory-synced. One bbolt commit atomically switches the manifest pointer and page locations. On failure the old hot/cold locations remain authoritative. Compaction streams one decoded page at a time, preserves page/row identities, publishes replacement locations through the same CAS, and only then removes retired segment files with directory synchronization. Crashes may leave unreferenced files; no missing referenced file is treated as EOF or rebuilt from a convenient alternate copy.

 Segment filenames are canonical relative paths `segments/<org>/<project>/<signal>/<signed UTC day>/<segment ID>.sps`. The day is floor(event-start nanoseconds / 86400000000000), including negative times; it describes the file's start-day partition, not an excuse to omit a straddling page. Each file contains one source/class/capture-policy revision and one page-start-day partition. Path components, identities and header namespace must agree. Existing 01.03 WAL/apply paths remain unchanged by this task.

## Segment header

 All header integers are big-endian. An `.sps` file starts with exactly 112 bytes:

| Offset | Bytes | Meaning |
|---:|---:|---|
| 0 | 4 | ASCII `SPS1` |
| 4 | 2 | Format version, exactly 1 |
 | 6 | 2 | Header size, exactly 112 |
| 8 | 16 | Organization ID |
| 24 | 16 | Project ID |
| 40 | 16 | Source ID |
| 56 | 1 | Signal code: metric/log/span/error/job/replay/profile/capability/loss/condition = 1–10 |
| 57 | 1 | Restricted-source flag, 0 or 1 |
 | 58 | 2 | Owned column encoding version, exactly 1 |
 | 60 | 8 | Original capture-policy revision |
 | 68 | 8 | Exact signed minimum event time, two's-complement bits |
 | 76 | 8 | Exact signed maximum event time, inclusive |
 | 84 | 8 | Total retained row count |
 | 92 | 1 | Capability/loss sub-signal code; zero for other kinds |
 | 93 | 15 | Reserved zeros |
 | 108 | 4 | CRC32C Castagnoli over bytes 0–107 |

 The file contains bounded column pages after this header. All pages in a file share this exact organization/project/source/signal/restricted/policy namespace. Each page reference has immutable page ID, offset, exact byte length, SHA-256, row count, capture-policy revision, event-time bounds and original retention deadline. The manifest additionally hashes the whole segment and records exact aggregate row/time/byte/retention bounds. Startup verifies every retained segment and full header; reads verify the namespace/header, page reference hash and page checksum. Unknown versions, missing files, invalid namespaces/offsets/lengths, malformed values and checksums fail explicitly.

## Column pages

`SPP1` pages have a 16-byte fixed header followed by nine 8-byte `(offset,length)` entries, then contiguous columns with no holes/trailing bytes. Header offsets 4/6/8/12 contain uint16 version=1, uint16 column count=9, uint32 row count (1–128), uint32 CRC32C over bytes 16 through end. The page byte cap is 4 MiB. Column order is:

1. Native row IDs.
2. Signal event times, modulo-2^64 deltas from the previous time, unsigned varints; this preserves signed extrema and out-of-order times exactly.
3. Typed C04 resources (canonical `model.ID` service/environment/build, instance and labels).
4. Closed C04 payload union, including both native histogram variants and SDK exception graphs.
5. Original applied cursors.
6. Project IDs.
7. Source IDs.
8. Exact uint64 loss counts for loss/replay/profile payloads, otherwise zero.
9. Original envelope observation times.

 The owned structural codec traverses the ordered exported fields of the closed C04 v1 schema. Unsigned integers, including native float bit patterns, use unsigned varints; signed integers use zig-zag varints. IDs, span IDs and hashes are exact fixed-length byte arrays, not strings or floats. Strings have a column-local dictionary: the low bit distinguishes a new entry, remaining bits give its consecutive dictionary index; new entries carry unsigned-varint byte length and exact UTF-8 bytes. Pointers carry a 0/1 presence tag; slices/maps use zero for nil and length+1 for nonnil (preserving nil versus empty). Map keys are sorted. Scalars use only the leaf model's closed null/bool/int64/string encoding; no payload or record is stored as a JSON query blob. Histogram counts/deltas stay native integers; float count/bucket/sum/threshold bits, NaN payloads, stale marker, signed zero, reset hints, custom bounds and spans are unchanged. Decoding uses typed column arenas for payload objects, scalar pointers and variable-length lists rather than allocating an independent row object. Native maps are instantiated only where the closed C04 value actually requires a distinct map. Any future C04 structural change requires a storage version change/migration, not silent reflection-schema drift.

Projection skips resource/payload column decoding when neither requested nor needed by a selector; checksums still cover the whole page. Returned columns retain equal lengths, with unrequested resource/payload/observation columns zeroed. IDs, event times, project/source identities, loss metadata and origin cursors are intrinsic. An empty projection returns all columns.

## Namespace and index order

 The hot/cold index namespace is `(org[16],project[16],signal[1],restricted[1])`; restricted namespaces additionally include source[16]. Capability/loss namespaces additionally include their closed C04 payload signal code, and their pages never mix sub-signals. The suffix is sign-bit-flipped big-endian event time[8], row ID[16], origin group[16], origin logical index[8], page ordinal[2]. Values contain page ID[16], ordinal[2], and CRC32C[4] over the complete key and first 18 value bytes. Every lookup verifies that checksum and the returned row's exact ID/time/origin before release. The index retains same-time/same-line logs with distinct IDs and origin identity; it does not perform query-time content deduplication. Ordered metric dedup/conflict semantics remain in the committed apply path.

 Typed equality postings cover row/resource IDs; trace/span/occurrence/release IDs; job/run/attempt, replay/session, profile/process/capability and condition/producer/epoch IDs; metric names, log/condition severity, log templates and labels. A length-delimited term precedes the same time/ID/origin suffix and each posting has its own key-bound CRC. Scans select an eligible nonempty equality posting and evaluate all matchers against native columns. Empty-string label equality must also admit missing labels, so it deliberately uses the time index. Regexes are anchored Go RE2 regexes. Literals distinguish string, signed/unsigned exact integer, boolean, null and float bits; labels remain strings. Signed/unsigned nonnegative integer equality is exact, never a float conversion. Native ID equality is parsed once and compared as native arrays, not converted into a string per row.

 Exact native scalar postings include histogram count/bits, job/replay/condition sequence and state, error handled/fatal/mechanism, profile method/units/loss, and capability/loss signal/reason. Approved log fields and structured metadata have type-tagged postings. Log-line tokens are a bounded candidate index (64 distinct ASCII word prefixes of at most 64 bytes), not a LogQL parser: a line-equality candidate is always checked against the complete immutable line. No token approximation changes a match result.

 `scan_integrity` independently stores a counted SHA-256 multiset root for each time/posting key set. An `SPI1` certificate has magic[4], version[2]=1, reserved[2]=0, count[8], XOR of SHA-256(key||value)[32], and CRC32C[4] over the preceding 48 bytes. Root updates and per-entry CRCs commit in the same apply transaction as rows/receipt/cursor; repeated posting overwrites remove the old digest first. Startup streams both indexes, verifies their complete counted roots and compares time-entry count with authoritative page row counts. A missing index entry therefore cannot silently become a successful empty startup result. Manifest index references record the current root certificates at their published cut. Future physical retention/deletion must update both key sets and roots transactionally, not drop a bucket behind this authority.

Times are metric/error/capability envelope `ObservedAt`; logs use explicit payload timestamp when present, otherwise `ObservedAt`; spans use start wall time; jobs use observed event time; replay uses clock wall time; profiles use start; loss uses interval start; conditions use event time. Every raw time filter is `[start,end)`. `ObservedTimes` separately preserves the envelope timestamp, so choosing a signal clock never rewrites retained records.

## Read and live ownership

 `Scan(context.Context,auth.Scope,ScanRequest)` authorizes every requested project and current credentials before any index lookup. Source-write credentials and zero/unmarshal-created scopes cannot read. A regular telemetry-read scope opens structured namespaces; restricted log reads require an auth-issued `raw.read` scope and an exact authorized `source_id` equality selector before restricted metadata/pages are touched. Auth-issued `profiles.read` permits only profile/capability/loss root kinds; capability/loss are additionally constrained to payload signal `profile_chunk` inside storage. Their namespace, page header, native payload and committed-feed route all enforce that restriction, before touching an unrelated sub-signal page. An unapproved root kind is denied before any lookup. No replacement telemetry scope is minted.

 Read-fence admission calls the replica owner's `replicaReadFence` after scope authorization and outside the engine mutex. The returned certified logical cut is retained directly; missing groups are excluded and partial state is explicit only when requested. Logical receipt/origin cursors are not replaced with physical Raft no-op indexes. Index origins outside the certified cut are skipped before page metadata/bytes are fetched. Chunk/EOF/watermark release calls `replicaReleaseFenceLocked`, then rechecks close/cancel and revalidates current credentials after its unlock/relock. No bbolt transaction crosses that network boundary. The replica owner supplies the real single-voter or quorum barrier; this format alone does not qualify HA.

A scan retains only its bounded current page, last index key, authorized namespace prefixes and admission watermarks. It does not materialize the dataset or hold a long-lived bbolt read transaction. Current page locations are resolved inside short transactions serialized with flush/compaction. Rows committed after scan admission are excluded by original cursors. This permits concurrent ingestion and relocation without duplicated tail rows or missing old-file reads. Scans revalidate at admission, before page lookup and again before releasing a chunk. Context cancellation closes/releases pages; corruption, denied scope and cancellation never become complete-exhaustion EOF. At most 32 active scans/subscriptions are admitted per engine; each subscription queue is bounded to 64 committed batches and each page to 128 rows/4 MiB.

`Page` and `ChangePage` borrow iterator-owned slices and nested payload graphs until the next `Next` or `Close`. Consumers that retain values must copy them at that boundary; ordinary iteration does not perform a deep copy per row. No retained OS file or database transaction survives a `Next` call.

 `Subscribe` registers a bounded actual committed-apply push feed. It never polls scans. A slow consumer receives `slow_consumer` with exact covered cursors; discarded in-flight epochs cannot deliver stale queued pages. An older reconnect, or a commit between certified admission and feed registration, yields `catch_up_required` rather than silently losing that window. Gap/page/watermark release uses the same current-scope and replica checks; a gap replacement/overrun during the unlocked barrier is rechecked before release. Confirmed credential revocation is distinct from replica/control unavailability. Cancellation closes/drains the queue and releases its page. The feed is not an exactly-once evidence journal. Durable lifecycle journals, physical retention/deletion, distributed tombstone barriers, snapshots and WAL truncation remain separate tasks.

 A revoked subscription ends with a final `ChangePage{Revoked:true}` whose `Cursors` are the cut the consumer was actually handed (rows and gap windows already delivered), never the engine's advance-on-commit watermark: that watermark also moves for events still queued, events dropped by an overrun and commits irrelevant to the scope, and `Subscribe` treats `After == mark` as caught up, so advertising it would silently skip `(delivered, marks]`. If a `catch_up_required`/`slow_consumer` gap is still pending when revocation is observed, the gap is delivered first as an ordinary gap page and the revoke page follows. The same rule applies to both revoke exits (revocation seen at the top of `Next` and revocation seen inside the release barrier). A consumer that resumes from the revoke cursors therefore receives each committed row exactly once or an explicit gap covering it.

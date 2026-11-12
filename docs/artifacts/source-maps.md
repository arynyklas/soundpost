<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Owned source maps

`internal/sourcemap` is a pure, independently authored v3 JSON/base64-VLQ decoder. It has no artifact-store, authorization, filesystem, subprocess or network dependency. Call `Decode(io.Reader, Limits)` on already authorized map bytes. A successful decode returns an immutable lookup index; `Lookup(line, column)` returns `(Position, mapped, error)`.

Generated and original lines are **one-based** at the public API. Columns are **zero-based UTF-16 code-unit offsets**, not UTF-8 bytes. Node stack columns must therefore be decremented once. Lookup uses the last segment at or before the requested column on that same generated line. It does not interpolate original columns, inherit a previous line's mapping or synthesize a function name. One-field segments explicitly end mapped ranges. Empty/unmapped locations return `mapped=false`; callers retain the original sanitized frame. Invalid maps and invalid generated lines also require callers to retain that frame rather than invent a result.

Indexed sections are inline only, ordered strictly by zero-based generated offset. Nested offsets add columns only on the first generated line of the child. Arithmetic is checked before narrowing. Duplicate/non-increasing section offsets, overlapping child mapping extents, overflow, remote section URLs, missing inline maps, mixed regular/indexed maps, malformed VLQ arity, non-increasing generated columns, invalid source/name indices and unsupported versions fail closed. Recursion means nested inline maps, not recursive reference resolution; there is no reference resolver.

`sourceRoot` and source entries are normalized as project-relative slash paths. Internal `.` and `..` components are canonicalized, but escaping above project root is rejected. Absolute/drive/UNC paths, schemes, backslashes, queries, fragments, encoded traversal escaping root, double-percent encodings and control/format characters are rejected. The returned identity is neither a local filename nor a fetch URL. Names are optional plain text, bounded to 256 bytes with control/format characters rejected. Render them as text, never HTML.

Zero-valued `Limits` uses C07 ceilings: 32 MiB input, 1024 cumulative source entries, 1024 inline map nodes and nesting depth 8 (root counts as one). The decoder additionally caps total mapping segments at 1,048,576. Positive caller limits only tighten ceilings; negative limits fail. Input is read through a ceiling plus one byte. No decompression occurs: an upstream archive owner must enforce C07's 32 MiB **expanded** bundle and 1024-file limits across the entire bundle. The symbolication process owner, not this pure library, enforces 100 ms/frame, five seconds/process and 256 MiB. Lookup uses binary searches and at most eight inline section levels.

`sourcesContent` and unknown extensions are not copied into the map index or Position. Errors are fixed content-free values: they contain no map text, source text, raw JSON diagnostic or supplied path. Protected source contents remain a separate policy-controlled artifact. This package grants no authorization and changes no artifact-storage behavior.

## Upload memory and admission

`artifacts.Service.Put` refuses a manifest whose declared size exceeds the source policy's `MaxBytes` before reading any body byte, then reserves estimated peak memory (declared size times four) from a non-queuing in-flight budget: 256 MiB globally and 128 MiB per principal by default, adjustable with `Service.LimitUploads`. A request that does not fit fails immediately with a retryable `quota` fault (HTTP 429 with `Retry-After: 1` on `POST /api/v1/artifacts`); nothing waits. The body is buffered once at its declared size, hashed, decoded with `sourcemap.DecodeBytes` (no second read) and split into the public and private outputs, whose bytes and digests are unchanged. The durable per-source byte quota is still charged on the transformed size after this phase. The 429 covers only this process's memory budget; the storage/replica write of the resulting fragments allocates considerably more transiently and is bounded only by that admission, not reduced by it. Operators should still set `GOMEMLIMIT` or a cgroup limit on the server.

## Real throwing fixture gate

The parent workspace pins `vite@7.3.7` (MIT). `generate.mjs` directly invokes Vite's production build API; no source-map decoding dependency or precomputed lookup table is used. It bundles and actually runs both TypeScript throwers with the invoking Node executable, parses the thrown generated frame and writes the generated maps and position evidence. The fixture producer canonicalizes its own output `sources` to project-relative fixture basenames and excludes source contents. `sections.map` wraps the actual second Vite map in a nonzero-offset indexed map.

Run from the repository root with the parent-installed pinned dependencies:

```text
.tools/node-v22.23.4-win-x64/node.exe fixtures/artifacts/generate.mjs <temp-artifact-dir>
SOUNDPOST_SOURCEMAP_FIXTURE_DIR=<temp-artifact-dir> .tools/go/bin/go.exe test ./internal/sourcemap -count=1
.tools/go/bin/go.exe run ./tools/smoke source-map --artifact-dir <temp-artifact-dir>
```

Set the environment variable with the current shell's syntax (the middle command above uses POSIX notation). Generation should print `Generated throwing Vite maps in ...`. Both thrown positions must resolve to their own `.ts` source, line 4, column 8. The smoke prints `source-map: actual thrown Vite positions and indexed offsets resolved; malformed maps rejected without content leakage`. It also checks the indexed offset wrapper and malformed/remote/traversal canaries. Unit tests without the environment variable explicitly skip only the real-bundler fixture gate; the shared `source-map` smoke never skips it. Its implementation directly invokes the decoder in `tools/smoke/sourcemap.go`; no shell or additional Go executable is launched.

## Mapping frames in the served process

`soundpost serve` resolves `POST /api/v1/evidence/frames` through the sandboxed worker of `docs/operations/symbolication.md` ("The served process"): the decoder above runs only inside that OS-isolated child, over the bytes of an artifact read through the same protected reader the artifact routes use (the caller's own organization, project, grant and retention fence; another organization's artifact answers exactly like an absent one). When the host cannot run the sandbox, or the operator turned it off with `--symbolicate-sandbox=off`, every frame keeps its original identity and answers `sandbox_unavailable`; nothing is mapped outside the sandbox. `sourcesContent` is removed at upload and never reaches a response, log or temp file unless an `include_sources` request is made by a reader holding the separate private-source grant.

First-party decoder, fixtures and smoke are Copyright 2026 Aryn Yklas, Apache-2.0. Go decoding uses only the standard library. Vite and its transitive build toolchain are fixture-only dependencies; exact source/integrity/license evidence belongs to the parent workspace's dependency inventory and lockfile. This document records expected commands, not an assertion that they have been executed.

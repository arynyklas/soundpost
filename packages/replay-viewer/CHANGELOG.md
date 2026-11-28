# Changelog

## Unreleased

- `renderReplay` shows the banner "Recording started after the page had loaded: pre-existing closed shadow roots may be unobservable." (`<p data-kind="late-start" role="note">`) when the first checkpoint (sequence 1) is gap-marked, which is how the recorder records a late start (D100); a supported start shows none.
- `renderTree` draws an opaque node whose text is the constant mask (the recorder's closed-shadow-root mark, 03.07-C7) as `[opaque: closed shadow root not observable]` with `data-opaque="closed-shadow"`, never its children; every other opaque node keeps `[opaque]`. No decode or vocabulary change.

## 0.1.0 — 2026-11-10

- Add `decodeChunk`: strict closed-format decoding that accepts exactly what the Go validator accepts (recorder version `"1"`, closed field/vocabulary set, 128 KiB / 4096-node/event caps, exact decimal-string integers up to 2^64-1, duplicate keys, lone surrogates, depth, BOM and trailing data refused) and hashes exactly like `replays.ChunkHash` (SHA-256 of canonical sorted-key JSON).
- Add `verifyChain`/`breakChain`: apply, checkpoint, gap or reject with an immutable state; no delta before its checkpoint, altered previous hash and wrong dependency reject, duplicates and stale chunks never re-apply, a valid next checkpoint resumes with the gap reported.
- Add `renderReplay`: fixed first-party inert DOM only (no innerHTML, no stream-derived attribute/URL/style), seek by decimal sequence, bounded history and model, visible gap timeline and opaque regions, and revocation/deletion/host-error handling that stops reading and clears every retained chunk.
- Add the sandboxed-frame helpers `VIEWER_SANDBOX`, `VIEWER_STYLE`, `viewerCsp`, `cspHash` and `attachFrameBridge`, the frame template `fixtures/sdk/replay/viewer.html`, the shared Go-generated cross-language vector file `fixtures/sdk/replay/chain-vectors.json` with its Go verifier, and the real-browser spec `fixtures/sdk/replay/viewer.spec.ts` (observed request, script, navigation and CSP counters).

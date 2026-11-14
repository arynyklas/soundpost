# @soundpost/replay-viewer

Copyright 2026 Aryn Yklas. Apache-2.0.

The inert renderer of the owned masked replay protocol (`docs/protocol/replay-v1.md`). It validates every chunk it is given, proves stream continuity, and builds only fixed first-party DOM. It owns decoding, chain verification and rendering; the experience layer owns authenticated fetching and supplies only a scope-authorized `ReplayStream`.

```ts
import {renderReplay, attachFrameBridge, VIEWER_SANDBOX, viewerCsp} from "@soundpost/replay-viewer";
const handle = renderReplay(container, stream);   // stream: AsyncIterable<ReplayItem>
await handle.seek("12");                           // decimal-string sequence
handle.status();                                   // "loading" | "ready" | "gap" | "unsupported" | "error"
handle.close();                                    // stops reading, clears DOM and every retained chunk
```

## Closed format, agreed with the Go validator

`decodeChunk(bytes, limits)` accepts exactly what `internal/replays` accepts (`model.StrictJSON` + `ValidateChunk`) and computes exactly `replays.ChunkHash`: SHA-256 over the canonical JSON (sorted keys, no whitespace, decimal-string integers) of the whole decoded chunk, independent of the wire's key order or whitespace. Recorder version is exactly `"1"`; the closed field set, the node tag/class/text vocabulary, coordinate bounds, the 128 KiB and 4096-node/event caps and the checkpoint/previous-hash rules are Go's. It is deliberately stricter in three places (case-exact keys, every field present, duplicate keys `malformed`); canonical server output is never affected. Limits passed by the caller can only narrow the protocol. Errors are `ReplayDecodeError` with a fixed code (`too_large`, `malformed`, `unsupported_version`, `invalid`, `limits`) and never echo content.

`fixtures/sdk/replay/chain-vectors.json` is the shared cross-language vector file: every hash and verdict in it was produced by the real Go validator and `ChunkHash` (`fixtures/sdk/replay/vectors_test.go` regenerates and verifies it; `SOUNDPOST_UPDATE_VECTORS=1 go test ./fixtures/sdk/replay -run TestChainVectors`). `test/stream.test.ts` asserts the same file, and also feeds real recorder output through the hash chain.

`verifyChain(chunk, state)` returns `apply`, `checkpoint`, `gap` or `reject` plus the next immutable state. A delta applies only when it directly extends the last applied chunk (sequence and previous hash), names the current verified checkpoint and no break is open. A missing chunk, an altered previous hash, a wrong checkpoint dependency, a recorder-declared gap or a delta with no checkpoint is never replayed best-effort: the chain stays broken until a valid checkpoint, which resumes with the gap reported. Duplicates and stale chunks leave the state untouched; a conflicting chunk at a seen sequence or a foreign session breaks the chain. The viewer shows the gap in its timeline for as long as the history is retained.

## Rendering and isolation

The renderer creates only `div span p section ol li` elements and sets only constant attributes (`data-*`, `role`, `inert`). Stream strings are exact-match lookup keys into constants; text is the constant `[masked]` or `[opaque]`; no `innerHTML`, no attribute/URL/style/markup from the stream, no `a`/`form`/`img`/`input`/`button` element is ever created, cycles/orphans/over-deep subtrees are unreachable or bounded, and the tree is `inert`.

Host it in a sandboxed iframe with `VIEWER_SANDBOX` (`allow-scripts`, never `allow-same-origin`) served with `viewerCsp(script, style)`: `default-src 'none'; connect-src 'none'; img-src 'none'; media-src 'none'; frame-src 'none'` plus a script and a style allowed by exact SHA-256 only, `form-action 'none'`, `base-uri 'none'`. `fixtures/sdk/replay/viewer.html` is the frame template and `attachFrameBridge(window, container)` the postMessage glue (only messages from the parent window; messages are rebuilt into closed items; a chunk flood is dropped so the hole shows as a gap).

Revocation, deletion or any host error (`{kind:"revoke"}`, `{kind:"error"}`, a rejecting stream, a malformed item) stops reading (the iterator's `return()` is called), clears the DOM and drops every retained chunk and node; nothing is cached across the scoped lifetime. `handle.retained()` reports what the renderer still holds (zero after close or stop). History for `seek` is bounded (`maxRetainedNodes`, oldest complete checkpoint groups dropped first); the reconstructed tree is bounded (`maxModelNodes`, beyond it the view stops).

## Known limits

- The Go closed format has no node rectangle or presentation field, so layout is structure and tag only. The recorder (`packages/browser`) still emits `rect`/`pres` and a wider tag enum that Go refuses; see its README and CHANGELOG. Until that is reconciled, recorder chunks are refused by this viewer exactly as the server would refuse them.
- Closed shadow roots, frames and unsupported widgets arrive as opaque nodes; nothing inside them exists.
- Exact browser-matrix support is parent-qualified: the real-browser rows here ran on Chrome 156 only.

## Checks

`bun test packages/replay-viewer/test/stream.test.ts`; `tsc --noEmit -p packages/replay-viewer/tsconfig.json` (and `tsconfig.test.json`); `go test ./fixtures/sdk/replay`; real browser: `playwright test -c fixtures/sdk/replay/playwright.config.ts --project=chromium --grep "no network|gap recovery|revoked stream"` (`SOUNDPOST_BUN` = bun used to bundle the viewer, `SOUNDPOST_CHROME` = optional Chrome executable).

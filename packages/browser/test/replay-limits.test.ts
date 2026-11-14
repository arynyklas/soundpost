// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// The server admits at most 65536 chunks and 1024 checkpoints per replay (internal/replays MaxSequence, MaxCheckpoints) and refuses
// the rest; a refused chunk would poison its whole ingest batch. The recorder therefore ends capture at its budget instead of emitting
// anything outside the server's closed schema.
import {test, expect} from "bun:test";
import {createRecorder} from "../src/replay/recorder.ts";
import {MAX_CHECKPOINTS, MAX_SEQUENCE} from "../src/replay/policy.ts";
import type {ReplayChunk} from "../src/replay/types.ts";
import {CHECKPOINT_MS, FLUSH_MS, scriptedPage} from "./recorded-session.ts";

function recording() {
 const stage = scriptedPage();
 const chunks: ReplayChunk[] = [];
 const recorder = createRecorder({...stage.config, projectPolicy: true, deploymentOptIn: true}, chunk => { chunks.push(chunk); return "accepted"; });
 recorder.setConsent(true);
 return {stage, chunks, recorder};
}

test("the constants mirror the server's ceilings", () => {
 expect(MAX_SEQUENCE).toBe(65536);
 expect(MAX_CHECKPOINTS).toBe(1024);
});

test("capture ends after the 1024th checkpoint and never resumes", () => {
 const {stage, chunks, recorder} = recording();
 for (let i = 0; i < MAX_CHECKPOINTS + 20; i++) stage.fire(CHECKPOINT_MS);
 expect(chunks).toHaveLength(MAX_CHECKPOINTS);
 expect(chunks.every(chunk => chunk.sequence === chunk.checkpoint_sequence)).toBe(true);
 expect(chunks.at(-1)!.sequence).toBe(String(MAX_CHECKPOINTS));
 stage.pointer("button", 1, 1); stage.fire(FLUSH_MS); stage.grow();
 recorder.setConsent(false); recorder.setConsent(true);
 expect(chunks).toHaveLength(MAX_CHECKPOINTS);
});

test("capture ends after the 65536th chunk and never resumes", () => {
 const {stage, chunks, recorder} = recording();
 for (let i = 0; i < MAX_SEQUENCE + 20; i++) { stage.pointer("html", i, i); stage.fire(FLUSH_MS); }
 expect(chunks).toHaveLength(MAX_SEQUENCE);
 expect(chunks.at(-1)!.sequence).toBe(String(MAX_SEQUENCE));
 recorder.setConsent(false); recorder.setConsent(true);
 stage.pointer("html", 1, 1); stage.fire(FLUSH_MS);
 expect(chunks).toHaveLength(MAX_SEQUENCE);
}, 60_000); // 65,556 real flushes: 8-11 s on Linux bun 1.3.14, past bun's 5 s default.

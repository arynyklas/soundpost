// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// The core entry must not pull the replay recorder or the profiler into its bundle (design 13: core <=40 KiB gzip, replay separate).
import {test, expect} from "bun:test";
import {mkdtempSync, readFileSync} from "node:fs";
import {spawnSync} from "node:child_process";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";

const SRC = resolve(import.meta.dir, "../src");

function graph(entry: string): Set<string> {
 const seen = new Set<string>(), pending = [resolve(SRC, entry)];
 while (pending.length > 0) {
  const file = pending.pop()!;
  if (seen.has(file)) continue;
  seen.add(file);
  const text = readFileSync(file, "utf8");
  for (const match of text.matchAll(/(?:^|\n)\s*(?:import|export)\s(?!type\s)[^"';]*?from\s*"(\.[^"]+)"|(?:^|\n)\s*import\s*"(\.[^"]+)"/g)) pending.push(resolve(dirname(file), (match[1] ?? match[2])!));
 }
 return seen;
}

test("the core entry imports neither the replay recorder nor the profiler", () => {
 const files = [...graph("index.ts")].map(file => file.slice(SRC.length + 1).replaceAll("\\", "/"));
 expect(files).toContain("index.ts");
 expect(files.filter(file => file.startsWith("replay") || file.startsWith("profile"))).toEqual([]);
});

test("replay and profile are their own entries", () => {
 const names = (entry: string) => [...graph(entry)].map(file => file.replaceAll("\\", "/"));
 expect(names("replay.ts").some(file => file.endsWith("replay/recorder.ts"))).toBe(true);
 expect(names("profile.ts").some(file => file.endsWith("profile_wire.ts"))).toBe(true);
});

// Built by a separate `bun build` process: an in-process Bun.build inside `bun test` breaks module resolution for every later
// test file in the run.
test("the core entry bundle carries neither the spool recovery nor the runtime profile mapping", () => {
 const out = join(mkdtempSync(join(tmpdir(), "sp-core-entry-")), "core.js");
 const built = spawnSync(process.execPath, ["build", resolve(SRC, "index.ts"), "--target", "browser", "--outfile", out], {encoding: "utf8"});
 expect(built.stderr).toBe("");
 expect(built.status).toBe(0);
 const text = readFileSync(out, "utf8");
 expect(text).not.toContain("invalid frozen spool");
 expect(text).not.toContain("runtime_cpu");
 expect(text).toContain("delivery"); // sanity: the queue itself is still in the bundle
});

// The design's browser budgets (docs/superpowers/specs design 13 "Browser SDK/replay": core <=40 KiB gzip, replay separate <=60 KiB gzip), measured the way
// fixtures/sdk/overhead.mjs --only bundle measures them: `bun build --target=browser --format=esm --minify` of one entry, then gzip level 9 by Node's zlib (that
// harness runs under Node; Bun's own zlib compresses the same file about 0.7% smaller, which would let this test pass while the qualification row fails). The budgets
// are the design's and are never raised here: a failing size means the entry grew, and the fix is in the code.
const BROWSER_CORE_GZIP_BUDGET = 40 * 1024, BROWSER_REPLAY_GZIP_BUDGET = 60 * 1024;
const NODE = process.env.SOUNDPOST_NODE ?? "node";
function minifiedGzipBytes(entry: string): number {
 const out = join(mkdtempSync(join(tmpdir(), "sp-size-")), "entry.js");
 const built = spawnSync(process.execPath, ["build", resolve(SRC, entry), "--target=browser", "--format=esm", "--minify", "--outfile", out], {encoding: "utf8"});
 expect(built.stderr).toBe("");
 expect(built.status).toBe(0);
 const measured = spawnSync(NODE, ["-e", 'process.stdout.write(String(require("node:zlib").gzipSync(require("node:fs").readFileSync(process.argv[1]), {level: 9}).length))', out], {encoding: "utf8"});
 if (measured.error !== undefined) throw new Error(`the bundle size is measured with Node's zlib like the qualification row; set SOUNDPOST_NODE or put node on PATH (${measured.error.message})`);
 expect(measured.status).toBe(0);
 return Number(measured.stdout);
}

test("the core entry bundle is within the design's 40 KiB gzip budget", () => {
 expect(minifiedGzipBytes("index.ts")).toBeLessThanOrEqual(BROWSER_CORE_GZIP_BUDGET);
});

test("the replay entry bundle is within the design's 60 KiB gzip budget", () => {
 expect(minifiedGzipBytes("replay.ts")).toBeLessThanOrEqual(BROWSER_REPLAY_GZIP_BUDGET);
});

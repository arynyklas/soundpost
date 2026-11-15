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

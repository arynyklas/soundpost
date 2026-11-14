// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// The core entry must not pull the replay recorder or the profiler into its bundle (design 13: core <=40 KiB gzip, replay separate).
import {test, expect} from "bun:test";
import {readFileSync} from "node:fs";
import {dirname, resolve} from "node:path";

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

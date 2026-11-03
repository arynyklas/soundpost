// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import { build } from 'vite';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.resolve(process.argv[2] ?? path.join(here, 'generated'));
await mkdir(out, { recursive: true });
for (const entry of ['simple', 'indexed']) {
  const result = await build({ configFile: false, root: here, logLevel: 'error', build: { write: false, minify: false, sourcemap: true, target: 'es2022', lib: { entry: path.join(here, `${entry}.ts`), formats: ['es'], fileName: () => `${entry}.mjs` }, rollupOptions: { output: { sourcemapExcludeSources: true } } } });
  // Library builds can return one RollupOutput per configured format.
  const outputs = Array.isArray(result) ? result : [result];
  const chunks = outputs.flatMap(output => output.output ?? []).filter(x => x.type === 'chunk' && x.isEntry);
  if (chunks.length !== 1) throw new Error('Vite did not produce exactly one entry chunk');
  const chunk = chunks[0];
  if (!chunk?.map) throw new Error('Vite did not produce entry source map');
  // Only the fixture producer knows its filesystem root. The decoder never resolves it.
  const map = JSON.parse(chunk.map.toString());
  map.sources = map.sources.map(s => path.posix.basename(s));
  delete map.sourcesContent;
  const code = chunk.code;
  const filename = path.join(out, `${entry}.mjs`);
  await writeFile(filename, code);
  await writeFile(`${filename}.map`, JSON.stringify(map));
  const run = spawnSync(process.execPath, [filename], { encoding: 'utf8' });
  if (run.error || run.status === 0 || run.status === null) throw new Error('Fixture did not execute and throw');
  const frame = run.stderr.split('\n').find(line => /at (throwingFixture|indexedFixture) /.test(line));
  const match = frame?.trim().match(/:(\d+):(\d+)\)?$/);
  if (!match) throw new Error('Missing thrown generated stack position');
  // Stack columns are one-based; source-map columns are zero-based.
  const evidence = { generatedLine: Number(match[1]), generatedColumn: Number(match[2]) - 1, sourceID: `${entry}.ts`, line: 4, column: 8 };
  await writeFile(path.join(out, `${entry}.position.json`), JSON.stringify(evidence));
  if (entry === 'indexed') {
    await writeFile(path.join(out, 'sections.map'), JSON.stringify({ version: 3, sections: [{ offset: { line: 2, column: 7 }, map }] }));
  }
}
console.log(`Generated throwing Vite maps in ${out}`);

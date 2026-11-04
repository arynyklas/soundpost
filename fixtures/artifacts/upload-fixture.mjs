// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Generates public, inert build evidence only. Scope IDs/retention/credentials
// belong in the integration owner's private manifest/config outside this repo.
import { mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve, join } from 'node:path';

const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--artifact-dir') {
  throw new Error('expected --artifact-dir <private-output-directory>');
}
const output = resolve(args[1]);
await mkdir(output, { recursive: true, mode: 0o700 });
// Real generated module text and its own deterministic v3 map. 70,000 generated
// lines force the sanitized map across more than one 256-KiB WAL fragment.
const lines = 70_000;
const generated = `${Array.from({ length: lines }, (_, i) => `export const value${i} = ${i};`).join('\n')}\n`;
const map = JSON.stringify({
  version: 3,
  sources: ['src/upload-fixture.ts'],
  names: [],
  mappings: Array.from({ length: lines }, (_, i) => i === 0 ? 'AAAA' : 'AACA').join(';'),
  sourcesContent: [generated],
});
const hash = (value) => createHash('sha256').update(value).digest('hex');
await mkdir(join(output, 'src'), { recursive: true, mode: 0o700 });
await writeFile(join(output, 'src', 'upload-fixture.ts'), generated, { mode: 0o600 });
await writeFile(join(output, 'upload-fixture.mjs'), generated, { mode: 0o600 });
await writeFile(join(output, 'upload-fixture.mjs.map'), map, { mode: 0o600 });
await writeFile(join(output, 'upload-fixture.identity.json'), JSON.stringify({
  debug_id: 'soundpost-owned-upload-fixture-v1',
  path: 'dist/upload-fixture.mjs',
  generated_sha256: hash(generated),
  map_sha256: hash(map),
  size: String(Buffer.byteLength(map)),
  source_content: false,
}, null, 2), { mode: 0o600 });

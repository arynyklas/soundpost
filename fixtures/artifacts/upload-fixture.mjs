// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Generates public, inert build evidence only. Scope IDs/retention/credentials
// belong in the integration owner's private manifest/config outside this repo.
import { mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve, join } from 'node:path';

const args = process.argv.slice(2);
const usage = 'expected --artifact-dir <private-output-directory> [--source-content]';
let artifactDir = '';
let sourceContent = false;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--artifact-dir' && i + 1 < args.length) artifactDir = args[++i];
  else if (args[i] === '--source-content') sourceContent = true;
  else throw new Error(usage);
}
if (artifactDir === '') throw new Error(usage);
const output = resolve(artifactDir);
await mkdir(output, { recursive: true, mode: 0o700 });
// Real generated module text and its own deterministic v3 map. Every generated
// line carries three genuine mapping segments (base64 VLQ), so the RETAINED
// map (what remains after the server strips sourcesContent) is itself larger
// than two 256-KiB WAL fragments. Size does not come from padding: sourcesContent
// is removed by the transformer and so cannot count; the script proves it below.
const lines = 70_000;
const generated = `${Array.from({ length: lines }, (_, i) => `export const value${i} = ${i};`).join('\n')}\n`;
// Segment 1 starts the line (source column returns by -9 after the previous
// line's +4 and +5 column deltas); segments 2 and 3 advance columns 4 and 5.
const mappings = Array.from({ length: lines }, (_, i) => `${i === 0 ? 'AAAA' : 'AACT'},IAAI,KAAK`).join(';');
const document = {
  version: 3,
  sources: ['src/upload-fixture.ts'],
  names: [],
  mappings,
  sourcesContent: [generated],
};
const map = JSON.stringify(document);
const { sourcesContent: _stripped, ...retainedDocument } = document;
const retainedSize = Buffer.byteLength(JSON.stringify(retainedDocument));
const fragmentLimit = 256 * 1024;
if (retainedSize <= 2 * fragmentLimit) {
  throw new Error(`retained map ${retainedSize} B is not larger than 512 KiB without sourcesContent`);
}
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
  retained_size: retainedSize,
  source_content: sourceContent,
}, null, 2), { mode: 0o600 });
console.log(JSON.stringify({ uploaded_map_bytes: Buffer.byteLength(map), retained_map_bytes: retainedSize, source_content: sourceContent }));

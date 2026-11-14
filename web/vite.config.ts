// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build, defineConfig, type Plugin } from 'vite';
import { VIEWER_STYLE } from '../packages/replay-viewer/src/render.ts';

const here = dirname(fileURLToPath(import.meta.url));

/** Builds the sandboxed replay viewer frame as a same-origin static asset. The document inlines exactly one classic script
 * and one style so the server can serve it under the viewer's hash-only CSP (no 'unsafe-inline', no network); the app's
 * own CSP is not loosened for scripts. */
function replayFrame(): Plugin {
 return {
  name: 'soundpost-replay-frame',
  apply: 'build',
  async closeBundle() {
   const result = await build({
    configFile: false, logLevel: 'silent', root: here,
    build: { write: false, minify: true, target: 'es2022', lib: { entry: resolve(here, 'frame/replay-frame.ts'), formats: ['iife'], name: 'SoundpostReplayFrame', fileName: 'frame' } },
   });
   const outputs = (Array.isArray(result) ? result : [result]).flatMap((r) => ('output' in r ? r.output : []));
   const chunk = outputs.find((o) => o.type === 'chunk');
   if (chunk?.type !== 'chunk') throw new Error('replay frame: no script was built');
   const script = chunk.code;
   if (/<\/script/i.test(script) || /<!--/.test(script)) throw new Error('replay frame: the script cannot be inlined safely');
   if (/<\/style/i.test(VIEWER_STYLE)) throw new Error('replay frame: the style cannot be inlined safely');
   const html = `<!doctype html>\n<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->\n<html lang="en"><head><meta charset="utf-8"><title>Soundpost replay</title><style>${VIEWER_STYLE}</style></head><body><div id="replay"></div><script>${script}</script></body></html>\n`;
   const out = resolve(here, 'dist/assets/replay-frame.html');
   mkdirSync(dirname(out), { recursive: true });
   writeFileSync(out, html);
  },
 };
}

export default defineConfig({ plugins: [replayFrame()], build: { outDir: 'dist', emptyOutDir: true, sourcemap: false, target: 'es2022' }, server: { host: '127.0.0.1' } });

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Entry of the sandboxed replay viewer frame. vite.config.ts bundles it into ONE classic script (an IIFE) and inlines it,
// with VIEWER_STYLE, into dist/assets/replay-frame.html. The Go server serves that document under viewerCsp(script, style)
// (hash-only script and style, no network of any kind) and the app embeds it as <iframe sandbox="allow-scripts">. The frame
// reads chunks only from postMessage of its parent (attachFrameBridge); it reports only its status string back.
import { attachFrameBridge } from '../../packages/replay-viewer/src/index.ts';

const host = document.getElementById('replay');
if (host !== null) {
 attachFrameBridge(window, host, { onStatus: (status) => window.parent.postMessage({ soundpost: 'status', status }, '*') });
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Stock Firefox (not a Playwright-patched build) driven by Playwright's WebDriver BiDi channel (`moz-firefox`).
//
// Playwright 1.64 sends `browser.setDownloadBehavior` for every new browser context, and stock Firefox 144 answers `unknown command`,
// so no context can be created. This process stands in for the Firefox executable: it starts the real binary (SOUNDPOST_FIREFOX_BINARY)
// with the arguments Playwright passed, relays the BiDi WebSocket byte for byte, and answers ONLY the commands listed in `stubbed`
// itself with an empty success. Nothing else is rewritten, so every page behaviour under test is stock Firefox's. The download behavior
// is the only thing not applied (no fixture downloads anything).
import {spawn} from "node:child_process";

const real = process.env.SOUNDPOST_FIREFOX_BINARY;
if (!real) throw Error("SOUNDPOST_FIREFOX_BINARY is required");
const stubbed: Record<string, true> = {"browser.setDownloadBehavior": true, "emulation.setScreenSettingsOverride": true};

const child = spawn(real, process.argv.slice(2), {stdio: ["ignore", "inherit", "pipe"]});
let target = "";
let seen = "";
const listening = new Promise<void>(done => {
 child.stderr.on("data", (chunk: Buffer) => {
  const text = chunk.toString();
  // Playwright must learn the proxy's address, never Firefox's own.
  process.stderr.write(text.replace(/WebDriver BiDi listening on ws:[^\n]*\n?/, ""));
  if (target) return;
  seen += text;
  const match = /WebDriver BiDi listening on (ws:\/\/[^\s]+)/.exec(seen);
  if (match) { target = match[1]!; done(); }
 });
});
child.on("exit", code => process.exit(code ?? 1));
process.on("SIGTERM", () => { child.kill("SIGTERM"); });
await listening;

interface Link {upstream: WebSocket; pending: string[]}
const links = new WeakMap<object, Link>();
const server = Bun.serve<{path: string}>({
 hostname: "127.0.0.1", port: 0,
 fetch(request, srv) { return srv.upgrade(request, {data: {path: new URL(request.url).pathname}}) ? undefined : new Response("upgrade required", {status: 426}); },
 websocket: {
  open(ws) {
   const link: Link = {upstream: new WebSocket(target.replace(/\/$/, "") + ws.data.path), pending: []};
   links.set(ws, link);
   link.upstream.onopen = () => { for (const message of link.pending) link.upstream.send(message); link.pending = []; };
   link.upstream.onmessage = event => ws.send(event.data as string);
   link.upstream.onclose = () => ws.close();
  },
  message(ws, message) {
   const link = links.get(ws)!;
   const text = typeof message === "string" ? message : message.toString();
   try {
    const command = JSON.parse(text) as {id?: number; method?: string};
    if (command.method !== undefined && stubbed[command.method]) { ws.send(JSON.stringify({type: "success", id: command.id, result: {}})); return; }
   } catch { /* not JSON: relay unchanged */ }
   if (link.upstream.readyState === WebSocket.OPEN) link.upstream.send(text); else link.pending.push(text);
  },
  close(ws) { links.get(ws)?.upstream.close(); },
 },
});
process.stderr.write(`WebDriver BiDi listening on ws://127.0.0.1:${server.port}\n`);

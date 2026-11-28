// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {execFileSync} from "node:child_process";
import {mkdtempSync, readFileSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join, resolve} from "node:path";

/*
 * The pages, policies and payloads shared by every real-browser proof of the replay viewer: the Playwright rows in viewer.spec.ts
 * (Chromium) and the own WebDriver BiDi driver in viewer-firefox.ts (stock Firefox, whose BiDi frame evaluation in Playwright is an
 * eval that the viewer's production CSP correctly blocks). Both build the viewer from source, serve the same documents and send
 * the same hostile chunks, so a row cannot pass in one browser on weaker material than in the other.
 */
export const root = resolve(__dirname, "../../..");
const bun = process.env.SOUNDPOST_BUN ?? "bun";
const dir = mkdtempSync(join(tmpdir(), "soundpost-viewer-"));
export const origin = "http://soundpost.test";
const viewerSource = join(root, "packages/replay-viewer/src/index.ts").replaceAll("\\", "/");

writeFileSync(join(dir, "frame-entry.ts"), `import {attachFrameBridge} from ${JSON.stringify(viewerSource)};
attachFrameBridge(window, document.getElementById("replay") as HTMLElement, {onStatus: status => window.parent.postMessage({soundpost: "status", status}, "*")});
`);
// Control: the renderer's tree builder alone, handed hostile typed nodes (decoding bypassed), with NO CSP at all.
writeFileSync(join(dir, "direct-entry.ts"), `import {renderTree} from ${JSON.stringify(viewerSource)};
window.addEventListener("message", event => { if (event.source === window.parent) document.getElementById("replay")!.append(renderTree(document, event.data.nodes)); });
window.parent.postMessage({soundpost: "status", status: "loading"}, "*");
`);
const build = (entry: string, out: string, target: string, format: string): void => { execFileSync(bun, ["build", join(dir, entry), "--outfile", join(dir, out), `--target=${target}`, `--format=${format}`], {stdio: "pipe"}); };
build("frame-entry.ts", "frame.js", "browser", "iife");
build("direct-entry.ts", "direct.js", "browser", "iife");
execFileSync(bun, ["build", viewerSource, "--outfile", join(dir, "helper.cjs"), "--target=node", "--format=cjs"], {stdio: "pipe"});
export const helper = require(join(dir, "helper.cjs")) as {VIEWER_STYLE: string; VIEWER_SANDBOX: string; viewerCsp: (script: string, style: string) => string};
const template = readFileSync(join(root, "fixtures/sdk/replay/viewer.html"), "utf8");
const fill = (script: string): string => template.replace("/*__VIEWER_STYLE__*/", () => helper.VIEWER_STYLE).replace("/*__VIEWER_SCRIPT__*/", () => script);
const frameScript = readFileSync(join(dir, "frame.js"), "utf8"), directScript = readFileSync(join(dir, "direct.js"), "utf8");
export const frameHtml = fill(frameScript), directHtml = fill(directScript);
export const csp = helper.viewerCsp(frameScript, helper.VIEWER_STYLE);

/** The deliberately vulnerable renderer used only to prove the counters can see an attack. */
export const vulnerableHtml = `<!doctype html><body><div id="replay"></div><script>
addEventListener("message", e => { if (e.source === parent) document.getElementById("replay").innerHTML = e.data.html; });
parent.postMessage({soundpost: "status", status: "loading"}, "*");
</script></body>`;
export const hostHtml = `<!doctype html><body><iframe id="f" sandbox="${helper.VIEWER_SANDBOX}" src="/frame.html"></iframe><script>
window.__messages = [];
addEventListener("message", e => { if (e.source === document.getElementById("f").contentWindow) window.__messages.push(e.data); });
const toBytes = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
window.__sendChunk = b64 => document.getElementById("f").contentWindow.postMessage({soundpost: "replay", item: {kind: "chunk", bytes: toBytes(b64)}}, "*");
window.__sendItem = item => document.getElementById("f").contentWindow.postMessage({soundpost: "replay", item}, "*");
window.__sendRaw = data => document.getElementById("f").contentWindow.postMessage(data, "*");
window.__fromSibling = spec => {
  const message = spec.b64 !== undefined
    ? "{soundpost: 'replay', item: {kind: 'chunk', bytes: Uint8Array.from(atob(" + JSON.stringify(spec.b64) + "), c => c.charCodeAt(0)).buffer}}"
    : JSON.stringify({soundpost: "replay", item: spec.item}).replace(/</g, "\\u003c");
  const sibling = document.createElement("iframe");
  sibling.setAttribute("sandbox", "allow-scripts");
  sibling.srcdoc = "<script>parent.frames[0].postMessage(" + message + ", '*');<" + "/script>";
  document.body.appendChild(sibling);
};
</script></body>`;

export interface VectorChunk {wire?: string; go: {verdict: string}}
export const vectors = JSON.parse(readFileSync(join(root, "fixtures/sdk/replay/chain-vectors.json"), "utf8")) as {chunks: Record<string, VectorChunk>};
export const b64 = (name: string): string => Buffer.from(vectors.chunks[name]!.wire!, "utf8").toString("base64");
export const forbidden = /evil\.test|soundpost\.test\/(pwn|probe)|PWN/;

export const ELEMENTS = ["div", "span", "p", "section", "ol", "li"];
export const ATTRIBUTES = ["id", "data-replay-root", "data-state", "data-replay-status", "role", "data-replay-tree", "inert", "data-tag", "data-opaque", "data-masked", "data-replay-timeline", "data-replay-interactions", "data-kind", "data-sequence"];

export const hostileNodes = [
 {id: "1", parent: "0", tag: "img src=x onerror=parent.postMessage('PWN','*')", class: "\"><svg onload=parent.postMessage('PWN','*')>", text: "<img src='http://soundpost.test/pwn-text.png'>"},
 {id: "2", parent: "1", tag: "script", class: "masked", text: "javascript:parent.postMessage('PWN','*')"},
 {id: "3", parent: "1", tag: "a", class: "", text: "[masked]"},
 {id: "4", parent: "3", tag: "iframe", class: "", text: "url(http://evil.test/css)"},
 {id: "5", parent: "4", tag: "input", class: "", text: "[masked]"},
 {id: "6", parent: "6", tag: "div", class: "", text: ""},
 {id: "7", parent: "8", tag: "div", class: "", text: ""},
 {id: "8", parent: "7", tag: "div", class: "", text: ""},
 {id: "9", parent: "1", tag: "style", class: "", text: "@import url(http://evil.test/x.css)"},
];

/** The payload chunks of the production row: each is the valid checkpoint c1 with one field replaced by hostile content. */
export function hostilePayloads(): string[] {
 const payloadChunk = (mutate: (chunk: Record<string, unknown>) => void): string => { const chunk = JSON.parse(vectors.chunks["c1"]!.wire!) as Record<string, unknown>; mutate(chunk); return Buffer.from(JSON.stringify(chunk), "utf8").toString("base64"); };
 return [
  payloadChunk(chunk => { chunk["nodes"] = hostileNodes; }),
  payloadChunk(chunk => { chunk["html"] = "<img src=http://soundpost.test/pwn-html.png onerror=parent.postMessage('PWN','*')>"; }),
  payloadChunk(chunk => { chunk["recorder_version"] = "1<script>parent.postMessage('PWN','*')</script>"; }),
  payloadChunk(chunk => { chunk["clock"] = {style: "background:url(http://evil.test/bg)", href: "javascript:parent.postMessage('PWN','*')"}; }),
 ];
}
/** Every vector chunk the Go validator refused, as wire names (the production row sends all of them). */
export const hostileWireNames = (): string[] => Object.entries(vectors.chunks).filter(([, entry]) => entry.go.verdict !== "valid" && entry.wire !== undefined).map(([name]) => name);

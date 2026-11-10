// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {ReplayPresentation, ReplayTag} from "./types.ts";

export const MASK = "[masked]" as const;
export const RECORDER_VERSION = "1";
export const MAX_NODES = 20000;
export const MAX_CHUNK_BYTES = 120000;
export const MAX_MUTATION_ROOTS = 64;
export const MAX_MUTATION_RECORDS = 512;
export const CHECKPOINT_INTERVAL_MS = 30000;
export const EVENT_FLUSH_MS = 1000;
export const MAX_PENDING_EVENTS = 1024;
export const MAX_DEPTH = 256;
export const ZERO_HASH = "0".repeat(64);

const TAGS: ReadonlySet<string> = new Set(["html", "body", "div", "span", "p", "button", "input", "section", "canvas", "img", "a", "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6", "form", "label", "nav", "main", "header", "footer", "article", "aside", "table", "tr", "td", "th"]);
/** Elements with no replay representation at all (code, style and metadata are never walked). */
const SKIPPED: ReadonlySet<string> = new Set(["script", "style", "template", "noscript", "head", "link", "meta", "title", "base"]);
/** Frames, embedded media and widgets whose value or content cannot be masked structurally. */
const OPAQUE: ReadonlySet<string> = new Set(["iframe", "frame", "frameset", "object", "embed", "video", "audio", "select", "textarea", "datalist", "option", "optgroup", "portal", "fencedframe", "dialog"]);

/** Allowlisted tag, or "masked" for anything outside the enum (custom elements, SVG, MathML). */
export function tagFor(localName: string): ReplayTag {
 return TAGS.has(localName) ? (localName as ReplayTag) : "masked";
}
export function isSkipped(localName: string): boolean { return SKIPPED.has(localName); }
export function isOpaqueWidget(localName: string): boolean { return OPAQUE.has(localName); }

/** Quantize to a multiple of 8 CSS px and clamp to ±32768. Non-finite input becomes 0. */
export function quantize(value: number): number {
 if (typeof value !== "number" || !Number.isFinite(value)) return 0;
 const q = Math.round(value / 8) * 8;
 return Math.max(-32768, Math.min(32768, q)) + 0;
}

const DISPLAY: Readonly<Record<string, ReplayPresentation>> = {inline: "inline", "inline-block": "inline", block: "block", "list-item": "block", flex: "flex", "inline-flex": "flex", grid: "grid", "inline-grid": "grid", none: "hidden"};
export function presentationFor(display: string, visibility: string): ReplayPresentation {
 if (visibility === "hidden" || visibility === "collapse") return "hidden";
 return typeof display === "string" && Object.hasOwn(DISPLAY, display) ? DISPLAY[display]! : "other";
}

/** Capture needs project policy AND deployment opt-in AND explicit consent, each strictly true. */
export function captureAllowed(projectPolicy: unknown, deploymentOptIn: unknown, consent: unknown): boolean {
 return projectPolicy === true && deploymentOptIn === true && consent === true;
}

const K = Uint32Array.from([
 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
/** Synchronous SHA-256 hex of a UTF-8 string (WebCrypto is async; the hash chain must be built inline). */
export function sha256Hex(input: string): string {
 const data = new TextEncoder().encode(input), padded = new Uint8Array(((data.length + 9 + 63) >> 6) << 6);
 padded.set(data); padded[data.length] = 0x80;
 const view = new DataView(padded.buffer), bits = data.length * 8;
 view.setUint32(padded.length - 8, Math.floor(bits / 4294967296)); view.setUint32(padded.length - 4, bits >>> 0);
 const h = Uint32Array.from([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]), w = new Uint32Array(64);
 const rotr = (x: number, n: number): number => (x >>> n) | (x << (32 - n));
 for (let off = 0; off < padded.length; off += 64) {
  for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
  for (let i = 16; i < 64; i++) { const a = w[i - 15]!, b = w[i - 2]!; w[i] = (w[i - 16]! + (rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3)) + w[i - 7]! + (rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10))) >>> 0; }
  let [a, b, c, d, e, f, g, hh] = h as unknown as [number, number, number, number, number, number, number, number];
  for (let i = 0; i < 64; i++) {
   const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i]! + w[i]!) >>> 0, t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
   hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
  }
  h[0] = (h[0]! + a) >>> 0; h[1] = (h[1]! + b) >>> 0; h[2] = (h[2]! + c) >>> 0; h[3] = (h[3]! + d) >>> 0; h[4] = (h[4]! + e) >>> 0; h[5] = (h[5]! + f) >>> 0; h[6] = (h[6]! + g) >>> 0; h[7] = (h[7]! + hh) >>> 0;
 }
 return Array.from(h, value => value.toString(16).padStart(8, "0")).join("");
}

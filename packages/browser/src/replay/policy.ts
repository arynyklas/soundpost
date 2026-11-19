// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {ReplayTag} from "./types.ts";

export const MASK = "[masked]" as const;
export const RECORDER_VERSION = "1";
export const MAX_NODES = 20000;
export const MAX_CHUNK_BYTES = 120000;
/** Protocol ceiling of nodes in one chunk (internal/replays: 4096). */
export const MAX_CHUNK_NODES = 4096;
/** Reserve for the one gap event a truncation adds. */
export const GAP_EVENT_BYTES = 96;
export const MAX_MUTATION_ROOTS = 64;
/** Records of one observer callback the recorder will attribute; a larger burst is a declared gap and one full checkpoint (a bound on main-thread work, not a cadence: ordinary bursts, such as a list re-render of a few hundred rows, are deltas). */
export const MAX_MUTATION_RECORDS = 4096;
export const CHECKPOINT_INTERVAL_MS = 30000;
export const EVENT_FLUSH_MS = 1000;
export const MAX_PENDING_EVENTS = 1024;
export const MAX_DEPTH = 256;
export const ZERO_HASH = "0".repeat(64);
/** Largest node id the server admits (internal/replays maxNodeID). */
export const MAX_NODE_ID = 2 ** 31;
/** Largest chunk sequence of one replay and most checkpoints of one replay the server admits (internal/replays MaxSequence, MaxCheckpoints). */
export const MAX_SEQUENCE = 1 << 16;
export const MAX_CHECKPOINTS = 1024;

/** The server's closed tag vocabulary (internal/replays nodeTags) minus the generic "masked". Anything else is recorded as "masked". */
const TAGS: ReadonlySet<string> = new Set(["div", "span", "p", "button", "input", "section", "canvas"]);
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

/** Capture needs project policy AND deployment opt-in AND explicit consent, each strictly true. */
export function captureAllowed(projectPolicy: unknown, deploymentOptIn: unknown, consent: unknown): boolean {
 return projectPolicy === true && deploymentOptIn === true && consent === true;
}

const K = Uint32Array.from([
 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
/** Synchronous SHA-256 hex of a UTF-8 string (WebCrypto is async; the hash chain must be built inline). Measured: the chain hash was ~70% of the recorder's per-batch time (03.09-W3), so the block loop is allocation-free and fully inlined (Int32 arithmetic, no closures, no per-block array destructuring). */
const encoder = new TextEncoder(), schedule = new Int32Array(64), state = new Int32Array(8);
/** One reusable message buffer (UTF-8 bytes + padding), grown when a longer input arrives: no per-hash allocation or copy of the encoded bytes. */
let message = new Uint8Array(1 << 17);
export function sha256Hex(input: string): string {
 const most = input.length * 3 + 72;
 if (message.length < most) message = new Uint8Array(Math.max(most, message.length * 2));
 const length = encoder.encodeInto(input, message).written, padded = message, paddedLength = ((length + 9 + 63) >> 6) << 6;
 padded.fill(0, length, paddedLength); padded[length] = 0x80;
 const bits = length * 8, high = Math.floor(bits / 4294967296), tail = paddedLength - 8;
 padded[tail] = high >>> 24; padded[tail + 1] = (high >>> 16) & 255; padded[tail + 2] = (high >>> 8) & 255; padded[tail + 3] = high & 255;
 padded[tail + 4] = (bits >>> 24) & 255; padded[tail + 5] = (bits >>> 16) & 255; padded[tail + 6] = (bits >>> 8) & 255; padded[tail + 7] = bits & 255;
 const w = schedule, h = state;
 h[0] = 0x6a09e667; h[1] = 0xbb67ae85 | 0; h[2] = 0x3c6ef372; h[3] = 0xa54ff53a | 0; h[4] = 0x510e527f; h[5] = 0x9b05688c | 0; h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19;
 for (let off = 0; off < paddedLength; off += 64) {
  for (let i = 0; i < 16; i++) { const at = off + i * 4; w[i] = (padded[at]! << 24) | (padded[at + 1]! << 16) | (padded[at + 2]! << 8) | padded[at + 3]!; }
  for (let i = 16; i < 64; i++) {
   const a = w[i - 15]!, b = w[i - 2]!;
   w[i] = (w[i - 16]! + (((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3)) + w[i - 7]! + (((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10))) | 0;
  }
  let a: number = h[0]!, b: number = h[1]!, c: number = h[2]!, d: number = h[3]!, e: number = h[4]!, f: number = h[5]!, g: number = h[6]!, hh: number = h[7]!;
  for (let i = 0; i < 64; i += 8) {
  // Eight rounds per pass with the working variables renamed instead of shifted (a..h rotate through the eight statements and are back in place after them): no register moves, one loop test per eight rounds.
  const i1 = i + 1, i2 = i + 2, i3 = i + 3, i4 = i + 4, i5 = i + 5, i6 = i + 6, i7 = i + 7;
  let t = (hh + (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + K[i]! + w[i]!) | 0;
  d = (d + t) | 0; hh = (t + (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
  t = (g + (((d >>> 6) | (d << 26)) ^ ((d >>> 11) | (d << 21)) ^ ((d >>> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + K[i1]! + w[i1]!) | 0;
  c = (c + t) | 0; g = (t + (((hh >>> 2) | (hh << 30)) ^ ((hh >>> 13) | (hh << 19)) ^ ((hh >>> 22) | (hh << 10))) + ((hh & a) ^ (hh & b) ^ (a & b))) | 0;
  t = (f + (((c >>> 6) | (c << 26)) ^ ((c >>> 11) | (c << 21)) ^ ((c >>> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + K[i2]! + w[i2]!) | 0;
  b = (b + t) | 0; f = (t + (((g >>> 2) | (g << 30)) ^ ((g >>> 13) | (g << 19)) ^ ((g >>> 22) | (g << 10))) + ((g & hh) ^ (g & a) ^ (hh & a))) | 0;
  t = (e + (((b >>> 6) | (b << 26)) ^ ((b >>> 11) | (b << 21)) ^ ((b >>> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + K[i3]! + w[i3]!) | 0;
  a = (a + t) | 0; e = (t + (((f >>> 2) | (f << 30)) ^ ((f >>> 13) | (f << 19)) ^ ((f >>> 22) | (f << 10))) + ((f & g) ^ (f & hh) ^ (g & hh))) | 0;
  t = (d + (((a >>> 6) | (a << 26)) ^ ((a >>> 11) | (a << 21)) ^ ((a >>> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + K[i4]! + w[i4]!) | 0;
  hh = (hh + t) | 0; d = (t + (((e >>> 2) | (e << 30)) ^ ((e >>> 13) | (e << 19)) ^ ((e >>> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g))) | 0;
  t = (c + (((hh >>> 6) | (hh << 26)) ^ ((hh >>> 11) | (hh << 21)) ^ ((hh >>> 25) | (hh << 7))) + ((hh & a) ^ (~hh & b)) + K[i5]! + w[i5]!) | 0;
  g = (g + t) | 0; c = (t + (((d >>> 2) | (d << 30)) ^ ((d >>> 13) | (d << 19)) ^ ((d >>> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f))) | 0;
  t = (b + (((g >>> 6) | (g << 26)) ^ ((g >>> 11) | (g << 21)) ^ ((g >>> 25) | (g << 7))) + ((g & hh) ^ (~g & a)) + K[i6]! + w[i6]!) | 0;
  f = (f + t) | 0; b = (t + (((c >>> 2) | (c << 30)) ^ ((c >>> 13) | (c << 19)) ^ ((c >>> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e))) | 0;
  t = (a + (((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7))) + ((f & g) ^ (~f & hh)) + K[i7]! + w[i7]!) | 0;
  e = (e + t) | 0; a = (t + (((b >>> 2) | (b << 30)) ^ ((b >>> 13) | (b << 19)) ^ ((b >>> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d))) | 0;
 }
  h[0] = (h[0]! + a) | 0; h[1] = (h[1]! + b) | 0; h[2] = (h[2]! + c) | 0; h[3] = (h[3]! + d) | 0; h[4] = (h[4]! + e) | 0; h[5] = (h[5]! + f) | 0; h[6] = (h[6]! + g) | 0; h[7] = (h[7]! + hh) | 0;
 }
 let out = "";
 for (let i = 0; i < 8; i++) out += (h[i]! >>> 0).toString(16).padStart(8, "0");
 return out;
}

/**
 * Canonical JSON exactly as Go's model.CanonicalJSON serializes a replay chunk: object keys sorted, no whitespace,
 * integers only, Go string escaping (U+2028/2029 escaped). The chain hash is SHA-256 over these bytes, so a server
 * computing replays.ChunkHash over the same chunk gets the same hash regardless of this object's key order.
 */
const SEPARATORS = /[\u2028\u2029]/;
/** JSON-quoted object keys, cached: the chunk vocabulary is a few dozen names that repeat for every node and event. Bounded so a hostile key set cannot grow it. */
const quotedKeys = new Map<string, string>();
function quoteKey(key: string): string {
 let quoted = quotedKeys.get(key);
 if (quoted === undefined) { quoted = JSON.stringify(key); if (quotedKeys.size < 512) quotedKeys.set(key, quoted); }
 return quoted;
}
/** Canonical JSON text a caller already built (the recorder writes its own nodes straight into canonical form); canonicalJSON embeds it as is. */
export class CanonicalText { constructor(readonly text: string) {} }
export function canonicalJSON(value: unknown): string {
 if (value === null) return "null";
 if (value instanceof CanonicalText) return value.text;
 switch (typeof value) {
  case "boolean": return value ? "true" : "false";
  case "number":
   if (!Number.isSafeInteger(value)) throw Error("replay_canonical_number");
   return String(value === 0 ? 0 : value);
  case "string": { const quoted = JSON.stringify(value); return SEPARATORS.test(quoted) ? quoted.replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029") : quoted; }
  case "object": {
   if (Array.isArray(value)) { let out = "["; for (let i = 0; i < value.length; i++) out += (i === 0 ? "" : ",") + canonicalJSON(value[i]); return out + "]"; }
   const record = value as Record<string, unknown>, keys = Object.keys(record);
   // Keys are ordered by UTF-16 code unit, the order `<` and the default sort use; the sort is skipped when the keys already are in that order.
   for (let i = 1; i < keys.length; i++) if (keys[i - 1]! > keys[i]!) { keys.sort(); break; }
   let out = "{";
   for (let i = 0; i < keys.length; i++) { const key = keys[i]!; out += (i === 0 ? "" : ",") + quoteKey(key) + ":" + canonicalJSON(record[key]); }
   return out + "}";
  }
  default: throw Error("replay_canonical_value");
 }
}

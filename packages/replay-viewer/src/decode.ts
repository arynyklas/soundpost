// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

/*
 * Closed-format decoding and hash-chain verification for owned replay chunks (docs/protocol/replay-v1.md).
 *
 * This module accepts exactly the chunks the Go validator (internal/replays ValidateChunk after
 * model.StrictJSON) accepts and computes exactly its ChunkHash: SHA-256 over the canonical JSON (sorted
 * keys, no insignificant whitespace, decimal-string integers) of the whole decoded chunk. It is stricter
 * than Go in three deliberate places: object keys must match case-exactly (Go's decoder is case-insensitive),
 * every field must be present (Go zero-fills missing ones), and duplicate keys are "malformed". Chunks the
 * server stores and re-emits are always canonical, so none of that rejects server output. Nothing here ever
 * echoes chunk content into an error.
 */

/** Protocol ceilings (internal/replays MaxChunkBytes, 4096 nodes, 4096 events). Limits may only narrow them. */
export interface ReplayLimits { readonly maxChunkBytes: number; readonly maxNodes: number; readonly maxEvents: number }
export const REPLAY_PROTOCOL_LIMITS: ReplayLimits = {maxChunkBytes: 128 << 10, maxNodes: 4096, maxEvents: 4096};
const MAX_SEQUENCE = 1n << 16n;
const MAX_NODE_ID = 1n << 31n;
const MAX_COORDINATE = 1 << 24;
const MAX_UINT64 = (1n << 64n) - 1n;
const MAX_INT64 = (1n << 63n) - 1n;
const SUPPORTED_VERSION = "1";
const MAX_DEPTH = 64;

export type ReplayDecodeCode = "too_large" | "malformed" | "invalid" | "unsupported_version" | "limits";
export class ReplayDecodeError extends Error {
 constructor(readonly code: ReplayDecodeCode) { super("replay chunk refused: " + code); this.name = "ReplayDecodeError"; }
}
const fail = (code: ReplayDecodeCode): never => { throw new ReplayDecodeError(code); };

export const NODE_TAGS = ["div", "span", "p", "button", "input", "section", "canvas", "masked"] as const;
export const EVENT_KINDS = ["pointer", "scroll", "resize", "mutation", "checkpoint", "gap"] as const;
export type ReplayTag = (typeof NODE_TAGS)[number];
export type ReplayEventKind = (typeof EVENT_KINDS)[number];

export interface ReplayNode { readonly id: string; readonly parent: string; readonly tag: ReplayTag; readonly class: "" | "masked"; readonly text: "" | "[masked]" }
export interface ReplayEvent { readonly at_ns: string; readonly kind: ReplayEventKind; readonly node: string; readonly x: number; readonly y: number }
export interface ReplayClock { readonly wall_ns: string; readonly mono_ns: string; readonly domain: {readonly host: string; readonly boot: string; readonly runtime: string}; readonly uncertainty_ns: string }
/** A decoded, validated chunk. `hash` is the chain hash (hex SHA-256 of the canonical wire JSON). */
export interface ReplayChunk {
 readonly replay_id: string;
 readonly session_id: string;
 readonly recorder_version: string;
 readonly sequence: string;
 readonly previous_hash: string;
 readonly checkpoint_sequence: string;
 readonly checkpoint_hash: string;
 readonly clock: ReplayClock;
 readonly nodes: readonly ReplayNode[];
 readonly events: readonly ReplayEvent[];
 readonly loss: string;
 readonly gap: boolean;
 readonly capture_policy_revision: string;
 readonly hash: string;
}

// ---------------------------------------------------------------------------------------------
// SHA-256 (synchronous: the chain decision must be inline and WebCrypto is asynchronous).

const K = Uint32Array.from([
 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);

/** SHA-256 digest bytes. */
export function sha256(data: Uint8Array): Uint8Array {
 const padded = new Uint8Array(((data.length + 9 + 63) >> 6) << 6);
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
 const out = new Uint8Array(32), outView = new DataView(out.buffer);
 for (let i = 0; i < 8; i++) outView.setUint32(i * 4, h[i]!);
 return out;
}
export function sha256Hex(data: Uint8Array): string {
 return Array.from(sha256(data), byte => byte.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------------------------
// Canonical JSON: sorted keys, no whitespace, integers only, Go-identical string escaping.

/** Serializes plain JSON values exactly as Go's model.CanonicalJSON does for replay chunks (ASCII keys). */
export function canonicalJSON(value: unknown): string {
 if (value === null) return "null";
 switch (typeof value) {
  case "boolean": return value ? "true" : "false";
  case "number":
   if (!Number.isSafeInteger(value)) return fail("invalid");
   return String(value === 0 ? 0 : value);
  case "string": return JSON.stringify(value).replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
  case "object": {
   if (Array.isArray(value)) return "[" + value.map(canonicalJSON).join(",") + "]";
   const record = value as Record<string, unknown>;
   return "{" + Object.keys(record).sort().map(key => JSON.stringify(key) + ":" + canonicalJSON(record[key])).join(",") + "}";
  }
  default: return fail("invalid");
 }
}

// ---------------------------------------------------------------------------------------------
// Strict JSON: duplicate keys, lone surrogate escapes, depth > 64, trailing data and non-JSON are malformed.

class JsonNumber { constructor(readonly raw: string) {} }
type Json = null | boolean | string | JsonNumber | Json[] | {[key: string]: Json};
const NUMBER = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/;

class Parser {
 private at = 0;
 constructor(private readonly text: string) {}
 parse(): Json {
  const value = this.value(0);
  this.space();
  if (this.at !== this.text.length) return fail("malformed");
  return value;
 }
 private space(): void { while (this.at < this.text.length) { const c = this.text.charCodeAt(this.at); if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.at++; else break; } }
 private value(depth: number): Json {
  if (depth > MAX_DEPTH) return fail("malformed");
  this.space();
  const c = this.text[this.at];
  if (c === "{") return this.object(depth);
  if (c === "[") return this.array(depth);
  if (c === "\"") return this.string();
  if (this.text.startsWith("true", this.at)) { this.at += 4; return true; }
  if (this.text.startsWith("false", this.at)) { this.at += 5; return false; }
  if (this.text.startsWith("null", this.at)) { this.at += 4; return null; }
  const match = NUMBER.exec(this.text.slice(this.at, this.at + 64));
  if (match === null) return fail("malformed");
  this.at += match[0].length;
  return new JsonNumber(match[0]);
 }
 private object(depth: number): Json {
  this.at++;
  const out: {[key: string]: Json} = Object.create(null) as {[key: string]: Json};
  this.space();
  if (this.text[this.at] === "}") { this.at++; return out; }
  for (;;) {
   this.space();
   if (this.text[this.at] !== "\"") return fail("malformed");
   const key = this.string();
   if (Object.hasOwn(out, key)) return fail("malformed");
   this.space();
   if (this.text[this.at++] !== ":") return fail("malformed");
   out[key] = this.value(depth + 1);
   this.space();
   const next = this.text[this.at++];
   if (next === "}") return out;
   if (next !== ",") return fail("malformed");
  }
 }
 private array(depth: number): Json {
  this.at++;
  const out: Json[] = [];
  this.space();
  if (this.text[this.at] === "]") { this.at++; return out; }
  for (;;) {
   out.push(this.value(depth + 1));
   this.space();
   const next = this.text[this.at++];
   if (next === "]") return out;
   if (next !== ",") return fail("malformed");
  }
 }
 private string(): string {
  this.at++;
  let out = "";
  for (;;) {
   if (this.at >= this.text.length) return fail("malformed");
   const c = this.text.charCodeAt(this.at++);
   if (c === 0x22) return out;
   if (c < 0x20) return fail("malformed");
   if (c !== 0x5c) { out += String.fromCharCode(c); continue; }
   const e = this.text[this.at++];
   switch (e) {
    case "\"": out += "\""; break;
    case "\\": out += "\\"; break;
    case "/": out += "/"; break;
    case "b": out += "\b"; break;
    case "f": out += "\f"; break;
    case "n": out += "\n"; break;
    case "r": out += "\r"; break;
    case "t": out += "\t"; break;
    case "u": {
     const unit = this.hex4();
     if (unit >= 0xd800 && unit <= 0xdbff) {
      if (this.text[this.at] !== "\\" || this.text[this.at + 1] !== "u") return fail("malformed");
      this.at += 2;
      const low = this.hex4();
      if (low < 0xdc00 || low > 0xdfff) return fail("malformed");
      out += String.fromCharCode(unit, low);
     } else if (unit >= 0xdc00 && unit <= 0xdfff) return fail("malformed");
     else out += String.fromCharCode(unit);
     break;
    }
    default: return fail("malformed");
   }
  }
 }
 private hex4(): number {
  const digits = this.text.slice(this.at, this.at + 4);
  if (!/^[0-9a-fA-F]{4}$/.test(digits)) return fail("malformed");
  this.at += 4;
  return parseInt(digits, 16);
 }
}

// ---------------------------------------------------------------------------------------------
// Closed-format validation.

type Obj = {[key: string]: Json};
const isObj = (value: Json | undefined): value is Obj => typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof JsonNumber);
function closed(value: Json | undefined, keys: readonly string[]): Obj {
 if (!isObj(value)) return fail("invalid");
 const present = Object.keys(value);
 if (present.length !== keys.length || !keys.every(key => Object.hasOwn(value, key))) return fail("invalid");
 return value;
}
const str = (value: Json | undefined): string => (typeof value === "string" ? value : fail("invalid"));
function id(value: Json | undefined): string {
 const text = str(value);
 return /^[0-9a-f]{32}$/.test(text) && /[1-9a-f]/.test(text) ? text : fail("invalid");
}
function hash(value: Json | undefined): string {
 const text = str(value);
 return /^[0-9a-f]{64}$/.test(text) ? text : fail("invalid");
}
/** Go's Uint64: a quoted canonical decimal with no sign, no leading zero, at most 2^64-1. */
function uint(value: Json | undefined, max = MAX_UINT64): bigint {
 const text = str(value);
 if (!/^(?:0|[1-9][0-9]{0,19})$/.test(text)) return fail("invalid");
 const parsed = BigInt(text);
 return parsed <= max ? parsed : fail("invalid");
}
/** Go's Int64 for wall_ns: positive canonical decimal within int64. */
function wall(value: Json | undefined): string {
 const text = str(value);
 if (!/^[1-9][0-9]{0,18}$/.test(text) || BigInt(text) > MAX_INT64) return fail("invalid");
 return text;
}
/** Go decodes x/y into int32 (a JSON integer, "-0" included) and then bounds them to ±2^24. */
function coordinate(value: Json | undefined): number {
 if (!(value instanceof JsonNumber) || !/^-?(?:0|[1-9][0-9]*)$/.test(value.raw) || value.raw.length > 9) return fail("invalid");
 const parsed = Number(value.raw);
 return Math.abs(parsed) <= MAX_COORDINATE ? parsed + 0 : fail("invalid");
}
function oneOf<T extends string>(value: Json | undefined, allowed: readonly T[]): T {
 const text = str(value);
 return (allowed as readonly string[]).includes(text) ? (text as T) : fail("invalid");
}
function list(value: Json | undefined, max: number): readonly Json[] {
 if (value === null) return [];
 if (!Array.isArray(value)) return fail("invalid");
 return value.length <= max ? value : fail("too_large");
}

const TOP_KEYS = ["capture_policy_revision", "checkpoint_hash", "checkpoint_sequence", "clock", "events", "gap", "loss", "nodes", "previous_hash", "recorder_version", "replay_id", "sequence", "session_id"] as const;

function checkLimits(limits: ReplayLimits): void {
 const bounded = (value: number, max: number, min: number): boolean => Number.isInteger(value) && value >= min && value <= max;
 if (!bounded(limits.maxChunkBytes, REPLAY_PROTOCOL_LIMITS.maxChunkBytes, 1) || !bounded(limits.maxNodes, REPLAY_PROTOCOL_LIMITS.maxNodes, 0) || !bounded(limits.maxEvents, REPLAY_PROTOCOL_LIMITS.maxEvents, 0)) fail("limits");
}

/**
 * Decodes and validates one wire chunk. Throws ReplayDecodeError for anything outside the closed format:
 * `too_large` (over the byte or count limits), `malformed` (not strict JSON, truncated, not an object),
 * `unsupported_version` (a recorder version other than "1"), `invalid` (violates the closed field set,
 * vocabularies or chain-field rules), `limits` (the caller passed limits wider than the protocol).
 */
export function decodeChunk(bytes: Uint8Array, limits: ReplayLimits): ReplayChunk {
 checkLimits(limits);
 if (!(bytes instanceof Uint8Array)) return fail("malformed");
 if (bytes.length > limits.maxChunkBytes) return fail("too_large");
 let text: string;
 try { text = new TextDecoder("utf-8", {fatal: true, ignoreBOM: true}).decode(bytes); } catch { return fail("malformed"); }
 const root = new Parser(text).parse();
 if (!isObj(root)) return fail("malformed");
 // A version this viewer cannot read may use a different field set, so it is "unsupported", not "invalid".
 const version = root["recorder_version"];
 if (typeof version === "string" && version !== SUPPORTED_VERSION) return fail("unsupported_version");
 const top = closed(root, TOP_KEYS);
 if (version !== SUPPORTED_VERSION) return fail("invalid");
 const replay = id(top["replay_id"]), session = id(top["session_id"]);
 const sequence = uint(top["sequence"], MAX_SEQUENCE), checkpointSequence = uint(top["checkpoint_sequence"], MAX_SEQUENCE);
 const previous = hash(top["previous_hash"]), checkpointHash = hash(top["checkpoint_hash"]);
 const policy = uint(top["capture_policy_revision"]);
 if (sequence < 1n || checkpointSequence < 1n || checkpointSequence > sequence || policy === 0n) return fail("invalid");
 const zero = "0".repeat(64);
 if ((sequence === 1n) !== (previous === zero)) return fail("invalid");
 if (checkpointSequence === sequence) { if (checkpointHash !== previous) return fail("invalid"); } else if (checkpointHash === zero) return fail("invalid");
 const clockObject = closed(top["clock"], ["domain", "mono_ns", "uncertainty_ns", "wall_ns"]), domain = closed(clockObject["domain"], ["boot", "host", "runtime"]);
 const clock: ReplayClock = {wall_ns: wall(clockObject["wall_ns"]), mono_ns: String(uint(clockObject["mono_ns"])), uncertainty_ns: String(uint(clockObject["uncertainty_ns"])), domain: {host: id(domain["host"]), boot: id(domain["boot"]), runtime: id(domain["runtime"])}};
 const gap = top["gap"];
 if (typeof gap !== "boolean") return fail("invalid");
 const loss = String(uint(top["loss"]));
 const rawNodes = list(top["nodes"], limits.maxNodes), rawEvents = list(top["events"], limits.maxEvents);
 const seen = new Set<string>();
 const nodes: ReplayNode[] = rawNodes.map(item => {
  const node = closed(item, ["class", "id", "parent", "tag", "text"]);
  const nodeId = uint(node["id"], MAX_NODE_ID), parent = uint(node["parent"], MAX_NODE_ID);
  if (nodeId === 0n || parent === nodeId || seen.has(String(nodeId))) return fail("invalid");
  seen.add(String(nodeId));
  const cls = str(node["class"]), tx = str(node["text"]);
  if ((cls !== "" && cls !== "masked") || (tx !== "" && tx !== "[masked]")) return fail("invalid");
  return {id: String(nodeId), parent: String(parent), tag: oneOf(node["tag"], NODE_TAGS), class: cls, text: tx};
 });
 const events: ReplayEvent[] = rawEvents.map(item => {
  const event = closed(item, ["at_ns", "kind", "node", "x", "y"]);
  return {at_ns: String(uint(event["at_ns"])), kind: oneOf(event["kind"], EVENT_KINDS), node: String(uint(event["node"], MAX_NODE_ID)), x: coordinate(event["x"]), y: coordinate(event["y"])};
 });
 // The hash covers every field, with an absent list exactly as Go marshals a nil slice.
 const wire = {
  capture_policy_revision: String(policy), checkpoint_hash: checkpointHash, checkpoint_sequence: String(checkpointSequence), clock,
  events: top["events"] === null ? null : events, gap, loss, nodes: top["nodes"] === null ? null : nodes, previous_hash: previous,
  recorder_version: SUPPORTED_VERSION, replay_id: replay, sequence: String(sequence), session_id: session,
 };
 // The canonical form of these closed-vocabulary values is never longer than the wire bytes already bounded above.
 const canonical = new TextEncoder().encode(canonicalJSON(wire));
 return Object.freeze({
  replay_id: replay, session_id: session, recorder_version: SUPPORTED_VERSION, sequence: String(sequence), previous_hash: previous, checkpoint_sequence: String(checkpointSequence), checkpoint_hash: checkpointHash,
  clock, nodes, events, loss, gap, capture_policy_revision: String(policy), hash: sha256Hex(canonical),
 });
}

// ---------------------------------------------------------------------------------------------
// Chain verification: continuity is proven by an unbroken hash chain from a verified checkpoint,
// never assumed (plan() in internal/replays/chain.go). Missing deltas are never best-effort replayed.

/** Closed reasons a stretch of history cannot be shown. A subset of internal/replays Reason* codes. */
export type GapReason = "missing_chunk" | "hash_mismatch" | "dependency_mismatch" | "recorder_gap" | "conflicting_chunk" | "invalid_chunk" | "no_checkpoint" | "recorder_version";
export const GAP_REASONS: readonly GapReason[] = ["missing_chunk", "hash_mismatch", "dependency_mismatch", "recorder_gap", "conflicting_chunk", "invalid_chunk", "no_checkpoint", "recorder_version"];
/** Why a chunk was discarded without being applied. */
export type RejectReason = "duplicate" | "stale" | "conflict" | "identity_mismatch" | "hash_mismatch" | "dependency_mismatch";

export interface ChainAnchor { readonly sequence: string; readonly hash: string }
export interface ReplayChainState {
 readonly replay: string | null;
 readonly session: string | null;
 /** Last chunk applied. */
 readonly head: ChainAnchor | null;
 /** Highest chunk observed, applied or not; it is what duplicates and reordering are judged against. */
 readonly seen: ChainAnchor | null;
 /** The verified checkpoint deltas currently depend on. */
 readonly checkpoint: ChainAnchor | null;
 /** Set while history since the last verified checkpoint is not continuous; names the first cause. */
 readonly broken: GapReason | null;
}
export interface ChainGap { readonly reason: GapReason; readonly from: string; readonly through: string }
export type ChainDecision =
 | {readonly kind: "apply"; readonly state: ReplayChainState}
 | {readonly kind: "checkpoint"; readonly state: ReplayChainState; readonly gap: ChainGap | null}
 | {readonly kind: "gap"; readonly state: ReplayChainState; readonly gap: ChainGap}
 | {readonly kind: "reject"; readonly state: ReplayChainState; readonly reason: RejectReason; readonly gap: ChainGap | null};

export function initialChainState(): ReplayChainState {
 return Object.freeze({replay: null, session: null, head: null, seen: null, checkpoint: null, broken: null});
}
/** Marks continuity lost for a reason found outside verifyChain (undecodable chunk, host-declared gap). The first cause is kept. */
export function breakChain(state: ReplayChainState, reason: GapReason): ReplayChainState {
 return Object.freeze({...state, broken: state.broken ?? reason});
}
const anchor = (chunk: ReplayChunk): ChainAnchor => Object.freeze({sequence: chunk.sequence, hash: chunk.hash});
const next = (sequence: string): string => String(BigInt(sequence) + 1n);

/**
 * Judges one decoded chunk against the chain so far and returns the decision plus the next state; the given
 * state is never modified. `apply`/`checkpoint` are the only decisions whose content may be shown. A delta
 * is applied only when it directly extends the last applied chunk (previous hash and sequence), names the
 * current verified checkpoint, and no break is open; otherwise it is a `gap` or `reject` and the chain stays
 * broken until a valid checkpoint arrives. A checkpoint is self-contained and resumes after any hole, unless
 * it contradicts the chunk right before it.
 */
export function verifyChain(chunk: ReplayChunk, state: ReplayChainState): ChainDecision {
 const sequence = BigInt(chunk.sequence);
 const here = anchor(chunk);
 let current = state;
 if (current.replay === null) current = Object.freeze({...current, replay: chunk.replay_id, session: chunk.session_id});
 else if (current.replay !== chunk.replay_id || current.session !== chunk.session_id) {
  // Another session claiming this replay root contradicts what was already shown: the chain cannot be trusted past it.
  const at = current.seen === null ? chunk.sequence : next(current.seen.sequence);
  return {kind: "reject", reason: "identity_mismatch", state: breakChain(state, "conflicting_chunk"), gap: {reason: "conflicting_chunk", from: at, through: at}};
 }
 const seen = current.seen, head = current.head;
 if (seen !== null) {
  const highest = BigInt(seen.sequence);
  if (sequence === highest) {
   if (chunk.hash === seen.hash) return {kind: "reject", reason: "duplicate", state, gap: null};
   return {kind: "reject", reason: "conflict", state: breakChain(state, "conflicting_chunk"), gap: {reason: "conflicting_chunk", from: chunk.sequence, through: chunk.sequence}};
  }
  if (sequence < highest) return {kind: "reject", reason: "stale", state, gap: null};
 }
 /** Continuity is lost: remember the first cause; `observed` also records this chunk as the highest seen. */
 const broken = (reason: GapReason, observed: boolean): ReplayChainState => Object.freeze({...current, seen: observed ? here : current.seen, broken: current.broken ?? reason});
 const one = (reason: GapReason): ChainGap => ({reason, from: chunk.sequence, through: chunk.sequence});
 if (chunk.checkpoint_sequence === chunk.sequence) {
  if (seen !== null && sequence === BigInt(seen.sequence) + 1n && chunk.previous_hash !== seen.hash) {
   // A checkpoint that contradicts the chunk right before it is not a recovery point.
   return {kind: "reject", reason: "hash_mismatch", state: broken("hash_mismatch", false), gap: one("hash_mismatch")};
  }
  let gap: ChainGap | null = null;
  if (current.broken !== null) {
   const through = sequence > 1n ? String(sequence - 1n) : "1";
   const from = head !== null ? next(head.sequence) : seen !== null ? next(seen.sequence) : through;
   gap = {reason: current.broken, from: BigInt(from) > BigInt(through) ? through : from, through};
  } else if (seen !== null && sequence > BigInt(seen.sequence) + 1n) gap = {reason: "missing_chunk", from: next(seen.sequence), through: String(sequence - 1n)};
  else if (chunk.gap) gap = one("recorder_gap");
  return {kind: "checkpoint", gap, state: Object.freeze({replay: current.replay, session: current.session, head: here, seen: here, checkpoint: here, broken: null})};
 }
 // A delta applies only when nothing is open, it extends the last applied chunk and names the current checkpoint.
 if (current.checkpoint === null || head === null || current.broken !== null) return {kind: "gap", gap: one("no_checkpoint"), state: broken("no_checkpoint", true)};
 if (sequence !== BigInt(head.sequence) + 1n) return {kind: "gap", gap: {reason: "missing_chunk", from: next(head.sequence), through: chunk.sequence}, state: broken("missing_chunk", true)};
 if (chunk.previous_hash !== head.hash) return {kind: "reject", reason: "hash_mismatch", state: broken("hash_mismatch", false), gap: one("hash_mismatch")};
 if (chunk.checkpoint_sequence !== current.checkpoint.sequence || chunk.checkpoint_hash !== current.checkpoint.hash) return {kind: "reject", reason: "dependency_mismatch", state: broken("dependency_mismatch", false), gap: one("dependency_mismatch")};
 if (chunk.gap) return {kind: "gap", gap: one("recorder_gap"), state: broken("recorder_gap", true)};
 return {kind: "apply", state: Object.freeze({replay: current.replay, session: current.session, head: here, seen: here, checkpoint: current.checkpoint, broken: null})};
}

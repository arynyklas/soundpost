// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {ReplayNode, ReplayTag} from "./types.ts";

/**
 * The recorded nodes of one emission as three parallel typed arrays (struct of arrays), reused by every walk of a recorder: a node is a number
 * triple (id, parent id, mark), never an object, and its canonical form (the bytes the chain hash covers) is written straight into the hash buffer. A batch of hundreds of nodes
 * therefore leaves no per-node object or id string for the garbage collector (Firefox charged its minor-collection pauses to the observer callback).
 * Objects (`ReplayNode`) exist only for a consumer that asks for them (`toArray`, the chunk's lazy `nodes`).
 */

/** The server's closed tag vocabulary (internal/replays nodeTags); the index is the tag code stored in a mark. */
export const TAG_NAMES: readonly ReplayTag[] = ["div", "span", "p", "button", "input", "section", "canvas", "masked"];
const CODES: ReadonlyMap<string, number> = new Map(TAG_NAMES.map((name, code) => [name, code]));
const TAG_MASKED = 7, TAG_INPUT = 4;
/** Tag code of an allowlisted element name, or "masked" for anything outside the enum (custom elements, SVG, MathML). */
export function tagCode(localName: string): number { return CODES.get(localName) ?? TAG_MASKED; }

/** A mark packs a node's three closed vocabularies: tag code (bits 0-2), class "masked" (bit 3), text "[masked]" (bit 4). */
const CLASS_BIT = 8, TEXT_BIT = 16;
export function markOf(tag: number, opaque: boolean, masked: boolean): number { return tag | (opaque ? CLASS_BIT : 0) | (masked ? TEXT_BIT : 0); }
/** A text node: generic tag with the constant text mask. */
export const MARK_TEXT = markOf(TAG_MASKED, false, true);
/** An opaque node (frame, widget, editable region, overflow or depth placeholder): empty text. */
export const MARK_OPAQUE = markOf(TAG_MASKED, true, false);
/** A closed shadow host: opaque with the constant mask, the one shape no other cause produces. */
export const MARK_CLOSED = markOf(TAG_MASKED, true, true);
/** An input: its tag and the constant mask, never its value. */
export const MARK_INPUT = markOf(TAG_INPUT, false, true);

const ascii = (text: string): Uint8Array => { const out = new Uint8Array(text.length); for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i); return out; };
/** Canonical text puts the keys in sorted order; the fixed pieces of a node are written as bytes. */
const WIRE_PARENT = ascii('","parent":"');
/** Canonical (sorted key) text: {"class":...,"id":...,"parent":...,"tag":...,"text":...}, the bytes the chain hash covers. */
const CANON_ID = ascii('","id":"');
const CLASS_NAME = ["", "masked"] as const, TEXT_NAME = ["", "[masked]"] as const;
const CANON_HEAD: Uint8Array[] = [ascii('{"class":"'), ascii('{"class":"masked')], CANON_TAIL: Uint8Array[] = [], VALUE_BYTES: number[] = [];
for (let mark = 0; mark < 32; mark++) {
 const tag = TAG_NAMES[mark & 7]!, cls = CLASS_NAME[(mark >> 3) & 1]!, text = TEXT_NAME[mark >> 4]!;
 CANON_TAIL[mark] = ascii(`","tag":"${tag}","text":"${text}"}`);
 VALUE_BYTES[mark] = tag.length + cls.length + text.length;
}
/** JSON text of one node with every value empty, plus its separator: a recorded node is exactly this plus the lengths of its five values. */
export const NODE_FRAME_BYTES = JSON.stringify({id: "", parent: "", tag: "", class: "", text: ""}).length + 1;

/** Decimal digits of a non-negative integer below 2^32. */
function digits(n: number): number { return n < 10 ? 1 : n < 100 ? 2 : n < 1e3 ? 3 : n < 1e4 ? 4 : n < 1e5 ? 5 : n < 1e6 ? 6 : n < 1e7 ? 7 : n < 1e8 ? 8 : n < 1e9 ? 9 : 10; }
function putDecimal(m: Uint8Array, at: number, n: number): number {
 let end = at + digits(n);
 const out = end;
 do { m[--end] = 48 + n % 10; n = (n / 10) >>> 0; } while (n > 0);
 return out;
}
function put(m: Uint8Array, at: number, bytes: Uint8Array): number {
 for (let i = 0; i < bytes.length; i++) m[at + i] = bytes[i]!;
 return at + bytes.length;
}

/** The byte buffer `Nodes.canonicalText` writes into (one chunk's nodes at most), and the size above which it is not kept. */
let TEXT_BUFFER = new Uint8Array(4096);
const TEXT_DECODER = new TextDecoder(), TEXT_KEEP = 1 << 19;
const INITIAL = 1024;

/** Decimal strings of small ids, made once: a consumer that reads `chunk.nodes` gets shared id strings instead of two new strings per node (ids restart at every checkpoint, so they stay small). */
const ID_STRINGS: string[] = [];
function idString(id: number): string {
 if (id >= 32768) return String(id);
 let text = ID_STRINGS[id];
 if (text === undefined) { text = String(id); ID_STRINGS[id] = text; }
 return text;
}

/** Read side of a list of nodes held as numbers: the live `NodeTable` of a walk, or the `freeze()` copy a chunk keeps. */
export class Nodes {
 constructor(public ids: Uint32Array, public parents: Uint32Array, public marks: Uint8Array, public length: number,
  /** Bytes the nodes take in a chunk (each node's JSON plus its separator), kept as nodes are added so sizing a chunk reads no node. */
  public bytes: number) {}

 /** Bytes node `at` takes in a chunk (as it is, or with another mark: a placeholder is the node's id and parent with the opaque mark). */
 size(at: number, mark: number = this.marks[at]!): number { return NODE_FRAME_BYTES + digits(this.ids[at]!) + digits(this.parents[at]!) + VALUE_BYTES[mark]!; }
 /** Node `at` as the object a consumer of the wire model reads. */
 at(at: number): ReplayNode {
  const mark = this.marks[at]!;
  return {id: idString(this.ids[at]!), parent: idString(this.parents[at]!), tag: TAG_NAMES[mark & 7]!, class: CLASS_NAME[(mark >> 3) & 1]!, text: TEXT_NAME[mark >> 4]!};
 }
 toArray(): ReplayNode[] { const out: ReplayNode[] = []; for (let i = 0; i < this.length; i++) out.push(this.at(i)); return out; }
 /** Writes the canonical JSON array of the nodes at `at` of `m` (room: `bytes + 2`) and returns the end: the same characters as JSON.stringify of the node objects, keys sorted. */
 canonical(m: Uint8Array, at: number): number {
  m[at++] = 91;
  for (let i = 0; i < this.length; i++) {
   const mark = this.marks[i]!;
   if (i > 0) m[at++] = 44;
   at = put(m, at, CANON_HEAD[(mark >> 3) & 1]!); at = put(m, at, CANON_ID); at = putDecimal(m, at, this.ids[i]!); at = put(m, at, WIRE_PARENT); at = putDecimal(m, at, this.parents[i]!); at = put(m, at, CANON_TAIL[mark]!);
  }
  m[at++] = 93;
  return at;
 }
 /** The canonical JSON array text of the nodes (`canonicalJSON(this.toArray())`), made without a node object: written into one reused byte buffer and decoded once (ASCII only). Chunks are consumed once, so it is recomputed per call, not cached. */
 canonicalText(): string {
  const room = this.bytes + 2;
  if (TEXT_BUFFER.length < room) TEXT_BUFFER = new Uint8Array(Math.max(room, TEXT_BUFFER.length * 2));
  const text = TEXT_DECODER.decode(TEXT_BUFFER.subarray(0, this.canonical(TEXT_BUFFER, 0)));
  if (TEXT_BUFFER.length > TEXT_KEEP) TEXT_BUFFER = new Uint8Array(INITIAL);
  return text;
 }
}

/** The no-node list of a chunk that carries only events. */
export const EMPTY_NODES: Nodes = new Nodes(new Uint32Array(0), new Uint32Array(0), new Uint8Array(0), 0, 0);

export class NodeTable extends Nodes {
 constructor() { super(new Uint32Array(INITIAL), new Uint32Array(INITIAL), new Uint8Array(INITIAL), 0, 0); }

 add(id: number, parent: number, mark: number): void {
  const at = this.length;
  if (at === this.ids.length) this.grow(at * 2);
  this.ids[at] = id; this.parents[at] = parent; this.marks[at] = mark;
  this.length = at + 1;
  this.bytes += NODE_FRAME_BYTES + digits(id) + digits(parent) + VALUE_BYTES[mark]!;
 }
 clear(): void { this.length = 0; this.bytes = 0; }
 /** Sets the byte total again after nodes were removed or replaced in place. */
 recount(): void { let total = 0; for (let i = 0; i < this.length; i++) total += this.size(i); this.bytes = total; }
 /** Drops an oversized backing store left by one huge emission (a whole-page walk), so a quiet page does not keep it. */
 trim(): void { if (this.ids.length > 8 * INITIAL) { this.ids = new Uint32Array(INITIAL); this.parents = new Uint32Array(INITIAL); this.marks = new Uint8Array(INITIAL); } }
 private grow(capacity: number): void {
  const ids = new Uint32Array(capacity), parents = new Uint32Array(capacity), marks = new Uint8Array(capacity);
  ids.set(this.ids); parents.set(this.parents); marks.set(this.marks);
  this.ids = ids; this.parents = parents; this.marks = marks;
 }
 /** A copy of the nodes as they are now, sized to fit (three typed arrays, no object per node): what a chunk keeps once the table is reused by the next walk. */
 freeze(): Nodes {
  if (this.length === 0) return EMPTY_NODES;
  return new Nodes(this.ids.slice(0, this.length), this.parents.slice(0, this.length), this.marks.slice(0, this.length), this.length, this.bytes);
 }
 static of(nodes: readonly ReplayNode[]): NodeTable {
  const table = new NodeTable();
  for (const node of nodes) {
   const tag = TAG_NAMES.indexOf(node.tag);
   if (tag < 0) throw Error(`NodeTable.of: tag ${node.tag} is not in the closed vocabulary`);
   table.add(Number(node.id), Number(node.parent), markOf(tag, node.class === "masked", node.text === "[masked]"));
  }
  return table;
 }
}

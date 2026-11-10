// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// A fetch-based server-sent-events reader. The live route is a GET whose cookie session needs the CSRF header, which the
// native EventSource cannot send, and whose reconnection must be an explicit, visible act: this parser has no retry state
// and never reconnects. Framing follows the HTML Living Standard "event stream" grammar (CRLF, CR and LF line ends, comment
// lines, multi-line data, one dropped leading space), with a hard bound on how much one frame may buffer.

/** One dispatched frame. `id` is the id field carried by this very frame, or null: frames do not inherit an earlier id. */
export interface SseFrame { id: string | null; event: string; data: string }

export class SseProtocolError extends Error {
 constructor(readonly code: 'frame_too_large' | 'invalid_utf8') { super(code); }
}

export class SseParser {
 private buffer = '';
 private started = false;
 private skipLineFeed = false;
 private event = '';
 private id: string | null = null;
 private data: string[] = [];
 private dataSize = 0;

 constructor(readonly maxFrameChars: number = 1 << 20) {}

 /** Feeds decoded text and returns the frames it completed. An incomplete frame stays buffered and is never dispatched. */
 push(chunk: string): SseFrame[] {
  if (!this.started && chunk.length > 0) {
   this.started = true;
   if (chunk.charCodeAt(0) === 0xfeff) chunk = chunk.slice(1);
  }
  if (this.skipLineFeed && chunk.length > 0) {
   this.skipLineFeed = false;
   if (chunk.charCodeAt(0) === 0x0a) chunk = chunk.slice(1);
  }
  const text = this.buffer + chunk;
  const frames: SseFrame[] = [];
  let at = 0;
  for (let i = 0; i < text.length; i++) {
   const c = text.charCodeAt(i);
   if (c !== 0x0a && c !== 0x0d) continue;
   this.line(text.slice(at, i), frames);
   at = i + 1;
   if (c === 0x0d) {
    if (at === text.length) this.skipLineFeed = true;
    else if (text.charCodeAt(at) === 0x0a) { at++; i++; }
   }
  }
  this.buffer = text.slice(at);
  if (this.buffer.length + this.dataSize > this.maxFrameChars) throw new SseProtocolError('frame_too_large');
  return frames;
 }

 private line(line: string, frames: SseFrame[]): void {
  if (line === '') {
   if (this.data.length > 0) frames.push({ id: this.id, event: this.event === '' ? 'message' : this.event, data: this.data.join('\n') });
   this.event = '';
   this.id = null;
   this.data = [];
   this.dataSize = 0;
   return;
  }
  if (line.charCodeAt(0) === 0x3a) return;
  const colon = line.indexOf(':');
  const field = colon < 0 ? line : line.slice(0, colon);
  let value = colon < 0 ? '' : line.slice(colon + 1);
  if (value.charCodeAt(0) === 0x20) value = value.slice(1);
  switch (field) {
   case 'event': this.event = value; break;
   case 'id': if (!value.includes('\u0000')) this.id = value; break;
   case 'data':
    this.data.push(value);
    this.dataSize += value.length + 1;
    if (this.dataSize > this.maxFrameChars) throw new SseProtocolError('frame_too_large');
    break;
   default: break; // retry and unknown fields are ignored: there is no automatic reconnection here
  }
 }
}

/** Yields each complete frame of a response body. Ending the iteration, normally or not, cancels the underlying stream. */
export async function* readSse(body: ReadableStream<Uint8Array>, maxFrameChars: number = 1 << 20): AsyncGenerator<SseFrame> {
 const reader = body.getReader();
 const decoder = new TextDecoder('utf-8', { fatal: true });
 const parser = new SseParser(maxFrameChars);
 try {
  for (;;) {
   const { done, value } = await reader.read();
   if (done) break;
   let text: string;
   try { text = decoder.decode(value, { stream: true }); } catch { throw new SseProtocolError('invalid_utf8'); }
   for (const frame of parser.push(text)) yield frame;
  }
  try { decoder.decode(); } catch { throw new SseProtocolError('invalid_utf8'); }
 } finally {
  await reader.cancel().catch(() => undefined);
 }
}

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { SseParser, SseProtocolError, readSse, type SseFrame } from './sse';

const feed = (text: string, parser = new SseParser()): SseFrame[] => parser.push(text);
const frame = (event: string, data: string, id: string | null = null): SseFrame => ({ id, event, data });
const bytes = (text: string): Uint8Array => new TextEncoder().encode(text);
const streamOf = (chunks: Uint8Array[], onCancel?: () => void): ReadableStream<Uint8Array> => {
 let i = 0;
 return new ReadableStream<Uint8Array>({ pull(controller) { if (i < chunks.length) controller.enqueue(chunks[i++]!); else controller.close(); }, cancel() { onCancel?.(); } });
};
async function collect(body: ReadableStream<Uint8Array>): Promise<SseFrame[]> {
 const out: SseFrame[] = [];
 for await (const f of readSse(body)) out.push(f);
 return out;
}

describe('SSE framing (HTML Living Standard server-sent events, no EventSource)', () => {
 test('id, event and data make one frame; the stream comment makes none', () => {
  expect(feed(': soundpost live\n\nid: 7\nevent: record\ndata: {"a":1}\n\n')).toEqual([frame('record', '{"a":1}', '7')]);
 });
 test('data lines are joined by a newline; the event name defaults to message', () => {
  expect(feed('data: a\ndata: b\n\n')).toEqual([frame('message', 'a\nb')]);
 });
 test('CRLF and lone CR end lines exactly like LF', () => {
  expect(feed('event: gap\r\ndata: x\r\n\r\n')).toEqual([frame('gap', 'x')]);
  expect(feed('event: gap\rdata: x\r\r')).toEqual([frame('gap', 'x')]);
 });
 test('exactly one leading space of a value is dropped; a field without a colon has an empty value', () => {
  expect(feed('data:  two\n\n')).toEqual([frame('message', ' two')]);
  expect(feed('data:none\n\n')).toEqual([frame('message', 'none')]);
  expect(feed('data\n\n')).toEqual([frame('message', '')]);
 });
 test('a blank line with no data field dispatches nothing and forgets the event name', () => {
  expect(feed('event: record\n\ndata: x\n\n')).toEqual([frame('message', 'x')]);
 });
 test('an id with a NUL is ignored; retry and unknown fields never change a frame', () => {
  expect(feed('id: a\u0000b\nretry: 1\nweird: yes\nevent: open\ndata: {}\n\n')).toEqual([frame('open', '{}')]);
 });
 test('the id belongs to the frame that carried it: a later frame without one has none', () => {
  expect(feed('id: 4\nevent: record\ndata: 1\n\nevent: heartbeat\ndata: 2\n\n')).toEqual([frame('record', '1', '4'), frame('heartbeat', '2')]);
 });
 test('an incomplete trailing frame is never dispatched', () => {
  const p = new SseParser();
  expect(p.push('event: record\ndata: {"x":')).toEqual([]);
  expect(p.push('1}\n')).toEqual([]);
  expect(p.push('\n')).toEqual([frame('record', '{"x":1}')]);
 });
 test('a byte order mark at the start of the stream is dropped', () => {
  expect(feed('\uFEFFdata: x\n\n')).toEqual([frame('message', 'x')]);
 });
 test('every chunk boundary, including inside CRLF, gives the same frames', () => {
  const whole = 'id: 1\r\nevent: record\r\ndata: {"a":"é€"}\r\n\r\n: keep\r\nevent: gap\ndata: g\n\nid: 3\revent: revoke\rdata: r\r\r';
  const expected = feed(whole);
  expect(expected).toHaveLength(3);
  for (let cut = 0; cut <= whole.length; cut++) {
   const p = new SseParser();
   expect([...p.push(whole.slice(0, cut)), ...p.push(whole.slice(cut))]).toEqual(expected);
  }
  const p = new SseParser();
  const bytewise: SseFrame[] = [];
  for (const ch of whole) bytewise.push(...p.push(ch));
  expect(bytewise).toEqual(expected);
 });
 test('a frame beyond the bound is a typed protocol error, not unbounded memory', () => {
  const small = new SseParser(64);
  expect(() => small.push(`data: ${'x'.repeat(100)}`)).toThrow(SseProtocolError);
  const lines = new SseParser(64);
  expect(() => { for (let i = 0; i < 20; i++) lines.push('data: 0123456789\n'); }).toThrow(SseProtocolError);
  try { new SseParser(8).push('data: 0123456789'); } catch (e) { expect((e as SseProtocolError).code).toBe('frame_too_large'); }
 });
 test('frames under the bound pass even when the stream is much longer', () => {
  const p = new SseParser(64);
  let n = 0;
  for (let i = 0; i < 500; i++) n += p.push('data: 0123456789\n\n').length;
  expect(n).toBe(500);
 });
});

describe('readSse over a byte stream', () => {
 test('multi-byte characters split across chunks decode exactly', async () => {
  const all = bytes('event: record\ndata: ✓ €1 😀\n\n');
  const cut = all.indexOf(0xe2) + 1; // inside the 3-byte check mark
  const frames = await collect(streamOf([all.slice(0, cut), all.slice(cut, cut + 5), all.slice(cut + 5)]));
  expect(frames).toEqual([frame('record', '✓ €1 😀')]);
 });
 test('invalid UTF-8 is a typed protocol error', async () => {
  await expect(collect(streamOf([new Uint8Array([0x64, 0x61, 0x74, 0x61, 0x3a, 0x20, 0xff, 0x0a, 0x0a])]))).rejects.toMatchObject({ code: 'invalid_utf8' });
 });
 test('a stream that ends inside a frame yields only the complete ones', async () => {
  expect(await collect(streamOf([bytes('event: record\ndata: 1\n\nevent: record\ndata: 2')]))).toEqual([frame('record', '1')]);
 });
 test('stopping the consumer cancels the underlying stream', async () => {
  let cancelled = false;
  const body = streamOf([bytes('data: 1\n\n'), bytes('data: 2\n\n')], () => { cancelled = true; });
  for await (const f of readSse(body)) { expect(f.data).toBe('1'); break; }
  expect(cancelled).toBe(true);
 });
});

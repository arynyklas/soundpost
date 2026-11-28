// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

/*
 * A minimal WebDriver BiDi client (https://w3c.github.io/webdriver-bidi/): command/response correlation, event dispatch and the value
 * (de)serialization that `script.callFunction` needs. It exists because Playwright's BiDi frame evaluation wraps every expression in an
 * `eval`, which the replay viewer's production Content-Security-Policy correctly refuses; `script.callFunction` with a function declaration
 * needs no eval, so a stock Firefox can be asked what the sandboxed viewer frame really did without weakening the policy under test
 * (no `bypassCSP`). Nothing here knows about the viewer.
 */

export interface BidiErrorBody { readonly error: string; readonly message: string }
export class BidiError extends Error {
 readonly code: string;
 constructor(body: BidiErrorBody, readonly method: string) { super(`${method}: ${body.error}: ${body.message}`); this.name = "BidiError"; this.code = body.error; }
}

type Pending = {readonly method: string; readonly resolve: (value: unknown) => void; readonly reject: (error: Error) => void; readonly timer: ReturnType<typeof setTimeout>};
export type EventHandler = (params: Record<string, unknown>) => void;

export class BidiConnection {
 private readonly pending = new Map<number, Pending>();
 private readonly handlers = new Map<string, Set<EventHandler>>();
 private next = 1;
 private closedError: Error | undefined;

 private constructor(private readonly socket: WebSocket, private readonly timeoutMs: number) {
  socket.addEventListener("message", event => this.onMessage(String(event.data)));
  socket.addEventListener("close", () => this.fail(new Error("WebDriver BiDi connection closed")));
  socket.addEventListener("error", () => this.fail(new Error("WebDriver BiDi connection failed")));
 }

 /** Opens the socket; commands that get no answer within `timeoutMs` reject instead of hanging a run. */
 static connect(url: string, timeoutMs = 30000): Promise<BidiConnection> {
  const {promise, resolve, reject} = Promise.withResolvers<BidiConnection>();
  const socket = new WebSocket(url);
  const failed = (): void => reject(new Error(`cannot connect to ${url}`));
  socket.addEventListener("error", failed, {once: true});
  socket.addEventListener("open", () => { socket.removeEventListener("error", failed); resolve(new BidiConnection(socket, timeoutMs)); }, {once: true});
  return promise;
 }

 send<T = Record<string, unknown>>(method: string, params: Record<string, unknown> = {}): Promise<T> {
  if (this.closedError !== undefined) return Promise.reject(this.closedError);
  const id = this.next++;
  const {promise, resolve, reject} = Promise.withResolvers<T>();
  const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`${method}: no response within ${this.timeoutMs} ms`)); }, this.timeoutMs);
  this.pending.set(id, {method, resolve: resolve as (value: unknown) => void, reject, timer});
  this.socket.send(JSON.stringify({id, method, params}));
  return promise;
 }

 on(event: string, handler: EventHandler): () => void {
  let set = this.handlers.get(event);
  if (set === undefined) { set = new Set(); this.handlers.set(event, set); }
  set.add(handler);
  return () => { set.delete(handler); };
 }

 close(): void { this.fail(new Error("WebDriver BiDi connection closed")); try { this.socket.close(); } catch { /* already closed */ } }

 private onMessage(text: string): void {
  let message: Record<string, unknown>;
  try { message = JSON.parse(text) as Record<string, unknown>; } catch { return; }
  if (message["type"] === "event" && typeof message["method"] === "string") {
   for (const handler of [...(this.handlers.get(message["method"]) ?? [])]) {
    try { handler((message["params"] ?? {}) as Record<string, unknown>); } catch { /* one listener cannot break the connection */ }
   }
   return;
  }
  const id = message["id"];
  if (typeof id !== "number") return;
  const entry = this.pending.get(id);
  if (entry === undefined) return;
  this.pending.delete(id);
  clearTimeout(entry.timer);
  if (message["type"] === "success") entry.resolve(message["result"]);
  else entry.reject(new BidiError({error: String(message["error"] ?? "unknown error"), message: String(message["message"] ?? "")}, entry.method));
 }

 private fail(error: Error): void {
  if (this.closedError !== undefined) return;
  this.closedError = error;
  for (const [id, entry] of this.pending) { clearTimeout(entry.timer); entry.reject(error); this.pending.delete(id); }
 }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// script.LocalValue / script.RemoteValue

type Json = null | boolean | number | string | Json[] | {[key: string]: Json};

/** A JSON-compatible JS value as a script.LocalValue (for `script.callFunction` arguments). */
export function toLocal(value: unknown): Record<string, unknown> {
 if (value === undefined) return {type: "undefined"};
 if (value === null) return {type: "null"};
 if (typeof value === "string") return {type: "string", value};
 if (typeof value === "boolean") return {type: "boolean", value};
 if (typeof value === "number") {
  if (Number.isNaN(value)) return {type: "number", value: "NaN"};
  if (Object.is(value, -0)) return {type: "number", value: "-0"};
  if (value === Infinity) return {type: "number", value: "Infinity"};
  if (value === -Infinity) return {type: "number", value: "-Infinity"};
  return {type: "number", value};
 }
 if (Array.isArray(value)) return {type: "array", value: value.map(toLocal)};
 if (typeof value === "object") return {type: "object", value: Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, toLocal(entry)])};
 throw new TypeError(`cannot send a ${typeof value} to the browser`);
}

/** A script.RemoteValue as plain data: primitives, arrays and objects (maps with string keys); anything else is its type name. */
export function fromRemote(remote: unknown): Json | undefined {
 if (remote === null || typeof remote !== "object") return undefined;
 const node = remote as {type?: string; value?: unknown};
 switch (node.type) {
  case "undefined": return undefined;
  case "null": return null;
  case "string": case "boolean": return node.value as string | boolean;
  case "number": return typeof node.value === "number" ? node.value : node.value === "-0" ? -0 : node.value === "NaN" ? NaN : node.value === "Infinity" ? Infinity : node.value === "-Infinity" ? -Infinity : Number(node.value);
  case "bigint": return String(node.value);
  case "array": case "set": return (node.value as unknown[]).map(entry => fromRemote(entry) ?? null);
  case "object": case "map": {
   const out: {[key: string]: Json} = {};
   for (const pair of node.value as [unknown, unknown][]) {
    const key = typeof pair[0] === "string" ? pair[0] : String(fromRemote(pair[0]));
    out[key] = fromRemote(pair[1]) ?? null;
   }
   return out;
  }
  default: return `[${node.type ?? "unknown"}]`;
 }
}

export interface Target { readonly context: string; readonly sandbox?: string }

/**
 * Calls `fn` (a function declaration, serialized with toString: it must be self-contained and eval-free) in the realm of `target` with
 * JSON arguments and returns its JSON result. `awaitPromise` makes an async function's result be awaited. An exception thrown by the
 * function rejects with its text.
 */
export async function callFunction<T = unknown>(connection: BidiConnection, target: Target, fn: (...args: never[]) => unknown, ...args: unknown[]): Promise<T> {
 const result = await connection.send<{type: string; result?: unknown; exceptionDetails?: {text?: string}}>("script.callFunction", {
  functionDeclaration: fn.toString(), awaitPromise: true, target: target.sandbox === undefined ? {context: target.context} : {context: target.context, sandbox: target.sandbox},
  arguments: args.map(toLocal), resultOwnership: "none", serializationOptions: {maxObjectDepth: 8, maxDomDepth: 0},
 });
 if (result.type === "exception") throw new Error(`script exception: ${result.exceptionDetails?.text ?? "unknown"}`);
 return fromRemote(result.result) as T;
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {afterEach, describe, expect, test} from "bun:test";
import {BidiConnection, BidiError, callFunction, fromRemote, toLocal} from "./bidi.ts";

/** A scripted BiDi endpoint: `answer` sees every command and replies through the socket it is given. */
interface Command { id: number; method: string; params: Record<string, unknown> }
type Reply = (message: Record<string, unknown>) => void;
const servers: ReturnType<typeof Bun.serve>[] = [];
afterEach(() => { for (const server of servers.splice(0)) server.stop(true); });

function endpoint(answer: (command: Command, reply: Reply, sockets: Set<{send(text: string): void; close(): void}>) => void): string {
 const sockets = new Set<{send(text: string): void; close(): void}>();
 const server = Bun.serve({port: 0, hostname: "127.0.0.1", fetch(request, bun) { return bun.upgrade(request) ? undefined : new Response("no", {status: 400}); }, websocket: {
  open(socket) { sockets.add(socket); },
  close(socket) { sockets.delete(socket); },
  message(socket, data) {
   const command = JSON.parse(String(data)) as Command;
   answer(command, message => socket.send(JSON.stringify(message)), sockets);
  },
 }});
 servers.push(server);
 return `ws://127.0.0.1:${server.port}`;
}

describe("commands", () => {
 test("answers are matched to their command by id even when they arrive out of order", async () => {
  const held: Command[] = [];
  const url = endpoint((command, reply) => {
   held.push(command);
   if (held.length === 2) for (const entry of [...held].reverse()) reply({type: "success", id: entry.id, result: {echo: entry.params["value"]}});
  });
  const connection = await BidiConnection.connect(url);
  const [first, second] = await Promise.all([connection.send("test.echo", {value: "one"}), connection.send("test.echo", {value: "two"})]);
  expect(first).toEqual({echo: "one"});
  expect(second).toEqual({echo: "two"});
  connection.close();
 });

 test("an error answer rejects with the BiDi error code and message, naming the method", async () => {
  const url = endpoint((command, reply) => reply({type: "error", id: command.id, error: "no such frame", message: "context 7 is gone"}));
  const connection = await BidiConnection.connect(url);
  const error = await connection.send("browsingContext.getTree").then(() => undefined, (value: unknown) => value as BidiError);
  expect(error).toBeInstanceOf(BidiError);
  expect(error!.code).toBe("no such frame");
  expect(error!.message).toContain("browsingContext.getTree");
  expect(error!.message).toContain("context 7 is gone");
  connection.close();
 });

 test("a command nobody answers rejects at its deadline instead of hanging the run", async () => {
  const url = endpoint(() => undefined);
  const connection = await BidiConnection.connect(url, 50);
  const error = await connection.send("session.status").then(() => undefined, (value: unknown) => value as Error);
  expect(error?.message).toContain("session.status: no response within 50 ms");
  connection.close();
 });

 test("closing rejects every pending command and every later one", async () => {
  const url = endpoint(() => undefined);
  const connection = await BidiConnection.connect(url);
  const pending = connection.send("session.status").then(() => undefined, (value: unknown) => value as Error);
  connection.close();
  expect((await pending)?.message).toContain("closed");
  expect((await connection.send("session.status").then(() => undefined, (value: unknown) => value as Error))?.message).toContain("closed");
 });

 test("a server that drops the socket rejects what was waiting", async () => {
  const url = endpoint((_command, _reply, sockets) => { for (const socket of sockets) socket.close(); });
  const connection = await BidiConnection.connect(url);
  expect((await connection.send("session.status").then(() => undefined, (value: unknown) => value as Error))?.message).toContain("closed");
 });

 test("connecting to nothing is an error naming the endpoint", async () => {
  const url = endpoint(() => undefined);
  for (const server of servers.splice(0)) server.stop(true);
  const error = await BidiConnection.connect(url).then(() => undefined, (value: unknown) => value as Error);
  expect(error?.message).toContain(url);
 });
});

describe("events", () => {
 test("events reach only the handlers of their method, and a throwing handler neither stops the others nor the connection", async () => {
  const url = endpoint((command, reply, sockets) => {
   // Events first, then the answer: a command's answer is then proof that the events before it were already delivered.
   for (const socket of sockets) {
    socket.send(JSON.stringify({type: "event", method: "log.entryAdded", params: {text: "boom"}}));
    socket.send(JSON.stringify({type: "event", method: "network.fetchError", params: {errorText: "x"}}));
   }
   reply({type: "success", id: command.id, result: {}});
  });
  const connection = await BidiConnection.connect(url);
  const logged: unknown[] = [], errors: unknown[] = [];
  connection.on("log.entryAdded", () => { throw new Error("listener bug"); });
  connection.on("log.entryAdded", params => logged.push(params["text"]));
  const off = connection.on("network.fetchError", params => errors.push(params["errorText"]));
  await connection.send("session.subscribe", {events: ["log"]});
  await connection.send("session.status");
  expect(logged).toEqual(["boom", "boom"]);
  expect(errors).toEqual(["x", "x"]);
  off();
  await connection.send("session.status");
  expect(errors).toEqual(["x", "x"]);
  connection.close();
 });
});

describe("values", () => {
 test("JSON arguments become script.LocalValue, including -0, NaN, infinities, arrays and nested objects", () => {
  expect(toLocal("a")).toEqual({type: "string", value: "a"});
  expect(toLocal(true)).toEqual({type: "boolean", value: true});
  expect(toLocal(null)).toEqual({type: "null"});
  expect(toLocal(undefined)).toEqual({type: "undefined"});
  expect(toLocal(1.5)).toEqual({type: "number", value: 1.5});
  expect(toLocal(-0)).toEqual({type: "number", value: "-0"});
  expect(toLocal(NaN)).toEqual({type: "number", value: "NaN"});
  expect(toLocal(-Infinity)).toEqual({type: "number", value: "-Infinity"});
  expect(toLocal([1, "b"])).toEqual({type: "array", value: [{type: "number", value: 1}, {type: "string", value: "b"}]});
  expect(toLocal({k: {n: null}})).toEqual({type: "object", value: [["k", {type: "object", value: [["n", {type: "null"}]]}]]});
  expect(() => toLocal(() => 1)).toThrow(TypeError);
  expect(() => toLocal(1n)).toThrow(TypeError);
 });

 test("script.RemoteValue becomes plain data and unserializable types are named, not invented", () => {
  expect(fromRemote({type: "string", value: "s"})).toBe("s");
  expect(fromRemote({type: "number", value: "-0"})).toBe(-0);
  expect(fromRemote({type: "number", value: "Infinity"})).toBe(Infinity);
  expect(fromRemote({type: "bigint", value: "18446744073709551615"})).toBe("18446744073709551615");
  expect(fromRemote({type: "null"})).toBeNull();
  expect(fromRemote({type: "undefined"})).toBeUndefined();
  expect(fromRemote({type: "array", value: [{type: "number", value: 1}, {type: "undefined"}]})).toEqual([1, null]);
  expect(fromRemote({type: "object", value: [["a", {type: "boolean", value: false}], ["b", {type: "array", value: []}]]})).toEqual({a: false, b: []});
  expect(fromRemote({type: "map", value: [[{type: "string", value: "k"}, {type: "string", value: "v"}]]})).toEqual({k: "v"});
  expect(fromRemote({type: "window", value: {context: "x"}})).toBe("[window]");
 });
});

describe("script.callFunction", () => {
 test("sends the function declaration as text with serialized arguments and awaits promises, and no eval is involved on the client", async () => {
  let seen: Command | undefined;
  const url = endpoint((command, reply) => {
   seen = command;
   reply({type: "success", id: command.id, result: {type: "success", realm: "r", result: {type: "object", value: [["sum", {type: "number", value: 5}], ["name", {type: "string", value: "frame"}]]}}});
  });
  const connection = await BidiConnection.connect(url);
  const result = await callFunction<{sum: number; name: string}>(connection, {context: "ctx-1"}, async (a: number, b: number) => ({sum: a + b, name: "frame"}), 2, 3);
  expect(result).toEqual({sum: 5, name: "frame"});
  expect(seen!.method).toBe("script.callFunction");
  expect(seen!.params["awaitPromise"]).toBe(true);
  expect(seen!.params["target"]).toEqual({context: "ctx-1"});
  expect(seen!.params["arguments"]).toEqual([{type: "number", value: 2}, {type: "number", value: 3}]);
  expect(String(seen!.params["functionDeclaration"])).toContain("a + b");
  expect(seen!.params["resultOwnership"]).toBe("none");
  connection.close();
 });

 test("a sandbox name is passed through, and an exception in the page rejects with its text", async () => {
  let seen: Command | undefined;
  const url = endpoint((command, reply) => {
   seen = command;
   reply({type: "success", id: command.id, result: {type: "exception", realm: "r", exceptionDetails: {text: "ReferenceError: nope is not defined"}}});
  });
  const connection = await BidiConnection.connect(url);
  const error = await callFunction(connection, {context: "ctx-2", sandbox: "probe"}, () => 1).then(() => undefined, (value: unknown) => value as Error);
  expect(error?.message).toContain("ReferenceError: nope is not defined");
  expect(seen!.params["target"]).toEqual({context: "ctx-2", sandbox: "probe"});
  connection.close();
 });
});

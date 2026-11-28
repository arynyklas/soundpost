// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Task 04.09 database wait of the Bun runtime column: a minimal PostgreSQL v3 wire-protocol client over Bun.connect
// (startup, trust or cleartext-password authentication, the simple Query message), so that the process really blocks in
// its event loop while a PostgreSQL server sleeps. No driver, no dependency. The database is named by an address
// ("host:port") the runner passes in the environment; the address is never printed.

export const DB_DELAY_S = 0.2;
// The server holds the statement for DB_DELAY_S and then reports, by its own clock and inside the same statement, how long
// the statement has been running (clock_timestamp() after the sleep minus statement_timestamp()): the materialized CTE is
// fully read before the outer select evaluates the clock, so the account cannot be taken before the sleep.
export const SLEEP_SQL = `with s as materialized (select pg_sleep(${DB_DELAY_S})) select (extract(epoch from clock_timestamp() - statement_timestamp()))::text from s`;

export function splitHostPort(addr: string): [string, number] {
  const i = addr.lastIndexOf(":");
  const port = Number(addr.slice(i + 1));
  if (i <= 0 || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error("the database address is not host:port");
  return [addr.slice(0, i).replace(/^\[|\]$/g, ""), port];
}

const cstring = (s: string): Buffer => Buffer.concat([Buffer.from(s, "utf8"), Buffer.from([0])]);
function frame(type: string, body: Buffer): Buffer {
  const head = Buffer.alloc(5);
  head[0] = type.charCodeAt(0);
  head.writeInt32BE(body.length + 4, 1);
  return Buffer.concat([head, body]);
}
function errorText(body: Buffer): string {
  // ErrorResponse: repeated (field byte, cstring) up to a zero byte; S is the severity and M the message
  let severity = "", message = "";
  for (let i = 0; i < body.length && body[i] !== 0;) {
    const field = String.fromCharCode(body[i]);
    const end = body.indexOf(0, i + 1);
    const text = body.subarray(i + 1, end).toString("utf8");
    if (field === "S") severity = text;
    if (field === "M") message = text;
    i = end + 1;
  }
  return `${severity}: ${message}`;
}

export class PgClient {
  private buf: Buffer = Buffer.alloc(0);
  private wake: (() => void) | null = null;
  failure: Error | null = null;
  closed = false;
  params: Record<string, string> = {};
  socket: Bun.Socket | null = null;

  notify(): void { const w = this.wake; this.wake = null; if (w) w(); }
  push(d: Uint8Array): void { this.buf = Buffer.concat([this.buf, d]); this.notify(); }
  write(b: Buffer): void {
    if (!this.socket) throw new Error("the database connection is not open");
    const n = this.socket.write(b);
    if (n !== b.length) throw new Error(`short socket write (${n} of ${b.length} bytes)`);
  }
  async message(): Promise<{ type: string; body: Buffer }> {
    for (;;) {
      if (this.buf.length >= 5) {
        const length = this.buf.readInt32BE(1);
        if (length < 4) throw new Error("malformed PostgreSQL message");
        if (this.buf.length >= 1 + length) {
          const type = String.fromCharCode(this.buf[0]);
          const body = this.buf.subarray(5, 1 + length);
          this.buf = this.buf.subarray(1 + length);
          return { type, body };
        }
      }
      if (this.failure) throw this.failure;
      if (this.closed) throw new Error("the database closed the connection");
      const { promise, resolve } = Promise.withResolvers<void>();
      this.wake = resolve;
      await promise;
    }
  }
  async startup(user: string, database: string, password: string): Promise<void> {
    const body = Buffer.concat([Buffer.from([0, 3, 0, 0]), cstring("user"), cstring(user), cstring("database"), cstring(database), cstring("application_name"), cstring("soundpost-nativeperf"), Buffer.from([0])]);
    const head = Buffer.alloc(4);
    head.writeInt32BE(body.length + 4, 0);
    this.write(Buffer.concat([head, body]));
    for (;;) {
      const { type, body: b } = await this.message();
      if (type === "R") {
        const code = b.readInt32BE(0);
        if (code === 3) {
          if (!password) throw new Error("the database asks for a password and none was given");
          this.write(frame("p", cstring(password)));
        } else if (code !== 0) {
          throw new Error(`the database asks for authentication method ${code}; the fixture speaks trust and cleartext only`);
        }
      } else if (type === "S") {
        const name = b.subarray(0, b.indexOf(0)).toString("utf8");
        this.params[name] = b.subarray(b.indexOf(0) + 1, b.length - 1).toString("utf8");
      } else if (type === "E") {
        throw new Error(errorText(b));
      } else if (type === "Z") {
        return;
      }
    }
  }
  // query runs one simple Query and returns its rows (arrays of text or null).
  async query(sql: string): Promise<(string | null)[][]> {
    this.write(frame("Q", cstring(sql)));
    const rows: (string | null)[][] = [];
    let failure: string | null = null;
    for (;;) {
      const { type, body } = await this.message();
      if (type === "D") {
        const n = body.readInt16BE(0);
        let at = 2;
        const row: (string | null)[] = [];
        for (let i = 0; i < n; i++) {
          const length = body.readInt32BE(at);
          at += 4;
          if (length < 0) { row.push(null); continue; }
          row.push(body.subarray(at, at + length).toString("utf8"));
          at += length;
        }
        rows.push(row);
      } else if (type === "E") {
        failure = errorText(body);
      } else if (type === "Z") {
        if (failure) throw new Error(failure);
        return rows;
      }
    }
  }
  close(): void {
    try { this.write(frame("X", Buffer.alloc(0))); } catch { /* the peer may be gone */ }
    try { this.socket?.end(); } catch { /* already closed */ }
  }
}

// connectPg opens the connection and runs the startup, then a first statement: the connection, its buffers and the
// first round trip exist before the measured phase.
export async function connectPg(addr: string, opts: { user?: string; database?: string; password?: string } = {}): Promise<PgClient> {
  const [hostname, port] = splitHostPort(addr);
  const client = new PgClient();
  client.socket = await Bun.connect({
    hostname, port,
    socket: {
      data(_socket: unknown, d: Uint8Array) { client.push(d); },
      open() {},
      close() { client.closed = true; client.notify(); },
      error(_socket: unknown, e: Error) { client.failure = e; client.notify(); },
      connectError(_socket: unknown, e: Error) { client.failure = e; client.notify(); },
    },
  });
  await client.startup(opts.user ?? "postgres", opts.database ?? "postgres", opts.password ?? "");
  await client.query("select 1");
  return client;
}

// databaseWait runs `requests` statements one after the other and returns each round trip (ms, by now()) and what the
// server reported holding each one (seconds). A server that did not hold a statement for the sleep it was asked is an
// error, not a result.
export async function databaseWait(client: PgClient, requests: number, now: () => number): Promise<{ waitsMs: number[]; reportedS: number[] }> {
  const waitsMs: number[] = [], reportedS: number[] = [];
  for (let i = 0; i < requests; i++) {
    const started = now();
    const rows = await client.query(SLEEP_SQL);
    waitsMs.push(now() - started);
    const held = Number(rows[0][0]);
    if (!(held >= DB_DELAY_S)) throw new Error(`the database reported holding a statement for ${held} s, less than the ${DB_DELAY_S} s it was asked to sleep`);
    reportedS.push(held);
  }
  return { waitsMs, reportedS };
}

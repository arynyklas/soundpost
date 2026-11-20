# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Task 04.09 database wait of the CPython runtime column: a minimal PostgreSQL v3 wire-protocol client over asyncio
streams (startup, trust or cleartext-password authentication, the simple Query message), so the interpreter really blocks
in the event loop's epoll while a PostgreSQL server sleeps. Standard library only. The database is named by an address
("host:port") the runner passes in the environment; the address is never printed."""
import asyncio
import struct
import time

DB_DELAY_S = 0.2
# The server holds the statement for DB_DELAY_S and then reports, by its own clock and inside the same statement, how long
# the statement has been running (clock_timestamp() after the sleep minus statement_timestamp()): the materialized CTE is
# fully read before the outer select evaluates the clock, so the account cannot be taken before the sleep.
SLEEP_SQL = (f"with s as materialized (select pg_sleep({DB_DELAY_S})) "
             "select (extract(epoch from clock_timestamp() - statement_timestamp()))::text from s")


def split_host_port(addr):
    host, sep, port = addr.rpartition(":")
    if not sep or not host or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("the database address is not host:port")
    return host.strip("[]"), int(port)


def _cstring(text):
    return text.encode() + b"\0"


def _frame(kind, body):
    return kind + struct.pack(">I", len(body) + 4) + body


def _error_text(body):
    # ErrorResponse: repeated (field byte, cstring) up to a zero byte; S is the severity and M the message
    fields = {}
    at = 0
    while at < len(body) and body[at] != 0:
        end = body.index(b"\0", at + 1)
        fields[chr(body[at])] = body[at + 1:end].decode(errors="replace")
        at = end + 1
    return f"{fields.get('S', '')}: {fields.get('M', '')}"


class PgClient:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.params = {}

    async def message(self):
        head = await self.reader.readexactly(5)
        length = struct.unpack(">I", head[1:])[0]
        if length < 4:
            raise ConnectionError("malformed PostgreSQL message")
        return chr(head[0]), await self.reader.readexactly(length - 4)

    async def startup(self, user, database, password):
        body = b"\0\x03\0\0" + b"".join(_cstring(x) for x in ("user", user, "database", database, "application_name", "soundpost-nativeperf")) + b"\0"
        self.writer.write(struct.pack(">I", len(body) + 4) + body)
        await self.writer.drain()
        while True:
            kind, body = await self.message()
            if kind == "R":
                code = struct.unpack(">i", body[:4])[0]
                if code == 3:
                    if not password:
                        raise ConnectionError("the database asks for a password and none was given")
                    self.writer.write(_frame(b"p", _cstring(password)))
                    await self.writer.drain()
                elif code != 0:
                    raise ConnectionError(f"the database asks for authentication method {code}; the fixture speaks trust and cleartext only")
            elif kind == "S":
                name, _, rest = body.partition(b"\0")
                self.params[name.decode()] = rest[:-1].decode()
            elif kind == "E":
                raise ConnectionError(_error_text(body))
            elif kind == "Z":
                return

    async def query(self, sql):
        """One simple Query; returns its rows (lists of text or None)."""
        self.writer.write(_frame(b"Q", _cstring(sql)))
        await self.writer.drain()
        rows, failure = [], None
        while True:
            kind, body = await self.message()
            if kind == "D":
                (count,) = struct.unpack(">h", body[:2])
                at, row = 2, []
                for _ in range(count):
                    (length,) = struct.unpack(">i", body[at:at + 4])
                    at += 4
                    if length < 0:
                        row.append(None)
                        continue
                    row.append(body[at:at + length].decode())
                    at += length
                rows.append(row)
            elif kind == "E":
                failure = _error_text(body)
            elif kind == "Z":
                if failure:
                    raise ConnectionError(failure)
                return rows

    def close(self):
        try:
            self.writer.write(_frame(b"X", b""))
        except Exception:
            pass
        self.writer.close()


async def connect_pg(addr, user="postgres", database="postgres", password=""):
    """Opens the connection, runs the startup and a first statement (the connection and its first round trip exist before
    the measured queries)."""
    host, port = split_host_port(addr)
    reader, writer = await asyncio.open_connection(host, port)
    client = PgClient(reader, writer)
    await client.startup(user, database, password)
    await client.query("select 1")
    return client


async def database_wait(client, requests):
    """Runs `requests` statements one after the other; returns each round trip (seconds, perf_counter) and what the server
    reported holding each one (seconds). A server that did not hold a statement for the sleep it was asked is an error, not
    a result."""
    waits, reported = [], []
    for _ in range(requests):
        started = time.perf_counter()
        rows = await client.query(SLEEP_SQL)
        waits.append(time.perf_counter() - started)
        held = float(rows[0][0])
        if not held >= DB_DELAY_S:
            raise ConnectionError(f"the database reported holding a statement for {held} s, less than the {DB_DELAY_S} s it was asked to sleep")
        reported.append(held)
    return waits, reported

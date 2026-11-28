# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Reference orders API (WSGI). Never logs or echoes request/prompt/SQL/note text."""
import json

SYSTEM_PROMPT = "You summarize a catalog order for the warehouse. Marker CANARY_PROMPT_9b2f."
PRICE_SQL = "SELECT price_cents FROM catalog WHERE item = %s /* CANARY_SQL_LITERAL_5d1e */"
INSERT_SQL = "INSERT INTO orders(item, quantity, note, channel, status) VALUES (%s, %s, %s, %s, %s) RETURNING id"
MAX_BODY = 65536

BAD_REQUEST = b'{"error":"bad_request"}'
SERVER_ERROR = b'{"error":"internal_error"}'
NOT_FOUND = b'{"error":"not_found"}'


class BadRequest(Exception):
    pass


def parse_order(raw):
    try:
        body = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise BadRequest from None
    if type(body) is not dict:
        raise BadRequest
    item, quantity, note = body.get("item"), body.get("quantity"), body.get("note", "")
    if type(item) is not str or not 1 <= len(item) <= 128:
        raise BadRequest
    if type(quantity) is not int or not 1 <= quantity <= 1000:
        raise BadRequest
    if type(note) is not str or len(note) > 2000:
        raise BadRequest
    return item, quantity, note


class Application:
    def __init__(self, instruments, dsn):
        self.instruments = instruments
        self.dsn = dsn

    def _respond(self, start_response, status, body):
        data = body if isinstance(body, bytes) else json.dumps(body, separators=(",", ":")).encode("utf-8")
        start_response(status, [("Content-Type", "application/json"), ("Content-Length", str(len(data)))])
        return [data]

    def __call__(self, environ, start_response):
        method, path = environ["REQUEST_METHOD"], environ.get("PATH_INFO", "")
        if path == "/healthz" and method == "GET":
            return self._respond(start_response, "200 OK", {"ok": True})
        if path != "/orders":
            return self._respond(start_response, "404 Not Found", NOT_FOUND)
        if method != "POST":
            return self._respond(start_response, "405 Method Not Allowed", NOT_FOUND)
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
            if not 0 < length <= MAX_BODY:
                raise BadRequest
            item, quantity, note = parse_order(environ["wsgi.input"].read(length))
        except (BadRequest, ValueError):
            return self._respond(start_response, "400 Bad Request", BAD_REQUEST)
        try:
            return self._respond(start_response, "200 OK", self.create_order(item, quantity, note))
        except Exception as error:
            self.instruments.capture(error, "request")
            return self._respond(start_response, "500 Internal Server Error", SERVER_ERROR)

    def create_order(self, item, quantity, note):
        import psycopg
        with psycopg.connect(self.dsn, autocommit=True) as connection:
            db = self.instruments.database(connection)
            row = db.execute(PRICE_SQL, (item,)).fetchone()
            total = row[0] * quantity if row is not None else None
            status = "priced" if total is not None else "unpriced"
            order_id = db.execute(INSERT_SQL, (item, quantity, note, "api", status)).fetchone()[0]
        prompt = f"{SYSTEM_PROMPT}\nitem: {item}\nnote: {note}"
        response = self.instruments.post_dependency("/v1/complete", json={"prompt": prompt, "max_tokens": 64})
        if response.status_code != 200:
            raise RuntimeError("dependency_unavailable")
        summary = response.json()["completion"]
        return {"order_id": order_id, "item": item, "quantity": quantity, "total_cents": total,
                "status": status, "summary": summary}

# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Deterministic HTTPS completion dependency for the reference journeys.

Standard library only and deliberately NOT instrumented. It never logs or
stores prompt text: only sha256 digests and canary-substring counters.
"""
import argparse
import hashlib
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CANARIES = ("CANARY_PROMPT_9b2f", "CANARY_BODY_7f3a")
MAX_BODY = 1 << 20

_lock = threading.Lock()
_state = {"requests": 0, "by_run": {}, "prompt_sha256": [], "prompt_contains": {name: 0 for name in CANARIES}}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "reference-dependency"

    def log_message(self, fmt, *args):  # replaced by log_request below
        pass

    def log_request(self, code="-", size="-"):
        # method, path (no query), status only
        path = self.path.split("?", 1)[0]
        print(f"{self.command} {path} {code}", flush=True)

    def _send(self, status, body):
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            return self._send(200, {"ok": True})
        if path == "/v1/stats":
            with _lock:
                snapshot = json.loads(json.dumps(_state))
            return self._send(200, snapshot)
        self._send(404, {"error": "not_found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if path != "/v1/complete":
            if 0 < length <= MAX_BODY:
                self.rfile.read(length)
            return self._send(404, {"error": "not_found"})
        if not 0 <= length <= MAX_BODY:
            self.close_connection = True
            return self._send(400, {"error": "bad_request"})
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw)
            prompt = body["prompt"]
            max_tokens = body["max_tokens"]
            if type(prompt) is not str or type(max_tokens) is not int or isinstance(max_tokens, bool) or max_tokens < 0:
                raise ValueError
        except (ValueError, KeyError, TypeError):
            return self._send(400, {"error": "bad_request"})
        digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        run = self.headers.get("X-Reference-Run")
        with _lock:
            _state["requests"] += 1
            _state["prompt_sha256"].append(digest)
            for name in CANARIES:
                if name in prompt:
                    _state["prompt_contains"][name] += 1
            first = False
            if run is not None:
                count = _state["by_run"].get(run, 0) + 1
                _state["by_run"][run] = count
                first = count == 1
        if first:
            return self._send(503, {"error": "warming_up"})
        words = len(prompt.split())
        self._send(200, {"completion": "summary-" + digest[:12], "tokens": min(max_tokens, max(1, words))})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()
    host, _, port = args.listen.rpartition(":")
    server = ThreadingHTTPServer((host, int(port)), Handler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(json.dumps({"listening": args.listen}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

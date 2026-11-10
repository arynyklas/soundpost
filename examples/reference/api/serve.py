# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""HTTPS WSGI server for the reference orders API.

PostgreSQL DSN comes only from REFERENCE_DATABASE_URL. Log lines carry method,
path, status and duration only. SIGTERM/SIGINT flushes the SDK and prints one
JSON line {"flush": {...}} to stdout.
"""
import argparse
import json
import os
import signal
import socketserver
import ssl
import sys
import threading
import time
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import telemetry  # noqa: E402
from app import Application  # noqa: E402


class QuietHandler(WSGIRequestHandler):
    def log_message(self, fmt, *args):
        pass


class Server(socketserver.ThreadingMixIn, WSGIServer):
    daemon_threads = True

    def server_bind(self):
        # Skip the reverse-DNS lookup WSGIServer.server_bind performs.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[0], self.server_address[1]
        self.setup_environ()


def logged(app):
    def wrapper(environ, start_response):
        started, status = time.monotonic(), ["-"]

        def start(value, headers, exc_info=None):
            status[0] = value[:3]
            return start_response(value, headers, exc_info) if exc_info is not None else start_response(value, headers)
        try:
            return app(environ, start)
        finally:
            path = environ.get("PATH_INFO", "")
            print(f"{environ['REQUEST_METHOD']} {path} {status[0]} {(time.monotonic() - started) * 1000:.1f}ms", file=sys.stderr, flush=True)
    return wrapper


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--config")
    parser.add_argument("--ca")
    parser.add_argument("--dependency-url", required=True)
    args = parser.parse_args()
    dsn = os.environ["REFERENCE_DATABASE_URL"]

    client = data = None
    if args.config:
        client, data = telemetry.load_client(args.config)
    ca = args.ca or (data or {}).get("ca_file")
    http = telemetry.http_client(ca)
    instruments = telemetry.Instruments(client, http, args.dependency_url)
    app = Application(instruments, dsn)
    instrumented = app
    if client is not None:
        from soundpost.integrations.wsgi import WSGIMiddleware
        instrumented = WSGIMiddleware(app, client, operation="request")

    def dispatch(environ, start_response):
        # Readiness probes are not part of the application journeys.
        if environ.get("PATH_INFO") == "/healthz":
            return app(environ, start_response)
        return instrumented(environ, start_response)

    host, _, port = args.listen.rpartition(":")
    server = Server((host, int(port)), QuietHandler)
    server.set_app(logged(dispatch))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)

    def stop(*_):
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(json.dumps({"listening": args.listen}), flush=True)
    server.serve_forever()
    server.server_close()
    http.close()
    report, clean = telemetry.finish(client, 10.0)
    if report is not None:
        print(json.dumps({"flush": report}), flush=True)
    sys.exit(0 if clean else 1)


if __name__ == "__main__":
    main()

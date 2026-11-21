# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread, Barrier

class DependencyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.parents.append(self.headers.get('traceparent'))
        self.server.concurrent.wait(timeout=10)
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'ok')
    def log_message(self, *args): pass

class Dependency:
    def __enter__(self):
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), DependencyHandler)
        self.server.parents = []
        self.server.concurrent = Barrier(2)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f'http://127.0.0.1:{self.server.server_port}'
        return self
    def __exit__(self, *error):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

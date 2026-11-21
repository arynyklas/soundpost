#!/usr/bin/env python3
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Alert route for the external deadman observer: an authenticated HTTPS webhook that turns each notice into one e-mail.

The observer (tests/acceptance/observer) delivers every outage notice as `POST <destination>` with
`Authorization: Bearer <delivery credential>` and an `Idempotency-Key`. This receiver is the destination: it checks the
credential, hands the notice to the local mail system (`sendmail -t -i`, so the message lands in a mailbox a person reads
and the product is not on the path), and only then answers 2xx. A repeated Idempotency-Key is answered 2xx without a second
message, so the observer's bounded retries never produce a second alert. A notice the mail system refuses is answered 503
(the observer retries) and is not recorded as accepted.

Credential: the environment variable OBSERVER_DELIVERY_TOKEN (never an argument, never logged). State: `accepted.jsonl`
in --state-dir, append-only and fsynced (idempotency key, kind, component, time). Standard library only.
"""
import argparse
import hmac
import json
import os
import ssl
import subprocess
import sys
import threading
import time
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KINDS = {"alert": "ALERT", "recovery": "RECOVERED"}


def rfc3339(ns):
    if not ns:
        return "never"
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ns / 1e9)) + " (%d ns)" % ns


class Bridge:
    def __init__(self, token, state_dir, sender, recipient, sendmail):
        self.token, self.sender, self.recipient, self.sendmail = token, sender, recipient, sendmail
        self.path = os.path.join(state_dir, "accepted.jsonl")
        self.lock = threading.Lock()
        self.seen = set()
        if os.path.exists(self.path):
            with open(self.path) as f:
                for line in f:
                    try:
                        self.seen.add(json.loads(line)["key"])
                    except (ValueError, KeyError):
                        pass

    def message(self, key, notice):
        kind, component = notice["kind"], notice["component"]
        msg = EmailMessage()
        msg["From"], msg["To"] = self.sender, self.recipient
        msg["Subject"] = "[Soundpost deadman] %s: %s heartbeat %s" % (KINDS[kind], component, "missing" if kind == "alert" else "is back")
        msg["Auto-Submitted"] = "auto-generated"
        msg["Importance"] = "high" if kind == "alert" else "normal"
        msg["X-Deadman-Idempotency-Key"] = key
        msg["X-Deadman-Observer"] = str(notice.get("observer", ""))
        msg.set_content(
            "External deadman observer %s\n\nNotice:     %s\nComponent:  %s\nOutage:     %s\nLast healthy heartbeat: %s\nMissing detected:       %s\nRecovered:              %s\nIdempotency key: %s\n\n"
            "This message was sent by the observer's own alert route. The Soundpost product is not on this path.\n"
            % (notice.get("observer", ""), KINDS[kind], component, notice.get("outage", ""), rfc3339(notice.get("last_ok_ns", 0)),
               rfc3339(notice.get("detected_ns", 0)), rfc3339(notice.get("recovered_ns", 0)), key))
        return msg

    def accept(self, key, notice):
        """Returns (status, body). The mail system's acceptance comes before the record and before the 2xx."""
        with self.lock:
            if key in self.seen:
                return 200, {"accepted": True, "duplicate": True}
            if notice.get("kind") not in KINDS or not notice.get("component"):
                return 400, {"error": "notice_invalid"}
            msg = self.message(key, notice)
            try:
                done = subprocess.run(self.sendmail, input=msg.as_bytes(), capture_output=True, timeout=30)
            except (OSError, subprocess.SubprocessError):
                return 503, {"error": "mail_unavailable"}
            if done.returncode != 0:
                return 503, {"error": "mail_refused"}
            with open(self.path, "a") as f:
                f.write(json.dumps({"key": key, "kind": notice["kind"], "component": notice["component"], "at": time.time()}) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self.seen.add(key)
            return 200, {"accepted": True, "duplicate": False}


def handler(bridge):
    class H(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # never log headers or bodies
            sys.stdout.write("%s %s\n" % (self.log_date_time_string(), fmt % args))
            sys.stdout.flush()

        def reply(self, status, body):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            got = self.headers.get("Authorization", "")
            if not hmac.compare_digest(got.encode(), ("Bearer " + bridge.token).encode()):
                return self.reply(401, {"error": "unauthorized"})
            key = self.headers.get("Idempotency-Key", "")
            length = int(self.headers.get("Content-Length", "0") or 0)
            if not key or length <= 0 or length > 16384:
                return self.reply(400, {"error": "request_invalid"})
            try:
                notice = json.loads(self.rfile.read(length))
            except ValueError:
                return self.reply(400, {"error": "notice_invalid"})
            if not isinstance(notice, dict):
                return self.reply(400, {"error": "notice_invalid"})
            status, body = bridge.accept(key, notice)
            self.reply(status, body)
            sys.stdout.write("notice %s %s -> %d\n" % (notice.get("kind"), notice.get("component"), status))
            sys.stdout.flush()

    return H


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--listen", required=True, help="host:port")
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--state-dir", required=True)
    p.add_argument("--from", dest="sender", required=True)
    p.add_argument("--to", dest="recipient", required=True)
    p.add_argument("--sendmail", default="/usr/sbin/sendmail -t -i", help="the local mail submission command")
    a = p.parse_args()
    token = os.environ.get("OBSERVER_DELIVERY_TOKEN", "")
    if not token:
        sys.exit("OBSERVER_DELIVERY_TOKEN is required")
    os.makedirs(a.state_dir, mode=0o700, exist_ok=True)
    host, _, port = a.listen.rpartition(":")
    bridge = Bridge(token, a.state_dir, a.sender, a.recipient, a.sendmail.split())
    server = ThreadingHTTPServer((host, int(port)), handler(bridge))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(a.cert, a.key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    sys.stdout.write("alert-mail-bridge listening on %s\n" % a.listen)
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for alert-mail-bridge.py. Run: python3 -m unittest tools/fixtures/deadman/test_alert_mail_bridge.py -v

The HTTP handler is served over plain HTTP on a loopback port (TLS is only the socket wrapper in main()); the mail system
is a stand-in command that stores the message or fails on request.
"""
import email
import http.client
import importlib.util
import json
import os
import sys
import tempfile
import textwrap
import threading
import unittest
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("alert_mail_bridge", os.path.join(HERE, "alert-mail-bridge.py"))
bridge_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge_mod)

TOKEN = "t0ken-for-tests"
ALERT = {"kind": "alert", "component": "cluster-a", "observer": "obs-1", "outage": "out-1",
         "last_ok_ns": 1_700_000_000_000_000_000, "detected_ns": 1_700_000_030_000_000_000}


class BridgeTest(unittest.TestCase):
    def setUp(self):
        real, sys.stdout = sys.stdout, open(os.devnull, "w")  # the handler logs request lines to stdout
        self.addCleanup(lambda: (sys.stdout.close(), setattr(sys, "stdout", real)))
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.mail = os.path.join(self.tmp.name, "mail")
        os.mkdir(self.mail)
        self.fail_flag = os.path.join(self.tmp.name, "fail")
        script = os.path.join(self.tmp.name, "fakemail.py")
        with open(script, "w") as f:
            f.write(textwrap.dedent("""
                import os, sys, uuid
                if os.path.exists(%r):
                    sys.exit(75)
                open(os.path.join(%r, uuid.uuid4().hex), "wb").write(sys.stdin.buffer.read())
            """) % (self.fail_flag, self.mail))
        self.state = os.path.join(self.tmp.name, "state")
        os.mkdir(self.state)
        self.start()

    def start(self):
        self.bridge = bridge_mod.Bridge(TOKEN, self.state, "deadman@example.test", "oncall@example.test", [sys.executable, os.path.join(self.tmp.name, "fakemail.py")])
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), bridge_mod.handler(self.bridge))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def post(self, notice=ALERT, key="k1", token=TOKEN, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=10)
        raw = body if body is not None else json.dumps(notice).encode()
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if key is not None:
            headers["Idempotency-Key"] = key
        c.request("POST", "/", raw, headers)
        r = c.getresponse()
        out = (r.status, json.loads(r.read()))
        c.close()
        return out

    def messages(self):
        out = []
        for n in sorted(os.listdir(self.mail)):
            with open(os.path.join(self.mail, n), "rb") as f:
                out.append(email.message_from_bytes(f.read()))
        return out

    def accepted(self):
        p = os.path.join(self.state, "accepted.jsonl")
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return [json.loads(l) for l in f]

    def test_alert_sends_one_mail_then_records(self):
        status, body = self.post()
        self.assertEqual((status, body), (200, {"accepted": True, "duplicate": False}))
        msgs = self.messages()
        self.assertEqual(len(msgs), 1)
        m = msgs[0]
        self.assertEqual(m["To"], "oncall@example.test")
        self.assertEqual(m["From"], "deadman@example.test")
        self.assertEqual(m["Subject"], "[Soundpost deadman] ALERT: cluster-a heartbeat missing")
        self.assertEqual(m["X-Deadman-Idempotency-Key"], "k1")
        self.assertEqual(m["Importance"], "high")
        self.assertIn("2023-11-14T22:13:20Z", m.get_payload())
        self.assertIn("Recovered:              never", m.get_payload())
        rec = self.accepted()
        self.assertEqual([(r["key"], r["kind"], r["component"]) for r in rec], [("k1", "alert", "cluster-a")])

    def test_recovery_subject_and_never_recovered_time(self):
        n = dict(ALERT, kind="recovery", recovered_ns=1_700_000_090_000_000_000)
        self.assertEqual(self.post(n, key="k2")[0], 200)
        m = self.messages()[0]
        self.assertEqual(m["Subject"], "[Soundpost deadman] RECOVERED: cluster-a heartbeat is back")
        self.assertEqual(m["Importance"], "normal")
        self.assertIn("Recovered:              2023-11-14T22:14:50Z", m.get_payload())

    def test_repeated_key_is_2xx_without_second_mail(self):
        self.assertEqual(self.post()[1]["duplicate"], False)
        status, body = self.post()
        self.assertEqual((status, body), (200, {"accepted": True, "duplicate": True}))
        self.assertEqual(len(self.messages()), 1)
        self.assertEqual(len(self.accepted()), 1)

    def test_dedupe_survives_restart(self):
        self.post()
        self.stop()
        self.start()
        self.assertEqual(self.post()[1]["duplicate"], True)
        self.assertEqual(len(self.messages()), 1)

    def test_wrong_or_missing_credential_is_401_and_sends_nothing(self):
        self.assertEqual(self.post(token="wrong")[0], 401)
        self.assertEqual(self.post(token=None)[0], 401)
        self.assertEqual(self.post(token=TOKEN + "x")[0], 401)
        self.assertEqual(self.messages(), [])
        self.assertEqual(self.accepted(), [])

    def test_mail_refusal_is_503_unrecorded_and_retry_succeeds(self):
        open(self.fail_flag, "w").close()
        status, body = self.post()
        self.assertEqual((status, body), (503, {"error": "mail_refused"}))
        self.assertEqual(self.accepted(), [])
        self.assertEqual(self.messages(), [])
        os.remove(self.fail_flag)
        self.assertEqual(self.post(), (200, {"accepted": True, "duplicate": False}))
        self.assertEqual(len(self.messages()), 1)
        self.assertEqual(len(self.accepted()), 1)

    def test_missing_mail_command_is_503(self):
        self.bridge.sendmail = ["/nonexistent/sendmail-for-test"]
        self.assertEqual(self.post(), (503, {"error": "mail_unavailable"}))
        self.assertEqual(self.accepted(), [])

    def test_invalid_requests_are_400(self):
        self.assertEqual(self.post(key=None)[0], 400)
        self.assertEqual(self.post(body=b"not json")[0], 400)
        self.assertEqual(self.post(body=b"[1]")[0], 400)
        self.assertEqual(self.post(dict(ALERT, kind="other"), key="k3")[0], 400)
        self.assertEqual(self.post({"kind": "alert"}, key="k4")[0], 400)
        self.assertEqual(self.post(body=b"x" * 16385)[0], 400)
        self.assertEqual(self.messages(), [])
        self.assertEqual(self.accepted(), [])

    def test_rfc3339(self):
        self.assertEqual(bridge_mod.rfc3339(0), "never")
        self.assertEqual(bridge_mod.rfc3339(1_700_000_000_000_000_000), "2023-11-14T22:13:20Z (1700000000000000000 ns)")


if __name__ == "__main__":
    unittest.main()

"""Patch 1b of the key swap's Part B: a call waits for this machine's vault broker while it starts again (fleet.py
`broker_wait`, `broker_ready`, `broker_socket`, `vault_call`, and the steps that read the broker's status first).

A broker starts again at each release that changes vault.py and at each change of its configuration (the key swap's
switch, an owner key), and its socket is gone for that moment: for less than 0.4 seconds on a test server (16 November
2026). A call in that moment was refused at once, with words that send the agent to its requester.

Run: python3 test_broker_wait.py"""
import json
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import fleet

STATUS = {"ok": True, "v": 2, "user": "fleet-vault", "callers": True}


class StandIn:
    """A stand-in vault broker on a Unix socket at `path`, made `after` seconds from now. Before that, the path has no
    socket, or (`refuses`) a socket that is bound and does not listen, so that each connection is refused. It answers
    one connection after the other with `answers` in their order: a dict is sent back, and None closes the connection
    with no answer. It keeps each request that it read."""

    def __init__(self, path, answers, after=0.0, refuses=False):
        self.path, self.answers, self.requests, self.ready = str(path), list(answers), [], threading.Event()
        self.thread = threading.Thread(target=self.run, args=(after, refuses), daemon=True)
        self.thread.start()

    def run(self, after, refuses):
        if refuses:
            blocked = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            blocked.bind(self.path)
            time.sleep(after)
            blocked.close()
            os.unlink(self.path)
        else:
            time.sleep(after)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(self.path)
            listener.listen(4)
            listener.settimeout(10)
            self.ready.set()
            while self.answers:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                with conn:
                    data = b""
                    while not data.endswith(b"\n"):
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                    self.requests.append(json.loads(data))
                    answer = self.answers.pop(0)
                    if answer is not None:
                        conn.sendall((json.dumps(answer) + "\n").encode())

    def done(self):
        self.thread.join(10)
        return self.requests


class Wait(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="bw-"))         # short: a Unix socket path has at most 104 bytes
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.path = self.dir / "vault.sock"
        # The stand-in runs as this user. On Linux, vault_call refuses a broker of the caller's own user, so the
        # caller is another user here.
        for p in (patch.object(fleet, "vault_socket", return_value=str(self.path)),
                  patch.object(fleet.os, "getuid", return_value=os.getuid() + 1)):
            p.start()
            self.addCleanup(p.stop)

    def waits(self, seconds):
        return patch.object(fleet, "broker_wait", return_value=seconds)

    def test_a_call_waits_for_a_broker_that_starts_again(self):
        broker = StandIn(self.path, [STATUS], after=0.4)
        began = time.monotonic()
        with self.waits(2.0):
            self.assertEqual(fleet.vault_call({"op": "status"}, timeout=5), STATUS)
        self.assertGreaterEqual(time.monotonic() - began, 0.35)
        self.assertEqual([r["op"] for r in broker.done()], ["status"])          # one request, sent one time

    def test_a_socket_that_refuses_is_tried_again(self):
        broker = StandIn(self.path, [STATUS], after=0.4, refuses=True)
        time.sleep(0.1)
        self.assertTrue(self.path.exists())                         # the socket is there, and it refuses
        with self.waits(2.0):
            self.assertEqual(fleet.vault_call({"op": "status"}, timeout=5), STATUS)
        self.assertEqual([r["op"] for r in broker.done()], ["status"])

    def test_no_broker_is_refused_after_the_wait_with_the_words_of_before(self):
        began = time.monotonic()
        with self.waits(0.3), self.assertRaises(fleet.Refused) as said:
            fleet.vault_call({"op": "status"}, timeout=5)
        self.assertGreaterEqual(time.monotonic() - began, 0.3)
        self.assertLess(time.monotonic() - began, 1.5)
        self.assertEqual(str(said.exception), "this machine's vault broker is not running; ask your requester")

    def test_with_no_wait_a_missing_broker_is_refused_at_once_as_before(self):
        began = time.monotonic()
        with self.waits(0.0), self.assertRaises(fleet.Refused) as said:
            fleet.vault_call({"op": "status"}, timeout=5)
        self.assertEqual(str(said.exception), "this machine's vault broker is not running; ask your requester")
        self.assertLess(time.monotonic() - began, 0.2)

    def test_with_no_wait_a_refused_connection_is_refused_at_once_as_before(self):
        broker = StandIn(self.path, [STATUS], after=0.6, refuses=True)
        time.sleep(0.1)
        with self.waits(0.0), self.assertRaises(fleet.Refused) as said:
            fleet.vault_call({"op": "status"}, timeout=5)
        self.assertEqual(str(said.exception), "this machine's vault broker did not answer; ask your requester")
        broker.ready.wait(5)
        fleet.vault_call({"op": "status"}, timeout=5)               # lets the stand-in end
        broker.done()

    def test_the_machine_report_does_not_wait_for_a_missing_socket(self):
        began = time.monotonic()
        with self.waits(2.0):
            self.assertIsNone(fleet.broker_status())
        self.assertLess(time.monotonic() - began, 0.2)

    def test_a_request_that_reached_the_broker_is_never_sent_again(self):
        broker = StandIn(self.path, [None, STATUS], after=0.2)
        with self.waits(2.0), self.assertRaises(fleet.Unknown):
            fleet.vault_call({"op": "request", "job": 7}, timeout=5)
        self.assertEqual(broker.requests, [{"op": "request", "job": 7, "v": 2}])   # once: the wait is before the send
        fleet.vault_call({"op": "status"}, timeout=5)               # lets the stand-in end
        broker.done()

    def test_broker_ready_finds_a_socket_that_comes_and_says_when_none_comes(self):
        broker = StandIn(self.path, [STATUS], after=0.3)
        with self.waits(2.0):
            self.assertTrue(fleet.broker_ready())
        fleet.vault_call({"op": "status"}, timeout=5)               # lets the stand-in end
        broker.done()
        os.unlink(self.path)
        began = time.monotonic()
        with self.waits(0.3):
            self.assertFalse(fleet.broker_ready())
        self.assertGreaterEqual(time.monotonic() - began, 0.3)

    def test_a_job_waits_for_the_broker_and_goes_with_its_fields(self):
        broker = StandIn(self.path, [STATUS, {"ok": True, "env": {}}], after=0.4)
        with patch.object(fleet, "load_agent_key", return_value="ak-example"), self.waits(2.0):
            self.assertEqual(fleet.broker_job_request("w", {"op": "read", "for": "session"}, timeout=5),
                             {"ok": True, "env": {}})
        self.assertEqual(broker.done(), [
            {"op": "status", "v": 2},
            {"op": "read", "for": "session", "agent": "w", "agent_key": "ak-example", "v": 2}])

    def test_the_wait_is_for_a_linux_machine_whose_broker_is_installed(self):
        for platform, installed, wait in (("linux", True, fleet.BROKER_WAIT), ("linux", False, 0.0),
                                          ("darwin", True, 0.0), ("darwin", False, 0.0)):
            def exists(path, installed=installed):
                return installed and path == fleet.BROKER_PROGRAM
            with patch.object(fleet.sys, "platform", platform), \
                    patch.object(fleet.os.path, "exists", side_effect=exists):
                self.assertEqual(fleet.broker_wait(), wait, (platform, installed))
        self.assertEqual(fleet.BROKER_PROGRAM, "/usr/local/lib/fleet-vault/vault.py")   # hubsetup.py's VAULT_LIB
        self.assertLessEqual(fleet.BROKER_WAIT, 3.0)                # a session's start never waits long for a vault

    def test_each_step_that_reads_the_status_first_waits_and_the_machine_report_does_not(self):
        text = Path(fleet.__file__).read_text(encoding="utf-8")
        self.assertIn("status = broker_status() if key and broker_ready() else None", text)    # broker_job_request
        self.assertEqual(text.count("status = broker_status() if broker_ready() else None"), 2)   # do_save, do_request
        self.assertIn("    status = broker_status()\n    recipient, source", text)          # vault_status: no wait
        self.assertIn("    if not os.path.exists(vault_socket()):\n        return None", text)   # broker_status


if __name__ == "__main__":
    unittest.main()

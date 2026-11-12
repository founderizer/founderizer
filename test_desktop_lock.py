"""The frame of a task's screen goes to its reader after the hub's lock, not inside it (10 November 2026).

`GET /ui/tasks/<id>/desktop` answers the frame that the owner's app shows while the owner watches a task: a JPEG of up
to 1 MiB in base64, so the answer can be 1.4 MB, and the app reads one each second. The write of an answer to its
socket ends only when the kernel has room for all of its bytes, and the kernel gets that room at the pace of the
reader. Until this change the route wrote its answer inside `with LOCK:`, so every other caller of the hub (the
helpers' polls, the agents' tool calls, the tick) waited for one reader's transfer.

Measured on 10 November 2026, with a hub of each tree in one process, a reader of the frame, and a second caller that
asks for the lock again and again while the frame goes out. Each number is that caller's longest wait in one read:

- Linux 6.10 (in a container on the owner's Mac; the hub runs Linux), with a round trip of 60 ms, as the owner's Mac
  has to the first fleet's hub, and the segment size of a Tailscale path, the median of 5 reads: 0.18 s for a frame
  of 100 KB, 0.19 s for 200 KB, 0.25 s for 400 KB and 0.34 s for 1 MiB (0.52 s in the worst read). After the change:
  0.001 s (0.004 s in the worst read).
- macOS, loopback, a frame of 1 MiB, and a reader that read nothing for 2 seconds: 2.0 s before, 0.002 s after.

The two routes of a frame (the owner's read, and the worker's `GET` and `POST /helper/desktop/<agent>/T-<id>`) now
make their answer inside the lock and send it after it. Each answer is what it was, with the headers that it had.
Outside the lock the owner's frame also goes compressed to a client that asks (test_gzip_answers).

The hub runs in this process on 127.0.0.1 and a port of its own, with a clock that stands still, so no frame gets old
during a test. Its frames (Watched) record each use that comes while the thread does not hold the lock. In the first
test the hub's end of each connection has a send buffer that holds no frame, as a real path has for a new connection,
so the write of a frame is under way until its reader reads; and a newer frame comes between the lock and the making
of the answer, which keeps the frame of its moment. The second test needs no such buffer: at each answer of the two
routes it records if the thread holds the lock.

    python3 -m unittest -v test_desktop_lock
"""
import base64
import hashlib
import http.client
import json
import socket
import sys
import threading
import time
import unittest
import urllib.parse
from unittest.mock import patch

import desktop
import hub
import test_ui_api          # by its name: `from test_ui_api import OwnerAPI` would run that class's own tests here too

GENERATION, WORKER, PATIENCE = "test-generation", "127.0.0.3", test_ui_api.PATIENCE
PLAIN = ["Server", "Date", "Content-Type", "Content-Length"]       # the header names of every JSON answer
STOPPED, STALE = "Desktop viewing is stopped for this task.", \
    "STOP: stale or wrong task attempt. Do not report, deliver, or continue work."


def jpeg(size, start=0):
    """`size` bytes that the hub takes as a JPEG, with the disorder of a real picture. start: another picture."""
    filling = b"".join(hashlib.sha256((start + n).to_bytes(8, "big")).digest() for n in range(size // 32 + 1))
    return b"\xff\xd8\xff" + filling[:size - 5] + b"\xff\xd9"


class Watched(desktop.Frames):
    """desktop.Frames, with a record of each use of its rows while the thread does not hold the hub's lock: the name of
    the function of hub.py that used them. The rows are a plain dict that view, put, prune and drop change, so every
    use of them is inside the lock, and the record stays empty."""
    outside = None          # the record starts after __init__, whose first rows no other thread can see

    def __init__(self):
        super().__init__()
        self.outside = []

    @property
    def rows(self):
        self.note()
        return self.__dict__["rows"]

    @rows.setter
    def rows(self, value):
        self.note()
        self.__dict__["rows"] = value

    def note(self):
        if self.outside is not None and not hub.LOCK._is_owned():
            caller = sys._getframe(2)
            while caller and caller.f_code.co_filename != hub.__file__:
                caller = caller.f_back
            self.outside.append(caller.f_code.co_name if caller else "a caller outside hub.py")


class Frames(unittest.TestCase):
    """The hub of test_ui_api with one screen task of an agent on a machine of its own, which the owner watches."""
    connect, request = test_ui_api.OwnerAPI.connect, test_ui_api.OwnerAPI.request
    tearDown = test_ui_api.OwnerAPI.tearDown

    def setUp(self):
        test_ui_api.OwnerAPI.setUp(self)
        for change in (patch.object(hub, "now", return_value=time.time()), patch.object(hub, "DESKTOP", Watched())):
            change.start()
            self.addCleanup(change.stop)
        hub.TEAM["addresses"]["studio"] = WORKER
        hub.TEAM["agents"]["studio"] = dict(role="worker", runtime="claude", machine="studio", can=["screen"])
        self.task = hub.ins("INSERT INTO tasks(title,owner,state,needs,attempt) "
                            "VALUES('Watch','studio','working','screen',1)")
        self.context = dict(generation=GENERATION, attempt=1)
        self.view = f"/ui/tasks/{self.task}/desktop?db={GENERATION}&attempt=1"
        self.worker = f"/helper/desktop/studio/T-{self.task}"
        self.asks = self.worker + "?" + urllib.parse.urlencode(self.context)

    def frame(self, size, start=0):
        return dict(status="live", image=base64.b64encode(jpeg(size, start)).decode(), captured_at=hub.now())

    def ask(self, path, body=None, source=None, **headers):
        """(status, the header names in their order, the headers, the body's bytes) of one request that carries
        exactly these headers. body: the JSON of a POST. source: the caller's address (test_ui_api.SourceHandler)."""
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=PATIENCE)
        try:
            conn.putrequest("GET" if body is None else "POST", path, skip_accept_encoding=True)
            data = None if body is None else json.dumps(body).encode()
            if data is not None:
                headers.update({"Content-Type": "application/json", "Content-Length": str(len(data))})
            if source:
                headers["X-Test-Source"] = source
            for name, value in headers.items():
                conn.putheader(name.replace("_", "-"), value)
            conn.endheaders(data)
            answer = conn.getresponse()
            raw, given = answer.read(), answer.getheaders()
            return answer.status, [name for name, _ in given], dict(given), raw
        finally:
            conn.close()

    def test_the_hub_serves_its_other_callers_while_a_reader_has_not_read_its_frame(self):
        self.assertEqual(self.request(self.view)[1]["status"], "waiting")           # the owner's look opens the lease
        first, second = self.frame(desktop.MAX_FRAME), self.frame(desktop.MAX_FRAME, start=1 << 20)
        newer = self.frame(desktop.MAX_FRAME, start=3 << 20)
        self.assertEqual(self.request(self.worker, dict(self.context, frame=first), source=WORKER),
                         (200, {"watching": True}))
        writing, written, failed, newer_put = threading.Event(), threading.Event(), [], []
        send, answer, setup = hub.Handler.send, hub.Handler.json, hub.Handler.setup

        def small_buffer(handler):
            handler.request.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
            setup(handler)

        def fresher(handler, code, obj, headers=None):
            """The worker's next frame, between the route's lock and the making of its answer's bytes."""
            if code == 200 and handler.path == self.view and not newer_put:
                with hub.LOCK:
                    newer_put.append(hub.DESKTOP.put((GENERATION, self.task, 1), newer, hub.now()))
            return answer(handler, code, obj, headers)

        def marked(handler, code, *args, **kwargs):
            frame = code == 200 and handler.path == self.view
            if frame:
                writing.set()
            try:
                return send(handler, code, *args, **kwargs)
            except BaseException as e:
                if frame:
                    failed.append(e)
                raise
            finally:
                if frame:
                    written.set()

        reader = socket.socket()
        try:
            with patch.object(hub.Handler, "setup", small_buffer), patch.object(hub.Handler, "send", marked), \
                    patch.object(hub.Handler, "json", fresher):
                reader.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
                reader.settimeout(PATIENCE)
                reader.connect(("127.0.0.1", self.server.server_port))
                reader.sendall(f"GET {self.view} HTTP/1.1\r\nHost: 127.0.0.1:{self.server.server_port}\r\n"
                               f"Connection: close\r\n\r\n".encode())
                self.assertTrue(writing.wait(PATIENCE), "the hub did not start to send the frame")
                self.assertFalse(written.wait(0.3), f"the write of the frame failed: {failed[0]!r}" if failed else
                                 "the kernel took the whole frame at once, so this test shows nothing: it needs a "
                                 "larger frame or smaller buffers")
                # The reader has read nothing, and the hub's write of its frame is under way. The lock is free:
                taken = hub.LOCK.acquire(timeout=PATIENCE)
                if taken:
                    hub.LOCK.release()
                self.assertTrue(taken, "the hub held its lock while the reader of a frame had read nothing")
                # and the hub serves its other callers, each of which needs the lock: the worker asks if somebody
                # watches and sends its next frame, and the owner reads that frame on another connection.
                self.assertEqual(self.request(self.asks, source=WORKER), (200, {"watching": True}))
                self.assertEqual(self.request(self.worker, dict(self.context, frame=second), source=WORKER),
                                 (200, {"watching": True}))
                self.assertFalse(written.is_set())                  # all of that while the first read is under way
                data = b""
                while True:
                    part = reader.recv(1 << 16)
                    if not part:
                        break
                    data += part
                self.assertTrue(written.wait(PATIENCE))
        finally:
            reader.close()              # before tearDown, which waits for every request to end
        head, _, body = data.partition(b"\r\n\r\n")
        self.assertEqual(head.split(b"\r\n")[0], b"HTTP/1.1 200 OK")
        self.assertIn(f"Content-Length: {len(body)}".encode(), head.split(b"\r\n"))
        # The reader gets the frame that the hub held when its read came, whole, and not the ones that came after.
        self.assertEqual(newer_put, [True])
        self.assertEqual(json.loads(body), dict(db=GENERATION, task=self.task, attempt=1, **first))
        self.assertEqual(self.request(self.view)[1]["image"], second["image"])
        self.assertEqual(hub.DESKTOP.outside, [], "the hub used its frames outside its lock")

    def test_each_answer_of_the_two_routes_is_sent_outside_the_lock_and_is_what_it_was(self):
        sent, send = [], hub.Handler.send

        def recorded(handler, code, *args, **kwargs):
            if "/desktop" in handler.path:
                sent.append((handler.command, handler.path.split("/")[1], code, hub.LOCK._is_owned()))
            return send(handler, code, *args, **kwargs)

        def said(answer):
            return answer[0], answer[1], json.loads(answer[3])

        shown, wrong = self.frame(20000), dict(self.frame(20000), image="not a JPEG")
        with patch.object(hub.Handler, "send", recorded):
            # The owner's read, with the two headers of its route.
            waiting = self.ask(self.view)
            self.assertEqual(said(waiting), (200, PLAIN + ["Cache-Control", "X-Content-Type-Options"], dict(
                db=GENERATION, task=self.task, attempt=1, status="waiting", image=None, captured_at=None)))
            self.assertEqual((waiting[2]["Cache-Control"], waiting[2]["X-Content-Type-Options"]),
                             ("no-store", "nosniff"))
            # The worker's question and its frame, with the one header of their route.
            for answer in (self.ask(self.asks, source=WORKER),
                           self.ask(self.worker, dict(self.context, frame=shown), source=WORKER)):
                self.assertEqual(said(answer), (200, PLAIN + ["Cache-Control"], {"watching": True}))
                self.assertEqual(answer[2]["Cache-Control"], "no-store")
            live = self.ask(self.view)
            self.assertEqual(said(live), (200, PLAIN + ["Cache-Control", "X-Content-Type-Options"],
                                          dict(db=GENERATION, task=self.task, attempt=1, **shown)))
            self.assertEqual((live[2]["Cache-Control"], live[2]["X-Content-Type-Options"]), ("no-store", "nosniff"))
            # Each refusal, with no header of its own.
            for answer, refusal in (
                    (self.ask(self.worker, dict(self.context, frame=wrong), source=WORKER),
                     (400, "invalid desktop frame")),
                    (self.ask(self.worker, dict(self.context, attempt=2, frame=shown), source=WORKER), (409, STALE)),
                    (self.ask(self.view.replace(GENERATION, "another"), ), (409, STALE)),
                    (self.ask(f"/helper/desktop/studio/T-{self.task + 1}?" + urllib.parse.urlencode(self.context),
                              source=WORKER), (409, "No such task."))):
                self.assertEqual(said(answer), (refusal[0], PLAIN, {"error": refusal[1]}))
            self.assertEqual(self.ask(self.asks, source="127.0.0.4")[0], 403)           # not the worker's machine
            self.assertEqual(json.loads(self.ask(self.view)[3])["image"], shown["image"])   # no refusal took the frame
            hub.q("UPDATE tasks SET state='completed' WHERE id=?", (self.task,))
            for answer in (self.ask(self.view), self.ask(self.worker, dict(self.context, frame=shown), source=WORKER)):
                self.assertEqual(said(answer), (409, PLAIN, {"error": STOPPED}))
            with hub.LOCK:
                self.assertEqual(hub.DESKTOP.rows, {})
        self.assertEqual([(method, route, code) for method, route, code, _ in sent], [
            ("GET", "ui", 200), ("GET", "helper", 200), ("POST", "helper", 200), ("GET", "ui", 200),
            ("POST", "helper", 400), ("POST", "helper", 409), ("GET", "ui", 409), ("GET", "helper", 409),
            ("GET", "helper", 403), ("GET", "ui", 200), ("GET", "ui", 409), ("POST", "helper", 409)])
        self.assertEqual([answer[:3] for answer in sent if answer[3]], [], "an answer was sent inside the hub's lock")
        self.assertEqual(hub.DESKTOP.outside, [], "the hub used its frames outside its lock")


if __name__ == "__main__":
    unittest.main()

"""Each answer of the hub leaves the socket in ONE write, with the same bytes as before (10 November 2026).

`Handler.send` wrote the head with end_headers() and then the body: two writes to the socket. The head left alone in a
small packet, and the kernel held the last packet of the body that was not full until the client had acknowledged that
small packet (Nagle's rule with Minshall's change). So each answer on a kept connection took one round trip more. From
the owner's Mac, at a round trip of 56 ms, the body of a 409 of 50 bytes came 0.056 s after its head. Now
`Handler.head_and_body_out` gives the kernel the head and the body in one sendmsg.

The measure of "the same bytes" is `old_send` below: Handler.send as it was, word for word. The hub runs in this process
on 127.0.0.1 and a port of its own, with a clock that stands still (test_gzip_answers.Answers) and one Date for every
answer. Each socket that the hub accepts is wrapped, so the test sees each write that reaches it. A handler with no
server and a socket of the test's own shows what a single call cannot show: a kernel that takes only a part.

    python3 -m unittest -v test_answer_write
"""
import http.client
import json
import socket
import socketserver
import threading
import unittest
from unittest.mock import patch

import hub
from test_gzip_answers import ASKS, Answers
from test_ui_api import quick

DATE = "Tue, 10 Nov 2026 19:00:00 GMT"


def old_send(self, code, body=b"", ctype="application/json", headers=None):
    """Handler.send before this change (hub.py at 0e6c93d7), word for word."""
    if isinstance(body, str):
        body = body.encode()
    self.answered = True            # this request has its answer (gone)
    self.send_response(code)
    self.send_header("Content-Type", ctype)
    self.send_header("Content-Length", str(len(body)))
    for k, v in (headers or {}).items():
        self.send_header(k, v)
    self.end_headers()
    if body and self.command != "HEAD":
        self.wfile.write(body)


class Seen:
    """An accepted socket of the hub, and each write that reaches it, in order: (call, the bytes that it sent). The lock
    is the test's too: a client that has read the whole answer takes it, and then each write of that answer is in the
    list, also the last one, whose bytes the client can have before its call returns."""

    def __init__(self, sock, writes, lock):
        self.sock, self.writes, self.lock = sock, writes, lock

    def sendall(self, data, *flags):
        with self.lock:
            self.sock.sendall(data, *flags)
            self.writes.append(("sendall", bytes(data)))

    def send(self, data, *flags):
        with self.lock:
            sent = self.sock.send(data, *flags)
            self.writes.append(("send", bytes(data)[:sent]))
        return sent

    def sendmsg(self, buffers, *rest):
        with self.lock:
            sent = self.sock.sendmsg(buffers, *rest)
            self.writes.append(("sendmsg", b"".join(buffers)[:sent]))
        return sent

    def __getattr__(self, name):
        return getattr(self.sock, name)


class Writes(Answers):
    """The hub of test_gzip_answers, and the writes of each connection that it accepts."""

    def setUp(self):
        super().setUp()
        quick(hub.DB)
        self.lock, self.connections = threading.Lock(), []

        def setup(handler, real=socketserver.StreamRequestHandler.setup):
            writes = []
            with self.lock:
                self.connections.append(writes)
            handler.request = Seen(handler.request, writes, self.lock)
            real(handler)

        for name, value in (("setup", setup), ("date_time_string", lambda handler, timestamp=None: DATE)):
            stand_in = patch.object(hub.Handler, name, value)
            stand_in.start()
            self.addCleanup(stand_in.stop)

    def writes(self):
        """The writes of the last connection, after its client has read what it waits for."""
        with self.lock:
            return list(self.connections[-1])

    def written(self, *request, old=False, **options):
        """(status, the writes that reached the socket) of one request on its own connection; old: with old_send."""
        if old:
            with patch.object(hub.Handler, "send", old_send):
                return self.written(*request, **options)
        status = self.read(*request, **options)[0]
        return status, self.writes()

    def same(self, *request, **options):
        """The writes of one request with the old send and with this one: the same bytes, and now one write."""
        before, old = self.written(*request, old=True, **options)
        after, new = self.written(*request, **options)
        self.assertEqual(before, after, request)
        self.assertEqual([call for call, _ in old], ["sendall"] * len(old), request)
        self.assertEqual(len(new), 1, request)
        self.assertEqual(new[0][1], b"".join(data for _, data in old), request)
        return before, old, new[0][1]


class OneWrite(Writes):
    def test_a_small_answer_is_one_write_and_the_same_bytes(self):
        status, old, data = self.same("/ui/triggers")
        self.assertEqual(status, 200)
        self.assertEqual(len(old), 2)                   # the head, and then the body: the round trip more
        head, body = data.split(b"\r\n\r\n", 1)
        self.assertEqual(old[0][1], head + b"\r\n\r\n")
        self.assertEqual(json.loads(body), {"db": None, "triggers": []})
        self.assertIn(b"\r\nDate: " + DATE.encode() + b"\r\n", head)

    def test_a_refusal_and_an_answer_with_no_body_are_one_write(self):
        status, old, data = self.same("/ui/nothing")
        self.assertEqual((status, len(old)), (404, 2))
        with patch.object(hub.Handler, "ui_state", lambda handler: handler.send(204)):
            status, old, data = self.same("/ui/state")
        self.assertEqual((status, len(old)), (204, 1))
        self.assertTrue(data.endswith(b"Content-Length: 0\r\n\r\n"))

    def test_a_large_answer_is_one_write_and_the_same_bytes(self):
        self.fill()
        status, old, data = self.same("/ui/state")
        self.assertEqual((status, len(old)), (200, 2))
        self.assertGreater(len(data), hub.GZIP_MIN)
        said = {"rows": ["the same few words"] * 100000}          # 2 MB, more than a socket's buffer takes at once
        with patch.object(hub.Handler, "ui_state", lambda handler: handler.json(200, said)):
            status, old, data = self.same("/ui/state")
        self.assertEqual((status, len(old)), (200, 2))
        self.assertEqual(json.loads(data.split(b"\r\n\r\n", 1)[1]), said)
        self.assertGreater(len(data), 2000000)

    def test_a_compressed_answer_is_one_write_and_the_same_bytes(self):
        self.fill()
        status, old, data = self.same("/ui/state", ASKS)
        self.assertEqual((status, len(old)), (200, 2))
        self.assertIn(b"\r\nContent-Encoding: gzip\r\nVary: Accept-Encoding\r\n\r\n\x1f\x8b", data)

    def test_a_head_is_one_write_and_the_same_bytes(self):
        self.fill()
        status, old, data = self.same("/ui/state", ASKS, method="HEAD")
        self.assertEqual((status, len(old)), (200, 1))
        self.assertTrue(data.endswith(b"\r\n\r\n"))
        self.assertNotIn(b"Content-Encoding", data)
        plain = self.read("/ui/state")[1]
        self.assertIn(b"\r\nContent-Length: %d\r\n" % len(plain), data)

    def test_text_a_post_and_a_421_are_one_write_and_the_same_bytes(self):
        self.fill()
        self.assertEqual(self.same("/board.txt")[0], 200)
        said = {"rows": ["the same few words"] * 2000}
        with patch.object(hub.Handler, "post", lambda handler: handler.json(200, said)):
            self.assertEqual(self.same("/ui/any/command", ASKS, method="POST", body=b"{}")[0], 200)

        def wrong_host(path):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            try:
                conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
                conn.putheader("Host", "evil.example:8765")
                conn.endheaders()
                return conn.getresponse().status
            finally:
                conn.close()

        for send in (old_send, hub.Handler.send):
            with patch.object(hub.Handler, "send", send):
                self.assertEqual(wrong_host("/ui/state"), 421)
            self.assertEqual(len(self.writes()), 1)
        self.assertEqual(self.connections[-2][0][1], self.connections[-1][0][1])
        self.assertIn(b"\r\nConnection: close\r\n\r\n", self.connections[-1][0][1])

    def test_a_kept_connection_gets_one_write_for_each_answer(self):
        self.fill()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.addCleanup(conn.close)
        asked = [("/ui/triggers", None, "GET"), ("/ui/state", None, "GET"), ("/ui/state", ASKS, "GET"),
                 ("/ui/state", ASKS, "HEAD"), ("/ui/nothing", None, "GET"), ("/ui/triggers", ASKS, "GET")]
        for n, (path, accept, method) in enumerate(asked, 1):
            status, body, _, headers = self.read(path, accept, method=method, conn=conn)
            writes = self.writes()
            self.assertEqual(len(writes), n, path)
            head, _, rest = writes[-1][1].partition(b"\r\n\r\n")
            self.assertTrue(head.startswith(b"HTTP/1.1 %d " % status), path)
            self.assertEqual(rest, body, path)                     # the whole answer, and nothing of the next
            if method == "GET":
                self.assertEqual(int(headers["Content-Length"]), len(body), path)
        self.assertEqual(len(self.connections), 1)

    def test_a_request_of_http_0_9_gets_its_body_alone_as_before(self):
        """No status line and no head, as http.server answers that version: the same write as before."""
        answers = []
        for send in (old_send, hub.Handler.send):
            with patch.object(hub.Handler, "send", send), \
                    socket.create_connection(("127.0.0.1", self.port), timeout=10) as raw:
                raw.sendall(b"GET /ui/triggers\r\nHost: 127.0.0.1:%d\r\n\r\n" % self.port)
                got = b""
                while True:
                    part = raw.recv(65536)
                    if not part:
                        break
                    got += part
            answers.append((got, self.writes()))
        (old, old_writes), (new, new_writes) = answers
        self.assertEqual(old, new)
        self.assertEqual(json.loads(new), {"db": None, "triggers": []})
        self.assertEqual(old_writes, [("sendall", new)])
        self.assertEqual([data for _, data in new_writes], [new])


class Bare(unittest.TestCase):
    """Handler.send with no server: a socket of the test's own, which can take a part of each call."""

    class Part:
        """A socket whose kernel takes at most `most` bytes of each call (all of it when most is None). It refuses
        more bytes than the answer has, so a loop that sends a part again fails and does not run on."""

        def __init__(self, most=None, size=None):
            self.most, self.size, self.calls, self.data = most, size, [], b""

        def sendmsg(self, buffers):
            self.calls.append([b.obj for b in buffers])
            whole = b"".join(buffers)
            sent = len(whole) if self.most is None else min(self.most, len(whole))
            if self.size is not None and len(self.data) + sent > self.size:
                raise AssertionError(f"more than the {self.size} bytes of the answer")
            self.data += whole[:sent]
            return sent

    class File:
        def __init__(self):
            self.data = b""

        def write(self, data):
            self.data += data
            return len(data)

    def handler(self, version="HTTP/1.1", command="GET"):
        handler = hub.Handler.__new__(hub.Handler)
        handler.request_version, handler.command = version, command
        handler.requestline = f"{command} /ui/state {version}"
        handler.connection, handler.wfile = self.Part(), self.File()
        return handler

    def answers(self, code, body, version="HTTP/1.1", command="GET", most=None, **options):
        """(the bytes of old_send, the bytes of send, the calls of send) for one answer."""
        with patch.object(hub.Handler, "date_time_string", lambda handler, timestamp=None: DATE):
            old = self.handler(version, command)
            old_send(old, code, body, **options)
            new = self.handler(version, command)
            new.connection.most, new.connection.size = most, len(old.wfile.data)
            new.send(code, body, **options)
        self.assertEqual(new.wfile.data, b"")
        return old.wfile.data, new.connection.data, new.connection.calls

    def test_each_size_gives_the_same_bytes(self):
        for size in (0, 1, 50, 1000, 1227, 1228, 1229, 65536, 2000000):
            body = bytes(n % 251 for n in range(size))
            old, new, calls = self.answers(200, body)
            self.assertEqual(new, old, size)
            self.assertEqual(len(calls), 1, size)

    def test_a_part_that_the_kernel_did_not_take_goes_in_the_next_call(self):
        body = json.dumps({"rows": ["the same few words"] * 50}).encode()
        whole = self.answers(200, body)[0]
        head = len(whole) - len(body)
        for most in (1, 7, head - 1, head, head + 1, len(whole) - 1, len(whole)):
            old, new, calls = self.answers(200, body, most=most)
            self.assertEqual(new, old, most)
            self.assertEqual(len(calls), -(-len(whole) // most), most)

    def test_the_body_goes_to_the_kernel_with_no_copy(self):
        body = b"x" * 3000000
        _, new, calls = self.answers(200, body, ctype="application/zip", headers={"Cache-Control": "no-store"})
        self.assertEqual(len(calls), 1)
        self.assertIs(calls[0][1], body)
        self.assertTrue(new.endswith(b"\r\nCache-Control: no-store\r\n\r\n" + body))

    def test_a_head_a_text_and_each_version_give_the_same_bytes(self):
        body = '{"error": "the same few words"}'
        for version, command in (("HTTP/1.1", "HEAD"), ("HTTP/1.0", "GET"), ("HTTP/1.0", "HEAD"), ("HTTP/1.1", "POST")):
            old, new, calls = self.answers(409, body, version, command)
            self.assertEqual((new, len(calls)), (old, 1), (version, command))
        old, new, _ = self.answers(200, "Fleet: the same words\n", ctype="text/plain; charset=utf-8")
        self.assertEqual(new, old)
        self.assertTrue(new.endswith(b"\r\n\r\nFleet: the same words\n"))

    def test_http_0_9_gets_the_body_alone_and_an_empty_answer_writes_nothing(self):
        old, new, calls = self.answers(200, b'{"db": null}', version="HTTP/0.9")
        self.assertEqual((old, new, len(calls)), (b'{"db": null}', b'{"db": null}', 1))
        old, new, calls = self.answers(421, b"", version="HTTP/0.9", headers={"Connection": "close"})
        self.assertEqual((old, new, calls), (b"", b"", []))


if __name__ == "__main__":
    unittest.main()

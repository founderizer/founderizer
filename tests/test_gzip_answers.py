"""A large answer of the owner API goes gzip-compressed to a client that asks, and every other answer stays as it was
(10 November 2026).

The apps read the whole state every 3 seconds. On the first fleet that answer was 1.4 MB with no compression, and its
transfer was half of each read. So `Handler.json` compresses a 200 of the owner API (`/ui/...`) that has more than
`GZIP_MIN` bytes, for a client whose `Accept-Encoding` names gzip. A client that does not ask, a small answer, an
answer that is not 200, a `HEAD`, an answer that a route writes while it holds the hub's lock, and every route outside
the owner API read what they always read.

The hub runs in this process on 127.0.0.1 and a port of its own. Every request goes over a real socket with exactly
the headers that the test names: no client library adds an `Accept-Encoding` of its own or decodes an answer.

    python3 -m unittest -v test_gzip_answers
"""
import base64
import gzip
import hashlib
import http.client
import json
import unittest
import urllib.request
from unittest.mock import patch

import desktop
import hub
from test_host_origin import LocalHub

ASKS = "gzip, deflate, br"          # what URLSession sends by itself
PLAIN = ["Server", "Date", "Content-Type", "Content-Length"]       # the header names of an answer before this change


class Answers(LocalHub):
    """The hub of test_host_origin, with a clock that stands still, so two reads of the state are the same bytes."""

    def setUp(self):
        super().setUp()
        clock = patch.object(hub, "now", return_value=1794322671.5)
        clock.start()
        self.addCleanup(clock.stop)

    def fill(self, notes=60):
        """Enough notes for a state that is larger than GZIP_MIN."""
        with hub.LOCK:
            for n in range(notes):
                hub.DB.execute("INSERT INTO notes(task,agent,ts,text) VALUES(?,?,?,?)",
                               (None, "manager", 1.0 + n, f"note {n}: " + "the same few words " * 12))
            hub.commit()

    def read(self, path, accept=None, method="GET", body=None, conn=None):
        """(status, body bytes, header names in their order, headers) of one request. accept: its Accept-Encoding
        lines (a string for one line, a list for more); None sends none."""
        own = conn is None
        conn = conn or http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", f"127.0.0.1:{self.port}")
            if body is not None:
                conn.putheader("Content-Type", "application/json")
                conn.putheader("Content-Length", str(len(body)))
            for line in [accept] if isinstance(accept, str) else accept or []:
                conn.putheader("Accept-Encoding", line)
            conn.endheaders(body)
            answer = conn.getresponse()
            data, headers = answer.read(), answer.getheaders()
            return answer.status, data, [name for name, _ in headers], dict(headers)
        finally:
            if own:
                conn.close()

    def plain_state(self):
        status, body, names, headers = self.read("/ui/state")
        self.assertEqual((status, names, headers["Content-Length"]), (200, PLAIN, str(len(body))))
        return body


class OwnerAnswers(Answers):
    def test_a_large_state_goes_compressed_to_a_client_that_asks(self):
        self.fill()
        plain = self.plain_state()
        self.assertGreater(len(plain), hub.GZIP_MIN)
        status, packed, names, headers = self.read("/ui/state", ASKS)
        self.assertEqual(status, 200)
        self.assertEqual(names, PLAIN + ["Content-Encoding", "Vary"])
        self.assertEqual((headers["Content-Type"], headers["Content-Encoding"], headers["Vary"]),
                         ("application/json", "gzip", "Accept-Encoding"))
        self.assertEqual(headers["Content-Length"], str(len(packed)))
        self.assertLess(len(packed), len(plain) // 2)
        self.assertEqual(gzip.decompress(packed), plain)                # the same JSON, byte for byte
        self.assertEqual(json.loads(gzip.decompress(packed))["notes"][59], json.loads(plain)["notes"][59])

    def test_the_same_state_gives_the_same_bytes_with_no_time_in_them(self):
        self.fill()
        first, second = self.read("/ui/state", "gzip")[1], self.read("/ui/state", "gzip")[1]
        self.assertEqual(first, second)
        self.assertEqual(first[:4], b"\x1f\x8b\x08\x00")                 # gzip, deflate, no name and no comment
        self.assertEqual(first[4:8], b"\x00\x00\x00\x00")               # no time of the hub's clock in the header

    def test_each_form_that_names_gzip_gets_the_compressed_answer(self):
        self.fill()
        plain = self.plain_state()
        for accept in ("gzip", "GZip", "gzip, deflate", "deflate, gzip", "br;q=1.0, gzip;q=0.8, *;q=0.1", "gzip;q=1",
                       "gzip; q=0.001", "gzip ;\tQ=1.000", "identity;q=0.5, gzip;q=1.0", ["deflate", "gzip"],
                       ["identity", "br, gzip;q=0.5"]):
            status, packed, _, headers = self.read("/ui/state", accept)
            self.assertEqual((status, headers.get("Content-Encoding")), (200, "gzip"), accept)
            self.assertEqual(gzip.decompress(packed), plain, accept)

    def test_a_client_that_does_not_ask_reads_what_it_always_read(self):
        """No Accept-Encoding, `identity`, another coding, a quality of zero, and each form that the grammar of the
        standard does not allow."""
        self.fill()
        plain = self.plain_state()
        for accept in (None, "", "identity", "deflate, br", "gzip;q=0", "gzip;q=0.0", "gzip;q=0.000", "*", "*;q=1",
                       "x-gzip", "gzipped", "gzip2", "not gzip", "gzip;q=", "gzip;q=high", "gzip;q=2", "gzip;q=1.5",
                       "gzip;q=0.1234", "gzip;level=1", "gzip;q=-1", "gzip; q = 1", "gzip;q =1", "gzip;q= 1",
                       ["identity", "deflate"], "gzip;q=0, gzip"):        # the first mention decides
            status, body, names, headers = self.read("/ui/state", accept)
            self.assertEqual((status, names), (200, PLAIN), accept)
            self.assertEqual((body, headers["Content-Length"]), (plain, str(len(plain))), accept)

    def test_urllib_and_owner_mcp_read_the_large_state_as_before(self):
        """urllib and http.client send `Accept-Encoding: identity` by themselves, and neither decodes gzip. The
        helpers, owner_mcp.py and the checks all use them."""
        import owner_mcp
        self.fill()
        plain, base, asked, real = self.plain_state(), f"http://127.0.0.1:{self.port}", [], hub.accepts_gzip
        with patch.object(hub, "accepts_gzip", side_effect=lambda lines: asked.append(lines) or real(lines)):
            with urllib.request.urlopen(base + "/ui/state", timeout=10) as answer:
                self.assertEqual((answer.status, answer.headers.get("Content-Encoding"), answer.read()),
                                 (200, None, plain))
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            self.addCleanup(conn.close)
            conn.request("GET", "/ui/state")
            answer = conn.getresponse()
            self.assertEqual((answer.status, answer.getheader("Content-Encoding"), answer.read()), (200, None, plain))
            answer = owner_mcp.call("GET", "/ui/state", base=base)
            self.assertEqual((answer.status, answer.data), (200, json.loads(plain)))
        self.assertEqual(asked, [["identity"]] * 3)

    def test_a_small_answer_is_not_compressed(self):
        status, body, names, _ = self.read("/ui/state", ASKS)
        self.assertEqual((status, names), (200, PLAIN))
        self.assertLessEqual(len(body), hub.GZIP_MIN)
        self.assertEqual(json.loads(body)["schema_version"], 1)

    def test_the_limit_is_more_than_gzip_min_bytes(self):
        size = len(self.plain_state())
        with patch.object(hub, "GZIP_MIN", size):
            self.assertEqual(self.read("/ui/state", ASKS)[2], PLAIN)
        with patch.object(hub, "GZIP_MIN", size - 1):
            self.assertEqual(self.read("/ui/state", ASKS)[3].get("Content-Encoding"), "gzip")

    def test_an_answer_that_would_grow_stays_as_it_is(self):
        """The gzip header and trailer are 18 bytes, so a very small answer would grow, whatever the limit says."""
        with patch.object(hub, "GZIP_MIN", 0):
            status, body, names, headers = self.read("/ui/triggers", ASKS)
        self.assertEqual((status, json.loads(body)), (200, {"db": None, "triggers": []}))
        self.assertEqual(names, PLAIN + ["Cache-Control"])
        self.assertGreater(len(hub.gzip_body(body)), len(body))

    def test_a_compressed_answer_keeps_the_headers_of_its_route(self):
        plain = self.read("/ui/machines")
        self.assertEqual((plain[0], plain[2]), (200, PLAIN + ["Cache-Control"]))
        with patch.object(hub, "GZIP_MIN", 200):
            status, packed, names, headers = self.read("/ui/machines", ASKS)
        self.assertEqual((status, names), (200, PLAIN + ["Cache-Control", "Content-Encoding", "Vary"]))
        self.assertEqual((headers["Cache-Control"], headers["Content-Encoding"]), ("no-store", "gzip"))
        self.assertEqual(gzip.decompress(packed), plain[1])

    def test_a_head_reads_the_headers_of_the_plain_answer_and_no_body(self):
        self.fill()
        plain = self.plain_state()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.addCleanup(conn.close)
        status, body, names, headers = self.read("/ui/state", ASKS, method="HEAD", conn=conn)
        self.assertEqual((status, body, names), (200, b"", PLAIN))
        self.assertEqual(headers["Content-Length"], str(len(plain)))
        # The same connection reads the next answer whole: the HEAD left no byte of a body on it.
        status, packed, _, headers = self.read("/ui/state", ASKS, conn=conn)
        self.assertEqual((status, headers["Content-Encoding"], gzip.decompress(packed)), (200, "gzip", plain))

    def test_a_kept_connection_reads_a_compressed_and_then_a_plain_answer(self):
        self.fill()
        plain = self.plain_state()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.addCleanup(conn.close)
        for accept in (ASKS, None, "gzip", "identity", ASKS):
            status, body, _, headers = self.read("/ui/state", accept, conn=conn)
            packed = headers.get("Content-Encoding") == "gzip"
            self.assertEqual((status, packed), (200, accept in (ASKS, "gzip")), accept)
            self.assertEqual(headers["Content-Length"], str(len(body)), accept)
            self.assertEqual(gzip.decompress(body) if packed else body, plain, accept)

    def test_an_answer_that_is_not_200_stays_as_it_is(self):
        """A refusal has its own path in each client, so its bytes do not change, whatever its size."""
        said = {"error": "the same few words " * 2000}
        plain = json.dumps(said).encode()
        self.assertGreater(len(plain), hub.GZIP_MIN)
        for code in (400, 403, 404, 409, 500, 503):
            with patch.object(hub.Handler, "ui_state", lambda handler, code=code: handler.json(code, said)):
                status, body, names, headers = self.read("/ui/state", ASKS)
            self.assertEqual((status, body, names), (code, plain, PLAIN), code)
        with patch.object(hub.Handler, "ui_state", lambda handler: handler.json(200, said)):       # and a 200 does
            status, body, _, headers = self.read("/ui/state", ASKS)
        self.assertEqual((status, headers.get("Content-Encoding"), gzip.decompress(body)), (200, "gzip", plain))

    def test_an_answer_that_a_route_writes_inside_the_lock_stays_as_it_is(self):
        """The compression of one reader's answer must not hold every other caller of the hub."""
        said = {"rows": ["the same few words"] * 2000}
        plain = json.dumps(said).encode()

        def inside(handler):
            with hub.LOCK:
                handler.json(200, said)

        with patch.object(hub.Handler, "ui_state", inside):
            self.assertEqual(self.read("/ui/state", ASKS)[:3], (200, plain, PLAIN))
        with patch.object(hub.Handler, "ui_state", lambda handler: handler.json(200, said)):       # and outside it
            self.assertEqual(self.read("/ui/state", ASKS)[3].get("Content-Encoding"), "gzip")

    def test_the_frame_of_a_task_screen_goes_compressed_too(self):
        """Its route sends it after the hub's lock (test_desktop_lock), so the rule of every large answer is its rule.
        Until then the route wrote it inside the lock, and it stayed as it was. Measured on 10 November 2026 with 11
        screenshots, encoded again at the worker's settings: together they became 58% of their size, in 0.1 to 2.8 ms
        each on an M4 Max, and on a path with a round trip of 60 ms a read took 0.18 s at the mean where it took
        0.24 s. The bytes of the picture in this test have no order at all, and 23% still goes, because base64 puts 6
        bits in a byte."""
        frames = patch.object(hub, "DESKTOP", desktop.Frames())
        frames.start()
        self.addCleanup(frames.stop)
        hub.kv_set("db_id", "gzip-test")
        hub.TEAM["addresses"]["studio"] = "127.0.0.3"
        hub.TEAM["agents"]["studio"] = dict(role="worker", runtime="claude", machine="studio", can=["screen"])
        task = hub.ins("INSERT INTO tasks(title,owner,state,needs,attempt) "
                       "VALUES('Watch','studio','working','screen',1)")
        view = f"/ui/tasks/{task}/desktop?db=gzip-test&attempt=1"
        self.assertEqual(json.loads(self.read(view)[1])["status"], "waiting")       # the owner's look opens the lease
        image = b"\xff\xd8\xff" + b"".join(hashlib.sha256(bytes([n])).digest() for n in range(250)) + b"\xff\xd9"
        shown = dict(status="live", image=base64.b64encode(image).decode(), captured_at=hub.now())
        self.assertTrue(hub.DESKTOP.put(("gzip-test", task, 1), shown, hub.now()))
        plain = self.read(view)
        self.assertEqual((plain[0], plain[2]), (200, PLAIN + ["Cache-Control", "X-Content-Type-Options"]))
        self.assertEqual((json.loads(plain[1])["status"], json.loads(plain[1])["image"]), ("live", shown["image"]))
        self.assertGreater(len(plain[1]), hub.GZIP_MIN)
        status, packed, names, headers = self.read(view, ASKS)
        self.assertEqual((status, names), (200, PLAIN + ["Cache-Control", "X-Content-Type-Options", "Content-Encoding",
                                                         "Vary"]))
        self.assertEqual((headers["Cache-Control"], headers["X-Content-Type-Options"], headers["Content-Encoding"],
                          headers["Vary"], headers["Content-Length"]),
                         ("no-store", "nosniff", "gzip", "Accept-Encoding", str(len(packed))))
        self.assertEqual(gzip.decompress(packed), plain[1])                         # the same JSON, byte for byte
        self.assertLess(len(packed), len(plain[1]))
        self.assertEqual(self.read(view, "identity")[:3], plain[:3])                # and as it was for the others
        # A look that shows no picture is a small answer, and stays as it is.
        hub.DESKTOP.rows.clear()
        waiting = self.read(view, ASKS)
        self.assertEqual((waiting[0], waiting[2], json.loads(waiting[1])["status"]),
                         (200, PLAIN + ["Cache-Control", "X-Content-Type-Options"], "waiting"))

    def test_the_answer_to_a_command_goes_compressed_too(self):
        """The method does not decide: the same rule for the answer to a POST of the owner API, and no other POST."""
        said = {"rows": ["the same few words"] * 2000}
        plain = json.dumps(said).encode()
        with patch.object(hub.Handler, "post", lambda handler: handler.json(200, said)):
            status, packed, names, headers = self.read("/ui/any/command", ASKS, method="POST", body=b"{}")
            self.assertEqual((status, names), (200, PLAIN + ["Content-Encoding", "Vary"]))
            self.assertEqual((headers["Content-Length"], gzip.decompress(packed)), (str(len(packed)), plain))
            self.assertEqual(self.read("/ui/any/command", method="POST", body=b"{}")[1:3], (plain, PLAIN))
            for path in ("/helper/any/report", "/mcp/manager", "/bridge/in", "/uix/state", "/ui"):
                self.assertEqual(self.read(path, ASKS, method="POST", body=b"{}")[:3], (200, plain, PLAIN), path)


class OtherAnswers(Answers):
    """Every route outside the owner API (an agent's session, a helper, the owner's own records), and every answer
    that is not JSON."""

    def test_the_records_stay_as_they_are(self):
        self.fill()
        plain = self.read("/records")
        self.assertEqual((plain[0], plain[2]), (200, PLAIN))
        self.assertGreater(len(plain[1]), hub.GZIP_MIN)
        status, body, names, _ = self.read("/records", ASKS)
        self.assertEqual((status, names), (200, PLAIN))
        self.assertEqual(json.loads(body)["notes"], json.loads(plain[1])["notes"])

    def test_an_agent_session_reads_its_tools_as_before(self):
        """Claude Code and Codex call /mcp with their own HTTP clients, which can ask for gzip by themselves."""
        hub.TEAM["addresses"].update(owner="127.0.0.9", box="127.0.0.1")
        hub.TEAM["agents"]["worker"] = {"role": "worker", "runtime": "claude", "machine": "box", "can": [],
                                        "reports_to": "manager"}
        call = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
        plain = self.read("/mcp/worker", method="POST", body=call)
        self.assertEqual((plain[0], plain[2]), (200, PLAIN))
        with patch.object(hub, "GZIP_MIN", 1000):
            self.assertGreater(len(plain[1]), hub.GZIP_MIN)
            status, body, names, _ = self.read("/mcp/worker", ASKS, method="POST", body=call)
        self.assertEqual((status, names, body), (200, PLAIN, plain[1]))
        self.assertIn("read_messages", [tool["name"] for tool in json.loads(body)["result"]["tools"]])

    def test_an_answer_that_is_not_json_stays_as_it_is(self):
        self.fill()
        with patch.object(hub, "GZIP_MIN", 0):
            for path in ("/board.txt", "/board"):
                plain, asked = self.read(path), self.read(path, ASKS)
                self.assertEqual((asked[0], asked[2]), (200, PLAIN), path)
                self.assertEqual(asked[1], plain[1], path)
                self.assertLess(len(hub.gzip_body(plain[1])), len(plain[1]), path)     # it would have been smaller


class Names(unittest.TestCase):
    """The two functions by themselves."""

    def test_what_names_gzip(self):
        for lines in (["gzip"], ["gzip, deflate, br"], ["deflate,gzip"], ["\tgzip\t"], ["GZIP;Q=0.5"], ["gzip;q=1.000"],
                      ["gzip;q=0.001"], ["gzip;q=1."], ["gzip;q=0.5", "identity"], ["br", "gzip"], ("gzip",),
                      ["gzip ;\tq=1"], ["gzip; Q=0.5 "]):
            self.assertIs(hub.accepts_gzip(lines), True, lines)
        for lines in (None, [], [""], [","], ["identity"], ["*"], ["deflate, br"], ["gzip;q=0"], ["gzip;q=0."],
                      ["gzip;q=0.000"], ["gzip;q=1.001"], ["gzip;q=01"], ["gzip;q=.5"], ["gzip;q=1e0"], ["gzip;q=nan"],
                      ["gzip;q=inf"], ["gzip;q"], ["gzip;"], ["gzip;q=0.5;x=1"], ["x-gzip"], ["gzip-9"], ["g zip"],
                      ["gzip\n"], ["gzip;q=0", "gzip"], ["gzip;q = 1"], ["gzip;q= 1"], ["gzip;q =1"]):
            self.assertIs(hub.accepts_gzip(lines), False, lines)

    def test_the_compressed_bytes_are_gzip_of_the_same_bytes(self):
        for body in (b"", b"{}", b'{"error": "not found"}', json.dumps({"rows": list(range(5000))}).encode(),
                     bytes(range(256)) * 300):
            self.assertEqual(gzip.decompress(hub.gzip_body(body)), body)
        big = json.dumps({"tasks": [{"id": n, "title": "a task of the fleet", "state": "completed"}
                                    for n in range(20000)]}).encode()
        self.assertLess(len(hub.gzip_body(big)), len(big) // 3)


if __name__ == "__main__":
    unittest.main()

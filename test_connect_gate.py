"""gate.py, the program that faces the Internet for the remote MCP address, and `hubsetup.py connect on|off`, its root
step. The gate runs on a free port of 127.0.0.1 in front of a stand-in hub on a Unix socket in a temporary folder. No
Tailscale, no root, no systemd: the root step runs against a stand-in shell. Example names only.

python3 -m unittest -v test_connect_gate
"""

import ast
import hashlib
import http.server
import json
import os
from pathlib import Path
import select
import shlex
import shutil
import socket
import socketserver
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import gate
import hubsetup

N = "hub-1.tail0000.ts.net"
HERE = Path(__file__).resolve().parent
ROUTES = [("GET", "/.well-known/oauth-protected-resource"), ("GET", "/.well-known/oauth-protected-resource/mcp"),
          ("GET", "/.well-known/oauth-authorization-server"), ("GET", "/authorize?client_id=x&state=y"),
          ("POST", "/authorize"), ("POST", "/token"), ("POST", "/register"), ("POST", "/revoke"), ("GET", "/mcp"),
          ("POST", "/mcp"), ("DELETE", "/mcp")]


class StandInHub(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path):
        self.seen = []
        super().__init__(path, Seen)


class Seen(http.server.BaseHTTPRequestHandler):
    def handle_one(self):
        size = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(size) if size else b""
        self.server.seen.append({"method": self.command, "path": self.path, "headers": list(self.headers.items()),
                                 "body": body})
        out = json.dumps({"ok": True, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = do_DELETE = handle_one

    def address_string(self):
        return "hub.sock"

    def log_message(self, *args):
        pass


def ask(port, raw, wait=5):
    """The whole answer of the gate to raw bytes, read until it closes."""
    with socket.create_connection(("127.0.0.1", port), timeout=wait) as s:
        try:
            s.sendall(raw)
        except OSError:
            pass
        out = b""
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    return out
                out += chunk
        except (ConnectionResetError, socket.timeout):
            return out


def status(answer):
    return int(answer.split(b" ", 2)[1]) if answer.startswith(b"HTTP/1.") else None


def request(method="GET", target="/mcp", host=N, headers=(), body=b"", length=True):
    lines = [f"{method} {target} HTTP/1.1"] + ([f"Host: {host}"] if host is not None else []) + list(headers)
    if body and length:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


class WithGate(unittest.TestCase):
    connections = 4

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="gate-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.sock = os.path.join(self.dir, "hub.sock")
        self.hub = StandInHub(self.sock)
        threading.Thread(target=self.hub.serve_forever, daemon=True).start()
        self.addCleanup(self.hub.server_close)
        self.addCleanup(self.hub.shutdown)
        self.lines = []
        self.gate = gate.Gate(N, socket_path=self.sock, port=0, connections=self.connections, read_time=1,
                              hub_time=5, log=self.lines.append)
        self.thread = threading.Thread(target=self.gate.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join, 5)
        self.addCleanup(self.gate.close)

    def send(self, raw, wait=5):
        return ask(self.gate.port, raw, wait)


class Forwarding(WithGate):
    def test_each_route_is_forwarded(self):
        for method, target in ROUTES:
            body = b'{"jsonrpc": "2.0"}' if method == "POST" else b""
            got = self.send(request(method, target, body=body))
            self.assertEqual(status(got), 200, (method, target, got[:80]))
            seen = self.hub.seen[-1]
            self.assertEqual((seen["method"], seen["path"], seen["body"]), (method, target, body))
        self.assertEqual(len(self.hub.seen), len(ROUTES))
        self.assertIn(f"200 GET /mcp", self.lines)

    def test_other_paths_and_methods_reach_nothing(self):
        for method, target in (("GET", "/ui/state"), ("GET", "/"), ("GET", "/health"), ("POST", "/mcp/manager"),
                               ("GET", "/token"), ("GET", "/register"), ("PUT", "/mcp"), ("HEAD", "/mcp"),
                               ("OPTIONS", "/mcp"), ("PATCH", "/authorize"), ("GET", "/mcp/"), ("GET", "/MCP"),
                               ("GET", "/%6dcp"), ("GET", "/authorize/"), ("GET", "//mcp"), ("GET", "/./mcp"),
                               ("GET", "/.well-known/openid-configuration"), ("POST", "/ui/messages"),
                               ("GET", "/.well-known/oauth-authorization-server/mcp")):
            got = self.send(request(method, target))
            self.assertEqual(status(got), 404, (method, target))
        self.assertEqual(self.hub.seen, [])

    def test_only_the_listed_headers_reach_the_hub(self):
        sent = ["Authorization: Bearer abc", "Content-Type: application/json", "Accept: application/json",
                "Accept: text/event-stream", "Origin: https://example.com", "MCP-Protocol-Version: 2025-11-25",
                "Mcp-Session-Id: s-1", "Cookie: a=b", "X-Forwarded-For: 198.51.100.7, 203.0.113.9",
                "X-Forwarded-Host: example.com", "X-Forwarded-Proto: https", "Forwarded: for=10.0.0.1",
                "Tailscale-User-Login: someone@example.com", "Tailscale-Funnel-Request: ?1",
                "X-Gate-Version: 99", "X-Gate-Source: 10.0.0.1", "Connection: keep-alive, Authorization",
                "Keep-Alive: 5", "Proxy-Authorization: Basic eA==", "Upgrade: websocket", "Expect: 100-continue",
                "User-Agent: example", "X-Real-IP: 10.0.0.1", "Te: trailers"]
        self.assertEqual(status(self.send(request("POST", "/mcp", headers=sent, body=b"{}"))), 200)
        got = self.hub.seen[-1]["headers"]
        self.assertEqual(got, [("Host", N), ("Authorization", "Bearer abc"), ("Content-Type", "application/json"),
                               ("Accept", "application/json, text/event-stream"),
                               ("Origin", "https://example.com"), ("MCP-Protocol-Version", "2025-11-25"),
                               ("Mcp-Session-Id", "s-1"), ("X-Gate-Version", gate.VERSION),
                               ("X-Gate-Source", "203.0.113.9"), ("Content-Length", "2"), ("Connection", "close")])

    def test_the_source_is_the_last_forwarded_address_or_none(self):
        for xff, want in ((["X-Forwarded-For: 198.51.100.7"], "198.51.100.7"),
                          (["X-Forwarded-For: 10.0.0.1", "X-Forwarded-For: 2001:db8::1"], "2001:db8::1"),
                          (["X-Forwarded-For: not-an-address"], None), (["X-Forwarded-For: "], None), ([], None)):
            self.send(request(headers=xff))
            got = dict(self.hub.seen[-1]["headers"]).get("X-Gate-Source")
            self.assertEqual(got, want, xff)

    def test_the_host(self):
        for host in (N, N + ":443", N.upper(), "Hub-1.Tail0000.TS.net:443"):
            self.assertEqual(status(self.send(request(host=host))), 200, host)
        for host in ("example.com", N + ":8765", N + ".", "hub-1", "", "x." + N, N + ":443:443", N + " x"):
            self.assertEqual(status(self.send(request(host=host))), 421, host)
        self.assertEqual(status(self.send(request(host=None))), 400)
        two = request(headers=["Host: example.com"])
        self.assertEqual(status(self.send(two)), 400)
        two = request(headers=[f"Host: {N}"])
        self.assertEqual(status(self.send(two)), 400)
        self.assertEqual(len(self.hub.seen), 4)

    def test_a_header_two_times_that_may_come_once(self):
        for name in ("Authorization", "Content-Type", "Origin", "MCP-Protocol-Version", "Mcp-Session-Id"):
            got = self.send(request(headers=[f"{name}: a", f"{name}: b"]))
            self.assertEqual(status(got), 400, name)
        self.assertEqual(self.hub.seen, [])

    def test_a_body_at_and_over_the_limits(self):
        self.assertEqual(status(self.send(request("POST", "/mcp", body=b"x" * 65536))), 200)
        self.assertEqual(len(self.hub.seen[-1]["body"]), 65536)
        self.assertEqual(status(self.send(request("POST", "/token", body=b"x" * 8192))), 200)
        self.assertEqual(status(self.send(request("POST", "/mcp", body=b"x" * 65537))), 413)
        self.assertEqual(status(self.send(request("POST", "/mcp", body=b"x" * (65 * 1024)))), 413)
        for path in ("/token", "/register", "/revoke", "/authorize"):
            self.assertEqual(status(self.send(request("POST", path, body=b"x" * 8193))), 413, path)
        # a length that announces too much is refused before the gate reads the body
        self.assertEqual(status(self.send(request("POST", "/mcp", headers=["Content-Length: 99999999"]))), 413)
        self.assertEqual(len(self.hub.seen), 2)

    def test_a_chunked_body_reaches_the_hub_with_its_length(self):
        chunked = request("POST", "/mcp", headers=["Transfer-Encoding: chunked"]) + \
            b"5;x=y\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: z\r\n\r\n"
        self.assertEqual(status(self.send(chunked)), 200)
        seen = self.hub.seen[-1]
        self.assertEqual(seen["body"], b"hello world")
        self.assertEqual(dict(seen["headers"])["Content-Length"], "11")
        self.assertNotIn("Transfer-Encoding", dict(seen["headers"]))
        big = request("POST", "/token", headers=["Transfer-Encoding: chunked"]) + b"2001\r\n" + b"x" * 8193 + \
            b"\r\n0\r\n\r\n"
        self.assertEqual(status(self.send(big)), 413)
        for bad in (request("POST", "/mcp", headers=["Transfer-Encoding: chunked", "Content-Length: 5"]) + b"hello",
                    request("POST", "/mcp", headers=["Transfer-Encoding: chunked"]) + b"zz\r\nhello\r\n0\r\n\r\n",
                    request("POST", "/mcp", headers=["Transfer-Encoding: chunked"]) + b"5\r\nhelloXX0\r\n\r\n",
                    request("POST", "/mcp", headers=["Content-Length: 5", "Content-Length: 5"]) + b"hello",
                    request("POST", "/mcp", headers=["Content-Length: +5"]) + b"hello",
                    request("POST", "/mcp", headers=["Content-Length: 5 5"]) + b"hello"):
            self.assertEqual(status(self.send(bad)), 400, bad[:120])
        self.assertEqual(status(self.send(request("POST", "/mcp", headers=["Transfer-Encoding: gzip"]))), 501)
        self.assertEqual(len(self.hub.seen), 1)

    def test_malformed_requests(self):
        for raw in (b"GET /mcp\r\nHost: x\r\n\r\n", b"get /mcp HTTP/1.1\r\n\r\n", b"GET mcp HTTP/1.1\r\n\r\n",
                    b"GET http://example.com/mcp HTTP/1.1\r\n\r\n", b"GET /mcp HTTP/2.0\r\n\r\n",
                    b"GET /m cp HTTP/1.1\r\n\r\n", b"GET /mcp HTTP/1.1\nHost: " + N.encode() + b"\n\n",
                    request(headers=[" folded: value"]), request(headers=["Bad Name: x"]),
                    request(headers=["Name : x"]), request(headers=["NoColon"]),
                    request(headers=["Authorization: a\rb"]), request(headers=["X-A: a\x00b"]),
                    request(headers=["Authorization: caf\xe9".encode("latin-1").decode("latin-1")]),
                    b"\r\n\r\n", b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + b"\x00" * 40 + b"\r\n\r\n"):
            got = self.send(raw)
            self.assertEqual(status(got), 400, raw[:80])
        self.assertEqual(self.hub.seen, [])

    def test_lines_and_headers_over_their_limits(self):
        self.assertEqual(status(self.send(request(target="/mcp?" + "a" * 4096))), 414)
        self.assertEqual(status(self.send(b"GET /mcp?" + b"a" * 9000)), 414)
        self.assertEqual(status(self.send(request(headers=["X-A: " + "a" * 4096]))), 431)
        self.assertEqual(status(self.send(request(headers=[f"X-{i}: " + "a" * 1000 for i in range(17)]))), 431)
        self.assertEqual(status(self.send(request(target="/mcp?" + "a" * 4000))), 200)
        self.assertEqual(len(self.hub.seen), 1)

    def test_a_hub_that_does_not_answer(self):
        self.hub.shutdown()
        self.hub.server_close()
        os.unlink(self.sock)
        self.assertEqual(status(self.send(request())), 502)


class BadClients(WithGate):
    connections = 3

    def test_a_request_that_stops_in_the_middle(self):
        for raw in (b"GET /mc", request("POST", "/mcp", headers=["Content-Length: 100"]) + b"x" * 10,
                    request("POST", "/mcp", headers=["Transfer-Encoding: chunked"]) + b"5\r\nhe"):
            with socket.create_connection(("127.0.0.1", self.gate.port), timeout=5) as s:
                s.sendall(raw)
                s.shutdown(socket.SHUT_WR)            # the client stops: the gate reads its end
                s.recv(100)
        self.assertEqual(status(self.send(request())), 200)
        self.assertEqual(len(self.hub.seen), 1)

    def test_a_slow_request_gets_408_and_others_go_on(self):
        slow = socket.create_connection(("127.0.0.1", self.gate.port), timeout=5)
        self.addCleanup(slow.close)
        slow.sendall(b"POST /mcp HTTP/1.1\r\nHost: " + N.encode() + b"\r\nContent-Length: 10\r\n\r\nab")
        t0 = time.monotonic()
        self.assertEqual(status(self.send(request())), 200)            # while the slow one waits
        self.assertLess(time.monotonic() - t0, 0.9)
        got = slow.recv(1000)
        self.assertEqual(status(got), 408)
        self.assertLess(time.monotonic() - t0, 3)
        self.assertEqual(len(self.hub.seen), 1)

    def test_a_drip_feed_does_not_outlast_the_read_time(self):
        s = socket.create_connection(("127.0.0.1", self.gate.port), timeout=5)
        self.addCleanup(s.close)
        t0, got = time.monotonic(), b""
        for c in b"GET /mcp HTTP/1.1\r\nX-Slow: " + b"a" * 200:
            try:
                s.sendall(bytes([c]))
            except OSError:
                break
            if select.select([s], [], [], 0.05)[0]:
                got = s.recv(1000)
                break
        self.assertEqual(status(got), 408)
        self.assertLess(time.monotonic() - t0, 3)

    def test_more_connections_than_the_limit_get_503(self):
        idle = []
        for _ in range(3):
            c = socket.create_connection(("127.0.0.1", self.gate.port), timeout=5)
            self.addCleanup(c.close)
            idle.append(c)
        time.sleep(0.2)
        self.assertEqual(status(self.send(request())), 503)
        for c in idle:
            c.close()
        time.sleep(0.3)
        self.assertEqual(status(self.send(request())), 200)

    def test_a_client_that_leaves_before_the_answer(self):
        with socket.create_connection(("127.0.0.1", self.gate.port), timeout=5) as s:
            s.sendall(request("POST", "/mcp", body=b"{}"))
        time.sleep(0.3)
        self.assertEqual(status(self.send(request())), 200)

    def test_a_flood_of_garbage_leaves_the_gate_serving(self):
        for raw in (os.urandom(5000), b"\x00" * 300, b"GET " + b"/" * 5000, b"\r\n" * 10):
            self.send(raw, wait=3)
        self.assertEqual(status(self.send(request())), 200)
        self.assertTrue(self.thread.is_alive())


class TheGateItself(unittest.TestCase):
    def tree(self):
        with open(HERE / "gate.py", encoding="utf-8") as f:
            return ast.parse(f.read())

    def test_standard_library_only(self):
        tree = self.tree()
        names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | \
            {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        self.assertEqual(names, {"argparse", "ipaddress", "re", "socket", "sys", "threading", "time"})

    def test_no_tcp_client_connection(self):
        """Section 1 rule 3: only AF_UNIX to the hub's socket. The one AF_INET socket is the listener, which binds and
        listens and never connects; no create_connection, no urllib, no http.client, no file, no process."""
        tree = self.tree()
        functions = {f.name: f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)}

        def inside(node):
            return [name for name, f in functions.items() if any(n is node for n in ast.walk(f))]
        sockets, connects = [], []
        for n in ast.walk(tree):
            if isinstance(n, ast.Name) and n.id in ("open", "exec", "eval", "__import__", "compile"):
                self.fail(f"gate.py uses {n.id}")
            if isinstance(n, ast.Attribute):
                self.assertNotIn(n.attr, ("create_connection", "connect_ex", "sendto", "sendmsg", "socketpair",
                                          "fromfd", "HTTPConnection", "HTTPSConnection", "urlopen", "getaddrinfo",
                                          "create_server", "SOCK_DGRAM", "SOCK_RAW", "AF_INET6", "AF_PACKET",
                                          "system", "popen"), n.attr)
                if n.attr == "connect":
                    connects.append(inside(n))
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "socket":
                family = n.args[0] if n.args else None
                self.assertIsInstance(family, ast.Attribute, "a socket without a named family")
                sockets.append((family.attr, inside(n)))
        self.assertEqual(sorted(sockets), [("AF_INET", ["listening_socket"]), ("AF_UNIX", ["hub_connection"])])
        self.assertEqual(connects, [["hub_connection"]])
        listener = ast.dump(functions["listening_socket"])
        self.assertIn("'bind'", listener)
        self.assertIn("'listen'", listener)
        self.assertIn("'LISTEN'", listener)
        self.assertEqual(gate.LISTEN, "127.0.0.1")

    def test_the_lists(self):
        self.assertEqual(set(gate.KEPT), {"host", "authorization", "content-type", "accept", "origin",
                                          "mcp-protocol-version", "mcp-session-id"})
        self.assertEqual({(m, p) for p, ms in gate.ROUTES.items() for m in ms},
                         {(m, t.split("?")[0]) for m, t in ROUTES})
        self.assertEqual((gate.PORT, gate.LINE_MAX, gate.HEAD_MAX, gate.BODY_MAX, gate.MCP_BODY_MAX,
                          gate.CONNECTIONS, gate.READ_TIME), (8767, 4096, 16384, 8192, 65536, 32, 10))
        self.assertEqual(gate.SOCKET, hubsetup.CONNECT_STATE + "/hub.sock")
        self.assertEqual(hubsetup.CONNECT_TARGET, f"http://{gate.LISTEN}:{gate.PORT}")

    def test_a_name_that_is_not_full_is_refused(self):
        for bad in ("hub-1", "HUB-1.example.com", "", "a b.example.com", None):
            with self.assertRaises(ValueError):
                gate.Gate(bad, port=0)
        self.assertEqual(gate.main(["--name", "hub-1", "--port", "0"]), 1)


# ---------------------------------------------------------------- hubsetup.py connect on|off, against a stand-in shell

OURS = {"TCP": {"443": {"HTTPS": True}}, "Web": {f"{N}:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8767"}}}},
        "AllowFunnel": {f"{N}:443": True}}


class Box:
    """A stand-in for root's shell on the hub's machine: what ran, and the state it changed."""
    def __init__(self, conf=None, user="", funnel_works=True):
        self.ran, self.files, self.conf = [], {}, json.loads(json.dumps(conf or {}))
        self.state = {"user": user, "folder": "", "program": "", "active": "inactive", "enabled": "disabled",
                      "restarts": "0"}
        self.funnel_works = funnel_works

    def run(self, script, timeout=120):
        self.ran.append(script)
        if script == "tailscale status --json":
            return 0, json.dumps({"Self": {"DNSName": N.upper() + "."}}), ""
        if script in ("tailscale serve status --json", "tailscale funnel status --json"):
            return 0, json.dumps(self.conf) if self.conf else "", ""
        if script.startswith("echo user="):
            return 0, "\n".join(f"{k}={v}" for k, v in self.state.items()), ""
        if "useradd --system" in script:
            self.state["user"] = hubsetup.CONNECT_USER
        if script.startswith("install -d -o fleet"):
            self.state["folder"] = f"fleet:{hubsetup.CONNECT_USER}:2750"
        if "/gate.py" in script and script.startswith("install -d -o root"):
            self.state["program"] = hashlib.sha256((HERE / "gate.py").read_bytes()).hexdigest()
        if hubsetup.CONNECT_UNIT in script:
            source = shlex.split(script.splitlines()[0])[-2]
            self.files[hubsetup.CONNECT_UNIT] = Path(source).read_text(encoding="utf-8")
        if "systemctl restart" in script:
            self.state.update(active="active", enabled="enabled")
        if "systemctl disable --now" in script:
            self.state.update(active="inactive", enabled="disabled")
        if script.startswith("tailscale funnel --bg"):
            if not self.funnel_works:
                return 1, "", "Funnel is not enabled on your tailnet."
            self.conf = json.loads(json.dumps(OURS))
        if script == "tailscale funnel --https=443 off":
            self.conf = {}
        return 0, "", ""

    def read(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def changes(self):
        return [s for s in self.ran if not s.startswith(("echo user=", "tailscale status", "tailscale serve status",
                                                         "tailscale funnel status"))]


def account(user):
    return {"uid": 1000, "group": user, "home": f"/home/{user}"}


class ConnectStep(unittest.TestCase):
    def on(self, box):
        return hubsetup.connect_on(hub_user="fleet", kit=str(HERE), run=box.run, read=box.read, account=account)

    def test_the_unit(self):
        unit = hubsetup.connect_unit_text(N)
        for line in ("User=founderizer-connect", "Group=founderizer-connect",
                     f"ExecStart=/usr/bin/python3 -I /usr/local/lib/founderizer-connect/gate.py --name {N}",
                     "IPAddressDeny=any", "IPAddressAllow=127.0.0.1/32", "RestrictAddressFamilies=AF_UNIX AF_INET",
                     "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
                     "WantedBy=multi-user.target"):
            self.assertIn(line + "\n", unit, line)
        # the folder of the hub's socket is the hub user's: systemd may not make it the gate's
        for word in ("StateDirectory", "RuntimeDirectory", "ReadWritePaths", "AmbientCapabilities", "User=root"):
            self.assertNotIn(word, unit)
        for bad in ("hub-1", "x.example.com\nExecStartPre=/bin/sh", "HUB.example.com", "a b.example.com"):
            with self.assertRaises(hubsetup.Stop):
                hubsetup.connect_unit_text(bad)

    def test_the_tailscale_commands(self):
        self.assertEqual(hubsetup.tailscale_argv("funnel-on"),
                         ["tailscale", "funnel", "--bg", "--yes", "--https=443", "http://127.0.0.1:8767"])
        self.assertEqual(hubsetup.tailscale_argv("funnel-off"), ["tailscale", "funnel", "--https=443", "off"])
        self.assertEqual(hubsetup.tailscale_argv("funnel-status"), ["tailscale", "funnel", "status", "--json"])
        self.assertEqual(hubsetup.tailscale_argv("serve-status"), ["tailscale", "serve", "status", "--json"])
        self.assertEqual(hubsetup.tailscale_argv("status"), ["tailscale", "status", "--json"])

    def test_what_port_443_and_funnel_may_hold(self):
        self.assertEqual(hubsetup.connect_conflicts({}), [])
        self.assertEqual(hubsetup.connect_conflicts(OURS), [])
        self.assertTrue(hubsetup.connect_in_place(OURS, N))
        self.assertFalse(hubsetup.connect_in_place({}, N))
        self.assertFalse(hubsetup.connect_in_place(dict(OURS, AllowFunnel={}), N))      # served, but not published
        hub_port = json.loads(json.dumps(OURS))
        hub_port["Web"][f"{N}:443"]["Handlers"]["/"]["Proxy"] = "http://127.0.0.1:8765"
        other_path = json.loads(json.dumps(OURS))
        other_path["Web"][f"{N}:443"]["Handlers"]["/ui"] = {"Proxy": "http://127.0.0.1:8765"}
        tcp = {"TCP": {"443": {"TCPForward": "127.0.0.1:8765"}}}
        other_port = dict(json.loads(json.dumps(OURS)), Web=dict(OURS["Web"], **{
            f"{N}:8443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8766"}}}}),
            AllowFunnel={f"{N}:443": True, f"{N}:8443": True})
        foreground = {"Foreground": {"abc": {"TCP": {"443": {"HTTPS": True}}, "Web": {f"{N}:443": {"Handlers": {
            "/": {"Path": "/srv/www"}}}}}}}
        text = {"Web": {f"{N}:443": {"Handlers": {"/": {"Text": "hello"}}}}, "AllowFunnel": {f"{N}:443": True}}
        unix = {"Web": {f"{N}:443": {"Handlers": {"/": {"Proxy": "unix:/var/lib/founderizer-connect/hub.sock"}}}}}
        for conf in (hub_port, other_path, tcp, other_port, foreground, text, unix):
            self.assertTrue(hubsetup.connect_conflicts(conf), conf)
            self.assertFalse(hubsetup.connect_in_place(conf, N), conf)
        # a target that Serve keeps on the private network only, on another port, stops nothing
        tailnet_only = dict(json.loads(json.dumps(OURS)), Web=dict(OURS["Web"], **{
            f"{N}:8443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:3000"}}}}))
        self.assertEqual(hubsetup.connect_conflicts(tailnet_only), [])

    def test_on_a_new_machine_each_part_in_its_order(self):
        box = Box()
        done = self.on(box)
        self.assertEqual(done, {"name": N, "address": f"https://{N}/mcp", "state": "made"})
        changes = box.changes()
        self.assertEqual(len(changes), 6, changes)
        self.assertIn("useradd --system --gid founderizer-connect", changes[0])
        self.assertTrue(changes[1].startswith("install -d -o fleet -g founderizer-connect -m 2750 "
                                              "/var/lib/founderizer-connect\n"))
        self.assertIn("install -o root -g root -m 644 " + shlex.quote(str(HERE / "gate.py")) +
                      " /usr/local/lib/founderizer-connect/gate.py", changes[2])
        self.assertIn("systemctl daemon-reload", changes[3])
        self.assertTrue(changes[4].startswith("systemctl daemon-reload\n"), changes[4])
        self.assertIn("systemctl restart founderizer-connect", changes[4])
        self.assertEqual(changes[5], "tailscale funnel --bg --yes --https=443 http://127.0.0.1:8767")
        self.assertEqual(box.ran[-1], "tailscale funnel status --json")
        self.assertEqual(box.files[hubsetup.CONNECT_UNIT], hubsetup.connect_unit_text(N))

    def test_a_unit_that_an_earlier_run_wrote_is_read_again_before_the_start(self):
        # an earlier run wrote the unit and stopped before systemd read it: this run writes nothing, and reloads
        box = Box()
        box.files[hubsetup.CONNECT_UNIT] = hubsetup.connect_unit_text(N)
        self.assertEqual(self.on(box)["state"], "made")
        start = [s for s in box.changes() if "systemctl restart founderizer-connect" in s]
        self.assertEqual(len(start), 1, box.changes())
        self.assertTrue(start[0].startswith("systemctl daemon-reload\n"), start[0])
        self.assertFalse([s for s in box.changes() if hubsetup.CONNECT_UNIT in s], box.changes())

    def test_a_second_run_changes_nothing(self):
        box = Box()
        self.on(box)
        box.ran.clear()
        self.assertEqual(self.on(box)["state"], "there")
        self.assertEqual(box.changes(), [])

    def test_a_new_program_restarts_the_gate_and_nothing_else(self):
        box = Box()
        self.on(box)
        box.state["program"] = "0" * 64
        box.ran.clear()
        self.assertEqual(self.on(box)["state"], "made")
        self.assertEqual(len(box.changes()), 2, box.changes())
        self.assertIn("systemctl restart", box.changes()[1])

    def test_another_target_on_443_or_in_funnel_changes_nothing(self):
        for conf in ({"TCP": {"443": {"TCPForward": "127.0.0.1:8765"}}},
                     {"Web": {f"{N}:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8765"}}}}},
                     {"Web": {f"{N}:10000": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8765"}}}},
                      "AllowFunnel": {f"{N}:10000": True}}):
            box = Box(conf=conf)
            with self.assertRaises(hubsetup.Stop) as e:
                self.on(box)
            self.assertIn("Nothing was changed", str(e.exception))
            self.assertEqual(box.changes(), [], conf)

    def test_a_user_of_another_group_stops_the_step(self):
        box = Box(user="users")
        with self.assertRaises(hubsetup.Stop):
            self.on(box)
        self.assertEqual(box.changes(), [])

    def test_a_funnel_that_tailscale_refuses(self):
        box = Box(funnel_works=False)
        with self.assertRaises(hubsetup.Stop) as e:
            self.on(box)
        self.assertIn("Funnel is not enabled", str(e.exception))

    def test_off(self):
        box = Box()
        self.on(box)
        box.ran.clear()
        self.assertEqual(hubsetup.connect_off(run=box.run), {"state": "off"})
        self.assertEqual(box.changes(), ["tailscale funnel --https=443 off", "systemctl disable --now founderizer-connect"])
        box.ran.clear()
        hubsetup.connect_off(run=box.run)
        self.assertEqual(box.changes(), [])

    def test_off_leaves_another_target_on_443(self):
        box = Box()
        self.on(box)
        box.conf = {"Web": {f"{N}:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:3000"}}}}}
        box.ran.clear()
        hubsetup.connect_off(run=box.run)
        self.assertEqual(box.changes(), ["systemctl disable --now founderizer-connect"])

    def test_the_command_refuses_on_a_mac_and_without_root(self):
        for system, uid, words in (("Darwin", 0, "Mac"), ("Linux", 1000, "as root"), ("FreeBSD", 0, "Linux")):
            with patch.object(hubsetup.platform, "system", return_value=system), \
                    patch.object(hubsetup.os, "geteuid", return_value=uid), \
                    patch.object(hubsetup, "connect_on") as on, patch.object(hubsetup, "connect_off") as off, \
                    patch("builtins.print") as said:
                self.assertEqual(hubsetup.main(["connect", "on"]), 1)
                self.assertEqual(hubsetup.main(["connect", "off"]), 1)
            on.assert_not_called()
            off.assert_not_called()
            last = json.loads([c.args[0] for c in said.call_args_list if c.args and c.args[0].startswith("{")][-1])
            self.assertIs(last["ok"], False)
            self.assertIn(words, last["error"])

    def test_the_command_runs_only_from_roots_clone(self):
        with patch.object(hubsetup.platform, "system", return_value="Linux"), \
                patch.object(hubsetup.os, "geteuid", return_value=0), \
                patch.object(hubsetup, "connect_on") as on, patch("builtins.print"):
            self.assertEqual(hubsetup.main(["connect", "on"]), 1)
        on.assert_not_called()


if __name__ == "__main__":
    unittest.main()

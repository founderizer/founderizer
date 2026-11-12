"""The names the hub answers to, and the requests a browser makes from another site (devops task 1.1, 24 October 2026).

The hub knows its callers by their address, so a web page in a browser on one of those machines is that machine to the
address check. Under a name of its own that points at the hub (DNS rebinding), such a page reads every answer; from
another site, a form or an image writes. So the hub answers only a Host that names it, takes a write only from its own
Origin, and refuses a cross-site request on a GET that writes. The hub runs in this process on 127.0.0.1 and a port of
its own, and every request goes over a real socket with the headers a browser would send.

    python3 -m unittest -v test_host_origin
"""
import http.client
import json
import os
import socket
import sqlite3
import shutil
import stat
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

import hub

OWNER, HUB_MACHINE = "127.0.0.1", "127.0.0.2"


class LocalHub(unittest.TestCase):
    """A hub in this process on 127.0.0.1 and a port of its own, and the helpers of a raw request."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fleet-host-origin-")
        self.addCleanup(self.tmp.cleanup)
        hub.DB = sqlite3.connect(self.tmp.name + "/test.db", check_same_thread=False)
        hub.DB.row_factory = sqlite3.Row
        hub.DB.executescript(hub.SCHEMA)
        hub.migrate()
        self.addCleanup(hub.DB.close)
        hub.TEAM = {"addresses": {"owner": OWNER, "hub": HUB_MACHINE}, "hub": {"machine": "hub", "port": 8765},
                    "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []}}}
        names = patch.dict(hub.TAILNET_NAMES, {"names": ()})
        names.start()
        self.addCleanup(names.stop)
        hub.REFUSED_HOSTS.clear()
        self.addCleanup(hub.REFUSED_HOSTS.clear)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), hub.Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_port

    # ---- helpers
    def ask(self, method, path, headers=None, body=None, host=None):
        """(status, body, headers) of one request. host: the Host header; None sends none at all."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            if host is not None:
                conn.putheader("Host", host)
            data = body.encode() if isinstance(body, str) else body
            if data is not None:
                conn.putheader("Content-Type", "application/x-www-form-urlencoded")
                conn.putheader("Content-Length", str(len(data)))
            for name, value in (headers or {}).items():
                conn.putheader(name, value)
            conn.endheaders(data)
            answer = conn.getresponse()
            return answer.status, answer.read().decode(), dict(answer.getheaders())
        finally:
            conn.close()

    def get(self, path, host="", **headers):
        return self.ask("GET", path, headers, host=host or f"127.0.0.1:{self.port}")

    def post(self, path, body="", host="", **headers):
        return self.ask("POST", path, headers, body=body, host=host or f"127.0.0.1:{self.port}")

    def refused_lines(self):
        return [r["what"] for r in hub.q("SELECT what FROM log WHERE agent='hub' AND what LIKE 'REFUSED a request%' "
                                         "ORDER BY id")]

    def said(self):
        return hub.q("SELECT what FROM log WHERE what LIKE 'said to the manager%'")

    FOREIGN = '{"error": "foreign origin"}'


class HostAndOrigin(LocalHub):
    # ---- Host
    def test_each_name_of_the_hub_with_the_bound_port_is_answered(self):
        for host in (f"127.0.0.1:{self.port}", f"localhost:{self.port}", f"LocalHost:{self.port}", f"[::1]:{self.port}",
                     f"{HUB_MACHINE}:{self.port}"):
            self.assertEqual(self.get("/board.txt", host)[0], 200, host)
        self.assertEqual(self.refused_lines(), [])

    def test_any_other_host_gets_421_with_an_empty_body(self):
        other = self.port + 1 if self.port < 65535 else self.port - 1
        for host in (f"127.0.0.1:{other}", "127.0.0.1", "localhost", f"rebind-test.example:{self.port}",
                     "rebind-test.example", f"127.0.0.1:{self.port}.rebind-test.example", f"127.0.0.1:{self.port}:1",
                     f"0.0.0.0:{self.port}", ""):
            status, body, _ = self.get("/board.txt", host) if host else self.ask("GET", "/board.txt", host="")
            self.assertEqual((status, body), (421, ""), host)

    def test_a_request_without_a_host_or_with_two_gets_421(self):
        self.assertEqual(self.ask("GET", "/board.txt", host=None)[:2], (421, ""))
        both = self.ask("GET", "/board.txt", {"Host": "rebind-test.example"}, host=f"127.0.0.1:{self.port}")
        self.assertEqual(both[:2], (421, ""))

    def test_the_rebinding_reads_of_the_owner_are_refused(self):
        """What a rebinding page in the owner's browser read before: every page and every record, the copy, the events."""
        host = f"rebind-test.example:{self.port}"
        for path in ("/", "/board", "/board.txt", "/records", "/ui/state", "/ui/backup?db=x", "/events/owner?wait=0",
                     "/health"):
            self.assertEqual(self.get(path, host)[:2], (421, ""), path)
        self.assertEqual(self.ask("HEAD", "/board", host=host)[:2], (421, ""))
        self.assertEqual(self.ask("DELETE", "/mcp", host=host)[:2], (421, ""))

    def test_a_post_for_a_foreign_host_is_refused_and_its_connection_ends(self):
        """The body is read first, so that the client reads its 421 and no reset; the route never runs."""
        status, body, headers = self.post("/say", "text=I+am+the+owner", f"rebind-test.example:{self.port}")
        self.assertEqual((status, body, headers.get("Connection")), (421, "", "close"))
        big = self.post("/say", "text=" + "x" * 200000, f"rebind-test.example:{self.port}")
        self.assertEqual(big[:2], (421, ""))
        self.assertEqual(self.said(), [])

    def test_a_request_that_tailscale_funnel_brought_is_refused_on_every_route(self):
        """Guard 6(a) of the connected apps (the build specification of the MCP address): the header of a Funnel request
        on the hub's own port, from any address and with the hub's own Host, gets 403 auth funnel before any route
        runs. That tailscaled adds the header is not confirmed; guard 6(b) keeps Funnel off this port."""
        host = f"127.0.0.1:{self.port}"
        for method, path in (("GET", "/board.txt"), ("GET", "/ui/state"), ("GET", "/ui/mobile"), ("GET", "/health"),
                             ("HEAD", "/board"), ("DELETE", "/mcp")):
            with self.subTest(method=method, path=path):
                status, body, _ = self.ask(method, path, {"Tailscale-Funnel-Request": "?1"}, host=host)
                self.assertEqual(status, 403)
                if method != "HEAD":
                    self.assertEqual(json.loads(body), {"error": "this port does not take requests from the Internet",
                                                        "auth": "funnel"})
        status, body, headers = self.post("/say", "text=I+am+the+owner", **{"Tailscale-Funnel-Request": "?1"})
        self.assertEqual((status, json.loads(body)["auth"], headers.get("Connection")), (403, "funnel", "close"))
        self.assertEqual(self.said(), [])
        self.assertEqual(self.get("/board.txt")[0], 200)                # without the header, as before
        self.assertEqual(len([r for r in self.refused_lines() if "Tailscale Funnel" in r]), 7)    # once for each path

    def test_the_tailscale_names_of_the_hub_are_answered_with_the_bound_port(self):
        hub.TAILNET_NAMES["names"] = ("hub-box.tail0000.ts.net", "hub-box")
        for host in (f"hub-box.tail0000.ts.net:{self.port}", f"HUB-BOX:{self.port}"):
            self.assertEqual(self.get("/board.txt", host)[0], 200, host)
        self.assertEqual(self.get("/board.txt", "hub-box.tail0000.ts.net:8766")[0], 421)

    def test_extra_hosts_are_answered_as_they_are_written(self):
        hub.TEAM["hub"]["extra_hosts"] = ["Fleet.Example.com:9000", "[fd7a:115c:a1e0::1]:8765"]
        self.assertEqual(self.get("/board.txt", "fleet.example.com:9000")[0], 200)
        self.assertEqual(self.get("/board.txt", "[fd7a:115c:a1e0::1]:8765")[0], 200)
        self.assertEqual(self.get("/board.txt", f"fleet.example.com:{self.port}")[0], 421)
        hub.TEAM["hub"]["extra_hosts"] = "fleet.example.com:9000"        # a file the hub started with and never checked
        self.assertEqual(self.get("/board.txt", "f")[0], 421)

    def test_each_refused_pair_is_logged_once_and_the_log_has_a_bound(self):
        self.get("/board.txt", "rebind-test.example:1")
        self.get("/board.txt", "rebind-test.example:1")
        self.get("/board.txt", "rebind-test.example:2")
        self.assertEqual(self.refused_lines(), [
            "REFUSED a request from 127.0.0.1 for the Host 'rebind-test.example:1': 421, not a name of this hub",
            "REFUSED a request from 127.0.0.1 for the Host 'rebind-test.example:2': 421, not a name of this hub"])
        self.get("/board.txt", "x" * 5000)
        self.assertIn("'" + "x" * hub.HOST_SHOWN + "'", self.refused_lines()[-1])
        self.assertNotIn("x" * (hub.HOST_SHOWN + 1), self.refused_lines()[-1])
        with patch.object(hub, "HOSTS_LOGGED", 4):
            for n in range(10):
                self.assertEqual(self.get("/board.txt", f"rebind-test.example:{100 + n}")[0], 421)
        self.assertEqual(len(self.refused_lines()), 4)

    def raw(self, request):
        """The bytes the hub answers to these request bytes, until it closes the connection (at most 10 s)."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
            s.sendall(request)
            answer = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    return answer
                answer += chunk

    def test_the_raw_forms_of_a_request_for_another_name(self):
        """What a client that writes its own bytes can send: an absolute-form target, HTTP/1.0 without a Host, and a
        second request after a 421 on the same connection, which the hub never reads."""
        port = self.port
        absolute = self.raw(f"GET http://127.0.0.1:{port}/board.txt HTTP/1.1\r\nHost: rebind-test.example\r\n\r\n"
                            .encode())
        self.assertTrue(absolute.startswith(b"HTTP/1.1 421 "), absolute[:80])
        old = self.raw(b"GET /board.txt HTTP/1.0\r\n\r\n")
        self.assertTrue(old.startswith(b"HTTP/1.1 421 "), old[:80])
        two = self.raw((f"GET /board.txt HTTP/1.1\r\nHost: rebind-test.example\r\n\r\n"
                        f"GET /board.txt HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").encode())
        self.assertEqual(two.count(b"HTTP/1.1 "), 1, two[:200])
        self.assertIn(b"\r\nConnection: close\r\n", two)

    def test_a_malformed_extra_host_is_never_answered(self):
        """A hub can start on a team.json that no check has read, so allowed_hosts applies the rule of validate_team."""
        hub.TEAM["hub"]["extra_hosts"] = ["*", "", "fleet.example.com", "http://x.example:1", "ok.example:9000"]
        self.assertEqual({h for h in hub.allowed_hosts(("127.0.0.1", 80)) if "example" in h or h in ("*", "")},
                         {"ok.example:9000"})

    def test_the_names_without_a_wildcard(self):
        self.assertNotIn("0.0.0.0:80", hub.allowed_hosts(("0.0.0.0", 80)))
        self.assertNotIn(":80", hub.allowed_hosts(("", 80)))
        self.assertEqual(hub.allowed_hosts(("10.1.2.3", 80)),
                         {"127.0.0.1:80", "localhost:80", "[::1]:80", f"{HUB_MACHINE}:80", "10.1.2.3:80"})

    # ---- Origin and Sec-Fetch-Site on a write
    def test_a_foreign_origin_on_a_write_gets_403_and_the_route_never_runs(self):
        for origin in ("https://attacker.example", "null", "Null", f"https://127.0.0.1:{self.port}", "",
                       f"http://rebind-test.example:{self.port}", f"http://127.0.0.1:{self.port}.attacker.example"):
            self.assertEqual(self.post("/say", "text=I+am+the+owner", Origin=origin)[:2], (403, self.FOREIGN), origin)
        for site in ("cross-site", "same-site", "Cross-Site", ""):
            self.assertEqual(self.post("/say", "text=I+am+the+owner", **{"Sec-Fetch-Site": site})[:2],
                             (403, self.FOREIGN), site)
        self.assertEqual(self.post("/needs/0", "answer=", Origin="https://attacker.example")[:2], (403, self.FOREIGN))
        self.assertEqual(self.post("/secrets", "label=", Origin="https://attacker.example")[:2], (403, self.FOREIGN))
        self.assertEqual(self.ask("DELETE", "/mcp", {"Origin": "https://attacker.example"},
                                  host=f"127.0.0.1:{self.port}")[:2], (403, self.FOREIGN))
        self.assertEqual(self.said(), [])

    def test_the_hub_own_origin_and_no_origin_are_answered(self):
        for headers in ({}, {"Origin": f"http://127.0.0.1:{self.port}"}, {"Origin": f"HTTP://LOCALHOST:{self.port}"},
                        {"Origin": f"http://127.0.0.1:{self.port}", "Sec-Fetch-Site": "same-origin"},
                        {"Sec-Fetch-Site": "none"}):
            self.assertEqual(self.post("/say", "text=", **headers)[0], 303, headers)
        self.assertEqual(self.ask("DELETE", "/mcp", {"Origin": f"http://127.0.0.1:{self.port}"},
                                  host=f"127.0.0.1:{self.port}")[0], 200)

    def test_the_address_check_and_its_own_words_stay_after_the_origin_check(self):
        """A refusal of the address has its own words, so foreign origin always names its cause."""
        hub.TEAM["addresses"]["owner"] = "127.0.0.9"
        status, body, _ = self.post("/say", "text=I+am+the+owner")
        self.assertEqual(status, 403)
        self.assertNotEqual(body, self.FOREIGN)
        hub.TEAM["addresses"]["owner"] = OWNER
        status, body, _ = self.post("/ui/team/reload", '{"request_id": "x"}', Origin=f"http://127.0.0.1:{self.port}")
        self.assertEqual((status, json.loads(body)), (403, {"error": "browser origins are not accepted"}))

    def test_a_kept_alive_connection_works_after_a_refused_origin(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.addCleanup(conn.close)
        conn.request("POST", "/say", "text=I+am+the+owner", {"Origin": "https://attacker.example",
                                                             "Content-Type": "application/x-www-form-urlencoded"})
        answer = conn.getresponse()
        self.assertEqual((answer.status, answer.read().decode()), (403, self.FOREIGN))
        conn.request("GET", "/board.txt")
        answer = conn.getresponse()
        answer.read()
        self.assertEqual(answer.status, 200)

    # ---- the GET routes that write
    def test_a_cross_site_get_that_writes_gets_403(self):
        for path in ("/events/owner?wait=0", "/events/manager?delivery=1&wait=0", "/events/manager", "/sealed/1",
                     "/site/logout", "/site/mfa/expire", "/site/key", "/site/blue", "/site/orange", "/site/price",
                     "/api/price", "/bridge/out?wait=0", "/bridge/config", "/ui/backup?db=x",
                     "/helper/login/manager/1", "/helper/trigger/manager/1/code", "/ui/tasks/1/desktop",
                     "/attachment/file/x", "/google/file/x"):
            for site in ("cross-site", "same-site"):
                self.assertEqual(self.get(path, **{"Sec-Fetch-Site": site})[:2], (403, self.FOREIGN), (path, site))
        self.assertEqual(hub.q("SELECT * FROM hits"), [])

    def test_a_get_that_writes_from_the_hub_or_a_typed_address_or_a_client_is_answered(self):
        for headers in ({}, {"Sec-Fetch-Site": "same-origin"}, {"Sec-Fetch-Site": "none"}):
            self.assertEqual(self.get("/api/price", **headers)[0], 200, headers)
            self.assertEqual(self.get("/events/owner?wait=0", **headers)[0], 200, headers)
        self.assertEqual(len(hub.q("SELECT * FROM hits")), 3)

    def test_a_link_from_another_site_still_opens_a_page_that_writes_nothing(self):
        for path in ("/board", "/board.txt", "/site/login", "/health"):
            self.assertEqual(self.get(path, **{"Sec-Fetch-Site": "cross-site"})[0], 200, path)

    def test_the_get_routes_that_write(self):
        writes = {"events/owner", "sealed/3", "site/logout", "site/mfa/expire", "site/key", "site/blue", "site/orange",
                  "site/price", "api/price", "bridge/out", "bridge/config", "ui/backup", "helper/login/vps/1",
                  "helper/trigger/vps/1/code", "ui/tasks/7/desktop", "attachment/file/1", "google/file/1"}
        reads = {"", "board", "board.txt", "health", "records", "outbox", "keys/vps", "leakcheck", "site/login",
                 "site/account", "site/mfa", "ui/state", "ui/mobile", "join", "worker/install/vps", "server/s1/jobs",
                 "helper/desktop/vps/T-1", "mcp", "events/owner/x", "helper/trigger/vps/1", "attachment/file",
                 "google/file/1/x"}
        for path in writes:
            self.assertTrue(hub.get_writes([p for p in path.split("/") if p]), path)
        for path in reads:
            self.assertFalse(hub.get_writes([p for p in path.split("/") if p]), path)

    # ---- team.json
    def test_validate_team_takes_extra_hosts_and_refuses_anything_else(self):
        team = json.loads(json.dumps(hub.TEAM))
        for good in ([], ["fleet.example.com:8765"], ["10.0.0.5:1", "[fd7a:115c:a1e0::1]:65535", "A-B.example:80"]):
            team["hub"]["extra_hosts"] = good
            hub.validate_team(team)
        for bad in ("fleet.example.com:8765", ["fleet.example.com"], ["fleet.example.com:0"], ["fleet.example.com:65536"],
                    ["http://fleet.example.com:8765"], ["fleet.example.com:8765/"], [8765], ["a b:80"],
                    ["x.example:80"] * (hub.EXTRA_HOSTS_MAX + 1)):
            team["hub"]["extra_hosts"] = bad
            with self.assertRaisesRegex(ValueError, "hub.extra_hosts"):
                hub.validate_team(team)


class RealClients(LocalHub):
    """The clients' own code, each with the hub URL that it makes from team.json, as in production. The hub machine's
    address is 127.1: the socket reaches 127.0.0.1, but 127.1 is no loopback name, so only the team.json rule of
    allowed_hosts can answer it."""

    def setUp(self):
        super().setUp()
        hub.TEAM["addresses"]["hub"] = "127.1"
        hub.TEAM["hub"]["port"] = self.port
        import fleet
        self.fleet = fleet
        self.base = fleet.hub_url({"addresses": hub.TEAM["addresses"], "hub": hub.TEAM["hub"]})
        self.assertEqual(self.base, f"http://127.1:{self.port}")
        address = patch.object(fleet, "HUB", self.base)
        address.start()
        self.addCleanup(address.stop)

    def test_each_client_reaches_the_hub_by_its_team_json_address(self):
        import channels
        import owner_mcp
        import server
        import verify
        self.assertEqual(self.fleet.http_once("GET", "/health", None, 10, None)[0], 200)
        self.assertIn(self.fleet.http_once("POST", "/say", {"text": ""}, 10, None)[0], (200, 303))
        self.assertEqual(verify._fetch(self.base + "/health")[0], 200)
        self.assertEqual(server.Hub(self.base).call("GET", "/health")[0], 200)
        self.assertEqual(channels.request(self.base + "/health")[0], 200)
        self.assertEqual(owner_mcp.call("GET", "/health", base=self.base).status, 200)
        self.assertEqual(self.refused_lines(), [])

    def test_a_name_that_team_json_does_not_give_gets_421(self):
        with patch.object(self.fleet, "HUB", f"http://127.0.1:{self.port}"):     # 127.0.0.1 too, by another name
            self.assertEqual(self.fleet.http_once("GET", "/health", None, 10, None)[0], 421)


class TailnetNames(unittest.TestCase):
    """`tailscale status --json`, with a stand-in tailscale first on PATH."""

    def stand_in(self, script):
        folder = tempfile.mkdtemp(prefix="fleet-tailscale-")
        self.addCleanup(lambda: [os.remove(os.path.join(folder, f)) for f in os.listdir(folder)] and os.rmdir(folder))
        program = os.path.join(folder, "tailscale")
        with open(program, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\n" + script + "\n")
        os.chmod(program, stat.S_IRWXU)
        path = patch.dict(os.environ, {"PATH": folder + os.pathsep + os.environ.get("PATH", "")})
        path.start()
        self.addCleanup(path.stop)

    def test_the_full_and_the_short_name_without_the_final_dot(self):
        self.stand_in("""echo '{"Self": {"DNSName": "Relay-Box-2.tail0000.ts.net."}}'""")
        self.assertEqual(hub.tailnet_names(), ("relay-box-2.tail0000.ts.net", "relay-box-2"))

    def test_no_names_when_tailscale_fails_or_says_nothing_usable(self):
        for script in ("exit 1", "echo 'not json'", """echo '{"Self": {"DNSName": ""}}'""",
                       """echo '{"Self": null}'""", """echo '{"Self": {"DNSName": "a b.example."}}'""", "echo '[]'"):
            self.stand_in(script)
            self.assertEqual(hub.tailnet_names(), (), script)
        with patch.dict(os.environ, {"PATH": tempfile.gettempdir()}), \
                patch.object(hub, "TAILSCALE_APP", os.path.join(tempfile.gettempdir(), "no-tailscale-app")):
            self.assertEqual(hub.tailnet_names(), ())

    def test_a_mac_hub_finds_the_tailscale_of_the_mac_app(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder, True)
        app = os.path.join(folder, "Tailscale")
        with open(app, "w") as f:
            f.write("#!/bin/sh\necho '{\"Self\": {\"DNSName\": \"danas-mac-mini.tail0000.ts.net.\"}}'\n")
        os.chmod(app, stat.S_IRWXU)
        with patch.dict(os.environ, {"PATH": tempfile.gettempdir()}), patch.object(hub, "TAILSCALE_APP", app):
            self.assertEqual(hub.tailnet_names(), ("danas-mac-mini.tail0000.ts.net", "danas-mac-mini"))

    def test_no_names_after_5_seconds(self):
        self.stand_in("sleep 30")
        started = time.monotonic()
        self.assertEqual(hub.tailnet_names(), ())
        self.assertLess(time.monotonic() - started, 10)

    def test_a_reload_keeps_the_names_when_the_lookup_fails(self):
        with patch.dict(hub.TAILNET_NAMES, {"names": ("hub-box",)}), patch.object(hub, "tailnet_names", return_value=()):
            hub.learn_tailnet_names().join(5)
            self.assertEqual(hub.TAILNET_NAMES["names"], ("hub-box",))
        with patch.dict(hub.TAILNET_NAMES, {"names": ()}), patch.object(hub, "tailnet_names", return_value=("a", "b")):
            hub.learn_tailnet_names().join(5)
            self.assertEqual(hub.TAILNET_NAMES["names"], ("a", "b"))

    def test_the_sweep_asks_again_once_a_minute_only_while_there_are_no_names(self):
        asked = []
        with patch.dict(hub.TAILNET_NAMES, {"names": ()}, clear=True), \
                patch.object(hub, "learn_tailnet_names", side_effect=lambda: asked.append(1)):
            hub.names_sweep(1000.0)
            hub.names_sweep(1030.0)         # within the minute: no second lookup
            hub.names_sweep(1061.0)
            self.assertEqual(len(asked), 2)
            hub.TAILNET_NAMES["names"] = ("hub-box",)
            hub.names_sweep(2000.0)         # a hub that has its names asks only at a reload
            self.assertEqual(len(asked), 2)


if __name__ == "__main__":
    unittest.main()

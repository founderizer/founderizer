"""oauth_server.py: the pure parts of the hub's own OAuth server for the remote MCP address. No hub, no database and
no network: the metadata fetch runs against a stand-in resolver and a stand-in connection. Example names only.

python3 -m unittest -v test_oauth_server
"""

import ast
import base64
import hashlib
import json
import os
import unittest
import urllib.parse

import oauth_server as o

N = "hub-1.tail0000.ts.net"
CLAUDE = "https://claude.ai/api/mcp/auth_callback"
CHATGPT = "https://chatgpt.com/connector_platform_oauth_redirect"
CC = o.CLAUDE_CODE
VERIFIER = "a" * 20 + "-._~" + "B" * 30
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()


def good_authorize(**more):
    return dict({"response_type": "code", "code_challenge": CHALLENGE, "code_challenge_method": "S256",
                 "resource": f"https://{N}/mcp", "state": "s-1", "scope": "fleet.read anything"}, **more)


class Stream:
    """A stand-in TLS connection: it keeps what was sent and gives back canned bytes, in pieces."""
    def __init__(self, answer, piece=7):
        self.answer, self.piece, self.sent, self.closed, self.timeouts = answer, piece, b"", False, []

    def settimeout(self, t):
        self.timeouts.append(t)

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        out, self.answer = self.answer[:min(n, self.piece)], self.answer[min(n, self.piece):]
        return out

    def close(self):
        self.closed = True


def answer(body, status="200 OK", head=None):
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
    lines = [f"HTTP/1.1 {status}", "Content-Type: application/json"] + list(head or [])
    if not any(h.lower().startswith(("content-length", "transfer-encoding")) for h in head or []):
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


class Net:
    """A stand-in resolver and connection: what was asked, and in which order."""
    def __init__(self, addresses=("8.8.8.8",), raw=None, fail_connect=()):
        self.addresses, self.raw, self.fail_connect = list(addresses), raw, set(fail_connect)
        self.asked, self.connected, self.stream = [], [], None

    def resolver(self, host, port, timeout):
        self.asked.append((host, port))
        return self.addresses

    def connect(self, address, port, host, timeout):
        self.connected.append((address, port, host))
        if address in self.fail_connect:
            raise OSError("refused")
        self.stream = Stream(self.raw)
        return self.stream


def cimd_doc(client_id=CC, **more):
    return dict({"client_id": client_id, "client_name": "Example Code",
                 "redirect_uris": ["http://localhost/callback", "http://127.0.0.1/callback"],
                 "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
                 "token_endpoint_auth_method": "none"}, **more)


class Documents(unittest.TestCase):
    def test_protected_resource_metadata(self):
        self.assertEqual(o.protected_resource_metadata(N), {
            "resource": f"https://{N}/mcp", "authorization_servers": [f"https://{N}"],
            "scopes_supported": ["fleet.read", "fleet.act"], "bearer_methods_supported": ["header"],
            "resource_name": "Founderizer"})

    def test_authorization_server_metadata(self):
        m = o.authorization_server_metadata(N)
        self.assertEqual(m["issuer"], f"https://{N}")
        for end in ("authorize", "token", "register", "revoke"):
            key = {"authorize": "authorization_endpoint", "token": "token_endpoint",
                   "register": "registration_endpoint", "revoke": "revocation_endpoint"}[end]
            self.assertEqual(m[key], f"https://{N}/{end}")
        self.assertEqual(m["code_challenge_methods_supported"], ["S256"])
        self.assertEqual(m["token_endpoint_auth_methods_supported"], ["none"])
        self.assertEqual(m["revocation_endpoint_auth_methods_supported"], ["none"])
        self.assertEqual(m["grant_types_supported"], ["authorization_code", "refresh_token"])
        self.assertEqual(m["response_types_supported"], ["code"])
        self.assertIs(m["client_id_metadata_document_supported"], True)
        self.assertIs(m["authorization_response_iss_parameter_supported"], True)
        self.assertNotIn("offline_access", m["scopes_supported"])

    def test_a_name_that_is_not_full_is_refused(self):
        for bad in ("hub-1", "HUB-1.tail0000.ts.net", "", None, "hub-1.tail0000.ts.net.", "a..b", "-a.b",
                    "hub 1.example.com", "x" * 64 + ".example.com", "hub-1.example.com/x", "hub-1.example.com:443"):
            with self.assertRaises(ValueError, msg=bad):
                o.issuer(bad)

    def test_www_authenticate(self):
        where = f"https://{N}/.well-known/oauth-protected-resource/mcp"
        self.assertEqual(o.www_authenticate(N), f'Bearer resource_metadata="{where}", scope="fleet.read fleet.act"')
        self.assertEqual(o.www_authenticate(N, insufficient=True),
                         f'Bearer error="insufficient_scope", scope="fleet.read fleet.act", resource_metadata="{where}"')

    def test_host(self):
        for good in (N, N + ":443", N.upper(), "Hub-1.Tail0000.ts.net:443"):
            self.assertTrue(o.host_allowed(good, N), good)
        for bad in ("example.com", N + ":8765", N + ".", "hub-1", "", None, N + ":443:443", "x." + N):
            self.assertFalse(o.host_allowed(bad, N), bad)

    def test_origin(self):
        for path in ("/mcp", "/token", "/register", "/revoke"):
            self.assertTrue(o.origin_allowed(path, "POST", None, N))
            for origin in ("https://example.com", f"https://{N}", "null", ""):
                self.assertFalse(o.origin_allowed(path, "POST", origin, N), (path, origin))
        self.assertTrue(o.origin_allowed("/authorize", "POST", None, N))
        self.assertTrue(o.origin_allowed("/authorize", "POST", f"https://{N}", N))
        for origin in ("https://example.com", "null", f"http://{N}", f"https://{N}:443", f"https://{N}.example.com"):
            self.assertFalse(o.origin_allowed("/authorize", "POST", origin, N), origin)

    def test_answer_headers(self):
        self.assertEqual(o.json_headers()["Cache-Control"], "no-store")
        h = o.html_headers(CLAUDE)
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertEqual(h["Cache-Control"], "no-store")
        self.assertEqual(h["Content-Security-Policy"], "default-src 'none'; style-src 'unsafe-inline'; "
                                                       "form-action 'self' https://claude.ai; frame-ancestors 'none'")
        self.assertIn("form-action 'self' http://localhost:53682;", o.html_headers(
            "http://localhost:53682/callback")["Content-Security-Policy"])
        self.assertIn("form-action 'self';", o.html_headers()["Content-Security-Policy"])
        with self.assertRaises(ValueError):
            o.html_headers("https://claude.ai.example.com/cb")


class Redirects(unittest.TestCase):
    def test_the_list(self):
        self.assertEqual(o.redirect_match(CLAUDE), {"kind": "exact", "name": "Claude", "host": "claude.ai"})
        self.assertEqual(o.redirect_match("https://claude.com/api/mcp/auth_callback")["name"], "Claude")
        self.assertEqual(o.redirect_match(CHATGPT), {"kind": "exact", "name": "ChatGPT", "host": "chatgpt.com"})
        self.assertEqual(o.redirect_match("https://chatgpt.com/connector/oauth/abc_DEF-123"),
                         {"kind": "pattern", "name": "ChatGPT", "host": "chatgpt.com"})
        for uri in ("http://127.0.0.1:53682/callback", "http://localhost/callback", "http://localhost:1/",
                    "http://127.0.0.1:65535/a/b.c"):
            self.assertEqual(o.redirect_match(uri)["kind"], "loopback", uri)

    def test_off_the_list(self):
        for uri in ("https://claude.ai.example.com/cb", "https://chatgpt.com.example.com/cb", "http://10.0.0.1/cb",
                    CLAUDE + "/x", CLAUDE + "?x=1", CLAUDE + "#f", CLAUDE.upper(), "http://claude.ai/api/mcp/auth_callback",
                    "https://claude.ai:443/api/mcp/auth_callback", "https://user@claude.ai/api/mcp/auth_callback",
                    "https://chatgpt.com/connector/oauth/", "https://chatgpt.com/connector/oauth/a/b",
                    "https://chatgpt.com/connector/oauth/" + "a" * 129, "https://chatgpt.com/connector/oauth/a%2F",
                    "http://127.0.0.1:65536/cb", "http://127.0.0.1:0/cb", "http://127.0.0.1:080/cb",
                    "https://127.0.0.1:8080/cb", "http://127.0.0.2/cb", "http://[::1]:8080/cb",
                    "http://localhost.example.com/cb", "http://localhost:8080/cb?x=1", "http://localhost:8080/cb#x",
                    "http://localhost:8080/../cb", "http://localhost:8080/./cb", "http://localhost:8080//cb",
                    "http://user@localhost:8080/cb", "http://localhost", "http://localhost:8080", "", None, 5,
                    "http://localhost:8080/c b", "http://localhost:8080/cb\n"):
            self.assertIsNone(o.redirect_match(uri), uri)

    def test_a_registered_redirect_matches_exactly_or_on_loopback_without_its_port(self):
        self.assertEqual(o.redirect_allowed(CLAUDE, [CLAUDE]), CLAUDE)
        self.assertIsNone(o.redirect_allowed(CLAUDE, [CHATGPT]))
        self.assertIsNone(o.redirect_allowed(CLAUDE, []))
        # Claude Code's own metadata document names its loopback redirects with no port
        reg = ["http://localhost/callback", "http://127.0.0.1/callback"]
        self.assertEqual(o.redirect_allowed("http://localhost:53682/callback", reg), "http://localhost/callback")
        self.assertEqual(o.redirect_allowed("http://127.0.0.1:1234/callback", reg), "http://127.0.0.1/callback")
        self.assertEqual(o.redirect_allowed("http://localhost:9/callback", ["http://localhost:8/callback"]),
                         "http://localhost:8/callback")
        self.assertIsNone(o.redirect_allowed("http://localhost:53682/other", reg))
        self.assertIsNone(o.redirect_allowed("http://127.0.0.1:1/callback", ["http://localhost/callback"]))
        self.assertIsNone(o.redirect_allowed("https://claude.ai.example.com/cb", ["https://claude.ai.example.com/cb"]))
        self.assertIsNone(o.redirect_allowed(CLAUDE, None))

    def test_shown_names(self):
        self.assertEqual(o.shown_name(CLAUDE, "x", "Anything"), "Claude")
        self.assertEqual(o.shown_name(CHATGPT, "x", "Claude"), "ChatGPT")
        self.assertEqual(o.shown_name("http://localhost:1/callback", CC, "Whatever"), "Claude Code")
        self.assertEqual(o.shown_name("http://localhost:1/callback", "x", "My  Tool!\n2"), "My Tool 2")
        self.assertEqual(o.shown_name("http://localhost:1/callback", "x", None), "App")
        self.assertEqual(o.shown_name("http://localhost:1/callback", "x", "!!!"), "App")
        self.assertEqual(o.shown_name("http://localhost:1/callback", "x", "Claude"), "App")
        self.assertEqual(o.shown_name("http://localhost:1/callback", "x", "Official ChatGPT"), "App")
        self.assertEqual(o.shown_name("http://localhost:1/callback", "x", "Сlaude tool"), "laude tool")
        self.assertEqual(len(o.shown_name("http://localhost:1/callback", "x", "a" * 99)), 40)
        # a reserved name, as a whole name in any case and with any spaces, shows as App (fix 7 of the reviews)
        for reserved in ("iPhone", "I Phone", "IPAD", "mac", "Windows", "windows", "PC", "p c", "WhatsApp",
                         "Whats App", "discord", "Owner", "HUB", "Manager", "Founderizer", "Fleet", "App", "a p p",
                         "iPhone!"):
            with self.subTest(reserved=reserved):
                self.assertEqual(o.clean_name(reserved), "")
                self.assertEqual(o.shown_name("http://localhost:1/callback", "x", reserved), "App")
        for kept in ("My Mac tool", "Fleet Watch", "Hubble", "Owners club", "Windows tool", "PC Desk"):
            self.assertEqual(o.shown_name("http://localhost:1/callback", "x", kept), kept)
        with self.assertRaises(ValueError):
            o.shown_name("https://example.com/cb", CC, "x")


class Registration(unittest.TestCase):
    def body(self, **meta):
        return json.dumps(dict({"redirect_uris": [CLAUDE], "client_name": "Example"}, **meta)).encode()

    def refused(self, content_type, body):
        with self.assertRaises(o.Refused) as e:
            o.check_registration(content_type, body)
        return e.exception.status, e.exception.error

    def test_a_good_registration(self):
        meta = o.check_registration("application/json; charset=utf-8", self.body(token_endpoint_auth_method="x"))
        self.assertEqual(meta, {"client_name": "Example", "redirect_uris": [CLAUDE],
                                "grant_types": ["authorization_code", "refresh_token"]})
        client = o.new_client_id()
        self.assertEqual(o.client_kind(client), "dcr")
        self.assertEqual(o.registration_answer(client, meta), {
            "client_id": client, "client_name": "Example", "redirect_uris": [CLAUDE],
            "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
            "token_endpoint_auth_method": "none"})
        self.assertEqual(o.check_registration("application/json", self.body(grant_types=["authorization_code"]))
                         ["grant_types"], ["authorization_code"])

    def test_refusals_in_order(self):
        self.assertEqual(self.refused("text/plain", self.body()), (415, "invalid_client_metadata"))
        self.assertEqual(self.refused(None, self.body()), (415, "invalid_client_metadata"))
        for body in (b"[]", b"not json", b'{"a": 1, "a": 2}', b'{"x": NaN}', b"\xff", b""):
            self.assertEqual(self.refused("application/json", body), (400, "invalid_client_metadata"), body)
        for uris in (None, [], "https://claude.ai/api/mcp/auth_callback", [CLAUDE] * 6, [5],
                     ["https://claude.ai.example.com/cb"], [CLAUDE, "https://chatgpt.com.example.com/cb"],
                     ["http://10.0.0.1/cb"], [CLAUDE + "/x"]):
            body = self.body(redirect_uris=uris) if uris is not None else json.dumps({}).encode()
            self.assertEqual(self.refused("application/json", body), (400, "invalid_redirect_uri"), uris)
        for grants in ([], ["client_credentials"], ["authorization_code", "implicit"], "authorization_code", [1]):
            self.assertEqual(self.refused("application/json", self.body(grant_types=grants)),
                             (400, "invalid_client_metadata"), grants)
        # the order: a bad redirect is named before bad grants
        self.assertEqual(self.refused("application/json", self.body(redirect_uris=["x"], grant_types=["x"])),
                         (400, "invalid_redirect_uri"))


class Cimd(unittest.TestCase):
    def test_the_list(self):
        for good in (CC, "https://chatgpt.com/oauth/client.json", "https://chatgpt.com/oauth/abc-1/client.json",
                     "https://claude.com/oauth/x"):
            self.assertTrue(o.is_cimd(good), good)
            self.assertEqual(o.client_kind(good), "cimd")
        for bad in ("https://example.com/oauth/x", "https://claude.ai.example.com/oauth/x", "http://claude.ai/oauth/x",
                    "https://claude.ai/oauth/", "https://claude.ai/oauth", "https://claude.ai/other/x",
                    "https://claude.ai:443/oauth/x", "https://user@claude.ai/oauth/x", "https://claude.ai@example.com/oauth/x",
                    "https://claude.ai/oauth/../x", "https://claude.ai/oauth/./x", "https://claude.ai/oauth/a/../../x",
                    "https://claude.ai/oauth/x?y=1", "https://claude.ai/oauth/x#y", "https://claude.ai/oauth/%2e%2e/x",
                    "https://claude.ai/oauth//x", "https://CLAUDE.AI/oauth/x", "https://claude.ai/oauth/x ",
                    "https://claude.ai/oauth/" + "x" * 400, None, 5):
            self.assertFalse(o.is_cimd(bad), bad)
            self.assertNotEqual(o.client_kind(bad), "cimd")
        self.assertIsNone(o.client_kind("short"))
        self.assertIsNone(o.client_kind("a" * 44))

    def test_the_documents_that_claude_code_and_chatgpt_publish(self):
        got = o.check_cimd_document(CC, cimd_doc(client_name="Claude Code"))
        self.assertEqual(got["redirect_uris"], ["http://localhost/callback", "http://127.0.0.1/callback"])
        self.assertEqual(got["grant_types"], ["authorization_code", "refresh_token"])
        self.assertEqual(o.shown_name("http://localhost:7/callback", got["client_id"], got["client_name"]),
                         "Claude Code")
        # ChatGPT's document names private_key_jwt first and none as one of its methods, and a grant of its own
        chatgpt = "https://chatgpt.com/oauth/client.json"
        doc = {"client_id": chatgpt, "redirect_uris": [CHATGPT], "token_endpoint_auth_method": "private_key_jwt",
               "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
               "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
               "response_types": ["code"], "client_name": "ChatGPT", "jwks_uri": "https://chatgpt.com/oauth/jwks.json"}
        got = o.check_cimd_document(chatgpt, doc)
        self.assertEqual(got["grant_types"], ["authorization_code", "refresh_token"])
        self.assertEqual(o.shown_name(CHATGPT, chatgpt, got["client_name"]), "ChatGPT")
        self.assertEqual(o.check_cimd_document(CC, {"client_id": CC, "redirect_uris": [CLAUDE]})["grant_types"],
                         ["authorization_code", "refresh_token"])

    def test_document_refusals(self):
        for doc in ([], cimd_doc(client_id=CC + "x"), cimd_doc(client_id=None), cimd_doc(client_secret="s"),
                    cimd_doc(client_secret_expires_at=0), cimd_doc(token_endpoint_auth_method="client_secret_basic"),
                    cimd_doc(token_endpoint_auth_method="private_key_jwt"),
                    cimd_doc(token_endpoint_auth_method=None, token_endpoint_auth_methods_supported=["private_key_jwt"]),
                    cimd_doc(token_endpoint_auth_method="none",
                             token_endpoint_auth_methods_supported=["none", "client_secret_post"]),
                    cimd_doc(token_endpoint_auth_methods_supported="none"), cimd_doc(token_endpoint_auth_method=5),
                    cimd_doc(redirect_uris=[]), cimd_doc(redirect_uris="http://localhost/callback"),
                    cimd_doc(redirect_uris=["http://localhost/callback", "https://example.com/cb"]),
                    cimd_doc(redirect_uris=["http://localhost/callback"] * 51),
                    cimd_doc(grant_types=["refresh_token"]), cimd_doc(grant_types="authorization_code"),
                    cimd_doc(response_types=["token"])):
            with self.assertRaises(o.CimdRefused, msg=doc):
                d = dict(doc) if isinstance(doc, dict) else doc
                if isinstance(d, dict) and d.get("token_endpoint_auth_method", "x") is None:
                    del d["token_endpoint_auth_method"]
                o.check_cimd_document(CC, d)


class Addresses(unittest.TestCase):
    def test_refused(self):
        for a in ("127.0.0.1", "127.9.9.9", "10.1.2.3", "172.16.0.1", "192.168.1.1", "100.100.100.100", "100.64.0.1",
                  "100.127.255.254", "169.254.169.254", "0.0.0.0", "224.0.0.1", "255.255.255.255", "240.0.0.1",
                  "192.0.2.1", "::1", "::", "fe80::1", "fe80::1%en0", "fc00::1", "fd12:3456::1", "ff02::1",
                  "::ffff:127.0.0.1", "::ffff:10.0.0.1", "2002:7f00:1::1", "2002:a00:1::1", "64:ff9b::a00:1",
                  "64:ff9b::7f00:1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:db8::1", "fec0::1", "fec0:1:2::3",
                  "feff:ffff::1", "not an address", "", None):
            self.assertIsNotNone(o.address_refused(a), a)

    def test_site_local_is_refused_by_its_own_rule(self):
        for a in ("fec0::1", "feff:ffff::1"):
            self.assertEqual(o.address_refused(a), "a site-local address", a)
        self.assertNotEqual(o.address_refused("fe80::1"), "a site-local address")

    def test_public(self):
        for a in ("203.0.114.10", "160.79.104.10", "2606:4700::6810:1", "8.8.8.8", "::ffff:8.8.8.8",
                  "64:ff9b::808:808"):
            self.assertIsNone(o.address_refused(a), a)


class Fetch(unittest.TestCase):
    def fetch(self, net, client_id=CC, **kw):
        return o.fetch_cimd(client_id, resolver=net.resolver, connect=net.connect, **kw)

    def test_a_good_fetch(self):
        net = Net(addresses=["8.8.8.8", "8.8.4.4", "8.8.8.8"], raw=answer(cimd_doc()))
        got = self.fetch(net)
        self.assertEqual(got["client_id"], CC)
        self.assertEqual(net.asked, [("claude.ai", 443)])
        self.assertEqual(net.connected, [("8.8.8.8", 443, "claude.ai")])
        sent = net.stream.sent.decode()
        self.assertTrue(sent.startswith("GET /oauth/claude-code-client-metadata HTTP/1.1\r\nHost: claude.ai\r\n"))
        self.assertIn("User-Agent: founderizer-hub\r\n", sent)
        self.assertIn("Accept: application/json\r\n", sent)
        self.assertIn("Connection: close\r\n", sent)
        self.assertTrue(net.stream.closed)

    def test_the_next_checked_address_when_one_does_not_connect(self):
        net = Net(addresses=["8.8.8.8", "8.8.4.4"], raw=answer(cimd_doc()), fail_connect={"8.8.8.8"})
        self.fetch(net)
        self.assertEqual([c[0] for c in net.connected], ["8.8.8.8", "8.8.4.4"])

    def test_a_chunked_answer(self):
        body = json.dumps(cimd_doc()).encode()
        chunks = b"".join(b"%x;ext=1\r\n%s\r\n" % (len(body[i:i + 50]), body[i:i + 50]) for i in range(0, len(body), 50))
        raw = answer(chunks + b"0\r\nX-Trailer: y\r\n\r\n", head=["Transfer-Encoding: chunked"])
        self.assertEqual(self.fetch(Net(raw=raw))["client_id"], CC)

    def test_a_private_address_is_refused_before_any_connection(self):
        for a in ("127.0.0.1", "10.1.2.3", "100.100.100.100", "169.254.169.254", "::1", "0.0.0.0", "::ffff:10.0.0.1"):
            net = Net(addresses=["8.8.8.8", a], raw=answer(cimd_doc()))
            with self.assertRaises(o.CimdRefused, msg=a):
                self.fetch(net)
            self.assertEqual(net.connected, [], a)

    def test_refusals(self):
        def refused(net, client_id=CC, **kw):
            with self.assertRaises(o.CimdRefused) as e:
                self.fetch(net, client_id, **kw)
            return str(e.exception)

        # off the list: nothing is resolved
        net = Net(raw=answer(cimd_doc()))
        refused(net, "https://example.com/oauth/x")
        refused(net, "http://claude.ai/oauth/x")
        self.assertEqual(net.asked, [])
        self.assertIn("redirect", refused(Net(raw=answer(b"", "302 Found", ["Location: https://example.com/x"]))))
        self.assertIn("404", refused(Net(raw=answer(cimd_doc(), "404 Not Found"))))
        self.assertIn("too large", refused(Net(raw=answer(b'{"a": "' + b"x" * (64 * 1024) + b'"}'))))
        self.assertIn("too large", refused(Net(raw=answer(b"x" * 10, head=[f"Content-Length: {64 * 1024 + 1}"]))))
        self.assertIn("too large", refused(Net(raw=answer(b'{"a": 1}')), limit=4))
        self.assertIn("not JSON", refused(Net(raw=answer(b"<html>", head=["Content-Type: text/html"])
                                              .replace(b"Content-Type: application/json\r\n", b""))))
        self.assertIn("JSON object", refused(Net(raw=answer(b"[1]"))))
        self.assertIn("JSON object", refused(Net(raw=answer(b"{bad"))))
        self.assertIn("client_id", refused(Net(raw=answer(cimd_doc(client_id=CC + "-other")))))
        self.assertIn("redirect list", refused(Net(raw=answer(cimd_doc(redirect_uris=["https://example.com/cb"])))))
        self.assertIn("compressed", refused(Net(raw=answer(b"x", head=["Content-Encoding: gzip"]))))
        self.assertIn("framing", refused(Net(raw=answer(b"x", head=["Transfer-Encoding: chunked", "Content-Length: 1"]))))
        self.assertIn("two times", refused(Net(raw=answer(b"x", head=["Content-Length: 1", "Content-Length: 1"]))))
        self.assertIn("ended early", refused(Net(raw=answer(b"x", head=["Content-Length: 5"]))))
        self.assertIn("chunks", refused(Net(raw=answer(b"zz\r\nx\r\n0\r\n\r\n", head=["Transfer-Encoding: chunked"]))))
        self.assertIn("not HTTP", refused(Net(raw=b"SSH-2.0-x\r\n\r\n")))
        self.assertIn("complete head", refused(Net(raw=b"HTTP/1.1 200 OK\r\n" + b"X: y\r\n" * 4000)))
        self.assertIn("no address", refused(Net(addresses=[])))
        self.assertIn("cannot be reached", refused(Net(addresses=["8.8.8.8"], fail_connect={"8.8.8.8"})))

    def test_a_resolver_that_fails(self):
        class Failing(Net):
            def resolver(self, host, port, timeout):
                raise OSError("no answer")
        with self.assertRaises(o.CimdRefused):
            self.fetch(Failing(raw=b""))

    def test_the_deadline_covers_the_whole_fetch(self):
        ticks = iter(range(0, 1000, 2))           # each read of the clock is 2 seconds later
        net = Net(raw=answer(cimd_doc()))
        with self.assertRaises(o.CimdRefused) as e:
            self.fetch(net, clock=lambda: next(ticks))
        self.assertIn("5 seconds", str(e.exception))

    def test_a_server_that_never_ends_is_cut(self):
        class Endless(Stream):
            def recv(self, n):
                return b"x" * n

        class EndlessNet(Net):
            def connect(self, address, port, host, timeout):
                return Endless(b"")
        with self.assertRaises(o.CimdRefused) as e:
            self.fetch(EndlessNet())
        self.assertIn("too large", str(e.exception))

    def test_a_stream_that_fails_while_it_is_read(self):
        class Broken(Stream):
            def recv(self, n):
                raise ConnectionResetError("cut")

        class BrokenNet(Net):
            def connect(self, address, port, host, timeout):
                self.stream = Broken(b"")
                return self.stream
        net = BrokenNet()
        with self.assertRaises(o.CimdRefused):
            self.fetch(net)
        self.assertTrue(net.stream.closed)


class Authorize(unittest.TestCase):
    def test_a_good_request(self):
        self.assertEqual(o.check_authorize(good_authorize(), N),
                         {"state": "s-1", "code_challenge": CHALLENGE, "resource": f"https://{N}/mcp"})
        params = good_authorize()
        del params["state"], params["scope"]
        self.assertIsNone(o.check_authorize(params, N)["state"])

    def test_refusals_in_order(self):
        def error(**more):
            with self.assertRaises(o.Refused) as e:
                o.check_authorize(good_authorize(**more), N)
            return e.exception.error
        self.assertEqual(error(response_type="token"), "unsupported_response_type")
        self.assertEqual(error(response_type="token", code_challenge_method="plain"), "unsupported_response_type")
        self.assertEqual(error(code_challenge_method="plain"), "invalid_request")
        self.assertEqual(error(code_challenge_method=None), "invalid_request")
        self.assertEqual(error(code_challenge="a" * 42), "invalid_request")
        self.assertEqual(error(code_challenge="a" * 129), "invalid_request")
        self.assertEqual(error(code_challenge="a" * 42 + "="), "invalid_request")
        self.assertEqual(error(code_challenge_method="plain", resource="x"), "invalid_request")
        for bad in (None, "", f"https://{N}/mcp/", f"https://{N}", f"https://{N}:443/mcp", f"http://{N}/mcp",
                    f"https://{N}/MCP", f"https://{N}/mcp?x=1", f"https://{N}/mcp#x", f"https://u@{N}/mcp",
                    "https://example.com/mcp", f"https://{N}.example.com/mcp", f" https://{N}/mcp"):
            self.assertEqual(error(resource=bad), "invalid_target", bad)
        self.assertEqual(error(state="x" * 1001), "invalid_request")

    def test_the_resource_in_any_case_of_scheme_and_host(self):
        self.assertTrue(o.resource_matches(f"HTTPS://{N.upper()}/mcp", N))

    def test_the_redirects_of_an_answer(self):
        url = o.code_redirect(CLAUDE, "c0de", "a b&c", N)
        self.assertEqual(url, CLAUDE + "?code=c0de&state=a+b%26c&iss=https%3A%2F%2F" + N)
        self.assertEqual(o.code_redirect(CLAUDE, "c", None, N), CLAUDE + f"?code=c&iss=https%3A%2F%2F{N}")
        err = urllib.parse.urlsplit(o.error_redirect("http://localhost:7/callback", "invalid_target", "s", N))
        self.assertEqual(urllib.parse.parse_qs(err.query), {"error": ["invalid_target"], "state": ["s"],
                                                            "iss": [f"https://{N}"]})
        for fn in (o.code_redirect, o.error_redirect):
            with self.assertRaises(ValueError):
                fn("https://claude.ai.example.com/cb", "x", "s", N)

    def test_fields(self):
        self.assertEqual(o.parse_query("a=1&b=&c=%20x"), {"a": "1", "b": "", "c": " x"})
        self.assertEqual(o.parse_form("application/x-www-form-urlencoded; charset=UTF-8", b"grant_type=x"),
                         {"grant_type": "x"})
        for bad in ("a=1&a=2", "&".join(f"k{i}=1" for i in range(31)), b"a=\xff", "a=%ff"):
            with self.assertRaises(o.Refused) as e:
                o.parse_query(bad)
            self.assertEqual((e.exception.status, e.exception.error), (400, "invalid_request"), bad)
        for kind in ("application/json", "multipart/form-data", None, ""):
            with self.assertRaises(o.Refused) as e:
                o.parse_form(kind, b"a=1")
            self.assertEqual(e.exception.status, 415)


class Pkce(unittest.TestCase):
    def test_s256(self):
        # RFC 7636 appendix B
        self.assertEqual(o.s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
                         "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        self.assertTrue(o.verifier_matches(VERIFIER, CHALLENGE))

    def test_refusals(self):
        self.assertFalse(o.verifier_matches(VERIFIER + "x", CHALLENGE))
        self.assertFalse(o.verifier_matches("a" * 42, o.s256("a" * 42)))         # under 43
        self.assertFalse(o.verifier_matches("a" * 129, o.s256("a" * 129)))       # over 128
        self.assertFalse(o.verifier_matches("a" * 42 + "+", o.s256("a" * 42 + "+")))
        self.assertFalse(o.verifier_matches(CHALLENGE, CHALLENGE))               # plain is no method here
        self.assertFalse(o.verifier_matches(None, CHALLENGE))
        self.assertFalse(o.verifier_matches(VERIFIER, None))
        self.assertTrue(o.verifier_matches("a" * 128, o.s256("a" * 128)))
        self.assertTrue(o.check_challenge(CHALLENGE, "S256"))
        self.assertFalse(o.check_challenge(CHALLENGE, "plain"))
        self.assertFalse(o.check_challenge(CHALLENGE, None))
        self.assertFalse(o.check_challenge(None, "S256"))


class Secrets(unittest.TestCase):
    def test_tokens(self):
        raw, sha = o.new_secret()
        self.assertGreaterEqual(len(raw), 43)
        self.assertEqual(sha, hashlib.sha256(raw.encode()).hexdigest())
        self.assertNotEqual(o.new_secret()[0], raw)
        self.assertEqual(o.token_answer("A", "R", "read"), {"access_token": "A", "token_type": "Bearer",
                                                             "expires_in": 3600, "refresh_token": "R",
                                                             "scope": "fleet.read"})
        self.assertEqual(o.scope_of("act"), "fleet.read fleet.act")
        with self.assertRaises(ValueError):
            o.scope_of("full")

    def test_the_one_time_code(self):
        made = o.new_code()
        self.assertRegex(made["code"], r"^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$")
        self.assertEqual(o.code_sha256(made["code"]), made["sha256"])
        self.assertEqual(o.code_sha256(made["code"].lower().replace("-", "")), made["sha256"])
        self.assertEqual(o.code_sha256(" " + made["code"][:2] + "-" + made["code"][2:] + " "), made["sha256"])
        self.assertEqual(o.normal_code("abcd-efgh-jklm"), "ABCDEFGHJKLM")
        for bad in ("ABCD-EFGH", "ABCD-EFGH-JKL", "ABCD-EFGH-JKLMN", "ABCD-EFGH-JKL1", "ABCD-EFGH-JKLO", "", None,
                    "A" * 65, 123456789012):
            self.assertEqual(o.normal_code(bad), "", bad)
            self.assertIsNone(o.code_sha256(bad), bad)
        self.assertEqual(o.CODE_LENGTH * 5, 60)         # 60 bits: no count of wrong tries (fix 4 of the reviews)
        self.assertEqual(len(set(o.CODE_ALPHABET)), 32)
        self.assertFalse(hasattr(o, "CODE_TRIES"))

    def test_the_handle_of_a_sign_in_page(self):
        key, fields = b"k" * 32, {"client": "c", "redirect_uri": CLAUDE, "state": "s \u00e9", "code_challenge": CHALLENGE,
                                   "resource": f"https://{N}/mcp", "name": "Claude", "redirect_uris": None}
        handle = o.make_handle(key, fields, 1000.0)
        self.assertEqual(o.read_handle(key, handle, 1000.0 + o.HANDLE_LIFE), dict(fields, made=1000.0))
        self.assertIsNone(o.read_handle(key, handle, 1000.0 + o.HANDLE_LIFE + 1))       # too old
        self.assertIsNone(o.read_handle(key, handle, 900.0))                             # from the future
        self.assertIsNone(o.read_handle(b"j" * 32, handle, 1000.0))                      # another key
        text, _, mac = handle.partition(".")
        changed = o._b64(o._unb64(text).replace(b'"Claude"', b'"Clause"')) + "." + mac
        for bad in (changed, handle + "x", handle.replace(".", ""), None, "", "a.b", "." * 3):
            self.assertIsNone(o.read_handle(key, bad, 1000.0), bad)
        self.assertNotIn(key.decode(), handle)
        self.assertIsNone(o.make_handle(key, dict(fields, redirect_uris=["http://localhost/" + "a" * 380] * 50), 1.0))


class Module(unittest.TestCase):
    def test_standard_library_only_and_no_hub(self):
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "oauth_server.py"), encoding="utf-8") as f:
            tree = ast.parse(f.read())
        names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | \
            {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        self.assertEqual(names - {"base64", "hashlib", "hmac", "ipaddress", "json", "re", "secrets", "socket", "ssl",
                                  "threading", "time", "urllib"}, set())


if __name__ == "__main__":
    unittest.main()

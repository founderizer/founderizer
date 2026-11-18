"""Tests of mcp.py against a stand-in MCP server on 127.0.0.1 (UI-API.md, "Custom MCP servers").

python3 -m unittest -v test_mcp_api
"""

import hashlib
import json
import unittest
import urllib.parse

import mcp
from test_google_api import StandIn, close, form, body

ACCESS, REFRESH, SECRET, CODE = "mcp-ACCESS-TOKEN", "mcp-REFRESH-TOKEN", "mcp-CLIENT-SECRET", "mcp-AUTH-CODE"
SECRETS = (ACCESS, REFRESH, SECRET, CODE)
CLIENT = "client-abc123"
TOOLS = {"tools": [{"name": "crm_orders", "description": "x"}, {"name": "crm_stores"}, {"bad": 1}]}


class McpApiTest(unittest.TestCase):
    def setUp(self):
        self.s = StandIn()
        self.saved = mcp.TIMEOUT
        mcp.TIMEOUT = 5
        self.addCleanup(self.s.close)
        self.addCleanup(setattr, mcp, "TIMEOUT", self.saved)

    def tearDown(self):
        for req in self.s.requests:
            self.assertEqual(req["headers"]["User-Agent"], "founderizer-hub")
            for secret in SECRETS:          # a secret goes in a form body or a header, never in a path or a query
                self.assertNotIn(secret, req["path"] + str(req["query"]))

    def metadata(self, **fields):
        """The two metadata documents of a server that protects itself."""
        self.s.on("GET", "/.well-known/oauth-protected-resource",
                  {"resource": self.s.url, "authorization_servers": [self.s.url], "scopes_supported": ["crm"]})
        self.s.on("GET", "/.well-known/oauth-authorization-server", dict({
            "issuer": self.s.url, "authorization_endpoint": self.s.url + "/oauth/authorize",
            "token_endpoint": self.s.url + "/oauth/token", "registration_endpoint": self.s.url + "/oauth/register",
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"]}, **fields))

    def refused(self, call, *a, **kw):
        with self.assertRaises(mcp.McpError) as caught:
            call(*a, **kw)
        for text in (str(caught.exception), repr(caught.exception), str(caught.exception.args)):
            for secret in SECRETS:
                self.assertNotIn(secret, text)
        return caught.exception

    # ---- the addresses that the hub takes
    def test_only_https_and_the_loopback_address_are_taken(self):
        for url in ("https://mcp.example.com/", "https://mcp.example.com/mcp?x=1", "http://127.0.0.1:5015/mcp",
                    "http://localhost:3000/"):
            self.assertEqual(mcp.address(url), url)
        for url in ("http://mcp.example.com/", "ftp://mcp.example.com/", "https://u:p@mcp.example.com/",
                    "https://mcp.example.com/#frag", "https://", "/mcp", "https://a b/", "x" * 500, 7, None):
            self.assertIsNone(mcp.address(url))
        self.assertIsNone(mcp.address("https://other.example.com/", host="mcp.example.com"))

    # ---- discovery
    def test_the_server_names_its_authorization_server_and_its_endpoints(self):
        self.metadata()
        found = mcp.discover(self.s.url + "/mcp")
        self.assertEqual((found["issuer"], found["authorization_endpoint"], found["token_endpoint"],
                          found["registration_endpoint"], found["scopes"], found["resource"]),
                         (self.s.url, self.s.url + "/oauth/authorize", self.s.url + "/oauth/token",
                          self.s.url + "/oauth/register", ["crm"], self.s.url))
        self.assertEqual(found["grants"], ["authorization_code", "refresh_token"])

    def test_a_server_with_a_path_is_asked_for_both_well_known_forms(self):
        self.s.on("GET", "/.well-known/oauth-protected-resource/mcp",
                  {"resource": self.s.url + "/mcp", "authorization_servers": [self.s.url]})
        self.s.on("GET", "/.well-known/oauth-authorization-server",
                  {"issuer": self.s.url, "authorization_endpoint": self.s.url + "/a", "token_endpoint": self.s.url + "/t"})
        found = mcp.discover(self.s.url + "/mcp")
        self.assertEqual(found["resource"], self.s.url + "/mcp")
        self.assertEqual([r["path"] for r in self.s.requests][:1], ["/.well-known/oauth-protected-resource/mcp"])

    def test_without_a_resource_document_the_server_is_its_own_authorization_server(self):
        self.s.on("GET", "/.well-known/openid-configuration",
                  {"issuer": self.s.url, "authorization_endpoint": self.s.url + "/a", "token_endpoint": self.s.url + "/t"})
        found = mcp.discover(self.s.url + "/mcp")
        self.assertEqual((found["issuer"], found["token_endpoint"], found["scopes"], found["resource"]),
                         (self.s.url, self.s.url + "/t", [], None))

    def test_discovery_refuses_a_server_without_oauth_or_with_an_endpoint_on_another_host(self):
        self.assertIn("no OAuth metadata", str(self.refused(mcp.discover, self.s.url + "/mcp")))
        self.s.on("GET", "/.well-known/oauth-authorization-server",
                  {"issuer": self.s.url, "authorization_endpoint": "https://evil.example.com/a",
                   "token_endpoint": self.s.url + "/t"})
        self.assertIn("gives no authorization and token endpoint", str(self.refused(mcp.discover, self.s.url)))
        self.metadata(grant_types_supported=["client_credentials"])
        self.assertIn("does not take an authorization code", str(self.refused(mcp.discover, self.s.url)))
        self.assertIn("must be https", str(self.refused(mcp.discover, "http://mcp.example.com/")))

    # ---- the hub as a client of the server
    def test_the_hub_registers_itself_and_takes_a_public_client(self):
        self.s.on("POST", "/oauth/register", {"client_id": CLIENT, "client_id_issued_at": 1})
        got = mcp.register(self.s.url + "/oauth/register", "http://127.0.0.1:53111/", scopes=["crm"])
        self.assertEqual(got, {"client_id": CLIENT, "client_secret": None})
        sent = body(self.s.find("POST", "/oauth/register")[0])
        self.assertEqual((sent["redirect_uris"], sent["grant_types"], sent["response_types"],
                          sent["token_endpoint_auth_method"], sent["scope"]),
                         (["http://127.0.0.1:53111/"], ["authorization_code", "refresh_token"], ["code"], "none", "crm"))
        self.s.on("POST", "/oauth/register", {"client_id": CLIENT, "client_secret": SECRET})
        self.assertEqual(mcp.register(self.s.url + "/oauth/register", "http://127.0.0.1:1/")["client_secret"], SECRET)
        # A server that has the authorization code only: the registration asks for that grant alone.
        mcp.register(self.s.url + "/oauth/register", "http://127.0.0.1:1/", grants=["authorization_code"])
        self.assertEqual(body(self.s.find("POST", "/oauth/register")[-1])["grant_types"], ["authorization_code"])
        self.s.on("POST", "/oauth/register", {"error": "invalid_redirect_uri"}, status=400)
        e = self.refused(mcp.register, self.s.url + "/oauth/register", "http://127.0.0.1:1/")
        self.assertEqual((e.status, e.reason), (400, "invalid_redirect_uri"))

    def test_the_consent_address_asks_for_this_server_with_pkce(self):
        verifier, challenge = mcp.pkce()
        self.assertEqual(challenge, mcp.base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode())
        url = mcp.consent_url("https://mcp.example.com/oauth/authorize?v=1", CLIENT, "http://127.0.0.1:53111/",
                              "state-1", challenge, scopes=["crm", "x"], resource="https://mcp.example.com/")
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        self.assertTrue(url.startswith("https://mcp.example.com/oauth/authorize?v=1&"))
        self.assertEqual(query, {"v": "1", "client_id": CLIENT, "redirect_uri": "http://127.0.0.1:53111/",
                                 "response_type": "code", "state": "state-1", "code_challenge": challenge,
                                 "code_challenge_method": "S256", "scope": "crm x",
                                 "resource": "https://mcp.example.com/"})

    # ---- the owner's tokens
    def test_the_code_becomes_a_refresh_token_and_the_secret_goes_only_in_the_body(self):
        self.s.on("POST", "/oauth/token", {"access_token": ACCESS, "refresh_token": REFRESH, "expires_in": 1800,
                                           "scope": "crm", "token_type": "Bearer"})
        got = mcp.exchange(self.s.url + "/oauth/token", CLIENT, SECRET, CODE, "verifier-1",
                           "http://127.0.0.1:53111/", resource=self.s.url)
        self.assertEqual((got["access_token"], got["refresh_token"], got["scopes"]), (ACCESS, REFRESH, ["crm"]))
        self.assertTrue(0 < got["expires_at"] - mcp.time.time() <= 1800)
        sent = form(self.s.find("POST", "/oauth/token")[0])
        self.assertEqual(sent, {"grant_type": "authorization_code", "client_id": CLIENT, "client_secret": SECRET,
                                "code": CODE, "code_verifier": "verifier-1", "redirect_uri": "http://127.0.0.1:53111/",
                                "resource": self.s.url})
        # A server that gives no refresh token (an authorization_code server) gives a long access token instead.
        self.s.on("POST", "/oauth/token", {"access_token": ACCESS, "expires_in": 365 * 24 * 3600, "scope": "mcp:tickets"})
        kept = mcp.exchange(self.s.url + "/oauth/token", CLIENT, None, CODE, "v", "http://127.0.0.1:1/")
        self.assertEqual((kept["refresh_token"], kept["scopes"]), (None, ["mcp:tickets"]))
        self.assertGreater(kept["expires_at"] - mcp.time.time(), 360 * 24 * 3600)
        self.s.on("POST", "/oauth/token", {"access_token": ACCESS, "expires_in": 900 * 24 * 3600})
        self.assertLess(mcp.exchange(self.s.url + "/oauth/token", CLIENT, None, CODE, "v",
                                     "http://127.0.0.1:1/")["expires_at"] - mcp.time.time(), 3700)
        self.s.on("POST", "/oauth/token", {"token_type": "Bearer"})
        self.assertIn("gave no access token", str(self.refused(
            mcp.exchange, self.s.url + "/oauth/token", CLIENT, None, CODE, "v", "http://127.0.0.1:1/")))

    def test_a_refresh_keeps_the_saved_token_until_the_server_rotates_it(self):
        self.s.on("POST", "/oauth/token", {"access_token": ACCESS, "expires_in": 3600})
        got = mcp.refresh(self.s.url + "/oauth/token", CLIENT, None, REFRESH, resource=self.s.url, scopes=["crm"])
        self.assertEqual((got["access_token"], got["refresh_token"]), (ACCESS, REFRESH))
        self.assertNotIn("client_secret", form(self.s.find("POST", "/oauth/token")[0]))
        self.s.on("POST", "/oauth/token", {"access_token": ACCESS, "refresh_token": "second-" + REFRESH})
        self.assertEqual(mcp.refresh(self.s.url + "/oauth/token", CLIENT, SECRET, REFRESH)["refresh_token"],
                         "second-" + REFRESH)
        self.s.on("POST", "/oauth/token", {"error": "invalid_grant", "error_description": "expired"}, status=400)
        e = self.refused(mcp.refresh, self.s.url + "/oauth/token", CLIENT, SECRET, REFRESH)
        self.assertEqual((e.status, e.reason, e.unknown), (400, "invalid_grant", False))
        self.assertIn("expired", str(e))

    # ---- what a server says about itself
    def test_a_check_initializes_the_session_lists_the_tools_and_ends_it(self):
        session, numbers = "session-1", []

        def answer(handler, req):
            sent = json.loads(req["body"])
            numbers.append((sent.get("method"), req["headers"].get("Mcp-Session-Id"),
                            req["headers"].get("MCP-Protocol-Version")))
            result = {"protocolVersion": "2025-06-18", "serverInfo": {"name": "crm-mcp", "version": "1.4"}} \
                if sent["method"] == "initialize" else TOOLS
            data = json.dumps({"jsonrpc": "2.0", "id": sent.get("id"), "result": result}).encode()
            handler.send_response(200)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("mcp-session-id", session)       # the case that the MCP SDK sends
            handler.send_header("Content-Length", str(len(data)))
            handler.end_headers()
            handler.wfile.write(data)

        self.s.on("POST", "/mcp", answer)
        self.s.on("DELETE", "/mcp", None, status=204)
        got = mcp.check(self.s.url + "/mcp", ACCESS)
        self.assertEqual(got, {"server": "crm-mcp", "version": "1.4", "tools": ["crm_orders", "crm_stores"],
                               "note": None})
        self.assertEqual(numbers, [("initialize", None, "2025-06-18"),
                                   ("notifications/initialized", session, "2025-06-18"),
                                   ("tools/list", session, "2025-06-18")])
        self.assertEqual(len(self.s.find("DELETE", "/mcp")), 1)         # the hub keeps no session
        self.assertEqual(self.s.requests[0]["headers"]["Authorization"], "Bearer " + ACCESS)

    def test_a_check_reads_an_event_stream_answer_and_a_server_without_tools_is_still_connected(self):
        first = ("event: message\r\n"
                 'data: {"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"public","version":"2"}}}\r\n\r\n')
        self.s.on("POST", "/mcp", first.encode(), headers={"Content-Type": "text/event-stream"})
        got = mcp.check(self.s.url + "/mcp")
        self.assertEqual((got["server"], got["version"], got["tools"], got["note"]), ("public", "2", [], None))
        self.assertIsNone(self.s.requests[0]["headers"].get("Authorization"))

    def test_a_server_that_wants_its_session_header_gives_its_reason_as_a_note(self):
        def answer(handler, req):
            sent = json.loads(req["body"] or b"{}")
            if sent.get("method") != "initialize":      # as the MCP SDK answers a call without its session header
                refusal = json.dumps({"error": {"code": "bad_request",
                                                "message": "MCP session initialization is required."}}).encode()
                handler.send_response(400)
                handler.send_header("Content-Type", "application/json")
                handler.send_header("Content-Length", str(len(refusal)))
                handler.end_headers()
                return handler.wfile.write(refusal)
            data = json.dumps({"jsonrpc": "2.0", "id": 1,
                               "result": {"serverInfo": {"name": "crm", "version": "1"}}}).encode()
            handler.send_response(200)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(data)))
            handler.end_headers()
            handler.wfile.write(data)

        self.s.on("POST", "/mcp", answer)
        got = mcp.check(self.s.url + "/mcp", ACCESS)        # no session header came back: the server says why
        self.assertEqual((got["server"], got["tools"]), ("crm", []))
        self.assertIn("session initialization is required", got["note"])

    def test_a_server_that_wants_a_connect_or_refuses_gives_its_status(self):
        self.s.on("POST", "/mcp", {"error": "invalid_token"}, status=401)
        self.assertEqual(self.refused(mcp.check, self.s.url + "/mcp", ACCESS).status, 401)
        self.s.on("POST", "/mcp", {"jsonrpc": "2.0", "id": 1,
                                   "error": {"code": -32000, "message": "no access to this tool"}})
        e = self.refused(mcp.check, self.s.url + "/mcp", ACCESS)
        self.assertEqual((e.reason, e.status), ("-32000", None))
        self.assertIn("no access to this tool", str(e))

    def test_a_redirect_is_an_answer_and_a_lost_answer_is_unknown(self):
        self.s.on("POST", "/oauth/token", None, status=302, headers={"Location": "https://evil.example.com/"})
        self.assertEqual(self.refused(mcp.refresh, self.s.url + "/oauth/token", CLIENT, None, REFRESH).status, 302)
        self.s.on("POST", "/oauth/token", close)
        self.assertTrue(self.refused(mcp.refresh, self.s.url + "/oauth/token", CLIENT, None, REFRESH).unknown)


if __name__ == "__main__":
    unittest.main()

"""Custom MCP servers (owner feature mcp): team.json, the owner routes, the hub's MCP file and Connect, the access
tokens of a task session, and the servers in a Claude or Codex session. The real mcp.py runs against a stand-in MCP
server on 127.0.0.1, so no call leaves this machine. Temporary folders and local git repositories only; no real hub,
~/.fleet or AI call.

python3 -m unittest -v test_mcp
"""

import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid

import fleet
import hub
import lifecycle
import mcp
from test_google_api import StandIn, body, form
from test_integrations import git
from test_ui_api import OwnerAPI

CODEX = "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "w1": "127.0.0.3", "w2": "127.0.0.4"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "dev": {"role": "worker", "runtime": "claude", "machine": "w1", "can": ["shell"]},
                   "ops": {"role": "worker", "runtime": "codex", "machine": "w2", "can": ["shell"], "start": CODEX}}}
CLAUDE = {"role": "worker", "runtime": "claude", "machine": "w1", "can": ["shell"], "allow": ["mcp__fleet__*"],
          "start": "claude --permission-mode dontAsk {chrome} {settings} {prompt}"}
CODEX_CONF = {"role": "worker", "runtime": "codex", "machine": "w2", "can": ["shell"], "start": CODEX}
SESSION = "11111111-2222-4333-8444-555555555555"
CRM = {"title": "Acme CRM", "url": "https://mcp.example.org/", "auth": "oauth"}
KEYED = {"title": "Shop", "url": "https://shop.example.com/mcp", "auth": "key", "key": "SHOP_KEY"}
LOCAL = {"title": "Notes", "command": "notes-mcp", "runtimes": ["claude"]}     # no args: DevOps plan 0.2
ACCESS, ACCESS2, REFRESH, SECRET, CODE = "mcp-ACCESS", "mcp-ACCESS-2", "mcp-REFRESH-TOKEN", "mcp-CLIENT-SECRET", "mcp-CODE"
CLIENT = "client-abc123"
TOKEN = "FLEET_MCP_CRM"


def load_tests(loader, _tests, _pattern):
    """HubSide keeps the order of its methods: each one builds on the team.json of the one before."""
    suite = unittest.TestSuite(HubSide(name) for name in HubSide.__dict__ if name.startswith("test_"))
    suite.addTests(loader.loadTestsFromTestCase(HelperSide))
    return suite


class HubSide(OwnerAPI):
    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="fleet-mcp-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        seed = self.root / "seed"
        seed.mkdir()
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", str(self.root / "origin.git"), str(self.root / "kit"))
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = json.loads(json.dumps(TEAM))
        self.stand = StandIn()                  # the stand-in MCP server; self.server is the hub's own
        self.addCleanup(self.stand.close)
        self.file = self.root / "mcp.json"
        for key, value in (("team_path", str(self.root / "kit" / "team.json")), ("mcp_file", str(self.file))):
            hub.CFG[key] = value
            self.addCleanup(hub.CFG.pop, key, None)
        hub.MCP.update(tokens={}, problems={}, pending=None, probes={})
        self.addCleanup(hub.MCP.update, tokens={}, problems={}, pending=None, probes={})
        allowed = patch.object(hub.Handler, "allowed", lambda handler, who, broker=False: True)
        allowed.start()
        self.addCleanup(allowed.stop)
        timeout = patch.object(mcp, "TIMEOUT", 5)
        timeout.start()
        self.addCleanup(timeout.stop)

    # ---- helpers
    def sha(self):
        return self.request("/ui/team?db=test-generation")[1]["sha256"]

    def save(self, route, **fields):
        return self.request(route, dict(request_id=str(uuid.uuid4()), db="test-generation", base_sha256=self.sha(),
                                        **fields))

    def post(self, route, **fields):
        return self.request(route, dict(request_id=str(uuid.uuid4()), db="test-generation", **fields))

    def view(self):
        return self.request("/ui/team?db=test-generation")[1]

    def origin_team(self):
        return json.loads(git("--git-dir", str(self.root / "origin.git"), "show", "main:team.json"))

    def oauth(self, register=True, token=None):
        """The stand-in server as an MCP server that protects itself: its metadata, its registration and its tokens."""
        self.stand.on("GET", "/.well-known/oauth-protected-resource",
                       {"resource": self.stand.url + "/mcp", "authorization_servers": [self.stand.url],
                        "scopes_supported": ["crm"]})
        self.stand.on("GET", "/.well-known/oauth-authorization-server", {
            "issuer": self.stand.url, "authorization_endpoint": self.stand.url + "/oauth/authorize",
            "token_endpoint": self.stand.url + "/oauth/token",
            **({"registration_endpoint": self.stand.url + "/oauth/register"} if register else {})})
        self.stand.on("POST", "/oauth/register", {"client_id": CLIENT, "client_secret": SECRET})
        self.stand.on("POST", "/oauth/token", token or {"access_token": ACCESS, "refresh_token": REFRESH,
                                                         "expires_in": 3600, "scope": "crm"})
        def answer(handler, req):
            sent = json.loads(req["body"] or b"{}")
            if sent.get("method") == "initialize":
                result = {"serverInfo": {"name": "crm-mcp", "version": "1"}}
            else:                       # a session call: the stand-in asks for the session header, as the SDK does
                if req["headers"].get("mcp-session-id") != "session-1":
                    return handler.send_error(400, "MCP session initialization is required")
                result = {"tools": [{"name": "crm_orders"}]}
            data = json.dumps({"jsonrpc": "2.0", "id": sent.get("id"), "result": result}).encode()
            handler.send_response(200)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("mcp-session-id", "session-1")
            handler.send_header("Content-Length", str(len(data)))
            handler.end_headers()
            handler.wfile.write(data)

        self.stand.on("POST", "/mcp", answer)
        self.stand.on("DELETE", "/mcp", None, status=204)

    def connect_server(self, name="crm", **fields):
        """A whole Connect of one server: the owner's browser gives the code back."""
        code, start = self.post("/ui/mcp/connect", name=name, redirect_uri="http://127.0.0.1:53111/", **fields)
        if code != 200:
            return code, start
        return self.post("/ui/mcp/finish", state=start["state"], code=CODE)

    def crm_no_refresh(self):
        """The stand-in server as an authorization_code server: one long access token and no refresh token, as the
        owner's own CRM gives it."""
        self.oauth(token={"access_token": ACCESS, "expires_in": 365 * 24 * 3600, "scope": "mcp:tickets"})
        self.stand.on("GET", "/.well-known/oauth-authorization-server", {
            "issuer": self.stand.url, "authorization_endpoint": self.stand.url + "/oauth/authorize",
            "token_endpoint": self.stand.url + "/oauth/token",
            "registration_endpoint": self.stand.url + "/oauth/register",
            "grant_types_supported": ["authorization_code"]})

    def crm(self, server=None, name="crm"):
        """One owner server in team.json, with the stand-in server's address."""
        entry = dict(server or CRM)
        if "url" in entry:
            entry["url"] = entry["url"] if entry["url"].startswith("http://127.0.0.1") else self.stand.url + "/mcp"
        return self.save("/ui/team/mcp", name=name, server=entry)

    # ---- team.json
    def test_team_json_takes_the_owners_mcp_servers_and_their_grants(self):
        def team(servers, **fields):
            t = json.loads(json.dumps(TEAM))
            t["mcp"] = servers
            t["agents"]["dev"].update(fields)
            return t
        hub.validate_team(team({"crm": CRM, "shop": KEYED, "notes": LOCAL}, tools=["crm", "github", "notes"]))
        refused = [({"crm": dict(CRM, title="")}, "needs a title"),
                   ({"crm": dict(CRM, url="http://crm.example.com/")}, "url must be an https address"),
                   ({"crm": dict(CRM, auth="basic")}, "auth must be"),
                   ({"crm": dict(CRM, extra=1)}, "takes only"),
                   ({"github": CRM}, "is Fleet's own"),
                   ({"fleet": CRM}, "is Fleet's own"),
                   ({"CRM": CRM}, "must be 1 to 31 characters"),
                   ({"crm": {"title": "x", "url": "https://a.example.com/", "command": "x"}}, "not both"),
                   ({"shop": dict(KEYED, key="PATH")}, 'auth "key" needs key'),
                   ({"notes": dict(LOCAL, command="rm -rf /")}, "command must be the name of a program"),
                   ({f"s{i}": CRM for i in range(33)}, "mcp must map up to 32"),
                   ([CRM], "mcp must map up to 32")]
        for servers, words in refused:
            with self.subTest(servers=servers), self.assertRaisesRegex(ValueError, words):
                hub.validate_team(team(servers))
        with self.assertRaisesRegex(ValueError, "tools must be different names"):
            hub.validate_team(team({"crm": CRM}, tools=["ghost"]))

    # ---- the owner's own servers
    def test_the_owner_adds_changes_and_removes_an_mcp_server(self):
        code, data = self.crm()
        self.assertEqual((code, data["changed"], data["name"]), (200, True, "crm"), data)
        self.assertEqual(self.origin_team()["mcp"]["crm"]["title"], "Acme CRM")
        said = hub.q1("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id DESC")["text"]
        self.assertIn("added or changed the MCP server crm", said)
        tools = self.view()["tools"]
        self.assertEqual({k: v for k, v in tools["crm"].items() if k not in ("connected_at", "problem")},
                         {"title": "Acme CRM", "url": self.stand.url + "/mcp", "auth": "oauth", "custom": True,
                          "runtimes": ["claude", "codex", "grok", "opencode"], "needs": [TOKEN],
                          "connected": False, "scopes": [],
                          "server": None, "tools": [], "access_ends": None})
        self.assertIs(tools["github"]["custom"], False)

        self.assertEqual(self.crm()[1]["changed"], False)                   # the same server again
        self.assertEqual(self.crm(dict(CRM, title="CRM"))[1]["changed"], True)
        self.assertEqual(self.origin_team()["mcp"]["crm"]["title"], "CRM")
        code, data = self.save("/ui/team/tools", tool="crm", agents=["dev", "ops"])
        self.assertEqual((code, data["agents"]), (200, ["dev", "ops"]), data)
        self.assertEqual(self.origin_team()["agents"]["dev"]["tools"], ["crm"])

        code, data = self.save("/ui/team/mcp", name="crm", delete=True)     # a delete takes the grants with it
        self.assertEqual((code, data["changed"], data["deleted"]), (200, True, True), data)
        team = self.origin_team()
        self.assertNotIn("mcp", team)
        self.assertNotIn("tools", team["agents"]["dev"])
        self.assertNotIn("tools", team["agents"]["ops"])
        self.assertNotIn("crm", self.view()["tools"])
        self.assertEqual(self.save("/ui/team/mcp", name="crm", delete=True)[0], 404)

    def test_the_owner_routes_refuse_a_bad_server_an_old_base_and_the_manager(self):
        for fields, status, words in ((dict(name="crm", server=dict(CRM, url="https://u:p@a.example.com/")), 400, "url must be"),
                                      (dict(name="CRM", server=CRM), 400, "name must be"),
                                      (dict(name="crm", server=CRM, delete=True), 400, "delete must be true"),
                                      (dict(name="crm", server=CRM, extra=1), 400, "unknown field extra")):
            with self.subTest(fields=fields):
                code, data = self.save("/ui/team/mcp", **fields)
                self.assertEqual(code, status, data)
                self.assertIn(words, data["error"])
        code, data = self.request("/ui/team/mcp", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                       base_sha256="0" * 64, name="crm", server=CRM))
        self.assertEqual(code, 409, data)
        self.crm()
        code, data = self.save("/ui/team/tools", tool="crm", agents=["manager"])
        self.assertEqual((code, "the manager has no repos or tools" in data["error"]), (400, True), data)

    # ---- Connect
    def test_the_owner_connects_a_server_and_the_hub_keeps_only_a_refresh_token(self):
        self.oauth()
        self.crm()
        code, start = self.post("/ui/mcp/connect", name="crm", redirect_uri="http://127.0.0.1:53111/")
        self.assertEqual(code, 200, start)
        self.assertTrue(start["url"].startswith(self.stand.url + "/oauth/authorize?"))
        self.assertIn("code_challenge_method=S256", start["url"])
        self.assertIn("resource=" + hub.urllib.parse.quote(self.stand.url + "/mcp", safe=""), start["url"])
        self.assertEqual(start["scopes"], ["crm"])
        registered = body(self.stand.find("POST", "/oauth/register")[0])
        self.assertEqual(registered["redirect_uris"], ["http://127.0.0.1:53111/"])

        code, done = self.post("/ui/mcp/finish", state=start["state"], code=CODE)
        self.assertEqual(code, 200, done)
        self.assertEqual((done["connected"], done["replaced"], done["server"], done["tools"]),
                         (True, False, "crm-mcp", ["crm_orders"]))
        self.assertEqual(form(self.stand.find("POST", "/oauth/token")[0])["code"], CODE)
        kept = json.loads(self.file.read_text())["servers"]["crm"]
        self.assertEqual((kept["refresh_token"], kept["client_id"], kept["client_secret"]), (REFRESH, CLIENT, SECRET))
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o600)
        tools = self.view()["tools"]["crm"]
        self.assertEqual((tools["connected"], tools["server"], tools["tools"], tools["scopes"], tools["problem"]),
                         (True, "crm-mcp", ["crm_orders"], ["crm"], None))
        for text in (json.dumps([dict(r) for r in hub.q("SELECT * FROM ui_requests")]),
                     json.dumps([dict(r) for r in hub.q("SELECT * FROM log")]), json.dumps(self.view())):
            for secret in (REFRESH, SECRET, ACCESS, CODE):
                self.assertNotIn(secret, text)

        code, data = self.post("/ui/mcp/finish", state=start["state"], code=CODE)    # the Connect is used up
        self.assertEqual((code, hub.MCP_STALE in data["error"]), (409, True), data)
        code, data = self.post("/ui/mcp/disconnect", name="crm")
        self.assertEqual((code, data["connected"]), (200, False), data)
        self.assertEqual(json.loads(self.file.read_text())["servers"], {})
        self.assertIs(self.view()["tools"]["crm"]["connected"], False)

    def test_a_connect_needs_a_server_of_team_json_with_oauth_and_a_loopback_address(self):
        self.oauth()
        self.crm(KEYED, name="shop")
        self.crm(LOCAL, name="notes")
        for fields, status, words in ((dict(name="crm", redirect_uri="http://127.0.0.1:53111/"), 404, "no MCP server crm"),
                                      (dict(name="shop", redirect_uri="http://127.0.0.1:53111/"), 409, hub.MCP_NO_OAUTH),
                                      (dict(name="notes", redirect_uri="http://127.0.0.1:53111/"), 409, hub.MCP_NO_OAUTH),
                                      (dict(name="shop", redirect_uri="https://example.com/"), 400, "redirect_uri must be")):
            with self.subTest(fields=fields):
                code, data = self.post("/ui/mcp/connect", **fields)
                self.assertEqual(code, status, data)
                self.assertIn(words, data["error"])

    def test_a_server_without_oauth_metadata_or_registration_says_what_is_missing(self):
        self.crm()
        code, data = self.post("/ui/mcp/connect", name="crm", redirect_uri="http://127.0.0.1:53111/")
        self.assertEqual((code, "gave no OAuth endpoints" in data["error"]), (502, True), data)
        self.oauth(register=False)
        code, data = self.post("/ui/mcp/connect", name="crm", redirect_uri="http://127.0.0.1:53111/")
        self.assertEqual((code, "registers no client itself" in data["error"]), (409, True), data)
        code, data = self.post("/ui/mcp/connect", name="crm", redirect_uri="http://127.0.0.1:53111/",
                                  client={"client_id": "own-client", "client_secret": SECRET})
        self.assertEqual(code, 200, data)
        self.assertIn("client_id=own-client", data["url"])
        self.assertEqual(self.stand.find("POST", "/oauth/register"), [])    # the owner's own client, no registration
        code, done = self.post("/ui/mcp/finish", state=data["state"], code=CODE)
        self.assertEqual((code, done["connected"]), (200, True), done)
        self.assertEqual(json.loads(self.file.read_text())["servers"]["crm"]["client_id"], "own-client")

    # ---- the tokens of a task session
    def test_a_task_session_gets_one_access_token_for_each_connected_server(self):
        self.oauth()
        self.crm()
        self.crm(KEYED, name="shop")
        self.connect_server()
        self.save("/ui/team/tools", tool="crm", agents=["dev"])
        self.save("/ui/team/tools", tool="shop", agents=["dev"])
        code, data = self.request("/helper/integrations/dev", {})
        self.assertEqual(code, 200, data)
        self.assertEqual((data["mcp"], data["mcp_problems"], sorted(data["tools"])),
                         ({TOKEN: ACCESS}, [], ["crm", "shop"]))           # a key server needs no token from the hub
        self.assertEqual(len(self.stand.find("POST", "/oauth/token")), 1)  # the token of the Connect still lives
        hub.MCP["tokens"].clear()                                          # as after a restart of the hub
        self.stand.on("POST", "/oauth/token", {"access_token": ACCESS2, "expires_in": 3600})
        code, again = self.request("/helper/integrations/dev", {})
        self.assertEqual(again["mcp"], {TOKEN: ACCESS2})
        self.assertEqual(form(self.stand.find("POST", "/oauth/token")[-1])["grant_type"], "refresh_token")
        code, third = self.request("/helper/integrations/dev", {})          # the new token is kept while it lives
        self.assertEqual((third["mcp"], len(self.stand.find("POST", "/oauth/token"))), ({TOKEN: ACCESS2}, 2))
        for text in (json.dumps([dict(r) for r in hub.q("SELECT * FROM log")]),):
            for secret in (ACCESS, ACCESS2, REFRESH, SECRET):
                self.assertNotIn(secret, text)

    def test_a_refused_refresh_is_a_note_for_the_session_and_a_problem_for_the_owner(self):
        self.oauth()
        self.crm()
        self.connect_server()
        self.save("/ui/team/tools", tool="crm", agents=["dev"])
        hub.MCP["tokens"].clear()
        self.stand.on("POST", "/oauth/token", {"error": "invalid_grant"}, status=400)
        code, data = self.request("/helper/integrations/dev", {})
        self.assertEqual((code, data["mcp"]), (200, {}))
        self.assertEqual(len(data["mcp_problems"]), 1)
        self.assertIn("The MCP server crm is not loaded", data["mcp_problems"][0])
        self.assertIn("invalid_grant", self.view()["tools"]["crm"]["problem"])
        hub.MCP["problems"].clear()
        os.remove(self.file)                # a server that the owner has not connected
        code, data = self.request("/helper/integrations/dev", {})
        self.assertIn(hub.MCP_UNCONNECTED, data["mcp_problems"][0])
        self.assertIs(self.view()["tools"]["crm"]["connected"], False)

    def test_the_refresh_token_and_the_client_secret_cannot_be_sent_as_text_afterwards(self):
        self.oauth()
        self.crm()
        self.connect_server()
        for secret in (REFRESH, SECRET):
            code, data = self.save("/ui/team/mcp", name="notes",
                                   server={"title": secret, "command": "notes-mcp"})
            self.assertEqual((code, data["error"]), (422, "a registered login cannot be sent as text"))

    def test_a_server_without_a_refresh_token_is_kept_by_its_access_token(self):
        self.crm_no_refresh()
        self.crm()
        code, done = self.connect_server()
        self.assertEqual((code, done["connected"]), (200, True), done)
        self.assertGreater(done["access_ends"] - hub.now(), 360 * 24 * 3600)
        kept = json.loads(self.file.read_text())["servers"]["crm"]
        self.assertEqual((kept.get("refresh_token"), kept["access_token"]), (None, ACCESS))
        self.assertEqual(body(self.stand.find("POST", "/oauth/register")[0])["grant_types"], ["authorization_code"])
        tools = self.view()["tools"]["crm"]
        self.assertEqual((tools["connected"], tools["problem"]), (True, None))
        self.assertEqual(tools["access_ends"], kept["access_expires_at"])
        self.save("/ui/team/tools", tool="crm", agents=["dev"])
        code, data = self.request("/helper/integrations/dev", {})
        self.assertEqual((data["mcp"], data["mcp_problems"]), ({TOKEN: ACCESS}, []))
        self.assertEqual(len(self.stand.find("POST", "/oauth/token")), 1)       # no refresh call is possible

        servers = json.loads(self.file.read_text())           # the access token of a connection that ended
        servers["servers"]["crm"]["access_expires_at"] = int(hub.now()) - 10
        self.file.write_text(json.dumps(servers))
        hub.MCP["problems"].clear()
        code, data = self.request("/helper/integrations/dev", {})
        self.assertEqual((data["mcp"], len(data["mcp_problems"])), ({}, 1))
        self.assertIn(hub.MCP_ENDED, data["mcp_problems"][0])
        self.assertEqual(self.view()["tools"]["crm"]["problem"], hub.MCP_ENDED)
        for text in (json.dumps([dict(r) for r in hub.q("SELECT * FROM ui_requests")]),
                     json.dumps([dict(r) for r in hub.q("SELECT * FROM log")]), json.dumps(self.view())):
            self.assertNotIn(ACCESS, text)

    def test_a_finish_is_refused_when_the_owner_changed_the_address_meanwhile(self):
        self.oauth()
        self.crm()
        code, start = self.post("/ui/mcp/connect", name="crm", redirect_uri="http://127.0.0.1:53111/")
        self.assertEqual(code, 200, start)
        self.save("/ui/team/mcp", name="crm",            # the owner points the server somewhere else
                  server=dict(CRM, url="https://other.example.com/mcp"))
        code, data = self.post("/ui/mcp/finish", state=start["state"], code=CODE)
        self.assertEqual((code, "the address of the MCP server crm changed" in data["error"]), (409, True), data)
        self.assertFalse(self.file.exists())                # nothing of that Connect is kept

    def test_a_file_that_the_hub_cannot_read_stops_a_connect_and_shows_the_problem(self):
        self.oauth()
        self.crm()
        self.file.write_text("{}")
        os.chmod(self.file, 0o644)
        self.assertIn("mode 600", self.view()["tools"]["crm"]["problem"])
        code, data = self.connect_server()
        self.assertEqual((code, "mode 600" in data["error"]), (409, True), data)


    # ---- does this server answer? (POST /ui/mcp/check)
    def mcp_endpoint(self, bearer=None, tools=("orders", "refund_one_order")):
        """The stand-in server as a plain MCP server at /mcp: one initialize, one tools/list and the session header.
        bearer: the token that it wants, so a call without it is a 401."""
        def answer(handler, req):
            if bearer and req["headers"].get("Authorization") != f"Bearer {bearer}":
                return handler.send_error(401, "unauthorized")
            sent = json.loads(req["body"] or b"{}")
            result = ({"serverInfo": {"name": "shop-mcp", "version": "2"}, "protocolVersion": mcp.VERSION}
                      if sent.get("method") == "initialize" else {"tools": [{"name": t} for t in tools]})
            data = json.dumps({"jsonrpc": "2.0", "id": sent.get("id"), "result": result}).encode()
            handler.send_response(200)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("mcp-session-id", "session-2")
            handler.send_header("Content-Length", str(len(data)))
            handler.end_headers()
            handler.wfile.write(data)
        self.stand.on("POST", "/mcp", answer)
        self.stand.on("DELETE", "/mcp", None, status=204)

    def machine(self, agent, features=("mcp_program",), seen=0.0):
        """One agent's machine as the hub reads it before it asks: when its helper last checked in, and the helper
        steps that it reports. seen: seconds ago, so a machine can be quiet."""
        hub.q("INSERT INTO agents(name,last_seen) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET "
              "last_seen=excluded.last_seen", (agent, hub.now() - seen))
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET "
              "data=excluded.data", (agent, json.dumps({"features": list(features)}), hub.now()))

    def stand_in_helper(self, machines):
        """A stand-in helper for each of these agents: it reads its own events as fleet.py does, resolves a program
        check the way lifecycle.exe would and sends the answer back. machines: {agent: the program's path, or None
        for a machine that does not have it}. It returns the list that each check appends to."""
        stop = threading.Event()
        self.addCleanup(stop.set)
        asked = []

        def run():
            while not stop.wait(0.05):
                try:            # the test's server closes under this thread at the end of the test
                    for agent, path in machines.items():
                        code, data = self.request(f"/events/{agent}?delivery=1&after=0&wait=0")
                        for ev in (data.get("events") or []) if code == 200 else []:
                            if ev["kind"] == "mcp_program":
                                asked.append((agent, ev["extra"]["command"]))
                                self.request(f"/helper/mcp/program/{agent}",
                                             {"probe": ev["extra"]["probe"], "found": bool(path), "path": path})
                            self.request(f"/helper/ack/{agent}", {"ids": [ev["id"]]})
                except OSError:
                    return

        threading.Thread(target=run, daemon=True).start()
        return asked

    def closed_address(self):
        """An address on this machine that nothing answers: a port that was free and is not taken."""
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return f"http://127.0.0.1:{s.getsockname()[1]}/mcp"

    def test_the_owner_asks_whether_a_url_server_answers_before_it_saves_it(self):
        self.mcp_endpoint()
        public = {"title": "Shop", "url": self.stand.url + "/mcp", "auth": "none"}
        code, data = self.post("/ui/mcp/check", name="shop", server=public)
        self.assertEqual((code, data["kind"], data["checked"], data["answers"], data["needs"]),
                         (200, "url", True, True, None), data)
        self.assertEqual((data["server"], data["version"], data["tools"], data["note"]),
                         ("shop-mcp", "2", ["orders", "refund_one_order"], None))
        self.assertEqual(data["keys"], {"needs": [], "missing": []})
        self.assertIn("answers as an MCP server with 2 tool(s)", data["says"])
        self.assertIn("own server", data["says"])                   # a loopback address: the hub's own server
        self.assertIn("mcp_check", self.request()[1]["ui_features"])
        self.assertNotIn("shop", self.origin_team().get("mcp") or {})        # a check writes nothing
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM log WHERE what LIKE '%team.json%'")["n"], 0)
        # The same server, saved: the route takes the name alone.
        self.assertEqual(self.crm(public, name="shop")[1]["changed"], True)
        code, again = self.post("/ui/mcp/check", name="shop")
        self.assertEqual((code, again["answers"], again["tools"]), (200, True, ["orders", "refund_one_order"]), again)
        code, gone = self.post("/ui/mcp/check", name="ghost")
        self.assertEqual((code, gone["error"]), (404, "no MCP server ghost"))

    def test_a_server_that_wants_credentials_is_a_server_that_answers(self):
        self.mcp_endpoint(bearer=ACCESS)                 # it refuses every call that has no token
        url = self.stand.url + "/mcp"
        code, data = self.post("/ui/mcp/check", name="crm", server=dict(CRM, url=url))
        self.assertEqual((code, data["checked"], data["answers"], data["needs"]), (200, True, True, "connect"), data)
        self.assertIn("asks for a sign-in", data["says"])
        code, data = self.post("/ui/mcp/check", name="shop", server=dict(KEYED, url=url))
        self.assertEqual((code, data["answers"], data["needs"]), (200, True, "key"), data)
        self.assertEqual(data["keys"], {"needs": ["SHOP_KEY"], "missing": ["SHOP_KEY"]})
        self.assertIn("never has it", data["says"])
        hub.TEAM["logins"] = {"bws://2f1c4f22-0000-4000-8000-00000000beef":
                              {"title": "SHOP_KEY", "kind": "api_key", "env": "SHOP_KEY"}}
        code, data = self.post("/ui/mcp/check", name="shop", server=dict(KEYED, url=url))
        self.assertEqual(data["keys"], {"needs": ["SHOP_KEY"], "missing": []}, data)
        # A server that calls itself public and asks for credentials is wrong, and the hub says so.
        code, data = self.post("/ui/mcp/check", name="shop", server={"title": "Shop", "url": url, "auth": "none"})
        self.assertEqual((code, data["answers"], data["needs"]), (200, False, None), data)
        self.assertIn('saved with auth "none"', data["says"])
        # A connected server is checked with its own saved access token.
        self.oauth()
        self.mcp_endpoint(bearer=ACCESS)
        self.crm()
        self.assertEqual(self.connect_server()[1]["connected"], True)
        code, data = self.post("/ui/mcp/check", name="crm")
        self.assertEqual((code, data["answers"], data["needs"]), (200, True, None), data)
        for text in (json.dumps(data), json.dumps([dict(r) for r in hub.q("SELECT * FROM ui_controls")])):
            self.assertNotIn(ACCESS, text)

    def test_a_server_that_does_not_answer_is_a_200_that_says_why(self):
        code, data = self.post("/ui/mcp/check", name="crm", server=dict(CRM, url=self.closed_address()))
        self.assertEqual((code, data["checked"], data["answers"], data["needs"]), (200, True, False, None), data)
        self.assertIn("did not answer as an MCP server", data["says"])
        self.assertIsNone(self.origin_team().get("mcp"))
        # A shape that team.json refuses never reaches the network, and leaves no command record.
        code, data = self.post("/ui/mcp/check", name="crm", server=dict(CRM, url="http://crm.example.com/"))
        self.assertEqual((code, "url must be an https address" in data["error"]), (400, True), data)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM ui_controls WHERE route='mcp/check'")["n"], 1)

    def test_a_command_server_is_run_by_nobody_and_asks_for_a_machine(self):
        local = {"title": "Notes", "command": "notes-mcp", "env": {"NOTES_TOKEN": "NOTES_KEY"}}
        code, data = self.post("/ui/mcp/check", name="notes", server=local)      # no agent has it, and none named
        self.assertEqual((code, data["kind"], data["checked"], data["answers"], data["needs"], data["machines"]),
                         (200, "command", False, None, "machine", []), data)
        self.assertIn("the hub never runs it", data["says"])
        self.assertIn("No agent has notes yet", data["says"])
        self.assertEqual(data["keys"], {"needs": ["NOTES_KEY"], "missing": ["NOTES_KEY"]})
        self.assertEqual(self.stand.requests, [])                   # nothing was asked of anybody
        code, data = self.post("/ui/mcp/check", name="notes", server=dict(local, command="rm -rf /"))
        self.assertEqual((code, "command must be the name of a program" in data["error"]), (400, True), data)
        # The agent to ask is an agent of team.json with task sessions, so a typo and the manager are both a 400.
        for who, why in (("ghost", "name of an agent"), ("manager", "worker or a lead")):
            code, data = self.post("/ui/mcp/check", name="notes", server=local, agent=who)
            self.assertEqual((code, why in data["error"]), (400, True), data)

    def test_the_machine_that_would_run_the_program_answers_the_check(self):
        local = {"title": "Notes", "command": "notes-mcp"}
        self.machine("dev")
        asked = self.stand_in_helper({"dev": "/usr/local/bin/notes-mcp"})
        code, data = self.post("/ui/mcp/check", name="notes", server=local, agent="dev")
        self.assertEqual((code, data["checked"], data["answers"], data["needs"]), (200, True, True, None), data)
        self.assertEqual(data["machines"], [{"agent": "dev", "machine": "w1", "state": "found",
                                             "path": "/usr/local/bin/notes-mcp",
                                             "says": "dev (w1): notes-mcp is at /usr/local/bin/notes-mcp."}])
        self.assertIn("nobody ran it", data["says"])
        self.assertEqual(asked, [("dev", "notes-mcp")])
        self.assertNotIn("notes", self.origin_team().get("mcp") or {})          # a check still writes nothing
        # Saved and given to the agents: then the route asks the machines of the agents that have it.
        self.assertEqual(self.crm(local, name="notes")[1]["changed"], True)
        hub.TEAM["agents"]["dev"]["tools"] = ["notes"]
        code, data = self.post("/ui/mcp/check", name="notes")
        self.assertEqual((code, data["answers"], [w["agent"] for w in data["machines"]]), (200, True, ["dev"]), data)
        self.assertEqual(asked, [("dev", "notes-mcp"), ("dev", "notes-mcp")])

    def test_a_machine_without_the_program_is_the_answer_too(self):
        local = {"title": "Notes", "command": "notes-mcp"}
        for agent in ("dev", "ops"):
            self.machine(agent)
            hub.TEAM["agents"][agent]["tools"] = ["notes"]
        self.stand_in_helper({"dev": "/usr/local/bin/notes-mcp", "ops": None})
        code, data = self.post("/ui/mcp/check", name="notes", server=local)
        self.assertEqual((code, data["checked"], data["answers"], data["needs"]), (200, True, False, "machine"), data)
        self.assertEqual([(w["agent"], w["state"], w["path"]) for w in data["machines"]],
                         [("dev", "found", "/usr/local/bin/notes-mcp"), ("ops", "missing", None)])
        self.assertIn("ops (w2): no notes-mcp on its PATH or in ~/.local/bin.", data["says"])

    def test_a_machine_that_is_quiet_or_older_than_this_check_is_not_asked_and_not_waited_for(self):
        local = {"title": "Notes", "command": "notes-mcp"}
        self.machine("dev", seen=600)                                   # it has not checked in for ten minutes
        self.machine("ops", features=["agent_key"])                     # its Fleet is older than this check
        for agent in ("dev", "ops"):
            hub.TEAM["agents"][agent]["tools"] = ["notes"]
        with patch.object(hub, "MCP_PROBE_WAIT", 30):       # nothing may be waited for, so the wait is never reached
            code, data = self.post("/ui/mcp/check", name="notes", server=local)
        self.assertEqual((code, data["checked"], data["answers"], data["needs"]), (200, False, None, "machine"), data)
        self.assertEqual([(w["agent"], w["state"]) for w in data["machines"]],
                         [("dev", "not_asked"), ("ops", "not_asked")])
        self.assertIn("dev (w1): not asked, this server has not checked in.", data["says"])
        self.assertIn("ops (w2): not asked, this server's Founderizer is older than this check.", data["says"])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE kind='mcp_program'")["n"], 0)
        # A machine that is asked and says nothing is one that answered nothing, and the hub gives up on its own.
        self.machine("dev")
        with patch.object(hub, "MCP_PROBE_WAIT", 2):
            code, data = self.post("/ui/mcp/check", name="notes", server=local, agent="dev")
        self.assertEqual((code, data["checked"], data["answers"], data["needs"]), (200, False, None, "machine"), data)
        self.assertEqual(data["machines"][0]["says"], "dev (w1): no answer in 2 seconds.")
        # That check gave up, so the hub hands its event to nobody and takes no answer for it any more.
        row = hub.q1("SELECT * FROM events WHERE kind='mcp_program' ORDER BY id DESC LIMIT 1")
        self.assertEqual(self.request("/events/dev?delivery=1&after=0&wait=0")[1]["events"], [])
        code, late = self.request("/helper/mcp/program/dev",
                                  {"probe": json.loads(row["extra"])["probe"], "found": True, "path": "/bin/x"})
        self.assertEqual((code, late), (200, {"taken": False}))

    def test_the_helper_route_takes_one_answer_for_its_own_agent_only(self):
        self.machine("dev")
        self.machine("ops")
        probes = []

        def catch(agent):
            for ev in self.request(f"/events/{agent}?delivery=1&after=0&wait=0")[1]["events"]:
                probes.append(ev["extra"]["probe"])
        threading.Thread(target=lambda: (time.sleep(0.3), catch("dev")), daemon=True).start()
        with patch.object(hub, "MCP_PROBE_WAIT", 1):
            self.post("/ui/mcp/check", name="notes", server={"title": "Notes", "command": "notes-mcp"}, agent="dev")
        self.assertEqual(len(probes), 1, probes)
        for agent, body, want in (("ops", {"probe": probes[0], "found": True, "path": "/bin/x"}, (200, {"taken": False})),
                                  ("dev", {"probe": "not-a-probe", "found": False, "path": None}, (200, {"taken": False})),
                                  ("dev", {"probe": probes[0], "found": "yes"}, (400, None)),
                                  ("ghost", {"probe": probes[0], "found": True}, (404, None))):
            code, data = self.request(f"/helper/mcp/program/{agent}", body)
            self.assertEqual(code, want[0], data)
            if want[1] is not None:
                self.assertEqual(data, want[1])


class HelperSide(unittest.TestCase):
    """The helper side: what a task session gets for the owner's servers."""
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-mcp-helper-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.kit = self.tmp / "kit"
        self.kit.mkdir()
        self.team(crm=CRM)
        self.home = self.tmp / ".fleet"
        for p in (patch.object(fleet, "HOME", str(self.home)), patch.object(fleet, "SESSIONS", str(self.home / "sessions")),
                  patch.object(fleet, "HUB", "http://hub:8765"), patch.object(fleet, "AGENT", None),
                  patch.object(fleet, "KIT", str(self.kit)), patch.object(fleet, "WORK", str(self.tmp / "work"))):
            p.start()
            self.addCleanup(p.stop)

    def team(self, **servers):
        """The checkout's team.json, with the owner's servers in it."""
        (self.kit / "team.json").write_text(json.dumps(dict(TEAM, mcp=servers)))

    def answer(self, tools=("crm",), **changes):
        body = dict({"repos": {}, "tools": list(tools), "errors": [], "tokens": [],
                     "mcp": {TOKEN: ACCESS}, "mcp_problems": []}, **changes)

        def http(method, path, data=None, timeout=40):
            return 200, body
        return http

    def command(self, conf, answer=None, program="/opt/fleet-test/bin/notes-mcp", **kw):
        with patch.object(fleet, "checkout_conf", return_value={"tools": ["crm"]}), \
                patch.object(fleet, "http", answer or self.answer()), \
                patch.object(fleet, "prepare_repos", return_value={}), \
                patch.object(fleet, "exe", side_effect=lambda name, home=None: program if name == "notes-mcp" else None):
            return fleet.session_command("dev", conf, "Do T-3.", task="T-3", generation="g", session=SESSION,
                                         token="s" * 43, env=fleet.session_env("dev", conf, "task"), **kw)

    def env_file(self, command):
        words = shlex.split(command)
        self.assertEqual((words[0], words[2:5]), (".", ["&&", "rm", "-f"]))
        path = Path(words[1])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        values = {}
        for line in path.read_text().splitlines():
            name, _, value = line.removeprefix("export ").partition("=")
            values[name] = shlex.split(value)[0] if value else ""
        return values

    def test_a_claude_task_loads_the_owners_server_with_the_token_of_its_env_file(self):
        command = self.command(CLAUDE)
        self.assertNotIn(ACCESS, command)
        values = self.env_file(command)
        self.assertEqual((values[TOKEN], values["FLEET_TOOLS"]), (ACCESS, "crm"))
        words = fleet.launch_words(command)
        servers = json.loads(Path(words[words.index("--mcp-config") + 1]).read_text())["mcpServers"]
        self.assertEqual(servers["crm"], {"type": "http", "url": "https://mcp.example.org/",
                                          "headers": {"Authorization": "Bearer ${%s}" % TOKEN}})
        self.assertEqual(json.loads(words[words.index("--settings") + 1])["permissions"]["allow"],
                         ["mcp__fleet__*", "mcp__crm__*", "Workflow"])          # AUTONOMY.md decision 41
        prompt = words[words.index("--append-system-prompt") + 1]
        self.assertIn("Your MCP servers besides Fleet's: crm (Acme CRM). Their tools are mcp__<server>__*.", prompt)

    def test_a_codex_task_gets_the_owners_server_as_options(self):
        words = fleet.launch_words(self.command(CODEX_CONF))
        for option in (f'mcp_servers.crm.url="https://mcp.example.org/"',
                       'mcp_servers.crm.bearer_token_env_var="%s"' % TOKEN,
                       'mcp_servers.crm.default_tools_approval_mode="approve"'):
            self.assertEqual(words[words.index(option) - 1], "-c")
        self.assertEqual(self.env_file(self.command(CODEX_CONF))[TOKEN], ACCESS)

    def test_a_stdio_server_of_the_owner_runs_its_program_with_its_key(self):
        self.team(notes=dict(LOCAL, env={"NOTES_TOKEN": "NOTES_KEY"}))
        with patch.object(fleet, "read_env", return_value={"NOTES_KEY": "shh"}):
            command = self.command(CLAUDE, answer=self.answer(tools=("notes",), mcp={}))
        words = fleet.launch_words(command)
        servers = json.loads(Path(words[words.index("--mcp-config") + 1]).read_text())["mcpServers"]
        self.assertEqual(servers["notes"], {"type": "stdio", "command": "/opt/fleet-test/bin/notes-mcp",
                                            "args": [], "env": {"NOTES_TOKEN": "${NOTES_TOKEN}"}})
        values = self.env_file(command)
        self.assertEqual((values["NOTES_TOKEN"], values["FLEET_TOOLS"]), ("shh", "notes"))
        with patch.object(fleet, "read_env", return_value={}):          # the agent has no such key
            prompt = fleet.launch_words(self.command(CLAUDE, answer=self.answer(tools=("notes",), mcp={})))[-1]
        self.assertIn("The tool notes is not loaded: this session has no NOTES_KEY. The owner gives the agent that "
                      "API key on the Secrets page.", prompt)

    def test_a_server_without_its_token_or_outside_this_checkout_is_not_loaded(self):
        prompt = fleet.launch_words(self.command(CLAUDE, answer=self.answer(
            mcp={}, mcp_problems=["The MCP server crm is not loaded: " + hub.MCP_UNCONNECTED])))[-1]
        self.assertIn("The MCP server crm is not loaded: " + hub.MCP_UNCONNECTED, prompt)
        self.assertIn("The tool crm is not loaded: this session has no FLEET_MCP_CRM. The owner connects this MCP "
                      "server in the app.", prompt)
        self.assertNotIn("Your MCP servers besides Fleet's", prompt)
        self.team(shop=KEYED)       # this checkout does not have the server that the hub gave
        command = self.command(CLAUDE)
        self.assertIn("The tool crm is not loaded: this machine's Fleet does not have it yet.",
                      fleet.launch_words(command)[-1])
        self.assertNotIn("mcp__crm__*", command)

    def test_a_codex_runner_gets_no_server(self):
        """An agent of an ACP program got none either, until the AI providers build: its servers now reach the ACP
        runner in a file of the session (test_acp_runner, Wiring)."""
        command = self.command(dict(CODEX_CONF, start="app-server"))
        self.assertNotIn("mcp_servers.crm", command)
        self.assertEqual(self.env_file(command)[TOKEN], ACCESS)      # the variable is there; no server uses it

    def test_the_machine_resolves_a_command_servers_program_and_runs_nothing(self):
        """The helper's answer to the hub's mcp_program event (owner feature mcp_program)."""
        helper = fleet.Helper("dev", CLAUDE)
        sent, ran = [], []

        def http(method, path, data=None, timeout=40):
            sent.append((method, path, data, timeout))
            return 200, {"taken": True}

        for program, says in (("/opt/fleet-test/bin/notes-mcp", "this machine has it at"), (None, "not on this")):
            sent.clear()
            with patch.object(fleet, "http", http), patch.object(fleet, "exe", return_value=program), \
                    patch.object(subprocess, "run", side_effect=lambda *a, **k: ran.append(a)), \
                    patch.object(helper, "say", lambda text: self.assertIn(says, text)):
                helper.mcp_program({"probe": "p-1", "command": "notes-mcp"})
            self.assertEqual(sent, [("POST", "/helper/mcp/program/dev",
                                     {"probe": "p-1", "found": bool(program), "path": program}, 10)])
        self.assertEqual(ran, [])                   # the program is resolved, never run
        # Only a program name is resolved, and the hub's answer must arrive.
        for extra in ({"probe": "p-1", "command": "notes-mcp; rm -rf /"}, {"command": "notes-mcp"}, {"probe": "p-1"}):
            with patch.object(fleet, "http", http), self.assertRaises(fleet.Refused):
                helper.mcp_program(extra)
        with patch.object(fleet, "http", lambda *a, **k: (503, {})), patch.object(fleet, "exe", return_value=None), \
                patch.object(helper, "say", lambda text: None), self.assertRaises(fleet.Refused):
            helper.mcp_program({"probe": "p-1", "command": "notes-mcp"})
        self.assertIn("mcp_program", lifecycle.FEATURES)     # the hub asks a machine that reports this step only

    def test_the_catalog_of_a_checkout_without_servers_is_fleets_own(self):
        (self.kit / "team.json").write_text(json.dumps(TEAM))
        self.assertEqual(sorted(fleet.team_catalog()), ["github"])
        (self.kit / "team.json").write_text("not json")         # the checkout's own team.json is the only source
        with patch.object(fleet, "TEAM", TEAM):
            self.assertEqual(sorted(fleet.team_catalog()), ["github"])


if __name__ == "__main__":
    unittest.main()

"""The connected apps: the remote MCP address of the hub (the build specification of the MCP address). A local hub of
OwnerAPI, and no Tailscale, no gate process, no network and no AI call. Example names only: the hub's DNS name is
hub-1.tail0000.ts.net.

The feature is dormant in every fleet: validate_team refuses hub.connect, and every part asks hub.capp_allowed()
first, which only hub.CONNECT_TEST makes true. Dormant holds that state as it ships. Every other class turns the
feature on with that one switch, for its own test only (switched_on)."""
import ast
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import time
import unittest
import urllib.parse
import uuid
from pathlib import Path
from unittest.mock import patch

import hub
import oauth_server
from test_ui_api import OwnerAPI

NAME = "hub-1.tail0000.ts.net"          # the hub's DNS name on the private network, an example
MAC, PHONE, OTHER = "127.0.0.1", "127.0.0.5", "127.0.0.9"


def load_tests(loader, _tests, _pattern):
    """Only this file's cases, not the inherited OwnerAPI ones."""
    suite = unittest.TestSuite()
    for cls in (Dormant, OwnerRoutes, Settings, MessageHeader, Opening, CimdCache, Separate, Endpoints, Codes, Tokens,
                Tools):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


def git(*args, cwd=None):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def register(secret, salt="s1"):
    """A registered login, as the vault's registration writes it (test_mobile.register)."""
    hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES(?,?,?,?,?)",
            (f"login {salt}", salt, hashlib.sha256((salt + secret).encode()).hexdigest(), len(secret), ""))


def switched_on(test, connect=True):
    """The one switch of the feature (hub.CONNECT_TEST), on for this test only, with the hub's DNS name and, when
    connect, hub.connect true in the test's team."""
    patcher = patch.object(hub, "CONNECT_TEST", [True])
    patcher.start()
    test.addCleanup(patcher.stop)
    names = dict(hub.TAILNET_NAMES)
    hub.TAILNET_NAMES["names"] = (NAME, NAME.split(".")[0])
    test.addCleanup(lambda: (hub.TAILNET_NAMES.clear(), hub.TAILNET_NAMES.update(names)))
    hub.TEAM.setdefault("hub", {"machine": "hub"})
    if connect:
        hub.TEAM["hub"]["connect"] = True


class Base(OwnerAPI):
    def command(self, path, **body):
        return self.request(path, dict({"request_id": str(uuid.uuid4()), "db": "test-generation"}, **body))

    def device(self, path, body=None):
        """A call of the owner's enrolled phone (MOBILE-APP.md), with its own key."""
        hub.TEAM["owner_devices"] = {"iphone": {"label": "iPhone", "address": PHONE}}
        made = hub.new_device_code("iphone")
        key = hub.enroll_device("iphone", made["code"])["key"]
        headers = {"Content-Type": "application/json", "X-Fleet-Client": "phone", "Authorization": "Bearer " + key}
        return self.request(path, body, headers=headers, source=PHONE)

    def connection(self, level="read", name="Claude", client="https://claude.ai/oauth/x"):
        """One open connection, written as an approval writes it."""
        return hub.ins("INSERT INTO capp_connections(client,name,redirect_host,level,resource,created) "
                       "VALUES(?,?,?,?,?,?)", (client, name, "claude.ai", level, oauth_server.resource(NAME), hub.now()))


class Dormant(Base):
    """What every fleet has after these commits: no part of the feature does anything."""

    ROUTES = (("/ui/connect?db=test-generation", None), ("/ui/connect/code", {"level": "read"}),
              ("/ui/connect/1/revoke", {}), ("/ui/connect/settings", {"on": True}))

    def test_the_switch_is_off_and_no_request_file_or_variable_reaches_it(self):
        self.assertEqual(hub.CONNECT_TEST, [False])
        self.assertFalse(hub.capp_allowed())
        hub.TEAM["hub"] = {"machine": "hub", "connect": True}       # a team.json written by hand
        self.assertFalse(hub.capp_on())
        with patch.dict(os.environ, {"CONNECT_TEST": "1", "FLEET_CONNECT": "1"}):
            self.assertFalse(hub.capp_allowed())
        # The code names the switch twice: its definition, and capp_allowed's reading of it. Nothing writes it.
        tree = ast.parse(Path(hub.__file__).read_text())
        uses = [(type(n.ctx).__name__, n.lineno) for n in ast.walk(tree) if isinstance(n, ast.Name)
                and n.id == "CONNECT_TEST"]
        self.assertEqual([kind for kind, _ in uses], ["Store", "Load"], uses)
        reader = next(f for f in tree.body if isinstance(f, ast.FunctionDef) and f.name == "capp_allowed")
        self.assertEqual(ast.unparse(reader.body[-1]), "return CONNECT_TEST[0] is True")
        self.assertFalse([n for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr == "CONNECT_TEST"])

    def test_validate_team_refuses_hub_connect(self):
        team = {"addresses": {"owner": MAC, "hub": "127.0.0.2"}, "hub": {"machine": "hub"},
                "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []}}}
        hub.validate_team(team)
        for value in (True, False, "yes"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "hub.connect is not in this release"):
                    hub.validate_team(dict(team, hub={"machine": "hub", "connect": value}))

    def test_the_owner_routes_answer_that_the_feature_is_not_here(self):
        for path, body in self.ROUTES:
            with self.subTest(path=path):
                code, answer = self.command(path, **body) if body is not None else self.request(path)
                self.assertEqual((code, answer["error"]), (409, hub.CAPP_NOT_HERE))
        self.assertEqual(self.count("ui_controls"), 0)
        self.assertEqual(self.count("capp_codes"), 0)

    def test_another_address_and_a_phone_are_refused_before_that(self):
        for path, body in self.ROUTES:
            with self.subTest(path=path):
                code, answer = self.request(path, dict(body, request_id=str(uuid.uuid4()), db="test-generation")
                                            if body is not None else None, source=OTHER)
                self.assertEqual(code, 403)
                code, answer = self.device(path, dict(body, request_id=str(uuid.uuid4()), db="test-generation")
                                           if body is not None else None)
                self.assertEqual((code, answer.get("auth")), (403, "device_not_allowed"))
        self.assertFalse(hub.device_may("/ui/connect", "GET"))
        self.assertFalse(hub.device_may("/ui/connect/code", "POST"))

    def test_the_apps_read_nothing_new(self):
        self.assertNotIn("connected_apps", hub.ui_features())
        hub.TEAM["hub"] = {"machine": "hub", "connect": True}
        self.assertNotIn("connected_apps", hub.ui_features())
        event = hub.emit("manager", "say", "[owner] A goal")
        hub.ins("INSERT INTO ui_requests(request_id,kind,text,event_id,created,client,recipient,connection) "
                "VALUES(?,'message','A goal',?,?,'mac','manager',3)", (str(uuid.uuid4()), event, hub.now()))
        code, state = self.request()
        self.assertEqual(code, 200)
        self.assertNotIn("connection", state["messages"][0])
        self.assertEqual(state["messages"][0]["text"], "A goal")


class OwnerRoutes(Base):
    """The owner routes with the feature on (switched_on)."""

    def setUp(self):
        super().setUp()
        switched_on(self)

    def test_the_page_says_the_address_the_open_connections_and_the_gate(self):
        first, second = self.connection(), self.connection("act", "ChatGPT")
        hub.q("UPDATE capp_connections SET revoked=?, ended_by='owner' WHERE id=?", (hub.now(), first))
        code, page = self.request("/ui/connect?db=test-generation")
        self.assertEqual(code, 200, page)
        self.assertEqual((page["db"], page["on"], page["address"]), ("test-generation", True, f"https://{NAME}/mcp"))
        self.assertEqual([(c["id"], c["name"], c["level"]) for c in page["connections"]], [(second, "ChatGPT", "act")])
        self.assertEqual(set(page["connections"][0]), {"id", "name", "level", "last_used", "created"})
        self.assertEqual(page["gate"], {"version": None, "ok": False})
        self.assertEqual(self.request("/ui/connect?db=old")[0], 409)

    def test_a_code_is_shown_once_and_a_new_one_replaces_it(self):
        code, made = self.command("/ui/connect/code", level="read")
        self.assertEqual(code, 200, made)
        self.assertRegex(made["code"], r"^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$")
        self.assertEqual(made["level"], "read")
        self.assertAlmostEqual(made["expires"], hub.now() + 600, delta=5)
        row = hub.q1("SELECT * FROM capp_codes")
        self.assertEqual(row["sha256"], oauth_server.code_sha256(made["code"]))
        self.assertEqual((row["level"], row["used"]), ("read", None))
        self.assertNotIn("wrong", row.keys())                   # nothing counts wrong tries
        kept = json.loads(hub.q1("SELECT result FROM ui_controls")["result"])
        self.assertIsNone(kept["code"])                         # the receipt never keeps the code
        self.assertNotIn(made["code"], json.dumps([dict(r) for r in hub.q("SELECT * FROM log")]))
        code, again = self.command("/ui/connect/code", level="act")
        self.assertEqual(code, 200, again)
        self.assertEqual([(r["level"], r["sha256"]) for r in hub.q("SELECT * FROM capp_codes")],
                         [("act", oauth_server.code_sha256(again["code"]))])
        self.assertEqual(self.command("/ui/connect/code", level="admin")[0], 400)
        self.assertEqual(self.command("/ui/connect/code", level="read", extra=1)[0], 400)

    def test_no_code_while_the_feature_is_off_in_team_json(self):
        hub.TEAM["hub"].pop("connect")
        code, answer = self.command("/ui/connect/code", level="read")
        self.assertEqual((code, answer["error"]), (409, hub.CAPP_OFF))
        self.assertEqual(self.count("capp_codes"), 0)

    def test_revoke_ends_one_connection_and_its_tokens(self):
        mine, other = self.connection(), self.connection(name="ChatGPT", client="https://chatgpt.com/oauth/x")
        for connection in (mine, other):
            hub.ins("INSERT INTO capp_tokens(sha256,connection,kind,created,expires) VALUES(?,?,'access',?,?)",
                    (oauth_server.sha256_hex(f"t{connection}"), connection, hub.now(), hub.now() + 3600))
        hub.ins("INSERT INTO capp_clients(client_id,kind,name,redirect_uris,created) VALUES(?,?,?,?,?)",
                ("https://claude.ai/oauth/x", "cimd", "", "[]", hub.now()))
        code, answer = self.command(f"/ui/connect/{mine}/revoke")
        self.assertEqual((code, answer["id"], answer["revoked"]), (200, mine, True))
        row = hub.q1("SELECT * FROM capp_connections WHERE id=?", (mine,))
        self.assertEqual(row["ended_by"], "owner")
        self.assertIsNotNone(row["revoked"])
        self.assertEqual([r["connection"] for r in hub.q("SELECT connection FROM capp_tokens")], [other])
        self.assertEqual(self.count("capp_clients"), 0)         # its client went with its last connection
        self.assertEqual(self.command(f"/ui/connect/{mine}/revoke")[0], 404)
        self.assertEqual(self.command("/ui/connect/x/revoke")[0], 400)


class Settings(Base):
    """POST /ui/connect/settings: hub.connect in one commit of team.json, through the hub's own checkout."""

    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="fleet-connect-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        seed = self.root / "seed"
        seed.mkdir()
        team = {"hub": {"machine": "hub", "port": 8765}, "addresses": {"owner": MAC, "hub": "127.0.0.2"},
                "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []}}}
        (seed / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", str(self.root / "origin.git"), str(self.root / "kit"))
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = json.loads(json.dumps(team))
        hub.CFG["team_path"] = str(self.root / "kit" / "team.json")
        self.addCleanup(hub.CFG.pop, "team_path", None)
        switched_on(self, connect=False)

    def origin_team(self):
        return json.loads(git("--git-dir", str(self.root / "origin.git"), "show", "main:team.json"))

    def test_on_and_off_are_commits_of_team_json_and_off_ends_every_connection(self):
        code, answer = self.command("/ui/connect/settings", on=True)
        self.assertEqual(code, 200, answer)
        self.assertTrue(answer["on"])
        self.assertIs(self.origin_team()["hub"]["connect"], True)
        self.assertTrue(hub.capp_on())
        open_one = self.connection()
        hub.ins("INSERT INTO capp_codes(sha256,level,created,expires) VALUES('x','read',?,?)", (hub.now(), hub.now() + 9))
        hub.ins("INSERT INTO capp_grants(sha256,client,name,redirect_host,level,redirect_uri,code_challenge,resource,"
                "created,expires) VALUES('g','c','App','claude.ai','read','r','x','r',?,?)", (hub.now(), hub.now() + 60))
        code, answer = self.command("/ui/connect/settings", on=False)
        self.assertEqual(code, 200, answer)
        self.assertEqual((answer["on"], answer["revoked"]), (False, 1))
        self.assertNotIn("connect", self.origin_team()["hub"])
        self.assertFalse(hub.capp_on())
        self.assertEqual(hub.q1("SELECT ended_by FROM capp_connections WHERE id=?", (open_one,))["ended_by"], "off")
        self.assertEqual((self.count("capp_codes"), self.count("capp_grants")), (0, 0))
        self.assertEqual(self.command("/ui/connect/settings", on="yes")[0], 400)


class MessageHeader(Base):
    """What the agent reads of a connected app's message: [owner via app:<name>], the name that the hub chose, in a
    form that no chat app and no device has."""

    def setUp(self):
        super().setUp()
        hub.TEAM["addresses"]["box"] = "127.0.0.3"
        hub.TEAM["agents"]["worker"] = {"role": "worker", "runtime": "claude", "machine": "box", "can": []}

    def test_the_connection_names_the_app_a_chat_app_wins_and_a_device_comes_after(self):
        text = hub.owner_message_text
        self.assertEqual(text("r", "Hi", "manager", None, None, (), connection="Claude"), "[owner via app:Claude] Hi")
        self.assertEqual(text("r", "Hi", "worker", None, None, (), connection="ChatGPT"),
                         "[owner chat request_id=r via=app:ChatGPT] Hi")
        self.assertEqual(text("r", "Hi", "manager", None, None, (), device=True, connection="Claude"),
                         "[owner via app:Claude] Hi")
        self.assertEqual(text("r", "Hi", "worker", None, None, (), connection="App"),
                         "[owner chat request_id=r via=app:App] Hi")
        self.assertEqual(text("r", "Hi", "manager", {"app": "whatsapp", "account": "a"}, None, (),
                              connection="Claude"), "[owner via WhatsApp] Hi")
        self.assertEqual(text("r", "Hi", "manager", None, None, (), device=True), "[owner via iPhone] Hi")
        self.assertEqual(text("r", "Hi", "manager", None, None, ()), "[owner] Hi")

    def test_the_row_keeps_the_connection_and_no_origin(self):
        rid = str(uuid.uuid4())
        with hub.committed():
            event = hub.owner_message_rows(rid, "message", None, "A goal", "connected:7", "manager", None, hub.now(),
                                           connection={"id": 7, "name": "Claude"})
        row = hub.q1("SELECT * FROM ui_requests WHERE request_id=?", (rid,))
        self.assertEqual((row["connection"], row["origin"], row["client"], row["text"]),
                         (7, None, "connected:7", "A goal"))
        self.assertEqual(hub.q1("SELECT text FROM events WHERE id=?", (event,))["text"],
                         "[owner via app:Claude] A goal")
        need = self.need()
        row = hub.q1("SELECT * FROM needs WHERE id=?", (need,))
        with hub.committed():
            event = hub.owner_message_rows(str(uuid.uuid4()), "answer", row, "Blue", "connected:7", "manager", None,
                                           hub.now(), connection={"id": 7, "name": "Claude"})
        self.assertTrue(hub.q1("SELECT text FROM events WHERE id=?", (event,))["text"]
                        .startswith(f"[owner via app:Claude] Answer to Needs-you N-{need} "))

    def sent(self, connection, recipient, words="First words"):
        """One message that a connected app sent, as capp_act writes it: its request id."""
        rid = str(uuid.uuid4())
        with hub.committed():
            hub.owner_message_rows(rid, "message", None, words, f"connected:{connection}", recipient, None, hub.now(),
                                   connection={"id": connection, "name": "Claude"})
        return rid

    def words(self, rid):
        """(what the agent reads of this message, the row's connection, the row's own words)"""
        row = hub.q1("SELECT * FROM ui_requests WHERE request_id=?", (rid,))
        return hub.q1("SELECT text FROM events WHERE id=?", (row["event_id"],))["text"], row["connection"], row["text"]

    def test_an_edit_before_anything_read_it_keeps_the_mark_of_the_connected_app(self):
        """The owner's edit path builds the message again (owner_message_replace). The header comes from the row's
        connection, so no client that the edit names, and no device, takes the app's mark away."""
        connection = self.connection()
        claimed = {"Content-Type": "application/json", "X-Fleet-Client": f"connected:{connection}"}
        for recipient, head in (("manager", "[owner via app:Claude] "),
                                ("worker", "[owner chat request_id={rid} via=app:Claude] ")):
            with self.subTest(recipient=recipient):
                rid = self.sent(connection, recipient)
                self.assertEqual(self.words(rid), (head.format(rid=rid) + "First words", connection, "First words"))
                # the owner's Mac names the app's client, which is the only way to this message's edit path
                code, answer = self.request("/ui/messages", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                             "text": "Other words", "recipient": recipient,
                                                             "replaces_request_id": rid}, headers=claimed)
                self.assertEqual((code, answer.get("edited"), answer.get("message_request_id")), (200, True, rid),
                                 answer)
                self.assertEqual(self.words(rid), (head.format(rid=rid) + "Other words", connection, "Other words"))
                # and an edit that comes with a device's mark: the connection comes before a device
                previous = hub.q1("SELECT * FROM ui_requests WHERE request_id=?", (rid,))
                with hub.committed():
                    hub.owner_message_replace(previous, "Third words", str(uuid.uuid4()), hub.now(), device=True)
                self.assertEqual(self.words(rid), (head.format(rid=rid) + "Third words", connection, "Third words"))
        self.assertEqual(self.count("ui_requests"), 2)          # each edit changed its message where it stands
        # the history reads the edited message with the app's mark too (history_rewrite_message)
        hub.history_catch_up()
        previous = hub.q1("SELECT * FROM ui_requests WHERE request_id=?", (rid,))
        with hub.committed():
            hub.owner_message_replace(previous, "Last words", str(uuid.uuid4()), hub.now())
        row = hub.q1("SELECT rowid FROM ui_requests WHERE request_id=?", (rid,))["rowid"]
        self.assertEqual([r["text"] for r in hub.q("SELECT text FROM history WHERE src='owner_message' AND src_id=?",
                                                    (row,))], ["The owner (through the app Claude): Last words"])
        # a row whose connection the hub cannot read still says that an app sent it, and never reads as his own Mac
        hub.q("DELETE FROM capp_connections WHERE id=?", (connection,))
        previous = hub.q1("SELECT * FROM ui_requests WHERE request_id=?", (rid,))
        with hub.committed():
            hub.owner_message_replace(previous, "No row", str(uuid.uuid4()), hub.now())
        self.assertEqual(self.words(rid)[0], f"[owner chat request_id={rid} via=app:App] No row")
        # the owner's own message has no mark before or after an edit
        own = str(uuid.uuid4())
        self.assertEqual(self.request("/ui/messages", {"request_id": own, "db": "test-generation",
                                                       "text": "My words"})[0], 200)
        self.assertEqual(self.request("/ui/messages", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                       "text": "My other words", "replaces_request_id": own})[0], 200)
        self.assertEqual(self.words(own), ("[owner] My other words", None, "My other words"))


# ---------------------------------------------------------------- the socket, the endpoints and the tools (commit 4)

CLAUDE_CB = "https://claude.ai/api/mcp/auth_callback"
CLAUDE_CIMD = "https://claude.ai/oauth/claude-web-client-metadata"      # an example on the CIMD list
LOOPBACK_CB = "http://localhost:4567/callback"
VERIFIER = "v" * 43 + "-example-verifier"
IN_PLACE = {"TCP": {"443": {"HTTPS": True}}, "Web": {f"{NAME}:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8767"}}}},
            "AllowFunnel": {f"{NAME}:443": True}}


class UnixConnection(http.client.HTTPConnection):
    """http.client over the hub's Unix socket, as the gate connects to it."""
    def __init__(self, path):
        super().__init__("localhost", timeout=10)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(self.path)


class Socket(Base):
    """A hub with the feature on, its socket in a folder of this test, and a stand-in for the serve status."""

    def setUp(self):
        super().setUp()
        switched_on(self)
        self.folder = tempfile.mkdtemp(prefix="capp-", dir="/tmp")     # a short path: a Unix socket's has a limit
        self.addCleanup(shutil.rmtree, self.folder, True)
        for patcher in (patch.object(hub, "CONNECT_DIR", self.folder),
                        patch.object(hub, "capp_serve_status", lambda: self.serve),
                        patch.object(hub, "capp_cimd", self.cimd)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.serve = IN_PLACE
        self.documents = {}
        self.addCleanup(hub.capp_close)
        self.addCleanup(hub.CONNECT.update, said=None, gate=None)

    def cimd(self, client_id):
        if client_id not in self.documents:
            raise oauth_server.CimdRefused("no such document in this test")
        return oauth_server.check_cimd_document(client_id, self.documents[client_id])

    @property
    def sock(self):
        return os.path.join(self.folder, "hub.sock")

    def opened(self):
        self.assertTrue(hub.capp_sync())
        return self.sock

    def http(self, method, path, body=None, headers=None, host=NAME):
        """(status, headers, body bytes) of one request on the hub's socket, with the gate's own headers."""
        conn = UnixConnection(self.sock)
        try:
            head = dict({"Host": host, "X-Gate-Version": hub.GATE_VERSION} if host else {}, **(headers or {}))
            if isinstance(body, dict):
                body = json.dumps(body).encode()
            conn.request(method, path, body=body, headers=head)
            r = conn.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        finally:
            conn.close()

    def raw(self, data):
        """The hub's answer to bytes written as they are."""
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect(self.sock)
            s.sendall(data)
            out = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    return out
                out += chunk

    def form(self, path, fields, headers=None):
        return self.http("POST", path, urllib.parse.urlencode(fields).encode(),
                         dict({"Content-Type": "application/x-www-form-urlencoded"}, **(headers or {})))

    # ---- the steps of a sign-in
    def register(self, redirects=(CLAUDE_CB,), name="An example app"):
        code, _, body = self.http("POST", "/register", {"redirect_uris": list(redirects), "client_name": name},
                                  {"Content-Type": "application/json"})
        self.assertEqual(code, 201, body)
        return json.loads(body)["client_id"]

    def owner_code(self, level="read"):
        code, made = self.command("/ui/connect/code", level=level)
        self.assertEqual(code, 200, made)
        return made["code"]

    def authorize(self, client_id, redirect=CLAUDE_CB, **extra):
        fields = dict({"response_type": "code", "client_id": client_id, "redirect_uri": redirect,
                       "code_challenge": oauth_server.s256(VERIFIER), "code_challenge_method": "S256",
                       "resource": f"https://{NAME}/mcp", "state": "s-1", "scope": "fleet.read"}, **extra)
        return self.http("GET", "/authorize?" + urllib.parse.urlencode(fields))

    def handle(self, page):
        found = re.search(rb'name="handle" value="([^"]+)"', page)
        self.assertIsNotNone(found, page)
        return found.group(1).decode()

    def approve(self, handle, code, origin=None):
        return self.form("/authorize", {"handle": handle, "code": code},
                         {"Origin": origin} if origin else None)

    def code_of(self, head):
        return urllib.parse.parse_qs(urllib.parse.urlsplit(head["Location"]).query)["code"][0]

    def exchange_code(self, client_id, code, redirect=CLAUDE_CB, verifier=VERIFIER):
        status, _, body = self.form("/token", {"grant_type": "authorization_code", "code": code,
                                               "client_id": client_id, "redirect_uri": redirect,
                                               "code_verifier": verifier})
        return status, json.loads(body)

    def signed_in(self, level="read", client_id=None, redirect=CLAUDE_CB):
        """A whole sign-in: (client_id, connection id, access token, refresh token)."""
        client_id = client_id or self.register((redirect,))
        typed = self.owner_code(level)
        status, _, page = self.authorize(client_id, redirect)
        self.assertEqual(status, 200, page)
        status, head, _ = self.approve(self.handle(page), typed)
        self.assertEqual(status, 303)
        got = urllib.parse.parse_qs(urllib.parse.urlsplit(head["Location"]).query)
        self.assertEqual((got["state"], got["iss"]), (["s-1"], [f"https://{NAME}"]))
        status, _, body = self.form("/token", {"grant_type": "authorization_code", "code": got["code"][0],
                                               "client_id": client_id, "redirect_uri": redirect,
                                               "code_verifier": VERIFIER, "resource": f"https://{NAME}/mcp"})
        self.assertEqual(status, 200, body)
        tokens = json.loads(body)
        connection = hub.q1("SELECT id FROM capp_connections ORDER BY id DESC LIMIT 1")["id"]
        return client_id, connection, tokens["access_token"], tokens["refresh_token"]

    def mcp(self, token, method, params=None, mid=1, headers=None):
        message = {"jsonrpc": "2.0", "method": method, **({"id": mid} if mid is not None else {}),
                   **({"params": params} if params is not None else {})}
        status, head, body = self.http("POST", "/mcp", message, dict({"Content-Type": "application/json",
                                                                      "Accept": "application/json, text/event-stream",
                                                                      "Authorization": "Bearer " + token},
                                                                     **(headers or {})))
        return status, head, json.loads(body) if body else None

    def call(self, token, tool, **args):
        status, head, answer = self.mcp(token, "tools/call", {"name": tool, "arguments": args})
        return status, head, answer


class Opening(Socket):
    """When the hub opens its socket, and what it is."""

    def test_the_socket_opens_only_when_every_condition_holds(self):
        self.assertTrue(hub.capp_sync())
        mode = os.stat(self.sock).st_mode
        self.assertTrue(stat.S_ISSOCK(mode))
        self.assertEqual(stat.S_IMODE(mode), 0o660)
        hub.TEAM["hub"].pop("connect")
        self.assertFalse(hub.capp_sync())
        self.assertFalse(os.path.exists(self.sock))
        hub.TEAM["hub"]["connect"] = True
        with patch.object(hub, "CONNECT_TEST", [False]):
            self.assertFalse(hub.capp_sync())
            self.assertIsNone(hub.capp_sync_later())        # dormant: no thread starts at all
        with patch.object(hub, "CONNECT_DIR", self.folder + "-missing"):
            self.assertFalse(hub.capp_sync())
        hub.TAILNET_NAMES["names"] = ()
        self.assertFalse(hub.capp_sync())
        self.assertFalse(os.path.exists(self.sock))

    def test_funnel_to_anything_else_or_a_failed_read_keeps_it_closed(self):
        to_hub = json.loads(json.dumps(IN_PLACE))
        to_hub["Web"][f"{NAME}:443"]["Handlers"]["/"]["Proxy"] = "http://127.0.0.1:8765"
        to_socket = json.loads(json.dumps(IN_PLACE))
        to_socket["Web"][f"{NAME}:8443"] = {"Handlers": {"/": {"Proxy": "unix:/var/run/hub.sock"}}}
        to_socket["AllowFunnel"][f"{NAME}:8443"] = True
        for serve in (to_hub, to_socket, {}, {"TCP": {"443": {"TCPForward": "127.0.0.1:8765"}},
                                              "AllowFunnel": {f"{NAME}:443": True}}):
            with self.subTest(serve=serve):
                self.serve = serve
                self.assertFalse(hub.capp_sync())
                self.assertFalse(os.path.exists(self.sock))

        def fails():
            raise OSError("the stand-in has no tailscale")
        with patch.object(hub, "capp_serve_status", fails):
            self.assertFalse(hub.capp_sync())
        said = [r["what"] for r in hub.q("SELECT what FROM log")]
        self.assertTrue(any("stays closed" in s for s in said), said)

    def test_a_stale_socket_file_goes_and_a_file_that_is_no_socket_stays(self):
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(self.sock)
        stale.close()
        self.assertTrue(hub.capp_sync())
        self.assertEqual(self.http("GET", "/.well-known/oauth-authorization-server")[0], 200)
        hub.capp_close()
        Path(self.sock).write_text("not a socket")
        self.assertFalse(hub.capp_sync())
        self.assertEqual(Path(self.sock).read_text(), "not a socket")

    def test_the_apps_see_connected_apps_after_the_gates_first_forward(self):
        self.opened()
        self.assertNotIn("connected_apps", hub.ui_features())
        self.assertEqual(self.http("GET", "/.well-known/oauth-protected-resource")[0], 200)
        self.assertIn("connected_apps", hub.ui_features())
        self.assertEqual(self.request("/ui/connect")[1]["gate"], {"version": hub.GATE_VERSION, "ok": True})
        import gate
        self.assertEqual(hub.GATE_VERSION, gate.VERSION)


class CimdCache(unittest.TestCase):
    """Fix 9 of the security reviews: one client_id's metadata document is fetched at most once in 300 seconds, and
    the hub keeps at most 50; a refusal is kept no longer than a document."""

    def setUp(self):
        self.fetched = []
        for patcher in (patch.object(hub, "CAPP_CIMD", {"lock": hub.threading.Lock(), "kept": {}, "fetching": {}}),
                        patch.object(oauth_server, "fetch_cimd", self.fetch)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def fetch(self, client_id):
        self.fetched.append(client_id)
        if client_id.endswith("/refused"):
            raise oauth_server.CimdRefused("no such document in this test")
        return {"client_id": client_id, "client_name": "", "redirect_uris": [CLAUDE_CB],
                "grant_types": ["authorization_code"]}

    def age(self, client_id, seconds):
        at, doc, why = hub.CAPP_CIMD["kept"][client_id]
        hub.CAPP_CIMD["kept"][client_id] = (at - seconds, doc, why)

    def test_a_document_and_a_refusal_are_kept_300_seconds(self):
        good, bad = "https://claude.ai/oauth/a", "https://claude.ai/oauth/refused"
        first = hub.capp_cimd(good)
        first["redirect_uris"].append("changed")                       # a copy: what is kept stays
        self.assertEqual(hub.capp_cimd(good)["redirect_uris"], [CLAUDE_CB])
        for _ in range(2):
            with self.assertRaises(oauth_server.CimdRefused):
                hub.capp_cimd(bad)
        self.assertEqual(self.fetched, [good, bad])
        self.age(good, hub.CAPP_CIMD_LIFE - 5)
        self.age(bad, hub.CAPP_CIMD_LIFE + 1)
        hub.capp_cimd(good)
        with self.assertRaises(oauth_server.CimdRefused):
            hub.capp_cimd(bad)
        self.assertEqual(self.fetched, [good, bad, bad])
        self.age(good, 10)
        hub.capp_cimd(good)
        self.assertEqual(self.fetched, [good, bad, bad, good])

    def test_at_most_fifty_are_kept_and_the_oldest_goes(self):
        ids = [f"https://claude.ai/oauth/c{n}" for n in range(hub.CAPP_CIMD_KEPT + 1)]
        for n, client_id in enumerate(ids):
            hub.capp_cimd(client_id)
            self.age(client_id, len(ids) - n)               # the first one fetched is the oldest
        self.assertEqual(len(hub.CAPP_CIMD["kept"]), hub.CAPP_CIMD_KEPT)
        self.assertNotIn(ids[0], hub.CAPP_CIMD["kept"])
        self.assertEqual(hub.CAPP_CIMD["fetching"], {})


class Separate(unittest.TestCase):
    """Rules 3 and 5 of section 1: the connected apps' code is not Handler's and never asks who calls by address."""

    def test_connect_handler_is_not_handler_and_shares_no_method(self):
        self.assertNotIn(hub.Handler, hub.ConnectHandler.__mro__)
        self.assertNotIn(hub.ConnectHandler, hub.Handler.__mro__)
        own = {k: v for k, v in vars(hub.ConnectHandler).items() if callable(v)}
        for key, value in own.items():
            self.assertIsNot(value, vars(hub.Handler).get(key), key)
            # the base class's own hooks, by name: the routes, the log line and the Server header
            self.assertTrue(key.startswith("capp_") or key in ("do_GET", "do_POST", "do_DELETE", "log_message",
                                                               "version_string"), key)

    def test_the_connected_apps_code_never_calls_an_owner_gate_or_handler(self):
        tree = ast.parse(Path(hub.__file__).read_text())
        region = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))
                  and (n.name.startswith("capp_") or n.name in ("ConnectHandler", "CappServer", "save_connect"))]
        self.assertGreater(len(region), 30)
        banned = {"ui_allowed", "allowed", "device_allowed", "session_allowed", "Handler", "bridge_allowed",
                  "owner_device_at", "address_of"}
        found = [(n.name, x.attr if isinstance(x, ast.Attribute) else x.id) for n in region for x in ast.walk(n)
                 if isinstance(x, ast.Attribute) and x.attr in banned or isinstance(x, ast.Name) and x.id in banned]
        self.assertEqual(found, [])
        reads = [n.name for n in region for x in ast.walk(n)
                 if isinstance(x, ast.Attribute) and x.attr == "client_address"]
        self.assertEqual(reads, [])

    def test_each_tool_is_a_route_that_a_phone_may_call_and_nothing_more(self):
        self.assertEqual([t["name"] for t in hub.capp_tools("read")],
                         ["fleet_status", "read_task", "read_chat", "read_knowledge"])
        self.assertEqual([t["name"] for t in hub.capp_tools("act")],
                         ["fleet_status", "read_task", "read_chat", "read_knowledge", "send_message", "answer_need",
                          "discuss_need", "control_task", "steer_task"])
        for tool in hub.CAPP_TOOLS:
            with self.subTest(tool=tool["name"]):
                self.assertTrue(hub.device_may(*tool["route"]), tool["route"])
                self.assertIs(tool["annotations"]["openWorldHint"], False)
                self.assertIs(tool["annotations"]["readOnlyHint"], tool["level"] == "read")
                if tool["level"] == "act":
                    self.assertIs(tool["annotations"]["destructiveHint"], tool["name"] == "control_task")
        for never in ("/ui/needs/1/secret", "/ui/tasks/1/desktop", "/ui/wait", "/ui/owner/devices", "/ui/state",
                      "/ui/attachments"):
            self.assertFalse(any(t["route"][0] == never or t["route"][0].startswith(never + "/")
                                 for t in hub.CAPP_TOOLS), never)


class Endpoints(Socket):
    """The OAuth endpoints and the checks before them (sections 1 and 3)."""

    def setUp(self):
        super().setUp()
        self.opened()

    def test_an_answer_names_the_hub_and_no_version_of_python(self):
        # these answers reach the Internet: a good one, a refused one and a page
        for method, path in (("GET", "/.well-known/oauth-authorization-server"), ("POST", "/mcp"),
                             ("GET", "/authorize")):
            _, head, _ = self.http(method, path, body={} if method == "POST" else None)
            self.assertEqual(head["Server"], "Founderizer", (method, path))

    def test_the_two_metadata_documents(self):
        for path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
            status, head, body = self.http("GET", path)
            self.assertEqual((status, head["Cache-Control"]), (200, "no-store"))
            self.assertEqual(json.loads(body), oauth_server.protected_resource_metadata(NAME))
        status, _, body = self.http("GET", "/.well-known/oauth-authorization-server")
        self.assertEqual(json.loads(body)["issuer"], f"https://{NAME}")

    def test_a_foreign_host_or_two_hosts_or_none(self):
        for host in ("example.com", f"{NAME}:8765", f"x.{NAME}", NAME.split(".")[0]):
            with self.subTest(host=host):
                self.assertEqual(self.http("GET", "/.well-known/oauth-authorization-server", host=host)[0], 421)
        self.assertEqual(self.http("GET", "/.well-known/oauth-authorization-server", host=f"{NAME.upper()}:443")[0],
                         200)
        two = self.raw(f"GET /mcp HTTP/1.1\r\nHost: {NAME}\r\nHost: {NAME}\r\n\r\n".encode())
        self.assertTrue(two.startswith(b"HTTP/1.1 400 "), two[:60])
        none = self.raw(b"GET /mcp HTTP/1.1\r\nX-Gate-Version: 1\r\n\r\n")
        self.assertTrue(none.startswith(b"HTTP/1.1 400 "), none[:60])

    def test_only_the_routes_of_the_gate_and_the_body_limits(self):
        for path in ("/ui/state", "/ui/mobile", "/mcp/manager", "/authorize/", "/helper/status/manager", "/"):
            with self.subTest(path=path):
                self.assertEqual(self.http("GET", path)[0], 404)
        self.assertEqual(self.http("GET", "/mcp")[0], 405)
        self.assertEqual(self.http("DELETE", "/mcp")[1].get("Allow"), "POST")
        # the size that the head gives is refused before the hub reads a byte of the body
        for path, size in (("/mcp", 65 * 1024 + 1), ("/register", 8193), ("/token", 8193)):
            with self.subTest(path=path):
                answer = self.raw(f"POST {path} HTTP/1.1\r\nHost: {NAME}\r\nContent-Type: application/json\r\n"
                                  f"Content-Length: {size}\r\n\r\n".encode())
                self.assertTrue(answer.startswith(b"HTTP/1.1 413 "), answer[:60])
        self.assertEqual(self.http("POST", "/mcp", b"x" * (64 * 1024), {"Content-Type": "application/json"})[0], 401)

    def test_transfer_encoding_and_two_content_lengths_are_refused(self):
        for head in ("Transfer-Encoding: chunked\r\n", "Content-Length: 2\r\nContent-Length: 2\r\n",
                     "Content-Length: 2\r\nTransfer-Encoding: chunked\r\n", "Content-Length: +2\r\n"):
            with self.subTest(head=head):
                answer = self.raw(f"POST /register HTTP/1.1\r\nHost: {NAME}\r\nContent-Type: application/json\r\n"
                                  f"{head}\r\n{{}}".encode())
                self.assertTrue(answer.startswith(b"HTTP/1.1 400 "), answer[:60])
        self.assertEqual(self.count("capp_clients"), 0)

    def test_a_browser_origin_is_refused_on_the_api_and_the_page_cannot_be_framed(self):
        for path in ("/token", "/register", "/revoke", "/mcp"):
            with self.subTest(path=path):
                self.assertEqual(self.http("POST", path, b"{}", {"Origin": "https://example.com",
                                                                 "Content-Type": "application/json"})[0], 403)
        client_id = self.register()
        status, head, page = self.authorize(client_id)
        self.assertEqual(status, 200, page)
        self.assertEqual(head["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", head["Content-Security-Policy"])
        self.assertIn("form-action 'self' https://claude.ai;", head["Content-Security-Policy"])
        handle = self.handle(page)
        for origin in ("https://example.com", f"https://{NAME}:443", f"http://{NAME}", "null", f"https://x.{NAME}"):
            with self.subTest(origin=origin):
                self.assertEqual(self.approve(handle, self.owner_code(), origin=origin)[0], 403)
        self.assertEqual(self.approve(handle, self.owner_code(), origin=f"https://{NAME}")[0], 303)

    def test_the_sign_in_page_is_the_approved_text_with_no_script(self):
        client_id = self.register()
        self.owner_code("act")
        status, _, page = self.authorize(client_id)
        text = page.decode()
        self.assertIn("<title>Founderizer</title>", text)
        # the first line names no level: the level is the one of the owner's code, and the page says no code's level
        self.assertIn("<p><strong>Claude</strong> wants to connect to your fleet.</p>", text)
        self.assertNotIn("read", re.sub(r'<input type="hidden"[^>]*>', "", text))
        self.assertIn("It returns to claude.ai", text)
        self.assertIn("Code from your Mac", text)
        self.assertIn(">Approve</button>", text)
        self.assertNotIn(hub.CAPP_LOOPBACK_LINE, text)
        for never in ("<script", "<img", "<link", "src=", "http://", "https://"):
            self.assertNotIn(never, text)
        local = self.register((LOOPBACK_CB,), name="Example CLI")
        status, _, page = self.authorize(local, "http://localhost:9999/callback")
        self.assertEqual(status, 200, page)
        self.assertIn("<strong>Example CLI</strong>", page.decode())
        self.assertIn("It returns to localhost", page.decode())
        self.assertIn(hub.CAPP_LOOPBACK_LINE, page.decode())

    def test_a_client_or_a_redirect_that_is_not_proved_gets_a_page_and_no_redirect(self):
        client_id = self.register()
        for client, redirect in ((client_id, "https://claude.ai.example.com/cb"),
                                 (client_id, "https://chatgpt.com.example.com/cb"),
                                 (client_id, "http://10.0.0.1/cb"), (client_id, CLAUDE_CB + "/x"),
                                 (client_id, "https://chatgpt.com/connector_platform_oauth_redirect"),
                                 ("x" * 43, CLAUDE_CB), ("https://claude.ai/oauth/unknown", CLAUDE_CB),
                                 ("https://example.com/oauth/x", CLAUDE_CB)):
            with self.subTest(client=client, redirect=redirect):
                status, head, page = self.authorize(client, redirect)
                self.assertEqual(status, 400)
                self.assertNotIn("Location", head)
                self.assertIn(hub.CAPP_PAGE_ERRORS["client"], page.decode())
        status, _, body = self.http("POST", "/register", {"redirect_uris": ["https://claude.ai.example.com/cb"]},
                                    {"Content-Type": "application/json"})
        self.assertEqual((status, json.loads(body)["error"]), (400, "invalid_redirect_uri"))

    def test_a_client_deleted_between_the_page_and_the_approval_is_refused(self):
        client_id = self.register()
        handle = self.handle(self.authorize(client_id)[2])
        right = self.owner_code()
        hub.q("DELETE FROM capp_clients WHERE client_id=?", (client_id,))
        status, head, page = self.approve(handle, right)
        self.assertEqual(status, 400)
        self.assertNotIn("Location", head)
        self.assertIn(hub.CAPP_PAGE_ERRORS["client"], page.decode())
        self.assertIsNone(hub.q1("SELECT used FROM capp_codes")["used"])      # the code stays the owner's
        self.assertEqual(self.count("capp_grants"), 0)

    def test_after_the_redirect_is_proved_an_error_goes_to_it_with_state_and_iss(self):
        client_id = self.register()
        for extra, error in (({"response_type": "token"}, "unsupported_response_type"),
                             ({"code_challenge_method": "plain"}, "invalid_request"),
                             ({"resource": f"https://{NAME}/other"}, "invalid_target")):
            with self.subTest(error=error):
                status, head, _ = self.authorize(client_id, **extra)
                self.assertEqual(status, 303)
                got = urllib.parse.parse_qs(urllib.parse.urlsplit(head["Location"]).query)
                self.assertEqual((got["error"], got["state"], got["iss"]), ([error], ["s-1"], [f"https://{NAME}"]))
        self.assertEqual((self.count("capp_grants"), self.count("capp_connections")), (0, 0))

    def test_a_cimd_client_is_written_at_its_first_connection_only(self):
        self.documents[CLAUDE_CIMD] = {"client_id": CLAUDE_CIMD, "client_name": "Claude", "redirect_uris": [CLAUDE_CB],
                                       "token_endpoint_auth_method": "none"}
        status, _, page = self.authorize(CLAUDE_CIMD)
        self.assertEqual(status, 200, page)
        self.assertEqual(self.count("capp_clients"), 0)
        status, head, _ = self.approve(self.handle(page), self.owner_code())
        self.assertEqual(status, 303)
        self.assertEqual((self.count("capp_clients"), self.count("capp_connections")), (0, 0))
        self.assertEqual(self.exchange_code(CLAUDE_CIMD, self.code_of(head))[0], 200)
        self.assertEqual([(r["client_id"], r["kind"], json.loads(r["redirect_uris"]))
                          for r in hub.q("SELECT * FROM capp_clients")], [(CLAUDE_CIMD, "cimd", [CLAUDE_CB])])
        self.assertEqual(hub.q1("SELECT name FROM capp_connections")["name"], "Claude")

    def test_a_dynamic_client_cannot_name_itself_claude(self):
        for name in ("Claude Desktop", "iPhone", "Whats App", "manager"):
            with self.subTest(name=name):
                client_id = self.register((LOOPBACK_CB,), name=name)
                _, connection, _, _ = self.signed_in(client_id=client_id, redirect=LOOPBACK_CB)
                self.assertEqual(hub.q1("SELECT name FROM capp_connections WHERE id=?", (connection,))["name"], "App")

    def test_markup_in_a_clients_name_is_escaped_on_the_page(self):
        # clean_name lets no markup through; a stand-in that lets it through shows that the page escapes it itself
        with patch.object(oauth_server, "clean_name", lambda value: value if isinstance(value, str) else ""):
            client_id = self.register((LOOPBACK_CB,), name='<script>alert(1)</script> & "x"')
            status, _, page = self.authorize(client_id, LOOPBACK_CB)
        self.assertEqual(status, 200, page)
        text = page.decode()
        self.assertIn("<strong>&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;x&quot;</strong>", text)
        self.assertNotIn("<script", text)

    def test_the_fifty_first_idle_registration_takes_the_place_of_the_oldest(self):
        first = self.register()
        for _ in range(oauth_server.CLIENTS_MAX):
            self.register()
        self.assertEqual(self.count("capp_clients"), oauth_server.CLIENTS_MAX)
        self.assertIsNone(hub.q1("SELECT 1 FROM capp_clients WHERE client_id=?", (first,)))

    def test_a_flood_of_pages_writes_no_row_and_pushes_out_no_page(self):
        client_id = self.register()
        first = self.handle(self.authorize(client_id)[2])
        tables = [r["name"] for r in hub.q("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'capp_%'")]
        before = {t: self.count(t) for t in tables}
        for _ in range(30):
            self.assertEqual(self.authorize(client_id)[0], 200)
        self.assertEqual({t: self.count(t) for t in tables}, before)
        self.assertNotIn("capp_pending", tables)
        self.assertEqual(self.approve(first, self.owner_code())[0], 303)       # the first page still works

    def test_a_handle_that_was_changed_made_with_another_key_or_too_old_is_refused(self):
        client_id = self.register()
        handle = self.handle(self.authorize(client_id)[2])
        right = self.owner_code()
        text, _, mac = handle.partition(".")
        fields = json.loads(oauth_server._unb64(text))
        changed = oauth_server._b64(json.dumps(dict(fields, redirect_uri=LOOPBACK_CB)).encode()) + "." + mac
        other = oauth_server.make_handle(b"another key of 32 bytes, example", fields, hub.now())
        for bad in (changed, other, handle[:-2], "x", ""):
            with self.subTest(bad=bad[:20]):
                status, head, page = self.approve(bad, right)
                self.assertEqual(status, 400)
                self.assertIn(hub.CAPP_PAGE_ERRORS["client"], page.decode())
        later = hub.now() + oauth_server.HANDLE_LIFE + 1
        with patch.object(hub, "now", lambda: later):
            hub.q("UPDATE capp_codes SET expires=?", (later + 60,))
            self.assertEqual(self.approve(handle, right)[0], 400)
        self.assertEqual(self.approve(handle, right)[0], 303)
        self.assertNotIn(hub.kv_get("capp_handle_key"), json.dumps([dict(r) for r in hub.q("SELECT * FROM log")]))


class Codes(Socket):
    """The owner's one-time code at the sign-in page (threats 1 and 2)."""

    def setUp(self):
        super().setUp()
        self.opened()
        self.client_id = self.register()

    def page(self):
        status, _, page = self.authorize(self.client_id)
        self.assertEqual(status, 200, page)
        return self.handle(page)

    def test_no_open_code_and_a_wrong_code_get_one_answer_and_make_no_connection(self):
        handle = self.page()
        none = self.approve(handle, "")
        self.owner_code()
        empty, wrong = self.approve(handle, ""), self.approve(handle, "ZZZZ-ZZZZ-ZZZZ")
        for status, _, page in (none, empty, wrong):
            self.assertEqual(status, 403)
            self.assertIn(hub.CAPP_PAGE_ERRORS["code"], page.decode())
        self.assertEqual(none[2], empty[2])             # the same page: nothing says whether a code is open
        self.assertEqual((self.count("capp_connections"), self.count("capp_grants")), (0, 0))

    def test_wrong_tries_end_nothing_so_a_stranger_cannot_lock_the_owner_out(self):
        right, handle = self.owner_code(), self.page()
        wrong = "ZZZZ-ZZZZ-ZZZZ" if right != "ZZZZ-ZZZZ-ZZZZ" else "YYYY-YYYY-YYYY"
        for _ in range(25):
            self.assertEqual(self.approve(handle, wrong)[0], 403)
        self.assertEqual(self.approve(handle, right)[0], 303)
        self.assertNotIn("wrong", hub.q1("SELECT * FROM capp_codes").keys())

    def test_an_expired_owner_code_is_refused(self):
        right, handle = self.owner_code(), self.page()
        hub.q("UPDATE capp_codes SET expires=?", (hub.now() - 1,))
        status, _, page = self.approve(handle, right)
        self.assertEqual(status, 403)
        self.assertIn(hub.CAPP_PAGE_ERRORS["code"], page.decode())
        self.assertEqual(self.count("capp_grants"), 0)

    def test_the_right_code_in_any_case_and_with_no_dash_approves_once(self):
        right, handle = self.owner_code("act"), self.page()
        status, head, _ = self.approve(handle, right.lower().replace("-", ""))
        self.assertEqual(status, 303)
        self.assertTrue(head["Location"].startswith(CLAUDE_CB + "?code="))
        self.assertEqual(self.count("capp_connections"), 0)            # the exchange makes it (capp_token)
        row = hub.q1("SELECT * FROM capp_grants")
        self.assertEqual((row["name"], row["level"], row["redirect_host"], row["resource"], row["connection"]),
                         ("Claude", "act", "claude.ai", f"https://{NAME}/mcp", None))
        self.assertIsNotNone(hub.q1("SELECT used FROM capp_codes")["used"])
        self.assertEqual(self.approve(handle, right)[0], 403)           # the code is used
        self.assertEqual(self.approve(self.page(), right)[0], 403)


class Tokens(Socket):
    """The token endpoint (threats 3, 4 and 5)."""

    def setUp(self):
        super().setUp()
        self.opened()

    def grant(self):
        client_id = self.register()
        self.owner_code()
        _, head, _ = self.approve(self.handle(self.authorize(client_id)[2]), self.last_code)
        return client_id, urllib.parse.parse_qs(urllib.parse.urlsplit(head["Location"]).query)["code"][0]

    def owner_code(self, level="read"):
        self.last_code = super().owner_code(level)
        return self.last_code

    def exchange(self, client, code, **extra):
        fields = {"grant_type": "authorization_code", "code": code, "client_id": client, "redirect_uri": CLAUDE_CB,
                  "code_verifier": VERIFIER}
        fields.update(extra)
        status, _, body = self.form("/token", fields)
        return status, json.loads(body)

    def refresh(self, client_id, token):
        status, _, body = self.form("/token", {"grant_type": "refresh_token", "refresh_token": token,
                                               "client_id": client_id})
        return status, json.loads(body)

    def test_a_code_gives_a_pair_only_with_its_verifier_and_a_failed_exchange_makes_no_connection(self):
        client_id, code = self.grant()
        status, answer = self.exchange(client_id, code, code_verifier="w" * 43)
        self.assertEqual((status, answer["error"]), (400, "invalid_grant"))
        self.assertEqual(self.count("capp_connections"), 0)
        status, answer = self.exchange(client_id, code)             # the second use of the code
        self.assertEqual((status, answer["error"]), (400, "invalid_grant"))
        self.assertEqual((self.count("capp_connections"), self.count("capp_tokens")), (0, 0))
        self.assertEqual(self.request("/ui/connect?db=test-generation")[1]["connections"], [])

    def test_a_second_use_of_a_code_that_connected_ends_its_connection(self):
        client_id, code = self.grant()
        self.assertEqual(self.exchange(client_id, code)[0], 200)
        self.assertEqual(hub.q1("SELECT connection FROM capp_grants")["connection"],
                         hub.q1("SELECT id FROM capp_connections")["id"])
        status, answer = self.exchange(client_id, code)
        self.assertEqual((status, answer["error"]), (400, "invalid_grant"))
        self.assertEqual(hub.q1("SELECT ended_by FROM capp_connections")["ended_by"], "code_reuse")
        self.assertEqual((self.count("capp_tokens"), self.count("capp_grants")), (0, 0))

    def test_an_approval_with_no_exchange_lists_no_connection(self):
        self.grant()
        self.assertEqual(self.count("capp_connections"), 0)
        self.assertEqual(self.request("/ui/connect?db=test-generation")[1]["connections"], [])

    def test_a_good_exchange_and_what_is_kept(self):
        client_id, code = self.grant()
        status, answer = self.exchange(client_id, code, resource=f"https://{NAME.upper()}/mcp")
        self.assertEqual(status, 200, answer)
        self.assertEqual((answer["token_type"], answer["expires_in"], answer["scope"]), ("Bearer", 3600, "fleet.read"))
        kept = json.dumps([dict(r) for t in ("capp_tokens", "capp_grants", "capp_codes",
                                             "capp_connections", "log") for r in hub.q(f"SELECT * FROM {t}")])
        for raw in (answer["access_token"], answer["refresh_token"], code, self.last_code):
            self.assertNotIn(raw, kept)
        self.assertEqual(self.exchange(client_id, code)[1]["error"], "invalid_grant")

    def test_each_check_of_the_exchange(self):
        for extra, error in (({"client_id": "y" * 43}, "invalid_grant"),
                             ({"redirect_uri": "https://claude.com/api/mcp/auth_callback"}, "invalid_grant"),
                             ({"resource": f"https://{NAME}/mcp/"}, "invalid_target")):
            with self.subTest(error=error, extra=extra):
                client_id, code = self.grant()
                self.assertEqual(self.exchange(client_id, code, **extra)[1]["error"], error)
        client_id, code = self.grant()
        hub.q("UPDATE capp_grants SET expires=?", (hub.now() - 1,))
        self.assertEqual(self.exchange(client_id, code)[1]["error"], "invalid_grant")
        self.assertEqual(self.count("capp_connections"), 0)         # no failed exchange made a connection

    def approved(self, client_id):
        """One more approval for a client that is registered: its authorization code, not exchanged yet."""
        self.owner_code()
        status, head, _ = self.approve(self.handle(self.authorize(client_id)[2]), self.last_code)
        self.assertEqual(status, 303)
        return self.code_of(head)

    def test_a_dynamic_client_whose_row_went_after_the_approval_cannot_exchange_its_code(self):
        """The two ways a dynamic client's row goes between the approval and the exchange (the confirm review of 12
        November 2026): with the revoke of its last connection, and as the oldest of more than 50 idle clients."""
        # 1. its only connection is revoked while a second approval waits for its exchange
        client_id, code = self.grant()
        self.assertEqual(self.exchange(client_id, code)[0], 200)
        first = hub.q1("SELECT id FROM capp_connections")["id"]
        waiting = self.approved(client_id)
        self.assertEqual(self.command(f"/ui/connect/{first}/revoke")[0], 200)
        self.assertEqual(self.count("capp_clients"), 0)
        status, answer = self.exchange(client_id, waiting)
        self.assertEqual((status, answer["error"]), (400, "invalid_grant"), answer)
        self.assertEqual([r["id"] for r in hub.q("SELECT id FROM capp_connections WHERE revoked IS NULL")], [])
        self.assertEqual((self.count("capp_connections"), self.count("capp_tokens")), (1, 0))
        self.assertIsNotNone(hub.q1("SELECT used FROM capp_grants")["used"])        # the code is used: no second try
        self.assertEqual(self.exchange(client_id, waiting)[1]["error"], "invalid_grant")
        self.assertEqual(self.request("/ui/connect?db=test-generation")[1]["connections"], [])
        # 2. the cap of idle clients takes the row of the oldest, which has an approval that waits
        hub.q("DELETE FROM capp_grants")
        client_id, code = self.grant()
        for _ in range(oauth_server.CLIENTS_MAX):
            self.register()
        self.assertIsNone(hub.q1("SELECT 1 FROM capp_clients WHERE client_id=?", (client_id,)))
        status, answer = self.exchange(client_id, code)
        self.assertEqual((status, answer["error"]), (400, "invalid_grant"), answer)
        self.assertEqual((self.count("capp_connections"), self.count("capp_tokens")), (1, 0))
        # a client of a metadata document has no row before its first connection, and its exchange is not refused
        self.documents[CLAUDE_CIMD] = {"client_id": CLAUDE_CIMD, "client_name": "Claude", "redirect_uris": [CLAUDE_CB],
                                       "token_endpoint_auth_method": "none"}
        self.assertEqual(self.exchange(CLAUDE_CIMD, self.approved(CLAUDE_CIMD))[0], 200)

    def test_a_restore_takes_the_key_of_the_page_handle_away(self):
        """A backup holds the key that signs a sign-in page's handle (kv capp_handle_key), so a restore starts a new
        one: a page that the copy's key signed is refused, also with the owner's right code."""
        client_id = self.register()
        old_page = self.handle(self.authorize(client_id)[2])
        old_key = hub.kv_get("capp_handle_key")
        self.assertTrue(old_key)
        hub.capp_restored()
        self.assertIsNone(hub.kv_get("capp_handle_key"))
        right = self.owner_code()
        status, head, page = self.approve(old_page, right)
        self.assertEqual(status, 400)
        self.assertNotIn("Location", head)
        self.assertIn(hub.CAPP_PAGE_ERRORS["client"], page.decode())
        self.assertIsNone(hub.q1("SELECT used FROM capp_codes")["used"])      # the code stays the owner's
        new_key = hub.kv_get("capp_handle_key")
        self.assertTrue(new_key and new_key != old_key and len(new_key) == 64)
        status, head, _ = self.approve(self.handle(self.authorize(client_id)[2]), right)     # a page of the new key
        self.assertEqual(status, 303)
        self.assertEqual(self.exchange(client_id, self.code_of(head))[0], 200)

    def test_no_client_authentication_of_any_kind(self):
        client_id, code = self.grant()
        for extra, head in (({"client_secret": "x"}, None), ({"client_assertion": "x.y.z"}, None),
                            ({"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, None),
                            ({}, {"Authorization": "Basic eDp5"})):
            with self.subTest(extra=extra, head=head):
                status, _, body = self.form("/token", dict({"grant_type": "authorization_code", "code": code,
                                                            "client_id": client_id, "redirect_uri": CLAUDE_CB,
                                                            "code_verifier": VERIFIER}, **extra), head)
                self.assertEqual((status, json.loads(body)["error"]), (400, "invalid_client"))
        self.assertEqual(self.exchange(client_id, code)[0], 200)        # none of them used the code
        self.assertEqual(self.http("POST", "/token", b"{}", {"Content-Type": "application/json"})[0], 415)

    # The four orders of a stolen refresh token (the security reviews of 12 November 2026). The hub cannot tell the
    # real client from the thief, so whoever uses a token of the pair that gave way, or the old token after its
    # successor was used, ends the connection.
    def paired(self):
        client_id, code = self.grant()
        _, first = self.exchange(client_id, code)
        return client_id, first

    def ended_by(self):
        return hub.q1("SELECT ended_by FROM capp_connections ORDER BY id DESC")["ended_by"]

    def use(self, client_id, pair, how):
        """One use of a pair: its access token at /mcp, or its refresh token at /token. The HTTP status."""
        if how == "access":
            return self.mcp(pair["access_token"], "ping")[0]
        return self.refresh(client_id, pair["refresh_token"])[0]

    def test_rotation_gives_a_new_pair_and_the_old_refresh_token_is_replaced(self):
        client_id, first = self.paired()
        status, second = self.refresh(client_id, first["refresh_token"])
        self.assertEqual(status, 200, second)
        self.assertEqual(self.mcp(second["access_token"], "ping")[0], 200)
        self.assertIsNotNone(hub.q1("SELECT replaced FROM capp_tokens WHERE sha256=?",
                                    (oauth_server.sha256_hex(first["refresh_token"]),))["replaced"])
        self.assertEqual(self.refresh("y" * 43, second["refresh_token"])[1]["error"], "invalid_grant")
        self.assertIsNone(self.ended_by())

    def test_a_the_thief_presents_the_old_token_before_the_real_pair_is_used(self):
        for how in ("access", "refresh"):
            with self.subTest(how=how):
                client_id, first = self.paired()
                _, real = self.refresh(client_id, first["refresh_token"])
                status, thief = self.refresh(client_id, first["refresh_token"])   # a race, as far as the hub sees
                self.assertEqual(status, 200, thief)
                connection = hub.q1("SELECT id FROM capp_connections ORDER BY id DESC")["id"]
                self.assertEqual(sorted(r["kind"] for r in hub.q(
                    "SELECT kind FROM capp_tokens WHERE dropped IS NOT NULL AND connection=?", (connection,))),
                    ["access", "refresh"])                  # the real pair is dropped, not deleted
                self.assertIsNone(self.ended_by())
                self.assertIn(self.use(client_id, real, how), (400, 401))
                self.assertEqual(self.ended_by(), "reuse")
                self.assertEqual(self.mcp(thief["access_token"], "ping")[0], 401)
                self.assertEqual(self.refresh(client_id, thief["refresh_token"])[1]["error"], "invalid_grant")

    def test_b_the_real_client_uses_its_new_pair_then_the_thief_presents_the_old_token(self):
        client_id, first = self.paired()
        _, real = self.refresh(client_id, first["refresh_token"])
        self.assertEqual(self.mcp(real["access_token"], "ping")[0], 200)
        status, answer = self.refresh(client_id, first["refresh_token"])
        self.assertEqual((status, answer["error"]), (400, "invalid_grant"))
        self.assertEqual(self.ended_by(), "reuse")
        self.assertEqual(self.mcp(real["access_token"], "ping")[0], 401)
        self.assertEqual(self.refresh(client_id, real["refresh_token"])[1]["error"], "invalid_grant")

    def test_c_the_thief_refreshes_first_and_the_real_client_presents_the_same_token(self):
        for how in ("access", "refresh"):
            with self.subTest(how=how):
                client_id, first = self.paired()
                _, thief = self.refresh(client_id, first["refresh_token"])
                status, real = self.refresh(client_id, first["refresh_token"])
                self.assertEqual(status, 200, real)
                self.assertIsNone(self.ended_by())
                self.assertIsNotNone(hub.q1("SELECT dropped FROM capp_tokens WHERE sha256=?", (
                    oauth_server.sha256_hex(thief["access_token"]),))["dropped"])    # the thief's pair gave way
                self.assertIn(self.use(client_id, thief, how), (400, 401))
                self.assertEqual(self.ended_by(), "reuse")
                self.assertEqual(self.mcp(real["access_token"], "ping")[0], 401)

    def test_d_the_thief_uses_his_pair_then_the_real_client_refreshes(self):
        client_id, first = self.paired()
        _, thief = self.refresh(client_id, first["refresh_token"])
        self.assertEqual(self.mcp(thief["access_token"], "ping")[0], 200)
        status, answer = self.refresh(client_id, first["refresh_token"])
        self.assertEqual((status, answer["error"]), (400, "invalid_grant"))
        self.assertEqual(self.ended_by(), "reuse")
        self.assertEqual(self.mcp(thief["access_token"], "ping")[0], 401)
        self.assertEqual(self.count("capp_tokens"), 0)

    def test_a_restore_ends_every_connection(self):
        self.paired()
        client_id, second = self.paired()
        first, last = [r["id"] for r in hub.q("SELECT id FROM capp_connections ORDER BY id")]
        hub.q("UPDATE capp_connections SET revoked=?, ended_by='owner' WHERE id=?", (hub.now(), first))
        self.grant()                                   # an approval that was not exchanged yet
        self.assertEqual(hub.capp_restored(), 1)
        self.assertEqual([(r["id"], r["ended_by"]) for r in hub.q("SELECT * FROM capp_connections ORDER BY id")],
                         [(first, "owner"), (last, "restore")])
        self.assertEqual((self.count("capp_tokens"), self.count("capp_grants")), (0, 0))
        self.assertEqual(self.mcp(second["access_token"], "ping")[0], 401)
        self.assertEqual(self.refresh(client_id, second["refresh_token"])[1]["error"], "invalid_grant")
        # and the hub's start calls it right after it took a copy (main, after take_restore)
        tree = ast.parse(Path(hub.__file__).read_text())
        main = next(f for f in tree.body if isinstance(f, ast.FunctionDef) and f.name == "main")
        taken = [n for n in ast.walk(main) if isinstance(n, ast.If) and isinstance(n.test, ast.Name)
                 and n.test.id == "restored" and any(isinstance(c, ast.Call) and getattr(c.func, "id", "") ==
                                                     "capp_restored" for b in n.body for c in ast.walk(b))]
        self.assertEqual(len(taken), 1)

    def test_revoke_by_the_owner_or_the_client_and_then_mcp_is_401(self):
        client_id, code = self.grant()
        _, pair = self.exchange(client_id, code)
        connection = hub.q1("SELECT id FROM capp_connections")["id"]
        self.assertEqual(self.mcp(pair["access_token"], "ping")[0], 200)
        self.assertEqual(self.command(f"/ui/connect/{connection}/revoke")[0], 200)
        status, head, _ = self.mcp(pair["access_token"], "ping")
        self.assertEqual(status, 401)
        self.assertEqual(head["WWW-Authenticate"], oauth_server.www_authenticate(NAME))
        self.assertEqual(self.refresh(client_id, pair["refresh_token"])[1]["error"], "invalid_grant")
        client_id, code = self.grant()
        _, pair = self.exchange(client_id, code)
        self.assertEqual(self.form("/revoke", {"token": pair["access_token"]})[0], 200)
        self.assertEqual(self.mcp(pair["access_token"], "ping")[0], 401)
        self.assertEqual(self.refresh(client_id, pair["refresh_token"])[0], 200)
        self.assertEqual(self.form("/revoke", {"token": pair["refresh_token"]})[0], 200)
        self.assertEqual(hub.q1("SELECT ended_by FROM capp_connections ORDER BY id DESC")["ended_by"], "client")
        self.assertEqual(self.form("/revoke", {"token": "no-such-token"})[0], 200)

    def test_an_expired_access_token_and_a_refresh_token_as_a_bearer_get_401(self):
        client_id, pair = self.paired()
        self.assertEqual(self.mcp(pair["access_token"], "ping")[0], 200)
        status, head, _ = self.mcp(pair["refresh_token"], "ping")
        self.assertEqual((status, head["WWW-Authenticate"]), (401, oauth_server.www_authenticate(NAME)))
        hub.q("UPDATE capp_tokens SET expires=? WHERE kind='access'", (hub.now() - 1,))
        status, head, _ = self.mcp(pair["access_token"], "ping")
        self.assertEqual((status, head["WWW-Authenticate"]), (401, oauth_server.www_authenticate(NAME)))
        self.assertIsNone(self.ended_by())                             # neither one ends the connection
        self.assertEqual(self.refresh(client_id, pair["refresh_token"])[0], 200)

    def test_revoke_takes_a_token_only_with_its_own_client_id_or_none(self):
        client_id, pair = self.paired()
        self.assertEqual(self.form("/revoke", {"token": pair["refresh_token"], "client_id": "y" * 43})[0], 200)
        self.assertIsNone(self.ended_by())
        self.assertEqual(self.form("/revoke", {"token": pair["access_token"], "client_id": "y" * 43})[0], 200)
        self.assertEqual(self.mcp(pair["access_token"], "ping")[0], 200)
        self.assertEqual(self.form("/revoke", {"token": pair["refresh_token"], "client_id": client_id})[0], 200)
        self.assertEqual(self.ended_by(), "client")

    def test_an_old_resource_after_a_rename_of_the_hub_machine_is_401(self):
        client_id, code = self.grant()
        _, pair = self.exchange(client_id, code)
        hub.TAILNET_NAMES["names"] = ("hub-2.tail0000.ts.net", "hub-2")
        status, _, _ = self.http("POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                                 {"Content-Type": "application/json", "Authorization": "Bearer " + pair["access_token"]},
                                 host="hub-2.tail0000.ts.net")
        self.assertEqual(status, 401)


class Tools(Socket):
    """/mcp and the tools of each level (section 4, and threats 13 and 14)."""

    def setUp(self):
        super().setUp()
        self.opened()

    def test_initialize_lists_the_level_and_a_notification_gets_202(self):
        _, _, read, _ = self.signed_in("read")
        status, _, answer = self.mcp(read, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                                          "clientInfo": {"name": "example", "version": "1"}})
        self.assertEqual(status, 200)
        self.assertEqual(answer["result"]["serverInfo"]["name"], "founderizer")
        self.assertEqual(answer["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(answer["result"]["instructions"], hub.CAPP_INSTRUCTIONS)
        self.assertEqual(self.mcp(read, "notifications/initialized", mid=None)[0], 202)
        names = [t["name"] for t in self.mcp(read, "tools/list")[2]["result"]["tools"]]
        self.assertEqual(names, ["fleet_status", "read_task", "read_chat", "read_knowledge"])
        self.assertEqual(self.mcp(read, "ping", headers={"MCP-Protocol-Version": "1999-01-01"})[0], 400)
        status, _, body = self.http("POST", "/mcp", b"[]", {"Content-Type": "application/json",
                                                           "Authorization": "Bearer " + read})
        self.assertEqual(status, 400)
        self.assertEqual(self.mcp("not-a-token", "ping")[0], 401)
        self.assertIsNotNone(hub.q1("SELECT last_used FROM capp_connections")["last_used"])

    def test_a_read_connection_cannot_write_and_a_tool_of_no_level_is_unknown(self):
        _, connection, read, _ = self.signed_in("read")
        status, head, answer = self.call(read, "send_message", text="Do the thing")
        self.assertEqual(status, 403)
        self.assertEqual(head["WWW-Authenticate"], oauth_server.www_authenticate(NAME, insufficient=True))
        receipt = hub.q1("SELECT * FROM capp_receipts")
        self.assertEqual((receipt["connection"], receipt["tool"], receipt["outcome"]),
                         (connection, "send_message", "refused"))
        self.assertEqual(self.count("ui_requests"), 0)
        status, _, answer = self.call(read, "read_secret", name="x")
        self.assertEqual((status, answer["error"]["code"]), (200, -32602))

    def test_the_read_tools_read_what_the_phone_reads(self):
        _, _, read, _ = self.signed_in("read")
        task = hub.ins("INSERT INTO tasks(title,details,done_when,owner,requester,state,created,needs,attempt) "
                       "VALUES('Write the plan','d','done','manager','manager','working',?,'none',1)", (hub.now(),))
        status, _, answer = self.call(read, "fleet_status")
        self.assertEqual(status, 200)
        self.assertFalse(answer["result"]["isError"])
        seen = json.loads(answer["result"]["content"][0]["text"])
        self.assertEqual([t["title"] for t in seen["tasks"]], ["Write the plan"])
        status, _, answer = self.call(read, "read_task", task=f"T-{task}")
        self.assertEqual(json.loads(answer["result"]["content"][0]["text"])["task"]["title"], "Write the plan")
        status, _, answer = self.call(read, "read_task", task=999)
        self.assertTrue(answer["result"]["isError"])
        status, _, answer = self.call(read, "read_chat", agent="manager")
        self.assertEqual(json.loads(answer["result"]["content"][0]["text"])["agent"], "manager")
        with patch.object(hub, "knowledge_entries", lambda: []):      # no read of this checkout's files
            status, _, answer = self.call(read, "read_knowledge", path="knowledge/owner/none.md")
        self.assertTrue(answer["result"]["isError"])
        status, _, answer = self.call(read, "fleet_status", extra=1)
        self.assertTrue(answer["result"]["isError"])
        self.assertEqual(self.count("capp_receipts"), 0)            # a read leaves no receipt

    def test_a_login_and_hidden_characters_never_leave(self):
        _, _, read, _ = self.signed_in("read")
        login = "Ex4mple-Login#2026"
        hub.ins("INSERT INTO tasks(title,details,done_when,owner,requester,state,created,needs,attempt) "
                "VALUES(?,?,'done','manager','manager','working',?,'none',1)",
                (f"Use {login} now", "Plain​ text⁦ here", hub.now()))
        register(login)
        _, _, answer = self.call(read, "read_task", task=1)
        text = answer["result"]["content"][0]["text"]
        self.assertNotIn(login, text)
        self.assertNotIn("​", text)
        self.assertIn("hidden character", text)

    def test_an_act_message_reaches_the_manager_as_through_the_app_with_a_receipt(self):
        _, connection, act, _ = self.signed_in("act")
        names = [t["name"] for t in self.mcp(act, "tools/list")[2]["result"]["tools"]]
        self.assertIn("send_message", names)
        status, _, answer = self.call(act, "send_message", text="Give this plan to the manager")
        self.assertEqual(status, 200, answer)
        self.assertFalse(answer["result"]["isError"], answer)
        row = hub.q1("SELECT * FROM ui_requests")
        self.assertEqual((row["connection"], row["client"], row["origin"]),
                         (connection, f"connected:{connection}", None))
        event = hub.q1("SELECT * FROM events WHERE id=?", (row["event_id"],))
        self.assertEqual(event["text"], "[owner via app:Claude] Give this plan to the manager")
        receipt = hub.q1("SELECT * FROM capp_receipts")
        self.assertEqual((receipt["tool"], receipt["outcome"], receipt["event_id"], receipt["request_id"]),
                         ("send_message", "ok", row["event_id"], row["request_id"]))
        self.assertNotIn("plan", receipt["detail"])
        status, _, answer = self.call(act, "send_message", text="x" * 10, agent="nobody")
        self.assertTrue(answer["result"]["isError"])
        self.assertEqual(hub.q1("SELECT outcome FROM capp_receipts ORDER BY id DESC")["outcome"], "refused")

    def test_answer_need_refuses_an_item_of_its_own_route_and_answers_an_ordinary_one(self):
        _, connection, act, _ = self.signed_in("act")
        plain = self.need()
        secret = hub.ins("INSERT INTO needs(title,why,todo,raised,by,kind) VALUES('Key','w','t',?,'manager','secret')",
                         (hub.now(),))
        door = hub.ins("INSERT INTO needs(title,why,todo,raised,by,door_call) VALUES('Run','w','t',?,'manager','h')",
                       (hub.now(),))
        for need in (secret, door):
            with self.subTest(need=need):
                status, _, answer = self.call(act, "answer_need", need=f"N-{need}", answer="Yes")
                self.assertTrue(answer["result"]["isError"])
                self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (need,))["answer"])
        self.assertEqual(self.call(act, "answer_need", need=plain, answer="Blue",
                                   statement="x", signature="y")[2]["result"]["isError"], True)
        status, _, answer = self.call(act, "answer_need", need=plain, answer="Blue")
        self.assertFalse(answer["result"]["isError"], answer)
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (plain,))["answer"], "Blue")
        said = hub.q1("SELECT text FROM events ORDER BY id DESC")["text"]
        self.assertTrue(said.startswith(f"[owner via app:Claude] Answer to Needs-you N-{plain} "), said)
        self.assertEqual([r["outcome"] for r in hub.q("SELECT outcome FROM capp_receipts ORDER BY id")],
                         ["refused", "refused", "refused", "ok"])

    def test_discuss_steer_and_control_say_where_they_came_from(self):
        _, connection, act, _ = self.signed_in("act")
        need = self.need()
        status, _, answer = self.call(act, "discuss_need", need=need, text="Which one is cheaper?")
        self.assertFalse(answer["result"]["isError"], answer)
        said = hub.q1("SELECT text FROM events WHERE agent='manager' ORDER BY id DESC")["text"]
        self.assertTrue(said.startswith(f"[owner via app:Claude] About the Needs-you item N-{need}"), said)
        task = hub.ins("INSERT INTO tasks(title,details,done_when,owner,requester,state,created,needs,attempt) "
                       "VALUES('Work','d','done','manager','manager','working',?,'none',1)", (hub.now(),))
        status, _, answer = self.call(act, "steer_task", task=task, text="Use plain words.")
        self.assertFalse(answer["result"]["isError"], answer)
        said, copy = [r["text"] for r in hub.q("SELECT text FROM events WHERE task=? ORDER BY id", (task,))]
        self.assertTrue(said.startswith(f"[owner via app:Claude] Steering from the owner for T-{task}"), said)
        self.assertIn(" through the app Claude: Use plain words.", copy)
        self.assertEqual(hub.q1("SELECT client FROM steers")["client"], f"connected:{connection}")
        status, _, answer = self.call(act, "control_task", task=task, action="pause", note="Wait")
        self.assertFalse(answer["result"]["isError"], answer)
        self.assertEqual([r["tool"] for r in hub.q("SELECT tool FROM capp_receipts WHERE outcome='ok' ORDER BY id")],
                         ["discuss_need", "steer_task", "control_task"])
        self.assertEqual({r["client"] for r in hub.q("SELECT client FROM ui_controls WHERE route NOT LIKE 'connect/%'")},
                         {f"connected:{connection}"})

    def test_a_steer_of_a_connected_app_says_so_in_the_history_and_the_owners_own_does_not(self):
        _, connection, act, _ = self.signed_in("act")
        task = hub.ins("INSERT INTO tasks(title,details,done_when,owner,requester,state,created,needs,attempt) "
                       "VALUES('Work','d','done','manager','manager','working',?,'none',1)", (hub.now(),))
        status, _, answer = self.call(act, "steer_task", task=task, text="Use plain words.")
        self.assertFalse(answer["result"]["isError"], answer)
        code, own = self.command(f"/ui/tasks/{task}/steer", text="Keep it short.")       # the owner's Mac
        self.assertEqual(code, 200, own)
        self.assertEqual([(r["client"], r["connection"]) for r in hub.q("SELECT * FROM steers ORDER BY id")],
                         [(f"connected:{connection}", connection), ("deterministic-test", None)])
        self.assertNotIn("connection", own["steer"])                # the apps read no new field of a steer
        hub.history_catch_up()
        rows = hub.q("SELECT * FROM history WHERE src='steer' ORDER BY src_id")
        self.assertEqual([r["text"] for r in rows],
                         [f"The owner (through the app Claude), on T-{task}: Use plain words.",
                          f"The owner, on T-{task}: Keep it short."])
        # the search card shows the record's own words, with neither head (HISTORY_HEADS)
        self.assertEqual([hub.history_own_words(r) for r in rows], ["Use plain words.", "Keep it short."])
        # a database of a release before this column gets it at the start (migrate), and its steers read as his own
        hub.q("ALTER TABLE steers DROP COLUMN connection")
        self.assertNotIn("connection", [c["name"] for c in hub.q("PRAGMA table_info(steers)")])
        hub.migrate()
        self.assertEqual([r["connection"] for r in hub.q("SELECT connection FROM steers ORDER BY id")], [None, None])

    def test_a_registered_login_in_an_act_text_gets_422_as_on_the_phone(self):
        _, _, act, _ = self.signed_in("act")
        login = "Ex4mple-Login#2026"
        register(login)
        status, _, answer = self.call(act, "send_message", text=f"The key is {login}")
        self.assertTrue(answer["result"]["isError"])
        self.assertIn("422", answer["result"]["content"][0]["text"])
        self.assertEqual(self.count("ui_requests"), 0)


if __name__ == "__main__":
    unittest.main()

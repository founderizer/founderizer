"""Owner API 1.12: agent keys, session credentials, agents on a shared machine, vault "none" and one browser or screen
task at a time on each machine. A local hub with a test source address for each machine, stand-in tmux answers and
stand-in process tables. No real host, credential, session or AI call."""
import ast
import hashlib
import inspect
import json
import os
import pwd
import stat
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import fleet
from leftovers import scratch_home
import hub
import lifecycle
import vault
from test_setup import git
from test_ui_api import OwnerAPI

KEYS = {"solo": "solo-key-" + "a" * 34, "alpha": "alpha-key-" + "b" * 33, "beta": "beta-key-" + "c" * 34}
SOLO, BOX = "127.0.0.4", "127.0.0.3"           # the machine of solo, and the machine that alpha and beta share
LOGIN = "bws://11111111-2222-4333-8444-55555555555b"


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite(Routes(name) for name in Routes.__dict__ if name.startswith("test_"))
    suite.addTests(VaultAccess(name) for name in VaultAccess.__dict__ if name.startswith("test_"))
    for cls in (HelperSide, FinishedDesktopTask, BrokerCallers):
        suite.addTests(loader.loadTestsFromTestCase(cls))
    return suite


class Routes(OwnerAPI):
    """The hub side, through the real routes."""
    def setUp(self):
        super().setUp()
        hub.TEAM["addresses"].update(solo=SOLO, box=BOX)
        hub.TEAM["agents"].update(
            solo=dict(role="worker", runtime="codex", machine="solo", can=["shell"]),
            alpha=dict(role="worker", runtime="claude", machine="box", can=["shell", "browser"]),
            beta=dict(role="worker", runtime="codex", machine="box", can=["shell", "browser"]))
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90, tick=5)

    # ---- helpers
    def call(self, path, body=None, source=None, token=None, auth=None):
        headers = {"Content-Type": "application/json", "X-Fleet-Client": "deterministic-test"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if auth is not None:
            headers["Authorization"] = auth
        return self.request(path, body, headers=headers, source=source)

    def owner_key(self, agent, **body):
        return self.request(f"/ui/team/agents/{agent}/key", dict({"request_id": str(uuid.uuid4()), "db": "test-generation"},
                                                                **body))

    def register(self, *agents):
        for agent in agents:
            code, data = self.owner_key(agent, sha256=sha(KEYS[agent]))
            self.assertEqual(code, 200, data)

    def task(self, owner, needs="none", state="working", attempt=1):
        return hub.ins("INSERT INTO tasks(title,owner,requester,state,created,needs,attempt) VALUES(?,?,?,?,?,?,?)",
                       ("Work", owner, "manager", state, hub.now(), needs, attempt))

    def credential(self, agent, source, key=None, **body):
        return self.call(f"/helper/session/{agent}", dict({"generation": "test-generation"}, **body), source=source,
                         token=key or KEYS[agent])

    def mcp(self, path, source, **kw):
        return self.call(path, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, source=source, **kw)

    def status(self, agent, **data):
        hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES(?,?,?)",
              (agent, json.dumps(dict({"features": ["agent_key"], "legacy_windows": []}, **data)), hub.now()))

    # ---- helper routes: a missing key and a wrong key are different cases
    def test_an_agent_without_a_key_alone_on_its_address_keeps_the_address_rule(self):
        self.assertEqual(self.call("/helper/ack/solo", {"ids": []}, source=SOLO)[0], 200)     # nothing sent: legacy
        for kwargs in ({"token": "made-up"}, {"auth": "Basic abc"}, {"auth": "Bearer "}):        # sent: never taken as absent
            code, data = self.call("/helper/ack/solo", {"ids": []}, source=SOLO, **kwargs)
            self.assertEqual((code, data.get("auth")), (403, "no_key"), kwargs)
        self.assertEqual(self.call("/helper/ack/solo", {"ids": []}, source=BOX)[0], 403)        # another machine

    def test_a_keyed_agent_needs_its_key_on_its_helper_routes_also_while_alone(self):
        self.register("solo")
        for kwargs, why in (({}, "key_required"), ({"token": "wrong"}, "key_mismatch"),
                            ({"token": KEYS["alpha"]}, "key_mismatch"), ({"auth": "Basic " + KEYS["solo"]}, "key_mismatch"),
                            ({"auth": "Bearer "}, "key_mismatch")):
            for path, body in (("/helper/ack/solo", {"ids": []}), ("/events/solo?after=-1", None),
                               ("/helper/status/solo", {}), ("/hook/activity/solo/T-1", {})):
                code, data = self.call(path, body, source=SOLO, **kwargs)
                self.assertEqual((code, data.get("auth")), (403, why), (path, kwargs))
        self.assertEqual(self.call("/helper/ack/solo", {"ids": []}, source=SOLO, token=KEYS["solo"])[0], 200)
        self.assertEqual(self.call("/helper/ack/solo", {"ids": []}, source=BOX, token=KEYS["solo"])[0], 403)

    def test_the_broker_routes_keep_the_address_rule_only_while_the_agent_is_alone(self):
        self.register("solo")
        sid = hub.ins("INSERT INTO sealed(sender,recipient,task,label,ciphertext,created) VALUES('alpha','solo','',"
                      "'site','-----BEGIN AGE ENCRYPTED FILE-----',?)", (hub.now(),))
        for path, body in (("/helper/vault/solo", {"job": 99, "kind": "probe"}),
                           ("/helper/vault/solo/fingerprints", {"job": 99, "fingerprints": []}),
                           (f"/sealed/{sid}?agent=solo&task=", None)):
            code, data = self.call(path, body, source=SOLO)             # its broker sends nothing: not an auth refusal
            self.assertNotEqual(code, 403, (path, data))
            code, data = self.call(path, body, source=SOLO, token="wrong")      # a wrong key is never taken as absent
            self.assertEqual((code, data.get("auth")), (403, "key_mismatch"), path)
            self.assertNotEqual(self.call(path, body, source=SOLO, token=KEYS["solo"])[0], 403, path)
        self.register("alpha", "beta")
        code, data = self.call("/helper/vault/alpha", {"job": 99, "kind": "probe"}, source=BOX)    # shared: the key, too
        self.assertEqual((code, data.get("auth")), (403, "key_required"))
        self.assertEqual(self.call("/helper/vault/alpha", {"job": 99, "kind": "probe"}, source=BOX,
                                   token=KEYS["alpha"])[0], 404)

    def test_on_a_shared_machine_each_agent_needs_its_own_key(self):
        self.register("alpha", "beta")
        ack = lambda who, **kw: self.call(f"/helper/ack/{who}", {"ids": []}, source=BOX, **kw)
        self.assertEqual((ack("alpha", token=KEYS["alpha"])[0], ack("beta", token=KEYS["beta"])[0]), (200, 200))
        self.assertEqual(ack("alpha", token=KEYS["beta"])[1].get("auth"), "key_mismatch")       # a sibling's key
        self.assertEqual(ack("alpha")[1].get("auth"), "key_required")                            # the address names nobody
        self.assertEqual(self.owner_key("beta", delete=True)[0], 200)
        self.assertEqual(ack("beta")[1].get("auth"), "key_required")             # never the address rule again
        self.assertEqual(ack("beta", token=KEYS["beta"])[1].get("auth"), "no_key")

    def test_a_name_whose_machine_has_no_address_is_refused_from_every_caller(self):
        """An agent whose machine is in no "addresses" was taken from any caller, with no key and no credential: the
        address check was skipped where there was no address, and one address names nobody is not the same as no
        address names everybody. validate_team gives every machine an address, so only a team.json the hub was
        started with and never validated holds this, and then that agent's name belongs to whoever calls."""
        hub.TEAM["agents"]["stray"] = dict(role="worker", runtime="claude", machine="nowhere", can=["shell"])
        t = self.task("stray")
        routes = (("/helper/ack/stray", {"ids": []}), ("/events/stray?after=-1", None),
                  ("/helper/status/stray", {}), (f"/hook/activity/stray/T-{t}", {}))
        for source in (SOLO, BOX, "127.0.0.9"):
            for path, body in routes:
                code, data = self.call(path, body, source=source)
                self.assertEqual(code, 403, (path, source, data))
                self.assertIn("no address", data.get("error", ""))
            self.assertEqual(self.mcp("/mcp/stray", source)[0], 403, source)
        self.assertEqual(self.owner_key("stray", sha256=sha("stray-key"))[0], 200)      # a key is no way around it
        self.assertEqual(self.call("/helper/ack/stray", {"ids": []}, source=SOLO, token="stray-key")[0], 403)
        self.assertEqual(self.call("/helper/ack/solo", {"ids": []}, source=SOLO)[0], 200)   # its own machine, as before

    def test_a_hub_whose_team_pins_no_address_checks_none(self):
        """The throwaway hubs of selftest.py: no machine has an address, so there is nothing to compare a caller
        with, and a name is taken as it is given. A fleet is never in this state (validate_team)."""
        hub.TEAM["addresses"] = {machine: "" for machine in hub.TEAM["addresses"]}
        self.assertEqual(self.call("/helper/ack/solo", {"ids": []}, source="127.0.0.9")[0], 200)
        self.assertEqual(self.mcp("/mcp/solo", "127.0.0.9")[0], 200)

    # ---- session credentials
    def test_a_session_credential_works_only_on_its_own_route(self):
        self.register("alpha", "beta")
        t = self.task("alpha")
        code, data = self.credential("alpha", BOX, kind="task", task=f"T-{t}", attempt=1)
        self.assertEqual(code, 200, data)
        token, route = data["token"], f"/mcp/alpha/test-generation/T-{t}/1"
        self.assertEqual(self.mcp(route, BOX, token=token)[0], 200)
        self.assertEqual(self.mcp(route, BOX)[1].get("auth"), "credential_required")        # shared: never without
        for wrong in ({"token": "wrong"}, {"token": KEYS["alpha"]}, {"auth": "Basic " + token}, {"auth": "Bearer "}):
            self.assertEqual(self.mcp(route, BOX, **wrong)[1].get("auth"), "credential_invalid", wrong)
        for other in (f"/mcp/alpha/test-generation/T-{t}/2", f"/mcp/alpha/old-generation/T-{t}/1", "/mcp/alpha",
                      "/mcp/alpha/test-generation/owner-chat/1", f"/mcp/beta/test-generation/T-{t}/1"):
            self.assertEqual(self.mcp(other, BOX, token=token)[1].get("auth"), "credential_invalid", other)
        self.assertEqual(self.mcp(route, SOLO, token=token)[0], 403)                          # from another machine
        code, again = self.credential("alpha", BOX, kind="task", task=f"T-{t}", attempt=1)   # a new one for the attempt
        self.assertEqual(self.mcp(route, BOX, token=token)[1].get("auth"), "credential_invalid")
        self.assertEqual(self.mcp(route, BOX, token=again["token"])[0], 200)
        self.assertNotIn(token, json.dumps([dict(r) for r in hub.q("SELECT * FROM session_credentials")]))

    def test_a_keyed_agent_needs_its_credential_on_every_mcp_route_also_while_alone(self):
        """The access review of 10 November 2026: an agent alone on its server took an MCP call with no credential
        on each of its routes, so any user of that machine could act as its owner chat, a conversation, one of its
        tasks or its standing session. An agent with a key now sends its session's credential there as its helper
        sends its key."""
        self.register("solo")
        t = self.task("solo")
        task, chat = f"/mcp/solo/test-generation/T-{t}/1", "/mcp/solo/test-generation/owner-chat/1"
        for route in (task, chat, "/mcp/solo", "/mcp/solo/test-generation/conversation/7"):
            code, data = self.mcp(route, SOLO)
            self.assertEqual((code, data.get("auth")), (403, "credential_required"), route)
            self.assertIn("solo has an agent key", data["error"])
            for wrong in ({"token": "wrong"}, {"token": KEYS["solo"]}, {"auth": "Basic x"}, {"auth": "Bearer "}):
                self.assertEqual(self.mcp(route, SOLO, **wrong)[1].get("auth"), "credential_invalid", (route, wrong))
        self.assertIn(f"REFUSED a call for solo from {SOLO}: credential_required",
                      [r["what"] for r in hub.q("SELECT what FROM log WHERE agent='hub'")])
        tokens = {route: self.credential("solo", SOLO, kind=kind, **body)[1]["token"]
                  for route, kind, body in ((task, "task", {"task": f"T-{t}", "attempt": 1}), (chat, "chat", {}))}
        for route, token in tokens.items():
            self.assertEqual(self.mcp(route, SOLO, token=token)[0], 200, route)
            self.assertEqual(self.mcp(route, BOX, token=token)[0], 403, route)          # from another machine

    def test_an_agent_without_a_key_alone_on_its_address_keeps_the_address_rule_on_its_mcp_routes(self):
        """Its helper's first round, before the hub has its key (fleet.Helper.enroll), and the round after the owner
        removed its key: the address alone names it, as on its helper routes."""
        t = self.task("solo")
        route = f"/mcp/solo/test-generation/T-{t}/1"
        self.assertEqual(self.mcp(route, SOLO)[0], 200)
        self.assertEqual(self.mcp(route, BOX)[0], 403)                                     # another machine
        for wrong in ({"token": "wrong"}, {"auth": "Basic x"}, {"auth": "Bearer "}):       # sent: never taken as absent
            self.assertEqual(self.mcp(route, SOLO, **wrong)[1].get("auth"), "credential_invalid", wrong)
        self.register("solo")
        self.assertEqual(self.mcp(route, SOLO)[1].get("auth"), "credential_required")      # its key ends that rule
        self.assertEqual(self.owner_key("solo", delete=True)[0], 200)
        self.assertEqual(self.mcp(route, SOLO)[0], 200)                    # without a key it is legacy until it enrolls

    def test_a_credential_is_given_only_for_a_current_binding_and_the_current_key(self):
        self.register("alpha", "beta")
        t, ended, theirs = self.task("alpha"), self.task("alpha", state="completed"), self.task("beta")
        for body, code in ((dict(kind="task", task=f"T-{t}", attempt=2), 409),
                           (dict(kind="task", task=f"T-{ended}", attempt=1), 409),
                           (dict(kind="task", task=f"T-{theirs}", attempt=1), 409),
                           (dict(kind="task", task=f"T-{t}", attempt=1, generation="old"), 409),
                           (dict(kind="standing"), 409), (dict(kind="other"), 400),
                           (dict(kind="task", task="nope", attempt=1), 400)):
            self.assertEqual(self.credential("alpha", BOX, **body)[0], code, body)
        self.assertEqual(self.credential("alpha", BOX, kind="chat")[0], 200)
        code, data = self.credential("alpha", BOX, key=KEYS["beta"], kind="chat")
        self.assertEqual((code, data.get("auth")), (403, "key_mismatch"))
        self.assertEqual(self.call("/helper/session/solo", {"kind": "chat", "generation": "test-generation"},
                                   source=SOLO)[0], 409)          # an agent without a key gets none
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM session_credentials")["n"], 1)

    def test_a_key_change_revokes_every_credential_and_never_restores_the_address_rule(self):
        self.register("alpha", "beta")
        t = self.task("alpha")
        task = self.credential("alpha", BOX, kind="task", task=f"T-{t}", attempt=1)[1]["token"]
        chat = self.credential("alpha", BOX, kind="chat")[1]["token"]
        code, receipt = self.owner_key("alpha", sha256=sha("alpha-new-key-" + "d" * 29))
        self.assertEqual((code, receipt["agent"], receipt["key"], receipt["replayed"]), (200, "alpha", True, False))
        for token, route in ((task, f"/mcp/alpha/test-generation/T-{t}/1"), (chat, "/mcp/alpha/test-generation/owner-chat/1")):
            self.assertEqual(self.mcp(route, BOX, token=token)[1].get("auth"), "credential_invalid")
        self.assertEqual(self.call("/helper/ack/alpha", {"ids": []}, source=BOX, token=KEYS["alpha"])[1].get("auth"),
                         "key_mismatch")
        code, receipt = self.owner_key("alpha", delete=True)
        self.assertEqual((code, receipt["key"], receipt["since"]), (200, False, None))
        self.assertEqual(self.call("/helper/ack/alpha", {"ids": []}, source=BOX)[1].get("auth"), "key_required")
        self.register("solo")
        self.assertEqual(self.owner_key("solo", delete=True)[0], 200)
        self.assertEqual(self.call("/helper/ack/solo", {"ids": []}, source=SOLO)[0], 200)     # alone: legacy again
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM session_credentials WHERE revoked IS NULL")["n"], 0)

    def test_a_key_replaced_while_a_credential_is_asked_for_gives_no_credential(self):
        """Main's finding: the key is checked again under the lock that replaces keys and revokes credentials."""
        self.register("alpha", "beta")
        t = self.task("alpha")
        form = hub.Handler.form

        def replaced_then_read(handler):
            with hub.transaction():
                hub.DB.execute("UPDATE agent_keys SET sha256=? WHERE agent='alpha'", (sha("rotated-" + "e" * 36),))
                hub.revoke_sessions("alpha", hub.now())
            return form(handler)
        with patch.object(hub.Handler, "form", replaced_then_read):
            code, data = self.credential("alpha", BOX, kind="task", task=f"T-{t}", attempt=1)
        self.assertEqual((code, data.get("auth"), "token" in data), (403, "key_mismatch", False))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM session_credentials")["n"], 0)

    def test_the_owner_key_route(self):
        body = {"request_id": str(uuid.uuid4()), "db": "test-generation", "sha256": sha("x" * 43)}
        code, first = self.request("/ui/team/agents/newcomer/key", body)          # not in team.json yet
        self.assertEqual((code, first["agent"], first["key"]), (200, "newcomer", True))
        self.assertTrue(self.request("/ui/team/agents/newcomer/key", body)[1]["replayed"])
        for wrong in ({"sha256": "ABC"}, {"sha256": sha("y"), "delete": True}, {"delete": False}, {"other": 1}, {}):
            self.assertEqual(self.owner_key("newcomer", **wrong)[0], 400, wrong)
        self.assertEqual(self.owner_key("Not_A_Name", sha256=sha("z"))[0], 404)
        self.assertEqual(self.request("/ui/team/agents/newcomer/key", dict(body, request_id=str(uuid.uuid4())),
                                      source=BOX)[0], 403)            # only the owner
        self.assertEqual(hub.agent_key("newcomer")["sha256"], sha("x" * 43))

    def test_enrollment_is_once_address_only_and_only_alone(self):
        digest = sha(KEYS["solo"])
        self.assertEqual(self.call("/helper/key/solo", {"sha256": digest}, source=BOX)[0], 403)
        self.assertEqual(self.call("/helper/key/solo", {"sha256": digest}, source=SOLO, token="anything")[0], 400)
        self.assertEqual(self.call("/helper/key/solo", {"sha256": "nope"}, source=SOLO)[0], 400)
        self.assertEqual(self.call("/helper/key/solo", {"sha256": digest}, source=SOLO)[0], 200)
        self.assertEqual(self.call("/helper/key/solo", {"sha256": digest}, source=SOLO)[0], 200)       # the same again
        self.assertEqual(self.call("/helper/key/solo", {"sha256": sha("other")}, source=SOLO)[0], 409)
        self.assertEqual(self.call("/helper/key/alpha", {"sha256": sha(KEYS["alpha"])}, source=BOX)[0], 409)
        self.assertEqual(hub.agent_key("solo")["sha256"], digest)
        self.assertIsNone(hub.agent_key("alpha"))

    def test_a_server_whose_service_registers_keys_takes_none_from_its_address(self):
        """The service of a server that joined with a code makes each agent's key in that agent's own home at its
        install and registers it (hub.install_key). The address of such a server names nobody for a key: any user of
        it could send the first key of an agent without one and then act as it (the access review of 10 and 11
        November 2026). So the hub takes no first key from that address, and the owner replaces such a key and never
        removes it. A machine whose service registers no keys keeps the address rule."""
        def features(*names):
            hub.q("INSERT OR REPLACE INTO server_status(server,data,reported) VALUES(?,?,?)",
                  ("solo", json.dumps({"features": list(names)}), hub.now()))
        features(hub.INSTALL_KEY)
        code, data = self.call("/helper/key/solo", {"sha256": sha(KEYS["solo"])}, source=SOLO)
        self.assertEqual((code, data.get("by")), (409, "server"), data)
        self.assertIsNone(hub.agent_key("solo"))
        self.assertIn(f"REFUSED key enrollment for solo from {SOLO}: the server service of solo registers its key",
                      [r["what"] for r in hub.q("SELECT what FROM log WHERE agent='hub'")])
        self.register("solo")       # as the install job's key step does, with the server's own key
        self.assertEqual(self.call("/helper/key/solo", {"sha256": sha(KEYS["solo"])}, source=SOLO)[0], 200)  # the same
        self.assertEqual(self.call("/helper/key/solo", {"sha256": sha("other")}, source=SOLO)[0], 409)
        code, data = self.owner_key("solo", delete=True)
        self.assertEqual(code, 400, data)
        self.assertIn("replaced and never removed", data["error"])
        self.assertEqual(hub.agent_key("solo")["sha256"], sha(KEYS["solo"]))
        self.assertEqual(self.owner_key("solo", sha256=sha("a new key"))[0], 200)       # a replacement is the way
        self.assertEqual(hub.agent_key("solo")["sha256"], sha("a new key"))
        features()                  # a service from before 3 November 2026 registers no keys: the address rule
        self.assertEqual(self.owner_key("solo", delete=True)[0], 200)
        self.assertEqual(self.call("/helper/key/solo", {"sha256": sha(KEYS["solo"])}, source=SOLO)[0], 200)
        self.assertEqual(hub.agent_key("solo")["sha256"], sha(KEYS["solo"]))

    def test_the_poll_names_the_windows_whose_credential_a_key_change_revoked(self):
        """A key change revokes every session credential of the agent (revoke_sessions). The helper's poll answer then
        names the owner chat or the standing session whose newest credential is revoked, until a new credential
        replaces it. A credential that the helper replaced itself, by starting the window again, names nothing, and
        an agent without a key names nothing: its helper starts those windows without a credential."""
        self.register("solo")

        def revoked(key):
            code, data = self.call("/events/solo?delivery=1&after=0&wait=0&alive_unknown=1", source=SOLO, token=key)
            self.assertEqual(code, 200, data)
            return data["revoked"]
        self.assertEqual(revoked(KEYS["solo"]), [])                         # no credential yet
        for _ in range(2):                                                  # the second start revokes the first
            self.assertEqual(self.credential("solo", SOLO, kind="chat")[0], 200)
        self.assertEqual(revoked(KEYS["solo"]), [])
        self.assertEqual(self.owner_key("solo", sha256=sha("new-key"))[0], 200)     # the owner replaced the key
        self.assertEqual(revoked("new-key"), ["owner-chat"])
        self.assertEqual(self.credential("solo", SOLO, key="new-key", kind="chat")[0], 200)
        self.assertEqual(revoked("new-key"), [])
        self.assertEqual(self.owner_key("solo", delete=True)[0], 200)      # alone without a key: the address rule,
        self.assertEqual(revoked(None), [])                                 # and its windows run without a credential
        self.register("solo")
        self.assertEqual(revoked(KEYS["solo"]), ["owner-chat"])
        t0 = hub.now()                  # the standing session's row, and a newer chat row of another generation
        hub.q("INSERT INTO session_credentials(sha256,agent,kind,generation,created,revoked) VALUES(?,?,?,?,?,?)",
              (sha("standing"), "solo", "standing", "test-generation", t0, t0))
        hub.q("INSERT INTO session_credentials(sha256,agent,kind,generation,created) VALUES(?,?,?,?,?)",
              (sha("elsewhere"), "solo", "chat", "another-generation", t0 + 1))
        self.assertEqual(revoked(KEYS["solo"]), ["manager", "owner-chat"])

    def test_an_agent_that_leaves_the_team_leaves_no_key_or_reading_to_its_name(self):
        """An agent moved to another server by removal and Add agent (30 October 2026): its new helper could not
        register its key ("only the owner replaces it"), and its install's sign-in read "signed in" from the old
        machine's reading. Its records stay."""
        self.register("solo")
        self.status("solo", runtime={"name": "codex", "signed_in": True})
        hub.q("INSERT INTO machine_updates(agent,state,requested,desired) VALUES('solo','failed',?,?)",
              (hub.now(), "a" * 40))
        hub.q("INSERT INTO session_credentials(sha256,agent,kind,generation,created) VALUES(?,?,?,?,?)",
              (sha("credential"), "solo", "chat", "test-generation", hub.now()))
        task = self.task("solo", state="completed")
        self.assertIs(hub.signed_in_now("solo", "codex"), True)
        team = json.loads(json.dumps(hub.TEAM))
        del team["agents"]["solo"]
        hub.apply_team(team)                                        # the owner removes solo
        team = json.loads(json.dumps(team))
        team["addresses"]["spare"] = "127.0.0.6"
        team["agents"]["solo"] = dict(role="worker", runtime="codex", machine="spare", can=["shell"])
        hub.apply_team(team)                                        # and adds it on another server
        self.assertIsNone(hub.signed_in_now("solo", "codex"))
        self.assertEqual([hub.q1(f"SELECT COUNT(*) n FROM {table} WHERE agent='solo'")["n"]
                          for table in ("agent_keys", "machine_status", "machine_updates")], [0, 0, 0])
        self.assertIsNotNone(hub.q1("SELECT revoked FROM session_credentials WHERE agent='solo'")["revoked"])
        self.assertEqual(self.call("/helper/key/solo", {"sha256": sha("new-key")}, source="127.0.0.6")[0], 200)
        self.assertEqual(hub.agent_key("solo")["sha256"], sha("new-key"))
        self.assertEqual(hub.q1("SELECT owner FROM tasks WHERE id=?", (task,))["owner"], "solo")       # its records stay

    def test_no_key_or_credential_appears_in_owner_answers_records_or_logs(self):
        self.register("alpha", "beta")
        t = self.task("alpha")
        token = self.credential("alpha", BOX, kind="task", task=f"T-{t}", attempt=1)[1]["token"]
        self.mcp(f"/mcp/alpha/test-generation/T-{t}/1", BOX, token=token)
        self.mcp(f"/mcp/alpha/test-generation/T-{t}/1", BOX, token=token + "x")
        self.call("/helper/ack/alpha", {"ids": []}, source=BOX, token=KEYS["beta"])
        texts = [json.dumps(self.request(path)[1]) for path in ("/ui/state", "/ui/machines?db=test-generation", "/records")]
        texts += [json.dumps([dict(r) for r in hub.q(f"SELECT * FROM {table}")]) for table in
                  ("log", "events", "calls", "ui_controls", "session_credentials", "agent_keys")]
        for secret in (token, KEYS["alpha"], KEYS["beta"]):
            for text in texts:
                self.assertNotIn(secret, text)

    # ---- shared placement
    def test_agents_share_a_machine_only_when_each_can_prove_its_identity(self):
        team = {"agents": {n: dict(hub.TEAM["agents"][n]) for n in ("alpha", "beta")}}
        self.assertEqual(hub.placement_missing(["alpha", "beta"], team), ["agent_without_key:alpha", "agent_without_key:beta"])
        self.register("alpha", "beta")
        self.assertEqual(hub.placement_missing(["alpha", "beta"], team), [])        # before their first reports: the key
        self.assertEqual(hub.placement_missing(["alpha", "beta"], team, strict=True),
                         ["helper_without_agent_key:alpha", "helper_without_agent_key:beta"])
        for windows, missing in ((None, ["legacy_windows_unknown:alpha"]), ("absent", ["legacy_windows_unknown:alpha"]),
                                 (["manager"], ["legacy_windows:alpha"]), ([], [])):
            data = {"features": ["agent_key"]} if windows == "absent" else {"features": ["agent_key"], "legacy_windows": windows}
            hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES('alpha',?,?)", (json.dumps(data), hub.now()))
            self.assertEqual(hub.placement_missing(["alpha", "beta"], team), missing, windows)
        self.status("alpha", features=["trigger_check"])
        self.assertEqual(hub.placement_missing(["alpha", "beta"], team), ["helper_without_agent_key:alpha"])
        self.status("alpha")
        team["agents"]["alpha"] = dict(team["agents"]["alpha"], vault="broker")
        self.assertEqual(hub.placement_missing(["alpha", "beta"], team), ["broker_machine"])

    # ---- vault "none"
    def test_an_agent_without_credential_access(self):
        hub.TEAM["agents"]["solo"]["vault"] = "none"
        t = self.task("solo")
        row = hub.q1("SELECT * FROM tasks WHERE id=?", (t,))
        self.assertIn("no credential access", hub.login_refusal("solo", row, LOGIN))
        self.assertIn("no credential access", hub.login_refusal("solo", row, LOGIN, confirm=True))
        mine = hub.q1("SELECT * FROM tasks WHERE id=?", (self.task("alpha"),))
        self.assertIn("solo has no credential access", hub.login_refusal("alpha", mine, LOGIN, "handover", "solo"))
        text, error = hub.call_tool("alpha", "hand_over", {"task_id": f"T-{mine['id']}", "login": LOGIN, "to": "solo"},
                                    ("test-generation", f"T-{mine['id']}", 1))
        self.assertTrue(error)
        self.assertIn("no credential access", text)
        hub.know("solo")
        hub.q("UPDATE agents SET pubkey='age1oldkeyoldkeyoldkeyoldkey' WHERE name='solo'")
        self.assertIsNone(hub.handover_key("solo"))
        self.assertEqual(self.call("/keys/solo", {"pubkey": "age1" + "q" * 58}, source=SOLO)[0], 403)
        sid = hub.ins("INSERT INTO sealed(sender,recipient,task,label,ciphertext,created) VALUES('alpha','solo','',"
                      "'site','-----BEGIN AGE ENCRYPTED FILE-----',?)", (hub.now(),))
        self.assertEqual(self.call(f"/sealed/{sid}?agent=solo&task=", source=SOLO)[0], 403)
        with patch.object(hub, "profile_logins", return_value={LOGIN}):
            agents = {a["agent"]: a for a in hub.capacity_view(["solo", "alpha"])["agents"]}
        self.assertEqual((agents["solo"]["logins"]["eligible"], agents["alpha"]["logins"]["eligible"]), ([], [LOGIN]))
        team = {"hub": {"machine": "hub"}, "addresses": {"hub": "10.0.0.1", "owner": "10.0.0.2", "wb": "10.0.0.3"},
                "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub"},
                           "wb": {"role": "worker", "runtime": "codex", "machine": "wb", "vault": "none"}}}
        hub.validate_team(team)
        team["agents"]["wb"]["vault"] = "nothing"
        with self.assertRaises(ValueError):
            hub.validate_team(team)

    # ---- one browser or screen task at a time on each machine
    def create(self, owner, needs="browser", caller="manager"):
        return hub.call_tool(caller, "create_task", {"owner": owner, "title": f"Use the desktop for {owner}",
                                                     "done_when": "Done.", "needs": needs}, None)

    def report_windows(self, agent, windows, at):
        hub.know(agent)
        hub.q("UPDATE agents SET alive=?, alive_ts=? WHERE name=?", (",".join(windows), at, agent))

    def test_one_desktop_task_on_a_machine_until_its_session_is_confirmed_quiet(self):
        self.status("alpha")
        text, error = self.create("alpha")
        self.assertFalse(error, text)
        first = hub.q1("SELECT MAX(id) id FROM tasks")["id"]
        text, error = self.create("beta")                       # the same machine
        self.assertTrue(error)
        self.assertIn(f"The desktop of box is busy with T-{first}; wait until it ends.", text)
        self.assertIn("busy with another browser or screen task", hub.desktop_refusal("beta", "screen", "lead-x"))
        self.assertFalse(self.create("beta", needs="none")[1])          # work without the desktop goes on
        route = {"owner": "beta", "requester": "manager", "parent": False, "kind": "task"}
        with self.assertRaises(hub.ToolError):                  # a wake-up waits with the same reason
            hub.wake_admission({"id": 1, "created_by": "manager"}, route,
                               {"needs": "browser", "goal_id": None, "title": "t", "done_when": "d", "details": ""})
        view = {a["agent"]: a for a in hub.capacity_view(["alpha", "beta"])["agents"]}
        self.assertEqual(view["beta"]["desktop_busy"], {"task": first, "agent": "alpha"})
        text = hub.capacity_text(hub.capacity_view(["beta"]), "", "browser")
        self.assertIn(f"DESKTOP BUSY: its machine runs T-{first}", text)
        # paused, stopped and not confirmed: the task is open, so the desktop stays busy
        for state in ("requested", "stopped", "not_confirmed"):
            hub.q("DELETE FROM holds")
            hub.ins("INSERT INTO holds(task,kind,by,state,created,attempt) VALUES(?,?,?,?,?,1)",
                    (first, "pause" if state == "stopped" else "stop", "owner", state, hub.now()))
            self.assertEqual(hub.desktop_busy("beta")["id"], first, state)

    def test_browser_tasks_in_tabs_of_their_own_run_side_by_side_and_a_screen_task_alone(self):
        """Two Claude in Chrome sessions read, scrolled and typed in their own tabs at the same time on one Mac (30
        October 2026): browser tasks of a runtime with browser_tabs run side by side. A screen task, and a browser task
        of a runtime that works the machine's own screen (Codex's runner), still need the desktop alone."""
        self.status("alpha")
        first = self.task("alpha", needs="browser")
        self.assertIsNone(hub.desktop_refusal("alpha", "browser", "manager"))          # a second read, beside it
        text, error = self.create("alpha")
        self.assertFalse(error, text)
        self.assertIn(f"is busy with T-{first}", hub.desktop_refusal("alpha", "screen", "manager"))
        self.assertIn(f"is busy with T-{first}", hub.desktop_refusal("beta", "browser", "manager"))     # Codex
        self.assertIn("a new screen task waits until it ends, and a new browser task runs beside it.",
                      hub.capacity_text(hub.capacity_view(["alpha"]), "", "browser"))
        hub.q("UPDATE tasks SET needs='screen' WHERE id=?", (first,))                   # a screen task: alone
        self.assertIn(f"is busy with T-{first}", hub.desktop_refusal("alpha", "browser", "manager"))
        self.assertIn("a new browser or screen task waits until it ends.",
                      hub.capacity_text(hub.capacity_view(["alpha"]), "", "browser"))

    def test_a_finished_desktop_task_holds_the_desktop_until_a_quiet_close_is_confirmed(self):
        for outcome in ("completed", "canceled"):
            with self.subTest(outcome=outcome):
                for table in ("tasks", "attempts", "events", "holds"):
                    hub.q(f"DELETE FROM {table}")
                self.status("alpha")
                done = self.task("alpha", needs="browser")
                t0 = hub.now()
                hub.q("UPDATE tasks SET state=?, delivered=? WHERE id=?", (outcome, t0, done))
                self.assertEqual(hub.desktop_busy("beta")["id"], done)          # no stop yet: still runs
                stop = hub.emit("alpha", "stop", "close", task=done, extra={"generation": "test-generation", "needs": "browser"})
                self.report_windows("alpha", [], t0 + 1)
                self.assertEqual(hub.desktop_busy("beta")["id"], done)          # not acknowledged: not confirmed quiet
                hub.q("UPDATE events SET helper_ack=? WHERE id=?", (t0 + 5, stop))
                self.report_windows("alpha", [], t0 + 4)                       # a report from before the acknowledgement
                self.assertEqual(hub.desktop_busy("beta")["id"], done)
                self.report_windows("alpha", [f"T-{done}", "owner-chat"], t0 + 6)   # its runtime still runs
                self.assertEqual(hub.desktop_busy("beta")["id"], done)
                self.status("alpha", features=["trigger_check"])                # a helper from before 1.12
                self.report_windows("alpha", ["owner-chat"], t0 + 7)
                self.assertEqual(hub.desktop_busy("beta")["id"], done)
                self.status("alpha")                                            # a 1.12 helper confirmed it
                self.assertIsNone(hub.desktop_busy("beta"))
                text, error = self.create("beta")
                self.assertFalse(error, text)

    def test_the_stop_event_names_the_generation_and_needs(self):
        t = self.task("alpha", needs="screen", state="completed")
        hub.q("UPDATE tasks SET delivered=? WHERE id=?", (hub.now() - 120, t))
        with patch.object(hub, "liveness"), patch.object(hub, "goal_sweep"), patch.object(hub, "integrity_check"), \
                patch.object(hub, "expire_handovers"), patch.object(hub, "settle_checks"), \
                patch.object(hub, "offline_sweep"), patch.object(hub, "trigger_sweep"):
            hub.tick()
        stop = hub.q1("SELECT extra FROM events WHERE kind='stop' AND task=?", (t,))
        self.assertIsNotNone(stop)
        self.assertEqual(json.loads(stop["extra"]), {"generation": "test-generation", "needs": "screen"})


class HelperSide(unittest.TestCase):
    """The helper side, with stand-in hub answers and tmux answers."""
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-auth-"))
        self.home = self.tmp / ".fleet"
        for p in (patch.object(fleet, "HOME", str(self.home)), patch.object(fleet, "SESSIONS", str(self.home / "sessions")),
                  patch.object(fleet, "HUB", "http://hub:8765"), patch.object(fleet, "AGENT", None),
                  patch.object(fleet, "team_runtime", return_value=None)):     # its update is loaded (Helper.outdated)
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.tmp)])

    def key(self, agent="alpha", text=KEYS["alpha"]):
        self.home.mkdir(mode=0o700, exist_ok=True)
        fleet.write_private(fleet.key_file(agent), text + "\n")

    def test_http_sends_the_agent_key_on_helper_routes_but_never_on_mcp_routes(self):
        sent = []

        class Answer:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b"{}"
        with patch.object(fleet.OPENER, "open", side_effect=lambda req, timeout: sent.append(req) or Answer()):
            fleet.http("GET", "/events/alpha")
            fleet.AGENT = "alpha"
            fleet.http("GET", "/events/alpha")
            self.key()
            fleet.http("GET", "/events/alpha")
            fleet.http("POST", "/mcp/alpha", {})
        auth = [req.get_header("Authorization") for req in sent]
        self.assertEqual(auth, [None, None, "Bearer " + KEYS["alpha"], None])

    def test_enrollment_makes_the_key_file_only_after_the_hub_has_the_key(self):
        answers = [(0, None), (409, {"error": "already has another key"}), (200, {"ok": True})]
        seen = []

        def http(method, path, data=None, timeout=40):
            seen.append((path, data["sha256"], os.path.exists(fleet.key_file("solo"))))
            code, body = answers.pop(0)
            if code == 0:
                raise OSError("no answer")
            return code, body
        with patch.object(fleet, "http", side_effect=http):
            with self.assertRaises(OSError):
                fleet.enroll_key("solo")                    # the answer is lost: the pending key stays for the next try
            self.assertFalse(fleet.enroll_key("solo"))
            self.assertTrue(fleet.enroll_key("solo"))
            self.assertTrue(fleet.enroll_key("solo"))       # it has its key: no hub call
        self.assertEqual(len(seen), 3)
        self.assertEqual(len({digest for _, digest, _ in seen}), 1)      # the same pending key each time
        self.assertEqual([path for path, _, _ in seen], ["/helper/key/solo"] * 3)
        self.assertEqual([present for _, _, present in seen], [False, False, False])
        key = fleet.load_agent_key("solo")
        self.assertEqual(sha(key), seen[0][1])
        self.assertEqual(stat.S_IMODE(os.stat(fleet.key_file("solo")).st_mode), 0o600)
        self.assertFalse(os.path.exists(fleet.key_file("solo") + ".pending"))

    def test_a_session_credential_only_with_a_key_and_never_a_silent_start_without_one(self):
        with patch.object(fleet, "http") as http:
            self.assertIsNone(fleet.session_credential("alpha", "chat", "g"))
            http.assert_not_called()
        self.key()
        for answer, expect in (((200, {"token": "t" * 43}), "t" * 43), ((404, {"error": "not found"}), None)):
            with patch.object(fleet, "http", return_value=answer):
                self.assertEqual(fleet.session_credential("alpha", "task", "g", task="T-3", attempt=2), expect)
        for answer in ((409, {"error": "that is not a current task attempt"}), (403, {"auth": "key_mismatch"}),
                       (200, {"token": "short"})):
            with patch.object(fleet, "http", return_value=answer), self.assertRaises(fleet.Refused):
                fleet.session_credential("alpha", "task", "g", task="T-3", attempt=2)

    def conf(self, runtime, role="worker"):
        start = {"claude": "claude --permission-mode dontAsk {chrome} {settings} {prompt}",
                 "codex": "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"}[runtime]
        return {"role": role, "runtime": runtime, "machine": "box", "can": ["shell", "browser", "screen"], "start": start,
                "screen_command": "/bin/codex"}

    def files(self):
        folder = self.home / "sessions"
        return {p.name: p for p in folder.iterdir()} if folder.exists() else {}

    @unittest.skipUnless(os.path.isfile(os.path.join(fleet.KIT, "profiles", "vps.md")),
                         "it reads profiles/vps.md, the owner's own profile, which a published copy has not got")
    def test_the_credential_reaches_each_runtime_through_its_configuration_never_an_argument(self):
        token = "s" * 43
        cases = [
            ("claude task", fleet.session_command("alpha", self.conf("claude"), "Go.", task="T-3", generation="g",
                                                  session=str(uuid.uuid4()), token=token), "json"),
            ("codex task", fleet.session_command("beta", self.conf("codex"), "Go.", task="T-4", generation="g",
                                                 session=str(uuid.uuid4()), token=token), "env"),
            ("screen task", fleet.session_command("alpha", self.conf("claude"), "Go.", task="T-5", needs="screen",
                                                  generation="g", session=str(uuid.uuid4()), token=token), "env"),
            ("claude manager", fleet.session_command("manager", self.conf("claude", "manager"), "Go.",
                                                     session=str(uuid.uuid4()), token=token), "json"),
            ("codex chat", fleet.chat_command("vps", self.conf("codex"), "g", token=token), "env"),
        ]
        for name, command, kind in cases:
            self.assertNotIn(token, command, name)
            words = fleet.launch_words(command)
            self.assertIn(os.path.basename(words[0]), ("claude", "codex", os.path.basename(fleet.sys.executable)), name)
            path = next(p for p in self.files().values() if str(p) in command and p.suffix == "." + kind)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, name)
            text = path.read_text()
            self.assertIn(token, text, name)
            if kind == "env":
                self.assertTrue(command.startswith(f". {path} && rm -f {path} && exec env "), name)
                self.assertEqual(text, f"export FLEET_SESSION_TOKEN={token}\n")
            else:
                config = json.loads(text)["mcpServers"]["fleet"]
                self.assertEqual(config["headers"], {"Authorization": "Bearer " + token})
        self.assertIn("mcp_servers.fleet.bearer_token_env_var", cases[1][1])
        self.assertIn('"http://hub:8765/mcp/manager"', (self.home / "sessions" / next(
            n for n in self.files() if n.startswith("manager."))).read_text())
        self.assertIn("--strict-mcp-config --mcp-config", cases[3][1])
        legacy = fleet.session_command("alpha", self.conf("claude"), "Go.", task="T-3", generation="g", session="s")
        self.assertNotIn(fleet.SESSIONS, legacy)                    # without a credential: as before
        self.assertTrue(legacy.startswith("env FLEET_ATTEMPT="))
        self.assertEqual(fleet.launch_words(cases[1][1])[0], "codex")

    def test_windows_without_a_credential_are_legacy_and_unused_files_go(self):
        helper = fleet.Helper("alpha", self.conf("claude"))
        self.home.mkdir(mode=0o700)
        (self.home / "sessions").mkdir(mode=0o700)
        used, stale, fresh, other = (self.home / "sessions" / n for n in
                                     ("alpha.T-3.aa.json", "alpha.T-1.bb.json", "alpha.T-4.cc.env", "beta.T-1.dd.json"))
        for p in (used, stale, fresh, other):
            p.write_text("x")
        old = time.time() - 120
        for p in (used, stale, other):
            os.utime(p, (old, old))
        listing = f"manager\tclaude ...\nT-3\tclaude --mcp-config {used} ...\nowner-chat\tenv FLEET_GENERATION=g codex\n"
        answer = subprocess.CompletedProcess([], 0, listing, "")
        with patch.object(fleet, "tmux", return_value=answer):
            self.assertEqual(helper.legacy_windows(), ["manager", "owner-chat"])
            helper.sweep_sessions()
        self.assertEqual(sorted(p.name for p in (self.home / "sessions").iterdir()),
                         sorted([used.name, fresh.name, other.name]))
        gone = subprocess.CompletedProcess([], 1, "", "can't find session: fleet-alpha")
        with patch.object(fleet, "tmux", return_value=gone):
            self.assertEqual(helper.legacy_windows(), [])            # tmux says that the session does not exist
        failed = subprocess.CompletedProcess([], 124, "", "timed out")
        with patch.object(fleet, "tmux", return_value=failed):
            self.assertIsNone(helper.legacy_windows())              # unknown, never "no legacy window"
            os.utime(fresh, (old, old))
            helper.sweep_sessions()
        self.assertTrue(fresh.exists())

    def test_the_first_manager_start_waits_for_its_credential_and_happens_once(self):
        helper = fleet.Helper("manager", self.conf("claude", "manager"))
        running = []
        with patch.object(fleet, "windows", side_effect=lambda session, **kw: list(running)), \
                patch.object(fleet, "ensure_session"), \
                patch.object(fleet, "manager_credential", side_effect=[fleet.Refused("not yet"), "tok"]) as credential, \
                patch.object(fleet, "session_command", return_value="cmd") as command, \
                patch.object(helper, "start", side_effect=lambda name, *a, **kw: running.append(name)) as start:
            self.assertTrue(helper.start_manager())
            self.assertFalse(helper.start_manager())
            self.assertFalse(helper.start_manager())
        self.assertEqual((credential.call_count, start.call_count), (2, 1))
        self.assertEqual(command.call_args.kwargs["token"], "tok")

    def test_the_key_comes_before_the_standing_session(self):
        """The hub refuses every MCP call of an agent with a key that comes without a session credential, also while
        the agent is alone. So the loop asks for the key before the standing session's start and never after it: a
        Mac's first standing session started before its helper had a key, and no credential reaches a window that
        runs. The order is read from the loop's calls, not from its text."""
        first = {}
        for node in ast.walk(ast.parse(inspect.getsource(fleet.cmd_run))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                    isinstance(node.func.value, ast.Name) and node.func.value.id == "h" and \
                    node.func.attr in ("enroll", "manage"):
                first[node.func.attr] = min(first.get(node.func.attr, node.lineno), node.lineno)
        self.assertEqual(sorted(first), ["enroll", "manage"])
        self.assertLess(first["enroll"], first["manage"])

    def test_a_helper_with_its_key_closes_the_windows_that_cannot_use_it(self):
        """The first round that a helper has its key (Helper.enroll) closes the standing session and the owner chat
        that cannot use it, and the hub refuses their calls from then on: a key that it registered just now closes
        both, whatever they hold, because the credentials of a key that is gone are revoked; a key file that was there
        closes the ones that started without any credential (legacy_windows). A window that has its credential, a
        task window and a conversation's window stay."""
        running, killed, answers, reading = [], [], [], {}

        def tmux(*args, **kw):
            self.assertEqual(args[0], "kill-window")
            name = args[2].rsplit(":=", 1)[1]
            found = name in running
            if found:
                running.remove(name)
                killed.append(name)
            return subprocess.CompletedProcess(args, 0 if found else 1, "", "" if found else "can't find window")

        def enroll_key(agent):
            answer = answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer

        def helper(agent, role, windows, legacy):
            h = fleet.Helper(agent, self.conf("claude", role))
            running[:], reading["legacy"], h.chat_started = list(windows), legacy, ("g", 2)
            return h
        with patch.object(fleet, "tmux", side_effect=tmux), patch.object(fleet, "enroll_key", side_effect=enroll_key), \
                patch.object(fleet.Helper, "look_known", lambda h: None if reading.get("tmux") is None else list(running)), \
                patch.object(fleet.Helper, "legacy_windows", lambda h: reading["legacy"]):
            reading["tmux"] = True
            # A Mac's first start: no key file, and the standing session started before the key.
            manager = helper("manager", "manager", ["manager", "other"], ["manager", "other"])
            answers[:] = [OSError("no answer"), False, True]
            with self.assertRaises(OSError):
                manager.enroll()                        # the answer was lost: it waits a minute, as after any answer
            self.assertFalse(manager.enroll())
            manager.enrolled_at -= 61
            self.assertFalse(manager.enroll())          # an answer without the key: a minute again
            manager.enrolled_at -= 61
            self.assertEqual((answers, killed, manager.manager_due), ([True], [], False))
            self.assertTrue(manager.enroll())
            self.assertEqual((killed, running, manager.manager_due), (["manager"], ["other"], True))
            self.assertTrue(manager.enroll())           # it has its key: no more calls, no more closing
            # The owner removed a worker's key, which revoked its credentials: its windows have session files and no
            # longer a credential that works, so the new key closes both whatever legacy_windows says.
            worker = helper("alpha", "worker", ["owner-chat", "T-3"], [])
            answers[:] = [True]
            self.assertFalse(worker.enroll())           # a task window runs: no registration now
            reading["tmux"] = None
            running.remove("T-3")
            self.assertFalse(worker.enroll())           # tmux gave no list: unknown, never "no task window"
            self.assertEqual((answers, killed), ([True], ["manager"]))
            reading["tmux"] = True
            self.assertTrue(worker.enroll())
            self.assertEqual((killed[1:], running, worker.chat_started), (["owner-chat"], [], None))
            # A helper that an update started again, with its key file in place: no call to the hub, also while a task
            # window runs, and only the windows without a credential close.
            self.key("beta", KEYS["beta"])
            answers[:] = []
            known = helper("beta", "worker", ["owner-chat", "T-5", "C-4"], ["owner-chat", "C-4"])
            self.assertTrue(known.enroll())
            self.assertEqual((killed[2:], running, known.chat_started), (["owner-chat"], ["T-5", "C-4"], None))
            fine = helper("beta", "worker", ["owner-chat"], [])             # its window has its credential
            self.assertTrue(fine.enroll())
            unknown = helper("beta", "worker", ["owner-chat"], None)        # tmux gave no list: never "no window"
            self.assertTrue(unknown.enroll())
            self.assertEqual((killed[3:], running, fine.chat_started, unknown.chat_started),
                             ([], ["owner-chat"], ("g", 2), ("g", 2)))

    def test_a_key_that_the_owner_removed_is_registered_again(self):
        """The hub answers no_key to a helper whose agent has no key any more (cmd_run calls key_removed): its key file
        goes, and the next round registers a key again at once, as for a helper that never had one."""
        self.key("alpha", KEYS["alpha"])
        h = fleet.Helper("alpha", self.conf("claude"))
        nothing = subprocess.CompletedProcess([], 1, "", "can't find window")       # no window to close: no real tmux
        with patch.object(fleet.Helper, "look_known", lambda h: []), patch.object(fleet.Helper, "legacy_windows", lambda h: []), \
                patch.object(fleet, "tmux", return_value=nothing), patch.object(fleet, "enroll_key", return_value=True) as enroll_key:
            self.assertTrue(h.enroll())
            enroll_key.assert_not_called()              # its key file is there
            h.key_removed()
            self.assertFalse(os.path.exists(fleet.key_file("alpha")))
            self.assertEqual((h.keyed, h.enrolled_at), (False, None))
            self.assertTrue(h.enroll())
            enroll_key.assert_called_once_with("alpha")
        called = {n.func.attr for n in ast.walk(ast.parse(inspect.getsource(fleet.cmd_run)))
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        self.assertIn("key_removed", called)            # the loop calls it for the hub's no_key

    def windows(self, running, killed):
        """A stand-in tmux that closes the windows of `running` that a kill-window names, into `killed`."""
        def tmux(*args, **kw):
            self.assertEqual(args[0], "kill-window")
            name = args[2].rsplit(":=", 1)[1]
            if name not in running:
                return subprocess.CompletedProcess(args, 1, "", "can't find window")
            running.remove(name)
            killed.append(name)
            return subprocess.CompletedProcess(args, 0, "", "")
        return tmux

    def test_a_helper_asks_no_more_where_the_server_service_registers_its_key(self):
        """Where a server service registers its agents' keys, the hub takes none from a helper (409, by: server):
        enroll_key gives None and removes its pending key, the helper asks no more, also a minute later, and the key
        file that the service or the owner makes ends the wait. The hub's next no_key (key_removed) allows one more
        try. The windows stay: a credential that a key change revoked is the hub's to name (close_revoked)."""
        refused = {"error": "the server service of worker-3 registers alpha's key", "by": "server"}
        with patch.object(fleet, "http", return_value=(409, refused)) as http:
            self.assertIsNone(fleet.enroll_key("alpha"))
        http.assert_called_once()
        self.assertEqual(list(self.home.iterdir()), [])                 # no key file, and no pending key
        running, killed = ["owner-chat", "C-4"], []
        h = fleet.Helper("alpha", self.conf("claude"))
        h.chat_started = ("g", 2)
        with patch.object(fleet, "tmux", side_effect=self.windows(running, killed)), \
                patch.object(fleet, "enroll_key", return_value=None) as enroll_key, \
                patch.object(fleet.Helper, "look_known", lambda h: list(running)), \
                patch.object(fleet.Helper, "legacy_windows", lambda h: []):
            self.assertFalse(h.enroll())
            self.assertTrue(h.key_by_server)
            h.enrolled_at -= 61
            self.assertFalse(h.enroll())                # a minute later: it asks no more
            self.assertEqual(enroll_key.call_count, 1)
            self.key("alpha", KEYS["alpha"])            # the owner made its key there and registered it
            self.assertTrue(h.enroll())
            h.key_removed()                             # the hub answered no_key: one more try, then the wait again
            self.assertEqual((h.keyed, h.key_by_server), (False, False))
            self.assertFalse(h.enroll())
            self.assertFalse(h.enroll())
            self.assertEqual(enroll_key.call_count, 2)
        self.assertEqual((killed, running, h.chat_started), ([], ["owner-chat", "C-4"], ("g", 2)))

    def test_the_windows_whose_credential_the_hub_revoked_close_and_start_again(self):
        """The hub names in its poll answer (revoked) the standing session and the owner chat whose newest credential
        a key change revoked. The helper closes the ones that run, also when it started after the change, and each
        starts again with a new credential. Another window, a window that does not run and an answer without the list
        close nothing. The loop reads the list before it keeps the owner chat, which may start it again at once."""
        running, killed = ["manager", "owner-chat", "T-2", "C-4"], []
        h = fleet.Helper("alpha", self.conf("claude"))
        h.chat_started = ("g", 2)
        with patch.object(fleet, "tmux", side_effect=self.windows(running, killed)):
            self.assertEqual(h.close_revoked(None, list(running)), [])
            self.assertEqual(h.close_revoked(["T-2", "C-4", "home"], list(running)), [])
            self.assertEqual(h.close_revoked(["owner-chat"], ["manager", "T-2"]), [])      # it does not run now
            self.assertEqual((killed, h.manager_due, h.chat_started), ([], False, ("g", 2)))
            self.assertEqual(h.close_revoked(["manager", "owner-chat"], None), ["manager", "owner-chat"])
            self.assertEqual(h.close_revoked(["manager", "owner-chat"], None), [])        # closed already
        self.assertEqual((killed, running, h.manager_due, h.chat_started),
                         (["manager", "owner-chat"], ["T-2", "C-4"], True, None))
        first = {}
        for node in ast.walk(ast.parse(inspect.getsource(fleet.cmd_run))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                    isinstance(node.func.value, ast.Name) and node.func.value.id == "h" and \
                    node.func.attr in ("close_revoked", "keep_chat"):
                first[node.func.attr] = min(first.get(node.func.attr, node.lineno), node.lineno)
        self.assertEqual(sorted(first), ["close_revoked", "keep_chat"])
        self.assertLess(first["close_revoked"], first["keep_chat"])

    def test_a_checkout_belongs_to_one_agent(self):
        fleet.claim_checkout("alpha")
        fleet.claim_checkout("alpha")
        with self.assertRaises(SystemExit):
            fleet.claim_checkout("beta")

    def test_no_credential_access(self):
        team = {"agents": {"w": {"vault": "none"}, "b": {"vault": "broker"}, "f": {"vault": "file"}, "q": {}}}
        self.home.mkdir(mode=0o700, exist_ok=True)
        (self.home / "bws-token").write_text("a token of the pilot's file mode\n")    # read by nothing any more
        (self.home / "bws-token").chmod(0o600)
        with patch.object(fleet, "TEAM", team), \
                patch.object(fleet, "vault_socket", return_value=str(self.home / "no-broker.sock")), \
                patch.object(fleet, "http", return_value=(200, {"ok": True, "job": 4, "logins": [LOGIN]})):
            # q says nothing, and a team.json that says nothing means no credential access (PRODUCT.md P5); f still
            # says "file", the Bitwarden token of its user, and file mode is gone: no credential access either
            self.assertEqual([fleet.vault_mode(a) for a in ("w", "b", "f", "q")], ["none", "broker", "none", "none"])
            for agent in ("w", "f"):
                self.assertTrue(fleet.register_key(agent))
                self.assertFalse((self.home / "age.key").exists())
                self.assertEqual(fleet.vault_status(agent), {
                    "mode": "none", "isolated": None, "callers": None, "creates": None, "captures": None,
                    "requests": None, "broker_recipient": None, "broker_read_at": None, "broker_source": None,
                    "deposits": None,       # owner feature secret_deliveries
                    "withdrawals": None,    # owner feature central_vault
                    "replaces": None,       # owner feature secret_replace
                    "places": None, "place_key": None})     # secret_targets
                self.assertEqual(fleet.probe_logins(agent, 4), {"ok": True, "results": []})
                for call in (lambda: fleet.read_login(LOGIN, agent), lambda: fleet.do_signin(LOGIN, agent, "T-1", 3),
                             lambda: fleet.do_handover(LOGIN, agent, "b", "T-1", 3)):
                    with self.assertRaises(fleet.Refused) as refused:
                        call()
                    self.assertIn("no credential access", str(refused.exception))

    def test_the_helper_reports_its_user_its_legacy_windows_and_agent_key(self):
        lc = lifecycle.Lifecycle("/kit", "alpha", {"role": "worker", "runtime": "codex"}, lambda payload: (200, {}),
                                 busy=lambda: False, run=lambda argv, **kw: (1, "", ""), legacy=lambda: ["manager"],
                                 models=lambda command: (None, "none"), home=str(self.tmp))    # its sign-in file: ours
        status = lc.collect()
        self.assertIn("agent_key", status["features"])
        self.assertEqual((status["legacy_windows"], status["access"]["user"]),
                         (["manager"], pwd.getpwuid(os.getuid()).pw_name))
        hub_view = hub.validate_status(status)
        self.assertEqual((hub_view["legacy_windows"], hub_view["access"]["user"]), (["manager"], status["access"]["user"]))


class FinishedDesktopTask(unittest.TestCase):
    """The helper acknowledges a finished browser task's stop event only after nothing that the task started still
    runs (main's review): the processes are taken before the window closes, as in control(), because a macOS child
    whose environment is hidden loses its parent link when the window closes."""
    def setUp(self):
        self.window, self.stubborn, self.sent = True, set(), []
        # pid: (parent, command, environment names the task); 102 is a platform child with a hidden environment
        self.alive = {100: (1, "claude --session-id s", True), 101: (100, "node browser-tool", True),
                      102: (100, "/System/Library/Helper --type=renderer", False), 300: (1, "unrelated", False)}
        conf = {"role": "worker", "runtime": "claude", "can": ["browser"], "machine": "studio",
                "start": "claude --permission-mode dontAsk {settings} {prompt}"}
        self.helper = fleet.Helper("studio", conf)
        for p in (patch.object(fleet, "process_table", side_effect=self.table),
                  patch.object(fleet, "end_processes", side_effect=self.end),
                  patch.object(fleet, "tmux", side_effect=self.tmux),
                  patch.object(fleet, "http", side_effect=lambda m, path, data=None, timeout=40: self.sent.append(path) or (200, {})),
                  patch.object(self.helper, "look", side_effect=lambda: ["T-5"] if self.window else []),
                  patch.object(self.helper, "pane", side_effect=lambda target: (100, "claude") if self.window else (None, ""))):
            p.start()
            self.addCleanup(p.stop)

    def table(self, task, generation):
        return [(pid, parent, command, marked) for pid, (parent, command, marked) in self.alive.items()]

    def end(self, pids, grace=5):
        for pid in pids:
            if pid not in self.stubborn:
                self.alive.pop(pid, None)
        return [pid for pid in pids if pid in self.alive]

    def tmux(self, *args, check=False, timeout=15):
        if args[:1] == ("kill-window",):
            self.window = False
            self.alive.pop(100, None)                    # the pane ends with its window; its children lose their parent
            for pid, (parent, command, marked) in list(self.alive.items()):
                if parent == 100:
                    self.alive[pid] = (1, command, marked)
        return subprocess.CompletedProcess(args, 0, "", "")

    def stop(self, needs="browser"):
        self.helper.handle({"id": 7, "kind": "stop", "task": "T-5", "extra": {"generation": "g", "needs": needs}})

    def test_a_child_that_lost_its_parent_is_ended_before_the_acknowledgement(self):
        self.stop()
        self.assertEqual(set(self.alive), {300})
        self.assertEqual(self.sent, ["/helper/ack/studio"])

    def test_a_child_that_cannot_be_ended_keeps_the_stop_unacknowledged(self):
        self.stubborn = {102}
        with self.assertRaises(fleet.Refused):
            self.stop()
        self.assertFalse(self.window)
        self.assertEqual(self.sent, [])                 # the hub keeps the desktop busy and sends the stop again

    def test_a_task_without_the_desktop_keeps_its_old_close(self):
        self.stop(needs="none")
        self.assertEqual(set(self.alive), {101, 102, 300})
        self.assertEqual(self.sent, ["/helper/ack/studio"])


STORE, OTHER_STORE = "age1" + "s" * 58, "age1" + "t" * 58
GRANT_TEAM = {"hub": {"machine": "hub", "port": 8765},
              "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "box": BOX, "lone": "127.0.0.5", "files": "127.0.0.6"},
              "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                         "alpha": {"role": "worker", "runtime": "claude", "machine": "box", "can": ["shell"],
                                   "vault": "broker", "vault_recipient": STORE},
                         "beta": {"role": "worker", "runtime": "codex", "machine": "box", "can": ["shell"], "vault": "none"},
                         "lone": {"role": "worker", "runtime": "codex", "machine": "lone", "can": ["shell"], "vault": "none"},
                         # It says "file" because a fixture must say what it means: an entry that says nothing
                         # about an agent is no credential access (PRODUCT.md P5), not the token file of its user.
                         "filer": {"role": "worker", "runtime": "codex", "machine": "files", "can": ["shell"],
                                   "vault": "file"}}}


class VaultAccess(OwnerAPI):
    """The owner gives and removes broker access in Fleet (owner feature vault_access), through the real routes and a
    real team.json commit."""
    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="fleet-vault-access-"))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.root)])
        seed = self.root / "seed"
        seed.mkdir()
        (seed / "team.json").write_text(json.dumps(GRANT_TEAM, indent=2) + "\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", str(self.root / "origin.git"), str(self.root / "kit"))
        hub.CFG["team_path"] = str(self.root / "kit" / "team.json")
        self.addCleanup(hub.CFG.pop, "team_path", None)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = json.loads(json.dumps(GRANT_TEAM))
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90, tick=5)
        for agent in ("alpha", "beta", "lone"):
            hub.ins("INSERT INTO agent_keys(agent,sha256,created,source) VALUES(?,?,?,'owner')", (agent, sha(agent), hub.now()))
            self.report(agent)

    def report(self, agent, recipient=STORE, callers=True, features=("agent_key", "broker_callers"), age=0):
        data = {"features": list(features), "legacy_windows": [],
                "security": {"vault": {"mode": hub.agents()[agent].get("vault", "none"), "isolated": True, "callers": callers,
                                       "broker_recipient": recipient, "broker_read_at": hub.now() - age}}}
        hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES(?,?,?)",
              (agent, json.dumps(hub.validate_status(data)), hub.now() - age))

    def team(self):
        code, team = self.request("/ui/team?db=test-generation")
        self.assertEqual(code, 200, team)
        return team

    def line(self, agent):
        return next(l for l in self.team()["lines"] if l["agent"] == agent)

    def vault(self, agent, value, request_id=None, **extra):
        return self.request(f"/ui/team/agents/{agent}", dict({"request_id": request_id or str(uuid.uuid4()),
                                                              "db": "test-generation", "base_sha256": self.team()["sha256"],
                                                              "vault": value}, **extra))

    def committed(self):
        return json.loads((self.root / "kit" / "team.json").read_text())

    def test_the_owner_gives_and_removes_broker_access_also_for_the_last_agent(self):
        self.assertIn("vault_access", self.request()[1]["ui_features"])
        self.assertEqual(self.line("beta")["vault_grant"], {"ready": True, "missing": []})
        self.assertIsNone(self.line("alpha")["vault_grant"])                 # it has access: its control is revoke
        self.assertEqual(self.team()["machines"]["box"]["vault_store"],
                         {"recipient": STORE, "agents": ["alpha"], "callers": True, "matches": True})
        rid = str(uuid.uuid4())
        code, receipt = self.vault("beta", "broker", request_id=rid)
        self.assertEqual(code, 200, receipt)
        self.assertEqual((receipt["changed"], receipt["updates_requested"], receipt["open_tasks"], receipt["activation"]),
                         ([{"field": "vault", "before": "none", "after": "broker"}], ["beta"], [], None))
        team = self.committed()
        self.assertEqual((team["agents"]["beta"]["vault"], team["agents"]["beta"]["vault_recipient"], team["vault_stores"]),
                         ("broker", STORE, {"box": STORE}))
        self.assertEqual(hub.agents()["beta"]["vault"], "broker")
        for agent in ("alpha", "beta"):                                   # the store agent, then the last agent
            code, receipt = self.vault(agent, "none")
            self.assertEqual((code, receipt["changed"][0]["after"]), (200, "none"), receipt)
        team = self.committed()
        self.assertEqual(team["vault_stores"], {"box": STORE})              # the binding stays
        self.assertNotIn("vault_recipient", team["agents"]["beta"])
        self.assertEqual(self.team()["machines"]["box"]["vault_store"]["agents"], [])
        self.report("beta")
        self.assertEqual(self.line("beta")["vault_grant"], {"ready": True, "missing": []})
        code, receipt = self.vault("beta", "broker")                       # the last agent gets its access back
        self.assertEqual(code, 200, receipt)
        self.assertEqual(self.committed()["agents"]["beta"]["vault_recipient"], STORE)
        code, again = self.vault("beta", "broker")
        self.assertEqual((code, again["changed"], again["updates_requested"]), (200, [], []))

    def test_a_stale_or_different_store_is_refused_and_nothing_is_committed(self):
        before = self.committed()
        for change, code in ((dict(age=700), "broker_status_unknown"), (dict(recipient=None), "broker_status_unknown"),
                             (dict(recipient=OTHER_STORE), "vault_store_mismatch"), (dict(callers=False), "broker_without_callers")):
            self.report("beta", **change)
            self.assertEqual(self.line("beta")["vault_grant"], {"ready": False, "missing": [code]}, change)
            status, answer = self.vault("beta", "broker")
            self.assertEqual((status, answer.get("missing"), answer.get("error")),
                             (409, [code], "Beta cannot get broker access yet."), change)
        self.report("beta", features=("agent_key",))
        self.assertEqual(self.line("beta")["vault_grant"]["missing"], ["helper_without_broker_callers"])
        hub.q("DELETE FROM agent_keys WHERE agent='beta'")
        self.assertEqual(self.line("beta")["vault_grant"]["missing"][0], "agent_without_key")
        # lone is alone on its machine and nothing is recorded for it, so the key its own broker reports is the one
        # the owner's grant would pin (hub.offered_store). Without a broker there, it has no store to give.
        self.assertEqual(self.line("lone")["vault_grant"], {"ready": True, "missing": []})
        self.report("lone", recipient=None)
        self.assertEqual(self.line("lone")["vault_grant"], {"ready": False, "missing": ["no_vault_store"]})
        self.assertEqual(self.committed(), before)

    def test_the_vault_command_is_broker_or_none_alone_for_workers_and_leads(self):
        self.assertIsNone(self.line("filer")["vault_grant"])                  # file mode is read-only here
        code, answer = self.vault("filer", "none")
        self.assertEqual((code, answer["error"]),
                         (409, "Filer uses the vault files of its server; Founderizer does not change that."))
        for agent, value, extra, code, error in (
                ("manager", "none", {}, 400, "the fleet manager's vault is set at installation"),
                ("beta", "file", {}, 400, "vault must be broker or none"),
                ("beta", "broker", {"model": None}, 400, "vault is set in a command of its own"),
                ("nobody", "none", {}, 404, "no such agent")):
            status, answer = self.vault(agent, value, **extra)
            self.assertEqual((status, answer.get("error")), (code, error), agent)
        self.assertEqual(self.committed(), GRANT_TEAM)

    def test_open_tasks_are_reported_and_a_revocation_takes_effect_at_once(self):
        mine = hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES('Work','alpha','manager','working',?)",
                       (hub.now(),))
        theirs = hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES('Work','beta','manager','working',?)",
                         (hub.now(),))
        code, receipt = self.vault("alpha", "none")
        self.assertEqual((code, receipt["open_tasks"]), (200, [mine]))
        row = hub.q1("SELECT * FROM tasks WHERE id=?", (mine,))
        self.assertIn("no credential access", hub.login_refusal("alpha", row, LOGIN))
        code, receipt = self.vault("beta", "broker")
        self.assertEqual((code, receipt["open_tasks"]), (200, [theirs]))

    def test_broker_access_decides_placement_and_job_confirmation(self):
        team = self.committed()
        team["agents"]["beta"]["vault"], team["agents"]["beta"]["vault_recipient"] = "broker", STORE
        self.assertEqual(hub.placement_missing(["alpha", "beta"], team), [])
        self.report("alpha", features=("agent_key",))                       # its helper sends no caller fields
        self.assertEqual(hub.placement_missing(["alpha", "beta"], team), ["broker_machine"])
        self.report("alpha", recipient=OTHER_STORE)
        self.assertEqual(hub.placement_missing(["alpha", "beta"], team), ["broker_machine"])
        hub.TEAM["agents"]["beta"]["vault"] = "none"
        hub.ins("INSERT INTO agent_keys(agent,sha256,created,source) VALUES('solo',?,?,'owner')", (sha(KEYS["solo"]), hub.now()))
        job = hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created) VALUES('beta',1,'signin',?,'',?)",
                      (LOGIN, hub.now()))
        hub.q("UPDATE agent_keys SET sha256=? WHERE agent='beta'", (sha(KEYS["beta"]),))
        headers = {"Content-Type": "application/json", "Authorization": "Bearer " + KEYS["beta"]}
        for path, body in ((f"/helper/vault/beta", {"job": job, "kind": "signin"}),
                           (f"/helper/vault/beta/fingerprints", {"job": job, "fingerprints": [
                               {"kind": "password", "hash": "0" * 64, "len": 12}]})):
            code, answer = self.request(path, body, headers=headers, source=BOX)
            self.assertEqual((code, answer.get("error")), (409, "this agent has no broker access"), path)

    def test_the_store_binding_is_checked_in_team_json(self):
        team = json.loads(json.dumps(GRANT_TEAM))
        team["vault_stores"] = {"box": STORE}
        hub.validate_team(team)
        for change in (lambda t: t["vault_stores"].update(box=OTHER_STORE),
                       lambda t: t["vault_stores"].update(nowhere=STORE),
                       lambda t: t["vault_stores"].update(box="age1short"),
                       lambda t: t["agents"]["beta"].update(vault="broker", vault_recipient=OTHER_STORE)):
            broken = json.loads(json.dumps(team))
            change(broken)
            with self.assertRaises(ValueError):
                hub.validate_team(broken)


class BrokerCallers(unittest.TestCase):
    """The broker's caller fields, the helper's gate for them, the key retry and redirects, with no real host."""
    def test_the_caller_fields_are_both_or_neither_and_exact(self):
        key = "k" * 43
        self.assertIsNone(vault.caller({"op": "handover", "job": 1}))
        self.assertEqual(vault.caller({"agent": "vps2", "agent_key": key}), ("vps2", key))
        for fields in ({"agent": None, "agent_key": None}, {"agent": None}, {"agent_key": None}, {"agent_key": key},
                       {"agent": "vps2"}, {"agent": "aa\n", "agent_key": key}, {"agent": "vps2", "agent_key": key + "\n"},
                       {"agent": "vps2", "agent_key": key[:42]}, {"agent": "vps2", "agent_key": "+" * 43},
                       {"agent": "Vps2", "agent_key": key}):
            with self.assertRaises(vault.Refused, msg=fields):
                vault.caller(fields)
        self.assertEqual(vault.described({"op": "handover", "job": 4, "agent": "vps2", "agent_key": key}),
                         "handover job=4 for vps2")
        self.assertEqual(vault.described({"op": key, "job": key, "agent": "aa\n"}), "request job=None")

    def server(self, answer):
        """A local server that answers each request with answer(handler) and keeps (path, Authorization)."""
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("Authorization")))
                answer(self)

            def log_message(self, *args):
                pass
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        return f"http://127.0.0.1:{httpd.server_port}", seen

    def test_a_redirect_is_an_answer_and_no_key_goes_to_another_place(self):
        other, elsewhere = self.server(lambda h: (h.send_response(200), h.end_headers(), h.wfile.write(b"{}")))

        def redirect(h):
            h.send_response(302)
            h.send_header("Location", other + "/took")
            h.end_headers()
        first, seen = self.server(redirect)
        key = "r" * 43
        self.assertEqual(vault.hub({"hub": first, "agent_key": key}, "GET", "/helper/vault/vps2")[0], 302)
        with tempfile.TemporaryDirectory() as home, patch.object(fleet, "HOME", home), \
                patch.object(fleet, "HUB", first), patch.object(fleet, "AGENT", "vps2"):
            fleet.write_private(fleet.key_file("vps2"), key + "\n")
            self.assertEqual(fleet.http("GET", "/events/vps2")[0], 302)
        self.assertEqual(seen, [("/helper/vault/vps2", "Bearer " + key), ("/events/vps2", "Bearer " + key)])
        self.assertEqual(elsewhere, [])                     # no second request, so the key went nowhere else

    def test_a_hub_auth_refusal_is_one_fixed_text(self):
        def refused(h):
            body = json.dumps({"error": "x", "auth": "key_required"}).encode()
            h.send_response(403)
            h.send_header("Content-Length", str(len(body)))
            h.end_headers()
            h.wfile.write(body)
        url, _ = self.server(refused)
        for conf in ({"hub": url}, {"hub": url, "agent_key": "q" * 43}):
            with self.assertRaises(vault.Refused) as error:
                vault.hub(conf, "GET", "/helper/vault/vps")
            self.assertEqual(str(error.exception), "the hub did not accept this agent's key")

    def test_the_helper_sends_caller_fields_only_to_a_broker_with_callers(self):
        sent = []
        with tempfile.TemporaryDirectory() as home, patch.object(fleet, "HOME", home), \
                patch.object(fleet, "vault_socket", return_value=home):            # it exists
            for status, has_key, fields in (({"callers": True}, True, True), ({"callers": False}, True, False),
                                            ({}, True, False), (None, True, False), ({"callers": True}, False, False)):
                if has_key and not os.path.exists(fleet.key_file("vps2")):
                    fleet.write_private(fleet.key_file("vps2"), "c" * 43 + "\n")
                elif not has_key and os.path.exists(fleet.key_file("vps2")):
                    os.remove(fleet.key_file("vps2"))
                sent.clear()

                def call(request, timeout=90):
                    sent.append(request)
                    if request["op"] == "status":
                        if status is None:
                            raise fleet.Refused("no broker")
                        return dict(status, ok=True)
                    return {"ok": True}
                with patch.object(fleet, "vault_call", side_effect=call):
                    fleet.broker_job_request("vps2", {"op": "handover", "job": 3})
                job = sent[-1]
                self.assertEqual(("agent" in job, "agent_key" in job), (fields, fields), (status, has_key))
                if fields:
                    self.assertEqual((job["agent"], job["agent_key"]), ("vps2", "c" * 43))
                self.assertEqual(any(r["op"] == "status" for r in sent), has_key)

    def test_a_request_without_the_key_goes_again_once_when_the_key_arrived(self):
        with tempfile.TemporaryDirectory() as home, patch.object(fleet, "HOME", home), patch.object(fleet, "AGENT", "vps2"), \
                patch.object(fleet, "HUB", "http://hub"):
            calls = []

            def once(method, path, data, timeout, key):
                calls.append(key)
                if len(calls) == 1:
                    fleet.write_private(fleet.key_file("vps2"), "a" * 43 + "\n")    # it arrives meanwhile
                    return 403, {"auth": "key_required"}
                return 200, {"ok": True}
            with patch.object(fleet, "http_once", side_effect=once):
                self.assertEqual(fleet.http("POST", "/helper/status/vps2", {}), (200, {"ok": True}))
            self.assertEqual(calls, [None, "a" * 43])
            for answer in ((403, {"auth": "key_required"}), (403, {"auth": "key_mismatch"})):
                calls.clear()
                with patch.object(fleet, "http_once", side_effect=lambda *a: calls.append(a[4]) or answer):
                    self.assertEqual(fleet.http("GET", "/events/vps2")[0], 403)
                self.assertEqual(calls, ["a" * 43])             # a refused key is never sent again
            os.remove(fleet.key_file("vps2"))
            calls.clear()
            with patch.object(fleet, "http_once", side_effect=lambda *a: calls.append(a[4]) or (403, {"auth": "key_required"})):
                fleet.http("GET", "/events/vps2")
            self.assertEqual(calls, [None])                     # still no key: no second request


if __name__ == "__main__":
    unittest.main()

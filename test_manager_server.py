"""A new fleet's manager gets its server in its own setup (owner feature manager_server, UI-API.md 1.82): the first
team.json gives it none ("placed": false), the hub then lists it on no server, reads no machine of it and answers no
caller as it, one move command gives it its server and its AI provider, and once its standing session can answer it
writes the owner first, once, and never after the owner has written. A local hub with a temporary Fleet repository and
a test source address for each machine; no AI, no machine."""
import json
import unittest

import hub
import hubsetup
from test_servers import HUB, NEW, OWNER, Servers

SPARE = "127.0.0.11"            # the address of the empty Linux server that the manager goes on


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(cls(name) for cls in (NewFleet, FirstMessage) for name in cls.__dict__
                              if name.startswith("test_"))


class NewFleet(Servers):
    """The fleet of a customer's first day, from hub.sh, with one empty Linux server that joined with a code."""

    def setUp(self):
        super().setUp()
        self.fresh_fleet(placed=False)
        self.joined("spare", "linux", source=SPARE, user="fleet")

    def place(self, server="spare", base=None, **extra):
        return self.owner("/ui/team/agents/manager/move", **dict(dict(base_sha256=base or self.team_sha(),
                                                                       server=server), **extra))

    def state_of(self, agent="manager"):
        return next(a for a in self.request(source=OWNER)[1]["agents"] if a["name"] == agent)

    def job(self, server, job, state, step, detail=None, source=SPARE):
        status, answer = self.service(f"/server/{server}/jobs/{job}", {"state": state, "step": step, "detail": detail},
                                      source=source)
        self.assertEqual(status, 200, answer)

    def test_the_feature_is_offered(self):
        self.assertIn("manager_server", self.request(source=OWNER)[1]["ui_features"])

    def test_the_manager_of_a_new_fleet_is_on_no_server(self):
        self.assertIs(self.state_of()["placed"], False)
        _, servers = self.servers()
        self.assertEqual((servers["hub"]["agents"], servers["hub"]["available"]), ([], False))
        self.assertIn("hub_machine", servers["hub"]["why"])
        self.assertEqual((servers["spare"]["agents"], servers["spare"]["available"]), ([], True))
        status, machines = self.request("/ui/machines?db=test-generation", source=OWNER)
        self.assertEqual((status, [m["agent"] for m in machines["machines"]]), (200, []))
        status, health = self.request("/ui/health?db=test-generation", source=OWNER)
        self.assertEqual(status, 200, health)
        self.assertEqual([w for w in health["warnings"] if w.get("agent") == "manager"], [])
        self.assertEqual(health["helpers"], [])

    def test_no_caller_is_the_manager_until_it_has_a_server(self):
        """Its entry names the hub's machine, where the central vault holds every key and no agent may run."""
        for path in ("/events/manager?after=-1&wait=0", "/worker/install/manager"):
            for source in (HUB, SPARE, NEW):
                status, answer = self.request(path, source=source)
                self.assertEqual((status, answer.get("error")),
                                 (403, "Manager has no server yet. Give it one in its setup in the app."), (path, source))
        for path, body in (("/mcp/manager", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
                           ("/helper/session/manager", {"kind": "standing", "generation": "test-generation"})):
            status, answer = self.request(path, body, source=HUB)
            self.assertEqual((status, answer.get("error")),
                             (403, "Manager has no server yet. Give it one in its setup in the app."), path)
        self.assertIsNone(hub.kv_get("listed:manager:manager"))

    def test_one_command_gives_it_its_server_and_its_provider(self):
        status, receipt = self.place(runtime="codex")
        self.assertEqual(status, 200, receipt)
        self.assertEqual({k: receipt[k] for k in ("agent", "server", "was", "runtime")},
                         {"agent": "manager", "server": "spare", "was": None, "runtime": "codex"})
        entry = self.origin_team()["agents"]["manager"]
        self.assertEqual(entry, {"role": "manager", "machine": "spare", "runtime": "codex", "can": ["shell", "web"],
                                 "vault": "none", "start": hubsetup.STARTS["codex"]})
        job = hub.q1("SELECT * FROM server_jobs WHERE id=?", (receipt["job"],))
        self.assertEqual((job["server"], job["kind"], job["agent"], job["runtime"], job["state"]),
                         ("spare", "install", "manager", "codex", "queued"))
        self.assertIs(self.state_of()["placed"], True)
        self.assertEqual(self.servers()[1]["spare"]["agents"], ["manager"])
        self.assertIsNone(hub.kv_get("moved_from:manager"))         # it left no machine whose calls hear `moved`
        self.assertEqual(hub.kv_get(hub.FIRST_MESSAGE), "placed")
        said = [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say'")]
        self.assertEqual(said, [], "the manager reads no move of its own: it was on no server")
        self.assertEqual(self.request("/events/manager?after=-1&wait=0", source=SPARE)[0], 200)   # it is there now
        self.assertEqual(self.request("/events/manager?after=-1&wait=0", source=HUB)[0], 403)

    def test_without_a_runtime_it_keeps_the_one_its_entry_names(self):
        status, receipt = self.place()
        self.assertEqual((status, receipt["runtime"]), (200, "claude"))
        entry = self.origin_team()["agents"]["manager"]
        self.assertEqual((entry["runtime"], entry["start"], "placed" in entry), ("claude", hubsetup.STARTS["claude"],
                                                                              False))

    def test_any_kind_of_server_takes_it_but_never_the_hubs(self):
        hub.q("INSERT INTO server_keys(server,sha256,created) VALUES('hub',?,0)", ("d" * 64,))
        hub.q("INSERT OR REPLACE INTO server_status(server,data,reported) VALUES('hub','{}',?)", (hub.now(),))
        status, answer = self.place("hub")
        self.assertEqual((status, answer["error"]), (409, "No agent runs on the hub's server."))
        self.assertEqual(self.place(runtime="grok")[0], 400)
        self.joined("mini", "mac", source=NEW)          # the hub's own machine is Linux: no kind to keep
        status, receipt = self.place("mini", runtime="claude")
        self.assertEqual(status, 200, receipt)
        self.assertEqual(self.origin_team()["agents"]["manager"]["machine"], "mini")

    def test_a_failed_install_goes_again_and_a_placed_agent_keeps_its_provider(self):
        status, receipt = self.place(runtime="codex")
        self.assertEqual(status, 200, receipt)
        self.job("spare", receipt["job"], "failed", "runtime", "Codex could not be installed.")
        head = self.origin_team()
        status, again = self.place()
        self.assertEqual(status, 200, again)
        self.assertEqual((again["was"], again["runtime"], self.origin_team()), ("spare", "codex", head))
        self.job("spare", again["job"], "failed", "runtime", "Codex could not be installed.")
        status, answer = self.place(runtime="claude")
        self.assertEqual((status, answer["error"]),
                         (409, "A move keeps Manager's AI provider. Switch it with a command of its own."))

    def test_its_first_message_waits_for_its_sign_in(self):
        """Its helper starts the standing session at the install's service step, before the owner has signed it in:
        a session that listed its tools then cannot answer yet, and a setup check then would fail on its sign-in."""
        status, receipt = self.place(runtime="codex")
        self.assertEqual(status, 200, receipt)
        self.job("spare", receipt["job"], "running", "service")
        hub.kv_set("listed:manager:manager", 1)
        with hub.LOCK:
            hub.first_message_sweep(hub.now())
        self.assertEqual(hub.kv_get(hub.FIRST_MESSAGE), "placed")
        self.assertIsNone(hub.q1("SELECT 1 FROM machine_checks WHERE agent='manager'"))
        self.job("spare", receipt["job"], "done", "sign_in")
        with hub.LOCK:
            hub.first_message_sweep(hub.now())
        self.assertTrue(hub.kv_get(hub.FIRST_MESSAGE).startswith("check:"))

    def test_placed_is_only_a_new_fleets_manager_on_the_hubs_machine(self):
        team = hubsetup.template("100.80.1.2", owner="100.90.3.4", placed=False)
        hub.validate_team(team)
        for change in ({"placed": True}, {"placed": None}, {"placed": False, "machine": "box"}):
            bad = json.loads(json.dumps(team))
            bad["addresses"]["box"] = "100.80.1.3"
            bad["agents"]["manager"].update(change)
            with self.assertRaises(ValueError, msg=change) as refused:
                hub.validate_team(bad)
            self.assertIn("placed is false for a manager that has no server yet", str(refused.exception))
        worker = json.loads(json.dumps(team))
        del worker["agents"]["manager"]["placed"]
        worker["agents"]["writer"] = {"role": "worker", "machine": "hub", "runtime": "codex", "placed": False}
        with self.assertRaises(ValueError):
            hub.validate_team(worker)


class FirstMessage(NewFleet):
    """The manager writes first, once: when its standing session on its new server has listed its tools and the setup
    check that the hub asked for then has its answer, the hub asks it for one short message."""

    def setUp(self):
        super().setUp()
        status, receipt = self.place(runtime="codex")
        self.assertEqual(status, 200, receipt)
        self.job("spare", receipt["job"], "done", "sign_in")

    def sweep(self):
        with hub.LOCK:
            hub.first_message_sweep(hub.now())

    def listed(self):
        """Its standing session on spare lists its tools, as every session does at its start (listed_window)."""
        status, answer = self.request("/mcp/manager", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                                      source=SPARE)
        self.assertEqual(status, 200, answer)

    def asked(self):
        return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id")]

    def answer_check(self, *items, state="completed"):
        check = hub.q1("SELECT * FROM machine_checks WHERE agent='manager' ORDER BY id DESC LIMIT 1")
        hub.q("UPDATE machine_checks SET state=?, completed=?, verify=? WHERE id=?",
              (state, hub.now(), json.dumps(list(items)) if state == "completed" else None, check["id"]))

    def test_the_manager_is_asked_once_when_it_can_answer_and_its_check_passed(self):
        self.sweep()
        self.assertEqual((hub.kv_get(hub.FIRST_MESSAGE), self.asked()), ("placed", []))   # no session yet
        self.listed()
        self.sweep()
        check = hub.q1("SELECT * FROM machine_checks WHERE agent='manager' ORDER BY id DESC LIMIT 1")
        self.assertEqual((check["state"], hub.kv_get(hub.FIRST_MESSAGE)), ("requested", f"check:{check['id']}"))
        self.sweep()
        self.assertEqual(self.asked(), [], "it waits for the check's answer")
        self.answer_check({"kind": "runtime", "ref": "codex", "state": "ok", "detail": "signed in", "required": True},
                          {"kind": "capability", "ref": "web", "state": "not_verified", "detail": "", "required": False})
        self.sweep()
        self.sweep()
        asked = self.asked()
        self.assertEqual(len(asked), 1, asked)
        self.assertIn("you run on spare, and your setup check passed", asked[0])
        self.assertIn("ONE short message now with message_owner, and nothing else: that the fleet is ready, that its "
                      "checks passed, and ask what you should look after first", asked[0])
        self.assertNotRegex(asked[0], r"\b(he|his|him)\b")          # the hub's words to agents name no owner "he"
        self.assertEqual(hub.kv_get(hub.FIRST_MESSAGE), "told")

    def test_a_check_that_did_not_pass_is_not_said_to_have_passed(self):
        self.listed()
        self.sweep()
        self.answer_check({"kind": "runtime", "ref": "codex", "state": "failed", "detail": "not signed in",
                           "required": True})
        self.sweep()
        asked = self.asked()
        self.assertEqual(len(asked), 1, asked)
        self.assertNotIn("passed", asked[0])
        self.assertIn("that the fleet is ready and ask what you should look after first", asked[0])
        check = hub.q1("SELECT id FROM machine_checks WHERE agent='manager' ORDER BY id DESC LIMIT 1")["id"]
        hub.kv_set(hub.FIRST_MESSAGE, f"check:{check}")     # and a check that never answered is no pass either
        hub.q("DELETE FROM events")
        self.answer_check(state="offline")
        self.sweep()
        self.assertNotIn("passed", self.asked()[0])

    def test_never_after_the_owner_wrote(self):
        status, answer = self.request("/ui/messages", self.command(text="Hello"), source=OWNER)
        self.assertEqual(status, 200, answer)
        hub.q("DELETE FROM events")
        self.listed()
        self.sweep()
        self.assertEqual((hub.kv_get(hub.FIRST_MESSAGE), self.asked()), ("none", []))
        self.assertIsNone(hub.q1("SELECT 1 FROM machine_checks WHERE agent='manager'"))

    def test_nor_after_the_manager_wrote(self):
        hub.q("INSERT INTO owner_reports(text,about,created,agent) VALUES('Hi','',?,'manager')", (hub.now(),))
        self.listed()
        self.sweep()
        self.assertEqual((hub.kv_get(hub.FIRST_MESSAGE), self.asked()), ("none", []))

    def test_a_fleet_whose_manager_always_had_a_server_is_never_asked(self):
        """The state starts at the first server of a new fleet's manager (move_agent), so a fleet from before this,
        the owner's own included, never meets it, whatever its manager's session lists."""
        hub.kv_set(hub.FIRST_MESSAGE, None)
        self.listed()
        self.sweep()
        self.assertEqual(self.asked(), [])
        self.assertIsNone(hub.q1("SELECT 1 FROM machine_checks WHERE agent='manager'"))


if __name__ == "__main__":
    unittest.main()

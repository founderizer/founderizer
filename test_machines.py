"""Owner API 1.2 machine routes. In-process hub and temporary Git repositories; no fleet or AI calls."""
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
from unittest.mock import patch
import unittest
import uuid

import hub
from test_ui_api import OwnerAPI


def git(*args, cwd=None):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell", "web"]}}}


class Machines(OwnerAPI):
    def setUp(self):
        super().setUp()
        self.server.machines = True             # each request comes from the machine that its route names
        hub.TEAM = json.loads(json.dumps(TEAM))
        self.root = Path(tempfile.mkdtemp(prefix="fleet-machines-"))
        seed = self.root / "seed"
        seed.mkdir()
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", str(self.root / "origin.git"), str(self.root / "kit"))
        self.kit = self.root / "kit"
        hub.CFG["team_path"] = str(self.kit / "team.json")
        hub._revision_cache.update(at=0.0, value=None)
        self.rev = git("rev-parse", "HEAD", cwd=self.kit)

    def tearDown(self):
        super().tearDown()
        hub.CFG.pop("team_path", None)
        hub._revision_cache.update(at=0.0, value=None)
        shutil.rmtree(str(self.root), ignore_errors=True)

    def machines(self, db="test-generation"):
        return self.request("/ui/machines?db=" + db)

    def row(self, name):
        code, data = self.machines()
        self.assertEqual(code, 200)
        return [m for m in data["machines"] if m["agent"] == name][0]

    def report(self, agent, revision=None, vault=None, **update):
        """One helper status report from the machine of `agent`, as a real helper sends it."""
        return self.request(f"/helper/status/{agent}", self.report_body(agent, revision, vault, **update))

    def report_body(self, agent, revision=None, vault=None, **update):
        runtime = TEAM["agents"][agent]["runtime"]
        body = {"revision": revision or self.rev, "os": {"name": "Ubuntu 24.04.4 LTS", "kernel": "6.8.0"},
                "access": {"user": "fleet"},
                "security": {"unattended_upgrades": True, "pending_security": 2, "reboot_required": False,
                             "firewall": "active", "tailscale": True,
                             **({"vault": vault} if vault else {})},
                "runtime": {"name": runtime, "version": ("codex-cli 0.160.0" if runtime == "codex"
                                                         else "claude-code 2.0.0"), "signed_in": True},
                "update": {"state": update.get("state"), "detail": update.get("detail")}}
        return body

    def status(self, revision=None, **update):
        return self.report("vps", revision, **update)

    def update(self, agent="vps", request_id=None):
        return self.request(f"/ui/machines/{agent}/update",
                            {"request_id": request_id or str(uuid.uuid4()), "db": "test-generation"})

    def start_manager(self, agent="manager", request_id=None):
        return self.request(f"/ui/machines/{agent}/manager",
                            {"request_id": request_id or str(uuid.uuid4()), "db": "test-generation"})

    def push_team(self, change):
        work = self.root / ("work-" + uuid.uuid4().hex[:6])
        git("clone", "-q", str(self.root / "origin.git"), str(work))
        team = json.loads((work / "team.json").read_text())
        change(team)
        (work / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        git("commit", "-q", "-am", "change team", cwd=work)
        git("push", "-q", "origin", "HEAD:main", cwd=work)
        return git("rev-parse", "HEAD", cwd=work)

    def push_file(self, name, text, message):
        """One commit that changes one file, as a release carries code to the fleet."""
        work = self.root / ("work-" + uuid.uuid4().hex[:6])
        git("clone", "-q", str(self.root / "origin.git"), str(work))
        (work / name).parent.mkdir(parents=True, exist_ok=True)
        (work / name).write_text(text)
        git("add", "-A", cwd=work)
        git("commit", "-q", "-m", message, cwd=work)
        git("push", "-q", "origin", "HEAD:main", cwd=work)
        return git("rev-parse", "HEAD", cwd=work)

    def move_kit(self, rev):
        """What a deployment does: the hub checkout takes the commit, and the caches that hold the old one go."""
        git("fetch", "-q", "origin", cwd=self.kit)
        git("reset", "-q", "--hard", rev, cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        hub._code_diffs.clear()
        hub._vault_source.clear()
        self.rev = rev

    def reload(self, revision, request_id=None):
        return self.request("/ui/team/reload", {"request_id": request_id or str(uuid.uuid4()), "db": "test-generation",
                                                "revision": revision})

    # ---- read
    def test_state_lists_the_machines_feature(self):
        code, state = self.request()
        self.assertIn("machines", state["ui_features"])

    def test_machines_need_the_current_generation(self):
        self.assertEqual(self.machines("old")[0], 409)

    def test_unreported_machines_are_stale_with_null_readings(self):
        code, data = self.machines()
        self.assertEqual(data["desired_revision"], self.rev)
        vps = [m for m in data["machines"] if m["agent"] == "vps"][0]
        self.assertEqual(vps["address"], "127.0.0.3")
        self.assertTrue(vps["stale"])
        self.assertIsNone(vps["revision"])
        self.assertIsNone(vps["update"]["state"])
        self.assertEqual(set(vps["security"].values()), {None})

    # ---- helper status
    def test_status_report_shows_a_current_machine(self):
        code, answer = self.status()
        self.assertEqual((code, answer["update_requested"], answer["desired_revision"]), (200, False, self.rev))
        vps = self.row("vps")
        self.assertFalse(vps["stale"])
        self.assertEqual(vps["update"]["state"], "current")
        self.assertEqual(vps["security"]["pending_security"], 2)
        self.assertEqual(vps["runtime"]["version"], "codex-cli 0.160.0")

    def test_the_standing_session_is_told_when_its_tool_list_is_no_longer_the_one(self):
        """**A new team tool reaches the standing manager session only when it starts.** The list is served once,
        at `initialize`, and this hub announces no change of it, so the hub tells that machine's helper instead and
        the helper starts the session again (the owner, 21 October 2026: "how are agents going to get the updates
        automatically?"). Nothing is said before this hub has served that session a list to compare with."""
        self.assertEqual(self.report("manager")[1]["manager_tools_changed"], False, "nothing served, nothing to compare")
        hub.kv_set("tools:manager", hub.tool_contract("manager"))
        self.assertEqual(self.report("manager")[1]["manager_tools_changed"], False)
        # A release that adds a tool for this agent: the same session would now get another list.
        hub.kv_set("tools:manager", "0" * 12)
        self.assertEqual(self.report("manager")[1]["manager_tools_changed"], True)
        # It keeps saying so until that session has asked again, so a helper that could not act acts later.
        self.assertEqual(self.report("manager")[1]["manager_tools_changed"], True)
        hub.kv_set("tools:manager", hub.tool_contract("manager"))
        self.assertEqual(self.report("manager")[1]["manager_tools_changed"], False)
        # A worker's session is one task long: it asks for the list at every start, so nothing is said about it.
        self.assertNotIn("manager_tools_changed", self.report("vps")[1])

    def test_the_contract_is_the_tools_and_their_fields_and_not_their_words(self):
        """What a running session cannot learn is a tool that is new, gone or that takes other fields. A tool's own
        words are built at each `tools/list` — they carry who an agent may write to and what each looks after — so
        they reach it at its next call and must not turn its session over."""
        before = hub.tool_contract("manager")
        self.assertEqual(before, hub.tool_contract("manager"))
        self.assertNotEqual(before, hub.tool_contract("vps"), "a worker holds other tools")
        with patch.object(hub, "described", lambda agent, name, desc: desc + " and other words"):
            self.assertEqual(hub.tool_contract("manager"), before, "a description is not the contract")
        one = [t for t in hub.TOOLS if t[1] != "tell_owner"]
        with patch.object(hub, "TOOLS", one):
            self.assertNotEqual(hub.tool_contract("manager"), before, "a tool that is gone is")

    def test_status_rejects_bad_fields_and_registered_logins(self):
        self.assertEqual(self.request("/helper/status/vps", {"security": {"firewall": "open"}})[0], 400)
        self.assertEqual(self.request("/helper/status/vps", {"revision": "not-a-commit"})[0], 400)
        secret = "PracticeLogin2026xyz"   # the hub check finds letter-and-digit logins
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES(?,?,?,?,?)",
                ("practice", "s1", hashlib.sha256(("s1" + secret).encode()).hexdigest(), len(secret), "u"))
        self.assertEqual(self.status(state="failed", detail="git said " + secret)[0], 422)
        self.assertIsNone(hub.q1("SELECT * FROM machine_status WHERE agent='vps'"))

    def test_access_comes_from_the_team_and_the_helper(self):
        self.assertIsNone(self.row("vps")["access"]["ssh"])
        hub.TEAM["access"] = {"vps": {"ssh_user": "claude", "ssh_port": 2222, "screen_sharing": True}}
        body = {"revision": self.rev, "access": {"ssh": True, "screen_sharing": False},
                "update": {"state": None, "detail": None}}
        self.assertEqual(self.request("/helper/status/vps", body)[0], 200)
        access = self.row("vps")["access"]
        self.assertEqual(access, {"ssh": {"user": "claude", "port": 2222, "available": True},
                                  "screen_sharing": {"available": False}})
        self.assertEqual(self.request("/helper/status/vps", dict(body, access={"ssh": "yes"}))[0], 400)
        bad = json.loads(json.dumps(TEAM))
        bad["access"] = {"vps": {"ssh_user": "bad user"}}
        with self.assertRaises(ValueError):
            hub.validate_team(bad)

    # ---- check this machine
    def check(self, agent="vps", request_id=None):
        return self.request(f"/ui/machines/{agent}/check",
                            {"request_id": request_id or str(uuid.uuid4()), "db": "test-generation"})

    def test_a_check_asks_the_helper_and_its_report_completes_it(self):
        self.assertIn("machine_check", self.request()[1]["ui_features"])
        rid = str(uuid.uuid4())
        code, result = self.check(request_id=rid)
        self.assertEqual((code, result["check"]["state"], result["changed"]), (200, "requested", True))
        self.assertTrue(self.check(request_id=rid)[1]["replayed"])
        self.assertEqual(self.check()[1]["changed"], False)              # one waiting check per machine
        cid = result["check"]["id"]
        events = self.request("/events/vps?delivery=1&after=0&wait=0")[1]["events"]
        self.assertEqual([(e["kind"], e["extra"]) for e in events if e["kind"] == "check"], [("check", {"check": cid})])
        body = {"revision": self.rev, "check": cid, "update": {"state": None, "detail": None}}
        self.assertEqual(self.request("/helper/status/vps", body)[0], 200)
        row = self.row("vps")
        self.assertEqual((row["check"]["id"], row["check"]["state"]), (cid, "completed"))
        self.assertFalse(row["stale"])
        self.assertNotIn("check", json.loads(hub.q1("SELECT data FROM machine_status WHERE agent='vps'")["data"]))
        self.assertEqual([e for e in self.request("/events/vps?delivery=1&after=0&wait=0")[1]["events"]
                          if e["kind"] == "check"], [])                 # a finished check is not sent again
        self.assertEqual(self.check("nobody")[0], 404)

    def test_a_check_without_a_report_ends_failed_or_offline(self):
        cid = self.check()[1]["check"]["id"]
        hub.settle_checks(hub.now() + hub.CHECK_WAIT + 1)
        self.assertEqual(self.row("vps")["check"]["state"], "offline")    # the helper never checked in
        cid = self.check()[1]["check"]["id"]
        hub.touch("vps")
        hub.settle_checks(hub.now() + hub.CHECK_WAIT + 1)
        check = self.row("vps")["check"]
        self.assertEqual((check["id"], check["state"]), (cid, "failed"))
        self.assertIn("sent no report", check["detail"])

    # ---- updates
    def test_update_request_runs_through_waiting_to_current(self):
        self.status(revision="a" * 40)
        self.assertEqual(self.row("vps")["update"]["state"], "behind")
        rid = str(uuid.uuid4())
        code, result = self.update(request_id=rid)
        self.assertEqual((code, result["state"], result["desired_revision"]), (200, "requested", self.rev))
        code, again = self.update(request_id=rid)
        self.assertTrue(again["replayed"])
        events = hub.q("SELECT * FROM events WHERE agent='vps' AND kind='update'")
        self.assertEqual(len(events), 1)
        self.assertEqual(json.loads(events[0]["extra"])["desired_revision"], self.rev)
        code, answer = self.status(revision="a" * 40, state="waiting_idle", detail="Waits until no task session is open.")
        self.assertTrue(answer["update_requested"])
        self.assertEqual(self.row("vps")["update"]["state"], "waiting_idle")
        code, answer = self.status(revision=self.rev)
        self.assertFalse(answer["update_requested"])
        vps = self.row("vps")
        self.assertEqual(vps["update"]["state"], "current")
        self.assertIsNotNone(vps["update"]["finished_at"])

    def test_a_machine_whose_first_report_is_behind_is_asked_to_follow(self):
        """The hub asks the machines that have reported when team.json changes (apply_team). A helper that loaded
        the file before a change of it, and reports for the first time after it, was asked by nobody, so its agent
        got no session until the next change. Its first report is asked now."""
        old = self.rev
        new = self.push_team(lambda team: team["agents"]["vps"].update(can=["shell", "web", "screen"]))
        self.move_kit(new)                          # the change is the hub's before this machine ever reported
        code, answer = self.status(revision=old)
        self.assertEqual((code, answer["update_requested"], answer["desired_revision"]), (200, True, new))
        asked = lambda: [json.loads(e["extra"])["desired_revision"]
                         for e in hub.q("SELECT * FROM events WHERE agent='vps' AND kind='update'")]
        self.assertEqual(asked(), [new])
        self.assertEqual(self.row("vps")["update"]["state"], "requested")
        code, answer = self.status(revision=old)    # the same report again asks no second time
        self.assertTrue(answer["update_requested"])
        self.assertEqual(asked(), [new])
        code, answer = self.status(revision=new)    # and the helper that followed ends the request
        self.assertFalse(answer["update_requested"])
        self.assertEqual(self.row("vps")["update"]["state"], "current")

    def test_a_machine_whose_reading_went_is_asked_again_at_its_next_report(self):
        """A move to another server and a removal take the agent's machine reading away, so its next report is a
        first one again, and a helper that still runs older settings is asked to follow."""
        old = self.rev
        self.assertFalse(self.status(revision=old)[1]["update_requested"])      # current: its reading is there
        hub.q("DELETE FROM machine_status WHERE agent='vps'")                   # as a move does
        self.move_kit(self.push_team(lambda team: team["agents"]["vps"].update(can=["shell"])))
        code, answer = self.status(revision=old)
        self.assertEqual((code, answer["update_requested"], answer["desired_revision"]), (200, True, self.rev))
        self.assertEqual(len(hub.q("SELECT 1 FROM events WHERE agent='vps' AND kind='update'")), 1)

    def test_a_first_report_that_is_not_behind_is_asked_nothing(self):
        """Current, of a commit that the hub does not know, and different in no Fleet file: none is asked. And a
        report after the first is not this rule's: the change's own request is (apply_team)."""
        events = lambda agent: hub.q("SELECT * FROM events WHERE agent=? AND kind='update'", (agent,))
        self.assertFalse(self.report("manager", revision=self.rev)[1]["update_requested"])
        self.assertFalse(self.status(revision="a" * 40)[1]["update_requested"])         # unknown: maybe a later one
        self.assertEqual((events("manager"), events("vps")), ([], []))
        hub.q("DELETE FROM machine_status")
        old = self.rev
        self.move_kit(self.push_file("outputs/T-1/notes.md", "A task's output.\n", "the output of a task"))
        self.assertFalse(self.status(revision=old)[1]["update_requested"])              # no Fleet file changed
        self.assertEqual(events("vps"), [])
        self.move_kit(self.push_team(lambda team: team["agents"]["vps"].update(can=["shell"])))
        self.assertFalse(self.status(revision=old)[1]["update_requested"])              # not its first report
        self.assertEqual(events("vps"), [])

    def test_each_row_says_what_the_agent_s_own_processes_use(self):
        """The owner's yes of 4 November 2026 to each agent's own use on Agents (lifecycle.agent_use): as its helper
        reported it, a figure of another shape as null, and null from a helper older than that."""
        self.assertEqual(self.status()[0], 200)
        self.assertIsNone(self.row("vps")["use"])
        body = self.report_body("vps")
        for use, kept in (({"cpu_percent": 2.47, "memory": 1288490188}, {"cpu_percent": 2.5, "memory": 1288490188}),
                          ({"cpu_percent": "x", "memory": -1}, {"cpu_percent": None, "memory": None})):
            self.assertEqual(self.request("/helper/status/vps", dict(body, use=use))[0], 200)
            self.assertEqual(self.row("vps")["use"], kept)
        before = hub.CHANGE["state"]            # it changes at every report, and the apps read it on their own clock
        self.assertEqual(self.request("/helper/status/vps", dict(body, use={"cpu_percent": 9.0, "memory": 5}))[0], 200)
        self.assertEqual(hub.CHANGE["state"], before)

    def test_failed_update_stays_visible(self):
        self.status(revision="a" * 40)
        self.update()
        self.status(revision="a" * 40, state="failed", detail="git merge failed: not a fast-forward")
        vps = self.row("vps")
        self.assertEqual(vps["update"]["state"], "failed")
        self.assertIn("fast-forward", vps["update"]["detail"])

    def test_a_new_request_after_a_failure_follows_the_helper(self):
        """A report of the earlier failure can come between the new request and the helper's update event. The
        steps that the helper then reports for the new request reach the row, and so does its new failure."""
        self.status(revision="a" * 40)
        self.update()
        self.status(revision="a" * 40, state="failed", detail="git merge failed: not a fast-forward")
        self.update()
        self.status(revision="a" * 40, state="failed", detail="git merge failed: not a fast-forward")
        code, answer = self.status(revision="a" * 40, state="waiting_idle", detail="Waits until no turn runs.")
        self.assertEqual(self.row("vps")["update"]["state"], "waiting_idle")
        self.status(revision="a" * 40, state="updating", detail="Updating Fleet while idle.")
        self.assertEqual(self.row("vps")["update"]["state"], "updating")
        self.status(revision="a" * 40, state="failed", detail="The update stopped: OSError.")
        self.assertEqual(self.row("vps")["update"]["detail"], "The update stopped: OSError.")
        self.assertEqual(self.status(revision=self.rev)[1]["update_requested"], False)
        self.assertEqual(self.row("vps")["update"]["state"], "current")

    def test_a_helper_that_started_again_during_its_update_is_asked_again(self):
        """Its update state lives in the helper's memory, so a new process reports none: the request stands again,
        and the answer asks for it, instead of a row that says updating for ever. A commit that the hub does not have
        yet can hold the update, so a report from one waits for the hub's fetch."""
        old = self.rev
        new = self.push_file("fleet.py", "# the helper, two\n", "a change of the helper")
        self.move_kit(new)
        self.status(revision=old)
        self.update()
        code, answer = self.status(revision=old, state="updating", detail="Updating Fleet while idle.")
        self.assertFalse(answer["update_requested"])
        code, answer = self.status(revision="b" * 40)                # a commit that the hub does not have: it waits
        self.assertFalse(answer["update_requested"])
        self.assertEqual(self.row("vps")["update"]["state"], "updating")
        code, answer = self.status(revision=old)
        self.assertEqual((code, answer["update_requested"], answer["desired_revision"]), (200, True, new))
        self.assertEqual(self.row("vps")["update"]["state"], "requested")
        code, answer = self.status(revision=old)        # a helper with nothing in hand at a request: no change
        self.assertTrue(answer["update_requested"])
        self.status(revision=old, state="failed", detail="git merge failed: not a fast-forward")
        self.status(revision=old)               # a failure stays until a new request: nothing asks again by itself
        self.assertEqual(self.row("vps")["update"]["state"], "failed")

    def test_a_release_that_only_changes_the_vault_leaves_the_machine_current_and_the_broker_behind(self):
        """The one piece of the fleet a release does not reach. The broker runs a root-owned copy of vault.py
        outside every checkout a helper updates, and `lifecycle.OWNER_ONLY` lists that file among the ones a helper
        never loads, so a commit that changes only it counts as taken: the machine says "current" and the broker
        goes on running the copy installed by hand. Nothing in a machine's revision can say that, so the broker says
        what its own program hashes to and the hub compares it with its own vault.py."""
        first = self.push_file("vault.py", "# the vault, one\n", "the vault")
        self.move_kit(first)
        installed = hashlib.sha256(b"# the vault, one\n").hexdigest()
        self.assertEqual(hub.vault_source(first), installed)
        self.assertIsNone(hub.vault_source("e" * 40))                   # an unknown commit says nothing
        self.assertIsNone(hub.vault_source(None))
        vault = {"mode": "broker", "isolated": True, "broker_source": installed, "broker_read_at": hub.now()}
        self.assertEqual(self.report("vps", vault=vault)[0], 200)
        self.assertEqual(self.row("vps")["security"]["vault"]["broker_source"], installed)
        self.assertEqual([w["kind"] for w in hub.health_view()["warnings"] if w["kind"] == "vault_behind"], [])
        # A release that changes only vault.py: the hub counts the machine as running its code, and it does.
        second = self.push_file("vault.py", "# the vault, two\n", "fix the vault")
        self.move_kit(second)
        self.assertTrue(hub.same_code(first, second))
        self.assertEqual(self.report("vps", revision=second, vault=vault)[0], 200)
        self.assertEqual(self.row("vps")["update"]["state"], "current")
        # And the broker, which took none of it, is said in one line that carries the way out. That machine's own
        # server service runs the root command by itself within ten minutes (server.Service.vault_program), so a
        # warning that stays is about a machine where it could not. T-37: in his words, with no revision, path or
        # command; the steps by hand are WORKER-INSTALL.md's, and never the join line (`new_join_code` refuses a
        # name the fleet already has).
        behind = [w for w in hub.health_view()["warnings"] if w["kind"] == "vault_behind"]
        self.assertEqual([w["agent"] for w in behind], ["vps"])
        self.assertEqual((behind[0]["detail"], behind[0]["fix"]),
                         ("The vault on vps has not taken the last update.",
                          "It updates itself within ten minutes; tell us if it does not."))
        said = behind[0]["detail"] + " " + behind[0]["fix"]
        for wrong in (second[:12], "/", "hubsetup", "join line", "git://"):
            self.assertNotIn(wrong, said)
        # The broker restarts on the new program, and its next report ends the warning.
        after = hashlib.sha256(b"# the vault, two\n").hexdigest()
        self.assertEqual(hub.vault_source(second), after)
        self.assertEqual(self.report("vps", revision=second, vault=dict(vault, broker_source=after))[0], 200)
        self.assertEqual([w for w in hub.health_view()["warnings"] if w["kind"] == "vault_behind"], [])

    def test_a_task_output_in_python_leaves_the_machine_current(self):
        """4 November 2026: Otto's T-124 delivered four .py files in outputs/T-124/, and every machine of the owner's
        fleet stood "behind" on System status, one block and one Update button each, while it ran the hub's code."""
        first = self.rev
        out = self.push_file("outputs/T-124/check.py", "print('a task output')\n", "otto delivered T-124")
        self.move_kit(out)
        self.assertTrue(hub.same_code(first, out))
        self.assertEqual(self.status(revision=first)[0], 200)
        self.assertEqual(self.row("vps")["update"]["state"], "current")
        self.assertEqual([w for w in hub.health_view()["warnings"]
                          if w.get("agent") == "vps" and w["kind"].startswith("machine_")], [])
        code = self.push_file("fleet.py", "# new code\n", "a release")       # code still counts
        self.move_kit(code)
        self.assertFalse(hub.same_code(first, code))

    def test_a_release_that_only_changes_place_py_leaves_the_machine_current(self):
        """place.py is the owner's own program, which no helper loads: lifecycle.OWNER_ONLY names it, and the hub's
        named the others and not it, so a release of it alone turned every machine "behind"."""
        first = self.rev
        second = self.push_file("place.py", "# the owner's place\n", "place")
        self.move_kit(second)
        self.assertTrue(hub.same_code(first, second))
        for name in ("place.py", "vault.py", "pilot.py", "verify.py", "selftest.py", "ui_fixture.py", "test_x.py",
                     "hub.py", "fleet.py", "lifecycle.py"):
            self.assertEqual(bool(hub.OWNER_ONLY.search(name)), bool(hub.lifecycle.OWNER_ONLY.search(name)), name)

    def test_update_refuses_only_an_unknown_agent(self):
        self.assertEqual(self.update("nobody")[0], 404)

    def test_the_hub_machine_updates_through_the_hub_like_a_worker(self):
        """The agent on the hub machine has its own home, its own checkout and its own user service, so the owner's
        Update button is the whole fix: ask, the helper reports waiting_idle, then the new revision. Before this,
        `/ui/health` warned that this machine was behind and the button it drew called a route that refused it."""
        self.report("manager", revision="a" * 40)
        self.assertEqual(self.row("manager")["update"]["state"], "behind")
        code, result = self.update("manager")
        self.assertEqual((code, result["state"], result["desired_revision"]), (200, "requested", self.rev))
        events = hub.q("SELECT * FROM events WHERE agent='manager' AND kind='update'")
        self.assertEqual(len(events), 1)
        self.assertEqual(json.loads(events[0]["extra"])["desired_revision"], self.rev)
        code, answer = self.report("manager", revision="a" * 40, state="waiting_idle",
                                   detail="Waits until no task session is open.")
        self.assertTrue(answer["update_requested"])
        self.assertEqual(self.row("manager")["update"]["state"], "waiting_idle")
        code, answer = self.report("manager", revision=self.rev)
        self.assertFalse(answer["update_requested"])
        self.assertEqual(self.row("manager")["update"]["state"], "current")

    def test_update_of_a_current_worker_does_nothing(self):
        self.status()
        code, result = self.update()
        self.assertEqual(result["state"], "current")
        self.assertEqual(hub.q("SELECT * FROM events WHERE kind='update'"), [])

    # ---- start the manager session (owner feature manager_start)
    def test_state_lists_the_manager_start_feature(self):
        self.assertIn("manager_start", self.request()[1]["ui_features"])

    def test_the_owner_asks_the_manager_s_helper_to_start_its_session(self):
        """The manager_down warning carries this, so that a screen which reports the session is down also puts it
        right. It asks and nothing more: the helper makes the start due and reads its own windows under the start
        lock, so a session that runs is left alone and a repeat changes nothing."""
        rid = str(uuid.uuid4())
        code, result = self.start_manager(request_id=rid)
        self.assertEqual((code, result["agent"], result["state"]), (200, "manager", "requested"))
        self.assertTrue(self.start_manager(request_id=rid)[1]["replayed"])
        events = hub.q("SELECT * FROM events WHERE agent='manager' AND kind='manager_start'")
        self.assertEqual([(e["text"], json.loads(e["extra"])) for e in events],
                         [("Start the manager session", {})])
        self.assertIsNone(events[0]["helper_ack"])              # it waits for the helper, as every helper event does

    def test_only_the_manager_has_a_standing_session_to_start(self):
        self.assertEqual(self.start_manager("vps")[0], 409)
        self.assertEqual(self.start_manager("nobody")[0], 404)
        self.assertEqual(hub.q("SELECT * FROM events WHERE kind='manager_start'"), [])

    # ---- team reload
    def test_team_reload_adds_a_worker_without_restart(self):
        new = self.push_team(lambda t: (t["agents"].__setitem__("vps2", {"role": "worker", "runtime": "codex",
                                                                         "machine": "vps2", "can": ["shell", "web"]}),
                                        t["addresses"].__setitem__("vps2", "100.99.1.2")))
        code, result = self.reload(new)
        self.assertEqual((code, result["added"], result["revision"]), (200, ["vps2"], new))
        self.assertIn("vps2", hub.agents())
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), new)
        code, state = self.request()
        self.assertIn("vps2", [a["name"] for a in state["agents"]])
        self.assertIn("vps2", [m["agent"] for m in self.machines()[1]["machines"]])

    def test_team_reload_refuses_an_invalid_team(self):
        new = self.push_team(lambda t: t["agents"].pop("manager"))
        code, result = self.reload(new)
        self.assertEqual(code, 422)
        self.assertIn("manager", hub.agents())
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), self.rev)

    def test_team_reload_refuses_an_unknown_revision(self):
        self.assertEqual(self.reload("b" * 40)[0], 404)

    def test_team_reload_refuses_to_change_a_busy_agent(self):
        hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES(?,?,?,?,?)",
                ("busy", "vps", "manager", "working", hub.now()))
        new = self.push_team(lambda t: t["addresses"].__setitem__("vps", "100.84.0.9"))
        code, result = self.reload(new)
        self.assertEqual(code, 409)
        self.assertIn("open tasks", result["error"])
        self.assertEqual(hub.TEAM["addresses"]["vps"], "127.0.0.3")

    def test_team_reload_refuses_a_checkout_with_local_changes(self):
        new = self.push_team(lambda t: t["addresses"].__setitem__("spare", "100.70.0.1"))
        (self.kit / "team.json").write_text("{}\n")
        self.assertEqual(self.reload(new)[0], 409)


class PlaceScript(unittest.TestCase):
    """place.sh, the host setup of Targets. Targets left the hub on 24 October 2026 with its /place routes (their 404
    is in test_access_refusals), and place.sh stays published with place.py."""

    def test_the_script_calls_no_route_that_the_hub_does_not_have(self):
        calls = []

        class Hub(http.server.BaseHTTPRequestHandler):
            def answer(self):
                calls.append((self.command, self.path))
                code, body = (200, b"{}") if self.path == "/health" else (404, b'{"error": "no such route"}')
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            do_GET = do_POST = answer

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Hub)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with tempfile.TemporaryDirectory(prefix="fleet-place-") as tmp:
            script = Path(tmp, "place.sh")       # with the hub's address in it, as GET /place served it
            script.write_text((Path(__file__).resolve().parent / "place.sh").read_text()
                              .replace("__FLEET_HUB__", "http://127.0.0.1:%d" % server.server_address[1]))
            stubs = Path(tmp, "bin")
            stubs.mkdir()
            (stubs / "id").write_text("#!/bin/sh\necho 0\n")         # root, as the line runs
            (stubs / "id").chmod(0o755)
            done = subprocess.run(["sh", str(script)], capture_output=True, text=True, timeout=60,
                                  env={"PATH": "%s:%s:/usr/bin:/bin" % (stubs, os.path.dirname(sys.executable)),
                                       "HOME": tmp, "TMPDIR": tmp, "FLEET_PLACE": "ABCD-EFGH"})
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("Founderizer did not give this host its setup.", done.stderr)
        self.assertEqual([call for call in calls if call[1].startswith("/place")], [])


if __name__ == "__main__":
    unittest.main()

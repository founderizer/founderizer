"""One OS user for each agent (the owner, 10 November 2026: "what needs to be fixed is how we ended up in this position,
and make it impossible!"; the owner's answers: one agent on each Mac, the Mac's desktop account is the agent's, and the
hub stops the work of agents that share one OS user). An agent's key, its session files and its sign-in live in the
home of the user that it runs as, so two agents of one user could each act as the other.

The rule of validate_team; each route that puts an agent on a machine; the machines' own readings and the faults the
hub keeps; the hold, its refusals and its quiet; the manager's way out; the vault broker's caller line; an old machine
after a move; and, as root on Linux only, the attack path with real users (RealUsers). No live team.json and no network;
each test's hub database is test_ui_api.quick."""
import contextlib
import copy
import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import fleet
import hub
import hubsetup
import vault
from leftovers import scratch_home
from test_servers import NEW, OTHER, OWNER, Servers, git, sha
from test_ui_api import OwnerAPI, session_bearer

SPARE = "127.0.0.11"            # an empty Linux server
OWN_USERS = {"scout": {"user": "fleet-scout", "uid": 1001}, "writer": {"user": "fleet-writer", "uid": 1002}}
MAC2 = "127.0.0.12"             # an empty Mac


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real home folder (leftovers.scratch_home)


def load_tests(loader, _tests, _pattern):
    """Each class's own tests only: the classes on Servers would run every test of test_servers again."""
    return unittest.TestSuite(cls(name) for cls in (Rule, Routes, Moves, Held, Readings, Broker, ServiceReading,
                                                    HelperHold, OldMachine, RealUsers, RealBroker)
                              for name in cls.__dict__ if name.startswith("test_"))


def team(**servers):
    """A team.json: a manager on the Linux server `base`, and the given servers {name: (kind, service user,
    [agents])}."""
    out = {"hub": {"machine": "hub", "port": 8765},
           "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "base": "127.0.0.3"},
           "servers": {"base": {"kind": "linux", "user": "fleet"}},
           "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "base", "can": []}}}
    for i, (name, (kind, user, names)) in enumerate(sorted(servers.items())):
        out["addresses"][name] = f"127.0.1.{i + 1}"
        out["servers"][name] = {"kind": kind, "user": user}
        for agent in names:
            out["agents"][agent] = {"role": "worker", "runtime": "claude", "machine": name, "can": ["shell", "web"]}
    return out


def refused(test, team_json, words, **kw):
    with test.assertRaises(ValueError) as caught:
        hub.validate_team(team_json, **kw)
    test.assertIn(words, str(caught.exception))


class Rule(unittest.TestCase):
    """The rule alone, with no running hub (hub.TEAM empty) and with one."""

    def setUp(self):
        self.addCleanup(setattr, hub, "TEAM", hub.TEAM)
        hub.TEAM = {}

    def test_the_os_user_of_an_agent_by_where_it_runs(self):
        t = team(box=("linux", "fleet", ["scout", "writer"]), mini=("mac", "macuser", ["desk"]))
        t["agents"]["writer"]["user"] = "fleet-old-name"
        t["addresses"]["old"] = "127.0.2.1"
        t["agents"]["legacy"] = {"role": "worker", "runtime": "codex", "machine": "old", "can": []}
        self.assertEqual(hub.agent_os_user(t, "scout"), ("box", "fleet-scout"))
        self.assertEqual(hub.agent_os_user(t, "writer"), ("box", "fleet-old-name"))      # kept after a rename
        self.assertEqual(hub.agent_os_user(t, "desk"), ("mini", "macuser"))               # the Mac's desktop account
        self.assertEqual(hub.agent_os_user(t, "legacy"), ("old", hub.OS_USER_UNKNOWN))   # no server service there
        t["agents"]["manager"].update(machine="hub", placed=False)
        self.assertIsNone(hub.agent_os_user(t, "manager"))                                # no server yet

    def test_each_breach_is_refused_and_own_users_pass(self):
        refused(self, team(mini=("mac", "macuser", ["desk", "coder"])), "would run as one user account on mini",
                shared_ok=set())
        t = team()
        t["addresses"]["old"] = "127.0.2.1"
        for name in ("one", "two"):
            t["agents"][name] = {"role": "worker", "runtime": "codex", "machine": "old", "can": []}
        refused(self, t, "would run as one user account on old", shared_ok=set())
        t = team(box=("linux", "fleet", ["scout", "writer"]))
        t["agents"]["writer"]["user"] = "fleet-scout"
        refused(self, t, "would run as one user account on box", shared_ok=set())
        refused(self, team(box=("linux", "fleet-scout", ["scout"])), "the user of the server service",
                shared_ok=set())
        t = team()
        t["agents"]["helper"] = {"role": "worker", "runtime": "codex", "machine": "hub", "can": []}
        refused(self, t, "the hub's own server", shared_ok=set())
        hub.validate_team(team(box=("linux", "fleet", ["scout", "writer", "coder"])), shared_ok=set())
        t = team()
        t["agents"]["manager"]["machine"] = "hub"                    # hub.sh's default: the manager beside the hub
        hub.validate_team(t, shared_ok=set())

    def test_outside_a_running_hub_a_file_keeps_its_own_breaches(self):
        """fleet.py verify, hubsetup.py and the installers read a fleet's file with no hub: a fleet from before the
        rule is not a broken file there, so verify's team check and a release's verify step stay as they were."""
        t = team(mini=("mac", "macuser", ["desk", "coder"]))
        hub.validate_team(t)
        self.assertIsNone(hub.team_problem(t))
        path = Path(tempfile.mkdtemp(prefix="fleet-os-users-")) / "team.json"
        self.addCleanup(shutil.rmtree, str(path.parent), True)
        path.write_text(json.dumps(t))
        self.assertEqual(hubsetup.read_team(str(path))["agents"].keys(), t["agents"].keys())

    def test_a_running_hub_keeps_its_breaches_and_takes_no_new_one(self):
        running = team(mini=("mac", "macuser", ["desk", "coder", "web"]))
        hub.TEAM = copy.deepcopy(running)
        other = copy.deepcopy(running)
        other["agents"]["desk"]["title"] = "Customer Support"
        hub.validate_team(other)                                     # a write about something else
        fewer = copy.deepcopy(running)
        del fewer["agents"]["web"]
        hub.validate_team(fewer)                                     # a remove
        moved = copy.deepcopy(running)
        moved["agents"]["web"]["machine"] = "base"
        hub.validate_team(moved)                                     # a move off the Mac
        more = copy.deepcopy(running)
        more["agents"]["new"] = dict(running["agents"]["desk"])
        refused(self, more, "would run as one user account on mini")
        self.assertIsNone(hub.team_problem(more))                    # the file is not broken: the hub holds them
        renamed = hub.renamed_team(running, "coder", "nova")
        hub.validate_team(renamed, shared_ok=hub.renamed_breaches("coder", "nova"))
        refused(self, renamed, "would run as one user account on mini")       # without the rename's own reference

    def test_a_pair_that_goes_together_to_another_user_account_is_new(self):
        """A pair of the running team passes only on the user name that it shares: two agents of an old machine, whose
        users the hub does not know, that go together to a Mac, or a Mac's pair that goes to one Linux user, is a new
        breach. The rename of a machine keeps every pair."""
        running = team(mini=("mac", "macuser", ["desk", "coder"]))
        running["addresses"]["old"] = "127.0.2.1"
        for name in ("one", "two"):
            running["agents"][name] = {"role": "worker", "runtime": "codex", "machine": "old", "can": []}
        hub.TEAM = copy.deepcopy(running)
        moved = copy.deepcopy(running)
        moved["agents"]["one"]["machine"] = moved["agents"]["two"]["machine"] = "mini"
        refused(self, moved, "would run as one user account on mini")
        linux = copy.deepcopy(running)
        linux["servers"]["box"] = {"kind": "linux", "user": "fleet"}
        linux["addresses"]["box"] = "127.0.2.2"
        for name in ("desk", "coder"):
            linux["agents"][name].update(machine="box", user="fleet-desk")
        refused(self, linux, "would run as one user account on box")
        hub.validate_team(hub.renamed_machine_team(running, "mini", "mini-2"))

    def test_a_file_of_another_shape_gets_the_words_of_its_shape(self):
        for broken in ({"agents": ["desk"]}, {"agents": {"desk": "worker"}},
                       dict(team(), servers=["base"]), dict(team(), hub="hub")):
            problem = hub.team_problem(broken)
            self.assertIsInstance(problem, str, broken)
            self.assertNotIn("Error", problem)

    def test_the_installer_refuses_two_agents_of_one_user(self):
        t = team(box=("linux", "fleet", ["scout", "writer"]))
        t["agents"]["writer"]["user"] = "fleet-scout"
        with self.assertRaisesRegex(hubsetup.Stop, "would share the OS user fleet-scout on box"):
            hubsetup.agent_users(t, "box", run=lambda script: (0, "", ""))

    def test_the_hubs_own_server_takes_held_agents_only_on_a_hub_that_takes_agents(self):
        """os_user_targets, the Linux servers that the manager names in its Needs-you options for a held group: never
        the group's own machine, and the hub's own server only on a hub whose own server takes agents (hub_shared).
        Never the manager's own server either, where it runs alone (owner API 1.336), except that hub's. The bug: a
        card offers the owner the manager's server, and the press is refused."""
        t = team(mini=("mac", "macuser", ["desk", "coder"]), box=("linux", "fleet", []))
        t["servers"]["hub"] = {"kind": "linux", "user": "fleet"}
        group = {"machine": "mini", "agents": ["desk", "coder"]}
        hub.TEAM = t
        with patch.object(hub, "service_user_agents", lambda names: []):
            # not base, the manager's own
            self.assertIn("Linux servers that can take them: box.", hub.os_user_targets(group))
            t["hub"]["shared"] = True
            self.assertIn("Linux servers that can take them: box, hub.", hub.os_user_targets(group))
            t["agents"]["manager"]["machine"] = "hub"
            self.assertIn("Linux servers that can take them: base, box, hub.", hub.os_user_targets(group))


class Routes(Servers):
    """Each route that puts an agent on a machine refuses what would share a user, before it writes anything."""

    def head(self):
        return git("--git-dir", str(self.root / "origin.git"), "rev-parse", "main")

    def done(self, server, job, source=NEW):
        status, answer = self.service(f"/server/{server}/jobs/{job}", {"state": "done", "step": "sign_in"},
                                      source=source)
        self.assertEqual(status, 200, answer)

    def test_add_agent_on_a_mac_with_an_agent_is_refused_and_the_mac_is_not_offered(self):
        self.joined("mini", "mac")
        status, receipt = self.add_agent("mini", "desk")
        self.assertEqual(status, 200, receipt)
        self.done("mini", receipt["job"])
        _, view = self.servers()
        self.assertEqual(view["mini"]["why"][:2], ["one_per_mac", "has_agent"])
        self.assertFalse(view["mini"]["available"])
        before = self.head()
        status, answer = self.add_agent("mini", "second")
        self.assertEqual(status, 409, answer)
        self.assertIn("A Mac runs one agent", answer["error"])
        self.assertEqual(self.head(), before)                        # nothing was written
        self.assertNotIn("second", hub.agents())

    def test_no_second_agent_beside_one_that_runs_as_the_service_user(self):
        self.joined("box", "linux", source=OTHER, user="fleet")
        status, receipt = self.add_agent("box", "scout", "codex")
        self.assertEqual(status, 200, receipt)
        self.done("box", receipt["job"], source=OTHER)
        hub.kv_set(hub.SERVICE_USER + "scout", "1")
        self.assertEqual(self.reading("box", source=OTHER, os_name="Ubuntu 24.04.1 LTS",
                                      features=[hub.INSTALL_KEY])[0], 200)
        status, answer = self.add_agent("box", "second", "codex")
        self.assertEqual(status, 409, answer)
        self.assertIn("runs as the user of the server service on box", answer["error"])
        self.assertIn("agent_not_ready", self.servers()[1]["box"]["why"])

    def test_a_server_whose_reading_names_the_other_system_takes_none(self):
        self.joined("box", "linux", source=OTHER, user="fleet")
        self.assertEqual(self.reading("box", source=OTHER, os_name="macOS 15.6")[0], 200)
        status, answer = self.add_agent("box", "scout", "codex")
        self.assertEqual(status, 409, answer)
        self.assertIn("joined as a Linux server, and its own reading says macOS", answer["error"])
        self.assertEqual(self.servers()[1]["box"]["why"], [])       # no new code: the app shows nothing new

    def test_the_existing_machine_route_is_ready_nowhere(self):
        status, view = self.request("/ui/team?db=test-generation", source=OWNER)
        self.assertEqual(status, 200, view)
        for machine, m in view["machines"].items():
            self.assertIn("shared_os_user", m["add_agent"]["missing"], machine)
            self.assertFalse(m["add_agent"]["ready"])

    def test_reload_refuses_a_commit_that_adds_a_pair(self):
        team_now = self.origin_team()
        team_now["servers"] = {"mac-studio": {"kind": "mac", "user": "macuser"}}
        team_now["agents"]["second"] = dict(team_now["agents"]["studio"], can=["shell", "web"])
        (self.kit / "team.json").write_text(json.dumps(team_now, indent=2) + "\n")
        git("commit", "-q", "-am", "a second agent on the Mac", cwd=self.kit)
        git("push", "-q", "origin", "HEAD:config", cwd=self.kit)
        rev = git("rev-parse", "HEAD", cwd=self.kit)
        git("reset", "-q", "--hard", "HEAD~1", cwd=self.kit)
        status, answer = self.owner("/ui/team/reload", revision=rev)
        self.assertEqual(status, 422, answer)
        self.assertIn("would run as one user account on mac-studio", answer["error"])

    def test_a_restore_keeps_the_copys_own_pairs(self):
        copy_team = team(mini=("mac", "macuser", ["desk", "coder"]))
        hub.TEAM = team()                                            # the new hub's own first team
        data = hub.restored_team({"config": {"team.json": json.dumps(copy_team)}})
        self.assertIn("coder", json.loads(data)["agents"])


class Moves(Servers):
    """move_agent between kinds and onto a Linux server that has agents; never onto a Mac that has one."""

    def setUp(self):
        super().setUp()
        self.joined("mini", "mac")
        self.add_and_done("mini", "desk", NEW)
        self.joined("box", "linux", source=OTHER, user="fleet")
        self.assertEqual(self.reading("box", source=OTHER, os_name="Ubuntu 24.04.1 LTS",
                                      features=[hub.INSTALL_KEY])[0], 200)       # it gives a new agent its key
        self.add_and_done("box", "scout", OTHER, runtime="codex")
        self.write_can("desk", ["shell", "web"])        # a Mac agent that needs no desktop, as most do

    def write_can(self, agent, can=None, **fields):
        team_now = self.origin_team()
        team_now["agents"][agent].update(fields, **({"can": can} if can is not None else {}))
        (self.kit / "team.json").write_text(json.dumps(team_now, indent=2) + "\n")
        git("commit", "-q", "-am", f"{agent} can {can}", cwd=self.kit)
        git("push", "-q", "origin", "HEAD", cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = json.loads(json.dumps(team_now))

    def add_and_done(self, server, agent, source, runtime="claude"):
        status, receipt = self.add_agent(server, agent, runtime)
        self.assertEqual(status, 200, receipt)
        status, answer = self.service(f"/server/{server}/jobs/{receipt['job']}",
                                      {"state": "done", "step": "sign_in"}, source=source)
        self.assertEqual(status, 200, answer)
        hub.q("INSERT OR REPLACE INTO agent_keys(agent,sha256,created,source) VALUES(?,?,?,'server')",
              (agent, sha(agent), hub.now()))

    def move(self, agent, server):
        return self.owner(f"/ui/team/agents/{agent}/move", base_sha256=self.team_sha(), server=server)

    def test_a_mac_agent_moves_to_a_linux_server_beside_another(self):
        status, receipt = self.move("desk", "box")
        self.assertEqual(status, 200, receipt)
        self.assertEqual(hub.agents()["desk"]["machine"], "box")
        self.assertEqual(hub.agent_os_user(hub.TEAM, "desk"), ("box", "fleet-desk"))
        job = hub.q1("SELECT * FROM server_jobs WHERE id=?", (receipt["job"],))
        self.assertEqual((job["server"], job["kind"], job["agent"]), ("box", "install", "desk"))

    def box_reads(self, browser="ready", memory=7000):
        """box's service reads its browser parts and the room of its user.slice (build plan 04, S1b and D6)."""
        row = hub.q1("SELECT data FROM server_status WHERE server='box'")
        data = dict(json.loads(row["data"]), browser={"state": browser},
                    room={"memory_max": memory << 20, "swap_max": None, "swap_total": 1910 << 20})
        hub.q("UPDATE server_status SET data=? WHERE server='box'", (json.dumps(data),))

    def test_a_desktop_agent_stays_on_a_mac(self):
        """A Mac's screen stays on a Mac. The Browser box moves to a Linux server that runs a browser for it (build plan
        04, S3): with the Shell box on (D2), on a supported system (D8), and with a place for it there (D6)."""
        self.write_can("desk", ["shell", "web", "browser", "screen"])
        status, answer = self.move("desk", "box")
        self.assertEqual(status, 409, answer)
        self.assertIn("uses a Mac's browser and screen", answer["error"])
        self.write_can("desk", ["shell", "web", "browser"])
        status, answer = self.move("desk", "box")           # box has sent no room yet: not the words of a full server
        self.assertEqual((status, answer.get("code"), answer.get("names")),
                         (409, "browser_room_unknown", {"server": "box", "agent": "Desk"}), answer)
        self.assertEqual(answer["error"], "box has not said how much memory it has for browsers: turn the Browser "
                                          "box of Desk off first, or move it to another server")
        # the manager's box stays on Linux and runs no browser task, so its move asks for no room: no place counts
        # a manager, and its move would be refused on a server of any size
        managed = json.loads(json.dumps(hub.TEAM))
        managed["agents"]["desk"]["role"] = "manager"
        self.assertIsNone(hub.browser_move_refusal(managed, "desk", "box"))
        self.box_reads(memory=5000)                         # one place for scout alone, none with both (D6)
        status, answer = self.move("desk", "box")
        self.assertEqual((status, answer.get("code"), answer.get("names")),
                         (409, "browser_no_place", {"server": "box", "agent": "Desk"}), answer)
        self.assertEqual(answer["error"], "box has no room for the browser of Desk: turn its Browser box off first, "
                                          "or move it to a server with more memory")
        self.assertEqual(hub.browser_move_refusal(hub.TEAM, "desk", "box").extra["code"], "browser_no_place")
        self.assertIsNone(hub.browser_move_refusal(managed, "desk", "box"))
        self.write_can("desk", ["web", "browser"])          # a closed agent hears its true reason first (D2), also
        self.box_reads(memory=1500)                         # where its smaller need leaves no place either
        status, answer = self.move("desk", "box")
        self.assertEqual((status, answer.get("code"), answer.get("names")),
                         (400, "browser_shell_off", {"agent": "Desk"}), answer)
        self.write_can("desk", ["shell", "web", "browser"])
        self.box_reads(browser="unsupported")
        status, answer = self.move("desk", "box")
        self.assertEqual((status, answer.get("code"), answer.get("names")),
                         (409, "browser_server", {"server": "box"}), answer)
        self.box_reads()
        status, receipt = self.move("desk", "box")
        self.assertEqual(status, 200, receipt)
        self.assertEqual(hub.agents()["desk"]["machine"], "box")

    def test_a_tick_of_the_browser_box_on_linux_is_refused_where_the_server_runs_none(self):
        """Build plan 04, D8 and D2, through the owner's settings route: a server whose service reads `unsupported`,
        and an agent whose Shell box is off, get no Browser box; the refusal has its code."""
        tick = lambda can: self.owner("/ui/team/agents/scout", base_sha256=self.team_sha(), can=can)    # noqa: E731
        self.box_reads(browser="unsupported")
        status, answer = tick(["shell", "web", "browser"])
        self.assertEqual((status, answer.get("code"), answer.get("names")),
                         (409, "browser_server", {"server": "box"}), answer)
        self.write_can("scout", ["web"])
        self.box_reads()
        status, answer = tick(["web", "browser"])
        self.assertEqual((status, answer.get("code")), (400, "browser_shell_off"), answer)
        status, answer = tick(["shell", "web", "browser"])
        self.assertEqual(status, 200, answer)
        self.assertIn("browser", self.origin_team()["agents"]["scout"]["can"])

    def test_no_move_onto_a_mac_that_runs_an_agent(self):
        status, answer = self.move("scout", "mini")
        self.assertEqual(status, 409, answer)
        self.assertIn("A Mac runs one agent", answer["error"])

    def test_a_move_takes_a_default_browser_with_it_and_reads_the_defaults_again(self):
        """Build plan 04 (D1, S3b): a browser that the Linux default gave never blocks a move; the move keeps the
        default's mark, so the default gives it again where there is room, and ends the done mark, but not his own
        removal."""
        self.write_can("scout", ["shell", "web", "browser"])
        hub.kv_set(hub.BROWSER_DEFAULT + "scout", hub.now())
        hub.kv_set("default_desktop:scout", 1)
        self.joined("mac2", "mac", source=MAC2)
        status, receipt = self.move("scout", "mac2")
        self.assertEqual(status, 200, receipt)
        self.assertNotIn("browser", self.origin_team()["agents"]["scout"]["can"])
        # a Mac's own default applies there, so the Linux default's mark ends
        self.assertEqual((hub.kv_get("default_desktop:scout"), hub.kv_get(hub.BROWSER_DEFAULT + "scout")), (None, None))
        hub.kv_set("default_desktop:desk", 2)
        self.joined("mac3", "mac", source="127.0.0.13")
        status, receipt = self.move("desk", "mac3")
        self.assertEqual((status, str(hub.kv_get("default_desktop:desk"))), (200, "2"), receipt)

    def test_a_default_browser_comes_again_on_the_linux_server_that_its_agent_moves_to(self):
        self.write_can("desk", ["shell", "web", "browser"], active=True)    # out of its setup: the default gives it one
        hub.kv_set(hub.BROWSER_DEFAULT + "desk", hub.now())       # a browser that a default gave: its mark
        status, receipt = self.move("desk", "box")
        self.box_reads()
        self.assertEqual(status, 200, receipt)
        self.assertNotIn("browser", self.origin_team()["agents"]["desk"]["can"])
        row = hub.q1("SELECT data FROM server_status WHERE server='box'")
        data = dict(json.loads(row["data"]), agents={"desk": {"user": "fleet-desk", "uid": 1003},
                                                      "scout": {"user": "fleet-scout", "uid": 1004}})
        hub.q("UPDATE server_status SET data=? WHERE server='box'", (json.dumps(data),))
        hub.TEAM = json.loads(json.dumps(self.origin_team()))
        hub.DEFAULT_ACCESS.update(at=0.0, retry={})
        hub.default_access_sweep(hub.now())
        self.assertIn("browser", self.origin_team()["agents"]["desk"]["can"])

    def test_a_linux_agent_moves_to_an_empty_mac_and_keeps_no_user(self):
        self.write_can("scout", user="fleet-old")
        self.joined("mac2", "mac", source=MAC2)
        status, receipt = self.move("scout", "mac2")
        self.assertEqual(status, 200, receipt)
        self.assertNotIn("user", self.origin_team()["agents"]["scout"])

    def shape(self, step):
        """The step of the slider "Your fleet's servers" that the owner chose last, as set_shape keeps it (None: no
        step)."""
        team_now = self.origin_team()
        if step:
            team_now["shape"] = {"step": step}
        else:
            team_now.pop("shape", None)
        (self.kit / "team.json").write_text(json.dumps(team_now, indent=2) + "\n")
        git("commit", "-q", "-am", f"the fleet's servers: {step}", cwd=self.kit)
        git("push", "-q", "origin", "HEAD", cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = json.loads(json.dumps(team_now))

    def test_the_manager_runs_alone_on_its_server(self):
        """The security read of 22 November 2026, its open point (owner API 1.336): an agent beside the manager that
        has, or gets, root on that server could read the manager's key and act as it. So at the step "each" the manager
        moves to no server where an agent runs, and no agent moves beside it. The step "2 servers", which the owner
        approved (the hub alone, the manager and every agent on a second server), takes agents beside it, and so does a
        fleet that keeps no step and runs an agent beside it already (the validator of 24 November 2026, M1). The bugs
        this catches: a move that puts an agent beside the manager at "each", an Add agent that the app offers there
        and the hub then refuses, and a fleet at "2 servers" that can add or move no agent."""
        hub.q("INSERT OR REPLACE INTO agent_keys(agent,sha256,created,source) VALUES('manager',?,?,'server')",
              (sha("manager"), hub.now()))
        self.shape("each")
        status, answer = self.move("manager", "box")
        self.assertEqual(status, 409, answer)
        self.assertIn("runs alone on its server, and Scout runs on box.", answer["error"])
        self.assertNotIn("manager_alone", self.servers()[1]["box"]["why"])
        self.write_can("manager", machine="box")        # a fleet from before the rule, by hand
        status, answer = self.move("desk", "box")
        self.assertEqual(status, 409, answer)
        self.assertIn("runs alone on its server, so no other agent runs on box beside it.", answer["error"])
        self.assertEqual(hub.agents()["desk"]["machine"], "mini")
        # the app offers no Add agent there: the servers view gives the manager's server its own code (owner API 1.336)
        box = self.servers()[1]["box"]
        self.assertEqual((box["available"], "manager_alone" in box["why"]), (False, True), box["why"])
        # the step "2 servers": Add agent and a move there, as the slider's own moves need
        self.shape("two")
        self.assertNotIn("manager_alone", self.servers()[1]["box"]["why"])
        status, receipt = self.move("desk", "box")
        self.assertEqual(status, 200, receipt)
        self.assertEqual(hub.agents()["desk"]["machine"], "box")
        self.assertEqual(self.service(f"/server/box/jobs/{receipt['job']}", {"state": "done", "step": "sign_in"},
                                      source=OTHER)[0], 200)
        hub.q("INSERT OR REPLACE INTO agent_keys(agent,sha256,created,source) VALUES('desk',?,?,'server')",
              (sha("desk"), hub.now()))                 # the service registers its key at the install, as add_and_done
        status, receipt = self.add_agent("box", "second", "codex")
        self.assertEqual(status, 200, receipt)
        # a fleet that keeps no step, and runs agents beside the manager already: as before
        self.shape(None)
        self.assertNotIn("manager_alone", self.servers()[1]["box"]["why"])
        self.assertIsNone(hub.placement_refusal(hub.TEAM, "box", "third", hub.server_agents("box")))

    def test_a_name_too_long_for_a_linux_user_is_refused(self):
        self.write_can("desk", user="fleet-" + "x" * 30)             # not a user name that Linux takes
        status, answer = self.move("desk", "box")
        self.assertEqual(status, 409, answer)
        self.assertIn("too long for a user account of its own", answer["error"])


class Held(Servers):
    """A fleet from before the rule: two agents on one Mac. The hub holds both: no session, no credential, no stall."""

    def setUp(self):
        super().setUp()
        self.joined("mini", "mac")
        status, receipt = self.add_agent("mini", "desk")
        self.assertEqual(status, 200, receipt)
        shared = self.origin_team()
        shared["agents"]["coder"] = dict(shared["agents"]["desk"])          # written by hand, before the rule
        (self.kit / "team.json").write_text(json.dumps(shared, indent=2) + "\n")
        git("commit", "-q", "-am", "a second agent on the Mac, by hand", cwd=self.kit)
        git("push", "-q", "origin", "HEAD", cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = json.loads(json.dumps(shared))
        for agent in ("desk", "coder"):
            hub.q("INSERT OR REPLACE INTO agent_keys(agent,sha256,created,source) VALUES(?,?,?,'owner')",
                  (agent, sha(agent), hub.now()))
        hub.os_user_refresh()

    def sweep(self):
        with hub.LOCK:
            hub.OS_USERS["at"] = 0
            hub.os_user_sweep(hub.now())

    def as_agent(self, agent, path, body=None, extra=None):
        headers = dict({"Content-Type": "application/json", "X-Fleet-Client": "test",
                        "Authorization": "Bearer " + agent},
                       **(extra or {}))
        return self.request(path, body, headers=headers, source=NEW)

    def test_both_are_held_and_the_manager_never(self):
        self.assertTrue(hub.os_user_held("desk") and hub.os_user_held("coder"))
        self.assertFalse(hub.os_user_held("manager"))
        self.assertEqual([g["why"] for g in hub.OS_USERS["groups"]], ["team"])

    def test_no_session_event_reaches_it_and_a_login_does(self):
        hub.emit("coder", "say", "a line for its session")
        hub.emit("coder", "login", "a sign-in", extra={"login": 1})
        status, answer = self.as_agent("coder", "/events/coder?delivery=1&after=0&wait=0")
        self.assertEqual(status, 200, answer)
        self.assertEqual(answer.get("hold"), "os_user")
        self.assertNotIn("say", [e["kind"] for e in answer["events"]])

    def test_the_cursor_stops_before_a_held_event(self):
        first = hub.emit("coder", "say", "held")
        hub.emit("coder", "withdraw", "a withdrawal", extra={"withdraw": 1})
        status, answer = self.as_agent("coder", "/events/coder?after=0&wait=0")
        self.assertEqual(status, 200, answer)
        self.assertLess(answer["last"], first)                     # it comes again when the hold ends
        self.assertEqual(answer["events"], [])

    def test_no_route_gives_it_a_credential_and_its_status_passes(self):
        for path, body in (("/helper/integrations/coder", {}), ("/helper/vault/coder/read", {}),
                           ("/helper/outputs/coder", {}), ("/helper/session/coder", {"kind": "chat", "generation":
                                                                                    hub.kv_get("db_id")}),
                           ("/helper/conversations/coder/1/start", {}),
                           ("/helper/mint/coder", {"tool": "crm", "task": "T-1", "attempt": 1})):
            status, answer = self.as_agent("coder", path, body)
            self.assertEqual((status, answer.get("auth")), (403, "os_user_shared"), path)
        status, answer = self.as_agent("coder", "/helper/vault/coder", {"job": 1, "kind": "withdraw"})
        self.assertNotEqual(answer.get("auth"), "os_user_shared")              # a login may leave
        status, answer = self.as_agent("coder", "/helper/status/coder", {"revision": hub.kit_revision(fresh=True),
                                                                         "os": {"name": "macOS 15.6"},
                                                                         "access": {"user": "macuser", "uid": 501}})
        self.assertEqual(status, 200, answer)

    def test_a_held_task_waits_with_its_words_and_is_not_stalled(self):
        """And a task whose session the hold ended in a turn beside the manager (owner API 1.336) waits the same way,
        then starts again by itself once its agent runs in a user account of its own. The bugs this catches: a cut
        turn that reads as failed or as a loss of the task's own (two of those in a row stop a task), or a cut task
        that never starts again."""
        tid = hub.ins("INSERT INTO tasks(owner,requester,title,state,created,attempt) VALUES('coder','manager','t',"
                      "'submitted',?,1)", (hub.now(),))
        with hub.LOCK:
            hub.liveness(hub.now())
            hub.liveness(hub.now())
        t = hub.q1("SELECT live_path, stalled_reason, stalled_since FROM tasks WHERE id=?", (tid,))
        self.assertEqual(t["stalled_reason"], hub.os_user_held_words("coder"))
        self.assertIsNone(t["stalled_since"])
        self.assertEqual(t["live_path"], t["stalled_reason"])
        # a turn of coder's that the hold cut beside the manager, after one loss of the task's own
        t0 = hub.now()
        cut = hub.ins("INSERT INTO tasks(owner,requester,title,state,created,attempt,started,restarts) VALUES('coder',"
                      "'manager','c','working',?,1,?,1)", (t0 - 900, t0 - 900))
        hub.ins("INSERT INTO events(agent,kind,task,text,created,extra,helper_ack) VALUES('coder','task',?,'go',?,?,?)",
                (cut, t0 - 900, json.dumps({"attempt": 1}), t0 - 890))
        hub.TEAM["agents"]["manager"]["machine"] = "mini"
        hub.os_user_refresh()
        with hub.LOCK:
            hub.liveness(t0)
        t = hub.q1("SELECT state, attempt, stalled_reason, stalled_since FROM tasks WHERE id=?", (cut,))
        self.assertEqual(tuple(t), ("working", 1, hub.os_user_held_words("coder"), None))
        # the owner moves the others out: coder runs alone, and its helper's list has no window of the cut task
        hub.TEAM["agents"]["manager"]["machine"] = "hub"
        hub.TEAM["agents"]["desk"]["machine"] = "vps"
        hub.os_user_refresh()
        self.assertFalse(hub.os_user_held("coder"))
        hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES('coder',?,?)",
              (json.dumps({"features": [hub.START_ONCE]}), t0))
        hub.know("coder")
        hub.q("UPDATE agents SET last_seen=?, alive='', alive_ts=? WHERE name='coder'", (t0, t0))
        with hub.LOCK:
            hub.liveness(t0)
        t = hub.q1("SELECT state, attempt, restarts, stalled_reason FROM tasks WHERE id=?", (cut,))
        self.assertEqual((t["state"], t["attempt"], t["restarts"]), ("working", 2, 0), dict(t))
        self.assertNotEqual(t["stalled_reason"], hub.os_user_held_words("coder"))
        self.assertIsNone(hub.kv_get(hub.HELD_CUT + str(cut)))

    def test_the_manager_hears_once_when_it_starts_and_once_when_it_ends(self):
        said = []
        with patch.object(hub, "emit", lambda agent, kind, text, *a, **k: said.append((agent, text)) or 1):
            with hub.LOCK:
                hub.OS_USERS["at"] = 0
                hub.os_user_sweep(hub.now())
                hub.OS_USERS["at"] = 0
                hub.os_user_sweep(hub.now())
            self.assertEqual(len([t for a, t in said if "run as one user account on mini" in t]), 1)
            del hub.TEAM["agents"]["coder"]
            hub.os_user_refresh()
            with hub.LOCK:
                hub.OS_USERS["at"] = 0
                hub.os_user_sweep(hub.now())
        self.assertTrue(any("held no more" in t for a, t in said))
        self.assertFalse(hub.os_user_held("desk"))

    def test_the_manager_tool_moves_only_a_held_agent_to_the_server_he_picked(self):
        self.joined("box", "linux", source=OTHER, user="fleet")
        with hub.LOCK:
            hub.OS_USERS["at"] = 0
            hub.os_user_sweep(hub.now() - 5)
        nid = hub.ins("INSERT INTO needs(title,why,todo,raised,by,options) VALUES('Where?','w','t',?,?,?)",
                      (hub.now(), "manager", json.dumps(["Move both to box", "Move both to box-2"])))

        def call(**a):
            return hub.t_move_agent("manager", dict({"request_id": str(uuid.uuid4())}, **a))
        with self.assertRaisesRegex(hub.ToolError, "not your own Needs-you item"):
            call(agent="coder", server="box", need=f"N-{nid}")                  # not answered yet
        hub.q("UPDATE needs SET answer='Move both to box-2', answered=?, chosen=1 WHERE id=?", (hub.now(), nid))
        with self.assertRaisesRegex(hub.ToolError, "names no server box"):
            call(agent="coder", server="box", need=f"N-{nid}")                  # box-2 is not box
        hub.q("UPDATE needs SET answer='Move both to box', chosen=0 WHERE id=?", (nid,))
        with patch.object(hub, "move_agent", lambda agent, body, by="owner": {"job": 7, "revision": "c" * 40}):
            self.assertIn("coder moves to box", call(agent="coder", server="box", need=f"N-{nid}").lower())
        with self.assertRaisesRegex(hub.ToolError, "You move yourself only while"):
            call(agent="manager", server="box", need=f"N-{nid}")
        with self.assertRaisesRegex(hub.ToolError, "has a user account of its own"):
            call(agent="vps", server="box", need=f"N-{nid}")            # not held: any move of it is the owner's


    def test_the_manager_in_a_group_is_never_held_and_the_others_stop_at_once(self):
        """The security read of 22 November 2026, claim 3 (owner API 1.336). The bug: a held agent's running session
        keeps working beside the manager. Its window closed only when its turn ended, so a turn of it beside the
        manager could read the manager's key and act as it. The manager keeps running (it moves the others), no route
        gives the others a credential, and the poll of each of them says hold_now, so that its helper ends its sessions
        at once, also in a turn. A group without the manager waits for its turns' ends, as before."""
        status, answer = self.as_agent("coder", "/events/coder?delivery=1&after=0&wait=0")
        self.assertEqual((status, answer.get("hold"), answer.get("hold_now")), (200, "os_user", None), answer)
        hub.TEAM["agents"]["manager"]["machine"] = "mini"       # the manager on the Mac too, from before the rule
        hub.os_user_refresh()
        self.assertIn("manager", hub.OS_USERS["groups"][0]["agents"])
        self.assertFalse(hub.os_user_held("manager"))
        self.assertTrue(hub.os_user_held("desk"))
        status, answer = self.as_agent("coder", "/events/coder?delivery=1&after=0&wait=0")
        self.assertEqual((status, answer.get("hold"), answer.get("hold_now")), (200, "os_user", True), answer)
        status, answer = self.as_agent("coder", "/helper/session/coder",
                                       {"kind": "chat", "generation": hub.kv_get("db_id")})
        self.assertEqual((status, answer.get("auth")), (403, "os_user_shared"))

    def test_a_lone_agent_of_the_service_user_is_held_by_nothing_and_a_pair_names_it(self):
        t = copy.deepcopy(hub.TEAM)
        t["servers"]["box"] = {"kind": "linux", "user": "fleet"}
        t["addresses"]["box"] = SPARE
        t["agents"]["writer"] = dict(t["agents"]["desk"], machine="box", user="fleet-writer")
        self.assertNotIn("service", [g["why"] for g in hub.os_user_faults(t)])
        t["agents"]["web"] = dict(t["agents"]["desk"], machine="box", user="fleet")
        group = next(g for g in hub.os_user_faults(t) if g["why"] == "service")
        self.assertEqual(group["agents"], ["writer", "web"])
        hub.TEAM = t
        self.assertIn("where Web runs as the user of the server service", hub.os_user_group_line(group, "manager"))

    def test_a_mac_whose_agents_report_one_uid_frees_the_one_that_stays(self):
        """Every helper of a Mac reports the desktop account's uid. team.json alone decides there: the readings keep no
        group of one agent, so once the others moved away the agent that stays is held no more."""
        for agent in ("desk", "coder"):
            status, answer = self.as_agent(agent, f"/helper/status/{agent}", {
                "revision": hub.kit_revision(fresh=True), "os": {"name": "macOS 15.6"},
                "access": {"user": "macuser", "uid": 501}})
            self.assertEqual(status, 200, answer)
        self.sweep()
        self.assertEqual(hub.os_user_kept(), [])
        self.assertTrue(hub.os_user_held("desk"))
        hub.TEAM["agents"]["coder"]["machine"] = "vps"          # its move: the hub deletes its reading
        hub.q("DELETE FROM machine_status WHERE agent='coder'")
        with hub.transaction():
            hub.os_user_drop("coder", "mini")
        self.sweep()
        self.assertFalse(hub.os_user_held("desk"))

    def test_one_needs_you_item_serves_each_move_of_a_group(self):
        """The agents move one at a time after one answer (the owner, 10 November 2026). Each agent's hold has its own
        start, which stays while it stays held, so the item that the manager raised after it serves each move; the
        manager hears of each agent's end once, and never of one that is still held."""
        self.joined("box", "linux", source=OTHER, user="fleet")
        hub.TEAM["agents"]["web"] = dict(hub.TEAM["agents"]["desk"])        # a third on the Mac, from before the rule
        hub.os_user_refresh()
        said = []

        def sweep():
            with patch.object(hub, "emit", lambda agent, kind, text, *a, **k: said.append(text) or 1):
                self.sweep()
        sweep()
        nid = hub.ins("INSERT INTO needs(title,why,todo,raised,by,options,answer,answered,chosen) "
                      "VALUES('Where?','w','t',?,'manager',?,'Move them to box',?,0)",
                      (hub.now(), json.dumps(["Move them to box"]), hub.now()))

        def moved(agent, body, by="owner"):
            hub.TEAM["agents"][agent]["machine"] = body["server"]
            hub.os_user_refresh()
            return {"job": 7, "revision": "c" * 40}

        def call(target):
            return hub.t_move_agent("manager", {"request_id": str(uuid.uuid4()), "agent": target, "server": "box",
                                                "need": f"N-{nid}"})
        with patch.object(hub, "move_agent", moved):
            self.assertIn("moves to box", call("web"))
            sweep()
            self.assertIn("moves to box", call("coder"))           # the same item, after its group changed
            sweep()
            hub.kv_set(hub.MOVED + "web", "mini")
            job = hub.ins("INSERT INTO server_jobs(server,kind,agent,runtime,state,created,updated) VALUES('box',"
                          "'install','web','claude','queued',?,?)", (hub.now(), hub.now()))
            self.assertIn("moves to box", call("web"))      # a repeat while the install of its move runs
            hub.q("UPDATE server_jobs SET state='failed' WHERE id=?", (job,))
            self.assertIn("goes again", call("web"))        # its install failed: the same item gives it again
            hub.q("UPDATE server_jobs SET state='done' WHERE id=?", (job,))
            with self.assertRaisesRegex(hub.ToolError, "has a user account of its own"):
                call("web")                                 # long after its move: nothing to do
        ends = [t.lower() for t in said if "held no more" in t]
        self.assertEqual(len(ends), 2, said)
        self.assertIn("web", ends[0])
        self.assertNotIn("desk", ends[0])
        self.assertTrue("coder" in ends[1] and "desk" in ends[1], ends)
        self.assertEqual(len([t for t in said if "run as one user account on mini" in t]), 1, said)

    def test_an_install_from_before_the_answer_is_no_move_of_this_item(self):
        """The repeat answer and a failed install's retry belong to the move that the item made: an install job from
        before the owner's answer is another move's, so the call goes through the checks of the hold."""
        self.joined("box", "linux", source=OTHER, user="fleet")
        hub.TEAM["agents"]["coder"]["machine"] = "box"               # the owner moved it there earlier
        hub.os_user_refresh()
        hub.kv_set(hub.MOVED + "coder", "mini")
        hub.ins("INSERT INTO server_jobs(server,kind,agent,runtime,state,created,updated) VALUES('box','install',"
                "'coder','claude','failed',?,?)", (hub.now() - 60, hub.now() - 60))
        nid = hub.ins("INSERT INTO needs(title,why,todo,raised,by,options,answer,answered,chosen) "
                      "VALUES('Where?','w','t',?,'manager',?,'Move it to box',?,0)",
                      (hub.now(), json.dumps(["Move it to box"]), hub.now()))
        with self.assertRaisesRegex(hub.ToolError, "has a user account of its own"):
            hub.t_move_agent("manager", {"request_id": str(uuid.uuid4()), "agent": "coder", "server": "box",
                                         "need": f"N-{nid}"})

    def test_a_held_worker_wants_no_owner_chat(self):
        yes = lambda *a, **k: True          # noqa: E731
        with patch.object(hub, "agent_active", yes), patch.object(hub, "owner_chat", yes), \
                patch.object(hub, "signed_in_now", yes):
            status, answer = self.as_agent("coder", "/events/coder?delivery=1&after=0&wait=0")
            self.assertEqual((status, answer["chat"]["warm"]), (200, False), answer)
            with patch.object(hub, "os_user_held", lambda agent: False):
                status, answer = self.as_agent("coder", "/events/coder?delivery=1&after=0&wait=0")
            self.assertTrue(answer["chat"]["warm"], answer)
            with patch.object(hub, "helper_features", lambda agent: {"chat_warm"}):
                self.assertIsNone(hub.chat_ready_now("coder", ""))          # the app draws its chat, not a setup
                with patch.object(hub, "os_user_held", lambda agent: False):
                    self.assertIs(hub.chat_ready_now("coder", ""), False)

    def test_a_task_event_waits_while_it_is_held_and_comes_after(self):
        tid = hub.ins("INSERT INTO tasks(owner,requester,title,state,created,attempt) VALUES('coder','manager','t',"
                      "'submitted',?,1)", (hub.now(),))
        eid = hub.emit("coder", "task", "a task", task=tid)
        status, answer = self.as_agent("coder", "/events/coder?delivery=1&after=0&wait=0")
        self.assertNotIn(eid, [e["id"] for e in answer["events"]], answer)
        with patch.object(hub, "os_user_held", lambda agent: False):
            status, answer = self.as_agent("coder", "/events/coder?delivery=1&after=0&wait=0")
        self.assertIn(eid, [e["id"] for e in answer["events"]], answer)

    def test_check_now_runs_no_check_of_a_held_agent(self):
        trigger = {"id": 1, "check_spec": json.dumps({"kind": "command"}), "agent": "coder", "created_by": "owner",
                   "revision": 1}
        with patch.object(hub.wakeups, "check_known", lambda spec: True), \
                patch.object(hub, "runner_of", lambda t: "coder"):
            with self.assertRaisesRegex(hub.Refusal, "runs no check until"):
                hub.check_now(trigger, hub.now())

    def test_a_renamed_agent_stays_held_and_the_manager_hears_nothing_new(self):
        job = hub.q1("SELECT id FROM server_jobs WHERE server='mini' ORDER BY id DESC LIMIT 1")["id"]
        self.assertEqual(self.service(f"/server/mini/jobs/{job}", {"state": "done", "step": "sign_in"})[0], 200)
        said = []
        with patch.object(hub, "emit", lambda agent, kind, text, *a, **k: said.append(text) or 1):
            self.sweep()
            status, receipt = self.owner("/ui/team/agents/coder/rename", base_sha256=self.team_sha(), name="nova")
            self.assertEqual(status, 200, receipt)
            self.assertTrue(hub.os_user_held("nova"))
            self.sweep()
        self.assertEqual(len([t for t in said if "run as one user account" in t]), 1, said)
        self.assertFalse([t for t in said if "held no more" in t], said)
        self.assertIsNotNone(hub.os_user_since("nova"))

    def test_the_watchdogs_leave_a_held_task_alone(self):
        tid = hub.ins("INSERT INTO tasks(owner,requester,title,state,created,attempt) VALUES('coder','manager','t',"
                      "'working',?,1)", (hub.now(),))
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))
        self.assertEqual(hub.live_reason(t, None), ("os_user", hub.os_user_held_words("coder")))
        self.assertIn("shares its user account with another agent", hub.fresh_refusal(t, 1))
        with self.assertRaisesRegex(hub.ToolError, "so the hub holds its work"), \
                patch.object(hub, "agent_active", lambda agent: True):
            hub.t_restart_task("manager", {"request_id": str(uuid.uuid4()), "task_id": f"T-{tid}", "reason": "stuck",
                                           "expected_attempt": 1})

    def test_a_due_rule_of_a_held_agent_starts_nothing_until_the_hold_ends(self):
        t0 = hub.now()
        rule = hub.ins("INSERT INTO triggers(agent,state,revision,schedule,task,late_minutes,max_tasks_per_day,anchor,"
                       "next_due,created,updated,request_id) VALUES('coder','active',1,?,?,30,4,?,?,?,?,'t-1')",
                       (json.dumps({"kind": "every", "minutes": 60}),
                        json.dumps({"title": "Look", "details": "Look.", "done_when": "Looked.", "needs": "none",
                                    "goal_id": None}), t0 - 7200, t0 - 60, t0, t0))
        with hub.LOCK:
            hub.trigger_sweep(t0)
        self.assertIsNone(hub.q1("SELECT 1 FROM trigger_runs WHERE trigger_id=?", (rule,)))
        self.assertEqual(hub.q1("SELECT next_due FROM triggers WHERE id=?", (rule,))["next_due"], t0 - 60)
        with patch.object(hub, "os_user_held", lambda agent: False), hub.LOCK:
            hub.trigger_sweep(t0)
        self.assertIsNotNone(hub.q1("SELECT 1 FROM trigger_runs WHERE trigger_id=?", (rule,)))

    def test_a_waiting_check_run_of_a_held_agent_is_not_sent(self):
        t0 = hub.now()
        task = json.dumps({"title": "Look", "details": "Look.", "done_when": "Looked.", "needs": "none",
                           "goal_id": None})
        rule = hub.ins("INSERT INTO triggers(agent,state,revision,schedule,check_spec,task,late_minutes,"
                       "max_tasks_per_day,anchor,next_due,created,updated,request_id) VALUES('coder','active',1,?,?,?,"
                       "30,4,?,?,?,?,'t-2')", (json.dumps({"kind": "every", "minutes": 60}),
                                              json.dumps({"kind": "command"}), task, t0 - 7200, t0 + 3600, t0, t0))
        run = hub.ins("INSERT INTO trigger_runs(trigger_id,revision,due,state,created,retry_at) "
                      "VALUES(?,1,?,'waiting',?,?)", (rule, t0 - 60, t0 - 60, t0 - 1))
        sent = []
        with patch.object(hub, "send_check", lambda r, now: sent.append(r["id"])), hub.LOCK:
            hub.trigger_sweep(t0)
            self.assertEqual(sent, [])
            with patch.object(hub, "os_user_held", lambda agent: False):
                hub.trigger_sweep(t0)
        self.assertEqual(sent, [run])

    def test_the_macs_own_setup_adds_no_second_agent(self):
        """A Mac's first agent comes from its own setup (mac_setup_add): on a Mac that runs an agent it stops with the
        rule's words and adds nothing."""
        job = hub.q1("SELECT id FROM server_jobs WHERE server='mini' ORDER BY id DESC LIMIT 1")["id"]
        self.assertEqual(self.service(f"/server/mini/jobs/{job}", {"state": "done", "step": "sign_in"})[0], 200)
        stopped = []
        row = {"server": "mini", "agent": "web", "runtime": "claude", "reported": 0,
               "tries": hub.MAC_SETUP_READINGS - 1}
        with patch.object(hub, "mac_setup_stop", lambda r, words: stopped.append(words)), \
                patch.object(hub, "mac_setup_set", lambda *a, **k: None):
            hub.mac_setup_add(row, hub.now())
        self.assertEqual(len(stopped), 1, stopped)
        self.assertIn("A Mac runs one agent", stopped[0])
        self.assertNotIn("web", hub.agents())

    def test_a_manager_of_the_hubs_own_user_is_warned_and_told_once(self):
        hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES('manager',?,?)",
              (json.dumps({"access": {"user": "hubuser", "uid": os.getuid()}}), hub.now()))
        self.assertTrue(hub.manager_hub_user())
        self.assertIn("manager_hub_user", [w["kind"] for w in hub.health_view()["warnings"]])
        said = []
        with patch.object(hub, "emit", lambda agent, kind, text, *a, **k: said.append(text) or 1):
            self.sweep()
            self.sweep()
        self.assertEqual(len([t for t in said if "You run as the hub's own user account" in t]), 1, said)
        self.assertIsNotNone(hub.os_user_since("manager"))

    def test_the_manager_hears_when_the_install_of_a_moved_agent_ends(self):
        said = []
        with patch.object(hub, "emit", lambda agent, kind, text, *a, **k: said.append(text) or 1):
            self.sweep()                # the floor: the ends of older jobs wait for nobody
            hub.ins("INSERT INTO server_jobs(server,kind,agent,runtime,state,created,updated) VALUES('box','install',"
                    "'coder','claude','done',?,?)", (hub.now(), hub.now()))
            hub.kv_set(hub.MOVED + "coder", "mini")
            self.sweep()
            self.sweep()
        self.assertEqual(len([t for t in said if "after its move ended: it runs there" in t]), 1, said)

    def test_a_ticked_option_names_its_server_as_a_whole_name(self):
        nid = hub.ins("INSERT INTO needs(title,why,todo,raised,by,options,multi,answer,answered,chose) "
                      "VALUES('Where?','w','t',?,'manager',?,1,'x',?,?)",
                      (hub.now(), json.dumps(["Move Web to box-10", "Move Coder to box"]), hub.now(), json.dumps([0])))
        self.assertFalse(hub.need_names_server(hub.q1("SELECT * FROM needs WHERE id=?", (nid,)), "box"))
        self.assertTrue(hub.need_names_server(hub.q1("SELECT * FROM needs WHERE id=?", (nid,)), "box-10"))
        hub.q("UPDATE needs SET chose=? WHERE id=?", (json.dumps([0, 1]), nid))
        self.assertTrue(hub.need_names_server(hub.q1("SELECT * FROM needs WHERE id=?", (nid,)), "box"))


class Readings(Servers):
    """The machines prove it: faults from the readings, which the hub keeps once seen."""

    def setUp(self):
        super().setUp()
        self.joined("box", "linux", source=OTHER, user="fleet")
        self.assertEqual(self.reading("box", source=OTHER, os_name="Ubuntu 24.04.1 LTS",
                                      features=[hub.INSTALL_KEY])[0], 200)
        for agent in ("scout", "writer"):
            status, receipt = self.add_agent("box", agent, "codex")
            self.assertEqual(status, 200, receipt)
            self.service(f"/server/box/jobs/{receipt['job']}", {"state": "done", "step": "sign_in"}, source=OTHER)
            hub.q("INSERT OR REPLACE INTO agent_keys(agent,sha256,created,source) VALUES(?,?,?,'server')",
                  (agent, sha(agent), hub.now()))

    def server_says(self, agents):
        status, answer = self.service("/server/box/status", {
            "revision": hub.kit_revision(fresh=True), "os": {"name": "Ubuntu 24.04.1 LTS"},
            "runtimes": {"codex": {"version": None, "signed_in": None}, "claude": {"version": None, "signed_in": None}},
            "access": {"user": "fleet", "uid": 1000}, "agents": agents}, source=OTHER)
        self.assertEqual(status, 200, answer)

    def sweep(self):
        with hub.LOCK:
            hub.OS_USERS["at"] = 0
            hub.os_user_sweep(hub.now())

    def test_own_users_are_no_fault(self):
        self.server_says(OWN_USERS)
        self.sweep()
        self.assertFalse(hub.os_user_held("scout") or hub.os_user_held("writer"))

    def test_one_uid_on_the_server_holds_both_and_stays_held(self):
        self.server_says({"scout": {"user": "fleet", "uid": 1000}, "writer": {"user": "fleet", "uid": 1000}})
        self.sweep()
        self.assertTrue(hub.os_user_held("scout") and hub.os_user_held("writer"))
        self.server_says(OWN_USERS)
        self.sweep()
        self.assertTrue(hub.os_user_held("scout"), "a later reading does not end a kept fault")
        with hub.transaction():
            hub.os_user_drop("writer")                                      # it moved away
        hub.os_user_refresh()
        self.assertFalse(hub.os_user_held("scout"))

    def test_a_service_user_agent_holds_its_siblings(self):
        self.server_says({"scout": {"user": "fleet", "uid": 1000}, "writer": {"user": "fleet-writer", "uid": 1002}})
        self.sweep()
        self.assertEqual(hub.kv_get(hub.SERVICE_USER + "scout"), "1")
        self.assertTrue(hub.os_user_held("writer"))

    def test_a_helper_that_names_another_agents_uid_holds_only_itself(self):
        self.server_says(OWN_USERS)
        hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES('writer',?,?)",
              (json.dumps({"access": {"user": "fleet-scout", "uid": 1001}}), hub.now()))
        self.sweep()
        self.assertTrue(hub.os_user_held("writer"))
        self.assertFalse(hub.os_user_held("scout"))

    def test_the_broker_line_of_another_user_holds_only_that_agent(self):
        headers = {"Content-Type": "application/json", "X-Fleet-Client": "test", "Authorization": "Bearer writer",
                   "X-Fleet-Caller-User": "fleet-scout"}
        status, answer = self.request("/helper/vault/writer/read", {}, headers=headers, source=OTHER)
        self.assertEqual((status, answer.get("auth")), (403, "os_user"))
        self.assertTrue(hub.os_user_held("writer"))
        self.assertFalse(hub.os_user_held("scout"))
        headers.update({"Authorization": "Bearer scout", "X-Fleet-Caller-User": "fleet-scout"})
        status, answer = self.request("/helper/vault/scout/read", {}, headers=headers, source=OTHER)
        self.assertNotIn(answer.get("auth"), ("os_user", "os_user_shared"))
        del headers["X-Fleet-Caller-User"]
        hub.TEAM["agents"]["scout"]["vault"] = "file"       # its helper reads its own vault: no broker, no line
        status, answer = self.request("/helper/vault/scout/read", {}, headers=headers, source=OTHER)
        self.assertNotIn(answer.get("auth"), ("os_user", "os_user_shared"))
        hub.TEAM["agents"]["scout"]["vault"] = "broker"
        status, answer = self.request("/helper/vault/scout/read", {}, headers=headers, source=OTHER)
        self.assertEqual((status, answer.get("auth")), (403, "os_user"))        # once seen, the broker's line is needed

    def test_the_service_users_line_passes_only_for_an_agent_alone(self):
        headers = {"Content-Type": "application/json", "X-Fleet-Client": "test", "Authorization": "Bearer writer",
                   "X-Fleet-Caller-User": "fleet"}
        status, answer = self.request("/helper/vault/writer/read", {}, headers=headers, source=OTHER)
        self.assertEqual((status, answer.get("auth")), (403, "os_user"))            # scout is beside it
        self.assertTrue(hub.os_user_held("writer"))
        self.assertIn("vault call", hub.os_user_hold_reason("writer"))

    def test_an_old_machine_whose_agents_report_one_uid_holds_both_until_one_leaves(self):
        """A machine with no server service (vps runs vps and lead): their own readings are all that the hub has. One
        uid holds both; when one leaves, the groups that compared the one that stays with it go, and it is free."""
        for agent in ("vps", "lead"):
            hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES(?,?,?)",
                  (agent, json.dumps({"access": {"user": "fleet", "uid": 1000}}), hub.now()))
        self.sweep()
        self.assertTrue(hub.os_user_held("vps") and hub.os_user_held("lead"))
        self.assertIn("readings", [g["why"] for g in hub.os_user_kept()])
        left = hub.os_user_uid("lead", "vps")                 # its move: before the hub deletes its reading
        hub.TEAM["agents"]["lead"]["machine"] = "box"
        hub.q("DELETE FROM machine_status WHERE agent='lead'")
        with hub.transaction():
            hub.os_user_drop("lead", "vps", left)
        self.sweep()
        self.assertFalse(hub.os_user_held("vps"))

    def test_the_owners_move_frees_the_one_that_stays_on_an_old_machine(self):
        """The same through the owner's move: the hub reads the uid of the agent that leaves before its reading goes."""
        for agent in ("vps", "lead"):
            hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES(?,?,?)",
                  (agent, json.dumps({"access": {"user": "fleet", "uid": 1000}}), hub.now()))
            hub.q("INSERT OR REPLACE INTO agent_keys(agent,sha256,created,source) VALUES(?,?,?,'server')",
                  (agent, sha(agent), hub.now()))
        self.sweep()
        self.assertTrue(hub.os_user_held("vps"))
        status, receipt = self.owner("/ui/team/agents/lead/move", base_sha256=self.team_sha(), server="box")
        self.assertEqual(status, 200, receipt)
        self.sweep()
        self.assertFalse(hub.os_user_held("vps"))

    def test_an_agent_that_leaves_ends_no_group_that_did_not_compare_it(self):
        """A group of one that a reading made stays when another agent leaves its machine, unless it compared its agent
        with the one that left; and no later reading of its own ends it (kept once seen)."""
        hub.TEAM["agents"]["third"] = dict(hub.TEAM["agents"]["scout"])
        self.server_says(dict(OWN_USERS, third={"user": "fleet-third", "uid": 1003}))
        hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES('writer',?,?)",
              (json.dumps({"access": {"user": "fleet-scout", "uid": 1001}}), hub.now()))
        self.sweep()
        self.assertTrue(hub.os_user_held("writer"))
        with hub.transaction():
            hub.os_user_drop("third", "box", hub.os_user_uid("third", "box"))       # third moves away
        hub.TEAM["agents"]["third"]["machine"] = "vps"
        hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES('writer',?,?)",
              (json.dumps({"access": {"user": "fleet-writer", "uid": 1002}}), hub.now()))
        self.sweep()
        self.assertTrue(hub.os_user_held("writer"))

    def test_a_server_whose_reading_names_the_other_system_holds_its_agents(self):
        status, answer = self.service("/server/box/status", {"revision": hub.kit_revision(fresh=True),
                                                              "os": {"name": "macOS 15.6"},
                                                              "access": {"user": "fleet", "uid": 1000}}, source=OTHER)
        self.assertEqual(status, 200, answer)
        said = []
        with patch.object(hub, "emit", lambda agent, kind, text, *a, **k: said.append(text) or 1):
            self.sweep()
        self.assertTrue(hub.os_user_held("scout") and hub.os_user_held("writer"))
        self.assertIn("another system", hub.os_user_hold_reason("scout"))
        line = next(text for text in said if "joined as one kind of machine" in text)
        self.assertNotIn("join line", line)
        self.assertIn("move_agent(agent, server, need)", line)

    def test_an_agent_that_runs_nowhere_yet_is_no_service_user(self):
        """Its install failed before its user was made: the service reports no user for it (server.py agent_users)."""
        self.server_says({"scout": {"user": None, "uid": None}, "writer": {"user": "fleet-writer", "uid": 1002}})
        self.sweep()
        self.assertIsNone(hub.kv_get(hub.SERVICE_USER + "scout"))
        self.assertFalse(hub.os_user_held("scout") or hub.os_user_held("writer"))

    def test_the_server_reading_keeps_the_agent_users(self):
        self.server_says({"scout": {"user": "fleet-scout", "uid": 1001}})
        data = json.loads(hub.q1("SELECT data FROM server_status WHERE server='box'")["data"])
        self.assertEqual(data["agents"], {"scout": {"user": "fleet-scout", "uid": 1001}})
        status, answer = self.service("/server/box/status", {"revision": hub.kit_revision(fresh=True),
                                                              "os": {"name": "Ubuntu 24.04.1 LTS"},
                                                              "access": {"user": "fleet", "uid": True}}, source=OTHER)
        self.assertEqual(status, 400, answer)


class Broker(unittest.TestCase):
    """vault.py names the caller's OS user, read from the socket's peer uid, on each hub call for that request."""

    def test_each_hub_call_of_a_request_carries_the_callers_user(self):
        seen = []

        class Opener:
            def open(self, request, timeout):
                seen.append(dict(request.header_items()))
                raise OSError("no hub here")
        me = pwd.getpwuid(os.getuid()).pw_name
        with patch.object(vault, "NO_PROXY", Opener()), patch.object(vault, "LocalStore", lambda conf: None):
            with self.assertRaises(vault.Refused):
                vault.handle({"agent": None, "worker_uid": os.getuid(), "hub": "http://127.0.0.1:9", "age_key": None},
                             json.dumps({"v": vault.PROTOCOL, "op": "read", "agent": "scout", "agent_key": "k" * 43}),
                             os.getuid())
        self.assertTrue(seen)
        self.assertEqual({h.get("X-fleet-caller-user") for h in seen}, {me})


class ServiceReading(unittest.TestCase):
    """server.py's map of its agents' users: an agent whose user is not made yet runs nowhere, never as the service."""

    def test_each_agent_runs_as_its_own_user_as_the_service_or_nowhere(self):
        import server
        home = Path(tempfile.mkdtemp(prefix="fleet-service-"))
        self.addCleanup(shutil.rmtree, str(home), True)
        (home / "fleet-old").mkdir()                        # an agent from before the per-agent move
        (home / "fleet-server").mkdir()                     # this service's own checkout
        svc = server.Service.__new__(server.Service)
        svc.platform, svc.home, svc.kit = "linux", str(home), str(home / "fleet-server")
        svc.agents_here = lambda: [("new", {}), ("old", {}), ("own", {}), ("server", {})]
        svc.agent_user = lambda name, named=None: "fleet-own" if name == "own" else None
        svc.users = lambda user: (2001, "/home/fleet-own") if user == "fleet-own" else None
        me = pwd.getpwuid(os.getuid()).pw_name
        self.assertEqual(svc.agent_users(), {"new": {"user": None, "uid": None},
                                             "old": {"user": me, "uid": os.getuid()},
                                             "own": {"user": "fleet-own", "uid": 2001},
                                             "server": {"user": None, "uid": None}})
        svc.platform = "darwin"
        self.assertEqual(svc.agent_users()["new"], {"user": me, "uid": os.getuid()})      # a Mac's one agent


class HelperHold(unittest.TestCase):
    """fleet.Helper.close_held: a held agent's windows close once their turns end, with their processes; beside the
    manager (the poll's hold_now, owner API 1.336) at once, also in a turn."""

    def test_only_idle_windows_of_its_sessions_close(self):
        """The bug of hold_now: a held agent's running session keeps working beside the manager, whose key it can
        read, until its turn ends."""
        h = fleet.Helper.__new__(fleet.Helper)
        h.session, h.typed_at = "fleet-scout", {"T-3": 200.0}
        h.hub_turns = ({"T-2"}, 100.0)
        h.look_known = lambda: ["T-1", "T-2", "T-3", "C-4", "owner-chat", "notes"]
        h.working = lambda target: target.endswith("=C-4")
        h.task_work = lambda window, text, keep_runtime=False: {"pid"}
        quiet, killed = [], []
        h.quiesce = lambda window, text, keep_runtime=False, also=None: quiet.append(window)
        h.say = lambda text: None
        with patch.object(fleet, "tmux", lambda *a, **k: killed.append(a)):
            h.close_held()
        self.assertEqual([a[2] for a in killed if a[0] == "kill-window"],
                         ["=fleet-scout:=T-1", "=fleet-scout:=owner-chat"])
        self.assertEqual(quiet, ["T-1", "owner-chat"])
        del killed[:], quiet[:]
        with patch.object(fleet, "tmux", lambda *a, **k: killed.append(a)):
            h.close_held(now=True)
        self.assertEqual([a[2] for a in killed if a[0] == "kill-window"],
                         [f"=fleet-scout:={w}" for w in ("T-1", "T-2", "T-3", "C-4", "owner-chat")])
        self.assertEqual(quiet, ["T-1", "T-2", "T-3", "C-4", "owner-chat"])


class OldMachine(unittest.TestCase):
    """fleet.Helper.moved_away on the machine that the agent left: its key and its own session files go before its
    service, never a folder, and its LaunchAgent is the real one in ~/Library/LaunchAgents."""

    def test_the_key_and_session_files_go_first_and_the_real_plist(self):
        home = Path(tempfile.mkdtemp(prefix="fleet-moved-"))
        self.addCleanup(shutil.rmtree, str(home), True)
        fleet_home, sessions = home / ".fleet", home / ".fleet" / "sessions"
        sessions.mkdir(parents=True)
        (fleet_home / "agent-scout.key").write_text("k")
        (fleet_home / "agent-other.key").write_text("k")
        (sessions / "scout.T-1.ab.env").write_text("x")
        (sessions / "scout-2.T-1.ab.env").write_text("x")       # another agent's, whose name starts the same way
        (sessions / "scout.dir").mkdir()
        order = []
        h = fleet.Helper.__new__(fleet.Helper)
        h.agent, h.session = "scout", "fleet-scout"
        real_remove = os.remove
        with patch.object(fleet, "HOME", str(fleet_home)), patch.object(fleet, "SESSIONS", str(sessions)), \
                patch.dict(os.environ, {"HOME": str(home)}), \
                patch.object(fleet, "tmux", lambda *args, **kw: order.append(("tmux",) + args)), \
                patch.object(fleet.sys, "platform", "darwin"), \
                patch.object(fleet.subprocess, "run", lambda argv, **kw: order.append(tuple(argv))), \
                patch.object(fleet.os, "remove", lambda path: (order.append(("rm", path)), real_remove(path))[1]
                             if os.path.exists(path) else order.append(("rm", path))):
            h.moved_away()
        removed = [p for kind, p, *rest in [o + ("",) for o in order] if kind == "rm"]
        self.assertIn(str(fleet_home / "agent-scout.key"), removed)
        self.assertIn(str(sessions / "scout.T-1.ab.env"), removed)
        self.assertNotIn(str(sessions / "scout-2.T-1.ab.env"), removed)
        self.assertTrue((fleet_home / "agent-other.key").exists() and (sessions / "scout.dir").is_dir())
        self.assertIn(str(home / "Library" / "LaunchAgents" / "com.agentfleet.scout.plist"), removed)
        bootout = next(i for i, o in enumerate(order) if o[:2] == ("launchctl", "bootout"))
        self.assertTrue(all(i < bootout for i, o in enumerate(order) if o[0] == "rm"))


@unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0 and shutil.which("tmux"),
                     "the attack path with real users runs as root on Linux (a throwaway container)")
class RealUsers(unittest.TestCase):
    """The attack path of the brief, with real OS users: one agent's user cannot read another agent's key or session
    files, cannot reach its tmux server, and the vault refuses the other agent's key from this agent's uid through a
    real Unix socket and a real hub, while it serves the agent's own key."""

    USERS = ("fleet-alpha", "fleet-beta")

    def setUp(self):
        for user in self.USERS:
            code, out, err = hubsetup._shell(hubsetup.user_script(user))
            self.assertEqual(code, 0, err or out)
            self.addCleanup(hubsetup._shell, hubsetup.remove_script(user))
        for user in self.USERS:
            agent = user.split("-", 1)[1]
            self.run_as(user, f"mkdir -p -m 700 ~/.fleet/sessions && umask 077 && echo key-of-{agent} > "
                              f"~/.fleet/agent-{agent}.key && echo env > ~/.fleet/sessions/{agent}.T-1.ab.env && "
                              f"tmux -L default new-session -d -s fleet-{agent} sleep 600")
            self.addCleanup(self.run_as, user, "tmux kill-server || true")

    def run_as(self, user, script):
        done = subprocess.run(["runuser", "-u", user, "--", "sh", "-c", script], capture_output=True, text=True,
                              timeout=60)
        return done.returncode, done.stdout, done.stderr

    def test_one_agent_user_reads_nothing_of_another(self):
        uid = pwd.getpwnam("fleet-beta").pw_uid
        for what in ("cat /home/fleet-beta/.fleet/agent-beta.key", "ls /home/fleet-beta/.fleet/sessions",
                     f"tmux -S /tmp/tmux-{uid}/default list-sessions"):
            code, out, err = self.run_as("fleet-alpha", what)
            self.assertNotEqual(code, 0, f"fleet-alpha could run: {what}: {out}")
            self.assertNotIn("key-of-beta", out)
        code, out, _ = self.run_as("fleet-beta", "cat ~/.fleet/agent-beta.key")
        self.assertEqual((code, out.strip()), (0, "key-of-beta"))

    def test_the_vault_refuses_another_agents_key_from_this_uid(self):
        """vault.handle reads the caller's uid from a real Unix socket (SO_PEERCRED) and names its user to the hub,
        which refuses beta's key from alpha's user and takes alpha's own: the check that the hub makes, with the line
        the broker sends."""
        folder = tempfile.mkdtemp(prefix="fleet-broker-")
        self.addCleanup(shutil.rmtree, folder, True)
        os.chmod(folder, 0o755)
        path = os.path.join(folder, "vault.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        os.chmod(path, 0o666)
        server.listen(2)
        self.addCleanup(server.close)
        said, refusals = [], []

        class Opener:
            def open(self, request, timeout):
                said.append(dict(request.header_items()).get("X-fleet-caller-user"))
                raise OSError("the hub's answer is not part of this check")

        def accept():
            conn, _ = server.accept()
            with conn:
                line = conn.makefile().readline()
                uid = vault.peer_uid(conn)
                with patch.object(vault, "NO_PROXY", Opener()), patch.object(vault, "LocalStore", lambda c: None):
                    try:
                        vault.handle({"agent": None, "worker_group": "fleet-agents", "hub": "http://127.0.0.1:9"},
                                     line, uid)
                    except vault.Refused as e:
                        refusals.append(str(e))
        thread = threading.Thread(target=accept)
        thread.start()
        line = os.path.join(folder, "request")
        Path(line).write_text(json.dumps({"v": vault.PROTOCOL, "op": "read", "agent": "beta", "agent_key": "k" * 43})
                              + "\n")
        os.chmod(line, 0o644)
        code, out, err = self.run_as("fleet-alpha", f"python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); "
                                                    f"s.connect(\"{path}\"); "
                                                    f"s.sendall(open(\"{line}\", \"rb\").read()); s.recv(10)'")
        thread.join(30)
        self.assertEqual(said, ["fleet-alpha"], (refusals, code, out, err))   # alpha's user, with beta's key
        hub_team = team(box=("linux", "fleet", ["alpha", "beta"]))
        self.assertNotEqual(hub.agent_os_user(hub_team, "beta")[1], said[0])


@unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                     "the vault broker with real users runs as root on Linux (a throwaway container)")
class RealBroker(OwnerAPI):
    """The attack path's last step, end to end: agent alpha's user holds agent beta's key and asks the vault broker for
    beta's logins. The broker (vault.handle) reads alpha's uid from a real Unix socket (SO_PEERCRED), names alpha's
    user on its call to a real hub, and the hub refuses it (403 os_user) and holds beta's key from then on; alpha's
    own key from alpha's own user is served."""

    USERS = ("fleet-alpha", "fleet-beta")
    KEYS = {"alpha": "A" * 43, "beta": "B" * 43}

    def setUp(self):
        super().setUp()
        for user in self.USERS:
            code, out, err = hubsetup._shell(hubsetup.user_script(user))
            self.assertEqual(code, 0, err or out)
            self.addCleanup(hubsetup._shell, hubsetup.remove_script(user))
        t = team(box=("linux", "fleet", ["alpha", "beta"]))
        for agent in ("alpha", "beta"):
            t["agents"][agent]["vault"] = "broker"
            hub.q("INSERT INTO agent_keys(agent,sha256,created,source) VALUES(?,?,?,'server')",
                  (agent, sha(self.KEYS[agent]), hub.now()))
        hub.TEAM = t
        hub.os_user_refresh()
        self.server.machines = True             # a call comes from the machine of the agent that its route names
        self.folder = tempfile.mkdtemp(prefix="fleet-broker-")
        self.addCleanup(shutil.rmtree, self.folder, True)
        os.chmod(self.folder, 0o755)

    def ask(self, user, agent):
        """One read request through a real Unix socket, sent by `user` with `agent`'s key: the broker's answer."""
        path = os.path.join(self.folder, f"vault-{user}-{agent}.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        os.chmod(path, 0o666)
        server.listen(1)
        answers = []

        def serve():
            conn, _ = server.accept()
            with conn:
                line = conn.makefile().readline()
                with patch.object(vault, "LocalStore", lambda conf: None):
                    try:
                        answers.append(vault.handle({"agent": None, "worker_group": "fleet-agents", "hub": self.base},
                                                    line, vault.peer_uid(conn)))
                    except vault.Refused as e:
                        answers.append(str(e))
        thread = threading.Thread(target=serve)
        thread.start()
        request = os.path.join(self.folder, f"request-{user}-{agent}")
        Path(request).write_text(json.dumps({"v": vault.PROTOCOL, "op": "read", "agent": agent,
                                             "agent_key": self.KEYS[agent]}) + "\n")
        os.chmod(request, 0o644)
        done = subprocess.run(["runuser", "-u", user, "--", "python3", "-c",
                               f"import socket; s=socket.socket(socket.AF_UNIX); s.connect({path!r}); "
                               f"s.sendall(open({request!r}, 'rb').read()); s.shutdown(socket.SHUT_WR); s.recv(10)"],
                              capture_output=True, text=True, timeout=60)
        thread.join(30)
        server.close()
        self.assertTrue(answers, done.stderr)
        return answers[0]

    def test_another_agents_key_from_this_user_gets_nothing_and_its_own_is_served(self):
        said = self.ask("fleet-alpha", "beta")
        self.assertIsInstance(said, str)
        self.assertIn("another user account", said)
        self.assertTrue(hub.os_user_held("beta"))
        self.assertFalse(hub.os_user_held("alpha"))
        answer = self.ask("fleet-alpha", "alpha")
        self.assertIsInstance(answer, dict, answer)
        self.assertTrue(answer.get("ok"), answer)


if __name__ == "__main__":
    unittest.main()

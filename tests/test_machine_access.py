"""Owner feature `machine_access`: `POST /ui/team/access`, the one route that puts on record how the fleet reaches a
machine, and the one that takes that record out again.

Before it, every writer of the `access` map of `team.json` wrote at creation time and never again: the hub installer
for the hub's own machine, a server's join (`root`, and only for a Linux port), and the local onboarding executor. So
a machine that already existed could not be corrected and no entry could be taken out, and the owner's Mac Studio,
which he reaches as `dana` every day, stood in the fleet's own record with `ssh: null` and `no_ssh` against it. The
owner, 19 October 2026: "ssh works for the studio
from here, so please make sure you fix it -- make sure we get this right for future updates, we can't lose access to
the fleet and its servers!"

An in-process hub and temporary Git repositories; no fleet, no network and no AI call.
"""
import json
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path

import hub
from test_ui_api import OwnerAPI

OWNER, HUB, VPS, STUDIO = "127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"
TEAM = {
    "hub": {"machine": "hub", "port": 8765},
    "addresses": {"owner": OWNER, "hub": HUB, "vps": VPS, "mac-studio": STUDIO},
    "access": {"vps": {"ssh_user": "root", "ssh_port": 22}},
    "agents": {
        "manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": ["shell", "web"]},
        "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell", "web"]},
        "studio": {"role": "worker", "runtime": "claude", "machine": "mac-studio", "can": ["shell", "browser"]},
    },
}


def git(*args, cwd=None):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def load_tests(loader, _tests, _pattern):
    """Only this file's tests: OwnerAPI, the fixture it borrows, carries its own."""
    return unittest.TestSuite(MachineAccess(name) for name in MachineAccess.__dict__ if name.startswith("test_"))


class MachineAccess(OwnerAPI):
    def setUp(self):
        super().setUp()
        self.server.machines = True
        hub.TEAM = json.loads(json.dumps(TEAM))
        self.root = Path(tempfile.mkdtemp(prefix="fleet-machine-access-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
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
        self.addCleanup(hub.CFG.pop, "team_path", None)
        hub._revision_cache.update(at=0.0, value=None)
        self.addCleanup(hub._revision_cache.update, at=0.0, value=None)
        # Each machine's own helper has reported, so machine_readiness knows the OS user its agents run as: the one
        # user besides root that the fleet may be recorded as.
        for agent, user in (("vps", "fleet-vps"), ("studio", "dana")):
            hub.q("INSERT INTO machine_status(agent,data,reported) VALUES(?,?,?)",
                  (agent, json.dumps({"access": {"user": user, "ssh": True, "screen_sharing": agent == "studio"}}),
                   time.time()))

    # ---- helpers
    def owner(self, path, **body):
        return self.request(path, dict(dict(request_id=str(uuid.uuid4()), db="test-generation"), **body), source=OWNER)

    def team_sha(self):
        return self.request("/ui/team?db=test-generation", source=OWNER)[1]["sha256"]

    def record(self, machine="mac-studio", base=None, **body):
        return self.owner("/ui/team/access", machine=machine, base_sha256=base or self.team_sha(), **body)

    def origin_team(self):
        return json.loads(git("--git-dir", str(self.root / "origin.git"), "show", "main:team.json"))

    def row(self, agent):
        code, data = self.request("/ui/machines?db=test-generation", source=OWNER)
        self.assertEqual(code, 200, data)
        return [m for m in data["machines"] if m["agent"] == agent][0]

    def readiness(self, machine):
        return hub.machine_readiness(hub.TEAM)[machine]

    def logged(self):
        return [r["what"] for r in hub.q("SELECT what FROM log WHERE agent='owner' ORDER BY id")]

    # ---- the route writes, and the machine's connection appears
    def test_the_owner_records_how_a_machine_is_reached(self):
        before = self.row("studio")
        self.assertIsNone(before["access"]["ssh"])
        self.assertIn("no_ssh", self.readiness("mac-studio")["add_agent"]["missing"])

        code, receipt = self.record(ssh_user="dana", ssh_port=22, screen_sharing=True)
        self.assertEqual(code, 200, receipt)
        self.assertEqual((receipt["machine"], receipt["changed"], receipt["deleted"]), ("mac-studio", True, False))
        self.assertEqual(receipt["access"], {"ssh_user": "dana", "ssh_port": 22, "screen_sharing": True})
        self.assertEqual(self.origin_team()["access"]["mac-studio"], receipt["access"])

        after = self.row("studio")
        self.assertEqual(after["access"]["ssh"], {"user": "dana", "port": 22, "available": True})
        self.assertEqual(after["access"]["screen_sharing"], {"available": True})
        self.assertEqual(self.readiness("mac-studio")["ssh"], {"user": "dana", "port": 22})
        self.assertNotIn("no_ssh", self.readiness("mac-studio")["add_agent"]["missing"])
        self.assertEqual([l for l in self.logged() if "mac-studio" in l],
                         [f"recorded how the fleet reaches mac-studio in {receipt['revision'][:12]}"])

    def test_the_port_and_screen_sharing_have_their_defaults(self):
        """The user is the one thing nothing can derive, so it is the one thing the owner must say."""
        code, receipt = self.record(ssh_user="dana")
        self.assertEqual(code, 200, receipt)
        self.assertEqual(receipt["access"], {"ssh_user": "dana", "ssh_port": 22, "screen_sharing": False})
        self.assertEqual(self.row("studio")["access"], {"ssh": {"user": "dana", "port": 22, "available": True},
                                                        "screen_sharing": None})

    def test_a_record_that_changes_nothing_makes_no_commit(self):
        first = self.record(ssh_user="dana", screen_sharing=True)[1]
        code, again = self.record(ssh_user="dana", screen_sharing=True)
        self.assertEqual((code, again["changed"]), (200, False), again)
        self.assertEqual(again["revision"], first["revision"])

    def test_the_same_command_twice_answers_once(self):
        body = dict(request_id=str(uuid.uuid4()), db="test-generation", machine="mac-studio",
                    base_sha256=self.team_sha(), ssh_user="dana")
        first = self.request("/ui/team/access", body, source=OWNER)
        second = self.request("/ui/team/access", body, source=OWNER)
        self.assertEqual(first[0], 200, first[1])
        self.assertEqual(second[0], 200, second[1])
        self.assertTrue(second[1]["replayed"])
        self.assertEqual(second[1]["revision"], first[1]["revision"])
        self.assertEqual(len(self.origin_team()["access"]), 2)

    # ---- the generation and the version of team.json
    def test_a_stale_generation_is_refused(self):
        code, refused = self.request("/ui/team/access",
                                     dict(request_id=str(uuid.uuid4()), db="another-generation",
                                          machine="mac-studio", base_sha256=self.team_sha(), ssh_user="dana"),
                                     source=OWNER)
        self.assertEqual(code, 409, refused)
        self.assertIn("hub generation changed", refused["error"])
        self.assertNotIn("mac-studio", self.origin_team().get("access", {}))

    def test_an_old_version_of_team_json_is_refused_with_the_current_one(self):
        code, refused = self.record(ssh_user="dana", base="0" * 64)
        self.assertEqual(code, 409, refused)
        self.assertIn("team.json changed meanwhile", refused["error"])
        self.assertEqual(refused["sha256"], self.team_sha())
        self.assertNotIn("mac-studio", self.origin_team().get("access", {}))
        self.assertEqual(self.count("ui_controls"), 0)      # a refused command leaves no record

    # ---- the user the fleet may not use
    def test_a_user_the_machine_would_refuse_is_refused_with_its_reason(self):
        """`machine_readiness` marks a recorded user that is neither root nor the agents' own OS user
        `ssh_user_not_allowed`. Writing one would leave the machine broken on every screen that reads that line, so
        the route asks machine_readiness itself, on the team the write would make, and refuses instead."""
        code, refused = self.record(ssh_user="somebody")
        self.assertEqual(code, 409, refused)
        self.assertIn("the agents of mac-studio run as dana", refused["error"])
        self.assertIn("ssh_user_not_allowed", refused["error"])
        self.assertEqual(refused["worker_user"], "dana")
        self.assertNotIn("mac-studio", self.origin_team().get("access", {}))
        self.assertIsNone(self.row("studio")["access"]["ssh"])
        self.assertEqual(self.count("ui_controls"), 0)
        # root is always allowed, and so is the user the helper reports
        self.assertEqual(self.record(ssh_user="root")[0], 200)
        self.assertEqual(self.record(ssh_user="dana")[0], 200)
        self.assertNotIn("ssh_user_not_allowed", self.readiness("mac-studio")["add_agent"]["missing"])

    def test_a_machine_whose_helper_reports_no_user_takes_any_user(self):
        """`machine_readiness` marks that machine `worker_user_unknown` and never `ssh_user_not_allowed`: with
        nothing to compare against, the route has no rule to apply and the owner's own word stands."""
        hub.q("DELETE FROM machine_status WHERE agent='studio'")
        self.assertEqual(self.record(ssh_user="somebody")[0], 200)
        missing = self.readiness("mac-studio")["add_agent"]["missing"]
        self.assertIn("worker_user_unknown", missing)
        self.assertNotIn("ssh_user_not_allowed", missing)

    # ---- removal
    def test_a_connection_that_is_gone_is_recordable_as_gone(self):
        self.record(ssh_user="dana", screen_sharing=True)
        code, receipt = self.record(delete=True)
        self.assertEqual(code, 200, receipt)
        self.assertEqual((receipt["changed"], receipt["deleted"], receipt["access"]), (True, True, None))
        self.assertNotIn("mac-studio", self.origin_team().get("access", {}))
        self.assertIsNone(self.row("studio")["access"]["ssh"])
        self.assertIsNone(self.row("studio")["access"]["screen_sharing"])
        self.assertIn("no_ssh", self.readiness("mac-studio")["add_agent"]["missing"])
        self.assertIn(f"forgot how the fleet reaches mac-studio in {receipt['revision'][:12]}", self.logged())
        self.assertEqual(self.record(delete=True)[0], 404)      # nothing left to forget

    def test_the_last_entry_removed_takes_the_map_with_it(self):
        self.assertEqual(self.record(machine="vps", delete=True)[0], 200)
        self.assertNotIn("access", self.origin_team())
        self.assertIsNone(self.row("vps")["access"]["ssh"])

    # ---- machines this fleet does not reach
    def test_a_machine_that_is_not_in_the_fleet_is_refused(self):
        code, refused = self.record(machine="nowhere", ssh_user="dana")
        self.assertEqual(code, 404, refused)
        self.assertIn("no server nowhere", refused["error"])
        self.assertIn("mac-studio", refused["error"])

    def test_the_owners_own_computer_is_not_a_machine_the_fleet_reaches(self):
        code, refused = self.record(machine="owner", ssh_user="dana")
        self.assertEqual(code, 409, refused)
        self.assertEqual("Your Mac connects to the fleet; the fleet does not reach it.", refused["error"])
        self.assertNotIn("owner", self.origin_team().get("access", {}))

    # ---- what the route will not take
    def test_what_the_route_refuses_to_read(self):
        base = self.team_sha()
        for body, word in (({"ssh_user": "-oProxyCommand=id"}, "ssh_user"),
                           ({"ssh_user": ""}, "ssh_user"),
                           ({"ssh_user": "dana\nroot"}, "ssh_user"),
                           ({"ssh_user": "dana root"}, "ssh_user"),
                           ({}, "ssh_user"),
                           ({"ssh_user": "dana", "ssh_port": 0}, "ssh_port"),
                           ({"ssh_user": "dana", "ssh_port": 70000}, "ssh_port"),
                           ({"ssh_user": "dana", "ssh_port": True}, "ssh_port"),
                           ({"ssh_user": "dana", "ssh_port": "22"}, "ssh_port"),
                           ({"ssh_user": "dana", "screen_sharing": "yes"}, "screen_sharing"),
                           ({"delete": True, "ssh_user": "dana"}, "delete"),
                           ({"delete": "yes"}, "delete"),
                           ({"ssh_user": "dana", "who": "me"}, "who")):
            code, refused = self.record(base=base, **body)
            self.assertEqual(code, 400, (body, refused))
            self.assertIn(word, refused["error"], (body, refused))
        for machine in ("Mac-Studio", "mac studio", "1studio", "a" * 40, 7):
            self.assertEqual(self.record(machine=machine, base=base, ssh_user="dana")[0], 400, machine)
        self.assertNotIn("mac-studio", self.origin_team().get("access", {}))
        self.assertEqual(self.count("ui_controls"), 0)
        # Space around the user is trimmed, as every other owner field of this hub is
        self.assertEqual(self.record(base=base, ssh_user=" dana\n")[1]["access"]["ssh_user"], "dana")

    def test_a_caller_that_is_not_the_owner_is_refused(self):
        code, refused = self.request("/ui/team/access",
                                     dict(request_id=str(uuid.uuid4()), db="test-generation", machine="mac-studio",
                                          base_sha256=self.team_sha(), ssh_user="dana"), source="127.0.0.9")
        self.assertEqual(code, 403, refused)
        self.assertNotIn("mac-studio", self.origin_team().get("access", {}))

    # ---- the gap that the app reads, unchanged where there is no record
    def test_a_machine_with_no_entry_still_reports_no_ssh(self):
        for machine, agent in (("mac-studio", "studio"),):
            self.assertIsNone(self.row(agent)["access"]["ssh"])
            self.assertIsNone(self.row(agent)["access"]["screen_sharing"])
            self.assertIn("no_ssh", self.readiness(machine)["add_agent"]["missing"])
            self.assertFalse(self.readiness(machine)["add_agent"]["ready"])
        # and a machine that has one does not
        self.assertNotIn("no_ssh", self.readiness("vps")["add_agent"]["missing"])
        self.assertEqual(self.row("vps")["access"]["ssh"], {"user": "root", "port": 22, "available": True})

    def test_the_hub_announces_the_feature(self):
        self.assertIn("machine_access", self.request("/ui/state")[1]["ui_features"])


if __name__ == "__main__":
    unittest.main()

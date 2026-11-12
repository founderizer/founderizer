"""An agent moves to an empty server (owner feature agent_move, UI-API.md 1.74, DevOps plan C7): one commit of
team.json, the install job on the new server, and the end of the old session, for a worker and for the manager; the
refusals; the second try of a failed install; and the old helper, which ends its own sessions and service when the hub
answers it `moved`."""
import json
import unittest
from unittest.mock import patch

import fleet
import hub
from test_servers import HUB, NEW, OTHER, OWNER, Servers, git

SPARE = "127.0.0.11"            # the address of the empty server that the agent moves to


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(cls(name) for cls in (Move, OldHelper) for name in cls.__dict__
                              if name.startswith("test_"))


class Move(Servers):
    """scout is a Codex worker on the Linux server box; spare is an empty Linux server that joined with a code."""

    def setUp(self):
        super().setUp()
        self.joined("box", "linux", source=OTHER, user="fleet")
        status, receipt = self.add_agent("box", "scout", "codex")
        self.assertEqual(status, 200, receipt)
        self.job("box", receipt["job"], "done", "sign_in", source=OTHER)
        self.joined("spare", "linux", source=SPARE, user="fleet")

    def job(self, server, job, state, step, detail=None, source=SPARE):
        status, answer = self.service(f"/server/{server}/jobs/{job}", {"state": state, "step": step, "detail": detail},
                                      source=source)
        self.assertEqual(status, 200, answer)

    def move(self, agent="scout", server="spare", base=None, **extra):
        return self.owner(f"/ui/team/agents/{agent}/move", **dict(dict(base_sha256=base or self.team_sha(),
                                                                       server=server), **extra))

    def head(self):
        return git("--git-dir", str(self.root / "origin.git"), "rev-parse", "main")

    def test_the_feature_is_offered(self):
        self.assertIn("agent_move", self.request(source=OWNER)[1]["ui_features"])

    def test_a_move_is_one_commit_an_install_job_and_the_end_of_the_old_records(self):
        team = self.origin_team()
        team["agents"]["scout"].update(vault="broker", vault_recipient="age1" + "q" * 58)
        (self.kit / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        git("commit", "-q", "-am", "scout has its machine's vault", cwd=self.kit)
        git("push", "-q", "origin", "HEAD", cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = json.loads(json.dumps(team))         # the hub's own copy, which the move changes
        hub.q("INSERT INTO agent_keys(agent,sha256,created,source) VALUES('scout',?,0,'enrolled')", ("a" * 64,))
        hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES('scout','{}',?)", (hub.now(),))
        hub.q("INSERT INTO session_credentials(sha256,agent,kind,generation,created) VALUES(?,?,?,?,?)",
              ("c" * 64, "scout", "task", "test-generation", hub.now()))
        hub.kv_set("default_vault:scout", 1)
        before = self.head()
        status, receipt = self.move()
        self.assertEqual(status, 200, receipt)
        self.assertEqual({k: receipt[k] for k in ("agent", "server", "was", "replayed")},
                         {"agent": "scout", "server": "spare", "was": "box", "replayed": False})
        self.assertEqual(git("--git-dir", str(self.root / "origin.git"), "rev-list", "--count", f"{before}..main"), "1")
        self.assertEqual(receipt["revision"], self.head())
        after = self.origin_team()["agents"]["scout"]
        expected = dict(team["agents"]["scout"], machine="spare", vault="none")
        expected.pop("vault_recipient")
        self.assertEqual(after, expected)
        self.assertEqual(hub.agents()["scout"]["machine"], "spare")
        job = hub.q1("SELECT * FROM server_jobs WHERE id=?", (receipt["job"],))
        self.assertEqual((job["server"], job["kind"], job["agent"], job["runtime"], job["state"]),
                         ("spare", "install", "scout", "codex", "queued"))
        self.assertIsNone(hub.agent_key("scout"))           # its helper on spare enrolls its own key
        self.assertIsNone(hub.q1("SELECT 1 FROM machine_status WHERE agent='scout'"))
        self.assertIsNotNone(hub.q1("SELECT revoked FROM session_credentials WHERE agent='scout'")["revoked"])
        self.assertIsNone(hub.kv_get("default_vault:scout"))        # the sweep gives it the new machine's vault
        self.assertEqual(hub.kv_get("moved_from:scout"), "box")
        said = hub.q1("SELECT text FROM events WHERE agent='manager' AND text LIKE '%moved scout%'")
        self.assertIn("from box to the server spare", said["text"])
        _, view = self.servers()
        self.assertEqual((view["box"]["agents"], view["spare"]["agents"]), ([], ["scout"]))

    def test_the_old_machine_hears_moved_and_the_new_one_is_scout(self):
        status, receipt = self.move()
        self.assertEqual(status, 200, receipt)
        status, answer = self.request("/worker/install/scout", source=OTHER)
        self.assertEqual((status, answer.get("auth")), (403, "moved"))
        status, answer = self.request("/events/scout?delivery=1&after=0&wait=0", source=OTHER)      # the helper's poll
        self.assertEqual((status, answer.get("auth")), (403, "moved"))
        status, answer = self.request("/worker/install/scout", source="127.0.0.12")      # never scout's machine
        self.assertEqual(status, 403)
        self.assertNotIn("auth", answer)
        self.assertEqual(self.request("/worker/install/scout", source=SPARE)[0], 200)
        self.assertEqual(self.request("/worker/install/studio", source="127.0.0.5")[0], 200)   # the others stay

    def test_a_failed_install_there_goes_again_with_the_same_command_and_no_new_commit(self):
        status, receipt = self.move()
        self.assertEqual(status, 200, receipt)
        self.job("spare", receipt["job"], "failed", "runtime", "Codex could not be installed.")
        head = self.head()
        status, again = self.move()
        self.assertEqual(status, 200, again)
        self.assertEqual((again["revision"], again["was"], self.head()), (head, "spare", head))
        self.assertEqual(hub.q1("SELECT kind, state FROM server_jobs WHERE id=?", (again["job"],))["state"], "queued")
        self.assertEqual(hub.kv_get("moved_from:scout"), "box")         # the machine it left is still the old one
        self.job("spare", again["job"], "done", "sign_in")
        status, answer = self.move()
        self.assertEqual((status, answer["error"]), (409, "Scout runs on spare already."))

    def test_the_manager_moves_off_the_hub(self):
        status, receipt = self.move("manager")
        self.assertEqual(status, 200, receipt)
        self.assertEqual((receipt["was"], self.origin_team()["agents"]["manager"]["machine"]), ("hub", "spare"))
        self.assertEqual(hub.server_agents("hub"), [])
        self.assertEqual(self.request("/worker/install/manager", source=HUB)[1].get("auth"), "moved")

    def test_refusals(self):
        self.assertEqual(self.move("nobody")[0], 404)
        self.assertEqual(self.move(server="nowhere")[0], 404)
        status, answer = self.move(server="vps")
        self.assertEqual((status, answer["error"]), (409, "vps has no server service: it did not join with a join code"))
        status, answer = self.move(server="box")            # box has scout already
        self.assertEqual((status, answer["error"]), (409, "Scout runs on box already."))
        status, answer = self.move("vps", server="box")
        self.assertEqual((status, answer["error"]), (409, "box has an agent already: scout"))
        self.joined("mini", "mac", source=NEW)
        status, answer = self.move(server="mini")
        self.assertEqual(status, 409)
        self.assertIn("an agent moves to a server of its own kind", answer["error"])
        with patch.object(hub, "running_turns", lambda owner=None, t0=None: [7] if owner == "scout" else []):
            status, answer = self.move()
        self.assertEqual((status, answer["error"]), (409, "Scout is in the middle of a turn. Move it when the turn "
                                                          "ends."))
        with patch.object(hub, "open_login", lambda agent: {"runtime": "codex"} if agent == "scout" else None):
            self.assertEqual(self.move()[0], 409)
        status, answer = self.move(base="0" * 64)
        self.assertEqual(status, 409)
        self.assertIn("sha256", answer)
        self.assertEqual(self.move(server="Spare!")[0], 400)
        self.assertEqual(self.move(name="x")[0], 400)
        hub.q("UPDATE server_status SET reported=0 WHERE server='spare'")
        status, answer = self.move()
        self.assertEqual((status, answer["error"]), (409, "spare sent no reading in the last 10 minutes: check that "
                                                          "it is on"))
        self.assertEqual(self.origin_team()["agents"]["scout"]["machine"], "box")
        self.assertIsNone(hub.kv_get("moved_from:scout"))

    def test_not_to_the_hubs_own_server_or_one_with_an_open_job(self):
        hub.q("INSERT INTO server_keys(server,sha256,created) VALUES('hub',?,0)", ("d" * 64,))
        hub.q("INSERT OR REPLACE INTO server_status(server,data,reported) VALUES('hub','{}',?)", (hub.now(),))
        status, answer = self.move("vps", server="hub")
        self.assertEqual((status, answer["error"]), (409, "No agent runs on the hub's server."))
        status, receipt = self.move()
        self.assertEqual(status, 200, receipt)
        status, answer = self.move("vps", server="spare")
        self.assertEqual((status, answer["error"]), (409, "spare installs scout now"))


    def test_not_while_its_own_server_works_on_a_job(self):
        """An install on its own server could still give it that server's key (hub.install_key; the review of 3
        November 2026)."""
        t0 = hub.now()
        hub.ins("INSERT INTO server_jobs(server,kind,agent,runtime,state,created,updated) VALUES(?,?,?,?,?,?,?)",
                ("box", "prepare", "scout", "claude", "running", t0, t0))
        status, answer = self.move()
        self.assertEqual((status, answer["error"]), (409, "box prepares a provider for scout now"))


class OldHelper(unittest.TestCase):
    """fleet.Helper.moved_away: what the helper on the machine that the agent left does with the answer `moved`."""

    def run_it(self, platform):
        h = fleet.Helper.__new__(fleet.Helper)
        h.agent, h.session = "scout", "fleet-scout"
        tmux, runs = [], []
        with patch.object(fleet, "tmux", lambda *args, **kw: tmux.append(args)), \
                patch.object(fleet.sys, "platform", platform), \
                patch.object(fleet.subprocess, "run", lambda argv, **kw: runs.append(argv)), \
                patch.object(fleet.os, "remove", lambda path: runs.append(["rm", path])):
            h.moved_away()
        return tmux, runs

    def test_on_linux_its_sessions_end_and_its_unit_is_disabled(self):
        tmux, runs = self.run_it("linux")
        self.assertEqual(tmux, [("kill-session", "-t", "=fleet-scout:")])
        self.assertEqual(runs, [["systemctl", "--user", "--no-block", "disable", "--now", "fleet-scout.service"]])

    def test_the_ops_command_is_put_on_the_box_once(self):
        """DevOps plan C1: the helper puts the door's command in ~/.local/bin, which every session's PATH carries."""
        import os
        import shutil
        import tempfile
        home = tempfile.mkdtemp(prefix="fleet-ops-")
        self.addCleanup(shutil.rmtree, home, True)
        with patch.dict(os.environ, {"HOME": home}):
            self.assertTrue(fleet.ensure_ops())
            self.assertFalse(fleet.ensure_ops())
            path = os.path.join(home, ".local", "bin", "ops")
            with open(path) as f:
                self.assertEqual(f.read(), f'#!/bin/sh\nexec python3 "{fleet.KIT}/ops.py" "$@"\n')
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o755)

    def test_on_a_mac_its_launch_agent_goes(self):
        tmux, runs = self.run_it("darwin")
        self.assertEqual(tmux, [("kill-session", "-t", "=fleet-scout:")])
        self.assertEqual(runs[0][0], "rm")
        self.assertTrue(runs[0][1].endswith("Library/LaunchAgents/com.agentfleet.scout.plist"))
        self.assertEqual(runs[1][:2], ["launchctl", "bootout"])
        self.assertTrue(runs[1][2].endswith("/com.agentfleet.scout"))


if __name__ == "__main__":
    unittest.main()

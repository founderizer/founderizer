"""What every agent holds unless the owner says otherwise (the owner, 28 October 2026: "it is essential that they all
have access to secrets!", and "a mac studio server should come by default with computer and browser use"): each
worker and lead gets its machine's vault once that vault can serve it, and an agent on a Mac gets the browser and the
screen of its desktop. The hub gives each once; the owner's own word on it is final. In-process hub and temporary Git
repositories; no helper, vault, Chrome or AI call."""
import json
import shlex
import unittest
from unittest.mock import patch

import fleet
import hub
from test_agent_auth import GRANT_TEAM, STORE, VaultAccess, sha
from test_setup import git

# GRANT_TEAM on a Mac: box is a Mac, lone a Linux server, and alpha's Claude start has no {chrome} yet, as a start
# copied from a Linux worker has not.
DESKTOP_TEAM = json.loads(json.dumps(GRANT_TEAM))
DESKTOP_TEAM["servers"] = {"box": {"kind": "mac", "user": "dana"}, "lone": {"kind": "linux", "user": "fleet"}}
DESKTOP_TEAM["agents"]["alpha"]["start"] = "claude --permission-mode dontAsk {settings} {prompt}"


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(DefaultAccess(name) for name in DefaultAccess.__dict__ if name.startswith("test_"))


class DefaultAccess(VaultAccess):
    def setUp(self):
        super().setUp()
        hub.DEFAULT_ACCESS.update(at=0.0, retry={})

    def put(self, team):
        """Commit a team.json, as a developer's push would leave it: the routes read the commit, not hub.TEAM."""
        kit = self.root / "kit"
        (kit / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        git("add", "-A", cwd=kit)
        git("commit", "-q", "-m", "a fleet from before the defaults", cwd=kit)
        git("push", "-q", "origin", "HEAD", cwd=kit)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = json.loads(json.dumps(team))

    def commits(self):
        return int(git("rev-list", "--count", "HEAD", cwd=self.root / "kit"))

    def sweep(self):
        hub.DEFAULT_ACCESS["at"] = 0.0          # each call is a pass of its own
        hub.default_access_sweep(hub.now())

    def told(self):
        return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id")
                if "by default" in r["text"]]

    # ---- the vault
    def test_every_worker_whose_vault_can_serve_it_gets_that_vault_once(self):
        before = self.committed()
        self.sweep()
        team = self.committed()
        for name in ("beta", "lone"):           # both ready: a key, a helper with callers and a broker that reports
            self.assertEqual((team["agents"][name]["vault"], team["agents"][name]["vault_recipient"]), ("broker", STORE))
        self.assertEqual(team["vault_stores"], {"box": STORE, "lone": STORE})
        self.assertEqual(team["agents"]["alpha"], before["agents"]["alpha"])        # it had its vault already
        self.assertEqual(team["agents"]["filer"]["vault"], "file")                  # file mode is never changed
        self.assertNotIn("vault", team["agents"]["manager"])                        # the manager's is set at install
        self.assertEqual(len(self.told()), 2, self.told())
        self.assertIn("its vault opens the logins it is given", self.told()[0])
        self.assertEqual(self.line("beta")["vault_grant"], None)                    # its control is revoke now
        head = self.commits()
        self.sweep()                            # nothing is given twice
        self.assertEqual((self.commits(), len(self.told())), (head, 2))

    def test_the_owners_none_stays(self):
        self.sweep()
        self.assertEqual(self.vault("beta", "none")[0], 200)
        self.sweep()
        self.assertEqual(self.committed()["agents"]["beta"]["vault"], "none")

    def test_a_vault_that_cannot_serve_the_agent_yet_is_given_when_it_can(self):
        self.report("beta", callers=False)
        self.sweep()
        self.assertEqual(self.committed()["agents"]["beta"]["vault"], "none")
        self.assertIsNone(hub.kv_get("default_vault:beta"))
        self.report("beta")
        self.sweep()
        self.assertEqual(self.committed()["agents"]["beta"]["vault"], "broker")

    def test_the_owners_word_before_the_default_ends_it(self):
        self.report("beta", callers=False)
        self.assertEqual(self.vault("beta", "none")[0], 200)                        # "none", while it is none
        self.report("beta")
        self.sweep()
        self.assertEqual(self.committed()["agents"]["beta"]["vault"], "none")

    def test_a_refused_grant_leaves_the_default_in_place(self):
        self.report("beta", callers=False)
        self.assertEqual(self.vault("beta", "broker")[0], 409)                      # not ready: he wanted it all the same
        self.report("beta")
        self.sweep()
        self.assertEqual(self.committed()["agents"]["beta"]["vault"], "broker")

    def test_a_rename_keeps_the_owners_word(self):
        self.assertTrue({"default_vault:", "default_desktop:"} <= set(hub.AGENT_KV))

    def test_an_agent_that_left_and_came_back_on_another_machine_gets_what_that_machine_gives(self):
        """30 October 2026: an agent left team.json on one server and came back on another under its name. Its mark
        still said that its default had ended, so the hub never gave it the new machine's vault, although vault_grant
        was ready, and the owner gave it by hand."""
        self.put(DESKTOP_TEAM)
        self.sweep()
        team = self.committed()
        self.assertEqual(team["agents"]["lone"]["vault"], "broker")     # given; its Linux browser waits for its
        self.assertEqual((hub.kv_get("default_vault:lone"), hub.kv_get("default_desktop:lone")), ("1", None))   # server
        del team["agents"]["lone"]
        hub.apply_team(json.loads(json.dumps(team)))                    # it leaves
        self.assertEqual((hub.kv_get("default_vault:lone"), hub.kv_get("default_desktop:lone")), (None, None))
        self.assertEqual(hub.kv_get("default_vault:beta"), "1")         # the others keep theirs
        team["agents"]["lone"] = {"role": "worker", "runtime": "claude", "machine": "box", "can": ["shell"]}
        self.put(team)                                                  # and comes back on the Mac
        hub.ins("INSERT INTO agent_keys(agent,sha256,created,source) VALUES('lone',?,?,'owner')", (sha("new"), hub.now()))
        self.report("lone")
        self.assertEqual(self.line("lone")["vault_grant"], {"ready": True, "missing": []})
        self.sweep()
        back = self.committed()["agents"]["lone"]
        self.assertEqual((back["vault"], back["vault_recipient"]), ("broker", STORE))
        self.assertEqual((back["can"], back["screen_command"]), (["shell", "browser", "screen"], hub.MAC_SCREEN_COMMAND))

    # ---- the desktop of a Mac
    def test_an_agent_on_a_mac_gets_its_desktop_once_and_a_linux_agent_none(self):
        self.put(DESKTOP_TEAM)
        self.sweep()
        team = self.committed()["agents"]
        self.assertEqual((team["alpha"]["can"], team["alpha"]["screen_command"], team["alpha"]["start"]),
                         (["shell", "browser", "screen"], hub.MAC_SCREEN_COMMAND,
                          "claude --permission-mode dontAsk {chrome} {settings} {prompt}"))
        self.assertTrue(hub.full_access("claude", dict(team["alpha"], allow=hub.FULL_ACCESS["claude"]["allow"])))
        self.assertEqual((team["beta"]["can"], team["beta"]["screen_command"]),          # Codex has no browser task
                         (["shell", "screen"], hub.MAC_SCREEN_COMMAND))
        self.assertEqual((team["lone"]["can"], "screen_command" in team["lone"]), (["shell"], False))   # Linux
        self.assertEqual(team["filer"]["can"], ["shell"])          # a machine of no known kind gets nothing yet
        self.assertIsNone(hub.kv_get("default_desktop:filer"))
        self.assertIn("browser and screen of its Mac", " ".join(self.told()))
        head = self.commits()
        self.sweep()
        self.assertEqual(self.commits(), head)

    def test_a_capability_that_the_owner_took_away_stays_away(self):
        self.put(DESKTOP_TEAM)
        self.sweep()
        code, receipt = self.request("/ui/team/agents/alpha", {
            "request_id": "6f1c4e1e-0d6e-4c4e-9b0e-2a3f6e0c8d11", "db": "test-generation",
            "base_sha256": self.team()["sha256"], "can": ["shell", "screen"]})
        self.assertEqual(code, 200, receipt)
        self.sweep()
        self.assertEqual(self.committed()["agents"]["alpha"]["can"], ["shell", "screen"])

    def test_a_new_agent_on_a_mac_starts_with_its_desktop(self):
        team = json.loads(json.dumps(DESKTOP_TEAM))
        entry = hub.server_agent_entry(team, "scout", "box", "claude", "worker", None)
        self.assertEqual((entry["can"], entry["screen_command"]), (["shell", "web", "browser", "screen"],
                                                                   hub.MAC_SCREEN_COMMAND))
        self.assertIn("{chrome}", entry["start"])
        linux = hub.server_agent_entry(team, "coder", "lone", "claude", "worker", None)
        self.assertEqual((linux["can"], "screen_command" in linux), (["shell", "web"], False))
        self.assertNotIn("no browser", hub.SERVER_PROFILE)
        self.assertNotIn("reject", hub.SERVER_PROFILE)

    # ---- the Linux default of D1 (build plan 04, S3b): "Every agent with shell"
    def linux_reads(self, room=True, state="ready", user="fleet-lone", memory=6000):
        """lone's server service reads its browser parts, whom each agent there runs as, and the room of its
        user.slice (S1b; room=False: a service from before it)."""
        data = {"os": {"name": "Ubuntu 24.04.3 LTS", "boot": "b1"}, "browser": {"state": state, "ports": []},
                "agents": {"lone": {"user": user, "uid": 1001}} if user else {}}
        if room:
            data["room"] = {"memory_max": memory << 20, "swap_max": None, "swap_total": 2000 << 20}
        hub.q("INSERT INTO server_status(server,data,reported) VALUES('lone',?,?) ON CONFLICT(server) DO UPDATE SET "
              "data=excluded.data, reported=excluded.reported", (json.dumps(data), hub.now()))

    def boxes(self, agent, can):
        return self.request(f"/ui/team/agents/{agent}", {"request_id": str(__import__("uuid").uuid4()),
                                                          "db": "test-generation", "base_sha256": self.team()["sha256"],
                                                          "can": can})

    def test_a_linux_agent_with_a_shell_gets_a_browser_of_its_own_once_its_server_has_a_place(self):
        """D1: a worker with a shell, its own OS user, on a supported server with a place gets a browser, once, and the
        manager hears it; while its server has sent no reading of its parts, its users or its room, or has no place,
        the default waits with no done mark, because a place can come."""
        self.put(DESKTOP_TEAM)
        for reads in ({}, dict(room=False), dict(user=None), dict(memory=500)):
            if reads:
                self.linux_reads(**reads)
            self.sweep()
            self.assertEqual((self.committed()["agents"]["lone"]["can"], hub.kv_get("default_desktop:lone")),
                             (["shell"], None), reads)
        self.linux_reads()
        self.sweep()
        self.assertEqual(self.committed()["agents"]["lone"]["can"], ["shell", "browser"])
        self.assertIsNotNone(hub.kv_get(hub.BROWSER_DEFAULT + "lone"))
        self.assertIn("a browser of its own on lone", " ".join(self.told()))
        head = self.commits()
        self.sweep()
        self.assertEqual(self.commits(), head)

    def test_his_page_keeps_the_browser_box_that_he_took_off_a_linux_agent(self):
        """His page draws the boxes of `boxes.offered` (owner API 1.216). A Linux agent's Browser box is offered where
        the default would give it a browser, once the default is done with it: none before that (the default turns
        it on at its next passes) and none in setup or with the Shell box off; after his untick it stays there, off, and
        his tick gives it back; where its browser cannot run (no place, D6; no system for it, D8) a box that it holds
        does nothing, and one that it lacks is not offered."""
        self.put(DESKTOP_TEAM)
        self.linux_reads()

        def boxes():
            got = next(line["boxes"] for line in self.team()["lines"] if line["agent"] == "lone")
            return got["on"], got["offered"], got["idle"]
        self.assertEqual(boxes(), (["shell"], ["shell", "web"], []))        # the default comes first: no box off
        self.sweep()
        self.assertEqual(boxes(), (["shell", "browser"], ["shell", "web", "browser"], []))
        self.assertEqual(self.boxes("lone", ["shell"])[0], 200)             # his untick
        self.assertEqual(boxes(), (["shell"], ["shell", "web", "browser"], []))
        self.assertEqual(self.boxes("lone", ["shell", "browser"])[0], 200)  # his tick on his page again
        self.assertEqual(self.committed()["agents"]["lone"]["can"], ["shell", "browser"])
        self.linux_reads(memory=500)                                        # its server has no place now
        self.assertEqual(boxes()[1:], (["shell", "web", "browser"], ["browser"]))
        self.linux_reads(state="unsupported")                               # a system that runs none
        self.assertEqual(boxes()[1:], (["shell", "web", "browser"], ["browser"]))
        self.assertEqual(self.boxes("lone", ["shell"])[0], 200)
        self.assertEqual(boxes()[1], ["shell", "web"])
        self.linux_reads()
        team = self.committed()
        browser = ["shell", "web", "browser"]
        hub.kv_set(hub.BROWSER_DONE_CLEARED, hub.now())             # the release's clear of the old marks ran
        for change, mark, want in (({"can": ["web"]}, 2, (["web"], ["shell", "web"], [])),          # Shell off (D2)
                                   ({"can": ["shell"], "active": False}, None, (["shell"], ["shell", "web"], [])),
                                   ({"can": ["shell", "browser"], "active": False}, 2, (["shell", "browser"], browser,
                                                                                         [])),     # paused
                                   ({"can": ["shell"]}, 1, (["shell"], browser, [])),   # the default is done with it
                                   ({}, 1, (["shell", "web"], ["shell", "web"], []))):   # no list: as the default
            entry = {k: v for k, v in team["agents"]["lone"].items() if k not in ("can", "active")}
            team["agents"]["lone"] = dict(entry, **change)
            self.put(team)
            hub.kv_set("default_desktop:lone", mark)
            self.assertEqual(boxes(), want, change)
        hub.kv_set(hub.BROWSER_DONE_CLEARED, None)                  # before that clear, a done mark is an old one
        team["agents"]["lone"]["can"] = ["shell"]
        self.put(team)
        self.assertEqual(boxes()[1], ["shell", "web"])

    def test_an_agent_in_setup_waits_for_its_default_browser_and_no_card_comes(self):
        """Its setup check would require a browser whose parts wait for the owner's Mac: the default waits for its
        activation. The default raises no item of its own, also where its server has no place (D6)."""
        team = json.loads(json.dumps(DESKTOP_TEAM))
        team["agents"]["lone"]["active"] = False
        self.put(team)
        self.linux_reads()
        self.sweep()
        self.assertEqual((self.committed()["agents"]["lone"]["can"], hub.kv_get("default_desktop:lone")), (["shell"], None))
        del team["agents"]["lone"]["active"]
        self.put(team)
        self.linux_reads(memory=500)
        self.sweep()
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs")["n"], 0)
        self.linux_reads()
        self.sweep()
        self.assertEqual(self.committed()["agents"]["lone"]["can"], ["shell", "browser"])

    def test_a_few_default_browsers_in_each_pass_and_a_mark_only_for_a_browser_that_came(self):
        """Each default browser is a commit under the hub's lock, so one pass gives a few (BROWSER_DEFAULT_PASS); a
        commit that failed leaves no mark of the browser that did not come."""
        team = json.loads(json.dumps(DESKTOP_TEAM))
        names = ["lone", "lone2", "lone3", "lone4"]
        for n in names[1:]:
            team["agents"][n] = dict(team["agents"]["lone"])
        self.put(team)
        data = {"os": {"boot": "b1"}, "browser": {"state": "ready", "ports": []},
                "agents": {n: {"user": f"fleet-{n}", "uid": 1001 + i} for i, n in enumerate(names)},
                "room": {"memory_max": 20000 << 20, "swap_max": None, "swap_total": 2000 << 20}}
        hub.q("INSERT INTO server_status(server,data,reported) VALUES('lone',?,?) ON CONFLICT(server) DO UPDATE SET "
              "data=excluded.data", (json.dumps(data), hub.now()))
        with patch.object(hub, "commit_kit_file", side_effect=OSError("the push failed")):
            self.sweep()
        self.assertEqual([hub.kv_get(hub.BROWSER_DEFAULT + n) for n in names], [None] * 4)
        hub.DEFAULT_ACCESS["retry"].clear()
        self.sweep()
        given = [n for n in names if "browser" in self.committed()["agents"][n]["can"]]
        self.assertEqual(len(given), hub.BROWSER_DEFAULT_PASS)
        self.sweep()
        self.assertEqual(sum("browser" in self.committed()["agents"][n]["can"] for n in names), 4)

    def test_a_default_browser_whose_commit_came_keeps_its_mark_when_a_step_after_it_fails(self):
        """A push can land before its own error, and the hub can stop between the commit and its apply: the browser
        is in team.json, so its mark must be too, or the owner's Shell-off write would meet D2 for a browser that he
        did not choose."""
        self.put(DESKTOP_TEAM)
        self.linux_reads()
        real_commit = hub.commit_kit_file

        def landed(*args, **kwargs):
            real_commit(*args, **kwargs)
            raise OSError("the push ran out of time after it landed")
        with patch.object(hub, "commit_kit_file", landed):
            self.sweep()
        self.assertIn("browser", self.committed()["agents"]["lone"]["can"])
        self.assertIsNotNone(hub.kv_get(hub.BROWSER_DEFAULT + "lone"))
        self.put(DESKTOP_TEAM)
        for key in (hub.BROWSER_DEFAULT + "lone", "default_desktop:lone"):
            hub.kv_set(key, None)
        hub.DEFAULT_ACCESS["retry"].clear()
        real, tries = hub.apply_team, []

        def apply(new, *args, **kwargs):
            tries.append(1)
            if len(tries) == 1:
                raise RuntimeError("the hub stopped")
            return real(new, *args, **kwargs)
        with patch.object(hub, "apply_team", apply):
            self.sweep()
        self.assertIn("browser", self.committed()["agents"]["lone"]["can"])
        self.assertIsNotNone(hub.kv_get(hub.BROWSER_DEFAULT + "lone"))

    def test_a_default_browser_that_a_rule_refuses_ends_its_default(self):
        """As on a Mac: a give that validate_team refuses ends the default for the agent, and the log says why, so that
        no such agent takes one of the few gives of each later pass (BROWSER_DEFAULT_PASS)."""
        self.put(DESKTOP_TEAM)
        self.linux_reads()
        real = hub.validate_team

        def refuse(team, *args, **kwargs):
            if "browser" in team["agents"]["lone"]["can"]:
                raise ValueError("a rule refuses it")
            return real(team, *args, **kwargs)
        with patch.object(hub, "validate_team", refuse):
            self.sweep()
        self.assertEqual((self.committed()["agents"]["lone"]["can"], str(hub.kv_get("default_desktop:lone")),
                          hub.kv_get(hub.BROWSER_DEFAULT + "lone")), (["shell"], "1", None))

    def test_the_manager_on_a_linux_server_gets_no_browser_by_default(self):
        team = json.loads(json.dumps(DESKTOP_TEAM))
        team["agents"]["manager"]["machine"] = "lone"       # a new fleet's manager on a server of its own
        self.put(team)
        self.linux_reads()
        self.sweep()
        self.assertEqual(self.committed()["agents"]["manager"]["can"], [])

    def test_the_linux_default_gives_none_where_its_browser_could_not_run(self):
        """A closed agent (D2), one that runs as the server service's user (D11's proof refuses it), a server whose
        system runs none (D8), the hub's own server (D6) and the manager get no browser by default: the done mark."""
        for name, change, reads in (("lone", lambda t: t["agents"]["lone"].update(can=["web"]), {}),
                                    ("lone", None, dict(user="fleet")), ("lone", None, dict(state="unsupported")),
                                    ("hal", lambda t: (t["servers"].update(hub={"kind": "linux", "user": "fleet"}),
                                                       t["hub"].update(shared=True),
                                                       t["agents"].update(hal={"role": "worker", "runtime": "claude",
                                                                               "machine": "hub", "can": ["shell"]})),
                                     {})):
            team = json.loads(json.dumps(DESKTOP_TEAM))
            if change:
                change(team)
            if team != self.committed():
                self.put(team)
            for n in (name, "manager"):
                hub.kv_set(f"default_desktop:{n}", None)
            self.linux_reads(**reads)
            self.sweep()
            self.assertNotIn("browser", self.committed()["agents"][name]["can"], name)
            self.assertEqual(str(hub.kv_get(f"default_desktop:{name}")), "1", (name, reads))
            self.assertEqual(self.committed()["agents"]["manager"]["can"], [])

    def test_the_owners_untick_ends_the_linux_default_and_the_old_done_marks_go_once(self):
        """His untick is his own removal, which the default respects; the done mark that each pass wrote for a Linux
        agent before this rule goes once, and a removal of his stays."""
        self.put(DESKTOP_TEAM)
        hub.kv_set("default_desktop:lone", 1)               # a pass of before wrote it: Linux got nothing
        hub.kv_set("default_desktop:filer", 2)              # his own removal of another agent
        self.linux_reads()
        self.sweep()
        self.assertEqual(self.committed()["agents"]["lone"]["can"], ["shell", "browser"])
        self.assertEqual(str(hub.kv_get("default_desktop:filer")), "2")
        code, receipt = self.boxes("lone", ["shell"])
        self.assertEqual(code, 200, receipt)
        self.assertEqual((str(hub.kv_get("default_desktop:lone")), hub.kv_get(hub.BROWSER_DEFAULT + "lone")), ("2", None))
        self.sweep()
        self.assertEqual(self.committed()["agents"]["lone"]["can"], ["shell"])
        hub.kv_set("default_desktop:lone", 1)               # the one-time clear ran: a later mark of 1 stays
        self.sweep()
        self.assertEqual(str(hub.kv_get("default_desktop:lone")), "1")

    def test_a_shell_box_that_goes_off_takes_the_default_browser_and_brings_it_back(self):
        """The hub's own removal: D2 never refuses his write for a browser that he did not choose, no removal mark of
        his is set, and the default gives the browser again when the Shell box comes back."""
        team = json.loads(json.dumps(DESKTOP_TEAM))
        team["agents"]["lone"]["runtime"] = "claude"        # only a Claude Code session can be held closed
        self.put(team)
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES('lone',?,?) ON CONFLICT(agent) DO UPDATE SET "
              "data=excluded.data", (json.dumps({"features": [hub.SHELL_BOX]}), hub.now()))
        self.linux_reads()
        self.sweep()
        self.assertEqual(self.committed()["agents"]["lone"]["can"], ["shell", "browser"])
        code, receipt = self.boxes("lone", ["browser"])     # he unticks the Shell box only
        self.assertEqual(code, 200, receipt)
        # his app checks that what it gets back is what it sent: the write is his, as he sent it
        self.assertEqual([c["after"] for c in receipt["changed"] if c["field"] == "can"], [["browser"]])
        hub.browser_place_sweep(hub.now())                  # no D2 notice for a browser that the hub takes itself
        self.assertEqual([r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say'")
                          if "with its Shell box off" in r["text"]], [])
        self.sweep()                                        # then the hub takes the default's browser in its own commit
        self.assertEqual(self.committed()["agents"]["lone"]["can"], [])
        self.assertIsNotNone(hub.kv_get(hub.BROWSER_DEFAULT + "lone"))
        self.assertIn("[hub] Fleet took back the browser that it gave lone by default, because its Shell box is off: "
                      "it can now use nothing.", self.told())         # the manager's view of the agent is current
        self.assertNotEqual(str(hub.kv_get("default_desktop:lone")), "2")
        self.sweep()
        self.assertEqual(self.committed()["agents"]["lone"]["can"], [])
        code, receipt = self.boxes("lone", ["shell"])
        self.assertEqual(code, 200, receipt)
        self.sweep()
        self.assertEqual(self.committed()["agents"]["lone"]["can"], ["shell", "browser"])

    def test_the_release_step_takes_back_every_default_browser_and_keeps_the_owners_ticks(self):
        team = json.loads(json.dumps(DESKTOP_TEAM))
        team["agents"]["alpha"]["can"] = ["shell", "browser"]   # his own tick, on the Mac
        self.put(team)
        self.linux_reads()
        self.sweep()
        self.assertEqual(hub.take_back_default_browsers("the default's rule is gone"), ["lone"])
        agents = self.committed()["agents"]
        self.assertEqual((agents["lone"]["can"], "browser" in agents["alpha"]["can"]), (["shell"], True))
        self.assertIsNone(hub.kv_get(hub.BROWSER_DEFAULT + "lone"))

    # ---- a browser task's own tools
    def test_a_browser_task_runs_chromes_tools_without_asking(self):
        conf = {"role": "worker", "runtime": "claude", "allow": list(hub.FULL_ACCESS["claude"]["allow"])}

        def allow(needs):
            flag, settings = shlex.split(fleet.settings_arg("alpha", conf, "T-1", needs=needs))
            return json.loads(settings)["permissions"]["allow"]
        self.assertIn(fleet.CHROME_TOOLS, allow("browser"))
        self.assertNotIn(fleet.CHROME_TOOLS, allow("none"))
        self.assertNotIn(fleet.CHROME_TOOLS, allow("screen"))
        self.assertNotIn(fleet.CHROME_TOOLS, conf["allow"])        # the agent's own list is not changed


if __name__ == "__main__":
    unittest.main()

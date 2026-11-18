"""What every agent holds unless the owner says otherwise (the owner, 28 October 2026: "it is essential that they all
have access to secrets!", and "a mac studio server should come by default with computer and browser use"): each
worker and lead gets its machine's vault once that vault can serve it, and an agent on a Mac gets the browser and the
screen of its desktop. The hub gives each once; the owner's own word on it is final. In-process hub and temporary Git
repositories; no helper, vault, Chrome or AI call."""
import json
import shlex
import unittest

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
        self.assertEqual(team["agents"]["lone"]["vault"], "broker")     # given, and Linux has no desktop to give
        self.assertEqual((hub.kv_get("default_vault:lone"), hub.kv_get("default_desktop:lone")), ("1", "1"))
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

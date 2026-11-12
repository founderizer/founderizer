"""One sitting at a new Mac (the owner, 31 October 2026): the app names the first agent with the join code, and the hub
carries the setup from there, through the real routes, to the page that only a real browser can answer."""
import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

import hub
import lifecycle
from test_servers import NEW, OWNER, FakeLife, Servers, ServerService, git


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(cls(name) for cls in (MacSetup, MacService, Readings)
                              for name in cls.__dict__ if name.startswith("test_"))


class MacSetup(Servers):
    def setUp(self):
        super().setUp()
        self.fresh_fleet()
        self.said = []
        real = hub.emit
        patcher = patch.object(hub, "emit", lambda *a, **k: (self.said.append(a), real(*a, **k))[1])
        patcher.start()
        self.addCleanup(patcher.stop)

    def joined_mac(self, name="mini", agent="juno"):
        status, answer = self.owner("/ui/servers/join", kind="mac", agent=agent, runtime="claude")
        self.assertEqual(status, 200, answer)
        self.next_name = name
        status, result = self.join(answer["code"])
        self.assertEqual(status, 200, result)
        return result

    def row(self, server="mini"):
        return hub.q1("SELECT * FROM mac_setups WHERE server=?", (server,))

    def sweep(self):
        with hub.LOCK:
            hub.mac_setup_sweep(hub.now())

    def report(self, boot="boot-1", browser=True, name="mini", **desktop):
        status, answer = self.service(f"/server/{name}/status", {
            "revision": hub.kit_revision(fresh=True), "os": {"name": "macOS 26.6", "boot": boot},
            "security": {"desktop": dict({"locked": False, "chrome": True, "extension": True, "browser": browser}, **desktop)},
            "runtimes": {"codex": {"version": None, "signed_in": None}, "claude": {"version": "2.1.316", "signed_in": True}},
            "access": {"user": "dana"}}, key="server-key-of-mini")
        self.assertEqual(status, 200, answer)
        hub.q("UPDATE server_status SET reported=? WHERE server=?", (hub.now() + len(self.said) * 0.001, name))

    def finish(self, boot="boot-1", restarts=True):
        return self.service("/server/mini/setup", {"boot": boot, "restarts": restarts}, key="server-key-of-mini")

    def ready_to_finish(self):
        self.joined_mac()
        self.report()
        self.sweep()
        self.assertEqual(self.row()["state"], "waiting")

    def check_passes(self):
        check = hub.q1("SELECT * FROM machine_checks WHERE agent='juno' ORDER BY id DESC LIMIT 1")
        hub.q("UPDATE machine_checks SET state='completed', completed=?, verify='[]' WHERE id=?", (hub.now(), check["id"]))

    def proving(self, restarts=True):
        self.ready_to_finish()
        self.assertEqual(self.finish(restarts=restarts)[0], 200)
        if restarts:
            self.report(boot="boot-2")
        else:
            self.report()
        self.sweep()
        self.assertEqual(self.row()["state"], "checking")
        self.check_passes()
        latest = hub.q1("SELECT * FROM machine_checks WHERE agent='juno' ORDER BY id DESC LIMIT 1")
        with patch.object(hub, "activation_missing", lambda agent: ([], latest)):
            self.sweep()
        self.assertEqual(self.row()["state"], "proving")
        return self.row()

    def manager_heard(self):
        return [a[2] for a in self.said if a[0] == hub.manager_name() and a[1] == "say"]

    def chosen_mac(self, runtime, chatgpt, name="mini", agent="juno"):
        status, answer = self.owner("/ui/servers/join", kind="mac", agent=agent, runtime=runtime, chatgpt=chatgpt)
        self.assertEqual(status, 200, answer)
        self.next_name = name
        status, result = self.join(answer["code"])
        self.assertEqual(status, 200, result)
        return result

    def needs(self, name="mini", key="server-key-of-mini"):
        status, answer = self.service(f"/server/{name}/needs", key=key)
        self.assertEqual(status, 200, answer)
        return answer

    def can(self, agent="juno"):
        return hub.agents()[agent].get("can")

    def access_sweep(self):
        hub.DEFAULT_ACCESS["at"] = 0.0
        with hub.LOCK:
            hub.default_access_sweep(hub.now())

    def test_the_choice_of_ai_is_checked(self):
        for body in ({"kind": "mac", "agent": "juno", "runtime": "codex", "chatgpt": False},
                     {"kind": "mac", "agent": "juno", "runtime": "claude", "chatgpt": "yes"},
                     {"kind": "mac", "chatgpt": True}):
            status, answer = self.owner("/ui/servers/join", **body)
            self.assertEqual(status, 400, answer)

    def test_a_join_for_chatgpt_alone_offers_no_claude_extension(self):
        self.assertIs(self.chosen_mac("codex", True)["extension"], False)
        self.assertEqual(self.row()["chatgpt"], 1)

    def test_a_join_for_claude_offers_its_extension_and_a_repeat_says_the_same(self):
        status, answer = self.owner("/ui/servers/join", kind="mac", agent="juno", runtime="claude", chatgpt=False)
        self.assertEqual(status, 200, answer)
        self.next_name = "mini"
        for replayed in (False, True):
            status, result = self.join(answer["code"])
            self.assertEqual(status, 200, result)
            self.assertIs(result["replayed"], replayed)
            self.assertIs(result["extension"], True)

    def test_claude_alone_holds_no_screen_until_chatgpt_is_signed_in_at_that_mac(self):
        self.chosen_mac("claude", False)
        self.report(chatgpt=False)
        self.sweep()
        self.assertIn("browser", self.can())
        self.assertNotIn("screen", self.can())
        self.assertEqual(self.needs()["chatgpt"], False)
        self.access_sweep()
        self.assertNotIn("screen", self.can())
        self.assertFalse(hub.kv_get("default_desktop:juno"))        # it waits, and it has not ended
        self.report(chatgpt=True)
        self.access_sweep()
        self.assertIn("screen", self.can())
        self.assertEqual(hub.agents()["juno"]["screen_command"], hub.MAC_SCREEN_COMMAND)
        self.assertTrue(hub.kv_get("default_desktop:juno"))
        self.assertEqual(self.needs()["chatgpt"], True)

    def test_a_mac_for_chatgpt_alone_proves_itself_on_its_screen(self):
        self.chosen_mac("codex", True)
        self.report(browser=None, chatgpt=False)
        self.sweep()
        self.assertEqual(hub.agents()["juno"]["runtime"], "codex")
        self.assertNotIn("browser", self.can())
        self.assertEqual({k: self.needs()[k] for k in ("browser", "chatgpt", "own_copy", "state")},
                         {"browser": False, "chatgpt": True, "own_copy": True, "state": "waiting"})
        self.assertEqual(self.finish()[0], 200)
        self.report(boot="boot-2", browser=None, chatgpt=True)
        self.sweep()
        self.assertEqual(self.row()["state"], "checking")
        self.check_passes()
        latest = hub.q1("SELECT * FROM machine_checks WHERE agent='juno' ORDER BY id DESC LIMIT 1")
        with patch.object(hub, "activation_missing", lambda agent: ([], latest)):
            self.sweep()
        self.assertEqual(self.row()["state"], "proving")
        task = hub.q1("SELECT * FROM tasks WHERE id=?", (self.row()["task"],))
        self.assertEqual(task["needs"], "screen")
        self.assertIn("Computer Use", task["details"] if "details" in task.keys() else task["body"])
        self.assertIn("click the address bar", task["details"])        # no browser access: the screen alone
        self.assertIn("Use no browser access", task["details"])

    def test_both_keeps_chatgpt_in_the_needs_while_its_sitting_runs(self):
        self.chosen_mac("claude", True)
        self.report(chatgpt=False)
        self.sweep()
        self.assertNotIn("screen", self.can())
        self.assertEqual({k: self.needs()[k] for k in ("browser", "chatgpt")}, {"browser": True, "chatgpt": True})

    def test_an_app_from_before_the_choice_has_both(self):
        self.joined_mac()
        self.assertEqual({k: self.needs()[k] for k in ("browser", "chatgpt")}, {"browser": True, "chatgpt": True})

    def test_a_mac_that_never_had_a_sitting_reads_its_agents_alone(self):
        self.joined("mini")
        self.assertEqual(self.service("/server/mini/needs")[1],
                         {"agents": [], "browser": False, "chatgpt": False, "own_copy": False, "state": None,
                          "screen_task": False, "locked": False})

    def test_the_needs_are_for_that_server_alone(self):
        self.joined_mac()
        self.assertEqual(self.service("/server/mini/needs", key="another-key")[0], 403)

    def test_a_stopped_sitting_keeps_the_owners_choice(self):
        self.chosen_mac("claude", True)
        self.report(chatgpt=False)
        self.sweep()
        hub.q("UPDATE mac_setups SET state='stopped' WHERE server='mini'")
        self.assertEqual(self.needs()["chatgpt"], True)
        hub.q("UPDATE mac_setups SET state='done' WHERE server='mini'")
        self.assertEqual(self.needs()["chatgpt"], False)

    def test_his_removal_of_the_screen_holds_and_a_small_change_does_not_end_the_wait(self):
        self.chosen_mac("claude", False)
        self.report(chatgpt=False)
        self.sweep()
        self.report(chatgpt=True)
        self.access_sweep()
        self.assertIn("screen", self.can())
        team = hub.team_view(hub.kit_revision(fresh=True))[1]
        hub.save_agent_settings("juno", {"can": [c for c in self.can() if c != "screen"], "base_sha256": team})
        self.assertEqual(str(hub.kv_get("default_desktop:juno")), "2")
        self.access_sweep()
        self.assertNotIn("screen", self.can())

    def test_a_sitting_on_the_screen_waits_for_chatgpt_at_its_reading(self):
        self.chosen_mac("codex", True)
        self.report(browser=None, chatgpt=False)
        self.sweep()
        self.assertEqual(self.finish()[0], 200)
        self.report(boot="boot-2", browser=None, chatgpt=False)
        self.sweep()
        self.assertEqual(self.row()["state"], "finished")           # not yet: the proof would stop

    def test_a_stopped_sitting_can_finish_again(self):
        self.proving()
        hub.q("UPDATE mac_setups SET state='stopped', tries=2, checks=1, seen=5 WHERE server='mini'")
        self.assertEqual(self.finish(boot="boot-3")[0], 200)
        row = self.row()
        self.assertEqual((row["state"], row["boot"], row["tries"], row["checks"], row["seen"]),
                         ("finished", "boot-3", 0, 0, None))

    def test_a_mac_whose_chatgpt_signed_out_is_news_for_its_screen(self):
        self.proving()
        hub.q("UPDATE mac_setups SET state='done' WHERE server='mini'")
        self.said.clear()
        self.report(boot="boot-2", chatgpt=False)
        self.desktop()
        self.report(boot="boot-2", chatgpt=False)
        self.desktop()
        self.assertIn("ChatGPT is signed out", self.manager_heard()[-1])

    def test_the_join_code_of_a_mac_names_its_first_agent(self):
        for body, words in (({"kind": "linux", "agent": "juno", "runtime": "claude"}, "first agent of a Mac"),
                            ({"kind": "mac", "agent": "Not A Name!", "runtime": "claude"}, "first agent of a Mac"),
                            ({"kind": "mac", "agent": "juno", "runtime": "grok"}, "first agent of a Mac"),
                            ({"kind": "mac", "agent": "juno", "runtime": ["claude"]}, "first agent of a Mac"),
                            ({"kind": "mac", "agent": "owner", "runtime": "claude"}, "first agent of a Mac"),
                            ({"kind": "mac", "agent": "manager", "runtime": "claude"}, "first agent of a Mac")):
            status, answer = self.owner("/ui/servers/join", **body)
            self.assertEqual(status, 400, answer)
            self.assertIn(words, answer["error"])
        status, answer = self.owner("/ui/servers/join", kind="mac", agent="juno", runtime="claude")
        self.assertEqual(status, 200, answer)
        self.assertAlmostEqual(answer["expires_at"], hub.now() + hub.MAC_JOIN_LIFE, delta=5)
        row = hub.q1("SELECT agent, runtime FROM join_codes ORDER BY id DESC LIMIT 1")
        self.assertEqual((row["agent"], row["runtime"]), ("juno", "claude"))

    def test_a_join_without_a_first_agent_starts_no_setup(self):
        self.joined(name="mini")
        self.assertIsNone(self.row())

    def test_the_hub_adds_the_agent_with_the_first_reading_and_the_installer_signs_it_in(self):
        self.joined_mac()
        self.assertEqual(self.row()["state"], "add")
        self.sweep()                            # nothing has reported yet
        self.assertEqual(self.row()["state"], "add")
        self.report()
        self.sweep()
        self.assertEqual(self.row()["state"], "waiting")
        entry = self.origin_team_entry("juno")
        self.assertEqual((entry["machine"], entry["runtime"], entry["active"]), ("mini", "claude", False))
        self.assertIn("browser", entry["can"])
        jobs = self.service("/server/mini/jobs", key="server-key-of-mini")[1]["jobs"]
        self.assertEqual([(j["agent"], j["sign_in"]) for j in jobs], [("juno", "at_the_mac")])

    def origin_team_entry(self, agent):
        return json.loads(git("show", "HEAD:team.json", cwd=self.kit))["agents"][agent]

    def test_a_refused_add_goes_again_with_each_reading_and_a_count_ends_it(self):
        self.joined_mac()
        with patch.object(hub, "add_server_agent", side_effect=hub.Refusal(502, "the fetch failed")):
            for tries in range(1, hub.MAC_SETUP_READINGS):
                self.report()
                self.sweep()
                self.sweep()            # no new reading: no new try
                self.assertEqual((self.row()["state"], self.row()["tries"]), ("add", tries))
            self.report()
            self.sweep()
        self.assertEqual(self.row()["state"], "stopped")
        heard = self.manager_heard()[-1]
        self.assertIn("could not be added", heard)
        self.assertNotIn("Only hands", heard)           # no person at a Mac puts this right

    def test_a_refused_add_that_passes_goes_on(self):
        self.joined_mac()
        with patch.object(hub, "add_server_agent", side_effect=hub.Refusal(502, "the fetch failed")):
            self.report()
            self.sweep()
        self.report()
        self.sweep()
        self.assertEqual((self.row()["state"], self.row()["tries"]), ("waiting", 0))

    def test_a_hub_restart_between_the_two_writes_of_the_add_loses_nothing(self):
        self.joined_mac()
        self.report()
        self.sweep()
        hub.q("UPDATE mac_setups SET state='add' WHERE server='mini'")
        self.sweep()
        self.assertEqual(self.row()["state"], "waiting")

    def test_a_failed_install_stops_the_setup_and_the_manager_says_so(self):
        self.ready_to_finish()
        hub.q("UPDATE server_jobs SET state='failed', detail='no network' WHERE agent='juno'")
        self.sweep()
        self.assertEqual(self.row()["state"], "stopped")
        self.assertIn("could not be installed: no network", self.manager_heard()[-1])

    def test_the_last_press_counts_once_and_a_mac_with_no_setup_is_refused(self):
        self.assertEqual(self.finish()[0], 403)         # nothing has joined
        self.joined_mac()
        self.assertEqual(self.finish()[0], 409)         # no agent yet, so the press would be lost
        self.report()
        self.sweep()
        self.assertEqual(self.finish(boot="")[0], 400)
        self.assertEqual(self.finish()[0], 200)
        self.assertEqual(self.finish(boot="boot-9")[0], 200)
        self.assertEqual((self.row()["state"], self.row()["boot"]), ("finished", "boot-1"))
        self.assertEqual(hub.mac_setup_finish("nothing", "b", True)[0], 404)

    def test_the_hub_waits_for_a_new_boot_and_chrome_before_its_check(self):
        self.ready_to_finish()
        self.finish()
        self.sweep()
        self.assertEqual(self.row()["state"], "finished")
        self.report(boot="boot-1")                      # the same boot: this reading says nothing of a restart
        self.sweep()
        self.assertEqual((self.row()["state"], self.row()["tries"]), ("finished", 0))
        self.report(boot="boot-2", browser=False)       # back, and Chrome has not connected yet
        self.sweep()
        self.assertEqual((self.row()["state"], self.row()["tries"]), ("finished", 1))
        self.report(boot="boot-2")
        self.sweep()
        self.assertEqual(self.row()["state"], "checking")
        self.assertEqual(hub.q1("SELECT state FROM machine_checks WHERE agent='juno'")["state"], "requested")

    def test_a_chrome_that_never_connects_ends_with_words_for_the_owner(self):
        self.ready_to_finish()
        self.finish()
        for _ in range(hub.MAC_SETUP_READINGS):
            self.report(boot="boot-2", browser=False)
            self.sweep()
        self.assertEqual(self.row()["state"], "stopped")
        self.assertIn("does not answer", self.manager_heard()[-1])

    def test_what_still_stops_the_agent_is_checked_again_and_a_count_ends_it(self):
        self.ready_to_finish()
        self.finish()
        missing = [{"kind": "mac", "ref": "awake", "detail": "System sleep after 10 minutes."}]
        with patch.object(hub, "activation_missing", lambda agent: (missing, None)):
            for tries in range(1, hub.MAC_SETUP_READINGS):
                self.report(boot="boot-2")
                self.sweep()
                self.assertEqual(self.row()["state"], "checking")
                self.check_passes()
                self.sweep()
                self.assertEqual((self.row()["state"], self.row()["checks"]), ("finished", tries))
                self.sweep()                    # no new reading: nothing moves
                self.assertEqual(self.row()["state"], "finished")
            self.report(boot="boot-2")
            self.sweep()
            self.check_passes()
            self.sweep()
        self.assertEqual(self.row()["state"], "stopped")
        self.assertIn("System sleep after 10 minutes.", self.manager_heard()[-1])

    def test_a_chrome_that_was_slow_leaves_every_check_its_own_count(self):
        self.ready_to_finish()
        self.finish()
        for _ in range(hub.MAC_SETUP_READINGS - 1):
            self.report(boot="boot-2", browser=False)
            self.sweep()
        self.report(boot="boot-2")
        self.sweep()
        self.check_passes()
        missing = [{"kind": "machine", "ref": "update", "detail": "Its server runs an older version."}]
        with patch.object(hub, "activation_missing", lambda agent: (missing, None)):
            self.sweep()
        self.assertEqual((self.row()["state"], self.row()["checks"]), ("finished", 1))

    def test_a_rename_in_the_setup_moves_the_setup_with_it(self):
        self.assertIn(("mac_setups", "agent"), hub.AGENT_COLUMNS)

    def test_the_agent_goes_active_and_its_task_opens_a_page_of_the_hub(self):
        row = self.proving()
        self.assertNotIn("active", self.origin_team_entry("juno"))
        task = hub.q1("SELECT * FROM tasks WHERE id=?", (row["task"],))
        self.assertEqual((task["owner"], task["requester"], task["needs"]), ("juno", hub.manager_name(), "browser"))
        self.assertIn(f"/mac-setup/{row['token']}", task["details"])

    def test_only_the_pages_own_script_ends_the_proof(self):
        row = self.proving()
        status, page = self.page(f"/mac-setup/{row['token']}")
        self.assertEqual(status, 200)
        self.assertIn("fetch(location.pathname", page)
        self.assertEqual(self.page("/mac-setup/not-this-one")[0], 404)
        self.sweep()
        self.assertEqual(self.row()["state"], "proving")    # a read of the page is no proof
        self.assertEqual(self.request("/mac-setup/not-this-one", {}, source=NEW)[0], 404)
        self.assertEqual(self.request(f"/mac-setup/{row['token']}", {}, source=OWNER)[0], 404)  # Chrome on another Mac
        self.sweep()
        self.assertEqual(self.row()["state"], "proving")
        self.assertEqual(self.request(f"/mac-setup/{row['token']}", {}, source=NEW)[0], 200)
        self.sweep()
        self.assertEqual(self.row()["state"], "done")
        heard = self.manager_heard()[-1]
        self.assertIn("message_owner", heard)
        self.assertTrue(heard.endswith("Juno is ready on mini."), heard)
        self.assertEqual(self.page(f"/mac-setup/{row['token']}")[0], 404)   # the page ends with the proof

    def page(self, path):
        import urllib.error
        import urllib.request
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(urllib.request.Request(self.base + path), timeout=5) as answer:
                return answer.status, answer.read().decode()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, e.read().decode()

    def test_a_task_that_ended_without_the_page_stops_the_setup(self):
        row = self.proving()
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (row["task"],))
        self.sweep()
        self.assertEqual(self.row()["state"], "stopped")
        self.assertIn("never opened", self.manager_heard()[-1])

    def test_a_mac_with_filevault_on_needs_no_restart_and_the_last_line_says_so(self):
        row = self.proving(restarts=False)
        hub.q("UPDATE mac_setups SET seen=? WHERE server='mini'", (hub.now(),))
        self.sweep()
        self.assertEqual(row["restarts"], 0)
        self.assertIn("a person must unlock this Mac after a power cut", self.manager_heard()[-1])

    def test_a_removed_server_takes_its_setup_with_it(self):
        self.joined_mac()
        self.assertEqual(self.owner("/ui/servers/mini/remove", base_sha256=self.team_sha())[0], 200)
        self.assertIsNone(self.row())

    def desktop(self):
        with hub.LOCK:
            hub.mac_desktop_sweep()

    def test_what_only_hands_can_fix_reaches_the_manager_once_in_the_second_reading(self):
        self.proving()
        hub.q("UPDATE mac_setups SET state='done' WHERE server='mini'")
        self.said.clear()
        self.report(boot="boot-2", locked=True)
        self.desktop()
        self.assertEqual(self.manager_heard(), [])      # one reading: it may be gone in the next
        self.report(boot="boot-2", locked=True)
        self.desktop()
        self.desktop()
        self.report(boot="boot-2", locked=True)
        self.desktop()
        heard = [h for h in self.manager_heard() if "screen is locked" in h]
        self.assertEqual(len(heard), 1, heard)
        self.assertIn("raise_needs_you", heard[0])
        self.report(boot="boot-2")
        self.desktop()                                  # put right: the next time is news again
        self.report(boot="boot-2", browser=False)
        self.desktop()
        self.report(boot="boot-2", browser=False)
        self.desktop()
        self.assertIn("signed out", self.manager_heard()[-1])

    def test_macos_setup_screens_are_said_first_and_hold_a_screen_task(self):
        """4 November 2026: macOS installed an update by itself, and its setup screens stayed open on a Mac that nobody
        watched. The manager hears it once, ahead of the locked screen; a screen task waits, a browser task does not."""
        self.proving()
        hub.q("UPDATE mac_setups SET state='done' WHERE server='mini'")
        self.said.clear()
        for _ in range(3):
            self.report(boot="boot-2", locked=True, setup=True)
            self.desktop()
        heard = self.manager_heard()
        self.assertEqual(self.clicks(), [])                 # T-1 holds the desktop, so no agent can press Continue now
        self.assertEqual(len([h for h in heard if "the setup screens of macOS are open on its screen" in h]), 1, heard)
        self.assertEqual([h for h in heard if "screen is locked" in h], [])
        self.assertEqual(hub.desktop_refusal("juno", "screen", "manager"),
                         "The setup screens of macOS are open on mini; a screen task waits until they are finished.")
        self.assertIsNone(hub.desktop_refusal("juno", "browser", "manager"))
        self.report(boot="boot-2", setup=False)
        self.desktop()
        self.assertNotIn("setup screens", hub.desktop_refusal("juno", "screen", "manager") or "")     # T-1 may hold it
        self.assertIsNone(hub.kv_get("desktop_told:mini"))         # put right: the next time is news again

    def clicks(self):
        return hub.q("SELECT * FROM tasks WHERE title=? ORDER BY id", (hub.SETUP_CLICK["title"],))

    def updated_mac(self):
        """A proved Mac whose screen agent has nothing else on its desktop, then two readings of the setup screens."""
        self.proving()
        hub.q("UPDATE mac_setups SET state='done' WHERE server='mini'")
        hub.q("UPDATE tasks SET needs='none' WHERE owner='juno'")       # the proof's task no longer holds the desktop
        self.assertIn("screen", self.can())
        self.said.clear()
        for _ in range(2):
            self.report(boot="boot-2", setup=True)
            self.desktop()

    def setup_heard(self):
        return [h for h in self.manager_heard() if "setup screens" in h]

    def test_the_screen_agent_presses_continue_before_anybody_asks_the_owner(self):
        """The owner's yes of 7 November 2026: after a macOS update, the screen agent of the Mac presses Continue on
        Update Complete, and only that. When the screens close, nobody else hears of them."""
        self.updated_mac()
        click, = self.clicks()
        self.assertEqual((click["owner"], click["requester"], click["needs"]), ("juno", hub.manager_name(), "screen"))
        self.assertIn('the screen titled "Update Complete"', click["details"])
        self.assertIn("On every other screen, click nothing", click["details"])
        self.assertEqual(hub.desktop_refusal("juno", "screen", "manager"),      # no agent's own screen task passes
                         "The setup screens of macOS are open on mini; a screen task waits until they are finished.")
        for _ in range(2):
            self.report(boot="boot-2", setup=True)
            self.desktop()
        self.assertEqual(len(self.clicks()), 1)
        self.assertEqual(self.setup_heard(), [])
        self.report(boot="boot-2", setup=False)
        self.desktop()
        self.assertEqual(self.setup_heard(), [])
        self.assertIsNone(hub.kv_get("desktop_click:mini"))        # the next update gets a task of its own

    def test_screens_still_open_after_the_click_go_to_the_owner_through_the_manager(self):
        """FileVault's offer after a major upgrade stays the owner's: the manager hears once, in a reading after the
        task ended, with the task that came first."""
        self.updated_mac()
        click, = self.clicks()
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (click["id"],))
        self.desktop()
        self.assertEqual(self.setup_heard(), [])             # that reading can be older than the task's end
        for _ in range(3):
            self.report(boot="boot-2", setup=True)
            self.desktop()
        heard = self.setup_heard()
        self.assertEqual(len(heard), 1, heard)
        self.assertIn(f"after Juno's task {hub.tref(click['id'])}, which was to press Continue on Update Complete", heard[0])
        self.assertIn("raise_needs_you", heard[0])
        self.assertEqual(len(self.clicks()), 1)

    def test_with_chatgpt_signed_out_the_manager_hears_at_once(self):
        """Computer Use runs through the ChatGPT app: without its sign-in no agent can press Continue."""
        self.proving()
        hub.q("UPDATE mac_setups SET state='done' WHERE server='mini'")
        hub.q("UPDATE tasks SET needs='none' WHERE owner='juno'")
        self.said.clear()
        for _ in range(2):
            self.report(boot="boot-2", setup=True, chatgpt=False)
            self.desktop()
        self.assertEqual(self.clicks(), [])
        self.assertEqual(len(self.setup_heard()), 1)

    def test_a_mac_with_no_agent_in_its_chrome_is_no_news(self):
        self.proving()
        hub.q("UPDATE mac_setups SET state='done' WHERE server='mini'")
        self.said.clear()
        with patch.object(hub, "browser_tabs", lambda agent: False), \
                patch.dict(hub.agents()["juno"], {"can": ["shell", "web", "browser"]}):
            self.report(boot="boot-2", locked=True)
            self.desktop()
            self.report(boot="boot-2", locked=True)
            self.desktop()
        self.assertEqual(self.manager_heard(), [])

    def test_a_mac_in_its_setup_is_no_news(self):
        self.ready_to_finish()
        self.said.clear()
        self.report(locked=True)
        self.report(locked=True)
        self.desktop()
        self.desktop()
        self.assertEqual(self.manager_heard(), [])


class MacService(ServerService):
    """server.py on a Mac: the sign-in at its own screen, and Chrome after a restart."""

    def signed_out_install(self, job):
        calls = []
        svc = self.service(platform="darwin", report=False)
        svc.user_step = lambda *a: None
        svc.runtime_step = lambda *a: "/x/claude"
        svc.checkout_step = lambda *a: "/x"
        svc.key_step = lambda *a: None
        svc.service_step = lambda *a: calls.append("service")
        svc.sign_in_step = lambda *a: calls.append("sign_in")
        svc.post = lambda *a, **k: calls.append(a[1])
        svc.install(job)
        return calls

    def test_an_agent_of_the_sitting_is_signed_in_at_the_mac_and_the_job_ends_without_the_hub(self):
        self.assertEqual(self.signed_out_install({"id": 1, "agent": "juno", "runtime": "claude", "sign_in": "at_the_mac"}),
                         ["service", "done"])
        self.assertEqual(self.signed_out_install({"id": 2, "agent": "juno", "runtime": "claude"}),
                         ["service", "sign_in", "done"])

    def chrome(self, state):
        folder = self.home / "Library/Application Support/Google/Chrome/Default"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "Secure Preferences").write_text(json.dumps({"extensions": {"settings": {
            lifecycle.CLAUDE_EXTENSION: state}}}))

    def test_a_chrome_that_does_not_start_stops_no_reading(self):
        self.chrome({"state": 1})
        svc = self.service(platform="darwin", report=False, answers={"pgrep": (1, "", "")})
        reports = []
        svc.report = lambda: (reports.append(svc.clock()), setattr(svc, "last_report", svc.clock()))[1]
        svc.hub.call = lambda method, path, body=None: (200, {"jobs": []})
        svc.vault_program = svc.update = lambda: None
        svc.loop(rounds=int(1200 / self.mod.POLL))
        self.assertGreaterEqual(len(reports), 4)
        self.assertLessEqual(len([c for c in self.commands if c[0][0] == "open"]), 5)

    def test_chrome_comes_back_once_its_extension_is_on(self):
        svc = self.service(platform="darwin", report=False, answers={"pgrep": (1, "", "")})
        svc.keep_chrome()
        self.assertFalse([c for c in self.commands if c[0][0] == "open"])       # nothing to keep before the extension
        self.chrome({"disable_reasons": [8192]})
        svc.keep_chrome()
        self.assertFalse([c for c in self.commands if c[0][0] == "open"])       # the owner's press opens it
        self.chrome({"state": 1})
        svc.keep_chrome()
        self.assertEqual([c[0] for c in self.commands if c[0][0] == "open"], [["open", "-g", "-a", "Google Chrome"]])
        self.assertEqual(svc.report_at, svc.clock() + self.mod.CHROME_SETTLES)   # a reading of its own, soon

    def test_a_chrome_folder_that_macos_will_not_list_stops_no_service(self):
        """Live, 4 November 2026: after macOS 27.2 installed itself, listing Chrome's folder raised PermissionError
        ("Operation not permitted") in keep_chrome, and the server service of danas-mac-studio stopped with it."""
        self.chrome({"state": 1})
        svc = self.service(platform="darwin", report=False, answers={"pgrep": (1, "", "")})
        real = os.listdir
        refused = lambda path: (_ for _ in ()).throw(PermissionError(1, "Operation not permitted", path)) \
            if path.endswith(os.path.join("Google", "Chrome")) else real(path)
        with patch("lifecycle.os.listdir", side_effect=refused):
            self.assertIsNone(lifecycle.chrome_extension(str(self.home)))
            svc.keep_chrome()
        self.assertFalse([c for c in self.commands if c[0][0] == "open"])       # nothing to keep that it cannot read

    def test_a_chrome_that_runs_and_a_linux_server_are_left_alone(self):
        self.chrome({"state": 1})
        self.service(platform="darwin", report=False, answers={"pgrep": (0, "1\n", "")}).keep_chrome()
        self.service(platform="linux", report=False, answers={"pgrep": (1, "", "")}).keep_chrome()
        self.assertFalse([c for c in self.commands if c[0][0] == "open"])


class Readings(unittest.TestCase):
    """The reading of a browser with no model: one exchange with the runtime's own Chrome server."""

    def chatgpt(self, there, answer):
        life = lifecycle.Lifecycle("/tmp", None, {}, None, lambda: False)
        life.run = lambda argv, **k: answer
        with patch.object(lifecycle.os.path, "exists", lambda path: there):
            return life.chatgpt()

    def test_the_chatgpt_reading_is_the_copy_in_the_app(self):
        self.assertIs(self.chatgpt(True, (0, "Logged in using ChatGPT\n", "")), True)
        self.assertIs(self.chatgpt(True, (1, "Not logged in\n", "")), False)
        self.assertIs(self.chatgpt(False, (0, "", "")), False)        # no app
        self.assertIs(self.chatgpt(True, (1, "", "")), False)         # silence gives no agent a screen

    def test_a_child_that_holds_the_pipe_does_not_stop_the_limit(self):
        folder = tempfile.mkdtemp(prefix="fleet-mcp-")
        self.addCleanup(lambda: __import__("shutil").rmtree(folder, True))
        path = os.path.join(folder, "server")
        with open(path, "w") as f:
            f.write("#!/usr/bin/env python3\nimport subprocess, time\n"
                    "subprocess.Popen(['sleep', '9'], start_new_session=True)\ntime.sleep(30)\n")
        os.chmod(path, 0o755)
        began = time.monotonic()
        self.assertIsNone(lifecycle.mcp_call([path], "any", timeout=1))
        self.assertLess(time.monotonic() - began, 5)

    def probe(self, text=None):
        folder = tempfile.mkdtemp(prefix="fleet-browser-")
        self.addCleanup(lambda: __import__("shutil").rmtree(folder, True))
        path = os.path.join(folder, "claude")
        reply = {"jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text", "text": text}]}}
        with open(path, "w") as f:
            f.write("#!/usr/bin/env python3\nimport sys, json\n"
                    "assert sys.argv[1] == '--claude-in-chrome-mcp'\n"
                    "for line in sys.stdin:\n    m = json.loads(line)\n"
                    "    if m.get('id') == 1:\n        print(json.dumps({'id': 1, 'result': {}}), flush=True)\n"
                    + f"    if m.get('id') == 2:\n        print({json.dumps(json.dumps(reply))}, flush=True)\n")
        os.chmod(path, 0o755)
        return lifecycle.browser_connected(path)

    def test_the_connected_browsers_of_the_account_say_it(self):
        self.assertIs(self.probe("[]"), False)
        self.assertIs(self.probe('[{"deviceId": "a", "isLocal": true}]'), True)
        self.assertIs(self.probe('[{"deviceId": "a", "onThisComputer": false}]'), False)
        self.assertIs(self.probe('[{"deviceId": "a"}]'), True)

    def test_a_signed_out_extension_is_read_from_the_runtimes_own_words(self):
        self.assertIs(self.probe("Browser extension is not connected. Please ensure"), False)

    def test_an_answer_that_says_nothing_stays_unread(self):
        self.assertIsNone(self.probe("something else"))
        self.assertIsNone(self.probe('{"a": 1}'))
        self.assertIsNone(lifecycle.browser_connected("/no/such/runtime"))


if __name__ == "__main__":
    unittest.main()

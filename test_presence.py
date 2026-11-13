"""Plan C2, the presence half: a helper whose main loop is inside one long step pings the hub, so it stays online and
names the step; the ping after the first tells the requesters whose work waits behind it, once; and every silence
counts from the hub's own start at the earliest. Deterministic: an in-process hub, no AI call, no machine."""
import json
import time
import uuid
import unittest
from unittest.mock import patch

import hub
import test_runtime
from leftovers import scratch_home


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def load_tests(loader, _tests, _pattern):
    """Only this file's cases, not the inherited Runtime ones."""
    suite = unittest.TestSuite()
    for cls in (Presence, ScreenWatch, ManagerRings, StuckScreens, SetupJobs, Lines, Closes, Losses, HelperCloses,
                HelperStarts, HelperScreens, HelperPresence):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Presence(test_runtime.Runtime):
    def ping(self, step, age, task=None, alive=None, agent="studio"):
        body = {"step": step, "age": age}
        if task:
            body["task"] = task
        if alive is not None:
            body["alive"] = alive
        return self.call("POST", f"/helper/presence/{agent}", body, client=None)

    def test_a_helper_inside_one_long_step_stays_online_and_its_task_keeps_a_path(self):
        tid = self.task()
        self.alive("studio", f"T-{tid}", seen=200)          # its last poll was 200 seconds ago: offline by the clock
        self.assertEqual(self.ping("event task", 200, task="T-99", alive=f"T-{tid}"), (200, {"ok": True}))
        row = hub.q1("SELECT last_seen, alive FROM agents WHERE name='studio'")
        self.assertGreater(row["last_seen"], hub.now() - 5)
        hub.liveness(hub.now())
        self.assertEqual(hub.q1("SELECT live_path FROM tasks WHERE id=?", (tid,))["live_path"], "live session")
        self.assertIn("HELPER BUSY: inside one step (event task)", hub.t_see_capacity("manager", {}))
        # the task that the step starts has no window yet, and is not taken for a lost session
        starting = self.task()
        self.ping("task event", 40, task=f"T-{starting}", alive=f"T-{tid}")
        hub.q("UPDATE tasks SET started=? WHERE id=?", (hub.now() - 600, starting))
        hub.liveness(hub.now())
        row = hub.q1("SELECT live_path, missing_since FROM tasks WHERE id=?", (starting,))
        self.assertEqual((row["live_path"], row["missing_since"]), ("helper online", None))

    def test_a_session_lost_while_its_helper_is_busy_is_seen_from_the_ping_s_list(self):
        tid = self.task()
        hub.q("UPDATE tasks SET started=? WHERE id=?", (hub.now() - 600, tid))
        self.alive("studio", f"T-{tid}", seen=100)
        self.ping("event task", 100, task="T-77", alive="")           # tmux answered: no window of the task
        hub.liveness(hub.now())
        self.assertIsNone(hub.q1("SELECT live_path FROM tasks WHERE id=?", (tid,))["live_path"])
        # a ping without a list (tmux did not answer) judges no window
        self.ping("event task", 130, task="T-77")
        hub.liveness(hub.now())
        self.assertEqual(hub.q1("SELECT live_path FROM tasks WHERE id=?", (tid,))["live_path"], "helper online")

    def test_the_second_ping_of_one_step_tells_the_requester_of_the_work_behind_it_once(self):
        clock = [hub.now()]
        with patch.object(hub, "now", lambda: clock[0]):
            tid = self.task()
            hub.emit("studio", "task", f"Your task is T-{tid}.", task=tid)          # queued before the first ping
            clock[0] += 1
            self.ping("event task", 31, task="T-5")
            self.assertFalse([t for t in self.said("manager") if "waits behind it" in t])     # one ping says nothing
            clock[0] += 30
            self.ping("event task", 61, task="T-5")
            told = [t for t in self.said("manager") if "waits behind it" in t]
            self.assertEqual(len(told), 1)
            self.assertIn(f"the start of T-{tid}", told[0])
            self.assertIn("inside one step (event task)", told[0])
            clock[0] += 30
            self.ping("event task", 91, task="T-5")
            self.assertEqual(len([t for t in self.said("manager") if "waits behind it" in t]), 1)     # once a step
            # a new step that ends before its second ping tells nobody
            later = self.task()
            hub.emit("studio", "task", f"Your task is T-{later}.", task=later)
            clock[0] += 30
            self.ping("chat", 31)
            self.assertEqual(len([t for t in self.said("manager") if "waits behind it" in t]), 1)
            self.assertEqual(hub.presence_of("studio", clock[0])["step"], "chat")
            self.assertIsNone(hub.presence_of("studio", clock[0] + 200))           # an old ping is history

    def test_a_hub_that_was_down_longer_than_the_heartbeat_judges_nobody_silent_for_it(self):
        tid = self.task()
        hub.q("UPDATE tasks SET started=? WHERE id=?", (hub.now() - 3600, tid))
        self.alive("studio", f"T-{tid}", seen=400)              # its last poll came before the hub went down
        with patch.object(hub, "STARTED", hub.now() - 30):      # the hub came back 30 seconds ago
            hub.liveness(hub.now())
            hub.offline_sweep(hub.now())
            self.assertEqual(hub.q1("SELECT live_path FROM tasks WHERE id=?", (tid,))["live_path"], "live session")
            self.assertFalse([t for t in self.said("manager") if "went offline" in t])
            self.assertFalse([w for w in hub.health_view()["warnings"] if w["kind"] == "helper_offline" and
                              w["agent"] == "studio"])
        with patch.object(hub, "STARTED", hub.now() - 200):     # and now it has heard nothing for 200 seconds
            hub.offline_sweep(hub.now())
            self.assertEqual(len([t for t in self.said("manager") if "went offline" in t]), 1)

    def test_a_ping_is_refused_without_a_step_and_names_only_a_task(self):
        self.assertEqual(self.ping("", 5)[0], 400)
        self.assertEqual(self.ping("x" * 121, 5)[0], 400)
        self.assertEqual(self.ping("event task", -1)[0], 400)
        self.assertEqual(self.ping("event task", 5, task="T-x")[0], 400)
        self.assertEqual(self.call("POST", "/helper/presence/nobody", {"step": "x", "age": 1}, client=None)[0], 404)


class ScreenWatch(test_runtime.Runtime):
    def dialog(self, window, kind=None, agent="studio"):
        return self.call("POST", f"/helper/dialog/{agent}/{window}", {"kind": kind} if kind else {}, client=None)

    def test_a_question_on_a_task_s_screen_is_told_once_and_its_going_restores_the_wait(self):
        tid = self.task()
        asked = hub.ins("INSERT INTO questions(task,asker,requester,text,asked) VALUES(?,?,?,?,?)",
                        (tid, "studio", "manager", "Which logo?", hub.now()))
        hub.q("UPDATE tasks SET state='input-required', waiting_on=? WHERE id=?", (f"Q-{asked}", tid))
        self.assertEqual(self.dialog(f"T-{tid}", "shown")[0], 200)
        self.dialog(f"T-{tid}", "shown")
        self.assertEqual(hub.q1("SELECT waiting_on FROM tasks WHERE id=?", (tid,))["waiting_on"], "its screen")
        self.assertEqual(sum("shows a question on its own screen" in t for t in self.said("manager")), 1)
        self.assertEqual(self.dialog(f"T-{tid}", "gone")[0], 200)
        self.assertEqual(hub.q1("SELECT waiting_on FROM tasks WHERE id=?", (tid,))["waiting_on"], f"Q-{asked}")
        self.assertEqual(self.dialog(f"T-{tid}", "maybe")[0], 400)

    def test_a_frozen_task_screen_is_told_once_and_waits_on_its_screen_until_it_moves(self):
        """Plan C2 (5): one message to the requester for each episode; the task waits on its screen, which the
        question half of the watch does not clear, and moving again puts back what it waited on."""
        tid = self.task()
        frozen = lambda: sum("its screen stopped moving" in t for t in self.said("manager"))
        waits = lambda: hub.q1("SELECT waiting_on FROM tasks WHERE id=?", (tid,))["waiting_on"]
        self.assertEqual(self.dialog(f"T-{tid}", "moving")[0], 200)     # a first reading that moves: nothing to clear
        self.assertEqual(self.dialog(f"T-{tid}", "frozen")[0], 200)
        self.dialog(f"T-{tid}", "frozen")
        self.assertEqual((waits(), frozen()), ("its screen", 1))
        self.dialog(f"T-{tid}", "gone")         # no question on it: the frozen screen still holds the task
        self.assertEqual(waits(), "its screen")
        self.dialog(f"T-{tid}", "moving")
        self.assertIsNone(waits())
        self.dialog(f"T-{tid}", "frozen")       # a new episode is told again
        self.assertEqual(frozen(), 2)
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))
        event = hub.attempt_event(t)                # it reads with commits, so before the transaction
        with hub.transaction():
            hub.attempt_rows(t, "lost", event, hub.now())
        self.assertIsNone(hub.kv_get(f"screen_frozen:{tid}"))      # a new session has no frozen screen

    def test_a_frozen_manager_screen_is_silent_with_one_notification_until_it_moves_or_reads(self):
        """Plan C2 and C10: a frozen manager is 'silent' whether or not a message waits for it."""
        notified = lambda: sum("has not moved since" in t for t in self.said("owner", "notify"))
        self.dialog("manager", "frozen", agent="manager")
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "silent")
        self.assertRegex(hub.kv_get("mgr_flag"), r"^The manager's session has not moved since \d\d:\d\d\.$")
        self.dialog("manager", "frozen", agent="manager")
        hub.tick()
        self.assertEqual(notified(), 1)
        self.dialog("manager", "moving", agent="manager")
        self.assertIsNone(hub.kv_get("mgr_flag_kind"))
        self.dialog("manager", "frozen", agent="manager")
        hub.t_read_messages("manager", {})      # a session that reads is not frozen
        hub.manager_flag_update(hub.now())
        self.assertIsNone(hub.kv_get("mgr_flag_kind"))
        self.assertEqual(notified(), 2)

    def test_the_manager_s_screen_banner_stays_until_its_question_goes(self):
        clock = [hub.now()]
        with patch.object(hub, "now", lambda: clock[0]):
            self.dialog("manager", "shown", agent="manager")
            hub.tick()
            self.assertEqual(hub.kv_get("mgr_flag_kind"), "screen")
            clock[0] += 600                     # ten minutes: the watch has not said that it went
            hub.tick()
            self.assertEqual(hub.kv_get("mgr_flag_kind"), "screen")
            self.dialog("manager", "gone", agent="manager")
            self.assertIsNone(hub.kv_get("mgr_flag_kind"))
            self.assertEqual(sum("shows a question" in t for t in self.said("owner", "notify")), 1)
            self.dialog("manager", agent="manager")         # a helper without the watch: no 90 s life (plan C10)
            hub.tick()
            self.assertEqual(hub.kv_get("mgr_flag_kind"), "screen")
            clock[0] += 3600
            hub.tick()
            self.assertEqual(hub.kv_get("mgr_flag_kind"), "screen")     # until the manager reads
            hub.t_read_messages("manager", {})
            hub.tick()
            self.assertIsNone(hub.kv_get("mgr_flag_kind"))


class ManagerRings(test_runtime.Runtime):
    """Owner-contact plan B3 (6 November 2026): the owner's phone rings about the manager's own health only when the
    fleet cannot put it right itself. The flag shows on the board, in /ui/health and in /ui/state as before; only its
    notification waits for the event that ends its hold. The bodies are the helper's own (fleet.Helper.signal and
    manager_start_failed), and a poll is its own poll with its window list (fleet.cmd_run)."""
    DOWN = "Fleet hub: The manager session is not running. Start it again."
    SILENT = "Fleet hub: The manager did not take a message it was given twice."

    def setUp(self):
        super().setUp()
        self.status()

    def status(self, features=(hub.MANAGER_START_FAILS,), signed_in=None):
        """The manager's machine report: its helper's features, and whether its runtime is signed in."""
        data = {"features": list(features)}
        if signed_in is not None:
            data["runtimes"] = {"claude": {"version": "2.1.318 (Claude Code)", "signed_in": signed_in}}
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES('manager',?,?) ON CONFLICT(agent) DO UPDATE SET "
              "data=excluded.data, reported=excluded.reported", (json.dumps(data), hub.now()))

    def poll(self, *windows):
        code, _ = self.call("GET", f"/events/manager?delivery=1&after=0&wait=0&alive={','.join(windows)}", client=None)
        self.assertEqual(code, 200)

    def dialog(self, **body):
        return self.call("POST", "/helper/dialog/manager/manager", body, client=None)[0]

    def unread(self):
        hub.emit("manager", "say", "[owner] Where do we stand?")

    def rings(self):
        return [t for t in self.said("owner", "notify") if t.startswith("Fleet hub: ")]

    def shown(self):
        """The flag as the owner's screens show it: its kind, /ui/health's warning, and /ui/state's kind and words."""
        warnings = [w["kind"] for w in hub.health_view()["warnings"] if w["kind"].startswith("manager_")]
        state = self.call("GET", "/ui/state")[1]
        return hub.kv_get("mgr_flag_kind"), warnings, (state["manager_warning"] or {}).get("kind"), state["manager_flag"]

    # ---- case 1: down
    def test_a_window_that_its_helper_starts_again_shows_down_and_rings_nobody(self):
        """28 October and 6 November 2026: the helper closed its manager session itself (new tools, then a new
        conversation), and the owner was told "not running" for a session that was back seconds later."""
        self.poll("manager")
        self.poll()                                         # its session ended: its helper starts it again by itself
        self.assertEqual(self.shown(), ("down", ["manager_down"], "down",
                                        "The manager session is not running. Start it again."))
        hub.tick()
        self.poll("manager")                                # and it is back
        self.assertEqual(self.shown(), (None, [], None, None))
        self.assertEqual(self.rings(), [])

    def test_a_start_that_failed_twice_in_a_row_rings_once_until_its_window_is_back(self):
        self.poll("manager")
        self.poll()
        self.assertEqual(self.rings(), [])
        self.assertEqual(self.dialog(kind="start_failed", reason="the session did not start or ended at its start"),
                         200)
        self.assertEqual(self.rings(), [self.DOWN])        # the helper's own try did not help
        self.assertEqual(self.shown()[:3], ("down", ["manager_down"], "down"))
        self.dialog(kind="start_failed", reason="the session did not start or ended at its start")
        self.poll()
        hub.tick()
        self.assertEqual(self.rings(), [self.DOWN])        # once for the episode
        self.poll("manager")                                # a list after its word shows the window: it runs again
        self.assertIsNone(hub.kv_get("mgr_start_failed"))
        self.assertIsNone(hub.kv_get("mgr_flag_kind"))
        self.poll()                                         # the next end of it is its helper's to start again
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "down")
        self.assertEqual(self.rings(), [self.DOWN])

    def test_a_list_from_before_the_helper_s_word_does_not_end_it(self):
        """The session that its helper started last showed in a list, and ended before it came up: that was its
        second failed start, and the next list, which lacks the window, rings."""
        self.poll("manager")
        self.dialog(kind="start_failed", reason="its session ended before it came up")
        self.assertIsNotNone(hub.kv_get("mgr_start_failed"))
        self.assertEqual(self.rings(), [])                  # nothing is down yet
        self.poll()
        self.assertEqual(self.rings(), [self.DOWN])

    def test_an_older_helper_that_never_says_so_rings_at_once_as_before(self):
        self.status(features=())
        self.poll("manager")
        self.poll()
        self.assertEqual(self.rings(), [self.DOWN])

    def test_a_down_manager_that_no_helper_can_start_rings_at_once(self):
        """Its helper's loop is inside one step with a message behind it, so it starts nothing; and a server that went
        silent with a message waiting has no helper at all."""
        t0 = hub.now()
        self.poll("manager")
        event = hub.emit("manager", "say", "[owner] unread")
        hub.q("UPDATE events SET created=? WHERE id=?", (t0 - 5, event))
        with hub.LOCK:
            hub.presence_ping("manager", "manage", None, t0 - 20, t0)
            hub.presence_ping("manager", "manage", None, t0 - 20, t0 + 1)
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "silent")
        self.poll()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "down")
        self.assertEqual(self.rings()[-1], self.DOWN)
        with hub.LOCK:
            hub.kv_set("presence:manager", None)
            hub.kv_set("mgr_flag_kind", None)
            hub.kv_set("mgr_flag_told", None)
        hub.q("UPDATE agents SET last_seen=? WHERE name='manager'", (t0 - 120,))     # the label flip
        with patch.object(hub, "STARTED", t0 - 86400):
            hub.tick()
        self.assertRegex(hub.kv_get("mgr_flag"), r"^The manager's server has been silent since \d\d:\d\d; a message "
                                                 r"waits\.$")
        self.assertEqual(len([t for t in self.rings() if "server has been silent" in t]), 1)

    # ---- case 2: silent
    def test_a_line_that_its_helper_starts_fresh_for_shows_silent_and_rings_nobody(self):
        self.poll("manager")
        self.unread()
        self.assertEqual(self.dialog(kind="untaken", fresh="yes"), 400)
        self.assertEqual(self.dialog(kind="untaken", fresh=True), 200)
        hub.tick()
        self.assertEqual(self.shown(), ("silent", ["manager_silent"], "silent",
                                        "The manager did not take a message it was given twice."))
        self.poll()                                         # its helper closed that idle session
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "down")
        self.poll("manager")                                # and started it on a new conversation
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "silent")
        hub.t_read_messages("manager", {})                  # the fresh session reads
        hub.tick()
        self.assertEqual(self.shown(), (None, [], None, None))
        self.assertEqual(self.rings(), [])

    def test_a_fresh_session_that_leaves_its_line_untaken_too_rings_once(self):
        self.poll("manager")
        self.unread()
        self.dialog(kind="untaken", fresh=True)
        hub.tick()
        self.poll()
        self.poll("manager")
        self.assertEqual(self.rings(), [])
        self.dialog(kind="untaken")                         # the fresh session took neither of its two lines
        hub.tick()
        hub.tick()
        self.assertEqual(self.rings(), [self.SILENT])

    def test_a_fresh_start_that_fails_rings_as_down(self):
        self.poll("manager")
        self.unread()
        self.dialog(kind="untaken", fresh=True)
        hub.tick()
        self.poll()                                         # closed, and its fresh start fails twice in a row
        self.assertEqual(self.rings(), [])
        self.dialog(kind="start_failed", reason="the hub gave no generation (503)")
        self.assertEqual(self.rings(), [self.DOWN])

    def test_a_line_that_no_fresh_start_follows_rings_at_once_as_before(self):
        self.poll("manager")
        self.unread()
        self.dialog(kind="untaken")                         # an older helper, or the fresh session already
        hub.tick()
        self.assertEqual(self.rings(), [self.SILENT])

    # ---- case 3: the rest as before
    def test_a_signed_out_manager_and_a_question_on_its_screen_ring_at_once(self):
        """Only the owner signs in; a helper with stuck_screens has closed a session at a question once already."""
        self.poll("manager")
        self.status(signed_in=False)
        self.poll()                                         # its window has closed as well: a start would not help
        self.assertEqual(self.shown()[:3], ("signed_out", ["manager_signed_out"], "signed_out"))
        self.assertEqual(self.rings(), ["Fleet hub: The manager is not signed in."])
        self.status(signed_in=True)
        self.poll("manager")
        self.assertIsNone(hub.kv_get("mgr_flag_kind"))
        self.assertEqual(self.dialog(kind="shown", still=True), 200)
        self.assertEqual(self.rings()[-1], "Fleet hub: The manager's session shows a question on its own screen.")


class StuckScreens(test_runtime.Runtime):
    """Runtime gaps C1 (29 October 2026): a question on a task session's own screen that no hook carries, which nobody
    sits at the machine to answer. The bodies are the helper's own (fleet.screen_report)."""

    def setUp(self):
        super().setUp()
        self.features("studio", hub.STUCK_SCREENS)

    def features(self, agent, *names):
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET "
              "data=excluded.data", (agent, json.dumps({"features": list(names)}), hub.now()))

    def dialog(self, tid, kind="shown", attempt=None, still=None, agent="studio"):
        import fleet
        return self.call("POST", f"/helper/dialog/{agent}/T-{tid}", fleet.screen_report(kind, attempt, still),
                         client=None)

    def row(self, tid):
        return tuple(hub.q1("SELECT attempt, waiting_on FROM tasks WHERE id=?", (tid,)))

    def told(self, tid, agent="manager"):
        return [t for t in self.said(agent) if f"for T-{tid} (" in t and "own screen" in t]

    def limit(self, tid, reset):
        self.records(tid, [{"seq": 1, "type": "error", "code": "usage_limit", "resets_at": reset}])

    def test_a_question_that_stands_still_starts_the_task_once_and_the_next_one_goes_to_the_requester(self):
        tid = self.task()
        self.assertEqual(self.dialog(tid, attempt=1, still=True)[0], 200)
        self.assertEqual(self.row(tid), (2, None))
        self.assertEqual(hub.q1("SELECT reason FROM attempts WHERE task=? AND attempt=2", (tid,))["reason"],
                         hub.SCREEN_REASON)
        start = hub.q1("SELECT text, extra FROM events WHERE agent='studio' AND kind='task' ORDER BY id DESC")
        self.assertEqual(json.loads(start["extra"])["attempt"], 2)      # its start closes the old window (handle)
        self.assertIn("no person reads", start["text"])
        self.assertEqual(self.told(tid), [])                             # nobody is asked for the first one
        for kind in ("gone", "shown"):                                  # a late word of the window it replaced
            self.dialog(tid, kind, attempt=1, still=True if kind == "shown" else None)
        self.assertEqual((self.row(tid), self.told(tid)), ((2, None), []))
        self.dialog(tid, attempt=2, still=False)        # the new session shows one while its records move: wait
        self.assertEqual((self.row(tid), self.told(tid)), ((2, None), []))
        self.dialog(tid, attempt=2, still=True)
        self.dialog(tid, attempt=2, still=True)
        told = self.told(tid)
        self.assertEqual((self.row(tid), len(told)), ((2, "its screen"), 1))
        self.assertIn("again: the hub already started it once more for such a question", told[0])
        self.assertIn("Start it again with restart_task (expected_attempt 2); raise a Needs-you item only if the "
                      "same question comes back.", told[0])
        self.dialog(tid, "gone", attempt=2)
        self.assertEqual(self.row(tid), (2, None))

    def test_no_new_attempt_while_its_session_holds_something_open_so_the_requester_restarts_it(self):
        """A card in the middle of a turn, a hold or a usage limit (fresh_refusal): restart_task is the backstop."""
        for words, held in (("while a turn of its session runs",
                             lambda tid: self.records(tid, [{"seq": 1, "type": "user_message", "text": "Go."}])),
                            ("is held", lambda tid: hub.request_hold(tid, "pause", "manager")),
                            ("is at a usage limit", lambda tid: hub.start_limit("studio", hub.now() + 600, tid))):
            with self.subTest(words):
                tid = self.task()
                held(tid)
                self.dialog(tid, attempt=1, still=True)
                told = self.told(tid)
                self.assertEqual((self.row(tid)[0], len(told)), (1, 1))
                self.assertIn(words, told[0])
                self.assertIn("which no person reads", told[0])
                self.assertIn("Start it again with restart_task (expected_attempt 1)", told[0])

    def test_a_question_that_comes_back_after_a_restart_reaches_the_requester_again(self):
        """The review of 29 October 2026: a new attempt left the task waiting on the old session's screen, so the
        question that the next session showed reached nobody, and the task waited for ever out of running_turns. A new
        attempt ends that wait, also one after a frozen screen, and a question that the task asked is its wait again."""
        tid = self.task()
        self.dialog(tid, attempt=1, still=True)             # the hub's own new attempt
        self.dialog(tid, attempt=2, still=True)             # the same question: the requester is told
        self.assertEqual((self.row(tid), len(self.told(tid))), ((2, "its screen"), 1))
        hub.new_attempt(hub.q1("SELECT * FROM tasks WHERE id=?", (tid,)), "restart")       # its restart_task
        self.assertEqual(self.row(tid), (3, None))
        self.dialog(tid, attempt=3, still=True)             # the new session shows it at its start
        told = self.told(tid)
        self.assertEqual((self.row(tid), len(told)), ((3, "its screen"), 2))
        self.assertIn("restart_task (expected_attempt 3)", told[1])
        frozen = self.task()
        self.dialog(frozen, "frozen", attempt=1)
        self.assertEqual(self.row(frozen), (1, "its screen"))
        hub.new_attempt(hub.q1("SELECT * FROM tasks WHERE id=?", (frozen,)), "restart")
        self.assertEqual(self.row(frozen), (2, None))
        asked = self.task()
        self.assertFalse(self.tool("studio", "ask_my_requester", asked, question="Which logo?")[1])
        self.features("studio")
        self.dialog(asked)                                  # a dialog while it waits for the answer
        self.assertEqual(self.row(asked), (1, "its screen"))
        hub.new_attempt(hub.q1("SELECT * FROM tasks WHERE id=?", (asked,)), "restart")
        self.assertEqual(self.row(asked), (2, "Q-1"))

    def test_a_helper_without_the_feature_tells_as_before_and_a_lead_asks_its_own_requester(self):
        tid = self.task()
        self.features("studio")
        self.dialog(tid, attempt=1, still=True)
        told = self.told(tid)
        self.assertEqual((self.row(tid), len(told)), ((1, "its screen"), 1))
        self.assertIn("own screen that the hub cannot answer. Start it again with restart_task (expected_attempt 1)",
                      told[0])
        led = self.task()
        hub.q("UPDATE tasks SET requester='vps' WHERE id=?", (led,))
        self.dialog(led)                        # a helper without the watch: no kind, no attempt
        self.assertIn("pass it up to your own requester only if the same question comes back",
                      self.told(led, "vps")[0])
        self.assertNotIn("Needs-you", self.told(led, "vps")[0])

    def test_the_usage_limit_menu_waits_for_the_reset_and_then_starts_a_new_attempt(self):
        menu, other = self.task(), self.task()
        self.alive("studio", f"T-{menu}", f"T-{other}")
        self.limit(menu, hub.now() + 600)
        self.assertEqual(self.dialog(menu, "limit", attempt=1)[0], 200)
        self.assertEqual((self.row(menu), self.told(menu)), ((1, None), []))     # the hold covers it: no word
        hub.q("UPDATE agent_limits SET until=?", (hub.now() - 1,))
        self.alive("studio", f"T-{menu}", f"T-{other}")
        hub.tick()
        self.assertEqual((self.row(menu)[0], self.row(other)[0]), (2, 1))     # no line can be typed into a menu
        self.assertEqual(hub.q1("SELECT reason FROM attempts WHERE task=? AND attempt=2", (menu,))["reason"],
                         hub.LIMIT_RESET)
        said = self.said("studio")
        self.assertTrue(any(f"Continue T-{other}." in t for t in said))       # its idle session gets the message
        self.assertFalse(any(f"Continue T-{menu}." in t for t in said))

    def test_a_menu_told_before_its_record_waits_for_the_hold_and_one_told_after_the_reset_starts_it_now(self):
        early, late = self.task(), self.task()
        self.alive("studio", f"T-{early}", f"T-{late}")
        self.dialog(early, "limit", attempt=1)              # its record is on its way: nothing yet
        self.assertEqual(self.row(early), (1, None))
        self.limit(early, hub.now() + 600)
        self.records(late, [{"seq": 1, "type": "error", "code": "usage_limit", "resets_at": hub.now() + 600}])
        hub.q("UPDATE agent_limits SET until=?", (hub.now() - 1,))
        self.alive("studio", f"T-{early}", f"T-{late}")
        hub.tick()
        self.assertEqual((self.row(early)[0], self.row(late)[0]), (2, 1))     # late's window had told nothing yet
        self.dialog(late, "limit", attempt=1)               # its menu, told after the reset: no line reaches it
        self.assertEqual(self.row(late)[0], 2)
        self.dialog(late, "limit", attempt=2)               # the next session at a menu whose record is not in
        self.assertEqual(self.row(late)[0], 2)

    def test_the_manager_hears_that_its_question_reached_nobody_and_its_limit_menu_is_the_limit_s(self):
        self.features("manager", hub.STUCK_SCREENS)
        mgr = lambda kind: self.call("POST", "/helper/dialog/manager/manager", {"kind": kind}, client=None)
        mgr("shown")
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "screen")
        self.assertEqual(mgr("closed")[0], 200)
        self.assertIsNone(hub.kv_get("mgr_flag_kind"))
        self.assertEqual(sum("your question reached nobody" in t for t in self.said("manager")), 1)
        hub.start_limit("manager", hub.now() + 600)
        mgr("shown")
        mgr("limit")                    # the menu: the limit's own flag, with no step for the owner at the machine
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "limited")
        self.assertNotIn("answer it on that machine", hub.kv_get("mgr_flag"))
        tid = self.task()
        self.assertEqual(self.dialog(tid, "closed", attempt=1)[0], 200)        # a word about the manager only
        self.assertEqual(self.row(tid), (1, None))
        self.assertEqual(self.dialog(tid, "shown", attempt=0)[0], 400)
        self.assertEqual(self.call("POST", f"/helper/dialog/studio/T-{tid}", {"kind": "shown", "still": "yes"},
                                   client=None)[0], 400)


class SetupJobs(test_runtime.Runtime):
    def job(self, server, updated):
        return hub.ins("INSERT INTO server_jobs(server,kind,agent,runtime,state,step,created,updated) "
                       "VALUES(?,'install','coder','claude','running','runtime',?,?)", (server, updated, updated))

    def status(self, server, reported, features):
        hub.q("INSERT INTO server_status(server,data,reported) VALUES(?,?,?)",
              (server, json.dumps({"features": features}), reported))

    def test_a_long_job_of_a_live_server_stays_open_and_one_whose_server_stopped_fails(self):
        """Plan C2: a server that reports while a job runs is judged by that heartbeat, not by the job's own silence;
        one without it keeps the old thirty minutes."""
        t0 = hub.now()
        live, gone, old = self.job("box", t0 - 3600), self.job("box2", t0 - 3600), self.job("box3", t0 - 3600)
        self.status("box", t0 - 100, ["job_heartbeat"])          # it reported 100 seconds ago, inside a long step
        self.status("box2", t0 - hub.MACHINE_STALE - 1, ["job_heartbeat"])
        self.status("box3", t0 - 10, [])                           # it reports, and not while a job runs
        hub.expire_server_jobs(t0)
        state = lambda j: hub.q1("SELECT state FROM server_jobs WHERE id=?", (j,))["state"]
        self.assertEqual([state(j) for j in (live, gone, old)], ["running", "failed", "failed"])
        fresh = self.job("box3", t0 - hub.JOB_SILENT + 60)
        hub.expire_server_jobs(t0)
        self.assertEqual(state(fresh), "running")


class Lines(test_runtime.Runtime):
    def test_each_listing_of_a_session_s_tools_is_counted_for_its_window(self):
        """Plan C5: the helper's first line waits for a count that passes the one it saw at the start: no clock."""
        tid = self.task()
        context = ("gen1", f"T-{tid}", "1")
        for _ in range(2):
            hub.rpc("studio", {"id": 1, "method": "tools/list"}, {}, context)
        hub.rpc("studio", {"id": 1, "method": "tools/list"}, {}, ("gen1", "conversation", "7"))
        self.assertEqual(hub.listed_windows("studio", f"T-{tid},C-7,owner-chat"),
                         {f"T-{tid}": 2, "C-7": 1, "owner-chat": 0, "manager": 0})
        self.alive("studio", f"T-{tid}")
        answer = self.call("GET", f"/events/studio?delivery=1&wait=0&alive=T-{tid}", client=None)[1]
        self.assertEqual(answer["listed"], {f"T-{tid}": 2, "manager": 0})
        self.assertEqual(self.call("POST", f"/helper/dialog/studio/T-{tid}", {"kind": "untaken"}, client=None)[0], 200)
        self.assertIsNotNone(hub.kv_get(f"untaken:studio:T-{tid}"))


class Closes(test_runtime.Runtime):
    def test_a_helper_that_closes_at_the_turn_s_end_gets_the_stop_at_delivery(self):
        """Plan C5: no 60 seconds after delivery for a helper with turn_close; an older one keeps stop_after."""
        tid = self.task()
        hub.q("UPDATE tasks SET state='completed', outcome='completed', delivered=? WHERE id=?", (hub.now(), tid))
        hub.tick()
        self.assertEqual(self.said("studio", "stop"), [])                   # an older helper: after stop_after
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES('studio',?,?)",
              (json.dumps({"features": ["turn_close"]}), hub.now()))
        hub.tick()
        self.assertEqual(len(self.said("studio", "stop")), 1)


class HelperCloses(unittest.TestCase):
    def helper(self):
        import fleet
        helper = fleet.Helper("vps", {"role": "worker", "runtime": "claude", "machine": "vps", "can": ["shell"]})
        return fleet, helper

    def feed(self, helper, window, rows):
        import threads
        feed = threads.Feed((window, "g", 1, "s1"), "claude")
        for row in rows:
            feed.translator.records(row)
        helper.tailer.feeds[(window, "s1")] = feed
        return feed

    USE = staticmethod(lambda cid, name: {"type": "assistant", "sessionId": "s1", "message": {"id": "m-" + cid, "content": [
        {"type": "tool_use", "id": cid, "name": name, "input": {}}]}})

    def test_a_delivered_window_closes_at_the_end_of_its_turn_or_at_the_next_tool_that_is_not_fleet_s(self):
        fleet, helper = self.helper()
        ask = {"type": "user", "sessionId": "s1", "message": {"role": "user", "content": "Go."}}
        self.feed(helper, "T-3", [ask, self.USE("d1", "mcp__fleet__deliver_result")])
        self.assertTrue(helper.closing("T-3"))                  # the turn that delivered still runs
        helper.screens["T-3"] = {"class": "idle"}
        self.assertFalse(helper.closing("T-3"))                 # its screen shows it idle: it closes
        helper.screens.clear()
        self.feed(helper, "T-3", [ask, self.USE("d1", "mcp__fleet__deliver_result"), self.USE("b1", "Bash")])
        self.assertFalse(helper.closing("T-3"))                 # it works on after delivering: it closes now
        done = {"type": "system", "subtype": "turn_duration", "sessionId": "s1"}
        self.feed(helper, "T-3", [ask, self.USE("d1", "mcp__fleet__deliver_result"), done])
        self.assertFalse(helper.closing("T-3"))                 # its turn ended
        self.assertFalse(helper.closing("T-4"))                 # no records: as before, it closes at the stop

    def test_a_pause_of_an_idle_session_is_confirmed_at_once_and_a_running_one_by_its_interrupt(self):
        fleet, helper = self.helper()
        ask = {"type": "user", "sessionId": "s1", "message": {"role": "user", "content": "Go."}}
        feed = self.feed(helper, "T-5", [ask])
        screens, keys = ["esc to interrupt"], []

        def tmux(*args, **_kw):
            if args[0] == "send-keys":
                keys.append(args[-1])
                feed.translator.records({"type": "user", "sessionId": "s1", "message": {"content": [
                    {"type": "text", "text": "[Request interrupted by user]"}]}})
                screens[0] = "❯ "
            out = screens[0] if args[0] == "capture-pane" else "0" if "#{pane_in_mode}" in args else ""
            return unittest.mock.Mock(returncode=0, stdout=out)
        with patch.object(fleet, "tmux", tmux), patch.object(fleet.time, "sleep"), \
                patch.object(helper, "look", return_value=["T-5"]), patch.object(helper, "runner", return_value=False), \
                patch.object(helper.tailer, "flush", return_value=[]):
            self.assertEqual(helper.interrupt("T-5"), (True, "interrupted; its records show the turn's end"))
            self.assertEqual(keys, ["Escape"])
            self.assertEqual(helper.interrupt("T-5"), (True, "no turn was running"))      # idle: at once

    def test_a_conversation_window_closes_when_the_hub_closed_its_conversation_and_gives_way_when_idle(self):
        fleet, helper = self.helper()
        open_windows, killed = ["C-1", "C-2"], []

        def tmux(*args, **_kw):
            if args[0] == "kill-window":
                killed.append(args[-1])
                open_windows.remove(args[-1].split(":=")[1])
            return unittest.mock.Mock(returncode=0, stdout="")
        with patch.object(fleet, "tmux", tmux), patch.object(helper, "look", side_effect=lambda: list(open_windows)):
            helper.conversations = [1, 2]
            helper.retire_conversations()
            self.assertEqual(killed, [])                        # both open: no clock closes one
            helper.conversations = [2]
            helper.retire_conversations()
            self.assertEqual(killed, ["=fleet-vps:=C-1"])
            open_windows.append("C-3")
            helper.screens = {"C-2": {"class": "running"}, "C-3": {"class": "idle"}}
            helper.newest = {"C-4": 9}
            self.assertTrue(helper.free_conversation_slot("C-4"))      # the idle one with nothing unread gives way
            self.assertEqual(killed[-1], "=fleet-vps:=C-3")
            self.assertFalse(helper.free_conversation_slot("C-5"))     # C-2 runs a turn: nothing gives way

    def test_a_chat_whose_starts_end_stops_after_two_and_starts_again_after_a_sign_in(self):
        fleet, helper = self.helper()
        with patch.object(helper, "chat_resume", return_value=None), \
                patch.object(fleet, "session_credential", return_value=None), \
                patch.object(fleet, "chat_recap", return_value=""), patch.object(fleet, "session_env", return_value={}), \
                patch.object(fleet, "chat_command", return_value="claude"), patch.object(helper, "start"), \
                patch.object(fleet, "save_chat_record"):
            helper.start_chat("g1")
            helper.start_chat("g1")
            with self.assertRaises(fleet.Refused) as refused:
                helper.start_chat("g1")
            self.assertIn("ended twice", str(refused.exception))
            helper.restart_after_login()
            helper.start_chat("g1")                             # a sign-in starts the count again

    def test_a_stop_closes_a_session_at_a_card_that_no_interrupt_reaches(self):
        """The second review of 29 October 2026: a Claude session at a card of its own shows no running turn to
        interrupt, and its records still show the turn, so no interrupt confirms, and restart_task, which the texts
        about a question on a screen name first, stopped nothing. A stop closes the window anyway, and the closing
        confirms it; a pause still keeps the session."""
        fleet, helper = self.helper()
        open_windows, killed, posted = ["T-5"], [], []

        def tmux(*args, **_kw):
            if args[0] == "kill-window":
                killed.append(args[-1])
                open_windows.clear()
            return unittest.mock.Mock(returncode=0, stdout="")
        refused = (False, "the session still shows a running turn after three interrupts")
        with patch.object(fleet, "tmux", tmux), patch.object(fleet.time, "sleep"), \
                patch.object(helper, "look", side_effect=lambda: list(open_windows)), \
                patch.object(helper, "interrupt", return_value=refused), \
                patch.object(helper, "end_requests", return_value=(True, 0)), \
                patch.object(helper, "task_work", return_value={}), patch.object(helper, "say"), \
                patch.object(helper.tailer, "flush", return_value=[]), \
                patch.object(fleet, "http", lambda m, p, b=None, timeout=40: (posted.append(b), (200, {}))[1]):
            helper.control("T-5", {"hold": 3, "action": "pause", "generation": "g"})
            self.assertEqual((killed, posted[-1]["confirmed"]), ([], False))       # a pause keeps its session
            helper.control("T-5", {"hold": 4, "action": "stop", "generation": "g"})
        self.assertEqual(killed, ["=fleet-vps:=T-5"])
        self.assertEqual((posted[-1]["hold"], posted[-1]["confirmed"]), (4, True))
        self.assertIn("closed with no confirmed interrupt", posted[-1]["detail"])

    def test_a_chat_or_conversation_window_at_a_question_closes_once_until_a_session_of_it_made_a_model_call(self):
        """Runtime gaps C2: the hub has no turn state of these windows, so the helper decides from its own reading. A
        window whose records move is no stuck window; a closed conversation frees its slot, and the owner chat starts
        again on a new conversation with the hub's recap."""
        fleet, helper = self.helper()
        wids, records, calls, killed = {"owner-chat": 1, "C-3": 1, "C-4": 1}, {"owner-chat": 5.0, "C-3": 7.0}, {}, []

        def tmux(*args, **_kw):
            if args[0] == "capture-pane":
                return unittest.mock.Mock(returncode=0, stdout=HelperScreens.ASKS)
            if args[0] == "kill-window":
                killed.append(args[-1].split(":=")[1])
                wids[killed[-1]] += 1                           # the window that starts next is a new one
            return unittest.mock.Mock(returncode=0, stdout="".join(f"{w}\t@{w}{i}\t\n" for w, i in wids.items()))
        with patch.object(fleet, "tmux", tmux), \
                patch.object(helper, "records_at", lambda w: records.get(w, time.monotonic())),  \
                patch.object(helper, "window_runtime", lambda _w: "claude"), \
                patch.object(helper, "conversation_kind", lambda _w: "closed"), \
                patch.object(helper, "last_call", lambda w: calls.get(w)):
            for _ in range(2):
                helper.watch_screens()
            self.assertEqual(sorted(killed), ["C-3", "owner-chat"])    # C-4's records move: it works
            self.assertEqual((helper.chat_fresh, helper.chat_started), (True, None))
            for _ in range(3):
                helper.watch_screens()          # the sessions that follow show a question before their first call
            self.assertEqual(len(killed), 2)
            calls["C-3"], records["C-3"] = time.time() + 1, 8.0      # C-3's session made a model call since
            for _ in range(2):
                helper.watch_screens()
            self.assertEqual(killed[2:], ["C-3"])


class Losses(test_runtime.Runtime):
    """Plan C6: a loss is a fact of the helper's window list, and progress decides whether it counts."""

    def setUp(self):
        super().setUp()
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES('studio',?,?)",
              (json.dumps({"features": ["start_once"]}), hub.now()))

    def started(self, tid):
        """The helper started the current attempt once: it acked its task event, through its own route (the live
        check of 27 October 2026 found that route dropping the ack of a task, so no lost session came back)."""
        t = hub.q1("SELECT attempt FROM tasks WHERE id=?", (tid,))
        event = hub.q1("SELECT id FROM events WHERE agent='studio' AND kind='task' AND task=? AND "
                       "COALESCE(json_extract(extra, '$.attempt'), 1)=? ORDER BY id DESC", (tid, t["attempt"]))
        self.assertEqual(self.call("POST", "/helper/ack/studio", {"ids": [event["id"]]}, client=None)[0], 200)
        self.assertTrue(hub.attempt_started(hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))))
        self.assertIsNone(hub.q1("SELECT read_at FROM events WHERE id=?", (event["id"],))["read_at"])

    def test_a_started_attempt_whose_window_is_gone_starts_again_and_two_that_left_nothing_stop(self):
        tid = self.task()
        self.alive("studio")                                    # the helper's list counts and has no window of it
        hub.liveness(hub.now())
        self.assertEqual(hub.q1("SELECT live_path FROM tasks WHERE id=?", (tid,))["live_path"],
                         "waiting for its session to start")    # not started by the helper yet: not lost
        self.started(tid)
        self.alive("studio")                                    # its next list, taken after the start
        hub.liveness(hub.now())                                 # lost at once: no grace and no debounce
        row = hub.q1("SELECT attempt, restarts FROM tasks WHERE id=?", (tid,))
        self.assertEqual((row["attempt"], row["restarts"]), (2, 1))    # it never came up: the loss counts
        self.started(tid)
        self.assertEqual(self.call("POST", f"/helper/dialog/studio/T-{tid}",
                                   {"kind": "start_failed", "reason": "claude: command not found"}, client=None)[0], 200)
        self.call("POST", f"/helper/dialog/studio/T-{tid}", {"kind": "start_failed",
                                                             "reason": "claude: command not found"}, client=None)
        self.assertEqual(sum("cannot start on studio" in t for t in self.said("manager")), 1)     # once a reason
        self.alive("studio")
        hub.liveness(hub.now())
        hub.liveness(hub.now())
        row = hub.q1("SELECT attempt, restarts FROM tasks WHERE id=?", (tid,))
        self.assertEqual((row["attempt"], row["restarts"]), (2, 2))    # the second counted loss: no more restarts
        told = [t for t in self.said("manager") if "times in a row" in t]
        self.assertEqual(len(told), 1)
        self.assertIn("claude: command not found", told[0])
        # restart_task is never refused by the count: the helper confirms that no session runs, then attempt 3
        text, err = hub.call_tool("manager", "restart_task", {"task_id": f"T-{tid}", "request_id": str(uuid.uuid4()),
                                                              "expected_attempt": 2, "reason": "installed it"})
        self.assertFalse(err, text)
        self.assertEqual(tuple(hub.q1("SELECT attempt, restarts FROM tasks WHERE id=?", (tid,))), (2, 0))
        hold = hub.q1("SELECT * FROM holds WHERE task=? ORDER BY id DESC", (tid,))
        hub.settle_hold(hold, True, "no session runs")
        hub.restart_continue(hold["id"])
        self.assertEqual(tuple(hub.q1("SELECT attempt, restarts FROM tasks WHERE id=?", (tid,))), (3, 0))

    def parked(self, note="the build ends then"):
        """A task whose started session set a reminder and then lost its window: its helper is online, and its list
        has no window of the task."""
        tid = self.task()
        self.started(tid)
        self.alive("studio", f"T-{tid}")
        text, err = self.tool("studio", "set_reminder", tid, minutes=240, note=note)
        self.assertFalse(err, text)
        self.alive("studio")
        return tid, text

    def attempt(self, tid):
        hub.liveness(hub.now())
        return hub.q1("SELECT attempt FROM tasks WHERE id=?", (tid,))["attempt"]

    def test_a_parked_task_whose_session_is_gone_comes_back_for_a_message(self):
        """A task that waits for its reminder reads a message in its own session, which stands open meanwhile. A session
        that was lost (its machine started again) reads nothing, and no session started before the reminder's time: on
        the first fleet a question of a lead's team and a message of its requester waited two hours that way (5
        November 2026). A message that the delivery tells brings the task back in a new session, which is no restart;
        a quiet message does not, and neither does a parked task with nothing to read. The reminder still comes, and
        the new session's start says what the task waits for, so that nothing it held back runs early."""
        note = "send the customer mail at nine, not before. " + "The list of the customers is long. " * 20 + \
            "And never send it before nine."
        tid, said = self.parked(note=note)
        due = hub.q1("SELECT due FROM reminders WHERE task=? AND done=0", (tid,))["due"]

        def row():
            return hub.q1("SELECT attempt, restarts, live_path FROM tasks WHERE id=?", (tid,))
        hub.liveness(hub.now())
        self.assertEqual((row()["attempt"], row()["restarts"]), (1, 0))        # parked, and nothing to read
        self.assertIn("waiting until", row()["live_path"])
        hub.emit("studio", "say", "[hub] A word that can wait.", task=tid, extra=hub.QUIET_SAY)
        self.assertEqual(self.attempt(tid), 1)                  # a quiet message wakes nobody
        hub.emit("studio", "say", "[message from manager on this task] The office is closed on Friday.", task=tid)
        self.alive("studio", f"T-{tid}")
        self.assertEqual(self.attempt(tid), 1)                  # its session runs: the helper types the signal there
        self.alive("studio")
        hub.liveness(hub.now())
        self.assertEqual((row()["attempt"], row()["restarts"]), (2, 0))        # a new session, and no restart
        attempt = hub.q1("SELECT reason FROM attempts WHERE task=? AND attempt=2", (tid,))
        self.assertEqual(attempt["reason"], "message")
        start = hub.q1("SELECT text, extra FROM events WHERE agent='studio' AND kind='task' AND task=? ORDER BY id DESC",
                       (tid,))
        self.assertEqual(json.loads(start["extra"])["attempt"], 2)
        at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(due))
        for words in (f"You are in task T-{tid} again, in a new session, and only for a message: the task itself still "
                      f"waits.", "Do not go on with its own work now, and do not deliver it for the message alone.",
                      "This session starts for a message, and not because the wait is over.",
                      f'your note for it was: "{note}".',                # whole: its last sentence is the condition
                      "Leave what waits for the reminder alone, unless the message changes it.",
                      f'Then call set_reminder again, with at="{at}" unless the message changes the time'):
            self.assertIn(words, start["text"])
        self.assertNotIn("continue and finish with deliver_result", start["text"])      # that is a resumed task's start
        self.assertLess(abs(hub.parse_wake(at, "at", within=None) - due), 1)            # set_reminder takes that time
        self.assertIsNotNone(hub.q1("SELECT 1 FROM reminders WHERE task=? AND done=0", (tid,)))      # it still comes
        self.assertEqual(sum("brought studio back" in r["what"] for r in hub.q("SELECT what FROM log")), 1)
        hub.liveness(hub.now())                                 # the new attempt waits for its start: no third one
        self.assertEqual((row()["attempt"], row()["live_path"]), (2, "waiting for its session to start"))
        unread = hub.q("SELECT text FROM events WHERE agent='studio' AND task=? AND kind='say' AND read_at IS NULL", (tid,))
        self.assertEqual(len(unread), 2)                        # the new session reads both
        self.assertIn(f"A message for T-{tid} still reaches you meanwhile", said)      # and set_reminder says so

    def test_only_a_message_that_somebody_is_behind_starts_a_session_for_a_parked_task(self):
        """The hub's own news starts no session: a new session reads its standing items at its start, a usage limit's
        notice is over when the limit is, a steer of an earlier attempt goes over by itself, and a message that was
        read waits for nobody. Each of them stays for the reminder's own time."""
        tid, _ = self.parked()
        hub.emit("studio", "say", "[hub] New standing item: I-1 instruction, from manager: Sign every reply.", task=tid,
                 extra={"standing": 1})
        hub.emit("studio", "say", "[hub] You reached your usage limit.", task=tid, extra=hub.LIMIT_SAY)
        hub.emit("studio", "say", "[owner] Steering from the owner for this task: an old word.", task=tid,
                 extra={"steer": True, "attempt": 0})
        read = hub.emit("studio", "say", "[message from manager on this task] Read long ago.", task=tid)
        hub.q("UPDATE events SET read_at=? WHERE id=?", (hub.now(), read))
        self.assertEqual(self.attempt(tid), 1)
        self.assertIn("waiting until", hub.q1("SELECT live_path FROM tasks WHERE id=?", (tid,))["live_path"])
        hub.emit("studio", "say", "[owner] Steering from the owner for this task: stop the build.", task=tid,
                 extra={"steer": True, "attempt": 1})
        self.assertEqual(self.attempt(tid), 2)                  # a steer of this attempt is the owner's word: it starts

    def test_a_parked_task_starts_for_a_message_only_on_the_facts_of_its_helper(self):
        """The loss is a fact of the helper's window list (plan C6), and so is this start: nothing starts while the
        helper is silent, while it has no list (tmux did not answer), from a list that it took before it started the
        attempt, for an attempt that it has not started, or for a helper that does not start each attempt once. A
        second session beside one that can still run is the fault that this keeps out."""
        said = "[message from manager on this task] One more thing."
        tid, _ = self.parked()
        hub.emit("studio", "say", said, task=tid)
        with patch.object(hub, "STARTED", hub.now() - 5000):     # a hub that runs for long, so silence counts
            hub.q("UPDATE agents SET last_seen=?, alive_ts=? WHERE name='studio'", (hub.now() - 1000, hub.now()))
            self.assertEqual(self.attempt(tid), 1)              # its helper is silent: its last list is no fact now
        self.alive("studio")
        hub.q("UPDATE agents SET alive_ts=NULL WHERE name='studio'")       # online, and tmux gave no list
        self.assertEqual(self.attempt(tid), 1)
        ack = hub.attempt_started(hub.q1("SELECT * FROM tasks WHERE id=?", (tid,)))
        hub.q("UPDATE agents SET alive_ts=?, last_seen=? WHERE name='studio'", (ack - 1, hub.now()))
        self.assertEqual(self.attempt(tid), 1)                  # a list from before the start's ack says nothing of it
        hub.q("UPDATE machine_status SET data=? WHERE agent='studio'", (json.dumps({"features": []}),))
        self.alive("studio")
        self.assertEqual(self.attempt(tid), 1)                  # a helper that does not start each attempt once
        hub.q("UPDATE machine_status SET data=? WHERE agent='studio'", (json.dumps({"features": ["start_once"]}),))
        self.assertEqual(self.attempt(tid), 2)                  # online, a list after the ack, and no window: it starts
        other = self.task()                                     # an attempt that its helper has not started
        self.assertFalse(self.tool("studio", "set_reminder", other, minutes=240, note="later")[1])
        hub.emit("studio", "say", said, task=other)
        self.alive("studio")
        self.assertEqual(self.attempt(other), 1)
        soon, _ = self.parked()                                 # a reminder that comes in a moment brings it back
        hub.q("UPDATE reminders SET due=? WHERE task=? AND done=0", (hub.now() + hub.PARK_SOON - 30, soon))
        hub.emit("studio", "say", said, task=soon)
        self.assertEqual(self.attempt(soon), 1)                 # itself, and the message with it: no start before it
        hub.q("UPDATE reminders SET due=? WHERE task=? AND done=0", (hub.now() + hub.PARK_SOON + 30, soon))
        self.assertEqual(self.attempt(soon), 2)

    def test_a_parked_task_with_a_message_waits_for_what_makes_any_lost_session_wait(self):
        """With a message to read and no session, a parked task is judged as one that is not parked: its own open
        question holds it as it holds any task whose session is gone, and so does a usage limit. It starts when
        nothing holds it any more."""
        tid = self.task()
        self.started(tid)
        self.alive("studio", f"T-{tid}")
        self.assertFalse(self.tool("studio", "set_reminder", tid, minutes=240, note="later")[1])
        qid = hub.ins("INSERT INTO questions(task, asker, requester, text, asked) VALUES(?,?,?,?,?)",
                      (tid, "studio", "manager", "Which region?", hub.now()))
        hub.emit("studio", "say", "[message from manager on this task] One more thing.", task=tid)
        self.alive("studio")

        def row():
            return hub.q1("SELECT attempt, restarts, live_path FROM tasks WHERE id=?", (tid,))
        hub.liveness(hub.now())
        self.assertEqual((row()["attempt"], row()["live_path"]), (1, f"waiting for the answer to Q-{qid}"))
        hub.q("UPDATE questions SET answer='eu', answered=? WHERE id=?", (hub.now(), qid))
        limit = hub.ins("INSERT INTO agent_limits(agent,since,until,reset_known) VALUES('studio',?,?,1)",
                        (hub.now(), hub.now() + 600))
        hub.liveness(hub.now())
        self.assertEqual(row()["attempt"], 1)                   # at its usage limit: nothing starts
        self.assertIn("usage limit", row()["live_path"])
        hub.q("UPDATE agent_limits SET ended=? WHERE id=?", (hub.now(), limit))
        hub.liveness(hub.now())
        self.assertEqual((row()["attempt"], row()["restarts"]), (2, 0))

    def test_a_lost_session_that_left_something_restarts_and_counts_nothing(self):
        tid = self.task()
        self.started(tid)
        hub.q("UPDATE tasks SET restarts=1 WHERE id=?", (tid,))
        hub.rpc("studio", {"id": 1, "method": "tools/call", "params": {"name": "nope"}}, {}, ("gen1", f"T-{tid}", "1"))
        self.assertIsNotNone(hub.q1("SELECT started FROM attempts WHERE task=? AND attempt=1", (tid,))["started"])
        hub.ins("INSERT INTO notes(task,agent,ts,text) VALUES(?,?,?,?)", (tid, "studio", hub.now(), "Half done."))
        self.alive("studio")
        hub.liveness(hub.now())
        self.assertEqual(tuple(hub.q1("SELECT attempt, restarts FROM tasks WHERE id=?", (tid,))), (2, 0))

    def test_a_submitted_task_whose_session_died_before_its_first_read_starts_again(self):
        """Attempt 1 too: the helper started its window once, and the window went before list_my_tasks."""
        tid = self.task()
        hub.q("UPDATE tasks SET state='submitted' WHERE id=?", (tid,))
        path = lambda: hub.q1("SELECT live_path FROM tasks WHERE id=?", (tid,))["live_path"]
        self.alive("studio")
        hub.liveness(hub.now())
        self.assertEqual(path(), "waiting for its session to start")
        self.started(tid)
        self.alive("studio", f"T-{tid}")
        hub.liveness(hub.now())
        self.assertEqual(path(), "live session")
        self.alive("studio")
        hub.liveness(hub.now())
        self.assertEqual(tuple(hub.q1("SELECT attempt, restarts FROM tasks WHERE id=?", (tid,))), (2, 1))

    def test_the_list_from_before_the_ack_says_nothing_of_the_window_it_started(self):
        """The live check of 27 October 2026: each new task lost its first session within two seconds. Its helper
        takes its list before the poll that brings the task, and the hub read that list after the ack."""
        tid = self.task()
        hub.q("UPDATE tasks SET state='submitted' WHERE id=?", (tid,))
        self.alive("studio", seen=1)                            # the poll's list, taken before the window started
        self.started(tid)
        hub.liveness(hub.now())
        self.assertEqual(tuple(hub.q1("SELECT attempt, restarts, live_path FROM tasks WHERE id=?", (tid,))),
                         (1, 0, "helper online"))
        self.alive("studio", f"T-{tid}")                        # the next poll's list has it
        hub.liveness(hub.now())
        self.assertEqual(hub.q1("SELECT live_path FROM tasks WHERE id=?", (tid,))["live_path"], "live session")

    def test_a_restart_that_waits_for_its_stop_waits_with_no_cut(self):
        tid = self.task()
        self.started(tid)
        hub.rpc("studio", {"id": 1, "method": "tools/call", "params": {"name": "nope"}}, {}, ("gen1", f"T-{tid}", "1"))
        self.alive("studio", f"T-{tid}")
        text, err = hub.call_tool("manager", "restart_task", {"task_id": f"T-{tid}", "request_id": str(uuid.uuid4()),
                                                              "expected_attempt": 1, "reason": "its screen froze"})
        self.assertFalse(err, text)
        hub.q("UPDATE restart_holds SET created=?", (hub.now() - 3600,))
        hub.restart_sweep(hub.now())
        self.assertEqual(hub.q1("SELECT state FROM restart_holds")["state"], "pending")      # it waits for the helper


class HelperStarts(unittest.TestCase):
    def test_a_started_attempt_whose_window_is_gone_is_not_started_again_by_the_helper(self):
        """Plan C6: the helper restarted a dead attempt at every poll, with no report. Now the hub decides."""
        import fleet
        helper = fleet.Helper("vps", {"role": "worker", "runtime": "claude", "machine": "vps", "can": ["shell"]})
        sent = []
        event = {"id": 9, "kind": "task", "task": "T-7", "text": "Go.", "extra": {"generation": "g", "attempt": 1},
                 "started": True}
        with patch.object(helper, "look", return_value=[]), patch.object(helper, "start") as start, \
                patch.object(fleet, "http", lambda m, p, b=None, timeout=40: (sent.append((p, b)), (200, {}))[1]):
            helper.handle_events([event])
            helper.handle_events([event])
        start.assert_not_called()
        self.assertEqual(sent, [("/helper/dialog/vps/T-7", {"kind": "start_failed",
                                                             "reason": "its window ended before its session read the task"})])

    def test_a_list_that_tmux_cannot_read_is_no_list(self):
        import fleet
        helper = fleet.Helper("vps", {"role": "worker", "runtime": "claude", "machine": "vps", "can": ["shell"]})
        with patch.object(fleet, "tmux", return_value=unittest.mock.Mock(returncode=1, stdout="")):
            self.assertIsNone(helper.look_known())
        with patch.object(fleet, "tmux", return_value=unittest.mock.Mock(returncode=0, stdout="home\nT-3\n")):
            self.assertEqual(helper.look_known(), ["T-3"])


class HelperScreens(unittest.TestCase):
    IDLE = ("✻ Cogitated for 6s · done 7:25 AM\n\n\n                        control this session from your phone\n"
            "────────────────────────────────────────\n❯ \n────────────────────────────────────────\n"
            "  ⏵⏵ don't ask on (shift+tab to cycle)\n")          # leo's Claude Code 2.1.285, read on 26 October 2026
    RUNNING = "✻ Cogitating… (12s · ↓ 300 tokens · esc to interrupt)\n\n────\n❯ \n────\n"
    ASKS = ("Do you want to make this edit to hub.py?\n❯ 1. Yes\n  2. Yes, allow all edits\n  3. No, and tell Claude\n\n"
            "Esc to cancel\n")

    def test_each_screen_has_one_class(self):
        import fleet
        self.assertEqual([fleet.screen_class(s) for s in (self.IDLE, self.RUNNING, self.ASKS, "Starting…\n", "")],
                         ["idle", "running", "question", "unknown", "unknown"])
        self.assertEqual(fleet.screen_class("────\n❯ a line not sent yet\n────\n"), "unknown")
        self.assertEqual(fleet.screen_class("Fleet: the agent is working. Ctrl-C stops it.\n"), "running")
        self.assertEqual(fleet.screen_class(self.FRESH), "idle")             # the hint of a new session's empty box
        self.assertEqual(fleet.screen_class(self.FRESH.replace('Try "fix lint errors"', 'New fleet messages.')),
                         "unknown")                                          # a typed line that is not taken yet

    # otto's T-156 window on worker-3 (Claude Code 2.1.311, 5 November 2026), which stood at this screen for 3 hours
    FRESH = (" ▐▛███▛█   Claude Code v2.1.311\n▝▜██████▀  Opus 5.5 · Claude Team\n ▝▝   ▝▝   ~/fleet-otto\n\n"
             "────────────────────────────────────────\n❯ Try \"fix lint errors\"\n"
             "────────────────────────────────────────\n  ⏵⏵ don't ask on (shift+tab to cycle)\n")

    def test_a_new_session_whose_empty_box_shows_a_hint_gets_its_first_line(self):
        """5 November 2026: after 44cf86ad a new Claude session's first line waited for its own empty input line, and
        a new session's empty box shows a dim hint, which capture-pane gives as text. Two agents' tasks
        stood at that first screen for hours, with no line typed."""
        import fleet
        helper = fleet.Helper("vps", {"role": "worker", "runtime": "claude", "machine": "vps", "can": ["shell"]})
        shown = ["Starting…\n"]

        def tmux(*args, **_kw):
            if args[0] == "capture-pane":
                return unittest.mock.Mock(returncode=0, stdout=shown[0])
            return unittest.mock.Mock(returncode=0, stdout="T-9\t@5\t\n")
        with patch.object(fleet, "tmux", tmux), patch.object(fleet, "start_window"), \
                patch.object(fleet, "http", lambda *_a, **_k: (200, {})), \
                patch.object(helper, "records_at", lambda _w: None):
            helper.start("T-9", "claude x", session="x")
            helper.listed = {"T-9": 1}                              # its session listed its tools
            helper.watch_screens()
            self.assertFalse(helper.first_line_due("T-9"))           # its input box is not up
            shown[0] = self.FRESH
            helper.watch_screens()
            self.assertFalse(helper.first_line_due("T-9"))           # one reading of its empty box
            helper.watch_screens()
            self.assertTrue(helper.first_line_due("T-9"))            # two that agree: the hint is its empty input line

    def test_an_open_panel_of_claude_code_is_a_question_and_the_prompt_s_own_hints_are_not(self):
        """/config in leo's T-12 window (Claude Code 2.1.285, 27 October 2026), before and after its first Esc."""
        import fleet
        rows = "   ❯ Auto-compact                            true\n     Reduce motion                           false\n"
        for footer in ("Type to filter · Enter/↓ to select · ↑ to tabs · Esc to clear",
                       "Enter/Space to change · / to search · Esc to close"):
            self.assertEqual(fleet.screen_class(f"   Settings  Status   Config\n\n{rows}     ↓ 35 more\n\n   {footer}\n"),
                             "question", footer)
        self.assertEqual(fleet.screen_class(self.IDLE.replace("control this session from your phone",
                                                              "double tap esc to clear input")), "idle")
        self.assertEqual(fleet.screen_class(self.RUNNING + "  ⏵⏵ don't ask on (shift+tab to cycle) · esc to interrupt\n"),
                         "running")

    def lines(self, screens=None):
        import fleet
        helper = fleet.Helper("vps", {"role": "worker", "runtime": "claude", "machine": "vps", "can": ["shell"]})
        typed, sent = [], []
        window = unittest.mock.Mock(returncode=0, stdout="@4\n")
        return fleet, helper, typed, sent, window

    def test_one_untaken_line_one_retell_at_the_next_idle_point_and_then_a_report(self):
        """Plan C5: no line goes because of time. While its last line is not taken and it has not been idle since, a
        session gets no new line; one still unread at its next idle point is told once more, then reported once."""
        fleet, helper, typed, sent, window = self.lines()
        helper.ready_base["T-7"] = 0
        with patch.object(fleet, "tmux", return_value=window), \
                patch.object(fleet, "type_into", lambda s, w, t: typed.append(w) or "typed"), \
                patch.object(fleet, "http", lambda m, p, b=None, timeout=40: (sent.append((p, b)), (200, {}))[1]):
            helper.signal("T-7", [1])
            self.assertEqual(typed, [])                         # its tools are not listed yet
            helper.listed = {"T-7": 1}
            helper.screens["T-7"] = {"class": "idle", "idle_run": 1}    # and its screen shows its empty input line
            helper.signal("T-7", [1])
            helper.signal("T-7", [1, 2])                        # a new message, and the first line is not taken
            self.assertEqual(typed, ["T-7"])
            helper.idle_at["T-7"] = time.monotonic() + 1        # its next idle point: told once more
            helper.signal("T-7", [1, 2])
            self.assertEqual(typed, ["T-7", "T-7"])
            helper.idle_at["T-7"] = time.monotonic() + 2        # idle again and still unread: reported, not typed
            helper.signal("T-7", [1, 2])
            helper.signal("T-7", [1, 2])
            self.assertEqual(typed, ["T-7", "T-7"])
            self.assertEqual(sent, [("/helper/dialog/vps/T-7", {"kind": "untaken"})])
            helper.signal("T-7", [3])                           # it read the first two: the next message has a line
            self.assertEqual(typed, ["T-7", "T-7", "T-7"])

    def test_the_report_of_an_untaken_line_goes_again_until_the_hub_answers(self):
        """The line was marked reported before its POST, and a POST that failed was ignored, so a hub that did not
        answer never heard of the line. No answer, or a 5xx, leaves it unreported, and the next poll sends the report
        again; only the hub's answer ends it, and nothing is typed again because of it."""
        fleet, helper, typed, sent, window = self.lines()
        helper.ready_base["T-7"], helper.listed = 0, {"T-7": 1}
        helper.screens["T-7"] = {"class": "idle", "idle_run": 1}
        answers = [ConnectionRefusedError("hub away"), (503, {}), (200, {})]

        def http(method, path, body=None, timeout=40):
            sent.append((path, body))
            answer = answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer
        with patch.object(fleet, "tmux", return_value=window), \
                patch.object(fleet, "type_into", lambda s, w, t: typed.append(w) or "typed"), \
                patch.object(fleet, "http", http):
            helper.signal("T-7", [1])
            helper.idle_at["T-7"] = time.monotonic() + 1        # its next idle point: told once more
            helper.signal("T-7", [1])
            helper.idle_at["T-7"] = time.monotonic() + 2        # still unread: reported
            for _ in range(4):                                  # no answer, a 503, then the hub takes it
                helper.signal("T-7", [1])
        self.assertEqual(typed, ["T-7", "T-7"])
        self.assertEqual(sent, [("/helper/dialog/vps/T-7", {"kind": "untaken"})] * 3)

    def test_a_session_whose_tools_never_list_gets_its_line_after_three_idle_readings(self):
        fleet, helper, typed, sent, window = self.lines()
        helper.ready_base["T-8"] = 0
        helper.screens["T-8"] = {"last": "idle", "class": "idle", "told": None, "idle_run": 3}
        with patch.object(fleet, "tmux", return_value=window), \
                patch.object(fleet, "type_into", lambda s, w, t: typed.append(w) or "typed"):
            helper.signal("T-8", [5])
        self.assertEqual(typed, ["T-8"])

    def test_a_question_that_opens_before_the_enter_gets_no_enter(self):
        import fleet
        screens, keys = ["❯ \n", "Do you trust this folder?\n❯ 1. Yes, I trust this folder\n  2. No, exit\n"], []

        def tmux(*args, **_kw):
            if args[0] == "send-keys":
                keys.append(args[-1])
            out = "0\n" if "#{pane_in_mode}" in args else screens.pop(0) if args[0] == "capture-pane" else ""
            return unittest.mock.Mock(returncode=0, stdout=out)
        with patch.object(fleet, "tmux", tmux), patch.object(fleet.time, "sleep"):
            self.assertEqual(fleet.type_into("fleet-vps", "T-9", "New fleet messages."), "asks")
        self.assertNotIn("Enter", keys)

    def test_a_line_that_stays_in_the_input_box_gets_its_enter_again(self):
        """3 November 2026: the Enter after the first line of a new session was lost, the line stayed in Claude Code's
        input box, and the task waited 1 h 40 min. After the Enter the helper reads the screen, and while the line is
        still there and no turn runs, it presses Enter again, ENTER_AGAIN times at most. A question that opens gets no
        Enter, and a runner's window, which has no input box, gets its one Enter only."""
        import fleet
        line = 'New fleet messages. Call read_messages(task_id="T-94") now.'
        empty, held = "────\n❯ \n────\n  ? for shortcuts\n", f"────\n❯ {line}\n────\n  ? for shortcuts\n"
        running = f"> {line}\n\n✻ Reading… (2s · esc to interrupt)\n────\n❯ \n────\n"
        question = "Do you trust this folder?\n❯ 1. Yes, I trust this folder\n  2. No, exit\n"
        cases = (([held, running], 2, True), ([empty], 1, True), ([held] * 5, 1 + fleet.ENTER_AGAIN, True),
                 ([question, held], 1, True), ([held], 1, False))
        for after, enters, asks in cases:
            screens, keys = [empty, held] + after, []

            def tmux(*args, **_kw):
                if args[0] == "send-keys":
                    keys.append(args[3:])
                out = "0\n" if "#{pane_in_mode}" in args else screens.pop(0) if args[0] == "capture-pane" else ""
                return unittest.mock.Mock(returncode=0, stdout=out)
            with self.subTest(after=after[0][:20], asks=asks), patch.object(fleet, "tmux", tmux), \
                    patch.object(fleet.time, "sleep"):
                self.assertEqual(fleet.type_into("fleet-vps", "T-94", line, asks=asks), "typed")
                self.assertEqual(keys, [("-l", "--", line)] + [("Enter",)] * enters)

    def later_polls(self, window, screens, mode="0", runner=False):
        """One poll that types the line into `window` (its own Enters lost), then one more poll for each screen: what
        was typed, the keys that signal() pressed itself, and what the helper said. mode: tmux's #{pane_in_mode}."""
        import fleet
        role = "manager" if window == "manager" else "worker"
        helper = fleet.Helper("boss", {"role": role, "runtime": "claude", "machine": "m", "can": ["shell"]})
        shown, typed, keys, said = [self.IDLE] + list(screens), [], [], []

        def tmux(*args, **_kw):
            if args[0] == "send-keys":
                keys.append(args[3:])
            out = "@4" if "#{window_id}" in args else mode if "#{pane_in_mode}" in args else \
                shown[0] if args[0] == "capture-pane" else ""
            return unittest.mock.Mock(returncode=0, stdout=out + "\n")
        with patch.object(fleet, "tmux", tmux), patch.object(helper, "say", said.append), \
                patch.object(helper, "runner", lambda _t: runner), \
                patch.object(helper, "restart_fresh", lambda *_a: False), \
                patch.object(helper, "fresh_task", lambda *_a: False), \
                patch.object(fleet, "type_into", lambda s, w, t, asks=True: typed.append((w, asks)) or "typed"):
            while shown:
                helper.signal(window, [1])
                shown.pop(0)
        return typed, keys, said

    def test_a_line_that_its_input_box_still_holds_gets_its_enter_at_later_polls(self):
        """5 November 2026: the manager's line went 3 seconds after its session started again, Claude Code put it into
        its input box without sending it, and no turn ran for more than 4 minutes, until a person pressed Enter. A line
        that the box still holds gets its Enter at each later poll, ENTER_LATER times at most, and is not typed again;
        the helper says so once. No Enter goes while a turn runs, while a question shows, while somebody is scrolled
        back in the window, or into a runner's window, which has no input box."""
        import fleet
        held = f"────\n❯ {fleet.CHAT_SIGNAL}\n────\n  ⏵⏵ don't ask on (shift+tab to cycle)\n"
        running = f"> {fleet.CHAT_SIGNAL}\n\n✻ Reading… (2s · esc to interrupt)\n────\n❯ \n────\n"
        typed, keys, said = self.later_polls("manager", [held] * (fleet.ENTER_LATER + 2))
        self.assertEqual((typed, keys), ([("manager", True)], [("Enter",)] * fleet.ENTER_LATER))
        self.assertEqual([s for s in said if "input box" in s],
                         [f"manager: its line is still in its input box; it gets Enter again at each poll, "
                          f"{fleet.ENTER_LATER} times at most"])
        self.assertEqual(self.later_polls("manager", [held, running, running])[1], [("Enter",)])     # it took it
        for screens, mode, runner in (([running] * 3, "0", False), ([self.ASKS] * 3, "0", False),
                                      ([held] * 3, "1", False), ([held] * 3, "0", True)):
            with self.subTest(screen=screens[0][:12], mode=mode, runner=runner):
                typed, keys, said = self.later_polls("T-7", screens, mode, runner)
                self.assertEqual((typed, keys), ([("T-7", not runner)], []))

    def test_a_new_session_s_first_line_waits_for_its_own_empty_input_line(self):
        """5 November 2026: the manager's session started again after its sign-in, and its first line went 3 seconds
        later, before its input box was up. The hub's listing of its tools can come first, and the screen watch still
        held the idle readings of the window that the sign-in thread had closed. Its first line now waits until the
        watch agreed on the new window's own empty input line. A runner's window, which has no input box, and a
        runtime whose screen the helper does not read go at their listing."""
        import fleet
        helper = fleet.Helper("boss", {"role": "manager", "runtime": "claude", "machine": "hub", "can": []})
        helper.screens["manager"] = {"last": "idle", "class": "idle", "told": "gone", "wid": "@3", "idle_run": 40}
        shown = ["Resuming conversation…\n"]

        def tmux(*args, **_kw):
            if args[0] == "capture-pane":
                return unittest.mock.Mock(returncode=0, stdout=shown[0])
            return unittest.mock.Mock(returncode=0, stdout="manager\t@5\t\n")
        with patch.object(fleet, "tmux", tmux), patch.object(fleet, "start_window"), \
                patch.object(fleet, "http", lambda *_a, **_k: (200, {})), \
                patch.object(helper, "records_at", lambda _w: None):
            helper.start("manager", "claude --resume x", session="x")
            self.assertFalse(helper.first_line_due("manager"))      # the closed window's readings are not its own
            helper.listed = {"manager": 1}                          # its session listed its tools
            self.assertFalse(helper.first_line_due("manager"))      # while its input box is not up
            helper.watch_screens()
            shown[0] = self.IDLE
            helper.watch_screens()
            self.assertFalse(helper.first_line_due("manager"))      # one reading of its empty input line
            helper.watch_screens()
            self.assertTrue(helper.first_line_due("manager"))       # two that agree
        self.assertEqual(helper.last_class["manager"], "idle")       # the closed window's, as the watch keeps it
        for runtime, runner in (("claude", True), ("codex", False)):
            worker = fleet.Helper("vps", {"role": "worker", "runtime": runtime, "machine": "vps", "can": ["shell"]})
            worker.ready_base["T-9"], worker.listed = 0, {"T-9": 1}
            with patch.object(worker, "runner", lambda _t: runner):
                self.assertTrue(worker.first_line_due("T-9"), runtime)

    def test_the_watch_tells_a_question_once_when_two_readings_agree_and_once_when_it_goes(self):
        import fleet
        helper = fleet.Helper("vps", {"role": "worker", "runtime": "claude", "machine": "vps", "can": ["shell"]})
        screens, sent = {"T-7": [self.ASKS, self.ASKS, self.ASKS, self.RUNNING, self.RUNNING, self.IDLE, self.IDLE]}, []

        def tmux(*args, **_kw):
            if args[0] == "capture-pane":
                return unittest.mock.Mock(returncode=0, stdout=screens["T-7"].pop(0))
            return unittest.mock.Mock(returncode=0, stdout="home\nT-7\n")
        with patch.object(fleet, "tmux", tmux), \
                patch.object(fleet, "http", lambda method, path, body=None, timeout=40: (sent.append((path, body)), (200, {}))[1]):
            for _ in range(7):
                helper.watch_screens()
        # runtime gaps C1: the question stood still between the two readings (no record, no running turn)
        self.assertEqual([s for s in sent if s[1]["kind"] in ("shown", "gone")],
                         [("/helper/dialog/vps/T-7", {"kind": "shown", "still": True}),
                          ("/helper/dialog/vps/T-7", {"kind": "gone"})])
        self.assertEqual(helper.screens["T-7"]["class"], "idle")

    # leo's T-2 window while a foreground `sleep 300` ran (Claude Code 2.1.285, 27 October 2026), cut to its bottom
    STILL = ("● Running a 300-second sleep in the foreground and time it · 6s\n"
             "  ⎿  $ sleep 300 (6s · 2 lines)\n     (ctrl+b ctrl+b (twice) to run in background)\n\n"
             "✶ Zigzagging… (15s · ↓ 684 tokens)\n────\n❯ \n────\n  ⏵⏵ don't ask on (shift+tab to cycle) · esc to interrupt\n")

    def watch(self, screens, records=None, conf=None, gap=3):
        """watch_screens over these screens of T-7, `gap` seconds apart; the dialog reports it sent."""
        import fleet
        conf = conf or {"role": "worker", "runtime": "claude", "machine": "vps", "can": ["shell"]}
        helper = fleet.Helper("vps", conf)
        sent, clock, screens, records = [], [100.0], list(screens), list(records or [None] * len(screens))

        def tmux(*args, **_kw):
            if args[0] == "capture-pane":
                return unittest.mock.Mock(returncode=0, stdout=screens.pop(0))
            return unittest.mock.Mock(returncode=0, stdout="home\nT-7\n")
        with patch.object(fleet, "tmux", tmux), patch.object(fleet.time, "monotonic", lambda: clock[0]), \
                patch.object(helper, "records_at", lambda _w: records[0]), \
                patch.object(fleet, "http", lambda method, path, body=None, timeout=40: (sent.append(body["kind"]), (200, {}))[1]):
            while screens:
                helper.watch_screens()
                records.pop(0)
                clock[0] += gap
        return [k for k in sent if k in ("frozen", "moving")], helper

    def test_a_running_screen_that_stops_moving_is_frozen_once_and_moving_once_again(self):
        """Plan C2 (5): the same running screen with its counter, FROZEN_GAP seconds or more apart and with no new
        record, is frozen; it is told when two readings agree, and once more when it moves again."""
        moving = [self.STILL.replace("15s", f"{s}s") for s in (17, 19, 21)]
        told, helper = self.watch([self.STILL] * 4 + moving)
        self.assertEqual(told, ["frozen", "moving"])
        self.assertEqual(helper.screens["T-7"]["class"], "running")
        told, _ = self.watch([self.STILL] * 5, gap=1)       # readings 1 s apart: frozen only from the old reading
        self.assertEqual(told, ["moving", "frozen"])

    def test_a_still_screen_is_not_frozen_without_its_counter_with_new_records_or_on_codex(self):
        runner = "Fleet: the agent is working. Ctrl-C stops it.\n"
        self.assertEqual(self.watch([runner] * 5)[0], ["moving"])
        self.assertEqual(self.watch([self.STILL] * 5, records=[1.0, 2.0, 3.0, 4.0, 5.0])[0], ["moving"])
        codex = {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]}
        self.assertEqual(self.watch([self.STILL] * 5, conf=codex)[0], ["moving"])

    def test_a_question_whose_permission_hook_still_runs_is_not_told(self):
        """Plan C7: while the task's permission hook asks the hub, Claude Code's question is the prompt that the hub
        carries; only a question with no hook running is the session's own."""
        import fleet
        helper = fleet.Helper("vps", {"role": "worker", "runtime": "claude", "machine": "vps", "can": ["shell"]})
        sent, hooks = [], [[(41, 1, "/usr/bin/python3 /kit/fleet.py hook permission vps T-7", False)]]

        def tmux(*args, **_kw):
            if args[0] == "capture-pane":
                return unittest.mock.Mock(returncode=0, stdout=self.ASKS)
            return unittest.mock.Mock(returncode=0, stdout="home\nT-7\n")
        with patch.object(fleet, "tmux", tmux), patch.object(fleet, "process_table", lambda *_: hooks[0]), \
                patch.object(fleet, "http", lambda method, path, body=None, timeout=40: (sent.append((path, body)), (200, {}))[1]):
            for _ in range(3):
                helper.watch_screens()
            self.assertEqual(sent, [("/helper/dialog/vps/T-7", {"kind": "moving"})])   # its first agreed reading
            hooks[0] = []                       # the hook ended: the question is now the session's own
            helper.watch_screens()
        self.assertEqual(sent[1:], [("/helper/dialog/vps/T-7", {"kind": "shown", "still": True})])

    # Runtime gaps C1. A running turn whose diff holds the words of a question (the coordinator's review, 29 October
    # 2026): its class is "question", and its screen shows the turn.
    DIFF = "● Update(hub.py)\n  ⎿  + 1. Yes\n     + 2. No\n✻ Cogitating… (12s · ↓ 300 tokens · esc to interrupt)\n"
    T7 = "home\t@1\t\nT-7\t@5\tg:3\n"            # tmux's window list: name, window id and @fleet_attempt

    def reports(self, screens, records=None, windows=None, menu=None, answers=None, conf=None, needs="none"):
        """watch_screens over these screens of T-7, one reading each: the reports it sent, but frozen and moving.
        needs: the window's @fleet_needs."""
        import fleet
        conf = conf or {"role": "worker", "runtime": "claude", "machine": "vps", "can": ["shell"]}
        helper = fleet.Helper("vps", conf)
        sent, screens = [], list(screens)
        records, windows = list(records or [None] * len(screens)), list(windows or [self.T7] * len(screens))

        def tmux(*args, **_kw):
            if args[0] == "capture-pane":
                return unittest.mock.Mock(returncode=0, stdout=screens.pop(0))
            if args[0] == "show-options" and args[-1] == "@fleet_needs":
                return unittest.mock.Mock(returncode=0, stdout=needs + "\n")
            return unittest.mock.Mock(returncode=0, stdout=windows[0])

        def http(method, path, body=None, timeout=40):
            sent.append(body)
            return (answers or {}).get(body["kind"], 200), {}
        with patch.object(fleet, "tmux", tmux), patch.object(fleet, "http", http), \
                patch.object(fleet, "hook_waits", return_value=False), \
                patch.object(helper, "records_at", lambda _w: records[0]), \
                patch.object(helper, "window_limit", lambda _w: menu):
            while screens:
                helper.watch_screens()
                records.pop(0)
                windows.pop(0)
        return [b for b in sent if b["kind"] not in ("frozen", "moving")], helper

    def test_a_question_is_told_with_its_attempt_and_whether_its_session_stood_still_since_it_showed(self):
        """A record between two readings, or a running turn on its screen, is no standing still: the hub starts no
        new attempt on it, and its task stays in running_turns."""
        sent, _ = self.reports([self.ASKS] * 4, records=[1.0, 2.0, 2.0, 2.0])
        self.assertEqual(sent, [{"kind": "shown", "attempt": 3, "still": False},
                                {"kind": "shown", "attempt": 3, "still": True}])
        sent, _ = self.reports([self.DIFF] * 4, records=[1.0] * 4)
        self.assertEqual(sent, [{"kind": "shown", "attempt": 3, "still": False}])

    def test_the_usage_limit_menu_is_told_as_limit_and_as_a_question_to_a_hub_that_does_not_know_that_kind(self):
        menu = {"type": "error", "code": "usage_limit", "resets_at": None}
        sent, _ = self.reports([self.ASKS] * 3, menu=menu)
        self.assertEqual(sent, [{"kind": "limit", "attempt": 3}])
        sent, helper = self.reports([self.ASKS] * 3, menu=menu, answers={"limit": 400})     # the release before
        self.assertEqual(sent, [{"kind": "limit", "attempt": 3}, {"kind": "shown", "attempt": 3, "still": True}])
        self.assertEqual(helper.screens["T-7"]["told"], "limit")            # and it is not asked again

    def test_a_new_window_of_the_same_name_is_watched_afresh(self):
        """A new attempt's window replaces the old one under the same name (Helper.handle): its question is its own."""
        sent, _ = self.reports([self.ASKS] * 4, windows=[self.T7] * 2 + ["T-7\t@6\tg:4\n"] * 2)
        self.assertEqual(sent, [{"kind": "shown", "attempt": 3, "still": True},
                                {"kind": "shown", "attempt": 4, "still": True}])

    def test_the_manager_session_at_a_question_closes_once_until_it_made_a_model_call(self):
        """Runtime gaps C1 for the manager: its helper closes it, the hub tells its next session that the question
        reached nobody (kind closed), and a question that the next session shows before its first call is the owner's
        flag, as before. A usage-limit menu waits for its reset."""
        import fleet
        helper = fleet.Helper("manager", {"role": "manager", "runtime": "claude", "machine": "hub", "can": []})
        state = {"wid": 1, "records": 5.0, "call": None, "menu": None}
        killed, sent = [], []

        def tmux(*args, **_kw):
            if args[0] == "capture-pane":
                return unittest.mock.Mock(returncode=0, stdout=self.ASKS)
            if args[0] == "kill-window":
                killed.append(args[-1])
                state["wid"] += 1
            return unittest.mock.Mock(returncode=0, stdout=f"manager\t@{state['wid']}\t\n")
        with patch.object(fleet, "tmux", tmux), \
                patch.object(fleet, "http", lambda m, p, b=None, timeout=40: (b["kind"] in ("frozen", "moving") or
                                                                                sent.append(b), (200, {}))[1]), \
                patch.object(helper, "records_at", lambda _w: state["records"]), \
                patch.object(helper, "window_limit", lambda _w: state["menu"]), \
                patch.object(helper, "window_runtime", lambda _w: "claude"), \
                patch.object(helper, "outdated", lambda: False), \
                patch.object(helper, "last_call", lambda _w: state["call"]):
            for _ in range(2):
                helper.watch_screens()
            self.assertEqual((killed, helper.manager_due, sent),
                             (["=fleet-manager:=manager"], True, [{"kind": "closed"}]))
            helper.manager_due = False              # its watch started it again (manage)
            for _ in range(3):
                helper.watch_screens()              # the new session shows a question before it made any call
            self.assertEqual((len(killed), sent[1:]), (1, [{"kind": "shown", "still": True}]))
            state.update(call=time.time() + 1, records=6.0)     # it made a model call since
            for _ in range(2):
                helper.watch_screens()
            self.assertEqual((len(killed), sent[2:]), (2, [{"kind": "closed"}]))
            helper.manager_due, state["menu"] = False, {"type": "error", "code": "usage_limit",
                                                        "resets_at": time.time() + 600}
            state.update(call=time.time() + 2, records=7.0)
            for _ in range(3):
                helper.watch_screens()              # its usage-limit menu: the hold's, until its reset
            self.assertEqual((len(killed), sent[3:]), (2, [{"kind": "limit"}]))
            state["menu"]["resets_at"] = time.time() - 1
            helper.watch_screens()
            self.assertEqual((len(killed), sent[4:]), (3, []))   # at its reset: a new session, and no word to give


    def test_the_manager_s_closed_word_goes_again_until_the_hub_answers(self):
        """A word lost while the hub restarts would leave the next session untold that its question reached nobody:
        it goes again at each round until the hub answers, as the frozen word does."""
        import urllib.error
        import fleet
        helper = fleet.Helper("manager", {"role": "manager", "runtime": "claude", "machine": "hub", "can": []})
        state = {"wid": 1}
        answers, sent = [None, (503, {}), (200, {})], []

        def tmux(*args, **_kw):
            if args[0] == "capture-pane":
                return unittest.mock.Mock(returncode=0, stdout=self.ASKS)
            if args[0] == "kill-window":
                state["wid"] += 1
            return unittest.mock.Mock(returncode=0, stdout=f"manager\t@{state['wid']}\t\n")

        def http(method, path, body=None, timeout=40):
            if body["kind"] != "closed":
                return 200, {}
            sent.append(body)
            answer = answers.pop(0)
            if answer is None:
                raise urllib.error.URLError("the hub restarts")
            return answer
        with patch.object(fleet, "tmux", tmux), patch.object(fleet, "http", http), \
                patch.object(helper, "records_at", lambda _w: 5.0), \
                patch.object(helper, "window_limit", lambda _w: None), \
                patch.object(helper, "window_runtime", lambda _w: "claude"), \
                patch.object(helper, "outdated", lambda: False), \
                patch.object(helper, "last_call", lambda _w: None):
            for _ in range(2):
                helper.watch_screens()              # it closes the session while the hub is away
            self.assertEqual((sent, helper.closed_due), ([{"kind": "closed"}], True))
            helper.manager_due = False              # its watch started it again (manage)
            for _ in range(3):
                helper.watch_screens()              # a 503, then the hub takes it, then nothing more
            self.assertEqual((sent, helper.closed_due), ([{"kind": "closed"}] * 3, False))

    def test_a_runner_window_shows_no_question_whatever_its_agent_writes(self):
        """The review of 29 October 2026: screen_runner.py prints its agent's own words as they come, and nothing in it
        asks on its screen, so a "1. Yes" or an "Esc to cancel" there must neither cost a healthy screen task its one
        new attempt nor take it out of running_turns."""
        sent, _ = self.reports([self.ASKS] * 3, needs="screen")
        self.assertEqual(sent, [{"kind": "gone", "attempt": 3}])

    def test_a_window_whose_session_has_background_work_open_is_not_closed_at_a_question(self):
        """The review of 29 October 2026: an async agent, a workflow or a background command writes records of its own
        while the session's main record file stands still, so neither the manager's session nor a conversation window
        closes at a question then, and nothing tells the manager that its question reached nobody."""
        import fleet
        import threads
        agent_call = [{"type": "assistant", "sessionId": "s1", "message": {"id": "m-a1", "content": [
                          {"type": "tool_use", "id": "a1", "name": "Agent", "input": {"description": "look"}}]}},
                      {"type": "user", "sessionId": "s1", "toolUseResult": {"status": "async_launched", "agentId": "g1"},
                       "message": {"content": [{"type": "tool_result", "tool_use_id": "a1", "content": "launched"}]}}]
        shell_call = [{"type": "assistant", "sessionId": "s1", "message": {"id": "m-b1", "content": [
                          {"type": "tool_use", "id": "b1", "name": "Bash", "input": {"command": "sleep 300"}}]}},
                      {"type": "user", "sessionId": "s1", "toolUseResult": {"backgroundTaskId": "bash_1"},
                       "message": {"content": [{"type": "tool_result", "tool_use_id": "b1", "content": "running"}]}}]
        for agent, role, window, rows in (("manager", "manager", "manager", agent_call),
                                          ("vps", "worker", "C-3", shell_call)):
            with self.subTest(window):
                helper = fleet.Helper(agent, {"role": role, "runtime": "claude", "machine": "m", "can": ["shell"]})
                feed = threads.Feed((window, "g", 1, "s1"), "claude")
                for row in rows:
                    feed.translator.records(row)
                helper.tailer.feeds[(window, "s1")] = feed
                killed, sent = [], []

                def tmux(*args, **_kw):
                    if args[0] == "capture-pane":
                        return unittest.mock.Mock(returncode=0, stdout=self.ASKS)
                    if args[0] == "kill-window":
                        killed.append(args[-1])
                    return unittest.mock.Mock(returncode=0, stdout=f"{window}\t@1\t\n")
                with patch.object(fleet, "tmux", tmux), patch.object(fleet, "hook_waits", return_value=False), \
                        patch.object(fleet, "http", lambda m, p, b=None, timeout=40: (sent.append(b), (200, {}))[1]), \
                        patch.object(helper, "records_at", lambda _w: 5.0), \
                        patch.object(helper, "window_limit", lambda _w: None), \
                        patch.object(helper, "window_runtime", lambda _w: "claude"), \
                        patch.object(helper, "outdated", lambda: False), patch.object(helper, "last_call", lambda _w: None), \
                        patch.object(helper, "conversation_kind", lambda _w: "tools"):
                    for _ in range(3):
                        helper.watch_screens()
                self.assertEqual(killed, [])
                self.assertNotIn({"kind": "closed"}, sent)

    def test_a_codex_subagent_is_background_work_for_the_helper_too(self):
        """The final review of 29 October 2026: background_open read only pending, shells and background, so the
        subagent that a Codex manager spawned did not keep its session from a close for a question or a restart."""
        import fleet
        import threads
        helper = fleet.Helper("manager", {"role": "manager", "runtime": "codex", "machine": "m", "can": ["shell"]})
        feed = threads.Feed(("manager", "g", 1, "s1"), "codex", root="/kit")
        item = lambda kind, ident: {"timestamp": "2026-10-29T10:00:01.000Z", "type": "event_msg", "payload": {
            "type": "item_completed", "item": {"type": "SubAgentActivity", "id": ident, "kind": kind,
                                               "agent_thread_id": "019a0000-0000-7000-8000-000000000001"}}}
        for row in ({"timestamp": "2026-10-29T10:00:00.000Z", "type": "session_meta",
                     "payload": {"id": "019a0000-0000-7000-8000-000000000000", "cwd": "/kit"}},
                    {"timestamp": "2026-10-29T10:00:00.500Z", "type": "response_item", "payload": {
                        "type": "function_call", "name": "spawn_agent", "namespace": "collaboration",
                        "call_id": "call_S", "arguments": json.dumps({"task_name": "review"})}},
                    item("started", "call_S")):
            feed.translator.records(row)
        helper.tailer.feeds[("manager", "s1")] = feed
        self.assertTrue(helper.background_open("manager"))
        feed.translator.records(item("completed", "subagent-completed-c-turn-1"))
        self.assertFalse(helper.background_open("manager"))

    def test_a_command_that_a_subagent_left_running_is_background_work_for_the_helper_too(self):
        """A subagent's call ends at its first notice, and a background command of its own can run on after it (Claude
        Code keeps the subagent for it, 11 November 2026). background_open read only the session's own calls, so such
        a command did not keep its session from a close for a question or a restart, and it would stop with it."""
        import fleet
        import threads
        helper = fleet.Helper("manager", {"role": "manager", "runtime": "claude", "machine": "m", "can": ["shell"]})
        feed = threads.Feed(("manager", "g", 1, "s1"), "claude", root="/kit")
        side = lambda row: dict(row, sessionId="s1", isSidechain=True)
        child = [side({"type": "assistant", "timestamp": "2026-11-11T10:00:05.000Z", "message": {"content": [
                     {"type": "tool_use", "id": "b1", "name": "Bash",
                      "input": {"command": "npm test", "run_in_background": True}}]}}),
                 side({"type": "user", "timestamp": "2026-11-11T10:00:05.100Z", "message": {"content": [
                     {"type": "tool_result", "tool_use_id": "b1",
                      "content": "Command running in background with ID: bk1. Output is being written to: /tmp/bk1. "
                                 "You will be notified when it completes."}]}}),
                 side({"type": "user", "timestamp": "2026-11-11T10:02:10.000Z", "isMeta": True,
                       "origin": {"kind": "task-notification", "producer": "session-task"}, "message": {"content":
                       "[SYSTEM NOTIFICATION - NOT USER INPUT]\n\n<task-notification>\n<task-id>bk1</task-id>\n"
                       "<tool-use-id>b1</tool-use-id>\n<status>completed</status>\n</task-notification>"}})]
        feed.translator.children = lambda agent, call=None: child if agent == "g1" else None
        notice = lambda clock, call: {"type": "queue-operation", "operation": "enqueue",
                                      "timestamp": f"2026-11-11T{clock}Z", "content":
                                      f"<task-notification>\n<task-id>g1</task-id>\n{call}<status>completed</status>\n"
                                      "</task-notification>"}
        for row in ({"type": "assistant", "sessionId": "s1", "message": {"id": "m-a1", "content": [
                         {"type": "tool_use", "id": "a1", "name": "Agent", "input": {"description": "test"}}]}},
                    {"type": "user", "sessionId": "s1", "toolUseResult": {"status": "async_launched", "agentId": "g1"},
                     "message": {"content": [{"type": "tool_result", "tool_use_id": "a1", "content": "launched"}]}},
                    notice("10:00:10.500", "<tool-use-id>a1</tool-use-id>\n")):
            feed.translator.records(row)
        helper.tailer.feeds[("manager", "s1")] = feed
        self.assertEqual((feed.translator.pending, helper.background_open("manager")), ({}, True))
        feed.translator.records(notice("10:02:10.900", ""))         # its command ended, and the subagent ran again
        self.assertFalse(helper.background_open("manager"))

    def test_a_codex_manager_s_own_records_say_when_its_turn_runs(self):
        """turn_runs read a turn that only the Claude reader kept, so a Codex manager's records always read idle, and
        its helper typed its line into a running turn. A Codex rollout gives each turn's start and its end too."""
        import fleet
        import threads
        helper = fleet.Helper("manager", {"role": "manager", "runtime": "codex", "machine": "m", "can": ["shell"]})
        feed = threads.Feed(("manager", "g", 1, "s1"), "codex", root="/kit")
        helper.tailer.feeds[("manager", "s1")] = feed
        event = lambda kind: {"timestamp": "2026-11-07T10:00:00.000Z", "type": "event_msg",
                              "payload": {"type": kind, "turn_id": "t1"}}
        target = f"={helper.session}:=manager"
        with patch.object(helper, "working", return_value=True):       # its screen shows a running turn
            for kind, runs in (("task_started", True), ("task_complete", False), ("task_started", True),
                               ("turn_aborted", False)):
                feed.translator.records(event(kind))
                self.assertEqual(helper.turn_runs("manager", target), runs, kind)
        feed.translator.records(event("task_started"))
        with patch.object(helper, "working", return_value=False):      # and its screen says idle: idle
            self.assertFalse(helper.turn_runs("manager", target))

    def test_a_runner_window_takes_its_message_signal_whatever_its_agent_printed(self):
        """The final review of 29 October 2026: a runner's screen is its agent's own words, and the runner reads its
        signal only as a typed line, so a "1. Yes" there must not keep the line from it (a screen task then waited
        for ever, and since the runner fix nothing told anybody)."""
        import fleet
        keys = []

        def tmux(*args, **_kw):
            if args[0] == "display-message":
                return unittest.mock.Mock(returncode=0, stdout="0\n")
            if args[0] == "capture-pane":
                return unittest.mock.Mock(returncode=0, stdout=self.ASKS)
            if args[0] == "send-keys":
                keys.append(args[3:])
            return unittest.mock.Mock(returncode=0, stdout="")
        with patch.object(fleet, "tmux", tmux), patch.object(fleet.time, "sleep", lambda _s: None):
            self.assertEqual((fleet.type_into("fleet-vps", "T-3", "New fleet messages."), keys), ("asks", []))
            self.assertEqual(fleet.type_into("fleet-vps", "T-3", "New fleet messages.", asks=False), "typed")
        self.assertEqual(keys, [("-l", "--", "New fleet messages."), ("Enter",)])

    def test_no_conversation_window_closes_for_a_fresh_start_or_a_slot_while_its_background_work_runs(self):
        """The final review of 29 October 2026: a cold conversation window and the least recently used one that gives
        its slot to another were closed while a background command or an async agent of theirs still ran."""
        import fleet
        helper = fleet.Helper("vps", {"role": "worker", "runtime": "claude", "machine": "m", "can": ["shell"]})
        killed = []
        with patch.object(fleet, "tmux", lambda *a, **_k: (killed.append(a) if a[0] == "kill-window" else None,
                                                             unittest.mock.Mock(returncode=0, stdout=""))[1]), \
                patch.object(helper, "conversation_kind", lambda _w: "tools"), \
                patch.object(helper, "window_reuse", lambda _t, _w: (False, "its session is cold")), \
                patch.object(helper, "look", lambda: ["C-1", "C-2"]), \
                patch.object(helper, "background_open", lambda w: w == "C-1"):
            helper.screens = {"C-1": {"class": "idle"}, "C-2": {"class": "idle"}}
            self.assertFalse(helper.fresh_conversation("fleet-vps:=C-1", "C-1"))
            self.assertEqual(killed, [])
            self.assertTrue(helper.free_conversation_slot("C-3"))
            self.assertEqual(killed, [("kill-window", "-t", "=fleet-vps:=C-2")])     # not the one that still works


class HelperPresence(unittest.TestCase):
    def test_the_presence_thread_pings_only_while_a_step_is_named(self):
        import fleet
        helper = fleet.Helper("vps", {"role": "worker", "runtime": "claude", "machine": "vps", "can": ["shell"]})
        sent, naps = [], []

        def sleep(seconds):
            naps.append(seconds)
            if len(naps) == 1:
                helper.doing("task event", "T-9")       # the loop enters a step during the first wait
            if len(naps) > 2:
                raise SystemExit                        # end the thread's loop for the test
        tmux = unittest.mock.Mock(return_value=unittest.mock.Mock(returncode=0, stdout="home\nT-9\n"))
        with patch.object(fleet.time, "sleep", sleep), patch.object(fleet, "tmux", tmux), \
                patch.object(fleet, "http", lambda method, path, body=None, timeout=40: sent.append((path, body))):
            with self.assertRaises(SystemExit):
                helper.presence()
        self.assertEqual(naps, [fleet.PRESENCE] * 3)
        self.assertEqual(len(sent), 2)          # the first wait had no step: nothing was sent
        self.assertEqual(sent[0][0], "/helper/presence/vps")
        self.assertEqual({k: sent[0][1][k] for k in ("step", "task", "alive")},
                         {"step": "task event", "task": "T-9", "alive": "T-9"})
        helper.step = None                      # the loop's next poll
        self.assertIsNone(helper.step)


if __name__ == "__main__":
    unittest.main()

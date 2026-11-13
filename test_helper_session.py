"""The helper's loop around its windows: the tmux session it does not own, and a message that no task owns.

Real tmux on a socket of this test, a stand-in command (`sleep`) in every window, and no hub, no runtime and no AI
call. The helper's conf is this file's own, so no agent of the live team.json is read.
"""
import os
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest
import unittest.mock
import uuid
from unittest.mock import patch

import fleet
from leftovers import tmux_socket

SOCKET = tmux_socket("fleet-session-test")
WORKER = {"role": "worker", "runtime": "claude", "machine": "mac-studio", "can": ["shell"],
          "start": "claude --permission-mode bypassPermissions --tools default {settings} {prompt}"}


@unittest.skipUnless(shutil.which("tmux"), "tmux is not installed")
class HelperSession(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fleet-helper-session-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(subprocess.run, ["tmux", "-S", SOCKET, "kill-server"], capture_output=True)
        real = fleet.tmux
        for p in (patch.object(fleet, "tmux", lambda *args, **kw: real("-S", SOCKET, *args, **kw)),
                  patch.object(fleet, "HOME", os.path.join(self.tmp, ".fleet")),
                  patch.object(fleet, "SESSIONS", os.path.join(self.tmp, ".fleet", "sessions")),
                  patch.object(fleet, "HUB", "http://127.0.0.1:9"),          # never a real hub
                  patch.object(fleet, "http", return_value=(200, {}))):
            p.start()
            self.addCleanup(p.stop)
        self.helper = fleet.Helper("studio", WORKER)
        self.said = []
        self.helper.say = self.said.append
        self.helper.sync_checkout = lambda: None        # no pull of the checkout in a test

    def task(self, name):
        """Start one task window with a stand-in command, as the helper's task event does."""
        self.helper.start(name, "sleep 120", 1, "g1", str(uuid.uuid4()), needs="none")

    def test_a_tmux_server_that_goes_under_the_helper_leaves_it_able_to_start_again(self):
        """The helper made its session at its own start and does not own the tmux server. When that server is
        restarted or killed — `tmux kill-server`, a logout, a crash, the last window killed by hand — every window
        goes with it and `new-window` answers "no server running", so no session of any kind can start. Nothing
        watched for it: the helper went on polling the hub and reporting its machine as healthy while every task
        event failed at its start, so the machine took no work until somebody restarted its service by hand.
        """
        self.assertTrue(self.helper.keep_session())              # its own start: there was no session yet
        self.task("T-1")
        self.assertEqual(self.helper.look(), ["T-1"])

        fleet.tmux("kill-server")                                # the tmux server goes under the helper
        self.assertEqual(self.helper.look(), [])
        with self.assertRaises(subprocess.CalledProcessError):   # a start of its own finds nothing to start in
            self.task("T-2")

        self.assertTrue(self.helper.keep_session())              # the next round of the loop
        self.assertIn(f"the tmux session fleet-studio was gone", self.said[-1])
        self.task("T-2")
        self.assertEqual(self.helper.look(), ["T-2"])
        # The session is new, so the window of T-1 is gone with it: the loop tells the hub which windows are alive,
        # and the hub makes a new attempt of that task instead of waiting for a session that ended.
        self.assertEqual(fleet.windows(self.helper.session), ["home", "T-2"])

    def test_a_window_starts_in_the_checkout_when_the_tmux_server_s_own_folder_is_gone(self):
        """tmux 3.8 starts a new window in the server's own folder whenever that folder was deleted, whatever `-c`
        says. On the owner's Mac Studio (25 October 2026) the server had started in the checkout of the agent's
        earlier name, the rename took that folder away, and Claude Code stopped at once in every window after it, so
        the agent's first owner chat never began. The window's command goes into the checkout itself."""
        old, kit = os.path.join(self.tmp, "old-checkout"), os.path.join(self.tmp, "checkout")
        os.makedirs(old)
        os.makedirs(kit)
        out = os.path.join(self.tmp, "where.txt")
        subprocess.run(["tmux", "-S", SOCKET, "new-session", "-d", "-s", "fleet-studio", "-n", "home"], cwd=old,
                       check=True, capture_output=True)
        os.rmdir(old)                                       # the rename takes the server's own folder away
        with patch.object(fleet, "KIT", kit):
            fleet.start_window("fleet-studio", "owner-chat", f"/bin/pwd > {shlex.quote(out)}")
        for _ in range(50):
            if os.path.exists(out) and open(out).read().strip():
                break
            time.sleep(0.1)
        self.assertIn(open(out).read().strip(), {kit, os.path.realpath(kit)})

    def test_a_session_that_is_there_is_left_alone_and_says_nothing(self):
        """One round per poll, so the round must cost one tmux reading and no line in the log when nothing is
        wrong: a helper that said something every two seconds would bury the line that matters."""
        self.assertTrue(self.helper.keep_session())
        self.task("T-1")
        self.said.clear()
        for _ in range(3):
            self.assertFalse(self.helper.keep_session())
        self.assertEqual((self.said, self.helper.look()), ([], ["T-1"]))

    def test_a_session_that_is_gone_never_reaches_another_whose_name_starts_with_its_own(self):
        """The agents of a Mac share one tmux server, and tmux takes a session that is not there as the start of
        another: with fleet-studio gone, "fleet-studio" found "fleet-studio-lead" (tmux 3.4 and 3.6a). Studio's helper
        then ended that agent's session when it moved away, read that agent's windows as its own, typed into one of
        them, and took its own session for there, so its next task started in the other agent's session."""
        fleet.tmux("new-session", "-d", "-s", "fleet-studio-lead", "-n", "home", "sleep 120", check=True)
        fleet.tmux("new-window", "-d", "-t", "=fleet-studio-lead:", "-n", "T-1", "sleep 120", check=True)
        real_run = subprocess.run
        with patch.object(fleet.sys, "platform", "linux"), \
                patch.object(fleet.subprocess, "run", lambda argv, **kw: real_run(argv, **kw) if argv[0] == "tmux"
                             else None):         # this machine's own services are not this test's to stop
            self.helper.moved_away()
        self.assertEqual(fleet.windows("fleet-studio-lead"), ["home", "T-1"])
        self.assertEqual(self.helper.look(), [])
        self.assertEqual(fleet.type_into("fleet-studio", "T-1", "not for this agent"), "gone")
        self.assertTrue(self.helper.keep_session())
        self.task("T-2")
        self.assertEqual((fleet.windows("fleet-studio"), fleet.windows("fleet-studio-lead")),
                         (["home", "T-2"], ["home", "T-1"]))

    def test_two_windows_of_one_name_take_no_line_and_the_helper_closes_them_for_one_new_window(self):
        """tmux refuses an exact name that two windows have, so nothing can be typed into either. An agent had two
        owner chat windows for eight hours (12 November 2026): its helper wrote "inbox signal gone" at each poll, and
        the owner's message waited until a person closed one by hand. The loop closes them by their tmux ids, both:
        the second start revoked the first window's credential, and its options went to the first by name."""
        self.assertTrue(self.helper.keep_session())
        self.helper.start("owner-chat", "sleep 120", 1, "g1")
        self.task("T-3")
        # the second window, as a start on a window list that tmux did not give made it
        self.helper.start("owner-chat", "sleep 120", 1, "g2")
        self.assertEqual(self.helper.look(), ["owner-chat", "T-3", "owner-chat"])
        self.assertEqual(fleet.type_into("fleet-studio", "owner-chat", "a line", asks=False), "gone")
        both = self.helper.windows_named()["owner-chat"]
        self.assertEqual([attempt for _, attempt in both], ["g2:1", ""])    # the second start's option: on the first
        self.said.clear()
        self.assertEqual(self.helper.one_window_each(), ["owner-chat"])
        self.assertEqual(self.helper.look(), ["T-3"])                       # the name is free; the task goes on
        self.assertEqual(self.said, [f"owner-chat: 2 windows had this name, and tmux types into none of them then; "
                                     f"the helper closed {both[0][0]}, {both[1][0]}, and one window of it starts again"])
        self.helper.start("owner-chat", "sleep 120", 1, "g1")               # the next poll's start
        self.assertEqual(fleet.type_into("fleet-studio", "owner-chat", "a line", asks=False), "typed")
        self.said.clear()
        self.assertEqual((self.helper.one_window_each(), self.said), ([], []))      # one each: no word, nothing closes

    def test_two_shells_of_one_name_that_a_person_opened_stay(self):
        """A person who attaches to the session can open two shells, and tmux names both after the shell. The rule is
        for the names that the helper starts."""
        self.assertTrue(self.helper.keep_session())
        for _ in range(2):
            fleet.tmux("new-window", "-d", "-t", "=fleet-studio:", "-n", "zsh", "sleep 120", check=True)
        self.assertEqual((self.helper.one_window_each(), self.helper.look(), self.said[1:]), ([], ["zsh", "zsh"], []))

    def test_a_listed_chat_window_that_refuses_its_screen_three_polls_in_a_row_is_closed_by_its_id(self):
        """The net under the rule of one window for each name: whatever makes a listed window take no keys, the
        helper does not write "gone" for ever. It closes the windows of that name, and the next poll starts the chat
        again on its own conversation."""
        self.assertTrue(self.helper.keep_session())
        self.helper.start("owner-chat", "sleep 120", 1, "g1")
        fleet.tmux("new-window", "-d", "-t", "=fleet-studio:", "-n", "owner-chat", "sleep 120", check=True)
        for _ in range(fleet.GONE_TRIES - 1):
            self.assertFalse(self.helper.chat_unreachable("gone"))
        self.assertFalse(self.helper.chat_unreachable("typed"))                     # a line that went: the count ends
        for _ in range(fleet.GONE_TRIES - 1):
            self.assertFalse(self.helper.chat_unreachable("gone"))
        self.assertEqual(self.helper.look(), ["owner-chat", "owner-chat"])
        self.assertTrue(self.helper.chat_unreachable("gone"))
        self.assertEqual(self.helper.look(), [])
        self.assertIn("the chat continues its conversation in a new window", self.said[-1])
        for _ in range(fleet.GONE_TRIES + 1):                                       # no window is listed: the next
            self.assertFalse(self.helper.chat_unreachable("gone"))                  # poll's start, nothing to close
        self.helper.start("owner-chat", "sleep 120", 1, "g1")                       # a window that gives its screen:
        for _ in range(fleet.GONE_TRIES + 1):                                       # a "gone" of a slow tmux counts
            self.assertFalse(self.helper.chat_unreachable("gone"))                  # nothing
        self.assertEqual(self.helper.look(), ["owner-chat"])

    def test_a_tmux_that_cannot_be_reached_is_said_once_and_the_round_goes_on(self):
        """tmux itself refusing is not the same as a session that is gone. The round must not raise: the helper's
        loop would end and its process would be restarted over and over by its own service."""
        def refused(*args, check=False, **kw):
            if check:       # as fleet.tmux does it: subprocess.run(..., check=True) on a refusal
                raise subprocess.CalledProcessError(1, args, "", "no server running")
            return subprocess.CompletedProcess(args, 1, "", "no server running")
        with patch.object(fleet, "tmux", refused):
            self.assertFalse(self.helper.keep_session())
        self.assertIn("could not be made again", self.said[-1])



class TaskLessMessage(unittest.TestCase):
    """A `say` event that the hub could file under no task. Stand-in tmux and hub; nothing starts."""

    def setUp(self):
        self.typed, self.said = [], []
        for p in (patch.object(fleet, "tmux", lambda *a, **kw: subprocess.CompletedProcess(a, 0, "", "")),
                  patch.object(fleet, "http", return_value=(200, {})),
                  patch.object(fleet, "type_into", lambda session, window, text:
                               self.typed.append((window, text)) or "typed")):
            p.start()
            self.addCleanup(p.stop)

    def helper(self, role, open_windows):
        h = fleet.Helper("x", dict(WORKER, role=role))
        h.say = self.said.append
        h.look = lambda: list(open_windows)
        return h

    def event(self):
        return {"id": 4, "kind": "say", "task": None, "extra": {}}

    def test_a_message_with_no_task_reaches_the_open_task_sessions(self):
        """The hub files a result told to a requester, a duty given to its holder, a decided permission or a
        question that has waited under no task when it cannot name one. `read_messages` gives the agent every
        unread message whichever task the call names, so the nudge belongs in whatever task session is open.
        This signalled a window named None, which raised TypeError at every poll for as long as the message stayed
        unread: a lead was never told that its subtask had ended, and its helper's log filled with the same line.
        """
        for role in ("worker", "lead"):
            self.typed.clear()
            self.helper(role, ["T-7", "T-9"]).handle_events([self.event()])   # a poll's signals come at its end
            self.assertEqual([w for w, _ in self.typed], ["T-7", "T-9"])
            self.assertTrue(all('read_messages(task_id="T-' in text for _, text in self.typed))

    def test_a_person_s_window_and_the_owner_chat_get_nothing_of_the_fleet(self):
        """A `C-<id>` window is one person's, locked (CHAT-APPS.md 7.2), and the owner chat is the owner's."""
        self.helper("worker", ["C-12", "owner-chat"]).handle_events([self.event()])
        self.assertEqual(self.typed, [])

    def test_with_no_session_open_nothing_is_typed_and_nothing_is_lost(self):
        """The hub keeps the message until a session reads it, so the quiet round is the right answer."""
        self.helper("worker", []).handle_events([self.event()])
        self.assertEqual((self.typed, self.said), ([], []))

    def test_the_manager_is_still_signalled_in_its_standing_session(self):
        self.helper("manager", []).handle_events([self.event()])
        self.assertEqual([w for w, _ in self.typed], ["manager"])


class ChatDelivery(unittest.TestCase):
    """The owner's chat message and the window it goes into: a tmux that does not answer, a chat whose cache went
    cold, and the helper's pause between two polls. Stand-in tmux answers; no hub, no session, no AI call.

    12 November 2026: a server ran out of memory, tmux did not answer the helper in its 15 seconds, and the empty
    list read as "no owner chat window". The helper started a second one, tmux then typed into neither, and the
    owner's next message waited 7 minutes, until a person closed one of the two by hand."""
    A = "anthropic:" + "a" * 32
    EVENTS = [{"id": 7, "kind": "chat", "extra": {"generation": "g1"}}]

    def setUp(self):
        self.helper = fleet.Helper("studio", WORKER)
        # silent: True when tmux answers no command in time, or the commands that it does not answer
        self.said, self.windows, self.silent, self.calls, self.refused = [], ["owner-chat"], (), [], ()
        self.silent_lists = ()      # the window lists of this test that tmux does not answer, by their number from 1
        self.helper.say = self.said.append
        self.helper.chat_cold_at = time.monotonic()     # no look at the chat's cache, but where a test asks for one

        def tmux(*args, **_):
            self.calls.append(args)
            listing = len(self.did("list-windows")) if args[0] == "list-windows" else 0
            if self.silent is True or args[0] in self.silent or listing in self.silent_lists:
                return subprocess.CompletedProcess(args, 124, "", "timed out")      # as fleet.tmux gives it
            if args[0] in self.refused:
                return subprocess.CompletedProcess(args, 1, "", "can't find window: owner-chat")
            if args[0] == "list-windows" and "#{window_id}" in args[-1]:
                return subprocess.CompletedProcess(args, 0, "".join(
                    f"@{n}\t{w}\tg1:1\n" for n, w in enumerate(["home", *self.windows])), "")
            if args[0] == "list-windows":
                return subprocess.CompletedProcess(args, 0, "".join(f"{w}\n" for w in ["home", *self.windows]), "")
            if args[0] == "show-options":
                return subprocess.CompletedProcess(args, 0, "g1:1\n", "")
            if args[0] == "kill-window":        # by its tmux id, or by its exact name
                target = args[args.index("-t") + 1]
                self.windows.remove(["home", *self.windows][int(target[1:])] if target.startswith("@")
                                    else target.rpartition(":=")[2])
            return subprocess.CompletedProcess(args, 0, "", "")
        self.started = unittest.mock.Mock(side_effect=lambda generation: self.windows.append("owner-chat"))
        for p in (patch.object(fleet, "tmux", side_effect=tmux),
                  patch.object(fleet, "http", return_value=(200, {})),
                  patch.object(fleet, "session_credential", return_value="credential"),
                  patch.object(self.helper, "other_runtime_windows", return_value=[]),
                  patch.object(self.helper, "start_chat", self.started),
                  patch.object(self.helper, "report_start")):
            p.start()
            self.addCleanup(p.stop)

    def chat(self):
        self.helper.keep_chat({"warm": True, "ready": True}, "g1")

    def did(self, command):
        return [a for a in self.calls if a[0] == command]

    def test_a_tmux_that_does_not_answer_starts_no_second_chat(self):
        for silent in (True, ("list-windows",)):                        # no command at all, or the list alone
            with self.subTest(silent=silent):
                self.silent = silent
                self.assertIsInstance(fleet.windows("fleet-studio"), fleet.Unlisted)
                self.assertEqual(self.helper.look(), [])                # a reader that only looks: nothing there
                with self.assertRaises(fleet.Silent):                   # a decision: not known
                    self.helper.look_sure()
                self.said.clear()
                self.helper.chat_problem = (None, 0.0)                  # its words are said again in this case
                self.chat()                                             # the poll of 12 November
                self.assertIn("it did not start before a message: tmux did not answer in time", self.said[-1])
                with self.assertRaises(fleet.Silent):                   # his message: it stays pending in the hub
                    self.helper.handle(self.EVENTS[0])
                self.helper.handle_events(self.EVENTS)
                self.assertEqual(self.said[-1], "event 7 remains pending: Silent")
        self.started.assert_not_called()
        self.assertEqual(self.did("kill-window"), [])
        self.silent = ()                                                # tmux answers again: one window, as before
        self.chat()
        self.helper.handle(self.EVENTS[0])
        self.started.assert_not_called()
        self.assertEqual((self.windows, self.helper.wanted), (["owner-chat"], {"owner-chat": {7}}))

    def test_an_option_that_tmux_does_not_give_closes_no_window(self):
        """A show-options with no answer gave "", which read as "another attempt", and the window closed: a chat in
        the middle of its work, or a task whose next lines then said that its window ended."""
        self.silent = ("show-options",)
        self.windows.append("T-5")
        task = {"id": 8, "kind": "task", "task": "T-5", "text": "", "started": True,
                "extra": {"generation": "g1", "attempt": 1}}
        for event in (self.EVENTS[0], task):
            with self.assertRaises(fleet.Silent):
                self.helper.handle(event)
        self.chat()                                                     # keep_chat reads the answer's code itself
        self.assertEqual((self.did("kill-window"), self.windows), ([], ["owner-chat", "T-5"]))
        self.helper.report_start.assert_not_called()
        self.started.assert_not_called()

    def test_a_helper_that_starts_again_types_the_line_of_a_pending_message_at_its_first_poll(self):
        """A release starts each helper again, on some days each half hour. The hub gives a chat event at each poll
        until its session read it and replied, and a new helper knows nothing of a line that the one before it typed:
        it types into the window that ran before it at once (first_line_due), and one line, not one at each poll."""
        with patch("fleet.type_into", return_value="typed") as typed:
            again = fleet.Helper("studio", WORKER)                      # the helper after the release
            again.say = self.said.append
            with patch.object(again, "other_runtime_windows", return_value=[]), \
                    patch.object(again, "restart_fresh", return_value=False), \
                    patch.object(again, "start_chat") as start:
                again.handle_events(self.EVENTS)
                typed.assert_called_once_with("fleet-studio", "owner-chat", fleet.CHAT_SIGNAL)
                again.handle_events(self.EVENTS)                        # its line is not taken yet: no second one
                again.handle_events(self.EVENTS + [dict(self.EVENTS[0], id=8)])     # also not for his next message
            start.assert_not_called()
            self.assertEqual(typed.call_count, 1)
        self.assertEqual(self.said, ["owner-chat: inbox signal typed; only read_messages acknowledges delivery"])

    def test_a_missing_session_is_still_an_empty_list(self):
        """Only tmux's silence is no list. A session that is not there has no windows, and the chat starts in the
        session that the loop makes again (keep_session)."""
        gone = subprocess.CompletedProcess([], 1, "", "can't find session: fleet-studio")
        with patch.object(fleet, "tmux", return_value=gone):
            self.assertEqual((fleet.windows("fleet-studio"), self.helper.look_sure()), ([], []))
            self.assertNotIsInstance(fleet.windows("fleet-studio"), fleet.Unlisted)
            with self.assertRaises(fleet.Refused):
                fleet.windows("fleet-studio", checked=True)

    def test_a_task_event_at_a_silent_tmux_starts_nothing_and_reports_no_window_as_ended(self):
        """The same empty list read "the task's window ended before its session read the task" for a task that was
        started, which makes the hub start a new attempt beside a session that runs, and "no window" for one that
        was not, which starts a second window. A Stop read it as "no session ran"."""
        self.silent = True
        for started in (True, False):
            event = {"id": 8, "kind": "task", "task": "T-5", "text": "", "started": started,
                     "extra": {"generation": "g1", "attempt": 1}}
            with patch.object(self.helper, "start") as start, self.assertRaises(fleet.Silent):
                self.helper.handle(event)
            start.assert_not_called()
        stop = {"id": 9, "kind": "stop", "task": "T-5", "extra": {"generation": "g1"}}
        with self.assertRaises(fleet.Silent):                           # a Stop does not count as confirmed,
            self.helper.handle(stop)
        with patch.object(self.helper, "end_requests") as ended, self.assertRaises(fleet.Silent):
            self.helper.control("T-5", {"action": "stop", "generation": "g1"})      # and the owner's Stop touches
        ended.assert_not_called()                                                   # nothing of the task yet
        self.assertEqual(self.said, [])
        with patch.object(self.helper, "start") as start:               # the poll: both stay pending, and the hub
            self.helper.handle_events([event, stop])                    # hears of no start that failed
        start.assert_not_called()
        self.helper.report_start.assert_not_called()
        self.assertEqual(self.said, ["event 8 remains pending: Silent; next try in 15 s",
                                     "event 9 remains pending: Silent"])
        self.silent, self.windows = (), []                              # a start that fails is still told
        with patch.object(self.helper, "start", side_effect=fleet.Refused("no checkout")), \
                patch.object(fleet.time, "monotonic", return_value=time.monotonic() + 60):
            self.helper.handle_events([event])
        self.helper.report_start.assert_called_once_with("T-5", "no checkout")

    def test_each_look_of_a_decision_stops_at_a_tmux_that_goes_silent_in_the_middle(self):
        """A tmux that answers one list and not the next: no later look of the same decision reads "no window"."""
        started = {"id": 8, "kind": "task", "task": "T-5", "text": "", "started": True,
                   "extra": {"generation": "g1", "attempt": 1}}
        self.silent_lists = (3,)                    # its window is not there at two looks; the third has no answer
        with self.assertRaises(fleet.Silent):
            self.helper.handle(started)
        self.helper.report_start.assert_not_called()                    # not "its window ended before it read"
        self.calls.clear()
        self.windows, self.silent_lists = ["T-5"], (1,)     # a Stop: the look before "its turn still runs" is silent
        stop = {"id": 9, "kind": "stop", "task": "T-5", "extra": {"generation": "g1"}}
        with patch.object(self.helper, "closing", return_value=True), self.assertRaises(fleet.Silent):
            self.helper.handle(stop)
        self.calls.clear()
        self.silent_lists = (2,)                    # and the look before its close: not "no window, so finished"
        with patch.object(self.helper, "closing", return_value=False), self.assertRaises(fleet.Silent):
            self.helper.handle(stop)
        self.assertEqual((self.did("kill-window"), self.said, self.windows), ([], [], ["T-5"]))

    def held(self, action, **silence):
        """One Pause or Stop of the task T-5 whose turn the interrupt confirmed; returns (what the hub got, the
        quiesce calls). silence: what tmux does not answer in it."""
        self.windows, self.calls = ["owner-chat", "T-5"], []
        for name, value in silence.items():
            setattr(self, name, value)
        with patch.object(self.helper, "end_requests", return_value=(True, 0)), \
                patch.object(self.helper, "task_work", return_value={}), \
                patch.object(self.helper, "interrupt", return_value=(True, "no turn was running")), \
                patch.object(self.helper.tailer, "flush", return_value=0), patch.object(fleet.time, "sleep"), \
                patch.object(self.helper, "quiesce", return_value=(True, 0, {})) as quiesce:
            self.helper.control("T-5", {"action": action, "generation": "g1", "hold": 3})
        posted = [c.args[2] for c in fleet.http.call_args_list if c.args[1] == "/helper/control/studio"]
        fleet.http.reset_mock()
        return posted[-1], [c.kwargs.get("keep_runtime", c.args[2] if len(c.args) > 2 else None)
                            for c in quiesce.call_args_list]

    def test_a_pause_or_a_stop_at_a_tmux_that_goes_silent_reports_no_session_as_ended(self):
        """After its first look, a Pause read a tmux with no answer as "no session was running" or as "the session
        is closed", and ended the runtime of the session that it must keep; a Stop whose close got no answer said
        "interrupted and closed" for a window that was still open."""
        self.windows.append("T-5")
        self.silent_lists = (1,)
        with self.assertRaises(fleet.Silent):                           # the interrupt's own first look
            self.helper.interrupt("T-5")
        self.assertEqual(self.did("send-keys"), [])
        # a Pause whose last look has no answer: its commands end, its runtime stays (the window is not "gone")
        got, quiesced = self.held("pause", silent_lists=(3,))
        self.assertEqual((got["confirmed"], quiesced), (True, [True]))
        # a Stop: the close and the look after it get no answer, so the window did not close
        got, quiesced = self.held("stop", silent=("kill-window",), silent_lists=(4,))
        self.assertEqual((got["confirmed"], got["detail"], quiesced), (False, "the session window did not close", [True]))
        # tmux answers: the Stop closes the window, and then ends what the task left
        got, quiesced = self.held("stop", silent=(), silent_lists=())
        self.assertEqual((got["confirmed"], got["detail"], quiesced, self.windows),
                         (True, "interrupted and closed", [True, False], ["owner-chat"]))

    def cold(self, idle, screen="", context=True, kills=True):
        """Patches for restart_fresh: a chat whose last model call was `idle` seconds ago, with this screen. context
        False: a session that made no model call yet. kills False: tmux does not answer its kill-window."""
        reading = (40000, 30000, time.time() - idle, None) if context else None
        window = subprocess.CompletedProcess([], 0, f"session-1\t{self.A}\tenv X=1 claude --x\n", "")
        shown = subprocess.CompletedProcess([], 0, screen, "")

        def tmux(*args, **_):
            self.calls.append(args)
            if args[0] == "kill-window":
                if not kills:
                    return subprocess.CompletedProcess(args, 124, "", "timed out")
                self.windows.remove("owner-chat")
            if args[0] == "show-options":
                return subprocess.CompletedProcess(args, 0, "g1:1\n", "")
            return shown if args[0] == "capture-pane" else window
        self.helper.chat_cold_at = float("-inf")
        return (patch.object(self.helper, "look", side_effect=lambda: list(self.windows)),
                patch.object(self.helper, "window_runtime", return_value="claude"),
                patch.object(self.helper, "outdated", return_value=False),
                patch.object(self.helper, "standing_context", return_value=reading),
                patch("fleet.account_now", return_value=self.A), patch("fleet.checkout_team", return_value={}),
                patch("fleet.tmux", side_effect=tmux))

    def test_a_cold_chat_starts_its_new_conversation_before_the_owners_next_message(self):
        """The reuse rule closed a cold chat only when a message came, so the owner's message waited 10 to 11 seconds
        for the start of the new session. The helper asks the rule between two turns and starts it then."""
        for p in self.cold(idle=7200):
            p.start()
            self.addCleanup(p.stop)
        self.chat()
        self.started.assert_called_once_with("g1")
        self.assertTrue(self.helper.__dict__.get("chat_fresh"))         # a new conversation, with the hub's recap
        self.assertIn("its cache is cold after 120 quiet minutes", self.said[-1])
        self.assertEqual(self.windows, ["owner-chat"])
        for _ in range(3):
            self.chat()                                                 # the rule is asked again a minute later,
        self.started.assert_called_once()                               # not at each poll
        self.assertEqual(len(self.did("kill-window")), 1)

    def test_a_new_session_is_not_cold_and_a_warm_or_working_chat_goes_on(self):
        cases = (dict(idle=30), dict(idle=7200, context=False),         # warm; no model call yet: nothing to read
                 dict(idle=7200, screen="\n✻ Working… (12s · esc to interrupt)\n"),
                 dict(idle=7200, screen="\nDo you trust the files in this folder?\n❯ 1. Yes, I trust this folder\n"
                                        "  2. No, exit\n"))
        for case in cases:
            with self.subTest(case=case):
                patches = self.cold(**case)
                for p in patches:
                    p.start()
                self.chat()
                for p in patches:
                    p.stop()
                self.started.assert_not_called()
                self.assertEqual((self.did("kill-window"), self.said), ([], []))

    def test_a_close_that_tmux_does_not_answer_starts_no_second_chat_and_takes_no_credential(self):
        """restart_fresh does not read the answer of its kill-window, and a tmux that does not answer raises nothing:
        the chat window is still there. A start then would be the second window of 12 November, and its new
        credential would revoke the one of the chat that runs."""
        patches = self.cold(idle=7200, kills=False)
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.started.side_effect = lambda generation: fleet.Helper.start_chat(self.helper, generation)      # the real one
        with patch.object(self.helper, "start") as start:
            self.chat()
            start.assert_not_called()
        fleet.session_credential.assert_not_called()
        self.assertEqual(self.windows, ["owner-chat"])
        self.assertIn("an owner chat window is open; no second one starts", self.said[-1])
        self.assertTrue(self.helper.__dict__.get("chat_fresh"))         # its next start is still a new conversation

    def test_a_look_at_the_cache_that_fails_closes_nothing(self):
        self.helper.chat_cold_at = float("-inf")
        with patch.object(self.helper, "restart_fresh", side_effect=OSError("no such file")):
            self.chat()
        self.started.assert_not_called()
        self.assertIn("the look at its cache failed (OSError)", self.said[-1])

    def blocked(self, **patches):
        """The helper's own steps around a signal, each as this test needs it."""
        values = dict(first_line_due=True, turn_runs=False, restart_fresh=False, chat_unreachable=False)
        values.update(patches)
        return [patch.object(self.helper, name, return_value=value) for name, value in values.items()]

    def told(self):
        return [c.args[2] for c in fleet.http.call_args_list if c.args[:2] == ("POST", "/helper/dialog/studio/owner-chat")]

    def test_a_line_that_cannot_be_typed_at_ten_polls_in_a_row_is_told_to_the_hub_once(self):
        """The helper wrote "inbox signal gone" 190 times in seven minutes, to its own log only. A count of polls,
        one report for each run, and a line that went ends the run."""
        for p in self.blocked():
            p.start()
            self.addCleanup(p.stop)
        with patch("fleet.type_into", return_value="asks") as typed:
            for _ in range(fleet.CHAT_BLOCKED_POLLS - 1):
                self.helper.handle_events(self.EVENTS)
            self.assertEqual(self.told(), [])
            typed.return_value = "typed"                                # the question went: its line is typed
            self.helper.handle_events(self.EVENTS)
            self.helper.lines.clear()
            typed.return_value = "asks"
            for _ in range(fleet.CHAT_BLOCKED_POLLS + 5):
                self.helper.handle_events(self.EVENTS)
                self.helper.lines.clear()
        self.assertEqual(self.told(), [{"kind": "undelivered", "reason": "its screen shows a question of its own"}])
        self.assertEqual(len([line for line in self.said if "the hub knows" in line]), 1)
        self.silent = True                                              # a chat event that fails counts too,
        fleet.http.reset_mock()
        self.helper.handle_events([])                                   # after a poll with nothing for the chat
        for _ in range(fleet.CHAT_BLOCKED_POLLS):
            self.helper.handle_events(self.EVENTS + [dict(self.EVENTS[0], id=8)])   # one count for each poll
        self.assertEqual([body["kind"] for body in self.told()], ["undelivered"])
        self.assertIn("tmux did not answer in time", self.told()[0]["reason"])

    def test_a_session_that_never_takes_its_first_line_and_a_line_told_twice_are_told_too(self):
        for p in self.blocked(first_line_due=False):
            p.start()
        for _ in range(fleet.CHAT_BLOCKED_POLLS):                       # a start takes four or five polls, not ten
            self.helper.handle_events(self.EVENTS)
        self.assertEqual(self.told(), [{"kind": "undelivered", "reason": "its new session cannot take its first line yet"}])
        patch.stopall()
        self.setUp()
        for p in self.blocked():
            p.start()
            self.addCleanup(p.stop)
        fleet.http.return_value = (400, {"error": "kind is shown, gone, …"})     # a hub from before this report
        self.helper.lines["owner-chat"] = {"wid": "", "ids": frozenset({7}), "at": 0.0, "retold": True,
                                           "reported": True, "text": fleet.CHAT_SIGNAL, "box": True, "enters": 3}
        with patch.object(self.helper, "idle_since", return_value=True):        # its window can no longer call the hub
            for _ in range(fleet.CHAT_BLOCKED_POLLS):
                self.helper.handle_events(self.EVENTS)
        self.assertEqual(self.told(), [{"kind": "undelivered", "reason": "its line was told twice and not taken"}])
        self.assertIn("the hub did not take the report (400)", self.said[-1])

    def test_a_chat_that_ends_at_each_start_is_told_and_one_start_is_not(self):
        self.windows = []
        self.started.side_effect = None                                 # a start whose window ends at once
        for _ in range(fleet.CHAT_BLOCKED_POLLS - 1):
            self.helper.handle_events(self.EVENTS)
        self.assertEqual(self.told(), [])
        self.helper.handle_events(self.EVENTS)
        self.assertEqual(self.told(), [{"kind": "undelivered", "reason": "its window was not there and started"}])
        self.assertEqual(self.started.call_count, fleet.CHAT_BLOCKED_POLLS)

    def test_a_line_that_finds_no_session_in_a_listed_window_closes_it_at_the_third_poll(self):
        """signal to chat_unreachable, whole: tmux lists the window and refuses its screen."""
        self.refused = ("capture-pane", "display-message")
        for p in self.blocked()[:3]:                                    # not chat_unreachable: the real one
            p.start()
            self.addCleanup(p.stop)
        for n in range(fleet.GONE_TRIES):
            self.assertEqual((self.did("kill-window"), self.windows), ([], ["owner-chat"]))
            self.helper.handle_events(self.EVENTS)
        self.assertEqual(([a[1:] for a in self.did("kill-window")], self.windows), ([("-t", "@1")], []))
        self.assertEqual(self.said[-1], "owner-chat: tmux lists its window and refused its screen at 3 polls in a "
                         "row; the helper closed @1, and the chat continues its conversation in a new window")
        self.helper.handle_events(self.EVENTS)                          # the next poll starts it again
        self.started.assert_called_once_with("g1")

    def test_a_report_that_the_hub_does_not_take_goes_again_at_the_next_such_poll(self):
        with patch.object(fleet, "http", side_effect=[OSError("refused"), (502, {}), (200, {})]) as sent:
            for _ in range(fleet.CHAT_BLOCKED_POLLS + 2):
                self.helper.chat_blocked("its screen shows a question of its own")
            self.assertEqual(sent.call_count, 3)
            for _ in range(3):
                self.helper.chat_blocked("its screen shows a question of its own")
            self.assertEqual(sent.call_count, 3)                        # told: no more for this run

    def test_the_pause_between_two_polls(self):
        """No pause after a poll that the hub held with no event, so that the poll which waits for the owner's next
        message is open again at once; the whole pause otherwise, also after an empty poll that came back at once."""
        pause = self.helper.pause
        self.assertEqual((pause([], 8.2), pause([], fleet.POLL_HELD)), (0, 0))
        self.assertEqual(pause([], 0.1), fleet.LOOP_PAUSE)              # no hot loop on a hub that does not hold
        self.assertEqual(pause(None, 0.1), fleet.LOOP_PAUSE)
        self.assertEqual(pause(self.EVENTS, 0.1), fleet.LOOP_PAUSE)     # something is pending: the rounds keep their
        self.assertEqual(pause(self.EVENTS, 8.2), fleet.LOOP_PAUSE)     # rhythm, which their counts were set for


if __name__ == "__main__":
    unittest.main()


class WindowStartCommand(unittest.TestCase):
    """The start command of every window goes into the checkout first (in_checkout), and the program it runs still
    replaces the shell; what reads a start command back (launch_words) still finds that program."""

    def test_each_shape_of_start_command_goes_into_the_checkout_and_keeps_its_exec(self):
        with patch.object(fleet, "KIT", "/Users/dana/fleet-ivy"):
            plain = fleet.in_checkout("env FLEET_TASK= claude --resume x")
            credential = fleet.in_checkout(". /h/.fleet/sessions/a.env && rm -f /h/.fleet/sessions/a.env && exec env A=1 codex")
            own = fleet.in_checkout("cd /Users/dana/fleet-ivy/people && exec env claude")
            login = fleet.in_checkout("exec claude /login")
        self.assertEqual(plain, "cd /Users/dana/fleet-ivy && exec env FLEET_TASK= claude --resume x")
        self.assertTrue(credential.startswith("cd /Users/dana/fleet-ivy && . /h/.fleet/sessions/a.env && rm -f"))
        self.assertTrue(own.startswith("cd /Users/dana/fleet-ivy && cd /Users/dana/fleet-ivy/people && exec env"))
        self.assertEqual(login, "cd /Users/dana/fleet-ivy && exec claude /login")
        self.assertEqual(fleet.launch_words(plain)[:2], ["claude", "--resume"])
        self.assertEqual(fleet.launch_words(credential), ["codex"])
        self.assertEqual(fleet.launch_words(login), ["claude", "/login"])
        with patch.object(fleet, "KIT", "/Users/dana/my checkout"):
            spaced = fleet.in_checkout("env claude")
        self.assertEqual(spaced, "cd '/Users/dana/my checkout' && exec env claude")
        self.assertEqual(fleet.launch_words(spaced), ["claude"])
        self.assertEqual(fleet.launch_words(shlex.quote(spaced)), ["claude"])     # as tmux shows a quoted command

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
from leftovers import scratch_home, tmux_socket

SOCKET = tmux_socket("fleet-session-test")
WORKER = {"role": "worker", "runtime": "claude", "machine": "mac-studio", "can": ["shell"],
          "start": "claude --permission-mode bypassPermissions --tools default {settings} {prompt}"}


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


@unittest.skipUnless(shutil.which("tmux"), "tmux is not installed")
class HelperSession(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fleet-helper-session-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(subprocess.run, ["tmux", "-S", SOCKET, "kill-server"], capture_output=True)
        real = fleet.tmux
        for p in (patch.object(fleet, "tmux", lambda *args, **kw: real("-S", SOCKET, *args, **kw)),
                  # the tmux server starts the login shell of the person who runs the test in its first window: with
                  # a HOME of this test, that shell reads none of their start files and writes its history here
                  patch.dict(os.environ, {"HOME": self.tmp}),
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


class OwnFolder(unittest.TestCase):
    """No test reads or writes the helper's folder of the machine that runs it (leftovers.scratch_home)."""

    @staticmethod
    def without_a_folder(text):
        """True for the text of a test file that builds a fleet.Helper and does not call scratch_home in its
        setUpModule."""
        return "fleet.Helper(" in text and "def setUpModule():\n    scratch_home()" not in text

    def test_each_test_file_that_builds_a_helper_gives_it_a_folder_of_this_run(self):
        """One rule for every file, so that no class depends on which code its tests reach: a test file that builds
        a fleet.Helper calls scratch_home in its setUpModule. A patch of the folder in one class is not enough: the
        class of 13 November was in a file whose other classes had one. test_helper_control.py sets HOME, and
        fleet.HOME with it, before it imports fleet, for its real hub and its real helper."""
        build = "class A(unittest.TestCase):\n    def test(self):\n        fleet.Helper('dev-lead', {})\n"
        patched = "class B(unittest.TestCase):\n    def setUp(self):\n        patch.object(fleet, \"HOME\", 'x').start()\n"
        self.assertTrue(self.without_a_folder(build))
        self.assertTrue(self.without_a_folder(patched + build))        # one class with its own folder, one without
        self.assertFalse(self.without_a_folder("def setUpModule():\n    scratch_home()      # why\n\n\n" + build))
        self.assertFalse(self.without_a_folder(patched))               # it builds none
        here = os.path.dirname(os.path.abspath(__file__))
        without = []
        for name in sorted(os.listdir(here)):
            if not (name.startswith("test_") and name.endswith(".py")) or name == "test_helper_control.py":
                continue
            with open(os.path.join(here, name), encoding="utf-8") as f:
                if self.without_a_folder(f.read()):
                    without.append(name)
        self.assertEqual(without, [], "a test file that builds a fleet.Helper needs, before its first class: "
                         "def setUpModule(): scratch_home()  (from leftovers import scratch_home)")

    def test_the_folder_is_one_of_this_run_and_a_class_keeps_its_own_inside_it(self):
        real = os.path.expanduser("~/.fleet")
        for path in (fleet.HOME, fleet.SESSIONS, fleet.KEPT_RUNTIMES):
            self.assertFalse(os.path.abspath(path).startswith(real + os.sep) or os.path.abspath(path) == real, path)
        self.assertEqual((fleet.SESSIONS, fleet.KEPT_RUNTIMES),
                         (os.path.join(fleet.HOME, "sessions"), os.path.join(fleet.HOME, "runtimes")))
        module = fleet.HOME
        with tempfile.TemporaryDirectory() as own, patch.object(fleet, "HOME", own):
            self.assertEqual(fleet.HOME, own)
        self.assertEqual(fleet.HOME, module)


class StartText(unittest.TestCase):
    """The hash of a standing session's start text (fleet.standing_text): what a conversation began with, which one
    that continues keeps. A scratch checkout; no session and no hub."""
    def setUp(self):
        self.kit = tempfile.mkdtemp(prefix="fleet-start-text-")
        self.addCleanup(shutil.rmtree, self.kit, ignore_errors=True)
        for name, text in (("RULES.md", "Rules for every agent."), ("rules/lead.md", "Rules for a lead."),
                           ("rules/github.md", "Rules for GitHub."), ("profiles/dev-lead.md", "Looks after the web app."),
                           ("profiles/dev-two.md", "Looks after the logs.")):
            path = os.path.join(self.kit, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(text)
        patcher = patch.object(fleet, "KIT", self.kit)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, name, text):
        with open(os.path.join(self.kit, name), "w") as f:
            f.write(text)

    def test_it_changes_with_each_part_of_the_start_text_and_with_nothing_else(self):
        text = lambda: fleet.standing_text("dev-lead", ["lead"], "The chat's instructions.")
        first = text()
        self.assertEqual((first, len(first)), (text(), 12))                     # the same files, the same hash
        for name, other in (("RULES.md", "Rules for every agent, with one more."),
                            ("rules/lead.md", "Rules for a lead, with one more."),
                            ("profiles/dev-lead.md", "Looks after the web app and its tests.")):
            before = open(os.path.join(self.kit, name)).read()
            self.write(name, other)
            self.assertNotEqual(text(), first, name)
            self.write(name, before)
            self.assertEqual(text(), first, name)
        self.assertNotEqual(fleet.standing_text("dev-lead", ["lead"], "Other instructions."), first)
        self.assertNotEqual(fleet.standing_text("dev-lead", ["lead", "github"], "The chat's instructions."), first)
        self.assertNotEqual(fleet.standing_text("dev-lead", None, "The chat's instructions."), first)
        self.write("rules/github.md", "A part that this session does not start with.")
        self.write("profiles/dev-two.md", "The profile of another agent.")
        os.makedirs(os.path.join(self.kit, "skills", "dev-lead"))
        self.write("skills/dev-lead/release.md", "A skill of its own: it changes with the agent's work.")
        self.assertEqual(text(), first)
        os.remove(os.path.join(self.kit, "profiles", "dev-lead.md"))            # a missing file is a text of its own
        self.assertNotEqual(text(), first)
        for rules in (5, "lead", {"lead": 1}):                                  # a record that something else wrote
            self.assertEqual(fleet.standing_text("dev-two", rules), fleet.standing_text("dev-two", None))


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
        home = tempfile.mkdtemp(prefix="fleet-chat-delivery-")
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        for p in (patch.object(fleet, "tmux", side_effect=tmux),
                  patch.object(fleet, "HOME", os.path.join(home, ".fleet")),        # never the real ~/.fleet: the
                  patch.object(fleet, "SESSIONS", os.path.join(home, ".fleet", "sessions")),   # chat reads its record
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
                self.assertIn("it did not start before a message: tmux gave no list of the windows", self.said[-1])
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
                # also not for his next message, by signal's own rule; in the helper's loop the count on the proof
                # forgets the line at a new message, so that it is told (chat_proof, test_chat_proof)
                again.handle_events(self.EVENTS + [dict(self.EVENTS[0], id=8)])
            start.assert_not_called()
            self.assertEqual(typed.call_count, 1)
        self.assertEqual(self.said, ["owner-chat: inbox signal typed; only read_messages acknowledges delivery"])

    def test_a_missing_session_is_still_an_empty_list(self):
        """A session that is not there has no windows, and the chat starts in the session that the loop makes again
        (keep_session). tmux says so in three ways: no such session, no server, and no socket of a server."""
        for words in ("can't find session: fleet-studio", "no server running on /tmp/tmux-1000/default",
                      "error connecting to /tmp/tmux-1000/default (No such file or directory)"):
            gone = subprocess.CompletedProcess([], 1, "", words)
            with patch.object(fleet, "tmux", return_value=gone):
                self.assertEqual((fleet.windows("fleet-studio"), self.helper.look_sure()), ([], []), words)
                self.assertNotIsInstance(fleet.windows("fleet-studio"), fleet.Unlisted)
                with self.assertRaises(fleet.Refused):
                    fleet.windows("fleet-studio", checked=True)

    def test_each_other_failure_of_tmux_is_no_list_as_its_silence_is(self):
        """A server with no memory left fails in more ways than by its silence: it refuses the connection, or the
        command ends with an error of its own. None of these says that the session has no windows, so each one is
        no list, as an answer that did not come in time is: no chat starts on it, and no window counts as ended."""
        for code, words in ((1, "error connecting to /tmp/tmux-1000/default (Resource temporarily unavailable)"),
                            (1, "server exited unexpectedly"), (1, ""), (2, "lost server"), (124, "timed out")):
            failed = subprocess.CompletedProcess([], code, "", words)
            with patch.object(fleet, "tmux", return_value=failed):
                self.assertIsInstance(fleet.windows("fleet-studio"), fleet.Unlisted, words)
                self.assertEqual(self.helper.look(), [])            # a reader that only looks gets its empty list
                with self.assertRaises(fleet.Silent) as told:
                    self.helper.look_sure()
                self.assertIn(f" ({words})," if words else "fleet-studio,", str(told.exception))    # tmux's own words
                self.assertFalse(self.helper.gone("owner-chat"))
                self.chat()                                         # the chat's keeper decides nothing on it
        self.started.assert_not_called()

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

    def test_a_tmux_that_stays_broken_is_told_for_a_task_when_its_wait_is_the_longest(self):
        """A list that tmux does not give one time says nothing, and the hub hears of no failed start. A tmux that
        stays so (a client and a server of two versions after an update, a socket that it may not open) starts no
        session of a task at all, and its requester must not wait on a line of the helper's log: at the longest wait
        between two tries the hub hears it, one time, with tmux's own words."""
        self.silent = True
        event = {"id": 8, "kind": "task", "task": "T-5", "text": "", "extra": {"generation": "g1", "attempt": 1}}
        at = [time.monotonic()]
        with patch.object(fleet.time, "monotonic", side_effect=lambda: at[0]):
            for wait in (15, 30, 60, 120, 240):
                self.helper.handle_events([event])
                self.helper.report_start.assert_not_called()
                self.assertIn(f"next try in {wait} s", self.said[-1])
                at[0] += wait + 1
            self.helper.handle_events([event])
        self.helper.report_start.assert_called_once_with(
            "T-5", "tmux gave no list of the windows of fleet-studio (timed out), so they are not known; nothing was "
                   "decided on them")

    def test_a_screen_that_tmux_does_not_give_is_no_idle_session(self):
        """working read a screen with no answer as "no turn runs". On that word the helper closes the manager's
        session for its new tools, a conversation window that runs another way now and the previous runtime's chat,
        takes its own update and a runtime's, and counts a Pause as done: each one in a turn that may run. A screen
        that tmux did not give says nothing, so it counts as a turn that runs, and each of them waits."""
        target = "=fleet-studio:=owner-chat"
        self.assertFalse(self.helper.working(target))               # tmux answers: an idle screen
        self.silent = ("capture-pane",)
        self.assertTrue(self.helper.working(target))
        self.silent, self.refused = (), ("capture-pane",)
        self.assertFalse(self.helper.working(target))               # no such window: no turn runs in it

    def test_a_conversation_window_whose_start_tmux_does_not_tell_is_not_closed(self):
        """How a conversation window started is its tmux option. An answer that did not come read as "", which is
        another way than "tools" or "closed": its message closed the window in the middle of the person's turn, and
        so did the round that retires windows."""
        self.windows = ["C-4"]
        self.helper.conversation_modes, self.helper.conversations = {"4": "tools"}, [4]
        self.silent = ("show-options",)
        self.assertIsNone(self.helper.conversation_kind("C-4"))
        with self.assertRaises(fleet.Silent):
            self.helper.conversation_switched("C-4")
        self.helper.retire_conversations()                          # the round closes nothing of it and goes on
        self.assertEqual((self.did("kill-window"), self.windows), ([], ["C-4"]))
        self.silent = ()
        self.assertEqual(self.helper.conversation_kind("C-4"), "g1:1")     # tmux answers again (the stand-in's value)
        self.assertTrue(self.helper.conversation_switched("C-4"))

    def test_a_pause_does_not_end_the_runtime_of_a_session_that_tmux_does_not_show(self):
        """A Pause ends the task's commands and keeps the session's own runtime, which it knows from the window's
        pane. With no answer of tmux about the window, or about its pane, nothing told that runtime from the
        commands, and the Pause ended the session with them."""
        self.windows = ["T-5"]
        for silent in (("list-windows",), ("display-message",)):
            self.silent = silent
            with patch.object(fleet, "process_table", return_value=[(41, 1, "claude", True)]), \
                    self.assertRaises(fleet.Silent):
                self.helper.task_work("T-5", "g1", keep_runtime=True)
        with patch.object(fleet, "process_table", return_value=[(41, 1, "claude", True)]):
            self.assertEqual(self.helper.task_work("T-5", "g1", keep_runtime=False), {41: "claude"})    # a Stop ends all

    def test_a_window_that_this_helper_started_keeps_its_attempt_when_tmux_took_no_option(self):
        """Helper.start goes on at a tmux that does not answer, so a window can run without its @fleet_attempt. The
        next message then read it as another attempt's window and closed a session that had just started. The helper
        knows what it started: such a window is that start's, and it gets its option at that look."""
        self.windows = []
        unset = subprocess.CompletedProcess([], 1, "", "invalid option: @fleet_attempt")
        with patch.object(fleet, "start_window", side_effect=lambda *a, **k: self.windows.append("T-5")):
            self.silent = ("set-option",)
            self.helper.start("T-5", "sleep 120", 2, "g1", "", needs="none")
        self.silent = ()
        answer = fleet.tmux.side_effect
        with patch.object(fleet, "tmux", side_effect=lambda *a, **k: unset if a[0] == "show-options" else answer(*a)):
            self.assertEqual(self.helper.window_attempt("T-5"), "g1:2")
            self.assertEqual(self.helper.window_attempt("C-9"), "")        # a window that it did not start
        self.assertIn(("set-option", "-w", "-t", "=fleet-studio:=T-5", "@fleet_attempt", "g1:2"), self.calls)

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

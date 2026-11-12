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

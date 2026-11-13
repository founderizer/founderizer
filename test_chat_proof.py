"""The one count on the proof of a chat message's delivery: its session's own read (fleet.Helper.chat_proof).

Real tmux on a socket of this test, a stand-in command in every window, and no hub, no runtime and no AI call. The
helper's conf is this file's own, so no agent of the live team.json is read.
"""
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import fleet
from leftovers import tmux_socket

WORKER = {"role": "worker", "runtime": "claude", "machine": "mac-studio", "can": ["shell"],
          "start": "claude --permission-mode bypassPermissions --tools default {settings} {prompt}"}
POLLS = fleet.CHAT_PROOF_POLLS


@unittest.skipUnless(shutil.which("tmux"), "tmux is not installed")
class ChatProof(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fleet-chat-proof-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        # A socket for each test: a tmux server leaves a moment after it answered its stop, and a new server on the
        # same socket can meet it as it goes (the session of the next test then did not start, one run in ten).
        self.socket = tmux_socket("fleet-chat-proof-test")
        self.addCleanup(subprocess.run, ["tmux", "-S", self.socket, "kill-server"], capture_output=True)
        self.real = fleet.tmux
        self.refuse = ()            # the tmux commands that give no answer in this test (their first word)
        self.hub = Mock(return_value=(200, {}))
        for p in (patch.object(fleet, "tmux", self.tmux),
                  patch.object(fleet, "HOME", os.path.join(self.tmp, ".fleet")),
                  patch.object(fleet, "SESSIONS", os.path.join(self.tmp, ".fleet", "sessions")),
                  patch.object(fleet, "HUB", "http://127.0.0.1:9"),          # never a real hub
                  patch.object(fleet, "http", self.hub)):
            p.start()
            self.addCleanup(p.stop)
        self.helper = fleet.Helper("studio", WORKER)
        self.said = []
        self.helper.say = self.said.append
        fleet.ensure_session(self.helper.session)

    def tmux(self, *args, **kw):
        """tmux on this test's socket; a command of self.refuse gets no answer in time, as on a server with no
        memory left (fleet.tmux gives exit status 124 then)."""
        if args[0] in self.refuse:
            return subprocess.CompletedProcess(args, 124, "", "timed out")
        return self.real("-S", self.socket, *args, **kw)

    def chat(self, command="sleep 120"):
        """One more window with the owner chat's name, as a start of the chat makes it."""
        fleet.tmux("new-window", "-d", "-t", f"={self.helper.session}:", "-n", "owner-chat", command, check=True)

    def chats(self):
        """The tmux ids of the windows that have the owner chat's name."""
        r = self.real("-S", self.socket, "list-windows", "-t", f"={self.helper.session}:", "-F",
                      "#{window_id} #{window_name}")
        return [line.split()[0] for line in r.stdout.splitlines() if line.split()[1:] == ["owner-chat"]]

    def polls(self, count, message=7, read=False, also=()):
        """So many polls of the hub that give this chat message, unread or read and not yet answered; also: the
        newer chat messages that wait behind it."""
        for _ in range(count):
            self.helper.chat_proof([{"id": message, "kind": "chat", "read": read}, {"id": 3, "kind": "say"}] +
                                   [{"id": i, "kind": "chat", "read": False} for i in also])

    def repaired(self):
        """True when a repair came since the last look: no window with the chat's name is left, and the next start
        is a new conversation. The look ends with a window of that name again, as the chat's new start gives one."""
        gone = self.chats() == [] and self.helper.__dict__.pop("chat_fresh", None) is True
        if gone:
            self.chat()
        return gone

    def test_a_name_that_two_windows_have_is_repaired_by_their_ids_at_the_count(self):
        """12 November 2026: a second owner chat window started beside the first. tmux types into no window whose
        name two windows have and closes none by that name, so the helper wrote "inbox signal gone" at each poll
        for eight hours, and the owner's message of the next morning waited until a person closed one window by its
        id. The count asks for no cause: the message brought no read in so many polls, so every window of the name
        closes, each by its id, and the chat starts a new conversation."""
        self.chat()
        self.chat()
        target = f"={self.helper.session}:=owner-chat"
        self.assertEqual(len(self.chats()), 2)
        self.assertEqual(fleet.type_into(self.helper.session, "owner-chat", "New fleet messages."), "gone")
        self.assertNotEqual(fleet.tmux("kill-window", "-t", target).returncode, 0)     # tmux closes neither by name

        self.polls(POLLS - 1)
        self.assertEqual(len(self.chats()), 2)              # one poll before the count: nothing is touched
        self.assertEqual(self.said, [])
        self.polls(1)
        self.assertEqual(self.chats(), [])
        self.assertIs(self.helper.__dict__.get("chat_fresh"), True)     # the next start is a new conversation
        self.assertIsNone(self.helper.chat_started)                     # and counts as no start that ended
        self.assertIn(f"M-7 is unread after {POLLS} polls", self.said[-1])
        self.hub.assert_not_called()                        # the hub hears nothing: it judges by its own clock

    def test_a_turn_that_does_not_end_is_replaced_at_the_count_like_every_other_cause(self):
        """The count reads no screen. An owner chat answers or opens a task, and its longest turn of three weeks was
        19 seconds, so a turn that still runs after the whole count while a message waits is a tool that hangs, or a
        screen that shows a turn for ever: the helper types nothing into a standing session whose screen shows a
        turn (signal), so without the count that message would wait for as long as the screen says so."""
        self.chat("printf 'working\\n\\n  esc to interrupt\\n'; exec sleep 120")
        target = f"={self.helper.session}:=owner-chat"
        for _ in range(50):
            if self.helper.working(target):
                break
            time.sleep(0.1)
        self.assertTrue(self.helper.working(target))        # its screen shows a turn, and goes on showing it
        self.polls(POLLS - 1)
        self.assertEqual(len(self.chats()), 1)
        self.polls(1)
        self.assertTrue(self.repaired())

    def test_the_read_ends_the_count_and_a_session_that_read_is_never_closed_for_its_reply(self):
        """The read is the proof of the delivery, and it proves the whole way: the window, its input box, the tools
        and the hub. What comes after it is the session's own work, which no count closes: the hub gives an owner's
        message until its reply, marked as read, and the helper counts none of those polls. The hub says by its own
        clock when that reply is late (hub.chat_late). A later message that nobody read has its own count."""
        self.chat()
        self.polls(POLLS - 1)
        self.polls(40 * POLLS, read=True)                   # read, and its reply does not come
        self.assertFalse(self.repaired())
        self.assertEqual((self.helper.chat_wait, self.said), ({}, []))
        self.polls(POLLS - 1, read=True, also=[12])         # a later message behind it
        self.assertFalse(self.repaired())
        self.polls(1, read=True, also=[12])
        self.assertIn(f"M-12 is unread after {POLLS} polls", self.said[-1])
        self.assertTrue(self.repaired())

    def test_a_hub_that_does_not_say_what_was_read_gets_no_count(self):
        """A hub from before this count gives a chat message with no word of its read, also one that was read and
        waits for its reply. Counted as unread, that one would close a chat that works, at each count without an
        end: so only a message that the hub calls unread counts."""
        self.chat()
        for _ in range(3 * POLLS):
            self.helper.chat_proof([{"id": 7, "kind": "chat"}])
        self.assertFalse(self.repaired())
        self.assertEqual(self.helper.chat_wait, {})

    def test_a_message_that_has_its_proof_ends_the_count_and_the_next_one_has_its_own(self):
        self.chat()
        self.polls(POLLS - 1)
        self.helper.chat_proof([{"id": 3, "kind": "say"}])  # the message was read and answered
        self.assertEqual(self.helper.chat_wait, {})
        self.polls(POLLS - 1)                               # the same number again counts from nothing
        self.polls(POLLS - 1, message=9)                    # and so does the message after it
        self.assertFalse(self.repaired())
        self.assertEqual(self.said, [])
        self.polls(1, message=9)
        self.assertTrue(self.repaired())

    def test_the_tries_for_an_unread_message_go_on_at_a_count_that_doubles(self):
        """Until 13 November 2026 a chat window whose line was told twice and not taken got no line again until its
        helper started again (signal). So the helper replaces the chat again while the message has no read, at twice
        the count, at four times, up to 32 times: a cause that ends (a provider that was down, a sign-in that the
        owner made) finds a chat that reads, and a cause that stays costs two starts an hour."""
        self.chat()
        for times in (1, 2, 4, 8, 16, 32, 32, 32):
            self.polls(times * POLLS - 1)
            self.assertFalse(self.repaired(), times)
            self.polls(1)
            self.assertTrue(self.repaired(), times)
        self.hub.assert_not_called()

    def test_a_new_message_is_told_to_the_session_that_stands_there(self):
        """signal types no line into a window whose last line was told twice and not taken, also not for a new
        message, so until 13 November 2026 a chat that left one message unanswered was deaf for every later one until
        its helper started again. A new chat message forgets that line: the session that stands there is told of it
        at this poll, and nothing closes for it, because that session may be one that works."""
        self.chat()
        line = {"wid": "@9", "ids": frozenset({7}), "retold": True, "reported": True}
        self.helper.lines["owner-chat"] = dict(line)
        self.polls(1)                                       # the message is new to this helper
        self.assertNotIn("owner-chat", self.helper.lines)
        self.helper.lines["owner-chat"] = dict(line)
        self.polls(5)
        self.assertIn("owner-chat", self.helper.lines)      # the same message is no new one at the next polls
        self.polls(1, also=[12])
        self.assertNotIn("owner-chat", self.helper.lines)   # a later message is
        self.assertFalse(self.repaired())
        self.polls(POLLS - 8, also=[12])
        self.assertFalse(self.repaired())                   # and the count of the oldest one goes on as it was
        self.polls(1, also=[12])
        self.assertTrue(self.repaired())

    def test_after_a_repair_a_new_message_brings_the_next_one_two_counts_after_the_last_at_the_latest(self):
        """The doubling keeps a cause that stays cheap. The owner's next message must not wait for a replacement
        that is half an hour away: it starts the doubling again."""
        self.chat()
        for times in (1, 2, 4, 8):
            self.polls(times * POLLS)
            self.assertTrue(self.repaired())
        self.polls(3)                                       # the next replacement is 16 counts away
        self.polls(1, also=[12])
        self.assertFalse(self.repaired())                   # nothing closes at the new message itself
        self.polls(2 * POLLS - 5, also=[12])
        self.assertFalse(self.repaired())
        self.polls(1, also=[12])
        self.assertTrue(self.repaired())                    # two counts after the last replacement, not sixteen
        self.polls(4 * POLLS - 1, also=[12])                # and the doubling goes on from there
        self.assertFalse(self.repaired())
        self.polls(1, also=[12])
        self.assertTrue(self.repaired())

    def test_only_a_repair_that_tmux_carried_out_is_one(self):
        """12 November 2026 began with a tmux that gave no answer on a server with no memory left. A repair that
        reads no window list, or closes no window, is none: it is tried again at each poll, and the count to the
        next one starts when tmux carried it out."""
        self.chat()
        self.refuse = ("list-windows",)
        self.polls(POLLS + 5)
        self.refuse = ("kill-window",)
        self.polls(5)
        self.assertEqual((self.helper.chat_wait["stage"], self.said, len(self.chats())), (0, [], 1))
        self.assertNotIn("chat_fresh", self.helper.__dict__)
        self.refuse = ()
        self.polls(1)
        self.assertIn(f"M-7 is unread after {POLLS + 11} polls", self.said[-1])
        self.assertTrue(self.repaired())
        self.polls(2 * POLLS - 1)
        self.assertFalse(self.repaired())
        self.polls(1)
        self.assertTrue(self.repaired())

    def test_the_start_after_the_repair_is_a_new_conversation_also_after_a_start_that_failed(self):
        """The repair must not need anything of the session that it replaces, so the chat does not continue that
        session's conversation: it starts a new one, as a chat whose cache is cold does, with the hub's recap. A
        start that fails (no credential from a hub that restarts, a Fleet update that runs) keeps that: until 13
        November 2026 the start after a failed one continued the old conversation."""
        self.chat()
        self.polls(POLLS)
        self.helper.chat_resume = Mock(return_value="the-old-conversation")
        with patch.object(fleet, "session_credential", side_effect=fleet.Refused("the hub gave no credential")):
            with self.assertRaises(fleet.Refused):
                self.helper.start_chat("g1")
        with patch.object(fleet, "session_credential", return_value="token"), \
                patch.object(fleet, "hub_opening", return_value={}), \
                patch.object(fleet, "chat_recap", return_value="The hub's record of this chat."), \
                patch.object(fleet, "session_env", return_value={}), \
                patch.object(fleet, "save_chat_record"), \
                patch.object(fleet, "chat_command", return_value="sleep 120") as command:
            self.helper.start_chat("g1")
        self.helper.chat_resume.assert_not_called()
        self.assertIsNone(command.call_args.kwargs["resume"])
        self.assertEqual(command.call_args.kwargs["recap"], "The hub's record of this chat.")
        self.assertEqual(len(self.chats()), 1)
        self.assertNotIn("chat_fresh", self.helper.__dict__)     # the start worked: the one after it continues it

    def test_a_standing_window_whose_screen_never_reads_idle_gets_its_first_line_all_the_same(self):
        """5 November 2026: a new version of Claude Code drew its empty input line in another way, the helper read no
        idle screen any more, and the first line of every new session waited for one without an end. The owner chat
        and the manager's session take their first line SIGNAL_GAP seconds after their start at the latest, as a
        runtime whose screen the helper cannot read does; a task window keeps its rule."""
        self.helper.start("owner-chat", "cat", 1, "g1")     # a session that shows no input line that the helper knows
        self.helper.start("T-5", "cat", 1, "g1", "s-5", needs="none")
        target = f"={self.helper.session}:=owner-chat"

        def screen():
            return fleet.tmux("capture-pane", "-p", "-t", target).stdout

        self.helper.signal("owner-chat", [7])
        self.assertNotIn("New fleet messages", screen())    # a new window: its line waits for its screen
        for window in ("owner-chat", "T-5"):                # their start is longer ago than SIGNAL_GAP now
            self.helper.signalled[window] = time.monotonic() - fleet.SIGNAL_GAP - 1
        self.assertFalse(self.helper.first_line_due("T-5"))
        self.helper.signal("owner-chat", [7])
        self.assertIn(fleet.CHAT_SIGNAL, screen())
        self.assertIn("owner-chat: inbox signal typed", self.said[-1])


if __name__ == "__main__":
    unittest.main()

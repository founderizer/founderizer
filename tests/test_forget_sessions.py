"""A removed person's session files leave the agent's machine (the lane "What a removal still keeps", step 2; the
owner's "Yes, as recommended" of 19 November 2026): the helper's event `forget` closes the person's windows, then
deletes only the runtime's own files of their sessions, and every other file stays. Claude Code's, Codex's and the
helper's folders are in a temporary folder, and tmux and the hub are stand-ins: no window, runtime or hub runs."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import fleet
from leftovers import scratch_home

CLAUDE = {"role": "worker", "runtime": "claude", "machine": "box", "can": ["shell"],
          "start": "claude --permission-mode dontAsk {chrome} {settings} {prompt}"}


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def new_ids(n):
    return [str(uuid.uuid4()) for _ in range(n)]


class Forget(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="fleet-forget-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.claude, self.codex, self.home = self.root / "claude", self.root / "codex", self.root / "fleet"
        self.chats = self.root / "fleet-chats"
        for p in (patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.claude), "CODEX_HOME": str(self.codex)}),
                  patch.object(fleet, "HOME", str(self.home)), patch.object(fleet, "CHATS", str(self.chats)),
                  patch.object(fleet, "SESSIONS", str(self.home / "sessions")),
                  patch.object(fleet, "CLAUDE_TMP", str(self.root / "tmp")),
                  patch.object(fleet, "tmux", self.tmux), patch.object(fleet, "http", self.http)):
            p.start()
            self.addCleanup(p.stop)
        self.helper = fleet.Helper("alpha", CLAUDE)
        self.notes, self.killed, self.asked, self.open, self.running = [], [], [], [], {}
        self.helper.say = self.notes.append
        self.helper.look = lambda: list(self.open)
        self.helper.task_windows = lambda: [(w, "g1", 1, s, None, "none") for w, s in self.running.items()
                                            if w in self.open]

    def tmux(self, *args, **kw):
        if args[0] == "kill-window":
            self.killed.append(args[-1].rsplit(":=", 1)[1])
            self.open = [w for w in self.open if w != self.killed[-1]]
        return subprocess.CompletedProcess(args, 0, "", "")

    def http(self, method, path, data=None, timeout=40):
        self.asked.append((method, path, data))
        return 200, {"ok": True}

    def file(self, path, text="words of the person\n", age=0):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        if age:
            os.utime(path, (time.time() - age, time.time() - age))
        return path

    def rollout(self, thread, first, prompt="", age=0):
        return self.file(self.codex / "sessions" / "2026" / "11" / "16" / f"rollout-2026-11-16T10-00-00-{thread}.jsonl",
                         json.dumps({"type": "session_meta", "payload": dict(first, id=thread)}) + "\n" +
                         json.dumps({"type": "response_item", "payload": {"type": "message", "role": "user",
                                     "content": [{"type": "input_text", "text": prompt}]}}) + "\n", age=age)

    def test_their_windows_end_first_then_only_their_sessions_files_go_until_none_is_left(self):
        """What goes: their task session's files (Claude's, a screen runner's), a session that their task window ran
        before its records reached the hub, a Codex session of three days ago with its subagents and a fork, their
        closed conversation's transcripts, and the helper's own files of their windows. Their conversation window
        closes at once, and the files wait for their task windows' stops. The first pass that finds nothing more ends
        the event, so a late line of a closed program goes too. What stays: other sessions' files, a transcript of
        their conversation's number from before it began (an older database's), other windows' and agents' files,
        each file behind a symbolic link, and the project to which a link at another conversation's folder points."""
        theirs, unsent, codex, other, owner_chat, closed, early = new_ids(7)
        checkout = self.root / "fleet-alpha"
        checkout.mkdir()
        (self.chats / "7").mkdir(parents=True)
        (self.chats / "8").symlink_to(checkout)
        project = self.claude / "projects" / re.sub(r"[^A-Za-z0-9-]", "-", os.path.realpath(checkout))
        chat = self.claude / "projects" / re.sub(r"[^A-Za-z0-9-]", "-", os.path.realpath(self.chats / "7"))
        since = time.time() - 3600
        gone = [self.file(project / f"{theirs}.jsonl"), self.file(project / theirs / "subagents" / "agent-a1.jsonl"),
                self.file(project / theirs / "tool-results" / "r1.txt"),
                self.file(self.claude / "projects" / "-home-alpha-other" / f"{theirs}.jsonl"),
                self.file(self.claude / "file-history" / theirs / "0507a50b3cad4720@v2"),
                self.file(self.claude / "tasks" / theirs / "1.json"), self.file(self.home / f"screen-{theirs}.jsonl"),
                self.file(self.root / "tmp" / project.name / theirs / "tasks" / "b1.output"),
                self.file(project / f"{unsent}.jsonl"), self.file(self.claude / "session-env" / unsent / "hook.sh"),
                self.file(chat / f"{closed}.jsonl"),
                self.file(chat / f"{early}.jsonl", age=3600 + fleet.FORGET_SKEW / 2),
                self.file(self.home / "sessions" / "alpha.C-7.0123456789abcdef.md"),
                self.file(self.home / "sessions" / "alpha.T-40.0123456789abcdef.json")]
        root, kid, grandkid, fork, stranger = new_ids(5)
        gone += [self.rollout(root, {"session_id": root}, f"Answer. [fleet-session {codex}]", age=3 * 86400),
                 self.rollout(kid, {"session_id": root, "parent_thread_id": root, "forked_from_id": root,
                                    "source": {"subagent": {"thread_spawn": {"parent_thread_id": root}}}}),
                 self.rollout(grandkid, {"source": {"subagent": {"thread_spawn": {"parent_thread_id": kid}}}}),
                 self.rollout(fork, {"session_id": fork, "forked_from_id": root})]
        outside = self.root / "outside"
        stays = [self.file(project / f"{other}.jsonl"), self.file(self.claude / "file-history" / other / "x@v2"),
                 self.file(self.root / "tmp" / project.name / other / "scratchpad" / "notes.md"),
                 self.file(project / f"{owner_chat}.jsonl"),
                 self.file(chat / f"{owner_chat}.jsonl", age=3600 + 2 * fleet.FORGET_SKEW),
                 self.file(self.home / "sessions" / "alpha.T-400.0123456789abcdef.md"),
                 self.file(self.home / "sessions" / "alpha.owner-chat.0123456789abcdef.md"),
                 self.file(self.home / "sessions" / "beta.T-40.0123456789abcdef.md"),
                 self.rollout(stranger, {"session_id": stranger}, f"Other work. [fleet-session {other}]"),
                 self.file(outside / "projects" / f"{theirs}.jsonl"), self.file(outside / "env" / "keep.txt")]
        (self.claude / "projects" / "linked").symlink_to(outside / "projects")
        (self.claude / "session-env" / theirs).symlink_to(outside / "env")
        (project / theirs / "pasted.txt").symlink_to(outside / "env" / "keep.txt")
        self.open = ["owner-chat", "C-7", "T-40", "T-41", "T-400", "T-99"]
        self.running = {"T-40": unsent, "T-41": other, "T-99": theirs}
        event = {"id": 9, "kind": "forget", "extra": {"conversations": [[7, since], [8, since]], "tasks": [40],
                                                      "sessions": [theirs, codex]}}
        with self.assertRaises(fleet.Refused):          # their conversation window closes, and their task windows wait
            self.helper.handle(event)
        self.assertEqual(self.killed, ["C-7"])
        self.open.remove("T-40")                        # its stop closed it
        with self.assertRaises(fleet.Refused):          # T-99 runs one of their sessions
            self.helper.handle(event)
        self.assertEqual([p for p in gone if not p.exists()], [])
        self.open.remove("T-99")
        with self.assertRaises(fleet.Refused):          # the files go, and the next poll looks once more
            self.helper.handle(event)
        self.assertEqual([p for p in gone if os.path.lexists(p)], [])
        late = self.file(project / f"{unsent}.jsonl")   # the last line of a program that its window's close ended
        with self.assertRaises(fleet.Refused):
            self.helper.handle(event)
        self.assertFalse(late.exists())
        self.assertEqual(self.asked, [])
        self.helper.handle(event)                       # nothing more is left: the ack
        self.assertEqual(self.asked, [("POST", "/helper/ack/alpha", {"ids": [9]})])
        self.assertEqual([p for p in stays if not p.exists()], [])
        self.assertFalse((project / theirs).exists())
        self.assertFalse((self.chats / "7").exists())               # its empty working folder goes too
        self.assertTrue(chat.is_dir())                              # its project keeps the older transcript
        self.assertTrue((self.claude / "session-env" / theirs).is_symlink())
        self.assertTrue((self.chats / "8").is_symlink())
        self.assertEqual(self.killed, ["C-7"])
        self.assertFalse(any(theirs in note or "/" in note for note in self.notes), self.notes)

    def test_an_event_with_an_id_that_is_no_uuid_deletes_nothing_and_is_acked(self):
        """A session id is a part of each path that goes, so one that is not a UUID makes the event no event of the
        contract (".." would name the folder of all transcripts): nothing is closed or deleted, and it is acked."""
        session = new_ids(1)[0]
        kept = self.file(self.claude / "projects" / "-home-alpha-fleet-alpha" / f"{session}.jsonl")
        self.open, self.running = ["T-40"], {"T-40": session}
        self.helper.handle({"id": 3, "kind": "forget", "extra": {"tasks": [40], "sessions": [session, ".."]}})
        self.assertTrue(kept.exists())
        self.assertEqual(self.killed, [])
        self.assertEqual(self.asked, [("POST", "/helper/ack/alpha", {"ids": [3]})])


if __name__ == "__main__":
    unittest.main()

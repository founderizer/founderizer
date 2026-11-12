"""The standing manager session across a runtime switch (owner feature runtime_switch), helper side: each runtime keeps
and continues its own recorded conversation (Codex by the marker at the end of its first prompt, with its Fleet tools
approved in its own command); the previous runtime's session closes only when it is quiet and its conversation stays,
under the start lock until every process of it has ended; and the helper's status tells the hub when the new session
runs. Temporary folders and stand-in tmux, process and hub answers: no AI call, no real runtime, no real session."""
import contextlib
import io
import json
import os
import re
import subprocess
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import fleet
import lifecycle
from threads import Tailer

CLAUDE = {"role": "manager", "runtime": "claude", "machine": "hub", "can": ["shell", "web"],
          "start": "claude --permission-mode bypassPermissions --tools default {settings} {prompt}"}
CODEX = dict(CLAUDE, runtime="codex", start="codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}")
TOKEN = "standing-credential-" + "s" * 24
PROMPT = fleet.MANAGER_START.format(agent="manager", resume=fleet.MANAGER_COLD)
CLAUDE_SESSION = "11111111-2222-4333-8444-555555555555"
MARKER = "22222222-3333-4444-8555-666666666666"
THREAD = "019a0000-1111-7222-8333-444444444444"
APPROVE = 'mcp_servers.fleet.default_tools_approval_mode="approve"'
OLD_CLAUDE = f"env FLEET_ATTEMPT=1 FLEET_TASK= claude --resume {CLAUDE_SESSION} --permission-mode bypassPermissions"
OLD_CODEX = ". /s/manager.env && rm -f /s/manager.env && exec env FLEET_TASK= codex --no-daemon --sandbox danger-full-access"
REAL_ENSURE_SESSION = fleet.ensure_session
GUIDANCE = "Owner-chat guidance: answer greetings and casual questions naturally with tell_owner.\n\n"
CLAUDE_LIMIT = {"type": "assistant", "isApiErrorMessage": True, "error": "rate_limit", "sessionId": CLAUDE_SESSION,
                "message": {"model": "<synthetic>", "stop_reason": "stop_sequence",
                            "content": [{"type": "text", "text": "You've hit your session limit"}]}}
CODEX_END = {"type": "event_msg", "payload": {"type": "task_complete", "turn_id": "t1", "last_agent_message": "Done."}}
CODEX_LIMIT_END = {"type": "event_msg", "payload": {"type": "task_complete", "turn_id": "t2", "last_agent_message": None,
                                                    "error": {"message": "You've hit your usage limit.",
                                                              "codex_error_info": "usage_limit_exceeded"}}}


def read_answer(*ids, body=None):
    """The hub's answer to the manager's read_messages with these messages (hub t_read_messages)."""
    return "Unread messages: " + ", ".join(f"M-{i}" for i in ids) + ".\n\n" + GUIDANCE + "\n\n".join(
        f"Message M-{i}:\n" + (body or f"[owner] Message {i}.") for i in ids)


def claude_read(call, *ids):
    """A Claude read_messages call and its result."""
    return [{"type": "assistant", "sessionId": CLAUDE_SESSION, "message": {"model": "claude-x", "stop_reason": "tool_use",
             "content": [{"type": "tool_use", "id": call, "name": "mcp__fleet__read_messages", "input": {}}]}},
            {"type": "user", "sessionId": CLAUDE_SESSION, "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": call, "content": [{"type": "text", "text": read_answer(*ids)}]}]}}]


def claude_end(text="Done.", sidechain=False):
    return {"type": "assistant", "sessionId": CLAUDE_SESSION, "isSidechain": sidechain,
            "message": {"model": "claude-x", "stop_reason": "end_turn", "content": [{"type": "text", "text": text}]}}


def codex_read(call, *ids, older=False):
    """A Codex read_messages call and its result: as the item that newer rollouts keep, or as an older function call."""
    if older:
        return [{"type": "response_item", "payload": {"type": "function_call", "name": "mcp__fleet__read_messages",
                                                      "call_id": call, "arguments": "{}"}},
                {"type": "response_item", "payload": {"type": "function_call_output", "call_id": call, "output": json.dumps(
                    {"content": [{"type": "text", "text": read_answer(*ids)}]})}}]
    return [{"type": "event_msg", "payload": {"type": "item_completed", "item": {
        "type": "McpToolCall", "id": call, "server": "fleet", "tool": "read_messages", "arguments": {},
        "status": "completed", "result": {"content": [{"type": "text", "text": read_answer(*ids)}], "isError": False}}}}]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-manager-runtime-"))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.tmp)])
        for p in (patch.object(fleet, "HOME", str(self.tmp / ".fleet")),
                  patch.object(fleet, "SESSIONS", str(self.tmp / ".fleet" / "sessions")),
                  patch.object(fleet, "HUB", "http://127.0.0.1:9"),       # never a real hub: no request leaves
                  patch.object(fleet, "http", return_value=(200, {})),     # a test that needs an answer sets its own
                  patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.tmp / ".claude"),
                                          "CODEX_HOME": str(self.tmp / ".codex")}),
                  patch.object(fleet, "mcp_config_file", return_value="/sessions/manager.json"),
                  # team.json of this checkout gives the helper's own runtime: its update is loaded
                  patch.object(fleet, "team_runtime", return_value=None),
                  # the hub gives no resume brief here, so a cold start's prompt is what it always was
                  patch.object(fleet, "manager_resume", return_value=fleet.MANAGER_COLD),
                  patch.object(fleet, "ensure_session"),        # never a real tmux session
                  # never this machine's own processes: the stand-in table, also for a Helper's start (load_seen)
                  patch.object(fleet, "process_table", side_effect=lambda *a: list(getattr(self, "table", [])))):
            p.start()
            self.addCleanup(p.stop)

    def record(self, runtime):
        return Path(fleet.chat_record_file("manager", runtime, "manager"))

    def save(self, runtime, **record):
        fleet.save_chat_record("manager", dict({"generation": "g1", "started": 1.0}, **record), runtime, "manager")
        return self.record(runtime).read_bytes()

    def claude_conversation(self, session=CLAUDE_SESSION):
        """A stand-in conversation file where Claude Code keeps this checkout's sessions."""
        folder = self.tmp / ".claude" / "projects" / re.sub(r"[^A-Za-z0-9-]", "-", os.path.realpath(fleet.KIT))
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"{session}.jsonl").write_text("{}\n")
        return folder / f"{session}.jsonl"

    def codex_rollout(self, marker=MARKER, rows=()):
        """A stand-in Codex rollout of this checkout whose first prompt ends with the marker."""
        folder = self.tmp / ".codex" / "sessions" / "2026" / "10" / "13"
        folder.mkdir(parents=True, exist_ok=True)
        head = [{"type": "session_meta", "payload": {"id": THREAD, "cwd": os.path.realpath(fleet.KIT)}},
                {"type": "response_item", "payload": {"type": "message", "role": "user", "content": [
                    {"type": "input_text", "text": PROMPT + "\n\n" + fleet.MARKER.format(marker)}]}}]
        path = folder / f"rollout-2026-10-13T06-00-00-{THREAD}.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in [*head, *rows]))
        return path


class Records(Base):
    def words(self, conf, generation="g1"):
        command, session, record, note = fleet.manager_start("manager", conf, generation, TOKEN)
        return fleet.launch_words(command), session, record, note

    def test_a_codex_manager_continues_its_thread_with_the_options_of_a_new_start(self):
        new, marker, record, _ = self.words(CODEX)
        self.assertIn(APPROVE, new)                                     # its Fleet tools need no machine configuration
        self.assertEqual(new[-1], PROMPT + "\n\n" + fleet.MARKER.format(marker))
        self.assertEqual((record["marker"], record["session"]), (marker, None))
        fleet.save_chat_record("manager", record, "codex", "manager")
        self.codex_rollout(marker=marker)
        again, window, found, note = self.words(CODEX)
        self.assertEqual((again[:2], again[-1], window, note),
                         (["codex", "resume"], THREAD, marker, "it continues its recorded conversation"))
        self.assertEqual(again[2:-1], new[1:-1])                        # every option of a new start, and no prompt
        self.assertEqual(found, dict(record, session=THREAD))           # saved when its window runs
        saved = self.save("codex", marker=marker, session=THREAD)
        third, window, kept, _ = self.words(CODEX)
        self.assertEqual((third[-1], window, kept), (THREAD, marker, None))
        self.assertEqual(self.record("codex").read_bytes(), saved)

    def test_a_standing_codex_session_gets_its_fleet_route_also_without_a_credential(self):
        for token in (TOKEN, None):
            with self.subTest(credential=bool(token)):
                words = fleet.launch_words(fleet.manager_start("manager", CODEX, "g1", token)[0])
                self.assertIn('mcp_servers.fleet.url="http://127.0.0.1:9/mcp/manager"', words)
                self.assertIn(APPROVE, words)
                self.assertEqual('mcp_servers.fleet.bearer_token_env_var="FLEET_SESSION_TOKEN"' in words, bool(token))
        claude = fleet.launch_words(fleet.manager_start("manager", CLAUDE, "g1", None)[0])
        self.assertNotIn("--mcp-config", claude)                        # Claude without a key: as before

    def test_a_codex_record_that_is_not_valid_or_not_found_stops_the_start_and_stays(self):
        for record, why in (({"marker": "../x", "session": None}, "is not valid"),
                            ({"session": THREAD}, "is not valid"),
                            ({"marker": MARKER, "session": "../x"}, "is not valid"),
                            ({"marker": MARKER, "session": THREAD}, "is not found")):
            with self.subTest(record=record):
                saved = self.save("codex", **record)
                with self.assertRaises(fleet.Refused) as refused:
                    self.words(CODEX)
                self.assertIn(why, str(refused.exception))
                self.assertEqual(self.record("codex").read_bytes(), saved)

    def test_a_codex_start_that_never_began_its_conversation_is_replaced_by_a_new_one(self):
        self.save("codex", marker=MARKER, session=None)                  # no rollout carries its marker
        words, marker, record, note = self.words(CODEX)
        self.assertEqual((note, record["session"]), ("a new conversation: the recorded start never began one", None))
        self.assertNotEqual(marker, MARKER)
        self.assertEqual(words[-1], PROMPT + "\n\n" + fleet.MARKER.format(marker))
        self.assertNotIn("resume", words)


    def test_a_claude_start_that_continues_its_conversation_marks_its_record_as_begun(self):
        self.save("claude", session=CLAUDE_SESSION, begun=False)        # its helper did not mark it yet
        self.claude_conversation()
        words, window, record, note = self.words(CLAUDE)
        self.assertEqual((words[words.index("--resume") + 1], window, note),
                         (CLAUDE_SESSION, CLAUDE_SESSION, "it continues its recorded conversation"))
        self.assertEqual(record, {"generation": "g1", "started": 1.0, "session": CLAUDE_SESSION, "begun": True})
        fleet.save_chat_record("manager", record, "claude", "manager")
        self.assertIsNone(self.words(CLAUDE)[2])                        # marked: the saved one stays

    def test_a_subagent_s_rollout_is_never_taken_for_the_manager_s_own_conversation(self):
        """A Codex subagent's rollout starts with a copy of its parent's history, also the first prompt with the
        marker. Whatever order the files are listed in, the marker names only the manager's own thread."""
        self.save("codex", marker=MARKER, session=None)
        own = self.codex_rollout()
        fork = own.with_name("rollout-2026-10-13T06-05-00-019a0000-9999-7222-8333-444444444444.jsonl")
        rows = own.read_text().splitlines()
        fork_meta = {"type": "session_meta", "payload": {"id": "019a0000-9999-7222-8333-444444444444",
                                                         "cwd": os.path.realpath(fleet.KIT), "forked_from_id": THREAD,
                                                         "source": {"subagent": {"thread_spawn": {"depth": 1}}}}}
        fork.write_text(json.dumps(fork_meta) + "\n" + "\n".join(rows) + "\n")
        real_glob = fleet.glob.glob
        for first in (fork, own):
            with self.subTest(listed_first=first.name), patch("glob.glob", side_effect=lambda pattern: sorted(
                    real_glob(pattern), key=lambda p: p != str(first))):
                fleet.MANAGER_THREADS.clear()
                words, window, record, _ = self.words(CODEX)
                self.assertEqual((words[:2], words[-1], window, record["session"]), (["codex", "resume"], THREAD, MARKER,
                                                                                      THREAD))
                self.assertEqual(fleet.manager_binding("manager", "codex", MARKER), str(own))

    def test_each_runtime_continues_its_own_conversation_and_writes_only_its_own_record(self):
        self.save("claude", session=CLAUDE_SESSION)
        self.save("codex", marker=MARKER, session=THREAD)
        self.claude_conversation()
        self.codex_rollout()
        claude, window, record, _ = self.words(CLAUDE)
        self.assertEqual((claude[claude.index("--resume") + 1], window, record), (CLAUDE_SESSION, CLAUDE_SESSION, None))
        codex, window, record, _ = self.words(CODEX)
        self.assertEqual((codex[:2], codex[-1], window, record), (["codex", "resume"], THREAD, MARKER, None))
        for conf, other in ((CLAUDE, "codex"), (CODEX, "claude")):     # a start of another hub database
            before = self.record(other).read_bytes()
            helper = fleet.Helper("manager", conf)
            with patch.object(fleet, "windows", return_value=[]), patch.object(fleet, "manager_generation", return_value="g2"), \
                    patch.object(fleet, "manager_credential", return_value=TOKEN), patch.object(helper, "start"), \
                    patch.object(helper, "say"):
                self.assertFalse(helper.start_manager())
            self.assertEqual(self.record(other).read_bytes(), before)
            self.assertEqual(json.loads(self.record(conf["runtime"]).read_text())["generation"], "g2")


    def test_a_start_during_a_fleet_update_waits_and_keeps_the_helper_running(self):
        helper = fleet.Helper("manager", CODEX)
        helper.lifecycle = Mock()
        helper.lifecycle.tools_changed = False
        helper.lifecycle.session_start.side_effect = lifecycle.Updating()      # the update holds its gate now
        with patch.object(fleet, "windows", return_value=[]), patch.object(fleet, "manager_generation", return_value="g1"), \
                patch.object(fleet, "manager_credential", return_value=TOKEN), \
                patch.object(fleet, "start_window") as started, patch.object(helper, "say"):
            self.assertTrue(helper.start_manager())                     # still due: no exception ends the helper
        started.assert_not_called()
        self.assertIsNone(json.loads(self.record("codex").read_text())["session"])     # a start that never began
        fleet.hold_manager_lock("manager").close()                      # and the start lock is free again


    def test_no_manager_window_runs_without_its_record_and_its_session_id(self):
        """Both starts save the record before the window starts, and tmux sets the window's session id in the same
        command as its start: a stop between the steps leaves no window that its record does not name."""
        for conf, runtime in ((CLAUDE, "claude"), (CODEX, "codex")):
            with self.subTest(runtime=runtime):
                for p in Path(fleet.HOME).glob("manager-manager.*.json"):
                    p.unlink()
                helper, calls = fleet.Helper("manager", conf), []

                def run(*args, **kw):
                    calls.append((args, kw, self.record(runtime).exists()))
                    return subprocess.CompletedProcess(args, 0, "", "")
                with patch.object(fleet, "windows", return_value=[]), patch.object(fleet, "manager_generation", return_value="g1"), \
                        patch.object(fleet, "manager_credential", return_value=TOKEN), patch.object(fleet, "tmux", side_effect=run), \
                        patch.object(helper, "say"):
                    self.assertFalse(helper.start_manager())
                start = next(c for c in calls if c[0][0] == "new-window")
                record = json.loads(self.record(runtime).read_text())
                session = record["marker" if runtime == "codex" else "session"]
                self.assertTrue(start[2])                               # the record was there first
                self.assertEqual(start[0][-7:], (";", "set-option", "-w", "-t", "=fleet-manager:=manager",
                                                 "@fleet_session", session))
                self.assertEqual(start[1], {"check": True})
                self.assertEqual([c for c in calls if "@fleet_session" in c[0] and c is not start], [])

    def test_a_manager_window_start_that_tmux_does_not_confirm_is_read_again(self):
        """It can have started or not: the manager's start reads which (start_manager, cmd_start). A task or chat
        window goes on as before."""
        timeout = subprocess.TimeoutExpired(["tmux"], 15)
        with patch.object(fleet.subprocess, "run", side_effect=timeout):
            self.assertEqual(fleet.tmux("new-window", "-d", check=True).returncode, 124)     # as before
            fleet.start_window("fleet-vps", "T-5", "codex")
            with self.assertRaises(subprocess.CalledProcessError) as failed:
                fleet.start_window("fleet-manager", "manager", "codex", {"@fleet_session": MARKER})
        self.assertEqual(failed.exception.returncode, 124)

    def test_a_task_window_that_tmux_starts_late_is_kept_and_a_stop_still_ends_what_it_saw(self):
        """A late answer of tmux does not make its event start a second session, which would kill the first one's
        window and repeat its work; and a Stop whose close was late still ends the processes that it saw."""
        worker, calls = fleet.Helper("vps", dict(CODEX, role="worker")), []

        def run(argv, **kw):
            calls.append(argv[1])
            if argv[1] in ("new-window", "kill-window"):
                raise subprocess.TimeoutExpired(argv, 15)
            return subprocess.CompletedProcess(argv, 0, "", "")
        before = {4242: "codex"}
        with patch.object(fleet.subprocess, "run", side_effect=run), patch.object(worker, "sync_checkout"), \
                patch.object(worker, "look", return_value=["T-5"]), patch.object(worker, "task_work", return_value=before), \
                patch.object(worker, "quiesce", return_value=(True, 0, "")) as quiesce, patch.object(worker, "say"):
            worker.start("T-5", "codex", 1, "g1", CLAUDE_SESSION, needs="none")
            self.assertEqual(calls.count("set-option"), 5)              # its own options, as before
            worker.handle({"id": 7, "kind": "stop", "task": "T-5", "extra": {"needs": "browser", "generation": "g1"}})
        self.assertEqual(quiesce.call_args.kwargs["also"], before)

    def test_fleet_py_start_saves_the_record_first_and_stops_with_words_when_tmux_fails(self):
        failed = subprocess.CalledProcessError(124, ["tmux", "new-window"], "", "timed out")
        with patch.object(fleet, "windows", return_value=[]), patch.object(fleet, "manager_generation", return_value="g1"), \
                patch.object(fleet, "manager_credential", return_value=TOKEN), patch.object(fleet, "agent_conf", return_value=CODEX), \
                patch.object(fleet, "claim_checkout"), patch.object(fleet, "start_window", side_effect=failed) as started, \
                contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
            fleet.cmd_start(types.SimpleNamespace(agent="manager"))
        marker = json.loads(self.record("codex").read_text())["marker"]
        self.assertEqual(started.call_args.args[3], {"@fleet_session": marker})
        self.assertIn("tmux did not start the manager window (timed out)", err.getvalue())
        fleet.hold_manager_lock("manager").close()                      # the start lock is free again


class StandIn(Base):
    """Stand-in tmux and process answers for the previous runtime's standing session after a switch."""
    def helper(self, conf, windows, screen):
        h = fleet.Helper("manager", conf)
        h.lifecycle = Mock()
        h.lifecycle.tools_changed = False
        self.addCleanup(lambda: h.manager_lock and h.manager_lock.close())
        self.windows, self.screen, self.killed, self.commands = windows, screen, [], []

        def tmux(*args, check=False, **kw):
            out = ""
            self.commands.append(args[0])
            if args[0] == "list-windows":
                out = "".join(f"{name}\t{session}\t{start}\n".replace("\n", "\\n", start.count("\n"))
                              for name, (session, start) in self.windows.items())      # tmux escapes newlines
            elif args[0] == "capture-pane":
                out = self.screen[0]
            elif args[0] == "kill-window":
                path = Path(fleet.closing_file("manager"))
                self.killed.append(args[-1])
                self.closing_at_kill = json.loads(path.read_text()) if path.exists() else None
                self.windows.pop("manager", None)
            return subprocess.CompletedProcess(args, 0, out, "")
        self.table = getattr(self, "table", [])      # (pid, ppid, args, of_task) of the processes that run now
        for p in (patch.object(fleet, "tmux", side_effect=tmux), patch.object(fleet.time, "sleep"),
                  patch.object(h, "look", side_effect=lambda: [n for n in self.windows if n != "home"]),
                  patch.object(h, "say"), patch.object(fleet, "process_table", side_effect=lambda *a: list(self.table))):
            p.start()
            self.addCleanup(p.stop)
        for target, name, value in ((fleet, "end_processes", []), (h, "task_work", {}), (h, "quiesce", (True, 0, ""))):
            patcher = patch.object(target, name, return_value=value)     # end_processes: never a real signal
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)
        return h

    def lock_held(self):
        try:
            fleet.hold_manager_lock("manager").close()
        except fleet.Refused:
            return True
        return False

    def quiet_twice(self, h):
        h.retire_old_manager()
        if h.manager_retiring:                  # the same quiet reading, RETIRE_QUIET seconds later
            h.manager_retiring = (h.manager_retiring[0] - fleet.RETIRE_QUIET - 1, h.manager_retiring[1])
        return h.retire_old_manager()


class ToolsChanged(StandIn):
    """**A new team tool reaches the standing session only when it starts.** The hub serves the list once and
    announces no change of it, so it tells the helper instead and the helper starts that session again, on the
    same conversation (the owner, 21 October 2026: "how are agents going to get the updates automatically?")."""
    def test_the_session_starts_again_when_its_tool_list_is_no_longer_the_one(self):
        h = self.helper(CLAUDE, {"home": ("", "bash"), "manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        h.lifecycle.tools_changed = False
        h.restart_for_tools()
        self.assertEqual((self.killed, h.manager_due), ([], False), "nothing changed, nothing closes")
        h.lifecycle.tools_changed = True
        h.restart_for_tools()
        self.assertEqual(self.killed, ["=fleet-manager:=manager"])
        self.assertTrue(h.manager_due)                                  # its own watch starts it again
        self.assertFalse(h.lifecycle.tools_changed)                     # and this round does not close it twice
        self.assertIn("team tools changed", h.say.call_args.args[0])

    def test_a_running_turn_keeps_its_session_until_the_next_round(self):
        h = self.helper(CLAUDE, {"home": ("", "bash"), "manager": (CLAUDE_SESSION, OLD_CLAUDE)},
                        ["Working (3s · esc to interrupt)\n"])
        h.lifecycle.tools_changed = True
        h.restart_for_tools()
        self.assertEqual((self.killed, h.manager_due), ([], False), "a turn of its own is never interrupted")
        self.assertTrue(h.lifecycle.tools_changed, "the hub says it again, and the next round acts")
        self.screen[0] = "> \n"
        h.restart_for_tools()
        self.assertEqual(self.killed, ["=fleet-manager:=manager"])

    def test_a_switch_closes_that_session_itself_and_this_stands_back(self):
        h = self.helper(CLAUDE, {"home": ("", "bash"), "manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        h.lifecycle.tools_changed = True
        h.manager_left = {1234: "claude"}               # a switch is still closing the previous session
        h.restart_for_tools()
        self.assertEqual(self.killed, [], "the switch starts it again with the current list anyway")
        h.manager_left, h.manager_due = {}, True        # or a start is already due
        h.restart_for_tools()
        self.assertEqual(self.killed, [])

    def test_a_background_workflow_or_command_keeps_its_session_until_it_ends(self):
        """The second review of 29 October 2026: an async agent, a workflow or a background command of the manager
        writes records of its own while its session's screen is idle, and a close for new tools stopped that run."""
        import threads
        h = self.helper(CLAUDE, {"home": ("", "bash"), "manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        feed = threads.Feed(("manager", "", 0, CLAUDE_SESSION), "claude")
        for row in ({"type": "assistant", "sessionId": CLAUDE_SESSION, "message": {"id": "m-a1", "content": [
                        {"type": "tool_use", "id": "a1", "name": "Agent", "input": {"description": "look"}}]}},
                    {"type": "user", "sessionId": CLAUDE_SESSION, "toolUseResult": {"status": "async_launched",
                                                                                    "agentId": "g1"},
                     "message": {"content": [{"type": "tool_result", "tool_use_id": "a1", "content": "launched"}]}}):
            feed.translator.records(row)
        h.tailer.feeds[("manager", CLAUDE_SESSION)] = feed
        h.lifecycle.tools_changed = True
        h.restart_for_tools()
        self.assertEqual((self.killed, h.manager_due), ([], False))
        self.assertTrue(h.lifecycle.tools_changed, "the hub says it again, and a later round acts")
        feed.translator.records({"type": "user", "sessionId": CLAUDE_SESSION, "message": {"content": [
            {"type": "text", "text": "<task-notification><task-id>g1</task-id><tool-use-id>a1</tool-use-id>"
                                     "<status>completed</status></task-notification>"}]}})
        h.restart_for_tools()
        self.assertEqual(self.killed, ["=fleet-manager:=manager"])

    def test_a_worker_has_no_standing_session_to_turn_over(self):
        h = self.helper(dict(CLAUDE, role="worker"), {"home": ("", "bash")}, ["> \n"])
        h.lifecycle.tools_changed = True
        h.restart_for_tools()
        self.assertEqual(self.killed, [], "its next task window asks for the list itself")


class OwnerContact(StandIn):
    """Owner-contact plan B3 (6 November 2026), the helper's half: it tells the hub when its own start of the standing
    session failed twice in a row, and it starts a session that left its line untaken fresh, once, so that the owner
    hears only of what the fleet cannot put right itself (hub.manager_flag_update)."""
    IDLE, RUNNING = "────\n❯ \n────\n", "✻ Working… (3s · esc to interrupt)\n────\n❯ \n────\n"

    def helper(self, conf=CLAUDE, windows=None, screen=None):
        h = super().helper(conf, {"home": ("", "bash"), "manager": (CLAUDE_SESSION, OLD_CLAUDE)} if windows is None
                           else windows, [self.IDLE] if screen is None else screen)

        def start(name, command, session=""):           # a start whose window runs (Helper.start)
            self.windows[name] = (session, "claude --resume x")
            h.lines.pop(name, None)
        for p in (patch.object(fleet, "manager_generation", return_value="g1"),
                  patch.object(fleet, "manager_credential", return_value=TOKEN),
                  patch.object(fleet, "windows", side_effect=lambda session, checked=False: list(self.windows)),
                  patch.object(fleet, "type_into", return_value="typed"),
                  patch.object(h, "start", side_effect=start),
                  patch.object(h, "restart_fresh", return_value=False),       # the session is not cold
                  patch.object(h, "window_runtime", side_effect=lambda w: "claude" if w in self.windows else None)):
            p.start()
            self.addCleanup(p.stop)
        return h

    def reports(self):
        return [c.args[2] for c in fleet.http.call_args_list if c.args[:2] == ("POST", "/helper/dialog/manager/manager")]

    # ---- case 1: its own start failed
    def test_two_failed_starts_in_a_row_are_told_once_and_a_session_that_came_up_ends_them(self):
        h = self.helper(windows={"home": ("", "bash")})
        with patch.object(fleet, "manager_generation", side_effect=fleet.Refused("the hub gave no generation (503)")):
            self.assertTrue(h.start_manager())
            self.assertEqual(self.reports(), [])                    # one failure is its own to try again
            self.assertTrue(h.start_manager())
            self.assertTrue(h.start_manager())
        failed = {"kind": "start_failed", "reason": "the hub gave no generation (503)"}
        self.assertEqual(self.reports(), [failed])                  # once for the run
        self.assertFalse(h.start_manager())                         # it starts at last
        h.listed = {"manager": 1}                                   # and its session lists its tools: it came up
        h.manage()
        self.assertEqual((h.manager_fails, h.manager_mark), (0, None))
        self.windows.pop("manager")
        with patch.object(h, "start", side_effect=subprocess.CalledProcessError(1, ["tmux"])):
            self.assertTrue(h.start_manager())                      # tmux refused, or its program ended at once
            self.assertTrue(h.start_manager())
        self.assertEqual(self.reports(), [failed, {"kind": "start_failed",
                                                   "reason": "the session did not start or ended at its start"}])

    def test_another_start_that_holds_the_lock_is_no_failure_of_its_own(self):
        h = self.helper(windows={"home": ("", "bash")})
        lock = fleet.hold_manager_lock("manager")                   # `fleet.py start` runs now
        self.addCleanup(lock.close)
        for _ in range(3):
            self.assertTrue(h.start_manager())
        self.assertEqual((h.manager_fails, self.reports()), (0, []))

    def test_a_session_that_ends_before_it_came_up_is_a_failed_start(self):
        """A start that tmux confirms, whose program ends a moment later (a setting it refuses, a conversation it
        cannot read): before 6 November 2026 each such start counted as a success, so a loop of them told nobody."""
        h = self.helper(windows={"home": ("", "bash")})
        h.manager_due = True
        for _ in range(2):
            h.manager_tried = None
            h.manage()                                              # started
            self.assertIn("manager", self.windows)
            self.windows.pop("manager")                             # it ends before it lists its tools or shows its box
            h.manage()
            self.assertTrue(h.manager_due)                          # its helper tries again either way
        self.assertEqual(self.reports(), [{"kind": "start_failed", "reason": "its session ended before it came up"}])

    def test_a_session_that_came_up_and_ended_later_is_no_failed_start(self):
        h = self.helper(windows={"home": ("", "bash")})
        for _ in range(3):
            h.manager_due, h.manager_tried = True, None
            h.manage()
            h.idle_at["manager"] = time.monotonic() + 1             # its screen showed its empty input line
            h.manage()
            self.windows.pop("manager")                             # a crash, later
            h.manage()
        self.assertEqual((h.manager_fails, self.reports()), (0, []))

    # ---- case 2: a line told twice and not taken
    def untaken(self, h, *ids):
        """Its line told, told once more at its next idle point, and at the idle point after that still unread
        (Helper.signal, plan C5)."""
        events = [{"id": i, "kind": "say", "task": None, "text": "[owner] Where do we stand?", "extra": {}} for i in ids]
        for n in range(3):
            if n:
                h.idle_at["manager"] = time.monotonic() + n
            h.handle_events(events)

    def test_an_idle_session_that_leaves_its_line_untaken_starts_fresh_once(self):
        h = self.helper()
        self.untaken(h, 1)
        self.assertEqual(self.killed, ["=fleet-manager:=manager"])  # closed between two turns
        self.assertEqual(self.reports(), [{"kind": "untaken", "fresh": True}])
        self.assertTrue(h.manager_fresh)                            # a new conversation with the hub's brief
        h.manage()
        self.assertIn("manager", self.windows)
        self.untaken(h, 1)                                          # the fresh session leaves it untaken too
        self.assertEqual(self.reports(), [{"kind": "untaken", "fresh": True}, {"kind": "untaken"}])
        self.assertEqual(len(self.killed), 1)                       # the owner hears of it, and nothing is closed
        h.handle_events([])                                         # its messages were read
        self.assertIsNone(h.manager_untaken)
        self.untaken(h, 2)                                          # a later line starts it fresh again
        self.assertEqual(self.reports()[-1], {"kind": "untaken", "fresh": True})
        self.assertEqual(len(self.killed), 2)

    def test_a_session_that_still_moves_is_never_closed_and_its_report_waits(self):
        for why, screen in (("a turn runs", self.RUNNING), ("a question shows", "Do you want to proceed?\n❯ 1. Yes\n"
                                                                                "  2. No\n\nEsc to cancel\n"),
                            ("background work runs", self.IDLE)):
            with self.subTest(why=why):
                fleet.http.reset_mock()
                h = self.helper()
                h.handle_events([{"id": 1, "kind": "say", "task": None, "text": "x", "extra": {}}])
                h.idle_at["manager"] = time.monotonic() + 1
                h.handle_events([{"id": 1, "kind": "say", "task": None, "text": "x", "extra": {}}])
                h.idle_at["manager"] = time.monotonic() + 2
                self.screen[0] = screen
                with patch.object(h, "background_open", return_value=why == "background work runs"):
                    h.handle_events([{"id": 1, "kind": "say", "task": None, "text": "x", "extra": {}}])
                self.assertEqual((self.killed, self.reports()), ([], []))
                self.screen[0] = self.IDLE                          # between two turns at a later poll
                h.handle_events([{"id": 1, "kind": "say", "task": None, "text": "x", "extra": {}}])
                self.assertEqual((self.killed, self.reports()), (["=fleet-manager:=manager"],
                                                                 [{"kind": "untaken", "fresh": True}]))


class Retire(StandIn):
    """The previous runtime's standing session after a switch."""
    def test_the_old_session_closes_only_when_quiet_and_its_conversation_stays(self):
        saved = self.save("claude", session=CLAUDE_SESSION)
        transcript = self.claude_conversation()
        h = self.helper(CODEX, {"home": ("", "bash"), "manager": (CLAUDE_SESSION, OLD_CLAUDE)},
                        ["Working (3s · esc to interrupt)\n"])
        self.assertEqual((h.other_runtime_windows(), h.manager_bound()), (["manager"], False))
        self.assertFalse(self.quiet_twice(h))                           # a running turn goes on
        self.assertTrue(self.lock_held())                               # from the first reading: no start meanwhile
        # (a question on its screen closes with it unanswered: test_an_old_session_at_a_question_closes_...)
        self.screen[0] = "> \n"
        self.assertFalse(h.retire_old_manager())                        # one quiet reading is not enough
        self.assertEqual(self.killed, [])
        self.assertTrue(self.quiet_twice(h))
        self.assertEqual(self.killed, ["=fleet-manager:=manager"])
        self.assertFalse(self.lock_held())
        h.lifecycle.report.assert_called()
        self.assertEqual((h.other_runtime_windows(), h.manager_bound()), ([], None))
        self.assertEqual(self.record("claude").read_bytes(), saved)      # kept for a switch back
        self.assertTrue(transcript.exists())

    def test_processes_that_remain_keep_the_switch_pending_and_the_lock_held(self):
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        self.quiesce.return_value, self.task_work.return_value = (False, 0, "4242 claude"), {4242: "claude"}
        self.assertFalse(self.quiet_twice(h))
        self.assertEqual((self.killed, h.other_runtime_windows()), (["=fleet-manager:=manager"], ["manager"]))
        self.assertTrue(self.lock_held())
        self.table = [(4242, 1, "claude", False), (4343, 1, "another program", False)]
        self.assertFalse(h.retire_old_manager())                        # it still runs: ended again, only it
        self.end_processes.assert_called_with([4242])
        self.assertTrue(self.lock_held())
        self.table = [(4242, 1, "a new program with a reused id", False)]
        self.assertTrue(h.retire_old_manager())                         # now the new runtime's session is due
        self.assertEqual(h.other_runtime_windows(), [])
        self.assertFalse(self.lock_held())

    def test_an_unrecorded_or_unreadable_old_session_stays_open_without_the_lock(self):
        self.claude_conversation()
        for start, why in ((OLD_CLAUDE, "its conversation is not recorded"), ("'unclosed", "its program cannot be read")):
            with self.subTest(why=why):
                h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, start)}, ["> \n"])
                self.assertFalse(self.quiet_twice(h))
                self.assertEqual((self.killed, h.other_runtime_windows()), ([], ["manager"]))
                self.assertFalse(self.lock_held())
                self.assertIn(why, h.say.call_args.args[0])


    def test_the_lock_goes_when_a_later_reading_finds_nothing_to_keep(self):
        """A first reading of a recorded old window takes the start lock. When a later reading finds nothing that its
        close would keep (here the owner removed its record), its window stays open and the lock goes, so that
        `fleet.py start` can go on."""
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        self.assertFalse(h.retire_old_manager())                        # a first quiet reading, with the lock
        self.assertTrue(self.lock_held())
        self.record("claude").unlink()
        self.assertFalse(h.retire_old_manager())
        self.assertFalse(self.lock_held())
        self.assertEqual((self.killed, h.other_runtime_windows()), ([], ["manager"]))
        self.assertIn("its conversation is not recorded or not found", h.say.call_args.args[0])

    def test_a_switch_back_closes_a_new_session_that_never_began_its_conversation(self):
        for runtime, conf, window, start in (("codex", CLAUDE, MARKER, OLD_CODEX),
                                             ("claude", CODEX, CLAUDE_SESSION, OLD_CLAUDE)):
            with self.subTest(runtime=runtime):
                if runtime == "codex":
                    self.save("codex", marker=MARKER, session=None)     # no rollout carries its marker
                else:
                    self.save("claude", session=CLAUDE_SESSION, begun=False) # Claude wrote no conversation file
                h = self.helper(conf, {"manager": (window, start)}, ["error: the model is not available\n"])
                self.assertTrue(self.quiet_twice(h))
                self.assertEqual(self.killed, ["=fleet-manager:=manager"])
                self.assertFalse(self.record(runtime).exists())         # nothing to continue: a later start is new
                self.assertIn("never began a conversation", h.say.call_args.args[0])

    def test_an_old_session_closed_by_hand_during_the_switch_lets_the_new_one_start(self):
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        old = {4242: f"claude --resume {CLAUDE_SESSION}"}
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["Do you want to proceed?\n❯ 1. Yes\n  2. No\n"])
        self.task_work.return_value, self.table = old, [(4242, 1, old[4242], False)]
        self.assertFalse(h.retire_old_manager())                        # a question: it waits, with the lock
        self.assertTrue(self.lock_held())
        self.windows.pop("manager")                                     # the owner closed it to end the question
        self.assertFalse(h.retire_old_manager())                        # its process still runs: still pending
        self.assertEqual((h.other_runtime_windows(), self.killed), (["manager"], []))
        self.table = []
        self.assertTrue(h.retire_old_manager())                         # now the new runtime's session is due
        self.assertFalse(self.lock_held())

    def test_a_never_begun_session_closed_by_hand_leaves_no_record_that_stops_a_later_start(self):
        self.save("claude", session=CLAUDE_SESSION, begun=False)         # Claude wrote no conversation file
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["Trust this folder?\n❯ 1. Yes\n  2. No, exit\n"])
        self.assertFalse(h.retire_old_manager())                        # a question: it waits, with the lock
        self.windows.pop("manager")                                     # the owner answered "No, exit"
        self.assertTrue(h.retire_old_manager())
        self.assertFalse(self.record("claude").exists())
        command, session, record, note = fleet.manager_start("manager", CLAUDE, "g1", TOKEN)
        self.assertNotIn("--resume", fleet.launch_words(command))       # the next Claude start is a new one
        self.save("claude", session=CLAUDE_SESSION, begun=False)         # and a record whose conversation began
        self.claude_conversation()                                      # meanwhile is never removed: it is marked
        self.assertFalse(h.forget_record("claude", CLAUDE_SESSION))
        self.assertIs(json.loads(self.record("claude").read_text())["begun"], True)


    def test_a_conversation_that_began_and_whose_file_is_not_found_keeps_its_record_and_its_window(self):
        """Its file can go while it runs (Claude Code's own cleanup, or moved by hand). Its record is not one of a
        start that never began: no switch is offered (manager_not_bound), the old window is not closed, a close by
        hand keeps the record, and the next start of that runtime stops and says so."""
        for begun in ({"begun": True}, {}):         # marked by its helper, or recorded by an earlier Fleet
            with self.subTest(record=begun):
                saved = self.save("claude", session=CLAUDE_SESSION, **begun)      # its file is not found
                self.assertIsNone(fleet.manager_keeps("manager", "claude", CLAUDE_SESSION))
                own = self.helper(CLAUDE, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
                self.assertIs(own.manager_bound(), False)
                h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
                self.assertFalse(self.quiet_twice(h))
                self.assertEqual((self.killed, h.other_runtime_windows()), ([], ["manager"]))
                self.assertIn("its conversation is not recorded or not found", h.say.call_args.args[0])
                self.assertFalse(h.forget_record("claude", CLAUDE_SESSION))
                self.windows.pop("manager")                             # the owner closes it by hand
                self.assertTrue(h.retire_old_manager())                 # then the new runtime's session starts
                self.assertEqual(self.record("claude").read_bytes(), saved)
                with self.assertRaises(fleet.Refused) as refused:       # and a switch back says so
                    fleet.manager_start("manager", CLAUDE, "g1", TOKEN)
                self.assertIn("is not found", str(refused.exception))

    def test_the_switch_close_marks_the_claude_conversation_that_it_keeps(self):
        """A Claude conversation that began just before the switch, before its helper marked it: the close keeps it
        and marks it, so that a switch back that misses its file stops instead of starting a new conversation."""
        self.save("claude", session=CLAUDE_SESSION, begun=False)
        transcript = self.claude_conversation()
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        self.assertTrue(self.quiet_twice(h))
        self.assertEqual(self.killed, ["=fleet-manager:=manager"])
        self.assertIs(json.loads(self.record("claude").read_text())["begun"], True)
        transcript.unlink()
        with self.assertRaises(fleet.Refused) as refused:
            fleet.manager_start("manager", CLAUDE, "g1", TOKEN)
        self.assertIn("is not found", str(refused.exception))


    def test_a_conversation_that_began_is_noted_also_when_its_window_goes_before_the_lock_is_free(self):
        """A reading found its file, but no note could be written then (the helper's first reading at its start, or a
        start held the lock); its window goes before the next reading, and its file soon after. The record is still
        noted as begun and kept, so that the next start of that runtime stops and says so."""
        for how in ("seen at the start", "lock busy at the reading", "own window, lock busy"):
            with self.subTest(how=how):
                self.save("claude", session=CLAUDE_SESSION, begun=False)
                transcript = self.claude_conversation()
                h = self.helper(CLAUDE if how.startswith("own") else CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)},
                                ["> \n"])
                if how == "seen at the start":
                    self.assertFalse(h.manager_first())
                else:
                    held = fleet.hold_manager_lock("manager")           # `fleet.py start` holds it now
                    self.assertFalse(h.retire_old_manager())
                    held.close()
                self.assertIs(json.loads(self.record("claude").read_text())["begun"], False)
                self.windows.pop("manager")                             # the owner closes it
                transcript.unlink()                                     # and its file goes (cleanup, moved)
                h.retire_old_manager()
                self.assertIs(json.loads(self.record("claude").read_text())["begun"], True)
                self.assertFalse(self.lock_held())
                with self.assertRaises(fleet.Refused) as refused:
                    fleet.manager_start("manager", CLAUDE, "g1", TOKEN)
                self.assertIn("is not found", str(refused.exception))


    def test_every_pending_note_waits_for_the_lock_and_the_window_that_runs_is_read_too(self):
        """A step of an earlier session waits while a start holds the lock; the session that runs now is still read
        at that round, so that its note waits too, also when its window and its file go before the next round."""
        second = "33333333-4444-4555-8666-777777777777"
        self.save("claude", session=CLAUDE_SESSION, begun=False)        # a start that has not begun
        h = self.helper(CLAUDE, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        self.assertFalse(h.retire_old_manager())
        self.save("claude", session=second, begun=False)                # `fleet.py start` replaced it
        transcript = self.claude_conversation(second)                   # and its conversation began at once
        self.windows["manager"] = (second, OLD_CLAUDE)
        held = fleet.hold_manager_lock("manager")                       # a start holds the lock at this round
        self.assertFalse(h.retire_old_manager())
        held.close()
        self.windows.pop("manager")                                     # it goes before the next round
        transcript.unlink()                                             # and so does its file
        self.assertFalse(h.retire_old_manager())
        self.assertIs(json.loads(self.record("claude").read_text())["begun"], True)
        self.assertEqual(h.manager_seen_own, {})
        self.assertFalse(self.lock_held())
        with self.assertRaises(fleet.Refused) as refused:
            fleet.manager_start("manager", CLAUDE, "g1", TOKEN)
        self.assertIn("is not found", str(refused.exception))

    def test_a_replaced_session_s_round_notes_the_conversation_of_the_new_one(self):
        """`fleet.py start` replaced the old window with a session whose conversation began, and a process of the old
        one still runs: the same round notes the new conversation."""
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        self.save("codex", marker=MARKER, session=None)                 # as the new start wrote it
        self.codex_rollout()                                            # its conversation began
        fleet.MANAGER_THREADS.clear()
        old = {4242: f"claude --resume {CLAUDE_SESSION}"}
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["Working (3s · esc to interrupt)\n"])
        self.task_work.return_value, self.table = old, [(4242, 1, old[4242], False)]
        self.assertFalse(h.retire_old_manager())                        # the old session, busy
        self.windows["manager"] = (MARKER, OLD_CODEX)                   # closed by hand; `fleet.py start` started Codex
        self.task_work.return_value = {5151: "codex --no-daemon"}
        self.table = [(4242, 1, old[4242], False), (5151, 1, "codex --no-daemon", False)]
        self.assertFalse(h.retire_old_manager())                        # replaced; 4242 still runs
        self.assertEqual(h.manager_left, old)
        self.assertEqual(json.loads(self.record("codex").read_text())["session"], THREAD)

    def test_a_codex_conversation_that_began_gets_its_thread_in_its_record(self):
        """A Codex record gets its thread at the first reading that finds its rollout, not only at its next start:
        when that rollout goes later (archived, moved), the window is not closed as a start that never began, and
        the next Codex start stops and says so."""
        for helper, how in ((CODEX, "its own helper"), (CLAUDE, "the switch close")):
            with self.subTest(how=how):
                self.save("codex", marker=MARKER, session=None)          # as its start wrote it
                rollout = self.codex_rollout()                          # its conversation began
                fleet.MANAGER_THREADS.clear()
                h = self.helper(helper, {"manager": (MARKER, OLD_CODEX)}, ["Working (3s · esc to interrupt)\n"])
                self.assertFalse(h.retire_old_manager())
                self.assertEqual(json.loads(self.record("codex").read_text())["session"], THREAD)
                if h.manager_lock:
                    h.release_manager(False)
                archived = self.tmp / ".codex" / "archived_sessions"
                archived.mkdir(parents=True, exist_ok=True)
                os.replace(rollout, archived / rollout.name)            # its rollout goes
                fleet.MANAGER_THREADS.clear()
                self.assertIsNone(fleet.manager_keeps("manager", "codex", MARKER))
                switch = self.helper(CLAUDE, {"manager": (MARKER, OLD_CODEX)}, ["> \n"])
                self.assertFalse(self.quiet_twice(switch))              # it stays open
                self.assertEqual(self.killed, [])
                self.assertEqual(json.loads(self.record("codex").read_text())["session"], THREAD)
                with self.assertRaises(fleet.Refused) as refused:
                    fleet.manager_start("manager", CODEX, "g1", TOKEN)
                self.assertIn("is not found", str(refused.exception))
                (archived / rollout.name).unlink()

    def test_a_helper_that_has_not_loaded_the_switch_changes_no_manager_session(self):
        """team.json of the shared checkout already gives Codex; this helper still runs Claude until its update. A
        Codex session that `fleet.py start` started is not closed, and no Claude session starts."""
        self.save("codex", marker=MARKER, session=None)
        h = self.helper(CLAUDE, {"manager": (MARKER, OLD_CODEX)}, ["> \n"])
        with patch.object(fleet, "team_runtime", return_value="codex"), \
                patch.object(fleet, "windows", return_value=["manager"]) as listed:
            for _ in range(3):
                h.manage()
                self.assertFalse(h.manager_due)
            self.windows.pop("manager")
            self.assertTrue(h.start_manager())                          # due, but it waits for the update
        listed.assert_not_called()
        self.assertEqual(self.killed, [])
        self.assertFalse(self.lock_held())
        self.assertIn("waits for its Fleet update to codex", h.say.call_args.args[0])

    def test_a_standing_session_that_goes_by_itself_comes_back_at_the_next_round(self):
        """The window is killed — a crash, a runtime error, an out-of-memory kill, `tmux kill-window` — and nothing
        else is going on. The helper's own loop finds it missing and starts it again (manager_gone). Until
        19 October 2026 nothing watched that window: the hub raised manager_down and only a restart of the helper's
        service by hand brought the manager back."""
        self.save("codex", marker=MARKER, session=THREAD)
        self.codex_rollout()
        h = self.helper(CODEX, {"manager": (MARKER, OLD_CODEX)}, ["> \n"])
        started = patch.object(h, "start_manager", return_value=False).start()
        self.addCleanup(patch.stopall)
        for _ in range(3):
            h.manage()
            self.assertFalse(h.manager_due)
        started.assert_not_called()                                     # its session runs: nothing starts
        self.windows.pop("manager")                                     # and now it is gone
        h.manage()
        started.assert_called_once()
        self.assertFalse(h.manager_due)
        self.assertIn("its session is not running", h.say.call_args.args[0])
        self.assertFalse(self.lock_held())

    def test_the_watch_waits_out_the_ten_second_guard_and_says_it_once(self):
        """A session whose program ends at once must not be started faster than the existing guard of manage, and
        the helper must not fill the owner's log with one line for each round."""
        self.save("codex", marker=MARKER, session=THREAD)
        self.codex_rollout()
        h = self.helper(CODEX, {}, ["> \n"])
        with patch.object(h, "start_manager", return_value=False) as started:
            for _ in range(5):                                          # five rounds inside the ten seconds
                h.manage()
            started.assert_called_once()
            h.manager_tried -= 11                                       # ten seconds later
            h.manage()
            self.assertEqual(started.call_count, 2)
        said = [c.args[0] for c in h.say.call_args_list if "its session is not running" in c.args[0]]
        self.assertEqual(len(said), 1)

    def test_the_watch_says_nothing_while_a_close_or_an_unknown_reading_is_open(self):
        """The rounds that already exist own the start: a switch whose session was seen, the processes of a closed
        session that have not ended, a lock that this helper holds, and a tmux reading that gives no answer."""
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        self.assertFalse(h.retire_old_manager())                        # the previous runtime's session, seen
        self.assertTrue(self.lock_held())
        self.windows.pop("manager")
        for why, state in (("the session was seen", {}),
                           ("its processes still run", {"manager_left": {4242: "claude"}, "manager_seen_old": None}),
                           ("this helper holds the lock", {"manager_left": {}, "manager_seen_old": None})):
            with self.subTest(why=why):
                for field, value in state.items():
                    setattr(h, field, value)
                self.assertFalse(h.manager_gone())
        h.manager_lock.close()
        h.manager_lock = None
        self.assertTrue(h.manager_gone())                               # nothing is open any more
        with patch.object(fleet, "manager_window", side_effect=fleet.Refused("no answer")), \
                patch.object(h, "started", return_value={"manager": OLD_CODEX}):
            self.assertFalse(h.manager_gone())                          # unknown is never "no window"

    def test_a_worker_helper_watches_no_standing_session(self):
        h = self.helper(dict(CODEX, role="worker"), {}, ["> \n"])
        with patch.object(h, "start_manager", return_value=False) as started:
            h.manage()
        started.assert_not_called()
        self.assertFalse(h.manager_due)

    def test_the_owner_s_own_control_makes_the_start_due_at_once(self):
        """Owner feature manager_start: the control that the manager_down warning carries. It only asks, so a
        session that runs is left alone, and it does not wait out the ten-second guard."""
        h = self.helper(CODEX, {}, ["> \n"])
        with patch.object(h, "start_manager", return_value=False) as started:
            h.manage()                                                  # the watch tried once a moment ago
            started.assert_called_once()
            h.handle({"id": 7, "kind": "manager_start", "extra": {}})
            self.assertTrue(h.manager_due)
            self.assertIsNone(h.manager_tried)
            h.manage()
            self.assertEqual(started.call_count, 2)                     # no wait for the guard
        self.assertFalse(h.manager_due)
        worker = self.helper(dict(CODEX, role="worker"), {}, ["> \n"])
        worker.handle({"id": 8, "kind": "manager_start", "extra": {}})
        self.assertFalse(worker.manager_due)                            # no standing session to start

    def test_the_helper_loop_closes_the_old_session_and_then_starts_exactly_one_new_one(self):
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        h = self.helper(CODEX, {"home": ("", "bash"), "manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        windows, starts = self.windows, []

        def start(name, command, **kw):                                 # the new window, as the helper's start makes it
            starts.append(command)
            windows[name] = (kw["session"], command)
        for p in (patch.object(h, "start", side_effect=start), patch.object(fleet, "manager_generation", return_value="g1"),
                  patch.object(fleet, "manager_credential", return_value=TOKEN),
                  patch.object(fleet, "windows", side_effect=lambda session, checked=False: list(windows))):
            p.start()
            self.addCleanup(p.stop)
        h.manage()                                                      # the first reading, after the helper's restart
        self.assertTrue(self.lock_held())
        h.manager_retiring = (h.manager_retiring[0] - fleet.RETIRE_QUIET - 1, h.manager_retiring[1])
        h.manage()                                                      # quiet twice: closed, the new session is due
        self.assertEqual((h.manager_due, self.killed, starts), (True, ["=fleet-manager:=manager"], []))
        for _ in range(3):
            h.manage()
        self.assertEqual((h.manager_due, len(starts)), (False, 1))      # exactly one new session
        self.assertEqual(fleet.launch_words(starts[0])[0], "codex")
        self.assertIs(h.manager_bound(), True)                          # its record names it before its conversation


    def test_a_close_stays_due_when_a_later_step_of_the_same_round_fails(self):
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        h.manage()
        h.manager_retiring = (h.manager_retiring[0] - fleet.RETIRE_QUIET - 1, h.manager_retiring[1])
        with patch.object(h, "report_manager_bound", side_effect=OSError("fork failed")):
            with self.assertRaises(OSError):                            # the loop catches it and goes on
                h.manage()
        self.assertEqual((self.killed, h.manager_due), (["=fleet-manager:=manager"], True))
        with patch.object(h, "start_manager", return_value=False) as started:
            h.manage()                                                  # the next round starts the new session
        started.assert_called_once()

    def test_a_reading_after_the_window_went_keeps_the_processes_of_earlier_readings(self):
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        old = {4242: f"claude --resume {CLAUDE_SESSION}", 4343: "npm run dev"}
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        self.task_work.return_value, self.table = old, [(pid, 1, args, False) for pid, args in old.items()]
        self.assertFalse(h.retire_old_manager())                        # a reading sees both processes
        self.task_work.return_value = {}                                # the next reading comes after the window went
        self.assertFalse(h.retire_old_manager())
        self.windows.pop("manager")
        self.assertFalse(h.retire_old_manager())                        # closed by hand: its processes still run
        self.assertFalse(h.retire_old_manager())                        # and the next round ends them
        self.end_processes.assert_called_with([4242, 4343])
        self.table = []
        self.assertTrue(h.retire_old_manager())

    def test_a_session_that_ends_at_its_start_never_ends_the_helper(self):
        h = self.helper(CODEX, {}, ["> \n"])
        error = subprocess.CalledProcessError(1, ["tmux", "set-option"])     # its window was gone at once
        with patch.object(fleet, "windows", return_value=[]), patch.object(fleet, "manager_generation", return_value="g1"), \
                patch.object(fleet, "manager_credential", return_value=TOKEN), patch.object(h, "start", side_effect=error):
            self.assertTrue(h.start_manager())                          # it is tried again
        first = json.loads(self.record("codex").read_text())             # the record of a start that never began
        self.assertIsNone(first["session"])
        self.assertFalse(self.lock_held())
        self.assertIn("ended at its start", h.say.call_args.args[0])
        command, marker, record, note = fleet.manager_start("manager", CODEX, "g1", TOKEN)
        self.assertEqual(note, "a new conversation: the recorded start never began one")    # the next try replaces it
        self.assertNotEqual(marker, first["marker"])

    def test_an_old_session_at_a_question_closes_without_an_answer_and_nobody_is_asked(self):
        """The second review of 29 October 2026: nobody sits at that screen, so the switch waited for a person, and the
        owner got switch_stalled ("answer what it shows"). It closes as at its usage-limit menu, which answers nothing,
        and the screen watch tells the hub nothing of that question meanwhile."""
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["Do you want to proceed?\n❯ 1. Yes\n  2. No\n"])
        with patch.object(fleet, "http", return_value=(200, {})) as sent:
            self.assertFalse(h.retire_old_manager())                    # its first quiet reading
            for _ in range(2):
                h.watch_screens()
            self.assertTrue(self.quiet_twice(h))
        self.assertEqual([c.args[2] for c in sent.call_args_list if c.args[1] == "/helper/dialog/manager/manager"
                          and c.args[2].get("kind") not in ("frozen", "moving")], [])
        self.assertEqual(self.killed, ["=fleet-manager:=manager"])
        self.assertNotIn("send-keys", self.commands)                    # no key went into the question
        self.assertTrue(any("which nobody reads" in c.args[0] for c in h.say.call_args_list))

    def test_a_start_makes_the_tmux_session_again_when_it_ended_with_the_old_window(self):
        h = self.helper(CODEX, {}, ["> \n"])
        session = {"there": False}
        commands = []

        def tmux(*args, check=False, **kw):
            commands.append(args[0])
            if args[0] == "has-session":
                return subprocess.CompletedProcess(args, 0 if session["there"] else 1, "", "")
            if args[0] == "new-session":
                session["there"] = True
            if args[0] == "list-windows" and not session["there"]:
                return subprocess.CompletedProcess(args, 1, "", "can't find session: fleet-manager")
            return subprocess.CompletedProcess(args, 0, "home\n" if args[0] == "list-windows" else "", "")
        with patch.object(fleet, "tmux", side_effect=tmux), patch.object(fleet, "manager_generation", return_value="g1"), \
                patch.object(fleet, "ensure_session", REAL_ENSURE_SESSION), \
                patch.object(fleet, "manager_credential", return_value=TOKEN), patch.object(h, "start") as started:
            self.assertFalse(h.start_manager())                         # it started
        self.assertLess(commands.index("new-session"), commands.index("list-windows"))
        started.assert_called_once()

    def test_a_restarted_helper_takes_two_quiet_readings_of_its_own(self):
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        windows = {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}
        first = self.helper(CODEX, windows, ["> \n"])
        self.assertFalse(first.retire_old_manager())
        first.manager_lock.close()                                      # its process ended, and its lock with it
        second = self.helper(CODEX, windows, ["> \n"])
        self.assertFalse(second.retire_old_manager())                   # its own first reading
        self.assertEqual(self.killed, [])
        self.assertTrue(self.quiet_twice(second))

    def test_an_old_session_in_its_usage_limit_menu_closes_without_an_answer(self):
        self.save("claude", session=CLAUDE_SESSION)
        transcript = self.claude_conversation()
        limit = {"type": "assistant", "isApiErrorMessage": True, "error": "rate_limit", "sessionId": CLAUDE_SESSION,
                 "timestamp": "2026-10-13T06:00:00.000Z", "quotaLimits": {"status": "rejected", "resetsAt": 1791900000},
                 "message": {"model": "<synthetic>", "content": [{"type": "text", "text": "Claude usage limit reached."}]}}
        later = {"type": "assistant", "sessionId": CLAUDE_SESSION,
                 "message": {"model": "claude-x", "content": [{"type": "text", "text": "Done."}]}}
        menu = "Claude usage limit reached.\n❯ 1. Stop and wait for limit to reset\n  2. Switch to extra usage\n"
        transcript.write_text(json.dumps(limit) + "\n" + json.dumps(later) + "\n")
        transcript.write_text(json.dumps(limit) + "\n" + json.dumps({"type": "system", "subtype": "turn_duration"}) + "\n")
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, [menu])
        self.assertTrue(self.quiet_twice(h))                            # its usage-limit menu: closed, not answered
        self.assertEqual(self.killed, ["=fleet-manager:=manager"])
        self.assertNotIn("send-keys", self.commands)                    # no key went into that menu
        self.assertTrue(any("usage-limit menu" in c.args[0] for c in h.say.call_args_list))
        self.assertTrue(transcript.exists())

    def test_a_conversation_ends_at_its_usage_limit_only_with_a_limit_as_its_last_record(self):
        limit = {"timestamp": "2026-10-13T06:00:00.000Z", "type": "event_msg",
                 "payload": {"type": "error", "message": "You've hit your usage limit.", "codex_error_info": "usage_limit"}}
        self.assertTrue(fleet.limit_menu("codex", str(self.codex_rollout(rows=[limit]))))
        self.assertFalse(fleet.limit_menu("codex", str(self.codex_rollout())))     # it ends with its first prompt
        self.assertFalse(fleet.limit_menu("codex", ""))                            # a start with no conversation
        self.assertFalse(fleet.limit_menu("codex", str(self.tmp / "missing.jsonl")))

    def test_a_restarted_helper_ends_the_closed_session_s_processes_before_any_start(self):
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        windows, old = {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, {4242: f"claude --resume {CLAUDE_SESSION}"}
        first = self.helper(CODEX, windows, ["> \n"])
        self.task_work.return_value, self.quiesce.return_value = old, (False, 0, "4242 claude")
        self.assertFalse(self.quiet_twice(first))
        self.assertEqual(self.closing_at_kill, {"procs": {"4242": old[4242]}, "start": True})     # kept before the close
        first.manager_lock.close()                                      # the helper stops: its lock ends with it
        self.table = [(4242, 1, old[4242], False)]                      # the old session's process still runs
        second = self.helper(CODEX, windows, ["> \n"])                  # the restarted helper
        self.assertEqual((second.manager_left, second.other_runtime_windows()), (old, ["manager"]))
        self.assertTrue(second.start_manager())                         # nothing starts while they run
        with patch.object(fleet, "agent_conf", return_value=CODEX), patch.object(fleet, "ensure_session"), \
                patch.object(fleet, "windows", return_value=[]), patch.object(fleet, "start_window") as started, \
                contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
            fleet.cmd_start(types.SimpleNamespace(agent="manager"))
        self.assertIn("still run (4242)", err.getvalue())
        started.assert_not_called()
        windows["manager"] = (CLAUDE_SESSION, OLD_CODEX)                # a later window by hand is never ended here
        self.assertFalse(second.retire_old_manager())
        self.end_processes.assert_called_with([4242])
        self.quiesce.assert_not_called()
        self.assertTrue(self.lock_held())                               # held again, as before the restart
        windows.pop("manager")
        self.table = []                                                 # it has ended
        self.assertTrue(second.retire_old_manager())                    # now the new runtime's session is due
        self.assertFalse(self.lock_held())
        self.assertFalse(Path(fleet.closing_file("manager")).exists())


    def test_fleet_py_start_says_whether_the_helper_starts_the_session_after_the_old_processes(self):
        """Not after a session that a start by hand replaced (the closing file's start flag): then the owner starts it
        again when they have ended."""
        old = {4242: f"claude --resume {CLAUDE_SESSION}"}
        self.table = [(4242, 1, old[4242], False)]
        for start, words in ((True, "Its helper ends them and then starts the session; nothing was started"),
                             (False, "Its helper ends them but starts no session after them: run this command again "
                                     "when they have ended; nothing was started")):
            with self.subTest(start=start):
                fleet.save_closing("manager", old, start)
                with patch.object(fleet, "agent_conf", return_value=CODEX), patch.object(fleet, "ensure_session"), \
                        patch.object(fleet, "windows", return_value=[]), patch.object(fleet, "start_window") as started, \
                        contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
                    fleet.cmd_start(types.SimpleNamespace(agent="manager"))
                self.assertIn(words, err.getvalue())
                started.assert_not_called()

    def test_an_unknown_window_list_closes_nothing_and_is_never_bound(self):
        h = fleet.Helper("manager", CODEX)
        h.lifecycle = Mock()
        h.lifecycle.tools_changed = False
        with patch.object(fleet, "tmux", return_value=subprocess.CompletedProcess([], 1, "", "no server")), \
                patch.object(h, "look", return_value=[]):
            self.assertFalse(h.retire_old_manager())
            self.assertEqual((h.manager_bound(), h.other_runtime_windows()), (False, ["manager"]))
            self.assertIs(h.switch_state()["manager_bound"], False)


class Handover(StandIn):
    """What a switch hands to the new runtime's session: the messages that the previous session read in its last turn
    that did not end normally, from that session's own conversation file."""
    def write(self, rows, name="conversation.jsonl"):
        path = self.tmp / name
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))
        return str(path)

    def test_a_claude_turn_that_ended_hands_nothing_over_and_one_that_stopped_hands_its_reads(self):
        finished = [*claude_read("r1", 5, 6), claude_end()]
        self.assertEqual(fleet.unfinished_turn_reads("claude", self.write(finished)), [])
        stopped = [*finished, *claude_read("r2", 7), CLAUDE_LIMIT]
        self.assertEqual(fleet.unfinished_turn_reads("claude", self.write(stopped)), [7])
        shell = [{"type": "assistant", "message": {"stop_reason": "tool_use", "content": [
                     {"type": "tool_use", "id": "b1", "name": "Bash", "input": {"command": "sqlite3 pilot.db"}}]}},
                 {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "b1",
                                                           "content": read_answer(9)}]}}]
        closed = [*finished, *claude_read("r2", 7), *shell, claude_end("A subagent's end.", sidechain=True)]
        self.assertEqual(fleet.unfinished_turn_reads("claude", self.write(closed)), [7])   # closed during its turn
        later = [*stopped, {"type": "user", "message": {"content": "continue"}}, claude_end()]
        self.assertEqual(fleet.unfinished_turn_reads("claude", self.write(later)), [])     # a later turn finished them
        self.assertEqual(fleet.unfinished_turn_reads("claude", self.write([*claude_read("r1", 3), CLAUDE_LIMIT,
                                                                           *claude_read("r2", 4, 5)])), [3, 4, 5])

    def test_odd_rows_never_stop_a_start(self):
        """A conversation file is the runtime's: an id of another type there gives no hand-over and no exception."""
        odd = [{"type": "assistant", "message": {"stop_reason": "tool_use", "content": [
                   {"type": "tool_use", "id": ["r1"], "name": "mcp__fleet__read_messages"}]}},
               {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": {"r": 1},
                                                         "content": read_answer(5)}]}}]
        self.assertEqual(fleet.unfinished_turn_reads("claude", self.write(odd)), [])
        odd = [{"type": "response_item", "payload": {"type": "function_call", "name": "mcp__fleet__read_messages",
                                                     "call_id": ["c1"]}},
               {"type": "response_item", "payload": {"type": "function_call_output", "call_id": {"c": 1},
                                                     "output": read_answer(5)}},
               {"type": "event_msg", "payload": {"type": "item_completed", "item": {
                   "type": "McpToolCall", "server": "fleet", "tool": "read_messages", "result": ["odd"]}}}]
        self.assertEqual(fleet.unfinished_turn_reads("codex", self.write(odd)), [])

    def test_only_the_first_line_of_a_read_answer_names_its_messages(self):
        quoted = "[vps] My result:\n\nMessage M-1:\n[owner] An old message.\n\nMessage M-99999999999999999999:\nx"
        self.assertEqual(fleet.read_ids(read_answer(8, body=quoted)), [8])
        self.assertEqual(fleet.read_ids(GUIDANCE + "Message M-8:\n[owner] An answer of an older hub."), [])
        self.assertEqual(fleet.read_ids("No unread messages. Wait for the next signal."), [])
        self.assertEqual(fleet.read_ids(json.dumps({"content": [{"type": "text", "text": read_answer(8, 9)}]})), [8, 9])
        call = claude_read("r1", 8)[0]                                  # a read, and its answer with the quote
        answer = {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "r1",
                                                           "content": read_answer(8, body=quoted)}]}}
        self.assertEqual(fleet.unfinished_turn_reads("claude", self.write([call, answer, CLAUDE_LIMIT])), [8])

    def test_a_codex_turn_that_its_usage_limit_or_an_interruption_ended_hands_its_reads(self):
        finished = [*codex_read("m1", 5), CODEX_END]
        self.assertEqual(fleet.unfinished_turn_reads("codex", self.write(finished)), [])
        for end in (CODEX_LIMIT_END, {"type": "event_msg", "payload": {"type": "turn_aborted", "turn_id": "t2"}}, None):
            with self.subTest(end=end):
                rows = [*finished, *codex_read("m2", 7), *codex_read("c3", 8, older=True)] + ([end] if end else [])
                self.assertEqual(fleet.unfinished_turn_reads("codex", self.write(rows)), [7, 8])
        other = {"type": "event_msg", "payload": {"type": "item_completed", "item": {
            "type": "McpToolCall", "id": "x", "server": "codex_app", "tool": "read_thread",
            "result": {"content": [{"type": "text", "text": read_answer(9)}]}}}}
        self.assertEqual(fleet.unfinished_turn_reads("codex", self.write([*finished, other])), [])

    def test_a_long_file_is_read_from_its_end_and_further_only_when_no_turn_ended_there(self):
        filler = [{"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "z", "content": "x" * 300}]}}]
        with patch.object(fleet, "HANDOVER_TAIL", 1024):
            self.assertEqual(fleet.unfinished_turn_reads(
                "claude", self.write([*claude_read("r1", 3), *filler * 20, *claude_read("r2", 4)])), [3, 4])
            self.assertEqual(fleet.unfinished_turn_reads(
                "claude", self.write([*claude_read("r1", 3), *filler * 20, claude_end(), *claude_read("r2", 4)])), [4])
        self.assertEqual(fleet.unfinished_turn_reads("claude", str(self.tmp / "missing.jsonl")), [])
        self.assertEqual(fleet.unfinished_turn_reads("claude", ""), [])     # a start that never began a conversation

    def unfinished_claude(self):
        """The previous runtime's recorded Claude session, whose last turn read M-7 and stopped at its usage limit."""
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation().write_text(self.read_rows([*claude_read("r1", 5), claude_end(),
                                                              *claude_read("r2", 7), CLAUDE_LIMIT]))

    def start(self, h, generation="g1"):
        """One start of the manager session by the helper's loop; the hand-over saved at the moment it starts."""
        at_start = []
        with patch.object(fleet, "windows", return_value=[]), \
                patch.object(fleet, "manager_generation", return_value=generation), \
                patch.object(fleet, "manager_credential", return_value=TOKEN), \
                patch.object(h, "start", side_effect=lambda *a, **kw: at_start.append(fleet.load_handover("manager"))):
            h.manager_due, h.manager_tried = True, None
            h.manage()
        self.assertFalse(h.manager_due)
        return at_start

    def test_the_start_after_a_switch_saves_the_hand_over_first_and_the_status_reports_it(self):
        self.unfinished_claude()
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        self.assertTrue(self.quiet_twice(h))                            # this helper closed it
        self.assertEqual(h.switch_state()["manager_handover"], {})
        self.assertEqual(self.start(h), [{"claude": [7]}])              # saved before the new session starts
        self.assertEqual(h.switch_state()["manager_handover"], {"claude": [7]})
        self.assertEqual(fleet.Helper("manager", CODEX).switch_state()["manager_handover"], {"claude": [7]})  # restarted

    def test_a_session_closed_before_the_helper_read_it_hands_over_at_the_start_too(self):
        """Closed by the owner, or gone with tmux, before the updated helper's first reading: no close ran here."""
        self.unfinished_claude()
        h = self.helper(CODEX, {}, ["> \n"])
        self.assertFalse(h.retire_old_manager())                        # nothing to close
        self.assertEqual(self.start(h), [{"claude": [7]}])

    def test_a_resumed_conversation_hands_over_its_own_stopped_turn_and_the_other_runtime_s(self):
        """A switch back after a start of the other runtime failed: the resumed session does not go on with the turn
        that its usage limit stopped. And each runtime's conversation gives its own list: the hub takes for each
        message the list of the runtime whose session read it last."""
        self.unfinished_claude()
        h = self.helper(CLAUDE, {}, ["> \n"])
        self.assertEqual(self.start(h), [{"claude": [7]}])              # no Codex conversation began
        self.save("codex", marker=MARKER, session=THREAD)
        self.codex_rollout(rows=[*codex_read("m1", 8), CODEX_LIMIT_END])
        self.assertEqual(self.start(h), [{"claude": [7], "codex": [8]}])

    def test_the_owner_s_start_saves_the_hand_over_too(self):
        self.unfinished_claude()
        saved = []
        with patch.object(fleet, "agent_conf", return_value=CODEX), patch.object(fleet, "windows", return_value=[]), \
                patch.object(fleet, "manager_generation", return_value="g1"), patch.object(fleet, "claim_checkout"), \
                patch.object(fleet, "manager_credential", return_value=TOKEN), patch.object(fleet, "tmux"), \
                patch.object(fleet, "start_window", side_effect=lambda *a: saved.append(fleet.load_handover("manager"))), \
                contextlib.redirect_stdout(io.StringIO()):
            fleet.cmd_start(types.SimpleNamespace(agent="manager"))
        self.assertEqual(saved, [{"claude": [7]}])

    def test_a_start_with_nothing_unfinished_or_of_another_hub_database_hands_nothing_over(self):
        self.unfinished_claude()
        h = self.helper(CODEX, {}, ["> \n"])
        fleet.save_handover("manager", {"claude": [3]})                 # an earlier one that the hub has not answered
        self.assertEqual(self.start(h, generation="g2"), [{}])          # its ids name another database's messages
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation().write_text(self.read_rows([*claude_read("r1", 5), claude_end()]))
        self.assertEqual(self.start(h), [{}])                           # its last turn ended normally
        self.record("claude").unlink()
        self.assertEqual(self.start(h), [{}])                           # no previous runtime's session at all
        self.assertFalse(Path(fleet.handover_file("manager")).exists())

    def test_a_long_claude_read_answer_is_read_whole(self):
        """Claude Code keeps only a preview of a long tool result in the message; toolUseResult has it whole."""
        call, answer = claude_read("r1", *range(1, 31))
        preview = "<persisted-output>\nOutput too large (61102 characters). Full output saved to: /x/r1.txt\n\n" + \
            read_answer(*range(1, 31))[:2000]
        row = dict(answer, toolUseResult=answer["message"]["content"][0]["content"])
        row["message"] = {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "r1", "content": preview}]}
        self.assertEqual(fleet.unfinished_turn_reads("claude", self.write([call, row, CLAUDE_LIMIT])), list(range(1, 31)))
        row = dict(row, toolUseResult="Error: a string result")         # an error result: its own text counts
        self.assertEqual(fleet.unfinished_turn_reads("claude", self.write([call, row, CLAUDE_LIMIT])), [])

    def test_a_tmux_session_that_ended_with_the_old_window_lets_the_switch_go_on(self):
        """The old window was the last one of the tmux session, which tmux then ended: no window, not unknown."""
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["Do you want to proceed?\n❯ 1. Yes\n  2. No\n"])
        self.assertFalse(h.retire_old_manager())                        # a question: it waits, with the lock
        gone = subprocess.CompletedProcess([], 1, "", "can't find session: fleet-manager")
        unknown = subprocess.CompletedProcess([], 1, "", "server exited unexpectedly")
        with patch.object(fleet, "tmux", side_effect=lambda *a, **kw: unknown):
            self.assertFalse(h.retire_old_manager())                    # an unknown answer changes nothing
            self.assertTrue(self.lock_held())
            self.assertEqual((h.other_runtime_windows(), h.manager_bound()), (["manager"], False))
        with patch.object(fleet, "tmux", side_effect=lambda *a, **kw: gone):
            self.assertTrue(h.retire_old_manager())                     # the new runtime's session is due
            self.assertFalse(self.lock_held())
            self.assertEqual((h.other_runtime_windows(), h.manager_bound()), ([], None))

    def test_one_status_takes_both_manager_fields_from_one_reading(self):
        """Two readings could disagree (no window, then no answer): the hub would take that for the new session."""
        h = self.helper(CODEX, {}, ["> \n"])
        with patch.object(h, "manager_reading", side_effect=[None, fleet.Refused("no answer")]) as reading:
            state = h.switch_state()
        self.assertEqual((state["other_runtime_windows"], state["manager_bound"], reading.call_count), ([], None, 1))
        with patch.object(h, "manager_reading", side_effect=fleet.Refused("no answer")):
            state = h.switch_state()
        self.assertEqual((state["other_runtime_windows"], state["manager_bound"]), (["manager"], False))

    def test_an_old_window_that_goes_before_the_helper_holds_the_lock_still_starts_the_new_session(self):
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        old = {4242: f"claude --resume {CLAUDE_SESSION}"}
        self.task_work.return_value, self.table = old, [(4242, 1, old[4242], False)]
        with patch.object(fleet, "hold_manager_lock", side_effect=fleet.Refused("a start runs")):
            self.assertFalse(h.retire_old_manager())                    # seen, but `fleet.py start` holds the lock
        self.windows.pop("manager")                                     # then the owner closes it
        held = fleet.hold_manager_lock("manager")                       # while `fleet.py start` still runs
        self.assertFalse(h.retire_old_manager())                        # nothing goes on without the lock
        self.assertEqual(h.manager_left, {})
        held.close()
        self.assertFalse(h.retire_old_manager())                        # its process still runs: still pending
        self.assertEqual((h.manager_left, h.other_runtime_windows()), (old, ["manager"]))
        self.table = []
        self.assertTrue(h.retire_old_manager())                         # the new runtime's session is due
        self.assertFalse(self.lock_held())

    def test_an_old_window_seen_at_the_helper_s_start_starts_the_new_session_when_it_goes(self):
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        for start, due in ((OLD_CLAUDE, True), (OLD_CODEX, False), ("'unclosed", False)):
            with self.subTest(start=start):
                h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, start)}, ["> \n"])
                self.assertFalse(h.manager_first())                     # a window runs: no start now
                self.windows.pop("manager")                             # it goes before the first round
                # Only a window of the previous runtime starts the new one; never the agent's own runtime's, which
                # the owner closed, and never one whose program cannot be read.
                self.assertEqual(h.retire_old_manager(), due)
        h = self.helper(CODEX, {}, ["> \n"])
        self.assertTrue(h.manager_first())                              # no window: due at once

    def test_a_session_that_fleet_py_start_replaced_still_ends_what_the_old_one_left(self):
        """The helper saw the previous runtime's window without the lock; the owner closed it and started the new
        runtime with `fleet.py start` before the helper's next round."""
        self.save("claude", session=CLAUDE_SESSION, begun=False)         # Claude wrote no conversation file
        old, new = {4242: f"claude --resume {CLAUDE_SESSION}"}, {5151: "codex --no-daemon"}
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        self.task_work.return_value, self.table = old, [(4242, 1, old[4242], False)]
        with patch.object(fleet, "hold_manager_lock", side_effect=fleet.Refused("a start runs")):
            self.assertFalse(h.retire_old_manager())                    # seen, but `fleet.py start` holds the lock
        self.windows["manager"] = (MARKER, OLD_CODEX)                   # its start replaced the closed old window
        self.assertEqual(h.other_runtime_windows(), ["manager"])        # not handled yet: the switch stays open
        self.task_work.return_value, self.table = new, [(4242, 1, old[4242], False), (5151, 1, new[5151], False)]
        self.assertFalse(h.retire_old_manager())
        self.assertEqual((h.manager_left, h.other_runtime_windows()), (old, ["manager"]))   # only the old one's
        self.assertFalse(self.record("claude").exists())                # it never began: nothing to continue
        self.table = [(5151, 1, new[5151], False)]
        self.assertFalse(h.retire_old_manager())                        # the old process has ended: nothing is due
        self.assertEqual((self.killed, h.other_runtime_windows()), ([], []))
        with patch.object(fleet, "windows", return_value=["home", "manager"]), patch.object(h, "start") as started, \
                patch.object(fleet, "manager_generation", return_value="g1"):
            h.manager_due, h.manager_tried = True, None
            h.manage()
        started.assert_not_called()                                     # its session runs: nothing more starts
        self.assertFalse(self.lock_held())

    def test_after_fleet_py_start_replaced_it_the_leftovers_end_before_anything_starts(self):
        """The leftovers of the replaced session end after the owner also closed the new runtime's session, also
        across a restart of this helper: neither the helper's start nor the close itself makes a start due while
        they run. Only once nothing of that session is left does the loop's own watch start one (manager_gone),
        because the fleet has no manager session at all then."""
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        old = {4242: f"claude --resume {CLAUDE_SESSION}"}
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        self.task_work.return_value, self.table = old, [(4242, 1, old[4242], False)]
        with patch.object(fleet, "hold_manager_lock", side_effect=fleet.Refused("a start runs")):
            self.assertFalse(h.retire_old_manager())
        self.windows["manager"] = (MARKER, OLD_CODEX)                   # replaced by `fleet.py start`
        self.task_work.return_value = {}
        self.assertFalse(h.retire_old_manager())                        # its process still runs
        self.assertEqual(json.loads(Path(fleet.closing_file("manager")).read_text())["start"], False)
        h.manager_lock.close()                                          # this helper stops here and starts again
        self.windows.pop("manager")                                     # the owner closes the new session too
        again = self.helper(CODEX, self.windows, ["> \n"])
        self.assertEqual((again.manager_left, again.manager_left_start), (old, False))
        again.manager_due = again.manager_first()                       # cmd_run's decision: no start now
        self.assertFalse(again.manager_due)
        self.table = []
        self.assertFalse(again.retire_old_manager())                    # they have ended: this close makes nothing due
        self.assertFalse(Path(fleet.closing_file("manager")).exists())
        self.assertFalse(self.lock_held())
        with patch.object(again, "start_manager", return_value=False) as started:
            again.manage()                                              # and no session stands: the watch starts one
        started.assert_called_once()

    def test_this_helper_s_own_close_also_ends_what_earlier_readings_saw(self):
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        self.task_work.return_value, self.table = {4000: "npm run dev"}, [(4000, 1, "npm run dev", False)]
        self.assertFalse(h.retire_old_manager())                        # seen at the first reading
        self.task_work.return_value = {}                                # it left the pane: no later reading has it
        self.assertTrue(self.quiet_twice(h))
        self.assertEqual(self.closing_at_kill, {"procs": {"4000": "npm run dev"}, "start": True})
        self.assertEqual(self.quiesce.call_args.kwargs["also"], {4000: "npm run dev"})     # ended with the session

    def test_a_claude_start_of_the_agent_s_runtime_closed_before_it_began_leaves_no_record(self):
        """Its record would stop every later Claude start, also a switch back to Claude."""
        self.save("claude", session=CLAUDE_SESSION, begun=False)         # Claude wrote no conversation file yet
        h = self.helper(CLAUDE, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["Trust this folder?\n❯ 1. Yes\n"])
        self.assertFalse(h.retire_old_manager())
        self.windows.pop("manager")                                     # the owner closes it at its first question
        held = fleet.hold_manager_lock("manager")                       # while a start runs: read again
        self.assertFalse(h.retire_old_manager())
        self.assertTrue(self.record("claude").exists())
        held.close()
        self.assertFalse(h.retire_old_manager())                        # never started again here
        self.assertFalse(self.record("claude").exists())
        self.assertFalse(self.lock_held())
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()                                      # one that began: its record stays
        self.windows["manager"] = (CLAUDE_SESSION, OLD_CLAUDE)
        self.assertFalse(h.retire_old_manager())
        self.windows.pop("manager")
        self.assertFalse(h.retire_old_manager())
        self.assertTrue(self.record("claude").exists())

    def test_a_helper_that_waits_for_its_update_keeps_what_its_session_leaves(self):
        """While it waits, its own session is already the previous runtime's: if it goes, its leftover processes go
        to the closing file, which the updated helper ends before any start."""
        old = {4242: f"claude --resume {CLAUDE_SESSION}"}
        for replaced in (False, True):
            with self.subTest(replaced=replaced):
                h = self.helper(CLAUDE, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
                self.task_work.return_value, self.table = old, [(4242, 1, old[4242], False)]
                with patch.object(fleet, "team_runtime", return_value="codex"):
                    self.assertFalse(h.retire_old_manager())             # it waits for its update
                    if replaced:
                        self.windows["manager"] = (MARKER, OLD_CODEX)   # `fleet.py start` started codex
                    else:
                        self.windows.pop("manager")                     # the owner closed it
                    self.task_work.return_value = {5151: "codex"} if replaced else {}
                    self.assertFalse(h.retire_old_manager())
                self.assertEqual((self.killed, json.loads(Path(fleet.closing_file("manager")).read_text())),
                                 ([], {"procs": {"4242": old[4242]}, "start": not replaced}))
                updated = self.helper(CODEX, self.windows, ["> \n"])
                self.assertEqual((updated.manager_left, updated.other_runtime_windows()[-1:]), (old, ["manager"]))
                fleet.save_closing("manager", {})
                self.windows.pop("manager", None)

    def test_a_replaced_session_with_nothing_left_makes_no_start_due(self):
        """Its old process ended already at the reading that finds the replacement: when the owner then closes the
        session that `fleet.py start` started, this helper does not start it again."""
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        with patch.object(fleet, "hold_manager_lock", side_effect=fleet.Refused("a start runs")):
            self.assertFalse(h.retire_old_manager())
        self.windows["manager"] = (MARKER, OLD_CODEX)                   # replaced by `fleet.py start`
        self.assertFalse(h.retire_old_manager())                        # nothing is due
        self.assertEqual((h.manager_left, h.other_runtime_windows()), ({}, []))
        self.assertFalse(self.lock_held())
        self.windows.pop("manager")                                     # the owner closes it
        self.assertFalse(h.retire_old_manager())

    def test_a_session_that_runs_after_a_tmux_option_failed_keeps_its_record(self):
        """The window started, and one of its tmux options failed: its program did not end, so it is not started
        again, and its conversation stays recorded for a switch back."""
        h = self.helper(CODEX, {}, ["> \n"])
        running = []
        failed = subprocess.CalledProcessError(1, ["tmux", "set-option"])

        def start(name, command, **kw):
            running.append(name)
            raise failed
        with patch.object(fleet, "windows", side_effect=lambda session, **kw: ["home", *running]), \
                patch.object(fleet, "manager_generation", return_value="g1"), \
                patch.object(fleet, "manager_credential", return_value=TOKEN), patch.object(h, "start", side_effect=start):
            self.assertFalse(h.start_manager())                         # it runs: no second start
        self.assertEqual(json.loads(self.record("codex").read_text())["generation"], "g1")
        self.assertIn("set-option", self.commands)                      # its session id is set again
        with patch.object(fleet, "windows", return_value=["home"]), patch.object(fleet, "manager_generation", return_value="g1"), \
                patch.object(fleet, "manager_credential", return_value=TOKEN), patch.object(h, "start", side_effect=failed):
            self.assertTrue(h.start_manager())                          # its program ended at once: tried again

    def test_the_end_of_a_replaced_session_s_leftovers_is_reported_at_once(self):
        """Nothing more starts then, and manager_bound does not change: the hub still learns at once that nothing of
        the previous session is left, which ends its hold."""
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        old = {4242: f"claude --resume {CLAUDE_SESSION}"}
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        self.task_work.return_value, self.table = old, [(4242, 1, old[4242], False)]
        with patch.object(fleet, "hold_manager_lock", side_effect=fleet.Refused("a start runs")):
            self.assertFalse(h.retire_old_manager())
        self.windows["manager"] = (MARKER, OLD_CODEX)                   # replaced by `fleet.py start`
        self.task_work.return_value = {}
        self.assertFalse(h.retire_old_manager())
        h.report_manager_bound()
        reports = h.lifecycle.report.call_count
        self.table = []                                                 # the old process ends
        self.assertFalse(h.retire_old_manager())
        h.report_manager_bound()
        self.assertEqual(h.lifecycle.report.call_count, reports + 1)
        self.assertEqual(h.other_runtime_windows(), [])

    def test_what_the_old_helper_saw_survives_its_update_restart(self):
        """The old helper waits for its update and keeps its session's processes; its restart can come before its
        next reading, and the owner can close the session meanwhile."""
        old = {4242: f"claude --resume {CLAUDE_SESSION}"}
        for after, due, left in (("closed", True, old), ("replaced", False, old), ("runs on", False, {})):
            with self.subTest(after=after):
                fleet.save_closing("manager", {})
                h = self.helper(CLAUDE, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
                self.task_work.return_value, self.table = old, [(4242, 1, old[4242], False)]
                with patch.object(fleet, "team_runtime", return_value="codex"):
                    self.assertFalse(h.retire_old_manager())            # it waits for its update
                if after == "closed":
                    self.windows.pop("manager")
                elif after == "replaced":
                    self.windows["manager"] = (MARKER, OLD_CODEX)       # `fleet.py start` started codex
                self.task_work.return_value = {5151: "codex"} if after == "replaced" else {}
                updated = self.helper(CODEX if after != "runs on" else CLAUDE, self.windows, ["> \n"])
                # Closed: due, once its leftovers have ended (start_manager waits for them); replaced: never again.
                self.assertEqual((updated.manager_first(), updated.manager_left), (due, left))
                if left:
                    self.assertEqual(json.loads(Path(fleet.closing_file("manager")).read_text())["start"], due)
                self.assertFalse(Path(fleet.seen_file("manager")).exists())
                self.assertEqual(self.end_processes.call_count, 0)      # nothing of a running session is ended
                self.windows["manager"] = (CLAUDE_SESSION, OLD_CLAUDE)

    def test_a_saved_snapshot_waits_for_a_reading_when_tmux_gives_no_answer_at_the_start(self):
        old = {4242: f"claude --resume {CLAUDE_SESSION}"}
        unknown = subprocess.CompletedProcess([], 1, "", "server exited unexpectedly")
        for after, left, start in (("closed", old, True), ("replaced", old, False), ("runs on", {}, None)):
            with self.subTest(after=after):
                fleet.save_closing("manager", {})
                self.table = [(4242, 1, old[4242], False)]
                fleet.save_seen("manager", (CLAUDE_SESSION, "claude", None), old)      # an earlier run saw it
                windows = {"closed": {}, "replaced": {"manager": (MARKER, OLD_CODEX)},
                           "runs on": {"manager": (CLAUDE_SESSION, OLD_CODEX)}}[after]
                h = self.helper(CODEX, windows, ["> \n"])
                with patch.object(fleet, "tmux", side_effect=lambda *a, **kw: unknown):
                    self.assertFalse(h.manager_first())                 # no answer: nothing starts yet
                self.task_work.return_value = {5151: "codex"} if windows else {}
                self.assertFalse(h.retire_old_manager())                # the first known reading
                self.assertEqual(h.manager_left, left)
                if left:
                    self.assertEqual(json.loads(Path(fleet.closing_file("manager")).read_text())["start"], start)
                self.assertFalse(Path(fleet.seen_file("manager")).exists())
                self.assertEqual(self.end_processes.call_count, 0)
                if h.manager_lock:
                    h.manager_lock.close()

    def test_a_never_begun_claude_record_goes_also_when_fleet_py_start_replaces_it_during_the_update(self):
        self.save("claude", session=CLAUDE_SESSION, begun=False)         # Claude wrote no conversation file
        h = self.helper(CLAUDE, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["Trust this folder?\n❯ 1. Yes\n"])
        self.assertFalse(h.retire_old_manager())                        # seen before the switch
        self.windows["manager"] = (MARKER, OLD_CODEX)                   # closed, and `fleet.py start` started codex
        with patch.object(fleet, "team_runtime", return_value="codex"):
            self.assertFalse(h.retire_old_manager())
        self.assertFalse(self.record("claude").exists())
        self.assertFalse(self.lock_held())

    def test_a_start_whose_tmux_answers_failed_twice_gets_its_id_again_when_its_window_runs(self):
        """tmux failed or did not answer during the start, and the window list gave no answer: the next round sees
        whether it runs. Its record was saved before its start; its window gets its id again, unless another start's
        window runs there."""
        failed = subprocess.CalledProcessError(124, ["tmux", "new-window"], "", "timed out")
        for other in (False, True):
            with self.subTest(other_start=other):
                Path(self.record("codex")).unlink(missing_ok=True)
                h = self.helper(CODEX, {}, ["> \n"])
                lists = iter([["home"], fleet.Refused("no answer")])

                def windows(session, **kw):
                    answer = next(lists)
                    if isinstance(answer, Exception):
                        raise answer
                    return answer
                with patch.object(fleet, "windows", side_effect=windows), patch.object(h, "start", side_effect=failed), \
                        patch.object(fleet, "manager_generation", return_value="g1"), \
                        patch.object(fleet, "manager_credential", return_value=TOKEN):
                    self.assertTrue(h.start_manager())                  # unknown: tried again
                marker = h.manager_pending[0]
                self.assertEqual(json.loads(self.record("codex").read_text())["marker"], marker)
                self.windows["manager"] = ("019a0000-0000-7000-8000-000000000001" if other else "", OLD_CODEX)
                self.commands.clear()
                with patch.object(fleet, "windows", return_value=["home", "manager"]), \
                        patch.object(h, "start") as started:
                    self.assertFalse(h.start_manager())                 # it runs: no second start
                started.assert_not_called()
                self.assertEqual("set-option" in self.commands, not other)
                self.assertEqual(json.loads(self.record("codex").read_text())["marker"], marker)
                self.assertIsNone(h.manager_pending)

    def test_the_own_session_s_processes_are_known_when_a_switch_comes_before_the_next_reading(self):
        """The owner closes the old window right after the switch, before the old helper's first round that knows of
        the switch: its processes of the last round before the switch are still ended before the new start."""
        old = {4242: f"claude --resume {CLAUDE_SESSION}"}
        h = self.helper(CLAUDE, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        self.task_work.return_value, self.table = old, [(4242, 1, old[4242], False)]
        self.assertFalse(h.retire_old_manager())                        # a round before the switch
        self.windows.pop("manager")                                     # the switch, and the owner closes it at once
        self.task_work.return_value = {}
        with patch.object(fleet, "team_runtime", return_value="codex"):
            self.assertFalse(h.retire_old_manager())                    # the first round that knows of the switch
        self.assertEqual(json.loads(Path(fleet.closing_file("manager")).read_text()),
                         {"procs": {"4242": old[4242]}, "start": True})


    def test_a_leftovers_round_keeps_the_own_session_s_processes_for_a_switch_before_the_next_round(self):
        """The round that ends what the previous runtime's session left also keeps the processes of the agent's own
        runtime's session, as its own rounds do: a switch back and a close by hand right after it still leave them for
        the next start to end first."""
        old, own = {4242: f"claude --resume {CLAUDE_SESSION}"}, {5151: "codex --no-daemon"}
        fleet.save_closing("manager", old, False)                       # left by a session that `fleet.py start` replaced
        self.table = [(4242, 1, old[4242], False), (5151, 1, own[5151], False)]
        h = self.helper(CODEX, {"manager": (MARKER, OLD_CODEX)}, ["> \n"])
        self.task_work.return_value = own
        self.assertFalse(h.retire_old_manager())                        # 4242 still runs
        self.table = [(5151, 1, own[5151], False)]                      # it ended; now the owner switches back
        self.windows.pop("manager")                                     # and closes the Codex window at once
        self.task_work.return_value = {}
        with patch.object(fleet, "team_runtime", return_value="claude"):
            self.assertFalse(h.retire_old_manager())                    # the leftovers have ended
            self.assertFalse(h.retire_old_manager())                    # it waits for its update
        self.assertEqual(h.manager_left, own)
        self.assertEqual(json.loads(Path(fleet.closing_file("manager")).read_text())["procs"], {"5151": own[5151]})


    def test_a_leftovers_round_also_notes_the_conversation_of_the_session_that_runs(self):
        old = {4242: f"claude --resume {CLAUDE_SESSION}"}
        fleet.save_closing("manager", old, False)                       # left by a session that `fleet.py start` replaced
        self.table = [(4242, 1, old[4242], False)]                      # it still runs
        self.save("codex", marker=MARKER, session=None)                 # the new session's record, as its start wrote it
        self.codex_rollout()                                            # its conversation began
        fleet.MANAGER_THREADS.clear()
        h = self.helper(CODEX, {"manager": (MARKER, OLD_CODEX)}, ["> \n"])
        self.assertFalse(h.retire_old_manager())                        # 4242 still runs
        self.assertEqual(json.loads(self.record("codex").read_text())["session"], THREAD)

    def test_the_closing_file_is_written_before_the_snapshot_goes(self):
        """A restart between the two writes must not lose both."""
        old = {4242: f"claude --resume {CLAUDE_SESSION}"}
        real = fleet.save_seen

        def save_seen(agent, seen, procs):
            if seen is None:
                raise SystemExit("the helper stops here")
            return real(agent, seen, procs)
        h = self.helper(CLAUDE, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        self.task_work.return_value, self.table = old, [(4242, 1, old[4242], False)]
        with patch.object(fleet, "team_runtime", return_value="codex"):
            self.assertFalse(h.retire_old_manager())                    # it waits for its update, and keeps them
            self.windows.pop("manager")
            self.task_work.return_value = {}
            with patch.object(fleet, "save_seen", side_effect=save_seen), self.assertRaises(SystemExit):
                h.retire_old_manager()
        self.assertTrue(Path(fleet.closing_file("manager")).exists())
        self.assertEqual(fleet.Helper("manager", CODEX).manager_left, old)

    def test_a_never_begun_start_seen_before_a_restart_leaves_no_record(self):
        self.save("claude", session=CLAUDE_SESSION, begun=False)         # Claude wrote no conversation file
        old = {4242: f"claude --session-id {CLAUDE_SESSION}"}
        h = self.helper(CLAUDE, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["Trust this folder?\n❯ 1. Yes\n"])
        self.task_work.return_value, self.table = old, [(4242, 1, old[4242], False)]
        with patch.object(fleet, "team_runtime", return_value="codex"):
            self.assertFalse(h.retire_old_manager())                    # it waits for its update
        self.windows.pop("manager")                                     # closed; then the update restarts it
        self.table = []
        updated = self.helper(CODEX, self.windows, ["> \n"])
        self.assertTrue(updated.manager_first())
        self.assertFalse(self.record("claude").exists())
        self.assertFalse(self.lock_held())


    def test_a_conversation_that_began_and_went_before_a_restart_is_noted_at_the_start(self):
        """The previous helper saw its file while a start held the lock; its window went before this helper's start."""
        self.save("claude", session=CLAUDE_SESSION, begun=False)
        transcript = self.claude_conversation()
        fleet.save_seen("manager", (CLAUDE_SESSION, "claude", str(transcript)), {})     # an earlier run saw it
        transcript.unlink()                                             # its file went too
        h = self.helper(CODEX, {}, ["> \n"])
        self.assertTrue(h.manager_first())
        self.assertIs(json.loads(self.record("claude").read_text())["begun"], True)
        self.assertFalse(self.lock_held())
        with self.assertRaises(fleet.Refused):
            fleet.manager_start("manager", CLAUDE, "g1", TOKEN)


    def test_a_note_that_a_busy_lock_keeps_back_at_the_start_is_written_later(self):
        self.save("claude", session=CLAUDE_SESSION, begun=False)
        transcript = self.claude_conversation()
        fleet.save_seen("manager", (CLAUDE_SESSION, "claude", str(transcript)), {})     # an earlier run saw its file
        h = self.helper(CODEX, {}, ["> \n"])
        held = fleet.hold_manager_lock("manager")                       # `fleet.py start` holds it now
        self.assertTrue(h.manager_first())
        held.close()
        self.assertIs(json.loads(self.record("claude").read_text())["begun"], False)
        transcript.unlink()                                             # its file goes too
        self.assertFalse(h.retire_old_manager())
        self.assertIs(json.loads(self.record("claude").read_text())["begun"], True)
        self.assertFalse(self.lock_held())

    def test_a_never_begun_record_goes_at_the_start_also_while_saved_leftovers_remain(self):
        self.save("claude", session=CLAUDE_SESSION, begun=False)         # Claude wrote no conversation file
        old = {4242: f"claude --session-id {CLAUDE_SESSION}"}
        self.table = [(4242, 1, old[4242], False)]
        fleet.save_seen("manager", (CLAUDE_SESSION, "claude", ""), old)                # it had not begun
        fleet.save_closing("manager", old)                              # the helper stopped during its close
        h = self.helper(CODEX, {}, ["> \n"])
        self.assertEqual(h.manager_left, old)
        self.assertTrue(h.manager_first())
        self.assertFalse(self.record("claude").exists())
        self.assertFalse(Path(fleet.seen_file("manager")).exists())
        self.assertEqual(h.manager_left, old)                           # still ended before the start

    def test_the_never_begun_record_goes_before_the_closing_files_are_written(self):
        """A helper that stops right after the close keeps no record that would stop a later Claude start."""
        for how in ("by hand", "own close"):
            with self.subTest(how=how):
                self.save("claude", session=CLAUDE_SESSION, begun=False) # Claude wrote no conversation file
                screen = ["Do you want to proceed?\n❯ 1. Yes\n"] if how == "by hand" else ["> \n"]
                h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, screen)
                stop = SystemExit("the helper stops here")
                if how == "by hand":
                    self.assertFalse(h.retire_old_manager())            # a question: it waits, with the lock
                    self.windows.pop("manager")
                    with patch.object(fleet, "save_closing", side_effect=stop), self.assertRaises(SystemExit):
                        h.retire_old_manager()
                else:
                    h.retire_old_manager()
                    h.manager_retiring = (h.manager_retiring[0] - fleet.RETIRE_QUIET - 1, h.manager_retiring[1])
                    self.quiesce.side_effect = stop
                    with self.assertRaises(SystemExit):
                        h.retire_old_manager()
                    self.quiesce.side_effect = None
                self.assertFalse(self.record("claude").exists())
                h.manager_lock and h.manager_lock.close()
                h.manager_lock = None

    def test_a_never_begun_start_of_the_new_runtime_during_the_update_leaves_no_record(self):
        """While the old Codex helper waits for its update to Claude, the owner's `fleet.py start` starts Claude, which
        ends before it begins its conversation: its record would stop the updated helper's start."""
        self.save("claude", session=CLAUDE_SESSION, begun=False)         # Claude wrote no conversation file
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["Trust this folder?\n❯ 1. Yes\n"])
        with patch.object(fleet, "team_runtime", return_value="claude"):
            self.assertFalse(h.retire_old_manager())                    # it waits for its update, and sees it
            self.windows.pop("manager")                                 # it ends at its first question
            self.assertFalse(h.retire_old_manager())
        self.assertFalse(self.record("claude").exists())
        self.assertFalse(self.lock_held())

    def test_a_claude_start_that_never_began_does_not_stop_a_later_start(self):
        """Its record says begun: false until the helper sees its conversation file; a later start that finds no file
        then starts a new conversation, whatever timing left that record (a switch back, a restart, a busy lock)."""
        words, session, record, _ = fleet.manager_start("manager", CLAUDE, "g1", TOKEN)
        self.assertIs(record["begun"], False)
        fleet.save_chat_record("manager", record, "claude", "manager")  # Claude wrote no conversation file
        again, other, new, note = fleet.manager_start("manager", CLAUDE, "g1", TOKEN)
        self.assertEqual(note, "a new conversation: the recorded start never began one")
        self.assertNotEqual(other, session)
        self.assertNotIn("--resume", fleet.launch_words(again))
        self.assertIs(new["begun"], False)

    def test_a_conversation_that_began_is_marked_and_never_replaced_without_notice(self):
        words, session, record, _ = fleet.manager_start("manager", CLAUDE, "g1", TOKEN)
        fleet.save_chat_record("manager", record, "claude", "manager")
        h = self.helper(CLAUDE, {"manager": (session, OLD_CLAUDE)}, ["> \n"])
        self.assertFalse(h.retire_old_manager())                        # its file is not there yet
        self.assertIs(json.loads(self.record("claude").read_text())["begun"], False)
        self.claude_conversation(session)                               # its first prompt: Claude writes its file
        held = fleet.hold_manager_lock("manager")                       # a start holds the lock: a later round
        self.assertFalse(h.retire_old_manager())
        self.assertIs(json.loads(self.record("claude").read_text())["begun"], False)
        held.close()
        self.assertFalse(h.retire_old_manager())
        self.assertIs(json.loads(self.record("claude").read_text())["begun"], True)
        self.assertFalse(self.lock_held())
        Path(fleet.claude_chat_file(session)).unlink()                  # its conversation file is lost
        with self.assertRaises(fleet.Refused) as refused:
            fleet.manager_start("manager", CLAUDE, "g1", TOKEN)
        self.assertIn("is not found", str(refused.exception))


    def test_a_conversation_that_began_just_before_its_window_went_is_marked_and_kept(self):
        """Its first prompt wrote its file after the helper's last reading, and its window went before the next one:
        the record stays and is marked, so that a later start that misses that file stops."""
        self.save("claude", session=CLAUDE_SESSION, begun=False)
        h = self.helper(CLAUDE, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        self.assertFalse(h.retire_old_manager())                        # its file is not there yet
        transcript = self.claude_conversation()                         # its first prompt
        self.windows.pop("manager")                                     # and the owner closes it at once
        self.assertFalse(h.retire_old_manager())
        self.assertIs(json.loads(self.record("claude").read_text())["begun"], True)
        self.assertFalse(self.lock_held())
        transcript.unlink()
        with self.assertRaises(fleet.Refused) as refused:
            fleet.manager_start("manager", CLAUDE, "g1", TOKEN)
        self.assertIn("is not found", str(refused.exception))

    def test_a_never_begun_claude_record_goes_also_while_the_helper_waits_for_its_update(self):
        self.save("claude", session=CLAUDE_SESSION, begun=False)         # Claude wrote no conversation file
        h = self.helper(CLAUDE, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["Trust this folder?\n❯ 1. Yes\n"])
        self.assertFalse(h.retire_old_manager())                        # seen before the switch
        self.windows.pop("manager")                                     # the owner closes it during the update
        with patch.object(fleet, "team_runtime", return_value="codex"):
            self.assertFalse(h.retire_old_manager())
        self.assertFalse(self.record("claude").exists())
        self.assertFalse(self.lock_held())

    def test_a_close_needs_two_equal_quiet_readings(self):
        self.save("claude", session=CLAUDE_SESSION)
        transcript = self.claude_conversation()
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        self.assertFalse(h.retire_old_manager())                        # a first quiet reading
        h.manager_retiring = (h.manager_retiring[0] - fleet.RETIRE_QUIET - 1, h.manager_retiring[1])
        self.screen[0] = "> \nOne more line of output\n"                # its screen changed meanwhile
        self.assertFalse(h.retire_old_manager())
        h.manager_retiring = (h.manager_retiring[0] - fleet.RETIRE_QUIET - 1, h.manager_retiring[1])
        os.utime(transcript, (time.time() + 5, time.time() + 5))        # and then its conversation file
        self.assertFalse(h.retire_old_manager())
        self.assertEqual(self.killed, [])
        self.assertTrue(self.quiet_twice(h))                            # two equal readings, far enough apart

    def test_fleet_py_start_names_the_next_step_for_an_old_session_that_its_helper_does_not_close(self):
        tmux = lambda start: (lambda *a, **kw: subprocess.CompletedProcess(a, 0, f"manager\t{CLAUDE_SESSION}\t{start}\n", ""))
        with patch.object(fleet, "tmux", side_effect=tmux(OLD_CLAUDE)):
            said = fleet.adopt_manager("manager", CODEX, "fleet-manager")
        self.assertIn("not recorded or not found, so its helper does not close it. Close its window; then its helper "
                      "starts codex", said)
        self.save("claude", session=CLAUDE_SESSION)
        self.claude_conversation()
        with patch.object(fleet, "tmux", side_effect=tmux(OLD_CLAUDE)):
            self.assertIn("its helper closes it when it is quiet", fleet.adopt_manager("manager", CODEX, "fleet-manager"))

    def test_an_old_window_seen_at_the_start_keeps_its_processes_and_its_record_as_a_reading_does(self):
        self.save("claude", session=CLAUDE_SESSION, begun=False)         # Claude wrote no conversation file
        old = {4242: f"claude --resume {CLAUDE_SESSION}"}
        h = self.helper(CODEX, {"manager": (CLAUDE_SESSION, OLD_CLAUDE)}, ["> \n"])
        self.task_work.return_value, self.table = old, [(4242, 1, old[4242], False)]
        self.assertFalse(h.manager_first())
        self.windows.pop("manager")                                     # the owner closes it before the first round
        self.task_work.return_value = {}
        self.assertFalse(h.retire_old_manager())                        # its process still runs: still pending
        self.assertEqual((h.manager_left, h.other_runtime_windows()), (old, ["manager"]))
        self.assertFalse(self.record("claude").exists())                # it never began: nothing to continue
        self.table = []
        self.assertTrue(h.retire_old_manager())

    def test_the_helper_forgets_its_hand_over_only_when_the_hub_has_it(self):
        h = fleet.Helper("manager", CODEX)
        sent_one = {"claude": [7]}
        for answer, saved, kept in (((500, {}), sent_one, sent_one), ((200, {"handover_done": False}), sent_one, sent_one),
                                    ((200, {"handover_done": True}), {"claude": [7, 8]}, {"claude": [7, 8]}),   # a later
                                    ((200, {"handover_done": True}), sent_one, {})):                            # start
            with self.subTest(answer=answer, saved=saved):
                fleet.save_handover("manager", saved)
                with patch.object(fleet, "http", return_value=answer) as sent:
                    self.assertEqual(h.post_status({"revision": None, "manager_handover": sent_one}), answer)
                self.assertEqual(sent.call_args.args[:2], ("POST", "/helper/status/manager"))
                self.assertEqual(fleet.load_handover("manager"), kept)
        fleet.save_handover("manager", {"codex": list(range(fleet.HANDOVER_MAX + 10, 0, -1)) + [5]})
        self.assertEqual(fleet.load_handover("manager"), {"codex": list(range(11, fleet.HANDOVER_MAX + 11))})  # the hub's
        Path(fleet.handover_file("manager")).write_text(json.dumps(                                           # limit
            {"claude": [7, 2 ** 63, True, -1, "8"], "codex": [], "grok": [9], "x": "y"}))
        self.assertEqual(fleet.load_handover("manager"), {"claude": [7]})    # no other value is a message
        for odd in ("{not json", "[7]", "null"):
            Path(fleet.handover_file("manager")).write_text(odd)
            self.assertEqual(fleet.load_handover("manager"), {})
        self.assertEqual(fleet.HANDOVER_MAX, __import__("hub").HANDOVER_MAX)

    @staticmethod
    def read_rows(rows):
        return "".join(json.dumps(r) + "\n" for r in rows)


class Status(Base):
    def helper(self, conf, windows):
        h = fleet.Helper("manager", conf)
        h.lifecycle = Mock()
        h.lifecycle.tools_changed = False

        def tmux(*args, check=False, **kw):
            out = "".join(f"{name}\t{session}\t{start}\n" for name, (session, start) in windows.items()) \
                if args[0] == "list-windows" else ""
            return subprocess.CompletedProcess(args, 0, out, "")
        for p in (patch.object(fleet, "tmux", side_effect=tmux), patch.object(h, "look", return_value=[])):
            p.start()
            self.addCleanup(p.stop)
        return h

    def test_manager_bound_needs_the_configured_runtime_and_its_recorded_conversation(self):
        self.save("codex", marker=MARKER, session=None)
        windows = {}
        h = self.helper(CODEX, windows)
        self.assertIn("manager_switch", lifecycle.FEATURES)
        self.assertEqual(h.switch_state(), {"other_runtime_windows": [], "owner_chat_bound": None, "manager_bound": None,
                                            "manager_handover": {}})
        windows["manager"] = (MARKER, OLD_CODEX)
        self.assertIs(h.manager_bound(), True)                          # recorded, before its rollout: nothing to lose
        self.codex_rollout()
        self.assertIs(h.manager_bound(), True)
        self.save("codex", marker=MARKER, session="019a0000-7777-7222-8333-444444444444")
        self.assertIs(h.manager_bound(), False)                         # a recorded thread whose rollout is gone
        self.save("codex", marker=MARKER, session=None)
        windows["manager"] = (CLAUDE_SESSION, OLD_CODEX)                # a session that its record does not name
        self.assertIs(h.manager_bound(), False)
        windows["manager"] = (MARKER, OLD_CLAUDE)                       # another runtime
        self.assertIs(h.manager_bound(), False)
        worker = fleet.Helper("vps", dict(CODEX, role="worker"))
        with patch.object(worker, "look", return_value=[]):
            self.assertEqual(worker.switch_state(), {"other_runtime_windows": [], "owner_chat_bound": None})

    def test_the_helper_reports_at_once_when_its_manager_session_changes(self):
        self.save("codex", marker=MARKER, session=None)
        windows = {}
        h = self.helper(CODEX, windows)
        h.lifecycle.report.return_value = True
        for change, reports in ((None, 1), (None, 1), ((MARKER, OLD_CODEX), 2), ("rollout", 2),
                                ((CLAUDE_SESSION, OLD_CODEX), 3), ((CLAUDE_SESSION, OLD_CODEX), 3)):
            if change == "rollout":
                self.codex_rollout()                                    # it began its conversation: still bound
            elif change:
                windows["manager"] = change                             # whoever started it
            h.report_manager_bound()
            self.assertEqual(h.lifecycle.report.call_count, reports)
        h.lifecycle.report.return_value = False                         # the hub did not take it: it goes again,
        windows.pop("manager")                                          # but not in each round of the helper:
        h.report_manager_bound()                                        # each report runs every status command
        h.report_manager_bound()
        self.assertEqual(h.lifecycle.report.call_count, 4)
        h.manager_report_failed -= 31                                   # 30 seconds later
        h.lifecycle.report.return_value = True
        h.report_manager_bound()
        h.report_manager_bound()
        self.assertEqual(h.lifecycle.report.call_count, 5)

    def test_only_the_configured_runtime_reports_the_manager_usage_limit(self):
        """A usage limit of a previous runtime's session never holds the new runtime: the helper reads the records of the
        window's session with its own runtime, and a Codex session is found by its marker."""
        limit = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()), "type": "event_msg",
                 "payload": {"type": "error", "message": "You've hit your usage limit.", "codex_error_info": "usage_limit"}}
        self.codex_rollout(rows=[limit])
        for session, posts in ((CLAUDE_SESSION, []), (MARKER, ["/helper/limit/manager"])):
            with self.subTest(session=session):
                h, posted = fleet.Helper("manager", CODEX), []
                with patch.object(fleet, "tmux", return_value=subprocess.CompletedProcess([], 0, f"manager\t{session}\n", "")), \
                        patch.object(fleet, "http", side_effect=lambda *a, **kw: posted.append(a[1]) or (200, {})), \
                        patch.object(h, "say"):
                    Tailer("codex", h.manager_windows, h.report_limit, home=str(self.tmp), kit=fleet.KIT).scan()
                self.assertEqual(posted, posts)


if __name__ == "__main__":
    unittest.main()

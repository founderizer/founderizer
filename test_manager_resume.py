"""The standing manager session continues its recorded Claude conversation: both starts (the helper's own and
`fleet.py start`) take one decision, a restart resumes the recorded session with the settings of a new start and no
first prompt, a session that runs is recorded only with its conversation file, and a record whose conversation is not
found stops the start and stays. Temporary folders and stand-in hub, tmux and window answers: no AI call, no real
runtime, no real session."""
import contextlib
import fcntl
import io
import json
import os
import re
import shlex
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import fleet

MANAGER = {"role": "manager", "runtime": "claude", "machine": "vps", "can": ["shell"],
           "start": "claude --permission-mode dontAsk {settings} {prompt}", "allow": ["mcp__fleet__*"],
           "model": "claude-sonnet-5-5"}
CODEX = dict(MANAGER, runtime="codex", start="codex --sandbox danger-full-access --ask-for-approval never {prompt}", model=None)
SESSION = "11111111-2222-4333-8444-555555555555"
OTHER = "99999999-8888-4777-8666-555555555555"
TOKEN = "standing-credential-" + "s" * 24
PROMPT = fleet.MANAGER_START.format(agent="manager", resume=fleet.MANAGER_COLD)


class ManagerResume(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-manager-"))
        self.home, self.said = self.tmp / ".fleet", []
        for p in (patch.object(fleet, "HOME", str(self.home)), patch.object(fleet, "SESSIONS", str(self.home / "sessions")),
                  patch.object(fleet, "HUB", "http://hub:8765"),
                  patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.tmp / ".claude")}),
                  # the credential's file: one path for each call, so that two commands can be compared
                  patch.object(fleet, "mcp_config_file", side_effect=lambda agent, window, url, token, servers=None:
                               self.said.append(("mcp", agent, window, url, token)) or "/sessions/manager.json"),
                  # team.json of this checkout gives the helper's own runtime: its update is loaded (Helper.outdated)
                  patch.object(fleet, "team_runtime", return_value=None),
                  # no hub answers here, so a cold start's prompt is the one a hub that gives no brief leaves
                  patch.object(fleet, "manager_resume", return_value=fleet.MANAGER_COLD)):
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.tmp)])
        self.record = Path(fleet.chat_record_file("manager", "claude", "manager"))

    def conversation(self, session=SESSION):
        """A stand-in conversation file where Claude Code keeps this checkout's sessions."""
        folder = self.tmp / ".claude" / "projects" / re.sub(r"[^A-Za-z0-9-]", "-", os.path.realpath(fleet.KIT))
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"{session}.jsonl").write_text("{}\n")

    def save(self, generation="g1", session=SESSION):
        fleet.save_chat_record("manager", {"generation": generation, "session": session, "started": 1.0}, "claude", "manager")
        return self.record.read_bytes()

    def words(self, conf=MANAGER, generation="g1"):
        command, session, record, note = fleet.manager_start("manager", conf, generation, TOKEN)
        return shlex.split(command), session, record, note

    def test_a_first_start_is_a_new_conversation_with_the_first_prompt_and_its_record(self):
        words, session, record, note = self.words()
        self.assertEqual(words[words.index("--session-id") + 1], session)
        self.assertEqual(words[-1], PROMPT)
        self.assertNotIn("--resume", words)
        self.assertEqual((record["generation"], record["session"], note), ("g1", session, ""))
        self.assertFalse(self.record.exists())                          # saved by the start, when its window runs

    def test_a_restart_continues_the_recorded_conversation_with_the_same_settings_and_no_prompt(self):
        fresh, new, _, _ = self.words()
        saved = self.save()
        self.conversation()
        again, session, record, note = self.words()
        self.assertEqual((session, record, note), (SESSION, None, "it continues its recorded conversation"))
        self.assertEqual(again[again.index("--resume") + 1], SESSION)
        for word in ("--session-id", "--fork-session", PROMPT):
            self.assertNotIn(word, again)
        # everything else is the command of a new start: permissions, settings, model, MCP configuration, credential
        self.assertEqual([w for w in again if w not in ("--resume", SESSION)],
                         [w for w in fresh if w not in ("--session-id", new, PROMPT)])
        self.assertEqual(self.said, [("mcp", "manager", "manager", "http://hub:8765/mcp/manager", TOKEN)] * 2)
        self.assertEqual(self.record.read_bytes(), saved)               # a continued conversation keeps its record

    def test_a_conversation_whose_start_text_changed_is_not_continued(self):
        """A conversation that continues keeps the rules and the profile that it began with (fleet.standing_text), so
        a manager whose rules changed in a release ran the old ones for as long as its conversation went on. The
        record of a new conversation keeps a hash of its start text, and a start after a change begins a new one."""
        _, session, record, _ = self.words()
        self.assertEqual(record["text"], fleet.standing_text("manager", record["rules"], fleet.MANAGER_START))
        self.assertNotEqual(record["text"], fleet.standing_text("manager", record["rules"]))    # its first prompt's
        fleet.save_chat_record("manager", record, "claude", "manager")
        self.conversation(session)
        again, continued, keep, note = self.words()                     # nothing changed: it continues
        self.assertEqual((again[again.index("--resume") + 1], continued, note),
                         (session, session, "it continues its recorded conversation"))
        helper = fleet.Helper("manager", MANAGER)
        self.assertEqual(helper.manager_text_changed(), "")
        with patch.object(fleet, "standing_text", return_value="another-text"):     # a release changed its rules
            self.assertEqual(helper.manager_text_changed(), "its rules or its profile changed")
            words, new, kept, note = self.words()
        self.assertNotIn("--resume", words)
        self.assertEqual((words[words.index("--session-id") + 1], words[-1]), (new, PROMPT))
        self.assertNotEqual(new, session)
        self.assertEqual((kept["session"], kept["text"]), (new, "another-text"))
        self.assertIn("its rules or its profile are not the ones that it began with", note)
        # a record from before the helper kept the text: a start continues it, and the helper's round leaves it one
        # time, because nothing says which tool definitions that conversation has
        self.save()
        self.conversation()
        self.assertEqual(self.words()[3], "it continues its recorded conversation")
        self.assertEqual(helper.manager_text_changed(), "its record does not say what it began with")
        self.record.unlink()
        self.assertEqual(helper.manager_text_changed(), "")             # no record: nothing to leave
        self.record.write_text("not a record")
        self.assertEqual(helper.manager_text_changed(), "")             # one that cannot be read stays (manager_start)

    def test_a_record_whose_conversation_is_not_found_stops_the_start_and_stays(self):
        saved = self.save()
        with self.assertRaises(fleet.Refused) as refused:
            self.words()
        text = str(refused.exception)
        for part in (SESSION, str(self.record), "Nothing starts and the record stays"):
            self.assertIn(part, text)
        self.assertEqual(self.record.read_bytes(), saved)
        helper, started = fleet.Helper("manager", MANAGER), []
        with patch.object(fleet, "windows", return_value=[]), patch.object(fleet, "manager_generation", return_value="g1"), \
                patch.object(fleet, "manager_credential", return_value=TOKEN), patch.object(helper, "say") as say, \
                patch.object(helper, "start", side_effect=lambda *a, **kw: started.append(a)), \
                patch.object(fleet, "start_window", side_effect=lambda *a: started.append(a)), \
                patch.object(fleet, "agent_conf", return_value=MANAGER), patch.object(fleet, "ensure_session"), \
                patch.object(fleet, "claim_checkout"), patch.object(fleet, "tmux"), \
                contextlib.redirect_stderr(io.StringIO()) as shown:
            self.assertTrue(helper.start_manager())                     # it must still start
            self.assertTrue(helper.start_manager())                     # the same words are said once
            with self.assertRaises(SystemExit) as stopped:
                fleet.cmd_start(types.SimpleNamespace(agent="manager"))
        self.assertEqual((started, say.call_count), ([], 1))
        self.assertEqual(say.call_args.args[0], "manager: the session does not start: " + text)
        self.assertEqual((stopped.exception.code, shown.getvalue()), (1, f"fleet: {text}\n"))
        self.assertEqual(self.record.read_bytes(), saved)
        self.assertNotIn(TOKEN, text)
        self.assertNotIn(PROMPT[:40], text)

    def test_a_record_that_cannot_be_read_or_is_not_valid_stops_the_start_and_stays(self):
        self.home.mkdir(mode=0o700)
        for content, why in (("not json", "cannot be read"), ('["g1"]', "is not valid"), ('{"session": "' + SESSION + '"}', "is not valid"),
                             (json.dumps({"generation": "g1", "session": "../" + SESSION}), "is not valid"),
                             (json.dumps({"generation": "g1"}), "is not valid")):
            self.record.write_text(content)
            self.conversation()
            with self.assertRaises(fleet.Refused) as refused:
                self.words()
            self.assertEqual(str(refused.exception), f"the manager session record {self.record} {why}")
            self.assertEqual(self.record.read_text(), content)

    def test_a_record_of_another_database_starts_a_new_conversation_and_says_so(self):
        self.save(generation="g0")
        self.conversation()
        words, session, record, note = self.words(generation="g1")
        self.assertNotEqual(session, SESSION)
        self.assertEqual((words[-1], record["generation"]), (PROMPT, "g1"))
        self.assertNotIn("--resume", words)
        self.assertEqual(note, "a new conversation: the recorded one is of another hub database")

    def test_a_codex_manager_starts_its_own_recorded_conversation_and_leaves_the_claude_record(self):
        saved = self.save()                                             # a Claude record is not this runtime's
        self.conversation()
        words, session, record, note = self.words(CODEX)
        self.assertEqual(words[-1], PROMPT + "\n\n" + fleet.MARKER.format(session))     # its rollout carries the marker
        self.assertEqual((record["generation"], record["marker"], record["session"], note), ("g1", session, None, ""))
        self.assertNotIn("resume", words)
        self.assertNotIn(SESSION, words)
        self.assertEqual(self.record.read_bytes(), saved)
        with self.assertRaises(fleet.Refused):                          # a task session never continues one
            fleet.session_command("manager", MANAGER, PROMPT, task="T-7", generation="g", session=SESSION, resume=True)
        with self.assertRaises(fleet.Refused):                          # nor another runtime's standing session
            fleet.session_command("manager", dict(CODEX, runtime="grok"), PROMPT, session=SESSION, resume=True)

    def test_both_starts_take_the_same_decision_and_save_a_new_conversation(self):
        def run(resume):
            helper, seen = fleet.Helper("manager", MANAGER), {}
            listing = subprocess.CompletedProcess([], 0, "", "")
            with patch.object(fleet, "windows", return_value=[]), patch.object(fleet, "manager_generation", return_value="g1"), \
                    patch.object(fleet, "manager_credential", return_value=TOKEN) as credential, patch.object(helper, "say") as say, \
                    patch.object(helper, "start", side_effect=lambda name, command, **kw: seen.update(helper=(name, command, kw))), \
                    patch.object(fleet, "start_window", side_effect=lambda session, name, command, options=None:
                                 seen.update(cli=(name, command, options))), \
                    patch.object(fleet, "agent_conf", return_value=MANAGER), patch.object(fleet, "ensure_session"), \
                    patch.object(fleet, "claim_checkout"), patch.object(fleet, "tmux", return_value=listing) as tmux, \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertFalse(helper.start_manager())
                first = self.record.read_bytes()
                if not resume:
                    self.record.unlink()                                # the explicit start, as a first start too
                fleet.cmd_start(types.SimpleNamespace(agent="manager"))
            self.assertEqual(credential.call_args_list[0].args, ("manager", "g1"))
            return seen, first, seen["cli"][2], say.call_args.args[0], out.getvalue()

        seen, first, option, said, printed = run(resume=False)
        (name, command, kw), (cli_name, cli_command, _) = seen["helper"], seen["cli"]
        new, cli_new = kw["session"], option["@fleet_session"]       # set with the window's start
        self.assertEqual((name, cli_name, list(option)), ("manager", "manager", ["@fleet_session"]))
        self.assertEqual(command.replace(new, "ID"), cli_command.replace(cli_new, "ID"))      # but for the new id
        self.assertEqual(json.loads(first)["session"], new)
        self.assertEqual(json.loads(self.record.read_bytes())["session"], cli_new)
        self.assertEqual(said, "manager: session started")
        self.conversation(cli_new)
        seen, first, option, said, printed = run(resume=True)
        self.assertEqual(seen["helper"][1], seen["cli"][1])             # the same command
        self.assertIn(f"--resume {cli_new} ", seen["cli"][1])
        self.assertEqual((seen["helper"][2]["session"], option["@fleet_session"]), (cli_new, cli_new))
        self.assertEqual(json.loads(first)["session"], cli_new)
        self.assertEqual(said, "manager: session started (it continues its recorded conversation)")
        for text in (said, printed):
            self.assertNotIn(TOKEN, text)
            self.assertNotIn(PROMPT[:40], text)

    def test_a_session_that_runs_is_recorded_only_with_its_conversation_and_nothing_else_changes(self):
        calls = []

        def tmux(*args, **kw):
            calls.append(args)
            return subprocess.CompletedProcess([], 0, f"home\t\nmanager\t{self.running}\n", "")

        def adopt():
            return fleet.adopt_manager("manager", MANAGER, "fleet-manager")
        self.running = SESSION
        with patch.object(fleet, "tmux", side_effect=tmux), patch.object(fleet, "manager_generation", return_value="g1"):
            with self.assertRaises(fleet.Refused) as refused:           # no conversation file: nothing is recorded
                adopt()
            self.assertIn(f"the conversation {SESSION} of the manager session that runs is not found", str(refused.exception))
            self.assertFalse(self.record.exists())
            self.conversation()
            self.assertEqual(adopt(), f"recorded its conversation {SESSION} in {self.record}: the next start continues it")
            record = json.loads(self.record.read_text())
            # the owner names it as the one to continue: its record takes the start text of now, so the helper's
            # round does not leave it for a new one
            self.assertEqual(record["text"], fleet.standing_text("manager", None, fleet.MANAGER_START))
            self.assertEqual(fleet.Helper("manager", MANAGER).manager_text_changed(), "")
            self.assertEqual((record["generation"], record["session"], record["adopted"]), ("g1", SESSION, True))
            self.assertEqual(os.stat(self.record).st_mode & 0o777, 0o600)
            saved = self.record.read_bytes()
            self.assertEqual(adopt(), f"its conversation {SESSION} is recorded: the next start continues it")
            self.assertEqual(self.record.read_bytes(), saved)           # a record that says what it began with stays
            self.record.write_text(json.dumps({k: v for k, v in record.items() if k not in ("text", "rules")}))
            self.assertEqual(adopt(), f"its conversation {SESSION} is recorded: the next start continues it")
            self.assertEqual(json.loads(self.record.read_text())["text"], record["text"])    # one from before: named now
            saved = self.record.read_bytes()
            self.running = OTHER                                        # the record names another conversation
            self.conversation(OTHER)
            with self.assertRaises(fleet.Refused) as refused:
                adopt()
            self.assertIn("Nothing changed", str(refused.exception))
            self.running = ""                                           # a window from before session ids
            self.record.unlink()
            with self.assertRaises(fleet.Refused):
                adopt()
            self.assertFalse(self.record.exists())
            self.assertEqual(fleet.adopt_manager("manager", CODEX, "fleet-manager"),
                             "its conversation is not recorded this way: a Codex manager records its conversation when "
                             "it starts")
        self.assertTrue(saved)
        self.assertEqual({args[0] for args in calls}, {"list-windows"})  # it only reads the window list
        # the recorded session is the one that the next start continues
        self.save()
        self.assertEqual(self.words()[1], SESSION)

    def test_the_explicit_start_records_a_session_that_runs_and_starts_nothing(self):
        self.conversation()
        listing = subprocess.CompletedProcess([], 0, f"manager\t{SESSION}\n", "")
        with patch.object(fleet, "agent_conf", return_value=MANAGER), patch.object(fleet, "ensure_session"), \
                patch.object(fleet, "windows", return_value=["home", "manager"]), patch.object(fleet, "claim_checkout"), \
                patch.object(fleet, "manager_generation", return_value="g1"), patch.object(fleet, "manager_credential") as credential, \
                patch.object(fleet, "tmux", return_value=listing) as tmux, patch.object(fleet, "start_window") as start, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            fleet.cmd_start(types.SimpleNamespace(agent="manager"))
        self.assertEqual(out.getvalue(), "the manager session is already running\n"
                         f"recorded its conversation {SESSION} in {self.record}: the next start continues it\n")
        self.assertEqual((start.call_count, credential.call_count), (0, 0))
        self.assertEqual([call.args[0] for call in tmux.call_args_list], ["list-windows"])
        self.assertEqual(json.loads(self.record.read_text())["session"], SESSION)

    def test_the_generation_comes_from_the_hub_only_for_an_agent_with_a_key(self):
        with patch.object(fleet, "load_agent_key", return_value=None), patch.object(fleet, "http") as http, \
                patch.object(fleet, "session_credential") as credential:
            self.assertEqual(fleet.manager_generation("manager"), "")   # as before: no question to the hub
            self.assertIsNone(fleet.manager_credential("manager"))
            self.assertEqual((http.call_count, credential.call_count), (0, 0))
        with patch.object(fleet, "load_agent_key", return_value="key"), \
                patch.object(fleet, "http", side_effect=[(200, {"db": "g1"}), (503, {}), (200, {"db": "g1"})]), \
                patch.object(fleet, "session_credential", return_value=TOKEN) as credential:
            self.assertEqual(fleet.manager_generation("manager"), "g1")
            with self.assertRaises(fleet.Refused):
                fleet.manager_generation("manager")
            self.assertEqual(fleet.manager_credential("manager", "g1"), TOKEN)   # no second question for it
            self.assertEqual(fleet.manager_credential("manager"), TOKEN)
            self.assertEqual([call.args for call in credential.call_args_list], [("manager", "standing", "g1")] * 2)

    def test_a_concurrent_start_holds_both_entry_points_before_credentials_or_records(self):
        self.home.mkdir()
        helper = fleet.Helper("manager", MANAGER)
        with open(self.home / "manager-manager.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(fleet, "windows", return_value=[]), \
                    patch.object(fleet, "agent_conf", return_value=MANAGER), patch.object(fleet, "ensure_session"), \
                    patch.object(fleet, "claim_checkout"), patch.object(fleet, "manager_generation", return_value="g1"), \
                    patch.object(fleet, "manager_credential", return_value=TOKEN) as credential, \
                    patch.object(helper, "start") as start, patch.object(helper, "say"), \
                    patch.object(fleet, "start_window") as cli_start, patch.object(fleet, "tmux"), \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertTrue(helper.start_manager())
                with self.assertRaises(SystemExit) as stopped:
                    fleet.cmd_start(types.SimpleNamespace(agent="manager"))
            self.assertEqual(stopped.exception.code, 1)
            self.assertIn("another start of the manager session", err.getvalue())
            self.assertEqual((credential.call_count, start.call_count, cli_start.call_count), (0, 0, 0))
            self.assertFalse(self.record.exists())

    def test_an_unknown_window_read_starts_nothing_through_either_entry_point(self):
        helper = fleet.Helper("manager", MANAGER)
        for status in (124, 1):
            with self.subTest(status=status), \
                    patch.object(fleet, "tmux", return_value=subprocess.CompletedProcess([], status, "", "unavailable")), \
                    patch.object(fleet, "agent_conf", return_value=MANAGER), patch.object(fleet, "ensure_session"), \
                    patch.object(fleet, "claim_checkout"), patch.object(fleet, "manager_generation", return_value="g1"), \
                    patch.object(fleet, "manager_credential", return_value=TOKEN) as credential, \
                    patch.object(helper, "start") as start, patch.object(helper, "say"), \
                    patch.object(fleet, "start_window") as cli_start, contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertTrue(helper.start_manager())
                with self.assertRaises(SystemExit) as stopped:
                    fleet.cmd_start(types.SimpleNamespace(agent="manager"))
                self.assertEqual(stopped.exception.code, 1)
                self.assertIn("cannot read windows", err.getvalue())
                self.assertEqual((credential.call_count, start.call_count, cli_start.call_count), (0, 0, 0))
                self.assertFalse(self.record.exists())
        # A later good reading of the existing session must not retry the start.
        with patch.object(fleet, "tmux", return_value=subprocess.CompletedProcess([], 0, "manager\n", "")), \
                patch.object(fleet, "manager_credential") as credential, patch.object(helper, "start") as start:
            self.assertFalse(helper.start_manager())
        self.assertEqual((credential.call_count, start.call_count), (0, 0))

    def test_the_start_lock_is_released_after_failures_in_either_entry_point(self):
        helper = fleet.Helper("manager", MANAGER)
        for entry in ("helper", "command"):
            for failure in ("credential", "conversation", "window", "record"):
                with self.subTest(entry=entry, failure=failure):
                    if self.record.exists():
                        self.record.unlink()
                    if failure == "conversation":
                        self.save()     # its conversation file is missing; keep the record as it is
                    before = self.record.read_bytes() if self.record.exists() else None
                    with patch.object(fleet, "windows", return_value=[]), \
                            patch.object(fleet, "agent_conf", return_value=MANAGER), patch.object(fleet, "ensure_session"), \
                            patch.object(fleet, "claim_checkout"), patch.object(fleet, "tmux"), \
                            patch.object(fleet, "manager_generation", return_value="g1"), \
                            patch.object(fleet, "manager_credential", side_effect=fleet.Refused("fixture credential")
                                         if failure == "credential" else None, return_value=TOKEN), \
                            patch.object(helper, "start", side_effect=OSError("fixture window") if failure == "window" else None), \
                            patch.object(fleet, "start_window", side_effect=OSError("fixture window") if failure == "window" else None), \
                            (patch.object(fleet, "save_chat_record", side_effect=OSError("fixture record"))
                             if failure == "record" else contextlib.nullcontext()), \
                            patch.object(helper, "say"), contextlib.redirect_stderr(io.StringIO()):
                        call = helper.start_manager if entry == "helper" else lambda: fleet.cmd_start(types.SimpleNamespace(agent="manager"))
                        if failure in ("window", "record"):
                            with self.assertRaisesRegex(OSError, f"fixture {failure}"):
                                call()
                        elif entry == "helper":
                            self.assertTrue(call())
                        else:
                            with self.assertRaises(SystemExit):
                                call()
                    with open(self.home / "manager-manager.lock", "a") as lock:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    if failure == "window":     # saved before its start: a start that never began, replaced next time
                        self.assertIs(json.loads(self.record.read_bytes())["begun"], False)
                    else:
                        self.assertEqual(self.record.read_bytes() if self.record.exists() else None, before)


if __name__ == "__main__":
    unittest.main()

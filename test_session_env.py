"""Owner feature secrets, the helper side: session_env gives each session start the API keys that its agent may read,
from the machine's vault broker, and the session gets them through the mode-600 file that its window reads and
removes. Stand-in vault answers and tmux; no real token or value."""
import io
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import fleet
from leftovers import scratch_home

KEY = "bws://21111111-2222-4333-8444-55555555555b"
VALUE = "sk-fake-only-key-20261014"
CLAUDE = {"role": "worker", "runtime": "claude", "machine": "box", "can": ["shell"], "vault": "broker",
          "start": "claude --permission-mode dontAsk {chrome} {settings} {prompt}"}
CODEX = {"role": "worker", "runtime": "codex", "machine": "box", "can": ["shell"], "vault": "broker",
         "start": "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"}
TEAM = {"agents": {
    "alpha": dict(CLAUDE, secrets={KEY: "read"}), "beta": dict(CODEX, secrets={KEY: "use"}),
    # "vault": "file" is said here: file mode, which read a Bitwarden token of this user, is gone, so it is no
    # credential access, as an entry that says nothing is (PRODUCT.md P5)
    "filer": {"role": "worker", "runtime": "codex", "machine": "files", "can": ["shell"], "vault": "file",
              "secrets": {KEY: "read"}},
    "manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": [],
                "start": "claude --permission-mode bypassPermissions --tools default {settings} {prompt}", "secrets": {KEY: "read"}}}}


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(SessionEnv(n) for n in SessionEnv.__dict__ if n.startswith("test_"))


class Checkout(unittest.TestCase):
    """A helper whose checkout is a temporary folder with its own team.json."""
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix="fleet-env-"))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.folder)])
        self.home, self.kit = self.folder / ".fleet", self.folder / "kit"
        (self.kit / "profiles").mkdir(parents=True)
        (self.kit / "team.json").write_text(json.dumps(TEAM))
        (self.kit / "profiles" / "alpha.md").write_text("# Profile: alpha\n")
        for p in (patch.object(fleet, "HOME", str(self.home)), patch.object(fleet, "SESSIONS", str(self.home / "sessions")),
                  patch.object(fleet, "KIT", str(self.kit)), patch.object(fleet, "TEAM", json.loads(json.dumps(TEAM))),
                  patch.object(fleet, "HUB", "http://hub:8765"), patch.object(fleet, "AGENT", None),
                  patch.object(fleet, "team_runtime", return_value=None)):
            p.start()
            self.addCleanup(p.stop)

    def env_file(self, command):
        words = shlex.split(command)
        self.assertEqual((words[0], words[2:5], words[6:8]), (".", ["&&", "rm", "-f"], ["&&", "exec"]), command)
        path = Path(words[1])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        return path


class SessionEnv(Checkout):
    def test_only_an_agent_with_a_read_grant_asks_its_vault_and_only_good_names_come_through(self):
        with patch.object(fleet, "broker_job_request", side_effect=AssertionError("asked")), \
                patch.object(fleet, "http", side_effect=AssertionError("asked")):
            self.assertEqual(fleet.session_env("beta", CODEX, "task"), {})          # use only: nothing to read
            fleet.TEAM["agents"]["alpha"]["vault"] = "none"
            self.assertEqual(fleet.session_env("alpha", CLAUDE, "task"), {})        # no credential access
            fleet.TEAM["agents"]["alpha"]["vault"] = "broker"
        given = {"ok": True, "v": 2, "missing": ["GONE_KEY"],
                 "env": {"OPENAI_API_KEY": VALUE, "FLEET_SESSION_TOKEN": "x" * 43, "PATH": "/tmp", "lower": "x", "EMPTY": ""}}
        printed = io.StringIO()
        with patch.object(fleet, "broker_job_request", return_value=given) as vault, patch("sys.stdout", printed):
            self.assertEqual(fleet.session_env("alpha", CLAUDE, "task"), {"OPENAI_API_KEY": VALUE})
        vault.assert_called_once_with("alpha", {"op": "read", "for": "session"}, timeout=60)   # support plan F1
        self.assertIn("task: the vault did not give GONE_KEY", printed.getvalue())
        self.assertNotIn(VALUE, printed.getvalue())
        printed = io.StringIO()
        with patch.object(fleet, "broker_job_request", side_effect=fleet.Refused("the vault broker refused: no")), \
                patch("sys.stdout", printed):
            self.assertEqual(fleet.session_env("alpha", CLAUDE, "chat"), {})      # the session starts without them
        self.assertIn("chat: the session starts without its read variables: the vault broker refused: no",
                      printed.getvalue())

    def test_an_agent_that_still_says_file_reads_nothing_and_asks_nothing(self):
        """File mode read the value with this helper's own Bitwarden token. It is gone: such an agent has no
        credential access, so its sessions start with no key, also with a read grant, and nothing is asked."""
        with patch.object(fleet, "broker_job_request", side_effect=AssertionError("asked")), \
                patch.object(fleet, "http", side_effect=AssertionError("asked")):
            for kind in ("task", "check", "chat"):
                self.assertEqual(fleet.session_env("filer", TEAM["agents"]["filer"], kind), {}, kind)
        self.assertFalse(hasattr(fleet, "read_values"))

    def test_every_session_start_gets_the_values_from_a_file_that_its_window_reads_and_removes(self):
        env, token = {"OPENAI_API_KEY": VALUE}, "s" * 43
        commands = {
            "codex task": fleet.session_command("beta", CODEX, "Go.", task="T-4", generation="g", session="s", token=token,
                                                env=env),
            "claude task": fleet.session_command("alpha", CLAUDE, "Go.", task="T-3", generation="g", session="s",
                                                 token=token, env=env),
            "codex chat": fleet.chat_command("alpha", CODEX, "g", token=token, env=env),
            "claude chat": fleet.chat_command("alpha", CLAUDE, "g", token=token, env=env)}
        with patch.object(fleet, "session_env", return_value=env) as hook:
            commands["manager"] = fleet.manager_start("manager", TEAM["agents"]["manager"], "g", token)[0]
        hook.assert_called_once_with("manager", TEAM["agents"]["manager"], "manager")
        for name, command in commands.items():
            with self.subTest(name):
                self.assertNotIn(VALUE, command)
                text = self.env_file(command).read_text()
                self.assertIn(f"export OPENAI_API_KEY={VALUE}\n", text)
                self.assertEqual("FLEET_SESSION_TOKEN" in text, name.startswith("codex"))   # Claude's is in its config
                self.assertIn(fleet.launch_words(command)[0], ("claude", "codex"))
        for name in ("codex task", "codex chat"):       # Codex hides *KEY* names from its commands: this one goes through
            words = shlex.split(commands[name])
            self.assertIn("shell_environment_policy.ignore_default_excludes=true", words)
            hidden = json.loads(next(w for w in words if w.startswith("shell_environment_policy.exclude="))[33:])
            self.assertIn("FLEET_SESSION_TOKEN", hidden)
            self.assertNotIn("OPENAI_API_KEY", hidden)
        plain = fleet.session_command("beta", CODEX, "Go.", task="T-4", generation="g", session="s")
        self.assertNotIn("shell_environment_policy", plain)            # without values: the start of before
        self.assertTrue(plain.startswith("env FLEET_ATTEMPT="))

    def test_the_window_shell_exports_the_values_and_removes_the_file_before_the_program_starts(self):
        prefix = fleet.env_prefix("alpha", "T-3", {"OPENAI_API_KEY": VALUE, "QUOTED_KEY": "a'b \"c\" $d\nline"})
        path = self.env_file(prefix + "true")
        out = subprocess.run(["sh", "-c", prefix + "sh -c 'printf %s \"$OPENAI_API_KEY|$QUOTED_KEY\"'"],
                             capture_output=True, text=True, check=True).stdout
        self.assertEqual(out, VALUE + "|a'b \"c\" $d\nline")
        self.assertFalse(path.exists())
        self.assertEqual(fleet.env_prefix("alpha", "T-3", {}), "")

    def test_the_task_and_chat_starts_of_the_helper_use_the_hook(self):
        helper = fleet.Helper("alpha", CLAUDE)
        helper.sync_checkout, helper.say = (lambda: None), (lambda text: None)
        started = []
        with patch.object(fleet, "tmux", lambda *a, **k: subprocess.CompletedProcess(a, 0, "", "")), \
                patch.object(fleet, "start_window", lambda session, name, command, options=None: started.append(command)), \
                patch.object(fleet, "session_credential", return_value=None), \
                patch.object(fleet, "session_env", return_value={"OPENAI_API_KEY": VALUE}) as hook:
            helper.handle({"id": 1, "kind": "task", "task": "T-7", "text": "Do T-7.",
                           "extra": {"needs": "none", "attempt": 1, "generation": "0123456789ab"}})
            helper.handle({"id": 2, "kind": "chat", "extra": {"generation": "g"}})
        # a task session works in its own clones (4 November 2026), which the hook gets as its place
        self.assertEqual([c.args for c in hook.call_args_list],
                         [("alpha", CLAUDE, "task", fleet.task_place("alpha", "0123456789ab", "T-7")),
                          ("alpha", CLAUDE, "chat")])
        self.assertEqual(len(started), 2)
        for command in started:
            self.assertIn(f"export OPENAI_API_KEY={VALUE}", self.env_file(command).read_text())


if __name__ == "__main__":
    unittest.main()

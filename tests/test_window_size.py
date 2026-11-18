"""Every window command that the helper builds stays far under what tmux takes, whatever the size of the data that the
session gets. tmux 3.6 refuses a command over about 16 KiB with "command too long": on 16 November 2026 the hub's brief
made the standing session's start command 16,419 bytes, and every start of it failed for 44 minutes (e749f6071 gave
that brief its own file). Each other part of a command that grows with the fleet comes from a mode-600 file now
(fleet.ARG_MOST says which): a task's text with the list of its repositories, a runner's prompt, a Codex task's MCP
servers, an owner chat's profile and recap, a closed session's settings with its host list.

Each test builds one command with data of several times 16 KiB, with quotes, $, backticks and $(...), and checks that
the command stays under 8 KiB. Then each shell that tmux may run it in (sh, bash, dash and zsh, as this machine has
them) runs it, with a stand-in program that keeps the arguments it was given: the program gets the data whole, the
shell ran no word of it, and each file that the shell reads is gone. A first prompt longer than one argument takes
reaches the program with its start and its end, and a line in place of its middle (fleet.fit_prompt). And only the
file of a session credential counts as one (fleet.holds_credential). No AI, no network, no tmux."""
import contextlib
import io
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import fleet
import lifecycle
import screen_runner
from leftovers import ROOT, removed_when_gone, scratch_home

AGENT = "dev-lead"
SESSION = "11111111-2222-4333-8444-555555555555"
TOKEN = "session-credential-for-tests-" + "t" * 16
LIMIT = 8192            # bytes of a window command here: half of what tmux takes
DATA = 3 * 16384        # bytes of each text that grows with the fleet
CLAUDE = {"role": "worker", "runtime": "claude", "machine": "box", "can": ["shell", "browser", "web"],
          "start": "claude --permission-mode dontAsk {chrome} {settings} {prompt}", "allow": ["mcp__fleet__*"]}
CODEX = {"role": "worker", "runtime": "codex", "machine": "box", "can": ["shell"],
         "start": "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"}
RUNNER = dict(CODEX, start=lifecycle.APP_SERVER)        # its tasks run in screen_runner.py
MANAGER = dict(CLAUDE, role="manager", start="claude --permission-mode bypassPermissions --tools default {settings} "
                                              "{prompt}")
CODEX_MANAGER = dict(CODEX, role="manager")
# The most catalog servers that team.json holds, each with the longest name, and the most plain settings of the most
# characters that a program server takes: no $ and no control character (lifecycle.plain_value), and every other
# character that a shell reads in its own way
SETTING = "\"quoted\" 'single' `true` ; exit 3 && (x) | y < z > w \\ * ? ~ # ! "
SERVERS = {f"server-{i:02d}-" + "x" * 21: {
    "title": f"Example server {i}", "command": "example-mcp",
    "settings": {f"EXAMPLE_SETTING_{j:02d}": (SETTING * 9)[:lifecycle.MCP_SETTING_MOST - 2] + f"{j:02d}"
                 for j in range(lifecycle.MCP_SETTINGS_MOST)}} for i in range(lifecycle.MCP_LIMIT)}
# 500 repositories, the most that one agent holds (hub.REPOS_MOST), with names of 100 characters
REPOS = " ".join(f"acme/repository-{i:03d}-" + "r" * 81 + ":" + ("write", "read", "deploy")[i % 3] for i in range(500))
# Each shell that tmux may run a window's command in: the login shell, zsh on a Mac and bash or dash on a server
SHELLS = [found for found in map(shutil.which, ("sh", "bash", "dash", "zsh")) if found]
STANDIN = """#!{python}
import json, os, sys
with open(os.environ["STANDIN_GIVEN"], "w", encoding="utf-8") as f:
    json.dump({{"argv": sys.argv[1:], "env": {{k: v for k, v in os.environ.items() if k.startswith("FLEET_")}}}}, f)
"""


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real home folder (leftovers.scratch_home)


class Sizes(unittest.TestCase):
    def setUp(self):
        # In /tmp, as leftovers.tmux_socket is: the checkout's path is in each rule of a Claude session's own settings
        # (fleet.settings_arg), so the size of a command depends on it, and no TMPDIR may decide that.
        self.root = Path(removed_when_gone(tempfile.mkdtemp(prefix="ws-", dir="/tmp")))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.ran = self.root / "ran"        # a word of the data that a shell ran makes this file
        self.kit, self.sessions, self.bin = self.root / "kit", self.root / "sessions", self.root / "bin"
        (self.kit / "profiles").mkdir(parents=True)
        self.bin.mkdir()
        (self.kit / "RULES.md").write_text("# Rules\n\nFLEET-RULES-MARKER\n")
        (self.kit / "profiles" / f"{AGENT}.md").write_text("# Profile\n\n" + self.tricky("Profile"))
        self.given = self.root / "given.json"
        kept = self.root / "kept"
        kept.mkdir()
        for program in (self.bin / "claude", self.bin / "codex", self.bin / "python", kept / "claude-2.1.312"):
            program.write_text(STANDIN.format(python=sys.executable))
            program.chmod(0o755)
        team = {"agents": {AGENT: CLAUDE}, "mcp": SERVERS}
        self.catalog = lifecycle.tool_catalog(team)
        self.assertEqual(sorted(SERVERS), sorted(n for n in self.catalog if n in SERVERS))     # all of them taken
        for p in (patch.object(fleet, "SESSIONS", str(self.sessions)), patch.object(fleet, "HUB", "http://hub.test:8765"),
                  patch.object(fleet, "KIT", str(self.kit)), patch.object(fleet, "KEPT_RUNTIMES", str(kept)),
                  patch.object(fleet, "CLAUDE_VERSIONS", str(self.root / "versions")),
                  patch.object(fleet, "CLAUDE_USER_SETTINGS", str(self.root / "no-user" / "settings.json")),
                  patch.object(fleet, "team_catalog", lambda: lifecycle.tool_catalog(team))):
            p.start()
            self.addCleanup(p.stop)

    def tricky(self, head):
        """DATA bytes of text in which each line has quotes, $, backticks and $(...): the first line would make
        self.ran if a shell ran it, and the others have a fixed size, so the text's size does not depend on the
        folder of the test."""
        line = f"{head}: T-7 \"quoted\" 'single' $HOME `true` $(true) \\ ; exit 3 && @/etc/hosts\n"
        return f"{head} `touch {self.ran}` $(touch {self.ran}) \"$(touch {self.ran})\"\n" + line * (DATA // len(line))

    def env(self, **more):
        return dict({"FLEET_REPOS": REPOS, "FLEET_TOOLS": " ".join(SERVERS)}, **more)

    def small(self, command):
        """The command as tmux gets it: under LIMIT, and no line of the data in it."""
        self.assertLess(len(fleet.in_checkout(command).encode()), LIMIT)
        for word in ("quoted", "acme/repository-", "EXAMPLE_SETTING_"):
            self.assertNotIn(word, command)
        return shlex.split(command)

    def run_window(self, command):
        """What the program of the window's command got (argv, and FLEET_ variables), through each shell of SHELLS,
        which must all give it the same. The files that a shell reads and removes come back before the next shell."""
        kept, given = {path: path.read_bytes() for path in self.shell_files(command)}, None
        self.assertTrue(SHELLS)
        for shell in SHELLS:
            for path, data in kept.items():
                if not path.exists():
                    path.write_bytes(data)
                    path.chmod(0o600)
            self.given.unlink(missing_ok=True)
            subprocess.run([shell, "-c", fleet.in_checkout(command)], check=True, timeout=60,
                           env={"PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.root),
                                "STANDIN_GIVEN": str(self.given)})
            self.assertFalse(self.ran.exists(), shell)              # no word of the data ran
            self.assertEqual([path for path in kept if path.exists()], [], shell)     # read and removed
            this = json.loads(self.given.read_text())
            given = this if given is None else given
            self.assertEqual(this, given, shell)
        return given

    def private(self, path):
        """A file that the program reads itself: in SESSIONS, mode 600, there after its start."""
        path = Path(path)
        self.assertEqual((path.parent, stat.S_IMODE(path.stat().st_mode)), (self.sessions, 0o600))
        return path.read_text()

    def shell_files(self, command):
        """The files of a command that its window's shell reads and removes: its env file and its first prompt."""
        words = shlex.split(command)
        found = [w for w in words if w.startswith(str(self.sessions)) and w.endswith(".env")] + \
            [shlex.split(w[len("$(cat "):].split(";")[0])[0] for w in words if w.startswith("$(cat ")]
        return [Path(w) for w in dict.fromkeys(found)]

    def rules_and(self, text):
        """The appended system prompt of a Claude start without its stable text: the rules, then the text, as Claude
        Code joined its --append-system-prompt-file and --append-system-prompt."""
        return "# Rules\n\nFLEET-RULES-MARKER\n\n" + text

    # ---------------------------------------------------------------- the commands

    def test_a_claude_task_without_its_stable_text_reads_its_text_from_a_file(self):
        """An older hub's task gives no rules: its text, with the list of 500 repositories, was one word of the command
        (--append-system-prompt). It is the file of its appended system prompt now, after the rules that
        --append-system-prompt-file gave before, and its MCP configuration names the most servers, from its file."""
        prompt, env = self.tricky("Task"), self.env()
        command = fleet.session_command(AGENT, CLAUDE, prompt, task="T-7", needs="browser", attempt=2,
                                        generation="g1", session=SESSION, token=TOKEN, env=env)
        words = self.small(command)
        self.assertNotIn("--append-system-prompt", words)
        self.assertEqual(words.count("--append-system-prompt-file"), 1)    # Claude Code takes one
        system = words[words.index("--append-system-prompt-file") + 1]
        self.assertEqual(self.private(system), self.rules_and(prompt + fleet.github_text(env, list(SERVERS))))
        config = json.loads(self.private(words[words.index("--mcp-config") + 1]))
        self.assertEqual(sorted(config["mcpServers"]), sorted(["fleet", *SERVERS]))
        settings = json.loads(words[words.index("--settings") + 1])  # bounded: one rule for each server
        self.assertEqual(settings["permissions"]["allow"][1:1 + len(SERVERS)], [f"mcp__{t}__*" for t in SERVERS])
        given = self.run_window(command)
        self.assertEqual(given["argv"], words[words.index("claude") + 1:])
        self.assertEqual(self.private(system), self.rules_and(prompt + fleet.github_text(env, list(SERVERS))))
        self.assertEqual(given["env"]["FLEET_TASK"], "T-7")
        # without a credential (an agent before its key) the configuration is a file too, and no credential
        words = shlex.split(fleet.session_command(AGENT, CLAUDE, prompt, task="T-7", generation="g1", session=SESSION,
                                                  env=env))
        config = json.loads(self.private(words[words.index("--mcp-config") + 1]))
        self.assertEqual((sorted(config["mcpServers"]), config["mcpServers"]["fleet"]),
                         (sorted(["fleet", *SERVERS]), {"type": "http", "url": "http://hub.test:8765/mcp/dev-lead/g1/T-7/1"}))

    def test_a_codex_task_reads_its_prompt_and_its_mcp_servers_from_files(self):
        """A Codex task's prompt is its first argument, and its rules and its catalog servers are -c options of Codex:
        its developer instructions are all of RULES.md (fleet.codex_rules), and each of the most servers with the most
        settings is thousands of characters. The window's shell reads the prompt from its file and the options from
        its env file, as the positional parameters that "$@" gives Codex in their place."""
        prompt, env = self.tricky("Task"), self.env(EXAMPLE_API_KEY="example-value")
        command = fleet.session_command(AGENT, CODEX, prompt, task="T-7", attempt=2, generation="g1", session=SESSION,
                                        token=TOKEN, env=env)
        words = self.small(command)
        files = self.shell_files(command)
        self.assertEqual(len(files), 2)
        given = self.run_window(command)
        options = fleet.codex_rules() + [w for t in SERVERS for w in shlex.split(fleet.codex_server(t, self.catalog))]
        self.assertEqual(options[:2], ["-c", "developer_instructions=" + json.dumps("# Rules\n\nFLEET-RULES-MARKER")])
        bearer = given["argv"].index(fleet.CODEX_BEARER_OPTION)
        self.assertEqual(given["argv"][bearer + 1:bearer + 1 + len(options)], options)   # where "$@" stood, whole
        self.assertEqual(given["argv"][-1], prompt + fleet.github_text(env, list(SERVERS)) + "\n\n" +
                         fleet.MARKER.format(SESSION))
        self.assertEqual(given["argv"][:bearer + 1], words[words.index("codex") + 1:words.index("$@")])
        self.assertEqual(given["env"].get("FLEET_SESSION_TOKEN"), TOKEN)
        self.assertFalse([f for f in files if f.exists()])         # both read and removed before Codex ran

    def test_a_codex_session_s_rules_fit_in_one_argument_on_linux(self):
        """A Codex session's developer instructions are all of this checkout's RULES.md in one argument of the program
        (fleet.codex_rules), and Linux takes one of at most 131,071 bytes with pages of 4 KiB: a RULES.md that grew
        past it would end every Codex start on Linux with "Argument list too long", in a pane that closes."""
        with patch.object(fleet, "KIT", ROOT):
            words = fleet.codex_rules()
        self.assertEqual(words[0], "-c")
        self.assertLess(len(words[1].encode("utf-8")), 32 * 4096 - 1)

    def test_a_runner_task_reads_its_prompt_from_a_file_that_it_removes(self):
        """A task in the runner (screen_runner.py) had its prompt, with the list of its repositories, as one word of
        the command (--prompt). It names the prompt's file now, which the runner reads and removes at its start."""
        prompt, env = self.tricky("Task"), self.env()
        with patch.object(sys, "executable", str(self.bin / "python")):     # its program, and the repository command
            command = fleet.session_command(AGENT, RUNNER, prompt, task="T-7", attempt=2, generation="g1",
                                            session=SESSION, token=TOKEN, env=env)
            whole = prompt + fleet.github_text(env, []) + "\n\n" + fleet.MARKER.format(SESSION)
        words = self.small(command)
        given = self.run_window(command)
        self.assertEqual(given["argv"][0], os.path.join(str(self.kit), "screen_runner.py"))
        self.assertEqual(given["argv"][1:-1], ["--needs", "none", "--prompt-file"])
        path = Path(given["argv"][-1])
        self.assertEqual(self.private(path), whole)
        self.assertEqual(given["env"]["FLEET_SESSION_TOKEN"], TOKEN)
        self.assertNotIn(str(path), [str(f) for f in self.shell_files(command)])
        # the runner's own start: it takes the prompt whole from the file and removes the file
        fixed = {"FLEET_AGENT": AGENT, "FLEET_TASK": "T-7", "FLEET_ATTEMPT": "2", "FLEET_GENERATION": "g1",
                 "FLEET_SESSION": SESSION}
        start = next(i for i, w in enumerate(words) if w.endswith("screen_runner.py"))
        for argv in (words[start:], words[start:-2] + ["--prompt", "Do T-61."]):     # and as a helper of before
            with self.subTest(argv[-2]), patch.object(fleet, "agent_conf", return_value=RUNNER), \
                    patch.object(fleet, "AGENT", None), patch.object(lifecycle, "exe", return_value="/opt/example/codex"), \
                    patch.object(screen_runner, "Runner") as runner, patch.dict(os.environ, fixed), \
                    patch.object(sys, "argv", argv):
                runner.return_value.run.return_value = 0
                self.assertEqual(screen_runner.main(), 0)
                self.assertEqual(runner.call_args.args[4], whole if argv[-2] == "--prompt-file" else "Do T-61.")
        self.assertFalse(path.exists())

    def test_an_owner_chat_without_its_stable_text_reads_its_profile_and_recap_from_a_file(self):
        """An owner chat that the hub gives no rules had its instructions and the agent's profile in its command, and
        cut only the hub's recap to fit (chat_fit), so a long profile alone stopped the chat. Its whole start text
        comes from a file now, on each runtime, with the recap whole."""
        recap = "This session has no memory of this chat.\n" + "\n".join(
            f"The owner: m{i} `touch {self.ran}` $(touch {self.ran}) \"quoted\" " + "x" * 760 for i in range(20))
        expected = fleet.chat_instructions(AGENT, CLAUDE) + " Your profile follows:\n" + \
            (self.kit / "profiles" / f"{AGENT}.md").read_text() + "\n\n" + recap
        self.assertGreater(len(expected.encode()), DATA + 16000)
        command = fleet.chat_command(AGENT, CLAUDE, "g1", token=TOKEN, marker=SESSION, recap=recap)
        words = self.small(command)
        self.assertNotIn("--append-system-prompt", words)
        system = words[words.index("--append-system-prompt-file") + 1]
        self.assertEqual(self.private(system), self.rules_and(expected))
        given = self.run_window(command)
        self.assertEqual(given["argv"], words[words.index("claude") + 1:])
        self.assertEqual(self.private(system), self.rules_and(expected))
        marker = "22222222-3333-4444-8555-666666666666"
        command = fleet.chat_command(AGENT, CODEX, "g1", token=TOKEN, marker=marker, recap=recap,
                                     env={"EXAMPLE_API_KEY": "example-value"})
        self.small(command)
        files = self.shell_files(command)
        given = self.run_window(command)
        self.assertEqual(given["argv"][-1], fleet.chat_instructions(AGENT, CODEX) + " Your profile follows:\n" +
                         (self.kit / "profiles" / f"{AGENT}.md").read_text() + "\n\n" + recap + "\n\n" +
                         fleet.MARKER.format(marker))
        self.assertEqual((len(files), [f for f in files if f.exists()]), (2, []))

    def test_a_closed_task_reads_its_settings_from_a_file(self):
        """A task session whose Shell box is off had its settings in its command: one rule for each host of its list
        and for each catalog server, and the hook of the host list names each host again. They come from a file now,
        as its MCP configuration and its start text do."""
        hosts = [("*." if i % 2 else "") + f"h{i:02d}-" + "d" * 58 + ".example.com" for i in range(lifecycle.WEB_HOSTS_MOST)]
        closed = {"runtime": "claude", "version": "2.1.312", "built_ins": ["WebSearch", "WebFetch"],
                  "web_hosts": hosts, "servers": list(SERVERS)}
        command = fleet.session_command(AGENT, dict(CLAUDE, can=["web"]), self.tricky("Task"), task="T-7",
                                        attempt=2, generation="g1", session=SESSION, token=TOKEN, env=self.env(),
                                        opening="read", rules=[], closed=closed)
        words = self.small(command)
        for host in hosts:
            self.assertNotIn(host, command)
        settings = json.loads(self.private(words[words.index("--settings") + 1]))
        self.assertEqual(settings["permissions"]["allow"],
                         ["mcp__fleet__*"] + [f"mcp__{t}__*" for t in SERVERS] + ["WebSearch"] + fleet.host_rules(hosts))
        self.assertEqual(settings["hooks"]["PreToolUse"], [fleet.hosts_hook(hosts)])
        given = self.run_window(command)
        self.assertEqual(given["argv"], words[words.index(str(self.root / "kept" / "claude-2.1.312")) + 1:])
        self.assertEqual(json.loads(self.private(given["argv"][given["argv"].index("--settings") + 1])), settings)

    def linux_limit(self):
        """ARG_MOST as Linux has it with pages of 4 KiB, which no machine's own limit is under."""
        limit = patch.object(fleet, "ARG_MOST", 32 * 4096 - 1)
        limit.start()
        self.addCleanup(limit.stop)

    def left_out(self, prompt, count=1):
        """The parts of a prompt on each side of its LEFT_OUT lines, and the cut that each line names."""
        line = re.compile(re.escape(fleet.LEFT_OUT).replace(r"\{cut\}", r"(\d+)")
                          .replace(r"\{most\}", str(fleet.ARG_MOST)))
        found = list(line.finditer(prompt))
        self.assertEqual(len(found), count, prompt[:300])
        sides = line.split(prompt)[::2]
        return sides, [int(f.group(1)) for f in found]

    def test_a_first_prompt_longer_than_one_argument_loses_its_middle_and_the_session_starts(self):
        """The next limit is the program's: a first prompt is one argument, and exec takes one of at most ARG_MOST
        bytes (Linux: 32 pages; macOS: half of what all the arguments and the environment may hold). One of that size
        reaches the program whole. A longer one loses a middle, with a line that says how much went, and the session
        starts: a refusal there stopped every start of the standing session again, as tmux's limit had. A stable text,
        and a chat's instructions and profile, come first and stay whole, so the session has what it is told it has;
        the session's own part keeps its start, which names its task, and its end: the brief's last words, and the
        marker that binds a Codex session to its rollout. Each cut ends at a line end, and the helper's log says how
        much went. With Linux's limit on every machine, so that the same sizes cut in the same places."""
        self.linux_limit()
        fits = "\u00e9" * (fleet.ARG_MOST // 2) + "x" * (fleet.ARG_MOST % 2)
        self.assertEqual(len(fits.encode()), fleet.ARG_MOST)
        given = self.run_window("codex " + fleet.file_prompt(AGENT, "manager", fits))
        self.assertEqual(given["argv"], [fits])
        head = f"Your task, first: `touch {self.ran}` $(touch {self.ran})\n"
        last = "Then call read_messages: its read is the receipt."
        # a third over the limit, in numbered lines of two-byte characters with a shell's words in each
        long = head + "".join(f"{i:06d} " + "\u00e9" * 40 + " \"q\" `true` $(true) $HOME\n"
                              for i in range(fleet.ARG_MOST // 80)) + last
        self.assertGreater(len(long.encode()), fleet.ARG_MOST * 6 // 5)
        profile = (self.kit / "profiles" / f"{AGENT}.md").read_text().strip()
        keys = {"EXAMPLE_API_KEY": "example-value"}
        marker = "\n\n" + fleet.MARKER.format(SESSION)
        # 50 repositories: a stable text that leaves its task a quarter of the limit (the next test has 500)
        some = dict(self.env(**keys), FLEET_REPOS=" ".join(REPOS.split()[:50]))
        repos = ("acme/repository-000-", "acme/repository-049-")
        for name, start, ends, whole in (
                ("codex manager", lambda: fleet.session_command(AGENT, CODEX_MANAGER, long, session=SESSION,
                                                                token=TOKEN, env=keys), last + marker, ()),
                ("claude manager", lambda: fleet.session_command(AGENT, MANAGER, long, session=SESSION, token=TOKEN,
                                                                 env=keys), last, ()),
                # a Codex task's text without its stable text ends with its repositories and catalog servers
                ("codex task", lambda: fleet.session_command(AGENT, CODEX, long, task="T-7", generation="g1",
                                                             session=SESSION, token=TOKEN, env=self.env(**keys)),
                 "Their tools are mcp__<server>__*." + marker, ()),
                ("codex chat", lambda: fleet.chat_command(AGENT, CODEX, "g1", token=TOKEN, marker=SESSION, env=keys,
                                                          recap=long), last + marker, (profile,)),
                ("codex manager, stable", lambda: fleet.session_command(AGENT, CODEX_MANAGER, long, session=SESSION,
                                                                        token=TOKEN, env=keys, rules=[]),
                 last + marker, (profile,)),
                ("codex task, stable", lambda: fleet.session_command(
                    AGENT, CODEX, long, task="T-7", generation="g1", session=SESSION, token=TOKEN, env=some,
                    opening="prompt", rules=[]), last + marker, (profile,) + repos),
                ("codex chat, stable", lambda: fleet.chat_command(AGENT, CODEX, "g1", token=TOKEN, marker=SESSION,
                                                                  env=keys, recap=long, rules=[]),
                 last + marker, (profile,))):
            with self.subTest(name):
                log = io.StringIO()
                with contextlib.redirect_stdout(log):
                    command = start()
                self.small(command)
                prompt = self.run_window(command)["argv"][-1]
                self.assertLessEqual(len(prompt.encode()), fleet.ARG_MOST)
                (before, after), (cut,) = self.left_out(prompt)
                self.assertGreater(cut, 0)
                self.assertIn(f"{cut} bytes of its first prompt are left out", log.getvalue())
                self.assertTrue(after.endswith(ends), after[-200:])
                self.assertEqual(prompt.count("\n" + last), 1)
                for part in whole:                  # what comes first stays whole, before the cut
                    self.assertIn(part, before)
                # the stable subtests take the stable path, whose text says that the profile is in the context
                self.assertEqual("do not read them again" in before, name.endswith("stable"))
                self.assertIn(head, before)         # the session's own part keeps its start
                self.assertTrue(before.endswith("$HOME"), before[-80:])     # a whole line on each side of the cut
                self.assertRegex(after, r"\A\d{6} \u00e9")
                self.assertFalse(self.ran.exists())

    def test_a_stable_text_longer_than_its_room_loses_its_middle_too(self):
        """A stable text that would leave the session's own part less than a quarter of ARG_MOST loses its middle as
        well: the session's part keeps that quarter, with its start and its end, and the whole fits."""
        self.linux_limit()
        (self.kit / "profiles" / f"{AGENT}.md").write_text(
            "# Profile\n\nPROFILE-START\n" + "A line of the profile, with $HOME and `true` in it.\n" *
            (fleet.ARG_MOST // 50) + "PROFILE-END\n")
        head, last = "Your task, first.\n", "Then call read_messages: its read is the receipt."
        long = head + "Another line of the task's block.\n" * (fleet.ARG_MOST // 100) + last
        log = io.StringIO()
        with contextlib.redirect_stdout(log):
            command = fleet.session_command(AGENT, CODEX, long, task="T-7", generation="g1", session=SESSION,
                                            token=TOKEN, env=self.env(), opening="prompt", rules=[])
        self.small(command)
        prompt = self.run_window(command)["argv"][-1]
        self.assertLessEqual(len(prompt.encode()), fleet.ARG_MOST)
        (stable, own, after), cuts = self.left_out(prompt, 2)
        self.assertTrue(all(cuts))
        self.assertIn(f"T-7: {sum(cuts)} bytes of its first prompt are left out", log.getvalue())
        self.assertIn("PROFILE-START", stable)
        self.assertNotIn("PROFILE-END", stable)             # in its own lost middle
        self.assertIn("acme/repository-499-", own)          # the stable text's end: its repositories
        self.assertIn(head, own)
        self.assertTrue(after.endswith(last + "\n\n" + fleet.MARKER.format(SESSION)))
        mine = len(own[own.index(head):].encode()) + len(fleet.LEFT_OUT.format(cut=cuts[1], most=fleet.ARG_MOST)
                                                          .encode()) + len(after.encode())
        self.assertLessEqual(mine, fleet.ARG_MOST // 4)                     # the task's own part: its quarter
        self.assertGreater(mine, fleet.ARG_MOST // 4 - 2 * fleet.LINE_NEAR - 8)

    def test_fit_argument_keeps_whole_characters_and_near_line_ends_within_its_limit(self):
        """fit_argument: a text that fits, to the byte, is given back as it is. A longer one is at most `most` bytes,
        keeps its start and its end with no character cut in two, and loses only the middle that the line names. Each
        side ends at a line end within LINE_NEAR bytes of the cut, keeps a line that already starts or ends there, and
        is cut where its bytes end when no line end is near: one long line is not lost whole, and a last line end does
        not take the end away."""
        for most in (2048, 4096):
            for char in ("x", "\u00e9", "\u4e2d", "\U0001F600"):
                fits = char * (most // len(char.encode()))
                fits += "x" * (most - len(fits.encode()))
                self.assertEqual(fleet.fit_argument(fits, most), (fits, 0))
                fitted, cut = fleet.fit_argument(fits + "x", most)
                self.assertTrue(cut > 0 and len(fitted.encode()) <= most, (char, most))
            for text in ("\U0001F600" * 3000, "\u4e2d\u6587" * 2500, "ab\n" * 3000, ("\u00e9" * 37 + "\n") * 300,
                         "line\r\n" * 2000, "\n" * 9000, "first\n" + "y" * 9000 + "\nlast", "x" * 50 + "\n" * 3):
                for extra in ("", "z", "zz\n", "z" * 977):
                    whole = text + extra
                    fitted, cut = fleet.fit_argument(whole, most)
                    size = len(whole.encode())
                    if size <= most:
                        self.assertEqual((fitted, cut), (whole, 0))
                        continue
                    self.assertLessEqual(len(fitted.encode()), most, (most, size))
                    note = fleet.LEFT_OUT.format(cut=cut, most=most)
                    self.assertEqual(fitted.count(note), 1)
                    before, _, after = fitted.partition(note)
                    self.assertEqual(len(before.encode()) + len(after.encode()) + cut, size)
                    self.assertTrue(whole.startswith(before) and whole.endswith(after) and after)
            room = lambda size: most - len(fleet.LEFT_OUT.format(cut=size, most=most).encode())
            # short lines: both sides end at a line end
            whole = "ab\n" * 3000
            before, _, after = fleet.fit_argument(whole, most)[0].partition("\n\n[")
            after = after.split("]\n\n", 1)[1]
            self.assertEqual((whole[len(before)], whole[-len(after) - 1]), ("\n", "\n"))
            # one long line at each cut: cut where its bytes end, so nearly all of the room stays
            whole = "You are the manager.\n" + "y" * (most * 3) + "\nThen call read_messages."
            fitted, _ = fleet.fit_argument(whole, most)
            self.assertGreaterEqual(len(fitted.encode()), most - 4)
            self.assertTrue(fitted.startswith("You are the manager.\n"))
            self.assertTrue(fitted.endswith("\nThen call read_messages."))
            # a last line end after a long last line: the end stays
            whole = "first\n" + "z" * (most * 3) + "\n"
            fitted, _ = fleet.fit_argument(whole, most)
            self.assertTrue(fitted.endswith("z" * (most // 4) + "\n"), fitted[-40:])
            # sides that already end and start at a line end keep each of their lines
            size = most * 3
            end, start = room(size) // 2, size - (room(size) - room(size) // 2)
            whole = "a" * (end // 2) + "\n" + "a" * (end - end // 2 - 1) + "\n" + "b" * (start - end - 2) + "\n" + \
                "c" * ((size - start) // 2) + "\n" + "c" * (size - start - (size - start) // 2 - 1)
            self.assertEqual(len(whole), size)
            fitted, cut = fleet.fit_argument(whole, most)
            self.assertEqual(fitted, whole[:end] + fleet.LEFT_OUT.format(cut=start - end, most=most) + whole[start:])
            # a line end of \r\n just after the cut: the head keeps that line whole, up to its \r
            whole = "a" * (end - 10) + "\n" + "a" * 9 + "\r\n" + "b" * (size - end - 2)
            self.assertEqual(len(whole), size)
            self.assertEqual(fleet.fit_argument(whole, most)[0].partition("\n\n[")[0], whole[:end])

    def test_the_argument_limit_is_the_machines_own(self):
        """fleet.arg_most: Linux takes one argument of at most 32 pages with its closing NUL, and each machine at most
        half of what all its arguments and its environment may hold, which is macOS's only limit. A value that the
        system does not give, or gives as 0 or less, is unknown: then 1 MiB in all, and pages of 4 KiB."""
        given = lambda **values: (lambda name: values[name])

        def unknown(name):
            raise ValueError(name)
        for linux, values, most in ((True, dict(SC_ARG_MAX=2 << 20, SC_PAGE_SIZE=4096), 131071),
                                    (True, dict(SC_ARG_MAX=2 << 20, SC_PAGE_SIZE=65536), 1 << 20),
                                    (True, dict(SC_ARG_MAX=128 << 10, SC_PAGE_SIZE=4096), 64 << 10),     # a small stack
                                    (False, dict(SC_ARG_MAX=1 << 20), 512 << 10),
                                    (True, dict(SC_ARG_MAX=-1, SC_PAGE_SIZE=0), 131071),
                                    (False, dict(SC_ARG_MAX=0), 512 << 10)):
            with self.subTest(linux=linux, **values):
                self.assertEqual(fleet.arg_most(given(**values), linux), most)
        self.assertEqual((fleet.arg_most(unknown, True), fleet.arg_most(unknown, False)), (131071, 512 << 10))

    # ---------------------------------------------------------------- which window holds its credential

    def test_only_the_file_of_a_credential_counts_as_one(self):
        """legacy_windows names each window that started without a session credential, so that the helper closes the
        standing session and the owner chat among them once it has the agent's key, and the hub places no agent with
        one. Until 16 November 2026 any file of ~/.fleet/sessions in a command counted as a credential, and a standing
        session without one reads its first prompt from such a file since e749f6071: its window counted as one that has
        a credential, and stayed without one. Real commands of each kind, with and without a credential."""
        brief, keys = "Where the fleet stands: nothing new.", {"EXAMPLE_API_KEY": "example-value"}
        listing = {
            "manager": fleet.session_command(AGENT, MANAGER, brief, session=SESSION),
            "manager-keyed": fleet.session_command(AGENT, MANAGER, brief, session=SESSION, token=TOKEN),
            "manager-stable": fleet.session_command(AGENT, MANAGER, brief, session=SESSION, rules=[]),
            "codex-manager": fleet.session_command(AGENT, CODEX_MANAGER, brief, session=SESSION, env=keys),
            "codex-manager-keyed": fleet.session_command(AGENT, CODEX_MANAGER, brief, session=SESSION, token=TOKEN,
                                                         env=keys),
            "owner-chat": fleet.chat_command(AGENT, CLAUDE, "g1", marker=SESSION),
            "owner-chat-keyed": fleet.chat_command(AGENT, CLAUDE, "g1", token=TOKEN, marker=SESSION),
            "codex-chat": fleet.chat_command(AGENT, CODEX, "g1", marker=SESSION, env=keys),
            "codex-chat-keyed": fleet.chat_command(AGENT, CODEX, "g1", token=TOKEN, marker=SESSION, env=keys),
            "T-1": fleet.session_command(AGENT, CLAUDE, "Do T-1.", task="T-1", generation="g1", session=SESSION,
                                         token=TOKEN, env=self.env()),
            "T-2": fleet.session_command(AGENT, CODEX, "Do T-2.", task="T-2", generation="g1", session=SESSION,
                                         token=TOKEN, env=self.env()),
            "T-3": fleet.session_command(AGENT, RUNNER, "Do T-3.", task="T-3", generation="g1", session=SESSION,
                                         token=TOKEN, env=self.env()),
            "T-4": fleet.session_command(AGENT, dict(CLAUDE, can=["web"]), "Do T-4.", task="T-4", generation="g1",
                                         session=SESSION, token=TOKEN, env=self.env(), opening="read", rules=[],
                                         closed={"version": "2.1.312"}),
            "T-5": fleet.session_command(AGENT, CLAUDE, "Do T-5.", task="T-5", generation="g1", session=SESSION,
                                         env=self.env()),
        }
        for name in ("manager", "manager-stable", "codex-manager", "codex-chat", "T-5"):
            self.assertIn(str(self.sessions), listing[name], name)    # a file of that folder, and no credential
        # as tmux 3.6a shows each start command in #{pane_start_command}: in double quotes, with " and \ escaped and
        # $ as it is (read on this Mac, 16 November 2026); and one as the command itself
        shown = {name: '"' + re.sub(r'(["\\])', r'\\\1', fleet.in_checkout(command)) + '"'
                 for name, command in listing.items()}
        shown["T-1"] = fleet.in_checkout(listing["T-1"])
        answer = subprocess.CompletedProcess([], 0, "".join(f"{n}\t{c}\n" for n, c in shown.items()), "")
        helper = fleet.Helper(AGENT, CLAUDE)
        with patch.object(fleet, "tmux", return_value=answer):
            self.assertEqual(helper.legacy_windows(), ["T-5", "codex-chat", "codex-manager", "manager",
                                                       "manager-stable", "owner-chat"])
        # a configuration file that is gone, or that names no credential, is none
        config = shlex.split(listing["manager-keyed"])
        config = Path(config[config.index("--mcp-config") + 1])
        self.assertTrue(fleet.holds_credential(listing["manager-keyed"]))
        config.unlink()
        self.assertFalse(fleet.holds_credential(listing["manager-keyed"]))
        # A runtime that the runtime table adds takes its credential from its env file, as a runner does, and as each
        # such window counted before; Claude and Codex count only as above.
        env_file = self.sessions / f"{AGENT}.T-9.0123456789abcdef.env"
        fourth = f"cd {self.kit} && . {env_file} && rm -f {env_file} && exec env FLEET_TASK=T-9 fourth --wide-open"
        self.assertTrue(fleet.holds_credential(fourth))
        self.assertFalse(fleet.holds_credential(fourth.replace("fourth --wide-open", "claude --tools ''")))
        codex = "codex -c 'mcp_servers.fleet.url=\"http://hub.test:8765/mcp/dev-lead\"' --no-daemon"
        self.assertFalse(fleet.holds_credential(fourth.replace("fourth --wide-open", codex)))
        self.assertTrue(fleet.holds_credential(fourth.replace("fourth --wide-open", codex.replace(
            " --no-daemon", " " + fleet.CODEX_BEARER.strip() + " --no-daemon"))))
        self.assertFalse(fleet.holds_credential(fourth.replace(str(self.sessions), str(self.root))))   # not its folder


if __name__ == "__main__":
    unittest.main()

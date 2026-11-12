"""One table for what the fleet knows about a runtime (lifecycle.RUNTIMES), and this is the fence around it.

Before 20 October 2026 those facts were spread over four constants in hub.py, four more in fleet.py, two in
lifecycle.py, two in hubsetup.py, one in server.py and about fifteen comparisons of the form `runtime == "grok"` in
hub.py, fleet.py and lifecycle.py. Each one encoded one fact about one runtime, so a fourth provider was a lane and
not an entry. This suite holds the line in three ways:

  1. **The facts did not change.** Every value the old constants had is written out below, by hand, and must be
     exactly what the table gives for codex, claude and grok. That is the regression fence: a wrong edit of an
     entry fails here and not in production.
  2. **Nothing reads a runtime's name to decide.** The AST of hub.py, fleet.py and lifecycle.py is walked for a
     comparison of a runtime against a name, and the functions that still hold one are exactly the ones named in
     MECHANICS, each with the reason it is code and not a fact.
  3. **A fourth entry is the only edit.** A stand-in provider is put in the table and every reader answers for it:
     the derived names, team.json's validation, the hub's offers and refusals, and the helper's start command.

No AI call, no hub database and no machine: these are reads of the table and of the source.
"""
import ast
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import acp_programs
import fleet
import hub
import hubsetup
import lifecycle
import onboard
import server
import usage

KIT = Path(__file__).resolve().parent

# What the fleet knew about each runtime before the table, written out as the constants and the comparisons had it.
# Nothing here is derived: a value that drifts must be a deliberate edit of both sides.
BEFORE = {
    "codex": {
        "label": "Codex",
        "driver": "terminal",
        "acp_command": None,
        "can": {"shell", "web", "screen"},
        "full_access": {"start": "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"},
        "manager_access": {"start": "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"},
        "first_worker": "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}",
        "manager": True, "owner_chat": True, "agent_messages": True, "conversation": False,
        "mcp_servers": True, "app_server": True, "switch": True, "session_settings": False, "token_in_env": True,
        "local_model": "--oss",
        "model_flags": {"model": ["-m", "{}"], "effort": ["-c", 'model_reasoning_effort="{}"']},
        "sign_in_url": r"https://auth\.openai\.com/[A-Za-z0-9/_?=&.%-]{0,2000}",
        "shows_code": r"\b[A-Z0-9]{4}-[A-Z0-9]{4,6}\b",
        "wants_code": False,
        "no_sign_in": None,
    },
    "claude": {
        "label": "Claude Code",
        "driver": "terminal",
        "acp_command": None,
        "can": {"shell", "web", "browser", "screen"},
        "full_access": {"start": "claude --permission-mode dontAsk {settings} {prompt}",
                        "allow": ["Bash", "Read", "Edit", "Write", "NotebookEdit", "WebFetch", "WebSearch",
                                  "mcp__fleet__*"]},
        "manager_access": {"start": "claude --permission-mode bypassPermissions --tools default {settings} {prompt}"},
        "first_worker": "claude --permission-mode dontAsk {chrome} {settings} {prompt}",
        "manager": True, "owner_chat": True, "agent_messages": True, "conversation": True,
        "mcp_servers": True, "app_server": False, "switch": True, "session_settings": True, "token_in_env": False,
        "local_model": None,
        "model_flags": {"model": ["--model", "{}"], "effort": ["--effort", "{}"]},
        "sign_in_url": r"https://(?:claude\.ai|claude\.com|console\.anthropic\.com)/[A-Za-z0-9/_?=&.%#+-]{0,2000}",
        "shows_code": None,
        "wants_code": True,
        "no_sign_in": None,
    },
    "grok": {
        "label": "Grok",
        "driver": "acp",
        "acp_command": "grok agent stdio",
        # Since the AI providers build (its spec, section 3.4): a Grok agent is a worker with a shell and the web, in
        # Fleet's one form for it, and its task sessions load the owner's MCP servers.
        "can": {"shell", "web"}, "full_access": {"start": "grok agent stdio"}, "manager_access": None,
        "first_worker": "grok agent stdio",
        "manager": False, "owner_chat": False, "agent_messages": False, "conversation": False,
        "mcp_servers": True, "app_server": False, "switch": False, "session_settings": False, "token_in_env": True,
        "local_model": None,
        "model_flags": None,
        "sign_in_url": None, "shows_code": None, "wants_code": None,
        "no_sign_in": ("Fleet drives no Grok sign-in: xAI's terms do not let a third party run it this way. "
                       "Sign in to Grok yourself on {where} machine."),
    },
    # The same build's second program. It was never a constant: this is its entry, written out a second time.
    "opencode": {
        "label": "OpenCode",
        "driver": "acp",
        "acp_command": "opencode acp",
        "can": {"shell", "web"}, "full_access": {"start": "opencode acp"}, "manager_access": None,
        "first_worker": "opencode acp",
        "manager": False, "owner_chat": False, "agent_messages": False, "conversation": False,
        "mcp_servers": True, "app_server": False, "switch": False, "session_settings": False, "token_in_env": True,
        "local_model": None,
        "model_flags": None,
        "sign_in_url": None, "shows_code": None, "wants_code": None,
        "no_sign_in": "OpenCode needs no sign-in on {where} machine.",
    },
}
# The facts that the AI providers build added to each entry, written out by hand as well (its spec, section 3.4).
ACP_FACTS = {
    "codex": {"acp_auth": None, "acp_quiet": None, "acp_models": None, "acp_allowance": None, "key_env": None,
              "own_env": None, "pinned": False, "continues": True, "task_opening": "prompt"},
    "claude": {"acp_auth": None, "acp_quiet": None, "acp_models": None, "acp_allowance": None, "key_env": None,
               "own_env": None, "pinned": False, "continues": True, "task_opening": "read"},
    "grok": {"acp_auth": {"plan": "cached_token", "key": "xai.api_key"},
             "acp_quiet": {"GROK_DISABLE_AUTOUPDATER": "1",
                           "GROK_CLAUDE_SKILLS_ENABLED": "0", "GROK_CLAUDE_RULES_ENABLED": "0",
                           "GROK_CLAUDE_AGENTS_ENABLED": "0", "GROK_CLAUDE_MCPS_ENABLED": "0",
                           "GROK_CLAUDE_HOOKS_ENABLED": "0", "GROK_CURSOR_SKILLS_ENABLED": "0",
                           "GROK_CURSOR_RULES_ENABLED": "0", "GROK_CURSOR_AGENTS_ENABLED": "0",
                           "GROK_CURSOR_MCPS_ENABLED": "0", "GROK_CURSOR_HOOKS_ENABLED": "0"},
             "acp_models": "initialize", "acp_allowance": "_x.ai/billing", "key_env": "XAI_API_KEY",
             "own_env": ("GROK_", "XAI_"), "pinned": True, "continues": False, "task_opening": "system",
             "memory_off": {"env": {"GROK_MEMORY": "0"}}, "closed_versions": (), "sign_out": None},
    "opencode": {"acp_auth": None,
                 "acp_quiet": {"OPENCODE_DISABLE_PROJECT_CONFIG": "1", "OPENCODE_DISABLE_CLAUDE_CODE": "1",
                               "OPENCODE_DISABLE_AUTOUPDATE": "1", "OPENCODE_DISABLE_MODELS_FETCH": "1"},
                 "acp_models": "session", "acp_allowance": None, "key_env": "FLEET_MODEL_KEY",
                 "own_env": ("OPENCODE_",), "pinned": True, "continues": False, "task_opening": "system",
                 "memory_off": {"env": {}}, "closed_versions": (), "sign_out": None},
}

# The functions that still compare a runtime against a name, and why each one is code and not a fact. A new name
# here is a decision: either the comparison belongs in the table, or this line says what mechanics it holds.
MECHANICS = {
    # The hub decides nothing from a runtime's name any more: every answer it gives comes from an entry.
    "hub.py": {},
    "lifecycle.py": {
        "runtime": "each provider's own status command, and the words it answers a sign-in reading with",
        "read_models": "whether the names of a provider's model options are its own",
        "model_options": "each terminal provider's own route to its model options, which a runtime update's check "
                         "reads too; an ACP program's list is read by the fact acp_models, with no name",
        "update_runtime": "only Claude Code's own updates read a channel and a floor from its settings, which a "
                          "vendor's installation that the helper adopts is given (onboard.CLAUDE_CHANNEL)",
    },
    # The two terminal providers keep their own conversation records, because the shapes are not alike: Codex has no
    # id the fleet can choose, so its session is found by a marker in its first prompt and then by its thread, while
    # a Claude session has the id the fleet gave it and a file that appears once the conversation has begun. A
    # provider whose entry says it has no owner chat and cannot be the manager never reaches any of this.
    "fleet.py": {
        "session_command": "each terminal provider's own command line: the daemon flag, the MCP options, the "
                           "session id or the prompt marker, an idle first turn, and how it resumes",
        "chat_command": "the same, for an owner chat window",
        "chat_record_file": "the file name a Codex chat had before each runtime kept a record of its own",
        "manager_conversation": "a Codex record names a marker and a thread, a Claude record a session",
        "manager_start": "the same, for the record that a start writes",
        "manager_binding": "the same, for the conversation file a running window is bound to",
        "chat_binding": "the same, for the owner chat's conversation file",
        "chat_resume": "the same, for the conversation an owner chat continues",
        "note_begun": "the same, for marking that a conversation has begun",
        "forget_record": "the same, for dropping a record whose session never began one",
        "manager_keeps": "the same, read from a window that runs",
        "start_handover": "the same, when a switch hands the standing session over",
        "unnoted": "the same, for a start whose conversation is not noted yet",
        "unbegun_record": "the same: only a Claude record carries \"begun\"",
        "start_chat": "the same, for the record a new owner chat writes",
        "adopt_manager": "only a running Claude session's conversation file can be adopted by hand",
        "restart_fresh": "only Claude Code reads its compaction window from the environment it started with "
                         "(CLAUDE_CODE_AUTO_COMPACT_WINDOW)",
        "conversation_work_command": "the same, for a conversation's session that stays open across messages "
                                     "(AUTONOMY.md P2)",
        "closed_program": "only Claude Code's own installer keeps each version in a store of its own, which a closed "
                          "conversation's pinned version is taken from (AUTONOMY.md P10)",
        "ready_codex_trust": "only Codex keeps a folder's trust as a block of its own config.toml, by the folder's git "
                             "root, which the helper writes for the checkout",
        "standing_context": "each provider's own conversation file, read for the session reuse rule (plan P9.10)",
        "window_reuse": "the same, for a task window's or a tools-on conversation window's conversation file",
        "record_files": "the same, for the conversation files of an owner chat whose stuck screen the helper reads "
                        "(runtime gaps C2)",
        "turn_reads": "how a turn ends in each provider's own records",
        "reads_its_screen": "only Claude Code's idle input line and turn records are read as facts (plan C5); another "
                            "provider keeps its clocks until its own are read",
        "cmd_chat_session": "reading a conversation id out of each provider's own records",
        "cmd_connect": "registering the Fleet MCP server with each provider's own CLI configuration",
        "cmd_check": "checking that registration with each provider's own command",
    },
    # What one ACP program does in its own way is code, and acp_programs.py is its one place: an adapter for each
    # program, which an entry names with `acp_adapter`. The adapters are chosen by that name and compare none, and so
    # does the runner that calls them: a fifth program is a row of the table, an adapter and a pin.
    "acp_programs.py": {},
    "acp_runner.py": {},
}
# A fourth provider, to prove an entry is the whole edit. It is a terminal CLI with an owner chat and no sign-in.
FOURTH = {
    "label": "Fourth", "driver": "terminal", "acp_command": None, "can": {"shell", "web"},
    "full_access": {"start": "fourth --wide-open {prompt}"},
    "manager_access": {"start": "fourth --wide-open --every-tool {prompt}"},
    "first_worker": "fourth --asks-first {prompt}",
    "manager": True, "owner_chat": True, "agent_messages": True, "conversation": False, "conversation_why": None,
    "mcp_servers": True, "app_server": False, "switch": False, "session_settings": False, "token_in_env": True,
    "model_flags": {"model": ["--model", "{}"], "effort": ["--effort={}"]}, "local_model": None,
    "sign_in": None, "no_sign_in": "Sign in to Fourth yourself on {where} machine.", "sandbox": None,
    "screen_counter": False, "browser_tabs": False,
}


class TheFacts(unittest.TestCase):
    """Each entry holds every fact, and every fact is the one the fleet acted on before the table."""

    def test_every_entry_holds_every_fact(self):
        self.assertEqual(set(lifecycle.RUNTIMES), set(BEFORE))
        for name, entry in lifecycle.RUNTIMES.items():
            self.assertEqual(set(entry), set(lifecycle.RUNTIME_FACTS), f"{name} is missing or invents a fact")

    def test_the_facts_of_the_acp_programs_are_the_ones_of_their_spec(self):
        """The AI providers build: each new fact of each entry, by hand. Both programs stay workers that the owner
        cannot switch to, talk to or put the manager on, until a later step says so."""
        self.assertEqual(set(ACP_FACTS), set(lifecycle.RUNTIMES))
        for name, facts in ACP_FACTS.items():
            for fact, want in facts.items():
                with self.subTest(name=name, fact=fact):
                    self.assertEqual(lifecycle.RUNTIMES[name][fact], want)
        for name in ("grok", "opencode"):
            entry = lifecycle.RUNTIMES[name]
            for fact in ("manager_access", "sandbox", "cache_seconds", "compact_tokens", "routine", "default_model",
                         "task_denied", "task_allowed", "conversation_denied", "manager_denied", "conversation_why"):
                self.assertIsNone(entry[fact], f"{name}: {fact}")
            for fact in ("manager", "owner_chat", "agent_messages", "conversation", "switch", "app_server",
                         "session_settings", "browser_tabs", "screen_counter"):
                self.assertIs(entry[fact], False, f"{name}: {fact}")

    def test_a_pinned_program_has_its_pin_and_no_vendor_installer(self):
        """A runtime with `pinned` comes from the fleet's own download (fleet.install_pinned), so its pin has a file
        for both Linux processors, and no installer of its vendor is written for it (onboard.RUNTIME_PINS)."""
        for name, entry in lifecycle.RUNTIMES.items():
            with self.subTest(name):
                self.assertIsInstance(entry["pinned"], bool)
                self.assertEqual(name in onboard.PINNED, entry["pinned"])
                if entry["pinned"]:
                    self.assertLessEqual({"linux-x64", "linux-arm64"}, set(onboard.PINNED[name]["files"]))
                    self.assertNotIn(name, onboard.RUNTIME_PINS)
                    self.assertTrue(lifecycle.pinned_path(name, "/home/a").startswith("/home/a/.fleet/runtimes/"))
                else:
                    self.assertIsNone(lifecycle.pinned_path(name, "/home/a"))

    def test_each_acp_runtime_names_an_adapter_that_exists_and_each_adapter_is_named(self):
        """The code of one ACP program has one home (the AI providers spec, section 3.11 item 12): its adapter in
        acp_programs.py, which its entry names. An entry with no adapter of its own gets the standard one."""
        named = {entry["acp_adapter"] for entry in lifecycle.RUNTIMES.values() if entry["acp_adapter"]}
        self.assertEqual(named, set(acp_programs.ADAPTERS))
        for name, entry in lifecycle.RUNTIMES.items():
            with self.subTest(name):
                if entry["driver"] == "acp":
                    self.assertIn(entry["acp_adapter"], acp_programs.ADAPTERS)
                    adapter = acp_programs.adapter(entry["acp_adapter"], "/home/a")
                    self.assertIsInstance(adapter, acp_programs.Program)
                    # its sessions have a folder of their own, so that no credential that the program stored
                    # reaches one, and each variable of that folder is one of the program's own names
                    folder = adapter.folder("s")
                    self.assertTrue(folder.startswith("/home/a/.fleet/"), folder)
                    self.assertTrue(adapter.session_env("s"))
                    for variable, value in adapter.session_env("s").items():
                        self.assertTrue(variable.startswith(entry["own_env"]), variable)
                        self.assertTrue(value.startswith(folder), value)
                else:
                    self.assertIsNone(entry["acp_adapter"])
        self.assertIs(type(acp_programs.adapter(None)), acp_programs.Program)
        with self.assertRaises(KeyError):
            acp_programs.adapter("no-such-program")
        self.assertIn("acp_programs.py", MECHANICS)

    def test_the_names_of_a_programs_own_variables_and_of_its_key(self):
        """own_env is what keeps a program's own settings out of its session without a new reserved name (a new one
        in ENV_RESERVED could refuse a live team.json): prefixes that end in _. key_env has the shape of a variable's
        name. And a runtime of driver acp holds each fact of its kind, or says None for it."""
        for name, entry in lifecycle.RUNTIMES.items():
            with self.subTest(name):
                acp = entry["driver"] == "acp"
                self.assertEqual(entry["own_env"] is not None, acp)
                self.assertEqual(entry["key_env"] is not None, acp)
                self.assertEqual(entry["acp_quiet"] is not None, acp)
                if acp:
                    self.assertIsInstance(entry["own_env"], tuple)
                    self.assertTrue(entry["own_env"])
                    for prefix in entry["own_env"]:
                        self.assertRegex(prefix, r"\A[A-Z][A-Z0-9]*_\Z")
                    self.assertTrue(lifecycle.KEY_ENV.fullmatch(entry["key_env"]), entry["key_env"])
                    self.assertTrue(entry["key_env"].endswith(lifecycle.KEY_SUFFIXES), entry["key_env"])
                    self.assertIn(entry["acp_models"], ("initialize", "session", None))
                    for variable, value in {**entry["acp_quiet"], **(entry["memory_off"].get("env") or {})}.items():
                        self.assertTrue(lifecycle.KEY_ENV.fullmatch(variable), variable)
                        self.assertIsInstance(value, str)
                        # each variable that the fleet's own start sets is one of the program's own names
                        self.assertTrue(variable.startswith(entry["own_env"]), variable)
        self.assertEqual(lifecycle.ENV_RESERVED.pattern,
                         r"(?:FLEET|BWS|LD|DYLD|ANTHROPIC|CLAUDE|CODEX|XAI)_[A-Z0-9_]*|PATH|HOME|SHELL|USER|LOGNAME|"
                         r"TMPDIR|TERM|PWD|IFS|ENV|BASH_ENV|ZDOTDIR|NODE_OPTIONS|PYTHONPATH|PYTHONHOME")

    def test_every_runtime_says_how_its_own_memory_stays_off_and_its_starts_do_it(self):
        """What an agent learns lives in the hub, where the owner reads it: a memory of the runtime's own would steer
        later sessions where nobody sees it. So each entry names its switch, and a new provider must name its own."""
        for name, entry in lifecycle.RUNTIMES.items():
            with self.subTest(name):
                self.assertEqual(len(entry["memory_off"]), 1, entry["memory_off"])
                self.assertIn(next(iter(entry["memory_off"])), ("env", "config", "settings"))
        self.assertEqual(fleet.CODEX_NO_MEMORY, ["-c", "features.memories=false"])
        self.assertEqual(fleet.CODEX_UNATTENDED[-2:], fleet.CODEX_NO_MEMORY)
        self.assertEqual(fleet.CLAUDE_NO_MEMORY, {"autoMemoryEnabled": False})
        self.assertIsNot(fleet.CLAUDE_NO_MEMORY, lifecycle.RUNTIMES["claude"]["memory_off"]["settings"])

    @unittest.skipUnless(shutil.which("codex"), "needs the codex CLI")
    def test_the_installed_codex_takes_its_memory_switch_over_a_users_own_config(self):
        """A Codex on a Mac reads that user's config, and the owner's own one turns memories on."""
        home = tempfile.mkdtemp(prefix="fleet-codex-home-")
        self.addCleanup(shutil.rmtree, home, True)
        Path(home, "config.toml").write_text("[features]\nmemories = true\n")

        def memories(*options):
            out = subprocess.run(["codex", *options, "features", "list"], capture_output=True, text=True, timeout=60,
                                 env=dict(os.environ, CODEX_HOME=home)).stdout
            return next((line.split()[-1] for line in out.splitlines() if line.split()[:1] == ["memories"]), None)
        self.assertEqual(memories(), "true")
        self.assertEqual(memories(*fleet.CODEX_NO_MEMORY), "false")

    def test_the_facts_are_the_ones_the_old_constants_gave(self):
        for name, before in BEFORE.items():
            with self.subTest(name):
                entry = lifecycle.RUNTIMES[name]
                for fact, want in before.items():
                    if fact in ("sign_in_url", "shows_code", "wants_code"):
                        continue
                    self.assertEqual(entry[fact], want, f"{name}: {fact}")
                flow = entry["sign_in"]
                self.assertEqual(flow["url"].pattern if flow else None, before["sign_in_url"], name)
                self.assertEqual(flow["shows_code"].pattern if flow and flow["shows_code"] else None,
                                 before["shows_code"], name)
                self.assertEqual(flow["wants_code"] if flow else None, before["wants_code"], name)

    def test_the_derived_names_still_say_what_they_said(self):
        """The hub, the helper and both installers kept their own copies of these. Each is one read of the table
        now, and each must still hold the same names in the same order: a message prints some of them."""
        self.assertEqual(hub.SWITCH_RUNTIMES, ("codex", "claude"))
        self.assertEqual(lifecycle.SWITCH_RUNTIMES, ("codex", "claude"))
        self.assertEqual(hub.LOGIN_RUNTIMES, ("claude", "codex"))
        self.assertEqual(lifecycle.MCP_RUNTIMES, ("claude", "codex", "grok", "opencode"))
        self.assertEqual(fleet.MANAGER_RUNTIMES, ("claude", "codex"))
        self.assertEqual(lifecycle.APP_SERVER_RUNTIME, "codex")
        self.assertEqual(hub.FULL_ACCESS, {n: BEFORE[n]["full_access"] for n in ("codex", "claude", "grok", "opencode")})
        self.assertEqual(hub.MANAGER_ACCESS, {n: BEFORE[n]["manager_access"] for n in ("codex", "claude")})
        self.assertEqual(hub.RUNTIME_CAN, {n: BEFORE[n]["can"] for n in ("codex", "claude", "grok", "opencode")})
        self.assertEqual(hubsetup.STARTS, {n: BEFORE[n]["manager_access"]["start"] for n in ("codex", "claude")})
        self.assertEqual(hubsetup.WORKER_STARTS,
                         {n: BEFORE[n]["first_worker"] for n in ("codex", "claude", "grok", "opencode")})
        self.assertEqual(server.LABELS, {"codex": "Codex", "claude": "Claude Code", "grok": "Grok",
                                         "opencode": "OpenCode"})
        self.assertEqual(fleet.LOGIN_LABELS, {"codex": "Codex", "claude": "Claude Code"})
        self.assertEqual(fleet.LOGIN_WANTS_CODE, ("claude",))
        self.assertEqual(sorted(fleet.LOGIN_SHOWN_CODE), ["codex"])
        self.assertEqual(sorted(fleet.LOGIN_URLS), ["claude", "codex"])
        self.assertEqual(lifecycle.TOOL_CATALOG["github"]["runtimes"], ["claude", "codex", "grok", "opencode"])

    def test_the_derived_forms_are_copies_and_not_the_table_itself(self):
        """team.json takes a start form from these, so a caller that keeps or edits one must not reach the table."""
        self.assertIsNot(hub.FULL_ACCESS["claude"]["allow"], lifecycle.RUNTIMES["claude"]["full_access"]["allow"])
        self.assertIsNot(hub.RUNTIME_CAN["codex"], lifecycle.RUNTIMES["codex"]["can"])

    def test_an_entry_drives_a_sign_in_or_says_why_not_and_never_both(self):
        for name, entry in lifecycle.RUNTIMES.items():
            with self.subTest(name):
                self.assertEqual(bool(entry["sign_in"]), not entry["no_sign_in"])
                if entry["sign_in"]:
                    self.assertEqual(set(entry["sign_in"]),
                                     {"args", "url", "shows_code", "wants_code", "setup_cursor"})
                else:
                    self.assertIn("{where}", entry["no_sign_in"])

    def test_an_entry_that_cannot_hold_a_conversation_has_its_reason_or_the_general_one(self):
        for name, entry in lifecycle.RUNTIMES.items():
            with self.subTest(name):
                self.assertFalse(entry["conversation"] and entry["conversation_why"])

    def test_an_acp_entry_carries_its_command_and_a_terminal_one_does_not(self):
        for name, entry in lifecycle.RUNTIMES.items():
            with self.subTest(name):
                self.assertIn(entry["driver"], ("terminal", "acp"))
                self.assertEqual(bool(entry["acp_command"]), entry["driver"] == "acp")

    def test_only_a_runtime_with_a_set_of_its_own_can_be_a_switch_target(self):
        """hub.switch_offer reads RUNTIME_CAN[to], so an entry that carries no `can` must carry no `switch` either:
        the two go together, and a fourth provider that wants the switch writes both."""
        for name, entry in lifecycle.RUNTIMES.items():
            with self.subTest(name):
                self.assertFalse(entry["switch"] and not entry["can"])

    def test_a_driven_sign_in_needs_an_installer_of_its_own_as_well(self):
        """Two dicts that must agree. `server.LABELS` derives from the table's `sign_in` and `pinned`, and the install
        step lets a runtime through on it and then reads `onboard.RUNTIME_PINS[runtime]` for the version to install,
        or the pinned program of `onboard.PINNED`. An entry with a sign-in and no pin makes that step raise instead
        of refusing, so this is the fence. The pin and the vendor's own install and update lines stay in onboard.py,
        which the helper loads for its runtime updates, because they are shell and not facts: a fourth provider
        writes them there."""
        for name, entry in lifecycle.RUNTIMES.items():
            if entry["sign_in"]:
                self.assertTrue(name in onboard.RUNTIME_PINS or name in onboard.PINNED,
                                f"{name} has a driven sign-in and no installer pin")
            if entry["sign_in"] or entry["pinned"]:
                self.assertIn(name, server.LABELS, name)
            else:
                self.assertNotIn(name, server.LABELS, name)

    def test_a_name_that_is_no_runtime_answers_the_question_and_does_not_raise(self):
        for fact in lifecycle.RUNTIME_FACTS:
            self.assertIsNone(lifecycle.runtime_fact("gemini", fact), fact)
        self.assertFalse(lifecycle.runtime_fact(None, "owner_chat"))
        self.assertIsNone(lifecycle.switch_target("gemini"))
        self.assertIsNone(lifecycle.no_sign_in("gemini"))
        self.assertEqual(hub.runtime_label("gemini"), "gemini")     # the name itself, where there is no word for it

    def test_the_switch_target_is_the_other_switchable_runtime(self):
        """The offer is one target today because two entries carry `switch`. Making it more is the next step, and
        this function is where it happens."""
        self.assertEqual(lifecycle.switch_target("codex"), "claude")
        self.assertEqual(lifecycle.switch_target("claude"), "codex")
        self.assertIsNone(lifecycle.switch_target("grok"))
        with patch.dict(lifecycle.RUNTIMES, {"fourth": dict(FOURTH, switch=True)}):
            table = dict(lifecycle.RUNTIMES)
            self.assertEqual(tuple(n for n, e in table.items() if e["switch"]), ("codex", "claude", "fourth"))
            # Three switchable runtimes mean the offer is no longer "the other one", and it says so rather than
            # guessing: SWITCH_RUNTIMES is read once at import, so this proves the rule and not the constant.
            self.assertIsNone(lifecycle.switch_target("nobody"))

    def test_the_words_the_owner_reads_come_from_the_entry(self):
        self.assertEqual(lifecycle.no_sign_in("grok", "this"),
                         "Fleet drives no Grok sign-in: xAI's terms do not let a third party run it this way. "
                         "Sign in to Grok yourself on this machine.")
        self.assertEqual(lifecycle.no_sign_in("grok", "that").count("that machine"), 1)
        self.assertEqual(hub.runtime_label("claude"), "Claude Code")


class NoSecondHome(unittest.TestCase):
    """The source itself: no decision anywhere reads a runtime's name except the mechanics that are named."""

    NAMES = set(lifecycle.RUNTIMES)

    def comparisons(self, name):
        """{the function it is in: the runtime names it compares against} for one module: every ==, != or `in`
        with a runtime's name on either side, whatever the other side is. A comparison outside every function is
        filed under the module itself. The scan is deliberately wide: a decision about a runtime looks like this
        however it is written, and a fact belongs in the table however it is spelled."""
        found = {}

        def walk(node, holder):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.Compare):
                    said = {w for side in (child.left, *child.comparators) for w in self.words(side)}
                    if said & self.NAMES:
                        found.setdefault(holder, []).extend(sorted(said & self.NAMES))
                walk(child, child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else holder)

        walk(ast.parse((KIT / name).read_text()), name)
        return {k: sorted(set(v)) for k, v in found.items()}

    @staticmethod
    def words(node):
        """Every string constant in one side of a comparison, tuples and lists included."""
        return {n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)}

    def test_only_the_named_mechanics_still_compare_a_runtime_to_a_name(self):
        for name, allowed in MECHANICS.items():
            with self.subTest(name):
                self.assertEqual(sorted(self.comparisons(name)), sorted(allowed),
                                 f"{name}: a comparison of a runtime against a name moved, appeared or went away. "
                                 f"A new one belongs in lifecycle.RUNTIMES, or in MECHANICS with its reason.")

    def test_the_table_is_where_a_runtime_is_named(self):
        """hub.py decides nothing from a name any more: its one mention is the pointer into Codex's own entry that
        the device sign-in prompt of a server install is checked against."""
        text = (KIT / "hub.py").read_text()
        named = [line.strip() for line in text.splitlines() if any(f'"{n}"' in line for n in self.NAMES)]
        self.assertEqual(named, ['CODEX_SIGN_IN = RUNTIMES["codex"]["sign_in"]["url"]     '
                                 '# the link of its own device sign-in (sign_in_prompt)'],
                         "hub.py names a runtime again. The fact belongs in lifecycle.RUNTIMES, and a pointer into "
                         "one entry belongs in this assertion with the reason it is that runtime's own.")


class AFourthEntry(unittest.TestCase):
    """A provider the fleet has never heard of, taught to it by one entry and nothing else."""

    def setUp(self):
        self.patch = patch.dict(lifecycle.RUNTIMES, {"fourth": FOURTH})
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_its_facts_are_read_everywhere_a_fact_is_read(self):
        self.assertEqual(hub.runtime_label("fourth"), "Fourth")
        self.assertTrue(hub.owner_chat({"role": "worker", "runtime": "fourth"}))
        self.assertTrue(lifecycle.runtime_fact("fourth", "agent_messages"))
        self.assertFalse(lifecycle.runtime_fact("fourth", "conversation"))
        self.assertEqual(lifecycle.no_sign_in("fourth", "this"), "Sign in to Fourth yourself on this machine.")
        self.assertEqual(fleet.model_flags({"runtime": "fourth", "model": "big", "effort": "high"}),
                         "--model big --effort=high")
        self.assertEqual(fleet.settings_arg("a", {"runtime": "fourth", "role": "worker"}, None), "")
        self.assertIsNone(lifecycle.switch_target("fourth"))        # its entry says no switch

    def test_team_json_takes_an_agent_of_it_and_refuses_a_name_with_no_entry(self):
        team = {"hub": {"machine": "hub", "port": 8765},
                "addresses": {"hub": "100.64.0.1", "owner": "100.64.0.2"},
                "agents": {"manager": {"role": "manager", "machine": "hub", "runtime": "fourth",
                                       "can": ["shell", "web"], "vault": "none",
                                       "start": FOURTH["manager_access"]["start"]}}}
        hub.validate_team(team)                                     # an entry is all it took
        team["agents"]["manager"]["runtime"] = "fifth"
        with self.assertRaises(ValueError) as refused:
            hub.validate_team(team)
        self.assertIn("claude, codex, fourth, grok or opencode", str(refused.exception))

    def test_a_task_session_starts_it_from_its_own_start_form(self):
        conf = {"role": "worker", "runtime": "fourth", "start": FOURTH["full_access"]["start"], "can": ["shell"]}
        with patch.object(fleet, "team_catalog", dict), patch.object(fleet, "session_env", lambda *a, **k: {}):
            command = fleet.session_command("alpha", conf, "do the thing", task="T-1", generation="g1")
        self.assertIn("fourth --wide-open", command)
        self.assertNotIn("acp_runner.py", command)                  # a terminal driver, as its entry says

    def test_an_acp_provider_needs_no_more_than_its_command(self):
        entry = dict(FOURTH, driver="acp", acp_command="fourth agent stdio", owner_chat=False, manager=False)
        files = tempfile.mkdtemp(prefix="fleet-fourth-")       # the session's prompt is a file of the window
        self.addCleanup(shutil.rmtree, files, True)
        with patch.dict(lifecycle.RUNTIMES, {"fourth": entry}):
            with patch.object(fleet, "team_catalog", dict), patch.object(fleet, "session_env", lambda *a, **k: {}), \
                    patch.object(fleet, "SESSIONS", files), patch.object(fleet, "HOME", files):
                command = fleet.session_command("alpha", {"role": "worker", "runtime": "fourth"}, "do it",
                                                task="T-1", generation="g1", session="s1")
            self.assertIn("acp_runner.py", command)
            # with no pin, no adapter and no fact of its own, its command is its entry's, and the runner speaks
            # standard ACP to it
            self.assertIn("--agent-command 'fourth agent stdio'", command)
            self.assertIn("--runtime fourth", command)
            self.assertIn("--policy full", command)
            self.assertEqual([Path(files, name).read_text() for name in os.listdir(files)], ["do it"])
            with self.assertRaises(fleet.Refused) as refused:
                fleet.chat_command("alpha", {"role": "worker", "runtime": "fourth"}, "g1")
            self.assertIn("a Fourth agent has no direct chat yet", str(refused.exception))

    def test_the_installers_and_the_server_service_read_it_when_they_next_start(self):
        """These names are one read of the table at import, so a running program keeps the set it started with and
        a new entry reaches it on the next start. The rule is what matters, and here it is, applied to a table
        that holds the fourth entry."""
        starts = {n: e["manager_access"]["start"] for n, e in lifecycle.RUNTIMES.items() if e["manager_access"]}
        workers = {n: e["first_worker"] for n, e in lifecycle.RUNTIMES.items() if e["first_worker"]}
        labels = {n: e["label"] for n, e in lifecycle.RUNTIMES.items() if e["sign_in"] or e.get("pinned")}
        self.assertEqual(starts["fourth"], FOURTH["manager_access"]["start"])
        self.assertEqual(workers["fourth"], FOURTH["first_worker"])
        self.assertNotIn("fourth", labels)      # no sign-in of its own and no pinned program: this service installs none
        self.assertEqual(hubsetup.STARTS, {k: v for k, v in starts.items() if k != "fourth"})
        self.assertEqual(hubsetup.WORKER_STARTS, {k: v for k, v in workers.items() if k != "fourth"})
        self.assertEqual(server.LABELS, labels)
        self.assertFalse(usage.local_model({"runtime": "fourth", "start": "fourth --oss"}))

    def test_what_an_entry_alone_does_not_buy(self):
        """Written down on purpose (see the result of this change): these are real work for a fourth provider, and
        the table only says that the fleet has none of them yet."""
        entry = dict(FOURTH, no_sign_in=None,
                     sign_in={"args": ["login"], "url": None, "shows_code": None, "wants_code": True})
        with patch.dict(lifecycle.RUNTIMES, {"fourth": entry}):
            # The sign-in command comes out of the entry, and the window around it is still fleet.do_signin's.
            self.assertEqual(fleet.runtime_login_command("fourth", "/x/fourth"), "exec /x/fourth login")
            # Its allowance has no reader: usage.Collector knows two routes, and neither is this one.
            self.assertNotIn("fourth", usage.SOURCES)
            self.assertNotIn("fourth", usage.LIMIT_SOURCES)
            # And the owner can read no sandbox of it, because its entry says the fleet cannot read one.
            self.assertIsNone(lifecycle.runtime_fact("fourth", "sandbox"))
            self.assertEqual(hub.start_sandbox({"runtime": "fourth", "start": "fourth --wide-open"}),
                             "The runtime's sandbox is unknown.")


if __name__ == "__main__":
    unittest.main()

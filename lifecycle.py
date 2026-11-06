"""Machine status reports and idle-only Fleet updates for one helper (owner API 1.2).

The helper reports what its machine runs and how it is protected, using only commands that need
no root. It updates its own Fleet checkout only when it has no task session: a fast-forward to the
hub's revision, then a restart of its own service. A failed step is reported; nothing is forced.
While an update runs, no task or chat session can start (see session_start).

It also updates the agent runtimes of its OS user, at most every six hours and only while no session of that user
works: the vendor's own update, a check of the new version, and the previous version back when the check fails
(update_runtimes).
"""
import contextlib
import fcntl
import glob
import json
import os
import plistlib
import pwd
import queue
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

import onboard      # the vendors' installers, which the runtime updates run (update_runtime)

REPORT_EVERY = 300          # seconds between status reports when nothing changes
RETRY_MAX = 30              # seconds at most between the tries of a status report that did not reach the hub
# What `tailscale status --json` can say of itself. `Starting` is up, as for Tailscale's own command: it lasts until the
# first live peer or relay. Any other state says neither.
TAILSCALE_UP, TAILSCALE_DOWN = ("Running", "Starting"), ("Stopped", "NeedsLogin", "NeedsMachineAuth")
# The server's own hardening, which the join sets (hubsetup.harden) and each reading reads again as any user, because
# `sshd -T` needs root: sshd's own files, npm's file for every user, and apt's record of its last good upgrade, which
# apt.systemd.daily writes only after unattended-upgrade ended well.
SSHD_CONFIG = "/etc/ssh/sshd_config"
NPMRC = "/etc/npmrc"
NPM_DAYS = 7
UPGRADE_STAMP = "/var/lib/apt/periodic/upgrade-stamp"
SSHD_PASSWORDS = ("passwordauthentication", "kbdinteractiveauthentication")     # sshd's default for each is yes


def sshd_settings(path, wanted, found, depth=0):
    """The first value of each wanted setting in sshd's file and the files it includes, in sshd's own order: sshd takes
    the first value it reads, an Include reads its files where it stands, and a Match block applies only to some
    connections, so the rest of its file is not read. False when a file that could still set one cannot be read."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return False
    for line in lines:
        words = re.split(r"[\s=]+", line.strip(), maxsplit=1)
        key = words[0].lower()
        if not key or key.startswith("#") or len(words) < 2:
            continue
        if key == "match":
            return True
        if key == "include" and depth < 8:
            for pattern in words[1].split():
                folder = os.path.dirname(SSHD_CONFIG)
                for one in sorted(glob.glob(pattern if pattern.startswith("/") else os.path.join(folder, pattern))):
                    if not sshd_settings(one, wanted, found, depth + 1):
                        if any(w not in found for w in wanted):
                            return False
        elif key in wanted and key not in found:
            found[key] = words[1].split()[0].strip('"').lower()
    return True


def sshd_keys_only(path=SSHD_CONFIG):
    """Whether sshd lets nobody in with a password: True, False, or None when its files cannot say (none, or one that
    this user cannot read before both settings are found)."""
    found = {}
    if not os.path.exists(path) or not sshd_settings(path, SSHD_PASSWORDS, found):
        return None
    return all(found.get(key, "yes") == "no" for key in SSHD_PASSWORDS)


def npm_rule(path=NPMRC, system="/usr/local/bin:/usr/bin:/bin"):
    """Whether npm's file for every user holds back a package version newer than NPM_DAYS: True, False (no such line, or
    fewer days), or None when it cannot be read or the system has no npm, which then has nothing to hold back."""
    if not shutil.which("npm", path=system):
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except FileNotFoundError:
        return False
    except OSError:
        return None
    days = re.findall(r"(?m)^\s*min-release-age\s*=\s*(\d+)\s*$", text)
    return bool(days) and int(days[-1]) >= NPM_DAYS


def upgraded_at(path=UPGRADE_STAMP):
    """When apt's daily run last ended a security upgrade well, or None when it has not yet."""
    try:
        return os.path.getmtime(path)
    except OSError:
        return None
OWNER_ONLY = re.compile(r"(?:^|/)(?:test_[^/]*|ui_fixture|selftest|verify|pilot|vault|place)\.py$")  # never loaded here
TICK = 15                   # seconds between idle checks
RESTART_GRACE = 120         # seconds this process may live on after it asked for its own restart
CONFIG_BRANCH = "config"    # the configuration ref that the fleet runs: the hub writes it, the code branch waits
                            # for a deployment (RULES.md "Where work goes")
BRANCH_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,100}")
# An agent's own skills (runtime gaps, design v4 D): skills/<agent>/<name>/SKILL.md on the configuration ref, and a few
# small files beside it, which the hub writes for that agent and nothing else writes. A script among them is no Fleet
# code: no helper loads it, so a checkout that gained one runs the code it ran before (Lifecycle.running).
SKILLS = "skills"
SKILL_NAME = r"[a-z0-9][a-z0-9-]{0,63}"         # a skill's folder, which is its name
SKILL_FILE = r"(?:[A-Za-z0-9_][A-Za-z0-9._-]{0,63}/){0,2}[A-Za-z0-9_][A-Za-z0-9._-]{0,63}"   # a file in that folder


FEATURES = ["trigger_check", "agent_setup", "trigger_code", "screen_model", "agent_key", "broker_callers",
            "runtime_switch", "login_create", "login_capture", "api_request",
            "app_server_tasks",     # helper abilities that the hub may use; app_server_tasks: app_server_task below
            "manager_switch",       # the manager's helper closes its previous runtime's session after a switch
            "mcp_program",          # it resolves a command MCP server's program for POST /ui/mcp/check
            "secret_deposits",      # it carries a sealed copy of the owner's into this machine's vault (deposit)
            "secret_withdrawals",   # it has this machine's vault take back a secret nobody here holds (withdraw)
            "task_outputs",         # it sends a delivered task's outputs folder to the hub (fleet.collect_outputs)
            "status_now",           # it reports at once when the hub asks (event status_now, report_soon)
            "chat_warm",            # it starts the owner chat before a message when the hub says so (keep_chat)
            "conversation_reads",   # a conversation's event stays until its session reads it (plan C5)
            "turn_close",           # a delivered task's window closes at the end of its turn (plan C5)
            "start_once",           # it starts each attempt once and says why a start failed (plan C6)
            "prompt_polls",         # its hooks and runners ask again for a permission prompt until it is decided (C7)
            "job_runs",             # it acks a job before it runs it and lists the jobs it holds in each poll (C7)
            "session_kinds",        # its usage report gives each session's four kinds of tokens (plan P8)
            "check_runs",           # it lists the check runs it holds in each poll, and no claim expires (C12)
            "update_between_turns",     # its update waits for the turns that run in its task windows (plan P0)
            "stable_start",             # a task session opens with its rules and profile, and its task last (P9.2)
            "session_reuse",            # a cold, grown or switched standing session starts fresh (P9.10)
            "fresh_tasks",              # a cold, grown or switched task window asks for a fresh attempt (P9.10)
            "stable_standing",          # the manager and an owner chat start with their rules and profile first
            "fresh_conversations",      # a cold, grown or switched tools-on conversation window closes (P9.10)
            "task_denied",              # a task session denies its runtime's task_denied (AUTONOMY.md decision 36)
            # AUTONOMY.md P2, P10 (lane L2): a conversation with the agent's own tools (conversation_work_command), a
            # closed one on the chosen runtime at its pinned version, and the records of a conversation's session
            "conversation_tasks",
            "check_lines",      # it runs checks that print lines, with the agent's read keys and its error output (P4)
            "chat_tools",       # an owner chat whose tools changed starts again between turns, on its conversation
            "stuck_screens",    # a question that stands on a screen nobody reads ends its session (runtime gaps C1, C2)
            # AUTONOMY.md decision 41: a task session runs Workflow, and its records keep a workflow open until its own
            # end notice; no session of it offers a tool that asks a person on its screen
            "workflow_tasks",
            "stable_skills",    # a session's stable text lists the agent's own skills (skills_text, design v4 D3)
            # its usage report gives each session's tokens by model, its sub-agents' and workflow agents' with them,
            # and each scan reads only what the transcripts gained (plan P8, decision 41)
            "session_models",
            # support plan F1: a task session of an agent whose Shell box is off starts closed (fleet.shell_off): the
            # pinned Claude Code, the built-in tools that the hub names, its own MCP servers only, and no key; and
            # F3: an MCP server of auth "mint" gets a token for that one session through the vault (mint_tokens)
            "shell_box",
            "signin_relink"]    # its sign-in waits out a hub that is away and sends its link again (send_link)
# ---------------------------------------------------------------- the runtimes
#
# What the fleet knows about a runtime is here, in one entry for each provider, and nowhere else. hub.py, fleet.py and
# both installers import this module, so a fact written here once is the fact the whole fleet acts on, and a new
# provider is an entry and not a lane. The owner's words, 20 October 2026: "the idea is to support many different
# providers".
#
# Every field is named for what it MEANS and not for who has it, so a check that reads one says what it is really
# asking. A field the fleet writes nothing for is None, which is a fact of its own: a runtime with no manager_access
# cannot be the manager, a runtime with no sign_in is one the owner signs in to themselves.
#
#   label             what the owner is shown, never the key
#   driver            "terminal" (a CLI in a tmux window) or "acp" (Agent Client Protocol, through acp_runner.py)
#   acp_command       the agent command of an acp runtime, when team.json "start" gives none
#   can               the kinds of work its sessions do, where the fleet writes a set; None when it writes none, and
#                     then no agent can be switched to it (hub.switch_offer)
#   full_access       Fleet's full-access form of a worker or a lead, {start, allow}; None when Fleet writes none.
#                     Full access is no runtime limit on files, commands or the network and no permission prompt.
#                     Fleet's own deny rules still apply to every Claude session, and Claude's bypassPermissions is
#                     not the form used for it, because that shows a prompt at start unless the user turned it off.
#                     The separately opted-in app_server_pair has different permissions.
#   manager_access    the form a manager of this runtime starts with, {start}; None when it cannot be the manager.
#                     The owner's correction of 13 October 2026: Claude Code with every built-in tool and no
#                     permission check (its settings turn the start prompt off and add no Fleet deny rule that
#                     limits a command or a file), and Codex as its own full_access; since AUTONOMY.md decision 41
#                     every built-in tool but its runtime's manager_denied. A switch of the manager keeps this access
#                     both ways.
#   first_worker      the start the hub installer writes for the first worker of a fleet, which has no other worker to
#                     copy from (hubsetup.WORKER_STARTS), with the allow list of full_access; None when it writes none.
#                     It is the full-access form (the owner, 26 October 2026: workers act without asking), with the
#                     browser's place kept for a browser task
#   manager           its standing session continues its own conversation, so a manager can run on it
#   owner_chat        the owner can talk to an agent of this runtime in that agent's own chat window
#   agent_messages    its agents send and answer agent messages
#   conversation      its session can be locked down to the conversation tools of another person (C-<id>)
#   conversation_why  why it cannot be, in the words that person reads; None when it can
#   closed_versions   the versions of it that passed the lockdown test (test_conversation_lockdown's LiveProof and
#                     Pinned), the default first: with contacts.v2 a closed conversation runs at one of them and at
#                     no other, at the first unless the owner chose another (AUTONOMY.md P10, decision 35). A version
#                     joins only in a release whose lockdown test passed; () where none did
#   mcp_servers       its task sessions load the owner's MCP servers and the catalog tools
#   app_server        the fleet drives it over its own app-server protocol: screen tasks, and the app-server start
#                     policy of a worker or a lead (screen_runner.py)
#   switch            the owner can switch an agent to it and from it (owner feature runtime_switch)
#   session_settings  Fleet writes the session's permissions, deny rules and hooks as a settings argument
#                     (fleet.settings_arg)
#   token_in_env      its session reads the session credential from the environment; a runtime without it takes that
#                     credential in its MCP configuration instead (owner API 1.12)
#   model_flags       how a model and an effort reach a new session, as this runtime's own flags; None for one that
#                     takes neither
#   local_model       the start-command flag by which it runs a model on the machine itself; None when it has none
#   sign_in           the sign-in the fleet drives for it, or None: {args, after the executable; url, the provider's
#                     own link as it is read from the screen, and the hub takes the machine's word for it only when
#                     the whole link matches this; its length allows for the scopes and the challenge a provider
#                     puts in one (Claude Code's ran to 465 characters on 21 October 2026, and 400 refused it);
#                     shows_code, the code the provider prints, or None;
#                     wants_code, it waits for a code the owner pastes; setup_cursor, how a first-run question of
#                     its own shows that it is waiting on a choice, or None for a runtime that asks none}
#   sign_out          the sign-out the fleet drives for it, or None: {args, after the executable}. It exists for one
#                     reason: a provider will not start a second sign-in while one is live, so an owner who wants a
#                     DIFFERENT account of the same provider needs this half first (hub.start_machine_login, replace)
#   no_sign_in        why the fleet drives none, in the words the owner reads ({where}: this machine or that one);
#                     None when it drives one
#   sandbox           how its start command says what it may touch, as the owner reads it; None when Fleet cannot
#                     read it
#   screen_counter    a running turn of its terminal session repaints an elapsed counter every second, read live on
#                     the fleet's machines, so the screen watch takes a running screen that stopped changing for a
#                     frozen runtime (fleet.Helper.watch_screens, plan C2); False where nobody has read it
#   cache_seconds     how long the provider keeps a session's prompt cache after its last model call, as far as
#                     the fleet knows; a session told of a message later than that reads its whole context again at
#                     the price of writing it (plan P9.10, session_reuse). A session's own records can say less (a
#                     Claude session on a five-minute cache). None where the fleet knows nothing
#   compact_tokens    the context at which a session of it compacts its conversation as Fleet starts it; the reuse
#                     rule leaves room before it. None where the fleet knows nothing
#   routine           the model and effort of routine work on it, {model, effort}, None for the runtime's own
#                     default model: what an agent's one changer reaches for first (plan P9.7, P8)
#   task_denied       the built-in tools that the owner took away from its task sessions, which their settings deny
#                     (AUTONOMY.md decisions 36 and 41, helper feature task_denied): every other tool stays, also a
#                     tool that a later version adds or renames; None where it has none of them
#   task_allowed      the built-in tools that its task sessions run without asking, beside the agent's own allow
#                     list, because its permission mode would refuse them unasked (decision 41); None for none
#   conversation_denied   what the settings of a conversation with the agent's own tools deny (decision 41): a
#                     task session's list and the tools that only task work has; None where it has none of them
#   manager_denied    what the manager's settings deny of its built-in tools, which are otherwise all its own (the
#                     owner, 13 October 2026; decision 41): the ones that ask a person on a screen that nobody reads
#   task_opening      how a task session that opens with its stable text first (helper feature stable_start, plan
#                     P9.2) gets its task: "read", in its first read_messages answer, because the rules and the
#                     profile are its appended system prompt; "prompt", at the end of its first prompt, because it
#                     reads RULES.md as its folder's AGENTS.md; None where Fleet starts none so
#   token_weights     its list prices in dollars per million tokens, {model key: {input, cache_read, cache_write,
#                     output}}, so that the cost of a session compares across providers (AUTONOMY.md P8, P10); on a
#                     subscription account they are weights, not money spent. A session's model takes the entry
#                     whose key is the longest part of its name, else "default". The owner's own prices are in
#                     team.json runtime_facts (facts_now); None for no prices
#
# What is NOT here, because it is code and not a fact: how a runtime's records become a transcript (threads.py), how
# its allowance is read (usage.py), what its own installer is (onboard.py), and how its sign-in window is driven to
# the end (fleet.do_signin). A fourth provider needs real work in each of those.
RUNTIMES = {
    "codex": {
        "label": "Codex",
        "driver": "terminal",
        "acp_command": None,
        "can": {"shell", "web", "screen"},              # screen tasks use the agent's own screen runtime
        # One line for all three forms, as it is on the pilot's own workers: this runtime has no narrower mode
        # Founderizer uses, so its manager and a fleet's first worker start exactly as any worker does.
        "full_access": {"start": "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"},
        "manager_access": {"start": "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"},
        "first_worker": "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}",
        "manager": True,
        "owner_chat": True,
        "agent_messages": True,
        "conversation": False,
        # Why a Codex agent has no conversations yet (CHAT-APPS.md 7.2), from test_conversation_lockdown's live proof
        # with Codex 0.160: no option takes away the global AGENTS.md of its CODEX_HOME, its MCP resource tools, or
        # the tools that OpenAI's model catalog gives each model (code mode, apply_patch, sub-agents).
        "conversation_why": ("a Codex agent has no conversations yet: no start option limits its tools to the Fleet "
                             "tools, and its global AGENTS.md always loads"),
        "closed_versions": (),          # 0.163 still offers its shell and its agent tools (27 October 2026)
        "mcp_servers": True,
        "app_server": True,
        "switch": True,
        "session_settings": False,
        "token_in_env": True,
        "model_flags": {"model": ["-m", "{}"], "effort": ["-c", 'model_reasoning_effort="{}"']},
        "local_model": "--oss",
        # Codex shows the owner a code to type into the browser; Claude gives the owner a code to type in here.
        "sign_in": {"args": ["login", "--device-auth"],
                    "url": re.compile(r"https://auth\.openai\.com/[A-Za-z0-9/_?=&.%-]{0,2000}"),
                    "shows_code": re.compile(r"\b[A-Z0-9]{4}-[A-Z0-9]{4,6}\b"), "wants_code": False,
                    "setup_cursor": None},
        "sign_out": {"args": ["logout"]},
        "no_sign_in": None,
        "sandbox": {"name": "Codex", "flag": "--sandbox", "value": "[a-z-]+", "unset": "the default",
                    "words": {"danger-full-access": "the runtime does not limit file or network access",
                              "workspace-write": "the runtime limits writes to the workspace",
                              "read-only": "the runtime allows reads only"},
                    "otherwise": "see the Codex settings"},
        "screen_counter": False,
        # a browser task runs in the app-server runner, whose native UI tools work the machine's own screen
        "browser_tabs": False,
        # OpenAI keeps a prompt's cache for some minutes of inactivity, and Codex keys it by its own thread
        # (prompt_cache_key), so a new Codex session reads little of another's
        "cache_seconds": 300,
        "compact_tokens": 200000,
        "routine": {"model": None, "effort": "low"},
        "task_denied": None,            # Codex has none of the tools that the owner took away
        "task_allowed": None,
        # Its ask tools go with a start option in every session instead (fleet.CODEX_UNATTENDED, decision 41)
        "conversation_denied": None,
        "manager_denied": None,
        "task_opening": "prompt",
        # gpt-6.1-sol's list prices as public price pages gave them on 27 October 2026, NOT checked on OpenAI's own
        # pricing page: the owner sets the right ones with runtime_facts. OpenAI charges no more for a cache write
        # than for input.
        "token_weights": {"default": {"input": 2.0, "cache_read": 0.1, "cache_write": 2.0, "output": 10.0}},
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
        # Fleet's full-access worker form, never the manager's bypass: a worker runs what its access allows without
        # asking (plan C15), and Fleet's deny list still applies to it (fleet.settings_arg). {chrome} gives a browser
        # task its browser, as a switch's form does not need to.
        "first_worker": "claude --permission-mode dontAsk {chrome} {settings} {prompt}",
        "manager": True,
        "owner_chat": True,
        "agent_messages": True,
        "conversation": True,
        "conversation_why": None,
        # On the owner's Mac, 27 and 28 October 2026, each with its updater off: only the Fleet tools and
        # fleet.CLAUDE_BUILT_INS, and only the hub's prompt. 2.1.308 first, because three of the four machines run it
        "closed_versions": ("2.1.308", "2.1.311", "2.1.312"),
        "mcp_servers": True,
        "app_server": False,
        "switch": True,
        "session_settings": True,
        "token_in_env": False,
        "model_flags": {"model": ["--model", "{}"], "effort": ["--effort", "{}"]},
        "local_model": None,
        # Signing Claude Code out puts its own first run back, so its sign-in can open behind a theme picker and a
        # "Select login method". `ready_runtime_config` answers those in the runtime's own file; this is what the
        # helper watches for when a question stands there anyway (a new one, or a version that asks it again).
        "sign_in": {"args": ["/login"],
                    "url": re.compile(r"https://(?:claude\.ai|claude\.com|console\.anthropic\.com)/[A-Za-z0-9/_?=&.%#+-]{0,2000}"),
                    "shows_code": None, "wants_code": True,
                    "setup_cursor": re.compile(r"(?m)^[^\S\n]*[\u276f\u203a>]\s+\S")},
        "sign_out": {"args": ["/logout"]},
        "no_sign_in": None,
        "sandbox": {"name": "Claude", "flag": "--permission-mode", "value": "[A-Za-z]+", "unset": "default",
                    "words": {},
                    "otherwise": "the session settings allow and deny tools; they are not an OS boundary"},
        # read on 2.1.285, 2.1.308 and 2.1.311 while a foreground `sleep 300` ran, 27 October 2026
        "screen_counter": True,
        # with --chrome each session works in a tab group of its own of Claude in Chrome: two sessions read, scrolled
        # and typed in their own tabs at the same time on one Mac, 30 October 2026
        "browser_tabs": True,
        "cache_seconds": 3600,          # an hour; its own records say when it is five minutes (fleet.claude_context)
        "compact_tokens": 200000,       # fleet.STANDING_COMPACT, the window that Fleet starts its standing sessions with
        "routine": {"model": "sonnet", "effort": "low"},
        # The owner, 27 October 2026: "Yes, remove Artifact, Workflow, AskUserQuestion, ReportFindings, Skill and
        # ListAgents from agent task sessions." On Claude Code 2.1.301, 2.1.304, 2.1.308, 2.1.311 and 2.1.312
        # (recorded against stand-ins), Claude Code then offers ArtifactComments and ArtifactData no more either, as
        # it offers them only together with Artifact. AUTONOMY.md decision 41, the owner on 28 October 2026: "when
        # AskUserQuestion from an agent, it should be its boss who gets the question! ... same for Workflows etc, I
        # think they are great". Workflow is back, and runs from the allow list, because it asks and dontAsk refuses
        # what asks. EnterPlanMode and ExitPlanMode go with AskUserQuestion: an approval card that nobody reads is a
        # question too. A question goes up with ask_my_requester.
        "task_denied": ["Artifact", "AskUserQuestion", "EnterPlanMode", "ExitPlanMode", "ReportFindings", "Skill",
                        "ListAgents"],
        "task_allowed": ["Workflow"],
        # a conversation with a person is no task work: it splits none of it
        "conversation_denied": ["Artifact", "AskUserQuestion", "EnterPlanMode", "ExitPlanMode", "ReportFindings",
                                "Skill", "ListAgents", "Workflow"],
        # the manager keeps Workflow, Skill and Artifact (his answer of 29 October 2026: Artifact stays with it)
        "manager_denied": ["AskUserQuestion", "EnterPlanMode", "ExitPlanMode"],
        "task_opening": "read",
        # Anthropic's list prices of 6 October 2026. Its sessions write one-hour caches, which cost twice the input.
        "token_weights": {"default": {"input": 4.0, "cache_read": 0.2, "cache_write": 8.0, "output": 20.0},
                          "fable": {"input": 10.0, "cache_read": 0.25, "cache_write": 20.0, "output": 50.0},
                          "opus": {"input": 4.0, "cache_read": 0.2, "cache_write": 8.0, "output": 20.0},
                          "sonnet": {"input": 2.0, "cache_read": 0.2, "cache_write": 4.0, "output": 10.0},
                          "haiku": {"input": 0.1, "cache_read": 0.01, "cache_write": 0.2, "output": 0.5}},
    },
    "grok": {
        "label": "Grok",
        "driver": "acp",
        "acp_command": "grok agent stdio",
        "can": None,
        "full_access": None,
        "manager_access": None,
        "first_worker": None,
        "manager": False,
        "owner_chat": False,
        "agent_messages": False,
        "conversation": False,
        "conversation_why": None,
        "closed_versions": (),
        "mcp_servers": False,
        "app_server": False,
        "switch": False,
        "session_settings": False,
        "token_in_env": True,
        "model_flags": None,
        "local_model": None,
        "sign_in": None,
        "sign_out": None,
        "no_sign_in": ("Fleet drives no Grok sign-in: xAI's terms do not let a third party run it this way. "
                       "Sign in to Grok yourself on {where} machine."),
        "sandbox": None,
        "screen_counter": False,
        "browser_tabs": False,
        "cache_seconds": None,
        "compact_tokens": None,
        "routine": None,
        "task_denied": None,
        "task_allowed": None,
        "conversation_denied": None,
        "manager_denied": None,
        "task_opening": None,
        "token_weights": None,
    },
}
# Claude's extension in the Chrome Web Store, the browser of a runtime with browser_tabs (offer_extension).
CLAUDE_EXTENSION = "fcoeoabgfenejglbffodgkkbkcdhcgfn"
CHATGPT_CODEX = "/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex"
# Every fact above in one list, so that a new entry cannot quietly leave one out (test_runtime_table).
RUNTIME_FACTS = ("label", "driver", "acp_command", "can", "full_access", "manager_access", "first_worker", "manager",
                 "owner_chat", "agent_messages", "conversation", "conversation_why", "closed_versions", "mcp_servers",
                 "app_server", "switch", "session_settings", "token_in_env", "model_flags", "local_model", "sign_in",
                 "sign_out", "no_sign_in", "sandbox", "screen_counter", "browser_tabs", "cache_seconds",
                 "compact_tokens", "routine", "task_denied", "task_allowed", "conversation_denied", "manager_denied",
                 "task_opening", "token_weights")


# The session reuse rule (AUTONOMY.md P9.10) and its setting (section 4), one object in team.json "settings":
# "session_reuse": {"on", "growth", "margin"} -- on, the growth factor of a context since its start, and the margin in
# seconds before the provider's cache lifetime ends. hub.SETTINGS checks the owner's value (reuse_value). A task's own
# session is not started again for its growth (fleet.Helper.window_reuse; the owner, 4 November 2026).
REUSE_SETTINGS = {"on": True, "growth": 2, "margin": 60}
REUSE_LIMITS = {"growth": (1, 10), "margin": (0, 3600)}
REUSE_ROOM = 0.8                # the share of the compaction point that a reused session's context may fill


def reuse_value(value):
    """The owner's session_reuse setting, checked and with its defaults: an object of on (true or false), growth
    (a whole number 1-10) and margin (seconds, 0-3600), any of which may be left out. Raises ValueError."""
    if not isinstance(value, dict) or set(value) - set(REUSE_SETTINGS):
        raise ValueError("must be an object of on, growth and margin")
    out = dict(REUSE_SETTINGS)
    for key, given in value.items():
        if key == "on":
            if not isinstance(given, bool):
                raise ValueError("on must be true or false")
        else:
            low, high = REUSE_LIMITS[key]
            if isinstance(given, bool) or not isinstance(given, int) or not low <= given <= high:
                raise ValueError(f"{key} must be a whole number from {low} to {high}")
        out[key] = given
    return out


def reuse_settings(team):
    """The reuse rule's setting from a team.json: the owner's own value, else the defaults; a value that its check
    refuses reads as the defaults, as hub.setting reads it."""
    stored = (team or {}).get("settings")
    try:
        return reuse_value(stored.get("session_reuse", {}) if isinstance(stored, dict) else {})
    except ValueError:
        return dict(REUSE_SETTINGS)


def session_reuse(runtime, context, started, now_runs, settings=None, at=None, facts=None):
    """The session reuse rule (AUTONOMY.md P9.10), for every kind of session and every provider: (True, "") to tell a
    session of a new message of its own thread, or (False, why) to start it fresh with the hub's short brief.

    A session is reused only when its cache is still warm (its records' cache lifetime, else its runtime's
    cache_seconds, less the margin), its context has at most grown by the growth factor since its start, there is
    room before its runtime's compaction point, and it runs on the runtime, model, effort and account that the agent
    has now: a provider keeps a cache for each account. The same thread is the caller's: a window is one thread (a
    task, a case, a conversation, the owner chat).

    context: its own records, (tokens now, tokens at its first call, time of its last model call, cache seconds or
    None), or None for a session that made no call yet, which has no context to read again. started and now_runs:
    {"runtime", "model", "effort", "account"} that it started with and that the agent has now; started is None when its
    start cannot be read, and then nothing is compared; an account that either of them does not name is not compared.
    facts: the runtime's facts as the owner set them (facts_now), else the table's. A growth of None in settings makes
    growth no reason: a task's own session grows with its work."""
    settings = dict(REUSE_SETTINGS, **(settings or {}))
    if not settings["on"]:
        return True, ""
    if started is not None and any(started.get(k) != (now_runs or {}).get(k) for k in ("runtime", "model", "effort")):
        return False, "it runs another runtime, model or effort than the agent has now"
    account, now_account = (started or {}).get("account"), (now_runs or {}).get("account")
    if account and now_account and account != now_account:
        return False, "it started on another account than the agent has now"
    if not context:
        return True, ""
    tokens, first, last, cache = context
    facts = facts if facts is not None else {fact: runtime_fact(runtime, fact) for fact in ("cache_seconds",
                                                                                           "compact_tokens")}
    lifetime = cache or facts.get("cache_seconds")
    idle = (time.time() if at is None else at) - last
    if lifetime is not None and idle > lifetime - settings["margin"]:
        return False, (f"its cache is cold after {idle / 60:.0f} quiet minutes, and a new session costs only its "
                       f"start")
    if settings["growth"] and first and tokens > settings["growth"] * first:
        return False, f"its context grew from {first // 1000}K to {tokens // 1000}K tokens since its start"
    room = facts.get("compact_tokens")
    if room and tokens > REUSE_ROOM * room:
        return False, f"its {tokens // 1000}K tokens leave no room before its compaction at {room // 1000}K"
    return True, ""


def shown_name(name):
    """A name as both apps show it, which is Swift's `capitalized`: a capital for every letter that starts the name or
    follows a character that is not a letter, and small letters for the rest ("hgr-dev" is "Hgr-Dev", "mini-2b"
    "Mini-2B"). Python's capitalize() gave "Hgr-dev", so one agent read two ways on one screen (review A9, 29 October
    2026). For the words the owner reads, from the hub and from a server's jobs."""
    out, before = [], ""
    for c in str(name or ""):
        out.append(c.upper() if c.isalpha() and not before.isalpha() else c.lower())
        before = c
    return "".join(out)


def runtime_fact(runtime, fact, otherwise=None):
    """One fact of one runtime's entry, and the only way to ask for it. `otherwise` is the answer for a name that is
    no runtime of this fleet, so that a check reads as the question it asks: such a name has no owner chat and holds
    no conversation."""
    return (RUNTIMES.get(runtime) or {}).get(fact, otherwise)


# ---------------------------------------------------------------- the facts the owner changes (AUTONOMY.md P10)
#
# A provider that changes its prices, its cache lifetime or its compaction point changes data, not code: the owner's
# own value of one of these is in team.json "runtime_facts", {runtime: {fact: value}}, written through GET/POST
# /ui/settings and the admin MCP, and read with facts_now. Each fact here has the check of a value (it gives the value
# back, or raises ValueError with what the value must be). A fact or a runtime that is not here is a later release's
# (plan P0): the hub checks none of those, and every write keeps them as they are.
TOKEN_KINDS = ("input", "cache_read", "cache_write", "output")
MODEL_KEY = re.compile(r"[A-Za-z0-9._:/\[\]-]{1,120}")
EFFORT_KEY = re.compile(r"[a-z]{1,20}")                 # hub.EFFORT_NAME: an effort as a runtime names it


def whole_or_none(low, high):
    def check(value):
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high):
            raise ValueError(f"must be a whole number from {low} to {high}, or null for none")
        return value
    return check


def weights_check(value):
    if value is None:
        return None
    if not isinstance(value, dict) or not value or len(value) > 50:
        raise ValueError('must map at most 50 model names, or "default", to their prices')
    for key, price in value.items():
        if not isinstance(key, str) or not (key == "default" or MODEL_KEY.fullmatch(key)):
            raise ValueError(f"names no model: {str(key)[:60]!r}")
        if not isinstance(price, dict) or set(price) != set(TOKEN_KINDS) or any(
                isinstance(p, bool) or not isinstance(p, (int, float)) or not 0 <= p <= 10000 for p in price.values()):
            raise ValueError(f"{key} must give input, cache_read, cache_write and output in dollars per million "
                             f"tokens, each from 0 to 10000")
    return value


def routine_check(value):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"model", "effort"} or \
            not (value["model"] is None or isinstance(value["model"], str) and MODEL_KEY.fullmatch(value["model"])) or \
            not (value["effort"] is None or isinstance(value["effort"], str) and EFFORT_KEY.fullmatch(value["effort"])):
        raise ValueError('must be {"model": a model name or null for the runtime\'s own, "effort": 1 to 20 letters a-z '
                         'or null}, or null for none')
    return value


EDITABLE_FACTS = {"cache_seconds": whole_or_none(0, 86400), "compact_tokens": whole_or_none(1000, 100000000),
                  "token_weights": weights_check,
                  "routine": routine_check}             # plan P9.7: what an agent's one changer reaches for first


def facts_now(team, runtime):
    """The facts of one runtime that the owner can change, as they are now: his own value from team.json
    "runtime_facts" where it is one that its check takes, else the table's."""
    stored = (team or {}).get("runtime_facts")
    stored = stored.get(runtime) if isinstance(stored, dict) else None
    out = {}
    for fact, check in EDITABLE_FACTS.items():
        out[fact] = runtime_fact(runtime, fact)
        if isinstance(stored, dict) and fact in stored:
            try:
                out[fact] = check(stored[fact])
            except ValueError:
                pass            # a file written by hand that the check refuses reads as the table's
    return out


def token_price(weights, model):
    """One model's prices from a runtime's token_weights: the entry whose key is the longest part of the model's
    name, case aside, else "default"; None for a runtime with no prices."""
    if not weights:
        return None
    name = str(model or "").lower()
    named = [k for k in weights if k != "default" and k.lower() in name]
    return weights[max(named, key=len)] if named else weights.get("default")


def runtimes_with(fact):
    """The runtimes whose entry says yes to one fact, in the table's own order."""
    return tuple(name for name, entry in RUNTIMES.items() if entry.get(fact))


def no_sign_in(runtime, where="this"):
    """Why the fleet drives no sign-in for this runtime, in the words the owner reads, or None when it drives one.
    `where` is the machine as its reader sees it: "this" on the machine itself, "that" from the hub or the app."""
    said = runtime_fact(runtime, "no_sign_in")
    return said.format(where=where) if said else None


SWITCH_RUNTIMES = runtimes_with("switch")   # the runtimes an owner can switch between (owner feature runtime_switch)
# The one runtime the fleet drives over its own app-server protocol: a screen task runs on it (screen_runner.py),
# and so does a worker or a lead whose start policy is exactly APP_SERVER. None when no entry carries the fact.
APP_SERVER_RUNTIME = (runtimes_with("app_server") or (None,))[0]


def switch_target(runtime):
    """The runtime an owner can switch this one to, or None for one that no switch reaches.

    Today the offer is one target, because exactly two entries carry `switch`: the other one. An offer of several
    targets is the next step, and it changes this function and nothing else."""
    others = [name for name in SWITCH_RUNTIMES if name != runtime]
    return others[0] if runtime in SWITCH_RUNTIMES and len(others) == 1 else None


# Where this helper leaves its sign-in reading for `fleet.py verify` to read, in the home of the user whose agents
# these are: ~/.fleet/signed-in-<agent>.json. verify imports this one path, so the writer and the reader of the file
# cannot drift apart (Lifecycle.remember_signed_in says why only a Mac needs it).
FLEET_DIR = ".fleet"
SIGNED_IN_FILE = "signed-in-%s.json"
MODELS_EVERY = 6 * 3600         # seconds between readings of the runtime's model options
# The helper's updates of the runtimes of its OS user (update_runtimes). One round at most every six hours for each
# user, whose ~/.fleet keeps when the last one began and what it did, and one helper at a time: a Mac keeps one user,
# and so one ~/.local/bin, for all of its agents. RUNTIME_RESULTS are the outcomes that its status reports.
RUNTIME_UPDATE_EVERY = 6 * 3600
RUNTIME_INSTALL_WAIT = 600      # seconds that one vendor installer may take
RUNTIME_UPDATES_FILE = "runtime-updates.json"
RUNTIME_UPDATES_LOCK = "runtime-updates.lock"
RUNTIME_RESULTS = ("updated", "current", "rolled_back", "failed", "skipped")
VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?")     # the version in a runtime's --version line
MODEL_NAME = re.compile(r"[A-Za-z0-9._:/\[\]-]{1,120}")
EFFORT_NAME = re.compile(r"[a-z]{1,20}")
LOGIN_REASONS = ("ok", "not_found", "no_access", "bad_format", "no_token", "timeout", "error")
APP_SERVER = "app-server"       # the start policy of a worker or lead of APP_SERVER_RUNTIME: screen_runner.py
# GitHub repositories (owner feature integrations): owner/name in lower case, and the access that the owner gives,
# from the lowest to the highest. deploy is write and the repository's own deployment: its workflow files, which a
# token without the App's workflows permission may not push at all, and its GitHub Actions runs.
REPO_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,38}/(?!\.\.?$)[a-z0-9._-]{1,100}")
REPO_ACCESS = ("read", "write", "deploy")
# What the owner alone can do for deploy, in one sentence: GitHub refuses the token until the App carries those two
# permissions and the installation has accepted them. The hub says it where a deploy token is refused, where an agent
# asks for deploy and where the manager grants it, so nobody reads a bare GitHub error.
DEPLOY_APP_NOTE = ("deploy needs the Workflows and Actions permissions on the hub's GitHub App, and the owner must "
                   "accept them on the App's installation page (GitHub Settings, Applications, the hub's App); "
                   "GitHub refuses a deploy token until then")
# A GitHub App installation token, as the hub gets it and a session uses it: GitHub's current ones have about 400
# characters, with - and . in them.
GITHUB_TOKEN = re.compile(r"[A-Za-z0-9_.-]{20,4096}")
# The MCP servers that the owner can give an agent (owner feature integrations). The hub checks and shows this one
# catalog; the helper adds an agent's chosen servers to its Claude and Codex task sessions. A server has a command
# (with args) or a url. env: {the server's variable: the session variable whose value it gets}; bearer: the session
# variable whose value is a url server's bearer token. A session that lacks one of these variables gets no such server.
TOOL_CATALOG = {
    "github": {"title": "GitHub", "command": "github-mcp-server", "args": ["stdio"],
               "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "GH_TOKEN"},
               # every runtime whose task sessions load a server at all (RUNTIMES "mcp_servers")
               "runtimes": sorted(runtimes_with("mcp_servers"))},
}
# The owner's own MCP servers (owner feature mcp): team.json "mcp" holds them, the hub checks each one and the owner
# gives them to agents as it gives a catalog tool. mcp_server turns one into a catalog entry, so the hub, the helper
# and the sessions handle an owner server and a catalog tool in exactly one way.
MCP_NAME = re.compile(r"[a-z][a-z0-9-]{0,30}")       # the server's name, which is also the prefix of its tools
MCP_LIMIT = 32                                       # the most servers that team.json holds
MCP_RUNTIMES = tuple(sorted(runtimes_with("mcp_servers")))   # the runtimes whose task sessions load a server
# How a url server proves who it is: nothing (a public server), the hub's own OAuth tokens (the owner connects it
# once and no refresh token ever leaves the hub), an API key that the agent reads (owner feature secret_grants), or a
# short-lived token that the vault mints for each task session with a key that the session never sees (support plan
# F3, "mint"): the vault sends POST <mint> to the site of that key's login, with {<mint_field>: the task's case key},
# and only the "token" of the answer reaches that session's MCP file.
MCP_AUTH = ("none", "oauth", "key", "mint")
MCP_PROGRAM = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")    # a stdio server's program, on PATH or in ~/.local/bin
MCP_FIELDS = {"title", "url", "command", "env", "auth", "key", "runtimes", "mint", "mint_field"}    # no args: plan 0.2
MINT_PATH = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,199}")      # the mint's path at the key's site, no query
MINT_FIELD = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,39}")                  # the field of its body that names the case


def desktop_path(home):
    """Where a Mac's server service leaves its reading of Chrome (Lifecycle.remember_browser)."""
    return os.path.join(home, ".fleet", "desktop.json")


def write_json(path, value):
    """One small file, whole or not at all: a check reads it while a helper writes it."""
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    with open(path + ".new", "w") as f:
        json.dump(value, f)
    os.replace(path + ".new", path)


def signed_in_path(home, agent):
    """The file where that agent's helper leaves its sign-in reading."""
    return os.path.join(home, FLEET_DIR, SIGNED_IN_FILE % agent)


def mcp_variable(name):
    """The session variable that holds the access token of one oauth server. FLEET_* is reserved for Fleet, so no API
    key of the owner can have this name."""
    return "FLEET_MCP_" + name.upper().replace("-", "_")


def mcp_address(value):
    """One url server's address, or None: https anywhere, http on 127.0.0.1 only, with a host, no user part and no
    fragment, at most 300 characters."""
    if not isinstance(value, str) or not 1 <= len(value) <= 300 or value.strip() != value or \
            any(c.isspace() for c in value):
        return None
    try:
        parts = urllib.parse.urlsplit(value)
    except ValueError:
        return None
    if parts.scheme == "http" and parts.hostname not in ("127.0.0.1", "localhost"):
        return None
    if parts.scheme not in ("https", "http") or not parts.hostname or parts.username or parts.password or parts.fragment:
        return None
    return value


def mcp_server(name, entry):
    """One server of team.json "mcp" as a catalog entry (TOOL_CATALOG's shape, with custom and auth), or ValueError
    with the reason. A url server has url and, for auth "oauth" or "key", bearer: the session variable that holds its
    token. A stdio server has command and env ({the server's variable: the session variable whose value it gets}), and
    no arguments (DevOps plan 0.2: a command line that team.json writes is code), so its args are always []. Each
    variable has the shape of a key's name (key_env). A session that lacks one of these variables gets no such
    server."""
    if not isinstance(name, str) or not MCP_NAME.fullmatch(name):
        raise ValueError(f"the MCP server name {name!r} must be 1 to 31 characters a-z 0-9 - that start with a letter")
    if name in TOOL_CATALOG or name == "fleet":
        raise ValueError(f"the name {name} is Fleet's own: choose another one")
    if not isinstance(entry, dict) or set(entry) - MCP_FIELDS:
        raise ValueError(f"the MCP server {name} takes only {', '.join(sorted(MCP_FIELDS))}")
    title = entry.get("title")
    if not (isinstance(title, str) and 1 <= len(title.strip()) <= 60 and "\n" not in title):
        raise ValueError(f"the MCP server {name} needs a title of one line and 1 to 60 characters")
    auth = entry.get("auth", "none")
    if auth not in MCP_AUTH:
        raise ValueError(f"the MCP server {name}: auth must be {', '.join(MCP_AUTH)}")
    runtimes = entry.get("runtimes", list(MCP_RUNTIMES))
    if not isinstance(runtimes, list) or not runtimes or len(set(runtimes)) != len(runtimes) or \
            any(r not in MCP_RUNTIMES for r in runtimes):
        raise ValueError(f"the MCP server {name}: runtimes must be different names of {', '.join(MCP_RUNTIMES)}")
    variables = entry.get("env") or {}
    if not isinstance(variables, dict) or len(variables) > 8 or not all(
            key_env(k) and key_env(v) for k, v in variables.items()):
        raise ValueError(f"the MCP server {name}: env maps up to 8 of its own variable names to the names of API keys "
                         f"that the agent reads, each the name of a key (A-Z 0-9 _, ending in "
                         f"{', '.join(KEY_SUFFIXES)}) and not a name that a session sets itself")
    made = {"title": title.strip(), "runtimes": sorted(runtimes), "custom": True, "auth": auth}
    if ("url" in entry) == ("command" in entry):
        raise ValueError(f"the MCP server {name} needs a url (a remote server) or a command (a program on the "
                         f"machine), not both")
    if "url" in entry:
        if not mcp_address(entry["url"]):
            raise ValueError(f"the MCP server {name}: url must be an https address (http only on 127.0.0.1) with a "
                             f"host, no user part and no #fragment, at most 300 characters")
        made["url"] = entry["url"]
        if auth == "oauth":
            made["bearer"] = mcp_variable(name)
        elif auth == "key":
            key = entry.get("key")
            if not key_env(key):
                raise ValueError(f"the MCP server {name}: auth \"key\" needs key, the name of an API key that the "
                                 f"agent reads in its sessions")
            made["bearer"] = key
        elif auth == "mint":
            key, path, field = entry.get("key"), entry.get("mint"), entry.get("mint_field", "case")
            field = None if field == "" else field          # "": an empty body, for a token that names no case
            if not key_env(key):
                raise ValueError(f"the MCP server {name}: auth \"mint\" needs key, the name of the API key whose "
                                 f"login mints the token; the session never reads it")
            if not (isinstance(path, str) and MINT_PATH.fullmatch(path)):
                raise ValueError(f"the MCP server {name}: mint must be the path at that key's site that makes a "
                                 f"token, beginning with / and with no query, at most 200 characters")
            if not (field is None or isinstance(field, str) and MINT_FIELD.fullmatch(field)):
                raise ValueError(f"the MCP server {name}: mint_field must be a field name of 1 to 40 characters "
                                 f"A-Z a-z 0-9 _ that starts with a letter, or \"\" for an empty body")
            made.update(bearer=mcp_variable(name), mint={"key": key, "path": path, "field": field})
        if auth != "mint" and ("mint" in entry or "mint_field" in entry):
            raise ValueError(f"the MCP server {name}: mint and mint_field are for auth \"mint\"")
        if variables:
            raise ValueError(f"the MCP server {name}: env is for a command server; a url server uses key")
    else:
        if auth != "none":
            raise ValueError(f"the MCP server {name}: a command server has no auth; give its key in env")
        if "key" in entry:
            raise ValueError(f"the MCP server {name}: key is for a url server with auth \"key\"")
        if "mint" in entry or "mint_field" in entry:
            raise ValueError(f"the MCP server {name}: mint and mint_field are for a url server with auth \"mint\"")
        if not isinstance(entry["command"], str) or not MCP_PROGRAM.fullmatch(entry["command"]):
            raise ValueError(f"the MCP server {name}: command must be the name of a program on the machine (1 to 64 "
                             f"characters A-Z a-z 0-9 . _ -), which the machine has on its PATH or in ~/.local/bin")
        made.update(command=entry["command"], args=[], env=dict(sorted(variables.items())))
    return made


def tool_needs(tool):
    """The session variables that one catalog entry needs: the variables of a stdio server, and the bearer variable of
    a url server. A session that lacks one of them gets no such server. A mint server's token is made at the start of
    each task session (fleet.mint_tokens), which drops the server when it gets none."""
    return sorted(set((tool.get("env") or {}).values()) |
                  ({tool["bearer"]} if tool.get("bearer") and not tool.get("mint") else set()))


def tool_catalog(team):
    """The catalog of this team: Fleet's own tools and the owner's MCP servers of team.json "mcp". A server that does
    not pass mcp_server is left out, so a hand-written entry can never reach a session."""
    catalog = {name: dict(tool, custom=False, auth="none") for name, tool in TOOL_CATALOG.items()}
    for name, entry in sorted(((team or {}).get("mcp") or {}).items()):
        try:
            catalog[name] = mcp_server(name, entry)
        except ValueError:
            continue
    return catalog


def app_server_task(conf, needs):
    """True when a task with these needs runs in screen_runner.py (Codex app-server) and not in a terminal CLI: every
    screen task, and every task of a Codex worker or lead whose start policy is exactly app-server. The helper and the
    hub use this one rule."""
    return needs == "screen" or bool(runtime_fact(conf.get("runtime"), "app_server")
                                     and conf.get("start") == APP_SERVER
                                     and conf.get("role") in ("worker", "lead"))


def offer_extension(home):
    """Chrome's own way to take an extension from its Web Store: this file. Chrome fetches the extension at its next
    start and asks once, on this Mac's screen, to enable it. The file stays, so a Chrome profile that is removed gets the
    extension back at the next start (the owner, 28 October 2026: "a mac studio server should come by default with
    computer and browser use")."""
    folder = os.path.join(home, "Library", "Application Support", "Google", "Chrome", "External Extensions")
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, CLAUDE_EXTENSION + ".json"), "w", encoding="utf-8") as f:
        f.write('{"external_update_url": "https://clients2.google.com/service/update2/crx"}\n')


def chrome_extension(home):
    """Claude's extension, from each Chrome profile's own record: True when a profile has it on, False when it is
    there and off, None when no profile has it or macOS will not list Chrome's folder (4 November 2026: after an
    update it refused the server service, which then stopped). A newer Chrome keeps only the reasons it is off."""
    chrome, found = os.path.join(home, "Library", "Application Support", "Google", "Chrome"), None
    try:
        profiles = os.listdir(chrome) if os.path.isdir(chrome) else ()
    except OSError:
        return None
    for profile in profiles:
        try:
            with open(os.path.join(chrome, profile, "Secure Preferences"), encoding="utf-8") as f:
                entry = json.load(f)["extensions"]["settings"][CLAUDE_EXTENSION]
            if entry.get("state") != 0 and not entry.get("disable_reasons"):
                return True
            found = False
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            continue
    return found


def mcp_call(argv, tool, timeout=20, popen=subprocess.Popen):
    """The text answer of one tool of a local MCP server, from one exchange over its standard input and output, or
    None when it gave none. No model runs."""
    try:
        proc = popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                     start_new_session=True)
    except (OSError, TypeError):
        return None
    lines, end, reply = queue.Queue(), time.monotonic() + timeout, None

    def pump():
        # This thread closes the pipe: a close from the caller waits for this read, which a child of the server can
        # hold open after the kill below, and the timeout would be no limit.
        with proc.stdout:
            for line in proc.stdout:
                lines.put(line)
        lines.put(None)

    def answer(number):
        while time.monotonic() < end:
            try:
                line = lines.get(timeout=max(0.05, end - time.monotonic()))
            except queue.Empty:
                return None
            if line is None:
                return None
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if isinstance(message, dict) and message.get("id") == number:
                return message
        return None

    threading.Thread(target=pump, daemon=True).start()
    try:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "founderizer", "version": "1"}}}) + "\n")
        proc.stdin.flush()
        if answer(1):
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                         "params": {"name": tool, "arguments": {}}}) + "\n")
            proc.stdin.flush()
            reply = answer(2)
    except (OSError, ValueError):
        reply = None
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()
        try:
            proc.stdin.close()
        except OSError:
            pass
    try:
        return reply["result"]["content"][0]["text"]
    except (TypeError, KeyError, IndexError):
        return None


def browser_connected(exe):
    """Whether a Chrome answers Claude Code's account: True or False, or None when nothing says. It is the runtime's own
    list of the browsers connected to its account, from its own Chrome server: no model runs, so a status report can
    read it. Only the login session opens the runtime's credential, so a run outside it reads False for a Mac that is
    signed in: it is read by the helper and the server service alone. A lone browser may stand on another Mac of the
    same account: `onThisComputer` comes only from a desktop app's hints, and `isLocal` says only that the operating
    systems match (31 October 2026, an agent worked in another Mac's Chrome). What ties a browser to this Mac is a page
    that only this Mac reaches: the installer's and the hub's proofs."""
    said = mcp_call([exe, "--claude-in-chrome-mcp"], "list_connected_browsers")
    if said is None:
        return None
    if said.startswith("Browser extension is not connected"):
        return False                    # its own words for no browser on this account (31 October 2026, a bare Mac)
    try:
        browsers = json.loads(said)
    except ValueError:
        return None
    if not isinstance(browsers, list):
        return None
    # With several browsers on the account, the field says where each one is when the runtime knows.
    return any(not isinstance(b, dict) or b.get("onThisComputer", b.get("isLocal", True)) is not False
               for b in browsers)


def console_session(run):
    """(who is at this Mac's console, whether its screen is locked), each None when it could not be read, and None
    for the whole reading when the console did not answer."""
    code, out, _ = run(["ioreg", "-n", "Root", "-d1", "-a"])
    try:
        root = plistlib.loads(out.encode()) if code == 0 else None
    except Exception:
        root = None
    if not isinstance(root, dict):
        return None
    return (next((u.get("kCGSSessionUserNameKey") for u in root.get("IOConsoleUsers") or []
                  if isinstance(u, dict) and u.get("kCGSSessionOnConsoleKey")), None), root.get("IOConsoleLocked"))


SETUP_SCREENS = "The setup screens of macOS are open on this Mac: finish them at this Mac or with Screen Sharing."
SOFTWARE_UPDATE = "/Library/Preferences/com.apple.SoftwareUpdate.plist"     # macOS's own record of its updates


def setup_screens(run):
    """Whether macOS's own setup screens are open (True, False, or None when nothing says): after macOS installed an
    update by itself and restarted, "Setup Assistant" stayed open on a Mac that nobody watched (4 November 2026), and
    while it is open the screen is not the session's, and launchd starts none of the user's own jobs."""
    code, _, _ = run(["pgrep", "-x", "Setup Assistant"])
    return True if code == 0 else False if code == 1 else None


def macos_update(installed, path=SOFTWARE_UPDATE):
    """What macOS itself says of its updates, from the file that its update service keeps (mode 644: no root, and no
    scan of our own): {"auto": whether it installs them by itself, "waiting": the newest update of the installed major
    version that it offers, or None}, or None when the file cannot be read. A new major version never waits: nobody
    has to take one."""
    try:
        with open(path, "rb") as f:
            data = plistlib.load(f)
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None
    if not isinstance(data, dict):
        return None

    def number(version):
        return tuple(int(x) for x in re.findall(r"\d+", version))
    have = number(installed or "")
    offered = [str(u.get("Display Version") or "") for u in data.get("RecommendedUpdates") or []
               if isinstance(u, dict) and u.get("MobileSoftwareUpdate") is True]
    waiting = [v for v in offered if re.fullmatch(r"\d+(\.\d+){0,3}", v) and have and number(v)[0] == have[0]
               and number(v) > have]
    auto = data.get("AutomaticallyInstallMacOSUpdates")
    return {"auto": auto if isinstance(auto, bool) else None, "waiting": max(waiting, key=number) if waiting else None}


def session_item(run, user):
    """macOS: who is at the console, and whether its screen is locked. A heartbeat cannot show this."""
    reading = console_session(run)
    if reading is None:
        return ("mac", "session", "not_verified", "The console session could not be read.")
    console, locked = reading
    if setup_screens(run):
        return ("mac", "session", "failed", SETUP_SCREENS)
    if not console:
        return ("mac", "session", "failed", "No one is logged in at the console.")
    if console != user:
        return ("mac", "session", "failed", f"{console} is at the console, not {user}.")
    if locked is True:
        return ("mac", "session", "failed", f"{user} is at the console, and the screen is locked.")
    if locked is False:
        return ("mac", "session", "ok", f"{user} is at the console, and the screen is unlocked.")
    return ("mac", "session", "not_verified", f"{user} is at the console; its lock state could not be read.")


def autologin_item(run, user):
    code, out, _ = run(["fdesetup", "status"])
    if code == 0 and "FileVault is On" in out:      # macOS offers no automatic login then: no fault of this machine's
        return ("mac", "automatic_login", "not_verified",
                "FileVault is on, so a person must unlock this Mac after each restart.")
    code, out, _ = run(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"])
    auto = out.strip() if code == 0 else ""
    if not auto:
        return ("mac", "automatic_login", "failed", "Automatic login is off.")
    if auto != user:
        return ("mac", "automatic_login", "failed", f"Automatic login is on for {auto}, not {user}.")
    return ("mac", "automatic_login", "ok", f"Automatic login is on for {user}.")


def awake_item(run):
    code, out, _ = run(["pmset", "-g"])
    if code != 0:
        return ("mac", "awake", "not_verified", "The power settings could not be read.")

    def minutes(key):
        m = re.search(r"^\s*" + key + r"\s+(\d+)", out, re.M)
        value = int(m.group(1)) if m else None
        return "unknown" if value is None else "never" if value == 0 else f"after {value} minutes"
    restart = re.search(r"^\s*autorestart\s+(\d+)", out, re.M)
    system = minutes("sleep")
    words = (f"System sleep {system}; display sleep {minutes('displaysleep')}; restart after a power failure "
             f"{'unknown' if not restart else 'on' if restart.group(1) == '1' else 'off'}.")
    return ("mac", "awake", "ok" if system == "never" else "not_verified" if system == "unknown" else "failed", words)


def desktop_items(run, home, user, tabs, connected=None):
    """What a Mac's desktop can do now, as setup check items: the one reading of it, which the helper's setup check and
    `fleet.py verify` both give. tabs: the runtime works in tabs of Chrome through Claude's extension. connected: what
    browser_connected read in the login session, None where nobody read it."""
    session = session_item(run, user)
    ready = session[2] == "ok"
    setup = session[3] if session[3] == SETUP_SCREENS else None         # the screens cover the session's own screen
    chrome = any(os.path.isdir(p) for p in ("/Applications/Google Chrome.app",
                                             os.path.join(home, "Applications", "Google Chrome.app")))
    extension = chrome_extension(home) if tabs else True
    usable = chrome and ready and extension and (not tabs or connected is not False)
    return [("capability", "browser", "ok" if usable else "failed",
             "Google Chrome is installed, and the session is ready." if usable else
             "Google Chrome is not installed." if not chrome else setup if setup else
             f"The browser needs {user} at the console with the screen unlocked." if not ready else
             "Claude's extension is off: press Enable Extension in Chrome on this Mac." if extension is False else
             "Claude's extension is not in Chrome on this Mac: restart Chrome, then press Enable Extension."
             if extension is None else
             "Claude's extension is not signed in: sign in to Claude in Chrome on this Mac, with this Mac's account."),
            ("capability", "screen", "not_verified" if ready else "failed",
             "The session is ready, but Fleet cannot check the macOS screen recording and accessibility "
             "permissions that screen control needs." if ready else
             setup or f"Screen control needs {user} at the console with the screen unlocked."),
            autologin_item(run, user), awake_item(run), session]


def exe(name, home=None):
    """A runtime's executable: on PATH, else in ~/.local/bin; None when neither has it."""
    local = os.path.join(home or os.path.expanduser("~"), ".local", "bin", name or "")
    return shutil.which(name or "") or (local if os.path.exists(local) else None)


def codex_model_list(exe, timeout=20):
    """(options, error): the models and efforts that this machine's Codex account offers, from one app-server
    query (initialize, initialized, model/list). No thread and no turn starts, so no model runs."""
    folder = tempfile.mkdtemp(prefix="fleet-models-")
    try:
        proc = subprocess.Popen([exe, "app-server"], cwd=folder, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, start_new_session=True)
    except OSError as e:
        shutil.rmtree(folder, ignore_errors=True)
        return None, f"codex app-server did not start: {type(e).__name__}"
    lines, end, reply = queue.Queue(), time.monotonic() + timeout, None

    def pump():
        for line in proc.stdout:
            lines.put(line)
        lines.put(None)

    def answer(number):
        while time.monotonic() < end:
            try:
                line = lines.get(timeout=max(0.05, end - time.monotonic()))
            except queue.Empty:
                return None
            if line is None:
                return None
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if isinstance(message, dict) and message.get("id") == number:
                return message
        return None

    threading.Thread(target=pump, daemon=True).start()
    try:
        proc.stdin.write(json.dumps({"id": 1, "method": "initialize", "params": {
            "clientInfo": {"name": "founderizer_models", "title": "Founderizer", "version": "1"}}}) + "\n")
        proc.stdin.flush()
        first = answer(1)
        if first and "result" in first:
            proc.stdin.write(json.dumps({"method": "initialized", "params": {}}) + "\n")
            proc.stdin.write(json.dumps({"id": 2, "method": "model/list",
                                         "params": {"limit": 100, "includeHidden": False}}) + "\n")
            proc.stdin.flush()
            reply = answer(2)
    except (OSError, ValueError):
        reply = None
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()
        for pipe in (proc.stdin, proc.stdout):
            try:
                pipe.close()
            except OSError:
                pass
        shutil.rmtree(folder, ignore_errors=True)
    if not reply:
        return None, f"codex app-server did not answer model/list in {timeout} seconds"
    if "error" in reply:
        message = (reply["error"] or {}).get("message") if isinstance(reply["error"], dict) else None
        return None, "codex app-server refused model/list" + (f": {str(message)[:200]}" if message else "")
    data = (reply.get("result") or {}).get("data") if isinstance(reply.get("result"), dict) else None
    options = []
    for d in data if isinstance(data, list) else []:
        model = d.get("model") or d.get("id") if isinstance(d, dict) else None
        if d.get("hidden") is True if isinstance(d, dict) else True:
            continue
        if not isinstance(model, str) or not MODEL_NAME.fullmatch(model):
            continue
        efforts = [e.get("reasoningEffort") for e in d.get("supportedReasoningEfforts") or [] if isinstance(e, dict)]
        default = d.get("defaultReasoningEffort")
        options.append({"model": model, "display_name": str(d.get("displayName") or model)[:120],
                        "default": d.get("isDefault") is True,
                        "efforts": [e for e in efforts if isinstance(e, str) and EFFORT_NAME.fullmatch(e)][:16],
                        "default_effort": default if isinstance(default, str) and EFFORT_NAME.fullmatch(default) else None})
    if not options:
        return None, "codex app-server listed no models"
    return options[:64], None


def claude_model_list(help_text):
    """(options, error) from the installed `claude --help`: the model aliases that it names and its effort levels.
    Claude also takes full model names that it does not list."""
    flat = " ".join(help_text.split())
    model = re.search(r"--model <model>(.*?)(?: --[a-z]|$)", flat)
    levels = re.search(r"--effort <level>[^(]*\(([a-z, ]+)\)", flat)
    aliases = list(dict.fromkeys(re.findall(r"'([a-z0-9][a-z0-9.\[\]-]{0,40})'", model.group(1)))) if model else []
    efforts = [x.strip() for x in levels.group(1).split(",") if EFFORT_NAME.fullmatch(x.strip())] if levels else []
    if not aliases:
        return None, "claude --help names no model aliases"
    return [{"model": a, "display_name": a, "default": False, "efforts": efforts, "default_effort": None}
            for a in aliases[:64]], None


class Updating(Exception):
    """No session may start: this helper is updating Fleet. The event stays pending for the new process."""


def _run(argv, timeout=20, cwd=None):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=cwd, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout, r.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)


def checkout_branch(kit, run=None):
    """The branch that this checkout is on, or None when it is detached."""
    code, out, _ = (run or _run)(["git", "-C", kit, "symbolic-ref", "--short", "--quiet", "HEAD"])
    out = out.strip()
    return out if code == 0 and BRANCH_NAME.fullmatch(out) else None


def give_way_to(kit, target, run=None):
    """Make room for a fast-forward to `target`: a file of outputs/ that this checkout holds untracked and that
    `target` adds with the same bytes is removed, and the merge brings it back tracked. It is one that the hub took
    in from here, a task's output that this helper sent when its agent delivered (helper feature task_outputs). A
    file with other bytes stays, and the merge then says why it cannot. Every fast-forward of a checkout that
    delivers goes through this: the task-start sync (follow_config_ref) and the Fleet update (Lifecycle.apply)."""
    run = run or _run

    def git(*args):
        code, out, _ = run(["git", "-C", kit, *args], timeout=60)
        return out.strip() if code == 0 else None

    added = git("diff", "--name-only", "--diff-filter=A", "-z", "HEAD", target, "--", "outputs/")
    for path in (added or "").split("\0"):
        full = os.path.join(kit, path)
        blob = path and os.path.isfile(full) and not os.path.islink(full) and git("hash-object", "--", path)
        if blob and blob == git("rev-parse", f"{target}:{path}"):
            with contextlib.suppress(OSError):
                os.remove(full)


SKILLS_CHARS = 6000         # the most that the list of an agent's skills adds to a session's start; the rest are counted
SKILLS_HEAD = ("YOUR SKILLS: procedures that you wrote for yourself. When a job matches the description of one, read "
               "its SKILL.md and follow it. Change or retire a skill only with write_skill.")
SKILL_AGENT = r"[a-z][a-z0-9-]{1,30}"          # hub.AGENT_NAME


def skill_front(text, key="description"):
    """The description in a SKILL.md's front matter, as write_skill writes it (a JSON string, which YAML reads as the
    same string), on one line and without a control character; "" when it has none. key "outside-reads": the hub's
    count of outside reads that write_skill wrote there, as a whole number, or 0."""
    lines = str(text or "").split("\n")
    if not lines or lines[0].strip() != "---":
        return 0 if key == "outside-reads" else ""
    for line in lines[1:40]:
        if line.strip() == "---":
            break
        name, sep, value = line.partition(":")
        if sep and name.strip() == key == "outside-reads":
            return int(value.strip()) if value.strip().isdigit() else 0
        if sep and name.strip() == key:
            value = value.strip()
            try:
                value = json.loads(value) if value.startswith('"') else value
            except ValueError:
                pass
            return " ".join(re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value)).split())[:300]
    return 0 if key == "outside-reads" else ""


def skill_rows(kit, agent=None):
    """Every skill at the HEAD of checkout `kit`, or one agent's: [{agent, name, description, path, files}], by agent
    and name; files are the paths beside its SKILL.md. Committed regular files only, read from git and not from the
    folder, so a file that a session wrote there by hand is no skill and a hand edit is not what a start lists.
    [] where the checkout cannot say."""
    def git(args, given=None):
        try:
            done = subprocess.run(["git", "-C", kit, *args], capture_output=True, timeout=20,
                                  **({"input": given} if given is not None else {"stdin": subprocess.DEVNULL}))
        except (OSError, subprocess.TimeoutExpired):
            return None
        return done.stdout if done.returncode == 0 else None
    tree = git(["ls-tree", "-r", "-z", "HEAD", "--", f"{SKILLS}/{agent}/" if agent else f"{SKILLS}/"])
    found = {}
    for item in (tree or b"").split(b"\0"):
        meta, _, raw = item.partition(b"\t")
        try:
            mode, kind, oid = meta.decode("ascii").split()
            parts = raw.decode("utf-8").split("/")
        except (ValueError, UnicodeError):
            continue
        rest = "/".join(parts[3:])
        if mode not in ("100644", "100755") or kind != "blob" or len(parts) < 4 or \
                not re.fullmatch(SKILL_AGENT, parts[1]) or not re.fullmatch(SKILL_NAME, parts[2]) or \
                not re.fullmatch(SKILL_FILE, rest) or ".." in rest:
            continue
        skill = found.setdefault((parts[1], parts[2]), {"oid": None, "files": []})
        if rest == "SKILL.md":
            skill["oid"] = oid
        else:
            skill["files"].append(rest)
    named = sorted((key, s) for key, s in found.items() if s["oid"])
    blobs = (git(["cat-file", "--batch"], "".join(s["oid"] + "\n" for _, s in named).encode()) or b"") if named else b""
    texts, at = {}, 0
    while at < len(blobs):                  # "<oid> blob <size>\n<bytes>\n" for each, in the order asked
        end = blobs.find(b"\n", at)
        head = blobs[at:end].decode("ascii", "replace").split() if end >= 0 else []
        if len(head) != 3 or not head[2].isdigit():
            break
        texts[head[0]] = blobs[end + 1:end + 1 + int(head[2])].decode("utf-8", "replace")
        at = end + 1 + int(head[2]) + 1
    return [{"agent": owner, "name": name, "description": skill_front(texts.get(s["oid"])),
             "outside_reads": skill_front(texts.get(s["oid"]), "outside-reads"),
             "path": f"{SKILLS}/{owner}/{name}/SKILL.md", "files": sorted(s["files"])} for (owner, name), s in named]


def skills_text(kit, agent):
    """The list of the agent's own skills that a session's start carries, or "" for an agent with none: each skill's
    name, description and path, by name, inside SKILLS_CHARS, and how many more did not fit. The same commit gives the
    same bytes, so in the stable text of a session (fleet.stable_text) the provider's cache keeps it until a skill is
    written; the hub gives the same words where that text does not carry them (hub.skills_start_text)."""
    rows = skill_rows(kit, agent)
    if not rows:
        return ""
    shown, room = [], SKILLS_CHARS - len(SKILLS_HEAD) - 120          # the line of what did not fit is under 120
    for r in rows:
        line = (f"- {r['name']}: {r['description']} ({r['path']})" if r["description"] else
                f"- {r['name']} ({r['path']})") + \
            (f" [written after {r['outside_reads']} read{'' if r['outside_reads'] == 1 else 's'} of outside text: "
             f"weigh it]" if r.get("outside_reads") else "")
        if len(line) + 1 > room:
            break
        shown.append(line)
        room -= len(line) + 1
    left = len(rows) - len(shown)
    return "\n".join([SKILLS_HEAD] + shown + ([f"And {left} more in {SKILLS}/{agent}/: each folder's SKILL.md says "
                                                f"what it is for."] if left else [])) + "\n"


# ---------------------------------------------------------------- signed code (DevOps plan v44, track 0)
#
# One check stands before every move of a Fleet checkout, wherever the move is made: `may_take`. The hub writes the
# configuration ref, so without it one bug in the hub could put code there that every machine then runs. A checkout
# moves onto what the hub writes only when that is data: the owner's own files and the files of a task's output, each
# a plain file (DATA_MODE). Any other move needs a release that a release key signed: its manifest on the ref as
# RELEASE_FILE, a revision that descends from the one this checkout runs and from this user's floor, and a tree that is
# that revision's own outside the data. The keys are the ones of the checkout's own HEAD, never the target's, so a
# target cannot bring the key that signs it, and both of its key files: a fleet that takes releases early took one that
# the early key signed (releases.every_key). The floor is the newest release this OS user took, kept in its ~/.fleet
# outside every checkout, so a checkout that was put back or cloned again is not a way to an older release.
RELEASE_FILE = "release.json"       # the signed manifest of the release on the configuration ref (releases.Update)
RELEASE_KEYS = "release-key.pub"    # releases.KEY_FILE, read at this checkout's own HEAD
EARLY_KEYS = "early-key.pub"        # releases.EARLY_KEY_FILE, read there too
FLOOR_FILE = "release-floor"        # in ~/.fleet: the newest release that this user's checkouts took
# What the hub may write on the configuration ref: the owner's own files. knowledge/ is all of it, and not only
# knowledge/owner/, because an agent writes the knowledge files its profile lists (hub.write_knowledge) and a file the
# hub can write but a release can replace is drift by construction. publish.py calls all of knowledge/ the fleet's own
# (OWNER_FILES). skills/ is each agent's own (design v4 D1): skills/<agent>/<name>/SKILL.md and the few small files
# beside it, at most two folders deep and never hidden.
CONFIG_FILES = re.compile(r"(?!.*\.\.)(?:team\.json|profiles/[A-Za-z0-9._-]+\.md|knowledge/[A-Za-z0-9._/-]+\.md|"
                          rf"{SKILLS}/[a-z][a-z0-9-]{{1,30}}/{SKILL_NAME}/{SKILL_FILE})\Z")
OUTPUTS = "outputs/"                # the files of a delivered task, which the hub commits (hub.commit_outputs)
DATA_MODE = "100644"                # a plain file: no program, no link and no submodule
GONE = "000000"                     # the mode git gives a path that a commit does not have
COMMIT = re.compile(r"[0-9a-f]{40}")


def data_path(path):
    """True for a path of the configuration ref that is data and never code: what a release leaves as the fleet has it
    (releases.Update), and what a checkout may take from the hub with no release."""
    return bool(CONFIG_FILES.match(path)) or (path.startswith(OUTPUTS) and ".." not in path.split("/"))


def _git(kit, run, *args, timeout=60):
    code, out, err = (run or _run)(["git", "-C", kit, *args], timeout=timeout)
    return code, out or "", (err or "").strip()


def _commit(kit, run, name):
    """The full commit id that `name` names in this repository, or None."""
    code, out, _ = _git(kit, run, "rev-parse", "--verify", "--quiet", f"{name}^{{commit}}")
    return out.strip() if code == 0 and COMMIT.fullmatch(out.strip()) else None


def _blob(kit, run, rev, path):
    """The text of one file of a commit, or None when the commit does not have it."""
    if _git(kit, run, "cat-file", "-e", f"{rev}:{path}")[0] != 0:
        return None
    code, out, _ = _git(kit, run, "cat-file", "blob", f"{rev}:{path}")
    return out if code == 0 else None


def _descends(kit, run, older, newer):
    """True when commit `older` is `newer` or in its history."""
    return older == newer or _git(kit, run, "merge-base", "--is-ancestor", older, newer)[0] == 0


def changed_paths(kit, run, old, new):
    """[(path, its mode in `new`)] of every path that differs between two commits, GONE for a path `new` does not
    have, or None when git cannot compare them. A rename is a path that went and a path that came."""
    code, out, _ = _git(kit, run, "diff", "--no-renames", "--raw", "-z", old, new)
    if code != 0:
        return None
    found, parts = [], out.split("\0")
    for at in range(0, len(parts) - 1, 2):
        if not parts[at].startswith(":"):
            break
        found.append((parts[at + 1], parts[at][1:].split()[1]))
    return found


def released(text):
    """The revision and version that a release.json names, or (None, None) when it names none."""
    try:
        said = json.loads(text)
    except ValueError:
        return None, None
    revision = said.get("revision") if isinstance(said, dict) else None
    if not (isinstance(revision, str) and COMMIT.fullmatch(revision)):
        return None, None
    version = said.get("version")
    return revision, version if isinstance(version, str) else None


def floor_path(home):
    """This user's floor: the newest release that its checkouts took."""
    return os.path.join(home, FLEET_DIR, FLOOR_FILE)


def read_floor(floor):
    """(the floor's revision or None, the reason it cannot be read or None). No file is no floor."""
    if not floor:
        return None, None
    try:
        with open(floor, encoding="utf-8") as f:
            revision, _ = released(f.read())
    except FileNotFoundError:
        return None, None
    except OSError as e:
        return None, f"the release floor {floor} cannot be read: {e}"
    return (revision, None) if revision else (None, f"the release floor {floor} names no release")


def keep_floor(kit, floor, run=None, head="HEAD"):
    """Raise this user's floor to the release that the checkout runs at `head`. It is never lowered: a release that does
    not descend from the floor leaves it as it is, and so does a floor that cannot be read, because may_take then says
    why. Called around every move, so the floor follows what each checkout took."""
    if not floor:
        return
    text = _blob(kit, run, head, RELEASE_FILE)
    revision, version = released(text) if text is not None else (None, None)
    if not revision:
        return
    current, problem = read_floor(floor)
    if problem or revision == current or (current and not _descends(kit, run, current, revision)):
        return
    with contextlib.suppress(OSError):
        os.makedirs(os.path.dirname(floor), mode=0o700, exist_ok=True)
        temp = f"{floor}.{os.getpid()}"
        with open(temp, "w", encoding="utf-8") as f:
            f.write(json.dumps({"revision": revision, "version": version}) + "\n")
        os.replace(temp, floor)


def may_take(kit, target, run=None, floor=None, head="HEAD"):
    """None when the checkout `kit` may move from `head` to `target`, else the one reason why it stays where it is.

    A move that changes data only (data_path) passes when each file it brings is a plain file. Any other move passes
    only onto a release: `target` carries a release.json that a key of `head`'s two key files signed, which is not
    held; its revision descends from the release that `head` runs and from the floor; and `target` is that revision's
    own tree outside the data. **A `head` with no release takes one that comes after the floor**: on a machine whose
    checkouts share one user (its agents and its server service), the first that took a signed release wrote the
    floor, and the others take theirs after it. They stayed where they were for every release after that (3 November
    2026: the Mac Studio's server service and Hgr-Support on worker-1, at the revisions of that morning). Every
    mover of a checkout calls this first: the helper's update and task-start sync, the server service, the hub, both
    installers, onboard.py and the owner's MCP server (the shell ones as `lifecycle.py may-take`)."""
    import releases                     # here and not at the top: releases imports this module
    old, new = _commit(kit, run, head), _commit(kit, run, target)
    if not old or not new:
        return f"{target if old else head} is not a commit of this checkout"
    if old == new:
        return None
    changed = changed_paths(kit, run, old, new)
    if changed is None:
        return f"git could not compare {old[:12]} with {new[:12]}"
    plain = [path for path, mode in changed if data_path(path) and mode not in (DATA_MODE, GONE)]
    if plain:
        return f"{new[:12]} brings {plain[0]}, which is not a plain file"
    if all(data_path(path) for path, _ in changed):
        return None
    text = _blob(kit, run, new, RELEASE_FILE)
    if text is None:
        return f"{new[:12]} changes Fleet's code and carries no signed release"
    try:
        manifest = releases.check(json.loads(text), releases.parse_keys(_blob(kit, run, old, RELEASE_KEYS) or "")
                                  + releases.parse_keys(_blob(kit, run, old, EARLY_KEYS) or ""))
    except ValueError:
        return f"the {RELEASE_FILE} of {new[:12]} cannot be read"
    except releases.Untrusted as e:
        return f"the release of {new[:12]} is refused: {e}"
    revision, version = manifest["revision"], manifest["version"]
    if manifest["hold"]:
        return f"release {version} is held: no fleet takes it"
    if not _commit(kit, run, revision):
        return f"the revision {revision[:12]} of release {version} is not in this repository"
    mine = _blob(kit, run, old, RELEASE_FILE)
    runs = released(mine)[0] if mine is not None else None
    if mine is not None and not runs:
        return f"the {RELEASE_FILE} that this checkout runs cannot be read"
    if runs and not _descends(kit, run, runs, revision):
        return f"release {version} does not descend from the release this checkout runs ({runs[:12]})"
    lowest, problem = read_floor(floor)
    if problem:
        return problem
    if lowest and not (_commit(kit, run, lowest) and _descends(kit, run, lowest, revision)):
        return f"release {version} does not descend from the newest release this user took ({lowest[:12]})"
    apart = changed_paths(kit, run, revision, new)
    if apart is None:
        return f"git could not compare {new[:12]} with release {version}"
    other = [path for path, _ in apart if path != RELEASE_FILE and not data_path(path)]
    if other:
        return f"{new[:12]} is not release {version}: it differs in {other[0]}"
    return None


def take(kit, target, run=None, floor=None, room=False):
    """Move this checkout onto `target` when may_take lets it: a fast-forward, and the floor raised to the release it
    then runs. `target` is read once, as one commit, and that commit is the one checked and the one taken, so a fetch
    in between moves nothing unchecked. room: first remove the outputs that it brings back tracked (give_way_to).
    None, or the reason why the checkout stays where it is."""
    keep_floor(kit, floor, run)
    commit = _commit(kit, run, target)
    if not commit:
        return f"{target} is not a commit of this checkout"
    problem = may_take(kit, commit, run, floor)
    if problem:
        return problem
    if room:
        give_way_to(kit, commit, run)
    code, out, err = _git(kit, run, "merge", "-q", "--ff-only", commit, timeout=120)
    if code != 0:
        return "git merge failed: " + (err or out.strip())[-200:]
    keep_floor(kit, floor, run)
    return None


def follow_config_ref(kit, run=None, floor=None):
    """Bring this checkout onto the configuration ref and up to date with it, fast-forward only, and only where
    may_take lets it. The hub commits the owner's team.json, profiles and knowledge there, so an agent reads the
    current RULES.md, its profile and the owner's knowledge, while code reaches this machine only with a signed
    release. Returns None when the checkout follows the ref, else the one reason why it stays as it is: a checkout
    with its own changes is never touched. An origin without the ref is a Fleet before the split of 2026-10-17, and
    is brought up to date as it was before, under the same check."""
    run = run or _run

    def git(*args, timeout=60):
        code, out, err = run(["git", "-C", kit, *args], timeout=timeout)
        return code, out.strip(), err.strip()

    code, _, err = git("fetch", "-q", "origin")
    if code != 0:
        return "git fetch failed: " + err[-200:]
    if git("status", "--porcelain", "--untracked-files=no")[1]:
        return "the checkout has its own changes, so it stays where it is"
    if git("rev-parse", "--verify", "--quiet", "refs/remotes/origin/" + CONFIG_BRANCH)[0] != 0:
        return take(kit, "@{upstream}", run, floor)
    if checkout_branch(kit, run) != CONFIG_BRANCH:
        here = git("rev-parse", "--verify", "--quiet", "refs/heads/" + CONFIG_BRANCH)[0] == 0
        keep_floor(kit, floor, run)
        # one commit, checked and then checked out, as take() does
        commit = _commit(kit, run, CONFIG_BRANCH if here else "origin/" + CONFIG_BRANCH)
        problem = may_take(kit, commit, run, floor) if commit else "the ref is not a commit of this checkout"
        if problem:
            return f"the checkout did not move onto {CONFIG_BRANCH}: {problem}"
        code, out, err = git("checkout", "-q", CONFIG_BRANCH) if here else \
            git("checkout", "-q", "-b", CONFIG_BRANCH, commit)
        if code == 0 and not here:
            code, out, err = git("branch", "-q", "--set-upstream-to=origin/" + CONFIG_BRANCH, CONFIG_BRANCH)
        if code != 0:
            return f"the checkout did not move onto {CONFIG_BRANCH}: " + (err or out)[-200:]
    return take(kit, "origin/" + CONFIG_BRANCH, run, floor, room=True)


# ---------------------------------------------------------------- data stops being code (DevOps plan v44, step 0.2)
#
# team.json is data that the hub writes, so no field of it may become code on a machine: each field that names a
# command line, a program or a variable is one of a fixed set that this module holds, and the machine refuses anything
# else where it uses it, whatever the hub let through. A closed start (support plan F1) is one more start form here.

LOCAL_PROVIDERS = ("ollama", "lmstudio")     # the local model servers that a local_model start may name


def start_forms(runtime):
    """Every start that team.json may give an agent of this runtime: Fleet's own forms (RUNTIMES full_access,
    manager_access and first_worker), each with and without Chrome's place before {settings} (hub.with_desktop), the
    full-access form with the runtime's local_model flag, alone or with one of LOCAL_PROVIDERS (the model is the
    agent's model setting, never a word of the start), a Codex form also without --no-daemon (the helper adds it), the
    agent command of an acp runtime, and APP_SERVER where the fleet speaks app-server to the runtime."""
    entry = RUNTIMES.get(runtime) or {}
    forms = {form["start"] for form in (entry.get("full_access"), entry.get("manager_access"))
             if form and form.get("start")}
    flag, full = entry.get("local_model"), (entry.get("full_access") or {}).get("start")
    if flag and full and " " in full:
        program, rest = full.split(" ", 1)
        forms |= {f"{program} {flag}{local} {rest}" for local in
                  ["", *(f" --local-provider {one}" for one in LOCAL_PROVIDERS)]}
    forms |= {one for one in (entry.get("first_worker"), entry.get("acp_command")) if one}
    forms |= {one.replace("{settings}", "{chrome} {settings}", 1) for one in forms
              if "{settings}" in one and "{chrome}" not in one}
    forms |= {one.replace("{chrome} ", "", 1) for one in forms}
    forms |= {one.replace(" --no-daemon", "", 1) for one in forms}
    if entry.get("app_server"):
        forms.add(APP_SERVER)
    return frozenset(forms)


def start_form(runtime, start):
    """True when `start` is one of this runtime's start forms (start_forms)."""
    return isinstance(start, str) and start in start_forms(runtime)


# The program of an agent's screen runtime (team.json screen_command): Codex with Computer Use, which the ChatGPT app
# keeps on a Mac (hub.with_desktop). One of these paths and no other is ever run as a screen runtime.
SCREEN_COMMANDS = ("/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex",)


def screen_program(conf):
    """The screen runtime's program of an agent's settings when it is one of SCREEN_COMMANDS, else None."""
    command = conf.get("screen_command") if isinstance(conf, dict) else None
    return command if command in SCREEN_COMMANDS else None


# The name of an API key in a session's environment. A team setting names these variables (a login's env, an MCP
# server's env), so a name must have the shape of a key's name and be none that a session's start or a runtime sets or
# reads itself: then no team setting can give a session a model address, a proxy or any other setting that a runtime
# or a tool reads as configuration. The helper keeps no other name (fleet.read_env, fleet.integration_env), and the
# hub takes no other.
KEY_ENV = re.compile(r"[A-Z][A-Z0-9_]{0,59}")
KEY_SUFFIXES = ("_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_PAT")
ENV_RESERVED = re.compile(r"(?:FLEET|BWS|LD|DYLD|ANTHROPIC|CLAUDE|CODEX|XAI)_[A-Z0-9_]*|PATH|HOME|SHELL|USER|LOGNAME|"
                          r"TMPDIR|TERM|PWD|IFS|ENV|BASH_ENV|ZDOTDIR|NODE_OPTIONS|PYTHONPATH|PYTHONHOME")


def key_env(name):
    """True for the name of an API key in a session's environment: it ends in _KEY, _TOKEN, _SECRET, _PASSWORD or _PAT,
    and it is not reserved (ENV_RESERVED)."""
    return isinstance(name, str) and bool(KEY_ENV.fullmatch(name)) and name.endswith(KEY_SUFFIXES) \
        and not ENV_RESERVED.fullmatch(name)


# Where a machine keeps the saved checks that its own sessions wrote, by the SHA-256 of their bytes:
# ~/fleet-checks/<sha256>.py, a folder of the agent's own user that its sessions may write. ~/.fleet holds the agent's
# key and its sessions' files, and Fleet's deny list keeps every session out of it (fleet.DENY). The hub keeps a saved
# check's text for the owner to read, and gives the helper only its SHA-256, so the code that runs is code that the
# agent's own session put on its own machine (fleet.run_check). The first store, ~/.fleet/checks/, is still read, so
# the checks that are there stay.
CHECK_STORE = "fleet-checks"
FIRST_CHECK_STORE = os.path.join(FLEET_DIR, "checks")
CHECK_FILE = re.compile(r"checks/[a-z0-9_]{1,64}\.py")      # a check of the code itself (hub.CHECK_PATH), never data


def check_stores(home):
    """The folders that the helper reads a saved check from, in that order."""
    return [os.path.join(home, CHECK_STORE), os.path.join(home, FIRST_CHECK_STORE)]


# ---- what a machine and an agent use (the owner, 4 November 2026: "do we have data of cpu/memory/disk usage for the
# different fleet servers? THAT would be useful for the Servers section, Agents AND also information that's good to
# know to the manager", and his yes the same day to the figures on Servers and to each agent's own use on Agents)
LOAD_KEYS = ("cpu_percent", "memory_used", "memory_total", "disk_used", "disk_total")
DATA_VOLUME = "/System/Volumes/Data"    # a Mac's own files: its system volume is sealed, and the free space is shared
MAC_MEMORY = ("Anonymous pages", "Pages purgeable", "Pages wired down", "Pages occupied by compressor")
USE_SPAN = 60                           # seconds: an agent's CPU is measured over at least this long (agent_use)


def machine_load(platform_name=sys.platform, run=None, loadavg=os.getloadavg, statvfs=os.statvfs, opener=open,
                 cores=os.cpu_count, exists=os.path.exists):
    """How busy and how full this machine is now: the five-minute load as a share of its cores, the memory in use and
    the disk. A Mac's memory in use is Activity Monitor's Memory Used (app memory, wired and compressed), and its disk
    is the data volume. A part that cannot be read is None."""
    load = dict.fromkeys(LOAD_KEYS)
    try:
        load["cpu_percent"] = round(loadavg()[1] / (cores() or 1) * 100, 1)
    except (OSError, IndexError, TypeError):
        pass
    try:
        if platform_name == "darwin":
            code, out, _ = (run or _run)(["sysctl", "-n", "hw.memsize"])
            total = int(out.strip()) if code == 0 and out.strip().isdigit() else None
            code, out, _ = (run or _run)(["vm_stat"])
            page = re.search(r"page size of (\d+) bytes", out) if code == 0 else None
            pages = dict((k, int(v)) for k, v in re.findall(r"^([^:\n]+):\s+(\d+)\.?\s*$", out, re.M)) if page else {}
            if total and all(k in pages for k in MAC_MEMORY):
                apps, purgeable, wired, compressed = (pages[k] for k in MAC_MEMORY)
                load["memory_used"] = (apps - purgeable + wired + compressed) * int(page.group(1))
                load["memory_total"] = total
        else:
            with opener("/proc/meminfo") as f:
                kb = dict((k, int(v)) for k, v in re.findall(r"^(\w+):\s+(\d+) kB", f.read(), re.M))
            if "MemTotal" in kb and "MemAvailable" in kb:
                load["memory_used"] = (kb["MemTotal"] - kb["MemAvailable"]) * 1024
                load["memory_total"] = kb["MemTotal"] * 1024
    except (OSError, ValueError):
        pass
    try:
        st = statvfs(DATA_VOLUME if platform_name == "darwin" and exists(DATA_VOLUME) else "/")
        load["disk_total"] = st.f_blocks * st.f_frsize
        load["disk_used"] = load["disk_total"] - st.f_bavail * st.f_frsize
    except OSError:
        pass
    return load


def cpu_seconds(text):
    """The CPU time of `ps -o time=`, in seconds: macOS writes minutes and seconds ("204:56.10"), Linux
    "[DD-]HH:MM:SS"."""
    days, _, clock = text.rpartition("-")
    seconds = 0.0
    for part in clock.split(":"):
        seconds = seconds * 60 + float(part)
    return seconds + 86400 * int(days or 0)


def agent_use(agent, mark=None, run=None, now=None, pid=None, cores=None):
    """What one agent's own processes use: its helper with what it started, and every pane of its tmux session with
    what runs there. The agents of a Mac share one user and one tmux server, so the session is what tells them apart,
    named whole ("=fleet-ivy:"): tmux takes a name as the start of another, and "fleet-ivy" found "fleet-ivy-lead".

    Returns ({cpu_percent, memory}, the mark for the next reading). memory is their resident memory now. CPU is their
    share of the machine's cores since the mark, at most 100, and None at the first reading of a helper: each process's
    CPU time against its own at the mark, so a process that started since counts whole. A process that started and
    ended between two readings is not in it: no `ps` column holds the time of reaped children (macOS -S and Linux
    --cumulative change other columns). A reading under USE_SPAN after the mark keeps the mark and its figure: a report
    that something asked for at once says no spike of a few seconds."""
    run = run or _run
    now = time.monotonic() if now is None else now
    code, out, _ = run(["tmux", "list-panes", "-s", "-t", f"=fleet-{agent}:", "-F", "#{pane_pid}"], timeout=5)
    roots = [os.getpid() if pid is None else pid] + ([int(p) for p in out.split() if p.isdigit()] if code == 0 else [])
    code, out, _ = run(["ps", "-A", "-o", "pid=,ppid=,rss=,time="], timeout=5)
    table = {}
    for line in out.splitlines() if code == 0 else []:
        words = line.split()
        try:
            table[int(words[0])] = (int(words[1]), int(words[2]) * 1024, cpu_seconds(words[3]))
        except (IndexError, ValueError):
            continue
    children = {}
    for one, (parent, _, _) in table.items():
        children.setdefault(parent, []).append(one)
    mine, todo = set(), [p for p in roots if p in table]
    while todo:
        one = todo.pop()
        if one not in mine:
            mine.add(one)
            todo += children.get(one, [])
    if not mine:
        return {"cpu_percent": None, "memory": None}, mark
    memory = sum(table[p][1] for p in mine)
    if mark and now - mark[0] < USE_SPAN:
        return {"cpu_percent": mark[2], "memory": memory}, mark
    seconds = {p: table[p][2] for p in mine}
    cpu = min(100.0, round(sum(max(0.0, s - mark[1].get(p, 0.0)) for p, s in seconds.items()) / (now - mark[0]) /
                           (cores or os.cpu_count() or 1) * 100, 1)) if mark else None
    return {"cpu_percent": cpu, "memory": memory}, (now, seconds, cpu)


class Lifecycle:
    def __init__(self, kit, agent, conf, post, busy, restart=None, run=_run, clock=time.time,
                 platform_name=sys.platform, home=None, vault=None, probe=None, models=codex_model_list, legacy=None,
                 switch=None, which=None, monotonic=time.monotonic, runtimes_busy=None, say=print, slow_file=None,
                 floor=None):
        self.kit, self.agent, self.conf, self.post, self.busy = kit, agent, conf, post, busy
        self.floor = floor              # this user's release floor (floor_path); None: no floor, as for a reading
        # () -> True while a session of this OS user may be using a runtime: its updates wait for False
        # (update_runtimes). None: this process updates no runtime, as for the server service's readings.
        self.runtimes_busy = runtimes_busy
        self.say = say                  # (text) -> a line in the helper's own log
        self.runtimes_tried = None      # when this process last tried a round of runtime updates (monotonic)
        self.runtime_round = None       # the thread of the round that runs now
        self.legacy = legacy            # () -> the windows without a session credential (owner API 1.12)
        self.switch = switch            # () -> {other_runtime_windows, owner_chat_bound}, for a manager also
                                        # manager_bound and manager_handover (owner feature runtime_switch)
        self.vault = vault              # () -> {mode, isolated}: where this machine keeps the vault token
        self.probe = probe              # (probe job) -> the vault's answer: which profile logins it can open
        self.codex_models = models      # (codex executable) -> (options, error)
        self.models = None              # the latest reading of the runtime's model options
        self.screen_models = None       # the same for the screen runtime (owner API 1.11)
        self.run, self.clock, self.platform = run, clock, platform_name
        # clock is the machine's own wall clock, which is what a reading's time has to be said in: the hub and the
        # app show it, and `fleet.py verify` reads it out of the sign-in file. tick measures with `monotonic`
        # instead, because a wall clock steps: NTP corrects a drifted machine, a VM's host sets it back, a Mac wakes
        # up somewhere else. Measured on the wall clock, a step backwards would hold the update gate for the whole
        # of the step (no task and no chat session starts, lifecycle.Updating at every event) and send no status
        # report in that time, so the machine would stop taking work while every screen showed it fine.
        self.monotonic = monotonic
        self.which = which              # (runtime) -> its executable, where this process cannot look for it itself
        self.home = home or os.path.expanduser("~")
        self.restart = restart or self.restart_service
        self.pending = None             # the hub revision of a requested update
        self.state = self.detail = None
        # Due at once, and said as a number rather than None because `monotonic` is time since this machine booted:
        # a plain 0.0 would hold the first report back for the rest of the first five minutes of uptime, which is
        # exactly when a helper starts (a user service at boot, launchd at login), and the hub would raise
        # `machine_stale` about a machine that had just come up.
        self.last_report = monotonic() - REPORT_EVERY
        self.lock = threading.Lock()
        self.report_lock = threading.Lock()     # one report at a time, so that the hub gets them in the order read
        self.gate = threading.Lock()    # held while a session starts, and from the idle check to the restart
        self.tools_changed = False      # the hub says the standing session's tool list is not the current one
        self.restarting = None          # when this process asked for its own restart
        self.loaded = self.revision()   # the revision this process runs; the checkout can move ahead of it
        # **No result waits for the report clock** (the owner, 25 October 2026: "it needs to be immediate"). What makes
        # a report due wakes the status thread (report_soon, an update request), a report that failed is tried again
        # within RETRY_MAX, and a report that something asked for is fast: it reuses the slow security reading.
        self.wake = threading.Event()
        self.soon = False               # a fast report is due now
        self.retry_at = None            # when a report that failed is tried again (monotonic), and how many failed
        self.failures = 0
        self.reported_once = False
        self.read_mono = None           # when the runtimes of the report being made were read (reading_age)
        self.slow_file = slow_file      # where this helper keeps its slow reading for the next process of this boot
        self.slow = self.load_slow()
        self.use_mark = None            # the CPU time of this agent's processes at its last use reading (agent_use)

    # ---- status
    def revision(self):
        code, out, _ = self.run(["git", "-C", self.kit, "rev-parse", "HEAD"])
        out = out.strip()
        return out if code == 0 and re.fullmatch(r"[0-9a-f]{40}", out) else None

    def running(self):
        """The revision this helper runs: its checkout when it started, or a later checkout that changed none of
        the files a helper loads (Python files and team.json), for example task outputs, a profile or a skill."""
        head = self.revision()
        if head and self.loaded and head != self.loaded:
            code, out, _ = self.run(["git", "-C", self.kit, "diff", "--name-only", self.loaded, head])
            if code == 0 and not any((p.endswith(".py") and not OWNER_ONLY.search(p) and not p.startswith(OUTPUTS)
                                      and not p.startswith(SKILLS + "/")) or p == "team.json" for p in out.split()):
                self.loaded = head
        return self.loaded or head

    def os_info(self):
        name = None
        if self.platform == "darwin":
            code, out, _ = self.run(["sw_vers", "-productVersion"])
            name = "macOS " + out.strip() if code == 0 and out.strip() else None
        else:
            try:
                with open("/etc/os-release") as f:
                    m = re.search(r'^PRETTY_NAME="?([^"\n]+)', f.read(), re.M)
                name = m.group(1) if m else None
            except OSError:
                pass
        code, out, _ = self.run(["uname", "-r"])
        return {"name": name, "kernel": out.strip() if code == 0 and out.strip() else None, "boot": self.boot()}

    def security(self):
        s = {"unattended_upgrades": None, "pending_security": None, "reboot_required": None,
             "firewall": None, "tailscale": None}       # tailscale: read as a report leaves (report)
        if self.platform == "darwin":
            code, out, _ = self.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
            if code == 0 and out.strip():
                s["firewall"] = "active" if "enabled" in out.lower() else "inactive"
            if self.agent is None:      # one reading for each Mac: the server service's, and no agent's
                s["desktop"] = self.desktop()
                self.remember_browser(s["desktop"]["browser"])
                code, out, _ = self.run(["sw_vers", "-productVersion"])
                s["macos_update"] = macos_update(out.strip() if code == 0 else None)
        else:
            code, out, _ = self.run(["systemctl", "is-enabled", "unattended-upgrades"])
            if out.strip():
                s["unattended_upgrades"] = out.strip() == "enabled"
            code, out, _ = self.run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=90)
            if code == 0:
                s["pending_security"] = len(re.findall(r"^Inst .*[Ss]ecurity", out, re.M))
            s["reboot_required"] = os.path.exists("/var/run/reboot-required")
            # OpenSSH that does not run lets nobody in with a password (a server that Tailscale's own SSH serves)
            code, out, _ = self.run(["systemctl", "is-active", "ssh.service", "ssh.socket"])
            s.update(ssh_keys_only=sshd_keys_only() if "active" in out.split() else None, npm_rule=npm_rule(),
                     upgraded_at=upgraded_at())
            try:
                with open("/etc/ufw/ufw.conf") as f:
                    m = re.search(r"^ENABLED=(\w+)", f.read(), re.M)
                if m:
                    s["firewall"] = "active" if m.group(1) == "yes" else "inactive"
            except OSError:
                pass
        try:
            s["vault"] = self.vault() if self.vault else None
        except Exception:
            s["vault"] = None
        return s

    def desktop(self):
        """What only hands at this Mac can put right: its lock, macOS's own setup screens, Chrome, Claude's extension
        and the ChatGPT app's sign-in, with no AI."""
        console = console_session(self.run)
        code, _, _ = self.run(["pgrep", "-x", "Google Chrome"])
        extension = chrome_extension(self.home)
        # Its answer means something only for a runtime that is signed in: a signed-out one reads no browser at all.
        claude = self.exe("claude") if extension and self.runtime("claude")["signed_in"] else None
        return {"locked": console[1] if console else None, "setup": setup_screens(self.run), "chrome": code == 0,
                "extension": extension, "browser": browser_connected(claude) if claude else None,
                "chatgpt": self.chatgpt()}

    def chatgpt(self):
        """Whether the ChatGPT app of this Mac is signed in: the copy of Codex it carries, which Computer Use runs
        through, and not the one a Codex agent has in its own home. False with no app, and when it says nothing: no agent
        gets a screen on a silence."""
        if not os.path.exists(CHATGPT_CODEX):
            return False
        _, out, err = self.run([CHATGPT_CODEX, "login", "status"])
        text = out + err
        return "Logged in" in text and "Not logged in" not in text

    def remember_browser(self, connected):
        """Leave the reading of Chrome where `fleet.py verify` reads it: over SSH it cannot read it, as a sign-in
        (remember_signed_in)."""
        try:
            write_json(desktop_path(self.home), {"at": self.clock(), "browser": connected})
        except OSError:
            pass                # the next reading writes it again

    def private_network(self):
        """Whether Tailscale says that it is up, or None when nothing says: no command, one that failed or hung, or a
        state that says neither. Only a report reads this, as it leaves (report). It waits 5 seconds and not 20,
        because a report that must be immediate reads it too."""
        app = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
        ts = shutil.which("tailscale") or (app if os.path.exists(app) else None)
        code, out, _ = self.run([ts, "status", "--json"], timeout=5) if ts else (1, "", "")
        try:
            state = json.loads(out).get("BackendState") if code == 0 else None
        except (ValueError, AttributeError):
            state = None
        return True if state in TAILSCALE_UP else False if state in TAILSCALE_DOWN else None

    def boot(self):
        """This boot of the machine: a reading saved before a reboot says nothing about the machine now."""
        if not hasattr(self, "_boot"):
            self._boot = None
            if self.platform == "darwin":
                code, out, _ = self.run(["sysctl", "-n", "kern.bootsessionuuid"])
                self._boot = (out.strip() or None) if code == 0 else None
            else:
                try:
                    with open("/proc/sys/kernel/random/boot_id") as f:
                        self._boot = f.read().strip() or None
                except OSError:
                    pass
        return self._boot

    def load_slow(self):
        """The slow reading that an earlier process of this boot saved, while it is younger than REPORT_EVERY: the
        first report of a restarted helper, after a settings change most often, is then a fast one too. The age is on
        the monotonic clock, which every process of one boot shares."""
        if not self.slow_file:
            return None
        try:
            with open(self.slow_file) as f:
                saved = json.load(f)
            if saved["boot"] and saved["boot"] == self.boot() and 0 <= self.monotonic() - float(saved["at"]) < REPORT_EVERY:
                return {"at": float(saved["at"]), "security": dict(saved["security"])}
        except (OSError, ValueError, TypeError, KeyError):
            pass
        return None

    def security_reading(self, fast):
        """security(), or for a fast report the last one while it is younger than REPORT_EVERY, with the vault read
        now. On Linux the scan runs `apt-get -s upgrade`, which can take a minute."""
        if fast and self.slow and 0 <= self.monotonic() - self.slow["at"] < REPORT_EVERY:
            reading = dict(self.slow["security"])
            try:
                reading["vault"] = self.vault() if self.vault else None
            except Exception:
                reading["vault"] = None
            return reading
        reading = self.security()
        self.slow = {"at": self.monotonic(), "security": {k: v for k, v in reading.items() if k != "vault"}}
        if self.slow_file and self.boot():
            try:
                os.makedirs(os.path.dirname(self.slow_file), mode=0o700, exist_ok=True)
                with open(self.slow_file + ".new", "w") as f:
                    json.dump(dict(self.slow, boot=self.boot()), f)
                os.replace(self.slow_file + ".new", self.slow_file)
            except OSError:
                pass            # the next full report saves it again
        return reading

    def access(self):
        """Whether the machine's own SSH server (or Tailscale SSH) and Screen Sharing are on. No root needed."""
        def listening(port):
            s = socket.socket()
            s.settimeout(1)
            try:
                s.connect(("127.0.0.1", port))
                return True
            except OSError:
                return False
            finally:
                s.close()
        if self.platform == "darwin":
            return {"ssh": listening(22), "screen_sharing": listening(5900)}
        ssh = None
        for unit in ("ssh", "sshd"):
            code, out, _ = self.run(["systemctl", "is-active", unit])
            if out.strip():
                ssh = ssh or out.strip() == "active"
        ts = shutil.which("tailscale")
        if ts and not ssh:
            code, out, _ = self.run([ts, "debug", "prefs"], timeout=5)
            try:
                ssh = bool(json.loads(out).get("RunSSH")) if code == 0 else ssh
            except ValueError:
                pass
        return {"ssh": ssh, "screen_sharing": None}

    def exe(self, name):
        """This runtime's executable.

        A reading made for ANOTHER OS user has to be given `which`, because this process cannot find that user's
        executable itself: its PATH is not that user's, and that user's home is its own at mode 700, so a look in
        its `~/.local/bin` is refused. Both ways of getting it wrong were live on 19 October 2026 — on one machine
        the service found nothing and read `signed_in: None`, on another it found its OWN codex and ran it as the
        agent, which answered for neither of them. The agent was signed in on both.
        """
        return self.which(name) if self.which else exe(name, self.home)

    def runtime(self, name=None):
        """{name, version, signed_in} of the agent's runtime, or of another one: status commands only, no model."""
        name = name or self.conf.get("runtime")
        result = {"name": name, "version": None, "signed_in": None}
        exe = self.exe(name)
        if not exe:
            return result
        code, out, _ = self.run([exe, "--version"])
        if code == 0 and out.strip():
            result["version"] = out.strip().splitlines()[0][:120]
        if name == "codex":
            code, out, err = self.run([exe, "login", "status"])
            text = out + err
            if text.strip():
                result["signed_in"] = "Logged in" in text and "Not logged in" not in text
        elif name == "claude":
            code, out, _ = self.run([exe, "auth", "status"])
            try:
                result["signed_in"] = bool(json.loads(out).get("loggedIn"))
            except ValueError:
                pass
        return result

    def collect(self, fast=False):
        with self.lock:
            update = {"state": self.state, "detail": self.detail}
        self.read_mono = self.monotonic()       # the runtimes are read from here on: the reading's age counts from it
        # owner feature runtime_switch: both runtimes that an owner can switch between, with the same status commands
        runtimes = {name: self.runtime(name) for name in SWITCH_RUNTIMES}
        self.remember_signed_in(runtimes)
        name = self.conf.get("runtime")
        said = {n: {"version": r["version"], "signed_in": r["signed_in"]} for n, r in runtimes.items()}
        outcomes = self.runtime_updates().get("runtimes") if self.runtimes_busy else None
        for n, outcome in outcomes.items() if isinstance(outcomes, dict) else ():
            if n in said and isinstance(outcome, dict):     # its last update, by any helper of this user
                said[n]["update"] = outcome
        return {"revision": self.running(), "os": self.os_info(), "security": self.security_reading(fast),
                "runtime": runtimes[name] if name in runtimes else self.runtime(),
                "runtimes": said,
                "access": dict(self.access(), user=pwd.getpwuid(os.getuid()).pw_name),
                "update": update, "features": list(FEATURES),
                "legacy_windows": self.legacy() if self.legacy else None,
                **(self.switch() if self.switch else {"other_runtime_windows": [], "owner_chat_bound": None}),
                "settings": self.settings(), "models": self.read_models(),
                "screen_settings": self.screen_settings(), "screen_models": self.read_screen_models(),
                "use": self.use()}

    def use(self):
        """What this agent's own processes use now (agent_use)."""
        use, self.use_mark = agent_use(self.agent, self.use_mark, self.run, self.monotonic())
        return use

    def remember_signed_in(self, runtimes):
        """Leave this sign-in reading in ~/.fleet, where a later `fleet.py verify` of this machine reads it.

        Only a Mac needs it, and this is the reason: there the runtime keeps its credential in the login Keychain,
        which opens for the login session alone. This process is a LaunchAgent of that session and reads it; the
        same reading taken over the owner's SSH connection, where the app runs the check, reads `loggedIn: false`
        on a machine that is signed in - as the same user, and as root through `launchctl asuser` too (both proved
        on the owner's Mac Studio, 19 October 2026; an SSH session's keychain search list holds the System
        keychain and not the user's login one). So the check answers from the reading made here, and the app's two
        screens cannot disagree about one machine. A failure to write is no failure of the status: the next report
        writes it again.
        """
        if self.platform != "darwin":
            return
        path = signed_in_path(self.home, self.agent)
        said = {"at": self.clock(), "signed_in": {name: r.get("signed_in") for name, r in runtimes.items()}}
        try:
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            tmp = path + ".new"
            with open(tmp, "w") as f:
                json.dump(said, f)
            os.replace(tmp, path)       # whole or not at all: verify reads this file while the helper writes it
        except OSError:
            pass

    # ---- agent setup (owner API 1.9)
    def settings(self):
        """What this process loaded: new sessions get this model, effort and these capabilities. Its runtime is the
        name in the status's runtime (owner feature runtime_switch)."""
        return {"model": self.conf.get("model"), "effort": self.conf.get("effort"), "can": list(self.conf.get("can") or [])}

    def screen_settings(self):
        """What this process loaded for screen tasks (owner API 1.11): {model, effort}, or None without a screen
        runtime."""
        if not self.conf.get("screen_command"):
            return None
        screen = self.conf.get("screen") or {}
        return {"model": screen.get("model"), "effort": screen.get("effort")}

    def read_screen_models(self, force=False):
        """The screen runtime's own model options (its Codex account), as read_models: model/list only, no thread and
        no turn. None without a screen runtime."""
        if not self.conf.get("screen_command"):
            return None
        command = screen_program(self.conf)             # one of the fixed paths (DevOps plan 0.2)
        if not force and self.screen_models and self.clock() - self.screen_models["read_at"] < MODELS_EVERY:
            return self.screen_models
        options, error = self.codex_models(command) if command and os.path.isfile(command) else \
            (None, "the screen runtime is not installed" if command else "the screen runtime is not one of Fleet's own")
        self.screen_models = {"runtime": APP_SERVER_RUNTIME, "ok": options is not None, "read_at": self.clock(),
                              "source": "codex app-server model/list", "other_names": False,
                              "error": None if options is not None else error, "options": options or []}
        return self.screen_models

    def read_models(self, force=False):
        """The runtime's own model options for this machine and account, read at most every six hours, and again
        for a machine check. No model runs for it."""
        if not force and self.models and self.clock() - self.models["read_at"] < MODELS_EVERY:
            return self.models
        name = self.conf.get("runtime")
        options, error, source = self.model_options(name, self.exe(name))
        self.models = {"runtime": name, "ok": options is not None, "read_at": self.clock(), "source": source,
                       "other_names": name == "claude", "error": None if options is not None else error,
                       "options": options or []}
        return self.models

    def model_options(self, name, exe):
        """(options, error, source): one runtime's own model options, read with its executable exe (None when it is
        not installed). The reading of read_models, and the check of a runtime update (runtime_check)."""
        if name == "codex":
            options, error = self.codex_models(exe) if exe else (None, "codex is not installed")
            return options, error, "codex app-server model/list"
        if name == "claude":
            code, out, _ = self.run([exe, "--help"]) if exe else (1, "", "")
            options, error = claude_model_list(out) if code == 0 else (None, "claude is not installed" if not exe
                                                                        else "claude --help did not answer")
            return options, error, "claude --help"
        return None, "This runtime reports no model list.", None

    def verify(self, status, probe_job=None):
        """The setup check: what this machine can prove now, with no AI. Each item is ok, failed or not_verified;
        the hub adds its own items and decides which ones are required."""
        items = []

        def add(kind, ref, state, detail):
            items.append({"kind": kind, "ref": ref, "state": state, "detail": detail[:300]})
        rt = status.get("runtime") or {}
        name = rt.get("name") or "unknown"
        if not rt.get("version"):
            add("runtime", name, "failed", f"{name} is not installed.")
        elif rt.get("signed_in") is True:
            add("runtime", name, "ok", f"{rt['version']}, signed in")
        elif rt.get("signed_in") is False:
            add("runtime", name, "failed", f"{rt['version']}, not signed in")
        else:
            add("runtime", name, "not_verified", f"{rt['version']}; the sign-in could not be read")
        add(*self.model_item(status.get("models")))
        user = pwd.getpwuid(os.getuid()).pw_name
        add("capability", "shell", "ok", f"Commands run as {user}.")
        add("capability", "web", "not_verified", "Web access is a runtime tool; Fleet cannot check it without a model turn.")
        if self.platform == "darwin":
            tabs = RUNTIMES.get(name, {}).get("browser_tabs")
            exe = self.exe(name) if tabs else None
            for item in desktop_items(self.run, self.home, user, tabs, browser_connected(exe) if exe else None):
                add(*item)
        else:
            add("capability", "browser", "failed", "A Linux worker has no desktop session for a browser.")
            add("capability", "screen", "failed", "A Linux worker has no desktop session.")
        items += self.login_items(probe_job)
        code, out, _ = self.run(["id", "-Gn"])
        add("access", "os_user", "ok", f"{user} (uid {os.getuid()}), groups: " +
            (", ".join(out.split()) if code == 0 and out.strip() else "unknown"))
        add("access", "files", "ok", f"The agent can read and change every file that {user} can, including this Fleet "
                                     f"checkout.")
        add(*self.admin_item())
        return items

    def model_item(self, reading):
        model, effort = self.conf.get("model"), self.conf.get("effort")
        ref = model or "default"
        if not reading or not reading.get("ok"):
            return ("model", ref, "failed" if model or effort else "not_verified",
                    (reading or {}).get("error") or "There is no model list.")
        options = {o["model"]: o for o in reading["options"]}
        if model and model not in options:
            if reading.get("other_names") and re.fullmatch(r"claude-[a-z0-9.-]+", model):
                return ("model", ref, "not_verified", "Claude takes full model names that it does not list; the first "
                                                      "session shows the model that it uses.")
            return ("model", ref, "failed", f"{model} is not offered here.")
        o = options.get(model) if model else next((x for x in reading["options"] if x["default"]), None)
        efforts = o["efforts"] if o else sorted({e for x in reading["options"] for e in x["efforts"]})
        if effort and effort not in efforts:
            return ("model", ref, "failed", f"{effort} is not an effort of {model or 'the default model'} here.")
        return ("model", ref, "ok", ("Offered" if model else "The default model") +
                (" with the efforts " + ", ".join(efforts) + "." if efforts else "."))

    def admin_item(self):
        sudo = shutil.which("sudo")
        if not sudo:
            return ("access", "admin", "not_verified", "sudo is not installed.")
        code, out, _ = self.run([sudo, "-n", "-l"])
        if code != 0:
            return ("access", "admin", "ok", "No administrator command runs without a password.")
        if re.search(r"\(ALL(?:\s*:\s*ALL)?\)\s*NOPASSWD:\s*ALL\b", out):
            return ("access", "admin", "ok", "Unrestricted administrator access without a password (sudo -n -l).")
        if "NOPASSWD" in out:
            return ("access", "admin", "ok", "Some administrator commands run without a password (sudo -n -l).")
        return ("access", "admin", "ok", "Administrator commands need a password.")

    def login_items(self, job):
        """The vault's fixed answer for each login of the profile. With no answer, the hub shows them as not probed."""
        if not job or not self.probe:
            return []
        try:
            answer = self.probe(job)
        except Exception:
            return []
        results = answer.get("results") if isinstance(answer, dict) and answer.get("ok") is True else None
        return [{"kind": "login", "ref": r["login"], "state": "ok" if r["state"] == "readable" else "failed",
                 "detail": r["reason"]} for r in (results if isinstance(results, list) else [])[:32]
                if isinstance(r, dict) and isinstance(r.get("login"), str) and r["login"].startswith("bws://")
                and r.get("state") in ("readable", "not_readable") and r.get("reason") in LOGIN_REASONS]

    def report(self, check=None, probe_job=None, fast=False):
        """Send the status. The status thread and the helper's loop both report; one at a time, each from its own
        reading, so that an older reading never arrives after a newer one and stands at the hub until the next.

        fast: a report that something asked for (report_soon, a sign-in), which reuses the slow security reading. Every
        report says how old its runtime reading is when it leaves (reading_age), so the hub dates it by when it was
        taken. One that does not reach the hub is tried again within RETRY_MAX, fast, and only one that does moves the
        report clock."""
        with self.report_lock:
            try:
                if check:
                    self.read_models(force=True)    # a machine check reads the model options again
                    self.read_screen_models(force=True)
                status = self.collect(fast=fast and not check)
                if check:
                    status["check"] = check         # this report answers the owner's "check this machine"
                    status["verify"] = self.verify(status, probe_job)
                # Tailscale, as the report leaves, and never saved: a report goes over the private network, so a reading
                # from before it says "off" when the network is back, and a retry after a break would repeat that.
                status["security"]["tailscale"] = self.private_network()
                status["reading_age"] = round(max(0.0, self.monotonic() - self.read_mono), 3)
                code, data = self.post(status)
            except Exception:
                code, data = None, None
            if code == 200:
                self.last_report, self.failures, self.retry_at = self.monotonic(), 0, None
                self.reported_once = True
            else:
                self.failures += 1
                self.retry_at = self.monotonic() + min(RETRY_MAX, 2 ** (self.failures - 1))
                return False
        if code == 200 and isinstance(data, dict):
            # The standing manager session is running on a tool list this hub would no longer serve: its helper
            # starts it again (Helper.restart_for_tools). It stays true in every answer until that session has
            # asked for the list again, so a helper that cannot act now acts at its next round.
            self.tools_changed = bool(data.get("manager_tools_changed"))
            if data.get("update_requested"):
                self.arm(data.get("desired_revision"))
        return code == 200

    # ---- updates
    def set(self, state, detail):
        with self.lock:
            self.state, self.detail = state, detail

    def arm(self, desired):
        """An update that the hub requests. Every helper takes it the same way, the manager's included: its checkout,
        its home and its user service are its own, so the fast-forward and the restart need no root (hub's
        `request_update` says why that was not always so)."""
        if desired is not None and not (isinstance(desired, str) and re.fullmatch(r"[0-9a-f]{7,40}", desired)):
            return
        with self.lock:
            if self.state == "updating":
                return
            self.pending = desired
            self.state, self.detail = "waiting_idle", "Waits until no turn runs in a task session."

    def check(self, extra):
        """The owner's "check this machine": collect and report now. The same checks as every report, no change."""
        check, job = (extra or {}).get("check"), (extra or {}).get("probe_job")
        if isinstance(check, int) and not isinstance(check, bool):
            self.report(check=check, probe_job=job if isinstance(job, int) and not isinstance(job, bool) else None)

    def request(self, extra):
        """An update event from the hub: arm it, and wake the status thread, which says so and applies it at once when
        this machine is idle — not at its next tick, and not in the helper's own loop."""
        self.arm((extra or {}).get("desired_revision"))
        self.report_soon()

    def report_soon(self):
        """A fast report now, from the status thread (event status_now, a sign-in, an update request). Requests that
        come while one is made give one more, not one each."""
        self.soon = True
        self.wake.set()

    @contextlib.contextmanager
    def session_start(self):
        """The helper opens every task and chat session inside this. It never waits: during an update it
        raises Updating, the event stays pending, and the restarted helper starts the session."""
        if not self.gate.acquire(blocking=False):
            raise Updating()
        try:
            yield
        finally:
            self.gate.release()

    def fail(self, detail):
        with self.lock:
            self.pending = None
        self.set("failed", detail)
        self.report()
        return False

    def upstream(self):
        """The remote configuration ref that this checkout follows: the branch it is on, at origin."""
        return "origin/" + (checkout_branch(self.kit, self.run) or CONFIG_BRANCH)

    def has(self, desired):
        """True when this checkout contains the requested commit and origin's configuration ref has the checkout's
        own commit too. The checkout can be past the requested commit: the hub machine's checkout is also the hub's,
        which can commit again before this helper takes its update (the hub pushes each of its commits first). A
        commit that only this checkout has is one that the hub cannot know, and its update would never close."""
        return self.run(["git", "-C", self.kit, "merge-base", "--is-ancestor", desired, "HEAD"], timeout=30)[0] == 0 and \
            self.run(["git", "-C", self.kit, "merge-base", "--is-ancestor", "HEAD", self.upstream()], timeout=30)[0] == 0

    def apply(self, desired):
        """Runs with the gate held. True when the restart was asked for: this process ends soon."""
        self.set("updating", "Updating Fleet while idle.")
        self.report()
        target = desired or self.upstream()
        # A checkout that has the requested commit already needs no fetch or merge: on the hub machine the checkout is
        # also the hub's, whose own git work a fetch here could disturb.
        if not (desired and self.has(desired)):
            code, out, err = self.run(["git", "-C", self.kit, "fetch", "-q", "origin"], timeout=120)
            if code != 0:
                return self.fail("The checkout could not fetch: " + (err or out).strip()[-300:])
            # The one check of every move (may_take), and the files of a task that this machine delivered.
            problem = take(self.kit, target, self.run, self.floor, room=True)
            if problem:
                return self.fail("The checkout did not move: " + problem[-300:])
        if desired and not (self.revision() or "").startswith(desired) and not self.has(desired):
            return self.fail("The checkout is not at the requested revision.")
        with self.lock:
            self.pending = None
        if self.restart():
            return True                 # the new helper process reports the new revision
        return self.fail("Updated the checkout; restart the helper service to load it.")

    def restart_service(self):
        if self.platform == "darwin":
            argv = ["launchctl", "kickstart", "-k", "gui/%d/com.agentfleet.%s" % (os.getuid(), self.agent)]
        else:
            argv = ["systemctl", "--user", "--no-block", "restart", "fleet-%s.service" % self.agent]
        return self.run(argv, timeout=30)[0] == 0

    def tick(self):
        if self.restarting is not None and self.monotonic() - self.restarting >= RESTART_GRACE:
            self.restarting = None
            self.fail("Updated the checkout, but the helper did not restart. Restart its service to load it.")
            self.gate.release()
        if self.soon or (self.retry_at is not None and self.monotonic() >= self.retry_at):
            self.soon = False
            self.report(fast=True)
        elif self.retry_at is None and self.monotonic() - self.last_report >= REPORT_EVERY:
            # A new process's first report takes the slow reading an earlier one of this boot saved (load_slow).
            self.report(fast=not self.reported_once)
        self.start_runtime_updates()
        with self.lock:
            ready = self.state == "waiting_idle"
            desired = self.pending
        if not ready or not self.gate.acquire(blocking=False):
            return                      # nothing to do, or a session is starting: try at the next tick
        restarted = False
        try:
            # Checked while no session can start, and with the update marked under the same lock that a sign-in
            # checks it with (Helper.begin_signin), so none can start between this check and the update.
            with self.lock:
                idle = not self.busy()
                if idle:
                    self.state, self.detail = "updating", "Updating Fleet while idle."
            if idle:
                restarted = self.apply(desired)
        except Exception as e:
            self.fail("The update stopped: %s." % type(e).__name__)
        finally:
            if restarted:
                self.restarting = self.monotonic()  # keep the gate until this process ends
            else:
                self.gate.release()

    def run_forever(self):
        while True:
            try:
                self.tick()
            except Exception:
                pass
            wait = TICK if self.retry_at is None else max(0.0, min(TICK, self.retry_at - self.monotonic()))
            self.wake.wait(wait)        # report_soon and an update request end it at once
            self.wake.clear()

    # ---- runtime updates (the owner, 22 October 2026: "they should probably update themselves too, right?")
    def start_runtime_updates(self):
        """Start one round of runtime updates when it is due and no session of this user uses a runtime. A Fleet
        update that waits or runs goes first. The idle check is made with the session gate held, so no session
        starts from that check on; the round runs in a thread of its own that keeps the gate until it ends, and this
        thread goes on sending the status reports while an installer works."""
        if self.runtimes_busy is None or (self.runtime_round and self.runtime_round.is_alive()):
            return
        with self.lock:
            if self.state in ("waiting_idle", "updating"):
                return
        if not self.runtimes_due() or not self.gate.acquire(blocking=False):
            return
        try:
            idle = not self.busy() and not self.runtimes_busy()
        except Exception:
            idle = False
        if not idle:
            self.gate.release()
            return
        try:
            self.runtime_round = threading.Thread(target=self.update_runtimes, name="runtime-updates", daemon=True)
            self.runtime_round.start()
        except Exception:
            self.gate.release()         # a gate that nothing releases would keep every session from starting
            raise

    def runtimes_due(self):
        """True when the last round of this user's runtime updates began RUNTIME_UPDATE_EVERY ago or more. The time
        is kept in the user's ~/.fleet, because a helper restarts with every Fleet update and a time in its memory
        alone would be due again after each one. A time ahead of the clock is not believed, so a clock that was set
        back never stops the updates. This process's own last try also counts, on its monotonic clock, so a file
        or a lock that cannot be written never lets one try follow another at every tick."""
        if self.runtimes_tried is not None and self.monotonic() - self.runtimes_tried < RUNTIME_UPDATE_EVERY:
            return False
        at = self.runtime_updates().get("at")
        return not (isinstance(at, (int, float)) and 0 <= self.clock() - at < RUNTIME_UPDATE_EVERY)

    def runtime_updates(self):
        """{at, runtimes} of this user's ~/.fleet: when its last round of runtime updates began, and the outcome for
        each runtime (update_runtime). {} when there is none, or none that can be read."""
        try:
            with open(os.path.join(self.home, FLEET_DIR, RUNTIME_UPDATES_FILE)) as f:
                saved = json.load(f)
        except (OSError, ValueError):
            return {}
        return saved if isinstance(saved, dict) else {}

    def save_runtime_updates(self, saved):
        """Write {at, runtimes} whole or not at all, because the other helpers of this user read it. A failure is
        said, and the round goes on: runtimes_tried keeps this process's next try six hours away."""
        path = os.path.join(self.home, FLEET_DIR, RUNTIME_UPDATES_FILE)
        try:
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            with open(path + ".new", "w") as f:
                json.dump(saved, f)
            os.replace(path + ".new", path)
        except OSError as e:
            self.say(f"runtime updates: {path} could not be written ({type(e).__name__})")

    @contextlib.contextmanager
    def runtime_lock(self):
        """This user's lock on its runtime updates, taken without a wait: True inside when this process has it. The
        helpers of one user share its ~/.local/bin, so two of them never run an installer into it at the same time."""
        path = os.path.join(self.home, FLEET_DIR, RUNTIME_UPDATES_LOCK)
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        with open(path, "a") as f:
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                held = True
            except OSError:
                held = False
            yield held                  # the lock ends with the file

    def update_runtimes(self):
        """One round, in its own thread, with the session gate that start_runtime_updates took: no task, chat or
        conversation session starts until it ends, so none starts on a runtime that is being replaced or checked. A
        session that runs keeps the program it started with and is not restarted; the next session starts on what
        the round leaves. The round ends with a status report, so that the hub has the new versions at once."""
        try:
            with self.runtime_lock() as held:
                # Due again under the lock: another helper of this user can have done the round a moment ago.
                if held and self.runtimes_due():
                    began, done = self.clock(), {}
                    self.save_runtime_updates({"at": began, "runtimes": done})
                    for name in onboard.RUNTIME_PINS:       # the runtimes that Fleet installs, and so updates
                        outcome = self.update_runtime(name)
                        if outcome:
                            done[name] = outcome
                            self.say(f"runtime update of {runtime_fact(name, 'label', name)} ({outcome['result']}): "
                                     f"{outcome['detail']}")
                            self.save_runtime_updates({"at": began, "runtimes": done})
        except Exception as e:
            self.say(f"runtime updates: the round stopped ({type(e).__name__})")
        finally:
            self.runtimes_tried = self.monotonic()      # whatever happened, this process tries again in six hours
            self.gate.release()
        self.report()

    def update_runtime(self, name):
        """One runtime of this user brought to the vendor's newest version, and checked. None when it is not
        installed, else the outcome {result (RUNTIME_RESULTS), at, detail}:

        1. Only the vendor's own installation (vendor_install), only when its owner did not turn its updates off
           (onboard.updates_off), and only a version that passes the check now, because the new one is held to
           what the installed one does. Otherwise it is skipped and nothing runs.
        2. The vendor's update (onboard.runtime_update), as this user, for at most RUNTIME_INSTALL_WAIT.
        3. The same check of what is there now (runtime_check), and a version that is not older than before.
        4. When that fails, the previous version again (onboard.runtime_install), which must answer as it did."""
        exe = self.exe(name)
        if not exe:
            return None

        def outcome(result, detail):
            return {"result": result, "at": self.clock(), "detail": detail[:300]}

        def shell(script):
            code, out, err = self.run(["/bin/sh", "-c", 'mkdir -p "$HOME/.local/bin" && ' + script],
                                      timeout=RUNTIME_INSTALL_WAIT, cwd=self.home)
            return code, " ".join((err or out).split())[-160:]

        why = self.vendor_install(name, exe) or onboard.updates_off(name, self.home)
        if why and self.adoptable(name, exe):
            # The vendor's own installation for this user, at the version Founderizer pins, in front of the other one
            # on this user's PATH (onboard.SERVICE_PATH); then the update below takes it to the newest.
            local = os.path.join(self.home, ".local", "bin", name)
            pin = onboard.RUNTIME_PINS[name]
            code, said = shell(onboard.runtime_install(name, pin))
            version, problem = self.runtime_check(name, local) if os.path.exists(local) else \
                (None, said or "the installer put nothing in ~/.local/bin")
            if problem:
                with contextlib.suppress(OSError):
                    os.remove(local)            # the other installation answers again, as it did before
                return outcome("skipped", f"{exe} is not the vendor's installation, and the vendor's {name} {pin} "
                                          f"for this user failed its check ({problem}), so {exe} stays.")
            if name == "claude":        # its own updates follow the stable channel, as install_runtime sets them
                self.run([sys.executable, "-c", onboard.CLAUDE_CHANNEL, local], timeout=120)
            exe, why = local, onboard.updates_off(name, self.home)
        if why:
            return outcome("skipped", f"{why}, so it stays as it is.")
        old, problem = self.runtime_check(name, exe)
        if problem:
            return outcome("skipped", f"The installed {old or name} does not pass the check now ({problem}), so no "
                                      f"new version is tried.")
        code, said = shell(onboard.runtime_update(name))
        new, problem = self.runtime_check(name, exe)
        if not problem and not onboard.not_older(new, old):
            problem = f"it is older than {old}"
        if not problem:
            if new != old:
                return outcome("updated", f"Updated from {old} to {new}, which passed its check.")
            if code == 0:
                return outcome("current", f"{old} stays: the vendor gives no newer version.")
            return outcome("failed", f"The update did not run ({said or 'exit status %d' % code}); {old} stays and "
                                     f"passes its check.")
        tried = new or "The new version"
        code, said = shell(onboard.runtime_install(name, old))
        if self.version_of(exe) == old:
            return outcome("rolled_back", f"{tried} failed its check ({problem}), so {old} is installed again.")
        return outcome("failed", f"{tried} failed its check ({problem}), and {old} did not come back "
                                 f"({said or 'exit status %d' % code}). Install {old} again on this machine.")

    def vendor_install(self, name, exe):
        """Why this runtime is not the vendor's own installation, which the helper updates, or None when it is: the
        command that this user's PATH finds is ~/.local/bin/<name>, where the vendor's installer puts it, and it is
        the vendor's program and no script. Another installer's runtime (Homebrew, npm, a system package) is that
        installer's to update, and a launcher of the owner's own in ~/.local/bin (one that reads a key from the
        Keychain first, say) stays exactly as it is."""
        if os.path.normpath(exe) != os.path.join(os.path.normpath(self.home), ".local", "bin", name):
            return f"{exe} is not the vendor's installation in ~/.local/bin"
        try:
            with open(exe, "rb") as f:          # through the link that the vendor's installer makes, if any
                script = f.read(2) == b"#!"
        except OSError:
            return f"{exe} cannot be read"
        return f"{exe} is a script and not the vendor's program" if script else None

    def adoptable(self, name, exe):
        """True when this user takes the vendor's own installation in place of a system one: on Linux, an agent's own
        OS user (`fleet-<agent>`) whose PATH finds the runtime in /usr/bin or /usr/local/bin (a system package, an
        npm install as root), with nothing of it in ~/.local/bin yet. A runtime that was on the machine before
        Founderizer made the agent's install skip the vendor's installer, so it never got an update (the owner's own
        hub ran Claude Code 2.1.285 from /usr/bin on 22 October 2026). A Mac keeps one user with a person in it, so its
        installations stay that person's, and Homebrew's stay Homebrew's."""
        return (self.platform == "linux" and os.path.dirname(os.path.normpath(exe)) in ("/usr/bin", "/usr/local/bin")
                and os.path.basename(os.path.normpath(self.home)).startswith("fleet-")
                and not os.path.lexists(os.path.join(self.home, ".local", "bin", name)))

    def runtime_check(self, name, exe):
        """(version, problem) of one installed runtime: the version that its --version answers, and why the check
        fails, or None when it passes. The check is the helper's own reading for the hub: --version answers a
        version, and the runtime's model options can be read (model_options). No model runs."""
        version = self.version_of(exe)
        if not version:
            return None, f"{name} --version answers no version"
        options, error, _ = self.model_options(name, exe)
        return version, None if options is not None else error

    def version_of(self, exe):
        """The version that a runtime's --version answers, or None."""
        code, out, _ = self.run([exe, "--version"])
        found = VERSION.search(out) if code == 0 else None
        return found.group(0) if found else None


def main(argv=None):
    """`python3 lifecycle.py may-take [--floor FILE] KIT TARGET`: may_take for a mover written in shell (join.sh,
    hub.sh, and what onboard.py and owner_mcp.py run on a machine). It raises this user's floor to the release that KIT
    runs, then answers with its exit status: 0 when KIT may move onto TARGET, else 1 and the one reason on standard
    error. The caller makes the move itself, with `git merge --ff-only TARGET`."""
    import argparse
    parser = argparse.ArgumentParser(prog="lifecycle.py", description="The one check of every move of a checkout")
    sub = parser.add_subparsers(dest="cmd", required=True)
    check = sub.add_parser("may-take", help="may this checkout move onto that commit?")
    check.add_argument("--floor", default=floor_path(os.path.expanduser("~")),
                       help="this user's release floor (default ~/.fleet/release-floor)")
    check.add_argument("kit", help="the checkout")
    check.add_argument("target", help="the commit it would move onto")
    args = parser.parse_args(argv)
    kit = os.path.abspath(args.kit)
    keep_floor(kit, args.floor)
    problem = may_take(kit, args.target, floor=args.floor)
    if problem:
        print(f"lifecycle.py may-take: {problem}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

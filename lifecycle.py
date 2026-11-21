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
import hashlib
import http.client
import json
import math
import os
import plistlib
import pwd
import queue
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

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


# The kernel's own file for the most memory that all users' processes of a server may hold together: the agents'
# sessions, their helpers and each login are in systemd's user.slice. Any user reads it.
USER_SLICE_MAX = "/sys/fs/cgroup/user.slice/memory.max"


def memory_guard(path=USER_SLICE_MAX):
    """Whether all users' processes of this server together have a memory limit, which the join's hardening sets
    (hubsetup.py harden): True for a number of bytes, False for the kernel's "max", which is no limit, and None when
    the file cannot say (a system with no memory groups of this kind, a Mac, a word that is neither).

    With no limit, a job that takes all the memory takes it from SSH, Tailscale and the server's own services too, and
    the server answers nothing until somebody restarts it at its provider (17 November 2026, a server of 4 GB: 55
    minutes and then 22 minutes at 95% of its memory, and the kernel ended no process in either)."""
    try:
        with open(path, encoding="ascii") as f:
            word = f.read().strip()
    except (OSError, UnicodeDecodeError):
        return None
    return False if word == "max" else True if word.isdigit() else None


# The kernel's own words for a server that stops: the seconds after a kernel panic until the kernel restarts the server
# (0: it waits forever), and the state of each watchdog device, which restarts the server when the program that holds
# it open (systemd, RuntimeWatchdogSec) stops pinging it. Any user reads both.
PANIC_SECONDS = "/proc/sys/kernel/panic"
WATCHDOG_DEVICES = "/sys/class/watchdog"
# The marks of a container, which its host restarts: systemd's own (systemd-detect-virt reads it) and Podman's. Both
# are in /run, which each start makes new, so neither stays in a disk image that was made from a container, as
# Docker's /.dockerenv can. A container shows the host's kernel and the host's watchdog devices.
CONTAINER_MARKS = ("/run/systemd/container", "/run/.containerenv")


def in_container(root=""):
    """Whether this system is a container (CONTAINER_MARKS), under `root` for the tests."""
    return any(os.path.lexists(root + mark) for mark in CONTAINER_MARKS)


def restart_guard(panic=PANIC_SECONDS, watchdogs=WATCHDOG_DEVICES, root=""):
    """Whether this server restarts by itself when it stops, which the join's hardening sets (hubsetup.py harden):
    True when a kernel panic restarts it (kernel.panic is not 0) and a watchdog device is active (systemd holds it
    open and pings it), False when either is not so, and None when the kernel's file of the panic cannot say (a Mac)
    and in a container, whose kernel and watchdog are its host's.

    With neither, a server whose kernel panicked or whose system stopped answers nothing until somebody restarts it at
    its provider (17 November 2026: a server of 4 GB stayed silent for 22 minutes, until a restart at its provider)."""
    if in_container(root):
        return None
    try:
        with open(panic, encoding="ascii") as f:
            seconds = int(f.read().strip())
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    return seconds != 0 and watchdog_active(watchdogs)


def watchdog_active(watchdogs=WATCHDOG_DEVICES):
    """Whether a watchdog device of this server is active: a program holds it open, and the kernel restarts the
    server when that program stops pinging it. False with no such device."""
    for state in sorted(glob.glob(glob.escape(watchdogs) + "/watchdog*/state")):
        try:
            with open(state, encoding="ascii") as f:
                if f.read().strip() == "active":
                    return True
        except (OSError, UnicodeDecodeError):
            continue
    return False


def upgraded_at(path=UPGRADE_STAMP):
    """When apt's daily run last ended a security upgrade well, or None when it has not yet."""
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


SSH_UNITS = ("ssh.service", "ssh.socket")      # OpenSSH runs when either is active: the socket starts the service


def hardening(run=None):
    """The facts of the join's hardening that any user reads in a moment, with the names that a reading gives
    them: `ssh_keys_only` (sshd_keys_only), None where OpenSSH does not run, because neither its service nor its socket
    is active and it then lets nobody in with a password (a server that Tailscale's own SSH serves), `npm_rule`,
    `memory_guard` (memory_guard), None where the kernel's own file cannot say, and `restart_guard` (restart_guard),
    the same. A
    server's own service reads them for its reading (Lifecycle.security), and the hub reads them of its own server,
    which has no service (hub.hub_hardening_read): one function, so that the two never read them in two ways.

    `ssh_keys_only` is left out when systemctl gives no state for each unit: systemd answers nothing for a second or
    two while it starts itself again (an update of systemd or libc6: "Failed to connect to system scope bus", status 1),
    and _run gives the same for a call that ran out of time. Such a read cannot say, so the hub keeps what was said of
    it (server_watch_sweep), where a null would end a fault that still stands (14 November 2026, measured)."""
    _code, out, _err = (run or _run)(["systemctl", "is-active", *SSH_UNITS])
    states, facts = out.split(), {"npm_rule": npm_rule(NPMRC), "memory_guard": memory_guard(USER_SLICE_MAX),
                                  "restart_guard": restart_guard(PANIC_SECONDS, WATCHDOG_DEVICES)}
    if len(states) == len(SSH_UNITS):
        facts["ssh_keys_only"] = sshd_keys_only(SSHD_CONFIG) if "active" in states else None
    return facts


# The fleet's own services of a Linux user (`fleet.py service <name>` writes each as fleet-<name>.service). The text of
# a unit is here and not in fleet.py, because the hub reads the text of its own unit too: at its start it writes the
# unit again when the file has the text of an earlier release (hub.unit_follows_code), which is how a hub that an
# earlier release installed gets a change of its unit with no step of its owner's. One function for the installer
# and for the hub, so that the two write one text where they read the same folder, program and home.
HUB_UNIT = "fleet-hub.service"


def service_path(home):
    """The PATH of each service that `fleet.py service` writes, for the user whose home folder is `home`."""
    return os.pathsep.join([os.path.join(home, ".local/bin"), "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin",
                            "/bin", "/usr/sbin", "/sbin"])


def hub_start(python):
    """The command of the hub's service: `python3 -m hub`, which finds hub.py in the unit's WorkingDirectory, the
    code's folder, and not `python3 <folder>/hub.py`.

    Python keeps the syntax tree of a file that it runs by its path until that file ends (for a module it frees
    the tree before the module runs), and it compiles the file again at every start. A module it compiles one time
    and keeps in __pycache__. Measured on a server with 1 GB (Ubuntu 24.04, Python 3.12) on 16 November 2026: a hub
    by its path holds 185 MB; as a module 37 to 46 MB when its start read the compiled file, and 58 MB after a
    start that compiled a new hub.py (that start's peak is 201 MB). On such a server about 135 MB are room that the
    checks of a release need beside the hub. The hub's main() takes no argument from the unit, and hub.py reads how
    it was started in one place only: to see that systemd started it by this line (hub.unit_follows_code)."""
    return [python, "-m", "hub"]


def _unit(name, argv, folder, path_env, more):
    """One unit's text: the frame that every fleet-<name>.service has, `folder` as the WorkingDirectory line says
    it, and `more` as the lines of this unit alone."""
    def quote(x):
        return json.dumps(x.replace("%", "%%"))
    return ("[Unit]\nDescription=Founderizer " + name + "\nAfter=network-online.target\nStartLimitIntervalSec=0\n"
            "[Service]\nType=simple\nWorkingDirectory=" + folder + "\n"
            "Environment=" + quote("PATH=" + path_env) + "\nExecStart=" + " ".join(map(quote, argv)) + "\n"
            "Restart=always\nRestartSec=5\nKillMode=process\nTimeoutStopSec=15\n" + more +
            "[Install]\nWantedBy=default.target\n")


def service_unit(name, argv, kit, path_env):
    """The text of the systemd user unit fleet-<name>.service: `argv` in the folder `kit`, started again whenever it
    ends.

    StartLimitIntervalSec=0 turns off systemd's own rate limit, which otherwise gives up after five starts in ten
    seconds and leaves the unit failed. With Restart=always and RestartSec=5 that is about twenty seconds, and a
    customer has no console to bring it back: whatever made the process exit, the fleet is then gone for as long as
    nobody looks. Keeping it trying costs one restart every five seconds and can recover by itself from a cause that
    passes: a disk that was full, a database that was locked, a machine still booting.

    OOMPolicy=continue, for the hub alone: the checks of a release run as processes of the hub's service
    (releases.Update.checks), and by systemd's default (stop) the whole service stops when the system ends one of its
    processes for lack of memory. Measured on a server with 1 GB on 15 and 16 November 2026 (Ubuntu 24.04, systemd
    255):
    with the default, one such end stopped the hub, and it answered again 6 seconds later; with continue, systemd
    wrote the event to the journal and the hub kept its process and answered at every second. The check that ended
    is then a check that failed, and the fleet keeps its revision. When the system ends the hub's own process, the
    unit starts it again as before.

    The folder is written as it is, with a space as a space: systemd reads the whole rest of the line as the path
    and takes \x20 for four characters, so that a unit with it never started (measured on 16 November 2026; until
    then this text wrote \x20). A percent sign is doubled, because systemd reads %h and its like in that line."""
    more = ("OOMPolicy=continue\n" if name == "hub" else "") + \
        ("UMask=0077\n" if name == "channels" else "")      # the bridge's journal holds the text of messages
    return _unit(name, argv, kit.replace("%", "%%"), path_env, more)


def hub_unit(kit, python, home):
    """The text of the hub's own unit, for the code in the folder `kit`: what `fleet.py service hub` writes, and what
    the hub compares its unit with at its start. The folder goes in by its real path, because a process that starts
    in a folder (the module form) reads the folder's real path where a link led to it, and the two texts must be
    the same one."""
    return service_unit("hub", hub_start(python), os.path.realpath(kit), service_path(home))


def hub_units_before(kit, python, home):
    """The texts that earlier releases wrote as the hub's unit, for the code in the folder `kit` as the installer of
    that time named it (links kept). The hub writes its unit again only over one of these (hub.unit_follows_code):
    a unit with another text is somebody's own, and the hub leaves it.

    **A change of the hub's unit adds the text of before to this list**, or no hub that runs gets the change. The
    text of today is never in it (test_schema_guard holds that), so the hub moves a unit one time and not back.
    Each text is written out here, word for word as its release wrote it, and not built from the code of today
    (_unit, service_unit): that code changes, and these texts are files on servers, which do not.

    1. From 18 October 2026 until the release that brought the module form (16 November 2026): the hub by its
       path, and no OOMPolicy line. A folder with a space had \x20 there. (hub.sh of 17 and 18 October 2026 wrote
       two texts before it, without StartLimitIntervalSec. No release carried them, and they are not here.)"""
    def quote(x):
        return json.dumps(x.replace("%", "%%"))
    first = ("[Unit]\nDescription=Founderizer hub\nAfter=network-online.target\nStartLimitIntervalSec=0\n"
             "[Service]\nType=simple\nWorkingDirectory=" + kit.replace("%", "%%").replace(" ", r"\x20") + "\n"
             "Environment=" + quote("PATH=" + os.pathsep.join([
                 os.path.join(home, ".local/bin"), "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin",
                 "/usr/sbin", "/sbin"])) + "\n"
             "ExecStart=" + quote(python) + " " + quote(os.path.join(kit, "hub.py")) + "\n"
             "Restart=always\nRestartSec=5\nKillMode=process\nTimeoutStopSec=15\n"
             "[Install]\nWantedBy=default.target\n")
    return [first]


def unit_of_a_release(text, kit, python, home):
    """True when `text` is the hub's unit as an earlier release wrote it (hub_units_before) for the folder `kit`, by
    any name of that folder. The installer of that time wrote the folder as it named it, and a link can lead to the
    folder: so the name is the one that the text's own WorkingDirectory line gives, and it must lead to `kit`."""
    line = next((one for one in text.split("\n") if one.startswith("WorkingDirectory=")), "")
    named = line.partition("=")[2].replace(r"\x20", " ").replace("%%", "%")
    try:
        return bool(named) and os.path.realpath(named) == os.path.realpath(kit) and \
            text in hub_units_before(named, python, home)
    except ValueError:          # a name that is no path (a character that no path has)
        return False


OWNER_ONLY = re.compile(r"(?:^|/)(?:test_[^/]*|ui_fixture|selftest|verify|pilot|vault|place)\.py$")  # never loaded here
TICK = 15                   # seconds between idle checks
RESTART_GRACE = 120         # seconds this process may live on after it asked for its own restart
CONFIG_BRANCH = "config"    # the configuration ref that the fleet runs: the hub writes it, and new code reaches it
                            # only as a signed release (RULES.md "Where work goes")
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
            # it installs an MCP server's npm or PyPI program itself and starts every program server through
            # `lifecycle.py mcp-start` with its settings, arguments and keys only (the owner's choice of 15 November
            # 2026, ~/dev/founderizer-plans/any-mcp-design.md), and it says whether a package is in place
            "mcp_packages",
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
            # the person access plan, version 5: a narrowed conversation starts locked, on the agent's own account,
            # with the narrowed tools as its allow list (fleet.NARROWED_TOOLS), and a window of another mode ends at once
            "narrowed_threads",
            "check_lines",      # it runs checks that print lines, with the agent's read keys and its error output (P4)
            "chat_tools",       # an owner chat whose tools changed starts again between turns, on its conversation
            "stuck_screens",    # a question that stands on a screen nobody reads ends its session (runtime gaps C1, C2)
            # AUTONOMY.md decision 41: its records keep a workflow open until its own end notice (since decision 50 only
            # the manager runs Workflow); no session of it offers a tool that asks a person on its screen
            "workflow_tasks",
            "stable_skills",    # a session's stable text lists the agent's own skills (skills_text, design v4 D3)
            # build plan 04, S6: it opens the sharing of its agent's screen on a Linux server for the owner's take-over
            # (takeover_open) and stops it at his answer (takeover_close)
            "takeover_screen",
            # its usage report gives each session's tokens by model, its sub-agents' and workflow agents' with them,
            # and each scan reads only what the transcripts gained (plan P8, decision 41)
            "session_models",
            # support plan F1: a task session of an agent whose Shell box is off starts closed (fleet.shell_off): the
            # pinned Claude Code, the built-in tools that the hub names (and, since 20 November 2026, the runtime's
            # task list at a version of PLAN_LIST_VERSIONS), its own MCP servers only, and no key; and
            # F3: an MCP server of auth "mint" gets a token for that one session through the vault (mint_tokens)
            "shell_box",
            "signin_relink",    # its sign-in waits out a hub that is away and sends its link again (send_link)
            # owner-contact plan B3: the manager's helper says when its start of the standing session failed twice in a
            # row, and starts a session that left its line untaken fresh once (hub.MANAGER_START_FAILS)
            "manager_start_fails",
            "default_models",   # its new sessions take the owner's default model and effort (fleet.run_settings)
            # The AI providers build, step 1. acp_tasks: a start of driver acp takes `opening` and `rules`, its
            # sessions' tokens are in the usage report (usage.acp_sessions), and an ACP program's model list is read
            # (Lifecycle.acp_model_options). The build's spec names this feature acp_v2, which no hub can take: a
            # feature's name is of the letters a to z and _ (hub.validate_status), and a report with another name
            # is refused whole. model_accounts: an agent whose account has a kind starts on that account's key or
            # model server, and its setup check has the `account` item (Lifecycle.account_item).
            "acp_tasks", "model_accounts",
            # the host list: a closed task session takes its agent's host list from the hub's start, and its page
            # reads open only on those hosts (fleet.closed_task_command)
            "web_hosts",
            # a removed person's windows close, and the runtime's own files of their sessions go (the event `forget`
            # of the hub's person_remove: forget_valid, fleet.Helper.forget)
            "forget_sessions",
            # a task in the screen runner takes the parts of the rules that the hub names for it (hub.stable_extra,
            # FLEET_RULES of screen_runner.py): its thread has them after RULES.md as its developer instructions
            "runner_rules"]
# ---------------------------------------------------------------- the host list
#
# The host list of an agent whose Shell box is off and whose Web box is on (team.json "web_hosts"): the hosts on which
# the page reads of its sessions open. An address that a session fetches can carry data to the site that it names, so
# the list is a control and not a convenience. One form of an entry for the hub, which checks the owner's write, and
# for the helper, which checks what the hub's start names: a host name in lower case, or "*." and a host name for that
# host and every host below it. A name has two labels or more and at most 80 characters, and its last label begins
# with a letter: so no entry is "*", "*.com", a name with a port or a path, or an address in numbers, which a
# browser's reading also takes in forms such as 127.0x1.
WEB_HOST = re.compile(r"(?:\*\.)?(?=[a-z0-9.-]{4,80}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                      r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")
WEB_HOSTS_MOST = 20     # with 80 characters each, the start of a session stays far below what tmux takes (16 KiB)
WEB_HOSTS_FORM = (f"a list of 1 to {WEB_HOSTS_MOST} different hosts, each a host name in lower case such as "
                  f"docs.example.com, or *.example.com for example.com and every host below it")
# The versions of Claude Code at which a closed session with a host list passed its live test (test_web_hosts.Live,
# with FLEET_LIVE_LOCKDOWN=1), first the one that a session takes where the version of closed sessions is not one of
# these: on the owner's Mac, 12 November 2026, a page on a listed host opened, and a page on another host, a redirect
# to another host and Claude Code's own list of documentation hosts did not. A session with a host list runs at the
# version of closed sessions when it is one of these, else at the first of these (hub.closed_extra), and a helper
# starts none at another (closed_task_command). A version joins only in a release whose live test passed at it.
# 2.1.308 was not on that Mac, so it is not here.
HOST_LIST_VERSIONS = ("2.1.312", "2.1.311")
# The versions of Claude Code at which a closed task session with the runtime's task list passed its live test
# (test_conversation_lockdown.ClosedTask, with FLEET_LIVE_LOCKDOWN=1; fleet.CLOSED_PLAN_TOOLS): on the owner's Mac,
# 20 November 2026, the model was offered the four task tools beside the tools of the session's list and nothing
# else (but the program's own fleet.CLAUDE_BUILT_INS), the four worked, and a shell, a file tool and a sub-agent
# did not exist. A helper names the task
# tools in a closed start only at one of these versions (fleet.closed_task_command); at another version the session
# starts as before, with no plan list. A version joins only in a release whose live test passed at it. 2.1.308 was
# not on that Mac, so it is not here.
PLAN_LIST_VERSIONS = ("2.1.311", "2.1.312")


def web_hosts(value):
    """value as a host list, in its own order, or ValueError with the form (WEB_HOSTS_FORM)."""
    if not isinstance(value, list) or not 1 <= len(value) <= WEB_HOSTS_MOST or \
            not all(isinstance(h, str) and WEB_HOST.fullmatch(h) for h in value) or len(set(value)) != len(value):
        raise ValueError(WEB_HOSTS_FORM)
    return list(value)


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
#   tool_pictures     a picture in an MCP tool's answer reaches its model, and the runtime keeps what the model takes
#                     for many pictures in one request, as its source says: read_attachment gives such an agent the
#                     owner's picture as the answer's image (hub.ATTACH_PICTURES). False where no source says so, and
#                     such an agent gets the download line
#   plan_lines        the task's own line for its plan (hub.plan_line): {"open": the line of an open session,
#                     "closed": a closed session's, or None}, or None for a runtime with no task list
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
#                     profile are its appended system prompt; "prompt", at the end of its first prompt, after its
#                     parts of the rules and its profile, because it has RULES.md as its developer instructions
#                     (fleet.codex_rules); None where Fleet starts none so
#   starts_idle       its task session starts with no prompt and runs nothing until its helper types a first line
#                     into its window (fleet.session_command), so the hub counts no turn of one that no line
#                     reached yet (hub.first_line_waits); False where its first prompt begins its first turn, and
#                     for an ACP program, whose runner holds its first prompt in its own way (acp_runner.py)
#   token_weights     its list prices in dollars per million tokens, {model key: {input, cache_read, cache_write,
#                     output}}, so that the cost of a session compares across providers (AUTONOMY.md P8, P10); on a
#                     subscription account they are weights, not money spent. A session's model takes the entry
#                     whose key is the longest part of its name, else "default". The owner's own prices are in
#                     team.json runtime_facts (facts_now); None for no prices
#
# The facts of a runtime of driver "acp", and of how its program comes to a machine (the AI providers build spec,
# section 3.4). For a terminal runtime each is None, `pinned` is False, and `continues` is its `manager` value.
#
#   acp_auth          the ACP sign-in method that a start names, by the kind of the agent's account, {"plan": a method
#                     id, "key": a method id}; None for a program whose sign-in method does nothing
#   acp_quiet         the variables of each start that keep the program from its own update and from the instruction
#                     files, skills, MCP servers and hooks of other programs on the machine; a variable that holds a
#                     path of one session is the session's own, and comes from its adapter
#   acp_models        where its model list is read with no prompt: "initialize", in the answer of that call, or
#                     "session", in the options of a new session; None for a program that gives none
#   acp_allowance     the name on the wire of its method that reads a plan's allowance; None where it has none
#   key_env           the variable by which the program takes the API key of a key account
#   own_env           the prefixes of the variables that the program reads as its own settings: its session gets none
#                     of that name but the ones that the fleet's own start sets
#   pinned            the fleet downloads the program itself, at the version and the digest of onboard.PINNED
#                     (fleet.install_pinned), and a session runs that file and never one of a PATH
#   continues         a new process of it continues a conversation of an earlier one
#   acp_adapter       the name of its adapter in acp_programs.py, which holds what the program does in its own way:
#                     the session's folder and files, the road of the system text, the sign that its tools are there,
#                     the tokens of a turn, its limit and its failures, and a tool call's own name. No other file
#                     compares a runtime to a name for it (test_runtime_table)
#
# What is NOT here, because it is code and not a fact: how a runtime's records become a transcript (threads.py), how
# its allowance is read (usage.py), what its own installer is (onboard.py), and how its sign-in window is driven to
# the end (fleet.do_signin). A fourth provider needs real work in each of those.
RUNTIMES = {
    "codex": {
        "label": "Codex",
        # The key swap (VAULT.md): the hosts of this program's own provider, which a session's NO_PROXY names, so that
        # its model calls and its sign-in never go through the vault's proxy. None: nobody proved this program with
        # the proxy's variables, so a session of it gets each key as a variable, as before.
        "own_hosts": ("openai.com", "chatgpt.com"),
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
        "tool_pictures": True,          # Codex shows a tool's picture to its model (openai/codex 5600)
        # OpenAI keeps a prompt's cache for some minutes of inactivity, and Codex keys it by its own thread
        # (prompt_cache_key), so a new Codex session reads little of another's
        "cache_seconds": 300,
        "compact_tokens": 200000,
        "routine": {"model": None, "effort": "low"},
        "default_model": None,          # the owner's default model and effort for this runtime (Settings › General)
        "task_denied": None,            # Codex has none of the tools that the owner took away
        "task_allowed": None,
        # Its ask tools go with a start option in every session instead (fleet.CODEX_UNATTENDED, decision 41)
        "conversation_denied": None,
        "manager_denied": None,
        "task_opening": "prompt",
        "starts_idle": False,
        # gpt-6.1-sol's list prices as public price pages gave them on 27 October 2026, NOT checked on OpenAI's own
        # pricing page: the owner sets the right ones with runtime_facts. OpenAI charges no more for a cache write
        # than for input.
        "token_weights": {"default": {"input": 2.0, "cache_read": 0.1, "cache_write": 2.0, "output": 10.0}},
        # Codex 0.163 has a memories feature that writes what it learns from a thread to $CODEX_HOME/memories and gives
        # it to later threads. Off by default, but one config line turns it on (the owner's own Mac has it on), and an
        # agent's Codex reads that user's config: so every Fleet session passes it off (fleet.CODEX_NO_MEMORY).
        "memory_off": {"config": {"features.memories": False}},
        # the task's own line for its plan (hub.plan_line): its update_plan; a closed session has none
        "plan_lines": {"open": " Keep the plan of a task of more than two steps with update_plan.", "closed": None},
        "acp_auth": None, "acp_quiet": None, "acp_models": None, "acp_allowance": None, "key_env": None,
        "own_env": None, "pinned": False, "continues": True, "acp_adapter": None,
    },
    "claude": {
        "label": "Claude Code",
        "own_hosts": ("anthropic.com", "claude.ai", "claude.com"),     # as Codex's
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
        # fleet.CLAUDE_BUILT_INS, and only the hub's prompt. 2.1.311 first, the default of every fleet since 20 November
        # 2026 (the owner's "Yes, start"): the host list's and the plan list's live tests passed at it
        # (HOST_LIST_VERSIONS, PLAN_LIST_VERSIONS). A user of a Claude Code agent at 2.1.311 holds its program already
        # (fleet.closed_program links it); another user downloads it at its first closed start, which waits. 2.1.308,
        # the default before, had neither list, and it stays for a fleet whose owner chose it.
        "closed_versions": ("2.1.311", "2.1.308", "2.1.312"),
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
        # Claude Code scales the copy of a tool's picture that it shows (its MCP documentation, since 2.1.283)
        "tool_pictures": True,
        "cache_seconds": 3600,          # an hour; its own records say when it is five minutes (fleet.claude_context)
        "compact_tokens": 200000,       # fleet.STANDING_COMPACT, the window that Fleet starts its sessions with
        "routine": {"model": "sonnet", "effort": "low"},
        "default_model": None,
        # The owner, 27 October 2026: "Yes, remove Artifact, Workflow, AskUserQuestion, ReportFindings, Skill and
        # ListAgents from agent task sessions." On Claude Code 2.1.301, 2.1.304, 2.1.308, 2.1.311 and 2.1.312
        # (recorded against stand-ins), Claude Code then offers ArtifactComments and ArtifactData no more either, as
        # it offers them only together with Artifact. AUTONOMY.md decision 41, the owner on 28 October 2026: "when
        # AskUserQuestion from an agent, it should be its boss who gets the question! ... same for Workflows etc, I
        # think they are great". EnterPlanMode and ExitPlanMode go with AskUserQuestion: an approval card that nobody
        # reads is a question too. A question goes up with ask_my_requester. Workflow came back with decision 41, and
        # leaves again with decision 50 (the owner, 19 November 2026: "Remove it"): 22,358 of the 102,372 characters of
        # a task session's first request on 2.1.311, and one call by all agents in 1,713 sessions in three weeks.
        # Sub-agents (the Agent tool) stay.
        "task_denied": ["Artifact", "AskUserQuestion", "EnterPlanMode", "ExitPlanMode", "ReportFindings", "Skill",
                        "ListAgents", "Workflow"],
        "task_allowed": None,
        # a conversation with a person is no task work: it splits none of it
        "conversation_denied": ["Artifact", "AskUserQuestion", "EnterPlanMode", "ExitPlanMode", "ReportFindings",
                                "Skill", "ListAgents", "Workflow"],
        # the manager keeps Workflow, Skill and Artifact (his answer of 29 October 2026: Artifact stays with it)
        "manager_denied": ["AskUserQuestion", "EnterPlanMode", "ExitPlanMode"],
        "task_opening": "read",
        "starts_idle": True,            # its task text is its appended system prompt (fleet.session_command)
        # Anthropic's list prices of 6 October 2026. Its sessions write one-hour caches, which cost twice the input.
        "token_weights": {"default": {"input": 4.0, "cache_read": 0.2, "cache_write": 8.0, "output": 20.0},
                          "fable": {"input": 10.0, "cache_read": 0.25, "cache_write": 20.0, "output": 50.0},
                          "opus": {"input": 4.0, "cache_read": 0.2, "cache_write": 8.0, "output": 20.0},
                          "sonnet": {"input": 2.0, "cache_read": 0.2, "cache_write": 4.0, "output": 10.0},
                          "haiku": {"input": 0.1, "cache_read": 0.01, "cache_write": 0.2, "output": 0.5}},
        # Claude Code's auto memory, in every session's settings (fleet.CLAUDE_NO_MEMORY).
        "memory_off": {"settings": {"autoMemoryEnabled": False}},
        # the task's own line for its plan (hub.plan_line): its deferred task tools. A closed session has the list
        # only at a version of PLAN_LIST_VERSIONS, named in its --tools with no ToolSearch, so its line says "if"
        "plan_lines": {"open": " Keep the plan of a task of more than two steps in your task list: load TaskCreate "
                               "and TaskUpdate with ToolSearch \"select:TaskCreate,TaskUpdate\".",
                       "closed": " If TaskCreate is among your tools, keep the plan of a task of more than two steps "
                                 "there."},
        "acp_auth": None, "acp_quiet": None, "acp_models": None, "acp_allowance": None, "key_env": None,
        "own_env": None, "pinned": False, "continues": True, "acp_adapter": None,
    },
    # Grok Build, for SpaceXAI, through ACP. Each fact of it and of OpenCode below was read from the program at its
    # pin, against a stand-in model with no account (step 0 of the AI providers build spec, 12 November 2026).
    "grok": {
        "label": "Grok",
        "own_hosts": None,              # not proved: its sessions run through the ACP runner
        "driver": "acp",
        "acp_command": "grok agent stdio",
        "can": {"shell", "web"},
        "full_access": {"start": "grok agent stdio"},       # Fleet's one worker form: the runner answers each prompt
        "manager_access": None,
        "first_worker": "grok agent stdio",
        "manager": False,
        "owner_chat": False,
        "agent_messages": False,
        "conversation": False,
        "conversation_why": None,
        "closed_versions": (),
        "mcp_servers": True,            # both kinds of server of a new session start in it
        "app_server": False,
        "switch": False,                # a third switchable name would end the Claude and Codex switch of each agent
        "session_settings": False,
        "token_in_env": True,
        "model_flags": None,            # a model and an effort are options of the session, which the runner sets
        "local_model": None,
        "sign_in": None,
        "sign_out": None,
        "no_sign_in": ("Fleet drives no Grok sign-in: xAI's terms do not let a third party run it this way. "
                       "Sign in to Grok yourself on {where} machine."),
        "sandbox": None,
        "screen_counter": False,
        "browser_tabs": False,
        "tool_pictures": False,
        "cache_seconds": None,
        "compact_tokens": None,
        "routine": None,
        "default_model": None,
        "task_denied": None,
        "task_allowed": None,
        "conversation_denied": None,
        "manager_denied": None,
        "task_opening": "system",       # its stable text is the session's system text, and its task the first prompt
        "starts_idle": False,
        "token_weights": None,
        # Grok Build's memory and its automatic dreaming: off by default, and on with GROK_MEMORY=1, its config or a
        # managed remote setting. GROK_MEMORY=0 turns it off for the whole process, whatever the others say.
        "memory_off": {"env": {"GROK_MEMORY": "0"}},
        "plan_lines": None,     # no task list that a task session is told of
        # It names "xai.api_key" in its initialize answer only while it has a key, and "cached_token" only while a
        # sign-in is stored.
        "acp_auth": {"plan": "cached_token", "key": "xai.api_key"},
        # Its updater, and the rules, named files, skills, MCP servers and hooks of Claude Code and of Cursor. Two
        # sources stay open: ~/.claude/agents/ and ~/.agents/skills/.
        "acp_quiet": {"GROK_DISABLE_AUTOUPDATER": "1",
                      **{f"GROK_{other}_{kind}_ENABLED": "0" for other in ("CLAUDE", "CURSOR")
                         for kind in ("SKILLS", "RULES", "AGENTS", "MCPS", "HOOKS")}},
        "acp_models": "initialize",     # _meta.modelState of the answer, each model with its efforts
        "acp_allowance": "_x.ai/billing",
        "key_env": "XAI_API_KEY",
        "own_env": ("GROK_", "XAI_"),
        "pinned": True,
        "continues": False,             # its sessions are in the session's own folder, which goes with the window
        "acp_adapter": "grok",
    },
    # OpenCode, for each other API key and for the owner's own model server, through ACP.
    "opencode": {
        "label": "OpenCode",
        "own_hosts": None,              # as Grok's: its own program is proved in a terminal only
        "driver": "acp",
        "acp_command": "opencode acp",
        "can": {"shell", "web"},
        "full_access": {"start": "opencode acp"},
        "manager_access": None,
        "first_worker": "opencode acp",
        "manager": False,
        "owner_chat": False,
        "agent_messages": False,
        "conversation": False,
        "conversation_why": None,
        "closed_versions": (),
        "mcp_servers": True,
        "app_server": False,
        "switch": False,
        "session_settings": False,
        "token_in_env": True,
        "model_flags": None,
        "local_model": None,
        "sign_in": None,
        "sign_out": None,
        "no_sign_in": "OpenCode needs no sign-in on {where} machine.",
        "sandbox": None,
        "screen_counter": False,
        "browser_tabs": False,
        "tool_pictures": False,
        "cache_seconds": None,
        "compact_tokens": None,
        "routine": None,
        "default_model": None,
        "task_denied": None,
        "task_allowed": None,
        "conversation_denied": None,
        "manager_denied": None,
        "task_opening": "system",
        "starts_idle": False,
        "token_weights": None,
        "memory_off": {"env": {}},      # the program has no memory of its own to switch off
        "plan_lines": None,     # no task list that a task session is told of
        "acp_auth": None,               # its one method, opencode-login, does nothing: the key is in its configuration
        # The working folder's configuration and its .opencode folder, each AGENTS.md from the working folder to the
        # home folder, Claude Code's skills, its own update, and the address of its model catalog. ~/.agents/skills/
        # stays open, and so does an AGENTS.md below the working folder when the agent reads a file there.
        "acp_quiet": {"OPENCODE_DISABLE_PROJECT_CONFIG": "1", "OPENCODE_DISABLE_CLAUDE_CODE": "1",
                      "OPENCODE_DISABLE_AUTOUPDATE": "1", "OPENCODE_DISABLE_MODELS_FETCH": "1"},
        "acp_models": "session",        # the option `model` of a new session, and the efforts of the current model
        "acp_allowance": None,
        "key_env": "FLEET_MODEL_KEY",   # the session's configuration names this variable as the provider's key
        "own_env": ("OPENCODE_",),
        "pinned": True,
        "continues": False,
        "acp_adapter": "opencode",
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
                 "compact_tokens", "routine", "default_model", "task_denied", "task_allowed", "conversation_denied",
                 "manager_denied", "task_opening", "starts_idle", "token_weights", "memory_off",
                 "acp_auth", "acp_quiet", "acp_models", "acp_allowance", "key_env", "own_env", "pinned", "continues",
                 "acp_adapter", "own_hosts", "tool_pictures", "plan_lines")


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
    follows a character that is not a letter, and small letters for the rest ("web-dev" is "Web-Dev", "mini-2b"
    "Mini-2B"). Python's capitalize() gave "Web-dev", so one agent read two ways on one screen (review A9, 29 October
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
                  "routine": routine_check,             # plan P9.7: what an agent's one changer reaches for first
                  # The owner, 9 November 2026: "a default for each [AI provider] somewhere under settings, and then each
                  # agent can be changed individually". What an agent of this runtime runs when it has no model or no
                  # effort of its own, where its machine's model list offers it (fleet.run_settings).
                  "default_model": routine_check}


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
    name, case aside, else "default"; None for a runtime with no prices. A key that ends in "/" matches only the start
    of a model's name, and such a key wins over each other key: it names where a model runs, as "own/" names the
    owner's own model server, whose models cost nothing whatever their names hold (own/deepseek-r1 is no model of a
    key "deepseek"). own/ costs nothing on every runtime, also on one with no prices (the lane "Tokens by day and
    model")."""
    name = str(model or "").lower()
    if name.startswith("own/"):         # the owner's own server or machine: a runtime whose prices have no own/, or
        return dict.fromkeys(TOKEN_KINDS, 0)    # that has no prices, prices it too
    if not weights:
        return None
    placed = [k for k in weights if k.endswith("/") and name.startswith(k.lower())]
    if placed:
        return weights[max(placed, key=len)]
    named = [k for k in weights if k != "default" and not k.endswith("/") and k.lower() in name]
    return weights[max(named, key=len)] if named else weights.get("default")


# The list prices of the models that an ACP program runs, in one file of this checkout (prices.py makes it from a
# public list; a person runs that when a pin moves). It is loaded here, relative to this file, as the token_weights of
# each runtime of driver acp. A file that is missing or wrong gives None and never an error: `lifecycle.py may-take`
# runs at each move of a checkout, and an import that fails there stops each update.
PRICE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prices", "models.json")


def price_file(path=PRICE_FILE):
    """The prices of the file as token_weights, or None for a file that is missing, too long or not of that shape."""
    try:
        with open(path, "rb") as f:
            raw = f.read(256 * 1024 + 1)
        return weights_check(json.loads(raw)) if len(raw) <= 256 * 1024 else None
    except (OSError, ValueError, TypeError, RecursionError, AttributeError):
        return None


for _entry in RUNTIMES.values():
    if _entry["driver"] == "acp":
        _entry["token_weights"] = price_file()
del _entry


def runtimes_with(fact):
    """The runtimes whose entry says yes to one fact, in the table's own order."""
    return tuple(name for name, entry in RUNTIMES.items() if entry.get(fact))


def no_sign_in(runtime, where="this"):
    """Why the fleet drives no sign-in for this runtime, in the words the owner reads, or None when it drives one.
    `where` is the machine as its reader sees it: "this" on the machine itself, "that" from the hub or the app."""
    said = runtime_fact(runtime, "no_sign_in")
    return said.format(where=where) if said else None


SWITCH_RUNTIMES = runtimes_with("switch")   # the runtimes an owner can switch between (owner feature runtime_switch)
# An agent's own browser on a Linux server and its screen-sharing server, each a unit of its own OS user's systemd
# (build plan 04, D5, D7 and D11): the helper starts and stops them, and the server service stops them where the port
# rule is gone. Their names have a "_", which no agent's name has: never the unit of an agent's helper,
# fleet-<agent>.service (an agent can be named "browser").
BROWSER_UNITS = ("fleet_browser.service", "fleet_vnc.service")
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
# token without the App's workflows permission may not push at all, and the start of its GitHub Actions runs. read and
# write read the runs where the App's installation holds Actions (hub.github_permissions, door.token_permissions).
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
# A program server is a program of the machine (command) or a package that Fleet installs from npm or PyPI (package).
# Both take plain settings; only a package takes arguments. DevOps plan 0.2 had taken arguments away, because a line
# that team.json writes is code. On 15 November 2026 the owner chose that a write of the owner API is enough to make
# an agent's server install and run a program ("The hub", ~/dev/founderizer-plans/any-mcp-design.md), and so a
# package takes arguments again. A command keeps no arguments, and no runner, shell or interpreter is a command
# (MCP_RUNNERS): `npx -y x@latest`, `uvx x` or `bash -c ...` would fetch and run a program around the pinned install
# and its rule that nothing is newer than PACKAGE_DAYS. What stays for every value: it cannot pull a variable of the
# session in (no "$": Claude Code expands ${NAME} in its MCP file), no setting changes how a runtime starts or where
# its traffic goes (SETTING_REFUSED), a setting with a secret's name or a URL with a password is no plain setting
# (secret_name, plain_value), and a program gets only its own settings and keys (mcp_start).
MCP_FIELDS = {"title", "url", "command", "package", "args", "settings", "env", "auth", "key", "runtimes", "mint",
              "mint_field"}
MCP_REGISTRIES = ("npm", "pypi")
# The programs that fetch, wrap or interpret another program: never a command server (the app holds the same list)
MCP_RUNNERS = ("npx", "npm", "pnpm", "pnpx", "yarn", "yarnpkg", "corepack", "bun", "bunx", "deno", "node", "nodejs",
               "uv", "uvx", "pip", "pip3", "pipx", "poetry", "conda", "mamba", "micromamba", "pixi", "nix", "go",
               "cargo", "docker", "podman", "nerdctl", "env", "sudo", "doas", "sh", "bash", "zsh", "dash", "fish",
               "ksh", "csh", "tcsh", "python", "python3", "ruby", "perl", "php", "java", "osascript", "xargs")
MCP_RUNNER = re.compile(r"(?:python|pypy)[0-9.]*|node[0-9.]*|ruby[0-9.]*|perl[0-9.]*|php[0-9.]*")
# The parts of a name that say it holds a secret, besides a key's ending (KEY_SUFFIXES): such a setting goes in env,
# from an API key of the Secrets page (the app holds the same list)
SECRET_WORDS = ("KEY", "APIKEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PASS", "PWD", "PAT", "CREDENTIAL",
                "CREDENTIALS", "COOKIE", "AUTH", "AUTHORIZATION", "DSN", "PRIVATE", "BEARER")
# A flag of an argument (--access-token, --api-key, -p): a flag whose words (between - and _) hold one of SECRET_WORDS
# names a secret, and its value after "=" or as the next argument goes in env (secret_flag)
FLAG = re.compile(r"--?[A-Za-z0-9][A-Za-z0-9_-]*")
NPM_PACKAGE = re.compile(r"(?:@[a-z0-9][a-z0-9._~-]{0,99}/)?[a-z0-9][a-z0-9._~-]{0,99}")
PYPI_PACKAGE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?")
PACKAGE_VERSION = re.compile(r"[0-9][0-9A-Za-z.+!_-]{0,63}")    # one exact version (npm's semver, PEP 440)
PACKAGE_DAY = re.compile(r"20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])")     # as_of, a day in UTC
PACKAGE_DAYS = NPM_DAYS         # the youngest version and dependency that Fleet installs, in days (the owner's rule)
MCP_ARGS_MOST, MCP_ARG_MOST = 16, 300           # arguments of a package server, and characters of each
MCP_KEYS_MOST = 8                               # keys of a program server (its env)
CREDENTIAL_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://(?:[^/@\s]+|[^@\s]*:[^@\s]*)@")   # a user part, or a password
MCP_SETTINGS_MOST, MCP_SETTING_MOST = 16, 500   # plain settings of a program server, and characters of each value
SETTING_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,59}")
# The names that change how a program's runtime starts, what it loads, or where its traffic goes: the session's own
# (ENV_RESERVED), the loaders, the interpreters' and package tools' options, proxies and trust stores. A setting of
# these names is refused, whatever the server says it reads, and so is a program's variable that takes a key, unless
# it has a key's ending (key_variable).
SETTING_REFUSED = re.compile(
    r"(?:FLEET|BWS|LD|DYLD|ANTHROPIC|CLAUDE|CODEX|XAI|NODE|NPM_CONFIG|UV|PIP|PIPX|POETRY|CONDA|VIRTUAL_ENV|GIT|"
    r"OPENSSL|CURL|REQUESTS|HTTPLIB2|GCONV|MALLOC|GLIBC|JAVA|JDK|_JAVA|GEM|BUNDLE|DENO|BUN|ELECTRON|GRPC|"
    r"XDG)(?:_[A-Z0-9_]*)?|PYTHON[A-Z0-9_]*|PERL[A-Z0-9_]*|RUBY[A-Z0-9_]*|SSL[A-Z0-9_]*|"
    r"[A-Z0-9_]*_PROXY|[A-Z0-9_]*_CA_BUNDLE|"
    r"PATH|HOME|SHELL|USER|LOGNAME|TMPDIR|TEMP|TMP|TERM|TERMINFO|TERMCAP|PWD|OLDPWD|IFS|ENV|BASH_ENV|ZDOTDIR|CDPATH|"
    r"GLOBIGNORE|SHELLOPTS|BASHOPTS|PROMPT_COMMAND|PS[1-4]|HISTFILE|INPUTRC|LANG|LANGUAGE|LC_[A-Z_]*|TZ|TZDIR|"
    r"LOCPATH|NLSPATH|HOSTALIASES|RES_OPTIONS|LOCALDOMAIN|CLASSPATH|BROWSER|EDITOR|VISUAL|PAGER|LESSOPEN|LESSCLOSE|"
    r"MANPAGER", re.IGNORECASE)
# The keys that Fleet itself puts in a task session (fleet.integration_env): GH_TOKEN, the hub's GitHub App token for
# gh, and the variables of Fleet's own tools (TOOL_CATALOG: the GitHub tool's GITHUB_PERSONAL_ACCESS_TOKEN, which holds
# that token too). No owner's program server takes its key from one: the session's own value wins over an API key of
# the same name, so the program would get the fleet's token (the reviews of 15 and 16 November 2026).
FLEET_KEYS = ("GH_TOKEN",) + tuple(sorted({own for tool in TOOL_CATALOG.values() for own in tool.get("env") or {}}))
# What mcp_start passes on from its own environment besides a server's own variables, and the most of those.
MCP_START_KEEPS = ("HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ")
MCP_START_MOST = 40
MINT_PATH = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,199}")      # the mint's path at the key's site, no query
MINT_FIELD = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,39}")                  # the field of its body that names the case


VAULT_CHROME = ("ok", "launching", "not_running", "no_window", "not_asked", "refused", "javascript_off", "error")


def vault_chrome(home, timeout=20):
    """What stops a sign-in of this Mac's Fleet Vault in Chrome now, one word of VAULT_CHROME, or None with no vault
    here, with one that is busy or older than its answer (`chrome` with `quiet`, ~/dev/founderizer-plans/
    vault-signin-causes-spec.md, section D). It shows no question of macOS. Only the vault can read it: macOS's
    permission is the vault's own, and macOS 27 hides Chrome's files from this service (chrome_hidden), so its menu item
    Allow JavaScript from Apple Events can be read only through the vault's one harmless script."""
    path = os.path.join(home, "Library", "Application Support", "AgentFleet", "vault.sock")
    if not os.path.exists(path):
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(path)
            s.sendall(b'{"v": 2, "op": "chrome", "quiet": true}\n')
            cause = json.loads(s.makefile().readline(4096)).get("cause")
    except (OSError, ValueError, AttributeError):
        return None
    return cause if cause in VAULT_CHROME else None


CODEX_KEPT = "codex-releases.json"      # in ~/.fleet: each Codex release that was old enough when read (codex_releases)
CODEX_TAG_PAGES = 5     # pages of 100 tags at most: the first held 11 stable tags of about 10 days (20 November 2026)


def github_json(url, timeout=30):
    """One answer of GitHub's public API, at most 2 MiB."""
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                                   "User-Agent": "founderizer-helper"})
    with urllib.request.urlopen(request, timeout=timeout) as answer:
        return json.loads(answer.read(2 * 1024 * 1024))


def codex_releases(home, now, get=github_json):
    """The vendor's own record of Codex's newest stable releases, newest first, as its API gives each one, down to the
    first that is onboard.RELEASE_AGE_DAYS old, which is the newest that its update may take (onboard.codex_release):
    the list of its tags, a page after another (GitHub gives them newest first, at most CODEX_TAG_PAGES), and the
    release of each stable tag. Each release read is kept in ~/.fleet (CODEX_KEPT). One that was that old when it was
    read is kept for good: its time and its marks do not change any more. A younger one is kept with the mark `young`
    and read once more when its own time is that old, and that read decides: so a release that the vendor marks a
    pre-release, pulls or publishes again in its first days is read so, and a round reads only the tags and what is
    new. A tag whose release has not come yet is read again at each round. What a read kept is written also when it
    stops half-way. Raises when GitHub does not answer as its API does."""
    path = os.path.join(home, FLEET_DIR, CODEX_KEPT)
    old = onboard.RELEASE_AGE_DAYS * 86400
    try:
        with open(path, encoding="utf-8") as f:
            kept = json.load(f)
    except (OSError, ValueError):
        kept = {}
    kept = {v: r for v, r in kept.items() if isinstance(v, str) and isinstance(r, dict)} if isinstance(kept, dict) else {}
    releases = []
    try:
        for page in range(1, CODEX_TAG_PAGES + 1):
            tags = get(f"{onboard.CODEX_TAGS}&page={page}")
            if not isinstance(tags, list):
                raise ValueError(f"GitHub gave no list of Codex's tags but {type(tags).__name__}")
            found = [onboard.CODEX_TAG.fullmatch(str(t.get("name"))) for t in tags if isinstance(t, dict)]
            for version in sorted({tag.group(1) for tag in found if tag}, key=lambda v: tuple(map(int, v.split("."))),
                                  reverse=True):
                record = kept.get(version)
                age = None if record is None else onboard.published_age(record, now)
                if record is None or record.get("young") and (age is None or age >= old):
                    try:
                        answer = get(onboard.CODEX_RELEASE.format(version))
                    except urllib.error.HTTPError as e:
                        if e.code != 404:
                            raise
                        kept.pop(version, None)     # a tag whose release has not come, or went: read again
                        continue
                    if not isinstance(answer, dict):
                        raise ValueError(f"GitHub gave no release of Codex {version} but {type(answer).__name__}")
                    record = {k: answer.get(k) for k in ("published_at", "prerelease", "draft")}
                    age = onboard.published_age(record, now)
                    kept[version] = record if age is not None and age >= old else dict(record, young=True)
                releases.append(dict(record, tag_name=f"rust-v{version}"))
                if onboard.codex_release(releases, now):
                    return releases
            if len(tags) < 100:
                break                                   # the last page
        return releases
    finally:
        with contextlib.suppress(OSError):
            write_json(path, kept)


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


def setting_name(name):
    """True for the name of a program server's own variable (a plain setting; the variable that takes a key may also
    be a key's name, key_variable): A-Z a-z 0-9 _, at most 60 characters, and none that changes how a runtime starts
    (SETTING_REFUSED)."""
    return isinstance(name, str) and bool(SETTING_NAME.fullmatch(name)) and not SETTING_REFUSED.fullmatch(name)


def key_variable(name):
    """True for a program server's own variable that takes a key (env): a setting name (setting_name), or a key's name
    (key_env), which every server of team.json had before 15 November 2026, so that an upgrade keeps each server that
    the hub took then (NODE_AUTH_TOKEN, UV_PUBLISH_TOKEN). A key's ending (_KEY, _TOKEN, _SECRET, _PASSWORD, _PAT) is the
    ending of no variable that changes how a runtime starts or what it loads."""
    return setting_name(name) or key_env(name)


def plain_value(value, most):
    """True for a plain value of a program server (a setting or an argument): a string of at most `most` characters
    with no control character, no $ (so that no MCP file expands it into another variable of the session), no
    character above U+FFFF (Codex's -c values are TOML, which takes no surrogate pair), and no URL with a password."""
    if not (isinstance(value, str) and len(value) <= most and "$" not in value and value.isprintable() and
            all(ord(c) <= 0xFFFF for c in value)):
        return False
    return not CREDENTIAL_URL.search(value)


def secret_name(name):
    """True for a variable whose name says that it holds a secret: a key's ending (KEY_SUFFIXES) or one of
    SECRET_WORDS among the words of its name, split as a flag's (flag_words: DB_PASS, X_AUTH, SENTRY_DSN, API_KEY_ID,
    apiToken, clientSecret)."""
    return str(name).upper().endswith(KEY_SUFFIXES) or any(word in SECRET_WORDS for word in flag_words(str(name)))


def flag_words(flag):
    """The words of a flag's name, in capitals: split at - and _ and where a lower case letter or a digit meets a
    capital (--access-token, --api_key and --accessToken all give ACCESS and TOKEN or API and KEY)."""
    return [w.upper() for w in re.split(r"[-_]+|(?<=[a-z0-9])(?=[A-Z])", flag) if w]


def secret_flag(flag):
    """True for a flag of an argument that names a secret: one of SECRET_WORDS among the words of its name."""
    return bool(FLAG.fullmatch(flag)) and any(word in SECRET_WORDS for word in flag_words(flag))


def mcp_runner(command):
    """True for a program that fetches, wraps or interprets another one (MCP_RUNNERS): never a command server."""
    return str(command).lower() in MCP_RUNNERS or bool(MCP_RUNNER.fullmatch(str(command).lower()))


def mcp_package(name, package):
    """The package of a program server that Fleet installs, checked: {registry, name, version, as_of, bin}. registry is
    npm or pypi; version is one exact version; as_of is the day (UTC) whose state of the registry every dependency is
    taken from, at least PACKAGE_DAYS before the owner's write (the hub checks that day at the write, and the helper
    again before an install); bin is the program of the package to run, or None for the package's own (npx and uvx
    choose it the same way). ValueError with the reason."""
    if not isinstance(package, dict) or set(package) - {"registry", "name", "version", "as_of", "bin"}:
        raise ValueError(f"the MCP server {name}: package takes registry, name, version, as_of and bin")
    registry, called = package.get("registry"), package.get("name")
    if registry not in MCP_REGISTRIES:
        raise ValueError(f"the MCP server {name}: package registry must be {' or '.join(MCP_REGISTRIES)}")
    if not isinstance(called, str) or not (NPM_PACKAGE if registry == "npm" else PYPI_PACKAGE).fullmatch(called):
        raise ValueError(f"the MCP server {name}: {called!r} is not the name of a package of {registry}")
    if not isinstance(package.get("version"), str) or not PACKAGE_VERSION.fullmatch(package["version"]):
        raise ValueError(f"the MCP server {name}: package version must be one exact version, such as 1.2.3")
    if not isinstance(package.get("as_of"), str) or not PACKAGE_DAY.fullmatch(package["as_of"]):
        raise ValueError(f"the MCP server {name}: package as_of must be a day, YYYY-MM-DD")
    run = package.get("bin")
    if run is not None and not (isinstance(run, str) and MCP_PROGRAM.fullmatch(run)):
        raise ValueError(f"the MCP server {name}: package bin must be the name of one program of the package")
    return {"registry": registry, "name": called, "version": package["version"], "as_of": package["as_of"],
            "bin": run}


# The names of the programs whose sessions put a server's name before the names of its tools, and deny that name's
# tools: OpenCode names each tool of a server `<server>_<tool>`, and its sessions deny the pattern `opencode_*`
# (acp_programs.OpenCode.config, the coordinator's decision D32), so a server named opencode would give an OpenCode
# session none of its tools, with nothing that says why (D33, the review's H1).
MCP_PROGRAM_NAMES = {"opencode": "OpenCode"}


def mcp_server(name, entry, new=False):
    """One server of team.json "mcp" as a catalog entry (TOOL_CATALOG's shape, with custom and auth), or ValueError
    with the reason. new: the owner's write of this server (POST /ui/team/mcp, and the check of a server before its
    save), which refuses a name of MCP_PROGRAM_NAMES too; team.json's own entries are read without it (validate_team,
    tool_catalog), because one refused name there refuses the whole team, so a fleet whose file has one would stop
    taking each write and each reload. A url server has url and, for auth "oauth" or "key", bearer: the session
    variable that holds its token. A program server has command (a program of the machine) or package (a program that
    Fleet installs from npm or PyPI, mcp_package), and args (its arguments), settings ({its own variable: a plain
    value}) and env ({its own variable: the session variable of the API key whose value it gets}). Its own variables
    are setting names (setting_name; a key's own variable may also be a key's name, key_variable), and each session
    variable has the shape of a key's name (key_env) and is none of Fleet's own (FLEET_KEYS). A session that lacks one
    of these keys gets no such server. Arguments and settings came back on 15 November 2026 (the owner's "The hub";
    MCP_FIELDS)."""
    if not isinstance(name, str) or not MCP_NAME.fullmatch(name):
        raise ValueError(f"the MCP server name {name!r} must be 1 to 31 characters a-z 0-9 - that start with a letter")
    if name in TOOL_CATALOG or name == "fleet":
        raise ValueError(f"the name {name} is Fleet's own: choose another one")
    if new and name in MCP_PROGRAM_NAMES:
        raise ValueError(f"the name {name} is the program {MCP_PROGRAM_NAMES[name]}'s own: choose another one")
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
    made = {"title": title.strip(), "runtimes": sorted(runtimes), "custom": True, "auth": auth}
    kinds = [kind for kind in ("url", "command", "package") if kind in entry]
    if len(kinds) != 1:
        raise ValueError(f"the MCP server {name} needs a url (a remote server), a command (a program on the "
                         f"machine) or a package (a program that Fleet installs): one of them, not both")
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
        for field in ("env", "args", "settings"):
            if entry.get(field):        # an empty one is none, as team.json had it before 15 November 2026
                raise ValueError(f"the MCP server {name}: {field} is for a program server; a url server takes only "
                                 f"a key")
        return made
    if auth != "none":
        raise ValueError(f"the MCP server {name}: a program server has no auth; give its key in env")
    if "key" in entry:
        raise ValueError(f"the MCP server {name}: key is for a url server with auth \"key\"")
    if "mint" in entry or "mint_field" in entry:
        raise ValueError(f"the MCP server {name}: mint and mint_field are for a url server with auth \"mint\"")
    variables, settings, args = entry.get("env") or {}, entry.get("settings") or {}, entry.get("args") or []
    if not isinstance(variables, dict) or len(variables) > MCP_KEYS_MOST or not all(
            key_variable(k) and key_env(v) and v not in FLEET_KEYS for k, v in variables.items()):
        raise ValueError(f"the MCP server {name}: env maps up to {MCP_KEYS_MOST} of its own variable names to the names "
                         f"of API keys that the agent reads: its own name A-Z a-z 0-9 _ and none that changes how a "
                         f"program starts, and the key's name A-Z 0-9 _ ending in {', '.join(KEY_SUFFIXES)}, which is "
                         f"no key of Fleet's own ({', '.join(FLEET_KEYS)})")
    if not isinstance(settings, dict) or len(settings) > MCP_SETTINGS_MOST or not all(
            setting_name(k) and plain_value(v, MCP_SETTING_MOST) for k, v in settings.items()):
        raise ValueError(f"the MCP server {name}: settings maps up to {MCP_SETTINGS_MOST} of its own variable names "
                         f"(A-Z a-z 0-9 _, none that changes how a program starts, such as NODE_OPTIONS, PYTHONPATH "
                         f"or a proxy) to plain values of at most {MCP_SETTING_MOST} characters, with no control "
                         f"character and no $")
    keyed = sorted(k for k in settings if secret_name(k) or k in variables)
    if keyed:
        raise ValueError(f"the MCP server {name}: {', '.join(keyed)} has the name of a secret, so it goes in env, "
                         f"from an API key of the Secrets page, and never in settings as plain text")
    if args and "package" not in entry:
        raise ValueError(f"the MCP server {name}: args is for a package that Fleet installs; a command takes none")
    if not isinstance(args, list) or len(args) > MCP_ARGS_MOST or not all(
            plain_value(a, MCP_ARG_MOST) and a for a in args):
        raise ValueError(f"the MCP server {name}: args takes up to {MCP_ARGS_MOST} arguments of 1 to {MCP_ARG_MOST} "
                         f"characters, with no control character and no $; it is no shell line")
    for i, arg in enumerate(args):
        flag, given, value = arg.partition("=")
        if secret_flag(flag) and (given and value or i + 1 < len(args) and not args[i + 1].startswith("-")):
            raise ValueError(f"the MCP server {name}: the argument {flag} takes a secret, which goes in env, from an "
                             f"API key of the Secrets page, and never in args as plain text")
    made.update(args=list(args), env=dict(sorted(variables.items())), settings=dict(sorted(settings.items())))
    if "package" in entry:
        made["package"] = mcp_package(name, entry["package"])
    elif not isinstance(entry["command"], str) or not MCP_PROGRAM.fullmatch(entry["command"]):
        raise ValueError(f"the MCP server {name}: command must be the name of a program on the machine (1 to 64 "
                         f"characters A-Z a-z 0-9 . _ -), which the machine has on its PATH or in ~/.local/bin")
    elif mcp_runner(entry["command"]):
        raise ValueError(f"the MCP server {name}: {entry['command']} fetches or runs another program, so it is no "
                         f"command server: give the server's npm or PyPI package, which Fleet installs itself")
    else:
        made["command"] = entry["command"]
    return made


def tool_needs(tool):
    """The session variables that one catalog entry needs: the variables of a stdio server, and the bearer variable of
    a url server. A session that lacks one of them gets no such server. A mint server's token is made at the start of
    each task session (fleet.mint_tokens), which drops the server when it gets none."""
    return sorted(set((tool.get("env") or {}).values()) |
                  ({tool["bearer"]} if tool.get("bearer") and not tool.get("mint") else set()))


def tool_catalog(team, refused=None):
    """The catalog of this team: Fleet's own tools and the owner's MCP servers of team.json "mcp". A server that does
    not pass mcp_server is left out, so a hand-written entry can never reach a session; refused, a dict, gets the
    reason of each one, so that the start text can say it."""
    catalog = {name: dict(tool, custom=False, auth="none") for name, tool in TOOL_CATALOG.items()}
    for name, entry in sorted(((team or {}).get("mcp") or {}).items()):
        try:
            catalog[name] = mcp_server(name, entry)
        except ValueError as e:
            if refused is not None:
                refused[name] = str(e)
    return catalog


def mcp_start(keep, path, folder, program, environ=None, execve=os.execve):
    """`python3 -E -s lifecycle.py mcp-start`: the start of every program server of the owner (owner feature
    mcp_packages). The program gets a new environment with only these variables: its own settings and keys (keep:
    "NAME" passes the variable NAME on, "NAME=SOURCE" gives the program NAME with the value of SOURCE, the session
    variable of a key), the few of MCP_START_KEEPS that its runtime needs, and PATH as given. So it gets no GH_TOKEN,
    no other key of the session, no proxy and no option of its runtime. It starts in a new empty folder of
    its own under folder (named by its process, whose number stays when the program replaces this one), because some
    programs read a .env file of their working folder (mcp-server-odoo does), and a shared folder can hold one that
    another program wrote; the folders of starts whose program ended go at the next start. Python runs it with -E -s, so no PYTHONPATH of the session changes this file.
    ValueError for a name that no program server may have."""
    environ = os.environ if environ is None else environ
    if not program or not os.path.isabs(program[0]) or len(keep) > MCP_START_MOST:
        raise ValueError("mcp-start needs the absolute path of a program and at most "
                         f"{MCP_START_MOST} variables")
    env = {name: environ[name] for name in MCP_START_KEEPS if name in environ}
    env.setdefault("HOME", os.path.expanduser("~"))
    for item in keep:
        own, _, source = item.partition("=")
        source = source or own
        if not (key_variable(own) and SETTING_NAME.fullmatch(source)) or source in FLEET_KEYS:    # a setting, a key
            raise ValueError(f"mcp-start passes no variable {item!r} on")
        if source in environ:
            env[own] = environ[source]
    env["PATH"] = path
    os.makedirs(folder, mode=0o700, exist_ok=True)
    for left in os.listdir(folder):     # the folders of starts whose program ended
        pid = left.split("-", 1)[0]
        if pid.isdigit() and int(pid) != os.getpid() and not process_alive(int(pid)):
            shutil.rmtree(os.path.join(folder, left), ignore_errors=True)
    os.chdir(tempfile.mkdtemp(prefix=f"{os.getpid()}-", dir=folder))       # mode 700, this start's alone
    execve(program[0], list(program), env)


def process_alive(pid):
    """True while a process of this number runs (one of another user counts as running)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


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


def chrome_hidden(home):
    """True when macOS refuses this process a list of Chrome's own folder ("Operation not permitted": macOS 27 to a
    background service, read on the owner's Mac Studio on 19 November 2026). chrome_extension then reads None whether
    Chrome has the extension or not, and only Claude Code's own list of browsers (browser_connected) can say. A refused
    open of a profile's record counts too. A Mac with no Chrome folder is no such Mac: its None means no extension."""
    chrome = os.path.join(home, "Library", "Application Support", "Google", "Chrome")
    try:
        names = os.listdir(chrome)
    except PermissionError:
        return True
    except OSError:
        return False
    for name in names:
        try:
            with open(os.path.join(chrome, name, "Secure Preferences"), "rb"):
                pass
        except PermissionError:
            return True
        except OSError:
            continue
    return False


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


# Anthropic's link server between Claude's extension in Chrome and Claude Code. The extension links to Claude Code
# only through it, and only while it is signed in to the same claude.ai account and organization as Claude Code;
# else Claude Code's browser tools say "Browser extension is not connected" (code.claude.com/docs/en/chrome, read on
# 19 November 2026). Claude Desktop's own link program in Chrome is no part of it: on the owner's Mac Studio it ran
# on 28 October 2026 too, the day a browser task worked there.
BRIDGE_HOST = "bridge.claudeusercontent.com"
# An organization's name as the manager reads it in the owner's steps (desktop_account): plain words, no markup. With
# "@": claude.ai names a personal organization "<email>'s Organization", and an account in a team organization and in
# its personal one is the case where the organization decides the link.
ORG_NAME = re.compile(r"[\w .,&'()+@-]{1,120}")


def claude_account(run, exe):
    """The account and the organization that Claude Code is signed in to on this machine, from its own `auth status`
    (no model turn): {"email", "org"}, or None when it is not signed in or names no valid email. Claude's extension
    links to Claude Code only when it is signed in to this same account and organization, so these are the words of
    the owner's step at the Mac (hub.mac_desktop_sweep). `org` is None for a name that is not plain words.

    Why (19 November 2026): the extension on the owner's Mac Studio stayed unlinked for 19 days through five cards,
    and no card named the account to sign in with. Meanwhile Claude Code there changed account, which leaves an
    extension that worked on the old one."""
    from usage import safe_email        # usage imports this module, so not at the top
    code, out, _ = run([exe, "auth", "status"])
    try:
        said = json.loads(out) if code == 0 else None
    except ValueError:
        return None
    if not isinstance(said, dict) or said.get("loggedIn") is not True or safe_email(said.get("email")) is None:
        return None
    org = said.get("orgName")
    return {"email": said["email"], "org": org.strip() if isinstance(org, str) and ORG_NAME.fullmatch(org.strip())
            else None}


def bridge_reachable(connect=socket.create_connection):
    """Whether this Mac reaches Anthropic's link server (BRIDGE_HOST) on port 443 directly: True or False. It is the one
    cause of an unlinked extension that no sign-in puts right, so it is read only while no browser answers. A Mac whose
    traffic goes through a proxy reads False while Chrome may reach it, so it is a note beside the sign-in steps, never
    in their place (hub.unlinked_steps)."""
    try:
        connect((BRIDGE_HOST, 443), timeout=5).close()
        return True
    except OSError:
        return False


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


def desktop_items(run, home, user, tabs, connected=None, account=None):
    """What a Mac's desktop can do now, as setup check items: the one reading of it, which the helper's setup check and
    `fleet.py verify` both give. tabs: the runtime works in tabs of Chrome through Claude's extension. connected: what
    browser_connected read in the login session, None where nobody read it. account: Claude Code's account there
    (claude_account), which an extension that is not linked must use, None where nobody read it."""
    session = session_item(run, user)
    ready = session[2] == "ok"
    setup = session[3] if session[3] == SETUP_SCREENS else None         # the screens cover the session's own screen
    chrome = any(os.path.isdir(p) for p in ("/Applications/Google Chrome.app",
                                             os.path.join(home, "Applications", "Google Chrome.app")))
    extension = chrome_extension(home) if tabs else True
    # macOS 27 refuses a background service a list of Chrome's own folder (chrome_hidden): there a Chrome that answers
    # Claude Code's account is the extension at work. A Mac that reads its folder and finds no extension stays failed.
    hidden = extension is None and chrome_hidden(home)
    usable = chrome and ready and (extension or hidden and connected is True) and (not tabs or connected is not False)
    store = " If Chrome has no Claude extension, add it from the Chrome Web Store first." if hidden else ""
    return [("capability", "browser", "ok" if usable else "failed",
             "Google Chrome is installed, and the session is ready." if usable else
             "Google Chrome is not installed." if not chrome else setup if setup else
             f"The browser needs {user} at the console with the screen unlocked." if not ready else
             "Claude's extension is off: press Enable Extension in Chrome on this Mac." if extension is False else
             "Claude's extension is not in Chrome on this Mac: restart Chrome, then press Enable Extension."
             if extension is None and not hidden else
             "macOS does not let Fleet read Chrome's folder on this Mac, and no reading of Claude Code's browser link "
             "was made here." if connected is None else
             "Claude's extension is not signed in: sign in to Claude in Chrome on this Mac, with this Mac's account."
             + store if not account else
             f"Claude's extension is not linked to Claude Code: in Chrome on this Mac, sign it in as {account['email']}"
             + (f", organization {account['org']}." if account.get("org") else ".") + store),
            ("capability", "screen", "not_verified" if ready else "failed",
             "The session is ready, but Fleet cannot check the macOS screen recording and accessibility "
             "permissions that screen control needs." if ready else
             setup or f"Screen control needs {user} at the console with the screen unlocked."),
            autologin_item(run, user), awake_item(run), session]


def pinned_path(name, home=None):
    """Where the pinned program of a runtime is for one OS user: ~/.fleet/runtimes/<name>-<version>/<bin>, by its
    entry of onboard.PINNED (fleet.install_pinned puts it there). None for a runtime whose program is not pinned."""
    pin = onboard.PINNED.get(name) if runtime_fact(name, "pinned") else None
    if not pin:
        return None
    return os.path.join(home or os.path.expanduser("~"), FLEET_DIR, "runtimes", f"{name}-{pin['version']}", pin["bin"])


def exe(name, home=None):
    """A runtime's executable: on PATH, else in ~/.local/bin; None when neither has it. A pinned program is the file
    of its pin and no other (pinned_path): no PATH decides which program runs."""
    if runtime_fact(name, "pinned"):
        path = pinned_path(name, home)
        return path if path and os.path.isfile(path) else None
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
    return [{"model": a, "display_name": a[:1].upper() + a[1:], "default": False, "efforts": efforts,
             "default_effort": None}
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
    file with other bytes stays, and the merge then says why it cannot; but a name that .gitignore names (run.log)
    is one that git writes over without a word, so the delivered bytes take its place. Every fast-forward of a
    checkout that delivers goes through this: the task-start sync (follow_config_ref) and the Fleet update
    (Lifecycle.apply)."""
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
    why. Called around every move, so the floor follows what each checkout took.

    The read, the check and the write hold the floor's lock: the checkouts of one OS user (its agents' helpers, each
    with a status thread and a task-start sync, and its server service) move at the same time, and one that read the
    floor before another raised it would else write its older release over the newer one."""
    if not floor:
        return
    text = _blob(kit, run, head, RELEASE_FILE)
    revision, version = released(text) if text is not None else (None, None)
    if not revision:
        return
    with contextlib.suppress(OSError):
        os.makedirs(os.path.dirname(floor), mode=0o700, exist_ok=True)
        lock = os.open(floor + ".lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            current, problem = read_floor(floor)
            if problem or revision == current or (current and not _descends(kit, run, current, revision)):
                return
            temp = f"{floor}.{os.getpid()}"
            with open(temp, "w", encoding="utf-8") as f:
                f.write(json.dumps({"revision": revision, "version": version}) + "\n")
            os.replace(temp, floor)
        finally:
            os.close(lock)


def may_take(kit, target, run=None, floor=None, head="HEAD"):
    """None when the checkout `kit` may move from `head` to `target`, else the one reason why it stays where it is.

    A move that changes data only (data_path) passes when each file it brings is a plain file. Any other move passes
    only onto a release: `target` carries a release.json that a key of `head`'s two key files signed, which is not
    held; its revision descends from the release that `head` runs and from the floor; and `target` is that revision's
    own tree outside the data. **A `head` with no release takes one that comes after the floor**: on a machine whose
    checkouts share one user (its agents and its server service), the first that took a signed release wrote the
    floor, and the others take theirs after it. They stayed where they were for every release after that (3 November
    2026: the Mac Studio's server service and a support agent on worker-1, at the revisions of that morning). Every
    mover of a checkout calls this first: the helper's update and task-start sync, the server service, the hub, both
    installers and the owner's MCP server (the shell ones as `lifecycle.py may-take`). The helper's two movers and the
    server service's then check that the release starts on their machine, and only after this passed (take,
    `starts`): no code of a tree runs before its signature passed."""
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


def take(kit, target, run=None, floor=None, room=False, starts=None):
    """Move this checkout onto `target` when may_take lets it: a fast-forward, and the floor raised to the release it
    then runs. `target` is read once, as one commit, and that commit is the one checked and the one taken, so a fetch
    in between moves nothing unchecked. room: first remove the outputs that it brings back tracked (give_way_to).
    starts: the role of the program that runs from this checkout (START_PROGRAMS: the helper's update and task-start
    sync, the server service's update), or None for a mover that starts nothing from it (the hub's own update, which
    has its larger check, the installers, the owner's MCP server, a new agent's checkout). With a role, a move that
    brings code runs the release's own start check after may_take and before the move (start_problem), and a release
    that does not start on this machine moves nothing and raises no floor; a check that cannot run here stops nothing.
    The result of each check is kept beside the floor (keep_start_check), and changes nothing of this decision.
    None, or the reason why the checkout stays where it is: a Refused for a release that did not start here, a
    CheckTimedOut for one whose check did not end in time."""
    keep_floor(kit, floor, run)
    commit = _commit(kit, run, target)
    if not commit:
        return f"{target} is not a commit of this checkout"
    problem = may_take(kit, commit, run, floor) or \
        (start_problem(kit, commit, starts, run, floor=floor) if starts else None)
    if problem:
        return problem
    if room:
        give_way_to(kit, commit, run)
    code, out, err = _git(kit, run, "merge", "-q", "--ff-only", commit, timeout=120)
    if code != 0:
        return "git merge failed: " + (err or out.strip())[-200:]
    keep_floor(kit, floor, run)
    return None


def follow_config_ref(kit, run=None, floor=None, starts=None):
    """Bring this checkout onto the configuration ref and up to date with it, fast-forward only, and only where
    may_take lets it. The hub commits the owner's team.json, profiles and knowledge there, so an agent reads the
    current RULES.md, its profile and the owner's knowledge, while code reaches this machine only with a signed
    release. Returns None when the checkout follows the ref, else the one reason why it stays as it is: a checkout
    with its own changes is never touched. An origin without the ref is a Fleet before the split of 2026-10-17, and
    is brought up to date as it was before, under the same check. starts: as take's, for each move that this makes,
    the one onto the ref's branch too. A checkout that keeps its revision for a release that did not start here also
    takes no later data of the ref, until a release that starts here."""
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
        return take(kit, "@{upstream}", run, floor, starts=starts)
    if checkout_branch(kit, run) != CONFIG_BRANCH:
        here = git("rev-parse", "--verify", "--quiet", "refs/heads/" + CONFIG_BRANCH)[0] == 0
        keep_floor(kit, floor, run)
        # one commit, checked and then checked out, as take() does
        commit = _commit(kit, run, CONFIG_BRANCH if here else "origin/" + CONFIG_BRANCH)
        problem = may_take(kit, commit, run, floor) if commit else "the ref is not a commit of this checkout"
        if problem:
            return f"the checkout did not move onto {CONFIG_BRANCH}: {problem}"
        problem = start_problem(kit, commit, starts, run, floor=floor) if starts else None
        if problem:
            return problem
        code, out, err = git("checkout", "-q", CONFIG_BRANCH) if here else \
            git("checkout", "-q", "-b", CONFIG_BRANCH, commit)
        if code == 0 and not here:
            code, out, err = git("branch", "-q", "--set-upstream-to=origin/" + CONFIG_BRANCH, CONFIG_BRANCH)
        if code != 0:
            return f"the checkout did not move onto {CONFIG_BRANCH}: " + (err or out)[-200:]
    return take(kit, "origin/" + CONFIG_BRANCH, run, floor, room=True, starts=starts)


# ---------------------------------------------------------------- a release starts here before a checkout moves onto it
#
# Only the hub checked a release before it ran it (releases.Update.checks). Each other program of a machine moved its
# checkout onto the release and started itself again on the new code, and a unit with Restart=always then started a
# release that did not start on that machine again and again, until a person installed it again. So the program that
# runs from a checkout checks a release on its machine before the checkout moves (take, `starts`): from a temporary
# copy of the target tree, with that tree's own command, `lifecycle.py start-check <role>`, so a later release can add
# to its own check with no change of the code that runs it. A release that does not start here leaves the checkout,
# the floor and the running program as they are, and the machine says why. A check that cannot run here stops nothing:
# it guards that a release starts, not that it is trusted (may_take passed already), so a fault of the checker is
# never worse than no checker.
START_CHECK_WAIT = 420      # seconds for a release's own start check: the hub's wait for fleet.py verify (releases)
START_PROGRAMS = {"helper": "fleet.py", "server": "server.py"}     # each role's program, from which its check loads
# hub.py is not loaded: verify.py imports it for one rule, it is the hub's own program, it costs seconds and more than
# 100 MB, and the hub's own check of a release loads it (releases.Update.checks).
START_LEFT_OUT = ("hub",)
# The files of the tree that each role's program starts by their path, as a program or a hook, and does not import:
# the import step never reads them, and a line that this machine's Python refuses in hook_hosts.py ends each tool call
# of each session there with status 2. The check compiles each of them, and each file that it imports that the import
# step did not load (hook_clean.py's hidden.py), with this machine's Python, and runs none of them: a hook runs at each
# tool call and a runner for a whole task, and their code reads and writes the machine. The helper starts the two hooks
# (fleet.clean_hook, fleet.hosts_hook), the two runners of a task (fleet.acp_command, fleet.session_command), the chat
# bridge (fleet.cmd_service), the door's `ops` command (fleet.ensure_ops) and `lifecycle.py mcp-start`
# (fleet.program_start); the server service starts `fleet.py` in an agent's checkout of the same release (its key, its
# service, a pinned install) and home_reading.py as each agent's user. test_signed_code reads fleet.py and server.py and
# fails for a file that one of them starts by its path and that is in neither list.
START_FILES = {"helper": ("acp_runner.py", "channels.py", "hook_clean.py", "hook_hosts.py", "lifecycle.py", "ops.py",
                          "screen_runner.py"),
               "server": ("fleet.py", "home_reading.py")}
# Each file that a program names by its path and does not start, and why, for that test.
START_NOT_STARTED = {"vault.py": "read and hashed, never started: the vault broker runs a root-owned copy of its own, "
                                 "outside every checkout (server.Service.vault_program)"}
# {a checkout's real path: (the revision of the last release that did not start, the words, its record's fields)}
_REFUSED = {}
# {a checkout's real path: (the revision of the last release whose check did not end in time, how many times in a row
# in this process, the words, its record's fields)}: from the second time on it is served from here (start_problem)
_TIMED_OUT = {}
# The result of the last start check of each program of this user (its role), in a file beside the user's release
# floor, which outlives the restart after a move: the helper's report and the server service's reading carry it as
# `start_check` (read_start_check), so the hub knows a check that passed from one that could not run, and a refusal as
# a fact and not as words to match. One file for each role: on a Mac the helper and the server service run as one
# user, with one floor, and the one that checked last would else write over the other's result.
START_RECORD = "start-check-{}.json"
START_RESULTS = ("passed", "not_run", "refused", "timed_out")     # hub.start_check_status takes these words only


class Refused(str):
    """take()'s reason for a release that did not start on this machine (start_problem): the words that the owner
    reads, which name the release and say why. A caller that starts again after a move tells it apart from any other
    reason."""


class CheckTimedOut(str):
    """take()'s reason for a release whose start check did not end within START_CHECK_WAIT (start_problem): the words
    that the owner reads. It is no refusal: nothing is kept, so the next request of that release checks it again. A
    caller shows the words as they are, keeps its checkout and starts nothing."""


def start_record_path(floor, role):
    """The file of the last start check of this user's program `role` (a key of START_PROGRAMS), beside its release
    floor; None with no floor or another role."""
    return os.path.join(os.path.dirname(floor), START_RECORD.format(role)) if floor and role in START_PROGRAMS else None


def keep_start_check(floor, role, result, release, revision, keeps, reason):
    """Write the result of one start check of the program `role` beside the floor (start_record_path), whole or not at
    all: a temporary file in the same folder, then os.replace. `result` is one of START_RESULTS; `release` the version
    of the release checked, else the first 12 of its commit; `revision` the release revision that its release.json
    names, or None; `keeps` the version of the release that the checkout carries now, or the first 12 of HEAD; `reason`
    why it did not pass, at most 300 characters, or None. It never raises: a record that cannot be written changes no
    decision of a move, and the next check writes it again."""
    temp = None
    try:
        path = start_record_path(floor, role)
        if not path:
            return
        said = {"result": result, "release": release, "revision": revision, "keeps": keeps,
                "reason": None if reason is None else str(reason)[:300], "at": time.time()}
        folder = os.path.dirname(path)
        os.makedirs(folder, mode=0o700, exist_ok=True)
        handle, temp = tempfile.mkstemp(prefix=os.path.basename(path) + ".", dir=folder)
        with os.fdopen(handle, "w", encoding="utf-8") as f:
            json.dump(said, f)
        os.replace(temp, path)
        temp = None
    except Exception:       # noqa: BLE001 -- a record is never worth a move or a report
        pass
    finally:
        if temp:
            with contextlib.suppress(OSError):
                os.unlink(temp)


def read_start_check(floor, role):
    """The record of the last start check of this user's program `role` (keep_start_check) as it was written, or None:
    no floor, no file, or a file that does not parse as one object. The hub checks each field (hub.start_check_status)."""
    path = start_record_path(floor, role)
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as f:
            said = json.load(f)
    except (OSError, ValueError):
        return None
    return said if isinstance(said, dict) else None


def start_problem(kit, commit, role, run=None, head="HEAD", floor=None):
    """None when the move of checkout `kit` from `head` onto `commit` brings data only (data_path), when the tree of
    `commit` starts on this machine as `role`, or when its check cannot run here; else a Refused, the words of why the
    checkout stays, or a CheckTimedOut when the check did not end within START_CHECK_WAIT. Called only after may_take
    passed on `commit`. It never raises.

    With a `floor` (the caller's release floor), each check that was due leaves its result beside it, in the file of
    `role`, once its answer decided (keep_start_check): passed, not_run, refused or timed_out. A refusal served
    again from this process writes its record again with a new time, so the record says what the last move met; the
    hub keeps that time as `checked_at` and decides by release, never by it (hub.start_refused). A move of data only
    and the same commit write nothing.

    Only the release's own answer refuses: its command ended by itself with a status above 0. That refusal is kept in
    this process: a later target that carries the same release (the revision of its release.json) is refused with the
    same words and no new copy, and a target of another release is checked. A new process checks once more, because an
    update of the system can have removed the cause. Anything else is a fault of this machine's moment or of the
    checker, not of the release: no room for the copy, a git step that fails, a command that could not start (no
    memory) or that a signal ended (status below 0) (start_check). Then the move goes on as it did before this check,
    one line on standard error says so, and nothing is kept. A check whose wait ran out is neither: a release that
    hangs as it loads would hang the program that starts it, the dead machine that this check exists to prevent, and
    a loaded server can be why. So the checkout stays, as for a refusal, and the next request of the release checks
    it again, once: a second time-out of the same release in this process is kept (_TIMED_OUT), with words that say
    so, and each later target of that release gets those words and its record again, with no copy and no wait,
    because each task start of each agent of the server would else wait START_CHECK_WAIT for it. A new process, or
    another release, checks again."""
    name, revision, keeps = commit[:12], None, None
    try:
        old = _commit(kit, run, head)
        if old == commit:
            return None
        changed = changed_paths(kit, run, old, commit) if old else None
        if changed is not None and all(data_path(path) for path, _ in changed):
            return None
        text = _blob(kit, run, commit, RELEASE_FILE)
        revision, version = released(text) if text is not None else (None, None)
        name, key = version or name, os.path.realpath(kit)
        kept = _REFUSED.get(key)
        if revision and kept and kept[0] == revision:
            keep_start_check(floor, role, "refused", *kept[2])
            return kept[1]
        hung = _TIMED_OUT.get(key)
        if revision and hung and hung[0] == revision and hung[1] >= 2:
            keep_start_check(floor, role, "timed_out", *hung[3])
            return hung[2]
        if floor and old:               # what the checkout keeps if this release does not start: for the record only
            mine = _blob(kit, run, old, RELEASE_FILE)
            keeps = (released(mine)[1] if mine is not None else None) or old[:12]
        result, reason = start_check(kit, commit, role, run)
    except Exception as e:      # the checker's own fault, never the release's
        result, reason = "not_run", _fault(e)
    keep_start_check(floor, role, result, name, revision, keeps, reason)
    if result == "passed":
        return None
    if result == "not_run":
        with contextlib.suppress(OSError, ValueError):      # a standard error that is gone stops nothing either
            print(f"Release {name} is taken without its start check, which could not run on this server: {reason}",
                  file=sys.stderr, flush=True)
        return None
    if result == "timed_out":
        hung = _TIMED_OUT.get(key) if revision else None
        times = hung[1] + 1 if hung and hung[0] == revision else 1
        # the second time-out is kept, and its words, which each later target of the release gets, say so
        words = CheckTimedOut((f"Release {name} was not taken this time: {reason}. It is checked again at the next "
                               f"update." if times < 2 else
                               f"Release {name} was not taken: {reason} two times. It is checked again with the next "
                               f"release, or when this program starts again.")[:300])
        if revision:
            _TIMED_OUT[key] = (revision, times, words, (name, revision, keeps, reason))
        return words
    words = Refused(f"Release {name} did not start on this server, so the server keeps the version that it runs: "
                    f"{reason}"[:300])
    if revision:
        _REFUSED[key] = (revision, words, (name, revision, keeps, reason))
    return words


def _fault(e):
    """An exception of this code as one short line: its type and the first line of its message."""
    said = str(e).strip().splitlines()
    return f"{type(e).__name__}: {said[0] if said else ''}".strip()[:300]


def start_check(kit, commit, role, run=None):
    """Whether the tree of `commit` starts on this machine as `role`, as (a word of START_RESULTS, the reason):
    ("passed", None); ("refused", the reason) when the tree's own `lifecycle.py start-check <role>` ended by itself
    with a status above 0, the reason being the last line that is not empty of what it printed (its standard output,
    else its standard error); ("timed_out", the reason) when it did not end within START_CHECK_WAIT; or ("not_run",
    the reason) when it gave no answer of its own: anything of this code went wrong before that command answered
    (the copy most of all), or the command could not start or a signal ended it (start_command). It never raises.
    The copy is made as the hub makes its own (releases.Update.in_clone), in a new temporary folder that goes in every
    case, with each git step through `run`, as every git step of take; the command runs in it with no compiled file
    written (-B), as a process of its own (start_command), because `run` gives one status for a command that ended
    with 1 and for one that never ran."""
    run, folder = run or _run, None
    try:
        folder = tempfile.mkdtemp(prefix="fleet-start-check-")
        copy = os.path.join(folder, "kit")
        code, out, err = run(["git", "clone", "-q", "--shared", kit, copy], timeout=120)
        if code == 0:
            code, out, err = run(["git", "-C", copy, "checkout", "-q", commit], timeout=120)
        if code != 0:
            said = (err or out or "").strip().splitlines()
            return "not_run", (said[-1] if said else "git made no copy")[:300]
        try:
            code, out, err = start_command([sys.executable, "-B", os.path.join(copy, "lifecycle.py"), "start-check",
                                            role], START_CHECK_WAIT, copy)
        except subprocess.TimeoutExpired:
            return "timed_out", f"its start check did not end within {START_CHECK_WAIT} seconds"
        if code == 0:
            return "passed", None
        if code is None or code < 0:        # no answer of the release's own: the machine's moment, never a refusal
            return "not_run", (err if code is None else f"its start check was ended by signal {-code}")[:300]
        said = [line.strip() for line in (out or "").splitlines() if line.strip()] or \
            [line.strip() for line in (err or "").splitlines() if line.strip()]
        return "refused", (said[-1] if said else f"its start check ended with {code} and said nothing")[:300]
    except Exception as e:      # before the release's command answered: the checker's fault
        return "not_run", _fault(e)
    finally:
        if folder:
            shutil.rmtree(folder, ignore_errors=True)


def start_command(argv, wait, cwd):
    """The release's own start check as a process of its own, in `cwd`: (its status, its standard output, its standard
    error). The status is None when the command could not start (an OSError: no memory for the process, no such
    program), and the error then says why; a status below 0 is the signal that ended it. A command that does not end
    within `wait` seconds is stopped, and subprocess.TimeoutExpired goes to the caller. Its output is read as UTF-8,
    with each byte that is not replaced."""
    try:
        done = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=wait, cwd=cwd,
                              stdin=subprocess.DEVNULL)
    except OSError as e:
        return None, "", f"its start check could not start: {_fault(e)}"
    return done.returncode, done.stdout, done.stderr


def program_modules(top, program):
    """The modules of folder `top` that the program in its file `program` can load, the program first: each name of
    an `import` or `from ... import` statement in any scope (an import inside a function counts) that is a .py file
    of `top`, and on from those files, read with ast. START_LEFT_OUT is not followed. A file that cannot be read or
    parsed is not followed either: its import says why."""
    import ast
    found, todo = [], [program[:-len(".py")]]
    while todo:
        name = todo.pop(0)
        if name in found or name in START_LEFT_OUT:
            continue
        found.append(name)
        try:
            with open(os.path.join(top, name + ".py"), encoding="utf-8") as f:
                tree = ast.parse(f.read())
        except (OSError, SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            names = [one.name for one in node.names] if isinstance(node, ast.Import) else \
                [node.module] if isinstance(node, ast.ImportFrom) and not node.level and node.module else []
            names = [each.split(".")[0] for each in names]
            todo += [one for one in names if os.path.isfile(os.path.join(top, one + ".py"))]
    return found


def start_readings(role, top, platform_name=sys.platform):
    """The readings that the program of `role` takes of its machine through this module, each of which changes
    nothing, sends nothing and needs no root: the system, the security facts and the ways in, for both; the load, the
    room and the browser parts for the server service (server.Service.reading); the agent's own use and Tailscale's
    word for a helper (Lifecycle.collect and leaving). Left out: the runtimes and their model lists, which start the
    vendors' programs, and those can reach the network; a Mac server's desktop, which writes a file and starts Claude
    Code; the live proof of the browser ports, which can stop an agent's browser, and the agents' users, which only
    the server's own process reads; the vault, the windows and the switch, which only the helper's process can say.

    Each reading runs its own code, with each command through one runner, but for the package lists: `apt-get -s
    upgrade` of the security facts can take a minute, while every agent of a server checks a release in the same
    seconds, and what it finds proves nothing about the code. So here it answers as a command that failed, and the
    reading's code takes that path (Lifecycle.security, whose other callers still run it)."""
    def run(argv, timeout=20, cwd=None):
        if argv[:1] == ["apt-get"]:
            return 1, "", "the start check reads no package list"
        return _run(argv, timeout=timeout, cwd=cwd)
    life = Lifecycle(top, role, {}, None, lambda: False, run=run, platform_name=platform_name)  # a name: no desktop
    taken = {"os": life.os_info(), "security": life.security(), "access": life.access()}
    if role == "server":
        taken.update(load=machine_load(platform_name, run=run), room=room_reading(platform_name),
                     browser=browser_reading(platform_name, run=run))
    else:
        taken.update(use=agent_use(role, run=run)[0], tailscale=life.private_network())
    return taken


def start_check_here(role, platform_name=sys.platform):
    """`lifecycle.py start-check <role>`, in the tree under test: (its exit status, its one line). Each module that
    the program of `role` can load (program_modules) loads, dependencies first, so a line names the module that does
    not load; each file that the program starts by its path (START_FILES), and each file that one of those imports
    and that did not load already, compiles with this Python, and none of them runs; and the readings of the machine
    end with no exception (start_readings). What a reading says does not count: a full disk or a firewall that is off
    never refuses a release. It is the seam of the later parts of the check, not a second `verify`."""
    import importlib
    sys.dont_write_bytecode = True      # no compiled file in the tree, as -B
    top = os.path.dirname(os.path.abspath(__file__))       # the folder of the tree, which is first on sys.path
    loaded = program_modules(top, START_PROGRAMS[role])
    for name in reversed(loaded):
        try:
            importlib.import_module(name)
        except (Exception, SystemExit) as e:        # a module that ends the process at its load does not load either
            said = str(e).strip().splitlines()
            return 1, f"start-check: {name} does not load: {type(e).__name__}: {said[0] if said else ''}".strip()
    compiled = []
    for started in START_FILES[role]:
        compiled += [name for name in program_modules(top, started) if name not in loaded and name not in compiled]
    for name in compiled:
        try:
            with open(os.path.join(top, name + ".py"), "rb") as f:
                source = f.read()
        except OSError:
            continue                    # a file that this tree does not have: nothing here starts it
        try:
            compile(source, name + ".py", "exec", dont_inherit=True)
        except (SyntaxError, ValueError) as e:      # ValueError: a null byte, on a Python before 3.12
            said = str(e).strip().splitlines()
            return 1, f"start-check: {name}.py does not compile: {type(e).__name__}: {said[0] if said else ''}".strip()
    try:
        start_readings(role, top, platform_name)
    except Exception as e:
        said = str(e).strip().splitlines()
        return 1, f"start-check: the reading of this machine failed: {type(e).__name__}: {said[0] if said else ''}"
    return 0, f"start-check: this release starts here as {role}"


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


def screen_codex(conf, name):
    """The screen runtime's program when the runtime `name` is this agent's Codex of its screen tasks, else None: the
    ONE rule for which program answers for Codex's sign-in on a machine. Codex is the runtime of every screen runtime
    (APP_SERVER_RUNTIME, which screen_runner drives). For an agent whose own provider is not Codex and whose settings
    give it a screen runtime that is on this machine, Codex is that program and no other: its screen tasks run it
    (screen_runner), so its status command says what the machine keeps (Lifecycle.runtime), its account read confirms
    that (usage.Collector, route "screen"), and the owner's sign-in and sign-out run it (fleet.Helper.runtime_login).
    An agent whose own provider is Codex keeps its own program for all three, and so does an agent with no screen
    runtime here.

    Why not "the plain `codex` of the PATH when the machine has one": nothing of such an agent ever runs that
    program, and it need not be the same Codex. On the owner's Mac Studio on 18 November 2026 it was 0.166.0 beside
    the app's 0.163.0-alpha.10.2, which answers an ended sign-in in other words (usage.codex_account); on the Mac
    that builds this code it is a script that starts a third version. Until that day the reading and the sign-in
    asked the plain program and only the account read asked the app's copy: that agreed only while both programs
    kept one sign-in in one file, and a Mac with no plain program read nothing of Codex's sign-in and could not be
    signed in from the app."""
    if not isinstance(conf, dict) or name != APP_SERVER_RUNTIME or conf.get("runtime") == name:
        return None
    program = screen_program(conf)
    return program if program and os.path.isfile(program) else None


# What `codex login status` prints for a sign-in that the machine keeps. Measured on 19 November 2026 in homes with
# made-up sign-ins: Codex 0.163.0 says "Logged in using ChatGPT" and "Logged in using an API key - ..."; the ChatGPT
# app's own Codex 0.169.0-alpha.11.1 says "Logged in using ChatGPT" and, for a key, "API key configured - ..." with
# a second line "Authentication is checked when you send a request." Both say "Not logged in" for none. Both end
# with status 0 for a sign-in and 1 for none, which no reader here asks.
CODEX_KEEPS_SIGN_IN = ("Logged in", "API key configured")


def codex_keeps_sign_in(text):
    """Whether these words of `codex login status` say that the machine keeps a sign-in of Codex: the ONE reading of
    that command's words for the machine's reading (Lifecycle.runtime), the Mac's ChatGPT reading (Lifecycle.chatgpt)
    and the health check (verify.py). onboard.CODEX_STATUS is the same rule in the shell of a machine that has no
    code of ours yet, and the Mac installer has its own (MacSittingRead.chatGPTSignedIn in app/, which still takes
    "Logged in" alone: with a key it asks for the ChatGPT app's own sign-in).

    A key is a sign-in here, as it was while Codex called it "Logged in using an API key". While only "Logged in"
    counted, an agent with a key read as signed out on a Codex that says "API key configured": the hub refused its
    switch to Codex, and the hub holds the work of an agent that reads so. False for no words: each reader says what
    a silence is for it."""
    return any(word in text for word in CODEX_KEEPS_SIGN_IN) and "Not logged in" not in text


# Where the helpers of one OS user leave the word of the newest account read of the screen runtime that gave an
# answer (leave_screen_word), for the one reader that has no account read of its own: a Mac's server service,
# whose reading says whether the ChatGPT app is signed in (Lifecycle.chatgpt). All agents of a Mac run as that
# service's user, so the file is in the home of them all: ~/.fleet/screen-sign-in.json, {at, ended, agent}.
SCREEN_WORD_FILE = "screen-sign-in.json"
# A word that no read gave again in this time says nothing any more: no helper of this user reads that account now
# (none runs, or each read fails). It is three reads of the account's poll clock, the count after which a helper drops
# its own word (usage.NO_ANSWER_READS, usage.POLL_SECONDS).
SCREEN_WORD_AGE = 900


def screen_word_path(home):
    """The file of the newest account read's word on the screen runtime's sign-in (SCREEN_WORD_FILE)."""
    return os.path.join(home, FLEET_DIR, SCREEN_WORD_FILE)


def leave_screen_word(home, ended, agent, at):
    """Leave the word of one answered account read of the screen runtime (usage.Collector.heard): whole or not at
    all, through a file of this process's own, because every helper of this user writes here and several read their
    accounts at the same moment after a sign-in (hub.signed_in_beside). A write that fails leaves the word as it was:
    the next read that gets an answer writes it again."""
    path = screen_word_path(home)
    own = f"{path}.{os.getpid()}.new"
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        with open(own, "w") as f:
            json.dump({"at": at, "ended": ended, "agent": agent}, f)
        os.replace(own, path)
    except OSError:
        pass


def screen_word(home, now):
    """What the newest account read of the screen runtime said, by any helper of this home's user: True, the provider
    ended the sign-in that this machine keeps; False, the account answered; None with no word of the last
    SCREEN_WORD_AGE seconds, or with a file that does not say."""
    try:
        with open(screen_word_path(home)) as f:
            said = json.load(f)
        ended, at = said["ended"], float(said["at"])
    except (OSError, ValueError, TypeError, KeyError):
        return None
    return ended if isinstance(ended, bool) and 0 <= now - at <= SCREEN_WORD_AGE else None


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


# ---------------------------------------------------------------- the key swap (VAULT.md, "The key swap")
#
# An API key that an agent reads can stay out of its sessions: the session holds a placeholder, and the vault of the
# agent's machine puts the key into the Authorization header, or into the one header that its form names, of an HTTPS
# request to the key's own site (vault.py). Here is what the hub and the helper share: which key can swap, and the
# variables of a session that holds one.

# The one form in which a key goes into a request: its catalog entry names it (`form`), and the first one holds for an
# entry that names none. Each of these is a word of the Authorization header with the key as the whole credential:
# bearer, token and key (`Key <key>`, as FAL takes it); basic-user: the key is the user name of Basic credentials;
# basic-password: it is the password. The other form is `header:<name>`: the key is the whole value of the one request
# header of that name (`header:xi-api-key`, as ElevenLabs takes it; design key-swap-two-more-forms.md, version 2).
KEY_FORMS = ("bearer", "token", "basic-user", "basic-password", "key")
KEY_HEADER_FORM = "header:"
KEY_HEADER_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
KEY_FORM_WORD = re.compile(r"[a-z][a-z0-9-]{0,39}")        # the shape of a word form, also of a later release's
# A header form's name holds one of these words, so that it is a credential's header: a deny list alone fails open
# (a site sends back many request headers, CORS's Access-Control-Request-Headers among them)
KEY_HEADER_WORDS = ("key", "token", "secret", "auth")
# Never a header form's name, though it can hold such a word: the scheme forms' own header, the proxy's dropped
# headers (vault.py SWAP_NOT_PASSED), and names that hold no credential
KEY_HEADER_NEVER = ("authorization", "proxy-authorization", "connection", "proxy-connection", "keep-alive", "upgrade")
KEY_HEADER_NEVER_PARTS = ("idempoten", "csrf", "xsrf", "authenticat")
KEY_SITE_HOST = re.compile(r"(?=.{1,240}$)(?![0-9.]+$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                           r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")


def key_form(form, full=False):
    """True for a form of a key (KEY_FORMS, or header:<name>), for any value and with no exception. full: the whole
    rule, which a write of a form and the vault's use keep (POST /ui/team/logins, the broker's read, the proxy): a
    header's name holds a word of KEY_HEADER_WORDS and is no name of KEY_HEADER_NEVER, no sec-* name and holds no part
    of KEY_HEADER_NEVER_PARTS. Without full, its shape only, which a read of stored data keeps (validate_team,
    key_swap), so a later release that refuses one more name, or that adds a word of the Authorization header (any
    plain word is a shape), never makes a stored team.json fail to load when this release runs it again. vault.py
    swap_form keeps the same rule in its own code."""
    if not isinstance(form, str):
        return False
    if form in KEY_FORMS or not full and KEY_FORM_WORD.fullmatch(form):
        return True
    name = form[len(KEY_HEADER_FORM):] if form.startswith(KEY_HEADER_FORM) else None
    if name is None or not KEY_HEADER_NAME.fullmatch(name):
        return False
    return not full or (any(w in name for w in KEY_HEADER_WORDS) and name not in KEY_HEADER_NEVER and
                        not name.startswith("sec-") and not any(p in name for p in KEY_HEADER_NEVER_PARTS))


def key_site(value):
    """The site of a key in its one written form, `https://host` or `https://host:port`, or None: an https address
    with no user part, whose host is a plain ASCII DNS name (no IP address) of at most 240 characters. The path of
    the address is not a part of it."""
    try:
        parts = urllib.parse.urlsplit(value) if isinstance(value, str) and len(value) <= 300 else None
        host, port = (parts.hostname or "", parts.port) if parts else ("", None)
    except ValueError:
        return None
    if not parts or parts.scheme != "https" or parts.username is not None or parts.password is not None:
        return None
    host = host[:-1] if host.endswith(".") else host
    if not KEY_SITE_HOST.fullmatch(host):
        return None
    return f"https://{host}" + (f":{port}" if port not in (None, 443) else "")


# The table of well-known services (the changed key swap, Part C; the owner's choices C29 and C30 of 14 November 2026):
# a key of such a service gets its site with no person who types it. A row has the site (the service's API host),
# the form in which the service's own SDK and CLI send the key, and the addresses that select the row: an API host by
# its exact name, with any path, and a web page only by its exact host and the exact path of the key page (a dashboard
# host holds other kinds of secret too, which must not get the row's site). A service is in the table only when its
# own SDK and CLI send the key in the Authorization header in the row's form, one API host takes the key, and that
# host sends no request's headers back. Each row names the sources that it was read from, and what was not checked.
# The central vault keeps a copy of the selecting addresses (vault.py KEY_TABLE_PLACES), and test_key_table holds the
# two equal. A row may change
# or go in a later release: an entry that the table made keeps its own site and form (validate_team does not compare
# them with the table), and only switch_key_site's "on" reads the row again.
KEY_TABLE = {
    # developers.openai.com/api/reference/overview (Bearer, the key pages) and openai-python
    # src/openai/lib/_client_auth.py ({"Authorization": f"Bearer {api_key}"}, base https://api.openai.com/v1), whose
    # package is also OpenAI's CLI; read 15 November 2026. Limits (VAULT.md): the realtime API is a websocket, and a
    # project with data residency uses its region's host (eu.api.openai.com and others). Not checked: an endpoint
    # that sends a request's headers back.
    "openai": {"site": "https://api.openai.com", "form": "bearer", "hosts": ("api.openai.com",),
               "pages": (("platform.openai.com", "/api-keys"), ("platform.openai.com", "/settings/organization/api-keys"))},
    # replicate.com/docs/reference/http (Bearer, the token page) and the clients replicate-python replicate/client.py,
    # replicate-javascript index.js and replicate-go client.go, which its CLI uses (each "Bearer", base
    # https://api.replicate.com/v1); read 15 November 2026. Limit (VAULT.md): the API also takes the word "Token",
    # which older clients and documents use, and the proxy takes a placeholder only in the row's form, so a request
    # that sends "Token" gets the proxy's refusal (403). Not checked: an endpoint that sends a request's headers back.
    "replicate": {"site": "https://api.replicate.com", "form": "bearer", "hosts": ("api.replicate.com",),
                  "pages": (("replicate.com", "/account/api-tokens"),)},
    # developers.cloudflare.com/fundamentals/api/get-started/create-token/ (Bearer, base api.cloudflare.com/client/v4),
    # cloudflare-typescript src/client.ts and Wrangler's workers-utils src/cfetch/index.ts addAuthorizationHeader (an
    # API token as "Bearer"); read 15 November 2026. No page selects it: the tokens page also shows the Global API Key,
    # which goes in X-Auth-Key. Limit (VAULT.md): an account in FedRAMP uses api.fed.cloudflare.com. Not checked: an
    # endpoint that sends a request's headers back.
    "cloudflare": {"site": "https://api.cloudflare.com", "form": "bearer", "hosts": ("api.cloudflare.com",),
                   "pages": ()},
}


def key_table_row(address, table=None):
    """The name of the one row of the table that this address selects, or None. The address is the one that the owner
    gave with a key (Add secret, a request's card, an import row). The exact rule, which vault.py key_table_row keeps
    too: an https address of at most 300 characters with no space and no user part; its host is a plain ASCII DNS name
    (KEY_SITE_HOST), in any case, with or without one dot at its end; its port is none or 443. Then an API host of a
    row selects it with any path, query and fragment, and a page selects it only when its host is the page's and its
    path is the page's path exactly, in its own case, with or without one slash at its end (a query and a fragment do
    not change the page). A longer name that starts with a row's host, a subdomain and another port select nothing,
    and so does an address that two rows would take."""
    table = KEY_TABLE if table is None else table
    if not isinstance(address, str) or len(address) > 300 or any(c.isspace() for c in address):
        return None
    try:
        parts = urllib.parse.urlsplit(address)
        host, port = parts.hostname or "", parts.port
    except ValueError:
        return None
    if parts.scheme != "https" or parts.username is not None or parts.password is not None or port not in (None, 443):
        return None
    host = host[:-1] if host.endswith(".") else host
    if not KEY_SITE_HOST.fullmatch(host):
        return None
    path = parts.path[:-1] if parts.path.endswith("/") and parts.path != "/" else parts.path
    found = {name for name, row in table.items()
             if host in row["hosts"] or any(host == page_host and path == page_path for page_host, page_path in row["pages"])}
    return found.pop() if len(found) == 1 else None


def key_swap(team, agent, ref):
    """(the site, the form) of the API key `ref` when a session of `agent` can hold a placeholder for it and not the
    key, or None. All of these hold, each one from team.json: the owner's own setting, except a site that the table of
    well-known services made (the entry's "table" mark), which the fleet manager switches off and on with
    switch_key_site, and an agent that persuades the fleet manager gets the key as a value:
    the agent reads the key (its grant is "read"); the key's catalog entry has a site (key_site); the agent's program
    has its own hosts in the table (RUNTIMES "own_hosts": it is proved with the proxy's variables); the key is not
    the key of a model account, which the program itself sends; no MCP server names the key, whose own program
    would need the proxy's variables; and the site is not a host of the program's own provider, which a session
    reaches without the proxy. Whether the agent's machine swaps keys is not asked here: its vault decides
    that by its own root-owned configuration (vault.py), and nothing that an agent's side reports."""
    team = team if isinstance(team, dict) else {}
    conf = (team.get("agents") or {}).get(agent) or {}
    entry = (team.get("logins") or {}).get(ref)
    if not isinstance(entry, dict) or entry.get("kind") != "api_key" or (conf.get("secrets") or {}).get(ref) != "read":
        return None
    site, form = key_site(entry.get("site")), entry.get("form", KEY_FORMS[0])
    own = runtime_fact(conf.get("runtime"), "own_hosts")
    if not site or not key_form(form) or not own:      # its shape only: the broker's read keeps the whole rule
        return None
    host = site.split("://", 1)[1].split(":")[0]
    if any(host == name or host.endswith("." + name) for name in own):
        return None             # NO_PROXY keeps this host out of the proxy: the program's own provider
    if any(isinstance(a, dict) and a.get("secret") == ref for a in (team.get("accounts") or {}).values()):
        return None
    name = entry.get("env")
    for server in (team.get("mcp") or {}).values():
        if isinstance(server, dict) and (server.get("key") == name or name in (server.get("env") or {}).values()):
            return None
    return site, form


def key_swap_env(proxy, bundle, sites, own_hosts=(), hub=None):
    """The variables of a session that holds one placeholder or more (VAULT.md, "The key swap"), which make its HTTPS
    programs use the vault's proxy and trust the CAs of its own keys' sites, and nothing else of the proxy.

    proxy: the proxy's address, http://127.0.0.1:<port>. bundle: a file with the system's CAs and the CAs of this
    session's sites. sites: a file with those CAs alone, for Node, which has its own list of public CAs. own_hosts:
    the hosts of the session's own program (RUNTIMES "own_hosts"), which never go through the proxy. hub: the hub's
    host, which does not either.

    Both spellings of each proxy variable, because wget reads only the small letters. Each host of NO_PROXY in two
    forms, `name` and `.name`: Claude Code obeys only the second one for the names under it, and Go and wget only the
    first one for the name itself (measured, 12 November 2026)."""
    direct = ["localhost", "127.0.0.1", "::1", ".localhost"] + ([hub] if hub else [])
    for host in own_hosts or ():
        direct += [host, "." + host]
    return {"HTTPS_PROXY": proxy, "https_proxy": proxy, "NO_PROXY": ",".join(direct), "no_proxy": ",".join(direct),
            "SSL_CERT_FILE": bundle, "CURL_CA_BUNDLE": bundle, "REQUESTS_CA_BUNDLE": bundle, "GIT_SSL_CAINFO": bundle,
            "NODE_EXTRA_CA_CERTS": sites, "NODE_USE_ENV_PROXY": "1"}


# ---------------------------------------------------------------- model accounts (the AI providers build spec, 3.1 to 3.3)
#
# An agent gets its model in one of three ways: a plan (a sign-in in the vendor's own program, as before), a key (an
# API key in the vault) or the owner's own model server (an address). The two last are an entry of team.json
# "accounts" with a `kind`, which the agent names with `account`. What follows is data: which program runs an account,
# what a provider is called inside that program, and the one call that says whether a key is good.
#
#   label     what the owner reads for the provider
#   runtime   the program of an account of this provider
#   program   the provider's name inside that program; None where the program has one provider only
#   makers    "one": the account may leave its model out, and the program takes its own default; "many": a seller of
#             several makers' models, whose account names its model
#   site      the key's site, for the vault's form
#   check     the call that a good key answers with 200 and a refused one with 400, 401 or 403: {method, url,
#             header: the header that carries the key, None for a bearer; body: a POST's JSON}. A key never goes
#             into an address. Not proved before a first owner's key: that each call answers 200 with a good one
ACCOUNT_KINDS = ("key", "server")
KEY_PROVIDERS = {
    "google": {"label": "Gemini", "runtime": "opencode", "program": "google", "makers": "one",
               "site": "https://generativelanguage.googleapis.com",
               "check": {"method": "GET", "url": "https://generativelanguage.googleapis.com/v1beta/models",
                         "header": "x-goog-api-key", "body": None}},
    "xai": {"label": "Grok", "runtime": "grok", "program": None, "makers": "one", "site": "https://api.x.ai",
            "check": {"method": "GET", "url": "https://api.x.ai/v1/models", "header": None, "body": None}},
    "opencode-go": {"label": "OpenCode Go", "runtime": "opencode", "program": "opencode-go", "makers": "many",
                    "site": "https://opencode.ai",
                    "check": {"method": "GET", "url": "https://opencode.ai/inference/go/v1/models", "header": None,
                              "body": None}},
    "openrouter": {"label": "OpenRouter", "runtime": "opencode", "program": "openrouter", "makers": "many",
                   "site": "https://openrouter.ai",
                   "check": {"method": "GET", "url": "https://openrouter.ai/api/v1/key", "header": None, "body": None}},
    # GET /v1/models there answers 200 to a wrong key, so it cannot check one; POST /api/me refuses it with 401
    "ollama-cloud": {"label": "Ollama Cloud", "runtime": "opencode", "program": "ollama-cloud", "makers": "many",
                     "site": "https://ollama.com",
                     "check": {"method": "POST", "url": "https://ollama.com/api/me", "header": None, "body": {}}},
}
# The owner's own model server: the provider "own" of a `server` account. The program's configuration names it `own`
# too, so each of its models is own/<name>.
OWN_SERVER = {"provider": "own", "runtime": "opencode", "program": "own", "makers": "many",
              # the name that the owner picked for it (his answer 12 of 14 November 2026); server.MODEL_SERVER_LABEL
              # is the same word, and a test holds the two equal
              "label": "Model server"}
REQUIRED_CONTEXT = 64000        # the tokens of context that a model server must take: the fleet's rules alone are
                                # about 17,000 at each start
ACCOUNT_FILE = "account-%s.json"    # in ~/.fleet: what the check of a model server kept for one agent
# The words of the setup check's `account` item. Proposed, not approved: no live fleet shows them before the apps
# offer an account kind, and the owner says yes to each one before a release shows it.
# The state of the `account` item in a check's first report while the item runs (the coordinator's decision D12):
# the hub waits for the report that follows (hub.CHECKING).
CHECKING = "checking"
NO_ANSWER = "This server does not answer."
OPEN_SERVER = "This server answers with no key, and more than one agent can reach it."
NO_TOOL_CALL = "No model here passed a tool call."
SMALL_CONTEXT = f"Its context is smaller than {REQUIRED_CONTEXT:,} tokens."
NO_KEY = "The vault gave no key for this account."
KEY_REFUSED = "The provider refused the key."
# The model that an account or its agent names is not in the program's list, or not in the model server's (the wave 1
# review, R6 part 2): the owner's approved sentence 9 for the setup page (round 2 of his answers to the pictures, 14
# November 2026: "Yes, both places"), filled with the provider's name that he picked, the model's name as he pasted
# it, and the agent's name as the apps show it (Lifecycle.account_item).
NOT_OFFERED = "{provider} has no model named {model}. Delete {agent}, then add it again with another model."
# A server whose models are named by their files' paths (llama.cpp without --alias): the check leaves such a name out
# (it can hold a home folder's user name), and says so. Proposed, not approved: for the owner's next round of pictures
# (decision D11 of the coordinator, 15 November 2026).
PATH_NAMES = ("This server names its models by their files' paths, and no session can start with such a name. Start "
              "it with a short name for each model (llama.cpp: --alias).")
# Decision D7 (15 November 2026): each detail of the account item has a stable code, and NOT_OFFERED its names, so
# that each app shows its own words in the device's language and the hub's text for a code that it does not know.
ACCOUNT_CODES = {NO_ANSWER: "no_answer", OPEN_SERVER: "open_server", NO_TOOL_CALL: "no_tool_call",
                 SMALL_CONTEXT: "small_context", NO_KEY: "no_key", KEY_REFUSED: "key_refused",
                 PATH_NAMES: "path_names", NOT_OFFERED: "not_offered"}
CHECK_CLIENT = "Founderizer-Fleet/1 (helper)"       # fleet.OUTSIDE_AGENT: an edge can refuse Python's default name
CHECK_MODELS = 8                # the models of a server's list that the check tries, in the list's order
# Step 4 measures a word's tokens and the chat template's own tokens with two short prompts of the word "seven", then
# sends a prompt that makes CONTEXT_AIM of REQUIRED_CONTEXT under that template. Measured on 14 November 2026: the
# template of gpt-oss-20b adds 67 tokens to a prompt of one message in llama.cpp, Ollama and LM Studio. A long prompt
# sized from one prompt alone falls short by about 31 tokens for each of the template's own, so a template of 108 or
# more failed the step on any server. CHECK_RATE bounds a word's tokens: a server that counts only the tokens that its
# cache did not hold gives far fewer, and no size of a long prompt follows from such a count.
CHECK_WORDS = (1000, 2000)
# Step 2's own routes of a server, called with no key at its host and port: a 200 whose JSON has the field fails it
OWN_ROUTES = (("/api/tags", "models"), ("/api/version", "version"), ("/version", "version"))
CONTEXT_AIM = 0.97
CHECK_RATE = (0.5, 4.0)
CHECK_BODY = 4 * 1024 * 1024    # the most of an answer that the check reads
PING = "Call the tool ping with the value 7."
PING_TOOL = {"type": "function", "function": {
    "name": "ping", "description": "Answers pong.",
    "parameters": {"type": "object", "properties": {"value": {"type": "integer"}}, "required": ["value"]}}}


def model_account(team, conf):
    """What team.json says of the model account of one agent, or None for an agent whose account has no kind (a
    plan's sign-in, as before): {id, kind, provider, runtime, program, makers, title, address, model, secret, env,
    check}. runtime is None for a provider that this release does not know, and no session starts on such an
    account. env is the variable name of the secret's own entry of team.json "logins", by which the vault gives its
    value."""
    accounts, ident = (team or {}).get("accounts"), (conf or {}).get("account")
    entry = accounts.get(ident) if isinstance(accounts, dict) and isinstance(ident, str) else None
    if not isinstance(entry, dict) or entry.get("kind") not in ACCOUNT_KINDS:
        return None
    kind, provider = entry["kind"], entry.get("provider")
    known = (OWN_SERVER if provider == OWN_SERVER["provider"] else None) if kind == "server" else \
        KEY_PROVIDERS.get(provider) if isinstance(provider, str) else None
    known = known or {}
    secret = entry.get("secret") if isinstance(entry.get("secret"), str) and entry["secret"] else None
    logins = team.get("logins") if isinstance(team.get("logins"), dict) else {}
    login = logins.get(secret) if secret and isinstance(logins.get(secret), dict) else {}
    name = login.get("env") if login.get("kind") == "api_key" else None
    model, address = entry.get("model"), entry.get("address")
    return {"id": ident, "kind": kind, "provider": provider, "runtime": known.get("runtime"),
            "program": known.get("program"), "makers": known.get("makers"),
            "title": entry.get("title") if isinstance(entry.get("title"), str) else None,
            "address": address.rstrip("/") if kind == "server" and isinstance(address, str) else None,
            "model": model if isinstance(model, str) and MODEL_NAME.fullmatch(model) else None,
            "secret": secret, "env": name if isinstance(name, str) and KEY_ENV.fullmatch(name) else None,
            "check": known.get("check")}


def hub_answered(code):
    """True when the hub answered a report itself: a 2xx or a 4xx. No answer (None) and a 5xx are a hub that did not
    take it, as while it starts again: a finished check then waits for the next report (Lifecycle.report). After a
    4xx no report carries that check again, so the hub never gets a report that it refused again and again."""
    return isinstance(code, int) and code < 500


def account_path(home, agent):
    return os.path.join(home or os.path.expanduser("~"), FLEET_DIR, ACCOUNT_FILE % agent)


def kept_account(home, agent, account):
    """What the setup check kept for this agent's model server, {account, address, key, models, model, at}, when it
    is of this account as team.json has it now: the same id, address and key or no key. Else None. The hub writes
    no team.json for the model that passed, because a write of an account would make the check of each agent old.

    Without a file of this agent's own name, the newest file of another name in the same ~/.fleet that is of this
    account stands: a result is the server's, not the agent's, and so the kept model follows a rename of the agent
    (the build plan, section 3.6, part b), and an agent of the same OS user on the same account starts with it."""
    own = account_path(home, agent)

    def changed(path):
        try:
            return os.stat(path).st_mtime
        except OSError:
            return 0
    others = glob.glob(os.path.join(glob.escape(os.path.dirname(own)), ACCOUNT_FILE % "*"))
    paths = [own] + sorted((p for p in others if p != own), key=changed, reverse=True)
    for path in paths[:64]:
        try:
            with open(path, "rb") as f:
                kept = json.loads(f.read(1 << 20))
        except (OSError, ValueError):
            continue
        if isinstance(kept, dict) and account and kept.get("account") == account["id"] and \
                kept.get("address") == account["address"] and kept.get("key") is bool(account["secret"]) and \
                isinstance(kept.get("model"), str) and MODEL_NAME.fullmatch(kept["model"]) and \
                isinstance(kept.get("models"), list):
            return kept
    return None


def forget_account(home, account, keep=None, model=None):
    """Remove each kept result of this account in this ~/.fleet, of any agent's name (kept_account): but the file
    `keep`, and with `model` only a result of that model."""
    folder = os.path.dirname(account_path(home, "x"))
    for path in glob.glob(os.path.join(glob.escape(folder), ACCOUNT_FILE % "*")):
        if keep and os.path.abspath(path) == os.path.abspath(keep):
            continue
        try:
            with open(path, "rb") as f:
                kept = json.loads(f.read(1 << 20))
        except (OSError, ValueError):
            continue
        if isinstance(kept, dict) and kept.get("account") == account["id"] and (model is None or
                                                                              kept.get("model") == model):
            with contextlib.suppress(OSError):
                os.remove(path)


def program_account(account, runtime, model=None, models=()):
    """An account as the adapter of its program takes it for the session's files (acp_programs.Program.files):
    {provider, the provider's name in the program; model; models, the names of a model server's own models; key_env,
    the variable that holds the key, None for a server with no key; address, title, context}."""
    if not account:
        return None
    return {"provider": account["program"], "model": model, "models": list(models),
            "key_env": runtime_fact(runtime, "key_env") if account["secret"] else None,
            "address": account["address"], "title": account["title"], "context": REQUIRED_CONTEXT}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """The check follows no redirect: a typed address is called as it is typed, and a key goes nowhere else."""

    def redirect_request(self, *args, **kwargs):
        return None


def model_call(method, url, key=None, body=None, timeout=30, header=None):
    """(status, the answer's JSON or None) of one fixed call of the setup check, or (None, None) for no answer in
    time. The key goes as a bearer, or in `header`; no proxy of the environment and no redirect is followed."""
    headers = {"User-Agent": CHECK_CLIENT, "Accept": "application/json"}
    if key:
        headers.update({header: key} if header else {"Authorization": f"Bearer {key}"})
    data = None
    if body is not None:
        data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(url, data=data, headers=headers, method=method), timeout=timeout) as r:
            status, raw = r.status, r.read(CHECK_BODY + 1)
    except urllib.error.HTTPError as e:
        return e.code, None
    except (OSError, ValueError, http.client.HTTPException):
        return None, None
    try:
        return status, json.loads(raw) if len(raw) <= CHECK_BODY else None
    except ValueError:
        return status, None


def listed_models(answer):
    """Every model id of a server's list, GET <address>/models in the OpenAI shape, in its order."""
    rows = answer.get("data") if isinstance(answer, dict) else None
    return [row.get("id") for row in rows if isinstance(row, dict) and isinstance(row.get("id"), str)] \
        if isinstance(rows, list) else []


def model_path(name):
    """True for a model's name that is a file's path, as llama.cpp names a model without --alias: it can hold a home
    folder's user name, and a session can start with none (measured on 14 November 2026: 187 characters)."""
    return name.startswith(("/", "~", "./", "../")) or "\\" in name or bool(re.match(r"[A-Za-z]:[\\/]", name)) or \
        "/" in name and name.lower().endswith(".gguf")


def cloud_model(name):
    """True for a model of Ollama's cloud, whose tag ends in "cloud" (gpt-oss:120b-cloud, gemma4:cloud): a signed-in
    Ollama runs it on ollama.com. The owner's own model server never sends a task to a third party's cloud
    (decision D9 of 15 November 2026). Not proved live: it needs an Ollama sign-in."""
    return ":" in name and name.rpartition(":")[2].lower().endswith("cloud")


def cloud_rows(answer):
    """The names of the models of Ollama's cloud in an answer of GET /api/tags: each row with remote_host."""
    rows = answer.get("models") if isinstance(answer, dict) else None
    return {row.get(field) for row in rows if isinstance(row, dict) and row.get("remote_host")
            for field in ("name", "model") if isinstance(row.get(field), str)} if isinstance(rows, list) else set()


def server_models(answer):
    """The model names of a server's list that a session can start with, in its order: a name that MODEL_NAME takes
    as own/<name>, and neither a file's path nor a model of Ollama's cloud."""
    return [name for name in listed_models(answer) if MODEL_NAME.fullmatch("own/" + name) and not model_path(name)
            and not cloud_model(name)][:64]


def pinged(answer):
    """True when a chat answer has exactly one tool call, of `ping`, whose arguments parse to {"value": 7}."""
    try:
        calls = answer["choices"][0]["message"].get("tool_calls") or []
        if len(calls) != 1 or calls[0]["function"]["name"] != "ping":
            return False
        given = calls[0]["function"]["arguments"]
        return (json.loads(given) if isinstance(given, str) else given) == {"value": 7}
    except (KeyError, IndexError, TypeError, ValueError, AttributeError):
        return False


def prompt_tokens(answer):
    value = (answer.get("usage") or {}).get("prompt_tokens") if isinstance(answer, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def check_server(account, key, kept=None, call=model_call, clock=time.time, wanted=None):
    """The setup check of the owner's own model server, in its order; the first failure ends it. Returns (state,
    detail, what to keep or None). The helper sends only fixed prompts and reports only the fixed words and a model's
    name.

      1. GET <address>/models, with the key if the account has one: the server answers with its models. A model that
         the agent or the account names (wanted, own/<name>) must be one of them (the wave 1 review, R6 part 2).
      2. With a key: the same call with no key must answer 401 or 403, and the server's own routes at its host and
         port (Ollama's /api/tags and /api/version) must not answer with their JSON: a proxy that guards /v1 only
         would leave them open to each agent that can reach the address.
      3. One tool call for each model of the list, 8 at most, until one passes; for the named model only, when there
         is one, because the sessions start with it.
      4. For that model: its context takes REQUIRED_CONTEXT tokens (CHECK_WORDS, CONTEXT_AIM). A server that cuts a
         long prompt fails here.

    Steps 3 and 4 run again only when the account, the address, the key, the model list or the named model differ
    from what was kept (kept_account); else the kept result stands."""
    address = account["address"]
    status, answer = call("GET", f"{address}/models", key=key, timeout=30)
    models = server_models(answer) if status == 200 else []
    if status != 200 or not isinstance(answer, dict):
        return "failed", NO_ANSWER, None
    parts = urllib.parse.urlsplit(address)
    base = f"{parts.scheme}://{parts.netloc}"
    # Ollama marks a model of its cloud itself: a row of /api/tags with remote_host (decision D19, the review's T4). A
    # copy under a name of the owner's own keeps it, where the name's tag says nothing. Read with the key, as /v1;
    # a server behind a proxy that passes /v1 only keeps the name's test of server_models alone.
    status, tags = call("GET", f"{base}/api/tags", key=key, timeout=30)
    remote = cloud_rows(tags) if status == 200 else set()
    models = [name for name in models if name not in remote]
    named = (wanted[len("own/"):] if wanted.startswith("own/") else wanted) if wanted else None
    if named is not None and named not in models:
        return "failed", NOT_OFFERED, None      # Lifecycle.account_item fills its names
    if key:
        status, _ = call("GET", f"{address}/models", timeout=30)
        if status not in (401, 403):
            return "failed", OPEN_SERVER, None
        # The server's own routes, at its host and port, with no key: Ollama's /api/tags and /api/version, and
        # vLLM's /version, which answers each caller while its --api-key guards /v1 only, as /invocations (inference)
        # does, and /pause and /update_weights in its dev mode (decision D16, measured on 14 and 15 November 2026)
        for route, field in OWN_ROUTES:
            status, said = call("GET", f"{base}{route}", timeout=30)
            if status == 200 and isinstance(said, dict) and field in said:
                return "failed", OPEN_SERVER, None
    if kept and kept.get("models") == models and (named is None or kept.get("model") == "own/" + named):
        return "ok", kept["model"], None
    if not models and any(model_path(name) for name in listed_models(answer)):
        return "failed", PATH_NAMES, None
    passed = None
    for name in [named] if named is not None else models[:CHECK_MODELS]:
        status, answer = call("POST", f"{address}/chat/completions", key=key, timeout=120, body={
            "model": name, "messages": [{"role": "user", "content": PING}], "tools": [PING_TOOL], "stream": False})
        if status == 200 and pinged(answer):
            passed = name
            break
    if passed is None:
        return "failed", NO_TOOL_CALL, None
    ask = lambda words: call("POST", f"{address}/chat/completions", key=key, timeout=600, body={
        "model": passed, "messages": [{"role": "user", "content": " ".join(["seven"] * words)}], "max_tokens": 1,
        "stream": False})
    counts = []
    for words in CHECK_WORDS:
        status, answer = ask(words)
        counts.append(prompt_tokens(answer) if status == 200 else None)
    if not all(counts):
        return "failed", SMALL_CONTEXT, None
    rate = (counts[1] - counts[0]) / (CHECK_WORDS[1] - CHECK_WORDS[0])
    if not CHECK_RATE[0] <= rate <= CHECK_RATE[1]:
        return "failed", SMALL_CONTEXT, None
    template = max(0, counts[0] - rate * CHECK_WORDS[0])
    status, answer = ask(math.ceil((CONTEXT_AIM * REQUIRED_CONTEXT - template) / rate))
    taken = prompt_tokens(answer) if status == 200 else None
    if not taken or taken < 0.95 * REQUIRED_CONTEXT:
        return "failed", SMALL_CONTEXT, None
    model = "own/" + passed
    return "ok", model, {"account": account["id"], "address": address, "key": bool(account["secret"]),
                         "models": models, "model": model, "at": clock()}


def check_key(account, key, call=model_call):
    """The setup check of a key account: the provider's own call answers 200 with the key. No model is called."""
    check = account.get("check")
    if not key:
        return "failed", NO_KEY
    if not check:
        return "failed", KEY_REFUSED
    status, _ = call(check["method"], check["url"], key=key, body=check.get("body"), timeout=30,
                     header=check.get("header"))
    return ("ok", "") if status == 200 else ("failed", KEY_REFUSED)


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


# ---- the agents' browsers on a Linux server (the owner's "Every agent with shell" of 17 November 2026; build plan 04,
# D6, D8 and D11 to D15). The server service reads the room for them and their parts at each reading; the hub counts a
# server's browser places from the room, and the owner's Mac installs and removes the parts as root (the app's
# ServerBrowser.swift), by the contract of the devops repository's scripts/fleet-browser/README.md.
USER_SLICE = "/sys/fs/cgroup/user.slice"
ROOM_KEYS = ("swap_total", "memory_max", "swap_max", "swap_current", "swap_peak", "oom", "swap_fail", "full_us")
BROWSER_SYSTEMS = ("24.04", "26.04")         # the x86 Ubuntu releases that probe 2 proved (D8)
BROWSER_PACKAGES = ("google-chrome-stable", "xvfb", "xauth", "openbox", "x11vnc", "ffmpeg", "nftables",
                    "fonts-noto-core", "fonts-noto-color-emoji", "libatomic1")
BROWSER_PARTS = {"unit": "/etc/systemd/system/fleet-browser-ports.service",
                 "dropin": "/etc/systemd/system/nftables.service.d/fleet-browser.conf",     # the table after nftables
                 "default": "/etc/default/google-chrome",
                 "origin": "/etc/apt/apt.conf.d/53fleet-google-chrome",
                 "fixed": "/etc/opt/chrome/policies/managed/fleet-fixed.json",
                 "policy": "/etc/opt/chrome/policies/managed/fleet-providers.json",
                 "ports": "/etc/fleet-browser/ports", "table": "/etc/fleet-browser/table.nft",
                 "source": "/etc/apt/sources.list.d/google-chrome.sources", "key": "/usr/share/keyrings/google-chrome.gpg"}
BROWSER_PORTS_UNIT = "fleet-browser-ports.service"   # a system unit: root's table
BROWSER_PORTS_LOCK = "/etc/fleet-browser/lock"   # root's: the Mac's step and the root helper change the ports under it
BROWSER_RECORD = "/var/lib/fleet-browser/added"         # root's: what the Mac's step added, which its removal takes away
BROWSER_PROOF = "/var/lib/fleet-browser/proof/state"    # the server service's: the live proof, which each agent reads
BROWSER_LOCK = "fleet-browser/port.lock"     # in an agent's runtime folder: its proof listener's and its browser's start
BROWSER_AGENT = re.compile(r"fleet-[a-z][a-z0-9-]{1,25}")
BROWSER_BROKER = "fleet-vault"               # the vault's broker, which may reach each DevTools port
BROWSER_PORT = re.compile(r"[1-9][0-9]{3}")


def room_reading(platform_name=sys.platform, root=""):
    """What the hub needs to count a Linux server's browser places (plan 04, D6), as the kernel says it now: the
    server's swap (`SwapTotal`), and of `user.slice`, where every agent runs, its limits of memory and of swap (None for
    the kernel's "max"), its swap in use and at its peak, the count of its ends at its own limit (`oom` of
    memory.events.local), of a full swap (`fail` of memory.swap.events), and the microseconds in which all its processes
    waited for memory at once (`full` of memory.pressure). The counts start at 0 at each boot, which `os.boot` names. A
    part that cannot be read is None; None on a Mac."""
    if platform_name == "darwin":
        return None
    room = dict.fromkeys(ROOM_KEYS)

    def text(path):
        try:
            with open(root + path, encoding="ascii") as f:
                return f.read(65536)
        except (OSError, UnicodeDecodeError):
            return None

    def number(word):
        return int(word) if word is not None and re.fullmatch(r"[0-9]{1,19}", word) else None

    swap = re.search(r"(?m)^SwapTotal:\s+([0-9]{1,16}) kB$", text("/proc/meminfo") or "")
    room["swap_total"] = int(swap.group(1)) * 1024 if swap else None
    for key, name in (("memory_max", "memory.max"), ("swap_max", "memory.swap.max"),
                      ("swap_current", "memory.swap.current"), ("swap_peak", "memory.swap.peak")):
        room[key] = number((text(f"{USER_SLICE}/{name}") or "").strip())
    for key, name, word in (("oom", "memory.events.local", "oom"), ("swap_fail", "memory.swap.events", "fail")):
        found = re.search(rf"(?m)^{word} ([0-9]+)$", text(f"{USER_SLICE}/{name}") or "")
        room[key] = number(found.group(1)) if found else None
    full = re.search(r"(?m)^full .* total=([0-9]+)$", text(f"{USER_SLICE}/memory.pressure") or "")
    room["full_us"] = number(full.group(1)) if full else None
    return room


def browser_port_rows(rows):
    """The agents' ports as the contract gives them ([{user, devtools, screen}], in their order), or None: an agent's
    own user (never the broker's), a DevTools port of 9300 to 9399 and a screen-sharing port of 5910 to 5999, each
    given once, 99 rows at most."""
    if not isinstance(rows, list) or len(rows) > 99:
        return None
    seen, out = set(), []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"user", "devtools", "screen"}:
            return None
        user, devtools, screen = row["user"], row["devtools"], row["screen"]
        if not (isinstance(user, str) and BROWSER_AGENT.fullmatch(user) and user != BROWSER_BROKER) or not all(
                type(p) is int for p in (devtools, screen)) or not 9300 <= devtools <= 9399 or \
                not 5910 <= screen <= 5999 or {user, devtools, screen} & seen:
            return None
        seen |= {user, devtools, screen}
        out.append({"user": user, "devtools": devtools, "screen": screen})
    return out


def browser_ports(text):
    """The rows of `/etc/fleet-browser/ports` (browser_port_rows), or None for a file that is not of the contract: one
    line `<user> <DevTools port> <screen-sharing port>` for each agent, each ending with a new line, and nothing else."""
    if not isinstance(text, str) or (text and not text.endswith("\n")):
        return None
    rows = []
    for line in text[:-1].split("\n") if text else []:
        parts = line.split(" ")
        if len(parts) != 3 or not all(BROWSER_PORT.fullmatch(p) for p in parts[1:]):
            return None
        rows.append({"user": parts[0], "devtools": int(parts[1]), "screen": int(parts[2])})
    return browser_port_rows(rows)



BROWSER_PROOF_AGE = 900         # seconds: a live proof older than this proves nothing (two readings, and a late one)
LINUX_BROWSER = ("claude", "codex")         # D4: the runtimes whose sessions get Google's DevTools MCP server on Linux


def linux_browser_refusal(conf):
    """Why this agent (its entry of team.json) gets no browser on a Linux server (build plan 04, D4), or None. Version 1
    runs it in a terminal session of Claude Code or Codex with its shell: an agent whose Shell box is off has closed
    sessions (D2), another runtime gets it only after a live check of its own, and Codex's sandboxed app-server start
    runs each task in screen_runner.py (app_server_task), which has no browser of its own on Linux yet. The hub and the
    helper use this one rule."""
    if conf.get("role") in ("worker", "lead") and "shell" not in (conf.get("can") or []):
        return "a browser on a Linux server needs the agent's Shell box, and its Shell box is off"
    if conf.get("runtime") not in LINUX_BROWSER:
        return ("a browser on a Linux server runs in a Claude Code or Codex session in this version, and this agent "
                f"runs on {runtime_fact(conf.get('runtime'), 'label', conf.get('runtime'))}")
    if app_server_task(conf, "browser"):
        return ("this agent's start policy (app-server) runs its tasks in Codex's sandbox, which has no browser of its "
                "own on Linux yet")
    return None


def browser_port(user=None, ports=BROWSER_PARTS["ports"]):
    """This OS user's DevTools port by the root-owned ports file (D11), or None."""
    try:
        user = user or pwd.getpwuid(os.getuid()).pw_name
        with open(ports, encoding="ascii") as f:
            rows = browser_ports(f.read(1 << 20))
    except (OSError, KeyError, UnicodeDecodeError):
        return None
    return next((row["devtools"] for row in rows or [] if row["user"] == user), None)


def screen_port(user=None, ports=BROWSER_PARTS["ports"]):
    """This OS user's screen-sharing port by the root-owned ports file (D11), or None (build plan 04, S6)."""
    try:
        user = user or pwd.getpwuid(os.getuid()).pw_name
        with open(ports, encoding="ascii") as f:
            rows = browser_ports(f.read(1 << 20))
    except (OSError, KeyError, UnicodeDecodeError):
        return None
    return next((row["screen"] for row in rows or [] if row["user"] == user), None)


def browser_proof_holds(user, ports=BROWSER_PARTS["ports"], proof=BROWSER_PROOF, now=None):
    """True where the server service's live proof of the port rule says `holds` for this user, for the ports file as
    it is now (its SHA-256 is the table's version), from a reading of the last BROWSER_PROOF_AGE seconds (D11)."""
    try:
        with open(ports, "rb") as f:
            version = hashlib.sha256(f.read(1 << 20)).hexdigest()
        with open(proof, encoding="ascii") as f:
            lines = f.read(1 << 16).splitlines()
        age = (now or time.time()) - os.path.getmtime(proof)
    except (OSError, UnicodeDecodeError):
        return False
    return bool(lines) and lines[0] == version and f"{user} holds" in lines[1:] and -60 <= age <= BROWSER_PROOF_AGE


def browser_item(conf, user, reading, port=None, proof=None):
    """The setup check's item of the Browser box on a Linux server (build plan 04, S3): ("capability", "browser",
    state, detail), ok where a browser task of this agent can start now by its helper's own rule
    (fleet.Helper.browser_start): a session that gets the browser (linux_browser_refusal), the server's browser parts
    in place (`reading`, browser_reading), a port of this agent's own user, and the server service's current live proof
    `holds` for it. Else failed. The owner reads its detail behind the item's mark, so it has one sentence of two forms
    and three reasons (his yes to them waits); the agents read the exact cause in the refusals of their browser
    tasks."""
    port, proof = port or browser_port, proof or browser_proof_holds

    def failed(reason):
        return "capability", "browser", "failed", BROWSER_NOT_YET.format(reason=reason)
    if linux_browser_refusal(conf):
        return failed(BROWSER_NEEDS)
    if (reading or {}).get("state") == "unsupported":
        return failed(BROWSER_SYSTEMS_ONLY)
    if (reading or {}).get("state") != "ready" or not port(user) or not proof(user):
        return failed(BROWSER_PARTS_NOT_READY)
    return "capability", "browser", "ok", BROWSER_READY


BROWSER_READY = "This agent's own Chrome is ready on this server."
BROWSER_NOT_YET = "This agent's own Chrome cannot start on this server yet: {reason}."
BROWSER_NEEDS = "it needs Claude Code or Codex, with its Shell box on"
BROWSER_SYSTEMS_ONLY = "only a server with x86 Ubuntu 24.04 or 26.04 runs one"
BROWSER_PARTS_NOT_READY = "its browser parts there are not ready yet"

def browser_reading(platform_name=sys.platform, root="", run=None, machine=lambda: os.uname().machine,
                    broker=lambda: pwd.getpwnam(BROWSER_BROKER).pw_uid):
    """The agents' browser parts on this Linux server, as its service reads them with no root (plan 04, S1): `state`
    is `unsupported` on a system that version 1 does not take (x86 Ubuntu 24.04 and 26.04 only, D8), `missing` while a
    part is not in place or the table's unit is not active, else `ready` (the service's live proof can make that
    `table_missing`: server.Service.browser_proof). Then Chrome's version, the packages that are not installed, the
    SHA-256 of each file of the parts (None where it is not there, and for the drop-in also where systemd does not run
    its lines), the word of the table's unit, the agents' ports,
    whether the Mac's step keeps a record of what it added, and the uid of the vault's broker. None on a Mac."""
    if platform_name == "darwin":
        return None
    run = run or _run
    try:
        with open(root + "/etc/os-release", encoding="utf-8", errors="replace") as f:
            release = dict(re.findall(r'(?m)^([A-Z_]+)="?([^"\n]*)"?$', f.read(65536)))
    except OSError:
        release = {}
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") not in BROWSER_SYSTEMS or \
            machine() not in ("x86_64", "amd64"):
        return {"state": "unsupported"}
    files = {}
    for key, path in BROWSER_PARTS.items():
        try:
            if os.path.isfile(root + path) and not os.path.islink(root + path):
                with open(root + path, "rb") as f:
                    files[key] = hashlib.sha256(f.read(1 << 20)).hexdigest()
            else:
                files[key] = None
        except OSError:
            files[key] = None
    _, out, _ = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n",
                     *BROWSER_PACKAGES])
    installed = {}
    for line in out.splitlines():
        # installed (`ii`, and `hi` for a package on hold), of this server's own architecture or of all
        parts = line.split("\t")
        if len(parts) == 4 and parts[2] in ("amd64", "all") and parts[3][1:2] == "i" and \
                re.fullmatch(r"[0-9A-Za-z.+:~-]{1,60}", parts[1]):
            installed[parts[0]] = parts[1]
    if files["dropin"]:
        # The drop-in counts only where systemd runs its three lines: a later drop-in that empties a list, or a
        # drop-in that systemd has not read again yet, leaves the file in place and the table gone after the next
        # event of nftables.service (a review of 17 November 2026). Any user reads these properties.
        code, out, _ = run(["systemctl", "show", "nftables.service", "-p", "NeedDaemonReload", "-p", "ExecStartPost",
                            "-p", "ExecReload", "-p", "ExecStopPost"])
        said = {}       # systemd gives one line for each command of a list: another part's drop-in adds lines too
        for line in out.splitlines():
            key, _, value = line.partition("=")
            said.setdefault(key, []).append(value)
        if code != 0 or said.get("NeedDaemonReload") != ["no"] or not all(
                any(BROWSER_PARTS["table"] in value for value in said.get(key, []))
                for key in ("ExecStartPost", "ExecReload", "ExecStopPost")):
            files["dropin"] = None
    code, out, _ = run(["systemctl", "is-active", BROWSER_PORTS_UNIT])
    unit = out.strip() if re.fullmatch(r"[a-z-]{1,20}", out.strip()) else None
    ports = []
    if files["ports"]:
        try:
            with open(root + BROWSER_PARTS["ports"], encoding="ascii") as f:
                ports = browser_ports(f.read(1 << 20))
        except (OSError, UnicodeDecodeError):
            ports = None
    try:
        broker_uid = broker()
    except (KeyError, OSError):
        broker_uid = None
    missing = [p for p in BROWSER_PACKAGES if p not in installed]
    state = "missing" if missing or None in files.values() or unit != "active" or ports is None else "ready"
    return {"state": state, "chrome": installed.get("google-chrome-stable"), "missing": missing, "files": files,
            "unit": unit, "ports": ports or [], "added": os.path.isfile(root + BROWSER_RECORD),
            "broker": broker_uid}


def browser_connect(port, timeout=2.0, connect=socket.create_connection):
    """This user's try of 127.0.0.1:<port> for the live proof (plan 04, D11): `connected`, `refused` (a reset), or
    `silent` (no answer in time, or another error)."""
    try:
        connect(("127.0.0.1", port), timeout=timeout).close()
        return "connected"
    except ConnectionRefusedError:
        return "refused"
    except OSError:
        return "silent"


def browser_listening(port, uid, opener=open):
    """True where a socket of this uid (the agent whose port it is) listens on 127.0.0.1:<port> or 0.0.0.0:<port>, by
    the kernel's own list (any user reads /proc/net/tcp): a try of 127.0.0.1 reaches it. A socket of another user does
    not count, so that no agent can make another agent's proof hold; an IPv6 socket does not count either, because the
    list does not say whether it takes IPv4 too."""
    wanted = {f"0100007F:{port:04X}", f"00000000:{port:04X}"}
    try:
        with opener("/proc/net/tcp", encoding="ascii") as f:
            next(f, None)                   # its head line
            for line in f:                  # the whole list, a line at a time: in a part of it, an agent with many
                row = line.split()          # sockets could push another agent's listener out (a review, 17 Nov 2026)
                if len(row) > 7 and row[1] in wanted and row[3] == "0A" and row[7] == str(uid):
                    return True
    except (OSError, UnicodeDecodeError):
        return False
    return False


def browser_verdict(said, listening):
    """The live proof of one port (plan 04, D11): `open` where this user's try connected (the port rule is not loaded),
    `holds` where it was reset while the kernel listed a socket that listens there, else `unread`. A reset alone proves
    nothing: the kernel resets a try of a port where nothing listens too, and the proof's own listener runs as the
    agent, which can end it."""
    if said == "connected":
        return "open"
    return "holds" if said == "refused" and listening else "unread"


# A host of a site that a clear names: a DNS name or an IPv4 address, in lower case (plan 04, S2 and S5).
BROWSER_HOST = re.compile(r"[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*")


def browser_clear_valid(extra):
    """**The clear of a site login's grant end**, or None where it is not one (plan 04: S5's hub part checks its event
    `browser_clear` with this rule before it sends it; the agent's helper runs it, S2).
    - `origins`: 1 to 50 addresses of the sign-in's top-level pages, the login's own among them. Each becomes its
      origin `scheme://host[:port]`: http or https, no path, query or fragment, no default port, a lower-case host.
    - `cookies` (none where it is missing or null): at most 200 cookies that the sign-in made on embedded domains,
      each `{name, domain}` as Chrome lists it (a domain cookie's domain begins with a dot), with `path` and
      `partitionKey` ({topLevelSite}) where the record has them.
    A host with a dot at its end, or one that is not ASCII (not punycode), makes no clear."""
    if not isinstance(extra, dict):
        return None
    origins, cookies = extra.get("origins"), extra.get("cookies")
    cookies = [] if cookies is None else cookies
    if not (isinstance(origins, list) and 0 < len(origins) <= 50 and isinstance(cookies, list) and len(cookies) <= 200):
        return None
    clear = {"origins": [], "cookies": []}
    for origin in origins:
        try:
            parts = urllib.parse.urlsplit(origin) if isinstance(origin, str) and len(origin) <= 4096 else None
            port, host = (parts.port, parts.hostname) if parts else (None, None)
        except ValueError:
            return None
        scheme = parts.scheme.lower() if parts else ""
        if scheme not in ("http", "https") or not host or not BROWSER_HOST.fullmatch(host) or \
                parts.username is not None or parts.password is not None:
            return None
        one = f"{scheme}://{host}" + (f":{port}" if port and port != {"http": 80, "https": 443}[scheme] else "")
        if one not in clear["origins"]:
            clear["origins"].append(one)
    for cookie in cookies:
        if not isinstance(cookie, dict):
            return None
        name, domain, path, key = cookie.get("name"), cookie.get("domain"), cookie.get("path"), cookie.get("partitionKey")
        domain = domain.lower() if isinstance(domain, str) else None
        if not (isinstance(name, str) and 0 < len(name) <= 4096 and domain and BROWSER_HOST.fullmatch(domain.removeprefix("."))
                and (path is None or isinstance(path, str) and path.startswith("/") and len(path) <= 4096)
                and (key is None or isinstance(key, dict) and isinstance(key.get("topLevelSite"), str)
                     and 0 < len(key["topLevelSite"]) <= 4096)):
            return None
        clear["cookies"].append(dict({"name": name, "domain": domain}, **({"path": path} if path is not None else {}),
                                     **({"partitionKey": {"topLevelSite": key["topLevelSite"]}} if key else {})))
    return clear


# The event `forget` of the hub's person_remove (the lane "What a removal still keeps", step 2; the owner's "Yes, as
# recommended" of 19 November 2026): what a removed person left on one agent's machine. One rule for the hub, which
# checks each event with it before it sends it, and for the helper, which acts only on what passes it.
FORGET_MOST = 200       # the ids of one event; the hub sends more of them in more events
# a session id, as helpers make them
SESSION_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def forget_valid(extra):
    """**What a removed person's event `forget` names**, or None where it is not such an event, and then nothing of it
    is done (fleet.Helper.forget):
    - `conversations`: [[id, since], ...]: each conversation of the person with this agent, whose window is C-<id>,
      and the time when it began on the hub's clock: the transcripts of its closed sessions are the files of its
      folder's project from then on, so a conversation with the same number in an older database keeps its own;
    - `tasks`: the numbers of the person's tasks of this agent, whose windows are T-<id>;
    - `sessions`: the ids of the runtime sessions of those tasks and windows (a UUID in lower case, as the helper
      makes it at each start), whose files go.
    A number is an int (no bool) from 1 to 12 digits, a time a number from 0, and no id comes twice; at most
    FORGET_MOST ids in all. A key that is missing is an empty list, and another key is not read."""
    if not isinstance(extra, dict):
        return None
    lists = [extra.get(key, []) for key in ("conversations", "tasks", "sessions")]
    if not all(isinstance(one, list) for one in lists) or sum(map(len, lists)) > FORGET_MOST:
        return None
    pairs, tasks, sessions = lists

    def number(value):
        return isinstance(value, int) and not isinstance(value, bool) and 0 < value < 10 ** 12

    if not (all(isinstance(p, list) and len(p) == 2 and number(p[0]) and isinstance(p[1], (int, float))
                and not isinstance(p[1], bool) and 0 <= p[1] < float("inf") for p in pairs)
            and all(number(t) for t in tasks)
            and all(isinstance(s, str) and SESSION_ID.fullmatch(s) for s in sessions)):
        return None
    conversations = {p[0]: float(p[1]) for p in pairs}
    if len(conversations) < len(pairs) or len(set(tasks)) < len(tasks) or len(set(sessions)) < len(sessions):
        return None
    return {"conversations": conversations, "tasks": list(tasks), "sessions": list(sessions)}


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
    what runs there. Agents from before one OS user for each agent could share one user and one tmux server, so the
    session is what tells them apart, named whole ("=fleet-scout:"): tmux takes a name as the start of another, and
    "fleet-scout" found "fleet-scout-lead".

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
                 floor=None, read_key=None, ended=None, releases=None):
        self.kit, self.agent, self.conf, self.post, self.busy = kit, agent, conf, post, busy
        # () -> the vendor's own record of Codex's newest releases (codex_releases): its update takes the newest that is
        # onboard.RELEASE_AGE_DAYS old
        self.releases = releases or (lambda: codex_releases(self.home, self.clock()))
        # (runtime) -> True when that runtime's own account read said that its sign-in is over at the provider
        # (usage.Collector.sign_in_ended). None: nothing reads the account here, as for the server service's readings.
        self.ended = ended
        # () -> the key of the agent's model account from this machine's vault, or None (fleet.account_key): the
        # setup check proves the key with it, and a reading of the program's model list starts the program with it
        self.read_key = read_key
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
        # The account item of a check runs outside report_lock (the coordinator's decision D26): one at a time, by the
        # thread of the check that started it. account_waiting is the newest check whose item waits for it:
        # (check, verify items of its first report); account_runs is True while a thread runs items. account_finished
        # is a check whose item ended and whose second report the hub did not take (no answer, or a 5xx): (check, its
        # finished items), which the next status report carries (the sixth review's P1).
        self.account_lock = threading.Lock()
        self.account_done = threading.Condition(self.account_lock)      # notified when account_runs ends
        self.account_waiting, self.account_runs, self.account_finished = None, False, None
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
                self.remember_browser(s["desktop"]["browser"], s["desktop"]["claude_account"])
                code, out, _ = self.run(["sw_vers", "-productVersion"])
                s["macos_update"] = macos_update(out.strip() if code == 0 else None)
        else:
            # Whether apt installs the security updates by itself: systemctl's word for the unit. With no word
            # (systemd answers nothing for a second or two while it starts itself again, after an update of systemd or
            # libc6, and _run gives nothing for a call that ran out of time) the reading cannot say: it leaves the
            # fact out, and the hub keeps what was said of it (hub.left_out), where a null would end a fault that still
            # stands with a false "in order again" (15 November 2026, measured on a real Ubuntu).
            code, out, _ = self.run(["systemctl", "is-enabled", "unattended-upgrades"])
            if out.strip():
                s["unattended_upgrades"] = out.strip() == "enabled"
            else:
                del s["unattended_upgrades"]
            code, out, _ = self.run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=90)
            if code == 0:
                s["pending_security"] = len(re.findall(r"^Inst .*[Ss]ecurity", out, re.M))
            s["reboot_required"] = os.path.exists("/var/run/reboot-required")
            s.update(hardening(self.run), upgraded_at=upgraded_at())   # the hub reads its own server with it too
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
        """What only hands at this Mac can put right: its lock, macOS's own setup screens, Chrome and Claude's
        extension; and the ChatGPT app's sign-in, which the owner's sign-in of Codex for an agent of this Mac puts
        right too (fleet.Helper.login_program). With no AI.

        `chatgpt_app` says whether this Mac has the ChatGPT app with its copy of Codex at all: `chatgpt` is false
        without it and also for an app that is signed out, and only the first of the two needs the app's install at
        this Mac (Founderizer's installer); the second needs a sign-in of Codex, which the owner starts from
        Founderizer on their own computer.

        `claude_account` is the account and the organization that the extension must be signed in to for Claude Code
        of this Mac (claude_account), and `bridge` whether this Mac reaches the server that links the two, read only
        while no browser answers (bridge_reachable): with them the manager names the cause and the owner's exact step,
        where it guessed before. `vault_chrome` is what stops a sign-in of this Mac's vault in Chrome now (vault_chrome).
        """
        console = console_session(self.run)
        code, _, _ = self.run(["pgrep", "-x", "Google Chrome"])
        extension = chrome_extension(self.home)
        # Its answer means something only for a runtime that is signed in: a signed-out one reads no browser at all.
        # An extension that macOS hides is read too (chrome_hidden): `extension` is None there, and until 19 November
        # 2026 the link was never read, so the manager never heard of an extension that was not linked. The hub tells
        # such a Mac by a None `extension` beside a `browser` that is not None.
        hidden = extension is None and chrome_hidden(self.home)
        claude = self.exe("claude") if (extension or hidden) and self.runtime("claude")["signed_in"] else None
        browser = browser_connected(claude) if claude else None
        return {"locked": console[1] if console else None, "setup": setup_screens(self.run), "chrome": code == 0,
                "extension": extension, "browser": browser,
                "claude_account": claude_account(self.run, claude) if claude else None,
                "bridge": bridge_reachable() if browser is False else None,
                "chatgpt": self.chatgpt(), "chatgpt_app": os.path.exists(CHATGPT_CODEX),
                "vault_chrome": vault_chrome(self.home)}

    def chatgpt(self):
        """Whether the ChatGPT app of this Mac is signed in: the copy of Codex it carries, which Computer Use runs
        through, and not the one a Codex agent has in its own home. False with no app, and when it says nothing: no agent
        gets a screen on a silence.

        **Its status command reads only what the Mac keeps**, and says "Logged in" after the provider ended that
        sign-in, while each screen task fails (the owner's Mac Studio, 18 November 2026: "workspace routing discovery
        unauthorized (401)" on the task, while this reading said "signed in"). This reading has no account
        read of its own, so it takes the word of the helpers' newest one (screen_word): False while that read says
        that the provider ended the sign-in. With no such word of the last SCREEN_WORD_AGE seconds, the status
        command's word stands, as before."""
        if not os.path.exists(CHATGPT_CODEX):
            return False
        _, out, err = self.run([CHATGPT_CODEX, "login", "status"])
        text = out + err
        return codex_keeps_sign_in(text) and screen_word(self.home, self.clock()) is not True

    def remember_browser(self, connected, account=None):
        """Leave the reading of Chrome where `fleet.py verify` reads it: over SSH it cannot read it, as a sign-in
        (remember_signed_in). account: Claude Code's account there (claude_account), which verify's line names as the
        helper's own setup check does (desktop_items)."""
        try:
            write_json(desktop_path(self.home), {"at": self.clock(), "browser": connected, "claude_account": account})
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

    def runtime(self, name=None, stored=False):
        """{name, version, signed_in} of the agent's runtime, or of another one: status commands only, no model.
        stored: only what the machine keeps, without the account read's word on it (`ended`): the question of a
        sign-out, which removes what is kept, and of a sign-in job, which asks the account read itself.

        **Codex's sign-in is asked of the program that this agent runs as Codex** (screen_codex): for an agent on
        another provider with a screen runtime here, that is the ChatGPT app's own copy, also on a Mac with no
        `codex` of its own, which read nothing of this sign-in until 18 November 2026. `version` stays the version
        of the runtime's own program, None without one: it says what a change of the agent's provider would run
        (hub.switch_view), and that is never the app's copy."""
        name = name or self.conf.get("runtime")
        result = {"name": name, "version": None, "signed_in": None}
        exe = self.exe(name)
        asked = screen_codex(self.conf, name) or exe
        if not asked:
            return result
        code, out, _ = self.run([exe, "--version"]) if exe else (1, "", "")
        if code == 0 and out.strip():
            result["version"] = out.strip().splitlines()[0][:120]
        if name == "codex":
            code, out, err = self.run([asked, "login", "status"])
            text = out + err
            if text.strip():
                result["signed_in"] = codex_keeps_sign_in(text)
        elif name == "claude":
            code, out, _ = self.run([exe, "auth", "status"])
            try:
                result["signed_in"] = bool(json.loads(out).get("loggedIn"))
            except ValueError:
                pass
        # A status command reads what the machine keeps, and Codex's keeps saying "Logged in" after the provider
        # ended the sign-in: the refresh token was revoked, has expired, or the account signed in again somewhere
        # else. Each turn fails then, and the owner's Sign in was refused with "is signed in on this machine" (the
        # owner's Mac Studio, 13 November 2026, for a day). The account read asks the provider, so its word decides.
        if result["signed_in"] and not stored and self.ended and self.ended(name):
            result["signed_in"] = False
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
        # the last start check of this user, read from its file at each report: it outlives the restart after a move
        checked = read_start_check(self.floor, "helper")
        return {**({"start_check": checked} if checked else {}),
                "revision": self.running(), "os": self.os_info(), "security": self.security_reading(fast),
                "runtime": runtimes[name] if name in runtimes else self.runtime(),
                "runtimes": said,
                # one OS user for each agent: the hub compares the uids of a machine's agents (hub.os_user_found)
                "access": dict(self.access(), user=pwd.getpwuid(os.getuid()).pw_name, uid=os.getuid()),
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

    def account(self):
        """The model account of this agent as this checkout's team.json has it now (model_account), or None for an
        agent whose account has no kind."""
        try:
            with open(os.path.join(self.kit, "team.json"), encoding="utf-8") as f:
                team = json.load(f)
        except (OSError, ValueError):
            return None
        return model_account(team, self.conf) if isinstance(team, dict) else None

    def account_key(self, account):
        """The key of the agent's model account, from the machine's vault; None with no secret or no value."""
        if not account or not account["secret"] or not self.read_key:
            return None
        try:
            key = self.read_key()
        except Exception:
            return None
        return key if isinstance(key, str) and key else None

    def acp_model_options(self, name, exe, how):
        """(options, error, source) of an ACP program, read where its entry's acp_models says: the program is started
        as a session starts it, in a folder of its own, with the account's key and configuration, and no prompt is
        sent. 64 options at most; the model that the program would run now is the default."""
        import acp_programs
        import acp_runner
        source = "ACP " + ("initialize" if how == "initialize" else "session/new")
        label = runtime_fact(name, "label", name)
        if not exe:
            return None, f"{label} is not installed", source
        account = self.account()
        if account and account["runtime"] != name:
            account = None
        adapter = acp_programs.adapter(runtime_fact(name, "acp_adapter"), self.home)
        kept = kept_account(self.home, self.agent, account) if account and account["kind"] == "server" else None
        model = self.conf.get("model") or (account or {}).get("model") or (kept or {}).get("model")
        names = [m for m in (kept or {}).get("models") or [] if isinstance(m, str)]
        key, session = self.account_key(account), str(uuid.uuid4())
        environ = dict(os.environ)
        if key:
            environ[runtime_fact(name, "key_env")] = key
        methods = runtime_fact(name, "acp_auth") or {}
        auth = methods.get(account["kind"] if account else "plan")
        try:
            adapter.prepare(session, None, program_account(account, name, model, names))
            listed, error = acp_runner.read_models(
                [exe, *shlex.split(runtime_fact(name, "acp_command") or "")[1:]], self.kit,
                acp_runner.started_env(name, adapter, session, auth, environ), adapter, how, auth=auth)
        except OSError as e:
            listed, error = None, f"{label} could not be started for its model list: {type(e).__name__}"
        finally:
            adapter.remove(session)
        options, starts = [], model         # starts: the model that a session of this agent starts with
        for model, efforts, effort, current in listed or []:
            if isinstance(model, str) and MODEL_NAME.fullmatch(model) and all(o["model"] != model for o in options):
                options.append({"model": model, "display_name": model, "default": current is True,
                                "efforts": [e for e in efforts if isinstance(e, str) and EFFORT_NAME.fullmatch(e)][:16],
                                "default_effort": effort if isinstance(effort, str) and EFFORT_NAME.fullmatch(effort)
                                else None})
        if not options:
            return None, error or f"{label} listed no models", source
        # a seller lists hundreds: the model that this agent starts with stays in the 64 that the reading keeps, so
        # that model_item and the account item (R6 part 2) find it where the program offers it
        chosen = [o for o in options[64:] if o["model"] == starts]
        return (options[:64 - len(chosen)] + chosen), None, source

    def model_options(self, name, exe):
        """(options, error, source): one runtime's own model options, read with its executable exe (None when it is
        not installed). The reading of read_models, and the check of a runtime update (runtime_check). An ACP
        program's list is read by its entry's acp_models, whatever the program is."""
        how = runtime_fact(name, "acp_models")
        if how:
            return self.acp_model_options(name, exe, how)
        if name == "codex":
            options, error = self.codex_models(exe) if exe else (None, "codex is not installed")
            return options, error, "codex app-server model/list"
        if name == "claude":
            code, out, _ = self.run([exe, "--help"]) if exe else (1, "", "")
            options, error = claude_model_list(out) if code == 0 else (None, "claude is not installed" if not exe
                                                                        else "claude --help did not answer")
            return options, error, "claude --help"
        return None, "This runtime reports no model list.", None

    def verify(self, status, probe_job=None, checking=False):
        """The setup check: what this machine can prove now, with no AI. Each item is ok, failed or not_verified;
        the hub adds its own items and decides which ones are required. checking: the item of the agent's model
        account is in state CHECKING and not checked yet (report: the coordinator's decision D12)."""
        items = []

        def add(kind, ref, state, detail, words=None):
            items.append(dict({"kind": kind, "ref": ref, "state": state, "detail": detail[:300]}, **(words or {})))
        rt = status.get("runtime") or {}
        name = rt.get("name") or "unknown"
        account = self.account()
        if not rt.get("version"):
            add("runtime", name, "failed", f"{name} is not installed.")
        elif account:
            # an agent on a key or on a model server: its program has no sign-in to read, and the account's own item
            # says whether the key or the server is good
            add("runtime", name, "ok", str(rt["version"]))
        elif rt.get("signed_in") is True:
            add("runtime", name, "ok", f"{rt['version']}, signed in")
        elif rt.get("signed_in") is False:
            add("runtime", name, "failed", f"{rt['version']}, not signed in")
        else:
            add("runtime", name, "not_verified", f"{rt['version']}; the sign-in could not be read")
        add(*self.model_item(status.get("models")))
        if account:
            add(*(("account", account["id"], CHECKING, "") if checking else self.account_item(account)))
        user = pwd.getpwuid(os.getuid()).pw_name
        add("capability", "shell", "ok", f"Commands run as {user}.")
        add("capability", "web", "not_verified", "Web access is a runtime tool; Fleet cannot check it without a model turn.")
        if self.platform == "darwin":
            tabs = RUNTIMES.get(name, {}).get("browser_tabs")
            exe = self.exe(name) if tabs else None
            connected = browser_connected(exe) if exe else None
            needed = claude_account(self.run, exe) if connected is False else None
            for item in desktop_items(self.run, self.home, user, tabs, connected, needed):
                add(*item)
        else:
            # build plan 04, S3: an agent's own Chrome on its Linux server, by its parts and its port's live proof
            try:
                reading = browser_reading(self.platform, run=self.run)
            except Exception:       # noqa: BLE001 - one item of the check, which goes on
                reading = None
            add(*browser_item(self.conf, user, reading))
            add("capability", "screen", "failed", "A Linux worker has no desktop session.")
        items += self.login_items(probe_job)
        code, out, _ = self.run(["id", "-Gn"])
        add("access", "os_user", "ok", f"{user} (uid {os.getuid()}), groups: " +
            (", ".join(out.split()) if code == 0 and out.strip() else "unknown"))
        add("access", "files", "ok", f"The agent can read and change every file that {user} can, including this Fleet "
                                     f"checkout.")
        add(*self.admin_item())
        return items

    def account_item(self, account):
        """The setup check's item of the agent's model account, ("account", its id, state, detail): the key is good at
        its provider (check_key), or the owner's own model server answers, asks for its key, passes a tool call and
        takes the context that the fleet needs (check_server). What a check of a server passed is kept for this
        agent in ~/.fleet (account_path): a session starts with the kept model while neither the agent nor the
        account names one."""
        key = self.account_key(account)
        if account["kind"] == "key" or (account["secret"] and not key):
            state, detail = check_key(account, key) if account["kind"] == "key" else ("failed", NO_KEY)
            # the account's model is in the program's own list (R6 part 2); the agent's own model is model_item's
            if state == "ok" and account["kind"] == "key" and account["model"] and not self.own_model():
                offered = self.offered_models()
                if offered is not None and account["model"] not in offered:
                    state, detail = "failed", NOT_OFFERED
            return self.account_words(account, state, detail, account["model"])
        if not account["address"]:
            return self.account_words(account, "failed", NO_ANSWER)
        # the program's list of a model server is made from its configuration, which names the model: so the server's
        # own list is the one that the named model must be in (check_server)
        kept = kept_account(self.home, self.agent, account)
        wanted = self.own_model() or account["model"]
        state, detail, keep = check_server(account, key, kept, clock=self.clock, wanted=wanted)
        if keep is None and state == "ok" and kept and not os.path.exists(account_path(self.home, self.agent)):
            keep = kept         # the result of another name, as after a rename: this agent's own file from now on
        if keep:
            path = account_path(self.home, self.agent)
            try:
                os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
                with open(os.open(path + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
                    json.dump(keep, f)
                os.replace(path + ".new", path)
            except OSError:
                return self.account_words(account, "failed", NO_ANSWER)     # without the file no session could start
            # this agent's own file is the account's one result here now: a file of another name (a rename) could
            # stand again after a later failure, with an older list (decision D19, the review's T5)
            forget_account(self.home, account, keep=path)
        elif state != "ok" and detail != NO_ANSWER:
            # a server that is open, or that no model of passes, keeps no model, under any agent's name; a model that
            # this agent names and that failed keeps no result of that model. One that only does not answer now keeps
            # what its last check proved, for when it answers again
            with contextlib.suppress(OSError):
                os.remove(account_path(self.home, self.agent))
            named = wanted if not wanted or wanted.startswith("own/") else "own/" + wanted
            forget_account(self.home, account, model=None if detail == OPEN_SERVER or not wanted else named)
        return self.account_words(account, state, detail, wanted)

    def account_words(self, account, state, detail, model=None):
        """The account item, ("account", its id, state, detail, words): words has the detail's code (ACCOUNT_CODES)
        (decision D7), and for NOT_OFFERED the model as it is saved. The hub fills the names of the sentence itself,
        the agent as the apps show it among them (decision D18, the review's T3). For a hub of an older release the
        detail is the sentence filled here: the agent by its role (its title), else its name as the apps write it,
        and the model as the owner pasted it, without the provider's part in the program (`openrouter/`, `own/`)."""
        words = {"code": ACCOUNT_CODES[detail]} if detail in ACCOUNT_CODES else {}
        if detail == NOT_OFFERED:
            words["model"] = model if isinstance(model, str) else ""
            program = account.get("program")
            shown = model[len(program) + 1:] if program and isinstance(model, str) and model.startswith(program + "/") \
                else model
            known = OWN_SERVER if account["kind"] == "server" else KEY_PROVIDERS.get(account.get("provider")) or {}
            role = " ".join(str(self.conf.get("title") or "").split())
            detail = NOT_OFFERED.format(provider=known.get("label") or account.get("provider") or "",
                                        model=shown or "", agent=role or shown_name(self.agent))
        return ("account", account["id"], state, detail, words)

    def own_model(self):
        """The agent's own model as this checkout's team.json has it now, which a session's start takes
        (fleet.checkout_conf): a change in the Model menu restarts no helper, so the entry of the helper's start
        (self.conf) can be old (the coordinator's decision D21, proved by lane H). That entry's model only when the
        file cannot be read."""
        try:
            with open(os.path.join(self.kit, "team.json"), encoding="utf-8") as f:
                entry = (json.load(f).get("agents") or {}).get(self.agent)
        except (OSError, ValueError, AttributeError):
            return self.conf.get("model")
        return entry.get("model") if isinstance(entry, dict) else self.conf.get("model")

    def offered_models(self):
        """The model names of the program's own list, as the last reading has it (read_models), or None when there is
        no list of this agent's runtime."""
        reading = self.models
        if not isinstance(reading, dict) or not reading.get("ok") or reading.get("runtime") != self.conf.get("runtime"):
            return None
        return {o.get("model") for o in reading.get("options") or [] if isinstance(o, dict)}

    def owner_default(self):
        """The owner's default model and effort of this agent's runtime (owner feature default_models), from this
        checkout's team.json; None without one."""
        try:
            with open(os.path.join(self.kit, "team.json"), encoding="utf-8") as f:
                team = json.load(f)
        except (OSError, ValueError):
            return None
        return facts_now(team, self.conf.get("runtime")).get("default_model") if isinstance(team, dict) else None

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
        gets = model     # with no model of its own, the owner's default where this list offers it (fleet.run_settings)
        wanted = None if model else (self.owner_default() or {}).get("model")
        if isinstance(wanted, str) and (wanted in options or reading.get("other_names") and
                                        re.fullmatch(r"claude-[a-z0-9.-]+", wanted)):
            gets = wanted
        o = options.get(gets) if gets else next((x for x in reading["options"] if x["default"]), None)
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
        runs, finished = False, None
        with self.report_lock:
            try:
                if check:
                    self.read_models(force=True)    # a machine check reads the model options again
                    self.read_screen_models(force=True)
                status = self.collect(fast=fast and not check)
                if check:
                    status["check"] = check         # this report answers the owner's "check this machine"
                    status["verify"] = self.verify(status, probe_job, checking=True)
                    with self.account_lock:
                        self.account_finished = None    # the hub replaced that check at this one's request (D20)
                    if any(i["kind"] == "account" and i["state"] == CHECKING for i in status["verify"]):
                        # The coordinator's decision D12: the account item can take minutes (a model server's tool
                        # call and context), and the hub fails a check that sends no report in its CHECK_WAIT. So a
                        # first report says that the item runs, and the hub then waits for its second half. A hub of
                        # an older release refuses the first one, and takes the second as before. The item runs
                        # outside this lock (D26): a later check and the status thread's reports do not wait for it.
                        with self.account_lock:
                            self.account_waiting = (check, status["verify"])
                            runs, self.account_runs = not self.account_runs, True
                else:
                    # Lane S3's live test on a test fleet (15 November 2026): the hub ends a check's wait at a report
                    # that names no check, as for a helper that started again (hub.record_status, D12), and its
                    # CHECK_WAIT then failed the first check of a new model server. Since D26 the status thread's
                    # reports leave while an item runs, so each of them names the check that waits, with its item
                    # still in CHECKING. After the item, a second report that the hub did not take leaves its check
                    # and finished items (account_finished), and each report carries them until the hub answers one
                    # (the sixth review's P1): else the check of a server that passed reads failed.
                    with self.account_lock:
                        waiting, finished = self.account_waiting, self.account_finished
                    carried = waiting or finished
                    if carried:
                        status["check"], status["verify"] = carried[0], [dict(i) for i in carried[1]]
                self.leaving(status)
                code, data = self.post(status)
            except Exception:
                code, data = None, None
            sent = self.sent(code, data)
            if finished is not None and hub_answered(code):
                with self.account_lock:
                    if self.account_finished is finished:
                        self.account_finished = None
        if runs:
            return self.account_rounds()
        return sent

    def account_rounds(self):
        """The account items of the checks that wait, one at a time, outside report_lock (the coordinator's decision
        D26): each item's result goes to the newest check that waits, in that check's second report. A check that
        came while an item ran takes that item's result, unless the account or the agent's model changed since the
        item began: then the item runs again. True when the last second report reached the hub."""
        sent, ended = False, False
        try:
            while True:
                with self.account_lock:
                    if self.account_waiting is None:  # in the same hold: a check that comes later runs its own
                        self.account_runs, ended = False, True
                        self.account_done.notify_all()
                        return sent
                account, model = self.account(), self.own_model()
                try:
                    item = self.account_item(account) if account else None
                except Exception:
                    item = None
                done = dict({"kind": item[0], "ref": item[1], "state": item[2], "detail": item[3][:300]},
                            **(item[4] if len(item) > 4 and item[4] else {})) if item else None
                # The coordinator's decision D32 (the review's E4): a model server's list of its own models comes from
                # the result that the item just kept (acp_model_options), and the first report read it before, when
                # nothing was kept: "No models are available", and a failed required item for an agent with an effort
                # of its own and no model, which then did not activate. So it is read again here, outside report_lock
                # (the reading starts the program), and the second report has its `model` item.
                again = None
                if account and account.get("kind") == "server":
                    try:
                        reading = self.read_models(force=True)
                        if reading:
                            kind, ref, state, detail = self.model_item(reading)
                            again = {"kind": kind, "ref": ref, "state": state, "detail": detail[:300]}
                    except Exception:
                        again = None
                # The check that waits leaves account_waiting under report_lock, in the hold of its second report: so
                # no status report goes out between the two that names no check (report).
                with self.report_lock:
                    with self.account_lock:
                        if (self.account(), self.own_model()) != (account, model):
                            continue    # the settings moved while it ran: the newest check gets a new item
                        check, items = self.account_waiting
                        self.account_waiting = None
                    finished = (check, [again if again and i["kind"] == "model" else
                                        (done or dict(i, state="not_verified")) if i["kind"] == "account" and
                                        i["state"] == CHECKING else i for i in items])
                    try:
                        status = self.collect(fast=True)  # a reading of now: never older than a report that left
                        status["check"], status["verify"] = check, [dict(i) for i in finished[1]]
                        self.leaving(status)
                        code, data = self.post(status)
                    except Exception:
                        code, data = None, None
                    sent = self.sent(code, data)
                    if not hub_answered(code):    # P1: the next status report carries it (report)
                        with self.account_lock:
                            self.account_finished = finished
        finally:
            if not ended:               # an error: never left on, for an update's restart waits for it
                with self.account_lock:
                    self.account_runs, self.account_waiting = False, None
                    self.account_done.notify_all()

    def account_running(self):
        """True while an account item of a check runs: an update's restart, which ends this process, waits for it
        (the fifth review's Y10)."""
        with self.account_lock:
            return self.account_runs

    def sent(self, code, data):
        """The report clock and the hub's answer of one report that left; True when it reached the hub."""
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

    def leaving(self, status):
        """What a report says as it leaves. Tailscale, and never saved: a report goes over the private network, so a
        reading from before it says "off" when the network is back, and a retry after a break would repeat that."""
        status["security"]["tailscale"] = self.private_network()
        status["reading_age"] = round(max(0.0, self.monotonic() - self.read_mono), 3)
        return status

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
        """Runs with the gate held. True when the restart was asked for: this process ends soon. A release that does
        not start on this machine (take, `starts`), or whose start check did not end in time, is a failed update with
        its own words, and no restart: this process keeps the code it runs, and so does its checkout. After a time-out
        the next request checks the release again."""
        self.set("updating", "Updating Fleet while idle.")
        with self.account_lock:         # a check's account item that began after the idle test ends first (Y10)
            while self.account_runs:
                self.account_done.wait()
        self.report()
        target = desired or self.upstream()
        # A checkout that has the requested commit already needs no fetch or merge: on the hub machine the checkout is
        # also the hub's, whose own git work a fetch here could disturb.
        if not (desired and self.has(desired)):
            code, out, err = self.run(["git", "-C", self.kit, "fetch", "-q", "origin"], timeout=120)
            if code != 0:
                return self.fail("The checkout could not fetch: " + (err or out).strip()[-300:])
            # The one check of every move (may_take), the release's own start check on this machine, and the files of
            # a task that this machine delivered.
            problem = take(self.kit, target, self.run, self.floor, room=True, starts="helper")
            if isinstance(problem, (Refused, CheckTimedOut)):     # in its own words: a request later tries again
                return self.fail(str(problem))
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
                idle = not self.busy() and not self.account_running()
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
            idle = not self.busy() and not self.runtimes_busy() and not self.account_running()
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
        if name == "codex":
            # The newest release that is onboard.RELEASE_AGE_DAYS old, by the vendor's own record, and never an older
            # one than this user runs: a version that came out hours ago waits, as the owner's npm rule has it.
            try:
                aged = onboard.codex_release(self.releases(), self.clock())
            except Exception as e:      # an answer of GitHub that is cut or of another shape: Claude Code's turn still comes
                return outcome("skipped", f"The record of Codex's releases could not be read ({e}), so {old} stays; "
                                          f"the next round reads it again.")
            if not aged:
                return outcome("skipped", f"The record of Codex's releases has no release that is "
                                          f"{onboard.RELEASE_AGE_DAYS} days old, so {old} stays.")
            if onboard.not_older(old, aged):
                return outcome("current", f"{old} stays: no newer release of Codex is {onboard.RELEASE_AGE_DAYS} "
                                          f"days old yet.")
            code, said = shell(onboard.runtime_install(name, aged))
        else:
            code, said = shell(onboard.runtime_update(name))
        new, problem = self.runtime_check(name, exe)
        if not problem and not onboard.not_older(new, old):
            problem = f"it is older than {old}"
        if not problem and name == "codex" and not onboard.not_older(aged, new):
            problem = f"it is not {aged}, the release that is {onboard.RELEASE_AGE_DAYS} days old"   # a newer one came
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
    hub.sh, and what owner_mcp.py runs on a machine). It raises this user's floor to the release that KIT
    runs, then answers with its exit status: 0 when KIT may move onto TARGET, else 1 and the one reason on standard
    error. The caller makes the move itself, with `git merge --ff-only TARGET`.

    `python3 -E -s lifecycle.py mcp-start --keep NAME[=SOURCE] ... --path PATH --folder FOLDER -- PROGRAM ARGS`: the
    start of one program server (mcp_start).

    `python3 -B lifecycle.py start-check ROLE`, in a copy of a release's tree: does this release start on this
    machine as that program (start_check_here)? One line, and 0 or 1."""
    import argparse
    parser = argparse.ArgumentParser(prog="lifecycle.py", description="The one check of every move of a checkout")
    sub = parser.add_subparsers(dest="cmd", required=True)
    check = sub.add_parser("may-take", help="may this checkout move onto that commit?")
    check.add_argument("--floor", default=floor_path(os.path.expanduser("~")),
                       help="this user's release floor (default ~/.fleet/release-floor)")
    check.add_argument("kit", help="the checkout")
    check.add_argument("target", help="the commit it would move onto")
    starts = sub.add_parser("start-check", help="does this tree start on this machine as that program?")
    starts.add_argument("role", choices=sorted(START_PROGRAMS), help="the program that runs from the checkout")
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ["mcp-start"]:       # its program's own arguments follow "--", and argparse reads none of them
        rest = argv.index("--") if "--" in argv else len(argv)
        start = argparse.ArgumentParser(prog="lifecycle.py mcp-start")
        start.add_argument("--keep", action="append", default=[], help="NAME or NAME=SOURCE, once for each")
        start.add_argument("--path", required=True, help="the PATH of the program")
        start.add_argument("--folder", required=True, help="the empty folder where it starts")
        given = start.parse_args(argv[1:rest])
        try:
            mcp_start(given.keep, given.path, given.folder, argv[rest + 1:])
        except (ValueError, OSError) as e:
            print(f"lifecycle.py mcp-start: {e}", file=sys.stderr)
            return 2
        return 0
    args = parser.parse_args(argv)
    if args.cmd == "start-check":
        code, line = start_check_here(args.role)
        print(line, flush=True)
        return code
    kit = os.path.abspath(args.kit)
    keep_floor(kit, args.floor)
    problem = may_take(kit, args.target, floor=args.floor)
    if problem:
        print(f"lifecycle.py may-take: {problem}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

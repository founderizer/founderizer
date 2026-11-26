#!/usr/bin/env python3
"""The day's error report: what a hub sends to our side, once a day, while the owner has turned error reports on.

The owner, 16 November 2026, to the picture of Settings › General with a section "Error reports" and one switch,
"Send to Founderizer's developers", off until he turns it on: "Yes, as drawn". The switch is now Settings › Help ›
Help improve Founderizer, and the first page of the setup turns it on too (Send anonymous usage data). The plan is
~/dev/founderizer-plans/feedback-diagnostics-plan.md, Phase 3, and its contract is the one of `POST
<channel>/api/errors`, which the Mac app and the website follow too.

**What goes is what he was told goes, and nothing else:** the hub's errors as diagnostics.view gives them (a class
from the fixed list, files and lines of this code tree, numbers and times, never a word of an error), its stalls in
the same shape (a class of STALL_CLASSES; the owner's "Yes, reports only" of 21 November 2026), the refused
calls in the same shape, and facts: the fleet's random id, the version of the release that runs (from its signed
manifest, never a commit of the configuration ref, which is this fleet's own), the code's id, the operating system's
name and version, and how many agents and servers the fleet has. Every value is checked again here against the
contract's own patterns, and a value out of shape is left out, so that nothing else can ride along. Only what
happened after the report before it, and after the owner turned reports on, goes.

**No word goes either, not even a name of the code** (the owner, 20 November 2026: "Yes, look at them"). The names of
files and tools are words joined by "_", and anybody can post a report to our side, whose mail and whose reader of the
kinds of error (an agent) read them. So a file of this code tree and a refused call's tool go as their mark (mark):
the first 16 hexadecimal characters of the SHA-256 of the name, which our side takes as hex and nothing else. A class
goes as its name, from the recorder's fixed list, which our side holds too. `python3 errorreports.py names`, in the
code of a report's version, prints each mark with its name.

**Where it goes:** only to our own site, over HTTPS, at founderizer.com or a host below it (the platform's
platform.founderizer.com, or staging for a staging fleet), and no redirect is followed. It carries no Authorization
header: the route asks for no account, and the report needs nothing that names the subscription.

**The fleet's health** (the reliability plan of 21 November 2026, W15, inside the owner's yes to "codes, versions and
counts"; the contract's "The health of a fleet"): the newest release that the channel named and how its runs went
here, the health checks of the fleet's servers, and the size of the hub's own server, each value a word of a copy of
our side's lists (STATES, STEPS, CAUSES, CHECKS), a version, a whole number or a time (health). The report goes
sooner than a day when something breaks (due), and goes again at once without the block when our side refuses it.
Since F5 piece 3 (22 November 2026, the owner's "Yes" to its privacy sentence) the checks also say which of the
hub's own warnings stand whose way out is ours ("Tell us", Report a problem): each as a code of CHECKS, never its
words (hub.WARNING_CODES).

**The funnel** (the SMB audit's Q8, the owner's "Go ahead" of 25 November 2026: "Five funnel counts under the
existing usage switch"): the day of four first steps of the fleet, each once (funnel); the Mac's report carries the
fifth, the first page of the setup. Only a day, made from a time, and never a word. It waits until our side takes it
(FUNNEL). The design: ~/dev/founderizer-plans/smb-x100-audit-2026-11-25/q8-funnel-design.md.

Python standard library only.
"""
import hashlib
import http.client
import json
import os
import platform
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import diagnostics

PATH = "/api/errors"
MANIFEST = "release.json"   # lifecycle.RELEASE_FILE: the signed manifest of the release on the configuration ref
DAY = 86400             # seconds between two reports, and the hold after a 4xx that is not 429, a 301 or a 308
RETRY = 3600            # seconds before a report that could not reach our side, or got a 5xx or another 3xx, goes again
LASTING = (301, 308)    # a redirect that stays: the report follows none, so each try would meet it again
RETRY_MOST = 6 * 3600   # the longest wait that our side's Retry-After may set
TIMEOUT = 30            # seconds for one send
MOST = 20               # faults, and refused calls, in one report (diagnostics.MAX_SHOWN)
LIMIT = 65536           # bytes of one report, as our side takes it
COUNT_MOST = 100_000    # agents, and servers
EPOCH = (1.6e9, 4e9)    # the times that a report may carry

HOST = re.compile(r"(?:[a-z0-9-]+\.)*founderizer\.com")
CHANNEL_PATH = re.compile(r"(?:/[A-Za-z0-9._~-]+)*")
FLEET = re.compile(r"[0-9a-f]{16}")
# The version and the system are numbers and one word, never words that a sentence could be made of (the owner, 20
# November 2026: "Yes, tighten them"), as our side checks them: a release's version ("2026.11.538") or "unknown", and
# one word of letters with its version number ("ubuntu 24.04", "macOS 26.6", "arch").
VERSION = re.compile(r"unknown|[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,6}")
SYSTEM = re.compile(r"[A-Za-z]{1,16}(?: [0-9]{1,4}(?:\.[0-9]{1,4}){0,3})?")
SYSTEM_WORD = re.compile(r"[A-Za-z]{1,16}")
SYSTEM_NUMBER = re.compile(r"[0-9]{1,4}(?:\.[0-9]{1,4}){0,3}(?![0-9])")
CODE = re.compile(r"[0-9a-f]{1,64}")
MARK = re.compile(r"[0-9a-f]{16}")   # a file's or a tool's mark: mark()
# The classes that our side takes (founderizer-web, src/lib/errors.ts, CLASSES), with "other": a report that names
# another is refused whole. A class added to diagnostics.CLASSES goes to our side first, then here; until then it goes
# as "other" (test_error_reports says when the two lists differ).
THEIR_CLASSES = frozenset((
    "ArithmeticError", "AssertionError", "AttributeError", "BlockingIOError", "BrokenPipeError", "BufferError",
    "CalledProcessError", "ChildProcessError", "ConnectionAbortedError", "ConnectionError", "ConnectionRefusedError",
    "ConnectionResetError", "DatabaseError", "EOFError", "FileExistsError", "FileNotFoundError", "HTTPError",
    "ImportError", "IncompleteRead", "IndexError", "IntegrityError", "InterfaceError", "InterruptedError",
    "IsADirectoryError", "JSONDecodeError", "KeyError", "LookupError", "MemoryError", "ModuleNotFoundError",
    "NameError", "NotADirectoryError", "NotImplementedError", "OSError", "OperationalError", "OverflowError",
    "PermissionError", "ProcessLookupError", "ProgrammingError", "RecursionError", "RemoteDisconnected",
    "RuntimeError", "SSLError", "StopIteration", "SubprocessError", "TimeoutError", "TimeoutExpired", "ToolError",
    "TypeError", "URLError", "UnboundLocalError", "UnicodeDecodeError", "UnicodeEncodeError", "UnicodeError",
    "ValueError", "ZeroDivisionError"))
# A stall of the hub (diagnostics.STALLS, owner API 1.284) goes as a fault of its kind's class, on the owner's "Yes,
# reports only" of 21 November 2026: our side takes these four (founderizer-web, src/lib/errors.ts, CLASSES) since
# that day, and a class that it lacked would refuse the whole report.
STALL_CLASSES = {"busy": "StallBusy", "hold": "StallHold", "collect": "StallCollect", "paused": "StallPaused"}
THEIR_CLASSES = THEIR_CLASSES | frozenset(STALL_CLASSES.values())
COMMIT = re.compile(r"[0-9a-f]{40}")

# The words of the health block: copies of our side's lists (founderizer-web, src/lib/errors.ts, HEALTH_WORDS), word for
# word. Our side refuses a report whole when it names a word outside its list, so a word of the hub's own that a copy
# does not have goes as "other" (word), as a class does (THEIR_CLASSES). A new word goes to our side first, then here:
# test_error_reports holds each word of each source (hub.RELEASE_STATES, releases.STEPS, releases.CAUSES, the server
# watch's keys) to be in its copy.
STATES = ("verified", "held", "updating", "passed", "kept", "rolled_back", "done", "failed", "none", "other")
STEPS = ("room", "hold", "branch", "clean", "pinned", "fetch", "have", "already", "minimum", "clone", "merge", "keep",
         "schema", "selftest", "verify", "take", "push", "follow", "other")
CAUSES = ("none", "no_ipv4_route", "dns", "connect", "tls", "http", "timeout", "memory", "disk", "conflict", "check",
          "busy", "hold", "branch", "own_changes", "other")
CHECKS = ("uplink", "ipv4_route", "ipv6_route", "dns", "channel", "upstream", "tailnet", "clock", "disk", "memory",
          "oom", "release_lag", "firewall", "updates", "restart", "quiet", "egress", "network", "ssh", "npm",
          "updates_off", "macos_update", "egress_table",
          # the hub's own warnings whose way out is ours (F5 piece 3, 22 November 2026: hub.WARNING_CODES)
          "records", "schema", "timers", "release_start", "helper", "vault", "manager_session",
          "server_update",      # a server's update failed or is behind (the owner's answer to card F5-3)
          "other")
CHECKS_MOST = 32            # checks in one report, as our side takes them
NUMBER_MOST = 100_000       # tries, behind, servers and starts
MB_MOST = 4_194_304         # memory and swap, in MB
CORES_MOST = 4096
EARLY_MOST = 4              # early reports in a DAY (the plan's 3.3); each one starts the day again
# The contract's behind_hours: a hub that has been behind this long (`since`: when it first learned of a release newer
# than the one that it runs, and has run no newer one since), with a run since then that did not end done (`tries`),
# sends the report early, once for each time behind.
BEHIND_WAIT = 6 * 3600
THIRD_RUN = 3               # and so does the third run of one release that did not end done
# The causes of a run that the fleet holds on purpose (a hold, a branch or changes of its own): our side counts no
# fleet behind for them (founderizer-web, src/lib/fleet-health.ts, `behind:`), so they ask for no early report either.
NO_ALARM = ("hold", "branch", "own_changes")
# The hub's own server, read for the block's `machine` (machine_reading): its memory and swap, the kernel's count of
# processes that it ended for lack of memory since the machine started, and the id of that start.
MEMINFO, VMSTAT, BOOT_ID = "/proc/meminfo", "/proc/vmstat", "/proc/sys/kernel/random/boot_id"

# The funnel's steps of a hub, in their order (the Mac's report has the one before them, "page"): its servers were
# built (the owner's Mac claimed it), the owner's first message, the first task that ended completed, and the first
# person other than the owner.
FUNNEL_STEPS = ("built", "message", "job", "person")
DAY_FORM = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")    # a UTC day as our side takes it: day_of
# **Our side takes the block.** False until it does: founderizer-web refuses a report with a key that it does not know,
# and counts each refusal. The website area's change goes live first, with the privacy page's sentences that the owner
# saw, then this is True, in a commit of its own (the design note's "Dormant until our site takes it").
FUNNEL = False


class ReportError(Exception):
    """Nothing was sent, or our side refused it. The message is safe to log: it never holds a value of the report.

    `retry_after`: the seconds after which a report may go again: our side's Retry-After for a 429, DAY for any other
    4xx (the same report would only be refused again), for a redirect that stays (LASTING: the report follows no
    redirect, so it would only meet the same one again, each hour for ever, with a line in the hub's log each time) and
    for a channel that is not ours, RETRY for a 5xx or another 3xx (our site, or a deploy of it, that is down for a
    moment: a DAY would put two reports 48 hours apart, and our side counts a hub that sent nothing for 36 hours as
    silent), and None when our side was not reached."""

    def __init__(self, says, retry_after=None, status=None):
        super().__init__(says)
        self.retry_after = retry_after
        self.status = status


def endpoint(channel):
    """The report's address on the fleet's release channel, which must be HTTPS at founderizer.com or a host below
    it (each label letters, digits and hyphens): never `xfounderizer.com`, never a user name, a query or an odd path.
    ReportError for any other channel, so that no hub whose channel names another site sends anything there."""
    refused = ReportError("the fleet's channel is not our site (founderizer.com or a host below it), so no error "
                          "report goes", retry_after=DAY)
    try:
        parts = urllib.parse.urlsplit(str(channel or "").strip())
        host, port = (parts.hostname or "").lower(), parts.port
    except ValueError:
        raise refused from None
    if parts.scheme.lower() != "https" or not HOST.fullmatch(host) or parts.username is not None \
            or parts.password is not None or parts.query or parts.fragment \
            or not CHANNEL_PATH.fullmatch(parts.path.rstrip("/")):
        raise refused
    netloc = host if port is None else f"{host}:{port}"
    return urllib.parse.urlunsplit(("https", netloc, parts.path.rstrip("/") + PATH, "", ""))


def version_of(manifest):
    """The version that a release's signed manifest names ("2026.11.538"), or "unknown". The manifest must name a
    release revision too, as lifecycle.released reads it."""
    try:
        said = json.loads(manifest)
    except (TypeError, ValueError, RecursionError):
        return "unknown"
    if not isinstance(said, dict) or not isinstance(said.get("revision"), str) \
            or not COMMIT.fullmatch(said["revision"]):
        return "unknown"
    version = said.get("version")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        return "unknown"            # never a commit's id either: it could be one fleet's own
    return version


def system_words():
    """The operating system as SYSTEM has it: one word and its version number ("ubuntu 24.04", "macOS 26.6"), or ""
    when the system gives no word that fits. On Linux the word is os-release's ID, the one word that names a
    distribution ("rhel", where NAME is "Red Hat Enterprise Linux"), up to its first character that is not a letter
    ("opensuse" of "opensuse-leap"); the number is the start of VERSION_ID, and a system with none (Arch) gives its
    word alone."""
    try:
        release = platform.freedesktop_os_release()
        word, number = release.get("ID", ""), release.get("VERSION_ID", "")
    except (OSError, ValueError, AttributeError):
        mac = platform.mac_ver()[0]
        word, number = ("macOS", mac) if mac else (platform.system(), platform.release())
    word, number = SYSTEM_WORD.match(str(word)), SYSTEM_NUMBER.match(str(number))
    if word is None:
        return ""
    text = f"{word.group()} {number.group()}" if number else word.group()
    return text if SYSTEM.fullmatch(text) else ""


def _number(value, low, high):
    return value if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high else None


def _time(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not EPOCH[0] <= value <= EPOCH[1]:
        return None
    return round(float(value), 3)


def _times(entry):
    """The count and the two times of a fault or a refused call, or None when one of them is out of shape."""
    count = _number(entry.get("count"), 1, diagnostics.COUNT_MOST)
    first, last = _time(entry.get("first")), _time(entry.get("last"))
    if count is None or first is None or last is None:
        return None
    return {"count": count, "first": first, "last": last}


def mark(name):
    """What a report carries for the name of a file of this code tree or of one of the hub's tools: the first 16
    hexadecimal characters of the SHA-256 of the name, so that no word goes (names() goes back)."""
    return hashlib.sha256(name.encode()).hexdigest()[:16]


def names(root=diagnostics.ROOT, tools=()):
    """Each mark that a report of this code can carry, with its name: every file under `root` that diagnostics.FILE
    takes, by its path inside `root`, and each of `tools` that diagnostics.NAME takes."""
    found = {}
    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        for file in files:
            path = os.path.relpath(os.path.join(folder, file), root).replace(os.sep, "/")
            if diagnostics.FILE.fullmatch(path):
                found[mark(path)] = path
    for tool in tools:
        if isinstance(tool, str) and diagnostics.NAME.fullmatch(tool):
            found[mark(tool)] = tool
    return found


def _frame(value):
    """A file of this code tree, as its mark, with its line (0 when Python gave none: diagnostics.place), or exactly
    ("lib", 0): a frame outside the tree, as diagnostics.py keeps it. Anything else is None."""
    if not isinstance(value, dict) or set(value) != {"file", "line"}:
        return None
    file, line = value.get("file"), value.get("line")
    if file == "lib" and _number(line, 0, 0) == 0:
        return {"file": "lib", "line": 0}
    line = _number(line, 0, diagnostics.LINE_MOST)
    if line is None or not isinstance(file, str) or not diagnostics.FILE.fullmatch(file):
        return None
    return {"file": mark(file), "line": line}


def _fault(entry):
    """One fault of diagnostics.view in the contract's shape, checked again, or None. Its class is one of the
    recorder's list, or "other": a name that code chose never goes."""
    frames = entry.get("frames")
    if not isinstance(frames, list) or not frames or len(frames) > diagnostics.MAX_FRAMES:
        return None
    frames = [_frame(f) for f in frames]
    times = _times(entry)
    name = entry.get("class")
    if None in frames or times is None or entry.get("program") not in diagnostics.PROGRAMS \
            or not isinstance(name, str) or not (name in diagnostics.CLASSES or name == "other"):
        return None
    name = name if name in THEIR_CLASSES else "other"
    errno, http = entry.get("errno"), entry.get("http")
    if errno is not None and _number(errno, 0, 100_000) is None or http is not None and _number(http, 100, 599) is None:
        return None
    return dict({"program": entry["program"], "class": name, "frames": frames, "errno": errno, "http": http}, **times)


def _stall(entry):
    """One stall of diagnostics.view as a fault of its kind's class (STALL_CLASSES), checked again, or None."""
    kind, frames = entry.get("kind"), entry.get("frames")
    name = STALL_CLASSES.get(kind) if isinstance(kind, str) else None
    if name is None or not isinstance(frames, list) or not frames or len(frames) > diagnostics.MAX_FRAMES:
        return None
    frames, times = [_frame(f) for f in frames], _times(entry)
    if None in frames or times is None:
        return None
    return dict({"program": "hub", "class": name if name in THEIR_CLASSES else "other", "frames": frames,
                 "errno": None, "http": None}, **times)


def _refusal(entry):
    """One refused call of diagnostics.view in the contract's shape, checked again, or None. Its tool goes as its
    mark, or as "other" when the recorder did not know it."""
    frame = _frame({"file": entry.get("file"), "line": entry.get("line")})
    times = _times(entry)
    tool = entry.get("tool")
    if frame is None or times is None or not isinstance(tool, str) or not diagnostics.NAME.fullmatch(tool):
        return None
    return dict({"tool": "other" if tool == "other" else mark(tool), "file": frame["file"], "line": frame["line"]},
                **times)


def _size(body):
    return len(json.dumps(body, separators=(",", ":")).encode())


def word(value, words):
    """`value` when it is a word of `words` (a copy of one of our side's lists), else "other"."""
    return value if isinstance(value, str) and value in words else "other"


def version_key(version):
    """A release's version as numbers to compare ("2026.11.538" is (2026, 11, 538)), or None for "unknown" and for any
    other text: the ids of two tracks do not order their releases, and a text does not either ("2026.11.99" is older
    than "2026.11.100")."""
    if not isinstance(version, str) or version == "unknown" or not VERSION.fullmatch(version):
        return None
    return tuple(int(part) for part in version.split("."))


def _count(value, most):
    """A count of the block, at most `most` (our side's bound: a higher count says as much as the bound), or None."""
    number = _number(value, 0, 2 ** 63)
    return None if number is None else min(number, most)


def machine_reading(cores=None):
    """The hub's own server as the block's `machine` needs it, from /proc: {"memory", "swap"} in MB (MemTotal and
    SwapTotal of MEMINFO), "cores" (os.cpu_count), "kills" (oom_kill of VMSTAT: the processes that the kernel ended for
    lack of memory since the machine started) and "boot" (the id of that start, BOOT_ID, which the hub keeps to know
    where the count of kills starts, and which never goes in a report). None where one of them cannot be read: a
    machine with no /proc (macOS, a test) sends no block at all, because every key of it is required and none of
    these could be said truly there."""
    try:
        with open(MEMINFO) as f:
            sizes = {line.split(":")[0]: int(line.split()[1]) for line in f if line.count(":") == 1
                     and len(line.split()) >= 2 and line.split()[1].isdigit()}
        with open(VMSTAT) as f:
            kills = [int(line.split()[1]) for line in f if line.split()[:1] == ["oom_kill"]
                     and len(line.split()) == 2 and line.split()[1].isdigit()]
        with open(BOOT_ID) as f:
            boot = f.read().strip()
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    cores = os.cpu_count() if cores is None else cores
    if "MemTotal" not in sizes or "SwapTotal" not in sizes or len(kills) != 1 or not boot or not cores:
        return None
    return {"memory": sizes["MemTotal"] // 1024, "swap": sizes["SwapTotal"] // 1024, "cores": cores,
            "kills": kills[0], "boot": boot[:64]}


def health(release, checks, machine):
    """The report's `health` block (the contract's "The health of a fleet") from the hub's readings, each value checked
    again against the contract: a word of a copy of our side's lists (word: "other" for any other), a version, a whole
    number in its range or a time (a time out of shape is null: it cannot be said). `release`: {newest, state, step,
    cause, tries, since, behind, channel}, where a step is None or a word and a cause None for "none"; `checks`:
    [{code, hub, servers, since}], each code once (a second of the same code is left out) and at most CHECKS_MOST,
    with no repair (`repairs` and `repaired` are 0: the root unit of W9 that makes them is not built); `machine`:
    {memory, swap, cores, ooms, starts}. None when a required value is out of shape: every key of the block is
    required, so then the report goes without it."""
    if not isinstance(release, dict) or not isinstance(checks, list) or not isinstance(machine, dict):
        return None
    newest, channel = release.get("newest"), release.get("channel")
    tries, behind = _count(release.get("tries"), NUMBER_MOST), _count(release.get("behind"), NUMBER_MOST)
    if not isinstance(newest, str) or not VERSION.fullmatch(newest) or tries is None or behind is None:
        return None
    step, cause = release.get("step"), release.get("cause")
    block = {"release": {"newest": newest, "state": word(release.get("state"), STATES),
                         "step": None if step is None else word(step, STEPS),
                         "cause": "none" if cause is None else word(cause, CAUSES), "tries": tries,
                         "since": _time(release.get("since")), "behind": behind,
                         "channel": channel if _number(channel, 100, 599) is not None else 0}}
    block["checks"], codes = [], set()
    for check in checks:
        if not isinstance(check, dict):
            continue
        code, hub = word(check.get("code"), CHECKS), check.get("hub")
        servers = _count(check.get("servers"), NUMBER_MOST)
        if code in codes or not (hub is None or isinstance(hub, bool)) or servers is None:
            continue
        codes.add(code)
        block["checks"].append({"code": code, "hub": hub, "servers": servers, "since": _time(check.get("since")),
                                "repairs": 0, "repaired": 0})
    block["checks"] = block["checks"][:CHECKS_MOST]
    sizes = [_number(machine.get("memory"), 1, 2 ** 63), _number(machine.get("swap"), 0, 2 ** 63),
             _number(machine.get("cores"), 1, 2 ** 63)]
    ooms, starts = _count(machine.get("ooms"), diagnostics.COUNT_MOST), _count(machine.get("starts"), NUMBER_MOST)
    if None in sizes or ooms is None or starts is None:
        return None
    block["machine"] = {"memory": min(sizes[0], MB_MOST), "swap": min(sizes[1], MB_MOST),
                        "cores": min(sizes[2], CORES_MOST), "ooms": ooms, "starts": starts}
    return block


def kinds(body):
    """The kinds of the faults that a report holds, its stalls left out: each the fault's class and the mark of its
    innermost file of the code tree ("lib" when none of its frames is in the tree), joined by ":", without the line,
    which moves with each release of the code. Sorted, each once (the hub's error_report_took)."""
    stalls, found = set(STALL_CLASSES.values()), set()
    for fault in (body or {}).get("faults") or []:
        if not isinstance(fault, dict) or fault.get("class") in stalls:
            continue
        files = [f.get("file") for f in fault.get("frames") or [] if isinstance(f, dict) and f.get("file") != "lib"]
        found.add(f"{fault.get('class')}:{files[-1] if files else 'lib'}")
    return sorted(found)


def day_of(t):
    """The UTC day of a time that a report may carry ("2026-11-26"), or None for any other value: a day, never a
    second, and made from a number, never from a text."""
    t = _time(t)
    return None if t is None else time.strftime("%Y-%m-%d", time.gmtime(t))


def funnel(firsts, taken, t0):
    """The report's `funnel` block: {step: day} for each step of FUNNEL_STEPS whose first time `firsts` gives
    ({step: seconds}), that no report that our side took carried (a key of `taken`), and whose time is at most a DAY
    ahead of `t0` (a step of a clock that ran ahead waits). A key that is not a step, and a time out of shape, are
    left out. None when no step waits: the report then has no block."""
    if not isinstance(firsts, dict):
        return None
    taken = taken if isinstance(taken, dict) else {}
    block = {}
    for step in FUNNEL_STEPS:
        first = firsts.get(step)
        day = day_of(first) if step not in taken and _time(first) is not None and first <= t0 + DAY else None
        if day is not None:
            block[step] = day
    return block or None


def report(fleet, version, system, code, agents, servers, view, since=0, health=None, funnel=None):
    """The day's report: the facts and the faults, stalls (as faults of STALL_CLASSES) and refused calls of `view`
    (diagnostics.view) whose last time is after `since`, at most MOST of each, and the oldest of them left out until
    the report is LIMIT bytes or less; `health`, the block that health() made, and `funnel`, the block that funnel()
    made, when there is one. None when a required fact is out of shape: then nothing goes."""
    if not isinstance(fleet, str) or not FLEET.fullmatch(fleet) or not isinstance(version, str) \
            or not VERSION.fullmatch(version):
        return None
    body = {"fleet": fleet, "from": "hub", "version": version}
    if isinstance(system, str) and SYSTEM.fullmatch(system):
        body["system"] = system
    if isinstance(code, str) and CODE.fullmatch(code):
        body["code"] = code
    for key, value in (("agents", agents), ("servers", servers)):
        if _number(value, 0, COUNT_MOST) is not None:
            body[key] = value
    if isinstance(health, dict):
        body["health"] = health
    if isinstance(funnel, dict) and funnel:
        body["funnel"] = funnel
    view = view if isinstance(view, dict) else {}

    def checked(key, check):
        given = view.get(key)
        given = given if isinstance(given, list) else []
        newer = [e for e in given if isinstance(e, dict) and (_time(e.get("last")) or 0) > since]
        return [x for x in map(check, newer) if x is not None]
    # a stall goes as a fault, after the faults: a run of stalls never pushes an exception out of the twenty
    body["faults"] = (checked("faults", _fault) + checked("stalls", _stall))[:MOST]
    body["refusals"] = checked("refusals", _refusal)[:MOST]
    stalls = set(STALL_CLASSES.values())
    while _size(body) > LIMIT and (body["faults"] or body["refusals"]):     # a stall goes first, then the oldest
        oldest = min((x.get("class") not in stalls, x["last"], key, i) for key in ("faults", "refusals")
                     for i, x in enumerate(body[key]))
        del body[oldest[2]][oldest[3]]
    return body


def due(on, sent, tried, hold, t, early=None, earlies=()):
    """Whether a report goes now, and which: "day" for the day's report, "early" for an early one, else None. Either
    goes only while error reports are on, our side holds nothing back and no try failed in the last RETRY seconds.
    The day's report goes when the last report that went is a DAY old or there was none; an early one when the hub
    asked for one (`early`: when it asked) and fewer than EARLY_MOST of `earlies`, the times of the early reports
    that went, are less than a DAY old (the plan's 3.3: at most four a day). A time more than a DAY after `t` was
    written while the clock was ahead, and counts as none, so that it cannot stop the reports for long; an early
    report up to a DAY ahead of `t` counts, so that a clock that went back gives no more early reports."""
    sent, tried, hold, early = (s if s and s <= t + DAY else None for s in (sent, tried, hold, early))
    if not on or (hold and t < hold) or (tried and sent != tried and t - tried < RETRY):
        return None
    if not sent or t - sent >= DAY:
        return "day"
    counted = sum(1 for e in earlies if isinstance(e, (int, float)) and t - e < DAY and e - t <= DAY)
    if early and counted < EARLY_MOST:
        return "early"
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an answer, never a second request: the report goes to the one address that endpoint checked."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send(url, body, timeout=None):
    """POST the report to `url` (endpoint(channel), or a test server's). Nothing when our side took it; ReportError
    when it refused it (retry_after: Retry-After for a 429, DAY for any other 4xx and for a 301 or a 308, RETRY for a
    5xx or another 3xx), could not be reached or gave no answer (retry_after None)."""
    request = urllib.request.Request(url, data=json.dumps(body, separators=(",", ":")).encode(), method="POST",
                                     headers={"Accept": "application/json", "Content-Type": "application/json",
                                              "User-Agent": "founderizer-hub"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    # The words name the host that endpoint checked: founderizer.com, or platform.founderizer.com since the platform
    # moved there (21 November 2026), or staging. It is our own host, never a value of the report.
    site = urllib.parse.urlsplit(url).hostname or "our site"
    try:
        with opener.open(request, timeout=timeout or TIMEOUT):
            pass                    # a 2xx: our side took it (a 3xx is an HTTPError here, because no redirect is followed)
    except urllib.error.HTTPError as answer:
        with answer:
            retry = DAY if 400 <= answer.code < 500 or answer.code in LASTING else RETRY
            if answer.code == 429:
                try:
                    retry = min(max(int(str(answer.headers.get("Retry-After") or "").strip()), 1), RETRY_MOST)
                except ValueError:
                    retry = RETRY
            raise ReportError(f"{site} answered {answer.code}", retry_after=retry, status=answer.code) \
                from None
    except urllib.error.URLError as e:          # the request did not get out: no connection, no name, no TLS
        raise ReportError(f"{site} cannot be reached: {str(e.reason)[:200]}") from None
    except (OSError, ValueError, http.client.HTTPException):    # it went, and no answer that HTTP reads came back
        raise ReportError(f"{site} gave no answer in time") from None


def main(argv):
    """`python3 errorreports.py names`: each mark that a report of this code can carry, with its name, one a line,
    for the reader of the kinds of error. Run it in the code of the report's version."""
    if argv != ["names"]:
        print("usage: python3 errorreports.py names", file=sys.stderr)
        return 2
    import hub          # its tool list; imported only here, because the hub itself imports this file
    for key, name in sorted(names(tools=[tool[1] for tool in hub.TOOLS]).items()):
        print(key, name)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

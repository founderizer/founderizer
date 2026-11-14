"""The hub's own faults and refused calls, kept as their kinds and their places in the code, never as their words.

The owner, 14 November 2026: "Pictures first (Recommended)" (build the hub's error recorder: error type and
file:line, no text) and, to the pictures of Report a problem and System status, "ok yes, make sure we include all
relevant inforamtion that is SAFE to send". The plan is ~/dev/founderizer-plans/feedback-diagnostics-plan.md, and
the review that it follows is ~/dev/founderizer-plans/audit/feedback-diagnostics-review-2026-11-14.md (sections 4.3
and 4.5).

**What a fault keeps, and nothing else:**

- the class of the exception, when its name is in CLASSES, else "other". Never its message: a message can hold a
  login, a path, a person's name or a stranger's words. Never the name of a class that is not on the list either,
  because code, a library or a page can choose that name;
- its errno and its HTTP status, when it has them: numbers in a range;
- at most MAX_FRAMES frames, the innermost last. Each frame is a file of this code tree with its line. A frame
  anywhere else is ("lib", 0), so no path of the machine, no user name and no library's version leaves the tree;
- how many times it came, and the first and the last time.

A refused call keeps the name of the tool (a name of the hub's own tool list, which the caller checks), the place
of the refusal (its innermost frame in the code tree), and the same count and times.

**record() and refused() are called from an `except` block.** Neither raises, neither takes a lock but its own, and
neither writes to a disk: they count in memory, and the hub's tick takes the counts with pending() and writes them.
So a handler that holds the hub's lock, or none, costs the same, and a database that refuses a write cannot make a
fault of its own handler. At most MAX_KINDS kinds wait between two takes; one more kind is not kept.

view() makes the owner route's answer from the stored rows, and checks every value again on its way out: a value
that does not have its type and its shape is left out. Standard library only, as hidden.py is."""

import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.error

ROOT = os.path.realpath(os.path.dirname(os.path.abspath(__file__)))
MAX_FRAMES = 12         # the innermost frames of a fault; the rest are cut
MAX_KINDS = 200         # kinds of faults, and kinds of refused calls, that wait in memory between two takes
MAX_SHOWN = 20          # faults, and refused calls, in one answer of view()

# The exception classes whose name a fault may carry. Any other class is "other".
CLASSES = frozenset((
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
PROGRAMS = ("hub",)
# A file of the code tree as its path inside the tree: letters, digits, "_", "-", "." and "/" only, ending ".py".
FILE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}(/[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}){0,3}\.py")
NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")      # a tool's name, and "other"
LINE_MOST = 10_000_000
COUNT_MOST = 1_000_000_000

_lock = threading.Lock()
_kinds = {}             # (kind, program, name, frames) -> [count, first, last, errno, http]
_held = {"fault": 0, "refusal": 0}      # how many kinds of each wait, so that refusals never crowd out a fault


def place(filename, line):
    """One frame as (file, line): a file of this code tree by its path inside the tree, else ("lib", 0)."""
    try:
        rel = os.path.relpath(os.path.realpath(filename), ROOT)
    except (TypeError, ValueError, OSError):
        return ("lib", 0)
    if rel.startswith(os.pardir) or os.path.isabs(rel) or ".." in rel.split(os.sep) or not FILE.fullmatch(rel):
        return ("lib", 0)
    return (rel, line if isinstance(line, int) and 0 < line < LINE_MOST else 0)


def places(tb):
    """The frames of a traceback as places, the innermost last, at most MAX_FRAMES of them. It reads no source
    file: the frame's own code object names its file."""
    raw = []
    while tb is not None:
        raw.append((tb.tb_frame.f_code.co_filename, tb.tb_lineno))
        tb = tb.tb_next
    return tuple(place(name, line) for name, line in raw[-MAX_FRAMES:])     # a deep recursion resolves 12 paths


def kind_of(exc):
    name = type(exc).__name__
    return name if name in CLASSES else "other"


def number(value, low, high):
    return value if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high else None


def errno_of(exc):
    return number(getattr(exc, "errno", None), 0, 100_000)


def http_of(exc):
    return number(exc.code, 100, 599) if isinstance(exc, urllib.error.HTTPError) else None


def _count(key, at, errno=None, http=None):
    with _lock:
        row = _kinds.get(key)
        if row is None:
            if _held.get(key[0], MAX_KINDS) >= MAX_KINDS:
                return
            _held[key[0]] += 1
            row = _kinds[key] = [0, at, at, None, None]
        row[0] += 1
        row[2] = max(row[2], at)
        if errno is not None:
            row[3] = errno
        if http is not None:
            row[4] = http


def record(program="hub", info=None, clock=time.time):
    """Count the exception that is being handled now (or `info`, an exc_info triple) as a fault of `program`."""
    try:
        _, exc, tb = info or sys.exc_info()
        if exc is None or program not in PROGRAMS:
            return
        _count(("fault", program, kind_of(exc), places(tb)), float(clock()), errno_of(exc), http_of(exc))
    except Exception:       # the recorder never raises: the handler that called it goes on as before
        pass


def refused(tool, info=None, clock=time.time):
    """Count a call that the hub refused: `tool`, a name of the hub's own tool list or "other", and the place of the
    refusal, the innermost frame of the exception being handled that is in the code tree."""
    try:
        if not isinstance(tool, str) or not NAME.fullmatch(tool):
            tool = "other"
        _, exc, tb = info or sys.exc_info()
        if exc is None:
            return
        inside = [p for p in places(tb) if p[0] != "lib"]
        site = inside[-1] if inside else ("lib", 0)
        _count(("refusal", "hub", tool, (site,)), float(clock()))
    except Exception:
        pass


def pending():
    """The counts since the last take, as rows, and nothing kept in memory after it."""
    global _kinds
    with _lock:
        taken, _kinds = _kinds, {}
        for kind in _held:
            _held[kind] = 0
    return [{"kind": k[0], "program": k[1], "name": k[2], "frames": [list(f) for f in k[3]], "count": v[0],
             "first": v[1], "last": v[2], "errno": v[3], "http": v[4]} for k, v in taken.items()]


def signature(kind, program, name, frames):
    """The key of one kind of fault or refusal: the same kind, program, name and frames give the same key."""
    text = json.dumps([kind, program, name, [list(f) for f in frames]], separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()[:24]


_code = {}


def code_id():
    """The code of this tree: a hash of every program file directly in it, tests left out. A release that changes
    one gives a new id, so the faults of the code before it end (the review, 4.9: a fault ends with its release),
    and the same code gives the same id at every start, whatever a process has imported. The hub reads it once,
    at its start (hub.main), before a release can move a file under it."""
    if "id" not in _code:
        digest = hashlib.sha256()
        try:
            names = sorted(n for n in os.listdir(ROOT) if n.endswith(".py") and not n.startswith("test_"))
        except OSError:
            names = []
        for name in names:
            try:
                with open(os.path.join(ROOT, name), "rb") as f:
                    digest.update(name.encode() + b"\0" + f.read() + b"\0")
            except OSError:
                continue
        _code["id"] = digest.hexdigest()[:24]
    return _code["id"]


def _frames(text):
    try:
        frames = json.loads(text)
    except (TypeError, ValueError, RecursionError):
        return None
    if not isinstance(frames, list) or not 1 <= len(frames) <= MAX_FRAMES:
        return None
    out = []
    for f in frames:
        if not (isinstance(f, list) and len(f) == 2 and isinstance(f[0], str)):
            return None
        line = number(f[1], 0, LINE_MOST - 1)
        if line is None or not (f[0] == "lib" and line == 0 or FILE.fullmatch(f[0]) and in_tree(f[0])):
            return None
        out.append({"file": f[0], "line": line})
    return out


def in_tree(name):
    """Whether a file of that name is in this code tree now."""
    try:
        return os.path.isfile(os.path.join(ROOT, name)) and place(os.path.join(ROOT, name), 1)[0] == name
    except (TypeError, ValueError, OSError):
        return False


def view(rows, tools=None):
    """The owner route's answer from the stored rows of this code: the newest faults and refused calls first, at
    most MAX_SHOWN of each. Every value is checked again here, and a row with one value out of shape is left out:
    a file must be in this code tree, and a refused call's tool in `tools` (the hub's own list) or "other"."""
    faults, refusals = [], []
    for r in sorted(rows, key=lambda r: r["last"] or 0, reverse=True):
        frames = _frames(r["frames"])
        count = number(r["count"], 1, COUNT_MOST)
        if frames is None or count is None or not isinstance(r["first"], (int, float)) \
                or not isinstance(r["last"], (int, float)):
            continue
        times = {"count": count, "first": round(float(r["first"]), 3), "last": round(float(r["last"]), 3)}
        if r["kind"] == "fault" and r["program"] in PROGRAMS and (r["name"] in CLASSES or r["name"] == "other"):
            if len(faults) < MAX_SHOWN:
                faults.append(dict({"program": r["program"], "class": r["name"], "frames": frames,
                                    "errno": number(r["errno"], 0, 100_000), "http": number(r["http"], 100, 599)},
                                   **times))
        elif r["kind"] == "refusal" and isinstance(r["name"], str) and NAME.fullmatch(r["name"]) and len(frames) == 1 \
                and (tools is None or r["name"] in tools or r["name"] == "other"):
            if len(refusals) < MAX_SHOWN:
                refusals.append(dict({"tool": r["name"], "file": frames[0]["file"], "line": frames[0]["line"]},
                                     **times))
    return {"faults": faults, "refusals": refusals}

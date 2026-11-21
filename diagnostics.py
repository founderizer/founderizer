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

**A stall names itself** (watch(), the thread "stall-watch" of the hub). On 20 November 2026 one thread of the hub
searched a delivery for logins in pure Python for about 4 minutes, every call of the hub ran about 100 times slower,
and nothing in the hub's own records said which code held it (the area "Hub core", ask 2 of that stall's evidence).
The watch keeps a stall as a fault keeps itself: its kind, the places of the thread that caused it, a count and
times, never a value. It is counted as kind "stall", which no app reads and no warning counts: the owner's screen has
no element for a stall yet.

view() makes the owner route's answer from the stored rows, and checks every value again on its way out: a value
that does not have its type and its shape is left out. Standard library only, as hidden.py is."""

import gc
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
_held = {"fault": 0, "refusal": 0, "stall": 0}     # kinds of each that wait: refusals and stalls never crowd out a fault


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


def _count(key, at, errno=None, http=None, times=1, first=None):
    """Count `key` `times` times at `at`, which came first at `first` (else at `at`); 0 times only moves its last
    time (a stall that goes on)."""
    first = at if first is None else first
    with _lock:
        row = _kinds.get(key)
        if row is None:
            if _held.get(key[0], MAX_KINDS) >= MAX_KINDS:
                return
            _held[key[0]] += 1
            row = _kinds[key] = [0, first, at, None, None]
        row[0] += times
        row[1] = min(row[1], first)
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
    """The owner route's answer from the stored rows of this code: the newest faults, refused calls and stalls first,
    at most MAX_SHOWN of each. Every value is checked again here, and a row with one value out of shape is left out:
    a file must be in this code tree, a refused call's tool in `tools` (the hub's own list) or "other", and a
    stall's kind one of STALLS."""
    faults, refusals, stalls = [], [], []
    for r in sorted(rows, key=lambda r: r["last"] or 0, reverse=True):
        frames = _frames(r["frames"])
        # a stall row that only went on is one stall: its first count was lost to a write that the database refused
        count = number(r["count"], 0 if r["kind"] == "stall" else 1, COUNT_MOST)
        if frames is None or count is None or not isinstance(r["first"], (int, float)) \
                or not isinstance(r["last"], (int, float)):
            continue
        times = {"count": max(count, 1), "first": round(float(r["first"]), 3), "last": round(float(r["last"]), 3)}
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
        elif r["kind"] == "stall" and r["program"] in PROGRAMS and r["name"] in STALLS:
            if len(stalls) < MAX_SHOWN:
                stalls.append(dict({"kind": r["name"], "frames": frames}, **times))
    return {"faults": faults, "refusals": refusals, "stalls": stalls}


# ---------------------------------------------------------------- a stall names itself (the area "Hub core")

STALL_TICK = 0.1        # seconds of the watch's sleep: its look after it waits for Python's interpreter lock
STALL_STEP = 1.0        # seconds between two readings of each thread's time on a CPU
STALL_HOLD = 2.0        # a look this many seconds late: for that long no other thread of Python ran
STALL_WINDOW = 10.0     # seconds over which the threads' time on a CPU is measured, sliding by STALL_STEP
STALL_SHARE = 0.5       # a process that ran this share of a window on a CPU stalls the hub. The owner's hub, 21
                        # November 2026, 69 to 80 threads: 0.004 to 0.12 of each window of 10 s
STALL_PART = 0.1        # a thread that a busy stall names ran this share of the window (that hub's busiest thread:
                        # 0.04 to 0.07)...
STALL_OF = 0.2          # ...and this share of the process's time in it, so that a bystander is not named
STALL_END = STALL_WINDOW    # a stall ends when nothing saw it for this many seconds: a thread's seconds stay in the
                            # window that long after it stops, so its tail and a stall near a bound are one stall
STALL_IDLE = 0.25       # a late look, or a window, in which the hub's process ran less than this share on a CPU
STALL_NAMED = 3         # threads named for one busy window, the most time first
STALL_ROWS = 100        # the newest stall rows that the table faults keeps (hub.fault_flush)
STALL_REST = 60.0       # seconds before the watch starts again after a fault of its own...
STALL_TRIES = 3         # ...and how many starts it has
TASKS = "/proc/self/task"
# What a stall is, as its row names it:
# - "busy": the process ran STALL_SHARE of a window on a CPU. In Python, each other thread waits for the interpreter
#   lock at each of its turns (on 20 November 2026 each call took about 100 times as long); in C code that lets the
#   lock go, it takes a CPU of the hub's machine. The places of the live threads that ran STALL_PART of it, the most
#   first, when the window ended, at most STALL_NAMED of them at a time; a thread's stall goes on while it runs
#   STALL_PART of the window and the process STALL_SHARE. With no such thread and no other stall (many threads that
#   each ran a little, or that ended), it has no place.
# - "hold": a look came STALL_HOLD late while the process ran: one thread held the interpreter lock in one call of C
#   code (a regular expression, json, sum). The thread that ran the most since the reading before the hold, with its
#   places at the look: the call has returned by then, so its innermost line can be the next one.
# - "collect": the same, while Python's garbage collector spent half of that time in full collections.
# - "paused": a late look, or a window whose looks were late for half of it by delays below STALL_HOLD, while the
#   process ran less than STALL_IDLE of that time: the machine gave the hub no CPU, slowed it or stopped it. No
#   thread is named.
# A stall that names no thread, and every stall on a system with no /proc, has the one place ("lib", 0).
STALLS = ("busy", "hold", "collect", "paused")
NO_PLACE = (("lib", 0),)

try:
    _TICKS = os.sysconf("SC_CLK_TCK")
except (AttributeError, ValueError, OSError):
    _TICKS = None


def thread_cpu(ids, tasks=TASKS):
    """Each thread's time on a CPU in seconds (user and system), by its native id, from Linux's /proc. A thread that
    ended is left out, and a system with no /proc (macOS) gives None."""
    if not _TICKS or not os.path.isdir(tasks):
        return None
    out = {}
    for n in ids:
        try:
            fd = os.open(os.path.join(tasks, str(n), "stat"), os.O_RDONLY)
            try:
                line = os.read(fd, 4096)
            finally:
                os.close(fd)
            fields = line[line.rindex(b")") + 2:].split()      # its name, in brackets, can hold spaces
            out[n] = (int(fields[11]) + int(fields[12])) / _TICKS
        except (OSError, ValueError, IndexError):
            continue
    return out


def frames_of(frame):
    """A frame and its callers as (file, line), the innermost first. It keeps no frame and calls nothing that lets
    the interpreter lock go, so every line is where its thread stood when the walk began."""
    out = []
    while frame is not None and len(out) < 1000:
        out.append((frame.f_code.co_filename, frame.f_lineno))
        frame = frame.f_back
    return out


def stack(raw):
    """frames_of's list as places, the innermost last: each run of frames outside the code tree is one ("lib", 0),
    and the innermost MAX_FRAMES are kept. Each file is resolved once."""
    names, out = {}, []
    for name, line in reversed(raw):
        if name not in names:
            names[name] = place(name, 1)[0]
        here = NO_PLACE[0] if names[name] == "lib" else \
            (names[name], line if isinstance(line, int) and 0 < line < LINE_MOST else 0)
        if here != NO_PLACE[0] or not out or out[-1] != here:
            out.append(here)
    return tuple(out[-MAX_FRAMES:])


def where(places):
    """"at hub.py 5574, from hub.py 74318": the innermost two places in the code tree, for the journal."""
    inside = [p for p in reversed(places) if p[0] != "lib"]
    if not inside:
        return "at no place in the code"
    return f"at {inside[0][0]} {inside[0][1]}" + (f", from {inside[1][0]} {inside[1][1]}" if len(inside) > 1 else "")


class Watch:
    """The stall watch between two looks (watch()). Its readers are arguments, so that a test gives its own."""

    def __init__(self, me=None, cpu=thread_cpu, frames=sys._current_frames, threads=threading.enumerate,
                 clock=time.monotonic, wall=time.time, process=time.process_time, out=None):
        self.me, self.cpu, self.frames, self.threads = me, cpu, frames, threads
        self.clock, self.wall, self.process, self.out = clock, wall, process, out
        self.lost = 0.0         # the seconds that the looks came late, all of them but holds and pauses
        self.readings = [self.reading()]        # (clock, process, lost, threads), one each STALL_STEP
        self.stalls = {}    # (native id, ident) of its thread, or its kind when it names none: [key, since, seen, first]
        # (since and seen on the clock, first on the wall clock: the row's first time)

    def read(self):
        """Each thread of Python but the watch: its time on a CPU and its ident, by its native id. None with no /proc."""
        idents = {t.native_id: t.ident for t in self.threads() if t.native_id is not None and t.native_id != self.me}
        cpu = self.cpu(idents)
        return None if cpu is None else {n: (s, idents[n]) for n, s in cpu.items() if n in idents}

    def reading(self, threads=None):
        return (self.clock(), self.process(), self.lost, self.read() if threads is None else threads)

    def raw(self):
        """The frames of every thread, read at once, by ident (frames_of)."""
        stacks = self.frames()
        try:
            return {ident: frames_of(frame) for ident, frame in stacks.items()}
        finally:
            stacks.clear()      # the dict holds this thread's own frame too: no cycle is left for the collector

    @staticmethod
    def ran(before, now, least, took, between=()):
        """(seconds, (native id, ident), alive) of each thread that ran `least` seconds or more on a CPU between two
        readings `took` seconds apart, the most first. A thread that ended in between counts up to the newest of the
        readings `between` that had it. A thread that is not in the first counts all of its time only when that is
        no more than `took`: else it was there before, and its time in between is not known."""
        if before is None or now is None:
            return []
        first = {(n, ident): seconds for n, (seconds, ident) in before.items()}
        newest = dict(first)
        for reading in between:
            newest.update({(n, ident): seconds for n, (seconds, ident) in (reading or {}).items()})
        alive = {(n, ident) for n, (seconds, ident) in now.items()}
        newest.update({(n, ident): seconds for n, (seconds, ident) in now.items()})
        ran = []
        for thread, seconds in newest.items():
            if thread in first:
                used = seconds - first[thread]
            elif seconds <= took + 0.05:
                used = seconds
            else:
                continue
            if used >= least:
                ran.append((used, thread, thread in alive))
        return sorted(ran, reverse=True)

    def look(self, late, used, collecting=0.0, inside=False):
        """One look, `late` seconds after the watch's sleep should have ended. In that time the hub's process ran
        `used` seconds on a CPU, and the garbage collector spent `collecting` seconds in full collections. `inside`:
        the hold came while the look before it read, so the newest reading may have been taken in the hold."""
        if late >= STALL_HOLD:
            raw = self.raw()        # first: the thread that held the lock goes on at the watch's next pause
            if used < STALL_IDLE * late:
                self.stall("paused", "paused", NO_PLACE, late)
            else:
                kind = "collect" if collecting >= late / 2 else "hold"
                before, now = self.readings[-2 if inside and len(self.readings) > 1 else -1], self.reading()
                ran = [r for r in self.ran(before[3], now[3], late / 2, now[0] - before[0])[:1] if r[2]]
                if not self.name(kind, ran, raw, late):
                    self.stall(kind, kind, NO_PLACE, late)
        else:       # a slow machine is many small delays: a hold or a pause is said already
            self.lost += max(late, 0.0)
        now = self.clock()
        if now - self.readings[-1][0] >= STALL_STEP:
            self.step(now)

    def step(self, now):
        """A reading, and the window from the newest reading that is STALL_WINDOW old: a window that a pause made
        longer than two is not measured, as late looks say what happened in it."""
        current = self.reading()
        self.readings.append(current)
        while len(self.readings) > 2 and self.readings[1][0] <= now - STALL_WINDOW:
            del self.readings[0]
        base, before = self.readings[0], self.readings[-2]
        took = current[0] - base[0]
        if STALL_WINDOW <= took <= 2 * STALL_WINDOW:
            process, lost = current[1] - base[1], current[2] - base[2]
            if process >= STALL_SHARE * took:
                least = max(STALL_PART * took, STALL_OF * process)
                ran = self.ran(base[3], current[3], least, took, [r[3] for r in self.readings[1:-1]])
                recent = {r[1] for r in self.ran(before[3], current[3], 0.005, current[0] - before[0])}
                going = [r[1] for r in ran if r[1] in self.stalls]
                running = [thread for thread in going if thread in recent]
                for thread in running:      # it ran since the reading before: its stall goes on
                    self.stall("busy", thread, None, took)
                new = [r for r in ran if r[2] and r[1] not in self.stalls][:max(STALL_NAMED - len(running), 0)]
                named = self.name("busy", new, self.raw()) if new else 0
                if not going and not named and set(self.stalls) <= {"busy"}:      # many threads that each ran a
                    self.stall("busy", "busy", NO_PLACE, min(took, process))        # little, or that ended
            elif lost >= STALL_SHARE * took and process < STALL_IDLE * took:
                self.stall("paused", "paused", NO_PLACE, took)
        for owner, (key, since, seen, first) in list(self.stalls.items()):
            if seen <= now - STALL_END:     # nothing saw it for STALL_END: it ended when it was seen last
                del self.stalls[owner]
                self.say(f"the hub's stall ({key[2]}) {where(key[3])} ended after about {seen - since:.0f} s")

    def name(self, kind, ran, raw, took=None):
        """Count a stall of `kind` for each thread of `ran` whose frames `raw` holds, with its places, which began
        `took` seconds ago, or (a busy thread) as many seconds ago as the thread ran. How many it named."""
        found = [(thread, stack(raw[thread[1]]), used) for used, thread, _ in ran if thread[1] in raw]
        for thread, places, used in found:
            self.stall(kind, thread, places, used if took is None else took)
        return len(found)

    def stall(self, kind, owner, places, took):
        """A new stall, which began `took` seconds ago, is counted once and said in the journal; one that goes on
        moves its row's last time and keeps its first, so that one stall's row says how long it lasted."""
        now, at = self.clock(), self.wall()
        held = self.stalls.get(owner)
        if held is None:
            key = ("stall", "hub", kind, places)
            held = self.stalls[owner] = [key, now - max(took, 0.0), now, at - max(took, 0.0)]
            _count(key, held[3])
            self.say(f"WARNING: the hub stalls ({kind}) {where(places)}")
        held[2] = now
        _count(held[0], at, first=held[3], times=0)

    def say(self, line):
        try:
            print(line, file=self.out or sys.stderr, flush=True)
        except Exception:       # a journal that cannot take the line: the row keeps the stall
            pass


_gc = {"start": None, "spent": 0.0}     # the seconds of full collections, all of them (_gc_timer)


def _gc_timer(phase, info):
    """gc.callbacks: the time of each full collection (its oldest generation), in whichever thread runs it."""
    try:
        if info.get("generation") != 2:
            return
        if phase == "start":
            _gc["start"] = time.monotonic()
        elif _gc["start"] is not None:
            _gc["spent"] += time.monotonic() - _gc["start"]
            _gc["start"] = None
    except Exception:       # the collector goes on whatever this says
        pass


_watching = {"thread": None}
_watch_lock = threading.Lock()


def watch(stop=None, tick=STALL_TICK, make=Watch, rest=STALL_REST):
    """The stall watch: a look every `tick` seconds until `stop` is set. Each look comes back only once this thread
    holds Python's interpreter lock again, so its delay is the time that other threads held it (or that the machine
    gave the hub no CPU); a look that itself took STALL_HOLD (a hold that came while it read) is a late look too.
    time.sleep, because a lock's timed wait follows the wall clock before Python 3.11. A fault of the watch is
    counted, and the watch starts again `rest` seconds later, STALL_TRIES times in all: no fault comes ten times a
    second, and one fault does not end it."""
    stop = stop or threading.Event()
    for _ in range(STALL_TRIES):
        try:
            w = make(me=threading.get_native_id())
            while not stop.is_set():
                used, collecting, t0 = time.process_time(), _gc["spent"], time.monotonic()
                time.sleep(tick)
                t1, u1, g1 = time.monotonic(), time.process_time(), _gc["spent"]
                w.look(t1 - t0 - tick, u1 - used, g1 - collecting)
                inside = time.monotonic() - t1
                if inside >= STALL_HOLD:
                    w.look(inside, time.process_time() - u1, _gc["spent"] - g1, inside=True)
            return
        except Exception:
            record("hub")
            if stop.wait(rest):
                return


def watch_stalls():
    """Start the hub's stall watch once (hub.main): a thread of its own, which runs while the hub runs, and the timer
    of the garbage collector's full collections."""
    with _watch_lock:
        if _watching["thread"] is None:
            gc.callbacks.append(_gc_timer)
            _watching["thread"] = threading.Thread(target=watch, name="stall-watch", daemon=True)
            _watching["thread"].start()

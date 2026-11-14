"""Read numeric CLI usage only. No prompts, provider credentials, or inference.

The helper runs this collector on a separate thread. Provider reads are limited
to one attempt per five minutes; transcript scans have size and time bounds, and
each scan reads only what the transcripts gained since the last one.
"""
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import sqlite3
import subprocess
import threading
import time

import lifecycle

POLL_SECONDS = 300
SCAN_SECONDS = 30
SCAN_TIME = 10                      # seconds that one scan reads, and MAX_BYTES its bytes: a scan that needs more
MAX_BYTES = 256 * 1024 * 1024       # goes on at the next one (Scan), and none gives a partial total
MAX_LINE = 4 * 1024 * 1024
MAX_ROW = 32 * 1024 * 1024          # a longer transcript line is passed over: no token record is that long
TAIL = 64                           # the bytes before where a file's reading stopped, to see that they are still there
TOKEN_KEYS = ("input", "output", "cache_read", "cache_write")
BY_SESSION = 500                    # per-session totals in one report: the newest sessions
SESSION_ID = re.compile(r"[A-Za-z0-9._:-]{1,80}")
SESSION_FIELDS = ("session_id", "total", "last_activity")
# Helper feature session_kinds (AUTONOMY.md P8): each session's four kinds of tokens apart, its model calls, the model
# of its newest call and the share of its first call that came from the cache. They go only to a hub whose last
# answer said that it takes them, so that the release before it never refuses a report (Collector.send).
SESSION_KINDS = ("input", "cache_read", "cache_write", "output", "calls", "model", "first_cache_share")
# Helper feature session_models (AUTONOMY.md P8 and decision 41): each session's tokens by model, its sub-agents' and
# workflow agents' with them, as "models": [[model, input, cache_read, cache_write, output, calls], ...], the largest
# first. A workflow agent often runs another model than its session, and the hub prices each model at its own weights.
# They too go only to a hub whose last answer said that it takes them (Collector.send).
MODEL_FIELDS = ("input", "cache_read", "cache_write", "output", "calls")
MODELS_MAX = 8                      # a session's models in one report: past it, the smallest fold into one of no model
REPORT_MAX = 512 * 1024             # hub.USAGE_REPORT_MAX: a report with the models past it goes with the kinds only
MODEL = re.compile(r"[A-Za-z0-9._:/\[\]-]{1,120}")      # threads.Translator.model_record takes the same names
SCOPE = "Retained Fleet workspace sessions"
SOURCES = {"claude": "Claude Code transcripts", "codex": "Codex session records"}
# The third source (the AI providers build spec, section 3.7): each runtime of driver acp, whose runner keeps the
# tokens of a session in a file of its own, ~/.fleet/acp/<fleet session>.json (acp_runner.Usage).
ACP_SOURCE = "ACP session records"
SOURCES.update({name: ACP_SOURCE for name, entry in lifecycle.RUNTIMES.items() if entry["driver"] == "acp"})
ACP_FILES = ".fleet/acp"
ACP_FILE_MAX = 256 * 1024           # a usage file is numbers and model names: a longer one is no usage file
ACP_FILES_MAX = 20000               # the files of one scan; more are a fault, and the reading fails as a whole
LIMIT_SOURCES = {"claude": "Claude Code /usage cache", "codex": "Codex account/rateLimits/read"}
SCREEN_SOURCE = "Codex screen task events"
SCREEN_SCOPE = "Recorded Fleet screen tasks"
NO_WINDOWS = "No account limits were reported."      # the runtime named its account, but gave no allowance window
SIGN_IN_REQUIRED = "CLI sign-in is required."        # the runtime itself said that it has no signed-in account
IDENTITY_CHANGED = "The signed-in account changed."  # the runtime named an account that this kept reading is not known to be
# A kept reading with one of these is history only: it is not the allowance of the runtime's account now.
IDENTITY_ERRORS = (SIGN_IN_REQUIRED, IDENTITY_CHANGED)
ERRORS = {"Token records could not be read.", "Account limits could not be refreshed.",
          SIGN_IN_REQUIRED, IDENTITY_CHANGED, "Account limit data is not current.", NO_WINDOWS}
EMAIL = re.compile(r"[^\s@\x00-\x1f\x7f-\x9f]+@[^\s@\x00-\x1f\x7f-\x9f]+")


class SignedOut(ValueError):
    """The runtime itself says that it has no signed-in account. This is no failed refresh: a reading that is kept is
    then no longer the runtime's identity."""


class SignInAgain(SignedOut):
    """The runtime keeps a sign-in, and the provider ended it: its status command still says "signed in", and no turn
    of a session can run (codex_limits). The other SignedOut, a runtime that keeps no account, is what its status
    command says too."""


class Unrefreshed(ValueError):
    """The limits could not be read, but the runtime itself named its account before that: email is that account's
    email, "" for an account without one (for example an API key)."""

    def __init__(self, email):
        super().__init__("limits not refreshed")
        self.email = email


def number(value, integer=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 2**53 - 1:
        raise ValueError("invalid number")
    if integer and not isinstance(value, int):
        raise ValueError("invalid count")
    return value


def timestamp(value):
    if isinstance(value, str):
        try:
            return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return number(value) if value is not None else None


def read_json(path, limit=4 * 1024 * 1024):
    with open(path, "rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("file too large")
    return json.loads(raw)


def account_key(provider, identity):
    return provider + ":" + hashlib.sha256((provider + ":" + identity).encode()).hexdigest()[:32] if identity else None


class ScanPending(ValueError):
    """A scan reached SCAN_TIME or MAX_BYTES before the end of the transcripts. Its Scan keeps what it read and the
    next scan goes on from there, so no scan gives a partial total."""


class Scan:
    """What one runtime's transcripts gave, file by file, from one scan to the next. A scan of every file every 30
    seconds failed as a whole at 5,000 files, 256 MiB or 10 seconds (the review of 29 October 2026), and every
    workflow agent writes a file of its own. So a file with the same identity, size and change time is not read again,
    one that grew is read on from where the last scan stopped, and one that changed before that point from its start.
    A scan reads at least one line, so the scans after it always reach the end."""

    def __init__(self):
        self.files = {}         # path -> its File
        self.read = 0           # the bytes of the lines that the last scan read
        self.made, self.stale = None, True      # the reading of the files as they are, unless one changed since


class File:
    """Where the reading of one transcript file stands, and what its complete lines gave (its records)."""
    __slots__ = ("mark", "done", "offset", "tail", "index", "records")

    def __init__(self, records):
        self.mark, self.done, self.offset, self.tail, self.index, self.records = None, False, 0, b"", 0, records


def in_checkout(cwd, kit):
    """A folder that is the checkout or inside it, where a sub-agent's worktree of the checkout lies too."""
    return isinstance(cwd, str) and (cwd == kit or cwd.startswith(kit.rstrip("/") + "/"))


def model_name(value):
    return value if isinstance(value, str) and MODEL.fullmatch(value) else None


def earliest(a, b):
    return b if a is None else a if b is None else min(a, b)


def latest(a, b):
    return b if a is None else a if b is None else max(a, b)


def spend(models, model, values):
    """One call of `model` into {model: MODEL_FIELDS}: its input, cache reads, cache writes and output, and one call
    when it read or wrote any token."""
    bucket = models.setdefault(model, [0] * len(MODEL_FIELDS))
    bucket[:] = [a + b for a, b in zip(bucket, [*values, int(any(values))])]


class ClaudeRecords:
    """One Claude transcript: each API message once, with the largest kinds that its blocks gave (several blocks of
    one message are one call), and for each session that its rows name whether the session ran in the checkout, its
    time span, its own first call and the model of its own newest. A sub-agent's and a workflow agent's rows carry the
    root session's id and their own model (AUTONOMY.md decision 41)."""
    __slots__ = ("calls", "sessions")

    def __init__(self):
        self.calls = {}         # message id -> [session, model, own, input, output, cache_read, cache_write]
        self.sessions = {}      # session -> [ran in the checkout, since, last, (time, message) of its own first call,
                                #             (time, model) of its own newest call]

    @staticmethod
    def wants(index, line):
        return b'"assistant"' in line           # a line without it holds no token record

    @staticmethod
    def reads_on():
        return True

    def take(self, index, row, kit):
        if row.get("type") != "assistant":
            return
        message = row.get("message") or {}
        usage, key, sid = message.get("usage"), message.get("id"), row.get("sessionId")
        if not usage or not isinstance(key, str) or not isinstance(sid, str):
            return
        values = [number(usage.get(k, 0), True) for k in
                  ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")]
        model, own, ts = model_name(message.get("model")), not row.get("isSidechain"), timestamp(row.get("timestamp"))
        call = self.calls.get(key)
        if call is None:
            self.calls[key] = [sid, model, own, *values]
        else:
            call[3:] = [max(a, b) for a, b in zip(call[3:], values)]
        # A session is the checkout's when any of its rows ran there: a row's folder is the session's folder at that
        # moment, which a change of folder or a sub-agent's worktree moves away from the checkout
        s = self.sessions.setdefault(sid, [False, None, None, None, None])
        s[0], s[1], s[2] = s[0] or in_checkout(row.get("cwd"), kit), earliest(s[1], ts), latest(s[2], ts)
        if own:
            s[3] = s[3] or (ts, key)
            s[4] = (ts, model) if model else s[4]


def claude_sessions(files):
    """{session: what it spent} for the sessions that ran in the checkout, with their sub-agents' and workflow
    agents' calls, and how many there are. Each message counts once over every file: a resumed or forked session's
    file can copy another's."""
    calls, sessions = {}, {}
    for path in sorted(files):
        records = files[path].records
        for key, call in records.calls.items():
            known = calls.get(key)
            if known is None:
                calls[key] = list(call)
            else:
                known[3:] = [max(a, b) for a, b in zip(known[3:], call[3:])]
        for sid, s in records.sessions.items():
            t = sessions.setdefault(sid, [False, None, None, None, None])
            t[0], t[1], t[2] = t[0] or s[0], earliest(t[1], s[1]), latest(t[2], s[2])
            if s[3] and (t[3] is None or (s[3][0] or math.inf) < (t[3][0] or math.inf)):
                t[3] = s[3]
            if s[4] and (t[4] is None or (s[4][0] or 0) >= (t[4][0] or 0)):
                t[4] = s[4]
    per = {}
    for sid, model, own, i, o, r, w in calls.values():
        if sessions[sid][0]:
            spend(per.setdefault(sid, {"models": {}})["models"], model, [i, r, w, o])
    for sid, s in per.items():
        t = sessions[sid]
        s.update(since=t[1], last=t[2], model=t[4][1] if t[4] else None, first=calls[t[3][1]][3:] if t[3] else None)
    return per, len(per)


CODEX_KEYS = ("input_tokens", "output_tokens", "cached_input_tokens", "cache_write_input_tokens")


class CodexRecords:
    """One Codex rollout: its thread, the session that it is part of, whether it ran in the checkout, and its own
    calls by model. A forked sub-agent's rollout starts with a copy of its parent's history (threads.codex_own_start),
    whose calls are the parent's: its own rows start at the ordinal that its first line gives (Codex 0.163 and later),
    or else at its first turn that started at the fork. A call counts once, with its own usage: a running total is
    given again, and an older Codex that resumes a session in the same file starts it again from nothing."""
    __slots__ = ("thread", "root", "parent", "ours", "start", "fork", "model", "newest", "total", "models", "first",
                 "since", "last")

    def __init__(self):
        self.thread = self.root = self.parent = self.start = self.fork = self.model = self.newest = None
        self.total = self.first = self.since = self.last = None
        self.ours, self.models = False, {}

    @staticmethod
    def wants(index, line):
        return index == 0 or b'"token_count"' in line or b'"turn_context"' in line or b'"task_started"' in line

    def reads_on(self):
        return self.ours        # another folder's rollout: its first line says all that it is to this checkout

    def take(self, index, row, kit):
        kind = row.get("type")
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        if index == 0:
            if kind == "session_meta" and isinstance(payload.get("id"), str):
                self.identify(payload, timestamp(row.get("timestamp")), kit)
            return
        event = payload.get("type") if kind == "event_msg" else None
        if self.start is None and event == "task_started":
            began = payload.get("started_at")       # whole seconds: up to a second before the file's first line
            if self.fork is None or not isinstance(began, (int, float)) or began >= self.fork - 2:
                self.start = index
        if self.start is None or index < self.start:
            if event == "token_count":              # the copied running total, which a fork can go on from
                self.total = self.running(payload) or self.total
        elif kind == "turn_context":                # the model of the calls that follow
            self.model = model_name(payload.get("model"))
            self.newest = self.model or self.newest
        elif event == "token_count":
            self.count(payload, timestamp(row.get("timestamp")))

    def identify(self, meta, at, kit):
        """Its first line: the thread, its root session (Codex 0.163 and later name it; an older one names only the
        parent, as the fork's or as the spawn's), whether it ran in the checkout, and where its own rows start."""
        source = meta.get("source")
        spawn = (source.get("subagent") or {}) if isinstance(source, dict) else {}
        spawn = spawn.get("thread_spawn") if isinstance(spawn, dict) else None
        parent = meta.get("forked_from_id") or meta.get("parent_thread_id") or \
            (spawn.get("parent_thread_id") if isinstance(spawn, dict) else None)
        self.thread, self.ours, self.fork = meta["id"], in_checkout(meta.get("cwd"), kit), at
        self.root = meta["session_id"] if isinstance(meta.get("session_id"), str) else None
        self.parent = parent if isinstance(parent, str) else None
        ordinal = meta.get("subagent_history_start_ordinal")
        if isinstance(ordinal, int) and not isinstance(ordinal, bool) and ordinal >= 1:
            self.start = ordinal
        elif not meta.get("forked_from_id"):
            self.start = 1                          # no copied history: every row after this one is its own

    @staticmethod
    def running(payload):
        usage = (payload.get("info") or {}).get("total_token_usage")
        return tuple(number(usage.get(k, 0), True) for k in CODEX_KEYS) if usage else None

    def count(self, payload, ts):
        total = self.running(payload)
        if total is None or total == self.total:
            return                                  # no usage yet, or the same running total again: no new call
        last = (payload.get("info") or {}).get("last_token_usage")
        if last:                                    # the call's own usage (Codex 0.159 and later)
            call = tuple(number(last.get(k, 0), True) for k in CODEX_KEYS)
        elif self.total and all(a >= b for a, b in zip(total, self.total)):
            call = tuple(a - b for a, b in zip(total, self.total))
        else:
            call = total                            # the running total started again
        raw, out, read, write = call
        values = [number(raw - read - write, True), read, write, out]
        self.total = total
        spend(self.models, self.model, values)
        if self.first is None and raw:
            self.first = [values[0], out, read, write]
        self.since, self.last = earliest(self.since, ts), latest(self.last, ts)


def codex_sessions(files):
    """{session: what it spent} for the sessions that ran in the checkout, each sub-agent's calls in its root session,
    and how many threads spent: a sub-agent's thread counts as one of them, as before."""
    threads = {}
    for path in sorted(files):
        r = files[path].records
        if r.thread is not None and (r.thread not in threads or held(r) > held(threads[r.thread])):
            threads[r.thread] = r                   # two files of one thread: the one that holds more

    def root_of(r, depth=0):
        up = r.root if r.root and r.root != r.thread else r.parent
        if not up or up == r.thread or depth > 32:
            return r.thread
        return root_of(threads[up], depth + 1) if up in threads else up
    per, spent = {}, 0
    for r in threads.values():
        root = root_of(r) if r.models else None
        top = threads.get(root)
        if root is None or not (top.ours if top else r.ours):
            continue
        s = per.setdefault(root, {"models": {}, "since": None, "last": None, "first": None, "model": None})
        for model, values in r.models.items():
            bucket = s["models"].setdefault(model, [0] * len(MODEL_FIELDS))
            bucket[:] = [a + b for a, b in zip(bucket, values)]
        s["since"], s["last"], spent = earliest(s["since"], r.since), latest(s["last"], r.last), spent + 1
    for root, s in per.items():
        if root in threads:                         # the session's own first call and newest model, not an agent's
            s["first"], s["model"] = threads[root].first, threads[root].newest
    return per, spent


def held(records):
    """What a Codex rollout holds: its tokens, then its calls."""
    return (sum(sum(v[:4]) for v in records.models.values()), sum(v[4] for v in records.models.values()))


def model_rows(models):
    """A session's {model: MODEL_FIELDS} as report rows, the largest first and none that spent nothing; past
    MODELS_MAX the smallest fold into one row of no model, which the hub prices at its runtime's default."""
    rows = sorted(([model, *values] for model, values in models.items() if any(values[:4])),
                  key=lambda row: (-sum(row[1:5]), row[0] is None, row[0] or ""))
    if len(rows) > MODELS_MAX:
        keep = [row for row in rows if row[0] is not None][:MODELS_MAX - 1]
        rows = keep + [[None, *map(sum, zip(*(row[1:] for row in rows if row not in keep)))]]
    return rows


def token_reading(runtime, per, spent):
    """The tokens of every counted session in total, and the newest BY_SESSION sessions each with its own."""
    if not per:
        return None
    for s in per.values():
        s["kinds"] = [sum(column) for column in zip(*s["models"].values())] or [0] * len(MODEL_FIELDS)
    input_, cache_read, cache_write, output, _ = (sum(column) for column in zip(*(s["kinds"] for s in per.values())))
    newest = sorted(per, key=lambda sid: per[sid]["last"] or 0, reverse=True)[:BY_SESSION]
    since = [s["since"] for s in per.values() if s["since"] is not None]
    last = [s["last"] for s in per.values() if s["last"] is not None]
    return dict(input=input_, output=output, cache_read=cache_read, cache_write=cache_write,
                total=input_ + output + cache_read + cache_write, sessions=spent, since=min(since, default=None),
                last_activity=max(last, default=None), collected_at=time.time(), source=SOURCES[runtime], scope=SCOPE,
                error=None, by_session=[session_row(sid, per[sid]) for sid in newest])


def session_row(sid, s):
    input_, cache_read, cache_write, output, calls = s["kinds"]
    return {"session_id": sid, "total": input_ + cache_read + cache_write + output, "last_activity": s["last"],
            "input": input_, "output": output, "cache_read": cache_read, "cache_write": cache_write, "calls": calls,
            "model": s["model"], "first_cache_share": cache_share(s["first"]) if s["first"] else None,
            "models": model_rows(s["models"])}


def holds(stream, f):
    """The bytes before where the reading of `f` stopped are still there: the file has only grown since."""
    if not f.offset:
        return True
    stream.seek(f.offset - len(f.tail))
    return stream.read(len(f.tail)) == f.tail


def read_on(scan, f, stream, size, kit, deadline):
    """Read the complete lines of `stream` after f.offset, up to the size that the file had when it was listed. A line
    that can hold a token record is parsed whole, and one longer than MAX_ROW, or a whole one that is not JSON or not
    of a record's shape, is passed over. A scan past its bounds stops between two lines (ScanPending), and a line that a writer is still
    finishing is read at a later scan."""
    while f.offset < size:
        if scan.read and (scan.read >= MAX_BYTES or time.monotonic() > deadline):
            raise ScanPending("scan limit")
        if f.index and not f.records.reads_on():
            break
        line = stream.readline(MAX_ROW + 1)
        length, tail, whole = len(line), (f.tail + line)[-TAIL:], line.endswith(b"\n")
        if length > MAX_ROW:                        # no token record is that long: passed over to its end
            chunk = line
            while chunk and not chunk.endswith(b"\n"):
                chunk = stream.readline(MAX_ROW + 1)
                length, tail = length + len(chunk), (tail + chunk)[-TAIL:]
            line, whole = None, chunk.endswith(b"\n")
        scan.read += length
        if not whole:
            break                                   # a writer can still be finishing the last record
        if line is not None and f.records.wants(f.index, line):
            try:
                row = json.loads(line)
            except ValueError:
                row = None                          # its offset moves past it, so no later scan stops at it again
            if isinstance(row, dict):
                try:
                    f.records.take(f.index, row, kit)
                except (AttributeError, KeyError, TypeError, ValueError):
                    pass                            # a row of another shape is passed over in the same way
        f.offset, f.tail, f.index = f.offset + length, tail, f.index + 1
    f.done = True


def read_files(scan, root, kit, records):
    """Bring `scan` up to date with the transcript files below `root`, within one scan's bounds."""
    deadline, scan.read, listed = time.monotonic() + SCAN_TIME, 0, set()
    for path in sorted(root.glob("**/*.jsonl")):
        try:
            if path.is_symlink():
                continue
            info = path.stat()
            mark = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            known = scan.files.get(path)
            listed.add(path)
            if known and known.mark == mark and known.done:
                continue
            scan.stale = True
            with path.open("rb") as stream:
                if not (known and known.mark and known.mark[:2] == mark[:2] and
                        (info.st_size > known.offset or known.mark == mark) and holds(stream, known)):
                    known = scan.files[path] = File(records())
                known.mark, known.done = mark, False
                stream.seek(known.offset)
                read_on(scan, known, stream, info.st_size, kit, deadline)
        except FileNotFoundError:
            listed.discard(path)                    # gone since it was listed
    for path in set(scan.files) - listed:
        del scan.files[path]
        scan.stale = True


def acp_sessions(home, kit, runtime):
    """{session: what it spent} from the usage files of this runtime's ACP sessions whose `kit` is this checkout, and
    how many sessions spent any token, as claude_sessions gives them. A file is written whole at each change, so each
    is read whole; one that is no usage file of this checkout and runtime is passed over."""
    per, folder = {}, Path(home) / ACP_FILES
    try:
        paths = sorted(p for p in folder.iterdir() if p.suffix == ".json")
    except OSError:
        return per, 0
    if len(paths) > ACP_FILES_MAX:
        raise ValueError("too many usage files")
    for path in paths:
        try:
            if path.is_symlink() or path.stat().st_size > ACP_FILE_MAX:
                continue
            data = json.loads(path.read_bytes())
        except (OSError, ValueError):
            continue
        sid = data.get("session_id") if isinstance(data, dict) else None
        if not isinstance(sid, str) or not SESSION_ID.fullmatch(sid) or data.get("kit") != kit or \
                data.get("runtime") != runtime or not isinstance(data.get("models"), dict):
            continue
        try:
            models = {}
            for name, row in data["models"].items():
                values = [number(v, True) for v in row]
                if len(values) != len(MODEL_FIELDS):
                    raise ValueError("invalid row")
                if not any(values[:4]):
                    continue            # a row with calls and no token is no row of a report (validate_models)
                bucket = models.setdefault(model_name(name), [0] * len(MODEL_FIELDS))   # a name of no model: none
                bucket[:] = [a + b for a, b in zip(bucket, values)]
            first = data.get("first")
            first = [number(v, True) for v in first] if isinstance(first, list) and len(first) == 4 else None
            since, last = (None if data.get(k) is None else number(data[k]) for k in ("since", "last"))
        except (ValueError, TypeError):
            continue
        if not any(any(row[:4]) for row in models.values()):
            continue
        # `first` is in the order of MODEL_FIELDS (input, cache_read, cache_write, output); cache_share reads the
        # order of TOKEN_KEYS (input, output, cache_read, cache_write)
        per[sid] = {"models": models, "since": since, "last": last, "model": model_name(data.get("model")),
                    "first": [first[0], first[3], first[1], first[2]] if first else None}
    return per, len(per)


def transcript_tokens(runtime, kit, home=None, scan=None):
    """The tokens of the retained sessions that ran in the checkout `kit`: in total, and each of the newest sessions
    its own, with its sub-agents' and workflow agents' calls and each model apart (helper feature session_models).
    `scan` keeps what earlier scans read (Scan). A scan that reaches its bounds raises ScanPending, so a reading that
    needs more than one scan and has no Scan to go on with fails, as a scan of every file did before."""
    home, kit = Path(home or Path.home()), str(Path(kit).resolve())
    scan = Scan() if scan is None else scan
    if lifecycle.runtime_fact(runtime, "driver") == "acp":
        # the runner's own files, each small and written whole: every reading reads them again
        made = token_reading(runtime, *acp_sessions(home, kit, runtime))
        return dict(made, collected_at=time.time()) if made else None
    if runtime == "claude":
        # Every level below the project folder: a subagent's transcript is <session>/subagents/agent-<id>.jsonl, and
        # a workflow agent's <session>/subagents/workflows/<run>/agent-<id>.jsonl (AUTONOMY.md decision 41), whose
        # rows carry the root session's id and their own usage and model, so they count in that session's totals
        read_files(scan, home / ".claude/projects" / re.sub(r"[^A-Za-z0-9-]", "-", kit), kit, ClaudeRecords)
    else:
        read_files(scan, home / ".codex/sessions", kit, CodexRecords)
    if scan.stale:
        scan.made = token_reading(runtime, *(claude_sessions if runtime == "claude" else codex_sessions)(scan.files))
        scan.stale = False
    return dict(scan.made, collected_at=time.time()) if scan.made else None


def cache_share(values):
    """The share of one call's input that it read from the cache, from its four kinds in TOKEN_KEYS order: cache
    reads against everything it read (input, cache reads, cache writes). None for a call that read nothing."""
    read = values[0] + values[2] + values[3]
    return round(values[2] / read, 4) if read else None


def run_json(args, cwd, timeout=25, ok=(0,)):
    # Anonymous temporary files bound RAM even if a CLI emits unexpected output.
    # No output or provider error is printed or persisted by the collector.
    import tempfile
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(args, cwd=cwd, stdout=output, stderr=subprocess.DEVNULL,
                                   stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            process.wait(timeout=timeout)
        finally:
            if process.poll() is None:
                import signal
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        if process.returncode not in ok or output.tell() > MAX_LINE:
            raise ValueError("CLI read failed")
        output.seek(0)
        return json.load(output)


# What Codex answers when its stored sign-in is over at the provider: the refresh token was revoked, has expired or was
# used a second time, or the account signed in again somewhere else. `codex login status` still says "Logged in" then,
# because it reads only the file of the sign-in, and each turn of a session fails. The first form is from the owner's
# own Mac Studio on 13 November 2026 (Codex 0.166.0), in the answer to account/read: "Your access token could not be
# refreshed because your refresh token was revoked. Please log out and sign in again." The same machine's
# account/rateLimits/read named the provider's own code, token_revoked.
SIGN_IN_AGAIN = re.compile(r"(?:sign|log) in again|token_revoked|refresh_token_(?:expired|reused|invalidated)", re.I)
SIGN_IN_AGAIN_WAIT = 3      # seconds from such an answer to the read that confirms it
ACCOUNT_AGAIN = 15          # seconds from one early account read to the next one (Collector.sign_in_ended)
NO_ANSWER_READS = 3         # account reads in a row with no answer, after which "the provider ended it" says nothing


def codex_limits(kit, command="codex"):
    """This account's allowance, by Codex's own app-server (codex_account). SignedOut when the runtime says that it
    keeps no account; SignInAgain when it says, two times in a row, that its sign-in is over at the provider
    (SIGN_IN_AGAIN); Unrefreshed when the account is known and only its limits are not.

    **One such answer can be a lost race.** Each Codex process of this user renews the same stored sign-in when its
    access token ends, and the provider takes a renewal token one time: a read that came with the token from before
    is told that it "was already used", with the same words as a sign-in that is over. So the answer is asked for
    again a moment later, when the other process has written the new sign-in, and only the same answer again is the
    provider's word: one that is wrong would show a working agent as signed out and hold its sessions."""
    try:
        return codex_account(kit, command)
    except SignInAgain:
        time.sleep(SIGN_IN_AGAIN_WAIT)
        return codex_account(kit, command)


def codex_account(kit, command="codex"):
    """One read of codex_limits: one start of the app-server, the account and its limits."""
    process = subprocess.Popen([command, "app-server", "--listen", "stdio://"], cwd=kit,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               bufsize=0, start_new_session=True)
    reader = selectors.DefaultSelector()
    reader.register(process.stdout, selectors.EVENT_READ)
    deadline, pending = time.monotonic() + 20, b""

    def send(value):
        process.stdin.write((json.dumps(value) + "\n").encode())

    def response(identifier):
        nonlocal pending
        while time.monotonic() < deadline:
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                data = json.loads(line)
                if data.get("id") == identifier:
                    if "result" not in data:
                        error = data.get("error") if isinstance(data.get("error"), dict) else {}
                        if SIGN_IN_AGAIN.search(str(error.get("message") or "")):
                            raise SignInAgain("the runtime asks for a new sign-in")
                        raise ValueError("account read failed")
                    return data["result"]
            if not reader.select(0.2):
                continue
            data = os.read(process.stdout.fileno(), 65536)
            if not data or len(pending) + len(data) > MAX_LINE:
                raise ValueError("account read failed")
            pending += data
        raise ValueError("account read timed out")

    try:
        send({"id": 1, "method": "initialize", "params": {"clientInfo": {"name": "fleet_usage", "version": "1.0"}}})
        response(1)
        send({"method": "initialized"})
        send({"id": 2, "method": "account/read", "params": {"refreshToken": False}})
        try:
            answer = response(2)
        except SignedOut:
            raise
        except ValueError as failed:
            # Not every Codex answers the account read of a sign-in that the provider ended in those words. The
            # ChatGPT app's own copy (0.163.0-alpha.10.2, the screen runtime of the owner's Mac Studio, 14 November
            # 2026) said "workspace routing discovery unauthorized (401)" there, and gave the provider's code,
            # token_revoked, only at the limits. So the limits are asked before this is a read with no answer; an
            # answer of theirs without the account is still that.
            try:
                send({"id": 3, "method": "account/rateLimits/read"})
                response(3)
            except SignedOut:
                raise
            except (OSError, ValueError, KeyError, TypeError):
                pass
            raise failed
        if "account" in answer and answer["account"] is None:
            raise SignedOut("no account")        # the runtime's own answer, not a failed read
        account = answer.get("account") or {}
        try:
            send({"id": 3, "method": "account/rateLimits/read"})
            result = response(3)
            return normalize_codex_limits(result, account, time.time())
        except SignedOut:
            raise                               # the provider ended this sign-in: no failed refresh of a known account
        except (OSError, ValueError, KeyError, TypeError):
            if isinstance(answer.get("account"), dict):         # the account is known; only its limits are not
                raise Unrefreshed(str(account.get("email") or "")) from None
            raise
    finally:
        import signal
        reader.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        process.stdin.close()
        process.stdout.close()


def safe_label(value, default):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9 ._()/:-]{1,70}", value) else default


def safe_email(value):
    """The account email that the signed-in runtime gave, or None (unknown): at most 254 characters, one @, and no
    whitespace or control character. It is for the owner only, and it never decides an account group."""
    return value if isinstance(value, str) and len(value) <= 254 and EMAIL.fullmatch(value) else None


def normalize_codex_limits(result, account, collected_at):
    windows = []
    buckets = result.get("rateLimitsByLimitId")
    if not isinstance(buckets, dict) or not buckets:
        single = result.get("rateLimits") or {}
        buckets = {single.get("limitId") or "codex": single}
    for key, bucket in buckets.items():
        for field in ("primary", "secondary"):
            window = bucket.get(field)
            if not window:
                continue
            minutes = window.get("windowDurationMins")
            period = "5 hours" if minutes == 300 else "7 days" if minutes == 10080 else f"{minutes} minutes" if minutes else field
            label = safe_label(bucket.get("limitName") or key, "Codex") + " / " + period
            windows.append(dict(id=safe_label(str(key) + ":" + field, field),
                                label=safe_label(label, period),
                                used_percent=number(window["usedPercent"]), resets_at=timestamp(window.get("resetsAt")),
                                window_minutes=number(minutes, True) if minutes is not None else None))
    identity = result.get("accountId") or account.get("email")
    if not windows and not identity:
        raise ValueError("no account windows")
    # An account without windows still gives its identity; its state stays unknown at the hub.
    return dict(collected_at=collected_at, source=LIMIT_SOURCES["codex"],
                plan=safe_label(account.get("planType"), "ChatGPT"), account_key=account_key("openai", identity),
                account_email=safe_email(account.get("email")), windows=windows, error=None if windows else NO_WINDOWS)


def claude_cache(home=None, signed_in=None):
    """The account record of this home and its cached usage windows. An account record and a cache can be old: they
    stay after a sign-out. So without signed_in, only a cache of this account with windows counts, with its own time
    and no email. signed_in is the email that the runtime's own sign-in status just gave ("" for none): then the
    account also counts without windows, and its email is given when it is the email of this account record."""
    home = Path(home or Path.home())
    data = read_json(home / ".claude.json")
    account = data.get("oauthAccount") or {}
    cache = data.get("cachedUsageUtilization") or {}
    identity = account.get("accountUuid")
    if not identity:
        raise ValueError("no account record")
    if cache.get("accountUuid") != identity:
        cache = {}                              # another account's cache gives no window of this account
    utilization = cache.get("utilization") or {}
    windows = []
    # Current Claude versions expose named/scoped windows here. Use the old
    # five_hour/seven_day fields only when this array is absent.
    if isinstance(utilization.get("limits"), list):
        for index, window in enumerate(utilization["limits"]):
            group = window.get("group")
            scope = window.get("scope") or {}
            model = (scope.get("model") or {}).get("display_name")
            label = "5 hours" if group == "session" else "7 days" if group == "weekly" else "Account limit"
            if model:
                label += " (" + safe_label(model, "model") + ")"
            windows.append(dict(id=safe_label(str(window.get("kind")) + ":" + str(index), str(index)),
                                label=label, used_percent=number(window["percent"]),
                                resets_at=timestamp(window.get("resets_at")),
                                window_minutes=300 if group == "session" else 10080 if group == "weekly" else None))
    else:
        for field, minutes, label in (("five_hour", 300, "5 hours"), ("seven_day", 10080, "7 days")):
            window = utilization.get(field)
            if window:
                windows.append(dict(id=field, label=label, used_percent=number(window["utilization"]),
                                    resets_at=timestamp(window.get("resets_at")), window_minutes=minutes))
    if not windows and signed_in is None:
        raise ValueError("no account windows")
    plan = {"default_claude_max_5x": "Claude Max 5x", "default_claude_max_20x": "Claude Max 20x"}.get(account.get("userRateLimitTier"))
    if not plan:
        plan = {"claude_team": "Claude Team", "claude_pro": "Claude Pro"}.get(account.get("organizationType"), "Claude")
    own = isinstance(signed_in, str) and signed_in.lower() == str(account.get("emailAddress") or "").lower()
    return dict(collected_at=number(cache["fetchedAtMs"]) / 1000 if windows else time.time(),
                source=LIMIT_SOURCES["claude"], plan=plan,
                account_key=account_key("anthropic", identity + ":" + str(account.get("organizationUuid") or "")),
                account_email=safe_email(signed_in) if own else None, windows=windows,
                error=None if windows else NO_WINDOWS)


def keep_windows(old, new):
    """A reading without windows names the account, but it never replaces the windows that an earlier reading gave
    for the same account: those stay, with their own time, as after a failed refresh."""
    if new["windows"] or not (old and old.get("windows") and old.get("account_key") == new["account_key"]):
        return new
    return dict(old, account_email=new["account_email"], error="Account limits could not be refreshed.")


def claude_signed_in(kit):
    """The runtime's own sign-in status (no model turn; it exits with 1 when signed out). Signed in: its email, "" for
    none. Signed out: SignedOut. A status that cannot be read: None, which proves neither."""
    try:
        status = run_json(["claude", "auth", "status", "--json"], kit, ok=(0, 1))
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if not isinstance(status, dict):
        return None
    if status.get("loggedIn") is False:
        raise SignedOut("signed out")
    return str(status.get("email") or "") if status.get("loggedIn") is True else None


def refresh_failed(reading, failure):
    """A refresh failed, so the reading is kept, with its windows and their own time. An ordinary failure keeps its
    email too. When the runtime itself just named another account, or one without an email, the reading is the earlier
    account's: it names no email, and its error says that the account changed, so the hub takes no allowance from it
    for this route. A reading that already says signed out or changed stays so until a reading succeeds; a runtime
    that is signed in again, but whose limits cannot be read, is not known to be the earlier account."""
    named = failure.email if isinstance(failure, Unrefreshed) else None
    if reading.get("error") in IDENTITY_ERRORS:
        if named is not None:
            reading["error"] = IDENTITY_CHANGED
    elif named is not None and reading.get("account_email") and named.lower() != reading["account_email"].lower():
        reading.update(account_email=None, error=IDENTITY_CHANGED)
    else:
        reading["error"] = "Account limits could not be refreshed."


def signed_out(reading):
    """After SignedOut: a reading that is kept keeps its windows and their time, but it names no account email."""
    if reading:
        reading.update(account_email=None, error=SIGN_IN_REQUIRED)


def claude_limits(kit, home=None):
    signed_in = claude_signed_in(kit)           # first: a signed-out runtime is not a failed refresh
    try:
        return claude_usage(kit, home, signed_in)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        if signed_in is not None:               # the account is known; only its limits are not
            raise Unrefreshed(signed_in) from None
        raise


def claude_usage(kit, home, signed_in):
    result = run_json(["claude", "-p", "/usage", "--output-format", "json", "--max-turns", "1",
                       "--tools", "", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
                       "--no-session-persistence", "--permission-mode", "dontAsk"], kit)
    if result.get("num_turns") != 0 or result.get("is_error"):
        raise ValueError("local command failed")
    data = claude_cache(home, signed_in)
    if time.time() - data["collected_at"] > POLL_SECONDS:
        data["error"] = "Account limit data is not current."
    return data


def validate_usage(data, runtime, screen=False):
    """Rebuild an allowlisted payload at the hub boundary; reject all extras."""
    if not isinstance(data, dict) or not {"tokens", "limits"} <= set(data) or set(data) - {"tokens", "limits", "screen", "previous"}:
        raise ValueError("invalid usage")
    for kind, value in data.items():
        if kind == "screen":
            if screen or not isinstance(value, dict) or set(value) != {"tokens", "limits"}:
                raise ValueError("invalid screen usage")
            validate_usage(value, "codex", screen=True)
            continue
        if kind == "previous":          # owner feature runtime_switch: the runtime before a switch, tokens only
            if screen or not isinstance(value, dict) or set(value) != {"runtime", "tokens"} or \
                    value["runtime"] not in SOURCES or value["runtime"] == runtime:
                raise ValueError("invalid previous usage")
            validate_usage({"tokens": value["tokens"], "limits": None}, value["runtime"])
            continue
        if value is None:
            continue
        fields = (set(TOKEN_KEYS) | {"total", "sessions", "since", "last_activity", "collected_at", "source", "scope", "error"}
                  if kind == "tokens" else {"collected_at", "source", "plan", "account_key", "windows", "error"})
        optional = {"by_session"} if kind == "tokens" else {"account_email"}     # an older helper sends no account email
        if not isinstance(value, dict) or set(value) - optional != fields:
            raise ValueError("invalid fields")
        if "by_session" in value:
            rows = value["by_session"]
            if not isinstance(rows, list) or len(rows) > BY_SESSION:
                raise ValueError("invalid sessions")
            for row in rows:
                if not isinstance(row, dict) or set(row) not in ({*SESSION_FIELDS}, {*SESSION_FIELDS, *SESSION_KINDS},
                                                                {*SESSION_FIELDS, *SESSION_KINDS, "models"}) \
                        or not isinstance(row["session_id"], str) or not SESSION_ID.fullmatch(row["session_id"]):
                    raise ValueError("invalid session")
                number(row["total"], True)
                if row["last_activity"] is not None:
                    number(row["last_activity"])
                if "calls" in row:              # helper feature session_kinds
                    for key in (*TOKEN_KEYS, "calls"):
                        number(row[key], True)
                    model, share = row["model"], row["first_cache_share"]
                    if row["total"] != sum(row[key] for key in TOKEN_KEYS) or \
                            not (model is None or isinstance(model, str) and MODEL.fullmatch(model)) or \
                            not (share is None or number(share) <= 1):
                        raise ValueError("invalid session")
                if "models" in row:             # helper feature session_models
                    validate_models(row)
        if value["error"] is not None and value["error"] not in ERRORS:
            raise ValueError("invalid error")
        if value["collected_at"] is not None and number(value["collected_at"]) > time.time() + 60:
            raise ValueError("invalid time")
        source = SCREEN_SOURCE if screen and kind == "tokens" else \
            (SOURCES if kind == "tokens" else LIMIT_SOURCES).get(runtime)
        if source is None or value["source"] != source:     # a runtime with no such source sends null for it
            raise ValueError("invalid source")
        if kind == "tokens":
            for key in (*TOKEN_KEYS, "total", "sessions"):
                number(value[key], True)
            if value["total"] != sum(value[key] for key in TOKEN_KEYS) or value["scope"] != (SCREEN_SCOPE if screen else SCOPE) or value["collected_at"] is None:
                raise ValueError("invalid totals")
            for key in ("since", "last_activity"):
                if value[key] is not None:
                    number(value[key])
        else:
            if value["plan"] is not None and safe_label(value["plan"], None) is None:
                raise ValueError("invalid plan")
            if value["account_key"] is not None and not re.fullmatch(r"(?:anthropic|openai):[a-f0-9]{32}", value["account_key"]):
                raise ValueError("invalid account key")
            if value.get("account_email") is not None and safe_email(value["account_email"]) is None:
                raise ValueError("invalid account email")
            if not isinstance(value["windows"], list) or len(value["windows"]) > 24:
                raise ValueError("invalid windows")
            seen = set()
            for window in value["windows"]:
                if set(window) != {"id", "label", "used_percent", "resets_at", "window_minutes"}:
                    raise ValueError("invalid window")
                if not all(safe_label(window[k], None) for k in ("id", "label")):
                    raise ValueError("invalid label")
                if window["id"] in seen:
                    raise ValueError("duplicate window")
                seen.add(window["id"])
                number(window["used_percent"])
                if window["resets_at"] is not None:
                    number(window["resets_at"])
                if window["window_minutes"] is not None:
                    number(window["window_minutes"], True)
    return data


def validate_models(row):
    """A session's models (helper feature session_models): each model once, and their tokens and calls add up to the
    session's own."""
    models, names, sums = row["models"], set(), [0] * len(MODEL_FIELDS)
    if not isinstance(models, list) or len(models) > MODELS_MAX:
        raise ValueError("invalid models")
    for entry in models:
        if not isinstance(entry, list) or len(entry) != 1 + len(MODEL_FIELDS) or \
                not (entry[0] is None or isinstance(entry[0], str) and MODEL.fullmatch(entry[0])) or entry[0] in names:
            raise ValueError("invalid models")
        names.add(entry[0])
        sums = [total + number(value, True) for total, value in zip(sums, entry[1:])]
    if sums != [row[key] for key in MODEL_FIELDS]:
        raise ValueError("invalid models")


def screen_database(home=None):
    path = Path(home or Path.home()) / ".fleet/screen-usage.sqlite3"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.exists():
        path.touch(mode=0o600)
    db = sqlite3.connect(path, timeout=5)
    db.execute("CREATE TABLE IF NOT EXISTS sessions(kit TEXT, agent TEXT, thread TEXT, raw_input INTEGER, output INTEGER, cache_read INTEGER, since REAL, updated REAL, cache_write INTEGER DEFAULT 0, PRIMARY KEY(kit,agent,thread))")
    return db


def record_screen_usage(kit, agent, thread, token_usage, home=None):
    """Store cumulative counters, never prompts. Repeated events cannot add tokens twice."""
    if not isinstance(thread, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,80}", thread):
        raise ValueError("invalid thread")
    total = token_usage["total"]
    raw, out, cache = [number(total[k], True) for k in ("inputTokens", "outputTokens", "cachedInputTokens")]
    write = number(total.get("cacheWriteInputTokens", 0), True)
    if cache + write > raw or number(total["totalTokens"], True) != raw + out:
        raise ValueError("invalid token totals")
    ts = time.time()
    with screen_database(home) as db:
        db.execute("""INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(kit,agent,thread)
            DO UPDATE SET raw_input=max(raw_input,excluded.raw_input), output=max(output,excluded.output),
            cache_read=max(cache_read,excluded.cache_read), cache_write=max(cache_write,excluded.cache_write), updated=excluded.updated""",
            (str(Path(kit).resolve()), agent, thread, raw, out, cache, ts, ts, write))
    db.close()


def screen_tokens(kit, agent, home=None):
    with screen_database(home) as db:
        row = db.execute("SELECT sum(raw_input-cache_read-cache_write),sum(output),sum(cache_read),count(*),min(since),max(updated),sum(cache_write) FROM sessions WHERE kit=? AND agent=?",
                         (str(Path(kit).resolve()), agent)).fetchone()
    db.close()
    if not row[3]:
        return None
    return dict(input=row[0], output=row[1], cache_read=row[2], cache_write=row[6],
                total=sum(row[:3])+row[6], sessions=row[3], since=row[4], last_activity=row[5],
                collected_at=time.time(), source=SCREEN_SOURCE, scope=SCREEN_SCOPE, error=None)


def local_model(conf, accounts=None):
    """A worker that runs a model which is the owner's own: its tokens count, but no vendor account limit applies.
    Two ways say it. Its account is the owner's own model server (accounts: team.json "accounts"; an entry of kind
    "server", the AI providers build spec, section 3.1). Or its start has the flag that its runtime has for a model
    on the machine itself (lifecycle.RUNTIMES "local_model"), as before. A caller that gives no accounts asks only
    the second."""
    entry = accounts.get(conf.get("account")) if isinstance(accounts, dict) and isinstance(conf.get("account"), str) \
        else None
    if isinstance(entry, dict) and entry.get("kind") == "server":
        return True
    flag = lifecycle.runtime_fact(conf.get("runtime"), "local_model")
    return bool(flag) and bool(re.search(rf"(?:^|\s){re.escape(flag)}(?:\s|$)", str(conf.get("start") or "")))


def plain_sessions(data):
    """A report without each session's four kinds: its shape before helper feature session_kinds."""
    return sessions_as(data, SESSION_FIELDS)


def kinds_sessions(data):
    """A report without each session's models: its shape before helper feature session_models."""
    return sessions_as(data, SESSION_FIELDS + SESSION_KINDS)


def sessions_as(data, fields):
    """A report whose sessions, and the runtime's before a switch, keep these fields only."""
    def keep(tokens):
        if not tokens or "by_session" not in tokens:
            return tokens
        return dict(tokens, by_session=[{k: row[k] for k in fields if k in row} for row in tokens["by_session"]])
    out = dict(data, tokens=keep(data.get("tokens")))
    if out.get("previous"):
        out["previous"] = dict(out["previous"], tokens=keep(out["previous"].get("tokens")))
    return out


class Collector:
    def __init__(self, kit, agent, runtime, publish, home=None, screen_command=None, local=False, previous=None):
        self.kit, self.agent, self.runtime, self.publish = kit, agent, runtime, publish
        self.screen_command, self.local = screen_command, local
        # owner feature runtime_switch: the runtime that this agent ran before its switch. Its retained workspace
        # sessions are read again every POLL_SECONDS, so that the last records of its closing chat count; its account
        # limits are never read again.
        self.previous = previous if previous in SOURCES and previous != runtime else None
        self.previous_poll = 0
        self.home = Path(home or Path.home())
        self.path = self.home / ".fleet" / ("usage-" + agent + ".json")
        self.data, self.last_poll = {"tokens": None, "limits": None}, 0
        self.wake = threading.Event()   # account_again: scan now, not at the end of this wait
        # {"limits" (the agent's own runtime), "screen" (Codex for its screen tasks): True} while the newest account
        # read that gave an answer said that the provider ended the sign-in that this machine keeps (SignInAgain). It
        # is apart from the reading, because a machine can have no reading yet: a new agent, one that moved here, or
        # one whose runtime the owner switched (heard, sign_in_ended).
        self.over, self.silent, self.over_asked = {}, {}, float("-inf")
        self.over_changed = None        # () -> None, called when that word changes: the machine's report is due
        self.takes = 0                  # the hub's last answer took each session's four kinds (1), and its models (2)
        self.scans = {}                 # runtime -> its Scan: each scan reads only what its transcripts gained
        try:
            cache = read_json(self.path)
            if cache["runtime"] != runtime:     # another runtime's numbers and poll time never stand for this one
                raise ValueError("another runtime")
            self.data = validate_usage(cache["data"], runtime)
            self.last_poll = number(cache["last_poll"])
            said = cache.get("over") if isinstance(cache.get("over"), dict) else {}
            self.over = {route: True for route in ("limits", "screen") if said.get(route) is True}
            if self.over:
                # The owner can have signed this machine in while its helper was down, and the machine's reading
                # takes this word over the status command's: the first scan reads the account, whatever the clock.
                self.last_poll = 0
        except (OSError, ValueError, KeyError, TypeError):
            pass
        if local:
            self.data["limits"] = None          # a cached account window would belong to a vendor login, not this model
        if local or runtime not in LIMIT_SOURCES:
            self.over = {}                      # nothing reads an account here, so no read could ever end that word
        if not self.previous or (self.data.get("previous") or {}).get("runtime") != self.previous:
            self.data.pop("previous", None)
        if screen_command:
            self.data.setdefault("screen", {"tokens": None, "limits": None})

    def heard(self, route, word):
        """What one account read said about the sign-in that this machine keeps for a route: True, the provider ended
        it (SignInAgain); False, the account answered, or the runtime keeps none, which its status command says
        too; None, the read gave no answer (a time-out, a network fault, a program that does not start). No answer
        leaves the word as it is, and NO_ANSWER_READS of them in a row end it: the read says nothing any more, and
        the status command's word stands again, as before this word existed. Without that end, a sign-in that the
        owner made again would read "signed out" for as long as the account read fails for another reason. The reads
        are the poll clock's, 15 minutes for three, and the early ones of sign_in_ended while a sign-in job looks:
        then a network fault of under a minute ends the word, until the next read that gets an answer."""
        before = bool(self.over.get(route))
        if word is None:
            self.silent[route] = self.silent.get(route, 0) + 1
            if self.silent[route] >= NO_ANSWER_READS:
                self.over.pop(route, None)
        else:
            self.silent[route] = 0
            if word:
                self.over[route] = True
            else:
                self.over.pop(route, None)
        if bool(self.over.get(route)) != before and self.over_changed:
            try:
                self.over_changed()
            except Exception:
                pass                    # a report that is not asked for now comes at the report clock

    def sign_in_ended(self, runtime):
        """True while the newest account read says that the provider ended the sign-in that this machine keeps for
        that runtime (heard): the agent's own runtime, or Codex as the runtime of its screen tasks. The runtime's
        status command still says "Logged in" then (codex_limits), so the machine's reading takes this word over that
        one (lifecycle.Lifecycle.runtime), and it is asked only when the status command says signed in.

        **That read can be older than a sign-in.** After the owner signs the machine in again, the status command and
        this word disagree until the account is read again. So each True also asks for that read now, at most each
        ACCOUNT_AGAIN seconds (account_again), and the read's new word asks for the machine's report (over_changed):
        a sign-in that worked reads so within seconds, and not at the end of the poll clock."""
        route = "limits" if runtime == self.runtime else \
            "screen" if runtime == "codex" and self.screen_command else None
        if not route or not self.over.get(route):
            return False
        if time.monotonic() - self.over_asked >= ACCOUNT_AGAIN:
            self.over_asked = time.monotonic()
            self.account_again()
        return True

    def account_again(self):
        """Read the account at the next scan, whatever the poll clock says. This machine signed in to another
        account, and until it reads itself again every reader of this reading — the owner's card above all — is
        shown the address of the account he has just left (the owner, 23 October 2026: he signed the manager in to
        another account, pasted the code, and the card kept the old address for the rest of the poll). And the next
        scan is now, not at the end of this one's wait (the owner, 25 October 2026: "it needs to be immediate")."""
        self.last_poll = 0
        self.wake.set()

    def collect(self):
        if self.screen_command:
            try:
                self.data["screen"]["tokens"] = screen_tokens(self.kit, self.agent, self.home)
            except (OSError, ValueError, sqlite3.Error):
                if self.data["screen"]["tokens"]:
                    self.data["screen"]["tokens"]["error"] = "Token records could not be read."
        if self.runtime not in SOURCES:         # a runtime with no usage source: unknown, never another's numbers
            self.send(self.data)
            return
        if self.previous and time.time() - self.previous_poll >= POLL_SECONDS:
            self.previous_poll = time.time()
            try:
                self.data["previous"] = {"runtime": self.previous, "tokens": self.tokens(self.previous)}
            except ScanPending:
                self.previous_poll = 0          # it goes on at the next scan, and the last reading stands till then
            except (OSError, ValueError, KeyError, TypeError):
                if (self.data.get("previous") or {}).get("tokens"):
                    self.data["previous"]["tokens"]["error"] = "Token records could not be read."
        try:
            self.data["tokens"] = self.tokens(self.runtime)
        except ScanPending:
            pass                                # it goes on at the next scan, and the last reading stands till then
        except (OSError, ValueError, KeyError, TypeError):
            if self.data["tokens"]:
                self.data["tokens"]["error"] = "Token records could not be read."
        # A runtime with no reader of an account's allowance sends none: an agent on a key or on a model server, and
        # each ACP program until its own reader is built.
        if not self.local and self.runtime in LIMIT_SOURCES and time.time() - self.last_poll >= POLL_SECONDS:
            self.last_poll = time.time()
            if self.screen_command:
                try:
                    self.data["screen"]["limits"] = keep_windows(self.data["screen"]["limits"],
                                                                 codex_limits(self.kit, self.screen_command))
                    self.heard("screen", False)
                except SignedOut as said:
                    self.heard("screen", isinstance(said, SignInAgain))
                    signed_out(self.data["screen"]["limits"])
                except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as failure:
                    self.heard("screen", False if isinstance(failure, Unrefreshed) else None)
                    if self.data["screen"]["limits"]:
                        refresh_failed(self.data["screen"]["limits"], failure)
            try:
                self.data["limits"] = keep_windows(self.data["limits"], codex_limits(self.kit) if self.runtime == "codex"
                                                   else claude_limits(self.kit, self.home))
                self.heard("limits", False)
            except SignedOut as said:       # confirmed by the runtime: no old cache stands in, and no email stays
                self.heard("limits", isinstance(said, SignInAgain))
                signed_out(self.data["limits"])
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as failure:
                # the runtime named its account before the limits failed (Unrefreshed): its sign-in works
                self.heard("limits", False if isinstance(failure, Unrefreshed) else None)
                if self.data["limits"] is None and self.runtime == "claude":
                    try:
                        self.data["limits"] = claude_cache(self.home)
                    except (OSError, ValueError, KeyError, TypeError):
                        pass
                if self.data["limits"]:
                    refresh_failed(self.data["limits"], failure)
        validate_usage(self.data, self.runtime)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Numbers, labels, the account key and the account email only. A failed write cannot change task handling.
        with open(self.path, "w", opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
            json.dump({"runtime": self.runtime, "data": self.data, "last_poll": self.last_poll,
                       "over": self.over}, stream)
        self.send(self.data)

    def tokens(self, runtime):
        return transcript_tokens(runtime, self.kit, self.home, self.scans.setdefault(runtime, Scan()))

    def send(self, data):
        """Publish one report. Each session's four kinds go only to a hub whose last answer said that it takes them
        (helper feature session_kinds), and its models only to one that said it takes those too (session_models),
        while they keep the report within the hub's size limit; a hub that refuses a report, a release from before
        what it carries, gets the plainer one at once."""
        level = self.takes
        if level == 2 and len(json.dumps(data)) > REPORT_MAX:
            level = 1
        shapes = (plain_sessions, kinds_sessions, lambda report: report)
        answer = self.publish(shapes[level](data))
        while level and isinstance(answer, tuple) and answer[0] in (400, 413):
            level -= 1
            answer = self.publish(shapes[level](data))
        if isinstance(answer, tuple) and answer[0] == 200:
            said = answer[1] if isinstance(answer[1], dict) else {}
            self.takes = 1 + (said.get("session_models") is True) if said.get("session_kinds") is True else 0

    def run(self):
        while True:
            try:
                self.collect()
            except Exception:
                pass  # Never print provider data, transcript text, or raw errors.
            self.wake.wait(SCAN_SECONDS)
            self.wake.clear()

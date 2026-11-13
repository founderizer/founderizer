"""Runtime thread records for the owner app. Standard library only.

The helper reads each task session's own record file: the Claude Code transcript
(found by the session's --session-id), the Codex rollout (found by a marker line in
its start prompt) or, for a task in screen_runner.py (lifecycle.app_server_task), the
Codex app-server notifications that the runner appends to
~/.fleet/screen-<session>.jsonl. It turns the lines into
ACP-shaped records with stable sequence numbers: the same file always gives the same
records. It sends them to the hub in bounded batches. No provider calls, no screen
reading, no credentials.
"""
import datetime
import glob
import json
import math
import os
import re
import threading
import time

MAX_LINE = 4 * 1024 * 1024
READ_STEP = 8 * 1024 * 1024         # most bytes read from one file in one scan
BATCH = 100
BATCH_BYTES = 48 * 1024
TEXT, THOUGHT, TITLE, OUTPUT, MESSAGE = 4000, 2000, 300, 800, 500
SAYS = 120                          # what the agent says a command does, for the owner's apps (tool_call "says")
APP_TEXT = 4000                     # screen_runner.py clips longer text in its record lines
KINDS = ("read", "edit", "delete", "move", "search", "execute", "think", "fetch", "other")
STATUSES = ("pending", "in_progress", "completed", "failed")
STOPS = ("end_turn", "cancelled", "max_tokens", "refusal", "error")
MARKER = "[fleet-session {}]"
MARKER_TEXT = re.compile(r"\s*\[fleet-session [0-9a-f-]{36}\]\s*$")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

CLAUDE_FIELDS = {"Bash": "command", "Read": "file_path", "Write": "file_path", "Edit": "file_path",
                 "MultiEdit": "file_path", "NotebookEdit": "notebook_path", "Grep": "pattern", "Glob": "pattern",
                 "WebFetch": "url", "WebSearch": "query", "Task": "description", "Agent": "description"}
CLAUDE_KINDS = {"Read": "read", "NotebookRead": "read", "BashOutput": "read", "TaskOutput": "read", "Skill": "read",
                "Grep": "search", "Glob": "search", "LS": "search", "WebSearch": "search", "ToolSearch": "search",
                "Edit": "edit", "MultiEdit": "edit", "Write": "edit", "NotebookEdit": "edit",
                "Bash": "execute", "KillShell": "execute", "KillBash": "execute", "WebFetch": "fetch",
                "ExitPlanMode": "think", "EnterPlanMode": "think"}
CODEX_KINDS = {"exec": "execute", "shell": "execute", "exec_command": "execute", "local_shell": "execute",
               "write_stdin": "execute", "apply_patch": "edit", "view_image": "read", "web_search": "search",
               "sleep": "think", "wait": "think"}
READ_ONLY_MCP = ("read", "get", "list", "find", "search", "see_", "tabs_context")
# Codex code mode: exec scripts call tools.exec_command({cmd: "..."}) and tools.write_stdin({session_id: N, chars: ""}).
EXEC_CMD = re.compile(r"""exec_command\(\{\s*cmd\s*:\s*(["'`])((?:\\.|(?!\1).)*)\1""", re.S)
STDIN = re.compile(r"""write_stdin\(\{\s*session_id\s*:\s*(\d+)\s*(?:,\s*chars\s*:\s*(["'`])((?:\\.|(?!\2).)*)\2)?""", re.S)
# And its plan: tools.update_plan({plan: [{step: "...", status: "in_progress"}]}), whose argument is read as a literal
# (Codex 0.163 sends it only there: its rollout has no plan event of its own).
PLAN_CALL = re.compile(r"\btools\.update_plan\s*\(")
JS_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
JS_GAP = re.compile(r"(?:\s|//[^\n]*|/\*.*?\*/)*", re.S)        # what may stand between two tokens
JS_NAME = re.compile(r"[A-Za-z_$][\w$]*")
JS_NUMBER = re.compile(r"-?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?")
JS_WORDS = {"true": True, "false": False, "null": None, "undefined": None}
JS_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


def clip(text, limit):
    text = str(text if text is not None else "")
    return text if len(text) <= limit else text[:limit - 1] + "…"


def when(value):
    """Epoch seconds from an ISO time or a number; None when there is none."""
    if isinstance(value, str):
        try:
            return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0:
        return float(value)
    return None


def text_of(content):
    """The plain text in a vendor content value: a string, or a list of text blocks."""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        return text_of(content.get("text") if "text" in content else content.get("content"))
    if isinstance(content, list):
        return "\n".join(t for t in (text_of(b) for b in content
                                     if not isinstance(b, dict) or b.get("type") not in ("image", "input_image")) if t)
    return ""


def first_line(value):
    text = str(value or "").strip()
    return text.splitlines()[0] if text else ""


def plan_entries(items, key):
    entries = []
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and str(item.get(key) or "").strip():
            status = item.get("status") if item.get("status") in ("pending", "in_progress", "completed") else "pending"
            entries.append({"content": clip(item[key], TITLE), "status": status})
    return entries[:50]


def js_literal(text, at, depth=0):
    """The JavaScript literal at text[at:] and where it ends: an object, an array, a string with no ${}, a number,
    true, false or null. ValueError for anything else, such as a name, a call or a sum."""
    at = JS_GAP.match(text, at).end()
    char = text[at:at + 1]
    if depth > 20 or not char:
        raise ValueError("no literal")
    if char in "{[":
        close, value, at = "]" if char == "[" else "}", [] if char == "[" else {}, at + 1
        while True:
            at = JS_GAP.match(text, at).end()
            if text[at:at + 1] == close:
                return value, at + 1
            if char == "[":
                item, at = js_literal(text, at, depth + 1)
                value.append(item)
            else:
                name = JS_NAME.match(text, at)
                key, at = (name.group(), name.end()) if name else js_literal(text, at, depth + 1)
                at = JS_GAP.match(text, at).end()
                if isinstance(key, (dict, list)) or text[at:at + 1] != ":":       # {plan} names a variable
                    raise ValueError("no literal property")
                value[str(key)], at = js_literal(text, at + 1, depth + 1)
            at = JS_GAP.match(text, at).end()
            if text[at:at + 1] == ",":
                at += 1
            elif text[at:at + 1] != close:
                raise ValueError("no literal")
    if char in "\"'`":
        parts, at = [], at + 1
        while text[at:at + 1] != char:
            if not text[at:at + 1] or (text[at] == "\n" and char != "`") or (char == "`" and text.startswith("${", at)):
                raise ValueError("no literal string")
            if text[at] != "\\":
                parts.append(text[at])
                at += 1
                continue
            code = text[at + 1:at + 2]
            if code == "u" and text[at + 2:at + 3] == "{":
                end = text.find("}", at + 3)
                if end < 0:
                    raise ValueError("an open escape")
                digits, at = text[at + 3:end], end + 1
            elif code in ("u", "x"):
                size = 4 if code == "u" else 2
                digits, at = text[at + 2:at + 2 + size], at + 2 + size
            else:
                digits, at = None, at + 2
                if code == "\r" and text[at:at + 1] == "\n":
                    at += 1
            parts.append(chr(int(digits, 16)) if digits is not None else
                         "" if code in ("\r", "\n") else JS_ESCAPES.get(code, code))      # a line continuation is none
        return "".join(parts).encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace"), at + 1
    word = JS_NAME.match(text, at)
    if word and word.group() in JS_WORDS:
        return JS_WORDS[word.group()], word.end()
    number = JS_NUMBER.match(text, at)
    if number and not JS_NAME.match(text, number.end()):
        return float(number.group()), number.end()
    raise ValueError("no literal")


def code_plans(code):
    """The plans that a Codex code-mode script keeps with tools.update_plan, as plan records in their order, and
    whether the script does nothing else (then it is its plan alone, not a call). A plan that is no literal, such as
    {plan: steps}, is none, and the script stays a call."""
    if "update_plan" not in code:
        return [], False
    plans, rest, last = [], [], 0
    for match in PLAN_CALL.finditer(code):
        if match.start() < last:
            continue                # inside the plan before it, as its text
        try:
            args, end = js_literal(code, match.end())
        except (ValueError, OverflowError):
            continue
        end = JS_GAP.match(code, end).end()
        if code[end:end + 1] == ",":
            end = JS_GAP.match(code, end + 1).end()
        if not isinstance(args, dict) or not isinstance(args.get("plan"), list) or code[end:end + 1] != ")":
            continue                # Codex refuses a call with no plan list, so the plan stays as it was
        plans.append({"type": "plan", "entries": plan_entries(args.get("plan"), "step")})
        rest.append(code[last:match.start()])
        last = end + 1
    if not plans:
        return [], False
    left = re.sub(r"\bawait\b", "", JS_COMMENT.sub("", "".join(rest) + code[last:]))
    return plans, re.fullmatch(r"[\s;]*(?:text\s*\(\s*\)[\s;]*)*", left) is not None


def mcp_kind(tool):
    return "read" if tool.startswith(READ_ONLY_MCP) else "other"


def line_count(text):
    return len(str(text).splitlines()) if text else 0


def diff_counts(diff):
    """(added, removed) lines of a unified diff, without its file headers."""
    lines = str(diff or "").splitlines()
    return (sum(1 for l in lines if l.startswith("+") and not l.startswith("+++")),
            sum(1 for l in lines if l.startswith("-") and not l.startswith("---")))


NOTICE = re.compile(r"<task-notification>.*?</task-notification>", re.S)
# The statuses of a notice that ends a background command, a monitor or a workflow (completed, failed or killed). A
# notice without one is a monitor's event, and its call stays open (plan C1: background work is a fact of the attempt
# until its own end notice).
SHELL_ENDS = ("completed", "failed", "stopped", "killed")
# The Claude Code tools whose result can say that they run on in the background, with the id of their end notice.
# Workflow (AUTONOMY.md decision 41) always does: its result is async_launched with a taskId.
BACKGROUND_TOOLS = ("Bash", "Monitor", "Workflow")
# The description in a Workflow script's meta literal, which Claude Code shows as the call's own title
WORKFLOW_DESCRIPTION = re.compile(r"""\bdescription\s*:\s*(["'`])((?:\\.|(?!\1).)*?)\1""")
# Claude Code's own task list, which it offers in place of TodoWrite while its tasks are on (the default in 2.1.3xx):
# TaskCreate and TaskUpdate change it and the other two read it. Like TodoWrite, they show as the plan, not as calls.
CLAUDE_TASK_TOOLS = ("TaskCreate", "TaskUpdate", "TaskList", "TaskGet")
TASK_MADE = re.compile(r"\bTask #(\d{1,9}) created")    # TaskCreate's result: "Task #3 created successfully: <subject>"


def notice_tag(notice, name):
    found = re.search(rf"<{name}>\s*([^<]*?)\s*</{name}>", notice)
    return found.group(1) if found else None


# The words of a command's result that say that it runs on in the background, with its task id, and that a notice
# of its end will come (Claude Code 2.1.311's own program text, and a subagent's file of 2.1.321, 11 November 2026).
# A subagent's own file gives such a row no `toolUseResult`, so there the id comes from these words, and only for a
# call that asked for the background. The result of a command that Claude Code ends with the subagent's answer says
# that in other words ("it is terminated when you give your final response and no notification can follow that"):
# no notice of its end comes, so it is no background call here, and it shows as a finished call, as before.
BACKGROUND_ID = re.compile(r"Command running in background with ID: ([A-Za-z0-9_-]{1,64})")
BACKGROUND_NOTICE = "You will be notified when it completes"
# The Claude Code tools with which a session stops a background task of its own, by the task's id (task_id; shell_id in
# the older ones). Claude Code gives no end notice for a task that the session stopped itself (2.1.321, 11 November
# 2026), so the result of the stop is that task's end.
STOP_TOOLS = ("TaskStop", "KillShell", "KillBash")


# A fork's own file starts with what its parent had in front of it (Claude Code 2.1.311's own program text, and a
# fork's files of 2.1.321, 11 November 2026): a `fork-context-ref` row, then a copy of the parent's message that
# started the fork, with every tool call of that message under its own id, and one user row with a stand-in result
# for each of those calls ("Fork started — that fork is you.") and the fork's instructions, which open with this block
# of Claude Code's own. Those calls are the parent's, and the copied starting call has the id that the fork's meta
# file names: read as the fork's own, it was a subagent call inside the fork whose subagent is the fork itself.
FORK_START, FORK_START_END = "<fork-boilerplate>", "</fork-boilerplate>"


def own_rows(rows):
    """The rows of a subagent's file that are its own work. A fork's rows are its own from the user row with its
    instructions, and of that row only the instructions after Claude Code's own block (FORK_START). A file that
    starts as a fork's (`fork-context-ref`) and has no such block is its own after its first user row, the one with
    the stand-in results, and has no row of its own before that row is written: the copied calls are never the
    fork's steps. Every other subagent's file is its own from its first row."""
    fork = bool(rows) and isinstance(rows[0], dict) and rows[0].get("type") == "fork-context-ref"
    first = None
    for at, row in enumerate(rows):
        message = row.get("message") if isinstance(row, dict) and isinstance(row.get("message"), dict) else None
        if not message or row.get("type") != "user":
            continue
        first = at if first is None else first
        content = message.get("content")
        for block in [{"type": "text", "text": content}] if isinstance(content, str) else \
                content if isinstance(content, list) else []:
            text = block.get("text") if isinstance(block, dict) and block.get("type") == "text" else None
            if isinstance(text, str) and text.lstrip().startswith(FORK_START):
                said = text.split(FORK_START_END, 1)[1].strip() if FORK_START_END in text else ""
                return [dict(row, message=dict(message, content=said))] + rows[at + 1:]
    if fork:
        return rows[first + 1:] if first is not None else []
    return rows


def complete_rows(data):
    """The JSON objects of a file's complete lines (a writer can still be finishing the last one)."""
    out = []
    for line in data.splitlines(keepends=True):
        if not line.endswith(b"\n") or len(line) > MAX_LINE:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            out.append(row)
    return out


def codex_event(row, *types):
    payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
    return payload if row.get("type") == "event_msg" and payload.get("type") in types else None


def codex_turn_end(row, turn):
    """The end of the named turn; with no name, the end of an aborted turn."""
    end = codex_event(row, "task_complete", "turn_aborted")
    return bool(end) and (end.get("turn_id") == turn if turn else end.get("type") == "turn_aborted")


def codex_own_start(rows, parent_turns):
    """Where a Codex subagent's own rows start. A forked subagent's file starts with a copy of its parent's
    history; its own part starts at its first turn that the parent never had and that started at the fork
    (started_at is in whole seconds and can come up to a second before the file's first line)."""
    fork = when(rows[0].get("timestamp")) if rows and rows[0].get("type") == "session_meta" else None
    for index, row in enumerate(rows):
        start = codex_event(row, "task_started")
        if start and start.get("turn_id") not in parent_turns:
            began = start.get("started_at")
            if fork is None or not isinstance(began, (int, float)) or began >= fork - 2:
                return index
    return None


class Translator:
    """One session file in, ACP-shaped records out. It keeps only what the next line needs."""

    def __init__(self, runtime, root=None, children=None, prefix=None, requested=None):
        self.runtime = runtime
        self.requested = requested or {}    # the model and effort that the helper passed to this session
        self.reported = None        # the (model, effort) of the newest "model" record
        self.root = os.path.realpath(root) if root else None    # paths inside it are shown relative to it
        self.children = children    # reads subagent files: Claude (agent id, starting call) -> rows or None;
                                    # Codex (thread id, byte offset) -> (new rows, new offset)
        self.prefix = prefix        # a subagent's records: its starting call's id
        self.agents = {}            # open subagent call -> its agent (Claude agent id, Codex thread id), once launched
        self.pending = {}           # Claude: async subagent call -> agent id, until its end notice
        self.shells = {}            # Claude: background command, monitor or workflow call -> its task id, until its
                                    # end notice
        self.shell_calls = {}       # Claude: BACKGROUND_TOOLS calls of this session -> the tool's name
        self.asked = set()          # Claude: Bash calls of this session that asked to run in the background
        self.stops = {}             # Claude: STOP_TOOLS call of this session -> the id of the task that it stops
        self.blocks = {}            # Claude: subagent call -> its translator ("child"), how many rows of its file
                                    # are shown ("shown"), its agent id as its launch gave it ("agent") and as its
                                    # notices name it ("named"), and the status of its newest end ("status")
        self.turn = False           # Claude and Codex: a turn of the main session runs
        self.ends = 0               # Claude: the turn ends of the main session so far (Helper.interrupt reads it)
        self.delivered = False      # Claude: the session called deliver_result
        self.after = False          # Claude: and called a tool other than Fleet's after it (Helper.closing)
        self.ending = None          # Claude: the message that ended a turn. One message can be two rows (its thinking
                                    # and its text), so the turn end goes out at the next row, or when a read finds
                                    # no new line (idle): one end for each turn, not one for each row.
        self.read_paths = set()     # Claude: files this session has read, written or edited: a Write to them is a change
        self.seq = 0
        self.started = False
        self.open = set()       # tool calls with no finish yet
        self.silent = set()     # tool calls shown as a plan, not as a call
        self.tasks = []         # Claude: its own task list (TaskCreate, TaskUpdate) in order, which is its plan
        self.limit = False      # Codex: inside a stretch where a limit is reached
        self.reset = None       # Codex: the latest reset time in its rate-limit records
        self.commands = {}      # Codex: exec call -> the commands it started, in order
        self.background = {}    # Codex: session id of a command still running -> its call id
        self.turns = set()      # Codex: turns started in this file, copied ones included
        self.threads = {}       # Codex: subagent thread id -> the call that started it
        self.kids = {}          # Codex: subagent thread id -> its translator and how far its rows are shown
        self.failed = None      # Codex app server: the turn whose error is already a record

    def model_record(self, model, effort):
        """One "model" record when the runtime first shows its model, and again when it changes (owner API 1.9)."""
        if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9._:/\[\]-]{1,120}", model):
            return []
        effort = effort if isinstance(effort, str) and re.fullmatch(r"[a-z]{1,20}", effort) else None
        if (model, effort) == self.reported:
            return []
        self.reported = (model, effort)
        return [{"type": "model", "requested_model": self.requested.get("model"),
                 "requested_effort": self.requested.get("effort"), "model": model, "effort": effort}]

    def records(self, row):
        if not isinstance(row, dict):
            return []
        return self.number(self.made(row), when(row.get("timestamp")))

    def finish(self):
        """The session is over: subagents with no recorded end are shown as far as they got."""
        return self.number(self.remaining(), None)

    def idle(self):
        """A read found no new line: the message that ended a turn was read whole, so the turn's end goes out now."""
        return self.number(self.turn_end("end_turn"), None) if self.ending else []

    def turn_end(self, how):
        """The one result record of a turn of the main session that ended; how: its stop reason."""
        self.ending, self.turn = None, False
        self.ends += 1
        return [{"type": "result", "stop_reason": how}]

    def remaining(self):
        out = self.turn_end("end_turn") if self.ending else []
        for call, agent in sorted(self.pending.items()):
            out.extend(self.subagent_block(call, agent))        # as far as it got: no end of it was seen
        self.pending.clear()
        # The session is over, and Claude Code stops its background commands when it exits: one with no end notice
        # did not finish. A Codex session's background commands end with it the same way.
        for call in sorted(self.shells) + sorted(p for p in self.background.values() if p in self.open):
            self.open.discard(call)
            out.append({"type": "tool_call_update", "tool_call_id": call, "status": "failed", "interrupted": False})
        self.shells.clear()
        self.background.clear()
        for thread, call in sorted(self.threads.items()):
            out.extend(self.codex_kid(thread, call, last=True))
        return out

    def number(self, made, ts):
        out = []
        for record in made:
            self.seq += 1
            out.append(dict(record, seq=self.seq, ts=record.pop("ts", ts) if "ts" in record else ts))
        return out

    def made(self, row):
        return self.mine(self.claude(row) if self.runtime == "claude" else
                         self.codex_app(row) if self.runtime == "codex_app" else self.codex(row))

    def mine(self, made):
        """Records as this translator gives them: a subagent's own carry its starting call as their parent, and
        their call ids start with it; deeper ones already carry their parent."""
        if not self.prefix:
            return made
        out = []
        for record in made:
            if "parent" not in record:
                if record["type"] == "session":
                    continue
                record = dict(record, parent=self.prefix)
                if "tool_call_id" in record:
                    record["tool_call_id"] = clip(f"{self.prefix}/{record['tool_call_id']}", 300)
            out.append(record)
        return out

    def left_open(self, call):
        """The end of a background call that got no end of its own in this translator's file: closed as failed, the
        record that a session's end gives its own (remaining)."""
        self.open.discard(call)
        return self.mine([{"type": "tool_call_update", "tool_call_id": call, "status": "failed", "interrupted": False}])

    def stop(self, task):
        """The end of the background call with this task id, in this translator or in a subagent below it: a session
        can stop a command that a subagent of it left running."""
        out = []
        for call in sorted(c for c, known in self.shells.items() if known == task):
            del self.shells[call]
            out.extend(self.left_open(call))
        for _, block in sorted(self.blocks.items()):
            out.extend(block["child"].stop(task))
        return out

    def inside(self):
        """True while a subagent of this session has background work of its own open in its records: a command that
        runs on after the subagent's call ended. It is background work of the session (fleet.Helper.background_open)."""
        return any(b["child"].pending or b["child"].shells or b["child"].inside() for b in self.blocks.values())

    def subagent_block(self, call, agent, until=None, over=False):
        """The records of a subagent's rows that are not shown yet, translated in the subagent's own state. They are
        placed where a row of its parent reports the subagent: the result of its call, a notice of it, or the
        session's end. until: the time of that row. Only the subagent's rows up to that time show there, so the same
        files give the same records in the same places whenever the helper reads them. A subagent's file can grow
        after a row that reports it: Claude Code runs a subagent again when background work of its own ends or when
        a message reaches it (2.1.311's own program text, and runs on 2.1.321, 11 November 2026), and each later
        notice of the subagent then shows the rows since (notices). A row without a time shows at once, as before.

        A subagent is never read inside itself: a call that started this translator's own subagent, or one above it,
        starts none below it. A fork's file has a copy of its starting call (own_rows), and its meta file names that
        call, so the reader found the fork's own file for it and read it inside itself without an end. That error
        took the fork's end with it: the hub held the call for one that ran on, refused the task's first delivery and
        told the requester that a subagent still ran (two tasks of 9 November 2026).

        over: the subagent is over for good, because its agent waited for its result or a notice says that it
        failed or was stopped. Claude Code then stops what the subagent left running (2.1.311: "killing orphaned
        shell task"), and no row of its file ends those calls, so each closes here as failed (left_open): an async
        subagent of its own, after that one's rows, and a background command, a monitor or a workflow. Without that
        end the hub held the call for work that still ran until the session's end: no turn end of the task was then
        an empty one (plan C9 asked nobody), and a subagent's call cost one refused delivery. A subagent in the
        background that stopped with the status "completed" is not over in that way: its own background work runs
        on, Claude Code keeps the subagent for it, and the subagent's file shows the end of that work later."""
        if call in (self.prefix or "").split("/"):
            return []
        rows = (self.children(agent, call) if self.children else None) or []
        block = self.blocks.get(call)
        if block is None:
            if not rows:
                return []
            child = Translator(self.runtime, self.root, self.children, prefix=f"{self.prefix}/{call}" if self.prefix else call)
            block = self.blocks[call] = {"child": child, "shown": 0, "agent": agent, "named": agent, "status": None}
        child, out = block["child"], []
        for row in own_rows(rows)[block["shown"]:]:
            ts = when(row.get("timestamp")) if isinstance(row, dict) else None
            if until is not None and ts is not None and ts > until:
                break
            block["shown"] += 1
            out.extend(dict(r, ts=r.get("ts", ts)) for r in child.made(row))
        for sub_call, sub_agent in sorted(child.pending.items()):
            out.extend(child.subagent_block(sub_call, sub_agent, until, over))
            out.extend(child.left_open(sub_call) if over else [])
        for sub_call in sorted(child.shells) if over else []:
            out.extend(child.left_open(sub_call))
        if over:
            child.pending.clear()
            child.shells.clear()
        return out

    def place(self, path):
        """A path as the app shows it: relative inside the Fleet checkout, otherwise as written."""
        text = str(path or "")
        if self.root and os.path.isabs(text):
            real = os.path.realpath(text)
            if real == self.root or real.startswith(self.root + os.sep):
                text = os.path.relpath(real, self.root)
        return clip(text, 300)

    # ---- Claude Code transcript lines
    def claude(self, row):
        kind, out, at = row.get("type"), [], when(row.get("timestamp"))
        message = row.get("message") if isinstance(row.get("message"), dict) else {}
        origin = row.get("origin") if isinstance(row.get("origin"), dict) else {}
        if self.prefix and row.get("isMeta") and kind == "user" and origin.get("kind") == "task-notification":
            # In a subagent's own file, the notice of the end of its own background work is a row of this form, with
            # a frame of Claude Code's text before the notice (2.1.321, 11 November 2026). It ends that work in the
            # subagent's records, and it is nobody's words.
            return self.notices(text_of(message.get("content")), at)
        if (row.get("isSidechain") and not self.prefix) or row.get("isMeta") or row.get("isCompactSummary") \
                or row.get("isVisibleInTranscriptOnly"):
            return []
        if self.ending and not (kind == "assistant" and message.get("id") == self.ending):
            out += self.turn_end("end_turn")        # the first row after the message that ended the turn
        if kind == "queue-operation" and row.get("operation") == "enqueue":
            return out + self.notices(row.get("content"), at)
        if kind == "attachment":
            attachment = row.get("attachment") if isinstance(row.get("attachment"), dict) else {}
            return out + (self.notices(attachment.get("prompt"), at) if attachment.get("type") == "queued_command" else [])
        if kind not in ("user", "assistant", "system"):
            return out
        if not self.started and row.get("sessionId"):
            self.started = True
            out.append({"type": "session", "runtime": "claude", "session_id": clip(row["sessionId"], 80)})
        if kind == "assistant" and self.prefix is None:
            out += self.model_record(message.get("model"), None)       # Claude transcripts give no effort
            self.turn = True
        content = message.get("content")
        if kind == "system":
            # turn_duration is missing on about one turn in five, and it follows the end_turn row when it is there:
            # it is the end only of a turn whose end_turn row was not read.
            if row.get("subtype") == "turn_duration" and self.turn and self.prefix is None:
                out += self.turn_end("end_turn")
            elif row.get("subtype") == "turn_duration" and self.prefix is not None:
                out.append({"type": "result", "stop_reason": "end_turn"})
            return out
        if kind == "assistant" and row.get("isApiErrorMessage"):
            code = re.sub(r"[^a-z_]", "", str(row.get("error") or "api_error").lower())[:40] or "api_error"
            quota = row.get("quotaLimits") if isinstance(row.get("quotaLimits"), dict) else {}
            limited = code == "rate_limit" and quota.get("status") == "rejected"
            out.append({"type": "error", "code": "usage_limit" if limited else code,
                        "message": clip(text_of(content).strip(), MESSAGE),
                        "retryable": code in ("rate_limit", "server_error"),
                        "resets_at": when(quota.get("resetsAt")) if limited else None})
            if self.prefix is None:
                out += self.turn_end("error")       # the turn stops at the error that Claude Code shows
            return out
        blocks = [{"type": "text", "text": content}] if isinstance(content, str) else content if isinstance(content, list) else []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            btype = block.get("type")
            if kind == "assistant" and btype == "text" and str(block.get("text") or "").strip():
                out.append({"type": "agent_message", "text": clip(block["text"].strip(), TEXT)})
            elif kind == "assistant" and btype == "thinking" and str(block.get("thinking") or "").strip():
                out.append({"type": "agent_thought", "text": clip(block["thinking"].strip(), THOUGHT)})
            elif kind == "assistant" and btype == "tool_use" and block.get("id"):
                out.extend(self.claude_call(block))
            elif kind == "user" and btype == "text":
                text = str(block.get("text") or "").strip()
                if text.startswith("<task-notification>"):     # a background task's end, not the user's words
                    out.extend(self.notices(text, at))
                    self.turn = self.turn or self.prefix is None    # an idle session's notice starts a turn
                elif text.startswith("[Request interrupted by user"):
                    if self.prefix is not None:
                        out.append({"type": "result", "stop_reason": "cancelled"})
                    elif self.turn:
                        out += self.turn_end("cancelled")
                elif text:
                    self.turn = self.turn or self.prefix is None
                    out.append({"type": "user_message", "text": clip(text, TEXT)})
            elif kind == "user" and btype == "tool_result":
                call = clip(block.get("tool_use_id"), 100)
                if call in self.silent:
                    out.extend(self.claude_task_made(call, block, row))
                    continue
                if call not in self.open:
                    continue
                result = row.get("toolUseResult") if isinstance(row.get("toolUseResult"), dict) else {}
                if call in self.agents:
                    agent = result.get("agentId")
                    if result.get("status") == "async_launched" or result.get("isAsync") is True:
                        self.pending[call] = agent      # it runs on; its end comes as a notice
                        out.append({"type": "tool_call_update", "tool_call_id": call, "status": "in_progress",
                                    "background": True, "interrupted": False})
                        continue
                    out.extend(self.subagent_block(call, agent, at, over=True))     # its agent waited for it
                body = text_of(block.get("content")).strip()
                tool = self.shell_calls.pop(call, None)
                running = result.get("backgroundTaskId") if tool == "Bash" else result.get("taskId") if tool == "Monitor" \
                    or (tool == "Workflow" and result.get("status") == "async_launched") else None
                if call in self.asked and not result and tool == "Bash":
                    # a subagent's file: the id is in the result's own words, when a notice of the end will come
                    found = BACKGROUND_ID.match(body) if BACKGROUND_NOTICE in body else None
                    running = found.group(1) if found else None
                self.asked.discard(call)
                if isinstance(running, str) and running.strip() and not block.get("is_error"):
                    # A command that runs on in the background, a monitor or a workflow: open until its own end notice,
                    # so that nothing takes its session for one that waits on nothing.
                    self.shells[call] = running.strip()
                    out.append({"type": "tool_call_update", "tool_call_id": call, "status": "in_progress",
                                "background": True, "interrupted": False, "output": clip(body, OUTPUT)})
                    continue
                stopped = self.stops.pop(call, None)
                if stopped and not block.get("is_error"):
                    # The session stopped a background command, a monitor or a workflow of its own: no notice of that
                    # end comes, so the call stayed open, and the hub counted a stopped command as work at every turn
                    # end until the session's end (four commands of three tasks in the fleet's records, 2 to 10
                    # November 2026). It did not finish: the record that a notice of a stopped task gives.
                    out.extend(self.stop(stopped))
                self.open.discard(call)
                out.append({"type": "tool_call_update", "tool_call_id": call,
                            "status": "failed" if block.get("is_error") else "completed",
                            "interrupted": "[Request interrupted by user" in body, "output": clip(body, OUTPUT)})
        if kind == "assistant" and self.prefix is None and message.get("stop_reason") == "end_turn":
            if message.get("id"):
                self.ending = message["id"]         # its turn end goes out at the next row or a quiet read
            else:
                out += self.turn_end("end_turn")
        return out

    def notices(self, text, ts=None):
        """Async subagents and background commands that ended, by Claude Code's task notices (the first copy of a
        notice counts). A notice without one of SHELL_ENDS is a monitor's event: its call stays open.

        ts: the time of the row that carries the notice. The first notice of a subagent in the background ends its
        call, after the subagent's rows up to that time. A subagent whose call has ended can run again
        (subagent_block): a later notice of it gives the rows that it wrote since and its status once more, and
        nothing when no row came and the status is the same, as for a copy of a notice. Such a notice names the
        subagent's task, and the call only the first time (2.1.321)."""
        out = []
        if not (self.pending or self.shells or self.blocks) or "<task-notification>" not in str(text or ""):
            return out
        for notice in NOTICE.findall(str(text)):
            named = clip(notice_tag(notice, "tool-use-id") or "", 100)
            agents = set(re.findall(r"<task-id>\s*([^<]*?)\s*</task-id>", notice))    # older notices name only agents
            first = [named] if named in self.pending else [c for c, a in sorted(self.pending.items()) if a and a in agents]
            later = [c for c, b in sorted(self.blocks.items())
                     if c not in self.pending and (c == named or (b["named"] and b["named"] in agents))]
            state = notice_tag(notice, "status")
            status = "completed" if state == "completed" else "failed"
            for call in first + later:
                block = self.blocks.get(call)
                agent = self.pending.pop(call) if call in first else block["agent"]
                more = self.subagent_block(call, agent, ts, over=status != "completed")
                if call in later and not more and block["status"] == status:
                    continue
                block = self.blocks.get(call)
                if block:       # a launch that named no agent: its notice does, and the later ones name nothing else
                    block["named"] = block["named"] or (min(agents) if len(agents) == 1 else None)
                    block["status"] = status
                self.open.discard(call)
                out.extend(more)
                out.append({"type": "tool_call_update", "tool_call_id": call, "interrupted": False, "status": status})
            if state in SHELL_ENDS:
                shells = [named] if named in self.shells else [c for c, t in sorted(self.shells.items()) if t in agents]
                for call in shells:
                    self.shells.pop(call)
                    self.open.discard(call)
                    out.append({"type": "tool_call_update", "tool_call_id": call, "interrupted": False,
                                "status": status})
        return out

    def claude_call(self, block):
        call, name = clip(block["id"], 100), str(block.get("name") or "tool")
        args = block.get("input") if isinstance(block.get("input"), dict) else {}
        if name == "TodoWrite" and isinstance(args.get("todos"), list):
            self.silent.add(call)
            return [{"type": "plan", "entries": plan_entries(args["todos"], "content")}]
        if name in CLAUDE_TASK_TOOLS:
            self.silent.add(call)
            return self.claude_task(call, name, args)
        server, label, kind = None, name, CLAUDE_KINDS.get(name, "other")
        if name.startswith("mcp__") and name.count("__") >= 2:
            _, server, tool = name.split("__", 2)
            label, kind = f"{server}: {tool}", mcp_kind(tool)
        field = CLAUDE_FIELDS.get(name)
        value = args.get(field) if field else next((v for v in args.values() if isinstance(v, str) and v.strip()), "")
        detail = first_line(value)
        self.open.add(call)
        if name in BACKGROUND_TOOLS:
            self.shell_calls[call] = name           # a result with a task id makes it a background call
        if name == "Bash" and args.get("run_in_background") is True:
            self.asked.add(call)
        if name in STOP_TOOLS:
            self.stops[call] = str(args.get("task_id") or args.get("shell_id") or "").strip()
        if name == "Workflow":                      # its saved name, else its script's own description
            found = WORKFLOW_DESCRIPTION.search(str(args.get("script") or ""))
            detail = first_line(args.get("name") or (found.group(2) if found else "") or
                                os.path.basename(str(args.get("scriptPath") or "")))
        if self.prefix is None:                     # the helper closes a delivered task at the end of its turn
            self.after = self.after or (self.delivered and not name.startswith("mcp__fleet__"))
            self.delivered = self.delivered or name == "mcp__fleet__deliver_result"
        record = {"type": "tool_call", "tool_call_id": call, "title": clip(f"{label}: {detail}" if detail else label, TITLE),
                  "kind": kind, "status": "in_progress", "server": clip(server, 60) if server else None}
        # What the agent itself says the command does, in its own plain words (Bash's description): the owner's apps
        # show it as what the agent does now. The title keeps the command, which a person does not read at a glance.
        says = first_line(args.get("description")) if name == "Bash" else ""
        if says:
            record["says"] = clip(says, SAYS)
        path = args.get("file_path") or args.get("notebook_path") or (args.get("path") if name in ("Grep", "Glob", "LS") else None)
        if isinstance(path, str) and path.strip():
            record["locations"] = [{"path": self.place(path)}]
        change = self.claude_change(name, args)
        if change:
            record["changes"] = [change]
        if isinstance(path, str) and path.strip() and (change or name in ("Read", "NotebookRead")):
            self.read_paths.add(os.path.realpath(path) if os.path.isabs(path) else path)    # the session knows this file now
        if name in ("Task", "Agent"):
            self.agents[call] = None
            record["subagent"] = {"name": clip(args.get("subagent_type") or args.get("description") or name, 100)}
        return [record]

    def claude_task(self, call, name, args):
        """A plan record when a call changes the session's task list. A new task gets its id from its call's result
        (claude_task_made), and an update names that id; a deleted task leaves the plan."""
        before = plan_entries(self.tasks, "content")
        if name == "TaskCreate" and str(args.get("subject") or "").strip():
            self.tasks.append({"id": None, "call": call, "content": args["subject"], "status": "pending"})
        elif name == "TaskUpdate":
            task = next((t for t in self.tasks if t["id"] is not None and t["id"] == str(args.get("taskId"))), None)
            if task and args.get("status") == "deleted":
                self.tasks.remove(task)
            elif task:
                if args.get("status") in ("pending", "in_progress", "completed"):
                    task["status"] = args["status"]
                if str(args.get("subject") or "").strip():
                    task["content"] = args["subject"]
        after = plan_entries(self.tasks, "content")
        return [{"type": "plan", "entries": after}] if after != before else []

    def claude_task_made(self, call, block, row):
        """A TaskCreate's result: the id that later updates name, or, when it was refused, the plan without it."""
        task = next((t for t in self.tasks if t["call"] == call and t["id"] is None), None)
        if task is None:
            return []
        made = TASK_MADE.search(text_of(block.get("content")))
        result = row.get("toolUseResult") if isinstance(row.get("toolUseResult"), dict) else {}
        given = result.get("task", {}).get("id") if isinstance(result.get("task"), dict) else None
        if made or isinstance(given, (str, int)) and not isinstance(given, bool):
            task["id"] = made.group(1) if made else str(given)
        elif block.get("is_error"):
            self.tasks.remove(task)
            return [{"type": "plan", "entries": plan_entries(self.tasks, "content")}]
        return []

    def claude_change(self, name, args):
        """What an edit tool changes, from its input: path, action and line counts. Never the text itself."""
        path = args.get("file_path") or args.get("notebook_path")
        if name not in ("Edit", "MultiEdit", "Write", "NotebookEdit") or not isinstance(path, str) or not path.strip():
            return None
        if name == "Edit":
            whole = args.get("replace_all") is True
            return {"path": self.place(path), "action": "modify", "added": None if whole else line_count(args.get("new_string")),
                    "removed": None if whole else line_count(args.get("old_string"))}
        if name == "MultiEdit":
            edits = [e for e in args.get("edits") or [] if isinstance(e, dict)]
            whole = any(e.get("replace_all") is True for e in edits)
            return {"path": self.place(path), "action": "modify",
                    "added": None if whole else sum(line_count(e.get("new_string")) for e in edits),
                    "removed": None if whole else sum(line_count(e.get("old_string")) for e in edits)}
        if name == "Write":     # Claude Code writes over a file only after it has read, written or edited it
            known = (os.path.realpath(path) if os.path.isabs(path) else path) in self.read_paths
            return {"path": self.place(path), "action": "modify" if known else "add",
                    "added": line_count(args.get("content")), "removed": None}
        return {"path": self.place(path), "action": "modify", "added": None, "removed": None}

    # ---- Codex rollout lines
    def codex(self, row):
        kind, out = row.get("type"), []
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        ptype = payload.get("type")
        if kind == "session_meta":
            if not self.started:
                self.started = True
                out.append({"type": "session", "runtime": "codex", "session_id": clip(payload.get("id") or "", 80)})
            return out
        if kind == "turn_context":
            return self.model_record(payload.get("model"), payload.get("effort")) if self.prefix is None else []
        if kind == "response_item" and ptype in ("function_call", "custom_tool_call") and payload.get("call_id"):
            return self.codex_call(payload)
        if kind == "response_item" and ptype in ("function_call_output", "custom_tool_call_output") and payload.get("call_id"):
            call = clip(payload["call_id"], 100)
            if call in self.silent or call not in self.open or self.agents.get(call):
                return out          # a spawned subagent runs on: its call ends when the subagent returns
            self.open.discard(call)
            body = text_of(payload.get("output")).strip()
            out.append({"type": "tool_call_update", "tool_call_id": call, "status": "completed",
                        "interrupted": "interrupted" in body.lower()[:200] or "aborted" in body.lower()[:200],
                        "output": clip(body, OUTPUT)})
            return out + self.codex_background(call, payload.get("output"))
        if kind != "event_msg":
            return out
        if ptype == "item_completed":
            return self.codex_item(payload.get("item") if isinstance(payload.get("item"), dict) else {})
        if ptype == "task_started":
            self.turns.add(payload.get("turn_id"))
            self.limit = False      # a limit in a later turn is that turn's own: it gives its own record
            self.turn = self.prefix is None     # a turn of the main session runs until its end (Helper.turn_runs)
        elif ptype == "task_complete":
            self.turn = False
            # Newer rollouts give the error that ended a turn, such as its usage limit, only in its end. A usage limit
            # that a token_count already gave is not given a second time.
            error = payload.get("error") if isinstance(payload.get("error"), dict) else None
            known = self.limit
            record = self.codex_error(error) if error else None
            if record and not (known and record["code"] == "usage_limit"):
                out.append(record)
            out.append({"type": "result", "stop_reason": "error" if error else "end_turn"})
        elif ptype == "turn_aborted":
            self.turn = False
            out.append({"type": "result", "stop_reason": "cancelled"})
        elif ptype == "error":
            out.append(self.codex_error(payload))
        elif ptype == "token_count" and isinstance(payload.get("rate_limits"), dict):
            limits = payload["rate_limits"]
            windows = [limits[k] for k in ("primary", "secondary") if isinstance(limits.get(k), dict)]
            full = [w for w in windows if isinstance(w.get("used_percent"), (int, float)) and w["used_percent"] >= 100]
            resets = [r for r in (when(w.get("resets_at")) for w in (full or windows)) if r]
            self.reset = max(resets) if resets else None
            reached = bool(limits.get("rate_limit_reached_type")) or bool(full)
            if reached and not self.limit:
                out.append({"type": "error", "code": "usage_limit", "message": "Codex usage limit reached.",
                            "retryable": True, "resets_at": self.reset})
            self.limit = reached
        return out

    def codex_error(self, error):
        """The record of a Codex error: an error event, or the error in the end of the turn that it ended."""
        message, info = str(error.get("message") or ""), str(error.get("codex_error_info") or "")
        limited = "usage_limit" in info.lower() or "usage limit" in message.lower()
        code = "usage_limit" if limited else (re.sub(r"[^a-z_]", "", info.lower())[:40] or "error")
        self.limit = self.limit or limited
        return {"type": "error", "code": code, "message": clip(message, MESSAGE), "retryable": limited,
                "resets_at": self.reset if limited else None}

    def codex_activity(self, item):
        """Codex multi-agent: "started" names the spawn call; "completed" names the subagent's turn that ended."""
        thread, kind = str(item.get("agent_thread_id") or ""), item.get("kind")
        if kind == "started":
            call = clip(item.get("id") or "", 100)
            if thread and call in self.agents and not self.agents[call]:
                self.agents[call], self.threads[thread] = thread, call
                if call in self.open:
                    # A Codex subagent runs on beside its parent's turn, as a Claude async agent does, so it is
                    # background work until its own end (live_reason, fresh_refusal, open_agents; AUTONOMY.md
                    # decision 41 gives every agent its runtime's own way to split work)
                    return [{"type": "tool_call_update", "tool_call_id": call, "status": "in_progress",
                             "background": True, "interrupted": False}]
            return []
        call = self.threads.get(thread)
        if not call or kind not in ("completed", "interrupted"):
            return []
        named = re.fullmatch(r"subagent-completed-(.+)", str(item.get("id") or ""))
        out = self.codex_kid(thread, call, turn=named.group(1) if named else None)
        if call in self.open:
            self.open.discard(call)
            out.append({"type": "tool_call_update", "tool_call_id": call, "interrupted": kind == "interrupted",
                        "status": "completed" if kind == "completed" else "failed"})
        return out

    def codex_kid(self, thread, call, turn=None, last=False):
        """A Codex subagent's own records, from its rollout, up to the end of the turn that the parent saw end
        (no turn named: its next aborted turn; last: all). A fixed place keeps the sequence numbers the same."""
        if not self.children:
            return []
        kid = self.kids.get(thread)
        if kid is None:
            child = Translator(self.runtime, self.root, self.children, prefix=f"{self.prefix}/{call}" if self.prefix else call)
            kid = self.kids[thread] = {"translator": child, "rows": [], "offset": 0, "done": None, "parent_turns": set(self.turns)}
        new, kid["offset"] = self.children(thread, kid["offset"])
        kid["rows"].extend(new)
        rows, child = kid["rows"], kid["translator"]
        if kid["done"] is None:
            own = codex_own_start(rows, kid["parent_turns"])
            if own is None:
                return []
            for row in rows[:own]:      # the copied history shows nothing; its turns are known to the subagent's own subagents
                start = codex_event(row, "task_started")
                if start:
                    child.turns.add(start.get("turn_id"))
            kid["done"] = own
        begin = kid["done"]
        if last:
            end = len(rows) - 1
        else:
            end = next((n for n in range(begin, len(rows)) if codex_turn_end(rows[n], turn)), None)
            if end is None:
                return []
        out = []
        for row in rows[begin:end + 1]:
            ts = when(row.get("timestamp"))
            out.extend(dict(r, ts=r.get("ts", ts)) for r in child.made(row))
        kid["rows"], kid["done"] = rows[end + 1:], 0       # shown rows are not needed again
        return out + (child.remaining() if last else [])

    def codex_background(self, call, output):
        """A command that runs longer than its wait returns a session id and no exit code. It keeps running,
        so it becomes its own open call, named by its command, until the process ends."""
        chunks = []
        for item in output if isinstance(output, list) else [output]:
            text = text_of(item).strip()
            try:
                value = json.loads(text) if text.startswith("{") else None
            except ValueError:
                value = None
            if isinstance(value, dict) and "chunk_id" in value:
                chunks.append(value)
        commands = self.commands.pop(call, [])
        out = []
        for index, chunk in enumerate(chunks):
            session = chunk.get("session_id")
            if session is None or chunk.get("exit_code") is not None or str(session) in self.background:
                continue
            command = commands[index] if len(commands) == len(chunks) else f"background session {session}"
            proc = clip(f"proc-{session}", 100)
            self.background[str(session)] = proc
            self.open.add(proc)
            out.append({"type": "tool_call", "tool_call_id": proc, "title": clip("Shell (background): " + first_line(command), TITLE),
                        "kind": "execute", "status": "in_progress", "server": None})
        return out

    def codex_call(self, payload):
        call, name = clip(payload["call_id"], 100), str(payload.get("name") or "tool")
        raw = payload.get("arguments") if payload.get("type") == "function_call" else payload.get("input")
        plans = []
        if name == "exec" and isinstance(raw, str):
            plans, alone = code_plans(raw)
            if alone:
                self.silent.add(call)       # a script that only keeps its plan shows as the plan, not as a call
                return plans
            commands = [m.group(2).replace("\\" + m.group(1), m.group(1)) for m in EXEC_CMD.finditer(raw)]
            if commands:
                self.commands[call] = commands
            waits = STDIN.findall(raw)
            if waits and not commands and "tools.mcp__" not in raw and all(not chars for _, _, chars in waits):
                self.open.add(call)        # only a wait on running commands: it changes nothing by itself
                return plans + [{"type": "tool_call", "tool_call_id": call, "kind": "read", "status": "in_progress",
                                 "server": None, "title": clip("Wait: background session " +
                                                               ", ".join(session for session, _, _ in waits), TITLE)}]
        if name == "spawn_agent":
            try:
                args = json.loads(raw) if isinstance(raw, str) else raw
            except ValueError:
                args = None
            args = args if isinstance(args, dict) else {}
            task = first_line(args.get("task_name") or args.get("agent_type") or "subagent")
            self.open.add(call)
            self.agents[call] = None
            return [{"type": "tool_call", "tool_call_id": call, "title": clip("Agent: " + task, TITLE), "kind": "other",
                     "status": "in_progress", "server": None,
                     "subagent": {"name": clip(first_line(args.get("agent_type") or task), 100)}}]
        if name == "update_plan":
            try:
                args = json.loads(raw) if isinstance(raw, str) else raw
            except ValueError:
                args = None
            if isinstance(args, dict):
                self.silent.add(call)
                return [{"type": "plan", "entries": plan_entries(args.get("plan"), "step")}]
        if isinstance(raw, str) and raw.strip().startswith("{"):
            try:
                parsed = json.loads(raw)
                raw = next((v for v in parsed.values() if isinstance(v, str) and v.strip()), raw) if isinstance(parsed, dict) else raw
            except ValueError:
                pass
        label = f"{payload['namespace']}.{name}" if payload.get("namespace") else name
        detail = first_line(raw if isinstance(raw, str) else "")
        self.open.add(call)
        return plans + [{"type": "tool_call", "tool_call_id": call, "title": clip(f"{label}: {detail}" if detail else label,
                                                                             TITLE),
                         "kind": CODEX_KINDS.get(name, "other"), "status": "in_progress", "server": None}]

    def codex_item(self, item):
        itype, ident = item.get("type"), clip(item.get("id") or "", 100)
        status = "failed" if item.get("status") == "failed" else "completed"
        if itype == "SubAgentActivity":
            return self.codex_activity(item)
        if itype == "AgentMessage" and text_of(item.get("content")).strip():
            return [{"type": "agent_message", "text": clip(text_of(item["content"]).strip(), TEXT)}]
        if itype == "UserMessage":
            text = MARKER_TEXT.sub("", text_of(item.get("content"))).strip()
            return [{"type": "user_message", "text": clip(text, TEXT)}] if text else []
        if itype == "Reasoning":
            text = "\n".join(str(s) for s in item.get("summary_text") or [] if isinstance(s, str)).strip()
            return [{"type": "agent_thought", "text": clip(text, THOUGHT)}] if text else []
        if not ident:
            return []
        if itype == "CommandExecution":
            parsed = [c.get("cmd") for c in item.get("parsed_cmd") or [] if isinstance(c, dict) and c.get("cmd")]
            command = " && ".join(parsed) or " ".join(str(c) for c in item.get("command") or [])
            if item.get("exit_code") not in (0, None):
                status = "failed"
            proc = self.background.pop(str(item.get("process_id") or ""), None)
            if proc and proc in self.open:
                self.open.discard(proc)
                return [{"type": "tool_call_update", "tool_call_id": proc, "status": status, "interrupted": False,
                         "output": clip(str(item.get("aggregated_output") or "").strip(), OUTPUT)}]
            return [{"type": "tool_call", "tool_call_id": ident, "title": clip("Shell: " + first_line(command), TITLE),
                     "kind": "execute", "status": status, "server": None,
                     "output": clip(str(item.get("aggregated_output") or "").strip(), OUTPUT)}]
        if itype == "McpToolCall":
            server, tool = str(item.get("server") or "mcp"), str(item.get("tool") or "tool")
            result = item.get("result") if isinstance(item.get("result"), dict) else {}
            if result.get("isError"):
                status = "failed"
            return [{"type": "tool_call", "tool_call_id": ident, "title": clip(f"{server}: {tool}", TITLE),
                     "kind": "read" if item.get("readOnlyHint") else mcp_kind(tool), "status": status,
                     "server": clip(server, 60), "output": clip(text_of(result.get("content")).strip(), OUTPUT)}]
        if itype == "FileChange":
            changed = item.get("changes") if isinstance(item.get("changes"), dict) else {}
            changes = []
            for path, change in sorted(changed.items())[:50]:
                change = change if isinstance(change, dict) else {}
                kind = change.get("type")
                if kind == "add":
                    changes.append({"path": self.place(path), "action": "add", "added": line_count(change.get("content")), "removed": 0})
                elif kind == "delete":
                    changes.append({"path": self.place(path), "action": "delete", "added": 0,
                                    "removed": line_count(change.get("content")) if change.get("content") else None})
                else:
                    added, removed = diff_counts(change.get("unified_diff")) if change.get("unified_diff") else (None, None)
                    changes.append({"path": self.place(path), "action": "move" if change.get("move_path") else "modify",
                                    "added": added, "removed": removed})
            record = {"type": "tool_call", "tool_call_id": ident, "title": clip("Edit: " + ", ".join(sorted(changed)), TITLE),
                      "kind": "edit", "status": status, "server": None}
            if changes:
                record["changes"] = changes
                record["locations"] = [{"path": c["path"]} for c in changes[:20]]
            return [record]
        if itype == "Extension":
            return [{"type": "tool_call", "tool_call_id": ident,
                     "title": clip(f"{item.get('kind') or 'search'}: {first_line(item.get('query'))}", TITLE),
                     "kind": "search", "status": "completed", "server": None}]
        return []

    # ---- Codex app-server notifications: a screen task's runner writes {timestamp, method, params} lines
    def codex_app(self, row):
        method = row.get("method")
        params = row.get("params") if isinstance(row.get("params"), dict) else {}
        out = []
        if not self.started and isinstance(params.get("threadId"), str) and params["threadId"]:
            self.started = True
            out.append({"type": "session", "runtime": "codex", "session_id": clip(params["threadId"], 80)})
        if method in ("item/started", "item/completed"):
            item = params.get("item") if isinstance(params.get("item"), dict) else {}
            return out + self.app_item(item, method == "item/completed")
        if method == "fleet/model":         # the screen runner: the model and effort that thread/start reported
            return out + self.model_record(params.get("model"), params.get("effort"))
        if method == "turn/plan/updated":
            plan = params.get("plan") if isinstance(params.get("plan"), list) else []
            steps = [dict(s, status="in_progress" if s.get("status") == "inProgress" else s.get("status"))
                     for s in plan if isinstance(s, dict)]
            out.append({"type": "plan", "entries": plan_entries(steps, "step")})
        elif method == "turn/completed":
            turn = params.get("turn") if isinstance(params.get("turn"), dict) else {}
            if turn.get("status") == "failed" and turn.get("id") != self.failed:
                out.append(self.app_error(turn.get("error")))
            stop = {"completed": "end_turn", "interrupted": "cancelled", "failed": "error"}.get(turn.get("status"))
            if stop:
                out.append({"type": "result", "stop_reason": stop})
        elif method == "error" and not params.get("willRetry"):      # a retried stream error is not shown
            self.failed = params.get("turnId")
            out.append(self.app_error(params.get("error")))
        elif method == "account/rateLimits/updated":
            out.extend(self.app_limits(params.get("rateLimits")))
        return out

    def app_item(self, item, done):
        itype, ident = item.get("type"), clip(item.get("id") or "", 100)
        if not done:
            call = self.app_call(item) if ident else None
            if call:
                self.open.add(ident)
                return [dict(call, tool_call_id=ident, status="in_progress")]
            return []
        if itype == "agentMessage" and str(item.get("text") or "").strip():
            return [{"type": "agent_message", "text": clip(str(item["text"]).strip(), TEXT)}]
        if itype == "userMessage":
            text = text_of(item.get("content")).strip()
            return [{"type": "user_message", "text": clip(text, TEXT)}] if text else []
        if itype == "reasoning":
            summary = item.get("summary") if isinstance(item.get("summary"), list) else []
            text = "\n".join(s for s in summary if isinstance(s, str)).strip()
            return [{"type": "agent_thought", "text": clip(text, THOUGHT)}] if text else []
        call = self.app_call(item) if ident else None
        if not call:
            return []
        result = item.get("result") if isinstance(item.get("result"), dict) else {}
        error = item.get("error") if isinstance(item.get("error"), dict) else {}
        failed = item.get("status") in ("failed", "declined") or item.get("exitCode") not in (0, None) or error \
            or item.get("success") is False
        if itype == "commandExecution":
            output = item.get("aggregatedOutput")
        elif itype == "mcpToolCall":
            output = text_of(result.get("content")) or error.get("message")
        else:
            output = text_of(item.get("contentItems"))
        status, output = ("failed" if failed else "completed"), clip(str(output or "").strip(), OUTPUT)
        if ident in self.open:
            self.open.discard(ident)
            return [{"type": "tool_call_update", "tool_call_id": ident, "status": status, "interrupted": False,
                     "output": output}]
        return [dict(call, tool_call_id=ident, status=status, output=output)]       # its start was not recorded

    def app_call(self, item):
        """The row of a tool call item: title, kind and server. None for an item that is not a tool call."""
        itype = item.get("type")
        if itype == "commandExecution":
            actions = item.get("commandActions") if isinstance(item.get("commandActions"), list) else []
            parsed = [a.get("command") for a in actions if isinstance(a, dict) and a.get("command")]
            command = " && ".join(str(c) for c in parsed) or str(item.get("command") or "")
            return {"type": "tool_call", "title": clip("Shell: " + first_line(command), TITLE), "kind": "execute", "server": None}
        if itype == "fileChange":
            listed = item.get("changes") if isinstance(item.get("changes"), list) else []
            listed = sorted((c for c in listed if isinstance(c, dict) and c.get("path")), key=lambda c: str(c["path"]))
            changes = []
            for change in listed[:50]:          # counts from the diff (an added or deleted file: its text), never the text
                kind = change.get("kind") if isinstance(change.get("kind"), dict) else {}
                action = {"add": "add", "delete": "delete"}.get(kind.get("type")) or ("move" if kind.get("move_path") else "modify")
                diff = change.get("diff") if isinstance(change.get("diff"), str) and len(change["diff"]) <= APP_TEXT else None
                added, removed = ((line_count(diff), 0) if action == "add" else (0, line_count(diff)) if action == "delete"
                                  else diff_counts(diff)) if diff is not None else (None, None)
                changes.append({"path": self.place(change["path"]), "action": action, "added": added, "removed": removed})
            record = {"type": "tool_call", "title": clip("Edit: " + ", ".join(str(c["path"]) for c in listed), TITLE),
                      "kind": "edit", "server": None}
            if changes:
                record["changes"] = changes
                record["locations"] = [{"path": c["path"]} for c in changes[:20]]
            return record
        if itype == "mcpToolCall":
            server, tool = str(item.get("server") or "mcp"), str(item.get("tool") or "tool")
            args = item.get("arguments") if isinstance(item.get("arguments"), dict) else {}
            detail = first_line(next((v for v in args.values() if isinstance(v, str) and v.strip()), ""))
            # The tool's own readOnlyHint is not trusted: cua_repl marks each js call read-only, also a click.
            return {"type": "tool_call", "title": clip(f"{server}: {tool}: {detail}" if detail else f"{server}: {tool}", TITLE),
                    "kind": mcp_kind(tool), "server": clip(server, 60)}
        if itype == "dynamicToolCall":
            tool = str(item.get("tool") or "tool")
            label = f"{item['namespace']}.{tool}" if isinstance(item.get("namespace"), str) and item["namespace"] else tool
            return {"type": "tool_call", "title": clip(label, TITLE), "kind": "other", "server": None}
        if itype == "webSearch":
            return {"type": "tool_call", "title": clip("web_search: " + first_line(item.get("query")), TITLE),
                    "kind": "search", "server": None}
        if itype == "imageView":
            return {"type": "tool_call", "title": clip("View image: " + first_line(item.get("path")), TITLE),
                    "kind": "read", "server": None}
        return None

    def app_error(self, error):
        error = error if isinstance(error, dict) else {}
        info = error.get("codexErrorInfo")
        name = str(next(iter(info), "")) if isinstance(info, dict) else str(info or "")     # "usageLimitExceeded", {…}
        message = str(error.get("message") or "")
        limited = name == "usageLimitExceeded" or "usage limit" in message.lower()
        code = "usage_limit" if limited else re.sub(r"[^a-z_]", "", re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower())[:40]
        self.limit = self.limit or limited
        return {"type": "error", "code": code or "error", "message": clip(message, MESSAGE), "retryable": limited,
                "resets_at": self.reset if limited else None}

    def app_limits(self, limits):
        """A rolling account update. A window at 100% or a reached type is a usage limit; an update that leaves
        out both windows and the reached type says nothing about it."""
        limits = limits if isinstance(limits, dict) else {}
        windows = [limits[k] for k in ("primary", "secondary") if isinstance(limits.get(k), dict)]
        full = [w for w in windows if isinstance(w.get("usedPercent"), (int, float)) and w["usedPercent"] >= 100]
        resets = [r for r in (when(w.get("resetsAt")) for w in (full or windows)) if r]
        if resets:
            self.reset = max(resets)
        if not windows and not limits.get("rateLimitReachedType"):
            return []
        reached = bool(limits.get("rateLimitReachedType")) or bool(full)
        out = []
        if reached and not self.limit:
            out.append({"type": "error", "code": "usage_limit", "message": "Codex usage limit reached.",
                        "retryable": True, "resets_at": self.reset})
        self.limit = reached
        return out


# ---------------------------------------------------------------- finding a session's file

def claude_file(session, home):
    for path in glob.glob(os.path.join(home, ".claude", "projects", "*", session + ".jsonl")):
        if not os.path.islink(path):
            return path
    return None


def screen_file(session, home):
    """The record file of a screen task, which screen_runner.py writes in the helper's own folder."""
    path = os.path.join(home, ".fleet", f"screen-{session}.jsonl")
    return path if UUID.fullmatch(session) and os.path.isfile(path) and not os.path.islink(path) else None


def manager_transcript(home, kit, prompt):
    """The session id of the newest transcript in the kit's own project folder that starts with this prompt.
    Only for a manager session started before session ids; other projects' files are never opened."""
    folder = os.path.join(home, ".claude", "projects", re.sub(r"[^A-Za-z0-9-]", "-", os.path.realpath(kit)))
    try:
        paths = sorted((p for p in glob.glob(os.path.join(folder, "*.jsonl")) if not os.path.islink(p)),
                       key=os.path.getmtime, reverse=True)
    except OSError:
        return None
    for path in paths[:20]:
        try:
            if time.time() - os.path.getmtime(path) > 7 * 86400:
                break
            with open(path, "rb") as stream:
                head = stream.read(256 * 1024)
        except OSError:
            continue
        for line in head.splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict) and row.get("type") == "user" and not row.get("isMeta"):
                content = (row.get("message") or {}).get("content") if isinstance(row.get("message"), dict) else None
                if text_of(content).strip().startswith(prompt[:60]):
                    return os.path.basename(path)[:-len(".jsonl")]
                break
    return None


class CodexFiles:
    """Find the rollout whose first lines carry a session's marker. A file never changes its first lines."""

    def __init__(self, home, kit=None):
        self.root = os.environ.get("CODEX_HOME") or os.path.join(home, ".codex")
        self.kit = os.path.realpath(kit) if kit else None
        self.known = {}         # path -> session marker found in it, or None when its head has none
        self.threads = {}       # subagent thread id -> its rollout, or None when it is another folder's

    def find(self, session, since=None):
        """since: the oldest change time to read (default two days ago), for a session that was quiet longer."""
        for path, found in self.known.items():
            if found == session:
                return path
        cutoff = time.time() - 2 * 86400 if since is None else since
        for path in glob.glob(os.path.join(self.root, "sessions", "*", "*", "*", "rollout-*.jsonl")):
            if path in self.known or os.path.islink(path):
                continue
            try:
                if os.path.getmtime(path) < cutoff:
                    continue
                with open(path, "rb") as stream:
                    first = stream.readline(MAX_LINE)
                    if not first.endswith(b"\n"):
                        continue                    # its first line is still being written: read it again later
                    if (self.kit and not self.ours(first)) or self.forked(first):
                        self.known[path] = None     # another folder's session, or a subagent: only its first line
                        continue
                    head = first + stream.read(256 * 1024)
            except OSError:
                continue
            match = re.search(rb"\[fleet-session ([0-9a-f-]{36})\]", head)
            if match:
                self.known[path] = match.group(1).decode()
            # No marker for good only once the first prompt is written: a user-role row of the session's context can
            # come shortly before it.
            elif len(head) >= 256 * 1024 or b'"UserMessage"' in head or b'"type":"user_message"' in head:
                self.known[path] = None
            if self.known.get(path) == session:
                return path
        return None


    def subagent(self, thread, offset=0):
        """A Codex subagent's complete rows after a byte offset, and the offset after them, by the thread id
        that ends its rollout's name (kit folder only)."""
        if not THREAD_ID.fullmatch(str(thread or "")):
            return [], offset
        if thread not in self.threads:
            found = glob.glob(os.path.join(self.root, "sessions", "*", "*", "*", f"rollout-*-{thread}.jsonl"))
            self.threads[thread] = next((p for p in found if not os.path.islink(p)), None)
        if not self.threads[thread]:
            return [], offset
        try:
            with open(self.threads[thread], "rb") as stream:
                if offset == 0 and self.kit and not self.ours(stream.readline(MAX_LINE)):
                    self.threads[thread] = None     # another folder's session: only its first line was read
                    return [], offset
                stream.seek(offset)
                data = stream.read(READ_STEP)
        except OSError:
            return [], offset
        consumed = data.rfind(b"\n") + 1 or (len(data) if len(data) >= READ_STEP else 0)
        return complete_rows(data[:consumed]), offset + consumed

    def ours(self, first):
        try:
            meta = json.loads(first)
            return meta.get("type") != "session_meta" or os.path.realpath(str((meta.get("payload") or {}).get("cwd"))) == self.kit
        except (ValueError, AttributeError):
            return False

    @staticmethod
    def forked(first):
        """True for a subagent's rollout. It starts with a copy of its parent's history, so it carries the parent's
        session marker too, but it is never that session's own file."""
        try:
            meta = json.loads(first)
            payload = (meta.get("payload") or {}) if meta.get("type") == "session_meta" else {}
            source = payload.get("source")
            return bool(payload.get("forked_from_id")) or (isinstance(source, dict) and "subagent" in source)
        except (ValueError, AttributeError):
            return False


# ---------------------------------------------------------------- the helper's thread

AGENT_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
THREAD_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def subagent_reader(path):
    """For a Claude transcript: agent id (or, with no id, the starting call) -> the complete rows of that
    subagent's transcript, or None."""
    folder = os.path.join(os.path.dirname(path), os.path.basename(path)[:-len(".jsonl")], "subagents")

    def agent_of(call):     # an interrupted subagent's result has no agent id; its meta file names the call
        try:
            names = sorted(n for n in os.listdir(folder) if n.startswith("agent-") and n.endswith(".meta.json"))
        except OSError:
            return None
        for name in names:
            try:
                with open(os.path.join(folder, name), "rb") as stream:
                    meta = json.loads(stream.read(65536))
            except (OSError, ValueError):
                continue
            if isinstance(meta, dict) and meta.get("toolUseId") == call:
                return name[len("agent-"):-len(".meta.json")]
        return None

    def rows(agent, call=None):
        agent = agent or (agent_of(call) if call else None)
        if not AGENT_ID.fullmatch(str(agent or "")):
            return None
        try:
            with open(os.path.join(folder, f"agent-{agent}.jsonl"), "rb") as stream:
                return complete_rows(stream.read(READ_STEP))
        except OSError:
            return None
    return rows


class Feed:
    def __init__(self, window, runtime, root=None, requested=None, runner=False):
        self.name, self.generation, self.attempt, self.session = window[:4]
        self.translator = Translator(runtime, root, requested=requested)
        self.path, self.offset, self.pending = None, 0, []
        self.hub_seq = None     # the last record the hub holds; None until asked
        self.dead = False       # the hub refused this session's records for good
        self.ended = False      # its window is gone and its file was read to the end
        # A primary task in the runner: its saved rollout is its file, and the runner's own file gives only how the
        # runner ended the session (Tailer.runner_end), one time (closed).
        self.runner, self.closed = runner, False


class Tailer:
    """Read every task session's records and send them to the hub. A failed send is retried next scan."""

    def __init__(self, runtime, windows, post, home=None, interval=2, kit=None, requested=None, screen_requested=None,
                 runner_requested=None):
        self.runtime, self.windows, self.post, self.interval = runtime, windows, post, interval
        self.requested = requested      # the model and effort that this helper passes to new sessions
        self.screen_requested = screen_requested or {}      # the same for screen tasks (owner API 1.11)
        self.runner_requested = runner_requested            # and for an app-server task of the primary runtime
        self.home = home or os.path.expanduser("~")
        self.codex = CodexFiles(self.home, kit)
        self.kit = kit
        self.lock = threading.RLock()
        self.feeds = {}         # (window name, session) -> Feed

    def run(self):
        while True:
            try:
                self.scan()
            except Exception:
                pass            # never print transcript text or raw errors
            time.sleep(self.interval)

    def feed(self, window, runtime=None):
        """A new feed for a window. A task in the runner ("codex_app") is a screen task when the window names no other
        needs, as before: it reads the runner's file, with the screen runtime's requested settings. A window's
        optional needs, after its runtime, can name another task in the runner (an app-server task of the primary
        runtime). Its thread is saved: its rollout, found by the session's marker as for a terminal Codex session, is
        its one source of records, with the primary runtime's requested settings, and the runner's file gives only
        how the session ended (runner_end). Every other session reads its runtime's own file."""
        runtime = runtime or (window[4] if len(window) > 4 else None) or self.runtime
        # a function gives them as they are when the session starts: the owner's default can change meanwhile
        requested = self.requested() if callable(self.requested) else self.requested
        if runtime == "codex_app" and (window[5] if len(window) > 5 else "screen") != "screen":
            asked = self.runner_requested if self.runner_requested is not None else requested
            return Feed(window, "codex", self.kit, requested=asked() if callable(asked) else asked, runner=True)
        screen = runtime == "codex_app"
        if screen:
            requested = self.screen_requested() if callable(self.screen_requested) else self.screen_requested
        return Feed(window, runtime, self.kit, requested=requested)

    def scan(self):
        """A window is (name, generation, attempt, session) and, optionally, its own runtime ("codex_app" for a
        task in the runner) and its needs. A session that ended keeps its feed until its last records reach the hub."""
        with self.lock:
            live = {(w[0], w[3]): w for w in self.windows()}
            for key, window in live.items():
                if key not in self.feeds:
                    self.feeds[key] = self.feed(window)
                self.pump(self.feeds[key])
            for key in [k for k in self.feeds if k not in live]:
                feed = self.feeds[key]          # the last records of a session that just ended
                sent = self.send(feed) if feed.ended else self.pump(feed, last=True)
                feed.ended = True
                if sent:
                    del self.feeds[key]

    def register(self, window, runtime=None):
        """A session that the helper has just started: (name, generation, attempt, session), its own runtime and its
        needs, as `windows` gives them. Its feed is made now, from what the helper knows. A session that ends before a
        scan sees its window thus has its records read and sent as those of a session that ended. One feed for each
        session: a feed that a scan made already stays as it is."""
        with self.lock:
            key = (window[0], window[3])
            if key not in self.feeds:
                self.feeds[key] = self.feed(window, runtime)

    def flush(self, name):
        """Send everything for one window now. Returns [{session, last_seq}] of its live sessions, or None if a
        send failed, also one for a session of the window that ended (it can be an earlier attempt's)."""
        with self.lock:
            try:
                self.scan()             # also finds a window that the background scan has not seen yet
            except Exception:
                return None
            done = []
            for feed in [f for f in self.feeds.values() if f.name == name]:
                if not self.pump(feed):
                    return None
                if not feed.ended:
                    done.append({"session": feed.session, "last_seq": feed.translator.seq})
            return done

    def quiet(self, name, seconds):
        """True when no record file of this window changed for some seconds."""
        with self.lock:
            try:
                self.scan()
            except Exception:
                pass
            paths = [f.path for f in self.feeds.values() if f.name == name and f.path]
        try:
            return all(time.time() - os.path.getmtime(p) >= seconds for p in paths)
        except OSError:
            return True

    def pump(self, feed, last=False):
        """Read new lines and send them. False when a send failed and must be retried. last: the session is over."""
        if feed.dead:
            return True
        if not feed.path:
            runtime = feed.translator.runtime
            feed.path = (screen_file(feed.session, self.home) if runtime == "codex_app" else
                         claude_file(feed.session, self.home) if runtime == "claude" else self.codex.find(feed.session))
            if not feed.path:
                if last and feed.runner:        # a primary task that ended before its thread was saved
                    self.runner_end(feed)
                    return self.send(feed)
                return True
            feed.translator.children = (subagent_reader(feed.path) if runtime == "claude" else
                                        self.codex.subagent if runtime == "codex" else None)
        for _ in range(16 if last else 1):     # a session that is over is read to its end
            try:
                with open(feed.path, "rb") as stream:
                    stream.seek(feed.offset)
                    data = stream.read(READ_STEP)
            except OSError:
                return True
            consumed = 0
            for line in data.splitlines(keepends=True):
                if not line.endswith(b"\n"):
                    break           # a writer can still be finishing the last line
                consumed += len(line)
                if len(line) > MAX_LINE:
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                feed.pending.extend(feed.translator.records(row))
            feed.offset += consumed
            if not consumed:
                feed.pending.extend(feed.translator.idle())
            if len(data) < READ_STEP:
                if last:
                    feed.pending.extend(feed.translator.finish())
                    if feed.runner:
                        self.runner_end(feed)
                break
        return self.send(feed)

    def runner_end(self, feed):
        """How the runner ended a primary task's session, one time, after its rollout was read to its end. Only the
        runner's own file has it: the last turn there, when it failed (the runtime's own failed turn, or the runner's
        stop record, also from before any thread was saved). A failure that is not a usage limit gives the session its
        error and a result with the stop reason "error", which the hub's failure pause reads. A usage limit is the
        rollout's, and the runner waits for it. The file is found only now, so a file that the runner made after this
        feed was made counts. Nothing else of it is read: the rollout gives every other record."""
        if feed.closed:
            return
        path, last = screen_file(feed.session, self.home), None
        if not path:
            feed.closed = True
            return
        try:
            with open(path, "rb") as stream:
                for line in stream:
                    if not line.endswith(b"\n") or len(line) > MAX_LINE:
                        continue
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(row, dict) and row.get("method") == "turn/completed":
                        last = row
        except OSError:
            # Keep the feed open: scan/flush must retry the read before confirming its final records.
            raise
        feed.closed = True
        params = last.get("params") if last and isinstance(last.get("params"), dict) else {}
        turn = params.get("turn") if isinstance(params.get("turn"), dict) else {}
        if turn.get("status") != "failed":
            return
        error = Translator("codex_app").app_error(turn.get("error"))
        if not error["retryable"]:
            feed.pending.extend(feed.translator.number([error, {"type": "result", "stop_reason": "error"}],
                                                       when(last.get("timestamp"))))

    def send(self, feed):
        if feed.hub_seq is None:
            ok, last = self.deliver(feed, [])
            if not ok:
                return False
            feed.hub_seq = last
        feed.pending = [r for r in feed.pending if r["seq"] > feed.hub_seq]
        while feed.pending and not feed.dead:
            batch, size = [], 0
            for record in feed.pending[:BATCH]:
                n = len(json.dumps(record))
                if batch and size + n > BATCH_BYTES:
                    break
                batch.append(record)
                size += n
            ok, last = self.deliver(feed, batch)
            if not ok:
                return False
            feed.hub_seq = max(feed.hub_seq, last, batch[-1]["seq"])
            feed.pending = [r for r in feed.pending if r["seq"] > feed.hub_seq]
        return True

    def deliver(self, feed, batch):
        try:
            code, data = self.post({"generation": feed.generation, "task": feed.name, "attempt": feed.attempt,
                                    "session": feed.session, "events": batch})
        except Exception:
            return False, 0
        if code == 200:
            return True, int(data.get("last_seq") or 0)
        if code == 409:             # an old generation or attempt: these records have no place any more
            feed.dead, feed.pending = True, []
            return True, 0
        if 400 <= code < 500:       # a batch the hub will never take: skip it rather than stop the feed
            return True, batch[-1]["seq"] if batch else 0
        return False, 0

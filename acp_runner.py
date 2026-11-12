#!/usr/bin/env python3
"""One Fleet task run by an Agent Client Protocol (ACP) agent: Grok Build (`grok agent stdio`), OpenCode
(`opencode acp`), or another program that speaks ACP.

The helper starts this runner in the task's tmux window, as it starts screen_runner.py for a screen task. The
runner starts the agent and speaks ACP to it in JSON-RPC lines: initialize, authenticate with the method that the
start names, session/new with the task-bound fleet MCP server and the agent's own MCP servers, the session's model
and effort as options of the session, then one session/prompt per turn. Every session/update becomes a thread record
for the hub, in the shapes that the transcript readers send. A line typed into the window (the helper's inbox signal)
is the next prompt. With the policy `full` the runner allows each permission request itself, as a worker with full
access; with `ask` the request goes to the task's requester through the hub, as a Claude Code hook does. Ctrl-C
cancels the turn with session/cancel, ends the agent's process group and exits, so the window closes and the helper
can confirm the hold.

A prompt that fails ends its turn and not the runner: the failure is a thread record with its cause (a limit, no
credit, a refused call, no answer), the turn's result is `error`, and the runner waits for the next line. So the hub's
message after a limit is the next prompt of the same session. Only a start that fails before the first prompt ends
the runner with 1.

What one program does in its own way is in its adapter (acp_programs.py), and nothing here compares a runtime to a
name. The program gets none of the variables of its own names (lifecycle.RUNTIMES `own_env`) but the ones that the
fleet's start sets, and never the session's credential.
"""
import argparse
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time

import acp_programs

TOOL_KINDS = ("read", "edit", "delete", "move", "search", "execute", "think", "fetch", "other")
STATUSES = ("pending", "in_progress", "completed", "failed")
STOPS = {"end_turn": "end_turn", "cancelled": "cancelled", "max_tokens": "max_tokens",
         "max_turn_requests": "max_tokens", "refusal": "refusal"}
BATCH_BYTES = 60000             # the hub takes at most 64 KiB in one batch
MODEL_FIELDS = 5                # usage.MODEL_FIELDS: input, cache_read, cache_write, output, calls


class Failed(RuntimeError):
    """The agent answered a call with a JSON-RPC error: `error` is its own object."""

    def __init__(self, method, error):
        self.error = error if isinstance(error, dict) else {}
        super().__init__(f"{method}: {self.error.get('message', 'error')}")


class Ended(RuntimeError):
    """The agent's process ended before it answered."""


class Refused(RuntimeError):
    """A start that the runner refuses, in the words of its error record."""


def text_of(content):
    """The text of an ACP content block, or of a list of tool-call content items."""
    if isinstance(content, list):
        return "\n".join(t for t in (text_of(c) for c in content) if t)
    if not isinstance(content, dict):
        return ""
    if content.get("type") == "text":
        return str(content.get("text") or "")
    if content.get("type") == "content":
        return text_of(content.get("content"))
    if content.get("type") == "diff":
        return f"changed {content.get('path')}"
    return ""


class Records:
    """Thread records for the hub, numbered per session and sent in small batches; a failed batch is sent again.
    adapter: the program's own (acp_programs), which gives a tool call the fleet's name for it."""

    def __init__(self, post, adapter=None):
        self.post, self.adapter = post, adapter or acp_programs.Program()
        self.seq, self.pending, self.lock = 0, [], threading.Lock()
        self.kind, self.parts = None, []        # message chunks of one kind become one record
        self.dead = False                       # the hub refused this session's records for good (409)

    def add(self, record):
        with self.lock:
            self._flush_text()
            self._add(record)

    def _add(self, record):
        self.seq += 1
        self.pending.append(dict(record, seq=self.seq, ts=time.time()))

    def chunk(self, kind, text):
        with self.lock:
            if kind != self.kind:
                self._flush_text()
                self.kind = kind
            self.parts.append(text)

    def _flush_text(self):
        if self.parts:
            limit = 2000 if self.kind == "agent_thought" else 4000
            self._add({"type": self.kind, "text": "".join(self.parts)[:limit]})
        self.kind, self.parts = None, []

    def send(self):
        """The rule of threads.Tailer.deliver: a batch that the hub did not take goes again at the next send; a 409
        (an old generation or attempt) ends the sending, and a batch of another 4xx, which the hub will never take,
        is passed over, so that it holds back no later record."""
        with self.lock:
            self._flush_text()
            while self.pending and not self.dead:
                batch, size = [], 0
                for record in self.pending[:100]:
                    size += len(json.dumps(record))
                    if batch and size > BATCH_BYTES:
                        break
                    batch.append(record)
                try:
                    code, _ = self.post(batch)
                except Exception:
                    return False
                if code == 409:
                    self.dead = True
                elif code != 200 and not 400 <= code < 500:
                    return False
                del self.pending[:len(batch)]
            if self.dead:
                self.pending.clear()            # these records have no place any more
            return True

    def tool(self, update, record):
        """One tool call's record, and the records of the calls that the program made inside it (the adapter's)."""
        output = text_of(update.get("content"))
        record = dict(record, output=output[:800]) if output else record
        inner = self.adapter.tool(update, record)
        for one in inner:
            self.add(one)
        self.add(record)

    def update(self, update):
        """One session/update from the agent, in record shapes."""
        kind = update.get("sessionUpdate")
        if kind in ("agent_message_chunk", "agent_thought_chunk", "user_message_chunk"):
            text = text_of(update.get("content"))
            if text:
                self.chunk(kind[:-len("_chunk")], text)
        elif kind == "tool_call":
            self.tool(update, {"type": "tool_call", "tool_call_id": str(update.get("toolCallId") or "")[:100],
                               "title": str(update.get("title") or "tool")[:300],
                               "kind": update.get("kind") if update.get("kind") in TOOL_KINDS else "other",
                               "status": update.get("status") if update.get("status") in STATUSES else "pending"})
        elif kind == "tool_call_update":
            self.tool(update, {"type": "tool_call_update", "tool_call_id": str(update.get("toolCallId") or "")[:100],
                               "status": update.get("status") if update.get("status") in STATUSES else "in_progress"})
        elif kind == "plan":
            entries = [{"content": str(e.get("content") or "")[:300],
                        "status": e.get("status") if e.get("status") in ("pending", "in_progress", "completed") else "pending"}
                       for e in (update.get("entries") or [])[:50] if isinstance(e, dict)]
            self.add({"type": "plan", "entries": entries})


class Usage:
    """The usage file of one session, ~/.fleet/acp/<fleet session>.json (the AI providers spec, section 3.7): the
    tokens of its turns by model, which the usage collector reads (usage.acp_sessions). Numbers and model names only.
    It is written whole at each change, to a .part file and then by a rename, with mode 600. A session whose program
    gives no token kinds leaves no file, and its tokens stay unknown."""

    def __init__(self, path, session, kit, runtime):
        self.path, self.session, self.kit, self.runtime = path, session, kit, runtime
        self.models, self.first, self.context, self.model = {}, None, None, None
        self.since = self.last = None

    def add(self, spent, model=None, now=None):
        """One turn: what the adapter read from the prompt's answer (acp_programs.Program.usage). A row of a model is
        that model's own numbers, and a model that spent no token gets no row."""
        rows = {name: [max(0, int(v)) for v in row[:MODEL_FIELDS]] for name, row in (spent.get("models") or {}).items()
                if isinstance(name, str) and name and len(row) >= MODEL_FIELDS and any(row[:4])}
        if not rows:
            return
        now = time.time() if now is None else now
        self.since, self.last = self.since or now, now
        for name, row in rows.items():
            held = self.models.setdefault(name, [0] * MODEL_FIELDS)
            held[:] = [a + b for a, b in zip(held, row)]
        if self.first is None:
            self.first = [sum(column) for column in zip(*(row[:4] for row in rows.values()))]
        self.model = model or self.model or next(iter(rows))
        self.took(spent.get("context"))
        self.write()

    def took(self, context):
        """The newest reading of the context: how much of it is used, and its size."""
        if isinstance(context, dict) and all(isinstance(context.get(k), int) and not isinstance(context.get(k), bool)
                                             and context[k] >= 0 for k in ("used", "size")):
            self.context = {"used": context["used"], "size": context["size"]}

    def write(self):
        if not self.path or not self.models:
            return
        data = {"session_id": self.session, "kit": self.kit, "runtime": self.runtime, "since": self.since,
                "last": self.last, "model": self.model, "models": self.models, "first": self.first,
                "context": self.context}
        try:
            os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
            part = self.path + ".part"
            with open(os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(part, self.path)
        except OSError:
            pass                    # a failed write cannot change the task


class Client:
    """JSON-RPC over the agent's stdin and stdout, one message per line."""

    def __init__(self, argv, cwd, on_update, on_request, env=None, on_notice=None):
        self.proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, start_new_session=True)
        self.on_update, self.on_request, self.on_notice = on_update, on_request, on_notice
        self.next_id, self.waiting, self.lock = 0, {}, threading.Lock()
        threading.Thread(target=self.read, daemon=True, name="acp-read").start()

    def write(self, message):
        with self.lock:
            self.proc.stdin.write((json.dumps(message) + "\n").encode())
            self.proc.stdin.flush()

    def read(self):
        for line in self.proc.stdout:
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if not isinstance(message, dict):
                continue
            if "method" not in message and "id" in message:
                waiter = self.waiting.pop(message["id"], None)
                if waiter:
                    waiter.put(message)
            elif message.get("method") == "session/update":
                self.on_update((message.get("params") or {}).get("update") or {})
            elif "method" in message and "id" in message:
                threading.Thread(target=self.answer, args=(message,), daemon=True).start()
            elif "method" in message and self.on_notice:
                try:                # a notification of the program's own (the adapter reads it)
                    self.on_notice(message["method"], message.get("params") or {})
                except Exception:
                    pass
        for waiter in list(self.waiting.values()):
            waiter.put({"ended": True})

    def answer(self, message):
        try:
            self.write({"jsonrpc": "2.0", "id": message["id"],
                        "result": self.on_request(message["method"], message.get("params") or {})})
        except LookupError:
            self.write({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "not supported"}})
        except (OSError, ValueError):
            pass

    def call(self, method, params, timeout=None, stop=None):
        """The result of one request. Raises Failed with the agent's own error object, Ended when its process ended,
        and TimeoutError when the wait was given up."""
        with self.lock:
            self.next_id += 1
            ident = self.next_id
        waiter = queue.Queue()
        self.waiting[ident] = waiter
        self.write({"jsonrpc": "2.0", "id": ident, "method": method, "params": params})
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            try:
                message = waiter.get(timeout=0.5)
                break
            except queue.Empty:
                if deadline is not None and time.monotonic() > deadline:
                    raise TimeoutError(f"{method} got no answer")
                if stop is not None and stop():
                    raise TimeoutError(f"{method} was given up")
        if message.get("ended"):
            raise Ended(f"{method}: the agent ended")
        if "error" in message:
            raise Failed(method, message["error"])
        return message.get("result") or {}

    def notify(self, method, params):
        self.write({"jsonrpc": "2.0", "method": method, "params": params})

    def stop(self):
        try:
            os.killpg(self.proc.pid, signal.SIGTERM)
            self.proc.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired, PermissionError):
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                self.proc.wait(timeout=5)       # no process of this runner stays as a zombie
            except subprocess.TimeoutExpired:
                pass
        for pipe in (self.proc.stdin, self.proc.stdout):
            try:
                pipe.close()
            except OSError:
                pass


def option(options, category):
    """The option of one category in a session's configOptions, found by its category and never by its id: the ids
    are each program's own (`reasoning_effort` in one, `effort` in another)."""
    return next((o for o in options if isinstance(o, dict) and o.get("category") == category), None)


def values(one):
    return [x.get("value") for x in (one or {}).get("options") or [] if isinstance(x, dict)]


def options_of(answer):
    """The configOptions of an answer: of session/new, and of session/set_config_option, which gives the whole list
    again."""
    listed = answer.get("configOptions") if isinstance(answer, dict) else answer
    return listed if isinstance(listed, list) else []


class Runner:
    def __init__(self, argv, prompt, mcp_url, cwd, runtime, records, permission, lines, token=None, *, system=None,
                 model=None, effort=None, auth=None, stored=None, label=None, servers=(), usage=None, policy="ask",
                 adapter=None, env=None, session=None):
        """system: the session's stable text, which goes on the program's own road to its system message (the
        adapter's), else at the head of the first prompt. auth: the ACP sign-in method of this start, and stored: the
        method that the program names while it holds a sign-in of its own, where `auth` is the account's key.
        servers: the agent's own MCP servers, in the shapes of ACP. usage: the session's Usage, or None. policy:
        "full" allows each permission request here; "ask" asks the hub. env: the program's environment. session: the
        Fleet session's id, whose folder the adapter removes at the end."""
        self.argv, self.prompt, self.mcp_url, self.cwd, self.runtime = argv, prompt, mcp_url, cwd, runtime
        self.headers = [{"name": "Authorization", "value": f"Bearer {token}"}] if token else []     # owner API 1.12
        self.records, self.permission, self.lines = records, permission, lines
        self.system, self.model, self.effort, self.auth, self.stored = system, model, effort, auth, stored
        self.label = label or runtime
        self.servers, self.usage, self.policy = list(servers), usage, policy
        self.adapter = adapter or acp_programs.Program()
        self.env, self.session = env, session
        self.stopping = threading.Event()
        self.cancelled_at = None
        self.client = self.sid = None
        self.current = None             # the session's model now
        self.limited = False            # this turn ended at the program's own word for a limit

    def request(self, method, params):
        if method != "session/request_permission":
            raise LookupError(method)           # no file system or terminal is offered to the agent
        tool = params.get("toolCall") or {}
        if self.policy == "full":
            allowed = True                      # Fleet's worker form: no question, and no record of its own
        else:
            raw = tool.get("rawInput") if isinstance(tool.get("rawInput"), dict) else {"title": tool.get("title")}
            allowed = self.permission(str(tool.get("title") or tool.get("kind") or "tool")[:80], raw)
        wanted = ("allow_once",) if allowed else ("reject_once", "reject_always")
        chosen = next((o for o in params.get("options") or [] if isinstance(o, dict) and o.get("kind") in wanted), None)
        return {"outcome": {"outcome": "selected", "optionId": chosen["optionId"]}} if chosen else \
            {"outcome": {"outcome": "cancelled"}}

    def cancel(self, *_):
        """Ctrl-C: cancel the turn; run() then ends the agent and exits."""
        if not self.stopping.is_set():
            self.stopping.set()
            self.cancelled_at = time.monotonic()
            self.end_turn()

    def end_turn(self):
        if self.client and self.sid:
            try:
                self.client.notify("session/cancel", {"sessionId": self.sid})
            except (OSError, ValueError):
                pass

    def given_up(self):
        return self.stopping.is_set() and time.monotonic() - self.cancelled_at > 10

    def update(self, update):
        """One session/update: what the runner keeps of it, then its thread record."""
        kind = update.get("sessionUpdate")
        if kind == "usage_update" and self.usage:
            self.usage.took(update)             # the newest context: used and size
        elif kind == "config_option_update":
            chosen = option(options_of(update), "model")
            if chosen and isinstance(chosen.get("currentValue"), str):
                self.current = chosen["currentValue"]
        hit = None if self.limited else self.adapter.update(update, time.time())
        if hit:
            # The program's own word for a limit, while it still waits to try again: the record goes now, and the
            # turn ends here, because the program's own wait could hold it for hours.
            record, end = hit
            self.limited = True
            self.records.add(record)
            if end:
                self.end_turn()
            return
        self.records.update(update)

    def start(self, gone):
        """From initialize to a session with its model and effort. Raises Refused, Failed, Ended or TimeoutError."""
        init = self.client.call("initialize", {"protocolVersion": 1, "clientCapabilities": {
            "fs": {"readTextFile": False, "writeTextFile": False}, "terminal": False}}, stop=gone)
        capabilities = init.get("agentCapabilities") or {}
        if not (capabilities.get("mcpCapabilities") or {}).get("http"):
            raise Refused("the agent cannot reach the fleet tools over HTTP (mcpCapabilities.http)")
        self.adapter.model_options(init, None)      # the adapter keeps what it needs of the model list
        methods = [m.get("id") for m in init.get("authMethods") or [] if isinstance(m, dict)]
        if self.auth:
            if self.stored and self.stored != self.auth and self.stored in methods:
                # The last check: a stored sign-in would win over the key for some of the program's calls
                raise Refused(f"{self.label} holds a sign-in of its own on this server, which would win over the "
                              f"account's key.")
            if self.auth not in methods:
                raise Refused("the program offers no sign-in of the kind that this account needs")
            self.client.call("authenticate", {"methodId": self.auth}, stop=gone)
        params = {"cwd": self.cwd, "mcpServers": [
            {"type": "http", "name": "fleet", "url": self.mcp_url, "headers": self.headers}, *self.servers]}
        head = self.adapter.new_session(params, self.system, capabilities)
        new = self.client.call("session/new", params, stop=gone)
        self.sid = new["sessionId"]
        options = options_of(new)
        self.current = (option(options, "model") or {}).get("currentValue")
        effort = None
        if self.model:
            options = self.choose(options, "model", self.model, "model", gone)
            self.current = self.model
        if self.effort and option(options, "thought_level"):
            # the effort's option is read from the list that the model's call answered: a program can offer it only
            # while the current model has efforts. With no such option none is set, and the session goes on: the
            # owner's default effort must not stop a model that has none.
            self.choose(options, "thought_level", self.effort, "effort", gone)
            effort = self.effort
        return head, effort

    def choose(self, options, category, value, word, gone):
        chosen = option(options, category)
        if not chosen or not isinstance(chosen.get("id"), str):
            raise Refused(f"the program has no option for a {word}, so this session cannot run the {word} {value}")
        if value not in values(chosen):
            raise Refused(f"the program does not offer the {word} {value}")
        answer = self.client.call("session/set_config_option", {"sessionId": self.sid, "configId": chosen["id"],
                                                                "value": value}, stop=gone)
        return options_of(answer) or options

    def turn(self, text):
        """One prompt: its stop reason for the result record. A failed prompt is a record with its cause, and the
        turn's stop reason is then `error`."""
        self.limited = False
        try:
            result = self.client.call("session/prompt", {"sessionId": self.sid, "prompt": [
                {"type": "text", "text": text}]}, stop=self.given_up)
        except TimeoutError:
            return "cancelled"
        except Failed as e:
            if not self.limited:
                self.records.add(self.adapter.failure(e.error))
            return "error"
        spent = self.adapter.usage(result, self.current) if self.usage else None
        if spent:
            self.usage.add(spent, self.current)
        return "error" if self.limited else STOPS.get(result.get("stopReason"), "error")

    def run(self):
        folder = self.adapter.folder(self.session) if self.session else None
        if folder and not os.path.isdir(folder):
            # The helper makes the session's own folder new, with its files, before the window starts. Without it
            # the program would read what it stored in its own home, so it does not start.
            words = "the session's own folder is not there, so the program does not start"
            self.records.add({"type": "error", "code": "error", "message": words, "retryable": False})
            self.records.send()
            print(f"Fleet: {words}", flush=True)
            return 1
        self.client = Client(self.argv, self.cwd, self.update, self.request, env=self.env,
                             on_notice=self.adapter.notified)
        # plan C7: no clock on the start. The screen says that it waits, so the helper's screen watch sees a start
        # that hangs; a stop or the agent's own exit ends the wait.
        print("Fleet: waiting for the agent to start", flush=True)
        gone = lambda: self.stopping.is_set() or self.client.proc.poll() is not None
        try:
            try:
                head, effort = self.start(gone)
                self.records.add({"type": "session", "runtime": self.runtime, "session_id": str(self.sid)[:80]})
                if self.model or effort or self.current:
                    self.records.add({"type": "model", "requested_model": self.model, "requested_effort": self.effort,
                                      "model": self.current, "effort": effort})
                if not self.adapter.tools_ready(self.sid):
                    print("Fleet: waiting for the agent's tools", flush=True)
                    while not self.adapter.tools_ready(self.sid):       # an event of the program, never a time
                        if gone():
                            raise Ended("the agent ended before its tools were there")
                        time.sleep(0.1)
                text, shown = self.prompt if not head else head + "\n\n" + self.prompt, self.prompt
                if self.adapter.first_prompt_waits:
                    # The program gives no sign when its tools are there. The helper's first signal comes when the hub
                    # saw the session list the fleet's tools: that line is the event, and the task's prompt goes then.
                    self.records.send()
                    print("Fleet: waiting for the helper's signal that the agent's tools are there", flush=True)
                    if self.next_line() is None:
                        text = None
                    elif self.adapter.settle:
                        self.stopping.wait(self.adapter.settle)     # the program's own last step has no sign
            except (Refused, Failed, Ended, TimeoutError, KeyError, OSError, ValueError) as e:
                words = str(e)
                if isinstance(e, Failed):       # a refused value of a start: the program's own words
                    words = f"{e}: {acp_programs.words_of(e.error)}" if e.error.get("data") else words
                self.records.add({"type": "error", "code": "error", "message": words[:500], "retryable": False})
                print(f"Fleet: {words}", flush=True)
                return 1
            while text is not None and not self.stopping.is_set():
                self.records.add({"type": "user_message", "text": shown[:4000]})
                self.records.send()
                print("Fleet: the agent is working. Ctrl-C stops it.", flush=True)
                try:
                    stop = self.turn(text)
                except (Ended, OSError, ValueError) as e:       # the agent's process is gone: nothing takes a prompt
                    self.records.add({"type": "error", "code": "error", "message": str(e)[:500], "retryable": False})
                    self.records.add({"type": "result", "stop_reason": "error"})
                    print(f"Fleet: {e}", flush=True)
                    return 1
                self.records.add({"type": "result", "stop_reason": stop})
                self.records.send()
                print(f"Fleet: turn ended ({stop}). Waiting for the next message.", flush=True)
                text = shown = self.next_line()
            return 0
        finally:
            self.client.stop()
            self.records.send()
            if self.session:
                self.adapter.remove(self.session)       # the session's own folder goes with its window

    def next_line(self):
        """The next prompt: the next typed line, and every line already queued behind it, as one prompt (plan C5).
        Lines that waited while a turn ran each asked for a read, so one turn reads them all."""
        while not self.stopping.is_set():
            try:
                line = self.lines.get(timeout=0.5)
            except queue.Empty:
                continue
            if line is None:
                return None
            if not line.strip():
                continue
            merged = [line.strip()]
            while True:
                try:
                    more = self.lines.get_nowait()
                except queue.Empty:
                    break
                if more is None:
                    self.lines.put(None)        # the end comes after this prompt
                    break
                if more.strip() and more.strip() not in merged:
                    merged.append(more.strip())
            return "\n".join(merged)
        return None


def program_env(environ, prefixes, own, keep=()):
    """The environment that the program starts with: this process's own, without the session's credential and without
    each variable whose name starts with one of the program's own prefixes (lifecycle.RUNTIMES `own_env`), but the
    names of `keep`; then `own`, the variables that the fleet's start sets. So a setting of the program that stands
    in the window's or the service's environment does not reach it."""
    prefixes = tuple(prefixes or ())
    env = {name: value for name, value in environ.items()
           if name in keep or not (prefixes and name.startswith(prefixes))}
    env.pop("FLEET_SESSION_TOKEN", None)
    env.update(own)
    return env


def started_env(runtime, adapter, session, auth, environ=None):
    """program_env for one start of a runtime of the table: what the fleet's own start sets is the table's acp_quiet
    and memory_off, and the adapter's variables of the session's folder. The key's variable stays only for a start
    whose sign-in is the key's: one that names the key's method, or a program with no sign-in method at all."""
    import lifecycle
    fact = lambda name: lifecycle.runtime_fact(runtime, name)
    own = dict(fact("acp_quiet") or {}, **((fact("memory_off") or {}).get("env") or {}))
    own.update(adapter.session_env(session) if session else {})
    methods = fact("acp_auth")
    by_key = methods is None or (auth is not None and auth == methods.get("key"))
    return program_env(os.environ if environ is None else environ, fact("own_env"), own,
                       keep=(fact("key_env"),) if by_key and fact("key_env") else ())


def read_models(argv, cwd, env, adapter, how, auth=None, timeout=60):
    """(options, error): the model options of an ACP program, read with no prompt, from where the table's acp_models
    says: "initialize", the answer of that call, or "session", the options of a new session, which is closed again
    where the program offers that. Each option is (model, efforts, default effort, is the current model)."""
    def nothing(method, params):
        raise LookupError(method)       # a reading offers the program nothing and answers no question
    try:
        client = Client(argv, cwd, lambda update: None, nothing, env=env, on_notice=adapter.notified)
    except OSError as e:
        return None, f"the program did not start: {type(e).__name__}"
    try:
        init = client.call("initialize", {"protocolVersion": 1, "clientCapabilities": {
            "fs": {"readTextFile": False, "writeTextFile": False}, "terminal": False}}, timeout=timeout)
        if how == "initialize":
            return adapter.model_options(init, None), None
        methods = [m.get("id") for m in init.get("authMethods") or [] if isinstance(m, dict)]
        if auth and auth in methods:
            client.call("authenticate", {"methodId": auth}, timeout=timeout)
        new = client.call("session/new", {"cwd": cwd, "mcpServers": []}, timeout=timeout)
        listed = adapter.model_options(None, new)
        if "close" in ((init.get("agentCapabilities") or {}).get("sessionCapabilities") or {}):
            try:
                client.call("session/close", {"sessionId": new.get("sessionId")}, timeout=10)
            except (Failed, Ended, TimeoutError):
                pass
        return listed, None
    except Failed as e:
        return None, f"the program refused the reading: {str(acp_programs.words_of(e.error))[:200]}"
    except (Ended, TimeoutError, OSError, ValueError, KeyError, AttributeError, TypeError) as e:
        return None, f"the program gave no model list: {type(e).__name__}"
    finally:
        client.stop()


def stdin_lines():
    lines = queue.Queue()

    def read():
        for line in sys.stdin:
            lines.put(line)
        lines.put(None)
    threading.Thread(target=read, daemon=True, name="typed-lines").start()
    return lines


def taken(path):
    """The text of one of the session's mode-600 files, which is removed once it is read: a prompt, the system text,
    the MCP servers with their credentials."""
    if not path:
        return None
    with open(path, encoding="utf-8") as f:
        text = f.read()
    try:
        os.remove(path)
    except OSError:
        pass
    return text


def main(argv=None):
    import fleet
    import lifecycle
    import shlex
    ap = argparse.ArgumentParser(description="Run one Fleet task with an ACP agent")
    ap.add_argument("--agent-command", required=True, help='for example "grok agent stdio"')
    ap.add_argument("--runtime", required=True)
    ap.add_argument("--mcp-url", required=True)
    ap.add_argument("--session", required=True, help="the Fleet session UUID of this task attempt")
    ap.add_argument("--prompt-file", required=True, help="the first prompt: a window command carries 16 KiB at most")
    ap.add_argument("--system-file", help="the session's stable text")
    ap.add_argument("--model")
    ap.add_argument("--effort")
    ap.add_argument("--auth", help="the ACP sign-in method of this start")
    ap.add_argument("--mcp-file", help='{"servers": [...]}: the agent\'s own MCP servers, in the shapes of ACP')
    ap.add_argument("--usage-file", help="where the session's tokens are kept for the usage collector")
    ap.add_argument("--policy", choices=("full", "ask"), default="ask")
    args = ap.parse_args(argv)
    agent, task = os.environ["FLEET_AGENT"], os.environ["FLEET_TASK"]
    fleet.AGENT = agent                 # its hub calls send the agent key (owner API 1.12)
    token = os.environ.pop("FLEET_SESSION_TOKEN", None)     # only in the MCP headers; the agent's process never sees it
    attempt, generation = int(os.environ["FLEET_ATTEMPT"]), os.environ["FLEET_GENERATION"]
    adapter = acp_programs.adapter(lifecycle.runtime_fact(args.runtime, "acp_adapter"))
    records = Records(lambda batch: fleet.http("POST", f"/helper/events/{agent}", {
        "task": task, "attempt": attempt, "generation": generation, "session": args.session, "events": batch},
        timeout=15), adapter)

    def permission(tool, tool_input):
        # plan C7: asked again until a decision, a hold or the end of the task, with no limit of its own
        data = fleet.ask_permission(f"/hook/permission/{agent}/{task}", {
            "attempt": attempt, "generation": generation, "tool_name": tool, "tool_input": tool_input},
            stopped=lambda: runner.stopping.is_set())
        decision = ((data or {}).get("hookSpecificOutput") or {}).get("decision") or {}
        return decision.get("behavior") == "allow"

    prompt, system = taken(args.prompt_file), taken(args.system_file)
    servers = (json.loads(taken(args.mcp_file)).get("servers") or []) if args.mcp_file else []
    usage = Usage(args.usage_file, args.session, os.path.realpath(fleet.KIT), args.runtime) if args.usage_file else None
    methods = lifecycle.runtime_fact(args.runtime, "acp_auth") or {}
    runner = Runner(shlex.split(args.agent_command), prompt, args.mcp_url, fleet.KIT, args.runtime, records,
                    permission, stdin_lines(), token=token, system=system, model=args.model, effort=args.effort,
                    auth=args.auth, stored=methods.get("plan"),
                    label=lifecycle.runtime_fact(args.runtime, "label", args.runtime), servers=servers, usage=usage,
                    policy=args.policy, adapter=adapter, session=args.session,
                    env=started_env(args.runtime, adapter, args.session, args.auth))
    for one in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):      # a window that is closed ends as Ctrl-C does
        signal.signal(one, runner.cancel)
    return runner.run()


if __name__ == "__main__":
    sys.exit(main())

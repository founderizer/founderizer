#!/usr/bin/env python3
"""One Fleet task run by an Agent Client Protocol (ACP) agent, for example Grok Build (`grok agent stdio`).

The helper starts this runner in the task's tmux window, as it starts screen_runner.py for a screen task. The
runner starts the agent and speaks ACP to it in JSON-RPC lines: initialize, authenticate with the agent's own
cached sign-in (never a key), session/new with the task-bound fleet MCP server, then one session/prompt per turn.
Every session/update becomes a thread record for the hub, in the shapes that the transcript readers send. A line
typed into the window (the helper's inbox signal) is the next prompt. A permission request goes to the task's
requester through the hub, as a Claude Code hook does. Ctrl-C cancels the turn with session/cancel, ends the
agent's process group and exits, so the window closes and the helper can confirm the hold.
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

TOOL_KINDS = ("read", "edit", "delete", "move", "search", "execute", "think", "fetch", "other")
STATUSES = ("pending", "in_progress", "completed", "failed")
STOPS = {"end_turn": "end_turn", "cancelled": "cancelled", "max_tokens": "max_tokens",
         "max_turn_requests": "max_tokens", "refusal": "refusal"}
BATCH_BYTES = 60000             # the hub takes at most 64 KiB in one batch


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
    """Thread records for the hub, numbered per session and sent in small batches; a failed batch is sent again."""

    def __init__(self, post):
        self.post = post
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

    def update(self, update):
        """One session/update from the agent, in record shapes."""
        kind = update.get("sessionUpdate")
        if kind in ("agent_message_chunk", "agent_thought_chunk", "user_message_chunk"):
            text = text_of(update.get("content"))
            if text:
                self.chunk(kind[:-len("_chunk")], text)
        elif kind == "tool_call":
            record = {"type": "tool_call", "tool_call_id": str(update.get("toolCallId") or "")[:100],
                      "title": str(update.get("title") or "tool")[:300],
                      "kind": update.get("kind") if update.get("kind") in TOOL_KINDS else "other",
                      "status": update.get("status") if update.get("status") in STATUSES else "pending"}
            output = text_of(update.get("content"))
            self.add(dict(record, output=output[:800]) if output else record)
        elif kind == "tool_call_update":
            record = {"type": "tool_call_update", "tool_call_id": str(update.get("toolCallId") or "")[:100],
                      "status": update.get("status") if update.get("status") in STATUSES else "in_progress"}
            output = text_of(update.get("content"))
            self.add(dict(record, output=output[:800]) if output else record)
        elif kind == "plan":
            entries = [{"content": str(e.get("content") or "")[:300],
                        "status": e.get("status") if e.get("status") in ("pending", "in_progress", "completed") else "pending"}
                       for e in (update.get("entries") or [])[:50] if isinstance(e, dict)]
            self.add({"type": "plan", "entries": entries})


class Client:
    """JSON-RPC over the agent's stdin and stdout, one message per line."""

    def __init__(self, argv, cwd, on_update, on_request):
        self.proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, start_new_session=True)
        self.on_update, self.on_request = on_update, on_request
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
        for waiter in list(self.waiting.values()):
            waiter.put({"error": {"message": "the agent ended"}})

    def answer(self, message):
        try:
            self.write({"jsonrpc": "2.0", "id": message["id"],
                        "result": self.on_request(message["method"], message.get("params") or {})})
        except LookupError:
            self.write({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "not supported"}})
        except (OSError, ValueError):
            pass

    def call(self, method, params, timeout=None, stop=None):
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
        if "error" in message:
            raise RuntimeError(f"{method}: {(message['error'] or {}).get('message', 'error')}")
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


class Runner:
    def __init__(self, argv, prompt, mcp_url, cwd, runtime, records, permission, lines, token=None):
        self.argv, self.prompt, self.mcp_url, self.cwd, self.runtime = argv, prompt, mcp_url, cwd, runtime
        self.headers = [{"name": "Authorization", "value": f"Bearer {token}"}] if token else []     # owner API 1.12
        self.records, self.permission, self.lines = records, permission, lines
        self.stopping = threading.Event()
        self.cancelled_at = None
        self.client = self.sid = None

    def request(self, method, params):
        if method != "session/request_permission":
            raise LookupError(method)           # no file system or terminal is offered to the agent
        tool = params.get("toolCall") or {}
        raw = tool.get("rawInput") if isinstance(tool.get("rawInput"), dict) else {"title": tool.get("title")}
        allowed = self.permission(str(tool.get("title") or tool.get("kind") or "tool")[:80], raw)
        wanted = ("allow_once",) if allowed else ("reject_once", "reject_always")
        option = next((o for o in params.get("options") or [] if isinstance(o, dict) and o.get("kind") in wanted), None)
        return {"outcome": {"outcome": "selected", "optionId": option["optionId"]}} if option else \
            {"outcome": {"outcome": "cancelled"}}

    def cancel(self, *_):
        """Ctrl-C: cancel the turn; run() then ends the agent and exits."""
        if not self.stopping.is_set():
            self.stopping.set()
            self.cancelled_at = time.monotonic()
            if self.client and self.sid:
                try:
                    self.client.notify("session/cancel", {"sessionId": self.sid})
                except (OSError, ValueError):
                    pass

    def given_up(self):
        return self.stopping.is_set() and time.monotonic() - self.cancelled_at > 10

    def run(self):
        self.client = Client(self.argv, self.cwd, self.records.update, self.request)
        # plan C7: no clock on the start. The screen says that it waits, so the helper's screen watch sees a start
        # that hangs; a stop or the agent's own exit ends the wait.
        print("Fleet: waiting for the agent to start", flush=True)
        gone = lambda: self.stopping.is_set() or self.client.proc.poll() is not None
        try:
            init = self.client.call("initialize", {"protocolVersion": 1, "clientCapabilities": {
                "fs": {"readTextFile": False, "writeTextFile": False}, "terminal": False}}, stop=gone)
            if not ((init.get("agentCapabilities") or {}).get("mcpCapabilities") or {}).get("http"):
                raise RuntimeError("the agent cannot reach the fleet tools over HTTP (mcpCapabilities.http)")
            if "cached_token" in [m.get("id") for m in init.get("authMethods") or [] if isinstance(m, dict)]:
                self.client.call("authenticate", {"methodId": "cached_token", "_meta": {"headless": True}}, stop=gone)
            self.sid = self.client.call("session/new", {"cwd": self.cwd, "mcpServers": [
                {"type": "http", "name": "fleet", "url": self.mcp_url, "headers": self.headers}]}, stop=gone)["sessionId"]
            self.records.add({"type": "session", "runtime": self.runtime, "session_id": str(self.sid)[:80]})
            text = self.prompt
            while text is not None and not self.stopping.is_set():
                self.records.add({"type": "user_message", "text": text[:4000]})
                self.records.send()
                print("Fleet: the agent is working. Ctrl-C stops it.", flush=True)
                try:
                    result = self.client.call("session/prompt", {"sessionId": self.sid, "prompt": [
                        {"type": "text", "text": text}]}, stop=self.given_up)
                    stop = STOPS.get(result.get("stopReason"), "error")
                except TimeoutError:
                    stop = "cancelled"
                self.records.add({"type": "result", "stop_reason": stop})
                self.records.send()
                print(f"Fleet: turn ended ({stop}). Waiting for the next message.", flush=True)
                text = self.next_line()
            return 0
        except (RuntimeError, TimeoutError, KeyError, OSError, ValueError) as e:
            self.records.add({"type": "error", "code": "error", "message": str(e)[:500], "retryable": False})
            print(f"Fleet: {e}", flush=True)
            return 1
        finally:
            self.client.stop()
            self.records.send()

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


def stdin_lines():
    lines = queue.Queue()

    def read():
        for line in sys.stdin:
            lines.put(line)
        lines.put(None)
    threading.Thread(target=read, daemon=True, name="typed-lines").start()
    return lines


def main(argv=None):
    import fleet
    import shlex
    ap = argparse.ArgumentParser(description="Run one Fleet task with an ACP agent")
    ap.add_argument("--agent-command", required=True, help='for example "grok agent stdio"')
    ap.add_argument("--runtime", required=True)
    ap.add_argument("--mcp-url", required=True)
    ap.add_argument("--session", required=True, help="the Fleet session UUID of this task attempt")
    ap.add_argument("--prompt", required=True)
    args = ap.parse_args(argv)
    agent, task = os.environ["FLEET_AGENT"], os.environ["FLEET_TASK"]
    fleet.AGENT = agent                 # its hub calls send the agent key (owner API 1.12)
    token = os.environ.pop("FLEET_SESSION_TOKEN", None)     # only in the MCP headers; the agent's process never sees it
    attempt, generation = int(os.environ["FLEET_ATTEMPT"]), os.environ["FLEET_GENERATION"]
    records = Records(lambda batch: fleet.http("POST", f"/helper/events/{agent}", {
        "task": task, "attempt": attempt, "generation": generation, "session": args.session, "events": batch}, timeout=15))

    def permission(tool, tool_input):
        # plan C7: asked again until a decision, a hold or the end of the task, with no limit of its own
        data = fleet.ask_permission(f"/hook/permission/{agent}/{task}", {
            "attempt": attempt, "generation": generation, "tool_name": tool, "tool_input": tool_input},
            stopped=lambda: runner.stopping.is_set())
        decision = ((data or {}).get("hookSpecificOutput") or {}).get("decision") or {}
        return decision.get("behavior") == "allow"

    runner = Runner(shlex.split(args.agent_command), args.prompt, args.mcp_url, fleet.KIT, args.runtime, records,
                    permission, stdin_lines(), token=token)
    signal.signal(signal.SIGINT, runner.cancel)
    signal.signal(signal.SIGTERM, runner.cancel)
    return runner.run()


if __name__ == "__main__":
    sys.exit(main())

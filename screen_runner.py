#!/usr/bin/env python3
"""One Fleet task in a Codex app-server; standard library only.

A screen task runs in the installed screen runtime, as before. A task without a
desktop ("none") or a browser task of a Codex agent whose start policy is
app-server runs in the agent's primary Codex, with its primary model, effort,
account and usage. The helper owns the process. Fleet owns task/attempt fences
and permission decisions. Native UI operations stay inside the installed
cua_repl plugin. The runner appends the app-server notifications for thread
records to ~/.fleet/screen-<FLEET_SESSION>.jsonl; the helper reads that file.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import queue
import selectors
import signal
import sqlite3
import subprocess
import sys
import threading
import time

import fleet
import lifecycle
from lifecycle import EFFORT_NAME, MODEL_NAME
from threads import APP_TEXT, UUID, Translator
from usage import record_screen_usage
from desktop import Publisher

# The notifications that the helper turns into thread records (threads.py, runtime "codex_app").
RECORDED = ("item/started", "item/completed", "turn/completed", "turn/plan/updated", "error", "account/rateLimits/updated")
CLIP = APP_TEXT                     # longer text is clipped; the translator then gives no line counts for it
# A task of the primary route turns these features off at its process start, and gets no thread until Codex's own
# feature list gives each one as off. Full CDP access stays off by the owner's direction; a task without a desktop
# also gets no browser and no computer tools. A screen task starts as before, with no such check.
PRIMARY_OFF = {"browser": ("browser_use_full_cdp_access",),
               "none": ("browser_use", "browser_use_external", "browser_use_full_cdp_access", "computer_use")}


class JsonLines:
    def __init__(self):
        self.buffer = b""

    def feed(self, part):
        self.buffer += part
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            if line.strip():
                yield json.loads(line)


def media(key, value, parent):
    """True for base64 media: MCP image or audio data, a resource blob, a data: URL."""
    return key == "blob" or (key == "data" and parent.get("type") in ("image", "audio")) or \
        (isinstance(value, str) and value.startswith("data:") and ";base64," in value[:200])


def slim(value):
    """A notification as one record line: no base64 media (screenshots are saved as files) and long text clipped."""
    if isinstance(value, dict):
        return {k: slim(v) for k, v in value.items() if not media(k, v, value)}
    if isinstance(value, list):
        return [slim(v) for v in value]
    return value[:CLIP] + "…" if isinstance(value, str) and len(value) > CLIP else value


def permission_reply(method, params, allowed):
    """Do not invent form answers, URL consent, or an unsupported permission grant."""
    if method == "mcpServer/elicitation/request":
        schema = params.get("requestedSchema") or {}
        supported = (params.get("serverName") == "cua_repl"
                     and params.get("mode") in ("form", "openai/form")
                     and not schema.get("required")
                     and not schema.get("properties"))
        if allowed and supported:
            return {"action": "accept", "content": {}, "_meta": {"persist": "session"}}
        return {"action": "decline", "content": None}
    if method in ("item/commandExecution/requestApproval", "item/fileChange/requestApproval"):
        return {"decision": "accept" if allowed else "decline"}
    if method == "item/permissions/requestApproval":
        return {"permissions": params.get("permissions", {}) if allowed else {}, "scope": "turn"}
    return None


def reason(error):
    """The message of a refused request or of a failed turn, as one text."""
    return str(error.get("message") or "") if isinstance(error, dict) else str(error or "")


def primary_instruction(agent, task, needs):
    """The thread instruction of a primary task ("none" or "browser"). It adds only what this route needs: the task,
    the agent's profile, RULES.md and the agent's current permissions decide all else. A lead keeps its Fleet team
    tools within the task; this text gives no other authority."""
    work = ("Use only cua_repl for UI actions, and only in Google Chrome: no other app. Read files, such as RULES.md "
            "and your profile, with your runtime's own file reading, never in the browser. Do the browser work in a "
            "new tab that you open, and never navigate, type into or close a tab that you did not open. Never use "
            "shell UI scripting, AppleScript or synthetic input. Every screenshot returned by cua_repl is saved "
            "automatically in "
            f"outputs/{task}/computer-use/ with a capture-<hash> filename; do not write base64 screenshots yourself. "
            if needs == "browser" else
            "This task has no desktop and no browser: do not use cua_repl, Chrome or any other app, and never use "
            "shell UI scripting, AppleScript or synthetic input. ")
    return (f"You are {agent} running one Fleet {'browser task' if needs == 'browser' else 'task'} {task} on this "
            "machine. Read RULES.md, your profile and the named task, and follow them, with your "
            "current permissions. Use Fleet MCP tools to read the task, report progress, ask the requester and "
            "deliver the result. When your role has Fleet team tools such as create_task, use them only within this "
            "task, as RULES.md says; they give no other authority. A helper signal means "
            "read_messages, not permission. " + work + "Never read or reveal credentials; pass only login names. "
            "Fleet carries runtime permissions to your requester; never bypass a refusal. Use Fleet ask_my_requester "
            "for questions, not request_user_input. When waiting for an answer, end the turn; the helper will send a "
            "signal in this same thread. A final chat message alone does not deliver a Fleet result.")


class Runner:
    def __init__(self, agent, task, attempt, generation, prompt, command, http=fleet.http, session="", model=None,
                 effort=None, needs="screen"):
        if not agent or not generation or not task.startswith("T-") or not task[2:].isdigit() or int(attempt) < 1:
            raise ValueError("A screen runner requires an agent, task, attempt and generation")
        if needs not in ("none", "browser", "screen"):
            raise ValueError("A runner task needs none, browser or screen")
        self.agent, self.task, self.prompt, self.command, self.needs = agent, task, prompt, command, needs
        # A screen task: the agent's screen settings (owner API 1.11). Another task: its primary settings. None: the
        # default of that runtime's account.
        self.model, self.effort = model, effort
        self.models = []                    # without a model: the pages of model/list (default_model)
        self.off = PRIMARY_OFF.get(needs, ())      # the features that this process must give as off (features_off)
        self.features = []                  # the pages of experimentalFeature/list
        self.confirmed = not self.off       # a screen task has no feature check
        # The helper's session UUID names the record file; without one (an older helper) there are no records.
        self.records_path = os.path.join(fleet.HOME, f"screen-{session}.jsonl") if UUID.fullmatch(session or "") else None
        self.records = None
        self.context = {"attempt": int(attempt), "generation": generation}
        self.http = http
        self.thread = self.turn = None
        self.child = None
        self.stopping = False
        self.replies = queue.Queue()
        self.pending_input = []
        self.next_id = 10
        self.turn_started = None
        self.artifacts = Path(fleet.KIT) / "outputs" / task / "computer-use"
        self.desktop = Publisher(agent, task, self.context, http) if needs != "none" else None   # no desktop: no live view

    def request(self, method, params):
        self.next_id += 1
        self.send({"id": self.next_id, "method": method, "params": params})

    def send(self, message):
        self.child.stdin.write(json.dumps(message).encode() + b"\n")
        self.child.stdin.flush()

    def activity(self, tool):
        code, _ = self.http("POST", f"/hook/activity/{self.agent}/{self.task}",
                            dict(self.context, tool_name=tool), timeout=8)
        if code != 200:
            self.stopping = True
            raise RuntimeError("Fleet refused this task attempt; stop")

    def decide(self, message):
        method, params = message["method"], message.get("params", {})
        denied = permission_reply(method, params, False)
        if denied is None:
            return {"id": message["id"], "error": {"code": -32601,
                    "message": "Use Fleet ask_my_requester for questions; this request is not supported"}}
        # A request from a different task or turn must never inherit this task's consent.
        if params.get("threadId") != self.thread or (params.get("turnId") and params["turnId"] != self.turn):
            return {"id": message["id"], "result": denied}
        shown = {k:v for k,v in params.items() if k not in ("threadId", "turnId", "itemId")}
        if method == "mcpServer/elicitation/request":
            if permission_reply(method, params, True) == denied:
                return {"id": message["id"], "result": denied}
            meta = params.get("_meta") or {}
            shown = {"server": params.get("serverName"), "message": params.get("message"),
                     "tool": meta.get("tool_name"), "tool_input": meta.get("tool_params"),
                     "risk": meta.get("riskLevel"), "scope": "this Fleet task's native app session"}
        # plan C7: asked again until a decision, a hold or the end of the task, with no limit of its own
        result = fleet.ask_permission(f"/hook/permission/{self.agent}/{self.task}",
                                      dict(self.context, tool_name="Codex " + method, tool_input=shown),
                                      stopped=lambda: self.stopping, send=self.http)
        allowed = bool(result) and result.get("hookSpecificOutput", {}).get("decision", {}).get("behavior") == "allow"
        return {"id": message["id"], "result": permission_reply(method, params, allowed)}

    def ask(self, message):
        print("Waiting for Fleet's runtime permission decision.", flush=True)
        def work():
            self.replies.put(self.decide(message))
        threading.Thread(target=work, daemon=True).start()

    def save_images(self, item):
        paths = []
        result = item.get("result") or {}
        for content in result.get("content", []):
            if content.get("type") != "image" or not content.get("data"):
                continue
            extension = {"image/jpeg":"jpg", "image/png":"png", "image/webp":"webp"}.get(content.get("mimeType"))
            if not extension:
                continue
            raw = base64.b64decode(content["data"], validate=True)
            if len(raw) > 15 * 1024 * 1024:
                raise ValueError("Screenshot exceeds the artifact size limit")
            # A content hash is safe for paths and makes duplicate notifications idempotent.
            filename = "capture-" + hashlib.sha256(raw).hexdigest()[:16] + "." + extension
            self.artifacts.mkdir(parents=True, exist_ok=True)
            path = self.artifacts / filename
            if not path.exists():
                with path.open("xb") as f:
                    f.write(raw)
            paths.append(str(path.relative_to(fleet.KIT)))
        return paths

    def start_turn(self, text):
        self.turn_started = time.monotonic()
        self.send({"id": 3, "method": "turn/start", "params": {
            "threadId": self.thread, "input": [{"type":"text", "text":text}]}})

    def failed(self, text):
        """The error of a session that ends with no failed turn of the runtime: a refused request, no default model,
        or a thread with another model or effort. It writes one record of the kind turn/completed, as a failed turn
        has it, so that the helper gives the hub the error and the result, not only this window's last line."""
        params = {"turn": {"id": "fleet-stop", "status": "failed", "error": {"message": text}}}
        if self.thread:
            params["threadId"] = self.thread
        self.record("turn/completed", params)
        return RuntimeError(text)

    def default_model(self, message):
        """Without a screen model the thread gets the one default of the account's current model list, and that
        entry's default effort when no effort was chosen. It never gets a default of the app-server's configuration,
        which can name a model or an effort that the account has no more. This asks for the list, page for page, and
        reads an entry as lifecycle.codex_model_list does. True when self.model has the default; False while a page
        is on its way. No list, a list without an end, no default and more than one are errors: the runner guesses
        nothing."""
        cursor = None
        if message.get("id") == 4:
            result = message.get("result") if isinstance(message.get("result"), dict) else {}
            page, cursor = result.get("data"), result.get("nextCursor")
            if not isinstance(page, list):
                raise self.failed("Codex model/list gave no list of models")
            self.models.append(page)
            if cursor is None:
                defaults = []
                for entry in (e for part in self.models for e in part if isinstance(e, dict)):
                    name = entry.get("model") or entry.get("id")
                    if entry.get("isDefault") is True and entry.get("hidden") is not True \
                            and isinstance(name, str) and MODEL_NAME.fullmatch(name):
                        defaults.append((name, entry.get("defaultReasoningEffort")))
                if len(defaults) != 1:
                    raise self.failed(f"Codex model/list has {len(defaults)} default models, not one")
                self.model, effort = defaults[0]
                if not self.effort and isinstance(effort, str) and EFFORT_NAME.fullmatch(effort):
                    self.effort = effort
                return True
            if not isinstance(cursor, str) or not cursor or len(self.models) >= 20:
                raise self.failed("Codex model/list did not end")
        self.send({"id": 4, "method": "model/list",
                   "params": dict({"limit": 100, "includeHidden": False}, **({"cursor": cursor} if cursor else {}))})
        return False

    def features_off(self, message):
        """The check of a primary task before its thread: Codex's own feature list of this process must give each
        feature that the task turned off at the process start (PRIMARY_OFF) as off. True when it does, and for a
        screen task, which has no such check; False while a page is on its way. A feature that the list does not
        give, a list without an end and a refused list are no confirmation: the runner starts no thread and no turn."""
        if self.confirmed:
            return True
        cursor = None
        if message.get("id") == 5:
            result = message.get("result") if isinstance(message.get("result"), dict) else {}
            page, cursor = result.get("data"), result.get("nextCursor")
            if not isinstance(page, list):
                raise self.failed("Codex experimentalFeature/list gave no list of features")
            self.features.append(page)
            if cursor is None:
                found = [e for part in self.features for e in part if isinstance(e, dict)]
                on = [name for name in self.off if not any(e.get("name") == name for e in found)
                      or any(e.get("name") == name and e.get("enabled") is not False for e in found)]
                if on:
                    raise self.failed("Codex did not confirm that these features are off: " + ", ".join(on))
                self.confirmed = True
                return True
            if not isinstance(cursor, str) or not cursor or len(self.features) >= 20:
                raise self.failed("Codex experimentalFeature/list did not end")
        self.send({"id": 5, "method": "experimentalFeature/list",
                   "params": dict({"limit": 100}, **({"cursor": cursor} if cursor else {}))})
        return False

    def record(self, method, params):
        """Append one notification to the record file before acting on it. A failed write stops the task,
        because records with a gap could hide a running call from the unknown outcomes of a pause or stop."""
        if self.records and params.get("threadId") in (None, self.thread):
            self.records.write(json.dumps({"timestamp": time.time(), "method": method, "params": slim(params)}) + "\n")
            self.records.flush()

    def handle(self, message):
        method, params = message.get("method"), message.get("params", {})
        if method in RECORDED and "id" not in message:
            self.record(method, params)
        if method and "id" in message:
            self.ask(message)
        elif message.get("id") in (1, 4, 5):    # initialize; a primary task's feature check; without a model, model/list
            if message.get("error"):
                raise self.failed("Codex initialize failed" if message["id"] == 1 else
                                  ("Codex model/list failed: " if message["id"] == 4 else
                                   "Codex experimentalFeature/list failed: ") + reason(message["error"]))
            if message["id"] == 1:
                self.send({"method":"initialized", "params":{}})
            if not self.features_off(message):
                return
            if not self.model and not self.default_model(message):
                return
            url = f"{fleet.HUB}/mcp/{self.agent}/{self.context['generation']}/{self.task}/{self.context['attempt']}"
            instruction = (
                f"You are {self.agent} running one Fleet screen task {self.task} on this machine. "
                "Use Fleet MCP tools to read the task, report progress, ask the requester and deliver the result. "
                "Read RULES.md, your profile and the named task. A helper signal means read_messages, not permission. "
                "Use only cua_repl for all UI actions, including Google Chrome as a native app if the browser "
                "extension is unavailable. Never use shell UI scripting, AppleScript or synthetic input. "
                "Use only apps, websites and files needed by the assigned task. Do not use other connectors, "
                "read credentials, change system settings, install software or delegate. "
                "Fleet carries runtime permissions to your requester; never bypass a refusal. "
                "Use Fleet ask_my_requester for questions, not request_user_input. "
                f"Every screenshot returned by cua_repl is saved automatically in outputs/{self.task}/computer-use/ "
                "with a capture-<hash> filename; do not write base64 screenshots yourself. The assigned task decides "
                "its output: its limits on shell use and files come before the output steps of RULES.md. Only when "
                "the task allows it, copy the screenshot that shows the result from that directory into "
                f"outputs/{self.task}/ with the shell and name its path in deliver_result: when you deliver, your "
                f"helper sends the files of outputs/{self.task}/ to the hub, but never its computer-use/ directory. "
                "Do not commit or push. Otherwise leave the automatic captures where they are and deliver the result "
                "in the form that the task asks for. Do not edit the helper, hub, profiles or settings. "
                "When waiting for an answer, end the turn; the helper will send a signal in this same thread. "
                "A final chat message alone does not deliver a Fleet result."
            )
            if self.needs != "screen":      # a primary task: its own instruction, not the screen task's limits
                instruction = primary_instruction(self.agent, self.task, self.needs)
            # The owner's direction excludes full Chrome DevTools Protocol access for the browser tools.
            config = {"mcp_servers.fleet.url":url,"mcp_servers.fleet.tool_timeout_sec":120,
                      "mcp_servers.fleet.default_tools_approval_mode":"approve","features.multi_agent":False,
                      "features.browser_use_full_cdp_access":False}
            if os.environ.get("FLEET_SESSION_TOKEN"):     # owner API 1.12: the session credential, from the environment
                config["mcp_servers.fleet.bearer_token_env_var"] = "FLEET_SESSION_TOKEN"
            # A primary task's thread is a saved session of the primary Codex, which the primary usage reading counts
            # (usage.transcript_tokens). A screen thread stays ephemeral; its token notifications are its count.
            params = {"cwd":fleet.KIT,"approvalPolicy":"on-request","sandbox":"workspace-write",
                      "ephemeral":self.needs == "screen","developerInstructions":instruction,"config":config}
            if self.model:              # the task's own settings (screen or primary), set for the whole thread
                params["model"] = self.model
            if self.effort:
                config["model_reasoning_effort"] = self.effort
            self.send({"id":2,"method":"thread/start","params":params})
        elif message.get("id") == 2:
            if message.get("error"):
                raise self.failed("Codex thread/start failed: " + reason(message["error"]))
            result = message["result"]
            self.thread = result["thread"]["id"]
            print("Fleet screen thread " + self.thread, flush=True)
            # The runtime's own report of the thread's model and effort; never the requested values.
            model, effort = result.get("model"), result.get("reasoningEffort")
            if isinstance(model, str):
                self.record("fleet/model", {"threadId": self.thread, "model": model, "effort": effort})
            if self.model and model != self.model:
                raise self.failed(f"Codex started the thread with model {model}, not the requested {self.model}")
            if self.effort and effort != self.effort:
                raise self.failed(f"Codex started the thread with effort {effort}, not the requested {self.effort}")
            self.start_turn(self.prompt)
        elif message.get("id") == 3:
            if message.get("error"):
                raise self.failed("Codex turn/start failed: " + reason(message["error"]))
            self.turn = message["result"]["turn"]["id"]
        elif method == "turn/started":
            self.turn = params.get("turn", {}).get("id", self.turn)
        elif method == "thread/tokenUsage/updated" and params.get("threadId") == self.thread and self.needs == "screen":
            try:
                record_screen_usage(fleet.KIT, self.agent, self.thread, params["tokenUsage"])
            except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
                print("Screen token counts could not be saved: " + type(exc).__name__, flush=True)
        elif method == "item/started":
            item = params.get("item", {})
            if item.get("type") in ("mcpToolCall", "commandExecution", "fileChange"):
                self.activity(item.get("tool") or item["type"])
        elif method == "item/completed":
            item = params.get("item", {})
            if item.get("type") == "agentMessage":
                print(item.get("text", ""), flush=True)
            elif item.get("type") == "mcpToolCall":
                paths = self.save_images(item)
                print("Tool " + str(item.get("tool")) + ": " + str(item.get("status")), flush=True)
                for path in paths:
                    print("Screenshot: " + path, flush=True)
        elif method == "turn/completed":
            self.turn = None
            self.turn_started = None
            turn = params.get("turn") if isinstance(params.get("turn"), dict) else {}
            if turn.get("error") or turn.get("status") == "failed":
                # The helper's own rule (threads.py): only a usage limit passes by itself. Each other failed turn
                # ends the session, with the runtime's records of it: a signal that waits or comes later starts no
                # turn, and the task's requester decides.
                if not Translator("codex_app").app_error(turn.get("error"))["retryable"]:
                    raise RuntimeError("Codex turn failed, and the session ends: " + reason(turn.get("error")))
                print("Turn failed; no automatic replay. Waiting for a Fleet signal.", flush=True)
            if self.pending_input:
                self.start_turn(self.pending_input.pop(0))

    def close(self):
        if self.desktop:
            self.desktop.close()
        if self.records:
            self.records.close()
            self.records = None
        if not self.child:
            return
        if self.child.poll() is None:
            try:
                if self.thread and self.turn:
                    self.request("turn/interrupt", {"threadId":self.thread,"turnId":self.turn})
                self.child.stdin.close()
                self.child.wait(timeout=5)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                pass
        # Own process group only, including any commands still running after app-server exits.
        try:
            os.killpg(self.child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            self.child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(self.child.pid, signal.SIGKILL)
            self.child.wait(timeout=3)

    def run(self):
        self.activity("screen runner start")  # Reject a closed/stale task before launching the runtime.
        if self.desktop:
            self.desktop.start()
        if self.records_path:
            os.makedirs(fleet.HOME, mode=0o700, exist_ok=True)
            fd = os.open(self.records_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            self.records = os.fdopen(fd, "a", encoding="utf-8")
        overrides = [x for name in self.off for x in ("-c", f"features.{name}=false")]     # none for a screen task
        # AUTONOMY.md decision 41: no request_user_input to refuse (decide) either, so the model never reaches for it;
        # and the plan tool, whose turn/plan/updated is the task's plan in the owner's app
        overrides += fleet.CODEX_NO_ASKING + fleet.CODEX_PLAN
        self.child = subprocess.Popen([self.command,"app-server",*overrides,"--stdio"], cwd=fleet.KIT,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr, start_new_session=True)
        def stop(_signum, _frame):
            self.stopping = True
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(sig, stop)
        selector = selectors.DefaultSelector()
        selector.register(self.child.stdout, selectors.EVENT_READ, "server")
        selector.register(sys.stdin, selectors.EVENT_READ, "inbox")
        decoder = JsonLines()
        self.send({"id":1,"method":"initialize","params":{
            "clientInfo":{"name":"agent_fleet_screen","version":"1"},
            "capabilities":{"experimentalApi":True}}})
        try:
            while not self.stopping:
                while not self.replies.empty():
                    self.send(self.replies.get_nowait())
                for key, _ in selector.select(0.5):
                    if key.data == "server":
                        part = os.read(self.child.stdout.fileno(),65536)
                        if not part:
                            return self.child.wait(timeout=5)
                        for msg in decoder.feed(part):
                            self.handle(msg)
                    else:
                        text = sys.stdin.readline().strip()
                        if text:
                            if self.turn_started or not self.thread:    # also before the thread exists
                                if text not in self.pending_input:
                                    self.pending_input.append(text)
                            else:
                                self.start_turn(text)
            return 0
        finally:
            selector.close()
            self.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--model")
    parser.add_argument("--effort")
    parser.add_argument("--needs", choices=("none", "browser", "screen"), default="screen")
    args = parser.parse_args()
    agent = os.environ.get("FLEET_AGENT", "")
    fleet.AGENT = agent or None         # its hook calls send the agent key (owner API 1.12)
    conf = fleet.agent_conf(agent)
    # This runner drives one runtime, the one the fleet speaks app-server to (lifecycle.APP_SERVER_RUNTIME), and
    # names it as the owner reads it.
    label = lifecycle.runtime_fact(lifecycle.APP_SERVER_RUNTIME, "label", lifecycle.APP_SERVER_RUNTIME)
    if args.needs == "screen":
        command = lifecycle.screen_program(conf)        # one of the fixed paths, never a program team.json names
        if not command or not Path(command).is_file():
            fleet.die(f"the configured {label} screen runner is not installed")
    else:                               # the primary runtime: the executable of the helper's own runtime status
        command = lifecycle.exe(lifecycle.APP_SERVER_RUNTIME)
        if not command:
            fleet.die(f"the {label} runtime is not installed")
    runner = Runner(agent, os.environ.get("FLEET_TASK", ""), os.environ.get("FLEET_ATTEMPT", "0"),
                    os.environ.get("FLEET_GENERATION", ""), args.prompt, command,
                    session=os.environ.get("FLEET_SESSION", ""), model=args.model, effort=args.effort, needs=args.needs)
    try:
        return runner.run()
    except (OSError, ValueError, RuntimeError) as exc:
        print("Fleet screen task stopped: " + str(exc), file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())

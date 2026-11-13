#!/usr/bin/env python3
"""Local owner-app fixture for API versions 1.1 to 1.3. Real hub code, synthetic data, loopback only.

    python3 -B ui_fixture.py [--port 0] [--manager-limited]

It never connects to the fleet, starts an agent or reads a vault. The first JSON line gives the PID, the
address for the app (use the printed http://localhost:<port>), the synthetic generation and the task
number for each state. A stand-in helper confirms pause and stop requests after two seconds, closes the
window of a stopped task, and adds a live record to the "live" task every four seconds. Stop with
Control-C; the temporary database is deleted. Logs hold ids and counts only. Profile saves and team
reloads use a private temporary copy of the Fleet repository with its own origin, never the real one.

Every agent of this fleet answers on loopback, so the hub reads them as sharing one machine and asks each
of them for its agent key (owner API 1.12). The fixture registers one key for each of them, as the owner's
app does, and its stand-in helper sends it: it plays by that rule instead of turning it off. It needs no
wrapper and no patch -- run the line above as it stands.
"""
import argparse
import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid

import hub
import threads
from leftovers import hub_files

KIT = os.path.dirname(os.path.abspath(__file__))
TEAM = {"hub": {"machine": "hub", "port": 8765},
        # Every machine that carries an agent is on 127.0.0.1 and must stay there: the stand-in helper calls the
        # hub's own helper routes, and `allowed()` wants the caller to come from that agent's machine address, which
        # for this process is loopback. The hub then reads those agents as sharing one machine and asks each for its
        # agent key, which is why `Fixture.agent_keys` registers one (see it). The three servers below carry no
        # agent that calls, so they have ordinary addresses.
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.1", "vps": "127.0.0.1", "mac-studio": "127.0.0.1",
                      "mac-mini": "127.0.0.1", "box": "100.70.1.21", "mini-2": "100.70.1.22", "vps-2": "100.70.1.23"},
        "servers": {"box": {"kind": "linux", "user": "fleet"}, "mini-2": {"kind": "mac", "user": "owner"},
                    "vps-2": {"kind": "linux", "user": "fleet"}},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell", "web"]},
                   "studio": {"role": "worker", "runtime": "claude", "machine": "mac-studio", "can": ["shell", "web", "browser", "screen"],
                              "repos": {"acme/web": "read"}, "tools": ["jobs"],
                              "secrets": {"bws://2f1e6c2a-0d44-4a51-9a6e-b4de012c53fb": "read"},
                              "google": {"gmail": {"account": "support@acme.example", "level": "read"}}},
                   "mini": {"role": "worker", "runtime": "codex", "machine": "mac-mini", "can": ["shell", "screen"]},
                   "scout": {"role": "worker", "runtime": "claude", "machine": "box", "can": ["shell", "web"], "active": False,
                             "vault": "none"}},
        "chat_apps": {"discord-studio": {"app": "discord", "label": "Studio", "agents": ["studio"], "unknown": "ignore"},
                      "whatsapp-main": {"app": "whatsapp", "label": "Fleet", "agents": ["manager"], "unknown": "ignore"}},
        "owner_devices": {"iphone": {"label": "iPhone", "address": "127.0.0.9"}},
        # owner feature resource_grants: one of each kind, so the Resources page shows a real pool, with a standing
        # for four of them. The grant is the authorization, so a mail account at send level is grantable too.
        "logins": {"bws://1f1e6c2a-0d44-4a51-9a6e-b4de012c53fb": {"title": "shop.example · admin", "kind": "login"},
                   "bws://2f1e6c2a-0d44-4a51-9a6e-b4de012c53fb": {"title": "DEPLOY_KEY", "kind": "api_key",
                                                                  "env": "DEPLOY_KEY"},
                   "bws://3f1e6c2a-0d44-4a51-9a6e-b4de012c53fb": {"title": "STRIPE_KEY", "kind": "api_key",
                                                                  "env": "STRIPE_KEY"}},
        "mcp": {"jobs": {"title": "Failed jobs", "url": "https://jobs.example/mcp", "auth": "key",
                         "key": "DEPLOY_KEY"}},
        "resources": {"repo:acme/web": {"max": "write", "to": "workers"},
                      "tool:jobs": {"max": "use", "to": "workers"},
                      "gmail:support@acme.example": {"max": "send", "to": "workers"},
                      "secret:bws://2f1e6c2a-0d44-4a51-9a6e-b4de012c53fb": {"max": "read", "to": "workers"}},
        # owner feature default_models: a Claude default, so the Settings row and "Default (Opus)" show
        "runtime_facts": {"claude": {"default_model": {"model": "opus", "effort": "high"}}}}


def say(event, **safe):
    print(json.dumps(dict(event=event, **safe)), flush=True)


class Fixture:
    def __init__(self, port, manager_limited):
        self.tmp = tempfile.mkdtemp(prefix="fleet-ui-fixture-")
        hub.TEAM.clear()
        hub.TEAM.update(TEAM)
        hub.CFG.update(**hub_files(self.tmp),       # its own files: the timers below sweep the attachment folder
                       silence=180, question_wait=120, manager_silence=120, ask_wait=45, ask_max=55, hook_wait=240,
                       job_wait=50, stop_after=60, offline_after=90, tick=2)
        hub.CFG["team_path"] = self.private_kit()
        hub.DB = sqlite3.connect(os.path.join(self.tmp, "fixture.db"), check_same_thread=False)
        hub.DB.row_factory = sqlite3.Row
        hub.DB.executescript(hub.SCHEMA)
        hub.migrate()
        self.db = "synthetic-ui-" + uuid.uuid4().hex[:12]
        hub.kv_set("db_id", self.db)
        self.keys = self.agent_keys()
        self.server = hub.HubServer(("127.0.0.1", port), hub.Handler)     # the hub's own backlog of 64
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.closed = set()         # windows the stand-in helper closed for a stop
        self.manager_limited = manager_limited
        self.live = threads.Translator("codex")
        self.tick = 0
        self.seeding = True
        self.tasks = self.seed(manager_limited)
        self.seeding = False

    def agent_keys(self):
        """One agent key for each agent that shares its address, the way the owner's app registers them.

        Every synthetic agent is on 127.0.0.1, because this process is the stand-in helper of all of them and
        `allowed()` wants a call to come from the agent's own machine address. The hub therefore reads them as
        sharing one machine, and owner API 1.12 then asks each of them for its agent key on every call: on a shared
        address the address alone names nobody. That is what a real shared machine does -- the owner registers the
        keys (`POST /ui/team/agents/<agent>/key`, because enrollment by the helper is refused there) and each helper
        sends its own -- so the fixture does the same thing, and no hub rule is turned off to get its data in.
        Without this, every batch of thread records is refused with 403 and all six threads come out empty, which
        reads like an app that draws nothing.

        An agent alone on its address (`scout`) gets no key, and keeps the plain address rule.
        """
        keys = {}
        for name in hub.agents():
            if not hub.shared_machine(name):
                continue
            keys[name] = secrets.token_urlsafe(32)      # never printed, never logged: the hub keeps the SHA-256 only
            hub.ins("INSERT INTO agent_keys(agent,sha256,created,source) VALUES(?,?,?,'owner')",
                    (name, hashlib.sha256(keys[name].encode()).hexdigest(), hub.now()))
        return keys

    def private_kit(self):
        """A temporary Fleet repository and origin, so that the hub's Git writes stay inside this fixture."""
        def git(*args, cwd=None):
            subprocess.run(["git", "-c", "user.name=fixture", "-c", "user.email=fixture@invalid", "-c",
                            "init.defaultBranch=main", *args], cwd=cwd, check=True, capture_output=True)
        seed = os.path.join(self.tmp, "seed")
        os.makedirs(os.path.join(seed, "profiles"))
        with open(os.path.join(seed, "team.json"), "w") as f:
            json.dump(TEAM, f, indent=2)
        for agent in TEAM["agents"]:
            source = os.path.join(KIT, "profiles", agent + ".md")
            target = os.path.join(seed, "profiles", agent + ".md")
            if os.path.exists(source):
                shutil.copy(source, target)
            else:
                with open(target, "w") as f:
                    f.write(hub.render_profile(agent, [
                        {"key": "character", "title": "Character", "text": "Synthetic and quiet."},
                        {"key": "responsible_for", "title": "Responsible for", "text": "Fixture work only."},
                        {"key": "may_do", "title": "May do without asking", "text": "Read files in this repository."},
                        {"key": "must_ask", "title": "Must ask first", "text": "Anything else."}]))
        git("init", "-q", seed)
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "fixture seed", cwd=seed)
        git("clone", "-q", "--bare", seed, os.path.join(self.tmp, "origin.git"))
        git("clone", "-q", os.path.join(self.tmp, "origin.git"), os.path.join(self.tmp, "kit"))
        return os.path.join(self.tmp, "kit", "team.json")

    # ---- the hub's own routes, called the way a helper calls them
    def post(self, path, body, agent=None):
        headers = {"Content-Type": "application/json"}
        if agent in self.keys:          # as that agent's helper would send it, on every call
            headers["Authorization"] = "Bearer " + self.keys[agent]
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), headers=headers)
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=10) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def records(self, agent, tid, rows, runtime, attempt=1, session=None, translator=None):
        translator = translator or threads.Translator(runtime)
        made = [r for row in rows for r in translator.records(row)]
        code, body = self.post(f"/helper/events/{agent}", {"generation": self.db, "task": f"T-{tid}",
                                                           "attempt": attempt, "session": session or str(uuid.uuid4()),
                                                           "events": made}, agent=agent)
        if code != 200:
            # A batch refused in silence leaves an empty thread, and an empty thread reads as an app that draws
            # nothing. So say it, and while seeding stop: a fixture that serves empty threads is worse than none.
            say("records_refused", agent=agent, task=tid, status=code, error=(body or {}).get("error"))
            if self.seeding:
                raise RuntimeError(f"the hub refused thread records for {agent} on T-{tid}: "
                                   f"{(body or {}).get('error')}")

    def task(self, owner, title, done_when, state="working"):
        text = hub.t_create_task("manager", {"owner": owner, "title": title, "done_when": done_when,
                                             "details": f"Synthetic fixture task: {title.lower()}."})
        tid = int(text.split()[1][2:].rstrip("."))
        hub.q("UPDATE tasks SET state=?, started=? WHERE id=?", (state, hub.now() - 600, tid))
        hub.ins("INSERT INTO notes(task,agent,ts,text) VALUES(?,?,?,?)", (tid, owner, hub.now() - 300, f"Started: {title}."))
        return tid

    def seed(self, manager_limited):
        now = time.time()
        self.heartbeat()
        live = self.task("vps", "Write the release note", "outputs/release-note.txt is pushed")
        self.live_session = str(uuid.uuid4())
        self.records("vps", live, [
            {"type": "session_meta", "payload": {"id": "synthetic-codex-thread"}},
            {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "UserMessage", "id": "u1",
                "content": [{"type": "text", "text": f"Your task is T-{live}. Write the release note."}]}}},
            {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "Reasoning", "id": "r1",
                "summary_text": ["Read the changelog, then draft three short paragraphs."]}}},
            {"type": "response_item", "payload": {"type": "function_call", "name": "update_plan", "call_id": "plan1",
                "arguments": json.dumps({"plan": [{"step": "Read the changelog", "status": "completed"},
                                                  {"step": "Draft the note", "status": "in_progress"},
                                                  {"step": "Commit and deliver", "status": "pending"}]})}},
            {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "CommandExecution", "id": "c1",
                "command": ["git log --oneline -5"], "status": "completed", "exit_code": 0, "aggregated_output": "3 commits"}}},
            {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "McpToolCall", "id": "m1",
                "server": "fleet", "tool": "report_progress", "readOnlyHint": False, "status": "completed",
                "result": {"content": [{"type": "text", "text": "Noted."}], "isError": False}}}},
            {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "AgentMessage", "id": "a1",
                "content": [{"type": "text", "text": "The changelog has three user-facing changes. I am drafting now."}]}}},
        ], "codex", session=self.live_session, translator=self.live)

        paused = self.task("studio", "Send the launch note once", "the practice outbox has one launch note")
        self.records("studio", paused, [
            {"type": "user", "sessionId": "synthetic-claude", "message": {"content": f"Your task is T-{paused}."}},
            {"type": "assistant", "sessionId": "synthetic-claude", "message": {"content": [
                {"type": "thinking", "thinking": "Check the outbox first, then send once."},
                {"type": "tool_use", "id": "toolu_check", "name": "Bash", "input": {"command": "curl -s hub/outbox?key=launch"}}]}},
            {"type": "user", "sessionId": "synthetic-claude", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "toolu_check", "content": '{"count": 0}'}]}},
            {"type": "assistant", "sessionId": "synthetic-claude", "message": {"content": [
                {"type": "tool_use", "id": "toolu_send", "name": "Bash",
                 "input": {"command": "curl -s -X POST hub/outbox -d key=launch -d text=hello"}}]}},
            {"type": "user", "sessionId": "synthetic-claude", "message": {"content": [
                {"type": "text", "text": "[Request interrupted by user for tool use]"}]}},
        ], "claude")
        hold = hub.request_hold(paused, "pause", "owner", "Synthetic pause with an unknown send")[0]
        hub.settle_hold(dict(hold), True, "synthetic helper: interrupted; the session is idle", True)

        unconfirmed = self.task("studio", "Fill the signup form", "a screenshot shows the confirmation page")
        # Its records come before the hold: `record_outcome_rows` reads this thread when a stop is settled, and the
        # open browser call is then what the owner must check. Settling it unconfirmed does not take that path, but
        # Stop pressed in the app confirms the same hold, and the unknown outcome then carries the call's own name
        # instead of "its actions were not recorded". The last turn has no end: that is the stop nobody confirmed.
        self.records("studio", unconfirmed, [
            {"type": "user", "sessionId": "synthetic-claude-signup",
             "message": {"content": f"Your task is T-{unconfirmed}. Fill the signup form."}},
            {"type": "assistant", "sessionId": "synthetic-claude-signup", "message": {"content": [
                {"type": "thinking", "thinking": "Open the signup page, fill it in, then screenshot the confirmation."},
                {"type": "tool_use", "id": "toolu_page", "name": "mcp__claude-in-chrome__navigate",
                 "input": {"url": "https://pilot-site-a.example/signup"}}]}},
            {"type": "user", "sessionId": "synthetic-claude-signup", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "toolu_page", "content": "the signup page is open"}]}},
            {"type": "assistant", "sessionId": "synthetic-claude-signup", "message": {"content": [
                {"type": "tool_use", "id": "toolu_fill", "name": "mcp__claude-in-chrome__form_input",
                 "input": {"ref": "email", "value": "pilot@pilot-site-a.example"}}]}},
            {"type": "user", "sessionId": "synthetic-claude-signup", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "toolu_fill", "content": "filled"}]}},
            {"type": "assistant", "sessionId": "synthetic-claude-signup", "message": {"content": [
                {"type": "tool_use", "id": "toolu_create", "name": "mcp__claude-in-chrome__computer",
                 "input": {"action_summary": "Presses Create account", "action": "left_click", "ref": "ref_7"}}]}},
        ], "claude")
        hold = hub.request_hold(unconfirmed, "stop", "owner", "Synthetic stop that the helper could not confirm")[0]
        hub.settle_hold(dict(hold), False, "synthetic helper: the session still shows a running turn after three interrupts")

        limited = self.task("studio", "Check the price page", "the price is in outputs/price.txt")
        resets_at = now + 45 * 60
        self.records("studio", limited, [
            {"type": "user", "sessionId": "synthetic-claude-price",
             "message": {"content": f"Your task is T-{limited}. Check the price page."}},
            {"type": "assistant", "sessionId": "synthetic-claude-price", "message": {"content": [
                {"type": "thinking", "thinking": "Open the price page, read the three plans, then write the file."},
                {"type": "tool_use", "id": "toolu_prices", "name": "mcp__claude-in-chrome__navigate",
                 "input": {"url": "https://pilot-site-a.example/pricing"}}]}},
            {"type": "user", "sessionId": "synthetic-claude-price", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "toolu_prices", "content": "the pricing page is open"}]}},
            {"type": "assistant", "sessionId": "synthetic-claude-price", "message": {"content": [
                {"type": "tool_use", "id": "toolu_read", "name": "mcp__claude-in-chrome__get_page_text", "input": {}}]}},
            {"type": "user", "sessionId": "synthetic-claude-price", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "toolu_read",
                 "content": "Starter EUR 19 a month, Team EUR 49, Scale EUR 99"}]}},
            # Where the allowance ran out, as a limited Claude session leaves it. The hub reads this record itself
            # and holds the agent's work until the reset, so the line below gives the same time and changes nothing:
            # the state is the same whether or not anything read the thread.
            {"type": "assistant", "sessionId": "synthetic-claude-price", "isApiErrorMessage": True, "error": "rate_limit",
             "quotaLimits": {"status": "rejected", "resetsAt": resets_at},
             "message": {"content": "You have reached your usage limit."}},
        ], "claude")
        hub.start_limit("studio", resets_at, limited)

        stalled = self.task("mini", "Summarize the analytics export", "outputs/summary.md is pushed")
        hub.know("mini")
        hub.q("UPDATE agents SET last_seen=? WHERE name='mini'", (now - 20 * 60,))
        hub.q("UPDATE tasks SET stalled_since=?, stalled_reason=? WHERE id=?",
              (now - 15 * 60, hub.silent_words("mini", now - 20 * 60, now), stalled))

        done = self.task("vps", "Write a haiku about tides", "outputs/haiku.txt is pushed")
        self.records("vps", done, [
            {"type": "session_meta", "payload": {"id": "synthetic-codex-done"}},
            {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "FileChange", "id": "f1",
                "changes": {"outputs/haiku.txt": {"type": "add"}}, "status": "completed"}}},
            {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "CommandExecution", "id": "c2",
                "command": ["git push"], "status": "failed", "exit_code": 1, "aggregated_output": "rejected: fetch first"}}},
            {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "CommandExecution", "id": "c3",
                "command": ["git pull --rebase && git push"], "status": "completed", "exit_code": 0}}},
            {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "AgentMessage", "id": "a2",
                "content": [{"type": "text", "text": "Pushed outputs/haiku.txt."}]}}},
            {"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": "Pushed."}},
        ], "codex")
        hub.q("UPDATE tasks SET state='completed', outcome='completed', what='Wrote the haiku', where_='outputs/haiku.txt', "
              "how='Read it back', delivered=?, accepted=1, checked_at=? WHERE id=?", (now - 60, now - 30, done))
        if manager_limited:
            hub.start_limit("manager", now + 30 * 60)
        # one goal with the live task, a next step and recorded spending near its limit
        gid = hub.ins("INSERT INTO goals(title,text,state,revision,limits,created,updated,request_id,next_step,next_task,"
                      "next_set,reviewed_at) VALUES(?,?,'active',1,?,?,?,?,?,?,?,?)",
                      ("Publish the spring release", "Ship the release note and the launch page.",
                       json.dumps({"money": {"amount": 100.0, "currency": "EUR"}, "tokens": None,
                                   "deadline": now + 3 * 86400, "not_to_do": ["No paid ads"]}),
                       now - 3600, now - 3600, str(uuid.uuid4()), "Check the release note", live, now - 600, now - 600))
        hub.q("UPDATE tasks SET goal_id=? WHERE id IN (?,?)", (gid, live, done))
        # owner feature need_options: one item with the agent's own buttons, one without, so the app can draw both
        for title, why, todo, raised, options in (
                ("Which label goes on the release note?", "Studio asks for the exact wording before it writes the file.",
                 "Answer with the label to use.", now - 900, None),
                ("Move the analytics export to another machine?", "mini has been silent for 20 minutes.",
                 "Press one, or write what you want instead.", now - 300,
                 ["Move it to vps and let it start again from the beginning",
                  "Wait for mini until 18:00, then ask me again",
                  "Stop the task and keep what it has written so far"])):
            hub.ins("INSERT INTO needs(title,why,todo,raised,by,options) VALUES(?,?,?,?,'manager',?)",
                    (title, why, todo, raised, json.dumps(options) if options else None))
        hub.ins("INSERT INTO spends(goal,cents,currency,what,task,by,created) VALUES(?,?,?,?,?,?,?)",
                (gid, 8500, "EUR", "Synthetic banner design", live, "manager", now - 900))
        hub.goal_history(gid, "owner", "created", "Publish the spring release")
        # owner API 1.24: the goal's plan, with a step that is done, one being worked on, one that waits and one
        # that was tried and did not work, so the app can draw every state
        for n, (text, task, state) in enumerate((
                ("Write the release note", done, "done"),
                ("Check the release note with the shop", live, "doing"),
                ("Ask the printer for a quote: they answer by mail, no API", None, "failed"),
                ("Send it to the mailing list, once the note is checked", None, "blocked")), start=1):
            hub.ins("INSERT INTO goal_steps(goal,n,text,task,state,created,updated) VALUES(?,?,?,?,?,?,?)",
                    (gid, n, text, task, state, now - 3000, now - 600))
            hub.goal_history(gid, "manager", "plan", f"step {n} [{state}]: {text}")
        hub.goal_sweep(now)
        self.chat_apps(now)
        self.servers(now)
        self.releases(now)
        return {"live": live, "paused_with_unknown_outcome": paused, "stop_not_confirmed": unconfirmed,
                "usage_limit": limited, "no_live_path": stalled, "completed": done, "goal": gid}

    def chat_apps(self, now):
        """Synthetic chat app data (owner features chat_apps and people): linked owner handles, the bridge's last status,
        a Discord message to studio with a read reply, a WhatsApp message to the manager whose reply is not confirmed,
        and one ignored sender. No bridge runs: the outbound items are settled here."""
        for app, ident in (("discord", "100200300"), ("whatsapp", "34600111222@s.whatsapp.net")):
            hub.q("INSERT INTO owner_handles(app,id,alias,name,linked) VALUES(?,?,NULL,'owner',?)", (app, ident, now - 86400))
        for aid, user, name, app_id in (("discord-studio", "4444", "Fleet Studio", "5555"),
                                        ("whatsapp-main", "34911222333:4@s.whatsapp.net", "+34 911 222 333", None)):
            hub.q("INSERT INTO chat_status(account,state,user,name,application_id,error,at) VALUES(?,'connected',?,?,?,NULL,?)",
                  (aid, user, name, app_id, now))
        hub.kv_set("bridge_seen", now)
        base = dict(group=False, sender_alt=None, sender_name="owner", bot=False, from_me=False, kind="text", ts=now)
        hub.chat_inbound(dict(base, account="discord-studio", id="synthetic-d1", chat="dm-1", sender="100200300",
                              text="How is the screenshot task going?"))
        chat = (self.db, "owner-chat", "1")
        req = hub.q1("SELECT request_id FROM ui_requests WHERE recipient='studio' ORDER BY created DESC")["request_id"]
        hub.call_tool("studio", "read_messages", {}, chat)
        hub.call_tool("studio", "tell_owner", {"text": "The **signup form** waits for your decision; the price check "
                                                       "resumes after the usage limit.", "about": "status",
                                               "in_reply_to": req}, chat)
        hub.chat_inbound(dict(base, account="whatsapp-main", id="synthetic-w1", chat="34600111222@s.whatsapp.net",
                              sender="34600111222@s.whatsapp.net", text="Is the spring release on track?"))
        event = hub.q1("SELECT event_id FROM ui_requests WHERE recipient='manager' ORDER BY created DESC")["event_id"]
        hub.call_tool("manager", "read_messages", {}, None)
        hub.call_tool("manager", "tell_owner", {"text": "Yes. The release note is in progress; 85 of 100 EUR are spent.",
                                                "about": f"Spring release, M-{event}"}, None)
        hub.chat_inbound(dict(base, account="whatsapp-main", id="synthetic-w2", chat="34699000000@s.whatsapp.net",
                              sender="34699000000@s.whatsapp.net", sender_name="Unknown", text="Hello, who is this?"))
        hub.q("UPDATE chat_out SET state='done', given=? WHERE kind IN ('typing','read')", (now,))
        for app, state, error in (("discord", "read", None), ("whatsapp", "unknown", "no report from the bridge in 120 seconds")):
            hub.q("UPDATE chat_out SET state=?, error=?, parts=1, platform_ids=?, given=?, updated=? WHERE kind='message' "
                  "AND app=?", (state, error, json.dumps([f"synthetic-{app}-p1"]), now, now, app))
        with hub.LOCK, hub.transaction():           # chat_count writes inside its caller's transaction
            for aid in ("discord-studio", "whatsapp-main"):
                hub.chat_count(aid, "parts", now, 1)
        # chat apps round 2: studio writes to the owner first (delivered on Discord), and asks vps, which answers
        hub.call_tool("studio", "message_owner", {"request_id": str(uuid.uuid4()), "text": "The screenshot task is "
                                                  "done: 12 pages, all in outputs."}, chat)
        hub.q("UPDATE chat_out SET state='delivered', parts=1, platform_ids=?, given=?, updated=? WHERE state='queued' "
              "AND kind='message'", (json.dumps(["synthetic-discord-p2"]), now, now))
        asked = json.loads(hub.call_tool("studio", "message_agent", {"request_id": str(uuid.uuid4()), "agent": "vps",
                                                                     "text": "Which proxy list does the scrape use?"},
                                         chat)[0])["id"]
        hub.call_tool("vps", "read_messages", {}, chat)
        hub.call_tool("vps", "message_agent", {"request_id": str(uuid.uuid4()), "agent": "studio",
                                               "text": "list-b.txt in the scrape folder.", "in_reply_to": asked}, chat)

    def releases(self, now):
        """Synthetic releases (owner features releases and entitlement): the subscription this fleet carries, the
        release it took last week, and one that rolled back, so the Updates screen has every state to draw. No
        channel is polled and nothing is merged: the rows are written here, and the fleet's own revision does not
        move. `have_release_key` is false, as it is in the repository until P7 commits the key."""
        hub.kv_set("fleet_id", "0123456789abcdef")
        hub.q("INSERT INTO entitlement(id,fleet,token,plan,until,machines,agents,verified,stored,channel_said,"
              "channel_at) VALUES(1,?,'synthetic.token','monthly',?,4,6,1,?,NULL,?)",
              ("0123456789abcdef", now + 20 * 86400, now - 30 * 86400, now - 600))
        hub.kv_set("releases_checked", now - 600)
        hub.kv_set("releases_status", 200)
        here = hub.kit_revision(fresh=True) or "0" * 40
        for seen, revision, version, state, step, says, reached in (
                (now - 7 * 86400, "a" * 40, "2026.10.1", hub.releases.DONE, "follow",
                 f"release 2026.10.1 is on config as {here[:12]}; this fleet moved", here),
                (now - 3 * 86400, "b" * 40, "2026.10.2", hub.releases.ROLLED_BACK, "selftest",
                 f"release 2026.10.2 fails 2 check(s) that the baseline does not have (the hub answers nothing, "
                 f"a task cannot be created); 110 of 121 passed. The fleet stays at {here[:12]}.", None),
                (now - 600, "c" * 40, "2026.10.3", "verified", None, None, None)):
            hub.q("INSERT INTO releases(seen,revision,version,notes,minimum,hold,state,step,says,pinned,reached,"
                  "started,finished,automatic) VALUES(?,?,?,?,NULL,0,?,?,?,?,?,?,?,0)",
                  (seen, revision, version, f"https://founderizer.com/releases/{version}", state, step, says,
                   here if state != "verified" else None, reached,
                   seen + 10 if state != "verified" else None, seen + 400 if state != "verified" else None))

    def servers(self, now):
        """Synthetic servers (owner feature servers): a free Mac and a free Linux server that joined, and a Linux server
        whose new agent scout waits for the owner's Claude Code sign-in. Readings of the older machines come from their
        agents' helpers. No server service runs: the readings and the job are written here."""
        def reading(system, codex, claude, user, load):
            return json.dumps({"revision": hub.kit_revision(fresh=True), "os": {"name": system, "kernel": "6.8.0"},
                               "security": {"unattended_upgrades": "Ubuntu" in system, "pending_security": 0,
                                            "reboot_required": False, "firewall": "active", "tailscale": True},
                               "runtimes": {"codex": codex, "claude": claude}, "access": {"user": user},
                               "load": dict(zip(hub.lifecycle.LOAD_KEYS, load))})
        none, signed = {"version": None, "signed_in": None}, {"version": "2.1.287", "signed_in": True}
        # Each server's load (lifecycle.machine_load): the Mac as the owner's Mac Studio read on 4 November 2026, and
        # vps-2 with its disk 91% full, so the app draws a figure that needs care.
        for name, system, codex, claude, user, load in (
                ("mini-2", "macOS 15.6", none, signed, "owner", (14.1, 12428394496, 38654705664, 273775087616,
                                                                 494384795648)),
                ("vps-2", "Ubuntu 24.04.1 LTS", {"version": "codex-cli 0.160.0", "signed_in": True}, none, "fleet",
                 (4.5, 783446016, 3999657984, 36360497438, 39956590592)),
                ("box", "Debian GNU/Linux 12 (bookworm)", none, {"version": "2.1.287", "signed_in": False}, "fleet",
                 (1.5, 1145614336, 3999657984, 15115923456, 80290492416))):
            hub.q("INSERT INTO server_keys(server,sha256,created) VALUES(?,?,?)", (name, "0" * 64, now - 3600))
            hub.q("INSERT INTO server_status(server,data,reported) VALUES(?,?,?)",
                  (name, reading(system, codex, claude, user, load), now - 40))
        # The sign-in of that new agent is the one the owner finishes in the app (machine_signin): the job's prompt
        # only says which agent and which sign-in, and the link lives in the hub's memory, on scout's machine row.
        lid = hub.ins("INSERT INTO signin_jobs(agent,runtime,state,detail,created,updated) "
                      "VALUES('scout','claude','needs_owner',?,?,?)",
                      ("Open the link and paste the code it gives you.", now - 100, now - 20))
        hub.LIVE_LOGINS[lid] = {"url": "https://claude.ai/oauth/authorize?code=true&client_id=fleet&state=fixture",
                                "show_code": None, "wants_code": True, "at": now - 20}
        hub.q("INSERT INTO server_jobs(server,kind,agent,runtime,state,step,detail,prompt,created,updated) "
              "VALUES('box','install','scout','claude','needs_owner','sign_in',?,?,?,?)",
              ("Sign Scout in to Claude Code in Founderizer.",
               json.dumps({"kind": "signin", "purpose": "claude_login", "agent": "scout", "login": lid}),
               now - 120, now - 20))
        # owner feature default_models: each machine's model list, as its helper reads it (Lifecycle.read_models)
        levels = ["low", "medium", "high", "xhigh", "max"]
        listed = {"claude": [{"model": m, "display_name": m.capitalize(), "default": False, "efforts": levels,
                              "default_effort": None} for m in ("fable", "opus", "sonnet")],
                  "codex": [{"model": "gpt-6-luna", "display_name": "GPT-6-Luna", "default": True, "efforts": levels,
                             "default_effort": "medium"},
                            {"model": "gpt-5.6-terra", "display_name": "GPT-5.6-Terra", "default": False,
                             "efforts": levels + ["ultra"], "default_effort": "medium"}]}

        def models(runtime):
            return {"runtime": runtime, "ok": True, "read_at": now - 60, "source": "fixture",
                    "other_names": runtime == "claude", "error": None, "options": listed[runtime]}
        for agent, system, runtime, use in (("manager", "Ubuntu 24.04.1 LTS", "claude", (0.3, 432013312)),
                                            ("vps", "Ubuntu 24.04.1 LTS", "codex", (2.4, 1288490188)),
                                            ("studio", "macOS 15.6", "claude", (6.8, 2469606195))):
            hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES(?,?,?)", (agent, json.dumps({
                "revision": hub.kit_revision(fresh=True), "os": {"name": system, "kernel": "6.8.0"},
                "runtime": {"name": runtime, "version": "1.0.0", "signed_in": True}, "access": {"user": "fleet"},
                # Its key is registered, so its helper reports that it sends one and that it has no legacy window.
                "features": ["agent_key", "default_models"], "legacy_windows": [], "models": models(runtime),
                "use": {"cpu_percent": use[0], "memory": use[1]}}), now - 60))       # lifecycle.agent_use

    # ---- the stand-in helpers
    def heartbeat(self):
        open_tasks = {r["id"]: r["owner"] for r in hub.q("SELECT id, owner FROM tasks WHERE state NOT IN "
                                                       "('completed','failed','rejected','canceled')")}
        for agent in ("manager", "vps", "studio"):
            windows = ["manager"] if agent == "manager" else [
                f"T-{tid}" for tid, owner in open_tasks.items() if owner == agent and f"T-{tid}" not in self.closed]
            hub.know(agent)
            hub.q("UPDATE agents SET last_seen=?, alive=?, alive_ts=?, client=COALESCE(client,'synthetic CLI'), client_seen=? "
                  "WHERE name=?", (hub.now(), ",".join(windows), hub.now(), hub.now(), agent))
        if not hub.active_limit("manager"):     # the stand-in manager reads its inbox, so no "silent" banner appears
            hub.q("UPDATE events SET read_at=? WHERE agent='manager' AND kind='say' AND read_at IS NULL", (hub.now(),))

    def confirm(self):
        for h in hub.q("SELECT h.*, t.owner FROM holds h JOIN tasks t ON t.id=h.task WHERE h.state='requested' AND h.created<?",
                       (hub.now() - 2,)):
            if h["owner"] == "mini":
                continue            # its helper is offline: the request waits, as it would in the fleet
            code, body = self.post(f"/helper/control/{h['owner']}", {"hold": h["id"], "confirmed": True, "ran": True,
                "detail": "synthetic helper: interrupted" + ("; the session is closed" if h["kind"] == "stop" else "; the session is idle"),
                "flushed": []}, agent=h["owner"])
            if h["kind"] == "stop":
                self.closed.add(f"T-{h['task']}")
            say("control_confirmed", hold=h["id"], task=h["task"], kind=h["kind"], status=code)
        for e in hub.q("SELECT task, extra FROM events WHERE kind='task' AND helper_ack IS NULL AND read_at IS NULL"):
            if json.loads(e["extra"] or "{}").get("resume") and f"T-{e['task']}" in self.closed:
                self.closed.discard(f"T-{e['task']}")     # a resumed task gets a new session window
                hub.q("UPDATE events SET read_at=? WHERE kind='task' AND task=?", (hub.now(), e["task"]))
                say("session_restarted", task=e["task"])

    def stream(self):
        tid = self.tasks["live"]
        t = hub.q1("SELECT state, attempt FROM tasks WHERE id=?", (tid,))
        if t["state"] in hub.TERMINAL or hub.active_hold(tid):
            return
        if t["attempt"] != getattr(self, "live_attempt", 1):
            self.live_attempt, self.live_session, self.live = t["attempt"], str(uuid.uuid4()), threads.Translator("codex")
        self.tick += 1
        call = f"call_{self.tick}"
        rows = [[{"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": f"call_{self.tick - 1}",
                  "output": [{"type": "input_text", "text": "a changelog line"}]}},
                 {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "AgentMessage", "id": f"a{self.tick}",
                  "content": [{"type": "text", "text": f"Draft paragraph {self.tick // 2} is ready."}]}}}],
                [{"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": call,
                  "input": f"curl -s -X POST hub/outbox -d key=draft-{self.tick}"}}]][self.tick % 2]
        self.records("vps", tid, rows, "codex", attempt=t["attempt"], session=self.live_session, translator=self.live)

    def run(self):
        threading.Thread(target=hub.timers, daemon=True).start()
        while True:
            time.sleep(1)
            self.heartbeat()        # no outer hub lock: confirm() calls the hub's own routes
            self.confirm()
            if int(time.time()) % 4 == 0:
                self.stream()       # a shell call stays open for four of every eight seconds

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        hub.DB.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="Local owner-app fixture for API versions 1.1 to 1.3 (synthetic, loopback only)")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--manager-limited", action="store_true", help="also show the manager's own usage-limit flag")
    args = ap.parse_args()
    fixture = Fixture(args.port, args.manager_limited)
    port = fixture.server.server_port
    print(json.dumps({"pid": os.getpid(), "app_url": f"http://localhost:{port}", "db": fixture.db,
                      "tasks": fixture.tasks, "features": ["thread_events", "task_controls", "limit_holds", "liveness",
                                                           "machines", "goals", "profiles", "chat_apps", "people", "servers",
                                                           "mobile", "resource_grants", "releases",
                                                           "entitlement"]}),
          flush=True)
    try:
        fixture.run()
    except KeyboardInterrupt:
        pass
    finally:
        fixture.close()
        say("stopped", tasks=len(fixture.tasks))


if __name__ == "__main__":
    sys.exit(main())

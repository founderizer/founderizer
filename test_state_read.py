"""A read of the state (`GET /ui/state`) takes less time and holds the hub's lock for less time, and its answer is the
same bytes as before (10 November 2026).

The Mac app reads `GET /ui/state` every 3 seconds. From the owner's Mac a read of the first fleet's hub took 0.33 s
that evening. Its first byte came after 0.32 s and one round trip was 0.056 s, so about 0.26 s was the hub's own work.
Measured with a copy of that fleet's database (its row counts and text sizes, with made-up words) in one process on the
owner's Mac, the median of 20 reads, the code before this change:

- a read took 139 ms, and its thread held the hub's lock 81 ms in all, in 8,981 takes;
- scrub read the registered logins once for each text of the answer: 8,980 reads of the `secrets` table, 83 ms. It
  reads them once for its whole value now (hub.SCRUB), and each text still goes through secret_hit;
- duty_view read the steps and the tasks of each case that it shows with two reads for each case: at least 236 reads
  for one duty with 118 open cases. duty_case_parts reads them for all the cases of a duty with two reads;
- goal_view read a goal's tokens twice, with one join each time. It reads them once;
- the rows of the five plain tables became dicts inside the lock: 2.1 ms for the tasks. They become dicts after it.

After the change a read took 45 ms, and its thread held the lock 9.6 ms in 2 takes: the `with LOCK:` block of
Handler.ui_state (9.5 ms; before, 14.3 ms) and scrub's one read of the logins. Over HTTP, at the app's rhythm, the
first byte came after 43.5 ms (before, 138.1 ms). The plain answer of that copy was 1,665,544 bytes with the same
SHA-256 before and after: that is the proof against the code before the change.

This file holds the change to that, for a database that has every part of the state, with registered logins inside
texts of each part:
- the state read now is the same bytes as the state read with scrub and the duty parts as they were before (each
  text's own read of the logins, each case's own reads);
- the five tables and a goal's tokens in the answer are what the database holds;
- one read of the logins for each read of the state, also with no login; one read of a goal's tokens; two reads for the
  steps and the tasks of all the cases of a duty, also in chunks;
- the rows of the five tables become dicts after the lock, and each keeps its place in the answer;
- the logins of one scrub stay in its thread and end with it.

The next day (11 November 2026) the other callers of the hub: a call that came while a read of the state built its
answer waited for Python's interpreter lock, 5 ms for each of its turns, because scrub and json.dumps run long stretches
of Python and of C. Measured on the first fleet's hub, a call that came 40 ms after a read of the state took 15 to 18 ms
more (three runs).
Now the hub sets a shorter switch interval (hub.SWITCH_INTERVAL), writes a large answer in parts (hub.json_text, the
same text as json.dumps), and scrub keeps the texts that it searched in a cache of its own that holds a whole state
(hub.SCRUB_SPANS_KEPT): with 8,192, a state of more than that many different texts searched every text again at each
read. OtherCallers holds these.

Later that day the hub's lock block itself. It was measured with the copy of the first fleet's database and with a copy
that has 2.3 times its rows, the median of 25 reads on the owner's Mac (on the hub the block took 20 to 25 ms). Before
this change, each item, goal, step of a plan, duty and wake-up rule read its own rows in the `with LOCK:` block of
Handler.ui_state: 290 and 369 statements, 9.4 ms and 18.6 ms. tasks has no index on its step, so each step of a plan
read the whole table, and each goal read every session event. Now need_reads, goal_reads and duty_reads read each of
those tables once for all of them, and the views of the needs and the duties, the messages and the reports are made from
their rows after the lock: 159 statements, 5.6 ms and 9.4 ms. The answer of both copies is the same bytes as before.
Reads and AfterTheLock hold this: each view is the same with the rows read for all as with its own reads.

Then the agents. Each agent's view read its own rows in the block: 119 statements for the 11 agents of the first fleet's
copy, and 10 of them read all of session_credentials, a table that gets a row for each session. agent_reads reads each
of those tables once for all the agents, in 10 statements, the chat credentials only when an agent needs them; with the
turn end of the manager, the agents' part of the block made 11 statements, and it took 0.5 ms in place of 1.4 ms in both
copies (measured). The views of the agents stay in the lock, because they also read the team's configuration.

Then the rest of the lock block: about 15 ms on the hub, for its statements and the fetching of their rows. Since then
the hub keeps its records in WAL mode (hub.wal_on), and a read of the state takes the lock for one moment only: it
starts a read transaction on a read-only connection of its own and takes the change token, the clock and a copy of the
team (hub.state_moment), so the views of the agents read the team of that moment. It reads the rest from that
transaction with no lock held, while the writers go on. In one process on the owner's Mac, the median of 25 reads of
the two copies, the read's thread held the lock 6.3 ms and 13.1 ms in all before, and 0.2 ms after, for the same answer,
in the same time. OwnMoment holds this: the same bytes and the same statements as under the lock, and the lock held only
in the moment; writers that come during the read go through at once and are not in it, nor is the team they wrote, and
the answer has the token and the time of its moment; each thread has its own moment; a login registered during the read
is masked; a read that cannot begin its own reads under the lock, as before; a read that fails gives its connection
back. RealHub: the hub puts its records in WAL mode and reads the state with a connection of its own. The copy of WAL
records that a backup takes is test_backup_restore's.

    python3 -m unittest -v test_state_read
"""
import ast
import functools
import hashlib
import http.client
import inspect
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import json
import random
import re
import shutil
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

import hub
from test_ui_api import KIT, PATIENCE, OwnerAPI, parent_pipe

T0 = 1794322671.5                       # the hub's clock stands still, so two reads of the state are the same bytes
LOGIN = "Pr4ct!ce-Login#2026"           # a registered login, found as it stands
QUOTED = 'Qu0te"Login-77'               # one with a quote, found in the JSON form of a text: Qu0te\"Login-77
LATER = "L4ter-Login!9090"              # registered while a scrub runs
LOGINS_READ = "SELECT salt, hash, len FROM secrets"
STEP_KEYS = ("c-look", "a-fix", "b-check")      # in the order of their ids, which is not the order of the keys
FIVE = (("tasks", "tasks"), ("notes", "notes"), ("prompts", "permissions"), ("holds", "holds"), ("outcomes", "outcomes"))


def load_tests(loader, _tests, _pattern):
    """Only this file's checks: the harness comes from OwnerAPI, its own tests stay in its own file."""
    suite = unittest.TestSuite()
    for cls in (SameBytes, AfterTheLock, Reads, ScrubLogins, OtherCallers, OwnMoment, RealHub):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


def register(secret, salt):
    hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES(?,?,?,?,?)",
            (f"login {salt}", salt, hashlib.sha256((salt + secret).encode()).hexdigest(), len(secret), ""))


class Unkept:
    """hub.SCRUB that keeps nothing: each text's secret_key reads the logins again, as scrub did before this change."""
    key = None

    def __setattr__(self, name, value):
        pass


def each_part_alone():
    """The reads as they were before these changes: each text reads the logins; each item, goal, step of a plan, duty,
    wake-up rule, case and agent reads its own rows."""
    return [patch.object(hub, "SCRUB", Unkept()), patch.object(hub, "duty_case_parts", lambda cases: None),
            patch.object(hub, "need_reads", lambda: None), patch.object(hub, "goal_reads", lambda: None),
            patch.object(hub, "duty_reads", lambda: None), patch.object(hub, "agent_reads", lambda: None)]


class Watched:
    """A row of one of the five tables, which records in `made` whether its thread held the hub's lock when it became a
    dict: dict() reads keys() first."""
    def __init__(self, row, made):
        self.row, self.made = row, made

    def keys(self):
        self.made.append(hub.LOCK._is_owned())
        return self.row.keys()

    def __getitem__(self, key):
        return self.row[key]


class StateCase(OwnerAPI):
    def setUp(self):
        super().setUp()
        clock = patch.object(hub, "now", return_value=T0)
        clock.start()
        self.addCleanup(clock.stop)
        hub.TEAM["addresses"]["w1"] = "127.0.0.3"
        hub.TEAM["agents"]["mia"] = {"role": "worker", "runtime": "claude", "machine": "w1", "can": ["shell"],
                                     "title": "Customer Support", "reports_to": "manager"}
        hub.TEAM["chat_apps"] = {"wa1": {"app": "whatsapp", "label": "Shop phone", "agents": ["manager"],
                                         "enabled": True}}

    def run_with(self, patches, fn):
        for p in patches:
            p.start()
        try:
            return fn()
        finally:
            for p in reversed(patches):
                p.stop()

    def state_bytes(self):
        """The plain body of one GET /ui/state: no Accept-Encoding, so no compression."""
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=PATIENCE)
        try:
            conn.putrequest("GET", "/ui/state", skip_accept_encoding=True)
            conn.endheaders()
            answer = conn.getresponse()
            body = answer.read()
            self.assertEqual((answer.status, answer.getheader("Content-Encoding")), (200, None))
            return body
        finally:
            conn.close()

    def traced(self, fn):
        """fn(), and the SQL statements that the hub's connection ran during it, in their order."""
        seen = []
        hub.DB.set_trace_callback(seen.append)
        try:
            result = fn()
        finally:
            hub.DB.set_trace_callback(None)
        return result, seen

    # ---- a database with every part of the state
    def x(self, sql, args=()):
        return hub.DB.execute(sql, args).lastrowid

    def fill(self, open_cases=12, logins=True):
        """Rows in every part of the state, a registered login inside texts of each part, and a duty with closed,
        open and joined cases whose steps and tasks are mixed in id order across the cases."""
        if logins:
            register(LOGIN, "s1")
            register(QUOTED, "s2")
        hidden = f"the key is {LOGIN} now"
        with hub.LOCK:
            hub.touch("manager")
            hub.touch("mia")
            x = self.x
            for n in range(1, 9):
                x("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,created,started,what,attempt,"
                  "check_note) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                  (f"Task {n}", hidden if n == 2 else f"details of task {n} " * 9, "a test passes", "[]",
                   "mia", "manager", "completed" if n < 6 else "working", T0 - 900 * n, T0 - 800 * n,
                   json.dumps({"password": QUOTED}) if n == 3 else None, 1, None))
            x("INSERT INTO notes(task,agent,ts,text) VALUES(?,?,?,?)", (2, "mia", T0 - 50, hidden))
            x("INSERT INTO notes(task,agent,ts,text) VALUES(?,?,?,?)", (3, "mia", T0 - 40, "a plain note"))
            x("INSERT INTO prompts(task,agent,tool,input,key,created,kind) VALUES(?,?,?,?,?,?,?)",
              (6, "mia", "Bash", json.dumps({"command": f"echo {LOGIN}"}), "k1", T0 - 30, "tool"))
            hold = x("INSERT INTO holds(task,kind,by,note,state,created,attempt) VALUES(?,?,?,?,?,?,?)",
                     (6, "limit", "mia", "held for a limit", "held", T0 - 20, 1))
            x("INSERT INTO outcomes(task,attempt,hold,tool_call_id,title,kind,state,created,note) "
              "VALUES(?,?,?,?,?,?,?,?,?)", (6, 1, hold, "toolu_1", "a send", "send", "open", T0 - 20, hidden))
            for n in range(1, 4):
                need = x("INSERT INTO needs(title,why,todo,raised,by,options,kind,secret,details,multi,chose) "
                         "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                         (f"Item {n}", hidden if n == 1 else "the owner decides", "say yes", T0 - 600, "manager",
                          json.dumps(["Yes", "No"]) if n < 3 else None, "secret" if n == 3 else None,
                          json.dumps({"kind": "api_key", "env": "SHOP_API_KEY"}) if n == 3 else None,
                          "the long part" if n == 2 else None, 1 if n == 2 else 0, json.dumps([0, 1]) if n == 2 else None))
                x("INSERT INTO need_talk(need,ts,who,text,request_id) VALUES(?,?,?,?,?)",
                  (need, T0 - 500, "owner", hidden if n == 2 else "why this one?", f"talk-{n}"))
                if n == 1:
                    x("UPDATE needs SET door_call=? WHERE id=?", ("ef" * 32, need))
            x("INSERT INTO need_talk(need,ts,who,text,request_id) VALUES(?,?,?,?,?)",     # in id order, not ts order
              (1, T0 - 550, "manager", "because the export waits", "talk-4"))
            x("INSERT INTO needs(title,why,todo,raised,by) VALUES(?,?,?,?,?)",      # an item with no discussion
              ("Item 4", "a new item", "say yes", T0 - 100, "manager"))
            x("INSERT OR REPLACE INTO kv(k,v) VALUES(?,?)", ("fleet_id", "fleet-test-1"))
            x("INSERT INTO agent_usage(name,data) VALUES(?,?)",
              ("mia", json.dumps({"limits": {"windows": [{"label": "5h", "used_percent": 40}]}})))
            x("INSERT INTO agent_limits(agent,since,until,reset_known,task,cause) VALUES(?,?,?,?,?,?)",
              ("mia", T0 - 300, T0 + 3600, 1, 7, "usage"))
            for n in range(1, 5):
                event = x("INSERT INTO events(agent,kind,task,text,created,extra,read_at) VALUES(?,?,?,?,?,?,?)",
                          ("manager", "say", None, f"message {n}", T0 - 400 + n, "{}", T0 - 390 + n if n < 4 else None))
                x("INSERT INTO ui_requests(request_id,kind,text,event_id,created,client,recipient,edits,origin) "
                  "VALUES(?,?,?,?,?,?,?,?,?)",
                  (f"req-{n}", "message", hidden if n == 1 else f"hello {n}", event, T0 - 400 + n, "mac-app",
                   "manager", json.dumps([{"at": T0 - 100, "text": "before"}]) if n == 2 else None,
                   json.dumps({"app": "whatsapp", "account": "wa1", "chat": "c1"}) if n == 3 else None))
            x("INSERT INTO attachments(request_id,name,mime,size,sha256,created,client,message) VALUES(?,?,?,?,?,?,?,?)",
              ("file-1", "plan.pdf", "application/pdf", 1234, "ab" * 32, T0 - 399, "mac-app", "req-1"))
            for n in range(1, 4):
                report = x("INSERT INTO owner_reports(text,about,created,agent,in_reply_to,pushed,turn) "
                           "VALUES(?,?,?,?,?,?,?)",
                           (hidden if n == 2 else f"report {n}", "the export", T0 - 200 + n, "manager",
                            f"req-{n}", n % 2, "the hub's own"))
                x("INSERT INTO chat_out(kind,app,account,chat,text,state,created,updated,report,request_id) "
                  "VALUES(?,?,?,?,?,?,?,?,?,?)",
                  ("message", "whatsapp", "wa1", "c1", f"report {n}", "sent", T0 - 190, T0 - 180, report, f"out-{n}"))
            x("INSERT INTO owner_reports(text,about,created,agent,in_reply_to,pushed,turn) VALUES(?,?,?,?,?,?,?)",
              ("report 4", "the export", T0 - 150, "manager", None, 0, None))          # a report with no delivery
            x("INSERT INTO chat_status(account,state,at) VALUES(?,?,?)", ("wa1", "connected", T0 - 60))
            goal_event = x("INSERT INTO events(agent,kind,task,text,created,extra,read_at) VALUES(?,?,?,?,?,?,?)",
                           ("manager", "goal", None, "a goal", T0 - 1000, "{}", T0 - 990))
            goal = x("INSERT INTO goals(title,text,state,revision,limits,next_step,created,updated,event_id,"
                     "request_id,warned) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                     ("Sell more", hidden, "active", 2, json.dumps({"tokens": 1000000}), "write the plan",
                      T0 - 1000, T0 - 900, goal_event, "goal-1", 0))
            for n in (1, 2):
                x("INSERT INTO goal_steps(goal,n,text,task,state,created,updated) VALUES(?,?,?,?,?,?,?)",
                  (goal, n, f"step {n}", n, "done" if n == 1 else "open", T0 - 900, T0 - 800))
            x("UPDATE tasks SET goal_id=? WHERE id IN (1,2)", (goal,))
            x("INSERT INTO thread_events(task,attempt,session,seq,ts,type,data,created) VALUES(?,?,?,?,?,?,?,?)",
              (1, 1, "s1", 1, T0 - 850, "session", json.dumps({"session_id": "sid-1"}), T0 - 850))
            x("INSERT INTO session_tokens(agent,session_id,total,reported) VALUES(?,?,?,?)", ("mia", "sid-1", 4321, T0 - 840))
            x("INSERT INTO spends(goal,cents,currency,what,by,created) VALUES(?,?,?,?,?,?)",
              (goal, 250, "EUR", "an ad", "manager", T0 - 700))
            self.fill_plans(goal)
            self.fill_duties(open_cases, hidden)
            self.fill_agents()
            steer_event = x("INSERT INTO events(agent,kind,task,text,created,extra,read_at) VALUES(?,?,?,?,?,?,?)",
                            ("mia", "steer", 7, "a steer", T0 - 10, "{}", None))
            x("INSERT INTO steers(task,attempt,text,event_id,request_id,client,created) VALUES(?,?,?,?,?,?,?)",
              (7, 1, hidden, steer_event, "steer-1", "mac-app", T0 - 10))
            hub.commit()

    def fill_plans(self, goal):
        """Two more goals, and steps of the plans that are split across tasks (parts): the first goal's next step has
        an open part, so it stands; the parts of the second goal's next step have ended or have no state, which is not
        an open part, so that goal has no next step; the third goal's next step has no parts, so it stands. A task of
        the second goal was in a session of the first goal too, so both count that session's tokens."""
        x = self.x
        second, third = (x("INSERT INTO goals(title,text,state,revision,limits,next_step,created,updated,request_id,"
                           "warned) VALUES(?,?,?,?,?,?,?,?,?,?)", (title, f"the goal {title}", "active", 1, "{}", step,
                                                                  T0 - 800, T0 - 700, request, 0))
                         for title, step, request in (("Hire help", "find people", "goal-2"),
                                                      ("Plan the launch", "write the date", "goal-3")))
        steps = {key: x("INSERT INTO goal_steps(goal,n,text,task,state,created,updated) VALUES(?,?,?,?,?,?,?)",
                        (key[0], key[1], f"split step {key[1]}", None, "doing", T0 - 700, T0 - 600))
                 for key in ((second, 2), (goal, 3), (second, 1), (third, 1))}     # ids not in the order of n
        parts = ((goal, 3, "working"), (second, 1, "completed"), (goal, 3, "completed"), (second, 2, None),
                 (second, 2, "failed"), (second, 2, "canceled"))
        tasks = [x("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,created,goal_id,step,"
                   "attempt) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                   (f"part {n}", "a part of a split step", "it is done", "[]", "mia", "manager", state, T0 - 500 + n, g,
                    steps[g, step], 1))
                 for n, (g, step, state) in enumerate(parts)]
        for g, n in ((goal, 3), (second, 2), (third, 1)):
            x("UPDATE goals SET next_step_id=? WHERE id=?", (steps[g, n], g))
        for seq, sid in enumerate(("sid-1", "sid-2", "sid-2")):
            x("INSERT INTO thread_events(task,attempt,session,seq,ts,type,data,created) VALUES(?,?,?,?,?,?,?,?)",
              (tasks[1], 1, "s2", seq, T0 - 830, "session", json.dumps({"session_id": sid}), T0 - 830))
        x("INSERT INTO session_tokens(agent,session_id,total,reported) VALUES(?,?,?,?)",
          ("mia", "sid-2", 1000, T0 - 830))
        self.goals = (goal, second, third)

    def fill_agents(self):
        """Agents of each kind and the rows of each part of an agent's view: a lead whose machine reading is old, an
        inactive worker that has no agents row, an active one that has no row and no machine reading, a worker with a
        local model, one that its machine says is signed out, one with no key and one whose helper does not start its
        chat; an open limit newer than another one and an ended limit; sign-ins done and failed, of no runtime, of
        another step and of another kind; chat credentials live, revoked (a newer one), of another hub generation, two
        live ones (the hub writes one at most: here the newest decides) and a newer task one; turn ends: one that leaves
        out some read messages, one of an agent that a limit holds, and one in other letters. The two agents with a turn
        end that the reads decide have messages that they read before it."""
        x = self.x
        hub.TEAM["agents"].update({
            "leo": {"role": "lead", "runtime": "codex", "machine": "w1", "can": ["shell"], "title": "Developer",
                    "reports_to": "manager"},
            "ivy": {"role": "worker", "runtime": "claude", "machine": "w1", "can": [], "active": False},
            "oli": {"role": "worker", "runtime": "codex", "machine": "w1", "can": [], "start": "codex --oss {prompt}",
                    "reports_to": "leo"},
            "kai": {"role": "worker", "runtime": "claude", "machine": "w1", "can": []},
            "zoe": {"role": "worker", "runtime": "claude", "machine": "w1", "can": []},
            "eve": {"role": "worker", "runtime": "claude", "machine": "w1", "can": []}})     # no row, no reading
        x("UPDATE agents SET alive=? WHERE name='mia'", ("owner-chat",))
        for name, alive in (("leo", ""), ("oli", "owner-chat"), ("kai", None), ("zoe", "owner-chat")):
            x("INSERT INTO agents(name,last_seen,alive,alive_ts,client,client_seen) VALUES(?,?,?,?,?,?)",
              (name, T0 - 30, alive, T0 - 30, "fleet-helper", T0 - 30))
        x("INSERT INTO agent_usage(name,data) VALUES(?,?)", ("leo", json.dumps({"limits": {}})))
        x("INSERT INTO agent_limits(agent,since,until,reset_known,task,cause) VALUES(?,?,?,?,?,?)",
          ("mia", T0 - 100, T0 + 7200, 0, None, "usage"))           # newer than the one of fill(): the one shown
        x("INSERT INTO agent_limits(agent,since,until,reset_known,task,cause,ended) VALUES(?,?,?,?,?,?,?)",
          ("leo", T0 - 900, T0 - 600, 1, None, "usage", T0 - 600))
        for name, reported, data in (
                ("manager", T0 - 20, {"runtime": {"name": "claude", "signed_in": True}, "reading_age": 3}),
                ("mia", T0 - 100, {"features": ["agent_key", "chat_warm"], "runtimes": {"claude": {"signed_in": False}}}),
                ("leo", T0 - hub.MACHINE_STALE - 100, {"features": ["agent_key", "chat_warm"],
                                                       "runtimes": {"codex": {"signed_in": False}}}),
                ("oli", T0 - 10, {"features": ["chat_warm"], "runtimes": {"codex": {"signed_in": True}}}),
                ("kai", T0 - 50, {"features": ["agent_key", "chat_warm"], "runtimes": {"claude": {"signed_in": False}}}),
                ("zoe", T0 - 40, {"features": ["agent_key"], "runtimes": {"claude": {"signed_in": True}}})):
            x("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES(?,?,?)", (name, json.dumps(data), reported))
        for name, runtime, state, kind, step, at in (("mia", "claude", "done", "install", "sign_in", T0 - 50),
                                                     ("mia", "claude", "done", "prepare", "sign_in", T0 - 70),
                                                     ("mia", None, "done", "install", "sign_in", T0 - 1),
                                                     ("kai", "claude", "failed", "install", "sign_in", T0 - 5),
                                                     ("kai", "claude", "done", "install", "runtime", T0 - 2),
                                                     ("kai", "claude", "done", "remove", "sign_in", T0 - 3),
                                                     ("oli", "claude", "done", "install", "sign_in", T0 - 5)):
            x("INSERT INTO server_jobs(server,kind,agent,runtime,state,step,created,updated) VALUES(?,?,?,?,?,?,?,?)",
              ("box", kind, name, runtime, state, step, at, at))
        for name, runtime, state, at in (("leo", "codex", "done", T0 - 30), ("leo", "codex", "failed", T0 - 10),
                                         ("mia", "claude", "done", T0 - 400), ("kai", "claude", "failed", T0 - 20)):
            x("INSERT INTO signin_jobs(agent,runtime,state,created,updated) VALUES(?,?,?,?,?)",
              (name, runtime, state, at, at))
        for name in ("mia", "leo", "oli", "zoe"):
            x("INSERT INTO agent_keys(agent,sha256,created,source) VALUES(?,?,?,?)", (name, "cd" * 32, T0 - 5000, "enrolled"))
        for sha, name, kind, generation, created, revoked, ready in (
                ("c1", "mia", "chat", "test-generation", T0 - 150, T0 - 100, None),
                ("c2", "mia", "chat", "test-generation", T0 - 200, None, T0 - 190),
                ("c3", "oli", "chat", "an-older-generation", T0 - 20, None, T0 - 15),
                ("c4", "oli", "chat", "test-generation", T0 - 50, None, None),
                ("c5", "mia", "task", "test-generation", T0 - 10, None, T0 - 5),
                ("c6", "oli", "chat", "test-generation", T0 - 60, None, T0 - 55),
                ("c7", "oli", "task", "test-generation", T0 - 40, None, T0 - 35)):
            x("INSERT INTO session_credentials(sha256,agent,kind,generation,created,revoked,ready) VALUES(?,?,?,?,?,?,?)",
              (sha, name, kind, generation, created, revoked, ready))
        for key, value in (("turn_ended:manager", T0 - 388.5), ("turn_ended:mia", T0 - 5), ("TURN_ENDED:leo", T0 - 5)):
            x("INSERT OR REPLACE INTO kv(k,v) VALUES(?,?)", (key, str(value)))
        for name, created, read in (("leo", T0 - 100, T0 - 20), ("mia", T0 - 90, T0 - 30)):
            event = x("INSERT INTO events(agent,kind,task,text,created,extra,read_at) VALUES(?,?,?,?,?,?,?)",
                      (name, "say", None, f"a message to {name}", created, "{}", read))
            x("INSERT INTO ui_requests(request_id,kind,text,event_id,created,client,recipient) VALUES(?,?,?,?,?,?,?)",
              (f"req-{name}", "message", f"hello {name}", event, created, "mac-app", name))

    def fill_duties(self, open_cases, hidden):
        """Three duties. The first has 4 closed cases, then open_cases open ones (at least 4); its last case is open.
        The second has two closed cases only, and it joined three open cases of the first and a closed one. The third
        has no case and no wake-up rule. Steps and case tasks are written in turn across the cases, so the ids of one
        case's rows are not in a row. The rules: each duty's own, with runs, an ended one and one with no run, and one
        of no duty."""
        self.assertGreaterEqual(open_cases, 4)
        x = self.x
        duties = [x("INSERT INTO responsibilities(agent,text,state,revision,created,updated,created_by,request_id) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    ("mia", f"Answer every ticket {n}. Each day.", "active", 1, T0 - 5000, T0 - 4000, "manager",
                     f"duty-{n}")) for n in (1, 2)]
        duties.append(x("INSERT INTO responsibilities(agent,text,state,revision,created,updated,created_by,request_id) "
                        "VALUES(?,?,?,?,?,?,?,?)", ("mia", "Watch the backups.", "active", 1, T0 - 3000, T0 - 3000,
                                                    "manager", "duty-3")))         # a duty with no case and no rule
        rule = lambda n, duty, state, watch: x(
            "INSERT INTO triggers(agent,state,revision,schedule,check_spec,task,late_minutes,max_tasks_per_day,anchor,"
            "next_due,created,updated,request_id,failures,created_by,responsibility,watch) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("mia", state, 1, json.dumps({"every_minutes": 15}),
             json.dumps({"path": "checks/c.py", "sha256": "cd" * 32, "condition": {"op": "gt", "value": 0},
                         "repeat_minutes": 60}) if watch == "check" else None,
             json.dumps({"title": "look", "needs": ["shell"]}), 30, 24, T0 - 9000, T0 + 600, T0 - 9000,
             T0 - 9000, f"trig-{n}", 0, "manager", duty, watch))
        run = lambda trigger, due, state: x(
            "INSERT INTO trigger_runs(trigger_id,revision,due,manual,state,reason,created,check_now,attempts,value) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)", (trigger, 1, due, 0, state, "a value", due, 0, 1, 2.0))
        first = rule(0, duties[0], "active", "check")
        second = rule(1, duties[1], "active", "clock")
        run(first, T0 - 900, "done")
        run(second, T0 - 900, "done")
        # The newest run of a rule is its run of the highest id, not its latest due time.
        run(first, T0 - 600, "done")
        run(first, T0 - 1200, "failed")
        rule(2, duties[0], "deleted", "clock")           # a duty shows its ended rules too
        rule(3, duties[1], "paused", "clock")            # a rule with no run
        rule(4, None, "active", "clock")                 # an agent's own rule, of no duty
        run(rule(5, duties[0], "active", "check"), T0 - 300, "waiting")
        cases = []
        for k in range(4 + open_cases):
            is_open = k >= 4
            cases.append(x("INSERT INTO duty_cases(responsibility,key,title,source,state,opened,by,closed,closed_by,"
                           "outcome,note,repeated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                           (duties[0], f"check/1/{k}", f"case {k}", "watch", "open" if is_open else "closed",
                            T0 - 86400 * (40 - k), "hub", None if is_open else T0 - 86400 * (39 - k),
                            None if is_open else "mia", None if is_open else "handled", None, k % 3 == 0)))
        for n in (1, 2):                                # the second duty's cases: its last one is closed too
            cases.append(x("INSERT INTO duty_cases(responsibility,key,title,source,state,opened,by,closed,closed_by,"
                           "outcome,repeated) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                           (duties[1], f"clock/2/{n}", f"the second duty's case {n}", "watch", "closed",
                            T0 - 7200 * n, "hub", T0 - 3600 * n, "mia", "no_action", 0)))
        for turn in range(3):
            for case in cases:
                x("INSERT INTO duty_steps(duty_case,key,text,task,by,ts) VALUES(?,?,?,?,?,?)",
                  (case, STEP_KEYS[turn], hidden if (case, turn) == (cases[6], 1) else f"step {turn} of {case}",
                   None, "mia", T0 - 100 + turn))
        for case in cases[4::3]:
            x("UPDATE tasks SET responsibility=?, duty_case=? WHERE id=(SELECT MIN(id) FROM tasks WHERE duty_case IS "
              "NULL)", (duties[0], case))
        x("UPDATE tasks SET responsibility=?, duty_case=? WHERE id=8", (duties[0], cases[4]))
        for case in (cases[7], cases[5], cases[6], cases[0]):  # not in id order; the last one is closed: not joined
            x("INSERT INTO duty_joins(duty_case,responsibility,ts) VALUES(?,?,?)", (case, duties[1], T0 - 50))
        self.duties, self.cases = duties, cases


class SameBytes(StateCase):
    def test_the_state_is_the_same_bytes_as_with_each_part_read_alone(self):
        self.fill()
        body = self.state_bytes()
        self.assertEqual(self.state_bytes(), body)              # the clock stands still: a second read is the same
        alone = self.run_with(each_part_alone(), self.state_bytes)
        self.assertEqual(alone, body)
        state = json.loads(body)
        # Each part has its rows, and the logins are masked in every part: the two reads agree because both mask.
        for key in ("tasks", "notes", "permissions", "holds", "outcomes", "needs", "agents", "messages", "reports",
                    "goals", "responsibilities", "steers", "secrets"):
            self.assertTrue(state[key], key)
        self.assertNotIn(LOGIN, body.decode())
        self.assertNotIn("Qu0te", body.decode())
        self.assertEqual(body.decode().count(hub.MASK), 13)
        self.assertEqual(state["tasks"][2]["what"], hub.MASK)                      # found in its JSON form only
        duty = state["responsibilities"][0]
        self.assertEqual(len(duty["cases"]), 12)
        self.assertEqual(duty["cases"][2]["steps"][1]["text"], hub.MASK)
        self.assertEqual([s["key"] for s in duty["cases"][0]["steps"]], list(STEP_KEYS))
        self.assertEqual([t["id"] for t in duty["cases"][0]["tasks"]], [1, 8])
        self.assertEqual(duty["last_case"]["id"], self.cases[15])
        self.assertEqual([c["id"] for c in state["responsibilities"][1]["joined"]], self.cases[5:8])
        self.assertEqual((state["goals"][0]["tokens_used"], state["goals"][0]["tokens_measured_at"]), (4321, T0 - 840))
        self.assertEqual(state["messages"][0]["attachments"][0]["name"], "plan.pdf")
        self.assertEqual([m["attachments"] for m in state["messages"][1:]], [[]] * 5)
        self.assertEqual([(m["edited"], "edits" in m) for m in state["messages"][:3]],
                         [(None, False), (T0 - 100, False), (None, False)])
        self.assertEqual([m["origin"] for m in state["messages"][2:]],
                         [{"app": "whatsapp", "account": "wa1", "label": "Shop phone"}] + [None] * 3)
        self.assertEqual(list(state["agents"][0]), ["name", "role", "runtime", "title", "active", "can", "usage",
                                                    "reports_to", "direct_chat", "local_model", "signed_in",
                                                    "chat_ready", "placed", "turn_ended_after",
                                                    "chat_undelivered", "limit",
                                                    *hub.AGENT_SEEN])
        self.assertEqual(hub.AGENT_SEEN, ("last_seen", "alive", "alive_ts", "client", "client_seen"))
        self.assertEqual({tuple(a) for a in state["agents"]}, {tuple(state["agents"][0])})    # also with no agents row
        self.assertEqual(state["reports"][0]["delivery"]["state"], "sent")
        self.assertEqual([(r["pushed"], "turn" in r, r["delivery"] and r["delivery"]["outbound"])
                          for r in state["reports"]],
                         [(True, False, 1), (False, False, 2), (True, False, 3), (False, False, None)])
        # The five tables have no twin of before: their rows, in their order and with the logins masked, are the
        # database's own.
        for table, key in FIVE:
            self.assertEqual(state[key], hub.scrub([dict(r) for r in hub.q(f"SELECT * FROM {table} ORDER BY id")]), key)

    def test_the_five_tables_keep_their_place_in_the_answer(self):
        """Their rows become dicts after the lock, and each key keeps the place that it had before."""
        self.fill()
        keys = list(json.loads(self.state_bytes()))
        self.assertEqual(keys, ["schema_version", "db", "time", "token", "manager_flag", "manager_warning",
                                "ui_features", "repository", "tasks", "notes", "permissions", "holds", "outcomes",
                                "needs", "agents",
                                "messages", "reports", "chat_apps", "goals", "responsibilities", "steers", "secrets",
                                "knowledge"])

    def test_the_rows_of_the_five_tables_become_dicts_after_the_lock(self):
        """Each row of the five tables is made into a dict once, by the thread of the read, and never while that thread
        holds the hub's lock. The answer is the same bytes."""
        self.fill()
        body, real, made = self.state_bytes(), hub.q, []
        reads = {f"SELECT * FROM {table} ORDER BY id" for table, _ in FIVE}

        def q(sql, args=()):
            rows = real(sql, args)
            return [Watched(r, made) for r in rows] if sql in reads else rows
        with patch.object(hub, "q", q):
            self.assertEqual(self.state_bytes(), body)
        self.assertEqual(len(made), sum(hub.q1(f"SELECT COUNT(*) n FROM {table}")["n"] for table, _ in FIVE))
        self.assertEqual(set(made), {False})


class AfterTheLock(StateCase):
    def test_the_views_of_the_needs_and_the_duties_are_made_after_the_lock(self):
        """need_view and duty_view run for the state after the hub's lock, with the rows read in it, and read nothing
        themselves; the rows of the needs, the messages, their attachments and the reports become dicts after the lock
        too. The answer is the same bytes."""
        self.fill()
        body, made, views, statements, inside = self.state_bytes(), [], [], [], threading.local()
        sources = {"SELECT * FROM needs ORDER BY id", "SELECT * FROM owner_reports ORDER BY id",
                   "SELECT * FROM attachments WHERE message IS NOT NULL ORDER BY id",
                   "SELECT u.*,e.read_at FROM ui_requests u JOIN events e ON e.id=u.event_id ORDER BY u.created,"
                   "u.request_id"}
        real_q, real_q1 = hub.q, hub.q1

        def q(sql, args=()):
            if getattr(inside, "view", False):
                statements.append(sql)
            rows = real_q(sql, args)
            return [Watched(r, made) for r in rows] if sql in sources else rows

        def q1(sql, args=()):
            if getattr(inside, "view", False):
                statements.append(sql)
            return real_q1(sql, args)

        def watched(real):
            def view(*args, **kwargs):
                views.append(hub.LOCK._is_owned())
                inside.view = True
                try:
                    return real(*args, **kwargs)
                finally:
                    inside.view = False
            return view
        with patch.object(hub, "q", q), patch.object(hub, "q1", q1), \
                patch.object(hub, "need_view", watched(hub.need_view)), \
                patch.object(hub, "duty_view", watched(hub.duty_view)):
            self.assertEqual(self.state_bytes(), body)
        self.assertEqual(views, [False] * (4 + 3))         # 4 items, 3 duties
        self.assertEqual(statements, [])
        rows = sum(hub.q1(f"SELECT COUNT(*) n FROM {table}")["n"]
                   for table in ("needs", "owner_reports", "ui_requests", "attachments"))
        self.assertGreaterEqual(len(made), rows)
        self.assertEqual(set(made), {False})


class Reads(StateCase):
    def test_a_read_of_the_state_reads_the_logins_once(self):
        """Before this change scrub read them once for each text of the answer, and each read took the hub's lock."""
        self.fill()
        _, seen = self.traced(self.state_bytes)
        self.assertEqual(sum(s.startswith(LOGINS_READ) for s in seen), 1)
        _, before = self.traced(lambda: self.run_with(each_part_alone(), self.state_bytes))
        self.assertGreater(sum(s.startswith(LOGINS_READ) for s in before), 300)

    def test_a_read_with_no_registered_login_reads_the_logins_once(self):
        """No login is a set of logins too: an empty one, which this scrub read."""
        self.fill(logins=False)
        _, seen = self.traced(self.state_bytes)
        self.assertEqual(sum(s.startswith(LOGINS_READ) for s in seen), 1)

    def test_a_state_with_no_item_goal_or_duty_reads_none_of_their_tables(self):
        """With no item, no goal and no duty the state reads no discussion, part, token, case, rule, run or join, as
        before: what is read for all of them is read only when there is one."""
        self.assertFalse(hub.q("SELECT id FROM needs") or hub.q("SELECT id FROM goals") or
                         hub.q("SELECT id FROM responsibilities"))
        _, seen = self.traced(self.state_bytes)
        words = ("FROM need_talk", "FROM tasks WHERE step", "FROM session_tokens st JOIN", "FROM duty_cases",
                 "FROM triggers t", "FROM trigger_runs", "FROM duty_joins", "fleet_id")
        self.assertEqual([s for s in seen if any(w in s for w in words)], [])
        self.assertTrue([s for s in seen if "FROM goals" in s])

    def test_each_agent_view_is_the_same_with_the_rows_read_for_all(self):
        """agent_view gives the same view with what agent_reads read for all the agents as with its own reads, for each
        outcome of chat_ready, signed_in and turn_ended_after. With those reads the views read only the turn end of an
        agent that has one and no open limit, and the chat credentials once, at the first agent whose chat can be ready.
        Both are the new code: the proof against the code before this change is the same bytes of the state of the two
        copies of the first fleet's database."""
        self.fill()
        with hub.LOCK:
            team = list(hub.agents().items())
            own = [hub.agent_view(name, config) for name, config in team]
            reads, before = self.traced(hub.agent_reads)
            views, seen = self.traced(lambda: [hub.agent_view(name, config, reads) for name, config in team])
        self.assertEqual(views, own)
        # agents, usage, limits, machine readings, server sign-ins, sign-ins, keys, turn ends, late chat messages
        self.assertEqual(len([s for s in before if s.startswith("SELECT")]), 9)
        self.assertEqual(sorted(s.split(" WHERE")[0] for s in seen),
                         ["SELECT MAX(u.created) AS created FROM ui_requests u JOIN events e ON e.id=u.event_id",
                          "SELECT agent, ready FROM session_credentials", "SELECT v FROM kv"])
        by = {v["name"]: v for v in views}
        self.assertEqual({n: (v["chat_ready"], v["signed_in"], v["turn_ended_after"]) for n, v in by.items()},
                         {"manager": (None, True, T0 - 399), "mia": (True, True, None), "leo": (False, True, None),
                          "ivy": (None, None, None), "oli": (False, None, None), "kai": (None, False, None),
                          "zoe": (None, True, None), "eve": (None, None, None)})
        self.assertEqual((by["mia"]["limit"]["since"], by["leo"]["limit"], by["leo"]["usage"]), (T0 - 100, None, {"limits": {}}))
        self.assertEqual((by["ivy"]["alive"], by["ivy"]["last_seen"], by["oli"]["reports_to"]), (None, None, "leo"))

    def test_the_state_reads_the_agents_tables_once(self):
        """A read of the state reads each table of the agents' views once, where each agent read its own rows."""
        self.fill()
        _, seen = self.traced(self.state_bytes)
        _, before = self.traced(lambda: self.run_with(each_part_alone(), self.state_bytes))
        tables = ("agent_usage", "agent_limits", "machine_status", "server_jobs", "signin_jobs", "agent_keys",
                  "session_credentials", "kv WHERE k%turn_ended")
        count = lambda statements: {t: sum(bool(re.search("FROM " + t.replace("%", ".*"), s)) for s in statements)
                                    for t in tables}
        self.assertEqual(count(seen), dict.fromkeys(tables, 1))
        # Before, for the 8 agents: usage and turn end of each; an open limit of each, and again for the 2 with a turn
        # end; the machine reading of the 7 that have no local model, and again for the 6 that can have an owner chat;
        # the two kinds of sign-in of those 7; the key of the 4 whose helper starts its chat; the chat of the 2 with a
        # key whose chat window runs.
        self.assertEqual(count(before), {"agent_usage": 8, "agent_limits": 8 + 2, "machine_status": 7 + 6,
                                         "server_jobs": 7, "signin_jobs": 7, "agent_keys": 4,
                                         "session_credentials": 2, "kv WHERE k%turn_ended": 8})

    def test_the_goals_read_their_tokens_once(self):
        """One read for the tokens of all the goals, where each goal read its own; a goal reads them once for itself."""
        self.fill()
        _, seen = self.traced(self.state_bytes)
        self.assertEqual(sum("FROM session_tokens st JOIN" in s for s in seen), 1)
        _, before = self.traced(lambda: self.run_with(each_part_alone(), self.state_bytes))
        self.assertEqual(sum("FROM session_tokens st JOIN" in s for s in before), 3)
        state = json.loads(self.state_bytes())
        self.assertEqual([(g["tokens_used"], g["tokens_measured_at"]) for g in state["goals"]],
                         [(4321, T0 - 840), (5321, T0 - 830), (None, None)])   # the second counts the first's session

    def test_each_view_is_the_same_with_the_rows_read_for_all(self):
        """need_view, goal_view and duty_view give the same view with what need_reads, goal_reads and duty_reads read
        for all of them as with their own reads. Also: a discussion of two turns, a door call, a part with no state, a
        next step whose parts all ended, a session of two goals, a duty with no case and no rule, a rule with no run, a
        rule's newest run, an ended rule, an agent's own rule, a join of a closed case."""
        self.fill()
        with hub.LOCK:
            needs, goals, duties = (hub.q(f"SELECT * FROM {table} ORDER BY id")
                                    for table in ("needs", "goals", "responsibilities"))
            own = ([hub.need_view(r) for r in needs], [hub.goal_view(g) for g in goals],
                   [hub.duty_view(r, T0) for r in duties])
            reads, before = self.traced(lambda: (hub.need_reads(), hub.goal_reads(), hub.duty_reads()))
            (need_views, goal_views, duty_views), seen = self.traced(lambda: (
                [hub.need_view(r, reads[0]) for r in needs], [hub.goal_view(g, reads[1]) for g in goals],
                [hub.duty_view(r, T0, reads[2]) for r in duties]))
            goal_reads = self.traced(lambda: [hub.goal_view(g, reads[1]) for g in goals])[1]
        self.assertEqual((need_views, goal_views, duty_views), own)
        # The discussions and the fleet's id; the tokens and the parts of the steps; the cases twice, the joins, the
        # rules and their runs, and the steps and the tasks of the cases.
        self.assertEqual(len([s for s in before if s.startswith("SELECT")]), 2 + 2 + 5 + 2)
        self.assertEqual(len(seen), len(goal_reads))          # the needs and the duties read nothing more
        self.assertFalse([s for s in goal_reads if "session_tokens" in s or "FROM tasks WHERE step" in s])
        self.assertEqual([t["text"] for t in need_views[0]["talk"]], ["why this one?", "because the export waits"])
        self.assertEqual((need_views[0]["door_fleet"], need_views[1]["door_fleet"]), ("fleet-test-1", None))
        self.assertEqual(need_views[3]["talk"], [])
        first, second, third = goal_views
        self.assertEqual((first["next_step"]["text"], second["next_step"], third["next_step"]["text"]),
                         ("write the plan", None, "write the date"))
        self.assertEqual([[p["state"] for p in step["parts"]] for step in second["plan"]],
                         [["completed"], [None, "failed", "canceled"]])
        self.assertEqual([p["state"] for p in first["plan"][2]["parts"]], ["working", "completed"])
        self.assertEqual(third["plan"][0]["parts"], [])
        one, two, three = duty_views
        self.assertEqual([(w["state"], w["last_run"] and w["last_run"]["created"]) for w in one["watch"]],
                         [("active", T0 - 1200), ("deleted", None), ("active", T0 - 300)])
        self.assertEqual([(w["state"], w["last_run"]) for w in two["watch"]][1], ("paused", None))
        self.assertEqual([c["id"] for c in two["joined"]], self.cases[5:8])
        self.assertEqual(two["last_case"]["state"], "closed")
        self.assertEqual((three["watch"], three["cases"], three["joined"], three["last_case"], three["cases_30d"]),
                         ([], [], [], None, 0))
        # Case k of 16 opened 40 - k days ago, and it repeated when k % 3 == 0; 12 are open.
        self.assertEqual((one["open_cases"], one["cases_30d"], one["repeats_30d"], one["cases_prev_30d"],
                          one["repeats_prev_30d"]), (12, 5, 2, 11, 4))

    def test_the_state_reads_each_table_once_for_all_its_items(self):
        """A read of the state reads the discussions of the items, the parts of the steps, and the cases, the rules
        and the runs of the duties once for all of them, where each item, step, duty and rule read its own."""
        self.fill()
        _, seen = self.traced(self.state_bytes)
        _, before = self.traced(lambda: self.run_with(each_part_alone(), self.state_bytes))
        reads = {"discussions": lambda s: "FROM need_talk" in s,
                 "parts of steps": lambda s: "FROM tasks WHERE step" in s, "cases": lambda s: "FROM duty_cases " in s,
                 "runs": lambda s: "FROM trigger_runs" in s,
                 "rules": lambda s: s.startswith("SELECT * FROM triggers ") and "responsibility" in s,
                 "joins": lambda s: "FROM duty_joins" in s}
        count = lambda statements: {what: sum(map(read, statements)) for what, read in reads.items()}
        self.assertEqual(count(seen), {"discussions": 1, "parts of steps": 1, "cases": 2, "rules": 1, "runs": 1,
                                       "joins": 1})
        # Before: each of 4 items; each of 6 steps, and the next step of 3 goals (its parts, and its open parts when it
        # has parts); each of 3 duties; each of the 5 rules of the duties.
        self.assertEqual(count(before), {"discussions": 4, "parts of steps": 6 + 2 + 2 + 1, "cases": 3, "rules": 3,
                                         "runs": 5, "joins": 3})

    def test_duty_view_reads_the_steps_and_the_tasks_of_its_cases_at_once(self):
        self.fill(open_cases=30)
        with hub.LOCK:
            rows = hub.q("SELECT * FROM responsibilities ORDER BY id")
            views, seen = self.traced(lambda: [hub.duty_view(r) for r in rows])
            alone, before = self.traced(lambda: self.run_with(each_part_alone(), lambda: [hub.duty_view(r) for r in rows]))
            with patch.object(hub, "DUTY_PARTS_CHUNK", 7):
                parts, chunked = self.traced(lambda: [hub.duty_view(r) for r in rows])
        self.assertEqual(views, alone)
        self.assertEqual(parts, views)
        self.assertEqual(len(views[0]["cases"]), 30)
        steps_reads = lambda statements: sum("FROM duty_steps" in s for s in statements)
        self.assertEqual(steps_reads(seen), 2)                  # one for each duty
        self.assertEqual(sum("FROM tasks WHERE duty_case" in s for s in seen), 2)
        self.assertEqual(steps_reads(before), 30 + 1 + 1 + 3)   # each case alone: the open ones, each last case, joined
        self.assertEqual(steps_reads(chunked), 5 + 1)           # 30 open cases (the last one among them) by 7, and 4

    def test_a_case_alone_reads_its_own_parts_as_before(self):
        """duty_case_view without parts, as the page of one duty calls it, and with parts that do not hold its case:
        it reads its own steps and tasks, and never shows a case with none because a caller left it out of the read."""
        self.fill(open_cases=4)
        with hub.LOCK:
            case, other = (hub.q1("SELECT * FROM duty_cases WHERE id=?", (c,)) for c in (self.cases[4], self.cases[5]))
            one, seen = self.traced(lambda: hub.duty_case_view(case))
            many = hub.duty_case_view(case, hub.duty_case_parts([case]))
            outside, read = self.traced(lambda: hub.duty_case_view(case, hub.duty_case_parts([other])))
        self.assertEqual(many, one)
        self.assertEqual(outside, one)
        self.assertEqual([s["key"] for s in one["steps"]], list(STEP_KEYS))
        self.assertEqual([t["id"] for t in one["tasks"]], [1, 8])
        self.assertEqual(sum("FROM duty_steps WHERE duty_case IN" in s for s in seen), 1)
        self.assertEqual(sum("FROM duty_steps WHERE duty_case IN" in s for s in read), 2)     # the other's, then its own


class ScrubLogins(StateCase):
    def test_the_logins_of_one_scrub_are_its_own(self):
        """One scrub reads the logins once, and only its own thread's secret_key gives them, only while it runs: another
        thread reads the table, and so does the next scrub. A login registered while a scrub runs is masked from the
        next one on."""
        register(LOGIN, "s1")
        seen, real = {}, hub.secret_hit

        def hit(*texts):
            if not seen:
                register(LATER, "s3")
                other = threading.Thread(target=lambda: seen.update(other=hub.secret_key()))
                other.start()
                other.join()
                seen["own"] = hub.secret_key()
            return real(*texts)
        value = {"a": [f"x {LOGIN} y", f"x {LATER} y"], "b": 7, "c": None, "d": {"e": f"{LOGIN}"}}
        with patch.object(hub, "secret_hit", hit):
            first = hub.scrub(value)
        self.assertEqual(len(seen["own"]), 1)
        self.assertEqual(len(seen["other"]), 2)
        self.assertEqual(first, {"a": [hub.MASK, f"x {LATER} y"], "b": 7, "c": None, "d": {"e": hub.MASK}})
        self.assertIsNone(getattr(hub.SCRUB, "key", None))
        self.assertEqual(len(hub.secret_key()), 2)
        self.assertEqual(hub.scrub(value), {"a": [hub.MASK, hub.MASK], "b": 7, "c": None, "d": {"e": hub.MASK}})

    def test_a_scrub_that_fails_keeps_no_logins(self):
        register(LOGIN, "s1")

        def broken(*texts):
            raise RuntimeError("a check that fails")
        with patch.object(hub, "secret_hit", broken), self.assertRaises(RuntimeError):
            hub.scrub({"a": "some text"})
        self.assertIsNone(getattr(hub.SCRUB, "key", None))
        register(LATER, "s3")
        self.assertEqual(hub.scrub([LATER]), [hub.MASK])

    def test_scrub_answers_as_each_text_alone(self):
        """The same answer as scrub with each text's own read of the logins, for texts, numbers, lists and dicts, also
        when no login is registered: a value of its own, never the one that it was given."""
        value = {"a": [f"the key is {LOGIN}", "short", 3, 2.5, None, True, ["x", {"y": f"({LOGIN}),"}]],
                 "b": json.dumps({"p": QUOTED}), "c": {"d": "nothing here"}}
        none = hub.scrub(value)
        self.assertEqual(none, value)
        self.assertIsNot(none, value)
        self.assertIsNot(none["a"], value["a"])
        register(LOGIN, "s1")
        register(QUOTED, "s2")
        scrubbed = hub.scrub(value)
        self.assertEqual(scrubbed, self.run_with(each_part_alone(), lambda: hub.scrub(value)))
        self.assertEqual(scrubbed, {"a": [hub.MASK, "short", 3, 2.5, None, True, ["x", {"y": hub.MASK}]],
                                    "b": hub.MASK, "c": {"d": "nothing here"}})



def json_value(rng, depth=0):
    """One value that json.dumps writes: texts with quotes, escapes and letters outside ASCII, numbers of each kind, and
    lists, tuples and dicts, with keys that are and keys that are not texts."""
    kind = rng.randrange(10 if depth < 3 else 6)
    if kind == 0:
        return rng.choice([None, True, False])
    if kind == 1:
        return rng.choice([0, -1, 7, 2 ** 70, -(2 ** 53) - 1])
    if kind == 2:
        return rng.choice([0.0, -0.0, 1.5, 1e300, -2.5e-308, float("inf"), float("-inf"), 3.141592653589793])
    if kind in (3, 4, 5):
        return "".join(rng.choice(['a', 'Z', ' ', '"', '\\', '/', '\n', '\t', '\x00', '\x1f', 'é', '€', '😀', 'ß', '{', '}'])
                       for _ in range(rng.randrange(12)))
    if kind == 6:
        return [json_value(rng, depth + 1) for _ in range(rng.choice([0, 1, 3, 31, 32, 33, 64, 65]))]
    if kind == 7:
        return tuple(json_value(rng, depth + 1) for _ in range(rng.randrange(4)))
    if kind == 8:
        return {json_value(rng, 5) if rng.random() < 0.1 and depth else rng.choice(["k", "ké", 'q"', "", "a b"]) + str(n):
                json_value(rng, depth + 1) for n in range(rng.randrange(6))}
    return {rng.choice([1, 2.5, True, None, "k"]): json_value(rng, depth + 1) for _ in range(rng.randrange(1, 4))}


class OtherCallers(StateCase):
    def test_the_state_written_in_parts_is_the_same_bytes_as_json_dumps(self):
        """json_text writes the state's answer in parts, and no other answer. The bytes are those of json.dumps, also
        when each list goes in parts of 3 items (the state of fill() has no list longer than JSON_SLICE)."""
        self.fill()
        written, real = [], hub.json_text

        def json_text(obj):
            written.append(obj)
            return real(obj)
        with patch.object(hub, "json_text", json_text):
            body = self.state_bytes()
            self.assertEqual(self.request("/ui/health?db=another")[0], 409)        # an answer of another route
        self.assertEqual([list(x)[:2] for x in written], [["schema_version", "db"]])
        with patch.object(hub, "json_text", json.dumps):
            self.assertEqual(self.state_bytes(), body)
        with patch.object(hub, "JSON_SLICE", 3):
            self.assertEqual(self.state_bytes(), body)

    def test_json_text_writes_in_parts(self):
        """No part of json_text writes a long list whole, or more than one slice of it; a dict of up to JSON_KEYS_MOST
        keys goes one key at a time, and one with more goes whole, with one json.dumps."""
        self.assertLessEqual(hub.JSON_SLICE, 64)
        rows = [f"row {n} of the list" for n in range(100)]
        widest = max(len(json.dumps(rows[at:at + hub.JSON_SLICE])) for at in range(0, len(rows), hub.JSON_SLICE))
        calls, real, me = [], json.dumps, threading.get_ident()

        def dumps(obj, *args, **kwargs):
            text = real(obj, *args, **kwargs)
            if threading.get_ident() == me:      # the test's own thread only
                calls.append(len(text))
            return text
        for value, most, least in (({"rows": rows, "n": 1}, widest, 4), ({f"k{n}": n for n in range(hub.JSON_KEYS_MOST)}, 10, 128),
                                   ({f"k{n}": n for n in range(hub.JSON_KEYS_MOST + 1)}, None, 1)):
            calls.clear()
            with patch.object(hub.json, "dumps", dumps):
                text = hub.json_text(value)
            self.assertEqual(text, real(value))
            if most is None:
                self.assertEqual(calls, [len(text)])
            else:
                self.assertLessEqual(max(calls), most)
                self.assertLess(max(calls), len(real(rows)))
                self.assertGreaterEqual(len(calls), least)

    def test_json_text_reads_its_items_once(self):
        """Another thread can run between two parts. json_text reads the dict's items before the first part, and each
        long list before its first slice: a change of the list after its first slice is not in the text, nor a key added
        after the first part. (No other thread changes an InParts answer anyway: scrub made its dicts and lists.)"""
        rows = list(range(100))
        value = hub.InParts(rows=rows, n=1)
        snapshot, real, changed, me = json.dumps(value), json.dumps, [], threading.get_ident()

        def dumps(obj, *args, **kwargs):
            text = real(obj, *args, **kwargs)
            if not changed and threading.get_ident() == me:     # as another thread would, after the first part
                changed.append(1)
                rows[50] = -1
                value["late"] = 2
            return text
        with patch.object(hub.json, "dumps", dumps):
            self.assertEqual(hub.json_text(value), snapshot)

    def test_json_text_gives_the_error_of_json_dumps(self):
        """The same type, words and notes (Python 3.14 adds notes that name the item), and no other error chained."""
        for bad in ({"a": [1] * 40 + [object()]}, {"a": {1}}, {"b": 1, "a": [{"c": object()}] * 33}):
            with self.assertRaises(TypeError) as ours:
                hub.json_text(bad)
            with self.assertRaises(TypeError) as theirs:
                json.dumps(bad)
            self.assertEqual((str(ours.exception), getattr(ours.exception, "__notes__", None)),
                             (str(theirs.exception), getattr(theirs.exception, "__notes__", None)))
            self.assertIsNone(ours.exception.__context__)
        bad, calls, real, me = hub.InParts(b=1, a=[1] * 40 + [object()]), [], json.dumps, threading.get_ident()

        def dumps(obj, *args, **kwargs):
            if threading.get_ident() == me:      # the test's own thread only
                calls.append(obj)
            return real(obj, *args, **kwargs)
        with patch.object(hub.json, "dumps", dumps), self.assertRaises(TypeError):
            hub.json_text(bad)
        self.assertIs(calls[-1], bad)           # the whole value once more, after the part that failed
        loop = {"a": []}
        loop["a"].append(loop)
        with self.assertRaises(ValueError):
            hub.json_text(loop)

    def test_json_text_is_json_dumps(self):
        rng = random.Random(20261111)
        values = [{}, [], "x", 1, None, {"a": []}, {"a": list(range(31))}, {"a": list(range(32))},
                  {"a": list(range(33))}, {"a": list(range(65))}, {1: "x"}, {"a": (1, 2)}, {"a": {"b": list(range(99))}},
                  {"": ""}, {"é": ["😀"] * 40}, {"a": [float("nan")] * 34}]
        values += [json_value(rng) for _ in range(400)]
        values += [dict(top=json_value(rng), rows=[json_value(rng) for _ in range(rng.randrange(100))]) for _ in range(100)]
        for value in values:
            text = json.dumps(value)
            self.assertEqual(hub.json_text(value), text, text[:200])
            with patch.object(hub, "JSON_SLICE", 2):
                self.assertEqual(hub.json_text(value), text, text[:200])

    def test_scrub_keeps_all_the_texts_of_a_state_of_more_than_8192(self):
        """Each read of the state asks for the same texts in the same order. A cache that holds fewer of them than the
        state has keeps none that the next read asks for: every read searched every text again. The live state had
        3,751 different texts on 11 November 2026 and grows each day, and a copy with 2.3 times its rows had 10,400, so
        scrub()'s own cache keeps 65,536. The general cache, which the guard of each tool call fills with texts that
        come once each, keeps 8,192 as before, and a read of the state adds nothing to it."""
        register(LOGIN, "s1")
        with hub.LOCK:
            hub.DB.executemany("INSERT INTO notes(task,agent,ts,text) VALUES(?,?,?,?)",
                               [(None, "manager", T0 - n, f"note {n:05d} about the export") for n in range(9000)])
            hub.commit()
        general = hub._secret_spans.cache_info().currsize

        def misses(cache):
            with patch.object(hub, "_scrub_spans", cache):
                self.state_bytes()
                before = cache.cache_info().misses
                self.state_bytes()
                return cache.cache_info().misses - before, cache.cache_info().currsize
        again, kept = misses(functools.lru_cache(maxsize=hub.SCRUB_SPANS_KEPT)(hub.find_secret_spans))
        self.assertEqual(again, 0)
        self.assertGreater(kept, 9000)
        old, _ = misses(functools.lru_cache(maxsize=8192)(hub.find_secret_spans))
        self.assertGreater(old, 9000)
        self.assertEqual(hub._secret_spans.cache_info().currsize, general)
        self.assertEqual((hub._scrub_spans.cache_info().maxsize, hub._secret_spans.cache_info().maxsize),
                         (hub.SCRUB_SPANS_KEPT, hub.SECRET_SPANS_KEPT))
        self.assertGreaterEqual(hub.SCRUB_SPANS_KEPT, 65536)
        self.assertEqual(hub.SECRET_SPANS_KEPT, 8192)

    def test_the_hub_sets_its_switch_interval(self):
        """main() calls sys.setswitchinterval(SWITCH_INTERVAL) as a statement of its own, not in a branch, before it
        starts its threads and its server, and the value is shorter than Python's own 0.005 without so short that the
        threads would switch all the time."""
        body = ast.parse(textwrap.dedent(inspect.getsource(hub.main))).body[0].body
        at = [n for n, step in enumerate(body) if isinstance(step, ast.Expr)
              and ast.unparse(step.value) == "sys.setswitchinterval(SWITCH_INTERVAL)"]
        starts = [n for n, step in enumerate(body)
                  if any(word in ast.unparse(step) for word in ("threading.Thread(", "HubServer(", "serve_forever("))]
        self.assertEqual(len(at), 1)
        self.assertTrue(starts)
        self.assertLess(at[0], min(starts))
        self.assertTrue(0.0005 <= hub.SWITCH_INTERVAL <= 0.002, hub.SWITCH_INTERVAL)

    def test_a_long_text_goes_to_the_general_cache(self):
        """scrub()'s own cache keeps texts of up to SCRUB_TEXT_MOST characters. A longer one (the state holds the whole
        input of each permission prompt) goes to the general cache, as every text went before, and the next read finds
        it there. Outside a scrub every text goes to the general cache, whatever its length, as before."""
        register(LOGIN, "s1")
        long = "word " * (hub.SCRUB_TEXT_MOST // 5) + LOGIN
        edge = ("x" * hub.SCRUB_TEXT_MOST)[:hub.SCRUB_TEXT_MOST - len(LOGIN) - 1] + " " + LOGIN
        self.assertEqual((len(long) > hub.SCRUB_TEXT_MOST, len(edge)), (True, hub.SCRUB_TEXT_MOST))
        info = lambda: (hub._secret_spans.cache_info(), hub._scrub_spans.cache_info())
        general, own = info()
        self.assertEqual(hub.scrub([long, long]), [hub.MASK, hub.MASK])
        self.assertEqual(hub.scrub([long]), [hub.MASK])
        general2, own2 = info()
        self.assertEqual((general2.currsize, general2.misses, own2.currsize),
                         (general.currsize + 1, general.misses + 1, own.currsize))
        self.assertEqual(hub.scrub([edge]), [hub.MASK])
        general3, own3 = info()
        self.assertEqual((general3.currsize, own3.currsize), (general2.currsize, own2.currsize + 1))
        huge = "word " * 10000 + LOGIN          # 50,005 characters outside a scrub: kept, as before
        self.assertTrue(hub.secret_hit(huge) and hub.secret_hit(huge))
        general4, _ = info()
        self.assertEqual((general4.currsize, general4.misses), (general3.currsize + 1, general3.misses + 1))

    def test_a_short_text_is_not_looked_up(self):
        """The search finds nothing in a text shorter than SECRET_TEXT_LEAST, and json_plain makes no text longer:
        secret_hit gives what it gave before, and does not look such a text up."""
        short = "Ab3$efgh"                  # a login of 8 characters: the search finds it in a text of 8 or more
        register(short, "s9")
        key = hub.secret_key()
        sizes = lambda: (hub._secret_spans.cache_info().currsize, hub._scrub_spans.cache_info().currsize)
        before = sizes()
        for text in ("", "Ab3$efg", "b3$efgh", "\\u0041b", "Ab3\\$ef", "x" * 7):
            self.assertFalse(hub.secret_hit(text), text)
            self.assertEqual(hub.scrub([text]), [text])
        self.assertEqual(sizes(), before)
        for text in (short, "xAb3$efgh", "Ab3$efgh!", "\\u0041b3$efgh", "1234567", "12345678", "a Ab3$efgh b"):
            old = bool(hub.find_secret_spans(text, key)) or ("\\" in text and bool(hub.find_secret_spans(hub.json_plain(text), key)))
            self.assertEqual(hub.secret_hit(text), old, text)
        self.assertTrue(hub.secret_hit(short) and hub.secret_hit("\\u0041b3$efgh"))

    def test_one_limit_for_short_texts(self):
        """SECRET_TEXT_LEAST is the one limit of the search and of secret_hit: with a lower one, both find a login of
        6 characters in a text of 6."""
        register("Ab3$ef", "s6")
        self.addCleanup(hub._secret_spans.cache_clear)
        hub._secret_spans.cache_clear()
        self.assertFalse(hub.secret_hit("Ab3$ef"))          # as it always was: nothing is found in 6 characters
        with patch.object(hub, "SECRET_TEXT_LEAST", 6):
            hub._secret_spans.cache_clear()
            self.assertTrue(hub.secret_hit("Ab3$ef"))
            self.assertEqual(hub.secret_spans("Ab3$ef"), [(0, 6)])


class OwnMoment(StateCase):
    """The state from its own moment of the records, as main() opens them: in WAL mode, with read connections of their
    own (hub.wal_on, hub.readers_for, hub.state_moment)."""

    def setUp(self):
        super().setUp()
        self.assertEqual(hub.wal_on(), (True, None))
        self.assertEqual(hub.DB.execute("PRAGMA journal_size_limit").fetchone()[0], hub.WAL_MOST)
        hub.readers_for(self.path)
        self.addCleanup(hub.readers_for, None)

    def statements(self, fn):
        """fn(), and each statement that the hub's connection and its read connections ran meanwhile, in their order:
        (the statement, whether its thread held the hub's lock)."""
        seen, real_reader, real_back = [], hub.reader, hub.reader_back

        def trace(sql):
            seen.append((sql, hub.LOCK._is_owned()))

        def reader():
            got = real_reader()
            if got is not None:
                got[0].set_trace_callback(trace)
            return got

        def reader_back(conn, turn):
            conn.set_trace_callback(None)
            real_back(conn, turn)
        hub.DB.set_trace_callback(trace)
        try:
            with patch.object(hub, "reader", reader), patch.object(hub, "reader_back", reader_back):
                return fn(), seen
        finally:
            hub.DB.set_trace_callback(None)

    def test_the_state_of_its_own_moment_is_the_same_bytes_and_statements_as_under_the_lock(self):
        """The state read from its own connection is the same bytes as the state read under the lock, with the same
        statements in the same order, for a fleet with nothing yet and for one with every part. Of its reads only the
        start of its read transaction holds the lock (the moment), where the read under the lock holds it for all."""
        for full in (False, True):
            with self.subTest(full=full):
                if full:
                    self.fill()
                hub.readers_for(self.path)
                own, seen = self.statements(self.state_bytes)
                hub.readers_for(None)
                locked, before = self.statements(self.state_bytes)
                self.assertEqual(own, locked)
                start, end = seen.index(("BEGIN", True)), seen.index(("ROLLBACK", False))
                self.assertEqual(seen[start + 1], ("SELECT count(*) FROM sqlite_master", True))
                build = seen[start + 2:end]
                self.assertEqual([s for s, _ in seen[:start] + build + seen[end + 1:]], [s for s, _ in before])
                self.assertGreater(len(build), 40 if full else 15)
                self.assertEqual({held for _, held in build}, {False})
                self.assertEqual({held for _, held in before[start:start + len(build)]}, {True})
                self.assertIn(("SELECT * FROM tasks ORDER BY id", False), build)
                self.assertEqual(seen[end + 1:], before[start + len(build):])       # scrub reads the logins, as before

    def test_a_writer_does_not_wait_for_a_read_of_the_state_and_is_not_in_it(self):
        """Two writers come during a read of the state: the first as soon as its moment lets the lock go, and the second
        at the build's first statement, while the build waits for it. Neither waits for the read. The state is the one
        of its moment: without their rows, with the team, the token and the time of before them. The second writer's
        thread reads its own row meanwhile and has no moment: SNAP is each thread's own. A login registered after the
        moment is masked all the same, because scrub reads the logins after the build. The next read has it all, and
        an app that waits with the token of the first read reads again at once."""
        self.fill()
        hub.q("UPDATE tasks SET details=? WHERE id=1", (f"the new key is {LATER}",))
        clock, seen, real_reader, real_back = {"at": T0}, {}, hub.reader, hub.reader_back
        hub.now.side_effect = lambda: clock["at"]

        def first():                            # as an owner command writes: rows, and the team that goes with them
            hub.ins("INSERT INTO needs(title,why,todo,raised,by) VALUES(?,?,?,?,?)",
                    ("Item 5", "it came during the read", "say yes", T0, "manager"))
            hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES(?,?,?,?,?)",
                    ("Task 9", "mia", "manager", "working", T0))
            register(LATER, "s3")
            with hub.LOCK:
                hub.TEAM.update(agents=dict(hub.TEAM["agents"], uma={"role": "worker", "runtime": "codex",
                                                                    "machine": "w1", "can": []}),
                                chat_apps={"wa1": dict(hub.TEAM["chat_apps"]["wa1"], label="New phone")})
                hub.changed()
            clock["at"] = T0 + 7
            seen["token"] = hub.change_token()

        def second():
            seen["its moment"] = hub.SNAP.conn
            hub.ins("INSERT INTO needs(title,why,todo,raised,by) VALUES(?,?,?,?,?)",
                    ("Item 6", "it came during the build", "say yes", T0, "manager"))
            seen["its rows"] = [r["title"] for r in hub.q("SELECT title FROM needs WHERE title='Item 6'")]

        def run(writer, name):
            thread = threading.Thread(target=writer)
            thread.start()
            thread.join(PATIENCE)
            seen[name] = thread.is_alive()      # it still waits: for the lock, which the read holds

        class Landing:
            """hub.LOCK, which lets the first writer in as soon as the read's moment lets it go."""
            def __init__(self, lock):
                self.lock = lock

            def acquire(self, *args, **kwargs):
                return self.lock.acquire(*args, **kwargs)

            def release(self):
                self.lock.release()
                if seen.get("moment") == threading.get_ident() and not self.lock._is_owned():
                    seen["moment"], seen["moment's token"] = None, hub.change_token()
                    run(first, "first waited")

            __enter__ = acquire

            def __exit__(self, *exc):
                self.release()

            def _is_owned(self):
                return self.lock._is_owned()

        def trace(sql):
            if sql == "SELECT count(*) FROM sqlite_master" and "first waited" not in seen:
                seen["moment"] = threading.get_ident()
            elif sql not in ("BEGIN", "ROLLBACK") and "first waited" in seen and "second waited" not in seen:
                run(second, "second waited")

        def reader():
            got = real_reader()
            if got is not None:
                got[0].set_trace_callback(trace)
            return got

        def reader_back(conn, turn):
            conn.set_trace_callback(None)
            real_back(conn, turn)
        with patch.object(hub, "LOCK", Landing(hub.LOCK)), patch.object(hub, "reader", reader), \
                patch.object(hub, "reader_back", reader_back):
            body = self.state_bytes()
        state, team = json.loads(body), list(hub.TEAM["agents"])
        self.assertEqual((seen["first waited"], seen["second waited"]), (False, False))
        self.assertEqual((seen["its moment"], seen["its rows"]), (None, ["Item 6"]))
        self.assertEqual([n["title"] for n in state["needs"]], ["Item 1", "Item 2", "Item 3", "Item 4"])
        self.assertNotIn("Task 9", [t["title"] for t in state["tasks"]])
        self.assertEqual([a["name"] for a in state["agents"]], [name for name in team if name != "uma"])
        self.assertEqual(state["messages"][2]["origin"]["label"], "Shop phone")
        self.assertEqual((state["time"], state["token"]), (T0, seen["moment's token"]))
        self.assertNotEqual(state["token"], seen["token"])
        self.assertEqual(state["tasks"][0]["details"], hub.MASK)
        self.assertNotIn(LATER, body.decode())
        self.assertEqual(self.request(f"/ui/wait?db=test-generation&since={state['token']}&wait=5"),
                         (200, {"db": "test-generation", "token": hub.change_token()}))
        then = json.loads(self.state_bytes())
        self.assertEqual([n["title"] for n in then["needs"]][4:], ["Item 5", "Item 6"])
        self.assertIn("Task 9", [t["title"] for t in then["tasks"]])
        self.assertEqual([a["name"] for a in then["agents"]], team)
        self.assertEqual(team[-1], "uma")
        self.assertEqual(then["messages"][2]["origin"]["label"], "New phone")
        self.assertEqual((then["token"], then["time"]), (hub.change_token(), T0 + 7))

    def test_the_moment_takes_the_token_the_time_and_the_team_under_the_lock(self):
        """No writer can come between the start of the read transaction and these three: each one is taken while the
        lock is held, and the team is copied."""
        held, real_token = [], hub.change_token
        hub.now.side_effect = lambda: held.append(("time", hub.LOCK._is_owned())) or T0

        class Team(dict):               # dict(TEAM) reads it through keys() or __iter__; another copy may not
            def keys(self):
                held.append(("team", hub.LOCK._is_owned()))
                return super().keys()

            def __iter__(self):
                held.append(("team", hub.LOCK._is_owned()))
                return super().__iter__()
        hub.TEAM = Team(hub.TEAM)
        with patch.object(hub, "change_token", lambda: held.append(("token", hub.LOCK._is_owned())) or real_token()):
            with hub.state_moment() as (token, at):
                self.assertEqual((type(hub.SNAP.team), hub.SNAP.team), (dict, hub.TEAM))
                self.assertFalse(hub.LOCK._is_owned())
        self.assertEqual(set(held), {("token", True), ("time", True), ("team", True)})
        self.assertEqual((token, at), (real_token(), T0))

    def test_a_read_that_fails_ends_its_read_and_gives_its_connection_back(self):
        """An error while the state is built: the thread keeps no moment, the connection's read ends, and the connection
        goes back for the next read, which is the state as before."""
        self.fill()
        body = self.state_bytes()
        with self.assertRaises(RuntimeError):
            with hub.state_moment():
                conn = hub.SNAP.conn
                raise RuntimeError("a fault in the build")
        self.assertEqual((hub.SNAP.conn, hub.SNAP.team, hub.SNAP.moment), (None, None, None))
        self.assertEqual(hub.READERS["idle"], [conn])
        self.assertFalse(conn.in_transaction)
        self.assertEqual(self.state_bytes(), body)

    def test_a_read_whose_moment_cannot_begin_holds_the_lock_as_before(self):
        """A read connection that cannot begin its read (SQLite says that the records are locked) is closed, and the
        state is read under the lock as before: the same bytes as from its own moment. The hub's log says so once for
        each reason."""
        self.fill()

        class Refusing:
            closed = 0

            def execute(self, sql, *args):
                raise sqlite3.OperationalError("database is locked")

            def set_trace_callback(self, trace):
                pass

            def close(self):
                Refusing.closed += 1
        held = []                   # whether the build held the lock across its statements: central_ok runs none
        central = lambda t0=None: held.append(hub.LOCK._is_owned()) or False
        with patch.object(hub, "reader", lambda: (Refusing(), hub.READERS["turn"])), \
                patch.object(hub, "central_ok", central):
            first, seen = self.statements(self.state_bytes)
            second = self.state_bytes()
        # The log line is written before the first read takes its token, so both reads have the same token.
        self.assertEqual((second, Refusing.closed, held), (first, 2, [True, True]))
        self.assertIn(("SELECT * FROM tasks ORDER BY id", True), seen)     # through the hub's own connection, locked
        self.assertNotIn(("SELECT * FROM tasks ORDER BY id", False), seen)
        said = [r["what"] for r in hub.q("SELECT what FROM log WHERE agent='hub' ORDER BY id")]
        self.assertEqual([w for w in said if "could not start its own read" in w],
                         ["a read of the state could not start its own read of the records, so it held the hub's "
                          "lock for all of it: database is locked"])
        self.assertEqual(hub.READERS["told"], "database is locked")
        with patch.object(hub, "central_ok", central):
            own, seen = self.statements(self.state_bytes)
        self.assertEqual((own, held[2:]), (first, [False]))
        self.assertIn(("BEGIN", True), seen)
        hub.readers_for(self.path)              # new read connections: a failure of theirs is logged again
        self.assertIsNone(hub.READERS["told"])

    def test_a_read_connection_only_reads_and_belongs_to_the_records_of_now(self):
        """A read connection refuses a write. One that comes back is kept for the next read, up to READERS_KEPT, and a
        read of the state gives its own back. readers_for closes what is idle, and a connection of an earlier turn is
        closed when it comes back. There is none for another DB, or after readers_for(None), and records that SQLite
        keeps in memory are not put in WAL mode."""
        conn, turn = hub.reader()
        with self.assertRaises(sqlite3.OperationalError):           # query_only
            conn.execute("INSERT INTO needs(title) VALUES('a write')")
        hub.reader_back(conn, turn)
        self.assertEqual(hub.reader(), (conn, turn))                # kept for the next read
        taken = [hub.reader() for _ in range(hub.READERS_KEPT + 2)]
        for got in [(conn, turn)] + taken:
            hub.reader_back(*got)
        self.assertEqual(len(hub.READERS["idle"]), hub.READERS_KEPT)
        old, idle = hub.reader(), list(hub.READERS["idle"])
        hub.readers_for(self.path)                  # another turn: what was idle is closed, and so is the old one
        self.assertEqual(hub.READERS["idle"], [])
        hub.reader_back(*old)
        self.assertEqual(hub.READERS["idle"], [])
        for conn in [old[0]] + idle:
            with self.assertRaises(sqlite3.ProgrammingError):
                conn.execute("SELECT 1")
        self.fill()
        first = self.state_bytes()                  # a read gives its connection back, and the next read takes it
        kept = list(hub.READERS["idle"])
        self.assertEqual((self.state_bytes(), len(kept)), (first, 1))
        self.assertEqual(hub.READERS["idle"], kept)
        other = sqlite3.connect(":memory:")
        self.addCleanup(other.close)
        with patch.object(hub, "DB", other):        # records that it was not opened for: none
            self.assertIsNone(hub.reader())
            self.assertEqual(hub.wal_on(), (False, "SQLite kept the journal mode memory"))
        hub.readers_for(None)
        self.assertIsNone(hub.reader())

    def test_the_build_reads_the_records_and_the_team_only_through_its_moment(self):
        """Every function that the body of the state's `with state_moment()` reaches in hub.py reads the records through
        q, q1, read_rows or read_row and the team through team_read, which read the moment's, and none writes. One that
        named DB or TEAM itself would read the records or the team of now, and a writer would write from a read. The
        scan follows names: a call through an attribute (self.x(), obj.y()), a function in a table or code in another
        module is not followed. The block has no self. at all, and this test keeps it so."""
        tree = ast.parse(inspect.getsource(hub))
        functions = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                functions[node.name] = node
                for sub in node.body if isinstance(node, ast.ClassDef) else ():
                    if isinstance(sub, ast.FunctionDef):
                        functions[f"{node.name}.{sub.name}"] = sub

        def names(node):
            return {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
        block = next(n for n in ast.walk(functions["Handler.ui_state"]) if isinstance(n, ast.With)
                     and ast.unparse(n.items[0].context_expr) == "state_moment()")
        selfs = [ast.unparse(n) for stmt in block.body for n in ast.walk(stmt)      # the scan cannot follow these
                 if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "self"]
        self.assertEqual(selfs, [])
        reached, todo = set(), [n for stmt in block.body for n in names(stmt) if n in functions]
        while todo:
            name = todo.pop()
            if name not in reached:
                reached.add(name)
                todo.extend(n for n in names(functions[name]) if n in functions)
        watched = {"DB", "TEAM", "LOCK", "ins", "kv_set", "log", "emit", "transaction", "committed", "log_row"}
        self.assertEqual({name: names(functions[name]) & watched for name in reached
                          if names(functions[name]) & watched},
                         {"q": {"DB", "LOCK"}, "read_rows": {"DB", "LOCK"}, "team_read": {"TEAM"},
                          "commit": {"DB"}, "counted": {"DB"}, "held": {"LOCK"}})
        self.assertGreater(len(reached), 50)
        self.assertTrue({"agents", "chat_apps", "setting", "unplaced", "goal_view", "DutyReads"} <= reached)
        writes = re.compile(r"\s*(INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER)\b", re.I)     # through q: refused
        self.assertEqual([(name, n.value) for name in sorted(reached) for n in ast.walk(functions[name])
                          if isinstance(n, ast.Constant) and isinstance(n.value, str) and writes.match(n.value)], [])

    def test_a_moment_inside_a_moment_of_its_own_thread_is_that_moment(self):
        self.fill()
        with hub.state_moment() as outer:
            conn = hub.SNAP.conn
            with hub.state_moment() as inner:
                self.assertEqual(inner, outer)
                self.assertIs(hub.SNAP.conn, conn)
                self.assertFalse(hub.LOCK._is_owned())
            self.assertIs(hub.SNAP.conn, conn)
            self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tasks")["n"], 14)
        self.assertEqual((hub.SNAP.conn, hub.SNAP.team, hub.SNAP.moment), (None, None, None))


class RealHub(unittest.TestCase):
    """hub.py itself puts its records in WAL mode, and a read of the state opens a read connection of its own: the
    process then holds the records' file open twice (lsof)."""

    def test_the_hub_keeps_its_records_in_wal_mode(self):
        folder = tempfile.mkdtemp(prefix="fleet-wal-test-")
        self.addCleanup(shutil.rmtree, folder, True)
        with open(os.path.join(folder, "team.json"), "w") as f:
            json.dump({"hub": {"machine": "hub", "port": 8765}, "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.1"},
                       "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []}}}, f)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        pipe, fds = parent_pipe(folder)
        records = os.path.join(folder, "hub.db")
        proc = subprocess.Popen([sys.executable, os.path.join(KIT, "hub.py"), "--host", "127.0.0.1",
                                 "--port", str(port), "--db", records, "--team", os.path.join(folder, "team.json"),
                                 "--parent-pipe", str(pipe)],
                                pass_fds=fds, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, env=dict(os.environ, HOME=folder))

        def stop():
            proc.kill()
            proc.wait(timeout=20)
            proc.stdout.close()
        self.addCleanup(stop)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(200):
            if proc.poll() is not None:
                self.fail("the hub did not start: " + proc.stdout.read())
            try:
                with opener.open(f"http://127.0.0.1:{port}/ui/state", timeout=PATIENCE) as r:
                    state = json.load(r)
                break
            except (urllib.error.URLError, OSError):
                time.sleep(0.1)
        else:
            self.fail("the hub never answered")
        lsof = shutil.which("lsof") or "/usr/sbin/lsof"
        listed = subprocess.run([lsof, "-n", "-P", "-Fn", "-p", str(proc.pid)], capture_output=True, text=True,
                                timeout=60).stdout
        files = [line[1:] for line in listed.splitlines() if line.startswith("n/")]
        self.assertGreaterEqual(files.count(os.path.realpath(records)), 2, "the hub has no read connection of its own")
        opened = sqlite3.connect(records)
        self.addCleanup(opened.close)
        self.assertEqual(opened.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(state["db"], opened.execute("SELECT v FROM kv WHERE k='db_id'").fetchone()[0])
        self.assertTrue(os.path.exists(records + "-wal"))


if __name__ == "__main__":
    unittest.main()

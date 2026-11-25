"""F14-3: the hub lets go of the raw records of the tasks that ended more than 90 days ago (hub.raw_sweep).

The owner, 22 November 2026: "The hub lets go of the raw records and start texts of tasks that ended more than 90
days ago, and keeps every task, result, conversation and case", and to the exact list of what goes: "Yes, all five
lines". These checks are the design's section 10 (F14-3-design.md): what goes and when, that nothing else changes,
that each reader of what stays still reads it, that the history and the ids stay whole, that a batch holds the lock a
short time and loses nothing when it stops, that it wakes no app, that nothing comes back late, and that a restore
lets go again of what it put back.

In-process hub, a temporary database and a set clock. No AI calls.

Run: python3 -m unittest -v test_raw_sweep.py
"""
import contextlib
import datetime
import hashlib
import json
import sqlite3
import time
import unittest
import uuid
from unittest.mock import patch

import diagnostics
import hub
import wakeups
from test_ui_api import OwnerAPI

TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3"},
        "accounts": {"gemini": {"kind": "key", "provider": "google", "title": "Gemini"}},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "vps": {"role": "worker", "runtime": "claude", "machine": "vps", "can": ["shell"],
                           "account": "gemini"}},
        "goals": {"timezone": "Europe/Madrid", "review_hour": 9, "sweep_minutes": 15}}
SESSION = "11111111-2222-4333-8444-555555555555"         # the helper's id of the session window
RUNTIME_SESSION = "0d6f2c8e-5b1a-4c3e-9f7d-2a4b6c8d0e1f"     # the runtime's own id of it, in its session record
DAY = 86400
START = datetime.datetime(2026, 6, 1, 10, 0, tzinfo=datetime.timezone.utc).timestamp()
NOW = START + 200 * DAY
FRAME = ("session", "model", "result", "error")
STEPS = ("user_message", "agent_thought", "plan", "tool_call", "tool_call_update", "agent_message")
# the tables that the sweep writes, and the kv keys that it writes (its two cursors, its time, and the history's floor)
SWEPT_TABLES = ("thread_events", "history", "calls", "events", "kv", "log", "history_unindexed")
SWEPT_KEYS = ("raw_swept", "raw_calls_swept", "raw_sweep_at", "row_floor:history")


def load_tests(loader, _tests, _pattern):
    """Only the tests of this file: the fixture it borrows from test_ui_api.py carries its own."""
    suite = unittest.TestSuite()
    for cls in (Keeping, NothingElse, Readers, Batches, Late, Index):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


def steps(word, seq=1, ts=START):
    """One turn of a session as the runner sends it: its frame (session, model, result) and its steps, with `word`
    in each step's words, and then an error, which a turn on an account with no credit ends with."""
    return [{"seq": seq, "ts": ts, "type": "session", "runtime": "claude", "session_id": RUNTIME_SESSION},
            {"seq": seq + 1, "ts": ts, "type": "model", "requested_model": "opus", "model": "claude-opus-4-5",
             "effort": "high"},
            {"seq": seq + 2, "ts": ts, "type": "user_message", "text": f"Fix the {word} export"},
            {"seq": seq + 3, "ts": ts, "type": "agent_thought", "text": f"The {word} column looks wrong"},
            {"seq": seq + 4, "ts": ts, "type": "plan", "entries": [{"content": f"Read {word}", "status": "completed"}]},
            {"seq": seq + 5, "ts": ts, "type": "tool_call", "tool_call_id": f"c{seq}", "status": "in_progress",
             "kind": "execute", "title": f"grep {word} export.csv"},
            {"seq": seq + 6, "ts": ts, "type": "tool_call_update", "tool_call_id": f"c{seq}", "status": "completed",
             "output": f"{word} found in line 4"},
            {"seq": seq + 7, "ts": ts, "type": "agent_message", "text": f"I fixed the {word} column"},
            {"seq": seq + 8, "ts": ts, "type": "result", "stop_reason": "end_turn"},
            {"seq": seq + 9, "ts": ts, "type": "error", "code": "no_credit", "message": "The key has no credit"}]


class Base(OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        self.clock = START
        for stand_in in (patch.object(hub, "now", lambda: self.clock),
                         patch.dict(hub.RAW_TOLD, {"at": None, "records": 0, "answers": 0, "starts": 0})):
            stand_in.start()
            self.addCleanup(stand_in.stop)
        hub.HISTORY_CALL_CACHE.clear()
        self.addCleanup(hub.HISTORY_CALL_CACHE.clear)

    # ---- a task with everything the sweep reads, as the hub's own writers leave it
    def task(self, state="working", **columns):
        columns = dict({"title": "A task", "details": "", "done_when": "it is done", "needs": "none",
                        "owner": "vps", "requester": "manager", "state": state, "created": self.clock,
                        "last_activity": self.clock, "attempt": 1}, **columns)
        return hub.ins(f"INSERT INTO tasks({','.join(columns)}) VALUES({','.join('?' * len(columns))})",
                       tuple(columns.values()))

    def records(self, tid, events, attempt=1, window=None):
        code, said = self.request("/helper/events/vps", {"generation": "test-generation",
                                                          "task": window or f"T-{tid}", "attempt": attempt,
                                                          "session": SESSION, "events": events}, source="127.0.0.3")
        self.assertEqual(code, 200, said)
        return said

    def call(self, tid, name, detail, ok=1, args=None, agent="vps"):
        hub.call_record(agent, tid, 1, name, ok, json.dumps(args or {"task_id": hub.tref(tid) if tid else None}),
                        detail, None)
        return hub.q1("SELECT MAX(id) n FROM calls")["n"]

    def start(self, tid, word):
        eid = hub.emit("vps", "task", f"You are vps. Your task T-{tid}: fix the {word} export. " + "Rules. " * 400,
                       task=tid, extra={"needs": "none", "resume": False, "attempt": 1, "generation": "test-generation"})
        hub.q("UPDATE events SET read_at=?, helper_ack=? WHERE id=?", (self.clock + 2, self.clock + 1, eid))
        return eid

    def worked(self, word, **columns):
        """A task with a session of one turn, its fleet calls (a read, a send, a write of the history's, an act in
        the hub, an act outside it, a refused read) and its start event, still open."""
        tid = self.task(**columns)
        self.start(tid, word)
        self.records(tid, steps(word))
        self.call(tid, "list_my_tasks", f"T-{tid} [working] fix the {word} export, and 40 more lines")
        self.call(tid, "message_owner", f"Sent to the owner: the {word} export is fixed.")
        self.call(tid, "write_knowledge", "knowledge/exports.md is written.", args={"path": "knowledge/exports.md"})
        self.call(tid, "create_task", f"T-{tid + 100} is given to vps: check the {word} export.")
        self.call(tid, "repo_change", f"Committed 1a2b3c4 to fleet/c1/{word}: export.csv")
        self.call(tid, "read_knowledge", f"read_knowledge is refused: knowledge/{word}.md is not a file.", ok=0)
        return tid

    def end(self, tid, ended, state="completed"):
        hub.q("UPDATE tasks SET state=?, outcome=?, what='Fixed the column', delivered=? WHERE id=?",
              (state, state, ended, tid))

    def fresh(self):
        """A task that ended now: the newest work of the fleet, which the mark is measured from (A2)."""
        tid = self.task(created=self.clock)
        self.end(tid, self.clock)
        return tid

    def sweep(self, end=None):
        """Batches until none leaves rows; how many it took."""
        n = 1
        while hub.raw_batch(self.clock, time.monotonic() + 60 if end is None else end):
            n += 1
            self.assertLess(n, 1000)
        return n

    # ---- a search of an agent of its own history
    def search(self, session, words):
        text, error = hub.call_tool("vps", "search_history", {"query": words, "task_id": hub.tref(session)},
                                    ("test-generation", hub.tref(session), 1))
        self.assertFalse(error, text)
        return self.refs(text)

    def refs(self, text):
        return [line.split(" · ")[0].split(". ", 1)[1] for line in text.split("\n")
                if " · " in line and line.split(". ", 1)[0].isdigit()]

    # ---- the rows of a table, before and after
    def rows(self, name):
        """One table's rows, in the order of their row ids (a table WITHOUT ROWID, as an index's own, in the order of
        its key)."""
        try:
            return [dict(r) for r in hub.q(f'SELECT rowid AS _rowid, * FROM "{name}" ORDER BY rowid')]
        except sqlite3.OperationalError:
            return [dict(r) for r in hub.q(f'SELECT * FROM "{name}"')]

    def pairs(self, before, after):
        self.assertEqual([r["_rowid"] for r in after], [r["_rowid"] for r in before])
        return zip(before, after)

    # ---- what a task holds
    def kinds(self, tid):
        return sorted({r["type"] for r in hub.q("SELECT type FROM thread_events WHERE task=?", (tid,))})

    def answers(self, tid):
        return {r["name"]: r["detail"] for r in hub.q("SELECT name, detail FROM calls WHERE task=?", (tid,))}

    def start_texts(self, tid):
        return [r["text"] for r in hub.q("SELECT text FROM events WHERE task=? AND kind='task'", (tid,))]

    def assertWhole(self, tid, word):
        self.assertEqual(self.kinds(tid), sorted(FRAME + STEPS), tid)
        self.assertIn(word, self.answers(tid)["list_my_tasks"])
        self.assertTrue(all(word in text for text in self.start_texts(tid)), tid)

    def assertLetGo(self, tid):
        self.assertEqual(self.kinds(tid), sorted(FRAME), tid)
        answers = self.answers(tid)
        self.assertIsNone(answers["list_my_tasks"], tid)
        for kept in ("message_owner", "write_knowledge", "create_task", "repo_change", "read_knowledge"):
            self.assertIsNotNone(answers[kept], (tid, kept))
        self.assertEqual(self.start_texts(tid), [hub.RAW_START], tid)


class Keeping(Base):
    def test_an_open_task_keeps_every_record_however_old(self):
        """An open task keeps every session record, call answer and start text, however old its rows are: one that
        is parked for 100 days, and one that waits for an answer. The state decides, and not a time: a pick that left
        the state out would also take an open task that has a time of delivery (no writer makes one today; one that
        wrote it at a step that is not the end would), and one that went by the task's creation would take every old
        open task."""
        parked = self.worked("parked")
        hub.ins("INSERT INTO reminders(due,note,agent,task,created) VALUES(?,?,?,?,?)",
                (NOW + 10 * DAY, "come back to the export", "vps", parked, self.clock))
        waiting = self.worked("waiting")
        hub.q("UPDATE tasks SET state='input-required', waiting_on='Q-1', delivered=? WHERE id=?",
              (START + DAY, waiting))
        self.clock = NOW
        self.fresh()
        self.sweep()
        self.assertWhole(parked, "parked")
        self.assertWhole(waiting, "waiting")

    def test_a_task_goes_ninety_days_after_its_delivery_and_not_before(self):
        """A task that ended 89 days ago keeps all; one that ended 91 days ago loses its steps, the answers of its
        reads and its start text; one that ended exactly 90 days ago keeps all. The time is its delivery: not its
        last activity, nor its creation. A terminal task with no time of delivery is never taken. And the mark is
        measured from the newest delivery of the fleet when that is earlier than now (A2): a clock that runs 100 days
        ahead lets go of nothing that ended within 90 days of the fleet's newest work."""
        younger = self.worked("younger")
        older = self.worked("older")
        mark = self.worked("mark")
        undated = self.worked("undated")
        self.clock = NOW
        self.end(younger, NOW - 89 * DAY)
        self.end(older, NOW - 91 * DAY)
        self.end(mark, NOW - 90 * DAY)
        self.end(undated, None, state="failed")
        hub.q("UPDATE tasks SET last_activity=? WHERE id=?", (NOW - 100 * DAY, younger))
        hub.q("UPDATE tasks SET last_activity=? WHERE id=?", (NOW - 10 * DAY, older))
        self.clock = NOW + 100 * DAY            # a clock 100 days ahead, for one pass: the newest work is younger's
        self.assertFalse(hub.raw_batch(self.clock, time.monotonic() + 60))
        for tid, word in ((younger, "younger"), (older, "older"), (mark, "mark"), (undated, "undated")):
            self.assertWhole(tid, word)
        self.clock = NOW
        self.fresh()
        self.sweep()
        self.assertLetGo(older)
        for tid, word in ((younger, "younger"), (mark, "mark"), (undated, "undated")):
            self.assertWhole(tid, word)

    def test_a_call_of_no_task_loses_its_answer_ninety_days_after_it(self):
        """Line 5 of the owner's list: the answer of a read of the manager's own session, of an owner chat or of a
        conversation window (no task) goes 90 days after the call. One of 89 days keeps it, and so do a refusal, a
        message to the owner and an act of the manager (a task that it gave), of any age: line 5 names reads only. Each
        row stays whole but that answer: its arguments say what was read. Without its own rule such a call keeps its
        answer for good, and with the rule of a task it would never go, or go at once."""
        self.clock = NOW - 91 * DAY
        old_read = self.call(None, "see_team", "vps: working on T-3, the export", agent="manager")
        old_refused = self.call(None, "create_task", "create_task is refused: no such agent", ok=0, agent="manager")
        old_sent = self.call(None, "message_owner", "Sent to the owner: the week's report.", agent="manager")
        old_act = self.call(None, "create_task", "T-3 is given to vps: fix the export.", agent="manager")
        self.clock = NOW - 89 * DAY
        young_read = self.call(None, "see_team", "vps: idle", agent="manager")
        self.clock = NOW
        self.fresh()
        before = self.rows("calls")
        self.assertEqual({r["id"] for r in before}, {old_read, old_refused, old_sent, old_act, young_read})
        self.sweep()
        for row, now_row in self.pairs(before, self.rows("calls")):         # each row stays, as T3 holds a task's
            self.assertIsNotNone(row["detail"])
            self.assertEqual(now_row, dict(row, detail=None if row["id"] == old_read else row["detail"]), row["id"])

    def test_a_start_event_stays_with_its_ids_times_and_extra_and_the_owner_s_steer_stays_on_its_page(self):
        """The start event of an old task keeps its id, read_at, helper_ack and extra, and only its text becomes
        the hub's line: the helper's cursor reads by an event's id, and the owner's messages and steers are in an
        answer only with their events. The owner's steer of that task is still in the state's answer."""
        tid = self.task()
        eid = self.start(tid, "steered")
        code, said = self.request(f"/ui/tasks/{tid}/steer", self.command(text="Use the March file, not April's"))
        self.assertEqual(code, 200, said)
        before = dict(hub.q1("SELECT * FROM events WHERE id=?", (eid,)))
        self.end(tid, START + DAY)
        self.clock = NOW
        self.fresh()
        self.sweep()
        after = hub.q1("SELECT * FROM events WHERE id=?", (eid,))
        self.assertIsNotNone(after)
        self.assertEqual(dict(after), dict(before, text=hub.RAW_START))
        code, state = self.request("/ui/state")
        self.assertEqual(code, 200, state)
        self.assertEqual([s["text"] for s in state["steers"] if s["task"] == tid], ["Use the March file, not April's"])


class NothingElse(Base):
    def test_nothing_else_changes(self):
        """One old ended task of each kind: a plain task, a case's task with its step, a conversation's task with its
        messages, a follower, and a part of a lead's task. After the sweep each table but those that it writes is
        equal row for row; in calls and events each column but the answer and the start text is equal; thread_events
        loses only the steps; the history only the rows of those steps; kv only its own keys; the log one line. A
        sweep that took anything else, a conversation's message, a case's step, a note or an event, fails here."""
        plain = self.worked("plain")
        hub.ins("INSERT INTO notes(task,agent,ts,text) VALUES(?,'vps',?,'Found the bad column')", (plain, self.clock))
        hub.ins("INSERT INTO questions(task,asker,requester,text,asked,answer,answered) VALUES(?,?,?,?,?,?,?)",
                (plain, "vps", "manager", "Which month?", self.clock, "March", self.clock))
        duty = hub.ins("INSERT INTO responsibilities(agent,text,state,revision,created,updated,created_by,request_id) "
                       "VALUES('vps','Watch the exports','active',1,?,?,'owner','r-1')", (self.clock, self.clock))
        case = hub.ins("INSERT INTO duty_cases(responsibility,key,title,source,state,opened,by) VALUES(?,'k1',"
                       "'The export broke','watch','open',?,'vps')", (duty, self.clock))
        cased = self.worked("cased", responsibility=duty, duty_case=case)
        hub.ins("INSERT INTO duty_steps(duty_case,key,text,task,by,ts) VALUES(?,'s1','Found the cause',?,'vps',?)",
                (case, cased, self.clock))
        person = hub.ins("INSERT INTO people(name,role,added) VALUES('Bruno Dupont','customer',?)", (self.clock,))
        conv = hub.ins("INSERT INTO conversations(person,agent,account,chat,state,created,last) "
                       "VALUES(?,'vps','discord-1','chat-1','open',?,?)", (person, self.clock, self.clock))
        asked = hub.ins("INSERT INTO conversation_messages(conversation,who,text,created) VALUES(?,'person',"
                        "'Is the export fixed?',?)", (conv, self.clock))
        talked = self.task(source_conversation=conv, source_message=asked, title="Answer Bruno Dupont")
        hub.q("UPDATE conversation_messages SET task=? WHERE id=?", (talked, asked))
        hub.ins("INSERT INTO conversation_messages(conversation,who,text,created,task) VALUES(?,'agent',"
                "'Yes, it is fixed',?,?)", (conv, self.clock, talked))
        self.records(talked, steps("talked", seq=100), attempt=conv, window=f"C-{conv}")
        self.call(talked, "list_my_tasks", "T-1 [working] the talked export")
        follower = self.worked("follower", follows=plain)
        part = self.worked("part", parent=plain)
        old = (plain, cased, talked, follower, part)
        for tid in old:
            self.end(tid, START + DAY)
        hub.history_catch_up()
        self.clock = NOW
        fresh = self.worked("fresh")
        self.end(fresh, NOW)
        before = self.tables()
        self.sweep()
        after = self.tables()
        self.assertEqual(sorted(after), sorted(before))
        for table in before:
            if table not in SWEPT_TABLES:
                self.assertEqual(after[table], before[table], table)
        for row, now_row in self.pairs(before["calls"], after["calls"]):
            goes = row["task"] in old and row["ok"] == 1 and row["name"] in hub.RAW_READ_TOOLS
            self.assertEqual(now_row, dict(row, detail=None if goes else row["detail"]), row["id"])
        for row, now_row in self.pairs(before["events"], after["events"]):
            goes = row["task"] in old and row["kind"] == "task"
            self.assertEqual(now_row, dict(row, text=hub.RAW_START if goes else row["text"]), row["id"])
        top = max(r["id"] for r in before["thread_events"])
        stays = [r for r in before["thread_events"]
                 if r["task"] not in old or r["type"] in FRAME or r["id"] == top]
        self.assertEqual(after["thread_events"], stays)
        self.assertEqual({r["task"] for r in after["thread_events"] if r["type"] in STEPS}, {fresh})
        records = {r["id"] for r in stays}
        self.assertEqual(after["history"], [h for h in before["history"]
                                            if h["src"] != "tool" or h["src_id"] in records])
        self.assertLess(len(after["history"]), len(before["history"]))
        left = {h["id"] for h in after["history"]}
        self.assertEqual([r["id"] for r in after["history_unindexed"]],        # (part 3b: whose words wait to leave)
                         [h["id"] for h in before["history"] if h["id"] not in left])
        self.assertEqual([r for r in after["kv"] if r["k"] not in SWEPT_KEYS],
                         [r for r in before["kv"] if r["k"] not in SWEPT_KEYS])
        self.assertEqual(after["log"][:len(before["log"])], before["log"])
        self.assertEqual([r["what"].split(":")[0] for r in after["log"][len(before["log"]):]], ["raw records let go"])

    def tables(self):
        return {r["name"]: self.rows(r["name"])
                for r in hub.q("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")}


class Readers(Base):
    def test_the_frame_of_each_session_still_answers_its_readers(self):
        """After the sweep the goal of an old task has the same measured tokens, the agent's reported model is the
        same, an account's warning from an old error is still there, and a person's removal still names the old
        task's session to the helper, which deletes the runtime's files of it. Those read the frame: a sweep that
        took every record of the task would change all four."""
        tid = self.worked("framed", goal_id=7)
        hub.q("INSERT INTO session_tokens(agent,session_id,total,last_activity,reported) VALUES('vps',?,1234,?,?)",
              (RUNTIME_SESSION, self.clock, self.clock))
        self.end(tid, START + DAY)
        self.clock = NOW
        self.fresh()
        tokens, model = hub.goal_tokens(7), hub.reported_model("vps")
        problem = hub.account_problem("vps", hub.team_read())
        self.assertEqual((tokens[0], model["model"], problem["code"]), (1234, "claude-opus-4-5", "key_no_credit"))
        self.sweep()
        self.assertEqual(self.kinds(tid), sorted(FRAME))
        self.assertEqual((hub.goal_tokens(7), hub.reported_model("vps"), hub.account_problem("vps", hub.team_read())),
                         (tokens, model, problem))
        with patch.object(hub, "helper_features", lambda agent: [hub.FORGET_FEATURE]):
            self.assertEqual(hub.removed_forget([], [hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))]), {"vps": 1})
        sent = json.loads(hub.q1("SELECT extra FROM events WHERE kind='forget'")["extra"])
        self.assertEqual(sent["sessions"], [SESSION])

    def test_what_a_task_sent_and_was_refused_and_what_a_removal_finds_stay(self):
        """A new task that follows an old one still gets "What it already sent outside" in its start, and
        see_earlier_work task= still gives the old task's refusals. A person's removal after the sweep still clears
        the receipt of a write of the old task (found by the request id in the call's arguments) and the call that
        kept their standing item (found by the first words of its answer). A sweep that cleared the answer of a call
        that is no read, a refusal, or the arguments of a write breaks one of them. And the list of reads names fleet
        tools, none of which sends: a read that a rename left out of it would keep its answers for good, and a send in
        it would lose them."""
        tools = {name for _role, name, _fn, _desc, _schema in hub.TOOLS}
        self.assertEqual([t for t in hub.RAW_READ_TOOLS if t not in tools], [])
        self.assertEqual([t for t in hub.RAW_READ_TOOLS if t in hub.CALLS_KEPT_WHOLE + hub.HISTORY_CALLS], [])
        person = hub.ins("INSERT INTO people(name,role,added) VALUES('Bruno Dupont','customer',?)", (self.clock,))
        conv = hub.ins("INSERT INTO conversations(person,agent,account,chat,state,created,last) "
                       "VALUES(?,'vps','discord-1','chat-1','open',?,?)", (person, self.clock, self.clock))
        said = hub.ins("INSERT INTO conversation_messages(conversation,who,text,created) VALUES(?,'person',"
                       "'Always copy me on the export',?)", (conv, self.clock - 60))
        item = hub.ins("INSERT INTO standing(agent,scope,kind,words,author_kind,author,conversation,message,created) "
                       "VALUES('vps','agent','instruction','Copy Bruno on the export','person',?,?,?,?)",
                       (f"P-{person}", conv, said, self.clock - 60))
        old = self.worked("sent")
        self.call(old, "keep_instruction", f"Kept as {hub.iref(item)}. It steers you from now on.",
                  args={"words": "Copy Bruno on the export"})
        request = str(uuid.uuid4())
        self.call(old, "remember", "Kept as lesson M-4.", args={"request_id": request, "lesson": "Bruno reads csv"})
        hub.ins("INSERT INTO tool_commands(agent,request_id,tool,digest,receipt,created) VALUES('vps',?,'remember',"
                "'d',?,?)", (wakeups.request_ref(request), json.dumps({"text": "Kept as lesson M-4: Bruno reads csv"}),
                             self.clock))
        self.end(old, START + DAY)
        self.clock = NOW
        self.fresh()
        self.sweep()
        self.assertLetGo(old)
        self.assertIn("message_owner: Sent to the owner: the sent export is fixed.", hub.warm_follows(old))
        follower = self.task(follows=old)
        text, error = hub.call_tool("vps", "see_earlier_work", {"task": hub.tref(old), "task_id": hub.tref(follower)},
                                    ("test-generation", hub.tref(follower), 1))
        self.assertFalse(error, text)
        self.assertIn("read_knowledge: read_knowledge is refused: knowledge/sent.md is not a file.", text)
        with hub.LOCK, hub.transaction():
            hub.removed_receipts_rows("task IN (?)", (old,))
            hub.removed_standing_rows(person)
        receipt = json.loads(hub.q1("SELECT receipt FROM tool_commands")["receipt"])
        self.assertEqual(receipt["text"], hub.REMOVED_WORDS)
        kept = hub.q1("SELECT args, detail FROM calls WHERE name='keep_instruction'")
        self.assertEqual((kept["args"], kept["detail"]), ("{}", hub.REMOVED_WORDS))

    def test_a_search_finds_no_old_step_and_no_record_that_is_gone(self):
        """After the sweep a search for a word of an old step gives no row, and no line of the answer says "(this
        record is gone)", also with the heal of a search turned off: the sweep takes each history row out with its
        record, in the same write. No row of the history points at no record. read_history of the old step's ref
        says that the step was let go, and not that the agent took no part in it."""
        tid = self.worked("zebrafix", title="Fix the zebrafix export")
        self.end(tid, START + DAY)
        hub.history_catch_up()
        self.clock = NOW
        session = self.task()
        found = self.search(session, "zebrafix")
        steps_found = [ref for ref in found if ref.startswith("TR-")]
        self.assertGreaterEqual(len(steps_found), 2, found)
        self.fresh()
        self.records(session, [{"seq": 1, "ts": NOW, "type": "agent_message", "text": "a newer record"}])
        self.sweep()
        self.assertEqual(hub.q("SELECT h.id FROM history h WHERE h.src='tool' AND NOT EXISTS (SELECT 1 FROM "
                               "thread_events e WHERE e.id=h.src_id)"), [])
        for heal in (lambda h: False, hub.history_heal):
            with patch.object(hub, "history_heal", heal):
                text, error = hub.call_tool("vps", "search_history", {"query": "zebrafix",
                                                                      "task_id": hub.tref(session)},
                                            ("test-generation", hub.tref(session), 1))
                self.assertFalse(error, text)
                self.assertNotIn("(this record is gone)", text)
                self.assertEqual([ref for ref in self.refs(text) if ref.startswith("TR-")], [], text)
                self.assertIn(f"T-{tid}", self.refs(text))       # the task itself stays found
        text, error = hub.call_tool("vps", "read_history", {"ref": steps_found[0], "task_id": hub.tref(session)},
                                    ("test-generation", hub.tref(session), 1))
        self.assertFalse(error, text)
        self.assertIn("a task that ended more than 90 days ago", text)

    def test_the_newest_record_stays_so_that_its_id_is_never_given_again(self):
        """The fleet's newest session record is of an old task: it stays, the next record gets a larger id, and a
        search finds that record's words. If the sweep took it, SQLite would give its id to the next record, which
        the history's stream has read past, so no search would ever find it."""
        tid = self.worked("quietfleet")
        self.records(tid, [{"seq": 11, "ts": START, "type": "agent_message", "text": "the fleet's last words"}])
        self.end(tid, START + DAY)
        hub.history_catch_up()
        top = hub.q1("SELECT MAX(id) n FROM thread_events")["n"]
        self.assertEqual(tuple(hub.q1("SELECT task, type FROM thread_events WHERE id=?", (top,))),
                         (tid, "agent_message"))
        self.clock = NOW
        self.fresh()
        self.sweep()
        self.assertEqual(hub.q1("SELECT MAX(id) n FROM thread_events")["n"], top)
        session = self.task()
        self.records(session, [{"seq": 1, "ts": NOW, "type": "agent_message", "text": "the newest wombat record"}])
        self.assertGreater(hub.q1("SELECT MAX(id) n FROM thread_events")["n"], top)
        self.assertTrue(any(ref.startswith("TR-") for ref in self.search(session, "wombat")))


class Batches(Base):
    def many(self, n):
        """One old task with n session records that hold work text, as the helper's intake leaves them."""
        tid = self.task()
        with hub.LOCK:
            hub.DB.executemany("INSERT INTO thread_events(task,attempt,session,seq,ts,type,data,created) "
                               "VALUES(?,1,?,?,?,'agent_message',?,?)",
                               [(tid, SESSION, i, START, json.dumps({"text": f"step {i}"}), START)
                                for i in range(1, n + 1)])
            hub.commit()
        self.end(tid, START + DAY)
        return tid

    def left(self, tid):
        return hub.q1("SELECT COUNT(*) n FROM thread_events WHERE task=?", (tid,))["n"]

    def test_a_batch_holds_the_lock_a_short_time_and_moves_the_cursor_with_the_task_s_last_row(self):
        """With a clock that says the budget is over after the first row, one batch takes one row, and the next goes
        on from the next. With 1,000 rows of one task, one batch takes at most RAW_ROWS, and the cursor stays before
        the task until its last row goes. A batch that held the lock for as long as it had rows would make every
        caller of the hub wait; a cursor that moved first would skip the task's rest at a stop in between."""
        first, second = self.many(3), self.many(1000)
        self.clock = NOW
        self.fresh()
        self.assertTrue(hub.raw_batch(self.clock, 0.0))
        self.assertEqual(self.left(first), 2)
        self.assertTrue(hub.raw_batch(self.clock, 0.0))
        self.assertEqual(self.left(first), 1)
        self.assertIsNone(hub.kv_get("raw_swept"))
        hub.raw_batch(self.clock, 0.0)
        self.assertEqual((self.left(first), hub.raw_cursor()[1]), (0, first))
        far = time.monotonic() + 60
        self.assertTrue(hub.raw_batch(self.clock, far))
        self.assertEqual(self.left(second), 1000 - hub.RAW_ROWS)
        self.assertEqual(hub.raw_cursor()[1], first)
        self.assertTrue(hub.raw_batch(self.clock, far))
        self.assertEqual(hub.raw_cursor()[1], first)
        self.sweep()
        self.assertEqual((self.left(second), hub.raw_cursor()[1]), (1, second))      # its newest record stays

    def test_a_stop_in_the_middle_of_a_batch_leaves_each_row_and_the_cursor(self):
        """A batch is one transaction: one that stops in the middle (here its third history row raises) leaves each
        session record, each history row, each answer and the cursor as they were, and the next batch does it all."""
        tid = self.worked("halfway")
        self.end(tid, START + DAY)
        hub.history_catch_up()
        self.clock = NOW
        self.fresh()
        tables = ("thread_events", "history", "calls", "events", "kv")
        before = [[tuple(r) for r in hub.q(f"SELECT * FROM {t} ORDER BY rowid")] for t in tables]
        dropped, drop = [], hub.history_drop_row

        def failing(h):
            dropped.append(h["id"])
            if len(dropped) == 3:
                raise sqlite3.OperationalError("disk I/O error")
            return drop(h)

        with patch.object(hub, "history_drop_row", failing), self.assertRaises(sqlite3.OperationalError):
            hub.raw_batch(self.clock, time.monotonic() + 60)
        self.assertEqual([[tuple(r) for r in hub.q(f"SELECT * FROM {t} ORDER BY rowid")] for t in tables], before)
        self.sweep()
        self.assertLetGo(tid)

    def test_the_sweep_wakes_no_app(self):
        """The sweep moves no change token, so it wakes no app's wait and makes no app read again, and the mark of the
        old task's block of older tasks does not move: each app would read that block again."""
        tid = self.worked("quiet")
        self.end(tid, START + DAY)
        self.clock = NOW
        self.fresh()
        block = lambda: hub.q1("SELECT rev FROM task_blocks WHERE block=?", (tid // hub.TASK_BLOCK,))["rev"]
        token, mark = hub.change_token(), block()
        hub.raw_sweep(self.clock)
        self.assertLetGo(tid)
        self.assertEqual((hub.change_token(), block()), (token, mark))
        self.assertTrue(hub.q("SELECT 1 FROM log WHERE what LIKE 'raw records let go:%'"))     # its line is quiet too

    def test_a_restore_lets_go_again_of_what_it_put_back(self):
        """A restore puts back the rows and the cursor of the copy's moment: the sweep takes them again at its next
        batches. A cursor kept outside the records would say that they were done, and they would stay for good."""
        tid = self.worked("restored")
        self.end(tid, START + DAY)
        self.clock = NOW
        self.fresh()
        put_back = self.kept()
        self.sweep()
        self.assertLetGo(tid)
        put_back()
        self.assertWhole(tid, "restored")
        self.sweep()
        self.assertLetGo(tid)


class Late(Base):
    def test_a_record_or_an_answer_that_comes_late_for_a_task_that_was_let_go_is_not_kept(self):
        """A helper that sends an old task's records again after the sweep gets ok, with its batch taken, and no row
        is stored. The same for a conversation window's record of an old conversation task, and for a done call that
        names an old task, which keeps its row and no answer (a send keeps its answer). The sweep's cursor is past
        those tasks, so a row that came late would stay for good."""
        tid = self.worked("late")
        person = hub.ins("INSERT INTO people(name,role,added) VALUES('Bruno Dupont','customer',?)", (self.clock,))
        conv = hub.ins("INSERT INTO conversations(person,agent,account,chat,state,created,last) "
                       "VALUES(?,'vps','discord-1','chat-1','open',?,?)", (person, self.clock, self.clock))
        asked = hub.ins("INSERT INTO conversation_messages(conversation,who,text,created) VALUES(?,'person',"
                        "'Is it fixed?',?)", (conv, self.clock))
        talked = self.task(source_conversation=conv, source_message=asked)
        self.records(talked, steps("talked", seq=100), attempt=conv, window=f"C-{conv}")    # one session: seq on
        for old in (tid, talked):
            self.end(old, START + DAY)
        self.clock = NOW
        fresh = self.fresh()
        self.sweep()
        count = lambda: hub.q1("SELECT COUNT(*) n FROM thread_events")["n"]
        held = count()
        said = self.records(tid, steps("late", seq=5) + [{"seq": 20, "type": "agent_message", "text": "late"}])
        self.assertEqual((said["ok"], said["stored"], said["last_seq"]), (True, 0, 20))
        said = self.records(talked, [{"seq": 130, "ts": START + 60, "type": "agent_message", "text": "late"}],
                            attempt=conv, window=f"C-{conv}")
        self.assertEqual((said["stored"], said["last_seq"]), (0, 130))
        self.assertEqual(count(), held)
        read = self.call(tid, "list_my_tasks", "T-1 [completed] the late export")
        sent = self.call(tid, "message_owner", "Sent to the owner: late news.")
        act = self.call(tid, "create_task", "T-9 is given to vps: the late export.")
        other = self.call(fresh, "list_my_tasks", "T-2 [completed]")
        details = {r["id"]: r["detail"] for r in hub.q("SELECT id, detail FROM calls")}
        self.assertEqual((details[read], details[sent], details[act], details[other]),
                         (None, "Sent to the owner: late news.", "T-9 is given to vps: the late export.",
                          "T-2 [completed]"))
        code, page = self.request(f"/ui/tasks/{tid}/events?db=test-generation")
        self.assertEqual((code, page.get("let_go"), sorted({e["type"] for e in page["events"]})),
                         (200, True, sorted(FRAME)))
        code, page = self.request(f"/ui/tasks/{fresh}/events?db=test-generation")
        self.assertNotIn("let_go", page)


LOGIN = "Zx9-Kp!w4Rt2-Bn7"


class Index(Base):
    """Part 3b: the index lets go of the words of the session records that the sweep took (hub.history_unindex)."""

    def setUp(self):
        super().setUp()
        self.assertEqual(hub.wal_on(), (True, None))     # the index is read from a second connection only in WAL mode

    def index_words(self):
        """{id: the words that the index holds at it}, read from the index itself (fts5vocab)."""
        hub.q("CREATE VIRTUAL TABLE IF NOT EXISTS temp.test_held USING fts5vocab(main, 'history_fts', 'instance')")
        out = {}
        for r in hub.q("SELECT doc, term FROM temp.test_held"):
            out.setdefault(r["doc"], []).append(r["term"])
        return out

    def swept(self, word, login=False):
        """An old task whose steps the sweep took, and whose words the index still holds: the ids that wait. With
        `login`, the agent wrote a login of a step that was registered only after the index took it."""
        tid = self.worked(word)
        if login:
            self.records(tid, [{"seq": 11, "ts": START, "type": "agent_message", "text": f"The key is {LOGIN} now"}])
        self.end(tid, START + DAY)
        hub.history_catch_up()
        if login:
            salt = "c0ffee"
            hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES('crm',?,?,?,'')",
                    (salt, hashlib.sha256((salt + LOGIN).encode()).hexdigest(), len(LOGIN)))
        return tid

    def test_the_words_of_the_steps_leave_the_index_and_a_ranked_search_still_answers(self):
        """After the thread's pass the index holds no word at an id of a step that the sweep took, whatever login was
        registered since: the words come from the index itself and not from the record, whose mask is another now.
        Words that came from the record would leave a login's words in the index, or damage it: a ranked search then
        fails for the hub's whole fleet. Every other row keeps its words, and a ranked search of them answers."""
        tid = self.swept("wordsgo", login=True)
        self.clock = NOW
        later = self.task()
        self.records(later, [{"seq": 1, "ts": NOW, "type": "agent_message", "text": "a wallaby and a kestrel"}])
        hub.history_catch_up()
        going = [h["id"] for h in hub.q("SELECT h.id FROM history h JOIN thread_events e ON e.id=h.src_id WHERE "
                                        "h.src='tool' AND h.task=? AND e.type<>'error' ORDER BY h.id", (tid,))]
        self.assertEqual(len(going), 4)                                         # two calls' records, and two messages
        self.assertIn("rt2", " ".join(" ".join(self.index_words()[i]) for i in going))      # the login's own words
        self.fresh()
        self.sweep()
        self.assertEqual([r["id"] for r in hub.q("SELECT id FROM history_unindexed ORDER BY id")], going)
        left = self.index_words()                       # the sweep leaves the words behind, the login's among them
        self.assertIn("w4rt2", " ".join(word for i in going for word in left.get(i, ())))
        token = hub.change_token()
        while hub.history_unindex():
            pass
        self.assertEqual(hub.change_token(), token)                             # and it wakes no app
        held = self.index_words()
        self.assertEqual([i for i in going if i in held], [])
        self.assertEqual(hub.q("SELECT id FROM history_fts_docsize WHERE id IN (%s)" % ",".join(map(str, going))), [])
        self.assertEqual(hub.q("SELECT id FROM history_unindexed"), [])
        kept = [h["id"] for h in hub.q("SELECT id FROM history WHERE task=? AND src='tool'", (later,))]
        self.assertTrue(kept and all("wallaby" in held[i] for i in kept))
        self.assertEqual([ref.split("-")[0] for ref in self.search(later, "wallaby kestrel")], ["TR"])

    def test_a_pass_that_fails_in_the_middle_leaves_the_rest_waiting(self):
        """Each write of a pass is one transaction with the ids that it takes off the waiting list: an error in the
        middle keeps the rest of the ids waiting with their words in the index, and the next pass takes them all."""
        for word in ("one", "two"):
            tid = self.swept(word)
        self.clock = NOW
        self.task()
        self.records(self.task(), [{"seq": 1, "ts": NOW, "type": "agent_message", "text": "the newest record"}])
        self.fresh()
        self.sweep()
        waiting = [r["id"] for r in hub.q("SELECT id FROM history_unindexed ORDER BY id")]
        self.assertEqual(len(waiting), 6)
        real, calls = hub.history_unindex_rows, []

        def failing(ids, words, at):
            calls.append(at)
            if len(calls) == 2:
                raise sqlite3.OperationalError("disk I/O error")
            return real(ids, words, at)

        with patch.object(hub, "RAW_ROWS", 2), patch.object(hub, "history_unindex_rows", failing), \
                self.assertRaises(sqlite3.OperationalError):
            hub.history_unindex()
        self.assertEqual([r["id"] for r in hub.q("SELECT id FROM history_unindexed ORDER BY id")], waiting[2:])
        held = self.index_words()
        self.assertEqual([i in held for i in waiting], [False, False, True, True, True, True])
        while hub.history_unindex():
            pass
        self.assertEqual([i for i in waiting if i in self.index_words()], [])
        self.assertEqual(hub.q("SELECT id FROM history_unindexed"), [])


    def test_a_pass_takes_no_words_of_an_id_that_has_its_row_or_has_none_left(self):
        """A pass gives the index a delete only for an id that has no row of the history and whose size the index
        still holds. History_mend, at a start after one that it failed, takes out the words of every id with no row,
        the waiting ids among them: a second delete of such an id counts a row less in the index's totals, so the
        rank of every search goes wrong, and after a few the index is "malformed". And the words of a row that is there
        (no writer puts one on the list today) stay, so its record is found."""
        self.swept("mended")
        self.clock = NOW
        later = self.task()
        self.records(later, [{"seq": 1, "ts": NOW, "type": "agent_message", "text": "a quokka record"}])
        self.fresh()
        self.sweep()
        hub.history_catch_up()
        waiting = [r["id"] for r in hub.q("SELECT id FROM history_unindexed ORDER BY id")]
        self.assertEqual(len(waiting), 3)                       # a call's two records, and a message
        hub.kv_set(hub.HISTORY_MENDED, None)
        hub.settle_history_index()                      # the mend takes the words of the waiting ids itself
        self.assertEqual([i for i in waiting if i in self.index_words()], [])
        present = hub.q1("SELECT id FROM history WHERE task=? AND src='tool'", (later,))["id"]
        hub.ins("INSERT INTO history_unindexed(id) VALUES(?)", (present,))
        totals = hub.q1("SELECT block FROM history_fts_data WHERE id=1")["block"]     # the index's row count
        words = self.index_words()[present]
        while hub.history_unindex():
            pass
        self.assertEqual(hub.q("SELECT id FROM history_unindexed"), [])
        self.assertEqual(hub.q1("SELECT block FROM history_fts_data WHERE id=1")["block"], totals)
        self.assertEqual(self.index_words().get(present), words)
        self.assertEqual([ref.split("-")[0] for ref in self.search(later, "quokka")], ["TR"])


    def failing_pass(self):
        """An old task's steps swept, with their three ids waiting for the thread; their ids."""
        self.swept("diskfull")
        self.clock = NOW
        self.records(self.task(), [{"seq": 1, "ts": NOW, "type": "agent_message", "text": "the newest record"}])
        self.fresh()
        self.sweep()
        waiting = [r["id"] for r in hub.q("SELECT id FROM history_unindexed ORDER BY id")]
        self.assertEqual(len(waiting), 3)
        return waiting

    def rested(self, *stand_ins):
        """One turn of the thread, with these stand-ins: the time of its rest, which ends the turn. A thread whose
        handler raises gives that error here, and not its rest."""
        class Rested(Exception):
            pass

        def rest(seconds):
            raise Rested(seconds)

        with contextlib.ExitStack() as stack:
            for stand_in in stand_ins + (patch.object(hub.time, "sleep", rest),
                                         patch.object(hub.traceback, "print_exc", lambda *a, **k: None)):
                stack.enter_context(stand_in)
            with self.assertRaises(Rested) as caught:
                hub.history_unindexer()
        return caught.exception.args[0]

    def test_a_pass_that_fails_on_a_full_disk_leaves_the_thread_going(self):
        """On a full disk every write to the records fails, the pass's own (its commit) and any that its handler
        would make. The thread still comes to its rest of UNINDEX_IDLE seconds and tries again then, and every id
        still waits for that pass. A handler that writes to the records, a line in the hub's log or a time in kv,
        would raise there too and end the thread until the hub's next start."""
        waiting = self.failing_pass()

        def full():
            raise sqlite3.OperationalError("database or disk is full")

        self.assertEqual(self.rested(patch.object(hub, "commit", full)), hub.UNINDEX_IDLE)
        self.assertEqual([r["id"] for r in hub.q("SELECT id FROM history_unindexed ORDER BY id")], waiting)

    def test_a_pass_that_fails_counts_one_fault_and_writes_no_log_line(self):
        """A pass that fails is a fault of the hub, as a damaged index is: diagnostics counts it once, in memory, and
        System status shows it. The records get no line of it: not the hub's log, which a full disk would refuse."""
        self.failing_pass()
        lines = hub.q1("SELECT COUNT(*) n FROM log")["n"]

        def full(ids, words, at):
            raise sqlite3.OperationalError("database or disk is full")

        diagnostics.pending()                   # what an earlier step counted is not this pass's
        self.assertEqual(self.rested(patch.object(hub, "history_unindex_rows", full)), hub.UNINDEX_IDLE)
        self.assertEqual([(r["kind"], r["program"], r["count"]) for r in diagnostics.pending()], [("fault", "hub", 1)])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM log")["n"], lines)


if __name__ == "__main__":
    unittest.main()

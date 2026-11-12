"""Reporting up without blocking (report_up, decide_report), readers with the window before them (see_history), the
hub seeing a repetition by itself (circle_sweep), and the manager's resume brief. In-process hub, a temporary
database and a set clock; no helper, no fleet and no AI call.

The gap this closes: the fleet had one upward verb and it cost the task, so an agent that was not blocked said
nothing; every reader answered "now", so nothing could be shown to have got better or worse; and nothing saw that the
same question, the same chain and the same refusal kept coming back.
"""
import datetime
import json
import sqlite3
import time
import unittest
import uuid
from unittest.mock import patch
from zoneinfo import ZoneInfo

import hub
from test_ui_api import OwnerAPI

MADRID = ZoneInfo("Europe/Madrid")
LOGIN = "bws://11111111-2222-4333-8444-55555555555b"
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3", "mac-studio": "127.0.0.4",
                      "lead-box": "127.0.0.5", "hand-box": "127.0.0.6"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]},
                   "studio": {"role": "worker", "runtime": "claude", "machine": "mac-studio", "can": ["shell"]},
                   "lead": {"role": "lead", "runtime": "claude", "machine": "lead-box", "can": ["shell"]},
                   "hand": {"role": "worker", "runtime": "claude", "machine": "hand-box", "can": ["shell"],
                            "reports_to": "lead"}},
        "logins": {LOGIN: {"title": "shop.test · admin", "kind": "login"}},
        "resources": {f"secret:{LOGIN}": {"max": "use"}},
        "goals": {"timezone": "Europe/Madrid", "review_hour": 9, "sweep_minutes": 15}}
FOUND = "The shop's product feed has been stale for three days; nothing in my task covers it."


def at(text, zone=MADRID):
    return datetime.datetime.fromisoformat(text).replace(tzinfo=zone).timestamp()


def load_tests(loader, _tests, _pattern):
    """Only this file's cases, not the inherited OwnerAPI ones."""
    suite = unittest.TestSuite()
    for cls in (Reporting, Deciding, Sweep, History, Circles, Resume, OwnerScreen, Bugs):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Base(OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90)
        self.clock = at("2026-10-19T14:20")
        clock = patch.object(hub, "now", lambda: self.clock)
        clock.start()
        self.addCleanup(clock.stop)
        self.task = self.new_task()

    def new_task(self, owner="vps", requester="manager", title="Fix the acme/web deploy", parent=None, **extra):
        fields = dict({"title": title, "details": "The smoke fails for the customer", "done_when": "the smoke is green",
                       "needs": "none", "owner": owner, "requester": requester, "state": "working",
                       "created": hub.now(), "last_activity": hub.now(), "attempt": 1, "parent": parent}, **extra)
        names = ",".join(fields)
        return hub.ins(f"INSERT INTO tasks({names}) VALUES({','.join('?' * len(fields))})", tuple(fields.values()))

    def tool(self, who, name, task=None, **args):
        """One tool call of an agent, in the session of its own task."""
        if hub.role_of(who) == "manager":
            return hub.call_tool(who, name, args)
        tid = task if task is not None else self.task
        if name not in hub.LEAD_TEAM_TOOLS:
            args = dict(args, task_id=hub.tref(tid))
        return hub.call_tool(who, name, args, ("test-generation", hub.tref(tid), 1))

    def report(self, who="vps", task=None, kind="outside_task", text=FOUND, **args):
        return self.tool(who, "report_up", task=task, request_id=str(uuid.uuid4()), kind=kind, text=text, **args)

    def said(self, agent="manager"):
        return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent=? AND kind='say' ORDER BY id", (agent,))]


class Reporting(Base):
    def test_a_report_leaves_the_task_running_and_counts_as_a_step(self):
        before = dict(hub.q1("SELECT * FROM tasks WHERE id=?", (self.task,)))
        self.clock += 60
        text, err = self.report()
        self.assertFalse(err, text)
        self.assertIn("UP-1 is with manager", text)
        after = dict(hub.q1("SELECT * FROM tasks WHERE id=?", (self.task,)))
        self.assertEqual((after["state"], after["waiting_on"]), ("working", None))     # not input-required
        self.assertEqual(before["state"], after["state"])
        self.assertEqual((after["last_tool"], after["last_activity"]), ("report_up", self.clock))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM questions")["n"], 0)       # it is no question

    def test_it_goes_one_level_up_and_no_further(self):
        sub = self.new_task(owner="hand", requester="lead", parent=self.new_task(owner="lead", title="Ship the shop"))
        text, err = self.report("hand", task=sub)
        self.assertFalse(err, text)
        row = hub.q1("SELECT * FROM reports WHERE id=1")
        self.assertEqual((row["from_agent"], row["to_agent"]), ("hand", "lead"))   # its lead, never the manager
        self.assertIn("is with lead", text)
        self.assertEqual(self.said("manager"), [])
        self.assertEqual(self.said("owner"), [])

    def test_a_now_report_is_lowered_unless_about_names_something_live(self):
        text, err = self.report(severity="now", about="the whole shop")
        self.assertFalse(err, text)
        self.assertEqual(hub.q1("SELECT delivered FROM reports WHERE id=1")["delivered"], "soon")
        self.assertIn("about names nothing the hub can confirm is live", text)
        self.assertEqual(self.said(), [])                   # nothing was emitted
        text, err = self.report(severity="now", about=hub.tref(self.task))
        self.assertFalse(err, text)
        self.assertEqual(hub.q1("SELECT delivered FROM reports WHERE id=2")["delivered"], "now")
        self.assertIn("Report UP-2 from vps", self.said()[0])
        self.assertIn("decide_report", self.said()[0])

    def test_every_urgent_report_about_a_live_thing_reaches_the_requester_at_once(self):
        """No day budget (the owner, 26 October 2026): the fourth urgent report of a day is as urgent as the first."""
        for n in range(5):
            text, err = self.report(severity="now", about=hub.tref(self.task), text=f"Finding number {n}.")
            self.assertFalse(err, text)
            self.assertEqual(hub.q1("SELECT delivered FROM reports WHERE id=?", (n + 1,))["delivered"], "now")
        self.assertEqual(len(self.said()), 5)

    def test_three_agents_that_find_one_thing_are_one_line_and_still_three_answers(self):
        other = self.new_task(owner="studio", title="Write the shop's copy")
        self.assertFalse(self.report("vps")[1])
        self.assertFalse(self.report("studio", task=other)[1])
        text, err = self.report("studio", task=other, text=FOUND.upper())       # the same words, loudly
        self.assertFalse(err, text)
        self.assertIn("says the same as UP-1", text)
        self.assertEqual(len(hub.open_reports("manager")), 1)                   # one line for the manager
        self.assertEqual(hub.q1("SELECT repeats FROM reports WHERE id=1")["repeats"], 2)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM reports")["n"], 3)      # and three rows
        self.assertIn("said by 3 of them", hub.report_line(hub.q1("SELECT * FROM reports WHERE id=1")))
        self.assertIn("studio, vps", hub.report_line(hub.q1("SELECT * FROM reports WHERE id=1")))

    def test_the_same_request_id_replays_its_answer_and_writes_one_row(self):
        rid = str(uuid.uuid4())
        first = self.tool("vps", "report_up", request_id=rid, kind="risk", text=FOUND)
        again = self.tool("vps", "report_up", request_id=rid, kind="risk", text=FOUND)
        self.assertEqual(first, again)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM reports")["n"], 1)
        text, err = self.tool("vps", "report_up", request_id=rid, kind="risk", text="Another thing entirely.")
        self.assertTrue(err)
        self.assertIn("already used for another call", text)

    def test_a_report_and_the_message_about_it_are_written_together_or_not_at_all(self):
        """filed_under reads with q1, and q commits: read inside this transaction it would commit the half-written
        report, so a failure after it would leave a report nobody was told about. The memory lane hit this class
        four times in one day, and admit_task is its tripwire."""
        # The report of a subtask, because that is the one filed_under really reads for: it files a lead's news
        # under the lead's own parent task, and only that branch calls q1.
        parent = self.new_task(owner="lead", requester="manager", title="Ship the shop")
        sub = self.new_task(owner="hand", requester="lead", parent=parent)
        with patch.object(hub, "EVENT", "INSERT INTO events(agent) VALUES(?)"):      # the message insert fails
            with self.assertRaises(sqlite3.Error):
                self.report("hand", task=sub, severity="now", about=hub.tref(sub))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM reports")["n"], 0)           # and the report went with it
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tool_commands")["n"], 0)     # so the same request_id works
        text, err = self.report("hand", task=sub, severity="now", about=hub.tref(sub))
        self.assertFalse(err, text)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM reports")["n"], 1)
        self.assertEqual(hub.q1("SELECT task FROM events WHERE kind='say' ORDER BY id DESC LIMIT 1")["task"], parent)

    def test_a_report_needs_a_kind_a_text_and_a_task_that_is_not_finished(self):
        text, err = self.tool("vps", "report_up", request_id=str(uuid.uuid4()), kind="chat", text=FOUND)
        self.assertTrue(err)
        self.assertIn("outside_task", text)
        text, err = self.tool("vps", "report_up", request_id=str(uuid.uuid4()), kind="risk", text="  ")
        self.assertTrue(err)
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (self.task,))
        text, err = self.report()
        self.assertTrue(err)
        self.assertIn("already completed", text)

    def test_a_lesson_for_others_is_sent_to_the_knowledge_files_and_not_to_a_memory(self):
        text, err = self.report(kind="lesson_for_others", text="The shop's feed is rebuilt at 03:00 UTC, not hourly.")
        self.assertFalse(err, text)
        self.assertIn("write_knowledge", text)
        self.assertIn("repository", text)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM memories")["n"], 0)     # no cross-agent memory share


class Deciding(Base):
    def test_a_decision_reaches_the_sender_s_next_session_and_wrong_is_one_of_them(self):
        self.assertFalse(self.report()[1])
        text, err = self.tool("manager", "decide_report", report_id="UP-1", decision="wrong",
                              note="The feed is rebuilt nightly; it was not stale.")
        self.assertFalse(err, text)
        self.assertIn("vps reads it at the start of its next task session", text)
        said = hub.report_feedback("vps")
        self.assertIn("UP-1", said)
        self.assertIn("manager says it was wrong", said)
        self.assertIn("rebuilt nightly", said)
        self.assertEqual(hub.report_feedback("studio"), "")             # only its own
        self.assertEqual(hub.open_reports("manager"), [])
        # and the sender's next task session opens with it, because that is where it is read
        nxt = self.tool("manager", "create_task", owner="vps", title="Look at the feed after all",
                        done_when="the feed is fresh")
        self.assertFalse(nxt[1], nxt[0])
        opening = hub.q1("SELECT text FROM events WHERE kind='task' ORDER BY id DESC LIMIT 1")["text"]
        self.assertIn("What came of what you reported up", opening)
        self.assertIn("manager says it was wrong", opening)
        self.assertEqual(hub.report_feedback("vps"), "")                # shown once: it does not follow it (plan C10)

    def test_a_report_that_becomes_work_names_the_task(self):
        self.assertFalse(self.report()[1])
        text, err = self.tool("manager", "decide_report", report_id="UP-1", decision="task")
        self.assertTrue(err)
        self.assertIn("give its id in became_task", text)
        text, err = self.tool("manager", "decide_report", report_id="UP-1", decision="task", became_task="T-99")
        self.assertTrue(err)
        self.assertIn("no task T-99", text)
        made = self.new_task(owner="studio", title="Rebuild the shop feed")
        text, err = self.tool("manager", "decide_report", report_id="UP-1", decision="task",
                              became_task=hub.tref(made))
        self.assertFalse(err, text)
        self.assertEqual(hub.q1("SELECT became_task FROM reports WHERE id=1")["became_task"], made)
        self.assertIn(hub.tref(made), hub.report_feedback("vps"))

    def test_a_decision_is_not_made_twice_and_carries_the_reports_that_say_the_same(self):
        other = self.new_task(owner="studio", title="Write the shop's copy")
        self.assertFalse(self.report("vps")[1])
        self.assertFalse(self.report("studio", task=other)[1])
        text, err = self.tool("manager", "decide_report", report_id="UP-1", decision="noted", note="Known.")
        self.assertFalse(err, text)
        self.assertIn("1 report(s) that say the same", text)
        self.assertEqual(hub.q1("SELECT decision FROM reports WHERE id=2")["decision"], "noted")
        self.assertIn("UP-2", hub.report_feedback("studio"))
        again, err = self.tool("manager", "decide_report", report_id="UP-1", decision="wrong")
        self.assertFalse(err, again)
        self.assertIn("already decided", again)
        self.assertEqual(hub.q1("SELECT decision FROM reports WHERE id=1")["decision"], "noted")
        text, err = self.tool("manager", "decide_report", report_id="UP-2", decision="noted")
        self.assertTrue(err)
        self.assertIn("says the same as UP-1", text)

    def test_only_the_one_it_was_reported_to_decides_it_and_a_lead_only_in_its_own_task(self):
        parent = self.new_task(owner="lead", requester="manager", title="Ship the shop")
        sub = self.new_task(owner="hand", requester="lead", parent=parent)
        self.assertFalse(self.report("hand", task=sub)[1])
        text, err = self.tool("manager", "decide_report", report_id="UP-1", decision="noted")
        self.assertTrue(err)
        self.assertIn("reported to lead", text)
        elsewhere = self.new_task(owner="lead", requester="manager", title="Another task of the lead")
        text, err = self.tool("lead", "decide_report", task=elsewhere, report_id="UP-1", decision="noted")
        self.assertTrue(err)
        self.assertIn("not a subtask", text)
        text, err = self.tool("lead", "decide_report", task=parent, report_id="UP-1", decision="noted",
                              note="I know about it.")
        self.assertFalse(err, text)
        self.assertIn("I know about it", hub.report_feedback("hand"))

    def test_a_worker_has_report_up_and_no_decide_report(self):
        names = [t["name"] for t in hub.tools_for("vps")]
        self.assertIn("report_up", names)
        self.assertNotIn("decide_report", names)
        # AUTONOMY.md decision 34: a worker reads its own costs with see_history, and no other mode of it
        self.assertEqual(next(t for t in hub.tools_for("vps") if t["name"] == "see_history")
                         ["inputSchema"]["properties"]["what"]["enum"], ["costs"])
        lead = [t["name"] for t in hub.tools_for("lead")]
        self.assertIn("report_up", lead)
        self.assertIn("decide_report", lead)
        mgr = [t["name"] for t in hub.tools_for("manager")]
        self.assertIn("decide_report", mgr)
        self.assertIn("see_history", mgr)
        self.assertNotIn("report_up", mgr)          # the manager reports to the owner, with tell_owner


class Sweep(Base):
    """Plan C9: no report clock. A report that the manager read and left undecided is named once, at its closing
    empty read, with the other things it left open."""

    def read(self):
        self.clock += 1
        hub.call_tool("manager", "read_messages", {})

    def chases(self):
        return [t for t in self.said() if t.startswith("[hub] You read these and left them open")]

    def test_the_hub_says_it_once_for_each_report_left_open(self):
        self.assertFalse(self.report()[1])
        self.read()                                             # it reads the report
        self.read()                                             # its closing empty read: one chase
        self.assertEqual(len(self.chases()), 1)
        self.assertIn("UP-1 [outside_task] from vps waits for decide_report", self.chases()[0])
        self.read()
        self.assertEqual(len(self.chases()), 1)                 # the same report is not named again
        self.assertFalse(self.report(text="A second, different thing.")[1])
        self.read()
        self.read()
        self.assertEqual(len(self.chases()), 2)
        self.assertIn("UP-2", self.chases()[1])
        self.assertNotIn("UP-1", self.chases()[1])

    def test_a_lesson_for_others_waits_for_nobody_and_a_lead_s_report_is_the_lead_s(self):
        self.assertFalse(self.report(kind="lesson_for_others", text="A fact for the others.")[1])
        self.read()
        self.read()
        self.assertEqual(self.chases(), [])
        parent = self.new_task(owner="lead", requester="manager", title="Ship the shop")
        sub = self.new_task(owner="hand", requester="lead", parent=parent)
        self.assertFalse(self.report("hand", task=sub)[1])
        self.read()
        self.read()
        self.assertEqual(self.chases(), [])                     # its lead decides it, while the lead's task runs


class History(Base):
    def done(self, owner, accepted, when, attempt=1, restarts=0):
        tid = self.new_task(owner=owner, state="completed", outcome="completed", attempt=attempt, restarts=restarts,
                            delivered=when, accepted=accepted, what="Done.")
        hub.q("INSERT INTO attempts(task,attempt,created,started,ended,reason) VALUES(?,?,?,?,?,'created')",
              (tid, 1, when - 3600, when - 3600, when - 1800))
        return tid

    def test_every_mode_reports_the_window_and_the_window_before_it(self):
        self.done("vps", 1, self.clock - 2 * 86400)
        self.done("vps", 0, self.clock - 40 * 86400)
        text, err = self.tool("manager", "see_history", what="agents")
        self.assertFalse(err, text)
        self.assertIn("delivered 1 (1 before)", text)
        self.assertIn("accepted 1 (none before)", text)
        self.assertIn("refused 0 (1 before)", text)
        self.assertIn("an attempt took 30 min in the middle (30 min before)", text)
        self.assertIn("ranks one against another", text)         # and no score
        text, err = self.tool("manager", "see_history", what="agents", window=1)
        self.assertFalse(err, text)
        self.assertIn("delivered 0 (none before)", text)

    def test_the_same_question_four_times_is_one_line_with_a_count(self):
        for n in range(4):
            hub.ins("INSERT INTO questions(task,asker,requester,text,asked) VALUES(?,?,?,?,?)",
                    (self.task, "vps", "manager", f"Which login do I use for the shop? (asked {n} times already)",
                     self.clock - n * 3600))
        hub.ins("INSERT INTO questions(task,asker,requester,text,asked) VALUES(?,?,?,?,?)",
                (self.task, "vps", "manager", "Which login do I use for the shop? (asked 9 times already)",
                 self.clock - 40 * 86400))
        text, err = self.tool("manager", "see_history", what="questions")
        self.assertFalse(err, text)
        self.assertIn("vps asked this 4 (1 before)", text)
        self.assertIn("4 never answered", text)
        self.assertIn("an answer that is nowhere", text)

    def test_the_refused_calls_group_by_agent_tool_and_reason(self):
        for n in range(3):
            hub.ins("INSERT INTO calls(ts,agent,task,attempt,name,args,ok,detail) VALUES(?,?,?,1,?,'{}',0,?)",
                    (self.clock - n, "vps", self.task, "call_api", "The vault refused: you may not use that login."))
        hub.ins("INSERT INTO calls(ts,agent,task,attempt,name,args,ok,detail) VALUES(?,?,?,1,?,'{}',1,'ok')",
                (self.clock, "vps", self.task, "call_api"))
        text, err = self.tool("manager", "see_history", what="refusals")
        self.assertFalse(err, text)
        self.assertIn("vps / call_api: 3 (none before)", text)
        self.assertIn("you may not use that login", text)
        self.assertIn(hub.tref(self.task), text)

    def test_the_duties_and_the_accounts_have_the_same_shape(self):
        duty = hub.ins("INSERT INTO responsibilities(agent,text,state,revision,created,updated,created_by,request_id) "
                       "VALUES('vps','Keep the shop online.','active',1,?,?,'manager',?)",
                       (self.clock, self.clock, str(uuid.uuid4())))
        for when, repeated in ((self.clock - 86400, 0), (self.clock - 2 * 86400, 1), (self.clock - 40 * 86400, 0)):
            hub.ins("INSERT INTO duty_cases(responsibility,key,title,source,state,opened,by,repeated) "
                    "VALUES(?,?,?,'watch','closed',?,'vps',?)", (duty, f"k{when}", "The shop was down", when, repeated))
        text, err = self.tool("manager", "see_history", what="duties")
        self.assertFalse(err, text)
        self.assertIn("cases 2 (1 before)", text)
        self.assertIn("of them a repeat 1 (none before)", text)
        hub.ins("INSERT INTO agent_limits(agent,since,until,reset_known,ended) VALUES('vps',?,?,1,?)",
                (self.clock - 3600, self.clock - 1800, self.clock - 1800))
        text, err = self.tool("manager", "see_history", what="accounts")
        self.assertFalse(err, text)
        self.assertIn("limit episodes 1 (none before)", text)
        self.assertIn("30 minutes of held work", text)

    def test_an_unknown_mode_a_bad_window_and_an_unknown_agent_are_refused(self):
        for args, says in (({"what": "everything"}, "what must be one of"),
                           ({"what": "agents", "window": 0}, "number of days"),
                           ({"what": "agents", "window": 900}, "number of days"),
                           ({"what": "agents", "agent": "nobody"}, "no agent nobody")):
            text, err = self.tool("manager", "see_history", **args)
            self.assertTrue(err, text)
            self.assertIn(says, text)


class Circles(Base):
    def lines(self):
        return [line for _, line in hub.circles(self.clock)]

    def test_the_same_question_twice_in_fourteen_days(self):
        for n in range(2):
            hub.ins("INSERT INTO questions(task,asker,requester,text,asked) VALUES(?,?,?,?,?)",
                    (self.task, "vps", "manager", "Which login do I use for the shop?", self.clock - n * 86400))
        self.assertIn("vps asked the same thing 2 times", " ".join(self.lines()))
        hub.q("UPDATE questions SET asked=? WHERE id=1", (self.clock - 20 * 86400,))
        self.assertEqual(self.lines(), [])

    def test_a_chain_of_three_that_ends_badly(self):
        first = self.new_task(state="failed", outcome="failed")
        second = self.new_task(state="failed", outcome="failed", follows=first)
        third = self.new_task(state="failed", outcome="failed", follows=second)
        self.assertIn(f"{hub.tref(third)} is the 3rd task of one chain", " ".join(self.lines()))
        hub.q("UPDATE tasks SET follows=NULL WHERE id=?", (second,))
        self.assertEqual(self.lines(), [])              # two tasks are a follow-up, not a circle

    def test_one_task_started_again_and_again_and_five_refusals_in_it(self):
        again = self.new_task(restarts=3, title="The task that keeps starting")
        self.assertIn(f"{hub.tref(again)} (vps) lost 3 sessions in a row that left nothing", " ".join(self.lines()))
        for n in range(5):
            hub.ins("INSERT INTO calls(ts,agent,task,attempt,name,args,ok,detail) VALUES(?,?,?,1,?,'{}',0,?)",
                    (self.clock - n, "vps", self.task, "sign_in", "The vault refused: you may not use that login."))
        self.assertIn(f"called sign_in on {hub.tref(self.task)} 5 times and was refused every time", " ".join(self.lines()))
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (self.task,))
        self.assertNotIn("was refused every time", " ".join(self.lines()))       # a finished task runs in no circle

    def test_a_task_whose_sessions_are_lost_while_they_work_is_no_circle(self):
        """Plan C6: the loss rate is no circle any more. A loss that left something for the next attempt counts
        nothing; the requester gets a quiet note every LOST_NOTE losses instead (session_lost)."""
        for i in range(10):
            hub.ins("INSERT INTO attempts(task,attempt,created,reason) VALUES(?,?,?,'restart')",
                    (self.task, 2 + i, self.clock - i))
        self.assertEqual(self.lines(), [])

    def test_two_agents_that_only_talk_are_no_circle_the_talk_guard_stops_them(self):
        for i in range(30):
            hub.ins("INSERT INTO agent_messages(sender,recipient,text,created,request_id) VALUES(?,?,?,?,?)",
                    ("vps" if i % 2 else "studio", "studio" if i % 2 else "vps", "What about the feed?",
                     self.clock - 100, str(uuid.uuid4())))
        self.assertEqual(self.lines(), [])

    def test_the_sweep_says_it_once_changes_nothing_and_never_cancels(self):
        again = self.new_task(restarts=3, title="The task that keeps starting")
        before = [dict(r) for r in hub.q("SELECT * FROM tasks ORDER BY id")]
        hub.circle_sweep(self.clock)
        self.assertEqual(len(self.said()), 1)
        self.assertIn("look like running in circles", self.said()[0])
        self.assertIn("the third attempt is sometimes the right one", self.said()[0])
        self.clock += 86400
        hub.circle_sweep(self.clock)
        self.assertEqual(len(self.said()), 1)                   # the same set says nothing again
        self.assertEqual(before, [dict(r) for r in hub.q("SELECT * FROM tasks ORDER BY id")])
        hub.q("UPDATE tasks SET restarts=4 WHERE id=?", (again,))
        self.clock += 86400
        hub.circle_sweep(self.clock)
        self.assertEqual(len(self.said()), 2)


class Resume(Base):
    def test_the_brief_says_where_each_thing_stood_and_is_shorter_than_see_team(self):
        goal = hub.ins("INSERT INTO goals(title,text,state,revision,limits,created,updated,request_id,next_step) "
                       "VALUES('Open the shop','Sell the first thing.','active',1,'{}',?,?,?,'Price the first ten')",
                       (self.clock, self.clock, str(uuid.uuid4())))
        hub.q("UPDATE tasks SET goal_id=?, why=? WHERE id=?",
              (goal, "vps is the only agent with the deploy secret", self.task))
        self.new_task(owner="studio", state="completed", outcome="completed", delivered=self.clock, what="Copy written.")
        hub.ins("INSERT INTO questions(task,asker,requester,text,asked) VALUES(?,?,?,?,?)",
                (self.task, "vps", "manager", "Which login do I use?", self.clock))
        hub.ins("INSERT INTO needs(title,why,todo,raised,by) VALUES(?,?,?,?,'manager')",
                ("A Stripe account", "the shop takes no money yet", "open one", self.clock))
        self.assertFalse(self.report()[1])
        said = hub.manager_resume_text()
        self.assertIn("G-1 [active] Open the shop -> next: Price the first ten", said)
        hub.ins("INSERT INTO goal_steps(goal,n,text,task,state,created,updated) "
                "VALUES(?,1,'Write the shop pages',?,'doing',?,?)", (goal, self.task, self.clock, self.clock))
        hub.ins("INSERT INTO goal_steps(goal,n,text,task,state,created,updated) "
                "VALUES(?,2,'Price the first ten',NULL,'todo',?,?)", (goal, self.clock, self.clock))
        said = hub.manager_resume_text()            # the plan's own step comes before the goal's next_step line
        self.assertIn("next: Write the shop pages (T-1)", said)
        self.assertIn("you gave it because: vps is the only agent with the deploy secret", said)
        self.assertIn("Results waiting for your check", said)
        self.assertIn("Q-1 from vps", said)
        self.assertIn("UP-1", said)
        self.assertIn("N-1 A Stripe account", said)
        self.assertIn("Then call read_messages", said)
        # the team directory and the manager's parts of the rules are the brief's too (plan P9.1 and P9.3): see_team
        # never carried them, so the comparison with see_team leaves them out
        brief = said.replace(hub.team_start_text(hub.manager_name()), "").replace(hub.manager_parts_line(), "")
        self.assertLess(len(brief), len(hub.overview_text()))
        self.assertLess(len(brief.splitlines()), 20)

    def test_an_empty_fleet_s_brief_says_so_in_a_line_each(self):
        hub.q("DELETE FROM tasks")
        said = hub.manager_resume_text()
        self.assertIn("No goal is open.", said)
        self.assertIn("No task is open.", said)

    def test_the_helper_takes_the_brief_with_the_generation_and_a_worker_gets_none(self):
        code, answer = self.request("/events/manager?after=-1&wait=0", source="127.0.0.2")
        self.assertEqual(code, 200)
        self.assertEqual(answer["db"], "test-generation")
        self.assertIn("Where the fleet stands", answer["resume"])
        code, answer = self.request("/events/vps?after=-1&wait=0", source="127.0.0.3")
        self.assertEqual((code, answer["resume"]), (200, None))


class OwnerScreen(Base):
    """What the hub's two new findings put on the owner's own screen. His rule, 19 October 2026: a screen that
    reports something wrong must carry the way to put it right. And the other half of it: he is told only what the
    manager has already had and not settled, because a circle the hub noticed a minute ago is the manager's to
    decide and interrupting him with it is the drowning this work set out to stop."""

    def warnings(self):
        code, health = self.request("/ui/health?db=test-generation")
        self.assertEqual(code, 200)
        return {w["kind"]: w for w in health["warnings"]}

    def turn_of_the_manager(self, at=None):
        """The manager's helper reports that its session ended a turn (plan C1)."""
        hub.kv_set("turn_ended:manager", self.clock if at is None else at)

    def test_a_fresh_circle_is_the_manager_s_and_one_it_leaves_unread_after_a_turn_is_his_too(self):
        """Plan C10: no clock. The owner sees a circle only while the manager had a turn after it was told of it and
        left that message unread, so nobody is acting on it."""
        self.new_task(restarts=3, title="The task that keeps starting")
        hub.circle_sweep(self.clock)
        self.assertEqual(len(self.said()), 1)                       # the manager is told at once
        self.assertNotIn("circles_stuck", self.warnings())          # the owner is not
        self.clock += 7 * 86400
        self.assertNotIn("circles_stuck", self.warnings())          # a week with no turn of the manager's: nothing
        self.turn_of_the_manager()
        w = self.warnings()["circles_stuck"]
        # T-37: how many, who is not acting, and the one way on; the circle's own line is the manager's
        self.assertEqual((w["detail"], w["fix"]), ("Manager has not acted on 1 loop it was told of.",
                                                   "Tell Manager what to do about it."))
        self.assertIn("lost 3 sessions in a row that left nothing", self.said()[0])
        self.assertEqual(w["agent"], "manager")
        hub.q("UPDATE events SET read_at=? WHERE agent='manager'", (self.clock,))
        self.assertNotIn("circles_stuck", self.warnings())          # it read it: the decision is its own
        hub.q("UPDATE tasks SET restarts=0")                        # the circle is gone
        self.clock += 16 * 60
        hub.circle_sweep(self.clock)
        self.assertIsNone(hub.kv_get("circle_watch"))

    def test_a_circle_that_comes_back_later_is_a_new_notice(self):
        again = self.new_task(restarts=3, title="The task that keeps starting")
        hub.circle_sweep(self.clock)
        first = hub.kv_get("circle_notice")
        hub.q("UPDATE events SET read_at=? WHERE id=?", (self.clock, int(first)))
        hub.q("UPDATE tasks SET restarts=0 WHERE id=?", (again,))
        self.clock += 3600
        hub.circle_sweep(self.clock)                                # it went: it leaves the map
        hub.q("UPDATE tasks SET restarts=3 WHERE id=?", (again,))
        self.clock += 3600
        hub.circle_sweep(self.clock)                                # it came back: told again
        self.assertNotEqual(hub.kv_get("circle_notice"), first)
        self.turn_of_the_manager(self.clock + hub.LATER_WAIT - 1)   # a turn before that message woke it
        self.assertNotIn("circles_stuck", self.warnings())
        self.turn_of_the_manager(self.clock + hub.LATER_WAIT + 1)
        self.assertIn("circles_stuck", self.warnings())

    def test_a_report_reaches_his_screen_only_when_nobody_is_deciding_it(self):
        parent = self.new_task(owner="lead", requester="manager", title="Ship the shop")
        hub.q("INSERT INTO attempts(task,attempt,created,reason) VALUES(?,1,?,'created')", (parent, self.clock))
        sub = self.new_task(owner="hand", requester="lead", parent=parent)
        self.assertFalse(self.report("vps")[1])
        self.assertFalse(self.report("hand", task=sub, text="The theme is broken on mobile.")[1])
        hub.call_tool("manager", "read_messages", {})               # its closing empty read (plan C9)
        self.assertEqual(len([t for t in self.said() if "You read these and left them open" in t]), 1)   # told
        self.assertNotIn("reports_undecided", self.warnings())      # the owner is not
        self.clock += 7 * 86400
        self.assertNotIn("reports_undecided", self.warnings())      # plan C10: no clock
        self.turn_of_the_manager()                                  # it had a turn and left the message unread
        w = self.warnings()["reports_undecided"]
        # T-37: how many, and the one way on, with no tool's name
        self.assertEqual((w["detail"], w["fix"]), ("1 report from your agents waits for a decision.",
                                                   "Ask Manager to decide it."))
        self.assertEqual(w["agent"], "manager")
        # The lead's own report is named to it in its task's session, and counts by that session's turns.
        chase = hub.requester_chase("lead", self.clock, task=hub.q1("SELECT * FROM tasks WHERE id=?", (parent,)))
        hub.chased("lead", chase[1], hub.emit("lead", "say", chase[0], task=parent))
        self.assertIn("1 report from", self.warnings()["reports_undecided"]["detail"])
        hub.q("UPDATE attempts SET turn=? WHERE task=?", (json.dumps({"session": "s", "seq": 9, "turns": 1,
                                                                      "running": False, "how": "end_turn",
                                                                      "at": self.clock + 1, "calls": {},
                                                                      "said": None}), parent))
        # The owner, 29 October 2026: what a lead leaves unread goes to the manager first, and reaches his screen
        # only when the manager had a turn after that and left it unread too.
        self.assertIn("1 report from", self.warnings()["reports_undecided"]["detail"])
        hub.lead_unread_sweep(self.clock)
        self.assertIn("UP-2 [outside_task] from hand: lead was named it to decide", self.said()[-1])
        self.turn_of_the_manager(self.clock + 2)
        w = self.warnings()["reports_undecided"]
        # one way on: the manager decides, and asks the lead that owes one itself
        self.assertEqual((w["detail"], w["fix"]), ("2 reports from your agents wait for a decision.",
                                                   "Ask Manager to decide them."))
        self.assertFalse(self.tool("manager", "decide_report", report_id="UP-1", decision="noted")[1])
        self.assertFalse(self.tool("lead", "decide_report", task=parent, report_id="UP-2", decision="wrong")[1])
        self.assertNotIn("reports_undecided", self.warnings())      # decided is decided

    def test_a_lesson_for_others_never_reaches_his_screen(self):
        self.assertFalse(self.report(kind="lesson_for_others", text="A fact the others need.")[1])
        hub.call_tool("manager", "read_messages", {})
        self.clock += 60
        self.turn_of_the_manager()
        self.assertNotIn("reports_undecided", self.warnings())      # it wants a knowledge file, not a decision

    def test_both_new_warnings_carry_the_way_out_and_name_an_agent_this_fleet_has(self):
        self.new_task(restarts=3, title="The task that keeps starting")
        hub.circle_sweep(self.clock)
        self.assertFalse(self.report()[1])
        hub.call_tool("manager", "read_messages", {})               # reads the circles
        hub.call_tool("manager", "read_messages", {})               # its closing empty read names the report
        self.clock += hub.LATER_WAIT + 60
        hub.q("UPDATE tasks SET restarts=0")
        hub.circle_sweep(self.clock)
        hub.q("UPDATE tasks SET restarts=3")
        self.clock += hub.LATER_WAIT + 60
        hub.circle_sweep(self.clock)                                # told again, and not read
        self.clock += hub.LATER_WAIT + 60
        self.turn_of_the_manager()
        got = self.warnings()
        for kind in ("circles_stuck", "reports_undecided"):
            self.assertIn(kind, got)
            self.assertTrue(got[kind]["detail"].strip(), kind)
            self.assertTrue(got[kind]["fix"].strip(), kind)
            self.assertIn(got[kind]["agent"], hub.agents(), kind)


class Bugs(Base):
    def test_the_why_of_a_task_is_in_the_lists_an_agent_reads(self):
        hub.q("UPDATE tasks SET why=? WHERE id=?", ("vps is the only agent with the deploy secret", self.task))
        self.assertIn("given to vps because: vps is the only agent with the deploy secret", hub.overview_text())
        parent = self.new_task(owner="lead", requester="manager", title="Ship the shop")
        sub = self.new_task(owner="hand", requester="lead", parent=parent, why="hand knows the shop's theme")
        earlier = self.new_task(owner="hand", requester="lead", state="completed", outcome="completed",
                                accepted=0, check_note="the theme was not changed", why="it had done it before",
                                title="An earlier task of the lead")
        hub.q("UPDATE tasks SET created=? WHERE id=?", (self.clock - 3 * 86400, earlier))
        said = hub.lead_overview("lead", parent)
        self.assertIn("you gave it to hand because: hand knows the shop's theme", said)
        self.assertIn("WHAT YOU GAVE OUT IN THE LAST 14 DAYS", said)
        self.assertIn("An earlier task of the lead", said)
        self.assertIn("NOT accepted: the theme was not changed", said)
        self.assertIn("because: it had done it before", said)
        hub.q("UPDATE tasks SET created=? WHERE id=?", (self.clock - 30 * 86400, earlier))
        self.assertNotIn("An earlier task of the lead", hub.lead_overview("lead", parent))

    def test_a_lead_reads_its_team_s_duty_markers_and_writes_nothing_to_them(self):
        duty = hub.ins("INSERT INTO responsibilities(agent,text,state,revision,created,updated,created_by,request_id,"
                       "marker_kind,marker_detail) VALUES('hand','Keep the shop online.','active',1,?,?,'manager',?,"
                       "'no_watch','This duty has no watch.')", (self.clock, self.clock, str(uuid.uuid4())))
        parent = self.new_task(owner="lead", requester="manager", title="Ship the shop")
        said = hub.lead_overview("lead", parent)
        self.assertIn(f"{hub.rref(duty)} Keep the shop online", said)
        self.assertIn("NOT IN ORDER: no watch", said)

    def test_two_agents_may_talk_until_twenty_messages_with_no_work_between_them(self):
        self.assertEqual(hub.TALK_GUARD, 20)
        talk = lambda: hub.ins("INSERT INTO agent_messages(sender,recipient,text,created,request_id) VALUES(?,?,?,?,?)",
                               ("vps", "studio", "What about the feed?", hub.now(), str(uuid.uuid4())))
        for n in range(hub.TALK_GUARD - 1):
            talk()
        self.assertIsNone(hub.agent_limit("vps", "studio", None, self.clock))
        talk()
        says = hub.agent_limit("vps", "studio", None, self.clock)
        self.assertIn("20 messages with no work of either of you between them", says)
        self.assertIn("open a task for it, or ask your requester", says)
        time.sleep(0.01)
        hub.ins("INSERT INTO questions(task,asker,requester,text,asked) VALUES(?,?,?,?,?)",
                (self.task, "studio", "manager", "Which feed?", hub.now()))
        self.assertIsNone(hub.agent_limit("vps", "studio", None, self.clock))    # a question is work

    def test_the_owner_is_not_asked_for_what_the_manager_may_already_give(self):
        text, err = self.tool("manager", "raise_needs_you", title="vps needs the shop login",
                              why=f"it cannot sign in: {LOGIN}", what_to_do="grant it")
        self.assertTrue(err)
        self.assertIn("That is yours to give; use grant_access", text)
        self.assertIn(f'resource="secret:{LOGIN}"', text)
        self.assertIn("raise it again without naming", text)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs")["n"], 0)
        text, err = self.tool("manager", "raise_needs_you", title="A Stripe account",
                              why="the shop takes no money yet", what_to_do="open one")
        self.assertFalse(err, text)                     # genuinely new: it reaches the owner as before
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs")["n"], 1)

    def test_a_normal_runtime_switch_shows_everywhere_and_wakes_nobody(self):
        hub.q("INSERT INTO agents(name,alive,alive_ts) VALUES('manager','',?) "
              "ON CONFLICT(name) DO UPDATE SET alive='', alive_ts=excluded.alive_ts", (self.clock,))
        hub.kv_set("switching:manager", self.clock)
        hub.tick()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "switching")
        self.assertIn("switches to Claude Code", hub.kv_get("mgr_flag"))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE agent='owner' AND kind='notify'")["n"], 0)
        self.clock += 7 * 86400                     # plan C10: no clock turns a long switch into a warning
        hub.tick()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "switching")
        hub.kv_set("mgr_screen_shown", self.clock)  # its previous session shows a question: that is the fact
        hub.tick()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "switch_stalled")
        self.assertEqual(hub.kv_get("mgr_flag"), "The manager's switch to Claude Code waits on a question.")
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE agent='owner' AND kind='notify'")["n"], 1)

    def test_a_grant_is_written_into_the_owner_s_chat_with_no_notification(self):
        with patch.object(hub, "grant_resource", return_value={"changed": True, "revision": "abcdef123456789"}):
            text, err = self.tool("manager", "grant_access", request_id=str(uuid.uuid4()), agent="vps",
                                  resource=f"secret:{LOGIN}", level="use",
                                  why="T-1 cannot deploy without the shop login.")
        self.assertFalse(err, text)
        row = hub.q1("SELECT * FROM owner_reports ORDER BY id DESC LIMIT 1")
        self.assertEqual(row["agent"], "manager")
        self.assertIn("vps now holds", row["text"])
        self.assertIn("at level use", row["text"])
        self.assertIn("I gave it because: T-1 cannot deploy without the shop login. The grant", row["text"])
        self.assertIn("Resources page", row["text"])
        self.assertEqual(f"grant secret:{LOGIN} to vps", row["about"])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE agent='owner' AND kind='notify'")["n"], 0)


if __name__ == "__main__":
    unittest.main()

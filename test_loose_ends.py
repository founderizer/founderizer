"""Work that nothing could finish: a thing left open that no agent and no owner action could settle (UI-API.md 1.43).

Each class is one such thing, found in the review of 23 October 2026 of how agents pass work to each other, and each
check first does what the fleet did when it went wrong. In-process hub, a temporary database and a set clock where
the check needs one; no helper, no fleet and no AI call.

- A question that meets a cancel: the canceled task came back as input-required.
- A permission prompt that outlives its session or the hub: its task stayed input-required for the rest of its life.
- A steer of an earlier attempt: the helper told the new session of it for the life of the task. Since 28 October an
  unread steer moves to the new attempt, which reads it once.
- A report to a lead whose task has ended: nobody could decide it, and the owner's warning stood for ever.
- A duty's case that its task left open: its watch started nothing for that key again, and nothing said so.
- The manager's lists: another agent's work and questions of ended tasks, as the manager's own to do.
- The notice that gives a worker a duty: it was filed under no task, and a worker reads only in a task session.

The classes from Reviewed on are what two adversarial reviews of that work found on 24 October 2026, in it and around
it: a request that a hub restart called "not sent", a lead nudged for waiting on its team, a case its own task could
not close, and the rest below.
"""
import threading
import time
import uuid
import unittest
from unittest.mock import patch

import hub
import test_call_api
import test_report_up
import test_responsibilities
from test_runtime import Runtime


def load_tests(loader, _tests, _pattern):
    """Only this file's own checks: the classes below inherit their fixtures' helpers, not their tests."""
    suite = unittest.TestSuite()
    for cls in (AskMeetsCancel, StalePrompt, StaleSteer, LeadReports, ManagerLists, CaseLeftOpen, DutyNotice,
                Reviewed, ReviewedNotices, ReviewedCases, ReviewedRequests, ReviewedLeads):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class AskMeetsCancel(Runtime):
    """ask_my_requester reads its task before it takes the lock."""

    def ask_while_canceled(self, **ask):
        """The requester's cancel lands right after the asker read its task, and before the asker's lock."""
        tid = self.task()
        real = hub.get_task

        def get_task(task_id, owner=None, requester=None):
            row = real(task_id, owner=owner, requester=requester)
            if owner == "studio":
                hub.t_cancel_task("manager", {"task_id": hub.tref(tid), "reason": "not needed"})
            return row
        with patch.object(hub, "get_task", get_task):
            said = self.tool("studio", "ask_my_requester", tid, question="Which logo?", **ask)
        return tid, said

    def test_a_question_that_meets_a_cancel_leaves_the_task_canceled(self):
        tid, (said, err) = self.ask_while_canceled()
        self.assertTrue(err, said)
        self.assertIn("already canceled", said)
        row = hub.q1("SELECT state, outcome, waiting_on FROM tasks WHERE id=?", (tid,))
        self.assertEqual(tuple(row), ("canceled", "canceled", None))        # it was input-required, waiting on Q-1
        self.assertEqual(hub.q("SELECT id FROM questions"), [])

    def test_so_does_a_question_with_a_default(self):
        tid, (said, err) = self.ask_while_canceled(default="the blue one")
        self.assertTrue(err, said)
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (tid,))["state"], "canceled")
        self.assertEqual(hub.q("SELECT id FROM questions"), [])
        self.assertFalse([t for t in self.said("manager") if "Question Q-" in t])     # nobody is asked about it

    def test_a_question_never_waits_inside_its_call(self):
        """No call waits for a person or an agent: the question returns at once, and its answer is a message."""
        tid = self.task()

        def sleep(_seconds):
            raise AssertionError("ask_my_requester waited inside its call")
        with patch.object(hub.time, "sleep", sleep):
            said, err = self.tool("studio", "ask_my_requester", tid, question="Which logo?")
        self.assertFalse(err, said)
        self.assertEqual(said, f"Q-1 is with manager, and T-{tid} is paused: the answer comes as a message in this "
                               f"session. Stop working on T-{tid} now.")
        hub.t_answer("manager", {"question_id": "Q-1", "text": "Blue."})
        self.assertIn("Answer to your question Q-1", self.said("studio")[-1])


class StalePrompt(Runtime):
    """A permission prompt is answered through the hook call that waits for it, and only that call ended the wait.
    The real clock: `hook_wait` is 2 seconds in this fixture and the route sleeps until it passes."""

    def hook(self, tid):
        code, body = self.call("POST", f"/hook/permission/studio/T-{tid}",
                               {"tool_name": "Bash", "tool_input": {"command": "make deploy"},
                                "generation": "gen1", "attempt": 1}, client=None)
        self.assertEqual(code, 200, body)
        return body["hookSpecificOutput"]["decision"]

    def test_a_prompt_that_outlives_its_session_leaves_the_task_working(self):
        tid = self.task()
        out = {}
        th = threading.Thread(target=lambda: out.update(decision=self.hook(tid)))
        th.start()
        for _ in range(100):
            if hub.q1("SELECT waiting_on FROM tasks WHERE id=?", (tid,))["waiting_on"] == "P-1":
                break
            time.sleep(0.02)
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (tid,))["state"], "input-required")
        hub.new_attempt(hub.q1("SELECT * FROM tasks WHERE id=?", (tid,)), "restart")    # liveness: the session was lost
        th.join(10)
        self.assertEqual(out["decision"]["behavior"], "deny")
        self.assertEqual(tuple(hub.q1("SELECT state, waiting_on, attempt FROM tasks WHERE id=?", (tid,))),
                         ("working", None, 2))          # it stayed input-required, waiting on P-1, for good
        self.assertEqual(hub.q1("SELECT decision FROM prompts WHERE id=1")["decision"], "expired")

    def test_a_hub_restart_ends_the_wait_on_a_prompt_and_keeps_a_question(self):
        asked, prompted = self.task(), self.task()
        self.assertFalse(self.tool("studio", "ask_my_requester", asked, question="Which logo?")[1])
        pid = hub.ins("INSERT INTO prompts(task,agent,tool,input,key,created) VALUES(?,?,?,?,?,?)",
                      (prompted, "studio", "Bash", "make deploy", "k", hub.now()))
        hub.q("UPDATE tasks SET state='input-required', waiting_on=? WHERE id=?", (f"P-{pid}", prompted))
        hub.settle_stopped_calls()
        self.assertEqual(tuple(hub.q1("SELECT state, waiting_on FROM tasks WHERE id=?", (prompted,))),
                         ("working", None))
        self.assertEqual(hub.q1("SELECT decision FROM prompts WHERE id=?", (pid,))["decision"], "expired")
        self.assertEqual(tuple(hub.q1("SELECT state, waiting_on FROM tasks WHERE id=?", (asked,))),
                         ("input-required", "Q-1"))     # a question is still asked, and its answer still comes

    def test_an_ask_whose_session_was_replaced_still_gets_its_answer(self):
        tid = self.task()
        said, err = self.tool("studio", "ask_my_requester", tid, question="Which logo?")
        self.assertFalse(err, said)
        hub.new_attempt(hub.q1("SELECT * FROM tasks WHERE id=?", (tid,)), "reminder")      # the session went
        hub.t_answer("manager", {"question_id": "Q-1", "text": "Blue."})
        self.assertIn("Answer to your question Q-1", self.said("studio")[-1])     # it reached nobody


class StaleSteer(Runtime):
    """A steer is bound to its attempt (1.4) until a session reads it: an unread one moves to the task's next attempt
    (hub.carry_steers, 28 October 2026), so the new session reads it once, and nothing stays pending for ever."""

    def steer(self, tid, text):
        code, body = self.call("POST", f"/ui/tasks/{tid}/steer", dict(request_id=str(uuid.uuid4()), db="gen1",
                                                                     text=text))
        self.assertEqual(code, 200, body)

    def test_a_steer_of_an_earlier_attempt_reaches_the_new_session_once(self):
        tid = self.task()
        self.steer(tid, "Use the blue logo.")
        hub.new_attempt(hub.q1("SELECT * FROM tasks WHERE id=?", (tid,)), "restart")   # lost before it read it
        self.assertEqual(sorted(e["kind"] for e in self.delivered("studio")), ["say", "task"])
        text, err = self.tool("studio", "read_messages", tid)
        self.assertFalse(err, text)
        self.assertIn("blue logo", text)
        # what the helper is handed now is nothing at all: before, the steer stayed pending for ever
        self.assertEqual(self.delivered("studio"), [])
        self.steer(tid, "Use the red logo after all.")          # one for this attempt still reaches it
        self.assertEqual([e["text"].startswith(f"[owner] Steering from the owner for T-{tid}: Use the red")
                          for e in self.delivered("studio")], [True])
        self.assertIn("red logo", self.tool("studio", "read_messages", tid)[0])


class LeadReports(test_report_up.Base):
    """A lead decides its subtasks' reports in the session of their parent task, and in no other."""

    def setUp(self):
        super().setUp()
        self.parent = self.new_task(owner="lead", requester="manager", title="Ship the shop")
        self.sub = self.new_task(owner="hand", requester="lead", parent=self.parent)
        self.assertFalse(self.report("hand", task=self.sub, text="The theme is broken on mobile.")[1])

    def end_parent(self, state="completed"):
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (self.sub,))
        hub.q("UPDATE tasks SET state=?, delivered=? WHERE id=?", (state, self.clock, self.parent))

    def test_while_the_lead_s_task_runs_the_report_is_the_lead_s(self):
        text, err = self.tool("manager", "decide_report", report_id="UP-1", decision="noted")
        self.assertTrue(err, text)
        self.assertIn("was reported to lead, not to you", text)
        self.assertNotIn("Reports waiting for your decision", hub.manager_resume_text())

    def test_once_the_lead_s_task_has_ended_the_manager_decides_it(self):
        for state in ("completed", "canceled"):
            with self.subTest(state=state):
                self.end_parent(state)
                other = self.new_task(owner="lead", requester="manager", title="The next thing")
                text, err = self.tool("lead", "decide_report", task=other, report_id="UP-1", decision="noted")
                self.assertTrue(err, text)          # its next task is another parent: it can never decide this one
                self.assertIn("Reports waiting for your decision (1):\n  UP-1", hub.manager_resume_text())
        text, err = self.tool("manager", "decide_report", report_id="UP-1", decision="task", became_task="T-1",
                              note="vps fixes the theme")
        self.assertFalse(err, text)
        r = hub.q1("SELECT * FROM reports WHERE id=1")
        self.assertEqual((r["decided_by"], r["decision"]), ("manager", "task"))
        self.assertNotIn("Reports waiting for your decision", hub.manager_resume_text())

    def test_the_chase_and_the_owner_s_screen_say_whose_it_is(self):
        self.end_parent()
        hub.call_tool("manager", "read_messages", {})               # its closing empty read (plan C9)
        said = self.said()[-1]
        self.assertIn("UP-1 [outside_task] from hand waits for decide_report", said)
        hub.kv_set("turn_ended:manager", self.clock + 1)     # plan C10: it had a turn and left that message unread
        code, health = self.request("/ui/health?db=test-generation")
        w = {x["kind"]: x for x in health["warnings"]}["reports_undecided"]
        self.assertNotIn("owe(s) one", w["fix"])       # no lead can decide it, so the manager is not sent to one
        self.assertFalse(self.tool("manager", "decide_report", report_id="UP-1", decision="noted")[1])
        code, health = self.request("/ui/health?db=test-generation")
        self.assertNotIn("reports_undecided", {x["kind"] for x in health["warnings"]})

    def test_the_manager_hears_of_it_once_when_the_lead_s_task_ends(self):
        hub.call_tool("manager", "read_messages", {})
        self.assertEqual([t for t in self.said() if "UP-1" in t], [])  # the lead's, while its task runs
        self.end_parent()
        hub.call_tool("manager", "read_messages", {})                   # its closing empty read (plan C9)
        told = len(self.said())
        self.assertIn("UP-1 [outside_task] from hand waits for decide_report", self.said()[-1])
        hub.call_tool("manager", "read_messages", {})
        hub.call_tool("manager", "read_messages", {})
        self.assertEqual(len(self.said()), told)                        # and once

    def test_an_agent_that_no_longer_leads_leaves_its_reports_to_the_manager(self):
        hub.TEAM["agents"]["lead"]["role"] = "worker"
        self.assertTrue(hub.report_for_manager(hub.q1("SELECT * FROM reports WHERE id=1")))
        self.assertFalse(self.tool("manager", "decide_report", report_id="UP-1", decision="noted")[1])


class ManagerLists(test_report_up.Base):
    """The manager's resume brief and see_team: what the manager itself can act on."""

    def test_a_lead_s_question_and_its_subtask_s_result_are_not_the_manager_s_to_do(self):
        parent = self.new_task(owner="lead", requester="manager", title="Ship the shop")
        sub = self.new_task(owner="hand", requester="lead", parent=parent)
        text, err = self.tool("hand", "ask_my_requester", task=sub, question="Which colour?")
        self.assertFalse(err, text)
        brief = hub.manager_resume_text()
        self.assertNotIn("Which colour?", brief)        # answer() refuses the manager: it was asked of the lead
        team = hub.overview_text()
        self.assertIn("asked of lead, which answers it: Which colour?", team)
        hub.q("UPDATE tasks SET state='completed', outcome='completed', what='Theme fixed', delivered=? WHERE id=?",
              (self.clock, sub))
        self.assertNotIn(f"T-{sub}", hub.manager_resume_text().split("Results waiting")[-1])
        self.assertNotIn("Theme fixed", hub.overview_text())    # check_result refuses the manager this one too
        mine = self.new_task(state="completed", outcome="completed", what="Deploy fixed", delivered=self.clock)
        self.assertIn(f"Results waiting for your check: T-{mine}", hub.manager_resume_text())
        self.assertIn("Deploy fixed", hub.overview_text())

    def test_a_question_of_an_ended_task_is_neither_chased_nor_listed(self):
        text, err = self.tool("vps", "ask_my_requester", question="Staging or production?")
        self.assertFalse(err, text)
        self.assertIn("Staging or production?", hub.manager_resume_text())
        self.assertFalse(self.tool("manager", "cancel_task", task_id=hub.tref(self.task), reason="not needed")[1])
        self.clock += 10 * hub.CFG["question_wait"]
        hub.tick()
        self.assertFalse([t for t in self.said() if "has waited" in t])
        self.assertNotIn("Staging or production?", hub.manager_resume_text())
        self.assertNotIn("Staging or production?", hub.overview_text())
        text, err = self.tool("manager", "answer", question_id="Q-1", text="Staging.")
        self.assertFalse(err, text)
        self.assertIn(f"T-{self.task} is already canceled, so no session of it reads this answer", text)

    def test_a_question_asked_with_a_default_waits_on_nobody_in_the_brief(self):
        text, err = self.tool("vps", "ask_my_requester", question="Metric or imperial?", default="metric")
        self.assertFalse(err, text)
        self.assertNotIn("Metric or imperial?", hub.manager_resume_text())
        self.assertIn("NOT WAITING", hub.overview_text())          # see_team still says what it went on with


class CaseLeftOpen(test_responsibilities.Base):
    """No result closes a case, and one key has one open case: a case whose last task failed marks its duty."""

    def setUp(self):
        super().setUp()
        self.r = self.duty(watch=[{"kind": "check", "check": test_responsibilities.CHECK}])
        self.rule = self.watches(self.r["id"])[0]["id"]
        self.assertEqual(self.fire(self.rule)["state"], "started")
        self.case_task = self.first_case_task()

    def fail(self):
        text, err = self.tool("vps", "deliver_result", task_id=hub.tref(self.case_task["id"]), outcome="failed",
                              what_was_done="The provider is down and nobody answers")
        self.assertFalse(err, text)

    def test_a_failed_case_task_says_the_case_stays_open_and_the_duty_is_marked(self):
        self.fail()
        result = self.manager_said()[-1]
        self.assertIn("R-1/C-1 is still open and no task works it", result)
        self.assertIn("close_case", result)
        run = self.fire(self.rule, when=self.clock + 1800)
        self.assertNotEqual(run["state"], "started")                # what the marker is about: the watch is blocked
        self.sweep(self.clock + 60)
        r = hub.duty_row(self.r["id"])
        self.assertEqual(r["marker_kind"], "case_left_open")
        self.assertIn(f"Its last task T-{self.case_task['id']} ended failed", r["marker_detail"])
        text, err = self.tool("manager", "close_case", request_id=str(uuid.uuid4()), case="R-1/C-1",
                              outcome="failed", note="The provider is down")
        self.assertFalse(err, text)
        self.sweep(self.clock + 60)
        self.assertIsNone(hub.duty_row(self.r["id"])["marker_kind"])
        self.assertEqual(self.fire(self.rule, when=self.clock + 3600)["state"], "started")     # it reacts again

    def test_a_canceled_case_task_says_so_to_whoever_canceled_it(self):
        text, err = self.tool("manager", "cancel_task", task_id=hub.tref(self.case_task["id"]), reason="not needed")
        self.assertFalse(err, text)
        self.assertIn("R-1/C-1 is still open and no task works it", text)

    def test_a_completed_case_task_leaves_its_case_open_and_marks_no_duty(self):
        """A task is often one part of its case. Its result says that the case is still open, and the case then waits
        for its next step without a mark on its duty, because a mark starts a review."""
        text, err = self.tool("vps", "deliver_result", task_id=hub.tref(self.case_task["id"]), outcome="completed",
                              what_was_done="Signed the pool in again", where_output_is="commit a95cee6",
                              how_checked="8 accounts signed in")
        self.assertFalse(err, text)
        self.assertIn("R-1/C-1 is still open and no task works it", self.manager_said()[-1])
        self.assertEqual(self.case()["state"], "open")
        self.sweep(self.clock + 60)
        self.assertIsNone(hub.duty_row(self.r["id"])["marker_kind"])

    def test_create_task_gives_an_open_case_s_work_and_its_worker_closes_the_case(self):
        self.fail()
        text, err = self.tool("manager", "create_task", owner="studio", title="Move the pool to the other provider",
                              done_when="The pool reports signed-in accounts", case_id="R-1/C-1")
        self.assertFalse(err, text)
        self.assertIn("It is work of R-1/C-1", text)
        t = hub.q1("SELECT * FROM tasks ORDER BY id DESC LIMIT 1")
        self.assertEqual((t["duty_case"], t["responsibility"], t["case_id"]), (1, self.r["id"], None))
        self.assertIn("This is case R-1/C-1", t["details"])
        self.sweep(self.clock + 60)
        self.assertIsNone(hub.duty_row(self.r["id"])["marker_kind"])        # work of it is open again
        text, err = self.tool("studio", "close_case", request_id=str(uuid.uuid4()), case="R-1/C-1",
                              outcome="handled", note="Moved the pool", task_id=hub.tref(t["id"]))
        self.assertFalse(err, text)
        text, err = self.tool("studio", "deliver_result", task_id=hub.tref(t["id"]), outcome="completed",
                              what_was_done="Moved the pool", where_output_is="commit 9998f42",
                              how_checked="8 accounts signed in")
        self.assertFalse(err, text)
        c = self.case()
        self.assertEqual((c["state"], c["outcome"]), ("closed", "handled"))

    def test_create_task_refuses_a_closed_case_and_a_value_that_is_no_case(self):
        text, err = self.tool("vps", "close_case", request_id=str(uuid.uuid4()), case="R-1/C-1", outcome="handled",
                              note="Signed the pool in again", task_id=hub.tref(self.case_task["id"]))
        self.assertFalse(err, text)
        text, err = self.tool("manager", "create_task", owner="vps", title="Again", done_when="Done",
                              case_id="R-1/C-1")
        self.assertTrue(err, text)
        self.assertIn("R-1/C-1 is closed (handled). A new event is a new case.", text)
        text, err = self.tool("manager", "create_task", owner="vps", title="Again", done_when="Done",
                              case_id="C-9")
        self.assertTrue(err, text)
        self.assertIn("There is no case C-9", text)
        text, err = self.tool("manager", "create_task", owner="vps", title="Again", done_when="Done",
                              case_id="run7-3")
        self.assertTrue(err, text)
        self.assertIn("Unknown case_id", text)


class DutyNotice(test_responsibilities.Base):
    """A worker reads only in a task session, and only the messages of that task."""

    def new_task(self, title):
        text, err = self.tool("manager", "create_task", owner="vps", title=title, done_when="Done")
        self.assertFalse(err, text)
        return hub.q1("SELECT * FROM tasks ORDER BY id DESC LIMIT 1")

    def delivered(self):
        code, data = self.request("/events/vps?delivery=1&after=0&wait=0", source="127.0.0.3")
        self.assertEqual(code, 200, data)
        return [(e["kind"], e["task"], e["text"]) for e in data["events"]]

    def read(self, task):
        text, err = self.tool("vps", "read_messages", task_id=hub.tref(task["id"]))
        self.assertFalse(err, text)
        return text

    def test_the_notice_of_a_new_duty_reaches_the_holder_s_next_task_session(self):
        running = self.new_task("Fix the render queue")
        self.read(running)                                  # its session reads its start
        self.duty()                                         # the manager gives vps a duty meanwhile
        self.assertNotIn("New duty", self.read(running))    # a running task is not interrupted by it
        self.assertFalse([e for e in self.delivered() if "New duty" in e[2]])
        nxt = self.new_task("Answer the support mailbox")
        said = self.read(nxt)
        self.assertIn("[duty R-1] New duty for vps, from manager", said)
        self.assertIn("do the task of that session", said)
        self.assertIn("open_case", said)
        later = self.new_task("Write the weekly note")
        self.assertNotIn("New duty", self.read(later))      # read once, and so delivered once
        self.assertTrue(any("New duty for vps" in t for t in self.manager_said()))      # the manager's own copy
        self.assertNotIn("do the task of that session", self.manager_said()[-1])

    def test_a_moved_duty_tells_its_new_holder_at_its_next_task_session(self):
        r = self.duty()
        told = len(self.manager_said())
        self.change(r["id"], agent="studio")                # the manager moves it: it knows, so it is not told
        self.assertEqual(len(self.manager_said()), told)
        text, err = self.tool("manager", "create_task", owner="studio", title="Check the pool", done_when="Done")
        self.assertFalse(err, text)
        t = hub.q1("SELECT * FROM tasks ORDER BY id DESC LIMIT 1")
        said, err = self.tool("studio", "read_messages", task_id=hub.tref(t["id"]))
        self.assertFalse(err, said)
        self.assertIn("[duty R-1] manager gave R-1 to studio; vps held it until now", said)
        self.assertIn("do the task of that session", said)

    def test_a_lead_s_move_and_change_are_told_to_the_manager(self):
        hub.TEAM["agents"]["lead"] = {"role": "lead", "runtime": "claude", "machine": "vps", "can": ["shell"]}
        for name in ("vps", "studio"):
            hub.TEAM["agents"][name]["reports_to"] = "lead"
        f = hub.check_task("manager", {"owner": "lead", "title": "Ship the autumn theme", "done_when": "It is live"})
        with hub.LOCK, hub.transaction():
            tid = hub.admit_task("manager", f)          # the lead's own task, whose session its team tools work in

        def set_duty(**args):
            text, err = self.tool("lead", "set_duty", task_id=hub.tref(tid), request_id=str(uuid.uuid4()), **args)
            self.assertFalse(err, text)
        set_duty(agent="vps", text="Watch the order queue. When an order sticks, find out why and fix it.",
                 watch=[test_responsibilities.CLOCK_WATCH])
        set_duty(responsibility="R-1", agent="studio")
        self.assertIn("[duty R-1] lead gave R-1 to studio; vps held it until now", self.manager_said()[-1])
        waiting = hub.q("SELECT text FROM events WHERE agent='studio' AND kind='say' AND task IS NULL")
        self.assertEqual(len(waiting), 1)                   # for studio's next task session
        set_duty(responsibility="R-1", text="Watch the order queue and the refund queue. Fix what sticks.")
        self.assertIn("[duty R-1] lead changed R-1 of studio", self.manager_said()[-1])
        self.assertIn("the refund queue", self.manager_said()[-1])
        self.assertEqual(len(hub.q("SELECT id FROM events WHERE agent='studio' AND kind='say'")), 1)

    def test_a_new_session_of_a_task_takes_it_too(self):
        t = self.new_task("Fix the render queue")
        self.read(t)
        self.duty()
        hub.new_attempt(hub.q1("SELECT * FROM tasks WHERE id=?", (t["id"],)), "restart")
        self.assertTrue([e for e in self.delivered() if e[0] == "say" and "New duty" in e[2]])
        text, err = hub.call_tool("vps", "read_messages", {"task_id": hub.tref(t["id"])},
                                  ("test-generation", hub.tref(t["id"]), 2))
        self.assertFalse(err, text)
        self.assertIn("New duty for vps", text)


class Reviewed(Runtime):
    """Sessions and their waits."""

    def setUp(self):
        super().setUp()
        p = patch.object(hub, "STARTED", hub.now() - 86400)     # the hub's own start is not a task's silence
        p.start()
        self.addCleanup(p.stop)

    def test_an_answer_after_the_session_was_replaced_reaches_the_new_session(self):
        tid = self.task()
        said, err = self.tool("studio", "ask_my_requester", tid, question="Which logo?")
        self.assertFalse(err, said)
        hub.new_attempt(hub.q1("SELECT * FROM tasks WHERE id=?", (tid,)), "restart")      # the session was lost
        hub.t_answer("manager", {"question_id": "Q-1", "text": "Blue."})
        text, err = hub.call_tool("studio", "read_messages", {"task_id": hub.tref(tid)}, ("gen1", hub.tref(tid), "2"))
        self.assertFalse(err, text)
        self.assertIn("Answer to your question Q-1", text)
        self.assertIn("Blue.", text)

    def test_an_answer_releases_a_task_whose_screen_showed_a_dialog_while_it_waited(self):
        tid = self.task()
        self.assertFalse(self.tool("studio", "ask_my_requester", tid, question="Which logo?")[1])
        self.assertEqual(self.call("POST", f"/helper/dialog/studio/T-{tid}", {}, client=None)[0], 200)
        self.assertEqual(hub.q1("SELECT waiting_on FROM tasks WHERE id=?", (tid,))["waiting_on"], "its screen")
        self.assertFalse(hub.call_tool("manager", "answer", {"question_id": "Q-1", "text": "Blue."})[1])
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (tid,))["state"], "working")

    def test_a_dialog_does_not_release_a_task_that_still_waits_on_another_question(self):
        tid = self.task()
        for question in ("Which logo?", "Which colour?"):
            self.assertFalse(self.tool("studio", "ask_my_requester", tid, question=question)[1])
        self.call("POST", f"/helper/dialog/studio/T-{tid}", {}, client=None)
        self.assertFalse(hub.call_tool("manager", "answer", {"question_id": "Q-1", "text": "The blue one."})[1])
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (tid,))["state"], "input-required")

    def test_a_limit_reset_leaves_a_parked_task_parked(self):
        t0 = [hub.now()]
        with patch.object(hub, "now", lambda: t0[0]), patch.object(hub, "STARTED", t0[0] - 86400):
            parked, busy = self.task(), self.task()
            self.assertFalse(self.tool("studio", "set_reminder", parked, note="Check the build at six", minutes=300)[1])
            hub.start_limit("studio", t0[0] + 600, busy)
            t0[0] += 600 + 5                                    # plan C9: no grace after the reset
            hub.tick()
            self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (parked,))["attempt"], 1)
            self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (busy,))["attempt"], 2)

    def test_a_decision_that_reached_no_session_is_said_to_its_decider(self):
        tid = self.task()
        out = {}
        th = threading.Thread(target=lambda: out.update(r=self.call(
            "POST", f"/hook/permission/studio/T-{tid}", {"tool_name": "Bash", "tool_input": {"command": "make deploy"},
                                                        "generation": "gen1", "attempt": 1}, client=None)))
        th.start()
        for _ in range(100):
            if hub.q1("SELECT id FROM prompts"):
                break
            time.sleep(0.02)
        # The session was lost: its prompt ends with it (plan C7), so the decider is told at its decision.
        hub.new_attempt(hub.q1("SELECT * FROM tasks WHERE id=?", (tid,)), "restart")
        text, error = hub.call_tool("manager", "decide_permission", {"prompt_id": "P-1", "decision": "allow"})
        self.assertTrue(error, text)
        self.assertIn("P-1 ended before a decision reached it: The session that asked was replaced", text)
        th.join(10)
        self.assertEqual(out["r"][1]["hookSpecificOutput"]["decision"]["behavior"], "deny")
        self.assertEqual(tuple(hub.q1("SELECT state, waiting_on FROM tasks WHERE id=?", (tid,))), ("working", None))
        self.assertIn("replaced", hub.q1("SELECT reason FROM prompts WHERE id=1")["reason"])


class ReviewedLeads(Runtime):
    """A lead that waits for its team."""

    def setUp(self):
        super().setUp()
        p = patch.object(hub, "STARTED", hub.now() - 86400)
        p.start()
        self.addCleanup(p.stop)
        hub.TEAM["agents"]["studio"]["role"] = "lead"
        hub.TEAM["agents"]["vps"]["reports_to"] = "studio"
        self.lead = self.task(owner="studio")
        self.assertFalse(hub.call_tool("studio", "create_task", {"owner": "vps", "title": "Build", "done_when": "Built"},
                                       ("gen1", f"T-{self.lead}", "1"))[1])
        self.sub = hub.q1("SELECT id FROM tasks ORDER BY id DESC LIMIT 1")["id"]
        hub.q("UPDATE tasks SET state='working' WHERE id=?", (self.sub,))
        self.alive("studio", f"T-{self.lead}")

    def test_a_lead_waiting_on_a_working_subtask_is_not_nudged_and_not_called_silent(self):
        hub.q("UPDATE tasks SET last_activity=? WHERE id=?", (hub.now() - 200, self.lead))
        hub.tick()
        self.assertEqual([t for t in self.said("studio") if "No activity" in t], [])
        hub.q("UPDATE tasks SET last_activity=?, nudge_level=1, nudged_at=? WHERE id=?",
              (hub.now() - 400, hub.now() - 200, self.lead))
        hub.tick()
        self.assertEqual([t for t in self.said("manager") if "has been silent" in t], [])
        self.assertEqual([x for x in hub.tasks_stuck(hub.now() + 3 * 3600) if f"T-{self.lead} " in x[1]], [])

    def lead_turn(self, seq):
        """One turn of the lead's session that reads its messages and ends with nothing of its own waiting."""
        hub.q("UPDATE events SET read_at=? WHERE agent='studio' AND read_at IS NULL", (hub.now(),))
        self.assertEqual(self.records(self.lead, [{"seq": seq, "type": "user_message", "text": "Go on."},
                                                  {"seq": seq + 1, "type": "result", "stop_reason": "end_turn"}])[0], 200)

    def test_a_lead_that_a_subtask_waits_on_hears_it_at_its_turn_end_and_then_its_requester_does(self):
        """Plan C9: no clock. At an empty turn end of the lead's session, what its team waits on comes in place of
        the continue; the second empty turn end in a row tells the lead's requester."""
        self.assertFalse(hub.call_tool("vps", "ask_my_requester",
                                       {"task_id": f"T-{self.sub}", "question": "Which theme?"},
                                       ("gen1", f"T-{self.sub}", "1"))[1])
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (self.sub,))["state"], "input-required")
        self.lead_turn(1)
        chase = [t for t in self.said("studio") if t.startswith("[hub] You read these and left them open")]
        self.assertEqual(len(chase), 1)
        self.assertIn(f"on T-{self.sub} waits for your answer: Which theme?", chase[0])
        self.assertEqual([t for t in self.said("studio") if "is open and nothing is waiting" in t], [])
        self.lead_turn(10)
        self.assertTrue([t for t in self.said("manager") if f"T-{self.lead}" in t and "two turns in a row" in t])

    def test_a_lead_delivers_when_the_worker_of_an_unchecked_result_left_its_team(self):
        done = {"outcome": "completed", "what_was_done": "x", "where_output_is": "y", "how_checked": "z"}
        self.assertFalse(hub.call_tool("vps", "deliver_result", dict(done, task_id=f"T-{self.sub}"),
                                       ("gen1", f"T-{self.sub}", "1"))[1])
        hub.TEAM["agents"]["vps"]["reports_to"] = "manager"         # the owner moves vps to the manager's team
        text, err = hub.call_tool("studio", "deliver_result", dict(done, task_id=f"T-{self.lead}"),
                                  ("gen1", f"T-{self.lead}", "1"))
        self.assertFalse(err, text)         # it may not check that result any more, so it is not held to it

    def test_a_lead_that_became_a_worker_delivers_its_task(self):
        done = {"outcome": "completed", "what_was_done": "x", "where_output_is": "y", "how_checked": "z"}
        self.assertFalse(hub.call_tool("vps", "deliver_result", dict(done, task_id=f"T-{self.sub}"),
                                       ("gen1", f"T-{self.sub}", "1"))[1])
        hub.TEAM["agents"]["studio"]["role"] = "worker"         # it holds no check_result any more
        self.assertFalse(hub.call_tool("studio", "deliver_result", dict(done, task_id=f"T-{self.lead}"),
                                       ("gen1", f"T-{self.lead}", "1"))[1])

    def test_once_its_team_is_done_its_turn_end_names_the_result_to_check(self):
        hub.q("UPDATE tasks SET state='completed', delivered=? WHERE id=?", (hub.now() - 5, self.sub))
        self.lead_turn(1)
        chase = [t for t in self.said("studio") if t.startswith("[hub] You read these and left them open")]
        self.assertEqual(len(chase), 1)
        self.assertIn(f"T-{self.sub} (Build) ended completed: check_result", chase[0])

    def test_a_lead_checks_its_subtasks_results_before_it_delivers(self):
        done = {"outcome": "completed", "what_was_done": "x", "where_output_is": "y", "how_checked": "z"}
        self.assertFalse(hub.call_tool("vps", "deliver_result", dict(done, task_id=f"T-{self.sub}"),
                                       ("gen1", f"T-{self.sub}", "1"))[1])
        text, err = hub.call_tool("studio", "deliver_result", dict(done, task_id=f"T-{self.lead}"),
                                  ("gen1", f"T-{self.lead}", "1"))
        self.assertTrue(err, text)
        self.assertIn(f"results that you have not checked: T-{self.sub}", text)
        self.assertFalse(hub.call_tool("studio", "check_result", {"task_id": f"T-{self.sub}", "accepted": True},
                                       ("gen1", f"T-{self.lead}", "1"))[1])
        self.assertFalse(hub.call_tool("studio", "deliver_result", dict(done, task_id=f"T-{self.lead}"),
                                       ("gen1", f"T-{self.lead}", "1"))[1])

    def test_see_team_says_which_prompts_another_agent_decides(self):
        pid = hub.ins("INSERT INTO prompts(task,agent,tool,input,key,created) VALUES(?,?,?,?,?,?)",
                      (self.sub, "vps", "Bash", "make deploy", "k", hub.now()))
        self.assertIn(f"P-{pid} from vps on T-{self.sub}, for studio to decide", hub.overview_text())


class ReviewedRequests(test_call_api.CallApi):
    """A request or a login that the vault took can have taken effect while the hub was down."""

    def test_a_request_the_vault_took_stays_unknown_across_a_hub_restart(self):
        (text, error), _ = self.machine(test_call_api.QID, self.asks, lambda job: hub.settle_stopped_calls())
        self.assertTrue(error and text.startswith(hub.REQUEST_UNKNOWN), text)
        self.assertEqual([o["state"] for o in self.outcomes()], ["unknown"])        # it gates a second send
        text, error = self.api()                                # the same request_id: asked, never sent again
        self.assertTrue(error and text.startswith(hub.REQUEST_UNKNOWN), text)
        job = self.job()
        code, _ = self.says(job["id"], ok=True, status=201, text="created", body='{"order": "o_1"}')
        self.assertEqual(code, 200)                             # the vault's own report is still taken
        self.assertEqual([o["state"] for o in self.outcomes()], ["done"])
        self.assertIn("HTTP 201", self.api()[0])

    def test_a_request_the_vault_never_took_is_not_sent(self):
        (text, error), _ = self.machine(test_call_api.QID, lambda job: hub.settle_stopped_calls())
        self.assertTrue(error, text)
        self.assertIn("the hub restarted", text)
        self.assertEqual(self.outcomes(), [])


class ReviewedNotices(test_responsibilities.Base):
    """A duty's notice says the duty as it stands when it is read, and only to the agent that holds it."""

    def new_task(self, owner="vps"):
        self.assertFalse(self.tool("manager", "create_task", owner=owner, title="Work", done_when="Done")[1])
        return hub.q1("SELECT * FROM tasks ORDER BY id DESC LIMIT 1")

    def read(self, t, owner="vps"):
        text, err = self.tool(owner, "read_messages", task_id=hub.tref(t["id"]))
        self.assertFalse(err, text)
        return text

    def test_a_notice_whose_first_task_ends_unread_waits_for_the_next(self):
        self.duty()
        first = self.new_task()
        self.assertFalse(self.tool("manager", "cancel_task", task_id=hub.tref(first["id"]), reason="not needed")[1])
        self.assertIn("New duty for vps", self.read(self.new_task()))

    def test_a_duty_moved_or_retired_before_the_read_is_not_told_to_the_agent_it_left(self):
        r = self.duty()
        self.change(r["id"], agent="studio")
        self.assertNotIn("[duty R-1]", self.read(self.new_task()))
        self.assertIn("manager gave R-1 to studio", self.read(self.new_task("studio"), "studio"))
        other = self.duty(text="Answer the support mailbox within a day. Escalate refunds to me.")
        self.assertFalse(self.tool("manager", "change_duty", request_id=str(uuid.uuid4()),
                                   responsibility=hub.rref(other["id"]), action="retire", note="not needed")[1])
        self.assertNotIn("support mailbox", self.read(self.new_task()))

    def test_a_notice_says_the_words_of_the_duty_when_it_is_read(self):
        r = self.duty()
        self.change(r["id"], text="Watch the refund queue only. Refund nothing without asking me first.")
        said = self.read(self.new_task())
        self.assertIn("refund queue", said)
        self.assertNotIn("Keep customer content generation working", said)

    def test_a_change_after_the_notice_was_filed_still_reaches_it_before_the_read(self):
        r = self.duty()
        t = self.new_task()                                 # the notice is filed under this task now, unread
        self.change(r["id"], text="Watch the refund queue only. Refund nothing without asking me first.")
        said = self.read(t)
        self.assertIn("refund queue", said)
        self.assertNotIn("Keep customer content generation working", said)
        other = self.duty(text="Answer the support mailbox within a day. Escalate refunds to me.")
        t = self.new_task()
        self.change(other["id"], agent="manager")           # the manager takes it before vps reads
        self.assertNotIn("support mailbox", self.read(t))

    def test_a_message_written_for_no_task_is_not_read_in_a_task_session(self):
        hub.ins(hub.EVENT, ("vps", "say", None, "[owner] Answer to Needs-you N-1: refund her", hub.now(), "{}"))
        self.assertNotIn("refund her", self.read(self.new_task()))

    def test_the_board_answers_a_person_s_question_in_that_conversation(self):
        cid = hub.ins("INSERT INTO conversations(person,agent,account,chat,state,created,last) "
                      "VALUES(1,'vps','acc','chat','open',?,?)", (hub.now(), hub.now()))
        nid = hub.ins("INSERT INTO needs(title,why,todo,raised,by,kind,conversation) VALUES(?,?,?,?,?,?,?)",
                      ("Ana Ruiz asks for a refund", "a customer", "answer her", hub.now(), "vps", "question", cid))
        code, data = self.request(f"/needs/{nid}", {"answer": "Yes, refund her in full."},
                                  headers={"Content-Type": "application/json", "Accept": "application/json",
                                           "X-Fleet-Client": "deterministic-test"}, source="127.0.0.1")
        self.assertIn(code, (200, 303), data)
        said = hub.q("SELECT who, text FROM conversation_messages WHERE conversation=?", (cid,))
        self.assertEqual([(m["who"], m["text"]) for m in said], [("owner", "Yes, refund her in full.")])
        self.assertEqual(hub.q("SELECT id FROM events WHERE agent='vps' AND kind='say'"), [])
        self.assertNotIn("refund her", self.read(self.new_task()))

    def test_a_move_ends_the_watch_the_old_holder_attached(self):
        r = self.duty()
        self.fire(self.watches(r["id"])[0]["id"])
        case_task = self.first_case_task()
        with hub.LOCK:
            own = hub.trigger_create({"agent": "vps", "check": None, "late_minutes": 60, "max_tasks_per_day": 24,
                                      "request_id": str(uuid.uuid4()), "schedule": {"kind": "every", "minutes": 10},
                                      "task": {"title": "Look at the mailbox", "details": "Mine.", "needs": "none",
                                               "goal_id": None, "done_when": "Every thread has a case."}},
                                     "vps", self.clock, created_by="vps")
        self.assertFalse(self.tool("vps", "attach_watch", request_id=str(uuid.uuid4()), responsibility="R-1",
                                   trigger=own["id"], task_id=hub.tref(case_task["id"]))[1])
        self.change(r["id"], agent="studio")
        rule = hub.trigger_row(own["id"])
        self.assertEqual((rule["state"], rule["responsibility"], rule["watch"]), ("paused", None, None))
        self.assertIn("moved to studio", rule["paused_reason"])
        said = self.tool("vps", "read_messages", task_id=hub.tref(case_task["id"]))[0]
        self.assertIn("R-1 moved to studio: it is no longer yours", said)        # its open task of R-1 is told
        self.assertIn("report_up", said)
        # and the case task the old holder still has is its work to finish: it records and closes it
        self.assertFalse(self.tool("vps", "record_step", request_id=str(uuid.uuid4()), case="R-1/C-1", step="fix",
                                   text="Signed the pool in again", task_id=hub.tref(case_task["id"]))[1])
        self.assertFalse(self.tool("vps", "close_case", request_id=str(uuid.uuid4()), case="R-1/C-1",
                                   outcome="handled", note="Fixed", task_id=hub.tref(case_task["id"]))[1])


class ReviewedCases(test_responsibilities.Base):
    """A case's work, whoever does it."""

    def setUp(self):
        super().setUp()
        self.r = self.duty(watch=[{"kind": "check", "check": test_responsibilities.CHECK}])
        self.rule = self.watches(self.r["id"])[0]["id"]
        self.assertEqual(self.fire(self.rule)["state"], "started")
        self.case_task = self.first_case_task()

    def test_a_case_task_closes_its_own_case_as_its_details_say(self):
        self.assertIn("Then close_case", self.case_task["details"])
        text, err = self.tool("vps", "close_case", request_id=str(uuid.uuid4()), case="R-1/C-1", outcome="no_action",
                              note="The pool recovered by itself", task_id=hub.tref(self.case_task["id"]))
        self.assertFalse(err, text)
        self.assertFalse(self.tool("vps", "deliver_result", task_id=hub.tref(self.case_task["id"]),
                                   outcome="completed", what_was_done="Nothing needed doing",
                                   where_output_is="-", how_checked="The pool reports 8 accounts")[1])
        c = self.case()
        self.assertEqual((c["state"], c["outcome"]), ("closed", "no_action"))

    def test_an_agent_given_a_case_s_work_records_it_and_its_lesson_is_judged(self):
        self.assertFalse(self.tool("vps", "deliver_result", task_id=hub.tref(self.case_task["id"]), outcome="failed",
                                   what_was_done="The provider is down")[1])
        self.assertFalse(self.tool("manager", "create_task", owner="studio", title="Move the pool", done_when="Done",
                                   case_id="R-1/C-1")[1])
        t = hub.q1("SELECT * FROM tasks ORDER BY id DESC LIMIT 1")
        text, err = self.tool("studio", "record_step", task_id=hub.tref(t["id"]), request_id=str(uuid.uuid4()),
                              case="R-1/C-1", step="moved", text="Moved the pool to provider B")
        self.assertFalse(err, text)
        self.assertFalse(self.tool("studio", "close_case", request_id=str(uuid.uuid4()), case="R-1/C-1",
                                   outcome="handled", note="Moved the pool", task_id=hub.tref(t["id"]))[1])
        self.assertFalse(self.tool("studio", "deliver_result", task_id=hub.tref(t["id"]), outcome="completed",
                                   what_was_done="Moved the pool", where_output_is="commit 1", how_checked="8 signed in",
                                   learned="Provider A drops sessions at night; keep the pool on provider B.",
                                   prevents="the pool signing out every night")[1])
        lesson = hub.q1("SELECT id FROM memories WHERE agent='studio'")["id"]
        hub.q("INSERT INTO memory_shown(memory,task,attempt,at) VALUES(?,?,9,?)",   # a later start showed it
              (lesson, t["id"], self.clock + 900))
        self.fire(self.rule, when=self.clock + 1800)            # the same key comes back
        self.assertEqual(hub.q1("SELECT contradicted FROM memories WHERE agent='studio'")["contradicted"], 1)

    def test_a_practice_case_cannot_take_an_id_that_names_a_duty_s_case(self):
        for case_id, code in (("C-5", 400), ("R-1/C-1", 400), ("run7-3", 200)):
            got, data = self.request("/cases", {"test": 3, "id": case_id}, source="127.0.0.1")
            self.assertEqual(got, code, (case_id, data))

    def test_a_case_named_with_another_duty_s_number_is_refused(self):
        other = self.duty(text="Answer the support mailbox within a day. Escalate refunds to me.")
        text, err = self.tool("manager", "create_task", owner="vps", title="Again", done_when="Done",
                              case_id=f"R-{other['id']}/C-1")
        self.assertTrue(err, text)
        self.assertIn(f"C-1 is a case of R-1, not of R-{other['id']}", text)


if __name__ == "__main__":
    unittest.main()

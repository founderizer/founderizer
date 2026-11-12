"""restart_task: the requester of an open browser task has the hub start it once more in a new session. It is the
owner's Stop and Resume with a check in one step. The hub runs in this process with a temporary Git kit, and the
helper is the real code without tmux: its control() sends the real result of a stop to the hub's own route. The
database is a file, so a test can end the hub at one write call and open the file again as a new hub process does.
No browser, no vault and no AI call."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import uuid

import fleet
import hub
from test_api_helper import helper_without_tmux
from test_capacity import LOGIN_A, Capacity

WHY = "the browser extension is not connected"


class Exit(BaseException):
    """The hub process ends here."""


class Ending:
    """The hub's database connection, with one planned end. `stop_at` is the number of the execute or commit call at
    which the hub process ends, and `when` picks a statement in its place. What is not committed at that call is
    lost: the connection rolls nothing back by itself, and the test opens the file again (RestartTask.reopen).
    With `error`, the call fails with an ordinary error in a hub that goes on."""
    def __init__(self, real, stop_at=None, when=None, error=None):
        self.real, self.calls, self.stop_at, self.when, self.error, self.dead = real, 0, stop_at, when, error, False

    def step(self, *statement):
        self.calls += 1
        if self.calls == self.stop_at or (self.when and statement and self.when(*statement)):
            if self.error:
                self.when = None            # one failure
                raise self.error
            self.dead = True
            raise Exit()

    def execute(self, sql, args=()):
        self.step(sql, args)
        return self.real.execute(sql, args)

    def commit(self):
        self.step()
        return self.real.commit()

    def rollback(self):
        return None if self.dead else self.real.rollback()

    def __getattr__(self, name):
        return getattr(self.real, name)


class Dying:
    """What a test needs to end a hub process in the middle of a write and open the file again as a new process does.
    Any OwnerAPI test can mix it in: the database is a file, and `Ending` is the connection with the planned end.
    test_crash_windows.py uses it for the other writes that commit in halves."""

    def raw(self):
        return hub.DB.real if isinstance(hub.DB, Ending) else hub.DB

    def reopen(self):
        """A new hub process on the same file: what the earlier one did not commit is gone."""
        self.raw().close()
        self.connect()

    def kept(self):
        hub.DB.commit()
        return Path(self.path).read_bytes()

    def back_to(self, data):
        """The database as it was when kept() read it."""
        self.raw().close()
        Path(self.path).write_bytes(data)
        Path(self.path + "-journal").unlink(missing_ok=True)
        self.connect()


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(RestartTask(name) for name in RestartTask.__dict__ if name.startswith("test_"))


class RestartTask(Dying, Capacity):
    """seo (a worker with a browser) reports to the lead pma. The fleet manager gave pma a task, and pma gave seo a
    browser task under it."""
    def setUp(self):
        super().setUp()
        self.home = Path(tempfile.mkdtemp(prefix="fleet-restart-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        for p in (patch.object(fleet, "HOME", str(self.home)), patch.object(fleet, "HUB", self.base),
                  patch.object(fleet, "TEAM", {"agents": {"seo": {"vault": "broker"}, "big": {}}})):
            p.start()
            self.addCleanup(p.stop)
        self.shop = self.create("manager", "pma", why="pma leads seo")
        self.task = self.create("pma", "seo", self.shop, needs="browser")
        self.work(self.task)
        self.helpers = {}

    # ---- helpers
    def work(self, task):
        """The owner of the task starts it, as its session does first."""
        text, error = self.call(self.row(task)["owner"], "list_my_tasks", {"task_id": f"T-{task}"}, task)
        self.assertFalse(error, text)
        self.assertEqual(self.row(task)["state"], "working")

    def restart(self, agent="pma", task=None, session=..., **changes):
        """restart_task, as the session of `agent` calls it: (text, is_error)."""
        args = dict({"task_id": f"T-{task or self.task}", "request_id": str(uuid.uuid4()), "expected_attempt": 1,
                     "reason": WHY}, **changes)
        return self.call(agent, "restart_task", args, self.shop if session is ... else session)

    def row(self, task=None):
        return hub.q1("SELECT * FROM tasks WHERE id=?", (task or self.task,))

    def hold(self, task=None):
        return hub.q1("SELECT * FROM holds WHERE task=? ORDER BY id DESC LIMIT 1", (task or self.task,))

    def marker(self, task=None):
        hold = self.hold(task)
        row = hub.q1("SELECT state FROM restart_holds WHERE hold=?", (hold["id"],)) if hold else None
        return row["state"] if row else None

    def found(self):
        """What a hub process finds of the restart: (the hold's state, the restart's state, the attempt of the task,
        its count of new sessions, its attempts, the stops sent to the helper, the attempts that have a start event,
        the kept answers)."""
        hold, row = self.hold(), self.row()
        starts = [json.loads(r["extra"])["attempt"] for r in hub.q(
            "SELECT extra FROM events WHERE agent='seo' AND kind='task' AND task=? ORDER BY id", (self.task,))]
        return (hold["state"] if hold else None, self.marker(), row["attempt"], row["restarts"], self.attempts(),
                len(self.told("seo", "control")), starts, hub.q1("SELECT COUNT(*) c FROM tool_commands")["c"])

    def report(self):
        """The helper's result of the stop, as the hub's route takes it. A hold that has its result gets no second one
        (409 for the helper), and then only the timers go on."""
        with hub.LOCK:
            hold = self.hold()
            if hold["state"] == "requested":
                hub.settle_hold(hold, True, "interrupted and closed")
                hub.restart_continue(hold["id"])

    def attempts(self, task=None):
        return [r["reason"] for r in hub.q("SELECT reason FROM attempts WHERE task=? ORDER BY attempt", (task or self.task,))]

    def told(self, agent, kind="say"):
        return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent=? AND kind=? ORDER BY id", (agent, kind))]

    def stop_arrives(self, confirmed=True, agent="seo"):
        """The helper of the agent gets the hub's control events and sends the result of each stop, as its loop does."""
        helper = self.helpers.setdefault(agent, helper_without_tmux(agent))
        helper.interrupt = lambda window: (True, "interrupted and closed") if confirmed else \
            (False, "the session did not stop")
        code, data = fleet.http("GET", f"/events/{agent}?delivery=1&after=0&wait=0")
        self.assertEqual(code, 200, data)
        events = [event for event in data["events"] if event["kind"] == "control"]
        for event in events:
            helper.handle(event)
        return events

    def owner(self, action, task=None):
        return self.request(f"/ui/tasks/{task or self.task}/control", dict(
            request_id=str(uuid.uuid4()), db="test-generation", action=action, note=""))

    # ---- the whole path
    def test_a_confirmed_stop_is_followed_by_one_new_attempt_with_a_check(self):
        # The session of attempt 1 has a browser action with no result, and a question about its failed tools.
        hub.ins("INSERT INTO thread_events(task,attempt,session,seq,ts,type,data,created) VALUES(?,1,'s1',1,?,'tool_call',?,?)",
                (self.task, hub.now(), json.dumps({"tool_call_id": "toolu_click", "kind": "other", "status": "in_progress",
                                                   "server": "claude-in-chrome", "title": "claude-in-chrome: computer"}),
                 hub.now()))
        text, error = self.call("seo", "ask_my_requester", {"question": f"Attempt 1: {WHY}."}, self.task)
        self.assertIn("is paused", text)
        question = hub.q1("SELECT id FROM questions WHERE task=?", (self.task,))["id"]
        self.assertEqual((self.row()["state"], self.row()["waiting_on"]), ("input-required", f"Q-{question}"))

        first = str(uuid.uuid4())
        text, error = self.restart(request_id=first)
        self.assertFalse(error, text)
        hold = self.hold()
        self.assertEqual((hold["kind"], hold["by"], hold["state"], hold["note"], self.marker()),
                         ("stop", "pma", "requested", WHY, "pending"))
        self.assertIn(f"The restart of T-{self.task} is requested (H-{hold['id']})", text)
        self.assertEqual((self.row()["attempt"], self.attempts()), (1, ["created"]))        # nothing before the stop
        # The same call again changes nothing and gives the first answer; another call waits for the first one. The
        # first answer also carried the lead's unread messages (plan P9.4), which were read with it.
        text = text.split("\n\nNEW MESSAGES of this task, read now:")[0]
        again, error = self.restart(request_id=first)
        self.assertEqual((error, again), (False, text + " This repeats an earlier request with the same request_id, so "
                                                       "nothing new was done."))
        self.assertIn("already used for another change", self.restart(request_id=first, reason="another reason")[0])
        self.assertIn("already used for another change", self.restart(request_id=first, task=self.shop)[0])  # another task
        self.assertIn(f"already waits for its stop (H-{hold['id']})", self.restart()[0])
        self.assertEqual((hub.q1("SELECT COUNT(*) c FROM holds WHERE task=?", (self.task,))["c"],
                          len(self.told("seo", "control"))), (1, 1))
        # While it waits: the session is stopped, and the task keeps the desktop of its machine.
        self.assertIn(f"STOP: T-{self.task} is stopped by the pma",
                      self.call("seo", "report_progress", {"note": "x"}, self.task)[0])
        self.assertEqual(hub.desktop_busy("seo")["id"], self.task)
        self.assertIn("is busy with", hub.desktop_refusal("seo", "screen", "pma"))      # a screen task waits for it
        self.assertIsNone(hub.desktop_refusal("seo", "browser", "pma"))     # a read in tabs of its own runs beside it

        events = self.stop_arrives()
        self.assertEqual([e["extra"]["action"] for e in events], ["stop"])
        hold = self.hold()
        self.assertEqual((hold["state"], hold["released_by"], hold["resume_mode"], self.marker()),
                         ("released", "pma", "check", "done"))
        row = self.row()
        self.assertEqual((row["attempt"], row["restarts"], row["state"], row["waiting_on"], self.attempts()),
                         (2, 0, "working", None, ["created", "resume"]))      # a restart counts no loss (C6)
        outcomes = hub.q("SELECT * FROM outcomes WHERE task=? ORDER BY id", (self.task,))
        self.assertEqual([(o["tool_call_id"], o["state"], o["attempt"], o["hold"]) for o in outcomes],
                         [("toolu_click", "unknown", 1, hold["id"]), (f"restart-{hold['id']}", "unknown", 1, hold["id"])])
        # The new session: the same task and history, a check first, its own tabs, and no answer to the old question.
        start = hub.q1("SELECT * FROM events WHERE agent='seo' AND kind='task' ORDER BY id DESC LIMIT 1")
        self.assertEqual(json.loads(start["extra"]), {"needs": "browser", "resume": True, "attempt": 2,
                                                       "generation": "test-generation"})
        for part in (f"T-{self.task} is resumed by the pma, with a check.", "without repeating any of them",
                     f"O-{outcomes[1]['id']} Attempt 1 was stopped for a restart ({WHY})", hub.RESTART_TABS,
                     f"Your question Q-{question} ended with the earlier session"):
            self.assertIn(part, start["text"])
        asked = hub.q1("SELECT * FROM questions WHERE id=?", (question,))
        self.assertEqual(asked["answer"], hub.RESTART_ANSWER.format(by="pma", task=f"T-{self.task}"))
        self.assertFalse([text for text in self.told("seo") if "Answer to your question" in text])
        self.assertIn(f"T-{self.task} (Work for seo) runs again in a new session, as attempt 2", self.told("pma")[-1])
        self.assertEqual(hub.desktop_busy("seo")["id"], self.task)
        # A second report of the same stop, and a call of the old attempt, change nothing.
        code, data = fleet.http("POST", "/helper/control/seo", {"hold": hold["id"], "confirmed": True, "detail": "again",
                                                               "flushed": [], "ran": False, "ended": 0})
        self.assertEqual((code, self.row()["attempt"]), (409, 2))
        old = hub.call_tool("seo", "report_progress", {"note": "late"}, ("test-generation", f"T-{self.task}", 1))
        self.assertEqual(old, ("STOP: stale or wrong task attempt. Do not report, deliver, or continue work.", True))
        self.assertIn(f"T-{self.task} is at attempt 2 now, not 1", self.restart()[0])       # a decision about attempt 1
        # The gate of unknown outcomes: no login work and no completion before the check of each one.
        gate = "STOP: first find out whether these earlier actions took effect"
        self.assertIn(gate, self.call("seo", "sign_in", {"login": LOGIN_A}, self.task)[0])
        self.assertIn(gate, self.call("seo", "deliver_result", {"what_was_done": "x", "where_output_is": "y",
                                                               "how_checked": "z"}, self.task)[0])
        for outcome in outcomes:
            text, error = self.call("seo", "resolve_outcome", {"outcome_id": f"O-{outcome['id']}", "finding": "not_done",
                                                               "evidence": "The page shows no change."}, self.task)
            self.assertFalse(error, text)
        self.assertNotIn(gate, self.call("seo", "sign_in", {"login": LOGIN_A}, self.task)[0])

    def test_a_stop_that_is_not_confirmed_or_not_reported_starts_nothing(self):
        self.assertFalse(self.restart()[1])
        self.stop_arrives(confirmed=False)
        hold = self.hold()
        self.assertEqual((hold["state"], self.marker(), self.row()["attempt"], self.attempts()),
                         ("not_confirmed", "canceled", 1, ["created"]))
        self.assertIn(f"T-{self.task} (Work for seo, owner seo) was not restarted: seo's helper did not confirm the stop "
                      f"(the session did not stop). It stays held, but the hub does not know whether its session stopped. "
                      f"It starts no new session by itself.", self.told("pma")[-1])
        self.assertIn("STOP:", self.call("seo", "report_progress", {"note": "x"}, self.task)[0])     # it stays held
        # The requester asks again: the same hold, a new stop. This time the helper sends no report at all.
        self.assertFalse(self.restart()[1])
        self.assertEqual((self.hold()["id"], self.hold()["state"], self.marker()), (hold["id"], "requested", "pending"))
        hub.restart_sweep(hub.now() + hub.CFG["silence"] - 5)
        self.assertEqual(self.marker(), "pending")                      # inside the hub's silence time: it still waits
        hub.restart_sweep(hub.now() + hub.CFG["silence"] + 5)
        self.assertEqual((self.marker(), self.hold()["state"], self.row()["attempt"]), ("canceled", "requested", 1))
        self.assertIn(f"The stop of T-{self.task} (Work for seo, owner seo) for its restart has no report from seo's "
                      f"helper", self.told("pma")[-1])
        self.assertIn("It stays held, but the hub does not know whether its session stopped.", self.told("pma")[-1])
        # A late report of that stop confirms it, and still nothing starts by itself.
        self.stop_arrives()
        self.assertEqual((self.hold()["state"], self.marker(), self.row()["attempt"]), ("stopped", "canceled", 1))
        # The requester decides again: the stop is already confirmed, so the one new attempt starts now.
        self.assertFalse(self.restart()[1])
        self.assertEqual((self.hold()["state"], self.marker(), self.row()["attempt"], self.row()["restarts"],
                          self.attempts()), ("released", "done", 2, 0, ["created", "resume"]))

    def test_a_stop_of_the_owner_ends_a_restart_that_waits(self):
        self.assertFalse(self.restart()[1])
        first = self.hold()["id"]
        code, data = self.owner("stop")
        hold = self.hold()
        self.assertEqual((code, data["changed"], data["hold"]["id"], hold["id"]), (200, True, first, first))  # the same hold
        self.assertEqual((hold["by"], hold["kind"], hold["state"], self.marker()), ("owner", "stop", "requested", "canceled"))
        self.assertIn(f"The owner stopped T-{self.task} (Work for seo, owner seo) while its restart waited. The restart "
                      f"is over: T-{self.task} starts no new session by itself. Only the owner resumes it.",
                      self.told("pma")[-1])
        self.assertEqual(len(self.stop_arrives()), 1)                   # the one stop that was already on its way
        self.assertEqual((self.hold()["state"], self.row()["attempt"], self.attempts()), ("stopped", 1, ["created"]))
        hub.restart_sweep(hub.now() + 3600)
        self.assertEqual(self.row()["attempt"], 1)                      # also the timers start nothing
        self.assertIn(f"T-{self.task} is stopped by the owner. Only the owner resumes it.", self.restart()[0])
        code, data = self.owner("resume_check")                         # the owner's own resume is as before
        self.assertEqual((code, data["resumed_with"], self.row()["attempt"], self.row()["restarts"]),
                         (200, "new session", 2, 0))

    def test_a_pause_of_the_leads_task_by_the_owner_ends_it_too(self):
        self.assertFalse(self.restart()[1])
        first = self.hold()["id"]
        code, data = self.request(f"/ui/tasks/{self.shop}/control", dict(
            request_id=str(uuid.uuid4()), db="test-generation", action="pause", note=""))
        hold = self.hold()
        self.assertEqual((code, self.task in data["subtasks_held"], hold["id"], hold["by"], hold["kind"], self.marker()),
                         (200, True, first, "owner", "stop", "canceled"))          # a stop is not made weaker
        self.assertTrue(hub.q1("SELECT 1 FROM parent_holds WHERE hold=? AND parent=?", (first, self.shop)))
        self.assertIn(f"The owner paused T-{self.task} (Work for seo, owner seo) while its restart waited.",
                      self.told("pma")[-1])
        self.stop_arrives()
        self.assertEqual((self.hold()["state"], self.row()["attempt"]), ("stopped", 1))
        self.assertIn(f"T-{self.task} is held with its parent task. Resume the parent.",
                      self.owner("resume_check")[1]["error"])            # it resumes only with the lead's task

    def test_a_task_that_its_requester_cancels_meanwhile_gets_no_new_attempt(self):
        self.assertFalse(self.restart()[1])
        self.assertFalse(self.call("pma", "cancel_task", {"task_id": f"T-{self.task}", "reason": "not needed"}, self.shop)[1])
        self.assertEqual((self.hold()["state"], self.hold()["resume_mode"]), ("released", "task ended"))
        self.stop_arrives()                                             # the stop that was on its way: the hub has no use for it
        hub.restart_sweep(hub.now())
        self.assertEqual((self.marker(), self.row()["state"], self.row()["attempt"], self.attempts()),
                         ("canceled", "canceled", 1, ["created"]))

    def test_the_second_half_is_done_once_also_after_the_hub_stopped_between_the_halves(self):
        self.assertFalse(self.restart()[1])
        hold = self.hold()
        hub.settle_hold(hold, True, "interrupted and closed")    # the helper's report is kept, and the hub stops here
        self.assertEqual((self.hold()["state"], self.marker(), self.row()["attempt"]), ("stopped", "pending", 1))
        for _ in range(3):                                      # the timers of the new hub process
            hub.restart_sweep(hub.now())
        self.assertEqual((self.hold()["state"], self.marker(), self.row()["attempt"], self.row()["restarts"],
                          self.attempts()), ("released", "done", 2, 0, ["created", "resume"]))
        # A hub that stopped after the new attempt, before it marked the restart as done, starts no second one.
        hub.q("UPDATE restart_holds SET state='pending' WHERE hold=?", (hold["id"],))
        hub.restart_sweep(hub.now())
        self.assertEqual((self.marker(), self.row()["attempt"], self.row()["restarts"]), ("canceled", 2, 0))

    # ---- a hub that ends in the middle
    NOTHING = (None, None, 1, 0, ["created"], 0, [1], 0)
    WAITS = ("requested", "pending", 1, 0, ["created"], 1, [1], 1)
    STOPPED = ("stopped", "pending", 1, 0, ["created"], 1, [1], 1)
    DONE = ("released", "done", 2, 0, ["created", "resume"], 1, [1, 2], 1)

    def test_a_failure_at_the_start_event_of_the_new_attempt_leaves_a_restart_that_the_timers_finish(self):
        # Before the writes went together, this left a released hold, attempt 2 with no start event, and a restart
        # that the timers then ended: a task that nothing continued.
        start_event = lambda sql, args: sql == hub.EVENT and args[1] == "task"
        self.assertFalse(self.restart()[1])
        hub.settle_hold(self.hold(), True, "interrupted and closed")
        waits = self.kept()
        for ends in (False, True):                  # an error in a hub that goes on, and the end of the hub process
            with self.subTest(ends=ends):
                self.back_to(waits)
                hub.DB = Ending(hub.DB, when=start_event, error=None if ends else RuntimeError("no start event"))
                with self.assertRaises(Exit if ends else RuntimeError):
                    hub.restart_continue(self.hold()["id"])
                if ends:
                    self.reopen()
                self.assertEqual(self.found(), self.STOPPED)
                for _ in range(2):
                    hub.restart_sweep(hub.now())
                self.assertEqual(self.found(), self.DONE)

    def test_a_hub_that_ends_at_any_write_of_the_first_half_keeps_all_of_it_or_nothing(self):
        args = {"task_id": f"T-{self.task}", "request_id": str(uuid.uuid4()), "expected_attempt": 1, "reason": WHY}
        before = self.kept()
        hub.DB = Ending(hub.DB)
        first, error = self.call("pma", "restart_task", args, self.shop)
        calls = hub.DB.calls
        self.assertEqual((error, self.found()), (False, self.WAITS))
        states = []
        for at in range(1, calls + 1):
            self.back_to(before)
            hub.DB = Ending(hub.DB, stop_at=at)
            with self.assertRaises(Exit):
                self.call("pma", "restart_task", args, self.shop)
            self.reopen()
            states.append(self.found())
            self.assertIn(states[-1], (self.NOTHING, self.WAITS), at)          # never a stop without its restart
            # The requester got no answer, so it sends the same call again: one stop, one restart, the first answer.
            text, error = self.call("pma", "restart_task", args, self.shop)
            self.assertEqual((error, text.replace(" This repeats an earlier request with the same request_id, so "
                                                  "nothing new was done.", ""), self.found()), (False, first, self.WAITS), at)
        self.assertEqual([x for n, x in enumerate(states) if x not in states[:n]], [self.NOTHING, self.WAITS])

    def test_a_hub_that_ends_at_any_write_of_the_second_half_starts_one_new_attempt(self):
        hub.ins("INSERT INTO thread_events(task,attempt,session,seq,ts,type,data,created) VALUES(?,1,'s1',1,?,'tool_call',?,?)",
                (self.task, hub.now(), json.dumps({"tool_call_id": "toolu_click", "kind": "other", "status": "in_progress",
                                                   "server": "claude-in-chrome", "title": "claude-in-chrome: computer"}),
                 hub.now()))
        self.assertIn("is paused", self.call("seo", "ask_my_requester", {"question": WHY}, self.task)[0])
        self.assertFalse(self.restart()[1])
        waits = self.kept()
        hub.DB = Ending(hub.DB)
        self.report()
        calls = hub.DB.calls
        self.assertEqual(self.found(), self.DONE)
        states = []
        for at in range(1, calls + 1):
            self.back_to(waits)
            hub.DB = Ending(hub.DB, stop_at=at)
            with self.assertRaises(Exit):
                self.report()
            self.reopen()
            states.append(self.found())
            self.assertIn(states[-1], (self.WAITS, self.STOPPED, self.DONE), at)
            self.report()                           # the helper got no answer, so it sends its result again
            for _ in range(2):
                hub.restart_sweep(hub.now())        # the timers of the new hub process
            self.assertEqual(self.found(), self.DONE, at)
            hold = self.hold()["id"]
            self.assertEqual([(o["tool_call_id"], o["state"]) for o in hub.q(
                "SELECT * FROM outcomes WHERE task=? ORDER BY id", (self.task,))],
                [("toolu_click", "unknown"), (f"restart-{hold}", "unknown")], at)
            self.assertEqual((len([x for x in self.told("pma") if "runs again in a new session" in x]),
                              hub.q1("SELECT COUNT(*) c FROM questions WHERE answer IS NULL")["c"],
                              self.row()["state"]), (1, 0, "working"), at)
        self.assertEqual([x for n, x in enumerate(states) if x not in states[:n]], [self.WAITS, self.STOPPED, self.DONE])

    # ---- no way around a permission decision
    def test_a_prompt_that_waits_stops_the_restart_and_a_refusal_goes_to_the_new_session(self):
        prompt = lambda text, **decided: hub.ins(
            "INSERT INTO prompts(task,agent,tool,input,key,created,decision,reason,by) VALUES(?,'seo','Bash',?,'k',?,?,?,?)",
            (self.task, text, hub.now(), decided.get("decision"), decided.get("reason"), decided.get("by")))
        waits = prompt("git push origin main")
        self.assertEqual(self.restart()[0], f"T-{self.task} waits for the decision of permission prompt P-{waits}. Decide "
                         f"it first with decide_permission: a restart is no way around a permission decision.")
        self.assertEqual((self.hold(), hub.q1("SELECT decision FROM prompts WHERE id=?", (waits,))["decision"]), (None, None))
        text, error = self.call("pma", "decide_permission", {"prompt_id": f"P-{waits}", "decision": "deny"}, self.shop)
        self.assertFalse(error, text)
        late = prompt("rm -rf   outputs", decision="expired")                       # no decision in time: told no
        held = prompt("ls", decision="deny", reason=f"T-{self.task} is held.", by="hub")  # only the answer of a hold
        allowed = prompt("git status", decision="allow", by="pma")
        self.assertFalse(self.restart()[1])
        self.stop_arrives()
        self.assertEqual(self.row()["attempt"], 2)
        start = self.told("seo", "task")[-1]
        self.assertIn(f"These permission requests of this task were refused, and each refusal still holds in this "
                      f"session: P-{waits} Bash: git push origin main; P-{late} Bash: rm -rf outputs. Do not ask for them "
                      f"in another form. Ask your requester if you cannot work without one.", start)
        self.assertNotIn(f"P-{held} ", start)
        self.assertNotIn(f"P-{allowed} ", start)
        self.assertEqual([(r["decision"], r["by"]) for r in hub.q("SELECT decision, by FROM prompts ORDER BY id")],
                         [("deny", "pma"), ("expired", None), ("deny", "hub"), ("allow", "pma")])    # no decision changed

    # ---- who, and when not
    def test_only_the_requester_restarts_an_open_browser_task_inside_its_scope(self):
        other = self.create("manager", "pma", why="a second task of pma")
        plain = self.create("pma", "seo", self.shop)                    # no browser task: it holds the limit below
        for agent, session, changes, why in (
                ("manager", None, {}, f"T-{self.task} was not requested by you."),
                ("pmb", self.create("manager", "pmb", why="a task of pmb"), {},
                 f"T-{self.task} was not requested by you."),
                ("pma", other, {}, f"T-{self.task} is not a subtask of T-{other}, the task of this session."),
                ("pma", self.shop, {"expected_attempt": 2}, f"T-{self.task} is at attempt 1 now, not 2"),
                ("pma", self.shop, {"expected_attempt": True}, "expected_attempt must be the attempt that failed"),
                ("pma", self.shop, {"expected_attempt": "1"}, "expected_attempt must be the attempt that failed"),
                ("pma", self.shop, {"reason": " "}, "Give the reason in 1 to 300 characters"),
                ("pma", self.shop, {"reason": "x" * 301}, "Give the reason in 1 to 300 characters"),
                ("pma", self.shop, {"request_id": "short"}, "request_id must be a new id for each new call"),
                ("pma", self.shop, {"task_id": "T-999"}, "There is no task T-999.")):
            with self.subTest(agent=agent, changes=changes):
                self.assertIn(why, self.refused(agent, "restart_task", dict(
                    {"task_id": f"T-{self.task}", "request_id": str(uuid.uuid4()), "expected_attempt": 1, "reason": WHY},
                    **changes), session))
        self.assertEqual((hub.q1("SELECT COUNT(*) c FROM holds")["c"], hub.q1("SELECT COUNT(*) c FROM tool_commands")["c"]),
                         (0, 0))                                        # a refused call keeps nothing
        self.assertNotIn("restart_task", [t["name"] for t in hub.tools_for("seo", ("test-generation", f"T-{self.task}", 1))])
        # A usage limit of its owner, and a task that ended.
        limit = hub.ins("INSERT INTO agent_limits(agent,since,until,reset_known,task) VALUES('seo',?,?,1,?)",
                        (hub.now(), hub.now() + 3600, plain))
        self.assertIn("seo waits for its usage limit to reset", self.restart()[0])
        hub.q("UPDATE agent_limits SET ended=? WHERE id=?", (hub.now(), limit))
        self.assertFalse(self.call("pma", "cancel_task", {"task_id": f"T-{self.task}", "reason": "not needed"}, self.shop)[1])
        self.assertIn(f"T-{self.task} is already canceled.", self.restart()[0])
        # The fleet manager restarts a browser task that it requested itself.
        hub.TEAM["agents"]["big"]["can"].append("browser")
        own = self.create("manager", "big", needs="browser")
        self.work(own)
        text, error = self.restart("manager", own, None)
        self.assertFalse(error, text)
        self.stop_arrives(agent="big")
        self.assertEqual((self.row(own)["attempt"], self.hold(own)["released_by"], self.told("manager")[-1].split(".")[0]),
                         (2, "manager", f"[hub] T-{own} (Work for big) runs again in a new session, as attempt 2"))

    def test_any_open_task_restarts_through_a_confirmed_stop_whatever_its_count(self):
        """Plan C6: no task kind, no state and no count refuses restart_task. A task that never started, with no
        browser and three losses behind it, restarts as any other: its helper confirms that no session runs first."""
        hub.TEAM["agents"]["big"]["can"].append("shell")
        asleep = self.create("manager", "big")
        hub.q("UPDATE tasks SET restarts=3 WHERE id=?", (asleep,))
        self.assertEqual((self.row(asleep)["state"], self.row(asleep)["needs"]), ("submitted", "none"))
        text, error = self.restart("manager", asleep, None, reason="its start failed: claude was not installed")
        self.assertFalse(error, text)
        self.assertIn(f"The restart of T-{asleep} is requested", text)
        self.assertEqual(self.row(asleep)["attempt"], 1)               # nothing starts before the stop is confirmed
        self.stop_arrives(agent="big")
        self.assertEqual((self.row(asleep)["attempt"], self.row(asleep)["restarts"]), (2, 0))

    def test_a_changed_reporting_line_or_a_usage_limit_at_the_stop_leaves_the_task_held(self):
        self.assertFalse(self.restart()[1])
        hub.TEAM["agents"]["seo"]["reports_to"] = "pmb"                 # seo left pma's team while the stop ran
        self.stop_arrives()
        self.assertEqual((self.hold()["state"], self.marker(), self.row()["attempt"]), ("stopped", "canceled", 1))
        self.assertIn(f"T-{self.task} (Work for seo, owner seo) was not restarted: seo reports to pmb",
                      self.told("pma")[-1])
        self.assertIn("seo reports to pmb", self.restart()[0])                      # and no new restart
        hub.TEAM["agents"]["seo"]["reports_to"] = "pma"
        limit = hub.ins("INSERT INTO agent_limits(agent,since,until,reset_known,task) VALUES('seo',?,?,1,?)",
                        (hub.now(), hub.now() + 3600, self.task))
        hub.q("UPDATE restart_holds SET state='pending' WHERE hold=?", (self.hold()["id"],))      # as if it still waited
        hub.restart_continue(self.hold()["id"])
        self.assertEqual((self.marker(), self.row()["attempt"]), ("canceled", 1))
        self.assertIn("was not restarted: seo reached its usage limit", self.told("pma")[-1])
        hub.q("UPDATE agent_limits SET ended=? WHERE id=?", (hub.now(), limit))
        hub.TEAM["agents"]["seo"]["active"] = False                     # seo goes into setup
        self.assertIn("seo is in setup.", self.restart()[0])
        self.assertEqual(self.row()["attempt"], 1)


if __name__ == "__main__":
    unittest.main()

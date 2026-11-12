"""Asking without stopping, one way to say "come back at this time", and patience that fits the work.

Three things, one feature (`asking_and_waiting`), and one rule that runs through all of them: work that is quiet on
purpose must never read as work that has stalled. A held task, an agent at its usage limit, a task parked until the
time its own agent named, and a session inside one long call are all deliberately quiet. Every check below that
says "not nudged", "a live path" or "not restarted" is that rule asked once more.

In-process hub on a temporary database. No AI calls, no network beyond 127.0.0.1, no real clock waits: the clock is
`hub.now`, patched, and `hub.tick()` is called by hand.

`LateDecision` is the follow-up the same review left (1.36), and it is the one class here that runs on the real
clock: the hook route's own window is a wait, and a frozen clock would never reach its end.
"""
import json
import threading
import time
import unittest
import uuid
from unittest.mock import patch

import hub
from test_runtime import Runtime, SESSION


def load_tests(loader, _tests, _pattern):
    """Only this file's own checks: the classes below inherit Runtime's helpers, not its tests."""
    suite = unittest.TestSuite()
    for cls in (Asking, ComingBack, Patience, BackgroundAgents, LateDecision, PromptPolls):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Tools:
    """call_tool answers (text, is_error) and raises nothing, so a refusal is a string to read."""

    def ok(self, *args, **kwargs):
        text, err = self.tool(*args, **kwargs)
        self.assertFalse(err, text)
        return text

    def refused(self, *args, **kwargs):
        text, err = self.tool(*args, **kwargs)
        self.assertTrue(err, text)
        return text


class Clock:
    """A clock the checks move by hand, so nothing sleeps."""

    def __init__(self, start):
        self.t = start

    def __call__(self):
        return self.t

    def on(self, seconds):
        self.t += seconds
        return self.t


class Asking(Tools, Runtime):
    """An agent that is unsure asks and carries on, and what it went on with is on the record."""

    def ask(self, tid, question, **extra):
        return self.ok("studio", "ask_my_requester", tid, question=question, **extra)

    # ---- 1. the ask itself
    def test_an_unsure_agent_asks_and_carries_on(self):
        tid = self.task()
        said = self.ask(tid, "Metric or imperial tides?", default="metric, which the last note used")
        row = hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))
        self.assertEqual((row["state"], row["waiting_on"]), ("working", None))      # nothing paused
        self.assertIn("NOT paused", said)
        self.assertIn("metric, which the last note used", said)
        self.assertIn("rule 9", said)               # check what you already did, if the answer differs
        self.assertIn("leaves the building", said)  # and what a default is never for
        asked = hub.q1("SELECT * FROM questions WHERE task=?", (tid,))
        self.assertEqual((asked["assumed"], asked["waiting"], asked["answer"]),
                         ("metric, which the last note used", 0, None))
        told = self.said("manager")[-1]
        self.assertIn("is NOT paused", told)
        self.assertIn("goes on with: metric, which the last note used", told)
        self.assertIn("only if that is wrong", told)
        # and the ask is activity, so it does not look like silence either
        self.assertEqual(hub.q1("SELECT last_tool FROM tasks WHERE id=?", (tid,))["last_tool"], "ask_my_requester")

    def test_an_ask_with_no_default_still_pauses_the_task(self):
        tid = self.task()
        said = self.ask(tid, "Which of the two logos?")
        row = hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))
        self.assertEqual((row["state"], row["waiting_on"]), ("input-required", "Q-1"))
        self.assertIn("paused", said)
        self.assertIsNone(hub.q1("SELECT assumed FROM questions WHERE id=1")["assumed"])

    def test_a_default_is_refused_for_an_ask_about_access(self):
        tid = self.task()
        said = self.refused("studio", "ask_my_requester", tid, question="May I push to the web repo?",
                            default="push it", needs_access="repo:acme/web")
        self.assertIn("never answered by a default", said)
        self.assertEqual(hub.q("SELECT id FROM questions"), [])     # nothing was written
        # the same ask without one is the real route, and it pauses
        self.ask(tid, "May I push to the web repo?", needs_access="repo:acme/web")
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (tid,))["state"], "input-required")

    def test_a_default_longer_than_the_limit_is_refused(self):
        tid = self.task()
        said = self.refused("studio", "ask_my_requester", tid, question="Which one?",
                            default="x" * (hub.ASSUMED_TEXT + 1))
        self.assertIn(str(hub.ASSUMED_TEXT), said)

    # ---- 2. the record the owner reads
    def test_what_was_decided_by_default_is_in_the_result_the_requester_checks(self):
        tid = self.task()
        self.ask(tid, "Metric or imperial?", default="metric")
        self.ok("studio", "report_progress", tid, note="wrote the note in metric")
        self.ok("studio", "deliver_result", tid, outcome="completed", what_was_done="Wrote the tides note",
                where_output_is="outputs/T-1/note.md", how_checked="read it back")
        result = next(t for t in self.said("manager") if "Result for" in t)
        self.assertIn("DECIDED BY ITS OWN READING, with no answer from you: Q-1 \"metric\"", result)
        # a question the requester did answer is its own decision, so it is not in that line
        self.assertEqual(hub.went_on_with(tid).count("Q-"), 1)
        hub.q("UPDATE questions SET answer='metric', answered=? WHERE id=1", (hub.now(),))
        self.assertEqual(hub.went_on_with(tid), "")

    def test_the_asker_sees_its_own_assumption_in_the_task_and_the_requester_on_the_board(self):
        tid = self.task()
        self.ask(tid, "Metric or imperial?", default="metric")
        mine = self.ok("studio", "list_my_tasks", tid)
        self.assertIn('Question Q-1: "Metric or imperial?" -> not answered yet (you went on with: "metric")', mine)
        board = hub.t_see_team("manager", {})
        self.assertIn("NOT WAITING: it goes on with \"metric\". Answer only if that is wrong.", board)

    def test_an_answer_that_comes_later_reaches_the_asker_and_names_what_it_went_on_with(self):
        tid = self.task()
        self.ask(tid, "Metric or imperial?", default="metric")
        said = hub.t_answer("manager", {"question_id": "Q-1", "text": "imperial, the customer is American"})
        self.assertIn("did not wait for you", said)
        self.assertIn("may be correcting work already done", said)
        reached = self.said("studio")[-1]
        self.assertIn("imperial, the customer is American", reached)
        self.assertIn("You went on with: metric", reached)
        self.assertIn("rule 9", reached)
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (tid,))["state"], "working")

    # ---- 3. the three places that read "an open question" and had to change
    def test_a_question_asked_with_a_default_is_not_chased(self):
        """Plan C9: no clock chases a question. What the requester read and left open is named once, at its closing
        empty read, and a question asked with a default is not in it."""
        tid = self.task()
        self.ask(tid, "Metric or imperial?", default="metric")
        self.ask(tid, "Which logo?")        # a blocking one beside it
        hub.call_tool("manager", "read_messages", {})          # it reads both
        hub.call_tool("manager", "read_messages", {})          # its closing empty read
        chased = [t for t in self.said("manager") if t.startswith("[hub] You read these and left them open")]
        self.assertEqual(len(chased), 1)
        self.assertIn("Q-2", chased[0])             # the blocking one, and only that one
        self.assertNotIn("Q-1", chased[0])

    def test_a_lost_session_with_a_defaulted_question_open_is_still_restarted(self):
        clock = Clock(hub.now())
        with patch.object(hub, "now", clock):
            tid = self.task()
            self.ask(tid, "Metric or imperial?", default="metric")
            clock.on(200)
            self.alive("studio")                    # the helper is online and lists no window for this task
            hub.tick()
            clock.on(60)
            self.alive("studio")
            hub.tick()
        row = hub.q1("SELECT attempt, restarts, live_path FROM tasks WHERE id=?", (tid,))
        self.assertEqual((row["attempt"], row["restarts"]), (2, 1))
        self.assertIsNone(row["live_path"])
        # the blocking kind is a live path, as it always was
        tid2 = self.task()
        clock2 = Clock(hub.now())
        with patch.object(hub, "now", clock2):
            self.ok("studio", "ask_my_requester", tid2, question="Which logo?")
            self.alive("studio")
            clock2.on(200)
            hub.tick()
        self.assertEqual(hub.q1("SELECT live_path FROM tasks WHERE id=?", (tid2,))["live_path"],
                         "waiting for the answer to Q-2")

    def test_answering_one_question_does_not_release_a_task_waiting_on_another(self):
        tid = self.task()
        self.ask(tid, "Metric or imperial?", default="metric")       # Q-1, not waiting
        self.ask(tid, "Which logo?")                                 # Q-2, the task waits on this one
        self.assertEqual(hub.q1("SELECT waiting_on FROM tasks WHERE id=?", (tid,))["waiting_on"], "Q-2")
        hub.t_answer("manager", {"question_id": "Q-1", "text": "metric is right"})
        row = hub.q1("SELECT state, waiting_on FROM tasks WHERE id=?", (tid,))
        self.assertEqual((row["state"], row["waiting_on"]), ("input-required", "Q-2"))
        hub.t_answer("manager", {"question_id": "Q-2", "text": "the round one"})
        row = hub.q1("SELECT state, waiting_on FROM tasks WHERE id=?", (tid,))
        self.assertEqual((row["state"], row["waiting_on"]), ("working", None))

    # ---- 4. the words that make an agent reach for it
    def test_the_default_is_named_where_an_agent_reads_it_at_the_moment_of_doubt(self):
        tid = self.task()
        start = hub.start_text("studio", tid)
        self.assertIn("default", start)                     # rule 4, in every start text
        self.assertIn("only UNSURE and not blocked", start)
        resumed = hub.start_text("studio", tid, resume=True)
        self.assertIn("default", resumed)                   # and in a resumed one
        described = next(d for role, name, fn, d, schema in hub.TOOLS if name == "ask_my_requester")
        self.assertIn("default", described)
        self.assertIn("leaves the building", described)
        schema = next(s for role, name, fn, d, s in hub.TOOLS if name == "ask_my_requester")
        self.assertIn("default", schema["properties"])


class ComingBack(Tools, Runtime):
    """One way to say "come back to this at this time": any agent, a task or a time, and it comes back to its setter."""

    def remind(self, agent, tid, **args):
        if tid is None:                 # a manager session, which holds no task
            text, err = hub.call_tool(agent, "set_reminder", args)
            self.assertFalse(err, text)
            return text
        return self.ok(agent, "set_reminder", tid, **args)

    def no_reminder(self, agent, tid, **args):
        text, err = self.tool(agent, "set_reminder", tid, **args)
        self.assertTrue(err, text)
        return text

    def test_a_reminder_set_for_a_time_comes_back_to_the_agent_that_set_it(self):
        clock = Clock(hub.now())
        with patch.object(hub, "now", clock):
            tid = self.task()
            at = hub.goal_time(clock() + 3600)          # "2026-10-21 09:00 UTC", as every "at" of the fleet reads
            said = self.remind("studio", tid, note="the build should be done",
                               at=at.split(" ")[0] + "T" + at.split(" ")[1])
            self.assertIn("brings you back to T-1", said)
            self.assertIn("nothing nudges it", said)
            row = hub.q1("SELECT * FROM reminders WHERE id=1")
            self.assertEqual((row["agent"], row["task"], row["done"]), ("studio", tid, 0))
            self.assertAlmostEqual(row["due"], clock() + 3600, delta=60)
            clock.on(3700)
            self.alive("studio", f"T-{tid}")
            hub.tick()
        # it went to studio, which set it, and not to the manager, which the old tool always told
        reached = self.said("studio")[-1]
        self.assertIn("the build should be done", reached)
        self.assertIn("carry on with T-1 now", reached)
        self.assertIn("rule 9", reached)
        self.assertEqual([t for t in self.said("manager") if "Reminder" in t], [])
        fired = hub.q1("SELECT done, fired FROM reminders WHERE id=1")
        self.assertEqual(fired["done"], 1)
        self.assertIsNotNone(fired["fired"])

    def test_minutes_still_work_and_a_session_with_no_task_only_gets_a_message(self):
        clock = Clock(hub.now())
        with patch.object(hub, "now", clock):
            said = self.remind("manager", None, note="look at the goal", minutes=30)
            self.assertIn("messages you at", said)
            self.assertIsNone(hub.q1("SELECT task FROM reminders WHERE id=1")["task"])
            clock.on(1900)
            hub.tick()
        self.assertIn("look at the goal", self.said("manager")[-1])

    def test_either_a_time_or_minutes_and_a_note_of_your_own(self):
        tid = self.task()
        for args, word in (({}, "Give one of minutes"),
                           ({"minutes": 5, "at": "2030-01-01"}, "not two of them"),
                           ({"minutes": "soon"}, "must be a number"),
                           ({"minutes": -5}, "minutes from now"),
                           ({"at": "tomorrow at nine"}, "ISO date"),
                           ({"at": "2020-01-01"}, "in the future")):
            self.assertIn(word, self.no_reminder("studio", tid, note="later", **args), str(args))
        self.assertIn("in your own words", self.no_reminder("studio", tid, minutes=5))
        # plan C12: a reminder's time is the agent's own, also beyond a year
        text, error = hub.call_tool("studio", "set_reminder", {"task_id": f"T-{tid}", "minutes": 400 * 1440,
                                                               "note": "the yearly renewal"}, ("gen1", f"T-{tid}", "1"))
        self.assertFalse(error, text)

    def test_a_parked_task_is_never_counted_as_silent_and_is_not_restarted(self):
        clock = Clock(hub.now())
        with patch.object(hub, "now", clock):
            tid = self.task()
            self.remind("studio", tid, note="the build finishes about then", minutes=240)
            self.alive("studio")        # online, and no window for this task: the lost-session case
            for _ in range(4):
                clock.on(3000)          # 200 minutes in all, still inside the park
                hub.tick()
            row = hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))
            self.assertEqual((row["nudge_level"], row["attempt"], row["restarts"]), (0, 1, 0))
            self.assertIn("waiting until", row["live_path"])
            self.assertIsNone(row["stalled_since"])
            self.assertEqual([t for t in self.said("studio") if "No activity" in t], [])
            self.assertEqual([t for t in self.said("manager") if "silent" in t or "no live path" in t], [])
            self.assertIn("WAITING until", hub.t_see_team("manager", {}))
            # and once it is back, the clocks are the ordinary ones again
            clock.on(2500)              # past the 240 minutes: the hub brings it back in a new session
            hub.tick()
            self.assertEqual(hub.q1("SELECT attempt, restarts FROM tasks WHERE id=?", (tid,))["attempt"], 2)
            self.assertEqual(hub.q1("SELECT restarts FROM tasks WHERE id=?", (tid,))["restarts"], 0)
            clock.on(4000)                  # plan C9: no clock nudges it afterwards either
            hub.tick()
        self.assertEqual([t for t in self.said("studio") if "No activity" in t], [])

    def test_the_owner_reads_until_when_a_task_is_parked(self):
        """Owner API 1.117: the time of a parked task's reminder, once a tick judged it parked, and until the park ends.
        The owner's apps showed such a task as work in progress."""
        clock = Clock(hub.now())
        with patch.object(hub, "now", clock):
            tid, other = self.task(), self.task()
            self.remind("studio", tid, note="the build finishes about then", minutes=240)
            due = hub.q1("SELECT due FROM reminders WHERE task=? AND done=0", (tid,))["due"]
            self.alive("studio")
            hub.tick()
            self.assertIn(hub.PARKED_PATH, hub.q1("SELECT live_path FROM tasks WHERE id=?", (tid,))["live_path"])
            self.assertEqual(hub.parked_until(), {tid: due})        # and not the task beside it
            self.assertNotIn(other, hub.parked_until())
            clock.on(241 * 60)              # the reminder comes: the park is over
            hub.tick()
            self.assertEqual(hub.parked_until(), {})

    def test_coming_back_is_not_one_of_the_three_restarts(self):
        clock = Clock(hub.now())
        with patch.object(hub, "now", clock):
            tid = self.task()
            for _ in range(5):
                self.remind("studio", tid, note="later", minutes=10)
                clock.on(700)
                hub.tick()
            row = hub.q1("SELECT attempt, restarts FROM tasks WHERE id=?", (tid,))
        self.assertEqual((row["attempt"], row["restarts"]), (6, 0))

    def test_a_second_reminder_for_the_same_task_moves_the_time(self):
        clock = Clock(hub.now())
        with patch.object(hub, "now", clock):
            tid = self.task()
            self.remind("studio", tid, note="at nine", minutes=60)
            self.remind("studio", tid, note="make it eleven", minutes=120)
            self.assertEqual([(r["id"], r["done"]) for r in hub.q("SELECT id, done FROM reminders ORDER BY id")],
                             [(1, 1), (2, 0)])
            self.assertEqual(hub.parked(tid)["id"], 2)
            clock.on(7300)
            self.alive("studio", f"T-{tid}")
            hub.tick()
        said = [t for t in self.said("studio") if "Reminder" in t]
        self.assertEqual(len(said), 1)
        self.assertIn("make it eleven", said[0])

    def test_a_reminder_waits_with_a_hold_and_a_usage_limit_and_dies_with_the_task(self):
        clock = Clock(hub.now())
        with patch.object(hub, "now", clock):
            tid = self.task()
            self.remind("studio", tid, note="later", minutes=10)
            hub.start_limit("studio", clock() + 9000)
            clock.on(700)
            hub.tick()
            self.assertEqual(hub.q1("SELECT done FROM reminders WHERE id=1")["done"], 0)   # held, not fired
            hub.q("UPDATE agent_limits SET until=?, ended=? WHERE id=1", (clock(), clock()))
            clock.on(10)
            self.alive("studio", f"T-{tid}")
            hub.tick()
            self.assertEqual(hub.q1("SELECT done FROM reminders WHERE id=1")["done"], 1)
            # a task that ends takes its reminder with it, so nothing comes back to finished work
            tid2 = self.task()
            self.remind("studio", tid2, note="nothing to come back to", minutes=10)
            hub.q("UPDATE tasks SET state='completed', delivered=? WHERE id=?", (clock(), tid2))
            clock.on(700)
            hub.tick()
            row = hub.q1("SELECT done, fired FROM reminders WHERE task=?", (tid2,))
        self.assertEqual(row["done"], 1)
        self.assertIsNone(row["fired"])
        self.assertEqual([t for t in self.said("studio") if "nothing to come back to" in t], [])

    def test_a_reminder_is_for_your_own_open_task_only(self):
        tid = self.task()
        text, err = hub.call_tool("vps", "set_reminder", {"note": "later", "minutes": 5, "task_id": f"T-{tid}"},
                                  context=("gen1", f"T-{tid}", "1"))
        self.assertTrue(err, text)
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (tid,))
        self.assertIn("nothing to come back to", self.no_reminder("studio", tid, note="later", minutes=5))

    def test_a_reminder_written_before_this_version_still_reaches_the_manager(self):
        """Every reminder of the old tool was the manager's, and migrate leaves its agent null."""
        clock = Clock(hub.now())
        with patch.object(hub, "now", clock):
            hub.ins("INSERT INTO reminders(due,note) VALUES(?,?)", (clock() + 60, "the old shape"))
            clock.on(100)
            hub.tick()
        self.assertIn("the old shape", self.said("manager")[-1])
        self.assertEqual(hub.q1("SELECT done FROM reminders WHERE id=1")["done"], 1)

    def test_every_agent_has_it_and_the_wake_up_rules_keep_what_it_does_not_do(self):
        for name in ("studio", "vps", "manager"):
            self.assertIn("set_reminder", [t["name"] for t in hub.tools_for(name)], name)
        for name in ("see_triggers", "save_trigger", "change_trigger"):
            self.assertIn(name, [t["name"] for t in hub.tools_for("studio")], name)
        described = next(d for role, name, fn, d, s in hub.TOOLS if name == "set_reminder")
        self.assertIn("save_trigger", described)        # it says which tool the other idea is
        self.assertIn("minutes", described)
        self.assertIn("at", described)
        # and it is not in a chat window, like every other tool that writes
        self.assertNotIn("set_reminder", [t["name"] for t in hub.tools_for("studio", ("gen1", "owner-chat", "0"))])


class Patience(Tools, Runtime):
    """Plan C9: no clock speaks for a task. Each stored turn end of its current attempt is checked once for a live
    reason: the first empty one asks the agent, the second in a row tells the requester with its last words."""

    def setUp(self):
        super().setUp()
        self.seq = 0

    def task(self, *args, **kw):
        tid = super().task(*args, **kw)
        hub.q("UPDATE events SET read_at=? WHERE task=? AND kind='task'", (hub.now(), tid))     # its start was read
        return tid

    def turn(self, tid, said="I looked at the queue.", *more, read=True):
        """One whole turn of the session: it reads its messages (unless read is false), then its words and its end."""
        if read:
            hub.q("UPDATE events SET read_at=? WHERE agent='studio' AND task=? AND read_at IS NULL", (hub.now(), tid))
        rows = [{"seq": self.seq + 1, "type": "user_message", "text": "Go on."}, *more,
                {"seq": self.seq + 50, "type": "agent_message", "text": said},
                {"seq": self.seq + 51, "type": "result", "stop_reason": "end_turn"}]
        self.seq += 100
        self.assertEqual(self.records(tid, rows)[0], 200)

    def continues(self, tid):
        return [t for t in self.said("studio") if t.startswith(f"[hub] T-{tid} is open and nothing is waiting")]

    def test_no_clock_speaks_for_a_session_inside_a_long_call_or_after_a_hub_start(self):
        clock = Clock(hub.now())
        with patch.object(hub, "now", clock):
            tid = self.task()
            self.records(tid, [{"seq": 1, "type": "tool_call", "tool_call_id": "toolu_1", "title": "Bash: xcodebuild",
                                "kind": "execute", "status": "in_progress"}])
            for _ in range(3):
                clock.on(86400)
                self.alive("studio", f"T-{tid}")
                hub.tick()
        self.assertEqual((self.said("studio"), self.said("manager")), ([], []))
        self.assertEqual(hub.q1("SELECT nudge_level FROM tasks WHERE id=?", (tid,))["nudge_level"], 0)

    def test_an_empty_turn_end_asks_once_and_the_second_tells_the_requester_with_its_last_words(self):
        tid = self.task()
        self.turn(tid)
        self.assertEqual(len(self.continues(tid)), 1)
        self.assertIn("ask_my_requester, with default when you are only unsure", self.continues(tid)[0])
        hub.turn_end_sweep(hub.now())                       # the tick's reconcile decides nothing twice
        self.assertEqual(len(self.continues(tid)), 1)
        self.tool("studio", "report_progress", tid, note="Half of it.")     # no event: it does not arm a second ask
        self.turn(tid, "I think it is done.")
        self.assertEqual(len(self.continues(tid)), 1)
        told = [t for t in self.said("manager") if "ended two turns in a row" in t]
        self.assertEqual(len(told), 1)
        self.assertIn('Its last words: "I think it is done."', told[0])
        self.assertEqual(hub.q1("SELECT nudge_level FROM tasks WHERE id=?", (tid,))["nudge_level"], 2)    # Stalled
        self.turn(tid, "Still here.")                       # nothing more until an event
        self.assertEqual((len(self.continues(tid)), len([t for t in self.said("manager") if "two turns" in t])), (1, 1))
        hub.emit("studio", "say", "[message from manager on T-1 id=AM-1] Please deliver it now.", task=tid)
        hub.q("UPDATE events SET read_at=? WHERE agent='studio' AND task=? AND kind='say'", (hub.now(), tid))
        self.records(tid, [{"seq": self.seq + 1, "type": "user_message", "text": "New fleet messages."}])
        self.assertEqual(hub.q1("SELECT nudge_level FROM tasks WHERE id=?", (tid,))["nudge_level"], 0)    # a new turn
        self.records(tid, [{"seq": self.seq + 2, "type": "result", "stop_reason": "end_turn"}])
        self.seq += 100
        self.assertEqual(len(self.continues(tid)), 2)       # a message came between: a new stretch

    def test_a_live_reason_at_the_turn_end_asks_nothing(self):
        tid = self.task()
        asked = hub.ins("INSERT INTO questions(task,asker,requester,text,asked) VALUES(?,?,?,?,?)",
                        (tid, "studio", "manager", "Which logo?", hub.now()))
        self.turn(tid)
        hub.q("UPDATE questions SET answer='The blue one.', answered=? WHERE id=?", (hub.now(), asked))
        hub.ins("INSERT INTO reminders(due,note,agent,task,created) VALUES(?,?,?,?,?)",
                (hub.now() + 3600, "Look again.", "studio", tid, hub.now()))
        self.turn(tid)
        hub.q("UPDATE reminders SET done=1")
        hub.emit("studio", "say", "[hub] A new message.", task=tid)    # unread, and its line will be typed
        self.turn(tid, read=False)
        self.assertEqual(self.continues(tid), [])

    def test_a_background_command_is_acknowledged_once_and_counts_as_work(self):
        tid = self.task()
        bash = [{"seq": 2, "type": "tool_call", "tool_call_id": "b1", "title": "Bash: npm run build", "kind": "execute",
                 "status": "in_progress"},
                {"seq": 3, "type": "tool_call_update", "tool_call_id": "b1", "status": "in_progress",
                 "background": True, "interrupted": False}]
        self.turn(tid, "The build runs.", *bash)
        acks = [t for t in self.said("studio") if "The hub counts Bash: npm run build as work" in t]
        self.assertEqual(len(acks), 1)
        self.assertEqual(sum("running in the background" in t for t in self.said("manager")), 1)
        self.turn(tid, "Waiting for it.")
        self.assertEqual((len([t for t in self.said("studio") if "counts Bash" in t]), self.continues(tid)), (1, []))

    def test_a_reminder_keeps_its_park_through_its_own_turn_and_a_later_turn_wakes_it(self):
        tid = self.task()
        self.alive("studio", f"T-{tid}")
        text, error = self.tool("studio", "set_reminder", tid, note="Look at the build again.", minutes=120)
        self.assertFalse(error, text)
        self.turn(tid, "I will look again in two hours.")      # the turn that set it: no continue, and still parked
        self.assertEqual(self.continues(tid), [])
        self.assertIsNotNone(hub.parked(tid))
        hub.emit("studio", "say", "[message from manager on T-9 id=AM-3] A quick question.", task=tid)
        self.turn(tid, "Answered it.")                          # a later turn: awake for liveness
        self.assertIsNone(hub.parked(tid))
        self.assertEqual(self.continues(tid), [])               # the open reminder is still a live reason
        hub.liveness(hub.now())
        self.assertNotIn("waiting until", hub.q1("SELECT live_path FROM tasks WHERE id=?", (tid,))["live_path"])

    def test_a_submitted_task_whose_first_turn_ends_before_list_my_tasks_is_asked(self):
        tid = self.task(state="submitted")
        self.turn(tid, "Hello.")
        self.assertEqual(len(self.continues(tid)), 1)

    def test_the_manager_hears_once_what_it_read_and_left_open(self):
        tid = self.task()
        asked = hub.ins("INSERT INTO questions(task,asker,requester,text,asked) VALUES(?,?,?,?,?)",
                        (tid, "studio", "manager", "Which logo?", hub.now() - 10))
        hub.emit("manager", "say", f"[hub] Q-{asked} from studio: Which logo?", task=tid)
        text, error = hub.call_tool("manager", "read_messages", {})
        self.assertIn("Which logo?", text)
        text, error = hub.call_tool("manager", "read_messages", {})     # its closing empty read: one chase
        chase = [t for t in self.said("manager") if t.startswith("[hub] You read these and left them open")]
        self.assertEqual(len(chase), 1)
        self.assertIn(f"Q-{asked} on T-{tid} waits for your answer: Which logo?", chase[0])
        hub.call_tool("manager", "read_messages", {})
        hub.call_tool("manager", "read_messages", {})
        self.assertEqual(len([t for t in self.said("manager") if t.startswith("[hub] You read these")]), 1)

    def test_the_oldest_unfinished_call_is_the_one_that_counts(self):
        clock = Clock(hub.now())
        with patch.object(hub, "now", clock):
            tid = self.task()
            self.records(tid, [{"seq": 1, "ts": None, "type": "tool_call", "tool_call_id": "toolu_1",
                                "title": "Bash: gh run watch", "kind": "execute", "status": "in_progress",
                                "server": None}])
            clock.on(600)
            self.records(tid, [{"seq": 2, "ts": None, "type": "tool_call", "tool_call_id": "toolu_2",
                                "title": "Read: notes.md", "kind": "read", "status": "in_progress", "server": None},
                               {"seq": 3, "ts": None, "type": "tool_call_update", "tool_call_id": "toolu_2",
                                "status": "completed", "interrupted": False}])
            title, started = hub.open_call(tid, 1)
            self.assertEqual(title, "Bash: gh run watch")
            self.assertEqual(clock() - started, 600)


class BackgroundAgents(Patience):
    """AUTONOMY.md decision 41: a Workflow or an async subagent of a task session runs in the background until its own
    end notice (threads.py). Meanwhile no turn end is chased, no fresh start takes the session, and a completed
    delivery is refused once in each attempt; the next one goes through and names what still ran. A failed or
    rejected delivery always goes through, and a background command never holds one."""
    FLOW = "Workflow: Review the three parts"

    def running(self, tid, call="toolu_w", title=FLOW, attempt=1):
        """The session starts a background call and ends its turn: its records, as the helper sends them."""
        hub.q("UPDATE events SET read_at=? WHERE agent='studio' AND task=? AND read_at IS NULL", (hub.now(), tid))
        rows = [{"seq": self.seq + 1, "type": "tool_call", "tool_call_id": call, "title": title, "kind": "other",
                 "status": "in_progress"},
                {"seq": self.seq + 2, "type": "tool_call_update", "tool_call_id": call, "status": "in_progress",
                 "background": True, "interrupted": False},
                {"seq": self.seq + 3, "type": "agent_message", "text": "It runs; I wait for it."},
                {"seq": self.seq + 4, "type": "result", "stop_reason": "end_turn"}]
        self.seq += 100
        self.assertEqual(self.records(tid, rows, attempt=attempt)[0], 200)

    def deliver(self, tid, outcome="completed"):
        done = dict(what_was_done="Reviewed the three parts.", where_output_is="outputs/review.md",
                    how_checked="Read each part against the plan.") if outcome == "completed" else \
            dict(what_was_done="The parts are not there.")
        return self.tool("studio", "deliver_result", tid, outcome=outcome, **done)

    def test_a_workflow_counts_as_work_until_its_end_notice_and_no_fresh_start_takes_it(self):
        tid = self.task()
        self.running(tid)
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))
        self.assertEqual((self.continues(tid), [x for x in self.said("studio") if "The hub counts" in x]), ([], []))
        self.assertEqual(hub.live_reason(t, hub.turn_state(tid, 1)), ("subagent", self.FLOW))
        self.assertEqual(hub.open_agents(t), [self.FLOW])
        self.assertIsNotNone(hub.fresh_refusal(t, 1))           # a fresh start would stop the run
        self.records(tid, [{"seq": self.seq + 1, "type": "user_message", "text": "<task-notification> done"},
                           {"seq": self.seq + 2, "type": "tool_call_update", "tool_call_id": "toolu_w",
                            "status": "completed", "interrupted": False},
                           {"seq": self.seq + 3, "type": "result", "stop_reason": "end_turn"}])
        self.seq += 100
        self.assertEqual((hub.open_agents(t), len(self.continues(tid))), ([], 1))     # nothing waits for it now

    def test_a_completed_delivery_while_a_workflow_runs_is_refused_once_and_the_next_names_it(self):
        tid = self.task()
        self.running(tid)
        text, error = self.deliver(tid)
        self.assertTrue(error, text)
        self.assertIn(f"T-{tid} is not delivered yet: your session has {self.FLOW} running", text)
        self.assertIn("Wait for its end notice", text)
        self.assertIn("call deliver_result again", text)
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (tid,))["state"], "working")
        self.assertFalse([x for x in self.said("manager") if x.startswith(f"[hub] Result for T-{tid}")])
        text, error = self.deliver(tid)                         # done without it: it goes through
        self.assertFalse(error, text)
        self.assertIn(f"Still running, and it stops with your session: {self.FLOW}", text)
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (tid,))["state"], "completed")
        (result,) = [x for x in self.said("manager") if x.startswith(f"[hub] Result for T-{tid}")]
        self.assertIn(f"Still running in its session when it delivered, so stopped with it: {self.FLOW}.", result)

    def test_each_attempt_is_refused_once_and_two_running_calls_are_named_together(self):
        tid = self.task()
        self.running(tid)
        self.assertTrue(self.deliver(tid)[1])
        hub.new_attempt(hub.q1("SELECT * FROM tasks WHERE id=?", (tid,)), "restart")
        self.running(tid, attempt=2)
        self.running(tid, call="toolu_a", title="Agent: read part two", attempt=2)
        text, error = self.deliver(tid)                         # a new session was never told
        self.assertTrue(error, text)
        self.assertIn(f"{self.FLOW}; Agent: read part two running", text)
        self.assertFalse(self.deliver(tid)[1])

    def test_failed_and_rejected_deliveries_go_through_and_a_background_command_holds_none(self):
        for outcome in ("failed", "rejected"):
            tid = self.task()
            self.running(tid, call="toolu_a", title="Agent: read part two")
            text, error = self.deliver(tid, outcome)
            self.assertFalse(error, text)
            self.assertIn("Still running, and it stops with your session: Agent: read part two", text)
            self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (tid,))["state"], outcome)
        tid = self.task()
        self.running(tid, call="toolu_b", title="Bash: npm run build")
        text, error = self.deliver(tid)
        self.assertFalse(error, text)
        self.assertNotIn("Still running", text)


if __name__ == "__main__":
    unittest.main()


class LateDecision(Tools, Runtime):
    """A permission prompt that nobody decided in time, and the way forward that used to go nowhere.

    A prompt waits `hook_wait` and is then answered "no for now". The decision was the only thing the hub said, and
    it said it to the session that asked; a `decide_permission` that came later was refused with "tell the agent to
    try again", and telling it meant a message, which lands in the agent's owner-chat window, which has no task
    tools. So the decider's word could not reach the work. Nothing below reverses a denial: the prompt stays
    expired, the command did not run, and what is added is that the next attempt is reachable.

    The real clock, not `Clock`: `hook_wait` is 2 seconds in this fixture and the route sleeps until it passes.
    """

    def hook(self, tid, command="curl -X POST http://hub/outbox -d key=k", agent="studio"):
        code, body = self.call("POST", f"/hook/permission/{agent}/T-{tid}",
                               {"tool_name": "Bash", "tool_input": {"command": command},
                                "generation": "gen1", "attempt": 1}, client=None)
        self.assertEqual(code, 200, body)
        return body["hookSpecificOutput"]["decision"]

    def late(self, decision="allow", prompt="P-1", **args):
        text, error = hub.call_tool("manager", "decide_permission",
                                    dict(args, prompt_id=prompt, decision=decision))
        self.assertTrue(error, text)            # a late decision decides nothing, so it is still a refusal
        return text

    def test_an_expiry_names_the_way_forward_and_a_late_word_reaches_the_session(self):
        tid = self.task()
        decision = self.hook(tid)
        self.assertEqual(decision["behavior"], "deny")
        self.assertIn("no for now", decision["message"])
        self.assertIn("run the same thing again", decision["message"])
        self.assertIn("ask your requester", decision["message"])        # and still not another route
        # the same thing in the session itself, because a Codex session reads the decision and drops the message
        told = self.said("studio")[-1]
        self.assertIn("P-1 expired", told)
        self.assertIn("did not run", told)
        self.assertIn("run the same thing again", told)
        self.assertEqual(hub.q1("SELECT task FROM events WHERE agent='studio' AND kind='say' "
                                "ORDER BY id DESC LIMIT 1")["task"], tid)
        row = hub.q1("SELECT state, waiting_on FROM tasks WHERE id=?", (tid,))
        self.assertEqual((row["state"], row["waiting_on"]), ("working", None))      # nothing waits on the prompt
        self.assertIn("may run the same thing again", self.said("manager")[-1])
        # the manager comes back too late: it decides nothing, and its word is no longer a dead end
        text = self.late(reason="the outbox is the practice one")
        self.assertIn("P-1 expired", text)
        self.assertIn("did not run", text)
        self.assertIn("Nothing can be decided on it now", text)
        self.assertIn("told in its own task session that you say allow", text)
        self.assertEqual(hub.q1("SELECT decision FROM prompts WHERE id=1")["decision"], "expired")
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM rules")["n"], 0)        # no standing rule out of an expiry
        word = self.said("studio")[-1]
        self.assertIn("manager says allow on P-1", word)
        self.assertIn("the command did not run", word)
        self.assertIn("asks manager once more", word)
        self.assertIn("the outbox is the practice one", word)
        # and it is passed once: the second call reads the first back instead of writing again
        again = self.late()
        self.assertIn("manager said allow after it expired", again)
        self.assertEqual(self.said("studio")[-1], word)

    def test_a_late_deny_tells_the_session_not_to_run_it_and_never_pre_approves(self):
        tid = self.task()
        self.hook(tid)
        text = self.late("deny", reason="that host is not ours")
        self.assertIn("so it will not run it", text)
        word = self.said("studio")[-1]
        self.assertIn("manager says deny on P-1", word)
        self.assertIn("Do not run it, and do not reach it another way", word)
        self.assertIn("that host is not ours", word)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM rules")["n"], 0)
        # always belongs to a prompt that can be decided, and this one cannot
        self.assertIn("P-1 expired", self.late("allow", always=True))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM rules")["n"], 0)

    def test_a_retry_asks_once_more_and_a_second_expiry_says_to_ask_instead(self):
        tid = self.task()
        self.hook(tid)
        decision = self.hook(tid)                   # the same command again: a new prompt and a new window
        self.assertEqual([r["id"] for r in hub.q("SELECT id FROM prompts ORDER BY id")], [1, 2])
        self.assertEqual(hub.q1("SELECT decision FROM prompts WHERE id=2")["decision"], "expired")
        self.assertIn("already expired once", decision["message"])
        self.assertIn("ask your requester", decision["message"])
        self.assertNotIn("run the same thing again", decision["message"])
        self.assertIn("already expired once", self.said("studio")[-1])
        # another command of the same task has its own count, so one loop does not quiet the next question
        other = self.hook(tid, command="make install")
        self.assertIn("run the same thing again", other["message"])

    def test_a_decision_that_arrived_stays_the_answer_and_carries_no_retry(self):
        """The hold: a command that was denied stays denied. Only an expiry says that nothing was decided."""
        tid = self.task()

        def decide():
            for _ in range(60):
                if hub.q1("SELECT id FROM prompts WHERE decision IS NULL"):
                    break
                time.sleep(0.02)
            hub.call_tool("manager", "decide_permission",
                          {"prompt_id": "P-1", "decision": "deny", "reason": "not that site"})
        thread = threading.Thread(target=decide, daemon=True)
        thread.start()
        decision = self.hook(tid)
        thread.join(5)
        self.assertEqual(decision["behavior"], "deny")
        self.assertIn("not that site", decision["message"])
        self.assertNotIn("run the same thing again", decision["message"])
        self.assertEqual(self.said("studio"), [])           # the denial is the whole answer: no second line
        self.assertIn("P-1 was already decided: deny", self.late())
        self.assertEqual(self.said("studio"), [])

    def test_a_late_word_has_nowhere_to_go_once_the_task_is_over(self):
        tid = self.task()
        self.hook(tid)
        before = len(self.said("studio"))
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (tid,))
        text = self.late()
        self.assertIn("no session to tell", text)
        self.assertIn("a new task that follows it", text)
        self.assertEqual(len(self.said("studio")), before)
        self.assertIsNone(hub.q1("SELECT reason FROM prompts WHERE id=1")["reason"])


class PromptPolls(Tools, Runtime):
    """Plan C7: a permission prompt waits for its decision. The hook asks, gets `pending` with the prompt's id, and
    asks again for that prompt until a decision, a hold or the end of its task. Nothing expires by time."""

    def setUp(self):
        super().setUp()
        for p in (patch.object(hub, "HOOK_POLL", 0.05),):
            p.start()
            self.addCleanup(p.stop)

    def ask(self, tid, prompt=None, attempt=1, command="make install"):
        body = {"tool_name": "Bash", "tool_input": {"command": command}, "generation": "gen1", "attempt": attempt,
                "poll": True}
        if prompt:
            body["prompt"] = prompt
        code, answer = self.call("POST", f"/hook/permission/studio/T-{tid}", body, client=None)
        self.assertEqual(code, 200, answer)
        return answer

    def decide(self, decision="allow", prompt="P-1"):
        return hub.call_tool("manager", "decide_permission", {"prompt_id": prompt, "decision": decision})

    def test_a_prompt_waits_for_its_decision_however_long_and_across_a_hub_start(self):
        tid = self.task()
        self.assertEqual(self.ask(tid), {"pending": True, "prompt": "P-1"})
        self.assertEqual(sum("Permission prompt P-1" in t for t in self.said("manager")), 1)
        for _ in range(3):                                          # the same prompt, asked again: no second one
            self.assertEqual(self.ask(tid, "P-1"), {"pending": True, "prompt": "P-1"})
        self.assertEqual(self.ask(tid), {"pending": True, "prompt": "P-1"})     # found by its request too
        hub.settle_stopped_calls()                                  # the hub starts again: the prompt is still open
        self.assertIsNone(hub.q1("SELECT decision FROM prompts WHERE id=1")["decision"])
        self.assertEqual(tuple(hub.q1("SELECT state, waiting_on FROM tasks WHERE id=?", (tid,))),
                         ("input-required", "P-1"))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM prompts")["n"], 1)
        self.assertEqual(self.decide(), ("P-1: allow.", False))
        self.assertEqual(self.ask(tid, "P-1")["hookSpecificOutput"]["decision"], {"behavior": "allow"})
        self.assertEqual(tuple(hub.q1("SELECT state, waiting_on FROM tasks WHERE id=?", (tid,))), ("working", None))
        self.assertEqual(sum("expired" in t for t in self.said("studio") + self.said("manager")), 0)

    def test_a_hold_a_new_attempt_and_the_end_of_the_task_each_end_a_waiting_prompt(self):
        tid = self.task()
        self.ask(tid)
        hub.request_hold(tid, "pause", "owner")
        answer = self.ask(tid, "P-1")["hookSpecificOutput"]["decision"]
        self.assertEqual(answer["behavior"], "deny")
        self.assertIn("STOP", answer["message"])
        other = self.task()
        self.ask(other, command="make test")
        hub.new_attempt(hub.q1("SELECT * FROM tasks WHERE id=?", (other,)), "restart")
        row = hub.q1("SELECT decision, reason FROM prompts WHERE task=?", (other,))
        self.assertEqual((row["decision"], row["reason"]), ("expired", hub.PROMPT_REPLACED))
        self.assertEqual(tuple(hub.q1("SELECT state, waiting_on FROM tasks WHERE id=?", (other,))), ("working", None))
        text, error = self.decide(prompt="P-2")
        self.assertTrue(error)
        self.assertIn("ended before a decision reached it", text)
        self.assertEqual(self.said("studio"), [])                  # no late word: the session that asked is gone
        third = self.task()
        self.ask(third, command="make docs")
        hub.end_holds(third)
        self.assertEqual(hub.q1("SELECT decision FROM prompts WHERE task=?", (third,))["decision"], "expired")

    def test_a_question_on_the_screen_with_no_hook_running_moves_the_prompt_there(self):
        tid = self.task()
        self.ask(tid)
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES('studio',?,?)",
              (json.dumps({"features": ["prompt_polls"]}), hub.now()))
        for _ in range(2):
            self.assertEqual(self.call("POST", f"/helper/dialog/studio/T-{tid}", {"kind": "shown"}, client=None)[0], 200)
        self.assertEqual(hub.q1("SELECT decision FROM prompts WHERE id=1")["decision"], "screen")
        self.assertEqual(hub.q1("SELECT waiting_on FROM tasks WHERE id=?", (tid,))["waiting_on"], "its screen")
        self.assertEqual(sum("shows a question on its own screen" in t for t in self.said("manager")), 1)
        text, error = self.decide()
        self.assertTrue(error)
        self.assertIn("P-1 is no longer with the hub", text)
        # runtime gaps A6: a new session first, and a person only if the same question comes back
        self.assertIn(f"Start T-{tid} again with restart_task; raise a Needs-you item only if the same question comes "
                      f"back.", text)

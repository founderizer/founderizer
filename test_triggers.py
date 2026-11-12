"""Owner API 1.7 and 1.8: prompt-task triggers and code checks. In-process hub, temporary database and Git
repositories, a set clock and a stand-in helper; no AI calls."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch
from zoneinfo import ZoneInfo

import fleet
import hub
from test_ui_api import OwnerAPI

MADRID = ZoneInfo("Europe/Madrid")
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3", "mac-studio": "127.0.0.4"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]},
                   "studio": {"role": "worker", "runtime": "claude", "machine": "mac-studio", "can": ["shell", "browser"]}},
        "goals": {"timezone": "Europe/Madrid"}}
WEEKLY = {"kind": "daily", "time": "09:00", "days": ["thu", "mon"], "timezone": "Europe/Madrid"}
TASK = {"title": "Write the weekly sales summary", "details": "Use the shop export in outputs/sales.csv.",
        "done_when": "outputs/sales-summary.md is pushed.", "needs": "none", "goal_id": None}
MON_12, THU_15, MON_19, THU_22, MON_26 = 1791788400.0, 1792047600.0, 1792393200.0, 1792652400.0, 1793001600.0


def at(text, zone=MADRID):
    """Epoch seconds of a wall time that exists once."""
    return datetime.datetime.fromisoformat(text).replace(tzinfo=zone).timestamp()


def utc(text):
    return at(text, datetime.timezone.utc)


def git(*args, cwd=None):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


SECRET = "Pr4ct!ce-Login#2026"
SYNTHETIC = (Path(__file__).parent / "checks" / "synthetic_value.py").read_bytes()


def register_secret():
    hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES(?,?,?,?,?)",
            ("practice", "s1", hashlib.sha256(("s1" + SECRET).encode()).hexdigest(), len(SECRET), "u"))


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (Schedules, Triggers, Runner, Checks):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Schedules(unittest.TestCase):
    def slots(self, schedule, after, n=5):
        return hub.trigger_slots(hub.trigger_schedule(schedule), after, after, n)

    def test_weekly_daily_and_monthly_times_use_the_local_clock(self):
        t0 = at("2026-10-10T21:10")
        self.assertEqual(hub.trigger_schedule(WEEKLY)["days"], ["mon", "thu"])          # stored in week order
        self.assertEqual(self.slots(WEEKLY, t0), [MON_12, THU_15, MON_19, THU_22, MON_26])
        self.assertEqual(MON_26 - THU_22, 4 * 86400 + 3600)        # 09:00 CET after the clock change on 25 October
        self.assertEqual(self.slots(dict(WEEKLY, days=None), t0, 2), [at("2026-10-11T09:00"), MON_12])
        monthly = {"kind": "monthly", "day": 31, "time": "09:00", "timezone": "Europe/Madrid"}
        self.assertEqual(self.slots(monthly, t0), [at("2026-10-31T09:00"), at("2026-12-31T09:00"), at("2027-01-31T09:00"),
                                                   at("2027-03-31T09:00"), at("2027-05-31T09:00")])
        self.assertEqual(self.slots(dict(monthly, day=29), at("2027-01-30T00:00"), 2),          # no 29 February in 2027
                         [at("2027-03-29T09:00"), at("2027-04-29T09:00")])
        self.assertEqual(self.slots(dict(monthly, day=29), at("2028-01-30T00:00"), 1), [at("2028-02-29T09:00")])

    def test_clock_changes_follow_the_owner_rule(self):
        night = {"kind": "daily", "time": "02:30", "days": None, "timezone": "Europe/Madrid"}
        # 28 March 2027: 02:00 CET becomes 03:00 CEST. 02:30 does not exist, so it runs at 03:00 CEST (01:00 UTC).
        self.assertEqual(self.slots(night, utc("2027-03-27T12:00"), 3),
                         [utc("2027-03-28T01:00"), utc("2027-03-29T00:30"), utc("2027-03-30T00:30")])
        # 25 October 2026: 03:00 CEST becomes 02:00 CET. 02:30 occurs twice and runs once, at the first (CEST).
        self.assertEqual(self.slots(night, utc("2026-10-24T12:00"), 2), [utc("2026-10-25T00:30"), utc("2026-10-26T01:30")])
        once = {"kind": "once", "at": "2027-03-28T02:30", "timezone": "Europe/Madrid"}
        self.assertEqual(self.slots(once, utc("2027-01-01T00:00")), [utc("2027-03-28T01:00")])

    def test_every_counts_elapsed_time_from_its_anchor_and_once_runs_once(self):
        anchor, every = at("2026-10-10T21:10"), hub.trigger_schedule({"kind": "every", "minutes": 15})
        self.assertEqual(hub.trigger_slots(every, anchor, anchor, 3), [anchor + 900, anchor + 1800, anchor + 2700])
        self.assertEqual(hub.trigger_slots(every, anchor, anchor + 1000, 2), [anchor + 1800, anchor + 2700])
        self.assertEqual(hub.latest_due(every, anchor, anchor + 900, anchor + 7300), anchor + 7200)
        once = hub.trigger_schedule({"kind": "once", "at": "2026-10-14T09:00", "timezone": "Europe/Madrid"})
        self.assertEqual(hub.trigger_slots(once, 0, anchor), [at("2026-10-14T09:00")])
        self.assertEqual(hub.trigger_slots(once, 0, at("2026-10-14T09:00")), [])

    def test_bad_schedules_are_refused(self):
        zone = {"timezone": "Europe/Madrid"}
        for bad, words in (({"kind": "cron", "expr": "* * * * *"}, "schedule.kind"),
                           ({"kind": "every", "minutes": 0}, "minutes must be a whole number from 1 to 10000000"),
                           ({"kind": "every", "minutes": 15, **zone}, "has no timezone"),
                           ({"kind": "daily", "time": "9:00", **zone}, "time must be HH:MM"),
                           ({"kind": "daily", "time": "09:00", "days": ["mon", "mon"], **zone}, "days must"),
                           ({"kind": "daily", "time": "09:00", "days": [], **zone}, "days must"),
                           ({"kind": "daily", "time": "09:00", "timezone": "europe/madrid"}, "timezone must"),
                           ({"kind": "monthly", "day": 32, "time": "09:00", **zone}, "day must be a whole number from 1 to 31"),
                           ({"kind": "monthly", "day": True, "time": "09:00", **zone}, "day must"),
                           ({"kind": "once", "at": "2026-02-30T09:00", **zone}, "at must"),
                           ({"kind": "once", "at": "2026-10-14 09:00", **zone}, "at must")):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as e:
                    hub.trigger_schedule(bad)
                self.assertIn(words, str(e.exception))

    def test_the_fleet_limit_in_team_json_is_checked(self):
        hub.validate_team(dict(json.loads(json.dumps(TEAM)), triggers={"max_tasks_per_day": 0}))
        for bad in ({"max_tasks_per_day": -1}, {"max_tasks_per_day": "0"}, {"max_tasks_per_day": True}, {}, []):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                hub.validate_team(dict(json.loads(json.dumps(TEAM)), triggers=bad))


def make(fields, t0):
    """One rule of the owner's own, as the fleet still holds them: nothing writes one any more (the editor went with
    POST /ui/triggers), but a stored one runs on the 1.7 path, which is what these checks exercise."""
    body = dict(hub.trigger_fields(fields, create=True), request_id=str(uuid.uuid4()))
    with hub.LOCK:
        t = hub.trigger_create(body, "owner", t0, created_by="owner")
        return {"trigger": hub.trigger_view(t, t0), "upcoming": hub.trigger_upcoming(t)}


def change(tid, base, fields, t0):
    with hub.LOCK:
        t = hub.trigger_edit(tid, base, hub.trigger_fields(fields, create=False), "owner", t0, created_by="owner")
        return {"trigger": hub.trigger_view(t, t0), "upcoming": hub.trigger_upcoming(t)}


class Triggers(OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90,
                       ask_wait=1, ask_max=1, hook_wait=2, job_wait=1, tick=5)
        self.clock = at("2026-10-10T21:10")         # Saturday
        clock = patch.object(hub, "now", lambda: self.clock)
        clock.start()
        self.addCleanup(clock.stop)

    # ---- helpers. A rule is an agent's: save_trigger's own path, which no owner route repeats.
    def fields(self, **changes):
        return dict({"agent": "vps", "schedule": WEEKLY, "task": TASK}, **changes)

    def create(self, **changes):
        return make(self.fields(**changes), self.clock)

    def edit(self, tid, base, **changes):
        return change(tid, base, changes, self.clock)

    def refused(self, tid=None, base=None, **changes):
        """Why the hub would not save this rule, in its own words."""
        with self.assertRaises((ValueError, hub.Refusal)) as caught:
            self.edit(tid, base, **changes) if tid else self.create(**changes)
        return str(caught.exception)

    def state(self, tid, base, action):
        return self.request(f"/ui/triggers/{tid}/state", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                              base_revision=base, action=action))

    def detail(self, tid):
        return self.request(f"/ui/triggers/{tid}?db=test-generation")

    def sweep(self, when):
        self.clock = when
        with hub.LOCK:
            hub.trigger_sweep(when)

    def run_now(self, tid):
        with hub.LOCK:
            return hub.run_trigger(hub.trigger_row(tid), self.clock, True, self.clock)

    def last_run(self):
        return tuple(hub.q1("SELECT state, reason FROM trigger_runs ORDER BY id DESC LIMIT 1"))

    def woken(self):
        """The AI-dispatch spy: events that start or wake a model session, for every agent and the manager."""
        return hub.q1("SELECT COUNT(*) n FROM events WHERE kind IN ('say','task','chat')")["n"]

    # ---- routes
    def test_a_saved_trigger_reads_back_in_its_stored_form(self):
        data = self.create()
        trigger = data["trigger"]
        # plan C12: no late window and no cap; failing_since says since when a check fails
        self.assertEqual(set(trigger), {"id", "agent", "state", "paused_by", "paused_reason", "revision", "schedule",
                                        "check", "task", "next_due", "last_run", "last_task", "tasks_24h", "created",
                                        "updated", "request_id", "failures", "failing_since", "armed", "created_by"})
        self.assertEqual((trigger["failures"], trigger["armed"]), (0, None))         # a prompt trigger has no check
        self.assertEqual((trigger["agent"], trigger["state"], trigger["paused_by"], trigger["revision"], trigger["check"],
                          trigger["last_run"], trigger["last_task"], trigger["tasks_24h"], trigger["next_due"]),
                         ("vps", "active", None, 1, None, None, None, 0, MON_12))
        self.assertEqual((trigger["schedule"], trigger["task"]), (dict(WEEKLY, days=["mon", "thu"]), TASK))
        self.assertEqual(data["upcoming"], [MON_12, THU_15, MON_19, THU_22, MON_26])
        code, listing = self.request("/ui/triggers?db=test-generation")
        self.assertEqual((code, listing), (200, {"db": "test-generation", "triggers": [trigger]}))     # no fleet budget
        code, one = self.detail(trigger["id"])
        history = one.pop("history")
        self.assertEqual((code, one), (200, {"db": "test-generation", "trigger": trigger, "upcoming": data["upcoming"],
                                             "runs": [], "next": None, "source": None}))
        self.assertEqual([(h["revision"], h["by"], h["action"]) for h in history], [(1, "owner", "create")])
        self.assertIn("triggers", self.request()[1]["ui_features"])
        self.assertEqual(self.request("/ui/triggers?db=old")[0], 409)
        self.assertEqual(self.request("/ui/triggers/99?db=test-generation")[0], 404)

    def test_a_rule_that_cannot_be_is_refused(self):
        past = {"kind": "once", "at": "2026-10-09T09:00", "timezone": "Europe/Madrid"}
        for change, word in (({"agent": "nobody"}, "there is no agent nobody"),
                             ({"task": dict(TASK, needs="browser")}, "vps has no browser"),
                             ({"task": dict(TASK, goal_id=7)}, "there is no goal G-7"),
                             ({"check": {"kind": "command"}}, "check needs path"), ({"color": "blue"}, "color"),
                             ({"task": dict(TASK, details=None)}, "details"), ({"task": {"title": "x"}}, "task needs"),
                             ({"task": dict(TASK, title="Two\nlines")}, "one line"),
                             ({"max_tasks_per_day": 49}, "max_tasks_per_day"), ({"late_minutes": -1}, "late_minutes"),
                             ({"schedule": past}, "this time has passed")):
            with self.subTest(change=change):
                self.assertIn(word, self.refused(**change))
        self.assertEqual(self.count("triggers"), 0)

    def test_the_next_times_of_a_schedule_come_from_its_slots(self):
        monthly = {"kind": "monthly", "day": 31, "time": "09:00", "timezone": "Europe/Madrid"}
        t0 = self.clock
        self.assertEqual(hub.trigger_slots(hub.trigger_schedule(monthly), t0, t0, 5),
                         [1793433600.0, 1798704000.0, 1801382400.0, 1806476400.0, 1811746800.0])
        for bad, word in ((dict(monthly, day=32), "day must be a whole number from 1 to 31"),
                          ({"kind": "once", "at": "2026-10-10T21:00", "timezone": "Europe/Madrid"}, "")):
            with self.subTest(bad=bad), self.assertRaises(ValueError) as caught:
                schedule = hub.trigger_schedule(bad)
                if not hub.trigger_slots(schedule, t0, t0, 1):
                    raise ValueError("this time has passed")
            self.assertIn(word, str(caught.exception))
        self.assertEqual(self.count("triggers"), 0)

    def test_an_edit_keeps_the_interval_start_unless_the_schedule_changes(self):
        every = {"kind": "every", "minutes": 60}
        tid = self.create(schedule=every)["trigger"]["id"]
        anchor = hub.trigger_row(tid)["anchor"]
        self.clock += 600
        form = {"agent": "vps", "schedule": every, "task": dict(TASK, title="Write the daily sales summary"),
                "check": None}         # the whole rule, as a save sends it
        data = self.edit(tid, 1, **form)
        self.assertEqual((data["trigger"]["revision"], data["trigger"]["next_due"], data["trigger"]["task"]["title"]),
                         (2, anchor + 3600, "Write the daily sales summary"))
        self.assertEqual(hub.trigger_row(tid)["anchor"], anchor)
        data = self.edit(tid, 2, **dict(form, schedule={"kind": "every", "minutes": 30}))
        self.assertEqual((data["trigger"]["revision"], data["trigger"]["next_due"]), (3, self.clock + 1800))
        self.assertEqual(hub.trigger_row(tid)["anchor"], self.clock)
        self.assertIn("changed meanwhile", self.refused(tid, 2, task=TASK))

    # ---- runs
    def test_a_due_trigger_starts_one_normal_task_from_the_hub_tick(self):
        trigger = self.create()["trigger"]
        hub.touch("vps")
        woken = self.woken()
        self.clock = MON_12 + 4                 # the app is closed; the hub ticks
        hub.touch("vps")
        hub.tick()
        task, run = hub.q1("SELECT * FROM tasks"), hub.q1("SELECT * FROM trigger_runs")
        self.assertEqual((task["owner"], task["requester"], task["state"], task["trigger_id"], task["trigger_run"],
                          task["title"], task["done_when"], task["needs"], task["goal"], task["goal_id"], task["attempt"]),
                         ("vps", "manager", "submitted", trigger["id"], run["id"], TASK["title"], TASK["done_when"],
                          "none", "", None, 1))
        self.assertEqual(task["details"], f"{TASK['details']}\n\nStarted by trigger {trigger['id']} (revision 1, run "
                                          f"{run['id']}) for Mon 12 Oct 2026 09:00 Europe/Madrid.")
        self.assertEqual((run["state"], run["reason"], run["task"], run["due"], run["manual"], run["revision"]),
                         ("started", None, task["id"], MON_12, 0, 1))
        self.assertEqual([tuple(r) for r in hub.q("SELECT task, attempt, reason FROM attempts")], [(task["id"], 1, "created")])
        event = hub.q1("SELECT * FROM events WHERE kind='task'")
        self.assertEqual((event["agent"], event["task"], event["text"]), ("vps", task["id"], hub.start_text("vps", task["id"])))
        self.assertEqual(json.loads(event["extra"]),
                         {"needs": "none", "resume": False, "attempt": 1, "generation": "test-generation"})
        self.assertEqual(self.woken(), woken + 1)           # the start event only: no manager turn
        hub.tick()                                          # one due time runs once
        self.assertEqual((self.count("tasks"), self.count("trigger_runs")), (1, 1))
        row = next(t for t in self.request()[1]["tasks"] if t["id"] == task["id"])
        self.assertEqual((row["trigger_id"], row["trigger_run"]), (trigger["id"], run["id"]))
        one = self.detail(trigger["id"])[1]
        self.assertEqual((one["trigger"]["next_due"], one["trigger"]["last_task"], one["trigger"]["tasks_24h"],
                          one["trigger"]["last_run"], one["runs"]), (THU_15, task["id"], 1, hub.run_view(run), [hub.run_view(run)]))
        self.assertNotIn("fleet", self.request("/ui/triggers?db=test-generation")[1])        # plan C12: no fleet budget

    def test_runs_that_start_nothing_say_why_and_wake_no_model(self):
        goal = hub.ins("INSERT INTO goals(title,text,state,revision,limits,created,updated,request_id) "
                       "VALUES(?,?,'active',1,?,?,?,?)", ("Sales", "Sell more.", json.dumps(
                           {"money": None, "tokens": None, "deadline": None, "not_to_do": []}), self.clock, self.clock,
                           str(uuid.uuid4())))
        tid = self.create(task=dict(TASK, goal_id=goal))["trigger"]["id"]
        self.sweep(MON_12)
        first = hub.q1("SELECT * FROM tasks")
        self.assertEqual((first["goal"], first["goal_id"]), (f"G-{goal}", goal))
        woken = self.woken()
        self.sweep(THU_15)
        self.assertEqual(self.last_run(), ("not_started", f"T-{first['id']} is still open."))
        hub.q("UPDATE tasks SET state='canceled' WHERE id=?", (first["id"],))
        oid = hub.ins("INSERT INTO outcomes(task,attempt,hold,tool_call_id,title,kind,state,created) VALUES(?,1,1,?,?,?,?,?)",
                      (first["id"], "call-1", "Send the note", "execute", "unknown", self.clock))
        self.sweep(MON_19)
        self.assertEqual(self.last_run(), ("not_started", f"O-{oid} of T-{first['id']} is unknown. Settle it first."))
        hub.settle_outcome(oid, "not_done", "owner")
        self.clock = MON_19 + 60
        second = self.run_now(tid)
        self.assertEqual(second["state"], "started")
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (second["task"],))
        self.clock += 60
        hub.TEAM["triggers"] = {"max_tasks_per_day": 1}     # read as valid, and used by nothing (plan C12)
        third = self.run_now(tid)                           # no count caps a rule, and no fleet budget
        self.assertEqual(third["state"], "started")
        del hub.TEAM["triggers"]
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (third["task"],))
        hub.q("UPDATE goals SET state='paused', paused_by='owner' WHERE id=?", (goal,))
        self.run_now(tid)
        self.assertEqual(self.last_run(), ("not_started", f"No new task for G-{goal}: the owner paused it."))
        hub.q("UPDATE goals SET state='active', paused_by=NULL WHERE id=?", (goal,))
        self.sweep(THU_22 + 7200)                           # no late window: it starts, and says how late
        self.assertEqual(self.last_run(), ("started", None))
        self.assertIn("It started 120 minutes after that time.",
                      hub.q1("SELECT details FROM tasks ORDER BY id DESC LIMIT 1")["details"])
        self.assertEqual(self.woken(), woken + 3)           # the start events of the second, third and fourth tasks
        self.assertEqual(self.count("tasks"), 4)

    def test_after_hub_downtime_only_the_latest_due_time_runs(self):
        tid = self.create(schedule={"kind": "every", "minutes": 15})["trigger"]["id"]
        anchor = hub.trigger_row(tid)["anchor"]
        self.sweep(anchor + 3 * 3600 + 60)                  # the hub was down while 12 due times passed
        self.assertEqual([(r["due"], r["state"]) for r in hub.q("SELECT * FROM trigger_runs")],
                         [(anchor + 3 * 3600, "started")])
        self.assertEqual((hub.trigger_row(tid)["next_due"], self.count("tasks")), (anchor + 3 * 3600 + 900, 1))

    def test_a_late_run_starts_and_says_how_late(self):
        """Plan C12: no late window ends a run. A run of a 1-minute rule a moment late says nothing; the newest due
        time after a long gap runs once, and its task says how late it started."""
        tid = self.create(schedule={"kind": "every", "minutes": 1})["trigger"]["id"]
        anchor = hub.trigger_row(tid)["anchor"]
        self.sweep(anchor + 60 + 59)
        self.assertEqual(self.last_run(), ("started", None))
        self.assertNotIn("after that time", hub.q1("SELECT details FROM tasks")["details"])
        weekly = self.create(task=dict(TASK, title="Weekly"))["trigger"]["id"]
        self.sweep(MON_12 + 3600)                           # the hub was down for an hour after the weekly time
        run = hub.q1("SELECT * FROM trigger_runs WHERE trigger_id=? ORDER BY id DESC", (weekly,))
        self.assertEqual((run["state"], run["due"]), ("started", MON_12))
        self.assertIn("It started 60 minutes after that time.",
                      hub.q1("SELECT details FROM tasks WHERE id=?", (run["task"],))["details"])

    def test_pause_resume_delete_and_run_now(self):
        tid = self.create()["trigger"]["id"]
        code, data = self.state(tid, 1, "run_now")
        run = data["run"]
        self.assertEqual((code, run["state"], run["manual"], run["revision"], data["trigger"]["revision"],
                          data["trigger"]["next_due"]), (200, "started", True, 1, 1, MON_12))
        task = hub.q1("SELECT * FROM tasks WHERE id=?", (run["task"],))
        self.assertTrue(task["details"].endswith(f"(revision 1, run {run['id']}) through Run task now at Sat 10 Oct 2026 "
                                                 f"21:10 Europe/Madrid."))
        again = self.state(tid, 1, "run_now")[1]["run"]
        self.assertEqual((again["state"], again["reason"], again["task"]), ("not_started", f"T-{task['id']} is still open.", None))
        code, data = self.state(tid, 1, "pause")
        self.assertEqual((code, data["trigger"]["state"], data["trigger"]["paused_by"], data["trigger"]["revision"],
                          data["trigger"]["next_due"], data["run"]), (200, "paused", "owner", 2, None, None))
        self.assertEqual(self.detail(tid)[1]["upcoming"], [])
        self.sweep(MON_12 + 5)                              # a paused trigger does not run
        self.assertEqual(self.count("trigger_runs"), 2)
        self.assertEqual(self.state(tid, 2, "run_now")[0], 409)
        code, data = self.state(tid, 1, "resume")
        self.assertEqual((code, data["revision"]), (409, 2))
        code, data = self.state(tid, 2, "resume")
        self.assertEqual((code, data["trigger"]["state"], data["trigger"]["revision"], data["trigger"]["next_due"]),
                         (200, "active", 3, THU_15))       # no backlog: the missed Monday does not run
        code, data = self.state(tid, 3, "delete")
        self.assertEqual((code, data["trigger"]["state"], data["trigger"]["next_due"]), (200, "deleted", None))
        self.assertEqual(self.request("/ui/triggers?db=test-generation")[1]["triggers"], [])
        one = self.detail(tid)[1]
        self.assertEqual((one["trigger"]["state"], len(one["runs"])), ("deleted", 2))         # the history stays
        self.assertIn("deleted", self.refused(tid, 4, task=TASK))
        self.assertEqual(self.state(tid, 4, "resume")[0], 409)
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (task["id"],))["state"], "submitted")

    def test_runs_page_newest_first(self):
        tid = self.create(schedule={"kind": "every", "minutes": 5})["trigger"]["id"]
        anchor = hub.trigger_row(tid)["anchor"]
        for k in range(1, 6):
            self.sweep(anchor + k * 300)
        code, page = self.request(f"/ui/triggers/{tid}?db=test-generation&limit=2")
        self.assertEqual(([r["due"] for r in page["runs"]], page["next"]), ([anchor + 1500, anchor + 1200], page["runs"][-1]["id"]))
        code, page = self.request(f"/ui/triggers/{tid}?db=test-generation&limit=2&before={page['next']}")
        self.assertEqual([r["due"] for r in page["runs"]], [anchor + 900, anchor + 600])
        code, page = self.request(f"/ui/triggers/{tid}?db=test-generation&limit=2&before={page['next']}")
        self.assertEqual(([r["due"] for r in page["runs"]], page["next"]), ([anchor + 300], None))
        self.assertEqual(self.request(f"/ui/triggers/{tid}?db=test-generation&limit=201")[0], 400)
        self.assertEqual(self.count("tasks"), 1)            # the first run starts its task; the others find it open

    def test_a_once_trigger_is_done_after_its_run(self):
        tid = self.create(schedule={"kind": "once", "at": "2026-10-14T09:00", "timezone": "Europe/Madrid"})["trigger"]["id"]
        self.sweep(at("2026-10-14T09:00") + 30)
        t = hub.trigger_row(tid)
        self.assertEqual((t["state"], t["next_due"], t["revision"], self.count("tasks")), ("done", None, 1, 1))
        self.assertEqual(self.state(tid, 1, "resume")[0], 409)
        self.assertEqual(self.state(tid, 1, "delete")[1]["trigger"]["state"], "deleted")

    def test_an_agent_that_left_the_team_pauses_its_trigger(self):
        tid = self.create()["trigger"]["id"]
        del hub.TEAM["agents"]["vps"]
        self.sweep(MON_12)
        t = hub.trigger_row(tid)
        self.assertEqual((t["state"], t["paused_by"], t["paused_reason"], t["revision"], t["next_due"]),
                         ("paused", "hub", "vps is no longer in the team.", 2, None))
        self.assertEqual(self.last_run(), ("not_started", "vps is no longer in the team, so the hub paused this trigger."))
        self.assertEqual((self.woken(), self.count("tasks")), (0, 0))

    def test_a_failed_write_leaves_no_run_task_or_attempt(self):
        class FailAt:
            """hub.DB with one failing INSERT: an interruption between the writes of a run."""
            def __init__(self, db, table):
                self.db, self.table = db, table

            def execute(self, sql, *args):
                if sql.startswith(f"INSERT INTO {self.table}("):
                    raise sqlite3.OperationalError("disk I/O error")
                return self.db.execute(sql, *args)

            def __getattr__(self, name):
                return getattr(self.db, name)

        tid = self.create()["trigger"]["id"]
        before = dict(hub.trigger_row(tid))
        tables = ("trigger_runs", "tasks", "attempts", "events")
        with patch.object(hub, "DB", FailAt(hub.DB, "events")), patch.object(hub.traceback, "print_exc"):
            self.sweep(MON_12)
        self.assertEqual([self.count(x) for x in tables], [0, 0, 0, 0])
        self.assertEqual(dict(hub.trigger_row(tid)), before)
        self.sweep(MON_12 + 5)                              # the next tick decides once
        self.assertEqual([self.count(x) for x in tables], [1, 1, 1, 1])


STAND_INS = {
    "value.py": SYNTHETIC.decode(),
    "probe.py": ("import json, os\n"
                 "bad = [k for k in os.environ if k.startswith('FLEET')] + (['cwd'] if os.listdir('.') else [])\n"
                 "bad += [] if os.path.realpath(os.environ['HOME']) == os.path.realpath(os.getcwd()) else ['home']\n"
                 "print(json.dumps({'value': len(bad), 'summary': ','.join(bad)}))\n"),
    "sleep.py": "import time\ntime.sleep(30)\n",
    "exit3.py": "raise SystemExit(3)\n",
    "loud.py": "print('x' * 5000)\n",
    "boolean.py": "print('{\"value\": true}')\n",
    "twice.py": "print('{\"value\": 1}')\nprint('{\"value\": 2}')\n",
    "nan.py": "print('{\"value\": NaN}')\n",
    "huge.py": "print('{\"value\": 1e999}')\n",
    "badcode.py": "print('{\"error\": \"Bad Code\"}')\n",
    "limited.py": "print('{\"error\": \"rate_limited\", \"detail\": \"HTTP 429\", \"retry_after\": 600}')\n",
}


class Runner(unittest.TestCase):
    """The helper's check runner, with stand-in checks in a temporary Git repository."""
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="fleet-runner-"))
        git("init", "-q", str(self.root))
        (self.root / "checks").mkdir()
        for name, text in STAND_INS.items():
            (self.root / "checks" / name).write_text(text)
        git("add", "-A", cwd=self.root)
        git("commit", "-q", "-m", "checks", cwd=self.root)
        self.commit = git("rev-parse", "HEAD", cwd=self.root)
        self.addCleanup(shutil.rmtree, str(self.root), True)

    def run_check(self, name, **changes):
        extra = dict({"trigger": 3, "run": 21, "token": str(uuid.uuid4()), "expires": time.time() + 60,
                      "path": f"checks/{name}", "commit": self.commit,
                      "sha256": hashlib.sha256(STAND_INS.get(name, "").encode()).hexdigest(), "args": {},
                      "timeout_seconds": 5}, **changes)
        return fleet.run_check(extra, kit=str(self.root))

    def test_a_check_runs_the_pinned_bytes_and_returns_its_value(self):
        (self.root / "checks" / "value.py").write_text("print('{\"value\": 999}')\n")     # the working tree changes
        result = self.run_check("value.py", args={"value": 11})
        self.assertEqual((result["ok"], result["value"], result["summary"]), (True, 11, "synthetic value 11"))
        self.assertIsInstance(result["elapsed_ms"], int)
        with patch.dict(os.environ, {"FLEET_AGENT": "vps", "FLEET_HUB": "http://127.0.0.2:8765"}):
            self.assertEqual(self.run_check("probe.py")["value"], 0)       # no Fleet value; an empty folder as HOME
        limited = self.run_check("limited.py")
        self.assertEqual((limited["ok"], limited["error"], limited["detail"], limited["retry_after"]),
                         (False, "rate_limited", "HTTP 429", 600))

    def test_runner_failures_are_errors_and_never_values(self):
        for name, code in (("sleep.py", "timeout"), ("exit3.py", "exit"), ("loud.py", "too_large"),
                           ("boolean.py", "bad_output"), ("twice.py", "bad_output"), ("nan.py", "bad_output"),
                           ("huge.py", "bad_output"), ("badcode.py", "bad_output")):
            with self.subTest(name=name):
                result = self.run_check(name, timeout_seconds=1)
                self.assertEqual((result["ok"], result["error"]), (False, code), result)
        self.assertEqual(self.run_check("value.py", sha256="0" * 64)["error"], "changed")
        self.assertEqual(self.run_check("none.py")["error"], "missing")
        # DevOps plan 0.2: a check of the code is read at this checkout's own HEAD, and only from checks/
        self.assertEqual(self.run_check("value.py", path="outputs/T-1/value.py")["error"], "missing")


    def test_saved_code_comes_from_this_machines_own_store_and_must_match_its_sha256(self):
        """DevOps plan 0.2: the hub gives only the SHA-256, and the code is the one that the agent's own session put
        in its machine's store; the hub is never asked for it."""
        source = STAND_INS["value.py"]
        extra = {"trigger": 3, "run": 21, "token": str(uuid.uuid4()), "expires": time.time() + 60, "code": "saved",
                 "sha256": hashlib.sha256(source.encode()).hexdigest(), "args": {"value": 7}, "timeout_seconds": 5}
        store = self.root / "store"
        store.mkdir()
        with patch.object(fleet, "http", side_effect=AssertionError("a saved check asks the hub for nothing")):
            self.assertEqual(fleet.run_check(extra, kit=str(self.root), agent="vps", store=str(store))["error"],
                             "missing")
            (store / f"{extra['sha256']}.py").write_text(source + "# changed\n")
            self.assertEqual(fleet.run_check(extra, kit=str(self.root), agent="vps", store=str(store))["error"],
                             "changed")
            (store / f"{extra['sha256']}.py").write_text(source)
            result = fleet.run_check(extra, kit=str(self.root), agent="vps", store=str(store))
        self.assertEqual((result["ok"], result["value"]), (True, 7))

class Checks(OwnerAPI):
    """Hub side of code checks, with a stand-in helper that reads the trigger_check events and posts results."""
    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        hub.TEAM["addresses"]["vps"] = "127.0.0.1"         # the stand-in helper posts from this machine
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90,
                       ask_wait=1, ask_max=1, hook_wait=2, job_wait=1, tick=5)
        self.clock = at("2026-10-10T21:10")
        clock = patch.object(hub, "now", lambda: self.clock)
        clock.start()
        self.addCleanup(clock.stop)
        self.kit = Path(tempfile.mkdtemp(prefix="fleet-check-kit-"))
        self.addCleanup(shutil.rmtree, str(self.kit), True)
        (self.kit / "team.json").write_text(json.dumps(hub.TEAM, indent=2) + "\n")
        (self.kit / "checks").mkdir()
        (self.kit / "checks" / "synthetic_value.py").write_bytes(SYNTHETIC)
        git("init", "-q", str(self.kit))
        self.commit = self.save_kit()
        hub.CFG["team_path"] = str(self.kit / "team.json")
        self.addCleanup(hub.CFG.pop, "team_path", None)
        hub._revision_cache.update(at=0.0, value=None)
        self.sha = hashlib.sha256(SYNTHETIC).hexdigest()
        self.online = True
        hub.touch("vps")
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES('vps',?,?)",
              (json.dumps({"features": ["trigger_check"]}), self.clock))

    # ---- helpers
    def save_kit(self, message="checks"):
        git("add", "-A", cwd=self.kit)
        git("commit", "-q", "-m", message, cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        return git("rev-parse", "HEAD", cwd=self.kit)

    def check(self, **changes):
        return dict({"path": "checks/synthetic_value.py", "commit": self.commit, "sha256": self.sha,
                     "args": {"value": 11}, "condition": {"op": ">", "value": 10}, "repeat_minutes": None}, **changes)

    def create(self, **changes):
        return make(dict({"agent": "vps", "schedule": {"kind": "every", "minutes": 60}, "task": TASK,
                          "check": self.check()}, **changes), self.clock)

    def edit(self, tid, base, **changes):
        return change(tid, base, changes, self.clock)

    def refused(self, **changes):
        with self.assertRaises((ValueError, hub.Refusal)) as caught:
            self.create(**changes)
        return str(caught.exception)

    def state(self, tid, base, action):
        return self.request(f"/ui/triggers/{tid}/state", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                              base_revision=base, action=action))

    def tick(self, when):
        self.clock = when
        if self.online:
            hub.touch("vps")                # the stand-in helper checks in
        with hub.LOCK:
            hub.trigger_sweep(when)

    def sent(self):
        """The stand-in helper reads the newest trigger_check event."""
        e = hub.q1("SELECT * FROM events WHERE kind='trigger_check' ORDER BY id DESC LIMIT 1")
        return json.loads(e["extra"]) if e else None

    def answer(self, extra, **result):
        body = dict({"token": extra["token"], "ok": True, "value": 10, "summary": "10 open tickets"}, **result)
        if not body["ok"]:
            body.pop("value"), body.pop("summary")
        return self.request(f"/helper/trigger/vps/{extra['run']}", body)

    def run_row(self, run=None):
        return hub.q1("SELECT * FROM trigger_runs WHERE id=?", (run,)) if run else \
            hub.q1("SELECT * FROM trigger_runs ORDER BY id DESC LIMIT 1")

    def woken(self):
        """The AI-dispatch spy: events that start or wake a model session, for every agent and the manager."""
        return hub.q1("SELECT COUNT(*) n FROM events WHERE kind IN ('say','task','chat')")["n"]

    def offline(self):
        self.online = False
        hub.q("UPDATE agents SET last_seen=? WHERE name='vps'", (self.clock - 1000,))

    # ---- catalog and pin
    def test_the_catalog_gives_exact_bytes_and_says_why_a_file_is_not_a_check(self):
        for name, data in (("big.py", b"#" * 65537), ("latin.py", "x = 'caf\xe9'\n".encode("latin-1")),
                           ("Bad-Name.py", b"print(1)\n"), ("notes.md", b"not a check\n"),
                           ("secret.py", f"TOKEN = '{SECRET}'\n".encode())):
            (self.kit / "checks" / name).write_bytes(data)
        os.symlink("synthetic_value.py", self.kit / "checks" / "link.py")
        rev = self.save_kit("more files")
        register_secret()
        code, data = self.request("/ui/checks?db=test-generation")
        self.assertEqual((code, set(data), data["revision"]), (200, {"db", "revision", "checks", "skipped"}, rev))
        self.assertEqual(data["checks"], [{"path": "checks/synthetic_value.py", "commit": rev, "sha256": self.sha,
                                           "bytes": len(SYNTHETIC), "source": SYNTHETIC.decode("utf-8")}])
        self.assertEqual(hashlib.sha256(data["checks"][0]["source"].encode("utf-8")).hexdigest(), self.sha)
        self.assertEqual({s["path"]: s["reason"] for s in data["skipped"]}, {
            "checks/Bad-Name.py": "Its name must be checks/<name>.py, with a name of a-z, 0-9 and _.",
            "checks/big.py": "It is larger than 64 KiB.", "checks/latin.py": "It is not UTF-8 text.",
            "checks/link.py": "It is not a regular file.", "checks/secret.py": "It contains a registered login."})
        self.assertNotIn(SECRET, json.dumps(data))
        self.assertEqual(self.request("/ui/checks?db=old")[0], 409)
        for i in range(40):
            (self.kit / "checks" / f"fill_{i:02d}.py").write_bytes(b"#" * 60000)
        self.save_kit("a large catalog")
        self.assertEqual(self.request("/ui/checks?db=test-generation"),
                         (413, {"error": "the check catalog is larger than 2 MiB; remove or shorten files in checks/"}))

    def test_a_check_is_pinned_to_exact_bytes_of_the_hub_history(self):
        trigger = self.create()["trigger"]
        self.assertEqual((trigger["check"], trigger["failures"], trigger["armed"]),
                         (self.check(timeout_seconds=30), 0, {"armed": True, "reason": None}))
        git("checkout", "-q", "-b", "side", cwd=self.kit)
        (self.kit / "checks" / "other.py").write_text("print('{\"value\": 1}')\n")
        side = self.save_kit("not on main")
        git("checkout", "-q", "main", cwd=self.kit)
        register_secret()
        no_repeat = {k: v for k, v in self.check().items() if k != "repeat_minutes"}
        for change in ({"check": self.check(sha256="0" * 64)}, {"check": self.check(commit=side)},
                       {"check": self.check(path="checks/none.py")}, {"check": self.check(extra=1)},
                       {"check": no_repeat}, {"check": self.check(condition={"op": "~", "value": 1})},
                       {"check": self.check(timeout_seconds=0)}, {"check": self.check(path="other.py")},
                       {"check": self.check(args={"blob": "x" * 5000})}):
            with self.subTest(change=change):
                self.assertTrue(self.refused(**change))
        self.assertTrue(hub.secret_hit(json.dumps(self.check(args={"login": SECRET}))))
        hub.q("UPDATE machine_status SET data=? WHERE agent='vps'", (json.dumps({"features": []}),))
        self.assertIn("cannot run these checks yet", self.refused())
        hub.q("UPDATE machine_status SET data=? WHERE agent='vps'", (json.dumps({"features": ["trigger_check"]}),))
        tid = trigger["id"]
        self.assertEqual(self.edit(tid, 1, check=self.check(timeout_seconds=90))["trigger"]["check"]["timeout_seconds"],
                         90)                                # plan C12: the author's own timeout, with no ceiling
        tid, trigger = tid, self.edit(tid, 2, check=self.check())["trigger"]
        data = self.edit(tid, 3, task=dict(TASK, title="Other"))    # an edit without check keeps the condition
        self.assertEqual(data["trigger"]["check"], trigger["check"])
        data = self.edit(tid, 4, check=None)                        # "check": null removes it
        self.assertEqual((data["trigger"]["check"], data["trigger"]["armed"]), (None, None))
        self.assertEqual(self.count("triggers"), 1)

    def test_check_args_are_counted_as_compact_utf8_json_bytes(self):
        fits = {"s": "\u00e9" * 2044}       # {"s":"…"}: 8 bytes and 2 bytes for each é, so exactly 4096
        self.assertEqual(len(json.dumps(fits, ensure_ascii=False, separators=(",", ":")).encode("utf-8")), 4096)
        self.assertEqual(self.create(check=self.check(args=fits))["trigger"]["check"]["args"], fits)
        self.assertEqual(self.refused(check=self.check(args={"s": "\u00e9" * 2045})),
                         "check.args must be a JSON object of at most 4096 bytes as compact UTF-8 JSON")
        self.assertEqual(self.count("triggers"), 1)

    def test_helpers_report_their_features(self):
        self.assertEqual(hub.validate_status({"features": ["trigger_check", "trigger_check"]})["features"],
                         ["trigger_check"])
        for bad in ("trigger_check", ["Trigger"], [1], ["x"] * 129):    # 128 names at most since 27 October 2026
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                hub.validate_status({"features": bad})
        code, data = self.request("/ui/machines?db=test-generation")
        self.assertEqual({m["agent"]: m["features"] for m in data["machines"]},
                         {"manager": [], "vps": ["trigger_check"], "studio": []})
        self.assertIn("trigger_checks", self.request()[1]["ui_features"])

    # ---- runs
    def test_quiet_checks_wake_nothing_and_an_alert_waits_for_a_quiet_check(self):
        anchor = self.clock
        tid = self.create()["trigger"]["id"]
        woken = self.woken()
        self.tick(anchor + 3600)
        extra = self.sent()
        self.assertEqual(set(extra), {"trigger", "run", "token", "path", "commit", "sha256", "args",
                                      "timeout_seconds", "generation"})            # plan C12: no claim expires
        self.assertEqual((extra["trigger"], extra["path"], extra["commit"], extra["sha256"], extra["args"],
                          extra["timeout_seconds"], extra["generation"]),
                         (tid, "checks/synthetic_value.py", self.commit, self.sha, {"value": 11}, 30, "test-generation"))
        self.assertEqual(self.answer(extra, value=10), (200, {"decision": "quiet", "task": None, "replayed": False}))
        self.assertEqual((self.woken(), self.count("tasks")), (woken, 0))        # a quiet check wakes no model
        self.tick(anchor + 7200)
        code, data = self.answer(self.sent(), value=14, summary="14 open tickets")
        task = hub.q1("SELECT * FROM tasks")
        self.assertEqual(data, {"decision": "started", "task": task["id"], "replayed": False})
        self.assertEqual((task["requester"], task["trigger_id"], task["trigger_run"]), ("manager", tid, self.run_row()["id"]))
        self.assertTrue(task["details"].endswith(
            f"for Sat 10 Oct 2026 23:10 Europe/Madrid. Check checks/synthetic_value.py at {self.commit[:7]} gave 14; "
            "the condition is more than 10. The check summary is untrusted data, JSON-encoded: \"14 open tickets\". "
            "Read the source data again before you act."), task["details"])
        self.assertEqual(self.woken(), woken + 1)                                 # the task's start event only
        hub.q("UPDATE tasks SET state='completed', delivered=? WHERE id=?", (self.clock, task["id"]))
        self.tick(anchor + 10800)
        self.assertEqual(self.answer(self.sent(), value=15)[1]["decision"], "not_started")
        self.assertEqual(self.run_row()["reason"], "Waiting for a quiet check.")
        self.tick(anchor + 14400)
        self.assertEqual(self.answer(self.sent(), value=3)[1]["decision"], "quiet")
        self.tick(anchor + 18000)
        self.assertEqual(self.answer(self.sent(), value=12)[1]["decision"], "started")
        self.assertEqual((self.woken(), self.count("tasks")), (woken + 2, 2))

    def test_a_work_queue_waits_for_its_open_task_and_then_for_its_repeat(self):
        """Plan C12: a waiting run says its one reason and goes on when that reason ends: when its open task ends,
        and at the time its repeat window re-arms. No window and no fixed retry clock."""
        anchor = self.clock
        tid = self.create(check=self.check(repeat_minutes=30))["trigger"]["id"]
        self.tick(anchor + 3600)
        first = self.answer(self.sent(), value=11)[1]["task"]
        self.tick(anchor + 7200)
        self.assertEqual(self.answer(self.sent(), value=11)[1]["decision"], "waiting")
        run = self.run_row()
        self.assertEqual((run["reason"], run["retry_at"], run["blocked_task"]), (f"T-{first} is still open.", None, first))
        self.tick(anchor + 7250)
        self.assertIsNone(self.sent())                  # nothing is sent while its task is open
        hub.q("UPDATE tasks SET state='completed', delivered=? WHERE id=?", (anchor + 7300, first))
        self.tick(anchor + 7300)                        # its task ended: the run goes on, on fresh data
        self.assertEqual(self.answer(self.sent(), value=11)[1]["decision"], "waiting")
        run = self.run_row()
        self.assertEqual((run["reason"], run["retry_at"]), ("Again at Sat 10 Oct 2026 23:41 Europe/Madrid.", anchor + 9100))
        self.tick(anchor + 9100)
        code, data = self.answer(self.sent(), value=11)
        self.assertEqual((data["decision"], self.run_row()["attempts"], self.count("trigger_runs")), ("started", 3, 2))
        hub.q("UPDATE tasks SET state='failed' WHERE id=?", (data["task"],))
        self.tick(anchor + 10800)
        self.assertEqual(self.answer(self.sent(), value=11)[1]["decision"], "not_started")
        self.assertEqual(self.run_row()["reason"], f"T-{data['task']} ended failed. Only a quiet check or Run task now "
                                                   "starts the next task.")

    def test_errors_try_again_at_their_own_time_and_never_pause_the_rule(self):
        """Plan C12: an error ends its run, or waits for its own retry_after; a series of errors pauses nothing and
        shows as failing since its first error, until a valid value comes."""
        anchor = self.clock
        tid = self.create()["trigger"]["id"]
        self.tick(anchor + 3600)
        code, data = self.answer(self.sent(), ok=False, error="timeout", detail="no answer in 30 seconds")
        run = self.run_row()
        self.assertEqual((data["decision"], run["state"], run["retry_at"], run["reason"], run["error"]),
                         ("error", "error", None, "The check failed: timeout.", "timeout"))     # the next due time
        self.assertEqual(hub.trigger_row(tid)["failures"], 1)
        self.tick(anchor + 7200)
        self.answer(self.sent(), ok=False, error="rate_limited", detail="HTTP 429", retry_after=1800)
        run = self.run_row()
        self.assertEqual((run["state"], run["retry_at"], hub.trigger_row(tid)["failures"]), ("waiting", anchor + 9000, 2))
        self.tick(anchor + 9000)
        self.answer(self.sent(), ok=False, error="exit", detail="exit code 3")
        for hours in (3, 4, 5):                         # six errors in a row: the rule stays active
            self.tick(anchor + 3600 * hours)
            self.answer(self.sent(), ok=False, error="exit", detail="exit code 3")
        t = hub.trigger_row(tid)
        self.assertEqual((t["state"], t["paused_by"], t["failures"]), ("active", None, 6))
        view = hub.trigger_view(t, self.clock)
        self.assertEqual(view["failing_since"], anchor + 3600)
        self.assertIn("Failing since Sat 10 Oct 2026 22:10 Europe/Madrid: 6 check error(s) in a row",
                      hub.wakeups.describe(view, hub.wake_when(t)))
        self.tick(anchor + 21600)
        self.assertEqual(self.answer(self.sent(), value=3)[1]["decision"], "quiet")      # a valid value ends the series
        t = hub.trigger_row(tid)
        self.assertEqual((t["failures"], hub.trigger_view(t, self.clock)["failing_since"]), (0, None))
        self.assertEqual(self.woken(), 0)

    def test_check_now_is_one_execution_that_never_starts_a_task(self):
        tid = self.create()["trigger"]["id"]
        code, data = self.state(tid, 1, "check_now")
        run = data["run"]
        self.assertEqual((code, run["state"], run["manual"], run["check_now"], run["attempts"], data["trigger"]["revision"]),
                         (200, "sent", True, True, 1, 1))
        self.assertEqual(self.state(tid, 1, "check_now")[0], 409)          # one open run at a time
        self.assertEqual(self.answer(self.sent(), value=11)[1]["decision"], "not_started")
        self.assertEqual(self.run_row()["reason"], "Check now never starts a task.")
        self.state(tid, 1, "check_now")
        self.assertEqual(self.answer(self.sent(), ok=False, error="exit", detail="exit code 3")[1]["decision"], "error")
        self.assertEqual((self.run_row()["retry_at"], hub.trigger_row(tid)["failures"]), (None, 1))     # no timer retry
        self.state(tid, 1, "check_now")
        self.assertEqual(self.answer(self.sent(), value=3)[1]["decision"], "quiet")
        self.assertEqual(hub.trigger_row(tid)["failures"], 0)
        code, data = self.state(tid, 1, "run_now")
        self.assertEqual((data["run"]["state"], data["run"]["manual"], data["run"]["check_now"]), ("started", True, False))
        self.assertEqual((self.count("tasks"), self.woken()), (1, 1))         # only Run task now started a task
        self.offline()
        self.assertEqual(self.state(tid, 1, "check_now"),
                         (409, {"error": "Vps is not answering. Check again when it does."}))

    def test_results_need_the_live_claim_and_a_retry_gets_the_stored_answer(self):
        anchor = self.clock
        tid = self.create()["trigger"]["id"]
        self.tick(anchor + 3600)
        extra = self.sent()
        body = {"token": extra["token"], "ok": True, "value": 3, "summary": "3 open"}
        first = self.request(f"/helper/trigger/vps/{extra['run']}", body)
        self.assertEqual(self.request(f"/helper/trigger/vps/{extra['run']}", body), (200, dict(first[1], replayed=True)))
        self.assertEqual(self.request(f"/helper/trigger/vps/{extra['run']}", dict(body, value=4))[0], 409)
        self.tick(anchor + 7200)
        extra = self.sent()
        # plan P0: a field that the hub does not know reads as absent, so it is not refused here
        # (test_release_turns.RollbackReads)
        for bad in ({"value": True}, {"value": float("nan")}, {"token": "x"}):
            with self.subTest(bad=bad):
                self.assertEqual(self.answer(extra, **bad)[0], 400)
        self.assertEqual(self.answer(dict(extra, token=str(uuid.uuid4())))[1], {"error": "this claim is obsolete"})
        self.assertEqual(self.request(f"/helper/trigger/studio/{extra['run']}", body)[0], 403)
        self.clock += 86400                             # plan C12: no claim expires
        self.assertEqual(self.answer(extra, value=3)[1]["decision"], "quiet")
        for action, why in (("edit", "The trigger changed."), ("pause", "The trigger was paused."),
                            ("delete", "The trigger was deleted.")):
            with self.subTest(action=action):
                base = hub.trigger_row(tid)["revision"]
                if hub.trigger_row(tid)["state"] == "paused":
                    self.state(tid, base, "resume")
                    base += 1
                self.tick(hub.trigger_row(tid)["next_due"])
                extra = self.sent()
                if action == "edit":
                    self.edit(tid, base, task=dict(TASK, title="Changed"))
                else:
                    self.state(tid, base, action)
                self.assertEqual(self.answer(extra), (409, {"error": "this claim is obsolete"}))
                self.assertEqual((self.run_row(extra["run"])["state"], self.run_row(extra["run"])["reason"]),
                                 ("obsolete", why))

    def test_a_secret_in_check_output_is_never_stored(self):
        anchor = self.clock
        self.create()
        register_secret()
        self.tick(anchor + 3600)
        code, data = self.answer(self.sent(), value=11, summary=f"found {SECRET}")
        run = self.run_row()
        self.assertEqual((data["decision"], run["error"], run["detail"]),
                         ("error", "blocked", "The check output contained a registered login."))
        self.assertNotIn(SECRET, json.dumps([dict(r) for r in hub.q("SELECT * FROM trigger_runs")]))

    def test_a_one_off_check_waits_for_an_offline_helper(self):
        once = {"kind": "once", "at": "2026-10-12T09:00", "timezone": "Europe/Madrid"}
        tid = self.create(schedule=once)["trigger"]["id"]
        self.offline()
        self.tick(MON_12 + 5)
        run, t = self.run_row(), hub.trigger_row(tid)
        self.assertEqual((run["state"], run["reason"], self.sent(), t["state"], t["next_due"]),
                         ("waiting", "Vps is not answering.", None, "active", None))
        self.online = True
        self.tick(MON_12 + 7200)                        # back two hours later: the check runs on fresh data
        self.assertEqual(self.answer(self.sent(), value=11)[1]["decision"], "started")
        self.assertEqual(hub.trigger_row(tid)["state"], "done")
        self.assertIn("It started 120 minutes after that time.", hub.q1("SELECT details FROM tasks")["details"])

    def test_a_one_minute_quiet_check_keeps_one_row_and_its_events_go(self):
        """Plan C12: a quiet run takes the place of the quiet run before it, and a decided run's event is deleted."""
        anchor = self.clock
        tid = self.create(schedule={"kind": "every", "minutes": 1})["trigger"]["id"]
        for k in range(1, 6):
            self.tick(anchor + 60 * k)
            self.assertEqual(self.answer(self.sent(), value=3)[1]["decision"], "quiet")
        runs = hub.q("SELECT * FROM trigger_runs WHERE trigger_id=?", (tid,))
        self.assertEqual([(r["state"], r["due"], r["created"]) for r in runs], [("quiet", anchor + 300, anchor + 60)])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE kind='trigger_check'")["n"], 0)

    def test_twenty_five_wake_ups_in_a_day_all_start(self):
        """Plan C12: no count of wake-ups caps a rule, and the fleet has no budget."""
        anchor = self.clock
        tid = self.create(schedule={"kind": "every", "minutes": 30}, check=self.check(repeat_minutes=0))["trigger"]["id"]
        for k in range(1, 26):
            self.tick(anchor + 1800 * k)
            self.assertEqual(self.answer(self.sent(), value=11)[1]["decision"], "started")
            hub.q("UPDATE tasks SET state='completed', delivered=? WHERE trigger_id=? AND state<>'completed'",
                  (self.clock, tid))
        self.assertEqual(self.count("tasks"), 25)

    def test_a_run_held_by_a_usage_limit_goes_on_at_the_reset(self):
        anchor = self.clock
        self.create()
        hub.ins("INSERT INTO agent_limits(agent,since,until,reset_known) VALUES('vps',?,?,1)", (anchor, anchor + 5400))
        self.tick(anchor + 3600)
        self.assertEqual(self.answer(self.sent(), value=11)[1]["decision"], "waiting")
        run = self.run_row()
        self.assertEqual((run["retry_at"], run["reason"]), (anchor + 5400, "vps is at its usage limit until 20:40 UTC."))
        self.tick(anchor + 5000)
        self.assertIsNone(self.sent())                                      # the reset, not a retry clock
        hub.q("UPDATE agent_limits SET ended=?", (anchor + 5400,))
        self.tick(anchor + 5400)
        self.assertEqual(self.answer(self.sent(), value=11)[1]["decision"], "started")

    def test_a_run_its_helper_lost_is_sent_once_more_and_a_second_loss_ends_it(self):
        anchor = self.clock
        tid = self.create()["trigger"]["id"]
        hub.q("UPDATE machine_status SET data=? WHERE agent='vps'", (json.dumps({"features": ["trigger_check",
                                                                                              "check_runs"]}),))
        self.tick(anchor + 3600)
        first = self.sent()
        event = hub.q1("SELECT id FROM events WHERE kind='trigger_check'")["id"]
        self.assertEqual(self.request("/helper/ack/vps", {"ids": [event]})[0], 200)
        self.clock += 1
        poll = lambda held: self.request(f"/events/vps?delivery=1&after=0&wait=0&checks={held}")
        self.assertEqual(poll(first["run"])[0], 200)                       # it holds the run: nothing changes
        self.assertEqual(self.run_row()["state"], "sent")
        poll("")                                                            # a helper that started again holds none
        run = self.run_row()
        self.assertEqual((run["state"], run["reason"]), ("waiting", "Vps lost this check; it is sent once more."))
        self.tick(self.clock + 1)
        again = self.sent()
        self.assertNotEqual(again["token"], first["token"])
        event = hub.q1("SELECT id FROM events WHERE kind='trigger_check'")["id"]
        self.request("/helper/ack/vps", {"ids": [event]})
        self.clock += 1
        poll("")
        run = self.run_row()
        self.assertEqual((run["state"], run["error"]), ("error", "lost"))
        self.assertEqual(hub.trigger_row(tid)["state"], "active")

    def test_a_fifth_run_on_one_machine_waits_as_busy(self):
        anchor = self.clock
        for _ in range(5):
            self.create()
        self.tick(anchor + 3600)
        runs = hub.q("SELECT state, reason FROM trigger_runs ORDER BY id")
        self.assertEqual(sorted(r["state"] for r in runs), ["sent"] * 4 + ["waiting"])
        self.assertEqual([r["reason"] for r in runs if r["state"] == "waiting"],
                         ["busy: 4 checks run on Vps's server now."])
        self.assertTrue(all(hub.trigger_row(r["trigger_id"])["failures"] == 0
                            for r in hub.q("SELECT trigger_id FROM trigger_runs")))
        extra = json.loads(hub.q1("SELECT extra FROM events WHERE kind='trigger_check' ORDER BY id LIMIT 1")["extra"])
        self.answer(extra, value=3)                                         # one slot frees
        self.tick(anchor + 3605)
        self.assertEqual(sorted(r["state"] for r in hub.q("SELECT state FROM trigger_runs")), ["quiet"] + ["sent"] * 4)

    def test_a_newer_due_time_ends_the_open_run(self):
        anchor = self.clock
        tid = self.create(schedule={"kind": "every", "minutes": 15})["trigger"]["id"]
        self.offline()
        self.tick(anchor + 900)
        self.tick(anchor + 1800)
        runs = hub.q("SELECT state, reason, due FROM trigger_runs ORDER BY id")
        self.assertEqual([tuple(r) for r in runs], [("missed", "A newer due time replaced it.", anchor + 900),
                                                    ("waiting", "Vps is not answering.", anchor + 1800)])

    def test_check_state_survives_a_hub_restart(self):
        anchor = self.clock
        tid = self.create()["trigger"]["id"]
        self.tick(anchor + 3600)
        self.answer(self.sent(), ok=False, error="timeout", retry_after=900)
        hub.DB.close()
        self.connect()                                  # the hub starts again with the same database
        run = self.run_row()
        self.assertEqual((run["state"], run["retry_at"], hub.trigger_row(tid)["failures"]), ("waiting", anchor + 4500, 1))
        self.tick(anchor + 4500)
        extra = self.sent()
        hub.DB.close()
        self.connect()
        self.assertEqual(self.answer(extra, value=11)[1]["decision"], "started")
        self.assertEqual((hub.trigger_row(tid)["failures"], self.count("tasks")), (0, 1))


if __name__ == "__main__":
    unittest.main()

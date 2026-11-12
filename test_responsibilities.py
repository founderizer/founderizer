"""Owner API 1.13: the standing duties of an agent (RESPONSIBILITIES.md). In-process hub, a temporary database, a set
clock and a stand-in for the check pinning; no AI calls."""
import datetime
import hashlib
import json
import re
import unittest
import uuid
from unittest.mock import patch
from zoneinfo import ZoneInfo

import hub
from test_login_cuts import across, assert_no_part, register
from test_ui_api import OwnerAPI

MADRID = ZoneInfo("Europe/Madrid")
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3", "mac-studio": "127.0.0.4"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]},
                   "studio": {"role": "worker", "runtime": "claude", "machine": "mac-studio",
                              "can": ["shell", "browser"]}},
        "goals": {"timezone": "Europe/Madrid", "review_hour": 9, "sweep_minutes": 15}}
CLOCK_WATCH = {"kind": "clock", "schedule": {"kind": "every", "minutes": 10}}
CHECK = {"path": "checks/pool.py", "commit": "a" * 40, "sha256": "b" * 64,
         "condition": {"op": "<", "value": 1}, "repeat_minutes": None}
DUTY = {"agent": "vps",
        "text": "Keep customer content generation working. Customers generate content all day. When it fails for "
                "them, find out why, change, push and deploy api-node yourself, and write to the customer "
                "that reported it. Any refund of money you ask me first.",
        "watch": [CLOCK_WATCH]}


def at(text, zone=MADRID):
    return datetime.datetime.fromisoformat(text).replace(tzinfo=zone).timestamp()


def show(*memory_ids, task, when):
    """A later start of a task showed these lessons whole: the rows that memory_shown_rows writes at a start. A key that
    comes back counts against a lesson only after this (memory_contradicted)."""
    for m in memory_ids:
        hub.q("INSERT OR IGNORE INTO memory_shown(memory,task,attempt,at) VALUES(?,?,?,?)", (m, task, 9, when))


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (Duties, Cases, Records, Notes, Memory, Loop, Limits, Sweep, Reviews, Edits, CaseLists):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Base(OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90,
                       ask_wait=1, ask_max=1, hook_wait=2, job_wait=1, tick=5)
        self.clock = at("2026-10-16T21:10")
        clock = patch.object(hub, "now", lambda: self.clock)
        clock.start()
        self.addCleanup(clock.stop)
        pin = patch.object(hub, "pin_check", lambda check: None)         # the pinning itself: test_triggers
        pin.start()
        self.addCleanup(pin.stop)
        features = patch.object(hub, "helper_features", lambda agent: {"trigger_check", "trigger_code"})
        features.start()
        self.addCleanup(features.stop)

    # ---- the manager writes a duty: set_duty's own path, which no owner route repeats
    def create(self, **changes):
        with hub.LOCK:
            return hub.duty_save(hub.duty_fields(dict(DUTY, **changes), True), "manager", hub.now())

    def change(self, duty_id, **changes):
        with hub.LOCK:
            return hub.duty_save(hub.duty_fields(changes, False), "manager", hub.now(), duty_id=duty_id)

    def refused(self, duty_id=None, **changes):
        """Why the hub would not save this duty, in its own words."""
        with self.assertRaises((ValueError, hub.Refusal)) as caught:
            self.change(duty_id, **changes) if duty_id else self.create(**changes)
        return str(caught.exception)

    # ---- the owner's routes
    def state(self, duty_id, base, action, note=""):
        return self.request(f"/ui/responsibilities/{duty_id}/state",
                            dict(request_id=str(uuid.uuid4()), db="test-generation", base_revision=base,
                                 action=action, note=note))

    def detail(self, duty_id):
        return self.request(f"/ui/responsibilities/{duty_id}?db=test-generation")

    def duty(self, **changes):
        """One duty as the manager writes it, as a row."""
        return self.create(**changes)

    # ---- the agents' tools
    def tool(self, who, name, **args):
        context = None
        if hub.role_of(who) != "manager" and args.get("task_id"):
            tid = hub.parse_task(args["task_id"])
            context = ("test-generation", args["task_id"], hub.q1("SELECT attempt FROM tasks WHERE id=?",
                                                                  (tid,))["attempt"])
        return hub.call_tool(who, name, args, context)

    # ---- the wake-up machinery
    def watches(self, duty_id):
        return hub.q(f"SELECT * FROM triggers WHERE responsibility=? ORDER BY id", (duty_id,))

    def review_task(self, agent="vps"):
        """The agent's newest review of its duties (plan C13), or None."""
        last = hub.duty_review_last(agent)
        return hub.q1("SELECT * FROM tasks WHERE id=?", (last["task"],)) if last.get("task") else None

    def reviews(self, agent="vps"):
        return hub.q1("SELECT COUNT(*) n FROM tasks WHERE owner=? AND title=?",
                      (agent, hub.DUTY_REVIEW_TASK["title"]))["n"]

    def fire(self, trigger_id, when=None):
        """One scheduled run of a watch at its due time."""
        with hub.LOCK:
            t = hub.trigger_row(trigger_id)
            due = when if when is not None else t["next_due"]
            self.clock = max(self.clock, due)
            return hub.run_trigger(t, due, False, self.clock)

    def sweep(self, when=None):
        self.clock = when if when is not None else self.clock
        with hub.LOCK:
            hub.duty_sweep(self.clock)

    def woken(self):
        """The AI-dispatch spy: the events that start or wake a model session."""
        return hub.q1("SELECT COUNT(*) n FROM events WHERE kind IN ('say','task','chat')")["n"]

    def manager_said(self):
        rows = hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id")
        return [r["text"] for r in rows]

    def case(self, case_id=None):
        return hub.q1("SELECT * FROM duty_cases WHERE id=?", (case_id,)) if case_id else \
            hub.q1("SELECT * FROM duty_cases ORDER BY id DESC LIMIT 1")

    def first_case_task(self):
        return hub.q1("SELECT * FROM tasks WHERE duty_case IS NOT NULL ORDER BY id DESC LIMIT 1")

    def handle(self, task, steps=("told the customer", "put it right", "stops it next time")):
        """Record what was done in a case, as its worker. No label is required: these are the agent's own."""
        c = self.case(task["duty_case"])
        for step in steps:
            text, error = self.tool(task["owner"], "record_step", request_id=str(uuid.uuid4()),
                                    case=hub.cref(c), step=step, text=f"{step} is done", task_id=hub.tref(task["id"]))
            self.assertFalse(error, text)
        return c


class Duties(Base):
    def test_a_login_registered_after_a_duty_never_shows_in_part_in_its_name(self):
        """A duty's name is its first sentence, cut at DUTY_NAME_MAX characters, and copies of it are kept: in the
        duty's history, task titles, messages, start texts and lessons. A login registered after the duty was written
        is masked in them only whole, so until 11 November 2026 one that lay across the cut showed in part, on the
        owner's page of the duty and in what was kept. Now the cut goes back to where such a run of characters
        starts."""
        login, salt = "Duty-Login-0123456789", "c0ffee"
        head = "Check every night that the backups of the shop and of its database ran"
        text = f"{head} {login} for the owner. Then tell me what failed."
        self.assertLess(len(head) + 1, hub.DUTY_NAME_MAX - 1)                # the login lies across the cut
        self.assertGreater(len(head) + 1 + len(login), hub.DUTY_NAME_MAX - 1)
        r = self.create(text=text)                                          # its history row keeps the name
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES('crm',?,?,?,'')",
                (salt, hashlib.sha256((salt + login).encode()).hexdigest(), len(login)))
        self.assertEqual(hub.duty_name(text), head + "…")
        code, data = self.detail(r["id"])
        self.assertEqual(code, 200, data)
        self.assertNotIn(login[:6], json.dumps(data))
        self.assertEqual((data["responsibility"]["title"], data["responsibility"]["text"]), (head + "…", hub.MASK))
        self.assertEqual([h["detail"] for h in data["history"] if h["kind"] == "created"], [head + "…"])
        self.assertEqual(hub.scrub(hub.duty_name(f"Use {login} for the backups")), hub.MASK)   # one not cut: whole
        prefix = "word " * 15                                              # a run across the cut starts at 75
        self.assertEqual(hub.duty_name(prefix + "abcdefg and more"), prefix + "abcd…")     # 7: no login is that short
        self.assertEqual(hub.duty_name(prefix + "Ab3-Kq9z and more"), prefix.rstrip() + "…")    # 8: a login can be

    def test_the_cut_of_a_name_counts_the_dot_that_it_dropped(self):
        """The name drops its sentence's final dot, and until 11 November 2026 it was cut after that, so a run of 7
        characters and a dot across the cut was cut inside it: 8 characters, as a login can be. Now the cut reads
        the run with its dot. A run of 8 or more that ends in more dots than the search finds without them keeps
        them."""
        prefix = "word " * 15                                              # a run across the cut starts at 75
        self.assertEqual(hub.duty_name(prefix + "abcdef. Then more"), prefix + "abcd…")          # 7 with its dot
        self.assertEqual(hub.duty_name(prefix + "abcdefg. Then more"), prefix.rstrip() + "…")    # 8 with its dot
        self.assertEqual(hub.duty_name("Watch the incidents. Then more"), "Watch the incidents")
        self.assertEqual(hub.duty_name("Watch the incidents... Then more"), "Watch the incidents")
        self.assertEqual(hub.duty_name("Watch the incidents.... Then more"), "Watch the incidents....")
        self.assertEqual(hub.duty_name("Watch it.... Then more"), "Watch it")
        # the dots that a further cut of the name counts (a lesson's tag): only ones glued to its last run
        self.assertEqual(hub.duty_name_dots("Rotate the key Ab3$efgh.. Then more"), ("Rotate the key Ab3$efgh", ".."))
        self.assertEqual(hub.duty_name_dots("Rotate the key ... Then more"), ("Rotate the key", ""))
        self.assertEqual(hub.duty_name_dots(prefix + "abcdefg. Then more"), (prefix.rstrip() + "…", ""))
        self.assertEqual(hub.cut_name("Rotate the key Ab3$efgh", 20, ".."), "Rotate the key")
        self.assertEqual(hub.cut_name("Rotate the key Ab3$efgh", 23, ".."), "Rotate the key Ab3$efgh")

    def test_a_saved_duty_reads_back_in_its_stored_form(self):
        code, data = self.detail(self.create()["id"])
        self.assertEqual(code, 200, data)
        r = data["responsibility"]
        self.assertEqual(set(r), {"id", "agent", "title", "text", "state", "revision", "created", "updated",
                                  "created_by", "request_id", "watch", "open_cases", "cases_30d", "repeats_30d",
                                  "cases_prev_30d", "repeats_prev_30d", "last_case", "cases", "joined", "marker"})
        self.assertEqual((r["agent"], r["state"], r["revision"], r["created_by"]), ("vps", "active", 1, "manager"))
        self.assertEqual((r["open_cases"], r["cases_30d"], r["repeats_30d"], r["last_case"], r["marker"]),
                         (0, 0, 0, None, None))
        # The duty has no title of its own: its name is the first sentence of its words.
        self.assertEqual(r["title"], "Keep customer content generation working")
        self.assertEqual(r["text"], DUTY["text"])
        # One watch, as a wake-up rule of the manager, so one scheduler carries it.
        self.assertEqual(len(r["watch"]), 1)
        watch, rule = r["watch"][0], self.watches(r["id"])[0]
        self.assertEqual((watch["kind"], watch["state"], watch["check"], watch["schedule"]),
                         ("clock", "active", None, {"kind": "every", "minutes": 10}))
        self.assertEqual((rule["created_by"], rule["watch"], rule["next_due"]),
                         ("manager", "clock", self.clock + 600))
        self.assertIn("Your duty R-1", json.loads(rule["task"])["details"])
        self.assertIn("record_step", json.loads(rule["task"])["details"])
        self.assertIn("change, push and deploy api-node yourself",
                      json.loads(rule["task"])["details"])
        self.assertEqual(json.loads(rule["task"])["title"], "Keep customer content generation working")
        # The manager and the holder are told; nobody else.
        self.assertTrue(any("New duty for vps" in t for t in self.manager_said()))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE agent='vps' AND kind='say'")["n"], 1)
        # Plan C13: no rule of the hub's; the next tick starts the holder's review, because a new duty is news (R6).
        self.assertIsNone(hub.q1("SELECT id FROM triggers WHERE watch='review'"))
        self.sweep()
        review = self.review_task()
        self.assertEqual((review["requester"], review["needs"], review["responsibility"], review["trigger_id"]),
                         ("manager", "none", None, None))
        self.assertIn("see_responsibilities", review["details"])
        self.assertIn("R-1 Keep customer content generation working: new, from manager.", review["details"])
        # The notice of the duty waits for the holder in that session.
        self.assertEqual(hub.q1("SELECT task FROM events WHERE agent='vps' AND kind='say'")["task"], review["id"])

    def test_a_duty_that_cannot_be_is_refused(self):
        for changes, word in (({"title": ""}, "title"), ({"text": "x" * 8001}, "text"),
                              ({"watch": [{"kind": "mailbox"}]}, "watch.kind"),
                              ({"watch": [{"kind": "clock"}]}, "needs schedule"),
                              ({"watch": [{"kind": "check"}]}, "needs check"),
                              ({"watch": [dict(CLOCK_WATCH, trigger=1)]}, "watch.trigger"),
                              ({"agent": "nobody"}, "there is no agent"),
                              ({"watch": [dict(CLOCK_WATCH, needs="browser")]}, "has no browser")):
            self.assertIn(word, self.refused(**changes), changes)
        for gone in ("react_within", "may_do", "must_ask", "limits", "title", "close_out", "max_open", "why",
                     "nonsense"):
            with self.assertRaises(ValueError) as caught:
                hub.duty_fields(dict(DUTY, **{gone: 1}), True)
            self.assertEqual(str(caught.exception), f"unknown field {gone}")
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM responsibilities")["n"], 0)      # no record of a refusal
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM triggers")["n"], 0)

    def test_a_field_the_tool_does_not_take_is_refused_in_the_hubs_own_words(self):
        """The failure a fleet cannot see coming. `set_duty` lost `react_within`, `may_do` and `must_ask` on 19
        October 2026; a fleet installed before that keeps a seeded manager profile that still names all three,
        and no release ever rewrites one, because `profiles/` is the owner's. So the refusal is the only thing
        that reaches such a manager: it names the fields, says the instructions that sent it there may be out of
        date, and points at the one copy of the contract that cannot be stale. It is also the hub's own refusal
        and not the runtime's, so it leaves a row the owner can read -- a validation error inside the caller's
        session left nothing anywhere."""
        text, error = self.tool("manager", "set_duty", request_id=str(uuid.uuid4()),
                                react_within="1h", may_do="restart it", must_ask="a refund", **DUTY)
        self.assertTrue(error, text)
        for gone in ("react_within", "may_do", "must_ask"):
            self.assertIn(gone, text)
        self.assertIn("out of date", text)
        self.assertIn("description is the current contract", text)
        # Refused whole: nothing is written with the unknown fields quietly dropped.
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM responsibilities")["n"], 0)
        row = hub.q1("SELECT * FROM calls WHERE name='set_duty' ORDER BY id DESC LIMIT 1")
        self.assertEqual(row["ok"], 0)
        self.assertIn("react_within", row["detail"])
        # The same call without them is the one the tool takes today. A readable request_id is kept as given.
        text, error = self.tool("manager", "set_duty", request_id="Mgr-Duty-0001", **DUTY)
        self.assertFalse(error, text)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM responsibilities")["n"], 1)
        self.assertEqual(hub.q1("SELECT request_id FROM responsibilities")["request_id"], "Mgr-Duty-0001")

    def test_the_task_id_the_fence_adds_is_not_read_as_the_callers_own_field(self):
        """message_agent takes no task_id and a worker's session has one added for it, so the check has to read
        what the caller wrote and not what the fence left."""
        self.tool("manager", "create_task", owner="vps", title="Look at the mailbox",
                  done_when="The mailbox is read.")
        task = hub.tref(hub.q1("SELECT id FROM tasks ORDER BY id DESC LIMIT 1")["id"])
        text, error = self.tool("vps", "message_agent", task_id=task, agent="manager",
                                request_id=str(uuid.uuid4()), text="A question about the duty.")
        self.assertFalse(error, text)

    def test_one_agent_holds_several_duties_up_to_its_limit(self):
        for n in range(hub.DUTY_MAX):
            self.create(text=f"Duty {n}. Look after it.")
        self.assertIn(f"already has {hub.DUTY_MAX} duties", self.refused(text="One too many."))
        # The duties of one agent share one review: its news is one list.
        self.sweep()
        self.assertEqual(self.reviews(), 1)
        self.assertEqual(self.review_task()["details"].count(": new, from manager."), hub.DUTY_MAX)
        self.assertEqual(len(hub.duty_view(hub.duty_row(1))["watch"]), 1)

    def test_a_change_of_a_duty_replaces_its_watches(self):
        r = self.duty()
        rule = self.watches(r["id"])[0]
        changed = self.change(r["id"], text="Fix it yourself and tell the customer.")
        self.assertEqual((changed["revision"], changed["text"]), (2, "Fix it yourself and tell the customer."))
        # The words of the duty reach the task of its watch again, and the rule stays the same rule.
        kept = self.watches(r["id"])
        self.assertEqual([t["id"] for t in kept], [rule["id"]])
        self.assertIn("Fix it yourself", json.loads(kept[0]["task"])["details"])
        self.assertEqual(kept[0]["revision"], 2)
        # A new watch list replaces the rules: the old one is deleted, the new one is made.
        self.change(r["id"], watch=[{"kind": "check", "check": CHECK}])
        rules = {t["id"]: t for t in self.watches(r["id"])}
        self.assertEqual(rules[rule["id"]]["state"], "deleted")
        live = [t for t in rules.values() if t["state"] == "active"]
        self.assertEqual(len(live), 1)
        self.assertEqual((live[0]["watch"], json.loads(live[0]["check_spec"])["path"]), ("check", "checks/pool.py"))
        self.assertEqual(json.loads(live[0]["schedule"]), {"kind": "every", "minutes": 30})      # half of 60 minutes

    def test_pause_retire_and_reopen_move_the_watches(self):
        r = self.duty()
        rule = self.watches(r["id"])[0]
        code, data = self.state(r["id"], 1, "pause", note="Not now")
        self.assertEqual(code, 200, data)
        self.assertEqual(data["responsibility"]["state"], "paused")
        self.assertEqual(hub.trigger_row(rule["id"])["state"], "paused")
        self.sweep()
        self.assertIsNone(self.review_task())                   # a paused duty is nobody's news
        self.assertEqual(self.state(r["id"], 2, "pause")[0], 409)
        code, data = self.state(r["id"], 2, "resume")
        self.assertEqual(code, 200, data)
        self.assertEqual(hub.trigger_row(rule["id"])["state"], "active")
        code, data = self.state(r["id"], 3, "retire")
        self.assertEqual((code, data["responsibility"]["state"]), (200, "retired"))
        self.assertEqual(hub.trigger_row(rule["id"])["state"], "paused")
        self.assertIn("retired", self.refused(r["id"], text="No."))      # a retired duty changes after a reopen
        self.assertEqual(self.state(r["id"], 4, "reopen")[0], 200)
        self.assertEqual(hub.trigger_row(rule["id"])["state"], "active")
        self.assertEqual([h["kind"] for h in hub.q("SELECT kind FROM duty_history WHERE responsibility=? ORDER BY id",
                                                   (r["id"],))],
                         ["created", "pause", "resume", "retire", "reopen"])

    def test_the_detail_route_gives_the_cases_and_the_history(self):
        r = self.duty()
        self.fire(self.watches(r["id"])[0]["id"])
        code, data = self.detail(r["id"])
        self.assertEqual(code, 200, data)
        self.assertEqual(set(data), {"db", "responsibility", "cases", "history", "next"})
        self.assertEqual(len(data["cases"]), 1)
        self.assertEqual(data["cases"][0]["ref"], "R-1/C-1")
        self.assertEqual(data["cases"][0]["steps"], [])
        self.assertEqual([h["kind"] for h in data["history"]], ["case_opened", "created"])
        self.assertEqual(self.request("/ui/responsibilities/9?db=test-generation")[0], 404)
        code, state = self.request("/ui/state")
        self.assertEqual(len(state["responsibilities"]), 1)
        self.assertIn("responsibilities", state["ui_features"])


class Cases(Base):
    def test_a_case_task_keeps_no_part_of_a_login_in_the_duty_words_and_a_wake_line(self):
        """A case task's details are the duty's words (duty_task_text, at most 8000 characters), the run's line and the
        case line, cut again at 8000 (admit_wake). The task keeps them, and a login registered after it was made is
        masked there only whole: each cut falls where no login can be cut in two (11 November 2026)."""
        words, line = "LqDutyWords-7f3e9a01b2", "LqWakeLine-7f3e9a01b2"
        r = self.duty()
        head = len(f"Your duty R-{r['id']}: Keep the shop up\n")
        text = "Keep the shop up. " + ("w " * 4000)[:8000 - 10 - head - 18 - 1] + " " + words + " and more."
        r = self.change(r["id"], text=text)
        rule = self.watches(r["id"])[0]
        self.fire(rule["id"])
        task = self.first_case_task()
        self.change(r["id"], text="Keep the shop up. Answer each customer who writes.")    # short words again
        rule = hub.trigger_row(rule["id"])
        body = json.loads(rule["task"])
        details = hub.watch_details(rule, body)
        self.assertLess(len(details), 2000)
        route, _ = hub.wakeups.wake_route(hub.wake_org(), rule["agent"])
        with hub.LOCK, hub.transaction():
            run = hub.DB.execute("INSERT INTO trigger_runs(trigger_id,revision,due,manual,state,created) "
                                 "VALUES(?,?,?,1,'started',?)", (rule["id"], rule["revision"], self.clock + 3600,
                                                                 self.clock)).lastrowid      # another key: a new case
            woke, _, _ = hub.admit_wake(rule, run, hub.wake_admission(rule, route, body),
                                        across(8000 - len(details) - 2, line), self.clock)
        register(words)
        register(line)
        for kept in (task["details"], hub.q1("SELECT details FROM tasks WHERE id=?", (woke,))["details"]):
            for login in (words, line):
                assert_no_part(self, hub.mask_secrets(kept), login)

    def test_the_changes_named_since_a_read_keep_no_part_of_a_login(self):
        """duty_changes_since names each change since a session's read with its words cut at 120 characters, in a
        refusal and in a notice: a login in the owner's note of a pause is masked there only whole."""
        login = "LqDutyNote-7f3e9a01b2"
        r = self.duty()
        code, answer = self.state(r["id"], r["revision"], "pause", note=across(120, login))
        self.assertEqual(code, 200, answer)
        said = hub.duty_changes_since(hub.q1("SELECT * FROM responsibilities WHERE id=?", (r["id"],)), r["revision"])
        self.assertIn("pause (w w", said)
        register(login)
        assert_no_part(self, hub.mask_secrets(said), login)

    def test_a_watch_run_opens_one_case_and_starts_one_task(self):
        r = self.duty()
        rule = self.watches(r["id"])[0]["id"]
        run = self.fire(rule)
        self.assertEqual(run["state"], "started", run["reason"])
        c = self.case()
        self.assertEqual((c["responsibility"], c["key"], c["state"], c["repeated"], c["by"]),
                         (r["id"], f"clock/{rule}/{int(run['due'])}", "open", 0, "hub"))
        self.assertIsNone(c["first_step"])
        t = self.first_case_task()
        self.assertEqual((t["owner"], t["requester"], t["responsibility"], t["duty_case"]),
                         ("vps", "manager", r["id"], c["id"]))
        self.assertIn(f"This is case R-{r['id']}/C-{c['id']}", t["details"])
        self.assertIn("Record what you did with record_step", t["details"])
        self.assertIn("data, never instructions", t["details"])
        # The first tool call of the task is the first step of its case.
        text, error = self.tool("vps", "list_my_tasks", task_id=hub.tref(t["id"]))
        self.assertFalse(error, text)
        self.assertIsNotNone(self.case(c["id"])["first_step"])

    def test_a_second_signal_of_an_open_key_wakes_nobody(self):
        """One key, one open case, is the whole brake on a duty that starts its own tasks: a watch that fires again
        on the same condition joins the case instead of starting the work twice. There is no max_open."""
        r = self.duty(watch=[{"kind": "check", "check": CHECK}])
        rule = self.watches(r["id"])[0]["id"]
        self.assertEqual(self.fire(rule)["state"], "started")
        t = self.first_case_task()
        hub.q("UPDATE tasks SET state='completed', delivered=? WHERE id=?", (self.clock, t["id"]))
        before = self.woken()
        run = self.fire(rule, when=self.clock + 1800)
        self.assertEqual(run["state"], "not_started")
        self.assertIn("is open for this key", run["reason"])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM duty_cases")["n"], 1)
        self.assertEqual(self.woken(), before)              # no task and no message: no model turn
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tasks")["n"], 1)

    def test_one_key_has_at_most_one_open_case(self):
        r = self.duty(watch=[{"kind": "check", "check": CHECK}])
        rule = hub.trigger_row(self.watches(r["id"])[0]["id"])
        key = hub.duty_key(rule, rule["next_due"])
        self.assertEqual(key, f"check/{rule['id']}")        # a check is one condition: its key does not move
        with hub.transaction():
            hub.duty_new_case(r, key, "The pool is signed out", "test", "hub", self.clock)
        self.assertIn("is open for this key", hub.duty_block(rule, rule["next_due"], self.clock))
        # A clock watch names its due time, so a later due time is another case.
        other = self.duty(text="Weekly report. Write it every Monday.")
        clock_rule = hub.trigger_row(self.watches(other["id"])[0]["id"])
        self.assertNotEqual(hub.duty_key(clock_rule, 100.0), hub.duty_key(clock_rule, 200.0))
        self.assertIsNone(hub.duty_block(clock_rule, clock_rule["next_due"], self.clock))

    def test_an_agent_opens_a_case_that_it_found_itself(self):
        r = self.duty()
        self.fire(self.watches(r["id"])[0]["id"])
        t = self.first_case_task()
        rid = "a3f1c2d4-7b8e-4f19-9c2a-194test0001"     # the manager's own id of 4 November 2026: not a UUID
        text, error = self.tool("vps", "open_case", request_id=rid, responsibility="R-1", key="order/9912",
                                title="A customer says the export is empty", task_id=hub.tref(t["id"]))
        self.assertFalse(error, text)
        self.assertIn("Opened R-1/C-2", text)
        again, error = self.tool("vps", "open_case", request_id=rid, responsibility="R-1", key="order/9912",
                                 title="A customer says the export is empty", task_id=hub.tref(t["id"]))
        self.assertEqual((again, error), (text, False))             # the same request_id writes nothing more
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM duty_cases")["n"], 2)
        other, error = self.tool("vps", "open_case", request_id=rid, responsibility="R-1", key="order/9912",
                                 title="Another title", task_id=hub.tref(t["id"]))
        self.assertTrue(error)
        self.assertIn("already used for another call", other)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tool_commands WHERE request_id=?", (rid,))["n"], 1)
        text, error = self.tool("vps", "open_case", request_id=str(uuid.uuid4()), responsibility="R-1",
                                key="order/9912", title="The same thing again", task_id=hub.tref(t["id"]))
        self.assertTrue(error)
        self.assertIn("is already open for the key", text)
        # Another key is another event, and the agent decides that: nothing of the duty's own holds it.
        text, error = self.tool("vps", "open_case", request_id=str(uuid.uuid4()), responsibility="R-1",
                                key="order/9913", title="And another one", task_id=hub.tref(t["id"]))
        self.assertFalse(error, text)
        self.assertIn("Opened R-1/C-3", text)

    def test_a_key_that_came_back_opens_no_second_case_until_the_agent_says_so(self):
        r = self.duty()
        self.fire(self.watches(r["id"])[0]["id"])
        t = self.first_case_task()

        def mine(title, **extra):
            return self.tool("vps", "open_case", request_id=str(uuid.uuid4()), responsibility="R-1",
                             key="order/9912", title=title, task_id=hub.tref(t["id"]), **extra)
        text, error = mine("A customer says the export is empty")
        self.assertFalse(error, text)
        first = self.case()
        hub.q("UPDATE duty_cases SET state='closed', closed=?, closed_by='vps', outcome='handled' WHERE id=?",
              (self.clock, first["id"]))
        # The same key after its case closed: the event itself again, so it opens nothing by itself.
        self.clock += 3600
        text, error = mine("The export is empty again")
        self.assertTrue(error)
        self.assertIn("One key is one event", text)
        self.assertIn(hub.cref(first), text)
        self.assertIn("repeat=true", text)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM duty_cases")["n"], 2)   # the watch's case and that one
        # The agent says that the event came back: the new case is a repeat, and it says what to record.
        text, error = mine("The export is empty again", repeat=True)
        self.assertFalse(error, text)
        second = self.case()
        self.assertEqual((second["key"], second["repeated"]), ("order/9912", 1))
        self.assertIn("why the earlier action did not hold", text)
        # Outside the 30 days the key is a new event again.
        hub.q("UPDATE duty_cases SET state='closed', closed=?, closed_by='vps', outcome='handled' WHERE id=?",
              (self.clock, second["id"]))
        self.clock += (hub.DUTY_REPEAT_DAYS + 1) * 86400
        text, error = mine("The export is empty, months later")
        self.assertFalse(error, text)
        self.assertEqual(self.case()["repeated"], 0)

    def test_a_duty_that_a_line_check_watches_reads_for_its_agent(self):
        """With checks.lines on, an agent's new check has the line form and no condition: reading a duty that one
        watched crashed see_responsibilities (live, 28 October 2026). The app reads the watch's check as the hub keeps
        it: a value check's condition object and its run's number, and null for a line check (agents 8e4f932)."""
        for condition, said in (({"op": ">", "value": 10485760}, "more than 10485760"),    # not 1.04858e+07
                                ({"op": "<=", "value": 0.25}, "at most 0.25"), (None, None),
                                ({"op": "~", "value": 1}, None), ({"op": "<", "value": float("nan")}, None)):
            self.assertEqual(hub.check_condition_words(condition), said)
        r = self.duty(watch=[{"kind": "check", "check": CHECK}])
        rule = self.watches(r["id"])[0]
        hub.q("INSERT INTO trigger_runs(trigger_id,revision,due,state,created,value) VALUES(?,?,?,?,?,?)",
              (rule["id"], rule["revision"], self.clock, "quiet", self.clock, 3.0))
        watch = hub.duty_view(hub.duty_row(r["id"]))["watch"][0]
        self.assertEqual((watch["check"]["condition"], watch["last_run"]["value"]), ({"op": "<", "value": 1}, 3.0))
        code = "print('T-1 a new thread in the mailbox')\n"
        spec = hub.trigger_check_spec(hub.wakeups.saved_check({"code": code}, "vps")[0], saved=True)
        with hub.LOCK, patch.object(hub, "helper_features", lambda agent: {"trigger_code", hub.LINES_FEATURE}):
            own = hub.trigger_create({"agent": "vps", "check": spec, "late_minutes": 60, "max_tasks_per_day": 24,
                                      "request_id": str(uuid.uuid4()), "schedule": {"kind": "every", "minutes": 10},
                                      "task": {"title": "Look at the support mailbox", "details": "My mechanism.",
                                               "needs": "none", "goal_id": None, "done_when": "A case for each."}},
                                     "vps", self.clock, created_by="vps", source=code)
        hub.q("UPDATE triggers SET responsibility=?, watch='own' WHERE id=?", (r["id"], own["id"]))
        lines = [w for w in hub.duty_view(hub.duty_row(r["id"]))["watch"] if w["kind"] == "own"]
        self.assertEqual([w["check"]["condition"] for w in lines], [None])
        text, error = self.tool("manager", "see_responsibilities", responsibility="R-1")     # duty_text, as for mia
        self.assertFalse(error, text)
        self.assertIn("check checks/pool.py less than 1", text)
        self.assertIn(f"check saved code {spec['sha256'][:12]}: each new line that it prints wakes the agent", text)

    def test_a_retired_duty_takes_no_new_watch_and_a_pause_without_a_reason_says_none(self):
        """Live, 28 October 2026: the manager retired R-2 because it had no watch, and a second later the agent's
        review attached one; and its watch line read "paused by mia: None"."""
        r = self.duty()
        self.fire(self.watches(r["id"])[0]["id"])
        task = self.first_case_task()
        own = self.own_rule()
        hub.q("UPDATE triggers SET state='paused', paused_by='vps', paused_reason=NULL WHERE id=?", (own["id"],))
        self.assertEqual(self.state(r["id"], 1, "retire", note="Not needed")[0], 200)
        text, error = self.tool("vps", "attach_watch", request_id=str(uuid.uuid4()), responsibility="R-1",
                                trigger=own["id"], task_id=hub.tref(task["id"]))
        self.assertTrue(error)
        self.assertIn("R-1 is retired, and a retired duty takes no new watch", text)
        self.assertIsNone(hub.trigger_row(own["id"])["responsibility"])
        hub.q("UPDATE triggers SET responsibility=?, watch='own' WHERE id=?", (r["id"], own["id"]))
        seen, error = self.tool("manager", "see_responsibilities", responsibility="R-1")
        self.assertFalse(error, seen)
        self.assertIn(f"Watch {own['id']} (own) [paused by vps]", seen)
        self.assertNotIn("None", seen)

    def own_rule(self, agent="vps", title="Look at the support mailbox"):
        """One wake-up rule that the agent made for itself, as save_trigger writes it after its plan."""
        with hub.LOCK:
            return hub.trigger_create({"agent": agent, "check": None, "late_minutes": 60, "max_tasks_per_day": 24,
                                       "request_id": str(uuid.uuid4()),
                                       "schedule": {"kind": "every", "minutes": 10},
                                       "task": {"title": title, "details": "My own mechanism.", "needs": "none",
                                                "goal_id": None, "done_when": "Every new thread has a case."}},
                                      agent, self.clock, created_by=agent)

    def test_an_agent_attaches_its_own_mechanism_to_its_duty(self):
        """The owner's direction: the hub holds the duty, the case and the scheduler; the agent builds the detection
        itself from the tools, integrations and keys that it has."""
        hub.TEAM["agents"]["vps"]["google"] = {"gmail": {"account": "support@example.com", "level": "send"}}
        hub.TEAM["agents"]["vps"]["repos"] = {"acme/api-node": "write"}
        hub.TEAM["agents"]["vps"]["tools"] = ["github", "crm"]
        r = self.duty()
        self.fire(self.watches(r["id"])[0]["id"])
        task = self.first_case_task()
        self.assertIn("Gmail of support@example.com at the level send", task["details"])
        self.assertIn("GitHub acme/api-node (write)", task["details"])
        self.assertIn("tools crm, github", task["details"])
        self.assertIn("attach that wake-up rule to the duty with attach_watch", task["details"])
        own = self.own_rule()
        rid = "leo-t142-r8-attach-19"                       # an agent's own readable id (4 November 2026)
        text, error = self.tool("vps", "attach_watch", request_id=rid, responsibility="R-1", trigger=own["id"],
                                task_id=hub.tref(task["id"]))
        self.assertFalse(error, text)
        self.assertIn(f"Rule {own['id']} is now a watch of R-1", text)
        again, error = self.tool("vps", "attach_watch", request_id=rid, responsibility="R-1", trigger=own["id"],
                                 task_id=hub.tref(task["id"]))
        self.assertEqual((again, error), (text, False))                 # one request_id, one write
        rule = hub.trigger_row(own["id"])
        self.assertEqual((rule["responsibility"], rule["watch"]), (r["id"], "own"))
        self.assertEqual([w["kind"] for w in hub.duty_view(hub.duty_row(r["id"]))["watch"]], ["clock", "own"])
        # Its runs start a duty task with no case of their own: the agent opens one for each event that it finds.
        hub.q("UPDATE tasks SET state='completed', delivered=? WHERE id=?", (self.clock, task["id"]))
        run = self.fire(own["id"])
        self.assertEqual(run["state"], "started", run["reason"])
        mine = hub.q1("SELECT * FROM tasks WHERE id=?", (run["task"],))
        self.assertEqual((mine["responsibility"], mine["duty_case"]), (r["id"], None))
        self.assertIn("Open one case with open_case for each event that you find", mine["details"])
        self.assertIn("My own mechanism.", mine["details"])      # its own task text stays; the hub adds the duty line
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM duty_cases")["n"], 1)        # only the clock watch's case
        text, error = self.tool("vps", "open_case", request_id=str(uuid.uuid4()), responsibility="R-1",
                                key="thread/18f2c", title="A customer says the export is empty",
                                task_id=hub.tref(mine["id"]))
        self.assertFalse(error, text)
        case = self.case()
        self.assertEqual((case["key"], case["by"]), ("thread/18f2c", "vps"))
        self.assertIsNotNone(case["first_step"])            # the agent is already on it: the reaction has begun
        # A rule of another agent is not a watch of this duty, and the hub's own kinds stay the hub's.
        other = self.own_rule(agent="studio", title="Not mine")
        text, error = self.tool("vps", "attach_watch", request_id=str(uuid.uuid4()), responsibility="R-1",
                                trigger=other["id"], task_id=hub.tref(mine["id"]))
        self.assertTrue(error)
        self.assertIn("A watch of a duty wakes its holder", text)
        text, error = self.tool("vps", "attach_watch", request_id=str(uuid.uuid4()), responsibility="R-1",
                                trigger=self.watches(r["id"])[0]["id"], task_id=hub.tref(mine["id"]))
        self.assertTrue(error)
        self.assertIn("the hub keeps", text)
        # An edit of the duty's watch list leaves the agent's own rule alone.
        self.change(r["id"], watch=[])
        self.assertEqual(hub.trigger_row(own["id"])["state"], "active")
        self.assertEqual([w["kind"] for w in hub.duty_view(hub.duty_row(r["id"]))["watch"] if w["state"] == "active"],
                         ["own"])
        text, error = self.tool("vps", "attach_watch", request_id=str(uuid.uuid4()), responsibility="R-1",
                                trigger=own["id"], detach=True, task_id=hub.tref(mine["id"]))
        self.assertFalse(error, text)
        self.assertIsNone(hub.trigger_row(own["id"])["responsibility"])
        self.assertEqual([h["kind"] for h in hub.q("SELECT kind FROM duty_history WHERE responsibility=? AND "
                                                   "kind LIKE 'watch%' ORDER BY id", (r["id"],))],
                         ["watch_attached", "watch_detached"])

    def test_see_capacity_gives_the_manager_the_facts_of_the_holder_choice(self):
        """R10: the manager chooses from what it knows — what the agent answers for already, and whether it can write
        to a customer at all."""
        hub.TEAM["agents"]["vps"]["google"] = {"gmail": {"account": "support@example.com", "level": "send"}}
        self.duty()
        text, error = self.tool("manager", "see_capacity")
        self.assertFalse(error, text)
        self.assertIn("duties it holds: R-1 Keep customer content generation working", text)
        self.assertIn("Gmail send", text)
        # A duty that is not in order says so in the same line, so the manager sees it when it chooses.
        self.change(1, watch=[])
        self.sweep(self.clock + 16 * 60)
        text, error = self.tool("manager", "see_capacity")
        self.assertFalse(error, text)
        self.assertIn("R-1 Keep customer content generation working [no watch]", text)

    def test_the_manager_can_hold_a_duty_itself(self):
        """The owner's direction: the manager decides between a worker and itself. Its own duty wakes it with a
        message, because it has a standing session and needs no task."""
        text, error = self.tool("manager", "set_duty", request_id=str(uuid.uuid4()), agent="manager",
                                text="Keep every duty of the fleet in order. Nobody else sees every duty at the "
                                     "same time.",
                                watch=[CLOCK_WATCH])
        self.assertFalse(error, text)
        r = hub.duty_row(1)
        self.assertEqual((r["agent"], hub.duty_name(r["text"])),
                         ("manager", "Keep every duty of the fleet in order"))
        rule = self.watches(r["id"])[0]
        self.assertIn("You hold this duty yourself", json.loads(rule["task"])["details"])
        self.assertIn("see_capacity", json.loads(rule["task"])["details"])
        before = hub.q1("SELECT COUNT(*) n FROM tasks")["n"]
        run = self.fire(rule["id"])
        self.assertEqual(run["state"], "started", run["reason"])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tasks")["n"], before)       # a message, not a task
        c = self.case()
        self.assertEqual((c["responsibility"], c["state"]), (r["id"], "open"))
        said = hub.q1("SELECT text FROM events WHERE id=?", (run["event_id"],))["text"]
        self.assertIn(f"This is case R-{r['id']}/C-{c['id']}", said)
        self.assertIn("Keep every duty of the fleet in order", said)
        # The same key opens no second case; a clock watch's key is its due time, so the open message holds the rest.
        self.assertIn("is open for this key", hub.duty_block(hub.trigger_row(rule["id"]), run["due"], self.clock))
        later = self.fire(rule["id"], when=self.clock + 600)
        self.assertNotEqual(later["state"], "started")
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM duty_cases")["n"], 1)
        for step in ("what I found", "what I did"):
            text, error = self.tool("manager", "record_step", request_id=str(uuid.uuid4()), case=hub.cref(c),
                                    step=step, text=f"{step} is written down")
            self.assertFalse(error, text)
        text, error = self.tool("manager", "close_case", request_id=str(uuid.uuid4()), case=hub.cref(c),
                                outcome="handled", note="Two duties were late; I asked both agents")
        self.assertFalse(error, text)
        self.assertEqual(self.case(c["id"])["state"], "closed")

    def test_the_manager_moves_a_duty_retires_it_and_finds_it_again(self):
        """The owner, 19 October 2026: the manager writes duties, edits them, reassigns them and removes them. A
        move takes the watch with it and is news for the new holder alone; a retired duty stays readable, or nobody
        could reopen it."""
        r = self.duty(agent="vps")
        moved = self.change(r["id"], agent="studio",
                            text="Keep customer content generation working. Studio owns the repository now.")
        self.assertEqual(moved["agent"], "studio")
        self.assertEqual(self.watches(r["id"])[0]["agent"], "studio")        # its watch wakes the new holder
        self.sweep()
        self.assertIsNone(self.review_task("vps"))                           # the old one has no news of it
        self.assertIn("moved to you by manager", self.review_task("studio")["details"])
        self.assertEqual([h["detail"] for h in hub.q("SELECT detail FROM duty_history WHERE responsibility=? AND "
                                                     "kind='edited'", (r["id"],))], ["agent, text"])
        # Retire is how a duty is removed, and the manager may do it itself.
        text, error = self.tool("manager", "change_duty", request_id=str(uuid.uuid4()), responsibility="R-1",
                                action="retire", note="The shop was sold")
        self.assertFalse(error, text)
        self.assertEqual(hub.duty_row(r["id"])["state"], "retired")
        self.assertEqual(hub.trigger_row(self.watches(r["id"])[0]["id"])["state"], "paused")
        # The duties that run now stay small: one line says the retired one is there and how to read it.
        seen, error = self.tool("manager", "see_responsibilities")
        self.assertFalse(error, seen)
        self.assertIn("1 retired, not listed here", seen)
        self.assertNotIn("R-1 ", seen)
        # Looking back names it with its id, so reopen is reachable.
        back, error = self.tool("manager", "see_responsibilities", retired=True)
        self.assertFalse(error, back)
        self.assertIn("Retired duties (1), newest first:", back)
        self.assertIn("R-1 [retired] Keep customer content generation working — studio", back)
        self.assertIn("change_duty reopen", back)
        text, error = self.tool("manager", "change_duty", request_id=str(uuid.uuid4()), responsibility="R-1",
                                action="reopen", note="The sale fell through")
        self.assertFalse(error, text)
        self.assertEqual(hub.duty_row(r["id"])["state"], "active")
        seen, _ = self.tool("manager", "see_responsibilities")
        self.assertNotIn("retired", seen)
        self.assertEqual(self.tool("manager", "see_responsibilities", retired=True)[0],
                         "No duty that you may see has been retired.")

    def test_one_duty_comes_with_every_case_and_how_it_was_managed(self):
        """The owner, 19 October 2026: "we should keep history of the different goals we've had, how they were
        managed etc. We dont need everything in the context all the time". So one duty on its own carries its
        closed cases and its history rows; the list of what runs now carries neither."""
        r = self.duty()
        self.fire(self.watches(r["id"])[0]["id"])
        t = self.first_case_task()
        self.handle(t, ("what I found", "the fix"))
        c = self.case(t["duty_case"])
        hub.q("UPDATE duty_cases SET state='closed', closed=?, closed_by='vps', outcome='handled' WHERE id=?",
              (self.clock, c["id"]))
        self.change(r["id"], text="Keep customer content generation working. Studio owns the repository now.")
        # The list of what runs now does not carry the closed case or the history.
        seen, error = self.tool("manager", "see_responsibilities")
        self.assertFalse(error, seen)
        self.assertNotIn("How it was managed", seen)
        self.assertNotIn("R-1/C-1", seen)
        # One duty does, oldest of its rows first, so it reads as what happened.
        one, error = self.tool("manager", "see_responsibilities", responsibility="R-1")
        self.assertFalse(error, one)
        self.assertIn("R-1/C-1 [closed handled]", one)   # the closed case is there, which the list left out
        self.assertIn("what I found", one)               # a record keeps the words the agent wrote
        self.assertIn("How it was managed:", one)
        kinds = [line.split(": ", 1)[1].split(" — ")[0] for line in one.splitlines()
                 if line.startswith("    2026-")]
        self.assertEqual(kinds, ["created", "case opened", "step", "step", "edited"])
        self.assertIn("manager: edited — text", one)
        # A retired duty is readable the same way.
        with hub.LOCK:
            hub.duty_state_change(hub.duty_row(r["id"]), "retire", "manager", "The shop was sold")
        one, error = self.tool("manager", "see_responsibilities", responsibility="R-1")
        self.assertFalse(error, one)
        self.assertIn("R-1 [retired]", one)
        self.assertIn("How it was managed:", one)

    def test_a_duty_carries_its_repeats_against_the_window_before(self):
        """"Fewer repeats" is the measure of the fleet getting better at a duty, and it needs no new counting: a
        repeat is already marked when a key comes back. The duty carries both windows so a screen can show the
        trend, and the rate matters, not the count alone."""
        r = self.duty(watch=[{"kind": "check", "check": CHECK}])
        day = 86400

        def case(key, when, repeated=0):
            with hub.transaction():
                cid = hub.duty_new_case(r, key, key, "test", "hub", when)
            hub.q("UPDATE duty_cases SET state='closed', closed=?, outcome='handled', repeated=? WHERE id=?",
                  (when, repeated, cid))

        # The 30 days before this one: three cases, two of them a key that came back.
        for n, again in ((0, 1), (1, 1), (2, 0)):
            case(f"old/{n}", self.clock - (45 - n) * day, again)
        # This window: three cases and one repeat, so the preventive work is landing.
        for n, again in ((0, 1), (1, 0), (2, 0)):
            case(f"new/{n}", self.clock - (10 - n) * day, again)
        v = hub.duty_view(hub.duty_row(r["id"]), self.clock)
        self.assertEqual((v["cases_30d"], v["repeats_30d"]), (3, 1))
        self.assertEqual((v["cases_prev_30d"], v["repeats_prev_30d"]), (3, 2))
        seen, error = self.tool("manager", "see_responsibilities")
        self.assertFalse(error, seen)
        self.assertIn("3 in 30 days, 1 of them a repeat; the 30 days before that, 2 of 3.", seen)
        # A duty with no case before this window says nothing about it, instead of saying zero.
        other = self.duty(text="Answer the support mailbox. Customers write all day.")
        seen, _ = self.tool("manager", "see_responsibilities", responsibility=hub.rref(other["id"]))
        self.assertIn("0 in 30 days, 0 of them a repeat.", seen)

    def test_a_duty_is_found_by_its_own_words_and_the_lists_are_capped(self):
        for n in range(hub.DUTY_LOOK_BACK + 2):
            made = self.create(text=f"Duty {n}. Answer the support mailbox.")
            with hub.LOCK:
                hub.duty_state_change(hub.duty_row(made["id"]), "retire", "manager", "done with")
        hits, error = self.tool("manager", "see_responsibilities", search="support mailbox")
        self.assertFalse(error, hits)
        self.assertIn(f"Duties whose words say 'support mailbox' ({hub.DUTY_LOOK_BACK + 2}), newest first:", hits)
        self.assertIn("and 2 older ones.", hits)
        self.assertIn(f"Duty {hub.DUTY_LOOK_BACK + 1}", hits)        # the newest is named
        self.assertNotIn("Duty 0.", hits)                            # the oldest two are counted, not named
        # The retired list is capped the same way, and a search that finds nothing says so.
        back, _ = self.tool("manager", "see_responsibilities", retired=True)
        self.assertIn(f"Retired duties ({hub.DUTY_LOOK_BACK + 2}), newest first:", back)
        self.assertIn("and 2 older ones.", back)
        self.assertIn("No duty of the ones you may see says 'ledger'",
                      self.tool("manager", "see_responsibilities", search="ledger")[0])

    # ---- a lead writes the duties of its own team (the owner, 20 October 2026)
    def with_a_lead(self):
        """A team with a lead over vps, and the lead's own task, whose session its team tools work in."""
        hub.TEAM["agents"]["lead"] = {"role": "lead", "runtime": "claude", "machine": "vps", "can": ["shell"]}
        hub.TEAM["agents"]["vps"]["reports_to"] = "lead"
        f = hub.check_task("manager", {"owner": "lead", "title": "Ship the autumn theme",
                                       "done_when": "The theme is live and the shop still takes orders."})
        with hub.LOCK, hub.transaction():
            return hub.admit_task("manager", f)

    def test_a_lead_writes_the_duties_of_its_own_team_and_of_nobody_else(self):
        """The owner, 20 October 2026: "manager should also act as a lead, and leads can also set duties, yes, that
        is fine". cd0b3cd had taken both tools off a lead for a good reason that no longer holds -- they could only
        refuse -- so the fix is the rule underneath, not the tool list."""
        self.assertEqual(hub.LEAD_TEAM_TOOLS,
                         ("create_task", "cancel_task", "restart_task", "answer", "check_result",
                          "decide_permission", "see_team", "see_capacity", "decide_report",
                          "set_duty", "change_duty",
                          "set_agent_model"))       # AUTONOMY.md P8: a lead is its team's one changer
        tid = self.with_a_lead()
        served = {t["name"] for t in hub.tools_for("lead")}
        self.assertLessEqual({"create_task", "see_capacity", "see_responsibilities", "set_duty", "change_duty"},
                             served)
        # Its own team: yes. Its own duty: yes since 26 October 2026 (plan C17). An agent of another team: no.
        self.assertEqual(hub.duty_write_allowed("lead", "vps"), (True, None))
        self.assertEqual(hub.duty_write_allowed("lead", "lead"), (True, None))
        allowed, why = hub.duty_write_allowed("lead", "studio")
        self.assertFalse(allowed)
        self.assertIn("does not report to you", why)
        self.assertIn("manager writes the duties of every other agent",
                      hub.duty_write_allowed("lead", "studio")[1])
        # And the tool itself, in the session of the lead's own task: one duty, written by the lead.
        text, error = self.tool("lead", "set_duty", task_id=hub.tref(tid), request_id=str(uuid.uuid4()),
                                agent="vps", text="Watch the shop's order queue. When an order sticks, find out "
                                                  "why, fix it and write to the customer yourself.",
                                watch=[CLOCK_WATCH])
        self.assertFalse(error, text)
        self.assertIn("for vps", text)
        r = hub.duty_row(1)
        self.assertEqual((r["agent"], r["created_by"]), ("vps", "lead"))
        # A lead reads what it may write, and the manager -- the authority over every duty -- is told who wrote it.
        seen, error = self.tool("lead", "see_responsibilities", task_id=hub.tref(tid))
        self.assertFalse(error, seen)
        self.assertIn("order queue", seen)
        told = hub.q("SELECT agent, text FROM events WHERE kind='say' AND text LIKE '%R-1%'")
        self.assertIn("manager", {r["agent"] for r in told})
        self.assertIn("lead", " ".join(r["text"] for r in told))
        # change_duty has the same reach, and the manager can still change what the lead wrote.
        text, error = self.tool("lead", "change_duty", task_id=hub.tref(tid), request_id=str(uuid.uuid4()),
                                responsibility="R-1", action="pause")
        self.assertFalse(error, text)
        self.assertEqual(hub.duty_row(1)["state"], "paused")
        text, error = self.tool("manager", "change_duty", request_id=str(uuid.uuid4()), responsibility="R-1",
                                action="resume")
        self.assertFalse(error, text)
        self.assertEqual(hub.duty_row(1)["state"], "active")

    def test_the_cases_of_a_duty_a_lead_wrote_reach_the_lead_in_a_session_of_its_own(self):
        """The half that keeps this from being a tool that can only refuse. duty_target used to require the holder
        to report to the MANAGER, because a duty's watch starts a case task and somebody has to read its result --
        so every duty a lead could write for its own team was refused, which is why cd0b3cd took both tools away.
        The rule it was standing in for is wake_route's, and that one already handles a lead's worker: the case task
        is the lead's subtask under a parent task the manager requests, so the lead reads its team's case results in
        a session the hub starts for it."""
        tid = self.with_a_lead()
        text, error = self.tool("lead", "set_duty", task_id=hub.tref(tid), request_id=str(uuid.uuid4()),
                                agent="vps", text="Watch the shop's order queue. When an order sticks, find out "
                                                  "why, fix it and write to the customer yourself.",
                                watch=[CLOCK_WATCH])
        self.assertFalse(error, text)
        run = self.fire(self.watches(1)[0]["id"])
        self.assertEqual(run["state"], "started", run["reason"])
        case = hub.q1("SELECT * FROM tasks WHERE id=?", (run["task"],))
        self.assertEqual((case["owner"], case["requester"]), ("vps", "lead"))
        parent = hub.q1("SELECT * FROM tasks WHERE id=?", (case["parent"],))
        self.assertEqual((parent["owner"], parent["requester"]), ("lead", "manager"))
        self.assertIsNotNone(case["duty_case"])
        # So the lead can check that result, in the session of that parent task -- which is the whole point of the
        # parent, and what makes a duty a lead wrote something the fleet can actually run.
        hub.CALL.context = ("test-generation", hub.tref(parent["id"]), parent["attempt"])
        try:
            self.assertIsNone(hub.in_scope("lead", case))
        finally:
            hub.CALL.context = None
        # And nothing else widened: ordinary work on a lead's worker still follows the reporting line.
        allowed, why = hub.authority("manager", "vps", "task")
        self.assertFalse(allowed)
        self.assertIn("only lead gives it tasks", why)
        self.assertEqual(hub.AUTHORITY_ACTIONS, ("task", "rule"))

    def test_a_key_that_another_duty_has_open_joins_that_case_and_keeps_no_copy(self):
        """Live, 3 November 2026: a lead's duty copied each of a DevOps agent's cases into a case of its
        own with the same key (25 of them), so every event had two records that two agents kept, and neither could
        see the other's. One event is one case: the second duty joins the case that is open, and works in it."""
        mine = self.duty()
        self.fire(self.watches(mine["id"])[0]["id"])
        found = self.first_case_task()
        text, error = self.tool("vps", "open_case", request_id=str(uuid.uuid4()), responsibility="R-1",
                                key="cve/CVE-2026-1/shop", title="zod 4.6.6 in shop", task_id=hub.tref(found["id"]))
        self.assertFalse(error, text)
        event = self.case()
        theirs = self.duty(agent="studio", text="Fix the shop's vulnerable packages. Push and release the fix.")
        self.fire(self.watches(theirs["id"])[0]["id"])
        work = self.first_case_task()
        self.assertEqual(work["owner"], "studio")
        step = dict(request_id=str(uuid.uuid4()), case=hub.cref(event), step="fixed", text="zod 4.6.7 pushed",
                    task_id=hub.tref(work["id"]))
        text, error = self.tool("studio", "record_step", **step)
        self.assertTrue(error)
        self.assertIn("is not a case of your duties", text)          # not before its duty joined it
        before = hub.q1("SELECT COUNT(*) n FROM duty_cases")["n"]
        text, error = self.tool("studio", "open_case", request_id=str(uuid.uuid4()), responsibility="R-2",
                                key="cve/CVE-2026-1/shop", title="zod in shop, again", task_id=hub.tref(work["id"]))
        self.assertFalse(error, text)
        self.assertIn(f"{hub.cref(event)} of vps", text)
        self.assertIn("One event is one case", text)
        self.assertIn("another key", text)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM duty_cases")["n"], before)       # no copy
        self.assertEqual(hub.q1("SELECT duty_case FROM tasks WHERE id=?", (work["id"],))["duty_case"],
                         work["duty_case"])                         # its task keeps its own case, and only that
        again, error = self.tool("studio", "open_case", request_id=str(uuid.uuid4()), responsibility="R-2",
                                 key="cve/CVE-2026-1/shop", title="zod in shop", task_id=hub.tref(work["id"]))
        self.assertFalse(error, again)                              # the line again: the same case, one record of it
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM duty_history WHERE kind='case_joined'")["n"], 1)
        # So it works in the case itself: its records are the holder's records, and the holder reads who else is in.
        text, error = self.tool("studio", "record_step", **dict(step, request_id=str(uuid.uuid4())))
        self.assertFalse(error, text)
        self.assertEqual([(s["key"], s["by"]) for s in hub.duty_steps_of(event["id"])], [("fixed", "studio")])
        seen, error = self.tool("studio", "see_responsibilities", task_id=hub.tref(work["id"]))
        self.assertFalse(error, seen)
        self.assertIn("Open cases of other duties that it works in (1)", seen)
        self.assertIn("zod 4.6.6 in shop", seen)
        seen, error = self.tool("vps", "see_responsibilities", task_id=hub.tref(found["id"]))
        self.assertIn("R-2 of studio works in it too", seen)
        code, detail = self.detail(theirs["id"])
        self.assertEqual(code, 200, detail)
        self.assertEqual([c["ref"] for c in detail["responsibility"]["joined"]], [hub.cref(event)])
        self.assertIn("case_joined", {h["kind"] for h in detail["history"]})
        # And it closes the case, which then leaves its list.
        text, error = self.tool("studio", "close_case", request_id=str(uuid.uuid4()), case=hub.cref(event),
                                outcome="handled", note="zod 4.6.7 is live", task_id=hub.tref(work["id"]))
        self.assertFalse(error, text)
        self.assertEqual((self.case(event["id"])["state"], self.case(event["id"])["closed_by"]), ("closed", "studio"))
        self.assertEqual(self.detail(theirs["id"])[1]["responsibility"]["joined"], [])
        # A key that no other duty has open is still this duty's own event.
        text, error = self.tool("studio", "open_case", request_id=str(uuid.uuid4()), responsibility="R-2",
                                key="cve/CVE-2026-2/shop", title="sharp in shop", task_id=hub.tref(work["id"]))
        self.assertFalse(error, text)
        self.assertEqual(self.case()["responsibility"], theirs["id"])

    def test_a_lead_gives_the_work_of_a_case_that_its_duty_joined_and_its_worker_closes_it(self):
        """The half that makes a joined case worth having: the lead gives its fix to its own team with create_task
        case_id, so its worker closes the one case of the event, where a copy used to be closed instead."""
        tid = self.with_a_lead()
        holder = self.duty(agent="studio", text="Find each advisory that touches what we run. One case each.")
        self.fire(self.watches(holder["id"])[0]["id"])
        found = self.first_case_task()
        text, error = self.tool("studio", "open_case", request_id=str(uuid.uuid4()), responsibility="R-1",
                                key="cve/CVE-2026-1/shop", title="zod 4.6.6 in shop", task_id=hub.tref(found["id"]))
        self.assertFalse(error, text)
        event = self.case()
        give = dict(owner="vps", title="Move shop to zod 4.6.7", done_when="zod 4.6.7 is live in shop",
                    case_id=hub.cref(event), task_id=hub.tref(tid))
        text, error = self.tool("lead", "create_task", **give)
        self.assertTrue(error)
        self.assertIn("is not a case of a duty you may read", text)
        self.duty(agent="lead", text="Fix the advisories that touch the shop, through the team.")
        text, error = self.tool("lead", "open_case", request_id=str(uuid.uuid4()), responsibility="R-2",
                                key="cve/CVE-2026-1/shop", title="zod in shop", task_id=hub.tref(tid))
        self.assertFalse(error, text)
        text, error = self.tool("lead", "create_task", **give)
        self.assertFalse(error, text)
        fix = hub.q1("SELECT * FROM tasks WHERE owner='vps' ORDER BY id DESC LIMIT 1")
        self.assertEqual(fix["duty_case"], event["id"])
        text, error = self.tool("vps", "close_case", request_id=str(uuid.uuid4()), case=hub.cref(event),
                                outcome="handled", note="zod 4.6.7 is live in shop", task_id=hub.tref(fix["id"]))
        self.assertFalse(error, text)
        text, error = self.tool("vps", "deliver_result", task_id=hub.tref(fix["id"]), outcome="completed",
                                what_was_done="zod 4.6.7 is live", where_output_is="commit a95cee6",
                                how_checked="The check no longer prints the line")
        self.assertFalse(error, text)
        self.assertEqual((self.case(event["id"])["state"], self.case(event["id"])["outcome"]), ("closed", "handled"))

    def test_a_lead_cannot_move_a_duty_onto_or_off_an_agent_outside_its_team(self):
        """set_duty with another agent moves the duty. Checking only the new holder would let a lead take a duty off
        an agent it has no authority over, which is writing that agent's duty by another route."""
        tid = self.with_a_lead()
        self.duty(agent="studio", text="Keep the shop pages up. Fix what breaks.")       # not the lead's team
        text, error = self.tool("lead", "set_duty", task_id=hub.tref(tid), request_id=str(uuid.uuid4()),
                                responsibility="R-1", agent="vps")
        self.assertTrue(error, text)
        self.assertIn("does not report to you", text)
        self.assertEqual(hub.duty_row(1)["agent"], "studio")
        own = self.duty(agent="vps")                                                     # this one is its team's
        text, error = self.tool("lead", "set_duty", task_id=hub.tref(tid), request_id=str(uuid.uuid4()),
                                responsibility=hub.rref(own["id"]), agent="studio")
        self.assertTrue(error, text)
        self.assertIn("does not report to you", text)
        self.assertEqual(hub.duty_row(own["id"])["agent"], "vps")
        # The manager's own reach is unchanged: it moves either of them.
        text, error = self.tool("manager", "set_duty", request_id=str(uuid.uuid4()),
                                responsibility=hub.rref(own["id"]), agent="studio")
        self.assertFalse(error, text)
        self.assertEqual(hub.duty_row(own["id"])["agent"], "studio")

    def test_a_worker_writes_its_own_duty_and_nobody_else_s_and_sees_only_its_own(self):
        """Plan C17 (the owner, 26 October 2026: "I dont want unnecessary gates and approvals"): a worker writes its own
        standing work as a duty, the manager is told once and quietly, and another agent's duty is still not its own
        to write."""
        self.duty()
        self.duty(agent="studio", text="Keep the shop pages up. Fix what breaks.")
        self.fire(self.watches(1)[0]["id"])
        t = self.first_case_task()
        text, error = self.tool("vps", "set_duty", request_id=str(uuid.uuid4()), agent="studio",
                                text="Somebody else's duty.", task_id=hub.tref(t["id"]))
        self.assertTrue(error)
        self.assertIn("you write duties for yourself only", text)
        text, error = self.tool("vps", "set_duty", request_id=str(uuid.uuid4()), agent="vps",
                                text="Keep the feed's mirror fresh. Rebuild it when the source changes.",
                                task_id=hub.tref(t["id"]))
        self.assertFalse(error, text)
        own = hub.q1("SELECT * FROM responsibilities WHERE text LIKE 'Keep the feed%'")
        self.assertEqual((own["agent"], own["created_by"]), ("vps", "vps"))
        told = [e for e in hub.q("SELECT * FROM events WHERE agent='manager' AND kind='say'")
                if f"vps wrote {hub.rref(own['id'])} for itself" in e["text"]]
        self.assertEqual(len(told), 1)
        self.assertEqual(json.loads(told[0]["extra"]), {"quiet": True})
        self.assertFalse([e for e in hub.q("SELECT * FROM events WHERE agent='vps' AND kind='say'")
                          if json.loads(e["extra"] or "{}").get("duty") == own["id"]])      # it wrote it: no notice
        self.assertEqual(hub.duty_write_allowed("vps", "vps"), (True, None))
        text, error = self.tool("vps", "see_responsibilities", task_id=hub.tref(t["id"]))
        self.assertFalse(error, text)
        self.assertIn("R-1", text)
        self.assertNotIn("Keep the shop pages up", text)
        seen, error = self.tool("manager", "see_responsibilities")
        self.assertFalse(error, seen)
        self.assertIn("Keep the shop pages up", seen)
        self.assertIn("R-1/C-1", seen)
        self.assertIn("Duty: Keep customer content generation working.", seen)

    def test_a_message_is_the_way_a_duty_is_made(self):
        """R9: the manager writes the duty in the session where the owner's message arrives, and a chat window only
        reads. No owner route and no file is part of this path."""
        hub.emit("manager", "say", "[owner] From now on, watch support@example.com and fix what customers report.")
        names = {x["name"] for x in hub.tools_for("manager")}
        self.assertLessEqual({"set_duty", "change_duty", "see_responsibilities"}, names)
        text, error = self.tool("manager", "set_duty", request_id=str(uuid.uuid4()), agent="vps",
                                text="Answer the support mailbox. Customers write to support@example.com.",
                                watch=[CLOCK_WATCH])
        self.assertFalse(error, text)
        self.assertIn("Saved R-1 (Answer the support mailbox)", text)
        self.assertEqual(hub.duty_row(1)["created_by"], "manager")
        # The owner can also ask the agent itself: its chat reads its duties and writes nothing.
        chat = ("test-generation", "owner-chat", "1")
        in_chat = {x["name"] for x in hub.tools_for("vps", chat)}
        self.assertIn("see_responsibilities", in_chat)
        self.assertEqual(in_chat & {"set_duty", "change_duty", "open_case", "record_step", "close_case"}, set())
        text, error = hub.call_tool("vps", "see_responsibilities", {}, chat)
        self.assertFalse(error, text)
        self.assertIn("Answer the support mailbox", text)
        text, error = hub.call_tool("vps", "set_duty", {"request_id": str(uuid.uuid4()), "agent": "vps",
                                                        "text": "I decide"}, chat)
        self.assertTrue(error)
        self.assertIn("no tool named set_duty", text)
        # message_agent stays its way to pass the owner's request up to the manager.
        self.assertIn("message_agent", in_chat)

    def test_the_manager_writes_and_changes_a_duty_with_its_tools(self):
        text, error = self.tool("manager", "set_duty", request_id=str(uuid.uuid4()), agent="vps",
                                text="Answer the support mailbox. Customers write all day. Answer them yourself.",
                                watch=[CLOCK_WATCH])
        self.assertFalse(error, text)
        self.assertIn("Saved R-1", text)
        r = hub.duty_row(1)
        self.assertEqual(r["created_by"], "manager")
        self.assertEqual(len(self.watches(1)), 1)
        text, error = self.tool("manager", "set_duty", request_id=str(uuid.uuid4()), responsibility="R-1",
                                text="Answer the support mailbox. Answer them yourself, and ask me about a refund.")
        self.assertFalse(error, text)
        self.assertIn("ask me about a refund", hub.duty_row(1)["text"])
        text, error = self.tool("manager", "change_duty", request_id=str(uuid.uuid4()), responsibility="R-1",
                                action="pause", note="The mailbox moves")
        self.assertFalse(error, text)
        self.assertEqual(hub.duty_row(1)["state"], "paused")
        self.assertEqual(hub.trigger_row(self.watches(1)[0]["id"])["state"], "paused")
        # A paused duty starts nothing: its watch is paused, and a forced run says why.
        run = self.fire(self.watches(1)[0]["id"], when=self.clock + 600)
        self.assertEqual(run["state"], "not_started")
        self.assertIn("R-1 is paused", run["reason"])


class Records(Base):
    def setUp(self):
        super().setUp()
        self.r = self.duty()
        self.fire(self.watches(self.r["id"])[0]["id"])
        self.task = self.first_case_task()

    def deliver(self, outcome="completed", **extra):
        args = dict(task_id=hub.tref(self.task["id"]), outcome=outcome,
                    what_was_done="Retired the signed-out accounts and released the fix",
                    where_output_is="commit a95cee6", how_checked="The pool reports 8 signed-in accounts")
        return self.tool("vps", "deliver_result", **dict(args, **extra))

    def test_a_completed_task_leaves_its_case_open_and_close_case_ends_it(self):
        """Live, 4 November 2026: a triage, a fix in git and a fix that waited for a host step each delivered
        completed, and each result closed the case before its fix was live, so the same advisory came back as a
        repeat three times. A task is often one part of its case, so no result closes one: close_case does, once the
        last step is done. Nothing is required, so a result is never refused for a missing record. The records are
        what the owner reads afterwards, and the agent writes the ones the duty's own words ask for."""
        self.handle(self.task, ("what broke", "the fix", "told the customer"))
        text, error = self.deliver()
        self.assertFalse(error, text)
        c = self.case(self.task["duty_case"])
        self.assertEqual(c["state"], "open")
        self.assertTrue(any(f"{hub.cref(c)} is still open and no task works it" in t for t in self.manager_said()))
        self.sweep()
        self.assertIsNone(hub.duty_row(self.r["id"])["marker_kind"])        # it waits for a next step: no review
        text, error = self.tool("manager", "close_case", request_id=str(uuid.uuid4()), case=hub.cref(c),
                                outcome="handled", note="The fix is live")
        self.assertFalse(error, text)
        c = self.case(c["id"])
        self.assertEqual((c["state"], c["outcome"], c["closed_by"]), ("closed", "handled", "manager"))
        steps = {s["key"]: s for s in hub.duty_steps_of(c["id"])}
        self.assertEqual(sorted(steps), ["the fix", "told the customer", "what broke"])
        self.assertEqual((steps["the fix"]["text"], steps["the fix"]["task"]),
                         ("the fix is done", self.task["id"]))
        self.assertIsNotNone(c["first_step"])

    def test_a_case_with_no_record_at_all_still_closes(self):
        """A duty like "look after SEO" has weeks where nothing happened. Its agent closes that case with no record,
        in the session of its result, and the result then says nothing about it."""
        c = self.case(self.task["duty_case"])
        text, error = self.tool("vps", "close_case", request_id=str(uuid.uuid4()), case=hub.cref(c),
                                outcome="no_action", note="Nothing happened", task_id=hub.tref(self.task["id"]))
        self.assertFalse(error, text)
        text, error = self.deliver()
        self.assertFalse(error, text)
        c = self.case(c["id"])
        self.assertEqual((c["state"], c["outcome"]), ("closed", "no_action"))
        self.assertEqual(hub.duty_steps_of(c["id"]), [])
        self.assertFalse(any("is still open" in t for t in self.manager_said()))

    def test_a_record_is_the_agents_own_label_and_replaces_the_one_before_it(self):
        c = self.case(self.task["duty_case"])
        for text in ("Told 3 customers", "Told 5 customers"):
            answer, error = self.tool("vps", "record_step", request_id=str(uuid.uuid4()), case=hub.cref(c),
                                      step="told the customer", text=text, task_id=hub.tref(self.task["id"]))
            self.assertFalse(error, answer)
        rows = hub.duty_steps_of(c["id"])
        self.assertEqual([(s["key"], s["text"]) for s in rows], [("told the customer", "Told 5 customers")])
        self.assertEqual([h["detail"] for h in hub.q("SELECT detail FROM duty_history WHERE kind='step'")],
                         ["R-1/C-1 told the customer: Told 3 customers",
                          "R-1/C-1 told the customer: Told 5 customers"])
        # Any label of the agent's own is a record; the hub keeps no catalogue of steps.
        answer, error = self.tool("vps", "record_step", request_id=str(uuid.uuid4()), case=hub.cref(c),
                                  step="refunded the order", text="EUR 49 back to the customer",
                                  task_id=hub.tref(self.task["id"]))
        self.assertFalse(error, answer)
        self.assertIn("refunded the order", "\n".join(hub.duty_case_text(self.case(c["id"]))))

    def test_a_failed_result_leaves_the_case_open_for_the_manager(self):
        text, error = self.deliver(outcome="failed", what_was_done="The provider is down and nobody answers")
        self.assertFalse(error, text)
        c = self.case(self.task["duty_case"])
        self.assertEqual(c["state"], "open")                    # a failure closes no case by itself
        text, error = self.tool("manager", "close_case", request_id=str(uuid.uuid4()), case=hub.cref(c),
                                outcome="failed", note="The provider is down.")
        self.assertFalse(error, text)
        c = self.case(c["id"])
        self.assertEqual((c["state"], c["outcome"], c["note"]), ("closed", "failed", "The provider is down."))
        # the note's own full stop is the line's: it read "The provider is down.. The watch"
        self.assertTrue(any("closed R-1/C-1 as failed: The provider is down. The watch opens no new case" in t
                            for t in self.manager_said()))

    def test_a_case_with_an_open_task_does_not_close(self):
        c = self.case(self.task["duty_case"])
        self.handle(self.task)
        text, error = self.tool("manager", "close_case", request_id=str(uuid.uuid4()), case=hub.cref(c),
                                outcome="handled", note="Done")
        self.assertTrue(error)
        self.assertIn("still has open tasks", text)
        text, error = self.deliver()
        self.assertFalse(error, text)
        self.assertEqual(self.case(c["id"])["state"], "open")
        text, error = self.tool("manager", "close_case", request_id=str(uuid.uuid4()), case=hub.cref(c),
                                outcome="handled", note="Done")
        self.assertFalse(error, text)
        self.assertEqual(self.case(c["id"])["state"], "closed")

    def test_a_task_that_opened_two_cases_carries_neither(self):
        """Live, 3 November 2026: a wake-up of one agent opened 25 cases, carried the first one only, and its result
        closed that one as handled while its fix still waited in another task. A task that opens a second case is
        the work of none of them, and no result closes a case."""
        text, error = self.tool("manager", "create_task", owner="vps", title="Read the advisories",
                                done_when="Each new advisory has its case")
        self.assertFalse(error, text)
        wake = hub.q1("SELECT * FROM tasks ORDER BY id DESC LIMIT 1")

        def opened(key):
            text, error = self.tool("vps", "open_case", request_id=str(uuid.uuid4()), responsibility="R-1", key=key,
                                    title=f"{key} touches the shop", task_id=hub.tref(wake["id"]))
            self.assertFalse(error, text)
            return self.case(), text
        first, text = opened("cve/1/shop")
        self.assertEqual(hub.q1("SELECT duty_case FROM tasks WHERE id=?", (wake["id"],))["duty_case"], first["id"])
        second, _ = opened("cve/2/shop")
        third, _ = opened("cve/3/shop")
        self.assertIsNone(hub.q1("SELECT duty_case FROM tasks WHERE id=?", (wake["id"],))["duty_case"])
        text, error = self.tool("vps", "record_step", request_id=str(uuid.uuid4()), case=hub.cref(first),
                                step="next", text="Waits for the fix in the shop", task_id=hub.tref(wake["id"]))
        self.assertFalse(error, text)
        self.assertIn("your result does not", text)
        text, error = self.tool("vps", "deliver_result", task_id=hub.tref(wake["id"]), outcome="completed",
                                what_was_done="Three cases opened", where_output_is="-", how_checked="Read them back")
        self.assertFalse(error, text)
        self.assertEqual([self.case(c["id"])["state"] for c in (first, second, third)], ["open"] * 3)
        # The watch's own case task carries its case, and its result leaves that case open too.
        text, error = self.deliver()
        self.assertFalse(error, text)
        self.assertEqual(self.case(self.task["duty_case"])["state"], "open")


class Notes(Base):
    """The agent's own working notes: what it has worked out about how it works, carried into its next session.
    The profile stays the owner's words; these are the agent's (owner direction, 19 October 2026)."""

    def setUp(self):
        super().setUp()
        self.r = self.duty()
        self.fire(self.watches(self.r["id"])[0]["id"])
        self.task = self.first_case_task()

    def write(self, who="vps", text="Check the pool count before the logs.", why="It caught me twice", task=True):
        args = dict(request_id=str(uuid.uuid4()), text=text, why=why)
        if task:
            args["task_id"] = hub.tref(self.task["id"])
        return self.tool(who, "write_notes", **args)

    def test_notes_are_kept_version_by_version_with_where_they_came_from(self):
        text, error = self.write()
        self.assertFalse(error, text)
        self.assertIn("revision 1", text)
        text, error = self.write(text="Check the pool count, then the queue depth.", why="The queue mattered too")
        self.assertFalse(error, text)
        self.assertIn("revision 2", text)
        # The newest is what the next session starts with; the one before it is kept.
        self.assertEqual(hub.agent_notes_text("vps"), "Check the pool count, then the queue depth.")
        v = hub.notes_view("vps")
        self.assertEqual([x["revision"] for x in v["versions"]], [2, 1])
        self.assertEqual(v["versions"][1]["text"], "Check the pool count before the logs.")
        # Provenance: every version names the task and the case it was written in.
        self.assertEqual((v["versions"][0]["task"], v["versions"][0]["duty_case"]),
                         (self.task["id"], self.task["duty_case"]))
        seen, error = self.tool("vps", "see_notes", task_id=hub.tref(self.task["id"]))
        self.assertFalse(error, seen)
        self.assertIn("The notes of vps, revision 2, written", seen)
        self.assertIn("Versions before it (1), newest first:", seen)
        self.assertIn("The queue mattered too", seen)       # what the newest version changed, and why
        self.assertIn("It caught me twice", seen)           # and the one before it

    def test_the_review_is_what_asks_an_agent_to_rewrite_its_notes(self):
        """Nothing else does. The tools exist, but a session only re-reads and rewrites its own notes because the
        review that already puts its duties in order asks it to — one rhythm, not two."""
        self.sweep()
        task = self.review_task()
        self.assertEqual(task["title"], "Put your duties and your notes in order")
        self.assertIn("read your own notes with see_notes", task["details"])
        self.assertIn("rewrite them with write_notes", task["details"])
        self.assertIn("Leave them as they are when nothing changed", task["details"])
        self.assertIn(hub.NOTES_RULE, task["details"])        # an instruction is not a memory
        self.assertIn("whether you changed your notes", task["details"])
        self.assertIn("the notes are either rewritten or left as they are on purpose", task["done_when"])
        # A version written from that task carries it, so the owner can read which review changed what.
        hub.q("INSERT INTO tasks(id,title,owner,requester,state,created,done_when) "
              "VALUES(90,?,'vps','manager','working',?,?)", (task["title"], self.clock, task["done_when"]))
        text, error = self.tool("vps", "write_notes", request_id=str(uuid.uuid4()), task_id="T-90",
                                text="Check the pool count before the logs.", why="Two repeats taught me")
        self.assertFalse(error, text)
        self.assertEqual(hub.notes_view("vps")["versions"][0]["task"], 90)

    def test_an_agent_with_no_notes_is_told_what_they_are_for(self):
        seen, error = self.tool("vps", "see_notes", task_id=hub.tref(self.task["id"]))
        self.assertFalse(error, seen)
        self.assertIn("has written no notes yet", seen)
        self.assertIn("An instruction is not a permission, and it is not a memory either.", seen)
        self.assertIsNone(hub.agent_notes_text("vps"))

    def test_notes_belong_to_their_agent_and_nobody_else_not_even_the_manager(self):
        """Narrower than a duty on purpose, and the same rule memory_read_allowed gives: an agent that knows the
        manager reads its notes writes them for the manager instead of for its own next session."""
        self.write()
        self.duty(agent="studio", text="Keep the shop pages up. Fix what breaks.")
        self.fire(self.watches(2)[0]["id"])
        theirs = hub.q1("SELECT * FROM tasks WHERE owner='studio' ORDER BY id DESC LIMIT 1")
        text, error = self.tool("studio", "see_notes", agent="vps", task_id=hub.tref(theirs["id"]))
        self.assertTrue(error)
        self.assertIn("are its own", text)
        text, error = self.tool("manager", "see_notes", agent="vps")
        self.assertTrue(error)
        self.assertIn("not even the manager", text)
        # Its own are still its own, and the owner still reads every agent's at /ui/notes/<agent>.
        seen, error = self.tool("vps", "see_notes", task_id=hub.tref(self.task["id"]))
        self.assertFalse(error, seen)
        self.assertIn("The notes of vps", seen)
        self.assertEqual(self.request("/ui/notes/vps?db=test-generation")[1]["revision"], 1)

    def test_notes_are_capped_guarded_and_written_once_for_one_request_id(self):
        text, error = self.write(text="x" * (hub.NOTES_MAX + 1))
        self.assertTrue(error)
        self.assertIn(f"1 to {hub.NOTES_MAX} characters", text)
        # The guard itself is test_capacity's; what this checks is that write_notes goes through it.
        with patch.object(hub, "secret_hit", lambda *texts: any("hunter2" in str(t) for t in texts)):
            text, error = self.write(text="The admin password of shop.example is hunter2.")
            self.assertTrue(error)
            self.assertIn("contains a login", text)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM agent_notes")["n"], 0)     # a refusal writes nothing
        rid = str(uuid.uuid4())
        first, error = self.tool("vps", "write_notes", request_id=rid, text="One version.", why="first",
                                 task_id=hub.tref(self.task["id"]))
        self.assertFalse(error, first)
        again, error = self.tool("vps", "write_notes", request_id=rid, text="One version.", why="first",
                                 task_id=hub.tref(self.task["id"]))
        self.assertEqual((again, error), (first, False))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM agent_notes")["n"], 1)

    def test_the_owner_reads_every_version(self):
        self.write()
        self.write(text="Check the pool count, then the queue depth.", why="The queue mattered too")
        code, data = self.request("/ui/notes/vps?db=test-generation")
        self.assertEqual(code, 200, data)
        self.assertEqual((data["agent"], data["revision"]), ("vps", 2))
        self.assertEqual(data["text"], "Check the pool count, then the queue depth.")
        self.assertEqual([v["revision"] for v in data["versions"]], [2, 1])
        self.assertEqual(data["versions"][0]["by"], "vps")
        self.assertEqual(self.request("/ui/notes/nobody?db=test-generation")[0], 404)
        code, empty = self.request("/ui/notes/studio?db=test-generation")
        self.assertEqual((code, empty["text"], empty["revision"], empty["versions"]), (200, None, 0, []))


class Memory(Base):
    """The owner reads an agent's lessons beside its notes (owner feature agent_memory, the owner's yes of
    25 October 2026): the ones that stand, as the agent's own recall sees them, each with the hub's own evidence.
    The agent writes them; the owner only reads, and his reading changes nothing."""

    def setUp(self):
        super().setUp()
        self.r = self.duty()
        self.fire(self.watches(self.r["id"])[0]["id"])
        self.task = self.first_case_task()

    def remember(self, text, about="the pool", prevents="Twenty minutes in the logs", **more):
        out, error = self.tool("vps", "remember", request_id=str(uuid.uuid4()), task_id=hub.tref(self.task["id"]),
                               about=about, text=text, prevents=prevents, **more)
        self.assertFalse(error, out)
        return hub.q1("SELECT id FROM memories ORDER BY id DESC LIMIT 1")["id"]

    def read(self, agent="vps"):
        return self.request(f"/ui/memory/{agent}?db=test-generation")

    def test_the_owner_reads_the_lessons_that_stand_with_the_hubs_own_evidence(self):
        day, written = 86400, self.clock
        old = self.remember("Check the signed-in pool count before reading any logs.")
        # an earlier round's `held`, its dead end and its summary, as those rounds wrote them: no tool writes them now
        held = hub.ins("INSERT INTO memories(agent,about,text,prevents,created,by_task,request_id,reinforced,"
                       "reinforced_at) VALUES('vps','the pool','Retire a signed-out account before the next run.',"
                       "'Twenty minutes in the logs',?,?,'r-held',1,?)", (written, self.task["id"], written + 30 * day))
        self.clock = written + 61 * day
        with hub.LOCK, hub.transaction():
            keyed = hub.memory_from_work("vps", "The deploy fails when the lock file is stale.",
                                         "R-1 opening a case with the key 'deploy' again", "the shop", self.clock,
                                         task=self.task["id"], responsibility=self.r["id"], prevents_key="deploy")
        show(keyed, task=self.task["id"], when=self.clock)
        with hub.LOCK, hub.transaction():
            hub.memory_contradicted(self.r["id"], "deploy", self.clock)
        wall = hub.ins("INSERT INTO memories(agent,about,text,prevents,created,by_task,request_id,kind,cost_minutes,"
                       "recheck) VALUES('vps','stripe','A test key cannot refund a live charge.',?,?,?,'r-wall',"
                       "'dead_end',180,'One refund with the test key: a 400 says the wall stands.')",
                       (hub.DEAD_END_PREVENTS, self.clock, self.task["id"]))
        gone = self.remember("The export wants ISO dates.")
        out, error = self.tool("vps", "forget", request_id=str(uuid.uuid4()), task_id=hub.tref(self.task["id"]),
                               memory=hub.mref(gone), reason="The header row wants them too.")
        self.assertFalse(error, out)
        first = self.remember("Run the smoke before the deploy.", about="acme/web")
        second = self.remember("The smoke is npm run smoke.", about="acme/web", new=True)
        summary = hub.ins("INSERT INTO memories(agent,about,text,prevents,created,request_id) VALUES('vps',"
                          "'acme/web','Run npm run smoke before every deploy.','Twenty minutes in the logs',?,'r-sum')",
                          (self.clock,))
        for member in (first, second):
            hub.q("UPDATE memories SET folded_into=? WHERE id=?", (summary, member))
            hub.q("INSERT INTO memory_folds(summary,member,created,by) VALUES(?,?,?,'vps')",
                  (summary, member, self.clock))
        archived = self.remember("The old dashboard is at /admin.", about="the dashboard")
        hub.q("UPDATE memories SET archived=? WHERE id=?", (self.clock, archived))
        later = self.remember("The staging key is hunter2hunter2 for now.", about="staging")
        recalls = hub.q1("SELECT SUM(recalls) n FROM memories")["n"]
        # A login registered after the write: the read masks it, as the notes route does.
        with patch.object(hub, "secret_hit", lambda *x: any("hunter2hunter2" in str(one) for one in x)), \
             patch.object(hub, "secret_spans", lambda text: [(text.index("hunter2hunter2"),
                                                              text.index("hunter2hunter2") + 14)]
                          if "hunter2hunter2" in text else []):
            code, data = self.read()
        self.assertEqual(code, 200, data)
        self.assertEqual((data["db"], data["agent"], data["total"]), ("test-generation", "vps", 6))
        # Newest first, and only what stands: the forgotten, the folded and the archived ones are not listed.
        self.assertEqual([m["id"] for m in data["lessons"]], [later, summary, wall, keyed, held, old])
        lessons = {m["id"]: m for m in data["lessons"]}
        m = lessons[old]
        self.assertEqual((m["kind"], m["about"], m["text"], m["prevents"], m["at"], m["task"]),
                         ("lesson", "the pool", "Check the signed-in pool count before reading any logs.",
                          "Twenty minutes in the logs", written, self.task["id"]))
        self.assertEqual((m["held"], m["contradicted"], m["contradicted_at"]), (0, 0, None))
        # No clock marks a lesson (AUTONOMY.md decision 39): an earlier round's stale and held_until are gone, 61 days on
        self.assertEqual({"stale", "held_until"} & {k for one in data["lessons"] for k in one}, set())
        self.assertEqual(lessons[held]["held"], 1)          # an earlier round's count stays readable
        m = lessons[keyed]      # the work judges a lesson with a case key
        self.assertEqual((m["contradicted"], m["contradicted_at"]), (1, written + 61 * day))
        m = lessons[wall]
        self.assertEqual((m["kind"], m["cost_minutes"], m["recheck"], m["prevents"]),
                         ("dead_end", 180, "One refund with the test key: a 400 says the wall stands.",
                          hub.DEAD_END_PREVENTS))
        self.assertEqual((lessons[old]["cost_minutes"], lessons[old]["recheck"]), (None, None))
        self.assertIsNone(lessons[summary]["task"])         # a summary carries no task: its members keep theirs
        self.assertEqual(lessons[later]["text"], f"The staging key is {hub.MASK} for now.")
        # The owner's reading is not a recall: it counts nothing and moves nothing.
        self.assertEqual(hub.q1("SELECT SUM(recalls) n FROM memories")["n"], recalls)
        self.assertEqual(self.request("/ui/memory/nobody?db=test-generation")[0], 404)
        self.assertEqual(self.request("/ui/memory/vps?db=old-generation")[0], 409)
        code, empty = self.read("studio")
        self.assertEqual((code, empty["agent"], empty["total"], empty["lessons"]), (200, "studio", 0, []))
        self.assertIn("agent_memory", self.request("/ui/state")[1]["ui_features"])

    def test_the_owner_reads_the_newest_200_and_how_many_there_are(self):
        with hub.LOCK:
            hub.DB.executemany("INSERT INTO memories(agent,about,text,prevents,created,request_id) "
                               "VALUES('vps','bulk',?,'Nothing',?,'')",
                               [(f"Lesson {n}.", self.clock) for n in range(1, 206)])
            hub.DB.commit()
        code, data = self.read()
        self.assertEqual((code, data["total"], len(data["lessons"])), (200, 205, hub.MEMORY_MOST))
        self.assertEqual((data["lessons"][0]["text"], data["lessons"][-1]["text"]), ("Lesson 205.", "Lesson 6."))


class Loop(Base):
    """The self-improvement loop, closed: the work writes a lesson, and the work contradicts it. The owner's words,
    19 October 2026: "I basically want to build a recursive self improvement LOOP"."""

    def setUp(self):
        super().setUp()
        self.r = self.duty(watch=[{"kind": "check", "check": CHECK}])
        self.rule = self.watches(self.r["id"])[0]["id"]

    def only_task(self):
        """One open task of vps, for a tool that needs a task session and nothing else of it."""
        row = hub.q1("SELECT id FROM tasks WHERE owner='vps' ORDER BY id DESC LIMIT 1")
        if not row:
            self.fire(self.rule)
            row = hub.q1("SELECT id FROM tasks WHERE owner='vps' ORDER BY id DESC LIMIT 1")
        return row["id"]

    def deliver(self, task, **extra):
        args = dict(task_id=hub.tref(task["id"]), outcome="completed",
                    what_was_done="Retired the signed-out account", where_output_is="commit a95cee6",
                    how_checked="The pool reports 8 signed-in accounts")
        return self.tool("vps", "deliver_result", **dict(args, **extra))

    def close(self, task):
        """Its agent ends the case before its result, as the case task's details say: no result closes a case."""
        text, error = self.tool("vps", "close_case", request_id=str(uuid.uuid4()), case=hub.cref(self.case(
            task["duty_case"])), outcome="handled", note="Retired the signed-out account", task_id=hub.tref(task["id"]))
        self.assertFalse(error, text)

    def test_a_lesson_from_a_case_carries_its_key_and_the_key_contradicts_it(self):
        self.fire(self.rule)
        t = self.first_case_task()
        self.close(t)
        out, error = self.deliver(t, learned="Check the signed-in pool count before reading any logs.",
                                  prevents="Twenty minutes lost in the logs when the pool is the cause")
        self.assertFalse(error, out)
        self.assertIn("M-1 keeps what you learned", out)
        self.assertIn("claims to stop R-1/C-1's key 'check/1' coming back", out)
        # the stop stays last and intact
        self.assertIn("You are done with it: stop now and end your turn; your session closes when it ends.", out)
        m = hub.q1("SELECT * FROM memories WHERE id=1")
        self.assertEqual((m["agent"], m["responsibility"], m["prevents_key"], m["contradicted"], m["by_task"]),
                         ("vps", self.r["id"], "check/1", 0, t["id"]))
        self.assertEqual(self.case()["state"], "closed")             # its agent closed it before its result
        # A later start shows the lesson, and then the same key comes back: the preventive action did not work, so the
        # lesson that claimed it was wrong.
        show(1, task=t["id"], when=self.clock + 3600)
        self.fire(self.rule, when=self.clock + 7200)
        self.assertEqual(self.case()["repeated"], 1)
        m = hub.q1("SELECT * FROM memories WHERE id=1")
        self.assertEqual(m["contradicted"], 1)
        self.assertIsNotNone(m["contradicted_at"])
        said = "\n".join(hub.memory_block(m, full=True))
        self.assertIn("That key HAS come back 1 time since", said)
        self.assertIn("wrong, or right and never acted on", said)
        # A second return counts again, and the hub never drops it: that judgement is the agent's.
        # A check watch waits while its last task is open, so that task has to end before the key can come back.
        hub.q("UPDATE duty_cases SET state='closed', closed=? WHERE state='open'", (self.clock,))
        hub.q("UPDATE tasks SET state='completed', outcome='completed', delivered=? WHERE state NOT IN "
              "('completed','failed','rejected','canceled')", (self.clock,))
        self.fire(self.rule, when=self.clock + 14400)
        m = hub.q1("SELECT * FROM memories WHERE id=1")
        self.assertEqual((m["contradicted"], m["dropped"]), (2, None))

    def test_a_lesson_tag_made_of_a_duty_name_keeps_no_part_of_a_login(self):
        """A lesson with no `about` of its own takes its duty's name, cut at MEMORY_ABOUT characters, and the tag is
        kept with the lesson and shown with it. A login registered after the duty was written is masked there only
        whole, so until 11 November 2026 one that lay across that cut stayed in part. Now the cut goes back to where
        such a run of characters starts, for a case's close and for a delivery alike."""
        login, salt = "Tag-Login-0123456789", "c0ffee"
        head = "Keep the signed-in account pool of the shop healthy"
        text = f"{head} {login} daily. Then tell me."
        self.assertEqual(hub.duty_name(text), f"{head} {login} daily")              # the name itself is not cut
        self.assertLess(len(head) + 1, hub.MEMORY_ABOUT)                            # and the login lies across 60
        self.assertGreater(len(head) + 1 + len(login), hub.MEMORY_ABOUT)
        r = self.duty(text=text, watch=[{"kind": "check", "check": CHECK}])
        self.fire(self.watches(r["id"])[0]["id"])
        t = self.first_case_task()
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES('crm',?,?,?,'')",
                (salt, hashlib.sha256((salt + login).encode()).hexdigest(), len(login)))
        out, error = self.tool("vps", "close_case", request_id=str(uuid.uuid4()), case=hub.cref(self.case(
            t["duty_case"])), outcome="handled", note="Retired the signed-out account", task_id=hub.tref(t["id"]),
            learned="Retire a signed-out account before the next run.")
        self.assertFalse(error, out)
        out, error = self.deliver(t, learned="Check the pool count first.", prevents="The same outage again")
        self.assertFalse(error, out)
        self.assertEqual([m["about"] for m in hub.q("SELECT about FROM memories ORDER BY id")], [head, head])

    def test_a_login_that_ends_a_duty_sentence_with_a_dot_never_shows_without_it(self):
        """A duty's name is its first sentence without the sentence's final dot, and a login can end there in a dot of
        its own. Until 11 November 2026 the name kept the rest of it: on every read, which makes the name again, and
        in every copy of the name (the duty's history, a case task's title, a lesson's tag, a start text), because a
        search for the whole login never found it there. Now the search finds a login whose last dots a name
        dropped, whether it was registered before a name was made or after."""
        login, salt = "Dot-Login-0123456789.", "c0ffee"
        text = f"Rotate the shop's key {login} Then tell me what failed."
        name = "Rotate the shop's key " + login[:-1]
        self.assertEqual(hub.duty_name(text), name)                     # as before: the sentence's dot is not in it
        r = self.duty(text=text, watch=[{"kind": "check", "check": CHECK}])     # its history row keeps the name
        self.fire(self.watches(r["id"])[0]["id"])
        t = self.first_case_task()
        self.assertEqual(t["title"], name)                              # and so does its case task's title
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES('crm',?,?,?,'')",
                (salt, hashlib.sha256((salt + login).encode()).hexdigest(), len(login)))
        code, data = self.detail(r["id"])                               # the name made again, after the login
        self.assertEqual(code, 200, data)
        self.assertEqual((data["responsibility"]["title"], data["responsibility"]["text"]), (hub.MASK, hub.MASK))
        self.assertEqual([h["detail"] for h in data["history"] if h["kind"] == "created"], [hub.MASK])
        code, state = self.request("/ui/state")
        self.assertEqual(code, 200, state)
        self.assertEqual([x["title"] for x in state["tasks"] if x["id"] == t["id"]], [hub.MASK])
        said = [json.dumps(data), json.dumps(state), hub.start_text("vps", t["id"]),
                self.tool("manager", "see_responsibilities")[0],
                self.tool("vps", "see_responsibilities", task_id=hub.tref(t["id"]))[0]]
        out, error = self.tool("vps", "close_case", request_id=str(uuid.uuid4()), case=hub.cref(self.case(
            t["duty_case"])), outcome="handled", note="Rotated the key", task_id=hub.tref(t["id"]),
            learned="Rotate the key before it runs out.")
        self.assertFalse(error, out)
        said.append(self.tool("vps", "recall", task_id=hub.tref(t["id"]))[0])     # a lesson tagged with the name
        out, error = self.deliver(t, learned="Read the key's age first.", prevents="The same outage again")
        self.assertFalse(error, out)
        code, memory = self.request("/ui/memory/vps?db=test-generation")
        self.assertEqual(code, 200, memory)
        self.assertEqual([m["about"] for m in memory["lessons"]], [f"Rotate the shop's key {hub.MASK}"] * 2)
        for text in said + [json.dumps(memory)]:
            self.assertNotIn(login[:6], text)

    def test_a_lesson_tag_cut_counts_the_dot_that_the_name_dropped(self):
        """A lesson's tag is the duty's name cut at MEMORY_ABOUT characters. The name drops its sentence's final dot,
        so until 11 November 2026 a run of 7 characters and a dot across that cut was cut inside it, and the tag,
        which is kept, held part of a login of 8. Now the cut reads the run with its dot."""
        login, salt = "Tg7-x9z.", "c0ffee"                              # 7 characters and a dot: 8, as a login can be
        head = "Keep the signed-in account pool of the web shop healthy"
        text = f"{head} {login} Then tell me."
        self.assertEqual(hub.duty_name(text), f"{head} {login[:-1]}")
        self.assertLess(len(head) + 1, hub.MEMORY_ABOUT)                            # the run lies across 60
        self.assertGreater(len(head) + len(login), hub.MEMORY_ABOUT)
        r = self.duty(text=text, watch=[{"kind": "check", "check": CHECK}])
        self.fire(self.watches(r["id"])[0]["id"])
        t = self.first_case_task()
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES('crm',?,?,?,'')",
                (salt, hashlib.sha256((salt + login).encode()).hexdigest(), len(login)))
        out, error = self.tool("vps", "close_case", request_id=str(uuid.uuid4()), case=hub.cref(self.case(
            t["duty_case"])), outcome="handled", note="Retired the signed-out account", task_id=hub.tref(t["id"]),
            learned="Retire a signed-out account before the next run.")
        self.assertFalse(error, out)
        out, error = self.deliver(t, learned="Check the pool count first.", prevents="The same outage again")
        self.assertFalse(error, out)
        self.assertEqual([m["about"] for m in hub.q("SELECT about FROM memories ORDER BY id")], [head, head])

    def test_a_lesson_from_the_work_takes_its_topic_or_else_the_duty_name(self):
        """A task's title is rarely said again, so a lesson tagged with it never matched a later task by its tag."""
        self.fire(self.rule)
        t = self.first_case_task()
        self.close(t)
        out, error = self.deliver(t, learned="Check the signed-in pool count before reading any logs.",
                                  prevents="Twenty minutes lost in the logs", about="the account   pool",
                                  tried="Reading the worker logs first: they say nothing about the pool.")
        self.assertFalse(error, out)
        self.assertEqual([m["about"] for m in hub.q("SELECT about FROM memories ORDER BY id")],
                         ["the account pool", "the account pool"])
        tool = next(x for x in hub.tools_for("vps") if x["name"] == "deliver_result")
        self.assertIn("A later task that names it starts with this lesson", tool["inputSchema"]["properties"]["about"]
                      ["description"])
        # without one, a duty's task tags it with the duty's name, which its next task names again
        hub.q("UPDATE duty_cases SET state='closed', closed=? WHERE state='open'", (self.clock,))
        hub.q("UPDATE tasks SET state='completed', outcome='completed', delivered=? WHERE state NOT IN "
              "('completed','failed','rejected','canceled')", (self.clock,))
        self.fire(self.rule, when=self.clock + 7200)
        t2 = self.first_case_task()
        self.close(t2)
        self.assertFalse(self.deliver(t2, learned="Retire the signed-out account first.",
                                      prevents="The same outage again")[1])
        self.assertEqual(hub.q1("SELECT about FROM memories ORDER BY id DESC")["about"],
                         hub.duty_name(self.r["text"])[:hub.MEMORY_ABOUT])
        # and a tag that is no short tag is refused before anything is delivered
        self.assertIn("about must be one short tag", self.deliver(t2, learned="x", prevents="y", about="x" * 61)[0])

    def test_a_case_closes_with_a_lesson_on_its_own_topic(self):
        self.fire(self.rule)
        t = self.first_case_task()
        rid = str(uuid.uuid4())
        text, error = self.tool("vps", "close_case", request_id=rid, case=hub.cref(self.case(
            t["duty_case"])), outcome="handled", note="Retired the signed-out account",
            learned="The pool needs one signed-in account per worker.", about="the account pool",
            task_id=hub.tref(t["id"]))
        self.assertFalse(error, text)
        m = hub.q1("SELECT * FROM memories ORDER BY id DESC")
        self.assertEqual((m["about"], m["prevents_key"]), ("the account pool", "check/1"))
        # the tag is part of the close: the same request with another tag is another call
        again, error = self.tool("vps", "close_case", request_id=rid, case=hub.cref(self.case(t["duty_case"])),
                                 outcome="handled", note="Retired the signed-out account",
                                 learned="The pool needs one signed-in account per worker.", about="the pool",
                                 task_id=hub.tref(t["id"]))
        self.assertTrue(error, again)
        self.assertIn("already used for another call", again)

    def test_a_rewritten_lesson_keeps_the_claim_so_the_work_can_judge_it_too(self):
        """The hole the memory session found, and worse than it looked: remember had no way to carry a key, so
        every lesson written after a contradiction was unfalsifiable — the one moment the loop had learned
        something produced a lesson nothing could ever check, which then expired as stale."""
        self.fire(self.rule)
        t = self.first_case_task()
        self.close(t)
        self.deliver(t, learned="Check the pool first.", prevents="Twenty minutes in the logs")
        show(1, task=t["id"], when=self.clock + 3600)
        self.fire(self.rule, when=self.clock + 7200)
        self.assertEqual(hub.q1("SELECT contradicted FROM memories WHERE id=1")["contradicted"], 1)
        t2 = self.first_case_task()
        out, error = self.tool("vps", "remember", request_id=str(uuid.uuid4()), task_id=hub.tref(t2["id"]),
                               instead_of="M-1", about="the pool",
                               text="Checking the pool is not enough: retire the signed-out account.",
                               prevents="The same outage again after a check that looked fine")
        self.assertFalse(error, out)
        self.assertIn("It takes over what M-1 claimed", out)
        self.assertIn("M-1 is removed, naming this one", out)
        old, new = hub.q1("SELECT * FROM memories WHERE id=1"), hub.q1("SELECT * FROM memories WHERE id=2")
        self.assertEqual((new["responsibility"], new["prevents_key"]), (self.r["id"], "check/1"))
        self.assertEqual(new["contradicted"], 0)                 # a fresh claim, judged on its own
        self.assertEqual((bool(old["dropped"]), old["drop_reason"]), (True, "written again as M-2"))
        self.assertEqual(old["contradicted"], 1)                 # and the old count stays, as history
        # The work judges the new one the same way, and only the new one, once a start has shown it.
        show(2, task=t2["id"], when=self.clock + 10800)
        hub.q("UPDATE duty_cases SET state='closed', closed=? WHERE state='open'", (self.clock,))
        hub.q("UPDATE tasks SET state='completed', outcome='completed', delivered=? WHERE state NOT IN "
              "('completed','failed','rejected','canceled')", (self.clock,))
        self.fire(self.rule, when=self.clock + 14400)
        self.assertEqual(hub.q1("SELECT contradicted FROM memories WHERE id=2")["contradicted"], 1)
        self.assertEqual(hub.q1("SELECT contradicted FROM memories WHERE id=1")["contradicted"], 1)

    def test_a_rewrite_of_a_keyless_lesson_is_still_keyless_and_says_so(self):
        text, error = self.tool("vps", "remember", request_id=str(uuid.uuid4()), about="reports",
                                text="The export wants ISO dates.", prevents="A report nobody can sort",
                                task_id=hub.tref(self.only_task()))
        self.assertFalse(error, text)
        out, error = self.tool("vps", "remember", request_id=str(uuid.uuid4()), instead_of="M-1", about="reports",
                               text="The export wants ISO dates, and the header row needs them too.",
                               prevents="A report nobody can sort", task_id=hub.tref(self.only_task()))
        self.assertFalse(error, out)
        self.assertIn("Nothing can contradict this one", out)
        self.assertIn("M-1 is removed, naming this one", out)
        self.assertIsNone(hub.q1("SELECT prevents_key FROM memories WHERE id=2")["prevents_key"])
        # A lesson already removed cannot be rewritten: write it on its own.
        out, error = self.tool("vps", "remember", request_id=str(uuid.uuid4()), instead_of="M-1", about="reports",
                               text="Something else.", prevents="x", task_id=hub.tref(self.only_task()))
        self.assertTrue(error)
        self.assertIn("already removed", out)

    def test_what_did_not_work_is_kept_beside_the_lesson_and_takes_no_key(self):
        """The expensive half: what did not work. A worker spends three hours finding a wall, and four months
        later another one spends three hours on the same wall. learned records what worked and nothing recorded
        this, so one delivery carries both — and what did not work takes no key, because it is not a claim about
        an event coming back. Since AUTONOMY.md P7 it is an ordinary lesson, with how to check it again in its
        own words."""
        self.fire(self.rule)
        t = self.first_case_task()
        self.close(t)
        out, error = self.deliver(
            t, learned="Check the pool before the logs.", prevents="Twenty minutes in the logs",
            tried="A Stripe test key cannot refund a live charge: the API answers 400 and the dashboard is silent. "
                  "To check: stripe refunds create --charge ch_live_x with the test key; a 400 means it stands.")
        self.assertFalse(error, out)
        self.assertIn("M-1 keeps what you learned", out)
        self.assertIn("M-2 keeps what did not work, so that nobody need pay for it again", out)
        self.assertIn("You are done with it: stop now and end your turn; your session closes when it ends.", out)
        lesson, dead = hub.q1("SELECT * FROM memories WHERE id=1"), hub.q1("SELECT * FROM memories WHERE id=2")
        self.assertEqual((lesson["kind"], lesson["prevents_key"]), ("lesson", "check/1"))
        # Even on a duty's case task, what did not work carries neither duty nor key.
        self.assertEqual((dead["kind"], dead["responsibility"], dead["prevents_key"]), ("lesson", None, None))
        self.assertEqual((dead["cost_minutes"], dead["recheck"], dead["by_task"]), (None, None, t["id"]))
        self.assertTrue(dead["text"].startswith(hub.MEMORY_TRIED + "A Stripe test key"), dead["text"])
        self.assertIn("stripe refunds create", dead["text"])
        self.assertEqual(dead["prevents"], hub.DEAD_END_PREVENTS)      # filled in, so the agent writes one field
        # how to check it again is asked for where the agent writes it
        tool = next(x for x in hub.tools_for("vps") if x["name"] == "deliver_result")
        self.assertIn("how to check cheaply whether it still stands", tool["inputSchema"]["properties"]["tried"]
                      ["description"])
        self.assertTrue({"cost_minutes", "recheck"}.isdisjoint(tool["inputSchema"]["properties"]))
        # Nothing can contradict it: the key comes back after a start showed both, and only the lesson is marked.
        show(1, 2, task=t["id"], when=self.clock + 3600)
        self.fire(self.rule, when=self.clock + 7200)
        self.assertEqual(hub.q1("SELECT contradicted FROM memories WHERE id=1")["contradicted"], 1)
        self.assertEqual(hub.q1("SELECT contradicted FROM memories WHERE id=2")["contradicted"], 0)

    def test_the_fields_of_an_earlier_round_are_refused_and_deliver_nothing(self):
        self.fire(self.rule)
        t = self.first_case_task()
        out, error = self.deliver(t, cost_minutes=180)
        self.assertTrue(error)
        self.assertIn("deliver_result does not take cost_minutes", out)
        out, error = self.deliver(t, recheck="run it again")
        self.assertTrue(error)
        self.assertIn("deliver_result does not take recheck", out)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM memories")["n"], 0)
        # And a delivery that says neither is untouched: the stop stays the whole answer.
        out, error = self.deliver(t)
        self.assertEqual(out, f"Delivered. {hub.tref(t['id'])} is completed. You are done with it: stop now and end "
                              f"your turn; your session closes when it ends.")

    def test_close_case_keeps_a_dead_end_too_and_records_it_on_the_duty(self):
        self.fire(self.rule)
        t = self.first_case_task()
        hub.q("UPDATE tasks SET state='completed', delivered=? WHERE id=?", (self.clock, t["id"]))
        c = self.case(t["duty_case"])
        out, error = self.tool("manager", "close_case", request_id=str(uuid.uuid4()), case=hub.cref(c),
                               outcome="handled", note="vps retired the account",
                               tried="The vendor's status page lies during an incident; it was green throughout.")
        self.assertFalse(error, out)
        self.assertIn("keeps what did not work, so that nobody need pay for it again", out)
        dead = hub.q1("SELECT * FROM memories ORDER BY id DESC LIMIT 1")
        self.assertEqual((dead["agent"], dead["kind"], dead["prevents_key"]), ("manager", "lesson", None))
        self.assertTrue(dead["text"].startswith(hub.MEMORY_TRIED), dead["text"])
        self.assertIn("a dead end:", [h["detail"] for h in
                                      hub.q("SELECT detail FROM duty_history WHERE kind='learned'")][0])

    def test_the_hub_asks_for_a_dead_end_when_the_work_was_hard_and_nothing_was_kept(self):
        hub.q("INSERT INTO tasks(id,title,owner,requester,state,created,done_when,attempt) "
              "VALUES(70,'Try again','vps','manager','working',?,'it works',2)", (self.clock,))
        out, error = self.deliver(hub.q1("SELECT * FROM tasks WHERE id=70"))
        self.assertFalse(error, out)
        self.assertIn("if you found a wall instead, say that in tried, with how to check it again", out)

    def test_a_lesson_from_an_ordinary_task_can_never_be_contradicted_and_says_so(self):
        text, error = self.tool("manager", "create_task", owner="vps", title="Write the October report",
                                done_when="outputs/report.md is pushed", why="vps writes the text work")
        self.assertFalse(error, text)
        t = hub.q1("SELECT * FROM tasks ORDER BY id DESC LIMIT 1")
        out, error = self.deliver(t, learned="The export needs the date in ISO, not the local format.",
                                  prevents="A report nobody can sort by date")
        self.assertFalse(error, out)
        self.assertIn("Nothing can contradict it, because this was not a duty's case: only your own work can show it "
                      "wrong.", out)
        m = hub.q1("SELECT * FROM memories ORDER BY id DESC LIMIT 1")
        self.assertEqual((m["responsibility"], m["prevents_key"]), (None, None))
        self.assertIn("Nothing can contradict this one", "\n".join(hub.memory_block(m)))

    def test_a_lesson_needs_to_say_what_it_prevents(self):
        self.fire(self.rule)
        t = self.first_case_task()
        out, error = self.deliver(t, learned="Something happened.")
        self.assertTrue(error)
        self.assertIn("say in prevents what you expect it to change in later work", out)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM memories")["n"], 0)

    def test_the_hub_asks_again_only_when_its_own_rows_say_the_work_was_hard(self):
        """Four signals, none of them new: a second attempt, a restart, or a task that follows one the manager
        refused or that failed. The refusal is the one no counter catches."""
        self.fire(self.rule)
        t = self.first_case_task()
        # Ordinary work that taught nothing: the answer stays what it was, and the stop is not diluted.
        out, error = self.deliver(t)
        self.assertFalse(error, out)
        self.assertEqual(out, f"Delivered. {hub.tref(t['id'])} is completed. You are done with it: stop now and end "
                              f"your turn; your session closes when it ends.")
        for n, (fields, expect) in enumerate((
                ({"attempt": 2}, "this was attempt 2"),
                ({"restarts": 1}, "this task was restarted"),
                ({"follows": 1}, "which was not accepted: The report had no dates"),
                ({"follows": 2}, "which failed"))):
            hub.q("INSERT INTO tasks(id,title,owner,requester,state,created,done_when) "
                  "VALUES(?,?,'vps','manager','working',?,?)", (50 + n, f"Try {n}", self.clock, "it works"))
            row = hub.q1("SELECT * FROM tasks WHERE id=?", (50 + n,))
            for key, value in fields.items():
                hub.q(f"UPDATE tasks SET {key}=? WHERE id=?", (value, 50 + n))
            out, error = self.deliver(hub.q1("SELECT * FROM tasks WHERE id=?", (50 + n,)))
            self.assertFalse(error, out)
            self.assertIn("You recorded nothing learned and ", out)
            self.assertIn(expect, out)
            self.assertIn("You are done with it: stop now and end your turn; your session closes when it ends.", out)
            if n == 0:      # set up the two tasks that the follows cases point at
                hub.q("UPDATE tasks SET accepted=0, check_note='The report had no dates' WHERE id=1")
                hub.q("UPDATE tasks SET outcome='failed' WHERE id=2")
                hub.q("INSERT INTO tasks(id,title,owner,requester,state,outcome,created,done_when) "
                      "VALUES(2,'Earlier','vps','manager','failed','failed',?,'x')", (self.clock,))
        # A hard task that DID record a lesson is not nagged for one.
        hub.q("INSERT INTO tasks(id,title,owner,requester,state,created,done_when,attempt) "
              "VALUES(60,'Try again','vps','manager','working',?,'it works',3)", (self.clock,))
        out, error = self.deliver(hub.q1("SELECT * FROM tasks WHERE id=60"),
                                  learned="The second attempt only worked after the cache was cleared.",
                                  prevents="A third attempt that fails the same way")
        self.assertFalse(error, out)
        self.assertNotIn("You recorded nothing learned", out)

    def test_close_case_takes_a_lesson_too_for_whoever_closes_it(self):
        """A worker cannot close its own case while its task is open, so close_case is the manager's path and the
        path of a case whose tasks have all ended. It carries the key the same way."""
        self.fire(self.rule)
        t = self.first_case_task()
        hub.q("UPDATE tasks SET state='completed', delivered=? WHERE id=?", (self.clock, t["id"]))
        c = self.case(t["duty_case"])
        out, error = self.tool("manager", "close_case", request_id=str(uuid.uuid4()), case=hub.cref(c),
                               outcome="handled", note="vps retired the account",
                               learned="A signed-out pool account looks like a code bug in the logs.")
        self.assertFalse(error, out)
        self.assertIn("keeps what you learned", out)
        m = hub.q1("SELECT * FROM memories ORDER BY id DESC LIMIT 1")
        self.assertEqual((m["agent"], m["responsibility"], m["prevents_key"]), ("manager", self.r["id"], "check/1"))
        self.assertEqual([h["kind"] for h in hub.q("SELECT kind FROM duty_history WHERE kind='learned'")],
                         ["learned"])
        # And a case closed with nothing learned writes no memory.
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM memories")["n"], 1)

    def test_the_review_is_what_prunes_the_lessons(self):
        self.sweep()
        review = self.review_task()
        self.assertIn("contradicted=true for every one that the work contradicted", review["details"])     # one call
        self.assertIn("A CONTRADICTED one claimed to stop a case key", review["details"])
        self.assertIn('remember instead_of="M-<id>"', review["details"])     # a rewrite keeps the claim
        self.assertIn("which hands the new lesson the same claim", review["details"])
        self.assertNotIn("for a while", review["details"])                   # no clock (decision 39)
        self.assertIn("nothing has refuted it, not that it was right", review["details"])
        self.assertIn("without their words", review["details"])              # a memory is its own agent's
        self.assertNotIn("held=", review["details"])                         # the fields of an earlier round
        self.assertNotIn("covers=", review["details"])
        self.assertIn("every lesson listed below has been written again or removed", review["done_when"])


class Limits(Base):
    def test_the_fleet_email_limit_is_a_setting_that_never_stops_a_duty(self):
        """The 20-a-day guard was Fleet's own, not Google's; a duty that writes to every customer of one event must
        not stop at it (owner direction, 16 October 2026)."""
        self.assertEqual(hub.gmail_send_limit(), 0)                 # none unless the owner writes one (26 October)
        hub.TEAM["google"] = {"max_send_per_day": 0}
        self.assertEqual(hub.gmail_send_limit(), 0)                 # 0: no limit at all
        hub.TEAM["google"] = {"max_send_per_day": 50}
        self.assertEqual(hub.gmail_send_limit(), 50)
        team = json.loads(json.dumps(TEAM))
        team["google"] = {"max_send_per_day": 50}
        hub.validate_team(team)
        for bad in ({"max_send_per_day": -1}, {"max_send_per_day": "many"}, {"max_send_per_day": True},
                    {"other": 1}, 20):
            team["google"] = bad
            with self.assertRaises(ValueError):
                hub.validate_team(team)


class Sweep(Base):
    def test_a_marker_is_set_once_and_the_manager_hears_it_once(self):
        """A duty with no watch is the plainest thing that is not in order: nothing can find its events. There is no
        reaction time to be late for (owner direction, 19 October 2026)."""
        r = self.duty()
        self.sweep()
        self.assertIsNone(hub.duty_row(r["id"])["marker_kind"])
        said = len(self.manager_said())
        self.change(r["id"], watch=[])
        self.sweep(self.clock + 16 * 60)
        row = hub.duty_row(r["id"])
        self.assertEqual(row["marker_kind"], "no_watch")
        self.assertIn("no event reaches its agent", row["marker_detail"])
        self.assertEqual(len(self.manager_said()), said + 1)
        self.assertIn("These duties are not in order", self.manager_said()[-1])
        self.sweep(self.clock + 60)                 # the same set of markers: no second message
        self.assertEqual(len(self.manager_said()), said + 1)
        # A watch again, and the duty is in order.
        self.change(r["id"], watch=[CLOCK_WATCH])
        self.sweep(self.clock + 16 * 60)
        self.assertIsNone(hub.duty_row(r["id"])["marker_kind"])

    def test_a_key_that_comes_back_inside_30_days_is_a_repeat(self):
        r = self.duty(watch=[{"kind": "check", "check": CHECK}])
        with hub.transaction():
            first = hub.duty_new_case(r, "pool/signed-out", "The pool is signed out", "test", "hub", self.clock)
        hub.q("UPDATE duty_cases SET state='closed', closed=?, outcome='handled' WHERE id=?", (self.clock, first))
        with hub.transaction():
            second = hub.duty_new_case(r, "pool/signed-out", "The pool is signed out again", "test", "hub",
                                       self.clock + 86400)
        self.assertEqual(self.case(second)["repeated"], 1)
        self.sweep(self.clock + 86400)
        row = hub.duty_row(r["id"])
        self.assertEqual(row["marker_kind"], "repeat")
        self.assertIn("the preventive action did not work", row["marker_detail"])

    def test_a_duty_without_a_watch_and_a_paused_watch_are_marked(self):
        r = self.duty(watch=[])
        self.sweep()
        self.assertEqual(hub.duty_row(r["id"])["marker_kind"], "no_watch")
        self.change(r["id"], watch=[CLOCK_WATCH])
        self.sweep()
        self.assertIsNone(hub.duty_row(r["id"])["marker_kind"])
        rule = self.watches(r["id"])[0]
        with hub.LOCK, hub.transaction():
            hub.pause_trigger(rule["id"], "hub", "The check failed 5 times in a row.", self.clock)
        self.sweep()
        row = hub.duty_row(r["id"])
        self.assertEqual(row["marker_kind"], "watch_broken")
        self.assertIn("The check failed 5 times", row["marker_detail"])

    def test_words_that_name_a_renamed_agent_are_news_once_and_said_until_they_are_written_again(self):
        """3 November 2026: ten agents took new names. A rename moves every record of an agent and leaves words as
        they were written, so a duty that gave each fix to an agent by its old name named an agent that was gone. It is
        news for its holder's review once, as a lesson is, and no mark: a mark in front of a repeat starts a second
        review when it goes."""
        r = self.duty(text="Fix the shop's packages. Give each fix to Studio, and keep the checks of fleet-studio.")
        self.sweep()
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (self.review_task()["id"],))
        reviews = self.reviews()
        hub.TEAM["agents"]["kai"] = hub.TEAM["agents"].pop("studio")
        hub.q("INSERT INTO server_jobs(server,kind,agent,runtime,state,created,updated,was) "
              "VALUES('mac-studio','rename','kai','claude','done',?,?,'studio')", (self.clock, self.clock))
        self.sweep(self.clock + 60)
        self.assertIsNone(hub.duty_row(r["id"])["marker_kind"])
        self.assertEqual(self.reviews(), reviews + 1)
        self.assertIn("its words name studio, which is kai now. Write them again with set_duty",
                      self.review_task()["details"])
        seen, error = self.tool("vps", "see_responsibilities", task_id=hub.tref(self.review_task()["id"]))
        self.assertFalse(error, seen)
        self.assertIn("Its words name studio, which is kai now", seen)
        # Listed once: a review that ends with the words as they were starts no second one for the same name.
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (self.review_task()["id"],))
        self.sweep(self.clock + 120)
        self.assertEqual(self.reviews(), reviews + 1)
        # Words with the names the agents have now say nothing more; the OS user's path was never the agent.
        self.change(r["id"], text="Fix the shop's packages. Give each fix to kai, and keep the checks of fleet-studio.")
        self.assertEqual(hub.duty_old_names(hub.duty_row(r["id"])["text"]), [])
        self.assertNotIn("Its words name", "\n".join(hub.duty_text(hub.duty_row(r["id"]), self.clock)))

    def test_the_sweep_wakes_nobody_when_every_duty_is_in_order(self):
        self.duty()
        self.sweep()                                # the new duty is news: its review, once
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (self.review_task()["id"],))
        before = self.woken()
        self.sweep(self.clock + 3600)
        self.assertEqual(self.woken(), before)
        self.assertIsNone(hub.kv_get("duty_sweep_sig"))



class Reviews(Base):
    """Plan C13: a holder's duties are reviewed when they have news, not once a day."""

    def finish(self, agent="vps"):
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (self.review_task(agent)["id"],))

    def test_with_no_news_nothing_starts_for_a_week(self):
        self.duty()
        self.sweep()
        self.assertEqual(self.reviews(), 1)                  # the new duty, at once
        self.finish()
        for _ in range(7 * 24):
            self.sweep(self.clock + 3600)
        self.assertEqual(self.reviews(), 1)
        self.assertIsNone(hub.q1("SELECT id FROM triggers WHERE watch='review'"))

    def test_a_mark_after_a_review_starts_one_and_a_second_waits_while_it_is_open(self):
        first = self.duty()
        second = self.duty(text="Keep the shop's order queue moving. When an order sticks, fix it yourself.")
        self.sweep()
        self.finish()
        self.change(first["id"], watch=[])                  # a change of watches is no news by itself
        self.sweep(self.clock + 60)                         # but the mark it leaves is
        self.assertEqual(self.reviews(), 2)
        self.assertIn("R-1 Keep customer content generation working: no watch.", self.review_task()["details"])
        self.change(second["id"], watch=[])
        self.sweep(self.clock + 60)
        self.assertEqual(self.reviews(), 2)                 # the review is open: the new mark waits for it
        self.finish()
        self.sweep(self.clock + 60)
        self.assertEqual(self.reviews(), 3)
        news = self.review_task()["details"].split("news since your last one:")[1]
        self.assertIn("R-2 Keep the shop's order queue moving: no watch.", news)
        self.assertNotIn("R-1", news)                       # set when the last review started: no news again

    def test_a_watch_that_breaks_and_recovers_again_and_again_starts_one_review(self):
        r = self.duty()
        self.sweep()
        self.finish()
        rule = self.watches(r["id"])[0]

        def breaks():
            with hub.LOCK, hub.transaction():
                hub.pause_trigger(rule["id"], "hub", "The check failed.", self.clock)
            self.sweep(self.clock + 60)

        def recovers():
            revision = hub.trigger_row(rule["id"])["revision"]         # a read that commits: before the transaction
            with hub.LOCK, hub.transaction():
                hub.trigger_state_rows(rule["id"], revision, "resume", "manager", self.clock)
            self.sweep(self.clock + 60)
            self.assertIsNone(hub.duty_row(r["id"])["marker_kind"])

        breaks()
        self.assertEqual(self.reviews(), 2)
        self.assertIn("watch broken", self.review_task()["details"])
        self.finish()
        for _ in range(3):
            recovers()
            breaks()
        self.assertEqual(self.reviews(), 2)

    def test_words_that_its_holder_wrote_are_no_news_to_it(self):
        with hub.LOCK:
            hub.duty_save(hub.duty_fields(dict(DUTY), True), "vps", hub.now())
        self.sweep()
        self.assertIsNone(self.review_task())

    def test_the_manager_reads_its_review_as_a_message_and_it_is_open_until_read(self):
        with hub.LOCK:
            hub.duty_save(hub.duty_fields(dict(DUTY, agent="manager"), True), "owner", hub.now())
        self.sweep()

        def reviews():
            return [t for t in self.manager_said() if t.startswith("[hub] Your duties have news")]
        self.assertEqual(len(reviews()), 1)
        self.assertIn("R-1 Keep customer content generation working: new, from owner.", reviews()[0])
        self.assertIsNone(hub.q1("SELECT id FROM tasks"))
        with hub.LOCK:
            hub.duty_save(hub.duty_fields(dict(DUTY, agent="manager", text="Look after the shop. Fix what breaks."),
                                          True), "owner", hub.now() + 30)
        self.sweep(self.clock + 60)
        self.assertEqual(len(reviews()), 1)                 # unread: the review is still open
        hub.q("UPDATE events SET read_at=? WHERE agent='manager'", (self.clock,))
        self.sweep(self.clock + 60)
        self.assertEqual(len(reviews()), 2)
        self.assertIn("R-2 Look after the shop: new, from owner.", reviews()[1])
        self.assertNotIn("R-1", reviews()[1])

    def test_a_review_through_a_lead_is_a_subtask_of_the_lead_s_own_task(self):
        hub.TEAM["agents"]["lead"] = {"role": "lead", "runtime": "claude", "machine": "vps", "can": ["shell"]}
        hub.TEAM["agents"]["vps"]["reports_to"] = "lead"
        self.duty()
        self.sweep()
        review = self.review_task()
        parent = hub.q1("SELECT * FROM tasks WHERE id=?", (review["parent"],))
        self.assertEqual((review["requester"], parent["owner"], parent["requester"], parent["title"]),
                         ("lead", "lead", "manager", "Your team's wake-up and case results"))   # plan P9.11

    def test_the_daily_review_rule_of_an_earlier_version_is_deleted(self):
        r = self.duty()
        old = self.watches(r["id"])[0]
        hub.q("UPDATE triggers SET watch='review', responsibility=NULL WHERE id=?", (old["id"],))
        self.sweep()
        self.assertEqual(hub.trigger_row(old["id"])["state"], "deleted")


class Edits(Base):
    """Two sessions change one duty (the owner, 8 November 2026: "Fix duty edits"). A change replaces each field that
    it gives, so a change over a revision that the session never read would lose a parallel session's words, as a
    whole write of an agent's notes did on 3 November 2026."""

    def setUp(self):
        super().setUp()
        self.r = self.duty()            # vps's own duty, which its sessions may change (plan C17)
        sessions = []
        for title in ("Look after the content queue", "Tidy the content duty"):
            f = hub.check_task("manager", {"owner": "vps", "title": title, "done_when": "It is in order."})
            with hub.LOCK, hub.transaction():
                sessions.append(hub.admit_task("manager", f))
        self.mine, self.theirs = sessions

    def edit(self, task, **fields):
        return self.tool("vps", "set_duty", request_id=str(uuid.uuid4()), task_id=hub.tref(task),
                         responsibility=hub.rref(self.r["id"]), **fields)

    def read(self, task, **more):
        text, error = self.tool("vps", "see_responsibilities", task_id=hub.tref(task), **more)
        self.assertFalse(error, text)
        return text

    def test_a_change_over_a_revision_that_the_session_never_read_writes_nothing_and_shows_the_duty(self):
        self.read(self.mine)
        self.read(self.theirs)
        text, error = self.edit(self.theirs, text="Keep content generation working, and the image queue too.")
        self.assertFalse(error, text)
        self.assertIn("revision 2", text)
        self.clock += 60
        text, error = self.edit(self.mine, text="Keep content generation working. Ask me first about a refund.")
        self.assertTrue(error, text)
        self.assertIn("R-1 changed after this session read revision 1 of it: it is revision 2 now, after these "
                      "changes: ", text)
        self.assertIn(" vps: edited (text). Nothing was written", text)
        self.assertIn("Duty: Keep content generation working, and the image queue too.", text)    # to merge into
        self.assertEqual(hub.duty_row(1)["revision"], 2)
        text, error = self.edit(self.mine, text="Keep content generation working, and the image queue too. Ask me "
                                                "first about a refund.")
        self.assertFalse(error, text)                       # the refusal showed it: read
        self.assertIn("revision 3", text)
        self.assertFalse(self.edit(self.mine, text="Keep content and images working. Ask me about refunds.")[1])
        text, error = self.edit(self.theirs, text="Keep content generation working.")     # its own write: read
        self.assertTrue(error, text)                        # and the other session has not read this one
        self.assertIn("changed after this session read revision 2 of it: it is revision 4 now", text)
        self.assertEqual(hub.duty_row(1)["text"], "Keep content and images working. Ask me about refunds.")

    def test_a_session_that_has_not_read_the_duty_is_shown_it_once(self):
        text, error = self.edit(self.mine, text="Keep content generation working.")
        self.assertTrue(error, text)
        self.assertIn("This session has not read R-1 in full yet. Nothing was written", text)
        self.assertIn("Duty: " + DUTY["text"], text)
        self.assertIn("Watch 1 (clock) [active], every 10 minutes", text)
        self.assertEqual(hub.duty_row(1)["revision"], 1)
        self.assertFalse(self.edit(self.mine, text="Keep content generation working.")[1])

    def test_a_refused_change_is_refused_again_for_the_same_request_id(self):
        """mcp.py gives up on an answer after 20 seconds while the hub is busy, and RULES.md asks for the same
        request_id again: that repeat found the duty read, and wrote the stale words that the refusal had said were
        not written."""
        self.read(self.mine)
        self.read(self.theirs)
        self.assertFalse(self.edit(self.theirs, text="Theirs.")[1])
        args = dict(request_id=str(uuid.uuid4()), task_id=hub.tref(self.mine), responsibility="R-1",
                    text="Mine, from revision 1.")
        first = self.tool("vps", "set_duty", **args)
        self.assertTrue(first[1], first[0])
        self.assertEqual(self.tool("vps", "set_duty", **args), first)
        self.assertEqual((hub.duty_row(1)["text"], hub.duty_row(1)["revision"]), ("Theirs.", 2))
        text, error = self.tool("vps", "set_duty", **dict(args, text="Theirs. Mine."))
        self.assertTrue(error, text)
        self.assertIn("already used for another call", text)
        self.assertFalse(self.tool("vps", "set_duty", **dict(args, request_id=str(uuid.uuid4()),
                                                              text="Theirs. Mine."))[1])
        self.assertEqual(hub.duty_row(1)["text"], "Theirs. Mine.")

    def test_the_words_of_a_duty_shown_whole_are_a_read_and_a_line_that_names_it_is_not(self):
        self.read(self.theirs, search="content")            # names only
        self.assertIn("has not read R-1 in full yet", self.edit(self.theirs, text="One.")[0])
        self.read(self.mine, responsibility="R-1")          # one duty in full
        self.assertFalse(self.edit(self.mine, text="Two.")[1])
        self.read(self.theirs)                              # the duties that run now, each with its words
        self.assertFalse(self.edit(self.theirs, text="Three.")[1])
        self.assertEqual(hub.duty_row(1)["text"], "Three.")

    def test_the_read_and_the_refusal_show_every_field_that_a_change_replaces(self):
        self.read(self.mine)
        self.read(self.theirs)
        self.assertFalse(self.edit(self.theirs, tools=["remember"])[1])
        text, error = self.edit(self.mine, tools=["write_notes"])
        self.assertTrue(error, text)
        self.assertIn(" vps: edited (tools)", text)
        self.assertIn("The sessions of its cases: tools remember.", text)
        self.assertIn("The sessions of its cases: tools remember.", self.read(self.mine))

    def test_a_read_shows_the_watch_list_as_set_duty_takes_it_and_sent_back_it_changes_nothing(self):
        """A watch list gives each rule whole, its check's commit and sha256 and its title among them, so a read shows
        each value: a session that read the duty and sent an older check back would put the old version back."""
        check = dict(CHECK, commit="c" * 40, sha256="d" * 64)
        self.read(self.theirs)
        kept = [{"kind": "clock", "trigger": 1, "schedule": CLOCK_WATCH["schedule"]}]
        self.assertFalse(self.edit(self.theirs, watch=kept + [{"kind": "check", "check": check,
                                                               "title": "Pool count"}])[1])
        text = self.read(self.mine)
        line = next(x for x in text.splitlines() if "Its watch list as set_duty takes it" in x)
        shown = json.loads(line[line.index("["):])
        self.assertEqual([(w["trigger"], w["title"]) for w in shown][1], (2, "Pool count"))
        self.assertEqual((shown[1]["check"]["commit"], shown[1]["check"]["sha256"]), ("c" * 40, "d" * 64))
        text, error = self.edit(self.mine, watch=shown + [{"kind": "clock", "schedule": {"kind": "every",
                                                                                          "minutes": 60}}])
        self.assertFalse(error, text)
        rule = hub.trigger_row(2)
        self.assertEqual((json.loads(rule["check_spec"])["commit"], json.loads(rule["task"])["title"]),
                         ("c" * 40, "Pool count"))
        self.assertEqual(len(hub.duty_watches(1, managed=True)), 3)

    def test_a_repeat_of_a_change_that_went_through_is_not_refused(self):
        self.read(self.mine)
        args = dict(request_id=str(uuid.uuid4()), task_id=hub.tref(self.mine), responsibility="R-1", text="Mine.")
        first, error = self.tool("vps", "set_duty", **args)
        self.assertFalse(error, first)
        self.read(self.theirs)
        self.assertFalse(self.edit(self.theirs, text="Theirs.")[1])
        again, error = self.tool("vps", "set_duty", **args)
        self.assertEqual((again, error), ("R-1 saved.", False))        # the receipt that duty_save kept
        self.assertEqual((hub.duty_row(1)["text"], hub.duty_row(1)["revision"]), ("Theirs.", 3))

    def test_its_own_state_action_keeps_its_read_and_somebody_else_s_does_not(self):
        self.read(self.mine)
        text, error = self.tool("vps", "change_duty", request_id=str(uuid.uuid4()), task_id=hub.tref(self.mine),
                                responsibility="R-1", action="pause")
        self.assertFalse(error, text)
        self.assertFalse(self.edit(self.mine, text="Keep content generation working when it runs again.")[1])
        code, data = self.state(1, hub.duty_row(1)["revision"], "resume")         # the owner's resume
        self.assertEqual(code, 200, data)
        text, error = self.edit(self.mine, text="Keep content generation working.")
        self.assertTrue(error, text)
        self.assertIn(" owner: resume. Nothing was written", text)
        self.assertIn("R-1 [active]", text)

    def test_its_own_state_action_over_a_change_it_never_read_leaves_that_change_unread(self):
        self.read(self.mine)
        self.read(self.theirs)
        self.assertFalse(self.edit(self.theirs, text="Theirs.")[1])          # revision 2, which mine never read
        text, error = self.tool("vps", "change_duty", request_id=str(uuid.uuid4()), task_id=hub.tref(self.mine),
                                responsibility="R-1", action="pause")       # revision 3
        self.assertFalse(error, text)
        text, error = self.edit(self.mine, text="Mine.")
        self.assertTrue(error, text)
        self.assertIn("read revision 1 of it: it is revision 3 now, after these changes: ", text)
        self.assertIn(" vps: edited (text); ", text)
        self.assertIn(" vps: pause. Nothing was written", text)
        self.assertEqual(hub.duty_row(1)["text"], "Theirs.")
        text, error = self.tool("vps", "change_duty", request_id=str(uuid.uuid4()), task_id=hub.tref(self.theirs),
                                responsibility="R-1", action="resume")      # theirs read revision 2, not 3
        self.assertFalse(error, text)
        self.assertIn("R-1 changed after this session read revision 2", self.edit(self.theirs, text="Again.")[0])

    def test_a_state_action_is_no_read_and_a_duty_that_the_session_wrote_is_read(self):
        text, error = self.tool("vps", "change_duty", request_id=str(uuid.uuid4()), task_id=hub.tref(self.mine),
                                responsibility="R-1", action="pause")       # it never read R-1
        self.assertFalse(error, text)
        self.assertIn("has not read R-1 in full yet", self.edit(self.mine, text="Mine.")[0])
        text, error = self.tool("vps", "set_duty", request_id=str(uuid.uuid4()), task_id=hub.tref(self.theirs),
                                agent="vps", text="Keep the image queue moving.")
        self.assertFalse(error, text)
        self.assertFalse(self.tool("vps", "set_duty", request_id=str(uuid.uuid4()), task_id=hub.tref(self.theirs),
                                   responsibility="R-2", text="Keep the image queue moving, oldest first.")[1])

    def test_a_watch_rule_changed_by_another_route_holds_a_change_that_gives_the_watch_list(self):
        """save_trigger and the owner's trigger controls change a rule of a duty's watch list with no new revision of
        the duty, and a watch list gives each rule whole: it put the rule back as the session had read it."""
        rule = self.watches(1)[0]
        self.read(self.mine)
        text, error = self.tool("manager", "save_trigger", request_id=str(uuid.uuid4()), trigger_id=rule["id"],
                                base_revision=rule["revision"], schedule={"kind": "every", "minutes": 30})
        self.assertFalse(error, text)
        self.assertEqual(hub.duty_row(1)["revision"], 1)
        self.assertFalse(self.edit(self.mine, text="Keep content generation working.")[1])     # no watch list
        stale = [{"kind": "clock", "trigger": rule["id"], "schedule": {"kind": "every", "minutes": 10}}]
        text, error = self.edit(self.mine, watch=stale)     # its own change made the rule's change no less unread
        self.assertTrue(error, text)
        self.assertIn(f"A wake-up rule that the watch list of R-1 keeps changed after this session read it (rule "
                      f"{rule['id']})", text)
        self.assertIn(f"Watch {rule['id']} (clock) [active], every 30 minutes", text)
        self.assertEqual(json.loads(hub.trigger_row(rule["id"])["schedule"])["minutes"], 30)
        self.assertFalse(self.edit(self.mine, watch=stale)[1])          # the refusal showed it: read
        self.assertEqual(json.loads(hub.trigger_row(rule["id"])["schedule"])["minutes"], 10)

    def test_a_lead_is_held_by_its_own_session_whatever_task_it_names(self):
        """A lead's team tools name a subtask's task_id, which call_tool leaves as it is: the session is still its
        own task's."""
        hub.TEAM["agents"]["lead"] = {"role": "lead", "runtime": "claude", "machine": "vps", "can": ["shell"]}
        hub.TEAM["agents"]["vps"]["reports_to"] = "lead"
        f = hub.check_task("manager", {"owner": "lead", "title": "Run the content team", "done_when": "It runs."})
        with hub.LOCK, hub.transaction():
            own = hub.admit_task("manager", f)
        session = ("test-generation", hub.tref(own), str(hub.q1("SELECT attempt FROM tasks WHERE id=?",
                                                                (own,))["attempt"]))

        def lead(name, **args):
            return hub.call_tool("lead", name, args, session)
        text, error = lead("set_duty", request_id=str(uuid.uuid4()), task_id=hub.tref(self.mine),
                           responsibility="R-1", text="The lead's words, from nothing that it read.")
        self.assertTrue(error, text)
        self.assertIn("has not read R-1 in full yet", text)
        self.assertFalse(lead("see_responsibilities")[1])
        text, error = lead("set_duty", request_id=str(uuid.uuid4()), task_id=hub.tref(self.mine),
                           responsibility="R-1", text="The lead read it.")
        self.assertFalse(error, text)
        self.assertEqual(hub.duty_row(1)["text"], "The lead read it.")

    def test_a_new_attempt_reads_again(self):
        self.read(self.mine)
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (self.mine,))
        event = hub.attempt_event(t)                        # built before the transaction, as every caller does
        with hub.LOCK, hub.transaction():
            hub.attempt_rows(t, "restart", event, self.clock)
        self.assertIn("has not read R-1 in full yet", self.edit(self.mine, text="Two.")[0])

    def test_the_manager_s_standing_session_is_held_and_a_call_of_no_session_is_not(self):
        def standing(sha, when):
            hub.q("INSERT INTO session_credentials(sha256,agent,kind,generation,created) VALUES(?,?,?,?,?)",
                  (sha, "manager", "standing", "test-generation", when))

        def edit(text):
            return self.tool("manager", "set_duty", request_id=str(uuid.uuid4()), responsibility="R-1", text=text)
        self.assertFalse(edit("No session holds this call.")[1])          # no standing session yet
        standing("c" * 64, self.clock)
        self.assertFalse(self.tool("manager", "see_responsibilities")[1])
        self.assertFalse(edit("The standing session read it.")[1])
        standing("d" * 64, self.clock + 1)                  # a new standing session has read nothing
        self.assertIn("has not read R-1 in full yet", edit("A new session.")[0])
        self.assertEqual(hub.duty_row(1)["text"], "The standing session read it.")
        standing("e" * 64, self.clock + 2)                  # a task_id that it names is another session's task
        text, error = self.tool("manager", "set_duty", request_id=str(uuid.uuid4()), responsibility="R-1",
                                task_id=hub.tref(self.mine), text="Named a worker's task.")
        self.assertIn("has not read R-1 in full yet", text)
        self.assertEqual(hub.duty_row(1)["text"], "The standing session read it.")


class CaseLists(Base):
    """One duty with a long run of open cases (the owner, 8 November 2026: "Yes, shorten it"). Each open case of every
    duty, records and all, made the manager's list of duties 130,000 characters: one duty had 118 open cases, and
    the ones that its holder worked were its oldest. The list shows the newest whole and counts the rest, one duty in
    full names every open case in one line, and one case reads whole."""

    RECORD = "x" * 270

    def setUp(self):
        super().setUp()
        self.r = self.duty()
        self.ids, self.sessions = [], {}
        for n in range(14):
            with hub.transaction():
                cid = hub.duty_new_case(self.r, f"cve/{n}", f"Advisory {n:02d}, due 2026-11-{n + 10}", "test", "vps",
                                        self.clock - (20 - n) * 3600)
            for k, step in enumerate(("triage", "next")):
                hub.q("INSERT INTO duty_steps(duty_case,key,text,task,by,ts) VALUES(?,?,?,?,?,?)",
                      (cid, step, f"{step} of {n:02d} {self.RECORD}", None, "vps", self.clock - (19 - n) * 3600 + k))
            self.ids.append(cid)
        # Three of the oldest are closed: they are history, which no list of open cases names.
        for cid in self.ids[1:4]:
            hub.q("UPDATE duty_cases SET state='closed', closed=?, closed_by='manager', outcome='handled', "
                  "note='patched' WHERE id=?", (self.clock - 3600, cid))

    def session(self, who):
        """A task session of `who`, which a worker's call of a fleet tool needs."""
        if who not in self.sessions:
            f = hub.check_task("manager", {"owner": who, "title": "Work the advisories", "done_when": "In order."})
            with hub.LOCK, hub.transaction():
                self.sessions[who] = hub.admit_task("manager", f)
        return hub.tref(self.sessions[who])

    def ask(self, who, **args):
        return self.tool(who, "see_responsibilities", **args,
                         **({} if who == "manager" else {"task_id": self.session(who)}))

    def read(self, who="vps", **args):
        text, error = self.ask(who, **args)
        self.assertFalse(error, text)
        return text

    def test_the_list_shows_the_newest_open_cases_whole_and_counts_the_others(self):
        text = self.read()
        shown = [n for n in range(14) if f"Advisory {n:02d}," in text]
        self.assertEqual(shown, [9, 10, 11, 12, 13])                   # the newest five of the eleven open ones
        self.assertLess(text.index("Advisory 13,"), text.index("Advisory 09,"))      # newest first
        self.assertIn(f"Records: triage: triage of 13 {self.RECORD}; next: next of 13", text)
        oldest = f"R-1/C-{self.ids[0]}"
        self.assertIn(f"    and 6 older open cases, the oldest {oldest}, opened ", text)
        self.assertIn(f': see_responsibilities with responsibility="R-1" shows every open case, and '
                      f'case="{oldest}" gives one whole.', text)
        self.assertNotIn("older closed cases", text)
        self.assertIn("Cases: 11 open", text)                          # the count stays whole

    def test_one_duty_in_full_names_every_open_case_and_counts_the_closed_ones(self):
        text = self.read(responsibility="R-1")
        whole = [n for n in range(14) if f"triage of {n:02d}" in text]
        self.assertEqual(whole, list(range(4, 14)))                     # the newest ten, any state
        self.assertIn(f'  Older open cases (1), newest first, one line each; case="R-1/C-{self.ids[0]}" gives one '
                      f'whole:', text)
        # The line has the case's key: a holder that needs the keys of its open cases reads them here, in one read
        # (9 November 2026: a holder read each of about 100 cases whole for its key, in two tasks).
        self.assertRegex(text, rf"\n  R-1/C-{self.ids[0]} \[open\] Advisory 00, due 2026-11-10 — key cve/0; "
                               r"opened [^\n]*; 2 records, the last [^\n]*\.\n")
        self.assertIn("    and 3 older closed cases.", text)
        self.assertNotIn("Advisory 01,", text)                         # closed and older: counted, not named

    def test_one_duty_in_full_lists_many_older_open_cases_newest_first(self):
        for n in range(14, 30):
            with hub.transaction():
                self.ids.append(hub.duty_new_case(self.r, f"cve/{n}", f"Advisory {n:02d}, due 2026-12-01", "test",
                                                  "vps", self.clock))
        hub.q("UPDATE duty_cases SET repeated=1 WHERE id=?", (self.ids[0],))
        tasks = []
        for title in ("Look at advisory 00", "Patch advisory 00"):
            f = hub.check_task("manager", {"owner": "studio", "title": title, "done_when": "Done.",
                                           "case_id": f"R-1/C-{self.ids[0]}"})
            with hub.LOCK, hub.transaction():
                tasks.append(hub.admit_task("manager", f))
            if len(tasks) == 1:
                hub.q("UPDATE tasks SET state='completed' WHERE id=?", (tasks[0],))     # an ended task is not named
        ended, work = tasks
        text = self.read(responsibility="R-1")
        self.assertIn(f'  Older open cases (17), newest first, one line each; case="R-1/C-{self.ids[19]}" gives one '
                      f'whole:', text)
        self.assertLess(text.index("[open] Advisory 19,"), text.index("[open] Advisory 14,"))
        self.assertLess(text.index("[open] Advisory 04,"), text.index("[open] Advisory 00,"))
        # One read gives the key of every open case: the newest ten whole ("Key: "), each other one in its line.
        keys = set(re.findall(r"(?m)^    Key: (\S+) \(from ", text)) | set(re.findall(r" — key (\S+); opened ", text))
        self.assertEqual(keys, {f"cve/{n}" for n in range(30)} - {"cve/1", "cve/2", "cve/3"})
        brief = re.findall(r"(?m)^  R-1/C-(\d+) \[open\] Advisory (\d\d), [^\n]* — key cve/(\d+); opened ", text)
        self.assertEqual(len(brief), 17)
        self.assertEqual([(int(case), int(key)) for case, n, key in brief],        # each line has its own case's key
                         [(self.ids[int(n)], int(n)) for case, n, key in brief])
        line = next(x for x in text.splitlines() if "[open] Advisory 00," in x)
        state = hub.q1("SELECT state FROM tasks WHERE id=?", (work,))["state"]
        self.assertIn(f"; it came back inside 30 days; tasks {hub.tref(work)} {state}.", line)
        self.assertNotIn(hub.tref(ended), line)

    def test_one_case_reads_whole_with_each_record_and_how_it_closed(self):
        text = self.read(case=f"R-1/C-{self.ids[0]}")
        self.assertTrue(text.startswith("R-1 [active] "), text)
        self.assertIn(f"  R-1/C-{self.ids[0]} [open] Advisory 00, due 2026-11-10", text)
        self.assertIn(f"    triage — vps, {hub.goal_time(self.clock - 19 * 3600)}: triage of 00 {self.RECORD}", text)
        self.assertIn(f"    next — vps, {hub.goal_time(self.clock - 19 * 3600 + 1)}: next of 00", text)
        self.assertLess(text.index("    triage — "), text.index("    next — "))
        closed = self.read(case=f"C-{self.ids[1]}")                    # any state, and the short form of the id
        self.assertIn(f"  R-1/C-{self.ids[1]} [closed handled] Advisory 01", closed)
        self.assertIn(f"    Closed {hub.goal_time(self.clock - 3600)} by manager: patched", closed)
        hub.q("UPDATE duty_cases SET closed_by=NULL, note=NULL WHERE id=?", (self.ids[2],))     # an old row
        old = self.read(case=f"R-1/C-{self.ids[2]}")
        self.assertIn(f"    Closed {hub.goal_time(self.clock - 3600)}.", old)
        self.assertNotIn("None", old)
        hub.q("UPDATE duty_cases SET closed=NULL WHERE id=?", (self.ids[3],))             # no close time either
        self.assertIn("    Closed by manager: patched", self.read(case=f"R-1/C-{self.ids[3]}"))
        with hub.transaction():
            bare = hub.duty_new_case(self.r, "cve/new", "Advisory new", "test", "vps", self.clock)
        self.assertIn("    No record yet.", self.read(case=f"R-1/C-{bare}"))
        self.assertIn("triage of 01", self.read("manager", case=f"R-1/C-{self.ids[1]}"))     # the manager reads all
        text, error = self.ask("studio", case=f"R-1/C-{self.ids[0]}")
        self.assertTrue(error)
        self.assertIn("is not a case of your duties", text)
        f = hub.check_task("manager", {"owner": "studio", "title": "Patch advisory 00", "done_when": "Patched.",
                                       "case_id": f"R-1/C-{self.ids[0]}"})
        with hub.LOCK, hub.transaction():
            work = hub.admit_task("manager", f)
        text, error = self.tool("studio", "see_responsibilities", case=f"R-1/C-{self.ids[0]}",
                                task_id=hub.tref(work))
        self.assertFalse(error, text)                                  # its worker reads it, as it records in it
        self.assertIn("triage of 00", text)
        text, error = self.ask("vps", case="R-2/C-1")
        self.assertTrue(error)
        self.assertIn("is a case of R-1, not of R-2", text)
        # A case wins over a duty when a call gives both, as the description says.
        both = self.read(case=f"R-1/C-{self.ids[0]}", responsibility="R-1")
        self.assertIn("    triage — vps, ", both)
        self.assertNotIn("How it was managed", both)
        self.assertIn("How it was managed", self.read(responsibility="R-1"))

    def test_the_cases_that_a_duty_joined_are_cut_the_same_way(self):
        theirs = self.duty(agent="studio", text="Fix the shop's vulnerable packages. Push and release the fix.")
        for cid in self.ids:
            hub.q("INSERT INTO duty_joins(duty_case,responsibility,ts) VALUES(?,?,?)", (cid, theirs["id"], self.clock))
        text = self.read("studio")
        self.assertIn("Open cases of other duties that it works in (11), one event each:", text)
        self.assertIn(f'    and 6 older open cases, the oldest R-1/C-{self.ids[0]}, opened ', text)
        self.assertIn(f'responsibility="{hub.rref(theirs["id"])}" shows every open case', text)
        self.assertNotIn("Advisory 08,", text)
        full = self.read("studio", responsibility=hub.rref(theirs["id"]))
        self.assertIn("Older open cases (1), newest first, one line each", full)
        self.assertIn(f"R-1/C-{self.ids[0]} [open] Advisory 00", full)
        self.assertIn(f"; {hub.rref(theirs['id'])} of studio works in it too.", full)
        self.assertIn("triage of 00", self.read("studio", case=f"R-1/C-{self.ids[0]}"))     # it works in it too
        hub.q("UPDATE responsibilities SET state='retired' WHERE id=?", (theirs["id"],))
        gone = self.read("studio", responsibility=hub.rref(theirs["id"]))
        self.assertNotIn("Open cases of other duties", gone)
        self.assertNotIn("Advisory 00", gone)
        text, error = self.ask("studio", case=f"R-1/C-{self.ids[0]}")
        self.assertTrue(error)
        self.assertIn("is not a case of your duties", text)

    def test_the_live_shape_stays_short(self):
        """118 open cases, two records each, as the duty that made the manager's list 130,000 characters had."""
        for n in range(14, 118):
            with hub.transaction():
                cid = hub.duty_new_case(self.r, f"cve/{n}", f"Advisory {n}, due 2026-12-01", "test", "vps", self.clock)
            for step in ("triage", "next"):
                hub.q("INSERT INTO duty_steps(duty_case,key,text,task,by,ts) VALUES(?,?,?,?,?,?)",
                      (cid, step, self.RECORD, None, "vps", self.clock))
        self.assertLess(len(self.read()), 9000)
        self.assertLess(len(self.read(responsibility="R-1")), 30000)


if __name__ == "__main__":
    unittest.main()

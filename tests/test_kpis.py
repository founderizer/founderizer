"""KPIs (lanes/agent-kpis.md; the design is agent-kpis-spec.md, version 10, of the plans folder): set_kpi and its one
setter, the parent; the values of a linked check; the state and the hub's next steps; and the start text. In-process
hub, a temporary database and a set clock; no helper, no fleet and no AI call.

    python3 -m unittest -v test_kpis
"""
import json
import unittest
from unittest.mock import patch

import hub
import test_checks_v2
import test_standing

DAY = 86400
KPI = {"name": "Drafts sent as written", "direction": "at_least", "number": 80, "unit": "%", "metric": "drafts_sent",
       "words": "Of all tickets that arrived, at least 80% got a draft that staff sent with no change, over 7 days."}
LINES = test_standing.LINES


def load_tests(loader, _tests, _pattern):
    """Only this file's cases, not the inherited ones."""
    suite = unittest.TestSuite()
    for cls in (Parents, Steps, StartText, Reads, Values, Now):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Kpis(test_standing.Base):
    """The team of test_standing (a lead with a worker and a nested lead, a worker of that lead, and a worker of the
    fleet manager), with an agent whose Shell box is off under the lead, KPIs and line checks on."""

    def setUp(self):
        super().setUp()
        hub.TEAM["agents"]["closed"] = {"role": "worker", "runtime": "claude", "machine": "hand-box", "can": [],
                                        "reports_to": "lead"}
        hub.TEAM["settings"] = {"kpis": True, "checks.lines": True}

    def kpi_call(self, who, args):
        """One set_kpi call: the manager in its standing session, any other agent in its task's session. (Base.tool
        takes `name` for the tool, which is a field of set_kpi.)"""
        if hub.role_of(who) == "manager":
            return hub.call_tool(who, "set_kpi", args)
        tid = self.tasks[who]
        return hub.call_tool(who, "set_kpi", dict(args, task_id=hub.tref(tid)), ("test-generation", hub.tref(tid), 1))

    def kpi_ok(self, who, **args):
        text, err = self.kpi_call(who, args)
        self.assertFalse(err, text)
        return text

    def kpi_refused(self, who, **args):
        text, err = self.kpi_call(who, args)
        self.assertTrue(err, text)
        return text

    def set_kpi(self, who, agent, **args):
        text = self.kpi_ok(who, **dict(KPI, agent=agent, **args))
        return hub.q1("SELECT * FROM standing WHERE kind='kpi' ORDER BY id DESC LIMIT 1"), text

    def rule(self, agent, saved_in=None):
        """A line check of `agent`'s own, saved in its task `saved_in` (the history row that a save writes)."""
        t0 = hub.now()
        tid = hub.ins("INSERT INTO triggers(agent,state,revision,schedule,check_spec,task,late_minutes,"
                      "max_tasks_per_day,anchor,next_due,created,updated,request_id,created_by) VALUES(?,'active',1,?,"
                      "?,?,60,24,?,?,?,?,?,?)",
                      (agent, json.dumps({"kind": "every", "minutes": 60}), json.dumps(LINES),
                       json.dumps({"title": "Drafts", "details": "", "done_when": "x", "needs": "none",
                                   "goal_id": None}), t0, t0 + 3600, t0, t0, f"req-{agent}-{t0}", agent))
        hub.ins("INSERT INTO trigger_history(trigger_id,revision,ts,by,action,detail,saved_by_task) VALUES(?,1,?,?,"
                "'create',?,?)", (tid, t0, agent, json.dumps({"created": {"check": {"sha256": LINES["sha256"]}}}),
                                  saved_in))
        return hub.trigger_row(tid)

    def link(self, who, r, rule, part="Mark each ticket that you answer with a draft."):
        return self.kpi_ok(who, id=hub.iref(r["id"]), check=rule["id"], how="Sent drafts in the help desk, which "
                           "staff write.", agent_part=part)

    def value(self, rule, v, when, spec=LINES):
        """One run of the linked check at `when` that printed the KPI's line."""
        self.clock, t = when, hub.trigger_row(rule["id"])
        with hub.transaction():
            hub.kpi_record_rows(t, {"drafts_sent": v}, spec, when)

    def kpi(self, r):
        return dict(hub.q1("SELECT * FROM standing WHERE id=?", (r["id"],)))

    def end(self, task_id, when=None):
        hub.q("UPDATE tasks SET state='completed', delivered=? WHERE id=?", (when or self.clock, task_id))


class Parents(Kpis):
    def test_only_the_parent_sets_changes_links_and_ends_a_kpi(self):
        """Spec R3: the agent that gives an agent its tasks (task_giver) is the one changer of its KPIs. Protects
        against an agent that lowers its own level, and a higher level that skips the parent."""
        r, _ = self.set_kpi("lead", "hand")
        ref = hub.iref(r["id"])
        self.assertIn("no tool named set_kpi", self.kpi_refused("hand", id=ref, number=10))     # a worker has none
        sub, _ = self.set_kpi("lead", "sublead", name="Team drafts")
        self.assertIn("sets your KPIs", self.kpi_refused("sublead", id=hub.iref(sub["id"]), number=10))
        self.assertIn("ends your KPIs", self.refused("hand", "end_standing", id=ref, why="Too hard."))
        self.assertIn("ask it with message_agent", self.kpi_refused("manager", id=ref, number=10))
        self.assertIn("ends this KPI", self.refused("manager", "end_standing", id=ref, why="Not needed."))
        self.kpi_refused("manager", **dict(KPI, agent="hand", name="Other"))
        self.kpi_refused("lead", **dict(KPI, agent="deep"))         # sublead gives deep its tasks
        self.assertIn("has no KPIs", self.kpi_refused("manager", **dict(KPI, agent="manager")))
        self.assertIn("Shell box is off", self.kpi_refused("lead", **dict(KPI, agent="closed")))
        self.kpi_ok("sublead", **dict(KPI, agent="deep"))
        self.kpi_ok("manager", **dict(KPI, agent="solo"))
        self.assertEqual(self.item(r["id"])["number"], 80)
        self.kpi_ok("lead", id=ref, number=85)
        self.assertEqual(self.item(r["id"])["number"], 85)
        self.ok("lead", "end_standing", id=ref, why="The help desk changed.")
        self.assertIsNotNone(self.item(r["id"])["ended"])
        self.assertEqual([c["by"] for c in hub.q("SELECT by FROM kpi_changes WHERE item=? ORDER BY id", (r["id"],))],
                         ["lead", "lead", "lead"])

    def test_a_lead_that_cannot_act_passes_its_kpis_up(self):
        """Spec R3, v10: a lead in setup or with its Shell box off cannot act, so the nearest agent above that can is
        the parent. Protects against a team whose KPIs nobody can set."""
        for change in ({"can": []}, {"active": False}):
            with self.subTest(change):
                saved = dict(hub.TEAM["agents"]["sublead"])
                hub.TEAM["agents"]["sublead"].update(change)
                self.addCleanup(hub.TEAM["agents"].__setitem__, "sublead", saved)
                r, _ = self.set_kpi("lead", "deep", name=f"Drafts {len(change)}{list(change)[0]}")
                self.assertEqual(r["author"], "lead")
                self.assertIn("sets deep's KPIs", hub.kpi_may_set("sublead", "deep"))
                hub.TEAM["agents"]["sublead"] = saved

    def refused_directly(self, who):
        """set_kpi's own refusal, behind the offer that tools_for already refuses."""
        with self.assertRaises(hub.ToolError) as caught:
            hub.t_set_kpi(who, dict(KPI, agent="hand"))
        return str(caught.exception)

    def test_set_kpi_is_off_with_its_setting_and_in_a_session_that_a_person_drives(self):
        """Spec 10: a release gate until the live check, and never in a contact session. Protects against KPIs set in
        a fleet whose apps cannot show them, and against a person's words that set one."""
        names = lambda who: {t["name"] for t in hub.tools_for(who)}
        self.assertIn("set_kpi", names("lead"))
        self.assertNotIn("set_kpi", names("hand"))
        r, _ = self.set_kpi("lead", "hand")
        with patch.object(hub, "contact_session", lambda *a: True):     # a session that a person's message drives
            self.assertNotIn("set_kpi", names("lead"))
            self.assertIn("never one that a person's message drives", self.refused_directly("lead"))
            for who in ("lead", "manager"):
                self.assertNotIn(hub.iref(r["id"]), hub.t_see_standing(who, {}))
            for call in (lambda: hub.t_see_history("lead", {"what": "kpis"}),
                         lambda: hub.t_end_standing("lead", {"id": hub.iref(r["id"]), "why": "A person asked."})):
                with self.assertRaises(hub.ToolError):
                    call()
        self.assertIsNone(self.item(r["id"])["ended"])
        hub.TEAM["settings"]["kpis"] = False
        self.assertNotIn("set_kpi", names("lead"))
        self.assertIn("not on in this fleet", self.refused_directly("lead"))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM standing WHERE kind='kpi'")["n"], 1)

    def test_the_setup_task_and_the_link_take_only_the_measuring_agents_own_line_check(self):
        """Spec 5.1, 7.1: the setup task reaches the measuring agent as a wake-up of it, and the link takes only that
        agent's own line check. The lead reads the rule that the setup saved, and no other rule of its team. Protects
        against a KPI measured by a check that the measured agent's words or the lead's own code decide."""
        r, text = self.set_kpi("lead", "hand")
        setup = hub.q1("SELECT * FROM tasks WHERE id=?", (r["setup_task"],))
        self.assertEqual((setup["owner"], setup["title"]), ("hand", "Measure Drafts sent as written"))
        self.assertTrue(hub.team_results_task(hub.q1("SELECT * FROM tasks WHERE id=?", (setup["parent"],))))
        self.assertIn(hub.KPI_DATA_RULE, setup["details"])
        self.assertIn(hub.tref(setup["id"]), text)
        other, own = self.rule("hand"), self.rule("hand", saved_in=setup["id"])
        org = hub.wake_org()
        self.assertTrue(hub.wakeups.may_read(org, "lead", hub.trigger_view(own, hub.now())))
        self.assertFalse(hub.wakeups.may_read(org, "lead", hub.trigger_view(other, hub.now())))
        self.assertFalse(hub.wakeups.may_read(org, "sublead", hub.trigger_view(own, hub.now())))   # another lead
        self.assertIn("was not saved in", self.kpi_refused("lead", id=hub.iref(r["id"]), check=other["id"], how="x"))
        self.assertIn("saved for itself", self.kpi_refused("lead", id=hub.iref(r["id"]),
                                                       check=self.rule("lead")["id"], how="x"))
        hub.q("UPDATE triggers SET check_spec=? WHERE id=?", (json.dumps(dict(LINES, form=None)), other["id"]))
        self.assertIn("no line check", self.kpi_refused("lead", id=hub.iref(r["id"]), check=other["id"],
                                                    how="x"))
        self.link("lead", r, own)
        self.assertEqual(self.kpi(r)["check"], own["id"])
        self.assertTrue(hub.wakeups.may_read(hub.wake_org(), "lead", hub.trigger_view(own, hub.now())))
        # a new meaning clears the link and its values (KPIs version 2, 4.2: they measured something else), and a new
        # setup opens
        self.value(own, 70, self.kpi(r)["linked_at"] + DAY)
        self.kpi_ok("lead", id=hub.iref(r["id"]), metric="drafts_kept")
        now = self.kpi(r)
        self.assertEqual((now["check"], now["kpi_state"]), (None, "no_data"))
        self.assertIsNone(hub.q1("SELECT 1 FROM kpi_points WHERE item=?", (r["id"],)))
        self.assertNotEqual(now["setup_task"], setup["id"])


class Steps(Kpis):
    def linked(self, agent, parent="lead"):
        r, _ = self.set_kpi(parent, agent, measured_by=parent if hub.shell_off(agent) else None)
        rule = self.rule(parent) if hub.shell_off(agent) else self.rule(agent, saved_in=r["setup_task"])
        self.link(parent, r, rule)
        return self.kpi(r), rule

    def test_values_before_one_window_after_the_link_count_for_nothing(self):
        """Spec 6: the first window after the link holds days from before the agent knew its KPI. Protects against
        a task at a KPI's birth."""
        r, rule = self.linked("hand")
        self.value(rule, 10, r["linked_at"] + 6 * DAY)
        self.assertEqual((self.kpi(r)["kpi_state"], self.kpi(r)["off_task"]), ("no_data", None))
        self.value(rule, 10, r["linked_at"] + 7 * DAY)
        self.assertEqual(self.kpi(r)["kpi_state"], "off")

    def test_an_off_kpi_gives_one_task_then_the_parent_one_step_a_window_later(self):
        """Spec 6, 7.2, 7.3: the first counting off value gives the agent one off-target task, a subtask of its lead's
        team-results task; values that go on and off give no second one; one window after that task, still off, the
        lead gets the still-off step in the same job, also while the agent's task is open, and no second step while
        its own is open. The marker clears only after a full window on target after the task ended. Protects against
        a task after each value, and a step that waits for ever."""
        r, rule = self.linked("hand")
        start = r["linked_at"] + 7 * DAY
        self.value(rule, 50, start)
        off = self.kpi(r)["off_task"]
        task = hub.q1("SELECT * FROM tasks WHERE id=?", (off,))
        self.assertEqual((task["owner"], task["title"]), ("hand", "Drafts sent as written is off target"))
        self.assertTrue(hub.team_results_task(hub.q1("SELECT * FROM tasks WHERE id=?", (task["parent"],))))
        self.assertIn("50%, where its level is at least 80%", task["details"])
        self.value(rule, 90, start + DAY)
        self.value(rule, 40, start + 2 * DAY)
        self.assertEqual((self.kpi(r)["off_task"], self.kpi(r)["parent_task"]), (off, None))   # no step before a window
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tasks WHERE owner='hand' AND title LIKE '%off target'")["n"], 1)
        self.value(rule, 40, task["created"] + 7 * DAY)          # one window later, the agent's task still open
        step = hub.q1("SELECT * FROM tasks WHERE id=?", (self.kpi(r)["parent_task"],))
        self.assertEqual((step["owner"], step["requester"], step["job"], step["title"]),
                         ("lead", "manager", off, "Hand: Drafts sent as written still off target"))
        self.assertIn("still open", step["details"])
        self.value(rule, 40, task["created"] + 15 * DAY)         # its own step is open: no second one
        self.assertEqual(self.kpi(r)["parent_task"], step["id"])
        ended = task["created"] + 16 * DAY
        self.end(off, ended)
        self.value(rule, 90, ended + 6 * DAY)                    # on, but its window began before the task ended
        self.assertEqual(self.kpi(r)["off_task"], off)
        self.value(rule, 90, ended + 7 * DAY)
        now = self.kpi(r)
        self.assertEqual((now["off_task"], now["judge_after"], now["parent_task"]), (None, None, step["id"]))
        self.end(step["id"], ended + 8 * DAY)                    # the open still-off task clears when it ends
        self.value(rule, 30, ended + 8 * DAY)
        now = self.kpi(r)
        self.assertIsNone(now["parent_task"])
        self.assertNotEqual(now["off_task"], off)                # a new episode: one new task
        self.assertIsNotNone(now["off_task"])

    def test_a_shell_off_agent_gets_no_task_and_its_parent_the_step_at_once(self):
        """Spec 6, 7.3: an agent whose Shell box is off can only pass a message on, so its parent gets the still-off
        step at once; with the fleet manager as parent it is one inbox message, and a new one replaces the unread
        one. Protects against a task that a Shell-off session cannot work, and a manager's inbox that fills."""
        hub.TEAM["agents"]["solo"]["can"] = []
        hub.TEAM["agents"]["hand"]["reports_to"] = None         # a worker of the manager that holds the source
        for agent, parent, measurer in (("closed", "lead", "lead"), ("solo", "manager", "hand")):
            with self.subTest(agent):
                r, _ = self.set_kpi(parent, agent, name=f"Drafts of {agent}", measured_by=measurer)
                rule = self.rule(measurer, saved_in=self.kpi(r)["setup_task"])
                self.link(parent, r, rule)
                start = self.kpi(r)["linked_at"] + 7 * DAY
                self.value(rule, 50, start)
                now = self.kpi(r)
                self.assertIsNone(now["off_task"])
                self.assertIsNone(hub.q1("SELECT id FROM tasks WHERE owner=? AND title LIKE '%off target'", (agent,)))
                if parent == "lead":
                    step = hub.q1("SELECT * FROM tasks WHERE id=?", (now["parent_task"],))
                    self.assertEqual((step["owner"], step["requester"]), ("lead", "manager"))
                    self.assertIn("Shell box is off", step["details"])
                    self.value(rule, 40, start + 8 * DAY)        # past judge_after, its step still open
                    self.assertEqual(self.kpi(r)["parent_task"], step["id"])
                    continue
                first = now["parent_event"]
                said = hub.q1("SELECT * FROM events WHERE id=?", (first,))
                self.assertEqual((said["agent"], said["task"]), ("manager", None))
                self.assertIn("still off target", said["text"])
                self.value(rule, 40, start + 3 * DAY)
                self.assertEqual(self.kpi(r)["parent_event"], first)
                self.value(rule, 40, start + 8 * DAY)            # still off one window later: a new message
                second = self.kpi(r)["parent_event"]
                self.assertNotEqual(second, first)
                self.assertIsNotNone(hub.q1("SELECT read_at FROM events WHERE id=?", (first,))["read_at"])

    def test_a_new_meaning_while_the_task_is_open_reaches_the_parent_one_window_after_the_new_link(self):
        """Spec 6: a change of words clears the link and keeps an open task's marker; at the new link the episode is
        judged one window later, so a KPI that stays off reaches the parent even while the old task is open. Protects
        against an episode that a change hides for ever."""
        r, rule = self.linked("hand")
        self.value(rule, 50, r["linked_at"] + 7 * DAY)
        off = self.kpi(r)["off_task"]
        self.kpi_ok("lead", id=hub.iref(r["id"]), words="Of all tickets that arrived, at least 80% got a "
                                                               "draft that staff sent, over 7 days.")
        self.assertEqual(self.kpi(r)["off_task"], off)
        own = self.rule("hand", saved_in=self.kpi(r)["setup_task"])
        self.link("lead", r, own)
        linked = self.kpi(r)["linked_at"]
        self.assertEqual(self.kpi(r)["judge_after"], linked + 7 * DAY)
        self.value(own, 50, linked + 7 * DAY)
        self.assertEqual(hub.q1("SELECT job FROM tasks WHERE id=?", (self.kpi(r)["parent_task"],))["job"], off)
        self.assertEqual(self.kpi(r)["off_task"], off)

    def test_one_value_for_each_day_and_a_newer_one_replaces_it(self):
        """Spec 5.3: one value for each KPI and day of the fleet's time zone, the newest of the day. Protects against
        a corrected value that is lost, and a day cut at UTC midnight."""
        r, rule = self.linked("hand")
        day = r["linked_at"] + 8 * DAY
        self.value(rule, 50, day)
        self.value(rule, 85, day + 60)
        rows = hub.q("SELECT day, value FROM kpi_points WHERE item=?", (r["id"],))
        self.assertEqual([(x["day"], x["value"]) for x in rows], [(hub.item_day(day), 85.0)])
        self.assertEqual((self.kpi(r)["progress"], self.kpi(r)["kpi_state"]), (85.0, "on"))
        late = test_standing.at("2026-11-12T00:30")      # 23:30 UTC the day before
        self.value(rule, 70, late)
        self.assertEqual(hub.q1("SELECT day FROM kpi_points WHERE item=? AND at=?", (r["id"], late))["day"],
                         "2026-11-12")

    def test_the_daily_pass_and_a_deleted_rule_name_who_measures(self):
        """Spec 5.1, 6: no value for two windows asks the measuring agent to measure again, once for each spell, also
        for a check that never gave a value; a deleted linked rule clears the link and asks the parent who measures.
        Protects against a KPI that waits for ever on a check that prints the wrong metric, and a task each day."""
        r, rule = self.linked("hand")
        again = lambda: hub.q1("SELECT COUNT(*) n FROM tasks WHERE owner='hand' AND title=?",
                               ("Measure Drafts sent as written again",))["n"]
        for days, count in ((13, 0), (14, 1), (15, 1)):
            with hub.transaction():
                hub.kpi_daily_rows(r["linked_at"] + days * DAY)
            self.assertEqual(again(), count, days)
        self.value(rule, 90, r["linked_at"] + 16 * DAY)
        self.assertEqual(self.kpi(r)["kpi_state"], "on")
        for days, count in ((29, 1), (30, 2), (31, 2)):
            with hub.transaction():
                hub.kpi_daily_rows(r["linked_at"] + days * DAY)
            self.assertEqual(again(), count, days)
        self.assertEqual(self.kpi(r)["kpi_state"], "no_data")
        revision = hub.trigger_row(rule["id"])["revision"]          # the link changed its schedule, so its revision
        with hub.transaction():
            hub.trigger_state_rows(rule["id"], revision, "delete", "hand", hub.now())
        self.assertIsNone(self.kpi(r)["check"])
        self.assertIsNotNone(hub.q1("SELECT id FROM tasks WHERE owner='lead' AND title=?",
                                    ("Name who measures Drafts sent as written",)))


class StartText(Kpis):
    def test_the_agent_reads_the_words_and_its_part_and_never_the_number(self):
        """Spec 7.4: one line for each KPI with its words and part, the hub's sentence once, and no end sentence for a
        KPI. Protects against a number that steers every session, and an agent told to end its own KPI."""
        r, _ = self.set_kpi("lead", "hand", words="Most tickets that arrived got a draft that staff sent as written.")
        hub.q("UPDATE standing SET agent_part='Mark each ticket that you answer with a draft.' WHERE id=?",
              (r["id"],))
        hub.q("UPDATE standing SET progress=41.5 WHERE id=?", (r["id"],))
        text = hub.standing_start_text("hand")
        self.assertIn(f"{hub.iref(r['id'])} KPI from Lead: Most tickets that arrived got a draft that staff sent as "
                      f"written. [your part: Mark each ticket that you answer with a draft.]", text)
        self.assertNotIn("80", text)
        self.assertNotIn("41.5", text)
        self.assertEqual(text.count("A KPI measures your work and never limits it"), 1)
        self.assertNotIn("end_standing", text)
        self.ok("lead", "keep_instruction", words="Answer in Spanish.", scope="team")
        self.assertIn("end_standing, never a KPI", hub.standing_start_text("hand"))

    def test_no_kpi_where_a_persons_words_drive_or_read(self):
        """Spec 7.4: a window's brief, a task that a conversation opened, and its news read no KPI. Protects against
        staff that read an agent's KPI."""
        r, _ = self.set_kpi("lead", "hand")
        line = f"{hub.iref(r['id'])} KPI"
        self.assertIn(line, hub.start_text("hand", self.tasks["hand"]))
        pid = self.person()
        conv = self.conversation(pid)
        opened = self.new_task("hand", source_conversation=conv)
        part = self.new_task("hand", parent=opened)
        for tid in (opened, part):
            self.assertNotIn(line, hub.start_text("hand", tid))
        self.assertNotIn(line, hub.start_text("hand", opened, first="A window's brief."))
        self.assertNotIn(r["id"], [x["id"] for x in hub.steering_items("hand", kpis=False)])
        self.assertFalse([n for n in hub.standing_pull("hand", conv, opening=False) if "KPI" in n])
        self.kpi_ok("lead", id=hub.iref(r["id"]), number=85)
        told = {e["task"] for e in hub.q("SELECT task FROM events WHERE agent='hand' AND text LIKE '%changed%'")}
        self.assertIn(self.tasks["hand"], told)
        self.assertFalse(told & {opened, part})

    def test_the_parent_reads_which_agents_have_no_kpi(self):
        """Spec 7.4: the parent's line in its team-results task, its first session included, and in the fleet
        manager's brief, only while an active agent whose tasks it gives has no KPI. Protects against KPIs that
        nobody sets, and a nudge in every task."""
        with hub.transaction():
            batch = hub.lead_batch_rows("lead", hub.now())
        first = hub.q1("SELECT text FROM events WHERE task=? ORDER BY id LIMIT 1", (batch,))["text"]
        self.assertIn("no KPI: Hand (hand), Sublead (sublead), Closed (closed)", first)
        self.assertNotIn("Set KPIs", hub.start_text("lead", self.tasks["lead"]))
        self.assertIn("no KPI: Lead (lead), Solo (solo)", hub.manager_resume_text())
        for agent in ("hand", "closed", "sublead"):
            self.set_kpi("lead", agent, measured_by="lead" if agent == "closed" else None)
        self.assertNotIn("Set KPIs", hub.start_text("lead", batch))
        hub.TEAM["settings"]["kpis"] = False
        self.assertNotIn("Set KPIs", hub.manager_resume_text())


class Reads(Kpis):
    def test_the_owner_reads_the_weeks_and_marks_and_the_snapshot_only_the_count(self):
        """Spec 8.1, and KPIs version 2 (4.2): GET /ui/kpis gives each week's newest value, each one shown (its
        `counts`), and the marks of the changes; the snapshot holds only the count. Protects against a snapshot that
        grows with every value, and a chart that hides the values of the first window (the owner, 22 November 2026:
        "the value needs to show immediately")."""
        r, _ = self.set_kpi("lead", "hand")
        rule = self.rule("hand", saved_in=r["setup_task"])
        self.link("lead", r, rule)
        linked = self.kpi(r)["linked_at"]
        self.value(rule, 40, linked + DAY)
        self.value(rule, 85, linked + 9 * DAY, dict(LINES, sha256="c" * 64))     # an edit of the check
        code, data = self.request("/ui/kpis?db=test-generation&agent=hand&weeks=2")
        self.assertEqual(code, 200, data)
        kpi = data["kpis"][0]
        self.assertEqual((kpi["name"], kpi["state"], kpi["setter_role"], kpi["value"]),
                         ("Drafts sent as written", "on", "Lead", 85.0))
        self.assertEqual([(w["value"], w["counts"]) for w in kpi["weeks"]], [(40.0, True), (85.0, True)])
        self.assertEqual([m["words"] for m in kpi["marks"]][-2:], ["Lead linked its check", "Check changed"])
        self.assertNotRegex(json.dumps(kpi["marks"]), r"[A-Z]-[0-9]|wake-up rule")     # the owner's words: no code
        code, state = self.request("/ui/state")
        row = next(a for a in state["agents"] if a["name"] == "hand")
        self.assertEqual(row["kpis"], 1)
        self.assertNotIn("drafts", json.dumps(row).lower())
        self.assertEqual(self.request("/ui/kpis?db=test-generation&agent=hand&weeks=27")[0], 400)
        self.assertEqual(self.request("/ui/kpis?db=test-generation&agent=nobody")[0], 404)
        code, every = self.request("/ui/kpis?db=test-generation")              # with no agent: every agent's
        self.assertEqual((code, [k["agent"] for k in every["kpis"]]), (200, ["hand"]))

    def test_a_lead_reviews_its_team_and_a_worker_reads_no_kpi_mode(self):
        """Spec 7.6: a lead reads its own KPIs and its team's, the fleet manager every agent's, and a worker has no
        such mode: its number reaches it in its task. Protects against a worker told its number in a routine read."""
        r, _ = self.set_kpi("lead", "hand")
        text = self.ok("lead", "see_history", what="kpis")
        self.assertIn(f"{hub.iref(r['id'])} hand (Hand): Drafts sent as written.", text)
        self.assertTrue(text.rstrip().endswith('window=<days>, agent="<name>" of your team.'))
        self.assertIn("It ranks no agent.", text)
        self.assertIn(hub.iref(r["id"]), self.ok("manager", "see_history", what="kpis"))
        self.assertIn("what must be one of costs.", self.refused("hand", "see_history", what="kpis"))
        tools = [t for t in hub.tools_for("lead") if t["name"] == "see_history"]
        self.assertEqual([t["inputSchema"]["properties"]["what"]["enum"] for t in tools], [["costs", "kpis"]])

    def test_a_removed_agents_kpi_goes_and_its_id_is_never_given_again(self):
        """Spec 11, 12.1 test 7: a KPI's values and changes go with its agent, and the next item gets a new id.
        Protects against a new item that shows an old agent's chart."""
        r, _ = self.set_kpi("lead", "hand")
        rule = self.rule("hand", saved_in=r["setup_task"])
        self.link("lead", r, rule)
        self.value(rule, 40, self.kpi(r)["linked_at"] + 8 * DAY)
        with hub.transaction():
            hub.remove_rows("hand", hub.now())
        for table in ("kpi_points", "kpi_changes"):
            self.assertIsNone(hub.q1(f"SELECT 1 FROM {table} WHERE item=?", (r["id"],)), table)
        hub.TEAM["agents"].pop("hand")
        new, _ = self.set_kpi("lead", "closed", measured_by="lead")
        self.assertGreater(new["id"], r["id"])

    def test_a_move_clears_a_link_that_the_new_parent_cannot_read(self):
        """Spec 5.1: a move keeps a link that the new parent reads (the agent measures itself, or the new parent
        measures it) and clears one whose measuring agent the new parent does not lead, also when the old parent
        measured it itself, with the step that names who measures. Protects against a parent that cannot read the
        check that judges its agent, and a measurer taken from whoever is the parent now."""
        own, _ = self.set_kpi("lead", "hand")
        self.link("lead", own, self.rule("hand", saved_in=own["setup_task"]))
        theirs, _ = self.set_kpi("lead", "hand", name="Drafts checked", measured_by="sublead")
        self.link("lead", theirs, self.rule("sublead", saved_in=theirs["setup_task"]))
        mine, _ = self.set_kpi("lead", "hand", name="Drafts read", measured_by="lead")
        self.link("lead", mine, self.rule("lead"))
        team = json.loads(json.dumps(hub.TEAM))
        team["agents"]["hand"]["reports_to"] = "sublead"
        hub.apply_team(team)
        self.assertEqual([self.kpi(x)["check"] is None for x in (own, theirs, mine)], [False, False, True])
        self.assertIsNotNone(hub.q1("SELECT id FROM tasks WHERE owner='sublead' AND title=?",
                                    ("Name who measures Drafts read",)))


class Values(test_checks_v2.Lines):
    """The values of a linked check through the hub's own result route (spec 5.2)."""

    def setUp(self):
        super().setUp()
        hub.TEAM["settings"]["kpis"] = True
        text, err = self.tool("lead", "set_kpi", dict(KPI, agent="seo"))
        self.assertFalse(err, text)
        self.kpi = hub.q1("SELECT * FROM standing WHERE kind='kpi'")
        self.setup_context = (hub.kv_get("db_id"), hub.tref(self.kpi["setup_task"]), 1)
        text, err = self.tool("seo", "save_trigger", {"request_id": "req-kpi-0001", "schedule": test_checks_v2.EVERY,
                                                      "task": test_checks_v2.TASK, "check": test_checks_v2.LINES},
                              self.setup_context)
        self.assertFalse(err, text)
        self.rule = hub.q1("SELECT * FROM triggers ORDER BY id DESC LIMIT 1")
        text, err = self.tool("lead", "see_triggers", {"trigger_id": self.rule["id"]})
        self.assertFalse(err, text)                         # the lead reads the check that the setup saved
        text, err = self.tool("lead", "set_kpi", {"id": hub.iref(self.kpi["id"]), "check": self.rule["id"],
                                                  "how": "The help desk's sent drafts.", "agent_part": ""})
        self.assertFalse(err, text)

    def points(self):
        return [p["value"] for p in hub.q("SELECT value FROM kpi_points WHERE item=? ORDER BY at", (self.kpi["id"],))]

    def test_a_kpi_line_records_and_never_wakes(self):
        """Spec 5.2: the leading block is a value and never a wake line; on a linked check a later or malformed kpi
        line is dropped, and on any other check it wakes. Protects against a value line that wakes the agent at each
        run."""
        # KPIs version 2 (4.2): the first run after the link may give a past day, at the end of its window
        linked = hub.q1("SELECT linked_at FROM standing WHERE id=?", (self.kpi["id"],))["linked_at"]
        before = int(linked - 2 * DAY)
        answer, run = self.once(self.rule, ["kpi drafts_sent 81.5", f"kpi drafts_sent 60 {before}",
                                            f"kpi drafts_sent 61 {int(linked - 60 * DAY)}", "kpi other 3"])
        self.assertEqual((answer["decision"], self.points()), ("quiet", [60.0, 81.5]))
        self.assertIn("1 dated kpi line(s) were not taken", run["reason"])     # more than 56 days back
        answer, run = self.once(self.rule, ["progress 4", "kpi drafts_sent 70", f"kpi drafts_sent 55 {before - DAY}",
                                            "T-1 new", "kpi drafts_sent lots"])
        self.assertEqual(answer["decision"], "started")
        details = hub.q1("SELECT details FROM tasks WHERE id=?", (answer["task"],))["details"]
        self.assertIn('JSON-encoded: ["T-1 new"]', details)
        self.assertIn("1 line(s) that begin with kpi were dropped", run["reason"])
        self.assertNotIn("dated", run["reason"])        # a later run's past goes with no words: it prints it each run
        self.assertEqual(self.points(), [60.0, 70.0])   # the same day: the newer value
        other = self.save("vps", "req-kpi-0002")
        hub.TEAM["settings"]["kpis"] = False             # a release gate: while KPIs are off, no check's lines change
        answer, _ = self.once(other, ["kpi drafts_sent 12"])
        self.assertIn(answer["decision"], ("started", "joined"))       # it wakes, as before the feature
        hub.TEAM["settings"]["kpis"] = True
        answer, _ = self.once(other, ["kpi drafts_sent 13"])
        self.assertEqual(answer["decision"], "quiet")    # a leading block wakes on no check
        answer, _ = self.once(other, ["kpi drafts_sent lots"])
        self.assertIn(answer["decision"], ("started", "joined"))   # no KPI links it: a malformed line is a line

    def test_a_run_that_waits_behind_a_limit_records_its_value_at_once(self):
        """Spec 5.2: the value is recorded at the run's first decision, also when the run then waits behind a usage
        limit with its wake lines. Protects against a waiting run that loses its value."""
        limit = {"until": self.clock + 7200, "since": self.clock, "reset_known": 1, "task": None, "id": 1}
        with patch.object(hub, "active_limit", lambda agent, *a, **k: limit if agent == "seo" else None):
            answer, run = self.once(self.rule, ["kpi drafts_sent 77", "T-9 new"])
        self.assertEqual((answer["decision"], self.points()), ("waiting", [77.0]))

    def test_check_now_and_a_stale_claim_record_nothing(self):
        """Spec 5.2: never for Check now, never from a stale claim. Protects against a value that the agent makes
        appear at will."""
        text, err = self.tool("seo", "change_trigger", {"request_id": "req-kpi-0003", "trigger_id": self.rule["id"],
                                                        "base_revision": self.rule["revision"],
                                                        "action": "check_now"}, self.setup_context)
        self.assertFalse(err, text)
        runner, extra = self.sent(self.rule["id"])
        self.post(runner, extra, lines=["kpi drafts_sent 99"])
        self.assertEqual(self.points(), [])
        t = hub.trigger_row(self.rule["id"])
        self.tick(t["next_due"])
        runner, extra = self.sent(t["id"])
        hub.TEAM["agents"]["seo"]["active"] = False          # the claim is stale at its result
        self.post(runner, extra, lines=["kpi drafts_sent 99"])
        run = hub.q1("SELECT state, reason FROM trigger_runs WHERE id=?", (extra["run"],))
        self.assertEqual((run["state"], run["reason"]), ("not_started", "seo is in setup."))
        self.assertEqual(self.points(), [])


class Now(Kpis):
    """KPIs version 2, piece now (~/dev/founderizer-plans/agent-kpis-v2/plan.md 4.2, 4.7, 4.8; the owner, 22 November
    2026: "we need kpis immediately, the value needs to show immediately")."""

    def linked(self, part=None, rule=None, r=None):
        r = r or self.set_kpi("lead", "hand")[0]
        rule = rule or self.rule("hand", saved_in=r["setup_task"])
        text = self.kpi_ok("lead", id=hub.iref(r["id"]), check=rule["id"], how="Sent drafts in the help desk, which "
                           "staff write.", **({"agent_part": part} if part else {}))
        return self.kpi(r), hub.trigger_row(rule["id"]), text

    def test_a_value_shows_at_once_and_is_judged_at_once_when_the_agent_has_no_part(self):
        """4.2, 4.8: the first value after the link shows on the owner's tab at once, with its state; a KPI whose
        agent has no part to play is judged from its link, so an off value gives its step at once; a value older than
        two windows keeps no colour. Protects against a tab that shows a dash for a whole window, and an old red value
        that stays red after its check stopped."""
        r, rule, _ = self.linked()
        self.value(rule, 50, r["linked_at"] + 60)
        code, data = self.request("/ui/kpis?db=test-generation&agent=hand&weeks=1")
        kpi = data["kpis"][0]
        self.assertEqual((kpi["value"], kpi["value_counts"], kpi["state"], kpi["weeks"][-1]["counts"]),
                         (50.0, True, "off", True))
        self.assertEqual(self.kpi(r)["kpi_state"], "off")
        self.assertIsNotNone(self.kpi(r)["off_task"])
        self.clock = r["linked_at"] + 2 * 7 * DAY + 61         # two windows with no value: it says nothing of now
        code, data = self.request("/ui/kpis?db=test-generation&agent=hand&weeks=1")
        self.assertEqual((data["kpis"][0]["value"], data["kpis"][0]["state"]), (50.0, "no_data"))

    def test_a_checks_first_run_after_its_link_fills_its_past_days_once(self):
        """4.2: the first recording run after a link may print past days, "kpi <metric> <value> <unix-seconds>": the
        hub takes them only in that run, only for the code that the parent linked, only before the link and at most
        56 days back, and only for a day with no value; they show, and are never judged. A new code of the same rule
        is a new link, whose first run fills its past again. Protects against a run that rewrites its history at each
        run, and a past that the measured agent's later code invents."""
        r, rule, _ = self.linked(part="Mark each ticket that you answer with a draft.")
        linked = r["linked_at"]
        dated = [("drafts_sent", 70.0, linked - 3 * DAY), ("drafts_sent", 71.0, linked - 3 * DAY + 10),
                 ("drafts_sent", 60.0, linked - 60 * DAY), ("drafts_sent", 99.0, linked + 30)]
        self.clock = linked + 60
        with hub.transaction():
            hub.kpi_record_rows(rule, {"drafts_sent": 80.0}, LINES, linked + 60, dated)
        points = lambda: [(p["value"], p["backfill"]) for p in
                          hub.q("SELECT value, backfill FROM kpi_points WHERE item=? ORDER BY at", (r["id"],))]
        self.assertEqual(points(), [(70.0, 1), (80.0, 0)])
        self.assertEqual(self.kpi(r)["kpi_state"], "no_data")       # a past value is shown, never judged
        with hub.transaction():                                     # a later run: its dated lines are dropped
            hub.kpi_record_rows(rule, {"drafts_sent": 81.0}, LINES, linked + 960,
                                [("drafts_sent", 10.0, linked - 5 * DAY)])
        self.assertEqual(points(), [(70.0, 1), (81.0, 0)])
        # new code of the same rule: the lead links it again, and its first run fills a day that had no value
        edited = dict(LINES, sha256="c" * 64)
        hub.q("UPDATE triggers SET check_spec=? WHERE id=?", (json.dumps(edited), rule["id"]))
        self.clock = linked + 2000
        self.kpi_ok("lead", id=hub.iref(r["id"]), check=rule["id"], how="Sent drafts in the help desk, which staff "
                    "write.", agent_part="Mark each ticket that you answer with a draft.")
        relinked = self.kpi(r)["linked_at"]
        self.assertGreater(relinked, linked)
        with hub.transaction():
            hub.kpi_record_rows(rule, {}, LINES, relinked + 60, [("drafts_sent", 55.0, linked - 5 * DAY)])
        self.assertNotIn((55.0, 1), points())                       # the old code's digest: dropped
        with hub.transaction():
            hub.kpi_record_rows(rule, {}, edited, relinked + 60, [("drafts_sent", 55.0, linked - 5 * DAY)])
        self.assertIn((55.0, 1), points())

    def test_a_link_runs_its_check_every_15_minutes_and_takes_a_duty_watch(self):
        """4.7, 4.8: a check that a KPI links runs at once and at least every 15 minutes, and its history says why;
        a duty's watch may be linked: it runs once, for its first value, and keeps its own times; a paused rule is
        named as paused and stays so. Protects against a KPI whose value comes only at its check's own slow times,
        the refusal of a duty's watch that cost an agent a second check on 22 November 2026, and a daily watch that
        loses its time and wakes its agent at each quarter hour (the validator, 23 November)."""
        r, _ = self.set_kpi("lead", "hand")
        rule = self.rule("hand", saved_in=r["setup_task"])
        hub.q("UPDATE triggers SET schedule=? WHERE id=?", (json.dumps({"kind": "every", "minutes": 1440}), rule["id"]))
        _, now_rule, text = self.linked(rule=rule, r=r)
        self.assertIn("every 15 minutes", text)
        self.assertEqual(json.loads(now_rule["schedule"]), {"kind": "every", "minutes": 15})
        self.assertEqual(now_rule["next_due"], self.kpi(r)["linked_at"])
        last = hub.q1("SELECT by, action FROM trigger_history WHERE trigger_id=? ORDER BY id DESC LIMIT 1",
                      (rule["id"],))
        self.assertEqual((last["by"], last["action"]), ("hub", "edit"))
        self.clock += 60                    # a second rule of hand: its own request id
        watch, _ = self.set_kpi("lead", "hand", name="Drafts of the watch")
        duty = self.rule("hand", saved_in=watch["setup_task"])
        daily = {"kind": "daily", "time": "09:00", "days": ["mon", "tue", "wed", "thu", "fri"],
                 "timezone": "Europe/Madrid"}
        hub.q("UPDATE triggers SET schedule=?, responsibility=1 WHERE id=?", (json.dumps(daily), duty["id"]))
        _, kept, text = self.linked(rule=hub.trigger_row(duty["id"]), r=watch)
        self.assertIn("it runs now, and after that at its own times", text)
        self.assertEqual((json.loads(kept["schedule"]), kept["next_due"], kept["revision"]),
                         (daily, self.kpi(watch)["linked_at"], duty["revision"]))
        self.clock += 60
        asleep, _ = self.set_kpi("lead", "hand", name="Drafts asleep")
        rule = self.rule("hand", saved_in=asleep["setup_task"])
        hub.q("UPDATE triggers SET state='paused', paused_by='owner', schedule=? WHERE id=?",
              (json.dumps(daily), rule["id"]))
        _, still, text = self.linked(rule=hub.trigger_row(rule["id"]), r=asleep)
        self.assertIn("It is paused by the owner, so it runs once it is resumed", text)
        self.assertEqual((json.loads(still["schedule"]), still["state"]), (daily, "paused"))

    def test_a_lead_links_only_the_code_it_read_and_an_old_link_keeps_its_code(self):
        """4.2 and two readers' findings of 22 November 2026: a lead links a rule only while its code now is the code
        saved in the setup task, where the lead read it; a link from before version 2 takes the digest of the check
        that made its newest value, so new words of how keep it; and a check of another agent cannot read the
        measured agent's reports. Protects against a change of how that links code the lead never read, whose first
        run then invents a past, and a fix time measured from the wrong agent's reports."""
        r, rule, _ = self.linked()
        hub.ins("INSERT INTO trigger_history(trigger_id,revision,ts,by,action,detail,saved_by_task) VALUES(?,2,?,"
                "'hand','edit',?,?)", (rule["id"], self.clock, json.dumps({"changed": {"check": {"before": None,
                                                                                                 "after": None}}}),
                                       self.tasks["hand"]))         # the agent edits its code in another task
        hub.q("UPDATE triggers SET check_spec=? WHERE id=?", (json.dumps(dict(LINES, sha256="d" * 64)), rule["id"]))
        self.assertIn("code now was not saved in", self.kpi_refused("lead", id=hub.iref(r["id"]), check=rule["id"],
                                                                    how="New words."))
        hub.q("UPDATE standing SET link_digest=NULL WHERE id=?", (r["id"],))         # a link from before version 2
        hub.q("INSERT INTO kpi_points(item,day,value,at,source) VALUES(?,'2026-10-20',50,?,?)",
              (r["id"], self.clock - 3 * DAY, f"rule {rule['id']} 0123abcd4567"))
        self.assertEqual(hub.migrate(), [])
        self.assertEqual(self.kpi(r)["link_digest"], "0123abcd4567")
        # the agent saves the check again in the setup task, with no change: the lead reads it there, and links it
        hub.ins("INSERT INTO trigger_history(trigger_id,revision,ts,by,action,detail,saved_by_task) VALUES(?,3,?,"
                "'hand','edit','{\"changed\": {}}',?)", (rule["id"], self.clock, r["setup_task"]))
        self.kpi_ok("lead", id=hub.iref(r["id"]), check=rule["id"], how="New words.")
        self.assertEqual(self.kpi(r)["link_digest"], hub.kpi_digest(dict(LINES, sha256="d" * 64)))
        mine, _ = self.set_kpi("lead", "hand", name="Fix time", measured_by="lead")
        own = self.rule("lead")
        hub.q("UPDATE triggers SET check_spec=? WHERE id=?", (json.dumps(dict(LINES, inputs=["reports"])), own["id"]))
        self.assertIn("reads the input reports", self.kpi_refused("lead", id=hub.iref(mine["id"]), check=own["id"],
                                                                  how="The fix times of the duties of hand."))


if __name__ == "__main__":
    unittest.main()

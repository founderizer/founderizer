"""KPIs (lanes/agent-kpis.md; the design is agent-kpis-spec.md, version 10, of the plans folder): set_kpi and its one
setter, the parent; the values of a linked check; the state and the hub's next steps; and the start text. In-process
hub, a temporary database and a set clock; no helper, no fleet and no AI call.

    python3 -m unittest -v test_kpis
"""
import json
import unittest
import uuid
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
    def test_each_level_above_sets_a_kpi_and_a_field_keeps_the_rank_that_set_it(self):
        """KPIs version 2, 4.4: the parent and each agent above it set, change, link and end an agent's KPIs; a field
        changes only from the rank of the newest change that named it, or above, while that changer is still above the
        agent; an end needs the highest rank of the KPI's fields; and the parent reads each change from above in its
        next task session. Protects against a lead that undoes the fleet manager's level, an agent that changes its
        own KPI, and a parent that never learns what changed above it."""
        r, _ = self.set_kpi("lead", "hand")
        ref = hub.iref(r["id"])
        self.assertIn("no tool named set_kpi", self.kpi_refused("hand", id=ref, number=10))     # a worker has none
        sub, _ = self.set_kpi("lead", "sublead", name="Team drafts")
        hub.TEAM["agents"]["lead"]["title"] = "Team Lead"   # an agent reads the parent as the team list: name (role)
        self.assertIn("lead (Team Lead) sets your KPIs", self.kpi_refused("sublead", id=hub.iref(sub["id"]), number=10))
        self.assertIn("ends your KPIs", self.refused("hand", "end_standing", id=ref, why="Too hard."))
        self.assertIn("sets hand's KPIs", self.kpi_refused("sublead", id=ref, number=10))       # not above hand
        self.assertIn("sets solo's KPIs", self.kpi_refused("lead", **dict(KPI, agent="solo")))
        self.assertIn("has no KPIs", self.kpi_refused("manager", **dict(KPI, agent="manager")))
        self.assertIn("Shell box is off", self.kpi_refused("lead", **dict(KPI, agent="closed")))
        # the fleet manager, above the lead, changes the level: the lead keeps its other fields, and not that one
        self.kpi_ok("manager", id=ref, number=85)
        note = hub.q1("SELECT * FROM events WHERE agent='lead' AND task IS NULL AND kind='say'")
        self.assertIn(f"above you, made a change to the KPI {ref} of hand", note["text"])
        self.assertIn("number to 85", note["text"])
        self.assertIn("above you: ask it", self.kpi_refused("lead", id=ref, number=70))
        self.kpi_ok("lead", id=ref, name="Drafts as written")
        self.assertIn("set " + ref + "'s number, above you", self.refused("lead", "end_standing", id=ref, why="No."))
        later = self.new_task("lead", title="The next task")     # its next task session reads the note, as written
        with hub.transaction():
            hub.waiting_say_rows("lead", later)
        self.assertEqual(hub.q1("SELECT task FROM events WHERE id=?", (note["id"],))["task"], later)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE agent='lead' AND "
                                "json_extract(extra, '$.kpi_note') IS NOT NULL")["n"], 1)      # its own change: none
        # a link from above locks the link; a change from above that clears it leaves the next link to the parent
        self.link("manager", r, self.rule("hand", saved_in=r["setup_task"]))
        self.assertIn("above you", self.kpi_refused("lead", id=ref, check=self.rule("hand")["id"], how="x"))
        self.kpi_ok("manager", id=ref, words="Most tickets got a draft that staff sent as written.")
        self.link("lead", r, self.rule("hand", saved_in=self.kpi(r)["setup_task"]))
        # a lead sets a KPI anywhere in its subtree, reads the check that measures it, and the parent below it keeps
        # out of the lead's fields
        deep, _ = self.set_kpi("lead", "deep")
        rule = self.rule("deep", saved_in=deep["setup_task"])
        self.assertTrue(hub.wakeups.may_read(hub.wake_org(), "lead", hub.trigger_view(rule, hub.now())))
        self.assertIn("above you", self.kpi_refused("sublead", id=hub.iref(deep["id"]), number=70))
        team = json.loads(json.dumps(hub.TEAM))     # a changer that is no longer above the agent locks nothing
        team["agents"]["sublead"]["reports_to"] = "manager"
        hub.apply_team(team)
        self.kpi_ok("sublead", id=hub.iref(deep["id"]), number=70)
        self.ok("manager", "end_standing", id=ref, why="The help desk changed.")
        self.assertIsNotNone(self.item(r["id"])["ended"])
        self.assertEqual([(c["by"], c["fields"] and json.loads(c["fields"])) for c in hub.q(
            "SELECT by, fields FROM kpi_changes WHERE item=? ORDER BY id", (r["id"],))],
            [("lead", [k for k in hub.KPI_LOCK_FIELDS[:-1] if k != "measured_by"]), ("manager", ["number"]), ("lead", ["name"]),
             ("manager", ["check"]), ("manager", ["words"]), ("lead", ["check"]), ("manager", None)])
        # the hub's "Name who measures" step reaches a parent below the setter of measured_by: the parent can do it
        named, _ = self.set_kpi("manager", "hand", name="Drafts read", measured_by="lead")
        notes = "SELECT task FROM events WHERE agent='lead' AND json_extract(extra, '$.kpi_note')=?"
        self.assertEqual(hub.q(notes, (named["id"],)), [])     # its setup task, which that change opened, says it all
        self.assertIn(f"{hub.shown_role('manager')} set the KPI Drafts read", hub.q1(
            "SELECT why FROM tasks WHERE id=?", (named["setup_task"],))["why"])
        self.kpi_ok("manager", id=hub.iref(named["id"]), number=75)       # its session there reads the next one now
        self.assertEqual([e["task"] for e in hub.q(notes, (named["id"],))], [named["setup_task"]])
        self.kpi_ok("manager", id=hub.iref(named["id"]), words="Most tickets got a draft that a person read.")
        self.assertEqual(len(hub.q(notes, (named["id"],))), 1)      # the new setup task that it opened says it all
        team = json.loads(json.dumps(hub.TEAM))
        team["agents"]["hand"]["reports_to"] = "sublead"        # lead measures it, and leads hand no more
        hub.apply_team(team)
        self.kpi_ok("sublead", id=hub.iref(named["id"]), measured_by="hand")
        # also when the measurer stays (its rule deleted, or no value for two windows): the step frees the measurer
        # and the link that an agent above set, and offers no end that the parent cannot make
        kept, said = self.set_kpi("manager", "hand", name="Drafts kept", measured_by="hand")
        self.assertIn(f"{hub.name_and_role('sublead')} reads its result and links it", said)
        kref = hub.iref(kept["id"])
        first = self.rule("hand", saved_in=kept["setup_task"])
        self.link("manager", kept, first)
        newer = self.rule("hand", saved_in=kept["setup_task"])
        self.assertIn("above you", self.kpi_refused("sublead", id=kref, check=newer["id"], how="x"))
        self.assertIn("above you", self.kpi_refused("sublead", id=kref, measured_by="hand"))

        def name_who(r):
            row = self.kpi(r)
            with hub.transaction():
                return hub.kpi_name_who_rows(row, "No value for two windows.", hub.now())
        step = name_who(kept)
        self.assertIsNone(hub.kpi_locked("sublead", self.kpi(kept), {"measured_by", "check"}, None))
        self.end(step["task"])                      # its task ended with nothing done: the locks are back
        self.assertIn("above you", self.kpi_refused("sublead", id=kref, check=newer["id"], how="x"))
        name_who(kept)
        self.value(first, 90, self.clock + 8 * DAY)     # a value came: the step is over
        self.assertIn("above you", self.kpi_refused("sublead", id=kref, check=newer["id"], how="x"))
        hub.q("UPDATE standing SET kpi_state='no_data' WHERE id=?", (kept["id"],))      # as the daily pass does
        self.clock += 60
        name_who(kept)
        with hub.transaction():         # a run with no new value: its old one moves the state, and ends no step
            hub.kpi_state_rows(kept["id"], hub.now())
        self.link("sublead", kept, newer)           # the parent restores the measurement, and the step is done
        self.assertIn("above you", self.kpi_refused("sublead", id=kref, measured_by="hand"))
        self.clock += 60
        name_who(kept)
        self.clock += 60
        self.kpi_ok("manager", id=kref, check=newer["id"], how="Drafts that staff sent as written.")   # made since
        self.assertIn("above you", self.kpi_refused("sublead", id=kref, check=first["id"], how="x"))
        # the step frees no end: an end passes every change that the KPI ever had, also one that the step freed
        mine, _ = self.set_kpi("sublead", "hand", name="Drafts mine")
        mref = hub.iref(mine["id"])
        self.kpi_ok("manager", id=mref, measured_by="hand")
        self.link("manager", mine, self.rule("hand", saved_in=self.kpi(mine)["setup_task"]))
        step = name_who(mine)
        self.assertNotIn("ended the KPI", hub.q1("SELECT done_when FROM tasks WHERE id=?", (step["task"],))["done_when"])
        self.assertIn("above you", self.refused("sublead", "end_standing", id=mref, why="No."))
        self.kpi_ok("sublead", id=mref, measured_by="hand")         # the parent names the measurer, as the step asks
        self.link("sublead", mine, self.rule("hand", saved_in=self.kpi(mine)["setup_task"]))       # and links its check
        self.assertIn("above you", self.refused("sublead", "end_standing", id=mref, why="No."))
        self.kpi_ok("manager", id=mref, measured_by="hand")
        name_who(mine)
        self.kpi_ok("manager", id=mref, words="Drafts that staff kept.")      # a new setup: the step is over
        self.assertIn("above you", self.kpi_refused("sublead", id=mref, measured_by="hand"))
        # a step in the fleet manager's inbox frees nothing for a lead that the agent moved under since
        top, _ = self.set_kpi("manager", "solo", name="Solo drafts")
        sref = hub.iref(top["id"])
        self.kpi_ok("manager", id=sref, measured_by="solo")
        self.assertIsNone(name_who(top).get("task"))
        team = json.loads(json.dumps(hub.TEAM))
        team["agents"]["solo"]["reports_to"] = "lead"
        hub.apply_team(team)
        self.assertIn("above you", self.kpi_refused("lead", id=sref, measured_by="solo"))

    def test_the_owners_message_sets_a_field_that_only_his_next_message_changes(self):
        """KPIs version 2, 4.4: a field set with asked_by, the owner's own message to the agent or to an agent above it
        up to the caller, with the new number in it, changes, and the KPI ends, only on a later message of his; a
        number that is not in his message makes the change the setter's own; a message that an AI session sent, one to
        another line or one to an agent above the caller, and his answer to a Needs-you item, ask for nothing; his
        message passes a rank's own change only when sent after it, and his later word passes his earlier ask
        whoever applied it. Protects against an agent above that overrules the owner's level, a level that a session's
        words lock, and his later word refused because his first one was applied late."""
        r, _ = self.set_kpi("lead", "hand")
        ref = hub.iref(r["id"])
        newest = "SELECT asked_by FROM kpi_changes WHERE item=? ORDER BY id DESC LIMIT 1"

        def says(recipient, text):          # a message of his, a minute after the last change
            self.clock += 60
            return f"M-{self.owner_says(recipient, text)}"
        loose = says("hand", "Make it a bit higher.")
        self.assertIn("is your own change", self.kpi_ok("lead", id=ref, number=85, asked_by=loose))
        self.assertIsNone(hub.q1(newest, (r["id"],))["asked_by"])
        asked = says("hand", "Make the drafts KPI 90%, please.")
        self.assertNotIn("your own change", self.kpi_ok("lead", id=ref, number=90, asked_by=asked))
        self.assertEqual(hub.q1(newest, (r["id"],))["asked_by"], asked)
        self.assertIn(f"The owner asked for {ref}'s number in {asked}", self.kpi_refused("manager", id=ref, number=95))
        self.assertIn("only on a later message", self.refused("manager", "end_standing", id=ref, why="Not needed."))
        higher = says("hand", "Raise it more.")       # no number: the manager's own, which his lock refuses
        self.assertIn("The owner asked", self.kpi_refused("manager", id=ref, number=96, asked_by=higher))
        again = says("lead", "Now 95 for the drafts.")      # a newer word of his, to an agent above it, passes a rank
        self.kpi_ok("manager", id=ref, number=95, asked_by=again)
        steady = says("hand", "Hold it steady.")        # a number in words is checked too
        self.assertIn("The owner asked", self.kpi_refused("lead", id=ref, number="70", asked_by=steady))
        self.assertIn("The owner asked", self.kpi_refused("lead", id=ref, direction="at_most"))   # what 95 means
        self.assertIn(f"{again} is not later than {again}", self.refused("lead", "end_standing", id=ref, why="Done.",
                                                                         asked_by=again))     # the one that locked it
        with hub.transaction():
            tool = hub.owner_message_rows(str(uuid.uuid4()), "message", None, "Set it to 50.", "founderizer-cli/1/test",
                                          "hand", None, hub.now(), session="claude-code/0d8aa41c")
        self.assertIn("AI session", self.kpi_refused("manager", id=ref, number=50, asked_by=f"M-{tool}"))
        other = says("solo", "Set it to 50.")
        self.assertIn("no message of the owner's to hand", self.kpi_refused("manager", id=ref, number=50,
                                                                            asked_by=other))
        top = says("manager", "Make the drafts KPI 99%.")      # the manager's to act on, not the lead's
        self.assertIn("went to manager", self.kpi_refused("lead", id=ref, number=99, asked_by=top))
        self.assertEqual(self.item(r["id"])["number"], 95)
        # he wrote twice before his first word was applied: his later word goes through
        first, second = says("lead", "Make it 97."), says("lead", "No, 98.")
        last = says("hand", "Make it 96 after all.")
        self.clock += 60
        self.kpi_ok("manager", id=ref, number=97, asked_by=first)
        self.kpi_ok("manager", id=ref, number=98, asked_by=second)
        self.assertEqual(self.item(r["id"])["number"], 98)
        self.kpi_ok("lead", id=ref, number=96, asked_by=last)     # his latest word, whoever applied the ones before
        self.assertEqual(self.item(r["id"])["number"], 96)
        answer = says("hand", "Set it to 60.")            # his answer to a Needs-you item is no message of his
        hub.q("UPDATE ui_requests SET kind='answer' WHERE event_id=?", (int(answer[2:]),))
        self.assertIn("no message of the owner's", self.kpi_refused("manager", id=ref, number=60, asked_by=answer))
        pair = says("lead", "Raise it from 91 to 92.")     # one message of his sets a field again, never ends it
        self.kpi_ok("manager", id=ref, number=91, asked_by=pair)
        self.kpi_ok("manager", id=ref, number=92, asked_by=pair)
        self.assertIn(f"{pair} is not later", self.refused("manager", "end_standing", id=ref, why="No.", asked_by=pair))
        self.assertIn("The owner asked", self.kpi_refused("manager", id=ref, direction="at_most", asked_by=pair))
        # a message of his from before an agent above changed a field does not pass that agent's rank
        before = says("lead", "Call it Drafts kept.")
        self.clock += 60
        self.kpi_ok("manager", id=ref, name="Drafts kept")
        self.assertIn("above you", self.kpi_refused("lead", id=ref, name="Drafts as sent", asked_by=before))
        self.kpi_ok("lead", id=ref, name="Drafts as sent", asked_by=says("lead", "Call it Drafts as sent."))
        named = says("lead", "Call it Drafts read, at 93.")     # the same message again: the number alone
        self.kpi_ok("manager", id=ref, name="Drafts read", number=93, asked_by=named)
        self.assertIn(f"{named} is not later", self.kpi_refused("manager", id=ref, name="Drafts kept", asked_by=named))
        # the step "Name who measures" frees his choice of the measurer for the parent that it went to, and no other
        self.kpi_ok("lead", id=ref, measured_by="lead", asked_by=says("lead", "Measure it yourself."))
        row = self.item(r["id"])
        with hub.transaction():
            hub.kpi_name_who_rows(row, "Its rule was deleted.", hub.now())
        self.assertIn("The owner asked", self.kpi_refused("manager", id=ref, measured_by="hand"))
        self.assertIsNotNone(hub.kpi_step_open(self.item(r["id"]), "lead"))
        team = json.loads(json.dumps(hub.TEAM))     # nor for its task's owner once that is no longer the parent
        team["agents"]["hand"]["reports_to"] = "sublead"
        hub.apply_team(team)
        self.assertIsNone(hub.kpi_step_open(self.item(r["id"]), "lead"))
        team = json.loads(json.dumps(hub.TEAM))
        team["agents"]["hand"]["reports_to"] = "lead"
        hub.apply_team(team)
        self.kpi_ok("lead", id=ref, measured_by="hand")
        self.ok("lead", "end_standing", id=ref, why="The owner asked.", asked_by=says("hand", "End the drafts KPI."))
        self.assertEqual(self.item(r["id"])["ended_by"], "owner")
        # his figures, read every way that a writer may mean them, and no ref or digit inside a word
        self.assertEqual(hub.kpi_figures("1,000 tickets in 4,5 h or 4.5 h, 80%, 1.000.000, 2.500, .5, -5 or 28-30, "
                                         "5k, I-116, x5, 1,2.5, 16.1k, 0.500, =-5, 20%-30%, \u22125, I\u2212116"),
                         [1.0, 1000.0, 4.5, 4.5, 80.0, 1000000.0, 2.5, 2500.0, 0.5, -5.0, 28.0, 30.0, 5000.0,
                          16100.0, 0.5, -5.0, 20.0, 30.0, -5.0])

    def test_a_leads_owner_chat_sets_its_teams_kpi_on_his_message_and_a_workers_chat_has_none(self):
        """KPIs version 2, 4.4: a lead's owner chat gets set_kpi, only with the owner's message to that chat as
        asked_by, and see_history for KPIs alone, while the setting kpis is on; a worker's chat and a Shell-off lead's
        get neither, and a worker's chat is told where the owner's words about its own KPIs go. Protects against a chat
        that sets a KPI on its own words, and a worker that changes its own."""
        names = lambda who: {t["name"] for t in hub.tools_for(who, test_standing.CHAT)}
        chat = lambda name, **args: hub.call_tool("lead", name, args, test_standing.CHAT)
        self.assertLessEqual({"set_kpi", "see_history"}, names("lead"))
        self.assertFalse({"set_kpi", "see_history"} & names("hand"))
        r, _ = self.set_kpi("lead", "hand")
        ref = hub.iref(r["id"])
        text, err = chat("set_kpi", id=ref, number=85)
        self.assertTrue(err and "asked_by" in text, text)
        to_hand = self.owner_says("hand", "Make it 85.")
        text, err = chat("set_kpi", id=ref, number=85, asked_by=f"M-{to_hand}")       # not a message to this chat
        self.assertTrue(err, text)
        said = self.owner_says("lead", "Make hand's drafts KPI 85%.")
        text, err = chat("set_kpi", id=ref, number=85, asked_by=f"M-{said}")
        self.assertFalse(err, text)
        self.assertEqual(self.item(r["id"])["number"], 85)
        self.assertIn("what must be one of kpis.", chat("see_history", what="costs")[0])
        self.assertTrue(chat("end_standing", id=ref, why="He asked.", asked_by=f"M-{said}")[1])    # its own lock
        self.clock += 60
        text, err = chat("end_standing", id=ref, why="He asked.",
                         asked_by=f"M-{self.owner_says('lead', 'End the drafts KPI of hand.')}")
        self.assertFalse(err, text)
        r, _ = self.set_kpi("lead", "hand")
        ref = hub.iref(r["id"])
        text, err = chat("end_standing", id=ref, why="He asked.")      # an end in a chat needs his message too
        self.assertTrue(err and "asked_by" in text, text)
        self.assertIn(ref, chat("see_history")[0])
        words = lambda who: hub.rpc(who, {"id": 1, "method": "initialize", "params": {}}, {},
                                    test_standing.CHAT)["result"]["instructions"]
        self.assertIn("pass their words to lead with message_agent", words("hand"))
        self.assertIn("do it here with set_kpi or end_standing", words("lead"))
        hub.TEAM["agents"]["sublead"]["can"] = []           # a lead whose Shell box is off
        self.assertFalse({"set_kpi", "see_history"} & names("sublead"))
        hub.TEAM["settings"]["kpis"] = False
        self.assertFalse({"set_kpi", "see_history"} & names("lead"))
        self.assertNotIn("KPI", words("hand"))

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
        A measurer whose Shell box is off writes no check, so the parent names who measures. Protects against a KPI
        that waits for ever on a check that prints the wrong metric, or on an agent that cannot write one, and a task
        each day."""
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
        named = lambda: hub.q1("SELECT COUNT(*) n FROM tasks WHERE owner='lead' AND title=?",
                               ("Name who measures Drafts sent as written",))["n"]
        self.value(rule, 90, r["linked_at"] + 32 * DAY)
        can = hub.TEAM["agents"]["hand"].get("can")
        hub.TEAM["agents"]["hand"]["can"] = []         # its Shell box is off: it writes no check any more
        with hub.transaction():
            hub.kpi_daily_rows(r["linked_at"] + 46 * DAY)
        self.assertEqual((again(), named()), (2, 1))
        self.assertIn("has its Shell box off", self.kpi_refused("lead", id=hub.iref(r["id"]), words="All drafts sent."))
        if can is None:
            hub.TEAM["agents"]["hand"].pop("can")
        else:
            hub.TEAM["agents"]["hand"]["can"] = can
        revision = hub.trigger_row(rule["id"])["revision"]          # the link changed its schedule, so its revision
        with hub.transaction():
            hub.trigger_state_rows(rule["id"], revision, "delete", "hand", hub.now())
        self.assertIsNone(self.kpi(r)["check"])
        self.assertEqual(named(), 2)


class StartText(Kpis):
    def test_an_agent_with_a_shell_reads_its_judged_value_and_one_without_reads_its_level_alone(self):
        """KPIs version 2, 4.5: a KPI line holds its name, level, words and part, and in a session of an agent with a
        shell its newest judged value with its days and whether that value is on target; never a value for a Shell-off
        agent; the hub's sentence once, and no end sentence for a KPI. Protects against an agent that does not know
        where its KPI stands, and a number in each session of a ticket agent."""
        r, _ = self.set_kpi("lead", "hand", words="Most tickets that arrived got a draft that staff sent as written.")
        ref = hub.iref(r["id"])
        rule = self.rule("hand", saved_in=r["setup_task"])
        self.link("lead", r, rule)
        self.assertIn(f"{ref} KPI from Lead: Drafts sent as written, at least 80%; no judged value yet. Most tickets "
                      f"that arrived got a draft that staff sent as written. [your part: Mark each ticket that you "
                      f"answer with a draft.]", hub.standing_start_text("hand"))
        linked = self.kpi(r)["linked_at"]
        self.value(rule, 41.5, linked + DAY)            # shown, not judged: its part gives one window first
        self.assertIn("no judged value yet", hub.standing_start_text("hand"))
        self.value(rule, 85, linked + 8 * DAY)
        self.assertIn("at least 80%; 85% for 28 Oct-4 Nov, on target. Most tickets", hub.standing_start_text("hand"))
        hub.q("UPDATE standing SET kpi_state='no_data' WHERE id=?", (r["id"],))     # no value in its last window
        self.assertIn("85% for 28 Oct-4 Nov, its newest judged value, and none since.", hub.standing_start_text("hand"))
        self.value(rule, 60, linked + 9 * DAY)
        text = hub.standing_start_text("hand")
        self.assertIn("at least 80%; 60% for", text)
        self.assertIn(", off target. Most tickets", text)
        self.assertEqual(text.count("A KPI measures your work and never limits it"), 1)
        self.assertNotIn("end_standing", text)
        self.ok("lead", "keep_instruction", words="Answer in Spanish.", scope="team")
        self.assertIn("end_standing, never a KPI", hub.standing_start_text("hand"))
        closed, _ = self.set_kpi("lead", "closed", measured_by="lead")
        own = self.rule("lead")
        self.link("lead", closed, own)
        self.value(own, 85, self.kpi(closed)["linked_at"] + 8 * DAY)
        line = hub.standing_start_text("closed")
        self.assertIn(f"{hub.iref(closed['id'])} KPI from Lead: Drafts sent as written, at least 80%. Of all", line)
        self.assertNotIn("85", line)

    def test_a_note_from_above_waits_for_a_task_of_the_parents_own_work(self):
        """KPIs version 2, 4.4 and spec 7.4: the parent's note of a change from above waits under no task for its next
        task session, never one that a conversation opened, whose start holds no KPI either; a task that ends unread
        gives it back; it is dropped once the agent is no longer the parent. Protects against a person's session that
        reads the owner's KPI words, and a note that a short task swallows."""
        r, _ = self.set_kpi("lead", "hand")
        own, _ = self.set_kpi("manager", "lead", name="Team drafts")
        self.kpi_ok("manager", id=hub.iref(r["id"]), number=85)
        note = hub.q1("SELECT id FROM events WHERE agent='lead' AND "
                      "json_extract(extra, '$.kpi_note') IS NOT NULL")["id"]
        filed = lambda: hub.q1("SELECT task, read_at FROM events WHERE id=?", (note,))
        pid = self.person(agents=("lead",))
        conv = hub.q1("SELECT * FROM conversations WHERE id=?", (self.conversation(pid, agent="lead"),))
        opened, _ = hub.conversation_line_task("lead", conv, hub.q1("SELECT * FROM people WHERE id=?", (pid,)),
                                               "Look at the drafts", "", "Asked the team", "A person asked.")
        self.assertIsNone(filed()["task"])
        start = hub.q1("SELECT text FROM events WHERE task=? AND kind='task'", (opened,))["text"]
        self.assertNotIn(hub.iref(own["id"]), start)
        later = self.new_task("lead", title="The next task")
        with hub.transaction():
            hub.waiting_say_rows("lead", later)
        self.assertEqual(filed()["task"], later)
        hub.unfile_notices(later)                # it ended before its session read the note
        self.assertIsNone(filed()["task"])
        team = json.loads(json.dumps(hub.TEAM))
        team["agents"]["hand"]["reports_to"] = "sublead"
        hub.apply_team(team)
        another = self.new_task("lead", title="Another task")
        with hub.transaction():
            hub.waiting_say_rows("lead", another)
        self.assertEqual((filed()["task"], filed()["read_at"] is not None), (None, True))

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
        self.assertIn("no KPI: hand, sublead, closed", first)      # as the team list: the name, and a role
        self.assertNotIn("Set KPIs", hub.start_text("lead", self.tasks["lead"]))
        self.assertIn("no KPI: lead, solo", hub.manager_resume_text())     # F16: as the team list writes them
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
        self.assertIn(f"{hub.iref(r['id'])} hand: Drafts sent as written.", text)       # no role: the name alone
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
        # a whole row of agent_limits, as active_limit gives it: the hold of seo's own route, and of no other route
        limit = dict({c["name"]: None for c in hub.q("PRAGMA table_info(agent_limits)")}, id=1, agent="seo",
                     since=self.clock, until=self.clock + 7200, reset_known=1, route="primary")
        with patch.object(hub, "active_limit", lambda agent, route="primary": limit
                          if (agent, route) == ("seo", "primary") else None):
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

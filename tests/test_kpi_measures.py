"""The hub's own numbers for KPIs (~/dev/founderizer-plans/agent-kpis-v2/plan.md 4.3 and 4.8): the hub measure
reports_came_back and its past, and the input "reports" that the hub adds to a line check's args at each send.
In-process hub, a temporary database and fixed data; no helper, no fleet and no AI call.

    python3 -m unittest -v test_kpi_measures
"""
import datetime
import json
import unittest
import uuid
from unittest.mock import patch

import hub
import test_kpis
from test_standing import MADRID, at

DAY = 86400
END = at("2026-11-08T12:00")        # the end of the measured window of 7 days
SECRETS = ("The card of the customer was charged twice", "customer@example.com", "wrong_charge", "billing",
           "inv-4471", "2026-11-01T10:00")       # summary, email, symptom, component, ids and seen_at of each report


def load_tests(loader, _tests, _pattern):
    """Only this file's cases, not the inherited ones."""
    suite = unittest.TestSuite()
    for cls in (CameBack, ReportsInput, Linked):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Records(test_kpis.Kpis):
    """Duties, cases and typed reports, written as the hub writes them: the duty of `solo` reports the tickets of its
    customers to the duty of `hand`."""

    def setUp(self):
        super().setUp()
        self.duties = {name: self.duty(name) for name in ("hand", "solo", "deep", "sublead")}

    def duty(self, agent):
        t = self.clock
        return hub.ins("INSERT INTO responsibilities(agent,text,state,revision,created,updated,created_by,request_id) "
                       "VALUES(?,?,'active',1,?,?,'manager',?)", (agent, f"The duty of {agent}", t, t,
                                                                  str(uuid.uuid4())))

    def case(self, agent, closed=None):
        return hub.ins("INSERT INTO duty_cases(responsibility,key,title,source,state,opened,by,closed) VALUES(?,?,"
                       "'A defect','report',?,?,?,?)", (self.duties[agent], f"case-{uuid.uuid4().hex[:8]}",
                                                        "closed" if closed else "open", END - 30 * DAY, agent,
                                                        closed))

    def report(self, ticket, created, to="hand", by="solo", covered=None, closed=None):
        """One typed report of `by`'s duty to `to`'s duty, joined to a case of its own, closed at `closed`; a cover
        is the close of the case that covers it."""
        case = self.case(to, closed=closed or covered)
        return hub.ins("INSERT INTO duty_reports(from_duty,from_case,from_task,ticket,to_duty,symptom,component,ids,"
                       "duty_case,covered,created,summary,email,seen_at) VALUES(?,1,1,?,?,?,?,?,?,?,?,?,?,?)",
                       (self.duties[by], ticket, self.duties[to], SECRETS[2], SECRETS[3], json.dumps([SECRETS[4]]),
                        case, covered, created, SECRETS[0], SECRETS[1], SECRETS[5]))


class CameBack(Records):
    """reports_came_back: the share of the tickets reported to an agent's duties that came back."""

    def setUp(self):
        super().setUp()
        self.report("T-1", END - 6 * DAY, covered=END - 5 * DAY)        # covered, then a new report: back
        self.report("T-1", END + 2 * DAY)
        self.report("T-2", END - 6 * DAY, closed=END - 4 * DAY)         # its case closed with no cover, then a new
        self.report("T-2", END + 5 * DAY)                                # report: back
        self.report("T-3", END - 5 * DAY, covered=END - 4 * DAY)        # covered, no new report
        self.report("T-3", END + 1 * DAY, by="deep")                     # the same key from another duty: no repeat
        self.report("T-4", END - 5 * DAY)                                # still open 14 days after: back
        self.report("T-5", END - 4 * DAY, covered=END - 3 * DAY)        # back only 15 days after the window
        self.report("T-5", END + 15 * DAY)
        self.report("T-6", END - 3 * DAY, covered=END - 1 * DAY)        # a second report while the first was open
        self.report("T-6", END - 2 * DAY, covered=END - 1 * DAY)
        self.report("T-7", END - 2 * DAY, closed=END - 1 * DAY)         # its case closed with no cover, no report
        self.report("T-8", END - 2 * DAY, to="deep")                     # another agent's duty: not in the base
        self.report("T-9", END - 2 * DAY, closed=END + 12 * DAY)        # closed late, then a new report within 14
        self.report("T-9", END + 20 * DAY)                               # days of the close: back

    def measure(self, t0, lag=True, agent="hand"):
        return hub.hub_measure_reports_came_back(agent, END, 7, lag=lag, t0=t0)

    def test_a_ticket_comes_back_by_a_new_report_after_its_end_or_by_staying_open(self):
        """Plan 4.3: of 8 tickets, T-1 (a report after its cover), T-2 (after its case's close), T-9 (within 14 days
        of a late close) and T-4 (open 14 days after the window) came back. Protects against a measure that the agent
        moves with covers, an open case or the time of its close: a close with no cover read as open (T-7), a report
        while the first is open (T-6), one more than 14 days after the cover (T-5), another duty's ticket of the same
        key (T-3), a base of covered tickets only, or a repeat after a close late in the 14 days not counted (T-9),
        each moves the share."""
        self.assertAlmostEqual(self.measure(END + 28 * DAY), 400 / 8)
        self.assertIs(hub.HUB_MEASURES["reports_came_back"], hub.hub_measure_reports_came_back)

    def test_the_judged_value_waits_for_the_lag_and_the_value_so_far_comes_at_once(self):
        """Plan 4.3 and 4.8: the judged value exists 28 days after the window's end, when a close 14 days after it has
        had its own 14 days; the value so far shows at once and counts only what has happened. Protects against a
        judged value that comes before a ticket could come back, and a value so far that counts an open report before
        its 14 days or a report of the future."""
        self.assertIsNone(self.measure(END + 28 * DAY - 1))
        self.assertAlmostEqual(self.measure(END + 28 * DAY), 400 / 8)
        self.assertAlmostEqual(self.measure(END, lag=False), 0)
        self.assertAlmostEqual(self.measure(END + 3 * DAY, lag=False), 100 / 8)        # T-1
        self.assertAlmostEqual(self.measure(END + 6 * DAY, lag=False), 200 / 8)        # T-1 and T-2
        self.assertAlmostEqual(self.measure(END + 14 * DAY, lag=False), 300 / 8)       # and T-4, open
        self.assertAlmostEqual(self.measure(END + 20 * DAY, lag=False), 400 / 8)       # and T-9: the judged value

    def test_a_window_of_fewer_than_five_tickets_has_no_value(self):
        """Plan 4.3: below 5 tickets in a window there is none. Protects against a share of 1 of 2 tickets that
        would read as 50% and give a step for nothing."""
        for n in range(4):
            self.report(f"S-{n}", END - DAY, to="sublead", covered=END)
        self.assertIsNone(self.measure(END + 28 * DAY, agent="sublead"))
        self.assertIsNone(self.measure(END + 28 * DAY, lag=False, agent="sublead"))
        self.report("S-4", END - DAY, to="sublead")
        self.assertAlmostEqual(self.measure(END + 28 * DAY, agent="sublead"), 20)

    def test_the_past_gives_each_day_its_value_so_far_in_the_fleet_s_day(self):
        """Plan 4.2 and 4.8: a new KPI shows its past at once. Each day has the value so far of the window that ends
        at its end, in the fleet's own day (Madrid here), so a past day and a live point of that day share one row of
        kpi_points. Protects against a past from the judged value (no recent day), days of UTC or a time at midnight
        (item_day(at) one day late), and a day of fewer than 5 tickets with a value."""
        t0 = END + 3 * DAY
        self.report("X-1", END + DAY)
        self.report("X-2", END + 2 * DAY)
        past = hub.hub_measure_past("reports_came_back", "hand", 7, t0)
        today = hub.hub_measure_reports_came_back("hand", t0, 7, lag=False, t0=t0)
        self.assertIsNotNone(today)
        self.assertEqual(past[-1], (hub.item_day(t0), today, t0))
        self.assertEqual(past[0][0], hub.item_day(END - 4 * DAY))      # the first day with 5 tickets in its window
        self.assertEqual([day for day, _, _ in past], sorted({day for day, _, _ in past}))
        for day, value, end in past[:-1]:
            self.assertEqual(hub.item_day(end), day)
            self.assertEqual(datetime.datetime.fromtimestamp(end + 1, MADRID).strftime("%H:%M:%S"), "00:00:00")
            self.assertEqual(value, hub.hub_measure_reports_came_back("hand", end, 7, lag=False, t0=t0))
        self.assertNotIn(hub.item_day(END - 5 * DAY), [day for day, _, _ in past])     # 4 tickets in its window


class ReportsInput(Records):
    """A line check that names the input reports gets the typed reports to its agent's duties in its args."""

    def setUp(self):
        super().setUp()
        hub.TEAM["agents"]["hand"].update(start="claude --permission-mode dontAsk {settings} {prompt}", allow=["Bash"])
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES('hand',?,?)",       # a helper that runs checks
              (json.dumps({"features": ["trigger_check", "trigger_code", "check_lines"]}), hub.now()))

    def save(self, check):
        """hand saves a rule with this check in its task's session. (Base.tool takes `task` for the session.)"""
        tid = hub.tref(self.tasks["hand"])
        return hub.call_tool("hand", "save_trigger", {
            "request_id": str(uuid.uuid4()), "check": check, "schedule": {"kind": "every", "minutes": 15},
            "task": {"title": "Fix time", "details": "", "done_when": "x", "needs": "none", "goal_id": None},
            "task_id": tid}, ("test-generation", tid, 1))

    def sent(self, t):
        """One send of rule t's check: the helper's job, and its one argument as fleet.run_source writes it."""
        hub.q("UPDATE trigger_runs SET state='quiet' WHERE trigger_id=?", (t["id"],))      # one open run at a time
        due = self.clock + hub.q1("SELECT COUNT(*) n FROM trigger_runs")["n"]
        run = hub.ins("INSERT INTO trigger_runs(trigger_id,revision,due,manual,check_now,state,created) "
                      "VALUES(?,?,?,0,0,'waiting',?)", (t["id"], t["revision"], due, self.clock))
        t = hub.trigger_row(t["id"])
        with hub.transaction():
            hub.dispatch_check(t, run, self.clock)
        extra = json.loads(hub.q1("SELECT extra FROM events WHERE kind='trigger_check' ORDER BY id DESC LIMIT 1")
                           ["extra"])
        return extra, json.dumps({"trigger": extra["trigger"], "run": extra["run"], "args": extra.get("args") or {}})

    def test_a_check_with_the_reports_input_gets_ids_and_times_and_nothing_else(self):
        """Plan 4.3: the hub's reports give a KPI check such as a fix time its start, with ids and times only. Protects
        against a save that drops the input, the reports of another agent's duties or of more than 56 days, the
        newest not first, the check's own args lost, and a report's summary or the customer's email on a machine."""
        text, err = self.save({"code": "print('ok')\n", "args": {"repo": "acme/web"}, "inputs": ["reports"]})
        self.assertFalse(err, text)
        t = hub.q1("SELECT * FROM triggers ORDER BY id DESC LIMIT 1")
        self.assertEqual(json.loads(t["check_spec"])["inputs"], ["reports"])
        old = self.report("T-1", self.clock - 3 * DAY, covered=self.clock - DAY)
        new = self.report("T-2", self.clock - DAY)
        self.report("T-3", self.clock - 57 * DAY)                       # older than 56 days
        self.report("T-4", self.clock - DAY, to="deep")                 # another agent's duty
        extra, _ = self.sent(t)
        cases = {r["id"]: r["duty_case"] for r in hub.q("SELECT id, duty_case FROM duty_reports")}
        self.assertEqual(extra["args"], {"repo": "acme/web", "reports": {
            "since": int(self.clock - 56 * DAY), "more": False, "rows": [
                {"id": new, "from_duty": self.duties["solo"], "ticket": "T-2", "created": int(self.clock - DAY),
                 "covered": None, "case": cases[new], "case_closed": None},
                {"id": old, "from_duty": self.duties["solo"], "ticket": "T-1", "created": int(self.clock - 3 * DAY),
                 "covered": int(self.clock - DAY), "case": cases[old], "case_closed": int(self.clock - DAY)}]}})
        raw = json.dumps(extra)
        self.assertEqual([word for word in SECRETS if word in raw], [])
        for check, said in (({"code": "x = 1\n", "inputs": ["reports"], "args": {"reports": []}}, "cannot have reports"),
                            ({"code": "x = 1\n", "inputs": ["mail"]}, "check.inputs must be")):
            text, err = self.save(check)
            self.assertTrue(err, text)
            self.assertIn(said, text)

    def test_the_reports_input_keeps_to_its_caps_and_marks_what_it_left_out(self):
        """Plan 4.3: at most 500 rows, the newest first, in one argument of at most 131,071 bytes (one Linux argument)
        with static args of 4 KiB, and a mark when rows were left out. 500 rows of the longest tickets fit in that
        argument, so a smaller limit shows the cut by size. Protects against a check that does not start (an argument
        too long, measured in compact JSON while the helper writes spaces and escapes), a cut that keeps the oldest,
        and a check that reads a part as the whole."""
        self.clock = END
        spec = dict(test_kpis.LINES, inputs=["reports"])
        t = self.rule("hand")
        hub.q("UPDATE triggers SET check_spec=? WHERE id=?", (json.dumps(spec), t["id"]))
        for n in range(3):
            self.report(f"T-{n}", END - DAY + n)
        extra, _ = self.sent(t)
        self.assertEqual((len(extra["args"]["reports"]["rows"]), extra["args"]["reports"]["more"]), (3, False))
        with hub.transaction():
            hub.DB.executemany("INSERT INTO duty_reports(from_duty,from_case,from_task,ticket,to_duty,symptom,"
                               "component,ids,created) VALUES(?,1,1,?,?,'s','c','[]',?)",
                               [(self.duties["solo"], f"U-{n}", self.duties["hand"], END - 2 * DAY - n)
                                for n in range(600)])
        extra, given = self.sent(t)
        rows = extra["args"]["reports"]["rows"]
        self.assertEqual((len(rows), extra["args"]["reports"]["more"]), (500, True))
        self.assertEqual([r["ticket"] for r in rows[:4]], ["T-2", "T-1", "T-0", "U-0"])
        self.assertEqual(rows[-1]["ticket"], "U-496")
        self.assertLess(len(given), hub.CHECK_ARG_MAX)
        # the longest tickets and the largest static args: fewer rows, as many as fit, and the mark
        hub.q("UPDATE duty_reports SET ticket='K' || id || substr(?, 1, 79 - length(id))", ("x" * 80,))
        big = {"note": "ñ" * 2000}                  # 4,000 bytes of compact UTF-8; 12,000 characters as escapes
        self.assertLessEqual(len(json.dumps(big, ensure_ascii=False, separators=(",", ":")).encode()),
                             hub.CHECK_ARGS_MAX)
        hub.q("UPDATE triggers SET check_spec=? WHERE id=?", (json.dumps(dict(spec, args=big)), t["id"]))
        extra, given = self.sent(t)
        self.assertEqual((len(extra["args"]["reports"]["rows"]), extra["args"]["reports"]["more"]), (500, True))
        self.assertLess(len(given), hub.CHECK_ARG_MAX)
        with patch.object(hub, "CHECK_ARG_MAX", 40000):
            extra, given = self.sent(t)
        rows = extra["args"]["reports"]["rows"]
        self.assertLessEqual(len(given), 40000)
        self.assertGreater(len(given), 40000 - 300)          # full: no row more would fit
        self.assertLess(len(rows), 500)
        self.assertTrue(extra["args"]["reports"]["more"])
        self.assertEqual((extra["args"]["note"], rows[0]["created"]), (big["note"], int(END - DAY + 2)))

    def test_the_input_s_name_is_part_of_the_check_s_digest(self):
        """Plan 4.3: a KPI's value comes from the check that its parent read, and a mark on the chart says when that
        check changed. Protects against an input that changes what the check reads with no mark, and a release that
        changes the digest of each check that has no input, which would mark every chart."""
        self.assertEqual(hub.kpi_digest(test_kpis.LINES), "6b68ceab7584")      # the digest before inputs existed
        self.assertNotEqual(hub.kpi_digest(dict(test_kpis.LINES, inputs=["reports"])), "6b68ceab7584")


class Linked(Records):
    """A KPI that its parent links to the hub measure reports_came_back (plan 4.3, 4.8): the hub counts it with no
    check and no measuring agent."""

    def setUp(self):
        super().setUp()
        self.clock = END
        for n in range(1, 5):                       # four tickets, each covered a day after its report
            self.report(f"A-{n}", END - (7 - n) * DAY, covered=END - (6 - n) * DAY)
        self.report("A-5", END - 2 * DAY)           # open: it counts as come back only 14 days after its window
        self.report("A-1", END - DAY)               # A-1 came back after its cover, and is open

    def points(self, r, past=None):
        return [(p["day"], round(p["value"], 2)) + (() if past is not None else (p["backfill"],)) for p in
                hub.q("SELECT day, value, backfill FROM kpi_points WHERE item=? AND (? IS NULL OR backfill=?) ORDER "
                      "BY day", (r["id"], past, past))]

    def test_a_hub_measure_shows_its_past_and_its_value_at_once_counts_again_at_each_event_and_judges_final_values(
            self):
        """Plan 4.2, 4.3, 4.8: the link shows the past days and today's value so far at once, and tells the setup task
        that it is no longer needed; an event counts every day that is not final again at once, past days too; each
        day's value is counted again as final once its 28 days have passed, and only a live one is then judged; a KPI
        of another unit or direction cannot link, nor change to one after. Protects against a tab that waits for a
        daily pass, past days that stay too low and green for weeks, a value that the agent moves before a ticket could
        come back, a count so far that gives a step for nothing, a setup that the agent goes on building, and a share
        drawn as hours or judged the wrong way round."""
        hours, _ = self.set_kpi("lead", "hand", name="Defect fix time", metric="fix_hours", direction="at_most",
                                number=4, unit="h", words="Defects fixed within 4 hours, over 7 days.")
        link = {"id": hub.iref(hours["id"]), "check": "hub:reports_came_back", "how": "The hub's reports."}
        self.assertIn("gives a value in %", self.kpi_refused("lead", **link))
        self.kpi_ok("lead", id=hub.iref(hours["id"]), unit="%", direction="at_least")
        self.assertIn("direction is at_most", self.kpi_refused("lead", **link))
        r, _ = self.set_kpi("lead", "hand", name="Defects that come back", metric="reports_came_back",
                            direction="at_most", number=20, words="Of the tickets reported to the duty, at most 20% "
                            "come back within 14 days, over 7 days.")
        done = self.tasks["hand"]                   # an off-target task of an earlier spell, which ended
        self.end(done)
        hub.q("UPDATE standing SET off_task=? WHERE id=?", (done, r["id"]))
        text = self.kpi_ok("lead", id=hub.iref(r["id"]), check="hub:reports_came_back",
                           how="The hub's typed reports to the duties of hand.")
        self.assertIn("past 56 days show at once", text)
        self.assertIn("final 28 days after its window ends", text)
        k = self.kpi(r)
        self.assertEqual((k["source"], k["check"], k["kpi_state"], k["off_task"]),
                         ("hub:reports_came_back", None, "no_data", None))       # the ended step's marker cleared
        said = [e["text"] for e in hub.q("SELECT text FROM events WHERE kind='say' AND task=?", (r["setup_task"],))]
        self.assertTrue(any("this setup is no longer needed" in text for text in said), said)
        past = [(day, round(v, 2), 1) for day, v, _ in hub.hub_measure_past("reports_came_back", "hand", 7, END)
                if day < hub.item_day(END)]
        today = hub.hub_measure_reports_came_back("hand", END, 7, lag=False, t0=END)
        self.assertEqual([v for _, v, _ in past], [20.0, 20.0])         # as the hub knows them at the link
        self.assertEqual(self.points(r), past + [(hub.item_day(END), round(today, 2), 0)])
        code, data = self.request("/ui/kpis?db=test-generation&agent=hand&weeks=1")
        kpi = next(x for x in data["kpis"] if x["id"] == r["id"])
        self.assertEqual((code, kpi["value"], kpi["value_counts"], kpi["state"]), (200, 20.0, True, "on"))
        # an event counts it again at once: a sixth ticket, open
        self.clock = END + 3600
        self.report("A-6", self.clock)
        with hub.transaction():
            hub.kpi_measure_agents_rows(["hand"], self.clock)
        self.assertEqual(self.points(r)[-1], (hub.item_day(END), round(100 / 6, 2), 0))
        self.assertEqual(self.kpi(r)["kpi_state"], "no_data")            # a value so far is never judged
        # the daily pass a day later: a new day's value so far; nothing is final yet
        self.clock = END + DAY
        with hub.transaction():
            hub.kpi_daily_rows(self.clock)
        self.assertEqual(len(self.points(r, past=0)), 2)
        self.assertEqual(self.kpi(r)["kpi_state"], "no_data")
        # a repeat of A-2 within 14 days of its cover moves each day that holds A-2 at once, past days too
        self.clock = END + DAY + 3600
        self.report("A-2", self.clock)
        with hub.transaction():
            hub.kpi_measure_agents_rows(["hand"], self.clock)
        self.assertEqual([v for _, v in self.points(r, past=1)], [40.0, 40.0])     # A-1 and A-2 of 5
        self.assertEqual(self.points(r, past=0)[0][1], round(200 / 6, 2))          # the link's day: of 6
        # 28 days after the newer day's last count: every day is counted again as final; A-5 and A-6 stayed open
        self.clock = END + 30 * DAY
        with hub.transaction():
            hub.kpi_daily_rows(self.clock)
        self.assertEqual([v for _, v in self.points(r, past=1)], [60.0, 60.0])     # past days: shown, final
        self.assertEqual([v for _, v in self.points(r, past=0)], [round(400 / 6, 2)] * 2)
        k = self.kpi(r)
        self.assertEqual(k["kpi_state"], "off")
        self.assertNotIn(k["off_task"], (None, done))                    # the ladder starts again
        # new words of how keep the link and what it judged
        self.kpi_ok("lead", id=hub.iref(r["id"]), check="hub:reports_came_back",
                    how="The hub's typed reports to the duties of hand, which the support duty sends.")
        self.assertEqual({key: self.kpi(r)[key] for key in ("linked_at", "kpi_state", "off_task")},
                         {key: k[key] for key in ("linked_at", "kpi_state", "off_task")})
        self.assertEqual(len(self.points(r)), 4)
        for change, said in (({"unit": "h"}, "gives a value in %"), ({"direction": "at_least"}, "is at_most")):
            self.assertIn(said, self.kpi_refused("lead", id=hub.iref(r["id"]), **change))
        self.assertEqual((self.kpi(r)["unit"], self.kpi(r)["direction"]), ("%", "at_most"))
        # a new measuring agent: the hub's values measured something else
        self.kpi_ok("lead", id=hub.iref(r["id"]), measured_by="hand")
        self.assertEqual((self.points(r), self.kpi(r)["source"]), ([], None))

if __name__ == "__main__":
    unittest.main()

"""A write and the receipt that says it happened land together, or neither lands.

RULES.md promises an agent that a repeat of the same `request_id` is safe: the work is done once and the answer comes
back the same. A write that commits in halves breaks that promise in whichever direction the halves fall. The hub
that marked a hold `stopped` and then wrote the unknown outcomes left nobody told to check whether a send went out;
the one that retired a duty and then kept the receipt answered the manager's repeat "retire does not apply", which
says the write did not apply when it did.

So each case here drives one write to the point between its halves, ends the hub process there, opens the file again
as a new process does, and asserts what a repeat then does. A test that only proves the normal path still works has
not touched the defect. `Structure` in test_write_atomic.py measures the other half of the property: that no
transaction body reaches anything which commits.
"""
import json
import unittest
from unittest.mock import patch
import uuid

import hub
from test_capacity import Capacity
from test_resources import Resources
from test_responsibilities import CHECK, CLOCK_WATCH, DUTY, Base
from test_restart_task import Dying, Ending, Exit
from test_shell_box import Reports


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (HoldSettles, DutySaves, DutyStates, GrantsAccess, OwnerCommands, CaseCloses, ReportJoins):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class HoldSettles(Dying, Capacity):
    """settle_hold: the hold's own state and the unknown outcomes of its attempt are one write.

    The helper reports the result of a stop once: the route refuses a second report of a hold that is no longer
    `requested`. So a hub that committed `state='stopped'` on its own and died before record_outcomes had thrown the
    outcomes away for good, and the task resumed with nobody told to check whether its send, post or payment went
    out. That is the one thing rule 9 and resolve_outcome exist for."""

    SEND = {"tool_call_id": "toolu_send", "kind": "execute", "status": "in_progress",
            "title": "Bash: curl -X POST $FLEET_HUB/outbox -d key=offer"}

    def setUp(self):
        super().setUp()
        self.task = self.create("manager", "big", why="big does the shell work")
        text, error = self.call("big", "list_my_tasks", {"task_id": f"T-{self.task}"}, self.task)
        self.assertFalse(error, text)
        hub.q("INSERT INTO thread_events(task,attempt,session,seq,ts,type,data,created) VALUES(?,?,?,?,?,?,?,?)",
              (self.task, 1, "s1", 1, hub.now(), "tool_call", json.dumps(self.SEND), hub.now()))
        with hub.LOCK:
            self.h = hub.request_hold(self.task, "stop", "owner")[0]
        self.assertEqual(self.hold()["state"], "requested")

    def hold(self):
        return hub.q1("SELECT * FROM holds WHERE id=?", (self.h["id"],))

    def outcomes(self):
        return [(o["tool_call_id"], o["state"], o["hold"]) for o in
                hub.q("SELECT * FROM outcomes WHERE task=? ORDER BY id", (self.task,))]

    def reports(self, confirmed=True):
        """The helper's result of the stop, through its own route, as its loop sends it."""
        return self.request("/helper/control/big", dict(hold=self.h["id"], confirmed=confirmed,
                                                        detail="interrupted and closed", ran=True, ended=0))

    def test_a_hub_that_ends_before_the_unknown_outcomes_leaves_the_stop_to_be_reported_again(self):
        # The write used to be: UPDATE holds SET state='stopped' (committed), then the outcomes (committed). A hub
        # that died in between left a stopped hold with no unknown outcome, and the helper's repeat was refused.
        hub.DB = Ending(hub.DB, when=lambda sql, args: sql.startswith("INSERT OR IGNORE INTO outcomes"))
        with self.assertRaises(Exit):
            hub.settle_hold(self.hold(), True, "interrupted and closed", ran=True)
        self.reopen()
        self.assertEqual((self.hold()["state"], self.outcomes()), ("requested", []))
        code, data = self.reports()                 # the helper's report again: the route still takes it
        self.assertEqual((code, data.get("state")), (200, "stopped"), data)
        self.assertEqual(self.outcomes(), [("toolu_send", "unknown", self.h["id"])])

    def test_a_hub_that_ends_at_any_write_of_the_stop_keeps_all_of_it_or_nothing(self):
        before = self.kept()
        hub.DB = Ending(hub.DB)
        self.assertEqual(hub.settle_hold(self.hold(), True, "interrupted and closed", ran=True), "stopped")
        calls, settled = hub.DB.calls, (self.hold()["state"], self.outcomes())
        self.assertEqual(settled, ("stopped", [("toolu_send", "unknown", self.h["id"])]))
        for at in range(1, calls + 1):
            with self.subTest(at=at):
                self.back_to(before)
                hub.DB = Ending(hub.DB, stop_at=at)
                try:
                    hub.settle_hold(self.hold(), True, "interrupted and closed", ran=True)
                except Exit:
                    pass
                self.reopen()
                found = (self.hold()["state"], self.outcomes())
                self.assertIn(found, (("requested", []), settled), f"half a stop at call {at}")

    def test_the_report_of_a_hold_that_is_settled_is_refused_so_the_outcomes_have_no_second_chance(self):
        """Why the first case matters: the route takes one report for each hold, and no more."""
        self.assertEqual(self.reports()[0], 200)
        code, data = self.reports()
        self.assertEqual((code, data.get("error")), (409, "this hold is not waiting for the helper"))


class DutySaves(Dying, Base):
    """set_duty: the duty row, its watches, the messages that say it exists and the manager's receipt are one write.

    The receipt was inside the transaction and the rest after it, and a repeat of the same request_id short-circuits
    on the receipt. So a hub that died in that window left a duty with no watch — nothing ever opens a case of it —
    nobody told that it exists, and a manager whose repeat was answered "R-1 saved"."""

    def save(self, request_id):
        return self.tool("manager", "set_duty", request_id=request_id, **DUTY)

    def found(self):
        """(the duty's state, its wake-up rules, the receipts kept, the agents told)."""
        r = hub.q1("SELECT * FROM responsibilities ORDER BY id DESC LIMIT 1")
        return (r["state"] if r else None,
                [(t["watch"], t["state"]) for t in hub.q("SELECT * FROM triggers ORDER BY id")],
                hub.q1("SELECT COUNT(*) n FROM tool_commands")["n"],
                [e["agent"] for e in hub.q("SELECT agent FROM events WHERE kind='say' ORDER BY id")])

    WHOLE = ("active", [("clock", "active")], 1, ["manager", "vps"])      # no review rule since plan C13

    def test_a_hub_that_ends_before_the_watches_leaves_no_duty_and_no_receipt(self):
        rid = str(uuid.uuid4())
        hub.DB = Ending(hub.DB, when=lambda sql, args: sql.startswith("INSERT INTO triggers"))
        with self.assertRaises(Exit):
            self.save(rid)
        self.reopen()
        self.assertEqual(self.found(), (None, [], 0, []))
        out, error = self.save(rid)               # the manager's repeat, with the same request_id
        self.assertFalse(error, out)
        self.assertIn("Wake-up rules of its watches: 1", out)
        self.assertEqual(self.found(), self.WHOLE)

    def test_a_hub_that_ends_at_any_write_of_the_duty_keeps_all_of_it_or_nothing(self):
        before = self.kept()
        hub.DB = Ending(hub.DB)
        self.assertFalse(self.save(str(uuid.uuid4()))[1])
        calls = hub.DB.calls
        self.assertEqual(self.found(), self.WHOLE)
        for at in range(1, calls + 1):
            with self.subTest(at=at):
                self.back_to(before)
                hub.DB = Ending(hub.DB, stop_at=at)
                try:
                    self.save(str(uuid.uuid4()))
                except Exit:
                    pass
                self.reopen()
                self.assertIn(self.found(), ((None, [], 0, []), self.WHOLE), f"half a duty at call {at}")


class DutyStates(Dying, Base):
    """change_duty: the duty's new state, its watches, the message and the receipt are one write.

    The duty changed with commits of its own and the receipt was kept afterwards. A hub that died in between retired
    the duty with no receipt, and the manager's repeat was then refused with "is retired; retire does not apply" —
    an answer that says the write did not apply when it did, which is the one thing a repeat must never say."""

    def setUp(self):
        super().setUp()
        self.r = self.duty(watch=[CLOCK_WATCH])
        self.rid = str(uuid.uuid4())

    def retire(self):
        return self.tool("manager", "change_duty", request_id=self.rid, responsibility=hub.rref(self.r["id"]),
                         action="retire", note="the shop is closed")

    def found(self):
        """(the duty's state, the states of its watches, the receipts kept, the history lines)."""
        return (hub.duty_row(self.r["id"])["state"],
                [t["state"] for t in hub.duty_watches(self.r["id"], live=False)],
                hub.q1("SELECT COUNT(*) n FROM tool_commands")["n"],
                [h["kind"] for h in hub.q("SELECT kind FROM duty_history ORDER BY id")])

    BEFORE = ("active", ["active"], 0, ["created"])
    RETIRED = ("retired", ["paused"], 1, ["created", "retire"])

    def test_a_hub_that_ends_before_the_receipt_answers_the_repeat_the_same_thing(self):
        self.assertEqual(self.found(), self.BEFORE)
        hub.DB = Ending(hub.DB, when=lambda sql, args: sql.startswith("INSERT INTO tool_commands"))
        with self.assertRaises(Exit):
            self.retire()
        self.reopen()
        self.assertEqual(self.found(), self.BEFORE)       # nothing of the retire landed
        out, error = self.retire()                        # the same request_id again
        self.assertFalse(error, out)
        self.assertEqual(out, f"{hub.rref(self.r['id'])} is retired.")
        self.assertEqual(self.found(), self.RETIRED)

    def test_a_hub_that_ends_at_any_write_of_the_retire_keeps_all_of_it_or_nothing(self):
        before = self.kept()
        hub.DB = Ending(hub.DB)
        self.assertFalse(self.retire()[1])
        calls = hub.DB.calls
        self.assertEqual(self.found(), self.RETIRED)
        for at in range(1, calls + 1):
            with self.subTest(at=at):
                self.back_to(before)
                hub.DB = Ending(hub.DB, stop_at=at)
                try:
                    self.retire()
                except Exit:
                    pass
                self.reopen()
                self.assertIn(self.found(), (self.BEFORE, self.RETIRED), f"half a retire at call {at}")


class GrantsAccess(Dying, Resources):
    """grant_access: the record of the grant, the manager's receipt and the line in the owner's chat are one write.

    The commit of team.json is the one side effect of these six that genuinely cannot join a database transaction,
    so this window cannot be closed; what can be made right is the repeat. The record used to be one transaction and
    the receipt another, and a hub that died between the commit and them left the hold in force with nothing the
    owner could read about who gave it — and then the manager's repeat answered "already had" instead of the first
    answer, because the only thing it asked was whether team.json already said so."""

    REPO = "repo:acme/web"

    def setUp(self):
        super().setUp()
        self.stand(self.REPO, {"max": "write"})

    def records(self):
        """(the rows of the record the owner reads, the receipts kept, the lines in the owner's chat)."""
        return ([(r["agent"], r["level"], r["by"]) for r in
                 hub.q("SELECT agent, level, by FROM resource_grants WHERE resource=? ORDER BY id", (self.REPO,))],
                hub.q1("SELECT COUNT(*) n FROM tool_commands")["n"],
                hub.q1("SELECT COUNT(*) n FROM owner_reports")["n"])

    def test_a_hub_that_ends_after_the_commit_of_team_json_answers_the_repeat_the_same_thing(self):
        rid, commits = str(uuid.uuid4()), self.commits()
        hub.DB = Ending(hub.DB, when=lambda sql, args: sql.startswith("INSERT INTO tool_commands"))
        with self.assertRaises(Exit):
            self.grant("dev", self.REPO, "write", request_id=rid)
        self.reopen()
        self.assertEqual(self.committed()["agents"]["dev"]["repos"], {"acme/web": "write"})   # the hold is in force
        self.assertEqual(self.records(), ([], 0, 0))        # and nothing the owner reads about it landed
        text = self.granted("dev", self.REPO, "write", request_id=rid)
        self.assertIn("dev now has the GitHub repository acme/web at level write", text)
        self.assertEqual(self.records(), ([("dev", "write", "manager")], 1, 1))
        self.assertEqual(self.commits(), commits + 1)       # and the commit of team.json is not made twice

    def test_a_grant_that_is_already_recorded_still_answers_already_had(self):
        """The healing is only for a hold the record does not carry: an ordinary repeat with a new request_id must
        still say that nothing changed."""
        self.granted("dev", self.REPO, "write")
        self.assertIn("already had", self.granted("dev", self.REPO, "write"))
        self.assertEqual(self.records(), ([("dev", "write", "manager")], 2, 2))


class OwnerCommands(Dying, Base):
    """ui_command: the owner's app is told what came of its command, or that the hub does not know.

    act() is the only one of these six whose work is not a database write alone — it commits team.json, it reaches a
    helper, it fetches a page — so it cannot join the transaction that keeps the receipt. The receipt was written
    after it with a commit of its own, and a hub that died in between left the action applied with no receipt: the
    app, retrying the same request_id as the contract tells it to, then ran the action a second time.

    So the row is claimed before the action and filled in after it. A repeat that finds the claim unfilled is told
    the outcome is not known, which is what the fleet tells an agent about its own cut-off call (rule 9). The cost
    is that a command whose act() failed in a way it did not declare burns its request_id: the hub cannot tell that
    case from a death, so it does not guess. A Refusal is declared and checked before any write, so that one still
    leaves no record and the same request_id is free."""

    def setUp(self):
        super().setUp()
        self.r = self.duty(watch=[CLOCK_WATCH])
        self.rid = str(uuid.uuid4())

    def pause(self):
        return self.request(f"/ui/responsibilities/{self.r['id']}/state",
                            dict(request_id=self.rid, db="test-generation", base_revision=self.r["revision"],
                                 action="pause", note=""))

    def aborting(self, table, *events):
        """Every write of those kinds to that table fails, the way a hub that is about to die does. Returns the one
        call that lets them through again. The database is a temporary file of this test, so nothing outlives it."""
        for event in events:
            hub.q(f"CREATE TRIGGER no_{event.lower()}_{table} BEFORE {event} ON {table} "
                  f"BEGIN SELECT RAISE(ABORT, 'test failure'); END")
        return lambda: [hub.q(f"DROP TRIGGER no_{e.lower()}_{table}") for e in events]

    def test_the_request_id_is_claimed_before_the_action_runs(self):
        """What the claim buys: while the action is running the hub already holds a row for this request_id, so
        nothing that happens to the hub afterwards can let the same request_id run the action a second time."""
        seen, real = [], hub.duty_state_change

        def watched(*args, **kw):
            seen.append(hub.q1("SELECT result FROM ui_controls WHERE request_id=?", (self.rid,)))
            return real(*args, **kw)

        with patch.object(hub, "duty_state_change", watched):
            self.assertEqual(self.pause()[0], 200)
        self.assertEqual([r["result"] if r else None for r in seen], [""])   # claimed, nothing known of it yet

    def test_a_receipt_that_cannot_be_written_leaves_the_outcome_not_known(self):
        """The write that fills the claim in fails. The shape before this change had no such write: it kept the
        result with an insert after the action, and nothing stood for the command while it ran."""
        allow = self.aborting("ui_controls", "UPDATE")
        with patch("hub.traceback.print_exc"):
            self.assertEqual(self.pause()[0], 500)
        self.assertEqual(hub.duty_row(self.r["id"])["state"], "paused")     # the action took effect
        allow()
        code, data = self.pause()                                          # the app's retry, same request_id
        self.assertEqual(code, 409, data)
        self.assertIn("does not know what came of it", data["error"])
        self.assertEqual(hub.duty_row(self.r["id"])["state"], "paused")     # and it is not applied twice

    def test_a_command_that_failed_in_the_action_is_not_run_again_either(self):
        """The hub cannot tell a failed action from one that took effect and lost its receipt, so it says so instead
        of guessing. The owner's app sends a new request_id after it has read the thing the command was about."""
        allow = self.aborting("responsibilities", "UPDATE")
        with patch("hub.traceback.print_exc"):
            self.assertEqual(self.pause()[0], 500)
        self.assertEqual(hub.duty_row(self.r["id"])["state"], "active")     # nothing took effect
        allow()
        self.assertEqual(self.pause()[0], 409)
        self.assertEqual(hub.duty_row(self.r["id"])["state"], "active")
        self.rid = str(uuid.uuid4())                                        # a new request_id does the work
        self.assertEqual(self.pause()[0], 200)
        self.assertEqual(hub.duty_row(self.r["id"])["state"], "paused")

    def test_a_refused_command_leaves_no_record_and_its_request_id_is_free(self):
        code, data = self.request(f"/ui/responsibilities/{self.r['id']}/state",
                                  dict(request_id=self.rid, db="test-generation", base_revision=99,
                                       action="pause", note=""))
        self.assertEqual((code, hub.q1("SELECT COUNT(*) n FROM ui_controls")["n"]), (409, 0), data)
        self.assertEqual(self.pause()[0], 200)
        self.assertEqual(hub.duty_row(self.r["id"])["state"], "paused")


def at_every_write(test, act, found):
    """Run `act` once whole, then once for each of its database calls with the hub process ending at that call, and
    assert that the file a new process opens then holds all of the write or none of it."""
    start, before = found(), test.kept()
    hub.DB = Ending(hub.DB)
    out, error = act()
    test.assertFalse(error, out)
    calls, whole = hub.DB.calls, found()
    test.assertNotEqual(whole, start)
    for at in range(1, calls + 1):
        with test.subTest(at=at):
            test.back_to(before)
            hub.DB = Ending(hub.DB, stop_at=at)
            try:
                act()
            except Exit:
                pass
            test.reopen()
            test.assertIn(found(), (start, whole), f"half of it at call {at}")
    return out


class CaseCloses(Dying, Base):
    """close_case as failed: the closed case, the manager's notice and the receipt are one write.

    The notice went after the commit of the receipt, and a repeat answers from the receipt alone, so a hub that died
    between the two closed the case as failed and told nobody to decide what happens with it."""

    def setUp(self):
        super().setUp()
        self.r = self.duty(watch=[{"kind": "check", "check": CHECK}])
        self.fire(self.watches(self.r["id"])[0]["id"])
        task = self.first_case_task()
        hub.q("UPDATE tasks SET state='completed', delivered=? WHERE id=?", (self.clock, task["id"]))
        self.c = self.case(task["duty_case"])

    def test_a_hub_that_ends_at_any_write_of_a_failed_close_keeps_all_of_it_or_nothing(self):
        def close():
            return self.tool("manager", "close_case", request_id=str(uuid.uuid4()), case=hub.cref(self.c),
                             outcome="failed", note="the account stays signed out")

        def found():
            return (self.case(self.c["id"])["state"], hub.q1("SELECT COUNT(*) n FROM tool_commands")["n"],
                    hub.q1("SELECT COUNT(*) n FROM events WHERE kind='say' AND text LIKE '%as failed%'")["n"])

        at_every_write(self, close, found)
        self.assertEqual(found()[0::2], ("closed", 1))


class ReportJoins(Dying, Reports):
    """join_report from the report's own task: the join, the end of that task and the receipt that says the hub
    ended it are one write. The task ended after the commit of the receipt, so a hub that died between the two left
    the task open, and its repeat answered "the hub ended it as completed"."""

    def test_a_hub_that_ends_at_any_write_of_the_join_keeps_all_of_it_or_nothing(self):
        self.once(["T-81 message", "T-82 message"])
        for task in self.tasks()[:2]:
            self.assertFalse(self.report(task, symptom="wrong_price", component="price_update")[1])
        d1, d2 = self.reports()
        t1, t2 = self.task_of(d1["task"]), self.task_of(d2["task"])
        case = self.open_dev_case(t1, "price-rules")

        def join():
            return self.tool("ops", "join_report", t2, report=f"D-{d2['id']}", case=hub.cref(case))

        def found():
            return (self.task_of(t2["id"])["state"],
                    hub.q1("SELECT duty_case FROM duty_reports WHERE id=?", (d2["id"],))["duty_case"],
                    hub.q1("SELECT COUNT(*) n FROM tool_commands")["n"])

        self.assertIn("the hub ended it as completed", at_every_write(self, join, found))
        self.assertEqual(found()[:2], ("completed", case["id"]))

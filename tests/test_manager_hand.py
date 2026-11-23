"""The owner routes' acts with the hand of the fleet manager's own CLI (`admin`; the owner feedback of 22 November 2026,
F6, and the Door area's read of its design, claims 10, 11 and 14). The manager runs some owner routes' own acts through
command_run with the hand `manager`. Such an act names the manager in its rows, never the owner; it resumes only a
task or a wake-up rule that the manager itself held or paused, never the owner's own; and it never runs now a rule
that sends to people. The tests run the acts as `admin` will: command_run with that hand."""
import json
import unittest
import uuid

import hub
import test_ui_api

# A rule that sends a text to people at its times (WAKEUPS-INTERFACE.md 8): synthetic group and words.
SEND = {"to": "group", "chat": "telegram", "group": "example-group", "text": "The weekly note."}


def load_tests(loader, _tests, _pattern):
    """Only this file's own tests: the class takes the owner API's fixture, not its tests."""
    suite = unittest.TestSuite()
    suite.addTests(ManagerHand(name) for name in ManagerHand.__dict__ if name.startswith("test_"))
    return suite


class ManagerHand(test_ui_api.OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM["agents"]["vps"] = {"role": "worker", "runtime": "claude", "machine": "hub", "can": []}

    def task(self):
        """A task of a worker in work."""
        text = hub.t_create_task("manager", {"owner": "vps", "title": "Rotate the logs", "done_when": "rotated"})
        tid = int(text.split()[1][2:].rstrip("."))
        hub.q("UPDATE tasks SET state='working', started=? WHERE id=?", (hub.now(), tid))
        return tid

    def owner_control(self, tid, action):
        """The owner's own press, through the route."""
        return self.request(f"/ui/tasks/{tid}/control", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                          "action": action})

    def manager_control(self, tid, action):
        """The manager's `admin` call of the same route's own act: command_run with the hand `manager`."""
        body = hub.task_control_read(tid, {"action": action})
        rid = str(uuid.uuid4())
        code, answer = hub.command_run(f"tasks/{tid}/control", rid, "fleet-manager-admin/1", "test-generation", body,
                                       lambda b: hub.task_control_act(tid, b), hand=hub.MANAGER_HAND)
        self.assertIsNone(hub.CALL.hand)        # the hand ends with its act: no later call of this thread has it
        return code, answer, rid

    def stopped(self, tid):
        """The helper confirms the stop, as it does for a hold."""
        hub.q("UPDATE holds SET state='stopped' WHERE task=? AND state='requested'", (tid,))

    def hold(self, tid):
        return hub.q1("SELECT * FROM holds WHERE task=? ORDER BY id DESC LIMIT 1", (tid,))

    def test_the_managers_hand_holds_in_its_own_name_and_resumes_only_its_own_hold(self):
        """Claims 11 and 14: the manager's stop names the manager, and its resume lifts that stop; the owner's own
        stop stays his, and the refused resume leaves no record."""
        owners = self.task()
        self.assertEqual(self.owner_control(owners, "stop")[0], 200)
        self.stopped(owners)
        code, answer, rid = self.manager_control(owners, "resume")
        self.assertEqual(code, 403, answer)
        self.assertIn("the fleet manager resumes only what it held itself", json.dumps(answer))
        self.assertEqual((self.hold(owners)["by"], self.hold(owners)["state"]), ("owner", "stopped"))
        self.assertIsNone(hub.q1("SELECT 1 FROM ui_controls WHERE request_id=?", (rid,)))

        mine = self.task()
        code, answer, rid = self.manager_control(mine, "stop")
        self.assertEqual(code, 200, answer)
        self.assertEqual(self.hold(mine)["by"], hub.manager_name())
        self.assertEqual(hub.q1("SELECT hand FROM ui_controls WHERE request_id=?", (rid,))["hand"], hub.MANAGER_HAND)
        self.stopped(mine)
        code, answer, _ = self.manager_control(mine, "resume")
        self.assertEqual(code, 200, answer)
        self.assertEqual((self.hold(mine)["state"], self.hold(mine)["released_by"]), ("released", hub.manager_name()))
        # the owner resumes a hold of the manager's, in his own name
        self.assertEqual(self.manager_control(mine, "pause")[0], 200)
        self.stopped(mine)
        self.assertEqual(self.owner_control(mine, "resume")[0], 200)
        self.assertEqual((self.hold(mine)["state"], self.hold(mine)["released_by"]), ("released", "owner"))
        # and the owner's own press is as before: his stop and his resume, in his name
        self.assertEqual(self.owner_control(owners, "resume")[0], 200)
        self.assertEqual(self.hold(owners)["state"], "released")

    def test_the_owners_stop_or_pause_over_the_managers_hold_is_his(self):
        """Claim 11, the Door area's reader and its validator: the owner's Stop, or his Pause, of a task that the
        manager paused kept the manager's name in the hold, so the manager's resume lifted the owner's hold."""
        for press in ("stop", "pause"):
            tid = self.task()
            self.assertEqual(self.manager_control(tid, "pause")[0], 200)
            self.assertEqual(self.owner_control(tid, press)[0], 200)
            self.assertEqual(self.hold(tid)["by"], "owner", press)
            self.stopped(tid)
            code, answer, _ = self.manager_control(tid, "resume")
            self.assertEqual(code, 403, f"{press}: {answer}")
            self.assertNotEqual(self.hold(tid)["state"], "released", press)

    def test_the_hubs_pause_in_the_managers_name_is_not_the_managers_to_resume(self):
        """The validator's finding 4: the hub pauses a task whose session ended with an error in its requester's name,
        which is often the manager; that hold is no hold of the manager's own admin, so its resume is refused."""
        tid = self.task()
        hub.request_hold(tid, "pause", hub.manager_name(), "the session ended with an error")
        self.stopped(tid)
        code, answer, _ = self.manager_control(tid, "resume")
        self.assertEqual(code, 403, answer)
        self.assertNotEqual(self.hold(tid)["state"], "released")

    def test_the_managers_stop_of_a_parent_never_lifts_the_owners_hold_of_a_subtask(self):
        """Claim 11, the Door area's reader: the owner paused a subtask, the manager stopped its parent (which made
        the owner's pause a stop and joined it to the parent's hold), and the manager's resume of the parent lifted
        the owner's hold of the subtask."""
        parent, sub = self.task(), self.task()
        hub.q("UPDATE tasks SET parent=? WHERE id=?", (parent, sub))
        self.assertEqual(self.owner_control(sub, "pause")[0], 200)
        self.stopped(sub)
        code, answer, _ = self.manager_control(parent, "stop")
        self.assertEqual(code, 200, answer)
        self.assertEqual((self.hold(sub)["by"], self.hold(sub)["kind"]), ("owner", "pause"))   # his, as he left it
        self.stopped(parent)
        code, answer, _ = self.manager_control(parent, "resume")
        self.assertEqual(code, 200, answer)
        self.assertNotEqual(self.hold(sub)["state"], "released")     # the owner's hold of the subtask stays his

    def test_a_subtask_under_the_managers_pause_stays_held_at_a_sign_in(self):
        """Claim 11, the Door area's reader: the sign-in path (other_hold_around) held a subtask under the owner's
        pause of its parent and not under the manager's own `admin` pause, so the subtask went on by itself."""
        parent, sub = self.task(), self.task()
        hub.q("UPDATE tasks SET parent=? WHERE id=?", (parent, sub))
        hub.request_hold(sub, "pause", "hub", "the session ended with an error")     # the hub's own pause first
        self.assertEqual(self.manager_control(parent, "pause")[0], 200)
        row = hub.q1("SELECT * FROM tasks WHERE id=?", (sub,))
        self.assertIn(hub.tref(parent), hub.other_hold_around(row) or "")
        # a hold in the manager's name that its `admin` did not make (its restart, its session-failed pause) does not
        hub.q("UPDATE holds SET hand=NULL WHERE task=?", (parent,))
        self.assertIsNone(hub.other_hold_around(row))

    def test_the_managers_pause_takes_over_no_restart_of_another(self):
        """My reader's round 2, A: a pending restart of another's (a lead's restart_task, the hub's no-tools restart)
        was taken over by the manager's pause, which then said `changed: false` and could not be resumed by the
        manager: only the owner could."""
        tid = self.task()
        hold, _ = hub.request_hold(tid, "stop", "manager-lead")
        hub.q("INSERT INTO restart_holds(hold,by,reason,created,state) VALUES(?,'manager-lead','a new session',?,"
              "'pending')", (hold["id"], hub.now()))
        code, answer, _ = self.manager_control(tid, "pause")
        self.assertEqual(code, 200, answer)
        self.assertIs(answer["changed"], False)
        self.assertIn("its restart waits", answer["unchanged"])       # admin's answer says why nothing changed
        self.assertIn("held by manager-lead", answer["unchanged"])
        self.assertEqual(self.hold(tid)["by"], "manager-lead")
        self.assertEqual(hub.q1("SELECT state FROM restart_holds WHERE hold=?", (hold["id"],))["state"], "pending")

    def test_the_managers_hand_resumes_no_subtask_under_the_owners_hold(self):
        """The validator's round 2: the manager stopped a subtask, then the owner stopped its parent, which left the
        subtask's hold as it was (no row of parent_holds); the manager's resume of the subtask passed."""
        parent, sub = self.task(), self.task()
        hub.q("UPDATE tasks SET parent=? WHERE id=?", (parent, sub))
        self.assertEqual(self.manager_control(sub, "stop")[0], 200)
        self.stopped(sub)
        self.assertEqual(self.owner_control(parent, "stop")[0], 200)
        self.stopped(parent)
        code, answer, _ = self.manager_control(sub, "resume")
        self.assertEqual(code, 403, answer)
        self.assertIn(f"The owner holds {hub.tref(parent)} above it", json.dumps(answer))
        self.assertEqual(self.hold(sub)["state"], "stopped")

    def test_the_managers_restart_lets_no_subtask_go_on_under_the_owners_hold(self):
        """My reader's round 4: the manager stopped a subtask with admin, the owner stopped its parent, and the
        manager's own restart_task took the admin hold as its own and started the subtask again under his Stop."""
        parent, sub = self.task(), self.task()
        hub.q("UPDATE tasks SET parent=? WHERE id=?", (parent, sub))
        self.assertEqual(self.manager_control(sub, "stop")[0], 200)
        self.stopped(sub)
        self.assertEqual(self.owner_control(parent, "stop")[0], 200)
        self.stopped(parent)
        text, err = hub.call_tool("manager", "restart_task", {"task_id": hub.tref(sub), "reason": "Its browser froze.",
                                                              "expected_attempt": 1, "request_id": str(uuid.uuid4())})
        self.assertTrue(err, text)
        self.assertIn(f"The owner holds {hub.tref(parent)} above", text)
        self.assertEqual(self.hold(sub)["state"], "stopped")

    def test_the_owners_pause_of_the_hubs_pause_stays_his_at_a_sign_in(self):
        """My reader's round 2, B: the owner's Pause makes the hub's pause after a session error his, and a sign-in
        of the task's runtime, which resumes the hub's own such pauses, must not resume his."""
        tid = self.task()
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))
        hub.request_hold(tid, "pause", t["requester"], hub.session_failed_note(t["needs"]))
        self.stopped(tid)
        self.assertEqual(self.owner_control(tid, "pause")[0], 200)
        self.assertEqual(self.hold(tid)["by"], "owner")
        hub.sign_in_resumes("vps", "claude")
        self.assertNotEqual(self.hold(tid)["state"], "released")

    def test_the_owners_pause_of_a_parent_keeps_the_holder_of_a_subtasks_hold(self):
        """My reader's round 2, C: only the owner's own press on a task takes its hold; his Pause of a parent left a
        subtask's hold (the hub's pause in its requester's name) in his name, so its lead could not restart it."""
        parent, sub = self.task(), self.task()
        hub.q("UPDATE tasks SET parent=? WHERE id=?", (parent, sub))
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (sub,))
        hub.request_hold(sub, "pause", t["requester"], hub.session_failed_note(t["needs"]))
        self.assertEqual(self.owner_control(parent, "pause")[0], 200)
        self.assertEqual(self.hold(sub)["by"], t["requester"])

    def rule(self, send=None):
        """An active wake-up rule of the worker's; one that sends when `send` is given."""
        t0 = hub.now()
        task = {"title": "Weekly note", "details": "", "done_when": "sent", "needs": "none", "goal_id": None}
        if send:
            task["send"] = send
        tid = hub.ins("INSERT INTO triggers(agent,state,revision,schedule,task,late_minutes,max_tasks_per_day,anchor,"
                      "next_due,created,updated,request_id,created_by) VALUES('vps','active',1,?,?,60,24,?,?,?,?,?,"
                      "'vps')", (json.dumps({"kind": "every", "minutes": 60}), json.dumps(task), t0, t0 + 3600, t0,
                                 t0, f"req-rule-{uuid.uuid4()}"))
        return tid

    def owner_rule(self, rule, action):
        t = hub.trigger_row(rule)
        return self.request(f"/ui/triggers/{rule}/state", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                          "base_revision": t["revision"], "action": action})

    def manager_rule(self, rule, action):
        t = hub.trigger_row(rule)
        body = {"trigger": rule, "base_revision": t["revision"], "action": action}     # as the route's read gives it
        rid = str(uuid.uuid4())
        code, answer = hub.command_run(f"triggers/{rule}/state", rid, "fleet-manager-admin/1", "test-generation", body,
                                       lambda b: hub.trigger_state_act(rule, b), hand=hub.MANAGER_HAND)
        self.assertIsNone(hub.CALL.hand)
        return code, answer, rid

    def test_the_managers_hand_resumes_no_rule_that_the_owner_paused_and_runs_no_send_rule_now(self):
        """Claims 10, 11 and 14: the owner's pause of a wake-up rule stays his; the manager's pause names the manager,
        in the rule and in its history, and its resume lifts it; a run now of a rule that sends to people stays the
        owner's, and starts nothing."""
        rule = self.rule()
        self.assertEqual(self.owner_rule(rule, "pause")[0], 200)
        code, answer, rid = self.manager_rule(rule, "resume")
        self.assertEqual(code, 403, answer)
        t = hub.trigger_row(rule)
        self.assertEqual((t["state"], t["paused_by"]), ("paused", "owner"))
        self.assertIsNone(hub.q1("SELECT 1 FROM ui_controls WHERE request_id=?", (rid,)))
        self.assertEqual(self.owner_rule(rule, "resume")[0], 200)

        code, answer, _ = self.manager_rule(rule, "pause")
        self.assertEqual(code, 200, answer)
        self.assertEqual(hub.trigger_row(rule)["paused_by"], hub.manager_name())
        self.assertEqual(hub.q1("SELECT by FROM trigger_history WHERE trigger_id=? AND action='pause' ORDER BY id DESC "
                                "LIMIT 1", (rule,))["by"], hub.manager_name())
        code, answer, _ = self.manager_rule(rule, "resume")
        self.assertEqual(code, 200, answer)
        self.assertEqual(hub.trigger_row(rule)["state"], "active")

        # a rule that the owner set is never the manager's to pause, delete or run (the validator's finding 5)
        owners = self.rule()
        hub.q("UPDATE triggers SET created_by='owner' WHERE id=?", (owners,))
        for action in ("pause", "delete", "run_now"):
            code, answer, _ = self.manager_rule(owners, action)
            self.assertEqual(code, 403, f"{action}: {answer}")
        self.assertEqual(hub.trigger_row(owners)["state"], "active")

        sends = self.rule(send=SEND)
        code, answer, _ = self.manager_rule(sends, "run_now")
        self.assertEqual(code, 403, answer)
        self.assertIn("stays the owner's", json.dumps(answer))
        self.assertIsNone(hub.q1("SELECT 1 FROM trigger_runs WHERE trigger_id=?", (sends,)))


if __name__ == "__main__":
    unittest.main()

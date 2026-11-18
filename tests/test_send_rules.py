"""Rules that send (WAKEUPS-INTERFACE.md section 8): a wake-up rule whose times send a ready text with no session, and
a person's own reminders, through the real hub.Handler and the bridge routes, over a Discord account (no platform,
no bridge process, no live hub, no ~/.fleet). Example names only."""
import datetime
import json
import re
import unittest
import uuid
from unittest.mock import patch

import hub
import test_chat_apps
import test_responsibilities
from test_chat_apps import OWNER_DISCORD

ANA = "555666777"           # a person's Discord user ID
WEEKLY = {"kind": "daily", "time": "09:00", "days": ["mon"], "timezone": "Europe/Madrid"}


class SendRules(test_chat_apps.ChatApps):
    def task(self, owner="studio", owner_asked=False):
        """A working task of the agent, and the context of its session. owner_asked: the owner asked for it in their
        own words in the agent's chat, so start_task's receipt names it."""
        tid = hub.ins("INSERT INTO tasks(title,done_when,owner,requester,state,created,attempt) VALUES(?,?,?,?,?,?,1)",
                      ("Weekly report", "saved", owner, "manager", "working", hub.now()))
        if owner_asked:
            hub.q("INSERT INTO tool_commands(agent,request_id,tool,digest,receipt,created) VALUES(?,?,?,?,?,?)",
                  (owner, str(uuid.uuid4()), "start_task", "test", json.dumps({"task": tid, "text": "Opened"}),
                   hub.now()))
        return ("test-generation", hub.tref(tid), "1")

    def due_now(self, tid):
        """The rule's time comes: the hub's tick runs what is due."""
        at = hub.now()
        hub.q("UPDATE triggers SET next_due=? WHERE id=?", (at - 1, tid))
        hub.trigger_sweep(at)
        return hub.q1("SELECT * FROM trigger_runs WHERE trigger_id=? ORDER BY id DESC LIMIT 1", (tid,))

    def rule(self, said):
        tid = int(re.search(r"(?i)(?:trigger|reminder) (\d+)", said).group(1))
        return tid, hub.q1("SELECT * FROM triggers WHERE id=?", (tid,))

    def view(self, tid, run):
        """The run as the owner's app reads it now."""
        code, data = self.request(f"/ui/triggers/{tid}?db=test-generation")
        self.assertEqual(code, 200, data)
        return next(r for r in data["runs"] if r["id"] == run["id"])

    def report(self, item, state, error=None):
        """The bridge takes the item and says how it went."""
        self.assertIn(item, [i["id"] for i in self.out()])
        code, data = self.bridge(f"/bridge/out/{item}", {"state": state, "parts": 0, "platform_ids": [],
                                                          "error": error})
        self.assertEqual(code, 200, data)

    def save(self, ctx, **fields):
        return hub.call_tool("studio", "save_trigger", dict({"request_id": str(uuid.uuid4())}, **fields), ctx)

    def test_a_ready_text_to_the_owner_goes_at_its_time_with_no_session(self):
        self.own()
        task = self.task(owner_asked=True)
        save = {"request_id": str(uuid.uuid4()), "schedule": WEEKLY,
                "send": {"to": "owner", "text": "Weekly report: **3** orders"}}
        said, error = hub.call_tool("studio", "save_trigger", dict(save), task)
        self.assertFalse(error, said)
        again, _ = hub.call_tool("studio", "save_trigger", dict(save), task)
        self.assertEqual(again, said + " This repeats an earlier request with the same request_id, so nothing new "
                                       "was done.")
        tid, row = self.rule(said)
        stored = json.loads(row["task"])
        self.assertEqual((stored["title"], stored["details"], stored["send"]),
                         ("Send to the owner", "Weekly report: **3** orders",
                          {"to": "owner", "text": "Weekly report: **3** orders"}))
        self.assertIsNone(row["check_spec"])
        seen, _ = hub.call_tool("studio", "see_triggers", {}, task)
        self.assertIn("sends for studio", seen)
        self.assertIn('Sends: "Send to the owner", its text word for word, with no session.', seen)
        code, listed = self.request("/ui/triggers?db=test-generation")
        self.assertEqual(code, 200, listed)
        shown = next(r for r in listed["triggers"] if r["id"] == tid)
        self.assertEqual((shown["task"]["title"], shown["task"]["send"]["to"]), ("Send to the owner", "owner"))
        # its time: the text is queued, as the agent's message to the owner, and no session starts
        tasks = hub.q1("SELECT COUNT(*) n FROM tasks")["n"]
        run = self.due_now(tid)
        self.assertEqual(run["state"], "started")
        item = hub.q1("SELECT * FROM chat_out WHERE id=?", (run["outbound"],))
        self.assertEqual((item["kind"], item["account"], item["recipient"], item["text"]),
                         ("message", "discord-studio", OWNER_DISCORD, "Weekly report: **3** orders"))
        self.assertEqual(hub.q1("SELECT pushed FROM owner_reports WHERE id=?", (item["report"],))["pushed"], 1)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tasks")["n"], tasks, "a ready text starts no session")
        self.assertGreater(hub.q1("SELECT next_due FROM triggers WHERE id=?", (tid,))["next_due"], hub.now())
        self.assertEqual(self.view(tid, run)["state"], "started")
        code, listed = self.request("/ui/triggers?db=test-generation")
        self.assertEqual(next(r for r in listed["triggers"] if r["id"] == tid)["tasks_24h"], 0, "a send is no wake")
        # each view reads how its text went: the bridge's failure, and a lost answer; no report writes the run
        self.report(run["outbound"], "failed", "Missing Access")
        shown = self.view(tid, run)
        self.assertEqual((shown["state"], shown["reason"]), ("not_sent", "Not sent: Missing Access"))
        self.assertEqual(hub.q1("SELECT state FROM trigger_runs WHERE id=?", (run["id"],))["state"], "started")
        # the owner's Send again: the view reads the newer item of the same text
        code, data = self.post(f"/ui/outbound/{run['outbound']}/again")
        self.assertEqual(code, 200, data)
        self.assertEqual(self.view(tid, run)["state"], "started")
        self.report(data["outbound"]["id"], "failed", "Missing Access")
        self.assertEqual(self.view(tid, run)["state"], "not_sent")
        code, data = self.post(f"/ui/outbound/{data['outbound']['id']}/again")      # a Send again of the Send again
        self.assertEqual(code, 200, data)
        self.assertEqual(self.view(tid, run)["state"], "started")
        self.report(data["outbound"]["id"], "sent")
        lost = self.due_now(tid)
        self.report(lost["outbound"], "unknown")
        shown = self.view(tid, lost)
        self.assertEqual((shown["state"], shown["reason"]), ("unknown", "Delivery not confirmed."))
        # Pause all, and no way to the owner: nothing goes, and the run says why
        self.post("/ui/chat-apps/pause", paused=True)
        self.assertEqual(self.due_now(tid)["reason"], "Pause all was on, so nothing was sent.")
        self.post("/ui/chat-apps/pause", paused=False)
        hub.q("DELETE FROM owner_handles")
        run = self.due_now(tid)
        self.assertEqual((run["state"], run["reason"]), ("not_sent", "There was no chat app route to the owner."))
        self.own()
        # the secret guard reads the text again at each run: a login registered since the save pauses the rule
        items = hub.q1("SELECT COUNT(*) n FROM chat_out")["n"]
        with patch.object(hub, "secret_hit", lambda *texts: any("orders" in str(t) for t in texts)):
            run = self.due_now(tid)
        self.assertEqual((run["state"], run["reason"]), ("not_sent", "The text holds a registered login now, so "
                                                         "nothing was sent and the hub paused this rule."))
        self.assertEqual(hub.q1("SELECT state FROM triggers WHERE id=?", (tid,))["state"], "paused")
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM chat_out")["n"], items)
        # a one-time text keeps its one send while its way is closed, and ends after it went
        said, error = self.save(task, schedule={"kind": "once", "at": "2099-01-05T08:30", "timezone": "Europe/Madrid"},
                                send={"to": "owner", "text": "Your summary is ready."})
        self.assertFalse(error, said)
        once, _ = self.rule(said)
        self.post("/ui/chat-apps/pause", paused=True)
        at = hub.now()
        self.assertEqual(self.due_now(once)["reason"], "Pause all was on, so nothing was sent.")
        row = hub.q1("SELECT state, next_due FROM triggers WHERE id=?", (once,))
        self.assertEqual(row["state"], "active")
        self.assertAlmostEqual(row["next_due"], at + hub.SEND_HOLD_RETRY, delta=5)
        self.post("/ui/chat-apps/pause", paused=False)
        # the owner's Run now sends it, and it ends: its next try sends nothing more
        revision = hub.q1("SELECT revision FROM triggers WHERE id=?", (once,))["revision"]
        code, data = self.post(f"/ui/triggers/{once}/state", base_revision=revision, action="run_now")
        self.assertEqual((code, data["run"]["state"]), (200, "started"), data)
        self.assertEqual(hub.q1("SELECT state, next_due FROM triggers WHERE id=?", (once,))["state"], "done")
        sent = hub.q1("SELECT COUNT(*) n FROM chat_out WHERE text='Your summary is ready.'")["n"]
        hub.trigger_sweep(hub.now() + 2 * hub.SEND_HOLD_RETRY)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM chat_out WHERE text='Your summary is ready.'")["n"], sent)
        # Pause all that lasts: a one-time text tries SEND_HOLD_TRIES times in its revision, and a new time is a new
        # wait; then the hub pauses it with why, so it stays in "On a schedule"
        said, error = self.save(task, schedule={"kind": "once", "at": "2099-01-05T08:30", "timezone": "Europe/Madrid"},
                                send={"to": "owner", "text": "The quarter's numbers are in."})
        self.assertFalse(error, said)
        late, _ = self.rule(said)
        self.post("/ui/chat-apps/pause", paused=True)
        for n in range(hub.SEND_HOLD_TRIES - 1):
            self.assertEqual(self.due_now(late)["state"], "not_sent")
        revision = hub.q1("SELECT revision FROM triggers WHERE id=?", (late,))["revision"]
        said, error = self.save(task, trigger_id=late, base_revision=revision, schedule={
            "kind": "once", "at": "2099-01-06T08:30", "timezone": "Europe/Madrid"})
        self.assertFalse(error, said)
        for n in range(hub.SEND_HOLD_TRIES):
            self.assertEqual(hub.q1("SELECT state FROM triggers WHERE id=?", (late,))["state"], "active", n)
            self.assertEqual(self.due_now(late)["state"], "not_sent")
        row = hub.q1("SELECT * FROM triggers WHERE id=?", (late,))
        self.assertEqual((row["state"], row["paused_by"], row["paused_reason"]),
                         ("paused", "hub", "Pause all was on, so nothing was sent."))
        self.post("/ui/chat-apps/pause", paused=False)
        # the owner's Resume: its time has passed (as it has after its tries), so it goes at once, and it ends
        hub.q("UPDATE triggers SET schedule=? WHERE id=?", (json.dumps(
            {"kind": "once", "at": "2020-01-06T08:30", "timezone": "Europe/Madrid"}), late))
        code, data = self.post(f"/ui/triggers/{late}/state", base_revision=row["revision"], action="resume")
        self.assertEqual(code, 200, data)
        self.assertLessEqual(hub.q1("SELECT next_due FROM triggers WHERE id=?", (late,))["next_due"], hub.now())
        hub.trigger_sweep(hub.now() + 1)
        last = hub.q1("SELECT * FROM trigger_runs WHERE trigger_id=? ORDER BY id DESC LIMIT 1", (late,))
        self.assertEqual(last["state"], "started", last["reason"])
        self.assertEqual(hub.q1("SELECT state FROM triggers WHERE id=?", (late,))["state"], "done")
        # an account of the agent's that is off makes a rule to the owner wait too
        said, error = self.save(task, schedule={"kind": "once", "at": "2099-01-05T08:30", "timezone": "Europe/Madrid"},
                                send={"to": "owner", "text": "Your report is ready."})
        self.assertFalse(error, said)
        off, _ = self.rule(said)
        hub.TEAM["chat_apps"]["discord-studio"]["enabled"] = False
        try:
            run = self.due_now(off)
        finally:
            hub.TEAM["chat_apps"]["discord-studio"].pop("enabled")
        self.assertEqual(run["reason"], "The chat account was off, so nothing was sent.")
        self.assertEqual(hub.q1("SELECT state FROM triggers WHERE id=?", (off,))["state"], "active")
        # a way that does not come back soon pauses a one-time text at once, with why
        said, error = self.save(task, schedule={"kind": "once", "at": "2099-01-05T08:30", "timezone": "Europe/Madrid"},
                                send={"to": "owner", "text": "Your invoice is ready."})
        self.assertFalse(error, said)
        gone, _ = self.rule(said)
        hub.q("DELETE FROM owner_handles")
        self.assertEqual(self.due_now(gone)["reason"], "There was no chat app route to the owner.")
        row = hub.q1("SELECT * FROM triggers WHERE id=?", (gone,))
        self.assertEqual((row["state"], row["paused_reason"]), ("paused", "There was no chat app route to the owner."))
        # the agent's own Resume of it, past its time, is refused: only the owner chooses when a text goes late
        hub.q("UPDATE triggers SET schedule=? WHERE id=?", (json.dumps(
            {"kind": "once", "at": "2020-01-06T08:30", "timezone": "Europe/Madrid"}), gone))
        said, error = hub.call_tool("studio", "change_trigger", {"request_id": str(uuid.uuid4()), "trigger_id": gone,
                                                                 "base_revision": row["revision"], "action": "resume"},
                                    task)
        self.assertTrue(error, said)
        self.assertIn("This time has passed", said)
        self.assertEqual(hub.q1("SELECT state FROM triggers WHERE id=?", (gone,))["state"], "paused")

    def test_what_a_rule_that_sends_refuses(self):
        self.own()
        task = self.task(owner_asked=True)
        # a task session reaches the owner only up its line: only one that he asked for saves a rule to him
        said, error = self.save(self.task(), schedule=WEEKLY, send={"to": "owner", "text": "x"})
        self.assertTrue(error)
        self.assertIn("A rule that sends to the owner is saved by the manager, or in a task that the owner asked", said)
        for send, schedule, words in (
                ({"to": "owner", "text": "x"}, {"kind": "every", "minutes": 30}, "at most once an hour"),
                ({"to": "owner", "text": ""}, WEEKLY, "send.text must be 1 to 4,000 characters"),
                ({"to": "owner", "text": "x", "by": "me"}, WEEKLY, 'send must be {"to": "owner"'),
                ({"to": "Nowhere", "text": "x"}, WEEKLY, "Nothing was saved.")):
            said, error = self.save(task, schedule=schedule, send=send)
            self.assertTrue(error, said)
            self.assertIn(words, said)
        said, error = self.save(task, schedule=WEEKLY, send={"to": "owner", "text": "x"},
                                task={"title": "t", "details": "", "done_when": "d", "needs": "none", "goal_id": None})
        self.assertTrue(error)
        self.assertIn("has no task and no check", said)
        said, error = self.save(task, schedule=WEEKLY, send={"to": "owner", "text": "x"}, agent="vps")
        self.assertTrue(error)
        self.assertIn("so it is yours: leave agent out", said)
        with patch.object(hub, "secret_hit", lambda *texts: any("orders" in str(t) for t in texts)):
            said, error = self.save(task, schedule=WEEKLY, send={"to": "owner", "text": "3 orders"})
        self.assertTrue(error)
        self.assertIn("Blocked: this text contains a login", said)
        # without a way to the owner there is no rule to the owner
        hub.q("DELETE FROM owner_handles")
        said, error = self.save(task, schedule=WEEKLY, send={"to": "owner", "text": "x"})
        self.assertTrue(error)
        self.assertIn("no chat app route to the owner", said)
        self.own()
        # a change of a rule that sends goes through the same rules: no schedule of minutes, no check, no task
        said, error = self.save(task, schedule=WEEKLY, send={"to": "owner", "text": "Weekly report"})
        self.assertFalse(error, said)
        tid, row = self.rule(said)
        for change, words in (({"schedule": {"kind": "every", "minutes": 5}}, "at most once an hour"),
                              ({"check": {"code": "print('x')"}}, "has no task and no check"),
                              ({"task": {"title": "t", "details": "", "done_when": "d", "needs": "none",
                                         "goal_id": None}}, "has no task and no check")):
            said, error = self.save(task, trigger_id=tid, base_revision=row["revision"], **change)
            self.assertTrue(error, said)
            self.assertIn(words, said)
        said, error = self.save(self.task(), trigger_id=tid, base_revision=row["revision"],
                                schedule={"kind": "every", "minutes": 60})
        self.assertTrue(error, said)
        self.assertIn("A rule that sends to the owner is changed by the manager, or in a task that the owner", said)
        said, error = hub.call_tool("manager", "save_trigger", {"request_id": str(uuid.uuid4()), "trigger_id": tid,
                                                                "base_revision": row["revision"],
                                                                "schedule": {"kind": "every", "minutes": 60}}, None)
        self.assertTrue(error, said)
        self.assertIn(f"Rule {tid} sends with studio's own account, so only studio changes it, in a task that the "
                      f"owner asked for in its own chat", said)
        said, error = hub.call_tool("vps", "save_trigger", {"request_id": str(uuid.uuid4()), "trigger_id": tid,
                                                            "base_revision": row["revision"],
                                                            "schedule": {"kind": "every", "minutes": 60}},
                                    self.task("vps"))
        self.assertTrue(error, said)
        self.assertIn(f"There is no rule of yours that sends with the number {tid}", said)
        said, error = self.save(task, trigger_id=tid, base_revision=row["revision"],
                                schedule={"kind": "daily", "time": "10:00", "days": None, "timezone": "Europe/Madrid"})
        self.assertFalse(error, said)
        row = hub.q1("SELECT * FROM triggers WHERE id=?", (tid,))
        self.assertEqual((json.loads(row["schedule"])["time"], json.loads(row["task"])["send"]["to"]), ("10:00", "owner"))
        said, error = self.save(task, trigger_id=tid, base_revision=row["revision"],
                                send={"to": "owner", "text": "The new weekly report"})
        self.assertFalse(error, said)
        self.assertEqual(json.loads(hub.q1("SELECT task FROM triggers WHERE id=?", (tid,))["task"])["details"],
                         "The new weekly report")
        # it has no check, and it is no watch of a duty: it starts no work
        revision = hub.q1("SELECT revision FROM triggers WHERE id=?", (tid,))["revision"]
        said, error = hub.call_tool("studio", "change_trigger", {"request_id": str(uuid.uuid4()), "trigger_id": tid,
                                                                 "base_revision": revision, "action": "check_now"},
                                    task)
        self.assertTrue(error)
        self.assertIn("sends a ready text at its times and has no check", said)
        with hub.LOCK:
            duty = hub.duty_save(hub.duty_fields(dict(test_responsibilities.DUTY, agent="studio"), True), "manager",
                                 hub.now())
        said, error = hub.call_tool("studio", "attach_watch", {"request_id": str(uuid.uuid4()),
                                                               "responsibility": hub.rref(duty["id"]), "trigger": tid},
                                    task)
        self.assertTrue(error)
        self.assertIn("sends a ready text and starts no work, so it is no watch of a duty", said)
        # an agent that left the team: its rule pauses at its next time
        hub.TEAM["agents"].pop("studio")
        run = self.due_now(tid)
        self.assertEqual((run["state"], run["reason"]), ("not_sent", "studio is no longer in the team."))
        self.assertEqual(hub.q1("SELECT state FROM triggers WHERE id=?", (tid,))["state"], "paused")

    def test_a_persons_reminder_goes_only_to_their_own_conversation(self):
        """An outsider reaches only an agent whose Shell box is off (contact_reach): the support agent's case."""
        hub.TEAM["agents"]["studio"]["can"] = []
        self.own()
        code, data = self.post("/ui/people", name="Ana Ruiz", role="customer", agents=["studio"],
                               handles=[{"app": "discord", "handle": ANA}])
        self.assertEqual(code, 200, data)
        pid = data["person"]["id"]
        self.inbound("Remind me tomorrow at 10:00 to bring the receipt.", sender=ANA, sender_name="Ana", chat="dm-ana")
        conv = hub.q1("SELECT * FROM conversations WHERE person=?", (pid,))
        self.assertTrue(conv)
        here = ("test-generation", "conversation", str(conv["id"]))
        self.assertIn("remind", [t["name"] for t in hub.tools_for("studio", here)])
        self.assertNotIn("remind", [t["name"] for t in hub.tools_for("studio", self.task())])
        said, error = hub.call_tool("studio", "remind", {"request_id": str(uuid.uuid4())}, here)
        self.assertEqual((error, said), (False, "Open reminders here: none."))
        # a person's words choose no rule that sends to the owner: that is work for open_work
        hub.CALL.context = here
        try:
            with self.assertRaises(hub.ToolError) as refused:
                hub.t_save_trigger("studio", {"request_id": str(uuid.uuid4()), "send": {"to": "owner", "text": "x"},
                                              "schedule": WEEKLY})
        finally:
            hub.CALL.context = None
        self.assertIn("A rule that sends is saved in a task session, not in a conversation", str(refused.exception))
        tomorrow = (datetime.datetime.now(hub.goal_settings()[2]) + datetime.timedelta(days=1)).strftime(
            "%Y-%m-%dT10:00")
        remind = {"request_id": str(uuid.uuid4()), "text": "Bring the receipt to the shop today.",
                  "schedule": {"kind": "once", "at": tomorrow}}
        said, error = hub.call_tool("studio", "remind", dict(remind, request_id=str(uuid.uuid4()), schedule={
            "kind": "once", "at": "2099-01-05T10:00"}), here)
        self.assertEqual((error, said), (True, "A one-time reminder is at most 90 days ahead. Nothing was saved."))
        said, error = hub.call_tool("studio", "remind", dict(remind), here)
        self.assertFalse(error, said)
        tid, row = self.rule(said)
        self.assertEqual(json.loads(row["schedule"])["timezone"], hub.goal_settings()[2].key)
        self.assertEqual(json.loads(row["task"])["title"], "Reminder for Ana Ruiz")
        self.assertEqual(hub.own_rules("studio"), 0, "a person's reminder is not one of the agent's own rules")
        run = self.due_now(tid)
        self.assertEqual(run["state"], "started")
        item = hub.q1("SELECT * FROM chat_out WHERE id=?", (run["outbound"],))
        self.assertEqual((item["account"], item["chat"], item["recipient"], item["text"]),
                         ("discord-studio", "dm-ana", None, "Bring the receipt to the shop today."))
        record = hub.q1("SELECT * FROM conversation_messages WHERE conversation=? ORDER BY id DESC LIMIT 1",
                        (conv["id"],))
        self.assertEqual((record["who"], record["text"]), ("agent", "Bring the receipt to the shop today."))
        self.assertEqual(hub.q1("SELECT state FROM triggers WHERE id=?", (tid,))["state"], "done")
        # three at most; cancel ends one
        ids = []
        for n in range(3):
            said, error = hub.call_tool("studio", "remind", {
                "request_id": str(uuid.uuid4()), "text": f"Reminder {n}",
                "schedule": {"kind": "daily", "time": "09:00", "days": None}}, here)
            self.assertFalse(error, said)
            ids.append(self.rule(said)[0])
        said, error = hub.call_tool("studio", "remind", {"request_id": str(uuid.uuid4()), "text": "One more",
                                                          "schedule": {"kind": "daily", "time": "10:00",
                                                                       "days": None}}, here)
        self.assertTrue(error)
        self.assertIn("3 open reminders, the most it can have", said)
        said, error = hub.call_tool("studio", "remind", {"request_id": str(uuid.uuid4()), "cancel": ids[0]}, here)
        self.assertEqual((error, said), (False, f"Reminder {ids[0]} is cancelled."))
        # a paused conversation and an account that is off only skip a run: both can come back
        hub.q("UPDATE conversations SET state='paused' WHERE id=?", (conv["id"],))
        run = self.due_now(ids[1])
        self.assertEqual((run["state"], run["reason"]),
                         ("not_sent", "The owner paused the conversation, so nothing was sent."))
        self.assertEqual(hub.q1("SELECT state FROM triggers WHERE id=?", (ids[1],))["state"], "active")
        hub.q("UPDATE conversations SET state='open' WHERE id=?", (conv["id"],))
        hub.TEAM["chat_apps"]["discord-studio"]["enabled"] = False
        try:
            run = self.due_now(ids[1])
        finally:
            hub.TEAM["chat_apps"]["discord-studio"].pop("enabled")
        self.assertEqual((run["state"], run["reason"]), ("not_sent", "The chat account was off, so nothing was sent."))
        self.assertEqual(hub.q1("SELECT state FROM triggers WHERE id=?", (ids[1],))["state"], "active")
        # a conversation with the agent's tools runs a task tool for its open conversation task: that session saves
        # no rule that sends, and sees and changes no person's reminder
        hub.TEAM["agents"]["studio"]["can"] = ["shell"]
        message = hub.q1("SELECT id FROM conversation_messages WHERE conversation=? AND who<>'agent' ORDER BY id LIMIT 1",
                         (conv["id"],))["id"]
        talk = hub.ins("INSERT INTO tasks(title,done_when,owner,requester,state,created,attempt,source_conversation,"
                       "source_message) VALUES(?,?,?,?,?,?,1,?,?)", ("Answer Ana", "answered", "studio", "manager",
                                                                     "working", hub.now(), conv["id"], message))
        ctx = ("test-generation", hub.tref(talk), "1")
        said, error = hub.call_tool("studio", "save_trigger", {"request_id": str(uuid.uuid4()), "schedule": WEEKLY,
                                                               "send": {"to": "owner", "text": "x"}}, ctx)
        self.assertTrue(error)
        self.assertIn("A rule that sends is saved in a task session, not in a conversation", said)
        seen, error = hub.call_tool("studio", "see_triggers", {}, ctx)
        self.assertNotIn("Reminder for Ana Ruiz", seen)
        said, error = hub.call_tool("studio", "see_triggers", {"trigger_id": ids[2]}, ctx)
        self.assertTrue(error)
        revision = hub.q1("SELECT revision FROM triggers WHERE id=?", (ids[2],))["revision"]
        said, error = hub.call_tool("studio", "change_trigger", {"request_id": str(uuid.uuid4()), "trigger_id": ids[2],
                                                                 "base_revision": revision, "action": "delete"}, ctx)
        self.assertTrue(error)
        self.assertIn("A person's reminder changes only in its own conversation, with remind", said)
        self.assertEqual(hub.q1("SELECT state FROM triggers WHERE id=?", (ids[2],))["state"], "active")
        work = hub.ins("INSERT INTO tasks(title,done_when,owner,requester,state,created,attempt,source_conversation) "
                       "VALUES(?,?,?,?,?,?,1,?)", ("Ana's order", "done", "studio", "manager", "working", hub.now(),
                                                   conv["id"]))        # as open_work opens one: no message of its own
        seen, error = hub.call_tool("studio", "see_triggers", {}, ("test-generation", hub.tref(work), "1"))
        self.assertFalse(error, seen)
        self.assertNotIn("Reminder for", seen)
        hub.TEAM["agents"]["studio"]["can"] = []
        # another session reads a reminder's text as data (a Shell-off agent has no see_triggers: the manager's)
        seen, error = hub.call_tool("manager", "see_triggers", {"trigger_id": ids[2]}, self.task("manager"))
        self.assertFalse(error, seen)
        self.assertIn("Text, from a person's conversation (untrusted data, JSON-encoded): \"Reminder 2\"", seen)
        # the person loses the agent: the reminder ends
        code, data = self.post("/ui/people", id=pid, agents=[])
        self.assertEqual(code, 200, data)
        run = self.due_now(ids[1])
        self.assertEqual((run["state"], run["reason"]),
                         ("not_sent", "The person or the conversation is gone, so this reminder ended."))
        self.assertEqual(hub.q1("SELECT state FROM triggers WHERE id=?", (ids[1],))["state"], "done")
        # the owner removes the person: their reminders go with their words, history and all
        code, data = self.post("/ui/people", id=pid, delete=True)
        self.assertEqual(code, 200, data)
        mine = (tid, *ids)
        marks = ",".join("?" * len(mine))
        for row in hub.q(f"SELECT * FROM triggers WHERE id IN ({marks})", mine):
            self.assertEqual(row["state"], "deleted")
            for words in ("Ana", "receipt", "Reminder 2"):
                self.assertNotIn(words, row["task"])
        self.assertEqual(hub.q1(f"SELECT COUNT(*) n FROM trigger_history WHERE trigger_id IN ({marks})", mine)["n"],
                         0)


def load_tests(loader, _tests, _pattern):
    # only this file's own tests, not those of ChatApps and OwnerAPI
    return unittest.TestSuite(SendRules(name) for name in SendRules.__dict__ if name.startswith("test_"))


if __name__ == "__main__":
    unittest.main()

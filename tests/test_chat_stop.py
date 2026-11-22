"""Stop in the chat box (owner feature chat_stop, UI-API.md 1.301), the hub's part, through the real routes: when a
press can stop a turn (agents[].chat_stop), the press (POST /ui/chats/<agent>/stop), and what each reader of a
message's reply does with a stopped message. The owner, 21 November 2026: "Yes, add Stop (Recommended)". A test's own
database and stand-in helper reports: no AI call, no runtime, no session."""
import json
import os
import tempfile
import unittest
import unittest.mock
import urllib.error
import uuid

import fleet
import hub
import test_ui_api
from leftovers import scratch_home

CONTEXT = ("test-generation", "owner-chat", "1")        # the owner chat of the test generation (chat_fence)


def setUpModule():
    scratch_home()      # the helper stand-in reads and writes no file of the real ~/.fleet (leftovers.scratch_home)


def load_tests(loader, _tests, _pattern):
    """Only this module's cases, not the ones of OwnerAPI that it borrows its fixture from."""
    return unittest.TestSuite(ChatStop(name) for name in ChatStop.__dict__ if name.startswith("test_"))


class ChatStop(test_ui_api.OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM["addresses"]["leo-host"] = "127.0.0.3"
        hub.TEAM["agents"]["leo"] = {"role": "worker", "runtime": "codex", "machine": "leo-host", "can": ["shell"]}
        self.server.machines = True             # each request comes from the machine that its route names
        for name in ("leo", "manager"):
            self.features(name)

    # ---- helpers
    def features(self, agent, names=("chat_stop",)):
        """The agent's helper names these features in its machine status."""
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET "
              "data=excluded.data", (agent, json.dumps({"features": list(names)}), hub.now()))

    def send(self, text, agent="leo", **more):
        code, receipt = self.request("/ui/messages", self.command(recipient=agent, text=text, **more))
        self.assertEqual(code, 200, receipt)
        return receipt

    def read(self, agent="leo"):
        """What the agent's session reads with read_messages: a worker in its owner chat, the manager in its own."""
        return hub.call_tool(agent, "read_messages", {}, CONTEXT)[0] if agent != "manager" else \
            hub.t_read_messages("manager", {})

    def press(self, message, agent="leo", request_id=None):
        return self.request(f"/ui/chats/{agent}/stop", {"request_id": request_id or str(uuid.uuid4()),
                                                        "db": "test-generation", "message": message})

    def stop_keys(self):
        """agents[].chat_stop of each agent that has one, as GET /ui/state and GET /ui/mobile both give it."""
        mac = {a["name"]: a["chat_stop"] for a in self.request("/ui/state")[1]["agents"] if "chat_stop" in a}
        phone = {a["name"]: a["chat_stop"] for a in self.request("/ui/mobile")[1]["agents"] if "chat_stop" in a}
        self.assertEqual(mac, phone)
        return mac

    def events(self, agent, kind):
        return hub.q("SELECT * FROM events WHERE agent=? AND kind=? ORDER BY id", (agent, kind))

    def polled(self, agent="leo"):
        """The events that the agent's helper gets from its delivery poll now."""
        code, data = self.request(f"/events/{agent}?delivery=1&after=0&wait=0")
        self.assertEqual(code, 200, data)
        return data["events"]

    # ---- tests
    def test_a_worker_reads_the_stop_line_and_not_the_stopped_message_again(self):
        """A worker's chat gets the owner's message again at each read until a report names it. After a press, its
        next read gives the hub's stop line and not the stopped message. The bug: the session reads the message
        again, after the interrupt, and goes on with the cut work."""
        asked = self.send("Rename every file of the shared folder.")
        self.assertIn("Rename every file", self.read())
        self.assertIn("Rename every file", self.read())          # no reply yet: given again, as before
        code, answer = self.press(asked["request_id"])
        self.assertEqual((code, answer["changed"], answer["stop"]["state"]), (200, True, "requested"), answer)
        text = self.read()
        self.assertIn(f"pressed Stop in this chat for their message M-{asked['event_id']}", text)
        self.assertIn('("Rename every file of the shared folder.")', text)
        self.assertEqual(text.count("Rename every file"), 1, text)     # only the quote of the line
        self.assertEqual(text.count("Message M-"), 1, text)
        self.assertEqual(self.read(), "No unread messages. Wait for the next signal.")
        correction = self.send("Only the files of November.")
        self.assertIn("Only the files of November.", self.read())     # the correction comes as every message

    def test_the_line_names_the_open_tasks_of_the_message_and_pauses_none(self):
        """The stop line names the open tasks that the agent opened or gave for the stopped message: they still
        run, and the hub pauses none. The bug: the agent cancels a task that the owner wanted, or does not know that
        one runs."""
        asked = self.send("Count the invoices of October.")
        self.read()
        t0 = hub.now()
        for title, owner, requester, state in (("Count the October invoices", "leo", "manager", "working"),
                                               ("Check the totals", "manager", "leo", "submitted"),
                                               ("An old count", "leo", "manager", "completed")):
            hub.ins("INSERT INTO tasks(title,owner,requester,state,created,ask) VALUES(?,?,?,?,?,?)",
                    (title, owner, requester, state, t0, asked["request_id"]))
        self.assertTrue(self.press(asked["request_id"])[1]["changed"])
        line = self.events("leo", "chat")[-1]["text"]
        self.assertRegex(line, r"opened or gave T-\d+ \(Count the October invoices\) and T-\d+ \(Check the totals\) "
                               r"for that message\. They still run\.")
        self.assertNotIn("An old count", line)
        self.assertEqual(self.events("leo", "control") + self.events("manager", "control"), [])
        self.assertEqual(hub.q("SELECT COUNT(*) n FROM holds")[0]["n"], 0)

    def test_the_poll_gives_no_signal_for_a_stopped_message_or_for_the_stop_line(self):
        """The helper's poll gives an owner chat message until its reply, and the helper types a signal for it. A
        stopped message and the hub's stop line come with no signal: the line comes with the chat's next read. The
        bug: after the interrupt the helper types the signal again, and a turn starts with nothing to do, or with the
        cut work."""
        asked = self.send("Rename every file of the shared folder.")
        self.read()
        self.assertEqual([e["id"] for e in self.polled() if e["kind"] == "chat"], [asked["event_id"]])
        self.press(asked["request_id"])
        self.assertEqual([e for e in self.polled() if e["kind"] == "chat"], [])
        self.assertEqual(len(self.events("leo", "chat")), 2)            # the message and the line, both in the hub
        # The SQL of the poll is a superset of its own rule: neither gives one of them (CHAT_OPEN).
        self.assertEqual(hub.q(f"SELECT id FROM events WHERE agent='leo' AND kind='chat' AND {hub.CHAT_OPEN}"), [])
        with unittest.mock.patch.object(hub, "CHAT_OPEN", "1"):     # the poll's own rule alone gives none either
            self.assertEqual([e for e in self.polled() if e["kind"] == "chat"], [])

    def test_the_next_report_without_a_name_is_for_the_correction(self):
        """The manager's report that names no message takes the turn of the oldest message that waits
        (unanswered_owner_message). A stopped message waits for nothing, so the report after the correction is the
        correction's. The bug: the answer to the correction stands under the stopped message, and the correction
        waits for its reply."""
        stopped = self.send("Write the release notes of the week.", "manager")
        self.read("manager")
        self.assertTrue(self.press(stopped["request_id"], "manager")[1]["changed"])
        correction = self.send("Only the notes of the hub.", "manager")
        text = self.read("manager")
        self.assertIn("Only the notes of the hub.", text)
        self.assertIn(f"pressed Stop in this chat for their message M-{stopped['event_id']}", text)
        hub.call_tool("manager", "tell_owner", {"text": "The hub's notes are written.", "about": "release notes"})
        report = hub.q1("SELECT * FROM owner_reports WHERE agent='manager' ORDER BY id DESC LIMIT 1")
        self.assertEqual((report["in_reply_to"], report["turn"]), (None, correction["request_id"]))
        self.assertIsNone(hub.unanswered_owner_message("manager"))

    def test_a_stopped_message_is_late_only_while_its_stop_is_not_over_and_keeps_nothing_waiting(self):
        """A stopped message keeps no runtime switch waiting, and after the correction's reply the words of its task
        ask for no more message to the owner. The timer says that it is late only while its stop is not over: a turn
        that hangs after an interrupt that waits or did not take shows "Not answering", and a stop that is over ends
        that. The bug: "Thinking" with no end under a turn that hangs, "Not answering" under a stopped message, a
        switch that waits for ever, or a second message to the owner after the correction's reply."""
        asked = self.send("Rename every file of the shared folder.")
        self.read()
        later = hub.now() + hub.CHAT_LATE + 1
        self.assertEqual(hub.chat_late("leo", later), asked["event_id"])
        self.assertEqual(hub.switch_busy("leo")["chats_waiting"], 1)
        stop = self.press(asked["request_id"])[1]["stop"]
        self.assertIsNone(hub.switch_busy("leo"))
        self.assertEqual(hub.chat_late("leo", later), asked["event_id"])          # the interrupt waits
        self.answer(stop["id"], confirmed=False, detail="the session still shows a running turn")
        self.assertEqual(hub.chat_late("leo", later), asked["event_id"])          # it did not take
        self.assertTrue(self.press(asked["request_id"])[1]["changed"])
        self.answer(stop["id"])
        self.assertIsNone(hub.chat_late("leo", later))                            # over: nothing waits for its reply
        again = self.send("And the folder of the photos.")
        self.read()
        later = hub.now() + hub.CHAT_LATE + 1
        self.assertTrue(self.press(again["request_id"])[1]["changed"])
        self.assertEqual(hub.chat_late("leo", later), again["event_id"])
        self.read()                                                                # the agent reads the stop line
        self.assertIsNone(hub.chat_late("leo", later))                            # that ends the stop too
        correction = self.send("Only the files of November.")
        self.read()
        hub.call_tool("leo", "tell_owner", {"text": "I rename the files of November.", "about": "files",
                                            "in_reply_to": correction["request_id"]}, CONTEXT)
        with hub.transaction():
            words = hub.after_task_words("leo", correction["request_id"])
        self.assertEqual(words, "The owner's message has its reply already: write nothing more to them about this "
                                "task now. ")

    def test_stop_is_offered_only_while_the_message_waits_for_the_turn_that_works_on_it(self):
        """agents[].chat_stop names the owner's newest waited message only while a press can stop its turn. The bug:
        Stop shows with nothing to stop: after the reply, after the turn's end, under a usage limit, from a helper
        that cannot interrupt, for an agent that is not active, under "Not answering", and after a press."""
        self.assertEqual(self.stop_keys(), {})
        asked = self.send("Is the backup of today done?")
        self.assertEqual(self.stop_keys(), {})                                  # not read: no turn works on it
        self.read()
        self.assertEqual(self.stop_keys(), {"leo": asked["request_id"]})
        self.features("leo", ("chat_warm",))
        self.assertEqual(self.stop_keys(), {})                                  # a helper with no chat_stop
        self.features("leo")
        hub.ins("INSERT INTO agent_limits(agent,since,until,reset_known) VALUES('leo',?,?,1)",
                (hub.now() - 10, hub.now() + 3600))
        self.assertEqual(self.stop_keys(), {})                                  # a usage limit holds it
        hub.q("UPDATE agent_limits SET ended=? WHERE agent='leo'", (hub.now(),))
        hub.kv_set("chat_undelivered:leo", asked["event_id"])
        self.assertEqual(self.stop_keys(), {})                                  # "Not answering": no work of its
        hub.kv_set("chat_undelivered:leo", None)
        hub.TEAM["agents"]["leo"]["active"] = False
        self.assertEqual(self.stop_keys(), {})                                  # in setup
        del hub.TEAM["agents"]["leo"]["active"]
        self.assertEqual(self.stop_keys(), {"leo": asked["request_id"]})
        hub.call_tool("leo", "tell_owner", {"text": "Yes, at 03:00.", "about": "backup",
                                            "in_reply_to": asked["request_id"]}, CONTEXT)
        self.assertEqual(self.stop_keys(), {})                                  # its reply came
        second = self.send("And the one of yesterday?")
        self.read()
        self.assertEqual(self.stop_keys(), {"leo": second["request_id"]})
        self.assertTrue(self.press(second["request_id"])[1]["changed"])
        self.assertEqual(self.stop_keys(), {})                                  # pressed: it waits for its helper
        # The manager: the end of the turn that read the message ends it.
        boss = self.send("Is the release out?", "manager")
        self.read("manager")
        self.assertEqual(self.stop_keys(), {"manager": boss["request_id"]})
        self.assertEqual(self.request("/helper/turn/manager", {"ended": hub.now()})[0], 200)
        self.assertEqual(self.stop_keys(), {})                                  # its turn is over

    def test_a_press_of_another_message_and_a_second_press_write_nothing(self):
        """A press names the message that the app read in chat_stop. A press of another message, and a second press
        of the same one with a new request id, change nothing and write no event. An exact repeat gives the first
        answer. The bug: two interrupts, the second one in the turn of the correction."""
        older = self.send("Rename every file of the shared folder.")
        self.read()
        self.assertFalse(hub.call_tool("leo", "tell_owner", {"text": "Done.", "about": "files",
                                                             "in_reply_to": older["request_id"]}, CONTEXT)[1])
        asked = self.send("Now the photos.")
        self.read()
        before = hub.q1("SELECT MAX(id) m FROM events")["m"]
        for message in (older["request_id"], str(uuid.uuid4())):
            code, answer = self.press(message)
            self.assertEqual((code, answer["changed"], answer["stop"]), (200, False, None), answer)
        self.assertEqual((hub.q1("SELECT MAX(id) m FROM events")["m"], hub.q("SELECT * FROM chat_stops")),
                         (before, []))
        first = str(uuid.uuid4())
        code, answer = self.press(asked["request_id"], request_id=first)
        self.assertEqual((code, answer["changed"]), (200, True))
        again = self.press(asked["request_id"], request_id=first)[1]
        self.assertEqual(again, dict(answer, replayed=True))
        code, second = self.press(asked["request_id"])
        self.assertEqual((code, second["changed"], second["stop"]), (200, False, answer["stop"]))
        self.assertEqual(len(self.events("leo", "chat_stop")), 1)
        self.assertEqual(len([e for e in self.events("leo", "chat") if json.loads(e["extra"]).get("stop")]), 1)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM chat_stops")["n"], 1)
        self.assertEqual(self.press(asked["request_id"], "nobody")[0], 404)       # an agent that does not exist
        self.assertEqual(self.press("M-1")[0], 400)

    def test_a_message_that_was_not_read_gets_no_stop_and_its_press_writes_nothing(self):
        """When the agent has not read the message, the turn that runs is not on it: the manager's session can work
        on an agent's report. No Stop is offered for it, and a press of it writes nothing: the message stays open for
        the next read. The bug: an interrupt cuts a turn of the manager that works on something else, or a press
        takes back the owner's message."""
        hub.emit("manager", "say", "[agent leo] The backup of today is done.")
        asked = self.send("Write the release notes of the week.", "manager")
        self.assertEqual(self.stop_keys(), {})
        code, answer = self.press(asked["request_id"], "manager")
        self.assertEqual((code, answer["changed"], answer["stop"]), (200, False, None), answer)
        self.assertEqual((hub.q("SELECT * FROM chat_stops"), self.events("manager", "chat_stop")), ([], []))
        self.assertEqual([e["id"] for e in self.polled("manager") if e["kind"] == "say"],
                         [e["id"] for e in self.events("manager", "say")])     # both come, as before
        text = self.read("manager")
        self.assertIn("The backup of today is done.", text)
        self.assertIn("Write the release notes", text)
        row = hub.q1("SELECT * FROM chat_stops")
        self.assertIsNone(row)
        code, answer = self.press(asked["request_id"], "manager")         # read now: its turn can be stopped
        self.assertEqual((code, answer["stop"]["state"], answer["stop"]["agent"]), (200, "requested", "manager"))
        row = hub.q1("SELECT * FROM chat_stops")
        self.assertEqual((row["event"] is not None, row["settled"], row["hand"]), (True, None, "app"))
        line = hub.q1("SELECT * FROM events WHERE id=?", (row["line"],))
        self.assertEqual((line["kind"], json.loads(line["extra"])), ("say", {"quiet": True, "stop": row["id"]}))

    def test_a_press_stops_the_read_message_in_work_and_leaves_the_newer_unread_one_open(self):
        """While the agent works on an older message that it read, the owner's newer message waits unread: a standing
        session gets no line while its turn runs. chat_stop names the message in work, the press interrupts its turn,
        and the newer message stays open for the next read, which gives it with the stop line. While the press waits
        for its helper, no Stop comes for another message. For a worker and for the manager. The bug: the press takes
        back the owner's correction, interrupts nothing, and no Stop comes again."""
        for agent in ("leo", "manager"):
            first = self.send("Deploy the new site to production.", agent)
            self.read(agent)
            second = self.send("No, wait: not production, the test server.", agent)
            self.assertEqual(self.stop_keys().get(agent), first["request_id"], agent)
            code, answer = self.press(first["request_id"], agent)
            self.assertEqual((code, answer["stop"]["state"]), (200, "requested"), agent)
            self.assertEqual(len(self.events(agent, "chat_stop")), 1, agent)
            self.assertNotIn(agent, self.stop_keys())                         # no Stop while the press waits
            self.assertFalse(self.press(second["request_id"], agent)[1]["changed"])
            text = self.read(agent)
            self.assertIn(f"Message M-{second['event_id']}:", text)
            self.assertIn(f"pressed Stop in this chat for their message M-{first['event_id']}", text)
            self.assertNotIn(f"Message M-{first['event_id']}:", text)
            # The correction is read now, and the press waits for its helper still: no second Stop, no second
            # interrupt. The correction came before the press, and its read is the turn of the correction: the
            # helper's next poll gets no interrupt, and the hub settles the press itself (chat_stop_due)
            self.assertNotIn(agent, self.stop_keys())
            self.assertEqual([e for e in self.polled(agent) if e["kind"] == "chat_stop"], [], agent)
            row = hub.q1("SELECT state, detail FROM chat_stops WHERE request=?", (first["request_id"],))
            self.assertEqual((row["state"], row["detail"]), ("stopped", "its turn ended before the interrupt"))

    def test_no_task_opens_for_a_stopped_message(self):
        """A press can come between the read of a message and the start_task that the turn calls for it: that call
        opens no task, and its words are those of the stop line. A task that the message opened before the press
        stays, and a repeat of that call gets its receipt. The bug: the press stops nothing, because the task of the
        cut work opens after it."""
        opened = self.send("Count the invoices of October.")
        self.read()
        args = {"in_reply_to": opened["request_id"], "title": "Count the October invoices",
                "done_when": "The owner has the count."}
        text, refused = hub.call_tool("leo", "start_task", args, CONTEXT)
        self.assertFalse(refused, text)
        self.assertTrue(self.press(opened["request_id"])[1]["changed"])
        self.answer(hub.q1("SELECT id FROM chat_stops")["id"])
        self.assertEqual(hub.call_tool("leo", "start_task", args, CONTEXT), (text, False))
        asked = self.send("Now the photos.")
        self.read()
        self.assertTrue(self.press(asked["request_id"])[1]["changed"])
        text, refused = hub.call_tool("leo", "start_task", dict(args, in_reply_to=asked["request_id"],
                                                                title="Sort the photos"), CONTEXT)
        self.assertTrue(refused)
        self.assertEqual(text, f"The owner pressed Stop in this chat, and that closed their message "
                               f"M-{asked['event_id']}: do not go on with that work, and do not answer that message. "
                               f"The owner's next message says what they want: act on that. No task was opened.")
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tasks WHERE title='Sort the photos'")["n"], 0)

    def test_create_task_takes_no_ask_of_a_stopped_message_and_a_correction_stays(self):
        """The manager files a task under the owner's message with create_task's ask. An ask that names a message
        that a press closed opens no task after the press, with the words of the stop line; an ask that names the
        owner's correction of it stays. The bug: the manager's turn opens the task of the cut work after the press,
        and the stop line names no such task."""
        asked = self.send("Write the release notes of the week.", "manager")
        self.read("manager")
        self.assertTrue(self.press(asked["request_id"], "manager")[1]["changed"])
        args = {"owner": "leo", "title": "Write the release notes", "done_when": "The notes are written.",
                "why": "It writes the notes.", "ask": f"M-{asked['event_id']}", "asked": "Write the release notes"}
        text, refused = hub.call_tool("manager", "create_task", args)
        self.assertTrue(refused)
        self.assertIn(f"closed their message M-{asked['event_id']}: do not go on with that work", text)
        for form in (asked["request_id"], asked["request_id"].upper(), "{" + asked["request_id"] + "}",
                     asked["request_id"].replace("-", "")):      # each form of the UUID that ask_message takes
            self.assertIn(f"closed their message M-{asked['event_id']}",
                          hub.call_tool("manager", "create_task", dict(args, ask=form))[0], form)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tasks")["n"], 0)
        # an ask N-<card> whose answer the press closed
        self.answer(hub.q1("SELECT id FROM chat_stops WHERE request=?", (asked["request_id"],))["id"], "manager")
        need = self.need()
        hub.q("UPDATE needs SET ask=? WHERE id=?", (asked["request_id"], need))
        self.assertEqual(self.request("/helper/turn/manager", {"ended": hub.now()})[0], 200)
        code, got = self.request(f"/ui/needs/{need}", self.command(answer="Yes, the second server."))
        self.assertEqual(code, 200, got)
        self.read("manager")
        card = hub.q1("SELECT request_id, event_id FROM ui_requests WHERE text='Yes, the second server.'")
        self.assertEqual(self.stop_keys().get("manager"), card["request_id"])
        self.assertTrue(self.press(card["request_id"], "manager")[1]["changed"])
        text, refused = hub.call_tool("manager", "create_task", dict(args, ask=f"N-{need}"))
        self.assertTrue(refused, text)
        self.assertIn(f"closed their message M-{card['event_id']}", text)
        fixed = self.send("Only the notes of the hub.", "manager", replaces_request_id=asked["request_id"])
        self.read("manager")
        text, refused = hub.call_tool("manager", "create_task", dict(args, ask=f"M-{fixed['event_id']}"))
        self.assertFalse(refused, text)

    def test_a_press_closes_the_older_messages_of_the_turn_too(self):
        """A press stops the whole turn: the owner's older messages that the agent read and did not answer close with
        the stopped one, and the stop line names them. For a worker a sentence before a task (before_task) is no reply:
        with no task its message comes again. A message that has its reply, and one that the agent has not read, stay
        as they are. The manager reads a message once and handles many with its tools and no report: its press closes
        only what its running turn read, after its last turn end, also the owner's answer to its card. The bug: an
        older message comes again by itself after the stop and starts a turn, with no Thinking and no Stop on the
        owner's screen; or the manager's press closes the messages of turns that ended, and their work is refused."""
        answered = self.send("Is the backup of today done?")
        self.read()
        hub.call_tool("leo", "tell_owner", {"text": "Yes.", "about": "backup", "in_reply_to": answered["request_id"]},
                      CONTEXT)
        early = self.send("Sort the photos of the trip.")
        self.read()
        self.assertFalse(hub.call_tool("leo", "tell_owner", {"text": "I open a task to sort them.", "about": "photos",
                                                             "in_reply_to": early["request_id"], "before_task": True},
                                       CONTEXT)[1])
        older = self.send("Count the invoices of October.")
        self.read()
        newer = self.send("Rename every file of the shared folder.")
        self.read()
        self.assertEqual(self.stop_keys(), {"leo": newer["request_id"]})
        later = self.send("And the photos.")                        # sent after the press's message, not read
        stop = self.press(newer["request_id"])[1]["stop"]
        rows = {r["request"]: (r["state"], r["line"]) for r in hub.q("SELECT * FROM chat_stops")}
        self.assertEqual(set(rows), {early["request_id"], older["request_id"], newer["request_id"]})
        self.assertEqual(rows[older["request_id"]][0], "stopped")
        self.assertEqual(rows[older["request_id"]][1], rows[newer["request_id"]][1])     # one line names them all
        line = hub.q1("SELECT text FROM events WHERE id=?", (rows[newer["request_id"]][1],))["text"]
        self.assertIn(f'The press closes their older messages that you read and did not answer too: '
                      f'M-{early["event_id"]} ("Sort the photos of the trip.") and '
                      f'M-{older["event_id"]} ("Count the invoices of October.").', line)
        self.assertIn("do not answer those messages", line)
        self.answer(stop["id"])
        text = self.read()
        for gone in (early, older, newer, answered):
            self.assertNotIn(f"Message M-{gone['event_id']}:", text)
        self.assertIn(f"Message M-{later['event_id']}:", text)
        self.assertEqual([e["id"] for e in self.polled() if e["kind"] == "chat"], [later["event_id"]])
        # The manager: a message of a turn that ended stays open, and its work opens later
        done = self.send("Deploy the new site.", "manager")
        self.read("manager")
        self.assertEqual(self.request("/helper/turn/manager", {"ended": hub.now()})[0], 200)
        code, got = self.request(f"/ui/needs/{self.need()}", self.command(answer="Yes, the second one."))
        self.assertEqual(code, 200, got)
        boss = self.send("Also check the logs.", "manager")
        self.read("manager")                        # the running turn reads the card's answer and the message
        self.assertTrue(self.press(boss["request_id"], "manager")[1]["changed"])
        card = hub.q1("SELECT request_id FROM ui_requests WHERE text='Yes, the second one.'")["request_id"]
        self.assertEqual({r["request"] for r in hub.q("SELECT request FROM chat_stops WHERE agent='manager'")},
                         {card, boss["request_id"]})
        text, refused = hub.call_tool("manager", "create_task", {
            "owner": "leo", "title": "Deploy the new site", "done_when": "It is live.", "why": "It deploys.",
            "ask": f"M-{done['event_id']}", "asked": "Deploy the new site"})
        self.assertFalse(refused, text)

    def test_the_line_names_the_tasks_of_a_stopped_correction(self):
        """A correction's tasks are filed under the first message of its chain (ask_message), so the stop line reads
        the tasks of a stopped message by its ask. The bug: the agent does not know that the task of the first
        message runs, and opens it again, or cancels it."""
        first = self.send("Count the invoices of October.")
        self.read()
        args = {"in_reply_to": first["request_id"], "title": "Count the October invoices",
                "done_when": "The owner has the count."}
        text, refused = hub.call_tool("leo", "start_task", args, CONTEXT)
        self.assertFalse(refused, text)
        hub.call_tool("leo", "tell_owner", {"text": "I count them.", "about": "invoices",
                                            "in_reply_to": first["request_id"]}, CONTEXT)
        fixed = self.send("Only the paid ones.", replaces_request_id=first["request_id"])
        self.read()
        self.assertTrue(self.press(fixed["request_id"])[1]["changed"])
        line = self.events("leo", "chat")[-1]["text"]
        self.assertRegex(line, r"opened or gave T-\d+ \(Count the October invoices\) for that message\.")

    def test_the_end_of_a_switch_hands_over_no_stopped_message(self):
        """The end of the manager's runtime switch makes the messages that the old session's last turn read and did
        not finish unread again, for the new session (handover_ids). A stopped message and the hub's line about it are
        not among them. The bug: the new session reads the stopped message again with "act on each one that still
        needs it", and does the cut work."""
        report = hub.emit("manager", "say", "[agent leo] The backup of today is done.")
        stopped = self.send("Write the release notes of the week.", "manager")
        self.read("manager")
        stop = self.press(stopped["request_id"], "manager")[1]["stop"]
        line = hub.q1("SELECT line FROM chat_stops WHERE id=?", (stop["id"],))["line"]
        self.read("manager")                                              # the line too
        runtime = hub.agents()["manager"]["runtime"]
        self.assertEqual(hub.handover_ids("manager", {runtime: [report, stopped["event_id"], line]}), [report])

    # ---- piece 2: the helper's answer, the poll's rule and the end of the wait
    def answer(self, stop, agent="leo", **body):
        return self.request(f"/helper/chat-stop/{agent}", dict({"stop": stop, "confirmed": True, "cut": True,
                                                                "detail": "interrupted", "reads": []}, **body))

    def test_the_helper_gets_the_interrupt_only_while_the_press_waits_and_never_after_a_newer_read(self):
        """The poll gives the event chat_stop only while its press is requested, and only while the agent has read no
        message of the owner's that is newer than the press. A helper that was away comes back to a press whose turn
        is over: the hub settles it with no interrupt. The bug: a late interrupt cuts the turn of the correction."""
        asked = self.send("Rename every file of the shared folder.")
        self.read()
        stop = self.press(asked["request_id"])[1]["stop"]
        given = [e for e in self.polled() if e["kind"] == "chat_stop"]
        self.assertEqual([e["extra"] for e in given], [{"stop": stop["id"], "window": "owner-chat",
                                                        "generation": "test-generation",
                                                        "created": stop["created"]}])
        self.assertEqual([e["kind"] for e in self.polled()], ["chat_stop"])     # given again until its answer
        self.send("Only the files of November.")                   # the correction comes, and is not read yet
        self.assertEqual([e["kind"] for e in self.polled() if e["kind"] == "chat_stop"], ["chat_stop"])
        self.read()                                                # its turn runs: no interrupt may cut it now
        before = hub.CHANGE["state"]
        self.assertEqual([e for e in self.polled() if e["kind"] == "chat_stop"], [])
        row = hub.q1("SELECT * FROM chat_stops WHERE id=?", (stop["id"],))
        self.assertEqual((row["state"], row["detail"]), ("stopped", "its turn ended before the interrupt"))
        self.assertGreater(hub.CHANGE["state"], before)            # the end of the stop wakes the apps
        self.assertIsNotNone(hub.q1("SELECT helper_ack FROM events WHERE id=?", (row["event"],))["helper_ack"])
        self.assertEqual(self.answer(stop["id"], cut=False)[0], 409)    # a late answer that cut nothing: no change
        self.assertEqual(self.answer(stop["id"], "manager")[0], 404)

    def test_a_confirmed_stop_gives_the_cut_turns_reads_again_but_not_the_stopped_message(self):
        """The helper sends the ids that the cut turn had read. The hub makes them unread again, so that the poll
        gives them again and a new turn reads them with the stop line: not the stopped message, not the stop line,
        not a message of another agent, and not one that a session of another runtime read last, which finished it.
        The bug: an agent's report that the cut turn had read is lost, or a message is done twice."""
        report = hub.emit("manager", "say", "[agent leo] The backup of today is done.")
        other = hub.emit("manager", "say", "[agent leo] The disk is full.")
        stopped = self.send("Write the release notes of the week.", "manager")
        self.read("manager")
        hub.q("UPDATE events SET extra=? WHERE id=?", (json.dumps({"read_by": "codex"}), other))
        foreign = hub.emit("leo", "chat", "Not the manager's.", extra={"generation": "test-generation"})
        stop = self.press(stopped["request_id"], "manager")[1]["stop"]
        row = hub.q1("SELECT * FROM chat_stops WHERE id=?", (stop["id"],))
        self.assertEqual(self.answer(stop["id"], "manager", reads=[report, "M-1"])[0], 400)
        line = hub.q1("SELECT text FROM events WHERE id=?", (row["line"],))["text"]
        self.assertIn(line, self.read("manager"))                  # the turn that did not stop yet reads the line
        code, body = self.answer(stop["id"], "manager", reads=[report, other, stopped["event_id"], row["line"],
                                                                foreign, 2 ** 70])     # no id of SQLite's: no message
        self.assertEqual((code, body["state"], body["unread"]), (200, "stopped", [report]), body)
        read = {r["id"]: r["read_at"] for r in hub.q("SELECT id, read_at FROM events")}
        self.assertIsNone(read[report])
        for kept in (other, stopped["event_id"], row["line"]):
            self.assertIsNotNone(read[kept], kept)
        self.assertEqual([e["text"] for e in self.polled("manager") if e["kind"] == "say"],
                         ["[agent leo] The backup of today is done."])
        text = self.read("manager")
        self.assertIn("The backup of today is done.", text)
        self.assertNotIn(f"Message M-{stopped['event_id']}:", text)
        self.assertNotIn(line, text)
        self.assertEqual(self.answer(stop["id"], "manager")[0], 409)        # settled: a second answer is refused
        # A worker's chat: its helper finds no ids (fleet.read_ids), so the hub takes each chat of its own that was
        # read from the read of the stopped message on: a task's result that the same read gave, and an agent's
        # message that a later read of the cut turn gave, come again. An agent's message of an earlier turn, and the
        # owner's message with its reply, which a read would not give again, stay read.
        done = self.send("Rename every file.")
        self.read()
        hub.call_tool("leo", "tell_owner", {"text": "Done.", "about": "files", "in_reply_to": done["request_id"]},
                      CONTEXT)
        before = hub.emit("leo", "chat", "[agent manager] The backup is done.",
                          extra={"generation": "test-generation", "agent_message": True})
        hub.q("UPDATE events SET read_at=? WHERE id=?", (hub.now(), before))
        result = hub.emit("leo", "chat", "[hub] T-5 (Count), which you opened from the owner's message, is completed.",
                          extra={"generation": "test-generation", "task_result": 5})
        asked = self.send("Now the photos.")
        self.assertIn("T-5 (Count)", self.read())                   # one read gives the result and the message
        note = hub.emit("leo", "chat", "[agent manager] The disk is full.",
                        extra={"generation": "test-generation", "agent_message": True})
        hub.q("UPDATE events SET read_at=? WHERE id=?", (hub.now(), note))
        told = hub.emit("leo", "chat", "[hub] T-6 (Sort), which you opened from the owner's message, is completed.",
                        extra={"generation": "test-generation", "task_result": 6})
        hub.q("UPDATE events SET read_at=?, extra=json_set(extra, '$.told', 12) WHERE id=?", (hub.now(), told))
        stop = self.press(asked["request_id"])[1]["stop"]
        self.assertEqual(self.answer(stop["id"], reads=[])[1]["unread"], [result, note])
        for kept in (done["event_id"], before, told):           # told: the owner has that result already
            self.assertIsNotNone(hub.q1("SELECT read_at FROM events WHERE id=?", (kept,))["read_at"], kept)
        self.assertEqual([e["id"] for e in self.polled() if e["id"] in (result, note)], [result, note])

    def test_an_answer_that_cut_no_turn_gives_nothing_again(self):
        """The helper says whether it cut a turn. A confirmed answer that cut none ("no turn was running", "its turn
        ended before the interrupt") settles the press, and the messages that the ended turn read stay read: that
        turn finished them. An earlier answer of the same press that cut counts. The bug: an agent's message that the
        ended turn handled comes again and starts a turn; or a result that a cut turn read is lost."""
        asked = self.send("Now the photos.")
        self.read()
        note = hub.emit("leo", "chat", "[agent manager] The disk is full.",
                        extra={"generation": "test-generation", "agent_message": True})
        hub.q("UPDATE events SET read_at=? WHERE id=?", (hub.now(), note))
        stop = self.press(asked["request_id"])[1]["stop"]
        code, body = self.answer(stop["id"], cut=False, detail="no turn was running")
        self.assertEqual((code, body["state"], body["unread"]), (200, "stopped", []))
        self.assertIsNotNone(hub.q1("SELECT read_at FROM events WHERE id=?", (note,))["read_at"])
        # An Esc that went and was not confirmed, a press again, and then "no turn was running": the first Esc cut
        # the turn, so what the turn read comes again
        result = hub.emit("leo", "chat", "[hub] T-5 (Count), which you opened from the owner's message, is completed.",
                          extra={"generation": "test-generation", "task_result": 5})
        again = self.send("And the videos.")
        self.read()                                 # one read: the result and the message
        stop = self.press(again["request_id"])[1]["stop"]
        self.answer(stop["id"], confirmed=False, cut=True, detail="the session still shows a running turn")
        self.assertTrue(self.press(again["request_id"])[1]["changed"])
        code, body = self.answer(stop["id"], cut=False, detail="no turn was running")
        self.assertEqual((code, body["unread"]), (200, [result]))

    def test_an_owner_message_of_the_cut_turn_never_comes_again(self):
        """The manager reads two messages of the owner's in one read, answers the first, and works on the second. A
        press stops the second, and its helper names both as reads of the cut turn. The hub never makes the owner's
        own rows unread again: each one of the cut turn is closed by the press or answered. The bug: the manager
        reads the answered message again as new, and answers it a second time."""
        o = self.send("What is the status of the backup?", "manager")
        o2 = self.send("Then move the logs to the new disk.", "manager")
        self.read("manager")
        hub.call_tool("manager", "tell_owner", {"text": "The backup ran at 03:00.", "about": "backup",
                                                "in_reply_to": f"M-{o['event_id']}"})
        self.assertEqual(self.stop_keys().get("manager"), o2["request_id"])
        stop = self.press(o2["request_id"], "manager")[1]["stop"]
        code, body = self.answer(stop["id"], "manager", reads=[o["event_id"], o2["event_id"]])
        self.assertEqual((code, body["unread"]), (200, []), body)
        self.assertNotIn(f"Message M-{o['event_id']}:", self.read("manager"))

    # ---- the ends of a press, through the hub and its helper's own code (fleet.Helper with no screen)
    def stand_in(self, agent, outcomes, reads, fails=0):
        """A helper of `agent` whose screen part gives `outcomes` in turn, (confirmed, detail, cut), and whose cut turn
        read `reads`; its own code keeps, sends and flushes the answers to the hub. `fails`: how many of its first
        sends of an answer get no answer from the hub."""
        home = tempfile.mkdtemp(prefix="chat-stop-helper-")
        for patcher in (unittest.mock.patch.object(fleet, "HOME", home),
                        unittest.mock.patch.object(fleet, "http", self.helper_http)):
            patcher.start()
            self.addCleanup(patcher.stop)
        conf = dict(hub.TEAM["agents"][agent], runtime="claude")
        helper = fleet.Helper(agent, conf)
        steps = iter(outcomes)
        helper.chat_turn_stop = lambda window, extra: next(steps)
        helper.cut_reads = lambda window, generation: list(reads)
        self.fails = fails
        return helper

    def helper_http(self, method, path, data=None, timeout=40):
        if path.startswith("/helper/chat-stop/") and self.fails:
            self.fails -= 1
            raise urllib.error.URLError("the hub restarts")
        return self.request(path, data)

    def helper_pass(self, helper, agent):
        """One pass of the helper's loop: the poll's events of Stop, handled, then its flush (handle_events)."""
        helper.handle_events([e for e in self.polled(agent) if e["kind"] == "chat_stop"])

    def read_at(self, *ids):
        return [hub.q1("SELECT read_at FROM events WHERE id=?", (i,))["read_at"] is not None for i in ids]

    def test_the_invariant_holds_after_each_ordering_of_a_press(self):
        """hub.CHAT_STOP_INVARIANT, after each ordering of the events of a press: when a press ends, by any path (a
        confirmed answer, a late answer, its settle at the read of a newer row of the owner's, a turn end, normal or
        not), each row that the cut turn read and did not answer becomes unread again, except the owner's messages
        that the press closed or that have a report; and nothing that a turn which ended normally handled comes
        again. The bugs: a task's result, an agent's report, the owner's correction or his answer to a secret
        request that the cut turn read is lost; or a row that a turn which ended normally handled comes twice."""
        self.assertIn("nothing that a turn which ended normally handled comes again", hub.CHAT_STOP_INVARIANT)
        for n in range(1, 6):           # five workers, each on a machine of its own
            hub.TEAM["addresses"][f"w{n}-host"] = f"127.0.0.{10 + n}"
            hub.TEAM["agents"][f"w{n}"] = dict(hub.TEAM["agents"]["leo"], machine=f"w{n}-host")
            self.features(f"w{n}")
        cutting, not_cut = (True, "interrupted; the session is idle", True), (True, "no turn was running", False)
        not_confirmed = (False, "the session still shows a running turn after three interrupts", True)

        def worker(agent):
            """An agent's message of an earlier turn, then one read of the cut turn: a task's result, the owner's
            answer to a secret request and his message, which a press stops."""
            before = hub.emit(agent, "chat", "[agent manager] The disk is full.",
                              extra={"generation": "test-generation", "agent_message": True})
            hub.q("UPDATE events SET read_at=? WHERE id=?", (hub.now() - 60, before))
            result = hub.emit(agent, "chat", "[hub] T-5 (Count), which you opened from the owner's message, is "
                              "completed.", extra={"generation": "test-generation", "task_result": 5})
            secret = hub.emit(agent, "chat", "[owner] Answer to Needs-you N-9 (Login for the shop): bws://example",
                              extra={"generation": "test-generation", "need": 9})
            hub.ins("INSERT INTO ui_requests(request_id,kind,need_id,text,event_id,created,client,recipient) "
                    "VALUES(?,?,?,?,?,?,?,?)", (str(uuid.uuid4()), "answer", 9, "bws://example", secret, hub.now(),
                                                "app", agent))
            asked = self.send("Now the photos.", agent)
            self.assertIn("T-5 (Count)", self.read(agent))
            return before, result, secret, asked

        # 1. confirmed and cut: the cut turn's rows come again, the earlier turn's row and the stopped message not
        before, result, secret, asked = worker("w1")
        helper = self.stand_in("w1", [cutting], [])
        self.press(asked["request_id"], "w1")
        self.helper_pass(helper, "w1")
        self.assertEqual(self.read_at(before, result, secret, asked["event_id"]), [True, False, False, True])
        # 2. not confirmed (an Esc went), a press again, then "no turn was running": the first Esc cut the turn
        before, result, secret, asked = worker("w2")
        helper = self.stand_in("w2", [not_confirmed, not_cut], [])
        self.press(asked["request_id"], "w2")
        self.helper_pass(helper, "w2")
        self.assertEqual(self.read_at(result, secret), [True, True])            # not over yet: still read
        self.press(asked["request_id"], "w2")
        self.helper_pass(helper, "w2")
        self.assertEqual(self.read_at(before, result, secret), [True, False, False])
        # 3. not confirmed (an Esc went), then the owner's correction, which its turn reads: the press ends at that
        # read, and only the rows before it come again
        before, result, secret, asked = worker("w3")
        helper = self.stand_in("w3", [not_confirmed], [])
        self.press(asked["request_id"], "w3")
        self.helper_pass(helper, "w3")
        self.send("Only the photos of November.", "w3")
        same = hub.emit("w3", "chat", "[hub] T-6 (Sort), which you opened from the owner's message, is completed.",
                        extra={"generation": "test-generation", "task_result": 6})
        self.read("w3")                                         # the correction's turn reads it and that result
        note = hub.emit("w3", "chat", "[agent manager] The backup is done.",
                        extra={"generation": "test-generation", "agent_message": True})
        hub.q("UPDATE events SET read_at=? WHERE id=?", (hub.now(), note))      # the correction's turn read it
        self.assertEqual(self.read_at(before, result, secret, same, note), [True, False, False, True, True])
        # 4. the answer's send fails after the Esc; the correction is signalled and read in the same pass; the poll
        # settles the press and never gives its event again; the helper's next pass sends the kept answer
        before, result, secret, asked = worker("w4")
        helper = self.stand_in("w4", [cutting], [], fails=1)
        self.press(asked["request_id"], "w4")
        self.helper_pass(helper, "w4")                                          # the Esc; its answer is kept
        self.send("Only the photos of November.", "w4")
        self.read("w4")
        self.assertEqual([e for e in self.polled("w4") if e["kind"] == "chat_stop"], [])     # settled, no event
        self.assertEqual(self.read_at(result, secret), [True, True])
        self.helper_pass(helper, "w4")                                          # the kept answer goes
        self.assertEqual(self.read_at(before, result, secret), [True, False, False])
        self.assertEqual(fleet.load_chat_stop_answers("w4"), {})
        # 5. the manager: the cut turn read the owner's correction and an agent's report; the turn ends normally
        # (no reads again), and at a later press it ends by the cut (its reads again, the correction too)
        report = hub.emit("manager", "say", "[agent leo] The backup of today is done.")
        m = self.send("Write the release notes of the week.", "manager")
        self.read("manager")
        helper = self.stand_in("manager", [not_confirmed], [report])
        self.press(m["request_id"], "manager")
        self.helper_pass(helper, "manager")
        helper.report_limit({"session": "s1", "events": [
            {"seq": 1, "type": "result", "stop_reason": "end_turn", "ts": hub.now()}]})
        self.assertEqual(self.read_at(report), [True])                          # a normal end handled it
        report = hub.emit("manager", "say", "[agent leo] The disk is full.")
        m = self.send("Move the logs to the new disk.", "manager")
        self.read("manager")
        c = self.send("No, to the old disk.", "manager")
        helper = self.stand_in("manager", [not_confirmed], [report, c["event_id"]])
        self.press(m["request_id"], "manager")
        events = [e for e in self.polled("manager") if e["kind"] == "chat_stop"]       # the poll gives the event
        self.read("manager")                                    # before the Esc lands, the turn reads C and the line
        helper.handle_events(events)
        helper.report_limit({"session": "s2", "events": [
            {"seq": 1, "type": "result", "stop_reason": "cancelled", "ts": hub.now()}]})
        self.assertEqual(self.read_at(report, c["event_id"], m["event_id"]), [False, False, True])
        # 6. the manager: the Esc did not take, and the same running turn reads the correction: no read ends its
        # press; that turn then ends normally, and nothing that it handled comes again
        report = hub.emit("manager", "say", "[agent leo] The certificate is renewed.")
        m = self.send("Write the notes of the certificate.", "manager")
        self.read("manager")
        helper = self.stand_in("manager", [not_confirmed], [report])
        self.press(m["request_id"], "manager")
        self.helper_pass(helper, "manager")
        c = self.send("No, only one line.", "manager")
        self.read("manager")                                    # the same turn reads the correction
        self.assertEqual(self.read_at(report, c["event_id"]), [True, True])
        helper.report_limit({"session": "s3", "events": [
            {"seq": 1, "type": "result", "stop_reason": "end_turn", "ts": hub.now()}]})
        self.assertEqual(self.read_at(report, c["event_id"]), [True, True])
        # 7. the manager: its turn ends (cut) while the press waits for its helper; the answer that comes after it
        # is not confirmed, and the press ends at once by the word of that end
        report = hub.emit("manager", "say", "[agent leo] The mail server is back.")
        m = self.send("Tell the customers that it is back.", "manager")
        self.read("manager")
        helper = self.stand_in("manager", [not_confirmed], [report])
        self.press(m["request_id"], "manager")
        events = [e for e in self.polled("manager") if e["kind"] == "chat_stop"]
        helper.report_limit({"session": "s4", "events": [
            {"seq": 1, "type": "result", "stop_reason": "cancelled", "ts": hub.now()}]})
        helper.handle_events(events)
        self.assertEqual(self.read_at(report, m["event_id"]), [False, True])
        # 8. a worker: the correction came before the press, unread; the running turn reads it before the Esc lands;
        # the answer is not confirmed: the press ends at once at that read
        before, result, secret, asked = worker("w5")
        fixed = self.send("Only the photos of November.", "w5")
        helper = self.stand_in("w5", [not_confirmed], [])
        self.press(asked["request_id"], "w5")
        events = [e for e in self.polled("w5") if e["kind"] == "chat_stop"]
        self.read("w5")                                         # the running turn reads the correction
        helper.handle_events(events)
        self.assertEqual(self.read_at(before, result, secret, fixed["event_id"]), [True, False, False, True])

        def manager_press(what):
            report = hub.emit("manager", "say", f"[agent leo] {what} is done.")
            m = self.send(f"Write the notes of {what}.", "manager")
            self.read("manager")
            return report, m

        def turn_end(helper, session, *reasons):
            helper.report_limit({"session": session, "events": [
                {"seq": n + 1, "type": "result", "stop_reason": reason, "ts": hub.now()}
                for n, reason in enumerate(reasons)]})
        # 9. the manager: its turn ends normally while the press waits for its helper; the answer that comes after
        # it is not confirmed: nothing that the normal end handled comes again
        report, m = manager_press("the backup")
        helper = self.stand_in("manager", [not_confirmed], [report])
        self.press(m["request_id"], "manager")
        events = [e for e in self.polled("manager") if e["kind"] == "chat_stop"]
        turn_end(helper, "s5", "end_turn")
        helper.handle_events(events)
        self.assertEqual(self.read_at(report), [True])
        # 10. the manager: the cut turn ends (not normal) while the press waits, a second turn ends normally, then
        # the answer comes, not confirmed: the cut end came after the press, so the cut turn's reads come again
        report, m = manager_press("the logs")
        helper = self.stand_in("manager", [not_confirmed], [report])
        self.press(m["request_id"], "manager")
        events = [e for e in self.polled("manager") if e["kind"] == "chat_stop"]
        turn_end(helper, "s6", "cancelled")
        turn_end(helper, "s7", "end_turn")
        helper.handle_events(events)
        self.assertEqual(self.read_at(report), [False])
        # 11. the manager: the Esc did not take (an answer that cut, with the report); a press again; the turn ends
        # normally while the press waits; the answer is confirmed, with no reads since that normal end: the report
        # that the normally ended turn handled does not come again
        report, m = manager_press("the certificate")
        helper = self.stand_in("manager", [not_confirmed, not_cut], [report])
        self.press(m["request_id"], "manager")
        self.helper_pass(helper, "manager")
        self.press(m["request_id"], "manager")
        events = [e for e in self.polled("manager") if e["kind"] == "chat_stop"]
        turn_end(helper, "s8", "end_turn")
        helper.cut_reads = lambda window, generation: []        # its records since that normal end read nothing
        helper.handle_events(events)
        self.assertEqual(self.read_at(report), [True])

    def test_a_database_of_an_earlier_build_gets_the_new_columns(self):
        """A hub that ran an earlier build of Stop has chat_stops without cut and reads; migrate() adds them. The bug:
        the helper's answer fails at each try on such a database."""
        hub.q("DROP TABLE chat_stops")
        hub.q("CREATE TABLE chat_stops(id INTEGER PRIMARY KEY, agent TEXT NOT NULL, request TEXT NOT NULL, "
              "state TEXT NOT NULL, created REAL NOT NULL, settled REAL, detail TEXT, line INTEGER, event INTEGER, "
              "hand TEXT)")
        hub.build_schema()
        self.assertLessEqual({"cut", "reads"}, {r["name"] for r in hub.q("PRAGMA table_info(chat_stops)")})

    def test_after_an_interrupt_that_did_not_take_a_press_again_makes_one_new_event(self):
        """An interrupt that did not take leaves the press not_confirmed: chat_stop names the message again, and a
        press again makes the same row requested with one new event, and no second line. The bug: a failed interrupt
        leaves no way to try again, or a press again writes a second line and two events."""
        note = hub.emit("leo", "chat", "[agent manager] The disk is full.",
                        extra={"generation": "test-generation", "agent_message": True})
        hub.q("UPDATE events SET read_at=? WHERE id=?", (hub.now(), note))
        asked = self.send("Rename every file of the shared folder.")
        self.read()
        stop = self.press(asked["request_id"])[1]["stop"]
        self.assertEqual(self.stop_keys(), {})
        code, body = self.answer(stop["id"], confirmed=False, detail="its screen shows a question", reads=[note])
        self.assertEqual((code, body["state"], body["unread"]), (200, "not_confirmed", []))
        self.assertIsNotNone(hub.q1("SELECT read_at FROM events WHERE id=?", (note,))["read_at"])   # its turn runs
        self.assertEqual(self.stop_keys(), {"leo": asked["request_id"]})
        # The helper's ack of the first event did not reach the hub: the poll gives only the event of the press now,
        # and the hub takes the other one itself, so that no poll reads it again.
        code, again = self.press(asked["request_id"])
        self.assertEqual((code, again["changed"], again["stop"]["id"], again["stop"]["state"]),
                         (200, True, stop["id"], "requested"))
        events = self.events("leo", "chat_stop")
        self.assertEqual(len(events), 2)
        self.assertEqual([e["id"] for e in self.polled() if e["kind"] == "chat_stop"], [events[-1]["id"]])
        self.assertIsNotNone(hub.q1("SELECT helper_ack FROM events WHERE id=?", (events[0]["id"],))["helper_ack"])
        self.assertEqual(len([e for e in self.events("leo", "chat") if json.loads(e["extra"]).get("stop")]), 1)
        self.assertEqual(self.stop_keys(), {})


if __name__ == "__main__":
    unittest.main()

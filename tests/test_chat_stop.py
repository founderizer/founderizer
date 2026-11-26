"""Stop in the chat box (owner feature chat_stop, UI-API.md 1.301), the hub's part, through the real routes: when a
press can stop a turn (agents[].chat_stop), the press (POST /ui/chats/<agent>/stop), and what each reader of a
message's reply does with a stopped message. The owner, 21 November 2026: "Yes, add Stop (Recommended)". A test's own
database and stand-in helper reports: no AI call, no runtime, no session."""
import datetime
import json
import os
import tempfile
import time
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
        self.reads = {}         # {agent: the ids that its reads named in their first line, in order}

    # ---- helpers
    def features(self, agent, names=("chat_stop", "chat_turns")):
        """The agent's helper names these features in its machine status."""
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET "
              "data=excluded.data", (agent, json.dumps({"features": list(names)}), hub.now()))

    def send(self, text, agent="leo", **more):
        code, receipt = self.request("/ui/messages", self.command(recipient=agent, text=text, **more))
        self.assertEqual(code, 200, receipt)
        return receipt

    def read(self, agent="leo"):
        """What the agent's session reads with read_messages: a worker in its owner chat, the manager in its own. The
        ids that its first line names are kept (self.reads), as the helper finds them in the conversation file."""
        text = hub.call_tool(agent, "read_messages", {}, CONTEXT)[0] if agent != "manager" else \
            hub.t_read_messages("manager", {})
        self.reads.setdefault(agent, []).extend(fleet.read_ids(text))
        return text

    def chat_turn(self, agent, cut=False, reads=()):
        """The agent's helper reports a turn end of its owner chat (POST /helper/turn/<agent>, helper feature
        chat_turns): normal, or cut with what the cut turn read. On the hub's own clock (no `now`), so that its time is
        exact: with `now` the hub counts the request's way as a clock difference, and a read a millisecond after the
        end would look before it (test_a_turn_report_is_on_the_hubs_clock tests the clock pair)."""
        t = hub.now()
        body = dict({"ended": t}, **({"cut_end": t, "cut_reads": list(reads)} if cut else {}))
        self.assertEqual(self.request(f"/helper/turn/{agent}", body)[0], 200)

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
        first = self.read()
        self.assertTrue(first.startswith(f"Unread messages: M-{asked['event_id']}.\n\n"), first[:80])
        self.assertEqual(fleet.read_ids(first), [asked["event_id"]])      # what its helper finds in the chat's file
        self.assertIn("Rename every file", first)
        self.assertNotIn("Owner-chat guidance", first)                    # the manager's words only
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
        that cannot interrupt, for an agent that is not active, under "Not answering", and after a press; or from a
        worker's helper that reports no turn end of its owner chat, whose press would wait for good when its Esc did
        not take. The manager's turn ends come from its records: its helper needs no chat_turns."""
        self.assertEqual(self.stop_keys(), {})
        asked = self.send("Is the backup of today done?")
        self.assertEqual(self.stop_keys(), {})                                  # not read: no turn works on it
        self.read()
        self.assertEqual(self.stop_keys(), {"leo": asked["request_id"]})
        self.features("leo", ("chat_warm",))
        self.assertEqual(self.stop_keys(), {})                                  # a helper with no chat_stop
        self.features("leo", ("chat_stop",))
        self.assertEqual(self.stop_keys(), {})                                  # a helper with no chat_turns
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
        # The manager, whose helper names chat_stop only: the end of the turn that read the message ends it.
        self.features("manager", ("chat_stop",))
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
        # A worker's chat: its helper names the ids that the first lines of the cut turn's reads named since its last
        # normal end (fleet.read_ids), and the hub keeps those that come again: a task's result that the same read
        # gave, and an agent's message that a later read of the cut turn gave. The stopped message, a result that the
        # owner has already, an agent's message of an earlier turn and the owner's message with its reply stay read.
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
        self.assertEqual(self.reads["leo"][-2:], sorted([result, asked["event_id"]]))     # the cut turn's first read
        cut = [result, asked["event_id"], note, told]
        self.assertEqual(self.answer(stop["id"], reads=cut)[1]["unread"], [result, note])
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
        code, body = self.answer(stop["id"], cut=False, detail="no turn was running",
                                 reads=[result, again["event_id"]])     # the reads since the last normal end
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
        helper.cut_reads = lambda window, generation, until=None: (list(reads() if callable(reads) else reads), None)
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
        confirmed answer, a late answer, a turn end, normal or not), each row that the cut turn read and did not
        answer becomes unread again, except the owner's messages that the press closed or that have a report; and
        nothing that a turn which ended normally handled comes again. A worker's cut turn read what the first lines
        of its reads named since its last normal end (self.reads, as its helper finds them in its conversation file),
        and its helper reports its turn ends (chat_turn). The bugs: a task's result, an agent's report, the owner's correction or his answer to a secret
        request that the cut turn read is lost; or a row that a turn which ended normally handled comes twice."""
        self.assertIn("nothing that a turn which ended normally handled comes again", hub.CHAT_STOP_INVARIANT)
        for n in range(1, 15):          # fourteen workers, each on a machine of its own
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
        helper = self.stand_in("w1", [cutting], lambda: self.reads["w1"])
        self.press(asked["request_id"], "w1")
        self.helper_pass(helper, "w1")
        self.assertEqual(self.read_at(before, result, secret, asked["event_id"]), [True, False, False, True])
        # 2. not confirmed (an Esc went), a press again, then "no turn was running": the first Esc cut the turn
        before, result, secret, asked = worker("w2")
        helper = self.stand_in("w2", [not_confirmed, not_cut], lambda: self.reads["w2"])
        self.press(asked["request_id"], "w2")
        self.helper_pass(helper, "w2")
        self.assertEqual(self.read_at(result, secret), [True, True])            # not over yet: still read
        self.press(asked["request_id"], "w2")
        self.helper_pass(helper, "w2")
        self.assertEqual(self.read_at(before, result, secret), [True, False, False])
        # 3. not confirmed (the Esc did not take), then the owner's correction, which the same running turn reads
        # with another result: no read ends the press; the turn then ends cut, and all that it read comes again
        before, result, secret, asked = worker("w3")
        helper = self.stand_in("w3", [not_confirmed], lambda: self.reads["w3"])
        self.press(asked["request_id"], "w3")
        self.helper_pass(helper, "w3")
        self.send("Only the photos of November.", "w3")
        same = hub.emit("w3", "chat", "[hub] T-6 (Sort), which you opened from the owner's message, is completed.",
                        extra={"generation": "test-generation", "task_result": 6})
        self.read("w3")                                         # the same running turn reads them
        self.assertEqual(self.read_at(result, secret, same), [True, True, True])     # no read ends the press
        self.chat_turn("w3", cut=True, reads=self.reads["w3"])
        self.assertEqual(self.read_at(before, result, secret, same), [True, False, False, False])
        # 4. the answer's send fails after the Esc; the cut end reaches the hub; the correction is signalled and read;
        # the poll settles the press and never gives its event again; the correction's turn ends normally; the
        # helper's next pass sends the kept answer, confirmed: what the cut turn read comes again, whatever ended since
        before, result, secret, asked = worker("w4")
        helper = self.stand_in("w4", [cutting], lambda: self.reads["w4"], fails=1)
        self.press(asked["request_id"], "w4")
        self.helper_pass(helper, "w4")                                          # the Esc; its answer is kept
        self.chat_turn("w4", cut=True, reads=list(self.reads["w4"]))            # the cut turn's end
        self.send("Only the photos of November.", "w4")
        self.read("w4")
        self.assertEqual([e for e in self.polled("w4") if e["kind"] == "chat_stop"], [])     # settled, no event
        self.chat_turn("w4")                                                    # the correction's turn ends normally
        self.assertEqual(self.read_at(result, secret), [True, True])
        self.helper_pass(helper, "w4")                                          # the kept answer goes
        self.assertEqual(self.read_at(before, result, secret), [True, False, False])
        self.assertEqual(fleet.load_chat_stop_answers("w4"), {})
        # 4b. the same, but the cut turn's end never reaches the hub (its session went away with no end row): the hub
        # knows no cut end before the correction's normal end, and a late confirmed answer still gives its own reads
        before, result, secret, asked = worker("w6")
        helper = self.stand_in("w6", [cutting], lambda: self.reads["w6"], fails=1)
        self.press(asked["request_id"], "w6")
        self.helper_pass(helper, "w6")                                          # the Esc; its answer is kept
        self.send("Only the photos of November.", "w6")
        self.read("w6")
        self.assertEqual([e for e in self.polled("w6") if e["kind"] == "chat_stop"], [])     # settled, no event
        self.chat_turn("w6")                                                    # the correction's turn ends normally
        self.helper_pass(helper, "w6")                                          # the kept answer goes
        self.assertEqual(self.read_at(before, result, secret), [True, False, False])
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
        # the answer is not confirmed; that turn then ends normally: nothing that it handled comes again
        before, result, secret, asked = worker("w5")
        fixed = self.send("Only the photos of November.", "w5")
        helper = self.stand_in("w5", [not_confirmed], lambda: self.reads["w5"])
        self.press(asked["request_id"], "w5")
        events = [e for e in self.polled("w5") if e["kind"] == "chat_stop"]
        self.read("w5")                                         # the running turn reads the correction
        helper.handle_events(events)
        self.chat_turn("w5")
        self.assertEqual(self.read_at(before, result, secret, fixed["event_id"]), [True, True, True, True])

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
        helper.cut_reads = lambda window, generation, until=None: ([], None)    # its records since that normal end read nothing
        helper.handle_events(events)
        self.assertEqual(self.read_at(report), [True])
        # 13. a worker: an earlier turn read the owner's message, left it with no reply, read an agent's note and
        # ended with a read that gave nothing new; the cut turn reads a result and his new message, whose press closes
        # the old message too: the cut turn's result comes again, and the note that the earlier turn handled does not
        # (the earlier turn's normal end ends the reads that the helper names)
        old = self.send("Count the photos.", "w7")
        note = hub.emit("w7", "chat", "[agent manager] The disk is full.",
                        extra={"generation": "test-generation", "agent_message": True})
        self.read("w7")                                         # the earlier turn: the message and the note
        hub.q("UPDATE events SET read_at=(SELECT read_at FROM events WHERE id=?) WHERE id=?", (old["event_id"], note))
        self.read("w7")                                         # its closing read gives nothing new
        self.reads["w7"] = []                                   # and the turn ends normally
        result = hub.emit("w7", "chat", "[hub] T-8 (Sort), which you opened from the owner's message, is completed.",
                          extra={"generation": "test-generation", "task_result": 8})
        asked = self.send("Now the photos of November.", "w7")
        self.read("w7")                                         # the cut turn
        helper = self.stand_in("w7", [cutting], lambda: self.reads["w7"])
        self.press(asked["request_id"], "w7")
        self.helper_pass(helper, "w7")
        self.assertEqual(self.read_at(note, result, old["event_id"]), [True, False, True])
        # 20. a worker: the cut turn reads a message and a task's result, reads again with nothing new, then reads the
        # owner's correction; the press for the correction closes the first message too: the result comes again, from
        # whichever read of the cut turn it came
        first = self.send("Sort the photos of the year.", "w9")
        result = hub.emit("w9", "chat", "[hub] T-10 (Count), which you opened from the owner's message, is completed.",
                          extra={"generation": "test-generation", "task_result": 10})
        self.assertIn("T-10 (Count)", self.read("w9"))
        self.read("w9")                                         # nothing new
        fixed = self.send("No, only the photos of November.", "w9")
        self.read("w9")
        helper = self.stand_in("w9", [cutting], lambda: self.reads["w9"])
        self.press(fixed["request_id"], "w9")
        self.helper_pass(helper, "w9")
        self.assertEqual(self.read_at(result, first["event_id"]), [False, True])
        # 21. a worker: an earlier turn on the same message reads a result and ends normally with no reply: that
        # turn end ends the message's turn, as the manager's does, so no Stop is offered for it and a press changes
        # nothing; a new turn that reads it again brings nothing of the earlier turn back
        asked = self.send("Count the photos.", "w10")
        r1 = hub.emit("w10", "chat", "[hub] T-11 (Count), which you opened from the owner's message, is completed.",
                      extra={"generation": "test-generation", "task_result": 11})
        self.read("w10")
        self.assertEqual(self.stop_keys().get("w10"), asked["request_id"])
        self.chat_turn("w10")                                   # it ends normally, with no reply
        self.read("w10")                                        # a new turn reads the message again
        self.assertNotIn("w10", self.stop_keys())
        self.assertFalse(self.press(asked["request_id"], "w10")[1]["changed"])
        self.assertEqual(self.read_at(r1), [True])
        # 22. a worker: the Esc did not take; a press again; the same running turn reads the correction before the
        # poll, which gives no event; the turn ends cut: what it read comes again
        before, result, secret, asked = worker("w11")
        helper = self.stand_in("w11", [not_confirmed], lambda: self.reads["w11"])
        self.press(asked["request_id"], "w11")
        self.helper_pass(helper, "w11")
        self.press(asked["request_id"], "w11")
        self.send("No, only one line.", "w11")
        self.read("w11")
        self.assertEqual([e for e in self.polled("w11") if e["kind"] == "chat_stop"], [])
        self.chat_turn("w11", cut=True, reads=self.reads["w11"])
        self.assertEqual(self.read_at(before, result, secret), [True, False, False])
        # 23. a worker: the Esc did not take (an answer that cut, with its reads); a press again; the turn ends
        # normally while the press waits; the answer is confirmed with no reads since that end: nothing comes again
        before, result, secret, asked = worker("w12")
        helper = self.stand_in("w12", [not_confirmed, not_cut], lambda: self.reads["w12"])
        self.press(asked["request_id"], "w12")
        self.helper_pass(helper, "w12")
        self.press(asked["request_id"], "w12")
        events = [e for e in self.polled("w12") if e["kind"] == "chat_stop"]
        self.chat_turn("w12")
        self.reads["w12"] = []
        helper.handle_events(events)
        self.assertEqual(self.read_at(result, secret), [True, True])
        # 14. the manager: the Esc did not take; the owner presses again; the same running turn reads his correction
        # before the helper's poll, which gives no event; the turn ends normally: what it handled does not come again
        report, m = manager_press("the photos")
        helper = self.stand_in("manager", [not_confirmed], [report])
        self.press(m["request_id"], "manager")
        self.helper_pass(helper, "manager")
        self.assertTrue(self.press(m["request_id"], "manager")[1]["changed"])          # a press again
        self.send("No, only one line.", "manager")
        self.read("manager")                                    # the same running turn reads the correction
        self.assertEqual([e for e in self.polled("manager") if e["kind"] == "chat_stop"], [])
        turn_end(helper, "s10", "end_turn")
        self.assertEqual(self.read_at(report), [True])
        # 15. the manager: the Esc does not take and its answer is lost; the same running turn reads the correction,
        # and the poll settles the press; the kept answer comes then, and the turn ends normally: nothing again
        report, m = manager_press("the invoices")
        helper = self.stand_in("manager", [not_confirmed], [report], fails=1)
        self.press(m["request_id"], "manager")
        self.helper_pass(helper, "manager")                     # the Esc; its answer is kept
        self.send("No, only those of November.", "manager")
        self.read("manager")
        self.assertEqual([e for e in self.polled("manager") if e["kind"] == "chat_stop"], [])
        self.helper_pass(helper, "manager")                     # the kept answer goes
        turn_end(helper, "s11", "end_turn")
        self.assertEqual(self.read_at(report), [True])
        # 16. the manager: the answer is not confirmed; the turn runs on and reads another report; then it ends cut:
        # both reports come again, the one read after the answer too (the cut end's reads, cut_reads)
        r1, m = manager_press("the domain")
        helper = self.stand_in("manager", [not_confirmed], [r1])
        self.press(m["request_id"], "manager")
        self.helper_pass(helper, "manager")
        r2 = hub.emit("manager", "say", "[agent leo] The certificate expires tomorrow.")
        self.read("manager")                                    # the turn that still runs reads it
        helper.cut_reads = lambda window, generation, until=None: ([r1, r2], None)
        turn_end(helper, "s12", "cancelled")
        self.assertEqual(self.read_at(r1, r2), [False, False])
        # 17. the manager: the turn reads on and ends cut while the press waits for its helper; the answer that comes
        # after it is not confirmed: the reads of that cut end come again with the answer's own
        r1, m = manager_press("the newsletter")
        helper = self.stand_in("manager", [not_confirmed], [r1])
        self.press(m["request_id"], "manager")
        events = [e for e in self.polled("manager") if e["kind"] == "chat_stop"]
        r2 = hub.emit("manager", "say", "[agent leo] The list has 40 new names.")
        self.read("manager")
        helper.cut_reads = lambda window, generation, until=None: ([r1, r2] if until else [r1], None)
        turn_end(helper, "s13", "cancelled")
        helper.handle_events(events)
        self.assertEqual(self.read_at(r1, r2), [False, False])
        # 18. the manager: the Esc did not take; a press again; the same running turn reads the correction and ends
        # cut before the helper's poll: that poll ends the press at once, by the cut end, with its reads
        r1, m = manager_press("the prices")
        helper = self.stand_in("manager", [not_confirmed], [r1])
        self.press(m["request_id"], "manager")
        self.helper_pass(helper, "manager")
        self.press(m["request_id"], "manager")
        self.send("No, only the prices of the shop.", "manager")
        self.read("manager")
        turn_end(helper, "s14", "cancelled")
        self.assertEqual(self.read_at(r1), [True])                  # the press waited for its helper at that end
        self.assertEqual([e for e in self.polled("manager") if e["kind"] == "chat_stop"], [])
        self.assertEqual(self.read_at(r1), [False])

    def test_a_kept_answer_of_an_earlier_event_never_takes_the_press_again(self):
        """The hub takes an answer that is not confirmed and its reply is lost, so the helper keeps it; the owner
        presses again; a pass of the helper whose poll came before that press sends the kept answer. The bug: that
        answer of the first event made the row not_confirmed again, the new event was never given, and the press
        again sent no Esc."""
        asked = self.send("Now the photos.")
        self.read()
        helper = self.stand_in("leo", [(False, "the session still shows a running turn after three interrupts", True),
                                       (True, "interrupted; the session is idle", True)], [])
        lose = [1]

        def http(method, path, data=None, timeout=40):
            answer = self.request(path, data)
            if path.startswith("/helper/chat-stop/") and lose[0]:
                lose[0] -= 1
                raise urllib.error.URLError("the reply of the hub is lost")
            return answer
        with unittest.mock.patch.object(fleet, "http", http):
            stop = self.press(asked["request_id"])[1]["stop"]
            self.helper_pass(helper, "leo")
            self.assertTrue(fleet.load_chat_stop_answers("leo"))            # kept: its reply was lost
            self.assertTrue(self.press(asked["request_id"])[1]["changed"])  # the owner presses again
            helper.handle_events([])                # a pass whose poll the hub answered before that press
            self.assertEqual(fleet.load_chat_stop_answers("leo"), {})       # refused (409), and dropped
            self.helper_pass(helper, "leo")         # the poll gives the new event: the Esc goes
        self.assertEqual(hub.q1("SELECT state FROM chat_stops WHERE id=?", (stop["id"],))["state"], "stopped")

    def test_an_answer_that_shows_a_normal_end_after_the_press_ends_it_at_once(self):
        """The answer of a press carries the time of the session's last normal turn end from the same read of its
        conversation file (normal_end, on the helper's clock, now): a normal end after the press ends a press that
        is not confirmed at once, with nothing again, also when the turn report did not come yet. The bug: the press
        stayed not_confirmed, and its turn's reads waited for a report."""
        result = hub.emit("leo", "chat", "[hub] T-5 (Count), which you opened from the owner's message, is completed.",
                          extra={"generation": "test-generation", "task_result": 5})
        asked = self.send("Now the photos.")
        self.read()
        stop = self.press(asked["request_id"])[1]["stop"]
        later = hub.now() + 100                 # the helper's clock is 100 seconds ahead; its normal end is now
        code, body = self.answer(stop["id"], confirmed=False, cut=True, reads=[], normal_end=later,
                                 now=later, detail="the session still shows a running turn")
        self.assertEqual((code, body["state"], body["unread"]), (200, "stopped", []), body)
        self.assertEqual(self.read_at(result), [True])

    def test_a_turn_report_is_on_the_hubs_clock(self):
        """A helper's turn report names its own clock (now): the hub keeps each time on its own clock (t0 - now
        more). The bug: a helper whose clock is ahead made every turn end look later than a press, or than now."""
        t = hub.now()
        self.assertEqual(self.request("/helper/turn/leo", {"ended": t + 500, "cut_end": t + 500, "cut_reads": [],
                                                           "now": t + 510})[0], 200)
        self.assertLess(abs(hub.turn_ended("leo") - (t - 10)), 2)
        self.assertLess(abs(float(hub.kv_get("turn_cut:leo")) - (t - 10)), 2)
        code, data = self.request("/events/leo?delivery=1&after=0&wait=0")     # and the hub names its own to the helper
        self.assertLess(abs(data["now"] - hub.now()), 2)

    # ---- the real helper of an owner chat, with its conversation file (fleet.Helper.report_chat_turns)
    def chat_helper(self, agent="leo"):
        """The real fleet.Helper of a Claude owner chat whose conversation file is self.path; its screen part says not
        confirmed after an Esc that went (cut). self.turn_fails: how many of its next turn reports the hub does not
        get."""
        home = tempfile.mkdtemp(prefix="chat-stop-turns-")
        self.path, self.turn_fails, self.answer_fails, self.calls = os.path.join(home, "chat.jsonl"), 0, 0, 0
        open(self.path, "w").close()

        def http(method, path, data=None, timeout=40):
            if path.startswith("/helper/turn/") and self.turn_fails:
                self.turn_fails -= 1
                raise urllib.error.URLError("the hub restarts")
            if path.startswith("/helper/chat-stop/") and self.answer_fails:
                self.answer_fails -= 1
                raise urllib.error.URLError("the hub restarts")
            return self.request(path, data)
        for patcher in (unittest.mock.patch.object(fleet, "HOME", home),
                        unittest.mock.patch.object(fleet, "http", http),
                        unittest.mock.patch.object(fleet, "load_chat_record",
                                                   return_value={"generation": "test-generation"})):
            patcher.start()
            self.addCleanup(patcher.stop)
        return self.chat_helper_again(agent)

    def chat_helper_again(self, agent="leo"):
        """A new fleet.Helper of the same owner chat, as after a start of the helper: it remembers nothing."""
        helper = fleet.Helper(agent, dict(hub.TEAM["agents"][agent], runtime="claude"))
        helper.chat_binding = lambda runtime, generation: self.path
        helper.chat_turn_stop = lambda window, extra: (False, "its conversation file still changes", True)
        return helper

    def stops(self, agent="leo"):
        return [e for e in self.polled(agent) if e["kind"] == "chat_stop"]

    def state_of(self, stop):
        return hub.q1("SELECT state FROM chat_stops WHERE id=?", (stop["id"],))["state"]

    def result(self, n, agent="leo"):
        return hub.emit(agent, "chat", f"[hub] T-{n} (Sort), which you opened from the owner's message, is completed.",
                        extra={"generation": "test-generation", "task_result": n})

    def test_a_report_of_an_end_before_the_cut_turns_reads_ends_no_press(self):
        """The press's turn ends normally after the press, the next turn reads a result, and the Esc cuts it, not
        confirmed; the report of the normal end does not reach the hub before the answer, and comes after it. Then the
        cut turn ends: its result comes again. And: the first turn ends cut after the press, the Esc does not take, the
        helper starts again while the next turn runs and sends that cut end again; that turn then ends normally: only
        the first turn's result comes again. The bugs: an end that came before the cut turn's own reads ended the
        press, with nothing again or with what a running turn still works on."""
        helper = self.chat_helper()
        asked = self.send("Now the photos.")
        self.file_read()                                # the press's turn
        helper.handle_events([])
        stop = self.press(asked["request_id"])[1]["stop"]
        self.file_end()                                 # it ends normally, after the press
        r2 = self.result(7)
        self.file_read()                                # the next turn
        self.turn_fails = 1
        helper.handle_events(self.stops())              # the report of that end fails; the Esc cuts the next turn
        self.assertEqual(self.state_of(stop), "not_confirmed")
        self.file_end(normal=False)
        helper.handle_events([])                        # both ends, the normal one first, after the answer
        self.assertEqual((self.state_of(stop), self.read_at(r2)), ("stopped", [False]))
        # the first turn ends cut, and the helper starts again
        r1, asked = self.result(8), self.send("Now the videos.")
        self.file_read()
        helper.handle_events([])
        stop = self.press(asked["request_id"])[1]["stop"]
        self.file_end(normal=False)                     # an API error, after the press
        r2 = self.result(9)
        self.file_read()                                # the next turn
        helper.handle_events(self.stops())              # that end goes; the Esc does not take
        self.assertEqual(self.state_of(stop), "not_confirmed")
        helper = self.chat_helper_again()
        helper.handle_events([])                        # its first pass sends that cut end again
        self.assertEqual((self.state_of(stop), self.read_at(r1, r2)), ("not_confirmed", [True, True]))
        self.file_end()                                 # the next turn ends normally: it handled r2
        helper.handle_events([])
        self.assertEqual((self.state_of(stop), self.read_at(r1, r2)), ("stopped", [False, True]))

    def test_a_kept_answer_after_its_turns_normal_end_ends_the_press(self):
        """The Esc does not take and its answer's send fails; the turn ends normally and handles a result; a later turn
        reads another one and ends at an API error; the kept answer goes after both ends. The press ends at once, the
        handled result does not come again, and the message is not late. The bugs: the press stayed not_confirmed and
        the cut end gave the handled result a second time; the cut end hid the normal end before it, so nothing was
        taken as handled; the stopped message said "Not answering"."""
        helper = self.chat_helper()
        asked = self.send("Now the photos.")
        r1 = self.result(5)
        self.file_read()
        helper.handle_events([])
        stop = self.press(asked["request_id"])[1]["stop"]
        self.answer_fails = 1
        helper.handle_events(self.stops())              # the Esc does not take; its answer is kept
        self.file_end()                                 # the turn ends normally: it handled r1
        self.result(6)
        self.file_read()                                # a later turn
        self.file_end(normal=False)                     # ends at an API error
        helper.handle_events(self.stops())              # both ends go, then the kept answer
        self.assertEqual((self.state_of(stop), self.read_at(r1)), ("stopped", [True]))
        self.assertIsNone(hub.chat_late("leo", hub.now() + 2 * hub.CHAT_LATE))

    def test_a_late_answer_after_its_turns_normal_end_ends_the_press(self):
        """The Esc does not take and its answer's send fails; the same running turn reads the correction, so the poll
        settles the press; the turn ends normally; the late answer comes after that end. The press ends at once, as
        UI-API.md 1.301 says, with nothing again. The bug: it stayed not_confirmed, and a later cut end gave the
        handled result a second time."""
        helper = self.chat_helper()
        asked = self.send("Now the photos.")
        r1 = self.result(5)
        self.file_read()
        helper.handle_events([])
        stop = self.press(asked["request_id"])[1]["stop"]
        self.answer_fails = 1
        helper.handle_events(self.stops())              # the Esc does not take; its answer is kept
        self.send("No, only one.")
        self.file_read()                                # the same running turn reads the correction
        self.assertEqual(self.stops(), [])              # the poll settles the press
        self.file_end()                                 # the turn ends normally: it handled r1
        helper.handle_events([])                        # that end goes, then the late answer
        self.assertEqual(self.state_of(stop), "stopped")
        self.result(6)
        self.file_read()
        self.file_end(normal=False)                     # a later turn ends at an API error
        helper.handle_events([])
        self.assertEqual(self.read_at(r1), [True])

    def test_a_second_esc_after_a_normal_end_gives_only_the_reads_of_the_turn_that_it_cut(self):
        """The Esc does not take (its answer names a result of the first turn); a press again; the first turn ends
        normally while the press waits; the next turn reads another result; the second Esc goes into it, not confirmed;
        that turn ends cut. Only its own result comes again: also when the report of the normal end reaches the hub
        only after the second answer (it failed while the hub restarted), so that the answer's own normal end and
        bound (normal_cut) decide. The bugs: the kept ids of the first answer came with it, and the result that the
        first turn had handled came a second time; with the report late, an answer whose bound the hub did not take
        counted nothing as handled, and that result came a second time too."""
        hub.TEAM["addresses"]["w1-host"] = "127.0.0.11"
        hub.TEAM["agents"]["w1"] = dict(hub.TEAM["agents"]["leo"], machine="w1-host")
        self.features("w1")
        for agent, late in (("leo", False), ("w1", True)):
            with self.subTest(agent=agent, late=late):
                r1 = self.result(5, agent)
                asked = self.send("Now the photos.", agent)
                self.read(agent)
                stop = self.press(asked["request_id"], agent)[1]["stop"]
                self.answer(stop["id"], agent, confirmed=False, cut=True, reads=list(self.reads[agent]),
                            detail="the session still shows a running turn after three interrupts")
                self.assertTrue(self.press(asked["request_id"], agent)[1]["changed"])
                ended = hub.now()                       # the first turn ends normally
                if not late:
                    self.assertEqual(self.request(f"/helper/turn/{agent}", {"ended": ended})[0], 200)
                r2 = self.result(6, agent)
                mark = len(self.reads[agent])
                self.read(agent)
                after = self.reads[agent][mark:]
                code, body = self.answer(stop["id"], agent, confirmed=False, cut=True, reads=after, normal_end=ended,
                                         normal_cut=0.0, detail="the session still shows a running turn")
                self.assertEqual(body["state"], "not_confirmed", body)
                if late:        # the report that failed goes again
                    self.assertEqual(self.request(f"/helper/turn/{agent}", {"ended": ended})[0], 200)
                self.chat_turn(agent, cut=True, reads=after)
                self.assertEqual(self.read_at(r1, r2), [True, False])

    def test_a_cut_turn_before_a_normal_end_keeps_its_reads_in_a_later_answer(self):
        """The Esc does not take (its answer names a result); a press again; the first Esc takes late and the turn ends
        cut; a normal turn reads and handles another result; the second Esc cuts the next turn, not confirmed, and
        names that normal end and the cut end before it (normal_cut); that turn ends cut. The results of both cut turns
        come again, the handled one not: with the two turn reports before the answer, after it (a report that failed
        while the hub restarted), and after an answer of a helper of an earlier build, which names no bound and so
        takes nothing as handled; and from a helper whose clock is 100 seconds behind the hub's, whose answer names
        both times on its own clock and its `now`. The bugs: a row read before the newest normal end counted as
        handled, also one that a cut turn before it read; with the reports late, the hub's old cut end made the first
        turn's result handled; the answer's bound taken on the helper's clock made it handled too."""
        for n in (1, 2, 3):
            hub.TEAM["addresses"][f"w{n}-host"] = f"127.0.0.{10 + n}"
            hub.TEAM["agents"][f"w{n}"] = dict(hub.TEAM["agents"]["leo"], machine=f"w{n}-host")
            self.features(f"w{n}")
        for agent, late, bound, behind in (("leo", False, True, 0), ("w1", True, True, 0), ("w2", True, False, 0),
                                           ("w3", True, True, 100)):
            with self.subTest(agent=agent, late=late, bound=bound, behind=behind):
                r1 = self.result(5, agent)
                asked = self.send("Now the photos.", agent)
                self.read(agent)                        # the first turn
                stop = self.press(asked["request_id"], agent)[1]["stop"]
                self.answer(stop["id"], agent, confirmed=False, cut=True, reads=list(self.reads[agent]),
                            detail="the session still shows a running turn after three interrupts")
                self.assertTrue(self.press(asked["request_id"], agent)[1]["changed"])          # a press again
                first, c1 = list(self.reads[agent]), hub.now()      # the first Esc takes late: the turn ends cut
                time.sleep(0.1)                         # the next turn reads later than an answer's way to the hub
                r2 = self.result(6, agent)
                self.read(agent)                        # a normal turn
                e2 = hub.now()
                time.sleep(0.1)                         # the next turn starts later than an answer's way to the hub
                reports = [{"ended": c1, "cut_end": c1, "cut_reads": first}, {"ended": e2}]
                for report in ([] if late else reports):
                    self.assertEqual(self.request(f"/helper/turn/{agent}", report)[0], 200)
                r3 = self.result(7, agent)
                mark = len(self.reads[agent])
                self.read(agent)                        # the turn that the second Esc cuts
                after = self.reads[agent][mark:]
                clock = {"now": hub.now() - behind} if behind else {}       # the helper's own clock and times
                code, body = self.answer(stop["id"], agent, confirmed=False, cut=True, reads=after,
                                         normal_end=e2 - behind, detail="the session still shows a running turn",
                                         **({"normal_cut": c1 - behind} if bound else {}), **clock)
                self.assertEqual(body["state"], "not_confirmed", body)
                for report in (reports if late else []):
                    self.assertEqual(self.request(f"/helper/turn/{agent}", report)[0], 200)
                self.chat_turn(agent, cut=True, reads=after)
                self.assertEqual(self.read_at(r1, r2, r3), [False, True, False])

    def test_an_answers_normal_end_that_the_hub_has_takes_the_hubs_bound(self):
        """An answer's normal end counts only when it is newer than both the hub's newest normal end and its newest cut
        end (the reports of those ends did not come yet): then with the bound that the answer names, and with none when
        it names none (an earlier build), so that nothing counts as handled. A normal end that the hub has already,
        a little later on another clock pair, takes the hub's own pair. The answer's bound is never before the hub's
        own newest cut end (the manager's turn that ends at max_tokens is a cut end in its records and no end in its
        file). The bugs: the answer's normal end counted as the newer one when it only passed the hub's normal end, and
        with no bound nothing counted as handled; a row read before the hub's cut end counted as handled. (No press can
        reach that answer with rows of that window today: the stop line, read in the next turn, ends Stop; the rule
        is kept for the field's clocks.)"""
        t = hub.now()
        for report in ({"ended": t - 30, "cut_end": t - 30, "cut_reads": []}, {"ended": t - 20},
                       {"ended": t - 10, "cut_end": t - 10, "cut_reads": []}):
            self.assertEqual(self.request("/helper/turn/leo", report)[0], 200)
        self.assertEqual(hub.chat_stop_newest_normal_end("leo"), (t - 20, t - 30))
        self.assertEqual(hub.chat_stop_newest_normal_end("leo", t - 20 + 1e-6), (t - 20, t - 30))
        self.assertEqual(hub.chat_stop_newest_normal_end("leo", t - 20 + 1e-6, t - 25), (t - 20, t - 30))
        self.assertEqual(hub.chat_stop_newest_normal_end("leo", t - 5, t - 10), (t - 5, t - 10))
        self.assertEqual(hub.chat_stop_newest_normal_end("leo", t - 5, t - 25), (t - 5, t - 10))
        self.assertEqual(hub.chat_stop_newest_normal_end("leo", t - 5), (0.0, 0.0))

    def test_a_normal_end_sent_again_keeps_the_bound_of_its_turn(self):
        """The Esc does not take (its answer names a result); a press again; the turn ends normally and handles it; the
        next turn reads another result and ends cut; a helper that starts again sends the normal end again, a little
        later on its own clock pair; then the second answer. The handled result does not come again. The bug: the
        resent normal end became the newest one, its bound became itself, nothing counted as handled, and the result
        came a second time."""
        r1 = self.result(5)
        asked = self.send("Now the photos.")
        self.read()
        stop = self.press(asked["request_id"])[1]["stop"]
        self.answer(stop["id"], confirmed=False, cut=True, reads=list(self.reads["leo"]),
                    detail="the session still shows a running turn after three interrupts")
        self.assertTrue(self.press(asked["request_id"])[1]["changed"])          # a press again
        e1 = hub.now()
        self.assertEqual(self.request("/helper/turn/leo", {"ended": e1})[0], 200)   # it handled r1
        time.sleep(0.2)                                 # the next turn comes later than the resend's clock shift
        r2 = self.result(6)
        mark = len(self.reads["leo"])
        self.read()                                     # the next turn
        after = self.reads["leo"][mark:]
        self.chat_turn("leo", cut=True, reads=after)    # it ends cut
        self.assertEqual(self.request("/helper/turn/leo", {"ended": e1, "now": hub.now() - 0.05})[0], 200)  # again
        code, body = self.answer(stop["id"], confirmed=False, cut=True, reads=after,
                                 detail="the session still shows a running turn after three interrupts")
        self.assertEqual(body["state"], "stopped", body)
        self.assertEqual(self.read_at(r1, r2), [True, False])

    def workers(self, n):
        """Workers w1 to w<n>, as leo, each on its own machine, whose helpers can stop a turn."""
        for i in range(1, n + 1):
            hub.TEAM["addresses"][f"w{i}-host"] = f"127.0.0.{10 + i}"
            hub.TEAM["agents"][f"w{i}"] = dict(hub.TEAM["agents"]["leo"], machine=f"w{i}-host")
            self.features(f"w{i}")

    def went_away(self, agent):
        """A press whose Esc does not take (its answer names a result that the cut turn read), and then a new session
        of the agent's owner chat: the helper replaced the stuck one (a chat's proof, a revoked credential, new tools,
        a window gone), whose turn wrote no end row, and the new one has the credential that helper_session writes at
        its start. (the result, the stopped message, the press, a time of the old session before the new start)"""
        r1 = self.result(5, agent)
        asked = self.send("Now the photos.", agent)
        self.read(agent)
        stop = self.press(asked["request_id"], agent)[1]["stop"]
        self.answer(stop["id"], agent, confirmed=False, cut=True, reads=list(self.reads[agent]),
                    detail="the session still shows a running turn after three interrupts")
        before = hub.now()
        time.sleep(0.05)
        hub.q("INSERT INTO session_credentials(sha256,agent,kind,generation,created) VALUES(?,?,?,?,?)",
              (uuid.uuid4().hex * 2, agent, "chat", "test-generation", hub.now()))
        time.sleep(0.05)
        return r1, asked, stop, before

    def test_a_press_whose_session_went_away_gives_its_reads_at_the_next_sessions_turn_end(self):
        """The Esc does not take, and the helper replaces the stuck session (went_away). (1) The new session reads the
        owner's correction, and its turn ends normally: the press ends, and the result comes again. (2) The old turn's
        own normal end, before the new start, is reported only after it: that turn handled the result, which does not
        come again. (3) A press again; the Esc goes into the new session's turn, which read another result, and does
        not take; that turn ends normally: the old result comes again, the new one not. (4) The same, after a normal
        end of the new session that the hub has before the answer. (5) The new session's first turn reads another
        result and ends cut, and its next turn ends normally: one report holds both ends. (6) As (2), after a turn
        before the press that read another result and ended cut (an API error, not the press): the session did not go
        away, and that result does not come again either. The bugs: no end of the old turn ever came, the new session's
        end ended the press with nothing, and the result stayed read for good; a late report of the old turn's own end
        gave its result twice; the new session's normal end gave its own reads again, or counted a row of the old
        session as handled; a cut end before the newest end gave only its own turn's reads, and the old session's
        result was lost; a new session that started after the turn's normal end counted as one that went away, and the
        result of the earlier cut turn came again. (7) A press again; the new session's turn reads another result and
        the stop line, and the Esc does not stop it at once: it ends normally, and the answer, not confirmed, names
        that end before its report reaches the hub. That end ends the press: the old result comes again, the new one
        not. The bug: the end that ended the press was not the one that bounded the session that went away, and the
        old result stayed read for good. (8) The old turn had ended normally before the new start, and its report comes
        late; a press again; the new session's turn reads another result, the Esc does not take, the old end's report
        comes, and the new turn ends cut: the new result comes again, the old one not. (9) The same, but the new turn
        ends normally and the answer names that end, after the old end's report: nothing comes again. The bugs: the
        newest cut end gave the kept ids that the old turn had handled; the answer's newer end hid the hub's older one,
        and the old result came a second time. (10) A press again; the new session's turn reads another result, the
        Esc does not take, and its answer does not go yet; that turn ends normally, the next one reads a third result
        and ends cut, and a normal turn follows; then the answer: the old result and the third come again, the one that
        the first new turn handled not. The bug: the rows of the new session counted as the old session's, and that
        result came a second time."""
        self.workers(9)
        for agent, case in (("leo", "went away"), ("w1", "ended before"), ("w2", "not confirmed again"),
                            ("w3", "a normal end first"), ("w4", "a cut end, then a normal end"),
                            ("w5", "ended before, after a cut turn"), ("w6", "a normal end in the answer"),
                            ("w7", "the old end late, then a cut end"),
                            ("w8", "the old end late, then a normal end in the answer"),
                            ("w9", "a late answer after the new session's ends")):
            with self.subTest(agent=agent, case=case):
                rx, ry = [], []
                if case == "ended before, after a cut turn":
                    rx = [self.result(4, agent)]
                    self.read(agent)                        # a turn before the press reads it and ends cut
                    self.chat_turn(agent, cut=True, reads=list(self.reads[agent]))
                    time.sleep(0.05)
                r1, asked, stop, before = self.went_away(agent)
                r2 = []
                if case == "went away":
                    self.send("No, only one.", agent)       # the correction, unread while the old session hung
                    self.read(agent)                        # the new session reads it
                    self.chat_turn(agent)                   # and its turn ends normally
                elif case.startswith("ended before"):
                    self.assertEqual(self.request(f"/helper/turn/{agent}", {"ended": before})[0], 200)
                elif case == "a late answer after the new session's ends":
                    self.assertTrue(self.press(asked["request_id"], agent)[1]["changed"])     # a press again
                    r2 = [self.result(6, agent)]
                    mark = len(self.reads[agent])
                    self.read(agent)                        # the new session's turn: the result and the stop line
                    named = self.reads[agent][mark:]        # the Esc does not take; its answer does not go yet
                    self.chat_turn(agent)                   # that turn ends normally; the press waits for its helper
                    ry = [self.result(7, agent)]
                    mark = len(self.reads[agent])
                    self.read(agent)
                    self.chat_turn(agent, cut=True, reads=self.reads[agent][mark:])      # the next turn ends cut
                    time.sleep(0.05)
                    self.chat_turn(agent)                   # and a normal turn follows
                    code, body = self.answer(stop["id"], agent, confirmed=False, cut=True, reads=named,
                                             detail="the session still shows a running turn")
                    self.assertEqual(body["state"], "stopped", body)
                elif case.startswith("the old end late, then"):
                    self.assertTrue(self.press(asked["request_id"], agent)[1]["changed"])     # a press again
                    r2 = [self.result(6, agent)]
                    mark = len(self.reads[agent])
                    self.read(agent)                        # the new session's turn: the result and the stop line
                    if case == "the old end late, then a cut end":
                        self.answer(stop["id"], agent, confirmed=False, cut=True, reads=self.reads[agent][mark:],
                                    detail="the session still shows a running turn")
                        self.assertEqual(self.request(f"/helper/turn/{agent}", {"ended": before})[0], 200)
                        self.chat_turn(agent, cut=True, reads=self.reads[agent][mark:])   # the new turn ends cut
                    else:
                        self.assertEqual(self.request(f"/helper/turn/{agent}", {"ended": before})[0], 200)
                        start = hub.q1("SELECT MAX(created) AS t FROM session_credentials WHERE agent=?",
                                       (agent,))["t"]
                        ended = hub.now()                   # the new turn ends normally; its report is late
                        code, body = self.answer(stop["id"], agent, confirmed=False, cut=True, reads=[],
                                                 normal_end=ended, normal_cut=start,
                                                 detail="the session still shows a running turn")
                        self.assertEqual(body["state"], "stopped", body)
                        self.assertEqual(self.request(f"/helper/turn/{agent}", {"ended": ended})[0], 200)
                elif case == "a normal end in the answer":
                    self.assertTrue(self.press(asked["request_id"], agent)[1]["changed"])     # a press again
                    r2 = [self.result(6, agent)]
                    self.read(agent)                        # the new session's turn: the result and the stop line
                    start = hub.q1("SELECT MAX(created) AS t FROM session_credentials WHERE agent=?", (agent,))["t"]
                    ended = hub.now()                       # the Esc did not stop it at once: it ended normally
                    code, body = self.answer(stop["id"], agent, confirmed=False, cut=True, reads=[], normal_end=ended,
                                             normal_cut=start, detail="the session still shows a running turn")
                    self.assertEqual(body["state"], "stopped", body)                   # that end ends the press
                    self.assertEqual(self.request(f"/helper/turn/{agent}", {"ended": ended})[0], 200)  # its report
                elif case == "a cut end, then a normal end":
                    r2 = [self.result(6, agent)]
                    mark = len(self.reads[agent])
                    self.read(agent)                        # the new session's first turn, which ends cut
                    cut = hub.now()
                    time.sleep(0.05)
                    report = {"ended": hub.now(), "cut_end": cut, "cut_reads": self.reads[agent][mark:]}
                    self.assertEqual(self.request(f"/helper/turn/{agent}", report)[0], 200)
                else:
                    self.assertTrue(self.press(asked["request_id"], agent)[1]["changed"])     # a press again
                    if case == "a normal end first":
                        self.chat_turn(agent)               # a turn of the new session ends normally
                        time.sleep(0.05)
                    r2 = [self.result(6, agent)]
                    mark = len(self.reads[agent])
                    self.read(agent)                        # the new session's turn that the Esc goes into
                    code, body = self.answer(stop["id"], agent, confirmed=False, cut=True,
                                             reads=self.reads[agent][mark:], detail="the session shows a running turn")
                    self.assertEqual(body["state"], "not_confirmed", body)
                    self.chat_turn(agent)                   # that turn ends normally
                # the new turn ended normally; the old turn ended normally
                handled = case not in ("a cut end, then a normal end", "the old end late, then a cut end")
                old_end = case.startswith(("ended before", "the old end late"))
                self.assertEqual((self.state_of(stop), self.read_at(r1, *rx, *r2, *ry)),
                                 ("stopped", [old_end] + [True] * len(rx) + [handled] * len(r2) + [False] * len(ry)))

    def test_a_confirmed_answer_after_the_session_went_away_gives_the_old_sessions_reads_too(self):
        """The Esc does not take, and the helper replaces the stuck session (went_away). (1) A press again finds the new
        session idle: its answer is confirmed, with no reads. (2) A press again; the new session's turn reads another
        result, and the Esc cuts it: confirmed. (The press comes before that read: the read gives the stop line, and
        then Stop is no longer offered for that message, chat_stop_over.) (3) The owner presses Stop under a newer
        message that the new session read: its Esc is confirmed and ends the older press. Each time the old session's
        result comes again, with the reads of the new cut turn. (4) The old turn had ended normally before the new
        start, and its report reaches the hub only after the press again (it failed, or the chat was replaced in the
        same round): then the idle answer gives nothing again. (5) A press again; the new session's turn reads another
        result and the stop line, the Esc does not take, and that turn ends normally, with its report late; the owner
        presses Stop under a newer message, and that answer is confirmed and names that normal end: the old result
        comes again, the one that the new turn handled not. (6) A resumed conversation: the idle answer names the old
        turn's normal end, from the same file, before its report reaches the hub: nothing comes again. The bugs: a
        confirmed answer gave only the reads of the new session's file, and the old session's result stayed read for
        good; the result that the old turn handled came a second time; the result that the new session's turn handled
        came a second time."""
        self.workers(6)
        for agent, case in (("w1", "idle"), ("w2", "cut"), ("w3", "a newer press"), ("w4", "the old end late"),
                            ("w5", "the new session's end late"), ("w6", "the old end only in the answer")):
            with self.subTest(agent=agent, case=case):
                r1, asked, stop, before = self.went_away(agent)
                cut = case in ("cut", "a newer press", "the new session's end late")
                r2 = [self.result(6, agent)] if cut else []
                mark = len(self.reads[agent])
                ends, late = {}, None
                if case == "a newer press":
                    newer = self.send("And the videos?", agent)
                    self.read(agent)
                    pressed = self.press(newer["request_id"], agent)[1]["stop"]
                    self.assertNotEqual(pressed["id"], stop["id"])
                elif case == "the new session's end late":
                    self.assertTrue(self.press(asked["request_id"], agent)[1]["changed"])     # a press again
                    self.read(agent)                        # the new session's turn: the result and the stop line
                    self.answer(stop["id"], agent, confirmed=False, cut=True, reads=self.reads[agent][mark:],
                                detail="the session still shows a running turn")
                    late = hub.now()                        # that turn ends normally; its report does not go yet
                    time.sleep(0.05)
                    newer = self.send("And the videos?", agent)
                    mark = len(self.reads[agent])
                    self.read(agent)
                    pressed = self.press(newer["request_id"], agent)[1]["stop"]
                    ends = {"normal_end": late, "normal_cut": 0.0}         # the new file's last normal end
                else:
                    self.assertTrue(self.press(asked["request_id"], agent)[1]["changed"])     # a press again
                    pressed = stop
                    if r2:
                        self.read(agent)                    # the new session's turn that the Esc cuts
                    if case == "the old end late":          # the old turn's normal end, before the new start
                        self.assertEqual(self.request(f"/helper/turn/{agent}", {"ended": before})[0], 200)
                    if case == "the old end only in the answer":
                        ends, late = {"normal_end": before, "normal_cut": 0.0}, before
                code, body = self.answer(pressed["id"], agent, confirmed=True, cut=cut, reads=self.reads[agent][mark:],
                                         detail="interrupted; the session is idle" if cut else "no turn was running",
                                         **ends)
                self.assertEqual((code, body["state"]), (200, "stopped"), body)
                if late is not None:                        # the report that was late goes now
                    self.assertEqual(self.request(f"/helper/turn/{agent}", {"ended": late})[0], 200)
                handled = case in ("the old end late", "the old end only in the answer")
                self.assertEqual((self.state_of(stop), self.read_at(r1, *r2)),
                                 ("stopped", [handled] + [case == "the new session's end late"] * len(r2)))

    def test_a_late_message_of_a_worker_says_not_answering_after_its_turn_ended(self):
        """Owner API 1.144: a worker read the owner's message and wrote no reply for CHAT_LATE seconds; its turn ended
        (here at an API error). The apps say "Not answering" under the message only while no turn end covers it, so the
        state that they read gives no turn end for it while it is late; its chat gives it again at the next read. The
        bug: the turn end hid the line, and the late message showed nothing at all."""
        asked = self.send("Is the backup of today done?")
        self.read()
        self.chat_turn("leo", cut=True, reads=list(self.reads["leo"]))
        created = hub.q1("SELECT created FROM ui_requests WHERE request_id=?", (asked["request_id"],))["created"]
        agents = lambda: {a["name"]: a for a in self.request("/ui/state")[1]["agents"]}
        self.assertGreaterEqual(agents()["leo"]["turn_ended_after"], created)       # not late yet: the turn is over
        hub.chat_late_sweep(hub.now() + hub.CHAT_LATE + 10)
        leo = agents()["leo"]
        self.assertTrue(leo["chat_undelivered"])
        self.assertFalse(leo["turn_ended_after"] is not None and leo["turn_ended_after"] >= created, leo)
        mobile = {a["name"]: a for a in self.request("/ui/mobile")[1]["agents"]}["leo"]
        self.assertFalse(mobile["turn_ended_after"] is not None and mobile["turn_ended_after"] >= created, mobile)
        self.assertIn("Is the backup of today done?", self.read())       # its next turn gets it again

    def file_rows(self, *rows):
        with open(self.path, "a") as f:
            f.write("".join(json.dumps(r) + "\n" for r in rows))

    def file_read(self, agent="leo"):
        """The session calls read_messages: its call and its answer go to the conversation file."""
        text = self.read(agent)
        self.calls += 1
        at = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        self.file_rows({"type": "assistant", "timestamp": at, "message": {"stop_reason": "tool_use", "content": [
                           {"type": "tool_use", "id": f"r{self.calls}", "name": fleet.FLEET_READ, "input": {}}]}},
                       {"type": "user", "timestamp": at, "message": {"content": [
                           {"type": "tool_result", "tool_use_id": f"r{self.calls}", "content": text}]}})
        return text

    def file_end(self, normal=True):
        time.sleep(0.01)
        at = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        self.file_rows({"type": "assistant", "timestamp": at, "message": {"stop_reason": "end_turn", "content": [
                           {"type": "text", "text": "Done."}]}} if normal else
                       {"type": "assistant", "timestamp": at, "isApiErrorMessage": True, "message": {
                           "stop_reason": "stop_sequence", "content": [{"type": "text", "text": "API Error: 529"}]}})
        # the next turn reads later than the report's way to the hub, which the hub counts as a clock difference (a
        # read within that time after the end looks before it: UI-API.md 1.309, "Known")
        time.sleep(0.1)

    def test_a_normal_end_before_a_cut_end_in_one_pass_keeps_what_its_turn_handled(self):
        """The Esc of a press does not take; its turn ends normally and handles a task's result; the report of that end
        does not reach the hub; a later turn reads another result and ends with an API error. The helper's next pass
        sends both ends, each in a report of its own and in their order: the press ends at the normal end with
        nothing again, so the first result stays read; the second is of a turn that no press cut, and stays read too.
        The bug: one report held only the newest end and cut end, the normal end was lost, and the press gave
        the result that its turn had handled a second time."""
        helper = self.chat_helper()
        r1 = hub.emit("leo", "chat", "[hub] T-5 (Count), which you opened from the owner's message, is completed.",
                      extra={"generation": "test-generation", "task_result": 5})
        asked = self.send("Now the photos.")
        self.assertIn("T-5 (Count)", self.file_read())
        helper.report_chat_turns()
        stop = self.press(asked["request_id"])[1]["stop"]
        helper.handle_events([e for e in self.polled() if e["kind"] == "chat_stop"])
        self.assertEqual(hub.q1("SELECT state FROM chat_stops WHERE id=?", (stop["id"],))["state"], "not_confirmed")
        self.file_end(normal=True)                  # the Esc did not take: its turn ends normally
        self.turn_fails = 1
        helper.handle_events([])                    # the report of that end does not reach the hub
        r2 = hub.emit("leo", "chat", "[hub] T-6 (Sort), which you opened from the owner's message, is completed.",
                      extra={"generation": "test-generation", "task_result": 6})
        self.file_read()                            # a later turn reads it
        self.file_end(normal=False)                 # and ends with an API error
        helper.handle_events([])
        self.assertEqual(hub.q1("SELECT state FROM chat_stops WHERE id=?", (stop["id"],))["state"], "stopped")
        self.assertEqual(self.read_at(r1, r2), [True, True])        # the press ended at the normal end, with nothing
        # the same ends, in the reports of turn_end_reports: a normal end that a cut end follows goes alone, first
        self.assertEqual(fleet.turn_end_reports([(1.0, False), (2.0, True), (3.0, True), (4.0, False), (5.0, True)]),
                         [{"ended": 3.0, "cut_end": 1.0}, {"ended": 5.0, "cut_end": 4.0}])

    def test_an_esc_that_cut_a_later_turn_gives_that_turns_reads_at_its_end(self):
        """The press's turn ends normally after the press, and a new turn starts before the Esc, which cuts it. The
        answer is not confirmed, cut, and names that turn's reads and the normal end before it. The bugs: the normal
        end ended the press at once with nothing again, or its report, which came again after the answer, ended it so,
        and the cut turn's end came for a press that was over, so the result that the cut turn read stayed read for
        good."""
        asked = self.send("Now the photos.")
        self.read()                                 # the press's turn
        stop = self.press(asked["request_id"])[1]["stop"]
        ended = hub.now()                           # that turn's normal end, after the press
        r2 = hub.emit("leo", "chat", "[hub] T-7 (Sort), which you opened from the owner's message, is completed.",
                      extra={"generation": "test-generation", "task_result": 7})
        mark = len(self.reads["leo"])
        self.read()                                 # the next turn, which the Esc cuts
        after = self.reads["leo"][mark:]
        normal = {"ended": ended}
        self.assertEqual(self.request("/helper/turn/leo", normal)[0], 200)     # its helper sends that end alone, first
        code, body = self.answer(stop["id"], confirmed=False, cut=True, reads=after, normal_end=ended,
                                 detail="its conversation file still changes after the interrupt")
        self.assertEqual((code, body["state"]), (200, "not_confirmed"), body)
        # and again after the answer: its report failed or its reply was lost, or the helper started again
        self.assertEqual(self.request("/helper/turn/leo", normal)[0], 200)
        self.assertEqual(hub.q1("SELECT state FROM chat_stops WHERE id=?", (stop["id"],))["state"], "not_confirmed")
        self.chat_turn("leo", cut=True, reads=after)
        self.assertEqual(self.read_at(r2), [False])

    def test_the_end_of_a_later_turn_gives_what_the_cut_turn_read_and_not_what_it_handled(self):
        """The press's turn ends cut after the press; the Esc then goes into the next turn, which read another result,
        and is not confirmed: the answer names the rows of both turns, and waits for that turn's end. A normal end of
        it gives only the cut turn's result again, and a cut end both. A report that names no ids gives those of the
        answer, from a helper that could not read the file and from one of an earlier build alike. The bugs: a result
        that the later turn handled comes a second time, or the result of a cut turn is lost."""
        for n in range(1, 5):
            hub.TEAM["addresses"][f"w{n}-host"] = f"127.0.0.{10 + n}"
            hub.TEAM["agents"][f"w{n}"] = dict(hub.TEAM["agents"]["leo"], machine=f"w{n}-host")
            self.features(f"w{n}")

        def result(agent, n):
            return hub.emit(agent, "chat", f"[hub] T-{n} (Sort), which you opened from the owner's message, is "
                            "completed.", extra={"generation": "test-generation", "task_result": n})

        def two_turns(agent):
            r1 = result(agent, 5)
            asked = self.send("Now the photos.", agent)
            self.read(agent)                            # the press's turn
            first = list(self.reads[agent])
            stop = self.press(asked["request_id"], agent)[1]["stop"]
            self.chat_turn(agent, cut=True, reads=first)            # it ends cut, while the press waits
            r2 = result(agent, 6)
            self.read(agent)                            # the next turn, into which the Esc goes
            code, body = self.answer(stop["id"], agent, confirmed=False, cut=True, reads=self.reads[agent],
                                     detail="its conversation file still changes after the interrupt")
            self.assertEqual((code, body["state"], self.read_at(r1, r2)), (200, "not_confirmed", [True, True]), body)
            return r1, r2
        r1, r2 = two_turns("w1")
        self.chat_turn("w1")                            # the later turn ends normally
        self.assertEqual(self.read_at(r1, r2), [False, True])
        r1, r2 = two_turns("w2")
        self.chat_turn("w2", cut=True, reads=self.reads["w2"])      # it ends cut
        self.assertEqual(self.read_at(r1, r2), [False, False])
        # a file that the helper could not read; a helper of an earlier build, with a normal end in the same report
        for agent, names, later in (("w3", {"cut_reads": []}, 0), ("w4", {}, 0.01)):
            r1 = result(agent, 5)
            asked = self.send("Now the photos.", agent)
            self.read(agent)
            stop = self.press(asked["request_id"], agent)[1]["stop"]
            self.answer(stop["id"], agent, confirmed=False, cut=True, reads=self.reads[agent],
                        detail="the session still shows a running turn after three interrupts")
            cut = hub.now()
            time.sleep(later)
            t = hub.now()
            report = dict(names, cut_end=cut, ended=t if later else cut, now=t)
            self.assertEqual(self.request(f"/helper/turn/{agent}", report)[0], 200)
            self.assertEqual(self.read_at(r1), [False], agent)

    def test_a_confirmed_press_that_cut_ends_the_older_press_that_did_not_take(self):
        """An older press did not take; the owner writes again and presses Stop for the newer message, and that Esc is
        confirmed and gives the cut turn's reads. The older press ends with it. Not so when the older press's turn read
        on after its answer (another result), ended cut (an error, or its Esc took late) and a normal turn followed,
        both reports late, so that the newer answer names that normal end and only the reads after it: the older press
        waits, and the late report of its cut end ends it with both results. And when the newer answer names no reads
        (its helper could not read the file), the older press's result comes with it all the same. And when the older
        press's Esc went into a turn that began after its turn's normal end (it read a result after that end), the
        newer answer that cut that turn ends it too, with reports on time. The bugs: the turn report that came later
        ended the older press by that cut end too, and its reads came a second time; the result that the older press's
        turn read after its answer was lost; with no reads in the answer, the older press's result was lost; the older
        press waited, and the cut end of the turn that the newer answer cut gave its result a second time."""
        r1 = hub.emit("leo", "chat", "[hub] T-8 (Count), which you opened from the owner's message, is completed.",
                      extra={"generation": "test-generation", "task_result": 8})
        first = self.send("Sort the photos.")
        self.read()
        old = self.press(first["request_id"])[1]["stop"]
        self.answer(old["id"], confirmed=False, cut=True, reads=list(self.reads["leo"]),
                    detail="the session still shows a running turn after three interrupts")
        fixed = self.send("No, only those of November.")
        self.read()
        new = self.press(fixed["request_id"])[1]["stop"]
        self.assertEqual(self.answer(new["id"], reads=list(self.reads["leo"]))[1]["unread"], [r1])
        self.assertEqual(hub.q1("SELECT state, detail FROM chat_stops WHERE id=?", (old["id"],))["state"], "stopped")
        self.read()                                 # the next turn reads the result again
        self.chat_turn("leo", cut=True, reads=list(self.reads["leo"]))        # the cut end's report, late
        self.assertEqual(self.read_at(r1), [True])
        self.workers(1)
        r1 = self.result(5, "w1")
        first = self.send("Sort the photos.", "w1")
        self.read("w1")
        old = self.press(first["request_id"], "w1")[1]["stop"]
        self.answer(old["id"], "w1", confirmed=False, cut=True, reads=list(self.reads["w1"]),
                    detail="the session still shows a running turn after three interrupts")
        q = self.result(6, "w1")
        self.read("w1")                             # its turn reads on after that answer: another result
        named = list(self.reads["w1"])              # what the cut end's report names: the reads since the normal end
        cut = hub.now()                             # that turn ends cut; the report does not go
        time.sleep(0.05)
        ended = hub.now()                           # the next turn ends normally; the report does not go
        time.sleep(0.05)
        fixed = self.send("No, only those of November.", "w1")
        mark = len(self.reads["w1"])
        self.read("w1")
        new = self.press(fixed["request_id"], "w1")[1]["stop"]
        self.assertEqual(self.answer(new["id"], "w1", reads=self.reads["w1"][mark:], normal_end=ended,
                                     normal_cut=cut)[0], 200)
        self.assertEqual(self.state_of(old), "not_confirmed")          # its own turn ended: that report ends it
        for report in ({"ended": cut, "cut_end": cut, "cut_reads": named}, {"ended": ended}):
            self.assertEqual(self.request("/helper/turn/w1", report)[0], 200)
        self.assertEqual((self.state_of(old), self.read_at(r1, q)), ("stopped", [False, False]))
        self.workers(2)
        r1 = self.result(5, "w2")
        first = self.send("Sort the photos.", "w2")
        self.read("w2")
        old = self.press(first["request_id"], "w2")[1]["stop"]
        self.answer(old["id"], "w2", confirmed=False, cut=True, reads=list(self.reads["w2"]),
                    detail="the session still shows a running turn after three interrupts")
        fixed = self.send("No, only those of November.", "w2")
        self.read("w2")
        new = self.press(fixed["request_id"], "w2")[1]["stop"]
        self.assertEqual(self.answer(new["id"], "w2", reads=[])[0], 200)      # its helper could not read the file
        self.assertEqual((self.state_of(old), self.read_at(r1)), ("stopped", [False]))
        self.workers(3)
        first = self.send("Sort the photos.", "w3")
        self.read("w3")                             # turn A
        old = self.press(first["request_id"], "w3")[1]["stop"]
        ended = hub.now()                           # turn A ends normally, before the Esc
        self.assertEqual(self.request("/helper/turn/w3", {"ended": ended})[0], 200)
        y = self.result(6, "w3")
        mark = len(self.reads["w3"])
        self.read("w3")                             # turn B: a result and the stop line
        self.answer(old["id"], "w3", confirmed=False, cut=True, reads=self.reads["w3"][mark:], normal_end=ended,
                    detail="the session still shows a running turn")             # the Esc went into turn B
        fixed = self.send("No, only those of November.", "w3")
        self.read("w3")
        new = self.press(fixed["request_id"], "w3")[1]["stop"]
        self.assertEqual(self.answer(new["id"], "w3", reads=self.reads["w3"][mark:], normal_end=ended,
                                     normal_cut=0.0)[0], 200)                 # its Esc cuts turn B
        self.assertEqual((self.state_of(old), self.read_at(y)), ("stopped", [False]))
        cut, b_reads = hub.now(), self.reads["w3"][mark:]                       # turn B's cut end
        time.sleep(0.05)
        self.read("w3")                             # turn C reads the result again, before that report comes
        self.assertEqual(self.request("/helper/turn/w3", {"ended": cut, "cut_end": cut, "cut_reads": b_reads})[0], 200)
        self.chat_turn("w3")                        # turn C ends normally
        self.assertEqual(self.read_at(y), [True])

    def test_a_correction_that_the_cut_turn_read_shows_its_turn_again(self):
        """A worker's cut turn read the owner's correction (it came after the poll gave the event). At the end of the
        press it is unread again, as for the manager, so that its next turn reads it and the apps say that the agent
        works on it, with Stop for it. The bug: the cut end ended its turn too, and the apps showed no "Thinking" and
        no Stop while the next turn worked on it."""
        asked = self.send("Now the photos.")
        self.read()
        stop = self.press(asked["request_id"])[1]["stop"]
        self.polled()
        fixed = self.send("No, only one.")
        self.read()                                 # the running turn reads it before the Esc lands
        self.answer(stop["id"], reads=list(self.reads["leo"]))
        self.chat_turn("leo", cut=True, reads=list(self.reads["leo"]))
        self.assertEqual(self.read_at(fixed["event_id"]), [False])
        self.assertIn("No, only one.", self.read())                 # its next turn
        self.assertEqual(self.stop_keys().get("leo"), fixed["request_id"])

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

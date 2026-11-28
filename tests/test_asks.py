"""What the owner asked for (owner feature asks; the owner, 15 November 2026: "I am not interested in the specific
individual tasks to be done but in the thing I asked for to be done", and "if I ask something new, it gets registered
too"). A task names the owner's own message that it comes from (tasks.ask), that message gets the few words that the
owner's apps show for it (ui_requests.asked), a follow-up and a subtask take the ask of their task, and a Needs-you
item names the ask whose work waits for it (needs.ask). In-process, against the hub of test_ui_api."""
import hashlib
import json
import unittest
import uuid

import hub
from test_ui_api import OwnerAPI

OWNER = "127.0.0.1"
CHAT = ("test-generation", "owner-chat", "1")
TEAM = {"addresses": {"owner": OWNER, "hub": "127.0.0.2"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   # a lead with one worker, and a worker of the manager
                   "lead": {"role": "lead", "runtime": "claude", "machine": "m-lead", "can": ["shell"]},
                   "w": {"role": "worker", "runtime": "claude", "machine": "m-w", "can": ["shell"],
                         "reports_to": "lead"},
                   "solo": {"role": "worker", "runtime": "claude", "machine": "m-solo", "can": ["shell"]}}}


class Asks(OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))

    # ---- helpers
    def context(self, tid):
        attempt = hub.q1("SELECT attempt FROM tasks WHERE id=?", (tid,))["attempt"]
        return ("test-generation", hub.tref(tid), str(attempt))

    def call(self, agent, name, args, task=None, context=None):
        return hub.call_tool(agent, name, args, context or (self.context(task) if task else None))

    def ok(self, *args, **kwargs):
        text, error = self.call(*args, **kwargs)
        self.assertFalse(error, text)
        return text

    def refused(self, *args, **kwargs):
        text, error = self.call(*args, **kwargs)
        self.assertTrue(error, text)
        return text

    def says(self, recipient="manager", text="Move the shop's images to the new server.", read=True, **more):
        """One message of the owner's to this agent, as its ui_requests row; the agent has read it unless read=False."""
        body = self.command(recipient=recipient, text=text, **more)
        code, receipt = self.request("/ui/messages", body)
        self.assertEqual(code, 200, receipt)
        if read:
            self.ok(recipient, "read_messages", {}, context=None if recipient == "manager" else CHAT)
        return hub.q1("SELECT * FROM ui_requests WHERE request_id=?", (body["request_id"],))

    def create(self, agent="manager", owner="solo", task=None, **more):
        said = self.ok(agent, "create_task", dict({"owner": owner, "title": f"Work for {owner}", "done_when": "Done.",
                                                   "why": "It suits it."}, **more), task)
        return hub.q1("SELECT * FROM tasks ORDER BY id DESC LIMIT 1"), said

    def asked(self, message):
        return hub.q1("SELECT asked FROM ui_requests WHERE request_id=?", (message["request_id"],))["asked"]

    # ---- the manager names the message
    def test_the_manager_s_task_names_the_owner_s_message_and_its_first_task_names_the_ask(self):
        message = self.says()
        ref = f"M-{message['event_id']}"
        # the first task of a message gives the ask its name, and the hub says how
        said = self.refused("manager", "create_task", {"owner": "solo", "title": "Copy the images", "done_when": "Done.",
                                                       "ask": ref})
        self.assertIn(f"first task of the owner's message {ref}", said)
        self.assertIn("asked", said)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tasks")["n"], 0)
        task, said = self.create(ask=ref, asked="  Move the shop's images\n to the new server ")
        self.assertEqual(task["ask"], message["request_id"])
        self.assertEqual(self.asked(message), "Move the shop's images to the new server")       # one line, as given
        self.assertIn(f"part of what the owner asked for in {ref}", said)
        self.assertIn("\"Move the shop's images to the new server\"", said)
        # a second task of the same message needs no name, and another name does not take the place of the first
        second, _ = self.create(ask=ref)
        third, _ = self.create(ask=message["request_id"], asked="Another name")            # its request UUID names it too
        self.assertEqual((second["ask"], third["ask"]), (message["request_id"],) * 2)
        self.assertEqual(self.asked(message), "Move the shop's images to the new server")
        # work that no message of the owner's began has no ask
        plain, said = self.create()
        self.assertIsNone(plain["ask"])
        self.assertNotIn("asked for", said)

    def test_the_name_of_an_ask_is_one_short_line_with_no_code(self):
        message = self.says()
        ref = f"M-{message['event_id']}"
        for name, why in (("x" * (hub.ASKED_CHARS + 1), f"at most {hub.ASKED_CHARS} characters"),
                          ("Finish T-12 for the shop", "Say T-12 in plain words"),
                          ("Ask in Q-3 again", "Say Q-3 in plain words")):
            self.assertIn(why, self.refused("manager", "create_task", {
                "owner": "solo", "title": "Copy the images", "done_when": "Done.", "ask": ref, "asked": name}))
        # a name with no message to name is no name
        self.assertIn("give ask too", self.refused("manager", "create_task", {
            "owner": "solo", "title": "Copy the images", "done_when": "Done.", "asked": "Move the images"}))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tasks")["n"], 0)
        self.assertIsNone(self.asked(message))
        self.create(ask=ref, asked="x" * hub.ASKED_CHARS)                    # the longest name that the hub takes
        self.assertEqual(self.asked(message), "x" * hub.ASKED_CHARS)

    def test_only_the_owner_s_own_read_message_to_this_agent_is_an_ask(self):
        mine, unread = self.says(), self.says(text="And the logos.", read=False)
        other = self.says("solo", text="Check the disk.")
        task, _ = self.create(ask=f"M-{mine['event_id']}", asked="Move the images")
        fields = {"owner": "solo", "title": "Copy the logos", "done_when": "Done.", "asked": "The logos"}
        for ref in (f"M-{unread['event_id']}",                 # the manager has not read it
                    f"M-{other['event_id']}", other["request_id"],        # the owner wrote it to another agent
                    "M-999999", "the message about logos", "AM-1", hub.tref(task["id"])):
            said = self.refused("manager", "create_task", dict(fields, ask=ref))
            self.assertTrue("ask names a message of the owner's own to you" in said or
                            "ask is the owner's message that this work comes from" in said, said)
        # the owner's answer to a Needs-you item is no message that work is filed under
        self.ok("manager", "raise_needs_you", {"title": "Which colour?", "why": "Only he chose the brand",
                                               "what_to_do": "Say blue or green", "reason": "person"})
        need = hub.q1("SELECT id FROM needs ORDER BY id DESC LIMIT 1")["id"]
        answer = self.command(answer="Blue")
        self.assertEqual(self.request(f"/ui/needs/{need}", answer)[0], 200)
        self.ok("manager", "read_messages", {})
        answered = hub.q1("SELECT * FROM ui_requests WHERE request_id=?", (answer["request_id"],))
        self.assertEqual(answered["kind"], "answer")
        for ref in (f"M-{answered['event_id']}", f"N-{need}"):
            self.assertIn(f"N-{need} names no message of the owner's that work is filed under",
                          self.refused("manager", "create_task", dict(fields, ask=ref)))
        self.assertIn("There is no Needs-you item N-999", self.refused("manager", "create_task", dict(fields, ask="N-999")))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tasks")["n"], 1)

    # ---- what takes the ask by itself
    def test_a_follow_up_and_a_subtask_take_the_ask_of_their_task(self):
        message = self.says()
        first, _ = self.create(owner="lead", ask=f"M-{message['event_id']}", asked="Move the images")
        # the lead's subtask, in the session of its own task, names nothing
        sub, said = self.create("lead", "w", task=first["id"])
        self.assertEqual((sub["parent"], sub["ask"]), (first["id"], message["request_id"]))
        self.assertIn("part of what the owner asked for", said)
        # a task that follows one of them names nothing either, also a follow-up of a follow-up
        follow, _ = self.create(follows=hub.tref(sub["id"]))
        again, _ = self.create(follows=hub.tref(follow["id"]))
        self.assertEqual((follow["ask"], again["ask"]), (message["request_id"],) * 2)
        # a task that follows work with no ask has none, and a named message wins over the task that it follows
        plain, _ = self.create()
        self.assertIsNone(self.create(follows=hub.tref(plain["id"]))[0]["ask"])
        other = self.says(text="And write the invoice.")
        moved, _ = self.create(follows=hub.tref(sub["id"]), ask=f"M-{other['event_id']}", asked="Write the invoice")
        self.assertEqual(moved["ask"], other["request_id"])

    def test_start_task_files_the_work_under_its_message(self):
        message = self.says("solo", text="Please write a short note about the logs.")
        fields = {"title": "Write the log note", "done_when": "outputs has the note",
                  "in_reply_to": message["request_id"]}
        self.ok("solo", "start_task", fields, context=CHAT)
        task = hub.q1("SELECT * FROM tasks ORDER BY id DESC LIMIT 1")
        self.assertEqual(task["ask"], message["request_id"])
        self.assertEqual(self.asked(message), "Write the log note")           # with no name, the title is the name
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tasks")["n"], 1)
        self.ok("solo", "start_task", fields, context=CHAT)                   # the same call is the same task
        self.ok("solo", "start_task", dict(fields, asked="The log note"), context=CHAT)     # also with a name now
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tasks")["n"], 1)
        self.assertEqual(self.asked(message), "Write the log note")
        # the agent's own name for it, checked as the manager's is
        named = self.says("solo", text="And tidy the old reports.")
        fields = {"title": "Sort the reports of 2025 into one folder for each month and delete the empty ones",
                  "done_when": "Done.", "in_reply_to": named["request_id"]}
        self.assertIn("Say T-4 in plain words",
                      self.refused("solo", "start_task", dict(fields, asked="Tidy the reports of T-4"), context=CHAT))
        self.ok("solo", "start_task", dict(fields, asked="Tidy the old reports"), context=CHAT)
        self.assertEqual(self.asked(named), "Tidy the old reports")
        # a long title is cut to a line, and refused for nothing
        long = self.says("solo", text="And one more.")
        self.ok("solo", "start_task", dict(fields, in_reply_to=long["request_id"]), context=CHAT)
        self.assertLessEqual(len(self.asked(long)), hub.ASKED_CHARS)
        self.assertTrue(self.asked(long).startswith("Sort the reports of 2025") and self.asked(long).endswith("..."))
        # a code in a title is not in the name that the owner reads
        self.assertEqual(hub.ask_name_of("Fix T-61: the follow-up of Q-3"), "Fix the follow-up of")
        for title, name in (("T-61", "Work"), ("-T-12 fix the shop", "fix the shop"), ("T-12-T-13 x", "x"),
                            ("Fix\x1bthe\tshop", "Fix the shop"), ("...", "Work"),
                            ("https://shop.example/" + "a" * 80, "Work")):
            self.assertEqual(hub.ask_name_of(title), name, title)
            self.assertIsNone(hub.asked_words(hub.ask_name_of(title)), title)
        coded = self.says("solo", text="And the last one.")
        self.ok("solo", "start_task", {"title": "Check T-4 again", "done_when": "Done.",
                                       "in_reply_to": coded["request_id"]}, context=CHAT)
        self.assertEqual(self.asked(coded), "Check again")

    def test_work_under_a_lead_keeps_its_ask_and_the_lead_s_batch_has_none(self):
        message = self.says("w", text="Please check the disk of your server.")
        self.ok("w", "start_task", {"title": "Check the disk", "done_when": "Done.",
                                    "in_reply_to": message["request_id"]}, context=CHAT)
        task = hub.q1("SELECT * FROM tasks WHERE owner='w'")
        batch = hub.q1("SELECT * FROM tasks WHERE id=?", (task["parent"],))
        self.assertEqual((task["ask"], batch["owner"], batch["ask"]), (message["request_id"], "lead", None))
        # what the lead gives out in that batch session is no part of the worker's ask
        sub, _ = self.create("lead", "w", task=batch["id"])
        self.assertEqual((sub["parent"], sub["ask"]), (batch["id"], None))
        # unless it follows the worker's task, which is how a fix of that work is given
        fix, _ = self.create("lead", "w", task=batch["id"], follows=hub.tref(task["id"]))
        self.assertEqual(fix["ask"], message["request_id"])

    def test_a_message_and_its_corrections_are_one_ask(self):
        message = self.says()
        self.create(ask=f"M-{message['event_id']}", asked="Move the images")
        correction = self.says(text="Move them to the server in Madrid.", replaces_request_id=message["request_id"])
        self.assertEqual(correction["replaces_request_id"], message["request_id"])
        task, said = self.create(ask=f"M-{correction['event_id']}")           # no name: the ask has its name
        self.assertEqual(task["ask"], message["request_id"])
        self.assertIn(f"M-{message['event_id']}", said)
        self.assertIsNone(self.asked(correction))
        # a correction of that correction is the same ask too
        second = self.says(text="No: to the one in Lisbon.", replaces_request_id=correction["request_id"])
        self.assertEqual(self.create(ask=f"M-{second['event_id']}")[0]["ask"], message["request_id"])
        # the first task names the correction of a message that no task named: the ask is the first message, and a
        # later task that names that first message is the same ask, with the name that it has
        loose = self.says(text="Write the invoice.")
        fixed = self.says(text="Write the invoice for May.", replaces_request_id=loose["request_id"])
        task, _ = self.create(ask=f"M-{fixed['event_id']}", asked="Write the invoice for May")
        again, _ = self.create(ask=f"M-{loose['event_id']}")
        self.assertEqual((task["ask"], again["ask"]), (loose["request_id"],) * 2)
        self.assertEqual((self.asked(loose), self.asked(fixed)), ("Write the invoice for May", None))
        # and a worker's start_task on a correction files its task under the first message
        note = self.says("solo", text="Write a note about the logs.")
        self.ok("solo", "start_task", {"title": "Write the log note", "done_when": "Done.",
                                       "in_reply_to": note["request_id"]}, context=CHAT)
        better = self.says("solo", text="Write it about the logs of May.", replaces_request_id=note["request_id"])
        self.ok("solo", "start_task", {"title": "Write the log note of May", "done_when": "Done.",
                                       "in_reply_to": better["request_id"]}, context=CHAT)
        asks = [t["ask"] for t in hub.q("SELECT ask FROM tasks WHERE owner='solo' ORDER BY id")][-2:]
        self.assertEqual(asks, [note["request_id"]] * 2)
        self.assertEqual(self.asked(note), "Write the log note")

    # ---- what the first review asked for
    def test_work_after_the_owner_s_answer_to_an_item_goes_on_under_the_same_ask(self):
        message = self.says()
        task, _ = self.create(ask=f"M-{message['event_id']}", asked="Move the images")
        self.ok("manager", "raise_needs_you", {"title": "Which colour?", "why": "Only he chose the brand",
                                               "what_to_do": "Say blue or green", "reason": "person", "ask": hub.tref(task["id"])})
        need = hub.q1("SELECT id FROM needs ORDER BY id DESC LIMIT 1")["id"]
        answer = self.command(answer="Blue")
        self.assertEqual(self.request(f"/ui/needs/{need}", answer)[0], 200)
        self.ok("manager", "read_messages", {})
        answered = hub.q1("SELECT * FROM ui_requests WHERE request_id=?", (answer["request_id"],))
        # the answer's own M-<n>, and the item, both name the ask of the item, and need no name
        after, said = self.create(ask=f"M-{answered['event_id']}")
        by_item, _ = self.create(ask=f"N-{need}")
        self.assertEqual((after["ask"], by_item["ask"]), (message["request_id"],) * 2)
        self.assertIn(f"M-{message['event_id']}", said)
        self.assertIsNone(self.asked(answered))
        # the answer of another agent's item is not this agent's to name
        hub.q("UPDATE ui_requests SET recipient='solo' WHERE request_id=?", (answer["request_id"],))
        self.refused("manager", "create_task", {"owner": "solo", "title": "Paint it", "done_when": "Done.",
                                                "ask": f"M-{answered['event_id']}"})

    def test_a_later_task_of_a_goal_takes_the_ask_of_the_goal_s_first_task(self):
        message = self.says()
        self.ok("manager", "update_goal", {"request_id": str(uuid.uuid4()), "title": "Move the shop",
                                           "text": "The shop runs on the new server before May."})
        loose, _ = self.create(goal="G-1")                         # before any task of the goal names a message
        self.assertIsNone(loose["ask"])
        first, _ = self.create(goal="G-1", ask=f"M-{message['event_id']}", asked="Move the shop")
        later, said = self.create(goal="G-1")                      # days later, with the goal alone
        self.assertEqual((first["ask"], later["ask"]), (message["request_id"],) * 2)
        self.assertIn("part of what the owner asked for", said)
        self.assertIsNone(self.create()[0]["ask"])                 # a task of no goal takes none
        # the run of a wake-up rule with that goal is no part of the ask: it would never end
        run = hub.check_task("manager", {"owner": "solo", "title": "Daily check", "done_when": "Checked.", "goal": "G-1"})
        self.assertIsNone(run["ask"])
        # and neither is a lead's subtask of such a run: it has the goal of its task, and that task has no ask
        hub.q("UPDATE tasks SET goal_id=1, owner='lead' WHERE id=?", (loose["id"],))
        sub, _ = self.create("lead", "w", task=loose["id"])
        self.assertEqual((sub["goal_id"], sub["parent"], sub["ask"]), (1, loose["id"], None))

    def test_the_manager_is_told_where_it_reads_and_when_it_misses(self):
        # the sentence comes with the owner's own words, where the manager reads them
        body = self.command(text="Move the shop's images to the new server.")
        self.request("/ui/messages", body)
        read = self.ok("manager", "read_messages", {})
        self.assertIn("give create_task ask=M-<n> of that message", read)
        message = hub.q1("SELECT * FROM ui_requests WHERE request_id=?", (body["request_id"],))
        ref = f"M-{message['event_id']}"
        # a task that names no message, after a message that no work is filed under: one sentence, and no refusal
        missed, said = self.create()
        self.assertIsNone(missed["ask"])
        self.assertIn(f"names no message of the owner's. If it is work that they asked for in {ref}", said)
        self.assertIn("Move the shop's images to the new server.", said)
        # the next task files the work, and then nothing is said: no message is left without work
        named, said = self.create(ask=ref, asked="Move the shop's images")
        self.assertNotIn("names no message", said)
        self.assertNotIn("names no message", self.create()[1])
        # each message is named one time, whatever tasks the hub made with the manager as their requester between
        logos = self.says(text="And the logos.")
        self.says("solo", text="Please check the disk.")
        self.ok("solo", "start_task", {"title": "Check the disk", "done_when": "Done.",
                                       "in_reply_to": hub.q1("SELECT request_id FROM ui_requests ORDER BY rowid DESC LIMIT 1")["request_id"]},
                context=CHAT)
        self.assertIn(f"asked for in M-{logos['event_id']}", self.create()[1])
        self.assertNotIn("names no message", self.create()[1])
        # a follow-up, and a lead's subtask, are told nothing
        self.says(text="And the fonts.")
        self.assertNotIn("names no message", self.create(follows=hub.tref(missed["id"]))[1])
        lead_task, _ = self.create(owner="lead", ask=ref)
        self.assertNotIn("names no message", self.create("lead", "w", task=lead_task["id"])[1])

    # ---- a Needs-you item of that work
    def test_a_needs_you_item_names_the_ask_whose_work_waits_for_it(self):
        message = self.says()
        ref = f"M-{message['event_id']}"
        task, _ = self.create(ask=ref, asked="Move the images")
        plain, _ = self.create()
        # each item after the first is of the same ask, the owner's job, so it says that it is another need (P7 4.2)
        item = {"title": "Which colour?", "why": "Only he chose the brand", "what_to_do": "Say blue or green",
                "reason": "person", "also": "Another choice of that work."}

        def raised(**more):
            self.ok("manager", "raise_needs_you", dict(item, **more))
            return hub.q1("SELECT * FROM needs ORDER BY id DESC LIMIT 1")

        self.assertEqual(raised(ask=hub.tref(task["id"]))["ask"], message["request_id"])     # a task of that work
        self.assertEqual(raised(ask=ref)["ask"], message["request_id"])                      # or the message itself
        self.assertIsNone(raised(ask=hub.tref(plain["id"]))["ask"])          # work that the owner did not ask for
        self.assertIsNone(raised()["ask"])
        self.assertIn("There is no task T-999", self.refused("manager", "raise_needs_you", dict(item, ask="T-999")))
        unnamed = self.says(text="And the logos.")                  # no work is filed under it
        self.assertIn(f"No work is filed under M-{unnamed['event_id']} yet",
                      self.refused("manager", "raise_needs_you", dict(item, ask=f"M-{unnamed['event_id']}")))
        # the item that takes the place of another keeps its ask
        old = raised(ask=ref)
        new = raised(replaces=f"N-{old['id']}")
        self.assertEqual((new["ask"], hub.q1("SELECT answer FROM needs WHERE id=?", (old["id"],))["answer"] is None),
                         (message["request_id"], False))
        # the item that carries a task's question to the owner has that task's ask
        self.ok("solo", "ask_my_requester", {"question": "Blue or green?"}, task["id"])
        question = hub.q1("SELECT id FROM questions ORDER BY id DESC LIMIT 1")["id"]
        self.assertEqual(raised(question_id=f"Q-{question}")["ask"], message["request_id"])

    # ---- what the apps read
    def test_the_state_gives_the_apps_the_three_links(self):
        message = self.says()
        task, _ = self.create(ask=f"M-{message['event_id']}", asked="Move the images")
        self.ok("manager", "raise_needs_you", {"title": "Which colour?", "why": "Only he chose the brand",
                                               "what_to_do": "Say blue or green", "reason": "person", "ask": hub.tref(task["id"])})
        code, state = self.request()
        self.assertEqual(code, 200)
        self.assertIn("asks", state["ui_features"])
        self.assertEqual([t["ask"] for t in state["tasks"]], [message["request_id"]])
        self.assertEqual([(m["request_id"], m["asked"]) for m in state["messages"]],
                         [(message["request_id"], "Move the images")])
        self.assertEqual([n["ask"] for n in state["needs"]], [message["request_id"]])

    def test_the_tools_say_how_to_name_the_message(self):
        tools = {t["name"]: t for t in hub.tools_for("manager")}
        self.assertIn("set ask to that message (M-<n>)", tools["create_task"]["description"])
        self.assertLessEqual({"ask", "asked"}, set(tools["create_task"]["inputSchema"]["properties"]))
        self.assertIn("ask", tools["raise_needs_you"]["inputSchema"]["properties"])
        self.assertLessEqual({"ask", "asked"}, set(tools["tell_owner"]["inputSchema"]["properties"]))
        chat = {t["name"]: t for t in hub.tools_for("solo", CHAT)}
        self.assertLessEqual({"ask", "asked"}, set(chat["start_task"]["inputSchema"]["properties"]))
        self.assertNotIn("asked", chat["start_task"]["inputSchema"].get("required", []))


class Jobs(Asks):
    """A job (owner feature jobs; the owner, 18 November 2026, of the Tasks page: "a higher level ... do not confuse
    this with DUTIES", and "Job" for its name): the tasks that their links make one piece of work, which the owner's
    apps show as one card with its tasks inside. The owner reads the title of each task and the plain words of each
    result on that card."""

    def test_a_further_part_of_work_names_its_job_and_takes_its_ask(self):
        """Without the link, three tasks of one update are three cards. Without the ask, a further part of what the
        owner asked for stands on a card of its own beside the card of its ask."""
        first, _ = self.create(title="Find what uses the old version", job_name=" Install the\n security update ")
        self.assertEqual((first["job"], first["job_name"]), (None, "Install the security update"))
        second, said = self.create(owner="lead", title="Update the servers", job=hub.tref(first["id"]),
                                   job_name="Another name")
        self.assertEqual((second["job"], second["job_name"]), (first["id"], None))
        self.assertIn(f"part of the same job as {hub.tref(first['id'])}: the owner reads them as one card", said)
        self.assertNotIn("Find what uses", said)        # a task of another team can be named: its title stays there
        self.assertIn("job_name was not used", said)
        message = self.says()
        asked, _ = self.create(ask=f"M-{message['event_id']}", asked="Move the shop")
        part, said = self.create(job=hub.tref(asked["id"]))
        self.assertEqual((part["job"], part["ask"]), (asked["id"], message["request_id"]))
        self.assertIn("part of what the owner asked for", said)
        # a job that is not there takes no task
        count = hub.q1("SELECT COUNT(*) n FROM tasks")["n"]
        self.assertIn("There is no task T-999", self.refused("manager", "create_task", {
            "owner": "solo", "title": "Update the apps", "done_when": "Done.", "job": "T-999"}))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tasks")["n"], count)
        # a fix of a finished task has follows, which is its job already: it begins none, so it names none. A name
        # that the hub leaves out is not read on a card, so it is not refused for its words either
        fix, said = self.create(follows=hub.tref(first["id"]), job_name="The fix of T-1 " + "x" * hub.TITLE_CHARS)
        self.assertEqual((fix["job"], fix["job_name"]), (None, None))
        self.assertIn("job_name was not used", said)
        self.assertNotIn("same job as", said)

    def test_a_task_is_in_one_job(self):
        """The apps put a task on the card of its ask first, so a task with a job and an ask of its own, or a case of
        its own, would stand on another card than the job that the hub's answer names."""
        first, _ = self.create(title="Find what uses the old version")
        message = self.says()
        ref = f"M-{message['event_id']}"
        asked, _ = self.create(ask=ref, asked="Move the shop")
        count = hub.q1("SELECT COUNT(*) n FROM tasks")["n"]
        fields = {"owner": "solo", "title": "Update the apps", "done_when": "Done."}
        said = self.refused("manager", "create_task", dict(fields, job=hub.tref(first["id"]), ask=ref))
        self.assertIn("A task is in one job. With job, leave out ask", said)
        self.assertIn("With job, leave out ask", self.refused("manager", "create_task", dict(
            fields, job=hub.tref(asked["id"]), ask=f"M-{self.says(text='Another thing.')['event_id']}",
            asked="Another thing")))
        self.assertIn("With job, leave out case_id", self.refused("manager", "create_task", dict(
            fields, job=hub.tref(first["id"]), case_id="R-1/C-1")))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tasks")["n"], count)
        # the ask of the job's own task is no second job: the manager may name both, and hears nothing about a message
        same, said = self.create(job=hub.tref(asked["id"]), ask=ref)
        self.assertEqual((same["job"], same["ask"]), (asked["id"], message["request_id"]))
        loose, said = self.create(job=hub.tref(first["id"]))
        self.assertNotIn("names no message of the owner's", said)
        # with a job and a task that it follows, the job's ask is its ask: the card of its job is its card
        second = self.says(text="And check the disk.")
        other, _ = self.create(ask=f"M-{second['event_id']}", asked="Check the disk")
        part, _ = self.create(job=hub.tref(asked["id"]), follows=hub.tref(other["id"]))
        self.assertEqual((part["job"], part["ask"]), (asked["id"], message["request_id"]))

    def test_a_lead_s_subtask_is_in_the_job_of_its_task_but_not_of_its_team_s_results(self):
        """The hub files the wake-ups, the reviews and the chat work of a whole team under the lead's one task for its
        team's results: as one job they would be one card of work that has nothing in common."""
        own, _ = self.create(owner="lead", title="Move the shop's images")
        sub, said = self.create("lead", "w", task=own["id"], title="Copy the images")
        self.assertEqual((sub["parent"], sub["job"]), (own["id"], own["id"]))
        self.assertNotIn("same job as", said)                   # the lead named no job: it is its own task's
        fix, _ = self.create("lead", "w", task=own["id"], follows=hub.tref(sub["id"]))
        self.assertEqual((fix["parent"], fix["job"]), (own["id"], None))      # a fix is in the job that it follows
        with hub.transaction():
            results = hub.lead_batch_rows("lead", hub.now())
        loose, _ = self.create("lead", "w", task=results, title="Check the disk")
        self.assertEqual((loose["parent"], loose["job"]), (results, None))
        hub.kv_set("lead_batch:lead", "0")         # a newer one took its place (a move of the line): still no job
        stale, _ = self.create("lead", "w", task=results, title="Check the logs")
        self.assertEqual((stale["parent"], stale["job"]), (results, None))
        # a subtask with an ask of its own is in that ask's job: the hub writes no second link beside it
        message = self.says("lead", text="Move the logos too.")
        hub.q("UPDATE tasks SET state='working' WHERE id=?", (own["id"],))
        logos, _ = self.create("lead", "w", task=own["id"], ask=f"M-{message['event_id']}", asked="Move the logos")
        self.assertEqual((logos["parent"], logos["job"], logos["ask"]), (own["id"], None, message["request_id"]))

    def test_the_parts_of_one_step_of_a_plan_are_one_job(self):
        self.ok("manager", "update_goal", {"request_id": str(uuid.uuid4()), "title": "Move the shop",
                                           "text": "The shop runs on the new server before May."})
        self.ok("manager", "update_goal", {"request_id": str(uuid.uuid4()), "goal": "G-1",
                                           "step": "Copy the images and the orders"})
        message = self.says()
        wrong, _ = self.create(goal="G-1", step=1, title="Copy the logos")
        self.ok("manager", "cancel_task", {"task_id": hub.tref(wrong["id"]), "reason": "It went to the wrong agent."})
        images, _ = self.create(goal="G-1", step=1, title="Copy the images", ask=f"M-{message['event_id']}",
                                asked="Move the shop")
        orders, said = self.create(owner="lead", goal="G-1", step=1, title="Copy the orders")
        # the first part that nobody canceled begins the job, and a later part takes its ask with its job
        self.assertEqual((images["job"], orders["job"], orders["ask"]),
                         (None, images["id"], message["request_id"]))
        self.assertNotIn("same job as", said)                   # the manager named no job: the step did
        # a task has the ask of its job, also when that is none: not the ask of another task of its goal, which would
        # put it on another card than its job's
        loose, _ = self.create(goal="G-1", title="Tell the customers", job=hub.tref(wrong["id"]))
        self.assertEqual((loose["job"], loose["ask"]), (wrong["id"], None))
        # a part with an ask of its own is in that ask's job: the hub writes no second link beside it
        other = self.says(text="And the invoices.")
        invoices, _ = self.create(goal="G-1", step=1, title="Copy the invoices", ask=f"M-{other['event_id']}",
                                  asked="Copy the invoices")
        self.assertEqual((invoices["job"], invoices["ask"]), (None, other["request_id"]))

    def test_the_owner_reads_a_title_so_it_is_short_and_has_no_code(self):
        fields = {"owner": "solo", "done_when": "Done.", "why": "It suits it."}
        for more, why in (({"title": "x" * (hub.TITLE_CHARS + 1)}, f"title is at most {hub.TITLE_CHARS} characters"),
                          ({"title": "Apply the fix and close C-974"}, "Say C-974 in plain words in title"),
                          ({"title": "Copy the images", "job_name": "y" * (hub.TITLE_CHARS + 1)},
                           f"job_name is at most {hub.TITLE_CHARS} characters"),
                          ({"title": "Copy the images", "job_name": "The work of T-12"},
                           "Say T-12 in plain words in job_name")):
            self.assertIn(why, self.refused("manager", "create_task", dict(fields, **more)))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tasks")["n"], 0)
        self.create(title="x" * hub.TITLE_CHARS, job_name="y" * hub.TITLE_CHARS)      # the longest that the hub takes
        # Each tool that asks an agent for such a title says the number that the hub refuses over: when the number
        # went from 80 to 50 (19 November 2026), two descriptions held 80 as a literal, and an agent that followed
        # them would have been refused.
        import wakeups
        words = {name: json.dumps([text, schema]) for _role, name, _fn, text, schema in hub.TOOLS}
        words["save_trigger"] = json.dumps(dict((n, (d, s)) for n, d, s in wakeups.TOOL_SPECS)["save_trigger"])
        for name in ("create_task", "open_case", "set_duty", "save_trigger"):
            self.assertIn(f"at most {hub.TITLE_CHARS} characters", words[name], name)
        # The task of a wake-up rule has the rule's own title, saved before: a refusal there would stop each run of
        # the rule. Its admission is check_task, which takes the title as it is.
        long = "R-7: the vulnerability cases that need me, with every open advisory of the week in one run"
        self.assertEqual(hub.check_task("manager", dict(fields, title=long))["title"], long)

    def test_a_result_keeps_its_plain_words_for_the_owner_s_card(self):
        def deliver(task, **more):
            return self.ok("solo", "deliver_result", dict({
                "task_id": hub.tref(task["id"]), "outcome": "completed", "what_was_done": "Copied 4,212 files.",
                "where_output_is": "The new server.", "how_checked": "Counted them."}, **more), task["id"])

        for _ in range(3):
            self.create()
        first, second, third = hub.q("SELECT * FROM tasks ORDER BY id")
        deliver(first, plain=" The shop's images are on the\n new server. ")
        deliver(second, plain="word " * 100)           # a result is never refused for its length: it is cut at a word
        deliver(third, plain="x" * 400)                # one run has no place for a cut (it could hold a login): none
        code, state = self.request()
        self.assertEqual(code, 200)
        rows = {t["id"]: t for t in state["tasks"]}
        self.assertEqual(rows[first["id"]]["plain"], "The shop's images are on the new server.")
        cut = rows[second["id"]]["plain"]
        self.assertTrue(len(cut) <= hub.PLAIN_CHARS and cut.endswith("word...") and "  " not in cut, cut)
        self.assertEqual((rows[second["id"]]["state"], rows[first["id"]]["job"], rows[first["id"]]["job_name"]),
                         ("completed", None, None))
        self.assertEqual((rows[third["id"]]["state"], rows[third["id"]]["plain"]), ("completed", None))
        self.assertIn("jobs", state["ui_features"])


class FollowUps(Asks):
    """A message that goes on with an earlier ask of the owner's is on that ask's card (the owner, 25 November 2026:
    "Sometimes I will be asking about related tasks repeatedly, so the system should catch that", "it needs to feel
    more natural", and "Yes, this" to the pictures of ~/dev/founderizer-plans/my-asks-tracking-2026-11-25/). The agent
    that reads it joins it with `ask`; a question that takes no task gets a name with `asked`; a wrong join goes back by
    the same words; a message that the owner writes on the card is on it for sure. Each test names the bug it stops: a
    follow-up that stays a card of its own, a question that never shows, a split that leaves the message or its work on
    the old card, a join to another agent's ask that nobody of it works on."""

    def row(self, message):
        return hub.q1("SELECT * FROM ui_requests WHERE request_id=?", (message["request_id"],))

    def card(self, request_id):
        """GET /ui/mobile/asks/<id> of this generation: (status, answer)."""
        return self.request(f"/ui/mobile/asks/{request_id}?db={hub.kv_get('db_id')}")

    def named(self, text, asked, recipient="manager"):
        """An ask of the owner's to the manager, named by its first task (for the solo worker), as its row."""
        message = self.says(recipient, text=text)
        self.create(ask=f"M-{message['event_id']}", asked=asked)
        return message

    def test_a_follow_up_is_on_the_earlier_card_and_its_work_rides_with_it(self):
        first = self.named("Make sure we charge nobody for the failed auto-orders.", "Charge nobody for failed orders")
        later = self.says(text="Are they refunded yet?")
        said = self.ok("manager", "tell_owner", {"text": "Leo checks it now.", "in_reply_to": f"M-{later['event_id']}",
                                                 "ask": f"M-{first['event_id']}"})
        self.assertIn(f"on the card of M-{first['event_id']} (\"Charge nobody for failed orders\")", said)
        self.assertEqual(self.row(later)["ask"], first["request_id"])
        task, _ = self.create(ask=f"M-{later['event_id']}")      # its first task needs no name: the card has one
        # and the message takes the card's, which the apps that read no follow-up yet show for its work
        self.assertEqual((task["ask"], self.asked(later)), (later["request_id"], "Charge nobody for failed orders"))
        fees = self.says(text="And the fees?")                  # a name that it gives is checked as any name is
        self.ok("manager", "tell_owner", {"text": "Checking.", "in_reply_to": f"M-{fees['event_id']}",
                                          "ask": f"M-{first['event_id']}"})
        self.assertIn("plain words", self.refused("manager", "create_task", {
            "owner": "solo", "title": "Check the fees", "done_when": "Done.", "why": "It suits it.",
            "ask": f"M-{fees['event_id']}", "asked": "The fees of T-4"}))
        code, state = self.request()
        self.assertEqual(code, 200)
        self.assertIn("ask_follow_ups", state["ui_features"])
        self.assertEqual({m["request_id"]: m["ask"] for m in state["messages"]},
                         {first["request_id"]: None, later["request_id"]: first["request_id"],
                          fees["request_id"]: first["request_id"]})
        # never onto itself, nor the first message onto its own follow-up
        lone = self.says(text="Something else.")
        self.assertIn("first message of that ask itself", self.refused(
            "manager", "tell_owner", {"text": "Yes.", "in_reply_to": f"M-{lone['event_id']}",
                                      "ask": f"M-{lone['event_id']}"}))
        self.refused("manager", "tell_owner", {"text": "Yes.", "in_reply_to": f"M-{first['event_id']}",
                                               "ask": f"M-{later['event_id']}"})
        self.assertIsNone(self.row(lone)["ask"])
        # nor onto a message with no name, which has no card: both would show on none
        then = self.says(text="And for the other shop?")
        self.assertIn("has no name", self.refused("manager", "tell_owner", {
            "text": "Yes.", "in_reply_to": f"M-{then['event_id']}", "ask": f"M-{lone['event_id']}"}))

    def test_a_question_gets_a_name_and_a_wrong_join_goes_back_with_its_work(self):
        question = self.says(text="Who looks after ads in our fleet?")
        said = self.ok("manager", "tell_owner", {"text": "The Browser Agent, each morning.",
                                                 "in_reply_to": f"M-{question['event_id']}",
                                                 "asked": "Who looks after ads"})
        self.assertIn("show their message as \"Who looks after ads\"", said)
        self.assertEqual(self.asked(question), "Who looks after ads")
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tasks")["n"], 0)
        coded = self.says(text="And the ads of T-4?")
        self.assertIn("plain words", self.refused("manager", "tell_owner", {
            "text": "Yes.", "in_reply_to": f"M-{coded['event_id']}", "asked": "The ads of T-4"}))
        self.assertIn("not both", self.refused("manager", "tell_owner", {
            "text": "Yes.", "in_reply_to": f"M-{coded['event_id']}", "asked": "Ads",
            "ask": f"M-{question['event_id']}"}))
        # the same words to a second message, with a name: that message's own answer, not a repeat of the first's
        both = [self.says(text=f"Who pays for {what}?") for what in ("hosting", "ads")]
        for one, name in zip(both, ("Who pays for hosting", "Who pays for ads")):
            self.ok("manager", "tell_owner", {"text": "The shop does.", "in_reply_to": f"M-{one['event_id']}", "asked": name})
        self.assertEqual([self.asked(m) for m in both], ["Who pays for hosting", "Who pays for ads"])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM owner_reports WHERE in_reply_to IN (?,?)",
                                tuple(m["request_id"] for m in both))["n"], 2)
        # joined by mistake, with work filed under it, then taken back by words: the work goes back with it
        later = self.says(text="Also change the shop's banner.")
        self.ok("manager", "tell_owner", {"text": "On it.", "in_reply_to": f"M-{later['event_id']}",
                                          "ask": f"M-{question['event_id']}"})
        task, _ = self.create(ask=f"M-{later['event_id']}")
        self.ok("manager", "tell_owner", {"text": "That is a thing of its own.", "in_reply_to": f"M-{later['event_id']}",
                                          "asked": "Change the shop's banner"})
        self.assertEqual((self.row(later)["ask"], self.asked(later)), (None, "Change the shop's banner"))
        card = self.card(later['request_id'])[1]        # its own card, with its work
        self.assertEqual((card["id"], [t["id"] for t in card["tasks"]]), (later["request_id"], [task["id"]]))
        # his correction goes with its message: joined onto a card by mistake, then taken back
        fixed = self.says(text="Also change the shop's logo.", replaces_request_id=later["request_id"])
        self.ok("manager", "tell_owner", {"text": "On it.", "in_reply_to": f"M-{fixed['event_id']}",
                                          "ask": f"M-{question['event_id']}"})
        self.assertEqual(hub.ask_first(fixed["request_id"]), question["request_id"])
        self.ok("manager", "tell_owner", {"text": "That is a thing of its own.", "in_reply_to": f"M-{fixed['event_id']}",
                                          "asked": "Change the shop's banner"})
        self.assertEqual(hub.ask_first(fixed["request_id"]), later["request_id"])
        self.assertIn(fixed["request_id"], [m["request_id"] for m in self.card(
            later['request_id'])[1]["messages"]])
        # a card of its own with a name keeps that name, and the answer says the name that stays
        said = self.ok("manager", "tell_owner", {"text": "Still the Browser Agent.",
                                                 "in_reply_to": f"M-{question['event_id']}", "asked": "Ads owner"})
        self.assertIn("show their message as \"Who looks after ads\"", said)
        self.assertEqual(self.asked(question), "Who looks after ads")

    def test_a_worker_s_follow_up_opens_its_task_on_the_earlier_card(self):
        first = self.says("solo", text="Check the disk of the shop's server.")
        self.ok("solo", "start_task", {"title": "Check the disk", "done_when": "Done.", "asked": "Check the shop's disk",
                                       "in_reply_to": first["request_id"]}, context=CHAT)
        later = self.says("solo", text="And clean it if it is full.")
        self.ok("solo", "start_task", {"title": "Clean the disk", "done_when": "Done.", "in_reply_to": later["request_id"],
                                       "ask": f"M-{first['event_id']}"}, context=CHAT)
        self.assertEqual(self.row(later)["ask"], first["request_id"])
        self.assertEqual(hub.q1("SELECT ask FROM tasks ORDER BY id DESC LIMIT 1")["ask"], later["request_id"])
        # the join wrote the message's reply; the worker still takes a wrong one back by words, with its task
        plain = self.says("solo", text="And empty its log folder.")     # a plain reply, then the same words with ask
        reply = {"text": "The log folder is empty.", "in_reply_to": plain["request_id"]}
        self.ok("solo", "tell_owner", reply, context=CHAT)
        said = self.ok("solo", "tell_owner", dict(reply, ask=f"M-{first['event_id']}"), context=CHAT)
        self.assertIn("already saved", said)
        self.assertIn(f"on the card of M-{first['event_id']}", said)
        self.assertEqual(self.row(plain)["ask"], first["request_id"])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM owner_reports WHERE in_reply_to=?",
                                (plain["request_id"],))["n"], 1)
        split = {"text": "That is a job of its own.", "in_reply_to": later["request_id"], "asked": "Clean the shop's disk"}
        before = hub.q1("SELECT COUNT(*) n FROM owner_reports WHERE agent='solo'")["n"]
        self.ok("solo", "tell_owner", split, context=CHAT)
        self.assertEqual((self.row(later)["ask"], self.asked(later)), (None, "Clean the shop's disk"))
        reports = hub.q1("SELECT COUNT(*) n FROM owner_reports WHERE agent='solo'")["n"]
        self.assertEqual(reports, before + 1)       # other words on an answered message go out: no repeat of its reply
        self.assertIn("already saved", self.ok("solo", "tell_owner", split, context=CHAT))   # a retry sends nothing
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM owner_reports WHERE agent='solo'")["n"], reports)

    def test_another_agent_s_ask_only_while_a_task_of_it_is_open(self):
        first = self.named("Link the KPIs of each agent.", "Link each agent's KPIs")       # its task is solo's
        task = hub.q1("SELECT id FROM tasks ORDER BY id DESC LIMIT 1")["id"]
        other = self.says("w", text="And the KPIs?")
        self.assertIn("the owner's ask to", self.refused("w", "tell_owner", {
            "text": "I do not know.", "in_reply_to": other["request_id"], "ask": f"M-{first['event_id']}"},
            context=CHAT))
        later = self.says("solo", text="Are the KPIs still in progress?")
        self.ok("solo", "tell_owner", {"text": "Six of seven are linked.", "in_reply_to": later["request_id"],
                                       "ask": f"M-{first['event_id']}"}, context=CHAT)
        self.assertEqual(self.row(later)["ask"], first["request_id"])
        with hub.transaction():
            hub.DB.execute("UPDATE tasks SET state='completed' WHERE id=?", (task,))
        again = self.says("solo", text="And now?")
        self.refused("solo", "tell_owner", {"text": "All seven.", "in_reply_to": again["request_id"],
                                            "ask": f"M-{first['event_id']}"}, context=CHAT)
        self.assertIn("the owner's ask to", self.refused(       # nor by its own earlier follow-up on that ask
            "solo", "tell_owner", {"text": "All seven.", "in_reply_to": again["request_id"],
                                   "ask": f"M-{later['event_id']}"}, context=CHAT))
        self.assertIsNone(self.row(again)["ask"])
        self.request("/ui/messages", self.command(recipient="solo", text="Any news?"))
        self.assertNotIn("Link each agent's KPIs", self.ok("solo", "read_messages", {}, context=CHAT))
        # the manager stays on top: it joins onto an ask that ANY open task is under (Needs-you, 25 November 2026)
        direct = self.says("w", text="Fix the shop's banner.")
        self.ok("w", "start_task", {"title": "Fix the banner", "done_when": "Done.", "asked": "Fix the shop's banner",
                                    "in_reply_to": direct["request_id"]}, context=CHAT)
        about = self.says(text="Is the banner fixed?", read=False)
        self.assertIn("Fix the shop's banner", self.ok("manager", "read_messages", {}))      # its read offers it
        self.ok("manager", "tell_owner", {"text": "It is in work.", "in_reply_to": f"M-{about['event_id']}",
                                          "ask": f"M-{direct['event_id']}"})
        self.assertEqual(self.row(about)["ask"], direct["request_id"])
        with hub.transaction():
            hub.DB.execute("UPDATE tasks SET state='completed' WHERE ask=?", (direct["request_id"],))
        late = self.says(text="And the logo?")
        self.assertIn("only while a task under it is open", self.refused("manager", "tell_owner", {
            "text": "Done.", "in_reply_to": f"M-{late['event_id']}", "ask": f"M-{direct['event_id']}"}))

    def test_a_message_written_on_a_card_is_on_it_for_sure(self):
        first = self.named("Make sure we charge nobody.", "Charge nobody for failed orders")
        later = self.says(text="How many were hit?", ask=first["request_id"], read=False)
        self.assertEqual(self.row(later)["ask"], first["request_id"])
        self.assertIn(f"card of their ask M-{first['event_id']} (\"Charge nobody for failed orders\")",
                      hub.q1("SELECT text FROM events WHERE id=?", (later["event_id"],))["text"])
        third = self.says(text="Thanks.", ask=later["request_id"], read=False)     # a follow-up names the same card
        self.assertEqual(self.row(third)["ask"], first["request_id"])
        # a correction written on the card names the message that it corrects, not the card, so it goes where that
        # message goes (a bug it stops: it kept the card's ask, and stayed behind when the message left the card). A
        # read message: an unread one is changed in place (edit_in_place), with no correction row
        self.ok("manager", "read_messages", {})
        fixed = self.says(text="Thanks a lot.", ask=first["request_id"], replaces_request_id=third["request_id"],
                          read=False)
        self.assertEqual((self.row(fixed)["ask"], hub.ask_first(fixed["request_id"])),
                         (third["request_id"], first["request_id"]))
        # a card that takes no more messages to this agent refuses no correction, which ignores the card (a bug it
        # stops: the correction got a 409)
        logs = self.says("solo", text="Check the logs.")
        with hub.transaction():
            hub.DB.execute("UPDATE tasks SET state='completed' WHERE owner='solo'")
        code, _ = self.request("/ui/messages", self.command(recipient="solo", text="And?", ask=first["request_id"]))
        self.assertEqual(code, 409)
        fixed = self.says("solo", text="Check the logs of May.", ask=first["request_id"],
                          replaces_request_id=logs["request_id"], read=False)
        self.assertEqual(self.row(fixed)["ask"], logs["request_id"])
        code, _ = self.request("/ui/messages", self.command(recipient="w", text="And?", ask=first["request_id"]))
        self.assertEqual(code, 409)             # no ask of w's, and no task of it is w's
        code, _ = self.request("/ui/messages", self.command(text="And?", ask=f"M-{first['event_id']}"))
        self.assertEqual(code, 400)

    def test_the_read_lists_the_owner_s_recent_asks_that_the_message_may_go_on_with(self):
        first = self.named("Make sure we charge nobody.", "Charge nobody for failed orders")
        self.says(text="Thanks.")                                       # no name: no ask
        disk = self.says("w", text="Check the disk.")
        self.ok("w", "start_task", {"title": "Check the disk", "done_when": "Done.", "asked": "Check the shop's disk",
                                    "in_reply_to": disk["request_id"]}, context=CHAT)
        for n in range(11):
            self.named(f"Thing {n}.", f"Do thing {n}")
        self.request("/ui/messages", self.command(text="Are they refunded yet?"))
        said = self.ok("manager", "read_messages", {})
        self.assertIn("The owner's recent asks: M-", said)
        self.assertIn("\"Do thing 10\"", said)
        self.assertNotIn("Check the shop's disk", said)                 # another agent's ask that it holds no task of
        self.assertEqual(said.count("\"Do thing"), 10)                  # at most ten, the newest
        # solo holds open tasks of the manager's asks: its read lists them, under their first message's name
        self.request("/ui/messages", self.command(recipient="solo", text="Any news?"))
        said = self.ok("solo", "read_messages", {}, context=CHAT)
        self.assertIn("\"Do thing 10\"", said)
        self.assertNotIn(f"\"Charge nobody for failed orders\"", said)  # the newest ten, by their last move
        # a read with no message of the owner's has no block
        self.assertNotIn("recent asks", self.ok("manager", "read_messages", {}))
        # a task session's read: the owner's steer starts "[owner" too, but it has no tell_owner: no block
        task = hub.q1("SELECT id FROM tasks WHERE owner='solo' ORDER BY id DESC LIMIT 1")["id"]
        with hub.transaction():
            hub.DB.execute("UPDATE tasks SET state='working', started=? WHERE id=?", (hub.now(), task))
        code, steered = self.request(f"/ui/tasks/{task}/steer", self.command(text="Keep it short."))
        self.assertEqual(code, 200, steered)
        said = self.ok("solo", "read_messages", {"task_id": hub.tref(task)}, task=task)
        self.assertIn("Keep it short.", said)
        self.assertNotIn("recent asks", said)

    def test_a_task_s_plain_result_is_an_answer_on_his_list_and_on_the_card(self):
        """His list and card say what the work came to: the newest result that its requester accepted. The bugs it
        stops: the newest answer stays an older reply after its task ended; an older result stands over a newer reply
        or a newer result; a result that its check refused ("Fixed", taken back) or that nobody checked yet stands as
        the answer; a part's result stands as the answer, which the card shows under its task only; a result that later
        work follows (it puts that result right) stands as the answer."""
        first = self.named("Check the disk.", "Check the disk")
        self.ok("manager", "tell_owner", {"text": "Solo checks it.", "in_reply_to": f"M-{first['event_id']}"})
        disk = hub.q1("SELECT id FROM tasks ORDER BY id DESC LIMIT 1")["id"]
        logs, part = (self.create(ask=f"M-{first['event_id']}")[0]["id"] for _ in range(2))
        t0 = hub.now()

        def ended(task, plain, at, accepted=1, parent=None):
            with hub.transaction():
                hub.DB.execute("UPDATE tasks SET state='completed', delivered=?, plain=?, accepted=?, parent=? "
                               "WHERE id=?", (at, plain, accepted, parent, task))

        def answer():
            said = self.request()[1]["owner_asks"][0]["answer"]
            return said["text"], said["agent"]

        def on_card(task):      # the card's plain words of a task: only where they stand as an answer
            return {t["id"]: t["plain"] for t in self.card(first["request_id"])[1]["tasks"]}[task]

        ended(disk, "The disk has 41% free.", t0 + 60)
        self.assertEqual(answer(), ("The disk has 41% free.", "solo"))
        self.assertEqual(on_card(disk), "The disk has 41% free.")
        ended(logs, "The logs take 3 GB.", t0 + 120)                    # a newer result is the newer answer
        self.assertEqual(answer()[0], "The logs take 3 GB.")
        for check in (0, None):                                         # refused, or not checked yet: no answer
            ended(logs, "The logs take 3 GB.", t0 + 120, accepted=check)
            self.assertEqual((answer()[0], on_card(logs)), ("The disk has 41% free.", None))
        ended(part, "Half of it is old logs.", t0 + 180, parent=disk)   # a part of the disk's task
        self.assertEqual((answer()[0], on_card(part)), ("The disk has 41% free.", None))
        ended(logs, "The logs take 3 GB.", t0 + 120)                    # accepted after all: the newest answer
        with hub.transaction():         # a later task that follows it, which somebody canceled, put nothing right
            hub.DB.execute("UPDATE tasks SET state='canceled', parent=NULL, follows=?, plain=NULL, accepted=NULL "
                           "WHERE id=?", (logs, part))
        self.assertEqual(answer()[0], "The logs take 3 GB.")
        with hub.transaction():         # in work, it puts that result right: no answer until it says its own
            hub.DB.execute("UPDATE tasks SET state='working' WHERE id=?", (part,))
        self.assertEqual((answer()[0], on_card(logs)), ("The disk has 41% free.", None))
        ended(disk, "The disk has 41% free.", t0 - 60)                  # a reply after the result is the newer answer
        self.assertEqual(answer()[0], "Solo checks it.")

    def test_the_manager_s_same_words_again_with_ask_make_the_join_and_send_nothing_twice(self):
        """The bugs it stops: the manager's retry with ask writes a second report, which goes to the chat app again;
        and the same words as its newest report, to a message that it names by its request id and that has no answer
        yet, make the join and are told as saved, so that message stays unanswered."""
        first = self.named("Make sure we charge nobody.", "Charge nobody for failed orders")
        later = self.says(text="Are they refunded yet?")
        self.ok("manager", "tell_owner", {"text": "Leo checks it.", "in_reply_to": f"M-{later['event_id']}"})
        # other words on a message that has its answer (a report with no link), and the same call again
        move = {"text": "That goes on with the refunds.", "in_reply_to": f"M-{later['event_id']}",
                "ask": f"M-{first['event_id']}"}
        self.assertIn("has no link", self.ok("manager", "tell_owner", move))
        again = self.ok("manager", "tell_owner", move)      # it writes no report, so it says nothing of one's link
        self.assertIn("already saved", again)
        self.assertIn(f"on the card of M-{first['event_id']}", again)
        self.assertNotIn("no link", again)
        self.assertEqual(self.row(later)["ask"], first["request_id"])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM owner_reports WHERE text=?", (move["text"],))["n"], 1)
        # two messages read, the same words to each, the second named by its request id with ask
        shop = self.says(text="Is the shop up?", read=False)
        fees = self.says(text="And the fees of May?")
        self.ok("manager", "tell_owner", {"text": "Leo looks.", "in_reply_to": f"M-{shop['event_id']}"})
        said = self.ok("manager", "tell_owner", {"text": "Leo looks.", "in_reply_to": fees["request_id"],
                                                 "ask": f"M-{first['event_id']}"})
        self.assertNotIn("already saved", said)
        self.assertEqual(self.row(fees)["ask"], first["request_id"])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM owner_reports WHERE in_reply_to=?",
                                (fees["request_id"],))["n"], 1)

    def test_the_phones_chat_gives_each_message_its_ask(self):
        first = self.named("Make sure we charge nobody.", "Charge nobody for failed orders")
        later = self.says(text="Are they refunded yet?")
        self.ok("manager", "tell_owner", {"text": "Leo checks it.", "in_reply_to": f"M-{later['event_id']}",
                                          "ask": f"M-{first['event_id']}"})
        items = self.request("/ui/mobile/chat/manager")[1]["items"]
        self.assertEqual({i["id"]: i["ask"] for i in items if i["kind"] == "message"},
                         {first["request_id"]: None, later["request_id"]: first["request_id"]})

    def test_an_ask_that_names_no_message_is_no_ask(self):
        lone = self.says(text="Check the disk.")
        with hub.transaction():
            hub.DB.execute("UPDATE ui_requests SET ask=? WHERE request_id=?", (str(uuid.uuid4()), lone["request_id"]))
        self.assertEqual(hub.ask_first(lone["request_id"]), lone["request_id"])
        one, two = self.says(text="One."), self.says(text="Two.")
        with hub.transaction():         # a loop, which no join writes, stops at its hops
            hub.DB.execute("UPDATE ui_requests SET ask=? WHERE request_id=?", (two["request_id"], one["request_id"]))
            hub.DB.execute("UPDATE ui_requests SET ask=? WHERE request_id=?", (one["request_id"], two["request_id"]))
        self.assertEqual(hub.ask_first(one["request_id"]), two["request_id"])     # one hop, then the loop ends
        self.request("/ui/messages", self.command(text="And?"))
        self.ok("manager", "read_messages", {})
        self.assertEqual(self.request()[0], 200)

    def test_his_list_holds_his_own_named_asks_with_their_follow_ups_and_newest_answer(self):
        """The Mac's window of messages holds about three days of the owner's fleet, so the hub builds the list. A bug
        it stops: an ask of his own that drops off, an AI session's ask or a word with no name that comes onto it, a
        follow-up on its own row, or an answer cut before the mask."""
        first = self.named("Make sure we charge nobody.", "Charge nobody for failed orders")
        later = self.says(text="Are they refunded yet?")
        self.ok("manager", "tell_owner", {"text": "Leo checks it now. " + "More words. " * 40,
                                          "in_reply_to": f"M-{later['event_id']}", "ask": f"M-{first['event_id']}"})
        self.says(text="Thanks.")                                            # no name: no ask
        session = self.command(text="Rank the new runtimes.")                # an AI session's ask: on the board only
        code, _ = self.request("/ui/messages", session, {"Content-Type": "application/json",
                                                         "X-Fleet-Client": "founderizer-mcp/1/test"})
        self.assertEqual(code, 200)
        self.ok("manager", "read_messages", {})
        self.create(ask=f"M-{hub.q1('SELECT event_id FROM ui_requests WHERE request_id=?', (session['request_id'],))['event_id']}",
                    asked="Rank the new runtimes")
        old = self.named("Check the old disk.", "Check the old disk")       # old, with its task open: still on it
        gone = self.named("Check the older logs.", "Check the older logs")   # old, and ended: not on it
        with hub.transaction():
            hub.DB.execute("UPDATE ui_requests SET created=created-20*86400 WHERE request_id IN (?,?)",
                           (old["request_id"], gone["request_id"]))
            hub.DB.execute("UPDATE tasks SET state='completed' WHERE ask=?", (gone["request_id"],))
        password = "Across-The-Cut-4242-Login"          # a login across the cut of an answer, registered after it
        self.ok("manager", "tell_owner", {"text": "The old disk is fine. " + "w " * 136 + password + " and more.",
                                          "in_reply_to": f"M-{old['event_id']}"})
        hub.ins("INSERT INTO secrets(salt,hash,len) VALUES(?,?,?)",
                ("cut-salt", hashlib.sha256(("cut-salt" + password).encode()).hexdigest(), len(password)))
        # rows of before the hand was kept (21 November 2026): his app's label is his hand, an AI session's is not
        before = self.named("Check the backups.", "Check the backups")
        bot = self.named("Rank the old runtimes.", "Rank the old runtimes")
        with hub.transaction():
            for row, client in ((before, "founderizer-swift/0.1.400"), (bot, "founderizer-mcp/1/test")):
                hub.DB.execute("UPDATE ui_requests SET hand=NULL, client=? WHERE request_id=?", (client, row["request_id"]))
        code, state = self.request()
        self.assertEqual(code, 200)
        listed = {a["id"]: a for a in state["owner_asks"]}
        self.assertEqual(set(listed), {first["request_id"], old["request_id"], before["request_id"]})
        mine = listed[first["request_id"]]
        self.assertEqual((mine["name"], mine["agent"], mine["messages"], mine["open"]),
                         ("Charge nobody for failed orders", "manager", [first["request_id"], later["request_id"]], True))
        self.assertTrue(mine["answer"]["text"].startswith("Leo checks it now."))
        self.assertLessEqual(len(mine["answer"]["text"]), hub.OWNER_ASK_WORDS)
        self.assertNotIn(password[:6], json.dumps(state))                  # cut after the mask: no part of it
        self.assertEqual(list(state)[-1], "owner_asks")                     # after every key of before
        code, phone = self.request("/ui/mobile")
        self.assertEqual((code, {a["id"] for a in phone["asks"]}), (200, set(listed)))
        # his own follow-up that goes on with an AI session's ask puts that ask on his list
        follow = self.says(text="And the GPU ones?")
        event = hub.q1("SELECT event_id FROM ui_requests WHERE request_id=?", (session["request_id"],))["event_id"]
        self.ok("manager", "tell_owner", {"text": "Yes, those too.", "in_reply_to": f"M-{follow['event_id']}",
                                          "ask": f"M-{event}"})
        mine = {a["id"]: a for a in self.request()[1]["owner_asks"]}
        self.assertEqual(mine[session["request_id"]]["messages"], [session["request_id"], follow["request_id"]])
        with hub.transaction():         # and an old one of his, while a task of the ask is open
            hub.DB.execute("UPDATE ui_requests SET created=created-20*86400 WHERE request_id=?", (follow["request_id"],))
        self.assertIn(session["request_id"], {a["id"] for a in self.request()[1]["owner_asks"]})

    def test_his_list_reads_nothing_more_for_a_message_that_is_no_ask_of_his(self):
        """Hub core, 25 November 2026: the list is read inside the hub's lock at each state read, and on his hub 290 of
        373 messages in 14 days came from AI sessions. A bug it stops: a read for each such message (about 760 point
        reads at each state read before)."""
        self.named("Make sure we charge nobody.", "Charge nobody for failed orders")

        def reads():
            ran = []
            hub.DB.set_trace_callback(ran.append)
            try:
                with hub.LOCK:
                    hub.owner_asks_rows(hub.now())
            finally:
                hub.DB.set_trace_callback(None)
            return len([sql for sql in ran if sql.lstrip().upper().startswith("SELECT")])
        few = reads()
        sent = []
        for n in range(12):
            body = self.command(text=f"Rank runtime {n}.")
            code, _ = self.request("/ui/messages", body,
                                   {"Content-Type": "application/json", "X-Fleet-Client": "founderizer-mcp/1/test"})
            self.assertEqual(code, 200)
            sent.append(body["request_id"])
        self.ok("manager", "read_messages", {})
        for request, kind in zip(sent, ("fast", "cheap", "small", "large", "local", "remote")):     # six with a name
            event = hub.q1("SELECT event_id FROM ui_requests WHERE request_id=?", (request,))["event_id"]
            self.ok("manager", "tell_owner", {"text": f"Noted: the {kind} ones.", "in_reply_to": f"M-{event}",
                                              "asked": f"Rank the {kind} runtimes"})
            self.assertEqual(self.asked({"request_id": request}), f"Rank the {kind} runtimes")
        self.assertEqual(reads(), few)

    def test_an_ask_s_card_gives_its_messages_answers_and_tasks_and_a_join_moves_its_follow_ups(self):
        first = self.named("Make sure we charge nobody.", "Charge nobody for failed orders")
        middle = self.says(text="And the fees?")
        last = self.says(text="And the emails?")
        self.ok("manager", "tell_owner", {"text": "Noted.", "in_reply_to": f"M-{middle['event_id']}",
                                          "asked": "Charge no fees"})          # a card of its own first, with a name
        self.ok("manager", "tell_owner", {"text": "Yes.", "in_reply_to": f"M-{last['event_id']}",
                                          "ask": f"M-{middle['event_id']}"})
        self.assertEqual(self.row(last)["ask"], middle["request_id"])
        self.ok("manager", "tell_owner", {"text": "Mia stops them.", "in_reply_to": f"M-{middle['event_id']}",
                                          "ask": f"M-{first['event_id']}"})
        self.assertEqual((self.row(middle)["ask"], self.row(last)["ask"]), (first["request_id"],) * 2)
        fees, _ = self.create(ask=f"M-{middle['event_id']}")
        code, card = self.card(last['request_id'])         # a follow-up's id opens the same card
        self.assertEqual(code, 200)
        self.assertEqual((card["id"], card["name"], card["agent"]),
                         (first["request_id"], "Charge nobody for failed orders", "manager"))
        self.assertEqual([m["request_id"] for m in card["messages"]],
                         [first["request_id"], middle["request_id"], last["request_id"]])
        self.assertEqual({r["text"] for r in card["reports"]}, {"Noted.", "Yes."})
        self.assertIn(fees["id"], [t["id"] for t in card["tasks"]])
        self.assertLessEqual(set(hub.MOBILE_HEAD), set(card["tasks"][0]))
        # a correction is on the card of the message that it corrects, also a correction of a correction, however many
        fixed = self.says(text="And the emails of May?", replaces_request_id=last["request_id"])
        for month in ("June", "July", "August", "September", "October"):
            fixed = self.says(text=f"And the emails of {month}?", replaces_request_id=fixed["request_id"])
        self.assertEqual((fixed["ask"], hub.ask_first(fixed["request_id"])), (last["request_id"], first["request_id"]))
        said = {m["request_id"]: m for m in self.card(first['request_id'])[1]["messages"]}
        self.assertEqual(said[fixed["request_id"]]["replaces_request_id"], fixed["replaces_request_id"])  # marked as one
        self.assertIsNone(said[first["request_id"]]["replaces_request_id"])
        # a later report that took a message's turn with no words of that turn is no answer to it (turn_word)
        with hub.transaction():
            hub.DB.execute("INSERT INTO owner_reports(text,about,created,agent,in_reply_to,turn,turn_word) "
                           "VALUES(?,?,?,?,?,?,?)", ("Unrelated news.", "", hub.now() + 5, "manager", None,
                                                    first["request_id"], None))
        code, card = self.card(first['request_id'])
        self.assertNotIn("Unrelated news.", [r["text"] for r in card["reports"]])
        self.assertNotEqual(self.request()[1]["owner_asks"][0]["answer"]["text"], "Unrelated news.")
        said = {m["request_id"]: (m["hand"], m["runtime"]) for m in self.request()[1]["messages"]}
        self.assertEqual([(m["hand"], m["runtime"]) for m in card["messages"]],      # who sent each, as the chat says
                         [said[m["request_id"]] for m in card["messages"]])
        self.assertFalse([m for m in card["messages"] if "session" in m])
        self.assertEqual(self.card(uuid.uuid4())[0], 404)
        self.assertEqual(self.request(f"/ui/mobile/asks/{first['request_id']}?db=other")[0], 409)
        self.assertTrue(hub.device_may(f"/ui/mobile/asks/{first['request_id']}", "GET"))   # the phone reads it too

    def test_each_read_of_his_asks_goes_by_an_index(self):
        """Hub core, 25 November 2026: a read under the hub's lock goes through an index, and the hub runs no ANALYZE.
        A later change that loses one (another condition, a dropped index) fails here, with its plan."""
        plans = {hub.ASKS_RECENT_READ: (("manager", 0.0, 10), ("ui_request_recipient",)),
                 hub.ASKS_OPEN_READ: (("solo",), ("task_owner_open", "task_owner_state")),
                 hub.ASK_FOLLOW_UPS_READ: (("x",), ("ui_requests_ask",)),
                 hub.ASK_CORRECTIONS_READ.format("?,?"): (("x", "y"), ("ui_requests_ask",)),
                 hub.ASK_REPLY_READ: (("manager", "x"), ("owner_reply_identity",)),
                 hub.ASK_TURN_READ: (("x",), ("owner_report_turn",)),
                 hub.ASK_TASKS_READ.format("?,?"): (("x", "y"), ("task_ask",)),
                 hub.ASK_RESULT_READ.format("?,?"): (("x", "y") * 3, ("task_ask",))}
        for sql, (args, indexes) in plans.items():
            plan = " | ".join(r["detail"] for r in hub.q("EXPLAIN QUERY PLAN " + sql, args))
            self.assertTrue(any(index in plan for index in indexes), f"{sql}: {plan}")


class FirstJob(Asks):
    """The fleet's first job (P5 version 3, piece J; section 3.4). solo is the first agent: the agent that the first
    plan of a fleet with no worker added (test_team_changes holds that part). Until the manager accepts a completed
    task of it that the owner asked for, a task of it whose ask holds the owner's files takes a first piece's words."""

    def setUp(self):
        super().setUp()
        hub.TEAM["agents"]["solo"]["can"].append("browser")
        hub.kv_set(hub.FIRST_AGENT + "solo", str(hub.now()))

    def with_file(self):
        """The owner's message to the manager with one file: mails of other people, the material of the first job."""
        message = self.says(text="Here are some client emails.")
        hub.q("INSERT INTO attachments(request_id,name,mime,size,sha256,created,client,message) VALUES(?,?,?,?,?,?,?,?)",
              (str(uuid.uuid4()), "mails.eml", "message/rfc822", 10, "0" * 64, hub.now(), "test", message["request_id"]))
        return message

    def piece(self, tone=""):
        title, _, done_when, details = hub.FIRST_JOBS[0]["piece"]
        return {"title": title, "done_when": done_when, "details": details + tone}

    def deliver(self, owner, task, outcome="completed"):
        self.ok(owner, "deliver_result", dict({"task_id": hub.tref(task["id"]), "outcome": outcome,
                                               "what_was_done": "Wrote what the mailbox needs."},
                                              **({"where_output_is": "This result.", "how_checked": "Read it again."}
                                                 if outcome == "completed" else {})), task["id"])

    def test_a_first_task_with_the_owner_s_files_takes_only_a_first_piece_s_words(self):
        """P5 3.4: a task of the first agent whose ask holds the owner's files takes the title, done_when and details
        of one first piece, with needs none, and at most 120 characters of the manager's own tone, with no web address
        in it, in its goal (an id or a plain label) or in its step; the refusal names the part that failed and the way
        for a job that no piece fits. Bugs: the manager copies the website's text or its address into the task that
        holds the mails (in the details, after them, or in a goal), also with a full-width dot or a zero-width space
        in the host name, or gives it a browser, so the agent reads other
        people's mails beside words from a site that it may open; a refusal that says the same for each fault, which
        the manager meets again and again; one that sends a job in the owner's own words to the nearest wrong piece;
        or one that sends the owner's files to the agent's own chat, where no check of the hub's reads them."""
        ref = f"M-{self.with_file()['event_id']}"
        base = {"owner": "solo", "ask": ref, "asked": "Draft three replies", "why": "Client emails"}
        site = "Costa Studio takes wedding photos. See https://costastudio.example/prices for all of them."
        t0 = hub.now()
        limits = json.dumps({"money": None, "tokens": None, "deadline": None, "not_to_do": []})     # update_goal's
        goal = hub.ins("INSERT INTO goals(title,text,state,revision,limits,created,updated,request_id) VALUES(?,?,"
                       "'active',1,?,?,?,?)", ("Client emails of costastudio.example", "Answer client mail.", limits,
                                               t0, t0, str(uuid.uuid4())))
        for fields, part in (({"title": "Answer the emails", "done_when": "Done.", "details": site},
                              "its title is the title of no first piece"),
                             (dict(self.piece(), title="Draft replies to client emails"),
                              "its title is the title of no first piece"),
                             (dict(self.piece(), done_when="Done."), "its done_when is not the line"),
                             (dict(self.piece(), details=site), "its details do not begin with the details"),
                             (self.piece(" Warm and short. Prices: costastudio.example/prices"),
                              "reads as a web address"),
                             (self.piece(" Warm and short, as on www.costastudio.example"), "reads as a web address"),
                             # NFKC and the skeleton: a full-width full stop, and a zero-width space in the host
                             (self.piece(" Warm. Prices: costastudio" + chr(0xFF0E) + "example/prices"),
                              "reads as a web address"),
                             (self.piece(" Warm, as on costastudio" + chr(0x200B) + ".example"),
                              "reads as a web address"),
                             (self.piece(" Warm and short." * 8), "the tone after the details has 127 characters"),
                             (dict(self.piece(), needs="browser"), "it needs browser"),
                             (dict(self.piece(), goal=f"G-{goal}"), "its goal or its plan step holds"),
                             (dict(self.piece(), goal="Costa Studio, costastudio.example"),
                              "its goal or its plan step holds")):
            said = self.refused("manager", "create_task", dict(base, **fields))
            self.assertIn(part, said)
            self.assertIn("give solo first a task whose ask holds no file", said)
            self.assertNotIn("own chat", said)          # the owner's files there pass no check of the hub's
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tasks")["n"], 0)
        task, _ = self.create(**dict(base, **self.piece(" Warm, short sentences, with the client's first name.")))
        self.assertEqual([a["name"] for a in hub.task_files(task)], ["mails.eml"])
        self.create(**dict(base, **dict(self.piece(), title=hub.FIRST_JOBS[0]["piece"][1])))     # a Spanish app's
        self.create(owner="lead", ask=ref, title="Check the replies", details=site)       # not the first agent
        hub.kv_set(hub.FIRST_RESULT, str(task["id"]))
        self.create(**dict(base, title="Answer the emails", details=site))                # after the first result

    def test_only_the_acceptance_of_an_asked_completed_task_of_the_first_agent_ends_the_first_job(self):
        """P5 3.4 and the readers' final note: the drafts piece is the offer, not the only way. A first task whose ask
        is the owner's typed words with no file ("just connect my mailbox") takes the manager's own words and holds no
        file, and the manager's acceptance of its completed result is the first result; what the manager does next
        stays in its reads until it acts. Bugs: the check refuses the owner's own work, so the first agent never
        starts; the agent's own delivery ends the first job, so an act of its own drops a protection early; a failed
        task, a task with no ask, or a peer's acceptance of a part that it gave ends it, before the manager or the
        agent's own lead saw any result; no result ends it, and the list stays for ever; the
        steps after the result leave with the list, before the manager takes them; they stay after the manager raised
        its next card (turn 8's Connect card has no Give) or a grant came, so each new session asks the owner the same
        question again; or a card, a grant or a take-back from before the result ends them."""
        ref = f"M-{self.says(text='No samples, just connect my mailbox.')['event_id']}"
        asked, _ = self.create(title="Connect the mailbox", ask=ref, asked="Connect the mailbox")
        self.assertEqual(hub.task_files(asked), [])
        self.deliver("solo", asked)                     # its own delivery, which nobody accepted yet
        failed, _ = self.create(title="Read the mailbox", ask=ref)
        self.deliver("solo", failed, "failed")
        plain, _ = self.create(title="Check the disk")  # no ask: no work of the owner's
        self.deliver("solo", plain)
        for task in (failed, plain):
            self.assertNotIn("first result", self.ok("manager", "check_result", {"task_id": hub.tref(task["id"]),
                                                                                  "accepted": True}))
        # lead gives solo, its peer under the manager, a part of its own asked task, and accepts it: no first result
        mine, _ = self.create(owner="lead", title="Check the replies", ask=ref)
        peer, _ = self.create("lead", "solo", task=mine["id"], title="Read the replies")
        self.assertEqual((peer["requester"], peer["ask"]), ("lead", mine["ask"]))
        self.deliver("solo", peer)
        self.assertNotIn("first result", self.ok("lead", "check_result", {"task_id": hub.tref(peer["id"]),
                                                                           "accepted": True}, mine["id"]))
        self.assertIsNone(hub.kv_get(hub.FIRST_RESULT))
        self.assertIn("FIRST JOBS", self.ok("manager", "see_capacity", {}))
        t0 = hub.now()
        grant = "INSERT INTO resource_grants(ts,resource,agent,level,by) VALUES(?,?,'solo',?,'owner')"
        card = "INSERT INTO needs(title,why,todo,raised,by) VALUES(?,'x','y',?,'manager')"      # no Give, as turn 8's
        hub.q(card, ("Choose a plan", t0))                                  # from before the result
        hub.q(grant, (t0, "drive:a@b.example", "read"))
        said = self.ok("manager", "check_result", {"task_id": hub.tref(asked["id"]), "accepted": True})
        self.assertIn("It is the fleet's first result", said)
        after = "AFTER THE FIRST RESULT: solo holds no duty yet. Ask the owner whether it sends by itself"
        self.assertIn(after, said)
        self.assertEqual(hub.kv_get(hub.FIRST_RESULT), str(asked["id"]))
        self.assertNotIn("FIRST JOBS", self.ok("manager", "see_capacity", {}))
        # it ends at the first sign that the manager went on, after the result: any card of its own, a grant to solo
        # that is no take-back, or a duty of solo; a second check of the task does not move the result's moment
        def line():
            return self.ok("manager", "see_team", {})
        hub.q(grant, (t0, "drive:a@b.example", None))                       # a take-back
        self.assertIn(after, line())
        hub.q(card, ("Connect Gmail", t0))
        self.assertNotIn("AFTER THE FIRST RESULT", line())
        self.ok("manager", "check_result", {"task_id": hub.tref(asked["id"]), "accepted": True})
        self.assertNotIn("AFTER THE FIRST RESULT", line())
        hub.q("DELETE FROM needs WHERE title='Connect Gmail'")
        self.assertIn(after, line())
        hub.q(grant, (t0, "gmail:a@b.example", "write"))
        self.assertNotIn("AFTER THE FIRST RESULT", line())
        hub.q("DELETE FROM resource_grants WHERE resource='gmail:a@b.example'")
        self.assertIn(after, line())
        hub.q("INSERT INTO responsibilities(agent,text,state,revision,created,updated,created_by,request_id) VALUES("
              "'solo','Show each draft, send nothing.','active',1,?,?,'manager','r-1')", (t0, t0))
        self.assertNotIn("AFTER THE FIRST RESULT", line())

    def test_the_lead_of_the_first_agent_accepts_its_first_result(self):
        """P5 3.4 (reader B, round 1): the acceptance of the first agent's task by its own requester, the lead that it
        reports to, is the first result too, and the next turns go to the manager. Bugs: a first agent under a lead
        never gets a first result, so the list and the hold of its tasks stay for ever; or the lead is told to ask the
        owner, which only the manager does; or the hold of the first agent's task with the owner's files sends the lead
        to the list of first jobs, which only the manager reads, or to the manager to give the task, which the hub
        refuses while the lead can act, so the lead cannot follow its refusal."""
        hub.kv_set(hub.FIRST_AGENT + "solo", None)
        hub.kv_set(hub.FIRST_AGENT + "w", str(hub.now()))       # w reports to lead
        files = f"M-{self.with_file()['event_id']}"
        held, _ = self.create(owner="lead", title="Answer the client emails", ask=files, asked="Answer the emails")
        said = self.refused("lead", "create_task", {"owner": "w", "title": "Answer the emails", "done_when": "Done.",
                                                    "why": "It suits it."}, held["id"])
        self.assertIn("The fleet has no first result yet, and this task for w holds the owner's files", said)
        self.assertIn("from a list that you do not read", said)
        # the manager may not give a task to w while its lead can act (authority): the lead asks for the words
        self.assertIn("ask the manager with ask_my_requester for the exact words of one first piece", said)
        self.assertNotIn("give this task", said)
        ref = f"M-{self.says(text='No samples, just connect my mailbox.')['event_id']}"
        mine, _ = self.create(owner="lead", title="Connect the mailbox", ask=ref, asked="Connect the mailbox")
        part, _ = self.create("lead", "w", task=mine["id"], title="Read the mailbox")
        self.assertEqual(part["ask"], mine["ask"])
        self.deliver("w", part)
        said = self.ok("lead", "check_result", {"task_id": hub.tref(part["id"]), "accepted": True}, mine["id"])
        self.assertIn("It is the fleet's first result", said)
        self.assertNotIn("AFTER THE FIRST RESULT", said)                # a lead asks the owner nothing
        self.assertEqual(hub.kv_get(hub.FIRST_RESULT), str(part["id"]))
        self.assertIn("AFTER THE FIRST RESULT: w holds no duty yet", self.ok("manager", "see_team", {}))


# unittest runs only this file's cases, not the ones it inherits from the owner API's.
def load_tests(_loader, _tests, _pattern):
    return unittest.TestSuite([*(Asks(name) for name in Asks.__dict__ if name.startswith("test_")),
                               *(Jobs(name) for name in Jobs.__dict__ if name.startswith("test_")),
                               *(FollowUps(name) for name in FollowUps.__dict__ if name.startswith("test_")),
                               *(FirstJob(name) for name in FirstJob.__dict__ if name.startswith("test_"))])


if __name__ == "__main__":
    unittest.main()

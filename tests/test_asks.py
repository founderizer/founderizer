"""What the owner asked for (owner feature asks; the owner, 15 November 2026: "I am not interested in the specific
individual tasks to be done but in the thing I asked for to be done", and "if I ask something new, it gets registered
too"). A task names the owner's own message that it comes from (tasks.ask), that message gets the few words that the
owner's apps show for it (ui_requests.asked), a follow-up and a subtask take the ask of their task, and a Needs-you
item names the ask whose work waits for it (needs.ask). In-process, against the hub of test_ui_api."""
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
        item = {"title": "Which colour?", "why": "Only he chose the brand", "what_to_do": "Say blue or green", "reason": "person"}

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
        chat = {t["name"]: t for t in hub.tools_for("solo", CHAT)}
        self.assertIn("asked", chat["start_task"]["inputSchema"]["properties"])
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


# unittest runs only this file's cases, not the ones it inherits from the owner API's.
def load_tests(_loader, _tests, _pattern):
    return unittest.TestSuite([*(Asks(name) for name in Asks.__dict__ if name.startswith("test_")),
                               *(Jobs(name) for name in Jobs.__dict__ if name.startswith("test_"))])


if __name__ == "__main__":
    unittest.main()

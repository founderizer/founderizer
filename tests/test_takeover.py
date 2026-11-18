"""Owner feature need_takeover (the owner's "Yes, as drawn" of 16 November 2026): an agent's browser or screen task asks
the owner for one step on its own screen that only a person can do. The item's title is the hub's words for that
step, the task waits
for his answer with no clock, his answer reaches the task's session, and the task's end takes an open request out of
Needs you. An in-process hub with the owner API's harness; no fleet, no network and no AI call."""
import json
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid

import hub
import test_ui_api

TITLE = "Solve the CAPTCHA on its screen"
OWNER = "127.0.0.1"             # the owner's Mac, as OwnerAPI sets it


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """The board answers a write with 303 back to the page; the checks read that code, not the page."""
    def redirect_request(self, *_args):
        return None


def load_tests(loader, _tests, _pattern):
    """Only this file's checks: the harness comes from OwnerAPI, its own tests stay in its own file."""
    suite = unittest.TestSuite()
    for cls in (Ask, Answer, Refusals):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Fixture(unittest.TestCase):
    """The owner API's hub of test_ui_api, without its tests, with a worker on a Mac (ivy) and a lead (leo)."""
    tearDown, connect = test_ui_api.OwnerAPI.tearDown, test_ui_api.OwnerAPI.connect
    request, command = test_ui_api.OwnerAPI.request, test_ui_api.OwnerAPI.command

    def setUp(self):
        test_ui_api.OwnerAPI.setUp(self)
        hub.TEAM["addresses"].update({"ivy-host": "127.0.0.3", "leo-host": "127.0.0.4"})
        hub.TEAM["agents"]["ivy"] = dict(role="worker", runtime="claude", machine="ivy-host",
                                         can=["shell", "web", "browser"])
        hub.TEAM["agents"]["leo"] = dict(role="lead", runtime="claude", machine="leo-host",
                                         can=["shell", "web", "browser"])
        # the Screen Sharing way that the owner's Mac app opens, as the machine's page reads it
        hub.TEAM["access"] = {m: {"ssh_user": "owner-example", "ssh_port": 22, "screen_sharing": True}
                              for m in ("ivy-host", "leo-host")}
        self.server.machines = True             # each request comes from the machine that its route names

    def task(self, owner="ivy", needs="browser"):
        text = hub.t_create_task("manager", {"owner": owner, "title": "Read the supplier's report", "done_when": "read"})
        tid = int(text.split()[1][2:].rstrip("."))
        hub.q("UPDATE tasks SET state='working', started=?, needs=? WHERE id=?", (hub.now(), needs, tid))
        return tid

    def ask(self, tid, agent="ivy", step="captcha"):
        return hub.call_tool(agent, "request_takeover", {"step": step} if step is not None else {},
                             ("test-generation", f"T-{tid}", "1"))

    def state(self, tid):
        t = hub.q1("SELECT state, waiting_on FROM tasks WHERE id=?", (tid,))
        return t["state"], t["waiting_on"]

    def says(self, tid):
        return [r["text"] for r in hub.q("SELECT text FROM events WHERE task=? AND kind='say' ORDER BY id", (tid,))]

    def item(self, nid):
        """The item as GET /ui/state gives it to the Mac app."""
        code, state = self.request()
        self.assertEqual(code, 200, state)
        return next(n for n in state["needs"] if n["id"] == nid)

    def answer(self, nid, **body):
        return self.request(f"/ui/needs/{nid}", dict(dict(request_id=str(uuid.uuid4()), db="test-generation"),
                                                     **body))

    def board(self, nid, answer):
        """One written answer on the hub's own board, without following its redirect back to the page."""
        req = urllib.request.Request(self.base + f"/needs/{nid}", data=urllib.parse.urlencode({"answer": answer}).encode(),
                                     headers={"Content-Type": "application/x-www-form-urlencoded",
                                              "X-Test-Source": OWNER})
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect).open(req, timeout=5) as r:
                return r.status
        except urllib.error.HTTPError as r:
            with r:
                return r.code


class Ask(Fixture):
    """The agent asks in its browser or screen task, and the task waits."""

    def test_a_browser_task_asks_and_its_task_waits(self):
        tid = self.task()
        text, err = self.ask(tid)
        self.assertFalse(err, text)
        self.assertIn("This task waits for the owner's answer: end your turn.", text)
        need = hub.q1("SELECT * FROM needs WHERE by='ivy'")
        self.assertEqual((need["kind"], need["title"], need["takeover_task"]), ("takeover", TITLE, tid))
        self.assertEqual((need["why"], need["todo"], need["answer"]), ("", "", None))
        self.assertIn(f"N-{need['id']}", text)
        self.assertEqual(self.state(tid), ("input-required", f"N-{need['id']}"))
        item = self.item(need["id"])
        self.assertEqual((item["kind"], item["takeover_task"], item["by"], item["title"]),
                         ("takeover", tid, "ivy", TITLE))
        self.assertIsNone(item["secret"])       # no secure form: he answers it as any item

    def test_a_screen_task_and_a_leads_task_ask_too(self):
        screen = self.task(needs="screen")
        self.assertFalse(self.ask(screen)[1])
        lead = self.task(owner="leo")
        text, err = self.ask(lead, agent="leo")
        self.assertFalse(err, text)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs WHERE kind='takeover'")["n"], 2)

    def test_a_second_call_of_the_task_names_the_open_request_and_raises_none(self):
        tid = self.task()
        self.assertFalse(self.ask(tid)[1])
        text, err = self.ask(tid)
        self.assertFalse(err, text)
        self.assertIn("already asks the owner for a step on your screen", text)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs")["n"], 1)

    def test_the_task_waits_on_it_again_after_something_else_released_it(self):
        tid = self.task()
        self.assertFalse(self.ask(tid)[1])
        nid = hub.q1("SELECT id FROM needs")["id"]
        hub.q("UPDATE tasks SET state='working', waiting_on=NULL WHERE id=?", (tid,))     # a restart, for example
        with hub.transaction():
            hub.secret_rewait(tid)
        self.assertEqual(self.state(tid), ("input-required", f"N-{nid}"))

    def test_the_apps_read_what_the_session_does(self):
        self.assertEqual(hub.DOING_FLEET["request_takeover"], "Asking you for a step on its screen")


class Answer(Fixture):
    """His answer reaches the task's session and ends the wait; the task's end takes an open request away."""

    def setUp(self):
        super().setUp()
        self.tid = self.task()
        self.assertFalse(self.ask(self.tid)[1])
        self.nid = hub.q1("SELECT id FROM needs")["id"]

    def test_his_quick_reply_reaches_the_tasks_session_and_the_task_works_again(self):
        code, body = self.answer(self.nid, answer="Done")
        self.assertEqual(code, 200, body)
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (self.nid,))["answer"], "Done")
        said = self.says(self.tid)
        self.assertEqual(len(said), 1, said)
        self.assertIn(f"Answer to Needs-you N-{self.nid} ({TITLE}): Done", said[0])
        self.assertEqual(self.state(self.tid), ("working", None))
        text, err = hub.call_tool("ivy", "read_messages", {}, ("test-generation", f"T-{self.tid}", "1"))
        self.assertFalse(err, text)
        self.assertIn("Done", text)

    def test_his_own_words_reach_it_too(self):
        code, body = self.answer(self.nid, answer="I cannot now, try again after lunch")
        self.assertEqual(code, 200, body)
        self.assertIn("I cannot now, try again after lunch", self.says(self.tid)[0])
        self.assertEqual(self.state(self.tid), ("working", None))

    def test_an_answer_on_the_hubs_board_reaches_the_task_too(self):
        self.assertEqual(self.board(self.nid, "Done on the board"), 303)
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (self.nid,))["answer"], "Done on the board")
        said = self.says(self.tid)
        self.assertEqual(len(said), 1, said)
        self.assertIn("Done on the board", said[0])
        self.assertEqual(self.state(self.tid), ("working", None))

    def test_a_second_answer_is_refused(self):
        self.assertEqual(self.answer(self.nid, answer="Done")[0], 200)
        self.assertEqual(self.answer(self.nid, answer="Done again")[0], 409)
        self.assertEqual(len(self.says(self.tid)), 1)

    def test_after_an_answer_that_is_not_done_the_task_asks_again_only_after_its_requester(self):
        """After "Done" the task asks for its next step at once. After any other answer ("Not now", "Done? No, stop
        asking", the owner's own words, from an app or the board) a call raises no card and no notification until a
        question that the task asked after it gets a real answer, so a session cannot ask the owner again and again; a
        restart that closes the question is no answer (review of 17 November 2026)."""
        ctx = ("test-generation", f"T-{self.tid}", "1")
        self.assertEqual(self.answer(self.nid, answer="Done")[0], 200)
        self.assertFalse(hub.call_tool("ivy", "ask_my_requester", {"question": "Which page comes after it?",
                                                                    "default": "The order page."}, ctx)[1])
        early = hub.q1("SELECT MAX(id) n FROM questions")["n"]
        self.assertFalse(self.ask(self.tid)[1])
        again = hub.q1("SELECT MAX(id) n FROM needs")["n"]
        self.assertEqual(self.answer(again, answer="Not now")[0], 200)
        # an answer, after it, to a question asked before it ends no stop
        self.assertFalse(hub.call_tool("manager", "answer", {"question_id": f"Q-{early}",
                                                             "text": "The order page."})[1])
        text, err = self.ask(self.tid)
        self.assertTrue(err, text)
        self.assertIn(f'did not answer "Done" to N-{again}', text)
        self.assertFalse(hub.call_tool("ivy", "ask_my_requester", {"question": "May I ask the owner again?"}, ctx)[1])
        qid = hub.q1("SELECT MAX(id) n FROM questions")["n"]
        hub.q("UPDATE questions SET answer=?, answered=?, waiting=0 WHERE id=?",     # a restart closes it, as
              (hub.RESTART_ANSWER.format(by="manager", task=f"T-{self.tid}"), hub.now(), qid))  # restart_continue does
        self.assertIn('did not answer "Done"', self.ask(self.tid)[0])
        self.assertFalse(hub.call_tool("ivy", "ask_my_requester", {"question": "May I ask them once more?"}, ctx)[1])
        qid = hub.q1("SELECT MAX(id) n FROM questions")["n"]
        self.assertFalse(hub.call_tool("manager", "answer", {"question_id": f"Q-{qid}", "text": "Yes, ask again."})[1])
        self.assertFalse(self.ask(self.tid)[1])
        third = hub.q1("SELECT MAX(id) n FROM needs")["n"]
        self.assertEqual(self.board(third, "Done? No, stop asking"), 303)
        self.assertIn(f'did not answer "Done" to N-{third}', self.ask(self.tid)[0])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs")["n"], 3)

    def test_a_task_that_ends_takes_its_open_request_out_of_needs_you(self):
        text, err = hub.call_tool("manager", "cancel_task", {"task_id": f"T-{self.tid}", "reason": "not needed"})
        self.assertFalse(err, text)
        self.assertIsNone(hub.q1("SELECT 1 FROM needs WHERE id=?", (self.nid,)))
        self.assertNotIn(self.nid, [n["id"] for n in self.request()[1]["needs"]])
        self.assertGreater(hub.unused_id("needs"), self.nid)         # its number is not given again

    def test_an_answered_request_stays_when_its_task_ends(self):
        self.assertEqual(self.answer(self.nid, answer="Done")[0], 200)
        self.assertFalse(hub.call_tool("manager", "cancel_task", {"task_id": f"T-{self.tid}", "reason": "done"})[1])
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (self.nid,))["answer"], "Done")


class Refusals(Fixture):
    """Who may ask, where, and with which words."""

    def refused(self, tid, agent="ivy", step="captcha"):
        text, err = self.ask(tid, agent=agent, step=step)
        self.assertTrue(err, text)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs")["n"], 0)
        return text

    def test_a_task_with_no_screen_cannot_ask(self):
        self.assertIn("Only a browser or screen task", self.refused(self.task(needs="none")))

    def test_another_agents_task_and_an_ended_task_cannot_ask(self):
        # the session fence refuses another agent's task before the tool runs; the tool refuses it too
        self.assertIn("STOP", self.refused(self.task(owner="leo")))
        hub.CALL.context = ("test-generation", f"T-{self.task(owner='leo')}", "1")
        try:
            with self.assertRaisesRegex(hub.ToolError, "your own open browser or screen task"):
                hub.t_request_takeover("ivy", {"step": "captcha"})
        finally:
            hub.CALL.context = None
        tid = self.task()
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (tid,))
        self.assertTrue(self.ask(tid)[1])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs")["n"], 0)

    def test_a_machine_with_no_screen_sharing_way_cannot_ask(self):
        del hub.TEAM["access"]["ivy-host"]
        self.assertIn("no Screen Sharing way to your machine", self.refused(self.task()))
        hub.TEAM["access"]["ivy-host"] = {"ssh_user": "owner-example", "ssh_port": 22, "screen_sharing": False}
        self.assertIn("no Screen Sharing way", self.refused(self.task()))
        hub.TEAM["access"]["ivy-host"] = {"screen_sharing": True}          # no SSH user: the app has no tunnel
        self.assertIn("no Screen Sharing way", self.refused(self.task()))

    def test_a_task_that_a_conversation_opened_cannot_ask(self):
        tid = self.task()
        hub.q("UPDATE tasks SET source_conversation=1 WHERE id=?", (tid,))
        self.assertIn("no tool named request_takeover", self.refused(tid))

    def test_the_owner_chat_and_the_manager_have_no_such_tool(self):
        self.assertNotIn("request_takeover", hub.CHAT_TOOLS)
        names = [t["name"] for t in hub.tools_for("manager")]
        self.assertNotIn("request_takeover", names)
        tid = self.task()
        self.assertIn("request_takeover", [t["name"] for t in hub.tools_for("ivy", ("test-generation", f"T-{tid}",
                                                                                     "1"))])

    def test_the_card_is_the_hubs_words_for_a_captcha_only(self):
        """The agent names the step and writes no word of the card, so no wording and no language can ask the owner for
        a password on its screen; and a one-time code is no step yet: a code typed on a screen that the agent drives
        can sign in somewhere else (review of 17 November 2026). The card is in the owner's language."""
        tid = self.task()
        for step in (None, "", "password", "code", "new_device", ["captcha"]):
            self.refused(tid, step=step)
        self.assertIn("A text-message code goes to your requester", self.refused(tid, step="code"))
        text, err = hub.call_tool("ivy", "request_takeover", {"step": "captcha", "what": "Type the password here"},
                                  ("test-generation", f"T-{tid}", "1"))
        self.assertTrue(err, text)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs")["n"], 0)
        hub.TEAM["settings"] = {"owner.language": "es"}
        self.addCleanup(hub.TEAM.pop, "settings", None)
        self.assertFalse(self.ask(tid)[1])
        self.assertEqual(hub.q1("SELECT title FROM needs")["title"], "Resuelve el CAPTCHA en su pantalla")

if __name__ == "__main__":
    unittest.main()

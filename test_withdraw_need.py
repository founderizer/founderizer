"""The owner's plan of 6 November 2026, B1 and B2: the manager withdraws a Needs-you item of its own that nothing needs
any more, and reads before it raises. A withdrawn item leaves Needs you with no notification and keeps its reason. An
in-process hub with the owner API's harness; no fleet, no network and no AI call."""
import hashlib
import json
import unittest
import uuid

import hub
from test_ui_api import OwnerAPI


def load_tests(loader, _tests, _pattern):
    """Only this file's checks: the harness comes from OwnerAPI, its own tests stay in its own file."""
    suite = unittest.TestSuite()
    for case in (Withdraw, AcceptNamesItems):
        suite.addTests(case(name) for name in case.__dict__ if name.startswith("test_"))
    return suite


class Withdraw(OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM["agents"]["vps"] = {"role": "worker", "runtime": "claude", "machine": "vps", "can": []}

    def raise_item(self, title="Revoke the old shared key?"):
        said = hub.t_raise_needs_you("manager", {"title": title, "why": "The three new keys work.",
                                                 "what_to_do": "Say yes or no"})
        return int(said.split("N-")[1].split(".")[0])

    def item(self, nid, **columns):
        """An item that the tool cannot make itself: another agent's, a question's, a conversation's."""
        row = dict({"title": "An item", "why": "Its why", "todo": "Its step", "raised": hub.now(), "by": "manager"},
                   **columns)
        names = ",".join(["id", *row])
        hub.ins(f"INSERT INTO needs({names}) VALUES({','.join('?' * (len(row) + 1))})", (nid, *row.values()))
        return nid

    def notices(self):
        return hub.q1("SELECT COUNT(*) n FROM events WHERE agent='owner' AND kind='notify'")["n"]

    def open_ids(self):
        """The items that the app shows in Needs you: /ui/state lists every item, and the app's Need.isOpen is
        `answer == nil && answered == nil`."""
        code, state = self.request()
        self.assertEqual(code, 200, state)
        return [n["id"] for n in state["needs"] if n["answer"] is None and n["answered"] is None]

    def refused(self, args, words):
        said, error = hub.call_tool("manager", "withdraw_need", args)
        self.assertTrue(error, said)
        self.assertIn(words, said)

    def test_the_manager_withdraws_its_own_item_with_no_notification(self):
        nid = self.raise_item()
        self.assertIn(nid, self.open_ids())
        told = self.notices()
        said, error = hub.call_tool("manager", "withdraw_need", {"need": f"N-{nid}",
                                                                 "why": "A plan change replaced it."})
        self.assertFalse(error, said)
        self.assertIn(f"Withdrew N-{nid}", said)
        row = hub.q1("SELECT * FROM needs WHERE id=?", (nid,))
        self.assertEqual((row["answer"], row["answered_by"]), ("Withdrawn by manager: A plan change replaced it.",
                                                               "manager"))
        self.assertIsNotNone(row["answered"])
        self.assertNotIn(nid, self.open_ids())                  # it left Needs you, as an answered item does
        self.assertEqual(self.notices(), told)                  # and nothing rang
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE kind='say'")["n"], 0)   # nobody waits on it
        self.assertTrue(hub.q1("SELECT 1 FROM log WHERE agent='manager' AND what LIKE ?", (f"withdrew N-{nid} %",)))

    def test_it_needs_a_reason(self):
        nid = self.raise_item()
        self.refused({"need": f"N-{nid}"}, "Say in why")
        self.refused({"need": f"N-{nid}", "why": "   "}, "Say in why")
        self.assertIn(nid, self.open_ids())

    def test_only_an_open_item_of_its_own(self):
        self.refused({"need": "N-99", "why": "Gone."}, "There is no Needs-you item N-99.")
        theirs = self.item(40, by="vps", kind="secret", secret=json.dumps({"kind": "api_key", "tasks": []}))
        self.refused({"need": f"N-{theirs}", "why": "Not needed."}, "only the agent that raised an item withdraws it")
        nid = self.raise_item()
        self.assertFalse(hub.call_tool("manager", "withdraw_need", {"need": f"N-{nid}", "why": "Fixed."})[1])
        self.refused({"need": f"N-{nid}", "why": "Again."}, f"N-{nid} is closed already: Withdrawn by manager: Fixed.")

    def test_an_item_that_others_wait_on_closes_their_way(self):
        asked = self.item(41, question=7)
        self.refused({"need": f"N-{asked}", "why": "Settled."}, "Answer Q-7 with answer instead")
        talk = self.item(42, conversation=3)
        self.refused({"need": f"N-{talk}", "why": "Settled."}, "the person waits for its answer")
        task = hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES(?,?,?,?,?)",
                       ("Deploy the fix", "vps", "manager", "input-required", hub.now()))
        key = self.item(43, kind="secret", secret=json.dumps({"kind": "api_key", "tasks": [task]}))
        self.refused({"need": f"N-{key}", "why": "Settled."}, f"T-{task} wait on N-{key}")
        hub.DB.execute("UPDATE tasks SET state='canceled' WHERE id=?", (task,))
        hub.DB.commit()
        self.assertFalse(hub.call_tool("manager", "withdraw_need", {"need": f"N-{key}", "why": "Its task ended."})[1])
        self.assertEqual([n for n in self.open_ids() if n in (asked, talk, key)], [asked, talk])

    def test_a_login_in_the_reason_is_refused(self):
        nid = self.raise_item()
        login, salt = "correct-horse-battery-staple-42", "synthetic-salt"
        hub.ins("INSERT INTO secrets(salt,hash,len) VALUES(?,?,?)",
                (salt, hashlib.sha256((salt + login).encode()).hexdigest(), len(login)))
        self.refused({"need": f"N-{nid}", "why": f"The key {login} works now."}, "Blocked")
        self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"])

    def test_only_the_manager_has_it_and_its_rules_name_it(self):
        self.assertIn("withdraw_need", [t["name"] for t in hub.tools_for("manager")])
        self.assertNotIn("withdraw_need", [t["name"] for t in hub.tools_for("vps", ("vps", "T-1", "1"))])
        with open("rules/manager.md") as f:     # the manager's start names the brief's rules file; the brief stays short
            rules = f.read()
        self.assertIn("close it at once with `withdraw_need`", rules)
        self.assertIn("The manager has twenty-three of its own", rules)    # door_rollout, door_hold, door_gitops

    def test_the_answer_of_a_raise_names_it(self):
        said = hub.t_raise_needs_you("manager", {"title": "Revoke the old shared key?", "why": "The new keys work.",
                                                 "what_to_do": "Say yes or no"})
        self.assertIn("If nothing needs it any more before the owner answers, close it at once with withdraw_need.",
                      said)

    def test_the_raise_tool_says_read_before_you_raise(self):
        described = next(t["description"] for t in hub.tools_for("manager") if t["name"] == "raise_needs_you")
        self.assertIn("Read before you raise", described)
        self.assertIn("why says how old that reading is", described)
        self.assertIn("withdraw_need closes it", described)


class AcceptNamesItems(Withdraw):
    """The owner, 11 November 2026: a card asked him to install two scripts as root that the business's DevOps agent
    had installed hours before ("why can't devops agent do that? that is the point of having it!"). The manager had
    accepted that result and never answered the question that the card took to him. Now an accept names the manager's
    open items of the same goal, and the answer of a raise says to answer the question when an agent does the work."""

    def setUp(self):
        super().setUp()
        hub.TEAM["agents"]["vps"]["can"] = ["shell"]         # a session with the Shell box off asks nobody

    def goal(self, title):
        """A goal as update_goal writes it down from the owner's words: no limits."""
        t0, limits = hub.now(), json.dumps({"money": None, "tokens": None, "deadline": None, "not_to_do": []})
        return hub.ins("INSERT INTO goals(title,text,state,revision,limits,created,updated,request_id) "
                       "VALUES(?,?,'active',1,?,?,?,?)", (title, title, limits, t0, t0, str(uuid.uuid4())))

    def task(self, goal=None, title="Work"):
        said, error = hub.call_tool("manager", "create_task", dict(
            {"owner": "vps", "title": title, "done_when": "Done.", "why": "It suits it."},
            **({"goal": f"G-{goal}"} if goal else {})))
        self.assertFalse(error, said)
        return hub.q1("SELECT MAX(id) id FROM tasks")["id"]

    def blocked(self, goal):
        """A task of `goal` whose question went to the manager, and the item that takes it to the owner."""
        tid = self.task(goal, "Deploy with the App's login")
        attempt = hub.q1("SELECT attempt FROM tasks WHERE id=?", (tid,))["attempt"]
        said, error = hub.call_tool("vps", "ask_my_requester", {"question": "Who installs the two scripts as root?"},
                                    ("test-generation", f"T-{tid}", str(attempt)))
        self.assertFalse(error, said)
        qid = hub.q1("SELECT MAX(id) id FROM questions")["id"]
        said, error = hub.call_tool("manager", "raise_needs_you", {
            "title": "Install the two deploy scripts as root", "why": "No agent of the team has a root shell there.",
            "what_to_do": "Install them, then answer", "question_id": f"Q-{qid}"})
        self.assertFalse(error, said)
        self.assertIn(f"If an agent does the work first, answer Q-{qid} yourself with what was done", said)
        return qid, hub.q1("SELECT MAX(id) id FROM needs")["id"]

    def accept(self, tid):
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (tid,))     # its owner delivered it
        said, error = hub.call_tool("manager", "check_result", {"task_id": f"T-{tid}", "accepted": True})
        self.assertFalse(error, said)
        return said

    def test_an_accept_names_the_open_item_of_its_goal_until_the_question_is_answered(self):
        goal = self.goal("Deploy with the App's login")
        qid, nid = self.blocked(goal)
        done = self.task(goal, "Install the two scripts as root through the door")
        said = self.accept(done)
        self.assertTrue(said.startswith(f"T-{done} accepted. Your Needs-you items about G-{goal} are still open: "
                                        f"N-{nid} \"Install the two deploy scripts as root\", which takes Q-{qid} to "
                                        f"the owner."), said)
        self.assertIn("answer its question now with what was done: the item then closes by itself", said)
        # the manager answers with what was done, and the item leaves Needs you with no word from the owner
        said, error = hub.call_tool("manager", "answer", {"question_id": f"Q-{qid}",
                                                          "text": "The DevOps agent installed both; sums match."})
        self.assertFalse(error, said)
        self.assertNotIn(nid, self.open_ids())
        more = self.task(goal, "One more step")
        self.assertEqual(self.accept(more), f"T-{more} accepted.")

    def test_an_accept_names_no_item_of_another_goal_no_plain_item_and_nothing_on_a_refusal(self):
        mine, other = self.goal("Deploy with the App's login"), self.goal("Retire the test copies")
        self.blocked(other)
        self.raise_item()                                         # no question, so no goal: the rules close it
        done = self.task(mine)
        self.assertEqual(self.accept(done), f"T-{done} accepted.")
        loose = self.task()                                       # a task with no goal names nothing
        self.assertEqual(self.accept(loose), f"T-{loose} accepted.")
        theirs = self.task(other)                                 # a refusal in the goal that has the item
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (theirs,))
        said, error = hub.call_tool("manager", "check_result", {"task_id": f"T-{theirs}", "accepted": False,
                                                                "note": "The sums differ."})
        self.assertFalse(error, said)
        self.assertIn(f"T-{theirs} not accepted.", said)
        self.assertNotIn("Needs-you", said)

    def test_the_manager_s_rules_say_to_answer_the_question(self):
        with open("rules/manager.md") as f:
            self.assertIn("When an agent does that work first, answer the question yourself with what was done",
                          f.read())


if __name__ == "__main__":
    unittest.main()

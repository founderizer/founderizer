"""The owner's plan of 6 November 2026, B1 and B2: the manager withdraws a Needs-you item of its own that nothing needs
any more, and reads before it raises. A withdrawn item leaves Needs you with no notification and keeps its reason. And
the owner's "Yes, build it" of 17 November 2026: the hub names each open item to the manager again (SecondLook). An
in-process hub with the owner API's harness; no fleet, no network and no AI call."""
import hashlib
import json
import unittest
import uuid
from unittest.mock import patch

import hub
import ops
from test_ui_api import OwnerAPI


def load_tests(loader, _tests, _pattern):
    """Only this file's checks: the harness comes from OwnerAPI, its own tests stay in its own file."""
    suite = unittest.TestSuite()
    for case in (Withdraw, AcceptNamesItems, SecondLook):
        suite.addTests(case(name) for name in case.__dict__ if name.startswith("test_"))
    return suite


class Withdraw(OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM["agents"]["vps"] = {"role": "worker", "runtime": "claude", "machine": "vps", "can": []}

    def raise_item(self, title="Revoke the old shared key?"):
        said = hub.t_raise_needs_you("manager", {"title": title, "why": "The three new keys work.",
                                                 "what_to_do": "Say yes or no", "reason": "person"})
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

    def pings(self):
        return [(r["kind"], r["item"]) for r in hub.q("SELECT kind, item FROM pings ORDER BY id")]

    def test_the_manager_withdraws_its_own_item_silently_unless_it_answers_the_owners_message(self):
        """A withdrawn item leaves Needs you with no notification. Owner API 1.316, feature need_updates (the owner, 22
        November 2026, "Yes" to his phone ringing when the agent closes a card after his message): a close of a card
        whose newest word is his message under it answers that message, so its reason is the manager's reply under
        the card, which rings and notifies as a reply does. Bug: his question under a card gets no answer when the
        card closes, or a plain withdraw rings his phone."""
        hub.TEAM["owner_devices"] = {"iphone": {"label": "iPhone", "address": "127.0.0.9"}}
        hub.q("INSERT INTO owner_device_push(device,token,environment,updated) VALUES('iphone',?, 'production',?)",
              ("ab" * 32, hub.now()))
        nid = self.raise_item()
        self.assertIn(nid, self.open_ids())
        told, rang = self.notices(), self.pings()
        said, error = hub.call_tool("manager", "withdraw_need", {"need": f"N-{nid}",
                                                                 "why": "A plan change replaced it."})
        self.assertFalse(error, said)
        self.assertIn(f"Withdrew N-{nid}. It left the owner's Needs you with no notification", said)
        row = hub.q1("SELECT * FROM needs WHERE id=?", (nid,))
        self.assertEqual((row["answer"], row["answered_by"]), (f"Withdrawn by {hub.shown_role('manager')}: A plan change replaced it.",
                                                               "manager"))
        self.assertIsNotNone(row["answered"])
        self.assertNotIn(nid, self.open_ids())                  # it left Needs you, as an answered item does
        self.assertEqual((self.notices(), self.pings()), (told, rang))      # and nothing rang
        self.assertEqual(hub.need_talk(nid), [])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE kind='say'")["n"], 0)   # nobody waits on it
        self.assertTrue(hub.q1("SELECT 1 FROM log WHERE agent='manager' AND what LIKE ?", (f"withdrew N-{nid} %",)))
        # his message under a card: the close answers it
        asked = self.raise_item("Pay for the DataFast key?")
        hub.need_talk_said({"need": asked, "text": "we're no longer using datafast, it can be removed"})
        told, rang = self.notices(), self.pings()
        self.refused({"need": f"N-{asked}", "why": "T-12 took DataFast out."}, "say T-12 in plain words")
        self.assertIn(asked, self.open_ids())                   # a refusal closes nothing
        said, error = hub.call_tool("manager", "withdraw_need", {"need": f"N-{asked}", "why": "DataFast is out of the "
                                                                 "site, so no key is needed."})
        self.assertFalse(error, said)
        # true also in a fleet with no phone: the Mac's notice always goes, a ring only to an enrolled phone
        self.assertIn("your reason stands under the card as your answer to their message there; the owner is notified "
                      "of it.", said)
        row = hub.q1("SELECT * FROM needs WHERE id=?", (asked,))
        self.assertEqual(row["answer"], f"Withdrawn by {hub.shown_role('manager')}: DataFast is out of the site, so "
                                        f"no key is needed.")
        self.assertEqual([(t["who"], t["text"], t["ts"]) for t in hub.need_talk(asked)][1:],
                         [("manager", "DataFast is out of the site, so no key is needed.", row["answered"])])
        reply = hub.q1("SELECT id FROM need_talk WHERE need=? AND who='manager'", (asked,))["id"]
        self.assertEqual((self.notices(), self.pings()), (told + 1, rang + [("talk", reply)]))
        # the apps of today draw an answered card's talk and then its answer: the view's answer leaves out the reason
        # that stands under the card already, so they show it once (the stored answer above stays whole)
        shown = {n["id"]: n["answer"] for n in self.request()[1]["needs"]}
        self.assertEqual((shown[asked], shown[nid]), (f"Withdrawn by {hub.shown_role('manager')}",
                                                      f"Withdrawn by {hub.shown_role('manager')}: A plan change "
                                                      f"replaced it."))
        # a rename of the manager moves need_talk.who but not needs.answered_by: the reason still shows once
        hub.q("UPDATE need_talk SET who='chief' WHERE who='manager'")
        shown = {n["id"]: n["answer"] for n in self.request()[1]["needs"]}
        self.assertEqual(shown[asked], f"Withdrawn by {hub.shown_role('manager')}")
        self.assertEqual(hub.q1("SELECT text FROM events WHERE agent='owner' AND kind='notify' ORDER BY id DESC")
                         ["text"], f"{hub.shown_role('manager')} replied about: Pay for the DataFast key?")
        # a new version answered his message, which it took along: its close later is silent again
        old = self.raise_item("Add prepaid X credits?")
        hub.need_talk_said({"need": old, "text": "how much each month?"})
        new = int(hub.t_raise_needs_you("manager", {"title": "Add $20 of X credits?", "why": "About $20 a month.",
                                                    "what_to_do": "Say yes or no", "reason": "person",
                                                    "replaces": f"N-{old}"}).split("N-")[1].split(".")[0])
        told, rang = self.notices(), self.pings()
        self.assertFalse(hub.call_tool("manager", "withdraw_need", {"need": f"N-{new}", "why": "X dropped it."})[1])
        self.assertEqual(([t["who"] for t in hub.need_talk(new)], self.notices(), self.pings()),
                         (["owner"], told, rang))

    def test_it_needs_a_reason(self):
        nid = self.raise_item()
        self.refused({"need": f"N-{nid}"}, "Say in why")
        self.refused({"need": f"N-{nid}", "why": "   "}, "Say in why")
        self.assertIn(nid, self.open_ids())

    def test_only_an_open_item_of_its_own(self):
        self.refused({"need": "N-99", "why": "Gone."}, "There is no Needs-you item N-99.")
        theirs = self.item(40, by="vps")
        self.refused({"need": f"N-{theirs}", "why": "Not needed."}, "only the agent that raised an item withdraws it")
        nid = self.raise_item()
        self.assertFalse(hub.call_tool("manager", "withdraw_need", {"need": f"N-{nid}", "why": "Fixed."})[1])
        self.refused({"need": f"N-{nid}", "why": "Again."}, f"N-{nid} is closed already: Withdrawn by {hub.shown_role('manager')}: Fixed.")

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

    def test_another_agents_key_request_that_no_task_waits_on_is_the_managers_to_close(self):
        """The owner, 17 November 2026: a key request from an agent's chat waited ten days for nothing, and only he
        could close it. The manager closes it now, the owner hears nothing, and the hub writes the agent nothing, because
        its owner chat would not read it: the manager tells it with message_agent."""
        chat = self.item(44, by="vps", kind="secret", title="Enter the API key ACME_TOKEN",
                         secret=json.dumps({"kind": "api_key", "env": "ACME_TOKEN", "reply": str(uuid.uuid4())}))
        task = hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES(?,?,?,?,?)",
                       ("Push the images", "vps", "manager", "input-required", hub.now()))
        waited = self.item(45, by="vps", kind="secret",
                           secret=json.dumps({"kind": "api_key", "env": "ACME_PUSH_TOKEN", "tasks": [task]}))
        self.refused({"need": f"N-{waited}", "why": "Not needed."}, f"T-{task} wait on N-{waited}")
        told, written = self.notices(), hub.q1("SELECT COUNT(*) n FROM events WHERE agent='vps'")["n"]
        said, error = hub.call_tool("manager", "withdraw_need", {"need": f"N-{chat}", "why": "The work found a route"})
        self.assertFalse(error, said)
        self.assertIn("vps is not told: tell it with message_agent when its work should know.", said)
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (chat,))["answer"],
                         f"Withdrawn by {hub.shown_role('manager')}: The work found a route")
        self.assertEqual((self.notices(), hub.q1("SELECT COUNT(*) n FROM events WHERE agent='vps'")["n"]),
                         (told, written))
        self.assertEqual([n for n in self.open_ids() if n in (chat, waited)], [waited])
        with open("rules/manager.md") as f:
            self.assertIn("also another agent's key or login request that no task waits on, after you ask that agent "
                          "with `message_agent`", f.read())

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
        # since owner API 1.316 a close that answers the owner's message under the card rings: no "no notification"
        self.assertIn("close it at once with `withdraw_need`: it leaves Needs you and keeps your reason", rules)
        self.assertIn("The manager has twenty-six of its own", rules)    # ..., door_fleet, switch_key_site, change_team

    def test_the_answer_of_a_raise_names_it(self):
        said = hub.t_raise_needs_you("manager", {"title": "Revoke the old shared key?", "why": "The new keys work.",
                                                 "what_to_do": "Say yes or no", "reason": "person"})
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
            "what_to_do": "Install them, then answer", "question_id": f"Q-{qid}",
            "reason": "access", "needs_access": "a root shell on that server"})
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


class SecondLook(Withdraw):
    """The owner, 17 November 2026: "does the manager or the Needs You task owner review it from time to time, in case
    it can be closed or there is any new info on it?" Nothing did, then "Yes, build it". The hub names each open item
    to the manager again, with what it knows of it now, and closes an agent's own chat request once it holds the key."""
    DAY = 86400
    T = 1_800_000_000                   # 15 Jan 2027, 08:00 UTC
    HOLD = "the door holds web-1: parts (Plan step 9: the old keys are still on it) in 0123456789ab"
    HELD = ("The door holds web-1 out of its hosts since 5 Jan 2027: Plan step 9: the old keys are still on it. While "
            "that hold stands, no agent gets web-1 through the door, whatever Tailscale tag it carries: only the manager "
            "ends it, with door_hold web-1 none, once its reason is gone.")

    def looks(self):
        return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id")
                if r["text"].startswith("[hub] A second look at the owner's open cards.")]

    def sweep(self, t0):
        hub.need_look_sweep(t0)
        return self.looks()

    def hold(self):
        hub.TEAM["door"] = {"holds": {"web-1": "parts"}}
        hub.ins(hub.LOG, (self.T - 10 * self.DAY, "manager", self.HOLD))

    def test_an_open_item_comes_back_after_a_day_then_after_longer_waits(self):
        nid = self.item(50, title="Scan the picture again", raised=self.T)
        self.assertEqual(self.sweep(self.T + self.DAY - 3600), [])
        self.assertEqual(len(self.sweep(self.T + self.DAY)), 1)
        self.assertIn(f'- N-{nid} "Scan the picture again", yours, open 1 day.', self.looks()[0])
        self.assertEqual(len(self.sweep(self.T + self.DAY + 120)), 1)          # one look, not one at each pass
        at, count = self.T + self.DAY, 1
        for gap in (2, 4, 7, 7):
            self.assertEqual(len(self.sweep(at + gap * self.DAY - 120)), count)
            at, count = at + gap * self.DAY, count + 1
            self.assertEqual(len(self.sweep(at)), count)
        self.assertIn(f'- N-{nid} "Scan the picture again", yours, open 21 days.', self.looks()[-1])
        hub.need_look_sweep(at - 7200)                                          # a clock set back two hours
        self.assertEqual(float(hub.kv_get("need_look_sweep_at")), at - 7200)    # runs: no pause
        self.assertEqual(json.loads(hub.kv_get("need_looks"))[str(nid)][0], at - 7200)  # no look ahead
        hub.need_look_sweep(at - 7170)                                          # once a minute at most
        self.assertEqual(float(hub.kv_get("need_look_sweep_at")), at - 7200)
        hub.q("UPDATE needs SET answer='Done', answered=? WHERE id=?", (at, nid))
        self.assertEqual(len(self.sweep(at + 8 * self.DAY)), count)             # an answered item is not named
        self.assertIsNone(hub.kv_get("need_looks"))

    def test_the_look_says_how_each_item_closes_and_what_the_hub_knows_of_it(self):
        self.hold()
        task = hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES(?,?,?,?,?)",
                       ("Push the images", "vps", "manager", "input-required", self.T))
        old = self.T - 3 * self.DAY
        asked = self.item(51, question=7, raised=old)
        chat = self.item(52, by="vps", kind="secret", raised=old, title="Enter the API key ACME_TOKEN",
                         secret=json.dumps({"kind": "api_key", "env": "ACME_TOKEN", "reply": str(uuid.uuid4())}))
        waited = self.item(53, by="vps", kind="secret", raised=old, title="Enter the API key ACME_PUSH_TOKEN",
                           secret=json.dumps({"kind": "api_key", "env": "ACME_PUSH_TOKEN", "tasks": [task]}))
        door = self.item(54, raised=old, title="Put the server behind the door", why="The door does not reach web-1.")
        talk = self.item(55, conversation=3, raised=old, title="A person's question")
        saved = self.item(56, kind="secret", raised=old, title="Enter the API key ACME_DOOR_KEY",
                          secret=json.dumps({"kind": "api_key", "env": "ACME_DOOR_KEY", "door": "acme:one"}))
        renewal = self.item(59, raised=old, title="Make a new private key", github_key="acme")
        swap = self.item(44, raised=old, title="Switch on the key swap on web-2?", key_swap_server="web-2")
        phone = self.item(43, raised=old, title="Scan the picture again", add_device=1)
        ended = hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES(?,?,?,?,?)",
                        ("Install the fix", "vps", "manager", "completed", old))
        yes = self.item(48, raised=old, title="Run one root script on web-10?", door_task_id=ended, door_host="web-10")
        live = self.item(45, raised=old, title="Run one root script on web-11?", door_task_id=task, door_host="web-11")
        pooled = self.item(47, by="vps", kind="secret", raised=old, title="Enter the API key ACME_POOL_TOKEN",
                           secret=json.dumps({"kind": "api_key", "env": "ACME_POOL_TOKEN", "reply": str(uuid.uuid4())}))
        tasked = self.item(46, by="vps", kind="secret", raised=old, title="Enter the API key ACME_POOL_TOKEN",
                           secret=json.dumps({"kind": "api_key", "env": "ACME_POOL_TOKEN", "tasks": [task]}))
        soon = self.item(57, raised=self.T - self.DAY + 6 * 3600, title="Made yesterday")
        later = self.item(58, raised=self.T - 3600, title="Made an hour ago")
        ref, pool = "bws://11111111-2222-3333-4444-555555555555", "bws://11111111-2222-3333-4444-666666666666"
        hub.TEAM["logins"] = {ref: {"kind": "api_key", "env": "ACME_DOOR_KEY", "title": "ACME_DOOR_KEY"},
                              pool: {"kind": "api_key", "env": "ACME_POOL_TOKEN", "title": "ACME_POOL_TOKEN"}}
        hub.TEAM["resources"] = {f"secret:{k}": {"max": "use", "to": "workers"} for k in (pool, ref)}   # a door key too
        said = self.sweep(self.T)
        self.assertEqual(len(said), 1)
        for line in (f'- N-{asked} "An item", yours, open 3 days: it takes Q-7 to the owner: when the work has '
                     f'settled it, answer Q-7 and the card closes.',
                     f'- N-{chat} "Enter the API key ACME_TOKEN", vps\'s key request from its chat, open 3 days: no '
                     f'task waits on it: ask vps with message_agent whether its work still needs it, and if not, '
                     f'withdraw_need closes it.',
                     f'- N-{waited} "Enter the API key ACME_PUSH_TOKEN", vps\'s key request, open 3 days: T-{task} '
                     f'wait on it: it closes with them, or with the owner\'s answer.',
                     f'- N-{door} "Put the server behind the door", yours, open 3 days: {self.HELD}',    # at a sentence's end
                     f'- N-{saved} "Enter the API key ACME_DOOR_KEY", yours, open 3 days: the fleet\'s list holds '
                     f'ACME_DOOR_KEY already, as {ref}: the owner can answer the card with that key and type nothing.',
                     f'- N-{pooled} "Enter the API key ACME_POOL_TOKEN", vps\'s key request from its chat, open 3 '
                     f'days: no task waits on it: ask vps with message_agent whether its work still needs it, and if '
                     f'not, withdraw_need closes it; the fleet\'s list holds ACME_POOL_TOKEN already, as {pool}, in the '
                     f'grantable pool: grant_access gives it, with no step of the owner\'s; then tell vps with '
                     f'message_agent, and the hub closes the card an hour later.',
                     f'- N-{tasked} "Enter the API key ACME_POOL_TOKEN", vps\'s key request, open 3 days: T-{task} wait '
                     f'on it: it closes with them, or with the owner\'s answer; the fleet\'s list holds ACME_POOL_TOKEN '
                     f'already, as {pool}: the owner can answer the card with that key and type nothing.',  # no grant
                     # releases a waiting task (round 2 of the reviews)
                     f'- N-{yes} "Run one root script on web-10?", yours, open 3 days: the task that asked for the '
                     f'door\'s yes, T-{ended}, has ended.',                  # web-10 is not web-1: no hold words
                     f'- N-{live} "Run one root script on web-11?", yours, open 3 days.',     # its task goes on
                     f'- N-{soon} "Made yesterday", yours, open 18 hours.'):
            self.assertIn(line + "\n", said[0] + "\n")          # each one whole, up to its line's end
        for nid in (talk, renewal, swap, phone):    # a person waits on it; or only the hub or the phone closes it
            self.assertNotIn(f"N-{nid} ", said[0])
        self.assertNotIn(f"N-{later} ", said[0])                # due in 23 hours: it comes at its own look
        hub.q("UPDATE tasks SET state='canceled' WHERE id=?", (task,))
        self.assertIn(f'- N-{waited} "Enter the API key ACME_PUSH_TOKEN", vps\'s key request, open 10 days: no task '
                      f'waits on it: ask vps', self.sweep(self.T + 7 * self.DAY)[-1])   # an ended task waits on nothing

    def test_a_chat_request_closes_when_its_agent_has_held_what_it_asks_for_a_while(self):
        """An hour, because the owner's own answer in the app gives the key a moment before it answers the card, and
        that answer must not find the card closed (both reviews of 17 November 2026). A chat request for a new value
        of a key that the agent holds (failed) never closes so: the agent holds the old value, which fails, and a
        close "given another way" an hour later drops the owner's card for it."""
        ref, other, login = ("bws://22222222-3333-4444-5555-666666666666", "bws://22222222-3333-4444-5555-777777777777",
                             "bws://22222222-3333-4444-5555-888888888888")
        spec = {"kind": "api_key", "env": "ACME_TOKEN"}
        chat = self.item(60, by="vps", kind="secret", raised=self.T,
                         secret=json.dumps(dict(spec, reply=str(uuid.uuid4()))))
        task = hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES(?,?,?,?,?)",
                       ("Push the images", "vps", "manager", "input-required", self.T))
        waited = self.item(61, by="vps", kind="secret", raised=self.T, secret=json.dumps(dict(spec, tasks=[task])))
        door = self.item(62, by="vps", kind="secret", raised=self.T, secret=json.dumps(dict(spec, door="acme:one")))
        site = self.item(63, by="vps", kind="secret", raised=self.T, secret=json.dumps(
            {"kind": "login", "site": "https://shop.example.com/login", "reply": str(uuid.uuid4())}))
        # another account of that site, and its own login whose password no longer works: neither one is held
        named, failed = (self.item(nid, by="vps", kind="secret", raised=self.T, secret=json.dumps(
            dict({"kind": "login", "site": "https://shop.example.com/login", "reply": str(uuid.uuid4())}, **more)))
            for nid, more in ((64, {"account": "kim"}), (65, {"account": "Sam", "failed": login})))
        renew = self.item(66, by="vps", kind="secret", raised=self.T,
                          secret=json.dumps(dict(spec, failed=ref, reply=str(uuid.uuid4()))))
        hub.TEAM["logins"] = {ref: {"kind": "api_key", "env": "ACME_TOKEN", "title": "ACME_TOKEN"},
                              other: {"kind": "api_key", "env": "ACME_OTHER_TOKEN", "title": "ACME_OTHER_TOKEN"},
                              login: {"kind": "login", "title": "admin.example.com · sam"}}
        hub.TEAM["agents"]["vps"]["secrets"] = {other: "use", login: "use"}     # another name, another site
        mine = (chat, waited, door, site, named, failed, renew)
        for t0 in (self.T + 60, self.T + 60 + 2 * hub.NEED_HELD_WAIT):
            hub.need_look_sweep(t0)
            self.assertEqual([n for n in self.open_ids() if n in mine], list(mine))
        t0 = self.T + 3 * hub.NEED_HELD_WAIT
        hub.TEAM["agents"]["vps"]["secrets"] = {other: "use", ref: "use"}    # the owner gave it on the Secrets page
        hub.kv_set("need_held", json.dumps({str(chat): t0 + 3 * 3600}))     # seen while the clock ran 3 hours fast
        hub.TEAM["logins"][login]["title"] = "shop.example.com · sam"
        hub.TEAM["agents"]["vps"]["secrets"][login] = "use"
        told = self.notices()
        hub.need_look_sweep(t0)
        hub.need_look_sweep(t0 + hub.NEED_HELD_WAIT - 60)
        self.assertEqual([n for n in self.open_ids() if n in mine], list(mine))     # the owner's answer may still come
        hub.need_look_sweep(t0 + hub.NEED_HELD_WAIT)
        row = hub.q1("SELECT * FROM needs WHERE id=?", (chat,))
        self.assertEqual((row["answer"], row["answered_by"]),
                         (f"Closed by the hub: {hub.shown_role('vps')} holds the API key ACME_TOKEN now, given another way.",
                          hub.NEED_CLOSED_BY))
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (site,))["answer"],
                         f"Closed by the hub: {hub.shown_role('vps')} holds a login for shop.example.com now, given another way.")
        self.assertEqual([n for n in self.open_ids() if n in mine], [waited, door, named, failed, renew])
        self.assertEqual(self.notices(), told)
        self.assertIsNone(hub.kv_get("need_held"))
        self.assertIn(f"[hub] The hub closed N-{chat} (vps: the API key ACME_TOKEN), N-{site} (vps: a login for "
                      f"shop.example.com) on the owner's Needs you: the agent that asked holds it now, given another "
                      f"way. When that agent's chat waits on it to start its work, tell it with message_agent.",
                      [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say'")])
        self.assertEqual(json.loads(hub.q1("SELECT extra FROM events WHERE agent='manager' AND kind='say' AND text LIKE '[hub] The hub closed%'")["extra"]), hub.LATER_SAY)     # it waits for the next read, an hour at most

    def test_the_manager_s_see_team_lists_each_door_hold_with_its_day_and_its_reason(self):
        """On 19 November 2026 the manager wrote that it held no hold on a server that its own rule-only hold of 6
        November kept from the agents' own calls: no tool showed it its holds. Its see_team lists them now, and a
        hold that ends leaves the list."""
        hub.TEAM["door"] = {"address": "100.64.0.9", "holds": {"web-1": "judged", "web-2": "parts"}}
        hub.ins(hub.LOG, (self.T, "manager", "the door holds web-1: judged (Plan step 2.17: old keys) in a1b2c3d"))
        hub.ins(hub.LOG, (self.T, "manager", self.HOLD.replace("web-1", "web-2")))
        text, err = hub.call_tool("manager", "see_team", {})
        self.assertFalse(err, text)
        self.assertTrue(text.endswith("\nDOOR HOLDS (yours: door_hold <server> none ends one, once its reason is gone)\n"
                                      "  web-1: rule-only since 15 Jan 2027: Plan step 2.17: old keys\n"
                                      "  web-2: out of the door since 15 Jan 2027: Plan step 9: the old keys are still "
                                      "on it"), text)
        self.assertNotIn("DOOR HOLDS", hub.overview_text(hub.OWNER_VIEW))         # the owner's board shows no line of it
        del hub.TEAM["door"]["holds"]["web-1"]                      # door_hold web-1 none
        self.assertNotIn("web-1:", hub.call_tool("manager", "see_team", {})[0])
        del hub.TEAM["door"]["holds"]                               # and the last one
        self.assertNotIn("DOOR HOLDS", hub.call_tool("manager", "see_team", {})[0])

    def test_a_refusal_for_a_held_server_leads_to_words_that_name_the_hold(self):
        """ops sends an agent that the door refused for no host to its requester with needs_access server:<host>, and
        the hub's route for that ask names the hold, which only the manager ends: no Tailscale step of the owner's."""
        self.assertEqual(ops.route_line({"route": "none", "why": "web-1 is no host of the door"}, "web-1"),
                         "route: none at the door, which has no host web-1. Check the name first. If it is right, ask "
                         "your requester with ask_my_requester and needs_access server:web-1: the hub names the agent "
                         "that holds it, or the hold that keeps it out of the door.")
        self.assertTrue(ops.route_line({"route": "none", "why": "web-1 is never a target of the door"}, "web-1")
                        .startswith("route: none. No grant and no yes of the owner"))
        self.assertNotIn("The door holds", hub.access_route("vps", "server:web-1", "manager", "fix"))
        # the door's route ask ends somewhere when no hold is why: the holder reads the two other causes, and that no
        # agent changes them, beside its own restart line
        hub.TEAM["agents"]["vps"]["servers"] = {"web-1": "fix"}
        causes = ("If the door refused a call on web-1 as rule-only, no hold of the manager is why. Then web-1 carries a "
                  "second business tag in Tailscale, which keeps a server of two businesses rule-only by design and "
                  "which only the owner changes, or its door install wrote rule-only, which no route of Founderizer "
                  "changes today. No agent changes either: ")
        self.assertIn(causes + "where the rule forms cannot do the work, raise a Needs-you item that names web-1, the "
                      "refused call and these two causes; for the second, the owner can send it to Founderizer with "
                      "Report a problem.", hub.access_route("vps", "server:web-1", "manager", "fix"))
        self.assertIn(causes + "pass the question up with answer(..., pass_up=true).",
                      hub.access_route("vps", "server:web-1", "vps", "fix"))
        # the manager ended a hold a moment ago: the door acts on it until the Mac's next door round, so the line has
        # the change's words, and not the no-hold words, which would be false until then
        with patch.object(hub, "DOOR_HELD", {"at": None}), patch.object(hub, "DOOR_OLD_READS", []):
            hub.door_change_keep("hold:web-1", {})
            line = hub.access_route("vps", "server:web-1", "manager", "fix")
            hub.door_change_keep("hold:web-1", None)
        self.assertIn("The hold of web-1 changed", line)
        self.assertNotIn("no hold of the manager is why", line)
        hub.TEAM["agents"]["vps"]["servers"] = {"web-1": "read"}       # a holder at Read meets no rule-only refusal
        self.assertNotIn("rule-only", hub.access_route("vps", "server:web-1", "manager", "read"))
        del hub.TEAM["agents"]["vps"]["servers"]
        self.hold()
        hub.TEAM["agents"]["vps"]["servers"] = {"web-1": "fix"}         # also an agent that team.json gives it
        for requester, end in (("manager", self.HELD),
                               ("vps", f"{self.HELD} Pass the question up with answer(..., pass_up=true): only the "
                                       f"manager ends the hold.")):
            line = hub.access_route("vps", "server:web-1", requester, "fix")
            self.assertEqual(line, f"ACCESS NEEDED: vps needs the server web-1 (server:web-1) at fix. {end}")
        # rule-only keeps the server in the door, where its holder runs the rule calls: that route stands beside the
        # hold's words, which come before any branch can return (rounds 2 and 3 of the reviews)
        hub.TEAM["door"]["holds"]["web-1"] = "judged"
        hub.TEAM["agents"]["vps"]["servers"] = {}
        hub.TEAM["agents"]["ops1"] = {"role": "worker", "runtime": "claude", "machine": "ops1", "can": [],
                                      "servers": {"web-1": "fix"}}
        hub.ins(hub.LOG, (self.T, "manager", "the door holds web-1: rule-only (Plan step 10: fixed forms only) in a1b2c3d"))
        line = hub.access_route("vps", "server:web-1", "manager", "read")
        self.assertIn("Held now by ops1 (fix): ops1 can do this part of the work", line)
        rule_only = ("The door holds web-1 at rule-only since 15 Jan 2027: Plan step 10: fixed forms only. While that "
                     "hold stands, only the door's rule calls run on web-1, and no call of an agent's own: only the "
                     "manager ends it, with door_hold web-1 none, once its reason is gone.")
        self.assertIn(f" none of it. {rule_only} Held now by", line)
        # The holder itself asks why its own call was refused (19 November 2026): the hold is the whole answer, first,
        # and no restart, which would meet the same hold
        hub.TEAM["agents"]["vps"]["servers"] = {"web-1": "fix"}
        for requester, end in (("manager", ""),
                               ("vps", " Pass the question up with answer(..., pass_up=true): only the manager ends "
                                       "the hold.")):
            self.assertEqual(hub.access_route("vps", "server:web-1", requester, "fix"),
                             f"ACCESS NEEDED: vps needs the server web-1 (server:web-1) at fix. {rule_only} team.json "
                             f"gives it at fix already, so no restart and no grant lets more through while the hold "
                             f"stands.{end}")
        # a hold set before rule-only had its name is in the log as judged: its date and reason still come
        hub.q("DELETE FROM log WHERE what LIKE 'the door holds web-1:%'")
        hub.ins(hub.LOG, (self.T, "manager", "the door holds web-1: judged (Plan step 11: old keys) in a1b2c3d"))
        self.assertIn("The door holds web-1 at rule-only since 15 Jan 2027: Plan step 11: old keys. While",
                      hub.access_route("vps", "server:web-1", "manager", "fix"))


if __name__ == "__main__":
    unittest.main()

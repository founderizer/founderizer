"""Questions go up the line (the owner, 28 October 2026: "Agent -> Lead -> Manager -> Me. if the lowest level can
handle it, that's it!"), and the decisions of 29 October 2026 around it: a lead passes a question up with answer
pass_up and the question moves; the holder and every level that passed it may answer, and the first answer wins; the
manager's last step is raise_needs_you with the question's id, and the owner's answer goes straight back to the asker
on every path he answers by; only the manager and the owner chats write to the owner first, and the work an owner
chat opens comes back into it; start_task opens work under a lead; the manager acts for a lead that cannot. In-process
hub on a temporary database, with the owner API's harness: no helper, no git, no network and no AI call."""
import json
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse
import urllib.request
import uuid

import hub
from test_ui_api import OwnerAPI

OWNER = "127.0.0.1"
CHAT = ("test-generation", "owner-chat", "1")
TEAM = {"addresses": {"owner": OWNER, "hub": "127.0.0.2", "m-x": "127.0.0.3"},     # x's helper polls (OwnerChats)
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   # a lead under the manager, a lead under that lead, and a worker of the second
                   "top": {"role": "lead", "runtime": "claude", "machine": "m-top", "can": ["shell"]},
                   "mid": {"role": "lead", "runtime": "claude", "machine": "m-mid", "can": ["shell"],
                           "reports_to": "top"},
                   "w": {"role": "worker", "runtime": "claude", "machine": "m-w", "can": ["shell"],
                         "reports_to": "mid"},
                   # a worker of the manager, and a lead with one worker
                   "solo": {"role": "worker", "runtime": "claude", "machine": "m-solo", "can": ["shell"]},
                   "lone": {"role": "lead", "runtime": "claude", "machine": "m-lone", "can": ["shell"]},
                   "x": {"role": "worker", "runtime": "claude", "machine": "m-x", "can": ["shell"],
                         "reports_to": "lone"}}}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args):
        return None


class Chain(OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        # top's task, mid's subtask of it, and w's subtask of mid's: three levels of the line
        self.t1 = self.create("manager", "top")
        self.t2 = self.create("top", "mid", self.t1)
        self.t3 = self.create("mid", "w", self.t2)

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

    def create(self, agent, owner, task=None):
        self.ok(agent, "create_task", {"owner": owner, "title": f"Work for {owner}", "done_when": "Done.",
                                       "why": "It suits it."}, task)
        return hub.q1("SELECT MAX(id) id FROM tasks")["id"]

    def ask(self, agent="w", task=None, question="Blue or green?", **extra):
        self.ok(agent, "ask_my_requester", dict({"question": question}, **extra), task or self.t3)
        return hub.q1("SELECT MAX(id) id FROM questions")["id"]

    def question(self, qid):
        return hub.q1("SELECT * FROM questions WHERE id=?", (qid,))

    def task(self, tid):
        return hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))

    def said(self, agent, task=None):
        """The say events of this agent, filed under `task` when it is given."""
        rows = hub.q("SELECT * FROM events WHERE agent=? AND kind='say' ORDER BY id", (agent,))
        return [r["text"] for r in rows if task is None or r["task"] == task]

    def pass_up(self, agent, qid, task, note=None):
        return self.ok(agent, "answer", dict({"question_id": f"Q-{qid}", "pass_up": True},
                                             **({"text": note} if note else {})), task)

    def answer(self, agent, qid, text, task=None):
        return self.call(agent, "answer", {"question_id": f"Q-{qid}", "text": text}, task)

    def turn_ended(self, tid, at):
        """The turn state of a session that ended a turn at `at`, as the helper's records leave it (plan C1)."""
        attempt = self.task(tid)["attempt"]
        hub.q("UPDATE attempts SET turn=? WHERE task=? AND attempt=?",
              (json.dumps({"running": False, "turns": 1, "at": at}), tid, attempt))

    def form(self, path, fields):
        req = urllib.request.Request(self.base + path, data=urllib.parse.urlencode(fields).encode(),
                                     headers={"Content-Type": "application/x-www-form-urlencoded",
                                              "X-Test-Source": OWNER})
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
        try:
            with op.open(req, timeout=5) as response:
                return response.status
        except urllib.error.HTTPError as response:
            with response:
                return response.code

    def raised(self, qid, **extra):
        """The manager's last step for a question that it holds: one Needs-you item linked to it."""
        said = self.ok("manager", "raise_needs_you", dict({"title": "Which colour?", "why": "Only he chose the brand",
                                                           "what_to_do": "Say blue or green", "question_id": f"Q-{qid}"},
                                                          **extra))
        return hub.q1("SELECT * FROM needs ORDER BY id DESC LIMIT 1"), said

    def up_to_manager(self):
        """w asks, mid passes it to top, top passes it to the manager."""
        qid = self.ask()
        self.pass_up("mid", qid, self.t2)
        self.pass_up("top", qid, self.t1)
        return qid


class PassUp(Chain):
    def test_a_lead_passes_a_question_up_and_it_moves_one_level(self):
        qid = self.ask()
        self.assertEqual(self.question(qid)["requester"], "mid")
        said = self.pass_up("mid", qid, self.t2, note="The brand book is not mine.")
        self.assertIn(f"Q-{qid} is with top now", said)
        self.assertIn("your own work goes on", said)
        row = self.question(qid)
        self.assertEqual((row["requester"], json.loads(row["passed"]), row["answer"]), ("top", ["mid"], None))
        # the asker still waits on it; the passer's own task is not paused
        self.assertEqual((self.task(self.t3)["state"], self.task(self.t3)["waiting_on"]),
                         ("input-required", f"Q-{qid}"))
        self.assertNotEqual(self.task(self.t2)["state"], "input-required")
        # top reads it in the session of its own task, T1: filed_under walks up the parent chain
        told = self.said("top", self.t1)[-1]
        self.assertIn(f"Question Q-{qid} from w on T-{self.t3}", told)
        self.assertIn("passed up to you by mid, who adds: The brand book is not mine.", told)
        self.assertIn("It asks: Blue or green?", told)
        self.assertIn(f'pass it up once more with answer(question_id="Q-{qid}", pass_up=true)', told)
        self.assertEqual(hub.filed_under("top", "say", self.t3), self.t1)
        # and see_team of each lead says where it is
        self.assertIn(f"Q-{qid} from w on T-{self.t3}, passed up to you by mid", self.ok("top", "see_team", {}, self.t1))
        self.assertIn("passed up by you: top holds it", self.ok("mid", "see_team", {}, self.t2))

    def test_the_manager_is_the_last_level_and_the_owner_answers_through_it(self):
        qid = self.up_to_manager()
        row = self.question(qid)
        self.assertEqual((row["requester"], json.loads(row["passed"])), ("manager", ["mid", "top"]))
        told = self.said("manager")[-1]
        self.assertIn("passed up to you by top", told)
        self.assertIn(f'raise_needs_you(..., question_id="Q-{qid}")', told)
        self.assertIn(f"Q-{qid} from w on T-{self.t3}, waiting", self.ok("manager", "see_team", {}))
        self.assertIn("passed up by mid, top", self.ok("manager", "see_team", {}))

    def test_what_a_pass_up_refuses(self):
        # a question with a default blocks nobody
        dflt = self.ask(question="Metric?", default="metric")
        self.assertIn("blocks nobody", self.refused("mid", "answer", {"question_id": f"Q-{dflt}", "pass_up": True},
                                                    self.t2))
        qid = self.ask()
        self.pass_up("mid", qid, self.t2)
        # the same agent twice
        self.assertIn("passed Q-%d up already" % qid, self.refused("mid", "answer", {"question_id": f"Q-{qid}",
                                                                                      "pass_up": True}, self.t2))
        self.pass_up("top", qid, self.t1)
        # the manager passes nothing up: its last step is raise_needs_you
        said = self.refused("manager", "answer", {"question_id": f"Q-{qid}", "pass_up": True})
        self.assertIn("raise_needs_you", said)
        self.assertEqual(self.question(qid)["requester"], "manager")
        # an answer needs words, and only a pass up goes without them
        self.assertIn("pass_up=true", self.refused("manager", "answer", {"question_id": f"Q-{qid}"}))

    def test_the_holder_and_the_levels_that_passed_it_answer_and_the_first_answer_wins(self):
        qid = self.up_to_manager()
        # nobody skips a level: a lead outside the chain may not, and neither may the asker's colleague
        self.assertIn("was not asked of you", self.answer("lone", qid, "Green.", self.create("manager", "lone"))[0])
        text, error = self.answer("mid", qid, "Blue, as the logo.", self.t2)      # the first level that passed it
        self.assertFalse(error, text)
        row = self.question(qid)
        self.assertEqual((row["answer"], row["answered_by"]), ("Blue, as the logo.", "mid"))
        self.assertEqual(self.task(self.t3)["state"], "working")
        answer = self.said("w", self.t3)[-1]
        self.assertIn(f"Answer to your question Q-{qid} on T-{self.t3}: Blue, as the logo.", answer)
        self.assertNotIn("answered by", answer)         # mid is the one it asked
        # the holder hears of it, quietly
        quiet = hub.q1("SELECT * FROM events WHERE agent='manager' ORDER BY id DESC LIMIT 1")
        self.assertIn(f"Q-{qid} on T-{self.t3}, which was with you, was answered by mid", quiet["text"])
        self.assertEqual(json.loads(quiet["extra"]), {"quiet": True})
        # an answer holds: the second one is refused, and says who answered first
        said, error = self.answer("manager", qid, "Green.")
        self.assertTrue(error, said)
        self.assertIn("already answered, by mid", said)
        self.assertEqual(self.question(qid)["answer"], "Blue, as the logo.")

    def test_an_answer_from_above_says_who_gave_it(self):
        qid = self.ask()
        self.pass_up("mid", qid, self.t2)
        text, error = self.answer("top", qid, "Green.", self.t1)
        self.assertFalse(error, text)
        self.assertIn(f"Q-{qid} on T-{self.t3}, answered by top: Green.", self.said("w", self.t3)[-1])
        self.assertEqual(hub.history_answer(self.question(qid))[0]["text"], f"Q-{qid} answered by top: Green.")


class NotChased(Chain):
    def test_the_passer_waits_on_the_line_above_and_the_holder_is_chased(self):
        qid = self.ask()
        self.assertFalse(hub.waits_on_parts(self.t2))           # its team waits on mid itself
        self.pass_up("mid", qid, self.t2)
        self.assertTrue(hub.waits_on_parts(self.t2))            # now it is work in progress for mid
        self.assertEqual(hub.live_reason(self.task(self.t2), None), ("parts", "its open subtasks"))
        # top holds it, so top's own silence counts again although its own subtask is working
        self.assertFalse(hub.waits_on_parts(self.t1))
        hub.q("UPDATE events SET read_at=? WHERE agent='top'", (hub.now() + 5,))
        chase = hub.requester_chase("top", hub.now(), task=self.task(self.t1))
        self.assertIsNotNone(chase)
        self.assertIn(f"Q-{qid} on T-{self.t3} waits for your answer", chase[0])
        self.assertIsNone(hub.requester_chase("mid", hub.now(), task=self.task(self.t2)))

    def test_a_lead_s_own_question_of_its_team_still_counts(self):
        prompt = hub.ins("INSERT INTO prompts(task,agent,tool,input,key,created) VALUES(?,?,?,?,?,?)",
                         (self.t3, "w", "Bash", "make deploy", "k1", hub.now()))
        hub.q("UPDATE tasks SET state='input-required', waiting_on=? WHERE id=?", (f"P-{prompt}", self.t3))
        self.assertFalse(hub.waits_on_parts(self.t2))           # a permission prompt is always its lead's


class Needs(Chain):
    def test_the_owner_answers_on_the_app_route_and_the_question_is_answered_with_his_words(self):
        qid = self.up_to_manager()
        need, said = self.raised(qid)
        self.assertEqual(need["question"], qid)
        # owner feature need_talk: the asker's words go behind Details, with its name and no code
        self.assertEqual(need["details"], 'W\'s question, in its own words: "Blue or green?"')
        self.assertNotIn("Quoting", need["why"])
        self.assertIn(f"the owner's answer goes to w as the answer of Q-{qid} by itself", said)
        self.assertEqual(self.item(need["id"])["question"], qid)          # /ui/state carries the link
        code, receipt = self.request(f"/ui/needs/{need['id']}", self.command(answer="Green, always."))
        self.assertEqual(code, 200, receipt)
        row = self.question(qid)
        self.assertEqual((row["answer"], row["answered_by"]), ("Green, always.", "owner"))
        self.assertEqual(self.task(self.t3)["state"], "working")
        self.assertIn(f"Q-{qid} on T-{self.t3}, answered by the owner: Green, always.", self.said("w", self.t3)[-1])
        manager = hub.q1("SELECT text FROM events WHERE id=?", (receipt["event_id"],))["text"]
        self.assertIn(f"The hub gave it to w as the answer to Q-{qid}: do not pass it on again.", manager)

    def test_a_press_of_an_option_answers_the_question_too(self):
        qid = self.up_to_manager()
        need, _ = self.raised(qid, options=["Blue", "Green"])
        code, _receipt = self.request(f"/ui/needs/{need['id']}", {"request_id": str(uuid.uuid4()),
                                                                  "db": "test-generation", "choice": 1})
        self.assertEqual(code, 200)
        self.assertEqual(self.question(qid)["answer"], "Green")

    def test_the_owner_answers_on_the_board_and_the_question_is_answered_too(self):
        qid = self.up_to_manager()
        need, _ = self.raised(qid)
        self.assertEqual(self.form(f"/needs/{need['id']}", {"answer": "Blue."}), 303)
        self.assertEqual(self.question(qid)["answer"], "Blue.")
        self.assertIn("answered by the owner: Blue.", self.said("w", self.t3)[-1])
        self.assertIn(f"The hub gave it to w as the answer to Q-{qid}", self.said("manager")[-1])

    def test_the_item_closes_when_the_question_is_answered_another_way(self):
        qid = self.up_to_manager()
        need, _ = self.raised(qid)
        self.answer("top", qid, "Blue.", self.t1)
        row = hub.q1("SELECT * FROM needs WHERE id=?", (need["id"],))
        self.assertEqual(row["answered_by"], "Fleet")
        self.assertIn(f"Closed: Q-{qid} was answered by top: Blue.", row["answer"])
        # and the owner's late answer is refused, as for every answered item
        code, _ = self.request(f"/ui/needs/{need['id']}", self.command(answer="Green."))
        self.assertEqual(code, 409)
        self.assertEqual(self.question(qid)["answer"], "Blue.")

    def test_the_item_closes_when_the_task_ends(self):
        qid = self.up_to_manager()
        need, _ = self.raised(qid)
        self.ok("mid", "cancel_task", {"task_id": f"T-{self.t3}", "reason": "not needed"}, self.t2)
        row = hub.q1("SELECT * FROM needs WHERE id=?", (need["id"],))
        self.assertEqual(row["answered_by"], "Fleet")
        self.assertIn(f"Closed: T-{self.t3} ended (canceled)", row["answer"])

    def test_the_item_closes_when_a_restart_ends_the_question(self):
        qid = self.up_to_manager()
        need, _ = self.raised(qid)
        self.ok("mid", "restart_task", {"task_id": f"T-{self.t3}", "request_id": str(uuid.uuid4()),
                                        "expected_attempt": 1, "reason": "a fresh session"}, self.t2)
        with hub.LOCK:          # the helper's report of the stop (test_blocked_access.stop_confirmed)
            hold = hub.q1("SELECT * FROM holds WHERE task=? ORDER BY id DESC LIMIT 1", (self.t3,))
            hub.settle_hold(hold, True, "interrupted and closed")
            hub.restart_continue(hold["id"])
        self.assertIn("This question ended when mid restarted", self.question(qid)["answer"])
        row = hub.q1("SELECT * FROM needs WHERE id=?", (need["id"],))
        self.assertEqual(row["answered_by"], "Fleet")
        self.assertIn(f"Closed: mid restarted T-{self.t3}", row["answer"])

    def test_what_raise_needs_you_refuses_for_a_question(self):
        qid = self.ask()
        self.assertIn("is with mid", self.refused("manager", "raise_needs_you", {
            "title": "x", "why": "y", "what_to_do": "z", "question_id": f"Q-{qid}"}))       # nobody skips a level
        self.pass_up("mid", qid, self.t2)
        self.pass_up("top", qid, self.t1)
        self.raised(qid)
        self.assertIn("already takes", self.refused("manager", "raise_needs_you", {
            "title": "x", "why": "y", "what_to_do": "z", "question_id": f"Q-{qid}"}))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs")["n"], 1)

    def item(self, nid):
        code, state = self.request()
        self.assertEqual(code, 200, state)
        return next(n for n in state["needs"] if n["id"] == nid)


class Access(Chain):
    def test_the_restart_hint_goes_to_the_subtask_s_requester(self):
        qid = self.ask(question="May I push?", needs_access="repo:acme/web")
        self.pass_up("mid", qid, self.t2)
        told = self.said("top", self.t1)[-1]
        self.assertIn("ACCESS NEEDED: w needs the GitHub repository acme/web", told)
        self.assertIn("mid, its requester, starts it again with restart_task", told)
        hub.TEAM["agents"]["w"]["repos"] = {"acme/web": "write"}      # the grant, as team.json gives it now
        text, error = self.answer("top", qid, "It is yours now.", self.t1)
        self.assertFalse(error, text)
        self.assertIn("Only mid, which restarts", text)
        hint = self.said("mid", self.t2)[-1]
        self.assertIn(f"Q-{qid} of w on T-{self.t3}", hint)
        self.assertIn(f'restart_task(task_id="T-{self.t3}", expected_attempt=1, ...)', hint)


class ManagerActs(Chain):
    """The manager acts for a lead that cannot: its session's task ended, it lost its authority over the agent below
    it, or it is no lead any more."""

    def test_lead_left(self):
        t3 = self.task(self.t3)
        self.assertFalse(hub.lead_left("mid", t3))
        self.assertFalse(hub.lead_left("manager", t3))
        hub.TEAM["agents"]["w"]["reports_to"] = "top"           # w left mid's team
        self.assertTrue(hub.lead_left("mid", t3))
        hub.TEAM["agents"]["w"]["reports_to"] = "mid"
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (self.t2,))      # mid's session task ended
        self.assertTrue(hub.lead_left("mid", t3))
        hub.q("UPDATE tasks SET state='working' WHERE id=?", (self.t2,))
        hub.TEAM["agents"]["mid"]["role"] = "worker"
        self.assertTrue(hub.lead_left("mid", t3))

    def test_the_manager_answers_decides_checks_and_restarts_for_a_lead_that_cannot(self):
        qid = self.ask()
        prompt = hub.ins("INSERT INTO prompts(task,agent,tool,input,key,created) VALUES(?,?,?,?,?,?)",
                         (self.t3, "w", "Bash", "make deploy", "k1", hub.now()))
        # while mid can act, nobody skips it
        self.assertIn("was not asked of you", self.answer("manager", qid, "Blue.")[0])
        self.assertIn("is for mid to decide", self.refused("manager", "decide_permission",
                                                           {"prompt_id": f"P-{prompt}", "decision": "allow"}))
        self.assertIn("was not requested by you", self.refused("manager", "restart_task", {
            "task_id": f"T-{self.t3}", "request_id": str(uuid.uuid4()), "expected_attempt": 1, "reason": "x"}))
        hub.TEAM["agents"]["w"]["reports_to"] = "top"           # mid lost its authority over w
        team = self.ok("manager", "see_team", {})
        self.assertIn("with mid, which cannot act on it any more: you answer it", team)
        self.assertIn(f"P-{prompt} from w on T-{self.t3}, for mid, which cannot decide it any more", team)
        text, error = self.answer("manager", qid, "Blue.")
        self.assertFalse(error, text)
        self.assertIn("answered by manager: Blue.", self.said("w", self.t3)[-1])
        self.assertIn(f"P-{prompt}: allow", self.ok("manager", "decide_permission",
                                                   {"prompt_id": f"P-{prompt}", "decision": "allow"}))
        self.assertIn("The restart of", self.ok("manager", "restart_task", {
            "task_id": f"T-{self.t3}", "request_id": str(uuid.uuid4()), "expected_attempt": 1,
            "reason": "its lead lost it"}))
        # and its result, which the manager's see_team lists with its own
        hub.q("UPDATE tasks SET state='completed', outcome='completed', what='Painted it.', delivered=? WHERE id=?",
              (hub.now(), self.t3))
        self.assertIn(f"T-{self.t3} [completed]", self.ok("manager", "see_team", {}).split(
            "RESULTS WAITING FOR YOUR CHECK")[1].split("OPEN QUESTIONS")[0])
        self.assertIn("accepted", self.ok("manager", "check_result", {"task_id": f"T-{self.t3}", "accepted": True}))

    def test_a_report_to_a_lead_that_lost_the_agent_is_the_manager_s(self):
        self.ok("w", "report_up", {"kind": "risk", "text": "The cert expires Friday.", "request_id": str(uuid.uuid4())},
                self.t3)
        r = hub.q1("SELECT * FROM reports ORDER BY id DESC LIMIT 1")
        self.assertEqual(r["to_agent"], "mid")
        self.assertFalse(hub.report_for_manager(r))
        hub.TEAM["agents"]["w"]["reports_to"] = "top"
        self.assertTrue(hub.report_for_manager(r))

    def test_what_a_lead_leaves_unread_goes_to_the_manager_before_the_owner(self):
        t0 = hub.now()
        hub.q("UPDATE tasks SET nudge_level=2 WHERE id=?", (self.t3,))
        notice = hub.emit("mid", "say", f"[hub] T-{self.t3} is stuck.", task=self.t3)
        hub.stuck_told(self.t3, notice)
        self.turn_ended(self.t2, t0 + 60)          # mid had a turn after it and left it unread
        with patch.object(hub, "now", lambda: t0 + 120):
            self.assertEqual(hub.tasks_stuck(t0 + 120), [])         # the manager first
            hub.lead_unread_sweep(t0 + 120)
            told = self.said("manager")[-1]
            self.assertIn(f"T-{self.t3} (Work for w, owner w): mid was told that it is stuck", told)
            hub.lead_unread_sweep(t0 + 120)
            self.assertEqual(self.said("manager")[-1], told)            # once for each notice
            self.assertEqual(hub.tasks_stuck(t0 + 120), [])         # the manager has had no turn since
            hub.kv_set("turn_ended:manager", t0 + 200)
            stuck = hub.tasks_stuck(t0 + 300)
        self.assertEqual(len(stuck), 1)
        self.assertIn(f"T-{self.t3}", stuck[0][1])


class OwnerChats(Chain):
    """Only the manager and the owner chats write to the owner first (29 October 2026), and the work that an owner
    chat opens comes back into that chat by itself."""

    def test_message_owner_is_the_manager_s_and_the_owner_chats(self):
        tools = lambda agent, context=None: {t["name"] for t in hub.tools_for(agent, context)}
        self.assertIn("message_owner", tools("manager"))
        self.assertIn("message_owner", tools("w", CHAT))
        self.assertIn("message_owner", tools("mid", CHAT))
        self.assertNotIn("message_owner", tools("w", self.context(self.t3)))
        self.assertNotIn("message_owner", tools("mid", self.context(self.t2)))
        self.assertIn("no tool named message_owner", self.refused("w", "message_owner", {
            "request_id": str(uuid.uuid4()), "text": "Done."}, self.t3))
        self.assertIn("Never contact the owner from here", hub.start_text("w", self.t3))

    def owner_asks(self, agent, text="Please write the release note."):
        body = self.command(recipient=agent, text=text)
        code, receipt = self.request("/ui/messages", body)
        self.assertEqual(code, 200, receipt)
        self.ok(agent, "read_messages", {}, context=CHAT)
        return body["request_id"]

    def test_a_worker_under_a_lead_opens_work_with_its_lead_as_requester_and_the_result_comes_back(self):
        rid = self.owner_asks("x")
        said = self.ok("x", "start_task", {"title": "Write the release note", "done_when": "outputs has it",
                                           "in_reply_to": rid}, context=CHAT)
        t = hub.q1("SELECT * FROM tasks ORDER BY id DESC LIMIT 1")
        batch = self.task(t["parent"])
        self.assertEqual((t["owner"], t["requester"], batch["owner"], batch["requester"]),
                         ("x", "lone", "lone", "manager"))
        self.assertIn("with lone as its requester", said)
        self.assertIn("message_owner", said)
        self.ok("x", "tell_owner", {"in_reply_to": rid, "text": "Opened it; I will tell you when it is done."},
                context=CHAT)          # as start_task's answer says: his message is answered, so it comes no more
        told = [e for e in hub.q("SELECT * FROM events WHERE agent='lone' AND kind='say'")
                if f"opened T-{t['id']}" in e["text"]]
        self.assertEqual((len(told), told[0]["task"], json.loads(told[0]["extra"])), (1, batch["id"], {"quiet": True}))
        self.assertIn("do not pass it on to the owner", told[0]["text"])
        # the same message again is the same task
        self.assertEqual(self.call("x", "start_task", {"title": "Write the release note", "done_when": "outputs has it",
                                                       "in_reply_to": rid}, context=CHAT), (said, False))
        # x delivers in the task's session, and the result comes back into its owner chat by itself
        self.ok("x", "deliver_result", {"outcome": "completed", "what_was_done": "Wrote the note.",
                                        "where_output_is": "outputs/T-1/note.md", "how_checked": "Read it."}, t["id"])
        back = hub.q1("SELECT * FROM events WHERE agent='x' AND kind='chat' ORDER BY id DESC LIMIT 1")
        self.assertEqual(json.loads(back["extra"])["task_result"], t["id"])
        self.assertIn(f"T-{t['id']} (Write the release note), which you opened from the owner's message {rid}",
                      back["text"])
        polled = lambda: [e["id"] for e in self.helper_events("x") if e["kind"] == "chat"]
        self.assertIn(back["id"], polled())                     # the helper tells the chat of it
        read = self.ok("x", "read_messages", {}, context=CHAT)
        self.assertIn("is completed: Wrote the note.", read)
        self.assertNotIn("is completed", self.ok("x", "read_messages", {}, context=CHAT))   # read once
        self.ok("x", "message_owner", {"request_id": str(uuid.uuid4()), "text": "The release note is written."},
                context=CHAT)
        # the final review of 29 October 2026: once read, the poll no longer sends it, so the chat hears the owner's
        # next message (a result sent for ever kept every later line of the helper from being typed)
        self.assertNotIn(back["id"], polled())
        code, _ = self.request("/ui/messages", self.command(recipient="x", text="Thanks. Also check the changelog."))
        self.assertEqual(code, 200)
        nxt = hub.q1("SELECT id FROM events WHERE agent='x' AND kind='chat' ORDER BY id DESC LIMIT 1")["id"]
        self.assertEqual(polled(), [nxt])

    def helper_events(self, agent):
        code, data = self.request(f"/events/{agent}?delivery=1&wait=0", source=hub.address_of(agent))
        self.assertEqual(code, 200, data)
        return data["events"]

    def test_a_worker_of_the_manager_still_opens_work_with_the_manager(self):
        rid = self.owner_asks("solo")
        self.ok("solo", "start_task", {"title": "Check the logs", "done_when": "a note says what they show",
                                       "in_reply_to": rid}, context=CHAT)
        t = hub.q1("SELECT * FROM tasks ORDER BY id DESC LIMIT 1")
        self.assertEqual((t["owner"], t["requester"], t["parent"]), ("solo", "manager", None))


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (PassUp, NotChased, Needs, Access, ManagerActs, OwnerChats):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


if __name__ == "__main__":
    unittest.main()

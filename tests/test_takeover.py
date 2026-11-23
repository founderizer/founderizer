"""Owner feature need_takeover (the owner's "Yes, as drawn" of 16 November 2026): an agent's browser or screen task asks
the owner for one step on its own screen that only a person can do. The item's title is the hub's words for that
step, the task waits
for his answer with no clock, his answer reaches the task's session, and the task's end takes an open request out of
Needs you. An in-process hub with the owner API's harness; no fleet, no network and no AI call."""
import json
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from unittest.mock import patch

import hub
import test_mobile
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
    for cls in (Ask, Answer, Refusals, Linux):
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
        # owner API 1.280: the task whose own mark an app draws on the answered card (with none, the card of a step
        # that the session still works on shows the check)
        self.assertEqual(item["task"], tid)
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

    def fresh(self):
        """Its helper found the session cold and asks for a fresh start (plan P9.10)."""
        return self.request(f"/helper/fresh/ivy/{hub.tref(self.tid)}",
                            {"attempt": 1, "why": "its cache is cold after 76 quiet minutes"})

    def test_its_session_does_not_start_fresh_before_it_read_the_owners_answer(self):
        """A session that waited on its take-over went cold, its helper asked for a fresh start, and the new attempt
        lost the session that the owner's answer was for. The request, and the answer that it has not read, keep it;
        once it read the answer, a cold one may start fresh again."""
        held = (409, {"error": "its request for a take-over waits for the owner's answer"})
        self.assertEqual(self.fresh(), held)
        self.assertEqual(self.answer(self.nid, answer="Done")[0], 200)
        self.assertEqual(self.fresh(), held)
        self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (self.tid,))["attempt"], 1)
        text, err = hub.call_tool("ivy", "read_messages", {}, ("test-generation", f"T-{self.tid}", "1"))
        self.assertFalse(err, text)
        self.assertEqual(self.fresh(), (200, {"attempt": 2}))

    def test_an_answer_on_the_board_keeps_it_too(self):
        self.assertEqual(self.board(self.nid, "Done on the board"), 303)
        self.assertEqual(self.fresh()[0], 409)
        self.assertFalse(hub.call_tool("ivy", "read_messages", {}, ("test-generation", f"T-{self.tid}", "1"))[1])
        self.assertEqual(self.fresh(), (200, {"attempt": 2}))

    def test_the_hubs_own_recoveries_are_not_held(self):
        """The hold is the helper's fresh start only: fresh_refusal serves the hub's recoveries as well."""
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (self.tid,))
        self.assertNotIn("take-over", hub.fresh_refusal(t, 1) or "")

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


PASSWORD = "Ab3dEf7h"           # a one-time password of 8 letters and digits, as the helper makes one


class Linux(Fixture):
    """Build plan 04, S6 (D7): Take over for an agent on a Linux server. His press asks the hub, the hub asks the agent's
    helper, and the helper's answer (the agent's screen port and a one-time password) reaches his press once and no
    row and no log line. At his answer the helper stops the sharing first, and the session gets the answer after that
    stop."""

    def setUp(self):
        super().setUp()
        hub.TEAM["addresses"]["srv1"] = "127.0.0.7"
        hub.TEAM["servers"] = {"srv1": {"kind": "linux", "user": "fleet"}}
        hub.TEAM["agents"]["nora"] = dict(role="worker", runtime="claude", machine="srv1",
                                          can=["shell", "web", "browser"])
        self.reading(state="ready")
        self.helper(features=[hub.TAKEOVER_FEATURE])
        self.addCleanup(hub.TAKEOVER_OPENS.clear)

    call, code, enroll, enrolled = (test_mobile.Devices.call, test_mobile.Devices.code, test_mobile.Devices.enroll,
                                    test_mobile.Devices.enrolled)

    def reading(self, state="ready", user="fleet-nora", screen=5911):
        """The server's own reading of its browser parts (S1b): their state, and the ports of the agent's OS user."""
        data = {"browser": {"state": state, "ports": [{"user": user, "devtools": 9301, "screen": screen}]},
                "agents": {"nora": {"user": "fleet-nora"}}}
        hub.q("DELETE FROM server_status WHERE server='srv1'")
        hub.q("INSERT INTO server_status(server, data, reported) VALUES('srv1', ?, ?)", (json.dumps(data), hub.now()))

    def helper(self, features, seen=None):
        hub.q("DELETE FROM machine_status WHERE agent='nora'")
        hub.q("INSERT INTO machine_status(agent, data, reported) VALUES('nora', ?, ?)",
              (json.dumps({"features": features}), hub.now()))
        hub.q("INSERT INTO agents(name, last_seen) VALUES('nora', ?) ON CONFLICT(name) DO UPDATE SET "
              "last_seen=excluded.last_seen", (hub.now() if seen is None else seen,))

    def asked(self):
        tid = self.task(owner="nora")
        text, err = self.ask(tid, agent="nora")
        self.assertFalse(err, text)
        return tid, hub.q1("SELECT id FROM needs WHERE by='nora' AND takeover_task=?", (tid,))["id"]

    def press(self, nid, answer=None, wait=5.0):
        """His press of Take over; `answer` is what the agent's helper sends once the hub asked it (None: no answer)."""
        played, floor = {}, hub.q1("SELECT COALESCE(MAX(id), 0) m FROM events")["m"]

        def play():
            end = time.monotonic() + wait
            while time.monotonic() < end:
                ev = hub.q1("SELECT * FROM events WHERE agent='nora' AND kind='takeover_open' AND id>? ORDER BY id DESC "
                            "LIMIT 1", (floor,))
                if ev:
                    nonce = json.loads(ev["extra"])["nonce"]
                    played["first"] = self.request("/helper/takeover/nora", dict(answer, nonce=nonce))
                    played["again"] = self.request("/helper/takeover/nora", dict(answer, nonce=nonce))
                    return
                time.sleep(0.05)
        player = threading.Thread(target=play, daemon=True)
        if answer is not None:
            player.start()
        got = self.request(f"/ui/needs/{nid}/takeover", {"db": "test-generation"})
        if answer is not None:
            player.join(wait)
        return got, played

    def test_the_linux_way_is_its_servers_ready_screen_and_an_online_helper_with_the_step(self):
        self.assertTrue(hub.takeover_way("nora"))
        self.assertEqual(hub.takeover_screen_port("nora"), 5911)
        self.asked()                                    # request_takeover takes it as a way
        for change in (lambda: self.reading(state="missing"), lambda: self.reading(user="fleet-other"),
                       lambda: self.helper(features=[]), lambda: self.helper([hub.TAKEOVER_FEATURE], seen=1.0)):
            change()
            self.assertFalse(hub.takeover_way("nora"))
            self.reading()
            self.helper([hub.TAKEOVER_FEATURE])
        self.assertTrue(hub.takeover_way("nora"))
        self.assertIn("takeover_linux", hub.UI_FEATURES)
        hub.TEAM["access"]["srv1"] = {"ssh_user": "owner-example", "ssh_port": 22, "screen_sharing": True}
        self.helper(features=[])
        self.assertFalse(hub.takeover_way("nora"))      # a Linux agent has only its own browser's screen
        self.assertTrue(hub.device_may("/ui/needs/5", "POST"))
        self.assertFalse(hub.device_may("/ui/needs/5/takeover", "POST"))      # the password goes to the Mac only

    def test_an_owner_s_pc_is_asked_for_no_screen_of_a_mac_or_a_linux_agent(self):
        """H2 (windows-app-plan-v2.md 5.3): the owner's PC has no Take over (Windows has no Screen Sharing, and its app
        no screen viewer yet). A card that asked for one would hold the task on an answer that the owner cannot give.
        The hub refuses the call before any card, for a Mac agent's screen and a Linux agent's alike (a refusal inside
        one machine's way would let the other ask), and names the way that is left. A Mac, which says every name, is
        asked as before; a Mac fleet has no kind at all, as every other test of this file."""
        mac_task, linux_task = self.task(), self.task(owner="nora")
        pc = {"kind": "windows", "label": "PC", "can": [name for name in hub.OWNER_CAN if name != "takeover"]}
        with patch.object(hub, "owner_computer", lambda: pc):
            for agent, tid in (("ivy", mac_task), ("nora", linux_task)):
                text, err = self.ask(tid, agent=agent)
                self.assertTrue(err, text)
                self.assertIn("The owner's computer is a PC, and its app cannot take over an agent's screen yet. Ask "
                              "your requester with ask_my_requester.", text)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs")["n"], 0)
        self.assertEqual(self.state(mac_task), ("working", None))
        mac = {"kind": "mac", "label": "Mac", "can": list(hub.OWNER_CAN)}
        with patch.object(hub, "owner_computer", lambda: mac):
            for agent, tid in (("ivy", mac_task), ("nora", linux_task)):
                text, err = self.ask(tid, agent=agent)
                self.assertFalse(err, text)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs WHERE kind='takeover'")["n"], 2)

    def test_his_press_gets_the_screen_and_its_password_once_and_no_row_or_log_line_holds_it(self):
        tid, nid = self.asked()
        (code, body), played = self.press(nid, {"port": 5911, "password": PASSWORD})
        self.assertEqual((code, body), (200, {"agent": "nora", "server": "srv1", "port": 5911, "password": PASSWORD}))
        self.assertEqual(played["first"], (200, {"taken": True}))
        self.assertEqual(played["again"], (200, {"taken": False}))      # given once: the press took it
        self.assertEqual(hub.TAKEOVER_OPENS, {})
        for (table,) in hub.DB.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
            for row in hub.DB.execute(f"SELECT * FROM {table}").fetchall():
                self.assertNotIn(PASSWORD, json.dumps([str(v) for v in row]), table)
        self.assertEqual(self.state(tid), ("input-required", f"N-{nid}"))     # the press is no answer

    def test_the_helpers_answer_is_its_own_agents_and_port_only(self):
        _, nid = self.asked()
        kept = hub.TAKEOVER_OPEN_WAIT
        hub.TAKEOVER_OPEN_WAIT = 1.0
        self.addCleanup(setattr, hub, "TAKEOVER_OPEN_WAIT", kept)
        (code, body), played = self.press(nid, {"port": 5912, "password": PASSWORD}, wait=2.0)
        self.assertEqual(played["first"], (200, {"taken": False}))      # not the agent's screen-sharing port
        self.assertEqual(body.get("code"), "takeover_late")
        for bad in ({"port": 5911, "password": "short"}, {"port": "5911", "password": PASSWORD},
                    {"refused": "tired"}, {"port": 5911, "password": PASSWORD, "more": 1}):
            self.assertEqual(self.request("/helper/takeover/nora", dict(bad, nonce="n" * 24))[0], 400, bad)
        self.assertEqual(self.request("/helper/takeover/ivy", {"nonce": "n" * 24, "refused": "screen"},
                                      source="127.0.0.5")[0], 403)      # another agent's machine

    def test_the_helpers_refusal_and_no_answer_in_time_reach_his_card_with_their_codes(self):
        _, nid = self.asked()
        for reason, code in (("provider", "takeover_provider"), ("no_browser", "takeover_no_browser"),
                             ("screen", "takeover_screen_failed")):
            hub.q("DELETE FROM events WHERE kind='takeover_open'")
            (status, body), _ = self.press(nid, {"refused": reason})
            self.assertEqual((status, body.get("code"), body.get("names")), (409, code, {"agent": "Nora"}), reason)
        kept = hub.TAKEOVER_OPEN_WAIT
        hub.TAKEOVER_OPEN_WAIT = 0.5
        self.addCleanup(setattr, hub, "TAKEOVER_OPEN_WAIT", kept)
        (status, body), _ = self.press(nid)
        self.assertEqual((status, body.get("code")), (409, "takeover_late"))

    def test_an_owner_device_gets_no_screen_and_no_password(self):
        """D7: the password goes to the owner's Mac app, which opens the tunnel; an enrolled phone or PC with its own key
        is refused, and the agent's sharing does not start again for it (a start ends a viewer that runs)."""
        hub.TEAM["owner_devices"] = {"iphone": {"label": "iPhone", "address": test_mobile.PHONE}}
        key = self.enrolled()
        _, nid = self.asked()
        for path in (f"/ui/needs/{nid}/takeover", f"/ui/needs//{nid}/takeover", f"/ui/needs/{nid}//takeover",
                     f"/ui/needs/{nid}/%74akeover"):           # the router reads each one as the take-over route
            status, _ = self.call(path, {"db": "test-generation"}, source=test_mobile.PHONE, token=key)
            self.assertEqual(status, 403, path)
        self.assertEqual(hub.q("SELECT * FROM events WHERE kind='takeover_open'"), [])
        self.assertEqual(self.call(f"/ui/needs/{nid}", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                         "answer": "Done"}, source=test_mobile.PHONE, token=key)[0],
                         200)                   # his answer from the phone still goes as on the Mac

    def test_a_second_press_takes_the_place_of_the_first_and_no_open_is_handed_out_again(self):
        _, nid = self.asked()
        first = {}
        waiting = threading.Thread(target=lambda: first.update(got=self.press(nid)[0]), daemon=True)
        waiting.start()                         # no helper answers the first press
        for _ in range(100):
            if hub.TAKEOVER_OPENS:
                break
            time.sleep(0.02)
        (code, body), _ = self.press(nid, {"port": 5911, "password": PASSWORD})
        waiting.join(5)
        self.assertEqual((code, body["password"]), (200, PASSWORD))
        self.assertEqual(first["got"][1].get("code"), "takeover_late")     # the newer press took its place
        opens = hub.q("SELECT helper_ack FROM events WHERE kind='takeover_open'")
        self.assertEqual((len(opens), all(o["helper_ack"] for o in opens)), (2, True))   # none goes out again

    def test_an_answer_during_the_wait_gives_no_password(self):
        tid, nid = self.asked()

        def answered(*args, **kwargs):          # his answer lands while the press waits for the helper
            hub.q("UPDATE needs SET answer='Done', answered=? WHERE id=?", (hub.now(), nid))
            return real(*args, **kwargs)
        real = hub.takeover_answer
        hub.takeover_answer = answered
        self.addCleanup(setattr, hub, "takeover_answer", real)
        (code, body), _ = self.press(nid, {"port": 5911, "password": PASSWORD})
        self.assertEqual((code, body.get("code")), (409, "takeover_closed"))
        self.assertNotIn(PASSWORD, json.dumps(body))

    def test_no_screen_for_a_closed_item_or_one_with_no_linux_way(self):
        tid, nid = self.asked()
        self.helper(features=[])
        self.assertEqual(self.press(nid)[0][1].get("code"), "takeover_no_screen")
        self.helper([hub.TAKEOVER_FEATURE])
        self.assertEqual(self.answer(nid, answer="Done")[0], 200)
        self.assertEqual(self.press(nid)[0][1].get("code"), "takeover_closed")
        ivy = self.task()
        self.assertFalse(self.ask(ivy)[1])
        mac = hub.q1("SELECT id FROM needs WHERE by='ivy'")["id"]
        self.assertEqual(self.press(mac)[0][1].get("code"), "takeover_no_screen")      # a Mac's take-over: its way
        self.assertEqual(hub.q("SELECT * FROM events WHERE kind='takeover_open'"), [])

    def test_at_his_answer_in_the_app_or_on_the_board_the_sharing_stops_before_the_session_reads_it(self):
        for way in ("app", "board"):
            tid, nid = self.asked()
            if way == "app":
                self.assertEqual(self.answer(nid, answer="Done")[0], 200)
            else:
                self.assertEqual(self.board(nid, "Done"), 303)
            close = hub.q1("SELECT * FROM events WHERE kind='takeover_close' AND task=?", (tid,))
            say = hub.q1("SELECT * FROM events WHERE kind='say' AND task=?", (tid,))
            self.assertLess(close["id"], say["id"], way)                # the helper reads the stop first
            self.assertEqual(json.loads(close["extra"]), {"need": nid})
            read = lambda: hub.call_tool("nora", "read_messages", {}, ("test-generation", f"T-{tid}", "1"))[0]
            self.assertNotIn("Done", read(), way)                      # the stop is not acknowledged yet
            polled = lambda: [e["id"] for e in self.request("/events/nora?delivery=1&after=0&wait=0")[1]["events"]]
            self.assertIn(close["id"], polled(), way)
            self.assertNotIn(say["id"], polled(), way)                 # nor does its helper get it to tell the session
            self.assertEqual(self.request("/helper/ack/nora", {"ids": [close["id"]]})[0], 200)
            self.assertIn(say["id"], polled(), way)
            self.assertIn("Done", read(), way)
            hub.q("UPDATE tasks SET state='completed' WHERE id=?", (tid,))
        mac = self.task()
        self.assertFalse(self.ask(mac)[1])
        self.assertEqual(self.answer(hub.q1("SELECT id FROM needs WHERE by='ivy'")["id"], answer="Done")[0], 200)
        self.assertEqual(hub.q("SELECT * FROM events WHERE kind='takeover_close' AND task=?", (mac,)), [])

    def test_the_tasks_end_stops_the_sharing_of_its_screen(self):
        tid, nid = self.asked()
        hub.secret_waits_end(tid)
        close = hub.q1("SELECT * FROM events WHERE kind='takeover_close' AND task=?", (tid,))
        self.assertEqual(json.loads(close["extra"]), {"need": nid})


if __name__ == "__main__":
    unittest.main()

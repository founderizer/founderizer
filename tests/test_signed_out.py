"""A worker or a lead whose own runtime is signed out on its machine: the hub starts no session for it and types nothing
into one until it is signed in, its tasks wait "to be signed in" and are no stall, the manager hears it once and each
requester of its tasks hears it in that task, and all of them again, quietly, when it is signed in; then each task
whose turns ended at the sign-in starts again in a new session. The capacity view, create_task's answer and the end of
a failed move say it too.

The owner, 16 November 2026: "the lead/manager needs to be aware of the status of their agents". That day an agent that
a move left signed out ran a session for each of its tasks for seven hours, every turn ended at "Not logged in", and
nobody was told. A local hub with a test source address for each machine; no real host, credential, session or AI
call. Each test's hub database is test_ui_api.quick, as for every OwnerAPI test."""
import json
import os
import re
import string
import threading
import unittest
import unittest.mock
from unittest.mock import patch

import hub
import test_agent_auth
from leftovers import ROOT, scratch_home
from test_agent_auth import BOX, KEYS

REFUSED = {"type": "error", "code": hub.AUTH_FAILED, "message": "Not logged in · Please run /login",
           "retryable": False, "resets_at": None}       # as the first fleet's hub had it, 16 November 2026
LINE = {"type": "user_message", "text": "New fleet messages."}     # a turn begins at a line
# Claude's refusal of the owner's own seat of a Claude Team organization, 23 November 2026 (its transcript row, as
# threads.py turns it into a record)
ORG_REFUSED = {"type": "error", "code": "oauth_org_not_allowed", "message": "Your organization has disabled Claude "
               "subscription access for Claude Code · Use an Anthropic API key instead, or ask your admin to enable "
               "access", "retryable": False, "resets_at": None}
# what the hub tells the manager to do for alpha's sign-in (F6, piece 1): the card with the hub's own step, and no
# words of the manager's that name a page ("open Example Developer in the app and sign it in" named none)
ASK = ('Only the owner can sign it in: raise_needs_you with sign_in "alpha" asks them, with the hub\'s own step, '
       'unless an item for it is open.')
SOURCES = os.path.join(ROOT, "app", "Sources")


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(SignedOut(name) for name in SignedOut.__dict__ if name.startswith("test_"))


class SignedOut(test_agent_auth.Routes):
    """alpha is a Claude worker under the lead boss, beta a Codex worker under the manager, both on one machine."""
    def setUp(self):
        super().setUp()
        hub.TEAM["agents"].update(boss=dict(role="lead", runtime="claude", machine="box", can=["shell"]))
        hub.TEAM["agents"]["alpha"].update(reports_to="boss", title="Example Developer", can=["shell", "screen"])
        self.register("alpha", "beta")

    def task(self, owner, needs="none", state="working", attempt=1):
        """A task with its first attempt, as admit_task writes both: the turn records of a session go to that row."""
        tid = super().task(owner, needs=needs, state=state, attempt=attempt)
        hub.ins("INSERT INTO attempts(task,attempt,created,started,reason) VALUES(?,?,?,?,'created')",
                (tid, attempt, hub.now(), hub.now()))
        return tid

    def signed(self, agent, value, features=("agent_key", "status_now")):
        """Its helper's report, with what it says of its own runtime's sign-in, and its helper online."""
        runtime = hub.agents()[agent]["runtime"]
        self.status(agent, features=list(features), runtimes={runtime: {"signed_in": value}})
        hub.know(agent)
        hub.q("UPDATE agents SET last_seen=? WHERE name=?", (hub.now(), agent))

    def poll(self, agent="alpha"):
        code, data = self.call(f"/events/{agent}?delivery=1&after=0&wait=0", source=BOX, token=KEYS[agent])
        self.assertEqual(code, 200, data)
        return sorted(e["kind"] for e in data["events"] if e["kind"] in ("task", "say", "chat", "conversation"))

    def said(self, agent, task=None):
        return [(r["text"], bool(json.loads(r["extra"] or "{}").get("quiet"))) for r in
                hub.q("SELECT text, extra FROM events WHERE agent=? AND kind='say' AND task IS ? ORDER BY id",
                      (agent, task))]

    def sweep(self):
        with hub.LOCK:
            hub.signed_out_sweep(hub.now())

    def records(self, t, *records, attempt=1, session="11111111-2222-4333-8444-555555555555", after=0):
        """A batch of its session's thread records through the helper's own route. after: the session's last seq."""
        events = [dict(r, seq=after + i + 1, ts=hub.now()) for i, r in enumerate(records)]
        code, data = self.call("/helper/events/alpha", dict(generation="test-generation", task=f"T-{t}",
                                                            attempt=attempt, session=session, events=events),
                               source=BOX, token=KEYS["alpha"])
        self.assertEqual(code, 200, data)

    def subtask(self):
        """A task of boss's own, and the subtask of it that boss gave alpha: (boss's task, alpha's task)."""
        mine = hub.ins("INSERT INTO tasks(title,owner,requester,state,created,needs,attempt) VALUES('Lead the work',"
                       "'boss','manager','working',?,'none',1)", (hub.now(),))
        theirs = hub.ins("INSERT INTO tasks(title,owner,requester,state,created,needs,attempt,parent) VALUES("
                         "'Fix it','alpha','boss','working',?,'none',1,?)", (hub.now(), mine))
        for tid in (mine, theirs):
            hub.ins("INSERT INTO attempts(task,attempt,created,started,reason) VALUES(?,1,?,?,'created')",
                    (tid, hub.now(), hub.now()))
        return mine, theirs

    # ---- the hold
    def test_no_task_line_or_chat_reaches_a_signed_out_agent_until_it_is_signed_in(self):
        t = self.task("alpha", state="submitted")
        hub.emit("alpha", "task", "start", task=t, extra={"generation": "test-generation", "attempt": 1})
        hub.emit("alpha", "say", "a line for its session", task=t)
        hub.emit("alpha", "chat", "a colleague's message", extra={"generation": "test-generation",
                                                                   "agent_message": 1})
        hub.emit("beta", "say", "a line for beta", task=self.task("beta"))
        self.signed("alpha", False)
        self.signed("beta", True)
        self.assertEqual(self.poll(), [])
        self.assertEqual(self.poll("beta"), ["say"])               # the hold is the agent's own
        self.signed("alpha", None)
        self.assertEqual(self.poll(), ["chat", "say", "task"])     # unknown is no sign-out
        self.signed("alpha", True)
        self.assertEqual(self.poll(), ["chat", "say", "task"])

    def test_a_screen_task_on_another_runtime_is_not_held(self):
        t = self.task("alpha", needs="screen")
        hub.emit("alpha", "say", "a line for its screen session", task=t)
        self.signed("alpha", False)
        self.assertEqual(self.poll(), ["say"])                     # it runs Codex, whose sign-in is its own
        self.assertFalse(hub.waits_for_sign_in(hub.q1("SELECT * FROM tasks WHERE id=?", (t,))))

    def test_an_open_install_holds_an_agent_that_has_no_reading_yet(self):
        """A move deletes the old machine's reading, and the new helper can poll before its first report."""
        hub.emit("alpha", "say", "a line", task=self.task("alpha"))
        hub.know("alpha")
        job = hub.ins("INSERT INTO server_jobs(server,kind,agent,runtime,state,step,created,updated) VALUES('box',"
                      "'install','alpha','claude','running','service',?,?)", (hub.now(), hub.now()))
        self.assertEqual(self.poll(), [])
        hub.q("UPDATE server_jobs SET state='done', step='sign_in' WHERE id=?", (job,))
        self.assertEqual(self.poll(), ["say"])

    def test_the_manager_and_an_agent_on_its_own_model_server_are_never_held(self):
        self.status("manager", runtimes={"claude": {"signed_in": False}})
        self.assertFalse(hub.runtime_signed_out("manager"))        # its own warning goes to the owner
        hub.TEAM["accounts"] = {"own": {"kind": "server", "provider": "own"}}
        hub.TEAM["agents"]["alpha"]["account"] = "own"
        self.signed("alpha", False)                                # its runtime's status says so, and it works
        self.assertFalse(hub.needs_sign_in("alpha"))
        t = self.task("alpha")
        hub.q("UPDATE agents SET alive=?, alive_ts=? WHERE name='alpha'", (f"T-{t}", hub.now()))
        with hub.LOCK:
            hub.liveness(hub.now())
        self.assertEqual(hub.q1("SELECT live_path FROM tasks WHERE id=?", (t,))["live_path"], "live session")
        del hub.TEAM["agents"]["alpha"]["account"]
        self.assertTrue(hub.runtime_signed_out("alpha"))

    def test_its_task_waits_to_be_signed_in_also_while_its_window_runs(self):
        t = self.task("alpha")
        self.signed("alpha", False)
        hub.q("UPDATE agents SET alive=?, alive_ts=? WHERE name='alpha'", (f"T-{t}", hub.now()))
        with hub.LOCK:
            hub.liveness(hub.now())
        row = hub.q1("SELECT live_path, stalled_since FROM tasks WHERE id=?", (t,))
        self.assertEqual((row["live_path"], row["stalled_since"]), ("waiting for alpha to be signed in", None))
        self.assertEqual(hub.fresh_refusal(hub.q1("SELECT * FROM tasks WHERE id=?", (t,)), 1), "alpha is not signed in")
        self.signed("alpha", True)
        hub.q("UPDATE agents SET alive=?, alive_ts=? WHERE name='alpha'", (f"T-{t}", hub.now()))
        with hub.LOCK:
            hub.liveness(hub.now())
        self.assertEqual(hub.q1("SELECT live_path FROM tasks WHERE id=?", (t,))["live_path"], "live session")

    def test_a_refused_turn_asks_for_a_reading_now_and_gets_no_nudge(self):
        t = self.task("alpha")
        self.signed("alpha", True)                                 # its runtime's last word, from before
        self.records(t, LINE, REFUSED,
                     {"type": "result", "stop_reason": "error"})
        self.assertEqual([r["kind"] for r in hub.q("SELECT kind FROM events WHERE agent='alpha'")], ["status_now"])
        row = hub.q1("SELECT * FROM tasks WHERE id=?", (t,))
        self.assertIsNotNone(hub.sign_in_refusal(row))
        self.assertTrue(hub.sign_in_waits(row))                     # until its machine's word after the refusal
        self.assertIsNone(hub.kv_get(f"turn_checked:{t}"))          # undecided: the tick decides it again
        self.records(t, {"type": "result", "stop_reason": "end_turn"}, session="22222222-2222-4333-8444-555555555555")
        self.assertIsNone(hub.sign_in_refusal(row))                 # a turn worked since

    # ---- the line
    def test_the_manager_and_each_requester_hear_it_once_and_again_quietly(self):
        mine, theirs = self.subtask()
        own = self.task("alpha")                                    # the manager's
        self.signed("alpha", False)
        self.sweep()
        self.sweep()
        (to_manager, quiet), = self.said("manager")
        self.assertFalse(quiet)
        self.assertIn("[hub] alpha (Example Developer) is not signed in to Claude Code on box: no session of it can "
                      "work.", to_manager)
        self.assertIn(f"Its open tasks: T-{theirs}, T-{own}.", to_manager)
        self.assertIn(ASK, to_manager)
        (to_lead, quiet), = self.said("boss", mine)                 # in its own task, where a lead reads its team
        self.assertFalse(quiet)
        self.assertIn(f"[hub] T-{theirs} (Fix it, owner alpha) waits: alpha is not signed in", to_lead)
        self.assertEqual((self.said("boss"), self.said("alpha")), ([], []))
        self.signed("alpha", None)                                  # an old or missing reading ends nothing
        self.sweep()
        self.assertEqual(len(self.said("manager")), 1)
        self.signed("alpha", True)
        self.sweep()
        self.sweep()
        self.assertEqual(self.said("manager")[1:], [("[hub] alpha (Example Developer) is signed in again: the "
                                                     "messages that waited for it go on.", True)])
        self.assertEqual(self.said("boss", mine)[1:], [(f"[hub] T-{theirs} goes on: alpha is signed in again.", True)])
        self.assertIsNone(hub.kv_get("signed_out_told:alpha"))
        self.signed("alpha", False)                 # again, with nothing new on it since the last word: quiet
        self.sweep()
        self.assertEqual([quiet for _, quiet in self.said("manager")], [False, True, True])
        self.signed("alpha", True)
        self.sweep()
        self.task("alpha")                          # new work came between: it wakes the manager again
        self.signed("alpha", False)
        self.sweep()
        self.assertEqual([quiet for _, quiet in self.said("manager")], [False, True, True, True, False])

    def tick(self):
        with hub.LOCK:
            hub.liveness(hub.now())
            hub.turn_end_sweep(hub.now())
            hub.signed_out_sweep(hub.now())

    def test_a_task_whose_turns_ended_at_the_sign_in_starts_again_in_a_new_session(self):
        refused, quiet_one = self.task("alpha"), self.task("alpha")
        self.signed("alpha", True)                                  # its machine's word from before the refusal
        self.records(refused, LINE, REFUSED, {"type": "result", "stop_reason": "error"})
        hub.emit("alpha", "say", "a line for it", task=refused)
        self.tick()
        self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (refused,))["attempt"], 1)
        self.assertEqual(self.poll(), [])           # its line waits: the old session must not take it
        self.signed("alpha", False)
        self.tick()
        self.signed("alpha", True)                  # its machine's word after the refusal
        self.tick()
        rows = {r["task"]: r for r in hub.q("SELECT * FROM attempts WHERE attempt=2")}
        self.assertEqual(list(rows), [refused])                     # the one that was never refused keeps its session
        self.assertEqual(rows[refused]["reason"], hub.SIGNED_IN)
        task = hub.q1("SELECT attempt, restarts FROM tasks WHERE id=?", (refused,))
        self.assertEqual((task["attempt"], task["restarts"] or 0), (2, 0))      # not counted: no crash loop
        start = hub.q1("SELECT text FROM events WHERE agent='alpha' AND kind='task' AND task=?", (refused,))["text"]
        self.assertIn("ended at \"Not logged in\" and did nothing", start)
        self.assertEqual(self.poll(), ["say", "task"])              # the new session, and the line that waited
        self.assertIn(f"T-{refused} starts again in a new session, because its turns ended at the sign-in",
                      self.said("manager")[-1][0])

    def test_an_account_that_its_provider_refuses_is_a_sign_in_to_do_until_one_finishes(self):
        """23 November 2026: from 11:09 UTC Claude refused the owner's own seat of a Claude Team organization at each
        turn (403 oauth_org_not_allowed), its machine still said "signed in", and an agent on that seat failed at each
        turn while nobody was asked to sign it in. The owner: "we need a better indicator so its as simple as logging in
        again!" The refusal is a sign-in to do: its work waits, its line hears why, the apps show its sign-in, which
        signs that account out first while its chat waits, and a finished sign-in ends it; the same account refused
        again holds it again, and a turn that works ends that. With F6 piece 1 the manager's line asks for the hub's
        card of that sign-in, which the hub raises while its machine reads the account signed in, keeps open while the
        refusal stands, and closes at the sign-in: the bugs, a card refused as "signed in", or closed at the next sweep
        with "is signed in" while every turn still fails."""
        t = self.task("alpha")
        holds = lambda: self.status("alpha", features=["agent_key", "status_now"], runtimes={"claude": {
            "signed_in": True}}, runtime={"name": "claude", "signed_in": True})
        self.signed("alpha", True)
        self.records(t, LINE, {"type": "result", "stop_reason": "end_turn"})         # it works, on the account of now
        hub.q("UPDATE events SET read_at=? WHERE agent='alpha'", (hub.now(),))       # and reads what that turn end sent
        self.records(t, LINE, ORG_REFUSED, {"type": "result", "stop_reason": "error"}, after=2)
        self.assertTrue(hub.needs_sign_in("alpha"))
        hub.emit("alpha", "say", "a line for it", task=t)
        holds()                                 # its machine goes on saying that it is signed in: no new session yet
        self.tick()
        self.assertEqual(self.poll(), [])                           # its work waits
        self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (t,))["attempt"], 1)     # no new session yet
        (to_manager, _), = self.said("manager")
        self.assertIn("is signed in to Claude Code on box with an account that Claude Code refuses at each turn",
                      to_manager)
        self.assertIn("sign it in with another account", to_manager)
        self.assertIn('raise_needs_you with sign_in "alpha" asks them', to_manager)       # the hub's card (F6, piece 1)
        # that card comes, for the refused account that its machine reads signed in, and stays while the refusal
        # stands: its step is the page's Sign in, which signs that account out first
        who = hub.shown_role("alpha")
        card = self.sign_in_card()
        self.assertIsInstance(card, int, card)
        self.assertEqual(hub.q1("SELECT todo FROM needs WHERE id=?", (card,))["todo"], (
            f"In Founderizer on your Mac, open Settings › Servers and choose box. Press Sign in beside Claude Code for "
            f"{who}, then follow the steps that it opens."))
        self.sweep_cards()
        self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (card,))["answer"])
        self.assertIs(hub.agent_view("alpha", hub.agents()["alpha"])["signed_in"], False)     # the apps' sign-in step
        machine = next(m for m in hub.machine_rows()[1] if m["agent"] == "alpha")      # and its page (AgentSetupFlow)
        self.assertIs(machine["runtime"]["signed_in"], False)
        hub.q("INSERT INTO ui_requests(request_id,kind,text,event_id,created,client,recipient) VALUES('r1','message',"
              "'Where do we stand?',1,?,'app','alpha')", (hub.now(),))      # its chat waits for that sign-in
        login = hub.start_machine_login("alpha", "claude")          # Sign in, not Use another account
        self.assertEqual(login["login"]["state"], "signing_out")    # the refused account goes first
        hub.q("UPDATE signin_jobs SET state='done', updated=? WHERE agent='alpha'", (hub.now(),))
        self.tick()
        self.assertFalse(hub.needs_sign_in("alpha"))
        self.sweep_cards()                                          # the sign-in that ends the refusal closes the card
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (card,))["answer"],
                         f"Closed by the hub: {who} is signed in to Claude Code now.")
        self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (t,))["attempt"], 2)    # the new sign-in
        self.assertEqual(self.poll(), ["say", "task"])
        start = hub.q1("SELECT text FROM events WHERE agent='alpha' AND kind='task' AND task=? ORDER BY id DESC",
                       (t,))["text"]
        self.assertIn("Claude Code refused the account that you were signed in with", start)
        self.records(t, LINE, ORG_REFUSED, {"type": "result", "stop_reason": "error"}, attempt=2,
                     session="33333333-2222-4333-8444-555555555555")
        self.assertTrue(hub.needs_sign_in("alpha"))                 # the same account, still refused
        self.records(t, LINE, {"type": "result", "stop_reason": "end_turn"}, attempt=2,
                     session="44444444-2222-4333-8444-555555555555")
        self.assertFalse(hub.needs_sign_in("alpha"))                # a turn of it that worked

    def test_a_refused_account_is_its_sign_ins_and_its_own_providers(self):
        """Two agents of one OS user keep one sign-in: after a sign-in from one row, the other must not stay held, where
        its own Sign in would sign out the new account. An old session of another runtime, and a subagent, say nothing
        of the account that the agent uses now."""
        code = {"code": "oauth_org_not_allowed"}
        note = lambda agent, data, ts=None: hub.account_refusal_note(agent, [(1, ts, "error", data)], hub.now())
        with hub.LOCK:
            note("alpha", dict(code, parent="toolu_1"))             # a subagent's
            note("beta", code)                                      # beta runs on Codex
            self.assertEqual([hub.account_refused(a) for a in ("alpha", "beta")], [None, None])
            note("alpha", code)
        for uid in (502, 501):
            for agent, own in (("alpha", 501), ("boss", uid)):
                self.status(agent, access={"uid": own}, runtimes={"claude": {"signed_in": True}})
            hub.ins("INSERT INTO signin_jobs(agent,runtime,state,created,updated) VALUES('boss','claude','done',?,?)",
                    (hub.now(), hub.now()))
            self.assertEqual(hub.needs_sign_in("alpha"), uid == 502)        # another user's sign-in is another one
        with hub.LOCK:
            note("alpha", code, hub.now() - 60)                     # a batch that comes late, from before that sign-in
            self.assertFalse(hub.needs_sign_in("alpha"))
            note("alpha", code)                                     # and the new account is refused too
            self.assertTrue(hub.needs_sign_in("alpha"))
            # boss shares it, and its own chat's refusal reaches no record: its waiting chat stops no sign-in either
            hub.q("INSERT INTO ui_requests(request_id,kind,text,event_id,created,client,recipient) VALUES('r2',"
                  "'message','And here?',2,?,'app','boss')", (hub.now(),))
            self.assertIsNone(hub.sign_out_busy("boss"))
            with unittest.mock.patch.dict(hub.TEAM["agents"]["boss"], runtime="codex"):     # another sign-in
                self.assertEqual(hub.sign_out_busy("boss")["chats_waiting"], 1)

    def test_a_persons_conversation_on_a_refused_account_holds_the_agent_too(self):
        person = hub.ins("INSERT INTO people(name,role,added) VALUES('Example Person','customer',?)", (hub.now(),))
        conv = hub.ins("INSERT INTO conversations(person,agent,account,chat,state,created,last) VALUES(?,'alpha',"
                       "'example','chat-1','open',?,?)", (person, hub.now(), hub.now()))
        tid = self.task("alpha")
        hub.q("UPDATE tasks SET source_conversation=?, source_message=1 WHERE id=?", (conv, tid))
        self.signed("alpha", True)
        self.call("/helper/events/alpha", dict(
            generation="test-generation", task=f"C-{conv}", attempt=conv,
            session="55555555-2222-4333-8444-555555555555",
            events=[dict(r, seq=i + 1, ts=hub.now()) for i, r in enumerate((LINE, ORG_REFUSED))]),
            source=BOX, token=KEYS["alpha"])
        self.assertTrue(hub.needs_sign_in("alpha"))

    def test_a_restart_on_the_machines_word_alone_comes_once(self):
        """A sign-in that the provider ended while the machine says that it is signed in: one new session, and then
        its empty turns reach its requester as any others do; a sign-in that finishes starts it again."""
        t = self.task("alpha")
        self.signed("alpha", True)
        self.records(t, LINE, REFUSED, {"type": "result", "stop_reason": "error"})
        self.signed("alpha", True)
        self.tick()
        self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (t,))["attempt"], 2)
        hub.q("UPDATE events SET read_at=? WHERE agent='alpha' AND kind='task'", (hub.now(),))   # its session read it
        self.records(t, LINE, REFUSED, {"type": "result", "stop_reason": "error"}, attempt=2,
                     session="33333333-2222-4333-8444-555555555555")
        self.signed("alpha", True)
        self.tick()
        self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (t,))["attempt"], 2)     # not again
        self.assertEqual([text for text, _ in self.said("alpha", t) if "is open and nothing is waiting" in text],
                         [hub.TURN_CONTINUE.format(task=f"T-{t}")])       # its empty turn goes on as any other
        hub.ins("INSERT INTO signin_jobs(agent,runtime,state,created,updated) VALUES('alpha','claude','done',?,?)",
                (hub.now(), hub.now()))
        self.tick()
        self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (t,))["attempt"], 3)     # a sign-in finished

    def test_a_turn_that_ended_while_signed_out_is_decided_after_the_sign_in(self):
        t = self.task("alpha")
        self.signed("alpha", False)
        self.records(t, LINE, {"type": "result", "stop_reason": "end_turn"})
        self.assertEqual(self.said("alpha", t), [])                 # no "nothing is waiting" now
        self.assertIsNone(hub.kv_get(f"turn_checked:{t}"))
        self.signed("alpha", True)
        self.tick()
        self.assertEqual(len(self.said("alpha", t)), 1)              # now it is decided, as any turn end is
        self.assertIsNotNone(hub.kv_get(f"turn_checked:{t}"))

    def refused(self, t, attempt=1, session="11111111-2222-4333-8444-555555555555"):
        """A turn of task t's session that its provider refused for want of a sign-in, while its machine's last word,
        from before it, said that it was signed in; then a line for it."""
        self.signed("alpha", True)
        self.records(t, LINE, REFUSED, {"type": "result", "stop_reason": "error"}, attempt=attempt, session=session)
        hub.emit("alpha", "say", "a line for it", task=t)

    def test_an_unknown_word_after_the_refusal_ends_the_wait(self):
        t = self.task("alpha")
        self.refused(t)
        self.assertEqual(self.poll(), [])                           # its line waits for the machine's word
        self.signed("alpha", None)                                  # the word comes, and says nothing
        self.assertEqual(self.poll(), ["say"])
        self.tick()
        self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (t,))["attempt"], 1)
        self.assertEqual(hub.kv_get(f"turn_checked:{t}"), "1:1")      # its turn is decided now, as any other

    def test_a_stale_report_ends_the_wait(self):
        t = self.task("alpha")
        self.refused(t)
        hub.q("UPDATE machine_status SET reported=? WHERE agent='alpha'", (hub.now() - hub.MACHINE_STALE - 60,))
        self.assertEqual(self.poll(), ["say"])                      # a machine that stopped reporting holds nothing

    def test_a_restart_that_a_background_command_holds_off_lets_the_lines_through(self):
        t = self.task("alpha")
        self.refused(t)
        state = hub.turn_state(t, 1)
        state["calls"] = {"toolu_1": ["Monitor: the deploy log", hub.now(), True]}
        hub.q("UPDATE attempts SET turn=? WHERE task=? AND attempt=1", (hub.json.dumps(state), t))
        self.signed("alpha", True)                                  # signed in since the refusal
        self.assertEqual(self.poll(), ["say"])                      # its old session takes them, as before
        self.tick()
        self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (t,))["attempt"], 1)

    def test_a_parked_task_is_not_held_for_a_restart_that_waits_for_its_time(self):
        t = self.task("alpha")
        self.refused(t)
        hub.ins("INSERT INTO reminders(due,note,agent,task,created) VALUES(?,?,'alpha',?,?)",
                (hub.now() + 3600, "look again", t, hub.now()))
        self.signed("alpha", True)
        self.assertEqual(self.poll(), ["say"])
        self.tick()
        self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (t,))["attempt"], 1)

    def test_a_session_that_worked_after_a_restart_starts_again_at_a_later_sign_out(self):
        """The once-only rule is for a session that never worked, not for one that a later sign-out stopped."""
        t = self.task("alpha")
        self.refused(t)
        self.signed("alpha", True)
        self.tick()
        self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (t,))["attempt"], 2)
        self.records(t, LINE, {"type": "result", "stop_reason": "end_turn"}, attempt=2,
                     session="44444444-2222-4333-8444-555555555555")      # it works
        self.refused(t, attempt=2, session="55555555-2222-4333-8444-555555555555")   # days later, a new sign-out
        self.assertTrue(hub.sign_in_refusal(hub.q1("SELECT * FROM tasks WHERE id=?", (t,)))["worked"])
        self.signed("alpha", True)
        self.tick()
        self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (t,))["attempt"], 3)

    def test_a_conversation_on_its_own_runtime_waits_for_the_sign_in(self):
        person = hub.ins("INSERT INTO people(name,role,added) VALUES('Example Person','customer',?)", (hub.now(),))
        conv = hub.ins("INSERT INTO conversations(person,agent,account,chat,state,created,last) VALUES(?,'alpha',"
                       "'example','chat-1','open',?,?)", (person, hub.now(), hub.now()))
        hub.emit("alpha", "conversation", "a person's message", extra={"conversation": conv})
        self.assertEqual(hub.conversation_runtime("alpha", conv), "claude")
        self.signed("alpha", False)
        self.assertEqual(self.poll(), [])
        self.signed("alpha", True)
        self.assertEqual(self.poll(), ["conversation"])

    def test_a_worker_under_the_manager_is_told_to_the_manager_alone(self):
        self.signed("beta", False)
        self.sweep()
        (text, _), = self.said("manager")
        self.assertIn("[hub] beta is not signed in to Codex on box", text)
        self.assertIn("Its open tasks: none.", text)
        self.assertEqual(self.said("boss"), [])

    def test_nothing_is_told_while_a_sign_in_waits_or_the_agent_cannot_be_read(self):
        self.signed("alpha", False)
        login = hub.ins("INSERT INTO signin_jobs(agent,runtime,state,created,updated) VALUES('alpha','claude',"
                        "'signing_in',?,?)", (hub.now(), hub.now()))
        self.sweep()
        hub.q("UPDATE signin_jobs SET state='failed' WHERE id=?", (login,))
        job = hub.ins("INSERT INTO server_jobs(server,kind,agent,runtime,state,step,created,updated) VALUES('box',"
                      "'install','alpha','claude','needs_owner','sign_in',?,?)", (hub.now(), hub.now()))
        self.sweep()
        hub.q("UPDATE server_jobs SET state='failed' WHERE id=?", (job,))
        hub.TEAM["agents"]["alpha"]["active"] = False           # in setup: it has no work to hold
        self.sweep()
        hub.TEAM["agents"]["alpha"]["active"] = True
        hub.q("UPDATE agents SET last_seen=? WHERE name='alpha'", (hub.now() - 600,))     # offline_sweep's
        self.sweep()
        self.assertEqual(self.said("manager"), [])
        hub.q("UPDATE agents SET last_seen=? WHERE name='alpha'", (hub.now(),))
        self.sweep()
        self.assertEqual(len(self.said("manager")), 1)

    # ---- what else says it
    def move_ended(self, detail, timed_out=1):
        hub.kv_set(hub.INSTALL_TOLD_FROM, "0")
        hub.kv_set(hub.MOVED + "alpha", "solo")
        hub.ins("INSERT INTO server_jobs(server,kind,agent,runtime,state,step,detail,timed_out,created,updated) "
                "VALUES('box','install','alpha','claude','failed','sign_in',?,?,?,?)",
                (detail, timed_out, hub.now(), hub.now()))

    def install_word(self):
        with hub.LOCK:
            hub.OS_USERS["at"] = 0
            hub.os_user_sweep(hub.now())

    def test_a_failed_move_says_why_once_and_the_sign_in_is_the_owners(self):
        """The incident's own case: the install of a moved agent ends at its sign-in wait. The manager reads one
        instruction, whichever word comes first, and the lead hears it in its own task."""
        mine, theirs = self.subtask()
        self.move_ended("Claude Code did not sign in within 15 minutes. Try again in Founderizer.")
        self.signed("alpha", False)
        self.install_word()                         # the install's word first: it tells the sweep's word itself
        self.assertEqual(len([t for t, _ in self.said("manager") if "is not signed in to" in t]), 1)
        self.sweep()
        said = [text for text, _ in self.said("manager")]
        move = [text for text in said if "after its move ended" in text]
        told = [text for text in said if "is not signed in to" in text]
        self.assertEqual((len(move), len(told)), (1, 1), said)
        self.assertIn("after its move ended: failed at its step sign_in (Claude Code did not sign in within 15 "
                      "minutes. Try again in Founderizer). It is installed there, and only its sign-in is missing",
                      move[0])
        self.assertNotIn("Read the server", move[0])
        self.assertIn(ASK, told[0])
        self.assertIn(f"[hub] T-{theirs} (Fix it, owner alpha) waits", self.said("boss", mine)[0][0])
        self.signed("alpha", True)
        self.sweep()
        self.assertIn("is signed in again", self.said("manager")[-1][0])

    def test_the_sweeps_word_first_and_a_sign_in_that_did_not_start(self):
        self.move_ended("The sign-in did not start: the hub did not answer.", timed_out=0)
        self.signed("alpha", False)
        self.sweep()                                # the sweep's word first
        self.install_word()
        said = [text for text, _ in self.said("manager")]
        self.assertEqual(len([text for text in said if "is not signed in to" in text]), 1, said)
        move, = [text for text in said if "after its move ended" in text]
        self.assertIn("only its sign-in is missing, which only the owner gives: the hub's word that it is not signed "
                      "in says what to do.", move)
        self.assertNotIn("Read the server", move)

    def test_a_queued_install_that_failed_names_no_step(self):
        hub.kv_set(hub.INSTALL_TOLD_FROM, "0")
        hub.kv_set(hub.MOVED + "alpha", "solo")
        hub.ins("INSERT INTO server_jobs(server,kind,agent,runtime,state,detail,created,updated) VALUES('box',"
                "'install','alpha','claude','failed','The server service stopped answering.',?,?)",
                (hub.now(), hub.now()))
        with hub.LOCK:
            hub.OS_USERS["at"] = 0
            hub.os_user_sweep(hub.now())
        text = next(t for t, _ in self.said("manager") if "after its move ended" in t)
        self.assertIn("ended: failed (The server service stopped answering). Read the server", text)

    def test_the_capacity_route_of_a_signed_out_runtime_cannot_work(self):
        self.signed("alpha", False)
        route = hub.capacity_view(["alpha"])["agents"][0]["routes"][0]
        self.assertEqual((route["route"], route["state"]), ("primary", "unknown"))
        self.assertEqual(route["reason"], f"The claude runtime of this route is signed out: {hub.SIGN_IN_REQUIRED}")
        self.signed("alpha", True)
        self.assertNotIn("signed out", hub.capacity_view(["alpha"])["agents"][0]["routes"][0]["reason"] or "")
        self.assertTrue(hub.chat_wanted("alpha", False))
        with hub.LOCK:          # its machine says "signed in", and its provider refuses that account at each turn
            hub.account_refusal_note("alpha", [(1, None, "error", {"code": "oauth_org_not_allowed"})], hub.now())
        route = hub.capacity_view(["alpha"])["agents"][0]["routes"][0]
        self.assertEqual(route["state"], "unknown")
        self.assertIn("an account that its provider refuses", route["reason"])
        self.assertFalse(hub.chat_wanted("alpha", False))           # no chat session starts for it

    def test_whoever_gives_it_work_reads_that_the_task_waits(self):
        self.signed("beta", False)
        said = hub.t_create_task("manager", {"owner": "beta", "title": "Write the notes", "done_when": "they exist"})
        self.assertIn("Note: beta is not signed in to Codex, so no session of it can work; the task waits until the "
                      "owner signs it in.", said)
        self.signed("beta", True)
        said = hub.t_create_task("manager", {"owner": "beta", "title": "Write the notes", "done_when": "they exist"})
        self.assertNotIn("not signed in", said)

    # ---- the owner's card of its sign-in (F6, piece 1)
    def sign_in_card(self, agent="Example Developer", caller="manager", **fields):
        """The manager's item with sign_in (by the agent's role) and a why: the new item's id, or the refusal."""
        said, error = hub.call_tool(caller, "raise_needs_you", dict({"sign_in": agent, "why": "Its tasks wait for it."},
                                                                    **fields))
        return said if error else int(said.split("N-")[1].split(".")[0])

    def sweep_cards(self):
        hub.kv_set("need_look_sweep_at", None)
        with hub.LOCK:
            hub.need_look_sweep(hub.now())

    def test_a_card_for_its_sign_in_has_the_hubs_step_and_closes_at_the_sign_in(self):
        """The owner, 19 November 2026, of four cards in one hour whose steps the manager wrote from memory: "what agent
        should I open?", "No sign in button appears", "There is no machines page, do you mean Servers?". With sign_in
        the hub writes the card's title and step from its own record. The believable bugs: a step that names a page, a
        server or a button that the owner's app does not show, or that a phone's reader takes for a page of the phone;
        a card for an agent that the hub reads signed in; a second card for the same sign-in; a card that stays open
        after the sign-in; a worker that raises one; a link or a code beside the hub's step, in why or in the asker's
        words behind Details, which could be a machine's that is not the fleet's; a card while the hub has no current
        reading, when the server's page shows no sign-in; a why that sends the owner into the vault for a key's value,
        which no card of another reason carries; a refused call for the title and what_to_do that the tool's
        schema asks for; a refusal of why that quotes what it read, which can be most of a key, into the hub's records;
        a web address whose user part reads as an email address, a key after a prefix with an underscore, or a code in
        full-width letters, with a non-breaking hyphen or a zero-width space; a limit of that check that its comment
        does not write (a known hole is fixed or written); the hub's word after a refusal for want of a reading, which
        never came (the area's reader of piece 1, finding 3); a reply under the card with an address or a code; a why
        over 140 characters whose refusal sends the manager to details, which this card refuses (P7 piece 2)."""
        who = hub.shown_role("alpha")           # the label of the owner's apps (a role before F16, the name after)
        self.assertIn(f"the hub has no current reading of {who}'s sign-in to Claude Code and Codex on box",
                      self.sign_in_card())
        self.signed("beta", True)
        signed_in = self.sign_in_card("beta")
        self.assertIn(f"the hub reads {hub.shown_role('beta')} signed in to Codex on box now, so the owner has no "
                      f"sign-in to make.", signed_in)
        # a provider can refuse an account that the machine reads signed in: the refusal leaves a way to the owner,
        # because card_runtime_sign_in refuses a card in the manager's own words
        self.assertIn("If its turns still end because the provider refuses that account, a refusal that the hub did "
                      "not read, tell the owner with message_owner that", signed_in)
        self.assertIn("needs a sign-in with another account there, or with the same one once its organization turned "
                      "that access on again.", signed_in)
        self.signed("alpha", False)
        self.sweep_cards()          # the hub's word after the first refusal: it reads one of them now
        told = self.said("manager")
        self.assertEqual(told[-1][0], '[hub] alpha (Example Developer) is not signed in to Claude Code on box: the hub '
                                      'reads it now, after it refused your card for want of a reading. Only the owner '
                                      'can sign it in: raise_needs_you with sign_in "alpha" asks them, with the hub\'s '
                                      'own step, unless an item for it is open.')
        self.sweep_cards()
        self.assertEqual(len(self.said("manager")), len(told))          # once: Codex has no reading yet
        for why, kind in (("Its tasks wait: open https://auth.openai.com/codex/device and enter `K7QD-2M4P`.",
                           "an address"),
                          ("Its tasks wait. On the page that opens, enter the code K7QD-2M4P.", "a code"),
                          ("Its tasks wait. Open https://owner@evil.com/device first.", "an address"),  # a user part
                          ("Its tasks wait. Open evil.app/device and enter the code that it shows.", "an address"),
                          ("Its tasks wait. Paste sk4f9Qz81LmN0pW2xV7-x9Lp2Qr7Zt5Vb3Nm when it asks.", "a code"),
                          ("Its tasks wait. Run `codex login` on it.", "a code"),
                          ("Its tasks wait. Paste ghp_9fQz81LmN0pW2xV7a4Kd2 there.", "a code"),       # a prefix
                          ("Its tasks wait. Paste sk_live_4f9Qz81LmN0pW2xV7 there.", "a code"),
                          ("Its tasks wait. Enter K7QD\u20112M4P there.", "a code"),          # a non-breaking hyphen
                          ("Its tasks wait. Enter K7Q\u200bD-2M4P there.", "a code"),          # a zero-width space
                          ("Its tasks wait. Open \uff45\uff56\uff49\uff4c.app\uff0fdevice first.", "an address"),
                          ("Its seat of 2025-2026 ended.", "a code"),           # honest lines
                          ("Version 2.1/3 of its app signed it out.", "an address")):
            with self.subTest(why=why):
                said = self.sign_in_card(why=why)
                self.assertIn(f"why holds no address and no code: a part of it reads as {kind}. The owner signs in on "
                              f"the provider's own page", said)
                # none of its words: the hub's log and the call's record mask a key only whole
                for word in re.findall(r"\S*[\d/:@]\S*", why):
                    self.assertNotIn(word.strip(".`"), said)
        said = self.sign_in_card(why="Its tasks wait. " + "w " * 62 + "w")                    # 141 characters
        self.assertIn("why is at most 140 characters", said)
        self.assertIn("Say it in fewer words: this card takes no details. This one has 141.", said)
        self.assertNotIn("in details", said)
        # the limits of that check, which the comment above NEED_SIGN_IN_CODE writes: each is true, and each is written
        with open(hub.__file__, encoding="utf-8") as f:
            source = f.read()
        lines = source[source.index("# what a why beside the hub's step of a sign-in"):
                       source.index("\nNEED_SIGN_IN_CODE = ")].splitlines()
        comment = " ".join(line.lstrip("# ") for line in lines)      # its words, read whole across the lines
        for why, written in (("Its seat of 2025 to 2026 ended.", "2025-2026"),          # the same lines in other words
                             ("Version 2.1 of 3 of its app signed it out.", "Version 2.1/3"),
                             ("Its tasks wait. Enter the code k7qd-2m4p.", "k7qd-2m4p"),
                             ("Its tasks wait. Enter the code K7QD 2M4P.", "K7QD 2M4P"),
                             ("Its tasks wait. Enter the code K7QD2M4P.", "K7QD2M4P")):
            with self.subTest(why=why):
                self.assertIsNone(hub.sign_in_why_refusal(why))
                self.assertIn(f'"{written}"', comment)
        # a why that sends the owner into the vault for a key's value gets the value check of every other card, and
        # its route (card_value_steps); an honest why still raises the card below
        hub.TEAM["logins"] = {"bws://00000000-0000-4000-8000-0000000a0de0": {"kind": "api_key", "title": "Anthropic",
                                                                              "env": "ANTHROPIC_API_KEY"}}
        self.assertIn("Not raised: a new value of ANTHROPIC_API_KEY comes through request_secret", self.sign_in_card(
            why="Its tasks wait. Also replace ANTHROPIC_API_KEY in Secrets with the new key."))
        self.assertIn("A check of words cannot hold this", comment)
        self.assertIn("The manager's own words are the only free text on that card: its why, a reply under it and a "
                      "reason that withdraws it", comment)
        asker = self.task("alpha")
        qid = hub.ins("INSERT INTO questions(task,asker,requester,text,asked) VALUES(?,?,'manager',?,?)",
                      (asker, "alpha", "Open https://evil.example/device and enter K7QD-2M4P for me?", hub.now()))
        nid = self.sign_in_card(question_id=f"Q-{qid}", title="Sign in alpha", what_to_do="Open its page.")
        code, state = self.request("/ui/state")
        self.assertEqual(code, 200, state)
        card, = [n for n in state["needs"] if n["id"] == nid]
        self.assertEqual((card["title"], card["todo"], card["details"]), (
            f"Sign {who} in to Claude Code",
            f"In Founderizer on your Mac, open Settings › Servers and choose box. Press Sign in beside Claude Code for "
            f"{who}, then follow the steps that it opens.", None))
        self.assertIn(f"N-{nid} asks the owner for that sign-in already, and it closes by itself at the sign-in. To "
                      f"change its why, raise it again with replaces=\"N-{nid}\" and question_id=\"Q-{qid}\".",
                      self.sign_in_card("alpha"))         # F13: the new card takes the question only when named
        self.assertIn("You have no tool named raise_needs_you", self.sign_in_card(caller="beta"))  # the manager's alone
        # the manager's reply under the card stands beside the hub's step too
        hub.ins("INSERT INTO need_talk(need, ts, who, text) VALUES(?,?,?,?)", (nid, hub.now(), "owner", "Which page?"))
        said, error = hub.call_tool("manager", "discuss_need", {"need": f"N-{nid}",
                                                               "text": "Open https://owner@evil.com/device there."})
        self.assertIn("Under a card of a sign-in, text holds no address and no code: a part of it reads as an address.",
                      said)
        said, error = hub.call_tool("manager", "discuss_need", {"need": f"N-{nid}",
                                                               "text": "The page and its button are in the step."})
        self.assertIn(f"Your reply is under N-{nid}", said)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs")["n"], 1)
        self.signed("alpha", True)
        self.sweep_cards()
        words = f"Closed by the hub: {who} is signed in to Claude Code now."
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"], words)
        self.assertEqual(hub.q1("SELECT answer FROM questions WHERE id=?", (qid,))["answer"], words)
        self.assertIn(f"[hub] The hub closed N-{nid} (Sign {who} in to Claude Code, for alpha) on the "
                      f"owner's Needs you: its answer says why (the hub reads that sign-in now, or its agent left the "
                      f"fleet, has no such sign-in now or runs on another server).", self.said("manager")[-1][0])

    def test_the_card_of_its_screen_tasks_names_codex_and_the_button_that_the_page_shows(self):
        """An agent whose own runtime is signed in and whose screen tasks' Codex is not (the owner's cards of 19
        November 2026 were of that Codex), on a Mac with a second such agent: the card is for Codex, whose one row on
        the Mac's page has no role, and whose button follows the sign-ins of both agents (the app's ScreenSignIn).
        The believable bugs: a card for the runtime that is signed in; Sign in on a step where the row shows Try again
        after a sign-in that failed, or Open while one runs, also another agent's of that Mac; a second card for that
        one sign-in; a step on a page that the owner's computer does not have (a PC), or with a button that a Mac with
        no ChatGPT app does not show; the hub's own step refused as fleet work for a server named deploy-1; a card
        that stays open after its agent left the fleet, moved to another server or lost its screen, whose step then
        names a row that the page does not draw (the area's reader of piece 1, finding 5); a reason that withdraws the
        card with an address or a code in it; replaces that does not take the open card's place."""
        who = hub.shown_role("alpha")
        hub.TEAM["agents"]["alpha"]["machine"] = "deploy-1"
        hub.TEAM["agents"]["gamma"] = dict(role="worker", runtime="claude", machine="deploy-1", can=["shell", "screen"],
                                           title="Example Designer")
        for agent in ("alpha", "gamma"):
            self.status(agent, features=["agent_key"], runtimes={"claude": {"signed_in": True},
                                                                 "codex": {"signed_in": False}})
        with patch.object(hub, "owner_computer", lambda: {"kind": "windows", "label": "PC", "can": []}):
            self.assertIn("the owner's computer is a PC, and only Founderizer on a Mac signs an agent in again yet",
                          self.sign_in_card())
        with patch.object(hub, "mac_desktop", lambda machine: {"chatgpt": False, "chatgpt_app": False}):
            self.assertIn("the ChatGPT app is not installed on deploy-1, so its page has no sign-in of Codex",
                          self.sign_in_card())
        login = hub.ins("INSERT INTO signin_jobs(agent,runtime,state,created,updated) VALUES('gamma','codex',"
                        "'signing_in',?,?)", (hub.now(), hub.now()))
        self.assertIn("a sign-in of Codex runs on deploy-1 now", self.sign_in_card())
        step = ("In Founderizer on your Mac, open Settings › Servers and choose deploy-1. Press {} beside Codex, then "
                "follow the steps that it opens.")
        hub.q("UPDATE signin_jobs SET state='failed', timed_out=1 WHERE id=?", (login,))    # nobody finished it in time
        nid = self.sign_in_card()
        self.assertEqual(tuple(hub.q1("SELECT title, todo FROM needs WHERE id=?", (nid,))),
                         (f"Sign {who} in to Codex", step.format("Sign in")))
        hub.q("UPDATE needs SET answer='Not now' WHERE id=?", (nid,))
        hub.q("UPDATE signin_jobs SET timed_out=NULL WHERE id=?", (login,))                 # one that failed
        nid = self.sign_in_card()
        self.assertEqual(hub.q1("SELECT todo FROM needs WHERE id=?", (nid,))["todo"], step.format("Try again"))
        self.assertIn(f"N-{nid} asks the owner for that sign-in already", self.sign_in_card("gamma"))
        # a reason that withdraws the card stands on it under the hub's step, as its why does
        said, error = hub.call_tool("manager", "withdraw_need", {"need": f"N-{nid}",
                                                                "why": "Not needed: open evil.app/device first."})
        self.assertIn("With a card of a sign-in, why holds no address and no code: a part of it reads as an address.",
                      said)
        self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"])
        # replaces takes the open card's place for that sign-in, with the hub's step again
        new = self.sign_in_card(replaces=f"N-{nid}", why="Its screen tasks wait for it.")
        self.assertIsInstance(new, int, new)
        old = hub.q1("SELECT answer, replaced_by FROM needs WHERE id=?", (nid,))
        self.assertTrue(old["answer"].startswith("Replaced by "), old["answer"])
        self.assertEqual((old["replaced_by"], hub.q1("SELECT todo FROM needs WHERE id=?", (new,))["todo"]),
                         (new, step.format("Try again")))
        nid = new
        alpha = hub.TEAM["agents"]["alpha"]
        for change, back, words in ((dict(machine="deploy-2"), dict(machine="deploy-1"),
                                     f"Closed by the hub: {who} does not run on deploy-1 now."),
                                    (dict(can=["shell"]), dict(can=["shell", "screen"]),
                                     f"Closed by the hub: {who} does not use Codex now.")):
            with self.subTest(change=change):
                alpha.update(change)
                self.sweep_cards()
                self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"], words)
                self.assertIn("When the hub still reads that agent signed out after a move or a change of its runtime, "
                              "raise it again with sign_in.", self.said("manager")[-1][0])
                alpha.update(back)
                nid = self.sign_in_card()
                self.assertIsInstance(nid, int)
        del hub.TEAM["agents"]["alpha"]
        self.sweep_cards()
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"],
                         "Closed by the hub: Alpha left the fleet.")

    def test_the_card_is_in_the_owners_language(self):
        """The apps show their own words in the language of the device, and the card's title and step as the hub wrote
        them (the area's reader of piece 1, finding 1). The believable bugs: a Mac in Spanish shows "Ajustes ›
        Servidores" and "Iniciar sesión" beside a step that names "Settings › Servers" and "Sign in"; a language that
        the apps do not have gets no card, or words that the app does not show; the card follows the Mac's first
        preferred language, not the language that the app shows, which the Mac sends (owner.app_language, the owner,
        23 November 2026, "Yes, two values"): a Mac with Catalan first and Spanish second, or an English app on a
        Spanish Mac."""
        self.signed("alpha", False)
        real, who = hub.setting, hub.shown_role("alpha")
        spanish = (f"Inicia la sesión de {who} en Claude Code",
                   "En Founderizer en tu Mac, abre Ajustes › Servidores y elige box. Pulsa Iniciar sesión junto a "
                   f"Claude Code para {who} y sigue los pasos que se abren.")
        english = (f"Sign {who} in to Claude Code",
                   "In Founderizer on your Mac, open Settings › Servers and choose box. Press Sign in beside Claude "
                   f"Code for {who}, then follow the steps that it opens.")
        for tag, app, (title, todo) in (("es-ES", None, spanish),     # a Mac app from before: owner.language
                                        ("fr-FR", None, english),     # a Mac in French alone: the app shows English
                                        ("ca-ES", "es", spanish),     # Catalan first, the app in Spanish
                                        ("es-ES", "en", english)):    # an English app on a Spanish Mac
            def language(key, tag=tag, app=app):
                return tag if key == "owner.language" else app if key == "owner.app_language" and app else real(key)
            with self.subTest(tag=tag, app=app), patch.object(hub, "setting", language):
                nid = self.sign_in_card()
                self.assertEqual(tuple(hub.q1("SELECT title, todo FROM needs WHERE id=?", (nid,))), (title, todo))
                hub.q("UPDATE needs SET answer='Not now' WHERE id=?", (nid,))

    def test_two_raises_at_one_moment_make_one_card(self):
        """One sign-in, one open card, also for two calls of the manager at the same moment: two parallel tool calls of
        one turn, or its owner chat and a task session that act on one line of the hub's, each on a thread of its own
        (ThreadingHTTPServer). call_tool runs raise_needs_you whole under LOCK (`with kit_lock() if name in KIT_TOOLS
        else LOCK`), need_sign_in's read of the open cards and the card's write, so the second call reads the first
        one's card. The believable bug: raise_needs_you joins the tools that call_tool runs outside LOCK, both calls
        read no open card before either writes its own, and the owner gets two cards and two rings for one sign-in."""
        self.signed("alpha", False)
        real, both, said = hub.need_sign_in, threading.Barrier(2), []

        def read_together(a):
            got = real(a)
            try:        # each call has read the open cards before either one writes
                both.wait(timeout=2)
            except threading.BrokenBarrierError:        # a lock around the whole call: the first one waits alone
                pass
            return got
        with patch.object(hub, "need_sign_in", read_together):
            calls = [threading.Thread(target=lambda: said.append(self.sign_in_card())) for _ in range(2)]
            for call in calls:
                call.start()
            for call in calls:
                call.join(60)
        cards = [nid for nid in said if isinstance(nid, int)]
        self.assertEqual(len(cards), 1, said)
        refused, = [words for words in said if not isinstance(words, int)]
        self.assertIn(f"Not raised: N-{cards[0]} asks the owner for that sign-in already", refused)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs")["n"], 1)

    @unittest.skipUnless(os.path.isdir(SOURCES), "a tree with no app/")
    def test_the_cards_words_are_the_apps_own(self):
        """The hub's step of a sign-in names the Mac app's page, row and button by the words of the views that draw
        them. The believable bug: the app renames its button, its tab or a runtime on its row, and the hub's cards go
        on naming what the owner no longer sees."""
        def source(*parts):
            with open(os.path.join(SOURCES, *parts), encoding="utf-8") as f:
                return f.read()
        section = source("Founderizer", "MachineSignInSection.swift")
        button = section.split("private var button: String {", 1)[1].split("\n    }", 1)[0]
        en = hub.NEED_SIGN_IN_WORDS["en"]
        for words in (en["button"], en["again"]):
            self.assertIn(f'String(l10n: "{words}")', button)
        self.assertIn("FormRow(card ? providerName(runtime)", section)         # the row is the runtime's own name
        self.assertIn('isFailure: Bool { state == "failed" && timed_out != true }',     # when the button says Try again
                      source("FleetCore", "MachineSignin.swift"))
        names = dict(re.findall(r'case "(\w+)": "([^"]+)"', source("FleetCore", "RuntimeSwitch.swift")
                                .split("func providerName", 1)[1].split("\n}", 1)[0]))
        self.assertEqual({r: names.get(r) for r in hub.LOGIN_RUNTIMES}, {r: hub.runtime_label(r)
                                                                         for r in hub.LOGIN_RUNTIMES})
        settings, tab = en["page"].split(" › ")
        self.assertEqual(settings, "Settings")
        self.assertIn(f'case .servers: String(l10n: "{tab}")', source("Founderizer", "SettingsPage.swift"))
        self.assertIn(f'("{tab}", "servers")', source("FleetCore", "CardNames.swift"))     # the step links the page
        # the same words in each language of the apps, as the app's catalog has them (the area's reader of piece 1,
        # finding 1): the app shows the card as the hub wrote it, and its own page and buttons in its own language
        with open(os.path.join(ROOT, "app", "Localization", "Localizable.xcstrings"), encoding="utf-8") as f:
            catalog = json.load(f)["strings"]
        with open(os.path.join(ROOT, "app", "Localization", "shipped"), encoding="utf-8") as f:
            shipped = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        self.assertEqual(set(hub.NEED_SIGN_IN_WORDS), {"en", *shipped})

        def fields(text):
            return {name for _, name, _, _ in string.Formatter().parse(text) if name}
        for language in shipped:
            with self.subTest(language=language):
                words = hub.NEED_SIGN_IN_WORDS[language]

                def app(key):
                    return catalog[key]["localizations"][language]["stringUnit"]["value"]
                self.assertEqual((words["button"], words["again"], words["page"]),
                                 (app(en["button"]), app(en["again"]), f"{app(settings)} › {app(tab)}"))
                self.assertEqual({key: fields(words[key]) for key in en}, {key: fields(en[key]) for key in en})


if __name__ == "__main__":
    unittest.main()

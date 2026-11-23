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
import unittest
import unittest.mock

import hub
import test_agent_auth
from leftovers import scratch_home
from test_agent_auth import BOX, KEYS

REFUSED = {"type": "error", "code": hub.AUTH_FAILED, "message": "Not logged in · Please run /login",
           "retryable": False, "resets_at": None}       # as the first fleet's hub had it, 16 November 2026
LINE = {"type": "user_message", "text": "New fleet messages."}     # a turn begins at a line
# Claude's refusal of the owner's own seat of a Claude Team organization, 23 November 2026 (its transcript row, as
# threads.py turns it into a record)
ORG_REFUSED = {"type": "error", "code": "oauth_org_not_allowed", "message": "Your organization has disabled Claude "
               "subscription access for Claude Code · Use an Anthropic API key instead, or ask your admin to enable "
               "access", "retryable": False, "resets_at": None}


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
        self.assertIn("raise one that asks the owner to open Example Developer in the app and sign it in", to_manager)
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
        again holds it again, and a turn that works ends that."""
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
        self.assertIn("raise one that asks the owner to open Example Developer in the app and sign it in", told[0])
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


if __name__ == "__main__":
    unittest.main()

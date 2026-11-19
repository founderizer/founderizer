"""A task that is blocked for want of access, from the worker's ask to the end of it: the ask names the thing itself,
the hub says which of the three routes it is, and the two outcomes follow - the manager grants it from the pool, or
takes it to the owner. Then the last step: the blocked task itself continues, because `restart_task` starts it once
more in a session that holds the access. Plus the one sentence that says what each agent looks after, which is how an
agent finds the agent that can help. In-process hub and temporary Git repositories; no helper, vault, GitHub, Google
or AI call."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch
import uuid

import door
import hub
from test_setup import git
from test_ui_api import OwnerAPI

WEB, BILLING = "repo:acme/web", "repo:acme/billing"
GONE = "secret:bws://11111111-2222-4333-8444-55555555555b"      # a standing whose secret left the catalog
TEAM = {
    "hub": {"machine": "hub", "port": 8765},
    "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "box": "127.0.0.3", "opsbox": "127.0.0.4",
                  "devbox": "127.0.0.5"},
    "agents": {
        "manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
        "lead": {"role": "lead", "runtime": "claude", "machine": "box", "can": ["shell"]},
        "dev": {"role": "worker", "runtime": "claude", "machine": "devbox", "can": ["shell"], "title": "Developer",
                "expertise": ["development"]},
        "ops": {"role": "worker", "runtime": "claude", "machine": "opsbox", "can": ["shell"], "title": "Systems",
                "expertise": ["infra"], "repos": {"acme/web": "write"}},
        "web": {"role": "worker", "runtime": "claude", "machine": "box", "can": ["shell"], "title": "Web",
                "reports_to": "lead", "expertise": ["development"]}},
    "resources": {}}
SAYS = {"dev": "The shop's own code: its pages, its checkout and its tests.",
        "web": "The shop's pages under the lead.",
        "ops": "The machines: the server at app-1, DNS, the certificates and the deploys.",
        "lead": "The work of the agents that report to it.",
        "manager": "Managing Fleet and its operation."}


def profile(name):
    return (f"# Profile: {name}\n\nWritten by the owner. Agents cannot change it.\n\n**Character.** Exact.\n\n"
            f"**Responsible for.** {SAYS[name]}\n\n**May do without asking.** Read files.\n\n"
            f"**Must ask first.** Spending.\n")


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(BlockedAccess(name) for name in BlockedAccess.__dict__ if name.startswith("test_"))


class BlockedAccess(OwnerAPI):
    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="fleet-blocked-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        seed = self.root / "seed"
        (seed / "profiles").mkdir(parents=True)
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        for name in SAYS:
            (seed / "profiles" / f"{name}.md").write_text(profile(name))
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", str(self.root / "origin.git"), str(self.root / "kit"))
        hub.CFG["team_path"] = str(self.root / "kit" / "team.json")
        self.addCleanup(hub.CFG.pop, "team_path", None)
        hub.CFG["google_file"] = str(self.root / "no-google.json")
        self.addCleanup(hub.CFG.pop, "google_file", None)
        hub.CFG["github_app"] = str(self.root / "no-github-app")    # the repository of a session, with no GitHub call
        self.addCleanup(hub.CFG.pop, "github_app", None)
        hub._revision_cache.update(at=0.0, value=None)
        hub._responsible.clear()
        self.addCleanup(hub._responsible.clear)
        hub.TEAM = json.loads(json.dumps(TEAM))
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90, tick=5,
                       ask_wait=0, ask_max=0)

    # ---- helpers

    def call(self, agent, name, args, task=None):
        context = ("test-generation", hub.tref(task), hub.q1("SELECT attempt FROM tasks WHERE id=?",
                                                             (task,))["attempt"]) if task else None
        return hub.call_tool(agent, name, args, context)

    def ok(self, agent, name, args, task=None):
        text, error = self.call(agent, name, args, task)
        self.assertFalse(error, text)
        return text

    def refused(self, agent, name, args, task=None):
        text, error = self.call(agent, name, args, task)
        self.assertTrue(error, text)
        return text

    def task_for(self, owner, requester="manager", parent=None):
        self.ok(requester, "create_task", {"owner": owner, "title": "Ship the shop page", "done_when": "It is live.",
                                           "why": "Its expertise."}, parent)
        return hub.q1("SELECT MAX(id) id FROM tasks")["id"]

    def ask(self, agent, task, question="May I have it?", **fields):
        return self.ok(agent, "ask_my_requester", dict({"question": question}, **fields), task)

    def said_to(self, agent):
        """The newest [hub] message that this agent's session got."""
        row = hub.q1("SELECT text FROM events WHERE agent=? AND kind='say' ORDER BY id DESC LIMIT 1", (agent,))
        return row["text"] if row else ""

    def stand(self, resource, policy):
        code, result = self.request("/ui/resources", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                      "base_sha256": self.request("/ui/resources?db=test-generation")[1]["sha256"],
                                                      "resource": resource, "policy": policy})
        self.assertEqual(code, 200, result)
        return result

    def committed(self):
        return json.loads((self.root / "kit" / "team.json").read_text())

    def holds(self, agent, repos):
        """What team.json gives this agent now. Every owner write and every grant commits team.json and reads it
        back, so a hold set here is set again after one of those."""
        hub.TEAM["agents"][agent]["repos"] = repos

    def grant(self, agent, resource, level):
        return self.ok("manager", "grant_access", {"request_id": str(uuid.uuid4()), "agent": agent,
                                                   "resource": resource, "level": level})

    def restart(self, task, **changes):
        return self.call("manager", "restart_task", dict(
            {"task_id": hub.tref(task), "request_id": str(uuid.uuid4()), "expected_attempt": 1,
             "reason": "the access that it asked for is granted"}, **changes))

    def stop_confirmed(self, task):
        """The helper's report of the stop, as POST /helper/control takes it: the hold is settled, and then the second
        half of the restart runs. This fixture has no helper, so the test is the report."""
        with hub.LOCK:
            hold = hub.q1("SELECT * FROM holds WHERE task=? ORDER BY id DESC LIMIT 1", (task,))
            hub.settle_hold(hold, True, "interrupted and closed")
            hub.restart_continue(hold["id"])
        return hold["id"]

    def session_of(self, agent, address):
        """What the helper gives that agent's next task session (POST /helper/integrations)."""
        code, data = self.request(f"/helper/integrations/{agent}", {}, source=address)
        self.assertEqual(code, 200, data)
        return data

    # ---- the ask carries the thing it needs

    def test_the_ask_names_the_resource_and_the_question_keeps_it(self):
        tid = self.task_for("dev")
        text = self.ask("dev", tid, needs_access="repo:ACME/Web")        # the id is one thing, in one case
        self.assertIn("the GitHub repository acme/web (repo:acme/web) as the access that you need", text)
        row = hub.q1("SELECT * FROM questions ORDER BY id DESC LIMIT 1")
        self.assertEqual((row["asker"], row["requester"], row["access"]), ("dev", "manager", WEB))
        self.assertEqual(hub.q1("SELECT waiting_on FROM tasks WHERE id=?", (tid,))["waiting_on"], f"Q-{row['id']}")
        self.assertIn("needs_access must be <kind>:<what>", self.refused(
            "dev", "ask_my_requester", {"question": "q", "needs_access": "database:shop"}, tid))
        self.ask("dev", self.task_for("dev"))                    # an ask that is not about access carries none
        self.assertIsNone(hub.q1("SELECT access FROM questions ORDER BY id DESC LIMIT 1")["access"])

    def test_the_ask_names_the_level_when_the_hold_it_has_is_below_what_the_work_needs(self):
        """The half that makes a higher level reachable at all. An agent that holds acme/web at write and must change
        a workflow file holds no access for that work, but the thing it would name is the thing it already has. So
        the ask names the level too, and the hub reads the ask as unsatisfied."""
        self.holds("dev", {"acme/web": "write"})
        tid = self.task_for("dev")
        text = self.ask("dev", tid, "I must change .github/workflows/deploy.yml.", needs_access=WEB,
                        needs_level="deploy")
        self.assertIn("the GitHub repository acme/web (repo:acme/web) at deploy as the access that you need", text)
        row = hub.q1("SELECT * FROM questions ORDER BY id DESC LIMIT 1")
        self.assertEqual((row["access"], row["access_level"]), (WEB, "deploy"))
        told = self.said_to("manager")
        self.assertIn("ACCESS NEEDED: dev needs the GitHub repository acme/web (repo:acme/web) at deploy, and "
                      "team.json gives it at write only, which does not reach deploy.", told)
        self.assertNotIn("so its next session has it", told)      # never read as settled by the hold it had
        self.assertIn("A grant is not the whole of it: deploy needs the Workflows and Actions permissions", told)
        # The ask is a request and not a grant: what the agent holds is what team.json gave it, before and after.
        self.assertEqual(self.session_of("dev", "127.0.0.5")["repos"], {"acme/web": "write"})
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM resource_grants")["n"], 0)

        # The grant the manager is sent to is the level the TASK named and not the ceiling the owner allows.
        self.stand(WEB, {"max": "deploy"})          # a standing is a commit of team.json, so the hold is set again
        self.holds("dev", {"acme/web": "read"})
        self.ask("dev", self.task_for("dev"), needs_access=WEB, needs_level="write")
        self.assertIn('It is in the grantable pool, up to deploy: grant_access(agent="dev", '
                      'resource="repo:acme/web", level="write") settles it.', self.said_to("manager"))

        # And the pool is still the authority: a level above the ceiling is the owner's, not the manager's.
        self.stand(WEB, {"max": "write"})
        self.holds("dev", {"acme/web": "write"})
        self.ask("dev", self.task_for("dev"), needs_access=WEB, needs_level="deploy")
        self.assertIn("The owner allows at most write of the GitHub repository acme/web, and you asked for deploy. "
                      "Give write, or ask the owner for deploy.", self.said_to("manager"))

        # A level the kind does not have, and a level with no thing beside it, are both refused at the ask.
        self.assertIn("needs_level must be one of read, write, deploy for a GitHub repository", self.refused(
            "dev", "ask_my_requester", {"question": "q", "needs_access": WEB, "needs_level": "admin"}, tid))
        self.assertIn("needs_level is the level of needs_access", self.refused(
            "dev", "ask_my_requester", {"question": "q", "needs_level": "deploy"}, tid))

    def test_a_grant_below_the_level_the_task_asked_for_leaves_it_blocked(self):
        """The two ways a half grant could have gone wrong: a restart that starts a session which GitHub refuses in
        exactly the same way, and an answer that tells the manager the task needs nothing more."""
        self.stand(WEB, {"max": "deploy"})
        self.holds("dev", {"acme/web": "read"})
        tid = self.task_for("dev")
        self.ask("dev", tid, "May I run its Actions?", needs_access=WEB, needs_level="deploy")
        qid = hub.q1("SELECT id FROM questions ORDER BY id DESC LIMIT 1")["id"]
        self.assertIn(f"T-{tid} waits at Q-{qid} for the GitHub repository acme/web at deploy (repo:acme/web), and "
                      f"dev holds it at read only: a new session would lack it too", self.restart(tid)[0])

        said = self.grant("dev", WEB, "write")
        self.assertIn(f"T-{tid} waits at Q-{qid} for it at deploy, which this grant does not reach: it stays blocked "
                      f"until it holds deploy.", said)
        self.assertNotIn("restart_task(", said)
        self.assertIn("dev holds it at write only: a new session would lack it too", self.restart(tid)[0])
        self.assertEqual(self.ok("manager", "answer", {"question_id": f"Q-{qid}", "text": "Not yet."}),
                         f"Answered Q-{qid}.")              # no "it holds it now, restart the task"

        # Then the level itself, and the whole path opens: the receipt also says the owner's own step on GitHub.
        self.ask("dev", tid, "May I run its Actions?", needs_access=WEB, needs_level="deploy")
        qid = hub.q1("SELECT id FROM questions ORDER BY id DESC LIMIT 1")["id"]
        said = self.grant("dev", WEB, "deploy")
        self.assertIn("dev now has the GitHub repository acme/web at level deploy", said)
        self.assertIn("Deploy needs the Workflows and Actions permissions on the hub's GitHub App", said)
        self.assertIn(f'restart_task(task_id="T-{tid}", expected_attempt=1, ...) starts it once more', said)
        self.assertIn(f"The restart of T-{tid} is requested", self.restart(tid)[0])
        self.stop_confirmed(tid)
        start = hub.q1("SELECT text FROM events WHERE agent='dev' AND kind='task' ORDER BY id DESC LIMIT 1")["text"]
        self.assertIn(f"Q-{qid} asked for the GitHub repository acme/web at deploy, which dev holds at deploy now",
                      start)
        self.assertIn("GitHub refuses its deploy token until the hub's GitHub App carries the Workflows and Actions "
                      "permissions and you accept them on the App's installation page.",
                      hub.q1("SELECT text FROM owner_reports ORDER BY id DESC LIMIT 1")["text"])

    # ---- the three routes, read at the moment the requester sees them

    def test_the_manager_reads_which_of_the_three_it_is(self):
        tid = self.task_for("dev")
        self.ask("dev", tid, needs_access=WEB)
        told = self.said_to("manager")
        self.assertIn("ACCESS NEEDED: dev needs the GitHub repository acme/web (repo:acme/web), and team.json gives "
                      "it none of it.", told)
        self.assertIn("Held now by ops (write): ops can do this part of the work, or answer the question from it: "
                      "give that part to ops with create_task.", told)      # ask the one that holds it
        self.assertNotIn("Needs-you", told)     # the owner, 29 October 2026: an agent holds it, so he is not asked
        self.assertIn("ACCESS NEEDED: dev needs the GitHub repository acme/web", self.ok("manager", "see_team", {}))

        self.stand(WEB, {"max": "write"})                   # the owner makes it grantable, and only that changes
        self.assertIn('grant_access(agent="dev", resource="repo:acme/web", level="write") settles it. The grant '
                      'reaches its next session, so restart_task then starts this task again in a session that has it.',
                      self.ok("manager", "see_team", {}))

        # A standing whose thing left team.json: the manager is told so, never sent to a tool that would refuse it.
        hub.TEAM["resources"] = {GONE: {"max": "use"}}
        self.ask("dev", self.task_for("dev"), needs_access=GONE)
        self.assertIn(f"The fleet does not hold the secret {GONE.split(':', 1)[1]} any more. Tell the owner.",
                      self.said_to("manager"))

    def test_a_resource_that_the_fleet_does_not_hold_at_all_is_the_owners(self):
        tid = self.task_for("dev")
        self.ask("dev", tid, needs_access=BILLING)
        told = self.said_to("manager")
        self.assertIn("The owner set no standing for it and no agent holds it, so the manager cannot give it: raise a "
                      "Needs-you item and say what the work needs it for.", told)
        self.assertNotIn("Held now by", told)
        self.assertNotIn("grant_access", told)
        # The question outlives its asker: see_team is the manager's own view, so the line never raises there.
        hub.TEAM["agents"].pop("dev")
        self.assertIn("ACCESS NEEDED: repo:acme/billing, which the hub cannot read any more",
                      self.ok("manager", "see_team", {}))

    def test_a_lead_is_sent_to_the_manager_because_it_cannot_grant(self):
        parent = self.task_for("lead")
        self.stand(WEB, {"max": "write"})
        tid = self.task_for("web", requester="lead", parent=parent)
        self.ask("web", tid, needs_access=WEB)
        told = self.said_to("lead")
        self.assertIn("ops can do this part of the work, or answer the question from it, and it is outside your "
                      "team.", told)
        self.assertIn("only the manager gives it. Pass the question up with answer(..., pass_up=true)", told)
        self.assertNotIn("grant_access(", told)
        self.assertIn("only the manager gives it", self.ok("lead", "see_team", {}, parent))

    # ---- the two outcomes

    def test_outcome_one_the_manager_grants_it_and_the_task_goes_on(self):
        tid = self.task_for("dev")
        self.ask("dev", tid, needs_access=WEB)
        qid = hub.q1("SELECT id FROM questions ORDER BY id DESC LIMIT 1")["id"]
        self.stand(WEB, {"max": "write"})
        self.assertIn("dev now has the GitHub repository acme/web at level write", self.ok("manager", "grant_access", {
            "request_id": str(uuid.uuid4()), "agent": "dev", "resource": WEB, "level": "write"}))
        self.assertEqual(self.committed()["agents"]["dev"]["repos"], {"acme/web": "write"})
        self.assertEqual([(r["agent"], r["level"], r["by"]) for r in hub.q("SELECT agent, level, by FROM "
                          "resource_grants WHERE resource=?", (WEB,))], [("dev", "write", "manager")])
        # An answer alone leaves the task in the session that cannot use the grant, so the answer says so itself.
        self.assertEqual(self.ok("manager", "answer", {"question_id": f"Q-{qid}", "text": "You have it now."}),
                         f"Answered Q-{qid}. dev holds the GitHub repository acme/web at write now, but the session of "
                         f"T-{tid} cannot use it: a running session keeps what it started with. Your answer does not "
                         f"change that, and the task needs no follow-up: restart_task starts T-{tid} once more in a "
                         f"session that has the access, with everything it already did.")
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (tid,))["state"], "working")
        # The ask that follows reads the grant, not the words of the first one: the route is the facts of the moment.
        self.ask("dev", tid, needs_access=WEB)
        self.assertIn("gives it at write already, so its next session has it", self.said_to("manager"))

    def test_outcome_two_the_manager_takes_it_to_the_owner(self):
        tid = self.task_for("dev")
        self.ask("dev", tid, needs_access=BILLING)
        self.assertIn("Raised N-", self.ok("manager", "raise_needs_you", {
            "title": "dev needs the repository acme/billing",
            # owner feature need_talk: the words he reads name the work, never its code
            "why": "Dev's task is blocked: no agent holds repo:acme/billing and it is in no standing of yours.",
            "what_to_do": "Add acme/billing to the GitHub App, then make it grantable.",
            "reason": "access", "needs_access": "repo:acme/billing"}))
        need = hub.q1("SELECT * FROM needs ORDER BY id DESC LIMIT 1")
        self.assertEqual(need["by"], "manager")
        self.assertIn("repo:acme/billing", need["why"])
        self.assertIn("acme/billing", need["title"])

    # ---- the last step: the blocked task itself continues, in a session that holds the access

    def test_the_blocked_task_continues_in_a_new_session_that_holds_the_access(self):
        """The whole path, from the ask to the session that can do the work. The grant reaches the agent's next task
        session only, so the task that waits at the question needs a new one: restart_task gives it that, with
        everything it already did and a check of its last actions."""
        self.stand(WEB, {"max": "write"})
        tid = self.task_for("dev")
        self.ok("dev", "report_progress", {"note": "I read the shop's pages."}, tid)
        self.ask("dev", tid, "The fix is written. May I push it?", needs_access=WEB)
        qid = hub.q1("SELECT id FROM questions ORDER BY id DESC LIMIT 1")["id"]
        self.assertIn('grant_access(agent="dev", resource="repo:acme/web", level="write") settles it. The grant '
                      'reaches its next session, so restart_task then starts this task again in a session that has '
                      'it.', self.said_to("manager"))
        # The access comes first: a restart before the grant is refused, and it names the thing that is missing.
        self.assertEqual(self.restart(tid)[0],
                         f"T-{tid} waits at Q-{qid} for the GitHub repository acme/web (repo:acme/web), and dev does "
                         f"not hold it yet: a new session would lack it too. Settle the access first, and restart "
                         f"T-{tid} after that.")
        self.assertEqual(hub.q1("SELECT COUNT(*) c FROM holds")["c"], 0)        # a refused call holds nothing

        # The grant, and the one step that the manager reads with it: the task that waits for exactly this access.
        self.assertIn(f"T-{tid} waits at Q-{qid} for it, and its session cannot use the grant: "
                      f'restart_task(task_id="T-{tid}", expected_attempt=1, ...) starts it once more in a session '
                      f"that has it.", self.grant("dev", WEB, "write"))
        text = self.ok("manager", "restart_task", {"task_id": hub.tref(tid), "request_id": str(uuid.uuid4()),
                                                   "expected_attempt": 1, "reason": "the repository is granted"})
        hold = hub.q1("SELECT * FROM holds WHERE task=? ORDER BY id DESC LIMIT 1", (tid,))
        self.assertIn(f"The restart of T-{tid} is requested (H-{hold['id']})", text)
        self.assertEqual((hold["kind"], hold["by"], hold["state"], hold["attempt"]), ("stop", "manager", "requested", 1))
        self.assertEqual(hub.q1("SELECT state FROM restart_holds WHERE hold=?", (hold["id"],))["state"], "pending")
        self.assertEqual((hub.q1("SELECT COUNT(*) c FROM events WHERE agent='dev' AND kind='control'")["c"],
                          hub.q1("SELECT attempt FROM tasks WHERE id=?", (tid,))["attempt"]), (1, 1))

        self.assertEqual(self.stop_confirmed(tid), hold["id"])
        task, hold = hub.q1("SELECT * FROM tasks WHERE id=?", (tid,)), hub.q1("SELECT * FROM holds WHERE id=?",
                                                                             (hold["id"],))
        self.assertEqual((task["attempt"], task["restarts"], task["state"], task["waiting_on"]), (2, 0, "working", None))
        self.assertEqual((hold["state"], hold["resume_mode"], hub.q1("SELECT state FROM restart_holds WHERE hold=?",
                                                                     (hold["id"],))["state"]),
                         ("released", "check", "done"))
        self.assertEqual(hub.q1("SELECT COUNT(*) c FROM tasks")["c"], 1)        # the same task, not a follow-up
        self.assertEqual([r["text"] for r in hub.q("SELECT text FROM notes WHERE task=?", (tid,))],
                         ["I read the shop's pages."])                          # and nothing it did was thrown away

        # The new session: the access it asked for, the check of its last actions, and no browser words.
        start = hub.q1("SELECT * FROM events WHERE agent='dev' AND kind='task' ORDER BY id DESC LIMIT 1")
        outcome = hub.q1("SELECT * FROM outcomes WHERE task=? ORDER BY id DESC LIMIT 1", (tid,))
        self.assertEqual(json.loads(start["extra"]), {"needs": "none", "resume": True, "attempt": 2,
                                                      "generation": "test-generation"})
        for part in (f"T-{tid} is resumed by the manager, with a check.", "without repeating any of them",
                     f"O-{outcome['id']} Attempt 1 was stopped for a restart (the repository is granted): check what "
                     f"its last actions did",
                     "The access that you asked for is settled, and this session has it: "
                     f"Q-{qid} asked for the GitHub repository acme/web, which dev holds at write now. Go on with "
                     f"the task and do not ask for it again.",
                     f"Your question Q-{qid} ended with the earlier session"):
            self.assertIn(part, start["text"])
        self.assertNotIn("browser", start["text"])
        self.assertEqual((outcome["state"], outcome["attempt"]), ("unknown", 1))
        self.assertEqual(hub.q1("SELECT answer FROM questions WHERE id=?", (qid,))["answer"],
                         hub.RESTART_ANSWER.format(by="manager", task=f"T-{tid}"))
        self.assertEqual(self.session_of("dev", "127.0.0.5")["repos"], {"acme/web": "write"})

        # The earlier attempt cannot report, and the new one checks before it delivers (rule 9).
        self.assertEqual(hub.call_tool("dev", "report_progress", {"note": "late"},
                                       ("test-generation", f"T-{tid}", 1)),
                         ("STOP: stale or wrong task attempt. Do not report, deliver, or continue work.", True))
        gate = "STOP: first find out whether these earlier actions took effect"
        self.assertIn(gate, self.call("dev", "deliver_result", {"what_was_done": "Pushed the fix.",
                                                                "where_output_is": "acme/web", "how_checked": "CI"}, tid)[0])
        self.ok("dev", "resolve_outcome", {"outcome_id": f"O-{outcome['id']}", "finding": "not_done",
                                           "evidence": "The repository has no commit of mine."}, tid)
        self.ok("dev", "deliver_result", {"what_was_done": "Pushed the fix.", "where_output_is": "acme/web",
                                          "how_checked": "The CI run of the commit is green."}, tid)

    def test_a_restart_for_access_needs_a_hold_of_it(self):
        """The gate is the ask and team.json, nothing else: an ask for access that nobody holds refuses a restart,
        and a hold that the owner gave himself counts like any other. A task with no ask for access restarts too
        (plan C6: no kind of task refuses restart_task)."""
        plain = self.task_for("dev")
        self.ok("dev", "report_progress", {"note": "I started."}, plain)
        self.assertIn(f"The restart of T-{plain} is requested", self.restart(plain)[0])
        tid = self.task_for("dev")
        self.ok("dev", "report_progress", {"note": "I started."}, tid)
        self.ask("dev", tid, "May I have it?", needs_access=BILLING)
        self.assertIn("dev does not hold it yet", self.restart(tid)[0])
        # The owner's own grant on the Access page is a hold like the manager's: the gate reads team.json.
        hub.TEAM["agents"]["dev"]["repos"] = {"acme/billing": "read"}
        self.assertIn(f"The restart of T-{tid} is requested", self.restart(tid)[0])
        self.stop_confirmed(tid)
        self.assertIn("which dev holds at read now",
                      hub.q1("SELECT text FROM events WHERE agent='dev' AND kind='task' ORDER BY id DESC LIMIT 1")["text"])
        self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (tid,))["attempt"], 2)

    # ---- a new grant reaches the door at the owner's Mac's next door round

    def linked_door(self, file):
        """This hub gets every GitHub token from its door (DevOps plan 13, item 4), whose access file gives `file`,
        {agent: {owner/name: level}}: the door's own code refuses what the file does not hold, in its own words
        (door.Door.github_tokens), and a grant of the file gets a token, as GitHub gives it. A door round of the owner's
        Mac is this test's read of GET /ui/door, and the test writes the file as such a round would."""
        code, got = self.request("/ui/door", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                              "address": "100.64.0.9", "port": 8766})
        self.assertEqual(code, 200, got)
        (self.root / "door.json").write_text(json.dumps({"token": "token-secret", "record": "record-secret"}))
        hub.CFG["door_secrets"] = str(self.root / "door.json")
        self.addCleanup(hub.CFG.pop, "door_secrets", None)
        real = door.Door.__new__(door.Door)
        real.access = lambda: {"agents": {a: {"github": dict(g)} for a, g in file.items()}}
        real.record = types.SimpleNamespace(add=lambda **_: None)
        levels = list(door.GITHUB_ACCESS)

        def answer(_conf, _method, path, _secret, body=None):
            if path != "/github/token":
                return 404, {"error": "no such route"}
            held = file.get(body["agent"], {})
            given = {r: v for r, v in body["repos"].items() if r in held and levels.index(held[r]) >= levels.index(v)}
            try:
                _, errors = real.github_tokens(body["agent"], {r: v for r, v in body["repos"].items() if r not in given})
            except door.Refused as e:
                return 403, {"error": str(e)}
            return 200, {"tokens": [{"token": "ghs_" + "a" * 36, "access": v, "repos": [r]} for r, v in given.items()],
                         "errors": errors}
        for patcher in [patch.object(hub, name, value) for name, value in (
                ("door_call", answer), ("DOOR_ROUNDS", []), ("DOOR_SWEPT", {"round": None}), ("DOOR_OLD_READS", []),
                ("DOOR_MARKS", {}), ("DOOR_HELD", {"at": None}), ("DOOR_SPOKE", {"at": None}))] + \
                [patch.dict(hub.DOOR_RENEW)]:        # a read with renew=form sets its time, and no later test sees it
            patcher.start()
            self.addCleanup(patcher.stop)

    def door_round(self, held=None):
        """A door round of the owner's Mac starts: it reads the hub's view (DoorSync), and the tick runs after it. held:
        the mark of the view whose plan the door's file holds, as an app since owner API 1.234 says it ("" for none);
        None for an app before that word. Gives the mark of the view that the read got."""
        code, view = self.request("/ui/door?db=test-generation&renew=form" + ("" if held is None else f"&held={held}"))
        self.assertEqual(code, 200, view)
        with hub.LOCK:
            hub.door_grants_sweep(hub.now())
            hub.restart_sweep(hub.now())
        return view["mark"]

    def attempt(self, task):
        return hub.q1("SELECT attempt FROM tasks WHERE id=?", (task,))["attempt"]

    def owner_gives(self, repo, level):
        code, got = self.request("/ui/team/repos", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                    "base_sha256": self.request("/ui/team?db=test-generation")[1]["sha256"],
                                                    "repo": repo, "agent": "dev", "level": level})
        self.assertEqual(code, 200, got)

    def test_a_restart_right_after_a_grant_starts_its_session_once_the_door_has_the_grant(self):
        """18 November 2026: the owner gave an agent write on a repository, the manager restarted its task 9 seconds
        later, and the new session had no token, because a grant reaches the door only at the owner's Mac's next door
        round. The manager read the door's refusal as a defect, and the task waited a day. Now the restart stops the
        session at once and starts the new one after that round, with the token. A restart of an attempt that did not
        ask for the new grant starts at once, as before: it may be for something else, such as a lost browser. Here the
        Mac's app is one before owner API 1.234, whose reads say nothing of the door's file: for it two reads after the
        grant stay the event."""
        file = {"dev": {}}
        self.linked_door(file)
        tid = self.task_for("dev")
        self.ask("dev", tid, "The fix is written. May I push it?", needs_access=WEB)
        self.door_round()                       # a round that read the hub's view before the grant cannot write it
        self.owner_gives("acme/web", "write")
        self.assertIn("[hub] The owner gave dev write access to the GitHub repository acme/web. An agent gets the "
                      "change in its next task session. The door gets a new grant at the owner's Mac's next door round",
                      self.said_to("manager"))
        refused = self.session_of("dev", "127.0.0.5")["errors"]       # the door's refusal of one repository
        self.assertEqual([e["repos"] for e in refused], [["acme/web"]])
        self.assertIn("This is no defect. If this task needs it, ask your requester", refused[0]["error"])
        self.assertIn("When dev's helper confirms the stop and the owner's Mac's next door round has given the door "
                      "dev's new grant of acme/web", self.restart(tid)[0])
        self.stop_confirmed(tid)
        self.assertEqual(self.attempt(tid), 1)          # stopped, and no new session that would have no token
        self.assertIn("already waits for the owner's Mac's next door round", self.restart(tid)[0])
        self.door_round()                       # this round holds the grant and writes it into the door's file
        file["dev"]["acme/web"] = "write"
        self.assertEqual(self.attempt(tid), 1)          # the hub sees a round start, not its end
        self.door_round()                       # and the app starts the next round only after that one ended
        self.assertEqual(self.attempt(tid), 2)
        self.assertEqual(self.session_of("dev", "127.0.0.5")["errors"], [])
        self.assertIsNone(hub.kv_get(hub.DOOR_GRANTS))      # a hub that starts again holds no restart for it

        self.owner_gives("acme/web", "deploy")      # a new grant of the same repository, which attempt 2 never asked for
        self.assertNotIn("door round", self.restart(tid, expected_attempt=2)[0])
        self.stop_confirmed(tid)
        self.assertEqual(self.attempt(tid), 3)

    def test_only_the_macs_word_that_the_doors_file_holds_the_grant_ends_the_wait(self):
        """The hole of the two reads (19 November 2026, release 2026.11.594): the hub saw only the start of each door
        round, and took the second read after a grant for the end of the round that wrote it. A read that wrote nothing
        (the GitHub App flow reads GET /ui/door too; a round stops after its read when its SSH fails or the app starts
        again) so ended a restart's wait one round early, and the new session had no token. Since owner API 1.234 the
        app's round says which view of the hub the door's file holds (held=<mark>): reads that name none, a view from
        before the grant, or a mark that the hub never gave, hold the restart however many come, and once two rounds
        went by its words say how old the door's file is, never while the rounds work; the word for a view after the
        grant starts it at once, also for a view that the hub gives again after the grant was lowered and given back."""
        file = {"dev": {}}
        self.linked_door(file)
        tid = self.task_for("dev")
        self.ask("dev", tid, "The fix is written. May I push it?", needs_access=WEB)
        for _ in range(2):
            self.door_round(held="")            # an app that has just started names no view, and its rounds stop
        before = self.door_round(held="")       # after their read: the hub cannot know what the door's file holds
        self.assertIn("door's access file has not taken the hub's view since the hub started", hub.door_round_seen())
        self.assertEqual(self.door_round(held=before), before)      # this round wrote the file from it, and says so
        self.owner_gives("acme/web", "write")
        self.restart(tid)
        self.stop_confirmed(tid)
        after = self.door_round(held=before)    # the round that reads the grant: the door's file holds the old view
        self.assertNotEqual(after, before)
        self.assertNotIn("door's access file", self.restart(tid)[0])        # while that round writes, nothing is wrong
        for held in ("", "", before, "0" * 32):     # the GitHub App flow twice, a round that stopped after its read,
            self.door_round(held=held)              # and a mark that the hub never gave
        self.assertEqual(self.attempt(tid), 1)      # five reads after the grant, and none of them wrote it
        self.assertIn("and the door's access file is as the hub had it", self.restart(tid)[0])
        file["dev"]["acme/web"] = "write"           # a round wrote the view with the grant, and says so at its end
        self.door_round(held=after)
        self.assertEqual(self.attempt(tid), 2)
        self.assertEqual(self.session_of("dev", "127.0.0.5")["errors"], [])
        self.assertIsNone(hub.kv_get(hub.DOOR_GRANTS))      # a hub that starts again holds no restart for it

        self.owner_gives("acme/web", "read")        # lowered and given back: a new grant, and the view of before
        self.owner_gives("acme/web", "write")
        self.ask("dev", tid, "My session has no token for acme/web.", needs_access=WEB)
        self.restart(tid, expected_attempt=2)
        self.stop_confirmed(tid)
        self.assertEqual(self.attempt(tid), 2)
        self.assertEqual(self.door_round(held=after), after)        # that view, given again, takes this read's time
        self.assertEqual(self.attempt(tid), 3)
        self.owner_gives("acme/billing", "read")    # a grant that a round reads,
        read = self.door_round(held=after)
        self.owner_gives("acme/billing", "write")   # another while that round writes,
        self.door_round(held=read)                  # that round's end, which names the view that it read,
        self.door_round(held=read)                  # and the next round's start: both rounds work, nothing is wrong
        self.assertNotIn("door's access file", hub.door_round_seen())

    def test_a_session_that_starts_before_the_door_has_a_new_grant_says_why_and_that_it_is_no_defect(self):
        """The same morning the manager gave an agent write on a repository and made its task at once. The session had
        no token, and its start gave only the door's refusal, which the manager read as a defect. Now the start text
        and the manager's lines say that the door gets the grant at the owner's Mac's next door round, and how the
        task gets it. A grant that the door still refuses after that round keeps the door's own words: a fault."""
        self.linked_door({})                    # the agent's first grant: the door's file has no entry for it yet
        self.stand(WEB, {"max": "write"})
        self.assertIn("The door gets a new grant at the owner's Mac's next door round, usually within 10 minutes",
                      self.grant("dev", WEB, "write"))
        tid = self.task_for("dev")
        refused = self.session_of("dev", "127.0.0.5")["errors"]
        self.assertEqual([e["repos"] for e in refused], [["acme/web"]])
        self.assertTrue(refused[0]["error"].startswith("the door gets this new grant at the owner's Mac's next door "
                                                       "round, usually within 10 minutes while the Mac's app runs (it "
                                                       "has started no door round in the "), refused)
        self.assertIn("This is no defect. If this task needs it, ask your requester to restart this task, with "
                      "needs_access repo:acme/web", refused[0]["error"])        # and no round is a Mac that is off
        self.ask("dev", tid, "My session has no token for acme/web.", needs_access=WEB)
        self.assertIn("That grant is new: the door gets it at the owner's Mac's next door round",
                      self.said_to("manager"))
        self.door_round()                       # two rounds that did not write the file: the door is at fault now
        self.door_round()
        self.assertEqual(self.session_of("dev", "127.0.0.5")["errors"],
                         [{"repos": ["acme/web"], "error": "the door gave no GitHub token: dev is not in the door's "
                                                           "access file"}])

    # ---- the sentence that says what an agent looks after

    def test_see_capacity_leads_with_what_each_agent_looks_after(self):
        text = self.ok("manager", "see_capacity", {})
        line = next(l for l in text.splitlines() if l.startswith("  ops "))
        self.assertIn("looks after: The machines: the server at app-1, DNS, the certificates and the deploys;", line)
        self.assertLess(line.index("looks after:"), line.index("expertise"))
        self.assertIn("looks after: The shop's own code", next(l for l in text.splitlines() if l.startswith("  dev ")))

    def test_a_duty_given_today_is_in_the_sentence_today(self):
        # A duty is its sentence, so what an agent looks after says the duty's own words and not a name derived
        # from them: set_duty lost title and why when the duty became a sentence, and this line followed it.
        self.ok("manager", "set_duty", {"request_id": str(uuid.uuid4()), "agent": "ops",
                                        "text": "Watch the nightly deploy of the shop and put a failed one right."})
        self.assertEqual(hub.looks_after("ops", hub.kit_revision()), SAYS["ops"].rstrip(".") +
                         ". Duties: Watch the nightly deploy of the shop and put a failed one right")
        self.assertIn("the deploys. Duties: Watch the nightly deploy of the shop and put a failed one right; "
                      "expertise infra", self.ok("manager", "see_capacity", {}))

    def test_a_login_registered_after_a_start_never_shows_in_part_in_what_an_agent_looks_after(self):
        """What an agent looks after is its profile's "Responsible for" line, cut before its last word when it is
        longer than LOOKS_AFTER_MAX. A line with no space in that part was cut where the cut fell, and the start texts
        that carry it are kept: a login registered after one was made is masked there only whole, so until 11 November
        2026 one that lay across the cut stayed in part. Now that cut goes back to where the run of characters starts,
        and with nothing left the line is the agent's role."""
        login, salt = "Look-Login-0123456789", "c0ffee"
        kit = self.root / "kit"
        (kit / "profiles" / "ops.md").write_text(profile("ops").replace(SAYS["ops"], "x" * 190 + login + " and DNS."))
        git("commit", "-qam", "A line with no space in its first 200 characters", cwd=kit)
        hub._revision_cache.update(at=0.0, value=None)
        hub._responsible.clear()
        tid = self.task_for("dev")                                  # its start text is kept, with the team in it
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES('crm',?,?,?,'')",
                (salt, hashlib.sha256((salt + login).encode()).hexdigest(), len(login)))
        self.assertEqual(hub.looks_after("ops", hub.kit_revision()), "Systems")
        kept = hub.q1("SELECT text FROM events WHERE agent='dev' AND kind='task' AND task=? ORDER BY id LIMIT 1",
                      (tid,))["text"]
        self.assertIn("looks after: Systems", kept)
        for said in (kept, hub.start_text("dev", tid), self.ok("manager", "see_capacity", {})):
            self.assertNotIn(login[:6], said)

    def test_a_login_that_ends_the_line_with_a_dot_never_shows_without_it(self):
        """What an agent looks after ends without the final dot of its profile's "Responsible for" line, and a login
        can end there in a dot of its own. Until 11 November 2026 the line kept the rest of it in every start text
        and on every read, because a search for the whole login never found it. Now the search finds a login whose
        last dots a line dropped, registered before the line was made or after."""
        login, salt = "Look-Login-0123456789.", "c0ffee"
        kit = self.root / "kit"
        (kit / "profiles" / "ops.md").write_text(profile("ops").replace(SAYS["ops"], "The deploys, with " + login))
        git("commit", "-qam", "A line that ends with a login", cwd=kit)
        hub._revision_cache.update(at=0.0, value=None)
        hub._responsible.clear()
        self.assertEqual(hub.looks_after("ops", hub.kit_revision()), "The deploys, with " + login[:-1])
        tid = self.task_for("dev")                                  # its start text is kept, with the team in it
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES('crm',?,?,?,'')",
                (salt, hashlib.sha256((salt + login).encode()).hexdigest(), len(login)))
        kept = hub.q1("SELECT text FROM events WHERE agent='dev' AND kind='task' AND task=? ORDER BY id LIMIT 1",
                      (tid,))["text"]
        self.assertIn("looks after: The deploys, with " + login[:-1], kept)     # made before the login was known
        code, capacity = self.request("/ui/capacity?db=test-generation")
        self.assertEqual(code, 200, capacity)
        for said in (hub.mask_secrets(kept), hub.scrub(kept), hub.start_text("dev", tid),
                     self.ok("manager", "see_capacity", {}), json.dumps(capacity)):
            self.assertNotIn(login[:6], said)

    def test_message_agent_shows_every_agent_and_what_it_looks_after(self):
        tid = self.task_for("dev")
        tool = next(t for t in hub.tools_for("dev", ("test-generation", hub.tref(tid), 1))
                    if t["name"] == "message_agent")
        # The directory is in the start block of the session (plan P9.1): no tool's text changes at run time.
        said = hub.start_text("dev", tid).split("YOUR TEAM", 1)[1]
        self.assertNotIn("looks after", tool["description"])
        self.assertIn("looks after: The machines: the server at app-1, DNS, the certificates and the deploys", said)
        self.assertIn("looks after: Managing Fleet", said)
        # The sentence is the owner's; what it holds is the fleet's own record, and on a fleet whose profiles keep
        # the line they were installed with it is the only thing that tells two workers apart.
        self.assertIn("expertise infra; GitHub acme/web (write); looks after: The machines", said)
        self.assertNotIn("dev [", said)                                  # not itself
        refused = self.refused("dev", "message_agent", {"request_id": str(uuid.uuid4()), "agent": "infra",
                                                        "text": "Who looks after the server?"}, tid)
        self.assertIn("there is no active agent named infra. The agents are: manager, lead, ops, web.", refused)
        self.assertIn("looks after: The shop's own code", hub.start_text("ops", self.task_for("ops")))


if __name__ == "__main__":
    unittest.main()

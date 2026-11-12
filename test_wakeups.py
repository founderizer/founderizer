"""Agent-managed wake-up rules (wakeups.py; owner corrections, 10 October 2026). The module tests need no hub: a
synthetic team, a set clock, no AI. The integration tests at the end check the hub glue of WAKEUPS-INTERFACE.md
with an in-process hub and a temporary database; they are skipped until the hub has that glue."""
import hashlib
import json
import unittest
import uuid
from unittest.mock import patch

import hub                  # an import or start failure of the hub fails these tests; it is never a skip
import lifecycle
import wakeups as w
from test_ui_api import OwnerAPI

HUB_GLUE = hasattr(hub, "wake_org")     # the one sign that the glue of WAKEUPS-INTERFACE.md section 5 exists


def load_tests(loader, _tests, _pattern):
    """Only the cases that each class of this file defines itself: HubGlue gets its server from OwnerAPI, whose own
    tests run in test_ui_api."""
    suite = unittest.TestSuite()
    for cls in (Authority, Routes, Grants, NoRunOn, SavedCode, StaleRules, Plans, Commands, Decisions, Texts,
                HubGlue):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite

CODEX_FULL = "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"
AGENTS = {
    "manager": {"role": "manager", "runtime": "claude", "start": "claude --permission-mode dontAsk {settings} {prompt}",
                "allow": ["mcp__fleet__*", "Bash"]},
    "vps": {"role": "worker", "runtime": "codex", "start": CODEX_FULL},
    "worker4": {"role": "worker", "runtime": "codex", "start": CODEX_FULL},
    "studio": {"role": "worker", "runtime": "claude", "start": "claude --permission-mode acceptEdits {chrome} {prompt}"},
    "seo": {"role": "worker", "runtime": "claude", "start": "claude --permission-mode acceptEdits {prompt}"},
    "lead-a": {"role": "lead", "runtime": "codex", "start": "codex --sandbox workspace-write {prompt}"},
    "lead-b": {"role": "lead", "runtime": "claude", "start": "claude --permission-mode dontAsk {settings} {prompt}"},
    "lead-old": {"role": "lead", "runtime": "claude", "start": "claude --permission-mode dontAsk {settings} {prompt}"},
    "dev": {"role": "worker", "reports_to": "lead-a", "runtime": "codex", "start": CODEX_FULL},
    "deeper": {"role": "worker", "reports_to": "dev", "runtime": "codex", "start": CODEX_FULL},
    "newbie": {"role": "worker", "active": False, "runtime": "codex", "start": CODEX_FULL},
}
TASK = {"title": "Look at the queue", "details": "", "done_when": "The queue is handled.", "needs": "none", "goal_id": None}
EVERY = {"kind": "every", "minutes": 15}
CHECK = {"code": "import json\nprint(json.dumps({'value': 11}))\n", "condition": {"op": ">", "value": 10}}


def org(agents=None, features=None):
    agents = AGENTS if agents is None else agents
    return w.Org("manager", agents, w.team_authority("manager", agents),
                 features=(lambda agent: (features or {}).get(agent, ())))


def rule(**kw):
    base = {"id": 7, "agent": "seo", "created_by": "seo", "state": "active", "paused_by": None,
            "revision": 3, "schedule": EVERY, "task": TASK, "check": None, "late_minutes": 60, "max_tasks_per_day": 4}
    return dict(base, **kw)


def refused(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except w.Refused as e:
        return str(e)
    raise AssertionError(f"{fn.__name__} did not refuse")


class Authority(unittest.TestCase):
    def test_levels_come_from_the_one_authority_function(self):
        o = org()
        self.assertEqual(w.level(o, "manager", "seo"), w.FLEET)
        self.assertEqual(w.level(o, "seo", "seo"), w.SELF)
        self.assertEqual(w.level(o, "lead-a", "seo"), w.NONE)                 # a lead sets nobody else's rules
        self.assertEqual(w.level(o, "lead-a", "dev"), w.NONE)                 # not even its own worker's
        self.assertEqual(w.level(o, "manager", "studio"), w.FLEET)
        self.assertEqual(w.level(o, "seo", "vps"), w.NONE)
        self.assertEqual(w.level(o, "ghost", "seo"), w.NONE)
        calls = []
        spy = w.Org("manager", AGENTS, lambda *a: calls.append(a) or (True, None))
        w.check_set(spy, "seo", "seo")
        self.assertEqual(calls, [("seo", "seo", "rule")])                      # the module asks; it never decides

    def test_an_agents_own_rule_is_its_own_and_the_managers_rule_is_the_managers(self):
        o = org()
        mine = rule(created_by="seo")
        self.assertIsNone(w.may_control(o, "seo", mine))
        self.assertIsNone(w.may_control(o, "manager", mine))
        self.assertIn("is not yours", refused(w.may_control, o, "lead-a", mine))
        self.assertFalse(w.may_read(o, "lead-a", mine))
        self.assertTrue(w.may_read(o, "seo", mine))                   # the target sees what wakes it
        self.assertTrue(w.may_read(o, "manager", mine))
        theirs = rule(created_by="manager")
        self.assertIn("You cannot change it", refused(w.may_control, o, "seo", theirs))
        self.assertIsNone(w.may_control(o, "manager", theirs))

    def test_current_authority_controls_reading_and_changing(self):
        o = org()
        r = rule(created_by="lead-old", check={"code": "saved", "sha256": "a" * 64, "bytes": 9,
                                               "code_by": "lead-old", "run_on": None})
        self.assertFalse(w.may_read(o, "lead-old", r))                 # its author, but no authority now
        self.assertIn("is not yours", refused(w.may_control, o, "lead-old", r))
        self.assertIsNone(w.may_control(o, "manager", r))              # the fleet manager takes it over
        ok, why = w.still_valid(o, dict(r, check=None))                # a prompt rule too
        self.assertFalse(ok)
        self.assertIn("lead-old set this rule and no longer has authority", why)
        gone = org(agents={n: a for n, a in AGENTS.items() if n != "seo"})
        ok, why = w.still_valid(gone, rule(created_by="manager"))
        self.assertEqual((ok, why), (False, "seo is no longer in the team."))

    def test_the_owner_rules_and_pauses_stay_the_owners(self):
        o = org()
        self.assertIn("Only the owner changes it", refused(w.may_control, o, "manager", rule(created_by="owner")))
        self.assertIn("Only the owner resumes it", refused(w.may_control, o, "seo", rule(paused_by="owner"), "resume"))
        self.assertIsNone(w.may_control(o, "seo", rule(state="paused", paused_by="hub"), "resume"))
        self.assertIsNone(w.may_control(o, "seo", rule(state="paused", paused_by="seo"), "resume"))
        self.assertIn("You cannot change it", refused(w.may_control, o, "seo", rule(created_by="manager")))
        self.assertIn("is not yours", refused(w.may_control, o, "vps", rule()))

    def test_an_agent_never_resumes_a_pause_by_the_fleet_manager(self):
        o = org()

        def resume(caller, r, team=o):
            return w.may_control(team, caller, r, "resume")
        mine = rule(state="paused")
        for caller in ("seo", "manager"):                               # its own pause: as before
            self.assertIsNone(resume(caller, dict(mine, paused_by="seo")))
        by_fleet = dict(mine, paused_by="manager")
        self.assertIn("manager paused trigger 7. Only the fleet manager resumes it.", refused(resume, "seo", by_fleet))
        self.assertIsNone(resume("manager", by_fleet))
        self.assertIn("is not yours", refused(resume, "lead-a", by_fleet))
        self.assertIsNone(w.may_control(o, "seo", by_fleet, "delete"))   # a delete starts nothing
        self.assertIsNone(resume("seo", dict(mine, paused_by="hub")))    # plan_change then requires still_valid
        self.assertIn("Only the owner resumes it", refused(resume, "seo", dict(mine, paused_by=None)))   # no pauser

    def test_who_may_set_a_rule_for_whom(self):
        o = org()
        self.assertIsNone(w.check_set(o, "seo", "seo"))
        self.assertIsNone(w.check_set(o, "manager", "manager"))
        self.assertIsNone(w.check_set(o, "manager", "seo"))
        self.assertIn("Only seo itself or manager", refused(w.check_set, o, "lead-a", "seo"))
        self.assertIn("Only dev itself or manager", refused(w.check_set, o, "lead-a", "dev"))
        self.assertIn("no agent ghost", refused(w.check_set, o, "manager", "ghost"))


class Routes(unittest.TestCase):
    def test_each_target_gets_a_route_whose_requester_sees_the_result(self):
        o = org()
        self.assertEqual(w.wake_route(o, "manager")[0], {"kind": "message", "to": "manager"})
        self.assertEqual(w.wake_route(o, "seo")[0],
                         {"kind": "task", "owner": "seo", "requester": "manager", "parent": None})
        self.assertEqual(w.wake_route(o, "lead-a")[0],                  # a lead's own rule: its own boss
                         {"kind": "task", "owner": "lead-a", "requester": "manager", "parent": None})
        self.assertEqual(w.wake_route(o, "dev")[0],                     # under a lead: a parent task for it
                         {"kind": "task", "owner": "dev", "requester": "lead-a",
                          "parent": {"owner": "lead-a", "requester": "manager"}})

    def test_every_task_of_a_route_passes_the_task_authority(self):
        asked = []
        def authority(actor, target, action):
            asked.append((actor, target, action))
            if action == "task" and (actor, target) == ("lead-a", "dev"):
                return False, "dev is in setup. The owner activates it in Fleet."
            return w.team_authority("manager", AGENTS)(actor, target, action)
        route, why = w.wake_route(w.Org("manager", AGENTS, authority), "dev")
        self.assertIsNone(route)
        self.assertEqual(why, "dev is in setup. The owner activates it in Fleet.")
        self.assertIn(("manager", "lead-a", "task"), asked)                    # the parent task
        self.assertIn(("lead-a", "dev", "task"), asked)                        # the target's task

    def test_a_route_needs_a_lead_that_reports_to_the_manager(self):
        o = org()
        route, why = w.wake_route(o, "deeper")                           # deeper reports to dev, a worker
        self.assertIsNone(route)
        self.assertIn("dev would receive deeper's result, but it is not a lead", why)
        agents = dict(AGENTS, **{"dev": dict(AGENTS["dev"], role="lead")})
        route, why = w.wake_route(org(agents=agents), "deeper")
        self.assertIn("reports to lead-a, not to the manager. A wake-up can go through one lead only", why)

class Grants(unittest.TestCase):
    def test_the_execution_grant_is_the_same_rule_for_every_runtime(self):
        cases = (({"runtime": "codex", "start": CODEX_FULL}, (), True),
                 ({"runtime": "codex", "start": "codex --sandbox=danger-full-access --ask-for-approval=never"}, (), True),
                 ({"runtime": "codex", "start": "codex --yolo {prompt}"}, (), True),
                 ({"runtime": "codex", "start": "codex --sandbox workspace-write --ask-for-approval never"}, (), False),
                 ({"runtime": "codex", "start": "codex --full-auto {prompt}"}, (), False),
                 ({"runtime": "codex", "start": CODEX_FULL + " -c sandbox_mode=read-only"}, (), False),
                 ({"runtime": "codex", "start": "codex 'unclosed"}, (), False),
                 ({"runtime": "claude", "start": "claude --permission-mode acceptEdits"}, (), False),
                 ({"runtime": "claude", "start": "claude --permission-mode dontAsk", "allow": ["Bash(git pull *)"]},
                  (), False),
                 # plan C14: one rule for every role -- Bash with no pattern, or a bypass, and every built-in tool
                 ({"runtime": "claude", "start": "claude --permission-mode dontAsk {chrome} {settings} {prompt}",
                   "allow": ["Bash", "Read", "Edit", "Write", "mcp__fleet__*"]}, (), True),
                 ({"runtime": "claude", "start": "claude --permission-mode dontAsk --disallowedTools WebFetch {prompt}",
                   "allow": ["Bash"]}, (), False),
                 ({"runtime": "claude", "start": "claude --permission-mode dontAsk --tools Bash,Read {prompt}",
                   "allow": ["Bash"]}, (), False),
                 ({"role": "manager", "runtime": "claude",
                   "start": "claude --permission-mode bypassPermissions --tools default {settings} {prompt}"}, (), True),
                 ({"role": "manager", "runtime": "claude", "start": "claude --permission-mode dontAsk", "allow": ["Bash"]},
                  (), True),
                 ({"role": "manager", "runtime": "claude",                  # a start without Bash runs no check
                   "start": "claude --permission-mode bypassPermissions --disallowedTools Bash {settings} {prompt}"},
                  (), False),
                 ({"role": "manager", "runtime": "claude",
                   "start": "claude --permission-mode bypassPermissions --tools Read,Edit {settings} {prompt}"}, (), False),
                 ({"runtime": "claude", "start": "claude --permission-mode bypassPermissions"}, (), True),
                 ({"runtime": "claude", "start": "claude --dangerously-skip-permissions"}, (), True),
                 ({"runtime": "claude", "start": "claude", "allow": ["Bash"]}, (), True),
                 ({"runtime": "claude", "start": "claude --allowedTools Bash Read"}, (), True),
                 ({"runtime": "grok", "start": "grok agent stdio"}, (), False))
        for conf, features, granted in cases:
            with self.subTest(conf=conf):
                self.assertEqual(w.execution_grant(conf)[0], granted)
        self.assertIn("asks before commands",
                      w.execution_grant({"runtime": "claude", "start": "claude --permission-mode acceptEdits"})[1])
        self.assertIn("removes a built-in tool", w.execution_grant(
            {"runtime": "claude", "start": "claude --permission-mode dontAsk --tools Bash {prompt}", "allow": ["Bash"]})[1])

    def test_saved_code_runs_only_as_its_own_agents_check_on_its_machine_with_the_grant(self):
        """Plan P4: a check runs only on its own agent's machine, with that agent's read keys, and only where that
        agent's runtime already runs any command without asking. So only that agent saves its code: another agent's
        code, the fleet manager's included, would run with this agent's keys (review, 27 October 2026)."""
        o = org()
        self.assertEqual(w.code_grant(o, "vps", "vps"), (True, None))                 # Codex, its own code
        self.assertEqual(w.code_grant(o, "manager", "manager"), (True, None))         # the manager's own
        for author in ("manager", "lead-a", "seo", "worker4"):
            with self.subTest(author=author):
                self.assertIn(f"A check runs only with code that its own agent saved, and {author} saved this one: "
                              f"only vps saves the code of vps's checks", w.code_grant(o, author, "vps")[1])
        self.assertIn("seo cannot run saved code", w.code_grant(o, "seo", "seo")[1])  # Claude, asks first
        self.assertIn("in setup", w.code_grant(o, "newbie", "newbie")[1])
        lead_claude = dict(AGENTS, **{"dev": dict(AGENTS["dev"], runtime="claude", start="claude")})
        self.assertFalse(w.code_grant(org(agents=lead_claude), "dev", "dev")[0])
        self.assertEqual(w.runner_of(rule(agent="vps", check={"run_on": "worker4"})), "vps")

    def test_a_claude_worker_with_full_access_runs_its_own_checks(self):
        """Plan C14 (the owner's yes, 26 October 2026): no helper feature and no approval of each revision. A worker
        that asks before commands still runs none."""
        self.assertIn("studio cannot run saved code", w.code_grant(org(), "studio", "studio")[1])
        full = dict(AGENTS["studio"], start="claude --permission-mode dontAsk {chrome} {settings} {prompt}",
                    allow=["Bash", "Read", "Edit", "Write", "mcp__fleet__*"])
        self.assertEqual(w.code_grant(org(agents=dict(AGENTS, studio=full)), "studio", "studio"), (True, None))


class NoRunOn(unittest.TestCase):
    """Plan P4 took away run_on and code approvals: a check runs only on its own agent's machine, with its own keys."""

    def test_a_save_with_run_on_is_refused_and_names_why(self):
        o = org()
        for caller, target in (("manager", "manager"), ("vps", "vps"), ("seo", "seo")):
            with self.subTest(caller=caller):
                self.assertIn("check has no field run_on: a check runs only on its own agent's machine",
                              refused(w.plan_save, o, caller, {"agent": target, "schedule": EVERY, "task": TASK,
                                                               "check": dict(CHECK, run_on="vps")}))
        self.assertIn("check has no field approval", refused(w.plan_save, o, "vps", {
            "schedule": EVERY, "task": TASK, "check": dict(CHECK, approval={"prompt": 1, "approver": "manager"})}))
        self.assertFalse(hasattr(w, "NeedsCodeApproval"))
        self.assertFalse(hasattr(w, "code_subject"))

    def test_a_stored_check_of_another_machine_stops_until_it_is_saved_again(self):
        o = org()
        old = dict(w.saved_check(CHECK, "seo")[0], run_on="vps",
                   approval={"prompt": 12, "approver": "manager", "subject": {}})
        valid, why = w.still_valid(o, rule(agent="seo", created_by="seo", check=old))
        self.assertFalse(valid)
        self.assertIn("saved to run on vps's machine", why)
        self.assertIn("save the check again, without run_on", why)
        same = dict(w.saved_check(CHECK, "vps")[0], run_on="vps", approval=old["approval"])   # its own machine
        self.assertEqual(w.still_valid(o, rule(agent="vps", created_by="vps", check=same)), (True, None))
        edit = {"trigger_id": 7, "base_revision": 3}
        moved = refused(w.plan_save, o, "manager", dict(edit, agent="worker4"),
                        rule=rule(agent="vps", created_by="vps", check=dict(same, run_on="seo")))
        self.assertIn("runs on seo's machine (run_on)", moved)
        kept = w.plan_save(o, "vps", dict(edit, check={"condition": CHECK["condition"]}),
                           rule=rule(agent="vps", created_by="vps", check=same, id=7))
        self.assertNotIn("run_on", kept["check"])
        self.assertNotIn("approval", kept["check"])
        self.assertEqual(kept["check"]["sha256"], same["sha256"])
        moved = w.plan_save(o, "manager", dict(edit, schedule=EVERY),      # an edit that keeps the check
                            rule=rule(agent="vps", created_by="vps", id=7, check=same))
        self.assertNotIn("check", moved)


class SavedCode(unittest.TestCase):
    def test_saved_code_is_kept_by_its_hash_with_its_author(self):
        stored, source = w.saved_check(dict(CHECK, args={"q": "é"}), "lead-a")
        data = CHECK["code"].encode("utf-8")
        self.assertEqual(source, CHECK["code"])
        self.assertEqual(stored, {"code": "saved", "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                                  "code_by": "lead-a", "condition": CHECK["condition"],
                                  "repeat_minutes": None, "args": {"q": "é"}})
        lines, _ = w.saved_check({"code": CHECK["code"], "timeout_seconds": 20}, "lead-a")     # plan P4
        self.assertEqual(lines, {"code": "saved", "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                                 "code_by": "lead-a", "form": "lines", "timeout_seconds": 20})
        unicode_code = "print('ñ')\n"
        self.assertEqual(w.saved_check(dict(CHECK, code=unicode_code), "vps")[0]["bytes"], len(unicode_code.encode()))

    def test_a_change_without_code_keeps_the_version_and_names_the_editor(self):
        old = w.saved_check(CHECK, "vps")[0]
        kept, source = w.saved_check({"condition": {"op": ">=", "value": 3}}, "manager", old)
        self.assertIsNone(source)
        self.assertEqual((kept["sha256"], kept["bytes"], kept["code_by"]), (old["sha256"], old["bytes"], "manager"))
        self.assertEqual(kept["condition"], {"op": ">=", "value": 3})
        self.assertIn("check.code is required", refused(w.saved_check, {"condition": {}}, "vps"))
        self.assertIn("check has no field repeat_minutes: a check wakes once for each new line",   # plan P4
                      refused(w.saved_check, dict(CHECK, repeat_minutes=30), "vps"))
        self.assertIsNone(kept["repeat_minutes"])           # kept for the app, with no meaning
        new, _ = w.saved_check(dict(CHECK, code=CHECK["code"] + "# v2\n"), "vps", old)
        self.assertNotEqual(new["sha256"], old["sha256"])               # an edit is a new immutable version

    def test_bad_code_and_repository_fields_are_refused(self):
        for value, words in ((dict(CHECK, code=""), "text of a Python program"),
                             (dict(CHECK, code=7), "text of a Python program"),
                             (dict(CHECK, code="print(1)\x00"), "NUL"),
                             (dict(CHECK, code="\ud800"), "valid Unicode"),
                             (dict(CHECK, code="#" * (w.CODE_MAX + 1)), "the limit is 65536 bytes"),
                             (dict(CHECK, path="checks/x.py"), "check has no field path"),
                             (dict(CHECK, commit="0" * 40), "check has no field commit"),
                             (dict(CHECK, run_on="vps"), "check has no field run_on"),
                             ("print(1)", "check must be an object")):
            with self.subTest(words=words):
                self.assertIn(words, refused(w.saved_check, value, "vps"))


class StaleRules(unittest.TestCase):
    def test_a_rule_is_checked_again_with_the_current_team_and_grants(self):
        o = org()
        self.assertEqual(w.still_valid(o, rule(created_by="manager")), (True, None))
        code = w.saved_check(CHECK, "vps")[0]           # vps's own code, on a rule that the manager changed last
        r = rule(agent="vps", created_by="manager", check=code)
        self.assertEqual(w.still_valid(o, r), (True, None))
        theirs = rule(agent="vps", created_by="manager", check=w.saved_check(CHECK, "manager")[0])
        self.assertIn("A check runs only with code that its own agent saved", w.still_valid(o, theirs)[1])
        moved = {n: a for n, a in AGENTS.items() if n != "manager"}
        moved["lead-a"] = dict(AGENTS["lead-a"], role="manager")
        cases = (
            (org(agents=dict(AGENTS, vps=dict(AGENTS["vps"], start="codex --sandbox workspace-write"))),
             "vps cannot run saved code"),
            (org(agents=dict(AGENTS, vps=dict(AGENTS["vps"], active=False))), "vps is in setup"),
            (org(agents={k: v for k, v in AGENTS.items() if k != "vps"}), "vps is no longer in the team"),
            (org(agents=moved), "manager set this rule and no longer has authority"),
        )
        for changed, words in cases:
            with self.subTest(words=words):
                ok, why = w.still_valid(changed, r)
                self.assertFalse(ok)
                self.assertIn(words, why)

    def test_owner_rules_keep_the_hub_rules(self):
        self.assertEqual(w.still_valid(org(), rule(created_by="owner")), (True, None))
        self.assertFalse(w.still_valid(org(), rule(created_by="owner", agent="ghost"))[0])

    def test_a_resume_or_check_now_of_a_stale_rule_is_refused(self):
        o = org(agents={k: v for k, v in AGENTS.items() if k != "seo"})
        r = rule(created_by="manager", state="paused", paused_by="hub")
        self.assertIn("seo is no longer in the team",
                      refused(w.plan_change, o, "manager", {"trigger_id": 7, "base_revision": 3, "action": "resume"}, r))
        self.assertEqual(w.plan_change(o, "manager", {"trigger_id": 7, "base_revision": 3, "action": "delete"}, r)["op"],
                         "delete")


class Plans(unittest.TestCase):
    def test_a_new_rule_defaults_to_the_caller_and_the_fleet(self):
        plan = w.plan_save(org(), "seo", {"request_id": "req-0001", "task_id": "T-9", "schedule": EVERY, "task": TASK})
        self.assertEqual(plan, {"op": "create", "trigger_id": None, "base_revision": None,
                                "fields": {"agent": "seo", "schedule": EVERY, "task": TASK},
                                "route": {"kind": "task", "owner": "seo", "requester": "manager", "parent": None},
                                "source": None, "by": "seo", "check": None})

    def test_the_manager_sets_a_rule_for_any_agent_and_a_lead_only_its_own(self):
        o = org()
        plan = w.plan_save(o, "manager", {"agent": "dev", "schedule": EVERY, "task": TASK})
        self.assertEqual(plan["route"]["requester"], "lead-a")           # dev's own lead gets its result
        self.assertIn("only dev saves the code of dev's checks",           # its check is dev's own to write
                      refused(w.plan_save, o, "manager", {"agent": "dev", "schedule": EVERY, "task": TASK,
                                                          "check": CHECK}))
        own = w.plan_save(o, "dev", {"schedule": EVERY, "task": TASK, "check": CHECK})
        self.assertNotIn("run_on", own["check"])                         # dev's own machine runs it
        self.assertEqual(own["source"], CHECK["code"])
        self.assertIn("Only seo itself or manager",
                      refused(w.plan_save, o, "lead-a", {"agent": "seo", "schedule": EVERY, "task": TASK}))
        self.assertIn("Only dev itself or manager",
                      refused(w.plan_save, o, "studio", {"agent": "dev", "schedule": EVERY, "task": TASK}))
        manager = w.plan_save(o, "manager", {"agent": "manager", "schedule": EVERY, "task": TASK, "check": CHECK})
        self.assertEqual(manager["route"], {"kind": "message", "to": "manager"})
        self.assertIn("task.needs must be none",
                      refused(w.plan_save, o, "manager", {"agent": "manager", "schedule": EVERY,
                                                          "task": dict(TASK, needs="browser")}))

    def test_code_needs_a_granted_runner(self):
        o = org()
        self.assertIn("seo cannot run saved code",
                      refused(w.plan_save, o, "seo", {"schedule": EVERY, "task": TASK, "check": CHECK}))
        self.assertIn("check has no field run_on",
                      refused(w.plan_save, o, "seo", {"schedule": EVERY, "task": TASK, "check": dict(CHECK, run_on="vps")}))
        self.assertEqual(w.plan_save(o, "vps", {"schedule": EVERY, "task": TASK, "check": CHECK})["check"]["code_by"],
                         "vps")
        self.assertIn("is in setup", refused(w.plan_save, o, "newbie", {"schedule": EVERY, "task": TASK}))

    def test_an_edit_needs_its_revision_and_authority_and_rechecks_moves(self):
        o = org()
        stored = rule(agent="vps", created_by="vps", check=w.saved_check(CHECK, "vps")[0])
        edit = {"trigger_id": "7", "base_revision": 3, "check": {"condition": {"op": ">", "value": 2}}}
        plan = w.plan_save(o, "vps", edit, rule=stored)
        self.assertEqual((plan["op"], plan["trigger_id"], plan["source"]), ("edit", 7, None))
        self.assertEqual(plan["check"]["sha256"], stored["check"]["sha256"])
        self.assertIn("base_revision is required",
                      refused(w.plan_save, o, "vps", dict(edit, base_revision=None), rule=stored))
        self.assertIn("There is no trigger 8", refused(w.plan_save, o, "vps", dict(edit, trigger_id=8), rule=stored))
        self.assertIn("is not yours", refused(w.plan_save, o, "worker4", edit, rule=stored))
        self.assertIn("Give at least one", refused(w.plan_save, o, "vps", {"trigger_id": 7, "base_revision": 3},
                                                   rule=stored))
        # Moved, vps's code would run as worker4's check, with worker4's keys: only worker4's own code may.
        self.assertIn("and vps saved this one: only worker4 saves the code of worker4's checks",
                      refused(w.plan_save, o, "manager", {"trigger_id": 7, "base_revision": 3, "agent": "worker4"},
                              rule=stored))
        keep = {"condition": CHECK["condition"]}
        self.assertIn("and manager saved this one: only worker4 saves",  # nor as the manager's, with the same code
                      refused(w.plan_save, o, "manager", {"trigger_id": 7, "base_revision": 3, "agent": "worker4",
                                                          "check": keep}, rule=stored))
        self.assertIn("seo cannot run saved code",                       # a Claude runner, even its own code
                      refused(w.plan_save, o, "seo", {"schedule": EVERY, "task": TASK, "check": CHECK}))
        moved = w.plan_save(o, "manager", {"trigger_id": 7, "base_revision": 3, "agent": "worker4", "check": None},
                            rule=stored)
        self.assertEqual((moved["fields"]["agent"], moved["check"]), ("worker4", None))   # moved without its check
        same = w.plan_save(o, "vps", {"trigger_id": 7, "base_revision": 3, "task": TASK}, rule=stored)
        self.assertNotIn("check", same)                                   # the check stays as it is

    def test_the_rule_limit_counts_agent_rules_of_the_target(self):
        o = org()
        rules = [rule(id=i, agent="vps", created_by="vps") for i in range(1, 21)]
        rules += [rule(id=50, agent="vps", created_by="owner"), rule(id=51, agent="vps", state="deleted")]
        self.assertIn("the limit is 20", refused(w.plan_save, o, "vps", {"schedule": EVERY, "task": TASK}, rules=rules))
        self.assertEqual(w.plan_save(o, "vps", {"schedule": EVERY, "task": TASK}, rules=rules[1:])["op"], "create")
        edit = w.plan_save(o, "vps", {"trigger_id": 1, "base_revision": 3, "task": TASK}, rule=rules[0], rules=rules)
        self.assertEqual(edit["op"], "edit")                              # an edit in place is not counted again

    def test_bad_input_is_refused(self):
        o = org()
        for args, words in (({"schedule": EVERY}, "needs task"),
                            ({"schedule": EVERY, "task": TASK, "colour": "red"}, "no field colour"),
                            ({"schedule": EVERY, "task": TASK, "base_revision": 2}, "base_revision belongs"),
                            ({"schedule": EVERY, "task": TASK, "agent": 5}, "agent must be"),
                            ("x", "needs an object")):
            with self.subTest(words=words):
                self.assertIn(words, refused(w.plan_save, o, "vps", args))
        r = rule(agent="vps", created_by="vps")
        for args, words in (({"trigger_id": 7, "base_revision": 3, "action": "run_now"}, "action must be"),
                            ({"trigger_id": 7, "action": "pause"}, "base_revision is required"),
                            ({"trigger_id": 7, "base_revision": 3, "action": "check_now"}, "has no check"),
                            ({"trigger_id": True, "base_revision": 3, "action": "pause"}, "trigger_id must be")):
            with self.subTest(words=words):
                self.assertIn(words, refused(w.plan_change, o, "vps", args, r))


class Commands(unittest.TestCase):
    def test_the_identity_of_a_write_ignores_only_its_id_and_task(self):
        a = {"request_id": "req-0001", "task_id": "T-1", "schedule": EVERY, "task": TASK}
        rid, digest = w.command_identity("vps", "save_trigger", a)
        self.assertEqual(rid, "req-0001")
        self.assertEqual(w.command_identity("vps", "save_trigger", dict(a, task_id="T-2"))[1], digest)
        self.assertEqual(w.command_identity("vps", "save_trigger", {"task": TASK, "schedule": EVERY,
                                                                    "request_id": "req-0001"})[1], digest)
        self.assertNotEqual(w.command_identity("vps", "save_trigger", dict(a, task=dict(TASK, title="x")))[1], digest)
        self.assertNotEqual(w.command_identity("vps", "change_trigger", a)[1], digest)
        for bad in (None, "short", "has space ok", "x" * 65, 12345678):
            with self.subTest(bad=bad):
                self.assertEqual(w.REQUEST_RULE, refused(w.command_identity, "vps", "save_trigger",
                                                         dict(a, request_id=bad)))

    def test_one_request_id_rule_for_every_tool(self):
        # The ids that agents sent on 4 November 2026: two of them were refused by open_case and attach_watch.
        for live in ("a3f1c2d4-7b8e-4f19-9c2a-194test0001", "leo-t142-r8-attach-19", "leo-t142-r8-trigger-1",
                     "T-135-owner-test-rule-1", "req:0001.a_b"):
            with self.subTest(live=live):
                self.assertEqual(w.request_ref(live), live)
                self.assertEqual(hub.request_ref({"request_id": live}), live)
        upper = "3F2504E0-4F89-41D3-9A0C-0305E82C3301"
        self.assertEqual(w.request_ref(upper), upper.lower())               # agent_write always kept a UUID so
        self.assertEqual(w.command_identity("vps", "save_trigger", {"request_id": upper})[0], upper.lower())
        for bad in (None, 7, "", "short", "x" * 65, "has space ok", "-dash-first1", ".dot-first1", "naïve-id-01"):
            with self.subTest(bad=bad):
                self.assertIsNone(w.request_ref(bad))
                with self.assertRaises(hub.ToolError) as caught:
                    hub.request_ref({"request_id": bad})
                self.assertEqual(str(caught.exception), w.REQUEST_RULE)
        # A vault job is kept by a UUID: the id itself when it is one, else one made from the agent and the id.
        self.assertEqual(hub.vault_request("seo", upper.lower()), upper.lower())
        made = hub.vault_request("seo", "seo-login-0001")
        self.assertEqual(str(uuid.UUID(made)), made)
        self.assertEqual(made, hub.vault_request("seo", "seo-login-0001"))
        self.assertNotEqual(made, hub.vault_request("kai", "seo-login-0001"))
        # Every request_id field of every agent tool says the same rule.
        fields = [s["properties"]["request_id"] for *_x, s in hub.TOOLS if "request_id" in s.get("properties", {})]
        fields += [s["properties"]["request_id"] for _n, _d, s in w.TOOL_SPECS if "request_id" in s["properties"]]
        self.assertGreater(len(fields), 27)
        for f in fields:
            self.assertTrue(f["description"].endswith(w.REQUEST_ID["description"]), f)

    def test_an_exact_repeat_gets_the_first_receipt(self):
        stored = {"tool": "save_trigger", "digest": "d1", "receipt": w.receipt("create", 7, 1)}
        self.assertIsNone(w.same_command(stored, "save_trigger", "d1"))
        self.assertIn("already used for another change", refused(w.same_command, stored, "save_trigger", "d2"))
        self.assertIn("already used", refused(w.same_command, stored, "change_trigger", "d1"))
        self.assertEqual(w.receipt_text(stored["receipt"]), "Created trigger 7 (revision 1).")
        self.assertIn("nothing new was done", w.receipt_text(stored["receipt"], replayed=True))
        self.assertIn("Run 31", w.receipt_text(w.receipt("check_now", 7, 4, 31)))


class Decisions(unittest.TestCase):
    """A prompt run of the fleet manager's rule. A check run wakes through its lines (plan P4: test_checks_v2)."""

    def test_the_manager_message_route_waits_for_its_unread_message(self):
        read = {"ref": "M-3", "open": False, "ended": "read", "ended_at": 9000.0}
        self.assertEqual(w.manager_decision(None), ("started", None))
        self.assertEqual(w.manager_decision(read), ("started", None))
        self.assertEqual(w.manager_decision(dict(read, open=True)), ("not_started", "M-3 is still unread."))
        self.assertFalse(hasattr(w, "wake_armed"))          # plan P4: no repeat and no armed state for an agent's check


class Texts(unittest.TestCase):
    when = staticmethod(lambda ts: f"<{ts:g}>")

    def test_messages_and_parent_tasks_say_where_they_come_from(self):
        text = w.manager_message(7, TASK, "Started by trigger 7 (revision 3, run 12) for <1>.")
        self.assertTrue(text.startswith("[hub] Wake-up from trigger 7: Look at the queue"))
        self.assertIn("Done when: The queue is handled.", text)
        batch = w.batch_fields("lead-a")          # plan P9.11: one task of the lead for its team's results
        self.assertEqual((batch["owner"], batch["needs"]), ("lead-a", "none"))
        self.assertIn("are subtasks of this task, and more join it while it is open", batch["details"])
        self.assertIn("by sample where it is good; you decide", batch["details"])
        self.assertLessEqual(len(batch["title"]), 200)

    def test_rule_texts_show_the_author_code_hash_and_history_but_not_secrets(self):
        code = w.saved_check(CHECK, "lead-a")[0]
        r = rule(created_by="lead-a", check=code, next_due=100.0, failures=2,
                 armed={"armed": False, "reason": "Waiting for a quiet check."},
                 last_run={"id": 12, "due": 90.0, "state": "quiet", "value": 3, "summary": "3 open"}, tasks_24h=1)
        text = w.describe(r, self.when)
        self.assertIn("set by lead-a, wakes seo: active", text)
        self.assertIn(f"saved code {code['sha256'][:12]}", text)
        self.assertIn("on seo's own machine", text)
        self.assertIn("Armed: no. Waiting for a quiet check.", text)
        self.assertNotIn("print(json.dumps", text)
        detail = w.describe_detail(r, [r["last_run"]], [{"revision": 3, "ts": 80.0, "by": "lead-a", "action": "edit",
                                                         "detail": {"changed": {"check": {}}}}], CHECK["code"],
                                   self.when)
        self.assertIn("revision 3 at <80> by lead-a: edit (check)", detail)
        self.assertIn("```python\nimport json", detail)
        self.assertEqual(w.history_detail("edit", {"created_by": "seo"}, {"created_by": "lead-a"}),
                         {"changed": {"created_by": {"before": "seo", "after": "lead-a"}}})

    def test_the_tool_specs_are_complete(self):
        names = [name for name, _, _ in w.TOOL_SPECS]
        self.assertEqual(names, ["see_triggers", "save_trigger", "change_trigger"])
        for name, description, schema in w.TOOL_SPECS:
            with self.subTest(name=name):
                self.assertEqual(schema["type"], "object")
                # The schema no longer closes itself: `hub.call_tool` refuses a field the tool does not take, in
                # the hub's own words and on the hub's own record, instead of leaving a validation error inside
                # the caller's runtime that nobody can read afterwards (`hub.S`, `hub.stale_instructions`).
                self.assertNotIn("additionalProperties", schema)
                self.assertEqual(hub.unknown_fields(name, {"react_within": "1h"}), ["react_within"])
                self.assertTrue(set(schema["required"]) <= set(schema["properties"]))
                self.assertTrue(all("description" in p or "enum" in p for p in schema["properties"].values()))
                keys = {"see_triggers": {"trigger_id", "task_id"}, "save_trigger": w.SAVE_KEYS,
                        "change_trigger": w.CHANGE_KEYS}[name]
                self.assertEqual(set(schema["properties"]), keys)
                self.assertGreater(len(description), 40)
        self.assertEqual(dict((n, s["required"]) for n, _, s in w.TOOL_SPECS)["save_trigger"], ["request_id"])

    def test_a_rule_has_no_project_field_any_more(self):
        """The owner removed projects on 18 October 2026: no tool takes one, and no plan carries one."""
        save = dict((n, s) for n, _, s in w.TOOL_SPECS)["save_trigger"]
        words = dict((n, d) for n, d, _ in w.TOOL_SPECS)
        self.assertNotIn("project", save["properties"])
        self.assertNotIn("project", json.dumps(words))
        self.assertNotIn("project", w.SAVE_KEYS)
        self.assertIn("no field project", refused(w.plan_save, org(), "manager",
                                                  {"schedule": EVERY, "task": TASK, "project": "shop"}))
        self.assertNotIn("project", w.plan_save(org(), "manager", {"schedule": EVERY, "task": TASK}))


@unittest.skipUnless(HUB_GLUE, "the hub has no wake-up glue yet (WAKEUPS-INTERFACE.md, section 5: wake_org)")
class HubGlue(OwnerAPI):
    """The contract of WAKEUPS-INTERFACE.md through the hub's own tools, tables and helper route: an in-process hub
    with its HTTP server, a temporary database, a set clock and a stand-in runner that posts results; no AI."""

    def setUp(self):
        super().setUp()
        hub.TEAM = {"addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.1", "seo": "127.0.0.4",
                                  "blog": "127.0.0.5", "shop": "127.0.0.6"},
                    "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": [],
                                           "start": "claude --permission-mode dontAsk {settings} {prompt}",
                                           "allow": ["Bash"]},
                               "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"],
                                       "start": CODEX_FULL},
                               "seo": {"role": "worker", "runtime": "claude", "machine": "seo", "can": ["shell"],
                                       "start": "claude --permission-mode dontAsk {settings} {prompt}",
                                       "allow": ["Bash"]},
                               "lead-b": {"role": "lead", "runtime": "claude", "machine": "blog", "can": ["shell"],
                                           "start": "claude --permission-mode dontAsk {settings} {prompt}"},
                               "lead-a": {"role": "lead", "runtime": "claude", "machine": "shop", "can": ["shell"],
                                           "start": "claude --permission-mode dontAsk {settings} {prompt}"}},
                    "goals": {"timezone": "Europe/Madrid"}}
        hub.TEAM["agents"]["seo"]["reports_to"] = "lead-b"          # seo's results go to its own lead
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90, tick=5)
        self.clock = 1791700000.0
        clock = patch.object(hub, "now", lambda: self.clock)
        clock.start()
        self.addCleanup(clock.stop)
        for name in hub.TEAM["agents"]:
            hub.touch(name)
            hub.q("INSERT INTO machine_status(agent,data,reported) VALUES(?,?,?)",
                  (name, json.dumps({"features": ["trigger_check", "trigger_code"]}), self.clock))
        # call_tool fences worker and lead tools to a real task attempt, so each of them calls from a task session of its
        # own; the manager calls without one. Every baseline below starts after this setup.
        self.sessions = {"vps": self.open_session("vps"), "lead-b": self.open_session("lead-b"),
                         "lead-a": self.open_session("lead-a"), "seo": self.open_session("seo")}
        self.first_task = hub.q1("SELECT COALESCE(MAX(id), 0) m FROM tasks")["m"]
        self.first_event = hub.q1("SELECT COALESCE(MAX(id), 0) m FROM events")["m"]

    def open_session(self, agent):
        """A real task of `agent`, requested by its boss through the hub's own admission, and its fence context: the
        manager's goes through check_task, and a lead's worker's straight to admit_task (a lead gives tasks only from
        a task session of its own)."""
        boss = hub.reports_to(agent)
        ask = {"owner": agent, "title": f"Fixture session of {agent}", "details": "", "done_when": "The test ends.",
               "needs": "none", "why": f"{agent} is the one for it."}
        fields = hub.check_task("manager", ask) if boss == "manager" else dict(
            ask, goal=None, goal_id=None, parent=None, follows=None, case_id=None)
        with hub.transaction():
            tid = hub.admit_task(boss, fields)
        return (hub.kv_get("db_id"), hub.tref(tid), 1)

    def tool(self, agent, name, args):
        return hub.call_tool(agent, name, args, self.sessions.get(agent))

    def model_events(self):
        return hub.q1("SELECT COUNT(*) n FROM events WHERE id>? AND kind IN ('say','task','chat')", (self.first_event,))["n"]

    def new_tasks(self):
        return hub.q("SELECT * FROM tasks WHERE id>? ORDER BY id", (self.first_task,))

    def save(self, caller, request_id, **fields):
        text, error = self.tool(caller, "save_trigger", dict({"request_id": request_id, "schedule": EVERY, "task": TASK},
                                                             **fields))
        self.assertFalse(error, text)
        return hub.q1("SELECT * FROM triggers ORDER BY id DESC LIMIT 1")

    def tick(self, when):
        self.clock = when
        for name in hub.TEAM["agents"]:
            hub.touch(name)
        with hub.LOCK:
            hub.trigger_sweep(when)

    def sent(self):
        """The stand-in runner reads the newest trigger_check event."""
        e = hub.q1("SELECT * FROM events WHERE kind='trigger_check' ORDER BY id DESC LIMIT 1")
        return e["agent"], json.loads(e["extra"])

    def goal(self, state):
        """A goal row in `state`, as the owner API stores it."""
        return hub.ins("INSERT INTO goals(title,text,state,paused_by,revision,limits,created,updated,request_id) "
                       "VALUES(?,?,?,?,1,?,?,?,?)",
                       (f"Synthetic {state} goal", "Synthetic goal text.", state, "owner" if state == "paused" else None,
                        json.dumps({"money": None, "tokens": None, "deadline": None, "not_to_do": []}), self.clock, self.clock,
                        f"00000000-0000-4000-8000-{len(hub.q('SELECT id FROM goals')):012d}"))

    def runs(self, trigger_id):
        return hub.q("SELECT * FROM trigger_runs WHERE trigger_id=? ORDER BY id", (trigger_id,))

    def source(self, runner):
        """The address of the runner's machine: a helper route answers only its own machine."""
        return hub.TEAM["addresses"][hub.TEAM["agents"][runner]["machine"]]

    def post(self, runner, extra, **result):
        return self.request(f"/helper/trigger/{runner}/{extra['run']}", dict({"token": extra["token"], "ok": True},
                                                                             **result), source=self.source(runner))

    def test_a_false_check_starts_no_model_and_a_match_starts_the_prompt_once(self):
        t = self.save("manager", "req-manager-1", agent="manager", check=CHECK)
        before = self.model_events()
        self.tick(t["next_due"])
        runner, extra = self.sent()
        self.assertEqual(runner, "manager")                               # its own machine (plan P4)
        self.assertEqual(self.post(runner, extra, value=10)[1]["decision"], "quiet")
        self.assertEqual(self.model_events(), before)                     # no manager or worker start
        self.assertEqual(self.new_tasks(), [])
        self.tick(t["next_due"] + 900)
        runner, extra = self.sent()
        self.assertEqual(self.post(runner, extra, value=11)[1]["decision"], "started")
        self.assertEqual(self.model_events(), before + 1)                 # one message to the manager
        self.assertEqual(self.new_tasks(), [])
        # The count of wake-ups is data and no limit (plan C12): this one manager message counts once.
        self.assertEqual(hub.trigger_view(hub.trigger_row(t["id"]), self.clock)["tasks_24h"], 1)
        status, listed = self.request("/ui/triggers?db=test-generation")
        self.assertEqual((status, "fleet" in listed), (200, False))

    def test_a_repeated_write_replays_its_receipt_after_delete_and_restart(self):
        t = self.save("vps", "req-vps-0001")
        text, error = self.tool("vps", "change_trigger", {"request_id": "req-vps-0002", "trigger_id": t["id"],
                                                          "base_revision": t["revision"], "action": "delete"})
        self.assertFalse(error, text)
        hub.DB.close()
        self.connect()                                                    # a hub restart
        text, error = self.tool("vps", "save_trigger", {"request_id": "req-vps-0001", "schedule": EVERY, "task": TASK})
        self.assertFalse(error, text)
        self.assertIn("nothing new was done", text)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM triggers")["n"], 1)
        text, error = self.tool("vps", "save_trigger", {"request_id": "req-vps-0001", "schedule": EVERY,
                                                        "task": dict(TASK, title="Other")})
        self.assertTrue(error)
        self.assertIn("already used for another change", text)

    def test_an_agents_rule_is_its_own_and_the_fleet_managers(self):
        t = self.save("manager", "req-blog-0001", agent="seo")
        text, error = self.tool("lead-a", "change_trigger", {"request_id": "req-shop-0001", "trigger_id": t["id"],
                                                             "base_revision": t["revision"], "action": "pause"})
        self.assertTrue(error)
        text, error = self.tool("lead-a", "see_triggers", {"trigger_id": t["id"]})
        self.assertTrue(error)                                            # not even visible to another lead
        self.assertEqual(hub.trigger_row(t["id"])["state"], "active")

    def test_a_claim_that_became_stale_starts_nothing(self):
        t = self.save("seo", "req-blog-0002", check=CHECK)       # a check's code is its own agent's
        self.tick(t["next_due"])
        runner, extra = self.sent()
        hub.TEAM["agents"]["seo"]["active"] = False                      # seo goes into setup after the claim
        before = self.model_events()
        self.assertEqual(self.post(runner, extra, value=11)[1]["decision"], "not_started")
        self.assertEqual(self.model_events(), before)
        self.assertEqual(self.new_tasks(), [])
        self.assertEqual(hub.trigger_row(t["id"])["paused_by"], "hub")

    def test_the_hub_gives_no_code_of_a_check_and_its_event_names_only_the_sha256(self):
        """DevOps plan 0.2: the code of a saved check runs from the machine's own store, which the agent's own
        session wrote, so the hub has no route that gives it and its event carries only the SHA-256."""
        t = self.save("seo", "req-blog-0004", check=CHECK)
        self.tick(t["next_due"])
        runner, extra = self.sent()
        self.assertEqual(runner, "seo")
        self.assertEqual((extra["code"], extra["sha256"]),
                         ("saved", hashlib.sha256(CHECK["code"].encode()).hexdigest()))
        self.assertNotIn("source", extra)
        path = f"/helper/trigger/seo/{extra['run']}/code?token={extra['token']}"
        status, body = self.request(path, source=self.source("seo"))
        self.assertEqual(status, 404)
        self.assertNotIn("source", body)

    def test_the_session_is_sent_to_a_store_that_it_may_write(self):
        """3 November 2026: Fleet's deny list closes ~/.fleet to every session, so the receipt and the tool's own text
        send the session to ~/fleet-checks/, where the helper reads the check."""
        text, error = self.tool("seo", "save_trigger", {"request_id": "req-blog-0005", "schedule": EVERY, "task": TASK,
                                                        "check": CHECK})
        self.assertFalse(error, text)
        sha = hashlib.sha256(CHECK["code"].encode()).hexdigest()
        self.assertIn(f"~/fleet-checks/{sha}.py on the machine of seo", text)
        described = dict((spec[0], spec[1]) for spec in w.TOOL_SPECS)["save_trigger"]
        self.assertIn(f"~/{lifecycle.CHECK_STORE}/<its SHA-256>.py", described)
        for said in (text, described):
            self.assertNotIn(".fleet/", said)

    def test_a_manager_wake_for_a_closed_goal_sends_no_message(self):
        rules = {}
        for state in ("paused", "done", "dropped", "active"):          # the active goal is the control: it sends one
            rules[state] = self.save("manager", f"req-manager-goal-{state}", agent="manager",
                                     task=dict(TASK, goal_id=self.goal(state)))
        before = self.model_events()
        self.tick(max(t["next_due"] for t in rules.values()))
        for state, t in rules.items():
            with self.subTest(goal=state):
                run = self.runs(t["id"])[-1]
                if state == "active":
                    self.assertEqual(run["state"], "started")
                    self.assertTrue(run["event_id"])
                else:
                    self.assertEqual(run["state"], "not_started")
                    self.assertIsNone(run["event_id"])
                    self.assertIn("G-", run["reason"])                       # refused for its goal, not another limit
                    self.assertIn({"paused": "paused", "done": "done", "dropped": "dropped"}[state], run["reason"])
        self.assertEqual(self.model_events(), before + 1)                  # only the active goal's message
        self.assertEqual(self.new_tasks(), [])

    def test_a_false_check_for_a_paused_goal_stays_quiet_and_a_match_sends_nothing(self):
        t = self.save("manager", "req-manager-goal-check", agent="manager", task=dict(TASK, goal_id=self.goal("paused")),
                      check=CHECK)
        before = self.model_events()
        self.tick(t["next_due"])
        runner, extra = self.sent()
        self.assertEqual(self.post(runner, extra, value=10)[1]["decision"], "quiet")
        self.tick(t["next_due"] + 900)
        runner, extra = self.sent()
        self.assertNotEqual(self.post(runner, extra, value=11)[1]["decision"], "started")
        self.assertIsNone(self.runs(t["id"])[-1]["event_id"])
        self.assertEqual(self.model_events(), before)                      # no manager or worker model start
        self.assertEqual(self.new_tasks(), [])

    def test_a_match_for_a_worker_under_a_lead_starts_a_parent_and_child_once(self):
        t = self.save("seo", "req-blog-0003", check=CHECK)
        self.tick(t["next_due"])
        runner, extra = self.sent()
        first = self.post(runner, extra, value=11, summary="11 open")
        self.assertEqual((first[0], first[1]["decision"]), (200, "started"))
        tasks = self.new_tasks()
        self.assertEqual([(x["owner"], x["requester"]) for x in tasks], [("lead-b", "manager"), ("seo", "lead-b")])
        self.assertEqual(tasks[1]["parent"], tasks[0]["id"])
        self.assertEqual(self.post(runner, extra, value=11, summary="11 open"), (200, dict(first[1], replayed=True)))
        self.assertEqual(self.post(runner, extra, value=12, summary="11 open")[0], 409)   # another body: refused
        self.assertEqual(len(self.new_tasks()), 2)                                     # still one pair


if __name__ == "__main__":
    unittest.main()

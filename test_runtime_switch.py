"""Owner feature runtime_switch: an existing worker changes between Codex and Claude through the 1.9 settings route
and the helper's normal idle update. In-process hub with a temporary Git kit and a stand-in helper status; the real
helper chat, update-guard and usage-collector code with stand-in tmux and files. No AI call, no real runtime and no
real machine."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid
from unittest.mock import Mock, patch

import fleet
from leftovers import scratch_home
import hub
import lifecycle
import usage
from test_ui_api import OwnerAPI

CODEX = "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"
STUDIO = "claude --permission-mode dontAsk {chrome} {settings} {prompt}"
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3", "mac-studio": "127.0.0.4",
                      "lab": "127.0.0.5", "pm": "127.0.0.6"},
        "accounts": {"openai-pro": {"provider": "openai", "title": "Pro"}},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": [],
                               "start": "claude --permission-mode dontAsk {settings} {prompt}"},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell", "web"],
                           "start": CODEX, "model": "gpt-6.1-sol", "effort": "high", "account": "openai-pro",
                           "title": "Operations", "expertise": ["ops"], "vault": "none"},
                   "studio": {"role": "worker", "runtime": "claude", "machine": "mac-studio",
                              "can": ["shell", "web", "browser", "screen"], "start": STUDIO, "allow": ["mcp__fleet__*"],
                              "screen_command": "/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex"},
                   "lab": {"role": "worker", "runtime": "grok", "machine": "lab", "can": ["shell"],
                           "start": "grok agent stdio"},
                   "pm": {"role": "lead", "runtime": "codex", "machine": "pm", "can": ["shell"], "start": CODEX}}}
OPENAI, ANTHROPIC = "openai:" + "a" * 32, "anthropic:" + "b" * 32
FEATURES = ["trigger_check", "trigger_code", "agent_setup", "agent_key", "runtime_switch"]
APP_SERVER = FEATURES + ["app_server_tasks"]        # a helper that runs Codex app-server tasks (lifecycle.app_server_task)
THREAD = "01a1245d-3a00-76a3-9ed4-299dcc277ae6"
CHAT = "You are vps, speaking directly with the owner in this agent's chat. The owner explicitly permits"


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def git(*args, cwd=None):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def tokens(runtime, total, at, sessions=None):
    """A token reading as the helper's collector sends it."""
    rows = sessions or [("s-" + runtime, total)]
    return {"input": total, "output": 0, "cache_read": 0, "cache_write": 0, "total": total, "sessions": len(rows),
            "since": at - 100, "last_activity": at, "collected_at": at, "source": usage.SOURCES[runtime],
            "scope": usage.SCOPE, "error": None,
            "by_session": [{"session_id": s, "total": n, "last_activity": at} for s, n in rows]}


def limits(runtime, key, at):
    return {"collected_at": at, "source": usage.LIMIT_SOURCES[runtime], "plan": "Pro", "account_key": key, "error": None,
            "windows": [{"id": "w", "label": "5 hours", "used_percent": 40, "resets_at": at + 3600, "window_minutes": 300}]}


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (Switch, HelperSide, Collector):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Switch(OwnerAPI):
    """The hub side, through the real routes, with a stand-in helper status of the VPS."""
    def setUp(self):
        super().setUp()
        self.server.machines = True             # each request comes from the machine that its route names
        self.root = Path(tempfile.mkdtemp(prefix="fleet-switch-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        seed = self.root / "seed"
        (seed / "profiles").mkdir(parents=True)
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        (seed / "profiles" / "vps.md").write_text("# Profile: vps\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", str(self.root / "origin.git"), str(self.root / "kit"))
        self.kit = self.root / "kit"
        hub.CFG["team_path"] = str(self.kit / "team.json")
        self.addCleanup(hub.CFG.pop, "team_path", None)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = json.loads(json.dumps(TEAM))
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90, tick=5)
        for name in hub.TEAM["agents"]:
            hub.touch(name)
        self.assertEqual(self.report()[0], 200)

    # ---- helpers
    def head(self):
        return git("rev-parse", "HEAD", cwd=self.kit)

    def team(self):
        return json.loads(git("show", "HEAD:team.json", cwd=self.kit))

    def sha(self):
        return self.request("/ui/team?db=test-generation")[1]["sha256"]

    def line(self, agent="vps"):
        return next(l for l in self.request("/ui/team?db=test-generation")[1]["lines"] if l["agent"] == agent)

    def report(self, runtime="codex", agent="vps", **changes):
        """The stand-in helper of an agent (the VPS) sends its machine status through the real route."""
        body = dict({"revision": self.head(), "runtime": {"name": runtime, "version": "1", "signed_in": True},
                     "runtimes": {"codex": {"version": "codex-cli 0.160.0", "signed_in": True},
                                  "claude": {"version": "2.1.287 (Claude Code)", "signed_in": True}},
                     "update": {"state": None, "detail": None}, "features": FEATURES,
                     "settings": hub.agent_settings(agent), "other_runtime_windows": [], "owner_chat_bound": None},
                    **changes)
        return self.request(f"/helper/status/{agent}", body)

    def opt_in(self, policy):
        """The owner's explicit opt-in of Studio, a team.json change that the hub runs: its stored Codex policy."""
        team = self.team()
        team["agents"]["studio"]["runtime_policies"] = {"codex": policy}
        hub.validate_team(team)
        (self.kit / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        git("commit", "-q", "-am", "Owner opts Studio in", cwd=self.kit)
        git("push", "-q", "origin", "HEAD:main", cwd=self.kit)
        hub.apply_team(team)
        return team["agents"]["studio"]

    def switch(self, runtime="claude", agent="vps", request_id=None):
        return self.request(f"/ui/team/agents/{agent}", {"request_id": request_id or str(uuid.uuid4()),
                                                         "db": "test-generation", "base_sha256": self.sha(),
                                                         "runtime": runtime})

    def usage_report(self, **body):
        return self.request("/helper/usage/vps", dict({"tokens": None, "limits": None}, **body))

    def stored_usage(self):
        return json.loads(hub.q1("SELECT data FROM agent_usage WHERE name='vps'")["data"])

    def task(self, state="completed", owner="vps"):
        return hub.ins("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,created,attempt) "
                       "VALUES(?,?,?,?,?,?,?,?,1)", ("t", "", "done", "none", owner, "manager", state, hub.now()))

    def model_record(self, task, model, effort, created):
        hub.ins("INSERT INTO thread_events(task,attempt,session,seq,ts,type,data,created) VALUES(?,?,?,?,?,?,?,?)",
                (task, 1, str(uuid.uuid4()), 1, created, "model", json.dumps({"model": model, "effort": effort}), created))

    def rule(self, check, agent="vps", state="active"):
        return hub.ins("INSERT INTO triggers(agent,state,revision,schedule,check_spec,task,late_minutes,"
                       "max_tasks_per_day,anchor,created,updated,request_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                       (agent, state, 1, json.dumps({"kind": "every", "minutes": 15}), json.dumps(check),
                        json.dumps({"title": "Look"}), 5, 1, hub.now(), hub.now(), hub.now(), str(uuid.uuid4())))

    def combined(self):
        """The agent's measured consumption: its runtime's reading and the reading of the runtime before."""
        data = self.stored_usage()
        return (data["tokens"] or {}).get("total", 0) + ((data.get("previous") or {}).get("tokens") or {}).get("total", 0)

    # ---- tests
    def test_an_idle_worker_switches_and_keeps_its_identity_access_and_history(self):
        t0 = hub.now()
        self.assertEqual(self.usage_report(tokens=tokens("codex", 1000, t0), limits=limits("codex", OPENAI, t0))[0], 200)
        done = self.task()
        self.model_record(done, "gpt-6.1-sol", "high", t0 - 5)
        hub.ins("INSERT INTO agent_limits(agent,since,until,reset_known,task) VALUES(?,?,?,?,?)",
                ("vps", t0 - 60, t0 + 3600, 1, None))                 # the Codex account's usage limit
        before = self.team()["agents"]["vps"]
        self.assertTrue(self.line()["runtime_switch"]["ready"], self.line()["runtime_switch"])

        code, receipt = self.switch()
        self.assertEqual(code, 200, receipt)
        self.assertEqual(receipt["changed"], [{"field": "runtime", "before": "codex", "after": "claude"},
                                              {"field": "model", "before": "gpt-6.1-sol", "after": None},
                                              {"field": "effort", "before": "high", "after": None},
                                              {"field": "account", "before": "openai-pro", "after": None}])
        self.assertEqual((receipt["updates_requested"], receipt["settings_pending"]), (["vps"], True))
        self.assertEqual(git("diff", "--name-only", "HEAD~1", "HEAD", cwd=self.kit), "team.json")   # profile unchanged
        after = self.team()["agents"]["vps"]
        self.assertEqual((after["runtime"], after["start"], after["allow"], after["runtime_policies"]),
                         ("claude", hub.FULL_ACCESS["claude"]["start"], hub.FULL_ACCESS["claude"]["allow"],
                          {"codex": {"start": CODEX}}))
        for key in ("role", "machine", "can", "title", "expertise", "vault"):
            self.assertEqual(after[key], before[key], key)
        self.assertEqual(self.count("tasks"), 1)
        # The old runtime's tokens stay apart; its account and its usage-limit hold end with it.
        data = self.stored_usage()
        self.assertEqual((data["previous"]["runtime"], data["previous"]["tokens"]["total"], data["tokens"], data["limits"]),
                         ("codex", 1000, None, None))
        self.assertIsNone(hub.active_limit("vps"))
        primary = next(r for a in hub.capacity_view(["vps"])["agents"] for r in a["routes"] if r["route"] == "primary")
        self.assertEqual(primary["group"], "unknown:vps:primary")
        # The old runtime's model is never shown as the new one's.
        self.assertIsNone(self.line()["reported_model"])
        self.model_record(done, "claude-sonnet-5-5", "high", hub.now() + 1)
        self.assertEqual(self.line()["reported_model"]["model"], "claude-sonnet-5-5")

    def test_new_work_waits_until_the_helper_runs_the_new_runtime_without_old_windows(self):
        self.assertEqual(self.switch()[0], 200)
        self.assertEqual(self.request("/ui/messages", self.command(recipient="vps"))[0], 200)
        delivered = lambda: [e["kind"] for e in
                             self.request("/events/vps?delivery=1&after=0&wait=0&alive=owner-chat")[1]["events"]]
        self.assertNotIn("chat", delivered())                   # the open chat window runs the old runtime
        self.report(runtime="claude", other_runtime_windows=["owner-chat"], owner_chat_bound=False)
        self.assertTrue(self.line()["settings_pending"])
        self.assertNotIn("chat", delivered())                   # the old chat is still closing
        missing = self.line()["runtime_switch"]["missing"]      # the old chat closes normally: no link request
        self.assertEqual(("settings_pending" in missing, "chat_not_bound" in missing), (True, False))
        self.report(runtime="claude", other_runtime_windows=[])
        self.assertFalse(self.line()["settings_pending"])
        self.assertIn("chat", delivered())
        row = next(m for m in self.request("/ui/machines?db=test-generation")[1]["machines"] if m["agent"] == "vps")
        self.assertEqual((row["settings"]["runtime"], row["runtimes"]["claude"]["signed_in"]), ("claude", True))

    def test_busy_work_is_named_and_nothing_changes(self):
        rule = self.rule({"path": "checks/queue.py", "commit": "c" * 40})      # committed code: no saved-code grant
        cases = {"open_tasks": lambda: self.task(state="working"),
                 "chats_waiting": lambda: self.request("/ui/messages", self.command(recipient="vps")),
                 "checks": lambda: hub.ins("INSERT INTO trigger_runs(trigger_id,revision,due,state,created) "
                                           "VALUES(?,?,?,?,?)", (rule, 1, hub.now(), "sent", hub.now())),
                 "jobs": lambda: hub.ins("INSERT INTO jobs(agent,task,kind,login,created) VALUES(?,?,?,?,?)",
                                         ("vps", None, "signin", "bws://login", hub.now()))}
        undo = {"open_tasks": "UPDATE tasks SET state='completed'", "chats_waiting": "DELETE FROM ui_requests",
                "checks": "UPDATE trigger_runs SET state='quiet'", "jobs": "UPDATE jobs SET finished=1"}
        head = self.head()
        for field, make in cases.items():
            with self.subTest(field):
                make()
                code, data = self.switch()
                self.assertEqual(code, 409, data)
                self.assertIn("agent_busy", data["missing"])
                self.assertTrue(data["busy"][field])
                self.assertEqual(self.line()["runtime_switch"]["busy"], data["busy"])
                self.assertEqual(self.head(), head)
                hub.q(undo[field])
        self.assertTrue(self.line()["runtime_switch"]["ready"])

    def test_missing_runtime_or_sign_in_or_an_old_helper_is_a_reason(self):
        for runtimes, features, code in (
                ({"claude": {"version": None, "signed_in": None}}, None, "runtime_not_installed"),
                ({"claude": {"version": "2.1.287", "signed_in": False}}, None, "runtime_not_signed_in"),
                ({"claude": {"version": "2.1.287", "signed_in": None}}, None, "runtime_sign_in_unknown"),
                (None, ["trigger_check", "agent_setup"], "helper_without_runtime_switch")):
            with self.subTest(code):
                changes = {"runtimes": runtimes} if runtimes else {}
                self.report(**changes, **({"features": features} if features else {}))
                self.assertIn(code, self.line()["runtime_switch"]["missing"])
                status, data = self.switch()
                self.assertEqual((status, code in data["missing"]), (409, True))
        self.report()
        self.assertTrue(self.line()["runtime_switch"]["ready"])

    def test_unsupported_agents_and_policies_say_why(self):
        manager, lab, studio = (self.line(n)["runtime_switch"] for n in ("manager", "lab", "studio"))
        # The manager says why (test_manager_switch): no helper report yet, and not its full-access form.
        why = ["helper_without_runtime_switch", "helper_status_unknown", "access_not_equivalent"]
        self.assertEqual((manager["ready"], manager["missing"]), (False, why))
        self.assertEqual((lab["to"], lab["missing"]), (None, ["runtime_not_supported"]))
        self.assertTrue({"access_not_equivalent", "capability_not_supported"} <= set(studio["missing"]))
        code, data = self.switch("codex", agent="manager")
        self.assertEqual((code, data["missing"]), (409, why))
        code, data = self.switch("codex", agent="studio")
        self.assertEqual(code, 409)
        self.assertEqual(self.team()["agents"]["studio"], TEAM["agents"]["studio"])

    def test_a_lost_receipt_replays_and_a_second_switch_waits_for_the_first(self):
        body = {"request_id": str(uuid.uuid4()), "db": "test-generation", "base_sha256": self.sha(), "runtime": "claude"}
        code, first = self.request("/ui/team/agents/vps", body)
        self.assertEqual(code, 200, first)
        head = self.head()
        self.assertEqual(self.request("/ui/team/agents/vps", body), (200, dict(first, replayed=True)))
        code, data = self.switch("codex")                       # the helper has not loaded the first switch
        self.assertEqual(code, 409)
        self.assertIn("settings_pending", data["missing"])
        self.assertEqual(self.head(), head)

    def test_an_open_chat_without_a_recorded_conversation_is_a_reason(self):
        self.report(owner_chat_bound=False)
        self.assertIn("chat_not_bound", self.line()["runtime_switch"]["missing"])
        self.report(owner_chat_bound=True)
        self.assertTrue(self.line()["runtime_switch"]["ready"])

    def test_a_rule_whose_saved_check_would_stop_is_named_and_other_rules_keep_working(self):
        # Plan C14: Claude Code in the full-access form runs its own checks too, so a switch between the two
        # full-access forms stops none of them.
        self.rule({"code": "saved", "sha256": "d" * 64, "code_by": "vps"})      # the VPS runs this saved code
        view = self.line()["runtime_switch"]
        self.assertEqual((view["rules"], "wakeup_rules_depend" in view["missing"]), ([], False))
        # The app-server pair is the owner's opt-in to other access: a Claude worker that runs its own checks would
        # stop them there, so each such rule is named.
        team = self.team()
        team["agents"]["studio"].update(start="claude --permission-mode bypassPermissions --tools default {chrome} "
                                              "{settings} {prompt}",
                                        runtime_policies={"codex": {"start": "app-server"}})
        hub.validate_team(team)
        (self.kit / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        git("commit", "-q", "-am", "Owner gives Studio full access and opts it in", cwd=self.kit)
        git("push", "-q", "origin", "HEAD:main", cwd=self.kit)
        hub.apply_team(team)
        self.report(runtime="claude", agent="studio", features=APP_SERVER)
        saved = {"code": "saved", "sha256": "e" * 64, "code_by": "studio"}
        stops = self.rule(saved, agent="studio")                        # Studio runs this saved code
        self.rule(dict(saved, run_on="vps"), agent="studio")            # another runner
        self.rule({"path": "checks/queue.py", "commit": "c" * 40}, agent="studio")      # committed code
        self.rule(saved, agent="studio", state="paused")
        view = self.line("studio")["runtime_switch"]
        self.assertEqual((view["rules"], "wakeup_rules_depend" in view["missing"]), ([stops], True))
        code, data = self.switch("codex", agent="studio")
        self.assertEqual((code, data["rules"]), (409, [stops]))
        hub.q("UPDATE triggers SET state='paused' WHERE id=?", (stops,))     # the owner pauses it first
        self.assertTrue(self.line("studio")["runtime_switch"]["ready"])

    def test_switch_back_restores_the_stored_policy_and_counts_every_token_once(self):
        t0 = hub.now()
        self.usage_report(tokens=tokens("codex", 1000, t0, [("chat", 400), ("t1", 600)]), limits=limits("codex", OPENAI, t0))
        self.assertEqual(self.switch()[0], 200)
        self.assertEqual(self.combined(), 1000)
        # The old chat writes its last records after the switch; the new helper reads the old runtime again.
        self.report(runtime="claude")
        self.assertEqual(self.usage_report(tokens=tokens("claude", 300, t0 + 10), limits=limits("claude", ANTHROPIC, t0 + 10),
                                           previous={"runtime": "codex", "tokens": tokens("codex", 1050, t0 + 10,
                                                                                         [("chat", 450), ("t1", 600)])})[0], 200)
        self.assertEqual(self.combined(), 1350)
        self.assertEqual(hub.q1("SELECT total FROM session_tokens WHERE agent='vps' AND session_id='chat'")["total"], 450)
        code, receipt = self.switch("codex")
        self.assertEqual(code, 200, receipt)
        vps = self.team()["agents"]["vps"]
        self.assertEqual((vps["start"], "allow" in vps, vps["runtime_policies"]),
                         (CODEX, False, {"claude": dict(hub.FULL_ACCESS["claude"])}))
        self.assertEqual(self.combined(), 1050 + 300)
        # Codex counts its own sessions again; Claude's reading stays apart.
        self.report(runtime="codex")
        self.usage_report(tokens=tokens("codex", 1070, t0 + 20, [("chat", 450), ("t1", 600), ("t2", 20)]),
                          previous={"runtime": "claude", "tokens": tokens("claude", 300, t0 + 20)})
        self.assertEqual(self.combined(), 1070 + 300)

    def test_a_write_about_one_agent_leaves_no_other_machine_behind(self):
        """Every machine runs team.json from its own checkout, so a write about one agent changes what all of them
        should run (hub.same_code). On 26 October 2026 the owner switched leo to Claude and changed its settings, and
        the machines of manager, mia and ivy stood "behind" for more than an hour (his app: Update available), because
        the hub asked only leo's machine to update. An added agent did the same on 24 October, and an account label
        asked no machine at all."""
        others = {"manager": "claude", "studio": "claude", "pm": "codex"}      # lab never reports: nothing to follow

        def report_all():
            self.assertEqual(self.report(self.team()["agents"]["vps"]["runtime"])[0], 200)
            for agent, runtime in others.items():
                self.assertEqual(self.report(runtime, agent)[0], 200)

        def states():
            machines = self.request("/ui/machines?db=test-generation")[1]["machines"]
            return {m["agent"]: m["update"]["state"] for m in machines}

        def owner(path, **body):
            return self.request(path, dict(request_id=str(uuid.uuid4()), db="test-generation", base_sha256=self.sha(),
                                           **body))

        report_all()
        self.assertEqual(states(), {"manager": "current", "vps": "current", "studio": "current", "pm": "current",
                                    "lab": None})
        writes = (("settings", lambda: owner("/ui/team/agents/vps", can=["shell"]), ["vps"]),
                  ("switch", self.switch, ["vps"]),
                  ("account", lambda: owner("/ui/team/accounts", account="anthropic-max", provider="anthropic",
                                            title="Max"), None))
        for n, (what, write, receipt) in enumerate(writes, 1):
            code, answer = write()
            self.assertEqual(code, 200, (what, answer))
            self.assertEqual(answer.get("updates_requested"), receipt, what)   # the receipt names the agent it is about
            head = self.head()
            self.assertEqual(states(), {"manager": "requested", "vps": "requested", "studio": "requested",
                                        "pm": "requested", "lab": None}, what)
            for agent in ("vps", *others):              # each machine asked once for each write, for its revision
                events = hub.q("SELECT extra FROM events WHERE agent=? AND kind='update' ORDER BY id", (agent,))
                self.assertEqual(len(events), n, (what, agent))
                self.assertEqual(json.loads(events[-1]["extra"])["desired_revision"], head, (what, agent))
            report_all()                                # each helper took its update and reports the new revision
            self.assertEqual(set(states().values()), {"current", None}, what)

    # ---- the owner's opt-in pair: Claude and Codex app-server, a different permission policy (not equal access)
    def test_studio_goes_to_codex_app_server_only_with_the_opt_in_and_back_to_its_exact_claude_policy(self):
        self.report(runtime="claude", agent="studio", features=APP_SERVER)
        for policy in (None, {"start": CODEX}):         # no opt-in; Fleet's full Codex form is no opt-in either
            if policy:
                self.opt_in(policy)
            self.assertTrue({"access_not_equivalent", "capability_not_supported"} <=
                            set(self.line("studio")["runtime_switch"]["missing"]), policy)
        before = self.opt_in({"start": "app-server"})
        self.report(runtime="claude", agent="studio", features=APP_SERVER)
        self.assertTrue(self.line("studio")["runtime_switch"]["ready"], self.line("studio")["runtime_switch"])
        code, receipt = self.switch("codex", agent="studio")
        self.assertEqual((code, receipt.get("changed")), (200, [{"field": "runtime", "before": "claude", "after": "codex"}]))
        after = self.team()["agents"]["studio"]
        self.assertEqual((after["runtime"], after["start"], "allow" in after, after["runtime_policies"]),
                         ("codex", "app-server", False, {"claude": {"start": STUDIO, "allow": ["mcp__fleet__*"]}}))
        self.assertEqual({k: v for k, v in after.items() if k not in ("runtime", "start", "allow", "runtime_policies")},
                         {k: v for k, v in before.items() if k not in ("runtime", "start", "allow", "runtime_policies")})
        # Its helper loads the change; the switch back restores the exact Claude policy, and Studio is as it was.
        self.report(runtime="codex", agent="studio", features=APP_SERVER)
        code, receipt = self.switch("claude", agent="studio")
        self.assertEqual(code, 200, receipt)
        self.assertEqual(self.team()["agents"]["studio"], before)

    def test_the_pair_needs_a_helper_with_app_server_tasks_and_keeps_every_other_guard(self):
        self.opt_in({"start": "app-server"})
        head = self.head()
        self.report(runtime="claude", agent="studio")                  # a helper from before app_server_tasks
        code, data = self.switch("codex", agent="studio")
        self.assertEqual((code, data["missing"]), (409, ["helper_without_runtime_switch"]))
        self.report(runtime="claude", agent="studio", features=APP_SERVER)
        task = self.task(state="working", owner="studio")
        code, data = self.switch("codex", agent="studio")
        self.assertEqual((code, data["missing"], data["busy"]["open_tasks"]), (409, ["agent_busy"], [f"T-{task}"]))
        hub.q("UPDATE tasks SET state='completed'")
        hub.q("UPDATE machine_status SET reported=? WHERE agent='studio'", (hub.now() - hub.MACHINE_STALE - 1,))
        code, data = self.switch("codex", agent="studio")
        self.assertEqual((code, data["missing"]), (409, ["helper_status_unknown"]))
        self.assertEqual(self.head(), head)                             # nothing changed
        # The manager never takes the policy: it is not the manager's full-access form, and team.json refuses it.
        team = self.team()
        team["agents"]["manager"]["runtime_policies"] = {"codex": {"start": "app-server"}}
        self.assertIn("access_not_equivalent", hub.runtime_switch("manager", team)["missing"])
        with self.assertRaisesRegex(ValueError, "app-server is only for a Codex worker or lead"):
            hub.validate_team(team)

    def test_a_malformed_or_inexact_app_server_policy_is_refused(self):
        team = self.team()
        for agent, change in (("studio", {"runtime_policies": {"codex": {"start": "app-server", "allow": []}}}),
                              ("pm", {"start": "app-server", "allow": ["Bash"]}),
                              ("vps", {"start": "app-server", "runtime_policies": {"claude": {"start": "app-server"}}}),
                              ("studio", {"start": "app-server"})):
            with self.subTest(agent=agent, change=change):
                bad = json.loads(json.dumps(team))
                bad["agents"][agent].update(change)
                with self.assertRaisesRegex(ValueError, "app-server is only for a Codex worker or lead, with no allow"):
                    hub.validate_team(bad)
        lone = json.loads(json.dumps(team))
        lone["agents"]["vps"]["start"] = "app-server"                  # no stored Claude policy to go back to
        hub.validate_team(lone)
        self.assertIn("access_not_equivalent", hub.runtime_switch("vps", lone)["missing"])
        # only an exact opt-in is the pair, and since DevOps plan 0.2 an inexact one is no start form at all
        inexact = json.loads(json.dumps(team))
        inexact["agents"]["studio"]["runtime_policies"] = {"codex": {"start": "app-server --listen stdio://"}}
        with self.assertRaisesRegex(ValueError, "start must be one of Fleet's own forms"):
            hub.validate_team(inexact)


class HelperSide(unittest.TestCase):
    """The helper after a switch: its chat bindings, the safe close of the old chat, and no restart during a check or
    a login job."""
    CLAUDE = {"role": "worker", "runtime": "claude", "machine": "vps", "can": ["shell"],
              "start": hub.FULL_ACCESS["claude"]["start"], "allow": hub.FULL_ACCESS["claude"]["allow"],
              "runtime_policies": {"codex": {"start": CODEX}}}

    def setUp(self):
        home = tempfile.TemporaryDirectory(prefix="fleet-switch-helper-")
        self.addCleanup(home.cleanup)
        self.home = Path(home.name)
        for p in (patch.object(fleet, "HOME", str(self.home / ".fleet")),
                  patch.object(fleet, "SESSIONS", str(self.home / ".fleet" / "sessions")),
                  patch.dict("os.environ", {"CODEX_HOME": str(self.home / ".codex"),
                                            "CLAUDE_CONFIG_DIR": str(self.home / ".claude")})):
            p.start()
            self.addCleanup(p.stop)

    def codex_chat(self):
        """The Codex owner chat of this generation with its recorded conversation file."""
        folder = self.home / ".codex" / "sessions" / "2026" / "10" / "11"
        folder.mkdir(parents=True, exist_ok=True)
        rows = [{"type": "session_meta", "payload": {"id": THREAD, "cwd": fleet.KIT}},
                {"type": "response_item", "payload": {"type": "message", "role": "user",
                                                      "content": [{"type": "input_text", "text": CHAT}]}}]
        (folder / f"rollout-2026-10-11T05-50-51-{THREAD}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))

    def tmux(self, windows, start, screen="> "):
        def run(*args, check=False, **kw):
            out, code = "", 0
            if args[0] == "display-message" and "#{pane_start_command}" in args:
                out = start + "\n" if "owner-chat" in windows else ""     # a missing window: 0 and no output (tmux)
            elif args[0] == "show-options":
                out = "test-db:1\n"
            elif args[0] == "capture-pane":
                out = screen
            elif args[0] == "kill-window":
                windows.remove("owner-chat")
            return subprocess.CompletedProcess(args, code, out, "")
        return run

    def helper(self, windows, start, screen="> "):
        h = fleet.Helper("vps", self.CLAUDE)
        h.lifecycle = Mock()
        for p in (patch("fleet.tmux", self.tmux(windows, start, screen)),
                  patch.object(h, "look", side_effect=lambda: list(windows)), patch.object(fleet.time, "sleep")):
            p.start()
            self.addCleanup(p.stop)
        return h

    def quiet_twice(self, h):
        h.retire_old_chat()
        if h.retiring:                          # the same quiet reading, RETIRE_QUIET seconds later
            h.retiring = (h.retiring[0] - fleet.RETIRE_QUIET - 1, h.retiring[1])
        h.retire_old_chat()

    def test_the_old_chat_closes_only_when_quiet_and_bound(self):
        old = "env FLEET_TASK= codex resume --no-daemon " + THREAD
        fleet.save_chat_record("vps", {"generation": "test-db", "marker": None, "session": THREAD, "started": 1.0})
        self.codex_chat()
        windows = ["owner-chat"]
        h = self.helper(windows, old, screen="Working (12s - esc to interrupt)")
        self.assertEqual(h.other_runtime_windows(), ["owner-chat"])
        with patch.object(h, "task_work", return_value={}), patch.object(h, "quiesce", return_value=(True, 0, "")):
            self.quiet_twice(h)
            self.assertEqual(windows, ["owner-chat"])                 # a running turn goes on
        h = self.helper(windows, old)
        with patch.object(h, "task_work", return_value={}), patch.object(h, "quiesce", return_value=(True, 0, "")):
            h.retire_old_chat()
            self.assertEqual(windows, ["owner-chat"])                 # one quiet reading is not enough
            self.quiet_twice(h)
        self.assertEqual((windows, h.other_runtime_windows()), ([], []))
        h.lifecycle.report.assert_called()
        self.assertEqual(fleet.load_chat_record("vps")["session"], THREAD)      # kept for a switch back

    def test_an_unbound_or_unreadable_old_chat_stays_and_keeps_the_switch_pending(self):
        for start in ("env FLEET_TASK= codex --no-daemon", "'unclosed"):
            with self.subTest(start):
                windows = ["owner-chat"]
                h = self.helper(windows, start)
                with patch.object(h, "task_work", return_value={}), patch.object(h, "quiesce", return_value=(True, 0, "")), \
                        patch.object(h, "say"):
                    self.quiet_twice(h)
                self.assertEqual(windows, ["owner-chat"])
                self.assertEqual(h.switch_state()["other_runtime_windows"], ["owner-chat"])

    def test_claude_s_unnumbered_trust_question_gets_no_typed_signal(self):
        """The first start of Claude Code in a folder that it does not trust yet: the inbox signal and its Enter would
        pick "No, exit", which is selected. The owner answers it; the session gets its signal after that."""
        screen, sent = ["Accessing workspace:\n\n /home/claude/fleet-pilot\n\n Quick safety check: Is this a project you "
                        "created or one you trust?\n\n ❯ No, exit\n   Yes, I trust this folder\n"], []

        def tmux(*args, check=False, **kw):
            if args[0] == "send-keys":
                sent.append(args)
            out = "0\n" if "#{pane_in_mode}" in args else screen[0] if args[0] == "capture-pane" else ""
            return subprocess.CompletedProcess(args, 0, out, "")
        with patch("fleet.tmux", tmux), patch.object(fleet.time, "sleep"):
            self.assertEqual((fleet.type_into("fleet-vps", "owner-chat", fleet.CHAT_SIGNAL), sent), ("asks", []))
            screen[0] = "╭───╮\n│ > \n╰───╯\n  ? for shortcuts\n"
            self.assertEqual(fleet.type_into("fleet-vps", "owner-chat", fleet.CHAT_SIGNAL), "typed")   # its input box
        self.assertEqual(len(sent), 2)

    def test_a_new_window_gets_no_signal_while_its_runtime_starts(self):
        h = fleet.Helper("vps", self.CLAUDE)
        # tmux answers with an idle screen: an owner chat is not typed into while its screen shows a turn running.
        idle = subprocess.CompletedProcess([], 0, "", "")
        with patch("fleet.start_window"), patch("fleet.tmux", return_value=idle), patch.object(h, "say"), \
                patch("fleet.type_into", return_value="typed") as typed:
            h.start("owner-chat", "claude --session-id x", 1, "test-db")
            h.signal("owner-chat", [7])             # the redelivery at the next poll, seconds after the start
            typed.assert_not_called()
            h.listed = {"owner-chat": 1}            # its session listed its tools (plan C5)
            h.signal("owner-chat", [7])
            typed.assert_not_called()               # and its input box is not up yet
            h.screens["owner-chat"] = {"class": "idle", "idle_run": 1}     # its empty input line: it can take a line now
            h.signal("owner-chat", [7])             # a message it was never told of
        typed.assert_called_once()

    def test_a_missing_chat_window_is_not_an_old_window_when_tmux_answers_with_nothing(self):
        windows = []
        h = self.helper(windows, "")                # tmux: exit status 0 and no output for a missing target
        self.assertEqual(h.switch_state(), {"other_runtime_windows": [], "owner_chat_bound": None})
        windows.append("owner-chat")                # a window that is there but cannot be read stays fail-closed
        self.assertEqual(h.other_runtime_windows(), ["owner-chat"])

    def test_leftover_processes_of_the_old_chat_keep_the_switch_pending_until_they_end(self):
        fleet.save_chat_record("vps", {"generation": "test-db", "marker": None, "session": THREAD, "started": 1.0})
        self.codex_chat()
        windows = ["owner-chat"]
        h = self.helper(windows, "env FLEET_TASK= codex resume " + THREAD)
        with patch.object(h, "task_work", return_value={4242: "codex-code-mode"}), \
                patch.object(h, "quiesce", return_value=(False, 0, "4242 codex-code-mode")), patch.object(h, "say"):
            self.quiet_twice(h)
        self.assertEqual((windows, h.other_runtime_windows()), ([], ["owner-chat"]))
        with patch.object(h, "quiesce", return_value=(True, 1, "")), patch.object(h, "say"):
            h.retire_old_chat()
        self.assertEqual(h.other_runtime_windows(), [])

    @unittest.skipUnless(os.path.isfile(os.path.join(fleet.KIT, "profiles", "vps.md")),
                         "it reads profiles/vps.md, the owner's own profile, which a published copy has not got")
    def test_a_claude_chat_records_its_own_session_and_continues_it_after_a_switch_back(self):
        fleet.save_chat_record("vps", {"generation": "test-db", "marker": None, "session": THREAD, "started": 1.0})
        windows, started = [], []
        h = fleet.Helper("vps", self.CLAUDE)
        event = dict(id=7, kind="chat", task=None, text="x", extra={"generation": "test-db"})
        with patch.object(h, "look", side_effect=lambda: list(windows)), patch.object(h, "say"), patch("fleet.http"), \
                patch("fleet.session_credential", return_value=None), \
                patch.object(h, "start", side_effect=lambda name, command, *a, **kw: started.append(command)):
            h.handle(event)
            session = fleet.load_chat_record("vps", "claude")["session"]
            words = fleet.launch_words(started[-1])
            self.assertEqual((words[0], words[words.index("--session-id") + 1]), ("claude", session))
            self.assertEqual(fleet.load_chat_record("vps")["session"], THREAD)     # the Codex binding is untouched
            folder = self.home / ".claude" / "projects" / re.sub(r"[^A-Za-z0-9-]", "-", os.path.realpath(fleet.KIT))
            folder.mkdir(parents=True, exist_ok=True)
            (folder / f"{session}.jsonl").write_text("{}\n")                    # Claude wrote the conversation
            h.handle(event)                                                     # its window ended meanwhile
        words = fleet.launch_words(started[-1])
        self.assertEqual(words[words.index("--resume") + 1], session)

    def test_the_owner_records_the_old_runtime_chat_by_name(self):
        self.codex_chat()
        args = type("Args", (), {"agent": "vps", "session": THREAD, "runtime": "codex"})
        with patch("fleet.agent_conf", return_value=self.CLAUDE), patch("fleet.http", return_value=(200, {"db": "test-db"})), \
                patch("builtins.print"):
            fleet.cmd_chat_session(args)
            self.assertEqual(fleet.load_chat_record("vps")["session"], THREAD)
            self.assertIsNone(fleet.load_chat_record("vps", "claude"))
            args.runtime = None                         # the Claude chat of that id does not exist
            with patch("sys.stderr"), self.assertRaises(SystemExit):
                fleet.cmd_chat_session(args)

    def test_no_update_restarts_the_helper_while_a_check_or_a_login_job_runs(self):
        h = fleet.Helper("vps", self.CLAUDE)
        life = lifecycle.Lifecycle("/kit", "vps", self.CLAUDE, lambda payload: (200, {}), busy=lambda: h.outside > 0,
                                   run=lambda argv, **kw: (1, "", ""), models=lambda command: (None, "none"))
        h.lifecycle, life.last_report = life, time.time()
        with patch.object(life, "apply", return_value=False) as apply, patch.object(life, "report"):
            h.begin_outside()                                   # a check runs
            life.arm("b" * 40)
            life.tick()
            apply.assert_not_called()
            h.end_outside()
            life.tick()
            apply.assert_called_once()
        with life.gate:                                         # an update is under way: the check event stays pending
            self.assertRaises(lifecycle.Updating, h.begin_outside)
        inside = []
        with patch("fleet.do_signin", side_effect=lambda *a: inside.append(h.outside) or "signed in"), \
                patch("fleet.http", return_value=(200, {})), patch.object(h, "say"):
            h.login_job("signin", "T-9", {"login": "bws://login", "job": 3})
        self.assertEqual((inside, h.outside), ([1], 0))


class Collector(unittest.TestCase):
    """The helper's usage collector after a switch: no number of the old runtime stands for the new one, and the old
    runtime's own sessions are read again."""
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="fleet-switch-usage-")
        self.addCleanup(tmp.cleanup)
        self.home, self.kit = Path(tmp.name) / "home", Path(tmp.name) / "kit"
        self.kit.mkdir(parents=True)
        self.rollout = self.home / ".codex" / "sessions" / "2026" / "10" / "11" / "rollout-x.jsonl"
        self.rollout.parent.mkdir(parents=True)
        self.rollout.write_text(json.dumps({"type": "session_meta", "payload": {"id": "s1", "cwd": str(self.kit.resolve())}}) + "\n")
        self.count(100)

    def count(self, total):
        """The old Codex session writes a cumulative token count."""
        with self.rollout.open("a") as stream:
            stream.write(json.dumps({"type": "event_msg", "timestamp": "2026-10-11T06:00:00Z", "payload": {
                "type": "token_count", "info": {"total_token_usage": {"input_tokens": total, "output_tokens": 0}}}}) + "\n")

    def collector(self, published):
        return usage.Collector(str(self.kit), "vps", "claude", published.append, home=self.home, previous="codex")

    def test_a_cache_of_another_runtime_gives_no_numbers_or_poll_time(self):
        cache = self.home / ".fleet" / "usage-vps.json"
        cache.parent.mkdir(parents=True)
        now = time.time()
        cache.write_text(json.dumps({"data": {"tokens": None, "limits": limits("codex", OPENAI, now)}, "last_poll": now}))
        c = self.collector([])
        self.assertEqual((c.data["limits"], c.last_poll), (None, 0))

    def test_the_old_runtime_is_read_again_without_its_account(self):
        published = []
        with patch("usage.claude_limits", side_effect=ValueError("no account here")), \
                patch("usage.codex_limits", side_effect=AssertionError("the old account is never read")):
            c = self.collector(published)
            c.collect()
            self.assertEqual(published[-1]["previous"]["tokens"]["total"], 100)
            self.count(130)                     # the old chat's last records, after the switch
            c.collect()
            self.assertEqual(published[-1]["previous"]["tokens"]["total"], 100)       # read again only every poll
            c.previous_poll = 0
            c.collect()
        self.assertEqual(published[-1]["previous"]["tokens"]["total"], 130)
        self.assertEqual(usage.validate_usage(published[-1], "claude")["previous"]["runtime"], "codex")
        saved = json.loads((self.home / ".fleet" / "usage-vps.json").read_text())
        self.assertEqual(saved["runtime"], "claude")


if __name__ == "__main__":
    unittest.main()

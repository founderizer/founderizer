"""Owner API 1.9: agent setup. In-process hub, temporary Git repositories, a stand-in helper, a stand-in Codex
app-server and a stand-in age program for the vault's own store; no AI calls and no real account."""
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

import fleet
from leftovers import scratch_home
import hub
import lifecycle
import onboard
import threads
import vault
from test_ui_api import OwnerAPI

START = "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3", "mac-studio": "127.0.0.4"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell", "web"], "start": START},
                   "studio": {"role": "worker", "runtime": "claude", "machine": "mac-studio", "can": ["shell", "browser"]}}}
LOGIN = "bws://11111111-2222-4333-8444-55555555555b"
PROFILE = f"""# Profile: vps

Written by the owner. Agents cannot change it.

**Character.** Careful.

**Responsible for.** Checks.

**May do without asking.** Read files.

**Must ask first.** Spending.

**Logins it may use.** The practice login `{LOGIN}`.

**Knowledge files.**

- knowledge/services.md
"""
OPTIONS = [{"model": "gpt-6.1-sol", "display_name": "GPT-6.1 Sol", "default": True, "efforts": ["low", "medium", "high"],
            "default_effort": "low"},
           {"model": "gpt-6-luna", "display_name": "GPT-6 Luna", "default": False, "efforts": ["low", "medium"],
            "default_effort": "medium"}]


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def git(*args, cwd=None):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (Setup, Helper):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Setup(OwnerAPI):
    """The hub side, through the real routes, with a stand-in helper on its own machine's address."""
    def setUp(self):
        super().setUp()
        self.server.machines = True             # each request comes from the machine that its route names
        self.root = Path(tempfile.mkdtemp(prefix="fleet-setup-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        seed = self.root / "seed"
        (seed / "profiles").mkdir(parents=True)
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        (seed / "profiles" / "vps.md").write_text(PROFILE)
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

    # ---- helpers
    def head(self):
        return git("rev-parse", "HEAD", cwd=self.kit)

    def sha(self):
        return self.request("/ui/team?db=test-generation")[1]["sha256"]

    def report(self, **changes):
        """The stand-in helper sends its machine status through the real route."""
        body = dict({"revision": self.head(), "runtime": {"name": "codex", "version": "codex-cli 0.160.0", "signed_in": True},
                     "update": {"state": None, "detail": None}, "features": ["trigger_check", "agent_setup"],
                     "settings": hub.agent_settings("vps"),
                     "models": {"runtime": "codex", "ok": True, "read_at": hub.now(), "source": "codex app-server model/list",
                                "other_names": False, "error": None, "options": OPTIONS}}, **changes)
        return self.request("/helper/status/vps", body)

    def settings(self, **body):
        return self.request("/ui/team/agents/vps", dict(dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                             base_sha256=self.sha()), **body))

    def check(self, items):
        """The owner asks for a machine check, and the stand-in helper answers it with these setup items."""
        code, data = self.request("/ui/machines/vps/check", {"request_id": str(uuid.uuid4()), "db": "test-generation"})
        self.assertEqual(code, 200, data)
        self.assertEqual(self.report(check=data["check"]["id"], verify=items)[0], 200)
        return data["check"]["id"]

    def row(self):
        return next(m for m in self.request("/ui/machines?db=test-generation")[1]["machines"] if m["agent"] == "vps")

    def delivered(self, alive=""):
        """The events that would start or reach a session; helper work such as an update event is not one."""
        return [e["kind"] for e in self.request(f"/events/vps?delivery=1&after=0&wait=0&alive={alive}")[1]["events"]
                if e["kind"] in ("task", "say", "chat")]

    def set_team(self, **vps):
        team = json.loads((self.kit / "team.json").read_text())
        team["agents"]["vps"].update(vps)
        (self.kit / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        git("commit", "-q", "-am", "test change", cwd=self.kit)
        git("push", "-q", "origin", "main", cwd=self.kit)
        hub.apply_team(team)

    # ---- tests
    def test_the_screen_runtime_has_its_own_model_and_effort(self):
        code, data = self.settings(screen={"model": "gpt-6.1-sol", "effort": "high"})
        self.assertEqual((code, data["error"]), (400, "Vps has no screen runtime."))
        self.set_team(screen_command="/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex")
        self.report()                                           # a helper older than 1.11: no screen_model
        self.assertEqual(self.settings(screen={"model": "gpt-6.1-sol", "effort": "high"})[0], 409)
        reading = {"runtime": "codex", "ok": True, "read_at": hub.now(), "source": "codex app-server model/list",
                   "other_names": False, "error": None, "options": OPTIONS}
        features = ["trigger_check", "agent_setup", "screen_model"]
        self.report(features=features, screen_settings={"model": None, "effort": None}, screen_models=reading)
        for screen, status in (({"model": "gpt-6-luna", "effort": "high"}, 409), ({"model": "gpt-7", "effort": None}, 409),
                               ({"model": "gpt-6-luna"}, 400), ({"model": "Bad Name", "effort": None}, 400)):
            with self.subTest(screen=screen):
                self.assertEqual(self.settings(screen=screen)[0], status)
        code, data = self.settings(screen={"model": "gpt-6-luna", "effort": "medium"})
        self.assertEqual(code, 200, data)
        after = {"model": "gpt-6-luna", "effort": "medium"}
        self.assertEqual((data["changed"], data["updates_requested"]),
                         ([{"field": "screen", "before": {"model": None, "effort": None}, "after": after}], ["vps"]))
        self.assertEqual(json.loads((self.kit / "team.json").read_text())["agents"]["vps"]["screen"], after)
        self.assertTrue(hub.settings_pending("vps"))            # no new session until the helper loads them
        self.report(features=features, screen_settings=after, screen_models=reading, settings=hub.agent_settings("vps"))
        self.assertFalse(hub.settings_pending("vps"))
        self.assertEqual(self.settings(model="gpt-6.1-sol")[0], 200)       # a primary edit keeps the screen settings
        line = next(l for l in self.request("/ui/team?db=test-generation")[1]["lines"] if l["agent"] == "vps")
        self.assertEqual((line["model"], line["screen"], line["reported_screen_model"]), ("gpt-6.1-sol", after, None))
        row = self.row()
        self.assertEqual((row["settings"]["screen"], row["screen_models"]["options"]), (after, OPTIONS))
        self.assertIn("screen_model", self.request()[1]["ui_features"])
        claude = {"runtime": "claude", "ok": True, "read_at": hub.now(), "source": "claude --help", "other_names": True,
                  "error": None, "options": [{"model": "opus", "display_name": "opus", "default": False,
                                              "efforts": ["max"], "default_effort": None}]}
        self.report(features=features, screen_settings=after, screen_models=claude, settings=hub.agent_settings("vps"))
        for screen in ({"model": "claude-opus-5-5", "effort": None}, {"model": "opus", "effort": "max"}):
            with self.subTest(screen=screen):                   # a non-Codex list never offers a screen model
                code, data = self.settings(screen=screen)
                self.assertEqual(code, 409, data)
                self.assertIn("no current Codex screen model list", data["error"])
        self.report(features=features, screen_settings=after, screen_models=reading, settings=hub.agent_settings("vps"))
        code, data = self.settings(screen={"model": None, "effort": None})     # back to the screen runtime's defaults
        self.assertEqual(code, 200, data)
        self.assertNotIn("screen", json.loads((self.kit / "team.json").read_text())["agents"]["vps"])

    def test_a_screen_report_never_stands_for_the_primary_model(self):
        tasks = {needs: hub.ins("INSERT INTO tasks(title,owner,requester,state,needs,created) "
                                "VALUES('t','vps','manager','completed',?,?)", (needs, hub.now())) for needs in ("none", "screen")}
        for needs, model in (("none", "gpt-6.1-sol"), ("screen", "gpt-6-luna")):       # the screen record is newer
            hub.ins("INSERT INTO thread_events(task,attempt,session,seq,ts,type,data,created) VALUES(?,1,?,1,NULL,'model',?,?)",
                    (tasks[needs], str(uuid.uuid4()), json.dumps({"model": model, "effort": "medium"}), hub.now()))
        self.assertEqual((hub.reported_model("vps")["model"], hub.reported_model("vps", screen=True)["model"]),
                         ("gpt-6.1-sol", "gpt-6-luna"))
        old = hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES('old','vps','manager','completed',?)",
                      (hub.now(),))                             # a task from before needs was set: primary
        hub.ins("INSERT INTO thread_events(task,attempt,session,seq,ts,type,data,created) VALUES(?,1,?,1,NULL,'model',?,?)",
                (old, str(uuid.uuid4()), json.dumps({"model": "gpt-5.6-sol", "effort": "low"}), hub.now()))
        self.assertIsNone(hub.q1("SELECT needs FROM tasks WHERE id=?", (old,))["needs"])
        self.assertEqual((hub.reported_model("vps")["model"], hub.reported_model("vps", screen=True)["model"]),
                         ("gpt-5.6-sol", "gpt-6-luna"))
        team = json.loads(json.dumps(TEAM))
        team["agents"]["vps"]["screen"] = {"model": "gpt-6-luna"}
        with self.assertRaises(ValueError) as refused:          # screen settings need a screen runtime
            hub.validate_team(team)
        self.assertIn("screen settings need a screen runtime", str(refused.exception))
        team["agents"]["vps"]["screen_command"] = "/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex"
        hub.validate_team(team)

    def test_model_and_effort_are_checked_against_the_runtime_reading_and_committed(self):
        self.report()
        for body, code in (({"model": "gpt-6-luna", "effort": "high"}, 409), ({"model": "gpt-7"}, 409),
                           ({"effort": "ultra"}, 409), ({"model": "Bad Name"}, 400), ({"can": ["shell", "fly"]}, 400),
                           ({"color": "blue"}, 400), ({}, 400)):
            with self.subTest(body=body):
                self.assertEqual(self.settings(**body)[0], code)
        self.assertEqual(self.request("/ui/team/agents/manager", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                                       base_sha256=self.sha(), active=False))[0], 400)
        hub.q("UPDATE machine_status SET data=json_set(data, '$.models.read_at', ?) WHERE agent='vps'", (hub.now() - 90000,))
        self.assertEqual(self.settings(model="gpt-6-luna")[1]["error"].split(" (")[0], "Vps has no current model list")
        self.report()
        body = dict(request_id=str(uuid.uuid4()), db="test-generation", base_sha256=self.sha(), model="gpt-6-luna",
                    effort="medium", can=["web", "shell"])
        code, data = self.request("/ui/team/agents/vps", body)
        self.assertEqual(code, 200, data)
        self.assertEqual((data["changed"], data["updates_requested"], data["settings_pending"], data["activation"]),
                         ([{"field": "model", "before": None, "after": "gpt-6-luna"},
                           {"field": "effort", "before": None, "after": "medium"}], ["vps"], True, None))
        self.assertEqual(self.request("/ui/team/agents/vps", body), (200, dict(data, replayed=True)))
        committed = json.loads(git("show", "origin/main:team.json", cwd=self.kit) if not git("fetch", "-q", cwd=self.kit)
                               else "{}")["agents"]["vps"]
        self.assertEqual((committed["model"], committed["effort"], committed["can"]), ("gpt-6-luna", "medium", ["shell", "web"]))
        line = next(l for l in self.request("/ui/team?db=test-generation")[1]["lines"] if l["agent"] == "vps")
        self.assertEqual((line["model"], line["effort"], line["active"], line["settings_pending"], line["reported_model"]),
                         ("gpt-6-luna", "medium", True, True, None))
        self.assertIn("agent_setup", self.request()[1]["ui_features"])

    def test_no_new_session_starts_with_old_settings(self):
        self.report()
        self.assertEqual(self.settings(model="gpt-6-luna")[0], 200)
        text, error = hub.call_tool("manager", "create_task", {"owner": "vps", "title": "Check", "done_when": "Checked."})
        self.assertFalse(error, text)
        hub.q("INSERT INTO ui_requests(request_id,kind,need_id,text,event_id,created,client,recipient) "
              "VALUES(?,?,?,?,?,?,?,?)", (str(uuid.uuid4()), "message", None, "Hello", hub.emit("vps", "chat", "Hello",
                                          extra={"generation": "test-generation"}), hub.now(), "t", "vps"))
        hub.touch("vps")
        hub.liveness(hub.now())
        self.assertEqual(hub.q1("SELECT live_path FROM tasks")["live_path"], "waiting for vps to load its new settings")
        self.assertEqual(self.delivered(), [])                              # neither the task nor a new chat session
        self.assertEqual(self.delivered(alive="owner-chat"), ["chat"])      # an open chat session continues
        self.assertTrue(self.row()["settings_pending"])
        self.report(settings={"model": "gpt-6-luna", "effort": None, "can": ["shell", "web"]})    # the restarted helper
        self.assertFalse(self.row()["settings_pending"])
        self.assertEqual(sorted(self.delivered()), ["chat", "task"])
        hub.liveness(hub.now())
        self.assertEqual(hub.q1("SELECT live_path FROM tasks")["live_path"], "waiting for its session to start")

    def test_an_agent_in_setup_gets_no_work_until_a_fresh_check_passes(self):
        self.set_team(active=False)
        self.report()
        text, error = hub.call_tool("manager", "create_task", {"owner": "vps", "title": "Check", "done_when": "Checked."})
        self.assertEqual((error, text), (True, "vps is in setup. The owner activates it in Fleet."))
        self.assertEqual(self.request("/ui/messages", self.command(recipient="vps"))[0], 409)
        self.assertIn("vps (in setup: no tasks)", hub.overview_text())
        self.assertFalse(next(a for a in self.request()[1]["agents"] if a["name"] == "vps")["active"])
        code, data = self.settings(active=True)
        self.assertEqual((code, [(m["kind"], m["ref"]) for m in data["missing"]]), (409, [("check", "latest")]))
        runtime = {"kind": "runtime", "ref": "codex", "state": "ok", "detail": "codex-cli 0.160.0, signed in"}
        self.check([runtime, {"kind": "login", "ref": LOGIN, "state": "failed", "detail": "not_found"}])
        code, data = self.settings(active=True)
        self.assertEqual((code, data["missing"]), (409, [{"kind": "login", "ref": LOGIN, "state": "failed",
                                                          "detail": "not_found", "required": True}]))
        cid = self.check([runtime, {"kind": "login", "ref": LOGIN, "state": "ok", "detail": "ok"}])
        hub.q("UPDATE machine_checks SET completed=? WHERE id=?", (hub.now() - 3700, cid))
        self.assertIs(self.row()["verify"]["holds"], False)
        self.assertEqual(self.settings(active=True)[1]["missing"][0]["detail"],
                         "The latest check is older than 60 minutes. Check this server again.")
        self.assertEqual(self.settings(active=True, model="gpt-6-luna")[0], 400)   # activate in a write of its own
        cid = self.check([runtime, {"kind": "login", "ref": LOGIN, "state": "ok", "detail": "ok"}])
        code, data = self.settings(active=True)
        self.assertEqual((code, data["activation"]["check"], data["changed"]), (200, cid, [
            {"field": "active", "before": False, "after": True}]), data)
        self.assertNotIn("active", hub.TEAM["agents"]["vps"])              # absent means active
        self.assertIn("vps: it is active now and can get tasks",
                      hub.q1("SELECT text FROM events WHERE agent='manager' ORDER BY id DESC LIMIT 1")["text"])
        self.assertFalse(hub.call_tool("manager", "create_task", {"owner": "vps", "title": "Check", "done_when": "x"})[1])

    def test_a_check_stays_valid_while_only_other_agents_change(self):
        """Each activation writes team.json, and six agents in setup needed six rounds of update, check and activate
        (30 October 2026). A write that changes only other agents' entries and profiles leaves this agent's check
        valid; a change of its own entry or profile, or of any other part of team.json, still makes it old. The
        machine row's `holds` gives the app that same answer before it asks (owner API 1.80)."""
        items = [{"kind": "runtime", "ref": "codex", "state": "ok", "detail": "codex-cli 0.160.0, signed in"},
                 {"kind": "login", "ref": LOGIN, "state": "ok", "detail": "ok"}]

        def change(team=None, profiles=None):
            data = json.loads((self.kit / "team.json").read_text())
            if team:
                team(data)
                (self.kit / "team.json").write_text(json.dumps(data, indent=2) + "\n")
            for name, text in (profiles or {}).items():
                (self.kit / "profiles" / name).write_text(text)
            git("add", "-A", cwd=self.kit)
            git("commit", "-q", "-m", "test change", cwd=self.kit)
            git("push", "-q", "origin", "main", cwd=self.kit)
            hub.apply_team(data)
            self.report()                           # its helper follows the new revision
        cases = (("another agent", dict(team=lambda t: t["agents"]["studio"].update(active=False, title="Designer"),
                                        profiles={"studio.md": PROFILE.replace("vps", "studio")}), 200),
                 ("its own entry", dict(team=lambda t: t["agents"]["vps"].update(title="Researcher")), 409),
                 ("its own profile", dict(profiles={"vps.md": PROFILE.replace("Careful.", "Careful and quick.")}), 409),
                 ("a new machine", dict(team=lambda t: t["addresses"].update({"worker-3": "127.0.0.9"})), 409))
        for what, edit, expected in cases:
            with self.subTest(what=what):
                if hub.agent_active("vps"):
                    self.set_team(active=False)
                self.report()
                self.check(items)
                change(**edit)
                self.assertIs(self.row()["verify"]["holds"], expected == 200)
                code, data = self.settings(active=True)
                self.assertEqual(code, expected, data)
                if expected == 200:
                    self.assertIsNone(self.row()["verify"]["holds"])        # an active agent is not activated
                if expected == 409:
                    self.assertEqual([m["detail"] for m in data["missing"]],
                                     ["The latest check saw older settings. Check this server again."])

    def test_the_manager_s_profile_keeps_its_own_opening(self):
        """The manager may update its own profile, and an owner's save wrote the workers' "Agents cannot change it."
        over the opening that its file ships with. The shipped sections now give the shipped file back, byte for
        byte, and a worker's profile keeps the workers' line."""
        for path in ("profiles/manager.md", "publish/profiles/manager.md"):
            with self.subTest(path=path):
                if not (Path(__file__).resolve().parent / path).is_file():
                    self.skipTest(f"{path} is not in a published copy")       # publish/ is the seed's source
                shipped = (Path(__file__).resolve().parent / path).read_text()
                self.assertEqual(hub.render_profile("manager", hub.parse_profile(shipped)), shipped)
        self.assertEqual(hub.render_profile("vps", hub.parse_profile(PROFILE)), PROFILE)

    def test_check_items_carry_the_hubs_required_flags(self):
        self.set_team(can=["shell", "web", "browser"], model="gpt-6-luna")
        self.report()
        items = [{"kind": "runtime", "ref": "codex", "state": "ok", "detail": "codex-cli 0.160.0, signed in"},
                 {"kind": "model", "ref": "gpt-6-luna", "state": "ok", "detail": "Offered."},
                 {"kind": "capability", "ref": "web", "state": "not_verified", "detail": "A runtime tool."},
                 {"kind": "capability", "ref": "browser", "state": "failed", "detail": "No desktop session."},
                 {"kind": "capability", "ref": "screen", "state": "not_verified", "detail": "Permissions unknown."},
                 {"kind": "mac", "ref": "awake", "state": "failed", "detail": "System sleep after 10 minutes."},
                 {"kind": "access", "ref": "admin", "state": "ok", "detail": "None without a password."},
                 {"kind": "access", "ref": "sandbox", "state": "ok", "detail": "a helper's claim that the hub replaces"}]
        cid = self.check(items)
        verify = self.row()["verify"]
        self.assertEqual((verify["check"], verify["revision"]), (cid, self.head()))
        got = {(i["kind"], i["ref"]): (i["state"], i["required"]) for i in verify["items"]}
        self.assertEqual(got, {
            ("runtime", "codex"): ("ok", True), ("model", "gpt-6-luna"): ("ok", True),
            ("capability", "web"): ("not_verified", False), ("capability", "browser"): ("failed", True),
            ("capability", "screen"): ("not_verified", False), ("mac", "awake"): ("failed", True),
            ("access", "admin"): ("ok", False), ("knowledge", "knowledge/services.md"): ("ok", True),
            ("login", LOGIN): ("not_verified", True), ("access", "sandbox"): ("ok", False),
            ("access", "vault"): ("not_verified", False)})
        detail = {(i["kind"], i["ref"]): i["detail"] for i in verify["items"]}
        self.assertEqual(detail[("access", "sandbox")],
                         "Codex --sandbox danger-full-access: the runtime does not limit file or network access.")
        self.assertEqual(detail[("login", LOGIN)], "not probed")
        for bad in ([{"kind": "login", "ref": LOGIN, "state": "ok", "detail": "the password is x"}],
                    [{"kind": "knowledge", "ref": "x", "state": "ok"}], [{"kind": "runtime", "ref": "codex", "state": "good"}]):
            with self.subTest(bad=bad):
                self.assertEqual(self.report(verify=bad)[0], 400)

    def test_a_probe_job_is_confirmed_once_with_the_profiles_logins(self):
        self.report()
        code, data = self.request("/ui/machines/vps/check", {"request_id": str(uuid.uuid4()), "db": "test-generation"})
        event = hub.q1("SELECT * FROM events WHERE kind='check' ORDER BY id DESC LIMIT 1")
        job = json.loads(event["extra"])["probe_job"]
        self.assertEqual(self.request("/helper/vault/vps", {"job": job, "kind": "probe"}),
                         (200, {"ok": True, "job": job, "kind": "probe", "logins": [LOGIN]}))
        self.assertEqual(self.request("/helper/vault/vps", {"job": job, "kind": "probe"})[0], 409)       # once
        self.assertEqual(self.request("/helper/vault/vps", {"job": job, "kind": "signin"})[0], 404)
        old = hub.ins("INSERT INTO jobs(agent,task,kind,created) VALUES('vps',NULL,'probe',?)", (hub.now() - 400,))
        self.assertEqual(self.request("/helper/vault/vps", {"job": old, "kind": "probe"})[0], 409)       # expired

    def test_knowledge_files_are_an_explicit_list_of_catalog_paths(self):
        sections = hub.parse_profile(PROFILE)
        base = hub.hashlib.sha256(PROFILE.encode()).hexdigest()
        files = next(s for s in sections if s["key"] == "knowledge_files")
        self.assertEqual(hub.knowledge_list(files["text"]), ["knowledge/services.md"])
        for text, code in (("- knowledge/none.md", 400), ("See the services file.", 400), ("- ../secret.md", 400)):
            with self.subTest(text=text):
                changed = [dict(s, text=text) if s is files else s for s in sections]
                self.assertEqual(self.request("/ui/profiles/vps", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                                       base_sha256=base, sections=changed))[0], code)

    def test_model_records_are_kept_with_safe_names_only(self):
        self.assertEqual(hub.clean_record({"seq": 1, "type": "model", "requested_model": "opus", "requested_effort": None,
                                           "model": "claude-opus-4-7", "effort": "<script>"}),
                         (1, None, "model", {"requested_model": "opus", "requested_effort": None,
                                             "model": "claude-opus-4-7", "effort": None}))


FAKE_APP_SERVER = r'''#!/usr/bin/env python3
import json, sys
answers = sys.argv[0].endswith("-ok")
for line in sys.stdin:
    m = json.loads(line)
    if m.get("method") == "initialize":
        print(json.dumps({"id": m["id"], "result": {"userAgent": "stand-in"}}), flush=True)
        print(json.dumps({"method": "remoteControl/status/changed", "params": {}}), flush=True)
    elif m.get("method") == "model/list" and answers:
        print(json.dumps({"id": m["id"], "result": {"nextCursor": None, "data": [
            {"id": "m1", "model": "gpt-test-1", "displayName": "Test 1", "isDefault": True, "hidden": False,
             "defaultReasoningEffort": "low", "supportedReasoningEfforts": [{"reasoningEffort": "low"},
                                                                         {"reasoningEffort": "ultra"}]},
            {"id": "m2", "model": "gpt-hidden", "hidden": True, "supportedReasoningEfforts": []}]}}), flush=True)
'''
# The logins of a probe, and the fixed code that the vault's own store gives for each: a login it holds, one it does
# not hold, and an item that is not a login.
REFS = {f"bws://{c * 8}-1111-2222-3333-444455556666": code for c, code in
        (("a", "ok"), ("b", "not_found"), ("d", "bad_format"))}
CLAUDE_HELP = """  --effort <level>                      Effort level for the current session
                                        (low, medium, high, xhigh, max)
  --model <model>                       Model for the current session. Provide
                                        an alias for the latest model (e.g.
                                        'fable', 'opus', or 'sonnet') or a
                                        model's full name.
  -n, --name <name>                     Set a display name for this session"""


class Helper(unittest.TestCase):
    """The helper side: discovery, the setup check, session flags, model records, the probe and the installer."""
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fleet-setup-helper-")
        os.chmod(self.tmp, 0o700)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.user = pwd.getpwuid(os.getuid()).pw_name
        self.connected = None           # what this Mac's real runtime answers stays out of every test here
        patcher = patch.object(lifecycle, "browser_connected", lambda exe: self.connected)
        patcher.start()
        self.addCleanup(patcher.stop)

    def script(self, name, text):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as f:
            f.write(text)
        os.chmod(path, 0o755)
        return path

    def test_codex_options_come_from_the_app_server_model_list(self):
        options, error = lifecycle.codex_model_list(self.script("codex-ok", FAKE_APP_SERVER), timeout=10)
        self.assertEqual((error, options), (None, [{"model": "gpt-test-1", "display_name": "Test 1", "default": True,
                                                    "efforts": ["low", "ultra"], "default_effort": "low"}]))
        options, error = lifecycle.codex_model_list(self.script("codex-silent", FAKE_APP_SERVER), timeout=1)
        self.assertEqual((options, error), (None, "codex app-server did not answer model/list in 1 seconds"))
        self.assertEqual(lifecycle.codex_model_list(os.path.join(self.tmp, "missing"))[1],
                         "codex app-server did not start: FileNotFoundError")

    def test_claude_options_come_from_its_installed_help(self):
        options, error = lifecycle.claude_model_list(CLAUDE_HELP)
        self.assertEqual((error, [o["model"] for o in options], options[0]["efforts"]),
                         (None, ["fable", "opus", "sonnet"], ["low", "medium", "high", "xhigh", "max"]))
        self.assertEqual(lifecycle.claude_model_list("no model option"), (None, "claude --help names no model aliases"))

    def life(self, platform="darwin", locked=False, conf=None, probe=None, pgrep=None):
        root = {"IOConsoleLocked": locked, "IOConsoleUsers": [{"kCGSSessionUserNameKey": self.user,
                                                               "kCGSSessionOnConsoleKey": True}]}
        answers = {"ioreg": (0, plistlib.dumps(root).decode(), ""), "defaults": (0, self.user + "\n", ""),
                   "pmset": (0, " sleep                0\n displaysleep         10\n autorestart          1\n", ""),
                   "sudo": (1, "", "sudo: a password is required"), "id": (0, "staff admin\n", "")}
        if pgrep is not None:
            answers["pgrep"] = pgrep
        os.makedirs(os.path.join(self.tmp, "Applications", "Google Chrome.app"), exist_ok=True)
        return lifecycle.Lifecycle("/kit", "vps", dict({"role": "worker", "runtime": "codex",
                                                        "can": ["shell", "web", "browser", "screen"]}, **(conf or {})),
                                   post=None, busy=lambda: False, platform_name=platform, home=self.tmp, probe=probe,
                                   run=lambda argv, **kw: answers.get(os.path.basename(argv[0]), (1, "", "")),
                                   models=lambda exe: (OPTIONS, None))

    def items(self, life, job=None, models=None):
        status = {"runtime": {"name": "codex", "version": "codex-cli 0.160.0", "signed_in": True},
                  "models": models or {"ok": True, "options": OPTIONS, "other_names": False, "error": None}}
        return {(i["kind"], i["ref"]): (i["state"], i["detail"]) for i in life.verify(status, job)}

    def test_macos_setup_screens_fail_the_session_the_browser_and_the_screen_with_one_sentence(self):
        """4 November 2026: macOS installed an update by itself, and its setup screens stayed open on a Mac that nobody
        watched. Only that sentence says what to do; a pgrep that finds nothing, or fails, keeps today's readings."""
        got = self.items(self.life(pgrep=(0, "1272\n", "")))
        for key in (("mac", "session"), ("capability", "browser"), ("capability", "screen")):
            self.assertEqual(got[key], ("failed", lifecycle.SETUP_SCREENS), key)
        for answer in ((1, "", ""), (2, "", "pgrep: bad option")):
            got = self.items(self.life(pgrep=answer))
            self.assertEqual((got[("mac", "session")][0], got[("capability", "browser")][0],
                              got[("capability", "screen")][0]), ("ok", "ok", "not_verified"), answer)

    def test_the_setup_check_reports_facts_and_never_calls_screen_control_ready(self):
        probe = lambda job: {"ok": True, "results": [{"login": "bws://" + "a" * 8 + "-1111-2222-3333-444455556666",
                                                      "state": "readable", "reason": "ok"},
                                                     {"login": "bws://" + "e" * 8 + "-1111-2222-3333-444455556666",
                                                      "state": "not_readable", "reason": "error"}]}
        got = self.items(self.life(probe=probe), job=5)
        self.assertEqual(got[("capability", "screen")][0], "not_verified")
        self.assertIn("screen recording and accessibility permissions", got[("capability", "screen")][1])
        self.assertEqual({k: v[0] for k, v in got.items() if k[0] in ("mac", "runtime", "model", "login")} | {
            ("capability", "browser"): got[("capability", "browser")][0]}, {
            ("runtime", "codex"): "ok", ("model", "default"): "ok", ("capability", "browser"): "ok",
            ("mac", "automatic_login"): "ok", ("mac", "awake"): "ok", ("mac", "session"): "ok",
            ("login", "bws://" + "a" * 8 + "-1111-2222-3333-444455556666"): "ok",
            ("login", "bws://" + "e" * 8 + "-1111-2222-3333-444455556666"): "failed"})
        self.assertEqual(got[("mac", "awake")][1], "System sleep never; display sleep after 10 minutes; restart after a "
                                                   "power failure on.")
        self.assertEqual(got[("access", "admin")][1], "No administrator command runs without a password.")
        locked = self.items(self.life(locked=True))
        self.assertEqual([locked[("mac", "session")][0], locked[("capability", "browser")][0],
                          locked[("capability", "screen")][0]], ["failed", "failed", "failed"])
        linux = self.items(self.life(platform="linux"))
        self.assertFalse([k for k in linux if k[0] == "mac"])
        self.assertEqual((linux[("capability", "browser")][0], linux[("capability", "web")][0]), ("failed", "not_verified"))

    def test_a_browser_on_claude_needs_its_extension_on_in_chrome(self):
        def browser(life):
            status = {"runtime": {"name": "claude", "version": "2.1.316 (Claude Code)", "signed_in": True}, "models": None}
            return {(i["kind"], i["ref"]): (i["state"], i["detail"]) for i in life.verify(status)}[("capability", "browser")]

        def profile(entry):
            folder = os.path.join(self.tmp, "Library", "Application Support", "Google", "Chrome", "Profile 1")
            os.makedirs(folder, exist_ok=True)
            with open(os.path.join(folder, "Secure Preferences"), "w") as f:
                json.dump({"extensions": {"settings": {lifecycle.CLAUDE_EXTENSION: entry} if entry is not None else {}}}, f)

        life = self.life(conf={"runtime": "claude"})
        self.assertEqual(browser(life), ("failed", "Claude's extension is not in Chrome on this Mac: restart Chrome, "
                                                   "then press Enable Extension."))
        profile(None)
        self.assertEqual(browser(life)[0], "failed")
        profile({"disable_reasons": [8192]})    # what Chrome 156 wrote for an extension that waits for its first press
        self.assertEqual(browser(life), ("failed", "Claude's extension is off: press Enable Extension in Chrome on this Mac."))
        profile({"state": 0, "disable_reasons": 8192})      # an older Chrome's shape
        self.assertEqual(browser(life)[0], "failed")
        for on in ({}, {"state": 1}, {"disable_reasons": []}):
            profile(on)
            self.assertEqual(browser(life), ("ok", "Google Chrome is installed, and the session is ready."))
        self.connected = False          # on, and not signed in: the runtime's own list of browsers says so
        self.assertEqual(browser(life), ("failed", "Claude's extension is not signed in: sign in to Claude in Chrome on "
                                                   "this Mac, with this Mac's account."))
        with open(os.path.join(self.tmp, "Library", "Application Support", "Google", "Chrome", "Profile 1",
                               "Secure Preferences"), "w") as f:
            f.write("not json")
        self.assertEqual(browser(life)[0], "failed")

    def test_the_model_item_follows_the_reading(self):
        self.assertEqual(self.items(self.life(conf={"model": "gpt-6-luna", "effort": "high"}))[("model", "gpt-6-luna")],
                         ("failed", "high is not an effort of gpt-6-luna here."))
        claude = {"ok": True, "other_names": True, "error": None, "options": [
            {"model": "opus", "display_name": "opus", "default": False, "efforts": ["low", "max"], "default_effort": None}]}
        self.assertEqual(self.items(self.life(conf={"model": "claude-opus-4-7"}), models=claude)[("model", "claude-opus-4-7")][0],
                         "not_verified")
        down = {"ok": False, "options": [], "error": "codex app-server did not answer model/list in 20 seconds"}
        self.assertEqual(self.items(self.life(), models=down)[("model", "default")][0], "not_verified")
        self.assertEqual(self.items(self.life(conf={"effort": "low"}), models=down)[("model", "default")][0], "failed")

    @unittest.skipUnless(os.path.isfile(os.path.join(fleet.KIT, "profiles", "vps.md")),
                         "it reads profiles/vps.md, the owner's own profile, which a published copy has not got")
    def test_new_sessions_get_the_runtime_flags(self):
        codex = {"role": "worker", "runtime": "codex", "start": START, "model": "gpt-6-luna", "effort": "medium"}
        self.assertIn("-m gpt-6-luna -c 'model_reasoning_effort=\"medium\"' ",
                      fleet.session_command("vps", codex, "Do it", task="T-1", attempt=1, generation="g", session="s"))
        self.assertIn("-m gpt-6-luna -c 'model_reasoning_effort=\"medium\"' ", fleet.chat_command("vps", codex, "g"))
        claude = {"role": "worker", "runtime": "claude", "model": "opus", "effort": "high",
                  "start": "claude --permission-mode dontAsk {chrome} {settings} {prompt}"}
        self.assertEqual(fleet.model_flags(claude), "--model opus --effort high")
        self.assertEqual(fleet.model_flags({"runtime": "codex"}), "")

    @unittest.skipUnless(os.path.isfile(os.path.join(fleet.KIT, "profiles", "vps.md")),
                         "it reads profiles/vps.md, the owner's own profile, which a published copy has not got")
    def test_a_session_without_a_model_gets_the_one_default_of_its_runtime_s_list(self):
        """A Mac's Codex config named a model that its ChatGPT sign-in did not offer, and every turn of the Codex agent
        there failed with model_not_found (28 October 2026): a new session gets the list's default, as a screen task
        does, and a model or an effort that the owner chose still wins."""
        listed = {"runtime": "codex", "ok": True, "options": [
            {"model": "gpt-6-luna", "default": True, "efforts": ["low", "medium", "xhigh"], "default_effort": "medium"},
            {"model": "gpt-5.6-terra", "default": False, "efforts": ["low"], "default_effort": "low"}]}
        codex = {"role": "worker", "runtime": "codex", "start": START}
        self.assertEqual(fleet.run_settings(codex, listed), {"model": "gpt-6-luna", "effort": "medium"})
        self.assertEqual(fleet.run_settings(dict(codex, effort="xhigh"), listed), {"model": "gpt-6-luna", "effort": "xhigh"})
        self.assertEqual(fleet.run_settings(dict(codex, model="gpt-5.6-terra"), listed),    # its own default effort,
                         {"model": "gpt-5.6-terra", "effort": "low"})                       # not the config's
        self.assertEqual(fleet.run_settings(dict(codex, model="gpt-7"), listed), {"model": "gpt-7", "effort": None})
        for other in (None, dict(listed, ok=False), dict(listed, runtime="claude"),
                      dict(listed, options=[dict(o, default=True) for o in listed["options"]]),
                      dict(listed, options=[dict(o, default=False) for o in listed["options"]])):
            self.assertEqual(fleet.run_settings(codex, other), {"model": None, "effort": None})
        claude = {"runtime": "claude", "ok": True, "options": [
            {"model": "opus", "default": False, "efforts": ["low"], "default_effort": None}]}
        self.assertEqual(fleet.run_settings({"runtime": "claude"}, claude), {"model": None, "effort": None})
        helper = fleet.Helper("vps", codex)
        self.assertEqual(helper.runs(), {"model": None, "effort": None})        # no reading: the runtime's own
        helper.lifecycle = unittest.mock.Mock(models=None, read_models=lambda force=False: listed)
        self.assertIn("-m gpt-6-luna -c 'model_reasoning_effort=\"medium\"' ",
                      fleet.chat_command("vps", helper.run_conf(), "g"))
        self.assertIn("-m gpt-6-luna -c 'model_reasoning_effort=\"medium\"' ",
                      fleet.session_command("vps", helper.run_conf(), "Do it", task="T-1", attempt=1, generation="g",
                                            session="s"))
        helper.lifecycle.models = dict(listed, ok=False, options=[])       # a failed reading keeps the one before
        self.assertEqual(helper.runs(), {"model": "gpt-6-luna", "effort": "medium"})
        self.assertNotIn("model", {k for k, v in helper.conf.items() if v})     # the owner's choice stays empty
        # a first reading that failed is read again, not kept for the lifecycle's six hours (adversarial review)
        readings, helper = [dict(listed, ok=False, options=[]), listed], fleet.Helper("vps", codex)
        helper.lifecycle = unittest.mock.Mock(models=None)
        helper.lifecycle.read_models = lambda force=False: setattr(helper.lifecycle, "models", readings.pop(0)) \
            or helper.lifecycle.models
        self.assertEqual(helper.runs(), {"model": None, "effort": None})
        self.assertEqual((helper.runs(), len(readings)), ({"model": None, "effort": None}, 1))     # not at once

        class Beside:           # the read again runs beside the main loop; here at once
            def __init__(self, target, kwargs, **_):
                self.start = lambda: target(**kwargs)
        helper.models_tried -= fleet.MODELS_RETRY
        with patch.object(fleet.threading, "Thread", Beside):
            self.assertEqual(helper.runs(), {"model": None, "effort": None})       # it holds no session start
        self.assertEqual((helper.runs(), readings), ({"model": "gpt-6-luna", "effort": "medium"}, []))

    def test_every_session_start_of_the_helper_passes_the_settings_that_it_starts_with(self):
        """A conversation with tools started with the agent's raw settings, so a Codex agent's ran on its machine's
        config model, and the reuse rule then started it again before each message (adversarial review, 28 October
        2026). Every builder call of the helper passes run_conf()."""
        source = Path(fleet.__file__).read_text(encoding="utf-8")
        helper = source[source.index("\nclass Helper:"):]
        helper = helper[:re.search(r"\n(?=[^\s#])", helper[1:]).start() + 1]
        for builder in ("session_command", "chat_command", "conversation_command", "conversation_work_command",
                        "manager_start"):
            with self.subTest(builder):
                given = re.findall(rf"\b{builder}\(\s*self\.agent,\s*([^,]+),", helper)
                self.assertTrue(given)
                # an app-server task's runner reads the account's list itself, fresh, at its start
                # (its own model and effort, else the owner's default where the helper's reading offers it)
                self.assertLessEqual(set(given), {"self.run_conf()", "self.runner_conf(needs) if runner else self.run_conf()"})

    def test_a_model_record_comes_once_per_model_from_the_transcript(self):
        claude = threads.Translator("claude", requested={"model": "opus", "effort": "high"})
        rows = [{"type": "assistant", "sessionId": "s", "message": {"model": m, "content": []}}
                for m in ("claude-opus-4-7", "claude-opus-4-7", "<synthetic>", "claude-sonnet-4-6")]
        got = [r for row in rows for r in claude.records(row) if r["type"] == "model"]
        self.assertEqual([(r["requested_model"], r["requested_effort"], r["model"], r["effort"]) for r in got],
                         [("opus", "high", "claude-opus-4-7", None), ("opus", "high", "claude-sonnet-4-6", None)])
        codex = threads.Translator("codex")
        rows = [{"type": "session_meta", "payload": {"id": "x"}}] + \
               [{"type": "turn_context", "payload": {"model": "gpt-6-astra", "effort": "xhigh"}}] * 2
        got = [r for row in rows for r in codex.records(row) if r["type"] == "model"]
        self.assertEqual([(r["requested_model"], r["model"], r["effort"]) for r in got], [(None, "gpt-6-astra", "xhigh")])

    def test_the_broker_probe_gives_fixed_codes_and_no_part_of_a_login(self):
        from test_vault import FAKE_AGE
        state = os.path.join(self.tmp, "state")
        os.mkdir(state, 0o700)
        conf = {"agent": "vps", "hub": "http://127.0.0.1:9", "worker_uid": os.getuid(),
                "age": self.script("age", FAKE_AGE.format(python=sys.executable)),
                "store": os.path.join(state, "store.age"), "store_key": os.path.join(state, "store.key")}
        with open(conf["store_key"], "w") as f:
            f.write(f"# public key: age1{'p' * 58}\nAGE-SECRET-KEY-1FAKESTORE\n")
        os.chmod(conf["store_key"], 0o600)
        locked = subprocess.run([conf["age"], "-a", "-r", "age1" + "p" * 58], input=json.dumps({"v": 1, "items": {}}),
                                capture_output=True, text=True, check=True).stdout
        with open(conf["store"], "w") as f:
            f.write(locked)
        os.chmod(conf["store"], 0o600)
        store = vault.LocalStore(conf)
        store.put("a" * 8 + "-1111-2222-3333-444455556666", "k",
                  json.dumps({"username": "u", "password": "Synthetic-Pass-123", "url": "https://example.com"}))
        store.put("d" * 8 + "-1111-2222-3333-444455556666", "k", "not a login")
        confirm = lambda conf, method, path, body=None: (200, {"ok": True, "job": 7, "kind": "probe", "logins": list(REFS)})
        with patch.object(vault, "hub", confirm):
            answer = vault.handle(conf, json.dumps({"v": 2, "op": "probe", "job": 7}), os.getuid())
        self.assertEqual({r["login"]: r["reason"] for r in answer["results"]}, REFS)
        self.assertEqual([r["state"] for r in answer["results"]], ["readable"] + ["not_readable"] * 2)
        self.assertNotIn("Synthetic-Pass-123", json.dumps(answer))
        os.remove(conf["store_key"])                    # a vault without its key opens nothing, and says so per login
        with patch.object(vault, "hub", confirm):
            self.assertEqual({r["reason"] for r in vault.probe(conf, 7)["results"]}, {"no_token"})
        with patch.object(vault, "hub", lambda *a, **k: (409, {"error": "this job has ended"})), \
                self.assertRaises(vault.Refused):
            vault.probe(conf, 7)

    def test_a_new_worker_starts_in_setup_without_another_agents_vault(self):
        kit = Path(self.tmp)
        (kit / "team.json").write_text(json.dumps({"addresses": {"vps": "100.64.0.3"}, "agents": {
            "manager": {"role": "manager", "runtime": "claude", "machine": "hub"},
            "vps": {"role": "worker", "machine": "vps", "runtime": "codex", "can": ["shell", "web"], "start": START,
                    "vault": "broker", "vault_recipient": "age1" + "q" * 58, "reports_to": "lead1",
                    "model": "gpt-6-luna", "effort": "low"}}}))
        onboard.register_in_kit(kit, "worker9", "codex", "100.64.0.9")
        self.assertEqual(json.loads((kit / "team.json").read_text())["agents"]["worker9"],
                         {"role": "worker", "machine": "worker9", "runtime": "codex", "can": ["shell", "web"],
                          "start": START, "active": False})


if __name__ == "__main__":
    unittest.main()

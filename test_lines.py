"""Owner API 1.6: reporting lines. In-process hub and temporary Git repositories; no fleet or AI calls."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid
from unittest.mock import patch

import hub
from test_ui_api import OwnerAPI
from leftovers import scratch_home

TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3", "mac-studio": "127.0.0.4"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]},
                   "studio": {"role": "worker", "runtime": "claude", "machine": "mac-studio", "can": ["shell", "browser"]}}}


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def git(*args, cwd=None):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (Lines, Leads, LeadDelivery):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Lines(OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        self.root = Path(tempfile.mkdtemp(prefix="fleet-lines-"))
        seed = self.root / "seed"
        seed.mkdir()
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", str(self.root / "origin.git"), str(self.root / "kit"))
        self.kit = self.root / "kit"
        hub.CFG["team_path"] = str(self.kit / "team.json")
        hub._revision_cache.update(at=0.0, value=None)

    def tearDown(self):
        super().tearDown()
        hub.CFG.pop("team_path", None)
        hub._revision_cache.update(at=0.0, value=None)
        shutil.rmtree(str(self.root), ignore_errors=True)

    def team(self):
        code, data = self.request("/ui/team?db=test-generation")
        self.assertEqual(code, 200)
        return data

    def save(self, base, lines):
        return self.request("/ui/team/lines", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                   base_sha256=base, lines=lines))

    def lines(self, **changes):
        out = [{"agent": "manager", "role": "manager", "reports_to": None},
               {"agent": "vps", "role": "worker", "reports_to": "manager"},
               {"agent": "studio", "role": "worker", "reports_to": "manager"}]
        for line in out:
            line.update(changes.get(line["agent"], {}))
        return out

    def task(self, owner, caller="manager"):
        return hub.call_tool(caller, "create_task", {"owner": owner, "title": "Check", "done_when": "Checked."})

    def test_the_editor_reads_lines_and_an_unchanged_save_commits_nothing(self):
        data = self.team()
        self.assertEqual(data["sha256"], hashlib.sha256((self.kit / "team.json").read_bytes()).hexdigest())
        self.assertEqual([(l["agent"], l["role"], l["reports_to"]) for l in data["lines"]],
                         [("manager", "manager", None), ("vps", "worker", "manager"), ("studio", "worker", "manager")])
        self.assertIn("reporting_lines", self.request()[1]["ui_features"])
        code, result = self.save(data["sha256"], self.lines())
        self.assertEqual((code, result["changed"]), (200, []))
        self.assertEqual(git("rev-list", "--count", "HEAD", cwd=self.kit), "1")

    def test_the_lead_role_can_be_switched_off(self):
        self.assertIn("leads", self.request()[1]["ui_features"])
        with patch("hub.LEADS_READY", False):
            code, result = self.save(self.team()["sha256"], self.lines(vps={"role": "lead"}))
        self.assertEqual(code, 409)
        self.assertEqual("Leads are not available yet; keep it a worker.", result["error"])

    @patch("hub.LEADS_READY", True)
    def test_a_lead_gets_a_team_and_nobody_skips_a_level(self):
        base = self.team()["sha256"]
        code, result = self.save(base, self.lines(vps={"role": "lead"}, studio={"reports_to": "vps"}))
        self.assertEqual(code, 200, result)
        self.assertEqual([c["agent"] for c in result["changed"]], ["vps", "studio"])
        self.assertEqual(result["updates_requested"], ["vps"])
        stored = json.loads(git("--git-dir", str(self.root / "origin.git"), "show", "main:team.json"))
        self.assertEqual((stored["agents"]["vps"]["role"], stored["agents"]["studio"]["reports_to"]), ("lead", "vps"))
        self.assertNotIn("reports_to", stored["agents"]["vps"])
        self.assertEqual(hub.reports_to("studio"), "vps")
        said = {r["agent"]: r["text"] for r in hub.q("SELECT agent, text FROM events WHERE kind='say'")}
        self.assertIn("vps is now a lead reporting to manager", said["manager"])
        self.assertNotIn("vps", said)              # a lead reads only in task sessions; its tasks name its team
        text, error = self.task("studio")
        self.assertTrue(error and "studio reports to vps: only vps gives it tasks" in text)
        text, error = self.task("vps")
        self.assertFalse(error, text)
        state = self.request()[1]
        self.assertEqual({a["name"]: a["reports_to"] for a in state["agents"]}["studio"], "vps")

    @patch("hub.LEADS_READY", True)
    def test_bad_lines_are_refused(self):
        base = self.team()["sha256"]
        bad = [self.lines(vps={"reports_to": "studio"}),                                   # a worker leads nobody
               self.lines(vps={"role": "lead", "reports_to": "studio"}, studio={"role": "lead", "reports_to": "vps"}),
               self.lines(manager={"role": "lead"}, vps={"role": "manager", "reports_to": None}),
               self.lines(vps={"reports_to": "vps"}),
               self.lines()[:2]]
        for lines in bad:
            self.assertEqual(self.save(base, lines)[0], 400, lines)
        code, result = self.save("0" * 64, self.lines())
        self.assertEqual((code, result["sha256"]), (409, base))
        self.assertFalse(self.task("vps")[1])
        code, result = self.save(base, self.lines(vps={"role": "lead"}))
        self.assertEqual((code, result["open_tasks"]), (409, {"vps": 1}))
        self.assertEqual(git("rev-list", "--count", "HEAD", cwd=self.kit), "1")


if __name__ == "__main__":
    unittest.main()


class Leads(OwnerAPI):
    """A lead works like a worker: one session per task, with team tools scoped to that task's subtasks."""
    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        hub.TEAM["agents"]["vps"]["role"] = "lead"
        hub.TEAM["agents"]["studio"]["reports_to"] = "vps"
        hub.TEAM["addresses"]["vps"] = "127.0.0.1"
        hub.CFG.update(ask_wait=1, ask_max=1, silence=180, question_wait=120, manager_silence=120, stop_after=60,
                       offline_after=90)

    def call(self, agent, name, args, task=None, attempt=1):
        context = ("test-generation", f"T-{task}", attempt) if task else None
        return hub.call_tool(agent, name, args, context)

    def create(self, caller, owner, task=None, **extra):
        text, error = self.call(caller, "create_task", dict(owner=owner, title="Part", done_when="Done.", **extra), task)
        self.assertFalse(error, text)
        return int(text.split("T-")[1].split(" ")[0])

    def said(self, agent, task=None):
        sql = "SELECT text FROM events WHERE agent=? AND kind='say'" + (" AND task=?" if task else "") + " ORDER BY id"
        return [r["text"] for r in hub.q(sql, (agent, task) if task else (agent,))]

    def test_a_lead_task_session_has_scoped_team_tools(self):
        lead = self.create("manager", "vps")
        names = [t["name"] for t in hub.tools_for("vps", ("test-generation", f"T-{lead}", 1))]
        for name in ("create_task", "check_result", "decide_permission", "deliver_result", "ask_my_requester"):
            self.assertIn(name, names)
        for name in ("raise_needs_you", "see_goals", "update_goal", "tell_owner"):
            self.assertNotIn(name, names)
        start = hub.q1("SELECT text FROM events WHERE agent='vps' AND kind='task'")["text"]
        self.assertIn("You lead studio", start)
        text, error = self.call("manager", "create_task", dict(owner="studio", title="x", done_when="y"))
        self.assertTrue(error and "only vps gives it tasks" in text)

    def test_subtasks_report_to_the_lead_session_of_their_parent(self):
        self.assertFalse(self.call("manager", "update_goal", dict(request_id=str(uuid.uuid4()), title="G",
                                                                  text="Goal."))[1])
        lead = self.create("manager", "vps", goal="G-1")
        other = self.create("manager", "vps")
        sub = self.create("vps", "studio", task=lead)
        row = hub.q1("SELECT * FROM tasks WHERE id=?", (sub,))
        self.assertEqual((row["parent"], row["requester"], row["goal_id"]), (lead, "vps", 1))
        text, error = self.call("studio", "ask_my_requester", {"question": "Which colour?"}, sub)
        self.assertFalse(error, text)
        self.assertTrue(any("Which colour?" in t for t in self.said("vps", lead)))
        self.assertFalse(self.call("vps", "answer", {"question_id": "Q-1", "text": "Blue."}, lead)[1])
        text, error = self.call("vps", "deliver_result", {"outcome": "completed", "what_was_done": "x",
                                                          "where_output_is": "y", "how_checked": "z"}, lead)
        self.assertTrue(error and f"T-{sub}" in text)                       # a lead delivers after its subtasks
        self.assertFalse(self.call("studio", "deliver_result", {"outcome": "completed", "what_was_done": "Done",
                                                                "where_output_is": "out", "how_checked": "read"}, sub)[1])
        inbox = self.call("vps", "read_messages", {}, lead)[0]
        self.assertIn(f"Result for T-{sub}", inbox)
        text, error = self.call("vps", "check_result", {"task_id": f"T-{sub}", "accepted": True}, other)
        self.assertTrue(error and "not a subtask" in text)
        self.assertFalse(self.call("vps", "check_result", {"task_id": f"T-{sub}", "accepted": True}, lead)[1])
        self.assertFalse(self.call("vps", "deliver_result", {"outcome": "completed", "what_was_done": "x",
                                                             "where_output_is": "y", "how_checked": "z"}, lead)[1])

    def test_only_the_requester_decides_a_subtask_prompt(self):
        lead = self.create("manager", "vps")
        sub = self.create("vps", "studio", task=lead)
        pid = hub.ins("INSERT INTO prompts(task,agent,tool,input,key,created) VALUES(?,?,?,?,?,?)",
                      (sub, "studio", "Bash", "{}", "k", hub.now()))
        text, error = self.call("manager", "decide_permission", {"prompt_id": f"P-{pid}", "decision": "allow"})
        self.assertTrue(error and "is for vps to decide" in text)
        self.assertFalse(self.call("vps", "decide_permission", {"prompt_id": f"P-{pid}", "decision": "allow"}, lead)[1])

    def test_owner_holds_and_cancels_reach_subtasks(self):
        lead = self.create("manager", "vps")
        sub = self.create("vps", "studio", task=lead)
        def control(action):
            return self.request(f"/ui/tasks/{lead}/control", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                                  action=action, note=""))
        code, result = control("pause")
        self.assertEqual((code, result["subtasks_held"]), (200, [sub]))
        self.assertIsNotNone(hub.active_hold(sub))
        self.assertEqual(control("resume")[0], 409)                         # not confirmed yet
        hub.q("UPDATE holds SET state='stopped'")                          # as the helpers confirm
        code, result = self.request(f"/ui/tasks/{sub}/control", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                                      action="resume", note=""))
        self.assertEqual(code, 409)                                         # it resumes with its parent
        self.assertIn("Resume the parent", result["error"])
        code, result = control("resume")
        self.assertEqual((code, result["subtasks_resumed"], result["subtasks_still_held"]), (200, [sub], []))
        self.assertIsNone(hub.active_hold(sub))
        self.assertFalse(self.call("manager", "cancel_task", {"task_id": f"T-{lead}", "reason": "not needed"})[1])
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (sub,))["state"], "canceled")

    def test_a_lead_updates_like_a_worker(self):
        code, result = self.request("/ui/machines/vps/update", dict(request_id=str(uuid.uuid4()), db="test-generation"))
        self.assertNotEqual(code, 409, result)
        import fleet
        self.assertTrue(fleet.Helper("vps", hub.TEAM["agents"]["vps"]).worker)


class LeadDelivery(OwnerAPI):
    """The helper delivery and the owner chat treat a lead like a worker."""
    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        hub.TEAM["agents"]["vps"]["role"] = "lead"
        hub.TEAM["agents"]["studio"]["reports_to"] = "vps"
        hub.TEAM["addresses"]["vps"] = "127.0.0.1"

    def delivered(self):
        code, data = self.request("/events/vps?delivery=1&after=0&wait=0")
        self.assertEqual(code, 200)
        return [(e["kind"], e["task"]) for e in data["events"]]

    def test_nothing_is_typed_into_a_held_or_finished_lead_task(self):
        live = hub.ins("INSERT INTO tasks(title,owner,requester,state,attempt,created) VALUES('a','vps','manager','working',1,0)")
        held = hub.ins("INSERT INTO tasks(title,owner,requester,state,attempt,created) VALUES('b','vps','manager','working',1,0)")
        done = hub.ins("INSERT INTO tasks(title,owner,requester,state,attempt,created) VALUES('c','vps','manager','completed',1,0)")
        hub.ins("INSERT INTO holds(task,kind,by,note,state,created,attempt) VALUES(?,'pause','owner','','stopped',0,1)", (held,))
        for tid in (live, held, done, None):
            hub.emit("vps", "say", "news", task=tid)
        self.assertEqual(self.delivered(), [("say", f"T-{live}")])

    def test_an_owner_chat_with_a_lead_uses_the_worker_chat(self):
        code, receipt = self.request("/ui/messages", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                          text="Hello lead.", recipient="vps"))
        self.assertEqual(code, 200, receipt)
        row = hub.q1("SELECT kind, text FROM events WHERE id=?", (receipt["event_id"],))
        self.assertEqual(row["kind"], "chat")
        context = ("test-generation", "owner-chat", 1)
        text, error = hub.call_tool("vps", "tell_owner", {"text": "Hi."}, context)
        self.assertTrue(error and "in_reply_to" in text)

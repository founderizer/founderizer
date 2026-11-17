"""The owner deletes an agent (owner feature agent_remove, the owner's yes of 7 November 2026): one commit takes it out
of team.json with its profile, its skills and its own chat app accounts; one transaction takes what is its own on the
hub and nothing of another agent's; its server's service removes its service, its files and its own OS user; the work
it did stays as history, and its name with it. The refusals, the Try again of a failed removal, the server job on Linux
and on a Mac, and the root command's --remove are here too."""
import functools
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import hub
import hubsetup
from test_servers import KEY, NEW, OTHER, OWNER, ServerService, Servers, git
from test_agent_users import TOOLS
from test_ui_api import PATIENCE


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(cls(name) for cls in (Remove, Spent, Leaving, RemoveService, Helper)
                              for name in cls.__dict__ if name.startswith("test_"))


class Remove(Servers):
    """The owner route, against a local hub with a temporary Fleet repository: scout is a Codex worker on the Linux
    server box, installed by box's own service; vps is another agent of the fleet, which nothing may touch."""

    def setUp(self):
        super().setUp()
        self.joined("box", "linux", source=OTHER, user="fleet")
        status, receipt = self.add_agent("box", "scout", "codex")
        self.assertEqual(status, 200, receipt)
        self.job("box", receipt["job"], "done", "sign_in")

    def job(self, server, job, state, step, detail=None, source=OTHER):
        status, answer = self.service(f"/server/{server}/jobs/{job}", {"state": state, "step": step, "detail": detail},
                                      source=source)
        self.assertEqual(status, 200, answer)

    def remove(self, agent="scout", base=None, **extra):
        return self.owner(f"/ui/team/agents/{agent}/remove", **dict(dict(base_sha256=base or self.team_sha()), **extra))

    def show(self, path):
        return git("--git-dir", str(self.root / "origin.git"), "show", f"main:{path}")

    def head(self):
        return git("--git-dir", str(self.root / "origin.git"), "rev-parse", "main")

    def write(self, files, team=None):
        """The fleet as earlier owner writes left it: files on the configuration ref, committed and pushed."""
        for path, text in files.items():
            (self.kit / path).parent.mkdir(parents=True, exist_ok=True)
            (self.kit / path).write_text(text)
        if team is not None:
            (self.kit / "team.json").write_text(json.dumps(team, indent=2) + "\n")
            hub.TEAM = team
        git("add", "-A", cwd=self.kit)
        git("commit", "-q", "-m", "earlier owner writes", cwd=self.kit)
        git("push", "-q", "origin", "HEAD", cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)

    def own_rows(self, agent):
        """One row of each kind that is the agent's own, as its work and the owner's would leave them."""
        t0 = hub.now()
        hub.q("INSERT OR REPLACE INTO agent_usage(name,data) VALUES(?,'{}')", (agent,))
        hub.q("INSERT INTO agent_notes(agent,text,revision,created,by,why) VALUES(?,'how I work',1,?,?,'start')",
              (agent, t0, agent))
        hub.q("INSERT INTO memories(agent,about,text,prevents,created,request_id) VALUES(?,'a','b','c',?,?)",
              (agent, t0, f"req-{agent}"))
        hub.q("INSERT INTO standing(agent,scope,kind,words,author_kind,author,created) VALUES(?,'agent','instruction',"
              "'be brief','owner','owner',?)", (agent, t0))
        hub.q("INSERT INTO rules(agent,tool,key,input,decision) VALUES(?,'Bash','k','{}','allow')", (agent,))
        hub.q("INSERT INTO owner_reports(text,about,created,agent) VALUES('hello','chat',?,?)", (t0, agent))
        hub.q("INSERT INTO events(agent,kind,text,created) VALUES(?,'say','[hub] hello',?)", (agent, t0))
        hub.q("INSERT INTO session_credentials(sha256,agent,kind,generation,created) VALUES(?,?,?,?,?)",
              (hub.hashlib.sha256(agent.encode()).hexdigest(), agent, "task", "test-generation", t0))
        hub.kv_set(f"tools:{agent}", "[]")
        hub.kv_set(f"listed:{agent}:manager", 1)

    def count(self, agent):
        return {table: hub.q1(f"SELECT COUNT(*) c FROM {table} WHERE {column}=?", (agent,))["c"]
                for table, column in hub.REMOVED_OWN}

    def test_the_feature_is_offered(self):
        self.assertIn("agent_remove", self.request(source=OWNER)[1]["ui_features"])

    def test_a_delete_is_one_commit_a_remove_job_and_the_end_of_its_own_records_only(self):
        team = self.origin_team()
        team["chat_apps"] = {"wa1": {"app": "whatsapp", "label": "Scout's number", "agents": ["scout"],
                                     "unknown": "ignore", "enabled": True},
                             "wa2": {"app": "whatsapp", "label": "Vps's number", "agents": ["vps"],
                                     "unknown": "ignore", "enabled": True}}
        self.write({"skills/scout/triage/SKILL.md": "---\nname: triage\n---\n",
                    "skills/vps/deploy/SKILL.md": "---\nname: deploy\n---\n"}, team)
        for agent in ("scout", "vps"):
            self.own_rows(agent)
        before = self.head()
        status, receipt = self.remove()
        self.assertEqual(status, 200, receipt)
        self.assertEqual({k: receipt[k] for k in ("agent", "server")}, {"agent": "scout", "server": "box"})
        self.assertEqual(git("--git-dir", str(self.root / "origin.git"), "rev-list", "--count", f"{before}..main"), "1")
        self.assertEqual(receipt["revision"], self.head())
        after = self.origin_team()
        self.assertNotIn("scout", after["agents"])
        self.assertEqual(list(after["chat_apps"]), ["wa2"])            # its own account goes, vps's stays
        # ... and the hub forgets what it held of that account, and tells the bridge (CHAT-APPS.md 18.4)
        self.assertEqual(list(hub.chat_removed()), ["wa1"])
        self.assertEqual(after["agents"]["vps"], team["agents"]["vps"])
        files = git("--git-dir", str(self.root / "origin.git"), "ls-tree", "-r", "--name-only", "main").split()
        self.assertNotIn("profiles/scout.md", files)
        self.assertNotIn("skills/scout/triage/SKILL.md", files)
        self.assertIn("skills/vps/deploy/SKILL.md", files)
        self.assertIn("profiles/vps.md", files)
        self.assertNotIn("scout", hub.agents())
        self.assertEqual(set(self.count("scout").values()), {0})
        self.assertEqual(self.count("vps")["agent_notes"], 1)
        self.assertEqual(self.count("vps")["memories"], 1)
        self.assertEqual(self.count("vps")["standing"], 1)
        self.assertIsNone(hub.kv_get("tools:scout"))
        self.assertIsNone(hub.kv_get("listed:scout:manager"))
        self.assertEqual(hub.kv_get("tools:vps"), "[]")
        job = hub.q1("SELECT * FROM server_jobs WHERE id=?", (receipt["job"],))
        self.assertEqual((job["server"], job["kind"], job["agent"], job["runtime"], job["state"]),
                         ("box", "remove", "scout", "codex", "queued"))
        said = hub.q1("SELECT text FROM events WHERE agent='manager' AND text LIKE '%deleted scout%'")
        self.assertIn("no longer in the fleet", said["text"])
        # box's service reads the job with the OS user it takes, which team.json no longer names
        status, jobs = self.service("/server/box/jobs", source=OTHER)
        self.assertEqual(status, 200, jobs)
        self.assertEqual([(j["kind"], j["agent"]) for j in jobs["jobs"]], [("remove", "scout")])
        # its row stays until box has removed it, and then its name is free, as it did no work
        self.assertIsNotNone(hub.q1("SELECT 1 FROM agents WHERE name='scout'"))
        status, answer = self.add_agent("box", "scout", "codex")
        self.assertEqual((status, answer["error"]), (409, "box removes scout now"))
        self.job("box", receipt["job"], "done", "user")
        self.assertIsNone(hub.q1("SELECT 1 FROM agents WHERE name='scout'"))
        self.assertEqual(self.add_agent("box", "scout", "codex")[0], 200)

    def deleted_inside(self, name, path, before=False):
        """The answer to scout's call of `path` when the owner's delete lands inside the hub's function `name`, which
        that call runs: at that function's first call, after its own work, or with `before` at its start."""
        real, done = getattr(hub, name), []

        def meanwhile(*args, **kwargs):
            result = None if before else real(*args, **kwargs)
            if not done:
                done.append(True)
                self.assertEqual(self.remove()[0], 200)
            return real(*args, **kwargs) if before else result
        with patch.object(hub, name, meanwhile):
            answer = self.request(path, source=OTHER)
        self.assertEqual(done, [True])
        self.assertNotIn("scout", hub.agents())
        return answer

    def test_a_poll_that_waited_while_its_agent_was_deleted_reads_unknown_agent(self):
        """scout's helper is in its poll for events when the owner deletes scout: the delete lands after the call's own
        checks, while it waits in the hub. The call ends as every call of a name that no agent has, with 404, and not
        with an error of the hub. It was a KeyError and a 500 on the first fleet, at each agent that left. Here the
        delete lands before the first round of the poll's wait."""
        self.assertEqual(self.deleted_inside("touch", "/events/scout?delivery=1&after=0&wait=0"),
                         (404, {"error": "unknown agent"}))

    def test_a_delete_before_the_poll_reads_its_tool_list_reads_unknown_agent(self):
        """Before its first round the poll reads the tool list of its agent's owner chat, which looks the agent up: a
        delete that landed before that read ends the call with 404 too."""
        self.assertEqual(self.deleted_inside("tool_contract", "/events/scout?delivery=1&after=0&wait=0", before=True),
                         (404, {"error": "unknown agent"}))

    def test_a_delete_inside_a_round_of_the_poll_reads_unknown_agent_too(self):
        """The delete lands inside a round's own reads, after the round looked the name up: the answer is still 404,
        and nothing is handed to a name that is gone."""
        self.assertEqual(self.deleted_inside("active_limit", "/events/scout?delivery=1&after=0&wait=0"),
                         (404, {"error": "unknown agent"}))

    def test_a_delete_between_two_rounds_of_the_poll_ends_the_wait_at_once(self):
        """The delete lands while the poll sleeps between two rounds, which is where the first fleet's helpers were:
        the next round ends the call with 404, well before its wait is over."""
        slept, read_after, begun = [], [], hub.time.monotonic()

        def sleep(seconds, _real=hub.time.sleep):
            if not slept:
                slept.append(seconds)
                self.assertEqual(self.remove()[0], 200)
            _real(min(seconds, 0.05))

        def features(agent, _real=hub.helper_features):         # each round of the poll reads them for its agent
            if slept and agent == "scout":
                read_after.append(agent)
            return _real(agent)
        with patch.object(hub.time, "sleep", sleep), patch.object(hub, "helper_features", features):
            answer = self.request("/events/scout?delivery=1&after=0&wait=4", source=OTHER)
        self.assertEqual((answer, slept), ((404, {"error": "unknown agent"}), [0.5]))
        self.assertEqual(read_after, [])            # the next round reads nothing for a name that is gone
        self.assertLess(hub.time.monotonic() - begun, 4)

    def test_a_status_report_that_waited_for_the_delete_writes_nothing(self):
        """A delete holds the hub's lock for its whole commit, and a status report of scout's helper can wait for it.
        The report then answers 404 and writes nothing: its machine_status row would come back after the delete took
        it, for an agent added again under that name to inherit. It was a KeyError and a 500."""
        report = {"revision": "0" * 40, "branch": "config", "update": {"state": None, "detail": None}}
        real, done = hub.validate_status, []

        def meanwhile(data):
            result = real(data)
            if not done:
                done.append(True)
                self.assertEqual(self.remove()[0], 200)
            return result
        with patch.object(hub, "validate_status", meanwhile):
            answer = self.request("/helper/status/scout", report, source=OTHER)
        self.assertEqual((answer, done), ((404, {"error": "unknown agent"}), [True]))
        self.assertIsNone(hub.q1("SELECT 1 FROM machine_status WHERE agent='scout'"))

    def test_an_owner_message_that_waited_for_the_delete_is_refused_as_for_any_name_that_is_gone(self):
        """The owner writes to scout from one device while the delete from another one runs: the message passed its
        own check of the name and then waits for the lock. It gets the answer of every message to a name that no agent
        has, and nothing is written. It was a KeyError and "hub error"."""
        hub.TEAM["agents"]["scout"].pop("active", None)        # the owner activated it: it takes messages
        real, done = hub.agent_active, []

        def meanwhile(name):
            result = real(name)
            if not done:
                done.append(True)
                self.assertEqual(self.remove()[0], 200)
            return result
        with patch.object(hub, "agent_active", meanwhile):
            answer = self.owner("/ui/messages", text="How are you, Scout?", recipient="scout")
        self.assertEqual((answer, done), ((400, {"error": "recipient must name a configured agent"}), [True]))
        self.assertEqual(self.count("scout")["ui_requests"], 0)
        self.assertEqual(self.count("scout")["events"], 0)

    def test_the_kept_os_user_goes_with_the_job(self):
        team = self.origin_team()
        team["agents"]["scout"]["user"] = "fleet-ranger"       # a renamed agent keeps the user of its first name
        self.write({}, team)
        status, receipt = self.remove()
        self.assertEqual(status, 200, receipt)
        status, jobs = self.service("/server/box/jobs", source=OTHER)
        self.assertEqual(jobs["jobs"][0]["user"], "fleet-ranger")

    def test_work_it_did_stays_and_keeps_its_name(self):
        t0 = hub.now()
        hub.q("INSERT INTO tasks(title,owner,requester,state,created) VALUES('a report','scout','manager',"
              "'completed',?)", (t0,))
        status, receipt = self.remove()
        self.assertEqual(status, 200, receipt)
        self.job("box", receipt["job"], "done", "user")
        self.assertEqual(hub.q1("SELECT COUNT(*) c FROM tasks WHERE owner='scout'")["c"], 1)
        self.assertIsNotNone(hub.q1("SELECT 1 FROM agents WHERE name='scout'"))
        status, answer = self.add_agent("box", "scout", "codex")
        self.assertEqual((status, answer["error"]), (409, "An agent named scout was in this fleet before, and its "
                                                          "records are still here. Choose another name."))

    def test_its_open_install_and_its_sign_in_end(self):
        t0 = hub.now()
        install = hub.ins("INSERT INTO server_jobs(server,kind,agent,runtime,state,step,created,updated) "
                          "VALUES('box','install','scout','codex','needs_owner','sign_in',?,?)", (t0, t0))
        hub.q("INSERT INTO signin_jobs(agent,runtime,state,created,updated) VALUES('scout','codex','needs_owner',?,?)",
              (t0, t0))
        status, receipt = self.remove()
        self.assertEqual(status, 200, receipt)
        self.assertEqual(hub.q1("SELECT state FROM server_jobs WHERE id=?", (install,))["state"], "canceled")
        self.assertIsNone(hub.q1("SELECT 1 FROM signin_jobs WHERE agent='scout'"))
        self.assertEqual(hub.q1("SELECT state FROM server_jobs WHERE id=?", (receipt["job"],))["state"], "queued")
        # the service's word about the ended install is refused, so it stops that job
        status, answer = self.service(f"/server/box/jobs/{install}", {"state": "running", "step": "sign_in"},
                                      source=OTHER)
        self.assertEqual(status, 409, answer)

    def test_its_duties_are_retired_and_its_wake_up_rules_deleted(self):
        t0 = hub.now()
        duty = hub.ins("INSERT INTO responsibilities(agent,text,state,revision,created,updated,created_by,request_id) "
                       "VALUES('scout','watch the inbox','active',1,?,?,'owner','d-1')", (t0, t0))
        rule = hub.ins("INSERT INTO triggers(agent,state,revision,schedule,task,late_minutes,max_tasks_per_day,anchor,"
                       "created,updated,request_id) VALUES('scout','active',1,'{}','look',30,4,?,?,?,'t-1')",
                       (t0, t0, t0))
        status, receipt = self.remove()
        self.assertEqual(status, 200, receipt)
        self.assertEqual(hub.q1("SELECT state FROM responsibilities WHERE id=?", (duty,))["state"], "retired")
        self.assertEqual(hub.q1("SELECT state FROM triggers WHERE id=?", (rule,))["state"], "deleted")

    def test_its_open_needs_you_items_close(self):
        """An item that scout raised leaves Needs you with the delete, as an item that the hub ends: nobody is left to
        read the owner's answer. An answer that the owner sends afterwards is refused, and writes nothing for the
        name. The items of the other agents stay open."""
        t0 = hub.now()
        mine, other = (hub.ins("INSERT INTO needs(title,why,todo,raised,by) VALUES('Choose a label','it asks','say "
                               "which',?,?)", (t0, by)) for by in ("scout", "manager"))
        status, receipt = self.remove()
        self.assertEqual(status, 200, receipt)
        closed = hub.q1("SELECT answer, answered_by FROM needs WHERE id=?", (mine,))
        self.assertEqual(tuple(closed), ("Closed: Scout was deleted.", "Fleet"))
        self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (other,))["answer"])
        status, answer = self.owner(f"/ui/needs/{mine}", answer="The blue one.")
        self.assertEqual((status, answer["error"]), (409, "owner request is already answered"))
        self.assertEqual((self.count("scout")["ui_requests"], self.count("scout")["events"]), (0, 0))

    def test_a_failed_removal_goes_again_with_the_same_command(self):
        status, receipt = self.remove()
        self.assertEqual(status, 200, receipt)
        self.job("box", receipt["job"], "failed", "user", "Scout's account on box could not be removed.")
        head = self.head()
        status, again = self.remove()
        self.assertEqual(status, 200, again)
        self.assertEqual((again["server"], self.head()), ("box", head))         # no second commit
        job = hub.q1("SELECT * FROM server_jobs WHERE id=?", (again["job"],))
        self.assertEqual((job["kind"], job["state"]), ("remove", "queued"))
        self.job("box", again["job"], "done", "user")
        self.assertEqual(self.remove()[0], 404)                 # nothing is left to remove

    def test_refusals(self):
        self.assertEqual(self.remove("nobody")[0], 404)
        status, answer = self.remove("manager")
        self.assertEqual((status, answer["error"]), (409, "The manager stays in your fleet."))
        t0 = hub.now()
        task = hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES('x','vps','scout',"
                       "'running',?)", (t0,))
        status, answer = self.remove()
        self.assertEqual((status, answer["error"]), (409, "Scout has open tasks. Delete it when they are done."))
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (task,))
        team = self.origin_team()
        team["agents"]["scout"]["role"] = "lead"
        team["agents"]["vps"]["reports_to"] = "scout"
        self.write({}, team)
        with patch.object(hub, "LEADS_READY", True):
            status, answer = self.remove()
        self.assertEqual((status, answer["error"]), (409, "Vps reports to Scout. Change the reporting lines first."))
        team["agents"]["scout"]["role"] = "worker"
        del team["agents"]["vps"]["reports_to"]
        self.write({}, team)
        hub.ins("INSERT INTO server_jobs(server,kind,agent,runtime,state,created,updated) VALUES(?,?,?,?,?,?,?)",
                ("box", "prepare", "other", "claude", "running", t0, t0))
        status, answer = self.remove()
        self.assertEqual((status, answer["error"]), (409, "box prepares a provider for other now"))
        status, answer = self.remove(base="0" * 64)
        self.assertEqual(status, 409)
        self.assertIn("sha256", answer)
        self.assertEqual(self.remove(extra="x")[0], 400)
        self.assertIn("scout", self.origin_team()["agents"])


DAY = 86400
ACCOUNT = "openai:" + "b" * 32      # the account that scout and vps spend from


class Spent(Remove):
    """What a deleted agent spent stays, and a new agent that takes its name later starts with no sessions. Until 17
    November 2026 a delete took the agent's sessions' tokens: the tokens of the goals that it worked on read too low,
    the window points of the agents beside it on its account read too high, and the rows of each period that it worked
    in lost its sessions."""

    def spend(self, agent, *sessions, used=40.0):
        """One usage report of the agent's helper, as the hub takes it (record_session_tokens): its sessions, each
        (session id, days ago, input tokens), and a reading of the account, whose week window is `used` percent used."""
        t0 = hub.now()
        rows = [dict(session_id=sid, total=tokens, last_activity=t0 - days * DAY, input=tokens, cache_read=0,
                     cache_write=0, output=0, calls=1, model="gpt-6.1-sol", first_cache_share=0.0)
                for sid, days, tokens in sessions]
        reading = {"collected_at": t0, "account_key": ACCOUNT, "error": None,
                   "windows": [{"label": "7 days", "used_percent": used, "resets_at": t0 + 3 * DAY,
                                "window_minutes": 7 * 24 * 60}]}
        hub.record_session_tokens(agent, rows, "codex", reading)

    def period(self, since_days, until_days):
        """The rows of that period under any name: what every session that spent in it cost, whichever agent it was.
        No reader of the hub sums them so; this reads the table itself."""
        t0 = hub.now()
        rows = hub.read_rows("SELECT * FROM session_tokens WHERE last_activity>=? AND last_activity<?",
                             (t0 - since_days * DAY, t0 - until_days * DAY))
        return {k: v for k, v in hub.costs_sums(rows, hub.price_book()).items() if k in ("sessions", "input", "cost")}

    def share(self, agent, sid):
        return hub.q1("SELECT window_share FROM session_tokens WHERE agent=? AND session_id=?", (agent, sid))[0]

    def test_what_it_spent_stays_and_a_new_agent_of_its_name_starts_at_zero(self):
        self.spend("scout", ("s-before", 10, 3000), ("s-now", 1, 1000))
        self.spend("vps", ("v-now", 1, 3000))
        self.spend("scout", ("s-now", 1, 1000))
        # the week's 40 points are split by cost over the fleet's sessions in it: scout 10, vps 30
        self.assertEqual((self.share("scout", "s-now"), self.share("vps", "v-now")), (10.0, 30.0))
        before, now = self.period(14, 7), self.period(7, 0)
        self.assertEqual((before["sessions"], before["input"], now["sessions"], now["input"]), (1, 3000, 2, 4000))
        self.assertIsNotNone(before["cost"])
        status, receipt = self.remove()
        self.assertEqual(status, 200, receipt)
        self.assertEqual(self.period(14, 7), before)
        self.job("box", receipt["job"], "done", "user")
        self.assertIsNone(hub.q1("SELECT 1 FROM agents WHERE name='scout'"))   # it did no work: its name is free
        self.assertEqual((self.period(14, 7), self.period(7, 0)), (before, now))
        # vps's next report: its points stay 30, and do not take the 10 of the deleted agent's session
        self.spend("vps", ("v-now", 1, 3000))
        self.assertEqual(self.share("vps", "v-now"), 30.0)
        # the sessions are no longer under the name, so a new agent of the name starts at zero
        self.assertIsNone(hub.q1("SELECT 1 FROM session_tokens WHERE agent='scout'"))
        status, answer = self.add_agent("box", "scout", "codex")
        self.assertEqual(status, 200, answer)
        start, end = hub.now() - 7 * DAY, hub.now()
        costs = hub.costs_view(["scout"], start, end)["agents"][0]
        self.assertEqual((costs["now"]["sessions"], costs["before"]["sessions"], costs["kinds"]), (0, 0, []))
        self.spend("scout", ("n-now", 1, 500))
        costs = hub.costs_view(["scout"], start, end)["agents"][0]
        self.assertEqual((costs["now"]["sessions"], costs["now"]["input"], costs["before"]["sessions"]), (1, 500, 0))
        self.assertEqual(self.period(14, 7), before)
        # the new scout is deleted too: its session goes under a name of its own, beside the first scout's two
        self.job("box", answer["job"], "done", "sign_in")
        status, receipt = self.remove()
        self.assertEqual(status, 200, receipt)
        self.job("box", receipt["job"], "done", "user")
        spent = {r["agent"]: r["n"] for r in hub.q("SELECT agent, COUNT(*) n FROM session_tokens WHERE agent LIKE "
                                                    "'scout:%' GROUP BY agent")}
        self.assertEqual(sorted(spent.values()), [1, 2])
        self.assertEqual([name for name in spent if hub.AGENT_NAME.match(name)], [])
        self.assertEqual((self.period(14, 7)["input"], self.period(7, 0)["input"]), (3000, 4500))

    def test_the_goals_that_it_worked_on_keep_its_tokens_and_its_name_keeps_its_sessions(self):
        t0 = hub.now()
        task = hub.ins("INSERT INTO tasks(title,owner,requester,state,created,goal_id) VALUES('a report','scout',"
                       "'manager','completed',?,7)", (t0,))
        hub.ins("INSERT INTO thread_events(task,attempt,session,seq,ts,type,data,created) VALUES(?,1,'s',1,?,"
                "'session',?,?)", (task, t0, json.dumps({"runtime": "codex", "session_id": "s-goal"}), t0))
        self.spend("scout", ("s-goal", 2, 5000))
        self.assertEqual((hub.goal_tokens(7)[0], hub.all_goal_tokens()[7][0]), (5000, 5000))
        status, receipt = self.remove()
        self.assertEqual(status, 200, receipt)
        self.job("box", receipt["job"], "done", "user")
        self.assertIsNotNone(hub.q1("SELECT 1 FROM agents WHERE name='scout'"))     # its work keeps its name
        self.assertEqual((hub.goal_tokens(7)[0], hub.all_goal_tokens()[7][0]), (5000, 5000))
        self.assertEqual(hub.q1("SELECT COUNT(*) c FROM session_tokens WHERE agent='scout'")["c"], 1)

    def test_a_delete_with_no_server_job_frees_the_name_at_once_and_keeps_what_it_spent(self):
        """vps runs on a machine with no Founderizer service, so its delete gives no server a job, and free_name runs
        inside the delete itself."""
        self.spend("vps", ("v-now", 1, 3000))
        now = self.period(7, 0)
        status, receipt = self.remove("vps")
        self.assertEqual((status, receipt["job"]), (200, None), receipt)
        self.assertIsNone(hub.q1("SELECT 1 FROM agents WHERE name='vps'"))
        self.assertIsNone(hub.q1("SELECT 1 FROM session_tokens WHERE agent='vps'"))
        self.assertEqual(self.period(7, 0), now)

    def test_the_removal_again_after_a_failed_job_keeps_what_it_spent(self):
        self.spend("scout", ("s-now", 1, 1000))
        now = self.period(7, 0)
        status, receipt = self.remove()
        self.assertEqual(status, 200, receipt)
        self.job("box", receipt["job"], "failed", "user", "Scout's account on box could not be removed.")
        status, again = self.remove()
        self.assertEqual(status, 200, again)
        self.assertEqual(hub.q1("SELECT COUNT(*) c FROM session_tokens WHERE agent='scout'")["c"], 1)
        self.job("box", again["job"], "done", "user")
        self.assertIsNone(hub.q1("SELECT 1 FROM session_tokens WHERE agent='scout'"))
        self.assertEqual(self.period(7, 0), now)

    def test_a_new_agent_of_its_name_lists_none_of_its_model_changes_and_checks(self):
        """The costs reading reads an agent's model changes and its checks by its name. The first scout's model change,
        its check that the delete deleted and the check that it had deleted itself go with its sessions under the one
        name that no agent can have, so the costs of a new agent of its name list none of them. They list the new
        agent's own, a check that it deleted included. The same rows of vps stay its own, and the owner's page of a
        moved rule names its agent as it was named, as the apps read an agent's name."""
        t0 = hub.now()

        def change(agent, effort):
            return hub.ins('INSERT INTO model_changes(agent,by,"from","to",why,at) VALUES(?,?,?,?,?,?)',
                           (agent, "manager", json.dumps({"model": None, "effort": None}),
                            json.dumps({"model": None, "effort": effort}), "routine work", t0 - DAY))

        def check(agent, state, run):
            """A check of the agent, in that state, with one run a day ago, quiet or failed: neither starts a task."""
            rule = hub.ins("INSERT INTO triggers(agent,state,revision,schedule,task,late_minutes,max_tasks_per_day,"
                           "anchor,created,updated,request_id,created_by) VALUES(?,?,1,'{}','{}',5,10,?,?,?,?,?)",
                           (agent, state, t0 - 3 * DAY, t0 - 3 * DAY, t0 - 3 * DAY, f"r-{agent}-{state}-{run}",
                            agent))
            hub.ins("INSERT INTO trigger_runs(trigger_id,revision,due,state,created,finished) VALUES(?,1,?,?,?,?)",
                    (rule, t0 - DAY, run, t0 - DAY, t0 - DAY))
            return rule

        def costs(agent="scout"):
            """The agent's costs of the last 7 days: (check, quiet runs, failed runs), the efforts that its model
            changes set, and see_history's words."""
            view = hub.costs_view([agent], t0 - 7 * DAY, hub.now())
            return ([(c["trigger"], c["now"]["quiet"], c["now"]["failed"]) for c in view["checks"]],
                    [m["to"]["effort"] for m in view["model_changes"]], "\n".join(hub.costs_text(view, 7, "manager")))

        self.spend("scout", ("s-now", 1, 1000))
        first = change("scout", "low")
        active, deleted = check("scout", "active", "quiet"), check("scout", "deleted", "error")
        theirs, their_check = change("vps", "medium"), check("vps", "deleted", "quiet")
        checks, changes, text = costs()
        self.assertEqual((checks, changes), ([(active, 1, 0), (deleted, 0, 1)], ["low"]))
        self.assertIn(f"check {active} of scout", text)
        self.assertIn("manager set scout to its default model, low", text)
        status, receipt = self.remove()
        self.assertEqual(status, 200, receipt)
        self.job("box", receipt["job"], "done", "user")
        self.assertIsNone(hub.q1("SELECT 1 FROM agents WHERE name='scout'"))   # it did no work: its name is free
        status, answer = self.add_agent("box", "scout", "codex")
        self.assertEqual(status, 200, answer)
        checks, changes, text = costs()
        self.assertEqual((checks, changes), ([], []))
        for old in (f"check {active} of scout", f"check {deleted} of scout", "set scout to"):
            self.assertNotIn(old, text)
        # they stay, under the name of the first scout's sessions, and its two checks stay deleted
        gone = hub.q1("SELECT agent FROM session_tokens WHERE session_id='s-now'")["agent"]
        self.assertTrue(gone.startswith("scout:deleted:"), gone)
        self.assertEqual(hub.q1("SELECT agent FROM model_changes WHERE id=?", (first,))["agent"], gone)
        self.assertEqual([tuple(r) for r in hub.q("SELECT agent, state FROM triggers WHERE id IN (?,?)",
                                                  (active, deleted))], [(gone, "deleted")] * 2)
        # vps's own stay its own
        self.assertEqual((hub.q1("SELECT agent FROM model_changes WHERE id=?", (theirs,))["agent"],
                          hub.q1("SELECT agent FROM triggers WHERE id=?", (their_check,))["agent"]), ("vps", "vps"))
        self.assertEqual(costs("vps")[:2], ([(their_check, 1, 0)], ["medium"]))
        # the owner's page of a moved rule names its agent as it was named: the apps refuse a name that is no agent's
        status, page = self.request(f"/ui/triggers/{active}?db=test-generation", source=OWNER)
        self.assertEqual((status, page["trigger"]["agent"], page["trigger"]["state"]), (200, "scout", "deleted"), page)
        # the new scout's own model change and its own check, which it deleted, are in its costs
        change("scout", "high")
        own = check("scout", "deleted", "quiet")
        checks, changes, text = costs()
        self.assertEqual((checks, changes), ([(own, 1, 0)], ["high"]))
        self.assertIn(f"check {own} of scout", text)
        self.assertIn("manager set scout to its default model, high", text)


class Leaving(Remove):
    """A call of an agent that is under way when the owner deletes or renames that agent. The command holds the hub's
    lock for its whole run, so the call waits and then goes on for a name that is gone. Before 10 November 2026 it
    read the team for that name, a KeyError that its route answered as an error of the hub's own, and where no such
    read stood in its way it wrote: the count of a window, the mark of a history search and a usage-limit hold came
    back after the delete had taken that agent's rows, and a key enrollment left a key that the next agent of that
    name could not replace. Now such a call takes the lock no more (hub.TeamLock): at every moment that the command
    can land, the call ends with 404 and nothing of that name is written."""
    patience = max(PATIENCE, 60)        # the owner's command, with its reads of the repository, runs inside one call

    def setUp(self):
        super().setUp()
        # box's service moves an agent's key file with a rename (hub.KEY_FEATURE), so a rename moves its key here too
        self.assertEqual(self.reading("box", source=OTHER, os_name="Ubuntu 24.04.1 LTS",
                                      features=[hub.KEY_FEATURE])[0], 200)
        self.own_rows("scout")
        hub.touch("scout")
        hub.TEAM["agents"]["scout"].pop("active", None)     # the owner activated it: it has a chat and gets messages
        hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES('scout',?,?)", (json.dumps(
            {"features": ["agent_key", "chat_warm", "start_once", "status_now"], "os": {"name": "Ubuntu 24.04.1 LTS"},
             "runtime": {"name": "codex", "version": "1.0.0", "signed_in": True}}), hub.now()))
        self.assertEqual(self.owner("/ui/messages", text="How are you, Scout?", recipient="scout")[0], 200)
        said, refused = hub.call_tool("manager", "message_agent", {"agent": "scout", "text": "A question for you.",
                                                                    "request_id": "leaving-1"})
        self.assertFalse(refused, said)
        self.done = hub.ins("INSERT INTO tasks(title,owner,requester,state,created,attempt,delivered) VALUES("
                            "'old work','scout','manager','completed',?,1,?)", (hub.now(), hub.now()))
        # What others do about scout: the owner knows a person, Pat, and scout has raised a Needs-you item.
        status, pat = self.owner("/ui/people", name="Pat", role="customer", agents=["vps"])
        self.assertEqual(status, 200, pat)
        self.pat = pat["person"]["id"]
        self.asked = hub.ins("INSERT INTO needs(title,why,todo,raised,by) VALUES('Choose a label','scout asks',"
                             "'say which',?,'scout')", (hub.now(),))
        self.back, self.printed = self.kept(), []
        for name, stand_in in (("commit_kit_file", lambda *a, **k: "f" * 40), ("central_due", lambda: None)):
            patcher = patch.object(hub, name, stand_in)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(hub.traceback, "print_exc", lambda *a, **k: self.printed.append(
            hub.traceback.format_exc().strip().splitlines()[-1]))
        patcher.start()
        self.addCleanup(patcher.stop)

    def again(self):
        """The fleet as it was before the owner's command, for the next moment."""
        self.back()
        del self.printed[:]

    def command(self, kind):
        """The owner's command as the hub runs it (ui_command): under the lock for its whole run. Its commit is a
        stand-in, so the same fleet serves every moment; its records and the team are real."""
        with hub.LOCK:
            body = {"base_sha256": hub.team_view(hub.kit_revision(fresh=True))[1]}
            if kind == "delete":
                hub.remove_agent("scout", body)
            else:
                hub.rename_agent("scout", dict(body, name="nova"))

    def left(self):
        """What the hub's records hold of the name scout that is an agent's own, and its row; and the keys of nova,
        the name that a rename gives it, because a rename moves a key that the call wrote before it."""
        return dict(self.count("scout"), kv=sorted(r["k"] for r in hub.q("SELECT k FROM kv WHERE k LIKE '%scout%'")),
                    keys=hub.q1("SELECT COUNT(*) c FROM agent_keys WHERE agent IN ('scout','nova')")["c"],
                    reading=hub.q1("SELECT COUNT(*) c FROM machine_status WHERE agent='scout'")["c"],
                    row=hub.q1("SELECT COUNT(*) c FROM agents WHERE name='scout'")["c"])

    def every_moment(self, kind, calls, others=False):
        """Each call, with the owner's command at each of its lock waits in turn (lock_waits). Returns how many moments
        that was. A call of scout's own reads 404 at each of them. A call of `others` about scout was done before the
        command or is refused after it, with the refusal of its route: what it reads is never an error of the hub's.
        After both kinds, the records hold of the name what the command leaves when no call is under way."""
        moments = 0
        self.again()
        self.command(kind)
        alone = self.left()
        self.assertNotIn("scout", hub.agents())
        self.assertEqual("nova" in hub.agents(), kind == "rename")
        for what, path, body, *more in calls:
            seen = 0
            call = functools.partial(self.request, path, body, headers=more[1] if len(more) > 1 else None,
                                     source=more[0] if more else OTHER)
            for n, answer in self.lock_waits(call, functools.partial(self.command, kind), self.again):
                where = f"{what}, the {kind} at its lock wait {n}: {answer}"
                if others:
                    self.assertIn(answer[0], (200, 400, 404, 409), where)
                else:
                    self.assertEqual(answer, (404, {"error": "unknown agent"}), where)
                self.assertEqual(self.printed, [], where)
                self.assertEqual(self.left(), alone, where)
                seen += 1
            self.assertGreater(seen, 0, what)   # the call took the lock at least once, so the command did land in it
            moments += seen
        return moments

    def calls(self):
        chat, task = "/mcp/scout/test-generation/owner-chat/1", f"/mcp/scout/test-generation/T-{self.done}/1"
        tool = lambda name, **args: {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                     "params": {"name": name, "arguments": args}}
        return [("the tool list of its chat", chat, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
                ("its chat reads its messages", chat, tool("read_messages")),
                ("its helper's usage-limit report", "/helper/limit/scout", {}),
                ("its helper's key enrollment", "/helper/key/scout", {"sha256": "a" * 64}),
                ("its helper's poll", "/events/scout?delivery=1&after=0&wait=0&alive=owner-chat", None),
                ("a search of its history", task, tool("search_history", query="work"))]

    def test_the_calls_reach_their_writes_when_no_command_comes(self):
        """The same calls with no delete: each one is answered, and three of them write what a delete takes. So the
        moments of the next two tests are real ones, after which a call had more to do."""
        for what, path, body in self.calls():
            self.again()
            self.assertEqual(self.request(path, body, source=OTHER)[0], 200, what)
            self.assertEqual(self.printed, [], what)
        self.again()
        chat = self.calls()[0]
        self.assertEqual(self.request(chat[1], chat[2], source=OTHER)[0], 200)
        self.assertEqual(hub.kv_get("listed:scout:owner-chat"), "1")
        self.assertEqual(self.request("/helper/limit/scout", {}, source=OTHER)[0], 200)
        self.assertEqual(hub.q1("SELECT COUNT(*) c FROM agent_limits WHERE agent='scout'")["c"], 1)
        self.assertEqual(self.request("/helper/key/scout", {"sha256": "a" * 64}, source=OTHER)[0], 200)
        self.assertEqual(hub.q1("SELECT COUNT(*) c FROM agent_keys WHERE agent='scout'")["c"], 1)

    def test_a_delete_at_any_moment_of_a_call_ends_it_with_404_and_nothing_written(self):
        self.assertGreater(self.every_moment("delete", self.calls()), 60)

    def test_a_rename_at_any_moment_of_a_call_ends_it_with_404_and_nothing_under_the_old_name(self):
        """And a key that the helper enrolled is there under the new name only when the helper read 200 for it: it
        keeps its key file on that answer alone. With the hub's record line after the key, a rename between the two
        moved the key to nova and the helper read 404, and nova's helper then had no key that the hub took."""
        self.assertGreater(self.every_moment("rename", self.calls()[:4]), 12)

    def others(self):
        """(what, path, body, the caller's address, its headers) of what others send about scout."""
        message = {"request_id": "5a7b3c2e-0c1d-4f6a-9b8e-1d2c3b4a5f60", "db": "test-generation",
                   "text": "One more thing, Scout.", "recipient": "scout"}
        person = {"request_id": "6b8c4d3f-1d2e-4a7b-8c9f-2e3d4c5b6a71", "db": "test-generation", "id": self.pat,
                  "agents": ["vps", "scout"]}
        answer = {"request_id": "7c9d5e40-2e3f-4b8c-9d0a-3f4e5d6c7b82", "db": "test-generation",
                  "answer": "The blue one."}
        board = {"Content-Type": "application/json", "Accept": "application/json"}
        return [("the owner's message to it", "/ui/messages", message, OWNER),
                ("the owner's answer to its Needs-you item", f"/ui/needs/{self.asked}", answer, OWNER),
                ("the same answer on the hub's own board", f"/needs/{self.asked}", {"answer": "The blue one."}, OWNER,
                 board),
                ("the owner gives a person this agent", "/ui/people", person, OWNER)]

    def test_what_others_send_about_it_at_any_moment_of_a_delete_is_done_before_or_refused_after(self):
        """The owner's message to scout, the owner's answer to scout's Needs-you item, in the app and on the board,
        the owner's word that gives Pat this agent, and its server's word about its job, each with the delete at
        each of its lock waits. Each of them looked the name up before it waited, and wrote after the wait: the
        message read "hub error", the answer left an event for scout, Pat kept an agent named scout for the next
        agent of that name, and the ask for a new status went to a name that no agent had. None of them leaves a
        row of scout's own after the delete. (A hand-over copy for it: test_capacity.)"""
        job = hub.ins("INSERT INTO server_jobs(server,kind,agent,runtime,state,step,created,updated) VALUES('box',"
                      "'prepare','scout','codex','running','runtime',?,?)", (hub.now(), hub.now()))
        self.back = self.kept()             # the fleet of each moment has this open job of scout
        service = {"Content-Type": "application/json", "X-Fleet-Client": "server-test",
                   "Authorization": "Bearer " + KEY}
        word = ("its server's word that its job is done", f"/server/box/jobs/{job}",
                {"state": "done", "step": "sign_in", "detail": None}, OTHER, service)
        self.assertGreater(self.every_moment("delete", self.others() + [word], others=True), 8)

    def test_what_others_send_about_it_at_any_moment_of_a_rename_is_done_before_or_refused_after(self):
        """The same with a rename, without the server's job: a rename is refused while a job of its server is open."""
        self.assertGreater(self.every_moment("rename", self.others(), others=True), 5)

    def test_a_request_that_waited_for_the_lock_while_its_agent_left_does_not_get_it(self):
        """The name is looked up after the wait for the lock, not before it: a request that asked while the owner's
        command held the lock gets the refusal when the command lets go. (The other tests run the command to its end
        before the call asks, so they do not tell a lookup before the wait from one after it.)"""
        self.again()
        asks, got = threading.Event(), []

        def request():
            hub.CALL.agent = "scout"
            asks.set()
            try:
                hub.q1("SELECT 1 one")
                got.append("the lock")
            except hub.Left:
                got.append("left")
            finally:
                hub.CALL.agent = None
        with hub.LOCK:                      # the owner's command holds the lock
            waiting = threading.Thread(target=request)
            waiting.start()
            self.assertTrue(asks.wait(5))
            time.sleep(0.3)                 # the request waits for the lock now
            self.assertEqual(got, [])
            hub.TEAM["agents"] = {name: a for name, a in hub.agents().items() if name != "scout"}
        waiting.join(5)
        self.assertEqual(got, ["left"])

    def test_a_request_that_had_its_answer_before_the_agent_left_gets_no_second_one(self):
        """The delete lands after a request sent its answer, and the request then has one more thing to read: the
        lock is not given, and the request ends there. Nothing follows its answer on the connection, which the hub
        closes: a second answer would be read as the answer to the client's next request."""
        sent = []

        def json_and_more(handler, code, obj, headers=None, _real=hub.Handler.json):
            _real(handler, code, obj, headers)
            if not sent:
                sent.append(code)
                owner = threading.Thread(target=self.command, args=("delete",))    # another request, as it is
                owner.start()
                owner.join()
                hub.kv_get("one more read")
        body = b'{"ids": []}'
        with patch.object(hub.Handler, "json", json_and_more), \
                socket.create_connection(("127.0.0.1", self.server.server_port), timeout=self.patience) as client:
            client.sendall(b"POST /helper/ack/scout HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Test-Source: %s\r\n"
                           b"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s"
                           % (self.server.server_port, OTHER.encode(), len(body), body))
            read, closed = b"", False
            try:
                for part in iter(lambda: client.recv(65536), b""):
                    read += part
                closed = True               # the hub ended the connection
            except TimeoutError:
                pass
        self.assertEqual((sent, self.printed), ([200], []))
        self.assertNotIn("scout", hub.agents())
        self.assertTrue(read.startswith(b"HTTP/1.1 200 "), read[:40])
        self.assertEqual((read.count(b"HTTP/1.1 "), closed), (1, True), read)

    def test_the_next_request_of_a_kept_connection_gets_its_own_404(self):
        """A connection that stays open serves one request after another. The mark that a request has its answer is
        that request's own: the next one, whose agent leaves before its answer, still reads 404. With the mark kept,
        the hub closed the connection with no answer at all."""
        landed = []

        def acked(handler, agent, _real=hub.Handler.allowed):
            allowed = _real(handler, agent)
            if handler.path.startswith("/helper/limit/") and not landed:
                landed.append(True)
                owner = threading.Thread(target=self.command, args=("delete",))
                owner.start()
                owner.join()
            return allowed
        kept = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=self.patience)
        self.addCleanup(kept.close)
        head = {"Content-Type": "application/json", "X-Test-Source": OTHER}
        with patch.object(hub.Handler, "allowed", acked):
            kept.request("POST", "/helper/ack/scout", body=b'{"ids": []}', headers=head)
            first = kept.getresponse()
            first.read()
            kept.request("POST", "/helper/limit/scout", body=b"{}", headers=head)
            second = kept.getresponse()
            said = json.loads(second.read())
        self.assertEqual((first.status, landed, second.status, said, self.printed),
                         (200, [True], 404, {"error": "unknown agent"}, []))

    def test_a_read_of_the_team_that_finds_no_such_name_ends_the_call_with_404_too(self):
        """The lock's refusal is one way that a call learns that its agent left. The other is a read of the team with
        no lock taken since the agent left, which is a KeyError: it ends the call in the same way, with 404 and no
        traceback, also inside a tool call's own error handling (rpc)."""
        def leaves_then_reads(agent, context=None):
            owner = threading.Thread(target=self.command, args=("delete",))
            owner.start()
            owner.join()
            return hub.agents()[agent]
        with patch.object(hub, "tools_for", leaves_then_reads):
            answer = self.request("/mcp/scout/test-generation/owner-chat/1",
                                  {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, source=OTHER)
        self.assertEqual((answer, self.printed), ((404, {"error": "unknown agent"}), []))

    def test_the_lock_is_not_given_to_a_request_of_a_name_that_left(self):
        """The rule itself (hub.TeamLock), in one thread: the request that works for scout takes the lock while scout
        is in the fleet, a take from inside is not asked again, and after scout left the take raises hub.Left and
        holds nothing. A thread that works for no agent is never asked."""
        self.again()
        hub.CALL.agent = "scout"
        try:
            with hub.LOCK:
                hub.TEAM["agents"] = {name: a for name, a in hub.agents().items() if name != "scout"}
                self.assertIsNone(hub.q1("SELECT 1 one WHERE 0"))       # from inside: the take that it has stays
            for take in (lambda: hub.q1("SELECT 1 one"), lambda: hub.kv_set("listed:scout:owner-chat", 1),
                         hub.LOCK.acquire, hub.transaction().__enter__):
                with self.assertRaises(hub.Left):
                    take()
                self.assertFalse(hub.LOCK._is_owned())
        finally:
            hub.CALL.agent = None
        self.assertEqual(hub.q1("SELECT 1 one")["one"], 1)
        self.assertIsNone(hub.kv_get("listed:scout:owner-chat"))


class RemoveService(ServerService):
    """server.py's remove job against this hub: scout is installed by the service, the owner deletes it, and the
    service takes away what is scout's and nothing else."""

    def runner(self, answers=None):
        inner = super().runner(answers)

        def run(argv, cwd=None, timeout=120, env=None):
            words = [str(a) for a in argv]
            if words[:3] == ["sudo", "-n", self.mod.AGENT_HELPER] and words[3].startswith("--remove="):
                self.commands.append((words[2:], cwd, None))
                if self.no_helper:      # an older helper, whose pattern has no --remove=
                    return 2, "", f"fleet-agent-user: {words[3]} is no agent user of a fleet"
                user = words[3][len("--remove="):]
                self.made.pop(user, None)
                return 0, f"fleet-agent-user: {user} is removed\n", ""
            user, _folder, rest = self.becomes(argv)
            if rest[:1] == ["find"] and user in self.made:
                self.commands.append((rest, cwd, user))
                return self.mod.Service.command(rest, timeout=timeout)
            return inner(argv, cwd, timeout, env)
        return run

    def ran(self):
        return [" ".join(argv) for argv, _cwd, _user in self.commands]

    def delete(self):
        status, receipt = self.owner("/ui/team/agents/scout/remove", base_sha256=self.team_sha())
        self.assertEqual(status, 200, receipt)
        return receipt

    def test_on_linux_its_service_ends_its_home_empties_and_its_user_goes(self):
        self.join_by_script(self.code("mini", "linux")["code"], kind="linux")
        svc = self.service()
        self.installed_agent(svc, "codex")
        home = Path(self.made["fleet-scout"])
        self.assertTrue((home / "fleet-scout").is_dir())
        self.delete()
        svc.loop(rounds=1)
        job = self.servers()[1]["mini"]["job"]
        self.assertEqual((job["kind"], job["state"], job["detail"]), ("remove", "done", "Scout is removed from mini."))
        ran = self.ran()
        stop = ran.index("systemctl --user disable --now fleet-scout.service")
        self.assertLess(stop, ran.index("tmux kill-session -t =fleet-scout:"))
        self.assertLess(ran.index("tmux kill-session -t =fleet-scout:"), next(i for i, r in enumerate(ran)
                                                                               if r.startswith("find ")))
        self.assertEqual(ran[-1], f"{self.mod.AGENT_HELPER} --remove=fleet-scout")
        self.assertEqual(list(home.iterdir()), [])              # emptied as scout, before its user went
        self.assertNotIn("fleet-scout", self.made)
        self.assertIsNone(hub.q1("SELECT 1 FROM agents WHERE name='scout'"))

    def test_an_older_helper_fails_the_job_at_the_account_and_says_what_to_do(self):
        self.join_by_script(self.code("mini", "linux")["code"], kind="linux")
        svc = self.service()
        self.installed_agent(svc, "codex")
        self.no_helper = True
        self.delete()
        svc.loop(rounds=1)
        job = self.servers()[1]["mini"]["job"]
        self.assertEqual((job["state"], job["step"], job["detail"]),
                         ("failed", "user", "Scout's account on mini could not be removed. Run the join line again on "
                                            "mini, then try again."))
        self.assertIsNotNone(hub.q1("SELECT 1 FROM agents WHERE name='scout'"))     # the name waits for the end

    def test_on_a_mac_only_its_own_files_go(self):
        """A Mac's agent runs as the Mac's user, which also holds the service's files and those of agents from before
        a Mac ran one agent: scout's files go by their names, and those of scout-two, whose name begins as scout's
        does, and of ac stay."""
        self.join_by_script(self.code()["code"])
        svc = self.service(platform="darwin", answers={"launchctl print": (1, "", "not loaded")})
        self.installed_agent(svc, "claude")
        fleet_dir = self.home / ".fleet"
        (fleet_dir / "sessions").mkdir(parents=True, exist_ok=True)
        (fleet_dir / "onboarding").mkdir(exist_ok=True)
        mine = ["agent-scout.key", "usage-scout.json", "chat-scout.json", "chat-scout.claude.json",
                "manager-scout.lock", "helper-scout.lock", "scout.log", "scout.err", "sessions/scout.T-4.ab12.json",
                "onboarding/scout.json", "slow-scout.json", "signed-in-scout.json"]
        theirs = ["agent-scout-two.key", "scout-two.log", "chat-scout-two.claude.json", "sessions/scout-two.T-1.cd.json",
                  "slow-scout-two.json", "signed-in-scout-two.json", "agent-ac.key", "server.key", "server.json"]
        for name in mine + theirs:
            path = fleet_dir / name
            if not path.exists():
                path.write_text("x")
        projects = self.home / ".claude" / "projects"
        own = projects / ("-" + str(os.path.realpath(self.home / "fleet-scout")).strip("/").replace("/", "-")
                          .replace(".", "-").replace("_", "-"))
        other = projects / (str(own.name) + "-two")
        own.mkdir(parents=True)
        other.mkdir()
        self.delete()
        svc.loop(rounds=1)
        job = self.servers()[1]["mini"]["job"]
        self.assertEqual((job["kind"], job["state"], job["step"]), ("remove", "done", "files"))
        self.assertIn("launchctl bootout gui/", " | ".join(self.ran()))
        for name in mine:
            self.assertFalse((fleet_dir / name).exists(), name)
        for name in theirs:
            self.assertTrue((fleet_dir / name).exists(), name)
        self.assertFalse((self.home / "fleet-scout").exists())
        self.assertFalse(own.exists())
        self.assertTrue(other.exists())
        self.assertTrue((self.home / "fleet-server").is_dir())         # the service's own checkout stays

    def test_a_folder_the_service_did_not_make_stays(self):
        self.join_by_script(self.code()["code"])
        svc = self.service(platform="darwin", answers={"launchctl print": (1, "", "not loaded")})
        self.installed_agent(svc, "claude")
        (self.home / "fleet-scout" / ".git" / "fleet-server").write_text("somebody\n")
        self.delete()
        svc.loop(rounds=1)
        self.assertEqual(self.servers()[1]["mini"]["job"]["state"], "done")
        self.assertTrue((self.home / "fleet-scout").is_dir())


class Helper(unittest.TestCase):
    """`fleet-agent-user --remove=fleet-<agent>`: the root command takes away an agent's user with its home, and only
    a user in the agents' group."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-agent-remove-"))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.tmp)])
        self.script = self.tmp / "fleet-agent-user"
        self.script.write_text(hubsetup.helper_script().replace("rm -rf -- /home/", f"rm -rf -- {self.tmp}/home/"))
        self.log, self.there, self.members = self.tmp / "ran", self.tmp / "users", self.tmp / "members"
        self.stubs = self.tmp / "bin"
        self.stubs.mkdir()
        for tool in TOOLS + ("pkill", "pgrep", "crontab", "userdel", "sleep"):
            body = ""
            if tool == "id":
                body = (f'if [ "$#" = 1 ] && [ "$1" = -u ]; then echo 0; exit 0; fi\n'
                        f'if [ "$1" = -u ]; then grep -qx "$2" {self.there} 2>/dev/null || exit 1; echo 4001; fi\n'
                        f'if [ "$1" = -nG ]; then printf "%s" "$2"; grep -qx "$2" {self.members} 2>/dev/null && '
                        f'printf " {hubsetup.AGENT_GROUP}"; echo; fi\n')
            if tool == "pgrep":     # no process of that user is left
                body = "exit 1\n"
            if tool == "userdel":   # the user is gone from here on
                body = (f'for a in "$@"; do u=$a; done; grep -vx "$u" {self.there} > {self.there}.new || true; '
                        f'mv {self.there}.new {self.there}\n')
            one = self.stubs / tool
            one.write_text(f'#!/bin/sh\nprintf "%s\\n" "{tool} $*" >> {self.log}\n{body}exit 0\n')
            one.chmod(0o755)

    def run_helper(self, *args):
        done = subprocess.run(["sh", str(self.script), *args], capture_output=True, text=True,
                              env=dict(os.environ, PATH=os.pathsep.join([str(self.stubs), os.environ["PATH"]])))
        return done.returncode, done.stdout + done.stderr

    def changes(self):
        return [line for line in (self.log.read_text().splitlines() if self.log.exists() else [])
                if not line.startswith("id ")]

    def test_it_removes_an_agents_user_with_its_home(self):
        self.there.write_text("fleet-writer\n")
        self.members.write_text("fleet-writer\n")
        home = self.tmp / "home" / "fleet-writer"
        home.mkdir(parents=True)
        (home / "file").write_text("x")
        code, said = self.run_helper("--remove=fleet-writer")
        self.assertEqual(code, 0, said)
        self.assertIn("fleet-writer is removed", said)
        ran = self.changes()
        for wanted in ("loginctl disable-linger fleet-writer", "loginctl terminate-user fleet-writer",
                       "pkill -KILL -u fleet-writer", "userdel -r fleet-writer"):
            self.assertIn(wanted, ran)
        self.assertLess(ran.index("pkill -KILL -u fleet-writer"), ran.index("userdel -r fleet-writer"))
        self.assertFalse(home.exists())
        self.assertEqual(self.there.read_text().split(), [])

    def test_a_user_that_is_not_there_is_gone_already(self):
        code, said = self.run_helper("--remove=fleet-writer")
        self.assertEqual((code, self.changes()), (0, []), said)

    def test_it_never_removes_a_user_outside_the_agents_group(self):
        self.there.write_text("fleet-somebody\n")
        code, said = self.run_helper("--remove=fleet-somebody")
        self.assertEqual((code, self.changes()), (3, []), said)
        self.assertIn("no agent's, so it stays as it is", said)

    def test_it_takes_one_checked_argument_and_nothing_else(self):
        for args in (("--remove",), ("--remove=",), ("--remove=root",), ("--remove=fleet",), ("--remove=fleet-a;id",),
                     ("--remove", "fleet-writer"), ("fleet-writer", "--remove"), ("--remove=fleet-writer", "x"),
                     ("--remove=../root",), ("--remove=fleet-writer/x",), ("--removefleet-writer",),
                     ("x--remove=fleet-writer",)):
            code, said = self.run_helper(*args)
            self.assertEqual((code, self.changes()), (2, []), (args, said))


if __name__ == "__main__":
    unittest.main()

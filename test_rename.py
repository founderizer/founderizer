"""A new name for an agent (owner feature agent_rename, UI-API.md 1.45): the owner route and what it moves in
team.json, the profile and the database; its refusals; the server job and its second try; the OS user an agent keeps
after a rename, as team.json, verify and the installers read it; and the server service's rename job against a real
local hub, on Linux and on a Mac. Nobody signs in again: that was the owner's question, and it is the design."""
import ast
import contextlib
import io
import json
import re
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import fleet
import hub
import hubsetup
import verify
from test_servers import NEW, OTHER, OWNER, ServerService, Servers, git, sha


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(cls(name) for cls in (Rename, Columns, KeptUser, RenameService) for name in cls.__dict__
                              if name.startswith("test_"))


JSON_COLUMNS = {"data", "extra", "body", "result", "detail", "args", "limits", "receipt", "schedule", "spec"}
KV_PREFIX = re.compile(r"[a-z][a-z0-9_]*:")


def kv_prefixes(source):
    """Every prefix that `source` builds a kv key from with a value: f"<prefix>{value}..." or "<prefix>" + value, as
    the key of kv_get or kv_set, or as a value of a statement that names the kv table."""
    found = set()
    for c in ast.walk(ast.parse(source)):
        if not isinstance(c, ast.Call):
            continue
        name = c.func.id if isinstance(c.func, ast.Name) else c.func.attr if isinstance(c.func, ast.Attribute) else ""
        sql = c.args[0].value if c.args and isinstance(c.args[0], ast.Constant) else ""
        keys = [c.args[0]] if name in ("kv_get", "kv_set") and c.args else \
            list(c.args[1].elts) if isinstance(sql, str) and " kv" in sql and len(c.args) > 1 and \
            isinstance(c.args[1], ast.Tuple) else []
        for k in keys:
            if isinstance(k, ast.JoinedStr) and len(k.values) > 1 and isinstance(k.values[0], ast.Constant) and \
                    isinstance(k.values[1], ast.FormattedValue) and KV_PREFIX.fullmatch(k.values[0].value):
                found.add(k.values[0].value)
            elif isinstance(k, ast.BinOp) and isinstance(k.op, ast.Add) and isinstance(k.left, ast.Constant) and \
                    isinstance(k.left.value, str) and KV_PREFIX.fullmatch(k.left.value):
                found.add(k.left.value)
    return found


def plant(table, column, value):
    """One row of that table with that column set to value, and every other column that must have a value given one
    of its own, so that one test can hold a record of the agent in each column a rename moves."""
    values, columns = {}, hub.DB.execute(f"PRAGMA table_info({table})").fetchall()
    rowid = [c["name"] for c in columns if c["pk"]]
    for c in columns:
        if c["name"] == column:
            values[c["name"]] = value
        elif rowid == [c["name"]] and c["type"].upper() == "INTEGER":
            continue                                # the row id
        elif c["notnull"] and c["dflt_value"] is None:       # a JSON column gets an object, any other one a word
            values[c["name"]] = 0 if c["type"].upper() in ("INTEGER", "REAL") else "{}" if c["name"] in JSON_COLUMNS \
                else f"x-{uuid.uuid4().hex[:8]}"
    hub.DB.execute(f"INSERT OR IGNORE INTO {table}({','.join(values)}) VALUES({','.join('?' * len(values))})",
                   tuple(values.values()))
    hub.DB.commit()
    assert hub.DB.execute(f"SELECT COUNT(*) FROM {table} WHERE {column}=?", (value,)).fetchone()[0], (table, column)


class Rename(Servers):
    """The owner route, against a local hub with a temporary Fleet repository: scout is a Codex worker on the Linux
    server box, installed by box's own service."""

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

    def rename(self, agent="scout", name="nova", base=None, **extra):
        return self.owner(f"/ui/team/agents/{agent}/rename", **dict(dict(base_sha256=base or self.team_sha(), name=name),
                                                                     **extra))

    def show(self, path):
        return git("--git-dir", str(self.root / "origin.git"), "show", f"main:{path}")

    def head(self):
        return git("--git-dir", str(self.root / "origin.git"), "rev-parse", "main")

    def write_team(self, team):
        """team.json as the owner's earlier writes left it, committed and pushed as the hub's own would be."""
        (self.kit / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        git("add", "team.json", cwd=self.kit)
        git("commit", "-q", "-m", "earlier owner writes", cwd=self.kit)
        git("push", "-q", "origin", "HEAD", cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = team

    def test_the_feature_is_offered(self):
        self.assertIn("agent_rename", self.request(source=OWNER)[1]["ui_features"])

    def test_a_rename_moves_the_entry_every_reference_and_the_profile_in_one_commit(self):
        team = self.origin_team()
        team["agents"]["scout"]["role"] = "lead"                     # it leads vps, and it has a WhatsApp number
        team["agents"]["vps"]["reports_to"] = "scout"
        team["chat_apps"] = {"wa-scout": {"app": "whatsapp", "label": "Scout", "agents": ["scout"],
                                          "unknown": "ignore", "enabled": True}}
        self.write_team(json.loads(json.dumps(team)))           # the hub's own copy, which the rename changes
        before, profile = self.head(), self.show("profiles/scout.md")
        status, receipt = self.rename()
        self.assertEqual(status, 200, receipt)
        self.assertEqual({k: receipt[k] for k in ("agent", "was", "server", "replayed")},
                         {"agent": "nova", "was": "scout", "server": "box", "replayed": False})
        after = self.origin_team()
        self.assertEqual(list(after["agents"]), [("nova" if n == "scout" else n) for n in team["agents"]])
        self.assertEqual(after["agents"]["nova"], dict(team["agents"]["scout"], user="fleet-scout"))
        self.assertEqual(after["agents"]["vps"]["reports_to"], "nova")
        self.assertEqual(after["chat_apps"]["wa-scout"]["agents"], ["nova"])
        self.assertEqual(git("--git-dir", str(self.root / "origin.git"), "rev-list", "--count", f"{before}..main"), "1")
        self.assertEqual(receipt["revision"], self.head())
        files = git("--git-dir", str(self.root / "origin.git"), "diff", "--no-renames", "--name-status", before, "main").split("\n")
        self.assertEqual(sorted(f.split()[-1] for f in files), ["profiles/nova.md", "profiles/scout.md", "team.json"])
        self.assertTrue(profile.startswith("# Profile: scout\n"))
        self.assertEqual(self.show("profiles/nova.md"), profile.replace("# Profile: scout", "# Profile: nova", 1))
        self.assertEqual(sorted(hub.agents()), sorted(after["agents"]))
        self.assertEqual(receipt["sha256"], self.team_sha())

    def test_a_rename_moves_the_agents_skills_in_the_same_commit(self):
        """Design v4 D1: skills/<agent>/ is the agent's own, as its profile is, so it moves with the name, byte for
        byte, and nothing of it stays under the old name."""
        skill = '---\nname: deploy\ndescription: "Deploy the shop."\n---\n\nSteps.'
        hub.commit_kit_file("skills/scout/deploy/SKILL.md", (skill + "\n").encode(), "scout wrote the skill deploy",
                            more={"skills/scout/deploy/scripts/check.sh": b"npm run smoke\n"}, author="scout")
        before = self.head()
        status, receipt = self.rename()
        self.assertEqual(status, 200, receipt)
        self.assertEqual(git("--git-dir", str(self.root / "origin.git"), "rev-list", "--count", f"{before}..main"), "1")
        self.assertEqual(self.show("skills/nova/deploy/SKILL.md"), skill)
        self.assertEqual(self.show("skills/nova/deploy/scripts/check.sh"), "npm run smoke")
        self.assertEqual(git("--git-dir", str(self.root / "origin.git"), "ls-tree", "-r", "--name-only", "main", "--",
                             "skills/scout/"), "")

    def test_a_rename_moves_every_record_of_the_agent_and_takes_its_key_back(self):
        base = self.team_sha()
        for table, column in hub.AGENT_COLUMNS:
            plant(table, column, "scout")
        hub.q("INSERT INTO agent_keys(agent,sha256,created,source) VALUES('scout',?,0,'enrolled')", ("a" * 64,))
        hub.q("INSERT INTO agent_keys(agent,sha256,created,source) VALUES('nova',?,0,'owner')", ("b" * 64,))
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES('nova','{}',0)")   # left by an agent removed by hand
        hub.kv_set("tools:scout", "contract")
        hub.kv_set("tools:nova", "an old one")
        hub.kv_set("default_vault:scout", 1)                # the owner's word on its defaults: a rename keeps it
        hub.kv_set("default_desktop:scout", 1)
        status, receipt = self.rename(base=base)
        self.assertEqual(status, 200, receipt)
        self.assertEqual([hub.kv_get(k) for k in ("default_vault:nova", "default_desktop:nova", "default_vault:scout",
                                                  "default_desktop:scout")], ["1", "1", None, None])
        for table, column in hub.AGENT_COLUMNS:
            self.assertEqual(hub.q1(f"SELECT COUNT(*) n FROM {table} WHERE {column}='scout'")["n"], 0, (table, column))
            self.assertGreater(hub.q1(f"SELECT COUNT(*) n FROM {table} WHERE {column}='nova'")["n"], 0, (table, column))
        self.assertEqual(hub.q("SELECT agent FROM agent_keys WHERE agent IN ('scout','nova')"), [])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM session_credentials WHERE agent='nova' AND revoked IS NULL")["n"], 0)
        self.assertEqual((hub.kv_get("tools:nova"), hub.kv_get("tools:scout")), ("contract", None))
        said = hub.q1("SELECT * FROM events WHERE agent='manager' AND kind='say' ORDER BY id DESC LIMIT 1")
        self.assertIn("The owner renamed scout to nova.", said["text"])
        self.assertIn("use nova from now on", said["text"])
        logged = [r["what"] for r in hub.q("SELECT what FROM log WHERE agent='owner'")]
        self.assertTrue(any(w.startswith("renamed agent scout to nova on server box") for w in logged), logged)

    def test_a_rename_moves_the_kv_notes_with_more_after_the_name_and_the_lists_of_names(self):
        """The audit of 7 November 2026: chased:<agent>:<item>, untaken:<agent>:<window> and listed:<agent>:<window>
        stayed under the old name, so the renamed agent was chased again for what it had been told; and the agents that
        passed a question up kept the old name, so its next pass named an agent that no longer exists."""
        base = self.team_sha()
        for key in ("chased:scout:Q-4", "untaken:scout:T-9", "listed:scout:owner-chat", "duty_review:scout",
                    "chased:scouts:Q-5", "chased:nova:Q-6"):
            hub.kv_set(key, "1")
        plant("questions", "asker", "manager")
        hub.q("UPDATE questions SET passed=?", (json.dumps(["scout", "lead"]),))
        status, receipt = self.rename(base=base)
        self.assertEqual(status, 200, receipt)
        held = {r["k"] for r in hub.q("SELECT k FROM kv WHERE k LIKE 'chased:%' OR k LIKE 'untaken:%' OR "
                                      "k LIKE 'listed:%' OR k LIKE 'duty_review:%'")}
        # Another agent's own key stays its own, and what an earlier agent of the new name left goes, as in AGENT_KV.
        self.assertEqual(held, {"chased:nova:Q-4", "untaken:nova:T-9", "listed:nova:owner-chat", "duty_review:nova",
                                "chased:scouts:Q-5"})
        self.assertEqual(hub.question_passers(hub.q1("SELECT * FROM questions")), ["nova", "lead"])

    def test_a_rename_keeps_the_agents_saved_checks_its_own(self):
        """Live, 3 November 2026: a DevOps agent became otto, and the hub paused otto's watch, because its saved
        check still named the old name as the agent that answers for its code (wakeups.code_grant). A check from
        before plan P4 also names the agent that runs it (run_on). Another agent's check keeps its own name."""
        own = {"code": "saved", "sha256": "c" * 64, "bytes": 10, "code_by": "scout", "form": "lines", "args": {},
               "timeout_seconds": 20}
        checks = (("scout", own), ("scout", dict(own, run_on="scout")), ("vps", dict(own, code_by="vps")))
        ids = [hub.ins("INSERT INTO triggers(agent,state,revision,schedule,check_spec,task,late_minutes,"
                       "max_tasks_per_day,anchor,created,updated,request_id) "
                       "VALUES(?,'active',1,'{}',?,'{}',0,0,0,0,0,?)", (agent, json.dumps(spec), str(uuid.uuid4())))
               for agent, spec in checks]
        status, receipt = self.rename()
        self.assertEqual(status, 200, receipt)
        kept = [json.loads(hub.q1("SELECT check_spec FROM triggers WHERE id=?", (i,))["check_spec"]) for i in ids]
        self.assertEqual(kept, [dict(own, code_by="nova"), dict(own, code_by="nova", run_on="nova"),
                                dict(own, code_by="vps")])

    def test_a_server_that_moves_the_key_file_keeps_the_key_under_the_new_name(self):
        data = json.loads(hub.q1("SELECT data FROM server_status WHERE server='box'")["data"])
        hub.q("UPDATE server_status SET data=? WHERE server='box'", (json.dumps(dict(data, features=[hub.KEY_FEATURE])),))
        hub.q("INSERT INTO agent_keys(agent,sha256,created,source) VALUES('scout',?,7,'enrolled')", ("a" * 64,))
        hub.q("INSERT INTO agent_keys(agent,sha256,created,source) VALUES('nova',?,0,'owner')", ("b" * 64,))
        hub.q("INSERT INTO session_credentials(sha256,agent,kind,generation,created) VALUES('s','scout','chat','g',0)")
        status, receipt = self.rename()
        self.assertEqual(status, 200, receipt)
        self.assertEqual([dict(r) for r in hub.q("SELECT agent,sha256,created,source FROM agent_keys WHERE agent IN "
                                                 "('scout','nova')")],
                         [{"agent": "nova", "sha256": "a" * 64, "created": 7, "source": "enrolled"}])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM session_credentials WHERE agent='nova' AND revoked IS NULL")["n"], 0)

    def test_a_call_that_waited_for_the_rename_is_not_told_that_the_key_is_gone(self):
        """A rename holds the hub's lock for its whole commit. A helper's poll that read the old name before it and
        waited for the lock read no key after it, and on `no_key` a helper deletes its key file (fleet.py), which is
        the file the rename's job then moves."""
        hub.q("INSERT INTO agent_keys(agent,sha256,created,source) VALUES('scout',?,0,'enrolled')", (sha("key"),))
        agent_key, seen = hub.agent_key, []

        def the_rename_lands(name):
            if name == "scout" and not seen:
                seen.append(name)
                self.assertEqual(self.rename()[0], 200)
            return agent_key(name)
        with patch.object(hub, "agent_key", the_rename_lands):
            status, answer = self.request("/events/scout?after=-1&wait=0", source=OTHER,
                                          headers={"Authorization": "Bearer key", "X-Fleet-Client": "test"})
        self.assertEqual(seen, ["scout"])
        self.assertEqual((status, answer), (404, {"error": "unknown agent"}))

    def test_the_server_gets_a_rename_job_with_the_old_name_and_the_kept_user(self):
        status, receipt = self.rename()
        self.assertEqual(status, 200, receipt)
        self.assertEqual(self.service("/server/box/jobs", source=OTHER)[1]["jobs"], [
            {"id": receipt["job"], "kind": "rename", "agent": "nova", "runtime": "codex", "state": "queued",
             "was": "scout", "user": "fleet-scout"}])
        box = self.servers()[1]["box"]
        self.assertEqual((box["agents"], box["job"]["kind"], box["job"]["agent"], box["why"]),
                         (["nova"], "rename", "nova", ["has_agent", "busy"]))
        # a later job of that agent names its kept user too, so the server never builds fleet-nova
        self.job("box", receipt["job"], "done", "service")
        code, prepared = self.request("/ui/servers/box/prepare", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                                  "agent": "nova", "runtime": "claude"}, source=OWNER)
        self.assertEqual(code, 200, prepared)
        self.assertEqual(self.service("/server/box/jobs", source=OTHER)[1]["jobs"][0]["user"], "fleet-scout")

    def test_a_repeat_of_the_command_is_the_same_rename(self):
        request_id, base = str(uuid.uuid4()), self.team_sha()
        first = self.rename(base=base, request_id=request_id)
        again = self.rename(base=base, request_id=request_id)
        self.assertEqual((again[0], again[1]["job"], again[1]["replayed"]), (200, first[1]["job"], True))
        self.assertEqual(self.count("server_jobs"), 2)          # the install and one rename

    def test_a_rename_that_stopped_is_given_again_by_the_command_that_gives_an_install_again(self):
        job = self.rename()[1]["job"]
        self.job("box", job, "failed", "service", "The service of scout did not stop.")
        status, again = self.add_agent("box", "nova", "codex")
        self.assertEqual(status, 200, again)
        self.assertNotEqual(again["job"], job)
        shown = self.service("/server/box/jobs", source=OTHER)[1]["jobs"]
        self.assertEqual([(j["kind"], j["agent"], j["was"]) for j in shown], [("rename", "nova", "scout")])
        self.assertEqual(self.add_agent("box", "nova", "claude")[0], 409)    # another agent, not the same job again

    def test_on_a_mac_the_agent_keeps_the_one_user_of_its_server(self):
        self.joined()                                                       # mini, a Mac
        self.assertEqual(self.add_agent(agent="pilot")[0], 200)
        self.job("mini", self.servers()[1]["mini"]["job"]["id"], "done", "sign_in", source=NEW)
        status, receipt = self.rename("pilot", "ace")
        self.assertEqual(status, 200, receipt)
        self.assertNotIn("user", self.origin_team()["agents"]["ace"])
        self.assertNotIn("user", self.service("/server/mini/jobs", source=NEW)[1]["jobs"][0])

    def test_refusals(self):
        def refused(status, words, *args, **kwargs):
            code, answer = self.rename(*args, **kwargs)
            self.assertEqual(code, status, answer)
            self.assertIn(words, answer["error"])
        refused(404, "no such agent", "nobody")
        refused(409, "The manager keeps its name.", "manager", "boss")
        refused(409, "Scout has this name already.", name="scout")
        refused(409, "An agent named studio exists.", name="studio")
        hub.q("INSERT INTO agents(name) VALUES('gone')")                   # an agent removed by hand
        refused(409, "An agent named gone was in this fleet before", name="gone")
        for name in ("Nova", "n", "owner", "hub", "nova\n", 5):
            self.assertEqual(self.rename(name=name)[0], 400, name)
        self.assertEqual(self.rename(extra="x")[0], 400)
        code, conflict = self.rename(base="0" * 64)
        self.assertEqual((code, conflict["sha256"]), (409, self.team_sha()))
        refused(409, "vps runs no Founderizer service", "vps", "vega")     # a machine from before servers
        task = hub.ins("INSERT INTO tasks(title,owner,requester,state) VALUES('t','manager','scout','working')")
        refused(409, "Scout has open tasks.")
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (task,))
        hub.q("UPDATE server_status SET reported=reported-601 WHERE server='box'")
        refused(409, "box sent no reading in the last 10 minutes")
        self.reading("box", source=OTHER, os_name="Ubuntu 24.04.1 LTS")
        login = hub.ins("INSERT INTO signin_jobs(agent,runtime,state,created,updated) VALUES('scout','codex','starting',?,?)",
                        (hub.now(), hub.now()))
        refused(409, "Scout has an open sign-in.")
        hub.q("UPDATE signin_jobs SET state='canceled' WHERE id=?", (login,))
        work = self.kit / "work"
        git("clone", "-q", str(self.root / "origin.git"), str(work))
        (work / "profiles" / "nova.md").write_text("# Profile: nova\n")
        git("add", "profiles/nova.md", cwd=work)
        git("commit", "-q", "-m", "a profile of an agent removed by hand", cwd=work)
        git("push", "-q", "origin", "HEAD:main", cwd=work)
        git("pull", "-q", "--ff-only", cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        refused(409, "A profile for nova is in the fleet already.")
        status, receipt = self.rename(name="vega")
        self.assertEqual(status, 200, receipt)
        refused(409, "box renames scout to vega now", "vega", "rigel")     # one job at a time on a server
        self.job("box", receipt["job"], "failed", "checkout")
        self.assertEqual(self.add_agent("box", "vega", "codex")[0], 200)   # its second try is a rename again
        self.assertEqual(self.servers()[1]["box"]["job"]["kind"], "rename")

    def test_an_install_that_stopped_comes_first(self):
        self.joined()
        self.assertEqual(self.add_agent(agent="pilot")[0], 200)
        self.job("mini", self.servers()[1]["mini"]["job"]["id"], "failed", "sign_in", source=NEW)
        code, answer = self.rename("pilot", "ace")
        self.assertEqual(code, 409, answer)
        self.assertIn("The install of pilot stopped. Try it again before you rename it.", answer["error"])

    def test_an_install_that_stopped_at_its_sign_in_is_done_once_a_later_sign_in_ended_done(self):
        """Two DevOps agents, 3 November 2026: each install stopped at its sign-in, the owner signed the
        agent in from the app afterwards, and it ran; only the stopped install refused its rename."""
        self.joined()
        self.assertEqual(self.add_agent(agent="pilot")[0], 200)
        job = self.servers()[1]["mini"]["job"]
        self.job("mini", job["id"], "failed", "sign_in", "Claude Code did not sign in within 15 minutes.", source=NEW)
        stopped = hub.q1("SELECT updated FROM server_jobs WHERE id=?", (job["id"],))["updated"]
        signed = "INSERT INTO signin_jobs(agent,runtime,state,created,updated) VALUES('pilot',?,'done',?,?)"
        hub.ins(signed, (job["runtime"], stopped - 9, stopped - 1))         # before it stopped: it says nothing
        self.assertEqual(self.rename("pilot", "ace")[0], 409)
        hub.ins(signed, ("codex", stopped + 5, stopped + 9))                # another runtime says nothing either
        self.assertEqual(self.rename("pilot", "ace")[0], 409)
        hub.ins(signed, (job["runtime"], stopped + 60, stopped + 90))
        hub.q("UPDATE server_jobs SET step='service' WHERE id=?", (job["id"],))
        self.assertEqual(self.rename("pilot", "ace")[0], 409)               # one that stopped earlier is not done
        hub.q("UPDATE server_jobs SET step='sign_in' WHERE id=?", (job["id"],))
        status, receipt = self.rename("pilot", "ace")
        self.assertEqual(status, 200, receipt)
        self.assertEqual(self.servers()[1]["mini"]["job"]["kind"], "rename")

    def test_team_json_takes_a_kept_user_only_for_a_worker_or_a_lead_and_one_agent_to_a_user(self):
        good = json.loads(json.dumps(hub.TEAM))
        good["agents"]["scout"]["user"] = "fleet-vps-old"
        hub.validate_team(good)
        for agent, user in (("scout", "vps"), ("scout", "fleet-Vps"), ("scout", "fleet-" + "a" * 27), ("scout", 5),
                            ("manager", "fleet-manager")):
            bad = json.loads(json.dumps(good))
            bad["agents"][agent]["user"] = user
            with self.assertRaises(ValueError, msg=(agent, user)):
                hub.validate_team(bad)
        twice = json.loads(json.dumps(good))
        twice["agents"]["vps"]["user"] = "fleet-lead"           # vps and lead are both on the machine vps
        with self.assertRaisesRegex(ValueError, "would share the OS user fleet-lead on vps"):
            hub.validate_team(twice)

    def test_team_json_takes_no_agent_named_owner_or_hub_and_no_name_with_a_final_newline(self):
        """The audit of 7 November 2026: `$` let "scout\\n" through every AGENT_NAME.match, and team.json took an
        agent named "owner" or "hub", which only the rename route refused."""
        for name in ("owner", "hub", "scout\n"):
            bad = json.loads(json.dumps(hub.TEAM))
            bad["agents"][name] = bad["agents"].pop("scout")
            with self.assertRaisesRegex(ValueError, "invalid agent name", msg=name):
                hub.validate_team(bad)
        self.assertIsNone(hub.AGENT_NAME.match("scout\n"))
        self.assertTrue(hub.AGENT_NAME.match("scout"))


class Columns(unittest.TestCase):
    """The junction: every column whose name can hold an agent's name is one a rename moves (hub.AGENT_COLUMNS) or
    one named here with what it holds, so a lane that adds a table with an agent in it decides which it is."""

    NOT_AGENTS = {
        ("agent_keys", "agent"): "the key follows the name only with its server's job (hub.rename_rows)",
        ("attachments", "name"): "a file", ("calls", "name"): "a tool", ("chat_ignored", "sender"): "a chat handle",
        ("chat_ignored", "name"): "a person", ("chat_in", "sender"): "a chat handle", ("chat_out", "sender"): "a chat handle",
        ("chat_out", "recipient"): "a Discord user", ("chat_status", "name"): "a bot",
        ("conversation_messages", "who"): "person, agent, owner or action", ("conversations", "sender"): "a chat handle",
        ("deposits", "machine"): "a machine", ("deposits", "recipient"): "a vault key", ("jobs", "target"): "a site",
        ("join_codes", "name"): "a server", ("join_codes", "agent"): "a first agent that does not exist yet", ("link_failures", "sender"): "a chat handle", ("owner_handles", "name"): "the owner",
        ("people", "name"): "a person", ("person_handles", "name"): "a person", ("place_codes", "machine"): "a machine",
        ("roles", "name"): "a role of people",
        ("place_hosts", "machine"): "a machine", ("placements", "target"): "a target", ("placements", "name"): "a variable",
        ("history_fts", "agent"): "the index's own key for an agent, which a rename keeps (hub.history_key)",
        ("placements", "machine"): "a machine", ("withdrawals", "machine"): "a machine",
        ("door_record", "target"): "a host or a provider account of the door (DevOps plan C4)",
        ("door_record", "caller"): "the door's own record of who called it, kept as the door keeps it (plan C4)",
        ("needs", "answered_by"): "the owner (null), a deputy 'P-<id> <name>' or Fleet",
        ("capp_clients", "name"): "a connected app's own name", ("capp_connections", "name"): "a connected app",
        ("capp_grants", "name"): "the connected app of an authorization code",
        ("capp_connections", "ended_by"): "what ended a connected app: owner, reuse, code_reuse, off, client or "
                                          "restore",
    }
    WORDS = {"agent", "owner", "requester", "asker", "from_agent", "to_agent", "decided_by", "by", "sender", "recipient",
             "released_by", "paused_by", "created_by", "closed_by", "dropped_by", "name", "who", "machine", "target",
             "holder", "author", "runner", "approver", "caller"}           # and every column whose name ends in _by
    NOT_AGENT_KV = {
        "check_fails:": "a wake-up rule", "check_lost:": "a run of a check", "conversation_brief:": "a conversation",
        "deliver_running:": "a task", "desktop_click:": "a Mac", "desktop_seen:": "a Mac", "desktop_told:": "a Mac",
        "door_mode:": "a server of the door",
        "history:": "a stream of the history", "knowledge_asked:": "a knowledge file", "lead_unread:": "an unread item",
        "lost:": "a task", "name_told:": "a machine", "owner_pin:": "a machine", "park_ended:": "a reminder",
        "row_floor:": "a table", "screen_frozen:": "a task", "screen_limit:": "a task", "screen_question:": "a task",
        "screen_restart:": "a task", "standing_told:": "a conversation", "start_failed:": "a task",
        "stuck_notice:": "a task", "turn_ack:": "a task", "turn_checked:": "a task", "turn_empty:": "a task"}

    def test_every_column_that_can_hold_an_agent_is_placed(self):
        kept = hub.DB
        self.addCleanup(setattr, hub, "DB", kept)
        hub.DB = sqlite3.connect(":memory:", check_same_thread=False)
        hub.DB.row_factory = sqlite3.Row
        hub.DB.executescript(hub.SCHEMA)
        hub.migrate()
        found = set()
        for (table,) in hub.DB.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
            found |= {(table, c[1]) for c in hub.DB.execute(f"PRAGMA table_info({table})").fetchall()}
        moved = set(hub.AGENT_COLUMNS)
        self.assertEqual(len(moved), len(hub.AGENT_COLUMNS), "a column is named twice")
        self.assertEqual(moved - found, set(), "a column that the schema does not have")
        self.assertEqual(moved & set(self.NOT_AGENTS), set())
        self.assertEqual({c for c in found if c[1] in self.WORDS or c[1].endswith("_by")} - moved - set(self.NOT_AGENTS),
                         set(), "a column that can hold an agent's name and is on neither side: add it to "
                                "hub.AGENT_COLUMNS, or to NOT_AGENTS with what it holds")
        self.assertLessEqual(set(hub.AGENT_ROWS.items()), moved)
        self.assertLessEqual(set(hub.AGENT_LISTS), found)

    def test_every_kv_key_built_from_a_value_is_placed(self):
        """The audit of 7 November 2026: chased:, untaken:, listed:, duty_review:, checks_brief:, chat_team:, presence:
        and turn_ended: hold an agent's name, and a rename left them under the old one, so the agent was chased again
        or reviewed again. Every prefix the code builds a key from is placed: a rename moves it (hub.AGENT_KV,
        hub.AGENT_KV_SCOPED), or it is named here with what it holds."""
        with open(hub.__file__) as f:
            found = kv_prefixes(f.read())
        placed = set(hub.AGENT_KV) | set(hub.AGENT_KV_SCOPED)
        self.assertEqual(set(hub.AGENT_KV) & set(hub.AGENT_KV_SCOPED), set())
        self.assertEqual(placed & set(self.NOT_AGENT_KV), set())
        self.assertGreater(len(found), 30)              # the scan reads the keys, and not nothing
        self.assertEqual(found - placed - set(self.NOT_AGENT_KV), set(),
                         "a kv key built from a value that is on neither side: add its prefix to hub.AGENT_KV (or "
                         "hub.AGENT_KV_SCOPED) when the value is an agent's name, or to NOT_AGENT_KV with what it holds")


class KeptUser(unittest.TestCase):
    """The OS user an agent keeps after a rename, as the installers and verify read it."""

    TEAM = {"hub": {"machine": "hub", "port": 8765},
            "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "box": "127.0.0.3"},
            "servers": {"box": {"kind": "linux", "user": "fleet"}},
            "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                       "nova": {"role": "worker", "runtime": "codex", "machine": "box", "can": [], "user": "fleet-scout"}}}

    def test_the_installers_make_and_list_the_kept_user(self):
        self.assertEqual(hubsetup.agent_user("nova", self.TEAM["agents"]["nova"]), "fleet-scout")
        self.assertEqual(hubsetup.agent_user("nova"), "fleet-nova")
        self.assertEqual(hubsetup.agent_user("nova", {"user": "root"}), "fleet-nova")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "team.json"
            path.write_text(json.dumps(self.TEAM))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                hubsetup.cmd_agent_list(type("Args", (), {"team": str(path), "machine": "box"})())
            self.assertEqual(out.getvalue(), "nova codex fleet-scout\n")
            with contextlib.redirect_stdout(io.StringIO()):
                made = hubsetup.agent_users(self.TEAM, "box", check=True, run=lambda script: (0, "exists=no\n", ""))
            self.assertEqual(made, [("nova", "fleet-scout", "would make")])

    def test_verify_reads_the_kept_user(self):
        users = {"fleet-scout": (4001, "/home/fleet-scout")}
        check = verify.Verify(str(Path(hub.__file__).parent), self.TEAM, "", platform="linux", me=("fleet", 1001),
                              passwd=users.get)
        self.assertEqual(check.agent_user("nova"), "fleet-scout")
        self.assertEqual(check.os_user("nova"), "fleet-scout")
        users.pop("fleet-scout")
        self.assertEqual(check.agent_user("nova"), check.me)         # a machine from before the move reads as before


class RenameService(ServerService):
    """server.py's rename job against this hub: scout is installed by the service, the owner renames it nova, and
    the service moves it under the OS user it has. `mv` runs for real here, as git does."""

    write_team = Rename.write_team

    def runner(self, answers=None):
        inner = super().runner(answers)

        def run(argv, cwd=None, timeout=120, env=None):
            user, folder, rest = self.becomes(argv)
            if rest[:1] == ["mv"] and (not user or user in self.made):
                self.commands.append((rest, folder or cwd, user))
                return self.mod.Service.command(rest, cwd=folder or cwd, timeout=timeout)
            return inner(argv, cwd, timeout, env)
        return run

    def renamed(self, svc, runtime):
        self.installed_agent(svc, runtime)
        status, receipt = self.owner("/ui/team/agents/scout/rename", base_sha256=self.team_sha(), name="nova")
        self.assertEqual(status, 200, receipt)
        return receipt

    def ran(self):
        return [" ".join(argv[1:] if argv[0] == __import__("sys").executable else argv)
                for argv, _cwd, _user in self.commands]

    def shared_key(self, home):
        """Scout shares its machine with vps, and has the key that `fleet.py key` made there and the owner registered,
        which is how an agent on a shared machine gets one. Returns the key."""
        team = self.origin_team()
        team["agents"]["vps"]["machine"] = "mini"
        self.write_team(team)
        self.assertTrue(hub.shared_machine("scout"))
        with patch.object(fleet, "HOME", str(home / ".fleet")):
            digest = fleet.make_key("scout")
        status, answer = self.owner("/ui/team/agents/scout/key", sha256=digest)
        self.assertEqual(status, 200, answer)
        return (home / ".fleet" / "agent-scout.key").read_text().strip()

    def helper_is_back(self, home, key):
        """The helper of nova on that machine: it has its key, so it asks to register nothing and leaves no pending
        key, and the hub knows it. On a shared machine a key that a helper made stays refused: the owner registers
        those."""
        with patch.object(fleet, "HOME", str(home / ".fleet")), \
                patch.object(fleet, "http", side_effect=AssertionError("a helper with its key registers nothing")):
            self.assertEqual(fleet.load_agent_key("nova"), key)
            self.assertTrue(fleet.enroll_key("nova"))
        self.assertEqual([p.name for p in (home / ".fleet").glob("agent-*")], ["agent-nova.key"])
        self.assertEqual(oct((home / ".fleet" / "agent-nova.key").stat().st_mode & 0o777), "0o600")
        headers = {"Content-Type": "application/json", "X-Fleet-Client": "test", "Authorization": "Bearer " + key}
        for path, body in (("/events/nova?after=-1&wait=0", None),
                           ("/helper/session/nova", {"kind": "chat", "generation": "test-generation"})):
            status, answer = self.request(path, body, headers=headers, source=NEW)
            self.assertEqual(status, 200, answer)
        self.assertEqual(self.request("/helper/key/nova", {"sha256": sha("a key of its own")}, source=NEW),
                         (409, {"error": "this machine has several agents: the owner registers their keys"}))
        self.assertEqual(hub.q1("SELECT sha256 FROM agent_keys WHERE agent='nova'")["sha256"], sha(key))

    def test_on_a_shared_mac_the_key_keeps_the_agent_in_the_hub(self):
        """30 October 2026: an agent renamed on a Mac that runs five agents under one OS user. Its job ended done and
        the agent stayed out, with "agent key not registered (409)" in its log, until a key was registered by hand."""
        self.join_by_script(self.code()["code"])
        svc = self.service(platform="darwin", answers={"launchctl print": (1, "", "not loaded")})
        self.installed_agent(svc, "claude")
        key = self.shared_key(self.home)
        status, receipt = self.owner("/ui/team/agents/scout/rename", base_sha256=self.team_sha(), name="nova")
        self.assertEqual(status, 200, receipt)
        svc.loop(rounds=1)
        self.assertEqual(self.servers()[1]["mini"]["job"]["state"], "done")
        self.helper_is_back(self.home, key)

    def test_on_a_shared_linux_server_the_key_moves_in_the_home_of_the_kept_user(self):
        self.join_by_script(self.code("mini", "linux")["code"], kind="linux")
        svc = self.service()
        self.installed_agent(svc, "codex")
        home = self.homes / "fleet-scout"
        key = self.shared_key(home)
        status, receipt = self.owner("/ui/team/agents/scout/rename", base_sha256=self.team_sha(), name="nova")
        self.assertEqual(status, 200, receipt)
        svc.loop(rounds=1)
        self.assertEqual(self.servers()[1]["mini"]["job"]["state"], "done")
        self.helper_is_back(home, key)
        ran, moved = self.ran(), f"mv -f {home}/.fleet/agent-scout.key {home}/.fleet/agent-nova.key"
        self.assertLess(ran.index("tmux kill-session -t =fleet-scout:"), ran.index(moved))    # the old helper has stopped
        self.assertLess(ran.index(moved), ran.index("fleet.py service nova"))               # the new one has its key
        self.assertEqual({user for _argv, _cwd, user in self.commands}, {"fleet-scout"})

    def test_a_key_that_does_not_move_fails_the_job_and_the_second_try_ends_it(self):
        self.join_by_script(self.code("mini", "linux")["code"], kind="linux")
        svc = self.service()
        self.installed_agent(svc, "codex")
        home = self.homes / "fleet-scout"
        key = self.shared_key(home)
        (home / ".fleet").chmod(0o500)
        self.addCleanup((home / ".fleet").chmod, 0o700)
        status, receipt = self.owner("/ui/team/agents/scout/rename", base_sha256=self.team_sha(), name="nova")
        self.assertEqual(status, 200, receipt)
        svc.loop(rounds=1)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["state"], shown["step"], shown["detail"]),
                         ("failed", "service", "The key of Nova could not take its new name. Try again."))
        self.assertNotIn("fleet.py service nova", self.ran())       # never a helper without its key
        (home / ".fleet").chmod(0o700)
        self.assertEqual(self.add_agent(agent="nova", runtime="codex")[0], 200)
        svc.loop(rounds=1)
        self.assertEqual(self.servers()[1]["mini"]["job"]["state"], "done")
        self.helper_is_back(home, key)

    def test_on_linux_the_agent_keeps_its_user_its_runtime_and_its_sign_in(self):
        self.join_by_script(self.code("mini", "linux")["code"], kind="linux")
        svc = self.service()
        receipt = self.renamed(svc, "codex")
        made = dict(self.made)
        svc.loop(rounds=1)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["id"], shown["kind"], shown["state"], shown["step"]),
                         (receipt["job"], "rename", "done", "service"), shown)
        self.assertEqual(self.made, made, "no new OS user, so no new runtime and no new sign-in")
        home = self.homes / "fleet-scout"
        self.assertFalse((home / "fleet-scout").exists())
        self.assertEqual((home / "fleet-nova" / ".git" / "fleet-server").read_text(), "nova\n")
        self.assertIn("nova", json.loads((home / "fleet-nova" / "team.json").read_text())["agents"])
        self.assertEqual(self.ran(), [
            f"mv {home}/fleet-scout {home}/fleet-nova",
            "systemctl --user disable --now fleet-scout.service", "systemctl --user is-active fleet-scout.service",
            f"rm -f {home}/.config/systemd/user/fleet-scout.service", "systemctl --user daemon-reload",
            "tmux kill-session -t =fleet-scout:",
            # the key that its install made in its home takes the new name (carry_key)
            f"mv -f {home}/.fleet/agent-scout.key {home}/.fleet/agent-nova.key",
            "-c import worker_install; print(worker_install.trust_codex_checkout())", "fleet.py service nova",
            "systemctl --user enable --now fleet-nova.service"])
        self.assertEqual({user for _argv, _cwd, user in self.commands}, {"fleet-scout"})
        self.assertEqual(self.count("signin_jobs"), 0)
        svc.loop(rounds=1)                                  # nothing more to do
        self.assertEqual(len(self.commands), 10)

    def test_on_a_mac_the_checkout_and_the_launch_agent_move(self):
        self.join_by_script(self.code()["code"])
        svc = self.service(platform="darwin", answers={"launchctl print": (1, "", "not loaded")})
        self.renamed(svc, "claude")
        svc.loop(rounds=1)
        self.assertEqual(self.servers()[1]["mini"]["job"]["state"], "done")
        self.assertFalse((self.home / "fleet-scout").exists())
        self.assertEqual((self.home / "fleet-nova" / ".git" / "fleet-server").read_text(), "nova\n")
        uid = __import__("os").getuid()
        self.assertEqual(self.ran(), [
            f"mv {self.home}/fleet-scout {self.home}/fleet-nova", f"launchctl bootout gui/{uid}/com.agentfleet.scout",
            f"rm -f {self.home}/Library/LaunchAgents/com.agentfleet.scout.plist",
            f"launchctl print gui/{uid}/com.agentfleet.scout", "tmux kill-session -t =fleet-scout:",
            f"mv -f {self.home}/.fleet/agent-scout.key {self.home}/.fleet/agent-nova.key",
            "fleet.py service nova", f"launchctl print gui/{uid}/com.agentfleet.nova",
            f"launchctl bootstrap gui/{uid} {self.home}/Library/LaunchAgents/com.agentfleet.nova.plist"])
        self.assertNotIn("user", self.origin_team()["agents"]["nova"])

    def test_a_service_that_does_not_stop_fails_the_job_and_the_second_try_ends_it(self):
        self.join_by_script(self.code("mini", "linux")["code"], kind="linux")
        answers = {"systemctl --user is-active fleet-scout.service": (0, "active\n", "")}
        svc = self.service(answers=answers)
        self.renamed(svc, "codex")
        svc.loop(rounds=1)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["state"], shown["step"]), ("failed", "service"))
        self.assertIn("The service of Scout did not stop.", shown["detail"])
        self.assertNotIn("fleet.py service nova", self.ran())
        answers.clear()
        self.assertEqual(self.add_agent(agent="nova", runtime="codex")[0], 200)
        svc.loop(rounds=1)
        self.assertEqual(self.servers()[1]["mini"]["job"]["state"], "done")
        self.assertEqual(self.ran().count("fleet.py service nova"), 1)
        self.assertEqual(self.ran().count(f"mv {self.homes}/fleet-scout/fleet-scout {self.homes}/fleet-scout/fleet-nova"), 1)

    def test_a_prepare_job_after_a_rename_works_in_the_kept_users_home(self):
        self.join_by_script(self.code("mini", "linux")["code"], kind="linux")
        self.runtimes("codex")                              # Claude Code is installed by the prepare job
        svc = self.service()
        self.renamed(svc, "codex")
        svc.loop(rounds=1)
        self.commands.clear()
        code, answer = self.request("/ui/servers/mini/prepare", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                                 "agent": "nova", "runtime": "claude"}, source=OWNER)
        self.assertEqual(code, 200, answer)
        svc.loop(rounds=1)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["kind"], shown["state"]), ("prepare", "done"), shown)
        self.assertEqual({user for _argv, _cwd, user in self.commands}, {"fleet-scout"})
        self.assertNotIn("fleet-nova", self.made)


if __name__ == "__main__":
    unittest.main()

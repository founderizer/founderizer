"""The person access plan (~/dev/founderizer-plans/person-access-plan.md, version 5): a person's list on one agent
narrows every session that their words drive, and a narrowed conversation runs locked, on the agent's own account,
with the hub as its door for repositories. An in-process hub with a temporary database and git repository
(test_people's fixture, through test_contacts_v2's Base), and test_thread_door's in-memory GitHub as the door's far
side: no bridge, no platform, no model, no network and no live hub."""
import json
import unittest
from unittest.mock import patch

import fleet
import hub
import test_contacts_v2
import test_thread_door
from test_contacts_v2 import KIM, PAT
from test_release_turns import helper_reports

REPO, OTHER = "acme/crm", "acme/web"        # OTHER is test_thread_door's repository
ORIGINAL_THREAD_REQUEST = hub.thread_request      # the real one, which the Door class patches for most of its tests
KEY = "bws://11111111-2222-4333-8444-555555555555"         # an API key that the agent reads
LOGIN = "bws://66666666-7777-4888-9999-000000000000"       # a login that the agent's vault uses for it


def load_tests(loader, _tests, _pattern):
    """Only the tests of this file: the fixtures that it borrows carry their own."""
    suite = unittest.TestSuite()
    for cls in (Rule, Narrowed, Owner, Door):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Base(test_contacts_v2.Base):
    """test_contacts_v2's hub, where studio holds two repositories and two secrets, Pat is a peer of studio, and
    studio's helper knows narrowed conversations."""
    ready = True

    def setUp(self):
        super().setUp()
        studio = hub.TEAM["agents"]["studio"]
        studio["repos"] = {REPO: "write", OTHER: "write"}
        studio["secrets"] = {KEY: "read", LOGIN: "use"}
        if self.ready:
            helper_reports("studio", hub.CONVERSATION_TASKS, hub.NARROWED_THREADS)
        self.pat = self.person("Pat", "peer", PAT)

    def narrow(self, pid, grants, agent="studio"):
        """A list, as the owner's write keeps it."""
        hub.q("INSERT INTO person_scopes(person,agent,grants,updated) VALUES(?,?,?,?) ON CONFLICT(person,agent) DO "
              "UPDATE SET grants=excluded.grants", (pid, agent, json.dumps(grants), hub.now()))

    def row(self, pid):
        return hub.q1("SELECT * FROM people WHERE id=?", (pid,))

    def task_context(self, cid):
        t = self.conversation_task(cid)
        return ("test-generation", hub.tref(t["id"]), "1")


class Rule(Base):
    """The rule itself: what a list leaves, and when a narrowed pair waits."""
    ready = False

    def test_the_effective_access_is_the_lower_level_of_what_both_hold(self):
        grants = {f"repo:{REPO}": "deploy", f"secret:{KEY}": "use", f"secret:{LOGIN}": "read",
                  "repo:acme/none": "write", "tool:crm": "use", "gmail:a@b.com": "send", "repo:acme/web": "admin"}
        self.assertEqual(hub.scope_effective("studio", grants),
                         {"repos": {REPO: "write"}, "secrets": {KEY: "use", LOGIN: "use"}})
        self.assertEqual(hub.scope_effective("studio", {}), {"repos": {}, "secrets": {}})
        hub.TEAM["agents"]["studio"]["repos"]["acme/none"] = "read"
        self.assertEqual(hub.scope_effective("studio", {"repo:acme/none": "write"})["repos"], {"acme/none": "read"})

    def test_no_row_is_all_and_a_row_that_cannot_be_read_is_an_empty_list(self):
        self.assertIsNone(hub.person_scope(self.pat["id"], "studio"))
        hub.q("INSERT INTO person_scopes(person,agent,grants,updated) VALUES(?,?,?,?)",
              (self.pat["id"], "studio", "not json", hub.now()))
        self.assertEqual(hub.person_scope(self.pat["id"], "studio"), {})
        hub.q("UPDATE person_scopes SET grants='[1,2]' WHERE person=?", (self.pat["id"],))
        self.assertEqual(hub.person_scope(self.pat["id"], "studio"), {})

    def test_a_narrowed_pair_waits_for_its_helper_and_only_the_owner_reads_why(self):
        cid = self.says(PAT, "Hi")["conversation"]          # an ordinary conversation, before the list
        self.narrow(self.pat["id"], {f"repo:{REPO}": "write"})
        view = hub.person_agent_view("studio", self.row(self.pat["id"]))
        self.assertFalse(view["can_chat"])
        self.assertIn("helper is older", view["says"])
        self.assertEqual(view["scope"], [{"resource": f"repo:{REPO}", "title": REPO, "level": "write", "held": True}])
        self.assertEqual(hub.conversation_refusal("studio", self.row(self.pat["id"])),
                         f"{hub.agent_display('studio')} cannot chat now.")
        with self.assertRaises(hub.Refusal) as refused:
            hub.conversation_start("studio", cid)
        self.assertIn("waits", str(refused.exception))
        # the pair of another person, on All, is untouched
        self.assertIsNone(hub.conversation_refusal("studio", self.row(self.person("Kim", "manager", KIM,
                                                                                  app="discord")["id"])))

    def test_each_reason_of_a_wait(self):
        helper_reports("studio", hub.CONVERSATION_TASKS, hub.NARROWED_THREADS)
        self.assertIsNone(hub.scope_refusal("studio"))
        real = hub.setting
        with patch.object(hub, "setting", lambda name: "codex" if name == "conversations.closed_runtime" else real(name)):
            self.assertIn("cannot run a locked conversation", hub.scope_refusal("studio"))
        hub.TEAM["agents"]["studio"]["can"] = []          # Shell off: closed for everybody, not narrowed
        self.narrow(self.pat["id"], {f"repo:{REPO}": "write"})
        self.assertEqual(hub.conversation_mode(self.row(self.pat["id"]), "studio"), "closed")
        view = hub.person_agent_view("studio", self.row(self.pat["id"]))
        self.assertIsNotNone(view["scope"])                 # the list stays, so it can go back to All
        hub.TEAM["agents"]["studio"]["can"] = ["shell"]
        helper_reports("studio", hub.CONVERSATION_TASKS)
        self.assertIn("helper is older", hub.scope_refusal("studio"))
        self.assertIn("cannot run a locked conversation", hub.scope_refusal("vps"))     # a Codex agent

    def test_a_change_of_one_pair_ends_only_that_pairs_sessions(self):
        cid = self.says(PAT, "Hi")["conversation"]
        other = hub.ins("INSERT INTO conversations(person,agent,account,chat,state,created,last) VALUES(?,?,?,?,?,?,?)",
                        (self.pat["id"], "vps", "discord-vps", "c9", "open", hub.now(), hub.now()))
        for n, talk in enumerate((cid, other)):
            hub.q("INSERT INTO session_credentials(sha256,agent,kind,generation,task,created) VALUES(?,?,?,?,?,?)",
                  (f"{n:064x}", "studio" if talk == cid else "vps", "conversation", "test-generation", talk, hub.now()))
        with hub.LOCK, hub.transaction():
            self.assertEqual(hub.conversation_sessions_end(hub.now(), "the list changed", person=self.pat["id"],
                                                           agent="studio"), 1)
        live = {r["task"] for r in hub.q("SELECT task FROM session_credentials WHERE kind='conversation' AND "
                                         "revoked IS NULL")}
        self.assertEqual(live, {other})

    def test_a_removed_person_leaves_no_list(self):
        self.narrow(self.pat["id"], {f"repo:{REPO}": "write"})
        code, gone = self.change(self.pat["id"], delete=True)
        self.assertEqual((code, gone["deleted"]), (200, True), gone)
        self.assertEqual(hub.q("SELECT * FROM person_scopes"), [])


class Narrowed(Base):
    """A narrowed pair whose agent's helper knows the narrowed start: how it starts, what it holds, sees and reaches."""

    def setUp(self):
        super().setUp()
        self.narrow(self.pat["id"], {f"repo:{REPO}": "write", f"secret:{LOGIN}": "use"})
        self.kim = self.person("Kim", "manager", KIM, app="discord")

    def test_it_starts_locked_on_the_agents_own_runtime(self):
        cid = self.says(PAT, "Please fix the form of the CRM")["conversation"]
        mode = hub.conversation_modes("studio")[str(cid)]
        self.assertTrue(mode.startswith("narrowed:") and fleet.narrowed_mode(mode), mode)
        start = hub.conversation_start("studio", cid)
        self.assertEqual((start["closed"], start["mode"], start["tools"]), (True, mode, list(hub.SCOPE_TOOLS)))
        self.assertEqual((start["runtime"], start["version"]), (hub.setting("conversations.closed_runtime"),
                                                                 hub.setting("conversations.closed_version")))
        self.assertEqual(start["runtime"], hub.TEAM["agents"]["studio"]["runtime"])     # its own account
        self.assertEqual(start["prompt"], hub.NARROWED_RULES.format(agent="studio"))
        for word in ("Pat", f"C-{cid}", REPO):
            self.assertNotIn(word, start["prompt"])         # one text for every narrowed window: its cache holds it
        # the owner's rule of 11 November 2026: a request that needs more changes nothing, and nobody is sent to him
        self.assertIn("if a part of it does, change nothing", start["prompt"])
        self.assertIn("never write code that reads or sends a secret", start["prompt"])
        self.assertNotIn("ask the owner", start["prompt"])

    def test_a_new_list_changes_the_mode_and_the_helper_kills_the_old_window_mid_turn(self):
        cid = self.says(PAT, "Hi")["conversation"]
        before = hub.conversation_modes("studio")[str(cid)]
        hub.q("UPDATE person_scopes SET updated=updated+1 WHERE person=?", (self.pat["id"],))
        after = hub.conversation_modes("studio")[str(cid)]
        self.assertNotEqual(before, after)              # a list that becomes another list ends the old window too
        helper = fleet.Helper("studio", {"role": "worker", "runtime": "claude", "machine": "studio-host",
                                         "can": ["shell"]})
        killed = []
        helper.conversations, helper.conversation_modes = [cid], {str(cid): after}
        with patch.object(fleet, "tmux", lambda *a, **_k: killed.append(a)), \
                patch.object(helper, "look", lambda: [f"C-{cid}"]), \
                patch.object(helper, "conversation_kind", lambda window: before), \
                patch.object(helper, "working", lambda target: True):          # in the middle of a turn
            helper.retire_conversations()
        self.assertTrue(any(a[0] == "kill-window" for a in killed), killed)
        for mode, locked in (("narrowed", True), (after, True), ("tools", False), ("closed", False), (None, False),
                             ("narrowedx", False)):
            self.assertEqual(fleet.narrowed_mode(mode), locked, mode)

    def test_the_helper_runs_it_locked_with_the_narrowed_allow_list(self):
        self.assertEqual(fleet.NARROWED_TOOLS, hub.SCOPE_TOOLS)     # dontAsk refuses a mismatch in silence
        command = fleet.conversation_command("studio", hub.TEAM["agents"]["studio"], "test-generation", 7,
                                             "http://127.0.0.1:8765/mcp/studio/test-generation/conversation/7",
                                             "token", "the rules", mode="narrowed")
        self.assertIn("--tools ''", command)
        self.assertIn("--strict-mcp-config", command)
        for name in fleet.NARROWED_TOOLS:
            self.assertIn(f"mcp__fleet__{name}", command)
        self.assertNotIn("mcp__fleet__ask_team", command)
        for leak in ("GH_TOKEN", "FLEET_GIT_TOKENS", "FLEET_REPOS"):
            self.assertNotIn(leak, command)
        closed = fleet.conversation_command("studio", hub.TEAM["agents"]["studio"], "test-generation", 7,
                                            "http://127.0.0.1:8765/mcp/studio/test-generation/conversation/7",
                                            "token", "the rules")
        self.assertNotIn("mcp__fleet__repo_change", closed)

    def test_its_tasks_carry_the_person_and_have_the_allowlist_only(self):
        cid = self.says(PAT, "Please fix the form of the CRM")["conversation"]
        t = self.conversation_task(cid)
        self.assertEqual(t["scope_person"], self.pat["id"])
        for context in (self.context(cid), self.task_context(cid)):
            names = {x["name"] for x in hub.tools_for("studio", context)}
            self.assertLessEqual(names, set(hub.SCOPE_TOOLS))
            self.assertTrue(set(hub.REPO_CALLS) <= names)
        for cut in ("open_work", "message_contact", "message_agent", "keep_instruction", "set_target", "set_duty",
                    "save_trigger", "remember", "recall", "see_notes", "read_knowledge", "search_knowledge",
                    "write_notes", "write_knowledge", "report_up", "report_progress", "see_earlier_work",
                    "read_attachment", "list_my_tasks"):
            text, error = self.tool(cut, self.context(cid))
            self.assertTrue(error, cut)
            self.assertIn(f"no tool named {cut}", text)
        other = self.says(KIM, "Hello", account="discord-studio")["conversation"]
        names = {x["name"] for x in hub.tools_for("studio", self.context(other))}
        self.assertTrue({"open_work", "message_contact", "keep_instruction"} <= names)
        self.assertEqual(names & set(hub.REPO_CALLS), set())         # the door's calls are a narrowed thread's only
        self.assertIsNone(self.conversation_task(other)["scope_person"])

    def test_the_door_offers_only_what_the_list_allows(self):
        cid = self.says(PAT, "Hi")["conversation"]
        self.narrow(self.pat["id"], {f"repo:{REPO}": "read"})
        names = {x["name"] for x in hub.tools_for("studio", self.context(cid))}
        self.assertEqual(names & set(hub.REPO_CALLS), set(hub.REPO_CALLS) - {"repo_change", "repo_pull_request"})
        self.narrow(self.pat["id"], {f"secret:{LOGIN}": "use"})
        self.assertEqual({x["name"] for x in hub.tools_for("studio", self.context(cid))} & set(hub.REPO_CALLS), set())

    def test_its_brief_names_the_list_and_nothing_of_the_agents_memory(self):
        cid = self.says(PAT, "Please fix the form of the CRM")["conversation"]
        hub.conversation_start("studio", cid)
        text = self.ok("read_messages", self.context(cid))
        self.assertIn(hub.SCOPE_OUTSIDE, text)
        self.assertIn(f"repositories {REPO} (write)", text)
        self.assertIn(LOGIN, text)
        self.assertIn("This conversation opens no other task.", text)
        self.assertIn("change nothing for that request", text)
        for word in (OTHER, KEY, "open_work", "message_contact", "PEOPLE ON YOUR LIST", "Kim", "(rule 9)",
                     "ask the owner"):
            self.assertNotIn(word, text)
        self.assertIn("opens no other task", hub.conversation_instructions("studio", self.context(cid)))

    def test_a_task_that_an_earlier_session_began_brings_the_line_to_look_first(self):
        cid = self.says(PAT, "Please fix the form of the CRM")["conversation"]
        hub.q("UPDATE tasks SET state='working' WHERE id=?", (self.conversation_task(cid)["id"],))
        hub.conversation_start("studio", cid)
        self.assertIn("search_history", self.ok("read_messages", self.context(cid)))

    def test_a_login_outside_the_list_is_refused_for_its_tasks(self):
        t = self.conversation_task(self.says(PAT, "Hi")["conversation"])
        for confirm in (False, True):
            self.assertIn(hub.SCOPE_OUTSIDE, hub.login_refusal("studio", t, KEY, confirm=confirm))
            self.assertNotIn(hub.SCOPE_OUTSIDE, hub.login_refusal("studio", t, LOGIN, confirm=confirm) or "")
        self.assertIn(hub.SCOPE_STOP, hub.login_refusal("studio", t, KEY))
        self.assertNotIn("ask the owner", hub.login_refusal("studio", t, KEY))
        other = self.conversation_task(self.says(KIM, "Hello", account="discord-studio")["conversation"])
        self.assertNotIn(hub.SCOPE_OUTSIDE, hub.login_refusal("studio", other, KEY) or "")

    def test_history_keeps_a_narrowed_pairs_records_apart(self):
        mine = self.says(PAT, "the export of the zebra form fails")["conversation"]
        theirs = self.says(KIM, "deploy the giraffe shop", account="discord-studio")["conversation"]
        nothing = "Nothing in your history matches"
        self.assertNotIn(nothing, self.ok("search_history", self.context(mine), query="zebra"))
        self.assertIn(nothing, self.ok("search_history", self.context(mine), query="giraffe"))
        self.assertNotIn(nothing, self.ok("search_history", self.context(theirs), query="giraffe"))
        self.assertIn(nothing, self.ok("search_history", self.context(theirs), query="zebra"))
        ref = hub.q1("SELECT id FROM conversation_messages WHERE text LIKE '%zebra%'")["id"]
        self.assertIn("zebra", self.ok("read_history", self.context(mine), ref=f"CM-{ref}"))
        self.assertNotIn("zebra", self.ok("read_history", self.context(theirs), ref=f"CM-{ref}"))
        self.assertTrue(hub.history_found("studio", {"query": "zebra"}, True, 10)[0])
        self.assertTrue(hub.history_records("studio", f"CM-{ref}"))

    def test_no_session_waits_for_a_narrowed_persons_answer(self):
        theirs = self.says(KIM, "Hello", account="discord-studio")["conversation"]
        text, error = self.tool("message_contact", self.context(theirs), person="Pat", text="Is it fixed?", waits=True,
                                request_id="person-scope-wait-1")
        self.assertTrue(error)
        self.assertIn("narrowed", text)

    def test_its_daily_number_counts_and_old_work_says_nothing_in_it(self):
        self.assertIsNone(hub.person_daily(self.row(self.pat["id"]), "studio"))
        hub.q("UPDATE people SET daily=3 WHERE id=?", (self.pat["id"],))
        self.assertEqual(hub.person_daily(self.row(self.pat["id"]), "studio"), 3)
        self.assertIsNone(hub.person_daily(self.row(self.kim["id"]), "studio"))
        cid = self.says(PAT, "Hi")["conversation"]
        work = hub.ins("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,created,attempt,"
                       "source_conversation,what) VALUES('Old work','x','done','none','studio','manager','completed',"
                       "?,1,?,'done')", (hub.now(), cid))
        before = hub.q1("SELECT COUNT(*) n FROM conversation_messages WHERE conversation=?", (cid,))["n"]
        hub.conversation_result(work)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM conversation_messages WHERE conversation=?", (cid,))["n"], before)

    def test_a_locked_window_never_holds_a_release(self):
        cid = self.says(PAT, "Hi")["conversation"]
        t = self.conversation_task(cid)
        hub.q("UPDATE agents SET last_seen=?, alive=?, alive_ts=? WHERE name='studio'",
              (hub.now(), f"C-{cid}", hub.now()))
        self.assertNotIn(t["id"], hub.running_turns("studio"))


class Owner(Base):
    """The owner's write and read of a list (POST and GET /ui/people), and what a change does."""

    def scopes(self, grants, agent="studio"):
        return self.change(self.pat["id"], scopes={agent: grants})

    def test_the_write_refuses_only_what_is_never_valid(self):
        for grants, words in (({"tool:crm": "use"}, "repositories (repo:) and secrets"),
                              ({"repo:acme/none": "read"}, "does not hold it"),
                              ({f"repo:{REPO}": "deploy"}, "never deploy"),
                              ({f"secret:{LOGIN}": "read"}, "at most use")):
            code, data = self.scopes(grants)
            self.assertEqual(code, 400, grants)
            self.assertIn(words, data["error"])
        code, data = self.scopes({f"repo:{REPO}": "write"}, agent="vps")      # not on Pat's list
        self.assertEqual(code, 400, data)
        self.assertEqual(hub.q("SELECT * FROM person_scopes"), [])

    def test_a_list_is_written_read_and_set_back_to_all(self):
        code, data = self.scopes({f"repo:{REPO}": "read", f"secret:{LOGIN}": "use"})
        self.assertEqual(code, 200, data)
        self.assertEqual(hub.person_scope(self.pat["id"], "studio"), {f"repo:{REPO}": "read", f"secret:{LOGIN}": "use"})
        agent = next(a for a in data["person"]["agents"] if a["agent"] == "studio")
        self.assertEqual([x["resource"] for x in agent["scope"]], [f"repo:{REPO}", f"secret:{LOGIN}"])
        self.assertIn("person_scope", hub.UI_FEATURES)
        code, data = self.scopes(None)
        self.assertEqual(code, 200, data)
        self.assertIsNone(hub.person_scope(self.pat["id"], "studio"))
        agent = next(a for a in data["person"]["agents"] if a["agent"] == "studio")
        self.assertIsNone(agent["scope"])

    def test_an_unchanged_list_changes_nothing(self):
        cid = self.says(PAT, "Hi")["conversation"]
        self.assertEqual(self.scopes({f"repo:{REPO}": "write"})[0], 200)
        mode = hub.conversation_modes("studio")[str(cid)]
        hub.q("INSERT INTO session_credentials(sha256,agent,kind,generation,task,created) VALUES(?,?,?,?,?,?)",
              ("b" * 64, "studio", "conversation", "test-generation", cid, hub.now()))
        self.assertEqual(self.scopes({f"repo:{REPO}": "write"})[0], 200)
        self.assertEqual(hub.conversation_modes("studio")[str(cid)], mode)     # its window keeps running
        self.assertIsNone(hub.q1("SELECT revoked FROM session_credentials WHERE sha256=?", ("b" * 64,))["revoked"])

    def test_a_first_list_ends_old_work_and_back_to_all_widens_the_open_task(self):
        cid = self.says(PAT, "Hi")["conversation"]
        hub.q("INSERT INTO session_credentials(sha256,agent,kind,generation,task,created) VALUES(?,?,?,?,?,?)",
              ("a" * 64, "studio", "conversation", "test-generation", cid, hub.now()))
        work = hub.ins("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,created,attempt,"
                       "source_conversation) VALUES('Old work','x','done','none','studio','manager','working',?,1,?)",
                       (hub.now(), cid))
        hub.THREAD_TOKENS[(cid, REPO, "write")] = ("kept", hub.time.time() + 600)
        self.assertEqual(self.scopes({f"repo:{REPO}": "write"})[0], 200)
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (work,))["state"], "canceled")
        self.assertIsNotNone(hub.q1("SELECT revoked FROM session_credentials WHERE sha256=?", ("a" * 64,))["revoked"])
        self.assertNotIn((cid, REPO, "write"), hub.THREAD_TOKENS)
        open_task = self.conversation_task(cid)
        hub.q("UPDATE tasks SET scope_person=? WHERE id=?", (self.pat["id"], open_task["id"]))
        self.assertEqual(self.scopes(None)[0], 200)
        self.assertIsNone(hub.q1("SELECT scope_person FROM tasks WHERE id=?", (open_task["id"],))["scope_person"])


class Door(Base):
    """The door for threads: the hub's repository calls, against test_thread_door's in-memory GitHub."""

    def setUp(self):
        super().setUp()
        self.narrow(self.pat["id"], {f"repo:{OTHER}": "write", f"repo:{REPO}": "read"})
        self.github = test_thread_door.GitHub()
        self.minted = []

        def tokens(repos, agent=None):
            self.minted.append(dict(repos))
            return [{"token": "ghs_" + "x" * 36, "access": next(iter(repos.values())), "repos": list(repos)}], []
        for name, value in (("github_tokens", tokens), ("thread_request", lambda token: self.github.req)):
            p = patch.object(hub, name, value)
            p.start()
            self.addCleanup(p.stop)
        hub.THREAD_TOKENS.clear()
        self.addCleanup(hub.THREAD_TOKENS.clear)
        self.cid = self.says(PAT, "Please fix the readme")["conversation"]

    def test_a_read_and_a_change_go_through_one_kept_token_that_no_answer_holds(self):
        text = self.ok("repo_read", self.context(self.cid), repo=OTHER, path="README.md")
        self.assertIn("hello world", text)
        self.ok("repo_files", self.context(self.cid), repo=OTHER, path="src")
        branch = f"fleet/c{self.cid}/readme"
        said = self.ok("repo_change", self.context(self.cid), repo=OTHER, branch=branch, message="Fix the readme",
                       changes=[{"path": "README.md", "edit": {"old": "hello world", "new": "hello there"}}])
        self.assertNotIn("ghs_", said)
        self.assertEqual(self.minted, [{OTHER: "write"}])           # one token for the run of calls
        self.assertTrue(any(c[0] == "POST" and c[1].endswith("/git/refs") for c in self.github.calls))
        # the record keeps paths and sizes, never the text of a file
        record = hub.q1("SELECT args, detail FROM calls WHERE name='repo_change' ORDER BY id DESC LIMIT 1")
        self.assertNotIn("hello there", record["args"])
        self.assertIn("README.md", record["args"])
        self.assertLessEqual(len(hub.q1("SELECT detail FROM calls WHERE name='repo_read'")["detail"]),
                             hub.GOOGLE_CALL_KEEP)

    def test_the_real_request_function_carries_the_token_to_github_only(self):
        import http.server
        import threading as th
        github, seen = self.github, []

        class Served(http.server.BaseHTTPRequestHandler):
            def handle_one(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                seen.append(self.headers.get("Authorization"))
                status, data = github.req(self.command, self.path, body, self.headers.get("Accept"))
                raw = b"" if data is None else json.dumps(data).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            do_GET = do_POST = do_PATCH = handle_one

            def log_message(self, *_a):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Served)
        th.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        p = patch.dict(hub.CFG, {"github_api": f"http://127.0.0.1:{server.server_address[1]}"})
        p.start()
        self.addCleanup(p.stop)
        with patch.object(hub, "thread_request", ORIGINAL_THREAD_REQUEST):
            text = self.ok("repo_read", self.context(self.cid), repo=OTHER, path="README.md")
            said = self.ok("repo_change", self.context(self.cid), repo=OTHER, branch=f"fleet/c{self.cid}/real",
                           message="m", changes=[{"path": "notes.txt", "content": "new"}])
        self.assertIn("hello world", text)
        self.assertTrue(seen and all(s == "Bearer ghs_" + "x" * 36 for s in seen), seen)
        for answer in (text, said):
            self.assertNotIn("ghs_", answer)
        self.assertTrue(any(c[0] == "POST" and c[1].endswith("/git/refs") for c in github.calls))

    def test_outside_the_list_and_below_its_level_nothing_is_asked(self):
        text, error = self.tool("repo_read", self.context(self.cid), repo="acme/other", path="README.md")
        self.assertTrue(error)
        self.assertIn(hub.SCOPE_OUTSIDE, text)
        self.assertIn(hub.SCOPE_STOP, text)
        self.assertNotIn("ask the owner", text)
        text, error = self.tool("repo_change", self.context(self.cid), repo=REPO, branch=f"fleet/c{self.cid}/x",
                                message="m", changes=[{"path": "a.txt", "content": "a"}])
        self.assertTrue(error)
        self.assertIn("may only read", text)
        self.assertIn(hub.SCOPE_STOP, text)
        self.assertEqual(self.minted, [])

    def test_a_session_without_a_list_has_no_repository_call(self):
        kim = self.person("Kim", "manager", KIM, app="discord")
        other = self.says(KIM, "Hello", account="discord-studio")["conversation"]
        text, error = self.tool("repo_read", self.context(other), repo=OTHER, path="README.md")
        self.assertTrue(error)
        self.assertIn("no tool named repo_read", text)
        with self.assertRaises(hub.ToolError):
            hub.thread_call("studio", {"repo": OTHER}, "read")      # fails closed outside a narrowed session
        self.assertIsNotNone(kim)

    def test_the_last_check_reads_the_list_the_conversation_and_the_person(self):
        import thread_door
        t = self.conversation_task(self.cid)
        hub.CALL.context = ("test-generation", hub.tref(t["id"]), "1")
        self.addCleanup(setattr, hub.CALL, "context", None)
        hub.thread_recheck("studio", self.cid, OTHER)()          # write on the list: it passes
        self.narrow(self.pat["id"], {f"repo:{OTHER}": "read"})
        with self.assertRaises(thread_door.Refused):
            hub.thread_recheck("studio", self.cid, OTHER)()
        self.narrow(self.pat["id"], {f"repo:{OTHER}": "write"})
        hub.q("UPDATE people SET blocked=? WHERE id=?", (hub.now(), self.pat["id"]))
        with self.assertRaises(thread_door.Refused):
            hub.thread_recheck("studio", self.cid, OTHER)()

    def test_a_list_narrowed_during_a_change_writes_nothing(self):
        with patch.object(hub, "thread_recheck", lambda agent, cid, repo: lambda: (_ for _ in ()).throw(
                __import__("thread_door").Refused("narrowed now"))):
            text, error = self.tool("repo_change", self.context(self.cid), repo=OTHER, branch=f"fleet/c{self.cid}/y",
                                    message="m", changes=[{"path": "new.txt", "content": "new"}])
            self.assertTrue(error, text)
            self.assertTrue(any(c[0] == "POST" and c[1].endswith("/git/commits") for c in self.github.calls))
            self.assertFalse(any(c[1].endswith("/git/refs") or "/git/refs/heads/" in c[1] and c[0] == "PATCH"
                                 for c in self.github.calls))
            text, error = self.tool("repo_pull_request", self.context(self.cid), repo=OTHER,
                                    branch=f"fleet/c{self.cid}/y", title="t", body="b")
            self.assertTrue(error, text)
        self.assertFalse(any(c[0] == "POST" and c[1].endswith("/pulls") for c in self.github.calls))

    def test_a_days_commits_have_a_cap(self):
        t = self.conversation_task(self.cid)
        for _ in range(hub.THREAD_COMMITS_DAY):
            hub.q("INSERT INTO calls(ts,agent,task,attempt,name,args,ok) VALUES(?,?,?,1,'repo_change','{}',1)",
                  (hub.now(), "studio", t["id"]))
        text, error = self.tool("repo_change", self.context(self.cid), repo=OTHER, branch=f"fleet/c{self.cid}/z",
                                message="m", changes=[{"path": "a.txt", "content": "a"}])
        self.assertTrue(error)
        self.assertIn("commits today", text)


if __name__ == "__main__":
    unittest.main()

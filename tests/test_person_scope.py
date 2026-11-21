"""The person access plan (~/dev/founderizer-plans/person-access-plan.md, version 5): a person's list on one agent
narrows every session that their words drive, and a narrowed conversation runs locked, on the agent's own account,
with the hub as its door for repositories. An in-process hub with a temporary database and git repository
(test_people's fixture, through test_contacts_v2's Base), and test_thread_door's in-memory GitHub as the door's far
side: no bridge, no platform, no model, no network and no live hub."""
import json
import unittest
import uuid
from unittest.mock import patch

import fleet
from leftovers import scratch_home
import hub
import test_contacts_v2
import test_thread_door
from test_contacts_v2 import KIM, PAT
from test_release_turns import helper_reports

REPO, OTHER = "acme/crm", "acme/web"        # OTHER is test_thread_door's repository
ORIGINAL_THREAD_REQUEST = hub.thread_request      # the real one, which the Door class patches for most of its tests
KEY = "bws://11111111-2222-4333-8444-555555555555"         # an API key that the agent reads
LOGIN = "bws://66666666-7777-4888-9999-000000000000"       # a login that the agent's vault uses for it


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def load_tests(loader, _tests, _pattern):
    """Only the tests of this file: the fixtures that it borrows carry their own."""
    suite = unittest.TestSuite()
    for cls in (Rule, Narrowed, Owner, Settle, Door, Writers):
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

    def owner_does(self, cid, action):
        """The owner pauses a conversation, or lets it run again (POST /ui/conversations/<id>)."""
        body = dict(self.command(), action=action)
        body.pop("text", None)
        code, data = self.request(f"/ui/conversations/{cid}", body)
        self.assertEqual(code, 200, data)

    def answers(self, cid, cm, text):
        """The conversation's window starts, reads what is unread, and answers CM-<cm>."""
        hub.conversation_start("studio", cid)
        self.ok("read_messages", self.context(cid))
        return self.ok("reply", self.context(cid), text=text, in_reply_to=f"CM-{cm}")

    def found(self, context, word):
        """Whether a session's search of its history finds `word`."""
        return "Nothing in your history matches" not in self.ok("search_history", context, query=word)


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

    def test_a_task_reads_only_what_a_session_with_more_wrote_to_a_narrowed_person(self):
        """Person access plan, section 5: a narrowed person's words, and the replies of their locked session, reach no
        session that holds more than their list. A task session's read of their conversation before it writes
        (conversation_since) gives only what a session with more wrote to them: here another task's message."""
        cid = self.says(PAT, "The giraffe key is in the drawer.")["conversation"]
        said = hub.q1("SELECT id FROM conversation_messages WHERE who='person' ORDER BY id DESC LIMIT 1")["id"]
        later = self.says(PAT, "And the zebra key is in the box.")["id"]        # one conversation task with the first
        hub.conversation_start("studio", cid)
        self.ok("read_messages", self.context(cid))
        self.ok("reply", self.context(cid), text="Noted: the giraffe drawer.", in_reply_to=f"CM-{said}")
        self.ok("reply", self.context(cid), text="Noted: the zebra box.", in_reply_to=f"CM-{later}")
        self.assertIsNone(hub.q1("SELECT task FROM conversation_messages WHERE text='Noted: the zebra box.'")["task"])
        # a message while the owner paused the conversation, and the reply to it: no task holds either, only the mark
        self.owner_does(cid, "pause")
        paused = self.says(PAT, "The okapi code is under the mat.")["id"]
        self.owner_does(cid, "resume")
        self.answers(cid, paused, "Noted: the okapi mat.")
        self.assertEqual([r["task"] for r in hub.q("SELECT task FROM conversation_messages WHERE text LIKE '%okapi%'")],
                         [None, None])
        _, first = self.normal_task(title="Ask about the deploy")
        self.ok("message_contact", first, person="Pat", text="Is the deploy done?",
                request_id=str(uuid.uuid4()))           # nothing in it that this session may read: it goes
        _, second = self.normal_task(title="Ask about the keys")
        text = self.reads(second, "Pat")
        self.assertEqual([json.loads(line) for line in text.splitlines() if line.startswith('"')],
                         ["Is the deploy done?"])
        self.assertNotIn("giraffe", text)
        self.assertNotIn("okapi", text)
        # and after the owner widened their access: what was said while it was narrowed stays with that pair
        code, data = self.change(self.pat["id"], scopes={"studio": None})
        self.assertEqual(code, 200, data)
        _, third = self.normal_task(title="Ask about the doors")
        text = self.reads(third, "Pat")
        for word in ("giraffe", "zebra", "okapi"):      # zebra: a reply with no task; okapi: a message in a pause
            self.assertNotIn(word, text)
        # nor does the brief of the conversation's next session, which holds more than that list now
        hub.conversation_start("studio", cid)
        brief = self.ok("read_messages", self.context(cid))
        self.assertIn("Is the deploy done?", brief)
        for word in ("giraffe", "zebra", "okapi"):
            self.assertNotIn(word, brief)

    def test_a_wider_window_names_no_message_or_file_of_the_narrowed_time_by_its_number(self):
        """Person access plan, section 5 (person-scope-row-mark-spec.md, test 5): after the owner widened a person's
        access, the conversation's window holds the agent's tools again, and could name a message or a file of the
        narrowed time by its number: open_work and ask_team pass a message's words on to a task, and read_attachment
        opens a file. Each refuses a row that carries the pair's mark, as each read of the conversation leaves it out.
        The bug: a read by id with no rule."""
        code, up = self.bridge_upload(test_contacts_v2.test_people.test_chat_apps.PICTURE, "m-narrow",
                                      account="whatsapp-studio", sender=PAT)
        self.assertEqual(code, 200, up)
        self.assertEqual(self.wrote(text="The tapir form.", kind="image", id="m-narrow", account="whatsapp-studio",
                                    sender=PAT), "stored")
        said = hub.q1("SELECT id, conversation FROM conversation_messages WHERE msg_id='m-narrow'")
        cid = said["conversation"]
        self.answers(cid, said["id"], "Noted: the tapir form.")        # answered, so the widening keeps its mark
        code, data = self.change(self.pat["id"], scopes={"studio": None})
        self.assertEqual(code, 200, data)
        hub.conversation_start("studio", cid)
        self.ok("read_messages", self.context(cid))
        self.ok("open_work", self.context(cid), title="Rebuild the October export", details="All of October.")
        work = hub.q1("SELECT * FROM tasks WHERE title='Rebuild the October export'")
        text, error = self.tool("open_work", self.context(cid), task=hub.tref(work["id"]), messages=[f"CM-{said['id']}"])
        self.assertTrue(error, text)
        self.assertIsNone(hub.q1("SELECT 1 FROM events WHERE kind='say' AND task=? AND text LIKE '%tapir%'",
                                 (work["id"],)))
        text, error = self.tool("read_attachment", self.context(cid), attachment_id=f"A-{up['id']}")
        self.assertTrue(error, text)
        self.assertIn("is not a file that Pat sent in this conversation", text)
        # reply tells nothing of the locked window's answer: the same refusal as for a message that it never read
        for words in ("Noted: the tapir form.", "Another answer."):
            text, error = self.tool("reply", self.context(cid), text=words, in_reply_to=f"CM-{said['id']}")
            self.assertTrue(error, text)
            self.assertIn("must be a message of this conversation that you read", text)
        # nor of its answer to a message from before the list (the settle marks such a message only at the next start)
        hub.q("UPDATE conversation_messages SET scope_person=NULL WHERE id=?", (said["id"],))
        for words in ("Noted: the tapir form.", "Another answer."):
            text, error = self.tool("reply", self.context(cid), text=words, in_reply_to=f"CM-{said['id']}")
            self.assertTrue(error, text)
            self.assertIn("must be a message of this conversation that you read", text)
        # and the start of work that follows the locked window's task would carry its result
        narrowed = hub.q1("SELECT id FROM tasks WHERE source_conversation=? AND scope_person IS NOT NULL", (cid,))
        text, error = self.tool("open_work", self.context(cid), title="Check the tapir form again", details="Again.",
                                follows=hub.tref(narrowed["id"]))
        self.assertTrue(error, text)
        # a closed conversation (a customer's): ask_team passes the named words on to a task in the same way
        ana = self.person("Ana", "customer", test_contacts_v2.ANA)
        self.narrow(ana["id"], {})
        closed = self.says(test_contacts_v2.ANA, "The quokka refund is for order 7.")
        self.answers(closed["conversation"], closed["id"], "Noted: the quokka refund.")
        code, data = self.change(ana["id"], scopes={"studio": None})
        self.assertEqual(code, 200, data)
        hub.conversation_start("studio", closed["conversation"])
        self.ok("read_messages", self.context(closed["conversation"]))
        text, error = self.tool("ask_team", self.context(closed["conversation"]), question="Can you check it?",
                                messages=[f"CM-{closed['id']}"])
        self.assertTrue(error, text)
        self.assertIsNone(hub.q1("SELECT 1 FROM events WHERE kind='say' AND text LIKE '%quokka%'"))      # where it would go

    def finished_pair(self):
        """A narrowed pair's finished conversation task, whose result holds the locked window's reply (the fault
        that the Chat area found in conversation_task_end), and a finished task of the agent's own beside it."""
        cid = self.says(PAT, "The giraffe key is in the drawer.")["conversation"]
        narrowed = self.conversation_task(cid)["id"]
        hub.q("UPDATE tasks SET state='completed', what='Noted: the giraffe drawer.', delivered=? WHERE id=?",
              (hub.now(), narrowed))
        plain, _ = self.normal_task(title="Send the zebra report")
        hub.q("UPDATE tasks SET state='completed', what='The zebra report went out.', delivered=? WHERE id=?",
              (hub.now(), plain))
        return narrowed, plain

    def test_a_narrowed_pairs_task_is_no_earlier_work_of_any_other_session(self):
        """Person access plan, sections 13 and 16 item 9: a session with more reads nothing of a narrowed pair's task
        in see_earlier_work, by no count and no title: not in its own finished work (mine, outcome), its search, its
        full read, the chain that its task follows, or the line of what followed a task. Its other work stays."""
        narrowed, plain = self.finished_pair()
        mine, context = self.normal_task(title="Prepare the next report")
        hub.q("UPDATE tasks SET follows=? WHERE id=?", (narrowed, mine))      # as an old link would hold it
        for args in ({"mine": True}, {"search": "giraffe"}, {"outcome": "completed"}, {}):
            text = self.ok("see_earlier_work", context, task_id=hub.tref(mine), **args)
            self.assertNotIn("drawer", text, args)        # its result's words (a search says the word it looked for)
            self.assertNotIn(hub.tref(narrowed), text, args)
        self.assertIn(f"{hub.tref(mine)} follows no earlier task", self.ok("see_earlier_work", context,
                                                                          task_id=hub.tref(mine)))
        text, error = self.tool("see_earlier_work", context, task_id=hub.tref(mine), task=hub.tref(narrowed))
        self.assertTrue(error)
        self.assertNotIn("drawer", text)
        self.assertIn("is neither a task that", text)       # the words of a task that does not exist
        listed = self.ok("list_my_tasks", context, task_id=hub.tref(mine))      # its own task, and what it follows
        self.assertNotIn("drawer", listed)
        self.assertNotIn(hub.tref(narrowed), listed)
        hub.q("UPDATE tasks SET follows=? WHERE id=?", (plain, narrowed))     # it followed the agent's own task
        behind = self.ok("see_earlier_work", context, task_id=hub.tref(mine))
        self.assertIn(f"{hub.tref(mine)} follows 1 earlier task(s)", behind)    # the walk goes on behind it
        self.assertIn(hub.tref(plain), behind)
        own = self.ok("see_earlier_work", context, task_id=hub.tref(mine), mine=True)
        self.assertIn("The zebra report went out.", own)
        self.assertNotIn(hub.tref(narrowed), own)          # and is not in that task's "Followed by"
        # the manager's see_team names it nowhere, nor a permission prompt of it; the owner's own overview reads it
        hub.ins("INSERT INTO prompts(task,agent,tool,input,key,created) VALUES(?,'studio','Bash','cat drawer','k',?)",
                (narrowed, hub.now()))
        team = hub.t_see_team("manager", {})
        self.assertNotIn(hub.tref(narrowed), team)
        self.assertNotIn("drawer", team)
        self.assertIn(hub.tref(narrowed), hub.overview_text(hub.OWNER_VIEW))

    def test_a_leads_view_of_its_team_names_no_narrowed_pairs_task(self):
        """Person access plan v4 (a lead's team view): a narrowed pair's conversation task has the agent's lead for its
        requester (task_giver), so see_team listed it under what the lead gave out, with the first words of the
        locked window's reply. It is no row there now; the lead's other work stays."""
        narrowed, plain = self.finished_pair()
        hub.TEAM["agents"]["boss"] = {"role": "lead", "runtime": "claude", "machine": "studio-host", "can": ["shell"]}
        hub.TEAM["agents"]["studio"]["reports_to"] = "boss"
        hub.q("UPDATE tasks SET requester='boss' WHERE id IN (?,?)", (narrowed, plain))
        _, context = self.normal_task(owner="boss", title="Lead the team")
        view = self.ok("see_team", context, agent="boss")
        self.assertIn(hub.tref(plain), view)
        self.assertNotIn(hub.tref(narrowed), view)
        self.assertNotIn("drawer", view)

    def test_a_narrowed_pairs_task_answers_its_requesters_controls_as_no_task(self):
        """The Opus review of the fix: check_result, restart_task and cancel_task of a narrowed pair's conversation
        task wrote on it for its requester (the manager here), and their refusal said to anyone else that it exists.
        Each one now answers as for a task that does not exist; a task of the agent's own is checked as before."""
        narrowed, plain = self.finished_pair()
        hub.q("UPDATE tasks SET requester='manager' WHERE id IN (?,?)", (narrowed, plain))
        for tool, args in (("check_result", {"accepted": True}), ("restart_task", {"reason": "again", "request_id": str(uuid.uuid4()),
                                                                     "expected_attempt": 1}),
                           ("cancel_task", {"reason": "done"})):
            with self.assertRaises(hub.ToolError, msg=tool) as refused:
                getattr(hub, f"t_{tool}")("manager", dict(args, task_id=hub.tref(narrowed)))
            self.assertEqual(str(refused.exception), f"There is no task {hub.tref(narrowed)}.", tool)
        self.assertIsNone(hub.q1("SELECT accepted FROM tasks WHERE id=?", (narrowed,))["accepted"])
        hub.t_check_result("manager", {"task_id": hub.tref(plain), "accepted": True})
        self.assertEqual(hub.q1("SELECT accepted FROM tasks WHERE id=?", (plain,))["accepted"], 1)

    def test_no_new_task_follows_a_narrowed_pairs_task_or_starts_with_its_words(self):
        """Person access plan, sections 13 and 16 item 9: create_task's follows of a narrowed pair's task is refused
        with the words of a task that does not exist, and a task that follows one (an old link) starts with nothing of
        it; a task that follows the agent's own work starts with that work's result, as before."""
        narrowed, plain = self.finished_pair()
        with self.assertRaises(hub.ToolError) as refused:
            hub.t_create_task("manager", {"owner": "studio", "title": "Go on with it", "done_when": "done",
                                          "follows": hub.tref(narrowed)})
        self.assertIn(f"There is no task {hub.tref(narrowed)} to follow.", str(refused.exception))
        # nor open_work of a conversation with the agent's own tools: the words of a task that is not the agent's
        other = self.says(KIM, "Hello", account="discord-studio")["conversation"]
        text, error = self.tool("open_work", self.context(other), title="Go on with it", details="The next step.",
                                follows=hub.tref(narrowed))
        self.assertTrue(error)
        self.assertIn(f"{hub.tref(narrowed)} is not a finished task of yours.", text)
        self.assertNotIn("drawer", text)
        mine, _ = self.normal_task(title="Prepare the next report")
        hub.q("UPDATE tasks SET follows=? WHERE id=?", (narrowed, mine))
        self.assertNotIn("drawer", hub.start_text("studio", mine))
        hub.q("UPDATE tasks SET follows=? WHERE id=?", (plain, mine))
        self.assertIn("The zebra report went out.", hub.start_text("studio", mine))

    def test_its_window_opens_its_persons_own_files_only(self):
        """CHAT-APPS.md 8.1: a narrowed window opens the files of its own person's messages (read_attachment is in
        SCOPE_TOOLS), and a file of the owner's never."""
        code, up = self.bridge_upload(test_contacts_v2.test_people.test_chat_apps.PICTURE, "m-scope",
                               account="whatsapp-studio", sender=PAT)
        self.assertEqual(code, 200, up)
        self.assertEqual(self.wrote(text="The form.", kind="image", id="m-scope", account="whatsapp-studio",
                                    sender=PAT), "stored")
        cid = hub.q1("SELECT conversation FROM conversation_messages WHERE msg_id='m-scope'")["conversation"]
        self.assertIn("The picture follows", self.ok("read_attachment", self.context(cid), attachment_id=f"A-{up['id']}"))
        owners = hub.ins("INSERT INTO attachments(request_id,name,mime,size,sha256,created,client,message) "
                         "VALUES('r-owner','plan.png','image/png',64,?,?,'deterministic-test','u-1')",
                         (up["id"] and hub.q1("SELECT sha256 FROM attachments WHERE id=?", (up["id"],))["sha256"],
                          hub.now()))
        text, error = self.tool("read_attachment", self.context(cid), attachment_id=f"A-{owners}")
        self.assertTrue(error)
        self.assertIn("is not a file that Pat sent in this conversation", text)

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

    def test_a_narrowed_pairs_message_keeps_no_item_and_its_task_hears_of_none(self):
        """person-scope-row-mark-spec.md: the row mark is the one rule of each read, and standing items are one. Bugs:
        standing_source read a person's message by its id alone, so a session with more than the narrowed person's
        list kept a lasting wish in words that only the locked window may read; and standing_news_rows gave the pair's
        own task the words of each new item of the agent, which that task's start leaves out (start_text)."""
        cid = self.says(PAT, "From now on put the giraffe links in every reply.")["conversation"]
        cm = hub.q1("SELECT id, scope_person FROM conversation_messages WHERE who='person' ORDER BY id DESC LIMIT 1")
        self.assertEqual(cm["scope_person"], self.pat["id"])          # the row carries the narrowed person's mark
        tid, task = self.normal_task(title="Look for the links")
        text, error = hub.call_tool("studio", "keep_instruction", {"words": "put the giraffe links in every reply",
                                                                  "scope": "agent", "source": f"CM-{cm['id']}",
                                                                  "task_id": task[1]}, task)
        self.assertTrue(error, text)
        self.assertIn(f"CM-{cm['id']} is no message of a person's in your own conversation", text)
        self.assertIsNone(hub.q1("SELECT 1 FROM standing"))
        pair = self.conversation_task(cid)
        self.assertEqual(pair["scope_person"], self.pat["id"])
        hub.q("UPDATE tasks SET source_message=NULL WHERE id=?", (pair["id"],))    # as a task that the pair opened
        text, error = hub.call_tool("studio", "keep_instruction", {"words": "Answer within the day.", "scope": "agent",
                                                                  "task_id": task[1]}, task)
        self.assertFalse(error, text)
        news = [r["task"] for r in hub.q("SELECT task FROM events WHERE agent='studio' AND kind='say' AND text LIKE "
                                         "'%New standing item%'")]
        self.assertNotIn(pair["id"], news)

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
                    "list_my_tasks"):           # read_attachment opens the person's own files (CHAT-APPS.md 8.1)
            text, error = self.tool(cut, self.context(cid))
            self.assertTrue(error, cut)
            self.assertIn(f"no tool named {cut}", text)
        other = self.says(KIM, "Hello", account="discord-studio")["conversation"]
        names = {x["name"] for x in hub.tools_for("studio", self.context(other))}
        self.assertTrue({"open_work", "message_contact", "keep_instruction"} <= names)
        # Its answers name only the tools that it holds: write_notes and remember, and no write_skill (the design "An
        # agent keeps its own rules", 5.4)
        self.assertIn("write_notes", names)
        self.assertNotIn("write_skill", names)
        text, error = self.tool("write_notes", self.context(other), request_id=str(uuid.uuid4()),
                                text="x" * (hub.NOTES_MAX + 1), why="what the work taught me")
        self.assertTrue(error, text)
        self.assertTrue(text.endswith("move a tested rule to remember, and keep one line that points to it."), text)
        # the owner's files are not for a session that a person drives, as his chats are not (17 November 2026): not
        # for the window, nor for the conversation's task that it runs. A task that the conversation opened reads a
        # steer's file of its own task only (owner API 1.223, test_contacts_v2). The window has the tool for its own
        # person's files only since 20 November 2026 (CHAT-APPS.md 8.1, conversation_attachment)
        task = {x["name"] for x in hub.tools_for("studio", self.task_context(other))}
        self.assertNotIn("read_attachment", task)
        self.assertIn("read_attachment", names)
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
        """Person access plan, section 5: a narrowed pair's records reach no session of the agent that holds more,
        while the pair is narrowed and after the owner widened it, and the owner reads them all. Each of their rows
        carries the person's mark (narrowed_mark), which history_scope_sql reads beside the task. The bug: the filter
        reads only the row's task, and two rows have none, the second reply to two messages that the window read
        together (only the first reply ends the conversation task), and a message that came while the owner had
        paused the conversation, with its reply."""
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
        # two messages read together and two replies: the second reply has no task of its own
        later = self.says(PAT, "and the walrus form too")["id"]
        hub.conversation_start("studio", mine)
        self.ok("read_messages", self.context(mine))
        self.ok("reply", self.context(mine), text="Fixing the zebra export.", in_reply_to=f"CM-{ref}")
        self.ok("reply", self.context(mine), text="And the narwhal check of the walrus form.",
                in_reply_to=f"CM-{later}")
        # a message while the owner paused the conversation, and the reply to it: neither has a task
        self.owner_does(mine, "pause")
        paused = self.says(PAT, "the okapi password is in the safe")["id"]
        self.owner_does(mine, "resume")
        self.answers(mine, paused, "Thanks for the okapi note.")
        self.assertEqual([r["task"] for r in hub.q("SELECT task FROM conversation_messages WHERE text LIKE "
                                                   "'%narwhal%' OR text LIKE '%okapi%'")], [None] * 3)
        _, task = self.normal_task(title="Look for the forms")
        for when in ("narrowed", "widened"):
            for context in (self.context(theirs), task):
                for word in ("narwhal", "okapi", "zebra", "walrus"):
                    self.assertFalse(self.found(context, word), (when, context, word))
            self.assertTrue(self.found(task, "giraffe"))
            if when == "narrowed":
                code, data = self.change(self.pat["id"], scopes={"studio": None})       # the owner widens it
                self.assertEqual(code, 200, data)
        self.assertTrue(hub.history_found(None, {"query": "okapi"}, True, 10)[0])          # the owner reads all

    def test_a_widening_gives_back_what_nobody_answered_and_nothing_else(self):
        """person-scope-row-mark-spec.md, section E: a list back to All gives back the narrowed person's messages that
        nobody answered, which wait for a reader: those of the open conversation task, an unread one with no task (it
        came in a pause), and an unread one whose task ended with no reply. Each reply, and each message that the
        locked window answered, keeps its mark. The bugs: the widening clears every mark, and a session with more
        finds the locked window's reply that had no task; or it clears none, and a session with the agent's tools
        never finds the message that waits for it; or it gives back an unread message only when it has no task; or the
        next start marks again the message of an ended task, which keeps its person; or the given-back message stays
        in that ended task, whose person hides it and its reply from the reads, and the next start marks them again."""
        cid = self.says(PAT, "The giraffe key is in the drawer.")["conversation"]
        first = hub.q1("SELECT id FROM conversation_messages WHERE who='person' ORDER BY id DESC LIMIT 1")["id"]
        later = self.says(PAT, "And the zebra key is in the box.")["id"]
        hub.conversation_start("studio", cid)
        self.ok("read_messages", self.context(cid))
        self.ok("reply", self.context(cid), text="Noted: the giraffe drawer.", in_reply_to=f"CM-{first}")
        self.ok("reply", self.context(cid), text="Noted: the zebra box.", in_reply_to=f"CM-{later}")
        lynx = self.says(PAT, "The lynx fence is down.")         # nobody read it, and its task ends with no reply
        hub.q("UPDATE tasks SET state='canceled' WHERE id=?", (lynx["task"],))
        self.says(PAT, "The tapir gate is open.")               # the next conversation task, which nobody read
        self.owner_does(cid, "pause")
        self.says(PAT, "The okapi door sticks.")                # no task, and nobody read it
        self.owner_does(cid, "resume")
        _, task = self.normal_task(title="Look for the gates")
        self.assertFalse(self.found(task, "lynx"))               # the history holds its row now, with its task
        code, data = self.change(self.pat["id"], scopes={"studio": None})
        self.assertEqual(code, 200, data)
        hub.settle_narrowed_rows()                              # the next start of the hub
        marks = {r["text"]: r["scope_person"] for r in hub.q(
            "SELECT text, scope_person FROM conversation_messages WHERE conversation=? AND who IN ('person','agent')",
            (cid,))}
        p = self.pat["id"]
        self.assertEqual(marks, {"The giraffe key is in the drawer.": p, "And the zebra key is in the box.": p,
                                 "Noted: the giraffe drawer.": p, "Noted: the zebra box.": p,
                                 "The lynx fence is down.": None, "The tapir gate is open.": None,
                                 "The okapi door sticks.": None})
        self.assertEqual([self.found(task, word) for word in ("tapir", "okapi", "zebra", "lynx")],
                         [True, True, False, True])            # lynx: its history row left the ended task too
        # the given-back message left its ended task: the window with the agent's tools reads it and answers it, and
        # neither the task conditions of the reads nor the next start take them away again
        self.assertIsNone(hub.q1("SELECT task FROM conversation_messages WHERE id=?", (lynx["id"],))["task"])
        hub.conversation_start("studio", cid)
        self.ok("read_messages", self.context(cid))
        self.ok("reply", self.context(cid), text="The lynx fence is fixed.", in_reply_to=f"CM-{lynx['id']}")
        reply = hub.q1("SELECT id FROM conversation_messages WHERE text='The lynx fence is fixed.'")["id"]
        hub.settle_narrowed_rows()
        shown = hub.q(f"SELECT id, scope_person FROM conversation_messages WHERE id IN (?,?) AND "
                      f"{hub.CONVERSATION_NOT_NARROWED}", (lynx["id"], reply))
        self.assertEqual(sorted((r["id"], r["scope_person"]) for r in shown), [(lynx["id"], None), (reply, None)])

    @unittest.expectedFailure       # the hole is late_permission_word's (lanes/fleet-awareness.md): its fix ends this
    def test_a_late_decision_on_a_narrowed_task_brings_no_words_of_its_decider(self):
        """The Chat area's privacy review: a decision that comes after a permission prompt of a narrowed task expired
        is written into that task (late_permission_word), and its locked window reads it. Its decider is the task's
        requester, a session with more than the list, so a line in that task says at most that a late decision came, with
        no reason. The bug: the decider's own words reach the narrowed window."""
        t = self.conversation_task(self.says(PAT, "Please fix the form of the CRM")["conversation"])
        prompt = hub.ins("INSERT INTO prompts(task,agent,tool,input,key,created,decision) VALUES(?,'studio','Bash',"
                         "'{}','k',?,'expired')", (t["id"], hub.now()))
        text, error = hub.call_tool("manager", "decide_permission", {"prompt_id": f"P-{prompt}", "decision": "allow",
                                                                    "reason": "the alpaca budget is approved"})
        self.assertTrue(error, text)            # a late decision decides nothing
        said = [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='studio' AND kind='say' AND task=?",
                                          (t["id"],))]
        self.assertFalse([line for line in said if "alpaca" in line], said)

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

    def test_an_answer_to_what_the_pairs_task_asked_before_a_first_list_does_not_come_into_it(self):
        """Person access plan, section 5: a task that a narrowed person's words drive reads no other person's or agent's
        words. The window asked Kim and the agent vps, each with waits, before the owner gave Pat a first list; their
        answers came after it. Each answer stays where it belongs (Kim's in her own conversation, vps's in studio's chat
        window), the waits end, and the task hears only that an answer came. The bug: the answer went into the waiting
        task (conversation_waiting_rows, agent_delivery), whose locked window then read it."""
        self.person("Kim", "manager", KIM, app="discord")
        cid = self.says(PAT, "Is order 7781 paid? Ask Kim.")["conversation"]
        hub.conversation_start("studio", cid)
        self.ok("read_messages", self.context(cid))
        self.ok("message_contact", self.context(cid), person="Kim", text="Is order 7781 paid?",
                request_id=str(uuid.uuid4()), waits=True)
        text, error = hub.call_tool("studio", "message_agent", {"agent": "vps", "text": "Is the 7781 refund deployed?",
                                                               "waits": True, "request_id": str(uuid.uuid4())},
                                    self.context(cid))
        self.assertFalse(error, text)
        asked = hub.q1("SELECT id FROM agent_messages WHERE sender='studio' ORDER BY id DESC LIMIT 1")["id"]
        task = self.conversation_task(cid)["id"]
        code, data = self.scopes({f"repo:{REPO}": "read"})          # the owner's first list for Pat
        self.assertEqual(code, 200, data)
        self.assertEqual(hub.task_scope(hub.q1("SELECT * FROM tasks WHERE id=?", (task,)))["person"], self.pat["id"])
        self.assertEqual(self.inbound(text="Order 7781 is paid, the wombat way.", account="discord-studio",
                                      sender=KIM, chat="dm-9")[0], "stored")
        vps_task, theirs = self.normal_task(owner="vps", title="Deploy the refunds")
        text, error = hub.call_tool("vps", "message_agent", {"agent": "studio", "text": "The quokka build of 7781 is "
                                                             "deployed.", "in_reply_to": f"AM-{asked}",
                                                             "request_id": str(uuid.uuid4())}, theirs)
        self.assertFalse(error, text)
        # a second answer to the same message: the wait is over already, so the task hears nothing more
        text, error = hub.call_tool("vps", "message_agent", {"agent": "studio", "text": "And the quokka logs are kept.",
                                                             "in_reply_to": f"AM-{asked}",
                                                             "request_id": str(uuid.uuid4())}, theirs)
        self.assertFalse(error, text)
        # and a new message of vps from a task that the pair's task requested (a link of plan C11) goes there neither:
        # that task is no link, so the one other link takes it, with no question which of two
        hub.q("UPDATE tasks SET requester='studio', parent=? WHERE id=?", (task, vps_task))
        mine, _ = self.normal_task(title="Check the refund log")
        hub.q("UPDATE tasks SET requester='vps', parent=? WHERE id=?", (vps_task, mine))    # vps's own subtask
        text, error = hub.call_tool("vps", "message_agent", {"agent": "studio", "text": "The numbat check passed.",
                                                             "request_id": str(uuid.uuid4())}, theirs)
        self.assertFalse(error, text)
        self.assertTrue(hub.q1("SELECT 1 FROM events WHERE task=? AND kind='say' AND text LIKE '%numbat%'", (mine,)))
        lines = [r["text"] for r in hub.q("SELECT text FROM events WHERE task=? AND kind='say'", (task,))]
        for word in ("wombat", "quokka", "numbat"):
            self.assertFalse([line for line in lines if word in line], (word, lines))
        self.assertEqual(sum(hub.NARROWED_ANSWER.split("{ref}")[1] in line for line in lines), 2, lines)
        self.assertIsNone(hub.q1("SELECT 1 FROM conversation_messages WHERE conversation=? AND waits IS NOT NULL",
                                 (hub.q1("SELECT conversation FROM conversation_messages WHERE text LIKE '%wombat%'")
                                  ["conversation"],)))
        said = hub.q1("SELECT event FROM conversation_messages WHERE text LIKE '%wombat%'")
        self.assertIsNotNone(said["event"])                 # Kim's window has her answer as any message of hers
        ended = hub.q1("SELECT state, waiting_on FROM tasks WHERE id=?", (task,))
        self.assertEqual((ended["state"], ended["waiting_on"]), ("working", None))
        self.assertTrue(hub.q1("SELECT wait_end FROM agent_messages WHERE id=?", (asked,))["wait_end"])
        # the chat window's read finds vps's answer by its own event (agent_messages.event_id)
        self.assertEqual(hub.q1("SELECT e.kind FROM agent_messages m JOIN events e ON e.id=m.event_id WHERE m.text "
                                "LIKE '%quokka%'")["kind"], "chat")
        self.assertTrue(hub.q1("SELECT 1 FROM events WHERE agent='studio' AND kind='chat' AND text LIKE '%quokka%'"))
        hub.conversation_start("studio", cid)
        text = self.ok("read_messages", self.context(cid))
        for word in ("wombat", "quokka"):
            self.assertNotIn(word, text)
        # and Kim's own window reads what the agent asked her, with her answer, though Pat's task asked it
        kim_cid = hub.q1("SELECT conversation FROM conversation_messages WHERE text LIKE '%wombat%'")["conversation"]
        hub.conversation_start("studio", kim_cid)
        brief = self.ok("read_messages", self.context(kim_cid))
        self.assertIn("Is order 7781 paid?", brief)
        self.assertIn("wombat", brief)
        # nor does an agent that gave the pair's task reach it by its id (same_work_note names no such road)
        hub.q("UPDATE tasks SET requester='vps' WHERE id=?", (task,))
        self.assertFalse(hub.given_reach("vps", "studio", task))
        self.assertEqual(hub.same_work("studio", None, f"Go on with {hub.tref(task)}."), [])     # no note names it

    def test_the_next_wait_takes_an_answer_that_a_narrowed_task_waited_for(self):
        """An answer that a narrowed pair's task waited for goes to the next task that waits in that conversation, and
        each wait of the narrowed task there ends, also the newer one that its waiting_on names. The bugs: the narrowed
        wait used the answer up and left the other task waiting; a task that asked twice stayed input-required."""
        self.person("Kim", "manager", KIM, app="discord")
        cid = self.says(PAT, "Ask Kim about order 7781.")["conversation"]
        hub.conversation_start("studio", cid)
        self.ok("read_messages", self.context(cid))
        for words in ("Is order 7781 paid?", "And is it shipped?"):
            self.ok("message_contact", self.context(cid), person="Kim", text=words, request_id=str(uuid.uuid4()),
                    waits=True)
        task = self.conversation_task(cid)["id"]
        other, theirs = self.normal_task(title="Check order 7781")
        self.reads(theirs, "Kim")
        self.ok("message_contact", theirs, person="Kim", text="Can I close 7781?", request_id=str(uuid.uuid4()),
                waits=True)
        code, data = self.scopes({f"repo:{REPO}": "read"})          # the owner's first list for Pat
        self.assertEqual(code, 200, data)
        self.assertEqual(self.inbound(text="Yes, 7781 is the dingo case: close it.", account="discord-studio",
                                      sender=KIM, chat="dm-9")[0], "stored")
        mine = [r["text"] for r in hub.q("SELECT text FROM events WHERE task=? AND kind='say'", (task,))]
        self.assertFalse([line for line in mine if "dingo" in line], mine)
        self.assertTrue([line for line in mine if hub.NARROWED_ANSWER.split("{ref}")[1] in line], mine)
        ended = hub.q1("SELECT state, waiting_on FROM tasks WHERE id=?", (task,))
        self.assertEqual((ended["state"], ended["waiting_on"]), ("working", None))
        self.assertTrue(hub.q1("SELECT 1 FROM events WHERE task=? AND kind='say' AND text LIKE '%dingo%'", (other,)))

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
        """Person access plan, section 7: a first list ends the open work that the conversation opened before it, and
        gives the open conversation task the person, so that the messages that join it and its result, the locked
        window's reply, stay the narrowed pair's (section 5); a list back to All gives the open task the agent's own
        tools again. The bug: the open task keeps no person, and a session with more finds the narrowed time's words
        in its result."""
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
        self.assertEqual(open_task["scope_person"], self.pat["id"])
        said = self.says(PAT, "the quokka code is 4411")
        self.assertEqual(said["task"], open_task["id"])         # it joins the open task
        self.answers(cid, said["id"], "Noted the quokka code.")
        self.assertEqual(self.task(open_task["id"])["state"], "completed")
        _, task = self.normal_task(title="Look for the codes")
        self.assertFalse(self.found(task, "quokka"))
        self.assertTrue(hub.history_found(None, {"query": "quokka"}, True, 10)[0])         # the owner's
        open_task = self.conversation_task(self.says(PAT, "and the wombat code?")["conversation"])
        self.assertEqual(self.scopes(None)[0], 200)
        self.assertIsNone(hub.q1("SELECT scope_person FROM tasks WHERE id=?", (open_task["id"],))["scope_person"])


    def test_a_first_list_ends_the_wait_of_a_message_that_nobody_will_read(self):
        """Fable's round 4: a message that another agent's open task sent with waits=true, filed under the open
        conversation task, is read for nobody at the first list (the locked window must not read it), so its wait
        ends there and its asker hears it once, in its own task, with no word of the message. The bug: the asker's
        task waits for an answer that never comes."""
        said = self.says(PAT, "Hi")
        asker, _ = self.normal_task(owner="vps", title="Ask studio about the stock")
        event = hub.ins(hub.EVENT, ("studio", "say", said["task"], "[message from vps] How many otters are in stock?",
                                    hub.now(), "{}"))
        message = hub.ins("INSERT INTO agent_messages(sender,sender_task,recipient,text,created,request_id,event_id,"
                          "waits) VALUES('vps',?,'studio','How many otters are in stock?',?,?,?,1)",
                          (asker, hub.now(), str(uuid.uuid4()), event))
        self.assertEqual(self.scopes({f"repo:{REPO}": "write"})[0], 200)
        self.assertIsNotNone(hub.q1("SELECT wait_end FROM agent_messages WHERE id=?", (message,))["wait_end"])
        told = [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='vps' AND task=? AND kind='say'",
                                         (asker,))]
        self.assertEqual(told, [f"[hub] AM-{message} will get no answer: T-{said['task']} will not read it. Go on "
                                f"without it, or {hub.wait_next('vps')}."])

    def test_a_first_list_ends_a_conversation_task_that_holds_no_message_of_the_person(self):
        """Fable's review of bf422aead: a conversation task that only a line of the hub's opened (a result of work of
        the time at All) waits on no message of the person, so nothing would end it before a widening: a first list
        ends it with the open work. The bug: it stays open with the person's list, and every later message of the
        person joins it."""
        hello = self.says(PAT, "Hi")
        self.answers(hello["conversation"], hello["id"], "Hello Pat.")          # a window with the agent's tools
        conv = hub.q1("SELECT * FROM conversations WHERE id=?", (hello["conversation"],))
        with hub.LOCK, hub.transaction():
            line = hub.conversation_post_rows(conv, "T-97 (Stock) is completed: the tamarin stock is counted.",
                                              hub.now())
        opened = self.conversation_task(hello["conversation"])
        self.assertEqual(opened["source_message"], line)
        self.assertEqual(self.scopes({f"repo:{REPO}": "write"})[0], 200)
        self.assertEqual(self.task(opened["id"])["state"], "canceled")
        self.assertIsNone(self.conversation_task(hello["conversation"]))

    def test_a_narrowed_session_finds_no_record_of_what_a_session_with_more_did(self):
        """The review of person-scope-row-mark-spec.md: a narrowed session's history gives the records of its own
        conversation's tasks, and a task of a time at All ran in a session with the agent's own tools, whose records
        hold what it read and ran: a read from more access to less. So it finds the person's and the agent's messages
        of its conversation, and of the other records only those of a task of its person's list from the time that the
        list began. The bug: the scope reads only that the task is one of the conversation, and the locked window finds
        what a session with more did in a task that ended before the first list, or in the open task that the first
        list gave its person, or the result of work of that time that the hub wrote into the conversation, or what
        such a task wrote to another person in that person's own conversation; or its window reads that line of the
        hub's, which nobody read before the first list (person_scope_rows reads it at the list), or a line that the
        fleet filed under the open task, and an unread line keeps the conversation task open after the window's
        answer; or the first list ends the open task, whose message the old window read and did not answer yet; or it
        reads for nobody the owner's steer of that task, which the window must follow; or it reads an agent's message
        there for nobody, and its sender never hears that nobody will; or it finds a late record of the revoked wide
        window's session, which the time rule lets through when it comes after the list (Fable's decision (a): no
        session record of a conversation task is a narrowed session's)."""
        hello = self.says(PAT, "Hi there")
        ended = hello["task"]
        self.answers(hello["conversation"], hello["id"], "Hello Pat.")          # a window with the agent's tools
        open_one = self.says(PAT, "One more thing")["task"]
        self.ok("read_messages", self.context(hello["conversation"]))         # read, and not answered yet
        made = []

        def record(tid, at, text):          # one record of the task's session (thread_events), as its helper sends it
            made.append(hub.ins("INSERT INTO thread_events(task,attempt,session,seq,ts,type,data,created) VALUES(?,1,"
                                "'s-1',?,?,'agent_message',?,?)", (tid, len(made) + 1, at, json.dumps({"text": text}),
                                                                   at)))
            return made[-1]
        t0 = hub.now()
        at_all = (record(ended, t0 - 100, "The launchpad plan is for Friday."),
                  record(open_one, t0 - 50, "The capybara budget is nine thousand."))
        conv = hub.q1("SELECT * FROM conversations WHERE id=?", (hello["conversation"],))
        with hub.LOCK, hub.transaction():           # a result of work of the time at All, which joins the open task
            line = hub.conversation_post_rows(conv, "T-99 (Prices) is completed: the ocelot prices are ready.", t0 - 40)
        self.assertEqual(hub.q1("SELECT task FROM conversation_messages WHERE id=?", (line,))["task"], open_one)
        hub.emit("studio", "say", "[hub] Result for T-98 (Cats): the margay report is ready.", task=open_one)
        said = hub.ins(hub.EVENT, ("studio", "say", open_one, "[message from manager] The puma files are in the vault.",
                                   hub.now(), "{}"))       # an agent's message filed under the open task
        message = hub.ins("INSERT INTO agent_messages(sender,recipient,text,created,request_id,event_id) VALUES("
                          "'manager','studio','The puma files are in the vault.',?,?,?)",
                          (hub.now(), str(uuid.uuid4()), said))
        with hub.LOCK:                              # and the owner's guidance on it, which nobody read yet
            hub.task_steer_act(open_one, {"expected_attempt": None, "text": "Keep the answer short, please.",
                                          "attachments": [], "request_id": str(uuid.uuid4())}, "test")
        steer = hub.q1("SELECT event_id FROM steers WHERE task=?", (open_one,))["event_id"]
        self.person("Kim", "manager", KIM, app="discord")       # the open task writes to another person: a row of
        self.ok("message_contact", self.context(hello["conversation"]), person="Kim",        # Kim's conversation
                text="The serval invoice is late.", request_id=str(uuid.uuid4()))
        self.assertEqual(self.scopes({f"repo:{REPO}": "write"})[0], 200)
        self.assertEqual(self.task(open_one)["state"], "working")          # still open: it waits on that message
        told = hub.q("SELECT text FROM events WHERE agent='manager' AND text LIKE ?", (f"[hub] AM-{message} %",))
        self.assertEqual([r["text"] for r in told], [f"[hub] AM-{message} reached T-{open_one}, which will not read "
                                                     f"it."])          # its sender hears it, with no word of it
        self.assertIsNone(hub.q1("SELECT read_at FROM events WHERE id=?", (steer,))["read_at"])
        # a late record of the revoked wide window, filed under the task that now has the person: a locked window
        # sends no session record, so every one of a conversation task is a wide window's
        late = record(open_one, hub.now() + hub.CONVERSATION_RECORD_SKEW + 1, "The koala branch is ready.")
        # and a call record of the list's own time, which the narrowed session made (its call_api)
        call = hub.ins("INSERT INTO calls(ts,agent,task,attempt,name,args,ok,detail) VALUES(?,'studio',?,1,"
                       "'call_api',?,1,'200 OK')", (hub.now() + hub.CONVERSATION_RECORD_SKEW + 1, open_one,
                                                    json.dumps({"url": "https://api.example.com/jaguar"})))
        here = self.context(hello["conversation"])
        self.assertEqual([self.found(here, w) for w in ("launchpad", "capybara", "ocelot", "serval", "koala", "jaguar",
                                                        "thing")], [False, False, False, False, False, True, True])
        for ref in at_all + (late,):
            self.assertIn("is not in your history", self.ok("read_history", here, ref=f"TR-{ref}"))
        self.assertIn("jaguar", self.ok("read_history", here, ref=f"CR-{call}"))
        # the line of the hub's that nobody read, and the line filed under the open task, were read at the first list:
        # the locked window never gets them, and its answer to the person's message ends the open task, which no
        # unread line keeps open
        self.assertIsNotNone(hub.q1("SELECT read_at FROM conversation_messages WHERE id=?", (line,))["read_at"])
        more = hub.q1("SELECT id FROM conversation_messages WHERE text='One more thing'")["id"]
        hub.conversation_start("studio", hello["conversation"])
        read = self.ok("read_messages", here)
        self.assertNotIn("ocelot", read)
        self.assertNotIn("margay", read)
        self.assertNotIn("puma", read)
        self.assertIn("Keep the answer short, please.", read)             # the owner's guidance reaches it
        self.ok("reply", here, text="Noted.", in_reply_to=f"CM-{more}")
        self.assertIsNone(self.conversation_task(hello["conversation"]))
        _, task = self.normal_task(title="Look at the plans")
        self.assertTrue(self.found(task, "launchpad"))          # a session with the agent's tools: its own work


class Settle(Base):
    """settle_narrowed_rows: the marks of the rows that a hub stored before the column came, at the start."""
    # person_route's INSERT of the release before the column, which a hub of that release still runs during a
    # restart or after a rollback
    OLD = ("INSERT INTO conversation_messages(id,conversation,who,text,created,msg_id,kind,missed) "
           "VALUES(?,?,?,?,?,?,?,?)")

    def conversation(self, pid):
        return hub.ins("INSERT INTO conversations(person,agent,account,chat,state,created,last) VALUES(?,?,?,?,?,?,?)",
                       (pid, "studio", "whatsapp-studio", f"chat-{pid}", "open", 1000.0, 1000.0))

    def said(self, cid, who, at, task=None, reply_to=None, read=True):
        """One row, as the release before wrote it: the old INSERT, and the columns that its writers set after it."""
        cm = hub.ins(self.OLD, (hub.unused_id("conversation_messages"), cid, who, f"words of {who} at {at}", at, None,
                                None, None))
        hub.q("UPDATE conversation_messages SET task=?, reply_to=?, read_at=? WHERE id=?",
              (task, reply_to, at if read else None, cm))
        return cm

    def marks(self, *ids):
        return [hub.q1("SELECT scope_person FROM conversation_messages WHERE id=?", (i,))["scope_person"] for i in ids]

    def test_the_start_marks_a_narrowed_pairs_rows_of_before_once_and_all_time_rows_never(self):
        """person-scope-row-mark-spec.md, section C: rows stored before the column (or by the release before, whose
        INSERT names no scope_person and still works after migrate) get the person's mark at the start: each start,
        a row of a narrowed task and a reply to a marked row; one time, in a pair that had a list, each message of
        the person and each reply from a minute before its first log line of a list, leaving out, for a pair at All
        now, what a widening gives back. The bugs: the column is NOT NULL and the old writer fails; the one-time pass
        runs at each start and marks the words of a time at All after it; a pair that never had a list loses its
        records; an unread message that a pair at All now waits on is hidden from the window that must answer it; a
        read message with no task is left open when the conversation has an open task (an IN over NULL is NULL, and
        so is its NOT); a line of the hub's that joined a narrowed task keeps a mark that no widening takes back."""
        kim, lee = self.person("Kim", "manager", KIM, app="discord"), self.add(name="Lee", role="peer")
        hub.q("DELETE FROM kv WHERE k=?", (hub.NARROWED_SETTLED,))
        pat_c, kim_c, lee_c = (self.conversation(p["id"]) for p in (self.pat, kim, lee))
        self.narrow(self.pat["id"], {f"repo:{REPO}": "write"})          # Pat has a list now; Kim had one
        for at, pid, words in ((5000.0, self.pat["id"], "1 resource(s) of its own"),
                               (5000.0, kim["id"], "1 resource(s) of its own"), (7000.0, kim["id"], "all of it")):
            hub.ins("INSERT INTO log(ts,agent,what) VALUES(?,?,?)",
                    (at, "owner", f"P-{pid}'s access with studio: {words}"))
        narrowed = hub.ins("INSERT INTO tasks(title,owner,requester,state,created,source_conversation,source_message,"
                           "scope_person) VALUES('Answer Pat','studio','manager','completed',4400,?,1,?)",
                           (pat_c, self.pat["id"]))
        hub.ins("INSERT INTO tasks(title,owner,requester,state,created,source_conversation,source_message) "
                "VALUES('Answer Kim','studio','manager','working',8500,?,1)", (kim_c,))     # Kim's open task
        before = self.said(pat_c, "person", 4000.0)                     # at All, long before the list
        of_task = self.said(pat_c, "person", 4500.0, task=narrowed)         # rule 1
        its_reply = self.said(pat_c, "agent", 4501.0, reply_to=of_task)     # rule 2
        line = self.said(pat_c, "action", 4502.0, task=narrowed)        # a line of the hub's that joined the task
        paused = self.said(pat_c, "person", 6000.0)                     # rule 3: no task, a message in a pause
        reply = self.said(pat_c, "agent", 6001.0, reply_to=paused)
        sent = self.said(pat_c, "agent", 6002.0)                        # message_contact of a session with more
        owners = self.said(pat_c, "owner", 6003.0)
        answered = self.said(kim_c, "person", 6000.0)
        kim_reply = self.said(kim_c, "agent", 6001.0, reply_to=answered)
        waiting = self.said(kim_c, "person", 8000.0, read=False)        # after Kim's widening: nobody read it
        read_later = self.said(kim_c, "person", 8001.0)                 # read, never answered: fails closed
        lee_rows = (self.said(lee_c, "person", 6000.0), self.said(lee_c, "agent", 6001.0))
        hub.settle_narrowed_rows()
        p, k = self.pat["id"], kim["id"]
        self.assertEqual(self.marks(before, of_task, its_reply, line, paused, reply, sent, owners),
                         [None, p, p, None, p, p, None, None])
        self.assertEqual(self.marks(answered, kim_reply, waiting, read_later), [k, k, None, k])
        self.assertEqual(self.marks(*lee_rows), [None, None])
        # a later start: the one-time pass does not run again, and the two rules of each start still do
        all_time = self.said(kim_c, "person", 9000.0)
        old_reply = self.said(pat_c, "agent", 9001.0, reply_to=paused)
        old_row = self.said(pat_c, "person", 9002.0, task=narrowed)
        hub.settle_narrowed_rows()
        self.assertEqual(self.marks(all_time, old_reply, old_row), [None, p, p])
        self.assertEqual(self.marks(waiting), [None])


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


class Writers(unittest.TestCase):
    """The source of hub.py itself: no hub, no database."""

    def test_each_write_of_a_conversation_message_says_its_mark(self):
        """Person access plan, section 5: a narrowed pair's rows carry the person's mark (narrowed_mark), and every
        read of the other sessions leaves a marked row out. So each INSERT into conversation_messages in hub.py names
        scope_person, with narrowed_mark or NULL, and names its columns, so that a hub of the release before still
        writes into the table after the column came. The bug: a new writer (WhatsApp files, say) stores a narrowed
        person's words with no mark, and every session with more reads them."""
        import ast
        import re
        from pathlib import Path
        found = []
        for node in ast.walk(ast.parse(Path(hub.__file__).read_text())):
            text = node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else \
                "".join(v.value for v in node.values if isinstance(v, ast.Constant)) \
                if isinstance(node, ast.JoinedStr) else ""
            for m in re.finditer(r"INTO\s+conversation_messages\s*(\(([^)]*)\))?", text):
                found.append((m.group(2) or "", text[:120]))
        self.assertGreaterEqual(len(found), 9, found)       # the nine writers of the spec, at least
        for columns, text in found:
            self.assertTrue(columns, f"names no columns: {text}")
            self.assertIn("scope_person", [c.strip() for c in columns.split(",")], text)


if __name__ == "__main__":
    unittest.main()

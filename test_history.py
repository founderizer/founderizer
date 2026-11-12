"""History search (AUTONOMY.md P6, lane L5): one search for each agent over everything it took part in.

The owner, 27 October 2026: keep everything, and make it searchable by date and topic "very easily (and fast)". These
checks are the plan's own: a search finds a conversation by date and person; ranking prefers the closer match; an
agent finds only its own records; a session that a contact drives finds no owner chat; the owner finds any agent's;
a long task keeps more than 5,000 tool records; and the backfill and the table sweeps hold (with selftest.py). Then
what makes those true: the streams index each record once as it arrives, pull by pull; a rollback's gap is taken in;
a tool record keeps what the session did and not what was typed into it; a rename keeps the history and a removed
person leaves it; a registered login never reaches the index; and a machine without FTS5 searches linearly.

In-process hub, a temporary database and a set clock. No AI calls.

Run: python3 -m unittest -v test_history.py
"""
import datetime
import hashlib
import json
import re
import sqlite3
import threading
import time
import unittest
import urllib.parse
import uuid
from unittest.mock import patch
from zoneinfo import ZoneInfo

import hub
import owner_mcp
from test_ui_api import OwnerAPI

MADRID = ZoneInfo("Europe/Madrid")
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3", "mac-studio": "127.0.0.4"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]},
                   "studio": {"role": "worker", "runtime": "claude", "machine": "mac-studio", "can": ["shell"]}},
        "goals": {"timezone": "Europe/Madrid", "review_hour": 9, "sweep_minutes": 15}}
SESSION = "11111111-2222-4333-8444-555555555555"
SECRET = "Hx7-Pw!q2Zr9-Lk4"


def at(text):
    return datetime.datetime.fromisoformat(text).replace(tzinfo=MADRID).timestamp()


def load_tests(loader, _tests, _pattern):
    """Only the tests of this file: the fixture it borrows from test_ui_api.py carries its own."""
    suite = unittest.TestSuite()
    for cls in (Finding, Own, ContactDriven, Owner, Messages, LongTask, Indexing, ToolRecords, Keeping, Tools):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Base(OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        self.clock = at("2026-10-26T10:00")
        clock = patch.object(hub, "now", lambda: self.clock)
        clock.start()
        self.addCleanup(clock.stop)
        hub.HISTORY_CALL_CACHE.clear()
        self.addCleanup(hub.HISTORY_CALL_CACHE.clear)
        self.sessions = {}

    # ---- records, as the hub's own writers leave them
    def task(self, owner="vps", requester="manager", title="A task", details="", done_when="it is done",
             parent=None, created=None):
        return hub.ins("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,created,attempt,parent) "
                       "VALUES(?,?,?,'none',?,?,'working',?,1,?)",
                       (title, details, done_when, owner, requester, self.clock if created is None else created, parent))

    def person(self, name):
        return hub.ins("INSERT INTO people(name,role,added) VALUES(?,'customer',?)", (name, self.clock))

    def conversation(self, person, agent="vps"):
        return hub.ins("INSERT INTO conversations(person,agent,account,chat,state,created,last) "
                       "VALUES(?,?,'discord-1',?,'open',?,?)", (person, agent, f"chat-{person}", self.clock, self.clock))

    def said(self, conversation, who, text, when=None):
        return hub.ins("INSERT INTO conversation_messages(conversation,who,text,created) VALUES(?,?,?,?)",
                       (conversation, who, text, self.clock if when is None else when))

    def owner_says(self, text, agent="vps"):
        with hub.LOCK, hub.transaction():
            hub.owner_message_rows(str(uuid.uuid4()), "message", None, text, "test", agent, None, self.clock)
        return hub.q1("SELECT rowid FROM ui_requests ORDER BY rowid DESC LIMIT 1")["rowid"]

    def records(self, tid, events, agent="vps", source="127.0.0.3", attempt=1):
        return self.request(f"/helper/events/{agent}", {"generation": "test-generation", "task": f"T-{tid}",
                                                        "attempt": attempt, "session": SESSION, "events": events},
                            source=source)

    # ---- an agent's calls, in a session of its own task (or the manager's own session)
    def session(self, who):
        """The task of the one session an agent calls from in a test, unless the call names another."""
        if who not in self.sessions:
            self.sessions[who] = self.task(owner=who, title="Session", details="", done_when="done")
        return self.sessions[who]

    def tool(self, who, name, task=None, **args):
        if hub.role_of(who) == "manager":
            return hub.call_tool(who, name, args)
        tid = task if task is not None else self.session(who)
        return hub.call_tool(who, name, dict(args, task_id=hub.tref(tid)), ("test-generation", hub.tref(tid), 1))

    def search(self, who, task=None, **args):
        text, error = self.tool(who, "search_history", task=task, **args)
        self.assertFalse(error, text)
        return text

    def read(self, who, ref, task=None):
        text, error = self.tool(who, "read_history", task=task, ref=ref)
        self.assertFalse(error, text)
        return text

    def refs(self, text):
        """The refs of a search's answer, in its order."""
        return re.findall(r"(?m)^\d+\. (\S+) · ", text)

    def owner(self, **query):
        query.setdefault("db", "test-generation")
        return self.request("/ui/history?" + urllib.parse.urlencode(query))

    def tick(self):
        printed = []
        with patch.dict(hub.CFG, {"silence": 180, "question_wait": 120, "manager_silence": 120, "stop_after": 60,
                                  "offline_after": 90, "tick": 5, "hook_wait": 240,
                                  "attachment_dir": self.tmp.name + "/attachments"}), \
                patch.object(hub.traceback, "print_exc", lambda *a, **k: printed.append(1)):
            hub.tick()
        self.assertEqual(printed, [], "a sweep raised")


class Finding(Base):
    def test_a_search_finds_a_conversation_by_date_and_person(self):
        bruno, angela = self.person("Bruno Dupont"), self.person("Ángela Ruiz")
        with_bruno, with_angela = self.conversation(bruno), self.conversation(angela)
        self.said(with_bruno, "person", "The export of the invoices is wrong again", at("2026-10-24T09:15"))
        yesterday = self.said(with_bruno, "person", "Can you send the invoice export as csv?", at("2026-10-25T16:40"))
        self.said(with_bruno, "agent", "Sent: invoices.csv", at("2026-10-25T16:55"))
        self.said(with_angela, "person", "Please hold the invoice export for me", at("2026-10-25T17:00"))
        found = self.search("vps", query="invoice export", person="Bruno", **{"from": "2026-10-25", "to": "2026-10-25"})
        self.assertEqual(self.refs(found), [f"CM-{yesterday}", f"CM-{yesterday + 1}"], found)
        self.assertIn("conversation with Bruno Dupont", found)
        self.assertIn("2026-10-25 16:40", found)                                 # the fleet's own time zone
        self.assertIn("Times are in Europe/Madrid", found)
        # with no words: that person's records of that day, the newest first
        newest = self.search("vps", person="bruno dupont", **{"from": "2026-10-25", "to": "2026-10-25"})
        self.assertEqual(self.refs(newest), [f"CM-{yesterday + 1}", f"CM-{yesterday}"], newest)
        self.assertIn("the newest first", newest)
        # Ángela's message is hers, and accents do not matter to the search
        self.assertEqual(self.refs(self.search("vps", person="angela", query="hold")), [f"CM-{yesterday + 2}"])
        self.assertIn("Nothing in your history matches",
                      self.search("vps", query="invoice", person="Bruno", **{"to": "2026-10-23"}))

    def test_ranking_prefers_the_closer_match(self):
        one = self.task(title="Refund the customer", details="One refund for the order of March")
        both = self.task(title="Refund the Stripe charge", details="The refund goes through Stripe, then the csv")
        none = self.task(title="Rotate the logs", details="Nothing about money")
        found = self.search("vps", query="refund stripe csv")
        self.assertEqual(self.refs(found)[:2], [f"T-{both}", f"T-{one}"], found)
        self.assertNotIn(f"T-{none}", self.refs(found))
        self.assertIn("the best first", found)

    def test_word_forms_phrases_and_refs(self):
        refunded = self.task(title="Customer refunded twice", details="see T-12 for the first one")
        spanish = self.task(title="Reembolso pedido por Ángela", details="la cliente pide un reembolso")
        self.assertIn(f"T-{refunded}", self.refs(self.search("vps", query="refund")))      # a word finds its forms
        self.assertIn(f"T-{spanish}", self.refs(self.search("vps", query="refund reembolso")))
        self.assertEqual(self.refs(self.search("vps", query="angela")), [f"T-{spanish}"])
        self.assertEqual(self.refs(self.search("vps", query="T-12")), [f"T-{refunded}"])   # a ref is a phrase
        self.assertEqual(self.refs(self.search("vps", query='"refunded twice"')), [f"T-{refunded}"])
        self.assertIn("Nothing", self.search("vps", query='"twice refunded"'))

    def test_dates_are_the_fleets_own_and_a_search_needs_something(self):
        self.task(title="Early", created=at("2026-10-25T00:30"))     # 22:30 UTC the day before
        self.task(title="Late", created=at("2026-10-25T23:30"))
        found = self.search("vps", **{"from": "2026-10-25", "to": "2026-10-25"})
        self.assertEqual(len(self.refs(found)), 2, found)
        self.clock = at("2026-10-26T08:00")
        self.assertEqual(len(self.refs(self.search("vps", **{"from": "yesterday", "to": "yesterday"}))), 2)
        self.assertEqual(len(self.refs(self.search("vps", **{"from": "2026-10-25 12:00"}))), 2)   # Late, and the
        text, error = self.tool("vps", "search_history", **{"from": "last week"})               # session's task
        self.assertTrue(error)
        self.assertIn("2026-10-26 14:00", text)
        newest = self.search("vps", query="  ")                         # nothing at all: the newest of all
        self.assertEqual(len(self.refs(newest)), 3, newest)
        self.assertIn("Your 3 newest records:", newest)
        text, error = self.tool("vps", "search_history", kind="gossip")
        self.assertTrue(error)
        self.assertIn("kind is one of", text)

    def test_read_history_opens_a_task_with_its_notes_result_and_check(self):
        tid = self.task(title="Fix the export")
        hub.ins("INSERT INTO notes(task,agent,ts,text) VALUES(?,'vps',?,'Found the bad column')", (tid, self.clock))
        self.clock += 60
        hub.q("UPDATE tasks SET state='completed', outcome='completed', what='Fixed the column', where_='commit 1a2b', "
              "how='ran the export', delivered=? WHERE id=?", (self.clock, tid))
        self.clock += 60
        hub.q("UPDATE tasks SET accepted=0, check_note='the header is still wrong', checked_at=? WHERE id=?",
              (self.clock, tid))
        mine = self.read("vps", f"T-{tid}")
        for text in ("Fix the export", "Found the bad column", "Fixed the column", "commit 1a2b",
                     "manager did not accept the result", "the header is still wrong"):
            self.assertIn(text, mine)
        self.assertLess(mine.index("Fix the export"), mine.index("Found the bad column"))
        self.assertLess(mine.index("Found the bad column"), mine.index("Fixed the column"))
        asked = self.read("manager", f"t{tid}")                 # the requester's: no progress note, which is vps's own
        self.assertIn("Fixed the column", asked)
        self.assertNotIn("Found the bad column", asked)
        self.assertIn("ref is one that search_history gave", self.tool("vps", "read_history", ref="X-1")[0])


class Own(Base):
    def test_an_agent_finds_only_its_own_records(self):
        mine = self.task(owner="vps", title="Deploy the shop", requester="manager")
        theirs = self.task(owner="studio", title="Deploy the landing page", requester="manager")
        self.records(mine, [{"seq": 1, "type": "agent_message", "text": "The shop deploy is green"}])
        self.records(theirs, [{"seq": 1, "type": "agent_message", "text": "The landing deploy is green"}],
                     agent="studio", source="127.0.0.4")
        self.assertEqual(sorted(self.refs(self.search("vps", task=mine, query="deploy"))),
                         sorted([f"T-{mine}", "TR-1"]))
        studio = self.search("studio", task=theirs, query="deploy")
        self.assertNotIn(f"T-{mine}", studio)
        self.assertNotIn("shop", studio)
        for ref in (f"T-{mine}", "TR-1"):
            self.assertIn("is not in your history", self.read("studio", ref, task=theirs))
        # the manager asked for both, so both tasks are its own records; the sessions' own records are not
        both = self.search("manager", query="deploy")
        self.assertEqual(sorted(self.refs(both)), sorted([f"T-{mine}", f"T-{theirs}"]), both)
        self.assertIn("is not in your history", self.read("manager", "TR-1"))

    def test_a_message_between_two_agents_is_in_both_histories(self):
        hub.ins("INSERT INTO agent_messages(sender,recipient,text,created,request_id) VALUES('vps','studio',"
                "'Which port does the staging proxy use?',?,'r1')", (self.clock,))
        for who in ("vps", "studio"):
            found = self.search(who, query="staging proxy")
            self.assertEqual(self.refs(found), ["AM-1"], found)
            self.assertIn("message with " + ("studio" if who == "vps" else "vps"), found)
        self.assertIn("Nothing", self.search("manager", query="staging proxy"))
        self.assertEqual(self.refs(self.search("vps", person="studio")), ["AM-1"])


class ContactDriven(Base):
    """A session that a contact drives never finds the owner's chats (the plan's one hard limit)."""

    def setUp(self):
        super().setUp()
        self.bruno = self.person("Bruno")
        self.talk = self.conversation(self.bruno)
        self.said(self.talk, "person", "Is my invoice ready?")
        self.said(self.talk, "owner", "Bruno pays late; the invoice waits for his payment")
        self.owner_says("Keep the invoice for Bruno until he pays")
        hub.ins("INSERT INTO owner_reports(text,about,created,agent) VALUES('I hold the invoice for Bruno','',?,'vps')",
                (self.clock,))
        work = self.task(title="Send the invoice", details=hub.HISTORY_OWNER_TASK + "vps's chat: send the invoice "
                                                                                    "to Bruno once he pays")
        hub.ins("INSERT INTO steers(task,attempt,text,event_id,request_id,client,created) VALUES(?,1,'not before the "
                "invoice is paid',0,'s1','test',?)", (work, self.clock))
        self.owner_records = 5          # the conversation's owner line, the chat both ways, the task, the steer
        self.theirs = 1                 # Bruno's own line

    def contact_task(self, column=True):
        if column and "source_conversation" not in {r["name"] for r in hub.q("PRAGMA table_info(tasks)")}:
            hub.DB.execute("ALTER TABLE tasks ADD COLUMN source_conversation INTEGER")     # lane L2's column
        tid = self.task(title="Answer Bruno")
        if column:
            hub.q("UPDATE tasks SET source_conversation=? WHERE id=?", (self.talk, tid))
        return tid

    def test_a_contact_driven_session_finds_no_owner_chat(self):
        everything = self.search("vps", query="invoice")
        self.assertEqual(len(self.refs(everything)), self.theirs + self.owner_records, everything)
        driven = self.contact_task()
        found = self.search("vps", task=driven, query="invoice")
        self.assertEqual(self.refs(found), ["CM-1"], found)
        self.assertIn("the owner's chats are not searched", found)
        for ref in ("CM-2", "OM-1", "OR-1", "T-1"):
            self.assertIn("is not in your history", self.read("vps", ref, task=driven))
        self.assertIn("Is my invoice ready?", self.read("vps", "CM-1", task=driven))
        # a part of it is driven by the same person; a task of its own is not
        part = self.task(title="Look up the sum", parent=driven)
        self.assertEqual(self.refs(self.search("vps", task=part, query="invoice")), ["CM-1"])
        self.assertEqual(len(self.refs(self.search("vps", task=self.task(), query="invoice"))),
                         self.theirs + self.owner_records)

    def test_the_owner_chat_finds_the_owners_chats_and_a_contact_session_still_does_not(self):
        """T3 Code idea 9A: the owner asks the agent in its chat where it said something, and the agent finds its own
        records, his chats included. The owner chat is no contact's session, and a contact's session keeps its limit."""
        chat = ("test-generation", "owner-chat", "1")
        self.assertFalse(hub.contact_session("vps", chat))
        found, error = hub.call_tool("vps", "search_history", {"query": "invoice"}, chat)
        self.assertFalse(error, found)
        self.assertEqual(len(self.refs(found)), self.theirs + self.owner_records, found)
        self.assertIn("OM-1", self.refs(found))
        self.assertNotIn("the owner's chats are not searched", found)
        text, error = hub.call_tool("vps", "read_history", {"ref": "OM-1"}, chat)
        self.assertFalse(error, text)
        self.assertIn("Keep the invoice for Bruno until he pays", text)
        self.assertEqual(self.refs(self.search("vps", task=self.contact_task(), query="invoice")), ["CM-1"])
        mine, _ = hub.call_tool("studio", "search_history", {"query": "invoice"}, chat)     # another agent's chat
        self.assertEqual(self.refs(mine), [], mine)

    def test_a_task_the_owner_asked_for_in_the_older_words_stays_the_owners(self):
        """start_task's details began with other words before 3 November 2026, and those tasks are still the
        owner's chat."""
        old = self.task(title="Pay the hosting", details=hub.HISTORY_OWNER_TASK_BEFORE + "vps's chat: pay the hosting")
        self.assertEqual(self.refs(self.search("vps", query="hosting")), [hub.tref(old)])
        self.assertEqual(self.refs(self.search("vps", task=self.contact_task(), query="hosting")), [])

    def test_before_lane_l2_no_task_is_a_contacts(self):
        tid = self.contact_task(column=False)
        self.assertFalse(hub.contact_session("vps", ("test-generation", hub.tref(tid), 1)))
        self.assertEqual(len(self.refs(self.search("vps", task=tid, query="invoice"))),
                         self.theirs + self.owner_records)

    def test_a_conversation_window_is_driven_by_its_person(self):
        self.assertTrue(hub.contact_session("vps", ("test-generation", "conversation", str(self.talk))))
        self.assertFalse(hub.contact_session("manager", None))


class Owner(Base):
    def test_the_owner_finds_any_agents_history(self):
        bruno = self.person("Bruno")
        self.said(self.conversation(bruno), "person", "Where is the refund?")
        self.owner_says("Refund Bruno only after the review", agent="studio")
        tid = self.task(owner="studio", title="Refund review")
        code, found = self.owner(agent="vps", query="refund")
        self.assertEqual(code, 200, found)
        self.assertEqual([r["ref"] for r in found["results"]], ["CM-1"])
        self.assertEqual(found["results"][0]["person_name"], "Bruno")
        self.assertEqual(found["index"]["zone"], "Europe/Madrid")
        code, every = self.owner(query="refund")
        self.assertEqual({(r["agent"], r["ref"]) for r in every["results"]},
                         {("vps", "CM-1"), ("studio", "OM-1"), ("studio", f"T-{tid}"), ("manager", f"T-{tid}")})
        self.assertTrue(next(r for r in every["results"] if r["ref"] == "OM-1")["owner_chat"])     # his own chats too
        code, one = self.owner(agent="studio", ref="OM-1")
        self.assertEqual((code, [r["text"] for r in one["records"]]),
                         (200, ["The owner: Refund Bruno only after the review"]))
        code, dated = self.owner(agent="vps", **{"from": "2026-10-27"})
        self.assertEqual((code, dated["results"]), (200, []))
        self.assertEqual(self.owner(agent="vps", query="refund", db="old")[0], 409)
        for bad in ({"agent": "Not An Agent"}, {"kind": "gossip"}, {"limit": "0"}, {"from": "soon"}, {"ref": "X"}):
            code, said = self.owner(**bad)
            self.assertEqual(code, 400, (bad, said))
        code, newest = self.owner(agent="studio")                         # an agent alone: its newest records
        self.assertEqual((code, sorted(r["ref"] for r in newest["results"])), (200, ["OM-1", f"T-{tid}"]))
        self.assertIn("history", self.request("/ui/state")[1]["ui_features"])

    def test_the_owners_mcp_server_has_a_tool_for_it(self):
        tool = next(t for t in owner_mcp.tools() if t["name"] == "search_history")
        self.assertEqual(set(tool["inputSchema"]["properties"]),
                         {"agent", "query", "from", "to", "person", "task", "kind", "ref", "limit"})
        asked = []
        with patch.object(owner_mcp, "get", lambda route, what, **q: asked.append((route, q)) or
                          type("Answer", (), {"data": {"results": []}})()):
            self.assertEqual(tool["run"]({"agent": "vps", "query": "refund", "from": "2026-10-25"}), {"results": []})
        self.assertEqual(asked, [("/ui/history", {"agent": "vps", "query": "refund", "from": "2026-10-25", "to": None,
                                                  "person": None, "task": None, "kind": None, "ref": None,
                                                  "limit": None})])


class Messages(Base):
    """GET /ui/history?mode=messages: the owner's search card in the Mac app (UI-API.md 1.128)."""

    def messages(self, words, **query):
        code, found = self.owner(mode="messages", query=words, **query)
        self.assertEqual(code, 200, found)
        return found

    def test_every_word_must_match_and_the_last_one_begins_words(self):
        tid = self.task(owner="vps", requester="manager", title="Rotate the staging certificate")
        self.clock += 30
        self.owner_says("Rotate the production certificate first", agent="vps")
        hub.ins("INSERT INTO agent_messages(sender,recipient,text,created,request_id) VALUES('vps','studio',"
                "'The staging certificate expires on Friday',?,'r1')", (self.clock + 60,))
        hub.history_catch_up()
        found = self.messages("staging certif")
        self.assertEqual([r["ref"] for r in found["results"]], ["AM-1", f"T-{tid}"], found)     # the newest first
        self.assertEqual([r["ref"] for r in self.messages("certificate rotate")["results"]], ["OM-1", f"T-{tid}"])
        self.assertEqual(self.messages("staging certificate monday")["results"], [])           # every word
        self.assertEqual(self.messages("stag certificate")["results"], [])        # only the last word is a start
        # one row for each record: the task is in the history of vps and of the manager, the message of vps and studio
        self.assertEqual([(r["ref"], r["agent"]) for r in found["results"]], [("AM-1", "vps"), (f"T-{tid}", "vps")])
        self.assertEqual(found["results"][1]["task"], f"T-{tid}")
        self.assertEqual((found["mode"], found["more"], found["index"]["zone"]), ("messages", False, "Europe/Madrid"))
        self.assertEqual(self.messages(" -- ")["results"], [])                    # no letter and no digit: nothing
        self.assertEqual(len(self.messages("certificate", limit="1")["results"]), 1)
        self.assertTrue(self.messages("certificate", limit="1")["more"])

    def test_a_row_carries_what_opens_its_chat_and_the_records_own_words(self):
        mine = self.owner_says("Please renew the domain before the end of the month", agent="studio")
        request = hub.q1("SELECT request_id FROM ui_requests WHERE rowid=?", (mine,))["request_id"]
        report = hub.ins("INSERT INTO owner_reports(text,about,created,agent) VALUES('The domain renews on the 30th',"
                         "'renewal',?,'studio')", (self.clock + 60,))
        hub.history_catch_up()
        rows = {r["ref"]: r for r in self.messages("domain")["results"]}
        self.assertEqual(set(rows), {f"OM-{mine}", f"OR-{report}"})
        self.assertEqual((rows[f"OM-{mine}"]["message"], rows[f"OM-{mine}"]["owner_chat"]), (request, True))
        self.assertIsNone(rows[f"OR-{report}"]["message"])
        self.assertEqual(rows[f"OM-{mine}"]["snippet"], "Please renew the domain before the end of the month")
        self.assertEqual(rows[f"OR-{report}"]["snippet"], "The domain renews on the 30th")   # no "studio to the owner"

    def test_no_tool_record_lesson_standing_item_or_conversation(self):
        tid = self.task(title="Session")
        self.records(tid, [{"seq": 1, "type": "agent_message", "text": "The parrot backup ran"}])
        hub.ins("INSERT INTO memories(agent,about,text,prevents,created,request_id) VALUES('vps','backups',"
                "'The parrot bucket rotates keys','a failed backup',?,'m1')", (self.clock,))
        hub.ins("INSERT INTO standing(agent,scope,kind,words,author_kind,author,created) VALUES('vps','agent',"
                "'instruction','Feed the parrot daily','owner','owner',?)", (self.clock,))
        self.said(self.conversation(self.person("Bruno")), "person", "My parrot is lost")
        hub.history_catch_up()
        self.assertGreaterEqual(hub.q1("SELECT COUNT(*) n FROM history")["n"], 4)
        self.assertEqual(self.messages("parrot")["results"], [])
        self.assertTrue(self.owner(query="parrot")[1]["results"])             # the route's own search finds them

    def test_no_index_work_comes_before_the_answer(self):
        self.task(title="Renew the TLS certificate")
        calls = []
        with patch.object(hub, "history_catch_up", lambda budget=None: calls.append(budget) or True):
            self.assertEqual(self.messages("certificate")["results"], [])     # not in the index yet
            self.assertEqual(calls, [])
            self.owner(query="certificate")                                  # the route's own search does it
            self.assertEqual(calls, [hub.HISTORY_SEARCH_STEP])
        hub.history_catch_up()                                                # the tick's pass
        self.assertEqual(len(self.messages("certificate")["results"]), 1)

    def test_a_registered_login_is_masked(self):
        salt = "c0ffee"
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES('crm',?,?,?,'')",
                (salt, hashlib.sha256((salt + SECRET).encode()).hexdigest(), len(SECRET)))
        self.owner_says(f"The crm password is {SECRET} now")
        hub.history_catch_up()
        found = self.messages("crm password")
        self.assertEqual(len(found["results"]), 1)
        self.assertIn(hub.MASK, found["results"][0]["snippet"])
        self.assertNotIn(SECRET, json.dumps(found))

    def test_refusals_and_the_feature(self):
        for bad in ({"mode": "everything"}, {"mode": "messages", "agent": "vps"}, {"mode": "messages", "kind": "task"},
                    {"mode": "messages", "ref": "T-1"}, {"mode": "messages", "limit": "101"}):
            code, said = self.owner(**bad)
            self.assertEqual(code, 400, (bad, said))
        self.assertEqual(self.owner(mode="messages", query="x", db="old")[0], 409)
        self.assertIn("history_messages", self.request("/ui/state")[1]["ui_features"])


class LongTask(Base):
    def test_a_long_task_keeps_more_than_5000_tool_records(self):
        tid = self.task(title="A very long migration")
        hub.ins("INSERT INTO attempts(task,attempt,created) VALUES(?,1,?)", (tid, self.clock))
        seq = 0
        for batch in range(52):
            events = []
            for _ in range(100):
                seq += 1
                events.append({"seq": seq, "type": "agent_message", "text": f"Moved table {seq} of the migration"})
            code, body = self.records(tid, events)
            self.assertEqual((code, body["stored"]), (200, 100), body)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM thread_events WHERE task=?", (tid,))["n"], 5200)
        self.assertEqual(hub.q("SELECT * FROM thread_events WHERE type='truncated'"), [])
        self.assertFalse(hasattr(hub, "EVENT_CAP"))
        self.assertEqual(hub.turn_state(tid, 1)["seq"], 5200)
        hub.history_catch_up(60)
        found = self.search("vps", query='"table 5199"')
        self.assertEqual(self.refs(found), ["TR-5199"], found)


class Indexing(Base):
    def test_the_backfill_takes_in_every_old_record_once(self):
        tid = self.task()
        n = hub.HISTORY_CHUNK * 2 + 7
        with hub.LOCK:              # every commit holds the lock (hub.held)
            hub.DB.executemany("INSERT INTO thread_events(task,attempt,session,seq,ts,type,data,created) "
                               "VALUES(?,1,?,?,?,'agent_message',?,?)",
                               [(tid, SESSION, i, self.clock, json.dumps({"text": f"step {i} of the backfill"}),
                                 self.clock) for i in range(1, n + 1)])
            hub.commit()
        self.assertEqual(hub.history_behind(), n + 1)                       # the task, and every record
        steps = 0
        while not hub.history_catch_up(0):                                  # one record a pass: the shortest hold
            steps += 1
        self.assertGreaterEqual(steps, 2)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM history WHERE kind='tool'")["n"], n)
        self.assertTrue(hub.history_catch_up())                             # nothing twice
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM history")["n"], n + 2)      # and the task, for both agents
        self.assertEqual((hub.history_behind(), hub.kv_get("history:tool")), (0, str(n)))
        self.assertEqual(self.refs(self.search("vps", query='"step 801"')), ["TR-801"])
        self.assertEqual(hub.q("SELECT * FROM log WHERE what LIKE 'history:%'"), [])

    def test_a_step_takes_no_row_past_its_budget_and_goes_on_from_the_next(self):
        """A step holds the hub's lock, and one row can be slow to mask (a long run of characters, many registered
        logins): a step of 400 such rows held it for seconds. Now a pass takes no row past its budget except its
        first, so that it moves, and the next pass goes on from the row after the last one taken: for a stream of rows,
        and for a stream of a moment whose rows share one time."""
        tid = self.task()
        notes = [hub.ins("INSERT INTO notes(task,agent,ts,text) VALUES(?,'vps',?,?)", (tid, self.clock, f"note {i}"))
                 for i in range(5)]
        questions = [hub.ins("INSERT INTO questions(task,asker,requester,text,asked,answer,answered) VALUES(?,'vps',"
                             "'manager',?,?,?,?)", (tid, f"question {i}", self.clock, f"answer {i}", self.clock))
                     for i in range(5)]
        mask = hub.mask_secrets

        def slow(text):
            time.sleep(0.02)
            return mask(text)

        def rows():
            return hub.q1("SELECT COUNT(DISTINCT src || ':' || src_id) n FROM history")["n"]

        taken, done = [], False
        with patch.object(hub, "mask_secrets", slow), \
                patch.object(hub, "HISTORY_STREAMS", [hub.HISTORY_BY_NAME["progress"], hub.HISTORY_BY_NAME["answer"]]):
            while not done and len(taken) < 40:
                before = rows()
                done = hub.history_catch_up(0.03)
                taken.append(rows() - before)
        self.assertTrue(done, taken)
        self.assertTrue(all(1 <= n <= 2 for n in taken), taken)          # 20 ms a note and 40 ms an answer
        self.assertEqual(sum(taken), 10)
        self.assertEqual(hub.q("SELECT src, src_id, agent FROM history GROUP BY src, src_id, agent "
                               "HAVING COUNT(*) > 1"), [])                # nothing twice, nothing left out
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM history WHERE src='answer'")["n"], 10)   # both agents' each
        self.assertEqual((hub.kv_get("history:progress"), hub.kv_get("history:answer")),
                         (str(notes[-1]), f"{float(self.clock)!r}:{questions[-1]}"))

    def test_a_stream_whose_filter_keeps_few_rows_reads_short_spans(self):
        """The fleet calls of an agent are mostly reads that the history leaves out: a step looks through at most
        HISTORY_SPAN ids, so the lock is never held for a scan of the whole table."""
        hub.DB.executemany("INSERT INTO calls(ts,agent,task,attempt,name,args,ok,detail) VALUES(?,'vps',1,1,"
                           "'list_my_tasks','{}',1,'')", [(self.clock,)] * (hub.HISTORY_SPAN + 5))
        hub.ins("INSERT INTO calls(ts,agent,task,attempt,name,args,ok,detail) VALUES(?,'vps',1,1,'gmail_send',?,1,"
                "'Sent.')", (self.clock, json.dumps({"subject": "The quarterly span report"})))
        passes = 0
        with patch.object(hub, "HISTORY_STREAMS", [hub.HISTORY_BY_NAME["call"]]):
            while not hub.history_catch_up(0):
                passes += 1
        self.assertEqual((passes, hub.kv_get("history:call")), (1, str(hub.HISTORY_SPAN + 6)))
        self.assertEqual(self.refs(self.search("vps", query="quarterly")), [f"CR-{hub.HISTORY_SPAN + 6}"])

    def test_a_record_written_while_no_index_ran_is_taken_in(self):
        """A release that does not index (the one before this, after a rollback) leaves rows past the cursors."""
        hub.history_catch_up()
        tid = self.task(title="Written while the older release ran")
        hub.ins("INSERT INTO notes(task,agent,ts,text) VALUES(?,'vps',?,'noted under the older release')",
                (tid, self.clock))
        self.assertEqual(self.refs(self.search("vps", query="older release")), [f"T-{tid}", f"T-{tid}"])

    def test_the_records_of_a_moment_are_indexed_when_they_happen(self):
        tid = self.task(owner="vps", requester="manager")
        qid = hub.ins("INSERT INTO questions(task,asker,requester,text,asked) VALUES(?,'vps','manager','Which "
                      "bucket?',?)", (tid, self.clock))
        rid = hub.ins("INSERT INTO reports(from_agent,from_task,to_agent,kind,text,severity,delivered,created,"
                      "request_id) VALUES('vps',?,'manager','risk','The backups stop in May','note','note',?,'u1')",
                      (tid, self.clock))
        mid = hub.ins("INSERT INTO memories(agent,about,text,prevents,created,request_id) VALUES('vps','backups',"
                      "'The bucket rotates keys monthly','a failed backup',?,'m1')", (self.clock,))
        hub.history_catch_up()
        self.clock += 60
        hub.q("UPDATE questions SET answer='The eu bucket', answered=? WHERE id=?", (self.clock, qid))
        hub.q("UPDATE reports SET decided=?, decided_by='manager', decision='task', became_task=? WHERE id=?",
              (self.clock, tid, rid))
        hub.q("UPDATE memories SET dropped=?, dropped_by='vps', drop_reason='the rotation is yearly' WHERE id=?",
              (self.clock, mid))
        hub.q("UPDATE tasks SET state='canceled', outcome='canceled', what='Not needed any more', delivered=? "
              "WHERE id=?", (self.clock, tid))
        for words, ref, kind in (('"eu bucket"', f"Q-{qid}", "question"), ('"decided by manager"', f"UP-{rid}", "report"),
                                 ("yearly", f"M-{mid}", "memory"), ('"not needed"', f"T-{tid}", "result")):
            for who in (("vps", "manager") if kind != "memory" else ("vps",)):
                found = self.search(who, query=words, kind=kind)
                self.assertEqual(self.refs(found), [ref], (who, found))
        self.assertIn("The bucket rotates keys monthly", self.read("vps", f"M-{mid}"))
        self.assertIn("forgotten by vps: the rotation is yearly", self.read("vps", f"M-{mid}"))

    def test_the_tick_indexes_quietly(self):
        self.task(title="Index me on the tick")
        before = hub.change_token()
        hub.history_sweep(self.clock)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM history")["n"], 2)
        self.assertEqual(hub.change_token(), before)                    # no change for the apps, not even activity
        self.task(title="And me")
        self.tick()
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM history")["n"], 4)

    def test_the_indexer_thread_ends_when_it_has_caught_up(self):
        with hub.LOCK:              # every commit holds the lock (hub.held)
            for i in range(hub.HISTORY_CHUNK + 3):
                hub.DB.execute("INSERT INTO notes(task,agent,ts,text) VALUES(1,'vps',?,?)", (self.clock, f"note {i}"))
            hub.commit()
        thread = threading.Thread(target=hub.history_indexer, daemon=True)
        thread.start()
        thread.join(30)
        self.assertFalse(thread.is_alive())
        self.assertEqual(hub.history_behind(), 0)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM history WHERE kind='note'")["n"], hub.HISTORY_CHUNK + 3)

    def test_one_record_it_cannot_read_does_not_hold_back_the_rest(self):
        tid = self.task()
        hub.ins("INSERT INTO thread_events(task,attempt,session,seq,ts,type,data,created) VALUES(?,1,?,1,?,"
                "'agent_message','not json',?)", (tid, SESSION, self.clock, self.clock))
        self.records(tid, [{"seq": 2, "type": "agent_message", "text": "the next record is fine"}])
        self.assertEqual(self.refs(self.search("vps", query="next record")), ["TR-2"])
        self.assertEqual(len(hub.q("SELECT * FROM log WHERE what LIKE 'history: tool 1 was not indexed%'")), 1)


class ToolRecords(Base):
    def test_what_a_session_did_is_indexed_and_what_was_typed_into_it_is_not(self):
        tid = self.task()
        call = lambda seq, cid, title, kind, server=None, **more: dict(
            {"seq": seq, "type": "tool_call", "tool_call_id": cid, "title": title, "kind": kind,
             "status": "in_progress", "server": server}, **more)
        done = lambda seq, cid, output: {"seq": seq, "type": "tool_call_update", "tool_call_id": cid,
                                         "status": "completed", "output": output}
        self.records(tid, [
            {"seq": 1, "type": "user_message", "text": "The owner says the alpaca plan is secret"},
            {"seq": 2, "type": "agent_thought", "text": "thinking about the alpaca plan"},
            call(3, "c1", "Bash: ./migrate.sh --apply", "execute"), done(4, "c1", "applied 12 migrations to zebra"),
            call(5, "c2", "Read config.yaml", "read", locations=[{"path": "/srv/app/config.yaml"}]),
            done(6, "c2", "secret_flamingo: yes"),
            call(7, "c3", "fleet: read_messages", "read", "fleet"), done(8, "c3", "[owner] the alpaca words"),
            call(9, "c4", "fleet: report_progress", "other", "fleet"), done(10, "c4", "Noted the koala."),
            call(11, "c5", "Edit hub.py", "edit", changes=[{"path": "/srv/app/hub.py", "action": "modify"}]),
            {"seq": 12, "type": "agent_message", "text": "Migrations applied; the gnu table is next"},
            {"seq": 13, "type": "error", "code": "api_error", "message": "the quokka API refused"},
            call(14, "c6", "acme-crm: list_tickets", "other", "acme-crm"), done(15, "c6", "ticket 7 from the wombat")])
        for words, ref in (("zebra", "TR-4"), ("migrate", "TR-3"), ("config.yaml", "TR-5"), ("hub.py", "TR-11"),
                           ("gnu", "TR-12"), ("quokka", "TR-13"), ("wombat", "TR-15")):
            self.assertIn(ref, self.refs(self.search("vps", query=words)), words)
        for words in ("alpaca", "flamingo", "koala"):
            self.assertIn("Nothing", self.search("vps", query=words), words)
        self.assertIn("Bash: ./migrate.sh --apply → applied 12 migrations to zebra", self.read("vps", "TR-4"))
        self.assertIn("is not in your history", self.read("vps", "TR-1"))      # what was typed into the session
        self.assertIn("is not in your history", self.read("vps", "TR-8"))      # a fleet tool's answer
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM history WHERE kind='tool' AND text IS NOT NULL")["n"], 0)

    def test_an_update_far_from_its_call_finds_it(self):
        tid = self.task()
        self.records(tid, [{"seq": 1, "type": "tool_call", "tool_call_id": "bg", "title": "Bash: npm run build",
                            "kind": "execute", "status": "in_progress"}])
        hub.history_catch_up()
        hub.HISTORY_CALL_CACHE.clear()                                          # a hub that restarted since
        self.records(tid, [{"seq": 2, "type": "tool_call_update", "tool_call_id": "bg", "status": "completed",
                            "output": "built in 41 seconds"}])
        self.assertIn("Bash: npm run build → built in 41 seconds", self.search("vps", query="41 seconds"))

    def test_a_fleet_call_that_acted_outside_is_a_tool_record(self):
        tid = self.task()
        args = {"task_id": f"T-{tid}", "request_id": "r1", "to": ["angela@example.com"], "subject": "The refund",
                "body": "The refund of order 88 is approved"}
        hub.ins("INSERT INTO calls(ts,agent,task,attempt,name,args,ok,detail) VALUES(?,'vps',?,1,'gmail_send',?,1,"
                "'Sent.')", (self.clock, tid, json.dumps(args)))
        hub.ins("INSERT INTO calls(ts,agent,task,attempt,name,args,ok,detail) VALUES(?,'vps',?,1,'list_my_tasks',"
                "'{}',1,'order 88')", (self.clock, tid))
        hub.ins("INSERT INTO calls(ts,agent,task,attempt,name,args,ok,detail) VALUES(?,'vps',?,1,'gmail_send',?,0,"
                "'Refused')", (self.clock, tid, json.dumps(dict(args, subject="order 88 again"))))
        found = self.search("vps", query='"order 88"')
        self.assertEqual(self.refs(found), ["CR-1"], found)
        self.assertIn("angela@example.com", self.read("vps", "CR-1"))
        self.assertIn("is not in your history", self.read("studio", "CR-1"))


class Keeping(Base):
    def test_a_rename_keeps_the_history_and_its_index(self):
        self.task(title="Tune the database")
        hub.history_catch_up()
        key = hub.history_key("vps")
        with hub.LOCK, hub.transaction():
            hub.rename_rows("vps", "leo", self.clock)
        hub.TEAM["agents"]["leo"] = hub.TEAM["agents"].pop("vps")
        self.assertEqual(hub.history_key("leo"), key)
        self.assertEqual(self.refs(self.search("leo", query="database")), ["T-1"])
        self.assertIn("task with leo", self.search("manager", query="database"))   # the other party follows too

    def test_a_removed_person_leaves_the_history_and_its_index(self):
        gone, stays = self.person("Gonzalo"), self.person("Stella")
        self.said(self.conversation(gone), "person", "My parrot order is late")
        self.said(self.conversation(stays), "person", "My parrot order arrived")
        hub.history_catch_up()
        with hub.LOCK:
            hub.person_remove(gone, self.clock)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM history WHERE person=?", (f"P-{gone}",))["n"], 0)
        self.assertEqual(self.refs(self.search("vps", query="parrot")), ["CM-2"])
        self.assertEqual(hub.q("SELECT rowid FROM history_fts WHERE history_fts MATCH 'late'"), [])

    def test_a_removal_leaves_no_deleted_id_behind_a_cursor(self):
        """SQLite gives a deleted newest id to the next row of its table, unless the writer takes ids above a floor
        (unused_id: the conversations, their messages and the needs have one since lane L2). A person's removal deletes
        their messages and their open Needs-you items. The message here is inserted as SQLite does it, as a release
        from before the floor writes it: it takes an id that its stream had read, and the removal moved the stream
        back, in the same write, so the history takes it in. The need is raised through the hub, which gives it a new
        id: the owner's N-<id> never names a removed item."""
        stays = self.conversation(self.person("Stella"))
        self.said(stays, "person", "My parrot order arrived")
        gone = self.person("Gonzalo")
        talk = self.conversation(gone)
        said = self.said(talk, "person", "My parrot order is late")
        need = hub.ins("INSERT INTO needs(title,why,raised,by,conversation) VALUES('A refund?','Gonzalo asks',?,"
                       "'vps',?)", (self.clock, talk))
        hub.history_catch_up()
        with hub.LOCK:
            hub.person_remove(gone, self.clock)
        self.assertEqual(self.said(stays, "person", "And the kayak came too"), said)       # the deleted id, again
        raised = hub.call_tool(hub.manager_name(), "raise_needs_you", {
            "title": "Renew the domain", "why": "It ends on Friday", "what_to_do": "Renew it at the registrar"})
        self.assertFalse(raised[1], raised[0])
        new = hub.q1("SELECT MAX(id) n FROM needs")["n"]
        self.assertGreater(new, need)
        self.assertEqual(self.refs(self.search("vps", query="kayak")), [f"CM-{said}"])
        self.assertEqual(self.refs(self.search(hub.manager_name(), query="domain")), [f"N-{new}"])

    def test_an_edited_message_is_indexed_as_it_reads_now(self):
        """The owner edits a message that nothing has read (edit_in_place), through his own route."""
        sent = self.command(recipient="studio", text="Ship the koala build tonight")
        self.assertEqual(self.request("/ui/messages", sent)[0], 200)
        hub.history_catch_up()
        self.assertEqual(self.refs(self.search("studio", query="koala")), ["OM-1"])
        edit = self.command(recipient="studio", text="Ship the panda build tonight",
                            replaces_request_id=sent["request_id"])
        code, done = self.request("/ui/messages", edit)
        self.assertEqual((code, done.get("edited")), (200, True), done)
        self.assertIn("Nothing", self.search("studio", query="koala"))
        self.assertEqual(self.refs(self.search("studio", query="panda")), ["OM-1"])
        self.assertEqual(hub.q("SELECT rowid FROM history_fts WHERE history_fts MATCH 'koala'"), [])

    def test_a_removal_takes_the_history_with_it_in_the_same_write_or_not_at_all(self):
        """The coordinator's condition: the index is contentless and gives words back from the record, so a record
        that is removed leaves the index in the write that removes it. That write fails whole, or it is whole."""
        gone = self.person("Gonzalo")
        self.said(self.conversation(gone), "person", "My parrot order is late")
        hub.history_catch_up()
        forget = hub.history_forget_person

        def then_fail(*args, **kwargs):
            forget(*args, **kwargs)
            raise RuntimeError("the write stops here")
        with patch.object(hub, "history_forget_person", then_fail), hub.LOCK, self.assertRaises(RuntimeError):
            hub.person_remove(gone, self.clock)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM conversation_messages")["n"], 1)      # nothing removed
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM history WHERE person=?", (f"P-{gone}",))["n"], 1)
        self.assertEqual(len(hub.q("SELECT rowid FROM history_fts WHERE history_fts MATCH 'parrot'")), 1)
        with hub.LOCK:
            hub.person_remove(gone, self.clock)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM history WHERE person=?", (f"P-{gone}",))["n"], 0)
        self.assertEqual(hub.q("SELECT rowid FROM history_fts WHERE history_fts MATCH 'parrot'"), [])

    def test_no_answer_gives_a_record_that_is_gone_or_different(self):
        """A lane that removes or changes a record and does not tell the history: a search and a read hold each row
        they find against its record as it reads now, so the old words are never answered."""
        words = ["alpha", "bravo", "charlie", "delta", "echo"]
        ids = [hub.ins("INSERT INTO agent_messages(sender,recipient,text,created,request_id) VALUES('vps','studio',"
                       "?,?,?)", (f"{w} message {i}", self.clock, f"r{i}")) for i, w in enumerate(words)]
        hub.history_catch_up()
        hub.q("DELETE FROM agent_messages WHERE id=?", (ids[0],))                    # alpha is gone
        hub.q("UPDATE agent_messages SET text='zulu message 1' WHERE id=?", (ids[1],))   # bravo is zulu now
        for who in ("vps", "studio"):
            for word in words + ["zulu", "message"]:
                found = self.search(who, query=word)
                for ref in self.refs(found):
                    row = hub.q1("SELECT text FROM agent_messages WHERE id=?", (int(ref[3:]),))
                    self.assertIsNotNone(row, (who, word, found))                    # never a record that is gone
                    self.assertIn(word, row["text"], (who, word, found))             # never one as it was
                    self.assertIn(row["text"], self.read(who, ref))
            self.assertEqual(self.refs(self.search(who, query="alpha bravo")), [])
            self.assertEqual(self.refs(self.search(who, query="zulu")), [f"AM-{ids[1]}"])
            self.assertIn("is not in your history", self.read(who, f"AM-{ids[0]}"))
        self.assertEqual(hub.q("SELECT rowid FROM history_fts WHERE history_fts MATCH 'alpha OR bravo'"), [])
        # a standing item whose words its holder changed (lane L3's set_target), read by its ref
        text, error = self.tool("vps", "set_target", measure="tickets answered within a day, in percent", number=90,
                                how="the CRM's ticket times", scope="agent")
        self.assertFalse(error, text)
        item = hub.q1("SELECT id FROM standing ORDER BY id DESC LIMIT 1")["id"]
        hub.history_catch_up()
        hub.q("UPDATE standing SET words='answer within two hours', measure='tickets answered within two hours' "
              "WHERE id=?", (item,))
        read = self.read("vps", hub.iref(item))
        self.assertIn("answer within two hours", read)
        self.assertNotIn("within a day", read)

    def test_a_person_removed_while_an_older_release_ran_leaves_at_the_start(self):
        gone = self.person("Gonzalo")
        self.said(self.conversation(gone), "person", "My parrot order is late")
        hub.history_catch_up()
        for table in ("conversation_messages", "conversations", "people"):        # as an older person_remove does
            hub.q(f"DELETE FROM {table}")
        hub.history_orphans()
        self.assertEqual(hub.q("SELECT * FROM history WHERE kind='conversation'"), [])
        self.assertEqual(hub.q("SELECT rowid FROM history_fts WHERE history_fts MATCH 'parrot'"), [])

    def test_a_registered_login_never_reaches_the_index(self):
        salt = "c0ffee"
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES('crm',?,?,?,'')",
                (salt, hashlib.sha256((salt + SECRET).encode()).hexdigest(), len(SECRET)))
        self.said(self.conversation(self.person("Mallory")), "person", f"Here is the password {SECRET} for the crm")
        found = self.search("vps", query="password crm")
        self.assertIn(hub.MASK, found)
        self.assertNotIn(SECRET, found + self.read("vps", "CM-1"))
        self.assertNotIn(SECRET, json.dumps([dict(r) for r in hub.q("SELECT * FROM history")]))
        blocks = b"".join(r["block"] for r in hub.q("SELECT block FROM history_fts_data"))
        self.assertIn(b"crm", blocks)                                   # the index holds the record's words
        self.assertNotIn(b"q2zr9", blocks)                              # and not the login's
        self.assertIn("Nothing", self.search("vps", query="pw q2zr9"))

    def test_a_long_record_is_read_for_logins_only_where_the_index_keeps_it(self):
        """A record is masked in the part that the index keeps, and in the run of characters that the cut falls in,
        whole: a login across the cut leaves no piece of itself behind, and the rest of a long record is not read, so
        masking a row inside a step costs what the part kept costs. The heal on read finds such a record unchanged."""
        salt = "c0ffee"
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES('crm',?,?,?,'')",
                (salt, hashlib.sha256((salt + SECRET).encode()).hexdigest(), len(SECRET)))
        cut = hub.HISTORY_TEXT
        head = ("words of a long brief " * (cut // 10))[:cut - 9] + " "      # the login starts 8 characters before it
        text = head + SECRET + " and then " + "more words " * 20000
        read, mask = [], hub.mask_secrets
        with patch.object(hub, "mask_secrets", lambda t: read.append(len(t)) or mask(t)):
            kept = hub.history_masked(text)
        self.assertEqual(read, [cut + 8])                               # to the end of the login, and no further
        self.assertEqual(kept, head + hub.MASK)                         # and not cut again
        self.assertEqual(hub.history_masked("short words"), "short words")
        tid = self.task(title="The long brief", details=text)
        self.assertIn(hub.tref(tid), self.refs(self.search("vps", query='"long brief"')))
        indexed = hub.q("SELECT id, text FROM history WHERE ref=?", (hub.tref(tid),))
        self.assertTrue(indexed and all(len(r["text"]) == cut for r in indexed), indexed)
        self.search("vps", query='"long brief"')
        self.assertEqual(hub.q("SELECT id, text FROM history WHERE ref=?", (hub.tref(tid),)), indexed)  # no heal
        self.assertNotIn(SECRET[:8], json.dumps([dict(r) for r in hub.q("SELECT * FROM history")]))

    def test_a_run_that_goes_on_past_the_cut_is_left_out_and_never_read_whole(self):
        """A record can be one long run of characters with no whitespace: a blob in a task's details, which have no
        size limit. Masking that run whole held the hub's lock for seconds. When the run that the cut falls in goes on
        more than HISTORY_RUN characters past the cut, it is left out from where it starts: masking reads at most
        HISTORY_TEXT + HISTORY_RUN characters, and no piece of a login in that run is kept."""
        salt = "c0ffee"
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES('crm',?,?,?,'')",
                (salt, hashlib.sha256((salt + SECRET).encode()).hexdigest(), len(SECRET)))
        mask, cut, room = hub.mask_secrets, hub.HISTORY_TEXT, hub.HISTORY_RUN
        for size in (cut, 100000, 300000):
            text = "The brief\n" + "A" * (cut - 50) + SECRET + "B" * size          # a login in the run, before the cut
            read = []
            with patch.object(hub, "mask_secrets", lambda t: read.append(len(t)) or mask(t)):
                kept = hub.history_masked(text)
            self.assertEqual((kept, read), ("The brief\n", [len("The brief\n")]), size)
        ends = "a " + "x" * (cut + room - 2)                         # a run that ends HISTORY_RUN past the cut is kept
        self.assertEqual(hub.history_masked(ends), ends)            # whole
        self.assertEqual(hub.history_masked(ends + "x"), "a ")      # and one character more is left out
        tid = self.task(title="The blob", details="A" * (cut - 50) + SECRET + "B" * 300000)
        self.assertEqual(self.refs(self.search("vps", query='"the blob"')), [hub.tref(tid)])
        self.assertEqual([r["text"] for r in hub.q("SELECT text FROM history WHERE ref=?", (hub.tref(tid),))],
                         [f"{hub.tref(tid)} The blob\n"] * 2)                # for the agent and its requester
        self.assertNotIn(SECRET[:8], json.dumps([dict(r) for r in hub.q("SELECT * FROM history")]))

    def test_a_login_registered_after_its_record_is_kept_whole_for_the_later_mask(self):
        """A login can be registered after its record was indexed, and scrub masks a row only where it finds a whole
        login. Until 11 November 2026 the masked words were cut again at HISTORY_TEXT, so a login in the run across the
        cut, or pushed across it by a mask longer than a login before it, stayed in the row in part. Now the row keeps
        it whole, a later scrub masks it, and a read indexes the row again with it masked."""
        salt, cut = "c0ffee", hub.HISTORY_TEXT
        later, early = "Later-Login-0123456789", "Ea7-Lgn9"            # the early login is shorter than the mask

        def register(login):
            hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES(?,?,?,?,'')",
                    ("crm" if login == later else "shop", salt, hashlib.sha256((salt + login).encode()).hexdigest(),
                     len(login)))

        words = "words of a long brief " * (cut // 10)
        across = words[:cut - 10] + " " + later + " and then more"
        pushed = early + " " + words[:cut - 7 - len(later) - len(early)] + " " + later + " and then more"
        self.assertEqual((across.index(later), pushed.index(later) + len(later)), (cut - 9, cut - 5))
        tid = self.task(title="The long brief")
        start = f"{hub.tref(tid)} The long brief\n"                     # how the task's record begins
        record = start + across[len(start):]                            # the login at the same place
        hub.q("UPDATE tasks SET details=? WHERE id=?", (record[len(start):], tid))
        register(early)                                                 # registered when the record is indexed
        hub.history_catch_up()
        kept = [hub.history_masked(across), hub.history_masked(pushed)]
        self.assertEqual(kept[0], across[:cut - 9 + len(later)])        # the run across the cut, whole
        self.assertEqual(kept[1], hub.MASK + pushed[len(early):cut])    # the later login now ends 13 past the cut
        for run, tail in (("abcdefg", " abc"), ("Ab3-Kq9z", " Ab3-Kq9z")):     # 7 characters: no login; 8: one can be
            self.assertEqual(hub.history_masked(words[:cut - 4] + " " + run + " more")[cut - 4:], tail)
        rows = [r["text"] for r in hub.q("SELECT text FROM history WHERE ref=?", (hub.tref(tid),))]
        self.assertEqual(rows, [record[:cut - 9] + later] * 2)          # for the agent and its requester
        register(later)
        self.assertEqual([hub.scrub(text) for text in kept + rows], [hub.MASK] * 4)
        code, shown = self.owner(ref=hub.tref(tid))
        self.assertEqual(code, 200, shown)
        self.assertNotIn(later[:6], json.dumps(shown))
        self.assertEqual([r["text"] for r in shown["records"]], [record[:cut - 9] + hub.MASK] * 2)
        self.assertNotIn(later[:6], json.dumps([dict(r) for r in hub.q("SELECT * FROM history")]))   # read again

    def test_a_row_that_an_older_release_cut_loses_the_run_it_ends_in(self):
        """A release before 11 November 2026 cut a long record's masked words at HISTORY_TEXT, so its row can end in
        part of a login registered later. history_heal indexes such a row again from its record, but never a moment's
        event (here a result) or a history_note row: so at the start the run that such a row of exactly HISTORY_TEXT
        characters ends in leaves the row and the index, NUL or not. A row that ends in a space, a shorter one and one
        that history_heal makes again stay. The next pass goes on from the last id: a row that an older release wrote
        after a rollback goes then."""
        cut, words = hub.HISTORY_TEXT, "words of a long result " * (hub.HISTORY_TEXT // 10)
        cut_in_run, nul = words[:cut - 9] + " Later-Lo", "\x00" + words[1:cut - 9] + " Later-Lo"
        self.assertEqual((len(cut_in_run), len(nul)), (cut, cut))

        def rows(*specs):                       # (src, text), as an older release wrote them, its words in the index
            with hub.LOCK, hub.transaction():
                key, ids = hub.history_key("vps", create=True), []
                for src, text in specs:
                    ids.append(hub.DB.execute("INSERT INTO history(agent,kind,ref,at,src,src_id,text) VALUES('vps',?,"
                                              "'T-9',?,?,9,?)", (src, self.clock, src, text)).lastrowid)
                    hub.DB.execute("INSERT INTO history_fts(rowid,text,agent) VALUES(?,?,?)", (ids[-1], text, key))
            return ids

        def texts(ids):
            return [hub.q1("SELECT text FROM history WHERE id=?", (i,))["text"] for i in ids]

        ids = rows(("result", cut_in_run), ("note", nul), ("result", words[:cut - 1] + " "),
                   ("result", "a short result"), ("task", cut_in_run))
        hub.history_recut()
        self.assertEqual(texts(ids), [words[:cut - 9].rstrip(), nul[:cut - 9].rstrip(), words[:cut - 1] + " ",
                                      "a short result", cut_in_run])
        match = "SELECT rowid FROM history_fts WHERE history_fts MATCH ? ORDER BY rowid"
        self.assertEqual([[r["rowid"] for r in hub.q(match, (w,))] for w in ("later", "result")], [[ids[4]], ids])
        after = rows(("result", cut_in_run))
        hub.history_recut()
        self.assertEqual(texts(ids[:1] + after), [words[:cut - 9].rstrip()] * 2)

    def test_a_standing_item_and_its_end_are_in_the_history(self):
        """Lane L3's items, as its own tools write them; one the owner gave is his words."""
        text, error = self.tool("vps", "keep_instruction", words="Answer refund mails in Spanish", scope="agent")
        self.assertFalse(error, text)
        text, error = self.tool("vps", "end_standing", id="I-1", why="the customers moved to English")
        self.assertFalse(error, text)
        self.assertEqual(self.refs(self.search("vps", query="refund spanish", kind="standing")), ["I-1", "I-1"])
        read = self.read("vps", "I-1")
        self.assertIn("I-1 instruction from vps: Answer refund mails in Spanish", read)
        self.assertIn("ended, as vps asked: the customers moved to English", read)
        with hub.LOCK, hub.transaction():
            hub.standing_new_rows("vps", {"scope": "agent", "kind": "instruction", "words": "Refunds go to Angela",
                                          "author_kind": "owner", "author": "owner"}, None, self.clock)
        self.assertIn("I-2", self.refs(self.search("vps", query="refunds")))
        driven = self.task(title="Answer a person")          # lane L2's column is in the schema since its push
        hub.q("UPDATE tasks SET source_conversation=1 WHERE id=?", (driven,))
        self.assertNotIn("I-2", self.refs(self.search("vps", task=driven, query="refunds")))

    def test_a_lane_writes_a_record_with_no_row_of_its_own(self):
        """history_note: what lanes L3 and L6 call for the end of a standing item and the removal of a lesson."""
        with hub.LOCK, hub.transaction():
            hub.history_note("vps", "standing", "I-7", "I-7 ended by Angela: refunds go back to her", task=None,
                             person="owner")
        self.assertEqual(self.refs(self.search("vps", query="refunds", kind="standing")), ["I-7"])
        self.assertIn("refunds go back to her", self.read("vps", "I-7"))
        with self.assertRaises(RuntimeError):
            hub.history_note("vps", "standing", "I-8", "outside a transaction")
        with hub.LOCK, hub.transaction(), self.assertRaises(ValueError):
            hub.history_note("vps", "gossip", "I-9", "an unknown kind")

    def test_without_fts5_the_search_reads_the_words_linearly(self):
        class NoFTS5:
            def __init__(self, db):
                self.db = db

            def execute(self, sql, *args):
                if "fts5" in sql:
                    raise sqlite3.Error("no such module: fts5")
                return self.db.execute(sql, *args)

            def __getattr__(self, name):
                return getattr(self.db, name)

        fresh = sqlite3.connect(":memory:", check_same_thread=False)
        fresh.row_factory = sqlite3.Row
        with patch.object(hub, "DB", NoFTS5(fresh)), patch.object(hub, "HISTORY_FTS", [None]), \
                patch.object(hub, "MEMORY_FTS", [None]):
            self.assertEqual(hub.build_schema(), [])          # a missing module is no refused schema step
            self.assertFalse(hub.HISTORY_FTS[0])
        with patch.object(hub, "HISTORY_FTS", [False]):
            tid = self.task(title="Renew the TLS certificate")
            self.records(tid, [{"seq": 1, "type": "agent_message", "text": "The certificate renews on Friday"}])
            found = self.search("vps", query="certificate friday")
            self.assertEqual(self.refs(found), ["TR-1", f"T-{tid}"], found)
            self.assertEqual(hub.q1("SELECT COUNT(*) n FROM history WHERE text IS NULL")["n"], 0)


class Tools(Base):
    def test_every_session_with_tools_has_them_and_a_window_of_a_person_or_the_owner_does_not(self):
        tid = self.task()
        names = lambda agent, context: {t["name"] for t in hub.tools_for(agent, context)}
        for agent, context in (("vps", ("test-generation", f"T-{tid}", 1)), ("manager", None)):
            self.assertLessEqual({"search_history", "read_history"}, names(agent, context))
        # T3 Code idea 9A (12 November 2026): the owner chat finds what the agent said there before
        self.assertLessEqual({"search_history", "read_history"}, names("vps", ("test-generation", "owner-chat", 1)))
        person = self.person("Bruno")
        hub.ins("INSERT INTO person_agents(person,agent,added) VALUES(?,'vps',?)", (person, self.clock))
        talk = self.conversation(person)
        self.assertFalse({"search_history", "read_history"} & names("vps", ("test-generation", "conversation", str(talk))))
        read_only = {t["name"]: t["annotations"]["readOnlyHint"] for t in hub.tools_for("manager", None)}
        self.assertTrue(read_only["search_history"] and read_only["read_history"])

    def test_the_moment_an_agent_looks_back_names_the_search(self):
        tid = self.task()
        follows = hub.ins("INSERT INTO tasks(title,owner,requester,state,created,attempt,follows) "
                          "VALUES('Again','vps','manager','working',?,1,?)", (self.clock, tid))
        text, _ = self.tool("vps", "see_earlier_work", task=follows, search="nothing like this")
        self.assertIn("search_history", text)
        text, _ = self.tool("vps", "recall", task=follows, search="nothing like this")
        self.assertIn("search_history", text)


if __name__ == "__main__":
    unittest.main()

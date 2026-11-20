"""A read of the state that does not grow with the Needs-you items, the reports, the messages and the steps of the
duties' cases (owner API 1.258, the lane "A bound for the rest of the state page").

The window of the tasks (owner API 1.254) left those parts of `GET /ui/state` with every row. On the first fleet, on
20 November 2026, they were 1.4 MB of a window read of 2.63 MB, and they grew by about 0.15 MB a day: the Mac app reads
at most 16,000,000 bytes of the answer. With `rest=window` the answer holds the items that are open and the items,
reports and messages of the newest keys, and `GET /ui/older` gives the others in blocks, each with a mark that moves
when the block's answer changes. The iPhone reads the ended heads of what the owner asked for in one chat. This file
holds:

- the window and the blocks together are the whole lists, row for row and in their order, and a window read's duties
  are the whole state's without the steps of their cases: an app that keeps the blocks shows what it showed;
- a window read has the same size after 600 more rows of the three lists and more cases and steps, while the whole
  answer grows with them;
- a block's mark moves at each change of its answer, also of a value that comes from the team (a resource's title in a
  grant line, a chat app's label), and a write that leaves the old rows as they are moves none;
- the window moves up one block at a time, and the rows that leave it are in the block below it at once;
- a start that changes nothing makes no trigger; a hub whose marks are not in place gives every row;
- the iPhone's ended read of a chat holds the heads of the asks of that chat from a time on, and no other.

    python3 -m unittest -v test_older_rows
"""
import http.client
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

import hub
# not `from test_state_read import StateCase`: a test class among this module's names runs all its tests here again
import test_state_read
from test_state_read import T0
from test_ui_api import PATIENCE

LISTS = ("needs", "reports", "messages")
DB = "test-generation"


def load_tests(loader, _tests, _pattern):
    """Only this file's checks: the harness comes from OwnerAPI, its own tests stay in its own file."""
    suite = unittest.TestSuite()
    for cls in (Together, Bound, Marks, Schema, Phone):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


def ordered(name, rows):
    """The rows of one list in the order of the whole state: by id, and the messages by their time and request id."""
    if name == "messages":
        return sorted(rows, key=lambda m: (m["created"], m["request_id"]))
    return sorted(rows, key=lambda r: r["id"])


class RowsCase(test_state_read.StateCase):
    """A hub with small blocks (BLOCK keys) and a small window (KEEP keys) for each list, so that a few rows make
    several blocks. The triggers take the block size when the records are made, so the numbers stand before setUp."""
    KEEP, BLOCK = 3, 4

    def setUp(self):
        for table in (hub.ROWS_KEEP, hub.ROWS_BLOCK):
            sized = patch.dict(table, {name: self.KEEP if table is hub.ROWS_KEEP else self.BLOCK for name in LISTS})
            sized.start()
            self.addCleanup(sized.stop)
        self.addCleanup(hub.ROWS.update, on=False)      # the next test's own records say it again
        super().setUp()
        hub.TEAM["logins"] = {"shop-key": {"title": "Shop key"}}

    def get(self, path):
        status, answer = self.request(path)
        self.assertEqual(status, 200, answer)
        return answer

    def window(self):
        return self.get("/ui/state?rest=window")

    def blocks(self, name):
        """{the first key of a block: its answer}, of every block of one list that its list names."""
        listed = self.get(f"/ui/older?db={DB}&list={name}")
        return {b["from"]: self.get(f"/ui/older?db={DB}&list={name}&from={b['from']}") for b in listed["blocks"]}

    def marks(self, name):
        """({the first key of a block: its mark}, the mark of them all as the state says it), of one list."""
        listed = self.get(f"/ui/older?db={DB}&list={name}")
        head = self.window()["older_rows"][name]
        self.assertEqual({k: listed[k] for k in head}, head, "the list's head is the state's older_rows")
        return {b["from"]: b["mark"] for b in listed["blocks"]}, head["mark"]

    # ---- rows of the three lists
    def need(self, answered=True, title="An item", why="the owner decides"):
        return hub.ins("INSERT INTO needs(title,why,todo,raised,by,answer,answered) VALUES(?,?,?,?,?,?,?)",
                       (title, why, "say yes", T0 - 500, "manager", "Yes" if answered else None,
                        T0 - 400 if answered else None))

    def message(self, text="hello", recipient="manager", origin=None, read=True, created=None):
        """A message of the owner with its event; returns its request id."""
        n = hub.q1("SELECT COUNT(*) AS n FROM ui_requests")["n"] + 1
        created = T0 - 300 + n if created is None else created
        event = hub.ins("INSERT INTO events(agent,kind,task,text,created,extra,read_at) VALUES(?,?,?,?,?,?,?)",
                        (recipient, "say", None, text, created, "{}", created + 1 if read else None))
        request = f"msg-{n:04d}"
        hub.ins("INSERT INTO ui_requests(request_id,kind,text,event_id,created,client,recipient,origin) "
                "VALUES(?,?,?,?,?,?,?,?)", (request, "message", text, event, created, "mac-app", recipient,
                                            json.dumps(origin) if origin else None))
        return request

    def report(self, text="report", about="the export", agent="manager", created=None):
        n = hub.q1("SELECT COUNT(*) AS n FROM owner_reports")["n"] + 1
        return hub.ins("INSERT INTO owner_reports(text,about,created,agent,in_reply_to,pushed) VALUES(?,?,?,?,?,?)",
                       (text, about, T0 - 200 + n if created is None else created, agent, None, 0))

    def fill_rows(self):
        """Rows of each list below the window and in it: answered and open items with a discussion, reports with a
        delivery, a file and a grant line, messages with files, a chat app's origin and an earlier text."""
        self.fill()
        self.items = [self.need(answered=n % 3 != 0, title=f"Item {n}") for n in range(12)]
        hub.ins("INSERT INTO need_talk(need,ts,who,text,request_id) VALUES(?,?,?,?,?)",
                (self.items[1], T0 - 450, "owner", "why this one?", "talk-old"))
        self.grant = self.report(text="Gave mia the shop key", about="grant secret:shop-key to mia")
        hub.ins("INSERT INTO resource_grants(ts,resource,agent,level,by) VALUES(?,?,?,?,?)",
                (hub.q1("SELECT created FROM owner_reports WHERE id=?", (self.grant,))["created"], "secret:shop-key",
                 "mia", "use", "manager"))
        self.reports = [self.report(text=f"report {n}") for n in range(12)]
        hub.ins("INSERT INTO chat_out(kind,app,account,chat,text,state,created,updated,report,request_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)", ("message", "whatsapp", "wa1", "c1", "report 1", "sent", T0 - 190,
                                                T0 - 180, self.reports[1], "out-old"))
        hub.ins("INSERT INTO attachments(request_id,name,mime,size,sha256,created,client,report) "
                "VALUES(?,?,?,?,?,?,?,?)", ("file-report", "chart.png", "image/png", 99, "cd" * 32, T0 - 180,
                                            "agent/manager", self.reports[2]))
        origin = {"app": "whatsapp", "account": "wa1", "chat": "c1"}
        self.messages = [self.message(text=f"message {n}", origin=origin if n == 2 else None, read=n != 3)
                         for n in range(12)]
        hub.ins("INSERT INTO attachments(request_id,name,mime,size,sha256,created,client,message) "
                "VALUES(?,?,?,?,?,?,?,?)", ("file-message", "plan.pdf", "application/pdf", 1234, "ab" * 32, T0 - 299,
                                            "mac-app", self.messages[1]))
        hub.q("UPDATE ui_requests SET edits=? WHERE request_id=?",
              (json.dumps([{"request_id": "e-1", "text": "first words", "at": T0 - 100}]), self.messages[4]))


class Together(RowsCase):
    def test_the_window_and_the_blocks_together_are_the_whole_lists(self):
        """An app that keeps the blocks beside its window read holds every item, report and message that the whole
        state holds, once, with the same values and in the same order: its Needs-you board, its chats and its search
        read the rows that they read before. The duties are the whole state's without the steps of their cases, and
        every other part is as it was."""
        self.fill_rows()
        open_old = self.items[0]            # open, below the window
        whole, window = self.get("/ui/state"), self.window()
        self.assertNotIn("older_rows", whole, "a reader that does not ask reads no blocks")
        for name in LISTS:
            blocks = self.blocks(name)
            before = window["older_rows"][name]["before"]
            self.assertGreater(len(blocks), 1, name)
            pieces = [row for block in blocks.values() for row in block[name]]
            self.assertEqual(ordered(name, window[name] + pieces), whole[name], name)
            self.assertEqual(window[name], ordered(name, window[name]), f"{name}: the window keeps the whole order")
            self.assertEqual(window["older_rows"][name]["rows"], len(pieces), name)
            self.assertEqual(sum(b["rows"] for b in self.get(f"/ui/older?db={DB}&list={name}")["blocks"]), len(pieces))
            self.assertTrue(all(b["from"] < before for b in self.get(f"/ui/older?db={DB}&list={name}")["blocks"]))
        self.assertIn(open_old, [n["id"] for n in window["needs"]], "an open item stays in the window")
        self.assertTrue(all(n["answer"] is not None for b in self.blocks("needs").values() for n in b["needs"]))
        kept = {m["request_id"]: m for b in self.blocks("messages").values() for m in b["messages"]}
        self.assertEqual([f["name"] for f in kept[self.messages[1]]["attachments"]], ["plan.pdf"])
        self.assertEqual(kept[self.messages[2]]["origin"]["label"], "Shop phone")
        self.assertEqual(kept[self.messages[4]]["edited"], T0 - 100)
        said = {r["id"]: r for b in self.blocks("reports").values() for r in b["reports"]}
        self.assertEqual(said[self.grant]["grant"]["title"], "Shop key")
        self.assertEqual(said[self.reports[1]]["delivery"]["state"], "sent")
        self.assertEqual([f["name"] for f in said[self.reports[2]]["attachments"]], ["chart.png"])
        steps = [c.pop("steps") for d in whole["responsibilities"]
                 for c in d["cases"] + d["joined"] + [d["last_case"] or {"steps": []}]]
        self.assertTrue(any(steps), "the fixture's cases have steps")
        self.assertEqual(window["responsibilities"], whole["responsibilities"], "the duties, without their steps")
        rest = set(whole) - set(LISTS) - {"responsibilities"}
        self.assertEqual({k: window[k] for k in rest}, {k: whole[k] for k in rest}, "every other part is as it was")
        both = self.get("/ui/state?tasks=window&rest=window")
        self.assertEqual(sorted(both["older_rows"]), sorted(LISTS))
        self.assertIn("older_tasks", both, "the two windows go together")

    def test_a_read_of_the_blocks_names_its_generation_its_list_and_a_block_of_it(self):
        self.fill_rows()
        self.assertEqual(self.request("/ui/older?db=another&list=needs")[0], 409, "a read names its generation")
        self.assertEqual(self.request("/ui/older?list=needs")[0], 409)
        self.assertEqual(self.request(f"/ui/older?db={DB}")[0], 400, "a read names its list")
        self.assertEqual(self.request(f"/ui/older?db={DB}&list=tasks")[0], 400)
        self.assertEqual(self.request(f"/ui/older?db={DB}&list=needs&from=1")[0], 400, "no first key of a block")
        self.assertEqual(self.request(f"/ui/older?db={DB}&list=needs&from=x")[0], 400)
        before = self.window()["older_rows"]["reports"]["before"]
        self.assertEqual(self.request(f"/ui/older?db={DB}&list=reports&from={before}")[0], 404, "the window's own rows")
        self.assertEqual(self.request(f"/ui/older?db={DB}&list=reports&from={before - self.BLOCK}")[0], 200)


class Bound(test_state_read.StateCase):
    """With the hub's own numbers."""

    def body(self, path):
        """The plain bytes of one GET: no Accept-Encoding, so no compression."""
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=PATIENCE)
        try:
            conn.putrequest("GET", path, skip_accept_encoding=True)
            conn.endheaders()
            answer = conn.getresponse()
            body = answer.read()
            self.assertEqual((answer.status, answer.getheader("Content-Encoding")), (200, None))
            return body
        finally:
            conn.close()

    def grow(self, count):
        """count more answered items, reports and messages, each with 1,000 characters of text, closed cases of the
        first duty with a step each, and a step more on each of its open cases."""
        with hub.transaction():
            x = hub.DB.execute
            for _ in range(count):
                x("INSERT INTO needs(title,why,todo,raised,by,answer,answered,details) VALUES(?,?,?,?,?,?,?,?)",
                  ("An item", "w" * 500, "say yes", T0 - 500, "manager", "Yes", T0 - 400, "d" * 500))
                x("INSERT INTO owner_reports(text,about,created,agent,in_reply_to,pushed) VALUES(?,?,?,?,?,?)",
                  ("r" * 1000, "the export", T0 - 200, "manager", None, 0))
                event = x("INSERT INTO events(agent,kind,task,text,created,extra,read_at) VALUES(?,?,?,?,?,?,?)",
                          ("manager", "say", None, "m", T0 - 300, "{}", T0 - 290)).lastrowid
                x("INSERT INTO ui_requests(request_id,kind,text,event_id,created,client,recipient) VALUES(?,?,?,?,?,?,?)",
                  (f"grow-{event}", "message", "m" * 1000, event, T0 - 300, "mac-app", "manager"))
                case = x("INSERT INTO duty_cases(responsibility,key,title,source,state,opened,by,closed,closed_by,"
                         "outcome,repeated) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                         (self.duties[0], f"grow/{event}", "an old case", "watch", "closed", T0 - 86400 * 9, "hub",
                          T0 - 86400 * 8, "mia", "handled", 0)).lastrowid
                x("INSERT INTO duty_steps(duty_case,key,text,task,by,ts) VALUES(?,?,?,?,?,?)",
                  (case, "a-look", "s" * 300, None, "mia", T0 - 86400 * 8))
                for open_case in hub.DB.execute("SELECT id FROM duty_cases WHERE state='open'").fetchall():
                    x("INSERT INTO duty_steps(duty_case,key,text,task,by,ts) VALUES(?,?,?,?,?,?)",
                      (open_case[0], f"k-{event}", "s" * 300, None, "mia", T0 - 50))

    def test_a_window_read_does_not_grow_with_the_rows(self):
        """The bound that the Mac app and the owner's tools need: 400 more items, reports and messages of 1,000
        characters each, 400 more closed cases with a step, and 400 more steps on each open case add nothing to a
        window read of the state but digits, while the whole answer takes them all. The window holds the rows of at
        most ROWS_KEEP + ROWS_BLOCK - 1 keys of each list, and the open items: both reads are at the same point of a
        block (250 and 650 keys), as test_older_tasks.Bound reads them."""
        self.fill()
        self.grow(250 - hub.q1("SELECT MAX(id) AS top FROM owner_reports")["top"])
        few, whole_few = self.body("/ui/state?tasks=window&rest=window"), self.body("/ui/state")
        self.grow(400)
        many, whole_many = self.body("/ui/state?tasks=window&rest=window"), self.body("/ui/state")
        self.assertLess(abs(len(many) - len(few)), 2000, "the same window, some keys and counts one digit longer")
        self.assertGreater(len(whole_many) - len(whole_few), 400 * 3000, "the whole answer holds each new row")
        answer = json.loads(many)
        for name in LISTS:
            most = hub.ROWS_KEEP[name] + hub.ROWS_BLOCK[name] - 1
            kept = [r for r in answer[name] if name != "needs" or r["answer"] is not None]
            self.assertTrue(hub.ROWS_KEEP[name] <= len(kept) <= most, (name, len(kept)))
            self.assertGreater(answer["older_rows"][name]["rows"], 400, name)
        self.assertEqual(len(json.loads(whole_many)["messages"]), hub.q1("SELECT COUNT(*) AS n FROM ui_requests")["n"])

    def test_a_reader_that_does_not_ask_reads_every_row(self):
        """An app from before this change sends no `rest`, and a reader may send words that the hub does not know: both
        read every row of the three lists, the steps of the cases, and no `older_rows`."""
        self.fill()
        self.grow(30)
        every = {name: hub.q1(f"SELECT COUNT(*) AS n FROM {table}")["n"]
                 for name, table in (("needs", "needs"), ("reports", "owner_reports"), ("messages", "ui_requests"))}
        for path in ("/ui/state", "/ui/state?tasks=window", "/ui/state?rest=all", "/ui/state?rest="):
            answer = json.loads(self.body(path))
            self.assertEqual(({name: len(answer[name]) for name in LISTS}, "older_rows" in answer), (every, False), path)
            self.assertTrue(any(c.get("steps") for d in answer["responsibilities"] for c in d["cases"]), path)


class Marks(RowsCase):
    def changes(self, name, write, moved, why):
        """Run `write`, and check for every block of one list: its mark moved when its answer changed, and it is
        `moved` that the answers changed at all. A mark that stands under a new answer leaves an app with old rows."""
        answers, (marks, head) = self.blocks(name), self.marks(name)
        write()
        after, (marked, headed) = self.blocks(name), self.marks(name)
        self.assertEqual(sorted(after), sorted(answers), why)
        changed = [start for start in answers
                   if {k: v for k, v in after[start].items() if k != "mark"}
                   != {k: v for k, v in answers[start].items() if k != "mark"}]
        self.assertEqual(bool(changed), moved, why)
        for start in answers:
            if start in changed:
                self.assertNotEqual(marked[start], marks[start], f"{why}: the block from {start}")
            self.assertEqual(after[start]["mark"], marked[start], "a block's answer says the mark of the list")
        # a write that changes no older row moves no mark at all: no app reads a block again for it
        self.assertEqual(headed != head, moved, f"{why}: the mark that the state says")
        if not moved:
            self.assertEqual(marked, marks, why)

    def test_a_mark_moves_when_its_block_changes(self):
        """Each write that changes an older row, or a row that its answer shows, moves the mark of its block and of
        the list; a write to a row of the window, or to an open item, changes no block. (A write that changes no value
        of an older row can move its mark: no trigger compares values, so none names a column that a later step could
        drop. An app then reads one block again.)"""
        self.fill_rows()
        q = hub.q
        open_old, answered, other = self.items[3], self.items[1], self.items[2]
        talk = hub.q1("SELECT id FROM need_talk WHERE request_id='talk-old'")["id"]
        newest_need = self.need(answered=True, title="In the window")
        for moved, why, write in (
            (True, "an open item below the window is answered", lambda: q(
                "UPDATE needs SET answer='No', answered=? WHERE id=?", (T0, open_old))),
            (True, "an answered item's words change (a person leaves)", lambda: q(
                "UPDATE needs SET why='removed words' WHERE id=?", (answered,))),
            (True, "a discussion line of an answered item", lambda: q(
                "INSERT INTO need_talk(need,ts,who,text,request_id) VALUES(?,?,?,?,?)",
                (answered, T0, "manager", "because", "talk-new"))),
            (True, "a line moves to another answered item", lambda: q("UPDATE need_talk SET need=? WHERE id=?",
                                                                      (other, talk))),
            (True, "a line leaves", lambda: q("DELETE FROM need_talk WHERE id=?", (talk,))),
            (True, "an answered item opens again", lambda: q("UPDATE needs SET answer=NULL WHERE id=?", (open_old,))),
            (True, "an answered item leaves", lambda: q("DELETE FROM needs WHERE id=?", (other,))),
            (False, "a write to an open item below the window", lambda: q(
                "UPDATE needs SET why='other' WHERE id=?", (self.items[6],))),
            (False, "a discussion line of an open item", lambda: q(
                "INSERT INTO need_talk(need,ts,who,text,request_id) VALUES(?,?,?,?,?)",
                (self.items[6], T0, "owner", "?", "talk-open"))),
            (False, "a write to an item of the window", lambda: q("UPDATE needs SET why='x' WHERE id=?", (newest_need,))),
        ):
            with self.subTest(why):
                self.changes("needs", write, moved, why)
        old, delivered, filed = self.reports[0], self.reports[1], self.reports[2]
        out = hub.q1("SELECT id FROM chat_out WHERE request_id='out-old'")["id"]
        file = hub.q1("SELECT id FROM attachments WHERE request_id='file-report'")["id"]
        record = hub.q1("SELECT id FROM resource_grants")["id"]
        for moved, why, write in (
            (True, "an old report's words change", lambda: q("UPDATE owner_reports SET text='removed' WHERE id=?", (old,))),
            (True, "its delivery is sent again", lambda: q("UPDATE chat_out SET state='failed', error='gone', updated=? "
                                                           "WHERE id=?", (T0, out))),
            (True, "a newer delivery of it", lambda: q(
                "INSERT INTO chat_out(kind,app,account,chat,text,state,created,updated,report,request_id) "
                "VALUES('message','whatsapp','wa1','c1','again','sent',?,?,?,'out-new')", (T0, T0, delivered))),
            (True, "that delivery leaves", lambda: q("DELETE FROM chat_out WHERE request_id='out-new'")),
            (False, "a chat_out row of no report's delivery", lambda: q(
                "INSERT INTO chat_out(kind,app,account,chat,text,state,created,updated,request_id) "
                "VALUES('message','whatsapp','wa1','c1','hi','sent',?,?,'out-none')", (T0, T0))),
            (True, "the owner keeps a file of a report", lambda: q("UPDATE attachments SET kept=5, knowledge='c.md' "
                                                                  "WHERE id=?", (file,))),
            (True, "the file goes to another report", lambda: q("UPDATE attachments SET report=? WHERE id=?",
                                                                (old, file))),
            (True, "the sweep removes it", lambda: q("DELETE FROM attachments WHERE id=?", (file,))),
            (True, "the grant's agent gets another name", lambda: q("UPDATE resource_grants SET agent='ana' WHERE id=?",
                                                                    (record,))),
            (True, "the grant's record leaves with its giver", lambda: q("DELETE FROM resource_grants WHERE id=?",
                                                                         (record,))),
            (True, "an old report leaves", lambda: q("DELETE FROM owner_reports WHERE id=?", (filed,))),
            (False, "a write to a report of the window", lambda: q(
                "UPDATE owner_reports SET text='x' WHERE id=(SELECT MAX(id) FROM owner_reports)")),
        ):
            with self.subTest(why):
                self.changes("reports", write, moved, why)
        first, with_file, read_later = self.messages[0], self.messages[1], self.messages[3]
        event = hub.q1("SELECT event_id FROM ui_requests WHERE request_id=?", (read_later,))["event_id"]
        message_file = hub.q1("SELECT id FROM attachments WHERE request_id='file-message'")["id"]
        steer_event = hub.ins("INSERT INTO events(agent,kind,task,text,created,extra) VALUES('mia','steer',7,'s',1,'{}')")
        for moved, why, write in (
            (True, "an old message's words change where it stands", lambda: q(
                "UPDATE ui_requests SET text='other words', edits=? WHERE request_id=?",
                (json.dumps([{"request_id": "e-2", "text": "x", "at": T0}]), first))),
            (True, "its agent reads it late", lambda: q("UPDATE events SET read_at=? WHERE id=?", (T0, event))),
            (False, "an event of no message is read", lambda: q("UPDATE events SET read_at=? WHERE id=?",
                                                                 (T0, steer_event))),
            (True, "the owner keeps its file", lambda: q("UPDATE attachments SET kept=5, knowledge='p.md' WHERE id=?",
                                                         (message_file,))),
            (True, "the file goes to another message", lambda: q("UPDATE attachments SET message=? WHERE id=?",
                                                                  (first, message_file))),
            (True, "a new file of an old message", lambda: q(
                "INSERT INTO attachments(request_id,name,mime,size,sha256,created,client,message) "
                "VALUES('file-new','late.pdf','application/pdf',5,?,1,'mac-app',?)", ("ef" * 32, with_file))),
            (True, "the sweep removes a file", lambda: q("DELETE FROM attachments WHERE id=?", (message_file,))),
            (True, "the event of a message leaves with its agent", lambda: q("DELETE FROM events WHERE id=?", (event,))),
            (True, "a new event takes that event's number", lambda: q(
                "INSERT INTO events(id,agent,kind,task,text,created,extra) VALUES(?,'manager','say',NULL,'x',1,'{}')",
                (event,))),
            (True, "an old message leaves", lambda: q("DELETE FROM ui_requests WHERE request_id=?", (with_file,))),
            (False, "a write to a message of the window", lambda: q(
                "UPDATE ui_requests SET text='x' WHERE rowid=(SELECT MAX(rowid) FROM ui_requests)")),
        ):
            with self.subTest(why):
                self.changes("messages", write, moved, why)

    def test_a_value_of_the_team_moves_the_marks_of_its_list(self):
        """A grant line shows its resource's title, and a message from a chat app shows the label of its account: both
        come from team.json, which no trigger sees. A new title moves the mark of every block of the reports, and a new
        label of every block of the messages, and of no block of another list: one digest of them all is in each mark,
        so that a window read reads no older row for it."""
        self.fill_rows()
        for name, change in (("reports", lambda: hub.TEAM["logins"]["shop-key"].update(title="The shop's key")),
                             ("messages", lambda: hub.TEAM["chat_apps"]["wa1"].update(label="Store phone"))):
            with self.subTest(name):
                before = {other: self.marks(other) for other in LISTS}
                change()
                for other in LISTS:
                    (marks, head), (marked, headed) = before[other], self.marks(other)
                    moved = {b for b in marks if marked[b] != marks[b]}
                    self.assertEqual((moved, headed != head), (set(marks), True) if other == name else (set(), False),
                                     (name, other))
        said = {r["id"]: r for b in self.blocks("reports").values() for r in b["reports"]}
        self.assertEqual(said[self.grant]["grant"]["title"], "The shop's key")
        kept = {m["request_id"]: m for b in self.blocks("messages").values() for m in b["messages"]}
        self.assertEqual(kept[self.messages[2]]["origin"]["label"], "Store phone")

    def test_a_login_that_is_registered_later_reaches_every_block(self):
        """A login can be registered after a text was stored, and the hub masks it from then on. A block that an app
        kept holds the text in plain, so every block of every list moves, and its new answer has the mask."""
        secret = "L4ter-Login!9090"
        self.fill_rows()
        hub.q("UPDATE owner_reports SET text=? WHERE id=?", (f"the key is {secret}", self.reports[0]))
        start = self.reports[0] // self.BLOCK * self.BLOCK
        before = {name: self.marks(name) for name in LISTS}
        held = {name: {b for b, block in self.blocks(name).items() if block[name]} for name in LISTS}
        self.assertIn(secret, json.dumps(self.blocks("reports")[start]))
        test_state_read.register(secret, "s9")
        for name in LISTS:                  # a block that holds no row has an empty answer, which no mask changes
            marks, head = before[name]
            marked, headed = self.marks(name)
            self.assertTrue(held[name] and all(marked[b] != marks[b] for b in held[name]), (name, marks, marked))
            self.assertNotEqual(headed, head, name)
        self.assertNotIn(secret, json.dumps(self.blocks("reports")[start]))
        kept, _ = self.marks("needs")
        for why, write in (("a login that keeps its value", lambda: hub.q("UPDATE secrets SET username='another'")),
                           ("a new key of the practice page", hub.practice_key)):
            write()
            self.assertEqual(self.marks("needs")[0], kept, why)

    def test_the_window_moves_up_one_block_and_the_rows_that_leave_it_are_in_a_block(self):
        """The window holds the KEEP newest keys at the least. When the newest key passes the next block, the rows of
        one block leave the window, the mark of the state says so, and the list names their block with those rows: an
        app that sees the new mark finds them at once."""
        for _ in range(self.KEEP + self.BLOCK - 2):
            self.report()
        first = self.window()
        self.assertEqual(first["older_rows"]["reports"]["before"], 0)
        self.assertEqual(self.get(f"/ui/older?db={DB}&list=reports")["blocks"], [])
        left = [r["id"] for r in first["reports"] if r["id"] < self.BLOCK]
        self.report()
        second = self.window()
        self.assertEqual(second["older_rows"]["reports"]["before"], self.BLOCK)
        self.assertNotEqual(second["older_rows"]["reports"]["mark"], first["older_rows"]["reports"]["mark"])
        self.assertEqual(len(second["reports"]), self.KEEP)
        self.assertEqual([r["id"] for r in self.blocks("reports")[0]["reports"]], left)
        self.assertEqual(second["older_rows"]["reports"]["rows"], len(left))


class Schema(RowsCase):
    def triggers(self):
        return {r["name"]: r["sql"] for r in hub.q("SELECT name, sql FROM sqlite_master WHERE type='trigger' AND name "
                                                   "LIKE 'row\\_block\\_%' ESCAPE '\\'")}

    def test_a_start_that_changes_nothing_makes_no_trigger_and_moves_no_mark(self):
        """Each start of the hub runs the schema again. A start must leave the marks as they are: else each release
        of the hub would make every app read every block again."""
        for _ in range(3 * self.BLOCK):
            self.need()
            self.report()
            self.message()
        marks, made = {name: self.marks(name) for name in LISTS}, self.triggers()
        self.assertEqual(len(made), len(hub.row_triggers()))
        ran = []
        hub.DB.set_trace_callback(ran.append)
        try:
            self.assertEqual(hub.migrate(), [])
        finally:
            hub.DB.set_trace_callback(None)
        self.assertEqual([s for s in ran if s.upper().startswith(("CREATE TRIGGER", "DROP TRIGGER"))], [])
        self.assertEqual(({name: self.marks(name) for name in LISTS}, self.triggers(), hub.ROWS["on"]),
                         (marks, made, True))

    def test_the_rows_of_before_this_change_get_their_blocks(self):
        """A hub that takes this release holds rows that came before the triggers. Its first start gives each of their
        blocks a mark and the number of its rows."""
        with hub.LOCK:
            for name in self.triggers():
                hub.DB.execute(f"DROP TRIGGER {name}")
            hub.DB.execute("DROP TABLE row_blocks")
            hub.commit()
        for _ in range(3 * self.BLOCK):
            self.need()
            self.report()
            self.message()
        self.assertEqual(hub.migrate(), [])
        for name in LISTS:
            listed = self.get(f"/ui/older?db={DB}&list={name}")
            self.assertEqual([(b["from"], b["rows"]) for b in listed["blocks"]],
                             [(0, self.BLOCK - 1), (self.BLOCK, self.BLOCK)], name)
            self.assertTrue(all(b["mark"].startswith(f"{self.BLOCK}.") and int(b["mark"].split(".")[1]) > 0
                                for b in listed["blocks"]), name)

    def test_a_column_can_be_dropped_after_the_triggers_that_name_it(self):
        """A trigger of these marks names columns of its own table and of others: the triggers of the grant records
        name a report's `about`, which SQLite then refuses to drop. older_unwatch of the reports takes every trigger of
        these marks away, and the next start makes them again and counts every block once."""
        for _ in range(3 * self.BLOCK):
            self.report()
        with self.assertRaises(sqlite3.OperationalError):
            hub.q("ALTER TABLE owner_reports DROP COLUMN about")
        hub.older_unwatch("owner_reports")
        marks, _ = self.marks("reports")
        hub.q("ALTER TABLE owner_reports DROP COLUMN about")
        self.assertEqual(self.triggers(), {})
        hub.q("ALTER TABLE owner_reports ADD COLUMN about TEXT NOT NULL DEFAULT ''")
        self.assertEqual(hub.migrate(), [])
        marked, _ = self.marks("reports")
        self.assertTrue(all(marked[b] != marks[b] for b in marks))
        self.assertEqual(len(self.triggers()), len(hub.row_triggers()))

    def test_a_release_that_changes_how_a_row_looks_counts_every_block_once(self):
        """A block that a reader kept stays with it until its mark moves, also on its disk. A release that adds a
        column to the items (their view gives every column), or changes a view of these rows in code, changes the
        answers of the older blocks with no write to a row: its first start counts every block once, and a start of
        the same release counts none."""
        for _ in range(3 * self.BLOCK):
            self.need()
            self.report()
            self.message()
        answers, marks = self.blocks("needs"), {name: self.marks(name)[0] for name in LISTS}
        hub.q("ALTER TABLE needs ADD COLUMN shade TEXT")
        self.assertEqual(hub.migrate(), [])
        moved = {name: self.marks(name)[0] for name in LISTS}
        self.assertTrue(all(moved[n][b] != marks[n][b] for n in LISTS for b in marks[n]), (marks, moved))
        self.assertNotEqual(self.blocks("needs"), answers, "the new column is in the older items' answers")
        self.assertEqual(hub.migrate(), [])
        self.assertEqual({name: self.marks(name)[0] for name in LISTS}, moved, "the same release counts nothing")
        with patch.object(hub, "ROWS_SHAPE", hub.ROWS_SHAPE + 1):     # a view that changed in code
            self.assertEqual(hub.migrate(), [])
            self.assertTrue(all(self.marks(n)[0][b] != moved[n][b] for n in LISTS for b in moved[n]))

    def test_the_shape_is_the_same_in_each_process(self):
        """The shape of the code is digested again at each start of the hub. A constant or a default value whose text
        holds an address, or follows the hash seed of its process (a set), would make each start of the same release
        count every block once, and each reader read every block again after each restart: two processes with other
        seeds give the same digests."""
        here = pathlib.Path(hub.__file__).resolve().parent
        said = set()
        for seed in ("1", "2"):
            done = subprocess.run([sys.executable, "-c", "import hub; print(hub.code_digest(('rows_read',)), "
                                   "hub.code_digest(('older_read',)))"], cwd=here, capture_output=True, text=True,
                                  timeout=120, env=dict(os.environ, PYTHONHASHSEED=seed))
            self.assertEqual(done.returncode, 0, done.stderr[-2000:])
            said.add(done.stdout.strip())
        self.assertEqual(len(said), 1, said)

    def test_a_hub_whose_marks_are_not_in_place_serves_every_row(self):
        """Without one of its triggers a block could change under a mark that stands. So a hub that could not make them
        serves no window: a reader that asks for one gets every row and no `older_rows`, and reads no block."""
        for _ in range(3 * self.BLOCK):
            self.report()
        every = hub.q1("SELECT COUNT(*) AS n FROM owner_reports")["n"]
        hub.q("DROP TRIGGER row_block_reports_update")
        real = hub.sql_step

        def refuses(sql, problems):
            if "CREATE TRIGGER row_block_reports_update " in sql:
                problems.append("row_block_reports_update: refused")
                return problems
            return real(sql, problems)

        with patch.object(hub, "sql_step", refuses):
            self.assertEqual(hub.migrate(), ["row_block_reports_update: refused"])
        status, answer = self.request("/ui/state?rest=window")
        self.assertEqual((status, len(answer["reports"]), "older_rows" in answer), (200, every, False))
        self.assertEqual(self.request(f"/ui/older?db={DB}&list=reports")[0], 404)
        self.assertEqual(hub.migrate(), [], "the next start makes it")
        self.assertIn("older_rows", self.window())


class Phone(RowsCase):
    def ended(self, path):
        return self.get(f"/ui/mobile/ended?db={DB}{path}")

    def test_the_ended_read_of_a_chat_holds_the_asks_of_its_lines_from_a_time_on(self):
        """The iPhone draws a row under each message of a chat that began an ask, from the heads of its tasks. It reads
        the ended ones for the chat that is open, from the oldest line that it holds of it: the answer has the ended
        tasks of the asks of that chat's messages from then on, and of a message that one of them corrects, and no
        other. A read without `chat` is every ended head, as the Windows app's Ended lane reads it."""
        old = self.message(text="an old ask", created=T0 - 900)
        corrected = self.message(text="a corrected ask", created=T0 - 800)
        held = self.message(text="a new ask", created=T0 - 100)
        correction = self.message(text="the correction", created=T0 - 50)
        hub.q("UPDATE ui_requests SET replaces_request_id=? WHERE request_id=?", (corrected.upper(), correction))
        other = self.message(text="mia's ask", recipient="mia", created=T0 - 40)
        tasks = {}
        for ask, state in ((old, "completed"), (corrected, "completed"), (held, "failed"), (held, "working"),
                           (other, "completed"), (None, "completed")):
            tasks[(ask, state)] = hub.ins(
                "INSERT INTO tasks(title,details,done_when,owner,requester,state,created,needs,attempt,ask) "
                "VALUES('Work','d','it is done','mia','manager',?,?,'none',1,?)", (state, T0, ask))
        hub.q("UPDATE ui_requests SET asked='The export' WHERE request_id=?", (held,))
        answer = self.ended(f"&chat=manager&from={T0 - 200}")
        self.assertEqual([t["id"] for t in answer["tasks"]],
                         [tasks[(corrected, "completed")], tasks[(held, "failed")]])
        self.assertEqual(answer["asked"], {held: "The export"})
        self.assertEqual(answer["mark"], self.get("/ui/mobile")["ended_mark"], "the mark of the main read")
        self.assertEqual(sorted(answer["tasks"][0]), sorted(hub.MOBILE_HEAD + ("trigger_id",)))
        self.assertEqual([t["id"] for t in self.ended(f"&chat=manager&from={T0 - 1000}")["tasks"]],
                         [tasks[(old, "completed")], tasks[(corrected, "completed")], tasks[(held, "failed")]])
        self.assertEqual([t["id"] for t in self.ended(f"&chat=mia&from={T0 - 1000}")["tasks"]],
                         [tasks[(other, "completed")]])
        self.assertEqual(len(self.ended("")["tasks"]), 5, "every ended head")
        self.assertEqual(self.request(f"/ui/mobile/ended?db={DB}&chat=manager&from=soon")[0], 400)
        self.assertEqual(self.request(f"/ui/mobile/ended?db={DB}&chat=manager&from=nan")[0], 400)

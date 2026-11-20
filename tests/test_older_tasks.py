"""A read of the state that does not grow with the tasks (owner API 1.254, the lane "A bound for the state page").

`GET /ui/state` held every task that the fleet ever had. On the first fleet, on 20 November 2026, that was 6.63 MB of
an answer of 8.88 MB for 1,528 tasks, and the answer grew by up to 1.5 MB a day: the owner's tools stopped at 8 MiB
on 19 November, and the Mac app reads at most 16,000,000 bytes of it.

With `tasks=window` the answer holds the tasks that have not ended and the ended tasks of the newest ids, and
`GET /ui/tasks/older` gives the others in blocks, each with a mark that moves when the block's answer changes. This
file holds:

- the window and the blocks together are the whole state, row for row, for a database with every part of the state:
  an app that keeps the blocks shows what it showed before;
- a window read has the same size after 400 more ended tasks, while the whole answer grows with them;
- a block's mark moves at each change of its answer, and at no write that leaves its answer as it was: an app reads
  a block again when it must, and only then;
- the window moves up one block at a time, and the tasks that leave it are in the block below it at once;
- a reader that does not ask, and a hub whose marks are not in place, get the whole state as before.

    python3 -m unittest -v test_older_tasks
"""
import http.client
import json
import re
import sqlite3
import unittest
from unittest.mock import patch

import hub
# not `from test_state_read import StateCase`: a test class among this module's names runs all its tests here again
import test_state_read
from test_ui_api import PATIENCE

PARTS = ("tasks", "notes", "permissions", "holds", "outcomes", "steers")
DB = "test-generation"


def load_tests(loader, _tests, _pattern):
    """Only this file's checks: the harness comes from OwnerAPI, its own tests stay in its own file."""
    suite = unittest.TestSuite()
    for cls in (Together, OwnMoment, Bound, Marks, Schema):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class OlderCase(test_state_read.StateCase):
    """A hub with small blocks (BLOCK ids) and a small window (KEEP ids), so that a few tasks make several blocks.
    The triggers take the block size when the records are made, so the two numbers stand before setUp makes them."""
    KEEP, BLOCK = 3, 4

    def setUp(self):
        for name, value in (("STATE_KEEP", self.KEEP), ("TASK_BLOCK", self.BLOCK)):
            sized = patch.object(hub, name, value)
            sized.start()
            self.addCleanup(sized.stop)
        self.addCleanup(hub.OLDER.update, on=False)     # the next test's own records say it again
        super().setUp()

    def get(self, path):
        status, answer = self.request(path)
        self.assertEqual(status, 200, answer)
        return answer

    def window(self):
        return self.get("/ui/state?tasks=window")

    def blocks(self):
        """{the first id of a block: its answer}, of every block that the list names."""
        listed = self.get(f"/ui/tasks/older?db={DB}")
        return {b["from"]: self.get(f"/ui/tasks/older?db={DB}&from={b['from']}") for b in listed["blocks"]}

    def marks(self):
        """({the first id of a block: its mark}, the mark of them all as the state says it)."""
        listed = self.get(f"/ui/tasks/older?db={DB}")
        head = self.window()["older_tasks"]
        self.assertEqual({k: listed[k] for k in head}, head, "the list's head is the state's older_tasks")
        return {b["from"]: b["mark"] for b in listed["blocks"]}, head["mark"]

    def task(self, state="completed", parent=None, title="Work", details="d"):
        return hub.ins("INSERT INTO tasks(title,details,done_when,owner,requester,state,created,needs,attempt,parent) "
                       "VALUES(?,?,?,?,?,?,?,'none',1,?)",
                       (title, details, "it is done", "mia", "manager", state, hub.now(), parent))

    def note(self, task, text="a note"):
        return hub.ins("INSERT INTO notes(task,agent,ts,text) VALUES(?,?,?,?)", (task, "mia", hub.now(), text))


class Together(OlderCase):
    def test_the_window_and_the_blocks_together_are_the_whole_state(self):
        """An app that keeps the blocks beside its window read holds every row that the whole state holds, once, with
        the same values: its board, its search, its chats and its task pages read the rows that they read before."""
        self.fill()
        talk = hub.ins("INSERT INTO conversations(agent,contact,created,updated) VALUES('mia','pat',?,?)",
                       (hub.now(), hub.now())) if self.has("conversations", "contact") else 1
        top = self.task(state="working", title="A person's conversation opened this")
        hub.q("UPDATE tasks SET source_conversation=? WHERE id=?", (talk, top))
        part = self.task(state="completed", parent=top, title="An ended part of it")
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (top,))
        self.rows_of(part)      # a row of each of the five kinds, and a file of its steer: a block gives them all
        early = hub.q1("SELECT MIN(id) AS id FROM tasks WHERE state='working'")["id"]       # open, below the window
        self.note(early, "a note of an open task that is older than the window")
        self.note(None, "a note of no task")
        self.note(99999, "a note of a task that is gone")
        self.note(-3, "a note of a number that is no task")
        for _ in range(3 * self.BLOCK):         # the window moves up, past the conversation's two tasks
            self.task()
        whole, window, blocks = self.get("/ui/state"), self.window(), self.blocks()
        before = window["older_tasks"]["before"]
        self.assertGreater(before, part, "the fixture puts the conversation's tasks below the window")
        self.assertGreater(len(blocks), 2)
        self.assertNotIn("older_tasks", whole, "a reader that does not ask reads no blocks")
        for key in PARTS:
            pieces = [window[key]] + [block[key] for block in blocks.values()]
            together = sorted((row for piece in pieces for row in piece), key=lambda row: row["id"])
            self.assertEqual([row["id"] for row in together], [row["id"] for row in whole[key]], key)
            self.assertEqual(together, whole[key], key)
            self.assertTrue(whole[key], f"the fixture has rows in {key}")
        for start, block in blocks.items():
            self.assertTrue(all(start <= t["id"] < start + self.BLOCK and t["state"] in hub.TERMINAL + (None,)
                                for t in block["tasks"]), start)        # the fixture has a task with no state
        self.assertIn(early, [t["id"] for t in window["tasks"]], "a task that has not ended stays in the window")
        self.assertTrue(all(t["id"] >= before or t["state"] not in hub.TERMINAL for t in window["tasks"]))
        kept = {t["id"]: t for block in blocks.values() for t in block["tasks"]}
        self.assertIs(kept[part]["from_conversation"], True, "through the task above it, which the block also holds")
        block = next(b for b in blocks.values() if part in [t["id"] for t in b["tasks"]])
        for key in PARTS[1:]:
            self.assertEqual([row["task"] for row in block[key] if row["task"] == part], [part], key)
        self.assertEqual([f["name"] for s in block["steers"] for f in s["attachments"]], ["plan.pdf"])
        self.assertEqual(window["older_tasks"]["tasks"], len(kept))
        self.assertEqual(sum(b["tasks"] for b in self.get(f"/ui/tasks/older?db={DB}")["blocks"]), len(kept))
        rest = set(whole) - set(PARTS)
        self.assertEqual({k: window[k] for k in rest}, {k: whole[k] for k in rest}, "every other part is as it was")

    def rows_of(self, task):
        """A note, a permission, a hold, an outcome and a steer with a file, all of this task."""
        self.note(task, "a note of an ended task")
        hub.ins("INSERT INTO prompts(task,agent,tool,input,key,created) VALUES(?,'mia','Bash','{}','k-part',1)", (task,))
        hold = hub.ins("INSERT INTO holds(task,kind,by,note,state,created,attempt) VALUES(?,'stop','owner','held',"
                       "'released',1,1)", (task,))
        hub.ins("INSERT INTO outcomes(task,attempt,hold,tool_call_id,title,kind,state,created) "
                "VALUES(?,1,?,'call-part','a send','send','resolved',1)", (task, hold))
        event = hub.ins("INSERT INTO events(agent,kind,task,text,created,extra,read_at) "
                        "VALUES('mia','steer',?,'a steer',1,'{}',2)", (task,))
        hub.ins("INSERT INTO steers(task,attempt,text,event_id,request_id,client,created) "
                "VALUES(?,1,'Do it so',?,'steer-part','mac-app',1)", (task, event))
        hub.ins("INSERT INTO attachments(request_id,name,mime,size,sha256,created,client,message) "
                "VALUES('file-part','plan.pdf','application/pdf',1234,?,1,'mac-app','steer-part')", ("ab" * 32,))

    def has(self, table, column):
        try:
            return column in {r["name"] for r in hub.q(f"PRAGMA table_info({table})")}
        except sqlite3.Error:
            return False

    def test_a_task_above_the_block_says_that_a_conversation_opened_its_part(self):
        """from_conversation of an ended part is true when the task that it is a part of is in no answer with it: the
        window holds the part and not the task above it, and so does a block of another id range."""
        top = self.task(state="completed", title="A person's conversation opened this")
        hub.q("UPDATE tasks SET source_conversation=7 WHERE id=?", (top,))
        for _ in range(2 * self.BLOCK):
            self.task()
        far = self.task(state="completed", parent=top)          # in another block than the task above it
        for _ in range(self.BLOCK):
            self.task()
        late = self.task(state="working", parent=far)           # in the window, two tasks under the conversation
        window, blocks = self.window(), self.blocks()
        self.assertNotIn(top, [t["id"] for t in window["tasks"]])
        self.assertIs({t["id"]: t for t in window["tasks"]}[late]["from_conversation"], True)
        block = next(b for b in blocks.values() if far in [t["id"] for t in b["tasks"]])
        self.assertNotIn(top, [t["id"] for t in block["tasks"]])
        self.assertIs({t["id"]: t for t in block["tasks"]}[far]["from_conversation"], True)

    def test_a_read_of_the_blocks_names_its_generation_and_a_block_of_the_list(self):
        for _ in range(3 * self.BLOCK):
            self.task()
        self.assertEqual(self.request("/ui/tasks/older?db=another")[0], 409, "a read names the generation it holds")
        self.assertEqual(self.request("/ui/tasks/older")[0], 409)
        self.assertEqual(self.request(f"/ui/tasks/older?db={DB}&from=1")[0], 400, "no first id of a block")
        self.assertEqual(self.request(f"/ui/tasks/older?db={DB}&from=x")[0], 400)
        before = self.window()["older_tasks"]["before"]
        self.assertEqual(self.request(f"/ui/tasks/older?db={DB}&from={before}")[0], 404, "the window's own tasks")
        self.assertEqual(self.request(f"/ui/tasks/older?db={DB}&from={before - self.BLOCK}")[0], 200)


class OwnMoment(OlderCase):
    """The hub reads the state and a block from a read connection of their own moment (hub.state_moment), with its
    records in WAL mode. The other checks of this file read under the hub's lock, as a test hub does."""

    def setUp(self):
        super().setUp()
        self.assertEqual(hub.wal_on(), (True, None))
        hub.readers_for(self.path)
        self.addCleanup(hub.readers_for, None)

    rows_of, has = Together.rows_of, Together.has

    def test_the_window_and_the_blocks_together_are_the_whole_state_from_a_read_connection(self):
        """The same union, read as the live hub reads it. A read that could not begin its own moment holds the lock in
        its place and says nothing, so this counts the read connections that gave an answer."""
        given, real = [], hub.reader

        def reader():
            got = real()
            given.append(got is not None)
            return got

        with patch.object(hub, "reader", reader):
            Together.test_the_window_and_the_blocks_together_are_the_whole_state(self)
        self.assertGreater(len(given), 4)
        self.assertTrue(all(given), "each read of the state and of a block had a read connection")


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

    def ended(self, count):
        with hub.transaction():
            for _ in range(count):
                hub.DB.execute("INSERT INTO tasks(title,details,done_when,owner,requester,state,created,needs,attempt,"
                               "what) VALUES('Work',?,'it is done','mia','manager','completed',?,'none',1,?)",
                               ("d" * 2000, hub.now(), "w" * 1000))
                task = hub.DB.execute("SELECT MAX(id) FROM tasks").fetchone()[0]
                hub.DB.execute("INSERT INTO notes(task,agent,ts,text) VALUES(?,?,?,?)", (task, "mia", hub.now(), "n" * 300))

    def test_a_window_read_does_not_grow_with_the_tasks(self):
        """The bound that the owner's tools and the Mac app need: 400 more ended tasks, each with 3,000 characters of
        text and a note, add nothing to a window read of the state but digits, while the whole answer takes them all.
        The window holds the ended tasks of at most STATE_KEEP + TASK_BLOCK - 1 ids."""
        self.fill()
        most = hub.STATE_KEEP + hub.TASK_BLOCK - 1
        self.ended(250 - hub.q1("SELECT MAX(id) AS top FROM tasks")["top"])
        few, whole_few = self.body("/ui/state?tasks=window"), self.body("/ui/state")
        self.ended(400)
        many, whole_many = self.body("/ui/state?tasks=window"), self.body("/ui/state")
        self.assertLess(abs(len(many) - len(few)), 2000, "the same window, some ids and counts one digit longer")
        self.assertGreater(len(whole_many) - len(whole_few), 400 * 3300, "the whole answer holds each new task")
        for answer in (json.loads(few), json.loads(many)):
            kept = [t for t in answer["tasks"] if t["state"] in hub.TERMINAL]
            self.assertTrue(hub.STATE_KEEP <= len(kept) <= most, len(kept))
        self.assertEqual(json.loads(many)["older_tasks"]["before"], 500)
        self.assertEqual(len(json.loads(whole_many)["tasks"]), 650)

    def test_the_head_of_the_state_holds_the_generation_and_reads_no_list(self):
        """Owner API 1.256: a program that needs the hub's generation or its features asks for the head of the state
        (the owner's tools, before their first call). Its answer holds those and none of the state's lists, and the
        hub reads no row of a list for it: a head that reads the tasks and leaves them out costs each call of the
        tools the fleet's history again, as the whole read did. Another value of `head` is no such read."""
        self.fill()
        lists = re.compile(r"\b(?:FROM|JOIN)\s+(?:tasks|notes|prompts|holds|outcomes|steers|needs|ui_requests|"
                           r"owner_reports|goals|responsibilities)\b", re.I)
        whole, read = self.traced(lambda: json.loads(self.body("/ui/state")))
        self.assertTrue([sql for sql in read if lists.search(sql)], "the trace sees the reads of the lists")
        for path in ("/ui/state?head=1", "/ui/state?head=1&tasks=window"):
            head, read = self.traced(lambda: json.loads(self.body(path)))
            self.assertEqual(sorted(head), ["db", "head", "repository", "schema_version", "time", "token",
                                            "ui_features"], path)
            self.assertEqual([head[key] for key in ("db", "ui_features", "repository", "schema_version", "head")],
                             [whole[key] for key in ("db", "ui_features", "repository", "schema_version")] + [True], path)
            self.assertEqual([sql for sql in read if lists.search(sql)], [], path)
        self.assertIn("tasks", json.loads(self.body("/ui/state?head=0")))

    def test_a_reader_that_does_not_ask_reads_the_whole_state(self):
        """An app from before this change sends no `tasks`, and a reader may send words that the hub does not know:
        both read every task, and no `older_tasks`."""
        self.fill()
        self.ended(300)
        every = hub.q1("SELECT COUNT(*) AS n FROM tasks")["n"]
        for path in ("/ui/state", f"/ui/state?db={DB}", "/ui/state?tasks=all", "/ui/state?tasks="):
            answer = json.loads(self.body(path))
            self.assertEqual((len(answer["tasks"]), "older_tasks" in answer), (every, False), path)


class Marks(OlderCase):
    def changes(self, write, moved, why):
        """Run `write`, and check for every block: its mark moved when its answer changed, and it is `moved` that the
        answers changed at all. A mark that stands under a new answer leaves an app with old rows; a mark that moves
        under the same answer makes each app read the block again for nothing."""
        answers, (marks, head) = self.blocks(), self.marks()
        write()
        after, (marked, headed) = self.blocks(), self.marks()
        self.assertEqual(sorted(after), sorted(answers), why)
        changed = [start for start in answers
                   if {k: v for k, v in after[start].items() if k != "mark"}
                   != {k: v for k, v in answers[start].items() if k != "mark"}]
        self.assertEqual(bool(changed), moved, why)
        for start in answers:
            self.assertEqual(marked[start] != marks[start], start in changed, f"{why}: the block from {start}")
            self.assertEqual(after[start]["mark"], marked[start], "a block's answer says the mark of the list")
        self.assertEqual(headed != head, moved, f"{why}: the mark that the state says")

    def test_a_mark_moves_when_its_block_changes_and_only_then(self):
        self.fill()
        old_open = self.task(state="working")
        old_ended = self.task(state="completed")
        noted = self.note(old_ended)
        gone = self.task(state="failed")
        self.note(gone)
        hold = hub.ins("INSERT INTO holds(task,kind,by,note,state,created,attempt) VALUES(?,?,?,?,?,?,?)",
                       (old_ended, "stop", "owner", "held", "held", hub.now(), 1))
        # the owner's guidance of that task, with a file: the file is part of the steer's row in the block
        event = hub.ins("INSERT INTO events(agent,kind,task,text,created,extra) VALUES('mia','steer',?,'a steer',1,'{}')",
                        (old_ended,))
        hub.ins("INSERT INTO steers(task,attempt,text,event_id,request_id,client,created) VALUES(?,1,'Do it so',?,?,?,1)",
                (old_ended, event, "steer-9", "mac-app"))
        steer_file = hub.ins("INSERT INTO attachments(request_id,name,mime,size,sha256,created,client,message) "
                             "VALUES('file-9','plan.pdf','application/pdf',1234,?,1,'mac-app','steer-9')", ("ab" * 32,))
        chat_file = hub.ins("INSERT INTO attachments(request_id,name,mime,size,sha256,created,client,message) "
                            "VALUES('file-8','note.pdf','application/pdf',99,?,1,'mac-app','req-1')", ("cd" * 32,))
        other_event = hub.ins("INSERT INTO events(agent,kind,task,text,created,extra) VALUES('mia','say',?,'x',1,'{}')",
                              (old_ended,))
        login = [{"kind": "password", "len": 12, "hash": "ef" * 32}]
        hub.register_fingerprints("bws://00000000-0000-0000-0000-000000000001", login)
        for _ in range(3 * self.BLOCK):
            self.task()
        top = self.task(state="working")
        before = self.window()["older_tasks"]["before"]
        self.assertTrue(gone < before <= top, "the fixture: old tasks below the window, a new one in it")
        q = hub.q
        for moved, why, write in (
            (True, "a task below the window ends", lambda: q("UPDATE tasks SET state='completed' WHERE id=?", (old_open,))),
            (True, "its check comes", lambda: q("UPDATE tasks SET accepted=1, checked_at=5 WHERE id=?", (old_ended,))),
            (True, "its agent gets another name", lambda: q("UPDATE tasks SET owner='ana' WHERE owner='mia' AND id<?", (before,))),
            (True, "a note of an ended task", lambda: self.note(old_ended, "a late note")),
            (True, "a note's words change", lambda: q("UPDATE notes SET text='other words' WHERE id=?", (noted,))),
            (True, "a note moves to another ended task", lambda: q("UPDATE notes SET task=? WHERE id=?", (gone, noted))),
            (True, "a note leaves", lambda: q("DELETE FROM notes WHERE id=?", (noted,))),
            (True, "a hold of it is released", lambda: q("UPDATE holds SET state='released', released=9 WHERE id=?", (hold,))),
            (True, "the owner keeps a file of its guidance", lambda: q("UPDATE attachments SET kept=5, knowledge='plan.md' "
                                                                       "WHERE id=?", (steer_file,))),
            (True, "the sweep removes that file", lambda: q("DELETE FROM attachments WHERE id=?", (steer_file,))),
            (True, "a new file of its guidance", lambda: q(
                "INSERT INTO attachments(request_id,name,mime,size,sha256,created,client,message) "
                "VALUES('file-7','late.pdf','application/pdf',5,?,1,'mac-app','steer-9')", ("ef" * 32,))),
            (False, "a file of a chat message", lambda: q("UPDATE attachments SET kept=5 WHERE id=?", (chat_file,))),
            (True, "a file comes to its guidance", lambda: q("UPDATE attachments SET message='steer-9' WHERE id=?",
                                                              (chat_file,))),
            (True, "and leaves it for a message", lambda: q("UPDATE attachments SET message='req-1' WHERE id=?",
                                                             (chat_file,))),
            (True, "its guidance is read after it ended", lambda: q("UPDATE events SET read_at=7 WHERE id=?", (event,))),
            (False, "another event of the task is read", lambda: q("UPDATE events SET read_at=7 WHERE id=?", (other_event,))),
            (False, "a row whose task is no whole number is written all the same",
             lambda: q("INSERT INTO prompts(task,agent,tool,input,key,created) VALUES(?,'mia','Bash','{}','k8',1)",
                       (top + 0.5,))),
            (True, "an outcome of it", lambda: q("INSERT INTO outcomes(task,attempt,hold,tool_call_id,state,created) "
                                                 "VALUES(?,1,?,'call-1','unknown',1)", (old_ended, hold))),
            (True, "a permission of it", lambda: q("INSERT INTO prompts(task,agent,tool,input,key,created) "
                                                   "VALUES(?,'mia','Bash','{}','k9',1)", (old_ended,))),
            (True, "an ended task comes back to work", lambda: q("UPDATE tasks SET state='working' WHERE id=?", (old_open,))),
            (True, "an ended task leaves the records", lambda: q("DELETE FROM tasks WHERE id=?", (gone,))),
            (True, "a note of a task that is gone", lambda: self.note(gone, "the block of its number has it")),
            (False, "a write to a task below the window that has not ended",
             lambda: q("UPDATE tasks SET last_activity=77, last_tool='Bash' WHERE id=?", (old_open,))),
            (False, "a note of a task that has not ended", lambda: self.note(old_open)),
            (False, "a write that changes no value of an ended task",
             lambda: q("UPDATE tasks SET accepted=1, checked_at=5, missing_since=NULL WHERE id=?", (old_ended,))),
            (False, "a write that changes no value of its hold", lambda: q("UPDATE holds SET state='released' WHERE id=?", (hold,))),
            (False, "a task in the window ends", lambda: q("UPDATE tasks SET state='completed' WHERE id=?", (top,))),
            (False, "a login that keeps its value", lambda: q("UPDATE secrets SET username='another name'")),
            (False, "the owner saves a login's value again (a new row, then the old one goes)",
             lambda: hub.register_fingerprints("bws://00000000-0000-0000-0000-000000000001", login, newest=True)),
            (False, "a new key of the practice page", hub.practice_key),
            (False, "a token that a provider gave the hub now",
             lambda: hub.mcp_fingerprints("notes", "a-fresh-token-of-the-provider", "")),
            (False, "and a Google account's", lambda: q(
                "INSERT INTO secrets(label,salt,hash,len,username) VALUES('google refresh-token ana@example.com','g1',?,40,'')",
                ("0a" * 32,))),
            (True, "the event of its guidance leaves with its agent", lambda: q("DELETE FROM events WHERE id=?", (event,))),
            (True, "a new event takes that event's number", lambda: q(
                "INSERT INTO events(id,agent,kind,task,text,created,extra) VALUES(?,'mia','say',NULL,'x',1,'{}')", (event,))),
        ):
            with self.subTest(why):
                self.changes(write, moved, why)

    def test_a_login_that_is_registered_later_reaches_every_block(self):
        """A login can be registered after a text was stored, and the hub masks it in each answer from then on. A block
        that an app kept before holds the text in plain, so every block's mark moves, and its new answer has the mask."""
        secret = "L4ter-Login!9090"
        told = self.task(details=f"the key is {secret} now")
        for _ in range(3 * self.BLOCK):
            self.task()
        start = told // self.BLOCK * self.BLOCK
        marks, head = self.marks()
        self.assertIn(secret, json.dumps(self.blocks()[start]))
        test_state_read.register(secret, "s9")
        marked, headed = self.marks()
        self.assertTrue(all(marked[b] != marks[b] for b in marks), (marks, marked))
        self.assertNotEqual(headed, head)
        self.assertNotIn(secret, json.dumps(self.blocks()[start]))
        # The login leaves: the text shows again, so every mark moves again. And a login with no label counts too.
        hub.q("DELETE FROM secrets WHERE label='login s9'")
        shown, _ = self.marks()
        self.assertTrue(all(shown[b] != marked[b] for b in marked), (marked, shown))
        self.assertIn(secret, json.dumps(self.blocks()[start]))
        hub.q("INSERT INTO secrets(label,salt,hash,len,username) VALUES(NULL,'s8',?,12,'')", ("1b" * 32,))
        self.assertTrue(all(self.marks()[0][b] != shown[b] for b in shown), "a login with no label")

    def test_the_guidance_of_a_task_that_left_while_open_counts_a_block_that_had_no_count(self):
        """A task that leaves the records while it is open moves no mark: no block held it. Its steer is then a row of
        the block of its number, and that block can have no count at all. A file of that steer that changes must give
        the block its first count: with none, the mark stays "0" under a new answer."""
        for _ in range(self.BLOCK):
            self.task(state="working")          # a block of open tasks only: nothing counts it
        lost = self.task(state="working")
        event = hub.ins("INSERT INTO events(agent,kind,task,text,created,extra) VALUES('mia','steer',?,'a steer',1,'{}')",
                        (lost,))
        hub.ins("INSERT INTO steers(task,attempt,text,event_id,request_id,client,created) VALUES(?,1,'Do it so',?,?,?,1)",
                (lost, event, "steer-lost", "mac-app"))
        file = hub.ins("INSERT INTO attachments(request_id,name,mime,size,sha256,created,client,message) "
                       "VALUES('file-lost','plan.pdf','application/pdf',9,?,1,'mac-app','steer-lost')", ("ab" * 32,))
        for _ in range(3 * self.BLOCK):
            self.task(state="working")
        start = lost // self.BLOCK * self.BLOCK
        hub.q("DELETE FROM tasks WHERE id=?", (lost,))
        self.assertEqual([s["id"] for s in self.blocks()[start]["steers"]], [1], "the steer is the block's now")
        for why, write in (("its file is kept", lambda: hub.q("UPDATE attachments SET kept=5 WHERE id=?", (file,))),
                           ("its event is read", lambda: hub.q("UPDATE events SET read_at=9 WHERE id=?", (event,)))):
            with self.subTest(why):
                self.changes(write, True, why)

    def test_a_count_only_goes_up_also_under_a_replace(self):
        """Inside a trigger SQLite takes the conflict rule of the statement that fired it. A write with OR REPLACE to
        a note of an ended task must count, as every write, and never put the block's count back to its start: a
        count that came back to a value that an app holds would stand for other rows."""
        old = self.task()
        for _ in range(4):
            self.note(old)
        for _ in range(3 * self.BLOCK):
            self.task()
        start = old // self.BLOCK * self.BLOCK
        mark = int(self.marks()[0][start])
        self.assertGreater(mark, 3)
        hub.q("INSERT OR REPLACE INTO notes(id,task,agent,ts,text) VALUES(?,?,?,?,?)",
              (hub.q1("SELECT MAX(id) AS id FROM notes")["id"], old, "mia", 1, "replaced"))
        self.assertGreater(int(self.marks()[0][start]), mark)

    def test_the_window_moves_up_one_block_and_the_tasks_that_leave_it_are_in_a_block(self):
        """The window holds the KEEP newest ids at the least. When the newest id passes the next block, the tasks of
        one block leave the window, the mark of the state says so, and the list names their block with those tasks:
        an app that sees the new mark finds them at once."""
        for _ in range(self.KEEP + self.BLOCK - 2):
            self.task()
        first = self.window()
        self.assertEqual(first["older_tasks"]["before"], 0, "fewer ids than a block and the ids that the window keeps")
        self.assertEqual(self.get(f"/ui/tasks/older?db={DB}")["blocks"], [])
        left = [t["id"] for t in first["tasks"] if t["id"] < self.BLOCK]
        self.task()
        second = self.window()
        self.assertEqual(second["older_tasks"]["before"], self.BLOCK)
        self.assertNotEqual(second["older_tasks"]["mark"], first["older_tasks"]["mark"])
        self.assertEqual(len(second["tasks"]), self.KEEP)
        self.assertEqual([t["id"] for t in self.blocks()[0]["tasks"]], left)
        self.assertEqual(second["older_tasks"]["tasks"], len(left))


class Schema(OlderCase):
    def triggers(self):
        return {r["name"]: r["sql"] for r in hub.q("SELECT name, sql FROM sqlite_master WHERE type='trigger'")}

    def test_a_start_that_changes_nothing_makes_no_trigger_and_moves_no_mark(self):
        """Each start of the hub runs the schema again. A start must leave the marks as they are: else each release
        of the hub would make every app read every block again."""
        for _ in range(3 * self.BLOCK):
            self.task()
        marks, made = self.marks(), self.triggers()
        # tasks, the five tables, a steer's files, a steer's event, the logins
        self.assertEqual(len(made), 3 + 4 * len(hub.OLDER_TABLES) + 4 + 3 + 3)
        ran = []
        hub.DB.set_trace_callback(ran.append)
        try:
            self.assertEqual(hub.migrate(), [])
        finally:
            hub.DB.set_trace_callback(None)
        self.assertEqual([s for s in ran if s.upper().startswith(("CREATE TRIGGER", "DROP TRIGGER"))], [])
        self.assertEqual((self.marks(), self.triggers(), hub.OLDER["on"]), (marks, made, True))

    def test_a_new_column_makes_its_trigger_again_and_every_block_counts(self):
        """A trigger compares the columns that its table had when it was made. After a start that added a column, a
        write to that column alone must count, and what was written between the column and the trigger is unknown:
        so every block counts once."""
        old = self.task()
        note = self.note(old)
        for _ in range(3 * self.BLOCK):
            self.task()
        hub.q("ALTER TABLE notes ADD COLUMN shade TEXT")
        marks, _ = self.marks()
        hub.q("UPDATE notes SET shade='blue' WHERE id=?", (note,))
        self.assertEqual(self.marks()[0], marks, "the trigger of before does not know the column")
        self.assertEqual(hub.migrate(), [])
        marked, _ = self.marks()
        self.assertTrue(all(marked[b] != marks[b] for b in marks), "every block counts once at that start")
        hub.q("UPDATE notes SET shade='green' WHERE id=?", (note,))
        start = old // self.BLOCK * self.BLOCK
        self.assertNotEqual(self.marks()[0][start], marked[start], "and its trigger counts the new column")

    def test_a_column_can_be_dropped_after_the_triggers_of_its_table(self):
        """A step of migrate() or a test that drops a column of a watched table meets SQLite's refusal: a trigger of the
        marks names each column. older_unwatch takes that table's triggers away, and the next start makes them again
        and counts every block once, for the writes that no trigger saw meanwhile."""
        old = self.task()
        note = self.note(old)
        for _ in range(3 * self.BLOCK):
            self.task()
        hub.q("ALTER TABLE notes ADD COLUMN shade TEXT")
        self.assertEqual(hub.migrate(), [])
        with self.assertRaises(sqlite3.OperationalError):
            hub.q("ALTER TABLE notes DROP COLUMN shade")
        hub.older_unwatch("notes")
        hub.q("ALTER TABLE notes DROP COLUMN shade")
        self.assertEqual(sorted(t for t in self.triggers() if "notes" in t), [])
        marks, _ = self.marks()
        hub.q("UPDATE notes SET text='written with no trigger' WHERE id=?", (note,))
        self.assertEqual(hub.migrate(), [])
        marked, _ = self.marks()
        self.assertTrue(all(marked[b] != marks[b] for b in marks))
        self.assertEqual(len(self.triggers()), 3 + 4 * len(hub.OLDER_TABLES) + 4 + 3 + 3)

    def test_a_hub_whose_marks_are_not_in_place_serves_the_whole_state(self):
        """Without one of its triggers a block could change under a mark that stands. So a hub that could not make
        them serves no window: a reader that asks for one gets every task and no `older_tasks`, and reads no
        block."""
        for _ in range(3 * self.BLOCK):
            self.task()
        every = hub.q1("SELECT COUNT(*) AS n FROM tasks")["n"]
        hub.q("DROP TRIGGER task_block_update")
        real = hub.sql_step

        def refuses(sql, problems):
            if "CREATE TRIGGER task_block_update " in sql:
                problems.append("task_block_update: refused")
                return problems
            return real(sql, problems)

        with patch.object(hub, "sql_step", refuses):
            self.assertEqual(hub.migrate(), ["task_block_update: refused"])
        status, answer = self.request("/ui/state?tasks=window")
        self.assertEqual((status, len(answer["tasks"]), "older_tasks" in answer), (200, every, False))
        self.assertEqual(self.request(f"/ui/tasks/older?db={DB}")[0], 404)
        self.assertEqual(hub.migrate(), [], "the next start makes it")
        self.assertIn("older_tasks", self.window())

    def test_the_tasks_of_before_this_change_get_their_blocks(self):
        """A hub that takes this release holds tasks that ended before the triggers were there. Its first start gives
        each of their blocks a mark and the number of its tasks."""
        with hub.LOCK:
            for name in self.triggers():
                hub.DB.execute(f"DROP TRIGGER {name}")
            hub.DB.execute("DROP TABLE task_blocks")
            hub.commit()
        for _ in range(3 * self.BLOCK):
            self.task()
        self.assertEqual(hub.migrate(), [])
        listed = self.get(f"/ui/tasks/older?db={DB}")
        self.assertEqual([(b["from"], b["tasks"]) for b in listed["blocks"]],
                         [(0, self.BLOCK - 1), (self.BLOCK, self.BLOCK)])
        self.assertTrue(all(int(b["mark"]) > 0 for b in listed["blocks"]))

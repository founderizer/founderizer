"""Changes only of the state (owner API 1.370, owner feature `state_changes`, 26 November 2026).

The Mac app reads the state's window (`GET /ui/state?tasks=window&rest=window`) at each change that the hub announces
and 3 seconds after its last read: about 1,632 reads an hour on the first fleet, each about 580 KB with gzip, while the
rows that changed between two reads 3 seconds apart were about 8 KB with gzip. A reader that asks with `changes=1`
gets `window`, the id of its answer; its next read with `base=<that id>` gets only what changed since. This file holds:

- the changes and their base are the whole state of the same moment, compared by JSON text (which tells 1, true and
  1.0 apart, as == does not): every value and the order of the rows of each list, with what scrub masks masked, after
  writes in each part and a value that comes and goes;
- made answers (state_answer alone): a list whose key changes, an empty list, a list that leaves and comes back, ids
  that turn from whole numbers to strings, a key twice, a value that becomes a list of rows, 1, true and 1.0, and two
  changed rows with text beyond ASCII and a lone surrogate, each answer the same text as json.dumps writes; and an
  answer whose logins changed between its two steps is no base;
- a base that the hub does not hold gets the whole state with a new window: one it never gave, one that four later
  answers pushed out of the ring, every base after a restart, one of another generation, and one from before a login
  was registered;
- a read of another shape than the Mac's, a read on a hub whose marks are not in place, and a HEAD keep nothing;
- two readers that read in turn each get the changes from their own window.

That a read without `changes=1` is the same bytes as before, with no `window`, is test_state_read.SameBytes.

    python3 -m unittest -v test_state_changes
"""
import copy
import http.client
import json
import unittest
from unittest.mock import patch

import hub
# not `from test_state_read import StateCase`: a test class among this module's names runs all its tests here again
import test_state_read
from test_state_read import LOGIN, T0, register

QUERY = "/ui/state?tasks=window&rest=window"        # the Mac app's read of the state (HubClient.stateReading)
LATE = "L4te-Login#5150"                             # a login that the owner registers between two reads
NEVER = "0123456789abcdef"                           # a window id that the hub never gave


def load_tests(loader, _tests, _pattern):
    """Only this file's checks: the harness comes from OwnerAPI, its own tests stay in its own file."""
    suite = unittest.TestSuite()
    for cls in (Rebuild, Answers, Whole, Kept, Readers):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


def applied(base, answer):
    """What a reader makes of a changes answer, as the Mac app does: the base's values with `set`, `rows` and `remove`,
    and the head and the window of the answer."""
    changes = answer["changes"]
    state = {name: value for name, value in base.items() if name not in changes["remove"]}
    state.update(changes["set"])
    for name, part in changes["rows"].items():
        rows = {row[part["key"]]: row for row in base[name]}
        rows.update({row[part["key"]]: row for row in part["set"]})
        state[name] = [rows[key] for key in part["order"]]
    state.update({name: answer[name] for name in hub.STATE_HEAD + ("window",)})
    return state


def ids(rows, key="id"):
    return [row[key] for row in rows]


def texts(state):
    """Each value of a state as its JSON text: 1, true and 1.0 are three texts, and == takes them for one. The order
    of the values is no part of the state; the order of each list is."""
    return {name: json.dumps(value) for name, value in state.items()}


def empty_ring(test):
    """The ring lives in the process: a test starts as a hub starts, with none."""
    hub.STATE_KEPT.clear()
    test.addCleanup(hub.STATE_KEPT.clear)
    hub.STATE_KEPT_LOGINS[0] = None
    test.addCleanup(hub.STATE_KEPT_LOGINS.__setitem__, 0, None)


class ChangesCase(test_state_read.StateCase):
    def setUp(self):
        super().setUp()
        empty_ring(self)

    def read(self, base=None):
        """One read that asks for changes, from `base` when given."""
        status, answer = self.request(QUERY + "&changes=1" + (f"&base={base}" if base else ""))
        self.assertEqual(status, 200, answer)
        self.assertIsInstance(answer.get("window"), str)
        return answer

    def whole(self):
        """A read of the same moment that does not ask: the state that a reader of the changes must have."""
        status, answer = self.request(QUERY)
        self.assertEqual(status, 200, answer)
        self.assertNotIn("window", answer)
        return answer

    def assertWhole(self, answer, seen=()):
        """`answer` is the whole state of this moment with a new window, last, and no changes."""
        self.assertNotIn("changes", answer)
        self.assertNotIn("base", answer)
        self.assertEqual(list(answer)[-1], "window")
        self.assertNotIn(answer["window"], seen)
        self.assertEqual(texts({name: value for name, value in answer.items() if name != "window"}),
                         texts(self.whole()))

    def edit(self, sql, args=()):
        with hub.LOCK:
            row = self.x(sql, args)
            hub.commit()
        return row


class Rebuild(ChangesCase):
    def test_the_changes_and_their_base_are_the_whole_state_of_the_same_moment(self):
        """A reader that holds a window and applies the changes holds what a whole read of the same moment gives:
        every value and the order of the rows of each list, with the logins masked. A changed row left out, a row that
        left and stays, an order that is not sent, a value that went and stays, or changes made before scrub would each
        show the Mac a state that is not the hub's, with no way for it to see that."""
        self.fill()
        with patch.object(hub, "teams_state", return_value={}):
            first = self.read()
        self.assertEqual(list(first)[-1], "window")
        self.assertNotIn("changes", first)
        self.assertNotIn(LOGIN, json.dumps(first))
        gone_note = next(n["id"] for n in first["notes"] if n["text"] == "a plain note")
        gone_report = next(r["id"] for r in first["reports"] if r["text"] == "report 4")
        hidden = next(n["id"] for n in first["notes"] if n["text"] == hub.MASK)
        # Writes in each part: changed rows, added rows, rows that leave, a new order of the messages, and a row whose
        # text holds a registered login.
        self.edit("UPDATE tasks SET title=? WHERE id=1", ("Task 1, renamed",))
        self.edit("UPDATE needs SET why=? WHERE id=2", ("a new reason",))
        self.edit("UPDATE goals SET title=? WHERE id=?", ("Sell much more", self.goals[0]))
        self.edit("UPDATE agents SET last_seen=? WHERE name='mia'", (T0 - 3,))
        self.edit("UPDATE notes SET ts=? WHERE id=?", (T0 - 49, hidden))
        added = self.edit("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,created,started,"
                          "attempt) VALUES(?,?,?,?,?,?,?,?,?,?)",
                          ("Task 9", "a new task", "a test passes", "[]", "mia", "manager", "working", T0 - 60,
                           T0 - 50, 1))
        self.edit("INSERT INTO notes(task,agent,ts,text) VALUES(?,?,?,?)", (added, "mia", T0 - 20, "a new note"))
        event = self.edit("INSERT INTO events(agent,kind,task,text,created,extra,read_at) VALUES(?,?,?,?,?,?,?)",
                          ("manager", "say", None, "message 5", T0 - 5, "{}", None))
        self.edit("INSERT INTO ui_requests(request_id,kind,text,event_id,created,client,recipient) "
                  "VALUES(?,?,?,?,?,?,?)", ("req-5", "message", "hello 5", event, T0 - 5, "mac-app", "manager"))
        self.edit("INSERT INTO owner_reports(text,about,created,agent,in_reply_to,pushed,turn) VALUES(?,?,?,?,?,?,?)",
                  ("report 5", "the export", T0 - 4, "manager", None, 0, None))
        self.edit("DELETE FROM notes WHERE id=?", (gone_note,))
        self.edit("DELETE FROM owner_reports WHERE id=?", (gone_report,))
        self.edit("UPDATE ui_requests SET created=? WHERE request_id='req-4'", (T0 - 900,))
        with patch.object(hub, "teams_state", return_value={"teams": {"seats": 3}}):       # a value that comes
            second = self.read(base=first["window"])
            whole = self.whole()
        self.assertEqual((second["base"], list(second)),
                         (first["window"], [*hub.STATE_HEAD, "window", "base", "changes"]))
        self.assertNotEqual(second["window"], first["window"])
        self.assertEqual(texts(applied(first, second)), texts(dict(whole, window=second["window"])))
        # The fixture does what it says, and only what changed is sent, masked.
        rows, changes = second["changes"]["rows"], second["changes"]
        self.assertEqual(changes["set"]["teams"], {"seats": 3})
        self.assertEqual(changes["remove"], [])
        self.assertEqual(sorted(ids(rows["tasks"]["set"])), [1, added])
        self.assertEqual(rows["tasks"]["order"], ids(whole["tasks"]))
        self.assertNotIn(gone_note, rows["notes"]["order"])
        self.assertNotIn(gone_report, rows["reports"]["order"])
        self.assertEqual(next(n["text"] for n in rows["notes"]["set"] if n["id"] == hidden), hub.MASK)
        self.assertNotIn(LOGIN, json.dumps(second))
        self.assertEqual((rows["agents"]["key"], rows["messages"]["key"]), ("name", "request_id"))
        kept = ids(first["messages"], "request_id")
        self.assertNotEqual([i for i in ids(whole["messages"], "request_id") if i in kept], kept)    # a new order
        self.assertTrue({"needs", "goals", "agents"} <= set(rows), sorted(rows))
        # Then the value goes, and nothing else changed.
        with patch.object(hub, "teams_state", return_value={}):
            third = self.read(base=second["window"])
            whole = self.whole()
        self.assertEqual(third["changes"], {"set": {}, "rows": {}, "remove": ["teams"]})
        self.assertEqual(texts(applied(applied(first, second), third)), texts(dict(whole, window=third["window"])))


class Answers(unittest.TestCase):
    """state_answer alone, on made answers, read as a reader reads them."""
    HEAD = {"schema_version": 1, "db": "g1", "time": 1.0, "token": "t"}
    LOGINS = ("a login",)

    def setUp(self):
        empty_ring(self)

    def step(self, held, answer):
        """One read of `answer` from the reader's state `held` (None for its first read): the answer's text is the
        text that json.dumps writes, and the state that the reader makes of it is `answer`, by JSON text."""
        text = hub.state_answer(copy.deepcopy(answer), held["window"] if held else None, self.LOGINS)
        self.assertEqual(json.dumps(json.loads(text)), text)
        text.encode()                   # what Handler.json sends: a lone surrogate written as it is would fail here
        got = json.loads(text)
        state = applied(held, got) if "changes" in got else got
        self.assertEqual(texts(state), texts(dict(answer, window=got["window"])))
        return state, got.get("changes")

    def test_made_answers_rebuild_with_each_kind_of_change(self):
        """The cases that the readers' fuzz found no test for (26 November 2026), each a believable bug of its own: a
        list whose key changes (the reader would index the base by a key that its rows lack), an empty list, a list of
        rows that leaves and comes back, ids that turn from whole numbers to strings, a key twice (the rows would
        become one), a value that becomes a list of rows (a 500 when the kind is not compared), and 1, true and 1.0
        (one value for ==, three for the app's decoder)."""
        a0 = dict(self.HEAD, tasks=[{"id": 1, "t": "a"}, {"id": 2, "t": "b"}], x=1, lst=[], gone=[{"id": 1, "t": "g"}],
                  shape=5)
        state, changes = self.step(None, a0)
        self.assertIsNone(changes)
        a1 = dict(self.HEAD, tasks=[{"name": "a"}], x=True, lst=[{"id": 1}], shape=[{"id": 1}])
        state, changes = self.step(state, a1)
        self.assertEqual(sorted(changes["set"]), ["shape", "tasks", "x"])
        self.assertEqual(changes["rows"], {"lst": {"key": "id", "order": [1], "set": [{"id": 1}]}})
        self.assertEqual(changes["remove"], ["gone"])
        a2 = dict(self.HEAD, tasks=[{"name": "a"}], x=1.0, lst=[{"id": "1"}], shape=[{"id": 1}],
                  gone=[{"id": 1, "t": "g"}], dup=[{"id": 2, "t": "x"}, {"id": 2, "t": "y"}])
        state, changes = self.step(state, a2)
        self.assertEqual(sorted(changes["set"]), ["dup", "gone", "x"])
        self.assertEqual(changes["rows"], {"lst": {"key": "id", "order": ["1"], "set": [{"id": "1"}]}})
        a3 = dict(a2, x=1, dup=[{"id": 2, "t": "z"}, {"id": 2, "t": "y"}], lst=[])
        state, changes = self.step(state, a3)
        self.assertEqual(sorted(changes["set"]), ["dup", "x"])
        self.assertEqual(changes["rows"], {"lst": {"key": "id", "order": [], "set": []}})
        # Two changed rows in one list, with text beyond ASCII and a lone surrogate, which json.dumps writes as \\u
        # escapes: the step's byte check sees a text written another way, or rows joined another way.
        a4 = dict(a3, lst=[{"id": 1, "t": "caf\u00e9"}, {"id": 2, "t": "\ud800 alone"}, {"id": 3, "t": "same"}])
        state, changes = self.step(state, a4)
        a5 = dict(a4, lst=[{"id": 1, "t": "caf\u00e9 \u2615"}, {"id": 2, "t": "\ud800 still alone"},
                           {"id": 3, "t": "same"}])
        state, changes = self.step(state, a5)
        self.assertEqual(ids(changes["rows"]["lst"]["set"]), [1, 2])

    def test_an_answer_whose_logins_changed_between_its_two_steps_is_no_base(self):
        """Read A checks the ring with the logins of before; read B, with a login registered meanwhile, empties the ring
        and keeps its own answer; then A keeps its answer (the readers' race, 26 November 2026). A's texts were masked
        with the logins of before: kept under the new ones, a read from A's window would get changes from texts that
        scrub masks now. A is not kept, and a read from its window gets the whole state."""
        old, new = ("a login",), ("a login", "a new login")
        answer = dict(self.HEAD, tasks=[{"id": 1, "t": "a"}])
        marks = hub.state_marks(answer)
        self.assertIsNone(hub.state_kept(None, "g1", old))                  # A's first step
        b = json.loads(hub.state_answer(copy.deepcopy(answer), None, new))     # all of B
        a = hub.state_keep("g1", marks, old)                                 # A's second step
        self.assertEqual(list(hub.STATE_KEPT), [b["window"]])
        later = json.loads(hub.state_answer(copy.deepcopy(answer), a, new))
        self.assertNotIn("changes", later)
        self.assertEqual(texts(later), texts(dict(answer, window=later["window"])))


class Whole(ChangesCase):
    def test_a_base_that_the_hub_does_not_hold_gets_the_whole_state(self):
        """A reader whose base the hub does not hold takes the whole state with a new window: a base that the hub never
        gave, one that four later answers pushed out, every base after a restart, and one of another generation.
        Changes from an answer that the reader does not hold, or from the state of another generation, would show the
        Mac a state that is not the hub's; and a ring that never forgets grows with each read."""
        self.fill()
        self.assertIn("state_changes", self.whole()["ui_features"])
        self.assertWhole(self.read(base=NEVER))
        # The ring holds the last four answers: a base is still held after three later answers, and not after four.
        first = self.read()
        later = [self.read()["window"] for _ in range(3)]
        self.assertEqual(self.read(base=first["window"])["base"], first["window"])        # the fourth answer after it
        self.assertWhole(self.read(base=first["window"]), seen=[first["window"], *later])
        self.assertEqual(len(hub.STATE_KEPT), hub.STATE_KEPT_MOST)
        # A hub that started again holds no window of before.
        held = self.read()
        hub.STATE_KEPT.clear()
        self.assertWhole(self.read(base=held["window"]), seen=[held["window"]])
        # A restore gives the records another generation: a window of the one before is no base.
        before = self.read()
        hub.kv_set("db_id", "test-generation-2")
        after = self.read(base=before["window"])
        self.assertEqual(after["db"], "test-generation-2")
        self.assertWhole(after, seen=[before["window"]])

    def test_a_login_registered_after_the_base_gives_the_whole_state(self):
        """A login registered after a base: the next read is the whole state, masked with it, and the ring keeps only
        that answer. A ring that kept the answers of before would keep texts that scrub masks now, and changes from
        them would rest on texts that the hub no longer gives."""
        self.fill()
        late = self.edit("INSERT INTO notes(task,agent,ts,text) VALUES(?,?,?,?)",
                         (3, "mia", T0 - 35, f"the new key is {LATE} now"))
        first = self.read()
        self.assertIn(LATE, next(n["text"] for n in first["notes"] if n["id"] == late))
        register(LATE, "s9")
        after = self.read(base=first["window"])
        self.assertWhole(after, seen=[first["window"]])
        self.assertEqual(next(n["text"] for n in after["notes"] if n["id"] == late), hub.MASK)
        self.assertEqual(list(hub.STATE_KEPT), [after["window"]])


class Kept(ChangesCase):
    def test_a_read_of_another_shape_and_a_head_keep_nothing(self):
        """Only the Mac's read, both windows served, keeps an answer: a read with changes=1 of the whole history would
        keep megabytes for each window, and a HEAD, which gets no body, would push a Mac's base out of the ring."""
        self.fill()
        for query in ("/ui/state?changes=1", "/ui/state?tasks=window&changes=1", "/ui/state?rest=window&changes=1"):
            status, answer = self.request(query)
            self.assertEqual((status, "window" in answer, len(hub.STATE_KEPT)), (200, False, 0), query)
        # A hub whose marks of the tasks' window are not in place gives every task to the Mac's read too: it keeps
        # nothing of it, whatever the query's words say.
        with patch.dict(hub.OLDER, on=False):
            status, answer = self.request(QUERY + "&changes=1")
        self.assertEqual((status, "window" in answer, len(hub.STATE_KEPT)), (200, False, 0))
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=30)
        try:
            conn.request("HEAD", QUERY + "&changes=1", headers={"X-Fleet-Client": "founderizer-swift/1/test"})
            self.assertEqual((conn.getresponse().status, len(hub.STATE_KEPT)), (200, 0))
        finally:
            conn.close()
        self.read()
        self.assertEqual(len(hub.STATE_KEPT), 1)


class Readers(ChangesCase):
    def test_two_readers_in_turn_each_get_the_changes_from_their_own_window(self):
        """The owner's two Macs read in turn, each from its own last window: each read gets the changes from that
        window, and they make the whole state. One kept answer for all would cost each read a whole state, and changes
        from the other reader's window would show a Mac a state that is not the hub's."""
        self.fill()
        a1, b1 = self.read(), self.read()
        self.edit("UPDATE tasks SET title=? WHERE id=2", ("Task 2, renamed",))
        a2 = self.read(base=a1["window"])
        self.assertEqual(texts(applied(a1, a2)), texts(dict(self.whole(), window=a2["window"])))
        self.edit("UPDATE tasks SET title=? WHERE id=3", ("Task 3, renamed",))
        b2 = self.read(base=b1["window"])
        a3 = self.read(base=a2["window"])
        whole = self.whole()
        self.assertEqual((a2["base"], b2["base"], a3["base"]), (a1["window"], b1["window"], a2["window"]))
        self.assertEqual(texts(applied(b1, b2)), texts(dict(whole, window=b2["window"])))
        self.assertEqual(texts(applied(applied(a1, a2), a3)), texts(dict(whole, window=a3["window"])))
        self.assertEqual(ids(a2["changes"]["rows"]["tasks"]["set"]), [2])
        self.assertEqual(ids(b2["changes"]["rows"]["tasks"]["set"]), [2, 3])        # both edits, from its own window
        self.assertEqual(ids(a3["changes"]["rows"]["tasks"]["set"]), [3])


if __name__ == "__main__":
    unittest.main()

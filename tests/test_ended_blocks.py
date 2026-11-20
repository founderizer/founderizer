"""The Windows app's read of the ended tasks, in a window and in blocks (owner API 1.270, the lane "The Windows app's
ended read").

`GET /ui/mobile/ended` gives the head of every ended task, and the Windows app's Ended lane needs every one. On the
first fleet, on 20 November 2026, that answer was 868,736 bytes for 1,669 heads, about 0.13 MB more a day, while the
app reads at most 32 MiB of it. With `window=1` the answer holds the heads of the newest ids and says where the others
are: `blocks=1` lists their blocks, each with a mark, and `block=<the first id>` gives the heads of one. This file
holds:

- the window and the blocks together are every head of the whole read, once each, with the same values: an app that
  keeps its blocks shows what it showed before;
- a window read has the same size after 400 more ended tasks, while the whole read grows with them;
- a block's mark moves when a head of it changes, when a task of it ends, and at a new look of a head, and the marks
  of the other blocks stand;
- a reader that does not ask, a value that the hub does not take, and a hub whose marks are not in place read every
  head, as before.

    python3 -m unittest -v test_ended_blocks
"""
import json
import unittest
from unittest.mock import patch

import hub
# not `from test_older_tasks import OlderCase`: a test class among this module's names runs all its tests here again
import test_older_tasks
import test_state_read

ENDED = f"/ui/mobile/ended?db={test_older_tasks.DB}"


def load_tests(loader, _tests, _pattern):
    """Only this file's checks: the harness comes from OwnerAPI, its own tests stay in its own file."""
    suite = unittest.TestSuite()
    for cls in (Together, Bound, Marks, Words):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class EndedCase(test_older_tasks.OlderCase):
    """A hub with blocks of BLOCK ids and a window of KEEP ids at the least (OlderCase)."""

    def ended(self, words=""):
        return self.get(ENDED + words)

    def held(self):
        """Every head that a reader holds after a window read, the list, and each block of the list, as the Windows app
        joins them: each head once, in the order of the ids."""
        window, listed = self.ended("&window=1"), self.ended("&blocks=1")
        self.assertEqual({key: listed[key] for key in window["older"]}, window["older"], "the list's head is the window's")
        heads = {t["id"]: t for t in window["tasks"]}
        for entry in listed["blocks"]:
            block = self.ended(f"&block={entry['from']}")
            self.assertEqual((block["mark"], len(block["tasks"])), (entry["mark"], entry["tasks"]), entry)
            self.assertLessEqual(entry["from"] + self.BLOCK, window["older"]["before"], entry)
            for head in block["tasks"]:
                self.assertTrue(entry["from"] <= head["id"] < entry["from"] + self.BLOCK, (entry, head))
                self.assertNotIn(head["id"], heads, "a head is in the window or in one block")
                heads[head["id"]] = head
        return [heads[n] for n in sorted(heads)]

    def marks(self):
        """({the first id of a block: its mark}, the mark of them all)."""
        listed = self.ended("&blocks=1")
        return {b["from"]: b["mark"] for b in listed["blocks"]}, listed["mark"]


class Together(EndedCase):
    def test_the_window_and_the_blocks_together_are_every_ended_head(self):
        """The Windows app's Ended lane counts and opens every ended task of its period, as the Mac's does: the heads
        that it holds after a window read and the blocks of the list are the heads of the whole read, each once, in
        the order of their ids, with the same values, a schedule's too, and a login that was registered after the text
        masked (the app keeps the blocks in its folder). A task that has not ended is in neither, and one that ends
        below the window is in its block at once. The window's mark is the one of GET /ui/mobile, by which the app
        knows when to read again."""
        states = ("completed", "failed", "rejected", "canceled", "working")
        ids = [self.task(state=states[n % 5], title=f"Work {n}") for n in range(17)]
        self.assertEqual(ids, list(range(1, 18)))
        hub.q("UPDATE tasks SET trigger_id=7 WHERE id IN (?,?)", (ids[1], ids[13]))
        secret = "L4ter-Login!9090"
        hub.q("UPDATE tasks SET title=? WHERE id IN (?,?)", (f"Use {secret} now", ids[5], ids[12]))  # a block, the window
        test_state_read.register(secret, "s9")
        whole = self.ended()
        self.assertEqual(self.held(), whole["tasks"])
        self.assertEqual({t["title"] for t in self.held() if t["id"] in (ids[5], ids[12])}, {hub.MASK})
        window = self.ended("&window=1")
        # 17 ids and a window of 3 at the least: the largest multiple of 4 at most 17 - 3 + 1
        self.assertEqual((window["mark"], window["older"]["before"], window["older"]["block"]),
                         (self.get("/ui/mobile")["ended_mark"], 12, self.BLOCK))
        self.assertEqual([t["id"] for t in window["tasks"]], [12, 13, 14, 16, 17])
        self.assertEqual(sorted(window["tasks"][0]), sorted(hub.MOBILE_HEAD + ("trigger_id",)))
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (ids[4],))         # in the block of 4 to 7
        self.assertIn(ids[4], [t["id"] for t in self.ended("&block=4")["tasks"]])
        self.assertEqual(self.held(), self.ended()["tasks"])


class Bound(test_state_read.StateCase):
    """With the hub's own numbers."""
    body, ended = test_older_tasks.Bound.body, test_older_tasks.Bound.ended

    def test_a_window_read_does_not_grow_with_the_ended_tasks(self):
        """The bound that the Windows app needs: 400 more ended tasks add nothing to a window read but digits, and a
        block holds the heads of TASK_BLOCK ids at the most, while the whole read takes each new head. The window holds
        the heads of at most STATE_KEEP + TASK_BLOCK - 1 ids."""
        self.fill()
        self.ended(250 - hub.q1("SELECT MAX(id) AS top FROM tasks")["top"])
        few, whole_few = self.body(f"{ENDED}&window=1"), self.body(ENDED)
        self.ended(400)
        many, whole_many = self.body(f"{ENDED}&window=1"), self.body(ENDED)
        self.assertLess(abs(len(many) - len(few)), 2000, "the same window, some ids one digit longer")
        self.assertGreater(len(whole_many) - len(whole_few), 400 * 300, "the whole read holds each new head")
        most = hub.STATE_KEEP + hub.TASK_BLOCK - 1
        for answer in (json.loads(few), json.loads(many)):
            self.assertTrue(hub.STATE_KEEP <= len(answer["tasks"]) <= most, len(answer["tasks"]))
        listed = json.loads(self.body(f"{ENDED}&blocks=1"))
        self.assertEqual([b["from"] for b in listed["blocks"]], [0, 100, 200, 300, 400])
        blocks = [json.loads(self.body(f"{ENDED}&block={b['from']}")) for b in listed["blocks"]]
        self.assertEqual(max(len(b["tasks"]) for b in blocks), hub.TASK_BLOCK)
        self.assertEqual(sum(len(b["tasks"]) for b in blocks) + len(json.loads(many)["tasks"]),
                         len(json.loads(whole_many)["tasks"]))


class Marks(EndedCase):
    def test_a_mark_moves_when_a_head_of_its_block_changes(self):
        """The Windows app reads a block again only when the list gives it another mark: a mark that stands under a
        changed head leaves the app's Ended lane with an old title or state while it runs. A changed head moves the
        mark of its own block and the mark of them all, a task that ends below the window moves its block's, and
        the marks of the other blocks stand."""
        ids = [self.task(state="working" if n == 1 else "completed") for n in range(17)]
        marks, mark = self.marks()
        hub.q("UPDATE tasks SET title='Renamed' WHERE id=?", (ids[5],))           # in the block of 4 to 7
        moved, mark_moved = self.marks()
        self.assertEqual([b for b in marks if moved[b] != marks[b]], [4])
        self.assertNotEqual(mark_moved, mark)
        self.assertEqual([t["title"] for t in self.ended("&block=4")["tasks"] if t["id"] == ids[5]], ["Renamed"])
        hub.q("UPDATE tasks SET state='failed' WHERE id=?", (ids[1],))            # in the block of 0 to 3
        ended, _ = self.marks()
        self.assertEqual([b for b in moved if ended[b] != moved[b]], [0])
        self.assertEqual(self.held(), self.ended()["tasks"])

    def test_a_new_look_of_a_head_moves_every_mark(self):
        """A release that changes how a head looks (its columns in MOBILE_HEAD, scrub) moves every mark once, so that
        no app keeps a block of the old look: the digest of the code that makes a block ends each mark."""
        for _ in range(17):
            self.task()
        marks, mark = self.marks()
        with patch.dict(hub.ROWS_CODE, clear=True), patch.object(hub, "MOBILE_HEAD", hub.MOBILE_HEAD[:-1]):
            moved, mark_moved = self.marks()
            self.assertNotIn("ask", self.ended("&block=4")["tasks"][0])
        self.assertTrue(all(moved[b] != marks[b] for b in marks), (marks, moved))
        self.assertNotEqual(mark_moved, mark)


class Words(EndedCase):
    def test_a_reader_that_does_not_ask_reads_every_head(self):
        """An app from before this version sends none of the three words, and a reader may send a value that the hub
        does not take: each reads every head, with `asked` and no `older`, as before. `chat` keeps its own read."""
        for _ in range(17):
            self.task()
        every = self.ended()
        self.assertEqual((len(every["tasks"]), "older" in every, "asked" in every), (17, False, True))
        for words in ("&window=0", "&window=yes", "&blocks=0", "&blocks="):
            self.assertEqual(self.ended(words), every, words)
        chat = self.ended("&chat=manager&from=0&window=1&block=4")
        self.assertEqual((chat["chat"], chat["tasks"], "older" in chat), ("manager", [], False))

    def test_a_block_that_is_none_is_refused(self):
        """A reader that asks for a block that the list does not give learns it: a value that is not the first id of a
        block is 400, a block at or above the window is 404 (the window came down over it: the reader reads the list
        again), and a read of another generation is 409, as every read of this route."""
        for _ in range(17):
            self.task()
        for words, status in (("&block=5", 400), ("&block=x", 400), ("&block=-4", 400), ("&block=", 400),
                              ("&block=12", 404), ("&block=400", 404)):
            self.assertEqual(self.request(ENDED + words)[0], status, words)
        self.assertEqual(self.request("/ui/mobile/ended?db=another&window=1")[0], 409)

    def test_a_hub_whose_marks_are_not_in_place_gives_every_head_to_the_window(self):
        """A hub that could not make the triggers of its marks serves no window (OLDER): a reader that asks for it gets
        every head and no `older`, so the Windows app holds every head and reads no block; the list and a block are
        404."""
        for _ in range(17):
            self.task()
        with patch.dict(hub.OLDER, on=False):
            self.assertEqual(self.ended("&window=1"), self.ended())
            self.assertEqual([self.request(ENDED + words)[0] for words in ("&blocks=1", "&block=0")], [404, 404])


if __name__ == "__main__":
    unittest.main()

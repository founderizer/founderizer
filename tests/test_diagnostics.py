"""The hub's own faults and refused calls (diagnostics.py, the lane "Bug reports"): what is kept is a class from a
fixed list, files and lines of the code tree, numbers and times, and never the words of a fault.

The owner, 14 November 2026: "Pictures first (Recommended)" and, to the pictures C0, E1, E2 and E3, "ok yes, make
sure we include all relevant inforamtion that is SAFE to send". So most of these tests are about what must NOT reach
GET /ui/diagnostics: a message, a secret, a path of the machine, a name of the fleet's work.

The first class needs no hub. The second runs the test hub of test_ui_api (OwnerAPI), as test_health does: a
temporary database, its own checkout, and nothing of the developer's own fleet."""
import contextlib
import gc
import http.client
import inspect
import io
import json
import os
import re
import sys
import tempfile
import threading
import time
import types
import unittest
import unittest.mock
import urllib.error
import uuid

import diagnostics
import hub
from test_ui_api import OwnerAPI
from leftovers import ROOT, TEST_DIR

# this file as diagnostics.place names a frame: by its path in the hub's tree, "tests/test_diagnostics.py" in a
# clone of the published repository
HERE = os.path.relpath(os.path.join(TEST_DIR, os.path.basename(__file__)), ROOT)


def canary():
    """Words that look like a key and a person's work, different in each test."""
    return f"sk-ant-api03-CANARY{uuid.uuid4().hex} for Ana's task about /Users/ana/secret-plans"


def strings(value):
    """Every text in a decoded answer, keys left out."""
    if isinstance(value, dict):
        return [s for v in value.values() for s in strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in strings(v)]
    return [value] if isinstance(value, str) else []


def leaves(value):
    if isinstance(value, dict):
        return [x for v in value.values() for x in leaves(v)]
    if isinstance(value, list):
        return [x for v in value for x in leaves(v)]
    return [value]


class CanaryLeak(Exception):
    """A class that is not on the list: its name is the code's choice, so it goes as "other"."""


def fail_with(exc):
    def deeper():
        raise exc
    deeper()


class Recorder(unittest.TestCase):
    def setUp(self):
        diagnostics.pending()       # what an earlier test counted is not this test's

    def recorded(self, exc, program="hub"):
        try:
            fail_with(exc)
        except Exception:
            diagnostics.record(program)
        return diagnostics.pending()

    def test_a_fault_keeps_its_class_and_places_and_never_its_words(self):
        words = canary()
        taken = self.recorded(KeyError(words))
        self.assertEqual(len(taken), 1)
        fault = taken[0]
        self.assertEqual((fault["kind"], fault["program"], fault["name"]), ("fault", "hub", "KeyError"))
        self.assertEqual(fault["frames"][-1][0], HERE)                  # the innermost frame: where it was raised
        self.assertIsInstance(fault["frames"][-1][1], int)
        text = json.dumps(taken)
        self.assertNotIn("CANARY", text)
        self.assertNotIn("Ana", text)
        self.assertNotIn(ROOT, text)    # no path of this machine

    def test_a_class_that_is_not_on_the_list_goes_as_other(self):
        self.assertEqual(self.recorded(CanaryLeak(canary()))[0]["name"], "other")

    def test_a_frame_outside_the_code_tree_is_lib_with_no_line(self):
        try:
            json.loads("{" + canary())
        except ValueError:
            diagnostics.record("hub")
        frames = diagnostics.pending()[0]["frames"]
        self.assertIn(["lib", 0], frames)
        self.assertEqual({f[0] for f in frames} - {"lib", HERE}, set())

    def test_errno_and_http_status_are_numbers_and_the_message_stays_behind(self):
        fault = self.recorded(PermissionError(13, canary()))[0]
        self.assertEqual((fault["name"], fault["errno"], fault["http"]), ("PermissionError", 13, None))
        words = canary()
        fault = self.recorded(urllib.error.HTTPError("https://example.com/" + words, 503, words, None, None))[0]
        self.assertEqual((fault["name"], fault["http"]), ("HTTPError", 503))
        self.assertNotIn("CANARY", json.dumps(fault))

    def test_the_recorder_never_raises(self):
        diagnostics.record("hub")                                   # no exception is being handled
        diagnostics.record("hub", info=(None, object(), "not a traceback"))
        diagnostics.refused("send_message", info=(None, object(), 42))
        with unittest.mock.patch.object(diagnostics, "places", side_effect=RecursionError("deep")):
            self.recorded(KeyError("x"))
        self.assertEqual(self.recorded(KeyError("x"), program="someone-else"), [])     # a program not on the list
        self.assertEqual(diagnostics.pending(), [])

    def test_one_kind_counts_its_times_and_keeps_its_first_and_last(self):
        clock = iter([100.0, 200.0, 300.0])
        for _ in range(3):
            try:
                raise KeyError("same place")
            except KeyError:
                diagnostics.record("hub", clock=lambda: next(clock))
        (fault,) = diagnostics.pending()
        self.assertEqual((fault["count"], fault["first"], fault["last"]), (3, 100.0, 300.0))

    def test_the_kinds_that_wait_in_memory_are_bounded(self):
        for n in range(diagnostics.MAX_KINDS + 50):
            diagnostics._count(("fault", "hub", "KeyError", (("hub.py", n + 1),)), 1.0)
        self.assertEqual(len(diagnostics.pending()), diagnostics.MAX_KINDS)

    def test_a_refused_call_keeps_its_tool_and_its_place(self):
        for tool, kept in (("send_message", "send_message"), ("Bad Name " + canary(), "other"), (None, "other")):
            try:
                fail_with(hub.ToolError(canary()))
            except hub.ToolError:
                diagnostics.refused(tool)
            (row,) = diagnostics.pending()
            self.assertEqual((row["kind"], row["name"]), ("refusal", kept))
            self.assertEqual(len(row["frames"]), 1)
            self.assertEqual(row["frames"][0][0], HERE)
            self.assertNotIn("CANARY", json.dumps(row))

    def test_refused_calls_never_crowd_out_a_fault(self):
        for n in range(diagnostics.MAX_KINDS + 50):
            diagnostics._count(("refusal", "hub", "send_message", (("hub.py", n + 1),)), 1.0)
        try:
            fail_with(KeyError("y"))
        except KeyError:
            diagnostics.record("hub")
        kinds = [row["kind"] for row in diagnostics.pending()]
        self.assertEqual(kinds.count("refusal"), diagnostics.MAX_KINDS)
        self.assertEqual(kinds.count("fault"), 1)

    def test_the_code_id_is_the_same_at_every_reading_of_the_same_tree(self):
        diagnostics._code.clear()
        first = diagnostics.code_id()
        diagnostics._code.clear()
        import thread_door  # noqa: F401  (a module that the hub imports late: it must not change the id)
        self.assertEqual(diagnostics.code_id(), first)
        self.assertRegex(first, r"^[0-9a-f]{24}$")

    def test_the_answer_keeps_only_tools_of_the_hubs_list_and_files_of_the_tree(self):
        refusal = {"kind": "refusal", "program": "hub", "name": "nova_acme_merger", "frames": '[["hub.py",9]]',
                   "errno": None, "http": None, "count": 1, "first": 5.0, "last": 6.0}
        self.assertEqual(diagnostics.view([refusal], tools={"send_message"})["refusals"], [])
        self.assertEqual(len(diagnostics.view([dict(refusal, name="send_message")], tools={"send_message"})["refusals"]), 1)
        self.assertEqual(len(diagnostics.view([dict(refusal, name="other")], tools={"send_message"})["refusals"]), 1)
        fault = {"kind": "fault", "program": "hub", "name": "KeyError", "frames": '[["Acme_layoffs_list.py",3]]',
                 "errno": None, "http": None, "count": 1, "first": 5.0, "last": 6.0}
        self.assertEqual(diagnostics.view([fault])["faults"], [])

    def test_frames_nested_too_deep_drop_their_row_and_raise_nothing(self):
        row = {"kind": "fault", "program": "hub", "name": "KeyError", "frames": "[" * 100_000 + "]" * 100_000,
               "errno": None, "http": None, "count": 1, "first": 5.0, "last": 6.0}
        self.assertEqual(diagnostics.view([row]), {"faults": [], "refusals": [], "stalls": []})


    def test_a_deep_recursion_keeps_its_innermost_twelve_frames(self):
        def down(n):
            if n == 0:
                raise RecursionError("deep " + canary())
            down(n - 1)
        try:
            down(40)
        except RecursionError:
            diagnostics.record("hub")
        (fault,) = diagnostics.pending()
        self.assertEqual(len(fault["frames"]), diagnostics.MAX_FRAMES)
        self.assertEqual(len(diagnostics.view([dict(fault, frames=json.dumps(fault["frames"]))])["faults"]), 1)

    def test_the_answer_checks_numbers_and_shows_at_most_twenty_of_each(self):
        row = {"kind": "fault", "program": "hub", "name": "KeyError", "frames": '[["hub.py",120]]',
               "errno": 10 ** 9, "http": 999, "count": 1, "first": 1.0, "last": 2.0}
        (fault,) = diagnostics.view([row])["faults"]
        self.assertEqual((fault["errno"], fault["http"]), (None, None))
        many = [dict(row, frames=f'[["hub.py",{n}]]', last=float(n)) for n in range(1, 31)]
        self.assertEqual(len(diagnostics.view(many)["faults"]), diagnostics.MAX_SHOWN)

    def test_the_answer_checks_every_value_again_and_keeps_no_free_text(self):
        good = {"kind": "fault", "program": "hub", "name": "KeyError", "frames": '[["hub.py",120],["lib",0]]',
                "errno": None, "http": None, "count": 2, "first": 10.0, "last": 20.0}
        refusal = {"kind": "refusal", "program": "hub", "name": "send_message", "frames": '[["hub.py",9]]',
                   "errno": None, "http": None, "count": 1, "first": 5.0, "last": 6.0}
        bad = [dict(good, name="Secret " + canary()), dict(good, frames='[["/home/ana/x.py",3]]'),
               dict(good, frames='[["../x.py",3]]'), dict(good, frames='[["lib",7]]'), dict(good, count=-1),
               dict(good, frames="not json"), dict(good, program="ana"), dict(refusal, name="Ana's " + canary()),
               dict(good, frames=json.dumps([["hub.py", 1]] * (diagnostics.MAX_FRAMES + 1)))]
        answer = diagnostics.view([good, refusal] + bad)
        self.assertEqual(len(answer["faults"]), 1)
        self.assertEqual(len(answer["refusals"]), 1)
        self.assertEqual(answer["faults"][0]["frames"], [{"file": "hub.py", "line": 120}, {"file": "lib", "line": 0}])
        # No free text anywhere: each text is a class of the list, a program, a file of the tree or "lib", or a tool.
        for text in strings(answer):
            self.assertTrue(text in diagnostics.CLASSES or text in ("other", "lib") or text in diagnostics.PROGRAMS
                            or diagnostics.FILE.fullmatch(text) or diagnostics.NAME.fullmatch(text), text)
        for leaf in leaves(answer):
            self.assertTrue(leaf is None or isinstance(leaf, (str, int, float)), leaf)
        self.assertNotIn("CANARY", json.dumps(answer))


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite(loader.loadTestsFromTestCase(Recorder))
    suite.addTests(OnTheHub(name) for name in OnTheHub.__dict__ if name.startswith("test_"))
    suite.addTests(loader.loadTestsFromTestCase(Stalls))
    return suite


def spin(flag):
    while not flag: pass    # noqa: E701  (the one line of the loop: the place that a busy stall names)


def spin_too(flag):
    while not flag: pass    # noqa: E701  (a second place)


SPUN = inspect.getsourcelines(spin)[1] + 1
SPUN_TOO = inspect.getsourcelines(spin_too)[1] + 1


class Stalls(unittest.TestCase):
    """The stall watch (diagnostics.Watch), with a clock, a wall clock, the process's time and each thread's time on
    a CPU of the test's own, and real threads for their frames."""

    def setUp(self):
        diagnostics.pending()
        self.addCleanup(diagnostics.pending)
        self.now, self.cpu, self.process, self.journal = [5000.0, 1_795_000_000.0], {}, [0.0], io.StringIO()

    def watch(self, cpu=True):
        read = (lambda ids: {n: self.cpu[n] for n in ids if n in self.cpu}) if cpu else (lambda ids: None)
        return diagnostics.Watch(me=threading.get_native_id(), cpu=read, clock=lambda: self.now[0],
                                 wall=lambda: self.now[1], process=lambda: self.process[0], out=self.journal)

    def later(self, seconds):
        self.now[0] += seconds
        self.now[1] += seconds

    def go(self, w, seconds, rates, late=0.001, process=None):
        """`seconds` looks a second apart, in which each thread of `rates` ran that share of each second."""
        for _ in range(seconds):
            self.later(1.0)
            for thread, rate in rates.items():
                self.cpu[thread.native_id] += rate
            used = sum(rates.values()) if process is None else process
            self.process[0] += used
            w.look(late, used)

    def spinner(self, target=spin):
        """A thread that runs Python and nothing else, as the login search of 20 November 2026 did, once it stands
        in its loop."""
        flag = []
        thread = threading.Thread(target=target, args=(flag,), daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(flag.append, 1)
        line = inspect.getsourcelines(target)[1] + 1
        for _ in range(500):
            frame = sys._current_frames().get(thread.ident)
            if frame is not None and frame.f_code is target.__code__ and frame.f_lineno == line:
                break
            time.sleep(0.01)
        del frame
        self.cpu[thread.native_id] = 0.0
        return thread

    def code(self, frames):
        """The places of a row in the code tree, innermost first."""
        return [tuple(f) for f in reversed(frames) if f[0] != "lib"]

    def test_a_thread_that_runs_half_a_window_is_one_stall_however_long_it_runs(self):
        """The stall of 20 November 2026: a thread ran Python for minutes, and nobody could tell which code. It is one
        stall with that thread's places and no value, counted once while it lasts, also across the edge of a
        window, and its first and last time say how long it lasted."""
        hog = self.spinner()
        w = self.watch()
        start = self.now[1]
        self.go(w, 4, {hog: 0.0})
        self.go(w, 6, {hog: 0.95})      # 5.7 s of the first window, from its fourth second
        (row,) = diagnostics.pending()
        self.assertEqual((row["kind"], row["program"], row["name"], row["count"]), ("stall", "hub", "busy", 1))
        self.assertEqual(self.code(row["frames"])[0], (HERE, SPUN))
        self.assertAlmostEqual(row["first"], start + 10 - 5.7, places=6)        # it ran 5.7 s of it
        self.assertEqual(row["last"], self.now[1])
        self.go(w, 30, {hog: 0.95})     # it goes on: no second stall, and its last time moves
        (row,) = diagnostics.pending()
        self.assertEqual((row["name"], row["count"], row["last"]), ("busy", 0, self.now[1]))
        self.assertAlmostEqual(row["first"], start + 10 - 5.7, places=6)
        del self.cpu[hog.native_id]     # it ended: its seconds stay in the window for a while, and no row says them
        self.go(w, 10, {})
        self.assertEqual(diagnostics.pending(), [])
        said = self.journal.getvalue().splitlines()
        self.assertEqual(said[0], f"WARNING: the hub stalls (busy) at {HERE} {SPUN}")
        self.assertEqual(said[1], f"the hub's stall (busy) at {HERE} {SPUN} ended after about 36 s")      # 4.3 to 40
        self.assertEqual(len(said), 2)
        again = self.spinner()          # another thread runs there: a second stall
        self.go(w, 6, {again: 0.95})
        self.assertEqual([(r["name"], r["count"]) for r in diagnostics.pending()], [("busy", 1)])

    def test_a_little_work_is_no_stall_and_threads_that_ended_or_a_slow_machine_are(self):
        """The owner's hub, 21 November 2026: its process ran 0.004 to 0.12 of each window. A process that runs 0.5 of
        it is a stall, which names each thread that ran 0.1 of it; with no such thread (short threads that ended),
        it names no place; and looks that came late for half of a window while the process hardly ran are a slow
        machine."""
        hog, other = self.spinner(), self.spinner(spin_too)
        w = self.watch()
        self.go(w, 12, {hog: 0.4, other: 0.05})
        self.assertEqual(diagnostics.pending(), [])
        self.go(w, 10, {hog: 0.3, other: 0.25})
        rows = diagnostics.pending()
        self.assertEqual([(r["name"], r["count"]) for r in rows], [("busy", 1), ("busy", 1)])
        self.assertEqual({self.code(r["frames"])[0] for r in rows}, {(HERE, SPUN), (HERE, SPUN_TOO)})
        w = self.watch()        # a bystander that ran 1.1 s while the process ran 9.1 s is not named
        self.go(w, 12, {hog: 0.8, other: 0.11})
        self.assertEqual([self.code(r["frames"])[0] for r in diagnostics.pending()], [(HERE, SPUN)])
        w = self.watch()
        self.go(w, 12, {hog: 0.0}, process=0.8)
        self.assertEqual([(r["name"], r["frames"]) for r in diagnostics.pending()], [("busy", [["lib", 0]])])
        w = self.watch()
        self.go(w, 12, {hog: 0.0}, late=0.6, process=0.1)
        self.assertEqual([(r["name"], r["frames"]) for r in diagnostics.pending()], [("paused", [["lib", 0]])])

    def test_a_late_look_names_the_thread_that_held_the_lock_and_a_pause_names_none(self):
        """A look that comes STALL_HOLD late: one call held Python's interpreter lock. The thread that ran in that time
        is named, from when the hold began, also after another thread ran Python for most of the window; a hub that
        got no CPU, and a full collection of the garbage collector, are said as such."""
        busy, holder = self.spinner(), self.spinner(spin_too)
        w = self.watch()
        self.go(w, 6, {busy: 0.9, holder: 0.0})
        self.later(2.6)
        self.cpu[holder.native_id] += 2.5
        self.process[0] += 2.5
        w.look(2.5, 2.5)
        (row,) = diagnostics.pending()
        self.assertEqual((row["name"], row["first"], row["last"]), ("hold", self.now[1] - 2.5, self.now[1]))
        self.assertEqual(self.code(row["frames"])[0], (HERE, SPUN_TOO))
        self.go(w, 12, {busy: 0.0, holder: 0.0})        # that stall ends
        diagnostics.pending()
        self.cpu[holder.native_id] += 1.5   # a hold that came while the watch read: its newest reading is in the hold
        self.go(w, 1, {busy: 0.0, holder: 0.0}, process=1.5)
        self.later(0.1)
        self.cpu[holder.native_id] += 1.0
        self.process[0] += 1.0
        w.look(2.5, 2.5, inside=True)
        self.assertEqual([(r["name"], self.code(r["frames"])[0]) for r in diagnostics.pending()],
                         [("hold", (HERE, SPUN_TOO))])
        w = self.watch(cpu=False)
        for used, collecting in ((0.2, 0.0), (3.0, 2.0), (3.0, 0.5)):      # a pause, a collection, a short one
            self.later(3.1)
            w.look(3.0, used, collecting)
        self.assertEqual({r["name"]: r["frames"] for r in diagnostics.pending()},
                         {"paused": [["lib", 0]], "collect": [["lib", 0]], "hold": [["lib", 0]]})

    def test_a_thread_that_runs_near_the_bound_is_one_stall(self):
        """A thread at about half a CPU puts 4.88 to 5.12 s into each window, so the window crosses STALL_SHARE 63 times
        in 200 s: that is one stall, not 30, and the journal says it once."""
        hog = self.spinner()
        w = self.watch()
        for t in range(200):
            self.go(w, 1, {hog: 0.56 if (t // 3) % 2 == 0 else 0.44})
        self.assertEqual([(r["name"], r["count"]) for r in diagnostics.pending()], [("busy", 1)])
        self.assertEqual(self.journal.getvalue().count("WARNING"), 1)

    def test_a_thread_whose_time_before_the_window_is_not_known_is_not_named(self):
        """A thread that is not in a window's first reading counts all of its time only when that time fits in the
        window: one that ran 500 s before is not named for them."""
        w = self.watch()
        old = self.spinner(spin_too)
        self.cpu[old.native_id] = 500.0
        self.go(w, 10, {old: 0.6})
        self.assertEqual([(r["name"], r["frames"]) for r in diagnostics.pending()], [("busy", [["lib", 0]])])

    def test_a_fault_of_the_watch_is_counted_and_it_starts_again_three_times(self):
        """A look that raises is a fault of the hub, counted at each of STALL_TRIES starts, and then the watch ends:
        it neither dies at its first fault nor counts one ten times a second."""
        starts = []

        class Broken:
            def __init__(self, me):
                starts.append(me)

            def look(self, late, used, collecting=0.0, inside=False):
                raise KeyError("a fault of the watch")

        thread = threading.Thread(target=diagnostics.watch, args=(None, 0.001, Broken, 0.01), daemon=True)
        thread.start()
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(starts), diagnostics.STALL_TRIES)
        self.assertEqual([(r["kind"], r["name"], r["count"]) for r in diagnostics.pending()],
                         [("fault", "KeyError", diagnostics.STALL_TRIES)])

    def test_a_hold_that_comes_while_the_watch_reads_is_a_late_look(self):
        """The watch lets the interpreter lock go while it reads each thread's time. A look that took STALL_HOLD (a
        call held the lock in the meantime) is followed by a late look of that length."""
        looks = []

        class Slow:
            def __init__(self, me):
                pass

            def look(self, late, used, collecting=0.0, inside=False):
                looks.append(late)
                if len(looks) == 3:
                    time.sleep(0.3)         # as long as a hold that came while it read

        stop = threading.Event()
        with unittest.mock.patch.object(diagnostics, "STALL_HOLD", 0.2):
            thread = threading.Thread(target=diagnostics.watch, args=(stop, 0.01, Slow), daemon=True)
            thread.start()
            for _ in range(1000):
                if len(looks) >= 4:
                    break
                time.sleep(0.01)
            stop.set()
            thread.join(5)
        self.assertGreaterEqual(looks[3], 0.29)       # the look after the third, with no sleep of its own

    def test_a_hold_that_names_no_thread_is_not_also_a_busy_stall(self):
        """The seconds of a hold stay in the window after it: while the hold's stall goes on, they make no busy row with
        no place beside it."""
        w = self.watch(cpu=False)
        self.go(w, 9, {}, process=0.2)
        self.later(5.1)
        self.process[0] += 5.0
        w.look(5.0, 5.0)
        self.go(w, 12, {}, process=0.2)
        self.assertEqual([r["name"] for r in diagnostics.pending()], ["hold"])

    def test_a_hold_and_a_pause_are_not_also_a_slow_machine(self):
        """A slow machine is many small delays in a window. A window that holds a hold and a pause, each said already,
        is not one: the pause keeps its own length (a run on Linux, 21 November 2026, said it twice)."""
        w = self.watch(cpu=False)
        self.go(w, 2, {})
        self.later(3.5)
        w.look(3.4, 1.0)            # a hold in which the process ran a little
        self.go(w, 1, {})
        self.later(3.1)
        w.look(3.0, 0.0)            # and a pause
        pause = self.now[1]
        self.go(w, 12, {}, late=0.05)
        rows = {r["name"]: r for r in diagnostics.pending()}
        self.assertEqual(sorted(rows), ["hold", "paused"])
        self.assertEqual((rows["paused"]["count"], rows["paused"]["first"], rows["paused"]["last"]),
                         (1, pause - 3.0, pause))

    def test_a_look_waits_for_the_interpreter_lock_and_counts_the_process_and_the_collector(self):
        """The real loop: while one call of C code holds the interpreter lock, the watch's look comes as late as that
        call took, with the process's time in it, and a full collection is timed (gc.callbacks)."""
        looks = []

        class Seen:
            def __init__(self, me):
                self.me = me

            def look(self, late, used, collecting=0.0, inside=False):
                looks.append((late, used, collecting))

        gc.callbacks.append(diagnostics._gc_timer)
        self.addCleanup(gc.callbacks.remove, diagnostics._gc_timer)
        stop = threading.Event()
        thread = threading.Thread(target=diagnostics.watch, args=(stop, 0.01, Seen), daemon=True)
        thread.start()
        time.sleep(0.1)
        wall, cpu = time.perf_counter(), time.process_time()
        sum(range(30_000_000))          # one call: no other thread of Python runs until it returns
        held, spent = time.perf_counter() - wall, time.process_time() - cpu
        time.sleep(0.05)
        gc.collect()
        time.sleep(0.05)
        stop.set()
        thread.join(5)
        late, used, _ = max(looks)
        self.assertGreater(late, held * 0.8 - 0.02)
        self.assertGreater(used, spent * 0.8 - 0.02)
        self.assertGreater(sum(look[2] for look in looks), 0.0)
        self.assertEqual(diagnostics.pending(), [])         # the loop itself counts nothing

    def test_a_run_of_library_frames_is_one_place_and_the_innermost_twelve_stay(self):
        """A stall's places as a fault's: the code tree's files and lines, a run of the library's frames as one
        ("lib", 0), and the innermost MAX_FRAMES."""
        seen = []

        def hook(obj):
            seen.append(diagnostics.stack(diagnostics.frames_of(sys._getframe())))      # the innermost
            return obj

        json.loads("{}", object_hook=hook)          # json's own frames lie between this line and the hook
        called = inspect.currentframe().f_lineno - 1
        (places,) = seen
        self.assertEqual(places[-1], (HERE, inspect.getsourcelines(hook)[1] + 1))
        self.assertEqual(places[-2], ("lib", 0))
        self.assertEqual(places[-3], (HERE, called))

        def deep(n):
            return diagnostics.stack(diagnostics.frames_of(sys._getframe())) if n == 0 else deep(n - 1)

        self.assertEqual(len(deep(30)), diagnostics.MAX_FRAMES)

    def test_a_threads_time_is_its_user_and_system_time_past_a_name_with_brackets(self):
        """Linux's stat line of a thread: its name, in brackets, can hold spaces and brackets of its own."""
        with tempfile.TemporaryDirectory() as tasks:
            os.makedirs(os.path.join(tasks, "77"))
            with open(os.path.join(tasks, "77", "stat"), "w") as f:
                f.write("77 (a (b) c) S" + " 1" * 10 + " 250 50" + " 7" * 30 + "\n")
            self.assertEqual(diagnostics.thread_cpu([77, 78], tasks=tasks), {77: 300 / diagnostics._TICKS})
        self.assertIsNone(diagnostics.thread_cpu([77], tasks=os.path.join(tasks, "gone")))


class OnTheHub(OwnerAPI):
    def setUp(self):
        super().setUp()
        diagnostics.pending()
        # As test_health: a checkout of the hub's own, and an empty `~/.fleet` of this test.
        kit = os.path.join(self.tmp.name, "kit")
        os.makedirs(os.path.join(kit, "profiles"))
        with open(os.path.join(kit, "team.json"), "w") as f:
            json.dump(hub.TEAM, f)
        hub.CFG["team_path"] = os.path.join(kit, "team.json")
        self.addCleanup(hub.CFG.pop, "team_path", None)
        for key, name in (("google_file", "google.json"), ("mcp_file", "mcp.json"),
                          ("github_app", "github-app.pem"), ("attachment_dir", "attachments")):
            hub.CFG[key] = os.path.join(self.tmp.name, "fleet-home", name)
            self.addCleanup(hub.CFG.pop, key, None)

    def fault(self, times=1):
        words = canary()
        for _ in range(times):
            try:
                fail_with(KeyError(words))
            except KeyError:
                with contextlib.redirect_stderr(io.StringIO()):     # the journal's copy, as before
                    hub.print_fault()           # as each of the hub's 18 handlers does
        with hub.LOCK:
            hub.fault_flush(hub.now())
        return words

    def test_a_handled_fault_reaches_the_route_with_no_words(self):
        self.assertIn("diagnostics", hub.UI_FEATURES)
        words = self.fault(times=2)
        code, answer = self.request("/ui/diagnostics?db=test-generation")
        self.assertEqual(code, 200)
        (fault,) = answer["faults"]
        self.assertEqual((fault["class"], fault["count"], fault["program"]), ("KeyError", 2, "hub"))
        self.assertEqual(fault["frames"][-1]["file"], HERE)
        self.assertNotIn(words.split(" ")[0], json.dumps(answer))
        self.assertNotIn("Ana", json.dumps(answer))
        self.assertEqual(self.request("/ui/diagnostics?db=another")[0], 409)

    def test_the_route_is_the_owners_only(self):
        self.fault()
        code, _ = self.request("/ui/diagnostics?db=test-generation", source="127.0.0.9")
        self.assertNotEqual(code, 200)

    def test_a_refused_tool_call_is_counted_with_its_tool_or_other(self):
        said, refused = hub.call_tool("manager", "no_such_tool_" + uuid.uuid4().hex[:6], {})
        self.assertTrue(refused)
        with hub.LOCK:
            hub.fault_flush(hub.now())
        (row,) = self.request("/ui/diagnostics?db=test-generation")[1]["refusals"]
        self.assertEqual(row["tool"], "other")
        self.assertEqual(row["file"], "hub.py")
        self.assertNotIn("no_such_tool", json.dumps(row))

    def test_system_status_says_how_many_times_and_since_when_only_while_no_error_report_can_go(self):
        """With error reports off, the card "The hub hit an error" is the owner's one way out (Report a problem). With
        them on, the faults go to us by themselves and no app shows the card (the owner, 25 November 2026: "the user
        sholdn't even see anything!"): a hub that kept the warning would show him a card that asks him to do what
        already happened. Off again, the card is back as it was. On a release channel that is not our site no report
        ever goes, so it is as with reports off: the card stays, and a new fault asks for no early report. A hub that
        read only the switch would hide a fault that nobody gets."""
        self.fault(times=3)
        for on, channel in ((False, None), (True, None), (False, None), (True, "https://releases.example.com")):
            with hub.LOCK:
                hub.kv_set("error_reports", "1" if on else "0")
                hub.kv_set("release_channel", channel)
                warnings = [w for w in hub.health_view()["warnings"] if w["kind"] == "hub_fault"]
            if on and channel is None:
                self.assertEqual(warnings, [])
                continue
            self.assertEqual(len(warnings), 1)
            self.assertRegex(warnings[0]["detail"], r"^3 times since .+\.$")
            self.assertIsNone(warnings[0]["fix"])
        try:
            fail_with(ValueError(canary()))
        except ValueError:
            diagnostics.record("hub")
        with hub.LOCK:
            hub.fault_flush(hub.now())
        self.assertIsNone(hub.kv_get("error_reports_early_at"))

    def test_one_fault_says_once(self):
        self.fault()
        with hub.LOCK:
            (warning,) = [w for w in hub.health_view()["warnings"] if w["kind"] == "hub_fault"]
        self.assertRegex(warning["detail"], r"^Once at .+\.$")

    def test_rows_of_other_code_and_old_rows_end_at_the_next_write(self):
        hub.ins("INSERT INTO faults(sig,kind,program,name,frames,count,first,last,code) VALUES(?,?,?,?,?,?,?,?,?)",
                ("old-code", "fault", "hub", "KeyError", '[["hub.py",1]]', 1, 1.0, hub.now(), "another-code"))
        hub.ins("INSERT INTO faults(sig,kind,program,name,frames,count,first,last,code) VALUES(?,?,?,?,?,?,?,?,?)",
                ("too-old", "fault", "hub", "KeyError", '[["hub.py",2]]', 1, 1.0,
                 hub.now() - (hub.FAULT_DAYS + 1) * 86400, diagnostics.code_id()))
        self.fault()
        kept = {r["sig"] for r in hub.q("SELECT sig FROM faults")}
        self.assertNotIn("old-code", kept)
        self.assertNotIn("too-old", kept)
        self.assertEqual(len(kept), 1)

    def test_writing_the_counts_wakes_no_app(self):
        before = hub.CHANGE["state"]
        self.fault()
        self.assertEqual(hub.CHANGE["state"], before)

    def test_a_row_older_than_its_days_is_not_answered_before_a_write_ends_it(self):
        hub.ins("INSERT INTO faults(sig,kind,program,name,frames,count,first,last,code) VALUES(?,?,?,?,?,?,?,?,?)",
                ("too-old", "fault", "hub", "KeyError", '[["hub.py",2]]', 1, 1.0,
                 hub.now() - (hub.FAULT_DAYS + 1) * 86400, diagnostics.code_id()))
        self.assertEqual(self.request("/ui/diagnostics?db=test-generation")[1]["faults"], [])

    def test_a_database_without_the_table_answers_nothing_and_keeps_its_health(self):
        hub.ins("DROP TABLE faults")
        code, answer = self.request("/ui/diagnostics?db=test-generation")
        self.assertEqual((code, answer["faults"], answer["refusals"]), (200, [], []))
        with hub.LOCK:
            self.assertEqual([w for w in hub.health_view()["warnings"] if w["kind"] == "hub_fault"], [])

    def test_a_length_that_is_not_a_number_is_the_callers_mistake_and_no_fault(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
        connection.putrequest("POST", "/ui/command")
        connection.putheader("Content-Length", "z")
        connection.endheaders()
        self.assertEqual(connection.getresponse().status, 400)
        connection.close()
        self.assertEqual([row for row in diagnostics.pending() if row["kind"] == "fault"], [])

    def test_rpc_params_that_are_not_an_object_are_the_callers_mistake_and_no_fault(self):
        for params in ([1], "x", 3):        # an empty list is "no params", which the call takes
            answer = hub.rpc("manager", {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": params}, {})
            self.assertEqual(answer["error"]["code"], -32602)
        answer = hub.rpc("manager", {"jsonrpc": "2.0", "id": 2, "method": "initialize",
                                     "params": {"clientInfo": ["a list"]}}, {})
        self.assertNotIn("error", answer)
        self.assertEqual(diagnostics.pending(), [])


    def test_every_handler_counts_its_fault(self):
        with open(hub.__file__, encoding="utf-8") as f:
            source = f.read()
        self.assertEqual(source.count("traceback.print_exc()"), 1)      # only print_fault's own
        self.assertIn("step(fault_flush, t0)", source)
        start = inspect.getsource(hub.main)                           # read at the start, and a dying thread
        self.assertIn("diagnostics.code_id()", start)
        self.assertIn("threading.excepthook = thread_fault", start)
        self.assertIn("diagnostics.watch_stalls()", start)          # and a stall names itself while the hub runs

    def test_the_tick_writes_what_was_counted(self):
        try:
            fail_with(KeyError(canary()))
        except KeyError:
            with contextlib.redirect_stderr(io.StringIO()):
                hub.print_fault()
        hub.tick()
        self.assertEqual([r["name"] for r in hub.q("SELECT name FROM faults")], ["KeyError"])

    def test_counts_add_up_across_writes(self):
        def burst(times, at):
            for _ in range(times):
                try:
                    fail_with(KeyError("the same place"))
                except KeyError:
                    diagnostics.record("hub", clock=lambda: at)
            with hub.LOCK:
                hub.fault_flush(hub.now())
        first = round(hub.now() - 120, 3)
        burst(2, first)
        burst(1, first + 60)
        (fault,) = self.request("/ui/diagnostics?db=test-generation")[1]["faults"]
        self.assertEqual((fault["count"], fault["first"], fault["last"]), (3, first, round(first + 60, 3)))

    def test_the_routes_gate_answers_nothing_when_a_registered_login_is_in_it(self):
        self.fault()
        with unittest.mock.patch.object(hub, "secret_hit", return_value=True):
            code, answer = self.request("/ui/diagnostics?db=test-generation")
        self.assertEqual((code, answer["faults"], answer["refusals"]), (200, [], []))

    def test_the_warning_counts_only_recent_faults_of_this_code(self):
        def row(sig, kind, last, code):
            hub.ins("INSERT INTO faults(sig,kind,program,name,frames,count,first,last,code) VALUES(?,?,?,?,?,?,?,?,?)",
                    (sig, kind, "hub", "KeyError" if kind == "fault" else "read_messages", '[["hub.py",2]]', 5,
                     last, last, code))
        row("old", "fault", hub.now() - (hub.FAULT_WARN_HOURS + 1) * 3600, diagnostics.code_id())
        row("refused", "refusal", hub.now(), diagnostics.code_id())
        row("other-code", "fault", hub.now(), "another-code")
        with hub.LOCK:
            self.assertEqual([w for w in hub.health_view()["warnings"] if w["kind"] == "hub_fault"], [])
        answer = self.request("/ui/diagnostics?db=test-generation")[1]
        self.assertEqual(len(answer["faults"]), 1)                 # the old one of this code, within its 30 days
        self.assertEqual([r["tool"] for r in answer["refusals"]], ["read_messages"])

    def test_the_route_answers_only_tools_of_the_hubs_list(self):
        for sig, tool in (("made-up", "acme_merger"), ("real", "read_messages")):
            hub.ins("INSERT INTO faults(sig,kind,program,name,frames,count,first,last,code) VALUES(?,?,?,?,?,?,?,?,?)",
                    (sig, "refusal", "hub", tool, '[["hub.py",2]]', 1, hub.now(), hub.now(), diagnostics.code_id()))
        refusals = self.request("/ui/diagnostics?db=test-generation")[1]["refusals"]
        self.assertEqual([r["tool"] for r in refusals], ["read_messages"])

    def test_a_tool_of_the_hubs_list_keeps_its_name(self):
        self.assertEqual(hub.known_tool("read_messages"), "read_messages")
        self.assertEqual(hub.known_tool("read_messages_" + canary()), "other")
        self.assertEqual(hub.known_tool(None), "other")

    def test_a_read_or_a_write_that_the_database_refuses_makes_no_new_fault(self):
        """The pass's store of the counts raises nothing when the database refuses the read of the error reports'
        records or the write of the counts: else each pass would count a fault of its own. A refused read asks for no
        early report, and the counts are still stored."""
        try:
            fail_with(KeyError("x"))
        except KeyError:
            diagnostics.record("hub")
        with hub.LOCK, unittest.mock.patch.object(hub, "error_reports_go",
                                                  side_effect=hub.sqlite3.OperationalError("database is locked")):
            hub.fault_flush(hub.now())          # raises nothing
        self.assertEqual([r["name"] for r in hub.q("SELECT name FROM faults")], ["KeyError"])
        hub.ins("DROP TABLE faults")
        try:
            fail_with(KeyError("x"))
        except KeyError:
            diagnostics.record("hub")
        with hub.LOCK:
            hub.fault_flush(hub.now())          # raises nothing
        self.assertEqual(diagnostics.pending(), [])

    def test_the_servers_own_error_handler_and_a_dying_thread_count_their_faults(self):
        server = object.__new__(hub.HubServer)
        try:
            fail_with(KeyError(canary()))
        except KeyError:
            with contextlib.redirect_stderr(io.StringIO()):
                hub.HubServer.handle_error(server, None, ("127.0.0.1", 1))
        self.assertEqual([r["name"] for r in diagnostics.pending()], ["KeyError"])
        try:
            fail_with(ValueError(canary()))
        except ValueError as e:
            args = types.SimpleNamespace(exc_type=ValueError, exc_value=e, exc_traceback=e.__traceback__, thread=None)
        hub.thread_fault(args, default=lambda _args: None)
        hub.thread_fault(types.SimpleNamespace(exc_type=SystemExit, exc_value=SystemExit(), exc_traceback=None,
                                               thread=None), default=lambda _args: None)
        self.assertEqual([r["name"] for r in diagnostics.pending()], ["ValueError"])

    def test_a_body_larger_than_any_route_takes_is_refused_before_it_is_read(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
        connection.putrequest("POST", "/ui/command")
        connection.putheader("Content-Length", "99999999999999999999")
        connection.endheaders()
        self.assertEqual(connection.getresponse().status, 413)
        connection.close()
        self.assertEqual([row for row in diagnostics.pending() if row["kind"] == "fault"], [])

    def test_an_address_that_does_not_parse_is_no_route_and_no_fault(self):
        for method in ("GET", "POST"):
            connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
            connection.putrequest(method, "http://[x/", skip_host=True)     # the client would parse it for Host
            connection.putheader("Host", f"127.0.0.1:{self.server.server_port}")
            connection.putheader("Content-Length", "0")
            connection.endheaders()
            self.assertEqual(connection.getresponse().status, 404, method)      # not the board, and no fault
            connection.close()
        self.assertEqual([row for row in diagnostics.pending() if row["kind"] == "fault"], [])

    def test_a_client_that_goes_away_while_its_answer_goes_out_is_no_fault(self):
        class Stub(hub.Handler):
            def __init__(self, fails, answered):
                self.fails, self.started, self.sent, self.path = fails, answered, [], "/ui/state"
            def body_sent(self): return False         # do_GET's first check since 3f7c2b15
            def funnel_refused(self): return False
            def host_allowed(self): return True
            def site_allowed(self): return True
            def gone(self): return False
            def json(self, code, body, headers=None): self.sent.append(code)
            def get(self):
                self.answered = self.started
                raise self.fails
        for error in (TimeoutError("stalled"), ConnectionAbortedError("gone")):
            stub = Stub(error, answered=True)
            stub.do_GET()
            self.assertEqual((stub.sent, diagnostics.pending()), ([], []))
        stub = Stub(TimeoutError("the hub's own call"), answered=False)       # before the answer: the hub's fault
        with contextlib.redirect_stderr(io.StringIO()):
            stub.do_GET()
        self.assertEqual(stub.sent, [500])
        self.assertEqual([row["name"] for row in diagnostics.pending()], ["TimeoutError"])
        # The server's own handler keeps its rule (test_ui_api.ClientGone): a reset or a broken pipe is the client's,
        # and any other error there prints, so it is counted too.
        server = object.__new__(hub.HubServer)
        for error in (ConnectionResetError("x"), ConnectionAbortedError("x")):
            try:
                raise error
            except OSError:
                with contextlib.redirect_stderr(io.StringIO()):
                    hub.HubServer.handle_error(server, None, ("127.0.0.1", 1))
        self.assertEqual([row["name"] for row in diagnostics.pending()], ["ConnectionAbortedError"])

    def test_a_stall_reaches_the_route_and_the_days_report_and_no_warning(self):
        """The owner's "Yes, reports only" of 21 November 2026: a stall is in the route (Report a problem's rows read it)
        and in the day's error report, as a fault of its kind's class, and it is no fault of the hub and no warning of
        System status. A stall that goes on over several writes stays one row, whose first and last time say how long
        it lasted, also when the database refused the write of its first count."""
        clock, me = [100.0, hub.now() - 60], sys._getframe()
        w = diagnostics.Watch(cpu=lambda ids: {7: (clock[0] - 100.0) * 0.9}, frames=lambda: {70: me},
                              threads=lambda: [types.SimpleNamespace(native_id=7, ident=70)],
                              clock=lambda: clock[0], wall=lambda: clock[1], process=lambda: clock[0] - 100.0,
                              out=io.StringIO())
        for second in range(20):
            clock[0] += 1
            clock[1] += 1
            looked = sys._getframe().f_lineno + 1
            w.look(0.001, 1.0)
            if second % 5 == 4:
                with hub.LOCK:
                    hub.fault_flush(hub.now())
        later = [0.0, hub.now() - 10]
        w = diagnostics.Watch(cpu=lambda ids: None, clock=lambda: later[0], wall=lambda: later[1],
                              process=lambda: 0.0, out=io.StringIO())
        for _ in range(2):          # a pause that goes on, whose first count a write that the database refused lost
            later[0] += 3.1
            later[1] += 3.1
            w.look(3.0, 0.1)
            diagnostics.pending() if _ == 0 else None
        with hub.LOCK:
            hub.fault_flush(hub.now())
        code, answer = self.request("/ui/diagnostics?db=test-generation")
        self.assertEqual((code, answer["faults"], answer["refusals"]), (200, [], []))
        stalls = {s["kind"]: s for s in answer["stalls"]}
        self.assertEqual(sorted(stalls), ["busy", "paused"])
        busy, paused = stalls["busy"], stalls["paused"]
        self.assertEqual((busy["count"], round(busy["last"] - busy["first"])), (1, 19))      # it ran 9 s of the first window
        self.assertEqual(busy["frames"][-1], {"file": HERE, "line": looked})      # this test's frame, innermost
        self.assertEqual((paused["count"], round(paused["last"] - paused["first"]), paused["frames"]),
                         (1, 6, [{"file": "lib", "line": 0}]))
        with hub.LOCK:
            self.assertEqual([x for x in hub.health_view()["warnings"] if x["kind"] == "hub_fault"], [])
            body = hub.error_report_body(0)
        self.assertEqual(sorted(f["class"] for f in body["faults"]), ["StallBusy", "StallPaused"])
        self.assertEqual(body["refusals"], [])

    def test_the_table_keeps_the_newest_stall_rows_and_every_fault(self):
        """A stall's places vary from one stall to the next, so its rows are not bounded by the code's places as a
        fault's are: the table keeps the newest STALL_ROWS of them, and no fault goes with them."""
        t, code = hub.now(), diagnostics.code_id()
        for n in range(diagnostics.STALL_ROWS + 5):
            hub.ins("INSERT INTO faults(sig,kind,program,name,frames,count,first,last,code) VALUES(?,?,?,?,?,?,?,?,?)",
                    (f"stall-{n}", "stall", "hub", "busy", f'[["hub.py",{n + 1}]]', 1, t - 900 + n, t - 900 + n, code))
        hub.ins("INSERT INTO faults(sig,kind,program,name,frames,count,first,last,code) VALUES(?,?,?,?,?,?,?,?,?)",
                ("a-fault", "fault", "hub", "KeyError", '[["hub.py",1]]', 1, t - 990, t - 990, code))
        diagnostics._count(("stall", "hub", "hold", diagnostics.NO_PLACE), t)
        with hub.LOCK:
            hub.fault_flush(t)
        stalls = {r["sig"] for r in hub.q("SELECT sig FROM faults WHERE kind='stall'")}
        self.assertEqual(len(stalls), diagnostics.STALL_ROWS)
        self.assertNotIn("stall-0", stalls)
        self.assertNotIn("stall-5", stalls)
        self.assertIn(f"stall-{diagnostics.STALL_ROWS + 4}", stalls)
        self.assertEqual([r["sig"] for r in hub.q("SELECT sig FROM faults WHERE kind='fault'")], ["a-fault"])

    def test_a_flush_with_nothing_counted_writes_nothing(self):
        with hub.LOCK:
            hub.fault_flush(hub.now())
        self.assertEqual(hub.q("SELECT * FROM faults"), [])


if __name__ == "__main__":
    unittest.main()

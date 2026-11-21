"""Registered-login detection with punctuation. Hub database only; no network, no fleet."""
import hashlib
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import hub


def register(secret, salt="s1", known_length=True):
    hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES(?,?,?,?,?)",
            ("practice", salt, hashlib.sha256((salt + secret).encode()).hexdigest(),
             len(secret) if known_length else None, ""))


class Secrets(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fleet-secrets-")
        hub.DB = sqlite3.connect(self.tmp.name + "/t.db", check_same_thread=False)
        hub.DB.row_factory = sqlite3.Row
        hub.DB.executescript(hub.SCHEMA)
        hub.migrate()

    def tearDown(self):
        hub.DB.close()
        self.tmp.cleanup()

    def test_no_registered_login_means_no_hit(self):
        self.assertFalse(hub.secret_hit("Pr4ct!ce-Login#2026"))
        self.assertEqual(hub.secret_spans("Pr4ct!ce-Login#2026"), [])

    def test_punctuated_login_is_found_alone_and_glued(self):
        register("Pr4ct!ce-Login#2026")
        self.assertTrue(hub.secret_hit("the password is Pr4ct!ce-Login#2026 today"))
        self.assertTrue(hub.secret_hit("xxPr4ct!ce-Login#2026yy"))
        self.assertTrue(hub.secret_hit("line one\n(Pr4ct!ce-Login#2026),"))

    def test_login_split_by_whitespace_is_not_a_match(self):
        register("Pr4ct!ce-Login#2026")
        self.assertFalse(hub.secret_hit("Pr4ct!ce-Login #2026"))

    def test_json_escaped_login_is_found(self):
        register('ab"cd!efgh\\12')
        text = json.dumps({"args": 'use ab"cd!efgh\\12 here'})
        self.assertNotIn('ab"cd!efgh\\12', text)
        self.assertTrue(hub.secret_hit(text))

    def test_spans_give_exact_positions_for_masking(self):
        register("Pr4ct!ce-Login#2026")
        text = "a Pr4ct!ce-Login#2026 b xPr4ct!ce-Login#2026"
        spans = hub.secret_spans(text)
        self.assertEqual([text[s:e] for s, e in spans], ["Pr4ct!ce-Login#2026"] * 2)

    def test_masking_covers_punctuated_logins(self):
        register("Pr4ct!ce-Login#2026")
        self.assertEqual(hub.mask_secrets("use Pr4ct!ce-Login#2026, then xPr4ct!ce-Login#2026."),
                         f"use {hub.MASK} then {hub.MASK}")
        self.assertEqual(hub.mask_secrets("Pr4ct!ce-Login #2026"), "Pr4ct!ce-Login #2026")

    def test_a_mask_takes_the_run_so_a_later_login_that_overlaps_keeps_no_part(self):
        """A masked text is often kept. A login registered later that overlaps one masked at the write lies in the
        same run of characters, because no login holds whitespace: when only the first login's characters were
        masked, the rest of the later one stayed in the kept text, and a search finds a login only whole. So a mask
        takes the characters glued to a login, out to the whitespace or the double quote on each side. A double quote
        ends a JSON string, so a JSON text with a login in a value stays JSON."""
        early, later = "Ear1y-Login#77", "postgres://shop:Ear1y-Login#77@db.example:5432/shop"
        register(early, "s1")
        kept = hub.mask_secrets(f"connect with {later} now, then TOKEN={early}. Done")
        self.assertEqual(kept, f"connect with {hub.MASK} now, then {hub.MASK} Done")
        register(later, "s2")
        for part in ("postgres", "shop:", "@db.example", "5432", "TOKEN"):
            self.assertNotIn(part, kept)
        self.assertEqual(hub.mask_secrets(kept), kept)
        self.assertEqual(hub.mask_secrets(f"a\t{early}\nb {early}{early} c"), f"a\t{hub.MASK}\nb {hub.MASK} c")
        for answer in (json.dumps({"token": early, "n": 1}), json.dumps({"token": early, "n": 1}, separators=(",", ":")),
                       json.dumps({"db": later, "ids": [early, "x"]})):
            with self.subTest(answer=answer):
                masked = hub.mask_secrets(answer)
                self.assertNotIn(early[:6], masked)
                self.assertIn(hub.MASK, next(iter(json.loads(masked).values())))         # still JSON
        self.assertEqual(hub.mask_secrets(f'say "{early}". "x{early}y" then'), f'say "{hub.MASK}". "{hub.MASK}" then')
        self.assertEqual(hub.mask_secrets(f'a"{early}"b c'), f'a"{hub.MASK}"b c')
        register('"Qz7$efgh-Login', "s3")                     # a login that starts with a quote: its edge is in it
        self.assertEqual(hub.mask_secrets('x Q"Qz7$efgh-Login z'), f"x {hub.MASK} z")
        # An escaped quote is in a JSON string: the mask goes on past it and takes the backslash with it. A login
        # that holds a quote is there only escaped, and a mask that stopped at its quote left half of it.
        register('ZQ9#"WV7XY', "s4")
        register("ZQ5#WV7XYZ.", "s5")
        for value in ('"  x=ZQ9#"WV7XY=\nZQ5#WV7XYZ.\\', f'curl -H "Authorization: Bearer {early}" https://x',
                      f'export TOKEN="{early}"'):
            for answer in (json.dumps({"k": value, "n": 108}), json.dumps({"k": value}, separators=(",", ":"))):
                with self.subTest(answer=answer):
                    masked = hub.mask_secrets(answer)
                    self.assertTrue(hub.MASK in json.loads(masked)["k"])               # still JSON
                    for part in ("ZQ9", "WV7XY", early[:6]):
                        self.assertNotIn(part, masked)
        for text in ("no login here, at all.", "tabs\tand\nlines, \"quoted\" words", '{"a": "b", "c": [1, 2]}',
                     'a \\"escaped\\" one, ' + "x" * 300, "Ear1y-Login#7 and Ear1y-Login#78 are not it"):
            with self.subTest(text=text):
                self.assertEqual((hub.mask_secrets(text), hub.scrub(text)), (text, text))     # the same bytes

    def test_a_login_whose_final_dots_a_name_dropped_is_found(self):
        """A duty's name is its first sentence without the final dot, and a profile's "Responsible for" line ends
        without one: a login that ends in a dot there is kept and shown without it. The search finds a login whose
        last DROPPED_DOTS dots or fewer are gone, where the rest has LOGIN_LEAST characters or more and ends its run or
        comes before a character that is not a letter or a digit, as each place that sets a name in a line has it."""
        login = "Pr4ct!ce-Login#2026."
        register(login)
        bare = login[:-1]
        closers = ")" * 8                                       # the most closing characters after a rest: DOTS_TAIL
        for text in (bare, f"R-3 ({bare}) is open", f"Duties: {bare}, Answer refunds", f"R-3 {bare}: a case",
                     f"looks after: {bare}. Duties: none", f"x{bare}\n", f"{bare}_", f"({bare}{closers}",
                     f"the key {login} as it is"):
            with self.subTest(text=text):
                self.assertTrue(hub.secret_hit(text))
                self.assertNotIn(bare[:8], hub.mask_secrets(text))
        self.assertEqual([(s, e) for s, e in hub.secret_spans(f"R-3 ({bare}) is open")], [(5, 5 + len(bare))])
        self.assertEqual(hub.secret_spans(f"the key {login} as it is"), [(8, 8 + len(login))])     # whole: one span
        for text in (f"{bare}x is not it", f"{bare}9", f"{bare[:-1]}", f"{bare}é", f"{bare}_x", f"{bare}-tail",
                     f"({bare}{closers})"):
            with self.subTest(text=text):
                self.assertFalse(hub.secret_hit(text))          # a letter or a digit after it in its run: another word
        register("Ab3$efgh...", "s2")                           # three dots dropped: found; four: the name keeps them
        self.assertTrue(hub.secret_hit("R-4 (Ab3$efgh)"))
        register("Zz9$efgh....", "s3")
        self.assertFalse(hub.secret_hit("R-5 (Zz9$efgh)"))
        self.assertTrue(hub.secret_hit("R-5 (Zz9$efgh....)"))
        register("Qw7$efg.", "s4")                              # a rest of 7 is not looked for: a word as often as not
        register("admin...", "s5")
        register("Rt5$efg...", "s6")
        self.assertFalse(hub.secret_hit("R-6 (Qw7$efg) is open"))
        self.assertFalse(hub.secret_hit("R-7 (Rt5$efg) is open"))
        self.assertEqual(hub.mask_secrets("Ask the admin, then retry."), "Ask the admin, then retry.")
        self.assertEqual(hub.final_dots_off("Watch Zz9$efgh...."), "Watch Zz9$efgh....")
        self.assertEqual(hub.final_dots_off("Watch Ab3$efgh..."), "Watch Ab3$efgh")
        self.assertEqual(hub.final_dots_off("Watch abcd...."), "Watch abcd....")     # a run of 8 can hold a login
        self.assertEqual(hub.final_dots_off("Watch abc...."), "Watch abc")           # a run of 7 cannot
        self.assertEqual(hub.final_dots_off("Watch ........"), "Watch ")             # dots alone: nothing to show

    def test_a_lone_surrogate_is_in_no_login(self):
        """A JSON field can bring a lone surrogate, which no login holds: the search reads past it, where it used to
        stop with an exception on it."""
        register("Ab3$efgh-Login.", "s1")
        register("Ab3$efgh-Logins.", "s2")      # 16: a run of 15 is read only for its rest, which holds the surrogate
        for text in ("\ud800" + "a" * 14, "x \ud800Ab3$efgh-Logix y", "\ud800" * 20, "x \ud800b3$efgh-Logins y"):
            with self.subTest(text=repr(text)):
                self.assertFalse(hub.secret_hit(text))
        for text in ("\ud800 (Ab3$efgh-Login) \ud800", "x \ud800Ab3$efgh-Login y"):
            with self.subTest(text=repr(text)):
                self.assertTrue(hub.secret_hit(text))

    def test_a_rest_at_the_end_of_a_line_in_json_is_found(self):
        """A JSON text writes a line break or a tab inside a string as two characters of the run (\\n, \\r, \\t), and
        json_plain leaves them as they are: a name at the end of a line of a start text, a team line or a tool's answer
        in JSON ends there, as at the end of a run, and is masked inside its value."""
        register("Zq9$Wv7xy.")
        name = "Rotate Zq9$Wv7xy"
        for text in (json.dumps({"text": f"Your duty R-3: {name}\nWatch it"}), json.dumps({"t": f"{name}\tWatch it"}),
                     json.dumps({"start": f"leo: looks after: {name}\nmia: none"}),
                     json.dumps({"t": f"R-3 ({name}),\r\nnext"}, separators=(",", ":"))):
            with self.subTest(text=text):
                self.assertTrue(hub.secret_hit(text))
                masked = hub.mask_secrets(text)
                self.assertNotIn("Zq9$", masked)
                self.assertIn(hub.MASK, next(iter(json.loads(masked).values())))            # still JSON
        self.assertFalse(hub.secret_hit(json.dumps({"t": f"{name}x\nWatch it"})))           # another word

    def test_a_json_escaped_login_whose_final_dot_was_dropped_is_found(self):
        """secret_hit also reads a text with its JSON string escapes undone (json_plain), and that reading finds a
        login whose final dots a name dropped too: a tool's answer in JSON carries a duty's name that way."""
        login = 'ab"cd!efgh\\12.'
        register(login)
        text = json.dumps({"title": 'R-3 (ab"cd!efgh\\12)', "n": 1})
        self.assertNotIn(login[:-1], text)
        self.assertTrue(hub.secret_hit(text))
        self.assertEqual(hub.mask_secrets(text), hub.MASK)
        self.assertEqual(hub.scrub({"answer": text}), {"answer": hub.MASK})

    def test_only_the_runs_that_can_hold_a_login_are_read(self):
        """The search reads only the runs of at least the length of the shortest login of the key, less the dots
        that a name may drop down to a rest of LOGIN_LEAST: one search of the whole text finds them. A state read held
        178,399 runs, and 2,922 of them were long enough for the live fleet's shortest login, of 30 characters (11
        November 2026). A rest is looked for only in a run that a name can make, of DOTS_RUN_MOST characters at most:
        a long run full of punctuation would cost three hashes a character for each login."""
        asked = []
        real = hub.long_runs
        def recorded(least):
            asked.append(least)
            return real(least)
        login30, login8 = "Pr4ct!ce-Login#2026-abcdefghi.", "Ab3$efgh"
        self.assertEqual((len(login30), len(login8)), (30, 8))
        register(login30, "s1")
        hub.long_runs = recorded
        self.addCleanup(setattr, hub, "long_runs", real)
        self.assertTrue(hub.secret_hit(f"short words and then {login30} here"))
        self.assertEqual(asked, [30 - hub.DROPPED_DOTS])
        self.assertTrue(hub.secret_hit("R-1 (" + "x" * 225 + login30[:-1] + ")"))         # a run of 256
        self.assertFalse(hub.secret_hit("R-1 (" + "x" * 226 + login30[:-1] + ")"))        # of 257
        self.assertTrue(hub.secret_hit("R-1 (" + "x" * 300 + login30 + ")"))             # whole: any run
        register(login8, "s2")
        self.assertTrue(hub.secret_hit(f"short words and then {login8} here"))
        self.assertEqual(asked[-1], 8)
        register("Legacy12345", "s3", known_length=False)
        self.assertTrue(hub.secret_hit("token Legacy12345 here"))
        self.assertEqual(hub.SECRET_TEXT_LEAST, hub.LOGIN_LEAST)
        self.assertGreaterEqual(hub.DOTS_RUN_MOST, max(hub.LOOKS_AFTER_MAX, hub.DUTY_NAME_MAX) + 8)

    def test_legacy_rows_without_length_match_whole_tokens(self):
        register("Legacy12345", known_length=False)
        self.assertTrue(hub.secret_hit("token Legacy12345 here"))
        self.assertFalse(hub.secret_hit("token xLegacy12345x here"))

    def test_a_new_registration_is_not_hidden_by_the_cache(self):
        text = "deploy with Ch@nge-Me-2026! now"
        self.assertFalse(hub.secret_hit(text))
        register("Ch@nge-Me-2026!", salt="s2")
        self.assertTrue(hub.secret_hit(text))

    def long_text(self, marker=""):
        """Rows with a login, a login whose last dots a name dropped and a row with no length, and a text whose search
        is long (one run of 40,000 characters) with them in it, beside split surrogate pairs and a lone surrogate."""
        register("Pr4ct!ce-Login#2026...", "s1")
        register("tokenABCDEFGH12345", "s2", known_length=False)
        register("Zz9$long-secret-value", "s3")
        pair = chr(0xD83D) + chr(0xDE00)        # a pair of surrogates as two characters: JSON made one of them
        text = (pair * 25 + marker + "x" * 40000 + " see Pr4ct!ce-Login#2026 and tokenABCDEFGH12345 \ud800 x "
                "Zz9$long-secret-value. done")
        key = hub.secret_key()
        self.assertGreaterEqual(hub.search_work(text, key), hub.SEARCH_CHILD_WORK)
        return text, key

    def test_a_long_search_runs_in_a_child_process_with_the_same_spans(self):
        """The search hashes each window of each run for each login, in pure Python, and holds Python's interpreter
        lock while it runs: on 20 November 2026 the 5.7 MB of one delivery's files took about 4 minutes, and every
        call of the hub ran about 100 times slower meanwhile. A text whose search is long (search_work) is searched in
        a child process, with the search that this process runs, and gives the same spans: a login whole, one whose
        last dots a name dropped, a row with no length, after pairs of surrogates (JSON would have made one character
        of each pair and moved every span after them) and with a lone one. Its own thread searches nothing. A long
        text with no long run (words) is searched here."""
        text, key = self.long_text()
        key = key + key[:1]                                  # a row twice
        here = hub.secret_spans_here(text, key)
        self.assertEqual(len(here), 3)
        searched = hub.secret_spans_here
        with patch.object(hub, "secret_spans_here", lambda text, key: self.fail("searched here")):
            self.assertEqual(hub.secret_spans_each(text, key), here)
            self.assertTrue(hub.secret_hit(text + " "))
        words = "a few words " * 10000 + "Zz9$long-secret-value"
        with patch.object(hub, "login_search_child", lambda asks: self.fail("a child")):
            self.assertEqual(hub.secret_spans_each(words, key), searched(words, key))

    def test_a_child_that_fails_is_tried_again_then_its_long_text_counts_as_a_login(self):
        """A child that cannot run the search (no Python to start, a fault) is tried once more. When no child finishes
        (two failed, or one passed its time, which is not tried again), each long text of the ask counts as holding
        each login of its ask, and only its short texts are searched here: the search of a long text here would hold
        the interpreter lock for minutes or hours, as on 20 November 2026, and a hub that missed a login would let it
        through. Each row gets the span, so a text stays marked while any of them stays registered: with the first
        row's span alone, its removal let the text pass as clean, also in the cache's file (a review of 21 November
        2026)."""
        text, key = self.long_text()
        here, real, calls, real_here = hub.secret_spans_here(text, key), hub.subprocess.run, [], hub.secret_spans_here

        def once_wrong(*args, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise OSError("no child")
            return real(*args, **kwargs)

        with patch.object(hub.subprocess, "run", once_wrong), patch.object(hub.diagnostics, "record") as recorded:
            self.assertEqual(hub.secret_spans_each(text, key), here)
        self.assertEqual((len(calls), recorded.call_count), (2, 1))
        short, rows = "a few words and Zz9$long-secret-value.", tuple(key)
        whole = {row: [(0, len(text))] for row in rows}
        # a search of about a second or less (below SEARCH_LONG_WORK, as this text) runs here when no child finished
        with patch.object(hub.subprocess, "run", side_effect=OSError("no child")), \
                patch.object(hub.diagnostics, "record") as recorded:
            self.assertEqual(hub.searched_once([(text, rows)]), [here])
        self.assertEqual(recorded.call_count, 2)
        long = patch.object(hub, "SEARCH_LONG_WORK", hub.search_work(text, rows))      # and this text counts as long
        with long, patch.object(hub.subprocess, "run", side_effect=OSError("no child")), \
                patch.object(hub.diagnostics, "record") as recorded, \
                patch.object(hub, "secret_spans_here", side_effect=lambda t, k: here if t == text else real_here(t, k)):
            self.assertEqual(hub.searched_once([(text, rows), (short, rows)]), [whole, real_here(short, rows)])
            hub.secret_spans_here.assert_called_once_with(short, rows)        # the long text is not searched here
        self.assertEqual(recorded.call_count, 2)
        calls = []

        def late(args, **kwargs):
            calls.append(1)
            raise subprocess.TimeoutExpired(args, hub.SEARCH_CHILD_SECONDS)

        with long, patch.object(hub.subprocess, "run", late), patch.object(hub.diagnostics, "record") as recorded:
            self.assertEqual(hub.searched_once([(text, rows), (short, rows)]), [whole, real_here(short, rows)])
        self.assertEqual((len(calls), recorded.call_count), (1, 1))
        # and with no program for a child at all, every text is searched here, as before the child
        with patch.object(hub, "LOGIN_SEARCH_PROGRAM", None):
            self.assertEqual(hub.secret_spans_each(text, key), here)

    def test_no_thread_waits_for_the_child_of_another_text(self):
        """A thread that holds the hub's lock and searches a long text never waits for another thread's child: one
        search at a time would hold the lock, and every route, for all of a delivery's search (minutes), and the child
        of a thread without the lock runs at nice 10, behind the hub's own threads. Two asks of the same text and rows
        share one child, as the helper sends its files again after its own time; an ask of the same text for other
        rows takes no answer of theirs (a login registered meanwhile would be missed, and the cache would keep the
        text as searched for it)."""
        first, key = self.long_text("first" + "y" * 20000)
        second, fewer = first.replace("first", "other"), key[:2]
        real, started, release, calls, answers = hub.subprocess.run, threading.Event(), threading.Event(), [], {}

        def slow_first(*args, **kwargs):
            calls.append(kwargs["input"])
            if b"first" in kwargs["input"] and not hub.LOCK._is_owned():
                started.set()
                self.assertTrue(release.wait(60))
            return real(*args, **kwargs)

        def ask(name, text, rows):
            answers.setdefault(name, []).append(hub.secret_spans_each(text, rows))

        def under_lock():
            with hub.LOCK:
                ask("locked", second, key)
                ask("locked", first, key)       # the same text and rows as a child that waits

        with patch.object(hub.subprocess, "run", slow_first):
            threads = [threading.Thread(target=ask, args=("all", first, key)) for _ in range(2)]
            threads.append(threading.Thread(target=ask, args=("fewer", first, fewer)))
            for thread in threads:
                thread.start()
            self.assertTrue(started.wait(60))
            locked = threading.Thread(target=under_lock)
            locked.start()
            locked.join(30)                      # it ends while the first text's children still wait
            self.assertEqual(answers.get("locked"), [hub.secret_spans_here(second, key),
                                                     hub.secret_spans_here(first, key)])
            release.set()
            for thread in threads:
                thread.join(60)
        self.assertEqual(answers["all"], [hub.secret_spans_here(first, key)] * 2)
        self.assertEqual(answers["fewer"], [hub.secret_spans_here(first, fewer)])
        # each child: whether it searched the first text, its nice and its rows. The lock holder's two run at the
        # hub's own priority, which every route then waits for
        heads = [(b"first" in asked, json.loads(asked.split(b"\n", 1)[0])) for asked in calls]
        self.assertEqual(sorted((has, head["nice"], len(head["rows"])) for has, head in heads),
                         [(False, 0, 3), (True, 0, 3), (True, 10, 2), (True, 10, 3)])

    def test_a_long_search_waits_for_a_place_and_a_shorter_one_does_not(self):
        """The children of long searches (SEARCH_LONG_WORK) of threads without the lock run at most one for each
        processor, as each holds its text for up to SEARCH_CHILD_SECONDS; a shorter search takes no place, so that it
        never waits hours behind a delivery's search, and a thread that holds the lock never waits for one (a review of
        21 November 2026)."""
        first, key = self.long_text("first" + "y" * 100000)
        second, short = first.replace("first", "other"), "short " + "z" * 40000 + " Zz9$long-secret-value"
        third = first.replace("first", "third")
        self.assertGreater(hub.search_work(second, key), hub.search_work(short, key))
        self.assertGreaterEqual(hub.search_work(short, key), hub.SEARCH_CHILD_WORK)        # a child, and no place
        real, started, release, calls, answers, places = hub.subprocess.run, threading.Event(), threading.Event(), \
            [], {}, []

        def slow_first(*args, **kwargs):
            calls.append(kwargs["input"])
            if b"first" in kwargs["input"]:
                started.set()
                self.assertTrue(release.wait(60))
            return real(*args, **kwargs)

        class Places(threading.BoundedSemaphore):
            def __enter__(self):
                places.append(1)
                return super().__enter__()

        def ask(name, text):
            answers[name] = hub.secret_spans_each(text, key)

        def under_lock(name, text):
            with hub.LOCK:
                ask(name, text)

        threads = {name: threading.Thread(target=ask, args=(name, text))
                   for name, text in (("first", first), ("second", second), ("short", short))}
        threads["third"] = threading.Thread(target=under_lock, args=("third", third))
        with patch.object(hub.subprocess, "run", slow_first), patch.object(hub, "SEARCH_CHILDREN", Places(1)), \
                patch.object(hub, "SEARCH_LONG_WORK", hub.search_work(second, key)):
            try:
                threads["first"].start()
                self.assertTrue(started.wait(60))
                threads["second"].start()
                threads["short"].start()
                threads["short"].join(30)                   # its answer comes while the one place is taken
                self.assertFalse(threads["short"].is_alive())
                threads["third"].start()
                threads["third"].join(30)                   # and a long one under the lock takes no place
                self.assertFalse(threads["third"].is_alive())
                deadline = time.monotonic() + 30
                while len(places) < 2 and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertEqual((len(places), len(calls)), (2, 3))     # the second long one waits for the place
            finally:
                release.set()
                for thread in threads.values():
                    if thread.is_alive() or thread.ident:
                        thread.join(60)
        self.assertEqual(answers, {name: hub.secret_spans_here(text, key) for name, text in
                                   (("first", first), ("second", second), ("short", short), ("third", third))})

    def test_a_delivery_searches_its_files_together(self):
        """Each file of a delivery alone can be short enough to be searched here, and 100 of them were 100 s of the
        interpreter lock (a review of 20 November 2026). Inside searched_ahead they are searched together, in one
        child, with the forms that secret_hit reads, and each secret_hit of them takes that answer."""
        register("Zz9$long-secret-value", "s3")
        key = hub.secret_key()
        files = [f"file {n} " + "y" * 3000 + (" Zz9$long-secret-value" if n == 7 else "") for n in range(40)]
        self.assertLess(max(hub.search_work(f, key) for f in files), hub.SEARCH_CHILD_WORK)
        self.assertGreaterEqual(sum(hub.search_work(f, key) for f in files), hub.SEARCH_CHILD_WORK)
        children, real = [], hub.login_search_child

        def child(asks):
            children.append(len(asks))
            return real(asks)

        long = "long " + "w" * 200000            # its own search reaches the bound: a child of its own, at its ask
        with patch.object(hub, "login_search_child", child):
            with hub.searched_ahead(files + [long]):
                with patch.object(hub, "secret_spans_here", lambda text, key: self.fail("searched here")):
                    self.assertEqual([hub.secret_hit(f) for f in files + [long]], [n == 7 for n in range(41)])
        self.assertEqual(children, [40, 1])
        # a login registered while the files are checked: each file is searched for it too, and takes no answer of
        # the rows of before, which would keep it in the cache as searched for the new login
        late = [f"late {n} " + "z" * 3000 + (" Qq8#second-secret-value" if n == 3 else "") for n in range(40)]
        with hub.searched_ahead(late):
            register("Qq8#second-secret-value", "s4")
            self.assertEqual([hub.secret_hit(f) for f in late], [n == 3 for n in range(40)])

    def test_two_sends_of_one_delivery_share_one_child(self):
        """A helper sends a delivery's files again after its own 120 s, and again while the delivery waits: each send
        started one more child for all the files, and 4 to 12 of them at once could take a small hub's memory (a review
        of 20 November 2026). Sends of the same files share the first send's child, and each takes its answer."""
        register("Zz9$long-secret-value", "s3")
        files = [f"send {n} " + "y" * 3000 + (" Zz9$long-secret-value" if n == 7 else "") for n in range(40)]
        real, started, release, calls, hits = hub.subprocess.run, threading.Event(), threading.Event(), [], []

        def slow(*args, **kwargs):
            calls.append(1)
            started.set()
            self.assertTrue(release.wait(60))
            return real(*args, **kwargs)

        def send():
            with hub.searched_ahead(files):
                hits.append([hub.secret_hit(f) for f in files])

        with patch.object(hub.subprocess, "run", slow):
            first = threading.Thread(target=send)
            first.start()
            self.assertTrue(started.wait(60))
            second = threading.Thread(target=send)
            second.start()
            second.join(1)                       # it waits for the first send's child
            release.set()
            for thread in (first, second):
                thread.join(60)
        self.assertEqual(hits, [[n == 7 for n in range(40)]] * 2)
        self.assertEqual(len(calls), 1)

    def test_a_search_that_failed_gives_its_waiters_the_answer_of_a_search_here(self):
        """When the child of a shared search fails, the thread that ran it searches here and gives that answer to each
        thread that waited: a waiter that took the failure for no login found would let the login through."""
        text, key = self.long_text()
        here, started, release = hub.secret_spans_here(text, key), threading.Event(), threading.Event()

        def failing(*args, **kwargs):
            started.set()
            self.assertTrue(release.wait(60))
            raise OSError("no child")

        answers = []
        with patch.object(hub.subprocess, "run", failing), patch.object(hub.diagnostics, "record"):
            threads = [threading.Thread(target=lambda: answers.append(hub.secret_spans_each(text, key)))
                       for _ in range(2)]
            threads[0].start()
            self.assertTrue(started.wait(60))
            threads[1].start()
            threads[1].join(1)
            release.set()
            for thread in threads:
                thread.join(60)
        self.assertEqual(answers, [here, here])
        # A searcher that ends with no answer at all (an exception, as a MemoryError under a large delivery): its
        # waiter searches itself, and takes no None for an answer.
        real, started, release, answers = hub.searched_by_child, threading.Event(), threading.Event(), []

        def raising(asks):
            if not started.is_set():
                started.set()
                self.assertTrue(release.wait(60))
                raise MemoryError("no room")
            return real(asks)

        def ask():
            try:
                answers.append(hub.secret_spans_each(text, key))
            except MemoryError:
                answers.append("raised")

        with patch.object(hub, "searched_by_child", raising):
            threads = [threading.Thread(target=ask) for _ in range(2)]
            threads[0].start()
            self.assertTrue(started.wait(60))
            threads[1].start()
            threads[1].join(1)                  # it waits for the first one's search
            release.set()
            for thread in threads:
                thread.join(60)
        self.assertEqual(answers, ["raised", here])

    def test_the_child_runs_the_code_that_this_process_runs(self):
        """The child's program is the search of this process, made from hub.py on the disk at the import. A release
        changes hub.py before the hub starts again, so a program whose functions differ from this process's own is
        none, and every search runs here."""
        self.assertIsNotNone(hub.LOGIN_SEARCH_PROGRAM)
        real = hub.inspect.getsource

        def changed(fn):
            text = real(fn)
            return text.replace("return min(", "return max(") if fn is hub.run_least else text

        with patch.object(hub.inspect, "getsource", changed), patch.object(hub.diagnostics, "record") as recorded:
            self.assertIsNone(hub.login_search_program())
        self.assertEqual(recorded.call_count, 1)
        # and a value that the search reads and the program does not hold (one added to the search and not to
        # LOGIN_SEARCH_VALUES) makes no program: each child would fail on it
        values = tuple(name for name in hub.LOGIN_SEARCH_VALUES if name != "DOTS_TAIL")
        with patch.object(hub, "LOGIN_SEARCH_VALUES", values), patch.object(hub.diagnostics, "record") as recorded:
            self.assertIsNone(hub.login_search_program())
        self.assertEqual(recorded.call_count, 1)

    def test_a_child_ends_with_the_hub_that_asked(self):
        """exec_again keeps the hub's children, and systemd's KillMode=process stops only the hub: a child searched on
        to its end, for an hour and more, for a hub that was gone (a review of 21 November 2026). A child ends when no
        process holds the other end of its pipe (the hub's exec or its end closes it), and at its own alarm."""
        text, key = self.long_text()
        text = text.replace("x" * 40000, "x" * 20000000)        # a search of a minute and more
        life = os.pipe()
        answers, t0 = [], time.monotonic()
        with patch.object(hub, "LOGIN_SEARCH_LIFE", life), patch.object(hub.diagnostics, "record") as recorded:
            os.close(life[1])                    # the hub is gone: no process holds the write end
            thread = threading.Thread(target=lambda: answers.append(hub.login_search_child([(text, tuple(key))])))
            thread.start()
            thread.join(60)
        os.close(life[0])
        self.assertEqual(answers, [hub.SEARCH_UNDONE])     # both children ended at once
        self.assertLess(time.monotonic() - t0, 20)
        self.assertEqual(recorded.call_count, 2)
        rows, data = [list(row) for row in key], text.encode("utf-8", "surrogatepass")
        head = {"rows": rows, "texts": [[len(data), list(range(len(rows)))]], "nice": 10, "seconds": 3}
        r, w = os.pipe()
        child = subprocess.Popen([sys.executable, "-I", "-S", "-c", hub.LOGIN_SEARCH_PROGRAM], stdin=subprocess.PIPE,
                                 stdout=subprocess.DEVNULL, pass_fds=(r,), env={})
        child.stdin.write(json.dumps(dict(head, life=r)).encode() + b"\n" + data)
        child.stdin.close()
        time.sleep(0.5)
        nice = os.getpriority(os.PRIO_PROCESS, child.pid) - os.getpriority(os.PRIO_PROCESS, 0)
        child.wait(60)
        os.close(r)
        os.close(w)
        self.assertEqual(child.returncode, -signal.SIGALRM)     # its alarm, with the hub still there
        self.assertEqual(nice, min(10, 19 - os.getpriority(os.PRIO_PROCESS, 0)))     # behind the hub's own threads


if __name__ == "__main__":
    unittest.main()

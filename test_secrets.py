"""Registered-login detection with punctuation. Hub database only; no network, no fleet."""
import hashlib
import json
import sqlite3
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()

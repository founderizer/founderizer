"""The package of the Teams code and its lock (teamspack.py; Founderizer for Teams, design 2, section 3.3).

A hub with a live licence runs the files of one package beside its checkout: the package whose hash the lock of its
release names, and no other. What is held here: the same files give the same bytes; a lock is read field by field; a
package that no release could name is refused before any byte of it is written; a folder counts as the package only
while its files are that package; and the one GET of a package sends the token only as its bearer. No network but a
stand-in of this module on the loopback address.

The seam's half (Seam) holds hub.py's region "Teams parts: the one seam of Core" (design 2, 3.4), with stand-in parts in
a package that each test writes: a fleet with no licence reads and imports nothing of it, a part loads only from the
bytes whose hash the lock of the code names, and a fault of a part is a line of build_schema, and no stop of the
hub."""
import contextlib
import hashlib
import http.server
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import py_compile
import shutil
import socket
import sqlite3
import stat
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import hub
import refusal_words
import teamspack
from test_ui_api import quick

LICENCE = "TEAMS-LICENSE.md"
FILES = {LICENCE: "DRAFT. Not in force.\n", "teams_demo.py": "FEATURE = 'demo'\r\n\n\ndef start(H):\n    return H\n",
         "teams_demo.json": '{"name": "' + chr(0xE9) + chr(0x1F600) + '"}\n'}


def raw(whole):
    """`whole` in the package's one form, whatever it holds: what a channel or a disk could give a hub."""
    return (json.dumps(whole, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def free_port():
    """A port of the loopback address on which nothing listens."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Folders(unittest.TestCase):
    def folder(self):
        made = Path(tempfile.mkdtemp(prefix="fleet-teamspack-"))
        self.addCleanup(shutil.rmtree, str(made), True)
        return made

    def placed(self):
        """(the root of the packages, the package's bytes, its lock, its folder) after one place."""
        root, data = self.folder() / "teams", teamspack.pack(FILES)
        lock = teamspack.lock_of(data)
        return root, data, lock, Path(teamspack.place(data, lock, str(root)))


class PackAndLock(Folders):
    def test_the_same_files_give_the_same_bytes_and_their_lock_reads_back(self):
        """The lock in a release's tree is made on the Mac, and a hub checks the package against it on a server, so
        two machines that pack the same files must make the same bytes, and a hub reads only a lock whose every field
        is one that a release writes. Bug: each hub with Teams refuses its package, or reads a lock whose size is
        larger than any package."""
        data = teamspack.pack(FILES)
        self.assertEqual(teamspack.pack(dict(reversed(list(FILES.items())))), data)
        self.assertTrue(data.isascii() and data.endswith(b"}\n") and data.count(b"\n") == 1, data)
        self.assertEqual(teamspack.unpacked(data), FILES)       # each byte of each text, a line end of \r\n too
        lock = teamspack.lock_of(data)
        self.assertEqual(lock, {"files": 1, "format": 1, "sha256": hashlib.sha256(data).hexdigest(),
                                "size": len(data)})
        self.assertEqual(teamspack.lock_text(lock), json.dumps(lock, sort_keys=True) + "\n")
        self.assertEqual(teamspack.read_lock(teamspack.lock_text(lock)), lock)
        for wrong in ("", "[]", "{}", "not json", dict(lock, files=True), dict(lock, files=-1), dict(lock, format=2),
                      dict(lock, sha256=lock["sha256"].upper()), dict(lock, sha256=lock["sha256"][:63]),
                      dict(lock, size=0), dict(lock, size=teamspack.MOST_BYTES + 1), dict(lock, size=1.5),
                      dict(lock, more=1)):
            with self.subTest(wrong=wrong):
                self.assertIsNone(teamspack.read_lock(wrong if isinstance(wrong, str) else json.dumps(wrong)))

    def test_a_package_that_no_release_could_name_is_refused(self):
        """A name with a folder in it would write a file outside the package's folder, and bytes that are not the
        one form of their files would let one lock name two sets of files. Bug: a hub writes a file outside its
        folder, or loads bytes that no release named."""
        data = teamspack.pack(FILES)
        many = {f"teams_{n}.py": "" for n in range(teamspack.MOST_FILES + 1)}
        for name, wrong in [
                ("a folder in a name", raw({"files": {"sub/teams_x.py": ""}, "format": 1})),
                ("a way up", raw({"files": {"../teams_x.py": ""}, "format": 1})),
                ("a way up at the end", raw({"files": {"teams_x.py/..": ""}, "format": 1})),
                ("a name of another kind", raw({"files": {"teams_x.sh": ""}, "format": 1})),
                ("a file that is a number", raw({"files": {"teams_x.py": 1}, "format": 1})),
                ("a file with a NUL", raw({"files": {"teams_x.py": "a" + chr(0) + "b"}, "format": 1})),
                ("a file that UTF-8 cannot hold", raw({"files": {"teams_x.py": chr(0xD800)}, "format": 1})),
                ("too many files", raw({"files": many, "format": 1})),
                ("too many bytes", raw({"files": {"teams_x.py": "x" * teamspack.MOST_BYTES}, "format": 1})),
                ("another format", raw({"files": {}, "format": 2})),
                ("a field more", raw({"files": {}, "format": 1, "more": 1})),
                ("not its one form", data.replace(b'":', b'": ', 1)),
                ("no line end", data[:-1]),
                ("no JSON", b"\x00" + data),
                ("no bytes", data.decode("ascii"))]:
            with self.subTest(name):
                with self.assertRaises(ValueError):
                    teamspack.unpacked(wrong)
                with self.assertRaises(ValueError):
                    teamspack.lock_of(wrong)
        with self.assertRaises(ValueError):
            teamspack.pack(many)


class OnTheHub(Folders):
    def test_place_writes_only_the_package_that_the_lock_names(self):
        """Each check comes before the first byte is written, and the folder appears whole, by one rename, readable
        by the hub's user alone. Bug: a hub loads bytes that no release named, or a half-written package."""
        data = teamspack.pack(FILES)
        lock, root = teamspack.lock_of(data), self.folder() / "teams"
        changed = data.replace(b"DRAFT", b"DRAFt")
        for wrong, its_lock in ((changed, lock), (data[:-1], lock), (data, dict(lock, files=2)), (data, "no lock")):
            with self.subTest(its_lock=its_lock):
                with self.assertRaises(ValueError):
                    teamspack.place(wrong, its_lock, str(root))
                self.assertFalse(root.exists())
        folder = teamspack.place(data, lock, str(root))
        self.assertEqual(folder, str(root / lock["sha256"]))
        self.assertEqual(os.listdir(root), [lock["sha256"]])             # no temporary folder stays
        self.assertEqual(stat.S_IMODE(os.stat(folder).st_mode), 0o700)
        for name, text in FILES.items():
            self.assertEqual((Path(folder) / name).read_bytes(), text.encode("utf-8"))
            self.assertEqual(stat.S_IMODE(os.stat(Path(folder) / name).st_mode), 0o600)
        self.assertEqual(teamspack.have(lock, str(root)), folder)

    def test_a_folder_is_the_package_only_while_its_files_are(self):
        """The load reads a folder only when have() says that it is the package, and Python's own __pycache__,
        which an import writes there, changes nothing. A place over a folder that is not the package puts the package
        back. Bug: a hub loads a folder in which a file was changed, added or taken away."""
        root, _data, lock, folder = self.placed()
        (folder / "__pycache__").mkdir()
        (folder / "__pycache__" / "teams_demo.cpython-312.pyc").write_bytes(b"\0")
        self.assertEqual(teamspack.have(lock, str(root)), str(folder))
        self.assertIsNone(teamspack.have(dict(lock, sha256="0" * 64), str(root)))
        self.assertIsNone(teamspack.have("no lock", str(root)))
        for change in (lambda: (folder / "teams_demo.py").write_text("FEATURE = 'other'\n"),
                       lambda: (folder / "teams_more.py").write_text(""),
                       lambda: (folder / "notes.txt").write_text(""),
                       lambda: (folder / LICENCE).unlink(),
                       lambda: (folder / "teams_sub.py").mkdir()):
            change()
            self.assertIsNone(teamspack.have(lock, str(root)))
            self.assertEqual(teamspack.place(teamspack.pack(FILES), lock, str(root)), str(folder))
            self.assertEqual(teamspack.have(lock, str(root)), str(folder))
            self.assertEqual(os.listdir(root), [lock["sha256"]])

    def test_prune_removes_other_packages_and_leftovers_and_nothing_else(self):
        """Bug: a hub removes the package that it runs, or a folder beside the packages that is no package."""
        root = self.folder()
        keep, other = "a" * 64, "b" * 64
        for name in (keep, other, teamspack.PART + "x1", "notes"):
            (root / name).mkdir()
        (root / ("c" * 64)).write_text("")
        self.assertEqual(teamspack.prune(str(root), {keep}), [teamspack.PART + "x1", other])
        self.assertEqual(sorted(os.listdir(root)), sorted([keep, "notes", "c" * 64]))
        self.assertEqual(teamspack.prune(str(root / "not there"), {keep}), [])


class StandIn(http.server.BaseHTTPRequestHandler):
    """The channel's route of a package, as this module's test needs it: each path that it is asked, with the
    Authorization header that came with it, and the answers of `server.answers`."""

    def do_GET(self):
        self.server.seen.append((self.path, self.headers.get("Authorization")))
        status, body, where = self.server.answers.get(self.path, (404, b"", None))
        self.send_response(status)
        if where:
            self.send_header("Location", where)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class Fetch(unittest.TestCase):
    def test_one_get_sends_the_token_only_as_its_bearer_and_takes_no_more_than_the_lock(self):
        """The licence's token is a login of the fleet (RULES.md, "Logins"). Bug: it reaches a proxy that the
        environment names or the address of a redirect, it is quoted in the words of a failure, or a hub takes an
        answer larger than the package that its lock names."""
        data = teamspack.pack(FILES)
        lock = teamspack.lock_of(data)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), StandIn)
        server.seen = []
        server.answers = {"/p": (200, data, None), "/big": (200, data + b" ", None), "/moved": (302, b"", "/p")}
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base, dead = f"http://127.0.0.1:{server.server_address[1]}", f"http://127.0.0.1:{free_port()}"
        environment = {name: value for name, value in os.environ.items() if name.lower() != "no_proxy"}
        environment.update(http_proxy=dead, HTTP_PROXY=dead)
        with patch.dict(os.environ, environment, clear=True):
            self.assertEqual(teamspack.fetch(base + "/p", lock, "the-token"), (200, data))
            self.assertEqual(teamspack.fetch(base + "/big", lock, "the-token"),
                             (200, f"an answer of more than the lock's {lock['size']} bytes"))
            self.assertEqual(teamspack.fetch(base + "/moved", lock, "the-token"), (302, "the channel answered 302"))
            self.assertEqual(teamspack.fetch(base + "/gone", lock, "the-token"), (404, "the channel answered 404"))
        self.assertEqual(server.seen, [(path, "Bearer the-token") for path in ("/p", "/big", "/moved", "/gone")])
        status, why = teamspack.fetch(dead + "/p", lock, "the-token", wait=5)
        self.assertEqual(status, 0)
        self.assertTrue(why.startswith("the channel did not answer: "), why)
        self.assertEqual(teamspack.fetch(base + "/p", lock, "a\nsecret"),
                         (0, "no request could be made of that address and token"))
        self.assertEqual(teamspack.fetch(base + "/p", "no lock", "the-token"), (0, "no lock"))
        self.assertEqual(len(server.seen), 4)



# ---- the seam of Core (hub.py, "Teams parts: the one seam of Core")

DEMO = ('FEATURE = "demo"\nHEARD = []\n\n\ndef start(H, *args):\n    return H, args\n\n\n'
        'def listed(H):\n    HEARD.append(H)\n    return H.CFG.get("demo_listed", True)\n\n\n'
        'def secret(H):\n    return "a function that Core does not declare"\n')       # a part, as a package holds it
ROWS = ('FEATURE = "rows"\nSCHEMA = ("CREATE TABLE IF NOT EXISTS teams_rows(id INTEGER PRIMARY KEY)",)\n\n\n'
        'def start(H):\n    return 1\n')                                                 # a part that makes its table
LIVE, ENDED = {}, {"ended": 1797811200}         # the entitlement rows of a live licence and of one that the word ended


class Seam(Folders):
    """The seam with stand-in parts and records of the test's own. Each test leaves the seam as it found it: no part,
    no load, no module teams_*, no finder, no folder of packages and no TEAMS_DIR_VAR."""

    def setUp(self):
        self.path = str(self.folder() / "test.db")
        had, db = hub.DB, quick(sqlite3.connect(self.path, check_same_thread=False))
        db.row_factory = sqlite3.Row
        hub.DB = db
        self.addCleanup(setattr, hub, "DB", had)
        self.addCleanup(db.close)
        db.executescript(hub.SCHEMA)
        hub.migrate()
        for patcher in (patch.dict(hub.CFG, {"teams_dir": None, "teams_source": False, "db_path": self.path}),
                        patch.dict(hub.TEAMS_CALLS, {"demo": ("start",), "other": ("start",), "rows": ("start",)}),
                        patch.dict(hub.TEAMS_CODE), patch.dict(hub.TEAMS_PARTS), patch.dict(hub.TEAMS_LOAD),
                        patch.object(hub, "TEAMS_LOCK", None), patch.object(sys, "meta_path", list(sys.meta_path)),
                        patch.dict(os.environ)):
            patcher.start()
            self.addCleanup(patcher.stop)
        had = set(sys.modules)
        self.addCleanup(lambda: [sys.modules.pop(one) for one in set(sys.modules) - had if one.startswith("teams_")])

    def unload(self):
        """What a load of this process did, taken back, for a second load in the same test: its record, its parts,
        the modules that it made and its finder."""
        finder = hub.TEAMS_LOAD.get("finder")
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
        for name in getattr(finder, "texts", ()):
            sys.modules.pop(name, None)
        hub.TEAMS_LOAD.clear()
        hub.TEAMS_CODE.clear()
        hub.TEAMS_PARTS.clear()

    def package(self, files):
        """`files` as a package in the test's folder of packages, which teams_dir() names, and its lock as the lock of
        the code that runs (TEAMS_LOCK): what a hub with Teams holds after the release step got its package."""
        root, data = self.folder() / "teams", teamspack.pack(files)
        hub.CFG["teams_dir"], hub.TEAMS_LOCK = str(root), teamspack.lock_of(data)
        return Path(teamspack.place(data, hub.TEAMS_LOCK, str(root)))

    def licence(self, row):
        """The entitlement row as store_entitlement and take_ended_word leave it: `row` changes a live licence of
        Founderizer for Teams (LIVE), and None is no row."""
        hub.q("DELETE FROM entitlement")
        if row is not None:
            row = dict({"plan": "teams", "verified": 1, "ended": None}, **row)
            hub.q("INSERT INTO entitlement(id, fleet, token, plan, until, verified, stored, ended) "
                  "VALUES(1, 'fleet', 'a-token', ?, 2000000000, ?, 1, ?)", (row["plan"], row["verified"], row["ended"]))

    def refused(self, feature):
        with self.assertRaises(hub.Refusal) as caught:
            hub.teams_part(feature, need=True)
        return caught.exception.status, refusal_words.refusal_body(caught.exception)["code"]

    def test_a_fleet_with_no_licence_or_an_old_token_reads_no_package_and_imports_no_teams_file(self):
        """Rule 1 of the launch: a fleet with no licence behaves as today in each path. No package exists before P4
        and P5, so nothing loads on any fleet in this piece; here a whole package waits, and the one thing between it
        and its load is the licence, which each case lacks: no row, the `monthly` token of the old shop, a `teams`
        token that our key did not sign, a licence that the signed word ended. A hub with no teams_dir() (each hub of
        a test) and the lock of each release from P1 on (it names no Python file) read nothing either, also with a
        live licence. The bugs: a free fleet or a test's hub reads or runs Teams code, or build_schema gives it a line
        that it did not give before the seam."""
        whole = self.package({"teams_demo.py": DEMO, "teams_boom.py": "raise RuntimeError('imported')\n"})
        root, lock = hub.CFG["teams_dir"], hub.TEAMS_LOCK
        draft = teamspack.pack({LICENCE: FILES[LICENCE]})
        teamspack.place(draft, teamspack.lock_of(draft), root)
        with patch.object(teamspack, "folder_pack", wraps=teamspack.folder_pack) as reads:
            for case, row, folder, code in (
                    ("no licence", None, root, lock), ("the old shop's token", {"plan": "monthly"}, root, lock),
                    ("a teams token that our key did not sign", {"verified": 0}, root, lock),
                    ("a licence that the signed word ended", ENDED, root, lock),
                    ("a hub with no folder of packages", LIVE, None, lock),
                    ("the lock of each release from P1 on", LIVE, root, teamspack.lock_of(draft)),
                    ("a tree with no lock", LIVE, root, None)):
                self.licence(row)
                hub.CFG["teams_dir"], hub.TEAMS_LOCK = folder, code
                self.assertEqual(hub.build_schema(), [], case)
                self.assertEqual((hub.teams_part("demo"), hub.teams_features(), hub.TEAMS_CODE, hub.TEAMS_PARTS),
                                 (None, [], {}, {}), case)
                self.assertEqual(([one for one in sys.modules if one.startswith("teams_")], reads.call_count), ([], 0),
                                 case)
                self.assertNotIn("finder", hub.TEAMS_LOAD, case)
                hub.TEAMS_LOAD.clear()
            hub.CFG["teams_dir"], hub.TEAMS_LOCK, hub.CFG["teams_source"] = root, lock, True
            said = hub.build_schema()       # the same package with a live licence: the licence was the one gate
        self.assertEqual((said, sorted(hub.TEAMS_CODE), reads.call_count),
                         (["The Teams part teams_boom.py did not load: RuntimeError: imported"], ["demo"], 1))
        self.assertEqual(sys.modules["teams_demo"].__file__, str(whole / "teams_demo.py"))

    def test_teams_part_is_none_while_teams_is_off_or_its_code_is_not_here_and_need_gives_design_1_s_refusal(self):
        """With None, Core does what it did before Teams; where only a part can do the work, need=True gives design 1's
        refusal from its one place (need_teams). The bugs: a fleet that canceled keeps a paid part; a part refuses
        with its own words; a fleet that pays reads "which this fleet does not have"."""
        off, missing = (409, "teams_off"), (409, "teams_part_missing")
        self.assertEqual((hub.teams_part("demo"), self.refused("demo")), (None, off))
        self.package({"teams_demo.py": DEMO})
        self.licence(LIVE)
        self.assertEqual(hub.build_schema(), [])
        self.assertIsInstance(hub.teams_part("demo", need=True), hub.TeamsPart)
        self.assertEqual((hub.teams_part("other"), self.refused("other")), (None, missing))
        self.licence(ENDED)                 # the signed word, after the load: the part stays in the process
        self.assertEqual((hub.teams_part("demo"), self.refused("demo"), self.refused("other")), (None, off, off))

    def test_a_call_gives_the_part_the_hub_s_names_first_and_only_for_a_name_that_core_declares(self):
        """part.<name>(...) calls <name>(H, ...); H reads the hub's names as they are at the call and writes none; Core
        reaches only the names of TEAMS_CALLS. The bugs: Core calls a function that it does not declare, and the
        fault shows only on a customer's hub; a part puts a function of its own in the place of the hub's."""
        self.package({"teams_demo.py": DEMO})
        self.licence(LIVE)
        self.assertEqual(hub.build_schema(), [])
        part = hub.teams_part("demo")
        names, args = part.start(1, 2)
        self.assertEqual((names, args), (hub.TEAMS_H, (1, 2)))
        self.assertIs(names.q, hub.q)
        with patch.object(hub, "kv_get", lambda key: "patched"):
            self.assertEqual(names.kv_get("x"), "patched")
        for wrong in (lambda: part.secret, lambda: part.place, lambda: names.no_such_name,
                      lambda: setattr(part, "x", 1), lambda: setattr(names, "q", print), lambda: delattr(names, "q")):
            self.assertRaises(AttributeError, wrong)
        self.assertIs(names.q, hub.q)

    def test_a_fault_of_one_teams_file_is_a_line_of_build_schema_and_the_other_parts_load(self):
        """build_schema raises nothing, so the hub starts on Core whatever a Teams file does: an import that raises or
        ends the process, a part of a feature that Core does not call, one that lacks a function of its row, a second
        file of one part, a table that the records refuse. Each is a line (the warning `schema`, and a refused step of a
        release's check), and the other files load, also one that a part imports. The bug: one Teams fault stops a
        hub, or leaves a part listed whose table is not there."""
        self.package({"teams_demo.py": "import teams_util\n" + DEMO, "teams_util.py": "NAMES = ('util',)\n",
                      "teams_boom.py": "raise RuntimeError('a fault at the import')\n",
                      "teams_exit.py": "import sys\nsys.exit(3)\n", "teams_stray.py": 'FEATURE = "stray"\n',
                      "teams_thin.py": 'FEATURE = "other"\n', "teams_twin.py": DEMO,
                      "teams_rows.py": ROWS.replace("TABLE IF NOT EXISTS teams_rows(id INTEGER PRIMARY KEY)",
                                                    "INDEX IF NOT EXISTS rows_x ON no_such_table(x)"),
                      "teams_zz.py": DEMO.replace('"demo"', '"other"')})
        sys.modules["teams_zz"] = type(sys)("teams_zz")     # a module of that name that is not the package's
        self.licence(LIVE)
        said = hub.build_schema()
        self.assertEqual(said[:6], [
            "The Teams part teams_boom.py did not load: RuntimeError: a fault at the import",
            "The Teams part teams_exit.py did not load: SystemExit: 3",
            "The Teams part teams_stray.py did not load: its FEATURE 'stray' is no part that this code calls "
            "(TEAMS_CALLS)",
            "The Teams part teams_thin.py did not load: no function start, which Core calls of the part other "
            "(TEAMS_CALLS)",
            "The Teams part teams_twin.py did not load: the part demo again, which teams_demo is already",
            "The Teams part teams_zz.py did not load: this process holds another module of that name"])
        self.assertEqual(len(said), 7, said)
        self.assertTrue(said[6].startswith("The Teams part teams_rows.py did not load: CREATE INDEX IF NOT EXISTS "
                                           "rows_x ON no_such_table(x): no such table"), said[6])
        self.assertEqual((sorted(hub.TEAMS_CODE), sorted(hub.TEAMS_PARTS)), (["demo"], ["demo"]))
        self.assertIs(sys.modules["teams_demo"].teams_util, sys.modules["teams_util"])
        self.assertEqual(hub.teams_features(), ["demo"])

    def test_a_part_s_own_condition_is_the_condition_of_its_entry(self):
        """J2: a part's name is listed while Teams is on, its code is loaded and its own condition holds, which the
        part gives as listed(H) and the seam writes into TEAMS_PARTS. The bug: role_sets shows on a fleet whose
        contacts.v2 is off."""
        self.package({"teams_demo.py": DEMO})
        self.licence(LIVE)
        self.assertEqual(hub.build_schema(), [])
        hub.CFG["demo_listed"] = False
        self.assertEqual(hub.teams_features(), [])
        hub.CFG["demo_listed"] = True
        self.assertEqual(hub.teams_features(), ["demo"])
        self.assertIs(sys.modules["teams_demo"].HEARD[-1], hub.TEAMS_H)

    def test_a_release_s_schema_check_runs_a_part_s_schema_on_a_copy_with_a_live_licence_and_not_on_one_with_none(self):
        """The check of a release runs the new code on a copy of the fleet's records, in a child of the hub, and finds
        the hub's packages by TEAMS_DIR_VAR. The bugs: a release meets a customer's rows for the first time at the
        restart, because its check never ran the part; the check of a fleet with no licence says another thing than
        before the seam."""
        self.package({"teams_rows.py": ROWS})
        os.environ[hub.TEAMS_DIR_VAR], hub.CFG["teams_dir"] = hub.CFG["teams_dir"], None

        def checked(row):
            self.licence(row)
            copy, out, db = str(self.folder() / "copy.db"), io.StringIO(), hub.DB
            with contextlib.closing(sqlite3.connect(copy)) as into:
                db.backup(into)
            try:
                with contextlib.redirect_stdout(out):
                    code = hub.check_schema(copy)
            finally:
                hub.DB.close()
                hub.DB = db
            with contextlib.closing(sqlite3.connect(copy)) as read:
                made = read.execute("SELECT count(*) FROM sqlite_master WHERE name='teams_rows'").fetchone()[0]
            return code, out.getvalue(), made
        self.assertEqual(checked(None), (0, "schema check: 0 steps refused.\n", 0))
        self.assertEqual(checked(LIVE), (0, "schema check: 0 steps refused.\n", 1))

    def test_the_load_runs_the_checked_text_and_never_a_compiled_file_of_the_package_s_folder(self):
        """teamspack.have and folder_pack leave __pycache__ out, so no hash covers a compiled file there, and Python's
        own import runs one whose source's time and size match in place of the source. The bugs: a file that no
        release named runs as a part, while the check of the package says that it is whole; a changed file of the
        package runs. The load compiles the text whose hash it checked, and writes no file into the package's
        folder."""
        source = 'FEATURE = "demo"\nFROM = "the package"\n\n\ndef start(H):\n    return FROM\n'
        folder = self.package({"teams_demo.py": source})
        other, real = self.folder() / "teams_demo.py", folder / "teams_demo.py"
        self.licence(LIVE)
        real.write_text(source.replace("the package", "a change   "))
        self.assertEqual((hub.build_schema(), hub.TEAMS_CODE), ([], {}))     # no package that the lock names
        self.unload()
        real.write_text(source)
        other.write_text(source.replace("the package", "a pyc file "))
        os.utime(other, ns=(real.stat().st_atime_ns, real.stat().st_mtime_ns))
        self.assertEqual(other.stat().st_size, real.stat().st_size)
        py_compile.compile(str(other), cfile=importlib.util.cache_from_source(str(real)), doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
        self.assertEqual(teamspack.have(hub.TEAMS_LOCK, hub.CFG["teams_dir"]), str(folder))
        there = sorted(folder.rglob("*"))
        self.assertEqual(hub.build_schema(), [])
        self.assertEqual((hub.teams_part("demo").start(), sorted(folder.rglob("*"))), ("the package", there))

    def test_only_an_installed_hub_or_one_given_a_folder_has_a_folder_of_packages(self):
        """main()'s teams_dir() (teams_folder): an installed hub's is `teams` beside its records; a hub of a test, of
        selftest.py or of a scratch run has none, so it loads nothing. A release's check gets the folder through
        TEAMS_DIR_VAR, and a hub with none takes another hub's out of it for its own children. The package that the
        seam takes is the one of the lock of the code's own folder. The bugs: a test's hub loads the package of the
        machine's own hub; a hub with Teams never reads the lock of its code, and so loads no part."""
        code = self.folder()
        self.assertIsNone(hub.teams_lock_here(str(code)))           # the source repository's tree has no lock
        data = teamspack.pack(FILES)
        (code / "teams.lock").write_text(teamspack.lock_text(teamspack.lock_of(data)))
        self.assertEqual(hub.teams_lock_here(str(code)), teamspack.lock_of(data))
        for text in ('{"files": 1}\n', "[" * 4000):    # deep JSON: json's RecursionError on Python 3.9 to 3.11
            (code / "teams.lock").write_text(text)
            self.assertIsNone(hub.teams_lock_here(str(code)))
        with patch.object(teamspack, "read_lock", side_effect=RecursionError("deep JSON")):     # on each Python
            self.assertIsNone(hub.teams_lock_here(str(code)))
        start = inspect.getsource(hub.main)                     # the folder is there before the load reads it
        self.assertLess(start.index("teams_folder(args.teams_dir)"), start.index("build_schema()"))
        given = str(self.folder() / "packages")
        os.environ[hub.TEAMS_DIR_VAR] = "/the/folder/of/another/hub"
        with patch.dict(hub.CFG, {"team_path": str(self.folder() / "team.json")}):
            self.assertEqual((hub.teams_folder(None), hub.teams_dir(), os.environ.get(hub.TEAMS_DIR_VAR)),
                             (None, None, None))
            self.assertEqual((hub.teams_folder(given), hub.teams_dir(), os.environ[hub.TEAMS_DIR_VAR]),
                             (given, given, given))
        with patch.dict(hub.CFG, {"team_path": hub.TEAM_DEFAULT, "db_path": hub.DB_DEFAULT}):
            self.assertTrue(hub.installed_hub())
            self.assertEqual(hub.teams_folder(None), os.path.expanduser(os.path.join("~", ".fleet", "teams")))

    def test_a_part_s_own_folder_stands_beside_the_records_with_mode_700(self):
        """teams_data_dir is where design 4's key file stands: beside the records, so a test's hub writes in its own
        folder, mode 700 also when the folder was there with another mode, and never outside teams-data. The bug:
        other users of the server read a part's key file."""
        made = Path(hub.teams_data_dir("person_links"))
        self.assertEqual(made, Path(self.path).parent / "teams-data" / "person_links")
        for one in (made, made.parent):
            one.chmod(0o755)
        self.assertEqual(hub.teams_data_dir("person_links"), str(made))
        self.assertEqual({stat.S_IMODE(one.stat().st_mode) for one in (made, made.parent)}, {0o700})
        for wrong in ("../x", "a/b", "", "Person", None):
            self.assertRaises(ValueError, hub.teams_data_dir, wrong)
        hub.CFG["db_path"] = None
        self.assertRaises(RuntimeError, hub.teams_data_dir, "person_links")

    def test_a_call_through_the_seam_runs_inside_the_caller_s_transaction(self):
        """Design 3 and design 4 ask for a part inside the caller's transaction() (the write of a role, the removal of
        a person). The bugs: the seam's read of the licence commits there, so each such call raises (no_commit_inside)
        or lands the caller's half-written rows; a part's write is not the caller's, and the caller's rollback leaves
        it."""
        hub.TEAMS_CALLS["demo"] = ("start", "write")
        self.package({"teams_demo.py": DEMO + '\n\ndef write(H, value):\n    H.in_transaction("write")\n'
                                              '    if H.teams_licence():\n'
                                              '        H.DB.execute("INSERT OR REPLACE INTO kv(k, v) VALUES(?, ?)", '
                                              '("teams-demo", value))\n'})
        self.licence(LIVE)
        self.assertEqual(hub.build_schema(), [])
        with hub.transaction():
            hub.teams_part("demo").write("kept")
            self.assertEqual((hub.teams_features(), self.refused("other")), (["demo"], (409, "teams_part_missing")))
        with self.assertRaises(KeyError), hub.transaction():
            hub.teams_part("demo", need=True).write("undone")
            raise KeyError("the caller's own fault, after the part's write")
        self.assertEqual(hub.kv_get("teams-demo"), "kept")

    def test_a_fault_after_the_load_takes_out_its_part_or_each_part_and_never_stops_the_start(self):
        """A part's step that raises another exception than sqlite3.Error (two statements in one string are
        sqlite3.Warning before Python 3.12; a lone surrogate is UnicodeEncodeError on each), a migrate that ends the
        process, a module whose own __getattr__ raises, a read of the licence that fails, and a fault of the seam
        itself. The bugs: the hub's start ends, also at main()'s print of a line; a part stays listed whose steps did
        not run, and Core calls it on records that lack its table."""
        hub.TEAMS_CALLS["exit"] = hub.TEAMS_CALLS["two"] = ("start",)
        self.package({"teams_demo.py": DEMO,
                      "teams_two.py": ROWS.replace('"rows"', '"two"').replace(
                          'PRIMARY KEY)",', 'PRIMARY KEY); CREATE TABLE IF NOT EXISTS teams_more(id INTEGER)", '
                                            '"CREATE TABLE IF NOT EXISTS teams_odd(a) -- \\ud800",'),
                      "teams_exit.py": ROWS.replace('"rows"', '"exit"') + "\n\ndef migrate(H):\n"
                                                                          "    raise SystemExit(4)\n",
                      "teams_odd.py": "def __getattr__(name):\n    raise RuntimeError('no ' + name)\n"})
        self.licence(LIVE)
        said = hub.build_schema()
        self.assertEqual(said[:2], ["The Teams part teams_odd.py did not load: RuntimeError: no FEATURE",
                                    "The Teams part teams_exit.py did not load: its migrate raised SystemExit: 4"])
        self.assertEqual(len(said), 4, said)
        self.assertTrue(said[2].startswith("The Teams part teams_two.py did not load: CREATE TABLE IF NOT EXISTS "
                                           "teams_rows(id INTEGER PRIMARY KEY); CREATE TABLE"), said[2])
        self.assertTrue(said[3].startswith("The Teams part teams_two.py did not load: CREATE TABLE IF NOT EXISTS "
                                           "teams_odd(a) -- ?: UnicodeEncodeError: "), said[3])
        "\n".join(said).encode("utf-8")                    # what main() prints and logs
        self.assertEqual((sorted(hub.TEAMS_CODE), sorted(hub.TEAMS_PARTS)), (["demo"], ["demo"]))
        self.unload()
        with patch.object(hub, "teams_steps", side_effect=MemoryError("the seam's own fault")), \
                patch.object(hub, "print_fault") as fault:
            self.assertEqual(hub.build_schema(), ["The Teams parts did not load: MemoryError: the seam's own fault"])
            self.assertEqual((hub.TEAMS_CODE, hub.TEAMS_PARTS, hub.teams_part("demo")), ({}, {}, None))
            with patch.object(hub, "teams_on", side_effect=RuntimeError("a fault of the read")):
                self.assertEqual(hub.teams_schema(), [])
            self.assertEqual(fault.call_count, 2)

    def test_a_rig_of_the_source_tree_loads_its_own_files_and_a_tree_with_a_lock_only_its_package(self):
        """--teams-source is for a rig of the source repository, whose tree has no lock: it loads the Teams files of
        the code's own folder. In a tree with a lock the flag is no other way: the package of the lock loads, as with
        no flag. The bugs: a rig never runs the Teams files that it tests; a published tree runs files that no lock
        names."""
        code = self.folder()
        (code / "teams_demo.py").write_text(DEMO + 'FROM = "the source tree"\n')
        self.licence(LIVE)
        with patch.object(hub, "__file__", str(code / "hub.py")):
            hub.CFG["teams_source"] = True
            self.assertEqual(hub.build_schema(), [])
            self.assertEqual(sys.modules["teams_demo"].FROM, "the source tree")
            self.unload()
            self.package({"teams_demo.py": DEMO + 'FROM = "the package"\n'})
            self.assertEqual(hub.build_schema(), [])
            self.assertEqual(sys.modules["teams_demo"].FROM, "the package")


if __name__ == "__main__":
    unittest.main()

"""The package of the Teams code and its lock (teamspack.py; Founderizer for Teams, design 2, section 3.3).

A hub with a live licence runs the files of one package beside its checkout: the package whose hash the lock of its
release names, and no other. What is held here: the same files give the same bytes; a lock is read field by field; a
package that no release could name is refused before any byte of it is written; a folder counts as the package only
while its files are that package; and the one GET of a package sends the token only as its bearer. No hub, and no
network but a stand-in of this module on the loopback address."""
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

import teamspack

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


if __name__ == "__main__":
    unittest.main()

"""hubpieces.py: the compiled file of hub.py, compiled in pieces, which Python reads in place of a compile of the whole
file at a release's checks and at the hub's restart.

What a hub depends on here: the pieces give the very code of a whole compile (a cut in the wrong place, a line that
moved or a call compiled in another form would run other code, or change hub.search_version() and so the search cache
of logins); what pieces cannot keep is left to Python's whole compile; Python reads the file, and compiles the source
again when it changed; and a file is never kept when its rest is cut, which would stop every start of the hub. One test
compiles the real hub.py whole, about 4 seconds and 400 MB on a Mac. No hub, server or network."""
import hashlib
import importlib.util
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import hubpieces
import releases
from leftovers import ROOT

MARK = "# " + "-" * 64


def hub_wait():
    """hub.PIECES_WAIT, read from hub.py's text: an import of hub costs seconds."""
    match = re.search(r"^PIECES_WAIT = (\d+)", Path(ROOT, "hub.py").read_text(encoding="utf-8"), re.M)
    return int(match.group(1))


def fingerprint(code):
    """What a code object runs and where its lines are: its instructions, names, flags, counts, first line, line
    and exception tables, and its constants, a nested code object by its own fingerprint, a set's members in order."""
    def const(value):
        if isinstance(value, types.CodeType):
            return fingerprint(value)
        if isinstance(value, (frozenset, set)):
            return b"{" + b",".join(sorted(const(v) for v in value)) + b"}"
        if isinstance(value, tuple):
            return b"(" + b",".join(const(v) for v in value) + b")"
        return repr((type(value).__name__, value)).encode()
    fields = (code.co_names, code.co_varnames, code.co_freevars, code.co_cellvars, code.co_flags, code.co_argcount,
              code.co_posonlyargcount, code.co_kwonlyargcount, code.co_nlocals, code.co_stacksize, code.co_name,
              getattr(code, "co_qualname", ""), code.co_firstlineno, code.co_filename)
    return b"\0".join([code.co_code, repr(fields).encode(), bytes(code.co_linetable),
                       bytes(getattr(code, "co_exceptiontable", b""))] + [const(c) for c in code.co_consts])


def below(code, found=None):
    """Each code object below a module's code (functions, class bodies, comprehensions, and those inside them), by its
    qualified name and first line, as a digest of its fingerprint. The module code of each piece is left out: the
    pieces' module code is not the whole source's."""
    found = {} if found is None else found
    for value in code.co_consts:
        if isinstance(value, types.CodeType):
            if value.co_name != "<module>":
                key = (getattr(value, "co_qualname", value.co_name), value.co_firstlineno)
                found[key] = hashlib.sha256(fingerprint(value)).hexdigest()
            below(value, found)
    return found


class Pieces(unittest.TestCase):
    def test_the_pieces_of_hub_py_have_the_code_of_a_whole_compile(self):
        """Every function, class body and comprehension of hub.py, compiled in pieces, is the one of a compile of the
        whole file: the same instructions (a call of an imported module's function in the same form, as
        search_version() reads it), names, constants, first line, line table and exception table. (Whether each change
        of hub.py still compiles in many small pieces, test_publish.HubInPieces checks: ship runs this module only for
        a change of hubpieces.py.)"""
        path = os.path.join(ROOT, "hub.py")
        text = importlib.util.decode_source(Path(path).read_bytes())
        module, spans = hubpieces.compiled(text, path)
        self.assertGreater(len(spans), 50, "hub.py is compiled in few pieces: does it still have its marker lines?")
        pieces = below(module)
        del module                              # the pieces' code before the whole compile: the larger one alone
        whole = below(compile(text, path, "exec", dont_inherit=True))
        self.assertEqual(sorted(set(whole) ^ set(pieces)), [])
        self.assertEqual([key for key in whole if whole[key] != pieces[key]], [])

    def test_a_marker_is_no_cut_inside_a_statement_and_the_pieces_share_what_one_compile_shares(self):
        """A marker inside a string, inside brackets, between a decorator and its function, inside a function body,
        before else, before except and before a line of a backslash is no cut; a piece that begins with a string, in
        brackets too, does not take the module's docstring; a function at the start calls a module that the source
        imports only at its end, and a method calls super() in a source whose top level names super, each in the form
        of a whole compile. The code is a whole compile's, and a run of it gives what a run of the source gives."""
        source = "\n".join([
            '"""The docstring of the module."""', "import os", "", "",
            "def early():", "    return late.join(os.sep, 'a')", "", "",
            "class Base:", "    def m(self):", "        return 1", "", "",
            "class Child(Base):", "    def m(self):", "        return super().m() + 1",
            MARK, 'TEXT = """', MARK, '"""', "CALLS = (", MARK, "    1,", ")", "", "",
            "def deco(f):", "    return f", "", "", "@deco", MARK, "def decorated():", "    return TEXT", "", "",
            "def body():", "    x = 1", MARK, "    return x", "", "",
            "if CALLS:", "    branch = 1", MARK, "else:", "    branch = 2",
            "try:", "    tried = 1", MARK, "except ValueError:", "    tried = 2",
            "if CALLS:", "    joined = 1", MARK, "\\", "    joined = 2",
            MARK, '("a string in brackets that is no docstring")', "AFTER = __doc__",
            MARK, "import posixpath as late", "KEEP = super",
            "RESULT = (early(), Child().m(), decorated(), body(), branch, tried, joined, AFTER)",
            "if __name__ == '__main__':", "    MAIN = True", ""])
        module, spans = hubpieces.compiled(source, "m.py")
        self.assertGreaterEqual(len(spans), 3, "the source was not cut")
        whole = compile(source, "m.py", "exec", dont_inherit=True)
        self.assertEqual(below(module), below(whole))
        ran, expected = {"__name__": "__main__"}, {"__name__": "__main__"}
        exec(module, ran)
        exec(whole, expected)
        self.assertEqual(ran["RESULT"], expected["RESULT"])
        self.assertEqual(ran["__doc__"], "The docstring of the module.")
        self.assertEqual(sorted(ran), sorted(expected))
        self.assertTrue(ran["MAIN"])
        self.assertTrue(hubpieces.in_pieces(module))
        self.assertFalse(hubpieces.in_pieces(whole))
        # A marker above the first statement is no cut: that statement can be the docstring, and __future__ imports
        # may follow it.
        future = f"\"\"\"The docstring.\"\"\"\n{MARK}\nfrom __future__ import annotations\n{MARK}\n"
        header = f"#!/usr/bin/env python3\n# a header\n{MARK}\n"
        for source in (header + f"\"\"\"The docstring.\"\"\"\nX = 1\n{MARK}\nY = 2\n",
                       # and the first piece's __future__ imports reach each later piece: names that no one defines
                       future + "def f(x: Undefined) -> Missing:\n    return x\n"):
            with self.subTest(source):
                module, spans = hubpieces.compiled(source, "m.py")
                whole = compile(source, "m.py", "exec", dont_inherit=True)
                self.assertEqual((len(spans), below(module)), (2, below(whole)))
                ran, expected = {}, {}
                exec(module, ran)
                exec(whole, expected)
                self.assertEqual((ran["__doc__"], sorted(ran)), (expected["__doc__"], sorted(expected)))

    def test_what_pieces_cannot_keep_is_left_to_the_whole_compile(self):
        """Module annotations after the first piece (one compile shares them), and a top-level binding of exec, a
        function's `global exec` or a top-level import of * (the module code calls exec between pieces): the writer
        refuses each, the command writes no file and says why, and Python compiles the whole source. A source that
        does not compile whole does not compile in pieces either: a __future__ import after the first piece, a
        source whose end does not compile, and one that ends in a backslash give their error, and no file."""
        cases = [(f"X = 1\n{MARK}\nY: int = 2\n", "annotations"), (f"X = 1\n{MARK}\nexec = print\n", "exec"),
                 (f"X = 1\n{MARK}\ndef f():\n    global exec\n    exec = print\n", "exec"),
                 (f"X = 1\n{MARK}\nfrom os import *\n", "import of *")]
        if sys.version_info < (3, 14):      # they set up __annotations__ at the module's start for these too
            cases.append((f"d = {{}}\n{MARK}\nd['k']: int = 2\n", "annotations"))
        for source, why in cases:
            with self.subTest(source):
                with self.assertRaises(hubpieces.Refused) as refused:
                    hubpieces.compiled(source, "m.py")
                self.assertIn(why, str(refused.exception))
        for source in (f"X = 1\n{MARK}\nfrom __future__ import annotations\nY = 2\n",
                       f"X = 1\n{MARK}\nY = 2\n{MARK}\ndef broken(:\n", f"X = 1\n{MARK}\nY = 2 \\"):
            with self.subTest(source), self.assertRaises(SyntaxError):
                compile(source, "m.py", "exec", dont_inherit=True)
            with self.subTest(source), self.assertRaises(SyntaxError):
                hubpieces.compiled(source, "m.py")
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "m.py")
            Path(path).write_text(f"X = 1\n{MARK}\nexec = print\n")
            # a command that wrote the file would become its import check (os.execv): here that ends the test
            with patch.dict(os.environ, {"PYTHONDONTWRITEBYTECODE": ""}), patch.object(hubpieces, "lower_priority"), \
                    patch.object(hubpieces.os, "execv", side_effect=AssertionError("the file was written")), \
                    patch("builtins.print") as said:
                self.assertEqual(hubpieces.main([path]), 0)
            self.assertIn("not written, so Python compiles the whole file", said.call_args[0][0])
            self.assertFalse(os.path.exists(importlib.util.cache_from_source(path)))


class TheFile(unittest.TestCase):
    """A hub.py of the test's own in a folder of its own, read by Pythons of their own (child processes) with a
    PYTHONPYCACHEPREFIX of their own, as a release's checks and a hub's start read it."""

    def setUp(self):
        self.folder = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", self.folder], check=False))
        self.path = os.path.join(self.folder, "hub.py")
        self.prefix = os.path.join(self.folder, "compiled")
        self.cache = os.path.join(self.folder, "__pycache__", f"hub.{sys.implementation.cache_tag}.pyc")
        # A statement of the last piece sees the frame that runs it: the module code of the pieces' file, or
        # Python's import (or runpy, for -m) when Python compiled the source itself.
        self.source = "\n".join(['"""A hub."""', "import other", "VALUE = 1", MARK, "def value():",
                                 "    return VALUE", MARK, "import sys",
                                 "CALLER = sys._getframe().f_back.f_code.co_filename",
                                 "if __name__ == '__main__':", "    print(value(), CALLER == __file__)", ""])
        Path(self.path).write_text(self.source)
        Path(self.folder, "other.py").write_text("OTHER = 1\n")         # another module of the hub's folder
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ("PYTHONPYCACHEPREFIX", "PYTHONDONTWRITEBYTECODE", "PYTHONOPTIMIZE", "PYTHONPATH",
                                 "PYTHONSAFEPATH")}
        self.env["PYTHONPYCACHEPREFIX"] = self.prefix
        self.written = os.path.join(self.prefix, self.folder.lstrip(os.sep), f"hub.{sys.implementation.cache_tag}.pyc")

    def child(self, *argv, status=0, **env):
        done = subprocess.run([sys.executable, *argv], cwd=self.folder, env=dict(self.env, **env),
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, status, done.stdout + done.stderr)
        return done.stdout.split()

    def test_python_reads_the_file_and_compiles_a_changed_source_again(self):
        """`python3 -m hubpieces` in the folder writes the file that `import hub` and `python3 -m hub` (a hub's
        start line) there read, also under a PYTHONPYCACHEPREFIX; Python runs it, and leaves it as it was; after a
        change of the source it runs the new source. A file at another path, or with a header that Python does not
        take, loses the gain in silence; a file that Python does not check against its source runs the code of
        before."""
        said = self.child("-B", "-m", "hubpieces", PYTHONPATH=ROOT)       # as the release and the restart run it
        self.assertEqual(said[-3:], ["written:", "3", "pieces"], said)
        # The check's import wrote no compiled file of the other modules: a full disk could leave one cut, which
        # stops every start of the hub before compiled_checked can remove it.
        self.assertEqual(sorted(os.listdir(os.path.dirname(self.written))),
                         [os.path.basename(self.written)])
        kept = Path(self.written).read_bytes()
        read = ["-c", "import hub; print(hub.value(), hub.CALLER == hub.__file__)"]
        self.assertEqual(self.child(*read), ["1", "True"])
        self.assertEqual(self.child("-m", "hub"), ["1", "True"])
        self.assertEqual(Path(self.written).read_bytes(), kept)
        Path(self.path).write_text(self.source.replace("VALUE = 1", "VALUE = 2"))
        self.assertEqual(self.child(*read), ["2", "False"])

    def test_a_file_whose_import_fails_or_does_not_end_is_removed(self):
        """After it writes the file, the command becomes a Python that imports the module, and removes a file whose
        import fails, or does not end within its own wait (which ends before the caller's, whose end of the command
        would leave the file): Python keeps a file for as long as its source is the same, so a module code that
        marshal reads and that does not run would stop every start of the hub, with nobody at a console."""
        Path(self.path).write_text(self.source + "raise RuntimeError('this module does not import')\n")
        said = self.child("-B", "-m", "hubpieces", status=1, PYTHONPATH=ROOT)
        self.assertIn("and removed: its import raised RuntimeError", " ".join(said))
        self.assertFalse(os.path.exists(self.written))
        # an import that waits and tries again, and catches each error: the alarm's own handler ends it
        Path(self.path).write_text(self.source + "import time\nwhile True:\n    try:\n        time.sleep(30)\n"
                                                 "    except BaseException:\n        pass\n")
        said = self.child("-B", "-c", "import sys, hubpieces; hubpieces.IMPORT_WAIT = 1; sys.exit(hubpieces.main([]))",
                          status=1, PYTHONPATH=ROOT)
        self.assertIn("and removed: its import took more than 1 seconds", " ".join(said))
        self.assertFalse(os.path.exists(self.written))
        self.assertLessEqual(hubpieces.IMPORT_WAIT, min(releases.PIECES_WAIT, hub_wait()) // 2)

    def test_a_current_file_is_kept_and_a_cut_or_stale_one_is_written_again(self):
        """A file that Python reads for the source is kept: the pieces' own, and Python's own of a whole compile. A
        file of a source before (the hub's folder holds one at each release) is written again: by the hash in the
        pieces' file, by the time and size in Python's own. And a file whose first 16 bytes are whole and whose
        rest is cut (a disk that was full) is written again too: it stops every import of the module, because
        Python does not compile again over it. And a file of this writer is written again when a release changed the
        writer since, also for the same hub.py."""
        self.assertEqual(hubpieces.write(self.path, self.cache), 3)
        self.assertEqual(hubpieces.write(self.path, self.cache), 0)
        data = Path(self.cache).read_bytes()
        Path(self.cache).write_bytes(data[:len(data) // 2])
        self.assertEqual(hubpieces.write(self.path, self.cache), 3)
        del self.env["PYTHONPYCACHEPREFIX"]             # Python reads the file of the folder's own __pycache__
        self.assertEqual(self.child("-c", "import hub; print(hub.value(), hub.CALLER == hub.__file__)"),
                         ["1", "True"])
        Path(self.path).write_text(self.source.replace("VALUE = 1", "VALUE = 3"))     # the same size
        self.assertEqual(hubpieces.write(self.path, self.cache), 3)
        self.assertEqual(self.child("-c", "import hub; print(hub.value())"), ["3"])
        os.remove(self.cache)
        py_compile.compile(self.path, cfile=self.cache, doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
        own = Path(self.cache).read_bytes()
        self.assertEqual(hubpieces.write(self.path, self.cache), 0)
        self.assertEqual(Path(self.cache).read_bytes(), own)
        Path(self.path).write_text(self.source.replace("VALUE = 1", "VALUE = 44"))
        self.assertEqual(hubpieces.write(self.path, self.cache), 3)
        self.assertEqual(self.child("-c", "import hub; print(hub.value())"), ["44"])
        writer = os.path.join(self.folder, "writer.py")     # the writer, as a release that changes it leaves it
        Path(writer).write_text("")
        with patch.object(hubpieces, "__file__", writer):
            os.utime(writer, (1, 1))
            self.assertEqual(hubpieces.write(self.path, self.cache), 0)
            later = os.stat(self.cache).st_mtime + 60
            os.utime(writer, (later, later))
            self.assertEqual(hubpieces.write(self.path, self.cache), 3)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""The compiled file of hub.py, compiled in pieces: what a hub's start and a release's checks read, in place of a
compile of the whole file.

Python keeps what it compiled of a module in __pycache__ and reads it back at each later import of that module, in
every process: `python3 -m hub` (the hub's own service, lifecycle.hub_start), `import hub`, the schema check of a
release and the hubs of selftest.py. When that file is not there, or is of another version of the source, the import
compiles the whole source as one piece. For hub.py, of about 71,000 lines, that compile is the largest use of memory of
a release on a small server: 270 to 290 MB on Linux (measured on 20 November 2026 on a server with 1 GB), one time in
the schema check of the release and one more time at the hub's restart.

This module writes that file itself, compiled in pieces. hub.py is cut at its own marker lines (`# ----`), each piece
is compiled alone with empty lines before it, so that each line keeps its number, and the module code of the file runs
the pieces one after the other in the module's own namespace. The peak is that of the largest piece: 82 to 85 MB
(Linux, Python 3.12.3 and 3.14.4, 84 pieces). Python reads the file as it reads its own: the hash of the source is in
its header (a checked file of PEP 552), so a source that changed is compiled again as before, and Python never writes
over a file that matches its source. hub.py is not split, and nothing that reads it changes: the functions and classes
that the pieces give have the same instructions, names, constants, lines and line tables as those of a whole compile
(measured on Python 3.10 to 3.15 for the 4,203 names of hub.py), so tracebacks below the module's own top level,
inspect and hub.search_version() are the same. A traceback that reaches the module's top level (an error at the import,
or one that leaves main()) shows one frame more: the line of the module code that runs the piece, at its first line.

Run it in the folder of hub.py, with the Python that runs the hub: `python3 -m hubpieces`. A release runs it in its
clone before its checks (releases.Update.checks), and the hub runs it in its own folder before its restart onto new code
(hub.restart_hub_soon). After it writes the file, the same process becomes a Python that imports the module from it
and writes no compiled file (main, CHECK), and a file whose import fails is removed. It never stops a release or a
restart: when it writes nothing, Python compiles the whole file as before. Standard library only, and the syntax of
Python 3.10 (publish.old_python)."""
import __future__
import dis
import hashlib
import importlib.util
import marshal
import os
import re
import symtable
import sys
import time
import types

MARKER = re.compile(r"# -{20,}")        # hub.py's own marker line of a part, at the start of a line
CLAUSE = re.compile(r"(?:else|elif|except|finally)\b")      # a line that goes on with the statement before it
FUTURE_IMPORT = re.compile(r"from\s+__future__\b")     # a line that only the start of a source may hold
ANNOTATIONS = {"__annotations__", "__annotate__", "__conditional_annotations__"}    # module annotations, 3.10 to 3.15
PLACE = "\0hubpieces {}"                # the constant of the module code that a piece's code takes the place of
CHECKED = 0b11                          # PEP 552: the file is hash-based, and Python checks the hash at each import
STALE = 3600                            # seconds after which a temporary file of this module is a killed run's
IMPORT_WAIT = 60    # seconds for the import that proves a file just written: with the writer's own second or two,
                    # inside the 120 seconds that each caller gives the whole command (releases.PIECES_WAIT,
                    # hub.PIECES_WAIT), so the check, and not the caller, ends an import that does not end, and the
                    # file goes. A server that swaps imports hub in a few seconds; a file that hangs every start would
                    # cost far more than the whole compile that a removal costs
FUTURE = 0
for _name in __future__.all_feature_names:
    FUTURE |= getattr(__future__, _name).compiler_flag


class Refused(Exception):
    """The source has something that pieces compiled alone cannot keep as one compile keeps it: the file is not
    written, and Python compiles the whole source."""


def code_line(lines, i):
    """The index of the first line from `i` on that holds code, not only a comment or nothing; or len(lines)."""
    while i < len(lines) and (not lines[i].strip() or lines[i].lstrip().startswith("#")):
        i += 1
    return i


def cuts(lines):
    """The marker lines where a piece may end: the next line of code begins at column 0, so every block above has
    ended; it is no clause (else, elif, except, finally) that goes on with the statement before the marker; it does
    not start with a backslash, after which Python takes the indentation of the line that follows; and it is no
    __future__ import, which only the start of a source may hold. Whether the piece above is whole statements (no
    open string, bracket, backslash or decorator) only its parse can say."""
    found = []
    for i, line in enumerate(lines):
        if MARKER.match(line):
            j = code_line(lines, i + 1)
            if j == len(lines) or (lines[j][:1] not in (" ", "\t", "\f", "\\") and not CLAUSE.match(lines[j])
                                   and not FUTURE_IMPORT.match(lines[j])):
                found.append(i)
    return found


def source_of(lines, start, end, before=None, after=None):
    """Lines start to end as a source of their own, at their own line numbers: empty lines before them, `before` on
    the line just before them, and `after` on the line just after them, where the whole source has a marker line.
    The last piece ends as the source ends, with no line end added, so that a source that does not compile whole
    does not compile here either."""
    head = "\n" * start if before is None else "\n" * (start - 1) + before + "\n"
    body = "\n".join(lines[start:end]) + ("\n" if end < len(lines) else "")
    return head + body + ("" if after is None else after + "\n")


def compiled(text, path):
    """The module code of the file for the source `text` of `path`, and the pieces that it runs, as (first line,
    line after the last) of each, counted from 0.

    1. Pieces: each ends at a marker of cuts(), or at the end of the source. A piece whose parse fails (a marker
       inside a string, inside brackets, after a backslash or between a decorator and its function) grows to the next
       marker. So each piece is whole top-level statements, and the same statements as a parse of the whole source
       gives. The first piece holds the first statement of the source, which can be its docstring: a marker above it
       is no cut.
    2. What one compile of the whole source shares between its parts, and pieces compiled alone do not. The
       compiler reads the symbol table of the module's top level in two places (CPython 3.10 to 3.15): a call of a
       name that the module imports (`json.dumps(...)`) has another form since 3.11 than a call of any other name, and
       `super()` in a method has another form since 3.12 when the module's top level names `super` (or a function
       declares it global). So each piece gets one line that never runs, `if 0: import <each name that the source
       imports at its top level>`, with `; super` where the source names it there: before the piece for each piece
       but the first (on the line where the source has the end of the piece before), and after the first piece, on
       its next marker line. Its names stay among the names of the piece's module code, and nothing of it runs but a
       NOP at its line. The line before a piece is also its first statement, so a string at the start of a piece is
       no docstring, as in the whole source.
       - The __future__ imports of the first piece: each piece is compiled with them. A marker before one is no cut,
         so a later piece holds one only after another statement, where the whole source does not compile either.
       - Module annotations: 3.14 makes one function for those of one compile (__annotate__), and 3.10 to 3.13 set
         up __annotations__ at the start of the module, also for the annotation of an attribute or a subscript.
         Annotations at the top level after the first piece are refused.
       - The name exec, which the module code calls between pieces: a source that binds it at its top level, that
         declares it global in a function, or that imports * at its top level (by the instruction, not by a value
         ("*",)) is refused. A binding through globals() or setattr is not seen.
       - A statement `global x` at the top level, or after x is bound: the whole source does not compile, and a
         piece can (the release's code passed whole compiles in its tests, which import hub, before it is published).
       - A name that a function declares global is in the module's symbol table: the whole source stores it at the
         top level with STORE_GLOBAL and a piece without that function with STORE_NAME. Both store into the module's
         namespace, which is the module code's globals and locals alike.
    3. The module code: one line `exec(<piece>)` for each piece, at the piece's first line, so a traceback of the
       start shows where the piece begins. Its frame is the module's own, so each piece runs with the module's
       namespace as its globals and its locals. Its only name is exec (in_pieces).
    Raises Refused, and SyntaxError for a source that does not compile."""
    lines = text.split("\n")            # as Python's tokenizer counts lines: no form feed or other line end counts
    spans, start, imported, names_super, first = [], 0, set(), False, code_line(lines, 0)
    for end in cuts(lines) + [len(lines)]:
        if end <= start or (not spans and end <= first and end < len(lines)):
            continue                    # nothing, or no statement yet: the first piece takes the first statement
        try:
            table = symtable.symtable(source_of(lines, start, end), path, "exec")
        except SyntaxError:
            if end == len(lines):
                raise
            continue                    # a marker inside a statement: the piece grows to the next marker
        for symbol in table.get_symbols():
            name = symbol.get_name()
            if symbol.is_imported():
                imported.add(name)
            names_super = names_super or name == "super"
            if name == "exec" and (symbol.is_assigned() or symbol.is_imported() or symbol.is_namespace()
                                   or symbol.is_declared_global()):
                raise Refused("the source binds the name exec, which the module code of the file calls")
        spans.append((start, end))
        start = end
    dead = "; ".join((["import " + ", ".join(sorted(imported))] if imported else []) +
                     (["super"] if names_super else [])) or "pass"
    dead = "if 0: " + dead
    codes, flags = [], 0
    for k, (start, end) in enumerate(spans):
        last = end == len(lines)
        if k == 0:
            code = compile(source_of(lines, start, end, after=None if last else dead), path, "exec",
                           dont_inherit=True)
            flags = code.co_flags & FUTURE
        else:
            code = compile(source_of(lines, start, end, before=dead), path, "exec", flags=flags, dont_inherit=True)
        ops = {(op.opname, op.argrepr) for op in dis.get_instructions(code)}
        if k and any(name == "SETUP_ANNOTATIONS" or (arg in ANNOTATIONS and "ATTR" not in name) for name, arg in ops):
            raise Refused(f"module annotations after the first piece (line {start + 1} on)")
        if ("IMPORT_STAR", "") in ops or ("CALL_INTRINSIC_1", "INTRINSIC_IMPORT_STAR") in ops:
            raise Refused(f"an import of * at the top level, which can bind exec (line {start + 1} on)")
        codes.append(code)
    rows = []
    for i, (start, _) in enumerate(spans):
        rows.extend([""] * (start - len(rows)))
        rows.append(f"exec({PLACE.format(i)!r})")
    module = compile("\n".join(rows) + "\n", path, "exec", dont_inherit=True)
    placed = {PLACE.format(i): code for i, code in enumerate(codes)}
    consts = tuple(placed.pop(c) if type(c) is str and c in placed else c for c in module.co_consts)
    if placed or any(type(c) is str and c.startswith(PLACE.format("")) for c in consts) or \
            module.co_names != ("exec",):
        raise Refused("this Python does not keep each piece's place as one constant of the module code")
    return module.replace(co_consts=consts), spans


def in_pieces(code):
    """True when `code`, the module code of a compiled file, is one that compiled() made: it calls only exec. After
    a change of the source Python writes its own file, which is checked and hash-based too when the file before it
    was, so the header alone does not tell."""
    return isinstance(code, types.CodeType) and code.co_names == ("exec",) and \
        all(isinstance(c, types.CodeType) for c in code.co_consts if not (c is None or isinstance(c, int)))


def current(cache, source, stat):
    """True when the compiled file `cache` is one that Python reads for these source bytes, and whole: a checked
    hash-based file with the source's hash, or Python's own file with the source's time and size. A file whose rest
    is cut (a full disk when it was written) passes Python's check of its first 16 bytes and stops each import of the
    module after it, so it is not current."""
    try:
        with open(cache, "rb") as f:
            data = f.read()
    except OSError:
        return False
    if len(data) < 16 or data[:4] != importlib.util.MAGIC_NUMBER:
        return False
    flags = int.from_bytes(data[4:8], "little")
    if flags == CHECKED:
        if data[8:16] != importlib.util.source_hash(source):
            return False
    elif flags != 0 or int.from_bytes(data[8:12], "little") != int(stat.st_mtime) & 0xFFFFFFFF or \
            int.from_bytes(data[12:16], "little") != stat.st_size & 0xFFFFFFFF:
        return False                    # another source, or an unchecked file, which Python runs for any source
    try:
        code = marshal.loads(data[16:])
    except Exception:                   # EOFError or ValueError for a cut file; what else marshal may say of one
        return False
    if not in_pieces(code):
        return isinstance(code, types.CodeType)
    try:                                # a writer that a release changed writes its own file again, also when
        return os.stat(__file__).st_mtime <= os.stat(cache).st_mtime    # hub.py is the same
    except OSError:
        return False


def write(path, cache=None):
    """Write the compiled file of the module source `path` in pieces, at `cache` (by default where Python reads it:
    importlib.util.cache_from_source, which follows PYTHONPYCACHEPREFIX). Returns how many pieces it wrote, or 0
    when the file there is current already, which it keeps. Raises Refused, SyntaxError and OSError."""
    path = os.path.abspath(path)
    cache = cache or importlib.util.cache_from_source(path)
    with open(path, "rb") as f:
        stat = os.fstat(f.fileno())     # the time and size of the bytes read, not of a file that replaced them
        source = f.read()
    if current(cache, source, stat):
        return 0
    module, spans = compiled(importlib.util.decode_source(source), path)
    data = importlib.util.MAGIC_NUMBER + CHECKED.to_bytes(4, "little") + importlib.util.source_hash(source) + \
        marshal.dumps(module)
    del module
    if not isinstance(marshal.loads(data[16:]), types.CodeType):
        raise Refused("the module code does not read back")
    folder = os.path.dirname(cache)
    os.makedirs(folder, exist_ok=True)
    for name in os.listdir(folder):     # what a run that the system ended left: never a file that Python reads
        if name.startswith(os.path.basename(cache) + ".") and name.endswith(".tmp"):
            try:
                if os.stat(os.path.join(folder, name)).st_mtime < time.time() - STALE:
                    os.remove(os.path.join(folder, name))
            except OSError:
                pass
    temporary = f"{cache}.{os.getpid()}.tmp"
    try:
        os.remove(temporary)            # a run that the system ended, whose number this process has now
    except OSError:
        pass
    try:
        # As Python writes its own: the source's mode with the owner's write, never a mode to run.
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, (stat.st_mode | 0o200) & 0o666)
        with open(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())        # the whole file on the disk before it takes the name that Python reads
        os.replace(temporary, cache)
    except BaseException:
        try:
            os.remove(temporary)
        except OSError:
            pass
        raise
    return len(spans)


# The import check, as the program of a Python that the writer's own process becomes (os.execv): the writer's memory
# is given back before the import takes its own, and a caller's end of the command ends the check too. Its arguments:
# the folder, the module's name, the file, the file's SHA-256, the number of pieces, the seconds of its wait.
CHECK = """import hashlib, importlib.util, os, signal, sys
folder, name, cache, digest, count, wait = sys.argv[1:7]
def read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except (OSError, TypeError):
        return None
def the_file():
    data = read(cache)
    return data is not None and hashlib.sha256(data).hexdigest() == digest
def remove(why):
    done = "it changed since, so it stays"
    if the_file():
        try:
            os.remove(cache)
            done = "removed"
        except OSError as e:
            done = "it could not be removed (" + type(e).__name__ + ")"
    print(cache + " written in " + count + " pieces, and " + done + ": its import " + why, flush=True)
def late(*_):
    try:
        remove("took more than " + wait + " seconds")
    finally:                                    # also when the print fails: a caller that is gone
        os._exit(1)
if hasattr(signal, "SIGALRM"):
    signal.signal(signal.SIGALRM, late)
    signal.alarm(int(wait))
sys.path.insert(0, folder)
try:
    __import__(name)
except (MemoryError, KeyboardInterrupt) as e:     # the system short of memory, or a signal: nothing against the file
    print(cache + " written: " + count + " pieces; its import ended with " + type(e).__name__)
    sys.exit(0)
except BaseException as e:
    remove("raised " + type(e).__name__)
    sys.exit(1)
if hasattr(signal, "SIGALRM"):
    signal.alarm(0)
spec = getattr(sys.modules.get(name), "__spec__", None)
data, source = read(cache), read(getattr(spec, "origin", None))
if getattr(spec, "cached", None) != cache or not the_file() or source is None or \\
        importlib.util.source_hash(source) != data[8:16]:
    print(cache + " written in " + count + " pieces, and its import did not read it")
    sys.exit(1)
print(cache + " written: " + count + " pieces")
"""


def prove(path, cache, count):
    """Become the check of the file just written: a Python (`-B`: it writes no compiled file of its own, of the hub's
    other modules either, which a full disk could leave cut where no step reads them back) that imports the module
    from its folder. The file goes when the import raises or takes more than IMPORT_WAIT seconds (the alarm's handler
    removes it and ends the process itself: an import that catches the error that it would raise goes on), and the
    check says so when the import did not read the file: it took another path (another optimization level), or the
    source changed after the write. A signal, a MemoryError, or a caller that ends the command, leaves the file, as
    does a writer ended between its rename and this step: the system short of memory says nothing against it, and the
    hub's start reads it. C code that never returns does not see the alarm either; the caller's wait ends it. Returns
    only when the check cannot start (a name that no import takes, or an exec that fails)."""
    name = os.path.splitext(os.path.basename(path))[0]
    if name.isidentifier():
        try:
            with open(cache, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            sys.stdout.flush()
            argv = [sys.executable, "-B", "-c", CHECK, os.path.dirname(path), name, cache, digest, str(count),
                    str(IMPORT_WAIT)]
            os.execv(sys.executable, argv)
        except OSError as e:
            print(f"{cache} written: {count} pieces; its import check did not start ({e})")
            return 0
    print(f"{cache} written: {count} pieces")
    return 0


def lower_priority():
    """On Linux, this process is the system's first choice when memory runs out: a release's check or a restart
    that ends here is one that compiles the whole file as before, where an end of the hub or a user's service is not."""
    try:
        with open("/proc/self/oom_score_adj", "w") as f:
            f.write("1000")
    except OSError:
        pass


def main(argv):
    """`python3 -B -m hubpieces [path]`: the compiled file of the path, by default hub.py in the folder where it runs.
    The callers give -B, so that Python writes no compiled file of this module either (a full disk could leave it cut,
    and then no later run would start); this module decides by the environment's PYTHONDONTWRITEBYTECODE, not by -B.
    It says what it did in one line. 0 when it wrote the file and an import ran it; kept a current one; was refused;
    found PYTHONDONTWRITEBYTECODE set; or wrote the file and its check could not start, or ended with a MemoryError
    or a KeyboardInterrupt (the file stays). 1 for an error, for a file whose import failed or did not end (removed,
    see prove), and for a file that the import did not read (it stays; Python compiles the whole source)."""
    path = os.path.abspath(argv[0] if argv else os.path.join(os.getcwd(), "hub.py"))
    if os.environ.get("PYTHONDONTWRITEBYTECODE"):
        print(f"{path}: not written, because this Python writes no compiled files (PYTHONDONTWRITEBYTECODE)")
        return 0
    lower_priority()
    cache = importlib.util.cache_from_source(path)
    try:
        count = write(path, cache)
    except Refused as e:
        print(f"{path}: not written, so Python compiles the whole file: {e}")
        return 0
    except Exception as e:              # a file that does not compile, a folder that cannot be written, and so on
        print(f"{path}: not written: {type(e).__name__}: {e}")
        return 1
    if not count:
        print(f"{cache} is current")
        return 0
    return prove(path, cache, count)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

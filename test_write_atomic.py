"""Every write of the hub lands whole or not at all. In-process hub, a temporary database, a set clock; no AI calls.

`hub.q` commits. So a read or a probe reached from inside a `transaction()` commits the half-written rows around it,
and the transaction's promise is gone — the caller believes it wrote the task, the lesson or the closed case together
or not at all, and in fact it wrote the first half. Five separate instances of that were found in one day, each one
fixed by `read_rows`, and each one was found by reading. Reading does not scale to 69 transactions.

So `Structure` measures the property instead: it reads hub.py **and every module of this folder that hub.py imports**,
follows every call a transaction body makes, and names the ones that can reach anything that commits. It needs no
database and no fixture, it covers the whole of that code rather than the paths some test happens to drive, and it is
the thing that catches the sixth instance. `Guard` is the other half, for the write that no reading can place: a
helper that writes with a plain `DB.execute` refuses to run outside a transaction at all. The cases after them drive
the real tools, because a structural check says a commit is reachable and not what is lost when it fires.

What it does NOT see, so nobody trusts it further than it goes: a call through a dispatch table, a callback or a
variable (only `name(...)`, `self.name(...)` and `module.name(...)` resolve); an attribute call on anything that is
not `self` or an imported module of this folder (`DESKTOP.x()`, `self.bridge.hub.x()`); a generator built inside a
transaction and consumed outside it; and nothing at all about ordering, partial writes, replay or slow work.
"""
import ast
import collections
import os
import re
import sqlite3
import threading
import unittest
import uuid
from unittest.mock import patch

import hub
from test_responsibilities import CHECK, Base


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (Structure, Guard, CloseCase, DeliverResult):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


# ---------------------------------------------------------------- reading the hub's own code
# A plain `name(...)` call is one of this module's own functions, or one it imported by name from a module of this
# folder; `self.name(...)` is one of its methods; `module.name(...)` is a function of that module. Every other
# attribute call is library code, so `row.get(...)` is not the module's `get` and `", ".join(...)` is not its `join`.
# `anything.commit()` is a commit, whatever the connection is called.

COMMIT = ("", "c", "commit")


def hub_sources(start="hub"):
    """{module: its source} for `start` and every module of its own folder that it imports, transitively. Derived
    from the import statements, so a module another lane adds to hub.py is swept without anyone remembering to."""
    folder, sources, todo = os.path.dirname(os.path.abspath(hub.__file__)), {}, [start]
    while todo:
        name = todo.pop()
        if name in sources:
            continue
        path = os.path.join(folder, name + ".py")
        if not os.path.exists(path):
            continue
        with open(path) as f:
            sources[name] = f.read()
        for node in ast.walk(ast.parse(sources[name])):
            if isinstance(node, ast.Import):
                todo += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                todo.append(node.module)
    return sources


def imports_of(tree, known):
    """({alias: module}, {bare name: (module, its name there)}) for the modules of this folder that this one
    imports: `import wakeups` and `from lifecycle import tool_catalog` both have to resolve."""
    modules, names = {}, {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name in known:
                    modules[a.asname or a.name] = a.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in known:
            for a in node.names:
                names[a.asname or a.name] = (node.module, a.name)
    return modules, names


def definitions(tree, module=""):
    """({(module, name): [body]} for the module-level defs, the same for the methods, {id(body): its name})."""
    funcs, methods, named = collections.defaultdict(list), collections.defaultdict(list), {}

    def walk(node, prefix, in_class):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                (methods if in_class else funcs)[(module, child.name)].append(child)
                named[id(child)] = prefix + child.name
                walk(child, f"{prefix}{child.name}.", False)         # a nested def is reached by its plain name
            elif isinstance(child, ast.ClassDef):
                walk(child, f"{prefix}{child.name}.", True)
            else:
                walk(child, prefix, in_class)

    walk(tree, "", False)
    return funcs, methods, named


def calls_in(node, module, modules, names, cache={}):
    """[(key, call)] for every call lexically inside node, each key (module, kind, name): ('f', a function of that
    module), ('m', a method of this one), or COMMIT. The cache keys on the node itself, never on id(node): it lives
    as long as the process, and the id of a tree that an earlier test freed is given to a new node, which then read
    that tree's calls (a failure under load, 27 October 2026)."""
    if (node, module) in cache:
        return cache[(node, module)]
    found, stack = [], list(ast.iter_child_nodes(node))
    while stack:
        n = stack.pop()
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                where, called = names.get(f.id, (module, f.id))
                found.append(((where, "f", called), n))
            elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                if f.attr == "commit":
                    found.append((COMMIT, n))
                elif f.value.id == "self":
                    found.append(((module, "m", f.attr), n))
                elif f.value.id in modules:
                    found.append(((modules[f.value.id], "f", f.attr), n))
        stack.extend(ast.iter_child_nodes(n))
    cache[(node, module)] = found
    return found


def transactions(body):
    """Every `with transaction():` or `with hub.transaction():` lexically inside one function body."""
    def opens(item):
        f = item.context_expr.func if isinstance(item.context_expr, ast.Call) else None
        return (isinstance(f, ast.Name) and f.id == "transaction") or \
               (isinstance(f, ast.Attribute) and f.attr == "transaction")
    for n in ast.walk(body):
        if isinstance(n, (ast.With, ast.AsyncWith)) and any(opens(i) for i in n.items):
            yield n


def commit_paths(sources, start="hub"):
    """[(module, line, the function it is in, the transaction's line, the call, the path down to the commit)] for
    every call a transaction body makes that can reach a commit.

    Nothing is listed by hand: the seed is the functions that call `<connection>.commit()` themselves — q, ins,
    record_session_tokens, memory_search_probe and `transaction` — and the rest is the closure of that. `transaction`
    is in the seed on purpose, because a transaction inside a transaction commits the outer one's work, which is the
    same defect wearing the other hat."""
    if isinstance(sources, str):
        sources = {start: sources}
    trees = {m: ast.parse(src) for m, src in sources.items()}
    funcs, methods, named, scope = {}, {}, {}, {}
    for module, tree in trees.items():
        f, m, n = definitions(tree, module)
        funcs.update(f)
        methods.update(m)
        named.update(n)
        scope[module] = imports_of(tree, set(sources))
    edges, commits = {}, set()
    for kind, table in (("f", funcs), ("m", methods)):
        for (module, name), bodies in table.items():
            key = (module, kind, name)
            edges[key] = {k for b in bodies for k, _ in calls_in(b, module, *scope[module])}
            if COMMIT in edges[key]:
                commits.add(key)
    growing = True
    while growing:
        growing = False
        for key, reaches in edges.items():
            if key not in commits and reaches & commits:
                commits.add(key)
                growing = True

    def path(start_key):
        seen, queue = {start_key}, collections.deque([[start_key]])
        while queue:
            walked = queue.popleft()
            if COMMIT in edges.get(walked[-1], ()):
                return walked + [COMMIT]
            for step in sorted(edges.get(walked[-1], ())):
                if step in commits and step not in seen:
                    seen.add(step)
                    queue.append(walked + [step])
        return [start_key]

    found = set()
    for table in (funcs, methods):
        for (module, name), bodies in table.items():
            for body in bodies:
                for block in transactions(body):
                    for statement in block.body:
                        for key, call in calls_in(statement, module, *scope[module]):
                            if key in commits:
                                found.add((module, call.lineno, named.get(id(body), name), block.lineno, key[2],
                                           " -> ".join(k[2] if k != COMMIT else "commit()"
                                                       for k in path(key))))
    return sorted(found)


WRITE_SQL = re.compile(r"\s*(INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER)\b", re.I)
HOLDERS = ("LOCK", "transaction", "committed")


def sql_start(node):
    """The literal start of a statement: a string, an f-string's text or the left side of a `+`."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value for v in node.values if isinstance(v, ast.Constant))
    if isinstance(node, ast.BinOp):
        return sql_start(node.left)
    return ""


def unlocked_writes(source):
    """[(line, function)] of every `DB.execute` write in `source` that runs neither inside a `with LOCK`, a
    `transaction()` or a `committed()` of its own code, nor after an `in_transaction(...)` or `held(...)` of its own
    function. All threads write through the one connection, and only LOCK keeps one thread's write out of another
    thread's open transaction. It sees statements that start with literal text, and not a statement in a variable."""
    tree = ast.parse(source)
    holding = set()
    for w in ast.walk(tree):
        if isinstance(w, ast.With) and any(
                (e.id if isinstance(e, ast.Name) else e.func.id if isinstance(e, ast.Call) and
                 isinstance(e.func, ast.Name) else None) in HOLDERS for e in (i.context_expr for i in w.items)):
            holding |= set(range(w.lineno, w.end_lineno + 1))
    functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    found = []
    for c in ast.walk(tree):
        if not (isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and
                c.func.attr in ("execute", "executemany", "executescript") and isinstance(c.func.value, ast.Name) and
                c.func.value.id == "DB" and c.args and WRITE_SQL.match(sql_start(c.args[0])) and
                c.lineno not in holding):
            continue
        around = [f for f in functions if f.lineno <= c.lineno <= f.end_lineno]
        fn = max(around, key=lambda f: f.lineno) if around else None
        if fn is None or not any(isinstance(g, ast.Call) and isinstance(g.func, ast.Name) and
                                 g.func.id in ("in_transaction", "held") and g.lineno < c.lineno
                                 for g in ast.walk(fn)):
            found.append((c.lineno, fn.name if fn else "<module>"))
    return sorted(found)


class Structure(unittest.TestCase):
    """The hub's own code as text. No database, no fixture, no clock: this one holds whatever the suites drive."""

    def test_every_raw_write_holds_the_lock_or_a_transaction(self):
        """The audit of 7 November 2026: 13 writers wrote with a plain DB.execute and relied on a docstring for the
        lock. Each holds it now, or refuses without it (in_transaction, held), and so must the next one."""
        with open(hub.__file__) as f:
            found = unlocked_writes(f.read())
        self.assertEqual([], found, "A DB.execute write that holds neither LOCK nor a transaction: hold `with LOCK:`, "
                                    "or call in_transaction() or held() before it:\n"
                         + "\n".join(f"  hub.py:{line} in {fn}()" for line, fn in found))

    def test_every_typed_list_of_task_end_states_is_terminal(self):
        """The audit of 7 November 2026: the end states of a task are typed by hand in a dozen SQL lists and tuples, so
        a fifth state in TERMINAL would leave each of them reading that task as open. Every list that names
        'completed' and 'rejected' is TERMINAL, or TERMINAL without 'canceled': the ends with a result to check."""
        with open(hub.__file__) as f:
            tree = ast.parse(f.read())
        ends, lists = set(hub.TERMINAL), []
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                lists += [re.findall(r"'([a-z_]+)'", m) for m in re.findall(r"\(\s*'[a-z_]+'(?:\s*,\s*'[a-z_]+')*\s*\)",
                                                                             n.value)]
            elif isinstance(n, (ast.Tuple, ast.List, ast.Set)) and n.elts and \
                    all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in n.elts):
                lists.append([e.value for e in n.elts])
        typed = [names for names in lists if {"completed", "rejected"} <= set(names)]
        self.assertGreater(len(typed), 10)          # the scan reads them, and not nothing
        self.assertEqual([names for names in typed if set(names) not in (ends, ends - {"canceled"})], [])
        self.assertEqual(hub.OPEN_TASK, "state NOT IN ('completed','failed','rejected','canceled')")

    def test_the_lock_check_itself_finds_a_planted_one(self):
        found = unlocked_writes("def bare(a):\n"
                                "    DB.execute('UPDATE rows SET x=1')\n"
                                "\n"
                                "def guarded(a):\n"
                                "    held('guarded')\n"
                                "    DB.execute(f'DELETE FROM rows WHERE x={a}')\n"
                                "\n"
                                "def late(a):\n"
                                "    DB.execute('INSERT INTO rows(x) VALUES(1)')\n"
                                "    in_transaction('late')\n"
                                "\n"
                                "def locked(a):\n"
                                "    with LOCK:\n"
                                "        DB.execute('INSERT INTO rows(x) VALUES(1)')\n"
                                "    DB.execute('SELECT 1')\n")
        self.assertEqual([(2, "bare"), (9, "late")], found)

    def test_no_transaction_can_reach_anything_that_commits(self):
        sources = hub_sources()
        self.assertIn("hub", sources)
        found = commit_paths(sources)
        self.assertEqual([], found, "A transaction() body reaches something that commits, so it writes its first "
                                    "half on its own. Use read_rows for a read, and a plain DB.execute for a write "
                                    "that belongs to the transaction:\n"
                         + "\n".join(f"  {module}.py:{line} in {fn}() (transaction at {tx}) calls {called}(): {how}"
                                     for module, line, fn, tx, called, how in found))

    def test_it_reads_the_modules_hub_imports_and_not_only_hub(self):
        """The four modules the hub calls from inside its own transactions were the blind spot: wakeups, google, mcp
        and releases. The set comes from the import statements, so a fifth is swept without anyone remembering."""
        swept = hub_sources()
        self.assertLessEqual({"hub", "wakeups", "google", "mcp", "releases", "lifecycle", "usage", "desktop"},
                             set(swept))
        self.assertNotIn("json", swept)                 # only the modules of this folder, not the library

    def test_the_check_itself_finds_a_planted_one(self):
        """The measure is worth nothing if it cannot fail, and `q` inside a transaction is what it must catch."""
        found = commit_paths("def q(sql):\n"
                             "    DB.commit()\n"
                             "\n"
                             "def t_write(a):\n"
                             "    with transaction():\n"
                             "        DB.execute('INSERT INTO rows(x) VALUES(1)')\n"
                             "        q('SELECT 1')\n")
        self.assertEqual([("hub", 7, "t_write", 5, "q", "q -> commit()")], found)

    def test_a_commit_in_another_module_is_caught_too(self):
        """`wakeups.pick(...)` inside a transaction, where wakeups commits. This is the case the first version of
        this check could not see at all: it read hub.py and stopped at the dot."""
        found = commit_paths({"hub": "import wakeups\n"
                                     "\n"
                                     "def t_write(a):\n"
                                     "    with transaction():\n"
                                     "        DB.execute('INSERT INTO rows(x) VALUES(1)')\n"
                                     "        wakeups.pick(a)\n",
                              "wakeups": "def pick(a):\n"
                                         "    return store(a)\n"
                                         "\n"
                                         "def store(a):\n"
                                         "    conn.commit()\n"})
        self.assertEqual([("hub", 6, "t_write", 4, "pick", "pick -> store -> commit()")], found)

    def test_a_name_imported_from_another_module_is_followed_too(self):
        """`from lifecycle import tool_catalog` is called as a bare name, so without this it looked like a function
        of hub.py that does not exist, and the check walked past it."""
        found = commit_paths({"hub": "from lifecycle import tool_catalog\n"
                                     "\n"
                                     "def t_write(a):\n"
                                     "    with transaction():\n"
                                     "        tool_catalog(a)\n",
                              "lifecycle": "def tool_catalog(a):\n"
                                           "    DB.commit()\n"})
        self.assertEqual([("hub", 5, "t_write", 4, "tool_catalog", "tool_catalog -> commit()")], found)

    def test_a_transaction_inside_a_transaction_is_caught_too(self):
        found = commit_paths("def transaction():\n"
                             "    yield\n"
                             "    DB.commit()\n"
                             "\n"
                             "def inner():\n"
                             "    with transaction():\n"
                             "        DB.execute('INSERT INTO rows(x) VALUES(1)')\n"
                             "\n"
                             "def outer():\n"
                             "    with transaction():\n"
                             "        inner()\n")
        self.assertEqual([("hub", 11, "outer", 10, "inner", "inner -> transaction -> commit()")], found)

    def test_a_library_call_of_the_same_name_is_not_one_of_the_hubs(self):
        """`row.get(...)` is sqlite3.Row.get and not hub.get, and `", ".join(...)` is str.join. Without this the
        check names dozens of innocent lines and nobody reads it again."""
        self.assertEqual([], commit_paths("def get(k):\n"
                                          "    DB.commit()\n"
                                          "\n"
                                          "def join(parts):\n"
                                          "    DB.commit()\n"
                                          "\n"
                                          "def t_write(row):\n"
                                          "    with transaction():\n"
                                          "        DB.execute('INSERT INTO rows(x) VALUES(?)', (row.get('x'),))\n"
                                          "        DB.execute(', '.join(['a']))\n"))


class Guard(Base):
    """A helper that writes with a plain DB.execute refuses to run outside a transaction. The structural check above
    reads the callers that exist; this one holds the caller the next lane writes.

    duty_new_case and memory_from_work were left unguarded while the lane closing the six crash windows moved the
    transaction boundaries around them, because a guard written against a boundary that is about to move is worse
    than none. That lane guarded both, and the row writers it made, as part of its own work (20 October 2026)."""

    def test_resource_record_outside_a_transaction_refuses_instead_of_losing_the_row(self):
        """It used to write with ins, which commits. Now the row belongs to grant_resource's transaction, so a
        caller without one would leave it uncommitted — committed later by any unrelated q(), or lost with the
        connection, and silently either way."""
        with hub.LOCK:
            with self.assertRaises(RuntimeError) as caught:
                hub.resource_record("repo:acme/web", "vps", "write", "manager", "a" * 40)
        self.assertIn("none is open", str(caught.exception))
        self.assertEqual(0, hub.q1("SELECT COUNT(*) n FROM resource_grants")["n"])
        # And inside one it writes, which is what grant_resource does.
        with hub.LOCK, hub.transaction():
            hub.resource_record("repo:acme/web", "vps", "write", "manager", "a" * 40)
        self.assertEqual(1, hub.q1("SELECT COUNT(*) n FROM resource_grants")["n"])

    def test_log_row_outside_a_transaction_refuses_and_log_itself_still_commits(self):
        with hub.LOCK:
            with self.assertRaises(RuntimeError):
                hub.log_row("hub", "a line with no transaction to land in")
        hub.log("hub", "a line of its own")
        self.assertEqual(1, hub.q1("SELECT COUNT(*) n FROM log WHERE what='a line of its own'")["n"])
        with hub.LOCK, hub.transaction():
            hub.log_row("hub", "a line inside one")
        self.assertEqual(1, hub.q1("SELECT COUNT(*) n FROM log WHERE what='a line inside one'")["n"])

    def test_the_three_older_transaction_only_writes_refuse_outside_one_too(self):
        """keep_command, event_rows and dispatch_check each promised "inside a transaction" in a docstring and
        nothing held it. Five helpers in that shape, each one line from safe, is how the next instance of this bug
        gets written (the coordinating lane's call, 20 October 2026)."""
        command = ("vps", str(uuid.uuid4()), "remember", "d" * 64)
        with hub.LOCK:
            self.assertRaises(RuntimeError, hub.keep_command, command, {"text": "x"}, hub.now())
            self.assertRaises(RuntimeError, hub.event_rows, [("vps", "say", None, "x", None)], hub.now())
            self.assertRaises(RuntimeError, hub.dispatch_check, {"id": 1}, 1, hub.now())
        self.assertEqual(0, hub.q1("SELECT COUNT(*) n FROM tool_commands")["n"])
        self.assertEqual(0, hub.q1("SELECT COUNT(*) n FROM events WHERE kind='say'")["n"])
        # And inside one they write, which is what every tool with a request_id does.
        with hub.LOCK, hub.transaction():
            hub.keep_command(command, {"text": "x"}, hub.now())
            hub.event_rows([("vps", "say", None, "x", None)], hub.now())
        self.assertEqual(1, hub.q1("SELECT COUNT(*) n FROM tool_commands")["n"])
        self.assertEqual(1, hub.q1("SELECT COUNT(*) n FROM events WHERE kind='say'")["n"])

    def test_the_two_the_moving_lane_left_are_guarded_now(self):
        """duty_new_case and memory_from_work, and memory_close_rows, which memory_from_work calls. Every caller of the
        first two is inside a transaction already: open_case, close_case, deliver_result and admit_wake."""
        r = self.duty()
        with hub.LOCK:
            self.assertRaises(RuntimeError, hub.duty_new_case, r, "check/1", "The pool signed out", "a watch",
                              "hub", self.clock)
            self.assertRaises(RuntimeError, hub.memory_from_work, "vps", "The status page lies.", "believing it",
                              "the vendor", self.clock)
            self.assertRaises(RuntimeError, hub.memory_close_rows, "vps", [(1, 2)])
        self.assertEqual((0, 0), (hub.q1("SELECT COUNT(*) n FROM duty_cases")["n"],
                                  hub.q1("SELECT COUNT(*) n FROM memories")["n"]))
        with hub.LOCK, hub.transaction():
            hub.duty_new_case(r, "check/1", "The pool signed out", "a watch", "hub", self.clock)
            hub.memory_from_work("vps", "The status page lies.", "believing it", "the vendor", self.clock)
        self.assertEqual((1, 1), (hub.q1("SELECT COUNT(*) n FROM duty_cases")["n"],
                                  hub.q1("SELECT COUNT(*) n FROM memories")["n"]))

    def test_every_row_writer_of_the_crash_windows_refuses_outside_a_transaction(self):
        """The nine the same lane made while closing them. Each has a committing twin or a committing caller, so
        the guard never stands between a caller and the write it meant to make — the twins are checked below, where
        settle_hold, duty_save and change_duty drive them."""
        hold = {"id": 1, "task": 1, "attempt": 1, "created": self.clock}
        calls = [(hub.record_outcome_rows, (hold,)),
                 (hub.stop_request_rows, (hold,)),
                 (hub.request_unknown_rows, ({"id": 1, "task": 1, "attempt": 1, "request_id": "r", "method": "POST",
                                              "path": "/x", "login": "bws://x"},)),
                 (hub.duty_history_row, (1, "manager", "created", "a duty")),
                 (hub.duty_watch_rows, ({"id": 1, "agent": "vps", "text": "Keep it working."}, [], "manager",
                                        self.clock)),
                 (hub.duty_review_rows, ("vps", {"kind": "message", "to": "manager"}, ["R-1 A duty: new."],
                                         self.clock)),
                 (hub.trigger_create_rows, ({"agent": "vps", "schedule": {"kind": "every", "minutes": 10}},
                                            "manager", self.clock, "manager")),
                 (hub.trigger_edit_rows, (1, 1, {}, "manager", self.clock)),
                 (hub.trigger_state_rows, (1, 1, "pause", "manager", self.clock))]
        with hub.LOCK:
            for call, args in calls:
                with self.subTest(wrote=call.__name__):
                    with self.assertRaises(RuntimeError) as caught:
                        call(*args)
                    self.assertIn("none is open", str(caught.exception))

    def test_every_writer_that_says_inside_a_transaction_refuses_outside_one(self):
        """The 7 that the guard's docstring named as not guarded yet, and 16 more in the same shape that it did not
        name. Each refuses before its first write: a guard after the first writes leaves them for the next commit."""
        t0 = self.clock
        task = {"id": 1, "owner": "vps", "attempt": 1, "requester": "manager"}
        calls = [(hub.attempt_rows, (task, "lost", ("vps", "task", 1, "x", None), t0)),
                 (hub.end_open_runs, (1, "why", t0)), (hub.pause_trigger, (1, "hub", "why", t0)),
                 (hub.record_trigger, (1, "hub", "pause", {}, t0)),
                 (hub.once_done, ({"id": 1, "schedule": '{"kind": "once"}'},)),
                 (hub.memory_contradicted, (1, "deploy", t0)), (hub.memory_indexed, (1,)),
                 (hub.revoke_sessions, ("vps", t0)), (hub.admit_task, ("manager", {})),
                 (hub.notes_save, ("vps", "a note", "why", "vps", t0)),
                 (hub.chat_count, ("*", "inbound", t0, 1)), (hub.conversation_signal, ("vps", 1, t0))]
        with hub.LOCK:
            for call, args in calls:
                with self.subTest(wrote=call.__name__):
                    with self.assertRaises(RuntimeError) as caught:
                        call(*args)
                    self.assertIn("none is open", str(caught.exception))
            self.assertEqual(0, hub.chat_count("*", "inbound", t0))     # a read needs no transaction
        self.assertEqual((0, 0, 0), (hub.q1("SELECT COUNT(*) n FROM tasks")["n"],
                                     hub.q1("SELECT COUNT(*) n FROM attempts")["n"],
                                     hub.q1("SELECT COUNT(*) n FROM events WHERE kind='conversation'")["n"]))

    def test_a_commit_inside_a_transaction_refuses_and_takes_nothing_with_it(self):
        """The other half: a write that commits at once (q, q1, ins, emit, kv_get, kv_set, log, committed) inside an
        open transaction landed its half-written rows. The structural check above reads the calls that resolve by
        name; this holds the ones it cannot see (a dispatch table, a callback)."""
        for name, call in (("q", lambda: hub.q("SELECT 1")), ("ins", lambda: hub.ins("INSERT INTO log(ts,agent,what) "
                                                                                     "VALUES(1,'hub','x')")),
                           ("emit", lambda: hub.emit("vps", "say", "x")), ("kv_get", lambda: hub.kv_get("db_id")),
                           ("kv_set", lambda: hub.kv_set("half", "1")), ("log", lambda: hub.log("hub", "x")),
                           ("committed", lambda: hub.committed().__enter__())):
            with self.subTest(commits=name):
                with self.assertRaises(RuntimeError) as caught:
                    with hub.LOCK, hub.transaction():
                        hub.DB.execute("INSERT INTO notes(task,agent,ts,text) VALUES(1,'vps',1,'the first half')")
                        call()
                self.assertIn("inside an open transaction()", str(caught.exception))
                self.assertIsNone(hub.q1("SELECT 1 FROM notes WHERE text='the first half'"))
        hub.kv_set("whole", "1")                # and outside one they commit, as they always did
        self.assertEqual(hub.kv_get("whole"), "1")

    def test_a_transaction_inside_a_transaction_refuses_before_it_writes(self):
        """One connection has one transaction: the inner block's commit was the outer block's commit too."""
        with self.assertRaises(RuntimeError) as caught:
            with hub.LOCK, hub.transaction():
                hub.DB.execute("INSERT INTO notes(task,agent,ts,text) VALUES(1,'vps',1,'outer')")
                with hub.transaction():
                    hub.DB.execute("INSERT INTO notes(task,agent,ts,text) VALUES(1,'vps',1,'inner')")
        self.assertIn("does not nest", str(caught.exception))
        self.assertEqual(0, hub.q1("SELECT COUNT(*) n FROM notes")["n"])
        with hub.LOCK, hub.transaction():       # and the next one opens as usual
            hub.DB.execute("INSERT INTO notes(task,agent,ts,text) VALUES(1,'vps',1,'next')")
        self.assertEqual(1, hub.q1("SELECT COUNT(*) n FROM notes")["n"])

    def test_the_writers_that_said_inside_a_transaction_in_other_words_refuse_outside_one(self):
        """The audit of 7 November 2026: nine more said "inside chat_route's transaction", "inside the run's
        transaction" or "inside the caller's write", and nothing held it. Every caller has one: these hold that."""
        calls = [(hub.answer_rows, 5), (hub.secret_rewait, 1), (hub.secret_wait_moved, 1), (hub.person_route, 6),
                 (hub.conversation_decided, 5), (hub.conversation_answer, 3), (hub.history_drop_row, 1),
                 (hub.admit_wake, 5), (hub.failure_wake_rows, 3)]
        with hub.LOCK:
            for call, count in calls:
                with self.subTest(wrote=call.__name__):
                    with self.assertRaises(RuntimeError) as caught:
                        call(*[None] * count)
                    self.assertIn("none is open", str(caught.exception))

    def test_a_commit_from_a_thread_without_the_lock_refuses_and_lands_nothing(self):
        """All threads write through one connection, and SQLite keeps one transaction on it. A commit from a thread
        that does not hold LOCK landed what another thread had half written in its transaction(), and that thread's
        rollback then took back nothing. Here another thread holds a transaction open while this one commits."""
        written, finish, outcome = threading.Event(), threading.Event(), []

        def request():
            try:
                with hub.transaction():
                    hub.DB.execute("INSERT INTO notes(task,agent,ts,text) VALUES(1,'vps',1,'half written')")
                    written.set()
                    finish.wait(10)
                    raise ValueError("the request fails after its first write")
            except ValueError:
                outcome.append("rolled back")
        thread = threading.Thread(target=request, daemon=True)
        thread.start()
        self.assertTrue(written.wait(10))
        for name, call in (("commit", hub.commit), ("rollback", hub.rollback),
                           ("window_shares", lambda: hub.window_shares("vps", "acct", {}, self.clock))):
            with self.subTest(call=name):
                with self.assertRaises(RuntimeError) as caught:
                    call()
                self.assertIn("does not hold LOCK", str(caught.exception))
        finish.set()
        thread.join(10)
        self.assertEqual(outcome, ["rolled back"])
        self.assertIsNone(hub.q1("SELECT 1 FROM notes WHERE text='half written'"))
        with hub.committed():           # committed() takes the lock itself, as transaction() does
            hub.DB.execute("INSERT INTO notes(task,agent,ts,text) VALUES(1,'vps',1,'whole')")
        self.assertEqual(1, hub.q1("SELECT COUNT(*) n FROM notes WHERE text='whole'")["n"])

    def test_the_guard_counts_the_transaction_and_not_the_lock(self):
        """getattr(TX, "open", 0) and not DB.in_transaction: sqlite3 opens its implicit transaction at the first
        statement, so a helper that is the FIRST write of a transaction would see in_transaction False and refuse.
        resource_record is exactly that: grant_resource's transaction holds nothing else."""
        with hub.LOCK, hub.transaction():
            self.assertFalse(hub.DB.in_transaction)     # nothing written yet
            hub.in_transaction("a helper")              # and the guard lets it through anyway
        with hub.LOCK:
            self.assertRaises(RuntimeError, hub.in_transaction, "a helper")


class CloseCase(Base):
    """close_case writes the closed case, the duty's history line, the lesson and the receipt in one transaction."""

    def setUp(self):
        super().setUp()
        self.r = self.duty(watch=[{"kind": "check", "check": CHECK}])
        self.rule = self.watches(self.r["id"])[0]["id"]
        self.fire(self.rule)
        task = self.first_case_task()
        hub.q("UPDATE tasks SET state='completed', delivered=? WHERE id=?", (self.clock, task["id"]))
        self.c = self.case(task["duty_case"])

    def close(self, **extra):
        return self.tool("manager", "close_case", request_id=str(uuid.uuid4()), case=hub.cref(self.c),
                         outcome="handled", note="vps retired the account", **extra)

    def wrote(self):
        return (self.case(self.c["id"])["state"],
                hub.q1("SELECT COUNT(*) n FROM memories")["n"],
                hub.q1("SELECT COUNT(*) n FROM duty_history WHERE kind='case_closed'")["n"],
                hub.q1("SELECT COUNT(*) n FROM tool_commands")["n"])

    def test_a_lesson_that_cannot_be_written_leaves_the_case_open(self):
        """t_of_case read the case's newest task with q1, which commits, and it is an argument of the very call that
        writes the lesson — so the case was already closed before the lesson could fail. Then the agent's repeat was
        refused with "already closed. A new event is a new case", and what it learned had nowhere to go."""
        with patch.object(hub, "memory_from_work", side_effect=RuntimeError("disk I/O error")):
            with self.assertRaises(RuntimeError):
                self.close(learned="A signed-out pool account looks like a code bug in the logs.")
        self.assertFalse(hub.DB.in_transaction)
        self.assertEqual(("open", 0, 0, 0), self.wrote())

    def test_a_field_of_an_earlier_round_is_refused_and_leaves_the_case_open(self):
        """The same thing on the path an agent can actually walk into: a session that started before AUTONOMY.md P7
        still holds the old close_case with its cost_minutes, and the hub refuses that field before anything runs."""
        out, error = self.close(tried="The vendor's status page lies during an incident; it was green throughout.",
                                cost_minutes=45)
        self.assertTrue(error, out)
        self.assertIn("close_case does not take cost_minutes", out)
        self.assertEqual(("open", 0, 0, 0), self.wrote())
        # And the same call without it closes the case and keeps what did not work.
        out, error = self.close(tried="The vendor's status page lies during an incident; it was green throughout.")
        self.assertFalse(error, out)
        self.assertEqual(("closed", 1, 1, 1), self.wrote())

    def test_a_search_index_that_fails_commits_no_half_written_lesson(self):
        """memory_indexed falls back to a scan when this machine's index refuses the row, and it said so with log(),
        which commits. The lesson around it was half written, so the log line committed it."""
        self.addCleanup(lambda: hub.MEMORY_FTS.__setitem__(0, hub.MEMORY_FTS[0]))
        indexed = hub.MEMORY_FTS[0]
        hub.MEMORY_FTS[0] = True

        class FailAt:
            """Refuses the search index, so memory_indexed takes its fallback, and then the receipt, so the
            transaction rolls back. Whatever the fallback committed is what survives."""

            def __init__(self, db):
                self.db = db

            def execute(self, sql, *args):
                if sql.startswith("INSERT INTO memory_fts"):
                    raise sqlite3.OperationalError("no such table: memory_fts")
                if sql.startswith("INSERT INTO tool_commands"):
                    raise RuntimeError("disk I/O error")
                return self.db.execute(sql, *args)

            def __getattr__(self, name):
                return getattr(self.db, name)

        try:
            with patch.object(hub, "DB", FailAt(hub.DB)):
                with self.assertRaises(RuntimeError):
                    self.close(learned="A signed-out pool account looks like a code bug in the logs.")
            self.assertFalse(hub.DB.in_transaction)
            self.assertEqual(("open", 0, 0, 0), self.wrote())
            self.assertFalse(hub.MEMORY_FTS[0])             # it did record that the index is gone, in this process
        finally:
            hub.MEMORY_FTS[0] = indexed


class DeliverResult(Base):
    """deliver_result updates the task with q, outside the transaction that writes its lessons. So everything the
    lessons need checking for must be checked before that update, or the result stands and the lesson is lost."""

    def setUp(self):
        super().setUp()
        text, error = self.tool("manager", "create_task", owner="vps", title="Write the October report",
                                done_when="outputs/report.md is pushed", why="vps writes the text work")
        self.assertFalse(error, text)
        self.task = hub.q1("SELECT * FROM tasks ORDER BY id DESC LIMIT 1")

    def deliver(self, **extra):
        return self.tool("vps", "deliver_result", task_id=hub.tref(self.task["id"]), outcome="completed",
                         what_was_done="Wrote the report", where_output_is="commit a95cee6",
                         how_checked="The file is in the repository", **extra)

    def row(self):
        """(state, outcome, when it was delivered) of the task this result is for."""
        r = hub.q1("SELECT state, outcome, delivered FROM tasks WHERE id=?", (self.task["id"],))
        return (r["state"], r["outcome"], r["delivered"])

    def test_a_field_of_an_earlier_round_delivers_nothing(self):
        """The task used to be delivered first and the dead end refused afterwards, so the agent was told its result
        was refused while the result stood — and rule 2 forbids reopening a finished task to record the lesson."""
        for extra in ({"cost_minutes": 45}, {"recheck": "Open the status page during the next incident."}):
            out, error = self.deliver(tried="The vendor's status page lies during an incident.", **extra)
            self.assertTrue(error, out)
            self.assertIn(f"deliver_result does not take {next(iter(extra))}", out)
            self.assertEqual(("submitted", None, None), self.row())
        self.assertEqual(0, hub.q1("SELECT COUNT(*) n FROM memories")["n"])

    def test_a_tried_the_hub_refuses_delivers_nothing(self):
        out, error = self.deliver(tried="x" * (hub.MEMORY_TEXT + 1))
        self.assertTrue(error, out)
        self.assertIn("tried must be 1 to", out)
        self.assertEqual(("submitted", None, None), self.row())
        self.assertEqual(0, hub.q1("SELECT COUNT(*) n FROM memories")["n"])

    def test_what_did_not_work_reaches_an_ordinary_lesson(self):
        out, error = self.deliver(tried="The vendor's status page lies during an incident. To check: open it during "
                                        "the next incident.")
        self.assertFalse(error, out)
        self.assertEqual("completed", self.row()[0])
        dead = hub.q1("SELECT * FROM memories ORDER BY id DESC LIMIT 1")
        self.assertEqual(("lesson", None, None, hub.DEAD_END_PREVENTS),
                         (dead["kind"], dead["cost_minutes"], dead["recheck"], dead["prevents"]))
        self.assertTrue(dead["text"].startswith(hub.MEMORY_TRIED + "The vendor's status page lies"), dead["text"])

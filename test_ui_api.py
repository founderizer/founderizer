"""Deterministic native-owner API checks. No real fleet or AI calls."""
import ast
import collections
import concurrent.futures
import contextlib
import copy
import errno
import functools
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import hub
from leftovers import parent_pipe, removed_when_gone, tmux_socket, when_gone, while_this_test_runs

KIT = os.path.dirname(os.path.abspath(__file__))

# ---- the attachment folder. hub.tick() sweeps it and removes every file there that the test's database does not name,
# so a test that ticks with no folder of its own empties the real ~/.fleet/attachments of the machine that runs it.

REAL_ATTACHMENTS = os.path.realpath(hub.ATTACH_DIR)


def own_attachments(test, folder):
    """The test's own attachment folder (hub.CFG["attachment_dir"]), until the test ends."""
    had, old = "attachment_dir" in hub.CFG, hub.CFG.get("attachment_dir")
    hub.CFG["attachment_dir"] = folder
    test.addCleanup(lambda: hub.CFG.update(attachment_dir=old) if had else hub.CFG.pop("attachment_dir", None))


def sweeps_only_a_test_folder(sweep):
    """hub.tick and hub.attachment_sweep in every test process that loads this module: each fails before it runs when
    the test has no folder of its own (own_attachments), or has the machine's own."""
    @functools.wraps(sweep)
    def checked(*args, **kwargs):
        folder = hub.CFG.get("attachment_dir")
        if not folder or os.path.realpath(folder) == REAL_ATTACHMENTS:
            raise AssertionError(f"hub.{sweep.__name__}() would sweep {folder or hub.ATTACH_DIR}: give the test a "
                                 "folder of its own with test_ui_api.own_attachments")
        return sweep(*args, **kwargs)
    return checked


hub.tick, hub.attachment_sweep = sweeps_only_a_test_folder(hub.tick), sweeps_only_a_test_folder(hub.attachment_sweep)


# ---- the test's database. A hub syncs every commit to the disk and keeps a rollback journal beside its records, so
# that a power cut loses nothing. A test's database lives for one test, and each statement of hub.SCHEMA is a commit
# of its own: with the hub's settings the 43 tests of test_needs_options wrote 830 MB to the disk, and with these two
# they wrote 39 MB (10 November 2026, when the threads' test runs together wrote 135 MB a second on the owner's Mac).

def quick(db):
    """A test's own connection to a database that no hub runs on: no sync to the disk, and no journal file."""
    db.execute("PRAGMA synchronous=OFF")
    db.execute("PRAGMA journal_mode=MEMORY")
    return db


# ---- what a test starts or makes outlives no test process (leftovers.py). The test process that HubProcesses kills:


def a_test_with_a_hub_and_a_server():
    """A test process that starts a hub as the tests do, a server under a keeper and a tmux server, gives the guard a
    command and a folder, and then waits to be killed (HubProcesses). The hub's folder names the tmux server's socket
    in its file tmux-socket."""
    folder = tempfile.mkdtemp(prefix="fleet-killed-test-")
    left = Path(folder).parent / "left"         # beside the folder, so that only the command removes it
    left.touch()
    when_gone(["rm", str(left)])
    removed_when_gone(tempfile.mkdtemp(prefix="fleet-killed-folder-"))
    sleeper = [sys.executable, "-c", "import time; time.sleep(600)", folder]
    command, fds = while_this_test_runs(sleeper)
    subprocess.Popen(command, pass_fds=fds, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
    if shutil.which("tmux"):
        tmux_path = tmux_socket("fleet-killed-test")
        subprocess.run(["tmux", "-S", tmux_path, "new-session", "-d", shlex.join(sleeper)], check=True,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        Path(folder, "tmux-socket").write_text(tmux_path)
    with open(os.path.join(folder, "team.json"), "w") as f:
        json.dump({"hub": {"machine": "hub", "port": 8765}, "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.1"},
                   "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []}}}, f)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    pipe, fds = parent_pipe(folder)
    subprocess.Popen([sys.executable, os.path.join(KIT, "hub.py"), "--host", "127.0.0.1", "--port", str(port),
                      "--db", os.path.join(folder, "hub.db"), "--team", os.path.join(folder, "team.json"),
                      "--parent-pipe", str(pipe)],
                     pass_fds=fds, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     env=dict(os.environ, HOME=folder))     # its timer sweeps ~/.fleet/attachments
    time.sleep(600)


@functools.lru_cache(maxsize=1)
def hub_starts():
    """Each subprocess.Popen of hub.py in a test file: (file:line, the call)."""
    return [(f"{path.name}:{node.lineno}", node) for path in sorted(Path(KIT).glob("test_*.py"))
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            if isinstance(node, ast.Call) and ast.unparse(node.func) == "subprocess.Popen" and node.args
            and re.search(r"\bhub\.py\b", ast.unparse(node.args[0]))]


# ---- no large answer leaves while its thread holds the hub's lock, in a test whose hub OwnerAPI.setUp makes. The
# write of an answer ends only when the kernel has room for all of its bytes, and it gets that room at the pace of the
# reader, so every other caller of the hub waits for that reader: until 10 November 2026 the frame of a task's screen
# (ui_desktop) and the start of a conversation window (helper_conversation_start) were two such answers. Measured that
# day on Linux 6.10 with a round trip of 60 ms: a new connection took an answer of 36 KB at once, and an answer of
# 46 KB waited one round trip. An answer of up to LOCKED_BODY_MAX bytes, with its head, is less than half of the first
# one. It is also the default middle value of net.ipv4.tcp_wmem: the send buffer that a Linux socket starts with,
# which the kernel makes larger when the connection opens.

LOCKED_BODY_MAX = 16384
LOCKED_SENDS = []       # (method, path, status, bytes) of each larger answer that a SourceHandler sent under the lock


def no_large_answer_under_the_lock(test, since):
    """The guard of every test with a hub of OwnerAPI.setUp (LOCKED_SENDS): no answer of more than LOCKED_BODY_MAX
    bytes went out while its thread held the hub's lock. A cleanup of that setUp, so it runs after tearDown, which
    waits for every request of the test's hub, and it fails the test that made the answer. A function, because some
    classes take OwnerAPI.setUp without being an OwnerAPI. It takes what it read, so the next test starts with none;
    an answer of a request that outlived tearDown's wait goes to the test that runs then, with its route in the
    words."""
    sent = LOCKED_SENDS[since:]
    del LOCKED_SENDS[since:since + len(sent)]
    if sent:
        test.fail("an answer of more than %d bytes went out while its thread held the hub's lock, so every other "
                  "caller of the hub waited for its reader: %s. Make the answer under the lock and send it after the "
                  "lock (hub.Handler.ui_desktop)." % (LOCKED_BODY_MAX, "; ".join(
                      f"{method} {path} {code} ({size:,} bytes)" for method, path, code, size in sent)))


class SourceHandler(hub.Handler):
    """The hub's handler in tests. Every test request comes from 127.0.0.1, but the owner and each machine can have
    their own address: the X-Test-Source header gives the caller's address. With server.machines true, a request
    without it comes from the machine of the agent that its route names, as on a real network; other requests keep
    127.0.0.1. The hub itself never reads this header.
    A request counts in server.busy from its parsed headers until its handling ends: OwnerAPI.tearDown waits for it,
    and not for an idle kept-alive connection."""
    def handle_one_request(self):
        self.counted = False
        try:
            super().handle_one_request()
        finally:
            if self.counted:
                with self.server.idle:
                    self.server.busy -= 1
                    self.server.idle.notify_all()

    def parse_request(self):
        ok = super().parse_request()
        if ok:
            with self.server.idle:
                self.server.busy += 1
            self.counted = True
        source = self.headers.get("X-Test-Source") if ok else None
        if ok and not source and getattr(self.server, "machines", False):
            parts, query = self.route()
            name = (parts[2] if parts[:1] in (["helper"], ["hook"], ["worker"]) and len(parts) > 2 else
                    parts[1] if parts[:1] in (["events"], ["mcp"], ["keys"]) and len(parts) > 1 else
                    query.get("agent") if parts[:1] == ["sealed"] else None)
            source = hub.address_of(name) if name else None
        if source:
            self.client_address = (source, self.client_address[1])
        return ok

    def send(self, code, body=b"", ctype="application/json", headers=None):
        """Every answer of a test's hub, JSON or not: one with more than LOCKED_BODY_MAX bytes of body that goes out
        while this thread holds the hub's lock is noted in LOCKED_SENDS before it goes, and the test that made it
        fails at its end (no_large_answer_under_the_lock). A HEAD sends no body."""
        size = 0 if self.command == "HEAD" else len(body.encode() if isinstance(body, str) else body)
        if size > LOCKED_BODY_MAX and hub.LOCK._is_owned():
            LOCKED_SENDS.append((self.command, self.path.split("?", 1)[0], code, size))
        return super().send(code, body, ctype, headers)


# Seconds that a test waits for one answer of the hub. FLEET_TEST_PATIENCE sets another time for a run on a loaded
# machine, where a call that starts git can take longer than this with nothing wrong in the hub.
PATIENCE = float(os.environ.get("FLEET_TEST_PATIENCE") or 5)


class LandingLock:
    """hub.LOCK for one call of a test: before the nth time that the call's own thread takes the lock from outside,
    `land` runs. A delete and a rename hold the lock for their whole run, so these are all the moments at which one of
    them can come between two steps of another call: the call waits for the lock, and goes on after it."""
    def __init__(self, lock):
        self.lock, self.test, self.depth = lock, threading.get_ident(), collections.Counter()
        self.arm(None, None)

    def arm(self, at, land):
        self.at, self.land, self.thread, self.count, self.landed = at, land, None, 0, False

    def acquire(self, *args, **kwargs):
        me = threading.get_ident()
        if self.at and me != self.test and not self.depth[me] and self.thread in (None, me):
            self.thread, self.count = me, self.count + 1        # the first thread that asks is the call's own
            if self.count == self.at and not self.landed:
                self.landed = True
                self.land()
        taken = self.lock.acquire(*args, **kwargs)
        if taken:
            self.depth[me] += 1
        return taken

    def release(self):
        self.lock.release()
        self.depth[threading.get_ident()] -= 1

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *exc):
        self.release()

    def _is_owned(self):
        return self.lock._is_owned()


class OwnerAPI(unittest.TestCase):
    patience = PATIENCE     # a class whose one call runs a whole owner command waits longer (test_agent_remove)

    def setUp(self):
        self.addCleanup(no_large_answer_under_the_lock, self, len(LOCKED_SENDS))       # after tearDown
        self.tmp = tempfile.TemporaryDirectory(prefix="fleet-ui-test-")
        removed_when_gone(self.tmp.name)                    # a test process that is killed runs no tearDown
        own_attachments(self, self.tmp.name + "/attachments")
        self.path = self.tmp.name + "/test.db"
        self.connect()
        hub.TEAM = {"addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2"},
                    "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []}}}
        hub.kv_set("db_id", "test-generation")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), SourceHandler)
        self.server.busy, self.server.idle = 0, threading.Condition()      # the requests that run now (SourceHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:" + str(self.server.server_port)

    def connect(self):
        hub.DB = quick(sqlite3.connect(self.path, check_same_thread=False))
        hub.DB.row_factory = sqlite3.Row
        hub.DB.executescript(hub.SCHEMA)
        hub.migrate()

    def tearDown(self):
        self.server.shutdown()
        # A request that outlived its client's timeout ends before the cleanups: without the test's team_path, its next
        # git steps would run in this checkout (hub.kit_dir). The request threads are daemons, and server_close does
        # not wait for them.
        with self.server.idle:
            self.server.idle.wait_for(lambda: not self.server.busy, 60)
        self.server.server_close()
        self.thread.join()
        hub.DB.close()
        self.tmp.cleanup()

    def request(self, path="/ui/state", body=None, headers=None, source=None):
        headers = dict(headers or {"Content-Type": "application/json", "X-Fleet-Client": "deterministic-test"})
        if source:
            headers["X-Test-Source"] = source           # the caller's address (SourceHandler)
        req = urllib.request.Request(self.base + path,
            data=json.dumps(body).encode() if body is not None else None, headers=headers)
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with op.open(req, timeout=getattr(self, "patience", PATIENCE)) as response:      # (a class can borrow this)
                return response.status, json.load(response)
        except urllib.error.HTTPError as response:
            with response:
                return response.code, json.load(response)

    def command(self, **changes):
        return dict(dict(request_id=str(uuid.uuid4()), db="test-generation", text="Write a test label."), **changes)

    def kept(self):
        """A function that puts the fleet back as it is now: its records and its team."""
        records = sqlite3.connect(":memory:", check_same_thread=False)
        self.addCleanup(records.close)
        hub.DB.backup(records)
        team = copy.deepcopy(hub.TEAM)

        def again():
            with hub.LOCK:
                records.backup(hub.DB)
            hub.TEAM = copy.deepcopy(team)
            hub._revision_cache.update(at=0.0, value=None)
        return again

    def lock_waits(self, call, land, again=None):
        """`call()` again and again, with `land()` run just before the nth time that the call's own thread takes the
        hub's lock from outside, for n = 1, 2, ... until a call has fewer lock waits than that. Those are all the
        moments at which another request can come between two steps of the call: whatever holds the lock runs to its
        end first, and the call goes on after it. `land` runs in a thread of its own, as another request does, and
        `again()` first puts the fleet back as each moment needs it. Gives (n, what the call returned) for each
        moment at which `land` ran."""
        lock, failed = LandingLock(hub.LOCK), []

        def landing():
            def run():
                try:
                    land()
                except Exception as e:          # told in the test's own thread, below
                    failed.append(e)
            thread = threading.Thread(target=run)
            thread.start()
            thread.join()
        with patch.object(hub, "LOCK", lock):
            for n in range(1, 200):
                if again:
                    again()
                lock.arm(n, landing)
                result = call()
                landed = lock.landed
                lock.arm(None, None)
                if failed:
                    raise failed[0]
                if not landed:
                    return
                yield n, result

    def count(self, table):
        return hub.q1("SELECT count(*) n FROM " + table)["n"]

    def need(self):
        return hub.ins("INSERT INTO needs(title,why,todo,raised,by) VALUES(?,?,?,?,?)",
                       ("Choose label", "owner choice", "enter label", hub.now(), "manager"))

    def test_state_is_read_only_and_excludes_private_runtime_data(self):
        hub.touch("manager")
        event = hub.emit("manager", "say", "unread")
        before = dict(hub.q1("SELECT * FROM agents WHERE name='manager'"))
        code, state = self.request()
        self.assertEqual(code, 200)
        self.assertEqual(state["schema_version"], 1)
        self.assertEqual(set(state), {"schema_version", "db", "time", "token", "manager_flag", "manager_warning", "goals", "steers", "tasks", "notes",
                                    "needs", "permissions", "agents", "messages", "reports", "ui_features", "knowledge", "secrets",
                                    "holds", "outcomes", "chat_apps", "responsibilities", "repository"})
        self.assertEqual(before, dict(hub.q1("SELECT * FROM agents WHERE name='manager'")))
        row = hub.q1("SELECT * FROM events WHERE id=?", (event,))
        self.assertIsNone(row["read_at"])
        self.assertIsNone(row["helper_ack"])
        self.assertNotIn("pubkey", state["agents"][0])
        self.assertNotIn("start", state["agents"][0])

    def test_state_says_until_when_a_task_is_parked_and_on_that_task_only(self):
        """Owner API 1.117: `parked_until` is on the row of a task whose live path says that it waits for its reminder,
        and no other task row has the key."""
        parked = hub.ins("INSERT INTO tasks(title,owner,state,live_path) VALUES('Wait for the build','vps','working',?)",
                         (hub.PARKED_PATH + "10:00 UTC, as vps asked (R-1)",))
        ended = hub.ins("INSERT INTO tasks(title,owner,state,live_path) VALUES('Old','vps','completed',?)",
                        (hub.PARKED_PATH + "10:00 UTC, as vps asked (R-2)",))
        working = hub.ins("INSERT INTO tasks(title,owner,state,live_path) VALUES('Work','vps','working','live session')")
        due = hub.now() + 3600
        for task in (parked, ended, working):
            hub.ins("INSERT INTO reminders(due,note,agent,task,created) VALUES(?,?,?,?,?)", (due, "later", "vps", task, hub.now()))
        code, state = self.request()
        self.assertEqual(code, 200)
        rows = {t["id"]: t for t in state["tasks"]}
        self.assertEqual(rows[parked]["parked_until"], due)
        self.assertNotIn("parked_until", rows[ended])           # a task that ended waits for nothing
        self.assertNotIn("parked_until", rows[working])         # its live path is a session: the tick did not judge it parked
        hub.q("UPDATE reminders SET done=1 WHERE task=?", (parked,))
        self.assertNotIn("parked_until", {t["id"]: t for t in self.request()[1]["tasks"]}[parked])

    def test_state_names_each_agents_role_in_the_team(self):
        """The owner, 3 November 2026: "a subtitle like their role in the team" under each agent's name: its team.json
        title, or null."""
        self.assertIsNone(self.request()[1]["agents"][0]["title"])
        hub.TEAM["agents"]["manager"]["title"] = "Fleet Manager"
        self.addCleanup(hub.TEAM["agents"]["manager"].pop, "title", None)
        self.assertEqual(self.request()[1]["agents"][0]["title"], "Fleet Manager")

    def test_receipt_is_not_a_manager_read(self):
        body = self.command()
        code, receipt = self.request("/ui/messages", body)
        self.assertEqual(code, 200)
        self.assertFalse(receipt["replayed"])
        self.assertIsNone(receipt["read_at"])
        self.assertIn(body["text"], hub.t_read_messages("manager", {}))
        _, state = self.request()
        self.assertEqual(state["messages"][0]["event_id"], receipt["event_id"])
        self.assertIsNotNone(state["messages"][0]["read_at"])

    def test_pending_result_includes_full_progress_history_for_requester_check(self):
        tid = hub.ins("INSERT INTO tasks(title,owner,state,what) VALUES('Recovery','vps','completed','Done')")
        for text in ("READY_WORKER_CRASH", "Resumed on attempt 2"):
            hub.ins("INSERT INTO notes(task,agent,ts,text) VALUES(?,?,?,?)", (tid, "vps", hub.now(), text))
        overview = hub.t_see_team("manager", {})
        self.assertLess(overview.index("READY_WORKER_CRASH"), overview.index("Resumed on attempt 2"))
        hub.q("UPDATE tasks SET accepted=1 WHERE id=?", (tid,))
        self.assertNotIn("READY_WORKER_CRASH", hub.t_see_team("manager", {}))

    def test_concurrent_repeat_dispatches_once(self):
        body = self.command()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.request("/ui/messages", body), range(8)))
        self.assertTrue(all(code == 200 for code, _ in results))
        self.assertEqual(len({r["event_id"] for _, r in results}), 1)
        self.assertEqual(sum(not r["replayed"] for _, r in results), 1)
        self.assertEqual(self.count("events"), 1)
        self.assertEqual(self.count("ui_requests"), 1)

    def test_unknown_outcome_reconciles_after_database_reopen(self):
        body = self.command()
        _, first = self.request("/ui/messages", body)
        hub.DB.close()
        self.connect()
        _, state = self.request()
        self.assertEqual(state["messages"][0]["request_id"], body["request_id"])
        _, repeated = self.request("/ui/messages", body)
        self.assertEqual(first["event_id"], repeated["event_id"])
        self.assertTrue(repeated["replayed"])
        self.assertEqual(self.count("events"), 1)

    def test_changed_payload_or_route_cannot_reuse_id(self):
        body = self.command()
        self.request("/ui/messages", body)
        self.assertEqual(self.request("/ui/messages", dict(body, text="Different"))[0], 409)
        nid = self.need()
        self.assertEqual(self.request(f"/ui/needs/{nid}", dict(body, answer="Different"))[0], 409)
        self.assertEqual(self.count("events"), 1)
        self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"])

    def test_stale_generation_is_never_replayed(self):
        body = self.command()
        self.request("/ui/messages", body)
        hub.kv_set("db_id", "new-generation")
        self.assertEqual(self.request("/ui/messages", body)[0], 409)
        self.assertEqual(self.count("events"), 1)

    def test_answer_and_duplicate_keep_one_event_and_original_answer(self):
        nid = self.need()
        body = self.command(answer="teal")
        code, receipt = self.request(f"/ui/needs/{nid}", body)
        self.assertEqual(code, 200)
        self.assertEqual(self.request(f"/ui/needs/{nid}", body)[1]["event_id"], receipt["event_id"])
        self.assertEqual(self.request(f"/ui/needs/{nid}", self.command(answer="blue"))[0], 409)
        self.assertEqual(self.count("events"), 1)
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"], "teal")
        self.assertIn("Answer to Needs-you", hub.t_read_messages("manager", {}))

    def test_missing_need_is_not_dispatched(self):
        self.assertEqual(self.request("/ui/needs/999", self.command(answer="teal"))[0], 404)
        self.assertEqual(self.count("events"), 0)

    def test_transaction_rolls_back_answer_event_and_receipt_together(self):
        nid = self.need()
        hub.q("CREATE TRIGGER fail_receipt BEFORE INSERT ON ui_requests BEGIN SELECT RAISE(ABORT, 'test failure'); END")
        body = self.command(answer="teal")
        with patch("hub.traceback.print_exc"):
            self.assertEqual(self.request(f"/ui/needs/{nid}", body)[0], 500)
        self.assertEqual(self.count("events"), 0)
        self.assertEqual(self.count("ui_requests"), 0)
        self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"])
        hub.q("DROP TRIGGER fail_receipt")
        self.assertEqual(self.request(f"/ui/needs/{nid}", body)[0], 200)
        self.assertEqual(self.count("events"), 1)

    def test_registered_secret_is_neither_dispatched_nor_stored(self):
        password, salt = "SyntheticPassword123", "synthetic-salt"
        hub.ins("INSERT INTO secrets(salt,hash,len) VALUES(?,?,?)",
                (salt, hashlib.sha256((salt + password).encode()).hexdigest(), len(password)))
        self.assertEqual(self.request("/ui/messages", self.command(text=password))[0], 422)
        self.assertEqual(self.count("ui_requests"), 0)
        self.assertEqual(self.count("events"), 0)
        self.assertEqual(hub.leak_scan(), [])

    def test_snapshot_masks_text_registered_as_a_login_later(self):
        text, salt = "SyntheticPassword123", "synthetic-salt"
        nid = self.need()
        hub.q("UPDATE needs SET title=? WHERE id=?", (text, nid))
        hub.ins("INSERT INTO secrets(salt,hash,len) VALUES(?,?,?)",
                (salt, hashlib.sha256((salt + text).encode()).hexdigest(), len(text)))
        code, state = self.request()
        self.assertEqual(code, 200)
        self.assertNotIn(text, json.dumps(state))
        self.assertEqual(state["needs"][0]["title"], "[Registered login removed]")

    def test_owner_address_is_required(self):
        hub.TEAM["addresses"]["owner"] = ""
        self.assertEqual(self.request()[0], 503)
        self.assertEqual(self.request("/ui/messages", self.command())[0], 503)

    def test_other_machine_cannot_read_or_send(self):
        hub.TEAM["addresses"]["owner"] = "127.0.0.2"
        self.assertEqual(self.request()[0], 403)
        self.assertEqual(self.request("/ui/messages", self.command())[0], 403)
        self.assertEqual(self.count("ui_requests"), 0)

    def test_browser_origin_and_form_post_are_refused(self):
        headers = {"Content-Type": "application/json", "Origin": "https://example.com"}
        self.assertEqual(self.request(headers=headers)[0], 403)
        self.assertEqual(self.request("/ui/messages", self.command(), headers)[0], 403)
        self.assertEqual(self.request("/ui/messages", self.command(), {"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.count("events"), 0)

    def test_invalid_or_oversized_requests_do_not_dispatch(self):
        for change in ({"request_id": "invalid"}, {"text": " "}, {"text": 3}, {"text": "a" * 16001}):
            self.assertEqual(self.request("/ui/messages", self.command(**change))[0], 400)
        self.assertEqual(self.request("/ui/messages", self.command(text="a" * 65536))[0], 413)
        self.assertEqual(self.count("events"), 0)

    def test_manager_report_is_real_readable_and_does_not_notify(self):
        result, error = hub.call_tool("manager", "tell_owner", {"text": "Checked T-1.", "about": "M-2 T-1"})
        self.assertFalse(error, result)
        self.assertEqual(self.count("events"), 0)
        self.assertEqual(self.request()[1]["reports"][0]["text"], "Checked T-1.")
        hub.TEAM["agents"]["worker"] = {"role": "worker", "runtime": "codex"}
        _, error = hub.call_tool("worker", "tell_owner", {"text": "Bypass manager"})
        self.assertTrue(error)
        self.assertEqual(self.count("owner_reports"), 1)

    def test_client_identity_is_recorded_and_cannot_change_on_replay(self):
        body = self.command()
        _, receipt = self.request("/ui/messages", body)
        self.assertEqual(receipt["client"], "deterministic-test")
        self.assertEqual(self.request()[1]["messages"][0]["client"], "deterministic-test")
        headers = {"Content-Type": "application/json", "X-Fleet-Client": "another-client"}
        self.assertEqual(self.request("/ui/messages", body, headers)[0], 409)
        self.assertEqual(self.request("/ui/messages", self.command(), {"Content-Type": "application/json"})[0], 400)
        self.assertEqual(self.count("events"), 1)


class AttachmentFolder(unittest.TestCase):
    """No test sweeps the machine's own ~/.fleet/attachments: the check of sweeps_only_a_test_folder, and the two
    things that keep it whole."""
    setUp, tearDown, connect = OwnerAPI.setUp, OwnerAPI.tearDown, OwnerAPI.connect

    def test_a_sweep_without_a_folder_of_the_tests_own_fails_before_it_runs(self):
        folder = os.path.join(self.tmp.name, "attachments")
        stray = os.path.join(folder, "stray.txt")           # no row names it, and nothing wrote it this hour
        os.makedirs(folder)
        with open(stray, "w") as f:
            f.write("x")
        os.utime(stray, (time.time() - 7200,) * 2)
        # The default folder is this one here, so a check that let a sweep through would not reach the machine's own.
        with patch.object(hub, "ATTACH_DIR", folder), patch.dict(hub.CFG, {"attachment_dir": None}):
            for sweep in (hub.tick, lambda: hub.attachment_sweep(hub.now())):
                with self.assertRaises(AssertionError):
                    sweep()
        self.assertTrue(os.path.exists(stray))
        hub.attachment_sweep(hub.now())                     # with a folder of the test's own, it runs
        self.assertFalse(os.path.exists(stray))

    def test_every_test_module_that_ticks_loads_the_check(self):
        """Itself or through a module of tests that it loads, so the check runs when that module runs alone."""
        found = {p.stem: p.read_text(encoding="utf-8") for p in Path(KIT).glob("test_*.py")}
        loads = {name: set(re.findall(r"^(?:from|import) (test_\w+)", text, re.M)) for name, text in found.items()}
        armed, new = set(), {"test_ui_api"}
        while new:
            armed |= new
            new = {name for name, them in loads.items() if them & armed} - armed
        ticking = {name for name, text in found.items() if "hub.tick()" in text}
        self.assertGreater(len(ticking), 10, "the scan found too few: its pattern no longer matches the tests")
        self.assertEqual(sorted(ticking - armed), [])

    def test_a_hub_process_that_a_test_starts_has_a_home_of_its_own(self):
        """Its own timer sweeps ~/.fleet/attachments, in a process that the check does not reach."""
        for where, call in hub_starts():
            env = next((ast.unparse(k.value) for k in call.keywords if k.arg == "env"), "")
            with self.subTest(where):
                self.assertIn("HOME", env)
        self.assertGreater(len(hub_starts()), 3, "the scan found too few: its pattern no longer matches the tests")


class HubProcesses(unittest.TestCase):
    """No hub.py process that a test starts, no server, no tmux socket file and no folder outlives the test process
    (leftovers.py)."""

    def test_a_hub_process_that_a_test_starts_stops_when_the_test_process_is_gone(self):
        for where, call in hub_starts():
            with self.subTest(where):
                self.assertIn("--parent-pipe", ast.unparse(call.args[0]))
                self.assertIn("pass_fds", [k.arg for k in call.keywords])
        self.assertGreater(len(hub_starts()), 3, "the scan found too few: its pattern no longer matches the tests")

    def test_a_test_process_that_is_killed_leaves_no_process_and_no_folder(self):
        """SIGKILL, which a caller sends at its time-out: the test process runs no cleanup, its hub stops itself, the
        keeper stops its server, and the guard runs its commands, which stop the tmux server, and then removes the
        tmux server's socket file and the folders. The test process makes its folders in a TMPDIR of this test's own,
        and its tmux server names one in its command, so that what it leaves is found by that path, and a test of
        another thread on this Mac is never found."""
        tmp = tempfile.mkdtemp(prefix="fleet-hub-processes-")
        self.addCleanup(shutil.rmtree, tmp, True)

        def naming():
            listed = subprocess.run(["ps", "-A", "-ww", "-o", "pid=,command="], capture_output=True, text=True).stdout
            return [line.strip() for line in listed.splitlines() if tmp in line]

        tmux = []                       # the socket of the test process's tmux server, when this Mac has tmux

        def tmux_left():
            return [path for path in tmux if os.path.lexists(path)]

        def stop_what_is_left():        # after a failure: by the PID of each process that names this test's TMPDIR
            for line in naming():
                with contextlib.suppress(ProcessLookupError):
                    os.kill(int(line.split()[0]), signal.SIGTERM)
            for path in tmux_left():
                with contextlib.suppress(FileNotFoundError):
                    os.remove(path)
        self.addCleanup(stop_what_is_left)
        stand_in = "import test_ui_api; test_ui_api.a_test_with_a_hub_and_a_server()"
        run = subprocess.Popen([sys.executable, "-c", stand_in], cwd=KIT, env=dict(os.environ, TMPDIR=tmp),
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def stop():
            if run.poll() is None:
                run.kill()
                run.wait()
        self.addCleanup(stop)
        deadline, records = time.time() + 120, []
        while time.time() < deadline and run.poll() is None and not records:
            records = list(Path(tmp).glob("*/hub.db"))
            time.sleep(0.1)
        self.assertTrue(records, f"the test process started no hub (it ended with {run.poll()})")
        self.assertTrue([line for line in naming() if "hub.py" in line], "its hub is not running")
        self.assertTrue([line for line in naming() if "time.sleep(600)" in line], "its server is not running")
        if shutil.which("tmux"):
            tmux.append((records[0].parent / "tmux-socket").read_text())
            self.assertTrue([line for line in naming() if "tmux -S " + tmux[0] in line], "no tmux server runs")
            self.assertTrue(tmux_left(), "its tmux server has no socket file")
        os.kill(run.pid, signal.SIGKILL)
        run.wait()
        deadline = time.time() + 60
        while time.time() < deadline and (naming() or os.listdir(tmp) or tmux_left()):
            time.sleep(0.2)
        self.assertEqual((naming(), os.listdir(tmp), tmux_left()), ([], [], []))


class Backlog(unittest.TestCase):
    """A page of the app reads a dozen routes or more at once. With socketserver's listen backlog of 5 the rest of
    such a burst was refused, and the app read the refusal as a failed read: a false "Last reading" while the hub
    was well (29 October 2026). The hub's own server keeps 64 connections waiting."""
    setUp, tearDown, connect = OwnerAPI.setUp, OwnerAPI.tearDown, OwnerAPI.connect

    def test_twenty_connections_at_once_are_all_answered(self):
        server = hub.HubServer(("127.0.0.1", 0), hub.Handler)       # it listens, and accepts nothing yet
        server.daemon_threads = True
        port, socks, serving = server.server_port, [], False
        try:
            for _ in range(20):         # all twenty wait in the backlog before the first one is accepted
                socks.append(socket.create_connection(("127.0.0.1", port), timeout=5))
            threading.Thread(target=server.serve_forever, daemon=True).start()
            serving = True
            for s in socks:
                s.sendall(f"GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode())
            answered = [s.makefile("rb").readline() for s in socks]
            self.assertEqual([line.split(b" ")[1] for line in answered], [b"200"] * 20)
        finally:
            for s in socks:
                s.close()
            if serving:
                server.shutdown()
            server.server_close()


class ClientGone(unittest.TestCase):
    """A client that resets its connection between two requests is no error of the hub's. socketserver printed a
    traceback for each one, 630 in 30 days on the first fleet, which hid the hub's own errors in its output. An error
    of the hub's own still prints."""
    setUp, tearDown, connect = OwnerAPI.setUp, OwnerAPI.tearDown, OwnerAPI.connect

    def printed(self, act):
        """What the hub's server writes to stderr while `act(port)` runs and until every request thread has ended."""
        server = hub.HubServer(("127.0.0.1", 0), hub.Handler)
        server.daemon_threads = False       # so that server_close joins the request threads, inside the capture
        out = io.StringIO()
        with contextlib.redirect_stderr(out):
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                act(server.server_port)
            finally:
                server.shutdown()
                server.server_close()
        return out.getvalue()

    def test_a_reset_between_two_requests_prints_nothing(self):
        def reset(port):
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            try:        # the connection always ends: server_close waits for its request thread (printed)
                s.sendall(f"GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
                reader = s.makefile("rb")
                self.assertEqual(reader.readline().split(b" ")[1], b"200")
                length = 0
                for line in iter(reader.readline, b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":")[1])
                reader.read(length)         # the whole answer is read: the hub waits for the next request now
            finally:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))     # close with a reset
                s.close()
        self.assertEqual(self.printed(reset), "")

    def test_an_error_of_the_hubs_own_still_prints(self):
        """Only a connection that its client ended is left out, a reset or a broken pipe as in do_GET and do_POST:
        any other error at the same place prints, also one of the operating system's and another connection error."""
        for error in (ValueError("the hub's own"), OSError(errno.EMFILE, "Too many open files"),
                      ConnectionAbortedError(errno.ECONNABORTED, "Software caused connection abort")):
            def broken(port, error=error):
                with patch.object(hub.Handler, "handle_one_request", side_effect=error):
                    s = socket.create_connection(("127.0.0.1", port), timeout=5)
                    s.sendall(f"GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
                    with contextlib.suppress(ConnectionError):
                        self.assertEqual(s.recv(1), b"")    # the server ended the connection with no answer
                    s.close()
            with self.subTest(error=type(error).__name__):
                said = self.printed(broken)
                self.assertIn("Traceback", said)
                self.assertIn(str(error), said)


class LockedAnswers(unittest.TestCase):
    """The guard of every test whose hub OwnerAPI.setUp makes (LOCKED_SENDS, no_large_answer_under_the_lock). A class
    of its own, so that the OwnerAPI classes of other files do not run these tests again."""
    setUp, tearDown, connect, request = OwnerAPI.setUp, OwnerAPI.tearDown, OwnerAPI.connect, OwnerAPI.request

    def raw(self, path, method="GET"):
        ask = urllib.request.Request(self.base + path, method=method)
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(ask, timeout=PATIENCE) as answer:
            return answer.status, answer.read()

    def test_a_large_answer_that_goes_out_under_the_lock_is_noted(self):
        """An answer of more than LOCKED_BODY_MAX bytes that goes out while its thread holds the hub's lock is noted
        before it goes, and the check names it; the answer itself reaches the client as it was. Bytes count, not
        characters. An answer of that many bytes exactly, one that goes out while another thread holds the lock, and
        a HEAD are not noted."""
        over = {"text": "x" * (LOCKED_BODY_MAX - 11)}          # one byte more than the limit, as JSON
        exactly = json.dumps({"text": "x" * (LOCKED_BODY_MAX - 12)})
        accents = "é" * (LOCKED_BODY_MAX // 2 + 1)              # fewer characters than the limit, more bytes
        self.assertEqual((len(json.dumps(over)), len(exactly), len(accents), len(accents.encode())),
                         (LOCKED_BODY_MAX + 1, LOCKED_BODY_MAX, LOCKED_BODY_MAX // 2 + 1, LOCKED_BODY_MAX + 2))

        def inside(handler, query):
            with hub.LOCK:
                return handler.json(200, over)

        def inside_exactly(handler, query):
            with hub.LOCK:
                return handler.send(200, exactly)

        def text_inside(handler, query):
            with hub.LOCK:
                return handler.send(200, accents, "text/plain; charset=utf-8")

        def beside_another(handler, query):
            held, free = threading.Event(), threading.Event()

            def hold():
                with hub.LOCK:
                    held.set()
                    free.wait(PATIENCE)
            holder = threading.Thread(target=hold)
            holder.start()
            held.wait(PATIENCE)
            try:
                return handler.json(200, over)
            finally:
                free.set()
                holder.join()
        since = len(LOCKED_SENDS)
        for route in (beside_another, inside_exactly):
            with patch.object(hub.Handler, "ui_health", route):
                self.assertEqual(self.raw("/ui/health")[0], 200)
        with patch.object(hub.Handler, "ui_health", inside):
            self.assertEqual(self.raw("/ui/health", "HEAD"), (200, b""))
            self.assertEqual(LOCKED_SENDS[since:], [])
            self.assertEqual(self.request("/ui/health"), (200, over))
        with patch.object(hub.Handler, "ui_health", text_inside):
            self.assertEqual(self.raw("/ui/health"), (200, accents.encode()))
        self.assertEqual(LOCKED_SENDS[since:], [("GET", "/ui/health", 200, LOCKED_BODY_MAX + 1),
                                                ("GET", "/ui/health", 200, LOCKED_BODY_MAX + 2)])
        with self.assertRaisesRegex(self.failureException,
                                    r"GET /ui/health 200 \(16,385 bytes\); GET /ui/health 200 \(16,386 bytes\)"):
            no_large_answer_under_the_lock(self, since)
        self.assertEqual(LOCKED_SENDS[since:], [])      # taken by the check, so the end of this test passes

    def test_a_test_that_sends_one_fails_at_its_end(self):
        """OwnerAPI.setUp registers the check, so a test that sends a large answer under the lock fails after its
        tearDown, with the route and the size in its words, and nothing of it stays noted for the next test."""
        def inside(handler, query):
            with hub.LOCK:
                return handler.json(200, {"text": "x" * LOCKED_BODY_MAX})

        class Inside(OwnerAPI):
            def test_inside(inner):
                with patch.object(hub.Handler, "ui_health", inside):
                    inner.assertEqual(inner.request("/ui/health")[0], 200)
        db, team, since = hub.DB, hub.TEAM, len(LOCKED_SENDS)
        result = unittest.TestResult()
        try:
            Inside("test_inside").run(result)
        finally:
            hub.DB, hub.TEAM = db, team         # the inner test's own went with it
            hub._revision_cache.update(at=0.0, value=None)
        self.assertEqual((result.testsRun, result.errors, len(result.failures)), (1, [], 1))
        self.assertIn("GET /ui/health 200 (16,396 bytes)", result.failures[0][1])
        self.assertEqual(LOCKED_SENDS[since:], [])


if __name__ == "__main__":
    unittest.main()

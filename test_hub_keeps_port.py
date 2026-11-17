"""The hub keeps its port open through its own restart, and a stop ends the open requests first (hub.restart_in_place,
hub.stop_serving, hub.after_serving, hub.inherited_listener). The owner's "Yes, build both" of 16 November 2026: a
release restarted the hub with systemctl, the port was closed for about 1.5 seconds, and an agent's owner chat that
asked for its tools in that time ran 6.4 hours with none.

Real hub processes on this machine's loopback, each with a home and records of its own, and the hub's own server in
this process. No systemd, no fleet of the owner's and no AI call."""
import contextlib
import http.client
import io
import json
import os
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import Mock, patch

import hub
from leftovers import parent_pipe, scratch_home
from test_ui_api import OwnerAPI, own_files

KIT = Path(__file__).resolve().parent
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []}}}
# A hub that a test starts the way its service does, and that restarts in place one time, when the file GO is there.
# The new code that the restart runs is this same file: it sees TEST_RESTARTS at 0, and restarts no more.
WRAPPER = """
import os, sys, threading, time
sys.path.insert(0, {kit!r})
import hub

if os.environ.get("TEST_RESTARTS") == "1":
    os.environ["TEST_RESTARTS"] = "0"

    def restart():
        while hub.SERVING["server"] is None or not os.path.exists({go!r}):
            time.sleep(0.02)
        print("restart:", hub.restart_in_place(), flush=True)
    threading.Thread(target=restart, daemon=True).start()
print("start:", os.getpid(), flush=True)
sys.exit(hub.main())
"""


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def load_tests(loader, _tests, _pattern):
    """This file's own cases: not the ones that Serving inherits from OwnerAPI."""
    suite = unittest.TestSuite(Serving(name) for name in Serving.__dict__ if name.startswith("test_"))
    for cls in (Restart, Pieces):
        suite.addTests(loader.loadTestsFromTestCase(cls))
    return suite


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get(url, timeout=30):
    """(status, JSON answer, the Connection header) of one GET on a new connection."""
    req = urllib.request.Request(url, headers={"X-Fleet-Client": "deterministic-test"})
    try:
        with OPENER.open(req, timeout=timeout) as answer:
            return answer.status, json.load(answer), answer.headers.get("Connection")
    except urllib.error.HTTPError as answer:
        with answer:
            return answer.code, json.load(answer), answer.headers.get("Connection")


class Restart(unittest.TestCase):
    """A real hub process restarts in place: the same process, the same open port, and no client is refused or cut."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="fleet-keeps-port-"))
        self.addCleanup(shutil.rmtree, str(self.root), ignore_errors=True)
        (self.root / "team.json").write_text(json.dumps(TEAM))
        self.go = self.root / "go"
        wrapper = self.root / "start_hub.py"
        wrapper.write_text(WRAPPER.format(kit=str(KIT), go=str(self.go)))
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        pipe, fds = parent_pipe(self.root)
        self.lines = []
        self.proc = subprocess.Popen([sys.executable, str(wrapper), "--host", "127.0.0.1", "--port", str(self.port),
                                      "--db", str(self.root / "hub.db"), "--team", str(self.root / "team.json"),
                                      "--tick", "60", "--parent-pipe", str(pipe)],
                                     pass_fds=fds, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL, text=True,
                                     env=dict(os.environ, HOME=str(self.root), TEST_RESTARTS="1"))
        self.addCleanup(self.stop)
        threading.Thread(target=lambda: self.lines.extend(iter(self.proc.stdout.readline, "")), daemon=True).start()
        self.wait_for(lambda: self.said("Founderizer hub on") == 1, "the hub did not start")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()
        self.proc.stdout.close()

    def said(self, words):
        return sum(1 for line in list(self.lines) if words in line)

    def wait_for(self, check, failure, most=90):
        deadline = time.monotonic() + most
        while time.monotonic() < deadline:
            if check():
                return
            self.assertIsNone(self.proc.poll(), f"the hub ended: {''.join(self.lines)}")
            time.sleep(0.05)
        self.fail(f"{failure}: {''.join(self.lines)}")

    def long_wait(self):
        """A GET /ui/wait that waits 20 seconds for a change, in a thread: [(status, seconds)] when it answered, or
        [(the error's name, seconds)]."""
        db = get(self.base + "/ui/state")[1]["db"]
        token = get(f"{self.base}/ui/wait?db={db}&wait=0")[1]["token"]
        got, began = [], time.monotonic()

        def run():
            try:
                got.append((get(f"{self.base}/ui/wait?db={db}&since={token}&wait=20")[0], time.monotonic() - began))
            except OSError as e:
                got.append((type(e).__name__, time.monotonic() - began))
        threading.Thread(target=run, daemon=True).start()
        time.sleep(0.5)                 # the wait has begun
        self.assertEqual(got, [])
        return got

    def test_a_restart_in_place_keeps_the_port_and_refuses_no_connection(self):
        waiting = self.long_wait()
        answers, errors, done = [], [], threading.Event()

        def clients():                  # a new connection after the other, all through the restart
            while not done.is_set():
                try:
                    answers.append(get(self.base + "/health")[0])
                except OSError as e:
                    errors.append(repr(e))
                time.sleep(0.01)
        client = threading.Thread(target=clients, daemon=True)
        client.start()
        self.go.touch()
        self.wait_for(lambda: self.said("Founderizer hub on") == 2, "the hub did not start its new code")
        self.wait_for(lambda: get(self.base + "/health")[0] == 200, "the new code does not answer")
        time.sleep(0.3)                 # some more connections to the new code
        done.set()
        client.join(60)
        self.assertEqual(self.said("restart: True"), 1)
        self.assertEqual([line.split()[1] for line in self.lines if line.startswith("start:")],
                         [str(self.proc.pid)] * 2)          # the same process ran the code two times
        self.assertEqual(errors, [])                        # no client was refused or cut
        self.assertEqual(set(answers), {200})
        self.assertEqual(len(waiting), 1)
        self.assertEqual(waiting[0][0], 200)                # the long wait answered at the stop, and was not cut
        self.assertLess(waiting[0][1], 10)
        self.assertEqual(get(self.base + "/ui/state")[0], 200)     # the records are the same ones

        # And a stop of the service ends the open requests first, then the process, by the same signal as before.
        waiting = self.long_wait()
        self.proc.send_signal(signal.SIGTERM)
        self.assertEqual(self.proc.wait(30), -signal.SIGTERM)
        deadline = time.monotonic() + 5     # the answer went out before the end; its thread may read it a moment later
        while not waiting and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(len(waiting), 1, "the long wait did not answer before the process ended")
        self.assertEqual(waiting[0][0], 200)


class Pieces(unittest.TestCase):
    """The parts, in this process."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="fleet-keeps-port-pieces-")
        self.addCleanup(folder.cleanup)
        own_files(self, folder.name)        # a handler of a test reads no file of the machine (test_ui_api.OwnFiles)

    def tearDown(self):
        hub.STOPPING.clear()
        hub.CLOSING.clear()
        hub.SERVING.update(server=None, exec=False, exit=False)

    def listening(self):
        s = socket.socket()
        self.addCleanup(s.close)
        s.bind(("127.0.0.1", 0))
        s.listen(4)
        return s

    def closed(self, fd):
        try:
            os.fstat(fd)
        except OSError:
            return True
        return False

    def test_the_socket_that_listens_at_the_address_is_taken_once_and_leaves_the_environment(self):
        s = self.listening()
        fd = os.dup(s.fileno())
        os.set_inheritable(fd, True)
        environ = {hub.LISTEN_FD: str(fd), "OTHER": "x"}
        got = hub.inherited_listener("127.0.0.1", s.getsockname()[1], environ)
        self.addCleanup(got.close)
        self.assertEqual((got.fileno(), got.getsockname()), (fd, s.getsockname()))
        self.assertEqual(environ, {"OTHER": "x"})
        self.assertFalse(got.get_inheritable())            # no program that the hub starts gets it
        self.assertIsNone(hub.inherited_listener("127.0.0.1", s.getsockname()[1], environ))

    def test_a_socket_at_another_address_or_bound_nowhere_is_closed_and_the_hub_binds(self):
        s = self.listening()
        for host, port, sock in (("127.0.0.1", s.getsockname()[1] + 1, s), ("127.0.0.2", s.getsockname()[1], s),
                                 ("127.0.0.1", 0, socket.socket())):
            with self.subTest(host=host, port=port):
                fd = os.dup(sock.fileno())
                self.assertIsNone(hub.inherited_listener(host, port, {hub.LISTEN_FD: str(fd)}))
                self.assertTrue(self.closed(fd))
                if sock is not s:
                    sock.close()

    def test_a_name_with_no_socket_behind_it_takes_nothing_and_closes_nothing(self):
        read, write = os.pipe()
        self.addCleanup(os.close, read)
        self.addCleanup(os.close, write)
        for value in (str(read), "", "x", "-3", "99999"):
            with self.subTest(value=value):
                self.assertIsNone(hub.inherited_listener("127.0.0.1", 1, {hub.LISTEN_FD: value}))
        self.assertFalse(self.closed(read))
        self.assertIsNone(hub.inherited_listener("127.0.0.1", 1, {}))

    def test_the_new_code_reads_back_only_what_it_compiled_after_the_exec(self):
        """An exec keeps the process and its start time (process_started), so the new code takes the moment of the
        exec from the code before it, and main()'s read-back (compiled_checked) reads only the files that it wrote."""
        with patch.dict(os.environ, {hub.EXEC_AT: "1794850000.25"}):
            self.assertEqual(hub.code_started(), 1794850000.25)
            self.assertNotIn(hub.EXEC_AT, os.environ)       # no program that the hub starts gets it
            self.assertStarted(hub.code_started())
        with patch.dict(os.environ, {hub.EXEC_AT: "not a time"}):
            self.assertStarted(hub.code_started())

    def assertStarted(self, value):
        """The process's own start (process_started), which Linux gives as a time that moves by a tick between two
        reads, and other systems not at all."""
        started = hub.process_started()
        if started is None:
            self.assertIsNone(value)
        else:
            self.assertAlmostEqual(value, started, delta=0.5)

    def test_only_code_that_takes_the_socket_is_run_in_place(self):
        """A release that goes back to code from before this one would bind the port that this process holds, fail,
        and leave the hub down until systemd started it again: that code is restarted by its service, as before."""
        self.assertTrue(hub.code_keeps_port())
        older = Path(tempfile.mkdtemp(prefix="fleet-older-")) / "hub.py"
        self.addCleanup(shutil.rmtree, str(older.parent), ignore_errors=True)
        older.write_text(Path(hub.__file__).read_text().replace(hub.KEEPS_PORT.decode(), "LISTEN = None"))
        self.assertFalse(hub.code_keeps_port(str(older)))
        self.assertFalse(hub.code_keeps_port(str(older.parent / "gone.py")))

    def test_a_restart_in_place_needs_a_server_that_serves_here_and_code_that_takes_the_socket(self):
        self.assertFalse(hub.restart_in_place())            # a test's hub: no server of main() in this process
        server = Mock()
        hub.SERVING["server"] = server
        with patch.object(hub, "code_keeps_port", return_value=False):
            self.assertFalse(hub.restart_in_place())
        self.assertFalse(hub.STOPPING.is_set())
        with patch.object(hub.sys, "orig_argv", [], create=True):
            self.assertFalse(hub.restart_in_place())
        self.assertTrue(hub.restart_in_place())
        self.assertTrue(hub.STOPPING.is_set())
        self.assertEqual((hub.SERVING["exec"], hub.SERVING["exit"]), (True, False))
        for thread in threading.enumerate():
            if thread.name == "hub-stop":
                thread.join(5)
        server.shutdown.assert_called_once_with()

    def test_the_stop_signal_sets_three_values_and_takes_no_lock_and_starts_no_thread(self):
        """A handler runs in the main thread between two steps of whatever it does, and Thread.start in
        process_request holds a lock that the handler would wait for, for ever (the reviewer's point of 16 November
        2026). So the handler only sets STOPPING, the stop, and the flag that ends serve_forever."""
        server = hub.HubServer(("127.0.0.1", 0), hub.Handler)
        self.addCleanup(server.server_close)
        hub.SERVING["server"] = server
        with patch.object(hub.threading.Thread, "start", side_effect=AssertionError("a thread")), \
                patch.object(hub, "CALLS", Mock(side_effect=AssertionError("a lock"))):
            hub.on_stop_signal(signal.SIGTERM, None)
        self.assertTrue(hub.STOPPING.is_set())
        self.assertEqual((hub.SERVING["exec"], hub.SERVING["exit"]), (False, True))
        server.serve_forever(poll_interval=0.05)            # it ends at once, as for server.shutdown()

    def after(self, exec_asked, exit_asked, drained=True, stop_at_lock=False):
        """after_serving with stand-ins for what ends the process: [the steps it took]. stop_at_lock: a SIGTERM
        comes while it waits for LOCK."""
        steps = []
        server = Mock()
        server.socket.close.side_effect = lambda: steps.append("close")
        hub.SERVING.update(server=server, exec=exec_asked, exit=exit_asked)

        class Ended(Exception):
            pass

        def ended(code):
            raise Ended(code)

        def lock(timeout):
            steps.append("lock")
            if stop_at_lock:
                hub.SERVING["exit"] = True

        def quiet(fresh):
            steps.append(f"quiet {fresh}" + (" after CLOSING" if hub.CLOSING.is_set() else ""))
        with patch.object(hub, "calls_drained", side_effect=lambda: steps.append("drain") or drained), \
                patch.object(hub, "quiet_connections_end", side_effect=quiet), \
                patch.object(hub, "LOCK", Mock(acquire=Mock(side_effect=lock))), \
                patch.object(hub, "exec_again", side_effect=lambda s: steps.append("exec")), \
                patch.object(hub.signal, "signal", side_effect=lambda *a: steps.append("default")), \
                patch.object(hub.os, "kill", side_effect=lambda pid, sig: steps.append(f"kill {sig.name}")), \
                patch.object(hub.os, "_exit", side_effect=ended), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(Ended):
                hub.after_serving(server)
        hub.CLOSING.clear()
        return steps

    def test_after_the_stop_the_hub_runs_its_new_code_or_ends_by_the_signal(self):
        self.assertEqual(self.after(True, False), ["quiet False", "drain", "quiet True after CLOSING", "lock",
                                                   "default", "exec", "kill SIGTERM"])
        # a stop of the service: the port closes at once, so a client is refused now and not reset after the drain
        ends = ["close", "quiet False", "drain", "close", "quiet True after CLOSING", "lock", "close", "default",
                "kill SIGTERM"]
        self.assertEqual(self.after(False, True), ends)
        self.assertEqual(self.after(True, True), ends)      # and it wins over a restart that the release asked for
        # a stop that comes while it waits for LOCK: no exec, and the port closes then
        self.assertEqual(self.after(True, False, stop_at_lock=True),
                         ["quiet False", "drain", "quiet True after CLOSING", "lock", "close", "default",
                          "kill SIGTERM"])
        self.assertEqual(self.after(True, False, drained=False)[:4],
                         ["quiet False", "drain", "quiet True after CLOSING", "lock"])
        # the connected apps' socket takes no new request from the stop's start on
        capp = Mock()
        with patch.dict(hub.CONNECT, {"server": capp}):
            self.after(True, False)
        self.assertIs(capp._BaseServer__shutdown_request, True)

    def test_the_new_code_gets_the_socket_the_moment_and_the_children_and_is_started_as_this_one_was(self):
        s = self.listening()
        server = Mock(socket=s)
        seen = {}

        def execve(path, argv, environ):
            seen.update(path=path, argv=argv, environ=environ)
        with patch.object(hub.os, "execve", execve), patch.object(hub, "children_now", return_value=[41, 42]), \
                patch.dict(os.environ, {hub.CHILDREN: "7"}), patch.object(hub.sys, "orig_argv",
                                                                       ["python3", "-m", "hub"], create=True):
            began = time.time()
            hub.exec_again(server)
        self.assertEqual((seen["path"], seen["argv"]), (sys.executable, ["python3", "-m", "hub"]))
        self.assertEqual(seen["environ"][hub.LISTEN_FD], str(s.fileno()))
        self.assertTrue(s.get_inheritable())
        self.assertEqual(seen["environ"][hub.CHILDREN], "41,42")
        self.assertGreaterEqual(float(seen["environ"][hub.EXEC_AT]), began)
        with patch.object(hub.os, "execve", execve), patch.object(hub, "children_now", return_value=[]), \
                patch.dict(os.environ, {hub.CHILDREN: "7"}):
            hub.exec_again(server)
        self.assertNotIn(hub.CHILDREN, seen["environ"])     # no list of before goes on to a later exec

    def test_the_release_restarts_the_hub_in_place_and_its_service_only_when_it_cannot(self):
        ran = []

        def run(argv, *args, **how):
            ran.append(argv)
            return subprocess.CompletedProcess(argv, 0, "", "")

        def restart(in_place):
            ran.clear()
            with patch.object(hub, "restart_in_place", return_value=in_place) as asked:
                hub.restart_hub_soon(None, None, always=True)
                for thread in threading.enumerate():
                    if thread.name == "release-restart":
                        thread.join(5)
            return list(ran), asked.call_count
        with patch.object(hub, "RESTART_DELAY", 0), patch.object(hub.subprocess, "run", run), \
                patch.object(hub, "kv_get", return_value="c0de" * 16), patch.dict(hub.CFG, clear=False):
            hub.CFG.pop("hub_restart", None)
            self.assertEqual(restart(True), ([], 1))
            self.assertEqual(restart(False), ([hub.HUB_RESTART], 1))
            hub.CFG["hub_restart"] = ["true"]               # a fleet's own command: as before, never in place
            self.assertEqual(restart(True), ([["true"]], 0))

    def test_the_child_processes_of_the_code_before_are_waited_for_and_no_other(self):
        sleeper = os.posix_spawn("/bin/sleep", ["sleep", "0.3"], dict(os.environ))
        mine = subprocess.Popen(["/bin/sleep", "0.3"])
        with patch.object(hub, "REAP_EVERY", 0.05):
            thread = hub.reap_children({hub.CHILDREN: f"{sleeper},x,"})
            thread.join(10)
        self.assertFalse(thread.is_alive())
        with self.assertRaises(ChildProcessError):
            os.waitpid(sleeper, os.WNOHANG)             # waited for already: no zombie is left
        self.assertEqual(mine.wait(10), 0)              # a child of this code's own keeps its own wait
        self.assertIsNone(hub.reap_children({}))
        if os.path.isdir("/proc/self"):
            child = subprocess.Popen(["/bin/sleep", "5"])
            self.addCleanup(child.wait)
            self.addCleanup(child.kill)
            self.assertIn(child.pid, hub.children_now())
        else:
            self.assertEqual(hub.children_now(), [])    # no /proc: nothing is named


class Serving(OwnerAPI):
    """The hub's Handler while the hub stops, on OwnerAPI's records and team: on the test's server, which takes a
    caller's address from X-Test-Source, and on the hub's own server, which counts a connection from its accept."""

    def setUp(self):
        super().setUp()
        self.addCleanup(hub.STOPPING.clear)
        self.addCleanup(hub.CLOSING.clear)

    def serve(self):
        server = hub.HubServer(("127.0.0.1", 0), hub.Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}"

    def test_an_answer_while_the_hub_stops_ends_its_connection(self):
        """A client that keeps its connection (http.client, as Claude Code's and the apps' clients do) reads
        `Connection: close` in the answer, and sends its next request on a new connection."""
        kept = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
        self.addCleanup(kept.close)
        for stopping, said in ((False, None), (True, "close")):
            with self.subTest(stopping=stopping):
                if stopping:
                    hub.STOPPING.set()
                kept.request("GET", "/health")
                answer = kept.getresponse()
                answer.read()
                self.assertEqual((answer.status, answer.getheader("Connection")), (200, said))

    def test_the_long_waits_answer_at_once_when_the_hub_stops(self):
        base = self.base
        token = get(base + "/ui/wait?db=test-generation&wait=0")[1]["token"]
        for path in (f"/ui/wait?db=test-generation&since={token}&wait=20", "/events/manager?after=0&wait=20",
                     "/events/manager?delivery=1&after=0&wait=20"):          # the helpers' own poll
            with self.subTest(path=path):
                hub.STOPPING.clear()
                got = []
                req = urllib.request.Request(base + path, headers={"X-Fleet-Client": "deterministic-test"})
                if path.startswith("/events/"):
                    req.add_header("X-Test-Source", "127.0.0.2")
                threading.Thread(target=lambda: got.append(self.timed(req)), daemon=True).start()
                time.sleep(1)
                self.assertEqual(got, [])                   # it waits
                hub.STOPPING.set()
                with hub.CHANGES:
                    hub.CHANGES.notify_all()                # as stop_serving does
                deadline = time.monotonic() + 5
                while not got and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertEqual(got[:1], [200])

    def timed(self, req):
        with OPENER.open(req, timeout=30) as answer:
            return answer.status

    def test_a_stop_waits_for_a_request_that_is_open_and_for_a_connection_that_has_not_sent_its_request(self):
        base = self.serve()
        port = int(base.rsplit(":", 1)[1])
        hold, entered = threading.Event(), threading.Event()
        real = hub.Handler.ui_health if hasattr(hub.Handler, "ui_health") else None

        def slow(handler, *args, **kw):
            entered.set()
            hold.wait(10)
            return handler.json(200, {"ok": True})
        self.assertTrue(real, "the test needs a route to hold")
        with patch.object(hub.Handler, "ui_health", slow):
            got = []
            threading.Thread(target=lambda: got.append(get(base + "/ui/health")[0]), daemon=True).start()
            self.assertTrue(entered.wait(10))
            self.assertFalse(hub.calls_drained(0.2))        # the request is open
            hold.set()
            self.assertTrue(hub.calls_drained(5))
        quiet = socket.create_connection(("127.0.0.1", port), timeout=5)     # accepted, and no request sent yet
        self.addCleanup(quiet.close)
        time.sleep(0.3)
        self.assertFalse(hub.calls_drained(0.2))
        hub.STOPPING.set()
        quiet.sendall(f"GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
        head = quiet.makefile("rb").read()                  # its answer, then the end of the connection
        self.assertIn(b"200 OK", head.split(b"\r\n", 1)[0])
        self.assertIn(b"Connection: close", head)
        self.assertTrue(hub.calls_drained(5))

    def hold_health(self):
        """GET /ui/health waits for the event that this returns, once its request is in the route."""
        hold, entered = threading.Event(), threading.Event()

        def slow(handler, *args, **kw):
            entered.set()
            hold.wait(10)
            return handler.json(200, {"ok": True})
        p = patch.object(hub.Handler, "ui_health", slow)
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(hold.set)
        return hold, entered

    def test_a_second_request_on_a_kept_connection_counts_too(self):
        """Claude Code sends initialize and then tools/list on one kept connection: the second request counts from
        its first line, as the first one counts from the accept."""
        port = int(self.serve().rsplit(":", 1)[1])
        kept = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        self.addCleanup(kept.close)
        kept.request("GET", "/health")
        kept.getresponse().read()
        self.assertTrue(hub.calls_drained(5))               # it waits for its next request, which is no request
        hold, entered = self.hold_health()
        got = []

        def second():
            kept.request("GET", "/ui/health")
            got.append(kept.getresponse().status)
        client = threading.Thread(target=second, daemon=True)
        client.start()
        self.assertTrue(entered.wait(10))
        self.assertFalse(hub.calls_drained(0.2))
        hold.set()
        self.assertTrue(hub.calls_drained(5))
        client.join(5)                      # the answer went out; its client reads it a moment later
        self.assertEqual(got, [200])

    def test_a_silent_connection_holds_a_stop_for_its_first_second_only_and_the_stop_ends_it(self):
        """A connection that a client opens and leaves silent (a browser's) holds no stop for DRAIN_MOST: after its
        first second the drain goes on without it, and the stop ends it, so that no request begins on it later."""
        port = int(self.serve().rsplit(":", 1)[1])
        quiet = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.addCleanup(quiet.close)
        time.sleep(0.2)
        began = time.monotonic()
        self.assertTrue(hub.calls_drained(5, fresh=0.5))
        self.assertLess(time.monotonic() - began, 2)
        hub.quiet_connections_end(fresh=False)              # a fresh connection is not ended with the idle ones
        quiet.settimeout(0.3)
        with self.assertRaises(socket.timeout):
            quiet.recv(1)
        hub.quiet_connections_end(fresh=True)
        quiet.settimeout(5)
        self.assertEqual(quiet.recv(1), b"")                # the hub ended it
        self.assertTrue(hub.calls_drained(5))

    def test_a_connection_whose_thread_comes_after_the_stop_ended_the_silent_ones_ends_too(self):
        """Under load a connection that the server accepted can reach its Handler only after the stop has ended the
        silent ones (the reviewer's point of 16 November 2026): it ends there, so no request begins on it."""
        port = int(self.serve().rsplit(":", 1)[1])
        ran = []
        with patch.object(hub.Handler, "ui_health", lambda handler, query: ran.append(1)):
            hub.CLOSING.set()
            late = socket.create_connection(("127.0.0.1", port), timeout=5)
            self.addCleanup(late.close)
            late.sendall(f"GET /ui/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())    # at once
            with contextlib.suppress(ConnectionError):
                self.assertEqual(late.recv(1), b"")
            self.assertTrue(hub.calls_drained(5))
        self.assertEqual(ran, [])                           # its request never ran

    def test_a_connection_that_the_stop_ended_begins_no_request_also_with_bytes_that_wait(self):
        """Linux gives the bytes that came before a shutdown to the next read (macOS drops them), so the handler of
        a connection that the stop ended refuses the request itself, before it counts or runs it."""
        handler = hub.Handler.__new__(hub.Handler)
        handler.late, handler.in_call, handler.conn_fresh, handler.close_connection = True, False, False, False
        before = hub.CALLS_OPEN[0]
        self.assertFalse(handler.parse_request())
        self.assertEqual((handler.close_connection, handler.in_call, hub.CALLS_OPEN[0]), (True, False, before))

    def test_a_stop_ends_the_kept_connections_that_wait_for_their_next_request(self):
        """No request can then begin on a connection of the code before, also not while the stop waits for LOCK,
        where it could write and then lose its answer at the exec (the reviewer's point of 16 November 2026)."""
        port = int(self.serve().rsplit(":", 1)[1])
        kept = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.addCleanup(kept.close)
        kept.sendall(f"GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
        reader = kept.makefile("rb")
        length = 0
        self.assertIn(b"200", reader.readline())
        for line in iter(reader.readline, b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":")[1])
        reader.read(length)                                 # the whole answer: the connection waits now
        time.sleep(0.2)
        hub.quiet_connections_end(fresh=False)
        self.assertEqual(reader.read(1), b"")
        self.assertTrue(hub.calls_drained(5))

    def test_a_connection_whose_handling_fails_ends_its_counts(self):
        before = (hub.CALLS_OPEN[0], hub.CALLS_FRESH[0], len(hub.CONNECTIONS))
        port = int(self.serve().rsplit(":", 1)[1])
        with patch.object(hub.Handler, "handle_one_request", side_effect=ValueError("the hub's own")), \
                contextlib.redirect_stderr(io.StringIO()):
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(f"GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
            with contextlib.suppress(ConnectionError):
                self.assertEqual(s.recv(1), b"")
            s.close()
            deadline = time.monotonic() + 5
            while (hub.CALLS_OPEN[0], hub.CALLS_FRESH[0], len(hub.CONNECTIONS)) != before and \
                    time.monotonic() < deadline:
                time.sleep(0.05)
            time.sleep(0.3)             # the server prints the error after the count ended, still into this capture
        self.assertEqual((hub.CALLS_OPEN[0], hub.CALLS_FRESH[0], len(hub.CONNECTIONS)), before)

    def test_a_setup_that_does_not_call_the_hubs_own_still_ends_its_counts(self):
        """A test's stand-in setup that calls only the base one (test_answer_write): the request is answered, and the
        count of the accept ends, on the hub's own server and on another."""
        base = socketserver.StreamRequestHandler.setup
        for url in (self.serve(), f"http://127.0.0.1:{self.server.server_port}"):
            with self.subTest(url=url), patch.object(hub.Handler, "setup", lambda handler: base(handler)):
                before = (hub.CALLS_OPEN[0], hub.CALLS_FRESH[0])
                with urllib.request.urlopen(url + "/health", timeout=10) as answer:
                    self.assertEqual(answer.status, 200)
                deadline = time.monotonic() + 5
                while (hub.CALLS_OPEN[0], hub.CALLS_FRESH[0]) != before and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertEqual((hub.CALLS_OPEN[0], hub.CALLS_FRESH[0]), before)


if __name__ == "__main__":
    unittest.main()

"""call_api, the helper side (fleet.py): a request runs in a thread of its own, the helper sends its report again
until the hub takes it, and a pause or stop has the vault end the requests of the task attempt before it is confirmed.
The hub and its tools run in this process with a temporary Git kit, and the helper is the real code without tmux. The
vault is a stand-in on a Unix socket: it sends each request with a real curl child to a stand-in service on
127.0.0.1. No vault, no real key, no other host and no AI call."""
import contextlib
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

import fleet
import hub
import lifecycle
from test_capacity import LOGIN_A, LOGIN_B, Capacity
from leftovers import scratch_home

KEY = "seo-agent-key-".ljust(43, "k")               # the agent key of seo: the caller field of its vault requests
SERVICE_KEY = "stand-in-service-key-0123456789"     # what a saved login would hold: only curl's stdin gets it
R1, R2, R3 = (f"0d4e5f60-3333-4444-8555-66666666666{n}" for n in "123")
NO_PROOF = "The vault cannot prove that its request ended."
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real home folder (leftovers.scratch_home)


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite(ApiHelper(name) for name in ApiHelper.__dict__ if name.startswith("test_"))
    suite.addTests(loader.loadTestsFromTestCase(Reports))
    return suite


def gone(pid):
    """True when no process has this PID: the process ended and its parent took its exit status."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


class Answer(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        self.server.seen.append((self.command, self.path, self.headers.get("Authorization"), body))
        if self.path == "/hold":
            self.server.release.wait(30)
        answer = json.dumps({"path": self.path}).encode()
        with contextlib.suppress(OSError):          # the vault ended its curl child: nobody reads the answer
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(answer)))
            self.end_headers()
            self.wfile.write(answer)

    do_GET = do_POST

    def log_message(self, *args):
        pass


class Service(ThreadingHTTPServer):
    """A stand-in for the service of a saved login, on 127.0.0.1. `seen` has each request that arrived: (method,
    path, Authorization header, body). The answer to /hold waits until `release` is set."""
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Answer)
        self.seen, self.release = [], threading.Event()
        self.base = f"http://127.0.0.1:{self.server_port}"
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def close(self):
        self.release.set()
        self.shutdown()
        self.server_close()


class Vault:
    """A stand-in for the vault broker of a machine: protocol 2 on a Unix socket, one JSON line in and one out. It has
    the scheduling of the real Mac broker: each connection has its own thread, every operation except cancel waits in
    one serial queue, and a cancel is served at once. For a request it asks the hub for the job's one confirmation
    with the caller's key, then sends the request with a real curl child, which gets its header on stdin (--config -)
    and not in its arguments. For a cancel it ends and reaps the children of that task attempt before it answers.
    `scripted` has a fixed answer for an operation; None is a vault that closes without a word."""
    def __init__(self, path, hub_url=None, site=None):
        self.path, self.hub, self.site = path, hub_url, site
        self.status = {"callers": True, "requests": True}       # what its status says that it can do
        self.scripted = {}
        self.asked, self.sent, self.argv, self.pids = [], [], [], []    # request lines; jobs, arguments, PIDs of curl
        self.started, self.ended = set(), set()     # (agent, job) of each started request; scopes that a cancel ended
        self.children = []                          # [process, scope, canceled] of each curl child that runs
        self.queue, self.lock = threading.Lock(), threading.Lock()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(path)
        self.sock.listen(8)
        threading.Thread(target=self.serve, daemon=True).start()

    def close(self):
        self.sock.close()
        with self.lock:
            for child, _, _ in self.children:
                child.kill()

    def ops(self):
        return [request.get("op") for request in self.asked]

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return                  # closed
            threading.Thread(target=self.connection, args=(conn,), daemon=True).start()

    def connection(self, conn):
        with conn, conn.makefile() as lines:
            try:
                request = json.loads(lines.readline())
            except ValueError:
                return
            self.asked.append(request)
            if request.get("op") == "cancel":       # at once, also while a request runs
                reply = self.answer(request)
            else:
                with self.queue:
                    reply = self.answer(request)
            if reply is not None:
                with contextlib.suppress(OSError):  # the asker stopped waiting
                    conn.sendall((json.dumps(dict(reply, v=2)) + "\n").encode())

    def answer(self, request):
        op = request.get("op")
        if op in self.scripted:
            return self.scripted[op]
        if op == "status":
            return dict(self.status, ok=True)
        if op not in ("request", "cancel") or self.status.get("requests") is not True:
            return {"ok": False, "error": "unknown operation"}
        return self.request(request) if op == "request" else self.cancel(request)

    def confirm(self, agent, key, job):
        """The hub's one confirmation of a request job, asked with the caller's key."""
        body = json.dumps({"job": job, "kind": "request", "provenance": 1, "creation": 1}).encode()
        ask = urllib.request.Request(f"{self.hub}/helper/vault/{agent}", data=body, method="POST", headers={
            "Content-Type": "application/json", "Authorization": "Bearer " + key})
        try:
            with NO_PROXY.open(ask, timeout=10) as answer:
                return answer.status, json.load(answer)
        except urllib.error.HTTPError as answer:
            with answer:
                return answer.code, json.load(answer)

    def request(self, request):
        agent, key, job = request.get("agent"), request.get("agent_key"), request.get("job")
        if (agent, job) in self.started:            # a duplicate of a started request: not known, and never sent
            return {"ok": False, "unknown": True, "error": "The vault started this request before."}
        code, given = self.confirm(agent, key, job)
        if code != 200:                             # the hub gave no request, so nothing went out
            return {"ok": False, "error": f"The hub did not confirm this job: {given.get('error')}"}
        scope = (key, given["db"], given["task"], given["attempt"])
        config = f'header = "Authorization: Bearer {SERVICE_KEY}"\n'
        if "body" in given:
            config += 'header = "Content-Type: application/json"\ndata-binary = "%s"\n' % \
                given["body"].replace("\\", "\\\\").replace('"', '\\"')
        argv = ["curl", "--disable", "--silent", "--noproxy", "*", "--max-time", "20", "--config", "-",
                "--request", given["method"], "--write-out", "%{http_code}", self.site + given["path"]]
        with self.lock:
            self.started.add((agent, job))
            if scope in self.ended:                 # the guard: a cancel ended this task attempt before
                return {"ok": False, "unknown": True, "canceled": True, "error": "The task attempt was stopped."}
            child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
            entry = [child, scope, False]
            self.children.append(entry)
            self.sent.append(job)
            self.argv.append(argv)
            self.pids.append(child.pid)
        out, _ = child.communicate(config.encode())         # until curl ends; this also reaps it
        with self.lock:
            self.children.remove(entry)
        if entry[2]:
            return {"ok": False, "unknown": True, "canceled": True, "error": "The request was stopped. It can have "
                                                                             "reached the service."}
        if child.returncode != 0 or not out[-3:].isdigit():
            return {"ok": False, "unknown": True, "error": "The service gave no answer."}
        return {"ok": True, "job": job, "status": int(out[-3:]), "body": out[:-3].decode(), "truncated": False}

    def cancel(self, request):
        """End and reap each curl child of the task attempt. A key that did not start its requests ends nothing."""
        scope = (request.get("agent_key"), request.get("db"), request.get("task"), request.get("attempt"))
        with self.lock:
            if any(entry[1][1:] == scope[1:] and entry[1][0] != scope[0] for entry in self.children):
                return {"ok": False, "error": NO_PROOF}
            self.ended.add(scope)
            mine = [entry for entry in self.children if entry[1] == scope]
            for entry in mine:
                entry[2] = True
                entry[0].terminate()
        for entry in mine:
            entry[0].wait(10)           # until it is reaped, here or in the thread of its request
        return {"ok": True, "task": request["task"], "attempt": request["attempt"], "stopped": True, "ended": len(mine)}


def helper_without_tmux(agent):
    """A helper of this agent that has no tmux session: the session parts of control() are stand-ins that find no
    window and no process. Its request jobs, its cancel to the vault and its reports to the hub are the real code.
    `said` has its log lines."""
    helper = fleet.Helper.__new__(fleet.Helper)
    helper.agent, helper.session, helper.said = agent, f"fleet-{agent}", []
    helper.outside, helper.outside_lock, helper.requests = 0, threading.Lock(), {}
    helper.jobs_held, helper.report_waits = {}, {}         # plan C7: the jobs it holds, and their reports
    helper.say = helper.said.append
    helper.look = lambda: []
    helper.task_work = lambda *args, **kw: {}
    helper.interrupt = lambda window: (True, "no session was running")
    helper.quiesce = lambda *args, **kw: (True, 0, "")
    helper.tailer = types.SimpleNamespace(flush=lambda task: [], quiet=lambda task, seconds: True)
    return helper


def until(check, seconds=10):
    """The first true value of check() within the time; else an AssertionError."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError("it did not happen in time")


@unittest.skipUnless(shutil.which("curl"), "curl is not installed")
class ApiHelper(Capacity):
    """seo is on a machine with the vault broker, with LOGIN_A and LOGIN_B in its profile and two open tasks under
    its lead pma. The hub and its tool are real, the helper is the real code without tmux, and the vault
    and the service are the stand-ins above."""
    def setUp(self):
        super().setUp()
        hub.CFG["request_wait"] = 20
        self.addCleanup(hub.CFG.pop, "request_wait", None)
        self.dir = Path(tempfile.mkdtemp(prefix="fa-"))         # short: a Unix socket path has at most 104 bytes
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.service = Service()
        self.addCleanup(self.service.close)
        self.vault = Vault(str(self.dir / "v.sock"), self.base, self.service.base)
        self.addCleanup(self.vault.close)
        self.real_http, self.calls, self.lose, self.before = fleet.http, [], [], None
        for p in (patch.object(fleet, "HOME", str(self.dir)), patch.object(fleet, "HUB", self.base),
                  patch.object(fleet, "TEAM", {"agents": {"seo": {"vault": "broker"}}}),
                  patch.object(fleet, "vault_socket", lambda: self.vault.path),
                  patch.object(fleet.sys, "platform", "darwin"), patch.object(fleet, "http", self.http)):
            p.start()
            self.addCleanup(p.stop)
        fleet.write_private(fleet.key_file("seo"), KEY + "\n")
        hub.ins("INSERT OR REPLACE INTO agent_keys(agent,sha256,created,source) VALUES('seo',?,?,'owner')",
                (hashlib.sha256(KEY.encode()).hexdigest(), hub.now()))
        # The machine's report is the helper's own reading of its vault: with it the hub lets seo call an API.
        status = {"features": lifecycle.FEATURES, "legacy_windows": [], "security": {"vault": fleet.vault_status("seo")}}
        hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES('seo',?,?)",
              (json.dumps(hub.validate_status(status)), hub.now()))
        self.shop, self.task, self.blog, self.other = self.parents()
        self.helpers, self.threads = [], []

    def tearDown(self):
        self.service.release.set()              # nothing waits for the service any more
        try:
            for thread in self.threads:
                thread.join(30)
            for helper in self.helpers:         # each request thread sent its report, before the hub closes
                until(lambda: helper.outside == 0, 30)
        finally:
            super().tearDown()

    # ---- helpers
    def http(self, method, path, data=None, timeout=40):
        """fleet.http for the helper of a test. `calls` keeps each call. `lose` names calls that get no answer, each
        one time: [a part of the path, True] is lost before the hub, [a part of the path, False] after the hub took
        it."""
        self.calls.append((method, path, data))
        if self.before:
            self.before(path)
        lost = next((item for item in self.lose if item[0] in path), None)
        if lost:
            self.lose.remove(lost)
            if lost[1]:
                raise OSError("the hub did not get it")
        answer = self.real_http(method, path, data, timeout)
        if lost:
            raise OSError("the answer of the hub was lost")
        return answer

    def helper(self):
        helper = helper_without_tmux("seo")
        self.helpers.append(helper)
        return helper

    def api(self, request, path="/v1/orders", task=None, **changes):
        """call_api as the agent's session calls it, in a thread: the helper works while the tool waits. Returns the
        thread and the list that gets its (text, is_error)."""
        args = dict({"request_id": request, "login": LOGIN_A, "method": "POST", "path": path, "body": '{"n": 1}',
                     "auth": "bearer"}, **changes)
        answer = []
        thread = threading.Thread(target=lambda: answer.append(self.call("seo", "call_api", args, task or self.task)))
        thread.start()
        self.threads.append(thread)
        return thread, answer

    def job(self, request):
        return hub.q1("SELECT * FROM jobs WHERE agent='seo' AND request_id=?", (request,))

    def emitted(self, request):
        """The job of this request, when the hub has its event for the helper: the tool saves the job first, and
        emits the event a moment later."""
        job = until(lambda: self.job(request))["id"]
        until(lambda: any(json.loads(event["extra"]) == {"job": job} for event in
                          hub.q("SELECT extra FROM events WHERE agent='seo' AND kind='request'")))
        return job

    def deliver(self, helper, kind):
        """Give the helper the events of this kind that the hub has for seo now, as its loop does. Returns them."""
        code, data = self.real_http("GET", "/events/seo?delivery=1&after=0&wait=0")
        self.assertEqual(code, 200, data)
        events = [event for event in data["events"] if event["kind"] == kind]
        for event in events:
            helper.handle(event)
        return events

    def held(self, helper, request=R1, task=None, **changes):
        """A request that waits for the answer of the service: (the tool's thread, its answer list, the job, the PID
        of the vault's curl child)."""
        before = len(self.service.seen)
        thread, answer = self.api(request, "/hold", task, **changes)
        job = self.emitted(request)
        self.assertEqual([event["extra"] for event in self.deliver(helper, "request")], [{"job": job}])
        until(lambda: len(self.service.seen) > before)
        return thread, answer, job, self.vault.pids[-1]

    def lost(self, job):
        """What a helper process that ended had asked its vault for. Nobody reports the answer."""
        with contextlib.suppress(fleet.Refused):
            fleet.do_request("seo", job)

    def stop(self, task=None, kind="stop"):
        """The owner's pause or stop: (the hold, the `extra` of its control event)."""
        hold, changed = hub.request_hold(task or self.task, kind, "owner", "")
        self.assertTrue(changed)
        event = hub.q1("SELECT * FROM events WHERE agent='seo' AND kind='control' ORDER BY id DESC LIMIT 1")
        return hold, json.loads(event["extra"])

    def hold(self, hold):
        return hub.q1("SELECT * FROM holds WHERE id=?", (hold["id"],))

    def outcomes(self, task=None):
        return [dict(row) for row in hub.q("SELECT * FROM outcomes WHERE task=? ORDER BY id", (task or self.task,))]

    # ---- the request
    def test_a_request_runs_in_its_own_thread_and_other_events_are_served_meanwhile(self):
        self.assertEqual((fleet.vault_status("seo")["requests"], "api_request" in lifecycle.FEATURES), (True, True))
        helper = self.helper()
        waiting, answer, job, pid = self.held(helper)       # handle() came back while the service holds its answer
        ref = f"T-{self.task}"
        self.assertEqual((helper.requests, helper.outside, self.job(R1)["finished"]), ({job: ref}, 1, None))
        self.assertIn(f"request-{job}", [thread.name for thread in threading.enumerate()])
        event = hub.q1("SELECT * FROM events WHERE agent='seo' AND kind='request'")
        self.assertIsNotNone(event["helper_ack"])           # taken: the hub does not give it again
        # The same event again (its acknowledgement was lost): the job runs, so the vault is not asked again.
        helper.handle({"id": event["id"], "kind": "request", "task": ref, "extra": {"job": job}})
        self.assertEqual((self.vault.ops().count("request"), helper.outside), (1, 1))
        # Another event is served while the request waits: a pause of seo's other task, which has no request.
        hold, extra = self.stop(self.other, "pause")
        self.assertEqual(extra["requests"], 0)
        self.deliver(helper, "control")
        self.assertEqual((self.hold(hold)["state"], self.hold(hold)["detail"]), ("stopped", "no session was running"))
        self.assertEqual((self.vault.ops().count("cancel"), gone(pid), waiting.is_alive()), (0, False, True))
        self.service.release.set()
        waiting.join(10)
        self.assertEqual(answer, [('HTTP 200.\n{"path": "/hold"}', False)])
        until(lambda: helper.outside == 0)
        self.assertEqual((helper.requests, helper.said[-1]), ({}, f"{ref}: request job {job}: HTTP 200"))
        # The service got the request once, with the key that only curl's stdin had.
        self.assertEqual(self.service.seen, [("POST", "/hold", "Bearer " + SERVICE_KEY, '{"n": 1}')])
        self.assertEqual(self.vault.asked[-1], {"v": 2, "op": "request", "job": job, "agent": "seo", "agent_key": KEY})
        self.assertNotIn(SERVICE_KEY, " ".join(self.vault.argv[0]))
        self.assertIn("--config -", " ".join(self.vault.argv[0]))
        for text in (json.dumps(helper.said), json.dumps([dict(row) for row in hub.q("SELECT * FROM jobs")])):
            self.assertNotIn(SERVICE_KEY, text)
        self.assertNotIn("path", json.dumps(helper.said))   # no body of the answer in the helper's log

    def test_a_report_that_the_hub_did_not_take_goes_again_and_nothing_is_sent_twice(self):
        helper = self.helper()
        for request, before_hub in ((R1, True), (R2, False)):
            self.lose.append(["/helper/job/", before_hub])
            thread, answer = self.api(request)
            job = self.emitted(request)
            self.assertEqual([event["extra"] for event in self.deliver(helper, "request")], [{"job": job}])
            thread.join(15)
            self.assertEqual(answer, [('HTTP 200.\n{"path": "/v1/orders"}', False)])
            until(lambda: helper.outside == 0)
            reports = [data for _, path, data in self.calls if path == f"/helper/job/seo/{job}"]
            self.assertEqual(reports, [{"ok": True, "status": 200, "text": "HTTP 200",
                                        "body": '{"path": "/v1/orders"}'}] * 2)
            self.assertEqual(helper.said[-1], f"T-{self.task}: request job {job}: HTTP 200")    # a 409 is taken too
            self.assertEqual((self.vault.sent.count(job), [r["job"] for r in self.vault.asked if r["op"] == "request"]
                              .count(job)), (1, 1))
        self.assertEqual([path for _, path, _, _ in self.service.seen], ["/v1/orders"] * 2)       # one for each request
        self.assertEqual(self.outcomes(), [])

    # ---- pause and stop
    def test_a_stop_has_the_vault_end_the_requests_of_that_task_attempt(self):
        helper = self.helper()
        waiting, answer, job, pid = self.held(helper)
        hold, extra = self.stop()
        self.assertEqual(extra, {"hold": hold["id"], "action": "stop", "attempt": 1, "generation": "test-generation",
                                 "requests": 1})
        asked = len(self.vault.asked)
        self.assertEqual(helper.end_requests(f"T-{self.task}", extra), (True, 1))
        self.assertEqual(self.vault.asked[asked:], [{"v": 2, "op": "cancel", "db": "test-generation",       # no status first
                                                     "task": f"T-{self.task}", "attempt": 1, "agent": "seo",
                                                     "agent_key": KEY}])
        self.assertTrue(gone(pid))                          # the vault answered after its child was gone
        waiting.join(10)
        self.assertTrue(answer[0][1] and answer[0][0].startswith(hub.REQUEST_UNKNOWN), answer)
        until(lambda: helper.outside == 0)
        self.assertEqual(helper.said, [f"T-{self.task}: request job {job}: outcome not known"])
        self.assertEqual((len(self.service.seen), self.vault.sent), (1, [job]))
        # Nothing of the task runs now: the next cancel has nothing to end, and that is proof too.
        self.assertEqual(helper.end_requests(f"T-{self.task}", extra), (True, 0))

    def test_a_status_question_that_waits_behind_the_request_does_not_hold_the_stop(self):
        helper = self.helper()
        waiting, answer, job, pid = self.held(helper)
        status = []
        asking = threading.Thread(target=lambda: status.append(fleet.broker_status(timeout=20)))
        asking.start()
        self.threads.append(asking)
        until(lambda: self.vault.ops()[-1] == "status")     # the vault has the question, behind the request that runs
        asking.join(0.5)
        self.assertEqual((asking.is_alive(), status, gone(pid)), (True, [], False))
        hold, _ = self.stop()
        self.deliver(helper, "control")
        self.assertEqual((gone(pid), self.hold(hold)["state"], self.hold(hold)["detail"]),
                         (True, "stopped", "no session was running; the vault ended 1 request(s)"))
        asking.join(10)
        self.assertEqual((status[0]["requests"], len(self.service.seen)), (True, 1))     # answered after the request

    def test_without_the_vaults_proof_the_stop_is_not_confirmed(self):
        helper = self.helper()
        waiting, answer, job, pid = self.held(helper)
        # The agent's key changed while the request ran: the vault ends the requests of a scope only for their key.
        os.remove(fleet.key_file("seo"))
        fleet.write_private(fleet.key_file("seo"), "seo-newer-key-".ljust(43, "n") + "\n")
        hold, extra = self.stop()
        self.deliver(helper, "control")
        self.assertEqual(self.vault.asked[-1]["agent_key"], "seo-newer-key-".ljust(43, "n"))
        self.assertEqual((self.hold(hold)["state"], self.hold(hold)["detail"]),
                         ("not_confirmed", "the vault did not prove that its request of the task ended"))
        self.assertEqual((gone(pid), waiting.is_alive(), self.outcomes()), (False, True, []))
        self.assertIn("stop NOT confirmed", helper.said[-1])
        # The owner sends Stop again, and the vault gets the key that started the request: now it is proof.
        os.remove(fleet.key_file("seo"))
        fleet.write_private(fleet.key_file("seo"), KEY + "\n")
        again, extra = self.stop()
        self.assertEqual((again["id"], extra["requests"]), (hold["id"], 1))
        self.deliver(helper, "control")
        self.assertEqual((self.hold(hold)["state"], gone(pid), len(self.service.seen)), ("stopped", True, 1))

    def test_a_request_of_another_task_goes_on(self):
        helper = self.helper()
        waiting, answer, job, pid = self.held(helper)       # in its first task
        # seo's other task has a request that the vault did not start yet: the hub counts it.
        queued, late = self.api(R2, "/v1/orders", self.other, login=LOGIN_B)
        until(lambda: self.job(R2))
        hold, extra = self.stop(self.other)
        self.assertEqual(extra["requests"], 1)
        self.assertEqual(helper.end_requests(f"T-{self.other}", extra), (True, 0))
        self.assertEqual((self.vault.asked[-1]["op"], self.vault.asked[-1]["task"]), ("cancel", f"T-{self.other}"))
        self.assertEqual((gone(pid), waiting.is_alive(), len(self.service.seen)), (False, True, 1))
        self.deliver(helper, "control")
        self.assertEqual(self.hold(hold)["state"], "stopped")
        queued.join(10)
        self.assertEqual(late, [("The request was not sent: the task was stopped first.", True)])
        self.service.release.set()
        waiting.join(10)
        self.assertEqual(answer, [('HTTP 200.\n{"path": "/hold"}', False)])
        self.assertEqual((self.vault.sent, len(self.service.seen)), ([job], 1))

    def test_a_helper_that_started_again_ends_the_request_that_the_hub_counts(self):
        # The helper that asked the vault is gone: its thread ends here without a report, as its process did.
        waiting, answer = self.api(R1, "/hold")
        job = until(lambda: self.job(R1))["id"]
        old = threading.Thread(target=self.lost, args=(job,))
        old.start()
        self.threads.append(old)
        until(lambda: self.service.seen)
        pid = self.vault.pids[-1]
        helper = self.helper()                              # the new process: it has no request in a thread
        hold, extra = self.stop()
        self.assertEqual((helper.requests, extra["requests"]), ({}, 1))
        # While the vault does not answer, the hub's count is a request that can run: no proof.
        self.vault.scripted["cancel"] = None
        self.assertEqual(helper.end_requests(f"T-{self.task}", extra), (False, 0))
        self.assertFalse(gone(pid))
        del self.vault.scripted["cancel"]
        self.deliver(helper, "control")
        self.assertEqual((gone(pid), self.hold(hold)["state"]), (True, "stopped"))
        waiting.join(10)
        self.assertTrue(answer[0][1] and answer[0][0].startswith(hub.REQUEST_UNKNOWN), answer)
        row = self.job(R1)
        self.assertEqual((row["finished"], bool(row["unknown"]), row["result"]),
                         (None, True, "the task was stopped while the request ran."))
        (outcome,) = self.outcomes()                        # only the stop found the request: the outcome has its hold
        self.assertEqual((outcome["state"], outcome["hold"], outcome["tool_call_id"]),
                         ("unknown", hold["id"], f"request-{R1}"))
        self.assertEqual(len(self.service.seen), 1)

    def test_a_task_without_a_request_asks_the_vault_for_nothing(self):
        helper = self.helper()
        hold, extra = self.stop()
        self.assertEqual(extra["requests"], 0)
        self.vault.scripted["cancel"] = {"ok": False, "error": NO_PROOF}        # it would refuse
        asked = len(self.vault.asked)
        self.deliver(helper, "control")
        self.assertEqual((self.hold(hold)["state"], self.vault.asked[asked:]), ("stopped", []))

    # ---- the whole way
    def test_a_stop_cuts_a_request_and_the_new_attempt_sends_only_a_new_one(self):
        helper = self.helper()
        ref = f"T-{self.task}"
        # 1. The service holds its answer when the owner stops the task.
        waiting, answer, job, pid = self.held(helper)
        hold, _ = self.stop()
        at_result = []          # at the helper's result of the stop: is the curl child gone, and what the hub has
        self.before = lambda path: path == "/helper/control/seo" and at_result.append((gone(pid), self.hold(hold)["state"]))
        self.deliver(helper, "control")
        self.assertEqual(at_result, [(True, "requested")])  # the child was gone before the hub confirmed the stop
        self.assertEqual((self.hold(hold)["state"], self.hold(hold)["detail"]),
                         ("stopped", "no session was running; the vault ended 1 request(s)"))
        waiting.join(10)
        self.assertTrue(answer[0][1] and answer[0][0].startswith(hub.REQUEST_UNKNOWN), answer)
        until(lambda: helper.outside == 0)
        row = self.job(R1)
        self.assertEqual((row["finished"], bool(row["unknown"]), bool(row["released"])), (None, True, True))
        # One unknown outcome for the request, with this stop as its hold: also when the helper's own report of the
        # cut request reaches the hub a moment before the result of the stop.
        (outcome,) = self.outcomes()
        self.assertEqual((outcome["state"], outcome["hold"], outcome["tool_call_id"]),
                         ("unknown", hold["id"], f"request-{R1}"))
        self.assertEqual([path for _, path, _, _ in self.service.seen], ["/hold"])
        # 2. Resume makes a new attempt. The request belongs to the old one: nothing is asked and nothing is sent.
        hub.release_hold(self.task, "check", "owner")
        self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (self.task,))["attempt"], 2)
        again, answer = self.api(R1, "/hold")
        again.join(10)
        self.assertEqual(answer, [(hub.REQUEST_OLD_ATTEMPT, True)])
        self.assertEqual((self.deliver(helper, "request"), self.vault.ops().count("request")), ([], 1))
        self.assertEqual(len([e for e in hub.q("SELECT * FROM events WHERE agent='seo' AND kind='request'")
                              if json.loads(e["extra"]) == {"job": job}]), 1)
        self.assertEqual(len(self.service.seen), 1)
        text, error = self.call("seo", "resolve_outcome", {"outcome_id": f"O-{outcome['id']}", "finding": "not_done",
                                                           "evidence": "GET /v1/orders shows no new order"}, self.task)
        self.assertFalse(error, text)
        # 3. A new request in the new attempt. The helper's first report gets no answer of the hub; the same report
        # goes again, and the hub keeps it.
        self.lose.append(["/helper/job/", True])
        new, answer = self.api(R2)
        second = self.emitted(R2)
        self.assertEqual([event["extra"] for event in self.deliver(helper, "request")], [{"job": second}])
        new.join(15)
        self.assertEqual(answer, [('HTTP 200.\n{"path": "/v1/orders"}', False)])
        until(lambda: helper.outside == 0)
        reports = [data for _, path, data in self.calls if path == f"/helper/job/seo/{second}"]
        self.assertEqual(reports, [{"ok": True, "status": 200, "text": "HTTP 200", "body": '{"path": "/v1/orders"}'}] * 2)
        same, answer = self.api(R2)                         # the same call again: the hub's stored answer
        same.join(10)
        self.assertEqual(answer, [('HTTP 200.\n{"path": "/v1/orders"}', False)])
        self.assertEqual(self.deliver(helper, "request"), [])
        self.assertEqual([path for _, path, _, _ in self.service.seen], ["/hold", "/v1/orders"])
        self.assertEqual((self.vault.sent, [r["job"] for r in self.vault.asked if r["op"] == "request"]),
                         ([job, second], [job, second]))
        self.assertEqual((self.job(R2)["attempt"], [o["state"] for o in self.outcomes()]), (2, ["not_done"]))
        # The line of the cut request and the line of the stop come from two threads: either one can be first.
        self.assertEqual((sorted(helper.said[:2]), helper.said[2:]),
                         ([f"{ref}: request job {job}: outcome not known",
                           f"{ref}: stop confirmed: no session was running; the vault ended 1 request(s)"],
                          [f"{ref}: request job {second}: HTTP 200"]))


class Reports(unittest.TestCase):
    """fleet.py alone: what the helper makes of each answer of its vault, and what it asks. A vault with fixed
    answers, and no hub: the reports are kept here."""
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="fa-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.vault = Vault(str(self.dir / "v.sock"))
        self.addCleanup(self.vault.close)
        self.posted = []
        for p in (patch.object(fleet, "HOME", str(self.dir)), patch.object(fleet, "vault_socket", lambda: self.vault.path),
                  patch.object(fleet, "TEAM", {"agents": {"seo": {"vault": "broker"}, "filey": {}}}),
                  patch.object(fleet.sys, "platform", "darwin"),
                  patch.object(fleet, "http", lambda *args, **kw: self.posted.append(args) or (200, {}))):
            p.start()
            self.addCleanup(p.stop)
        fleet.write_private(fleet.key_file("seo"), KEY + "\n")
        self.helper = helper_without_tmux("seo")

    def report(self, answer="vault", agent="seo"):
        """The helper's report of request job 7 when its vault gives this answer, through the helper's own thread."""
        if answer != "vault":
            self.vault.scripted["request"] = answer
        self.posted.clear()
        self.helper.agent = agent
        self.helper.request_job("T-3", {"job": 7})
        until(lambda: self.helper.outside == 0 and self.posted)
        self.assertEqual([call[:2] for call in self.posted], [("POST", f"/helper/job/{agent}/7")])
        return self.posted[0][2]

    def test_the_vaults_answer_becomes_the_report(self):
        done = {"ok": True, "status": 200, "text": "HTTP 200"}
        big = "x" * 70000 + "é" * 30000                     # an answer line of more than 64 KiB
        for answer, report in (
                ({"ok": True, "v": 2, "job": 7, "status": 200, "body": '{"id": 7}', "truncated": False},
                 dict(done, body='{"id": 7}')),
                ({"ok": True, "v": 2, "job": 7, "status": 206, "body": "part", "truncated": True},
                 {"ok": True, "status": 206, "text": "HTTP 206", "body": "part", "truncated": True}),
                ({"ok": True, "v": 2, "job": 7, "status": 200, "withheld": "key"}, dict(done, withheld="key")),
                ({"ok": True, "v": 2, "job": 7, "status": 200, "withheld": "binary", "body": "no"},
                 dict(done, withheld="binary")),
                ({"ok": True, "v": 2, "job": 7, "status": 204}, {"ok": True, "status": 204, "text": "HTTP 204"}),
                ({"ok": True, "v": 2, "job": 7, "status": 200, "body": "", "withheld": "other"}, dict(done, body="")),
                ({"ok": True, "v": 2, "job": 7, "status": 200, "body": big, "truncated": False}, dict(done, body=big))):
            self.assertEqual(self.report(answer), report, str(answer)[:120])
            self.assertEqual(self.helper.said[-1], f"T-3: request job 7: HTTP {report['status']}")
        self.assertEqual(self.vault.asked[-3:], [{"v": 2, "op": "status"}] * 2 + [
            {"v": 2, "op": "request", "job": 7, "agent": "seo", "agent_key": KEY}])      # a job number, and the caller
        self.assertEqual(len(self.helper.said), 7)          # one line for each: no key and no body in the helper's log

    def test_only_the_vaults_refusal_says_that_nothing_went_out(self):
        unknown = lambda text: {"ok": False, "unknown": True, "text": text}
        no_status = unknown("the vault gave no status for the request")
        unclear = unknown("this machine's vault broker gave no clear answer for the request")
        for answer, report in (
                # The vault's own word that nothing went out.
                ({"ok": False, "v": 2, "error": "No connection to the service was made."},
                 {"ok": False, "text": "the vault broker refused: No connection to the service was made."}),
                # Its word that the request can have gone out, also when a pause or stop ended it.
                ({"ok": False, "v": 2, "unknown": True, "error": "The service did not answer in time."},
                 unknown("the vault could not confirm the outcome: The service did not answer in time.")),
                ({"ok": False, "v": 2, "unknown": True, "canceled": True, "error": "The request was stopped."},
                 unknown("the vault could not confirm the outcome: The request was stopped.")),
                # No word at all, or one that is no answer of protocol 2: nothing is proved.
                (None, unknown("this machine's vault broker gave no answer for the request")),
                ([], unclear), ({}, unclear), ({"ok": None, "error": "?"}, unclear), ({"ok": "false"}, unclear),
                # An answer without the job or without a status of a service is no answer.
                ({"ok": True, "v": 2, "job": 8, "status": 200, "body": "x"}, no_status),
                ({"ok": True, "v": 2, "status": 200}, no_status), ({"ok": True, "v": 2, "job": 7}, no_status),
                ({"ok": True, "v": 2, "job": 7, "status": "200"}, no_status),
                ({"ok": True, "v": 2, "job": 7, "status": True}, no_status),
                ({"ok": True, "v": 2, "job": 7, "status": 99}, no_status),
                ({"ok": True, "v": 2, "job": 7, "status": 600}, no_status)):
            self.assertEqual(self.report(answer), report, answer)
            self.assertEqual(self.helper.said[-1], "T-3: request job 7: " +
                             ("outcome not known" if report.get("unknown") else "not sent"))
        with patch.object(fleet, "REPLY_LIMIT", 100000):    # an answer that is larger than the helper reads
            self.assertEqual(self.report({"ok": True, "v": 2, "job": 7, "status": 200, "body": "x" * 300000}),
                             unknown("this machine's vault broker gave no answer for the request"))
        with patch.object(fleet, "do_request", side_effect=RuntimeError("detail")):         # an error of the helper itself
            self.assertEqual(self.report(), unknown("the helper hit an error (RuntimeError). Ask your requester."))

    def test_a_machine_that_cannot_send_a_request_asks_its_vault_for_nothing(self):
        self.vault.scripted["request"] = {"ok": True, "v": 2, "job": 7, "status": 200, "body": "sent"}
        cannot = {"ok": False, "text": "this machine's vault cannot send an API request"}
        self.assertEqual(self.report(agent="filey"), {"ok": False, "text": "an API request is sent only by this machine's "
                                                      "vault broker, and this agent has no broker access"})
        self.assertEqual(self.vault.asked, [])              # no broker access: not even its status
        for status in ({"callers": True}, {"callers": True, "requests": False}, {"callers": False, "requests": True},
                       {"callers": True, "requests": "yes"}):
            self.vault.status = status
            self.vault.asked.clear()
            self.assertEqual(self.report(), cannot, status)
            self.assertEqual(self.vault.ops(), ["status"], status)
            self.assertIs(fleet.vault_status("seo")["requests"], status.get("requests") is True)
        self.vault.status = {"callers": True, "requests": True}
        self.vault.scripted["status"] = None                # a vault that gives no status
        self.vault.asked.clear()
        self.assertEqual((self.report(), self.vault.ops()), (cannot, ["status"]))
        self.assertIsNone(fleet.vault_status("seo")["requests"])
        del self.vault.scripted["status"]
        os.remove(fleet.key_file("seo"))                    # no agent key: no caller fields, so no request
        self.vault.asked.clear()
        self.assertEqual((self.report(), self.vault.ops()), (cannot, ["status"]))
        fleet.write_private(fleet.key_file("seo"), KEY + "\n")
        for job in (None, 0, True, "7"):                    # only a job number of the hub goes to the vault
            self.vault.asked.clear()
            self.posted.clear()
            self.helper.request_job("T-3", {"job": job})
            until(lambda: self.helper.outside == 0 and self.posted)
            self.assertEqual((self.posted[0][2].get("unknown"), self.posted[0][2]["ok"], self.vault.ops()),
                             (None, False, ["status"]), job)
        self.vault.close()                                  # no vault on this machine
        os.remove(self.vault.path)
        self.assertEqual(self.report(), cannot)
        self.assertEqual(self.helper.said[-1], "T-3: request job 7: not sent")

    def test_the_same_report_goes_again_until_the_hub_takes_it(self):
        report = {"ok": True, "status": 200, "text": "HTTP 200", "body": "made"}
        cut = http.client.IncompleteRead(b"")               # the hub's answer ended early
        # Plan C7: for as long as the helper runs, with a pause doubled up to a minute; only a hub that refuses the
        # report itself (a 4xx) ends it, and then the hub settles the job as unknown.
        for answers, took in (([(200, {})], True), ([OSError("no hub"), (200, {})], True), ([cut, (409, {})], True),
                              ([(500, {}), urllib.error.URLError("no hub"), (503, {}), (200, {})], True),
                              ([OSError("no hub")] * 7 + [(200, {})], True), ([(413, {})], False)):
            with patch.object(fleet, "http", side_effect=list(answers)) as post, patch.object(fleet.time, "sleep") as sleep:
                self.assertEqual(self.helper.post_job(7, report), took, answers)
            self.assertEqual(post.call_args_list, [unittest.mock.call("POST", "/helper/job/seo/7", report, timeout=15)]
                             * len(answers), answers)       # the same report each time, and the vault is not asked
            self.assertEqual([call.args[0] for call in sleep.call_args_list],
                             [2, 4, 8, 16, 32, 60, 60][:len(answers) - 1])
            self.assertEqual(self.helper.jobs_held, {})
        self.assertEqual(self.vault.asked, [])
        with patch.object(fleet, "do_request", return_value=report), patch.object(fleet.time, "sleep"), \
                patch.object(fleet, "http", side_effect=[OSError("no hub")] * 3 + [(413, {})]):
            self.helper.request_thread("T-3", 7)
        self.assertEqual(self.helper.said, ["T-3: request job 7: HTTP 200; the hub took no report"])

    def test_only_a_known_request_needs_the_vault_and_only_its_answer_is_proof(self):
        extra = {"hold": 4, "action": "stop", "attempt": 2, "generation": "g1", "requests": 0}
        counted = dict(extra, requests=1)
        cancel = {"v": 2, "op": "cancel", "db": "g1", "task": "T-7", "attempt": 2, "agent": "seo", "agent_key": KEY}
        proof = {"ok": True, "v": 2, "task": "T-7", "attempt": 2, "stopped": True, "ended": 1}
        self.vault.scripted["cancel"] = proof
        # No request of the task is known: there is nothing to end, and the vault is not asked.
        self.helper.requests = {9: "T-8"}                   # a request of another task
        self.assertEqual((self.helper.end_requests("T-7", extra), self.vault.asked), ((True, 0), []))
        # A request in a thread of this helper, or one that only the hub counts (the helper started again).
        for requests, event in (({9: "T-7"}, extra), ({}, counted), ({9: "T-7"}, counted)):
            self.helper.requests = requests
            self.vault.asked.clear()
            self.assertEqual(self.helper.end_requests("T-7", event), (True, 1))
            self.assertEqual(self.vault.asked, [cancel])    # the scope and the caller; no status question before it
        # Every other answer is no proof.
        for answer in ({"ok": False, "v": 2, "error": NO_PROOF}, {"ok": False, "v": 2, "error": "unknown operation"},
                       {"ok": False, "v": 2, "unknown": True, "error": "?"}, None, [], {},
                       dict(proof, stopped=False), dict(proof, stopped="yes"),
                       {k: v for k, v in proof.items() if k != "stopped"},
                       dict(proof, task="T-8"), dict(proof, attempt=1), dict(proof, attempt="2")):
            self.vault.scripted["cancel"] = answer
            for requests, event in (({9: "T-7"}, extra), ({}, counted)):
                self.helper.requests = requests
                self.assertEqual(self.helper.end_requests("T-7", event), (False, 0), answer)
            self.helper.requests = {}
            self.assertEqual(self.helper.end_requests("T-7", extra), (True, 0), answer)
        self.vault.scripted["cancel"] = dict(proof, ended=0)        # no child ran: the vault's answer is still proof
        self.assertEqual(self.helper.end_requests("T-7", counted), (True, 0))
        # A vault that sends no requests has no cancel. Its status is no proof for a request that is known.
        del self.vault.scripted["cancel"]
        self.vault.status = {"callers": True}
        for requests, event, result in (({9: "T-7"}, extra, (False, 0)), ({}, counted, (False, 0)), ({}, extra, (True, 0))):
            self.helper.requests = requests
            self.vault.asked.clear()
            self.assertEqual(self.helper.end_requests("T-7", event), result)
            self.assertEqual(self.vault.ops(), ["cancel"] if requests or event["requests"] else [])
        # No agent key, no broker access or no vault: the helper cannot ask, so a known request has no proof.
        both = lambda: (self.helper.end_requests("T-7", counted), self.helper.end_requests("T-7", extra))
        self.vault.status = {"callers": True, "requests": True}
        self.vault.scripted["cancel"] = proof
        self.vault.asked.clear()
        os.remove(fleet.key_file("seo"))
        self.assertEqual(both(), ((False, 0), (True, 0)))
        fleet.write_private(fleet.key_file("seo"), KEY + "\n")
        self.helper.agent = "filey"
        fleet.write_private(fleet.key_file("filey"), KEY + "\n")
        self.assertEqual(both(), ((False, 0), (True, 0)))
        self.assertEqual(self.vault.asked, [])
        self.helper.agent = "seo"
        self.vault.close()
        os.remove(self.vault.path)
        self.assertEqual(both(), ((False, 0), (True, 0)))

    def test_control_reports_a_stop_without_proof_as_not_confirmed(self):
        extra = {"hold": 4, "action": "stop", "attempt": 2, "generation": "g1", "requests": 1}
        for answer, confirmed, detail in (
                ({"ok": True, "v": 2, "task": "T-7", "attempt": 2, "stopped": True, "ended": 2}, True,
                 "no session was running; the vault ended 2 request(s)"),
                ({"ok": True, "v": 2, "task": "T-7", "attempt": 2, "stopped": True, "ended": 0}, True,
                 "no session was running"),
                ({"ok": False, "v": 2, "error": NO_PROOF}, False,
                 "the vault did not prove that its request of the task ended")):
            self.vault.scripted["cancel"] = answer
            self.posted.clear()
            self.helper.control("T-7", extra)
            self.assertEqual(self.posted, [("POST", "/helper/control/seo", {
                "hold": 4, "confirmed": confirmed, "detail": detail, "flushed": [], "ran": False, "ended": 0})])
            self.assertEqual(self.helper.said[-1], f"T-7: stop {'confirmed' if confirmed else 'NOT confirmed'}: {detail}")


if __name__ == "__main__":
    unittest.main()

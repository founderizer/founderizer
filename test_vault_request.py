"""call_api on a Linux worker: the broker sends one HTTP request for a confirmed job with the key of a saved login,
keeps the identity of each request that it started, and a cancel ends the requests of one task attempt. The real
broker on a socket with the fleet's own store, the real hub routes, a real curl program and a local service on
127.0.0.1; age is the stand-in of test_vault.py. No other host, no account, no real token and no real key."""
import base64
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import stat
import subprocess
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
import uuid

import hub
import vault
from test_vault import LOGIN, REF, SECRET_ID, VPS_KEY, VaultBroker, lock

CURL = shutil.which("curl")
KEY, OTHER_KEY = "vps-agent-key-".ljust(43, "k"), "another-key-".ljust(43, "w")
NOT_CONFIRMED = "The hub did not confirm this vault job."
NOT_REACHED = "The service could not be reached. Nothing was sent."
NOT_KNOWN = "The request may have been sent. Its answer is not known. It is not sent again."
STARTED_BEFORE = "This request was already started. It is not sent again."
STOPPED = "This task's requests were stopped. Nothing was sent."
NO_PROOF = "The vault cannot prove that its request ended."


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(BrokerRequests(name) for name in BrokerRequests.__dict__ if name.startswith("test_"))


class Answer(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def answer(self):
        service = self.server
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        service.seen.append({"method": self.command, "path": self.path, "headers": self.headers, "body": body})
        service.arrived.set()
        if service.interim:
            self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        service.go.wait(60)                     # a test can hold the answer
        self.send_response(service.status)
        for name, value in service.headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(service.declared or len(service.body)))
        self.end_headers()
        self.wfile.write(service.body)
        self.wfile.flush()
        if service.declared:
            service.rest.wait(60)               # the rest of the body never comes

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = answer


class Service(ThreadingHTTPServer):
    """A stand-in for a service, on 127.0.0.1: it counts the requests, keeps what each one had, and can hold its
    answer. declared: a Content-Length that is more than the body that it sends."""
    def __init__(self):
        super().__init__(("127.0.0.1", 0), Answer)
        self.seen, self.status, self.headers, self.body, self.declared, self.interim = [], 200, [], b'{"ok": true}', None, False
        self.arrived, self.go, self.rest = threading.Event(), threading.Event(), threading.Event()
        self.go.set()

    def handle_error(self, request, client_address):
        pass                                    # a child that the broker ended; the test looks at the broker's answer


@unittest.skipUnless(CURL, "these checks need a curl program")
class BrokerRequests(VaultBroker):
    """vps has broker access and an agent key. A second broker of the same store has a curl program in its
    configuration, and the address of the saved login is the local service."""
    def setUp(self):
        super().setUp()
        self.service = Service()
        threading.Thread(target=self.service.serve_forever, daemon=True).start()
        self.addCleanup(self.end_service)
        self.site = f"http://127.0.0.1:{self.service.server_port}"
        self.login = dict(LOGIN, url=self.site + "/login")
        self.item(SECRET_ID, self.login)
        self.logged, self.private_host = [], vault.private_host
        # The local service has no TLS: for these checks its address counts as the hub's private range. The checks of
        # that rule use the real function (self.private_host).
        for p in (patch.object(vault, "log", self.logged.append),
                  patch.object(vault, "private_host", lambda host: host == "127.0.0.1" or self.private_host(host))):
            p.start()
            self.addCleanup(p.stop)
        self.rconf = dict(self.conf, socket=str(self.dir / "r.sock"), curl=os.path.realpath(CURL))
        self.sender = self.start(self.rconf)
        hub.ins("INSERT OR REPLACE INTO agent_keys(agent,sha256,created,source) VALUES('vps',?,?,'owner')",
                (hashlib.sha256(KEY.encode()).hexdigest(), hub.now()))
        self.journal = self.dir / "state" / "requests.json"

    # ---- helpers
    def end_service(self):
        self.service.go.set()
        self.service.rest.set()
        self.service.shutdown()
        self.service.server_close()

    def start(self, conf):
        """A broker with this configuration on its socket."""
        broker = vault.Broker(conf).open()
        threading.Thread(target=broker.serve, daemon=True).start()
        self.addCleanup(broker.close)
        return broker

    def request_job(self, request=None, method="GET", path="/v1/orders?x=1", body=None, auth="bearer", login=REF, attempt=1):
        """A request job as call_api makes it. The hub's route confirms it once."""
        return hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created,request_id,attempt,method,path,body,auth) "
                       "VALUES('vps',?,'request',?,'',?,?,?,?,?,?,?)",
                       (self.task, login, hub.now(), request or str(uuid.uuid4()), attempt, method, path, body, auth))

    def call(self, request, to=None):
        """One request line to a broker on its socket, and its one answer line."""
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(30)
            s.connect((to or self.rconf)["socket"])
            s.sendall((json.dumps(dict(request, v=2)) + "\n").encode())
            data = b""
            while not data.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        return json.loads(data)

    def ask(self, job, **fields):
        return self.call(dict({"op": "request", "job": job, "agent": "vps", "agent_key": KEY}, **fields))

    def cancel(self, attempt=1, **fields):
        return self.call(dict({"op": "cancel", "db": "test-generation", "task": f"T-{self.task}", "attempt": attempt,
                               "agent": "vps", "agent_key": KEY}, **fields))

    def answered(self, body, **job):
        """The broker's answer to a new request when the service answers with this body."""
        self.service.body = body if isinstance(body, bytes) else body.encode()
        number = self.request_job(**job)
        return number, self.ask(number)

    def in_thread(self, job):
        """Send the request of `job` in a thread: (the thread, the list that gets the broker's answer)."""
        answer = []
        thread = threading.Thread(target=lambda: answer.append(self.ask(job)), daemon=True)
        thread.start()
        return thread, answer

    def held(self, job):
        """Send the request of `job` while the service holds its answer: (the thread, the list that gets the broker's
        answer, the curl child that runs now)."""
        self.service.go.clear()
        self.service.arrived.clear()
        thread, answer = self.in_thread(job)
        self.assertTrue(self.service.arrived.wait(10))
        (child,) = self.sender.conf["_requests"].running
        return thread, answer, child

    def records(self):
        return json.loads(self.journal.read_text()) if self.journal.exists() else []

    def stand_in(self, name, script):
        """A broker whose curl program is this shell script: it takes the place of self.sender (one process has the
        record of the requests)."""
        program = self.dir / name
        program.write_text("#!/bin/sh\n" + script)
        program.chmod(0o755)
        self.sender.close()
        self.sender = self.start(dict(self.rconf, curl=str(program)))
        return program

    def write_setup(self):
        """A broker that also makes logins, and the owner's permission for vps. The store writes itself, so it needs
        only the record of its saves, which one process has: the first broker gives it up, and this one takes the
        place of self.sender (one process has the records of the requests too)."""
        hub.TEAM["agents"]["vps"]["vault_create"] = True
        self.broker.close()
        self.sender.close()
        self.sender = self.start(self.rconf)

    def create_job(self, request, label, username, url):
        """A create job as create_login makes it."""
        return hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created,request_id,label,username,url,attempt) "
                       "VALUES('vps',?,'create',NULL,'',?,?,?,?,?,1)", (self.task, hub.now(), request, label, username, url))

    @staticmethod
    def ended(pid):
        """True when no process with this pid runs: there is none, or only its status is left for its parent."""
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        return subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()[:1] in ("Z", "")

    # ---- the request
    def test_a_request_goes_to_the_site_of_the_saved_login_with_its_key(self):
        job = self.request_job(path="/v1/orders?x=1&y=[2]{3}")
        self.assertEqual(self.ask(job), {"ok": True, "v": 2, "job": job, "status": 200, "body": '{"ok": true}', "truncated": False})
        (got,) = self.service.seen
        self.assertEqual((got["method"], got["path"], got["body"]), ("GET", "/v1/orders?x=1&y=[2]{3}", b""))
        self.assertEqual(got["headers"].get_all("Authorization"), ["Bearer " + LOGIN["password"]])
        self.assertEqual((got["headers"]["Host"], got["headers"]["Accept"], got["headers"]["Content-Type"]),
                         (self.site[7:], "application/json", None))
        self.assertTrue(self.released(job))
        self.assertEqual([r["label"] for r in self.rows()], [REF + " password", REF + " totp"])    # protected at the hub
        self.assertEqual(self.reads(), [SECRET_ID])
        self.assertIn(f"request job={job}: HTTP 200", self.logged)
        self.assertIn(f"request job={job} for vps: ok", self.logged)
        # A body goes as it is, with its type. Basic: the user name and the key.
        sent = '{"name": "caf\u00e9 \\"A\\"", "lines": "1\\n2"}\n'
        self.service.status = 201
        job = self.request_job(method="POST", path="/v1/orders", body=sent, auth="basic")
        self.assertEqual(self.ask(job)["status"], 201)
        got = self.service.seen[-1]
        basic = base64.b64encode(f"{LOGIN['username']}:{LOGIN['password']}".encode()).decode()
        self.assertEqual((got["method"], got["headers"].get_all("Authorization"), got["headers"]["Content-Type"], got["body"]),
                         ("POST", ["Basic " + basic], "application/json", sent.encode()))
        # A named header: the key is its value, and there is no Authorization header.
        for method, name in (("DELETE", "X-Api-Key"), ("PUT", "X_Key"), ("PATCH", "K" * 64)):
            self.ask(self.request_job(method=method, path="/v1/orders/7", auth="header:" + name))
            got = self.service.seen[-1]
            self.assertEqual((got["method"], got["headers"].get_all(name), got["headers"]["Authorization"]),
                             (method, [LOGIN["password"]], None))
            # A method that has a body says so when the body is empty.
            self.assertEqual(got["headers"]["Content-Length"], None if method == "DELETE" else "0")
        # An interim answer is not the answer.
        self.service.interim, self.service.status = True, 404
        self.assertEqual(self.answered('{"error": "none"}')[1]["status"], 404)
        self.assertEqual(len(self.service.seen), 6)

    def test_the_key_is_in_no_argument_no_environment_and_no_log_line(self):
        sent, started, real = '{"note": "body-marker-13579"}', [], subprocess.Popen

        def spy(argv, *args, **kwargs):
            started.append((list(argv), dict(kwargs.get("env") or {})))
            return real(argv, *args, **kwargs)
        job = self.request_job(method="POST", path="/v1/echo?marker=path-marker", body=sent, auth="basic")
        with patch.object(vault.subprocess, "Popen", spy), patch.dict(os.environ, {"FLEET_TEST_MARKER": "inherited"}):
            thread, answer, child = self.held(job)
            pid = child.proc.pid                # the child runs now: the service holds its answer
            shown = real(["ps", "-o", "command=", "-p", str(pid)], stdout=subprocess.PIPE, text=True).communicate()[0]
            wide = real(["ps", "eww", "-o", "command=", "-p", str(pid)], stdout=subprocess.PIPE, text=True).communicate()[0]
            environ = f"/proc/{pid}/environ"
            if os.path.exists(environ):         # Linux gives the environment itself
                with open(environ, "rb") as f:
                    wide += f.read().decode("utf-8", "replace")
            self.service.go.set()
            thread.join(10)
        self.assertEqual(answer[0]["status"], 200)
        self.assertEqual(shown.strip(), f"{self.rconf['curl']} -q --config -")
        (child_argv, child_env), = [s for s in started if s[0][0] == self.rconf["curl"]]
        self.assertEqual((child_argv, child_env), ([self.rconf["curl"], "-q", "--config", "-"],
                                                   {"PATH": "/usr/local/bin:/usr/bin:/bin"}))
        basic = base64.b64encode(f"{LOGIN['username']}:{LOGIN['password']}".encode()).decode()
        kept = json.dumps([dict(r) for table in ("events", "log", "secrets") for r in hub.q(f"SELECT * FROM {table}")])
        for where in (shown, wide, json.dumps(started[-1]), "\n".join(self.logged), self.journal.read_text(), kept):
            for secret in (LOGIN["password"], basic, LOGIN["totp"], KEY, "body-marker-13579", "path-marker",
                           "FLEET_TEST_MARKER"):
                self.assertNotIn(secret, where)
        self.assertEqual(self.service.seen[0]["body"], sent.encode())           # and the service got all of it

    def test_the_record_is_kept_before_the_child_starts_and_one_request_is_sent_once(self):
        steps, request = [], str(uuid.uuid4())
        real_hub, real_sync, real_replace, real_popen = vault.hub, os.fsync, os.replace, subprocess.Popen

        def hub_spy(conf, method, path, body=None):
            steps.append("hub " + path.rsplit("/", 1)[-1])
            return real_hub(conf, method, path, body)

        def sync(fd):
            steps.append("sync folder" if stat.S_ISDIR(os.fstat(fd).st_mode) else "sync file")
            return real_sync(fd)

        def replace(old, new):
            steps.append("name " + os.path.basename(new))
            return real_replace(old, new)

        def popen(argv, *args, **kwargs):
            steps.append("child " + os.path.basename(argv[0]))
            return real_popen(argv, *args, **kwargs)
        first = self.request_job(request, method="POST", path="/v1/pay", body='{"amount": 5}')
        with patch.object(vault, "hub", hub_spy), patch.object(vault.os, "fsync", sync), \
                patch.object(vault.os, "replace", replace), patch.object(vault.subprocess, "Popen", popen):
            self.assertEqual(self.ask(first)["status"], 200)
        # The store opens before the hub is asked; then the hub's confirmation, the login read from the store, its
        # fingerprints, the record on the disk, and only then the child.
        self.assertEqual(steps, ["child age", "hub vps", "child age", "hub fingerprints", "sync file",
                                 "name requests.json", "sync folder", "child curl"])
        (record,) = self.records()
        self.assertEqual({k: v for k, v in record.items() if k != "started_at"},
                         {"request_id": request, "agent": "vps", "db": "test-generation", "task": f"T-{self.task}",
                          "attempt": 1, "job": first})
        self.assertEqual((self.journal.stat().st_mode & 0o777, sorted(os.listdir(self.dir / "state"))),
                         (0o600, ["age.key", "creates.json.lock", "requests.json", "requests.json.lock", "store.age",
                                  "store.key"]))                        # no body file stays
        # The hub has one job for one request_id of an agent. A hub that lost that record (an older copy of its
        # database) confirms the same request_id again: it is not sent, and the outcome is not known.
        with self.assertRaises(sqlite3.IntegrityError):
            self.request_job(request, method="POST", path="/v1/pay", body='{"amount": 5}')
        hub.q("DELETE FROM jobs WHERE id=?", (first,))
        again = self.request_job(request, method="POST", path="/v1/pay", body='{"amount": 5}')
        self.assertEqual(self.ask(again), {"ok": False, "v": 2, "unknown": True, "error": STARTED_BEFORE})
        self.assertTrue(self.released(again))
        self.assertEqual((len(self.service.seen), len(self.reads()), len(self.records())), (1, 1, 1))
        # A second process gets no record, so it sends nothing.
        self.assertNotIn("_requests", vault.with_requests(dict(self.rconf), threading.Lock()))
        self.assertEqual(self.logged[-1], "no requests: the vault's record of its requests cannot be read, so it sends none")
        # After a restart of the broker, the record is still there.
        self.sender.close()
        self.sender = self.start(self.rconf)
        hub.q("DELETE FROM jobs WHERE id=?", (again,))
        third = self.request_job(request, method="POST", path="/v1/pay", body='{"amount": 5}')
        self.assertEqual(self.ask(third), {"ok": False, "v": 2, "unknown": True, "error": STARTED_BEFORE})
        self.assertEqual(len(self.service.seen), 1)
        # A record that cannot be kept: nothing is sent.
        state = self.dir / "state"
        state.chmod(0o500)
        self.addCleanup(state.chmod, 0o700)
        self.assertEqual(self.ask(self.request_job()),
                         {"ok": False, "v": 2, "error": "The vault could not keep its record of this request. Nothing was sent."})
        state.chmod(0o700)
        self.assertEqual((len(self.service.seen), len(self.records())), (1, 1))
        # The newest records of ended requests stay, and each one of a request that runs.
        calls, old = self.sender.conf["_requests"], [str(uuid.uuid4()) for _ in range(6)]
        with patch.object(vault.Requests, "KEEP", 3):
            calls.running.append(type("Runs", (), {"request_id": old[0]}))
            for one in old:
                calls.begin(dict(record, request_id=one))
            calls.running.clear()
        self.assertEqual([r["request_id"] for r in self.records()], [old[0]] + old[3:])
        # A record that cannot be read stops requests; the broker still reads logins.
        self.sender.close()
        self.journal.write_text("{not a record")
        self.sender = self.start(self.rconf)
        self.assertNotIn("requests", self.call({"op": "status"}))
        self.assertEqual(self.call({"op": "handover", "job": self.job()})["to"], "studio")

    def test_a_body_with_the_key_or_without_text_is_held_back(self):
        basic = base64.b64encode(f"{LOGIN['username']}:{LOGIN['password']}".encode()).decode()
        for body, job in ((json.dumps({"echo": LOGIN["password"]}), {}), ("seed " + LOGIN["totp"], {}),
                          (json.dumps({"authorization": "Basic " + basic}).replace("/", "\\/"), {"auth": "basic"})):
            number, reply = self.answered(body, **job)
            self.assertEqual(reply, {"ok": True, "v": 2, "job": number, "status": 200, "withheld": "key"}, body)
        for body in (b"\xff\xfe\x00\x01", b'{"zero": "\x00"}', "caf\u00e9".encode("latin-1")):
            number, reply = self.answered(body)
            self.assertEqual(reply, {"ok": True, "v": 2, "job": number, "status": 200, "withheld": "binary"}, body)
        # A key with a character that JSON writes as an escape: the escapes of the body are undone before the look.
        key = "stand-in-\u00e9-value-0123456789"
        self.item(SECRET_ID, dict(self.login, password=key))
        written = json.dumps({"password": key})
        self.assertIn("\\u00e9", written)                                       # the key as it is is not in this body
        pad = '{"pad": "' + "x" * (vault.ANSWER_LIMIT - 40) + '", '             # the written key lies across the cut
        pair = "stand-in-\U0001f600/\"value\"-0123456789"
        for body in (written, written.replace("\\u00e9", "\\u00E9"), json.dumps({"password": key}, ensure_ascii=False),
                     pad + written[1:], pad + written[1:] + "y" * 5000):
            number, reply = self.answered(body)
            self.assertEqual(reply, {"ok": True, "v": 2, "job": number, "status": 200, "withheld": "key"}, body[-80:])
        self.assertLess(len(pad), vault.ANSWER_LIMIT)
        self.assertGreater(len(pad + written[1:]), vault.ANSWER_LIMIT)
        # One pass from the left: a written backslash and the text u00e9 are not the key's character.
        other = json.dumps({"note": key.replace("\u00e9", "\\u00e9")})
        self.assertIn("\\\\u00e9", other)
        self.assertEqual(self.answered(other)[1]["body"], other)
        # The two halves of one character, and the marks before a quote and "/".
        self.item(SECRET_ID, dict(self.login, password=pair))
        for body in (json.dumps({"password": pair}), json.dumps({"password": pair}).replace("/", "\\/")):
            self.assertIn("\\ud83d\\ude00", body)
            self.assertEqual(self.answered(body, auth="basic")[1].get("withheld"), "key", body)
        # A short key can be in any text by chance: it is used and not looked for, as before.
        self.item(SECRET_ID, dict(self.login, password="Sh0rt!7", totp="JBSW Y3"))
        self.assertEqual(self.answered('{"echo": "Sh0rt!7"}')[1]["body"], '{"echo": "Sh0rt!7"}')

    def test_a_long_answer_is_cut_and_the_broker_does_not_wait_for_the_rest(self):
        limit = vault.ANSWER_LIMIT
        self.assertEqual(limit, 65536)
        reply = self.answered("a" * limit)[1]
        self.assertEqual((len(reply["body"]), reply["truncated"]), (limit, False))
        reply = self.answered("a" * (limit + 1))[1]
        self.assertEqual((reply["body"], reply["truncated"]), ("a" * limit, True))
        reply = self.answered("b" + "\u00e9" * 40000)[1]                         # the cut is inside one character
        self.assertEqual((reply["body"], reply["truncated"]), ("b" + "\u00e9" * 32767, True))
        # A service that says 10 MB, sends a part and then nothing: the broker ends its child and answers at once.
        self.service.declared = 10_000_000
        t0 = time.monotonic()
        number, reply = self.answered("c" * 70000)
        self.assertEqual((reply["status"], reply["body"], reply["truncated"]), (200, "c" * limit, True))
        self.assertLess(time.monotonic() - t0, 10)
        self.assertEqual(self.sender.conf["_requests"].running, [])
        self.assertFalse(self.service.rest.is_set())                            # the service still holds the rest

    def test_a_redirect_is_an_answer_and_is_not_followed(self):
        self.service.status, self.service.headers = 302, [("Location", self.site + "/elsewhere")]
        number, reply = self.answered("moved")
        self.assertEqual(reply, {"ok": True, "v": 2, "job": number, "status": 302, "body": "moved", "truncated": False})
        self.assertEqual([s["path"] for s in self.service.seen], ["/v1/orders?x=1"])            # one request only

    def test_only_an_end_without_a_connection_says_that_nothing_was_sent(self):
        with socket.socket() as s:              # a port where nothing listens
            s.bind(("127.0.0.1", 0))
            closed = s.getsockname()[1]
        self.item(SECRET_ID, dict(self.login, url=f"http://127.0.0.1:{closed}/login"))
        job = self.request_job()
        self.assertEqual(self.ask(job), {"ok": False, "v": 2, "error": NOT_REACHED})            # the real curl: status 7
        self.assertIn(f"request job={job} for vps refused: {NOT_REACHED}", self.logged)
        # Each end of the child, with a stand-in that only ends with a status.
        program = self.stand_in("curl-ends", 'cat > /dev/null\nexit "$(cat "$0.status")"\n')
        for status, sent in ((6, False), (7, False), (0, True), (1, True), (2, True), (3, True), (5, True), (28, True),
                             (35, True), (52, True), (55, True), (56, True), (60, True)):
            (self.dir / (program.name + ".status")).write_text(str(status))
            self.assertEqual(self.ask(self.request_job()), {"ok": False, "v": 2, "unknown": True, "error": NOT_KNOWN} if sent
                             else {"ok": False, "v": 2, "error": NOT_REACHED}, status)
        # A curl program that is not there: no child starts, so nothing was sent.
        program.unlink()
        self.assertEqual(self.ask(self.request_job()),
                         {"ok": False, "v": 2, "error": "The vault could not start this request. Nothing was sent."})
        self.assertEqual((self.service.seen, self.sender.conf["_requests"].running), ([], []))

    def test_no_answer_in_the_time_limit_is_unknown_and_the_child_is_ended(self):
        self.service.go.clear()                 # the service takes the request and never answers
        job, t0 = self.request_job(method="POST", path="/v1/pay", body='{"amount": 5}'), time.monotonic()
        with patch.object(vault, "REQUEST_LIMIT", 1):
            self.assertEqual(self.ask(job), {"ok": False, "v": 2, "unknown": True, "error": NOT_KNOWN})
        self.assertLess(time.monotonic() - t0, 10)
        self.assertEqual((len(self.service.seen), self.sender.conf["_requests"].running), (1, []))
        self.assertIn(f"request job={job}: outcome not known", self.logged)
        # A child that does not keep the limit by itself, with a second process in its group: the broker ends both.
        program = self.stand_in("curl-hangs", 'sleep 30 &\necho $! > "$0.pid"\nwait\n')
        with patch.object(vault, "REQUEST_LIMIT", 0.5):
            self.assertEqual(self.ask(self.request_job()), {"ok": False, "v": 2, "unknown": True, "error": NOT_KNOWN})
        second = int((self.dir / (program.name + ".pid")).read_text())
        self.assertTrue(self.ended(second))
        self.assertLess(time.monotonic() - t0, 20)

    # ---- the cancel
    def test_a_cancel_ends_the_child_before_it_answers_and_stops_the_task_attempt(self):
        seen, real_stop, first = [], vault.Requests.stop, str(uuid.uuid4())
        job = self.request_job(request=first, method="POST", path="/v1/pay", body='{"amount": 5}')
        thread, answer, child = self.held(job)
        pid = child.proc.pid
        self.assertEqual((os.getpgid(pid), os.getsid(pid)), (pid, pid))        # a process group of its own

        def stop(calls, scope):
            ended = real_stop(calls, scope)     # the broker has its answer here, and has not sent it yet
            seen.append((ended, child.proc.returncode, self.ended(pid)))
            return ended
        # Another key than the one that came with the request: no proof, and the child is not ended.
        self.assertEqual(self.cancel(agent_key=OTHER_KEY), {"ok": False, "v": 2, "error": NO_PROOF})
        self.assertEqual(self.cancel(attempt=9), {"ok": True, "v": 2, "task": f"T-{self.task}", "attempt": 9, "stopped": True,
                                                   "ended": 0})                 # no child in that scope
        self.assertEqual(self.cancel(db="another-generation")["ended"], 0)
        os.kill(pid, 0)
        self.assertEqual((child.proc.poll(), child.canceled, answer), (None, False, []))
        self.assertIs(self.call({"op": "status"})["requests"], True)            # a status is served while the request runs
        with patch.object(vault.Requests, "stop", stop):
            self.assertEqual(self.cancel(), {"ok": True, "v": 2, "task": f"T-{self.task}", "attempt": 1, "stopped": True,
                                             "ended": 1})
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)                     # no such process now: the broker took its status
        with self.assertRaises(ProcessLookupError):
            os.killpg(pid, 0)                   # and its process group has no process
        self.assertEqual(seen, [(1, -9, True)])                                 # ended by the signal, before the answer
        thread.join(10)
        self.assertEqual(answer, [{"ok": False, "v": 2, "unknown": True, "canceled": True, "error":
                                   "The request was stopped before its answer. The service can have received it. It is not "
                                   "sent again."}])
        self.assertIn(f"cancel T-{self.task} attempt 1: ended 1", self.logged)
        self.assertIn(f"request job={job}: stopped by a cancel", self.logged)
        # After the cancel, a late request of that key and attempt is refused, also one that the hub confirms. No
        # login is read for it.
        self.service.go.set()
        late, reads = self.request_job(), len(self.reads())
        self.assertEqual(self.ask(late), {"ok": False, "v": 2, "error": STOPPED})
        self.assertTrue(self.released(late))
        self.assertEqual((len(self.service.seen), len(self.reads())), (1, reads))
        self.assertEqual(self.cancel()["ended"], 0)                             # again: nothing runs
        # The request that was sent and then stopped, named again (a hub that gives it a second time): its identity
        # is known, so the answer is unknown and never "nothing was sent". The identity counts before the guard.
        hub.q("DELETE FROM jobs WHERE id=?", (job,))
        again = self.request_job(request=first, method="POST", path="/v1/pay", body='{"amount": 5}')
        self.assertEqual(self.ask(again), {"ok": False, "v": 2, "unknown": True, "error": vault.REPEATED})
        self.assertEqual((len(self.service.seen), len(self.reads())), (1, reads))
        # A later attempt of the task works.
        hub.q("UPDATE tasks SET attempt=2 WHERE id=?", (self.task,))
        self.assertEqual(self.ask(self.request_job(attempt=2))["status"], 200)
        # What a cancel needs, and what a broker without requests says.
        for fields, why in (({"agent": None, "agent_key": None}, "the caller fields are not valid"),
                            ({"db": "bad generation"}, "a cancel request needs db, task and attempt"),
                            ({"task": "T-1\n"}, "a cancel request needs db, task and attempt"),
                            ({"task": 7}, "a cancel request needs db, task and attempt"),
                            ({"attempt": 0}, "a cancel request needs db, task and attempt"),
                            ({"attempt": True}, "a cancel request needs db, task and attempt")):
            self.assertEqual(self.cancel(**fields), {"ok": False, "v": 2, "error": why}, fields)
        self.assertEqual(self.call({"op": "cancel", "db": "test-generation", "task": "T-1", "attempt": 1}),
                         {"ok": False, "v": 2, "error": "a cancel needs the caller fields"})
        self.assertEqual(self.call(dict({"op": "cancel", "db": "test-generation", "task": "T-1", "attempt": 1, "agent": "vps",
                                         "agent_key": KEY}), to=self.conf),
                         {"ok": False, "v": 2, "error": "This machine's vault is not set up to send requests."})

    def test_a_cancel_ends_all_of_the_childs_process_group(self):
        program = self.stand_in("curl-hangs", 'sleep 30 &\necho $! > "$0.pid"\nwait\n')
        mark = self.dir / (program.name + ".pid")
        thread, answer = self.in_thread(self.request_job())
        deadline = time.monotonic() + 10
        while not (mark.exists() and mark.read_text().strip()) and time.monotonic() < deadline:
            time.sleep(0.02)
        (child,) = self.sender.conf["_requests"].running
        pid, second = child.proc.pid, int(mark.read_text())
        self.assertEqual(os.getpgid(second), pid)                               # the second process is in the child's group
        self.assertFalse(self.ended(pid) or self.ended(second))
        self.assertEqual(self.cancel()["ended"], 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        self.assertTrue(self.ended(second))                                     # the signal went to the group
        thread.join(10)
        self.assertEqual((answer[0].get("canceled"), answer[0].get("unknown")), (True, True))

    # ---- the setup and the checks of the broker
    def test_only_a_broker_with_a_curl_program_sends_requests(self):
        self.assertNotIn("requests", self.call({"op": "status"}, to=self.conf))
        status = self.call({"op": "status"})
        self.assertEqual(set(status), {"ok", "v", "agent", "store", "user", "recipient", "callers", "requests",
                                       "backend", "source", "deposits", "withdrawals"})       # no journal: the first broker has it
        self.assertIs(status["requests"], True)
        job = self.request_job()
        self.assertEqual(self.call({"op": "request", "job": job, "agent": "vps", "agent_key": KEY}, to=self.conf),
                         {"ok": False, "v": 2, "error": "This machine's vault is not set up to send requests."})
        self.assertIsNone(self.released(job))                                   # the hub was not asked
        for fields, why in (({"agent": None, "agent_key": None}, "the caller fields are not valid"),
                            ({"agent_key": "w" * 43}, "the hub did not accept this agent's key"),
                            ({"job": "7"}, "a request needs a job number"), ({"job": True}, "a request needs a job number")):
            self.assertEqual(self.call(dict({"op": "request", "job": job, "agent": "vps", "agent_key": KEY}, **fields)),
                             {"ok": False, "v": 2, "error": why}, fields)
        self.assertEqual(self.call({"op": "request", "job": job}), {"ok": False, "v": 2, "error": "a request needs the caller fields"})
        self.assertIsNone(self.released(job))
        self.assertEqual((self.service.seen, self.reads(), self.records()), ([], [], []))
        # The form of the configuration: the key is optional, and a configuration without it loads as before.
        path, other, program = self.dir / "vault.json", {"worker_uid": os.getuid() + 1}, self.dir / "open" / "curl"
        own = dict(self.conf)                   # the fleet's own store, as every broker has
        rown = dict(own, curl=self.rconf["curl"])
        for good in (dict(own, **other), dict(rown, **other)):
            path.write_text(json.dumps(good))
            self.assertEqual(vault.load_config(str(path)), good)
        program.parent.mkdir()
        shutil.copy(self.dir / "age", program)
        program.parent.chmod(0o777)             # the agent could put another program there
        for bad in ({"curl": "curl"}, {"curl": None}, {"curl": 7}, {"wget": "/usr/bin/wget"}, {"curl": str(program)}):
            path.write_text(json.dumps(dict(rown, **other, **bad)))
            with self.assertRaises(SystemExit, msg=bad):
                vault.load_config(str(path))
        program.parent.chmod(0o755)             # the same program in a folder that only its owner changes
        self.assertEqual(vault.load_config(str(path))["curl"], str(program))
        self.assertEqual(self.call({"op": "handover", "job": self.job()}, to=self.conf)["to"], "studio")    # reads are as before

    def test_the_broker_checks_again_what_the_hub_confirms(self):
        good = {"kind": "request", "request_id": str(uuid.uuid4()), "db": "test-generation", "task": "T-7", "attempt": 2,
                "method": "GET", "path": "/v1/orders?x=1", "auth": "bearer"}
        self.assertEqual(vault.request_of(good),
                         dict({k: v for k, v in good.items() if k != "kind"}, body=None, headers={}, limit=None))
        # plan C7: the agent's own time for the service, which the curl child gets; a bad one sends nothing
        self.assertEqual(vault.request_of(dict(good, timeout=600))["limit"], 600)
        for bad in (0, -1, True, "60", 1e8):
            with self.assertRaises(vault.Refused, msg=bad):
                vault.request_of(dict(good, timeout=bad))
        for change in ({"path": "/"}, {"path": "/" + "a" * 1999}, {"path": "/a/..//b?q=\"1\"&r=[]{}~!$'()*+,;=:@%20"},
                       {"auth": "basic"}, {"auth": "header:X_Key"}, {"auth": "header:x-api-key"}, {"auth": "header:K"},
                       {"auth": "header:" + "K" * 64}, {"auth": "header:Hosts"}, {"body": None}, {"body": ""},
                       {"request_id": good["request_id"].upper()}) + tuple({"method": m} for m in vault.API_METHODS):
            self.assertEqual(vault.request_of(dict(good, **change))["body"], None, change)
        self.assertEqual(vault.request_of(dict(good, body="caf\u00e9"))["body"], "caf\u00e9".encode())
        self.assertEqual(len(vault.request_of(dict(good, body="x" * 65536))["body"]), 65536)
        # The agent's own headers, which the broker checks exactly as the hub did: the five that are the vault's are
        # refused here too, so a hub that was talked into one still sends nothing.
        self.assertEqual(vault.request_of(dict(good, headers={"Stripe-Version": "2026-10-01", "A-B": "v"}))["headers"],
                         {"A-B": "v", "Stripe-Version": "2026-10-01"})
        self.assertEqual(vault.request_of(dict(good, headers={}))["headers"], {})
        self.assertEqual(vault.request_of(dict(good, headers=None))["headers"], {})
        self.assertEqual(vault.request_of(dict(good, auth="header:X-Api-Key",
                                               headers={"Content-Type": "text/plain"}))["headers"],
                         {"Content-Type": "text/plain"})
        for change in ({"headers": {"Host": "evil.example"}}, {"headers": {"host": "evil.example"}},
                       {"headers": {"Authorization": "Bearer x"}}, {"headers": {"Content-Length": "0"}},
                       {"headers": {"Transfer-Encoding": "chunked"}}, {"headers": {"Connection": "close"}},
                       {"headers": {"X-Key": "a\r\nHost: evil.example"}}, {"headers": {"X-Key": "a\nb"}},
                       {"headers": {"X-Key": "a\x00b"}}, {"headers": {"X-Key": "a\tb"}}, {"headers": {"X-Key": ""}},
                       {"headers": {"X-Key": "x" * 1001}}, {"headers": {"X-Key": 7}}, {"headers": {"X-Key": None}},
                       {"headers": {"X Key": "v"}}, {"headers": {"7Key": "v"}}, {"headers": {"-Key": "v"}},
                       {"headers": {"X.Key": "v"}}, {"headers": {"": "v"}}, {"headers": {"K" * 65: "v"}},
                       {"headers": {7: "v"}}, {"headers": {"X-Key": "v", "x-key": "w"}},
                       {"headers": [["X-Key", "v"]]}, {"headers": "X-Key: v"},
                       {"headers": {f"X-{n}": "v" for n in range(17)}},
                       {"auth": "header:X-Api-Key", "headers": {"X-Api-Key": "mine"}},
                       {"auth": "header:X-Api-Key", "headers": {"x-api-key": "mine"}}):
            with self.assertRaises(vault.Refused, msg=change) as refused:
                vault.request_of(dict(good, **change))
            self.assertEqual(str(refused.exception), NOT_CONFIRMED, change)
        for change in ({"path": ""}, {"path": "v1/orders"}, {"path": "//evil.example/x"}, {"path": "/a b"}, {"path": "/a#b"},
                       {"path": "/a\\b"}, {"path": "/a\n"}, {"path": "/a\r\nHost: evil.example"}, {"path": "/a\tb"},
                       {"path": "/caf\u00e9"}, {"path": "/a\x7f"}, {"path": "/" + "a" * 2000}, {"path": None}, {"path": 7},
                       {"auth": "header:7Key"}, {"auth": "header:-Key"}, {"auth": "header:_Key"}, {"auth": "header:"},
                       {"auth": "header:" + "K" * 65}, {"auth": "header:X Key"}, {"auth": "header:X-Key\n"},
                       {"auth": "header:X-Key:"}, {"auth": "header:Cl\u00e9"}, {"auth": "Bearer"}, {"auth": "token"},
                       {"auth": "bearer\n"}, {"auth": None}, {"auth": 7}, {"auth": "header:Host"},
                       {"auth": "header:AUTHORIZATION"}, {"auth": "header:content-type"}, {"auth": "header:Content-Length"},
                       {"auth": "header:Transfer-Encoding"}, {"auth": "header:connection"},
                       {"body": "x" * 65537}, {"body": "\u00e9" * 32769}, {"body": 7}, {"body": ["x"]}, {"body": "\ud800"},
                       {"method": "HEAD"}, {"method": "get"}, {"method": "GET\n"}, {"method": None}, {"method": ["GET"]},
                       {"request_id": "not-a-uuid"}, {"request_id": None}, {"db": "bad generation"}, {"db": None},
                       {"attempt": 0}, {"attempt": True}, {"attempt": "2"}, {"task": ""}, {"task": "T-7\n"}, {"task": 7},
                       {"kind": "signin"}):
            with self.assertRaises(vault.Refused, msg=change) as refused:
                vault.request_of(dict(good, **change))
            self.assertEqual(str(refused.exception), NOT_CONFIRMED, change)
        # Through the hub's route and the socket: nothing is sent, and no login is read.
        for job in ({"auth": "header:7Key"}, {"auth": "header:Authorization"}, {"path": "//127.0.0.1:1/x"},
                    {"path": "/a b"}, {"method": "HEAD"}, {"method": "POST", "body": "x" * 65537}):
            number = self.request_job(**job)
            self.assertEqual(self.ask(number), {"ok": False, "v": 2, "error": NOT_CONFIRMED}, job)
            self.assertTrue(self.released(number))
        self.assertEqual((self.service.seen, self.reads(), self.records()), ([], [], []))
        # A handed-over copy is not used for a request, and it is not opened.
        sid = hub.ins("INSERT INTO sealed(sender,recipient,task,label,ciphertext,created) VALUES(?,?,?,?,?,?)",
                      ("studio", "vps", f"T-{self.task}", "handed-site", lock(VPS_KEY, self.login), hub.now()))
        self.assertEqual(self.ask(self.request_job(login=f"sealed:{sid}")),
                         {"ok": False, "v": 2, "error": "A request needs a login that is saved in this fleet's vault, not a "
                                                        "handed-over copy. Nothing was sent."})
        self.assertEqual(hub.q1("SELECT fetched FROM sealed WHERE id=?", (sid,))["fetched"], 0)
        # The saved login: an origin that is not visible ASCII without a quote and a backslash, a port that is no
        # number, and a key that no header line can have.
        for change, auth, why in (({"url": "https://b\u00fccher.example/login"}, "bearer", vault.BAD_ADDRESS),
                                  ({"url": "https://a\\b.example/login"}, "bearer", vault.BAD_ADDRESS),
                                  ({"url": "https://a\"b.example/login"}, "bearer", vault.BAD_ADDRESS),
                                  ({"url": self.site + ":x/login"}, "bearer", vault.BAD_ADDRESS),
                                  ({"password": "two\r\nX-Other: lines-0123456789"}, "bearer", vault.NO_HEADER),
                                  ({"password": "two\nlines-0123456789"}, "header:X-Api-Key", vault.NO_HEADER)):
            self.item(SECRET_ID, dict(self.login, **change))
            self.assertEqual(self.ask(self.request_job(auth=auth)), {"ok": False, "v": 2, "error": why}, change)
        self.assertEqual((self.service.seen, self.records()), ([], []))
        self.assertEqual(self.ask(self.request_job(auth="basic"))["status"], 200)       # base64 carries every value
        self.assertEqual(self.service.seen[0]["headers"]["Authorization"], "Basic " + base64.b64encode(
            f"{LOGIN['username']}:two\nlines-0123456789".encode()).decode())
        self.assertEqual([vault.origin(u) for u in ("https://Example.org:443/login?x=1", "http://100.64.0.1:8765/x",
                                                    "http://shop_api.internal:80", "https://[::1]:8443/x", "https://a b.example/")],
                         [("https", "example.org", "https://example.org"), ("http", "100.64.0.1", "http://100.64.0.1:8765"),
                          ("http", "shop_api.internal", "http://shop_api.internal"), ("https", "::1", "https://[::1]:8443"), None])

    def test_the_key_goes_out_with_https_or_to_the_private_range_of_the_hub_only(self):
        started, real = [], subprocess.Popen

        def spy(argv, *args, **kwargs):
            started.append(os.path.basename(argv[0]))
            return real(argv, *args, **kwargs)
        # A public address without TLS: refused before the child starts.
        self.item(SECRET_ID, dict(self.login, url="http://example.com/path"))
        with patch.object(vault.subprocess, "Popen", spy):
            self.assertEqual(self.ask(self.request_job()),
                             {"ok": False, "v": 2, "error": "This login's address is not HTTPS. Nothing was sent."})
        self.assertEqual((self.reads(), [p for p in started if p != "age"], self.records(), self.service.seen),
                         ([SECRET_ID], [], [], []))             # the login was read from the store; no curl
        # The rule itself, with the real function: no child and no connection here.
        call = vault.request_of({"kind": "request", "request_id": str(uuid.uuid4()), "db": "test-generation", "task": "T-7",
                                 "attempt": 1, "method": "GET", "path": "/v1/orders?x=1", "auth": "bearer"})
        with patch.object(vault, "private_host", self.private_host):
            for url, site in (("http://100.64.0.1:8765", "http://100.64.0.1:8765"),
                              ("http://100.127.255.254", "http://100.127.255.254"),
                              ("http://100.100.100.100:80/login", "http://100.100.100.100")):
                lines = vault.curl_config(call, dict(LOGIN, url=url))[0].decode().splitlines()
                self.assertEqual((lines[0], lines[-2], lines[-1]),
                                 ('proto = "-all"', f'url = "{site}/v1/orders?x=1"', 'proto = "=http"'), url)
            for url in ("http://100.63.0.1", "http://100.128.0.1", "http://0100.64.0.1", "http://localhost", "http://10.0.0.1",
                        "http://127.0.0.1:8080", "http://example.com/path", "http://100.64.0.1.example.com",
                        "http://100.64.0", "http://100.64.0.256", "http://100.064.0.1"):
                with self.assertRaises(vault.Refused, msg=url) as refused:
                    vault.curl_config(call, dict(LOGIN, url=url))
                self.assertEqual(str(refused.exception), "This login's address is not HTTPS. Nothing was sent.", url)
            # An HTTPS address passes, and curl gets these limits: one scheme, no proxy, no redirect, one HTTP version
            # and the time limits.
            config, values = vault.curl_config(call, dict(LOGIN, url="https://api.example.com/login"))
            self.assertEqual(config.decode().splitlines(), [
                'proto = "-all"', "silent", "globoff", "include", "no-buffer", "http1.1", 'noproxy = "*"', "max-redirs = 0",
                "max-time = 60", "connect-timeout = 15", 'request = "GET"', 'header = "Accept: application/json"',
                'user-agent = "Founderizer-Fleet/1 (vault)"',     # an edge refused curl's own (6 November 2026)
                f'header = "Authorization: Bearer {LOGIN["password"]}"', 'url = "https://api.example.com/v1/orders?x=1"',
                'proto = "=https"'])
            mine = vault.request_of({"kind": "request", "request_id": str(uuid.uuid4()), "db": "test-generation",
                                     "task": "T-7", "attempt": 1, "method": "GET", "path": "/v1/orders", "auth": "bearer",
                                     "headers": {"User-Agent": "shop-bot/2"}})
            lines = vault.curl_config(mine, dict(LOGIN, url="https://api.example.com/login"))[0].decode().splitlines()
            self.assertLess(lines.index('user-agent = "Founderizer-Fleet/1 (vault)"'),
                            lines.index('header = "User-Agent: shop-bot/2"'))     # the agent's own header wins in curl
            self.assertEqual(values, [LOGIN["password"], LOGIN["totp"]])
            lines = vault.curl_config(dict(call, method="POST"), dict(LOGIN, url="https://api.example.com/login"), 9)[0]
            self.assertIn('header = "Content-Type: application/json"\ndata-binary = "@/dev/fd/9"\n', lines.decode())
            lines = vault.curl_config(dict(call, method="PUT"), dict(LOGIN, url="https://api.example.com/login"))[0]
            self.assertIn('header = "Content-Length: 0"\n', lines.decode())
            # The agent's own headers are written, sorted, before the one that carries the key; a content type of
            # its own replaces the JSON default, which is what a Stripe refund needs.
            form = dict(call, method="POST", headers={"Idempotency-Key": "refund:ch_1", "Stripe-Version": "2026-10-01",
                                                      "Content-Type": "application/x-www-form-urlencoded"})
            lines = vault.curl_config(form, dict(LOGIN, url="https://api.stripe.com/login"), 9)[0].decode().splitlines()
            self.assertEqual(lines[-7:], [
                'data-binary = "@/dev/fd/9"',
                'header = "Content-Type: application/x-www-form-urlencoded"',
                'header = "Idempotency-Key: refund:ch_1"',
                'header = "Stripe-Version: 2026-10-01"',
                f'header = "Authorization: Bearer {LOGIN["password"]}"',
                'url = "https://api.stripe.com/v1/orders?x=1"',
                'proto = "=https"'])
            self.assertNotIn('header = "Content-Type: application/json"', lines)
            self.assertEqual(sum(l.startswith('header = "Authorization:') for l in lines), 1)   # the key, once
            self.assertEqual(sum(l.lower().startswith('header = "content-type:') for l in lines), 1)
        self.assertEqual([self.private_host(h) for h in ("100.64.0.0", "100.127.255.255", "100.64.0.1", "100.63.255.255",
                                                         "100.128.0.0", "100.64.0.01", "100.64.0.1 ", "", "100.64.0.1\n")],
                         [True, True, True, False, False, False, False, False, False])

    def test_a_login_that_the_task_made_needs_this_brokers_record_also_for_a_request(self):
        asked, real = [], vault.hub
        made = {"request_id": str(uuid.uuid4()), "db": "test-generation", "agent": "vps", "attempt": 1, "label": "Shop",
                "username": "vps@example.com", "url": "https://example.org/"}

        def answer(conf, method, path, body=None):
            asked.append((path, body))
            code, data = real(conf, method, path, body)
            return (code, dict(data, created_by=made)) if code == 200 and data.get("kind") == "request" else (code, data)
        job, handover = self.request_job(), self.job()
        with patch.object(vault, "hub", answer):
            self.assertEqual(self.ask(job), {"ok": False, "v": 2, "error": "This vault did not make this login for that "
                                                                           "request, so it does not use it."})
            self.assertEqual((self.service.seen, self.reads(), self.records()), ([], [], []))
            self.assertEqual(self.call({"op": "handover", "job": handover})["to"], "studio")
        # A request says that this broker compares the creation; a handover is asked as before.
        self.assertEqual(asked[:2], [("/helper/vault/vps", {"job": job, "kind": "request", "provenance": 1, "creation": 1}),
                                     ("/helper/vault/vps", {"job": handover, "kind": "handover", "provenance": 1})])

    # ---- a new login, and then a request with it
    def test_a_login_that_the_broker_made_goes_out_in_a_request_of_the_same_task_with_the_saved_value(self):
        self.write_setup()
        started, popen = [], subprocess.Popen
        request, label, username, address = str(uuid.uuid4()), "Shop orders", "vps@example.com", self.site + "/login"
        refusal = "This vault did not make this login for that request, so it does not use it."

        def spy(argv, *args, **kwargs):
            started.append((list(argv), dict(kwargs.get("env") or {})))
            return popen(argv, *args, **kwargs)
        can = self.call({"op": "status"})
        self.assertEqual((can.get("creates"), can.get("requests")), (True, True))      # one broker does both
        # The broker makes the login for a create job of the task. Its answer names the login, its store has the new
        # item, and the broker's record has the creation. The helper's report then ends the job at the hub.
        create = self.create_job(request, label, username, address)
        made = self.call({"op": "create", "job": create, "agent": "vps", "agent_key": KEY})
        new = {i: x for i, x in vault.LocalStore(self.conf).opened().items() if x["note"].startswith("fleet-create:")}
        self.assertEqual(len(new), 1, made)
        (item, stored), = new.items()
        ref, creates = "bws://" + item, self.journal.with_name("creates.json")
        self.assertEqual(made, {"ok": True, "v": 2, "job": create, "login": ref})
        (record,) = json.loads(creates.read_text())
        self.assertEqual((record["request_id"], record["state"], record["login"]), (request, "registered", ref))
        code, taken = self.request(f"/helper/job/vps/{create}", {"ok": True, "text": f"The vault made {ref}."},
                                   headers={"Content-Type": "application/json", "Authorization": "Bearer " + KEY})
        self.assertEqual(code, 200, taken)
        # The saved value: only the store has the password that the broker made, and a request reads the same login
        # from it.
        saved = json.loads(stored["value"])
        password = saved["password"]
        self.assertEqual((stored["key"], saved["username"], saved["url"]), (label, username, address))
        reads = len(self.reads())
        # A request of the same task with the made login. The owner gave no grant for it: the hub names the creation
        # by itself, and the broker has it in its own record. The service gets one request, with the saved value.
        order = '{"sku": "A-1", "n": 2}'
        sent = self.request_job(method="POST", path="/v1/orders", body=order, auth="basic", login=ref)
        with patch.object(vault.subprocess, "Popen", spy):
            first = self.ask(sent)
        self.assertEqual(first, {"ok": True, "v": 2, "job": sent, "status": 200, "body": '{"ok": true}', "truncated": False})
        (got,) = self.service.seen
        basic = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.assertEqual((got["method"], got["path"], got["body"], got["headers"].get_all("Authorization")),
                         ("POST", "/v1/orders", order.encode(), ["Basic " + basic]))
        self.assertIn(f"vault broker opened {ref} for request job {sent} (made by create job {create})",
                      [r["what"] for r in hub.q("SELECT what FROM log")])        # the hub's own reason
        # A second request, where the hub names the creation with an address on another origin. The broker's record
        # has no such creation: nothing more is sent, no login is read, and no record is kept.
        other = self.request_job(method="POST", path="/v1/refunds", body=order, auth="basic", login=ref)
        named, real = [], vault.hub

        def elsewhere(conf, method, path, body=None):
            code, data = real(conf, method, path, body)
            if code == 200 and data.get("kind") == "request" and data.get("job") == other:
                named.append(data["created_by"])            # what the real hub gave
                data = dict(data, created_by=dict(data["created_by"], url="https://example.org/login"))
            return code, data
        with patch.object(vault.subprocess, "Popen", spy), patch.object(vault, "hub", elsewhere):
            second = self.ask(other)
        self.assertEqual(second, {"ok": False, "v": 2, "error": refusal})
        self.assertEqual(named, [{"request_id": request, "db": "test-generation", "agent": "vps", "attempt": 1,
                                  "label": label, "username": username, "url": address}])
        self.assertEqual((len(self.service.seen), [r["job"] for r in self.records()]), (1, [sent]))
        # One login read, by the first request. The second opened the store before the hub refused it, and read nothing.
        self.assertEqual((self.reads()[reads:], [argv[0] for argv, _ in started]),
                         ([item], [self.conf["age"], self.conf["age"], self.rconf["curl"], self.conf["age"]]))
        # The password is in no answer, no log line and no record, and in no argument or environment of a child.
        self.assertEqual([line for line in self.logged if " for vps" in line],
                         [f"create job={create} for vps: ok", f"request job={sent} for vps: ok",
                          f"request job={other} for vps refused: {refusal}"])
        kept = json.dumps([dict(r) for table in ("jobs", "events", "log", "secrets")
                           for r in hub.q(f"SELECT * FROM {table}")])
        for where in (json.dumps([made, first, second]), "\n".join(self.logged), creates.read_text(),
                      self.journal.read_text(), json.dumps(started), kept):
            for secret in (password, basic):
                self.assertNotIn(secret, where)


if __name__ == "__main__":
    unittest.main()

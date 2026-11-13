"""call_api, the hub side: one job for one request, the vault's one confirmation, the stored answer, and the unknown
outcome that the agent must check. The hub runs in this process with a temporary Git kit; the tests play the vault and
the helper through the hub's own routes. No vault, no HTTP request to a service, no real key and no AI call."""
import base64
import hashlib
import html.parser
import http.client
import json
import threading
import time
import unittest
import urllib.parse
import uuid

from unittest.mock import patch

import fleet
from leftovers import scratch_home
import hub
from test_create_login import MADE, NO_GRANT, OLD_BROKER, RID, STAND_IN, CreateLogin
from test_capacity import LOGIN_A, LOGIN_B

QID = "0c3d4e5f-2222-4333-8444-555555555555"
API = {"request_id": QID, "login": LOGIN_A, "method": "POST", "path": "/v1/orders?dry=0", "body": '{"sku": "A-1", "n": 2}',
       "auth": "bearer"}


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite(CallApi(name) for name in CallApi.__dict__ if name.startswith("test_"))
    suite.addTests(JobRuns(name) for name in JobRuns.__dict__ if name.startswith("test_"))
    suite.addTests(loader.loadTestsFromTestCase(HelperJobs))
    return suite


class CallApi(CreateLogin):
    """seo has broker access and LOGIN_A and LOGIN_B in its profile, with two open tasks under its lead pma."""
    def setUp(self):
        super().setUp()
        hub.CFG["request_wait"] = 0.05                  # no machine answers in most tests
        self.addCleanup(hub.CFG.pop, "request_wait", None)

    # ---- helpers
    def report(self, agent, features=("agent_key", "broker_callers", "login_create", "login_capture", "api_request"),
               age=0, requests=True, **vault):
        """The machine's report, with a vault that sends requests."""
        data = {"features": list(features), "legacy_windows": [],
                "security": {"vault": dict({"mode": "broker", "isolated": True, "callers": True, "creates": True,
                                            "captures": True, "requests": requests,
                                            "broker_recipient": hub.agents()[agent].get("vault_recipient"),
                                            "broker_read_at": hub.now() - age}, **vault)}}
        hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES(?,?,?)",
              (agent, json.dumps(hub.validate_status(data)), hub.now() - age))

    def api(self, task=None, **changes):
        return self.call("seo", "call_api", {**API, **changes}, task or self.task)

    def job(self, request=QID):
        return super().job(request)

    def asks(self, job, **fields):
        """The vault's one question before it sends a request."""
        return self.request("/helper/vault/seo", dict({"job": job, "kind": "request", "provenance": 1, "creation": 1}, **fields))

    def says(self, job, **report):
        """The helper's report of a request job."""
        return self.request(f"/helper/job/seo/{job}", report)

    def outcomes(self):
        return [dict(r) for r in hub.q("SELECT * FROM outcomes WHERE task=? ORDER BY id", (self.task,))]

    def requests(self, job):
        return [r for r in hub.q("SELECT * FROM events WHERE agent='seo' AND kind='request' ORDER BY id")
                if json.loads(r["extra"])["job"] == job]

    def machine(self, request, *steps, **changes):
        """Run the tool while the machine acts: each step gets the job number as soon as the job is there."""
        hub.CFG["request_wait"] = 5
        seen, failed = [], []

        def act():
            try:
                deadline = time.time() + 5
                while time.time() < deadline and not self.job(request):
                    time.sleep(0.02)
                for step in steps:
                    seen.append(step(self.job(request)["id"]))
            except Exception as error:          # shown by the main thread
                failed.append(error)
        thread = threading.Thread(target=act)
        thread.start()
        try:
            return self.api(request_id=request, **changes), seen
        finally:
            thread.join()
            hub.CFG["request_wait"] = 0.05
            self.assertEqual(failed, [])

    def sent(self, request=QID):
        """A request that the vault asked for and that got no answer: its outcome is unknown. Returns the job row."""
        (text, error), _ = self.machine(request, self.asks)
        self.assertTrue(error and text.startswith(hub.REQUEST_UNKNOWN), text)
        return self.job(request)

    # ---- the tool
    def test_the_arguments_name_a_request_on_the_site_of_a_saved_login(self):
        for change in ({"request_id": "seven"}, {"request_id": 7}, {"login": "sealed:4"}, {"login": "https://example.com"},
                       {"login": None}, {"method": "get"}, {"method": "HEAD"}, {"method": None}, {"path": "v1/orders"},
                       {"path": "//other.example.com/x"}, {"path": "/a b"}, {"path": "/a#b"}, {"path": "/a\\b"},
                       {"path": "/café"}, {"path": "/a\nb"}, {"path": "/" + "x" * 2000}, {"path": ""}, {"path": None},
                       {"body": 7}, {"body": {"n": 1}}, {"body": "x" * 65537}, {"body": "é" * 32769},
                       {"body": "half\ud800pair"}, {"auth": None}, {"auth": "Bearer"}, {"auth": "token"},
                       {"auth": "header:"}, {"auth": "header:Host"}, {"auth": "header:authorization"},
                       {"auth": "header:Content-Type"}, {"auth": "header:content-length"},
                       {"auth": "header:Transfer-Encoding"}, {"auth": "header:connection"}, {"auth": "header:X Key"},
                       {"auth": "header:" + "x" * 65}, {"auth": "header:X-Key: v"}, {"auth": "header:7Key"},
                       {"auth": "header:-Key"}, {"auth": "header:_Key"}, {"auth": "header:X.Key"}, {"auth": "header:X_Key\n"}):
            with self.subTest(change=change):
                text, error = self.api(**change)
                self.assertTrue(error, text)
        self.assertEqual(self.count("jobs"), 0)
        schema = next(t for t in hub.tools_for("seo") if t["name"] == "call_api")["inputSchema"]
        self.assertEqual(sorted(schema["properties"]),
                         ["auth", "body", "headers", "login", "method", "path", "request_id", "task_id",
                          "timeout_seconds"])
        self.assertEqual(sorted(schema["required"]), ["auth", "login", "method", "path", "request_id", "task_id"])   # no site
        hub.register_fingerprints(LOGIN_B, [{"kind": "password", "len": len(STAND_IN), "hash": hashlib.sha256(
            (hub.fingerprint_salt(hub.fingerprint_label(LOGIN_B, "password")) + STAND_IN).encode()).hexdigest()}])
        for change in ({"path": "/v1?key=" + STAND_IN}, {"body": json.dumps({"key": STAND_IN})}):       # a key is no argument
            self.assertIn("Blocked: this text contains a login", self.api(**change)[0])
        self.assertEqual(self.count("jobs"), 0)
        # The forms that are a request: every method with or without a body, a body that is text, and each way to
        # send the key. No body: absent, null or empty.
        for n, change in enumerate(({"method": "GET", "body": None, "path": "/"}, {"method": "DELETE", "body": ""},
                                    {"method": "GET", "body": "{}"}, {"method": "PUT", "body": "plain text"},
                                    {"method": "PATCH", "auth": "basic", "body": "x" * 65536},
                                    {"auth": "header:X-Api-Key", "path": "/" + "x" * 1999}, {"auth": "header:X_Key"},
                                    {"auth": "header:K" + "9" * 63}, {"login": LOGIN_A.upper().replace("BWS", "bws")})):
            request = str(uuid.uuid4())
            text, error = self.api(request_id=request, **change)
            self.assertEqual(text, "The request was not sent: this machine's helper did not answer in 0 seconds.", change)
            row = self.job(request)
            self.assertEqual((row["kind"], row["login"], row["method"], row["auth"], row["body"]),
                             ("request", LOGIN_A, change.get("method", "POST"), change.get("auth", "bearer"),
                              change["body"] or None if "body" in change else API["body"]), change)
        self.assertEqual(self.count("jobs"), 9)

    def test_the_agent_sends_its_own_headers_and_only_five_stay_the_vaults(self):
        """The agent composes the request; the vault keeps the key. So every header is the agent's except the five
        that say where the key goes, carry it, or frame the request on the connection."""
        for change in ({"headers": []}, {"headers": "X: 1"}, {"headers": 7},
                       {"headers": {"X-Key": 7}}, {"headers": {"X-Key": None}}, {"headers": {"X-Key": ""}},
                       {"headers": {"X-Key": "x" * 1001}}, {"headers": {"X-Key": "a\nb"}},
                       {"headers": {"X-Key": "a\rb"}}, {"headers": {"X-Key": "a\tb"}}, {"headers": {"X-Key": "a\x00b"}},
                       {"headers": {7: "v"}}, {"headers": {"": "v"}}, {"headers": {"X Key": "v"}},
                       {"headers": {"X.Key": "v"}}, {"headers": {"7Key": "v"}}, {"headers": {"-Key": "v"}},
                       {"headers": {"X" * 65: "v"}}, {"headers": {"X-Key": "v", "x-key": "w"}},
                       {"headers": {f"X-{n}": "v" for n in range(17)}},
                       # the five that are the vault's, however they are spelled
                       {"headers": {"Host": "evil.example.com"}}, {"headers": {"host": "evil.example.com"}},
                       {"headers": {"Authorization": "Bearer x"}}, {"headers": {"AUTHORIZATION": "Bearer x"}},
                       {"headers": {"Content-Length": "0"}}, {"headers": {"Transfer-Encoding": "chunked"}},
                       {"headers": {"Connection": "close"}},
                       # and the one the agent's own auth already writes
                       {"auth": "header:X-Api-Key", "headers": {"X-Api-Key": "mine"}},
                       {"auth": "header:X-Api-Key", "headers": {"x-api-key": "mine"}}):
            with self.subTest(change=change):
                text, error = self.api(**change)
                self.assertTrue(error, text)
        self.assertEqual(self.count("jobs"), 0)
        # A login in a header value is a login in a header value: guard reads the names and the values too.
        hub.register_fingerprints(LOGIN_B, [{"kind": "password", "len": len(STAND_IN), "hash": hashlib.sha256(
            (hub.fingerprint_salt(hub.fingerprint_label(LOGIN_B, "password")) + STAND_IN).encode()).hexdigest()}])
        self.assertIn("Blocked: this text contains a login", self.api(headers={"X-Other": STAND_IN})[0])
        self.assertEqual(self.count("jobs"), 0)
        # What a refund needs: a form body, Stripe's own idempotency, an API version. Kept sorted, on the job.
        stripe = {"Content-Type": "application/x-www-form-urlencoded", "Idempotency-Key": "refund:ch_1A2B",
                  "Stripe-Version": "2026-10-01"}
        request = str(uuid.uuid4())
        text, error = self.api(request_id=request, headers=stripe, body="charge=ch_1A2B&reason=requested_by_customer")
        self.assertEqual(text, "The request was not sent: this machine's helper did not answer in 0 seconds.")
        self.assertEqual(json.loads(self.job(request)["headers"]), stripe)
        # The headers are part of what the request_id is bound to: the same id with other headers is another request.
        self.assertIn(hub.REQUEST_TAKEN, self.api(request_id=request, headers=dict(stripe, **{"Idempotency-Key": "x"}),
                                                  body="charge=ch_1A2B&reason=requested_by_customer")[0])
        self.assertIn(hub.REQUEST_TAKEN, self.api(request_id=request,
                                                  body="charge=ch_1A2B&reason=requested_by_customer")[0])
        self.assertEqual(self.count("jobs"), 1)
        # No headers is the old call, unchanged, and the vault is confirmed an empty object rather than nothing.
        plain = str(uuid.uuid4())
        self.api(request_id=plain)
        self.assertEqual(self.job(plain)["headers"], "{}")
        _, [(code, confirmed)] = self.machine(str(uuid.uuid4()), self.asks, headers=stripe)
        self.assertEqual((code, confirmed["headers"]), (200, stripe))

    def test_the_use_needs_the_grant_of_the_login_and_a_vault_that_sends_requests(self):
        names = lambda agent: [t["name"] for t in hub.tools_for(agent)]
        self.assertIn("api_request", self.request()[1]["ui_features"])
        self.assertIn("call_api", names("seo") + names("deva"))
        self.assertNotIn("call_api", names("big") + names("pma") + names("manager"))        # no broker access
        unknown = "bws://91111111-2222-4333-8444-55555555555b"
        self.assertIn(NO_GRANT, self.api(login=unknown)[0])
        for report, code in (({"features": ("agent_key", "broker_callers")}, "helper_without_api_request"),
                             ({"requests": False}, "broker_without_requests"), ({"requests": None}, "broker_status_unknown"),
                             ({"age": hub.VAULT_FRESH + 60}, "broker_status_unknown")):
            self.report("seo", **report)
            self.assertEqual(self.api(), (f"This machine's vault cannot call an API now ({code}). Ask your requester.", True))
        self.assertEqual((self.count("jobs"), self.requests(None)), (0, []))
        self.report("seo")
        self.assertIn("not sent", self.api(self.other, login=LOGIN_B)[0])                   # and in its other task
        self.assertEqual(self.job()["task"], self.other)
        hub.TEAM["agents"]["seo"]["vault"] = "none"
        self.assertEqual(self.api(request_id=str(uuid.uuid4())), ("You have no tool named call_api.", True))

    def test_the_vault_gets_the_request_once_and_the_agent_gets_the_answer(self):
        (text, error), ((code, confirmed), _) = self.machine(
            QID, self.asks, lambda job: self.says(job, ok=True, status=201, text="HTTP 201", body='{"id": 7}'))
        self.assertEqual((text, error), ('HTTP 201.\n{"id": 7}', False))
        job = self.job()
        self.assertEqual((code, confirmed), (200, {
            "ok": True, "job": job["id"], "task": f"T-{self.task}", "kind": "request", "login": LOGIN_A,
            "source": LOGIN_A, "fingerprint_salts": {k: hub.fingerprint_salt(hub.fingerprint_label(LOGIN_A, k))
                                                    for k in ("password", "totp")},
            "db": "test-generation", "attempt": 1, "request_id": QID, "method": "POST", "path": "/v1/orders?dry=0",
            "auth": "bearer", "headers": {}, "body": '{"sku": "A-1", "n": 2}'}))
        self.assertEqual(json.loads(self.requests(job["id"])[0]["extra"]), {"job": job["id"]})        # a number only
        # The answer is the hub's own record: the same call again gives it, and the machine is not asked again.
        self.assertEqual(self.api(), (text, False))
        self.assertEqual((self.count("jobs"), len(self.requests(job["id"]))), (1, 1))
        code, data = self.asks(job["id"])                   # the hub gives a request to the vault once
        self.assertEqual((code, data["error"]), (409, "this job has ended or its login was already opened"))
        self.assertEqual(self.says(job["id"], ok=True, status=500, text="HTTP 500")[0], 409)          # a second report
        self.assertEqual((self.job()["status"], self.outcomes()), (201, []))
        # No body in the request: the confirmation has no body field.
        second = str(uuid.uuid4())
        (text, error), ((_, confirmed), _) = self.machine(
            second, self.asks, lambda job: self.says(job, ok=True, status=204, text="HTTP 204"))
        self.assertEqual((text, "body" in confirmed), ("HTTP 204.", True))       # this one had the body of API
        third = str(uuid.uuid4())
        (text, error), ((_, confirmed), _) = self.machine(
            third, self.asks, lambda job: self.says(job, ok=True, status=200, text="HTTP 200", body="[]"),
            method="GET", body=None)
        self.assertEqual((text, "body" in confirmed, confirmed["method"]), ("HTTP 200.\n[]", False, "GET"))

    def test_one_request_id_is_one_request_for_every_tool(self):
        self.allow()
        self.assertIn("not sent", self.api()[0])
        for change in ({"method": "PUT"}, {"path": "/v1/orders"}, {"body": "{}"}, {"body": None}, {"auth": "basic"}):
            self.assertEqual(self.api(**change), (hub.REQUEST_TAKEN, True))
        self.assertEqual(self.api(self.other), (hub.REQUEST_TAKEN, True))                    # another task
        self.assertEqual(self.ask(request_id=QID), (hub.REQUEST_TAKEN, True))                # create_login with that ID
        self.assertEqual(self.call("seo", "save_key", {"request_id": QID, "label": "Key", "username": "k", "url":
                                                       "https://shop.example.com/", "selector": "#k"}, self.task),
                         (hub.REQUEST_TAKEN, True))
        self.assertTrue(self.ask()[0].startswith(hub.CREATE_UNKNOWN))                        # a create job with RID
        self.assertEqual(self.api(request_id=RID), (hub.REQUEST_TAKEN, True))                # and call_api with its ID
        self.assertEqual(self.count("jobs"), 2)
        with self.assertRaises(hub.sqlite3.IntegrityError):
            hub.ins("INSERT INTO jobs(agent,task,kind,created,request_id) VALUES('seo',?,'request',?,?)",
                    (self.task, hub.now(), QID))
        self.assertEqual(self.asks(self.job(RID)["id"])[0], 404)                             # each job has its kind
        self.assertEqual(self.confirm(self.job(QID)["id"])[0], 404)

    def test_a_readable_request_id_is_one_job_that_the_gate_lets_through_while_it_is_unknown(self):
        """One request_id rule for every agent tool (4 November 2026): the job of a readable id is kept by the UUID that
        vault_request makes of it, and the same id again only asks for its answer, also while its outcome is unknown."""
        self.allow()
        readable = "seo-order-A1-0001"
        kept = hub.vault_request("seo", readable)
        hub.CFG["request_wait"] = 5
        failed = []

        def act():
            try:
                deadline = time.time() + 5
                while time.time() < deadline and not self.job(kept):
                    time.sleep(0.02)
                self.asks(self.job(kept)["id"])
            except Exception as error:          # shown by the main thread
                failed.append(error)
        thread = threading.Thread(target=act)
        thread.start()
        try:
            text, error = self.api(request_id=readable)
        finally:
            thread.join()
            hub.CFG["request_wait"] = 0.05
        self.assertEqual(failed, [])
        self.assertTrue(error and text.startswith(hub.REQUEST_UNKNOWN), text)
        self.assertEqual(self.count("jobs"), 1)
        again, error = self.api(request_id=readable)
        self.assertTrue(error and again.startswith(hub.REQUEST_UNKNOWN), again)            # not STOP: the same request
        self.assertEqual(self.count("jobs"), 1)
        self.assertEqual(self.api(request_id=readable, body="{}"), (hub.REQUEST_TAKEN, True))
        self.assertIn("STOP", self.api(request_id="seo-order-A1-0002")[0])         # a new one waits for the unknown one

    # ---- sent, not sent, or not known
    def test_a_request_that_the_vault_never_asked_for_was_not_sent(self):
        text, error = self.api()
        self.assertEqual((text, error), ("The request was not sent: this machine's helper did not answer in 0 seconds.", True))
        job = self.job()
        self.assertEqual((bool(job["finished"]), job["ok"], job["released"], self.outcomes()), (True, 0, None, []))
        code, data = self.asks(job["id"])                   # a late question is refused, so nothing goes out later
        self.assertEqual((code, data["error"]), (409, "this job has ended or its login was already opened"))
        self.assertEqual(self.api(), (text, True))          # the same answer again, and nothing is asked
        self.assertEqual((self.count("jobs"), len(self.requests(job["id"]))), (1, 1))
        # The helper says that it could not ask the vault: also not sent, whatever word it uses.
        for report in ({"ok": False, "text": "this machine's vault cannot send an API request"},
                       {"ok": False, "unknown": True, "text": "the helper hit an error (OSError). Ask your requester."}):
            request = str(uuid.uuid4())
            (text, error), _ = self.machine(request, lambda job: self.says(job, **report))
            self.assertEqual(text, "The request was not sent: " + report["text"])
            self.assertEqual((self.job(request)["ok"], self.outcomes()), (0, []))
        code, data = self.says(self.job()["id"], ok=True, status=200, text="HTTP 200")     # no answer without a question
        self.assertEqual(code, 409)

    def test_a_lost_answer_is_unknown_until_the_agent_checks_the_service(self):
        job = self.sent()
        self.assertEqual((job["finished"], bool(job["unknown"]), bool(job["released"])), (None, True, True))
        (outcome,) = self.outcomes()
        self.assertEqual((outcome["state"], outcome["hold"], outcome["tool_call_id"], outcome["attempt"], outcome["title"]),
                         ("unknown", 0, f"request-{QID}", 1, f"call_api POST /v1/orders?dry=0 with {LOGIN_A}: the request can "
                                                               f"have reached the service"))
        # The same call again: the hub has no answer and the vault keeps none, so nothing is asked and nothing is sent.
        text, error = self.api()
        self.assertEqual(text, hub.REQUEST_UNKNOWN + " Last report: this machine's helper did not answer in 5 seconds.")
        self.assertEqual((self.count("jobs"), len(self.requests(job["id"]))), (1, 1))
        # Until the agent has checked, no other request that can change something goes out. A GET is a way to check.
        stop = self.api(request_id=str(uuid.uuid4()))[0]
        self.assertTrue(stop.startswith("STOP: first find out whether these earlier actions took effect") and
                        f"O-{outcome['id']}" in stop, stop)
        self.assertIn("STOP", self.call("seo", "sign_in", {"login": LOGIN_A}, self.task)[0])
        self.assertIn("not sent", self.api(request_id=str(uuid.uuid4()), method="GET", body=None)[0])
        self.assertEqual(self.count("jobs"), 2)
        text, error = self.call("seo", "resolve_outcome", {"outcome_id": f"O-{outcome['id']}", "finding": "not_done",
                                                           "evidence": "GET /v1/orders shows no order A-1"}, self.task)
        self.assertFalse(error, text)
        self.assertEqual(self.api(), (hub.REQUEST_UNKNOWN + " Last report: this machine's helper did not answer in 5 "
                                      "seconds.", True))    # the old request is still never sent again
        self.assertIn("not sent", self.api(request_id=str(uuid.uuid4()))[0])                 # a new one is a new request
        self.assertEqual(self.count("jobs"), 3)

    def test_an_answer_that_arrives_late_settles_the_outcome(self):
        job = self.sent()
        (outcome,) = self.outcomes()
        # The helper still had the answer and sends its report again: the hub keeps it and settles the outcome.
        self.assertEqual(self.says(job["id"], ok=True, status=200, text="HTTP 200", body="made")[0], 200)
        (settled,) = self.outcomes()
        self.assertEqual((settled["state"], settled["by"], settled["note"]), ("done", "hub", "the service answered (HTTP 200)"))
        self.assertEqual(self.api(), ("HTTP 200.\nmade", False))
        self.assertEqual(self.says(job["id"], ok=True, status=200, text="HTTP 200", body="made")[0], 409)   # a duplicate
        self.assertEqual((self.job()["response"], self.count("jobs"), len(self.requests(job["id"]))), ("made", 1, 1))
        self.assertIn("not sent", self.api(request_id=str(uuid.uuid4()))[0])                 # nothing is left to check

    def test_the_vaults_words_decide_between_not_sent_and_unknown(self):
        # After its question, a refusal without `unknown` is the vault's proof that nothing went out.
        (text, error), _ = self.machine(QID, self.asks, lambda job: self.says(
            job, ok=False, text="the vault broker refused: No connection to the service was made."))
        self.assertEqual(text, "The request was not sent: the vault broker refused: No connection to the service was made.")
        self.assertEqual((self.job()["ok"], self.outcomes()), (0, []))
        # With `unknown`, the request can have gone out.
        second = str(uuid.uuid4())
        (text, error), _ = self.machine(second, self.asks, lambda job: self.says(
            job, ok=False, unknown=True, text="the vault could not confirm the outcome: The service did not answer in time."))
        self.assertEqual(text, hub.REQUEST_UNKNOWN + " Last report: the vault could not confirm the outcome: The service did "
                                                     "not answer in time.")
        self.assertEqual([o["state"] for o in self.outcomes()], ["unknown"])
        # A second question for the same job: the hub refuses it, and the outcome is unknown whatever comes after.
        third = str(uuid.uuid4())
        hub.q("UPDATE outcomes SET state='done' WHERE task=?", (self.task,))        # the gate is free for a new request
        (text, error), seen = self.machine(third, self.asks, self.asks, lambda job: self.says(
            job, ok=False, text="the vault broker refused: The hub did not confirm this vault job."))
        self.assertEqual([code for code, _ in seen], [200, 409, 200])
        self.assertTrue(text.startswith(hub.REQUEST_UNKNOWN), text)
        row = self.job(third)
        self.assertEqual((row["finished"], bool(row["unknown"])), (None, True))
        self.assertEqual(self.outcomes()[-1]["tool_call_id"], f"request-{third}")
        # An answer with no status of a service is no answer.
        fourth = str(uuid.uuid4())
        hub.q("UPDATE outcomes SET state='done' WHERE task=?", (self.task,))
        for status in (99, 600, "200", True, None):
            (text, error), _ = self.machine(fourth, *(() if self.job(fourth) else (self.asks,)),
                                            lambda job: self.says(job, ok=True, status=status, text="HTTP"))
            self.assertTrue(text.startswith(hub.REQUEST_UNKNOWN), (status, text))

    def test_a_stop_cuts_a_request_and_a_new_attempt_never_sends_it_again(self):
        job = self.sent()                                   # the vault asked for it; no answer yet
        hub.q("UPDATE jobs SET unknown=NULL, result=NULL WHERE id=?", (job["id"],))         # as while the request runs
        hub.q("DELETE FROM outcomes WHERE task=?", (self.task,))
        waiting = str(uuid.uuid4())                         # a second request, which the vault did not ask for yet
        hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created,request_id,attempt,method,path,auth) "
                "VALUES('seo',?,'request',?,'',?,?,1,'GET','/v1/orders','bearer')", (self.task, LOGIN_A, hub.now(), waiting))
        held, _ = hub.request_hold(self.task, "stop", "owner", "")
        control = hub.q1("SELECT * FROM events WHERE agent='seo' AND kind='control' ORDER BY id DESC LIMIT 1")
        self.assertEqual(json.loads(control["extra"]), {"hold": held["id"], "action": "stop", "attempt": 1,
                                                        "generation": "test-generation", "requests": 2})
        code, data = self.asks(self.job(waiting)["id"])     # the hub gives no request to a vault during a hold
        self.assertEqual((code, data["error"]), (409, "the task of this job is paused or stopped"))
        code, data = self.request("/helper/control/seo", {"hold": held["id"], "confirmed": True, "ran": False,
                                                          "detail": "interrupted and closed; the vault ended 1 request(s)",
                                                          "flushed": [], "ended": 0})
        self.assertEqual((code, data["state"]), (200, "stopped"))
        row = self.job()
        self.assertEqual((row["finished"], bool(row["unknown"]), row["result"]), (None, True, "the task was stopped while "
                                                                                             "the request ran."))
        (outcome,) = self.outcomes()
        self.assertEqual((outcome["state"], outcome["hold"], outcome["tool_call_id"]), ("unknown", held["id"], f"request-{QID}"))
        row = self.job(waiting)                             # the vault never asked for this one: it was not sent
        self.assertEqual((bool(row["finished"]), row["ok"], row["result"]), (True, 0, "The request was not sent: the task "
                                                                                     "was stopped first."))
        # The helper's own report of the cut request is still taken, before or after the stop's result: the
        # outcome is the one of this stop in both orders.
        self.assertEqual(self.says(job["id"], ok=False, unknown=True, text="stopped")[0], 200)
        self.assertEqual((self.job()["finished"], self.outcomes()[0]["state"], self.outcomes()[0]["hold"]),
                         (None, "unknown", held["id"]))
        early = dict(self.job(), request_id=str(uuid.uuid4()))        # the same in the other order, as functions
        hub.request_unknown(early, "the vault could not confirm the outcome")
        hub.request_unknown(early, "the task was stopped while the request ran.", hold=held["id"])
        self.assertEqual([o["hold"] for o in self.outcomes()], [held["id"], held["id"]])
        hub.q("DELETE FROM outcomes WHERE tool_call_id=?", (f"request-{early['request_id']}",))
        # Resume makes a new attempt. The request belongs to the old one: it is refused, and nothing is asked or sent.
        hub.release_hold(self.task, "check", "owner")
        self.assertEqual(self.row()["attempt"], 2)
        before = len(self.requests(job["id"]))
        self.assertEqual(self.api(), (hub.REQUEST_OLD_ATTEMPT, True))
        self.assertEqual(self.api(method="PUT"), (hub.REQUEST_TAKEN, True))                  # and it cannot change
        self.assertEqual((len(self.requests(job["id"])), self.count("jobs")), (before, 2))
        self.assertEqual(self.outcomes()[0]["state"], "unknown")                             # its record is as it was
        self.assertIn("STOP", self.api(request_id=str(uuid.uuid4()))[0])
        text, error = self.call("seo", "resolve_outcome", {"outcome_id": f"O-{outcome['id']}", "finding": "done",
                                                           "evidence": "GET /v1/orders shows the order"}, self.task)
        self.assertFalse(error, text)
        self.assertIn("not sent", self.api(request_id=str(uuid.uuid4()))[0])                 # a new request, new attempt
        self.assertEqual((self.count("jobs"), hub.q1("SELECT attempt FROM jobs ORDER BY id DESC LIMIT 1")["attempt"]), (3, 2))

    def test_a_pause_of_an_attempt_that_asked_for_a_request_resumes_in_a_new_attempt(self):
        alive = lambda: hub.q("INSERT INTO agents(name,alive,alive_ts,last_seen) VALUES('seo',?,?,?) ON CONFLICT(name) "
                              "DO UPDATE SET alive=excluded.alive, alive_ts=excluded.alive_ts, last_seen=excluded.last_seen",
                              (f"T-{self.task},T-{self.other}", hub.now(), hub.now()))       # a check-in with its list

        def pause_and_resume(task):
            held, _ = hub.request_hold(task, "pause", "owner", "")
            code, data = self.request("/helper/control/seo", {"hold": held["id"], "confirmed": True, "ran": False,
                                                              "detail": "interrupted", "flushed": [], "ended": 0})
            self.assertEqual((code, data["state"]), (200, "stopped"))
            alive()                                         # the paused session is still there
            return hub.release_hold(task, "check", "owner")[1]
        # A task with no API request: the pause goes on in its own session, as before.
        self.assertEqual(pause_and_resume(self.other), "message to its session")
        self.assertEqual(self.row(self.other)["attempt"], 1)
        # A request that ended before the pause (no child for the vault to end): the vault can still have its guard
        # for this attempt, so the task goes on in a new attempt. The old request and its answer stay.
        (text, error), _ = self.machine(QID, self.asks, lambda job: self.says(job, ok=True, status=200, text="HTTP 200"))
        self.assertEqual(text, "HTTP 200.")
        self.assertEqual(pause_and_resume(self.task), "new session")
        self.assertEqual((self.row()["attempt"], self.job()["attempt"], self.job()["status"]), (2, 1, 200))
        self.assertEqual(self.api(), (hub.REQUEST_OLD_ATTEMPT, True))                        # its ID stays with attempt 1
        self.assertIn("not sent", self.api(request_id=str(uuid.uuid4()))[0])                 # a new request in attempt 2
        # The new attempt has asked for a request too: the next pause again goes on in a new attempt.
        self.assertEqual(pause_and_resume(self.task), "new session")
        self.assertEqual(self.row()["attempt"], 3)

    def test_a_cancel_ends_the_vaults_request_through_the_existing_stop(self):
        holds = lambda task: [dict(r) for r in hub.q("SELECT * FROM holds WHERE task=? ORDER BY id", (task,))]
        controls = lambda: [json.loads(r["extra"]) for r in hub.q("SELECT * FROM events WHERE agent='seo' AND kind='control' ORDER BY id")]
        result = lambda hold, **report: self.request("/helper/control/seo", dict(
            {"hold": hold, "ran": False, "flushed": [], "ended": 0}, **report))
        # A task with no API request: a cancel is as before. No hold, and nothing for the helper to end.
        text, error = self.call("pma", "cancel_task", {"task_id": f"T-{self.other}", "reason": "not needed"}, self.blog)
        self.assertEqual((error, self.row(self.other)["state"], holds(self.other), controls()), (False, "canceled", [], []))
        # A request that the vault asked for is not finished, and a second one waits for the vault.
        job = self.sent()
        hub.q("UPDATE jobs SET unknown=NULL, result=NULL WHERE id=?", (job["id"],))         # as while the request runs
        hub.q("DELETE FROM outcomes WHERE task=?", (self.task,))
        waiting = str(uuid.uuid4())
        hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created,request_id,attempt,method,path,auth) "
                "VALUES('seo',?,'request',?,'',?,?,1,'GET','/v1/orders','bearer')", (self.task, LOGIN_A, hub.now(), waiting))
        text, error = self.call("pma", "cancel_task", {"task_id": f"T-{self.task}", "reason": "changed plan"}, self.shop)
        self.assertEqual((text, error, self.row()["state"]), (f"T-{self.task} is canceled.", False, "canceled"))
        (hold,) = holds(self.task)                          # the existing stop, for the helper
        self.assertEqual((hold["kind"], hold["state"], hold["by"], hold["attempt"], hold["note"]),
                         ("stop", "requested", "pma", 1, "canceled while an API request can run"))
        self.assertEqual(controls(), [{"hold": hold["id"], "action": "stop", "attempt": 1, "generation": "test-generation",
                                       "requests": 2}])
        # The helper is away: the hold waits on the canceled task, and nothing says that the request ended.
        self.assertIn("already canceled", self.call("pma", "cancel_task", {"task_id": f"T-{self.task}", "reason": "again"},
                                                    self.shop)[0])
        self.assertEqual((holds(self.task)[0]["state"], self.job()["finished"], self.job()["unknown"], self.outcomes()),
                         ("requested", None, None, []))
        # The helper is back, and the vault gave no proof. The result says so. The request that the vault asked for
        # is unknown, with an outcome; it is not "not sent", and it does not go away with the task.
        code, data = result(hold["id"], confirmed=False, detail="the vault did not prove that its request of the task ended")
        self.assertEqual((code, data["state"]), (200, "not_confirmed"))
        (hold,) = holds(self.task)
        self.assertEqual((hold["state"], hold["released_by"], hold["resume_mode"], hold["detail"]),
                         ("released", "hub", "task ended", "stop not confirmed: the vault did not prove that its request "
                                                             "of the task ended"))
        row = self.job()
        self.assertEqual((row["finished"], bool(row["unknown"]), row["result"]),
                         (None, True, "the task was canceled while the request ran."))
        (outcome,) = self.outcomes()
        self.assertEqual((outcome["state"], outcome["hold"], outcome["tool_call_id"]), ("unknown", hold["id"], f"request-{QID}"))
        row = self.job(waiting)                             # the vault never asked for this one, and cannot ask now
        self.assertEqual((row["ok"], row["result"]), (0, "The request was not sent: the task was canceled first."))
        self.assertEqual(self.asks(self.job()["id"])[0], 409)
        self.assertEqual(result(hold["id"], confirmed=True, detail="late")[0], 409)         # one result for one hold
        # A parent that is canceled: its subtask with a request gets the same stop, and here the vault proves the end.
        parent = self.create("manager", "pma", why="pma leads seo")
        child = self.create("pma", "seo", parent)
        request = str(uuid.uuid4())
        (text, error), _ = self.machine(request, self.asks, task=child)
        self.assertTrue(text.startswith(hub.REQUEST_UNKNOWN), text)
        text, error = self.call("manager", "cancel_task", {"task_id": f"T-{parent}", "reason": "the work ended"})
        self.assertEqual((error, self.row(parent)["state"], self.row(child)["state"], holds(parent)), (False, "canceled", "canceled", []))
        (hold,) = holds(child)
        self.assertEqual((hold["state"], hold["by"], controls()[-1]["hold"], controls()[-1]["requests"]),
                         ("requested", "pma", hold["id"], 1))
        code, data = result(hold["id"], confirmed=True, detail="interrupted and closed; the vault ended 1 request(s)")
        self.assertEqual((code, data["state"]), (200, "stopped"))
        (hold,) = holds(child)
        self.assertEqual((hold["state"], hold["resume_mode"], hold["detail"]),
                         ("released", "task ended", "stop confirmed: interrupted and closed; the vault ended 1 request(s)"))
        mine = hub.q1("SELECT * FROM outcomes WHERE task=?", (child,))
        self.assertEqual((mine["state"], mine["hold"], mine["tool_call_id"], bool(self.job(request)["unknown"])),
                         ("unknown", hold["id"], f"request-{request}", True))
        kept = [r["what"] for r in hub.q("SELECT what FROM log ORDER BY id")]
        self.assertTrue(any(w.startswith(f"H-{hold['id']} on T-{child}: stopped") for w in kept), kept[-6:])

    def test_the_vault_asks_only_while_the_task_the_attempt_and_the_grant_stand(self):
        cases = []

        def refused(error, change, undo):
            request = str(uuid.uuid4())
            hub.CFG["request_wait"] = 5
            result = []
            thread = threading.Thread(target=lambda: result.append(self.api(request_id=request)))
            thread.start()
            deadline = time.time() + 5
            while time.time() < deadline and not self.job(request):
                time.sleep(0.02)
            job = self.job(request)["id"]
            change()
            code, data = self.asks(job)
            undo()
            self.says(job, ok=False, text="the vault broker refused: the hub did not confirm this job")
            thread.join()
            hub.CFG["request_wait"] = 0.05
            cases.append((code, data.get("error"), result[0][0][:24], self.job(request)["released"]))
            self.assertEqual((code, data["error"]), (409, error))
        hold = []
        refused("the task of this job is paused or stopped", lambda: hold.append(self.hold()),
                lambda: hub.q("UPDATE holds SET state='released' WHERE id=?", (hold[0],)))
        refused("the attempt that asked for this request has ended",
                lambda: hub.q("UPDATE tasks SET attempt=2 WHERE id=?", (self.task,)),
                lambda: hub.q("UPDATE tasks SET attempt=1 WHERE id=?", (self.task,)))
        refused("this agent has no broker access", lambda: hub.TEAM["agents"]["seo"].update(vault="none"),
                lambda: hub.TEAM["agents"]["seo"].update(vault="broker"))
        refused("the task of this job has ended", lambda: hub.q("UPDATE tasks SET state='canceled' WHERE id=?", (self.task,)),
                lambda: hub.q("UPDATE tasks SET state='working' WHERE id=?", (self.task,)))
        # None of them was given to the vault, so each one was not sent, with no outcome to check.
        self.assertEqual([(text, released) for _, _, text, released in cases], [("The request was not sent", None)] * 4)
        self.assertEqual(self.outcomes(), [])

    # ---- the answer
    def test_the_body_is_masked_before_the_cut_and_held_back_when_a_login_stays(self):
        hub.register_fingerprints(LOGIN_B, [{"kind": "password", "len": len(STAND_IN), "hash": hashlib.sha256(
            (hub.fingerprint_salt(hub.fingerprint_label(LOGIN_B, "password")) + STAND_IN).encode()).hexdigest()}])
        quoted = 'stand-in"value\\0123456789-with-a-quote'      # a registered value that JSON writes with escapes
        hub.register_fingerprints(LOGIN_A, [{"kind": "password", "len": len(quoted), "hash": hashlib.sha256(
            (hub.fingerprint_salt(hub.fingerprint_label(LOGIN_A, "password")) + quoted).encode()).hexdigest()}])
        accent = "stand-in-\u00e9-value-0123456789"            # JSON writes its letter as \\u00e9
        hub.register_fingerprints(LOGIN_A, [{"kind": "totp", "len": len(accent), "hash": hashlib.sha256(
            (hub.fingerprint_salt(hub.fingerprint_label(LOGIN_A, "totp")) + accent).encode()).hexdigest()}])
        self.assertEqual((hub.secret_hit(accent), "\\u00e9" in json.dumps(accent), hub.secret_hit(json.dumps({"password": accent}))),
                         (True, True, True))
        answers = lambda **report: (lambda job: self.says(job, ok=True, text="HTTP", **report))
        cut = hub.API_ANSWER
        held = " The hub held the body back: it had a registered login."
        nothing = ("None of it is kept: it is one run of characters with no space across the cut, and a part of it "
                   "could be part of a login. Ask for less of it.")
        cases = (
            # a value that JSON writes with \\uXXXX: found in the standard form, with upper-case hex, with every
            # character written as an escape, and when the cut is inside it
            ({"status": 200, "body": json.dumps({"password": accent})}, "HTTP 200." + held),
            ({"status": 200, "body": json.dumps({"password": accent}).replace("\\u00e9", "\\u00E9")}, "HTTP 200." + held),
            ({"status": 200, "body": '{"p": "' + "".join(f"\\u{ord(c):04x}" for c in accent) + '"}'}, "HTTP 200." + held),
            ({"status": 200, "body": "x" * (cut - 12) + json.dumps(accent)}, "HTTP 200." + held),
            ({"status": 200, "body": "a lone half \ud83d is no text, and \\\\u00e9 is no letter"},
             "HTTP 200.\na lone half \ufffd is no text, and \\\\u00e9 is no letter"),
            # a registered value in the body is masked
            ({"status": 200, "body": f'{{"token": "{STAND_IN}", "n": 1}}'}, 'HTTP 200.\n{"token": "' + hub.MASK + '", "n": 1}'),
            # a value across the cut is masked whole, and then the body is cut, where no login can be cut in two: the
            # run of the mask that the cut falls in is kept whole (cut_whole with keep)
            ({"status": 200, "body": "x" * (cut - 10) + " " + STAND_IN + " tail"},
             "HTTP 200. The body was cut.\n" + "x" * (cut - 10) + " " + hub.MASK.split()[0]),
            # a value that is there in another form holds the whole body back; the status stays
            ({"status": 201, "body": json.dumps({"password": quoted})}, "HTTP 201. The hub held the body back: it had a "
                                                                        "registered login."),
            ({"status": 200, "withheld": "key"}, "HTTP 200. The vault held the body back: it had the key."),
            ({"status": 200, "withheld": "binary", "body": "ignored"}, "HTTP 200. The vault held the body back: it is no text."),
            # a body that the vault cut loses the run that it ends in, which the vault's cut may have cut in two; a run
            # across the hub's own cut is kept whole when it ends within API_ANSWER more characters, and none of it
            # when it goes on further
            ({"status": 206, "body": "the part", "truncated": True}, "HTTP 206. The body was cut.\nthe"),
            ({"status": 206, "body": "part", "truncated": True}, "HTTP 206. The body was cut. " + nothing),
            ({"status": 302, "body": ""}, "HTTP 302."),
            ({"status": 500, "body": "x" * (cut + 5)}, "HTTP 500.\n" + "x" * (cut + 5)),
            ({"status": 500, "body": "x" * (2 * cut + 5)}, "HTTP 500. The body was cut. " + nothing))
        for report, expected in cases:
            request = str(uuid.uuid4())
            (text, error), _ = self.machine(request, self.asks, answers(**report))
            self.assertEqual((text, error), (expected, False), report)
            kept = json.dumps([dict(r) for r in hub.q("SELECT * FROM jobs WHERE request_id=?", (request,))])
            self.assertNotIn(STAND_IN, kept)
            self.assertNotIn("0123456789-with-a-quote", kept)
            self.assertNotIn("value-0123456789", kept)
        big = {"ok": True, "status": 200, "text": "HTTP 200", "body": "x" * 600000}        # more than the hub takes
        (text, error), ((code, _), (late, _)) = self.machine(str(uuid.uuid4()), self.asks, lambda job: self.says(job, **big))
        self.assertEqual((late, text.startswith(hub.REQUEST_UNKNOWN)), (413, True))

    def test_a_login_that_the_task_made_is_used_only_with_the_vaults_own_record(self):
        self.allow()
        self.make()                                         # create_login made MADE in this task
        request = str(uuid.uuid4())
        (text, error), ((code, data),) = self.machine(request, lambda job: self.request(
            "/helper/vault/seo", {"job": job, "kind": "request", "provenance": 1}), login=MADE)    # a vault without the marker
        self.assertEqual((code, data["error"]), (409, OLD_BROKER))
        self.assertIn("The request was not sent", text)     # the vault got nothing, so nothing went out
        self.assertIn(NO_GRANT, self.api(request_id=str(uuid.uuid4()), login="bws://91111111-2222-4333-8444-55555555555b")[0])
        second = str(uuid.uuid4())
        hub.CFG["request_wait"] = 5
        result = []
        thread = threading.Thread(target=lambda: result.append(self.api(request_id=second, login=MADE)))
        thread.start()
        deadline = time.time() + 5
        while time.time() < deadline and not self.job(second):
            time.sleep(0.02)
        job = self.job(second)["id"]
        code, data = self.asks(job)
        self.assertEqual((code, data["login"], data["created_by"]["request_id"], data["created_by"]["label"]),
                         (200, MADE, RID, "Shop newsletter"))
        salt = data["fingerprint_salts"]["password"]
        code, stored = self.request("/helper/vault/seo/fingerprints", {"job": job, "fingerprints": [
            {"kind": "password", "hash": hashlib.sha256((salt + "another-stand-in-0001").encode()).hexdigest(), "len": 21}]})
        self.assertEqual(code, 200, stored)                 # the fingerprints of the login, as for a sign-in
        self.says(job, ok=True, status=200, text="HTTP 200", body="ok")
        thread.join()
        hub.CFG["request_wait"] = 0.05
        self.assertEqual(result[0], ("HTTP 200.\nok", False))
        self.assertIn(NO_GRANT, self.api(self.other, request_id=str(uuid.uuid4()), login=MADE)[0])    # its other task

    def test_the_leak_scan_reads_every_text_of_a_job_also_the_request_and_its_answer(self):
        columns = ("login", "result", "label", "username", "url", "selector", "source_url", "path", "body", "auth",
                   "headers", "response")
        rows = [hub.ins(f"INSERT INTO jobs(agent,task,kind,created,{column}) VALUES('seo',?,'request',?,?)",
                        (self.task, hub.now(), f'{{"note": "{STAND_IN}"}}')) for column in columns]
        self.assertEqual(hub.leak_scan(), [])               # no login has this value: the texts are only texts
        # The value is registered later, as a vault does it for a key that a service returned and a task then saved.
        hub.register_fingerprints(LOGIN_B, [{"kind": "password", "len": len(STAND_IN), "hash": hashlib.sha256(
            (hub.fingerprint_salt(hub.fingerprint_label(LOGIN_B, "password")) + STAND_IN).encode()).hexdigest()}])
        self.assertEqual(hub.leak_scan(), [f"jobs row {row}" for row in rows])

    # ---- the practice send of the hub, for a real request through Fleet and a vault
    def test_the_practice_send_checks_a_basic_login_counts_each_send_and_can_hold_its_answer(self):
        word, salt = "practice-stand-in-0001", "a" * 32             # no real login: a stand-in with its fingerprint
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES('pilot-site-a',?,?,?,'pilot-a')",
                (salt, hashlib.sha256((salt + word).encode()).hexdigest(), len(word)))
        basic = lambda text: {"Content-Type": "application/json", "Authorization": "Basic " + base64.b64encode(text.encode()).decode()}
        plain = {"Content-Type": "application/json"}
        send = lambda headers, **body: self.request("/outbox", dict({"key": "K-1", "text": "one"}, **body), headers=headers)
        count = lambda key="K-1": hub.q1("SELECT COUNT(*) c FROM outbox WHERE key=?", (key,))["c"]
        self.assertEqual(send(plain), (200, {"ok": True, "key": "K-1", "count": 1}))            # as before: no header
        self.assertEqual(send(basic("pilot-a:" + word)), (200, {"ok": True, "key": "K-1", "count": 2, "auth": "pilot-a"}))
        self.assertEqual(send(basic("pilot-a:" + word))[1]["count"], 3)     # each send counts: the service hides no replay
        for wrong in (basic("pilot-a:wrong-word-0001"), basic("nobody:" + word), basic("pilot-a"), basic(":" + word),
                      basic("pilot-a:" + word + " "), dict(plain, Authorization="Bearer " + word),
                      dict(plain, Authorization="Basic not base64!"), dict(plain, Authorization=""),
                      dict(plain, Authorization="basic " + base64.b64encode(("pilot-a:" + word).encode()).decode())):
            self.assertEqual(send(wrong), (401, {"error": "wrong authorization"}), wrong)
        self.assertEqual(count(), 3)                                # a refused send recorded nothing
        kept = json.dumps([dict(r) for table in ("outbox", "log") for r in hub.q(f"SELECT * FROM {table}")])
        self.assertNotIn(word, kept)
        self.assertIn("send recorded for key K-1 (now 2), signed as pilot-a", kept)
        self.assertIn("a practice send with a wrong Authorization header was refused", kept)
        for hold in (-1, hub.PRACTICE_HOLD + 1, "5", True, None):
            self.assertEqual(send(plain, hold=hold)[0], 400, hold)
        self.assertEqual(count(), 3)
        # A held answer: the send is recorded at once, the answer waits, and the hub serves other calls meanwhile.
        done, started = [], time.time()
        thread = threading.Thread(target=lambda: done.append(self.request(
            "/outbox", {"key": "K-2", "text": "held", "hold": 1.2}, headers=basic("pilot-a:" + word))))
        thread.start()
        deadline = time.time() + 1
        while time.time() < deadline and not count("K-2"):
            time.sleep(0.02)
        self.assertEqual((count("K-2"), done), (1, []))             # the service has it; the caller still waits
        self.assertEqual(self.request()[0], 200)                    # no lock of the hub is held
        self.assertLess(time.time() - started, 1.1)
        thread.join()
        self.assertEqual(done, [(200, {"ok": True, "key": "K-2", "count": 1, "auth": "pilot-a"})])
        self.assertGreaterEqual(time.time() - started, 1.2)

    def test_the_practice_site_takes_a_login_that_a_task_made_for_it_by_the_fingerprint_of_its_saved_value(self):
        here = "http://%s:%d" % hub.hub_address()                   # the origin of this hub: its address in team.json
        self.assertNotEqual(hub.origin(here), hub.origin(self.base))        # the calls of this test go to another one
        word, salt = "practice-stand-in-0001", "a" * 32             # the owner's practice login, as before
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES('pilot-site-a',?,?,?,'pilot-a')",
                (salt, hashlib.sha256((salt + word).encode()).hexdigest(), len(word)))
        self.allow()
        ref = lambda n: f"bws://{n}1111111-2222-4333-8444-55555555555b"
        value = lambda name: f"made-stand-in-{name}-0123456789"     # what a vault could have made; never a real value

        def made(login, name, tool="create_login", finish=True, **args):
            """A login that the vault made for a job of seo, through the routes that a vault and a helper call: the
            hub gets the login's name and the fingerprint of its saved value."""
            request = str(uuid.uuid4())
            self.call("seo", tool, dict({"request_id": request, "label": "Practice account"}, **args), self.task)
            job = self.job(request)["id"]
            steps = [self.confirm(job, kind="create" if tool == "create_login" else "capture"), self.created(job, login)]
            mark = hub.fingerprint_salt(hub.fingerprint_label(login, "password"))
            steps.append(self.request("/helper/vault/seo/fingerprints", {"job": job, "fingerprints": [
                {"kind": "password", "hash": hashlib.sha256((mark + value(name)).encode()).hexdigest(), "len": len(value(name))}]}))
            if finish:
                steps.append(self.done(job))
            self.assertEqual([code for code, _ in steps], [200] * len(steps), steps)
            self.assertEqual(steps[1][1]["fingerprint_salts"]["password"], mark)

        made(MADE, "same", username="pilot-a", url=here + "/site/login")        # the user name of the practice login
        made(ref(5), "new", username="made-user", url=here + "/account/new")
        made(ref(6), "key", tool="save_key", username="key-user", url=here + "/outbox", selector="#key")
        made(ref(7), "far", username="far-user", url="https://news.example.com/signup")        # another site
        made(ref(8), "host", username="host-user", url=self.base + "/site/login")       # the address of the calls
        made(ref(9), "tls", username="tls-user", url=here.replace("http:", "https:") + "/site/login")
        made(ref("a"), "port", username="port-user", url=here[:-1] + "0/site/login")
        made(ref("b"), "open", username="open-user", url=here + "/site/login", finish=False)    # its job did not end
        seed = "made-stand-in-seed-0123456789"                      # an authenticator seed is no password
        hub.register_fingerprints(ref(5), [{"kind": "totp", "len": len(seed), "hash": hashlib.sha256(
            (hub.fingerprint_salt(hub.fingerprint_label(ref(5), "totp")) + seed).encode()).hexdigest()}])

        def send(user, word):
            return self.request("/outbox", {"key": "K-9", "text": "one"}, headers={
                "Content-Type": "application/json",
                "Authorization": "Basic " + base64.b64encode(f"{user}:{word}".encode()).decode()})
        sent = lambda n, user, **more: (200, dict({"ok": True, "key": "K-9", "count": n, "auth": user}, **more))
        self.assertEqual(send("pilot-a", word), sent(1, "pilot-a"))                 # the practice login: as before
        self.assertEqual(send("made-user", value("new")), sent(2, "made-user", login=ref(5), shown=False))  # by its value
        self.assertEqual(send("key-user", value("key")), sent(3, "key-user", login=ref(6), shown=False))    # a saved key
        refused = [("pilot-a", value("same")),                      # no made login signs in as the practice login
                   ("made-user", value("new") + "x"), ("made-user", value("new")[:-1]), ("made-user", ""),
                   ("made-user", value("same")), ("pilot-a", value("new")), ("nobody", value("new")),
                   ("made-user", seed),                             # the fingerprint of a seed signs nobody in
                   ("far-user", value("far")), ("host-user", value("host")), ("tls-user", value("tls")),
                   ("port-user", value("port")), ("open-user", value("open"))]
        for user, wrong in refused:
            self.assertEqual(send(user, wrong), (401, {"error": "wrong authorization"}), user)
        self.assertEqual(hub.q1("SELECT COUNT(*) c FROM outbox WHERE key='K-9'")["c"], 3)

        # The sign-in form of the practice site has the same check.
        def sign_in(user, word):
            """The form as a browser sends it: (the status, the next address, the page)."""
            at = urllib.parse.urlsplit(self.base)
            conn = http.client.HTTPConnection(at.hostname, at.port, timeout=5)
            self.addCleanup(conn.close)
            conn.request("POST", "/site/login", urllib.parse.urlencode({"username": user, "password": word}),
                         {"Content-Type": "application/x-www-form-urlencoded"})
            answer = conn.getresponse()
            return answer.status, answer.getheader("Location"), answer.read().decode()
        pages = []
        for user, right in (("pilot-a", word), ("key-user", value("key")), ("made-user", value("new"))):
            pages.append(sign_in(user, right))
            self.assertEqual((pages[-1][:2], hub.kv_get("site_user")), ((303, "/site/account"), user))
        for user, wrong in refused:
            pages.append(sign_in(user, wrong))
            self.assertEqual((pages[-1][0], "Wrong login." in pages[-1][2]), (200, True), user)
        self.assertEqual(hub.kv_get("site_user"), "made-user")      # a refused sign-in changed nothing

        # No value is in an answer or in the hub's records; the log names the made login.
        kept = json.dumps(pages) + json.dumps([dict(r) for table in ("outbox", "log", "kv", "jobs", "events", "secrets")
                                               for r in hub.q(f"SELECT * FROM {table}")])
        for text in [word, seed] + [value(name) for name in ("same", "new", "key", "far", "host", "tls", "port", "open")]:
            self.assertNotIn(text, kept)
        for line in ("send recorded for key K-9 (now 1), signed as pilot-a\"",
                     f"send recorded for key K-9 (now 2), signed as made-user with the made login {ref(5)}",
                     f"send recorded for key K-9 (now 3), signed as key-user with the made login {ref(6)}",
                     "a sign-in to the practice site succeeded as pilot-a\"",
                     f"a sign-in to the practice site succeeded as key-user with the made login {ref(6)}",
                     f"a sign-in to the practice site succeeded as made-user with the made login {ref(5)}"):
            self.assertIn(line, kept)
        self.assertNotIn("pilot-a with the made login", kept)       # the practice identity stayed the owner's login
        self.assertEqual(kept.count("a sign-in to the practice site FAILED"), len(refused))

    def test_the_key_page_shows_a_new_key_each_time_and_a_saved_copy_of_the_last_one_is_shown(self):
        here = "http://%s:%d" % hub.hub_address()                   # the origin of this hub: its address in team.json
        self.allow()
        fingerprint = lambda salt, text: hashlib.sha256((salt + text).encode()).hexdigest()
        ref = lambda n: f"bws://{n}1111111-2222-4333-8444-55555555555b"
        keys, salts = [], []                                        # of each page: its key, and the salt of its record

        def render():
            """The key page as a browser gets it, and the hub's one record of it. Returns the key of the page."""
            at = urllib.parse.urlsplit(self.base)
            conn = http.client.HTTPConnection(at.hostname, at.port, timeout=5)
            self.addCleanup(conn.close)
            conn.request("GET", "/site/key")
            answer = conn.getresponse()
            page = answer.read().decode()
            self.assertEqual((answer.status, answer.getheader("Content-Type"), answer.getheader("Cache-Control")),
                             (200, "text/html; charset=utf-8", "no-store"))
            fields, reader = [], html.parser.HTMLParser()           # the attributes of each input field of the page
            reader.handle_starttag = lambda tag, attrs: tag == "input" and fields.append(dict(attrs))
            reader.feed(page)
            self.assertEqual(len(fields), 1, page)                  # the page has one field
            key = fields[0].pop("value", None) or ""
            self.assertEqual(fields[0], {"id": "key", "type": "password", "readonly": None, "autocomplete": "off"})
            self.assertRegex(key, r"\A[A-Za-z0-9_-]{32}\Z")
            self.assertNotIn(hub.MASK, page)                        # the page is sent as it is: the field has the key
            rows = [dict(r) for r in hub.q("SELECT * FROM secrets WHERE label=?", (hub.SITE_KEY,))]
            self.assertEqual(len(rows), 1, rows)                    # one record: a new page replaces the one before
            salt = rows[0]["salt"]
            self.assertRegex(salt, r"\A[0-9a-f]{32}\Z")
            self.assertEqual((rows[0]["hash"], rows[0]["len"], rows[0]["username"]), (fingerprint(salt, key), 32, ""))
            self.assertTrue(key not in keys and salt not in salts)  # a new key and a new salt each time
            self.assertTrue(hub.secret_hit(key))                    # the key is a registered value at once
            keys.append(key)
            salts.append(salt)
            return key

        def made(login, word, tool, **args):
            """A login that the vault made for a job of seo, through the routes that a vault and a helper call: the hub
            gets the login's name and the fingerprint of its saved value. Returns the salt of that fingerprint."""
            request = str(uuid.uuid4())
            self.call("seo", tool, dict({"request_id": request, "label": "Practice login"}, **args), self.task)
            job = self.job(request)["id"]
            steps = [self.confirm(job, kind="capture" if tool == "save_key" else "create"), self.created(job, login)]
            self.assertEqual([code for code, _ in steps], [200, 200], steps)
            salt = steps[1][1]["fingerprint_salts"]["password"]     # the salt that the hub gives the vault for this login
            code, stored = self.request("/helper/vault/seo/fingerprints", {"job": job, "fingerprints": [
                {"kind": "password", "hash": fingerprint(salt, word), "len": len(word)}]})
            self.assertEqual((code, stored), (200, {"ok": True, "job": job, "stored": 1, "known": 0}))     # a row of its own
            self.assertEqual(self.done(job)[0], 200)
            return salt

        def send(user, word):
            return self.request("/outbox", {"key": "K-7", "text": "one"}, headers={
                "Content-Type": "application/json",
                "Authorization": "Basic " + base64.b64encode(f"{user}:{word}".encode()).decode()})
        sent = lambda n, user, **more: (200, dict({"ok": True, "key": "K-7", "count": n, "auth": user}, **more))

        old, saved = render(), render()
        self.assertFalse(hub.secret_hit(old))                       # the record of the page before is gone, and its key with it
        # The vault saves the key that the page shows now (save_key), and a request sends the saved copy.
        salt = made(ref(5), saved, "save_key", username="key-user", url=here + "/outbox", selector="#key")
        own = hub.q("SELECT salt, hash FROM secrets WHERE label=?", (hub.fingerprint_label(ref(5), "password"),))
        self.assertEqual([(r["salt"], r["hash"]) for r in own], [(salt, fingerprint(salt, saved))])
        self.assertNotIn(salt, salts)                               # the salt of the login, never that of the page record
        self.assertEqual(send("key-user", saved), sent(1, "key-user", login=ref(5), shown=True))
        last = render()                                             # the page opens again: the saved key is not its last key
        self.assertEqual(send("key-user", saved), sent(2, "key-user", login=ref(5), shown=False))  # its own row stayed
        refused = [("key-user", saved + "x"), ("key-user", last),   # a changed value, and a key that no vault saved
                   (hub.SITE_KEY, last), ("", last)]                # the record has no user name: its key signs nobody in
        for user, wrong in refused:
            self.assertEqual(send(user, wrong), (401, {"error": "wrong authorization"}), user)
        self.assertEqual(hub.q1("SELECT COUNT(*) c FROM outbox WHERE key='K-7'")["c"], 2)   # a refused send recorded nothing
        made(ref(6), STAND_IN, "create_login", username="made-user", url=here + "/site/login")
        self.assertEqual(send("made-user", STAND_IN), sent(3, "made-user", login=ref(6), shown=False))     # no key of the page
        word = "practice-stand-in-0001"                             # a practice login of the owner: its answer is as before
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES('pilot-site-a',?,?,?,'pilot-a')",
                ("a" * 32, fingerprint("a" * 32, word), len(word)))
        self.assertEqual(send("pilot-a", word), sent(4, "pilot-a"))

        # No key and no stand-in value is in the hub's records. The log has one line for each page, and no value.
        kept = json.dumps([dict(r) for table in ("outbox", "log", "kv", "jobs", "events", "secrets")
                           for r in hub.q(f"SELECT * FROM {table}")])
        for text in keys + [STAND_IN, word]:
            self.assertNotIn(text, kept)
        lines = lambda agent: [r["what"] for r in hub.q("SELECT what FROM log WHERE agent=? ORDER BY id", (agent,))]
        self.assertEqual(lines("site"), ["the practice site showed a new key"] * len(keys))
        self.assertEqual(lines("outside"), [
            f"send recorded for key K-7 (now 1), signed as key-user with the made login {ref(5)} and the shown key",
            f"send recorded for key K-7 (now 2), signed as key-user with the made login {ref(5)}",
            *["a practice send with a wrong Authorization header was refused"] * len(refused),
            f"send recorded for key K-7 (now 3), signed as made-user with the made login {ref(6)}",
            "send recorded for key K-7 (now 4), signed as pilot-a"])

        # Last, the leak check: it finds the last key of the page in a stored text. This puts the key in a table on purpose.
        self.assertEqual(hub.leak_scan(), [])
        self.assertEqual(self.request("/outbox", {"key": "K-8", "text": f"my key is {last}"})[0], 200)
        row = hub.q1("SELECT id FROM outbox WHERE key='K-8'")["id"]
        self.assertEqual(hub.leak_scan(), [f"outbox row {row}"])


if __name__ == "__main__":
    unittest.main()


class JobRuns(CallApi):
    """Plan C7, for a helper that names job_runs: a call that waits on the machine answers "still running" before
    the client's own limit, its outcome comes to the task as one message, and a job that its helper lost is settled
    "unknown" from the helper's own list and never runs again. No clock marks a job failed."""
    def setUp(self):
        super().setUp()
        p = patch.object(hub, "JOB_CALL_WAIT", 0.05)
        p.start()
        self.addCleanup(p.stop)
        self.report("seo", features=("agent_key", "broker_callers", "login_create", "login_capture", "api_request",
                                     "job_runs"))

    def poll(self, *held):
        return self.request(f"/events/seo?delivery=1&after=0&wait=0&jobs={','.join(str(j) for j in held)}")

    def test_a_request_that_outlasts_the_call_is_still_running_and_its_answer_comes_once(self):
        text, error = self.api(timeout_seconds=600)
        self.assertFalse(error, text)
        self.assertIn("Still running on this machine: call_api POST /v1/orders?dry=0", text)
        job = self.job()
        self.assertEqual(json.loads(self.requests(job["id"])[0]["extra"])["timeout"], 600)
        self.assertTrue(hub.open_job(self.task))
        code, given = self.asks(job["id"])
        self.assertEqual((code, given["timeout"]), (200, 600))         # the vault gives its curl that time
        self.assertIn("Still running", self.api()[0])                   # the same call while it runs: nothing again
        self.assertEqual(len(self.requests(job["id"])), 1)
        self.assertEqual(self.says(job["id"], ok=True, status=201, text="HTTP 201", body='{"id": 7}')[0], 200)
        told = [t for t in self.said("seo") if "finished" in t]
        self.assertEqual(len(told), 1)
        self.assertIn('finished: HTTP 201. {"id": 7}', told[0])
        self.assertFalse(hub.open_job(self.task))
        self.assertEqual(self.api(), ('HTTP 201.\n{"id": 7}', False))   # the same call reads the stored answer
        self.assertEqual(self.api(timeout_seconds=0)[1], True)

    def test_a_sign_in_that_ends_after_the_call_is_done_and_not_failed(self):
        text, error = self.call("seo", "sign_in", {"login": LOGIN_A}, self.task)
        self.assertFalse(error, text)
        self.assertIn(f"Still running on this machine: sign_in with {LOGIN_A}", text)
        job = hub.q1("SELECT * FROM jobs WHERE kind='signin'")
        self.assertIsNone(job["finished"])                              # no clock marked it failed
        self.assertEqual(self.request(f"/helper/job/seo/{job['id']}", {"ok": True, "text": "Signed in."})[0], 200)
        self.assertEqual(hub.q1("SELECT ok FROM jobs WHERE id=?", (job["id"],))["ok"], 1)
        self.assertEqual(sum(f"sign_in with {LOGIN_A} is done: Signed in." in t for t in self.said("seo")), 1)

    def test_a_job_that_its_helper_lost_is_unknown_once_and_is_never_handed_out_again(self):
        self.call("seo", "sign_in", {"login": LOGIN_A}, self.task)
        job = hub.q1("SELECT * FROM jobs WHERE kind='signin'")["id"]
        event = hub.q1("SELECT id FROM events WHERE agent='seo' AND kind='signin'")["id"]
        self.assertEqual([e["id"] for e in self.poll()[1]["events"] if e["kind"] == "signin"], [event])
        self.assertEqual(self.request("/helper/ack/seo", {"ids": [event]})[0], 200)     # acked before it runs
        self.assertEqual(self.poll(job)[0], 200)                        # the helper holds it: nothing changes
        self.assertIsNone(hub.q1("SELECT unknown FROM jobs WHERE id=?", (job,))["unknown"])
        code, data = self.poll()                                        # a helper that started again holds nothing
        self.assertEqual(code, 200)
        self.assertNotIn("signin", [e["kind"] for e in data["events"]])  # it never runs a second time
        self.poll()
        row = hub.q1("SELECT unknown, finished FROM jobs WHERE id=?", (job,))
        self.assertTrue(row["unknown"] and not row["finished"])
        self.assertEqual(sum("its outcome is not known" in t for t in self.said("seo")), 1)
        self.assertEqual([o["tool_call_id"] for o in self.outcomes()], [f"job-{job}"])
        self.assertIn("first find out whether these earlier actions took effect",
                      self.call("seo", "sign_in", {"login": LOGIN_A}, self.task)[0])
        # its report comes after all: the outcome is known now
        self.assertEqual(self.request(f"/helper/job/seo/{job}", {"ok": True, "text": "Signed in."})[0], 200)
        self.assertEqual([o["state"] for o in self.outcomes()], ["done"])

    def test_a_task_whose_job_runs_is_not_nudged(self):
        self.api()
        hub.q("UPDATE tasks SET state='working', last_activity=? WHERE id=?", (hub.now() - 3600, self.task))
        # its helper is online and lists the task's window: a machine that went offline is told at once (plan C10)
        self.request(f"/events/seo?delivery=1&after=0&wait=0&alive={hub.tref(self.task)}")
        hub.tick()
        self.assertEqual(hub.q1("SELECT nudge_level FROM tasks WHERE id=?", (self.task,))["nudge_level"], 0)

    def test_a_helper_without_job_runs_keeps_the_old_wait(self):
        self.report("seo")
        text, error = self.api()
        self.assertTrue(error and text.startswith(hub.REQUEST_UNKNOWN) or "was not sent" in text, text)


class HelperJobs(unittest.TestCase):
    """The helper's half: the ack before the job, the job in each poll's list, and a report kept until it is taken."""
    def test_a_job_runs_only_after_its_ack_and_its_report_is_kept_until_the_hub_takes_it(self):
        helper, ran = fleet.Helper("vps", {"role": "worker", "runtime": "claude", "machine": "vps",
                                           "can": ["shell", "browser"]}), []
        answers = {"ack": [500, 200], "job": [500, 200]}

        def http(method, path, body=None, timeout=40):
            return answers["ack" if "/helper/ack/" in path else "job"].pop(0), {}
        event = {"id": 5, "kind": "signin", "task": "T-3", "text": "", "extra": {"job": 9, "login": LOGIN_A}}
        with patch.object(fleet, "http", http), patch.object(helper, "say"), \
                patch.object(fleet, "do_signin", lambda *args: ran.append(args) or "Signed in."):
            with self.assertRaises(fleet.Refused):
                helper.handle(event)            # the hub did not take the ack: the job does not run
            self.assertEqual((ran, helper.jobs_held), ([], {}))
            helper.handle(event)                # acked: it runs, and the hub does not take its report
            self.assertEqual(len(ran), 1)
            self.assertEqual(helper.jobs_held, {9: {"ok": True, "text": "Signed in."}})
            helper.send_reports()               # its pause is not over: nothing is sent
            self.assertEqual(answers["job"], [200])
            helper.report_waits[9] = (2, 0)
            helper.send_reports()
        self.assertEqual((helper.jobs_held, answers), ({}, {"ack": [], "job": []}))

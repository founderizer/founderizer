"""create_login: the vault on an agent's machine makes and saves one new login, and the agent gets only its name.
save_key: that vault reads a key from one field of a Chrome page and saves it the same way. The hub side through the
real tools, owner routes and helper routes; the helper side with a stand-in vault. In-process hub and temporary Git
repositories. No vault, no browser, no real login and no AI call."""
import hashlib
import json
import socket
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import fleet
import hub
import lifecycle
from test_capacity import LOGIN_A, LOGIN_B, Capacity
from leftovers import scratch_home

MADE = "bws://41111111-2222-4333-8444-55555555555b"         # the login that the stand-in vault reports
OTHER = "bws://51111111-2222-4333-8444-55555555555b"        # a login that the hub has never seen
RID = "0b0e7a52-6f0e-4d5e-9d53-1d3a3c1f0a01"
ARGS = {"request_id": RID, "label": "Shop newsletter", "username": "seo@example.com",
        "url": "https://news.example.com/signup"}
STAND_IN = "stand-in-value-0123456789"          # what a vault could have made; only its fingerprint reaches the hub
KID = "0b2c3d4e-1111-4222-8333-444444444444"
KEY_ARGS = {"request_id": KID, "label": "Shop API key", "username": "shop-key-1",
            "url": "https://shop.example.com/settings/keys", "selector": "#api-key"}
NO_GRANT = "This login is not in your profile"
OLD_BROKER = ("this vault broker does not compare a login that a task made with its own record of the logins that it "
              "made; update it before it opens one without the owner's grant")


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real home folder (leftovers.scratch_home)


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite(CreateLogin(name) for name in CreateLogin.__dict__ if name.startswith("test_"))
    suite.addTests(SaveKey(name) for name in SaveKey.__dict__ if name.startswith("test_"))
    suite.addTests(loader.loadTestsFromTestCase(HelperSide))
    return suite


class CreateLogin(Capacity):
    """seo is a worker of the lead pma, on a machine with the vault broker. Its profile has LOGIN_A and LOGIN_B."""
    def setUp(self):
        super().setUp()
        self.report("seo")
        self.shop, self.task, self.blog, self.other = self.parents()      # two task sessions of seo under pma
        # Package 1 of the vault's gates (C3, C8): the hub locks a handover only for a machine whose kept pin of the
        # owner names its vault's key (hub.handover_unpinned). deva's machine has one here, so that these handovers
        # reach the refusals that the tests check. The hub reads the statement, and a broker checks the signature.
        statement = json.dumps({"v": 1, "kind": "pin", "machine": "w2", "at": int(hub.now()),      # a pin lives 90 days
                                "recipient": hub.TEAM["agents"]["deva"]["vault_recipient"]})
        hub.kv_set("owner_pin:w2", json.dumps({"statement": statement, "signature": "AAAA"}))

    # ---- helpers
    def report(self, agent, creates=True, features=("agent_key", "broker_callers", "login_create", "login_capture"),
               age=0, captures=True):
        data = {"features": list(features), "legacy_windows": [],
                "security": {"vault": {"mode": "broker", "isolated": True, "callers": True, "creates": creates,
                                       "captures": captures,
                                       "broker_recipient": hub.agents()[agent].get("vault_recipient"),
                                       "broker_read_at": hub.now() - age}}}
        hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES(?,?,?)",
              (agent, json.dumps(hub.validate_status(data)), hub.now() - age))

    def agent_command(self, agent, **fields):
        return self.request(f"/ui/team/agents/{agent}", dict(dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                                  base_sha256=self.sha()), **fields))

    def allow(self):
        """The owner's permission: seo may make logins."""
        code, data = self.agent_command("seo", vault_create=True)
        self.assertEqual(code, 200, data)

    def ask(self, task=None, **changes):
        return self.call("seo", "create_login", dict(ARGS, **changes), task or self.task)

    def job(self, request=RID):
        return hub.q1("SELECT * FROM jobs WHERE agent='seo' AND request_id=?", (request,))

    def confirm(self, job, agent="seo", kind="create"):
        return self.request(f"/helper/vault/{agent}", {"job": job, "kind": kind})

    def created(self, job, login=MADE, agent="seo"):
        return self.request(f"/helper/vault/{agent}/created", {"job": job, "login": login})

    def done(self, job, ok=True, text="The vault made it.", **more):
        return self.request(f"/helper/job/seo/{job}", dict({"ok": ok, "text": text}, **more))

    def make(self, login=MADE, task=None, **changes):
        """One made login: the tool call (no helper answers in the test's wait), the routes that the vault and the
        helper call, and the same call again. Returns the job row."""
        text, error = self.ask(task, **changes)
        self.assertTrue(error and text.startswith(hub.CREATE_UNKNOWN), text)
        job = self.job(changes.get("request_id", RID))["id"]
        for code, data in (self.confirm(job), self.created(job, login), self.done(job)):
            self.assertEqual(code, 200, data)
        text, error = self.ask(task, **changes)
        self.assertFalse(error, text)
        return self.job(changes.get("request_id", RID))

    def sign_in_job(self, login=MADE, task=None, kind="signin", target=""):
        return hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created) VALUES('seo',?,?,?,?,?)",
                       (task or self.task, kind, login, target, hub.now()))

    def opens(self, job, **fields):
        """What the vault asks before it opens a login for a sign-in job. provenance: 1 is today's broker."""
        return self.request("/helper/vault/seo", dict({"job": job, "kind": "signin", "provenance": 1}, **fields))

    def row(self, task=None):
        return hub.q1("SELECT * FROM tasks WHERE id=?", (task or self.task,))

    def events(self, job):
        return [r for r in hub.q("SELECT * FROM events WHERE agent='seo' AND kind IN ('create','capture') ORDER BY id")
                if json.loads(r["extra"])["job"] == job]

    def machine(self, request, kind, seen, failed):
        """The helper and the vault of seo's machine while the tool waits (a thread): the vault confirms the job,
        reports the login and its fingerprint, and the helper reports the end."""
        try:
            deadline = time.time() + 5
            while time.time() < deadline and not self.job(request):
                time.sleep(0.02)
            job = self.job(request)["id"]
            seen.append(self.confirm(job, kind=kind))
            seen.append(self.created(job, MADE.upper().replace("BWS", "bws")))
            digest = hashlib.sha256((seen[-1][1]["fingerprint_salts"]["password"] + STAND_IN).encode()).hexdigest()
            seen.append(self.request("/helper/vault/seo/fingerprints", {"job": job, "fingerprints": [
                {"kind": "password", "hash": digest, "len": len(STAND_IN)}]}))
            seen.append(self.done(job))
        except Exception as error:          # shown by the main thread
            failed.append(error)

    def hold(self):
        return hub.ins("INSERT INTO holds(task,kind,by,note,state,created,attempt) VALUES(?,'pause','owner','','requested',?,1)",
                       (self.task, hub.now()))

    # ---- the owner's permissions
    def test_new_logins_are_off_until_the_owner_allows_the_agent(self):
        names = lambda agent: [t["name"] for t in hub.tools_for(agent)]
        self.assertIn("login_create", self.request()[1]["ui_features"])
        self.assertIn("login_create", lifecycle.FEATURES)
        self.assertNotIn("create_login", names("seo"))
        self.assertEqual(self.ask(), ("You have no tool named create_login.", True))
        code, data = self.agent_command("seo", vault_create=True)
        self.assertEqual(code, 200, data)
        self.assertIn("create_login", names("seo"))
        self.assertNotIn("create_login", names("deva") + names("pma") + names("manager"))
        for report, code in (({"features": ("agent_key", "broker_callers")}, "helper_without_login_create"),
                             ({"creates": False}, "broker_without_creates"), ({"creates": None}, "broker_status_unknown"),
                             ({"age": hub.VAULT_FRESH + 60}, "broker_status_unknown")):
            self.report("seo", **report)
            self.assertEqual(self.ask(), (f"This machine's vault cannot make a login now ({code}). Ask your requester.",
                                          True))
        self.assertEqual((self.count("jobs"), self.events(None)), (0, []))       # no refusal reached the helper
        self.report("seo")
        free = hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES('Free','seo','manager','working',?)",
                       (hub.now(),))
        self.assertTrue(self.ask(free)[0].startswith(hub.CREATE_UNKNOWN))     # the agent's own permission alone
        self.assertEqual(self.job()["task"], free)
        self.assertEqual(self.agent_command("seo", vault_create=False)[0], 200)
        self.assertNotIn("create_login", names("seo"))
        self.assertEqual(self.ask(free), ("You have no tool named create_login.", True))

    def test_the_owner_commands_and_fields(self):
        team = lambda: self.request("/ui/team?db=test-generation")[1]
        line = lambda agent: next(l for l in team()["lines"] if l["agent"] == agent)
        self.assertEqual((line("seo")["vault_create"], line("seo")["vault_create_grant"]),
                         (False, {"ready": True, "missing": []}))
        self.assertEqual(line("big")["vault_create_grant"], {"ready": False, "missing": ["no_broker_access"]})
        self.assertEqual(line("deva")["vault_create_grant"],
                         {"ready": False, "missing": ["helper_without_login_create", "broker_status_unknown"]})
        self.assertIsNone(line("manager")["vault_create_grant"])
        self.assertEqual(team()["created_logins"], [])
        head = self.sha()
        for agent, fields, code, error in (
                ("seo", {"vault_create": "yes"}, 400, "vault_create must be true or false"),
                ("seo", {"vault_create": True, "model": None}, 400, "vault_create is set in a command of its own"),
                ("seo", {"vault_create": True, "vault": "broker"}, 400, "vault_create is set in a command of its own"),
                ("nobody", {"vault_create": True}, 404, "no such agent"),
                ("manager", {"vault_create": True}, 400, "only a worker or a lead can make logins"),
                ("big", {"vault_create": True}, 409, "Big cannot create logins yet."),
                ("deva", {"vault_create": True}, 409, "Deva cannot create logins yet.")):
            with self.subTest(agent=agent, fields=fields):
                status, data = self.agent_command(agent, **fields)
                self.assertEqual((status, data["error"]), (code, error), data)
        self.assertEqual(self.agent_command("deva", vault_create=True)[1]["missing"],
                         ["helper_without_login_create", "broker_status_unknown"])
        stale = dict(request_id=str(uuid.uuid4()), db="test-generation", base_sha256="0" * 64, vault_create=True)
        code, data = self.request("/ui/team/agents/seo", stale)
        self.assertEqual((code, data["sha256"]), (409, head))
        self.assertEqual(self.sha(), head)                                     # no refusal changed team.json
        self.assertEqual(self.agent_command("seo", vault_create=False)[1]["changed"], [])       # already off
        body = dict(request_id=str(uuid.uuid4()), db="test-generation", base_sha256=head, vault_create=True)
        code, receipt = self.request("/ui/team/agents/seo", body)
        self.assertEqual((code, receipt["changed"]), (200, [{"field": "vault_create", "before": False, "after": True}]))
        self.assertTrue(self.request("/ui/team/agents/seo", body)[1]["replayed"])
        self.assertIs(json.loads((self.kit / "team.json").read_text())["agents"]["seo"]["vault_create"], True)
        self.assertEqual((line("seo")["vault_create"], line("seo")["vault_create_grant"]), (True, None))
        for wrong in ({"agents": {"seo": {"vault_create": False}}}, {"agents": {"manager": {"vault_create": True}}}):
            broken = json.loads(json.dumps(hub.TEAM))
            for part, entries in wrong.items():
                for name, change in entries.items():
                    broken[part][name].update(change)
            with self.assertRaises(ValueError, msg=wrong):
                hub.validate_team(broken)
        self.assertEqual(self.agent_command("seo", vault_create=False)[1]["changed"],
                         [{"field": "vault_create", "before": True, "after": False}])
        self.assertNotIn("vault_create", json.loads((self.kit / "team.json").read_text())["agents"]["seo"])

    # ---- the tool and its job
    def test_the_arguments_are_names_and_places_only(self):
        self.allow()
        for change in ({"request_id": "seven"}, {"request_id": 7}, {"request_id": "x" * 65}, {"label": ""},
                       {"label": "x" * 61}, {"label": "two\nlines"}, {"label": 4}, {"username": " "},
                       {"username": "x" * 201}, {"username": "a\tb"}, {"url": "ftp://example.com/"}, {"url": "https://"},
                       {"url": "https://seo:word@example.com/"}, {"url": "https://example.com/a b"},
                       {"url": "https://example.com/" + "x" * 500}, {"url": None},
                       # What the vault's own reading of a request does not take: the hub refuses it before any job.
                       {"label": "zero\u200bwidth"}, {"label": "line\u2028separator"}, {"label": "soft\u00adhyphen"},
                       {"username": "right\u202eleft"}, {"username": "half\ud800pair"}, {"url": "HTTPS://example.com/"},
                       {"url": "https://example.com/caf\u00e9"}, {"url": "https://example.com/a%zz"},
                       {"url": "https://example.com/a#b#c"}, {"url": "https://example.com:port/"},
                       {"url": "https://@example.com/"}, {"url": "https://[::1]/"}, {"url": "https://example.com/a\\b"},
                       {"url": " https://example.com/"}):
            with self.subTest(change=change):
                text, error = self.ask(**change)
                self.assertTrue(error, text)
        self.assertEqual(self.count("jobs"), 0)
        self.assertEqual(hub.plain_line("  Caf\u00e9 \u2014 news\u00a0", 60), "Caf\u00e9 \u2014 news")   # ends are cut
        for url in ("http://localhost:8080/", "https://sub.example.co.uk/sign-up?plan=free&ref=a%20b#form",
                    "https://example.com/@seo/~new;v=1,2!$'()*+", "https://example.com:/", "https://xn--caf-dma.example/"):
            self.assertEqual(hub.site_url(url), url)
        hub.register_fingerprints(LOGIN_A, [{"kind": "password", "len": len(STAND_IN), "hash": hashlib.sha256(
            (hub.fingerprint_salt(hub.fingerprint_label(LOGIN_A, "password")) + STAND_IN).encode()).hexdigest()}])
        for field in ("label", "username"):                 # a registered value is no name
            self.assertIn("Blocked: this text contains a login", self.ask(**{field: STAND_IN})[0])
        self.assertIn("Blocked", self.ask(url="https://example.com/?p=" + STAND_IN)[0])
        self.assertEqual(self.count("jobs"), 0)
        schema = next(t for t in hub.tools_for("seo") if t["name"] == "create_login")["inputSchema"]
        self.assertEqual(sorted(schema["properties"]), ["label", "request_id", "task_id", "url", "username"])

    def test_the_vault_makes_the_login_and_the_agent_gets_only_its_name(self):
        self.allow()
        head = self.sha()
        hub.CFG["job_wait"] = 5
        seen, failed = [], []
        thread = threading.Thread(target=self.machine, args=(RID, "create", seen, failed))
        thread.start()
        text, error = self.ask()
        thread.join()
        self.assertEqual(failed, [])
        self.assertEqual((text, error), (
            f'Saved a new login as {MADE} ("Shop newsletter"). The vault made its password; you never see it. Nothing '
            f"was sent to a site: use sign_in with this name in this task. Another task needs the owner's grant.", False))
        (code, confirmed), (_, created), (_, stored), _ = seen
        job = self.job()
        self.assertEqual((code, confirmed), (200, {
            "ok": True, "job": job["id"], "task": f"T-{self.task}", "kind": "create", "db": "test-generation",
            "attempt": 1, "request_id": RID, "label": "Shop newsletter",
            "username": "seo@example.com", "url": "https://news.example.com/signup", "mark": f"fleet-create:seo:{RID}"}))
        self.assertEqual(created, {"ok": True, "job": job["id"], "login": MADE, "fingerprint_salts": {
            kind: hub.fingerprint_salt(hub.fingerprint_label(MADE, kind)) for kind in ("password", "totp")}})
        self.assertEqual((stored["stored"], stored["known"]), (1, 0))
        self.assertTrue(hub.secret_hit(f"it is {STAND_IN} now"))                # masked from now on
        self.assertEqual(len(self.events(job["id"])), 1)
        self.assertEqual(json.loads(self.events(job["id"])[0]["extra"]), {"job": job["id"]})    # a number only
        self.assertEqual(self.ask(), (text, False))                             # the same call again: the same answer
        self.assertEqual((self.count("jobs"), len(self.events(job["id"]))), (1, 1))
        # For the owner: the record, and nothing more. No team.json, no profile, no label and no grant.
        self.assertEqual(self.request("/ui/team?db=test-generation")[1]["created_logins"], [{
            "login": MADE, "label": "Shop newsletter", "username": "seo@example.com",
            "url": "https://news.example.com/signup", "agent": "seo", "task": f"T-{self.task}",
            "request_id": RID, "kind": "create", "selector": None, "source_url": None, "state": "created",
            "created_at": job["created"], "labelled": False, "protected": True}])
        self.assertEqual(self.sha(), head)
        self.assertNotIn(MADE, hub.granted_logins("seo") | set(hub.logins()))
        kept = json.dumps([dict(r) for table in ("jobs", "events", "calls", "log") for r in hub.q(f"SELECT * FROM {table}")])
        self.assertNotIn(STAND_IN, kept)

    def test_one_request_is_one_job_and_another_request_is_another_login(self):
        self.allow()
        self.assertTrue(self.ask()[0].startswith(hub.CREATE_UNKNOWN))
        job = self.job()["id"]
        fixed = hub.REQUEST_TAKEN                           # one text for the three tools that take a request_id
        for change in ({"label": "Shop news"}, {"username": "other@example.com"}, {"url": "https://example.com/"}):
            self.assertEqual(self.ask(**change), (fixed, True))                # a changed repeat is refused
        self.assertEqual(self.ask(self.other), (fixed, True))                   # also in another task
        self.assertEqual(self.ask(request_id=RID.upper())[0][:len(hub.CREATE_UNKNOWN)], hub.CREATE_UNKNOWN)   # one spelling
        self.assertEqual((self.count("jobs"), len(self.events(job))), (1, 2))   # the same job, asked for again
        with self.assertRaises(hub.sqlite3.IntegrityError):                     # the database holds the rule too
            hub.ins("INSERT INTO jobs(agent,task,kind,created,request_id) VALUES('seo',?,'create',?,?)",
                    (self.task, hub.now(), RID))
        second = str(uuid.uuid4())                  # the same values with a new request_id: a separate, explicit request
        self.assertTrue(self.ask(request_id=second)[0].startswith(hub.CREATE_UNKNOWN))
        self.assertEqual(self.count("jobs"), 2)
        self.assertNotEqual(self.job(second)["id"], job)
        self.assertEqual(self.confirm(self.job(second)["id"])[1]["mark"], f"fleet-create:seo:{second}")
        # One request_id rule for every agent tool (4 November 2026): the vault keeps a job by a UUID, so a readable
        # id becomes the UUID that vault_request makes of it, and the confirmation and its mark carry that one.
        readable, label = "seo-login-news-01", {"label": "Readable"}
        kept = hub.vault_request("seo", readable)
        self.assertTrue(self.ask(request_id=readable, **label)[0].startswith(hub.CREATE_UNKNOWN))
        self.assertEqual(self.count("jobs"), 3)
        confirmed = self.confirm(self.job(kept)["id"])[1]
        self.assertEqual((confirmed["request_id"], confirmed["mark"]), (kept, f"fleet-create:seo:{kept}"))
        self.assertTrue(self.ask(request_id=readable, **label)[0].startswith(hub.CREATE_UNKNOWN))     # its repeat
        self.assertEqual(self.count("jobs"), 3)
        self.assertEqual(self.ask(request_id=readable, label="Other"), (fixed, True))
        hub.TEAM["agents"]["deva"]["vault_create"] = True               # another agent can use the same request_id:
        self.report("deva")                                             # the mark names the agent too
        task = self.create("pma", "deva", self.shop)
        self.assertTrue(self.call("deva", "create_login", dict(ARGS), task)[0].startswith(hub.CREATE_UNKNOWN))
        mine = hub.q1("SELECT id FROM jobs WHERE agent='deva' AND request_id=?", (RID,))["id"]
        self.assertEqual(self.confirm(mine, "deva")[1]["mark"], f"fleet-create:deva:{RID}")
        self.assertEqual(self.confirm(mine)[0], 404)                    # and no agent confirms another agent's job

    def test_an_unknown_outcome_stays_open_and_is_only_looked_for_again(self):
        self.allow()
        text, error = self.ask()                                        # no word from the machine at all
        self.assertEqual((text, error), (hub.CREATE_UNKNOWN + " Last report: this machine's helper did not answer in "
                                         "0 seconds.", True))
        job = self.job()
        self.assertEqual((job["finished"], job["ok"], bool(job["unknown"])), (None, None, True))
        state = lambda: self.request("/ui/team?db=test-generation")[1]["created_logins"][0]["state"]
        self.assertEqual(state(), "unknown")
        self.assertEqual(self.confirm(job["id"])[0], 200)
        self.assertEqual(self.done(job["id"], ok=False, unknown=True, text="the vault could not confirm the outcome")[0], 200)
        self.assertEqual((self.job()["finished"], state()), (None, "unknown"))
        text, error = self.ask()
        self.assertTrue(error and text.startswith(hub.CREATE_UNKNOWN), text)
        self.assertEqual((self.count("jobs"), len(self.events(job["id"]))), (1, 2))     # looked for again; nothing new
        # The helper says that it is made, but the vault reported no login: still not known.
        self.assertEqual(self.done(job["id"])[0], 200)
        self.assertEqual((self.job()["finished"], self.job()["result"]), (None, "The vault reported no saved login."))
        self.assertEqual(self.created(job["id"])[0], 200)                       # the vault found the item by its mark
        self.assertEqual((state(), self.job()["finished"]), ("unknown", None))  # the login is known; the job is open
        self.assertEqual(self.done(job["id"])[0], 200)
        self.assertEqual(state(), "created")
        self.assertIn(f"Saved a new login as {MADE}", self.ask()[0])
        self.assertEqual(self.done(job["id"])[0], 409)                          # a closed job takes no report

    def test_after_the_vaults_confirmation_a_plain_refusal_keeps_the_job_unknown(self):
        self.allow()
        self.ask()
        job = self.job()["id"]
        state = lambda: self.request("/ui/team?db=test-generation")[1]["created_logins"][0]["state"]
        self.assertEqual(self.confirm(job)[0], 200)         # confirmed: the vault's one create call can go out now
        refusals = []
        hold = self.hold()                                  # the owner pauses the task before the vault asks again
        refusals.append(self.confirm(job))
        self.assertEqual(self.done(job, ok=False, text="the vault broker refused: the task of this job is paused or "
                                                       "stopped")[0], 200)
        self.assertEqual((self.job()["finished"], state()), (None, "unknown"))
        self.assertIn("STOP", self.ask()[0])                # a held task takes no tool call
        hub.q("UPDATE holds SET state='released' WHERE id=?", (hold,))
        self.assertEqual(self.agent_command("seo", vault_create=False)[0], 200)     # the owner takes the permission away
        refusals.append(self.confirm(job))
        self.assertEqual(self.done(job, ok=False, text="the vault broker refused: seo may not make logins")[0], 200)
        self.assertEqual(self.agent_command("seo", vault_create=True)[0], 200)
        # The vault could not reach the hub at all (for example a refused key): its refusal has no word either.
        self.assertEqual(self.done(job, ok=False, text="the vault broker refused: the hub did not accept this agent's key")[0], 200)
        self.assertEqual([(code, data["error"]) for code, data in refusals],
                         [(409, "the task of this job is paused or stopped"), (409, "seo may not make logins")])
        row = self.job()
        self.assertEqual((row["finished"], row["ok"], bool(row["unknown"]), state()), (None, None, True, "unknown"))
        self.assertEqual(self.count("jobs"), 1)             # nothing asked for a second login
        text, error = self.ask()                            # allowed again: the same request looks for the outcome
        self.assertEqual(text, hub.CREATE_UNKNOWN + " Last report: this machine's helper did not answer in 0 seconds.")
        self.assertEqual((self.count("jobs"), self.job()["id"]), (1, job))
        for code, data in (self.confirm(job), self.created(job), self.done(job)):
            self.assertEqual(code, 200, data)
        self.assertEqual((self.ask()[1], state(), self.count("jobs")), (False, "created", 1))

    def test_a_refusal_before_the_vaults_confirmation_closes_the_job(self):
        self.allow()
        self.ask()
        job = self.job()["id"]
        self.assertEqual(self.created(job)[0], 409)                     # no confirmation, so no made login
        self.assertEqual(self.done(job, ok=False, text="this machine's vault cannot make a login")[0], 200)
        row = self.job()
        self.assertEqual((bool(row["finished"]), row["ok"], row["login"]), (True, 0, None))
        self.assertEqual(self.request("/ui/team?db=test-generation")[1]["created_logins"][0]["state"], "failed")
        self.assertEqual(self.ask(), ("this machine's vault cannot make a login", True))    # the same answer again
        self.assertEqual((self.count("jobs"), len(self.events(job))), (1, 1))               # and nothing was asked
        code, data = self.confirm(job)
        self.assertEqual((code, data["error"]), (409, "this job is closed"))
        self.assertEqual(self.created(job)[0], 409)
        self.assertTrue(self.ask(request_id=str(uuid.uuid4()))[0].startswith(hub.CREATE_UNKNOWN))   # a new request

    # ---- the routes that the vault calls
    def test_the_vault_gets_the_request_only_while_the_task_and_both_permissions_stand(self):
        self.allow()
        self.ask()
        job = self.job()["id"]
        first = self.confirm(job)
        self.assertEqual(first[0], 200)
        self.assertEqual(self.confirm(job), first)                      # again while the job is open: the same values
        self.assertEqual(self.request("/helper/vault/seo", {"job": job, "kind": "signin"})[0], 404)
        self.assertEqual(self.confirm(job + 50)[0], 404)
        self.assertEqual(self.confirm(job, "deva")[0], 404)

        def refused(error, undo):
            code, data = self.confirm(job)
            self.assertEqual((code, data["error"]), (409, error))
            undo()
            self.assertEqual(self.confirm(job), first)
        hold = self.hold()
        refused("the task of this job is paused or stopped",
                lambda: hub.q("UPDATE holds SET state='released' WHERE id=?", (hold,)))
        hub.q("UPDATE tasks SET attempt=2 WHERE id=?", (self.task,))
        refused("the attempt that asked for this login has ended",
                lambda: hub.q("UPDATE tasks SET attempt=1 WHERE id=?", (self.task,)))
        self.agent_command("seo", vault_create=False)
        refused("seo may not make logins", lambda: self.agent_command("seo", vault_create=True))
        hub.TEAM["agents"]["seo"]["vault"] = "none"
        refused("seo has no broker access", lambda: hub.TEAM["agents"]["seo"].update(vault="broker"))
        hub.q("UPDATE tasks SET state='canceled' WHERE id=?", (self.task,))
        refused("the task of this job has ended", lambda: hub.q("UPDATE tasks SET state='working' WHERE id=?", (self.task,)))

    def test_the_made_login_is_reported_once_and_must_be_new_to_the_hub(self):
        self.allow()
        self.ask()
        job = self.job()["id"]
        self.assertEqual(self.created(job)[0], 409)                     # before the confirmation
        self.assertEqual(self.confirm(job)[0], 200)
        fingerprints = lambda: self.request("/helper/vault/seo/fingerprints", {"job": job, "fingerprints": [
            {"kind": "password", "hash": "a" * 64, "len": 20}]})
        self.assertEqual(fingerprints()[0], 409)                        # no made login yet
        for body in ({"job": job}, {"job": job, "login": "sealed:4"}, {"job": job, "login": MADE, "label": "x"},
                     {"job": str(job), "login": MADE}, {"job": job, "login": MADE + "0"}):
            self.assertEqual(self.request("/helper/vault/seo/created", body)[0], 400, body)
        self.assertEqual(self.created(job + 50)[0], 404)
        self.assertEqual(self.created(job, agent="deva")[0], 404)
        signin = self.sign_in_job(LOGIN_A)
        self.assertEqual(self.created(signin)[0], 404)                  # a sign-in job makes nothing
        # A login that the hub already knows was not made a moment ago: a profile's, a labelled one, a
        # protected one, and the login of another job.
        label = dict(request_id=str(uuid.uuid4()), db="test-generation", base_sha256=self.sha(),
                     login="bws://61111111-2222-4333-8444-55555555555b", title="Bank")
        self.assertEqual(self.request("/ui/team/logins", label)[0], 200)
        protected = "bws://71111111-2222-4333-8444-55555555555b"
        hub.register_fingerprints(protected, [{"kind": "password", "hash": "b" * 64, "len": 20}])
        used = "bws://81111111-2222-4333-8444-55555555555b"
        self.sign_in_job(used.upper().replace("BWS", "bws"), self.other)
        for known in (LOGIN_A, LOGIN_B, label["login"], protected, used):
            code, data = self.created(job, known)
            self.assertEqual((code, data["error"]), (409, "the hub already knows this login, so this job did not make it"))
        self.assertIsNone(self.job()["login"])
        self.assertEqual(self.created(job)[0], 200)
        self.assertEqual(self.created(job)[0], 200)                     # the same login again
        code, data = self.created(job, OTHER)
        self.assertEqual((code, data["error"]), (409, "this job already has another login"))
        self.assertEqual(self.job()["login"], MADE)
        self.assertEqual(fingerprints()[1]["stored"], 1)
        self.assertEqual(fingerprints()[1]["known"], 1)
        second = str(uuid.uuid4())                                      # another job cannot report the same login
        self.ask(request_id=second)
        self.assertEqual(self.confirm(self.job(second)["id"])[0], 200)
        self.assertEqual(self.created(self.job(second)["id"])[0], 409)

    # ---- use of the made login
    def test_the_maker_signs_in_with_its_login_in_the_same_task_and_the_vault_gets_the_creation_to_check(self):
        self.allow()
        made = self.make()
        self.assertIsNone(hub.login_refusal("seo", self.row(), MADE))
        text, error = self.call("seo", "sign_in", {"login": MADE}, self.task)      # the tool passes the grant check
        self.assertIn("helper did not answer", text)
        job = self.sign_in_job()
        code, data = self.opens(job)                        # a vault that keeps no record of what it made
        self.assertEqual((code, data["error"]), (409, OLD_BROKER))
        self.assertEqual(self.opens(job, creation=True)[0], 409)        # the marker is the number 1
        self.assertIsNone(hub.q1("SELECT released FROM jobs WHERE id=?", (job,))["released"])   # nothing was opened
        code, data = self.opens(job, creation=1)
        self.assertEqual(code, 200, data)
        self.assertEqual(data["created_by"], {"request_id": RID, "db": "test-generation", "agent": "seo", "attempt": 1,
                                              "label": "Shop newsletter", "username": "seo@example.com",
                                              "url": "https://news.example.com/signup"})
        self.assertEqual((data["task"], data["login"], data["source"]),
                         (f"T-{self.task}", MADE, MADE))                # with these, the creation's whole binding
        self.assertEqual(made["id"], self.job()["id"])
        # The owner's grant is the usual route, with today's broker and without the descriptor: also for this task's
        # own login, as soon as the owner gave it.
        usual = self.sign_in_job(LOGIN_A)
        code, data = self.opens(usual)
        self.assertEqual((code, "created_by" in data), (200, False))
        (self.kit / "profiles" / "seo.md").write_text(
            (self.kit / "profiles" / "seo.md").read_text().replace(f"`{LOGIN_B}`", f"`{LOGIN_B}`, `{MADE}`"))
        for args in (("add", "-A"), ("commit", "-q", "-m", "grant"), ("push", "-q")):
            hub.subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=self.kit, check=True,
                               capture_output=True)
        hub._revision_cache.update(at=0.0, value=None)
        granted = self.sign_in_job()
        code, data = self.opens(granted)
        self.assertEqual((code, "created_by" in data), (200, False))

    def test_the_task_that_made_a_login_gives_it_to_nobody_else(self):
        self.allow()
        self.make()
        self.assertIn("This task made this login. It is handed over only after the owner adds it to a profile",
                      self.refused("seo", "hand_over", {"login": MADE, "to": "deva"}, self.task))
        handover = self.sign_in_job(kind="handover", target="deva")
        code, data = self.request("/helper/vault/seo", {"job": handover, "kind": "handover", "provenance": 1,
                                                        "creation": 1})
        self.assertEqual((code, data["error"]), (409, "a login that this task made is handed over only after the owner "
                                                      "adds it to a profile"))
        self.assertIn(NO_GRANT, self.refused("seo", "sign_in", {"login": MADE}, self.other))      # its other task
        other = self.sign_in_job(task=self.other)
        self.assertEqual(self.opens(other, creation=1)[0], 409)
        sibling = self.create("pma", "seo", self.shop)                    # another task of the same agent
        self.assertIn(NO_GRANT, self.refused("seo", "sign_in", {"login": MADE}, sibling))
        task = self.create("pma", "deva", self.shop)                      # another agent of the same lead
        self.assertIn(NO_GRANT, hub.login_refusal("deva", self.row(task), MADE))

    def test_a_reference_that_the_task_did_not_make_opens_nothing(self):
        self.allow()
        self.ask()
        job = self.job()["id"]
        self.assertEqual(self.confirm(job)[0], 200)
        # A worker with its own key reports a login of the fleet as made by its job: the hub knows that login.
        self.assertEqual(self.created(job, LOGIN_B)[0], 409)
        self.assertIsNone(hub.login_refusal("seo", self.row(), LOGIN_B))   # its profile has it, so the grant is there
        # It reports a login that the hub has never seen: the hub cannot tell, and records the worker's word.
        self.assertEqual((self.created(job, OTHER)[0], self.done(job)[0]), (200, 200))
        self.assertIsNone(hub.login_refusal("seo", self.row(), OTHER))
        forged = self.sign_in_job(OTHER)
        code, data = self.opens(forged)                     # today's broker would open it: it is refused
        self.assertEqual((code, data["error"]), (409, OLD_BROKER))
        self.assertIsNone(hub.q1("SELECT released FROM jobs WHERE id=?", (forged,))["released"])
        # A vault with the marker gets the hub's creation record to compare with its own protected record. That
        # record has no creation of OTHER for this request, so the vault opens nothing.
        code, data = self.opens(forged, creation=1)
        self.assertEqual((code, data["login"], data["created_by"]["request_id"]), (200, OTHER, RID))
        # The owner's list shows the worker's word with the request that gives the item's mark, for a check of the item.
        listed = self.request("/ui/team?db=test-generation")[1]["created_logins"][0]
        self.assertEqual((listed["login"], listed["agent"], listed["request_id"], listed["labelled"]),
                         (OTHER, "seo", RID, False))

    def test_the_use_ends_with_the_task_the_attempt_and_the_owners_permissions(self):
        self.allow()
        self.make()
        job = self.sign_in_job()

        def ends(error, tool=NO_GRANT):
            code, data = self.opens(job, creation=1)
            self.assertEqual((code, data["error"]), (409, error))
            if tool:
                self.assertIn(tool, self.call("seo", "sign_in", {"login": MADE}, self.task)[0])
            self.assertIsNone(hub.q1("SELECT released FROM jobs WHERE id=?", (job,))["released"])

        def back():
            self.assertIsNone(hub.login_refusal("seo", self.row(), MADE))
        back()
        hold = self.hold()
        ends("the task of this job is paused or stopped", "STOP")
        hub.q("UPDATE holds SET state='released' WHERE id=?", (hold,))
        back()
        self.agent_command("seo", vault_create=False)               # the permission to make logins is taken away
        ends("this login is no longer in the agent's profile")
        self.agent_command("seo", vault_create=True)
        back()
        hub.TEAM["agents"]["seo"]["vault"] = "none"                 # the owner revokes its credential access
        ends("this agent has no broker access", "You have no credential access")
        hub.TEAM["agents"]["seo"]["vault"] = "broker"
        back()
        hub.q("UPDATE tasks SET attempt=2 WHERE id=?", (self.task,))        # a new attempt of the same task
        ends("this login is no longer in the agent's profile")
        hub.q("UPDATE tasks SET attempt=1 WHERE id=?", (self.task,))
        back()
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (self.task,))
        ends("the task of this job has ended", f"T-{self.task} is already completed")


class SaveKey(CreateLogin):
    """save_key (job kind capture): the vault reads the key from one field of a Chrome page, which a selector names.
    The value is no argument and reaches neither the helper nor the hub. The page and the vault are stand-ins: the
    routes that a vault calls."""
    def save(self, task=None, **changes):
        return self.call("seo", "save_key", dict(KEY_ARGS, **changes), task or self.task)

    def keep(self, login=MADE, **changes):
        """One saved key: the tool call, the routes that the vault and the helper call, and the same call again."""
        text, error = self.save(**changes)
        self.assertTrue(error and text.startswith(hub.CAPTURE_UNKNOWN), text)
        job = self.job(changes.get("request_id", KID))["id"]
        for code, data in (self.confirm(job, kind="capture"), self.created(job, login), self.done(job)):
            self.assertEqual(code, 200, data)
        text, error = self.save(**changes)
        self.assertFalse(error, text)
        return self.job(changes.get("request_id", KID))

    def test_the_tool_needs_the_two_permissions_a_browser_and_a_vault_that_captures(self):
        names = lambda agent: [t["name"] for t in hub.tools_for(agent)]
        self.assertIn("login_capture", self.request()[1]["ui_features"])
        self.assertIn("login_capture", lifecycle.FEATURES)
        self.assertNotIn("save_key", names("seo"))
        self.assertEqual(self.save(), ("You have no tool named save_key.", True))
        self.assertEqual(self.agent_command("seo", vault_create=True)[0], 200)         # the permission of create_login
        self.assertIn("save_key", names("seo"))
        self.assertNotIn("save_key", names("deva") + names("pma") + names("manager"))
        for report, code in (({"features": ("agent_key", "broker_callers", "login_create")}, "helper_without_login_capture"),
                             ({"captures": False}, "broker_without_captures"), ({"captures": None}, "broker_status_unknown"),
                             ({"age": hub.VAULT_FRESH + 60}, "broker_status_unknown")):
            self.report("seo", **report)
            self.assertEqual(self.save(), (f"This machine's vault cannot save a key now ({code}). Ask your requester.", True))
        self.assertEqual(self.count("jobs"), 0)
        self.report("seo", captures=False)                  # a vault that only makes logins still makes them
        self.assertTrue(self.ask()[0].startswith(hub.CREATE_UNKNOWN))
        self.report("seo")
        machine = next(m for m in self.request("/ui/machines?db=test-generation")[1]["machines"] if m["agent"] == "seo")
        self.assertEqual((machine["security"]["vault"]["captures"], "login_capture" in machine["features"]), (True, True))
        hub.TEAM["agents"]["deva"]["vault_create"] = True   # deva has no browser capability
        self.report("deva")
        task = self.create("pma", "deva", self.shop)
        self.assertEqual(self.call("deva", "save_key", dict(KEY_ARGS), task),
                         ("This machine has no browser to read a key from.", True))
        self.assertEqual(self.count("jobs"), 1)             # only the create job from above

    def test_the_selector_names_one_field_and_no_argument_is_a_value(self):
        self.allow()
        for change in ({"selector": ""}, {"selector": " "}, {"selector": "x" * 501}, {"selector": "two\nlines"},
                       {"selector": 7}, {"selector": None}, {"selector": "zero\u200bwidth"}, {"label": ""},
                       {"url": "ftp://shop.example.com/"}, {"request_id": "seven"}):
            with self.subTest(change=change):
                text, error = self.save(**change)
                self.assertTrue(error, text)
        without = {k: v for k, v in KEY_ARGS.items() if k != "selector"}
        self.assertIn("selector must be a CSS selector", self.call("seo", "save_key", without, self.task)[0])
        self.assertEqual(self.count("jobs"), 0)
        schema = next(t for t in hub.tools_for("seo") if t["name"] == "save_key")["inputSchema"]
        self.assertEqual(sorted(schema["properties"]),
                         ["label", "request_id", "selector", "source_url", "task_id", "url", "username"])     # no value
        self.assertEqual(sorted(schema["required"]), sorted(set(schema["properties"]) - {"source_url"}))
        hub.register_fingerprints(LOGIN_A, [{"kind": "password", "len": len(STAND_IN), "hash": hashlib.sha256(
            (hub.fingerprint_salt(hub.fingerprint_label(LOGIN_A, "password")) + STAND_IN).encode()).hexdigest()}])
        self.assertIn("Blocked: this text contains a login", self.save(selector=f'input[value="{STAND_IN}"]')[0])
        self.assertEqual(self.count("jobs"), 0)
        quoted = "form[data-kind=\"key\"] input[name='secret'] > code.it"         # kept as it is; the ends are cut
        self.assertTrue(self.save(selector=f"  {quoted} ")[0].startswith(hub.CAPTURE_UNKNOWN))
        self.assertEqual((self.job(KID)["selector"], self.job(KID)["kind"]), (quoted, "capture"))
        self.assertEqual(self.confirm(self.job(KID)["id"], kind="capture")[1]["selector"], quoted)

    def test_the_vault_reads_the_key_and_the_agent_gets_only_its_name(self):
        self.allow()
        head = self.sha()
        hub.CFG["job_wait"] = 5
        seen, failed = [], []
        thread = threading.Thread(target=self.machine, args=(KID, "capture", seen, failed))
        thread.start()
        text, error = self.save()                           # the machine answers while the tool waits
        thread.join()
        self.assertEqual(failed, [])
        self.assertEqual((text, error), (
            f'Saved the key as {MADE} ("Shop API key"). The vault read it from the page; its value did not pass the hub. '
            f"You can use sign_in with this name in this task. Another task needs the owner's grant.", False))
        (code, confirmed), (_, created), (_, stored), _ = seen
        job = self.job(KID)
        self.assertEqual(json.loads(self.events(job["id"])[0]["extra"]), {"job": job["id"]})       # a number only
        self.assertEqual((self.events(job["id"])[0]["kind"], len(self.events(job["id"]))), ("capture", 1))
        self.assertEqual((code, confirmed), (200, {
            "ok": True, "job": job["id"], "task": f"T-{self.task}", "kind": "capture", "db": "test-generation",
            "attempt": 1, "request_id": KID, "label": "Shop API key", "username": "shop-key-1",
            "url": "https://shop.example.com/settings/keys", "selector": "#api-key", "mark": f"fleet-create:seo:{KID}"}))
        self.assertEqual((created["login"], stored["stored"]), (MADE, 1))
        self.assertEqual(self.save(), (text, False))                            # the same call again: the same answer
        self.assertTrue(hub.secret_hit(f"the key is {STAND_IN}"))               # masked from now on
        self.assertEqual(self.request("/ui/team?db=test-generation")[1]["created_logins"], [{
            "login": MADE, "label": "Shop API key", "username": "shop-key-1",
            "url": "https://shop.example.com/settings/keys", "agent": "seo", "task": f"T-{self.task}",
            "request_id": KID, "kind": "capture", "selector": "#api-key", "source_url": None, "state": "created",
            "created_at": job["created"], "labelled": False, "protected": True}])
        self.assertEqual((self.sha(), self.count("jobs")), (head, 1))           # no team.json, no profile, no grant
        self.assertNotIn(MADE, hub.granted_logins("seo") | set(hub.logins()))
        kept = json.dumps([dict(r) for table in ("jobs", "events", "calls", "log") for r in hub.q(f"SELECT * FROM {table}")])
        self.assertNotIn(STAND_IN, kept)

    def test_one_request_cannot_change_its_tool_or_its_field(self):
        self.allow()
        self.assertTrue(self.save()[0].startswith(hub.CAPTURE_UNKNOWN))
        self.assertTrue(self.ask()[0].startswith(hub.CREATE_UNKNOWN))
        capture, create = self.job(KID)["id"], self.job(RID)["id"]
        self.assertEqual(self.save(selector="#other-key"), (hub.REQUEST_TAKEN, True))           # another field
        same = {k: v for k, v in KEY_ARGS.items() if k != "selector"}
        self.assertEqual(self.call("seo", "create_login", same, self.task), (hub.REQUEST_TAKEN, True))   # the other tool
        self.assertEqual(self.call("seo", "save_key", dict(ARGS, selector="#api-key"), self.task),
                         (hub.REQUEST_TAKEN, True))                             # and a create that would become a capture
        self.assertEqual(self.count("jobs"), 2)
        self.assertEqual(self.confirm(capture)[0], 404)                         # each job answers only to its own kind
        self.assertEqual(self.confirm(create, kind="capture")[0], 404)
        self.assertEqual(self.confirm(capture, kind="capture")[1]["kind"], "capture")
        self.assertFalse({"selector", "source_url"} & set(self.confirm(create)[1]))    # a create confirmation is as it was
        with self.assertRaises(hub.sqlite3.IntegrityError):                     # one job for a request, of either kind
            hub.ins("INSERT INTO jobs(agent,task,kind,created,request_id) VALUES('seo',?,'create',?,?)",
                    (self.task, hub.now(), KID))

    def test_a_page_that_was_not_ready_stays_unknown_and_the_same_request_saves_the_key(self):
        self.allow()
        self.save()
        job = self.job(KID)["id"]
        state = lambda: self.request("/ui/team?db=test-generation")[1]["created_logins"][0]["state"]
        self.assertEqual(self.confirm(job, kind="capture")[0], 200)     # confirmed: then the vault reads the page
        for sentence in ("No Chrome tab on that address is in front.", "The field is empty.",
                         "The selector does not match exactly one field on that page."):
            self.assertEqual(self.done(job, ok=False, text="the vault broker refused: " + sentence)[0], 200)
            row = self.job(KID)
            self.assertEqual((row["finished"], row["ok"], bool(row["unknown"]), state()), (None, None, True, "unknown"))
            self.assertEqual(hub.unknown_text(row), hub.CAPTURE_UNKNOWN + " Last report: the vault broker refused: " + sentence)
        self.assertEqual(self.count("jobs"), 1)
        before = len(self.events(job))
        self.assertTrue(self.save()[0].startswith(hub.CAPTURE_UNKNOWN))  # the page is right now: the same request again
        self.assertEqual((self.count("jobs"), self.job(KID)["id"], len(self.events(job))), (1, job, before + 1))
        for code, data in (self.confirm(job, kind="capture"), self.created(job), self.done(job)):
            self.assertEqual(code, 200, data)
        self.assertEqual((self.save()[1], state(), self.count("jobs")), (False, "created", 1))

    def test_the_saved_key_is_used_in_the_same_task_with_its_kind_and_its_field_to_check(self):
        self.allow()
        self.keep()
        self.assertIsNone(hub.login_refusal("seo", self.row(), MADE))
        job = self.sign_in_job()
        code, data = self.opens(job)                        # a broker without the marker
        self.assertEqual((code, data["error"]), (409, OLD_BROKER))
        code, data = self.opens(job, creation=1)
        self.assertEqual(code, 200, data)
        self.assertEqual(data["created_by"], {"request_id": KID, "db": "test-generation", "agent": "seo", "attempt": 1,
                                              "label": "Shop API key", "username": "shop-key-1",
                                              "url": "https://shop.example.com/settings/keys", "kind": "capture",
                                              "selector": "#api-key"})
        self.assertIn("This task made this login", self.refused("seo", "hand_over", {"login": MADE, "to": "deva"}, self.task))
        self.assertIn(NO_GRANT, self.refused("seo", "sign_in", {"login": MADE}, self.other))
        hub.q("UPDATE tasks SET attempt=2 WHERE id=?", (self.task,))            # a new attempt
        self.assertEqual(self.opens(self.sign_in_job(), creation=1)[0], 409)
        hub.q("UPDATE tasks SET attempt=1 WHERE id=?", (self.task,))
        self.assertEqual(self.opens(self.sign_in_job(), creation=1)[0], 200)
        self.agent_command("seo", vault_create=False)                           # the owner takes the permission away
        self.assertEqual(self.opens(self.sign_in_job(), creation=1)[0], 409)
        self.assertIn(NO_GRANT, self.refused("seo", "sign_in", {"login": MADE}, self.task))

    def test_a_capture_needs_the_browser_capability_each_time_the_vault_asks(self):
        self.allow()
        state = lambda request: next(r["state"] for r in self.request("/ui/team?db=test-generation")[1]["created_logins"]
                                     if r["request_id"] == request)
        self.save()
        job = self.job(KID)["id"]
        hub.TEAM["agents"]["seo"]["can"].remove("browser")          # the owner takes the browser away before the vault asks
        code, data = self.confirm(job, kind="capture")
        self.assertEqual((code, data["error"]), (409, "seo has no browser"))
        self.assertIsNone(self.job(KID)["released"])                # not confirmed, so the vault reads no page
        self.assertEqual(self.done(job, ok=False, text="the vault broker refused: seo has no browser")[0], 200)
        self.assertEqual(state(KID), "failed")                      # a refusal before the confirmation closes the job
        self.assertEqual(self.save(request_id=str(uuid.uuid4())), ("This machine has no browser to read a key from.", True))
        self.assertTrue(self.ask()[0].startswith(hub.CREATE_UNKNOWN))       # a made login needs no browser
        self.assertEqual(self.confirm(self.job(RID)["id"])[0], 200)
        hub.TEAM["agents"]["seo"]["can"].append("browser")
        # An item that exists: the capability goes after the vault reported the login. As for a removed permission,
        # the vault's next question is refused and the job stays unknown with its login. Nothing is lost and nothing
        # is made again: with the capability back, the same request ends as made.
        second = str(uuid.uuid4())
        self.save(request_id=second)
        job = self.job(second)["id"]
        self.assertEqual((self.confirm(job, kind="capture")[0], self.created(job)[0]), (200, 200))
        hub.TEAM["agents"]["seo"]["can"].remove("browser")
        code, data = self.confirm(job, kind="capture")
        self.assertEqual((code, data["error"]), (409, "seo has no browser"))
        self.assertEqual(self.done(job, ok=False, text="the vault broker refused: seo has no browser")[0], 200)
        row = self.job(second)
        self.assertEqual((row["finished"], bool(row["unknown"]), row["login"], state(second)), (None, True, MADE, "unknown"))
        hub.TEAM["agents"]["seo"]["can"].append("browser")
        self.assertTrue(self.save(request_id=second)[0].startswith(hub.CAPTURE_UNKNOWN))
        self.assertEqual((self.confirm(job, kind="capture")[0], self.done(job)[0]), (200, 200))
        self.assertEqual((self.save(request_id=second)[1], state(second), self.job(second)["id"]), (False, "created", job))

    def test_a_queued_sign_in_needs_the_browser_capability_when_the_vault_asks(self):
        self.allow()
        self.keep()
        made, usual = self.sign_in_job(), self.sign_in_job(LOGIN_A)       # the saved key, and a login with the owner's grant
        handover = self.sign_in_job(LOGIN_A, kind="handover", target="deva")
        probe = hub.ins("INSERT INTO jobs(agent,kind,target,created) VALUES('seo','probe','',?)", (hub.now(),))
        hub.TEAM["agents"]["seo"]["can"].remove("browser")          # after the tool calls, before the vault asks
        for job, more in ((made, {"creation": 1}), (usual, {})):
            code, data = self.opens(job, **more)
            self.assertEqual((code, data["error"]), (409, "seo has no browser"))
            self.assertIsNone(hub.q1("SELECT released FROM jobs WHERE id=?", (job,))["released"])      # nothing was opened
        # A handover and a probe use no browser: they are as before.
        code, data = self.request("/helper/vault/seo", {"job": handover, "kind": "handover", "provenance": 1})
        self.assertEqual((code, data["target"]), (200, "deva"), data)
        self.assertEqual(self.request("/helper/vault/seo", {"job": probe, "kind": "probe"})[0], 200)
        hub.TEAM["agents"]["seo"]["can"].append("browser")          # the capability is back: the same jobs are confirmed
        self.assertEqual((self.opens(usual)[0], self.opens(made, creation=1)[0]), (200, 200))

    def test_the_page_of_a_key_can_be_another_address_than_its_use_and_both_are_bound(self):
        self.allow()
        use, page = "https://api.shop.example.com/v1", "https://shop.example.com/settings/keys"
        for wrong in ("ftp://shop.example.com/", "HTTPS://shop.example.com/", "https://seo@shop.example.com/", "", 7):
            self.assertIn("source_url must be an address", self.save(source_url=wrong)[0])
        self.assertEqual(self.count("jobs"), 0)
        # No source_url: the page is url, and the request has no page of its own. The same call with url named as
        # the page is the same request, and the vault gets no source_url.
        self.assertTrue(self.save()[0].startswith(hub.CAPTURE_UNKNOWN))
        self.assertIsNone(self.job(KID)["source_url"])
        self.assertTrue(self.save(source_url=KEY_ARGS["url"])[0].startswith(hub.CAPTURE_UNKNOWN))
        self.assertNotIn("source_url", self.confirm(self.job(KID)["id"], kind="capture")[1])
        self.assertEqual(self.save(source_url=page + "?tab=2"), (hub.REQUEST_TAKEN, True))     # another page: a changed repeat
        self.assertEqual(self.count("jobs"), 1)
        # Another page on the same site: bound, and the use in the same task stays.
        near, account = str(uuid.uuid4()), "https://SHOP.example.com:443/account"
        self.assertEqual(self.save(request_id=near, source_url=account)[1], True)
        self.assertEqual(self.save(request_id=near), (hub.REQUEST_TAKEN, True))               # and it cannot lose its page
        made = self.keep(request_id=near, source_url=account)
        self.assertEqual(self.confirm(made["id"], kind="capture")[0], 409)                    # closed: the same values were
        self.assertEqual(made["source_url"], account)                                          # in every confirmation
        self.assertTrue(hub.created_text(made).endswith("You can use sign_in with this name in this task. Another task "
                                                        "needs the owner's grant."))
        code, data = self.opens(self.sign_in_job(), creation=1)
        self.assertEqual((code, data["created_by"]["source_url"], data["created_by"]["url"]), (200, account, KEY_ARGS["url"]))
        # A page on one site and a use on another: saved and bound, but no use without the owner's grant.
        far = str(uuid.uuid4())
        text, error = self.save(request_id=far, url=use, source_url=page)
        job = self.job(far)["id"]
        code, confirmed = self.confirm(job, kind="capture")
        self.assertEqual((code, confirmed["url"], confirmed["source_url"]), (200, use, page))
        self.assertEqual((self.created(job, OTHER)[0], self.done(job)[0]), (200, 200))
        self.assertEqual(self.save(request_id=far, url=use, source_url=page), (
            f'Saved the key as {OTHER} ("Shop API key"). The vault read it from the page; its value did not pass the hub. '
            f"Its page and its address are on different sites, so every use needs the owner's grant.", False))
        self.assertIsNone(hub.temporary_use("seo", self.row(), OTHER))
        self.assertIn(NO_GRANT, self.refused("seo", "sign_in", {"login": OTHER}, self.task))
        code, data = self.opens(self.sign_in_job(OTHER), creation=1)
        self.assertEqual((code, data["error"]), (409, "this login is no longer in the agent's profile"))
        row = next(r for r in self.request("/ui/team?db=test-generation")[1]["created_logins"] if r["request_id"] == far)
        self.assertEqual((row["url"], row["source_url"], row["kind"], row["state"]), (use, page, "capture", "created"))
        self.assertEqual([hub.origin(u) for u in ("https://Shop.Example.com:443/a", "http://shop.example.com:80", use,
                                                   "https://shop.example.com:8443/x", "http://shop.example.com/")],
                         ["https://shop.example.com", "http://shop.example.com", "https://api.shop.example.com",
                          "https://shop.example.com:8443", "http://shop.example.com"])

    def test_a_short_key_is_saved_and_used_without_a_fingerprint(self):
        self.allow()
        self.save()
        job = self.job(KID)["id"]
        self.assertEqual((self.confirm(job, kind="capture")[0], self.created(job)[0]), (200, 200))
        short = {"job": job, "fingerprints": [{"kind": "password", "hash": "c" * 64, "len": 5}]}
        self.assertEqual(self.request("/helper/vault/seo/fingerprints", short)[0], 400)    # the rule of the fingerprints
        self.assertEqual(self.done(job)[0], 200)            # the vault registered none; the key is saved all the same
        self.assertFalse(self.save()[1])
        row = self.request("/ui/team?db=test-generation")[1]["created_logins"][0]
        self.assertEqual((row["state"], row["kind"], row["protected"]), ("created", "capture", False))
        self.assertEqual(self.opens(self.sign_in_job(), creation=1)[0], 200)    # and used in this task


class HelperSide(unittest.TestCase):
    """fleet.py: the helper passes a job number to the vault and gets a name back. A stand-in vault on a socket."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fleet-create-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.sock = str(self.home / "v.sock")
        self.asked = []
        for patcher in (patch.object(fleet, "HOME", str(self.home)), patch.object(fleet, "vault_socket", lambda: self.sock),
                        patch.object(fleet, "TEAM", {"agents": {"mac": {"vault": "broker"}, "filey": {}}}),
                        patch.object(fleet.sys, "platform", "darwin")):
            patcher.start()
            self.addCleanup(patcher.stop)
        fleet.write_private(fleet.key_file("mac"), "k" * 43 + "\n")

    def vault(self, answer, status=None):
        """A vault that answers status, and one other request with `answer` (None: it closes without a word)."""
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.sock)
        server.listen(4)
        self.addCleanup(server.close)

        def serve():
            while True:
                try:
                    conn, _ = server.accept()
                except OSError:
                    return
                with conn:
                    request = json.loads(conn.makefile().readline())
                    self.asked.append(request)
                    reply = dict(status if status is not None else {"callers": True, "creates": True, "captures": True},
                                 ok=True, v=2) \
                        if request["op"] == "status" else answer
                    if reply is not None:
                        conn.sendall((json.dumps(reply) + "\n").encode())
        threading.Thread(target=serve, daemon=True).start()

    def test_only_a_job_number_goes_to_the_vault_and_only_a_name_comes_back(self):
        self.vault({"ok": True, "v": 2, "job": 7, "login": MADE.upper().replace("BWS", "bws")})
        self.assertEqual(fleet.do_save("mac", 7, "create"), f"The vault made {MADE}. Its password never left the vault.")
        self.assertEqual([r for r in self.asked if r["op"] != "status"],
                         [{"op": "create", "job": 7, "agent": "mac", "agent_key": "k" * 43, "v": 2}])
        self.assertEqual(fleet.vault_status("mac")["creates"], True)

    def test_a_machine_that_cannot_make_a_login_asks_its_vault_for_nothing(self):
        with self.assertRaises(fleet.Refused) as refused:           # no broker access
            fleet.do_save("filey", 7, "create")
        self.assertNotIsInstance(refused.exception, fleet.Unknown)
        for status in ({"callers": True}, {"callers": True, "creates": False}, {"callers": False, "creates": True}):
            self.asked.clear()
            if Path(self.sock).exists():
                Path(self.sock).unlink()
            self.vault({"ok": True, "v": 2, "job": 7, "login": MADE}, status)
            with self.assertRaises(fleet.Refused) as refused:
                fleet.do_save("mac", 7, "create")
            self.assertNotIsInstance(refused.exception, fleet.Unknown, status)
            self.assertEqual([r["op"] for r in self.asked], ["status"], status)
        Path(fleet.key_file("mac")).unlink()                         # no agent key: no caller fields, so no request
        self.asked.clear()
        with self.assertRaises(fleet.Refused):
            fleet.do_save("mac", 7, "create")
        self.assertNotIn("create", [r["op"] for r in self.asked])

    def test_no_clear_answer_is_unknown_and_never_a_failure(self):
        for answer, unknown in (({"ok": False, "v": 2, "unknown": True, "error": "the save was not confirmed"}, True),
                                ({"ok": False, "v": 2, "error": "no write access"}, False),
                                (None, True),                               # the vault closed without a word
                                ({"ok": True, "v": 2, "job": 7}, True),     # no name for the new login
                                ({"ok": True, "v": 2, "job": 8, "login": MADE}, True),
                                ({"ok": True, "v": 2, "job": 7, "login": "sealed:4"}, True)):
            if Path(self.sock).exists():
                Path(self.sock).unlink()
            self.vault(answer)
            with self.assertRaises(fleet.Refused) as refused:
                fleet.do_save("mac", 7, "create")
            self.assertEqual(isinstance(refused.exception, fleet.Unknown), unknown, answer)
        Path(self.sock).unlink()                    # no vault at all: nothing was sent, so this is a refusal
        with self.assertRaises(fleet.Refused) as refused:
            fleet.do_save("mac", 7, "create")
        self.assertNotIsInstance(refused.exception, fleet.Unknown)

    def test_a_capture_goes_only_to_a_vault_that_captures(self):
        self.vault({"ok": True, "v": 2, "job": 7, "login": MADE})
        self.assertEqual(fleet.do_save("mac", 7, "capture"), f"The vault saved the key as {MADE}. The key never left the vault.")
        self.assertEqual([r for r in self.asked if r["op"] != "status"],
                         [{"op": "capture", "job": 7, "agent": "mac", "agent_key": "k" * 43, "v": 2}])   # no value, no field
        self.assertEqual(fleet.vault_status("mac")["captures"], True)
        for status in ({"callers": True, "creates": True}, {"callers": True, "creates": True, "captures": False},
                       {"callers": False, "captures": True}):
            self.asked.clear()
            Path(self.sock).unlink()
            self.vault({"ok": True, "v": 2, "job": 7, "login": MADE}, status)
            with self.assertRaises(fleet.Refused) as refused:           # a vault from before save_key gets no capture
                fleet.do_save("mac", 7, "capture")
            self.assertEqual((str(refused.exception), isinstance(refused.exception, fleet.Unknown)),
                             ("this machine's vault cannot save a key", False))
            self.assertEqual([r["op"] for r in self.asked], ["status"], status)
        for answer, unknown, text in (
                ({"ok": False, "v": 2, "error": "The field is empty."}, False, "the vault broker refused: The field is empty."),
                ({"ok": False, "v": 2, "unknown": True, "error": "not confirmed"}, True,
                 "the vault could not confirm the outcome: not confirmed"),
                (None, True, "this machine's vault broker gave no answer for the new login")):
            Path(self.sock).unlink()
            self.vault(answer)
            with self.assertRaises(fleet.Refused) as refused:
                fleet.do_save("mac", 7, "capture")
            self.assertEqual((str(refused.exception), isinstance(refused.exception, fleet.Unknown)), (text, unknown))

    def test_the_helper_reports_made_refused_or_unknown_to_the_hub(self):
        posted = []
        helper = fleet.Helper.__new__(fleet.Helper)
        helper.agent, helper.jobs_held, helper.report_waits = "mac", {}, {}
        for outcome, report in ((lambda *a: f"The vault made {MADE}.", {"ok": True, "text": f"The vault made {MADE}."}),
                                (fleet.Refused("the vault broker refused: no write access"),
                                 {"ok": False, "text": "the vault broker refused: no write access"}),
                                (fleet.Unknown("the vault could not confirm the outcome"),
                                 {"ok": False, "text": "the vault could not confirm the outcome", "unknown": True}),
                                (RuntimeError("detail"), {"ok": False, "unknown": True, "text":
                                                         "the helper hit an error (RuntimeError). Ask your requester."})):
            posted.clear()
            with patch.object(fleet, "do_save", side_effect=outcome), \
                    patch.object(fleet, "http", side_effect=lambda *a, **k: posted.append(a) or (200, {})), \
                    patch.object(helper, "begin_outside", create=True), patch.object(helper, "end_outside", create=True), \
                    patch.object(helper, "say", create=True):
                for kind in ("create", "capture"):
                    helper.login_job(kind, "T-3", {"job": 7})
            self.assertEqual(posted, [("POST", "/helper/job/mac/7", report)] * 2)


if __name__ == "__main__":
    unittest.main()

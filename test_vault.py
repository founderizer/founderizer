"""Vault isolation (V3): the store's key and the handover key belong to the vault broker, and no broker operation gives
a login to the agents' user. Fake keys, a stand-in age program, the fleet's own store and an in-process hub; no
network, account or real key. The broker and this test run as one OS user here, so the user check is tested with a
different configured user ID."""
import base64
import hashlib
import contextlib
import secrets
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import fleet
import hub
import lifecycle
import vault
from test_ui_api import OwnerAPI

SECRET_ID = "22222222-2222-4222-8222-222222222222"
OTHER_ID = "33333333-3333-4333-8333-333333333333"
THIRD_ID = "44444444-4444-4444-8444-444444444444"
REF, OTHER = "bws://" + SECRET_ID, "bws://" + OTHER_ID
LOGIN = {"username": "pilot-b", "password": "FakeOnlyPassword-987654321", "url": "https://example.org/login",
         "totp": "JBSWY3DPEHPK3PXP"}
VPS_KEY, STUDIO_KEY, AGENT_KEY = ("age1" + c * 58 for c in "vsa")
STORE_KEY = "age1" + "p" * 58             # the public half of the key of vps's own store
EMPTY = json.dumps({"v": 1, "items": {}}, sort_keys=True)            # the empty store that store-init writes
# The owner of these tests (DevOps plan 0.3): a P-256 key made for this run, which signs each machine's pin as the app
# does, so that a broker hands a login over only to a recipient the owner pinned.
FLEET = "0123456789abcdef"


def owner_key(d):
    """The base64 public key of a P-256 private scalar, as CryptoKit's x963Representation writes it."""
    x, y = vault.point_times(d, vault.P256_G)
    return base64.b64encode(b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")).decode()


def owner_sign(d, statement):
    """An ECDSA P-256 signature over SHA-256 of `statement`, in the DER form of CryptoKit, as base64."""
    n, e = vault.P256_N, int.from_bytes(hashlib.sha256(statement.encode()).digest(), "big")
    while True:
        k = secrets.randbelow(n - 1) + 1
        r = vault.point_times(k, vault.P256_G)[0] % n
        sig = pow(k, -1, n) * (e + r * d) % n
        if r and sig:
            break

    def integer(number):
        raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
        raw = b"\x00" + raw if raw[0] & 0x80 else raw
        return b"\x02" + bytes([len(raw)]) + raw
    body = integer(r) + integer(sig)
    return base64.b64encode(b"\x30" + bytes([len(body)]) + body).decode()


OWNER_D = secrets.randbelow(vault.P256_N - 1) + 1
OWNER = owner_key(OWNER_D)


def owner_pin(machine, recipient, d=OWNER_D, fleet_id=FLEET):
    """The owner's signed pin of one machine's key: what the app sends to POST /ui/vault/pin."""
    statement = vault.canonical({"v": 1, "kind": "pin", "fleet": fleet_id, "machine": machine, "recipient": recipient,
                                 "at": 1793600000})
    return {"statement": statement, "signature": owner_sign(d, statement)}


FAKE_AGE = """#!{python}
# Fake age: "-a -r KEY" locks stdin for KEY; "-d -i FILE" opens it only when FILE names that KEY.
import base64, re, sys
args = sys.argv[1:]
data = sys.stdin.read()
if args[:2] == ["-a", "-r"]:
    body = base64.b64encode(("to:" + args[2] + "\\n" + data).encode()).decode()
    print("-----BEGIN AGE ENCRYPTED FILE-----\\n" + body + "\\n-----END AGE ENCRYPTED FILE-----")
elif args[:2] == ["-d", "-i"]:
    key = re.search(r"^# public key: (\\S+)$", open(args[2]).read(), re.M).group(1)
    to, _, text = base64.b64decode(data.split("\\n")[1]).decode().partition("\\n")
    if to != "to:" + key:
        sys.exit("age: no identity matched any of the recipients")
    sys.stdout.write(text)
else:
    sys.exit("age: bad use")
"""


def lock(recipient, login):
    body = base64.b64encode(("to:" + recipient + "\n" + json.dumps(login)).encode()).decode()
    return "-----BEGIN AGE ENCRYPTED FILE-----\n" + body + "\n-----END AGE ENCRYPTED FILE-----\n"


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite(VaultBroker(name) for name in VaultBroker.__dict__ if name.startswith("test_"))
    suite.addTests(loader.loadTestsFromTestCase(BrokerConfiguration))
    return suite


class VaultBroker(OwnerAPI):
    """vps's vault broker on a socket, with the fleet's own store, which holds two logins (SECRET_ID and OTHER_ID).
    It is the only store that a broker opens (PRODUCT.md P5)."""
    def setUp(self):
        super().setUp()
        hub.TEAM["agents"].update(
            vps=dict(role="worker", runtime="codex", machine="vps", can=["shell"], vault="broker", vault_recipient=VPS_KEY),
            studio=dict(role="worker", runtime="claude", machine="studio", can=["shell", "browser"], vault="broker",
                        vault_recipient=STUDIO_KEY),
            filey=dict(role="worker", runtime="codex", machine="filey", can=["shell"], vault="file"))
        hub.TEAM["addresses"].update(vps="127.0.0.1", studio="127.0.0.4", filey="127.0.0.5")
        self.server.machines = True             # each request comes from the machine that its route names
        self.dir = Path(tempfile.mkdtemp(prefix="fv-"))         # short: a Unix socket path has at most 104 bytes
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.dir.chmod(0o700)
        state = self.dir / "state"
        state.mkdir(mode=0o700)
        self.key, self.store, self.store_key = state / "age.key", state / "store.age", state / "store.key"
        self.key.write_text(f"# created: 2026-10-10T00:00:00Z\n# public key: {VPS_KEY}\nAGE-SECRET-KEY-1FAKE\n")
        self.store_key.write_text(f"# created: 2026-10-10T00:00:00Z\n# public key: {STORE_KEY}\nAGE-SECRET-KEY-1FAKESTORE\n")
        for f in (self.key, self.store_key):
            f.chmod(0o600)
        self.keys = {"vps": self.key}
        for name, public in (("studio", STUDIO_KEY), ("agent", AGENT_KEY)):
            self.keys[name] = self.dir / f"{name}.key"
            self.keys[name].write_text(f"# public key: {public}\nAGE-SECRET-KEY-1FAKE\n")
        (self.dir / "age").write_text(FAKE_AGE.format(python=sys.executable))
        (self.dir / "age").chmod(0o755)
        self.conf = {"agent": "vps", "hub": self.base, "worker_uid": os.getuid(), "store": str(self.store),
                     "store_key": str(self.store_key), "age_key": str(self.key), "socket": str(self.dir / "vault.sock"),
                     "age": str(self.dir / "age"), "owner_keys": [OWNER], "fleet": FLEET}
        self.locked(EMPTY)                                  # the empty store that store-init writes
        for sid, login in ((SECRET_ID, LOGIN), (OTHER_ID, dict(LOGIN, password="OtherFakePassword-123456"))):
            self.item(sid, login)
        # Each item that the broker reads from its store, by its id, in order: a login that it opened.
        self.store_reads, real_item = [], vault.LocalStore.item

        def item(store, sid):
            self.store_reads.append(str(sid).lower())
            return real_item(store, sid)
        # The owner pinned each machine's key (DevOps plan 0.3), and the hub keeps each pin as it came.
        for name, agent in hub.TEAM["agents"].items():
            if agent.get("vault_recipient"):
                hub.kv_set(f"owner_pin:{agent['machine']}", json.dumps(owner_pin(agent["machine"],
                                                                                 agent["vault_recipient"])))
        # The log goes quiet before the broker opens, because that is where it says what it makes of its setup.
        for early in (patch.object(vault, "log", lambda text: None), patch.object(vault.LocalStore, "item", item)):
            early.start()
            self.addCleanup(early.stop)
        self.broker = vault.Broker(self.conf).open()
        threading.Thread(target=self.broker.serve, daemon=True).start()
        self.addCleanup(self.broker.close)
        self.home = self.dir / "worker-home"                      # the worker's ~/.fleet: no vault file there
        self.home.mkdir()
        team = {"agents": {n: dict(hub.TEAM["agents"][n]) for n in ("vps", "studio", "filey")}}
        for p in (patch.object(fleet, "HOME", str(self.home)), patch.object(fleet, "TEAM", team),
                  patch.object(fleet, "HUB", self.base), patch.object(fleet, "vault_socket", return_value=self.conf["socket"]),
                  patch.object(hub, "kit_revision", return_value="a" * 40),
                  patch.object(hub, "profile_view", return_value=self.profile(REF))):
            p.start()
            self.addCleanup(p.stop)
        self.task = hub.ins("INSERT INTO tasks(title,owner,state,created) VALUES('Hand over','vps','working',?)", (hub.now(),))

    @staticmethod
    def profile(*logins):
        return {"sections": [{"key": "logins", "title": "Logins it may use", "text": "Sites: " + ", ".join(logins)}]}

    def job(self, login=REF, agent="vps", kind="handover", target="studio", finished=None):
        return hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created,finished) VALUES(?,?,?,?,?,?,?)",
                       (agent, self.task, kind, login, target, hub.now(), finished))

    def released(self, job):
        return hub.q1("SELECT released FROM jobs WHERE id=?", (job,))["released"]

    def locked(self, text, recipient=STORE_KEY, path=None):
        """Write a store file with the stand-in age, as the broker writes it: mode 600, locked for one key."""
        r = subprocess.run([str(self.dir / "age"), "-a", "-r", recipient], input=text, capture_output=True,
                           text=True, check=True)
        path = path or self.store
        path.write_text(r.stdout)
        path.chmod(0o600)

    def item(self, sid, login, key=None):
        """One login or key in vps's own store under this id, as a delivery from the central vault saves it. A value
        that is there is replaced. Gives its bws:// name."""
        store = vault.LocalStore(self.conf)
        items = store.opened()
        items[sid] = {"key": key or "site-" + sid[:4], "value": json.dumps(login), "note": vault.DELIVERED,
                      "made_at": time.time()}
        store.keep(items)
        return "bws://" + sid

    def reads(self):
        """The ids of the items that the broker read from its store, in order: each one a login that it opened."""
        return list(self.store_reads)

    def opens(self, ciphertext, who):
        """The login in a locked copy, without its provenance; None when `who` cannot open it."""
        r = subprocess.run([str(self.dir / "age"), "-d", "-i", str(self.keys[who])], input=ciphertext,
                           capture_output=True, text=True)
        return {k: v for k, v in json.loads(r.stdout).items() if k != "fleet"} if r.returncode == 0 else None

    def made(self, ciphertext, who):
        """The provenance inside a locked copy (owner API 1.10)."""
        r = subprocess.run([str(self.dir / "age"), "-d", "-i", str(self.keys[who])], input=ciphertext,
                           capture_output=True, text=True, check=True)
        return json.loads(r.stdout).get("fleet")

    def test_a_handover_gives_only_a_copy_locked_for_the_receivers_pinned_key(self):
        job, started, real = self.job(), [], subprocess.run

        def spy(argv, *args, **kwargs):
            if argv and argv[0] == self.conf["age"]:
                started.append((list(argv), kwargs.get("env"), kwargs.get("input")))
            return real(argv, *args, **kwargs)
        with patch.dict(os.environ, {"FLEET_TEST_MARKER": "inherited"}), patch.object(vault.subprocess, "run", spy):
            text = fleet.do_handover(REF, "vps", "studio", "T-1", job)
        sid = int(text.split()[0].split(":")[1])
        self.assertIn("Only studio can open it", text)
        stored = hub.q1("SELECT * FROM sealed WHERE id=?", (sid,))
        self.assertEqual((stored["sender"], stored["recipient"], stored["label"]), ("vps", "studio", "site-2222"))
        self.assertEqual((stored["job"], stored["login"]), (job, REF))
        self.assertEqual(self.opens(stored["ciphertext"], "studio"), LOGIN)
        self.assertEqual(self.made(stored["ciphertext"], "studio"), {"v": 1, "job": job, "source": REF})
        self.assertIsNone(self.opens(stored["ciphertext"], "vps"))
        self.assertIsNone(self.opens(stored["ciphertext"], "agent"))
        raw = fleet.vault_call({"op": "handover", "job": self.job()})
        self.assertEqual(set(raw), {"ok", "v", "job", "to", "label", "ciphertext"})
        for secret in (LOGIN["password"], LOGIN["totp"], "AGE-SECRET-KEY"):
            self.assertNotIn(secret, json.dumps(raw))
        # The broker's own children are age, which opens the store and locks the copy: the value goes on standard
        # input, no argument holds a value or a key, and no child gets the broker's environment.
        self.assertEqual(sorted({argv[1] for argv, _, _ in started}), ["-a", "-d"])
        for argv, env, given in started:
            self.assertEqual(env, {"PATH": "/usr/local/bin:/usr/bin:/bin"})      # vault.run's own: nothing else
            for secret in (LOGIN["password"], LOGIN["totp"], "AGE-SECRET-KEY"):
                self.assertNotIn(secret, " ".join(argv))
        self.assertTrue(any(LOGIN["password"] in (given or "") for argv, _, given in started if argv[1] == "-a"))

    def test_the_request_cannot_choose_the_receiver_key_or_login(self):
        raw = fleet.vault_call({"op": "handover", "job": self.job(), "to": "filey", "recipient": AGENT_KEY, "ref": OTHER,
                                "login": OTHER, "target": "filey"})
        self.assertEqual(raw["to"], "studio")
        self.assertEqual(self.opens(raw["ciphertext"], "studio"), LOGIN)
        self.assertIsNone(self.opens(raw["ciphertext"], "agent"))
        self.assertEqual(self.reads(), [SECRET_ID])

    def test_no_operation_gives_a_login_and_the_linux_broker_never_signs_in(self):
        for op in ("login", "get"):
            with self.assertRaises(fleet.Refused) as refused:
                fleet.vault_call({"op": op, "job": self.job(), "ref": REF})
            self.assertIn("unknown operation", str(refused.exception))
        # read gives only the API keys that the owner lets the agent read: none here, whatever the request names.
        self.assertEqual(fleet.vault_call({"op": "read", "job": self.job(), "ref": REF}),
                         {"ok": True, "v": 2, "env": {}, "missing": []})
        job = self.job(kind="signin", target="")
        with self.assertRaises(fleet.Refused) as refused:
            fleet.vault_call({"op": "signin", "job": job})
        self.assertIn("only the Mac vault helper signs in", str(refused.exception))
        self.assertIsNone(self.released(job))                               # refused before the hub was asked
        status = fleet.vault_call({"op": "status"})
        self.assertEqual(set(status), {"ok", "v", "agent", "store", "user", "recipient", "callers", "backend", "source",
                                       "creates", "deposits", "withdrawals", "replaces"})
        self.assertEqual(status["backend"], "store")            # the one store a broker opens (P5)
        self.assertEqual((status["recipient"], status["callers"]), (VPS_KEY, True))
        self.assertEqual(self.reads(), [])

    def test_read_gives_a_session_only_the_api_keys_that_the_agent_may_read_and_protects_them_first(self):
        value = "sk-fake-only-key-20261014"
        self.item(SECRET_ID, {"username": "", "password": value}, key="SHOP_API_KEY")
        gone = "bws://" + THIRD_ID                          # granted, but the store has no such item
        hub.TEAM["logins"] = {REF: {"title": "SHOP_API_KEY", "kind": "api_key", "env": "SHOP_API_KEY"},
                              gone: {"title": "GONE_KEY", "kind": "api_key", "env": "GONE_KEY"},
                              OTHER: {"title": "example.org · pilot-b", "kind": "login"}}
        self.addCleanup(hub.TEAM.pop, "logins", None)
        hub.TEAM["agents"]["vps"]["secrets"] = {REF: "read", gone: "read", OTHER: "use"}
        self.addCleanup(hub.TEAM["agents"]["vps"].pop, "secrets", None)
        self.assertFalse(hub.secret_hit("echo " + value))
        raw = fleet.vault_call({"op": "read"})
        self.assertEqual(raw, {"ok": True, "v": 2, "env": {"SHOP_API_KEY": value}, "missing": ["GONE_KEY"]})
        self.assertTrue(hub.secret_hit("echo " + value))                 # registered before the value left the broker
        self.assertEqual(self.reads(), [THIRD_ID, SECRET_ID])           # the use grant is not read
        # support plan F1: a Shell-off agent's check reads its keys, and a session of it gets none, also from a
        # helper that took its box for on, or from a broker that names no purpose
        hub.TEAM["agents"]["vps"]["can"] = ["web"]
        for request in ({"op": "read"}, {"op": "read", "for": "session"}):
            with self.subTest(request), self.assertRaisesRegex(fleet.Refused, "gets no key: its Shell box is off"):
                fleet.vault_call(request)
        self.assertEqual(fleet.vault_call({"op": "read", "for": "check"})["env"], {"SHOP_API_KEY": value})
        hub.TEAM["agents"]["vps"]["can"] = ["shell"]
        hub.TEAM["agents"]["vps"]["vault"] = "none"
        self.addCleanup(hub.TEAM["agents"]["vps"].update, vault="broker")
        with self.assertRaises(fleet.Refused) as refused:
            fleet.vault_call({"op": "read"})
        self.assertIn("vps has no credential access", str(refused.exception))

    def test_a_read_counts_the_values_with_a_user_name_or_a_seed_and_still_gives_them(self):
        """C11, its first step: the broker writes into its own log how many of the values that it gives have the shape
        of a login (a user name or an authenticator seed), and it leaves none of them out yet."""
        named, seeded, plain = "sk-fake-named-20261113", "sk-fake-seeded-20261113", "sk-fake-plain-20261113"
        seed = "JBSWY3DPEHPK3PXP"
        refs = {"SHOP_API_KEY": self.item(SECRET_ID, {"username": "pilot-b", "password": named}),
                "SEED_KEY": self.item(OTHER_ID, {"username": "", "password": seeded, "totp": seed}),
                "PLAIN_KEY": self.item(THIRD_ID, {"username": "", "password": plain})}
        hub.TEAM["logins"] = {ref: {"title": env, "kind": "api_key", "env": env} for env, ref in refs.items()}
        self.addCleanup(hub.TEAM.pop, "logins", None)
        hub.TEAM["agents"]["vps"]["secrets"] = {ref: "read" for ref in refs.values()}
        self.addCleanup(hub.TEAM["agents"]["vps"].pop, "secrets", None)
        logged = []
        with patch.object(vault, "log", side_effect=logged.append):
            raw = fleet.vault_call({"op": "read"})
        self.assertEqual(raw["env"], {"SHOP_API_KEY": named, "SEED_KEY": seeded, "PLAIN_KEY": plain})
        self.assertEqual(raw["missing"], [])
        head = "a session read of vps gave 2 value(s) with a user name or an authenticator seed: "
        line = next(line for line in logged if line.startswith(head))
        self.assertEqual(sorted(line[len(head):].split(", ")), sorted([refs["SHOP_API_KEY"], refs["SEED_KEY"]]))
        self.assertFalse([line for line in logged if any(v in line for v in (named, seeded, plain, seed, "pilot-b"))])
        self.assertEqual([vault.login_shaped(text) for text in ('{"username": "", "password": "x"}', "not json", "[1]",
                                                                 '{"username": 7, "password": "x"}')],
                         [False, False, False, False])

    def test_a_sealed_handover_is_opened_only_inside_the_broker(self):
        # A copy names its source login (owner API 1.10), and a handover needs its receiver to hold that login
        # already (DevOps plan V1): studio does, in its profile here.
        made = {"v": 1, "job": 7, "source": REF}
        sid = hub.ins("INSERT INTO sealed(sender,recipient,task,label,ciphertext,created,login,job) "
                      "VALUES(?,?,?,?,?,?,?,?)", ("studio", "vps", "T-1", "handed-site",
                                                  lock(VPS_KEY, dict(LOGIN, fleet=made)), hub.now(), REF, 7))
        with self.assertRaises(fleet.Refused) as refused:
            fleet.read_login(f"sealed:{sid}", "vps", "T-1")
        self.assertIn("only the broker opens logins", str(refused.exception))
        job = self.job(login=f"sealed:{sid}")
        raw = fleet.vault_call({"op": "handover", "job": job})
        self.assertEqual((raw["to"], raw["label"]), ("studio", "handed-site"))
        self.assertEqual(self.opens(raw["ciphertext"], "studio"), LOGIN)
        self.assertEqual(self.made(raw["ciphertext"], "studio"), {"v": 1, "job": job, "source": REF})
        self.assertEqual(self.reads(), [])                  # a sealed copy is opened with the handover key only

    def test_a_copy_says_which_job_made_it_and_one_sent_again_under_another_job_is_refused(self):
        other = hub.ins("INSERT INTO tasks(title,owner,state,created) VALUES('Other','vps','working',?)", (hub.now(),))
        use = hub.ins("INSERT INTO tasks(title,owner,state,created) VALUES('Use','studio','working',?)", (hub.now(),))
        self.keys["studio"].chmod(0o600)
        studio = dict(self.conf, agent="studio", age_key=str(self.keys["studio"]))
        with patch.object(hub, "profile_view", return_value=self.profile(REF, OTHER)):
            a = self.job()
            sid = int(fleet.do_handover(REF, "vps", "studio", f"T-{self.task}", a).split()[0].split(":")[1])
            copy = hub.q1("SELECT * FROM sealed WHERE id=?", (sid,))
            self.assertEqual(self.made(copy["ciphertext"], "studio"), {"v": 1, "job": a, "source": REF})
            b = hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created) VALUES('vps',?,'handover',?,'studio',?)",
                        (other, OTHER, hub.now()))
            code, data = self.request("/sealed", {"sender": "vps", "recipient": "studio", "task": f"T-{other}", "job": b,
                                                  "label": "relabelled", "ciphertext": copy["ciphertext"]})
            self.assertEqual(code, 200)                     # the hub cannot see inside a copy: the receiver checks it
            with self.assertRaises(vault.Refused) as refused:
                vault.open_login(studio, f"sealed:{data['id']}", f"T-{use}", "unused")
            self.assertIn("was made for another handover", str(refused.exception))
            self.assertEqual(vault.open_login(studio, f"sealed:{sid}", f"T-{use}", "unused"),
                             (LOGIN, "site-2222", REF))
            legacy = hub.ins("INSERT INTO sealed(sender,recipient,task,label,ciphertext,created,login) "
                             "VALUES('vps','studio','T-1','old',?,?,?)", (lock(STUDIO_KEY, LOGIN), hub.now(), REF))
            self.assertEqual(vault.open_login(studio, f"sealed:{legacy}", f"T-{use}", "unused"),
                             (LOGIN, "old", None))          # it says nothing: it carries no source login

    def test_the_hub_opens_nothing_for_other_agents_wrong_kinds_ended_jobs_or_repeats(self):
        once = self.job()
        fleet.vault_call({"op": "handover", "job": once})
        for job, why in ((self.job(agent="studio"), "no such handover job"), (self.job(kind="signin"), "no such handover"),
                         (self.job(finished=hub.now()), "has ended"), (once, "already opened"),
                         (self.job(target="filey"), "no vault broker")):
            with self.assertRaises(fleet.Refused) as refused:
                fleet.vault_call({"op": "handover", "job": job})
            self.assertIn(why, str(refused.exception))
        self.assertEqual(len(self.reads()), 1)

    def test_the_grant_is_checked_again_when_the_broker_asks(self):
        ended, held, removed = self.job(), self.job(), self.job()
        other_task = hub.ins("INSERT INTO tasks(title,owner,state,created) VALUES('Old','vps','canceled',?)", (hub.now(),))
        hub.q("UPDATE jobs SET task=? WHERE id=?", (other_task, ended))
        with self.assertRaises(fleet.Refused) as refused:
            fleet.vault_call({"op": "handover", "job": ended})
        self.assertIn("the task of this job has ended", str(refused.exception))
        hub.ins("INSERT INTO holds(task,kind,by,state,created,attempt) VALUES(?,?,?,?,?,1)",
                (self.task, "pause", "owner", "requested", hub.now()))
        with self.assertRaises(fleet.Refused) as refused:
            fleet.vault_call({"op": "handover", "job": held})
        self.assertIn("the task of this job is paused or stopped", str(refused.exception))
        hub.q("UPDATE holds SET state='released' WHERE task=?", (self.task,))
        with patch.object(hub, "profile_view", return_value=self.profile(OTHER)), \
                self.assertRaises(fleet.Refused) as refused:
            fleet.vault_call({"op": "handover", "job": removed})
        self.assertIn("this login is no longer in the agent's profile", str(refused.exception))
        for job in (ended, held, removed):
            self.assertIsNone(self.released(job))
        self.assertEqual(self.reads(), [])
        self.assertEqual(fleet.vault_call({"op": "handover", "job": removed})["to"], "studio")   # the same job, allowed

    def rows(self):
        return [dict(r) for r in hub.q("SELECT label, salt, hash, len, username FROM secrets ORDER BY id")]

    def spy(self, steps):
        real_hub, real_run = vault.hub, vault.run
        def hub_spy(conf, method, path, body=None):
            steps.append(path.rsplit("/", 1)[-1])
            return real_hub(conf, method, path, body)
        def run_spy(argv, data, env=None):
            steps.append(os.path.basename(argv[0]) + " " + argv[1])
            return real_run(argv, data, env)
        return patch.object(vault, "hub", hub_spy), patch.object(vault, "run", run_spy)

    def test_eligible_password_and_both_seed_forms_are_registered_before_the_locked_copy(self):
        password = "pass\u2713phrase-\u00e9t\u00e9-2026"          # Unicode, no whitespace: the filter finds it
        uri = "otpauth://totp/Site:pilot?secret=jbsw%20y3dp-ehpk3pxp%3D%3D&issuer=Site"
        ref = self.item(THIRD_ID, dict(LOGIN, password=password, totp=uri))
        steps = []
        hub_spy, run_spy = self.spy(steps)
        with patch.object(hub, "profile_view", return_value=self.profile(ref)), hub_spy, run_spy:
            raw = fleet.vault_call({"op": "handover", "job": self.job(login=ref)})
        self.assertEqual(self.opens(raw["ciphertext"], "studio")["password"], password)
        self.assertEqual(steps[-2:], ["fingerprints", "age -a"])       # protected first, then locked
        seed = "JBSWY3DPEHPK3PXP"
        expected = [(f"{ref} password", password), (f"{ref} totp", uri), (f"{ref} totp", seed)]
        rows = self.rows()
        self.assertEqual([(r["label"], r["len"], r["username"]) for r in rows], [(l, len(v), "") for l, v in expected])
        for row, (label, value) in zip(rows, expected):
            self.assertEqual(row["salt"], hub.fingerprint_salt(label))
            self.assertEqual(row["hash"], hashlib.sha256((row["salt"] + value).encode()).hexdigest())
        for value in (password, uri, seed):
            text = f"Here it is: {value} (do not share)"
            self.assertTrue(hub.secret_hit(text))
            self.assertNotIn(value, hub.mask_secrets(text))

    def test_repeated_use_adds_no_row_and_a_rotated_password_adds_one(self):
        fleet.vault_call({"op": "handover", "job": self.job()})
        first = self.rows()
        fleet.vault_call({"op": "handover", "job": self.job()})
        self.assertEqual(self.rows(), first)
        self.item(SECRET_ID, dict(LOGIN, password="RotatedFakePassword-24680"))
        fleet.vault_call({"op": "handover", "job": self.job()})
        self.assertEqual(self.rows()[:len(first)], first)               # old rows stay
        self.assertEqual([r["label"] for r in self.rows()[len(first):]], [REF + " password"])

    def test_short_or_spaced_values_are_skipped_and_the_login_is_still_used(self):
        ref = self.item(THIRD_ID, dict(LOGIN, password="Sh0rt!7"))   # short password, eligible seed
        with patch.object(hub, "profile_view", return_value=self.profile(ref)):
            raw = fleet.vault_call({"op": "handover", "job": self.job(login=ref)})
        self.assertEqual(self.opens(raw["ciphertext"], "studio")["password"], "Sh0rt!7")
        self.assertEqual([r["label"] for r in self.rows()], [ref + " totp"])
        ref = self.item(THIRD_ID, dict(LOGIN, password="two words here", totp="JBSW Y3"))   # nothing eligible
        steps = []
        hub_spy, run_spy = self.spy(steps)
        with patch.object(hub, "profile_view", return_value=self.profile(ref)), hub_spy, run_spy:
            raw = fleet.vault_call({"op": "handover", "job": self.job(login=ref)})
        self.assertEqual(self.opens(raw["ciphertext"], "studio")["password"], "two words here")
        self.assertNotIn("fingerprints", steps)                          # no request without an eligible value
        self.assertEqual(len(self.rows()), 1)

    def test_a_long_password_with_spaces_is_still_checked_in_the_locked_copy(self):
        ref = self.item(THIRD_ID, dict(LOGIN, password="two words here"))    # not registered, still checked
        real_run = vault.run
        def leaky_age(argv, data, env=None):                              # a "locked" copy that is plain text
            if argv[1:3] == ["-a", "-r"]:
                return subprocess.CompletedProcess(argv, 0, "-----BEGIN AGE ENCRYPTED FILE-----\n" + data + "\n", "")
            return real_run(argv, data, env)
        with patch.object(hub, "profile_view", return_value=self.profile(ref)), patch.object(vault, "run", leaky_age), \
                self.assertRaises(fleet.Refused) as refused:
            fleet.vault_call({"op": "handover", "job": self.job(login=ref)})
        self.assertIn("the locked copy was not locked", str(refused.exception))

    def test_no_exact_receipt_means_no_use(self):
        real_hub = vault.hub
        for answer in ((503, {}), (200, {"ok": True, "job": None, "stored": 2, "known": 0}),
                       (200, {"ok": True, "job": "same", "stored": 0, "known": 0})):
            def hub_answer(conf, method, path, body=None):
                if not path.endswith("/fingerprints"):
                    return real_hub(conf, method, path, body)
                return answer[0], dict(answer[1], job=body["job"]) if answer[1].get("job") == "same" else answer[1]
            with patch.object(vault, "hub", hub_answer), self.assertRaises(fleet.Refused) as refused:
                fleet.vault_call({"op": "handover", "job": self.job()})
            self.assertIn("could not be protected in messages, so it was not used", str(refused.exception))
        self.assertEqual(hub.q1("SELECT count(*) n FROM sealed")["n"], 0)

    def test_the_fingerprint_route_is_bound_to_a_confirmed_open_granted_job_and_strict(self):
        site = hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES('pilot-site-a','ab','cd',24,'pilot-a')")
        good = {"kind": "password", "hash": "a" * 64, "len": 20}
        totp = dict(good, kind="totp")
        post = lambda body: self.request("/helper/vault/vps/fingerprints", body)
        open_job, other, unconfirmed, ended = self.job(), self.job(agent="studio"), self.job(), self.job()
        hub.q("UPDATE jobs SET released=? WHERE id IN (?,?,?)", (hub.now(), open_job, other, ended))
        hub.q("UPDATE jobs SET finished=? WHERE id=?", (hub.now(), ended))
        self.assertEqual(post({"job": 999, "fingerprints": [good]})[0], 404)
        self.assertEqual(post({"job": other, "fingerprints": [good]})[0], 404)
        self.assertEqual(post({"job": unconfirmed, "fingerprints": [good]})[1]["error"], "this job is not confirmed yet")
        self.assertEqual(post({"job": ended, "fingerprints": [good]})[1]["error"], "this job has ended")
        for bad in ({"job": open_job, "fingerprints": [good], "label": "x"}, {"job": open_job, "fingerprints": []},
                    {"job": open_job, "fingerprints": [good, good]}, {"job": open_job, "fingerprints": [totp, totp, totp]},
                    {"job": open_job, "fingerprints": [dict(good, hash="A" * 64)]},
                    {"job": open_job, "fingerprints": [dict(good, len=7)]}, {"job": open_job, "fingerprints": [dict(good, len=True)]},
                    {"job": str(open_job), "fingerprints": [good]}, {"job": open_job, "fingerprints": [dict(good, salt="00")]}):
            self.assertEqual(post(bad)[0], 400, bad)
        self.assertEqual(post({"job": open_job, "fingerprints": [totp]})[1], {"ok": True, "job": open_job, "stored": 1, "known": 0})
        self.assertEqual(post({"job": open_job, "fingerprints": [dict(good, len=2000), totp]})[1]["stored"], 1)
        self.assertEqual(post({"job": open_job, "fingerprints": [totp]})[1]["known"], 1)
        with patch.object(hub, "profile_view", return_value=self.profile(OTHER)):
            self.assertEqual(post({"job": open_job, "fingerprints": [good]})[1]["error"],
                             "this login is no longer in the agent's profile")
        hub.ins("INSERT INTO holds(task,kind,by,state,created,attempt) VALUES(?,?,?,?,?,1)",
                (self.task, "pause", "owner", "requested", hub.now()))
        self.assertEqual(post({"job": open_job, "fingerprints": [good]})[1]["error"], "the task of this job is paused or stopped")
        hub.q("UPDATE holds SET state='released' WHERE task=?", (self.task,))
        hub.q("UPDATE tasks SET state='canceled' WHERE id=?", (self.task,))
        self.assertEqual(post({"job": open_job, "fingerprints": [good]})[1]["error"], "the task of this job has ended")
        self.assertEqual(dict(hub.q1("SELECT label, salt, hash, len, username FROM secrets WHERE id=?", (site,))),
                         {"label": "pilot-site-a", "salt": "ab", "hash": "cd", "len": 24, "username": "pilot-a"})

    def test_a_broker_machine_hands_logins_only_to_broker_machines_with_pinned_keys(self):
        with patch.dict(hub.CFG, {"job_wait": 0.05}), patch.object(hub, "profile_logins", return_value={REF}):
            jobs = self.count("jobs")
            with self.assertRaises(hub.ToolError) as refused:
                hub.helper_job("vps", self.task, "handover", REF, "filey")
            self.assertIn("filey keeps its handover key where its agents can read it", str(refused.exception))
            self.assertEqual(self.count("jobs"), jobs)
        hub.know("studio")
        hub.q("UPDATE agents SET pubkey=? WHERE name='studio'", (AGENT_KEY,))
        self.assertEqual(self.request("/keys/studio")[1]["pubkey"], STUDIO_KEY)          # the pin wins
        code, data = self.request("/keys/vps", {"pubkey": AGENT_KEY})
        self.assertEqual((code, data["error"]), (403, "this agent's handover key is pinned in team.json"))

    def test_the_helper_never_opens_a_login_in_broker_mode(self):
        with self.assertRaises(fleet.Refused):
            fleet.read_login(REF, "vps", "T-1")
        with self.assertRaises(fleet.Refused) as refused:
            fleet.do_handover(REF, "vps", "studio", "T-1")
        self.assertIn("only for a sign-in or handover job", str(refused.exception))
        with patch.object(fleet.shutil, "which", side_effect=AssertionError("age-keygen used in broker mode")):
            self.assertTrue(fleet.register_key("vps"))
        (self.home / "age.key").write_text("AGE-SECRET-KEY-1FAKE\n")
        with self.assertRaises(fleet.Refused) as refused:
            fleet.do_handover(REF, "vps", "studio", "T-1", self.job())
        self.assertIn("~/.fleet/age.key can still be read by the agents' user", str(refused.exception))
        self.assertEqual(self.reads(), [])

    def test_unsafe_vault_files_and_other_users_are_refused_before_the_hub_is_asked(self):
        job = self.job()
        for path, what in ((self.store_key, "store key"), (self.store, "store")):
            path.chmod(0o640)                       # the worker's group could read it
            with self.assertRaises(fleet.Refused) as refused:
                fleet.vault_call({"op": "handover", "job": job})
            self.assertIn(f"{what} file must belong to the vault user and have mode 600", str(refused.exception))
            path.chmod(0o600)
        self.key.chmod(0o644)
        with self.assertRaises(fleet.Refused) as refused:
            fleet.vault_call({"op": "status"})
        self.assertIn("handover key file must belong to the vault user", str(refused.exception))
        self.key.chmod(0o600)
        # The broker's own configuration, not the one this test built it from: with_writes, with_requests and
        # with_source each give the broker a copy, so only this dict is the one it reads.
        with patch.dict(self.broker.conf, worker_uid=os.getuid() + 1), self.assertRaises(fleet.Refused) as refused:
            fleet.vault_call({"op": "status"})
        self.assertIn("only an agent user of this machine", str(refused.exception))
        with patch.object(fleet.sys, "platform", "linux"), self.assertRaises(fleet.Refused) as refused:
            fleet.vault_call({"op": "status"})
        self.assertIn("runs as the agents' user", str(refused.exception))
        self.assertIsNone(self.released(job))
        self.assertEqual(self.reads(), [])

    def test_a_handover_goes_only_to_an_agent_that_holds_its_login_already(self):
        """DevOps plan V1: hand_over moves a login only to an agent that the owner gave it to, so no agent passes a
        login on beyond his grants. The hub refuses it at the tool and again at the broker's confirmation, and for a
        sealed copy it reads the first source login the copy was made from."""
        sender = {"sections": [{"key": "logins", "title": "Logins it may use", "text": f"The site: {REF}."}]}

        def profiles(agent, rev):
            return sender if agent == "vps" else {"sections": []}
        with patch.object(hub, "profile_view", side_effect=profiles), patch.dict(hub.CFG, {"job_wait": 0.05}):
            jobs = self.count("jobs")
            with self.assertRaises(hub.ToolError) as refused:
                hub.helper_job("vps", self.task, "handover", REF, "studio")
            self.assertIn("Studio does not hold this login: the owner has not given it to studio", str(refused.exception))
            self.assertEqual(self.count("jobs"), jobs)
            job = self.job()
            with self.assertRaises(fleet.Refused) as refused:
                fleet.vault_call({"op": "handover", "job": job})
            self.assertIn("studio does not hold this login", str(refused.exception))
            self.assertIsNone(self.released(job))
            sid = hub.ins("INSERT INTO sealed(sender,recipient,task,label,ciphertext,created,login) "
                          "VALUES('studio','vps','T-1','x',?,?,?)", (lock(VPS_KEY, LOGIN), hub.now(), REF))
            for unknown in (hub.ins("INSERT INTO sealed(sender,recipient,task,label,ciphertext,created) "
                                    "VALUES('studio','vps','T-1','x',?,?)", (lock(VPS_KEY, LOGIN), hub.now())), sid):
                self.assertIn("does not hold this login",
                              hub.login_refusal("vps", hub.q1("SELECT * FROM tasks WHERE id=?", (self.task,)),
                                                f"sealed:{unknown}", "handover", "studio") or "")
        hub.TEAM["agents"]["studio"]["secrets"] = {REF: "use"}         # the owner gives it to studio: it goes
        self.addCleanup(hub.TEAM["agents"]["studio"].pop, "secrets", None)
        with patch.object(hub, "profile_view", side_effect=profiles):
            self.assertIsNone(hub.login_refusal("vps", hub.q1("SELECT * FROM tasks WHERE id=?", (self.task,)),
                                                f"sealed:{sid}", "handover", "studio"))
            self.assertEqual(fleet.vault_call({"op": "handover", "job": self.job()})["to"], "studio")

    def test_no_agent_gets_the_vault_files_of_its_server_any_more(self):
        """File mode read a Bitwarden token on the agent's server, and Founderizer has no Bitwarden backend any more.
        An agent that has the word keeps it (its helper reads it as no credential access), and a team.json that gives
        it to one more agent is refused."""
        team = {"hub": {"machine": "hub"}, "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3",
                                                         "filey": "127.0.0.5"},
                "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub"},
                           "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "vault": "none"},
                           "filey": {"role": "worker", "runtime": "codex", "machine": "filey", "vault": "file"}}}
        running = patch.object(hub, "TEAM", json.loads(json.dumps(team)))      # the team.json that runs now
        running.start()
        self.addCleanup(running.stop)
        hub.validate_team(team)                                         # filey keeps its vault files
        team["agents"]["vps"]["vault"] = "file"
        with self.assertRaises(ValueError) as refused:
            hub.validate_team(team)
        self.assertIn("agent vps: vault file is gone, because Founderizer has no Bitwarden backend any more: its vault "
                      "is broker or none", str(refused.exception))
        team["agents"]["newcomer"] = dict(team["agents"]["filey"])
        team["agents"]["vps"]["vault"] = "none"
        with self.assertRaises(ValueError):
            hub.validate_team(team)
        with patch.object(hub, "TEAM", {}):            # fleet.py verify and the installers run no team: no "new"
            self.assertIsNone(hub.team_problem(team))

    def test_an_isolated_agent_may_ask_only_for_logins_in_its_profile(self):
        sections = {"sections": [{"key": "logins", "title": "Logins it may use", "text": f"The test site: {REF}."}]}
        with patch.object(hub, "profile_view", return_value=sections), patch.dict(hub.CFG, {"job_wait": 0.05}):
            jobs = self.count("jobs")
            with self.assertRaises(hub.ToolError) as refused:
                hub.helper_job("vps", self.task, "handover", OTHER, "studio")
            self.assertIn("not in your profile", str(refused.exception))
            self.assertEqual(self.count("jobs"), jobs)
            with self.assertRaises(hub.ToolError):                      # created, then no helper answers here
                hub.helper_job("vps", self.task, "handover", REF, "studio")
            self.assertEqual(self.count("jobs"), jobs + 1)

    # ---- shared broker callers: one broker for each agent with broker access on its machine
    def shared(self):
        """vps2 shares the machine and the broker of vps; both have keys. Returns their keys."""
        keys = {}
        for name in ("vps", "vps2"):
            hub.TEAM["agents"][name] = dict(hub.TEAM["agents"]["vps"])
            fleet.TEAM["agents"][name] = dict(hub.TEAM["agents"]["vps"])
            keys[name] = (name + "-agent-key-").ljust(43, "k")
            hub.ins("INSERT OR REPLACE INTO agent_keys(agent,sha256,created,source) VALUES(?,?,?,'owner')",
                    (name, hashlib.sha256(keys[name].encode()).hexdigest(), hub.now()))
            fleet.write_private(fleet.key_file(name), keys[name] + "\n")
        return keys

    def open_job(self, agent):
        task = hub.ins("INSERT INTO tasks(title,owner,state,created) VALUES('Hand over',?,'working',?)", (agent, hub.now()))
        return task, hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created) VALUES(?,?,'handover',?,'studio',?)",
                             (agent, task, REF, hub.now()))

    def test_a_shared_broker_acts_for_each_caller_with_that_callers_key_only(self):
        keys = self.shared()
        logged = []
        task, job = self.open_job("vps2")
        with patch.object(vault, "log", side_effect=logged.append), patch.object(fleet, "AGENT", "vps2"):
            text = fleet.do_handover(REF, "vps2", "studio", f"T-{task}", job)     # status, then the caller fields
            stored = hub.q1("SELECT * FROM sealed WHERE id=?", (int(text.split()[0].split(":")[1]),))
            self.assertEqual((stored["sender"], stored["job"]), ("vps2", job))
            self.assertEqual(self.opens(stored["ciphertext"], "studio"), LOGIN)
            for request, why in (({"op": "handover", "job": self.open_job("vps2")[1]}, "without caller fields"),
                                 ({"op": "handover", "job": self.open_job("vps2")[1], "agent": "vps2",
                                   "agent_key": keys["vps"]}, "with a sibling's key"),
                                 ({"op": "handover", "job": self.open_job("vps2")[1], "agent": "vps2",
                                   "agent_key": "w" * 43}, "with a wrong key")):
                with self.assertRaises(fleet.Refused) as refused:
                    fleet.vault_call(request)
                self.assertIn("the hub did not accept this agent's key", str(refused.exception), why)
                self.assertIsNone(self.released(request["job"]), why)
            for fields in ({"agent": None, "agent_key": None}, {"agent": None}, {"agent_key": keys["vps2"]},
                           {"agent": "vps2\n", "agent_key": keys["vps2"]}, {"agent": "vps2", "agent_key": keys["vps2"][:42]}):
                job2 = self.open_job("vps2")[1]
                with self.assertRaises(fleet.Refused) as refused:
                    fleet.vault_call(dict({"op": "handover", "job": job2}, **fields))
                self.assertIn("the caller fields are not valid", str(refused.exception), fields)
                self.assertIsNone(self.released(job2), fields)
            hub.TEAM["agents"]["vps2"] = dict(hub.TEAM["agents"]["vps2"], vault="none")     # no broker access now
            job3 = self.open_job("vps2")[1]
            with self.assertRaises(fleet.Refused) as refused:
                fleet.vault_call({"op": "handover", "job": job3, "agent": "vps2", "agent_key": keys["vps2"]})
            self.assertIn("this agent has no broker access", str(refused.exception))
        self.assertIn(f"handover job={job} for vps2: ok", logged)
        for secret in keys.values():
            self.assertFalse([line for line in logged if secret in line])

    def test_the_machine_report_says_whether_agents_can_read_a_vault_file(self):
        mode = lambda agent: {k: v for k, v in fleet.vault_status(agent).items() if k in ("mode", "isolated")}
        self.assertEqual(mode("vps"), {"mode": "broker", "isolated": True})
        (self.home / "age.key").write_text("x")
        self.assertEqual(mode("vps"), {"mode": "broker", "isolated": False})
        # An entry that still says "file" is no credential access: no helper reports file mode any more, whatever
        # old vault file its user can read.
        self.assertEqual(mode("filey"), {"mode": "none", "isolated": None})
        (self.home / "age.key").unlink()
        self.assertEqual(mode("filey"), {"mode": "none", "isolated": None})
        public = fleet.vault_status("filey")        # every mode reports the broker's public status
        self.assertEqual((public["callers"], public["broker_recipient"]), (True, VPS_KEY))
        # the broker's word that it puts a new value over a delivered one: the helper passes it on, the hub keeps it,
        # and the hub sends a replaced value only to a vault whose report says it (hub.can_replace)
        self.assertIs(public["replaces"], True)
        kept = hub.validate_status({"security": {"vault": public}})["security"]["vault"]
        self.assertIs(kept["replaces"], True)
        with self.assertRaises(ValueError):
            hub.validate_status({"security": {"vault": dict(public, replaces="yes")}})
        self.assertIsInstance(public["broker_read_at"], float)
        self.broker.close()
        unread = {"callers": None, "creates": None, "captures": None, "requests": None, "broker_recipient": None,
                  "broker_source": None, "broker_read_at": None, "deposits": None,     # deposits: secret_deliveries
                  "withdrawals": None,                                                 # withdrawals: central_vault
                  "replaces": None,                                                    # replaces: secret_replace
                  "places": None, "place_key": None}                                   # places: secret_targets
        self.assertEqual(fleet.vault_status("vps"), dict(unread, mode="broker", isolated=False))
        report = hub.validate_status({"security": {"vault": {"mode": "broker", "isolated": True, "token": "x"}}})
        self.assertEqual(report["security"]["vault"], dict(unread, mode="broker", isolated=True))
        for wrong in ({"broker_recipient": "age1short"}, {"callers": "yes"}, {"broker_read_at": "now"}, {"creates": 1},
                      {"captures": "yes"}, {"requests": 1}):
            with self.assertRaises(ValueError):
                hub.validate_status({"security": {"vault": dict({"mode": "broker"}, **wrong)}})
        self.assertIsNone(hub.validate_status({"security": {}})["security"]["vault"])
        with self.assertRaises(ValueError):
            hub.validate_status({"security": {"vault": {"mode": "keychain-file"}}})
        life = lifecycle.Lifecycle("/nonexistent", "vps", {"role": "worker"}, post=None, busy=lambda: False,
                                   run=lambda argv, **kw: (1, "", ""), platform_name="linux",
                                   vault=lambda: {"mode": "broker", "isolated": True})
        self.assertEqual(life.security()["vault"], {"mode": "broker", "isolated": True})
        self.assertIn("vault_isolation", self.request()[1]["ui_features"])

    def test_the_broker_says_what_its_own_program_hashes_to_and_the_report_carries_it(self):
        """No release reaches the broker: it runs a root-owned copy of vault.py outside every checkout a helper
        updates, and `lifecycle.OWNER_ONLY` lists that file among the ones a helper never loads, so a commit that
        changes only it advances the revision every machine reports and reaches no broker. The checksum of the
        program the broker runs is the one thing that says which vault a machine has, so the status answers it and
        the machine report carries it."""
        with open(vault.__file__, "rb") as f:
            installed = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(fleet.vault_call({"op": "status"})["source"], installed)
        self.assertEqual(fleet.vault_status("vps")["broker_source"], installed)
        # It is read once, at the start: a copy installed under a broker that was not restarted has not reached the
        # running code, so the status must go on saying the old one.
        other = self.dir / "other-vault.py"
        other.write_text("# another vault\n")
        with patch.object(vault, "__file__", str(other)):
            self.assertEqual(fleet.vault_call({"op": "status"})["source"], installed)
            fresh = vault.with_source(self.conf)
        self.assertEqual(fresh["_source"], hashlib.sha256(b"# another vault\n").hexdigest())
        # A program it cannot read leaves the status saying nothing, which is not the same as current.
        with patch.object(vault, "__file__", str(self.dir / "gone.py")):
            self.assertNotIn("_source", vault.with_source(self.conf))
        # The hub keeps the checksum and refuses anything that is not one.
        report = hub.validate_status({"security": {"vault": {"mode": "broker", "broker_source": installed}}})
        self.assertEqual(report["security"]["vault"]["broker_source"], installed)
        self.assertIsNone(hub.validate_status({"security": {"vault": {"mode": "broker"}}})["security"]["vault"]["broker_source"])
        for wrong in ("not-a-sha256", installed.upper(), installed + "0", 1):
            with self.assertRaises(ValueError):
                hub.validate_status({"security": {"vault": {"mode": "broker", "broker_source": wrong}}})
        # A broker that does not answer says nothing either, and nothing invents a checksum for it.
        self.broker.close()
        self.assertIsNone(fleet.vault_status("vps")["broker_source"])

    def test_team_vault_setting_needs_a_pinned_key_in_broker_mode(self):
        team = {"hub": {"machine": "hub"}, "addresses": {"hub": "10.0.0.1", "owner": "10.0.0.2", "wb": "10.0.0.3"},
                "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub"},
                           "worker-b": {"role": "worker", "runtime": "codex", "machine": "wb", "vault": "broker",
                                        "vault_recipient": VPS_KEY}}}
        hub.validate_team(team)
        for bad in ({"vault": "keychain"}, {"vault_recipient": None}, {"vault_recipient": "age1short"}):
            broken = json.loads(json.dumps(team))
            broken["agents"]["worker-b"].update(bad)
            with self.assertRaises(ValueError):
                hub.validate_team(broken)


class BrokerConfiguration(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="fv-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        for name in ("age", "curl"):
            (self.dir / name).write_text("x")
            (self.dir / name).chmod(0o755)
        self.conf = {"agent": "vps", "hub": "http://100.111.0.10:8765", "worker_uid": os.getuid() + 1,
                     "store": "/var/lib/fleet-vault/store.age", "store_key": "/var/lib/fleet-vault/store.key",
                     "age_key": "/var/lib/fleet-vault/age.key", "socket": "/run/fleet-vault/vault.sock",
                     "age": str(self.dir / "age")}

    def load(self, mode=0o644, **changes):
        path = self.dir / "vault.json"
        path.write_text(json.dumps(dict(self.conf, **changes)))
        path.chmod(mode)
        return vault.load_config(str(path))

    def test_only_an_unchangeable_configuration_for_another_user_loads(self):
        self.assertEqual(self.load()["agent"], "vps")
        for bad in (dict(worker_uid=os.getuid()), dict(hub="file:///etc/passwd"), dict(store="relative/store.age"),
                    dict(age_key="age.key")):
            with self.assertRaises(SystemExit):
                self.load(**bad)
        with self.assertRaises(SystemExit):
            self.load(mode=0o666)                                       # the worker could rewrite it
        (self.dir / "age").chmod(0o775)
        with self.assertRaises(SystemExit):
            self.load()                                                  # or swap a program
        (self.dir / "age").chmod(0o755)

    def test_a_configuration_with_any_bitwarden_key_is_refused_and_says_what_to_do(self):
        """Founderizer has no Bitwarden backend any more (11 November 2026): a configuration that names one key of a
        Bitwarden project or of its write setup is refused, alone or beside the fleet's own store, and the broker does
        not start on it. The text says what to give it instead. No value of these keys is a secret."""
        old = {"region": "eu", "token_file": "/var/lib/fleet-vault/bws-token", "bws": "/usr/local/bin/bws",
               "bws_config": "/etc/fleet-vault/bws.toml", "sdk": "/usr/local/lib/fleet-vault/libbitwarden_c.so",
               "sdk_sha256": "a" * 64, "write_project": "c0ffee00-0000-4000-8000-0000000000ea"}
        self.assertEqual(set(old), vault.BITWARDEN_KEYS)
        without_store = {k: v for k, v in self.conf.items() if k not in vault.STORE_KEYS}
        project = {k: old[k] for k in ("region", "token_file", "bws", "bws_config")}
        for conf in [dict(self.conf, **{key: value}) for key, value in old.items()] + \
                [dict(without_store, **project), dict(without_store, **old), dict(self.conf, **old)]:
            named = sorted(set(conf) & vault.BITWARDEN_KEYS)
            with self.subTest(named), self.assertRaises(SystemExit) as refused:
                self.written_load(conf)
            said = str(refused.exception)
            self.assertIn("Founderizer has no Bitwarden backend any more, so this vault broker does not start", said)
            self.assertIn("its configuration names " + ", ".join(named) + ".", said)
            self.assertIn("Give it the fleet's own store: store and store_key, made by store-init", said)
        # The service itself does not start on such a configuration: serve stops before it opens a socket.
        path = self.written(dict(self.conf, token_file="/var/lib/fleet-vault/bws-token"))
        program = self.dir / "vault.py"         # as root installs it: serve refuses a checkout in a temporary folder
        program.write_text("x")
        program.chmod(0o644)
        with patch.object(vault, "__file__", str(program)), \
                patch.object(vault.Broker, "open", side_effect=AssertionError("served")), \
                self.assertRaises(SystemExit) as refused:
            vault.main(["serve", "--config", path])
        self.assertIn("has no Bitwarden backend any more", str(refused.exception))

    def written(self, conf):
        path = self.dir / "vault.json"
        path.write_text(json.dumps(conf))
        path.chmod(0o644)
        return str(path)

    def written_load(self, conf):
        return vault.load_config(self.written(conf))

    def test_a_configuration_with_exactly_the_keys_of_a_live_broker_loads(self):
        """What a broker of the fleet has: hub, age_key, socket and age; who may ask it (worker_group, worker_uid or
        both); its store (store and store_key); and optionally curl, the ssh that an older installer wrote, agent,
        and the owner's keys with the fleet's ID."""
        me = __import__("pwd").getpwuid(os.getuid())
        agents = type("Group", (), {"gr_mem": ["fleet-vps"], "gr_gid": me.pw_gid + 9000})()
        base = {k: v for k, v in self.conf.items() if k not in ("agent", "worker_uid")}
        callers = ({"worker_group": "fleet-agents"}, {"worker_uid": os.getuid() + 1},
                   {"worker_group": "fleet-agents", "worker_uid": os.getuid() + 1})
        optional = ({"curl": str(self.dir / "curl")}, {"ssh": "/usr/bin/ssh"}, {"agent": "vps"},
                    {"owner_keys": [OWNER], "fleet": FLEET})
        with patch.object(vault.grp, "getgrnam", return_value=agents):
            for who in callers:
                for mask in range(1 << len(optional)):
                    conf = dict(base, **who)
                    for i, extra in enumerate(optional):
                        if mask & (1 << i):
                            conf.update(extra)
                    with self.subTest(sorted(conf)):
                        self.assertEqual(self.written_load(conf), conf)
            # and nothing less: no store, half of the store, no caller, half of the owner's keys
            for less in ({"store": None}, {"store_key": None}, {"worker_group": None}, {"fleet": FLEET},
                         {"owner_keys": [OWNER]}):
                conf = dict(base, worker_group="fleet-agents")
                conf.update(less)
                conf = {k: v for k, v in conf.items() if v is not None}
                with self.subTest(less), self.assertRaises(SystemExit):
                    self.written_load(conf)

    def test_sdk_install_and_sdk_test_are_no_commands(self):
        """The write setup of a Bitwarden project is gone with it: no command installs a library, and none loads one."""
        path = self.written(self.conf)
        for argv in (["sdk-install", "--config", path, "--manifest", str(self.dir / "vault-sdk.json"), "--project",
                      "c0ffee00-0000-4000-8000-0000000000ea"], ["sdk-test", "--library", str(self.dir / "age")]):
            with self.subTest(argv[0]), self.assertRaises(SystemExit) as stopped, \
                    contextlib.redirect_stderr(io.StringIO()) as said:
                vault.main(argv)
            self.assertEqual(stopped.exception.code, 2)                         # argparse: no such command
            self.assertIn(f"invalid choice: '{argv[0]}'", said.getvalue())
        for name in ("sdk_install", "sdk_test", "run_sdk_test", "Sdk", "Items", "open_items", "BitwardenStore",
                     "bws_item", "probe_one", "library_problem", "SDK_PIN", "WRITE_KEYS", "backend", "says"):
            self.assertFalse(hasattr(vault, name), name)

    def test_a_folder_that_others_can_change_is_refused_on_the_given_and_the_real_path(self):
        open_dir = self.dir / "open"
        open_dir.mkdir()
        (open_dir / "age").write_text("x")
        (open_dir / "age").chmod(0o755)
        open_dir.chmod(0o777)                                         # the agent could put another program here
        with self.assertRaises(SystemExit) as refused:
            self.load(age=str(open_dir / "age"))
        self.assertIn("in a folder that others can change", str(refused.exception))
        (self.dir / "link").symlink_to(open_dir)                      # a safe-looking path through a link
        with self.assertRaises(SystemExit):
            self.load(age=str(self.dir / "link" / "age"))
        open_dir.chmod(0o755)
        self.assertEqual(self.load(age=str(self.dir / "link" / "age"))["agent"], "vps")

    def test_the_broker_does_not_run_from_a_folder_that_others_can_change(self):
        path = self.dir / "vault.json"
        path.write_text(json.dumps(self.conf))
        path.chmod(0o644)
        checkout = self.dir / "checkout"
        checkout.mkdir()
        (checkout / "vault.py").write_text("x")
        checkout.chmod(0o777)
        with patch.object(vault, "__file__", str(checkout / "vault.py")), \
                patch.object(vault.Broker, "open", side_effect=AssertionError("served")), \
                self.assertRaises(SystemExit) as refused:
            vault.main(["serve", "--config", str(path)])
        self.assertIn("The vault broker program is in a folder that others can change", str(refused.exception))
        checkout.chmod(0o755)

    def test_the_service_unit_runs_the_broker_as_its_own_user(self):
        path = self.dir / "vault.json"
        path.write_text(json.dumps(self.conf))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            vault.main(["unit", "--config", str(path), "--group", "fleet"])
        unit = out.getvalue()
        for line in ("User=fleet-vault", "Group=fleet", "RuntimeDirectory=fleet-vault", "RuntimeDirectoryMode=0750",
                     "StateDirectoryMode=0700", "NoNewPrivileges=yes", "ProtectHome=yes",
                     "serve --config " + str(path)):
            self.assertIn(line, unit)


if __name__ == "__main__":
    unittest.main()

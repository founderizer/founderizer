"""The fleet's own store (PRODUCT.md P5): a broker that holds the owner's logins and keys in one encrypted file on its
machine, with no account, no organization and no machine token. It is the only store that a broker opens. The real
broker on a socket and the real hub routes; the age program and the key are stand-ins, as in test_vault.py, and every
store is a temporary one of this test. No account, no real key and no real value.

What the four groups below prove: a login is saved and then used with no Bitwarden key in the configuration; no answer
of the broker holds a value, and the store file holds none either; one agent reaches neither another agent's store nor
a login that the owner did not give it; and a fresh team.json means no credential access at all.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

import fleet
import hub
import vault
from test_vault import EMPTY, FAKE_AGE, LOGIN, STORE_KEY, VaultBroker

OTHER_STORE = "age1" + "q" * 58
AKEY = "vps-store-agent-key-".ljust(43, "k")            # the agent key that the caller fields carry
RID = "5c2f9a10-7d41-4c88-9b55-0e3a1f6c2d90"
API_KEY = "sk-fake-only-store-20261017"


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite(StoreBroker(name) for name in StoreBroker.__dict__ if name.startswith("test_"))
    suite.addTests(loader.loadTestsFromTestCase(StoreSetup))
    return suite


class StoreBroker(VaultBroker):
    """The broker of test_vault, whose store starts empty here: **no Bitwarden key of any kind** in its configuration.
    The helper of each test talks to that broker."""

    def setUp(self):
        super().setUp()
        self.other_key = self.dir / "state" / "other-store.key"
        self.other_key.write_text(f"# created: 2026-10-17T00:00:00Z\n# public key: {OTHER_STORE}\nAGE-SECRET-KEY-1FAKESTORE\n")
        self.other_key.chmod(0o600)
        self.locked(EMPTY)                                  # the empty store that store-init writes
        self.assertEqual(set(self.conf) & vault.BITWARDEN_KEYS, set())       # no token, no region, no bws, no settings
        hub.ins("INSERT OR REPLACE INTO agent_keys(agent,sha256,created,source) VALUES('vps',?,?,'owner')",
                (hashlib.sha256(AKEY.encode()).hexdigest(), hub.now()))

    # ---- helpers
    def put(self, title, item, note=""):
        """One item in the store, the way a delivery from the central vault saves it. Gives its bws:// name."""
        value = json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return "bws://" + vault.LocalStore(self.conf).add(title, value, note)

    def items(self):
        return vault.LocalStore(self.conf).opened()

    def profiled(self, *logins):
        return patch.object(hub, "profile_view", return_value=self.profile(*logins))

    def create_job(self, request=RID, label="Shop newsletter"):
        return hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created,request_id,label,username,url,attempt) "
                       "VALUES('vps',?,'create',NULL,'',?,?,?,'vps@example.com','https://news.example.com/signup',1)",
                       (self.task, hub.now(), request, label))

    # ---- 1. a fresh fleet stores a login and uses it
    def test_a_login_is_saved_and_used_with_no_bitwarden_account(self):
        ref = self.put("example.org · pilot-b", LOGIN)
        self.assertRegex(ref, vault.SECRET_REF)
        status = fleet.vault_call({"op": "status"})
        self.assertEqual(status["backend"], "store")
        with self.profiled(ref):
            raw = fleet.vault_call({"op": "handover", "job": self.job(login=ref)})
        self.assertEqual((raw["to"], raw["label"]), ("studio", "example.org · pilot-b"))
        self.assertEqual(self.opens(raw["ciphertext"], "studio"), LOGIN)        # the receiving broker opens it
        self.assertIsNone(self.opens(raw["ciphertext"], "vps"))                 # and no one else
        self.assertEqual(self.reads(), [ref[6:]])                               # opened from this store, once
        probe = hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created) VALUES('vps',?,'probe',NULL,'',?)",
                        (self.task, hub.now()))
        with self.profiled(ref):
            answer = fleet.vault_call({"op": "probe", "job": probe})
        self.assertEqual(answer["results"], [{"login": ref, "state": "readable", "reason": "ok"}])

    def test_a_session_reads_only_the_api_keys_that_the_owner_gives_this_agent(self):
        mine = self.put("SHOP_API_KEY", {"password": API_KEY})
        theirs = self.put("OTHER_API_KEY", {"password": "sk-fake-only-other-20261017"})
        hub.TEAM["logins"] = {mine: {"title": "SHOP_API_KEY", "kind": "api_key", "env": "SHOP_API_KEY"},
                              theirs: {"title": "OTHER_API_KEY", "kind": "api_key", "env": "OTHER_API_KEY"}}
        self.addCleanup(hub.TEAM.pop, "logins", None)
        hub.TEAM["agents"]["vps"]["secrets"] = {mine: "read"}           # the other key belongs to another agent
        hub.TEAM["agents"]["studio"]["secrets"] = {theirs: "read"}
        self.addCleanup(hub.TEAM["agents"]["studio"].pop, "secrets", None)
        self.addCleanup(hub.TEAM["agents"]["vps"].pop, "secrets", None)
        self.assertFalse(hub.secret_hit("echo " + API_KEY))
        self.assertEqual(fleet.vault_call({"op": "read"}),
                         {"ok": True, "v": 2, "env": {"SHOP_API_KEY": API_KEY}, "missing": []})
        self.assertTrue(hub.secret_hit("echo " + API_KEY))              # the hub masks it before the value leaves

    def test_a_new_login_is_made_in_the_store_with_no_library_and_no_project(self):
        hub.TEAM["agents"]["vps"]["vault_create"] = True
        self.assertIsNotNone(self.broker.conf.get("_journal"))          # the store writes itself: no write setup
        job = self.create_job()
        ask = {"op": "create", "job": job, "agent": "vps", "agent_key": AKEY}
        answer = fleet.vault_call(dict(ask))
        self.assertEqual(set(answer), {"ok", "v", "job", "login"})
        made = self.items()[vault.SECRET_REF.fullmatch(answer["login"]).group(1)]
        self.assertEqual((made["key"], made["note"]), ("Shop newsletter", f"fleet-create:vps:{RID}"))
        login = json.loads(made["value"])
        self.assertEqual(set(login), {"username", "password", "url"})
        self.assertNotIn(login["password"], json.dumps(answer))          # the agent gets a name, never the password
        self.assertNotIn(login["password"], self.store.read_text())      # and the file holds no value in plain
        again = fleet.vault_call(dict(ask))                              # the same request makes no second login
        self.assertEqual(again["login"], answer["login"])
        self.assertEqual([x["key"] for x in self.items().values()], ["Shop newsletter"])

    # ---- 2. no answer and no file holds a value
    def test_no_answer_of_the_broker_and_no_file_of_the_store_holds_a_value(self):
        ref = self.put("example.org · pilot-b", LOGIN)
        with self.profiled(ref):
            raw = fleet.vault_call({"op": "handover", "job": self.job(login=ref)})
        self.assertEqual(set(raw), {"ok", "v", "job", "to", "label", "ciphertext"})
        on_disk = self.store.read_text()
        for secret in (LOGIN["password"], LOGIN["totp"], json.dumps(LOGIN, sort_keys=True)):
            self.assertNotIn(secret, json.dumps(raw))
            self.assertNotIn(secret, on_disk)
        self.assertNotIn("AGE-SECRET-KEY", json.dumps(raw) + on_disk)
        self.assertEqual(stat.S_IMODE(self.store.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.store_key.stat().st_mode), 0o600)

    def test_a_store_or_a_key_that_another_user_can_read_is_refused(self):
        ref = self.put("example.org · pilot-b", LOGIN)
        for path in (self.store, self.store_key):
            path.chmod(0o640)                                   # the worker's group could read it
            with self.profiled(ref), self.assertRaises(fleet.Refused) as refused:
                fleet.vault_call({"op": "handover", "job": self.job(login=ref)})
            self.assertIn("mode 600", str(refused.exception))
            path.chmod(0o600)
        self.store.write_text("plain json, not a locked file\n")
        with self.profiled(ref), self.assertRaises(fleet.Refused) as refused:
            fleet.vault_call({"op": "handover", "job": self.job(login=ref)})
        self.assertIn("not a locked file", str(refused.exception))

    def test_a_store_that_an_age_did_not_lock_is_not_written(self):
        ref = self.put("example.org · pilot-b", LOGIN)
        before = self.store.read_text()
        armor = vault.ARMOR + "\n{value}\n-----END AGE ENCRYPTED FILE-----\n"
        real = vault.run

        def leaky(argv, data, env=None):                        # an age that gives the values back in plain
            if argv[1:2] == ["-a"]:
                return subprocess.CompletedProcess(argv, 0, armor.format(value=data), "")
            return real(argv, data, env)
        with patch.object(vault, "run", leaky), self.assertRaises(vault.Refused) as refused:
            vault.LocalStore(self.conf).add("leaky", json.dumps({"password": "FakeOnlyPassword-987654321"}))
        self.assertIn("was not locked", str(refused.exception))
        self.assertEqual(self.store.read_text(), before)        # the store is the one it was
        self.assertEqual([x["key"] for x in self.items().values()], ["example.org · pilot-b"])
        self.assertTrue(ref.endswith(next(iter(self.items()))))

    # ---- 3. one agent reaches no other agent's material
    def test_another_user_of_the_machine_gets_nothing_from_this_broker(self):
        ref = self.put("example.org · pilot-b", LOGIN)
        line = json.dumps({"v": 2, "op": "handover", "job": self.job(login=ref)})
        with self.profiled(ref), self.assertRaises(vault.Refused) as refused:
            vault.handle(self.broker.conf, line, os.getuid() + 1)        # another agent's own OS user (P2 gives each one)
        self.assertIn("only an agent user of this machine may ask this broker", str(refused.exception))
        with self.profiled(ref), self.assertRaises(vault.Refused):
            vault.handle(self.broker.conf, json.dumps({"v": 2, "op": "read"}), os.getuid() + 1)

    def test_a_broker_with_another_store_key_cannot_open_this_store(self):
        self.put("example.org · pilot-b", LOGIN)
        with self.assertRaises(vault.Refused) as refused:
            vault.LocalStore(dict(self.conf, store_key=str(self.other_key)))
        self.assertIn("cannot be opened with this machine's store key", str(refused.exception))
        self.locked(EMPTY, recipient=OTHER_STORE, path=self.dir / "state" / "other-store.age")
        theirs = dict(self.conf, store=str(self.dir / "state" / "other-store.age"), store_key=str(self.other_key))
        self.assertEqual(vault.LocalStore(theirs).opened(), {})          # each store opens with its own key only
        with self.assertRaises(vault.Refused):
            vault.LocalStore(dict(theirs, store_key=str(self.store_key)))

    def test_a_login_that_the_owner_did_not_give_this_agent_is_not_opened(self):
        mine = self.put("example.org · pilot-b", LOGIN)
        theirs = self.put("studio only", dict(LOGIN, password="OtherFakePassword-123456"))
        with self.profiled(mine), self.assertRaises(fleet.Refused) as refused:
            fleet.vault_call({"op": "handover", "job": self.job(login=theirs)})
        self.assertIn("profile", str(refused.exception))
        hub.TEAM["agents"]["vps"]["vault"] = "none"
        self.addCleanup(hub.TEAM["agents"]["vps"].update, vault="broker")
        with self.profiled(mine), self.assertRaises(fleet.Refused) as refused:
            fleet.vault_call({"op": "handover", "job": self.job(login=mine)})
        self.assertIn("no broker access", str(refused.exception))       # the hub refuses the job, so nothing opens
        with self.assertRaises(fleet.Refused) as refused:
            fleet.vault_call({"op": "read"})
        self.assertIn("no credential access", str(refused.exception))


class StoreSetup(unittest.TestCase):
    """The configuration of the one store, and the operations that root and the vault user run on it."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="fs-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.dir.chmod(0o755)
        (self.dir / "age").write_text(FAKE_AGE.format(python=os.sys.executable))
        (self.dir / "age").chmod(0o755)
        self.state = self.dir / "state"
        self.state.mkdir(mode=0o700)
        self.user = __import__("pwd").getpwuid(os.getuid()).pw_name
        self.base = {"agent": "vps", "hub": "http://100.111.0.10:8765", "worker_uid": os.getuid() + 1,
                     "age_key": str(self.state / "age.key"), "socket": "/run/fleet-vault/vault.sock",
                     "age": str(self.dir / "age")}
        self.store = {"store": str(self.state / "store.age"), "store_key": str(self.state / "store.key")}

    def config(self, **conf):
        path = self.dir / "vault.json"
        path.write_text(json.dumps(dict(self.base, **conf)))
        path.chmod(0o644)
        return str(path)

    def initialised(self):
        """A store configuration whose key is already there (this machine has no age-keygen), after store-init."""
        Path(self.store["store_key"]).write_text(f"# public key: {STORE_KEY}\nAGE-SECRET-KEY-1FAKESTORE\n")
        config = self.config(**self.store)
        vault.store_init(config, self.user, keygen="/nonexistent/age-keygen")
        return config

    def test_a_configuration_names_its_one_store_and_no_bitwarden_key(self):
        conf = vault.load_config(self.config(**self.store))
        self.assertEqual({k: conf[k] for k in vault.STORE_KEYS}, self.store)
        for bad in (dict(), {"store": self.store["store"]}, {"store_key": self.store["store_key"]}):
            with self.assertRaises(SystemExit) as refused:
                vault.load_config(self.config(**bad))
            self.assertIn("its one store: store and store_key", str(refused.exception))
        # Founderizer has no Bitwarden backend any more: its project and its write setup are refused, also beside
        # the fleet's own store, and the store stays the one that a configuration names
        for bad in ({"region": "eu", "token_file": str(self.state / "bws-token")},
                    dict(self.store, bws="/usr/local/bin/bws"),
                    dict(self.store, sdk="/usr/local/lib/fleet-vault/libbitwarden_c.so", sdk_sha256="a" * 64,
                         write_project=str(uuid.uuid4()))):
            with self.assertRaises(SystemExit) as refused:
                vault.load_config(self.config(**bad))
            self.assertIn("Founderizer has no Bitwarden backend any more", str(refused.exception))
        with self.assertRaises(SystemExit):                             # a path of the store must be absolute
            vault.load_config(self.config(store="store.age", store_key=self.store["store_key"]))

    def test_store_init_makes_a_private_store_and_keeps_the_key_when_it_runs_again(self):
        config = self.initialised()
        conf = vault.load_config(config)
        self.assertEqual(vault.state_folder(conf), str(self.state))
        for path in (self.store["store"], self.store["store_key"]):
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(os.stat(path).st_uid, os.getuid())
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        self.assertEqual(vault.LocalStore(conf).opened(), {})
        key, store = (Path(self.store[k]).read_text() for k in ("store_key", "store"))
        made = vault.store_init(config, self.user, keygen="/nonexistent/age-keygen")
        self.assertEqual(made["made"], [])                              # nothing was replaced: the values stay readable
        self.assertEqual([Path(self.store[k]).read_text() for k in ("store_key", "store")], [key, store])

    def test_the_store_lists_only_names_and_takes_no_value_from_a_command(self):
        """The central vault is the one way a value reaches a server (DevOps plan V3): store-put is gone, and
        store-list names what a delivery saved, never a value."""
        config = self.initialised()
        conf = vault.load_config(config)
        one = vault.LocalStore(conf).add("GitHub · owner", json.dumps(dict(LOGIN, url="https://github.com/login")),
                                         vault.DELIVERED)
        two = vault.LocalStore(conf).add("SHOP_API_KEY", json.dumps({"password": API_KEY}), vault.DELIVERED)
        listed = vault.store_list(config)
        self.assertEqual([x["title"] for x in listed], ["GitHub · owner", "SHOP_API_KEY"])
        self.assertEqual({x["login"] for x in listed}, {"bws://" + one, "bws://" + two})
        self.assertNotIn(API_KEY, json.dumps(listed))                   # a list names, it never gives a value
        self.assertNotIn(API_KEY, Path(self.store["store"]).read_text())
        self.assertFalse(hasattr(vault, "store_put"))
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            vault.main(["store-put", "--config", config, "--title", "x"])

    def test_a_team_that_says_nothing_gives_an_agent_no_credential_access(self):
        team = {"agents": {"quiet": {"role": "worker"}, "broker": {"role": "worker", "vault": "broker"},
                           "filey": {"role": "worker", "vault": "file"}, "said": {"role": "worker", "vault": "none"}}}
        with patch.object(fleet, "TEAM", team):
            # An entry that still says "file" is no credential access either: file mode read a Bitwarden token,
            # and Founderizer has no Bitwarden backend any more.
            self.assertEqual([fleet.vault_mode(a) for a in ("quiet", "broker", "filey", "said", "unknown")],
                             ["none", "broker", "none", "none", "none"])
            # No agent named: the owner's own command on his own machine opens no login either.
            self.assertEqual(fleet.vault_mode(None), "none")

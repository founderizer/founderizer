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
import socket
import stat
import subprocess
import threading
import unittest
from unittest.mock import patch
import uuid

import fleet
import hub
import vault
from test_vault import EMPTY, FAKE_AGE, LOGIN, STORE_KEY, VaultBroker, private_temp

OTHER_STORE = "age1" + "q" * 58
AKEY = "vps-store-agent-key-".ljust(43, "k")            # the agent key that the caller fields carry
RID = "5c2f9a10-7d41-4c88-9b55-0e3a1f6c2d90"
API_KEY = "sk-fake-only-store-20261017"
ROUTE, OTHER_SITE = "route.example.com", "other.example.com"
MADE_KEY = "made-only-in-this-test-" + "r" * 20          # a key that the central vault made, in this test only
MADE_ITEM = {"made": {"password": MADE_KEY, "url": "https://" + ROUTE}}     # as a deposit keeps it (made_text)


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite(StoreBroker(name) for name in StoreBroker.__dict__ if name.startswith("test_"))
    suite.addTests(loader.loadTestsFromTestCase(MadeKeys))     # its own tests only (below the class)
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


class MadeKeys(StoreBroker):
    """A key that the central vault made (piece 2a of the read routes) reaches a process of the agent never as its
    value: a session and a check get a placeholder for the key's own site on a broker that swaps keys, and nothing on
    one that does not; no handover and no sign-in takes it. call_api still sends it (test_vault_request). The store
    holds the key as a deposit keeps it, in its own form {"made": {"password", "url"}}. A run that names this class
    runs its own tests only (the names of the inherited ones are None below the class)."""
    PART = {"user": "founderizer-swap", "vault": "fleet-vault", "port": 876, "openssl": "/usr/bin/openssl"}

    def setUp(self):
        super().setUp()
        hub.TEAM["logins"] = {}
        self.addCleanup(hub.TEAM.pop, "logins", None)
        hub.TEAM["agents"]["vps"]["secrets"] = {}
        self.addCleanup(hub.TEAM["agents"]["vps"].pop, "secrets", None)

    # ---- helpers
    def given(self, env, item, site=None):
        """One more key in the store, in the catalog with this variable (and site), which vps reads. Its reference."""
        ref = self.put(env, item, vault.DELIVERED)
        hub.TEAM["logins"][ref] = dict({"title": env, "kind": "api_key", "env": env},
                                       **({"site": site} if site else {}))
        hub.TEAM["agents"]["vps"]["secrets"][ref] = "read"
        return ref

    def swapping(self):
        """vps's broker, started again with the part "swap", as test_key_swap's BrokerPart starts it: the machine's
        users are stand-ins, and this test's own user is the proxy's user and the agent's (fleet-vps)."""
        self.stop_broker()
        self.swap_sock = str(self.dir / "swap.sock")
        part = dict(self.PART, uid=os.getuid(), vault_uid=os.getuid(), group="fleet-agents", broker=self.swap_sock)
        real = vault.swap_user
        for p in (patch.object(vault, "swap_part", lambda conf: dict(part)),
                  patch.object(vault, "swap_user", lambda uid: "fleet-vps" if uid == os.getuid() else real(uid))):
            p.start()
            self.addCleanup(p.stop)
        self.conf = dict(self.conf, swap=dict(self.PART))
        self.broker = vault.Broker(self.conf).open()
        threading.Thread(target=self.broker.serve, daemon=True).start()
        self.addCleanup(self.stop_broker, self.broker)

    def swap(self, name, host):
        """The swap proxy's question for the value of a placeholder, for a request to this host: the broker's answer."""
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect(self.swap_sock)
            s.sendall((json.dumps({"op": "swap", "uid": os.getuid(), "host": host, "port": 443, "name": name,
                                   "form": "bearer"}) + "\n").encode())
            data = b""
            while not data.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        said = json.loads(data)
        said.pop("program", None)
        return said

    # ---- the session's read
    def test_a_broker_that_does_not_swap_gives_a_made_key_to_no_session_and_no_check(self):
        """Bugs: read gives a made key as a variable, as each key on a broker that does not swap (or each key that the
        hub names with no site); read takes the mark for none when the value has an address; the answer does not say
        why the key is missing. A key without the mark, also one with an address, is given as before."""
        self.given("ROUTE_KEY", MADE_ITEM, "https://" + ROUTE)
        self.given("PLAIN_KEY", {"password": API_KEY, "url": "https://" + ROUTE, "username": ""}, "https://" + ROUTE)
        for request in ({"op": "read"}, {"op": "read", "for": "session"}, {"op": "read", "for": "check"}):
            with self.subTest(request):
                raw = fleet.vault_call(request)
                self.assertEqual(raw, {"ok": True, "v": 2, "env": {"PLAIN_KEY": API_KEY}, "missing": ["ROUTE_KEY"],
                                       "made": ["ROUTE_KEY"]})

    def test_a_broker_that_swaps_gives_a_made_key_as_a_placeholder_for_its_own_site_only(self):
        """Bugs: read gives a made key a placeholder for each site that the hub names, so a hub that names another site
        (a hub that is broken into, or a catalog entry that changed) has the proxy put the key into a request there;
        the proxy's own value path (swap_value) does not read the mark, so a delivery that puts a made key under the
        reference of a placeholder for another site sends it there."""
        self.swapping()
        made = self.given("ROUTE_KEY", MADE_ITEM, f"https://{ROUTE}/api/v1/query")
        raw = fleet.vault_call({"op": "read"})
        name = raw["env"]["ROUTE_KEY"]
        self.assertRegex(name, vault.PLACEHOLDER)
        self.assertEqual((raw["missing"], raw["swap"]["names"]), ([], {"ROUTE_KEY": ROUTE}))
        self.assertNotIn(MADE_KEY, json.dumps(raw))
        self.assertEqual(fleet.vault_call({"op": "read", "for": "check"})["env"], {"ROUTE_KEY": name})
        self.assertEqual(self.swap(name, ROUTE), {"ok": True, "value": MADE_KEY})      # the proxy, for its own site
        self.assertEqual(self.swap(name, OTHER_SITE), {"ok": False, "code": "refused"})
        # the hub names another site for it: no placeholder, and the one of before opens nothing any more
        hub.TEAM["logins"][made]["site"] = "https://" + OTHER_SITE
        self.assertEqual(fleet.vault_call({"op": "read"}),
                         {"ok": True, "v": 2, "env": {}, "missing": ["ROUTE_KEY"], "made": ["ROUTE_KEY"]})
        for host in (ROUTE, OTHER_SITE):
            self.assertEqual(self.swap(name, host), {"ok": False, "code": "refused"}, host)
        # the second wall: a placeholder of a key for another site, whose value a delivery replaces with this made key
        hub.TEAM["logins"][made]["site"] = "https://" + ROUTE
        other = self.given("OTHER_KEY", {"password": API_KEY, "username": ""}, "https://" + OTHER_SITE)
        placeholder = fleet.vault_call({"op": "read"})["env"]["OTHER_KEY"]
        self.assertEqual(self.swap(placeholder, OTHER_SITE), {"ok": True, "value": API_KEY})
        self.item(other[6:], MADE_ITEM, key="OTHER_KEY")
        self.assertEqual(self.swap(placeholder, OTHER_SITE), {"ok": False, "code": "refused"})

    def test_the_hubs_site_names_the_keys_own_site_in_each_form_of_one_origin(self):
        """2a-S4. The key's own site and the hub's are compared as one origin, (host, port). Bugs: read compares them
        as text, so a site with ":443", one trailing dot or capital letters, which is the same origin, gets no
        placeholder; or it compares the host alone, or the start of a name, so another port or another host gets
        one."""
        self.swapping()
        self.given("ROUTE_KEY", MADE_ITEM, "https://" + ROUTE)
        real, said = vault.hub, {}

        def hub(conf, method, path, body=None):     # the hub's answer to a read, with the key's site in another form
            code, data = real(conf, method, path, body)
            if path.endswith("/read") and code == 200:
                data = dict(data, secrets=[dict(x, site=said["site"]) if said["site"] else
                                           {k: v for k, v in x.items() if k not in ("site", "swap", "form")}
                                           for x in data["secrets"]])
            return code, data
        with patch.object(vault, "hub", hub):
            for site, same in ((f"https://{ROUTE}:443", True), (f"https://{ROUTE}.", True),
                               ("https://Route.EXAMPLE.com/api/v1", True), (f"https://{ROUTE}:8443", False),
                               (f"https://{ROUTE}.other.example", False), ("https://example.com", False),
                               (None, False)):     # the hub names no site: a key that would be a value elsewhere
                said["site"] = site
                raw = fleet.vault_call({"op": "read"})
                with self.subTest(site):
                    self.assertNotIn(MADE_KEY, json.dumps(raw))
                    self.assertEqual(bool(vault.PLACEHOLDER.fullmatch(raw["env"].get("ROUTE_KEY", ""))), same, raw)
                    self.assertEqual(raw.get("made"), None if same else ["ROUTE_KEY"])

    def test_one_key_under_two_names_keeps_the_placeholder_that_one_name_got(self):
        """The Door area's read of 2a. Bugs: a read that leaves a made key out under one name (another site) takes its
        reference out of the names that keep a placeholder, so Swaps.only switches off the placeholder that the same
        read gave under the other name, and each request of the session through it fails."""
        self.swapping()
        self.given("ROUTE_KEY", MADE_ITEM, "https://" + ROUTE)
        real = vault.hub

        def hub(conf, method, path, body=None):     # the hub names the key twice: at its own site, and at another one
            code, data = real(conf, method, path, body)
            if path.endswith("/read") and code == 200:
                (x,) = data["secrets"]
                data = dict(data, secrets=[x, dict(x, env="ROUTE_KEY_TOO", site="https://" + OTHER_SITE)])
            return code, data
        with patch.object(vault, "hub", hub):
            raw = fleet.vault_call({"op": "read"})
        self.assertEqual((raw["missing"], raw["made"]), (["ROUTE_KEY_TOO"], ["ROUTE_KEY_TOO"]))
        self.assertEqual(self.swap(raw["env"]["ROUTE_KEY"], ROUTE), {"ok": True, "value": MADE_KEY})

    # ---- no other way out
    def test_no_handover_and_no_sign_in_takes_a_made_key_out_of_the_broker(self):
        """Bugs: a handover seals a made key again for another machine's vault, which can be of a program from before
        the rule (or Fleet Vault on a Mac) and gives it to a session there as a value; a sign-in types it into a page
        of the agent's own browser, which the agent's own programs read. A key without the mark goes on as before."""
        made = self.given("ROUTE_KEY", MADE_ITEM, "https://" + ROUTE)
        with self.profiled(made), self.assertRaisesRegex(fleet.Refused, "so it is not handed over"):
            fleet.vault_call({"op": "handover", "job": self.job(login=made)})
        self.assertEqual(hub.q("SELECT * FROM sealed"), [])
        plain = self.given("PLAIN_KEY", {"password": API_KEY, "url": "https://" + ROUTE, "username": ""})
        done = []

        class Browser:                          # the agent's own Chrome: never reached for a made key
            def __init__(self, *_a, **_k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass
        conf = {k: v for k, v in self.broker.conf.items() if k != "_lock"}
        for ref, typed in ((made, False), (plain, True)):
            done.clear()
            with patch.object(vault, "signin_port", lambda user, path=None: 9312), \
                    patch.object(vault, "SigninCdp", Browser), patch.object(vault, "protect", lambda *a, **k: None), \
                    patch.object(vault, "confirm_job", lambda c, job, kind, ref=ref: {"login": ref, "job": job}), \
                    patch.object(vault, "hub", lambda *a, **k: done.append("kept") or (200, {"ok": True, "job": 5})), \
                    patch.object(vault, "signin_page", lambda *a, **k: done.append("typed") or (True, False)):
                if typed:
                    self.assertEqual(vault.signin(conf, 5, os.getuid())["origin"], "https://" + ROUTE)
                    self.assertEqual(done, ["kept", "typed"])     # its origin at the hub, then the page
                else:
                    with self.assertRaisesRegex(vault.Refused, "so it is not typed into a page"):
                        vault.signin(conf, 5, os.getuid())
                    self.assertEqual(done, [])      # no origin kept at the hub, and nothing typed


for _name in dir(MadeKeys):          # each test that MadeKeys inherits expects the setUp of its own class
    if _name.startswith("test_") and _name not in MadeKeys.__dict__:
        setattr(MadeKeys, _name, None)


class StoreSetup(unittest.TestCase):
    """The configuration of the one store, and the operations that root and the vault user run on it."""

    def setUp(self):
        self.dir = Path(private_temp("fs-"))
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

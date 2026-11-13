"""The central vault, end to end (DevOps plan V5): the one way a value reaches a server.

The hub runs in this process with its real routes, its reconciler and a team.json in git. The central vault and the
vault brokers of two machines, vps and studio, are vault.py's own serving code (`Broker(conf).open()` and `serve`, what
`vault.py serve` runs) on Unix sockets, and every copy is locked and opened by the real `age` program. The owner's app
is played here: it seals a value to the central vault's key with age, and signs its pins, its recovery key and each
grant with a P-256 owner key of this test (test_vault_central.owner_sign). The helper is fleet.py's own Helper code.

Six cases: a wrong pin, a key change, an agent that moved, the vault down, a grant removed, and a secret removed from
Founderizer. Then the owner's replace of a value under its reference (owner feature secret_replace): the new value
reaches each vault that holds a copy and the old one leaves each store, a replace that is not the owner's changes
nothing, a copy that waited is never saved, and a delivery that fails leaves the old value whole. Every process here
is this user, so the boundary between OS users (the hub's user and the manager's
cannot read the vault's keys) is checked on the hub itself, as root, at the cut-over (V10).
"""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid

import fleet
import hub
import vault
from test_setup import git
from test_ui_api import OwnerAPI
from test_vault_central import OWNER_C, canon, owner_sign

AGE, KEYGEN = shutil.which("age"), shutil.which("age-keygen")
KEY_REF = "bws://5a3b1c2d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
VALUE = {"password": "sk-e2e-only-" + "q7" * 12}          # a fake API key, in this test only
NEW = {"password": "sk-e2e-new-" + "w3" * 12}             # the value that the owner puts in its place


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(EndToEnd(name) for name in EndToEnd.__dict__ if name.startswith("test_"))


@unittest.skipUnless(AGE and KEYGEN, "the real age program is not installed")
class EndToEnd(OwnerAPI):
    def setUp(self):
        super().setUp()
        self.dir = Path(tempfile.mkdtemp(prefix="fe2e-", dir="/tmp"))     # a Unix socket's path is short
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.dir.chmod(0o700)
        team = {"hub": {"machine": "hub", "port": 8765},
                "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3", "studio": "127.0.0.5"},
                "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []}}}
        self.brokers, self.keys = {}, {}
        for machine in ("vps", "studio"):
            self.keys[machine] = self.broker(machine)
            team["agents"][machine] = {"role": "worker", "runtime": "codex", "machine": machine, "can": ["shell"],
                                       "vault": "broker", "vault_recipient": self.keys[machine]}
        team["vault_stores"] = dict(self.keys)
        seed = self.dir / "seed"
        seed.mkdir()
        (seed / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.dir / "origin.git"))
        git("clone", "-q", str(self.dir / "origin.git"), str(self.dir / "kit"))
        hub.CFG["team_path"] = str(self.dir / "kit" / "team.json")
        self.addCleanup(hub.CFG.pop, "team_path", None)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = team
        state = self.dir / "central"
        state.mkdir(mode=0o700)
        self.central = {"central": True, "hub_uid": vault.os.getuid(), "fleet": hub.fleet_id(),
                        "owner_keys": [OWNER_C], "age": AGE, "age_key": self.keygen(state / "age.key")[0],
                        "socket": str(self.dir / "c.sock"), "state": str(state / "central.json")}
        self.central.update(self.store(state))
        self.serve(self.central)
        for p in (patch.dict(hub.CFG, central_vault=self.central["socket"]),
                  patch.dict(hub.CENTRAL, hub.CENTRAL_START, clear=True),
                  patch.object(hub.Handler, "allowed", lambda handler, who, broker=False: True),
                  patch.object(vault, "log", lambda text: None),
                  patch.object(fleet, "HUB", self.base),
                  patch.object(fleet, "load_agent_key", lambda agent: agent.ljust(43, "k")),
                  patch.object(fleet, "broker_status", lambda: {"callers": True})):
            p.start()
            self.addCleanup(p.stop)
        for machine in ("vps", "studio"):
            hub.q("INSERT INTO agent_keys(agent,sha256,created,source) VALUES(?,?,?,'test')",
                  (machine, hashlib.sha256(fleet.load_agent_key(machine).encode()).hexdigest(), hub.now()))
            self.report(machine)
        self.app("pin", machine="vps", recipient=self.keys["vps"])
        self.app("pin", machine="studio", recipient=self.keys["studio"])
        self.app("recovery", recipient=self.keygen(self.dir / "recovery.key")[1])

    # ---- the pieces
    @staticmethod
    def cmd(**fields):
        """The body of one owner command: a new request id, this hub's generation, and the command's own fields."""
        return dict(fields, request_id=str(uuid.uuid4()), db="test-generation")

    def keygen(self, path):
        subprocess.run([KEYGEN, "-o", str(path)], capture_output=True, check=True)
        path.chmod(0o600)
        return str(path), next(line.split(": ")[1] for line in path.read_text().splitlines() if "public key" in line)

    def store(self, folder):
        """The fleet's own store in this folder: its key, and an empty store locked to it with age."""
        key, public = self.keygen(folder / "store.key")
        empty = subprocess.run([AGE, "-a", "-r", public], input=json.dumps({"v": vault.STORE, "items": {}}),
                               capture_output=True, text=True, check=True).stdout
        (folder / "store.age").write_text(empty)
        (folder / "store.age").chmod(0o600)
        return {"store": str(folder / "store.age"), "store_key": key}

    def serve(self, conf):
        broker = vault.Broker(conf).open()
        threading.Thread(target=broker.serve, daemon=True).start()
        self.addCleanup(broker.close)
        return broker

    def broker(self, machine):
        """A machine's own broker with the fleet's own store; its key is the one the owner pins."""
        folder = self.dir / machine
        folder.mkdir(mode=0o700, exist_ok=True)
        for old in folder.iterdir():
            old.unlink()
        if machine in self.brokers:
            self.brokers[machine].close()
        key, public = self.keygen(folder / "age.key")
        conf = dict({"agent": machine, "hub": self.base, "worker_uid": vault.os.getuid(), "age_key": key,
                     "socket": str(self.dir / f"{machine}.sock"), "age": AGE}, **self.store(folder))
        self.brokers[machine] = self.serve(conf)
        self.brokers[machine].conf = conf
        return public

    def report(self, machine, agent=None, withdrawals=True, replaces=True):
        """The helper status of the agent on this machine, as it reports its broker (hub.broker_report). withdrawals
        False: a vault that cannot give a copy back, as the Mac Studio's could not on 6 November 2026. replaces
        False: a vault whose program is from before the owner's replace."""
        data = {"features": ["secret_deposits", "secret_withdrawals", "broker_callers"],
                "security": {"vault": {"broker_recipient": self.keys[machine], "callers": True, "deposits": True,
                                       "withdrawals": withdrawals, "replaces": replaces, "broker_read_at": hub.now(),
                                       "mode": "broker"}}}
        data = dict(hub.validate_status(data), features=data["features"])    # what the hub keeps of a helper's report
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET "
              "data=excluded.data, reported=excluded.reported", (agent or machine, json.dumps(data), hub.now()))

    def app(self, kind, route=None, **fields):
        """One statement of the owner's, signed in his app, through its owner route."""
        said = canon(dict({"v": 1, "kind": kind, "fleet": hub.fleet_id(), "at": int(hub.now()) + len(hub.q(
            "SELECT 1 FROM ui_controls"))}, **fields))
        route = route or {"pin": "pin", "unpin": "pin", "recovery": "recovery"}.get(kind, "grant")
        code, body = self.request(f"/ui/vault/{route}", self.cmd(statement=said, signature=owner_sign(said)))
        self.assertEqual(code, 200, body)
        return body

    def add_and_give(self, agent):
        """The app's secure form: the catalog entry and the value's fingerprints, the value sealed to the central
        vault's own key, the grant in team.json, and the owner's signed grant."""
        hub.central_read()
        salts = self.request(f"/ui/secrets/salts?db=test-generation&login={KEY_REF}")[1]
        prints = [{"kind": "password", "hash": hashlib.sha256((salts["password"] + VALUE["password"]).encode())
                   .hexdigest(), "len": len(VALUE["password"])}]
        code, body = self.request("/ui/secrets/add", self.cmd(login=KEY_REF, title="SHOP_API_KEY", kind="api_key",
                                                                  env="SHOP_API_KEY", fingerprints=prints))
        self.assertEqual(code, 200, body)
        sealed = subprocess.run([AGE, "-a", "-r", hub.CENTRAL["status"]["recipient"]], input=json.dumps(VALUE),
                                capture_output=True, text=True, check=True).stdout
        code, body = self.request("/ui/vault/intake", self.cmd(login=KEY_REF, ciphertext=sealed))
        self.assertEqual((code, body.get("saved")), (200, "new"), body)
        self.give(agent)

    def give(self, agent, grant="use"):
        code, body = self.request("/ui/secrets/grant", self.cmd(login=KEY_REF, agent=agent, grant=grant))
        self.assertEqual(code, 200, body)
        if grant:
            self.app("grant", login=KEY_REF, agent=agent, machine=hub.TEAM["agents"][agent]["machine"])
        else:
            self.app("ungrant", login=KEY_REF, agent=agent)

    def pass_once(self, t0=None):
        """One pass of the hub's reconciler, then each carrier's helper does its deliveries and withdrawals with
        fleet.py's own Helper code, against its machine's broker."""
        hub.central_read()
        hub.central_reconcile(t0)
        for kind, table in (("deposit", "deposits"), ("withdraw", "withdrawals")):
            for row in hub.q(f"SELECT * FROM {table} WHERE finished IS NULL ORDER BY id"):
                self.carry(kind, row)

    def carry(self, kind, row):
        """The helper of this delivery's or withdrawal's carrier does it, with fleet.py's own Helper code."""
        helper = type("Helper", (), {"agent": row["agent"], "say": lambda self, text: None})()
        with patch.object(fleet, "AGENT", row["agent"]), \
                patch.object(fleet, "vault_socket", lambda m=row["machine"]: self.brokers[m].conf["socket"]):
            getattr(fleet.Helper, kind)(helper, {kind: row["id"]})

    def session_keys(self, machine):
        """What the vault of this machine gives a session start of its agent (the broker's read): {variable: value}."""
        with patch.object(fleet, "AGENT", machine), \
                patch.object(fleet, "vault_socket", lambda: self.brokers[machine].conf["socket"]):
            return fleet.broker_job_request(machine, {"op": "read", "for": "session"}, timeout=60)["env"]

    def sealed(self, value):
        """A copy of this value as the owner's app seals it: to the central vault's own key, with age."""
        hub.central_read()
        return subprocess.run([AGE, "-a", "-r", hub.CENTRAL["status"]["recipient"]], input=json.dumps(value),
                              capture_output=True, text=True, check=True).stdout

    def register(self, value):
        """The app's hub step for a new value under the reference that the list has: its fingerprints, and the same
        entry, so nothing is committed."""
        salts = self.request(f"/ui/secrets/salts?db=test-generation&login={KEY_REF}")[1]
        prints = [{"kind": "password", "hash": hashlib.sha256((salts["password"] + value["password"]).encode())
                   .hexdigest(), "len": len(value["password"])}]
        code, body = self.request("/ui/secrets/add", self.cmd(login=KEY_REF, title="SHOP_API_KEY", kind="api_key",
                                                                  env="SHOP_API_KEY", fingerprints=prints))
        self.assertEqual((code, body.get("changed")), (200, False), body)

    def statement(self, copy, at=None, **other):
        """The owner's replace statement about this sealed copy, in its canonical form."""
        self.at = at or max(getattr(self, "at", 0) + 1, int(hub.now()) + len(hub.q("SELECT 1 FROM ui_controls")))
        return canon(dict({"v": 1, "kind": "replace", "fleet": hub.fleet_id(), "login": KEY_REF, "at": self.at,
                           "sha256": hashlib.sha256(copy.encode()).hexdigest()}, **other))

    def replace(self, value=NEW, sign=owner_sign, **other):
        """Add secret for a name that the list has: the hub step, then the sealed copy with the owner's signed
        statement about it. (code, body) of the intake."""
        self.register(value)
        copy = self.sealed(value)
        said = self.statement(copy, **other)
        return self.request("/ui/vault/intake", self.cmd(login=KEY_REF, ciphertext=copy, statement=said,
                                                         signature=sign(said)))

    def stores(self):
        """Each store of this fleet, opened with its own key, as one text: the central vault's and each machine's."""
        return json.dumps([vault.LocalStore(conf).opened() for conf in
                           [self.central] + [self.brokers[m].conf for m in sorted(self.brokers)]])

    def held(self, machine):
        """What this machine's store holds, opened with its own key: {reference: value}."""
        items = vault.LocalStore(self.brokers[machine].conf).opened()
        return {"bws://" + sid: json.loads(x["value"]) for sid, x in items.items()}

    # ---- the five cases
    def test_a_grant_reaches_only_its_holders_machine_and_leaves_when_the_grant_goes(self):
        self.add_and_give("vps")
        self.pass_once()
        self.assertEqual(self.held("vps"), {KEY_REF: VALUE})
        self.assertEqual(self.held("studio"), {})                       # pinned, and no grant of the owner's there
        sealed = hub.q1("SELECT * FROM deposits WHERE machine='vps'")
        self.assertEqual((sealed["recipient"], sealed["ciphertext"], sealed["ok"]), (self.keys["vps"], None, 1))
        self.give("vps", None)                                          # the grant removed, and its ungrant signed
        self.pass_once()
        self.assertEqual(self.held("vps"), {})
        with self.assertRaises(hub.Refusal) as refused:                 # the vault itself refuses the hub now
            hub.central_call("seal", {"login": KEY_REF, "machine": "vps"})
        self.assertIn("has signed no grant", str(refused.exception))

    def test_a_wrong_pin_gets_no_copy(self):
        """The owner's pin of studio is not the key its broker reports: nothing is sealed for it, and a copy sealed to
        that pin would open for nobody on studio."""
        self.add_and_give("vps")
        hub.TEAM["agents"]["studio"]["secrets"] = {KEY_REF: "use"}
        self.app("grant", login=KEY_REF, agent="studio", machine="studio")
        other = self.keygen(self.dir / "other.key")[1]
        self.app("pin", machine="studio", recipient=other)
        self.pass_once()
        self.assertEqual(self.held("studio"), {})
        self.assertEqual(hub.q("SELECT * FROM deposits WHERE machine='studio'"), [])
        self.assertIn("pin_mismatch", next(m for m in hub.vault_view()["machines"] if m["machine"] == "studio")["missing"])
        copy = hub.central_call("seal", {"login": KEY_REF, "machine": "studio"})["ciphertext"]
        self.assertEqual(subprocess.run([AGE, "-d", "-i", self.brokers["studio"].conf["age_key"]], input=copy,
                                        capture_output=True, text=True).returncode, 1)

    def test_a_new_key_on_a_machine_gets_the_secret_again_sealed_to_it(self):
        self.add_and_give("vps")
        self.pass_once()
        old = self.keys["vps"]
        self.keys["vps"] = self.broker("vps")                           # a new broker: a new key and an empty store
        hub.TEAM["vault_stores"]["vps"] = hub.TEAM["agents"]["vps"]["vault_recipient"] = self.keys["vps"]
        self.report("vps")
        self.pass_once()
        self.assertEqual(self.held("vps"), {})                          # the old key's pin: nothing for the new key
        self.app("pin", machine="vps", recipient=self.keys["vps"])
        self.pass_once()
        self.assertEqual(self.held("vps"), {KEY_REF: VALUE})
        newest = hub.q1("SELECT * FROM deposits WHERE machine='vps' ORDER BY id DESC")
        self.assertEqual((newest["recipient"], newest["ok"]), (self.keys["vps"], 1))
        self.assertNotEqual(old, self.keys["vps"])

    def test_an_agent_that_moved_gets_its_secret_only_with_a_new_signed_grant(self):
        """keeper stays on the machine vps and holds nothing, so its helper carries the vault's giving back there. (A
        machine that no agent is left on has no helper to carry it: its store goes with the machine.)"""
        self.add_and_give("vps")
        self.pass_once()
        self.assertEqual(self.held("vps"), {KEY_REF: VALUE})
        hub.TEAM["agents"]["keeper"] = {k: v for k, v in hub.TEAM["agents"]["vps"].items() if k != "secrets"}
        hub.q("INSERT INTO agent_keys(agent,sha256,created,source) VALUES('keeper',?,?,'test')",
              (hashlib.sha256(fleet.load_agent_key("keeper").encode()).hexdigest(), hub.now()))
        self.report("vps", agent="keeper")
        hub.TEAM["agents"]["vps"]["machine"] = "studio"                 # vps now works on studio
        hub.TEAM["agents"]["vps"]["vault_recipient"] = self.keys["studio"]
        self.report("studio", agent="vps")
        self.pass_once()
        self.assertEqual(self.held("studio"), {})                       # the signed grant names vps's old machine
        self.assertEqual(self.held("vps"), {})                          # and the old machine gave it back
        self.app("grant", login=KEY_REF, agent="vps", machine="studio")
        self.pass_once()
        self.assertEqual(self.held("studio"), {KEY_REF: VALUE})

    def test_when_the_vault_does_not_answer_nothing_is_sent_and_the_agents_keep_their_keys(self):
        self.add_and_give("vps")
        self.pass_once()
        t0 = hub.now()
        hub.central_read(t0)
        with patch.dict(hub.CFG, central_vault=str(self.dir / "gone.sock")):
            hub.central_read(t0 + hub.CENTRAL_FRESH + 1)
            self.assertNotIn("central_vault", hub.ui_features())
            code, body = self.request("/ui/secrets/add", self.cmd(
                login="bws://6a3b1c2d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", title="NEW_KEY", kind="api_key", env="NEW_KEY"))
            self.assertEqual(code, 503, body)
            self.assertEqual(hub.central_sweep(t0 + hub.CENTRAL_FRESH + 2), None)     # no pass, no delivery
            hub.central_read(t0 + 2 * hub.CENTRAL_FRESH + 2)
        self.assertEqual(self.held("vps"), {KEY_REF: VALUE})            # the machine's own vault keeps its key
        said = hub.q1("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id DESC")["text"]
        self.assertIn("raise_needs_you", said)
        self.assertNotIn(VALUE["password"], json.dumps([dict(r) for r in hub.q("SELECT * FROM events")]))

    def test_remove_from_founderizer_empties_the_central_vault_after_the_last_copy_left(self):
        """V10 of the DevOps plan, 6 November 2026: after Remove from Founderizer the central vault still held the
        value. It goes now, once no machine's vault holds a copy: the hub takes a copy back only while the central
        vault lists the secret, so studio, whose vault cannot give its copy back yet, keeps it there until it can."""
        self.add_and_give("vps")
        self.give("studio")
        self.pass_once()
        self.assertEqual((self.held("vps"), self.held("studio")), ({KEY_REF: VALUE}, {KEY_REF: VALUE}))
        self.report("studio", withdrawals=False)
        self.give("vps", None)
        self.give("studio", None)
        base = self.request("/ui/team?db=test-generation")[1]["sha256"]
        code, body = self.request("/ui/team/logins", self.cmd(base_sha256=base, login=KEY_REF, delete=True))
        self.assertEqual((code, body.get("deleted")), (200, True), body)
        self.assertNotIn(KEY_REF, hub.logins())
        self.pass_once()
        self.assertEqual((self.held("vps"), self.held("studio")), ({}, {KEY_REF: VALUE}))
        self.assertEqual(hub.central_call("inventory")["logins"], [KEY_REF])         # studio still holds a copy
        self.report("studio")                                                         # its vault gives keys back now
        self.pass_once()
        self.assertEqual(self.held("studio"), {})
        self.pass_once()
        self.assertEqual(hub.central_call("inventory")["logins"], [])
        self.assertEqual(vault.LocalStore(self.central).opened(), {})
        self.assertEqual(hub.central_read()["items"], 0)
        # A hub that is broken into cannot put a value of its own under the removed name, for a later grant to send.
        other = {"password": "sk-hub-own-" + "z9" * 12}
        salts = {"password": "0f" * 16, "totp": "a5" * 16}
        sealed = subprocess.run([AGE, "-a", "-r", hub.CENTRAL["status"]["recipient"]], input=json.dumps(other),
                                capture_output=True, text=True, check=True).stdout
        with self.assertRaises(hub.Refusal) as refused:
            hub.central_call("intake", {"login": KEY_REF, "title": "SHOP_API_KEY", "item": "api_key",
                                        "ciphertext": sealed, "salts": salts, "fingerprints": [
                                            {"kind": "password", "len": len(other["password"]), "hash": hashlib.sha256(
                                                (salts["password"] + other["password"]).encode()).hexdigest()}]})
        self.assertIn("removed from the fleet", str(refused.exception))
        self.assertEqual(hub.central_call("inventory")["logins"], [])

    # ---- the owner replaces a value under its reference (owner feature secret_replace)
    def test_the_owner_replaces_a_value_and_each_vault_that_holds_a_copy_gets_the_new_one(self):
        self.add_and_give("vps")
        self.give("vps", "read")                    # its sessions read the key
        self.give("studio")
        self.pass_once()
        self.assertEqual((self.held("vps"), self.held("studio")), ({KEY_REF: VALUE}, {KEY_REF: VALUE}))
        self.assertEqual(self.session_keys("vps"), {"SHOP_API_KEY": VALUE["password"]})
        self.assertIn("secret_replace", hub.ui_features())
        team, stamp = json.dumps(hub.TEAM, sort_keys=True), hub.key_stamp("vps")
        commits = git("rev-list", "--count", "HEAD", cwd=self.dir / "kit")
        self.report("studio", replaces=False)       # a vault whose program is from before the replace

        before = hub.now()
        code, body = self.replace()
        self.assertEqual((code, body["login"], body["saved"]), (200, KEY_REF, "replaced"), body)
        # a pass of the reconciler that started before the replace makes no delivery: its seal can hold the old value
        self.pass_once(before)
        self.assertEqual((self.held("vps"), hub.q1("SELECT COUNT(*) n FROM deposits")["n"]), ({KEY_REF: VALUE}, 2))
        # the same reference, the same entry and the same grants: nothing of team.json changed, and no commit
        self.assertEqual(json.dumps(hub.TEAM, sort_keys=True), team)
        self.assertEqual(git("rev-list", "--count", "HEAD", cwd=self.dir / "kit"), commits)
        self.assertEqual(vault.LocalStore(self.central).opened()[KEY_REF[6:]]["value"], canon(NEW))
        self.assertEqual(len(vault.LocalStore(self.central).opened()), 1)
        # the hub masks the new value, and goes on masking the old one
        self.assertTrue(hub.secret_hit("a text with " + NEW["password"]))
        self.assertTrue(hub.secret_hit("a text with " + VALUE["password"]))
        value = hub.q1("SELECT * FROM secret_values WHERE login=?", (KEY_REF,))
        self.assertEqual(len(json.loads(value["prints"])), 1)
        self.assertNotIn(NEW["password"], json.dumps([dict(r) for r in hub.q("SELECT * FROM ui_controls")]))

        self.pass_once()
        self.assertEqual(self.held("vps"), {KEY_REF: NEW})              # its vault put it in the place of the old one
        self.assertEqual(hub.q1("SELECT result FROM deposits WHERE machine='vps' ORDER BY id DESC")["result"],
                         "Saved in this machine's vault.")               # the helper's words for a replaced value
        self.assertEqual(self.held("studio"), {KEY_REF: VALUE})         # this vault cannot yet: it keeps the old value
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM deposits WHERE machine='studio'")["n"], 1)
        self.assertEqual(self.session_keys("vps"), {"SHOP_API_KEY": NEW["password"]})      # the next session start
        self.assertGreater(hub.key_stamp("vps"), stamp)                 # a helper reads its kept keys again
        self.report("studio")                                           # its program is the new one now
        self.pass_once()
        self.assertEqual(self.held("studio"), {KEY_REF: NEW})
        self.assertNotIn(VALUE["password"], self.stores())              # the old value left each store
        self.assertEqual(hub.central_held(), {"studio": [KEY_REF], "vps": [KEY_REF]})
        self.assertEqual([(r["machine"], r["ok"]) for r in hub.q("SELECT * FROM deposits ORDER BY id")],
                         [("studio", 1), ("vps", 1), ("vps", 1), ("studio", 1)])
        self.pass_once()                                                # and nothing more is sent
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM deposits")["n"], 4)
        # the old copy cannot come back: not as a plain intake, and not with the owner's older statement
        code, body = self.request("/ui/vault/intake", self.cmd(login=KEY_REF, ciphertext=self.sealed(VALUE)))
        self.assertEqual(code, 409, body)
        self.assertIn("holds another value under this reference", body["error"])
        code, body = self.replace(VALUE, at=self.at - 1)
        self.assertEqual(code, 409, body)
        self.assertIn("as new or newer", body["error"])
        self.assertEqual(vault.LocalStore(self.central).opened()[KEY_REF[6:]]["value"], canon(NEW))
        # a grant that goes takes the new value back, as any delivered secret
        self.give("studio", None)
        self.pass_once()
        self.assertEqual(self.held("studio"), {})

    def test_a_replace_that_is_not_the_owners_changes_nothing(self):
        """The hub cannot make the owner's statement, so a hub that is broken into puts no value under his name."""
        self.add_and_give("vps")
        self.pass_once()
        stranger = 0x2B0C0FFEE5EED0F7E57B1A5ED0D1E7C0A2B3C4D5E6F708192A3B4C5D6E7F8011      # no owner key
        copy = self.sealed(NEW)
        said = self.statement(copy)
        cases = ((dict(ciphertext=copy), "holds another value under this reference"),
                 (dict(ciphertext=copy, statement=said, signature=owner_sign(said, stranger)), "valid signature of the owner"),
                 (dict(ciphertext=self.sealed({"password": "sk-the-hubs-own-" + "h1" * 10}), statement=said,
                       signature=owner_sign(said)), "another copy than this one"),
                 (dict(ciphertext=copy, statement=self.statement(copy, fleet="0123456789abcdef"),
                       signature=owner_sign(self.statement(copy, fleet="0123456789abcdef"))), "another fleet"))
        self.register(NEW)
        for fields, why in cases:
            code, body = self.request("/ui/vault/intake", self.cmd(login=KEY_REF, **fields))
            self.assertEqual(code, 409, body)
            self.assertIn(why, body["error"])
        for fields in (dict(ciphertext=copy, statement=said), dict(ciphertext=copy, signature=owner_sign(said)),
                       dict(ciphertext=copy, statement=canon({"v": 1, "kind": "grant"}), signature=owner_sign(said))):
            self.assertEqual(self.request("/ui/vault/intake", self.cmd(login=KEY_REF, **fields))[0], 400)
        self.assertEqual(vault.LocalStore(self.central).opened()[KEY_REF[6:]]["value"], canon(VALUE))
        self.assertEqual(hub.q("SELECT * FROM secret_values"), [])
        self.pass_once()
        self.assertEqual(self.held("vps"), {KEY_REF: VALUE})
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM deposits")["n"], 1)
        self.assertNotIn(NEW["password"], self.stores())
        # a central vault from before the replace: the hub serves no such feature and passes no statement on
        with patch.dict(hub.CENTRAL, status={k: v for k, v in hub.CENTRAL["status"].items() if k != "replaces"}):
            self.assertNotIn("secret_replace", hub.ui_features())
            code, body = self.request("/ui/vault/intake", self.cmd(login=KEY_REF, ciphertext=copy, statement=said,
                                                                   signature=owner_sign(said)))
            self.assertEqual((code, body["error"]), (409, "the central vault's program does not replace a value yet"))

    def test_a_copy_that_waits_at_a_replace_is_never_saved_and_the_same_save_ends_a_replace_that_stopped(self):
        self.add_and_give("vps")
        self.pass_once()
        self.give("studio")
        hub.central_read()
        hub.central_reconcile()                     # a copy of the old value waits for studio, which did not take it
        waits = hub.q1("SELECT * FROM deposits WHERE machine='studio'")
        self.assertIsNone(waits["finished"])
        # The hub stops between the central vault's write and its own record: the vault holds the new value, and the
        # hub knows nothing of it.
        self.register(NEW)
        copy = self.sealed(NEW)
        said = self.statement(copy)
        self.assertEqual(hub.central_intake(KEY_REF, hub.sealed_copy(copy), said, owner_sign(said))["saved"], "replaced")
        self.assertEqual(hub.q("SELECT * FROM secret_values"), [])
        # The same Save again (the form keeps the copy and the statement): the vault says "same", and the hub's
        # record is written now. The copy that waited ends, and no vault gets it.
        code, body = self.request("/ui/vault/intake", self.cmd(login=KEY_REF, ciphertext=copy, statement=said,
                                                               signature=owner_sign(said)))
        self.assertEqual((code, body["saved"]), (200, "same"), body)
        ended = hub.q1("SELECT * FROM deposits WHERE id=?", (waits["id"],))
        self.assertEqual((ended["ok"], ended["ciphertext"], ended["result"]),
                         (0, None, "The owner replaced its value after this copy was sealed."))
        with patch.object(fleet, "AGENT", "studio"), \
                patch.object(fleet, "vault_socket", lambda: self.brokers["studio"].conf["socket"]), \
                self.assertRaises(fleet.Refused):
            fleet.broker_job_request("studio", {"op": "deposit", "job": waits["id"]}, timeout=60)
        self.assertEqual(self.held("studio"), {})
        # The same save a third time changes nothing more: the record keeps its time, and the copies of the new
        # value that wait now are not ended.
        record = dict(hub.q1("SELECT * FROM secret_values"))
        hub.central_read()
        waiting = hub.central_reconcile()["delivered"]
        self.assertEqual(len(waiting), 2)
        self.assertEqual(self.request("/ui/vault/intake", self.cmd(login=KEY_REF, ciphertext=copy, statement=said,
                                                                   signature=owner_sign(said)))[1]["saved"], "same")
        self.assertEqual(dict(hub.q1("SELECT * FROM secret_values")), record)
        self.assertEqual([r["id"] for r in hub.q("SELECT id FROM deposits WHERE finished IS NULL ORDER BY id")], waiting)
        self.pass_once()
        self.assertEqual((self.held("vps"), self.held("studio")), ({KEY_REF: NEW}, {KEY_REF: NEW}))
        self.assertNotIn(VALUE["password"], self.stores())

    def test_a_hub_that_stopped_at_a_replace_reads_it_in_the_vault_s_status(self):
        """The same stop, and the owner does not save again. The hub's next read of the central vault's status
        finds the replace that it has no record of, and each vault that holds a copy gets the new value."""
        self.add_and_give("vps")
        self.pass_once()
        self.register(NEW)
        copy = self.sealed(NEW)
        said = self.statement(copy)
        self.assertEqual(hub.central_intake(KEY_REF, hub.sealed_copy(copy), said, owner_sign(said))["saved"], "replaced")
        self.assertEqual((hub.q("SELECT * FROM secret_values"), self.held("vps")), ([], {KEY_REF: VALUE}))
        self.pass_once()                            # it reads the status first, as the hub's timer does
        self.assertEqual(hub.q1("SELECT sha256 FROM secret_values")["sha256"], hashlib.sha256(copy.encode()).hexdigest())
        self.assertEqual(self.held("vps"), {KEY_REF: NEW})
        self.assertNotIn(VALUE["password"], self.stores())
        self.pass_once()
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM deposits")["n"], 2)

    def test_a_delivery_that_fails_leaves_the_old_value_whole_and_its_copy_still_counts(self):
        self.add_and_give("vps")
        self.pass_once()
        self.assertEqual(self.replace()[0], 200)
        store = self.brokers["vps"].conf["store"]
        keep = vault.LocalStore.keep

        def broken(this, items):                    # the store of vps cannot be written; the central vault's can
            if this.conf["store"] == store:
                raise vault.Refused("the vault store could not be saved")
            return keep(this, items)
        with patch.object(vault.LocalStore, "keep", broken):
            self.pass_once()
        failed = hub.q1("SELECT * FROM deposits ORDER BY id DESC")
        self.assertEqual((failed["ok"], failed["result"]), (0, "the vault broker refused: the vault store could not be "
                                                               "saved"))
        self.assertEqual(self.held("vps"), {KEY_REF: VALUE})            # the old value, whole
        self.assertEqual(hub.central_held(), {"vps": [KEY_REF]})        # the copy of the earlier delivery counts
        self.pass_once()                                                # a delivery that failed waits before the next
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM deposits")["n"], 2)
        hub.q("UPDATE deposits SET finished=finished-? WHERE id=?", (hub.CENTRAL_RETRY + 1, failed["id"]))
        self.pass_once()                                                # after the wait, the hub sends it again
        self.assertEqual(self.held("vps"), {KEY_REF: NEW})
        # and a copy that failed to be replaced still goes back when its grant goes
        self.assertEqual(self.replace({"password": "sk-e2e-third-" + "t5" * 12})[0], 200)
        with patch.object(vault.LocalStore, "keep", broken):
            self.pass_once()
        self.assertEqual(self.held("vps"), {KEY_REF: NEW})
        self.give("vps", None)
        self.pass_once()
        self.assertEqual(self.held("vps"), {})


if __name__ == "__main__":
    unittest.main()

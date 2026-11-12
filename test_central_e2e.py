"""The central vault, end to end (DevOps plan V5): the one way a value reaches a server.

The hub runs in this process with its real routes, its reconciler and a team.json in git. The central vault and the
vault brokers of two machines, vps and studio, are vault.py's own serving code (`Broker(conf).open()` and `serve`, what
`vault.py serve` runs) on Unix sockets, and every copy is locked and opened by the real `age` program. The owner's app
is played here: it seals a value to the central vault's key with age, and signs its pins, its recovery key and each
grant with a P-256 owner key of this test (test_vault_central.owner_sign). The helper is fleet.py's own Helper code.

Six cases: a wrong pin, a key change, an agent that moved, the vault down, a grant removed, and a secret removed from
Founderizer. Every process here is this user, so the boundary between OS users (the hub's user and the manager's
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

    def report(self, machine, agent=None, withdrawals=True):
        """The helper status of the agent on this machine, as it reports its broker (hub.broker_report). withdrawals
        False: a vault that cannot give a copy back, as the Mac Studio's could not on 6 November 2026."""
        data = {"features": ["secret_deposits", "secret_withdrawals", "broker_callers"],
                "security": {"vault": {"broker_recipient": self.keys[machine], "callers": True, "deposits": True,
                                       "withdrawals": withdrawals, "broker_read_at": hub.now(), "mode": "broker"}}}
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

    def pass_once(self):
        """One pass of the hub's reconciler, then each carrier's helper does its deliveries and withdrawals with
        fleet.py's own Helper code, against its machine's broker."""
        hub.central_read()
        hub.central_reconcile()
        for kind, table in (("deposit", "deposits"), ("withdraw", "withdrawals")):
            for row in hub.q(f"SELECT * FROM {table} WHERE finished IS NULL ORDER BY id"):
                helper = type("Helper", (), {"agent": row["agent"], "say": lambda self, text: None})()
                with patch.object(fleet, "AGENT", row["agent"]), \
                        patch.object(fleet, "vault_socket", lambda m=row["machine"]: self.brokers[m].conf["socket"]):
                    getattr(fleet.Helper, kind)(helper, {kind: row["id"]})

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


if __name__ == "__main__":
    unittest.main()

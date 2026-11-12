"""The central vault, the hub's half (owner feature central_vault).

A fake central vault serves the socket protocol (one JSON line in, one line out) on a temporary Unix socket, and
`hub.CFG["central_vault"]` points at it. The hub reads its status, serves `central_vault` only while that read is ok
and fresh, passes the owner's own commands through, delivers to each pinned machine only what its agents hold, takes
back what nobody there holds any more, and carries the vault's sealed store in a copy of the fleet. The fake looks,
at every request, whether any thread holds the hub's LOCK: none may. `hubsetup.py central-vault` is run against a
stand-in machine that writes into a temporary root and runs nothing.
"""
import base64
import contextlib
import hashlib
import io
import json
import os
import shlex
import shutil
import socket
import subprocess
import sqlite3
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import fleet
import hub
import hubsetup
import lifecycle
import releases
from test_backup_restore import Fixture
from test_ui_api import OwnerAPI

LOGIN_A = "bws://11111111-2222-4333-8444-55555555555b"      # an API key: vps reads it, studio uses it
LOGIN_B = "bws://21111111-2222-4333-8444-55555555555b"      # a login: vps uses it
LOGIN_C = "bws://31111111-2222-4333-8444-55555555555b"      # an API key the central vault does not hold
LOGIN_D = "bws://41111111-2222-4333-8444-55555555555b"      # a secret the central vault holds, out of the catalog
STORE_A, STORE_B, OTHER = "age1" + "q" * 58, "age1" + "r" * 58, "age1" + "s" * 58
CENTRAL_KEY, STORE_KEY, RECOVERY = "age1" + "c" * 58, "age1" + "d" * 58, "age1" + "e" * 58
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3", "w4": "127.0.0.4",
                      "studio": "127.0.0.5"},
        "vault_stores": {"vps": STORE_A, "studio": STORE_B},
        "logins": {LOGIN_A: {"title": "OPENAI_API_KEY", "kind": "api_key", "env": "OPENAI_API_KEY"},
                   LOGIN_B: {"title": "shop.example.com · ops", "kind": "login"},
                   LOGIN_C: {"title": "STRIPE_KEY", "kind": "api_key", "env": "STRIPE_KEY"}},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"],
                           "vault": "broker", "vault_recipient": STORE_A,
                           "secrets": {LOGIN_A: "read", LOGIN_B: "use", LOGIN_C: "read"}},
                   "worker4": {"role": "worker", "runtime": "codex", "machine": "w4", "can": ["shell"]},
                   "studio": {"role": "worker", "runtime": "claude", "machine": "studio", "can": ["shell"],
                              "vault": "broker", "vault_recipient": STORE_B, "secrets": {LOGIN_A: "use"}}}}
KIT = os.path.dirname(os.path.abspath(__file__))


def armored(payload=b"x" * 40):
    """An armored age file of the shape the hub takes (hub.sealed_copy): it checks the header and opens nothing."""
    blob = b"age-encryption.org/v1\n-> X25519 " + base64.b64encode(payload) + b"\n--- " + base64.b64encode(payload) \
        + b"\n" + payload
    text = base64.b64encode(blob).decode()
    return "-----BEGIN AGE ENCRYPTED FILE-----\n" + "".join(text[at:at + 64] + "\n" for at in range(0, len(text), 64)) \
        + "-----END AGE ENCRYPTED FILE-----\n"


def statement(**fields):
    """One of the owner's statements, in the canonical form the app signs (sorted keys, no spaces)."""
    return json.dumps(dict({"v": 1, "at": 1761300000}, **fields), sort_keys=True, separators=(",", ":"))


SIGNATURE = base64.b64encode(bytes(range(70))).decode()      # the shape of a DER signature: the hub reads no more


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (Central, CentralCopy, HelperWithdraw, Install, KitClone):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class FakeCentral:
    """A central vault that speaks the socket protocol on a temporary socket. It keeps every request it was sent, and
    while it answers one it looks whether any thread holds hub.LOCK, which none may (hub.central_call)."""

    def __init__(self, path, fleet):
        self.path, self.fleet = path, fleet
        self.requests, self.locked, self.refuse, self.sealed = [], [], {}, 0
        self.pins, self.recovery, self.items = {}, None, {}
        self.grants, self.pool = [], []         # what the owner signed: {login, agent, machine}, and pooled logins
        self.removes = True                     # its status says that it serves remove; an older program's does not
        self.stop = threading.Event()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(path)
        self.sock.listen(8)
        self.sock.settimeout(0.1)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(5)
                data = b""
                while not data.endswith(b"\n"):
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                request = json.loads(data)
                if hub.LOCK.acquire(blocking=False):
                    hub.LOCK.release()
                else:
                    self.locked.append(request.get("op"))
                self.requests.append(request)
                conn.sendall((json.dumps(self.answer(request)) + "\n").encode())

    def close(self):
        if not self.stop.is_set():
            self.stop.set()
            self.thread.join(5)
            self.sock.close()

    def ops(self, op):
        return [r for r in self.requests if r.get("op") == op]

    @staticmethod
    def no(error):
        return {"ok": False, "v": 2, "error": error}

    def answer(self, r):
        op = r.get("op")
        if r.get("v") != 2:
            return self.no("this vault speaks protocol 2")
        if op in self.refuse:
            return self.no(self.refuse[op])
        if op == "status":
            return {"ok": True, "v": 2, "central": True, "recipient": CENTRAL_KEY, "store_recipient": STORE_KEY,
                    "fleet": self.fleet, "owner_keys": 1,
                    "pins": {m: {"recipient": k, "at": 1761300000} for m, k in self.pins.items()},
                    "recovery": self.recovery, "grants": list(self.grants), "pool": list(self.pool),
                    "items": len(self.items), "source": "0" * 64, **({"removes": True} if self.removes else {})}
        if op == "intake":
            saved = "same" if r["login"] in self.items else "new"
            self.items[r["login"]] = r["title"]
            return {"ok": True, "v": 2, "login": r["login"], "saved": saved}
        if op in ("pin", "unpin", "recovery"):
            said = json.loads(r["statement"])
            if said["kind"] != op:
                return self.no("this statement is not of this kind")
            if op == "pin":
                self.pins[said["machine"]] = said["recipient"]
                return {"ok": True, "v": 2, "kind": op, "machine": said["machine"], "recipient": said["recipient"],
                        "saved": "new"}
            if op == "unpin":
                self.pins.pop(said["machine"], None)
                return {"ok": True, "v": 2, "kind": op, "machine": said["machine"], "saved": "removed"}
            self.recovery = said["recipient"]
            return {"ok": True, "v": 2, "kind": op, "recipient": said["recipient"], "saved": "new"}
        if op in ("grant", "ungrant", "pool", "unpool"):
            said = json.loads(r["statement"])
            if said["kind"] != op:
                return self.no("this statement is not of this kind")
            if op in ("grant", "ungrant"):
                self.grants = [g for g in self.grants if (g["login"], g["agent"]) != (said["login"], said["agent"])]
                if op == "grant":
                    self.grants.append({"login": said["login"], "agent": said["agent"], "machine": said["machine"]})
            else:
                self.pool = sorted(set(self.pool) - {said["login"]} | ({said["login"]} if op == "pool" else set()))
            return dict({"ok": True, "v": 2, "kind": op, "saved": "removed" if op.startswith("un") else "new"},
                        **{k: said[k] for k in ("login", "agent", "machine") if k in said})
        if op == "seal":
            if r["machine"] not in self.pins or r["login"] not in self.items:
                return self.no("this machine has no pin, or the store has no such item")
            if r["login"] not in self.pool and not any(g["login"] == r["login"] and g["machine"] == r["machine"]
                                                       for g in self.grants):
                return self.no("the owner has signed no grant of this secret to an agent of this machine")
            self.sealed += 1
            text = armored(f"{r['login']} for {r['machine']}, copy {self.sealed}".encode())
            return {"ok": True, "v": 2, "login": r["login"], "machine": r["machine"],
                    "recipient": self.pins[r["machine"]], "title": self.items[r["login"]], "ciphertext": text,
                    "sha256": hashlib.sha256(text.encode()).hexdigest()}
        if op == "inventory":
            return {"ok": True, "v": 2, "logins": sorted(self.items)}
        if op == "remove" and self.removes:
            if r["login"] in self.pool or any(g["login"] == r["login"] for g in self.grants):
                return self.no("a grant or the pool that the owner signed still names this login, so it is not removed")
            held = self.items.pop(r["login"], None) is not None
            return {"ok": True, "v": 2, "login": r["login"], "removed": "removed" if held else "absent"}
        if op == "export":
            if not self.recovery:
                return self.no("no recovery key is stored")
            return {"ok": True, "v": 1, "made_at": 1761300000.5, "items": len(self.items),
                    "store_recipient": STORE_KEY, "recovery": self.recovery, "store": armored(b"the whole store"),
                    "key": armored(b"the store key, sealed")}
        return self.no("unknown op")


class WithCentral:
    """A fake central vault for one test, with the hub's own central state put back afterwards."""

    def start_central(self):
        folder = tempfile.mkdtemp(prefix="fleet-central-")
        if len(folder) > 80:                    # a Unix socket's path is short (104 bytes on a Mac)
            shutil.rmtree(folder, ignore_errors=True)
            folder = tempfile.mkdtemp(prefix="fc-", dir="/tmp")
        self.addCleanup(shutil.rmtree, folder, True)
        self.vault = FakeCentral(os.path.join(folder, "vault.sock"), hub.fleet_id())
        self.addCleanup(self.vault.close)
        state = patch.dict(hub.CENTRAL, hub.CENTRAL_START, clear=True)
        state.start()
        self.addCleanup(state.stop)
        hub.CFG["central_vault"] = self.vault.path
        self.addCleanup(hub.CFG.pop, "central_vault", None)


class Central(WithCentral, OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        hub.CFG["attachment_dir"] = os.path.join(self.tmp.name, "attachments")       # nothing here sweeps ~/.fleet
        self.addCleanup(hub.CFG.pop, "attachment_dir", None)
        allowed = patch.object(hub.Handler, "allowed", lambda handler, who, broker=False: True)
        allowed.start()
        self.addCleanup(allowed.stop)
        for agent in ("vps", "studio"):
            hub.q("INSERT INTO agent_keys(agent,sha256,created,source) VALUES(?,?,?,?)",
                  (agent, hashlib.sha256(agent.encode()).hexdigest(), hub.now(), "test"))
            self.report(agent)
        self.start_central()
        self.vault.items = {LOGIN_A: "OPENAI_API_KEY", LOGIN_B: "shop.example.com · ops"}
        self.vault.grants = self.signed_grants()            # the owner signed every grant of TEAM (DevOps plan V1)

    # ---- helpers
    @staticmethod
    def signed_grants():
        """Every grant of team.json now, as the owner's app signed them: {login, agent, machine}."""
        return [{"login": ref, "agent": name, "machine": a["machine"]} for name, a in sorted(hub.TEAM["agents"].items())
                for ref in sorted(a.get("secrets") or {})]

    def report(self, agent, key=None, features=("secret_deposits", "secret_withdrawals"), withdrawals=True):
        """One helper status, as a machine reports its vault (hub.broker_report)."""
        key = key or {"vps": STORE_A, "studio": STORE_B}[agent]
        data = {"features": list(features),
                "security": {"vault": {"broker_recipient": key, "callers": True, "deposits": True,
                                       "withdrawals": withdrawals, "broker_read_at": hub.now(), "mode": "broker"}}}
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET "
              "data=excluded.data, reported=excluded.reported", (agent, json.dumps(data), hub.now()))

    def view(self):
        code, body = self.request("/ui/vault?db=test-generation")
        self.assertEqual(code, 200, body)
        return body

    def machines(self):
        return {m["machine"]: m for m in self.view()["machines"]}

    def deposits(self, machine=None):
        return hub.q("SELECT * FROM deposits" + (" WHERE machine=?" if machine else "") + " ORDER BY id",
                     (machine,) if machine else ())

    def deliver_and_keep(self):
        """vps is pinned, gets LOGIN_A and LOGIN_B, and its vault reports both saved."""
        self.vault.pins = {"vps": STORE_A}
        hub.central_read()
        made = hub.central_reconcile()["delivered"]
        self.assertEqual(len(made), 2)
        for did in made:
            hub.finish_deposit(hub.q1("SELECT * FROM deposits WHERE id=?", (did,)), True, "Saved.")
        return made

    def said(self):
        return hub.q1("SELECT text, extra FROM events WHERE agent='manager' AND kind='say' ORDER BY id DESC")

    def intake(self, **changes):
        body = self.command(login=LOGIN_A, ciphertext=armored(b"the value, sealed to the central vault"))
        body.pop("text")
        return self.request("/ui/vault/intake", dict(body, **changes))

    def signed(self, route, said, **changes):
        body = self.command(statement=said, signature=SIGNATURE)
        body.pop("text")
        return self.request(route, dict(body, **changes))

    # ---- the feature, and the read behind it
    def test_the_feature_is_served_only_while_the_last_read_is_ok_and_fresh(self):
        self.assertNotIn("central_vault", self.request()[1]["ui_features"])       # never read yet
        hub.central_sweep()
        offered = self.request()[1]["ui_features"]
        self.assertEqual(offered, hub.UI_FEATURES + ["central_vault"])
        with hub.LOCK:
            self.assertEqual(hub.mobile_state("test-generation")["ui_features"], offered)     # the phone: one list
        read_at = hub.CENTRAL["read_at"]
        self.assertTrue(hub.central_ok(read_at + hub.CENTRAL_FRESH - 1))
        self.assertFalse(hub.central_ok(read_at + hub.CENTRAL_FRESH + 1))           # five minutes with no read
        # A read that is not ok turns it off at once, and the last ok answer stays with its own time.
        self.vault.refuse["status"] = "the store does not open"
        hub.central_read()
        self.assertNotIn("central_vault", self.request()[1]["ui_features"])
        view = self.view()
        self.assertEqual((view["central"]["recipient"], view["read_at"]), (CENTRAL_KEY, read_at))
        self.assertEqual(view["error"], "the central vault refused: the store does not open")
        self.vault.refuse.clear()
        hub.central_read()
        self.assertIn("central_vault", self.request()[1]["ui_features"])
        self.assertIsNone(self.view()["error"])
        # A central vault of another fleet is not this hub's, and a socket that is gone is no vault at all.
        self.vault.fleet = "0123456789abcdef"
        hub.central_read()
        self.assertNotIn("central_vault", hub.ui_features())
        self.assertIn("another fleet", hub.CENTRAL["error"])
        self.vault.close()
        hub.central_read()
        self.assertNotIn("central_vault", hub.ui_features())
        self.assertEqual(hub.CENTRAL["error"], "no central vault answers on this hub")

    def test_the_status_is_read_at_most_once_a_minute_unless_something_asks(self):
        t0 = hub.now()
        hub.central_sweep(t0)
        hub.central_sweep(t0 + 30)
        self.assertEqual(len(self.vault.ops("status")), 1)
        hub.central_due()                                   # a command changed the vault: read it again now
        hub.central_sweep(t0 + 31)
        self.assertEqual(len(self.vault.ops("status")), 2)
        hub.central_sweep(t0 + 31 + hub.CENTRAL_READ_EVERY)
        self.assertEqual(len(self.vault.ops("status")), 3)

    # ---- GET /ui/vault
    def test_the_vault_page_names_the_fleet_and_no_path_before_any_central_vault_answers(self):
        """The page gives the fleet's id, which the owner signs with, and no folder: the app installs the vault from
        the root-owned clone at its one fixed place, never from a path that the hub names (DevOps plan V2)."""
        view = self.view()
        self.assertEqual(set(view), {"db", "fleet", "central", "read_at", "error", "machines", "held", "program",
                                     "hub"})
        self.assertEqual(view["fleet"], hub.fleet_id())
        self.assertRegex(view["fleet"], r"\A[0-9a-f]{16}\Z")
        self.assertNotIn("/", json.dumps({k: v for k, v in view.items() if k != "machines"}))
        self.assertEqual((view["central"], view["read_at"], view["error"]), (None, None, None))
        machines = {m["machine"]: m for m in view["machines"]}
        self.assertEqual(sorted(machines), ["studio", "vps", "w4"])
        for m in machines.values():
            self.assertEqual(set(m), {"machine", "carrier", "broker_recipient", "pinned", "matches", "missing"})
        self.assertEqual(machines["vps"], {"machine": "vps", "carrier": "vps", "broker_recipient": STORE_A,
                                           "pinned": None, "matches": False, "missing": []})
        self.assertEqual(machines["w4"]["missing"], ["no_broker_access"])
        self.assertEqual(view["held"], {"studio": [], "vps": [], "w4": []})
        self.assertEqual(self.request("/ui/vault?db=other")[0], 409)
        self.assertEqual(self.request("/ui/vault")[0], 409)
        self.assertEqual(self.vault.requests, [])           # a read of the page asks the central vault nothing

    def test_the_vault_page_says_which_machine_is_pinned_and_which_is_not(self):
        self.vault.pins = {"vps": STORE_A, "studio": OTHER}
        hub.central_read()
        view = self.view()
        machines = {m["machine"]: m for m in view["machines"]}
        self.assertEqual(view["central"]["fleet"], view["fleet"])
        self.assertEqual((machines["vps"]["pinned"], machines["vps"]["matches"], machines["vps"]["missing"]),
                         (STORE_A, True, []))
        self.assertEqual((machines["studio"]["pinned"], machines["studio"]["matches"], machines["studio"]["missing"]),
                         (OTHER, False, ["pin_mismatch"]))
        self.assertEqual(machines["w4"]["missing"], ["no_broker_access", "not_pinned"])
        self.vault.pins = {"vps": STORE_A}
        hub.central_read()
        self.assertEqual(self.machines()["studio"]["missing"], ["not_pinned"])

    def test_the_vault_page_names_the_program_of_the_release_this_hub_runs(self):
        """The central vault's status names the program it runs (`source`), and the page names the vault.py of the
        hub's own release, so the owner's app can bring the vault up to date by itself where the two differ."""
        rev = hub.kit_revision()
        self.assertEqual(self.view()["program"], hub.vault_source(rev))
        if rev:                                     # a checkout: the committed vault.py of the hub's revision
            committed = subprocess.run(["git", "-C", hub.kit_dir(), "cat-file", "blob", f"{rev}:vault.py"],
                                       capture_output=True, check=True).stdout
            self.assertEqual(self.view()["program"], hashlib.sha256(committed).hexdigest())
        hub.central_read()
        self.assertEqual(self.view()["central"]["source"], "0" * 64)       # the fake vault's own program
        with patch.object(hub, "vault_source", lambda rev: None):        # a revision or a file it cannot read
            self.assertIsNone(self.view()["program"])

    def test_the_vault_page_names_the_central_vault_s_machine_and_how_the_fleet_reaches_it(self):
        """The central vault is on the hub's own machine, where no agent need run (the manager has a server of its
        own): the app runs the vault's root step there, so the page names that machine and its access record."""
        self.assertEqual(self.view()["hub"], {"machine": "hub", "address": "127.0.0.2", "ssh": None})
        hub.TEAM["access"] = {"hub": {"ssh_user": "root", "ssh_port": 2222, "screen_sharing": False}}
        self.assertEqual(self.view()["hub"], {"machine": "hub", "address": "127.0.0.2",
                                              "ssh": {"user": "root", "port": 2222}})
        del hub.TEAM["access"]["hub"]["ssh_port"]
        self.assertEqual(self.view()["hub"]["ssh"], {"user": "root", "port": 22})
        del hub.TEAM["hub"]
        self.assertIsNone(self.view()["hub"])

    # ---- POST /ui/vault/intake
    def test_an_intake_passes_the_salts_and_the_registered_fingerprints_and_gives_a_receipt(self):
        prints = [{"kind": "password", "hash": "a" * 64, "len": 51}, {"kind": "totp", "hash": "b" * 64, "len": 32}]
        hub.register_fingerprints(LOGIN_A, prints)
        self.vault.items = {}
        body = self.command(login=LOGIN_A, ciphertext=armored(b"the value, sealed to the central vault"))
        body.pop("text")
        code, receipt = self.request("/ui/vault/intake", body)
        self.assertEqual(code, 200, receipt)
        self.assertEqual((receipt["login"], receipt["saved"], receipt["replayed"]), (LOGIN_A, "new", False))
        sent = self.vault.ops("intake")[-1]
        self.assertEqual(sent, {"v": 2, "op": "intake", "login": LOGIN_A, "title": "OPENAI_API_KEY",
                                "item": "api_key", "ciphertext": body["ciphertext"], "fingerprints": prints,
                                "salts": {k: hub.fingerprint_salt(hub.fingerprint_label(LOGIN_A, k))
                                          for k in ("password", "totp")}})
        self.assertTrue(all(len(s) == 32 for s in sent["salts"].values()))
        self.assertTrue(hub.CENTRAL["due"])                 # the next pass delivers it at once
        # An exact repeat is the first answer, and the vault is not asked again.
        code, again = self.request("/ui/vault/intake", body)
        self.assertEqual((code, again["replayed"], again["saved"]), (200, True, "new"))
        self.assertEqual(len(self.vault.ops("intake")), 1)
        # The record keeps the copy's checksum and never the copy.
        kept = hub.q1("SELECT body, result FROM ui_controls WHERE route='vault/intake'")
        self.assertIn(hashlib.sha256(body["ciphertext"].encode()).hexdigest(), kept["body"])
        self.assertNotIn(body["ciphertext"].split("\n")[1], kept["body"] + kept["result"])
        self.assertEqual(self.vault.locked, [])

    def test_an_intake_is_refused_with_what_is_missing_and_leaves_no_record(self):
        code, body = self.intake(login=LOGIN_A)              # no fingerprint is registered for it
        self.assertEqual(code, 409, body)
        self.assertIn("no fingerprint", body["error"])
        hub.register_fingerprints(LOGIN_A, [{"kind": "password", "hash": "a" * 64, "len": 51}])
        self.assertEqual(self.intake(login="bws://41111111-2222-4333-8444-55555555555b")[0], 404)  # not in the catalog
        self.assertEqual(self.intake(ciphertext="sk-not-sealed-at-all")[0], 400)
        self.assertEqual(self.intake(extra="field")[0], 400)
        self.vault.refuse["intake"] = "the value does not match what the owner registered"
        code, body = self.intake()
        self.assertEqual((code, body["error"]),
                         (409, "the central vault refused: the value does not match what the owner registered"))
        self.vault.close()
        code, body = self.intake()
        self.assertEqual((code, body["error"]), (503, "no central vault answers on this hub"))
        self.assertEqual(self.count("ui_controls"), 0)       # a refused command leaves no record

    # ---- POST /ui/vault/pin and /recovery
    def test_a_pin_an_unpin_and_a_recovery_key_pass_through_as_they_came(self):
        fleet = hub.fleet_id()
        pin = statement(kind="pin", fleet=fleet, machine="studio", recipient=STORE_B)
        code, receipt = self.signed("/ui/vault/pin", pin)
        self.assertEqual(code, 200, receipt)
        self.assertEqual({k: receipt[k] for k in ("kind", "machine", "recipient", "saved")},
                         {"kind": "pin", "machine": "studio", "recipient": STORE_B, "saved": "new"})
        self.assertEqual(self.vault.requests[-1], {"v": 2, "op": "pin", "statement": pin, "signature": SIGNATURE})
        self.assertTrue(hub.CENTRAL["due"])
        unpin = statement(kind="unpin", fleet=fleet, machine="studio")
        code, receipt = self.signed("/ui/vault/pin", unpin)
        self.assertEqual((code, receipt["kind"], receipt["saved"]), (200, "unpin", "removed"))
        self.assertNotIn("recipient", receipt)
        self.assertEqual(self.vault.requests[-1], {"v": 2, "op": "unpin", "statement": unpin, "signature": SIGNATURE})
        recovery = statement(kind="recovery", fleet=fleet, recipient=RECOVERY)
        self.assertEqual(self.signed("/ui/vault/pin", recovery)[0], 400)          # each route takes its own kinds
        self.assertEqual(self.signed("/ui/vault/recovery", pin)[0], 400)
        code, receipt = self.signed("/ui/vault/recovery", recovery)
        self.assertEqual((code, receipt["kind"], receipt["recipient"]), (200, "recovery", RECOVERY))
        self.assertNotIn("machine", receipt)
        self.assertEqual(self.vault.requests[-1]["op"], "recovery")
        self.assertEqual(self.signed("/ui/vault/pin", "not json")[0], 400)
        self.assertEqual(self.signed("/ui/vault/pin", pin, signature="not base64!")[0], 400)
        self.vault.refuse["pin"] = "the signature is not one of the owner's keys"
        code, body = self.signed("/ui/vault/pin", statement(kind="pin", fleet=fleet, machine="vps", recipient=STORE_A))
        self.assertEqual((code, body["error"]),
                         (409, "the central vault refused: the signature is not one of the owner's keys"))
        self.assertEqual(self.vault.locked, [])

    # ---- POST /ui/vault/grant: the owner's signed grants (DevOps plan V1)
    def test_a_signed_grant_or_pool_statement_passes_through_as_it_came(self):
        fleet = hub.fleet_id()
        said = statement(kind="grant", fleet=fleet, login=LOGIN_B, agent="studio", machine="studio")
        code, receipt = self.signed("/ui/vault/grant", said)
        self.assertEqual(code, 200, receipt)
        self.assertEqual({k: receipt.get(k) for k in ("kind", "login", "agent", "machine", "saved", "recipient")},
                         {"kind": "grant", "login": LOGIN_B, "agent": "studio", "machine": "studio", "saved": "new",
                          "recipient": None})
        sent = self.vault.ops("grant")[-1]
        self.assertEqual((sent["statement"], sent["signature"]), (said, SIGNATURE))     # byte for byte
        self.assertTrue(hub.CENTRAL["due"])                 # the next pass reads the signed grants at once
        for kind in ("ungrant", "pool", "unpool"):
            fields = {"login": LOGIN_B} if kind != "ungrant" else {"login": LOGIN_B, "agent": "studio"}
            code, receipt = self.signed("/ui/vault/grant", statement(kind=kind, fleet=fleet, **fields))
            self.assertEqual((code, receipt["kind"]), (200, kind), receipt)
        for other in (statement(kind="pin", fleet=fleet, machine="vps", recipient=STORE_A),
                      statement(kind="recovery", fleet=fleet, recipient=RECOVERY), "not json"):
            self.assertEqual(self.signed("/ui/vault/grant", other)[0], 400)            # each route takes its own kinds
        self.assertEqual(self.signed("/ui/vault/pin", said)[0], 400)
        self.vault.refuse["grant"] = "the statement does not carry a valid signature of the owner"
        code, body = self.signed("/ui/vault/grant", said)
        self.assertEqual(code, 409, body)
        self.assertIn("valid signature of the owner", body["error"])
        self.assertIn("signed_grants", hub.UI_FEATURES)

    def test_the_reconciler_seals_only_what_the_owner_signed_for_that_machine(self):
        """A grant that team.json holds and the owner never signed reaches no machine, and one whose signature the
        owner took back goes back, as a grant that team.json lost does. A secret in the signed pool reaches any
        machine whose agent holds it."""
        self.vault.grants = [g for g in self.signed_grants() if g["login"] != LOGIN_B]
        self.vault.pins = {"vps": STORE_A}
        hub.central_read()
        made = hub.central_reconcile()["delivered"]
        self.assertEqual([r["login"] for r in self.deposits("vps")], [LOGIN_A])          # LOGIN_B: no signature
        self.assertEqual(self.vault.ops("seal")[-1]["login"], LOGIN_A)                  # nothing asked for LOGIN_B
        self.vault.pool = [LOGIN_B]                          # the owner signs LOGIN_B into the grantable pool
        hub.central_read()
        made += hub.central_reconcile()["delivered"]
        self.assertEqual(sorted(r["login"] for r in self.deposits("vps")), [LOGIN_A, LOGIN_B])
        for did in made:
            hub.finish_deposit(hub.q1("SELECT * FROM deposits WHERE id=?", (did,)), True, "Saved.")
        self.vault.grants = [g for g in self.vault.grants if g["login"] != LOGIN_A]     # the owner's ungrant
        hub.central_read()
        done = hub.central_reconcile()
        self.assertEqual([hub.q1("SELECT login FROM withdrawals WHERE id=?", (w,))["login"] for w in done["withdrawn"]],
                         [LOGIN_A])                          # team.json still names it: the signature decides

    def test_a_copy_counts_as_held_only_when_it_was_sealed_to_the_pin_of_now(self):
        """A machine whose vault key changed (a new broker, a moved agent) gets each secret again, sealed to its new
        key, although the hub delivered it to the old key before (DevOps plan V1)."""
        self.deliver_and_keep()
        self.assertEqual(self.view()["held"]["vps"], [LOGIN_A, LOGIN_B])
        hub.TEAM["vault_stores"]["vps"] = OTHER
        hub.TEAM["agents"]["vps"]["vault_recipient"] = OTHER
        self.report("vps", key=OTHER)
        self.vault.pins = {"vps": OTHER}
        hub.central_read()
        self.assertEqual(self.view()["held"]["vps"], [])
        made = hub.central_reconcile()["delivered"]
        self.assertEqual(sorted(hub.q1("SELECT login FROM deposits WHERE id=?", (d,))["login"] for d in made),
                         [LOGIN_A, LOGIN_B])
        self.assertEqual({hub.q1("SELECT recipient FROM deposits WHERE id=?", (d,))["recipient"] for d in made},
                         {OTHER})

    # ---- when the vault does not answer (DevOps plan V1)
    def test_no_secret_is_added_unless_the_central_vault_answers_with_a_recovery_key(self):
        body = self.command(login=LOGIN_C, title="STRIPE_KEY", kind="api_key", env="STRIPE_KEY", fingerprints=[])
        body.pop("text")
        code, said = self.request("/ui/secrets/add", body)
        self.assertEqual(code, 503, said)
        self.assertEqual(said["error"], "the central vault does not answer, so nothing was sent: try again in a moment")
        hub.central_read()                                  # it answers, and holds no recovery key yet
        code, said = self.request("/ui/secrets/add", body)
        self.assertEqual(code, 503, said)
        self.assertIn("holds no recovery key yet", said["error"])
        self.assertEqual(self.count("ui_controls"), 0)       # a refused command leaves no record
        self.assertEqual(self.count("secrets"), 0)

    def test_the_manager_hears_once_when_the_central_vault_stops_answering(self):
        t0 = hub.now()
        hub.central_read(t0)                                # it answered once: its silence is news now
        self.vault.refuse["status"] = "the store does not open"
        hub.central_read(t0 + 60)
        hub.central_read(t0 + 60 + hub.CENTRAL_FRESH - 1)
        self.assertIsNone(self.said())                      # a short silence is no Needs-you
        hub.central_read(t0 + 60 + hub.CENTRAL_FRESH)
        said = self.said()
        self.assertIn("The central vault on the hub's server has not answered", said["text"])
        self.assertIn("the store does not open", said["text"])
        self.assertIn("raise_needs_you", said["text"])
        self.assertNotIn("quiet", json.loads(said["extra"] or "{}"))        # it wakes the manager
        hub.central_read(t0 + 60 + 2 * hub.CENTRAL_FRESH)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE agent='manager' AND kind='say'")["n"], 1)
        self.vault.refuse.clear()
        hub.central_read(t0 + 60 + 3 * hub.CENTRAL_FRESH)
        back = self.said()
        self.assertIn("answers again", back["text"])
        self.assertTrue(json.loads(back["extra"])["quiet"])

    def test_a_hub_with_no_central_vault_ever_tells_the_manager_nothing(self):
        self.vault.close()
        t0 = hub.now()
        for at in (t0, t0 + hub.CENTRAL_FRESH + 60):
            hub.central_read(at)
        self.assertIsNone(self.said())

    # ---- the reconciler: deliveries
    def test_the_reconciler_delivers_only_what_a_pinned_machine_s_agents_hold(self):
        self.vault.pins = {"vps": STORE_A}                   # studio has no pin
        done = hub.central_sweep()
        self.assertEqual(len(done["delivered"]), 2)
        rows = self.deposits()
        # LOGIN_C is granted to vps and not in the central vault, so it is not sealed for anybody.
        self.assertEqual(sorted((r["machine"], r["login"]) for r in rows), [("vps", LOGIN_A), ("vps", LOGIN_B)])
        self.assertEqual(sorted((r["machine"], r["login"]) for r in self.vault.ops("seal")),
                         [("vps", LOGIN_A), ("vps", LOGIN_B)])
        for r in rows:
            self.assertEqual((r["agent"], r["recipient"]), ("vps", STORE_A))
            self.assertTrue(r["request_id"].startswith("central:"))
            self.assertEqual(r["sha256"], hashlib.sha256(r["ciphertext"].encode()).hexdigest())
            event = hub.q1("SELECT * FROM events WHERE kind='deposit' AND json_extract(extra,'$.deposit')=?",
                           (r["id"],))
            self.assertEqual((event["agent"], json.loads(event["extra"])), ("vps", {"deposit": r["id"],
                                                                                   "login": r["login"]}))
        self.assertEqual(self.machines()["studio"]["missing"], ["not_pinned"])
        # Nothing is delivered twice while one waits.
        self.assertEqual(hub.central_reconcile(), {"delivered": [], "withdrawn": [], "removed": []})
        self.assertEqual(len(self.deposits()), 2)
        # A pin that is not the machine's key leaves it out; the right pin brings it in.
        self.vault.pins["studio"] = OTHER
        hub.central_read()
        hub.central_reconcile()
        self.assertEqual(self.deposits("studio"), [])
        self.assertEqual(self.machines()["studio"]["missing"], ["pin_mismatch"])
        self.vault.pins["studio"] = STORE_B
        hub.central_read()
        hub.central_reconcile()
        self.assertEqual([(r["login"], r["recipient"]) for r in self.deposits("studio")], [(LOGIN_A, STORE_B)])
        self.assertEqual(self.vault.locked, [])

    def test_the_carrier_s_vault_takes_a_central_copy_with_today_s_code_path(self):
        self.vault.pins = {"vps": STORE_A}
        hub.central_sweep()
        row = self.deposits()[0]
        code, given = self.request("/helper/vault/vps", {"job": row["id"], "kind": "deposit"})
        self.assertEqual(code, 200, given)
        self.assertEqual((given["ciphertext"], given["login"]), (row["ciphertext"], row["login"]))
        code, _ = self.request(f"/helper/deposit/vps/{row['id']}", {"ok": True, "text": "Saved."})
        self.assertEqual(code, 200)
        self.assertEqual(self.view()["held"]["vps"], [row["login"]])
        self.assertIn("is now in the vault of vps", self.said()["text"])

    def test_a_delivery_that_failed_waits_before_it_is_sent_again(self):
        self.vault.pins = {"vps": STORE_A}
        hub.central_sweep()
        first = self.deposits()[0]
        hub.finish_deposit(first, False, "The vault did not save it.")
        said = self.said()
        self.assertIn("sends it again from the central vault in 6 hours", said["text"])
        self.assertTrue(json.loads(said["extra"])["quiet"])
        self.assertEqual(hub.central_reconcile()["delivered"], [])
        # The wait is over (the failure is moved back, because the helper's own report would age with the clock).
        hub.q("UPDATE deposits SET finished=? WHERE id=?", (hub.now() - hub.CENTRAL_RETRY - 1, first["id"]))
        later = hub.central_reconcile()["delivered"]
        self.assertEqual([hub.q1("SELECT login FROM deposits WHERE id=?", (d,))["login"] for d in later],
                         [first["login"]])
        # A new pin is a new key, so a copy for it goes at once, whatever failed before.
        newest = hub.q1("SELECT * FROM deposits WHERE id=?", (later[0],))
        hub.finish_deposit(newest, False, "The vault did not save it.")
        hub.q("UPDATE deposits SET recipient=? WHERE id=?", (OTHER, newest["id"]))     # sealed to an older pin
        self.assertEqual(len(hub.central_reconcile()["delivered"]), 1)

    def test_the_reconciler_seals_a_batch_at_a_time_and_asks_for_the_next_pass(self):
        self.vault.pins = {"vps": STORE_A}
        hub.central_read()
        with patch.object(hub, "CENTRAL_BATCH", 1):
            self.assertEqual(len(hub.central_reconcile()["delivered"]), 1)
            self.assertTrue(hub.CENTRAL["due"])
            hub.central_sweep()
        self.assertEqual(len(self.deposits()), 2)

    def test_a_grant_that_changes_starts_a_pass_at_once(self):
        t0 = hub.now()
        hub.central_sweep(t0)                              # no pin yet: nothing to deliver
        self.vault.pins = {"vps": STORE_A}
        hub.central_due()
        hub.central_sweep(t0 + 1)
        self.assertEqual(len(self.deposits()), 2)
        hub.TEAM["agents"]["studio"]["secrets"][LOGIN_B] = "use"
        self.vault.grants = self.signed_grants()            # the owner's app signs the grant it just made
        self.vault.pins["studio"] = STORE_B
        hub.central_read(t0 + 2)
        hub.central_sweep(t0 + 3)                          # inside the minute, and the grant changed
        self.assertEqual(sorted(r["login"] for r in self.deposits("studio")), [LOGIN_A, LOGIN_B])

    # ---- the reconciler: withdrawals
    def test_a_secret_nobody_there_holds_goes_back_when_the_central_vault_has_it(self):
        self.deliver_and_keep()
        self.assertEqual(self.view()["held"]["vps"], [LOGIN_A, LOGIN_B])
        del hub.TEAM["agents"]["vps"]["secrets"][LOGIN_B]
        done = hub.central_reconcile()
        self.assertEqual(len(done["withdrawn"]), 1)
        row = hub.q1("SELECT * FROM withdrawals WHERE id=?", (done["withdrawn"][0],))
        self.assertEqual((row["login"], row["machine"], row["agent"], row["finished"]), (LOGIN_B, "vps", "vps", None))
        event = hub.q1("SELECT * FROM events WHERE kind='withdraw'")
        self.assertEqual((event["agent"], json.loads(event["extra"])),
                         ("vps", {"withdraw": row["id"], "login": LOGIN_B}))
        self.assertEqual(hub.central_reconcile(), {"delivered": [], "withdrawn": [], "removed": []})   # it waits
        self.assertEqual(self.view()["held"]["vps"], [LOGIN_A, LOGIN_B])                   # held until it is done

    def test_a_secret_the_central_vault_lacks_is_never_taken_back(self):
        self.deliver_and_keep()
        # LOGIN_C reached vps from the owner's app, and the central vault never had it.
        hub.q("INSERT INTO deposits(login,machine,agent,recipient,sha256,ciphertext,request_id,created,finished,ok) "
              "VALUES(?,?,?,?,?,NULL,?,?,?,1)", (LOGIN_C, "vps", "vps", STORE_A, "0" * 64,
                                                 "0d4d8d8a-6a2f-4c1e-8f43-7b7d3c3c1a11", hub.now(), hub.now()))
        del hub.TEAM["agents"]["vps"]["secrets"][LOGIN_C]
        self.assertEqual(hub.central_reconcile()["withdrawn"], [])
        self.assertEqual(self.view()["held"]["vps"], [LOGIN_A, LOGIN_B, LOGIN_C])

    def test_a_carrier_that_cannot_carry_a_withdrawal_is_left_alone(self):
        self.deliver_and_keep()
        del hub.TEAM["agents"]["vps"]["secrets"][LOGIN_B]
        self.report("vps", features=("secret_deposits",))                     # an older helper
        self.assertEqual(hub.central_reconcile()["withdrawn"], [])
        self.report("vps", withdrawals=False)                                  # a new helper, an older broker
        self.assertEqual(hub.central_reconcile()["withdrawn"], [])
        self.report("vps")
        self.assertEqual(len(hub.central_reconcile()["withdrawn"]), 1)

    def test_the_helper_carries_a_withdrawal_from_its_event_to_its_end(self):
        self.deliver_and_keep()
        del hub.TEAM["agents"]["vps"]["secrets"][LOGIN_B]
        wid = hub.central_reconcile()["withdrawn"][0]
        code, polled = self.request("/events/vps?delivery=1&wait=0")
        self.assertEqual(code, 200, polled)
        self.assertEqual([(e["kind"], e["extra"]) for e in polled["events"] if e["kind"] == "withdraw"],
                         [("withdraw", {"withdraw": wid, "login": LOGIN_B})])
        self.assertEqual(self.request("/helper/vault/studio", {"job": wid, "kind": "withdraw"})[0], 404)
        code, confirmed = self.request("/helper/vault/vps", {"job": wid, "kind": "withdraw"})
        self.assertEqual((code, confirmed), (200, {"ok": True, "job": wid, "kind": "withdraw", "login": LOGIN_B}))
        self.assertIsNotNone(hub.q1("SELECT released FROM withdrawals WHERE id=?", (wid,))["released"])
        code, done = self.request(f"/helper/withdraw/vps/{wid}", {"ok": True, "text": "Removed from this machine's vault."})
        self.assertEqual(code, 200, done)
        row = hub.q1("SELECT * FROM withdrawals WHERE id=?", (wid,))
        self.assertEqual((row["ok"], row["result"]), (1, "Removed from this machine's vault."))
        said = self.said()
        self.assertIn("is out of the vault of vps", said["text"])
        self.assertTrue(json.loads(said["extra"])["quiet"])
        self.assertEqual(self.view()["held"]["vps"], [LOGIN_A])
        polled = self.request("/events/vps?delivery=1&wait=0")[1]
        self.assertEqual([e for e in polled["events"] if e["kind"] == "withdraw"], [])     # it carries nothing now
        self.assertEqual(self.request(f"/helper/withdraw/vps/{wid}", {"ok": True, "text": "again"})[0], 409)
        self.assertEqual(hub.central_reconcile(), {"delivered": [], "withdrawn": [], "removed": []})   # it stays out

    def test_a_removal_the_vault_never_asked_for_is_not_taken_as_done(self):
        self.deliver_and_keep()
        del hub.TEAM["agents"]["vps"]["secrets"][LOGIN_B]
        wid = hub.central_reconcile()["withdrawn"][0]
        self.assertEqual(self.request(f"/helper/withdraw/vps/{wid}", {"ok": True, "text": "Removed."})[0], 200)
        row = hub.q1("SELECT * FROM withdrawals WHERE id=?", (wid,))
        self.assertEqual((row["ok"], row["result"]), (0, "The vault reported a removal that the hub did not see it "
                                                         "ask for."))

    def test_a_withdrawal_that_failed_is_asked_again_only_after_the_wait(self):
        self.deliver_and_keep()
        del hub.TEAM["agents"]["vps"]["secrets"][LOGIN_B]
        wid = hub.central_reconcile()["withdrawn"][0]
        self.request("/helper/vault/vps", {"job": wid, "kind": "withdraw"})
        text = "the vault broker refused: this login was not delivered here, so it is not removed"
        self.assertEqual(self.request(f"/helper/withdraw/vps/{wid}", {"ok": False, "text": text})[0], 200)
        self.assertIn("is still in the vault of vps", self.said()["text"])
        self.assertIn("asks again in 6 hours", self.said()["text"])
        self.assertEqual(self.view()["held"]["vps"], [LOGIN_A, LOGIN_B])
        self.assertEqual(hub.central_reconcile()["withdrawn"], [])
        hub.q("UPDATE withdrawals SET finished=? WHERE id=?", (hub.now() - hub.CENTRAL_RETRY - 1, wid))
        self.assertEqual(len(hub.central_reconcile()["withdrawn"]), 1)

    def test_a_withdrawal_its_machine_never_took_is_dropped_after_a_week(self):
        self.deliver_and_keep()
        del hub.TEAM["agents"]["vps"]["secrets"][LOGIN_B]
        wid = hub.central_reconcile()["withdrawn"][0]
        hub.expire_withdrawals(hub.now() + hub.WITHDRAW_WAIT - 60)
        self.assertIsNone(hub.q1("SELECT finished FROM withdrawals WHERE id=?", (wid,))["finished"])
        hub.expire_withdrawals(hub.now() + hub.WITHDRAW_WAIT + 60)
        row = hub.q1("SELECT * FROM withdrawals WHERE id=?", (wid,))
        self.assertEqual(row["ok"], 0)
        self.assertIn("did not take it in a week", row["result"])
        hub.TEAM["agents"]["vps"]["vault"] = "none"                             # and a carrier that lost its broker
        hub.q("UPDATE withdrawals SET finished=NULL, ok=NULL WHERE id=?", (wid,))
        hub.expire_withdrawals(hub.now())
        self.assertIn("no broker access", hub.q1("SELECT result FROM withdrawals WHERE id=?", (wid,))["result"])

    def test_the_tick_expires_withdrawals(self):
        self.deliver_and_keep()
        del hub.TEAM["agents"]["vps"]["secrets"][LOGIN_B]
        wid = hub.central_reconcile()["withdrawn"][0]
        hub.q("UPDATE withdrawals SET created=? WHERE id=?", (hub.now() - hub.WITHDRAW_WAIT - 60, wid))
        hub.tick()
        self.assertEqual(hub.q1("SELECT ok FROM withdrawals WHERE id=?", (wid,))["ok"], 0)

    # ---- the reconciler: removals from the central vault (Remove from Founderizer)
    def test_a_secret_out_of_the_catalog_leaves_the_central_vault_only_after_its_last_copy(self):
        """V10 of the DevOps plan, 6 November 2026: a secret that the owner removed from Founderizer stayed in the
        central vault. It goes now, but only once no machine's vault holds a copy, because the hub takes a copy back
        only while the central vault lists the secret. A vault that cannot give its copy back (the Mac Studio's, that
        day) keeps the secret in the central vault until it can."""
        self.deliver_and_keep()
        del hub.TEAM["agents"]["vps"]["secrets"][LOGIN_B]          # the grant taken back, and its ungrant signed
        self.vault.grants = self.signed_grants()
        del hub.TEAM["logins"][LOGIN_B]                            # Remove from Founderizer
        self.report("vps", withdrawals=False)                      # a vault that cannot give a copy back
        hub.central_read()
        self.assertEqual(hub.central_reconcile(), {"delivered": [], "withdrawn": [], "removed": []})
        self.assertIn(LOGIN_B, self.vault.items)
        self.report("vps")                                         # now it can
        wid = hub.central_reconcile()["withdrawn"][0]
        self.assertIn(LOGIN_B, self.vault.items)                   # the withdrawal is open: the copy is still there
        hub.finish_withdrawal(hub.q1("SELECT * FROM withdrawals WHERE id=?", (wid,)), True,
                              "Removed from this machine's vault.")
        hub.CENTRAL["due"] = False
        self.assertEqual(hub.central_reconcile(), {"delivered": [], "withdrawn": [], "removed": [LOGIN_B]})
        self.assertTrue(hub.CENTRAL["due"])                         # the next read counts the vault's items again
        self.assertEqual(sorted(self.vault.items), [LOGIN_A])
        self.assertEqual(self.vault.ops("remove"), [{"v": 2, "op": "remove", "login": LOGIN_B}])
        self.assertEqual(hub.central_reconcile()["removed"], [])                       # and it is asked once
        self.assertEqual(len(self.vault.ops("remove")), 1)
        said = hub.q1("SELECT what FROM log WHERE what LIKE ?", (f"the central vault no longer holds {LOGIN_B}%",))
        self.assertIn("no machine's vault holds it", said["what"])

    def test_nothing_is_removed_while_the_owner_s_signature_names_it_or_the_vault_cannot_remove(self):
        self.vault.items[LOGIN_D] = "OLD_KEY"                      # out of the catalog, and on no machine
        self.vault.grants.append({"login": LOGIN_D, "agent": "vps", "machine": "vps"})
        hub.central_read()
        self.assertEqual(hub.central_reconcile()["removed"], [])   # a grant that the owner signed names it
        self.vault.grants.pop()
        self.vault.pool = [LOGIN_D]
        hub.central_read()
        self.assertEqual(hub.central_reconcile()["removed"], [])   # and so does the pool
        self.vault.pool, self.vault.removes = [], False            # an older program, which serves no remove
        hub.central_read()
        self.assertEqual(hub.central_reconcile()["removed"], [])
        self.assertEqual(self.vault.ops("remove"), [])             # it is asked nothing
        self.vault.removes = True
        self.vault.refuse["remove"] = "the vault store is in use, so nothing was saved"
        hub.central_read()
        self.assertEqual(hub.central_reconcile()["removed"], [])
        self.assertIn(f"did not remove {LOGIN_D}", hub.CENTRAL["said"])
        del self.vault.refuse["remove"]
        self.assertEqual(hub.central_reconcile()["removed"], [LOGIN_D])
        self.assertNotIn(LOGIN_D, self.vault.items)

    # ---- the one rule about the socket
    def test_the_central_vault_is_never_asked_under_the_hub_s_lock(self):
        with hub.LOCK:
            with self.assertRaises(RuntimeError):
                hub.central_call("status")
        self.assertEqual(self.vault.requests, [])           # the guard stops it before the socket
        self.deliver_and_keep()
        del hub.TEAM["agents"]["vps"]["secrets"][LOGIN_B]
        self.vault.items[LOGIN_D] = "OLD_KEY"               # out of the catalog, and on no machine: it is removed
        hub.central_reconcile()
        hub.register_fingerprints(LOGIN_A, [{"kind": "password", "hash": "a" * 64, "len": 51}])
        self.assertEqual(self.intake()[0], 200)
        self.assertEqual(self.signed("/ui/vault/pin", statement(kind="pin", fleet=hub.fleet_id(), machine="studio",
                                                                recipient=STORE_B))[0], 200)
        self.assertEqual(sorted({r["op"] for r in self.vault.requests}),
                         ["intake", "inventory", "pin", "remove", "seal", "status"])
        self.assertEqual(self.vault.locked, [])


class CentralCopy(WithCentral, Fixture):
    """The copy of the fleet carries the central vault's sealed store when the vault has a recovery key to seal it to,
    and says why not when it does not."""

    def setUp(self):
        super().setUp()
        self.start_central()
        self.vault.items = {LOGIN_A: "OPENAI_API_KEY"}

    def copy(self):
        code, _headers, data = self.download()
        self.assertEqual(code, 200)
        zf = zipfile.ZipFile(io.BytesIO(data))
        return data, zf, json.loads(zf.read("fleet.json")), zf.read("RESTORE.md").decode()

    def test_a_copy_carries_the_sealed_store_when_there_is_a_recovery_key(self):
        self.vault.recovery = RECOVERY
        hub.central_read()
        data, zf, manifest, notes = self.copy()
        member = zf.read(hub.CENTRAL_MEMBER)
        export = json.loads(member)
        self.assertEqual(export, dict(self.vault.answer({"v": 2, "op": "export"})))
        self.assertEqual((export["recovery"], export["items"]), (RECOVERY, 1))
        self.assertEqual(manifest["files"][hub.CENTRAL_MEMBER]["sha256"], hashlib.sha256(member).hexdigest())
        self.assertEqual(manifest["central_vault"], {"in": hub.CENTRAL_MEMBER, "vault": True, "items": 1,
                                                     "recovery": RECOVERY, "store_recipient": STORE_KEY})
        self.assertIn(hub.CENTRAL_MEMBER, notes)
        self.assertIn("recovery code", notes)
        self.assertIn("The hub never opens it", notes)
        self.assertNotIn("no key anywhere in this copy", notes)
        # A restore reads it and writes it nowhere: it is not one of the owner's files.
        bundle = hub.read_bundle(data)
        self.assertEqual(bundle["central"], member)
        self.assertNotIn(hub.CENTRAL_MEMBER, bundle["config"])
        self.assertTrue(all(not name.startswith("vault/") for name in bundle["config"]))
        self.assertEqual(self.vault.locked, [])

    def test_without_a_recovery_key_the_copy_says_why_its_store_is_not_in_it(self):
        hub.central_read()
        _data, zf, manifest, notes = self.copy()
        self.assertNotIn(hub.CENTRAL_MEMBER, zf.namelist())
        self.assertNotIn(hub.CENTRAL_MEMBER, manifest["files"])
        self.assertEqual(manifest["central_vault"], {"in": None, "vault": True, "why": "the central vault holds no "
                                                     "recovery key, so its store is not in this copy"})
        self.assertIn("**Your central vault.**", notes)
        self.assertEqual(self.vault.ops("export"), [])
        self.assertEqual(hub.read_bundle(_data)["central"], None)

    def test_a_hub_with_no_central_vault_says_nothing_of_one(self):
        self.vault.close()                                # never read, and gone
        _data, zf, manifest, notes = self.copy()
        self.assertNotIn(hub.CENTRAL_MEMBER, zf.namelist())
        self.assertEqual((manifest["central_vault"]["in"], manifest["central_vault"]["vault"]), (None, False))
        self.assertNotIn("central vault", notes)
        self.assertIn("**There is no password, no token and no key anywhere in this copy**", notes)

    def test_a_copy_whose_central_member_is_not_what_its_manifest_says_is_refused(self):
        self.vault.recovery = RECOVERY
        hub.central_read()
        data = self.copy()[0]
        old = zipfile.ZipFile(io.BytesIO(data))
        members = {name: old.read(name) for name in old.namelist()}
        members[hub.CENTRAL_MEMBER] = members[hub.CENTRAL_MEMBER].replace(b"the", b"thE", 1) + b" "
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as zf:
            for name, body in members.items():
                zf.writestr(name, body)
        with self.assertRaises(hub.Refusal) as refused:
            hub.read_bundle(out.getvalue())
        self.assertIn(hub.CENTRAL_MEMBER, str(refused.exception))


class HelperWithdraw(unittest.TestCase):
    """fleet.py's half: a `withdraw` event goes to the machine's broker by its number alone, and the outcome goes back
    to the hub, as a delivery's does (Helper.deposit)."""

    def run_it(self, reply=None, refused=None, code=200, extra=None):
        asked, told = [], []

        def broker(agent, request, timeout=90):
            asked.append((agent, request))
            if refused:
                raise fleet.Refused(refused)
            return reply

        def http(method, path, body=None, timeout=None):
            told.append((method, path, body))
            return code, {"ok": True}
        helper = SimpleNamespace(agent="vps", say=lambda text: None)
        with patch.object(fleet, "broker_job_request", broker), patch.object(fleet, "http", http):
            fleet.Helper.withdraw(helper, {"withdraw": 7, "login": LOGIN_B} if extra is None else extra)
        return asked, told

    def test_the_broker_is_asked_by_number_and_the_hub_hears_what_came_of_it(self):
        asked, told = self.run_it({"ok": True, "withdrawal": 7, "login": LOGIN_B, "removed": "removed"})
        self.assertEqual(asked, [("vps", {"op": "withdraw", "job": 7})])
        self.assertEqual(told, [("POST", "/helper/withdraw/vps/7", {"ok": True,
                                                                     "text": "Removed from this machine's vault."})])
        _, told = self.run_it({"ok": True, "withdrawal": 7, "login": LOGIN_B, "removed": "absent"})
        self.assertEqual(told[0][2], {"ok": True, "text": "This machine's vault did not have it."})
        _, told = self.run_it(refused="the vault broker refused: this login was not delivered here, so it is not "
                                      "removed")
        self.assertEqual(told[0][2]["ok"], False)
        self.assertIn("not delivered here", told[0][2]["text"])

    def test_an_outcome_the_hub_did_not_take_keeps_the_event_pending(self):
        with self.assertRaises(fleet.Refused):
            self.run_it({"ok": True, "removed": "removed"}, code=503)
        with self.assertRaises(fleet.Refused):
            self.run_it(extra={"login": LOGIN_B})                      # no number: nothing is asked
        self.assertIn("secret_withdrawals", lifecycle.FEATURES)


# ---------------------------------------------------------------- hubsetup.py central-vault

OWNER_KEY = base64.b64encode(b"\x04" + bytes(range(1, 65))).decode()
NEW_KEY = base64.b64encode(b"\x04" + bytes(range(65, 129))).decode()
FLEET = "0f1e2d3c4b5a6978"
UNIT = ("[Unit]\nDescription=Fleet central vault\n\n[Service]\nUser=founderizer-vault\nGroup=fleet\n"
        "ExecStart=/usr/bin/python3 /usr/local/lib/fleet-vault-central/vault.py serve --config "
        "/etc/fleet-vault-central/vault.json\nRuntimeDirectory=fleet-vault-central\n\n[Install]\n"
        "WantedBy=multi-user.target")        # as `_shell` gives it: its last newline stripped


class Machine:
    """The hub's machine, as the installer sees it: it answers the reading, writes each `install` into a temporary
    root, keeps a key file that is there, and runs nothing. vault.py's `unit --central` is the other agent's half,
    so its output is given here."""

    def __init__(self, root):
        self.root, self.ran, self.made = Path(root), [], {"age.key": 0, "store.key": 0, "store.age": 0}
        self.state = {"user": "no", "age": "no", "keygen": "no", "program": "", "age.key": "no", "store.key": "no",
                      "store.age": "no", "active": "", "restarts": "0"}
        self.status = {"ok": True, "v": 2, "central": True, "recipient": CENTRAL_KEY, "store_recipient": STORE_KEY,
                       "fleet": FLEET, "owner_keys": 1, "pins": {}, "recovery": None, "items": 0, "source": "0" * 64}

    def run(self, script, timeout=120):
        self.ran.append(script)
        if "echo active=" in script:
            return 0, "\n".join(f"{k}={v}" for k, v in self.state.items()), ""
        if "vault.py unit --central" in script:
            return 0, UNIT, ""
        if script.startswith("runuser -u "):
            return 0, json.dumps(self.status), ""
        if "useradd --system" in script:
            self.state["user"] = "yes"
        if "apt-get" in script:
            self.state.update(age="yes", keygen="yes")
        if "age-keygen -o" in script and self.state["age.key"] == "no":     # behind `test -s`: never a second one
            self.state["age.key"] = "yes"
            self.made["age.key"] += 1
        if "store-init" in script:                                           # vault.py keeps what it finds
            for name in ("store.key", "store.age"):
                if self.state[name] == "no":
                    self.state[name] = "yes"
                    self.made[name] += 1
        for line in script.splitlines():
            words = shlex.split(line)
            if words[:7] == ["install", "-o", "root", "-g", "root", "-m", "644"] and len(words) == 9:
                target = self.root / words[8].lstrip("/")
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(words[7], target)
                if words[8].endswith("/vault.py"):
                    self.state["program"] = hashlib.sha256(target.read_bytes()).hexdigest()
        if "systemctl restart" in script:
            self.state.update(active="active", restarts="0")
        return 0, "", ""

    def read(self, path):
        return (self.root / path.lstrip("/")).read_text(encoding="utf-8")

    def scripts(self, fragment):
        return [s for s in self.ran if fragment in s]


class Install(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-central-install-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.kit = self.tmp / "kit"
        self.kit.mkdir()
        shutil.copy(os.path.join(KIT, "vault.py"), self.kit / "vault.py")
        self.box = Machine(self.tmp / "root")
        self.db = self.tmp / "pilot.db"
        con = sqlite3.connect(self.db)
        con.execute("CREATE TABLE kv(k TEXT PRIMARY KEY, v TEXT)")
        con.execute("INSERT INTO kv(k,v) VALUES('fleet_id', ?)", (FLEET,))
        con.commit()
        con.close()
        quiet = patch.object(hubsetup, "say", lambda text: None)
        quiet.start()
        self.addCleanup(quiet.stop)

    def install(self, key=OWNER_KEY, **extra):
        return hubsetup.central_install(key, hub_user="fleet", kit=str(self.kit), run=self.box.run,
                                        read=self.box.read, db=str(self.db),
                                        account=lambda user: {"uid": 998, "group": "fleet", "home": "/home/fleet"},
                                        **extra)

    def file(self, path):
        return (self.box.root / path.lstrip("/")).read_text(encoding="utf-8")

    def test_a_hub_machine_with_no_central_vault_gets_one(self):
        done = self.install()
        self.assertEqual(done, {"state": "made", "recipient": CENTRAL_KEY, "store_recipient": STORE_KEY,
                                "fleet": FLEET})
        self.assertEqual(self.file(hubsetup.CENTRAL_LIB + "/vault.py"), (self.kit / "vault.py").read_text())
        self.assertEqual(json.loads(self.file(hubsetup.CENTRAL_CONF)), {
            "central": True, "hub_uid": 998, "fleet": FLEET, "owner_keys": [OWNER_KEY], "age": "/usr/bin/age",
            "age_key": "/var/lib/fleet-vault-central/age.key", "store": "/var/lib/fleet-vault-central/store.age",
            "store_key": "/var/lib/fleet-vault-central/store.key", "socket": "/run/fleet-vault-central/vault.sock",
            "state": "/var/lib/fleet-vault-central/central.json"})
        self.assertEqual(self.file(hubsetup.CENTRAL_UNIT), UNIT + "\n")
        self.assertEqual(hubsetup.CENTRAL_UNIT, "/etc/systemd/system/fleet-vault-central.service")
        # Every step, in the order each one needs.
        order = ["useradd --system --home-dir /var/lib/fleet-vault-central --shell /usr/sbin/nologin "
                 "founderizer-vault", "apt-get", "test -s /var/lib/fleet-vault-central/age.key || age-keygen -o",
                 "/usr/local/lib/fleet-vault-central/vault.py\ninstall -o root -g root -m 644",
                 "vault.py store-init --config /etc/fleet-vault-central/vault.json --user founderizer-vault",
                 "vault.py unit --central --config /etc/fleet-vault-central/vault.json --group fleet",
                 "systemctl daemon-reload", "systemctl restart fleet-vault-central", "runuser -u fleet -- python3"]
        at = [self.box.ran.index(self.box.scripts(fragment)[0]) for fragment in order]
        self.assertEqual(at, sorted(at), order)
        self.assertTrue(self.box.scripts("systemctl enable fleet-vault-central"))
        self.assertIn("/run/fleet-vault-central/vault.sock", self.box.scripts("runuser -u fleet")[0])
        self.assertIn('"op": "status"', self.box.scripts("runuser -u fleet")[0])
        # No root helper and no sudoers line: the hub's user can neither install nor change it.
        for script in self.box.ran:
            self.assertNotIn("sudoers", script)
            self.assertNotIn("/usr/local/sbin", script)
        self.assertEqual(self.box.made, {"age.key": 1, "store.key": 1, "store.age": 1})

    def test_a_second_run_changes_nothing(self):
        self.install()
        self.box.ran.clear()
        done = self.install()
        self.assertEqual(done["state"], "there")
        self.assertEqual(len(self.box.ran), 3)                      # the reading, the unit it prints, the status
        self.assertEqual([bool(self.box.scripts(f)) for f in ("echo active=", "unit --central", "runuser -u fleet")],
                         [True, True, True])
        self.assertEqual(self.box.made, {"age.key": 1, "store.key": 1, "store.age": 1})

    def test_a_new_owner_key_replaces_the_old_one_and_no_key_file(self):
        self.install()
        self.box.ran.clear()
        done = self.install(NEW_KEY)
        self.assertEqual(done["state"], "made")
        self.assertEqual(json.loads(self.file(hubsetup.CENTRAL_CONF))["owner_keys"], [NEW_KEY])
        self.assertTrue(self.box.scripts("systemctl restart fleet-vault-central"))   # it reads the key at its start
        self.assertEqual(self.box.made, {"age.key": 1, "store.key": 1, "store.age": 1})
        self.assertIn("test -s /var/lib/fleet-vault-central/age.key ||", self.box.scripts("age-keygen -o")[0])
        self.assertFalse(self.box.scripts("apt-get"))                               # age is there now

    def test_the_fleet_id_is_the_one_given_or_the_hub_s_own(self):
        self.assertEqual(self.install()["fleet"], FLEET)                       # read from the hub's own records
        self.box.status["fleet"] = "0123456789abcdef"
        self.assertEqual(self.install(fleet="0123456789abcdef")["fleet"], "0123456789abcdef")
        self.assertEqual(json.loads(self.file(hubsetup.CENTRAL_CONF))["fleet"], "0123456789abcdef")
        with self.assertRaises(hubsetup.Stop):
            self.install(fleet="not-a-fleet")
        self.db.unlink()
        with self.assertRaises(hubsetup.Stop) as stop:
            self.install()
        self.assertIn("--fleet", str(stop.exception))

    def test_a_key_that_is_not_the_owner_s_public_key_stops_before_anything_runs(self):
        for key in ("", "not base64!", base64.b64encode(b"\x04" + b"x" * 63).decode(),
                    base64.b64encode(b"\x02" + b"x" * 64).decode()):
            with self.assertRaises(hubsetup.Stop):
                self.install(key)
        self.assertEqual(self.box.ran, [])

    def test_a_vault_that_does_not_answer_the_hub_s_user_stops_the_install(self):
        self.box.status = {"ok": False, "v": 2, "error": "this caller is not the hub"}
        with self.assertRaises(hubsetup.Stop) as stop:
            self.install()
        self.assertIn("this caller is not the hub", str(stop.exception))

    def command(self, *argv, linux=True, root=True, kit=None):
        """central-vault as the app runs it: from root's own clone, which is this test's kit here."""
        real = hubsetup.central_install

        def stub(key, **kw):
            return real(key, kit=str(self.kit), run=self.box.run, read=self.box.read, db=str(self.db),
                        account=lambda user: {"uid": 998, "group": "fleet", "home": "/home/fleet"}, **kw)
        out = io.StringIO()
        with patch.object(hubsetup, "central_install", stub), \
                patch.object(hubsetup.platform, "system", lambda: "Linux" if linux else "Darwin"), \
                patch.object(hubsetup.os, "geteuid", lambda: 0 if root else 1000), \
                patch.object(hubsetup, "ROOT_KIT", os.path.realpath(self.kit)), \
                patch.object(hubsetup, "KIT", kit or str(self.kit)), \
                patch.object(hubsetup, "root_owned", lambda path: path == os.path.realpath(self.kit)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = hubsetup.main(["central-vault", *argv])
        return code, json.loads(out.getvalue().strip().splitlines()[-1])

    def test_a_vault_of_the_old_user_moves_to_the_new_one_with_its_keys_store_and_pins(self):
        """The live hub of 3 November 2026: a central vault that the app installed before V2 runs as the user
        fleet-vault-central, with its own key, the store's key, the store and the owner's pins and recovery key in
        central.json, all files of that user. The app's install from root's own clone (with --keep-owner and the same
        owner key) gives the whole state folder to founderizer-vault before anything else touches it, because the
        vault reads each file only as its own, keeps every key and every statement, and starts the service as the new
        user."""
        conf = hubsetup.central_config(998, FLEET, OWNER_KEY)
        for path, text in ((hubsetup.CENTRAL_CONF, json.dumps(conf, indent=2) + "\n"),
                           (hubsetup.CENTRAL_UNIT, UNIT.replace("founderizer-vault", "fleet-vault-central") + "\n")):
            (self.box.root / path.lstrip("/")).parent.mkdir(parents=True, exist_ok=True)
            (self.box.root / path.lstrip("/")).write_text(text)
        self.box.state.update({"user": "no", "age": "yes", "keygen": "yes", "program": "an older vault.py",
                               "age.key": "yes", "store.key": "yes", "store.age": "yes", "active": "active"})
        self.assertEqual(self.install(keep_owner=True)["state"], "made")
        self.assertEqual(self.box.made, {"age.key": 0, "store.key": 0, "store.age": 0})        # no key is made again
        users = self.box.scripts("useradd --system")[0].splitlines()
        given = "if test -d /var/lib/fleet-vault-central; then chown -R founderizer-vault:founderizer-vault " \
                "/var/lib/fleet-vault-central; fi"
        self.assertLess(users.index(given), users.index("install -d -o founderizer-vault -g founderizer-vault -m 700 "
                                                        "/var/lib/fleet-vault-central"))
        self.assertLess(self.box.ran.index(self.box.scripts("useradd --system")[0]),
                        self.box.ran.index(self.box.scripts("store-init")[0]))     # before any step reads a file
        self.assertEqual(json.loads(self.file(hubsetup.CENTRAL_CONF))["owner_keys"], [OWNER_KEY])
        self.assertIn("User=founderizer-vault", self.file(hubsetup.CENTRAL_UNIT))
        self.assertTrue(self.box.scripts("systemctl restart fleet-vault-central"))

    def test_the_apps_own_install_takes_no_vault_of_another_owner(self):
        """--keep-owner, which the app's own install runs by itself: a vault whose configuration names another owner
        key, or cannot be read, is left as it is, and only the owner's own Set up (no --keep-owner) takes it over."""
        self.install(NEW_KEY)
        ran = len(self.box.ran)
        with self.assertRaises(hubsetup.OtherOwner):
            self.install(OWNER_KEY, keep_owner=True)
        self.assertFalse(any("install -o root" in script or "useradd" in script for script in self.box.ran[ran:]))
        self.assertEqual(json.loads(self.file(hubsetup.CENTRAL_CONF))["owner_keys"], [NEW_KEY])
        code, last = self.command("--owner-key", OWNER_KEY, "--keep-owner")
        self.assertEqual((code, last), (1, {"ok": False, "owner": "other",
                                            "error": "the central vault on this machine holds another owner key"}))
        self.assertEqual(self.install(NEW_KEY, keep_owner=True)["state"], "there")        # its own key: as before
        (self.box.root / hubsetup.CENTRAL_CONF.lstrip("/")).write_text("not json")
        with self.assertRaises(hubsetup.OtherOwner):
            self.install(NEW_KEY, keep_owner=True)
        self.assertEqual(self.install(OWNER_KEY)["state"], "made")                         # the owner's Set up

    def test_it_runs_only_from_roots_own_clone(self):
        """DevOps plan V2: never from a folder that the hub's user can change, such as the hub's own checkout."""
        code, last = self.command("--owner-key", OWNER_KEY, kit=KIT)
        self.assertEqual((code, last["ok"]), (1, False))
        self.assertIn("only from root's own clone", last["error"])
        self.assertEqual(self.box.ran, [])
        self.assertEqual(hubsetup.ROOT_KIT, "/usr/local/lib/founderizer-kit")
        self.assertEqual(hubsetup.CENTRAL_USER, "founderizer-vault")
        self.assertFalse(hubsetup.CENTRAL_USER.startswith("fleet-"))   # no name the hub's user can put in a group

    def test_the_last_line_is_one_json_object_for_the_app(self):
        code, last = self.command("--owner-key", OWNER_KEY)
        self.assertEqual((code, last), (0, {"ok": True, "recipient": CENTRAL_KEY, "store_recipient": STORE_KEY,
                                            "fleet": FLEET}))
        code, last = self.command("--owner-key", "not a key")
        self.assertEqual((code, last["ok"]), (1, False))
        self.assertIn("--owner-key", last["error"])
        code, last = self.command("--owner-key", OWNER_KEY, root=False)
        self.assertEqual((code, last["ok"]), (1, False))
        self.assertIn("root", last["error"])
        code, last = self.command("--owner-key", OWNER_KEY, linux=False)
        self.assertEqual((code, last["ok"]), (1, False))
        self.assertEqual(set(last), {"ok", "error"})



SEED, OTHER_SEED = bytes(range(32)), bytes(range(1, 33))         # release keys of this test only


class KitClone(unittest.TestCase):
    """hubsetup.py kit-clone (DevOps plan V2): root's own clone of the published repository, at the revision of the
    hub's signed release.json and never older, with real git and a release key of this test. Root's own steps (the
    owner and the modes of the files) are the one part a test cannot take, so `own` stands in for them."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-kit-clone-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.published, self.hub, self.root_kit = self.tmp / "published", self.tmp / "hub", self.tmp / "root-kit"
        self.hub.mkdir()
        self.git("init", "-q", "-b", "main", str(self.published))
        self.revisions = [self.commit(f"release {n}", n) for n in (1, 2)]
        self.owned = []
        quiet = patch.object(hubsetup, "say", lambda text: None)
        quiet.start()
        self.addCleanup(quiet.stop)

    def git(self, *args, cwd=None):
        return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t.invalid", *args], cwd=cwd,
                              capture_output=True, text=True, check=True).stdout.strip()

    def commit(self, message, n):
        (self.published / "release-key.pub").write_text(base64.b64encode(releases.public_key(SEED)).decode() + "\n")
        (self.published / "hubsetup.py").write_text(f"# the installer of release {n}\n")
        self.git("add", "-A", cwd=self.published)
        self.git("commit", "-q", "-m", message, cwd=self.published)
        return self.git("rev-parse", "HEAD", cwd=self.published)

    def release(self, revision, seed=SEED, version="2026.11.200"):
        """The hub's release.json: the signed manifest of the release it runs."""
        body = {"revision": revision, "version": version, "notes": None, "minimum": None, "hold": False}
        signature = base64.b64encode(releases.sign(seed, releases.signed_text(body))).decode()
        (self.hub / "release.json").write_text(json.dumps(dict(body, signature=signature)))

    def clone(self):
        return hubsetup.kit_clone(checkout=str(self.hub), source=str(self.published), root_kit=str(self.root_kit),
                                  own=self.owned.append, keys=(releases.public_key(SEED),))

    def head(self):
        return self.git("rev-parse", "HEAD", cwd=self.root_kit)

    def test_the_clone_is_made_at_the_signed_revision_and_given_to_root(self):
        self.release(self.revisions[0])
        self.assertEqual(self.clone(), {"revision": self.revisions[0], "version": "2026.11.200", "state": "made"})
        self.assertEqual(self.head(), self.revisions[0])
        self.assertEqual((self.root_kit / "hubsetup.py").read_text(), "# the installer of release 1\n")
        self.assertEqual(self.owned, [str(self.root_kit)])
        self.assertEqual(self.clone()["state"], "there")                # a second run changes nothing
        self.assertEqual(self.owned, [str(self.root_kit)])

    def test_a_newer_release_moves_it_and_an_older_one_never_comes_back(self):
        self.release(self.revisions[0])
        self.clone()
        self.release(self.revisions[1], version="2026.11.201")
        self.assertEqual(self.clone()["state"], "moved")
        self.assertEqual(self.head(), self.revisions[1])
        self.release(self.revisions[0])
        with self.assertRaises(hubsetup.Stop) as stop:
            self.clone()
        self.assertIn("does not descend from the revision", str(stop.exception))
        self.assertEqual(self.head(), self.revisions[1])

    def test_a_release_that_no_key_of_its_own_signed_is_refused(self):
        self.release(self.revisions[0], seed=OTHER_SEED)
        with self.assertRaises(hubsetup.Stop) as stop:
            self.clone()
        self.assertIn("not a release that this clone can trust", str(stop.exception))
        self.assertFalse(self.root_kit.exists())
        self.release(self.revisions[0])
        self.clone()
        # Once it is there, the clone trusts its own keys at its own revision, never the ones a run is given.
        self.release(self.revisions[1], seed=OTHER_SEED)
        with self.assertRaises(hubsetup.Stop):
            hubsetup.kit_clone(checkout=str(self.hub), source=str(self.published), root_kit=str(self.root_kit),
                               own=self.owned.append, keys=(releases.public_key(OTHER_SEED),))
        self.assertEqual(self.head(), self.revisions[0])

    def test_a_hub_with_no_signed_release_gets_no_clone(self):
        with self.assertRaises(hubsetup.Stop) as stop:
            self.clone()
        self.assertIn("carries no release.json", str(stop.exception))
        (self.hub / "release.json").write_text(json.dumps({"revision": self.revisions[0]}))        # no signature
        with self.assertRaises(hubsetup.Stop):
            self.clone()
        self.assertFalse(self.root_kit.exists())


if __name__ == "__main__":
    unittest.main()

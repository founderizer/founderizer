"""A key the owner typed, sealed by the central vault and carried into one machine's vault (owner feature
central_vault).

Until 2 November 2026 the owner's app also sealed a copy to every machine itself (owner feature secret_deliveries,
`POST /ui/secrets/deliver`). The DevOps plan's track B (V1) took that route out: the central vault is the one way a
value reaches a server. This is what is left of the hub's half: what it keeps of a delivery, the one route by which a
copy leaves it again, and the grant that it reads again on that route. No value is sealed or opened here, because the
hub opens none: a copy is the shape `sealed_copy` takes, and nothing more. The reconciler that makes a delivery is in
test_central_vault.py.
"""
import base64
import hashlib
import json
import unittest
from unittest.mock import patch

import hub
from test_ui_api import OwnerAPI

LOGIN = "bws://11111111-2222-4333-8444-55555555555b"
STORE_A, STORE_B = "age1" + "q" * 58, "age1" + "r" * 58
NO_STORE = "age1" + "s" * 58
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3", "w4": "127.0.0.4",
                      "studio": "127.0.0.5"},
        "vault_stores": {"vps": STORE_A, "studio": STORE_B},
        "logins": {LOGIN: {"title": "OPENAI_API_KEY", "kind": "api_key", "env": "OPENAI_API_KEY"}},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"],
                           "vault": "broker", "vault_recipient": STORE_A, "secrets": {LOGIN: "read"}},
                   "worker4": {"role": "worker", "runtime": "codex", "machine": "w4", "can": ["shell"]},
                   "studio": {"role": "worker", "runtime": "claude", "machine": "studio", "can": ["shell"],
                              "vault": "broker", "vault_recipient": STORE_B}}}


def copy(payload=b"x" * 40):
    """An armored age file of the shape the hub takes: it checks the header and never opens it (`sealed_copy`)."""
    blob = b"age-encryption.org/v1\n-> X25519 " + base64.b64encode(payload) + b"\n--- " + base64.b64encode(payload) \
        + b"\n" + payload
    text = base64.b64encode(blob).decode()
    rows = [text[at:at + 64] for at in range(0, len(text), 64)]
    return "-----BEGIN AGE ENCRYPTED FILE-----\n" + "".join(r + "\n" for r in rows) \
        + "-----END AGE ENCRYPTED FILE-----\n"


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(Deliveries(name) for name in Deliveries.__dict__ if name.startswith("test_"))


class Deliveries(OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        allowed = patch.object(hub.Handler, "allowed", lambda handler, who, broker=False: True)
        allowed.start()
        self.addCleanup(allowed.stop)
        for agent in ("vps", "studio"):
            hub.q("INSERT INTO agent_keys(agent,sha256,created,source) VALUES(?,?,?,?)",
                  (agent, hashlib.sha256(agent.encode()).hexdigest(), hub.now(), "test"))
        self.report("vps", STORE_A)
        self.report("studio", STORE_B)

    # ---- helpers
    def report(self, agent, key, deposits=True, callers=True, features=("secret_deposits",), at=None):
        """One helper status, as a machine reports its vault (`broker_report`)."""
        data = {"features": list(features),
                "security": {"vault": {"broker_recipient": key, "callers": callers, "deposits": deposits,
                                       "broker_read_at": at or hub.now(), "mode": "broker"}}}
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET "
              "data=excluded.data, reported=excluded.reported", (agent, json.dumps(data), at or hub.now()))

    def deliver(self, text=None, machine="vps", pin=STORE_A):
        """One delivery as the reconciler makes it from a copy that the central vault sealed (central_deliver)."""
        with hub.LOCK:
            return hub.central_deliver(machine, LOGIN, text or copy(), pin, hub.now())

    # ---- the owner's own copies are gone
    def test_the_owners_app_seals_no_copy_to_a_machine_any_more(self):
        self.assertEqual(self.request("/ui/secrets/machines?db=test-generation")[0], 404)
        body = self.command(login=LOGIN, copies=[{"machine": "vps", "recipient": STORE_A, "ciphertext": copy()}])
        body.pop("text")
        self.assertEqual(self.request("/ui/secrets/deliver", body)[0], 404)
        self.assertNotIn("secret_deliveries", hub.UI_FEATURES)
        self.assertEqual(self.count("deposits"), 0)

    # ---- what one delivery keeps
    def test_the_hub_keeps_the_checksum_of_a_copy_and_the_copy_only_until_its_vault_has_it(self):
        text = copy()
        did = self.deliver(text)
        row = hub.q1("SELECT * FROM deposits WHERE id=?", (did,))
        self.assertEqual(row["sha256"], hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(row["ciphertext"], text)                             # it waits here for its own machine
        self.assertEqual((row["agent"], row["recipient"]), ("vps", STORE_A))
        self.assertTrue(row["request_id"].startswith(hub.CENTRAL_REQUEST))
        self.assertIsNone(self.deliver())                                     # it still waits: no second copy

    def test_a_machine_whose_agents_do_not_hold_the_secret_gets_no_copy(self):
        self.assertIsNone(self.deliver(machine="studio", pin=STORE_B))
        self.assertEqual(self.count("deposits"), 0)

    # ---- how a copy leaves the hub
    def test_the_vault_takes_the_copy_and_its_report_drops_it(self):
        text = copy()
        did = self.deliver(text)
        code, given = self.request("/helper/vault/vps", {"job": did, "kind": "deposit"})
        self.assertEqual(code, 200, given)
        self.assertEqual(given["ciphertext"], text)
        self.assertEqual((given["login"], given["title"], given["item"]), (LOGIN, "OPENAI_API_KEY", "api_key"))
        self.assertEqual(sorted(given["fingerprint_salts"]), ["password", "totp"])
        self.assertIsNotNone(hub.q1("SELECT released FROM deposits WHERE id=?", (did,))["released"])
        code, done = self.request(f"/helper/deposit/vps/{did}", {"ok": True, "text": "saved"})
        self.assertEqual(code, 200, done)
        row = hub.q1("SELECT * FROM deposits WHERE id=?", (did,))
        self.assertIsNone(row["ciphertext"])                                  # the hub keeps no copy after that
        self.assertEqual((row["ok"], row["result"]), (1, "saved"))
        self.assertIsNotNone(row["finished"])
        said = hub.q1("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id DESC")["text"]
        self.assertIn("is now in the vault of vps", said)
        self.assertIn("vps hold", said)                                       # the agent whose sessions read it
        self.assertNotIn(text[40:80], said)

    def test_a_vault_that_asks_for_a_copy_of_another_machine_gets_nothing(self):
        did = self.deliver()
        code, body = self.request("/helper/vault/studio", {"job": did, "kind": "deposit"})
        self.assertEqual(code, 404, body)
        self.assertIn("no such delivery", body["error"])

    def test_a_copy_is_not_given_out_after_its_machines_pinned_key_changed(self):
        did = self.deliver()
        hub.TEAM["vault_stores"]["vps"] = NO_STORE
        code, body = self.request("/helper/vault/vps", {"job": did, "kind": "deposit"})
        self.assertEqual(code, 409, body)
        self.assertIn("pinned vault key changed", body["error"])

    def test_a_copy_is_not_given_out_after_its_grant_went(self):
        """DevOps plan V1: the grant is read again when the vault takes the copy, as when it was sealed."""
        did = self.deliver()
        del hub.TEAM["agents"]["vps"]["secrets"]
        code, body = self.request("/helper/vault/vps", {"job": did, "kind": "deposit"})
        self.assertEqual(code, 409, body)
        self.assertIn("no agent of this machine holds this secret any more", body["error"])
        self.assertIsNone(hub.q1("SELECT released FROM deposits WHERE id=?", (did,))["released"])

    def test_a_copy_no_vault_can_take_any_more_is_dropped_and_said_in_words(self):
        did = self.deliver()
        hub.TEAM["vault_stores"]["vps"] = NO_STORE
        hub.expire_deposits(hub.now())
        row = hub.q1("SELECT * FROM deposits WHERE id=?", (did,))
        self.assertEqual((row["ok"], row["ciphertext"]), (0, None))
        self.assertIn("vault key changed", row["result"])
        self.assertIn("did not reach the vault of vps", hub.q1(
            "SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id DESC")["text"])

    def test_a_copy_whose_grant_went_is_dropped(self):
        did = self.deliver()
        hub.expire_deposits(hub.now())
        self.assertIsNone(hub.q1("SELECT finished FROM deposits WHERE id=?", (did,))["finished"])
        hub.TEAM["agents"]["vps"]["secrets"] = {}
        hub.expire_deposits(hub.now())
        row = hub.q1("SELECT * FROM deposits WHERE id=?", (did,))
        self.assertEqual((row["ok"], row["ciphertext"]), (0, None))
        self.assertEqual(row["result"], "No agent of its server holds it any more.")

    def test_a_copy_its_machine_never_took_is_dropped_after_a_week(self):
        did = self.deliver()
        hub.expire_deposits(hub.now() + hub.DEPOSIT_WAIT - 60)
        self.assertIsNone(hub.q1("SELECT finished FROM deposits WHERE id=?", (did,))["finished"])
        hub.expire_deposits(hub.now() + hub.DEPOSIT_WAIT + 60)
        row = hub.q1("SELECT * FROM deposits WHERE id=?", (did,))
        self.assertEqual((row["ok"], row["ciphertext"]), (0, None))
        self.assertIn("did not take it in a week", row["result"])

    # ---- what the manager reads
    def test_the_words_for_an_agent_say_where_its_secret_is_and_never_what_it_is(self):
        self.assertEqual(hub.delivery_words(LOGIN, ["vps"]), ["It has not reached the vault of vps yet."])
        did = self.deliver()
        self.assertEqual(hub.delivery_words(LOGIN, ["vps"]),
                         ["It is on its way to the vault of vps: the hub tells you when it is there."])
        hub.finish_deposit(hub.q1("SELECT * FROM deposits WHERE id=?", (did,)), True, "saved")
        self.assertEqual(hub.delivery_words(LOGIN, ["vps"]), ["The vault of vps has it."])
        self.assertEqual(hub.delivery_words(LOGIN, ["worker4"]), [])          # a machine that takes none is left out


if __name__ == "__main__":
    unittest.main()

"""create_login on a Linux worker: the broker makes a login in the fleet's own store, keeps a record before its one
save, and answers with a name. The real broker on a socket, the real hub routes and the real store; the age program is
the stand-in of test_vault.py. No real key, no real value and no account."""
import hashlib
import json
import os
import stat
import subprocess
import unittest
from unittest.mock import patch
import uuid

import fleet
import hub
import vault
from test_vault import REF, STORE_KEY, VaultBroker

RID = "0b0e7a52-6f0e-4d5e-9d53-1d3a3c1f0a01"
KEY = "vps-agent-key-".ljust(43, "k")
MARK = f"fleet-create:vps:{RID}"


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite(BrokerCreates(name) for name in BrokerCreates.__dict__ if name.startswith("test_"))
    suite.addTests(loader.loadTestsFromTestCase(NewPasswords))
    return suite


class Saves:
    """The broker's calls to its store for a new login (vault.LocalStore.create and login), kept in order. outcome:
    created (the real save), lost (the real save, and then the broker gets no answer, as when it ends in the call)
    or unknown (no item, and no answer). during: what happens at the moment of the call."""
    def __init__(self):
        self.calls, self.outcome, self.during = [], "created", None
        self.create, self.login = vault.LocalStore.create, vault.LocalStore.login

    def patches(self):
        saves = self

        def create(store, name, value, note):
            saves.calls.append(("create", name, note))
            if saves.during:
                saves.during()
            if saves.outcome == "unknown":
                raise OSError("no answer")
            made = saves.create(store, name, value, note)
            if saves.outcome == "lost":
                raise OSError("the broker ended")
            return made

        def login(store, item):
            saves.calls.append(("login", item))
            return saves.login(store, item)
        return patch.object(vault.LocalStore, "create", create), patch.object(vault.LocalStore, "login", login)

    def made(self):
        return [c for c in self.calls if c[0] == "create"]


class BrokerCreates(VaultBroker):
    """vps has broker access, an agent key and the owner's permission. Its broker makes logins in its own store."""
    def setUp(self):
        super().setUp()
        self.saves, self.logged = Saves(), []
        for p in (*self.saves.patches(), patch.object(vault, "log", self.logged.append)):
            p.start()
            self.addCleanup(p.stop)
        self.writer = self.broker
        hub.TEAM["agents"]["vps"]["vault_create"] = True
        hub.ins("INSERT OR REPLACE INTO agent_keys(agent,sha256,created,source) VALUES('vps',?,?,'owner')",
                (hashlib.sha256(KEY.encode()).hexdigest(), hub.now()))
        fleet.write_private(fleet.key_file("vps"), KEY + "\n")
        self.journal = self.dir / "state" / "creates.json"

    # ---- helpers
    def create_job(self, request=RID, label="Shop newsletter", username="vps@example.com",
                   url="https://news.example.com/signup"):
        return hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created,request_id,label,username,url,attempt) "
                       "VALUES('vps',?,'create',NULL,'',?,?,?,?,?,1)", (self.task, hub.now(), request, label, username, url))

    def ask(self, job, **fields):
        return fleet.vault_call(dict({"op": "create", "job": job, "agent": "vps", "agent_key": KEY}, **fields))

    def refused(self, job, **fields):
        """(the text, True when the outcome is not known) of a create request that gave no login."""
        with self.assertRaises(fleet.Refused) as refused:
            self.ask(job, **fields)
        return str(refused.exception), isinstance(refused.exception, fleet.Unknown)

    def records(self):
        return json.loads(self.journal.read_text()) if self.journal.exists() else []

    def new_items(self):
        """{id: item} of the store's items that a create made: the ones with a mark of this broker."""
        return {i: x for i, x in vault.LocalStore(self.conf).opened().items() if x["note"].startswith("fleet-create:")}

    def hub_answers(self, change):
        """The real hub, with `change(path, body, code, data)` giving another answer for some calls."""
        real = vault.hub

        def answer(conf, method, path, body=None):
            code, data = real(conf, method, path, body)
            other = change(path, body, code, data)
            return other if other is not None else (code, data)
        return patch.object(vault, "hub", answer)

    # ---- the setup
    def test_a_broker_without_its_record_of_saves_reads_as_before_and_makes_nothing(self):
        """The store writes itself, so a broker makes logins once its journal is open. A second process has no
        journal (one process only makes logins): it says so in its status, refuses the job before the hub is asked,
        and still reads."""
        job = self.create_job()
        status = lambda conf: vault.handle(conf, json.dumps({"v": 2, "op": "status"}), os.getuid())
        second = vault.with_writes(dict(self.conf))
        self.assertNotIn("_journal", second)
        self.assertEqual(self.logged[-1], "no new logins: the vault's record of its saves cannot be read, so it makes "
                                          "no login")
        self.assertNotIn("creates", status(second))
        self.assertIs(status(self.writer.conf)["creates"], True)
        request = json.dumps({"v": 2, "op": "create", "job": job, "agent": "vps", "agent_key": KEY})
        with self.assertRaises(vault.Refused) as refused:
            vault.handle(second, request, os.getuid())
        self.assertEqual(str(refused.exception), "This machine's vault is not set up to save logins.")
        self.assertIsNone(self.released(job))                                   # the hub was not asked
        self.assertEqual((self.saves.calls, self.new_items()), ([], {}))
        # The old write setup of a Bitwarden project is no configuration at all: the broker does not start on it.
        path, other = self.dir / "vault.json", {"worker_uid": os.getuid() + 1}     # the file is read by the vault user
        for keys in ({"sdk": "/usr/local/lib/fleet-vault/libbitwarden_c.so"}, {"sdk_sha256": "0" * 64},
                     {"write_project": "7b1f5e0c-3a9d-4c55-8f0e-2f6a1c9d4b77"}, {"journal": "/tmp/other.json"}):
            path.write_text(json.dumps({**self.conf, **keys, **other}))
            with self.assertRaises(SystemExit, msg=keys) as refused:
                vault.load_config(str(path))
            if "journal" not in keys:
                self.assertIn("Founderizer has no Bitwarden backend any more", str(refused.exception))
        self.assertEqual(fleet.vault_call({"op": "handover", "job": self.job()})["to"], "studio")      # reads are as before

    # ---- the save
    def test_the_broker_makes_the_login_and_only_its_name_leaves_it(self):
        job = self.create_job()
        text = fleet.do_save("vps", job, "create")                              # the helper's whole path
        (made, item), = self.new_items().items()
        self.assertEqual(text, f"The vault made bws://{made}. Its password never left the vault.")
        value = json.loads(item["value"])
        self.assertEqual((item["key"], item["note"], value["username"], value["url"], sorted(value)),
                         ("Shop newsletter", MARK, "vps@example.com", "https://news.example.com/signup",
                          ["password", "url", "username"]))
        password = value["password"]
        self.assertEqual(len(password), 24)
        # One save, and the values that the hub protects are read again from the store, not from memory.
        self.assertEqual(self.saves.calls, [("create", "Shop newsletter", MARK), ("login", made)])
        row = hub.q1("SELECT * FROM jobs WHERE id=?", (job,))
        self.assertEqual((row["login"], bool(row["released"])), (f"bws://{made}", True))
        self.assertEqual([r["label"] for r in self.rows()], [f"bws://{made} password"])
        self.assertTrue(hub.secret_hit(f"it is {password} now"))                # the hub masks it from now on
        (record,) = self.records()
        self.assertEqual((record["request_id"], record["state"], record["login"], record["mark"], record["title"],
                          len(record["binding"]), record["db"]),
                         (RID, "registered", f"bws://{made}", MARK, "Shop newsletter", 64, "test-generation"))
        self.assertEqual(self.journal.stat().st_mode & 0o777, 0o600)
        kept = self.journal.read_text() + self.store.read_text() + \
            json.dumps([dict(r) for table in ("jobs", "events", "log", "secrets") for r in hub.q(f"SELECT * FROM {table}")]) \
            + "\n".join(self.logged)
        for secret in (password, KEY):
            self.assertNotIn(secret, kept)
        self.assertIn(f"create job={job} for vps: ok", self.logged)
        # The same request again: the same name, and nothing is asked of the store.
        before = list(self.saves.calls)
        self.assertEqual(self.ask(job), {"ok": True, "v": 2, "job": job, "login": f"bws://{made}"})
        self.assertEqual(self.saves.calls, before)

    def test_the_record_is_kept_before_the_one_create_call(self):
        job, seen, steps = self.create_job(), [], []
        real_sync, real_replace = os.fsync, os.replace

        def sync(fd):
            steps.append("sync folder" if stat.S_ISDIR(os.fstat(fd).st_mode) else "sync file")
            return real_sync(fd)

        def replace(old, new):
            steps.append("name " + os.path.basename(new))
            return real_replace(old, new)
        self.saves.during = lambda: (seen.extend(self.records()), steps.append("create call"))
        with patch.object(vault.os, "fsync", sync), patch.object(vault.os, "replace", replace):
            self.ask(job)
        self.assertEqual([(r["request_id"], r["state"], r["login"]) for r in seen], [(RID, "creating", None)])
        # The file, its name and the folder are safe on the disk before the call: also a loss of power then leaves
        # the record, so the request never gets a second save. The store is written in the call, after them.
        self.assertEqual(steps[:steps.index("create call") + 1],
                         ["sync file", "name creates.json", "sync folder", "create call"])
        self.assertIn("name store.age", steps[steps.index("create call"):])
        # A journal that cannot be kept: nothing is made.
        second, state = str(uuid.uuid4()), self.dir / "state"
        other = self.create_job(second)
        state.chmod(0o500)
        self.addCleanup(state.chmod, 0o700)
        self.assertEqual(self.refused(other), ("the vault broker refused: The vault could not keep its record of this "
                                               "save, so it made nothing.", False))
        state.chmod(0o700)
        self.assertEqual((len(self.saves.made()), [r["request_id"] for r in self.records()]), (1, [RID]))
        self.assertEqual(self.ask(other)["ok"], True)                           # with its record, the request is made
        # A broker that ended during its create call: at the next start the record is unknown, never sent again.
        self.writer.close()
        records = self.records()
        records[1].update(state="creating", login=None)
        self.journal.write_text(json.dumps(records))
        again = vault.with_writes(dict(self.conf))
        self.addCleanup(lambda: again.get("_journal") and again["_journal"].close())
        self.assertEqual([r["state"] for r in again["_journal"].records], ["registered", "unknown"])
        self.assertEqual([r["state"] for r in self.records()], ["registered", "unknown"])
        # A second process gets no journal: one process only makes logins.
        self.assertNotIn("_journal", vault.with_writes(dict(self.conf)))
        # A journal that cannot be read stops new logins, and the broker still reads.
        again["_journal"].close()
        self.journal.write_text("{not a journal")
        self.assertNotIn("_journal", vault.with_writes(dict(self.conf)))

    def test_an_unknown_outcome_is_only_looked_for_by_its_mark(self):
        job = self.create_job()
        self.saves.outcome = "lost"                         # the store saved the item, but the broker got no answer
        self.assertEqual(self.refused(job), ("the vault could not confirm the outcome: The vault could not confirm that "
                                             "its store saved the login. It is not sent again.", True))
        self.assertEqual((self.records()[0]["state"], self.records()[0]["login"]), ("unknown", None))
        self.assertIsNone(hub.q1("SELECT login FROM jobs WHERE id=?", (job,))["login"])
        # The store cannot be read for the look-up: still not known, and nothing is saved.
        with patch.object(vault.LocalStore, "named", side_effect=vault.Refused("the vault store cannot be read")):
            self.assertTrue(self.refused(job)[1])
        (made,) = self.new_items()
        vault.LocalStore(self.conf).put(                    # the same name with another mark, as another request made
            "11111111-2222-4333-8444-555555555555", "Shop newsletter", "{}", "fleet-create:vps:another-request")
        self.assertEqual(self.ask(job), {"ok": True, "v": 2, "job": job, "login": f"bws://{made}"})      # found by its mark
        self.assertEqual((len(self.saves.made()), self.records()[0]["state"]), (1, "registered"))
        self.assertEqual(hub.q1("SELECT login FROM jobs WHERE id=?", (job,))["login"], f"bws://{made}")
        # No item at all: the record stays unknown, and the request gets no second save.
        second = str(uuid.uuid4())
        other = self.create_job(second)
        self.saves.outcome = "unknown"
        for _ in range(2):
            self.assertTrue(self.refused(other)[1])
        self.assertEqual((len(self.saves.made()), self.records()[1]["state"]), (2, "unknown"))

    def test_a_refused_save_makes_nothing_and_is_not_sent_again(self):
        job, before = self.create_job(), self.store.read_text()
        self.store.chmod(0o640)                             # a store that does not open: nothing is asked of the hub
        self.assertEqual(self.refused(job), ("the vault broker refused: the vault store file must belong to the vault "
                                             "user and have mode 600", False))
        self.store.chmod(0o600)
        self.assertEqual((self.records(), self.saves.made(), self.released(job)), ([], [], None))  # the request can come again
        real = vault.run

        def no_lock(argv, data, env=None):                  # an age that cannot lock the store: it saves nothing
            if argv[1:3] == ["-a", "-r"] and argv[3] == STORE_KEY:
                return subprocess.CompletedProcess(argv, 1, "", "age: no")
            return real(argv, data, env)
        with patch.object(vault, "run", no_lock):
            for _ in range(2):
                self.assertEqual(self.refused(job), ("the vault broker refused: The vault store refused this save and "
                                                     "made nothing.", False))
        self.assertEqual((len(self.saves.made()), self.records()[0]["state"], self.new_items()), (1, "failed", {}))
        self.assertEqual(self.store.read_text(), before)    # the store is the one it was
        self.assertFalse(self.refused(job)[1])              # also when the store works again: one request, one save
        self.assertEqual(len(self.saves.made()), 1)

    def test_a_request_cannot_come_back_with_other_values(self):
        job = self.create_job()
        self.ask(job)
        for change in ("label='Other name'", "username='other@example.com'", "url='https://other.example.com/'"):
            hub.q(f"UPDATE jobs SET {change} WHERE id=?", (job,))
            self.assertEqual(self.refused(job), ("the vault broker refused: This save was made with other values. It is "
                                                 "not made again.", False))
        self.assertEqual((len(self.saves.made()), len(self.records())), (1, 1))
        # What the hub confirms must have the form that the broker binds, and the mark of this agent and request.
        other = self.create_job(str(uuid.uuid4()))
        for change in ({"mark": "fleet-add:" + RID}, {"mark": MARK}, {"selector": "#key"}, {"source_url": "https://x.example/"},
                       {"attempt": 0}, {"attempt": "1"}, {"db": "bad generation"}, {"request_id": "not-a-uuid"},
                       {"label": "two\nlines"}, {"label": ""}, {"username": " padded"}, {"url": "https://vps@example.com/"},
                       {"url": "ftp://example.com/"}, {"task": ""}):
            with self.hub_answers(lambda path, body, code, data: (code, dict(data, **change)) if code == 200 else None):
                self.assertEqual(self.refused(other), ("the vault broker refused: The hub did not confirm this vault job.",
                                                       False), change)
        with self.hub_answers(lambda path, body, code, data: (code, dict(data, kind="capture")) if code == 200 else None):
            self.assertIn("the hub did not confirm this job", self.refused(other)[0])
        hub.ins("INSERT INTO holds(task,kind,by,state,created,attempt) VALUES(?,?,?,?,?,1)",
                (self.task, "pause", "owner", "requested", hub.now()))
        self.assertEqual(self.refused(other)[0], "the vault broker refused: the hub did not confirm this job: the task of "
                                                 "this job is paused or stopped")
        hub.q("UPDATE holds SET state='released' WHERE task=?", (self.task,))
        for fields, why in (({"agent": None, "agent_key": None}, "the caller fields are not valid"),
                            ({"agent_key": "w" * 43}, "the hub did not accept this agent's key")):
            self.assertIn(why, self.refused(other, **fields)[0])
        with self.assertRaises(vault.Refused) as refused:       # no caller fields at all
            vault.handle(self.writer.conf, json.dumps({"v": 2, "op": "create", "job": other}), os.getuid())
        self.assertEqual(str(refused.exception), "a create request needs the caller fields")
        self.assertEqual((len(self.saves.made()), len(self.records())), (1, 1))     # none of these made anything

    def test_the_hub_steps_after_the_save_stay_unknown_until_they_are_done(self):
        job = self.create_job()
        unregistered = "the vault could not confirm the outcome: The login is saved, but the hub did not register it."
        with self.hub_answers(lambda path, body, code, data: (500, {}) if path.endswith("/created") else None):
            self.assertEqual(self.refused(job), (unregistered, True))
        (made,) = self.new_items()
        self.assertEqual((self.records()[0]["state"], self.records()[0]["login"]), ("created", f"bws://{made}"))
        with self.hub_answers(lambda path, body, code, data:
                              (200, dict(data, stored=0)) if path.endswith("/fingerprints") else None):
            self.assertEqual(self.refused(job), (unregistered, True))           # no exact receipt of the fingerprints
        self.assertEqual(self.records()[0]["state"], "created")
        real = vault.hub

        def no_key(conf, method, path, body=None):
            if path.endswith("/created"):
                raise vault.Refused("the hub did not accept this agent's key")
            return real(conf, method, path, body)
        with patch.object(vault, "hub", no_key):
            self.assertEqual(self.refused(job), ("the vault could not confirm the outcome: the hub did not accept this "
                                                 "agent's key", True))
        self.assertEqual(self.ask(job)["login"], f"bws://{made}")               # the same request finishes the steps
        self.assertEqual((self.records()[0]["state"], len(self.saves.made())), ("registered", 1))
        self.assertEqual([r["label"] for r in self.rows()], [f"bws://{made} password"])

    def test_a_use_by_the_tasks_own_creation_needs_this_brokers_record(self):
        job = self.create_job()
        made = self.ask(job)["login"]
        proof = {"request_id": RID, "db": "test-generation", "agent": "vps", "attempt": 1, "label": "Shop newsletter",
                 "username": "vps@example.com", "url": "https://news.example.com/signup"}

        def confirmed(conf, login, **change):
            data = {"ok": True, "job": 9, "task": f"T-{self.task}", "kind": "handover", "login": login,
                    "source": login, "target": "studio", "recipient": "age1" + "s" * 58,
                    "fingerprint_salts": {"password": "0" * 32, "totp": "1" * 32}, "created_by": dict(proof, **change)}
            with patch.object(vault, "hub", lambda *a, **k: (200, data)):
                return vault.confirm_job(dict(conf, agent="vps"), 9, "handover")
        unrecorded = {k: v for k, v in self.writer.conf.items() if k != "_journal"}     # a broker with no record of saves
        self.assertEqual(confirmed(self.writer.conf, made)["login"], made)      # this broker made it for that request
        for conf, login, change in ((self.writer.conf, REF, {}), (self.writer.conf, made, {"label": "Other"}),
                                    (self.writer.conf, made, {"attempt": 2}), (self.writer.conf, made, {"agent": "studio"}),
                                    (self.writer.conf, made, {"request_id": str(uuid.uuid4())}), (unrecorded, made, {})):
            with self.assertRaises(vault.Refused) as refused:
                confirmed(conf, login, **change)
            self.assertEqual(str(refused.exception), "This vault did not make this login for that request, so it does "
                                                     "not use it.")


class NewPasswords(unittest.TestCase):
    """What a new login is made of: a password in the form that the Mac vault makes, and the binding of its request."""

    def test_a_password_has_the_form_that_the_mac_vault_makes(self):
        made = {vault.new_password() for _ in range(50)}
        self.assertEqual(len(made), 50)
        for text in made:
            self.assertEqual(len(text), 24)
            self.assertTrue(all(any(c in part for c in text) for part in (vault.UPPER, vault.LOWER, vault.DIGITS)))
            self.assertTrue(set(text) <= set(vault.UPPER + vault.LOWER + vault.DIGITS))
        fields = {"request_id": RID, "db": "g1", "task": "T-7", "attempt": 2, "label": "Shop",
                  "username": "u", "url": "https://example.com/"}
        first = vault.creation(fields, "vps")
        self.assertEqual((first["mark"], len(first["binding"])), (MARK, 64))
        for change in ({"db": "g2"}, {"task": "T-8"}, {"attempt": 3}, {"label": "Shop 2"},
                       {"username": "v"}, {"url": "https://example.com/x"}):
            self.assertNotEqual(vault.creation(dict(fields, **change), "vps")["binding"], first["binding"], change)
        self.assertNotEqual(vault.creation(fields, "studio")["binding"], first["binding"])
        self.assertEqual(vault.creation(dict(fields, request_id=RID.upper()), "vps")["binding"], first["binding"])


if __name__ == "__main__":
    unittest.main()

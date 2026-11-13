"""Owner feature secrets: the two kinds of the catalog, Add secret's one hub step, one-click grants (use and read) and
the vault's read route. In-process hub and temporary Git repositories; no helper, vault or AI call."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid

from unittest.mock import patch

import hub
from test_agent_auth import GRANT_TEAM, STORE, VaultAccess, sha
from test_setup import git
from test_ui_api import OwnerAPI

LOGIN = "bws://11111111-2222-4333-8444-55555555555b"
KEY = "bws://21111111-2222-4333-8444-55555555555b"
NEW = "bws://31111111-2222-4333-8444-55555555555b"
TEAM = dict(json.loads(json.dumps(GRANT_TEAM)), logins={
    LOGIN: {"title": "shop.test · admin", "kind": "login"},
    KEY: {"title": "OPENAI_API_KEY", "kind": "api_key", "env": "OPENAI_API_KEY"}})
VALUE = "sk-test-Pr4ct!ce-2026"


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(Grants(name) for name in Grants.__dict__ if name.startswith("test_"))


class Grants(VaultAccess):
    def setUp(self):
        OwnerAPI.setUp(self)
        self.root = Path(tempfile.mkdtemp(prefix="fleet-grants-"))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.root)])
        seed = self.root / "seed"
        seed.mkdir()
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", str(self.root / "origin.git"), str(self.root / "kit"))
        hub.CFG["team_path"] = str(self.root / "kit" / "team.json")
        self.addCleanup(hub.CFG.pop, "team_path", None)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = json.loads(json.dumps(TEAM))
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90, tick=5)
        for agent in ("alpha", "beta", "lone"):
            hub.ins("INSERT INTO agent_keys(agent,sha256,created,source) VALUES(?,?,?,'owner')", (agent, sha(agent), hub.now()))
            self.report(agent)
        # A central vault that answers and holds the owner's recovery key, as the hub last read it: without one, Add
        # secret's hub step refuses (DevOps plan V1, test_central_vault.py)
        central = patch.dict(hub.CENTRAL, dict(hub.CENTRAL_START, status={"recovery": "age1" + "e" * 58},
                                               read_at=hub.now()), clear=True)
        central.start()
        self.addCleanup(central.stop)

    def commits(self):
        return int(git("rev-list", "--count", "HEAD", cwd=self.root / "kit"))

    def grant(self, login, agent, grant, request_id=None):
        return self.request("/ui/secrets/grant", {"request_id": request_id or str(uuid.uuid4()), "db": "test-generation",
                                                  "login": login, "agent": agent, "grant": grant})

    def add(self, **fields):
        return self.request("/ui/secrets/add", dict({"request_id": str(uuid.uuid4()), "db": "test-generation"}, **fields))

    def vault_call(self, agent, path, body):
        """A call of the agent's vault, from its machine and with its key (the key of each test agent is its name)."""
        headers = {"Content-Type": "application/json", "Authorization": "Bearer " + agent}
        return self.request(f"/helper/vault/{agent}/{path}", body, headers=headers, source=hub.address_of(agent))

    def prints(self, login, value=VALUE):
        salt = self.request(f"/ui/secrets/salts?db=test-generation&login={login}")[1]["password"]
        return [{"kind": "password", "hash": hashlib.sha256((salt + value).encode()).hexdigest(), "len": len(value)}]

    def test_add_registers_the_fingerprints_and_the_catalog_entry_in_one_commit(self):
        self.assertIn("secret_grants", self.request()[1]["ui_features"])
        before = self.commits()
        body = dict(login=NEW.upper().replace("BWS", "bws"), title="GITHUB_PAT", kind="api_key", env="GITHUB_PAT",
                    fingerprints=self.prints(NEW))
        self.assertFalse(hub.secret_hit("the key is " + VALUE))
        code, receipt = self.add(**body)
        self.assertEqual((code, receipt["login"], receipt["stored"], receipt["known"], receipt["changed"]),
                         (200, NEW, 1, 0, True), receipt)
        self.assertEqual(self.commits(), before + 1)
        self.assertEqual(self.committed()["logins"][NEW], {"title": "GITHUB_PAT", "kind": "api_key", "env": "GITHUB_PAT"})
        self.assertTrue(hub.secret_hit("the key is " + VALUE))
        again = self.add(**body)[1]                         # the same step again: found, nothing committed
        self.assertEqual((again["stored"], again["known"], again["changed"]), (0, 1, False))
        self.assertEqual(self.commits(), before + 1)
        login = "bws://41111111-2222-4333-8444-55555555555b"
        code, receipt = self.add(login=login, title="shop.test · owner", kind="login")    # a short value: no fingerprint
        self.assertEqual((code, receipt["stored"], receipt["changed"]), (200, 0, True), receipt)
        catalog = self.team()["logins"]
        self.assertEqual(catalog[NEW], {"title": "GITHUB_PAT", "kind": "api_key", "env": "GITHUB_PAT", "protected": True,
                                        "grants": {}, "deliveries": {}})       # central_vault: none yet
        self.assertEqual(catalog[login], {"title": "shop.test · owner", "kind": "login", "protected": False, "grants": {},
                                          "deliveries": {}})
        for bad in (dict(body, env="FLEET_SESSION_TOKEN"), dict(body, env="PATH"), dict(body, env="ANTHROPIC_API_KEY"),
                    dict(body, env="openai_key"), dict(body, env="X" * 61), dict(body, kind="login"),
                    dict(body, env=None), dict(body, kind="note"), dict(body, value=VALUE), dict(body, title=""),
                    dict(body, login="sealed:4"), dict(body, fingerprints=self.prints(NEW) * 2)):
            with self.subTest(bad={k: v for k, v in bad.items() if k != "fingerprints"}):
                self.assertEqual(self.add(**bad)[0], 400)
        self.assertNotIn(VALUE, json.dumps([dict(r) for r in hub.q("SELECT * FROM ui_controls")]))

    def test_a_click_gives_and_takes_back_a_secret_and_read_is_only_for_an_api_key(self):
        before = self.commits()
        self.assertIn("not given it to you", hub.grant_refusal("alpha", KEY))
        code, receipt = self.grant(KEY, "alpha", "use")
        self.assertEqual((code, receipt["changed"], receipt["vault"], receipt["updates_requested"]),
                         (200, True, None, []), receipt)
        self.assertEqual(self.committed()["agents"]["alpha"]["secrets"], {KEY: "use"})
        self.assertIsNone(hub.grant_refusal("alpha", KEY))         # the grant gives the use, as a profile line does
        self.assertEqual(hub.read_secrets("alpha"), [])
        self.assertEqual(self.grant(KEY, "alpha", "use")[1]["changed"], False)      # the same click again: no commit
        self.assertEqual(self.commits(), before + 1)
        code, receipt = self.grant(KEY, "alpha", "read")
        self.assertEqual((code, receipt["updates_requested"]), (200, ["alpha"]), receipt)   # its helper starts sessions
        self.assertEqual(hub.read_secrets("alpha"), [(KEY, "OPENAI_API_KEY")])
        self.assertEqual(self.team()["logins"][KEY]["grants"], {"alpha": "read"})
        code, answer = self.grant(LOGIN, "alpha", "read")
        self.assertEqual((code, answer["error"]), (400, "only an API key can be read; an agent uses a login without seeing it"))
        self.assertEqual(self.grant(LOGIN, "alpha", "use")[0], 200)
        code, answer = self.request("/ui/team/logins", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                            base_sha256=self.team()["sha256"], login=KEY, delete=True))
        self.assertEqual((code, answer["agents"]), (409, ["alpha"]), answer)        # a granted secret stays
        code, receipt = self.grant(KEY, "alpha", None)
        self.assertEqual((code, receipt["changed"]), (200, True), receipt)
        self.assertEqual(self.committed()["agents"]["alpha"]["secrets"], {LOGIN: "use"})
        self.grant(LOGIN, "alpha", None)
        self.assertNotIn("secrets", self.committed()["agents"]["alpha"])
        # A new title keeps the kind and the variable name.
        code, _ = self.request("/ui/team/logins", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                       base_sha256=self.team()["sha256"], login=KEY, title="OpenAI"))
        self.assertEqual(self.committed()["logins"][KEY], {"title": "OpenAI", "kind": "api_key", "env": "OPENAI_API_KEY"})
        for login, agent, grant, code in ((KEY, "nobody", "use", 404), (NEW, "alpha", "use", 404),
                                          (KEY, "alpha", "write", 400), ("sealed:4", "alpha", "use", 400)):
            with self.subTest(agent=agent, grant=grant):
                self.assertEqual(self.grant(login, agent, grant)[0], code)

    def test_a_grant_turns_on_broker_access_when_the_machine_vault_is_ready(self):
        code, receipt = self.grant(LOGIN, "beta", "use")
        self.assertEqual((code, receipt["vault"], receipt["updates_requested"]),
                         (200, {"before": "none", "after": "broker"}, ["beta"]), receipt)
        team = self.committed()
        self.assertEqual((team["agents"]["beta"]["vault"], team["agents"]["beta"]["vault_recipient"], team["vault_stores"],
                          team["agents"]["beta"]["secrets"]), ("broker", STORE, {"box": STORE}, {LOGIN: "use"}))
        # lone is alone on its machine and nothing is recorded for it. With no broker there, its machine has no
        # store to give and the grant waits.
        self.report("lone", recipient=None)
        code, receipt = self.grant(LOGIN, "lone", "use")
        self.assertEqual((code, receipt["changed"], receipt["vault"]),
                         (200, True, {"before": "none", "after": "none", "missing": ["no_vault_store"]}), receipt)
        self.assertEqual(self.committed()["agents"]["lone"]["vault"], "none")
        self.assertEqual(self.grant(LOGIN, "lone", "use")[1]["changed"], False)
        # Once its broker answers, the key it reports is the one the grant pins (hub.offered_store), so the first
        # broker access on a machine is possible at all - which is what installing a broker with the machine needs.
        self.report("lone")
        code, receipt = self.grant(LOGIN, "lone", "use")
        self.assertEqual((code, receipt["vault"]), (200, {"before": "none", "after": "broker"}), receipt)
        team = self.committed()
        self.assertEqual((team["vault_stores"]["lone"], team["agents"]["lone"]["vault_recipient"]), (STORE, STORE))
        self.assertIsNone(self.grant(LOGIN, "filer", "use")[1]["vault"])         # vault files: nothing to turn on
        self.assertIsNone(self.grant(LOGIN, "manager", "use")[1]["vault"])
        code, receipt = self.grant(KEY, "manager", "read")       # the hub machine's own helper is not asked to update
        self.assertEqual((code, receipt["changed"], receipt["updates_requested"]), (200, True, []), receipt)

    def test_the_vault_reads_only_the_api_keys_that_the_agent_may_read(self):
        self.grant(KEY, "alpha", "read")
        self.grant(LOGIN, "alpha", "use")
        code, answer = self.vault_call("alpha", "read", {})
        salts = self.request(f"/ui/secrets/salts?db=test-generation&login={KEY}")[1]
        self.assertEqual((code, answer), (200, {"ok": True, "secrets": [
            {"login": KEY, "env": "OPENAI_API_KEY", "fingerprint_salts": {"password": salts["password"],
                                                                          "totp": salts["totp"]}}]}))
        code, receipt = self.vault_call("alpha", "fingerprints", {"login": KEY, "fingerprints": self.prints(KEY)})
        self.assertEqual((code, receipt["login"], receipt["stored"], receipt["known"]), (200, KEY, 1, 0), receipt)
        self.assertTrue(hub.secret_hit("echo " + VALUE))
        code, answer = self.vault_call("alpha", "fingerprints", {"login": LOGIN, "fingerprints": self.prints(LOGIN)})
        self.assertEqual((code, answer["error"]), (409, "alpha may not read this secret"))
        self.assertEqual(self.vault_call("alpha", "fingerprints", {"login": KEY, "fingerprints": []})[0], 400)
        self.assertEqual(self.vault_call("beta", "read", {}), (409, {"error": "beta has no credential access"}))
        code, answer = self.request("/helper/vault/alpha/read", {}, headers={"Content-Type": "application/json"},
                                    source=hub.address_of("alpha"))
        self.assertEqual(code, 403, answer)             # alpha shares its machine: only its key names it
        self.assertEqual(self.request("/helper/vault/filer/read", {}, source=hub.address_of("filer")),
                         (200, {"ok": True, "secrets": []}))    # alone on its machine, without a key: the address rule

    def test_team_json_takes_two_kinds_and_grants_of_the_catalog_only(self):
        team = json.loads(json.dumps(TEAM))
        hub.validate_team(team)
        for logins in ({KEY: {"title": "K", "kind": "api_key"}}, {KEY: {"title": "K", "env": "OPENAI_API_KEY"}},
                       {KEY: {"title": "K", "kind": "api_key", "env": "HOME"}}, {KEY: {"title": "K", "kind": "note"}},
                       {KEY: {"title": "K", "kind": "login", "env": "OPENAI_API_KEY"}}):
            with self.subTest(logins=logins), self.assertRaises(ValueError):
                hub.validate_team(dict(team, logins=logins))
        for grants in ({NEW: "use"}, {LOGIN: "read"}, {KEY: "write"}, [KEY], {KEY.upper(): "use"}):
            with self.subTest(grants=grants), self.assertRaises(ValueError):
                bad = json.loads(json.dumps(team))
                bad["agents"]["alpha"]["secrets"] = grants
                hub.validate_team(bad)
        twice = json.loads(json.dumps(team))
        twice["logins"][NEW] = dict(team["logins"][KEY], title="OpenAI 2")
        twice["agents"]["alpha"]["secrets"] = {KEY: "read", NEW: "use"}
        hub.validate_team(twice)
        twice["agents"]["alpha"]["secrets"][NEW] = "read"           # two values for one variable name
        with self.assertRaisesRegex(ValueError, "agent alpha: it reads two keys named OPENAI_API_KEY"):
            hub.validate_team(twice)

    def second_key(self):
        """A second API key of the catalog with the variable name of KEY, as a second Save of Add secret made one
        until 13 November 2026. The hub refuses a new one since, so this is a list from before."""
        with patch.object(hub, "key_named", lambda team, name, but=None: []):
            code, receipt = self.add(login=NEW, title="OPENAI_API_KEY", kind="api_key", env="OPENAI_API_KEY",
                                     fingerprints=self.prints(NEW, "sk-test-0ther-V4lue-2026"))
        self.assertEqual((code, receipt["changed"]), (200, True), receipt)

    def test_the_list_takes_no_second_key_of_one_name_and_a_list_from_before_stays_writable(self):
        """The owner, 13 November 2026: "having 2 keys named the same should not be possible". Each path that makes a
        key ends in this one hub step (Add secret, a request's card, an import), so the refusal is here."""
        before, other = self.commits(), "sk-test-0ther-V4lue-2026"
        code, answer = self.add(login=NEW, title="OPENAI_API_KEY", kind="api_key", env="OPENAI_API_KEY",
                                fingerprints=self.prints(NEW, other))
        self.assertEqual((code, answer["error"]), (409, "The list already has an API key named OPENAI_API_KEY, and it "
                                                        "takes no second key of that name."), answer)
        self.assertEqual((self.commits(), sorted(self.committed()["logins"])), (before, [LOGIN, KEY]))
        self.assertFalse(hub.secret_hit("the key is " + other))         # nothing was registered for it
        self.assertEqual(self.add(login=NEW, title="A second title", kind="api_key", env="OPENAI_API_KEY")[0], 409)
        # another name, and a login with that title, are no second key
        self.assertEqual(self.add(login=NEW, title="OPENAI_ORG_KEY", kind="api_key", env="OPENAI_ORG_KEY")[0], 200)
        login = "bws://41111111-2222-4333-8444-55555555555b"
        self.assertEqual(self.add(login=login, title="OPENAI_API_KEY", kind="login")[0], 200)
        # The key that is there is saved again under its own reference: the hub step of a replace of its value. It
        # adds the fingerprints of the new value and leaves the entry, so nothing is committed.
        commits = self.commits()
        code, receipt = self.add(login=KEY, title="OPENAI_API_KEY", kind="api_key", env="OPENAI_API_KEY",
                                 fingerprints=self.prints(KEY, other))
        self.assertEqual((code, receipt["stored"], receipt["changed"], self.commits()), (200, 1, False, commits), receipt)
        self.assertTrue(hub.secret_hit("the key is " + other))
        # The owner saves the first value again: its fingerprint is the newest one of the reference now, with no
        # second row of it, because an intake gives the central vault only the newest of each kind.
        newest = lambda: hub.q1("SELECT hash FROM secrets WHERE label=? ORDER BY id DESC",
                                (hub.fingerprint_label(KEY, "password"),))["hash"]
        self.assertEqual(newest(), self.prints(KEY, other)[0]["hash"])
        code, receipt = self.add(login=KEY, title="OPENAI_API_KEY", kind="api_key", env="OPENAI_API_KEY",
                                 fingerprints=self.prints(KEY))
        self.assertEqual((code, receipt["stored"], receipt["known"], receipt["changed"]), (200, 1, 0, False), receipt)
        code, receipt = self.add(login=KEY, title="OPENAI_API_KEY", kind="api_key", env="OPENAI_API_KEY",
                                 fingerprints=self.prints(KEY, other))
        self.assertEqual((code, receipt["stored"], receipt["known"], newest()),
                         (200, 0, 1, self.prints(KEY, other)[0]["hash"]), receipt)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM secrets WHERE label=?",
                                (hub.fingerprint_label(KEY, "password"),))["n"], 2)
        # a key cannot take the name of another one either
        code, answer = self.add(login=NEW, title="OPENAI_API_KEY", kind="api_key", env="OPENAI_API_KEY")
        self.assertEqual(code, 409, answer)
        # A list from before has two keys of one name. No write fails that leaves them as they are: the same step
        # again for either one, a new title, a grant; and validate_team takes the file.
        fourth = "bws://61111111-2222-4333-8444-55555555555b"
        with patch.object(hub, "key_named", lambda team, name, but=None: []):
            self.assertEqual(self.add(login=fourth, title="OPENAI_API_KEY", kind="api_key", env="OPENAI_API_KEY")[0], 200)
        self.assertEqual(hub.key_named(hub.TEAM, "OPENAI_API_KEY"), sorted([KEY, fourth]))
        self.assertEqual(hub.key_named(hub.TEAM, "OPENAI_API_KEY", KEY), [fourth])
        self.assertIsNone(hub.team_problem(json.loads(json.dumps(hub.TEAM))))
        for ref in (KEY, fourth):
            code, receipt = self.add(login=ref, title="OPENAI_API_KEY", kind="api_key", env="OPENAI_API_KEY",
                                     fingerprints=self.prints(ref, "sk-test-Th1rd-V4lue-2026"))
            self.assertEqual((code, receipt["changed"]), (200, False), receipt)
        code, _ = self.request("/ui/team/logins", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                       base_sha256=self.team()["sha256"], login=fourth, title="OpenAI old"))
        self.assertEqual(code, 200)
        self.assertEqual(self.grant(fourth, "alpha", "use")[0], 200)
        self.assertEqual(self.grant(KEY, "alpha", "read")[0], 200)
        # and a third one of that name is refused as the second one is
        self.assertEqual(self.add(login="bws://71111111-2222-4333-8444-55555555555b", title="OPENAI_API_KEY",
                                  kind="api_key", env="OPENAI_API_KEY")[0], 409)

    def test_one_agent_never_reads_two_keys_of_one_variable_name(self):
        """The guard of 13 November 2026: a vault that gets one variable name two times refuses the whole read, so
        the agent's sessions start with none of its keys. The hub refuses the grant that would make that state, in
        words for the row that shows the grant, and it commits nothing."""
        self.second_key()
        self.assertEqual(self.grant(KEY, "alpha", "read")[0], 200)
        before = self.commits()
        code, answer = self.grant(NEW, "alpha", "read")
        self.assertEqual((code, answer["error"]), (409, "This agent already reads another key named OPENAI_API_KEY. A "
                                                        "session has one value for one name. Take the other key back "
                                                        "from this agent first."), answer)
        self.assertEqual((self.commits(), self.committed()["agents"]["alpha"]["secrets"]), (before, {KEY: "read"}))
        self.assertEqual(hub.read_secrets("alpha"), [(KEY, "OPENAI_API_KEY")])
        # the manager's grant goes the same way (grant_access calls save_grant)
        with hub.LOCK, self.assertRaises(hub.Refusal) as refused:
            hub.save_grant({"login": NEW, "agent": "alpha", "grant": "read"}, by="manager")
        self.assertEqual(refused.exception.status, 409)
        # the key is another agent's to read, and this agent can use it: neither puts two values under one name
        self.assertEqual(self.grant(NEW, "beta", "read")[0], 200)
        self.assertEqual(self.grant(NEW, "alpha", "use")[0], 200)
        self.assertEqual(self.vault_call("alpha", "read", {})[1]["secrets"][0]["login"], KEY)
        # use to read is the same grant: refused, and the use stays
        self.assertEqual(self.grant(NEW, "alpha", "read")[0], 409)
        self.assertEqual(self.committed()["agents"]["alpha"]["secrets"], {KEY: "read", NEW: "use"})
        # after the take-back of the first key, the agent reads the second one
        self.assertEqual(self.grant(KEY, "alpha", None)[0], 200)
        self.assertEqual(self.grant(NEW, "alpha", "read")[0], 200)
        self.assertEqual(hub.read_secrets("alpha"), [(NEW, "OPENAI_API_KEY")])
        self.assertEqual(self.grant(KEY, "alpha", "read")[0], 409)          # and now the first one is the second
        # a key that an agent only uses is no value of its sessions: it reads the other key of that name
        self.assertEqual(self.grant(NEW, "lone", "use")[0], 200)
        self.assertEqual(self.grant(KEY, "lone", "read")[0], 200)
        self.assertEqual(hub.read_secrets("lone"), [(KEY, "OPENAI_API_KEY")])

    def test_a_read_names_no_variable_two_times(self):
        """A team.json that no owner write made can give one agent two read keys of one name (the hub starts on such
        a file and says the rule). The hub's answer to the vault then leaves both out and names the agent's other
        keys, so one fault does not cost the agent each of its keys."""
        self.second_key()
        other = "bws://51111111-2222-4333-8444-55555555555b"
        self.assertEqual(self.add(login=other, title="GITHUB_PAT", kind="api_key", env="GITHUB_PAT")[0], 200)
        team = json.loads(json.dumps(hub.TEAM))
        team["agents"]["alpha"]["secrets"] = {KEY: "read", NEW: "read", other: "read"}
        self.assertIn("it reads two keys named OPENAI_API_KEY", hub.team_problem(team))
        with patch.object(hub, "TEAM", team):
            self.assertEqual(hub.read_twice(team, "alpha", KEY), [NEW])
            self.assertEqual(hub.read_twice(team, "alpha", other), [])
            code, answer = self.vault_call("alpha", "read", {})
        self.assertEqual((code, [x["env"] for x in answer["secrets"]]), (200, ["GITHUB_PAT"]), answer)
        said = [r["what"] for r in hub.q("SELECT what FROM log WHERE agent='alpha' AND what LIKE 'REFUSED the keys%'")]
        self.assertEqual(len(said), 1, said)
        self.assertIn("OPENAI_API_KEY", said[0])


if __name__ == "__main__":
    unittest.main()

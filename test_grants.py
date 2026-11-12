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
        with self.assertRaises(ValueError):
            hub.validate_team(twice)


if __name__ == "__main__":
    unittest.main()

"""The hub's side of an account with a key or with the owner's own model server (the AI providers build, lane B1):
team.json "accounts" with a `kind`, each rule of it and its words, the three refusals for the pool, the group of its
agents, the setup check's `account` item, the task start of an ACP program, the pause of its failed turn, its costs,
and what the manager may change of its model. An in-process hub with a temporary database and a temporary Git
checkout; no helper, no vault, no model server and no AI call. Each agent of an account runs on a Linux server of its
own, so these tests hold with the rule "one OS user for each agent" and without it."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

import hub
import lifecycle
from test_ui_api import OwnerAPI

GEMINI_KEY = "bws://5b0c1d2e-0000-4000-8000-000000000001"
SERVER_KEY = "bws://5b0c1d2e-0000-4000-8000-000000000002"
ROUTER_KEY = "bws://5b0c1d2e-0000-4000-8000-000000000003"
FREE_KEY = "bws://5b0c1d2e-0000-4000-8000-000000000004"
SHOP_LOGIN = "bws://5b0c1d2e-0000-4000-8000-000000000005"
LINUX = {"kind": "linux", "user": "fleet"}
OPENCODE = {"role": "worker", "runtime": "opencode", "can": ["shell", "web"], "reports_to": "manager"}
TEAM = {
    "hub": {"machine": "hub", "port": 8765},
    "addresses": {"owner": "127.0.0.1", "hub": "100.64.0.2", "app-1": "100.64.0.11", "app-2": "100.64.0.12",
                  "app-3": "100.64.0.13", "app-4": "100.64.0.14", "app-5": "100.64.0.15", "app-6": "100.64.0.16",
                  "mac-1": "100.64.0.21"},
    "servers": {"app-1": LINUX, "app-2": LINUX, "app-3": LINUX, "app-4": LINUX, "app-5": LINUX, "app-6": LINUX,
                "mac-1": {"kind": "mac", "user": "fleet"}},
    "logins": {GEMINI_KEY: {"title": "Gemini key", "kind": "api_key", "env": "GEMINI_API_KEY"},
               SERVER_KEY: {"title": "Model server key", "kind": "api_key", "env": "MODEL_SERVER_KEY"},
               ROUTER_KEY: {"title": "OpenRouter key", "kind": "api_key", "env": "OPENROUTER_API_KEY"},
               FREE_KEY: {"title": "Another key", "kind": "api_key", "env": "ANOTHER_API_KEY"},
               SHOP_LOGIN: {"title": "Shop", "kind": "login"}},
    "accounts": {"codex-main": {"provider": "openai", "title": "Codex Pro"},
                 "gemini": {"provider": "google", "title": "Gemini", "kind": "key", "secret": GEMINI_KEY},
                 "spark": {"provider": "own", "title": "Spark", "kind": "server",
                           "address": "http://100.64.0.7:8000/v1", "secret": SERVER_KEY},
                 "router": {"provider": "openrouter", "title": "OpenRouter", "kind": "key", "secret": ROUTER_KEY,
                            "model": "openrouter/qwen3.8-max"}},
    "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
               "dev-lead": {"role": "worker", "runtime": "claude", "machine": "app-4", "can": ["shell"],
                            "account": "codex-main"},
               "gem-1": dict(OPENCODE, machine="app-1", account="gemini", secrets={GEMINI_KEY: "read"}),
               "gem-2": dict(OPENCODE, machine="app-2", account="gemini", secrets={GEMINI_KEY: "read"}),
               "own-1": dict(OPENCODE, machine="app-3", account="spark", secrets={SERVER_KEY: "read"}),
               "seller-1": dict(OPENCODE, machine="app-5", account="router", secrets={ROUTER_KEY: "read"})}}


def git(*args, cwd=None):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def helper_reports(agent, *features, **data):
    """The status report of the agent's helper as the hub keeps it (test_release_turns.helper_reports)."""
    assert not set(features) - set(lifecycle.FEATURES), features
    hub.q("INSERT INTO machine_status(agent,data,reported) VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET "
          "data=excluded.data, reported=excluded.reported",
          (agent, json.dumps(dict(data, features=list(features))), hub.now()))


def models(runtime, *names, efforts=("low", "medium", "high")):
    """A current model reading of one runtime, its first model the default (lifecycle.Lifecycle.model_options)."""
    return {"runtime": runtime, "ok": True, "read_at": time.time(), "source": "ACP session/new", "other_names": False,
            "error": None, "options": [{"model": m, "display_name": m, "default": i == 0, "efforts": list(efforts),
                                        "default_effort": None} for i, m in enumerate(names)]}


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(ModelAccounts(name) for name in ModelAccounts.__dict__ if name.startswith("test_"))


class ModelAccounts(OwnerAPI):
    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="fleet-model-accounts-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        seed = self.root / "seed"
        seed.mkdir()
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", str(self.root / "origin.git"), str(self.root / "kit"))
        self.kit = self.root / "kit"
        hub.CFG["team_path"] = str(self.kit / "team.json")
        self.addCleanup(hub.CFG.pop, "team_path", None)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = copy.deepcopy(TEAM)
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90, tick=5,
                       ask_wait=1, ask_max=1, hook_wait=0.2, job_wait=0.05)
        allowed = patch.object(hub.Handler, "allowed", lambda handler, who, broker=False: True)
        allowed.start()
        self.addCleanup(allowed.stop)
        central = patch.dict(hub.CENTRAL, {"status": None})
        central.start()
        self.addCleanup(central.stop)

    # ---- helpers
    def sha(self):
        return self.request("/ui/team?db=test-generation")[1]["sha256"]

    def account(self, account, **fields):
        return self.request("/ui/team/accounts", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                      base_sha256=self.sha(), account=account, **fields))

    def stored(self):
        return json.loads((self.kit / "team.json").read_text())

    def refused(self, change):
        """The words with which validate_team refuses the team after change(team)."""
        team = copy.deepcopy(TEAM)
        change(team)
        with self.assertRaises(ValueError) as said:
            hub.validate_team(team)
        return str(said.exception)

    def service(self, server, os_name="Ubuntu 24.04.1 LTS", features=("install_key", "model_accounts")):
        """A server that joined: its service's key and a fresh reading with these features (server.py reading)."""
        hub.q("INSERT OR REPLACE INTO server_keys(server,sha256,created) VALUES(?,?,?)", (server, "0" * 64, hub.now()))
        hub.q("INSERT OR REPLACE INTO server_status(server,data,reported) VALUES(?,?,?)",
              (server, json.dumps({"revision": hub.kit_revision(fresh=True), "os": {"name": os_name},
                                   "access": {"user": "fleet"}, "features": list(features)}), hub.now()))

    def put(self, team):
        """team.json as the owner's routes write it: committed through the hub and applied."""
        hub.validate_team(team)
        hub.commit_kit_file("team.json", (json.dumps(team, indent=2) + "\n").encode(), "Owner changed the team")
        hub.apply_team(team)

    def task(self, owner):
        text = hub.t_create_task("manager", {"owner": owner, "title": "Write the release notes",
                                             "done_when": "The notes are in the repository.", "needs": "none"})
        return int(text.split()[1][2:].rstrip("."))

    def start_event(self, tid):
        row = hub.q1("SELECT * FROM events WHERE task=? AND kind='task' ORDER BY id LIMIT 1", (tid,))
        return dict(row, extra=json.loads(row["extra"] or "{}"))

    # ---- the entries and their rules (spec 3.1, 3.3, 3.8)
    def test_the_team_with_each_kind_is_valid_and_an_entry_of_todays_shape_reads_and_writes_as_before(self):
        hub.validate_team(copy.deepcopy(TEAM))
        code, receipt = self.account("codex-team", provider="openai", title="Codex Team")
        self.assertEqual((code, receipt["changed"], receipt["deleted"]), (200, True, False), receipt)
        self.assertEqual(set(receipt) - {"request_id", "client", "ok", "replayed"},
                         {"account", "revision", "sha256", "changed", "deleted"})     # the route's answer keeps its shape
        self.assertEqual(self.stored()["accounts"]["codex-team"], {"provider": "openai", "title": "Codex Team"})
        accounts = self.request("/ui/team?db=test-generation")[1]["accounts"]
        self.assertEqual(accounts["codex-team"], {"provider": "openai", "title": "Codex Team"})
        self.assertEqual(accounts["spark"], TEAM["accounts"]["spark"])          # each field; secret is a reference
        for fields in ({"secret": GEMINI_KEY}, {"address": "http://127.0.0.1:11434"}, {"model": "gpt-6.1-sol"}):
            with self.subTest(fields=fields):
                code, said = self.account("codex-team", provider="openai", title="Codex Team", **fields)
                self.assertEqual(code, 400)
                self.assertIn("only for an account with a kind", said["error"])
        team = copy.deepcopy(TEAM)
        team["accounts"]["codex-main"]["secret"] = GEMINI_KEY
        with self.assertRaises(ValueError) as said:
            hub.validate_team(team)
        self.assertEqual(str(said.exception), hub.ACCOUNT_WORDS["labels"].format(aid="codex-main"))

    def test_a_key_account_is_taken_by_the_route_and_each_of_its_refusals_has_its_words(self):
        code, receipt = self.account("gemini-2", provider="google", title="Gemini 2", kind="key",
                                     secret=GEMINI_KEY.upper().replace("BWS", "bws"))
        self.assertEqual(code, 200, receipt)
        self.assertEqual(self.stored()["accounts"]["gemini-2"], {"provider": "google", "title": "Gemini 2",
                                                                  "kind": "key", "secret": GEMINI_KEY})
        W = hub.ACCOUNT_WORDS
        for fields, words in (
                ({"provider": "openai", "kind": "key", "secret": FREE_KEY},
                 W["key_provider"].format(aid="acc-x", providers=", ".join(lifecycle.KEY_PROVIDERS))),
                ({"provider": "google", "kind": "key", "secret": FREE_KEY, "address": "https://models.example.com"},
                 W["key_address"].format(aid="acc-x")),
                ({"provider": "google", "kind": "key"}, W["key_secret"].format(aid="acc-x")),
                ({"provider": "google", "kind": "key", "secret": SHOP_LOGIN}, W["secret"].format(aid="acc-x")),
                ({"provider": "google", "kind": "key", "secret": "bws://5b0c1d2e-0000-4000-8000-0000000000ff"},
                 W["secret"].format(aid="acc-x")),
                ({"provider": "openrouter", "kind": "key", "secret": FREE_KEY},
                 W["key_model"].format(aid="acc-x", label="OpenRouter")),
                ({"provider": "own", "kind": "server", "address": "https://models.example.com", "secret": FREE_KEY,
                  "model": "bad model"}, "model must be 1 to 120 characters of A-Z a-z 0-9 . _ : / - [ ]"),
                ({"provider": "openai", "kind": "server", "address": "https://models.example.com",
                  "secret": FREE_KEY}, W["own_provider"].format(aid="acc-x")),
                ({"provider": "own", "kind": "plan"}, "kind must be key or server, or absent"),
                ({"provider": "own", "kind": "server", "secret": "sealed:4"},
                 "secret must be a bws://<uuid> reference")):
            with self.subTest(fields=fields):
                code, said = self.account("acc-x", title="X", **fields)
                self.assertEqual((code, said["error"]), (400, words))
        self.assertNotIn("acc-x", self.stored()["accounts"])
        # A seller of several makers with its model, and a server with a key: both taken.
        self.assertEqual(self.account("router-2", provider="openrouter", title="R", kind="key", secret=FREE_KEY,
                                      model="openrouter/kimi-k3")[0], 200)
        self.assertEqual(self.account("box", provider="own", title="Box", kind="server",
                                      address="https://models.example.com/api/v1", secret=FREE_KEY)[0], 200)

    def test_the_address_of_a_model_server_follows_its_rule_and_is_kept_in_one_form(self):
        for given, kept in (("HTTP://LocalHost:11434", "http://localhost:11434/v1"),
                            ("http://127.0.0.1:1234/v1/", "http://127.0.0.1:1234/v1"),
                            ("http://127.8.0.1:1234/", "http://127.8.0.1:1234/v1"),
                            ("http://[::1]:8080", "http://[::1]:8080/v1"),
                            ("http://100.64.0.7:8000/v1", "http://100.64.0.7:8000/v1"),
                            ("http://100.127.255.1/v1", "http://100.127.255.1/v1"),
                            ("http://spark.tail1234.ts.net:8000", "http://spark.tail1234.ts.net:8000/v1"),
                            ("https://models.example.com/api/v1", "https://models.example.com/api/v1"),
                            ("https://203.0.113.5:8443", "https://203.0.113.5:8443/v1")):
            with self.subTest(given=given):
                self.assertEqual(hub.account_address(given, "box"), kept)
        address, plain = hub.ACCOUNT_WORDS["address"].format(aid="box"), hub.ACCOUNT_WORDS["plain_http"].format(aid="box")
        for given, words in (("ftp://models.example.com/v1", address), ("models.example.com", address),
                             ("http://owner@100.64.0.7/v1", address), ("http://u:p@100.64.0.7/v1", address),
                             ("http://100.64.0.7/v1?key=1", address), ("http://100.64.0.7/v1#top", address),
                             ("http://100.64.0.7:0/v1", address), ("http://100.64.0.7:99999/v1", address),
                             ("https://exa mple.com/v1", address), ("https://ex_ample.com/v1", address),
                             ("https://models.example.com/v1/%2e%2e", address), ("https://", address),
                             ("https://models.example.com/" + "a" * 200, address), ("", address), (None, address),
                             ("http://models.example.com/v1", plain), ("http://192.168.1.5:8000/v1", plain),
                             ("http://100.128.0.1/v1", plain), ("http://ts.net.example.com/v1", plain)):
            with self.subTest(given=given):
                with self.assertRaises(ValueError) as said:
                    hub.account_address(given, "box")
                self.assertEqual(str(said.exception), words)
        code, receipt = self.account("box", provider="own", title="Box", kind="server",
                                     address="HTTP://LocalHost:11434")
        self.assertEqual(code, 200, receipt)
        self.assertEqual(self.stored()["accounts"]["box"]["address"], "http://localhost:11434/v1")
        self.assertEqual(self.account("box", provider="own", title="Box", kind="server",
                                      address="http://models.example.com")[1]["error"], plain)
        # A hand-written address that is not in the hub's one form is refused by validate_team.
        self.assertEqual(self.refused(lambda t: t["accounts"]["spark"].update(address="http://100.64.0.7:8000")),
                         hub.ACCOUNT_WORDS["address"].format(aid="spark"))

    def test_a_model_server_with_no_key_is_one_agents_alone_on_its_server_on_the_loopback(self):
        def open_spark(address):
            def change(team):
                team["accounts"]["spark"] = {"provider": "own", "title": "Spark", "kind": "server", "address": address}
                team["agents"]["own-1"].pop("secrets")
            return change
        words = hub.ACCOUNT_WORDS["open"].format(aid="spark")
        self.assertEqual(self.refused(open_spark("http://100.64.0.7:8000/v1")), words)
        team = copy.deepcopy(TEAM)
        open_spark("http://127.0.0.1:11434/v1")(team)
        hub.validate_team(team)                                 # one agent, alone on app-3, at the loopback
        team["agents"]["own-1"]["account"] = "codex-main"       # and no agent at all: the order of the owner's writes
        team["agents"]["own-1"]["runtime"] = "codex"
        hub.validate_team(team)
        self.assertEqual(self.refused(lambda t: (open_spark("http://localhost:11434/v1")(t), t["agents"].update(
            {"own-2": dict(OPENCODE, machine="app-6", account="spark")}))), words)        # two agents reach it
        self.assertEqual(self.refused(lambda t: (open_spark("http://localhost:11434/v1")(t), t["agents"].update(
            {"beside": {"role": "worker", "runtime": "claude", "machine": "app-3", "can": ["shell"]}}))),
            words)                                                                       # its server has two agents
        # The route takes an open loopback server that no agent names.
        self.assertEqual(self.account("local", provider="own", title="Local", kind="server",
                                      address="http://127.0.0.1:1234")[0], 200)
        self.assertEqual(self.account("local", provider="own", title="Local", kind="server",
                                      address="https://models.example.com")[1]["error"],
                         hub.ACCOUNT_WORDS["open"].format(aid="local"))

    def test_an_owner_label_reads_and_writes_exactly_as_before(self):
        """The spec writer's answer of 14 November 2026, rule 2: a write replaces the whole entry and carries nothing
        over only for an entry with a kind; an entry of today's shape (no kind) reads and writes exactly as before."""
        team = self.stored()
        self.assertEqual(self.account("codex-team", provider="openai", title=" Codex Team ")[1]["changed"], True)
        self.assertEqual(self.stored()["accounts"]["codex-team"], {"provider": "openai", "title": "Codex Team"})
        self.assertEqual(self.account("codex-team", provider="openai", title="Codex Team")[1]["changed"], False)
        code, receipt = self.account("codex-main", provider="openai", title="Codex Pro (owner)")
        self.assertEqual(code, 200, receipt)
        after = self.stored()
        self.assertEqual(after["accounts"]["codex-main"], {"provider": "openai", "title": "Codex Pro (owner)"})
        self.assertEqual(after["agents"]["dev-lead"], team["agents"]["dev-lead"])         # its agent stays on it
        self.assertEqual({k: v for k, v in after["accounts"].items() if k not in ("codex-main", "codex-team")},
                         {k: v for k, v in team["accounts"].items() if k != "codex-main"})   # no other entry moved
        self.assertEqual(self.request("/ui/team?db=test-generation")[1]["accounts"]["codex-main"],
                         {"provider": "openai", "title": "Codex Pro (owner)"})
        code, said = self.account("codex-main", delete=True)
        self.assertEqual((code, said["agents"]), (409, ["dev-lead"]))                   # in use: as before

    def test_an_open_model_server_refuses_a_second_agent_on_its_machine(self):
        """The spec writer's answer, rule 3: validate_team runs on every write, so a later add of a second agent to
        the machine of an open model server's one agent is refused."""
        team = copy.deepcopy(TEAM)
        team["accounts"]["spark"] = {"provider": "own", "title": "Spark", "kind": "server",
                                     "address": "http://127.0.0.1:11434/v1"}
        team["agents"]["own-1"].pop("secrets")
        self.put(team)
        self.service("app-3")
        with patch.object(hub, "not_shareable", lambda team, here: []):     # its own agent key: not this test's
            code, said = self.request("/ui/servers/app-3/agents", dict(
                request_id=str(uuid.uuid4()), db="test-generation", base_sha256=self.sha(), agent="beside",
                runtime="claude", role="worker", reports_to=None))
        self.assertEqual((code, said["error"]), (400, hub.ACCOUNT_WORDS["open"].format(aid="spark")))
        self.assertNotIn("beside", self.stored()["agents"])
        self.assertEqual(hub.q("SELECT * FROM server_jobs"), [])
        with patch.object(hub, "not_shareable", lambda team, here: []):     # a server with a key: taken
            team["accounts"]["spark"]["secret"] = SERVER_KEY
            self.put(team)
            code, said = self.request("/ui/servers/app-3/agents", dict(
                request_id=str(uuid.uuid4()), db="test-generation", base_sha256=self.sha(), agent="beside",
                runtime="claude", role="worker", reports_to=None))
        self.assertEqual(code, 200, said)

    def test_an_open_model_server_refuses_a_second_agent_that_names_it(self):
        """The spec writer's answer, rule 3: a second agent that names an open model server is refused, at the write
        that would add it and at the owner's change of an agent's account."""
        team = copy.deepcopy(TEAM)
        team["accounts"]["spark"] = {"provider": "own", "title": "Spark", "kind": "server",
                                     "address": "http://127.0.0.1:11434/v1"}
        team["agents"]["own-1"].pop("secrets")
        self.put(team)
        second = copy.deepcopy(team)
        second["agents"]["own-2"] = dict(OPENCODE, machine="app-6", account="spark")     # alone on its own server
        with self.assertRaises(ValueError) as said:
            hub.validate_team(second)
        self.assertEqual(str(said.exception), hub.ACCOUNT_WORDS["open"].format(aid="spark"))
        code, said = self.request("/ui/team/agents/gem-2", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                                base_sha256=self.sha(), account="spark"))
        self.assertEqual(code, 409)                 # the owner's route refuses it first: no change of account (K7)
        self.assertEqual(self.stored()["agents"]["gem-2"]["account"], "gemini")

    def test_a_write_never_takes_the_key_or_the_program_away_from_the_agents_of_an_account(self):
        """The wave 1 review, R1, and the spec writer's answer of 14 November 2026."""
        before = self.stored()
        # 1. A write with no kind of an entry that has one: a client that knows no kind (the owner MCP's save_account
        # of today sends provider and title) cannot make a key account a label.
        code, said = self.account("gemini", provider="google", title="Gemini key")
        self.assertEqual((code, said["error"]), (409, hub.ACCOUNT_WORDS["kind_kept"]))
        # 2. While agents name it: no change of its kind, its provider or its secret, nor a label made a kind.
        for account, fields, agents in (
                ("gemini", dict(provider="openrouter", kind="key", secret=GEMINI_KEY, model="openrouter/kimi-k3"),
                 ["gem-1", "gem-2"]),
                ("spark", dict(provider="google", kind="key", secret=SERVER_KEY), ["own-1"]),
                ("gemini", dict(provider="google", kind="key", secret=FREE_KEY), ["gem-1", "gem-2"]),
                ("spark", dict(provider="own", kind="server", address="http://127.0.0.1:11434"), ["own-1"]),
                ("codex-main", dict(provider="google", kind="key", secret=FREE_KEY), ["dev-lead"])):
            with self.subTest(account=account, fields=fields):
                code, said = self.account(account, title="T", **fields)
                self.assertEqual((code, said["error"], said["agents"]), (409, hub.ACCOUNT_WORDS["in_use"], agents))
        self.assertEqual(self.stored(), before)
        # Taken: a change of its title, its model or its address, with its secret named again.
        for account, fields in (("gemini", dict(provider="google", title="Gemini (team)", kind="key",
                                                secret=GEMINI_KEY)),
                                ("router", dict(provider="openrouter", title="OpenRouter", kind="key",
                                                secret=ROUTER_KEY, model="openrouter/kimi-k3")),
                                ("spark", dict(provider="own", title="Spark", kind="server",
                                               address="http://100.64.0.8:8000", secret=SERVER_KEY))):
            with self.subTest(account=account, taken=fields):
                code, said = self.account(account, **fields)
                self.assertEqual((code, said["changed"]), (200, True), said)
        self.assertEqual(self.stored()["accounts"]["spark"]["address"], "http://100.64.0.8:8000/v1")
        # An owner label as before: its provider changes while an agent names it.
        self.assertEqual(self.account("codex-main", provider="anthropic", title="Claude Max")[0], 200)
        # An account that no agent names changes freely, and delete stays the way to remove one.
        self.assertEqual(self.account("spare", provider="google", title="S", kind="key", secret=FREE_KEY)[0], 200)
        self.assertEqual(self.account("spare", provider="openrouter", title="S", kind="key", secret=FREE_KEY,
                                      model="openrouter/kimi-k3")[0], 200)
        self.assertEqual(self.account("spare", delete=True)[0], 200)
        code, said = self.account("gemini", delete=True)
        self.assertEqual((code, said["agents"]), (409, ["gem-1", "gem-2"]))

    def test_an_accounts_model_is_named_as_its_program_names_it(self):
        """The wave 1 review, R6: a key account's model is <the provider's name in the program>/<model>, a model
        server's own/<model>; Grok Build, one provider only, names its models with no part before them."""
        for fields, prefix in ((dict(provider="google", kind="key", secret=FREE_KEY, model="gemini-3.1-pro"), "google"),
                               (dict(provider="google", kind="key", secret=FREE_KEY, model="google/"), "google"),
                               (dict(provider="openrouter", kind="key", secret=FREE_KEY, model="qwen/qwen3.8-max"),
                                "openrouter"),
                               (dict(provider="own", kind="server", address="https://models.example.com",
                                     secret=FREE_KEY, model="qwen3.8-max"), "own")):
            with self.subTest(fields=fields):
                code, said = self.account("acc-x", title="X", **fields)
                self.assertEqual((code, said["error"]), (400, hub.ACCOUNT_WORDS["model_prefix"].format(
                    aid="acc-x", prefix=prefix)))
        for account, fields in (("acc-g", dict(provider="google", kind="key", secret=FREE_KEY,
                                               model="google/gemini-3.1-pro")),
                                ("acc-r", dict(provider="openrouter", kind="key", secret=FREE_KEY,
                                               model="openrouter/qwen/qwen3.8-max")),
                                ("acc-o", dict(provider="own", kind="server", address="https://models.example.com",
                                               secret=FREE_KEY, model="own/qwen3.8-max")),
                                ("acc-x", dict(provider="xai", kind="key", secret=FREE_KEY, model="grok-4.7"))):
            with self.subTest(taken=account):
                self.assertEqual(self.account(account, title="X", **fields)[0], 200)

    def test_an_agent_on_an_account_runs_its_program_on_a_linux_server(self):
        W = hub.ACCOUNT_WORDS
        self.assertEqual(self.refused(lambda t: t["agents"]["gem-1"].update(runtime="claude")),
                         W["runtime"].format(name="gem-1", aid="gemini", label="OpenCode"))
        self.assertEqual(self.refused(lambda t: (t["accounts"].update(
            grok={"provider": "xai", "title": "Grok", "kind": "key", "secret": FREE_KEY}),
            t["agents"]["gem-1"].update(account="grok"))), W["runtime"].format(name="gem-1", aid="grok", label="Grok"))
        self.assertEqual(self.refused(lambda t: t["agents"]["gem-1"].update(machine="mac-1")),
                         W["linux"].format(name="gem-1"))
        self.assertEqual(self.refused(lambda t: (t["addresses"].update({"box-9": "100.64.0.30"}),
                                                 t["agents"]["gem-1"].update(machine="box-9"))),
                         W["linux"].format(name="gem-1"))        # a machine that joined as no server
        self.assertEqual(self.refused(lambda t: t["accounts"]["gemini"].update(provider="acme")),
                         W["unknown"].format(name="gem-1", aid="gemini"))
        # An OpenCode agent on an owner label, as before this build: the label rule says nothing of its runtime.
        team = copy.deepcopy(TEAM)
        team["agents"]["dev-lead"]["runtime"] = "codex"
        hub.validate_team(team)

    def test_the_manager_never_gives_an_accounts_key(self):
        # 1. save_account refuses a secret that team.json resources holds, or the central vault's pool.
        team = copy.deepcopy(TEAM)
        team["resources"] = {f"secret:{FREE_KEY}": {"max": "read"}}
        hub.commit_kit_file("team.json", (json.dumps(team, indent=2) + "\n").encode(), "Owner pooled a key")
        hub.apply_team(team)
        code, said = self.account("box", provider="own", title="Box", kind="server",
                                  address="https://models.example.com", secret=FREE_KEY)
        self.assertEqual((code, said["error"]), (409, hub.ACCOUNT_WORDS["pooled"]))
        other = "bws://5b0c1d2e-0000-4000-8000-000000000006"
        team["logins"][other] = {"title": "Pooled key", "kind": "api_key", "env": "POOLED_API_KEY"}
        hub.commit_kit_file("team.json", (json.dumps(team, indent=2) + "\n").encode(), "Owner added a key")
        hub.apply_team(team)
        hub.CENTRAL["status"] = {"pool": [other]}
        code, said = self.account("box", provider="own", title="Box", kind="server",
                                  address="https://models.example.com", secret=other)
        self.assertEqual((code, said["error"]), (409, hub.ACCOUNT_WORDS["pooled"]))
        hub.CENTRAL["status"] = {"pool": []}
        self.assertEqual(self.account("box", provider="own", title="Box", kind="server",
                                      address="https://models.example.com", secret=other)[0], 200)
        # 2. validate_team refuses a resources entry for a secret that an account names.
        self.assertEqual(self.refused(lambda t: t.update(resources={f"secret:{GEMINI_KEY}": {"max": "use"}})),
                         hub.ACCOUNT_WORDS["resource"].format(rid=f"secret:{GEMINI_KEY}", aid="gemini"))
        # 3. The route of the owner's signed statements refuses a pool statement for it, before the central vault.
        def statement(kind, login):
            return dict(request_id=str(uuid.uuid4()), db="test-generation", signature="A" * 96, statement=json.dumps(
                {"v": 1, "kind": kind, "fleet": "fleet-example", "login": login, "at": 1}))
        with patch.object(hub, "central_call", side_effect=AssertionError("the vault is never asked")):
            code, said = self.request("/ui/vault/grant", statement("pool", GEMINI_KEY))
        self.assertEqual((code, said["error"]), (409, hub.ACCOUNT_WORDS["pool_statement"]))
        with patch.object(hub, "central_call", side_effect=hub.Refusal(503, "no central vault here")):
            for kind, login in (("pool", FREE_KEY.replace("0004", "0009")), ("unpool", GEMINI_KEY)):
                code, said = self.request("/ui/vault/grant", statement(kind, login))
                self.assertEqual((code, said["error"]), (503, "no central vault here"), kind)

    def test_a_write_of_the_whole_entry_keeps_nothing_of_the_one_before(self):
        self.assertEqual(self.account("box", provider="own", title="Box", kind="server",
                                      address="https://models.example.com/v1", secret=FREE_KEY,
                                      model="own/qwen3.8-max")[0], 200)
        self.assertEqual(self.stored()["accounts"]["box"]["model"], "own/qwen3.8-max")
        # Another address: the secret and the model of before stay only where the write names them again.
        self.assertEqual(self.account("box", provider="own", title="Box", kind="server",
                                      address="https://models-2.example.com", secret=FREE_KEY)[0], 200)
        self.assertEqual(self.stored()["accounts"]["box"], {"provider": "own", "title": "Box", "kind": "server",
                                                             "address": "https://models-2.example.com/v1",
                                                             "secret": FREE_KEY})
        code, said = self.account("box", provider="own", title="Box", kind="server",
                                  address="https://models-3.example.com")
        self.assertEqual((code, said["error"]), (400, hub.ACCOUNT_WORDS["open"].format(aid="box")))
        self.assertEqual(self.stored()["accounts"]["box"]["address"], "https://models-2.example.com/v1")

    def test_the_owner_moves_no_agent_into_out_of_or_between_accounts_with_a_kind(self):
        def settings(agent, **fields):
            return self.request(f"/ui/team/agents/{agent}", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                                 base_sha256=self.sha(), **fields))
        team = copy.deepcopy(TEAM)
        team["accounts"]["gemini-2"] = {"provider": "google", "title": "G2", "kind": "key", "secret": FREE_KEY}
        hub.commit_kit_file("team.json", (json.dumps(team, indent=2) + "\n").encode(), "Owner added an account")
        hub.apply_team(team)
        for agent, account in (("gem-1", "gemini-2"), ("gem-1", None), ("dev-lead", "gemini"), ("own-1", "gemini")):
            with self.subTest(agent=agent, account=account):
                code, said = settings(agent, account=account)
                self.assertEqual((code, said["error"]), (409, hub.ACCOUNT_WORDS["change"]))
        self.assertEqual(self.stored()["agents"]["gem-1"]["account"], "gemini")
        team["accounts"]["codex-team"] = {"provider": "openai", "title": "Codex Team"}       # labels: as before
        hub.commit_kit_file("team.json", (json.dumps(team, indent=2) + "\n").encode(), "Owner added a label")
        hub.apply_team(team)
        code, said = settings("dev-lead", account="codex-team")
        self.assertEqual(code, 200, said)
        self.assertEqual(hub.agents()["dev-lead"]["account"], "codex-team")

    # ---- the setup check's account item (spec 3.8)
    def test_a_status_report_with_the_account_item_is_taken_and_keeps_only_fixed_words(self):
        item = lambda detail: {"kind": "account", "ref": "spark", "state": "failed", "detail": detail}
        for detail, kept in (("", ""), (lifecycle.NO_ANSWER, lifecycle.NO_ANSWER),
                             (lifecycle.SMALL_CONTEXT, lifecycle.SMALL_CONTEXT), (lifecycle.KEY_REFUSED,
                                                                                  lifecycle.KEY_REFUSED),
                             ("own/qwen3.8-max", "own/qwen3.8-max"), ("own/", ""), ("own/bad name", ""),
                             ("<html>Welcome to nginx</html>", ""), ("qwen3.8-max", ""), (None, "")):
            with self.subTest(detail=detail):
                report = hub.validate_status({"verify": [item(detail), {"kind": "runtime", "ref": "opencode",
                                                                         "state": "ok", "detail": "2.2.5"}]})
                self.assertEqual(report["verify"][0], item(kept))
        self.assertTrue(hub.item_required("gem-1", item("")))

    def test_an_agent_with_a_key_account_activates_with_no_sign_in_and_not_without_its_account_item(self):
        def check(items):
            cid = hub.ins("INSERT INTO machine_checks(agent,requested,state) VALUES(?,?,'requested')",
                          ("gem-1", hub.now()))
            merged = hub.verify_merge("gem-1", items, {})
            hub.q("UPDATE machine_checks SET state='completed', completed=?, verify=?, revision=? WHERE id=?",
                  (hub.now(), json.dumps(merged), hub.kit_revision(fresh=True), cid))
            return merged
        rows = (None, [{"agent": "gem-1", "stale": False, "update": {"state": "current"}}])
        runtime = [{"kind": "runtime", "ref": "opencode", "state": "ok", "detail": "2.2.5"},     # no sign-in to read
                   {"kind": "login", "ref": GEMINI_KEY, "state": "ok", "detail": "ok"}]          # its read grant
        with patch.object(hub, "machine_rows", lambda: rows), patch.object(hub, "settings_pending", lambda a: False):
            merged = check(runtime)
            self.assertIn({"kind": "account", "ref": "gemini", "state": "failed", "detail": ""}, merged)
            missing, _ = hub.activation_missing("gem-1")
            self.assertEqual([(m["kind"], m["ref"]) for m in missing], [("account", "gemini")])
            check(runtime + [{"kind": "account", "ref": "gemini", "state": "failed",
                              "detail": lifecycle.KEY_REFUSED}])
            self.assertEqual([(m["kind"], m["detail"]) for m in hub.activation_missing("gem-1")[0]],
                             [("account", lifecycle.KEY_REFUSED)])
            merged = check(runtime + [{"kind": "account", "ref": "gemini", "state": "ok", "detail": ""}])
            self.assertEqual([i for i in merged if i["kind"] == "account"],
                             [{"kind": "account", "ref": "gemini", "state": "ok", "detail": ""}])
            self.assertEqual(hub.activation_missing("gem-1")[0], [])
        # An agent of today's shape gets no account item from the hub.
        self.assertFalse([i for i in hub.verify_merge("dev-lead", [], {}) if i["kind"] == "account"])

    # ---- the group of an account with a kind (spec 3.1)
    def test_a_hold_of_one_agent_of_an_account_holds_the_other_and_never_the_manager(self):
        self.assertEqual((hub.model_group("gem-1"), hub.model_group("own-1"), hub.model_group("dev-lead")),
                         ("account:gemini", "account:spark", None))
        groups = hub.account_groups()
        self.assertEqual(groups["account:gemini"]["agents"], ["gem-1", "gem-2"])
        self.assertEqual(groups["account:spark"]["agents"], ["own-1"])             # a model server is a group too
        self.assertEqual(groups["account:gemini"]["state"], {"state": "available", "reason": "Paid per use.",
                                                             "until": None, "retry_at": None})
        self.assertEqual(groups["account:spark"]["state"]["reason"], "Local model.")
        self.assertEqual(hub.account_group("gem-1")["sharers"], ["gem-2"])
        team = copy.deepcopy(TEAM)
        team["agents"]["manager"]["account"] = "gemini"     # an owner's label on the manager, by hand: never held
        hub.TEAM = team
        hub.start_limit("gem-1", hub.now() + 600)
        self.assertIsNotNone(hub.active_limit("gem-1"))
        held = hub.active_limit("gem-2")
        self.assertIsNotNone(held)
        self.assertEqual(held["cause"], hub.active_limit("gem-1")["id"])
        self.assertIsNone(hub.active_limit("manager"))
        self.assertIsNone(hub.active_limit("own-1"))
        self.assertEqual(hub.account_groups()["account:gemini"]["state"]["state"], "limited")

    def test_the_capacity_view_puts_both_agents_in_one_group_with_no_window(self):
        helper_reports("gem-1", "acp_tasks", "model_accounts", limits=None)
        view = hub.capacity_view()
        group = next(g for g in view["accounts"] if g["group"] == "account:gemini")
        self.assertEqual((group["provider"], group["label"], group["windows"], group["mismatch"], group["state"],
                          group["reason"]), ("google", "gemini", [], None, "available", "Paid per use."))
        self.assertEqual([r["agent"] for r in group["routes"]], ["gem-1", "gem-2"])
        spark = next(g for g in view["accounts"] if g["group"] == "account:spark")
        self.assertEqual((spark["provider"], spark["state"], spark["reason"]), ("own", "available", "Local model."))
        routes = {a["agent"]: a["routes"][0] for a in view["agents"]}
        self.assertEqual((routes["gem-1"]["group"], routes["gem-2"]["group"]), ("account:gemini", "account:gemini"))

    def test_a_model_server_is_a_local_model_for_each_caller(self):
        self.assertTrue(hub.local_model(hub.agents()["own-1"], hub.TEAM.get("accounts")))
        self.assertFalse(hub.local_model(hub.agents()["gem-1"], hub.TEAM.get("accounts")))
        agents = {a["name"]: a for a in self.request()[1]["agents"]}
        self.assertEqual((agents["own-1"]["local_model"], agents["own-1"]["signed_in"]), (True, None))
        self.assertFalse(agents["gem-1"]["local_model"])
        self.assertEqual(hub.allowance_start_text("own-1", None), "")

    # ---- costs (spec 3.7)
    def test_a_session_on_its_own_server_costs_nothing_and_one_on_a_priced_model_its_price(self):
        def report(agent, session, model):
            hub.record_session_tokens(agent, [{"session_id": session, "total": 1_000_000 + 200_000,
                                               "last_activity": hub.now(), "input": 1_000_000, "cache_read": 0,
                                               "cache_write": 0, "output": 200_000, "calls": 4, "model": model,
                                               "first_cache_share": 0.0}], runtime="opencode")
            return hub.q1("SELECT * FROM session_tokens WHERE agent=? AND session_id=?", (agent, session))
        own = report("own-1", "s-own", "own/qwen3.8-max")
        priced = report("gem-1", "s-gem", "google/gemini-3.1-pro")
        self.assertEqual((own["account"], priced["account"]), ("account:spark", "account:gemini"))
        book = hub.price_book()
        self.assertEqual(hub.session_cost(own, book), 0)
        price = lifecycle.token_price(book["opencode"], "google/gemini-3.1-pro")
        self.assertGreater(price["input"], 0)
        self.assertAlmostEqual(hub.session_cost(priced, book), price["input"] + price["output"] * 0.2)

    # ---- the task start of an ACP program (spec 3.5.1)
    def test_a_task_of_an_acp_program_starts_with_its_rules_first_on_a_helper_with_acp_tasks(self):
        helper_reports("gem-1", "acp_tasks", "model_accounts")
        helper_reports("gem-2", "model_accounts")
        helper_reports("dev-lead", "stable_start")
        first, second, claude = self.task("gem-1"), self.task("gem-2"), self.task("dev-lead")
        event = self.start_event(first)
        self.assertEqual((event["extra"]["opening"], event["extra"]["rules"]), ("system", hub.rules_parts("gem-1")))
        self.assertNotIn("Read RULES.md", event["text"])
        self.assertNotIn("opening", self.start_event(second)["extra"])          # an older helper: as before
        self.assertIn("RULES.md", self.start_event(second)["text"])
        self.assertEqual(self.start_event(claude)["extra"]["opening"], "read")   # Claude: as before
        self.assertEqual(hub.stable_opening("dev-lead", "none"), "read")
        # Its start event stays unread at the session's first call, so the helper's first signal still comes
        # (OpenCode's first prompt waits for it), and the first read gives START_READ, not the start again.
        hub.task_started(hub.q1("SELECT * FROM tasks WHERE id=?", (first,)))
        self.assertIsNone(self.start_event(first)["read_at"])
        said, error = hub.call_tool("gem-1", "read_messages", {"task_id": hub.tref(first)},
                                    ("test-generation", hub.tref(first), 1))
        self.assertFalse(error, said)
        self.assertIn(hub.START_READ, said)
        # A conversation with tools never reaches it: no ACP runtime has an owner chat, and each such agent is
        # refused a conversation.
        self.assertFalse(lifecycle.runtime_fact("opencode", "owner_chat"))

    # ---- the pause of a failed turn (spec 3.11 item 7)
    def test_a_failed_turn_of_an_acp_session_pauses_its_task_one_time_and_a_limit_pauses_none(self):
        tid = self.task("gem-1")
        hub.q("UPDATE tasks SET state='working', started=? WHERE id=?", (hub.now(), tid))
        session = str(uuid.uuid4())

        def records(*events):
            code, said = self.request(f"/helper/events/gem-1", dict(generation="test-generation", task=hub.tref(tid),
                                                                    attempt=1, session=session, events=list(events)))
            self.assertEqual(code, 200, said)
        limit = {"seq": 1, "ts": time.time(), "type": "error", "code": "usage_limit", "message": "Rate limited",
                 "retryable": True, "resets_at": time.time() + 600}
        records(limit, {"seq": 2, "ts": time.time(), "type": "result", "stop_reason": "error"})
        self.assertEqual(hub.q("SELECT * FROM holds WHERE task=?", (tid,)), [])
        self.assertIsNotNone(hub.active_limit("gem-1"))
        hub.q("UPDATE agent_limits SET ended=?", (hub.now(),))
        refused = {"seq": 3, "ts": time.time(), "type": "error", "code": "refused", "message": "The key was refused.",
                   "retryable": False, "resets_at": None}
        records(refused, {"seq": 4, "ts": time.time(), "type": "result", "stop_reason": "error"})
        (hold,) = hub.q("SELECT * FROM holds WHERE task=?", (tid,))
        self.assertEqual((hold["kind"], hold["by"]), ("pause", "manager"))
        told = [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say'")
                if "paused" in r["text"]]
        self.assertEqual(len(told), 1)
        self.assertIn("The error: The key was refused.", told[0])
        records({"seq": 5, "ts": time.time(), "type": "error", "code": "no_credit", "message": "No credit.",
                 "retryable": False, "resets_at": None}, {"seq": 6, "ts": time.time(), "type": "result",
                                                          "stop_reason": "error"})
        self.assertEqual(len(hub.q("SELECT * FROM holds WHERE task=?", (tid,))), 1)

    # ---- the model of an ACP agent (spec 5.2 items 7 and 9)
    def test_the_owner_sets_a_model_and_an_effort_of_an_acp_agent_against_its_own_reading(self):
        helper_reports("gem-1", "acp_tasks", "model_accounts",
                       models=models("opencode", "google/gemini-3.1-pro", "google/gemini-3.5-flash"))
        def settings(**fields):
            return self.request("/ui/team/agents/gem-1", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                              base_sha256=self.sha(), **fields))
        code, said = settings(model="google/gemini-3.5-flash", effort="low")
        self.assertEqual(code, 200, said)
        self.assertEqual({k: self.stored()["agents"]["gem-1"].get(k) for k in ("model", "effort")},
                         {"model": "google/gemini-3.5-flash", "effort": "low"})
        self.assertEqual(settings(model="google/gemini-9")[0], 409)            # not in its own reading
        # OpenCode lists the efforts of its current model only (plan risk 3): another model and an effort of it
        # cannot be set in one write.
        reading = models("opencode", "google/gemini-3.5-flash", "google/gemini-3.1-pro")
        reading["options"][1]["efforts"] = []
        helper_reports("gem-1", "acp_tasks", "model_accounts", models=reading)
        code, said = settings(model="google/gemini-3.1-pro", effort="high")
        self.assertEqual(code, 409)
        self.assertIn("high is not an effort of google/gemini-3.1-pro", said["error"])
        self.assertEqual(settings(model="google/gemini-3.1-pro", effort=None)[0], 200)
        # Settings › General gets no row of an ACP program: its readings have no model flags.
        self.assertEqual([r for r, _ in hub.model_readings()], [])
        self.assertNotIn("opencode", hub.model_choices())

    def test_the_manager_changes_only_the_effort_of_an_agent_at_a_seller_of_several_makers(self):
        helper_reports("seller-1", "acp_tasks", "model_accounts",
                       models=models("opencode", "openrouter/qwen3.8-max", "openrouter/kimi-k3"))
        said, error = hub.call_tool("manager", "set_agent_model", {"agent": "seller-1", "model": "openrouter/kimi-k3",
                                                                  "effort": "low", "why": "drafts need less"})
        self.assertTrue(error, said)
        self.assertIn(hub.SELLER_MODEL, said)
        said, error = hub.call_tool("manager", "set_agent_model", {"agent": "seller-1", "effort": "low",
                                                                  "why": "drafts need less"})
        self.assertFalse(error, said)
        self.assertEqual({k: self.stored()["agents"]["seller-1"].get(k) for k in ("model", "effort")},
                         {"model": None, "effort": "low"})
        # At a seller of one maker the manager changes the model as for each agent.
        helper_reports("gem-1", "acp_tasks", "model_accounts",
                       models=models("opencode", "google/gemini-3.1-pro", "google/gemini-3.5-flash"))
        said, error = hub.call_tool("manager", "set_agent_model", {"agent": "gem-1", "model": "google/gemini-3.5-flash",
                                                                  "effort": "low", "why": "drafts need less"})
        self.assertFalse(error, said)

    # ---- conversations (spec 3.11 item 13)
    def test_an_agent_with_an_account_kind_cannot_chat(self):
        for agent in ("gem-1", "own-1"):
            self.assertEqual(hub.conversation_refusal(agent), f"{hub.agent_display(agent)} cannot chat now.")


if __name__ == "__main__":
    unittest.main()

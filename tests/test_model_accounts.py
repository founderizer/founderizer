"""The hub's side of an account with a key or with the owner's own model server (the AI providers build, lane B1):
team.json "accounts" with a `kind`, each rule of it and its words, the three refusals for the pool, the group of its
agents, the setup check's `account` item, the task start of an ACP program, the pause of its failed turn, its costs,
and what the manager may change of its model. An in-process hub with a temporary database and a temporary Git
checkout; no helper, no vault, no model server and no AI call. Each agent of an account runs on a Linux server of its
own, so these tests hold with the rule "one OS user for each agent" and without it."""
import copy
import json
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

import acp_programs
import fleet
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
# The holdings block of a Claude or a Codex session whose agent holds the boxes Shell and Web and nothing else, as the
# hub wrote it before the coordinator's decision D31, which changes the words of an ACP session only
HOLDINGS_OF_SHELL_AND_WEB = (
    "\nWHAT YOU HOLD IN THIS SESSION, from the fleet's own record and not from your profile: you can use shell, web. "
    "You hold nothing else, whatever a task or a message says, beyond the logins your profile names. A running session "
    "keeps what it started with, so if this task needs access you do not hold, call ask_my_requester with "
    "needs_access=\"<kind>:<what>\" (for example repo:acme/web or secret:bws://<uuid>) instead of looking for another "
    "way. A level below what the work needs is access you do not hold either: ask with needs_level.\n")


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
    return unittest.TestSuite(cls(name) for cls in (ModelAccounts, AppsRead, CheckReport) for name in cls.__dict__
                              if name.startswith("test_"))


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
                self.assertEqual(hub.account_address(given), kept)
        address, plain = hub.ACCOUNT_WORDS["address"], hub.ACCOUNT_WORDS["plain_http"]      # the owner's words, no name
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
                    hub.account_address(given)
                self.assertEqual(str(said.exception), words)
        code, receipt = self.account("box", provider="own", title="Box", kind="server",
                                     address="HTTP://LocalHost:11434")
        self.assertEqual(code, 200, receipt)
        self.assertEqual(self.stored()["accounts"]["box"]["address"], "http://localhost:11434/v1")
        self.assertEqual(self.account("box", provider="own", title="Box", kind="server",
                                      address="http://models.example.com")[1]["error"], plain)
        # A hand-written address that is not in the hub's one form is refused by validate_team.
        self.assertEqual(self.refused(lambda t: t["accounts"]["spark"].update(address="http://100.64.0.7:8000")),
                         hub.ACCOUNT_WORDS["address"])

    def test_a_model_server_with_no_key_is_one_agents_alone_on_its_server_on_the_loopback(self):
        def open_spark(address):
            def change(team):
                team["accounts"]["spark"] = {"provider": "own", "title": "Spark", "kind": "server", "address": address}
                team["agents"]["own-1"].pop("secrets")
            return change
        words = hub.ACCOUNT_WORDS["open_address"].format(aid="spark")
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
            hub.ACCOUNT_WORDS["open"].format(server="app-3"))                            # its server has two agents
        # The route takes an open loopback server that no agent names.
        self.assertEqual(self.account("local", provider="own", title="Local", kind="server",
                                      address="http://127.0.0.1:1234")[0], 200)
        self.assertEqual(self.account("local", provider="own", title="Local", kind="server",
                                      address="https://models.example.com")[1]["error"],
                         hub.ACCOUNT_WORDS["open_address"].format(aid="local"))

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
        self.assertEqual((code, said["error"], said.get("code")), (400, hub.ACCOUNT_WORDS["open"].format(
            server="app-3"), "open"))       # with B2 its code too (open_server_refusal)
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
        self.assertEqual(str(said.exception), hub.ACCOUNT_WORDS["open_address"].format(aid="spark"))
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
                self.assertEqual((code, said["error"], said["code"], said["names"]), (
                    400, hub.ACCOUNT_WORDS["model_prefix"].format(prefix=prefix, model=fields["model"]),
                    "model_prefix", {"prefix": prefix, "model": fields["model"]}))
        for account, fields in (("acc-g", dict(provider="google", kind="key", secret=FREE_KEY,
                                               model="google/gemini-3.1-pro")),
                                ("acc-r", dict(provider="openrouter", kind="key", secret=FREE_KEY,
                                               model="openrouter/qwen/qwen3.8-max")),
                                ("acc-o", dict(provider="own", kind="server", address="https://models.example.com",
                                               secret=FREE_KEY, model="own/qwen3.8-max")),
                                ("acc-x", dict(provider="xai", kind="key", secret=FREE_KEY, model="grok-4.7"))):
            with self.subTest(taken=account):
                self.assertEqual(self.account(account, title="X", **fields)[0], 200)

    def test_the_owners_words_fill_with_the_cases_names_and_each_refusal_gives_its_code(self):
        """The coordinator's decision D7: the hub holds the owner's approved words of round 2 (14 November 2026,
        ai-providers-step-5-answers.md, "The approved words, as templates"), filled with the case's names and never
        an account's id, and each refusal's answer adds `code` and `names`."""
        W = hub.ACCOUNT_WORDS
        self.assertEqual({k: W[k] for k in hub.APPROVED_WORDS if not re.search(r"{\w+}", W[k])}, {
            "plain_http": "Plain http works only over Tailscale or on the agent's own server. Use that machine's "
                          "Tailscale address, or https.",
            "address": "Write the address as http:// or https://, then the host, and a port and a path if it has them.",
            "pooled": "The fleet manager may give this key. Set it to You alone in Settings \u203a Secrets, then save "
                      "again.",
            "kind_kept": "This account runs on a key or a model server, and this change would drop that. To remove the "
                         "account, delete it.",
            "in_use": "Agents use this account, so its AI and its key stay as they are. For a new key, save it in "
                      "Settings \u203a Secrets under the same name.",
            "placement": "Founderizer no longer has this key or address. Start again from Add agent."})
        self.assertEqual(W["open"].format(server="app-1"), "app-1 has an agent on a model server with no key, so it "
                                                           "takes no other agent. Choose another server.")
        self.assertEqual(W["change"].format(agent="Iris", provider="Gemini"),
                         "Iris stays on Gemini. For another AI, add a new agent.")
        self.assertEqual(W["change_server"].format(agent="Iris"),
                         "Iris stays on its model server. For another AI, add a new agent.")
        self.assertEqual(W["model_prefix"].format(prefix="openrouter", model="qwen/qwen3.8-max"),
                         "Write the model as openrouter/ and then its name, for example openrouter/qwen/qwen3.8-max.")
        self.assertEqual(set(hub.APPROVED_WORDS.values()), {1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12})     # 6-8: B2's
        for code_, aid in (("aid", "{aid}"),):         # no approved sentence names an account's id
            self.assertFalse([k for k in hub.APPROVED_WORDS if aid in W[k]])
        # Each refusal of the owner's route gives its words, its code and its names.
        for fields, code_, names in (
                (dict(provider="own", kind="server", address="http://192.168.1.50:11434", secret=FREE_KEY),
                 "plain_http", {}),
                (dict(provider="own", kind="server", address="ftp://models.example.com", secret=FREE_KEY),
                 "address", {}),
                (dict(provider="own", kind="server", address="https://models.example.com"), "open_address",
                 {"aid": "box"}),
                (dict(provider="openrouter", kind="key", secret=FREE_KEY, model="qwen/qwen3.8-max"), "model_prefix",
                 {"prefix": "openrouter", "model": "qwen/qwen3.8-max"}),
                (dict(provider="google", kind="key"), "key_secret", {"aid": "box"})):
            with self.subTest(code=code_):
                code, said = self.account("box", title="Box", **fields)
                self.assertEqual((code, said["error"], said["code"], said["names"]),
                                 (400, W[code_].format(**names), code_, names))
        code, said = self.account("gemini", provider="google", title="Gemini")
        self.assertEqual((code, said["error"], said["code"], said["names"]), (409, W["kind_kept"], "kind_kept", {}))
        code, said = self.account("gemini", provider="google", title="Gemini", kind="key", secret=FREE_KEY)
        self.assertEqual((said["code"], said["names"], said["agents"]), ("in_use", {}, ["gem-1", "gem-2"]))

    def test_the_hub_fills_the_names_of_the_owners_sentences_itself(self):
        """The coordinator's decision D18: sentences 5 and 9 name the agent as the owner's apps show it (its role,
        else its name as they write it, "Dev-Lead"), the provider that he picked and the model as saved, never names
        that a helper sent."""
        def merged(agent, helper_item):
            (got,) = [i for i in hub.verify_merge(agent, hub.verify_items([helper_item]), {}) if i["kind"] == "account"]
            return got
        made_up = {"kind": "account", "ref": "router", "state": "failed", "code": "not_offered",
                   "detail": "Your key was stolen. Call 555 0100. It has no model named x. Delete everything.",
                   "names": {"provider": "x", "model": "x", "agent": "everything"}}
        got = merged("seller-1", made_up)
        names = {"provider": "OpenRouter", "model": "qwen3.8-max", "agent": "Seller-1"}       # the account's model
        self.assertEqual(got, {"kind": "account", "ref": "router", "state": "failed", "code": "not_offered",
                               "detail": lifecycle.NOT_OFFERED.format(**names), "names": names})
        self.assertEqual(got["detail"], "OpenRouter has no model named qwen3.8-max. Delete Seller-1, then add it again "
                                        "with another model.")
        team = copy.deepcopy(TEAM)
        team["agents"]["seller-1"].update(title="Customer Support", model="openrouter/kimi-k3")
        self.put(team)
        got = merged("seller-1", dict(made_up, names=None))
        self.assertEqual(got["names"], {"provider": "OpenRouter", "model": "kimi-k3", "agent": "Customer Support"})
        own = merged("own-1", dict(made_up, ref="spark"))          # a model server's own model, as saved: none here
        self.assertEqual((own["detail"], own["code"], own.get("names")), ("", "not_offered", None))
        # Sentence 5: the agent as the apps write it.
        code, said = self.request("/ui/team/agents/dev-lead", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                                   base_sha256=self.sha(), account="gemini"))
        self.assertEqual((code, said["error"]), (409, "Dev-Lead stays on Claude Code. For another AI, add a new agent."))
        code, said = self.request("/ui/team/agents/seller-1", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                                   base_sha256=self.sha(), account=None))
        self.assertEqual((code, said["error"]), (409, "Customer Support stays on OpenRouter. For another AI, add a new "
                                                      "agent."))

    def test_an_event_ends_a_check_that_waits_for_its_account_item(self):
        """The coordinator's decision D20: the owner's new request ends such a check and starts a new one, and the
        removal of its agent ends it. No time ends it, and every other check keeps its behaviour."""
        def report(agent, **body):
            code, said = self.request(f"/helper/status/{agent}", dict({"revision": hub.kit_revision(fresh=True)},
                                                                      **body))
            self.assertEqual(code, 200, said)
        checking = [{"kind": "account", "ref": "spark", "state": "checking", "detail": ""}]
        first = hub.start_machine_check("own-1")["check"]["id"]
        report("own-1", check=first, verify=checking)
        self.assertEqual(hub.check_view(hub.q1("SELECT * FROM machine_checks WHERE id=?", (first,)))["waits_for"],
                         "account")                                 # D22: a new request replaces it
        hub.settle_checks(hub.now() + 30 * 86400)                   # no time ends it
        self.assertEqual(hub.q1("SELECT state FROM machine_checks WHERE id=?", (first,))["state"], "requested")
        again = hub.start_machine_check("own-1")
        self.assertTrue(again["changed"])
        self.assertNotEqual(again["check"]["id"], first)
        old = hub.q1("SELECT * FROM machine_checks WHERE id=?", (first,))
        self.assertEqual((old["state"], old["detail"]), ("failed", hub.CHECK_REPLACED))
        self.assertIsNone(hub.kv_get(hub.CHECK_RUNNING + str(first)))
        # The old check's report, if it still comes, changes nothing.
        report("own-1", check=first, verify=[dict(checking[0], state="ok", detail="own/qwen3.8-max")])
        self.assertEqual(hub.q1("SELECT state FROM machine_checks WHERE id=?", (first,))["state"], "failed")
        # A check that waits for no account item: the same check back, as before.
        plain = hub.start_machine_check("gem-1")["check"]["id"]
        self.assertEqual((hub.start_machine_check("gem-1")["check"]["id"],
                          hub.start_machine_check("gem-1")["changed"]), (plain, False))
        # The removal of its agent takes its checks (hub.REMOVED_OWN), and the mark goes with them.
        second = again["check"]["id"]
        report("own-1", check=second, verify=checking)
        self.assertEqual(hub.kv_get(hub.CHECK_RUNNING + str(second)), "own-1")
        hub.q("DELETE FROM machine_checks WHERE agent='own-1'")    # as remove_rows deletes an agent's own rows
        hub.settle_checks(hub.now())
        self.assertIsNone(hub.kv_get(hub.CHECK_RUNNING + str(second)))
        self.assertIn(("machine_checks", "agent"), hub.REMOVED_OWN)

    def test_the_hub_asks_for_a_check_itself_when_what_the_check_proved_changes(self):
        """The coordinator's decision D21: a change of the agent's model, or of its account's model or address, asks
        for a machine check under the hood. It replaces an open check, it goes out at the helper's report that holds
        the new settings, and no check's own result asks for one."""
        def checks(agent):
            return [dict(r) for r in hub.q("SELECT id, state, detail FROM machine_checks WHERE agent=? ORDER BY id",
                                           (agent,))]

        def sent(agent):
            return [json.loads(r["extra"])["check"] for r in hub.q(
                "SELECT extra FROM events WHERE agent=? AND kind='check' ORDER BY id", (agent,))]

        def report(agent, revision, **body):
            code, said = self.request(f"/helper/status/{agent}", dict({"revision": revision}, **body))
            self.assertEqual(code, 200, said)
        helper_reports("gem-1", "acp_tasks", "model_accounts",
                       models=models("opencode", "google/gemini-3.1-pro", "google/gemini-3.5-flash"))
        before = hub.kit_revision(fresh=True)
        open_check = hub.start_machine_check("gem-1")["check"]["id"]        # one that the owner asked, sent
        code, said = self.request("/ui/team/agents/gem-1", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                                base_sha256=self.sha(), model="google/gemini-3.5-flash"))
        self.assertEqual(code, 200, said)
        (replaced, due) = checks("gem-1")
        self.assertEqual((replaced["id"], replaced["state"], replaced["detail"]),
                         (open_check, "failed", hub.CHECK_REPLACED))
        self.assertEqual((due["state"], sent("gem-1")), ("requested", [open_check]))     # not sent yet
        self.assertEqual(hub.check_view(hub.q1("SELECT * FROM machine_checks WHERE id=?", (due["id"],)))["waits_for"],
                         "settings")
        hub.settle_checks(hub.now() + hub.CHECK_WAIT + 600)                 # no time ends its wait
        self.assertEqual(checks("gem-1")[-1]["state"], "requested")
        report("gem-1", before)                                             # the helper has not loaded it yet
        self.assertEqual(sent("gem-1"), [open_check])
        after = hub.kit_revision(fresh=True)
        report("gem-1", after)                                              # now it has: the check goes out
        self.assertEqual(sent("gem-1"), [open_check, due["id"]])
        self.assertIsNone(hub.check_view(hub.q1("SELECT * FROM machine_checks WHERE id=?", (due["id"],)))["waits_for"])
        report("gem-1", after, check=due["id"], verify=[{"kind": "account", "ref": "gemini", "state": "ok",
                                                         "detail": ""}])
        self.assertEqual(checks("gem-1")[-1]["state"], "completed")
        report("gem-1", after)
        self.assertEqual(len(checks("gem-1")), 2)                           # its result asks for no other check
        # The account's model or address: each of its agents; its title alone: none.
        self.assertEqual(self.account("router", provider="openrouter", title="OpenRouter", kind="key",
                                      secret=ROUTER_KEY, model="openrouter/kimi-k3")[0], 200)
        self.assertEqual([c["state"] for c in checks("seller-1")], ["requested"])
        self.assertEqual(self.account("spark", provider="own", title="Spark", kind="server",
                                      address="http://100.64.0.8:8000", secret=SERVER_KEY)[0], 200)
        self.assertEqual([c["state"] for c in checks("own-1")], ["requested"])
        self.assertEqual(self.account("spark", provider="own", title="Spark (box)", kind="server",
                                      address="http://100.64.0.8:8000/v1", secret=SERVER_KEY)[0], 200)
        self.assertEqual(len(checks("own-1")), 1)
        # The manager's tool: a new model asks for one, an effort alone does not.
        helper_reports("gem-2", "acp_tasks", "model_accounts",
                       models=models("opencode", "google/gemini-3.1-pro", "google/gemini-3.5-flash"))
        said, error = hub.call_tool("manager", "set_agent_model", {"agent": "gem-2", "effort": "low", "why": "drafts"})
        self.assertFalse(error, said)
        self.assertEqual(checks("gem-2"), [])
        said, error = hub.call_tool("manager", "set_agent_model", {"agent": "gem-2", "model": "google/gemini-3.5-flash",
                                                                  "effort": "low", "why": "drafts"})
        self.assertFalse(error, said)
        self.assertEqual([c["state"] for c in checks("gem-2")], ["requested"])
        # An agent of today's shape: no check of the hub's own.
        hub.save_agent_settings("dev-lead", {"base_sha256": self.sha(), "title": "Developer"})
        self.assertEqual(checks("dev-lead"), [])

    def test_a_check_that_ends_by_time_leaves_no_probe_job_open(self):
        """The coordinator's decision D23 (the fifth review, X1, live since release 2026.11.477): a check that
        settle_checks ends ("has been silent", "sent no report in 60 seconds") ends its own probe job, also for an
        agent of today's shape with a key. Before, its job stayed open until the hub started again, and "Use another
        account" and the runtime switch were refused for that agent."""
        team = copy.deepcopy(TEAM)
        team["agents"]["dev-lead"]["secrets"] = {FREE_KEY: "read"}
        self.put(team)

        def open_jobs():
            return [r["id"] for r in hub.q("SELECT id FROM jobs WHERE agent='dev-lead' AND kind='probe' AND "
                                           "finished IS NULL")]
        for touched in (False, True):        # offline, then failed: the helper checks in after the request
            with self.subTest(touched=touched):
                cid = hub.start_machine_check("dev-lead")["check"]["id"]
                self.assertEqual(len(open_jobs()), 1)
                if touched:
                    hub.touch("dev-lead")
                hub.settle_checks(hub.now() + hub.CHECK_WAIT + 1)
                row = hub.q1("SELECT state FROM machine_checks WHERE id=?", (cid,))
                self.assertEqual(row["state"], "failed" if touched else "offline")
                self.assertEqual(open_jobs(), [])
                self.assertIsNone(hub.switch_busy("dev-lead"))
                code, said = self.request("/helper/status/dev-lead", {"revision": hub.kit_revision(fresh=True),
                                                                       "check": cid, "verify": []})
                self.assertEqual(code, 200, said)       # its late report: no job opens or stays open
                self.assertEqual(open_jobs(), [])

    def test_a_check_that_replaces_one_that_waits_for_the_settings_keeps_that_wait(self):
        """The coordinator's decision D26 (the fifth review, X4): the owner's request while the hub's own check waits
        for the helper's new settings ends that check, and the new one keeps the wait: it never runs on the old
        model."""
        helper_reports("gem-1", "acp_tasks", "model_accounts",
                       models=models("opencode", "google/gemini-3.1-pro", "google/gemini-3.5-flash"))
        code, said = self.request("/ui/team/agents/gem-1", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                                base_sha256=self.sha(), model="google/gemini-3.5-flash"))
        self.assertEqual(code, 200, said)
        (due,) = hub.q("SELECT id FROM machine_checks WHERE agent='gem-1'")
        asked = hub.start_machine_check("gem-1")            # the owner's request, through his own agent's tool
        self.assertTrue(asked["changed"])
        self.assertEqual((asked["check"]["waits_for"], hub.q1("SELECT state, detail FROM machine_checks WHERE id=?",
                                                              (due["id"],))["detail"]), ("settings", hub.CHECK_REPLACED))
        self.assertEqual(hub.q("SELECT * FROM events WHERE agent='gem-1' AND kind='check'"), [])     # nothing sent

    def test_a_start_refused_for_no_checked_model_asks_for_a_check_and_tells_only_after_one_failed(self):
        """The coordinator's decision D24 (the fifth review, X2, X6): the helper's word that a start on a model
        server has no kept result of its model asks for one check when none is open, and the requester hears of it
        only when no check was open and the last one failed. Other causes, and other agents, are told as before."""
        self.assertEqual(hub.NO_CHECKED_MODEL, fleet.NO_CHECKED_MODEL)

        def refused(agent, why=hub.NO_CHECKED_MODEL):
            tid = self.task(agent)
            code, said = self.request(f"/helper/dialog/{agent}/{hub.tref(tid)}", {"kind": "start_failed",
                                                                                 "reason": why})
            self.assertEqual(code, 200, said)
            return tid

        def told(tid):
            return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say' AND task=?",
                                             (tid,)) if "cannot start" in r["text"]]

        def checks():
            return [(r["id"], r["state"]) for r in hub.q("SELECT id, state FROM machine_checks WHERE agent='own-1' "
                                                         "ORDER BY id")]

        def report(**body):
            code, said = self.request("/helper/status/own-1", dict({"revision": hub.kit_revision(fresh=True)}, **body))
            self.assertEqual(code, 200, said)
        ok = [{"kind": "account", "ref": "spark", "state": "ok", "detail": "own/qwen3.8-max"}]
        first = hub.start_machine_check("own-1")["check"]["id"]
        report(check=first, verify=ok)                                       # the last check passed
        tid = refused("own-1")
        self.assertEqual(told(tid), [])                                     # the check decides
        self.assertEqual(checks(), [(first, "completed"), (first + 1, "requested")])
        tid = refused("own-1")                                              # while that check is open
        self.assertEqual((told(tid), len(checks())), ([], 2))
        report(check=first + 1, verify=[{"kind": "account", "ref": "spark", "state": "failed",
                                         "detail": lifecycle.NO_ANSWER, "code": "no_answer"}])
        tid = refused("own-1")                                              # no check open, the last one failed
        self.assertEqual(len(told(tid)), 1)
        self.assertEqual(checks()[-1][1], "requested")                      # and one more check is asked
        # Another cause, and an agent of today's shape: told as before, and no check.
        self.assertEqual(len(told(refused("own-1", "the vault gave no key for this agent's account"))), 1)
        self.assertEqual(len(told(refused("dev-lead"))), 1)
        self.assertEqual(hub.q("SELECT * FROM machine_checks WHERE agent='dev-lead'"), [])

    def test_the_agents_of_one_model_server_are_checked_one_after_the_other(self):
        """The coordinator's decision D27, as lane S3 measured it (15 November 2026: four checks at once of one
        llama.cpp server all failed its context step, and each passes alone): a check of an agent waits while a check
        of another agent of the same model server is out, and goes out at its helper's report after that one ended.
        A key account's checks are not held."""
        team = copy.deepcopy(TEAM)
        team["agents"]["own-2"] = dict(OPENCODE, machine="app-6", account="spark", secrets={SERVER_KEY: "read"})
        self.put(team)

        def report(agent, **body):
            code, said = self.request(f"/helper/status/{agent}", dict({"revision": hub.kit_revision(fresh=True)},
                                                                      **body))
            self.assertEqual(code, 200, said)

        def sent(agent):
            return [json.loads(r["extra"])["check"] for r in hub.q(
                "SELECT extra FROM events WHERE agent=? AND kind='check' ORDER BY id", (agent,))]
        first = hub.start_machine_check("own-1")["check"]
        second = hub.start_machine_check("own-2")["check"]
        self.assertEqual((first["waits_for"], second["waits_for"]), (None, "turn"))
        self.assertEqual((sent("own-1"), sent("own-2")), ([first["id"]], []))
        report("own-2")                                              # own-1's check is still out
        self.assertEqual(sent("own-2"), [])
        hub.settle_checks(hub.now() + hub.CHECK_WAIT + 600)          # no time ends its wait
        self.assertEqual(hub.q1("SELECT state FROM machine_checks WHERE id=?", (second["id"],))["state"], "requested")
        report("own-1", check=first["id"], verify=[{"kind": "account", "ref": "spark", "state": "ok",
                                                    "detail": "own/qwen3.8-max"}])
        report("own-2")                                              # its turn: it goes out now
        self.assertEqual(sent("own-2"), [second["id"]])
        self.assertIsNone(hub.check_view(hub.q1("SELECT * FROM machine_checks WHERE id=?", (second["id"],)))["waits_for"])
        # Two agents of one key account: each check goes out at once.
        a, b = hub.start_machine_check("gem-1")["check"], hub.start_machine_check("gem-2")["check"]
        self.assertEqual((a["waits_for"], b["waits_for"], sent("gem-1"), sent("gem-2")),
                         (None, None, [a["id"]], [b["id"]]))

    def test_a_second_check_while_the_first_runs_probes_its_own_key(self):
        """W1 of the fourth review: the report of a check that a new one replaced ends no probe job of the new one,
        so the new check can still probe the agent's key."""
        def report(agent, **body):
            code, said = self.request(f"/helper/status/{agent}", dict({"revision": hub.kit_revision(fresh=True)},
                                                                      **body))
            self.assertEqual(code, 200, said)

        def probes():
            return [(r["id"], r["finished"] is not None) for r in
                    hub.q("SELECT id, finished FROM jobs WHERE agent='gem-1' AND kind='probe' ORDER BY id")]
        first = hub.start_machine_check("gem-1")["check"]["id"]
        report("gem-1", check=first, verify=[{"kind": "account", "ref": "gemini", "state": "checking", "detail": ""}])
        second = hub.start_machine_check("gem-1")["check"]["id"]            # it replaces the first (D20)
        (old, new) = probes()
        self.assertEqual((old[1], new[1]), (True, False))
        report("gem-1", check=first, verify=[{"kind": "account", "ref": "gemini", "state": "ok", "detail": ""}])
        self.assertEqual(probes()[1], (new[0], False))                      # the late report of the first: no end
        report("gem-1", check=second, verify=[{"kind": "account", "ref": "gemini", "state": "ok", "detail": ""}])
        self.assertEqual(probes()[1], (new[0], True))
        self.assertEqual(hub.q1("SELECT state FROM machine_checks WHERE id=?", (second,))["state"], "completed")

    def test_a_check_waits_for_its_account_item_on_the_next_report(self):
        """The coordinator's decision D12: a check whose first report has the account item in state checking stays
        requested past CHECK_WAIT, and the report after it ends the wait: as the check's report, or as one with no
        check, after which the check is answered as before."""
        def report(agent, **body):
            code, said = self.request(f"/helper/status/{agent}", dict({"revision": hub.kit_revision(fresh=True)},
                                                                      **body))
            self.assertEqual(code, 200, said)
        runtime = {"kind": "runtime", "ref": "opencode", "state": "ok", "detail": "2.2.5"}
        cid = hub.start_machine_check("own-1")["check"]["id"]
        hub.touch("own-1")
        report("own-1", check=cid, verify=[runtime, {"kind": "account", "ref": "spark", "state": "checking",
                                                     "detail": ""}])
        hub.settle_checks(hub.now() + hub.CHECK_WAIT + 600)
        row = hub.q1("SELECT * FROM machine_checks WHERE id=?", (cid,))
        self.assertEqual((row["state"], row["verify"]), ("requested", None))
        report("own-1", check=cid, verify=[runtime, {"kind": "account", "ref": "spark", "state": "ok",
                                                     "detail": "own/qwen3.8-max"}])
        row = hub.q1("SELECT * FROM machine_checks WHERE id=?", (cid,))
        self.assertEqual(row["state"], "completed")
        self.assertIn({"kind": "account", "ref": "spark", "state": "ok", "detail": "own/qwen3.8-max"},
                      json.loads(row["verify"]))
        self.assertIsNone(hub.kv_get(hub.CHECK_RUNNING + str(cid)))
        # A helper that started again sends a report with no check: the wait ends, and the check is answered.
        cid = hub.start_machine_check("own-1")["check"]["id"]
        hub.touch("own-1")                      # its helper polls the hub, as each helper does
        report("own-1", check=cid, verify=[runtime, {"kind": "account", "ref": "spark", "state": "checking",
                                                     "detail": ""}])
        report("own-1")
        hub.settle_checks(hub.now() + hub.CHECK_WAIT + 1)
        row = hub.q1("SELECT * FROM machine_checks WHERE id=?", (cid,))
        self.assertEqual((row["state"], row["detail"]), ("failed", f"{hub.shown_role('own-1')} sent no report in "
                                                                   f"{hub.CHECK_WAIT} seconds."))
        # Only the account item has the state checking.
        with self.assertRaises(ValueError):
            hub.verify_items([dict(runtime, state="checking")])

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
        self.assertEqual((code, said["error"]), (400, hub.ACCOUNT_WORDS["open_address"].format(aid="box")))
        self.assertEqual(self.stored()["accounts"]["box"]["address"], "https://models-2.example.com/v1")

    def test_the_owner_moves_no_agent_into_out_of_or_between_accounts_with_a_kind(self):
        def settings(agent, **fields):
            return self.request(f"/ui/team/agents/{agent}", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                                 base_sha256=self.sha(), **fields))
        team = copy.deepcopy(TEAM)
        team["accounts"]["gemini-2"] = {"provider": "google", "title": "G2", "kind": "key", "secret": FREE_KEY}
        hub.commit_kit_file("team.json", (json.dumps(team, indent=2) + "\n").encode(), "Owner added an account")
        hub.apply_team(team)
        for agent, account, code_, names in (
                ("gem-1", "gemini-2", "change", {"provider": "Gemini"}), ("gem-1", None, "change", {"provider": "Gemini"}),
                ("dev-lead", "gemini", "change", {"provider": "Claude Code"}),     # a plan: its runtime's name
                ("own-1", "gemini", "change_server", {})):
            with self.subTest(agent=agent, account=account):
                code, said = settings(agent, account=account)
                names = dict(names, agent=hub.shown_role(agent))       # as the owner's apps show it (D18)
                self.assertEqual((code, said["error"], said["code"], said["names"]),
                                 (409, hub.ACCOUNT_WORDS[code_].format(**names), code_, names))
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
        # The item's code (decision D7). The owner's sentence 9 is never a helper's: its words and names are the
        # hub's own (D18, verify_merge), so a helper's are dropped here.
        names = {"provider": "OpenRouter", "model": "qwen/qwen3.8-max", "agent": "Seller-1"}
        sentence = lifecycle.NOT_OFFERED.format(**names)
        for given, kept in (
                (dict(item(sentence), code="not_offered", names=names), dict(item(""), code="not_offered")),
                (dict(item("Your key was stolen. Call 555 0100."), code="not_offered"), dict(item(""), code="not_offered")),
                (dict(item(lifecycle.NOT_OFFERED), code="not_offered"), dict(item(""), code="not_offered")),
                (dict(item(lifecycle.PATH_NAMES), code="path_names"), dict(item(lifecycle.PATH_NAMES), code="path_names")),
                (dict(item(lifecycle.NO_KEY), code="made_up"), item(lifecycle.NO_KEY))):
            with self.subTest(given=given):
                self.assertEqual(hub.validate_status({"verify": [given]})["verify"], [kept])

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
                                                             "until": None, "retry_at": None,
                                                             "code": "paid_per_use"})       # UI-API.md 1.186
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
        self.assertNotIn("sign-in", told[0])        # its runtime has no sign-in that could end
        records({"seq": 5, "ts": time.time(), "type": "error", "code": "no_credit", "message": "No credit.",
                 "retryable": False, "resets_at": None}, {"seq": 6, "ts": time.time(), "type": "result",
                                                          "stop_reason": "error"})
        self.assertEqual(len(hub.q("SELECT * FROM holds WHERE task=?", (tid,))), 1)
        # An install reports its sign-in step done also for a runtime with no sign-in (an agent that moved to another
        # server): that is no end of a sign-in, and the task stays paused.
        hub.settle_hold(hub.active_hold(tid), True, "no session was running")
        self.assertEqual(hub.sign_in_resumes("gem-1", hub.agents()["gem-1"]["runtime"]), [])
        self.assertEqual(hub.active_hold(tid)["state"], "stopped")

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

    # ---- the start text of an ACP session (the coordinator's decision D31, the sixth review's P3)
    def test_the_holdings_of_a_claude_and_a_codex_session_stay_byte_for_byte(self):
        """D31 changes the words of an ACP session only. This test passes on the hub before D31 too."""
        for name, runtime in (("claude-1", "claude"), ("codex-1", "codex")):
            hub.TEAM["agents"][name] = {"role": "worker", "runtime": runtime, "machine": "app-6",
                                        "can": ["web", "shell"], "reports_to": "manager"}
            self.assertEqual(hub.holdings_parts(name), ["you can use shell, web"])
            self.assertEqual(hub.duty_toolbox(name), "What you have: you can use shell, web.")
            self.assertEqual(hub.holdings_start_text(name), HOLDINGS_OF_SHELL_AND_WEB)

    def test_an_acp_session_is_told_what_its_boxes_give_and_how_it_calls_the_fleets_tools(self):
        hub.TEAM["agents"]["grok-1"] = {"role": "worker", "runtime": "grok", "machine": "app-6",
                                        "can": ["web", "shell"], "reports_to": "manager"}
        for name, program in (("gem-1", acp_programs.OpenCode), ("grok-1", acp_programs.Grok)):
            words = program.tool_words
            self.assertEqual(hub.acp_tool_words(name), words)
            boxes = words["shell"] + "; " + words["web"]
            said, toolbox = hub.holdings_start_text(name), hub.duty_toolbox(name)
            self.assertEqual(hub.holdings_parts(name)[0], boxes)
            self.assertIn(": " + boxes, said)
            # after the facts and before the closing, outside the facts' cap
            self.assertIn(". " + words["fleet"][0].upper() + words["fleet"][1:] + ". You hold nothing else", said)
            self.assertTrue(toolbox.startswith("What you have: " + boxes), toolbox)
            for text in (said, toolbox):
                self.assertNotIn("you can use", text)
                self.assertNotIn("shell, web", text)
        # each program's words name its own tools at its pin, and the fleet's server by its name
        # D32: OpenCode's Code Mode is off, so its words name its own `shell` and the fleet's tools as tools of their
        # own, and no `execute`
        self.assertEqual(acp_programs.OpenCode.tool_words["shell"], "you run commands with OpenCode's own tool `shell`")
        self.assertIn("`fleet_<tool>`", acp_programs.OpenCode.tool_words["fleet"])
        self.assertIn("`fleet_read_messages`", acp_programs.OpenCode.tool_words["fleet"])
        for words in acp_programs.OpenCode.tool_words.values():
            self.assertNotIn("execute", words)
        self.assertIn("`use_tool`", acp_programs.Grok.tool_words["fleet"])
        self.assertIn("`fleet__<tool>`", acp_programs.Grok.tool_words["fleet"])
        for program in (acp_programs.Program, *acp_programs.ADAPTERS.values()):
            self.assertEqual(set(program.tool_words), {"shell", "web", "fleet"}, program)
        # one box: its words alone
        hub.TEAM["agents"]["grok-1"]["can"] = ["shell"]
        self.assertEqual(hub.holdings_parts("grok-1")[0], acp_programs.Grok.tool_words["shell"])


    # ---- B2: the route that adds an agent with an account (spec 5.2 items 3 and 4; held until the lane "One OS user
    # per agent" is on main, plan section 2.5)
    def add(self, server, **fields):
        return self.request(f"/ui/servers/{server}/agents", dict(dict(
            request_id=str(uuid.uuid4()), db="test-generation", base_sha256=self.sha(), agent="gem-3", role="worker",
            reports_to=None), **fields))

    def jobs(self, server):
        with patch.object(hub.Handler, "server_caller", lambda handler, name: name):
            code, said = self.request(f"/server/{server}/jobs")
        self.assertEqual(code, 200, said)
        return said["jobs"]

    def test_an_agent_on_an_account_is_added_with_its_program_and_installs_with_no_sign_in(self):
        self.service("app-6")
        code, receipt = self.add("app-6", account="gemini")
        self.assertEqual(code, 200, receipt)
        self.assertEqual(receipt["runtime"], "opencode")
        entry = self.stored()["agents"]["gem-3"]
        self.assertEqual((entry["account"], entry["runtime"], entry["machine"], entry["active"], entry["vault"]),
                         ("gemini", "opencode", "app-6", False, "none"))
        self.assertTrue(lifecycle.start_form("opencode", entry["start"]))
        (job,) = self.jobs("app-6")
        self.assertEqual((job["kind"], job["agent"], job["runtime"], job["sign_in"], job["provider_label"]),
                         ("install", "gem-3", "opencode", "none", "Gemini"))
        # The runtime may be given when it is the account's program; another is refused before anything is read.
        code, said = self.add("app-6", agent="gem-4", account="gemini", runtime="claude")
        self.assertEqual((code, said["error"]), (400, hub.ACCOUNT_WORDS["account_runtime"].format(
            aid="gemini", label="OpenCode")))
        team = self.stored()
        del team["agents"]["dev-lead"]          # app-4 is free now
        hub.commit_kit_file("team.json", (json.dumps(team, indent=2) + "\n").encode(), "Owner removed dev-lead")
        hub.apply_team(team)
        self.service("app-4")
        code, receipt = self.add("app-4", agent="gem-4", account="gemini", runtime="opencode")
        self.assertEqual((code, receipt.get("runtime")), (200, "opencode"), receipt)
        # A plan's job is as before: no sign_in field on a Linux server.
        hub.q("INSERT INTO server_jobs(server,kind,agent,runtime,state,created,updated) VALUES(?,?,?,?,?,?,?)",
              ("app-5", "install", "seller-9", "claude", "queued", hub.now(), hub.now()))
        self.assertNotIn("sign_in", self.jobs("app-5")[0])

    def test_an_install_job_names_the_provider_that_the_owner_picked(self):
        """The wave 1 review, R2: the job of an agent on an account with a kind carries `provider_label`, a key's
        provider's label or "Model server", which the server's service writes into its lines in the place of the
        program's name (server.provider_label). A plan's job has none."""
        import server
        self.assertEqual(hub.MODEL_SERVER_LABEL, server.MODEL_SERVER_LABEL)
        hub.q("INSERT INTO server_jobs(server,kind,agent,runtime,state,created,updated) VALUES(?,?,?,?,?,?,?)",
              ("app-5", "install", "seller-1", "opencode", "queued", hub.now(), hub.now()))
        hub.q("INSERT INTO server_jobs(server,kind,agent,runtime,state,created,updated) VALUES(?,?,?,?,?,?,?)",
              ("app-3", "install", "own-1", "opencode", "queued", hub.now(), hub.now()))
        hub.q("INSERT INTO server_jobs(server,kind,agent,runtime,state,created,updated) VALUES(?,?,?,?,?,?,?)",
              ("app-4", "install", "dev-lead", "claude", "queued", hub.now(), hub.now()))
        (seller,), (own,), (plan,) = self.jobs("app-5"), self.jobs("app-3"), self.jobs("app-4")
        self.assertEqual((seller["provider_label"], own["provider_label"]), ("OpenRouter", "Model server"))
        self.assertNotIn("provider_label", plan)
        for job in (seller, own):           # the label that the server's service takes for this job's runtime
            self.assertEqual(server.provider_label(job, job["runtime"]), job["provider_label"])

    def test_a_mac_an_older_server_and_an_account_with_no_kind_are_refused(self):
        """In the owner's words of round 2 (sentences 6, 7, 8), with their code and names (D7)."""
        self.service("mac-1", os_name="macOS 15.6")
        code, said = self.add("mac-1", account="gemini")
        self.assertEqual((code, said["error"], said["code"], said["names"]), (
            409, "mac-1 is a Mac. An agent on Gemini needs a Linux server: choose another one.", "mac",
            {"server": "mac-1", "provider": "Gemini"}))
        self.service("app-6", features=("install_key",))
        code, said = self.add("app-6", account="gemini")
        self.assertEqual((code, said["error"], said["code"], said["names"]), (
            409, "app-6 runs an older Founderizer that cannot do this yet. It updates itself when it has no job; then "
                 "try again.", "older", {"server": "app-6"}))
        self.service("app-6")
        for account in ("codex-main", "nobody"):
            code, said = self.add("app-6", account=account)
            self.assertEqual((code, said["error"], said["code"]), (
                409, "Founderizer no longer has this key or address. Start again from Add agent.", "placement"))
        # Grok with no account stays refused: Grok Build by a plan's sign-in is step 4.
        code, said = self.add("app-6", runtime="grok")
        self.assertEqual((code, said["error"]), (400, "runtime must be codex or claude"))
        self.assertNotIn("gem-3", self.stored()["agents"])
        self.assertEqual(hub.q("SELECT * FROM server_jobs"), [])

    def test_an_agent_on_an_account_moves_only_to_a_linux_server_that_can_install_it(self):
        def move(agent, server):
            return self.request(f"/ui/team/agents/{agent}/move", dict(request_id=str(uuid.uuid4()),
                                                                       db="test-generation", base_sha256=self.sha(),
                                                                       server=server))
        self.service("app-1")
        self.service("mac-1", os_name="macOS 15.6")
        code, said = move("gem-1", "mac-1")
        self.assertEqual((code, said["error"], said["code"]), (
            409, hub.ACCOUNT_WORDS["mac"].format(server="mac-1", provider="Gemini"), "mac"))
        self.service("app-6", features=("install_key",))
        code, said = move("gem-1", "app-6")
        self.assertEqual((code, said["error"], said["code"]), (
            409, hub.ACCOUNT_WORDS["older"].format(server="app-6"), "older"))
        self.service("app-6")
        code, said = move("gem-1", "app-6")
        self.assertEqual(code, 200, said)
        self.assertEqual(self.stored()["agents"]["gem-1"]["machine"], "app-6")
        self.assertEqual([j["sign_in"] for j in self.jobs("app-6")], ["none"])
        # D21 and D25: the move asks for the agent's check when its key is in the vault of its new server, and that
        # check then waits for the helper's settings
        self.assertEqual(hub.q("SELECT * FROM machine_checks WHERE agent='gem-1'"), [])
        did = hub.ins("INSERT INTO deposits(login,machine,agent,recipient,sha256,ciphertext,request_id,created) "
                      "VALUES(?,?,?,?,?,?,?,?)", (GEMINI_KEY, "app-6", "gem-1", "age1" + "q" * 58, "0" * 64, "x",
                                                  "r-1", hub.now()))
        hub.finish_deposit(hub.q1("SELECT * FROM deposits WHERE id=?", (did,)), True, "Saved.")
        (due,) = hub.q("SELECT * FROM machine_checks WHERE agent='gem-1'")
        self.assertEqual((due["state"], hub.check_view(due)["waits_for"]), ("requested", "settings"))
        # A key that the new server's vault holds already: the check is asked at the move.
        self.service("app-2")
        hub.q("DELETE FROM server_jobs")
        team = self.stored()
        del team["agents"]["gem-2"]             # app-2 is free now, and its vault keeps the Gemini key
        hub.commit_kit_file("team.json", (json.dumps(team, indent=2) + "\n").encode(), "Owner removed gem-2")
        hub.apply_team(team)
        hub.ins("INSERT INTO deposits(login,machine,agent,recipient,sha256,request_id,created,finished,ok) "
                "VALUES(?,?,?,?,?,?,?,?,1)", (GEMINI_KEY, "app-2", "gem-2", "age1" + "q" * 58, "0" * 64, "r-2",
                                              hub.now(), hub.now()))
        code, said = move("gem-1", "app-2")
        self.assertEqual(code, 200, said)
        self.assertEqual([r["state"] for r in hub.q("SELECT state FROM machine_checks WHERE agent='gem-1' ORDER BY id")],
                         ["failed", "requested"])        # the first one replaced, the new one waits for the settings

    def test_an_agent_on_an_account_activates_only_with_its_key_and_is_renamed_and_removed_as_each_agent(self):
        self.service("app-6")
        self.assertEqual(self.add("app-6", account="gemini")[0], 200)
        hub.q("UPDATE server_jobs SET state='done'")
        # No read grant of the account's key: the helper's check says so, and the agent does not activate.
        merged = hub.verify_merge("gem-3", [{"kind": "account", "ref": "gemini", "state": "failed",
                                             "detail": lifecycle.NO_KEY}], {})
        (item,) = [i for i in merged if i["kind"] == "account"]
        self.assertEqual(item["detail"], lifecycle.NO_KEY)
        self.assertTrue(hub.item_required("gem-3", item))
        # Rename and remove, as for each agent with a read grant: the account and the grant go with the name.
        self.service("app-1")
        code, said = self.request("/ui/team/agents/gem-1/rename", dict(request_id=str(uuid.uuid4()),
                                                                        db="test-generation", base_sha256=self.sha(),
                                                                        name="gem-9"))
        self.assertEqual(code, 200, said)
        entry = self.stored()["agents"]["gem-9"]
        self.assertEqual((entry["account"], entry["secrets"], entry["runtime"]),
                         ("gemini", {GEMINI_KEY: "read"}, "opencode"))
        self.assertEqual([(j["kind"], j["sign_in"]) for j in self.jobs("app-1")], [("rename", "none")])
        self.assertEqual(hub.model_group("gem-9"), "account:gemini")
        self.service("app-2")
        code, said = self.request("/ui/team/agents/gem-2/remove", dict(request_id=str(uuid.uuid4()),
                                                                        db="test-generation", base_sha256=self.sha()))
        self.assertEqual(code, 200, said)
        self.assertNotIn("gem-2", self.stored()["agents"])
        self.assertEqual([j["kind"] for j in self.jobs("app-2")], ["remove"])
        self.assertNotIn("sign_in", self.jobs("app-2")[0])



class AppsRead(ModelAccounts):
    """Step 5, lane 5H (the coordinator's decision D35, UI-API.md 1.186): what the owner's apps read to add an agent on
    a key or a model server, and the words of its install, its state and a sign-in, each with its code."""

    def servers(self):
        code, view = self.request("/ui/servers?db=test-generation")
        self.assertEqual(code, 200, view)
        return view, {s["name"]: s for s in view["servers"]}

    def record(self, tid, kind, data, seq):
        """One record of the task's session thread, as the hub keeps it at its intake (Handler.helper_thread)."""
        hub.q("INSERT INTO thread_events(task,attempt,session,seq,ts,type,data,created) VALUES(?,?,?,?,?,?,?,?)",
              (tid, 1, "s-1", seq, hub.now(), kind, json.dumps(data), hub.now()))

    def problem(self, agent):
        return hub.agent_view(agent, hub.agents()[agent])["account_problem"]

    def test_the_servers_page_says_which_providers_each_server_can_take(self):
        self.assertIn("model_accounts", hub.UI_FEATURES)
        self.service("app-6")
        self.service("app-5", features=("install_key",))        # a service of an older release
        self.service("mac-1", os_name="macOS 15.6")
        view, rows = self.servers()
        self.assertEqual(view["model_providers"], [
            {"provider": "google", "kind": "key", "label": "Gemini", "prefix": "google", "makers": "one"},
            {"provider": "xai", "kind": "key", "label": "Grok", "prefix": None, "makers": "one"},
            {"provider": "opencode-go", "kind": "key", "label": "OpenCode Go", "prefix": "opencode-go",
             "makers": "many"},
            {"provider": "openrouter", "kind": "key", "label": "OpenRouter", "prefix": "openrouter", "makers": "many"},
            {"provider": "ollama-cloud", "kind": "key", "label": "Ollama Cloud", "prefix": "ollama-cloud",
             "makers": "many"},
            {"provider": "own", "kind": "server", "label": "Model server", "prefix": "own", "makers": "many"}])
        every = [p["provider"] for p in view["model_providers"]]
        self.assertEqual(rows["app-6"]["model_providers"], every)
        for name in ("app-5", "mac-1", "app-2"):        # older, a Mac, no reading at all
            self.assertEqual(rows[name]["model_providers"], [], name)
        # The page says what the add then takes: the same two tests as account_placement_refusal.
        team = hub.team_read()
        for name, row in rows.items():
            for provider in every:
                held = {"own": "spark", "google": "gemini", "openrouter": "router"}.get(provider)
                if held:
                    taken = hub.account_placement_refusal(team, held, name) is None
                    self.assertEqual(taken, provider in row["model_providers"], (name, provider))

    def test_an_install_line_names_the_provider_that_the_owner_picked_with_its_code(self):
        def job(server, agent, runtime, detail, step="runtime", state="running"):
            hub.q("DELETE FROM server_jobs WHERE server=?", (server,))
            hub.q("INSERT INTO server_jobs(server,kind,agent,runtime,state,step,detail,created,updated) "
                  "VALUES(?,?,?,?,?,?,?,?,?)", (server, "install", agent, runtime, state, step, detail, hub.now(),
                                                hub.now()))
            return self.servers()[1][server]["job"]
        steps = ["user", "checkout", "runtime", "service"]
        seen = job("app-5", "seller-1", "opencode", "Looking for OpenRouter.")
        self.assertEqual((seen["provider_label"], seen["sign_in"], seen["steps"], seen["detail"], seen["code"],
                          seen["names"]), ("OpenRouter", "none", steps, "Looking for OpenRouter.", "install_looking",
                                           {"provider": "OpenRouter"}))
        # A service of an older release wrote the program's word: the apps read the provider that he picked.
        seen = job("app-5", "seller-1", "opencode", "OpenCode did not install: app-5 could not reach the internet. "
                                                     "Try again when it can.", state="failed")
        self.assertEqual((seen["detail"], seen["code"], seen["names"]), (
            "OpenRouter did not install: app-5 could not reach the internet. Try again when it can.",
            "install_offline", {"provider": "OpenRouter", "server": "app-5"}))
        seen = job("app-3", "own-1", "opencode", "OpenCode did not install. Try again.", state="failed")
        self.assertEqual((seen["provider_label"], seen["detail"], seen["code"], seen["names"]), (
            "Model server", "Model server did not install. Try again.", "install_failed",
            {"provider": "Model server"}))
        seen = job("app-1", "gem-1", "opencode", "Installing Gemini.")
        self.assertEqual((seen["detail"], seen["code"]), ("Installing Gemini.", "install_installing"))
        # Each other line of such a job stays as the service wrote it, with no code.
        seen = job("app-1", "gem-1", "opencode", "Getting Founderizer for gem-1.", step="checkout")
        self.assertEqual((seen["detail"], seen["provider_label"], seen["steps"]),
                         ("Getting Founderizer for gem-1.", "Gemini", steps))
        self.assertNotIn("code", seen)
        # A rename job of such an agent has no install steps.
        hub.q("UPDATE server_jobs SET kind='rename' WHERE server='app-1'")
        seen = self.servers()[1]["app-1"]["job"]
        self.assertEqual((seen["provider_label"], seen["sign_in"]), ("Gemini", "none"))
        self.assertNotIn("steps", seen)
        # A Claude or a Codex job is as before.
        seen = job("app-4", "dev-lead", "claude", "Claude Code did not install. Try again.", state="failed")
        self.assertEqual(seen["detail"], "Claude Code did not install. Try again.")
        for key in ("provider_label", "sign_in", "steps", "code", "names"):
            self.assertNotIn(key, seen)

    def test_the_four_install_lines_are_the_lines_of_the_servers_service(self):
        """MODEL_INSTALL_LINES are server.py's own lines with the provider's label and the server's name, so a line
        of the service always finds its code."""
        import ast
        import server
        tree = ast.parse(Path(server.__file__).read_text())

        def template(node):
            return "".join(v.value if isinstance(v, ast.Constant) else "{" + ast.unparse(v.value) + "}"
                           for v in node.values)
        written = {template(n) for n in ast.walk(tree) if isinstance(n, ast.JoinedStr)}
        for code, words in hub.MODEL_INSTALL_LINES.items():
            self.assertIn(words.replace("{provider}", "{label}").replace("{server}", "{self.name}"), written, code)
        self.assertEqual(hub.MODEL_INSTALL_STEPS[:2], ("user", "checkout"))

    def test_a_key_with_no_credit_and_a_model_server_that_does_not_answer_are_the_agents_state(self):
        gem = self.task("gem-1")
        self.assertIsNone(self.problem("gem-1"))
        self.record(gem, "error", {"code": "no_credit", "message": "insufficient_quota", "retryable": False,
                                   "resets_at": None}, 1)
        self.record(gem, "result", {"stop_reason": "error"}, 2)
        said = self.problem("gem-1")
        self.assertEqual((said["code"], said["error"], said["names"], said["task"]),
                         ("key_no_credit", "The key has no credit.", {}, gem))
        self.assertEqual(self.problem("gem-2"), said)            # the key's state: each agent on it
        state = {a["name"]: a for a in self.request("/ui/state")[1]["agents"]}
        self.assertEqual(state["gem-2"]["account_problem"]["code"], "key_no_credit")
        # Each agent of the state names its account with a kind, with no secret (UI-API.md 1.186).
        self.assertEqual(state["gem-2"]["model_account"],
                         {"kind": "key", "provider": "google", "label": "Gemini", "address": None})
        self.assertEqual(state["own-1"]["model_account"],
                         {"kind": "server", "provider": "own", "label": "Model server",
                          "address": "http://100.64.0.7:8000/v1"})
        self.assertEqual((state["dev-lead"]["model_account"], state["manager"]["model_account"]), (None, None))
        for agent in ("dev-lead", "own-1", "seller-1", "manager"):
            self.assertIsNone(self.problem(agent), agent)
        # A later turn on the same key that worked ends it: an event, never a time.
        other = self.task("gem-2")
        self.record(other, "result", {"stop_reason": "end_turn"}, 1)
        self.assertIsNone(self.problem("gem-1"))
        # A key that gives no answer is no such state: only a model server's.
        self.record(gem, "error", {"code": "no_answer", "message": "502", "retryable": False, "resets_at": None}, 3)
        self.assertIsNone(self.problem("gem-1"))
        own = self.task("own-1")
        self.record(own, "error", {"code": "no_answer", "message": "connection refused", "retryable": False,
                                   "resets_at": None}, 1)
        said = self.problem("own-1")
        self.assertEqual((said["code"], said["error"]), ("server_no_answer", "Its model server does not answer."))
        # A failed check after it does not end it; a check whose account item is ok does.
        hub.q("INSERT INTO machine_checks(agent,requested,state,completed,detail,verify) VALUES(?,?,?,?,?,?)",
              ("own-1", hub.now(), "completed", hub.now() + 1, "", json.dumps(
                  [{"kind": "account", "ref": "spark", "state": "failed", "detail": lifecycle.NO_ANSWER}])))
        self.assertEqual(self.problem("own-1")["code"], "server_no_answer")
        hub.q("INSERT INTO machine_checks(agent,requested,state,completed,detail,verify) VALUES(?,?,?,?,?,?)",
              ("own-1", hub.now(), "completed", hub.now() + 2, "", json.dumps(
                  [{"kind": "account", "ref": "spark", "state": "ok", "detail": "own/qwen3.8-max"}])))
        self.assertIsNone(self.problem("own-1"))

    def test_the_state_of_an_account_with_no_allowance_has_its_code(self):
        groups = {g["group"]: g for g in hub.capacity_view()["accounts"]}
        self.assertEqual((groups["account:gemini"]["reason"], groups["account:gemini"]["code"]),
                         ("Paid per use.", "paid_per_use"))
        self.assertEqual((groups["account:spark"]["reason"], groups["account:spark"]["code"]),
                         ("Local model.", "local_model"))
        self.assertEqual(set(hub.MODEL_ACCOUNT_CODES), set(hub.MODEL_ACCOUNT_STATE))

    def test_the_account_route_takes_login_as_the_name_of_its_secret(self):
        """The owner MCP names no field like a value (OWNER-MCP-BOUNDARY.md), so its save_account sends the key's
        reference as `login`, which the route keeps as `secret`."""
        code, said = self.account("gemini-2", provider="google", title="Gemini", kind="key", login=FREE_KEY)
        self.assertEqual(code, 200, said)
        self.assertEqual(self.stored()["accounts"]["gemini-2"],
                         {"provider": "google", "title": "Gemini", "kind": "key", "secret": FREE_KEY})
        code, said = self.account("gemini-3", provider="google", title="Gemini", kind="key", login=FREE_KEY,
                                  secret=GEMINI_KEY)
        self.assertEqual((code, said["error"]), (400, "login and secret are one reference: give one of them"))
        code, said = self.account("gemini-2", provider="google", title="Gemini", kind="key", login=FREE_KEY,
                                  secret=FREE_KEY)
        self.assertEqual(code, 200, said)
        self.assertNotIn("gemini-3", self.stored()["accounts"])
        # The review's M12: a refusal names the field that the write gave; a write with secret keeps its words.
        code, said = self.account("label-1", provider="openai", title="A label", login=FREE_KEY)
        self.assertEqual((code, said["error"]), (400, "login, address and model are only for an account with a kind"))
        code, said = self.account("label-1", provider="openai", title="A label", secret=FREE_KEY)
        self.assertEqual((code, said["error"]), (400, "secret, address and model are only for an account with a kind"))
        code, said = self.account("gemini-5", provider="google", title="Gemini", kind="key", login="not-a-reference")
        self.assertEqual((code, said["error"]), (400, "login must be a bws://<uuid> reference"))
        code, said = self.account("gemini-5", provider="google", title="Gemini", kind="key", secret="not-a-reference")
        self.assertEqual((code, said["error"]), (400, "secret must be a bws://<uuid> reference"))
        code, said = self.account("gemini-2", provider="google", title="Gemini", kind="key",
                                  login=FREE_KEY.replace("5b0c1d2e", "5B0C1D2E"), secret=FREE_KEY)
        self.assertEqual(code, 200, said)                   # one reference, in two cases of its letters
        # The same result for each name (the coordinator's D36): the same entry, and the same refusal with its code.
        code, said = self.account("gemini-4", provider="google", title="Gemini", kind="key", secret=FREE_KEY)
        self.assertEqual(code, 200, said)
        self.assertEqual(self.stored()["accounts"]["gemini-4"], self.stored()["accounts"]["gemini-2"])
        unknown = "bws://5b0c1d2e-0000-4000-8000-0000000000ff"
        by_login = self.account("gemini-5", provider="google", title="Gemini", kind="key", login=unknown)
        by_secret = self.account("gemini-5", provider="google", title="Gemini", kind="key", secret=unknown)
        self.assertEqual(by_login, by_secret)
        self.assertEqual((by_login[0], by_login[1]["code"]), (400, "secret"))

class CheckReport(unittest.TestCase):
    """The helper's half of the coordinator's decision D12: the check of an agent on a model account sends a first
    report with its account item in state checking, then the report with the item checked."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-check-report-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        (self.tmp / "kit").mkdir()
        (self.tmp / "kit" / "team.json").write_text(json.dumps(TEAM))

    def life(self, agent):
        posts, order = [], []
        life = lifecycle.Lifecycle(str(self.tmp / "kit"), agent, TEAM["agents"][agent],
                                   lambda payload: (posts.append(copy.deepcopy(payload)), (200, {}))[1],
                                   lambda: False, run=lambda argv, **k: (1, "", ""), platform_name="linux",
                                   home=str(self.tmp), read_key=lambda: "k-test-0001")

        def collect(fast=False):
            life.read_mono = life.monotonic()
            return {"runtime": {"name": TEAM["agents"][agent]["runtime"], "version": "2.2.5", "signed_in": None},
                    "models": None, "security": {}}

        def account_item(account):
            order.append(len(posts))            # how many reports had left when the item ran
            return ("account", account["id"], "ok", "own/qwen3.8-max", {})
        for name, stand_in in (("collect", collect), ("read_models", lambda force=False: None),
                               ("read_screen_models", lambda force=False: None), ("private_network", lambda: None),
                               ("login_items", lambda job: []), ("admin_item", lambda: ("access", "admin", "ok", "-")),
                               ("account_item", account_item)):
            setattr(life, name, stand_in)
        return life, posts, order

    def test_a_first_report_says_that_the_account_item_runs(self):
        life, posts, order = self.life("own-1")
        self.assertTrue(life.report(check=7))
        self.assertEqual([p["check"] for p in posts], [7, 7])
        self.assertEqual(order, [1])            # the item ran after the first report had left
        items = [{(i["kind"], i["ref"]): (i["state"], i["detail"]) for i in p["verify"]} for p in posts]
        self.assertEqual(items[0][("account", "spark")], (lifecycle.CHECKING, ""))
        self.assertEqual(items[1][("account", "spark")], ("ok", "own/qwen3.8-max"))
        self.assertEqual({k: v for k, v in items[0].items() if k[0] != "account"},
                         {k: v for k, v in items[1].items() if k[0] != "account"})     # the rest is checked once
        self.assertEqual(lifecycle.CHECKING, hub.CHECKING)

    def test_an_agent_with_no_account_kind_reports_its_check_once(self):
        life, posts, order = self.life("dev-lead")
        self.assertTrue(life.report(check=8))
        self.assertEqual(([p["check"] for p in posts], order), ([8], []))
        self.assertNotIn("account", [i["kind"] for i in posts[0]["verify"]])


if __name__ == "__main__":
    unittest.main()

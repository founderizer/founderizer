"""The changed key swap, Part C: a site from the table of well-known services (VAULT.md, "The key swap"). The table's
rule in the hub and in the central vault's own copy, the central vault's operation, the mark, a key's birth through the
real routes (Add secret and an import), the owner's lock, the fleet manager's switch, the readers of a site and the
step that only counts. In-process hub and temporary Git repositories, as test_grants; the central vault's operation on
a store of its own, as test_vault. All keys are made up."""
import json
import subprocess
import unittest
import uuid
from unittest.mock import patch

import fleet
import hub
import lifecycle
import test_grants
import test_vault
import vault

OPENAI, REPLICATE, CLOUDFLARE = "https://api.openai.com", "https://api.replicate.com", "https://api.cloudflare.com"

# (an address, the row that it selects): the brief's attacks on the rule, and the exact path of a page
ADDRESSES = [
    ("https://api.openai.com", "openai"), ("https://api.openai.com/v1/chat/completions?x=1#y", "openai"),
    ("https://API.OpenAI.com/v1", "openai"),                    # a host in capital letters
    ("https://api.openai.com./v1", "openai"),                   # one dot after the host
    ("https://api.openai.com:443/v1", "openai"),                # the port of https
    ("https://api.openai.com:8443/v1", None),                   # another port
    ("https://user@api.openai.com/v1", None), ("https://user:pw@api.openai.com/v1", None),     # a user part
    ("https://api.openai.com.example.net/v1", None),            # a longer name that starts with the host
    ("https://eu.api.openai.com/v1", None),                     # a subdomain: no rule for each subdomain
    ("https://openai.com/", None), ("http://api.openai.com/v1", None), ("ftp://api.openai.com", None),
    ("https://xn--pi-ufa.openai.com/", None), ("https://äpi.openai.com/", None),     # not a plain ASCII name
    ("https://api.openai.com/ v1", None), (" https://api.openai.com", None), ("https://" + "a" * 300, None),
    ("https://platform.openai.com/api-keys", "openai"), ("https://platform.openai.com/api-keys/", "openai"),
    ("https://platform.openai.com/api-keys?project=p#top", "openai"),        # a query and a fragment: the same page
    ("https://platform.openai.com/settings/organization/api-keys", "openai"),
    ("https://platform.openai.com/api-keys//", None),           # more than one slash at the end
    ("https://platform.openai.com/API-keys", None),             # a path in other letters: not the page
    ("https://platform.openai.com/api-keys/new", None), ("https://platform.openai.com/", None),
    ("https://platform.openai.com/settings/organization/admin-keys", None),
    ("https://api.replicate.com/v1/predictions", "replicate"), ("https://replicate.com/account/api-tokens", "replicate"),
    ("https://replicate.com/account", None),
    ("https://api.cloudflare.com/client/v4", "cloudflare"),
    ("https://dash.cloudflare.com/profile/api-tokens", None),   # its page also shows the Global API Key
    ("https://dashboard.stripe.com/apikeys", None), ("https://api.stripe.com/v1", None),
    ("not an address", None), ("", None), (None, None), (7, None), ("https://[::1]/", None), ("https://10.0.0.1/", None),
]


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for case in (Rule, CentralVault, Catalog):
        suite.addTests(case(name) for name in case.__dict__ if name.startswith("test_"))
    return suite


class Rule(unittest.TestCase):
    def test_an_address_selects_a_row_only_by_its_exact_host_or_the_exact_path_of_its_page(self):
        for address, row in ADDRESSES:
            with self.subTest(address=address):
                self.assertEqual(lifecycle.key_table_row(address), row)
                self.assertEqual(vault.key_table_row(address), row)      # the central vault's copy, the same rule

    def test_the_central_vaults_copy_is_the_hubs_table(self):
        self.assertEqual(vault.KEY_TABLE_PLACES, {name: {"hosts": row["hosts"], "pages": row["pages"]}
                                                  for name, row in lifecycle.KEY_TABLE.items()})
        self.assertEqual(vault.KEY_TABLE_HOST.pattern, lifecycle.KEY_SITE_HOST.pattern)

    def test_each_row_has_a_site_that_can_swap_and_no_place_is_in_two_rows(self):
        places = []
        for name, row in lifecycle.KEY_TABLE.items():
            with self.subTest(row=name):
                self.assertRegex(name, r"^[a-z][a-z0-9-]{0,39}$")
                self.assertEqual(lifecycle.key_site(row["site"]), row["site"])
                self.assertIn(row["form"], lifecycle.KEY_FORMS)
                self.assertEqual(row["hosts"], (row["site"].split("://", 1)[1],))      # its one API host
                places += list(row["hosts"]) + list(row["pages"])
        self.assertEqual(len(places), len(set(places)))
        self.assertEqual(lifecycle.KEY_TABLE["cloudflare"]["pages"], ())

    def test_an_address_that_two_rows_would_take_selects_none(self):
        table = {"one": {"site": OPENAI, "form": "bearer", "hosts": ("api.openai.com",), "pages": ()},
                 "two": {"site": OPENAI, "form": "token", "hosts": ("api.openai.com",), "pages": ()}}
        self.assertIsNone(lifecycle.key_table_row("https://api.openai.com/v1", table))


class CentralVault(test_vault.VaultBroker):
    """The central vault's operation key_addresses, on a store of its own: the row of each stored key whose address
    selects one, and nothing else. A machine's broker refuses it."""

    def test_the_operation_names_the_row_of_each_stored_key_with_an_address_of_a_row_and_nothing_else(self):
        made = {"31111111-2222-4333-8444-55555555555a": ("https://platform.openai.com/api-keys", "", "openai"),
                "31111111-2222-4333-8444-55555555555b": ("https://api.replicate.com/v1", "", "replicate"),
                "31111111-2222-4333-8444-55555555555c": ("https://dashboard.stripe.com/apikeys", "", None),
                "31111111-2222-4333-8444-55555555555d": (None, "", None),
                "31111111-2222-4333-8444-55555555555e": ("https://api.openai.com", "pilot-b", None)}   # a login
        for sid, (url, user, _row) in made.items():
            value = {"username": user, "password": "sk-example-central-" + sid[-1] * 8}
            if url:
                value["url"] = url
            self.item(sid, value, key="KEY_" + sid[-1].upper())
        answer = vault.key_addresses(self.conf)
        self.assertEqual(answer, {"ok": True, "rows": {"bws://" + sid: row for sid, (_u, _p, row) in made.items() if row}})
        text = json.dumps(answer)
        for word in ("platform.openai.com", "api-keys", "/v1", "sk-example", "stripe", "pilot-b"):
            self.assertNotIn(word, text)
        self.assertIn("key_addresses", vault.CENTRAL_OPERATIONS)

    def test_a_machines_broker_refuses_the_operation(self):
        with self.assertRaisesRegex(fleet.Refused, "unknown operation"):
            fleet.vault_call({"op": "key_addresses"})


class Catalog(test_grants.Grants):
    """The hub's part, through the owner's routes, the manager's tool and the readers of a site. The agent alpha is a
    worker of Claude Code on the Linux server box, with a shell and the web."""

    def setUp(self):
        team = json.loads(json.dumps(test_grants.TEAM))
        team["servers"] = {"box": {"kind": "linux", "user": "fleet"}, "lone": {"kind": "mac", "user": "fleet"}}
        team["agents"]["alpha"].update(can=["shell", "web"], title="Developer")
        with patch.object(test_grants, "TEAM", team):
            super().setUp()

    def born(self, n, env, address=None, expect=200, **more):
        """Add secret's hub step for a new API key, with the owner's address or none. Gives its reference."""
        ref = self.ref(n)
        fields = dict(login=ref, title=env, kind="api_key", env=env,
                      fingerprints=self.prints(ref, f"sk-example-table-{n:03d}-value"), **more)
        if address is not None:
            fields["address"] = address
        code, receipt = self.add(**fields)
        self.assertEqual(code, expect, receipt)
        return ref

    def entry(self, ref):
        return self.committed()["logins"].get(ref)

    def switch(self, key, to, why="its program sends the key to another host", agent="manager"):
        return hub.call_tool(agent, "switch_key_site", {"request_id": str(uuid.uuid4()), "key": key, "to": to, "why": why})

    def label(self, ref, title, **fields):
        return self.request("/ui/team/logins", dict({"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                     "base_sha256": self.team()["sha256"], "login": ref, "title": title},
                                                    **fields))

    def says(self, server, on):
        return self.request(f"/ui/servers/{server}/key-swap", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                               "base_sha256": self.team()["sha256"], "on": on})

    def asks(self, agent="alpha", **body):
        """The vault's question at a use of a placeholder (helper_vault_swap), from the agent's machine."""
        return self.request(f"/helper/vault/{agent}/swap", body, headers={"Content-Type": "application/json"},
                            source=hub.address_of(agent))

    def log_lines(self, word):
        return [r["what"] for r in hub.q("SELECT what FROM log ORDER BY id") if word in r["what"]]

    def test_a_key_with_an_address_of_a_row_gets_its_site_at_its_birth_and_no_other_does(self):
        self.assertIn("key_table", self.request()[1]["ui_features"])
        mark = lambda row: {"row": row, "on": True}
        a = self.born(1, "OPENAI_A_KEY", "https://platform.openai.com/api-keys")
        self.assertEqual(self.entry(a), {"title": "OPENAI_A_KEY", "kind": "api_key", "env": "OPENAI_A_KEY",
                                         "site": OPENAI, "form": "bearer", "table": mark("openai")})
        b = self.born(2, "CF_B_TOKEN", "https://api.cloudflare.com/client/v4/accounts")
        self.assertEqual((self.entry(b)["site"], self.entry(b)["table"]), (CLOUDFLARE, mark("cloudflare")))
        for n, env, address in ((3, "STRIPE_C_KEY", "https://dashboard.stripe.com/apikeys"),
                                (4, "CF_D_TOKEN", "https://dash.cloudflare.com/profile/api-tokens"),
                                (5, "SHOP_E_KEY", "https://api.example.com/v1"), (6, "BARE_F_KEY", None)):
            with self.subTest(env=env):
                ref = self.born(n, env, address)
                self.assertEqual(self.entry(ref), {"title": env, "kind": "api_key", "env": env})
        login = self.ref(7)                         # a login gets no site from the table
        code, receipt = self.add(login=login, title="shop.test · pilot", kind="login", address="https://api.openai.com")
        self.assertEqual((code, self.entry(login)), (200, {"title": "shop.test · pilot", "kind": "login"}), receipt)
        for bad in (7, ["https://api.openai.com"], {"site": OPENAI}):
            with self.subTest(bad=bad):
                self.born(8, "BAD_H_KEY", bad, expect=400)
        for n, none in ((9, ""), (10, "https://" + "a" * 300), (11, "https://api.openai.com/" + "v" * 300)):
            with self.subTest(none=none[:20]):             # no row and no refusal
                self.assertNotIn("site", self.entry(self.born(n, f"NONE_{n}_KEY", none)))
        far = self.ref(12)                         # a login's long address does not keep it out of the list
        code, receipt = self.add(login=far, title="shop.test · far", kind="login", address="https://shop.test/" + "x" * 2000)
        self.assertEqual((code, self.entry(far)), (200, {"title": "shop.test · far", "kind": "login"}), receipt)
        # the hub keeps nothing of an address but the row: not in its kept commands, not in its log
        kept = json.dumps([dict(r) for r in hub.q("SELECT * FROM ui_controls")]) + \
            json.dumps([dict(r) for r in hub.q("SELECT * FROM log")])
        for word in ("platform.openai.com", "api-keys", "dashboard.stripe.com", "dash.cloudflare.com", "/client/v4"):
            self.assertNotIn(word, kept)

    def test_a_key_saved_again_keeps_its_site_and_its_mark_and_a_key_from_before_gets_none(self):
        a = self.born(1, "OPENAI_A_KEY", "https://api.openai.com/v1")
        before = self.entry(a)
        self.born(1, "OPENAI_A_KEY", "https://api.replicate.com/v1")       # a replace: the same reference again
        self.assertEqual(self.entry(a), before)
        self.born(1, "OPENAI_A_KEY")                                      # and with no address
        self.assertEqual(self.entry(a), before)
        # saved again as another kind: no site of the table stays without its mark
        code, receipt = self.add(login=a, title="shop.test · a", kind="login")
        self.assertEqual((code, self.entry(a)), (200, {"title": "shop.test · a", "kind": "login"}), receipt)
        self.born(1, "OPENAI_A_KEY", "https://api.openai.com")               # and a key again: no birth, no site
        self.assertEqual(self.entry(a), {"title": "OPENAI_A_KEY", "kind": "api_key", "env": "OPENAI_A_KEY"})
        code, receipt = self.add(login=test_grants.KEY, title="OPENAI_API_KEY", kind="api_key", env="OPENAI_API_KEY",
                                 fingerprints=self.prints(test_grants.KEY), address="https://api.openai.com")
        self.assertEqual(code, 200, receipt)                              # a key of the list from before: no birth
        self.assertEqual(self.entry(test_grants.KEY), {"title": "OPENAI_API_KEY", "kind": "api_key", "env": "OPENAI_API_KEY"})

    def test_a_key_that_something_holds_gets_no_site(self):
        ref = self.ref(1)
        with patch.object(hub, "profile_logins", lambda agent: {ref} if agent == "alpha" else set()):
            self.born(1, "PROFILED_KEY", "https://api.openai.com")             # a profile lists it
        self.assertNotIn("site", self.entry(ref))
        now = hub.now()
        hub.ins("INSERT INTO triggers(agent,state,revision,schedule,check_spec,task,late_minutes,max_tasks_per_day,anchor,"
                "created,updated,request_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                ("alpha", "active", 1, "every 1h", json.dumps({"path": "checks/url_lines.py", "args": {
                    "key": "CHECKED_KEY", "url": "https://api.openai.com/v1/models"}}), "Look at it.", 0, 1, now, now, now,
                 str(uuid.uuid4())))
        self.assertNotIn("site", self.entry(self.born(2, "CHECKED_KEY", "https://api.openai.com")))    # a check names it
        # each other holder, by the rule itself: a grant at each level, an account, an MCP server's key or variable
        team, new = self.committed(), self.ref(3)
        team["logins"][new] = {"title": "HELD_KEY", "kind": "api_key", "env": "HELD_KEY"}
        holders = {"read": lambda t: t["agents"]["alpha"].update(secrets={new: "read"}),
                   "use": lambda t: t["agents"]["beta"].update(secrets={new: "use"}),
                   "an account": lambda t: t.update(accounts={"a": {"secret": new}}),
                   "an MCP server's key": lambda t: t.update(mcp={"s": {"key": "HELD_KEY"}}),
                   "an MCP server's variable": lambda t: t.update(mcp={"s": {"env": {"TOKEN": "HELD_KEY"}}})}
        for why, hold in holders.items():
            with self.subTest(why):
                held = json.loads(json.dumps(team))
                hold(held)
                self.assertEqual(hub.key_table_site(held, new, "HELD_KEY", "openai", hub.key_hold_index(held)), {})
        self.assertEqual(hub.key_table_site(team, new, "HELD_KEY", "openai", hub.key_hold_index(team))["site"], OPENAI)
        self.assertEqual(hub.key_table_site(team, new, "HELD_KEY", "gone", hub.key_hold_index(team)), {})     # no such row now

    def test_an_import_gives_each_row_its_site_by_the_same_conditions_in_one_commit(self):
        before = self.commits()
        entries = []
        for n, env, address in ((1, "OPENAI_A_KEY", "https://platform.openai.com/settings/organization/api-keys"),
                                (2, "REPLICATE_B_TOKEN", "https://replicate.com/account/api-tokens"),
                                (3, "STRIPE_C_KEY", "https://dashboard.stripe.com/apikeys"), (4, "BARE_D_KEY", None)):
            entry = self.key(n, env, f"sk-example-import-{n:03d}-value")
            if address:
                entry["address"] = address
            entries.append(entry)
        code, receipt = self.importing(entries)
        self.assertEqual(code, 200, receipt)
        self.assertEqual(self.commits(), before + 1)
        catalog = self.committed()["logins"]
        self.assertEqual([(catalog[self.ref(n)].get("site"), (catalog[self.ref(n)].get("table") or {}).get("row"))
                          for n in (1, 2, 3, 4)], [(OPENAI, "openai"), (REPLICATE, "replicate"), (None, None), (None, None)])
        self.assertNotIn("replicate.com/account", json.dumps([dict(r) for r in hub.q("SELECT * FROM ui_controls")]))

    def test_the_owners_site_ends_the_mark_and_the_managers_switch_then_refuses_the_key(self):
        a = self.born(1, "OPENAI_A_KEY", "https://api.openai.com")
        self.assertEqual(self.label(a, "OPENAI_A_KEY")[0], 200)            # a title alone keeps the mark
        self.assertEqual(self.entry(a)["table"], {"row": "openai", "on": True})
        code, receipt = self.label(a, "OPENAI_A_KEY", site=OPENAI + "/v1")
        self.assertEqual(code, 200, receipt)
        self.assertEqual(self.entry(a), {"title": "OPENAI_A_KEY", "kind": "api_key", "env": "OPENAI_A_KEY",
                                         "site": OPENAI + "/v1", "form": "bearer"})        # the owner's lock
        text, error = self.switch("OPENAI_A_KEY", "off")
        self.assertTrue(error, text)
        self.assertIn("only the owner changes it", text)
        self.assertEqual(self.entry(a)["site"], OPENAI + "/v1")
        b = self.born(2, "OPENAI_B_KEY", "https://api.openai.com")         # a site taken away by the owner: no mark
        self.assertEqual(self.label(b, "OPENAI_B_KEY", site="")[0], 200)
        self.assertEqual(self.entry(b), {"title": "OPENAI_B_KEY", "kind": "api_key", "env": "OPENAI_B_KEY", "form": "bearer"})

    def test_the_managers_switch_takes_the_site_off_and_on_with_its_why(self):
        a = self.born(1, "OPENAI_A_KEY", "https://api.openai.com")
        self.assertEqual(self.grant(a, "alpha", "read")[0], 200)
        site = lambda: next(s.get("site") for s in self.vault_call("alpha", "read", {})[1]["secrets"] if s["login"] == a)
        self.assertEqual(site(), OPENAI)
        token = next(s["swap"] for s in self.vault_call("alpha", "read", {})[1]["secrets"] if s["login"] == a)
        use = dict(login=a, site=OPENAI, form="bearer", swap=token)     # a session that runs with the placeholder
        self.assertEqual(self.asks(**use)[0], 200)
        before = self.commits()
        text, error = self.switch("OPENAI_A_KEY", "off", why="its program sends the key to eu.api.openai.com")
        self.assertFalse(error, text)
        self.assertIn("is off", text)
        self.assertEqual(self.entry(a), {"title": "OPENAI_A_KEY", "kind": "api_key", "env": "OPENAI_A_KEY",
                                         "table": {"row": "openai", "on": False}})
        self.assertIsNone(site())                                          # the vault gives the value now
        self.assertEqual(self.asks(**use)[0], 409)          # and a session that runs with the placeholder gets no key
        message = subprocess.run(["git", "log", "-1", "--format=%s"], cwd=self.root / "kit", capture_output=True,
                                 text=True).stdout.strip()
        self.assertEqual(message, "Manager switched the table's site of OPENAI_A_KEY off: its program sends the key to "
                                  "eu.api.openai.com")
        self.assertEqual(len(self.log_lines("switched the table's site of OPENAI_A_KEY")), 1)
        text, error = self.switch("OPENAI_A_KEY", "off")                   # off already: nothing written
        self.assertFalse(error, text)
        self.assertEqual((self.commits(), "already" in text), (before + 1, True))
        text, error = self.switch(a, "on", why="it works with the placeholder again")     # by its reference
        self.assertFalse(error, text)
        self.assertEqual((self.entry(a)["site"], self.entry(a)["table"]), (OPENAI, {"row": "openai", "on": True}))
        self.assertEqual(site(), OPENAI)
        self.assertEqual(self.asks(**use)[0], 200)                       # the same placeholder works again
        for args, why in ((dict(key="OPENAI_A_KEY", to="up"), "to"), (dict(key="OPENAI_API_KEY", to="off"), "no mark"),
                          (dict(key="NO_SUCH_KEY", to="off"), "no key"), (dict(key="OPENAI_A_KEY", to="off", why=""), "why"),
                          (dict(key="OPENAI_A_KEY", to="off", why="two\nlines"), "one line"),
                          (dict(key="OPENAI_A_KEY", to="off", why="x" * (hub.GRANT_WHY_MAX + 1)), "long")):
            with self.subTest(why):
                text, error = self.switch(**args)
                self.assertTrue(error, text)
        text, error = self.switch("OPENAI_A_KEY", "off", agent="alpha")    # a worker has no such tool
        self.assertTrue(error, text)
        self.assertEqual(self.entry(a)["site"], OPENAI)
        # a later release takes the row out of the table: the list loads as it is, and "on" is refused
        self.assertFalse(self.switch("OPENAI_A_KEY", "off")[1])
        with patch.dict(lifecycle.KEY_TABLE, clear=True):
            hub.validate_team(self.committed())
            text, error = self.switch("OPENAI_A_KEY", "on")
            self.assertTrue(error, text)
            self.assertIn("no row openai any more", text)

    def test_a_team_json_with_a_row_that_the_table_does_not_have_loads_and_a_mark_of_another_shape_does_not(self):
        team, ref = self.committed(), test_grants.KEY
        base = team["logins"][ref]
        for good in (dict(base, site="https://api.gone.example", form="token", table={"row": "gone-service", "on": True}),
                     dict(base, table={"row": "gone-service", "on": False})):
            with self.subTest(good=good):
                hub.validate_team(dict(team, logins=dict(team["logins"], **{ref: good})))
        for bad in (dict(base, table={"row": "openai", "on": True}),                   # on with no site
                    dict(base, site=OPENAI, form="bearer", table={"row": "openai", "on": False}),     # off with a site
                    dict(base, site=OPENAI, table={"row": "openai", "on": True}),      # on with no form
                    dict(base, site="https://10.0.0.1", form="bearer", table={"row": "openai", "on": True}),
                    dict(base, site=OPENAI, form="bearer", table={"row": "Open AI", "on": True}),
                    dict(base, site=OPENAI, form="bearer", table={"row": "openai", "on": "yes"}),
                    dict(base, site=OPENAI, form="bearer", table={"row": "openai", "on": True, "by": "x"}),
                    dict(base, site=OPENAI, form="bearer", table="openai"),
                    {"title": "shop.test · a", "kind": "login", "table": {"row": "openai", "on": False}}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                hub.validate_team(dict(team, logins=dict(team["logins"], **{ref: bad})))

    def test_a_start_text_names_the_table_site_on_a_server_that_swaps_keys_by_the_owners_word(self):
        a = self.born(1, "OPENAI_A_KEY", "https://platform.openai.com/api-keys")
        self.assertEqual(self.grant(a, "alpha", "read")[0], 200)
        self.assertEqual(self.says("box", True)[0], 200)
        self.assertIn("OPENAI_A_KEY is for api.openai.com only, as Bearer: the variable holds a placeholder",
                      hub.key_words("alpha"))
        tid = hub.ins("INSERT INTO tasks(title,owner,requester,state,created,needs,attempt) VALUES(?,?,?,?,?,?,?)",
                      ("Work", "alpha", "manager", "working", hub.now(), "none", 1))
        start = hub.start_text("alpha", tid)                               # a task session's whole start text
        self.assertIn("WHAT YOU HOLD IN THIS SESSION", start)
        self.assertIn("OPENAI_A_KEY is for api.openai.com only, as Bearer: the variable holds a placeholder", start)
        self.assertIn("; OPENAI_A_KEY has its site from the fleet's table of well-known services: the fleet manager "
                      "can switch such a site off, and your next session then holds that key itself)", start)
        said = hub.holdings_start_text("alpha")             # the words raise the block's cap by their own length
        self.assertIn(hub.key_words("alpha"), said)
        self.assertLessEqual(len(said.strip()), hub.HOLDINGS_CHARS + len(hub.key_words("alpha")))
        self.assertIn("API keys in this session: OPENAI_A_KEY (OPENAI_A_KEY is for api.openai.com only",
                      " ".join(hub.holdings_parts("alpha")))
        self.assertEqual(hub.session_keys("alpha"), [])                    # no value of it in the sessions
        # the same key for an agent of Codex, whose own provider is OpenAI: no placeholder, a value as before
        team = self.committed()
        team["agents"]["beta"].update(secrets={a: "read"}, vault="broker")
        self.assertIsNone(lifecycle.key_swap(team, "beta", a))
        self.assertEqual(lifecycle.key_swap(team, "alpha", a), (OPENAI, "bearer"))

    def test_the_words_name_each_keys_form_and_kind_and_the_managers_own_acts(self):
        """The changed key swap, Part D (the manager's choice C41): on a server with the owner's word, each key's form
        beside its host, the clause on files and on what to do, and one clause for the table's keys and one for the
        owner's, each naming only its own keys; the manager's own acts in its own words; elsewhere the words of
        before."""
        a = self.born(1, "OPENAI_A_KEY", "https://api.openai.com")         # a site from the table: its mark is on
        self.assertEqual(self.grant(a, "alpha", "read")[0], 200)
        self.assertEqual(self.label(test_grants.KEY, "OPENAI_API_KEY", site="https://api.example.com",
                                    form="basic-password")[0], 200)       # the owner's own site, in another form
        self.assertEqual(self.grant(test_grants.KEY, "alpha", "read")[0], 200)
        before = hub.key_words("alpha")         # no owner's word yet: the words of before, with each key's form
        self.assertTrue(before.startswith(" (OPENAI_API_KEY is for api.example.com only, as the password of Basic, "
                                          "OPENAI_A_KEY is for api.openai.com only, as Bearer: when its value begins "
                                          "with vaultswap_"), before)
        self.assertNotIn("table of well-known services", before)
        self.assertNotIn("never write a placeholder", before)
        self.assertEqual(hub.key_words("alpha", short=True),
                         " (a placeholder when its value begins with vaultswap_: OPENAI_API_KEY for api.example.com "
                         "as the password of Basic, OPENAI_A_KEY for api.openai.com as Bearer)")
        self.assertEqual(self.says("box", True)[0], 200)
        shared = (": the variable holds a placeholder, which begins with vaultswap_, and not the key, and this machine's "
                  "vault puts the key in its place only in the Authorization header of an HTTPS request to that host, "
                  "in that form, and nowhere else; a request with the placeholder in another form or another place "
                  "gets a refusal; never write a placeholder into a file or into an application's configuration, on a "
                  "server or in a repository: it works only in this session's own requests; when a program needs the "
                  "key itself, sends it in another form, or the work must put a key into a configuration, ")
        self.assertEqual(hub.key_words("alpha"),
                         " (OPENAI_API_KEY is for api.example.com only, as the password of Basic, OPENAI_A_KEY is for "
                         "api.openai.com only, as Bearer" + shared + "ask your requester, say which key, which program "
                         "and what it answered, and do not look for the key; OPENAI_A_KEY has its site from the "
                         "fleet's table of well-known services: the fleet manager can switch such a site off, and your "
                         "next session then holds that key itself; OPENAI_API_KEY has the owner's own site, which only "
                         "the owner changes)")
        self.assertEqual(hub.key_words("alpha", short=True),
                         " (a placeholder, which begins with vaultswap_, and not the key: OPENAI_API_KEY for "
                         "api.example.com as the password of Basic, OPENAI_A_KEY for api.openai.com as Bearer; never in "
                         "a file or a configuration; when a program cannot use it, ask your requester; the fleet "
                         "manager can give your next session OPENAI_A_KEY itself)")
        with patch.dict(hub.agents()["alpha"], {"role": "manager"}):       # the manager's own acts, and no requester
            words, short = hub.key_words("alpha"), hub.key_words("alpha", short=True)
            self.assertNotIn("ask your requester", words + short)
            self.assertTrue(words.endswith(
                shared + "do not look for the key; OPENAI_A_KEY has its site from the fleet's table of well-known "
                "services: when a program cannot use the placeholder of such a key and the work needs the key, switch "
                "its site off with switch_key_site, and your next session then holds that key itself; OPENAI_API_KEY "
                "has the owner's own site, which only the owner changes: when a program cannot use the placeholder of "
                "such a key and the work needs the key, raise one Needs-you item)"), words)
            self.assertTrue(short.endswith(
                "; never in a file or a configuration; when a program cannot use OPENAI_A_KEY and the work needs it, "
                "switch that key's site off with switch_key_site; when a program cannot use OPENAI_API_KEY and the "
                "work needs it, raise a Needs-you item)"), short)
        # a manager with an owner's key alone: the item only under its condition, never as an order at each start (the
        # switch writes team.json and reads it again, so the manager's role is given after it)
        self.assertFalse(self.switch("OPENAI_A_KEY", "off")[1])
        with patch.dict(hub.agents()["alpha"], {"role": "manager"}):
            self.assertEqual(hub.key_words("alpha", short=True),
                             " (a placeholder, which begins with vaultswap_, and not the key: OPENAI_API_KEY for "
                             "api.example.com as the password of Basic; never in a file or a configuration; when a "
                             "program cannot use OPENAI_API_KEY and the work needs it, raise a Needs-you item)")
        self.assertFalse(self.switch("OPENAI_A_KEY", "on")[1])
        # each form in its words, as the proxy takes it (vault.swap_found)
        self.assertEqual(set(hub.KEY_FORM_WORDS), set(lifecycle.KEY_FORMS))
        for form, said in (("bearer", "as Bearer"), ("token", "as token"), ("basic-user", "as the user name of Basic"),
                           ("basic-password", "as the password of Basic")):
            with self.subTest(form=form):
                self.assertEqual(self.label(test_grants.KEY, "OPENAI_API_KEY", site="https://api.example.com",
                                            form=form)[0], 200)
                self.assertIn(f"OPENAI_API_KEY is for api.example.com only, {said}, OPENAI_A_KEY is for",
                              hub.key_words("alpha"))
        # the table's key switched off: a value, with no words of a placeholder, and the owner's key alone is named
        self.assertFalse(self.switch("OPENAI_A_KEY", "off")[1])
        words = hub.key_words("alpha")
        self.assertNotIn("OPENAI_A_KEY", words)
        self.assertNotIn("table of well-known services", words)
        self.assertTrue(words.endswith("; OPENAI_API_KEY has the owner's own site, which only the owner changes)"), words)
        self.assertFalse(self.switch("OPENAI_A_KEY", "on")[1])
        # a key that the vault left out at its last read gets no words (C11), and its clause goes with it
        hub.kv_set("read_missing:alpha", json.dumps({"OPENAI_API_KEY": "other"}))
        words = hub.key_words("alpha")
        self.assertNotIn("OPENAI_API_KEY", words)
        self.assertNotIn("the owner's own site", words)
        self.assertIn("OPENAI_A_KEY is for api.openai.com only, as Bearer", words)
        # a duty's text, through the real path of its run, has the short form
        self.assertIn("OPENAI_A_KEY (a placeholder, which begins with vaultswap_, and not the key: OPENAI_A_KEY for "
                      "api.openai.com as Bearer; never in a file or a configuration; when a program cannot use it, ask "
                      "your requester; the fleet manager can give your next session OPENAI_A_KEY itself)",
                      hub.duty_mechanism_text({"agent": "alpha"}))

    def test_the_settings_check_says_why_a_key_that_the_manager_switched_off_is_a_value(self):
        a = self.born(1, "OPENAI_A_KEY", "https://api.openai.com")
        self.assertEqual(self.grant(a, "alpha", "read")[0], 200)
        self.assertFalse(self.switch("OPENAI_A_KEY", "off")[1])
        keys, boxes = hub.settings_junction("alpha")
        self.assertEqual(keys, ["OPENAI_A_KEY"])
        words = hub.settings_words("alpha", keys, boxes)
        self.assertIn("The fleet manager switched the table's site of OPENAI_A_KEY off, so its sessions hold that key on "
                      "purpose: switch_key_site with to=on gives it the site again.", words)
        self.assertNotIn("Switch the key swap on", words)
        self.assertFalse(self.switch("OPENAI_A_KEY", "on")[1])
        self.assertNotIn("switched the table's site", hub.settings_words("alpha", ["OPENAI_A_KEY"], boxes))

    def test_the_step_that_only_counts_writes_nothing_and_counts_once(self):
        a = self.born(1, "OPENAI_A_KEY")                                   # no address at its birth
        b = self.born(2, "REPLICATE_B_TOKEN")
        self.assertEqual(self.grant(b, "alpha", "read")[0], 200)           # held
        self.assertEqual(self.label(test_grants.KEY, "OPENAI_API_KEY", site="https://api.example.com")[0], 200)
        rows = {a: "openai", b: "replicate", test_grants.KEY: "openai", self.ref(9): "openai"}   # the last: no entry
        sha, commits = self.team()["sha256"], self.commits()
        # a central vault whose status does not say that it serves the operation is not asked, at any tick
        with patch.object(hub, "central_call", lambda op, fields=None: self.fail(f"the central vault was asked {op}")):
            hub.key_table_count()
        self.assertIsNone(hub.kv_get(hub.KEY_TABLE_PASS))
        hub.CENTRAL["status"] = dict(hub.CENTRAL["status"], key_addresses=True)     # this fixture's patch restores it
        with patch.dict(hub.CENTRAL, error="this vault is another fleet's"), \
                patch.object(hub, "central_call", lambda op, fields=None: self.fail(f"the central vault was asked {op}")):
            hub.key_table_count()                                          # a read that was not good: not asked
        self.assertIsNone(hub.kv_get(hub.KEY_TABLE_PASS))
        with patch.object(hub, "central_call", lambda op, fields=None: {"ok": True, "rows": rows} if op == "key_addresses"
                          else self.fail(op)):
            hub.key_table_count()
            hub.key_table_count()                                          # a second run: the record holds it
        lines = self.log_lines("the table of well-known services counted")
        self.assertEqual(lines, ["the table of well-known services counted the list of 3 API keys and wrote nothing: it "
                                 "would give 1 a site (openai 1, replicate 0, cloudflare 0); left out: 0 with no "
                                 "address of a row, 1 with a site, 0 with a mark, 1 held, 0 of a row that is gone"])
        for word in ("OPENAI_A_KEY", "REPLICATE_B_TOKEN", "OPENAI_API_KEY", "bws://", "https://"):
            self.assertNotIn(word, lines[0])
        record = json.loads(hub.kv_get(hub.KEY_TABLE_PASS))
        self.assertEqual((record["step"], record["would"], record["keys"]), ("counted", {"openai": 1, "replicate": 0,
                                                                                         "cloudflare": 0}, 3))
        self.assertEqual((self.team()["sha256"], self.commits()), (sha, commits))   # nothing written
        self.assertNotIn("site", self.entry(a))
        # a central vault that does not know the operation yet: no record and no line, so a later tick counts
        hub.q("DELETE FROM kv WHERE k=?", (hub.KEY_TABLE_PASS,))

        def refuses(op, fields=None):
            raise hub.Refusal(409, "unknown operation")
        with patch.object(hub, "central_call", refuses):
            hub.key_table_count()
        self.assertIsNone(hub.kv_get(hub.KEY_TABLE_PASS))
        self.assertEqual(len(self.log_lines("the table of well-known services counted")), 1)
        # an answer of another shape: no fault, no row, and the record, so no tick asks again
        odd = {a: ["openai"], b: {"row": "openai"}, test_grants.KEY: 7}
        with patch.object(hub, "central_call", lambda op, fields=None: {"ok": True, "rows": odd}):
            hub.key_table_count()
        self.assertEqual(json.loads(hub.kv_get(hub.KEY_TABLE_PASS))["would"], {"openai": 0, "replicate": 0, "cloudflare": 0})
        self.assertEqual(self.log_lines("the table of well-known services counted")[-1],
                         "the table of well-known services counted the list of 3 API keys and wrote nothing: it would "
                         "give 0 a site (openai 0, replicate 0, cloudflare 0); left out: 3 with no address of a row, "
                         "0 with a site, 0 with a mark, 0 held, 0 of a row that is gone")

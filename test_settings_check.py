"""The settings check (hub.settings_check): an agent whose settings put three things together -- its sessions hold the
value of a key, it has a shell, and its Tools boxes give it the web -- gets one finding on the fleet manager's list of
proposals for the owner, as the hub's own report. In-process hub, a temporary database and a set clock; no helper, no
fleet and no AI call.

What it holds: one finding for each state and never one for each run, a new finding when the settings change, the end
of an open finding whose settings are gone, no message and no chase for it, and a check that stops nothing.
"""
import inspect
import itertools
import json
import re
import unittest
from pathlib import Path
from unittest.mock import patch

import fleet
import hub
from leftovers import scratch_home
from test_ui_api import OwnerAPI

KEY_A = "bws://11111111-2222-4333-8444-55555555550a"
KEY_B = "bws://11111111-2222-4333-8444-55555555550b"
KEY_C = "bws://11111111-2222-4333-8444-55555555550c"
KEY_D = "bws://11111111-2222-4333-8444-55555555550e"
KEY_E = "bws://11111111-2222-4333-8444-55555555550f"
LOGIN = "bws://11111111-2222-4333-8444-55555555550d"
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "box-1": "127.0.0.3", "box-2": "127.0.0.4",
                      "box-3": "127.0.0.5", "box-4": "127.0.0.6"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": ["shell", "web"]},
                   # the case: two keys that it reads, a shell and the web
                   "dev-lead": {"role": "worker", "runtime": "claude", "machine": "box-1", "can": ["shell", "web"],
                                "title": "Developer", "vault": "broker",
                                "secrets": {KEY_A: "read", KEY_B: "read", LOGIN: "use"}},
                   # each of these has two of the three
                   "support": {"role": "worker", "runtime": "claude", "machine": "box-2", "can": ["web"],
                               "vault": "broker", "secrets": {KEY_A: "read"}},
                   "writer": {"role": "worker", "runtime": "claude", "machine": "box-3", "can": ["shell"],
                              "vault": "broker", "secrets": {KEY_A: "read"}},
                   "caller": {"role": "worker", "runtime": "claude", "machine": "box-4", "can": ["shell", "web"],
                              "vault": "broker", "secrets": {KEY_A: "use", LOGIN: "use"}}},
        "logins": {KEY_A: {"title": "ACME_API_KEY", "kind": "api_key", "env": "ACME_API_KEY",
                           "site": "https://api.example.com"},
                   KEY_B: {"title": "SHOP_API_KEY", "kind": "api_key", "env": "SHOP_API_KEY",
                           "site": "https://shop.example.com"},
                   KEY_C: {"title": "MAIL_API_KEY", "kind": "api_key", "env": "MAIL_API_KEY",
                           "site": "https://mail.example.com"},
                   # two keys that no HTTP request uses: their logins name no site
                   KEY_D: {"title": "DB_READ_PASSWORD", "kind": "api_key", "env": "DB_READ_PASSWORD"},
                   KEY_E: {"title": "PACKAGES_TOKEN", "kind": "api_key", "env": "PACKAGES_TOKEN"},
                   LOGIN: {"title": "shop.example.com · admin", "kind": "login"}},
        "goals": {"timezone": "Europe/Madrid", "review_hour": 9, "sweep_minutes": 15}}


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def load_tests(loader, _tests, _pattern):
    """Only this file's cases, not the inherited OwnerAPI ones."""
    suite = unittest.TestSuite()
    for cls in (Keys, Start, Finding, States, Manager, Junctions):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Base(OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        self.clock = 1_794_000_000.0
        clock = patch.object(hub, "now", lambda: self.clock)
        clock.start()
        self.addCleanup(clock.stop)

    def agent(self, name="dev-lead"):
        return hub.TEAM["agents"][name]

    def reports(self):
        return [dict(r) for r in hub.q("SELECT * FROM reports ORDER BY id")]

    def open(self):
        return [r["id"] for r in self.reports() if r["decided"] is None]

    def mark(self, name="dev-lead"):
        value = hub.kv_get(f"settings_finding:{name}")
        return json.loads(value) if value else None

    def manager(self, name, **args):
        text, err = hub.call_tool("manager", name, args)
        self.assertFalse(err, text)
        return text


class Keys(Base):
    """The one answer to "do this agent's sessions hold the value of a key" (hub.session_keys)."""

    def test_a_read_grant_of_an_api_key_is_in_the_sessions_by_its_name(self):
        self.assertEqual(hub.session_keys("dev-lead"), ["ACME_API_KEY", "SHOP_API_KEY"])

    def test_a_use_grant_and_a_login_are_not(self):
        self.assertEqual(hub.session_keys("caller"), [])
        self.agent("caller")["secrets"][LOGIN] = "read"         # a team.json written by hand: a login is no API key
        self.assertEqual(hub.session_keys("caller"), [])
        self.assertEqual(hub.session_keys("manager"), [])       # no grant at all
        self.assertEqual(hub.session_keys("nobody"), [])        # and no such agent

    def test_a_session_of_an_agent_whose_shell_box_is_off_gets_no_key(self):
        self.assertEqual(hub.session_keys("support"), [])
        self.agent("support")["can"] = ["shell", "web"]
        self.assertEqual(hub.session_keys("support"), ["ACME_API_KEY"])

    def test_only_an_agent_whose_vault_is_its_machine_s_broker_gets_a_key(self):
        """The helper asks for the values only for an agent whose team.json entry says `"vault": "broker"`
        (fleet.vault_mode): "none", the old "file" and an entry that says nothing are all no credential access."""
        for vault in ("none", "file", None):
            with self.subTest(vault):
                self.agent().pop("vault", None)
                if vault:
                    self.agent()["vault"] = vault
                self.assertEqual(hub.session_keys("dev-lead"), [])
                self.assertIsNone(hub.settings_junction("dev-lead"))

    def test_an_agent_with_no_tools_list_and_the_manager_have_a_shell(self):
        del self.agent()["can"]
        self.assertEqual(hub.session_keys("dev-lead"), ["ACME_API_KEY", "SHOP_API_KEY"])
        # only a worker or a lead has a Shell box
        self.agent("manager").update(can=[], vault="broker", secrets={KEY_C: "read"})
        self.assertEqual(hub.session_keys("manager"), ["MAIL_API_KEY"])

    def session_gets(self, name):
        """The names of the keys that a session of this agent gets, from the code that gives them: the helper's own
        rule (fleet.session_env), with a vault that has a value for each key that the hub's route names for it."""
        conf = hub.TEAM["agents"][name]
        kit = Path(self.tmp.name) / "kit"
        kit.mkdir(exist_ok=True)
        (kit / "team.json").write_text(json.dumps(hub.TEAM))

        def vault(agent, request, timeout=60):
            code, data = self.request(f"/helper/vault/{agent}/read", {"for": request["for"]},
                                      source=hub.address_of(agent))
            if code != 200:
                raise fleet.Refused(data["error"])
            return {"env": {secret["env"]: "a-value" for secret in data["secrets"]}}
        with patch.object(fleet, "KIT", str(kit)), patch.object(fleet, "TEAM", hub.TEAM), \
                patch.object(fleet, "broker_job_request", vault), \
                patch.object(fleet, "integration_env", return_value={}), patch("builtins.print"):
            return sorted(fleet.session_env(name, conf, "manager" if conf["role"] == "manager" else "task"))

    def test_it_says_what_a_session_gets_from_the_helper_and_the_hub(self):
        """session_keys is the hub's one answer, and the helper (fleet.session_env, read_env) with the hub's route
        (Handler.helper_vault_read) is what gives a session its keys. A change of how a key reaches a session that
        does not change session_keys too fails here."""
        cases = {"dev-lead": {}, "support": {}, "writer": {}, "caller": {},        # the fixture's four
                 "manager": {"vault": "broker", "secrets": {KEY_C: "read"}},
                 "dev-lead with no vault": {"vault": None}, "dev-lead with none": {"vault": "none"},
                 "dev-lead with file": {"vault": "file"}, "dev-lead with no Tools list": {"can": None},
                 "dev-lead with a grant of no login": {"secrets": {KEY_A: "read", LOGIN: "read",
                                                                   "bws://99999999-2222-4333-8444-555555555550": "read"}},
                 "support with Shell on": {"can": ["shell", "web"]}}
        got = {}
        for case, changes in cases.items():
            with self.subTest(case):
                hub.TEAM = json.loads(json.dumps(TEAM))
                name = case.split(" ")[0]
                for field, value in changes.items():
                    if value is None:
                        del self.agent(name)[field]
                    else:
                        self.agent(name)[field] = value
                got[case] = self.session_gets(name)
                self.assertEqual(hub.session_keys(name), got[case])
                self.assertEqual([env for _ref, env in hub.session_variables(name)], got[case])
        self.assertEqual(got["dev-lead"], ["ACME_API_KEY", "SHOP_API_KEY"])        # and the route does give names
        self.assertEqual((got["manager"], got["writer"], got["support with Shell on"]),
                         (["MAIL_API_KEY"], ["ACME_API_KEY"], ["ACME_API_KEY"]))
        self.assertEqual([case for case, names in got.items() if not names],
                         ["support", "caller", "dev-lead with no vault", "dev-lead with none", "dev-lead with file"])

    def test_the_hub_refuses_a_key_for_a_session_of_an_agent_whose_shell_box_is_off(self):
        """The helper of such an agent does not ask. The hub's route refuses also when it does, so session_keys is
        right whatever that helper read of its box."""
        code, data = self.request("/helper/vault/support/read", {"for": "session"}, source=hub.address_of("support"))
        self.assertEqual((code, data["error"]), (409, "a session of support gets no key: its Shell box is off"))
        code, data = self.request("/helper/vault/support/read", {"for": "check"}, source=hub.address_of("support"))
        self.assertEqual((code, [x["env"] for x in data["secrets"]]), (200, ["ACME_API_KEY"]))    # its checks do


class Start(Keys):
    """What a start text says of the keys of a session (hub.holdings_parts in a task's start, hub.duty_toolbox in a
    duty's task): the variables that the session gets, and no key that it does not get."""

    def named(self, name):
        """The key names of the two clauses, each as a list: the task start's, and the duty toolbox's."""
        texts = (("; ".join(hub.holdings_parts(name)), "API keys in this session: "),
                 (hub.duty_toolbox(name), "API keys in your session: "))
        found = [re.search(re.escape(head) + "([A-Z0-9_, ]+)", text) for text, head in texts]
        return [m.group(1).strip().split(", ") if m else [] for m in found]

    def test_it_names_the_keys_that_the_session_gets(self):
        self.agent("manager").update(vault="broker", secrets={KEY_C: "read"})
        for name, keys in (("dev-lead", ["ACME_API_KEY", "SHOP_API_KEY"]), ("writer", ["ACME_API_KEY"]),
                           ("manager", ["MAIL_API_KEY"]), ("caller", [])):
            with self.subTest(name):
                self.assertEqual(self.session_gets(name), keys)
                self.assertEqual(self.named(name), [keys, keys])

    def test_it_names_no_key_for_an_agent_with_no_vault_broker(self):
        """A read grant waits while the vault of the agent's machine is not ready (hub.save_grant), and the helper
        asks for no value then (fleet.vault_mode). The start text said "API keys in this session" all the same."""
        for vault in ("none", "file", None):
            with self.subTest(vault):
                self.agent().pop("vault", None)
                if vault:
                    self.agent()["vault"] = vault
                self.assertEqual(self.session_gets("dev-lead"), [])
                self.assertEqual(self.named("dev-lead"), [[], []])
                self.assertNotIn("API keys in", hub.holdings_start_text("dev-lead") + hub.duty_toolbox("dev-lead"))

    def test_it_names_no_key_for_an_agent_whose_shell_box_is_off(self):
        self.assertEqual((self.session_gets("support"), self.named("support")), ([], [[], []]))

    def test_it_still_names_a_key_that_swaps_because_the_variable_is_there(self):
        """On a server whose vault swaps keys the session gets the variable with a placeholder: the start text names
        it and says what it holds (hub.key_words, the key swap lane), and the settings check does not count it."""
        hub.TEAM["servers"] = {"box-1": {"kind": "linux", "key_swap": True}}
        self.assertEqual(self.named("dev-lead"), [["ACME_API_KEY", "SHOP_API_KEY"]] * 2)
        self.assertIn("the variable holds a placeholder", "; ".join(hub.holdings_parts("dev-lead")))
        self.assertEqual(hub.session_keys("dev-lead"), [])


class Finding(Base):
    """Which settings are the case, and what the finding says."""

    def test_the_three_together_are_the_case_and_two_of_them_are_not(self):
        self.assertEqual(hub.settings_junction("dev-lead"), (["ACME_API_KEY", "SHOP_API_KEY"], ["web"]))
        for name in ("manager", "support", "writer", "caller"):
            with self.subTest(name):
                self.assertIsNone(hub.settings_junction(name))

    def test_the_browser_box_is_the_web_too_and_no_tools_list_has_both(self):
        self.agent()["can"] = ["shell", "browser"]
        self.assertEqual(hub.settings_junction("dev-lead")[1], ["browser"])
        self.agent()["can"] = ["browser", "screen", "web", "shell"]
        self.assertEqual(hub.settings_junction("dev-lead")[1], ["web", "browser"])
        self.agent()["can"] = ["shell", "screen"]               # the screen alone is not one of the boxes
        self.assertIsNone(hub.settings_junction("dev-lead"))
        del self.agent()["can"]
        self.assertEqual(hub.settings_junction("dev-lead"), (["ACME_API_KEY", "SHOP_API_KEY"], None))

    def test_one_finding_goes_to_the_manager_s_list_as_the_hub_s_own_report(self):
        events = hub.q1("SELECT COUNT(*) n FROM events")["n"]
        self.assertEqual(hub.settings_check(), [1])
        (row,) = self.reports()
        self.assertEqual((row["from_agent"], row["from_task"], row["to_agent"], row["kind"], row["about"]),
                         ("hub", None, "manager", "proposal", "dev-lead"))
        self.assertEqual((row["severity"], row["delivered"], row["event_id"], row["decided"]),
                         ("note", "note", None, None))
        self.assertTrue(row["request_id"].startswith("settings:"))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events")["n"], events)     # no message, and nobody is woken
        self.assertEqual(self.mark(), {"keys": ["ACME_API_KEY", "SHOP_API_KEY"], "boxes": ["web"], "report": 1})
        self.assertIn("settings check: UP-1", hub.q1("SELECT what FROM log WHERE agent='hub' ORDER BY id DESC")["what"])

    def test_it_names_the_agent_by_its_role_the_keys_by_name_and_the_boxes(self):
        hub.settings_check()
        text = self.reports()[0]["text"]
        self.assertTrue(text.startswith("Developer reads 2 API keys in its sessions (ACME_API_KEY, SHOP_API_KEY), and "
                                        "it has a shell and the web (Tools: Shell, Web). A text from outside, a web "
                                        "page for example, can then make it send a key to another place."), text)
        self.assertNotIn("dev-lead", text)                      # the name is in `about`, a field
        self.assertNotIn("bws://", text)
        self.assertNotIn("UP-", text)
        self.assertEqual(text, " ".join(text.split()))          # one line, as clip keeps it
        self.assertLessEqual(len(text), hub.REPORT_TEXT_MAX)

    def test_it_gives_the_three_options_each_with_its_cost_and_how_to_undo_it(self):
        hub.settings_check()
        text = self.reports()[0]["text"]
        self.assertIn(" The choice is the owner's: put these three options on your weekly list. (1) ", text)
        one, two, three = text.split(" (1) ")[1].split(" (2) ")[0], text.split(" (2) ")[1].split(" (3) ")[0], \
            text.split(" (3) ")[1]
        self.assertEqual(one, "Change the grant of each key from read to use: the vault keeps the key, and Developer "
                              "calls the service with call_api. Cost: each command or saved check that reads the key "
                              "from its variable fails until somebody changes it. To undo: give read again.")
        self.assertEqual(two, "Set Web off for Developer. Cost: its start no longer tells it that it has the web. With "
                              "Shell on, Web off removes no tool from its sessions. Its shell still reaches the "
                              "internet, so most of the risk stays. To undo: set it on again.")
        # the manager closes it as noted only on the owner's word, and reads what the hub does then
        self.assertEqual(three, "Leave it as it is. Cost: the risk stays. When the owner chooses this, decide this "
                                "report as noted. The hub makes no second finding while these settings stay.")

    def test_the_second_option_follows_the_boxes(self):
        both = hub.settings_words("dev-lead", ["ACME_API_KEY"], ["web", "browser"])
        self.assertIn("reads 1 API key in its sessions (ACME_API_KEY)", both)
        self.assertIn("(Tools: Shell, Web, Browser)", both)
        self.assertIn("(1) Change the grant of the key from read to use", both)
        self.assertIn("(2) Set Web and Browser off for Developer. Cost: its start no longer tells it that it has the "
                      "web, and it takes no browser task. With Shell on, Web off removes no tool from its sessions. Its "
                      "shell still reaches the internet, so most of the risk stays. To undo: set them on again. (3)",
                      both)
        browser = hub.settings_words("dev-lead", ["ACME_API_KEY"], ["browser"])
        self.assertIn("(2) Set Browser off for Developer. Cost: it takes no browser task. Its shell still reaches the "
                      "internet, so most of the risk stays. To undo: set it on again. (3)", browser)
        self.assertNotIn("Web off", browser)

    def test_an_agent_with_no_tools_list_gets_words_that_are_true_of_it(self):
        bare = hub.settings_words("dev-lead", ["ACME_API_KEY"], None)
        self.assertIn("(it has no Tools list, so its sessions have both)", bare)
        self.assertIn("(2) Give Developer a Tools list with Shell on and Web off. Cost: none. With Shell on, Web off "
                      "removes no tool from its sessions.", bare)
        self.assertIn("To undo: set Web on again. (3)", bare)
        del self.agent()["title"]                               # an agent with no role is named by its name
        self.assertTrue(hub.settings_words("dev-lead", ["ACME_API_KEY"], ["web"]).startswith("Dev-Lead reads 1 "))

    def test_the_tools_boxes_of_a_manager_are_no_part_of_its_case(self):
        """Nothing reads a manager's Tools boxes: its sessions have the shell and the web tools of its runtime
        whatever they say. So a manager whose sessions hold a key is the case with each list of boxes, a change of
        its boxes is no new state, and its finding does not give the boxes as an option."""
        self.agent().pop("secrets")                             # only the manager is the case here
        self.agent("manager").update(title="Fleet Manager", vault="broker", secrets={KEY_C: "read"})
        for can in (["shell", "web"], [], ["web", "browser"], None):
            with self.subTest(can):
                self.agent("manager").pop("can", None)
                if can is not None:
                    self.agent("manager")["can"] = can
                self.assertEqual(hub.settings_junction("manager"), (["MAIL_API_KEY"], None))
                self.assertEqual(hub.settings_check(), [1] if can == ["shell", "web"] else [])
        text = self.reports()[0]["text"]
        self.assertTrue(text.startswith("Fleet Manager reads 1 API key in its sessions (MAIL_API_KEY), and it has "
                                        "a shell and the web (its sessions have both, whatever its Tools boxes say)."))
        self.assertIn("The choice is the owner's: put these two options on your weekly list. (1) Change the grant of "
                      "the key from read to use: the vault keeps the key, and a worker or a lead that has a use grant "
                      "of it calls the service with call_api.", text)         # a manager has no call_api
        self.assertTrue(text.endswith("To undo: give read again. (2) Leave it as it is. Cost: the risk stays. When the "
                                      "owner chooses this, decide this report as noted. The hub makes no second "
                                      "finding while these settings stay."), text)
        for words in ("(3)", "Tools list", "Set Web", "off for"):
            self.assertNotIn(words, text)

    def test_a_manager_whose_key_fits_no_option_has_one_option(self):
        self.agent("manager").update(title="Fleet Manager", vault="broker", secrets={KEY_D: "read"})
        text = hub.settings_words("manager", ["DB_READ_PASSWORD"], None)
        self.assertTrue(text.endswith(
            "can then make it send a key to another place. Nothing takes a key out of its sessions now: a use grant "
            "needs the https site of the key on its login, and this login names none. The choice is the owner's: put "
            "this one option on your weekly list. (1) Leave it as it is. Cost: the risk stays. When the owner chooses "
            "this, decide this report as noted. The hub makes no second finding while these settings stay."), text)

    def words(self, secrets, **team):
        """The finding about dev-lead with these grants, and with these parts of team.json."""
        self.agent()["secrets"] = secrets
        hub.TEAM.update(team)
        keys, boxes = hub.settings_junction("dev-lead")
        return hub.settings_words("dev-lead", keys, boxes)

    def test_a_use_grant_is_an_option_only_for_a_key_whose_login_names_its_site(self):
        """call_api sends its request to the https site of the key's login. A key with no site there, a database
        password for example, cannot go that way, so the option does not name it."""
        place = "can then make it send a key to another place."
        each = self.words({KEY_A: "read", KEY_B: "read"})
        self.assertIn(f"{place} The choice is the owner's: put these three options on your weekly list. (1) Change "
                      f"the grant of each key from read to use: the vault", each)
        one = self.words({KEY_A: "read", KEY_D: "read"})
        self.assertIn(f"{place} Only ACME_API_KEY fits the next option: a use grant needs the https site of the key on "
                      f"its login. The choice is the owner's: put these three options on your weekly list. (1) Change "
                      f"the grant of that key from read to use: the vault keeps the key, and Developer calls", one)
        two = self.words({KEY_A: "read", KEY_B: "read", KEY_D: "read", KEY_E: "read"})
        self.assertIn(f"{place} Only ACME_API_KEY, SHOP_API_KEY fit the next option: a use grant needs the https site "
                      f"of the key on its login. The choice", two)
        self.assertIn("(1) Change the grant of those keys from read to use: the vault", two)
        for text in (each, one, two):
            self.assertIn(" (2) Set Web off for Developer.", text)

    def test_the_words_say_plainly_when_no_option_takes_a_key_out_of_the_sessions(self):
        none = self.words({KEY_D: "read", KEY_E: "read"})
        self.assertTrue(none.endswith(
            "can then make it send a key to another place. Nothing takes a key out of its sessions now: a use grant "
            "needs the https site of the key on its login, and none of these logins names one. The choice is the "
            "owner's: put these two options on your weekly list. (1) Set Web off for Developer. Cost: its start no "
            "longer tells it that it has the web. With Shell on, Web off removes no tool from its sessions. Its shell "
            "still reaches the internet, so most of the risk stays. To undo: set it on again. (2) Leave it as it is. "
            "Cost: the risk stays. When the owner chooses this, decide this report as noted. The hub makes no second "
            "finding while these settings stay."), none)
        for words in ("call_api", "read to use", "Switch the key swap"):
            self.assertNotIn(words, none)
        one = self.words({KEY_D: "read"})
        self.assertIn("of the key on its login, and this login names none. The choice", one)
        linux = self.words({KEY_D: "read"}, servers={"box-1": {"kind": "linux"}})      # where the key swap can be
        self.assertIn("now: a use grant and the key swap need the https site of the key on its login, and this", linux)

    SWAP = ("Switch the key swap on for its server box-1 (WORKER-INSTALL.md says how): the vault then keeps {} out "
            "of its sessions, and it puts the key into the Authorization header of an HTTPS request to the key's "
            "site. Cost: a program that uses the key in another way fails. To undo: switch it off again.")

    def test_the_key_swap_is_an_option_for_a_key_that_can_swap_on_a_linux_server_that_does_not_swap_yet(self):
        """The key swap lane's rule (hub.key_swap) says which key can swap, and the owner's command takes the word
        only for a Linux server (hub.server_key_swap). A key that swaps already is no key of the case."""
        linux = {"box-1": {"kind": "linux"}}
        text = self.words({KEY_A: "read", KEY_B: "read"}, servers=linux)
        self.assertIn("put these four options on your weekly list. (1) Change the grant of each key from read", text)
        self.assertIn(f"To undo: give read again. (2) {self.SWAP.format('each key')} (3) Set Web off for", text)
        self.assertIn("so most of the risk stays. To undo: set it on again. (4) Leave it as it is.", text)
        part = self.words({KEY_A: "read", KEY_D: "read"}, servers=linux)
        self.assertIn(" Only ACME_API_KEY fits the next two options: a use grant and the key swap need the https site "
                      "of the key on its login. The choice is the owner's: put these four options", part)
        self.assertIn(f"(2) {self.SWAP.format('that key')} (3)", part)
        # a key that an MCP server names does not swap, and a use grant still fits it: the option names the other
        named = self.words({KEY_A: "read", KEY_B: "read"}, servers=linux, mcp={"crm": {"key": "ACME_API_KEY"}})
        self.assertIn("(1) Change the grant of each key from read to use", named)
        self.assertIn(f"(2) {self.SWAP.format('SHOP_API_KEY')} (3)", named)
        self.assertEqual(hub.key_swap("dev-lead", KEY_A), None)
        self.assertEqual(hub.key_swap("dev-lead", KEY_B), ("https://shop.example.com", "bearer"))
        # the sentence before the options says "two options" only where both fit the same keys
        mixed = self.words({KEY_A: "read", KEY_B: "read", KEY_D: "read"})
        self.assertIn(" Only ACME_API_KEY, SHOP_API_KEY fit the next option: a use grant and the key swap need the "
                      "https site of the key on its login. The choice", mixed)
        self.assertIn("(1) Change the grant of those keys from read to use", mixed)
        self.assertIn(f"(2) {self.SWAP.format('SHOP_API_KEY')} (3)", mixed)

    def test_the_key_swap_option_counts_the_keys_of_the_other_agents_of_the_server_that_swap_with_it(self):
        """Root switches the key swap on for a whole server: each key there that can swap, in the sessions of each
        agent there, swaps then. The cost says how many keys of how many other agents that is, and nothing where no
        key of another agent swaps."""
        both, linux = {KEY_A: "read", KEY_B: "read"}, {"box-1": {"kind": "linux"}}
        cost = "HTTPS request to the key's site. Cost: {}a program that uses the key in another way fails. To undo: "
        self.assertIn(cost.format(""), self.words(both, servers=linux))    # alone on its server
        self.agent("writer")["machine"] = "box-1"               # it reads ACME_API_KEY, which has a site
        self.assertIn(cost.format("it also swaps 1 key of another agent of that server, and "), self.words(both))
        self.agent("writer")["secrets"] = {KEY_A: "read", KEY_C: "read", KEY_D: "read"}     # the third has no site
        self.assertIn(cost.format("it also swaps 2 keys of another agent of that server, and "), self.words(both))
        self.agent("manager").update(machine="box-1", vault="broker", secrets={KEY_C: "read"})
        # a key that two of them read is one key
        self.assertIn(cost.format("it also swaps 2 keys of 2 other agents of that server, and "), self.words(both))
        self.agent("writer")["secrets"] = {KEY_C: "read"}
        self.assertIn(cost.format("it also swaps 1 key of 2 other agents of that server, and "), self.words(both))
        # no key of these agents swaps with it: a use grant, a key with no site, a Shell box that is off, no vault
        # broker, an agent of another server, and an entry that cannot be read
        self.agent("manager")["machine"] = "hub"
        self.agent("writer")["secrets"] = {KEY_A: "use", KEY_D: "read"}
        self.agent("caller")["machine"] = "box-1"
        self.agent("support")["machine"] = "box-1"
        hub.TEAM["agents"]["plain"] = {"role": "worker", "runtime": "claude", "machine": "box-1", "can": ["shell"],
                                       "secrets": {KEY_A: "read"}}
        hub.TEAM["agents"]["odd"] = "no entry"
        hub.TEAM["agents"]["bent"] = {"role": "worker", "machine": "box-1", "vault": "broker", "secrets": ["no map"]}
        self.assertIn(cost.format(""), self.words(both))
        self.assertIn(f"(2) {self.SWAP.format('each key')} (3)", self.words(both))

    def test_the_key_swap_is_no_option_where_it_cannot_be_switched_on(self):
        both = {KEY_A: "read", KEY_B: "read"}
        cases = {"a Mac": dict(servers={"box-1": {"kind": "mac"}}), "no joined server": dict(servers={}),
                 "an entry of a wrong shape": dict(servers={"box-1": "linux"})}
        for case, team in cases.items():
            with self.subTest(case):
                text = self.words(both, **team)
                self.assertIn("put these three options on your weekly list", text)
                self.assertNotIn("key swap", text)
        self.agent()["runtime"] = "opencode"                    # a program with no hosts in the table: no key swaps
        text = self.words(both, servers={"box-1": {"kind": "linux"}})
        self.assertIn("put these three options on your weekly list", text)
        self.assertNotIn("key swap", text)
        text = self.words({KEY_A: "read", KEY_D: "read"})       # and a site makes no key swap there: the words name none
        self.assertIn(" Only ACME_API_KEY fits the next option: a use grant needs the https site of the key on", text)
        self.assertNotIn("key swap", text)

    def test_on_a_server_that_swaps_keys_the_option_is_not_there_and_the_placeholders_are_no_keys_of_the_case(self):
        swaps = {"box-1": {"kind": "linux", "key_swap": True}}
        self.agent()["secrets"] = {KEY_A: "read", KEY_B: "read"}
        hub.TEAM["servers"] = swaps
        self.assertIsNone(hub.settings_junction("dev-lead"))    # each key is a placeholder: no case
        text = self.words({KEY_A: "read", KEY_D: "read"}, servers=swaps)
        self.assertTrue(text.startswith(
            "Developer reads 1 API key in its sessions (DB_READ_PASSWORD), and it has a shell and the web (Tools: "
            "Shell, Web). 1 more key is not in its sessions: the vault of its server swaps it, so a session holds a "
            "placeholder (ACME_API_KEY). A text from outside, a web page for example, can then make it send a key to "
            "another place. Nothing takes a key out of its sessions now: a use grant and the key swap need the https "
            "site of the key on its login, and this login names none. The choice is the owner's: put these two "
            "options on your weekly list. (1) Set Web off for Developer."), text)
        self.assertNotIn("Switch the key swap", text)

    def long_team(self, sites, kind="linux", swap=False, can=("shell", "web", "browser"), mcp=0, role="worker"):
        """dev-lead with the longest role, server name and 40 key names that team.json takes. sites: which of the
        keys have a site. mcp: how many of those an MCP server names, so that they do not swap."""
        server, keys = "a" + "b" * 30, [f"K{n:02d}_" + "A" * 56 for n in range(40)]
        refs = [f"bws://11111111-2222-4333-8444-5555555555{n:02d}" for n in range(40)]
        hub.TEAM["logins"] = {ref: dict({"title": f"K{n:02d}", "kind": "api_key", "env": keys[n]},
                                        **({"site": f"https://s{n}.example.com"} if n in sites else {}))
                              for n, ref in enumerate(refs)}
        hub.TEAM["servers"] = {server: dict({"kind": kind}, **({"key_swap": True} if swap else {}))}
        hub.TEAM["mcp"] = {f"tool-{n}": {"key": keys[n]} for n in sorted(sites)[:mcp]}
        self.agent().update(title="R" * 60, machine=server, role=role, secrets={ref: "read" for ref in refs})
        self.agent().pop("can", None)
        if can is not None:
            self.agent()["can"] = list(can)
        self.assertTrue(hub.ENV_NAME.fullmatch(keys[0]) and hub.SERVER_NAME.fullmatch(server))
        return keys

    def test_the_longest_finding_stays_inside_one_report(self):
        patterns = {"each": range(40), "half": range(1, 40, 2), "one": [0], "none": []}
        longest = 0
        for sites, kind, swap, can, mcp, role in itertools.product(
                patterns, ("linux", "mac"), (False, True),
                (("shell", "web", "browser"), ("shell", "web"), ("shell", "browser"), None), (0, 1, 6),
                ("worker", "manager")):
            if swap and kind != "linux":
                continue
            with self.subTest(sites=sites, kind=kind, swap=swap, can=can, mcp=mcp, role=role):
                self.long_team(set(patterns[sites]), kind, swap, can, mcp, role)
                found = hub.settings_junction("dev-lead")
                if found:
                    text = hub.settings_words("dev-lead", *found)
                    self.assertLessEqual(len(text), hub.REPORT_TEXT_MAX)
                    self.assertEqual(text, " ".join(text.split()))
                    longest = max(longest, len(text))
        self.assertGreater(longest, hub.REPORT_TEXT_MAX - 200)  # and the cases do reach the length of one report

    def test_a_finding_that_is_too_long_names_fewer_of_its_keys_and_then_counts_the_keys_of_an_option(self):
        def text():
            found = hub.settings_words("dev-lead", *hub.settings_junction("dev-lead"))
            self.assertLessEqual(len(found), hub.REPORT_TEXT_MAX)
            return found
        keys = self.long_team(set())                            # no key with a site: eight names
        self.assertIn(f"reads 40 API keys in its sessions ({', '.join(keys[:8])} and 32 more)", text())
        self.assertIn("none of these logins names one", text())
        keys = self.long_team({1, 3})                           # two keys fit both options: four names, and those two
        self.agent()["title"] = "Developer"
        self.assertIn(f"sessions ({', '.join(keys[:4])} and 36 more)", text())
        self.assertIn(f" Only {keys[1]}, {keys[3]} fit the next two options: a use grant and the key swap", text())
        keys = self.long_team(set(range(1, 40, 2)))             # 20 fit, and the longest role: four names and a count
        self.assertIn(f"sessions ({', '.join(keys[:4])} and 36 more)", text())
        self.assertIn(" Only 20 of these keys fit the next two options: a use grant and the key swap need", text())
        self.assertIn("(1) Change the grant of those keys from read to use", text())
        self.assertIn("the vault then keeps those keys out of its sessions, and it puts", text())
        self.assertNotIn("Only K", text())
        # on a server that swaps: the placeholders as a number too, where their names do not fit
        keys = self.long_team(set(range(1, 40, 2)), swap=True, mcp=6)
        self.assertIn(" 14 more keys are not in its sessions: the vault of its server swaps them, so a session holds "
                      "a placeholder. A text from outside", text())
        self.assertIn(" fit the next option: a use grant needs the https site", text())    # no site makes one swap
        self.assertNotIn("Switch the key swap", text())
        hub.settings_check()                                    # and the manager's list gives it whole
        self.assertTrue(hub.report_line(hub.q1("SELECT * FROM reports")).endswith("while these settings stay."))


class States(Base):
    """One finding for each state: none for a second run, a new one when the settings change."""

    def test_a_second_run_makes_no_second_finding(self):
        self.assertEqual(hub.settings_check(), [1])
        self.clock += 7 * 86400                                 # no clock decides: a week later is the same state
        self.assertEqual(hub.settings_check(), [])
        self.assertEqual(len(self.reports()), 1)
        self.assertEqual(self.open(), [1])

    def test_a_finding_that_the_manager_decided_is_not_made_again(self):
        hub.settings_check()
        self.manager("decide_report", report_id="UP-1", decision="noted", note="the owner accepts it")
        self.assertEqual(hub.settings_check(), [])
        self.agent("writer")["title"] = "Writer"                # a change of the team that is none of the three
        self.agent()["can"] = ["web", "shell", "screen"]        # and another order of the boxes, with one more box
        self.agent()["secrets"] = {KEY_B: "read", LOGIN: "use", KEY_A: "read"}
        self.assertEqual(hub.settings_check(), [])
        (row,) = self.reports()
        self.assertEqual((row["decided_by"], row["decision"]), ("manager", "noted"))

    def test_other_keys_make_a_new_finding_and_end_the_open_one(self):
        hub.settings_check()
        self.agent()["secrets"][KEY_C] = "read"
        self.clock += 60
        self.assertEqual(hub.settings_check(), [2])
        old, new = self.reports()
        self.assertEqual((old["decided"], old["decided_by"], old["decision"]), (self.clock, "hub", "noted"))
        self.assertEqual(old["note"], "The settings changed. UP-2 replaces this finding.")
        self.assertIn("reads 3 API keys in its sessions (ACME_API_KEY, MAIL_API_KEY, SHOP_API_KEY)", new["text"])
        self.assertEqual(self.open(), [2])
        self.assertEqual(self.mark()["report"], 2)
        self.assertEqual(hub.settings_check(), [])

    def test_other_boxes_make_a_new_finding_after_the_manager_decided_the_first(self):
        hub.settings_check()
        self.manager("decide_report", report_id="UP-1", decision="wrong", note="it needs its keys")
        self.agent()["can"] = ["shell", "web", "browser"]
        self.assertEqual(hub.settings_check(), [2])
        old, new = self.reports()
        self.assertEqual((old["decided_by"], old["decision"], old["note"]), ("manager", "wrong", "it needs its keys"))
        self.assertIn("(Tools: Shell, Web, Browser)", new["text"])

    def test_settings_that_are_gone_end_the_open_finding_and_their_return_is_a_new_one(self):
        hub.settings_check()
        self.agent()["can"] = ["shell"]                         # the owner sets Web off
        self.assertEqual(hub.settings_check(), [])
        (row,) = self.reports()
        self.assertEqual((row["decided_by"], row["decision"]), ("hub", "noted"))
        self.assertEqual(row["note"], "The settings changed: what this finding says is no longer there.")
        self.assertIsNone(self.mark())
        self.assertEqual(hub.settings_check(), [])
        self.agent()["can"] = ["shell", "web"]                  # and on again: the three are together once more
        self.assertEqual(hub.settings_check(), [2])
        self.assertEqual(self.open(), [2])

    def test_each_way_out_of_the_case_ends_it(self):
        ways = {"a use grant": lambda a: a.update(secrets={KEY_A: "use", KEY_B: "use"}),
                "no grant": lambda a: a.pop("secrets"),
                "Shell off": lambda a: a.update(can=["web"]),
                "no vault": lambda a: a.update(vault="none")}
        for n, (name, way) in enumerate(ways.items(), 1):
            with self.subTest(name):
                hub.TEAM = json.loads(json.dumps(TEAM))
                self.assertEqual(hub.settings_check(), [n])
                way(self.agent())
                self.assertEqual(hub.settings_check(), [])
                self.assertEqual(self.open(), [])
                self.assertIsNone(self.mark())

    def test_a_decided_finding_stays_as_it_was_decided_when_the_settings_go(self):
        hub.settings_check()
        self.manager("decide_report", report_id="UP-1", decision="noted", note="Web goes off")
        self.agent()["can"] = ["shell"]
        hub.settings_check()
        (row,) = self.reports()
        self.assertEqual((row["decided_by"], row["note"]), ("manager", "Web goes off"))
        self.agent()["can"] = ["shell", "web"]                  # somebody undid it: that is a new finding
        self.assertEqual(hub.settings_check(), [2])

    def test_each_agent_has_its_own_finding(self):
        self.agent("writer")["can"] = ["shell", "browser"]
        self.assertEqual(hub.settings_check(), [1, 2])
        self.assertEqual([r["about"] for r in self.reports()], ["dev-lead", "writer"])
        self.agent("writer")["can"] = ["shell"]
        self.assertEqual(hub.settings_check(), [])
        self.assertEqual(self.open(), [1])                      # the end of one leaves the other

    def test_a_rename_keeps_the_finding_and_makes_no_new_one(self):
        hub.settings_check()
        self.assertIn("settings_finding:", hub.AGENT_KV)
        with hub.transaction():
            hub.rename_rows("dev-lead", "builder", hub.now())
        hub.TEAM = hub.renamed_team(hub.TEAM, "dev-lead", "builder")
        self.assertEqual(hub.settings_check(), [])
        self.assertEqual(self.open(), [1])
        self.assertEqual((self.mark("builder")["report"], self.mark("dev-lead")), (1, None))
        self.assertEqual(self.reports()[0]["about"], "builder")         # the open finding names it as it is named now

    def test_an_open_finding_follows_a_new_role_and_a_decided_one_stays_as_it_was_read(self):
        hub.settings_check()
        self.agent()["title"] = "Backend Developer"
        self.assertEqual(hub.settings_check(), [])
        (row,) = self.reports()
        self.assertTrue(row["text"].startswith("Backend Developer reads 2 API keys in its sessions"), row["text"])
        self.assertIn("(2) Set Web off for Backend Developer.", row["text"])
        self.assertEqual((row["about"], row["decided"]), ("dev-lead", None))
        del self.agent()["title"]                               # with no role, the words name it by its name
        hub.settings_check()
        self.assertTrue(self.reports()[0]["text"].startswith("Dev-Lead reads 2 API keys"))
        self.manager("decide_report", report_id="UP-1", decision="noted", note="the owner accepts it")
        self.agent()["title"] = "Developer"
        self.assertEqual(hub.settings_check(), [])
        self.assertTrue(self.reports()[0]["text"].startswith("Dev-Lead reads 2 API keys"))

    def test_an_agent_that_left_ends_its_open_finding(self):
        hub.settings_check()
        with hub.transaction():
            hub.remove_rows("dev-lead", hub.now())              # a removal deletes the mark
        del hub.TEAM["agents"]["dev-lead"]
        self.assertEqual(hub.settings_check(), [])
        self.assertEqual((self.open(), self.reports()[0]["decided_by"]), ([], "hub"))

    def test_an_agent_that_a_reload_took_away_ends_it_too(self):
        hub.settings_check()
        del hub.TEAM["agents"]["dev-lead"]                      # no removal ran: the mark is still there
        self.assertEqual(hub.settings_check(), [])
        self.assertEqual((self.open(), self.mark()), ([], None))
        hub.TEAM = json.loads(json.dumps(TEAM))                 # an agent of that name again is a new finding
        self.assertEqual(hub.settings_check(), [2])

    def test_a_mark_that_cannot_be_read_counts_as_none(self):
        for value in ("not json", json.dumps({"keys": ["ACME_API_KEY", "SHOP_API_KEY"], "boxes": ["web"],
                                              "report": 99})):
            with self.subTest(value):
                hub.q("DELETE FROM reports")
                hub.kv_set("settings_finding:dev-lead", value)
                self.assertEqual(len(hub.settings_check()), 1)
                self.assertEqual(self.mark()["report"], self.open()[0])


class Manager(Base):
    """What the fleet manager reads, and what it does with it."""

    def test_the_list_of_proposals_gives_the_finding_whole(self):
        hub.settings_check()
        self.clock += 120
        team = self.manager("see_team").split("PROPOSALS FOR THE OWNER")[1].split("\n\n")[0]
        self.assertIn("  UP-1 [proposal] from hub, about dev-lead, 2m ago: Developer reads 2 API keys", team)
        self.assertIn("The hub makes no second finding while these settings stay.", team)      # its last words
        self.assertNotIn("...", team)
        brief = "\n".join(hub.resume_lines(hub.now()))
        self.assertIn("Reports waiting for your decision (1):", brief)
        self.assertIn("decide this report as noted", brief)

    def test_an_agent_s_own_report_is_still_cut(self):
        hub.ins("INSERT INTO reports(from_agent,to_agent,kind,text,severity,delivered,created,request_id) "
                "VALUES('dev-lead','manager','proposal',?,'note','note',?,'r-1')", ("word " * 200, hub.now()))
        line = hub.report_line(hub.q1("SELECT * FROM reports"))
        self.assertTrue(line.endswith("..."))
        self.assertLess(len(line), 400)

    def test_nothing_chases_it_and_no_screen_of_the_owner_counts_it(self):
        hub.settings_check()
        self.assertEqual(hub.open_reports(kinds=False), [])
        self.assertEqual(hub.reports_waiting(hub.now()), [])
        self.assertEqual([r["id"] for r in hub.managers_reports()], [1])
        hub.q("UPDATE events SET read_at=?", (hub.now() + 1,))
        self.clock += 3600
        self.assertIsNone(hub.requester_chase("manager", hub.now()))

    def test_the_manager_decides_it_and_reads_what_the_hub_does_then(self):
        hub.settings_check()
        text = self.manager("decide_report", report_id="UP-1", decision="noted", note="on the weekly list")
        self.assertIn("UP-1 is decided: noted (on the weekly list).", text)
        self.assertIn("The hub makes no new finding about these settings until they change.", text)
        self.assertNotIn("hub reads it", text)
        self.assertIn("  none", self.manager("see_team").split("PROPOSALS FOR THE OWNER")[1].split("\n\n")[0])

    def test_only_the_owner_s_yes_makes_it_a_goal_as_for_each_proposal(self):
        hub.settings_check()
        text, err = hub.call_tool("manager", "decide_report", {"report_id": "UP-1", "decision": "goal",
                                                               "note": "a good idea"})
        self.assertTrue(err)
        self.assertIn("only on the owner's yes", text)
        self.assertEqual(self.open(), [1])

    def test_an_agent_s_report_that_says_the_same_ends_with_it(self):
        """report_up joins a report to an open one of the same receiver, kind, about and first words (report_head). An
        agent's proposal that joined the hub's finding takes the hub's end of it, and is not left with no decision."""
        hub.settings_check()
        text = self.reports()[0]["text"]
        hub.ins("INSERT INTO reports(from_agent,to_agent,kind,text,about,severity,delivered,created,request_id,"
                "collapsed_into) VALUES('writer','manager','proposal',?,'dev-lead','note','note',?,'r-2',1)",
                (text, hub.now()))
        self.agent()["can"] = ["shell"]
        hub.settings_check()
        self.assertEqual([(r["decided_by"], r["decision"]) for r in self.reports()], [("hub", "noted")] * 2)

    def test_it_is_in_the_manager_s_history_and_in_nobody_else_s(self):
        hub.settings_check()
        (record,) = hub.history_report(hub.q1("SELECT * FROM reports"))
        self.assertEqual((record["agent"], record["person"], record["ref"]), ("manager", "hub", "UP-1"))
        self.assertTrue(record["text"].startswith("UP-1 hub to manager, proposal about dev-lead: Developer reads 2 "))
        self.assertIsNotNone(hub.HISTORY_HEADS["report"].match(record["text"]))


class Junctions(Base):
    """Where the check runs, and that it stops nothing."""

    def applied(self, team):
        with patch.object(hub, "kit_revision", lambda fresh=False: None):
            hub.apply_team(json.loads(json.dumps(team)))

    def test_a_change_of_team_json_runs_it(self):
        team = json.loads(json.dumps(TEAM))
        team["agents"]["dev-lead"]["can"] = ["shell"]
        self.applied(team)                                      # no case yet
        self.assertEqual(self.reports(), [])
        team["agents"]["dev-lead"]["can"] = ["shell", "web"]    # the owner sets Web on
        self.applied(team)
        self.assertEqual(self.open(), [1])
        self.applied(team)                                      # each later write of the team is the same state
        team["agents"]["writer"]["title"] = "Writer"
        self.applied(team)
        self.assertEqual(len(self.reports()), 1)
        team["agents"]["dev-lead"]["secrets"][KEY_B] = "use"    # a grant changes: other keys
        self.applied(team)
        self.assertEqual(self.open(), [2])

    def test_a_check_that_fails_stops_no_write_of_the_team(self):
        team = json.loads(json.dumps(TEAM))
        team["agents"]["writer"]["title"] = "Writer"
        with patch.object(hub, "settings_check", side_effect=RuntimeError("no records")), \
                patch("builtins.print") as printed:
            self.applied(team)
        self.assertEqual(hub.agents()["writer"]["title"], "Writer")
        self.assertIn("the settings check did not run: RuntimeError: no records", printed.call_args[0][0])
        self.assertEqual(self.reports(), [])

    def test_a_failure_in_the_middle_leaves_no_half_of_a_finding(self):
        with patch.object(hub, "log_row", side_effect=RuntimeError("stop")), patch("builtins.print"):
            self.assertEqual(hub.settings_checked(), [])
        self.assertEqual((self.reports(), self.mark()), ([], None))
        self.assertEqual(hub.settings_checked(), [1])           # and the next run makes it

    def test_an_agent_entry_of_a_wrong_shape_stops_the_check_of_no_other_agent(self):
        """The hub starts on the team.json that it has, also one that passed no check. An entry that the check
        cannot read gets no finding, and each other agent is checked."""
        hub.settings_check()
        self.agent("writer").update(can=["shell", "web"], secrets=["not", "a", "map"])
        hub.TEAM["agents"] = {"odd": "no entry", **hub.TEAM["agents"]}       # before the manager, too
        self.agent("support").update(can=["shell", "browser"])          # and one more that is the case now
        with self.assertRaises(ValueError):
            hub.settings_junction("writer")
        with self.assertRaises(AttributeError):
            hub.settings_junction("odd")
        with patch("builtins.print") as printed:
            self.assertEqual(hub.settings_checked(), [2])
        printed.assert_not_called()
        self.assertEqual([(r["about"], r["decided"]) for r in self.reports()], [("dev-lead", None), ("support", None)])

    def test_a_tools_list_of_a_wrong_type_is_read_as_no_tools_list(self):
        """As hub.shell_off and the helper read it: only a list can take the shell or the web away."""
        self.agent()["can"] = "web"
        self.assertEqual(hub.settings_junction("dev-lead"), (["ACME_API_KEY", "SHOP_API_KEY"], None))

    def test_the_hub_runs_it_at_its_start_before_its_timers(self):
        source = inspect.getsource(hub.main)
        self.assertIn("settings_checked()", source)
        self.assertLess(source.index("settings_checked()"), source.index("target=timers"))
        self.assertLess(source.index("settle_people_names()"), source.index("settings_checked()"))

    def test_a_grant_of_the_owner_reaches_it_through_apply_team(self):
        """Each write of team.json ends in apply_team, the one place that the check hangs on: the owner's grant, the
        Tools row, a reload, the manager's grant_access, a rename and a removal."""
        source = inspect.getsource(hub.apply_team)
        self.assertIn("settings_checked()", source)
        for writer in (hub.save_grant, hub.reload_team):
            with self.subTest(writer.__name__):
                self.assertIn("apply_team(", inspect.getsource(writer))


if __name__ == "__main__":
    unittest.main()

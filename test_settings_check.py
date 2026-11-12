"""The settings check (hub.settings_check): an agent whose settings put three things together -- its sessions hold the
value of a key, it has a shell, and its Tools boxes give it the web -- gets one finding on the fleet manager's list of
proposals for the owner, as the hub's own report. In-process hub, a temporary database and a set clock; no helper, no
fleet and no AI call.

What it holds: one finding for each state and never one for each run, a new finding when the settings change, the end
of an open finding whose settings are gone, no message and no chase for it, and a check that stops nothing.
"""
import inspect
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import fleet
import hub
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


def load_tests(loader, _tests, _pattern):
    """Only this file's cases, not the inherited OwnerAPI ones."""
    suite = unittest.TestSuite()
    for cls in (Keys, Finding, States, Manager, Junctions):
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
                              "calls the service with call_api. call_api sends an HTTP request to the site that the "
                              "login of the key names. call_api cannot use a key that is not for HTTP, for example a "
                              "database password. Cost: each command or saved check that reads the key from its "
                              "variable fails until somebody changes it. To undo: give read again.")
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
        self.agent("manager").update(title="Fleet Manager", vault="broker", secrets={KEY_D: "read"})
        for can in (["shell", "web"], [], ["web", "browser"], None):
            with self.subTest(can):
                self.agent("manager").pop("can", None)
                if can is not None:
                    self.agent("manager")["can"] = can
                self.assertEqual(hub.settings_junction("manager"), (["DB_READ_PASSWORD"], None))
                self.assertEqual(hub.settings_check(), [1] if can == ["shell", "web"] else [])
        text = self.reports()[0]["text"]
        self.assertTrue(text.startswith("Fleet Manager reads 1 API key in its sessions (DB_READ_PASSWORD), and it has "
                                        "a shell and the web (its sessions have both, whatever its Tools boxes say)."))
        self.assertIn("The choice is the owner's: put these two options on your weekly list. (1) Change the grant of "
                      "the key from read to use: the vault keeps the key, and a worker or a lead that has a use grant "
                      "of it calls the service with call_api.", text)         # a manager has no call_api
        self.assertTrue(text.endswith("To undo: give read again. (2) Leave it as it is. Cost: the risk stays. When the "
                                      "owner chooses this, decide this report as noted. The hub makes no second "
                                      "finding while these settings stay."), text)
        for words in ("(3)", "Tools list", "Set Web", "off for"):
            self.assertNotIn(words, text)

    def test_the_first_option_says_which_logins_name_no_site(self):
        """call_api sends its request to the site of the key's login, so a key with no site cannot go that way yet."""
        cases = (({KEY_A: "read"}, "of the key names. call_api cannot use a key"),
                 ({KEY_D: "read"}, "of the key names. This login names no site yet. call_api cannot use a key"),
                 ({KEY_A: "read", KEY_D: "read"}, "of the key names. 1 of these logins names no site yet. call_api "),
                 ({KEY_A: "read", KEY_D: "read", KEY_E: "read"}, "names. 2 of these logins name no site yet. call_api "),
                 ({KEY_D: "read", KEY_E: "read"}, "of the key names. None of these logins names a site yet. call_api "))
        for secrets, words in cases:
            with self.subTest(words):
                self.agent()["secrets"] = secrets
                keys, boxes = hub.settings_junction("dev-lead")
                self.assertIn(words, hub.settings_words("dev-lead", keys, boxes))

    def test_the_longest_finding_stays_inside_one_report(self):
        self.agent()["title"] = "R" * 60                        # the longest role and key names that team.json takes
        hub.TEAM["logins"] = {f"bws://11111111-2222-4333-8444-5555555555{n:02d}":
                              {"title": f"K{n:02d}", "kind": "api_key", "env": f"K{n:02d}_" + "A" * 56}
                              for n in range(40)}
        self.agent()["secrets"] = {ref: "read" for ref in hub.TEAM["logins"]}
        for can in (["shell", "web", "browser"], None):
            with self.subTest(can):
                self.agent().pop("can", None)
                if can:
                    self.agent()["can"] = can
                keys, boxes = hub.settings_junction("dev-lead")
                text = hub.settings_words("dev-lead", keys, boxes)
                self.assertEqual((len(keys), len(keys[0])), (40, 60))
                self.assertIn("reads 40 API keys in its sessions", text)
                self.assertIn(f"{keys[7]} and 32 more)", text)
                self.assertNotIn(keys[8], text)
                self.assertIn("None of these logins names a site yet.", text)
                self.assertLessEqual(len(text), hub.REPORT_TEXT_MAX)
                self.assertTrue(hub.ENV_NAME.fullmatch(keys[0]))
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

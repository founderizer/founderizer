"""An agent by its name or by its role (UI-API.md Versions 1.112 and 1.315).

The owner's apps name an agent by its name, with its role, its team.json "title", beside it, and the owner and the
agents may name it either way. So a tool field that names an agent takes either, the hub's words for the owner use
the name (the role only where the role holds the name), the agents' rules ask for the name, the phone reads the role,
and two agents never share a role.
"""
import json
import os
import unittest
import uuid

import hub
import leftovers
from test_capacity import Capacity


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(Roles(name) for name in Roles.__dict__ if name.startswith("test_"))


class Roles(Capacity):
    def settings(self, agent, **fields):
        return self.request(f"/ui/team/agents/{agent}", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                             base_sha256=self.sha(), **fields))

    def test_a_name_in_any_case_or_a_role_in_any_case_and_spacing_names_one_agent(self):
        for word, agent in (("seo", "seo"), ("SEO", "seo"), ("Deva", "deva"), ("seo expert", "seo"),
                            ("  SEO   Expert ", "seo"), ("SEO Expert", "seo")):
            self.assertEqual(hub.agent_called(word), agent, word)
        for word in ("", None, "Nobody", "SEO", "Expert"):
            if word != "SEO":
                self.assertIsNone(hub.agent_called(word), word)
        twice = json.loads(json.dumps(hub.TEAM["agents"]))
        twice["deva"]["title"] = "seo expert"              # a team.json written by hand: the role names neither
        self.assertIsNone(hub.agent_called("SEO Expert", twice))
        self.assertEqual(hub.agent_called("deva", twice), "deva")      # a name still names its agent

    def test_a_tool_field_that_names_an_agent_takes_its_role(self):
        self.assertEqual(self.settings("big", title="Builder")[0], 200)
        tid = self.create("manager", "BUILDER")             # big reports to the manager
        self.assertEqual(hub.q1("SELECT owner FROM tasks WHERE id=?", (tid,))["owner"], "big")
        # The tool's own checks read the name: seo's role names seo, whose lead gives it its tasks.
        self.assertIn("seo reports to pma", self.refused("manager", "create_task", {
            "owner": "SEO Expert", "title": "Work", "done_when": "Done.", "why": "Its expertise."}))
        text, error = self.call("manager", "message_agent", {"request_id": str(uuid.uuid4()), "agent": "seo expert",
                                                             "text": "Which keywords rank this week?"})
        self.assertFalse(error, text)
        self.assertEqual(hub.q1("SELECT recipient FROM agent_messages ORDER BY id DESC LIMIT 1")["recipient"], "seo")
        call = hub.q1("SELECT args FROM calls WHERE name='message_agent' AND ok=1 ORDER BY id DESC LIMIT 1")
        self.assertEqual(json.loads(call["args"])["agent"], "seo")      # the record holds the one spelling
        text, error = self.call("manager", "see_responsibilities", {"agent": "SEO Expert"})
        self.assertFalse(error, text)
        # A word that names no agent reaches the tool as it was written, which refuses it in its own words.
        self.assertIn("Nobody", self.refused("manager", "message_agent", {"request_id": str(uuid.uuid4()),
                                                                          "agent": "Nobody", "text": "Hello."}))

    def test_a_list_of_agents_takes_each_one_by_its_role(self):
        # The fixture has no door, so the tool refuses; its record holds what the tool read: the agents' names.
        text, error = self.call("manager", "door_gitops", {"request_id": str(uuid.uuid4()), "repo": "acme/gitops",
                                                           "sync": "sync.yml", "agents": ["SEO Expert", "Deva"],
                                                           "why": "The plan's step."})
        self.assertTrue(error, text)
        call = hub.q1("SELECT args FROM calls WHERE name='door_gitops' ORDER BY id DESC LIMIT 1")
        self.assertEqual(json.loads(call["args"])["agents"], ["seo", "deva"])

    def test_a_replay_of_one_request_with_the_other_name_is_the_same_command(self):
        rid = str(uuid.uuid4())
        first, error = self.call("manager", "message_agent", {"request_id": rid, "agent": "SEO Expert", "text": "Hi."})
        self.assertFalse(error, first)
        again, error = self.call("manager", "message_agent", {"request_id": rid, "agent": "seo", "text": "Hi."})
        self.assertFalse(error, again)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM agent_messages")["n"], 1)

    def test_two_agents_never_share_a_role_and_a_role_is_no_other_agent_s_name(self):
        code, data = self.settings("big", title="seo expert")
        self.assertEqual((code, data.get("error")), (409, "Seo has this role already."), data)
        code, data = self.settings("big", title="DEVA")
        self.assertEqual((code, data.get("error")), (409, "Deva has this name. Give Big another role."), data)
        self.assertEqual(self.settings("big", title="Builder")[0], 200)
        self.assertEqual(hub.agents()["big"]["title"], "Builder")
        self.assertEqual(self.settings("big", title=" builder ")[0], 200)     # its own role again: no clash
        self.assertEqual(self.settings("big", title=None)[0], 200)
        self.assertNotIn("title", {k: v for k, v in hub.agents()["big"].items() if v is not None})

    def test_a_role_that_stays_is_not_checked_so_an_old_clash_does_not_stop_other_settings(self):
        self.assertEqual(self.settings("deva", title="Builder")[0], 200)
        team = json.loads((self.kit / "team.json").read_text())
        self.assertEqual(team["agents"]["deva"]["title"], "Builder")

    def test_a_new_name_that_is_another_agent_s_role_is_refused(self):
        self.assertEqual(self.settings("deva", title="Builder")[0], 200)
        code, data = self.request("/ui/team/agents/big/rename", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                                     base_sha256=self.sha(), name="builder"))
        self.assertEqual((code, data.get("error")), (409, "Builder is the role of Deva. Choose another name."), data)

    def test_the_owner_reads_an_agent_by_its_name_and_by_its_role_only_where_the_role_holds_the_name(self):
        """F16 (the owner, 22 November 2026): the hub's words name an agent by its name, as his apps do, and by its
        role only when one word of the role is the name, where the name would say less ("Fleet Manager" for manager).
        Bug: the role comes back as the label, or the exception goes and the owner reads "Manager"."""
        self.assertEqual(self.settings("deva", title="Builder")[0], 200)
        self.assertEqual(self.settings("manager", title="Fleet Manager")[0], 200)
        self.assertEqual(tuple(hub.shown_role(n) for n in ("deva", "manager", "seo", "big", "gone")),
                         ("Deva", "Fleet Manager", "SEO Expert", "Big", "Gone"))
        self.assertIn("Deva has been silent since", hub.silent_words("deva", hub.now() - 7200))
        self.assertEqual(hub.silent_words("big", None), "Big has never answered")
        self.assertEqual(hub.shown_role("seo"), hub.agent_label("seo", "  SEO   Expert "))    # a role on one line
        self.assertEqual(hub.agent_label("web-dev", "Web Dev"), "Web-Dev")      # no role holds a name with a hyphen
        self.assertEqual(hub.name_and_role("deva"), "deva (Builder)")            # an agent's words: as the team list
        self.assertEqual(hub.name_and_role("big"), "big")
        # a card that signs an agent in names it by its role or by its name: card_signs_in reads the role itself
        self.assertTrue(hub.card_signs_in("Sign Builder in again") and hub.card_signs_in("Sign Deva in again"))

    def test_the_rules_and_the_tool_texts_tell_an_agent_to_name_a_colleague_by_its_name(self):
        """F16, the owner's "Yes, as written" to the sentence of RULES.md: an agent names a colleague by its name, and
        never by its role alone. Bug: a later edit brings "by its role" back into RULES.md or into one of the tool
        texts that say how to name an agent, and an agent reads two rules that disagree."""
        sentence = ('Name an agent the way the owner\'s apps do: by its name, with a capital ("Nova"), and never by its '
                    'role alone ("Customer Support"), which YOUR TEAM gives in brackets after the name. In a tool, its '
                    'role and its name both reach it.')
        with open(os.path.join(leftovers.ROOT, "RULES.md"), encoding="utf-8") as f:
            rules = f.read()
        self.assertIn(sentence, rules)
        self.assertNotIn("by its role", rules.replace(sentence, ""))
        tools = {name: json.dumps([desc, schema]) for _role, name, _fn, desc, schema in hub.TOOLS}
        for name in ("tell_owner", "message_owner", "set_duty", "save_trigger"):
            self.assertIn("an agent by its name", tools[name], name)
            self.assertNotIn("by its role", tools[name], name)
        self.assertEqual([n for n, text in tools.items() if "an agent by its role" in text], [])

    def test_the_phone_reads_each_agent_s_role(self):
        code, data = self.request("/ui/mobile?db=test-generation")
        self.assertEqual(code, 200, data)
        roles = {a["name"]: a["title"] for a in data["agents"]}
        self.assertEqual((roles["seo"], roles["deva"]), ("SEO Expert", None))


if __name__ == "__main__":
    unittest.main()

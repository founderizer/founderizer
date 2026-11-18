"""An agent by its role or by its name (UI-API.md Version 1.112).

The owner's apps show an agent by its role, its team.json "title", with its name under it, and the owner and the
agents may name it either way. So a tool field that names an agent takes either, the hub's words for the owner use
the role, the phone reads the role, and two agents never share a role.
"""
import json
import unittest
import uuid

import hub
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

    def test_the_owner_reads_an_agent_by_its_role_and_one_with_no_role_by_its_name(self):
        self.assertEqual((hub.shown_role("seo"), hub.shown_role("deva"), hub.shown_role("gone")),
                         ("SEO Expert", "Deva", "Gone"))
        self.assertIn("SEO Expert has been silent since", hub.silent_words("seo", hub.now() - 7200))
        self.assertEqual(hub.silent_words("deva", None), "Deva has never answered")

    def test_the_phone_reads_each_agent_s_role(self):
        code, data = self.request("/ui/mobile?db=test-generation")
        self.assertEqual(code, 200, data)
        roles = {a["name"]: a["title"] for a in data["agents"]}
        self.assertEqual((roles["seo"], roles["deva"]), ("SEO Expert", None))


if __name__ == "__main__":
    unittest.main()

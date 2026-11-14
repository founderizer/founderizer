"""A fleet whose manager has a name of its own (hub.sh --manager-name; the owner approved the app's page "Name your
manager" on 14 November 2026, and no flow of the app gives the name yet). The hub finds the manager by its role and
never by the name `manager`, so nothing in it changes for such a fleet: this file proves that.

Two parts. (1) Every check of test_manager_server.py again, for a manager named `juno`: its setup with no server yet,
the one command that gives it its server, and its first message to the owner. (2) What that file does not reach: the
owner's pages, the manager's tools, the rules that its session starts with, its profile, and the owner's message that
names no agent. A local hub with a temporary Fleet repository; no AI, no machine."""
import json
import shutil
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

import fleet
import hub
import owner_mcp
import test_manager_server
from test_servers import HUB, OWNER, Servers

NAME = "juno"
KIT = Path(__file__).resolve().parent


class NamedFleet(test_manager_server.NewFleet):
    MANAGER, SHOWN = NAME, "Juno"


class NamedFirstMessage(test_manager_server.FirstMessage):
    MANAGER, SHOWN = NAME, "Juno"


class Juno(Servers):
    """A new fleet whose manager is named juno and runs on the hub's server, as hub.sh leaves it with --manager-name
    and without the app's word for a server of its own."""

    def setUp(self):
        super().setUp()
        self.team = self.fresh_fleet(manager=NAME)

    def call(self, name, args=None):
        """One tool of the manager's standing session, as its MCP call runs it."""
        with hub.LOCK:
            text, error = hub.call_tool(NAME, name, args or {}, None)
        self.assertFalse(error, text)
        return text

    def text_page(self, path):
        request = urllib.request.Request(self.base + path, headers={"X-Test-Source": OWNER})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=30) as answer:
            return answer.status, answer.read().decode()

    def test_the_first_commit_has_the_manager_and_its_profile_under_its_name(self):
        self.assertEqual(list(self.origin_team()["agents"]), [NAME])
        self.assertEqual((hub.manager_name(), hub.role_of(NAME)), (NAME, "manager"))
        rev = hub.kit_revision(fresh=True)
        self.assertIsNone(hub.git_blob(rev, "profiles/manager.md"))
        view = hub.profile_view(NAME, rev)
        self.assertEqual((view["path"], view["text"].split("\n")[0]), (f"profiles/{NAME}.md", f"# Profile: {NAME}"))
        # a profile that the owner saves keeps the manager's opening, which says that the manager may update it
        saved = hub.render_profile(NAME, view["sections"])
        self.assertTrue(saved.startswith(f"# Profile: {NAME}\n\n{hub.MANAGER_OPENING}\n"), saved[:200])

    def test_each_page_of_the_owner_answers_and_names_no_agent_manager(self):
        """Every page that the owner's own agent can read (owner_mcp.PAGES), and the board. The name `manager` is
        nowhere an agent's name: the one agent is juno, with the role manager."""
        # some work first, so that the pages have rows that name an agent: the owner's message, the manager's
        # answer to it, a Needs-you item of the manager, and a goal
        status, sent = self.request("/ui/messages", self.command(text="Hello"), source=OWNER)
        self.assertEqual(status, 200, sent)
        self.call("tell_owner", {"text": "Hello. The fleet is ready."})
        self.call("raise_needs_you", {"title": "Choose a plan", "why": "The work needs a paid plan.",
                                      "what_to_do": "Say which plan you want."})
        status, state = self.request(source=OWNER)
        self.assertEqual(status, 200, state)
        self.assertEqual([(a["name"], a["role"], a["reports_to"]) for a in state["agents"]], [(NAME, "manager", None)])
        self.assertEqual(([m["recipient"] for m in state["messages"]], [r["agent"] for r in state["reports"]],
                          [n["by"] for n in state["needs"]]), ([NAME], [NAME], [NAME]))
        read, naming = [], set()
        for page, (route, _what) in sorted(owner_mcp.PAGES.items()):
            if "{id}" in route or "{name}" in route or page == "knowledge":
                continue                    # a page about one task, goal, rule or account, or one file by its path
            path = route.replace("{agent}", NAME) + "?db=test-generation" + \
                ("&agent=" + NAME if page == "agent_messages" else "")
            status, answer = self.request(path, source=OWNER)
            self.assertEqual(status, 200, (page, answer))
            read.append(page)

            def names(value):               # every value under a key that names an agent
                if isinstance(value, dict):
                    for key, inner in value.items():
                        if key in ("agent", "name", "recipient", "by", "owner", "requester", "reports_to") and \
                                isinstance(inner, str):
                            yield key, inner
                        yield from names(inner)
                elif isinstance(value, list):
                    for inner in value:
                        yield from names(inner)
            if page not in ("roles", "people"):     # `manager` is also a role that a person can hold
                self.assertEqual([found for found in names(answer) if found[1] == "manager"], [], page)
            if any(found[1] == NAME for found in names(answer)):
                naming.add(page)
        self.assertGreaterEqual(len(read), 20, read)
        # the check above is not empty: these pages name an agent, and the agent that they name is juno
        self.assertEqual({"state", "team", "capacity", "machines", "profiles", "health"} - naming, set(), naming)
        status, team = self.request("/ui/team?db=test-generation", source=OWNER)
        self.assertEqual([(line["agent"], line["role"]) for line in team["lines"]], [(NAME, "manager")])
        status, health = self.request("/ui/health?db=test-generation", source=OWNER)
        self.assertEqual([w for w in health["warnings"] if w.get("agent") not in (None, NAME)], [])
        for path in ("/board.txt", "/board"):
            status, page = self.text_page(path)
            self.assertEqual(status, 200, path)
            self.assertIn(NAME, page, path)

    def test_the_owners_message_that_names_no_agent_goes_to_the_manager(self):
        """UI-API.md: a message with no `recipient` is for the manager. It is the manager by its role."""
        status, answer = self.request("/ui/messages", self.command(text="Hello"), source=OWNER)
        self.assertEqual(status, 200, answer)
        asked = hub.q1("SELECT * FROM ui_requests ORDER BY rowid DESC LIMIT 1")
        self.assertEqual(asked["recipient"], NAME)
        said = hub.q1("SELECT agent, text FROM events WHERE kind='say' ORDER BY id DESC LIMIT 1")
        self.assertEqual((said["agent"], "Hello" in said["text"]), (NAME, True), dict(said))
        status, state = self.request(source=OWNER)
        self.assertEqual([m["recipient"] for m in state["messages"]], [NAME])
        # the word `manager` is no agent's name in this fleet, so a client that sends it as the name is refused
        status, answer = self.request("/ui/messages", self.command(text="Hello again", recipient="manager"),
                                      source=OWNER)
        self.assertEqual((status, answer["error"]), (400, "recipient must name a configured agent"))

    def test_its_session_gets_the_managers_tools_and_the_managers_rules(self):
        """Its tools are its role's, and each tool that reads the team runs. Its session starts with RULES.md, the
        lead's and the manager's parts of the rules, and its own profile: the hub names the parts, and the helper
        reads the files by the agent's name."""
        status, listed = self.request(f"/mcp/{NAME}", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, source=HUB)
        self.assertEqual(status, 200, listed)
        tools = {t["name"] for t in listed["result"]["tools"]}
        self.assertEqual({"create_task", "raise_needs_you", "see_team", "see_capacity", "grant_access", "set_duty",
                          "tell_owner", "read_messages"} - tools, set())
        self.assertEqual(hub.kv_get(f"listed:{NAME}:manager"), "1")       # its standing window, by the window's name
        for tool in ("see_team", "see_capacity", "see_goals", "read_messages", "see_responsibilities"):
            self.call(tool)
        self.assertIn(NAME, self.call("see_team"))
        raised = self.call("raise_needs_you", {"title": "Choose a plan", "why": "The work needs a paid plan.",
                                               "what_to_do": "Say which plan you want."})
        need = hub.q1("SELECT * FROM needs ORDER BY id DESC LIMIT 1")
        self.assertEqual(need["by"], NAME, raised)
        parts = hub.rules_parts(NAME)
        self.assertEqual(parts[:2], ["lead", "manager"])
        self.assertEqual(hub.rules_files(parts)[:3], ["RULES.md", "rules/lead.md", "rules/manager.md"])
        with hub.LOCK:
            brief = hub.manager_resume_text()
        self.assertIn("rules/manager.md", brief)
        status, opening = self.request(f"/events/{NAME}?after=-1&wait=0", source=HUB)
        self.assertEqual(status, 200, opening)
        # the helper's side, on the manager's own checkout: the released rules, and the profile under its name
        for name in ("RULES.md", "rules"):
            source, target = KIT / name, self.kit / name
            shutil.copytree(source, target) if source.is_dir() else shutil.copy(source, target)
        with patch.object(fleet, "KIT", str(self.kit)):
            start = fleet.stable_text(NAME, "read", parts, head="")
            first = fleet.MANAGER_START.format(agent=NAME, resume="")
        self.assertIsNotNone(start)
        self.assertIn(f"# Profile: {NAME}", start)
        self.assertIn((KIT / "rules" / "manager.md").read_text().strip()[:200], start)
        self.assertIn(f"profiles/{NAME}.md", first)

    def test_a_new_agent_reports_to_the_manager_and_reads_it_by_its_name(self):
        """The first agent that the owner adds: its line goes to juno, and its start names juno as the agent that
        gives it its tasks. `manager` in a tool's field names nobody; `juno` and `Juno` do."""
        self.joined("mini")
        status, answer = self.add_agent()
        self.assertEqual(status, 200, answer)
        self.assertEqual(hub.reports_to("scout"), NAME)
        with hub.LOCK:
            team = self.origin_team()
            team["agents"]["scout"]["active"] = True
            hub.TEAM = team
            directory = hub.team_start_text("scout")
        self.assertIn(f"{NAME} [manager", directory)
        self.assertIn("it gives you your tasks", directory)
        self.assertEqual((hub.agent_called(NAME), hub.agent_called("Juno"), hub.agent_called("manager")),
                         (NAME, NAME, None))


def load_tests(loader, _tests, _pattern):
    """Each class with the checks of its own file only: Servers, which they all build on, has checks of its own that
    belong to test_servers.py."""
    suite = unittest.TestSuite()
    for cls, own in ((NamedFleet, test_manager_server.NewFleet), (NamedFirstMessage, test_manager_server.FirstMessage),
                     (Juno, Juno)):
        suite.addTests(cls(name) for name in own.__dict__ if name.startswith("test_"))
    return suite


if __name__ == "__main__":
    unittest.main()
